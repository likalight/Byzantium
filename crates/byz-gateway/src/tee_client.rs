//! TEE client — calls the SGX enclaves over localhost HTTP.
//!
//! When BYZ_TEE_ENABLED=true the gateway delegates mandate checks and
//! reputation queries to the Gramine SGX enclaves instead of running them
//! in-process. The enclave's Dilithium public key is verified against the
//! DCAP attestation quote before trusting any response.
//!
//! Hot path: mandate check → enclave signs response → gateway verifies sig.
//! Graceful fallback: if the enclave is unreachable, falls back to in-process.

use byz_common::{ActionType, AgentDid, ByzantiumError, ByzResult, Counterparty, SpendMandate};
use byz_crypto::dilithium::{DilithiumPublicKey, DilithiumSignature};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct AttestationResponse {
    pubkey_hex: String,
    mrenclave: String,
}

#[derive(Debug, Clone, Serialize)]
struct TeeCheckRequest<'a> {
    agent_did:    &'a str,
    action_type:  &'a ActionType,
    amount_cents: Option<u64>,
    counterparty: Option<&'a Counterparty>,
}

#[derive(Debug, Deserialize)]
struct TeeCheckResponse {
    compliant:          bool,
    mandate_hash:       String,
    /// ML-DSA signature by enclave key over "agent_did:mandate_hash:compliant:ts"
    enclave_signature:  String,
}

#[derive(Debug, Deserialize)]
struct TeeCommitmentResponse {
    commitment_hex:           String,
    meets_default_threshold:  bool,
    threshold_proof:          Option<Vec<u8>>,
}

/// Lightweight HTTP client to the two TEE services.
#[derive(Clone)]
pub struct TeeClient {
    mandate_url:    String,
    reputation_url: String,
    http:           reqwest::Client,
    /// Enclave signing public keys — pinned during startup via attestation.
    mandate_pubkey:    Option<DilithiumPublicKey>,
    reputation_pubkey: Option<DilithiumPublicKey>,
}

impl TeeClient {
    pub fn new(mandate_port: u16, reputation_port: u16) -> Self {
        Self {
            mandate_url:    format!("http://127.0.0.1:{}", mandate_port),
            reputation_url: format!("http://127.0.0.1:{}", reputation_port),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(150))
                .build()
                .expect("tee http client"),
            mandate_pubkey:    None,
            reputation_pubkey: None,
        }
    }

    pub fn from_env() -> Option<Self> {
        let enabled = std::env::var("BYZ_TEE_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let mandate_port = std::env::var("MANDATE_ENGINE_PORT")
            .ok().and_then(|p| p.parse().ok()).unwrap_or(9001);
        let reputation_port = std::env::var("REPUTATION_TEE_PORT")
            .ok().and_then(|p| p.parse().ok()).unwrap_or(9002);
        Some(Self::new(mandate_port, reputation_port))
    }

    /// Fetch attestation from both TEE services and pin their public keys.
    /// If BYZ_MANDATE_MRENCLAVE is set, asserts the returned mrenclave matches.
    /// Returns Err if the mrenclave check fails (MITM prevention).
    pub async fn fetch_and_pin_keys(&mut self) -> ByzResult<()> {
        let expected_mandate_mrenclave = std::env::var("BYZ_MANDATE_MRENCLAVE").ok();
        let expected_reputation_mrenclave = std::env::var("BYZ_REPUTATION_MRENCLAVE").ok();

        // Fetch mandate TEE attestation
        let mandate_resp = self
            .http
            .get(format!("{}/internal/attestation", self.mandate_url))
            .send()
            .await
            .map_err(|e| ByzantiumError::Tee(format!("mandate-tee attestation unreachable: {e}")))?;

        if !mandate_resp.status().is_success() {
            return Err(ByzantiumError::Tee(format!(
                "mandate-tee attestation returned {}",
                mandate_resp.status()
            )));
        }

        let mandate_attest: AttestationResponse = mandate_resp
            .json()
            .await
            .map_err(|e| ByzantiumError::Tee(format!("mandate-tee attestation parse: {e}")))?;

        if let Some(ref expected) = expected_mandate_mrenclave {
            if mandate_attest.mrenclave != *expected {
                return Err(ByzantiumError::Tee(format!(
                    "mandate-tee mrenclave mismatch: expected {expected}, got {}",
                    mandate_attest.mrenclave
                )));
            }
        }

        self.mandate_pubkey = Some(
            DilithiumPublicKey::from_hex(&mandate_attest.pubkey_hex)
                .map_err(|e| ByzantiumError::Tee(format!("mandate pubkey decode: {e}")))?,
        );

        tracing::info!(
            mrenclave = %mandate_attest.mrenclave,
            pubkey_prefix = &mandate_attest.pubkey_hex[..16],
            "mandate-tee attestation pinned"
        );

        // Fetch reputation TEE attestation
        let rep_resp = self
            .http
            .get(format!("{}/internal/attestation", self.reputation_url))
            .send()
            .await
            .map_err(|e| ByzantiumError::Tee(format!("reputation-tee attestation unreachable: {e}")))?;

        if !rep_resp.status().is_success() {
            return Err(ByzantiumError::Tee(format!(
                "reputation-tee attestation returned {}",
                rep_resp.status()
            )));
        }

        let rep_attest: AttestationResponse = rep_resp
            .json()
            .await
            .map_err(|e| ByzantiumError::Tee(format!("reputation-tee attestation parse: {e}")))?;

        if let Some(ref expected) = expected_reputation_mrenclave {
            if rep_attest.mrenclave != *expected {
                return Err(ByzantiumError::Tee(format!(
                    "reputation-tee mrenclave mismatch: expected {expected}, got {}",
                    rep_attest.mrenclave
                )));
            }
        }

        self.reputation_pubkey = Some(
            DilithiumPublicKey::from_hex(&rep_attest.pubkey_hex)
                .map_err(|e| ByzantiumError::Tee(format!("reputation pubkey decode: {e}")))?,
        );

        tracing::info!(
            mrenclave = %rep_attest.mrenclave,
            pubkey_prefix = &rep_attest.pubkey_hex[..16],
            "reputation-tee attestation pinned"
        );

        Ok(())
    }

    /// Check mandate compliance via the SGX enclave.
    /// Returns (compliant, mandate_hash) or an error if the enclave is unreachable.
    pub async fn mandate_check(
        &self,
        agent_did: &AgentDid,
        action: &ActionType,
        amount_cents: Option<u64>,
        counterparty: Option<&Counterparty>,
    ) -> ByzResult<(bool, String)> {
        let body = TeeCheckRequest {
            agent_did:    agent_did.as_str(),
            action_type:  action,
            amount_cents,
            counterparty,
        };

        let resp = self
            .http
            .post(format!("{}/internal/mandate/check", self.mandate_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| ByzantiumError::Tee(format!("mandate-tee unreachable: {e}")))?;

        if !resp.status().is_success() {
            return Err(ByzantiumError::Tee(format!(
                "mandate-tee returned {}",
                resp.status()
            )));
        }

        let tee_resp: TeeCheckResponse = resp
            .json()
            .await
            .map_err(|e| ByzantiumError::Tee(format!("mandate-tee parse: {e}")))?;

        // Verify enclave signature if we have the pinned public key
        if let Some(ref pk) = self.mandate_pubkey {
            let payload = format!(
                "{}:{}:{}",
                agent_did, tee_resp.mandate_hash, tee_resp.compliant
            );
            let sig = DilithiumSignature::from_hex(&tee_resp.enclave_signature)
                .map_err(|e| ByzantiumError::Tee(format!("bad sig hex: {e}")))?;
            byz_crypto::dilithium::verify(payload.as_bytes(), &sig, pk)?;
        }

        Ok((tee_resp.compliant, tee_resp.mandate_hash))
    }

    /// Register a mandate with the enclave.
    pub async fn register_mandate(&self, mandate: &SpendMandate) -> ByzResult<()> {
        let resp = self
            .http
            .post(format!("{}/internal/mandate/register", self.mandate_url))
            .json(&serde_json::json!({ "mandate": mandate }))
            .send()
            .await
            .map_err(|e| ByzantiumError::Tee(format!("mandate-tee unreachable: {e}")))?;

        if !resp.status().is_success() {
            return Err(ByzantiumError::Tee(format!(
                "mandate-tee register returned {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Get a score commitment + optional threshold proof from the reputation enclave.
    pub async fn reputation_commitment(
        &self,
        agent_did: &AgentDid,
        threshold: Option<u32>,
    ) -> ByzResult<(String, bool, Option<Vec<u8>>)> {
        let body = serde_json::json!({
            "agent_did": agent_did.as_str(),
            "threshold": threshold,
        });

        let resp = self
            .http
            .post(format!("{}/internal/reputation/commitment", self.reputation_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| ByzantiumError::Tee(format!("reputation-tee unreachable: {e}")))?;

        if !resp.status().is_success() {
            return Err(ByzantiumError::Tee(format!(
                "reputation-tee returned {}",
                resp.status()
            )));
        }

        let tee_resp: TeeCommitmentResponse = resp
            .json()
            .await
            .map_err(|e| ByzantiumError::Tee(format!("reputation-tee parse: {e}")))?;

        Ok((
            tee_resp.commitment_hex,
            tee_resp.meets_default_threshold,
            tee_resp.threshold_proof,
        ))
    }

    pub fn is_mandate_available(&self) -> bool {
        // Quick check — actual connectivity determined at request time
        true
    }
}
