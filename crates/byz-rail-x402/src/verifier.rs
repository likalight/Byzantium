//! X402Verifier — the main integration point for resource servers.
//!
//! Resource servers call `X402Verifier::verify()` before serving protected
//! resources. It simultaneously validates the payment proof AND calls the
//! Byzantium trust-check endpoint.

use byz_common::{ActionType, AgentDid, TrustVerdict};
use chrono::Utc;
use uuid::Uuid;

use crate::{
    error::X402Error,
    payment::{parse_proof_header, validate_proof_format},
    PaymentRequired, X402VerificationResult,
};

pub struct X402Verifier {
    /// Byzantium gateway URL
    byzantium_url: String,
    /// Bearer API key for Byzantium
    api_key: String,
    http: reqwest::Client,
}

impl X402Verifier {
    pub fn new(byzantium_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            byzantium_url: byzantium_url.into(),
            api_key: api_key.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(190))
                .build()
                .expect("http client"),
        }
    }

    /// Full verification: payment proof format + Byzantium trust-check.
    /// Call this in your axum middleware or handler before serving the resource.
    pub async fn verify(
        &self,
        proof_header: &str,
        required: &PaymentRequired,
        agent_did: &str,
    ) -> Result<X402VerificationResult, X402Error> {
        let proof = parse_proof_header(proof_header)?;
        validate_proof_format(&proof, required)?;

        // Parallel: trust-check while we validate format
        let trust_result = self
            .trust_check(agent_did, proof.value, required.mandate_hash.as_deref())
            .await?;

        Ok(X402VerificationResult {
            payment_valid: true,
            trust_verdict: trust_result,
            agent_did: AgentDid::new(agent_did),
            amount_usdc_micro: proof.value,
            verified_at: Utc::now(),
            request_id: Uuid::new_v4(),
        })
    }

    async fn trust_check(
        &self,
        agent_did: &str,
        amount_usdc_micro: u64,
        _mandate_hash: Option<&str>,
    ) -> Result<TrustVerdict, X402Error> {
        let amount_cents = amount_usdc_micro / 10_000; // USDC micro → USD cents

        let body = serde_json::json!({
            "agent_did": agent_did,
            "action_type": "payment",
            "amount_cents": amount_cents,
            "rail_id": "x402",
        });

        let resp = self
            .http
            .post(format!("{}/v1/trust-check", self.byzantium_url))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| X402Error::Gateway(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(X402Error::Gateway(format!("{status}: {text}")));
        }

        let response: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| X402Error::Gateway(e.to_string()))?;

        // Parse verdict from response
        let verdict_str = response["verdict"]["verdict"]
            .as_str()
            .or_else(|| response["verdict"].as_str())
            .unwrap_or("BLOCK");

        Ok(match verdict_str {
            "PASS" => TrustVerdict::Pass,
            "FLAG" => TrustVerdict::Flag {
                reason: response["verdict"]["reason"]
                    .as_str()
                    .unwrap_or("flagged")
                    .to_string(),
            },
            _ => TrustVerdict::Block {
                reason: response["verdict"]["reason"]
                    .as_str()
                    .unwrap_or("blocked")
                    .to_string(),
            },
        })
    }

    /// Generate a 402 response body + header value for a resource that requires payment.
    pub fn payment_required_response(
        &self,
        amount_usdc_micro: u64,
        pay_to: &str,
        chain_id: u64,
        mandate_hash: Option<&str>,
    ) -> Result<(u16, String, String), X402Error> {
        let mut pr = PaymentRequired::new(amount_usdc_micro, pay_to, chain_id);
        if let Some(hash) = mandate_hash {
            pr = pr.with_mandate(hash);
        }
        let header = pr.to_header_value()?;
        let body = serde_json::to_string(&serde_json::json!({
            "error": "Payment Required",
            "x402_version": "1.0",
            "payment_required": pr,
        }))
        .map_err(|e| X402Error::Serialization(e.to_string()))?;
        Ok((402, header, body))
    }
}
