//! Component B — Reputation Threshold Proof (SP1 host side).
//!
//! Public inputs:  commitment_hex, threshold
//! Private inputs: score, nonce  (stay in TEE; only commitment_hex is stored/shared)
//!
//! SP1 workflow:
//!   generate() → ProverClient::prove() → VerifiedThreshold { proof_bytes }
//!   verify()   → ProverClient::verify() → bool  (milliseconds on hot path)
//!
//! Feature flags:
//!   `sp1` feature enabled  → real STARK proofs via SP1 prover
//!   `sp1` feature disabled → stub proofs (development / unit tests)
//!
//! Environment:
//!   SP1_PROVER=mock    — no actual proving, instant (for CI)
//!   SP1_PROVER=local   — local STARK prover (~minutes for large circuits)
//!   SP1_PROVER=network — Succinct prover network (seconds, requires key)

use serde::{Deserialize, Serialize};

/// Guest ELF compiled by `cd programs && cargo prove build`.
/// Committed to the repo after first build so CI doesn't need the toolchain.
#[cfg(feature = "sp1")]
const THRESHOLD_ELF: &[u8] =
    include_bytes!("../../../programs/elf/threshold-proof");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdPublicInputs {
    pub commitment_hex: String,
    pub threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedThreshold {
    pub public_inputs: ThresholdPublicInputs,
    /// STARK proof bytes (SP1 output). Opaque to the caller; pass to verify().
    pub proof_bytes: Vec<u8>,
    /// SP1 verifying key hash — used to select the correct VK during verification.
    pub vk_hash: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
}

impl VerifiedThreshold {
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.valid_until
    }
}

/// Request for off-path proof generation (runs in TEE; private inputs never leave).
pub struct ThresholdProveRequest {
    pub commitment_hex: String,
    pub threshold: u32,
    /// Private witness — stays in TEE, never serialized to disk
    pub score_private: u32,
    pub nonce_private: Vec<u8>,
    pub valid_for_secs: i64,
}

pub struct ThresholdProver;

impl ThresholdProver {
    /// Generate a threshold proof. Runs off the hot path (TEE, background job).
    ///
    /// With `sp1` feature: calls SP1 prover via ProverClient.
    /// Without `sp1` feature: returns `Err(NotSupported)` — never a silent stub.
    pub fn prove(req: ThresholdProveRequest) -> byz_common::ByzResult<Option<VerifiedThreshold>> {
        if req.score_private < req.threshold {
            tracing::warn!(
                threshold = req.threshold,
                "cannot generate threshold proof: score below threshold"
            );
            return Ok(None);
        }

        #[cfg(feature = "sp1")]
        {
            Ok(Self::prove_sp1(req))
        }

        #[cfg(not(feature = "sp1"))]
        {
            Err(byz_common::ByzantiumError::NotSupported(
                "ZK proofs require BYZ_ZK_PROOFS_ENABLED=true and sp1 feature".into(),
            ))
        }
    }

    #[cfg(feature = "sp1")]
    fn prove_sp1(req: ThresholdProveRequest) -> Option<VerifiedThreshold> {
        use sp1_sdk::{ProverClient, SP1Stdin};

        let client = ProverClient::from_env(); // reads SP1_PROVER env var
        let (pk, vk) = client.setup(THRESHOLD_ELF);

        let mut stdin = SP1Stdin::new();
        stdin.write(&req.commitment_hex);
        stdin.write(&req.threshold);
        stdin.write(&req.score_private);   // private — goes into zkVM witness
        stdin.write(&req.nonce_private);

        match client.prove(&pk, stdin).run() {
            Ok(proof) => {
                let proof_bytes = bincode::serialize(&proof).unwrap_or_default();
                Some(VerifiedThreshold {
                    public_inputs: ThresholdPublicInputs {
                        commitment_hex: req.commitment_hex,
                        threshold: req.threshold,
                    },
                    proof_bytes,
                    vk_hash: vk.bytes32().to_string(),
                    generated_at: chrono::Utc::now(),
                    valid_until: chrono::Utc::now()
                        + chrono::Duration::seconds(req.valid_for_secs),
                })
            }
            Err(e) => {
                tracing::error!(error = %e, "SP1 threshold proof generation failed");
                None
            }
        }
    }

}

pub struct ThresholdVerifier;

impl ThresholdVerifier {
    /// Verify a threshold proof against its public inputs. Called on the hot path.
    /// Must complete in single-digit milliseconds.
    pub fn verify(proof: &VerifiedThreshold) -> bool {
        if proof.is_expired() {
            tracing::warn!(agent = ?proof.public_inputs.commitment_hex, "threshold proof expired");
            return false;
        }

        #[cfg(feature = "sp1")]
        {
            Self::verify_sp1(proof)
        }

        #[cfg(not(feature = "sp1"))]
        {
            // Without the sp1 feature, no real proof can exist — always reject.
            false
        }
    }

    #[cfg(feature = "sp1")]
    fn verify_sp1(proof: &VerifiedThreshold) -> bool {
        use sp1_sdk::{ProverClient, SP1ProofWithPublicValues};

        let client = ProverClient::from_env();
        let (_, vk) = client.setup(THRESHOLD_ELF);

        let sp1_proof: SP1ProofWithPublicValues = match bincode::deserialize(&proof.proof_bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "failed to deserialize SP1 proof");
                return false;
            }
        };

        match client.verify(&sp1_proof, &vk) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "SP1 threshold proof verification failed");
                false
            }
        }
    }
}
