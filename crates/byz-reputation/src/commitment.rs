//! Score commitment and threshold proof scaffolding.
//!
//! The commitment is SHA-256(score_le_bytes || nonce) — published and anchored
//! so rails can verify a threshold proof was generated against the committed score.
//!
//! Inside the STARK circuit (byz-proof Component B) this becomes Poseidon2(score, nonce)
//! for circuit efficiency, with a range/bit-decomposition proof that score >= threshold.
//!
//! The proof is pre-generated on score refresh (every N minutes in the TEE),
//! cached in Redis, and only verified (never generated) on the hot path.

use byz_common::{AgentDid, ByzResult, ReputationScore};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreCommitment {
    pub agent_did: AgentDid,
    /// SHA-256(score_le_bytes || nonce) — the published commitment
    pub commitment_hex: String,
    pub nonce_hex: String,
    pub committed_at: chrono::DateTime<chrono::Utc>,
}

impl ScoreCommitment {
    pub fn new(score: &ReputationScore) -> ByzResult<Self> {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let score_bytes = score.score.to_le_bytes();
        let mut h = Sha256::new();
        h.update(score_bytes);
        h.update(nonce);
        let commitment = h.finalize();

        Ok(Self {
            agent_did: score.agent_did.clone(),
            commitment_hex: hex::encode(commitment),
            nonce_hex: hex::encode(nonce),
            committed_at: chrono::Utc::now(),
        })
    }

    /// Verify that a raw score opens to this commitment.
    pub fn verify_opening(&self, score: u32) -> bool {
        let nonce = match hex::decode(&self.nonce_hex) {
            Ok(n) => n,
            Err(_) => return false,
        };
        let score_bytes = score.to_le_bytes();
        let mut h = Sha256::new();
        h.update(score_bytes);
        h.update(&nonce);
        hex::encode(h.finalize()) == self.commitment_hex
    }
}

/// Request to generate a threshold proof off the hot path.
/// The resulting proof is cached and only verified synchronously.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdProofRequest {
    pub agent_did: AgentDid,
    pub commitment: ScoreCommitment,
    /// The threshold the rail wants to check against
    pub threshold: u32,
    /// Raw score (private — stays in TEE, never logged)
    pub score_private: u32,
    pub nonce_private: Vec<u8>,
}

/// Placeholder for the actual STARK proof bytes.
/// In production: SP1/Winterfell proof bytes that the verifier checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdProof {
    pub agent_did: AgentDid,
    pub commitment_hex: String,
    pub threshold: u32,
    /// STARK proof bytes (SP1 or Winterfell output)
    pub proof_bytes: Vec<u8>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
}

impl ThresholdProof {
    /// Stub: real implementation calls the SP1/Winterfell prover inside the TEE.
    /// The prover takes (score, nonce) as private witness and (commitment, threshold) as public.
    pub fn generate_stub(req: &ThresholdProofRequest) -> Option<Self> {
        if req.score_private < req.threshold {
            return None; // cannot generate a passing proof for a failing score
        }
        // In production: call sp1_sdk::ProverClient to generate the circuit proof.
        // For now, placeholder proof bytes so the rest of the system can be tested.
        let placeholder = format!(
            "STUB_PROOF:agent={},commitment={},threshold={}",
            req.agent_did, req.commitment.commitment_hex, req.threshold
        );
        Some(ThresholdProof {
            agent_did: req.agent_did.clone(),
            commitment_hex: req.commitment.commitment_hex.clone(),
            threshold: req.threshold,
            proof_bytes: placeholder.into_bytes(),
            generated_at: chrono::Utc::now(),
            valid_until: chrono::Utc::now() + chrono::Duration::minutes(30),
        })
    }

    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.valid_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::ReputationScore;

    fn make_score(score: u32) -> ReputationScore {
        ReputationScore {
            agent_did: AgentDid::new("did:byz:test"),
            score,
            compliance_rate: 0.9,
            violation_rate: 0.01,
            total_actions: 100,
            computed_at: chrono::Utc::now(),
            commitment: None,
            commitment_nonce: None,
        }
    }

    #[test]
    fn commitment_roundtrip() {
        let score = make_score(750);
        let c = ScoreCommitment::new(&score).unwrap();
        assert!(c.verify_opening(750));
        assert!(!c.verify_opening(749));
    }

    #[test]
    fn threshold_proof_stub() {
        let score_rep = make_score(800);
        let commitment = ScoreCommitment::new(&score_rep).unwrap();
        let nonce = hex::decode(&commitment.nonce_hex).unwrap();
        let req = ThresholdProofRequest {
            agent_did: score_rep.agent_did.clone(),
            commitment,
            threshold: 600,
            score_private: 800,
            nonce_private: nonce,
        };
        assert!(ThresholdProof::generate_stub(&req).is_some());

        // Cannot prove below threshold
        let req_fail = ThresholdProofRequest { score_private: 500, ..req };
        assert!(ThresholdProof::generate_stub(&req_fail).is_none());
    }
}
