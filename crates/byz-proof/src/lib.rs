//! ZK proof generation and verification — four components, all STARK-based (post-quantum).
//!
//! Feature flags:
//!   (default) → stub proofs, compiles anywhere, safe for dev/CI
//!   sp1       → real SP1 STARK proofs; requires:
//!               1. `cargo prove` toolchain: curl -L https://sp1.succinct.xyz | bash && sp1up
//!               2. Build guest ELFs:        cd programs && cargo prove build
//!               3. Set SP1_PROVER env var:  mock | local | network
//!
//! Proof system rationale: SP1 is STARK-based (FRI + hash functions only).
//! No pairing assumptions → post-quantum safe. Consistent with Kyber-1024 commitment.

pub mod disclosure;
pub mod inclusion;
pub mod threshold;

pub use disclosure::{CredentialDisclosureProof, CredentialDisclosureRequest};
pub use inclusion::InclusionVerifier;
pub use threshold::{ThresholdProveRequest, ThresholdProver, ThresholdVerifier, VerifiedThreshold};

use serde::{Deserialize, Serialize};

/// Unified proof bundle cached in Redis per agent.
/// Redis TTL = min(threshold_proof.valid_until, credential_proof.valid_until) - now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedProofBundle {
    pub agent_did: String,
    pub threshold_proof: Option<Vec<u8>>,
    pub credential_proof: Option<Vec<u8>>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
}

impl CachedProofBundle {
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.valid_until
    }
}
