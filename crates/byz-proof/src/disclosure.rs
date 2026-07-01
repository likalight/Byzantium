//! Component A — Credential Disclosure Proof (SP1 host side).
//!
//! Proves: attr_value ∈ credential AND predicate(attr) == true
//! Without revealing: credential contents, other attributes.

use byz_crypto::merkle::MerkleProof;
use serde::{Deserialize, Serialize};

#[cfg(feature = "sp1")]
const DISCLOSURE_ELF: &[u8] =
    include_bytes!("../../../programs/elf/disclosure-proof");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisclosureRequest {
    pub credential_id: uuid::Uuid,
    pub attribute_name: String,
    pub predicate_id: String,
    pub cred_root: String,
    pub issuer_id: String,
    pub merkle_proof: MerkleProof,
    /// Private — stays in TEE, drives the circuit witness
    pub attribute_value_private: String,
    pub attribute_salt_private: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisclosureProof {
    pub cred_root: String,
    pub issuer_id: String,
    pub predicate_id: String,
    pub predicate_result: bool,
    pub proof_bytes: Vec<u8>,
    pub vk_hash: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
}

impl CredentialDisclosureProof {
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.valid_until
    }

    pub fn generate(req: &CredentialDisclosureRequest) -> byz_common::ByzResult<Self> {
        #[cfg(feature = "sp1")]
        {
            Ok(Self::generate_sp1(req))
        }

        #[cfg(not(feature = "sp1"))]
        {
            Err(byz_common::ByzantiumError::NotSupported(
                "ZK proofs require BYZ_ZK_PROOFS_ENABLED=true and sp1 feature".into(),
            ))
        }
    }

    #[cfg(feature = "sp1")]
    fn generate_sp1(req: &CredentialDisclosureRequest) -> Self {
        use sp1_sdk::{ProverClient, SP1Stdin};

        let client = ProverClient::from_env();
        let (pk, vk) = client.setup(DISCLOSURE_ELF);

        // Build Merkle path as (sibling_hash, is_right_sibling) pairs
        let path: Vec<(String, bool)> = req
            .merkle_proof
            .siblings
            .iter()
            .map(|s| {
                (
                    s.hash.clone(),
                    s.position == byz_crypto::merkle::SiblingPosition::Right,
                )
            })
            .collect();

        let mut stdin = SP1Stdin::new();
        stdin.write(&req.cred_root);
        stdin.write(&req.predicate_id);
        stdin.write(&req.attribute_value_private);
        stdin.write(&req.attribute_salt_private);
        stdin.write(&path);

        match client.prove(&pk, stdin).run() {
            Ok(proof) => {
                let proof_bytes = bincode::serialize(&proof).unwrap_or_default();
                Self {
                    cred_root: req.cred_root.clone(),
                    issuer_id: req.issuer_id.clone(),
                    predicate_id: req.predicate_id.clone(),
                    predicate_result: true,
                    proof_bytes,
                    vk_hash: vk.bytes32().to_string(),
                    generated_at: chrono::Utc::now(),
                    valid_until: chrono::Utc::now() + chrono::Duration::hours(1),
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "SP1 disclosure proof generation failed");
                panic!("SP1 disclosure proof generation failed: {e}");
            }
        }
    }

    pub fn verify(&self) -> bool {
        if self.is_expired() {
            return false;
        }

        #[cfg(feature = "sp1")]
        {
            use sp1_sdk::{ProverClient, SP1ProofWithPublicValues};
            let client = ProverClient::from_env();
            let (_, vk) = client.setup(DISCLOSURE_ELF);
            match bincode::deserialize::<SP1ProofWithPublicValues>(&self.proof_bytes) {
                Ok(proof) => client.verify(&proof, &vk).is_ok(),
                Err(_) => false,
            }
        }

        #[cfg(not(feature = "sp1"))]
        {
            // Without the sp1 feature, no real proof can exist — always reject.
            false
        }
    }
}

pub struct InclusionVerifier;

impl InclusionVerifier {
    pub fn verify_receipt_in_batch(
        proof: &byz_crypto::merkle::MerkleProof,
        batch_root: &str,
    ) -> byz_common::ByzResult<()> {
        proof.verify(batch_root)
    }
}
