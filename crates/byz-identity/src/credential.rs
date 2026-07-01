//! Verifiable credentials for Byzantium agents.
//!
//! A credential is a Merkle tree of attributes. The issuer ML-DSA-signs the root.
//! This keeps expensive signature verification outside ZK circuits — a circuit
//! only needs to prove attribute membership against the signed root.
//!
//! Component A (credential_disclosure circuit) proves:
//!   SHA-256-Merkle(attr_value, salt, path) == cred_root  &&  predicate(attr_value) == true
//! without revealing the credential contents or other attributes.

use byz_common::{AgentDid, ByzResult, ByzantiumError};
use byz_crypto::{merkle::MerkleTree, DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAttribute {
    pub name: String,
    pub value: String,
    /// Per-attribute blinding salt (hex) prevents correlation across presentations
    pub salt: String,
}

impl CredentialAttribute {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        use rand::RngCore;
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            name: name.into(),
            value: value.into(),
            salt: hex::encode(salt),
        }
    }

    /// Canonical leaf bytes: SHA-256(name || ":" || value || salt_bytes)
    pub fn leaf_bytes(&self) -> Vec<u8> {
        let salt = hex::decode(&self.salt).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(self.name.as_bytes());
        h.update(b":");
        h.update(self.value.as_bytes());
        h.update(&salt);
        h.finalize().to_vec()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub subject_did: AgentDid,
    pub issuer_did: String,
    pub attributes: Vec<CredentialAttribute>,
    /// SHA-256 Merkle root over attribute leaf bytes
    pub merkle_root: String,
    /// ML-DSA signature by issuer over merkle_root bytes
    pub issuer_signature: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Credential {
    pub fn is_valid(&self) -> bool {
        self.issuer_signature.is_some()
            && self
                .expires_at
                .map(|exp| Utc::now() < exp)
                .unwrap_or(true)
    }

    pub fn attribute(&self, name: &str) -> ByzResult<&CredentialAttribute> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| ByzantiumError::CredentialAttributeNotFound(name.to_string()))
    }

    /// Returns (attribute, merkle_proof) for selective disclosure.
    /// The verifier checks the proof against merkle_root, then evaluates the predicate.
    pub fn disclose(
        &self,
        attribute_name: &str,
    ) -> ByzResult<(&CredentialAttribute, byz_crypto::merkle::MerkleProof)> {
        let idx = self
            .attributes
            .iter()
            .position(|a| a.name == attribute_name)
            .ok_or_else(|| {
                ByzantiumError::CredentialAttributeNotFound(attribute_name.to_string())
            })?;

        let leaves: Vec<Vec<u8>> = self.attributes.iter().map(|a| a.leaf_bytes()).collect();
        let tree = MerkleTree::new(&leaves);
        let proof = tree.proof(idx)?;

        Ok((&self.attributes[idx], proof))
    }
}

pub struct CredentialIssuer {
    pub issuer_did: String,
    keypair: DilithiumKeypair,
}

impl CredentialIssuer {
    pub fn new(issuer_did: impl Into<String>, keypair: DilithiumKeypair) -> Self {
        Self {
            issuer_did: issuer_did.into(),
            keypair,
        }
    }

    pub fn issue(
        &self,
        subject_did: AgentDid,
        attributes: Vec<CredentialAttribute>,
        expires_at: Option<DateTime<Utc>>,
    ) -> ByzResult<Credential> {
        let leaves: Vec<Vec<u8>> = attributes.iter().map(|a| a.leaf_bytes()).collect();
        let tree = MerkleTree::new(&leaves);
        let root_hex = tree.root_hex();

        let sig = self.keypair.sign(root_hex.as_bytes())?;

        Ok(Credential {
            id: Uuid::new_v4(),
            subject_did,
            issuer_did: self.issuer_did.clone(),
            attributes,
            merkle_root: root_hex,
            issuer_signature: Some(hex::encode(sig.as_bytes())),
            issued_at: Utc::now(),
            expires_at,
        })
    }

    pub fn public_key(&self) -> &DilithiumPublicKey {
        &self.keypair.public_key
    }
}

pub struct CredentialVerifier {
    pub issuer_public_key: DilithiumPublicKey,
}

impl CredentialVerifier {
    pub fn new(issuer_public_key: DilithiumPublicKey) -> Self {
        Self { issuer_public_key }
    }

    /// Verify the issuer's signature over the credential's Merkle root.
    pub fn verify_credential(&self, cred: &Credential) -> ByzResult<()> {
        if !cred.is_valid() {
            return Err(ByzantiumError::CredentialInvalid);
        }
        let sig_hex = cred
            .issuer_signature
            .as_ref()
            .ok_or(ByzantiumError::CredentialInvalid)?;
        let sig_bytes =
            hex::decode(sig_hex).map_err(|_| ByzantiumError::CredentialInvalid)?;
        let sig = DilithiumSignature(sig_bytes);
        byz_crypto::dilithium::verify(
            cred.merkle_root.as_bytes(),
            &sig,
            &self.issuer_public_key,
        )
    }

    /// Verify that an attribute is present in a credential and satisfies a predicate.
    /// Checks: (1) signature over root, (2) Merkle proof, (3) predicate(value).
    pub fn verify_attribute_predicate(
        &self,
        cred: &Credential,
        attribute_name: &str,
        predicate: impl Fn(&str) -> bool,
    ) -> ByzResult<bool> {
        self.verify_credential(cred)?;

        let (attr, proof) = cred.disclose(attribute_name)?;

        // Verify Merkle proof against the signed root
        proof.verify(&cred.merkle_root)?;

        Ok(predicate(&attr.value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_issuer() -> CredentialIssuer {
        let kp = DilithiumKeypair::generate();
        CredentialIssuer::new("did:byz:issuer:test", kp)
    }

    #[test]
    fn issue_and_verify() {
        let issuer = make_issuer();
        let verifier = CredentialVerifier::new(issuer.public_key().clone());

        let attrs = vec![
            CredentialAttribute::new("operator_kyb", "verified"),
            CredentialAttribute::new("agent_role", "payment_facilitator"),
            CredentialAttribute::new("jurisdiction", "SG"),
        ];
        let subject = AgentDid::new("did:byz:00000000-0000-0000-0000-000000000001");
        let cred = issuer.issue(subject, attrs, None).unwrap();

        verifier.verify_credential(&cred).expect("credential must verify");
    }

    #[test]
    fn selective_disclosure() {
        let issuer = make_issuer();
        let verifier = CredentialVerifier::new(issuer.public_key().clone());

        let attrs = vec![
            CredentialAttribute::new("operator_kyb", "verified"),
            CredentialAttribute::new("agent_role", "payment_facilitator"),
        ];
        let subject = AgentDid::new("did:byz:00000000-0000-0000-0000-000000000002");
        let cred = issuer.issue(subject, attrs, None).unwrap();

        let ok = verifier
            .verify_attribute_predicate(&cred, "operator_kyb", |v| v == "verified")
            .unwrap();
        assert!(ok);
    }
}
