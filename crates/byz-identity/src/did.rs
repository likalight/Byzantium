//! W3C Decentralized Identifier (DID) management for Byzantium agents.
//!
//! DID format: did:byz:<agent_uuid>
//! DID documents are stored in immudb (tamper-evident) and resolved locally.

use byz_common::{AgentDid, ByzResult, ByzantiumError};
use byz_crypto::DilithiumPublicKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub key_type: String,
    pub controller: String,
    /// ML-DSA (Dilithium3) public key, hex-encoded
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub controller: Option<String>,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    /// Operator who controls this agent
    pub operator_id: String,
    /// KYB/KYA status from zkMe (consumed, not built)
    pub kyb_verified: bool,
    pub active: bool,
}

impl DidDocument {
    pub fn new(agent_id: Uuid, operator_id: &str, public_key: &DilithiumPublicKey) -> Self {
        let did = format!("did:byz:{agent_id}");
        let vm_id = format!("{did}#key-1");
        let now = Utc::now();

        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: did.clone(),
            controller: Some(format!("did:byz:operator:{operator_id}")),
            verification_method: vec![VerificationMethod {
                id: vm_id.clone(),
                key_type: "MlDsaVerificationKey2024".to_string(),
                controller: did,
                public_key_hex: public_key.to_hex(),
            }],
            authentication: vec![vm_id],
            created: now,
            updated: now,
            operator_id: operator_id.to_string(),
            kyb_verified: false,
            active: true,
        }
    }

    pub fn did(&self) -> AgentDid {
        AgentDid::new(&self.id)
    }

    pub fn primary_public_key(&self) -> ByzResult<DilithiumPublicKey> {
        let vm = self
            .verification_method
            .first()
            .ok_or_else(|| ByzantiumError::CredentialInvalid)?;
        DilithiumPublicKey::from_hex(&vm.public_key_hex)
    }
}

/// Thin in-process resolver backed by a map — in production backed by immudb.
pub struct DidResolver {
    store: std::collections::HashMap<String, DidDocument>,
}

impl DidResolver {
    pub fn new() -> Self {
        Self {
            store: std::collections::HashMap::new(),
        }
    }

    pub fn register(&mut self, doc: DidDocument) {
        self.store.insert(doc.id.clone(), doc);
    }

    pub fn resolve(&self, did: &AgentDid) -> ByzResult<&DidDocument> {
        self.store
            .get(did.as_str())
            .ok_or_else(|| ByzantiumError::AgentNotFound(did.to_string()))
    }

    pub fn deactivate(&mut self, did: &AgentDid) -> ByzResult<()> {
        let doc = self
            .store
            .get_mut(did.as_str())
            .ok_or_else(|| ByzantiumError::AgentNotFound(did.to_string()))?;
        doc.active = false;
        doc.updated = Utc::now();
        Ok(())
    }
}

impl Default for DidResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple DID builder — generates a new UUID-based DID.
pub struct Did;

impl Did {
    pub fn generate() -> (Uuid, AgentDid) {
        let id = Uuid::new_v4();
        (id, AgentDid::new(format!("did:byz:{id}")))
    }

    pub fn parse_uuid(did: &AgentDid) -> ByzResult<Uuid> {
        let s = did.as_str();
        let suffix = s
            .strip_prefix("did:byz:")
            .ok_or_else(|| ByzantiumError::AgentNotFound(s.to_string()))?;
        Uuid::parse_str(suffix)
            .map_err(|_| ByzantiumError::AgentNotFound(s.to_string()))
    }
}
