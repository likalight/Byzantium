//! Liability receipt creation and ML-DSA signing.
//!
//! Each receipt is signed by the agent's TEE key (non-custodially — the AISA pattern).
//! The signature is over SHA-256(canonical_json(receipt_fields)).

use byz_common::{
    ActionType, AgentDid, ByzResult, Counterparty, LiabilityReceipt, ReceiptOutcome,
};
use byz_crypto::{sha256_hex, DilithiumKeypair};
use chrono::Utc;
use uuid::Uuid;

pub struct ReceiptSigner {
    keypair: DilithiumKeypair,
}

impl ReceiptSigner {
    pub fn new(keypair: DilithiumKeypair) -> Self {
        Self { keypair }
    }

    pub fn create_and_sign(
        &self,
        agent_did: AgentDid,
        action_type: ActionType,
        counterparty: Option<Counterparty>,
        amount_cents: Option<u64>,
        outcome: ReceiptOutcome,
        mandate_id: Uuid,
        rail_id: impl Into<String>,
    ) -> ByzResult<LiabilityReceipt> {
        let mut receipt = LiabilityReceipt {
            id: Uuid::new_v4(),
            agent_did,
            action_type,
            counterparty,
            amount_cents,
            outcome,
            mandate_id,
            rail_id: rail_id.into(),
            timestamp: Utc::now(),
            signature: None,
        };

        let hash_input = receipt.canonical_hash_input();
        let hash_bytes = sha256_hex(hash_input.as_bytes());
        let sig = self.keypair.sign(hash_bytes.as_bytes())?;
        receipt.signature = Some(sig.as_bytes().to_vec());

        Ok(receipt)
    }
}
