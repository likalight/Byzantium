//! Mandate builder and Merkle-root computation.
//!
//! The mandate root is SHA-256(JSON-canonical(mandate_fields)).
//! It is ML-DSA signed by the operator's key and stored in the TEE.
//! The ZK mandate-compliance circuit (byz-proof) proves range/membership
//! constraints against this root without revealing the policy internals.

use byz_common::{ActionType, AgentDid, ByzResult, SpendMandate};
use byz_crypto::sha256_hex;
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::HashSet;
use uuid::Uuid;

pub struct MandateBuilder {
    agent_did: AgentDid,
    operator_id: String,
    counterparty_whitelist: HashSet<String>,
    allowed_action_types: Vec<ActionType>,
    per_tx_cap_cents: u64,
    daily_cap_cents: u64,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

impl MandateBuilder {
    pub fn new(agent_did: AgentDid, operator_id: impl Into<String>) -> Self {
        Self {
            agent_did,
            operator_id: operator_id.into(),
            counterparty_whitelist: HashSet::new(),
            allowed_action_types: vec![],
            per_tx_cap_cents: 0,
            daily_cap_cents: 0,
            valid_from: Utc::now(),
            valid_until: Utc::now() + chrono::Duration::days(30),
        }
    }

    pub fn allow_counterparty(mut self, id: impl Into<String>) -> Self {
        self.counterparty_whitelist.insert(id.into());
        self
    }

    pub fn allow_action(mut self, action: ActionType) -> Self {
        self.allowed_action_types.push(action);
        self
    }

    pub fn per_tx_cap_cents(mut self, cents: u64) -> Self {
        self.per_tx_cap_cents = cents;
        self
    }

    pub fn daily_cap_cents(mut self, cents: u64) -> Self {
        self.daily_cap_cents = cents;
        self
    }

    pub fn valid_from(mut self, dt: DateTime<Utc>) -> Self {
        self.valid_from = dt;
        self
    }

    pub fn valid_until(mut self, dt: DateTime<Utc>) -> Self {
        self.valid_until = dt;
        self
    }

    /// Build the mandate and compute its Merkle root.
    /// Caller is responsible for signing with the operator's Dilithium key.
    pub fn build(self) -> ByzResult<SpendMandate> {
        let id = Uuid::new_v4();
        let whitelist_sorted: Vec<&str> = {
            let mut v: Vec<&str> = self.counterparty_whitelist.iter().map(String::as_str).collect();
            v.sort_unstable();
            v
        };

        // Canonical JSON for the mandate root commitment.
        // The ZK circuit proves constraints against this root.
        let canonical = json!({
            "id": id.to_string(),
            "agent_did": self.agent_did.as_str(),
            "operator_id": self.operator_id,
            "counterparty_whitelist": whitelist_sorted,
            "allowed_action_types": self.allowed_action_types,
            "per_tx_cap_cents": self.per_tx_cap_cents,
            "daily_cap_cents": self.daily_cap_cents,
            "valid_from": self.valid_from.timestamp(),
            "valid_until": self.valid_until.timestamp(),
        });
        let canonical_bytes = serde_json::to_vec(&canonical)?;
        let mandate_root = sha256_hex(&canonical_bytes);

        Ok(SpendMandate {
            id,
            agent_did: self.agent_did,
            operator_id: self.operator_id,
            counterparty_whitelist: self.counterparty_whitelist,
            allowed_action_types: self.allowed_action_types,
            per_tx_cap_cents: self.per_tx_cap_cents,
            daily_cap_cents: self.daily_cap_cents,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            mandate_root: Some(mandate_root),
            signature: None,
            operator_pubkey: None,
        })
    }
}
