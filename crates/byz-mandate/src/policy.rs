//! Mandate builder and Merkle-root computation.
//!
//! The mandate root is SHA-256(JSON-canonical(mandate_fields)).
//! It is ML-DSA signed by the operator's key and stored in the TEE.
//! The ZK mandate-compliance circuit (byz-proof) proves range/membership
//! constraints against this root without revealing the policy internals.

use byz_common::{ActionType, AgentDid, ByzResult, ByzantiumError, SpendMandate};
use byz_crypto::sha256_hex;
use byz_underwrite::UnderwritingDecision;
use chrono::{DateTime, Duration, Utc};
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

    /// Build a mandate from an underwriting decision rather than from numbers an
    /// operator typed.
    ///
    /// This is the inversion the whole system turns on. `per_tx_cap_cents` and
    /// `daily_cap_cents` stop being configuration and become the output of a risk
    /// process, which is what makes the resulting mandate portable: the same
    /// evidence produces the same caps wherever it is presented.
    ///
    /// Note that the cap fields carry minor units of the decision's unit of
    /// account, which is not necessarily USD despite the historical field names.
    ///
    /// The counterparty whitelist stays with the operator. Underwriting decides
    /// *how much*; it does not decide *who* an agent is allowed to pay.
    pub fn from_decision(
        decision: &UnderwritingDecision,
        operator_id: impl Into<String>,
        counterparty_whitelist: Vec<String>,
    ) -> ByzResult<SpendMandate> {
        if !decision.is_issued() {
            return Err(ByzantiumError::MandateViolation(
                "cannot build a mandate from a refused underwriting decision".to_string(),
            ));
        }

        let mut builder = MandateBuilder::new(decision.agent_did.clone(), operator_id)
            .per_tx_cap_cents(decision.lim_single.minor_units)
            .daily_cap_cents(decision.lim_window.minor_units)
            .valid_from(Utc::now())
            .valid_until(Utc::now() + Duration::seconds(decision.window_secs as i64));

        for id in counterparty_whitelist {
            builder = builder.allow_counterparty(id);
        }

        // An empty action scope would otherwise block every action, since
        // `allows_action` requires membership.
        if decision.scope.action_types.is_empty() {
            builder = builder.allow_action(ActionType::Payment);
        } else {
            for action in &decision.scope.action_types {
                builder = builder.allow_action(action.clone());
            }
        }

        builder.build()
    }

    /// Build the mandate and compute its Merkle root.
    /// Caller is responsible for signing with the operator's Dilithium key.
    pub fn build(self) -> ByzResult<SpendMandate> {
        let id = Uuid::new_v4();
        let whitelist_sorted: Vec<&str> = {
            let mut v: Vec<&str> = self
                .counterparty_whitelist
                .iter()
                .map(String::as_str)
                .collect();
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
