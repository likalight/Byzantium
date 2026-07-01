use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentDid(pub String);

impl AgentDid {
    pub fn new(did: impl Into<String>) -> Self {
        Self(did.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Payment,
    ApiCall,
    DataAccess,
    ContractExecution,
    CrossAgentDelegation,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counterparty {
    pub id: String,
    pub chain: Option<String>,
    pub address: Option<String>,
}

/// Cryptographically signed policy defining what an agent may do.
/// Stored in TEE; the mandate_root is the Merkle root of all fields,
/// ML-DSA signed by the operator's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendMandate {
    pub id: Uuid,
    pub agent_did: AgentDid,
    pub operator_id: String,
    pub counterparty_whitelist: HashSet<String>,
    pub allowed_action_types: Vec<ActionType>,
    /// Per-transaction cap in USD cents
    pub per_tx_cap_cents: u64,
    /// Rolling 24h cap in USD cents
    pub daily_cap_cents: u64,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// SHA-256 Merkle root over mandate fields (used for ZK range/membership proofs)
    pub mandate_root: Option<String>,
    /// ML-DSA signature by operator over mandate_root
    pub signature: Option<Vec<u8>>,
    /// Operator's ML-DSA public key (hex)
    pub operator_pubkey: Option<String>,
}

impl SpendMandate {
    pub fn is_active(&self) -> bool {
        let now = Utc::now();
        now >= self.valid_from && now <= self.valid_until
    }

    pub fn allows_action(&self, action: &ActionType) -> bool {
        self.allowed_action_types.contains(action)
    }

    pub fn allows_counterparty(&self, counterparty_id: &str) -> bool {
        self.counterparty_whitelist.contains(counterparty_id)
    }

    pub fn allows_amount(&self, amount_cents: u64) -> bool {
        amount_cents <= self.per_tx_cap_cents
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustVerdict {
    Pass,
    Flag { reason: String },
    Block { reason: String },
}

impl TrustVerdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, TrustVerdict::Pass)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCheckRequest {
    pub agent_did: AgentDid,
    pub action_type: ActionType,
    pub amount_cents: Option<u64>,
    pub counterparty: Option<Counterparty>,
    pub rail_id: String,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCheckResponse {
    pub verdict: TrustVerdict,
    /// Only present on PASS; short-lived ML-DSA signed token for the rail
    pub token: Option<PassToken>,
    pub request_id: Uuid,
    pub checked_at: DateTime<Utc>,
    pub latency_ms: u64,
}

/// Short-lived signed assertion: agent passed at this moment, under this mandate.
/// Rail verifies the ML-DSA signature; verification is microseconds, never proving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassToken {
    pub agent_did: AgentDid,
    pub verdict: TrustVerdict,
    pub mandate_hash: String,
    pub reputation_threshold_met: bool,
    pub valid_until: DateTime<Utc>,
    /// ML-DSA signature by Byzantium's gateway key over the token payload
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiabilityReceipt {
    pub id: Uuid,
    pub agent_did: AgentDid,
    pub action_type: ActionType,
    pub counterparty: Option<Counterparty>,
    pub amount_cents: Option<u64>,
    pub outcome: ReceiptOutcome,
    pub mandate_id: Uuid,
    pub rail_id: String,
    pub timestamp: DateTime<Utc>,
    /// ML-DSA signature by the agent's TEE key over the receipt hash
    pub signature: Option<Vec<u8>>,
}

impl LiabilityReceipt {
    pub fn canonical_hash_input(&self) -> String {
        format!(
            "{}:{}:{:?}:{:?}:{}:{}",
            self.id,
            self.agent_did,
            self.action_type,
            self.amount_cents,
            self.mandate_id,
            self.timestamp.timestamp_millis()
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Success,
    Failed { reason: String },
    Pending,
}

/// Agent behavioral score. The raw score never leaves Byzantium.
/// Only the commitment and threshold-proof are shared with rails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub agent_did: AgentDid,
    /// 0–1000 composite behavioral score
    pub score: u32,
    pub compliance_rate: f64,
    pub violation_rate: f64,
    pub total_actions: u64,
    pub computed_at: DateTime<Utc>,
    /// SHA-256(score_bytes || nonce); published and anchored.
    /// Inside a STARK this would be Poseidon2(score, nonce).
    pub commitment: Option<String>,
    pub commitment_nonce: Option<String>,
}
