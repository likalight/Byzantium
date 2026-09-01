//! Provenance event types.
//!
//! Events carry hashes of payloads rather than payloads. The underwriter needs to
//! know that a tool call happened, in what order, and under whose approval — it
//! does not need the arguments, and collecting them would make the system an
//! exfiltration risk that no serious operator would integrate.

use byz_common::AgentDid;
use byz_crypto::sha256_hex;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

/// What kind of execution step this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    /// The agent invoked a tool or external capability.
    ToolCall,
    /// The agent committed to a plan before acting.
    Plan,
    /// The agent wrote to durable memory.
    MemoryWrite,
    /// A human approved a step. The strongest single provenance signal.
    HumanApproval,
    /// The agent recorded an observation from the environment.
    Observation,
    /// The agent initiated a payment. Cross-references a settlement receipt.
    PaymentIntent,
}

impl ProvenanceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProvenanceKind::ToolCall => "tool_call",
            ProvenanceKind::Plan => "plan",
            ProvenanceKind::MemoryWrite => "memory_write",
            ProvenanceKind::HumanApproval => "human_approval",
            ProvenanceKind::Observation => "observation",
            ProvenanceKind::PaymentIntent => "payment_intent",
        }
    }

    /// Relative weight when summarising a session. Human approval and completed
    /// payment intents say more about trustworthiness than raw tool chatter.
    pub fn weight(&self) -> u32 {
        match self {
            ProvenanceKind::HumanApproval => 5,
            ProvenanceKind::PaymentIntent => 4,
            ProvenanceKind::Plan => 2,
            ProvenanceKind::ToolCall => 1,
            ProvenanceKind::MemoryWrite => 1,
            ProvenanceKind::Observation => 1,
        }
    }
}

/// One step of execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceEvent {
    pub agent_did: AgentDid,
    /// Groups events from one agent run. Sequence numbers are scoped to this.
    pub session_id: Uuid,
    /// Monotonic within a session. Gaps and repeats are how replay and
    /// truncation are detected.
    pub seq: u64,
    pub kind: ProvenanceKind,
    pub at: DateTime<Utc>,
    /// Hash of the actual payload. The payload itself stays with the operator.
    pub payload_hash: String,
    /// Optional non-identifying label, e.g. the tool name.
    #[serde(default)]
    pub label: Option<String>,
    /// Whether the step completed successfully.
    pub ok: bool,
}

impl ProvenanceEvent {
    pub fn new(
        agent_did: AgentDid,
        session_id: Uuid,
        seq: u64,
        kind: ProvenanceKind,
        payload_hash: impl Into<String>,
    ) -> Self {
        Self {
            agent_did,
            session_id,
            seq,
            kind,
            at: Utc::now(),
            payload_hash: payload_hash.into(),
            label: None,
            ok: true,
        }
    }

    /// Convenience for callers holding the raw payload — hashes it here so the
    /// payload never has to be moved anywhere to be committed to.
    pub fn hashing_payload(
        agent_did: AgentDid,
        session_id: Uuid,
        seq: u64,
        kind: ProvenanceKind,
        payload: &[u8],
    ) -> Self {
        Self::new(
            agent_did,
            session_id,
            seq,
            kind,
            format!("sha256:{}", sha256_hex(payload)),
        )
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_ok(mut self, ok: bool) -> Self {
        self.ok = ok;
        self
    }

    pub fn at(mut self, when: DateTime<Utc>) -> Self {
        self.at = when;
        self
    }

    /// Canonical bytes the runtime signs. Deterministic key order.
    pub fn signing_payload(&self) -> Vec<u8> {
        let canonical = json!({
            "agent_did": self.agent_did.as_str(),
            "session_id": self.session_id.to_string(),
            "seq": self.seq,
            "kind": self.kind.as_str(),
            "at": self.at.timestamp_millis(),
            "payload_hash": self.payload_hash,
            "label": self.label,
            "ok": self.ok,
        });
        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    /// Leaf bytes for the evidence Merkle tree.
    pub fn leaf_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
}

/// A provenance event with the runtime's signature over it.
///
/// `runtime_id` names the key that signed, not the agent. An agent cannot
/// produce one of these for itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedProvenance {
    pub event: ProvenanceEvent,
    pub runtime_id: String,
    /// ML-DSA signature by the runtime key over `event.signing_payload()`.
    pub signature: Vec<u8>,
}

impl SignedProvenance {
    pub fn new(event: ProvenanceEvent, runtime_id: impl Into<String>, signature: Vec<u8>) -> Self {
        Self {
            event,
            runtime_id: runtime_id.into(),
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_payload_is_deterministic() {
        let e = ProvenanceEvent::new(
            AgentDid::new("did:byz:a"),
            Uuid::nil(),
            1,
            ProvenanceKind::ToolCall,
            "sha256:abc",
        );
        assert_eq!(e.signing_payload(), e.signing_payload());
    }

    #[test]
    fn changing_any_field_changes_the_signed_bytes() {
        let base = ProvenanceEvent::new(
            AgentDid::new("did:byz:a"),
            Uuid::nil(),
            1,
            ProvenanceKind::ToolCall,
            "sha256:abc",
        );
        let mut other = base.clone();
        other.seq = 2;
        assert_ne!(base.signing_payload(), other.signing_payload());

        let mut third = base.clone();
        third.ok = false;
        assert_ne!(base.signing_payload(), third.signing_payload());
    }

    #[test]
    fn payload_is_committed_to_by_hash_only() {
        let e = ProvenanceEvent::hashing_payload(
            AgentDid::new("did:byz:a"),
            Uuid::nil(),
            1,
            ProvenanceKind::MemoryWrite,
            b"secret business logic",
        );
        let signed = String::from_utf8(e.signing_payload()).unwrap();
        assert!(!signed.contains("secret business logic"));
        assert!(e.payload_hash.starts_with("sha256:"));
    }

    #[test]
    fn human_approval_outweighs_tool_chatter() {
        assert!(ProvenanceKind::HumanApproval.weight() > ProvenanceKind::ToolCall.weight());
    }
}
