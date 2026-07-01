//! A2A (Agent-to-Agent) Protocol Trust Adapter for Byzantium.
//!
//! The A2A protocol (Google / Anthropic) enables AI agents to communicate
//! and delegate tasks to each other via JSON-RPC over HTTP.
//!
//! This adapter intercepts A2A messages and validates both agents through
//! Byzantium before allowing the delegation to proceed.
//!
//! Integration pattern: run as a proxy / middleware in front of your A2A endpoint.

pub mod error;
pub mod message;
pub mod proxy;

use byz_common::{AgentDid, TrustVerdict};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use error::A2AError;
pub use proxy::A2AProxy;

/// Standard A2A JSON-RPC message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AMessage {
    pub jsonrpc: String,
    pub method: String,
    pub id: Uuid,
    pub params: serde_json::Value,
}

/// Byzantium-augmented A2A message — wraps A2A with trust metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedA2AMessage {
    #[serde(flatten)]
    pub message: A2AMessage,
    /// DID of the agent sending this message
    pub from_agent_did: AgentDid,
    /// DID of the target agent
    pub to_agent_did: AgentDid,
    /// Byzantium PassToken for the sender (valid for 30s)
    pub pass_token: Option<String>,
    pub trust_checked_at: DateTime<Utc>,
}

/// Result of trust-checking an A2A delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2ATrustResult {
    pub allowed: bool,
    pub from_verdict: TrustVerdict,
    pub to_verdict: TrustVerdict,
    pub request_id: Uuid,
    pub checked_at: DateTime<Utc>,
    /// Combined cross-agent trust score (0.0 – 1.0)
    pub cross_trust_score: f64,
}

impl A2ATrustResult {
    pub fn is_allowed(&self) -> bool {
        self.allowed
            && self.from_verdict.is_pass()
            && self.to_verdict.is_pass()
    }
}
