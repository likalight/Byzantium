//! x402 HTTP Payment Rail Adapter for Byzantium.
//!
//! x402 is an open HTTP-native payment protocol built on EIP-3009.
//! Flow:
//!   1. Resource server returns 402 + `X-Payment-Required` header with payment details.
//!   2. Client makes payment (USDC on Base) and includes `X-Payment-Proof` in next request.
//!   3. This adapter: verifies payment proof AND calls Byzantium trust-check before
//!      allowing the request through.
//!
//! Reference: https://x402.org

pub mod error;
pub mod payment;
pub mod verifier;

use byz_common::{ActionType, AgentDid, TrustVerdict};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use error::X402Error;
pub use verifier::X402Verifier;

/// Payment details broadcast in the 402 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequired {
    /// x402 scheme version
    pub version: String,
    /// Amount in USDC (micro-units, 6 decimals)
    pub amount: u64,
    /// EVM-compatible payment address
    pub pay_to: String,
    /// Chain ID (e.g. 8453 for Base)
    pub chain_id: u64,
    /// Unique nonce to prevent replay attacks
    pub nonce: Uuid,
    /// Payment deadline
    pub expires_at: DateTime<Utc>,
    /// Byzantium mandate hash — binds this payment to the agent's policy
    pub mandate_hash: Option<String>,
}

impl PaymentRequired {
    pub fn new(amount_usdc_micro: u64, pay_to: impl Into<String>, chain_id: u64) -> Self {
        Self {
            version: "x402/1.0".to_string(),
            amount: amount_usdc_micro,
            pay_to: pay_to.into(),
            chain_id,
            nonce: Uuid::new_v4(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            mandate_hash: None,
        }
    }

    pub fn with_mandate(mut self, hash: impl Into<String>) -> Self {
        self.mandate_hash = Some(hash.into());
        self
    }

    pub fn to_header_value(&self) -> Result<String, X402Error> {
        let json = serde_json::to_string(self)
            .map_err(|e| X402Error::Serialization(e.to_string()))?;
        Ok(base64::encode(json))
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// EIP-3009 transferWithAuthorization proof submitted by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    pub from: String,
    pub to: String,
    pub value: u64,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: String,
    /// ECDSA signature over the EIP-712 hash
    pub signature: String,
    /// Chain the payment was made on
    pub chain_id: u64,
    /// Byzantium-issued PassToken (from prior trust-check)
    pub pass_token: Option<String>,
}

/// Result of verifying an x402 payment + trust-check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402VerificationResult {
    pub payment_valid: bool,
    pub trust_verdict: TrustVerdict,
    pub agent_did: AgentDid,
    pub amount_usdc_micro: u64,
    pub verified_at: DateTime<Utc>,
    pub request_id: Uuid,
}

impl X402VerificationResult {
    pub fn is_allowed(&self) -> bool {
        self.payment_valid && self.trust_verdict.is_pass()
    }
}
