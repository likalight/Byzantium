//! A2AProxy — trust-aware proxy for A2A JSON-RPC endpoints.
//!
//! Deploy in front of your A2A agent endpoint. All inbound A2A messages are
//! trust-checked before being forwarded to the underlying agent.

use chrono::Utc;
use uuid::Uuid;

use byz_common::TrustVerdict;

use crate::{
    error::A2AError,
    message::{extract_amount_cents, extract_recipient_did, extract_sender_did},
    A2AMessage, A2ATrustResult, TrustedA2AMessage,
};

pub struct A2AProxy {
    byzantium_url: String,
    api_key: String,
    /// Minimum cross-agent trust score to allow delegation (0.0–1.0)
    min_cross_trust: f64,
    http: reqwest::Client,
}

impl A2AProxy {
    pub fn new(
        byzantium_url: impl Into<String>,
        api_key: impl Into<String>,
        min_cross_trust: f64,
    ) -> Self {
        Self {
            byzantium_url: byzantium_url.into(),
            api_key: api_key.into(),
            min_cross_trust: min_cross_trust.clamp(0.0, 1.0),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(190))
                .build()
                .expect("http client"),
        }
    }

    /// Check an inbound A2A message for trust before forwarding.
    pub async fn check(&self, msg: &A2AMessage) -> Result<A2ATrustResult, A2AError> {
        let from_did = extract_sender_did(msg)?;
        let to_did = extract_recipient_did(msg)?;
        let amount_cents = extract_amount_cents(msg);

        // Check both agents in parallel
        let (from_verdict, to_verdict) = tokio::try_join!(
            self.trust_check(from_did.as_str(), amount_cents, "a2a-sender"),
            self.trust_check(to_did.as_str(), None, "a2a-recipient"),
        )?;

        let cross_trust_score = compute_cross_trust(&from_verdict, &to_verdict);

        let allowed = from_verdict.is_pass()
            && to_verdict.is_pass()
            && cross_trust_score >= self.min_cross_trust;

        if !allowed {
            if let TrustVerdict::Block { ref reason } = from_verdict {
                return Err(A2AError::SenderBlocked {
                    did: from_did.to_string(),
                    reason: reason.clone(),
                });
            }
            if let TrustVerdict::Block { ref reason } = to_verdict {
                return Err(A2AError::RecipientBlocked {
                    did: to_did.to_string(),
                    reason: reason.clone(),
                });
            }
            if cross_trust_score < self.min_cross_trust {
                return Err(A2AError::CrossTrustTooLow {
                    score: cross_trust_score,
                    threshold: self.min_cross_trust,
                });
            }
        }

        Ok(A2ATrustResult {
            allowed,
            from_verdict,
            to_verdict,
            request_id: Uuid::new_v4(),
            checked_at: Utc::now(),
            cross_trust_score,
        })
    }

    /// Wrap a message with Byzantium trust metadata.
    pub async fn wrap(&self, msg: A2AMessage) -> Result<TrustedA2AMessage, A2AError> {
        let from_did = extract_sender_did(&msg)?;
        let to_did = extract_recipient_did(&msg)?;
        let trust = self.check(&msg).await?;

        Ok(TrustedA2AMessage {
            message: msg,
            from_agent_did: from_did,
            to_agent_did: to_did,
            pass_token: None, // populated by gateway after trust-check
            trust_checked_at: trust.checked_at,
        })
    }

    async fn trust_check(
        &self,
        agent_did: &str,
        amount_cents: Option<u64>,
        rail_id: &str,
    ) -> Result<TrustVerdict, A2AError> {
        let body = serde_json::json!({
            "agent_did": agent_did,
            "action_type": "cross_agent_delegation",
            "amount_cents": amount_cents,
            "rail_id": rail_id,
        });

        let resp = self
            .http
            .post(format!("{}/v1/trust-check", self.byzantium_url))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| A2AError::Gateway(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(A2AError::Gateway(format!("HTTP {}", resp.status())));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| A2AError::Gateway(e.to_string()))?;

        let verdict_str = body["verdict"]["verdict"]
            .as_str()
            .or_else(|| body["verdict"].as_str())
            .unwrap_or("BLOCK");

        Ok(match verdict_str {
            "PASS" => TrustVerdict::Pass,
            "FLAG" => TrustVerdict::Flag {
                reason: body["verdict"]["reason"].as_str().unwrap_or("flagged").to_string(),
            },
            _ => TrustVerdict::Block {
                reason: body["verdict"]["reason"].as_str().unwrap_or("blocked").to_string(),
            },
        })
    }
}

/// Simple cross-trust score: 1.0 if both pass, 0.5 if either flags, 0.0 if either blocks.
fn compute_cross_trust(from: &TrustVerdict, to: &TrustVerdict) -> f64 {
    match (from, to) {
        (TrustVerdict::Pass, TrustVerdict::Pass)   => 1.0,
        (TrustVerdict::Pass, TrustVerdict::Flag{..}) |
        (TrustVerdict::Flag{..}, TrustVerdict::Pass) => 0.5,
        _ => 0.0,
    }
}
