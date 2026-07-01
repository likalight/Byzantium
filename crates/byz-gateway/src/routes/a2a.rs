//! POST /v1/a2a/check — trust-check an inbound A2A message before forwarding.
//!
//! The request body is the raw A2A JSON-RPC message (see `A2AMessage`).
//! The handler runs both sender and recipient DIDs through Byzantium and
//! returns the combined trust verdict together with the augmented message
//! (or null when the message is blocked).

use axum::{extract::State, http::StatusCode, Json};
use byz_common::TrustVerdict;
use byz_rail_a2a::{A2AMessage, A2AProxy};
use serde::Serialize;
use serde_json::Value;

use crate::state::AppState;

/// Response returned by the A2A check endpoint.
#[derive(Debug, Serialize)]
pub struct A2ACheckResponse {
    pub verdict: String,
    /// Present on PASS/FLAG; null when the message is blocked.
    pub trusted_message: Option<Value>,
    pub reason: String,
}

pub async fn check_a2a(
    State(state): State<AppState>,
    Json(msg): Json<A2AMessage>,
) -> Result<Json<A2ACheckResponse>, (StatusCode, Json<Value>)> {
    let gateway_url = format!("http://127.0.0.1:{}", state.config.gateway.port);
    let api_key = state
        .config
        .gateway
        .api_keys
        .first()
        .cloned()
        .unwrap_or_default();

    // Require both agents to score at least 0.5 cross-trust.
    let proxy = A2AProxy::new(&gateway_url, &api_key, 0.5);

    // Run the trust check.
    let trust_result = match proxy.check(&msg).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "a2a trust check returned an error");
            return Ok(Json(A2ACheckResponse {
                verdict: "BLOCK".to_string(),
                trusted_message: None,
                reason: e.to_string(),
            }));
        }
    };

    let verdict_str = if trust_result.from_verdict.is_pass() && trust_result.to_verdict.is_pass() {
        match (&trust_result.from_verdict, &trust_result.to_verdict) {
            (TrustVerdict::Pass, TrustVerdict::Pass) => "PASS",
            _ => "FLAG",
        }
    } else {
        // Either from or to was flagged (cross_trust < threshold falls back to FLAG).
        match (&trust_result.from_verdict, &trust_result.to_verdict) {
            (TrustVerdict::Block { .. }, _) | (_, TrustVerdict::Block { .. }) => "BLOCK",
            _ => "FLAG",
        }
    };

    let reason = match verdict_str {
        "PASS" => "trust-check passed".to_string(),
        "FLAG" => format!(
            "cross-trust score {:.2} may be below acceptable threshold",
            trust_result.cross_trust_score
        ),
        _ => "sender or recipient blocked by Byzantium".to_string(),
    };

    // Wrap the message with trust metadata when it is allowed through.
    let trusted_message = if trust_result.allowed {
        match proxy.wrap(msg).await {
            Ok(wrapped) => serde_json::to_value(wrapped).ok(),
            Err(e) => {
                tracing::warn!(error = %e, "a2a wrap failed after passing trust check");
                None
            }
        }
    } else {
        None
    };

    tracing::info!(
        request_id  = %trust_result.request_id,
        verdict     = verdict_str,
        cross_score = trust_result.cross_trust_score,
        "a2a trust check",
    );

    if trust_result.allowed {
        state.metrics.record_trust_check("PASS", 0);
    }

    Ok(Json(A2ACheckResponse {
        verdict: verdict_str.to_string(),
        trusted_message,
        reason,
    }))
}
