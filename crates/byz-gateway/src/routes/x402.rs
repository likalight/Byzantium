//! POST /v1/payments/x402/verify — verify an X-Payment-Receipt header from
//! an x402 payment flow before allowing the protected resource to be served.

use axum::{extract::State, http::StatusCode, Json};
use byz_common::TrustVerdict;
use byz_rail_x402::{payment::parse_required_header, PaymentRequired, X402Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::AppState;

/// Request body for the x402 verify endpoint.
#[derive(Debug, Deserialize)]
pub struct X402VerifyRequest {
    /// Base64-encoded X-Payment-Proof header value (EIP-3009 proof from client).
    pub payment_proof: String,
    /// Base64-encoded X-Payment-Required header value (payment request issued by server).
    pub payment_required: String,
    /// DID of the agent submitting the payment.
    pub agent_did: String,
}

/// Response returned by the x402 verify endpoint.
#[derive(Debug, Serialize)]
pub struct X402VerifyResponse {
    pub valid: bool,
    pub verdict: String,
    pub payment_id: String,
}

pub async fn verify_x402(
    State(state): State<AppState>,
    Json(req): Json<X402VerifyRequest>,
) -> Result<Json<X402VerifyResponse>, (StatusCode, Json<Value>)> {
    // Parse the PaymentRequired from the header value provided by the caller.
    let payment_required: PaymentRequired =
        parse_required_header(&req.payment_required).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid payment_required: {}", e) })),
            )
        })?;

    let gateway_url = format!("http://127.0.0.1:{}", state.config.gateway.port);
    let api_key = state
        .config
        .gateway
        .api_keys
        .first()
        .cloned()
        .unwrap_or_default();

    let verifier = X402Verifier::new(&gateway_url, &api_key);

    let result = verifier
        .verify(&req.payment_proof, &payment_required, &req.agent_did)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    let verdict_str = match &result.trust_verdict {
        TrustVerdict::Pass => "PASS",
        TrustVerdict::Flag { .. } => "FLAG",
        TrustVerdict::Block { .. } => "BLOCK",
    };

    let valid = result.is_allowed();

    tracing::info!(
        payment_id = %result.request_id,
        agent_did  = %result.agent_did,
        verdict    = verdict_str,
        valid      = valid,
        "x402 payment verification",
    );

    if valid {
        state.metrics.record_trust_check("PASS", 0);
    }

    Ok(Json(X402VerifyResponse {
        valid,
        verdict: verdict_str.to_string(),
        payment_id: result.request_id.to_string(),
    }))
}
