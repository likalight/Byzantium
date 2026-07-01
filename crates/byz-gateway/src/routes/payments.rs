//! Payment rail routes.
//!
//! POST /v1/payments/eip3009/verify  — verify an EIP-3009 transferWithAuthorization
//!                                     before the agent action proceeds.

use axum::{extract::State, http::StatusCode, Json};
use byz_rail_eip3009::{AuthorizationStatus, Eip3009Verifier, TransferAuthorization};
use byz_rail_solana::{SolanaTransferProof, SolanaVerifier, TransferStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct Eip3009VerifyRequest {
    pub authorization: TransferAuthorization,
    /// Optional: override Byzantium trust-check threshold for this call
    pub min_trust_score: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct Eip3009VerifyResponse {
    pub status: String,
    pub valid: bool,
    pub recovered_from: Option<String>,
    pub value: u128,
    pub message: String,
}

pub async fn verify_eip3009(
    State(state): State<AppState>,
    Json(req): Json<Eip3009VerifyRequest>,
) -> Result<Json<Eip3009VerifyResponse>, (StatusCode, Json<Value>)> {
    if state.cb_base_rpc.is_open() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Base RPC service temporarily unavailable (circuit open)",
                "retry_after": 60
            })),
        ));
    }

    let rpc_url = std::env::var("BASE_RPC_URL")
        .unwrap_or_else(|_| "https://mainnet.base.org".to_string());

    let gateway_url = format!(
        "http://127.0.0.1:{}",
        state.config.gateway.port
    );

    // Re-use the first configured API key for internal trust-check calls.
    let api_key = state
        .config
        .gateway
        .api_keys
        .first()
        .cloned()
        .unwrap_or_default();

    let verifier = Eip3009Verifier::new(&rpc_url, &gateway_url);

    let result = verifier
        .verify(&req.authorization, &api_key)
        .await
        .map_err(|e| {
            state.cb_base_rpc.record_failure();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
        })?;
    state.cb_base_rpc.record_success();

    let (status_str, message) = match &result.status {
        AuthorizationStatus::Valid => ("VALID", "Authorization is valid".to_string()),
        AuthorizationStatus::InvalidSignature => ("INVALID_SIGNATURE", "Signature does not match `from` address".to_string()),
        AuthorizationStatus::Expired => ("EXPIRED", "Authorization has expired".to_string()),
        AuthorizationStatus::NotYetValid => ("NOT_YET_VALID", "Authorization is not yet active".to_string()),
        AuthorizationStatus::NonceUsed => ("NONCE_USED", "Nonce already consumed on-chain".to_string()),
        AuthorizationStatus::TrustBlocked => ("TRUST_BLOCKED", "Byzantium trust-check blocked sender".to_string()),
    };

    let valid = result.status == AuthorizationStatus::Valid;

    if valid {
        state.metrics.record_trust_check("PASS", 0);
    }

    tracing::info!(
        status = status_str,
        from = %req.authorization.from,
        value = result.value,
        token = %req.authorization.token,
        "eip3009 verification"
    );

    Ok(Json(Eip3009VerifyResponse {
        status: status_str.to_string(),
        valid,
        recovered_from: result.recovered_from,
        value: result.value,
        message,
    }))
}

pub async fn verify_solana(
    State(state): State<AppState>,
    Json(req): Json<SolanaTransferProof>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if state.cb_solana.is_open() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Solana RPC service temporarily unavailable (circuit open)",
                "retry_after": 60
            })),
        ));
    }

    let byzantium_url = format!("http://127.0.0.1:{}", state.config.gateway.port);
    let api_key = state.config.gateway.api_keys.first().cloned().unwrap_or_default();
    let verifier = SolanaVerifier::for_cluster(&req.cluster, &byzantium_url);
    let result = verifier
        .verify(&req, &api_key)
        .await
        .map_err(|e| {
            state.cb_solana.record_failure();
            (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))
        })?;
    state.cb_solana.record_success();
    let valid = result.status == TransferStatus::Verified;
    Ok(Json(json!({
        "status": format!("{:?}", result.status),
        "valid": valid,
        "slot": result.slot,
        "fee_lamports": result.fee_lamports,
    })))
}
