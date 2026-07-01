//! Rail authentication middleware.
//!
//! Rails authenticate with a pre-shared API key via `Authorization: Bearer <key>`.
//! Keys are checked in two layers:
//!   1. Database: SHA-256 hash the Bearer token, look up in api_keys table (when store is available).
//!   2. Env-var fallback: comma-separated BYZ_API_KEYS env var (dev mode).
//! Production upgrade path: mTLS + short-lived Dilithium-signed JWTs.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use crate::state::AppState;

pub async fn require_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    // ── Layer 1: database key check (when store is available) ─────────────────
    if let Some(store) = &state.store {
        match store.api_keys.validate(provided).await {
            Ok(Some(key_row)) => {
                // Valid key found in database — propagate the operator_id from the DB row
                let operator_id: String = key_row.operator_id.clone();
                request.extensions_mut().insert(operator_id);
                return Ok(next.run(request).await);
            }
            Ok(None) => {
                // Key not found or revoked/expired in DB — fall through to env check
            }
            Err(e) => {
                // DB error — log and fall through to env check so we don't hard-fail on DB issues
                tracing::warn!(error = %e, "api_keys DB check failed, falling back to env keys");
            }
        }
    }

    // ── Layer 2: env-var key check (dev mode / fallback) ─────────────────────
    if state.config.gateway.api_keys.is_empty() && state.store.is_none() {
        // Development mode: if no keys configured at all, allow all traffic with warning.
        tracing::warn!("BYZ_API_KEYS not set — auth disabled. Set it before accepting real rail traffic.");
        request.extensions_mut().insert("default".to_string());
        return Ok(next.run(request).await);
    }

    if state.config.gateway.api_keys.iter().any(|k| k == provided) {
        request.extensions_mut().insert("default".to_string());
        return Ok(next.run(request).await);
    }

    // Also accept SHA-256 prefixed env-var keys (for env-stored hashed keys)
    let provided_hash = sha256_hex(provided.as_bytes());
    if state.config.gateway.api_keys.iter().any(|k| k == &provided_hash) {
        request.extensions_mut().insert("default".to_string());
        return Ok(next.run(request).await);
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid or missing API key" })),
    ))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
