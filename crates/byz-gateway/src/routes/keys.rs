//! Operator API key management routes.
//!
//! POST /v1/keys     — create a new key (returns raw key ONCE)
//! GET  /v1/keys     — list keys for operator (never returns raw key)
//! DELETE /v1/keys/:id — revoke a key
//!
//! The operator_id is derived from the authenticated Bearer token's associated row,
//! propagated through request extensions by the auth middleware.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use byz_store::ApiKeyRow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub label: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub id: Uuid,
    /// Raw key — shown ONCE, never retrievable again
    pub key: String,
    pub label: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: Uuid,
    pub label: String,
    pub operator_id: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<ApiKeyRow> for ApiKeyInfo {
    fn from(r: ApiKeyRow) -> Self {
        Self {
            id: r.id,
            label: r.label,
            operator_id: r.operator_id,
            scopes: r.scopes,
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
        }
    }
}

/// POST /v1/keys — create a new API key
pub async fn create_key(
    State(state): State<AppState>,
    Extension(operator_id): Extension<String>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<Json<CreateKeyResponse>, (StatusCode, Json<Value>)> {

    let store = state.store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "database not available" })),
        )
    })?;

    let scopes: Vec<&str> = req.scopes.iter().map(|s| s.as_str()).collect();

    let (id, raw_key) = store
        .api_keys
        .create(&operator_id, &req.label, &scopes, req.expires_at)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    tracing::info!(operator_id = %operator_id, key_id = %id, label = %req.label, "api key created");

    Ok(Json(CreateKeyResponse {
        id,
        key: raw_key,
        label: req.label,
        scopes: req.scopes,
        created_at: Utc::now(),
        expires_at: req.expires_at,
    }))
}

/// GET /v1/keys — list keys for an operator
pub async fn list_keys(
    State(state): State<AppState>,
    Extension(operator_id): Extension<String>,
) -> Result<Json<Vec<ApiKeyInfo>>, (StatusCode, Json<Value>)> {

    let store = state.store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "database not available" })),
        )
    })?;

    let keys = store
        .api_keys
        .list(&operator_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    Ok(Json(keys.into_iter().map(ApiKeyInfo::from).collect()))
}

/// DELETE /v1/keys/:id — revoke a key
pub async fn revoke_key(
    State(state): State<AppState>,
    Extension(operator_id): Extension<String>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {

    let store = state.store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "database not available" })),
        )
    })?;

    store
        .api_keys
        .revoke(id, &operator_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    tracing::info!(operator_id = %operator_id, key_id = %id, "api key revoked");

    Ok(Json(json!({ "status": "revoked", "id": id })))
}
