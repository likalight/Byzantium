use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use byz_common::{ActionType, AgentDid, SpendMandate};
use byz_mandate::policy::MandateBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateMandateRequest {
    pub agent_did: String,
    pub operator_id: String,
    pub counterparty_whitelist: Vec<String>,
    pub allowed_action_types: Vec<ActionType>,
    pub per_tx_cap_cents: u64,
    pub daily_cap_cents: u64,
    pub valid_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreateMandateResponse {
    pub mandate_id: Uuid,
    pub mandate_root: Option<String>,
    pub agent_did: String,
}

pub async fn create_mandate(
    State(state): State<AppState>,
    Json(req): Json<CreateMandateRequest>,
) -> Result<Json<CreateMandateResponse>, (StatusCode, Json<Value>)> {
    let valid_days = req.valid_days.unwrap_or(30);
    let mut builder = MandateBuilder::new(AgentDid::new(&req.agent_did), &req.operator_id)
        .per_tx_cap_cents(req.per_tx_cap_cents)
        .daily_cap_cents(req.daily_cap_cents)
        .valid_until(chrono::Utc::now() + chrono::Duration::days(valid_days));
    for cp in req.counterparty_whitelist {
        builder = builder.allow_counterparty(cp);
    }
    for action in req.allowed_action_types {
        builder = builder.allow_action(action);
    }

    let mandate = builder.build().map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))
    })?;

    let resp = CreateMandateResponse {
        mandate_id: mandate.id,
        mandate_root: mandate.mandate_root.clone(),
        agent_did: mandate.agent_did.to_string(),
    };

    // Write to persistent store if available, then update in-memory engine.
    if let Some(store) = &state.store {
        store.mandates.insert(&mandate).await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
        })?;
    }
    state.mandate_engine.write().await.store_mut().insert(mandate);

    tracing::info!(mandate_id = %resp.mandate_id, agent_did = %resp.agent_did, "mandate created");
    Ok(Json(resp))
}

pub async fn get_mandate(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SpendMandate>, (StatusCode, Json<Value>)> {
    // Prefer persistent store; fall back to in-memory.
    if let Some(store) = &state.store {
        let mandate = store.mandates.get(id).await.map_err(|e| {
            (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() })))
        })?;
        return Ok(Json(mandate));
    }
    let engine = state.mandate_engine.read().await;
    let mandate = engine.store().get(id).map_err(|e| {
        (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() })))
    })?;
    Ok(Json(mandate.clone()))
}

pub async fn revoke_mandate(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Some(store) = &state.store {
        store.mandates.revoke(id).await.map_err(|e| {
            (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() })))
        })?;
    }
    state.mandate_engine.write().await.store_mut().revoke(id).ok();
    Ok(Json(json!({ "revoked": id })))
}
