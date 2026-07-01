use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use byz_common::AgentDid;
use byz_crypto::DilithiumKeypair;
use byz_identity::did::{Did, DidDocument};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterAgentRequest {
    pub operator_id: String,
    pub kyb_proof: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterAgentResponse {
    pub did: String,
    pub public_key_hex: String,
}

pub async fn register_agent(
    State(state): State<AppState>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, (StatusCode, Json<Value>)> {
    let keypair = DilithiumKeypair::generate();
    let (agent_uuid, did) = Did::generate();
    let doc = DidDocument::new(agent_uuid, &req.operator_id, &keypair.public_key);
    let pub_key_hex = keypair.public_key.to_hex();

    // Persist DID document.
    if let Some(store) = &state.store {
        store.agents.insert(&doc).await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
        })?;
    }
    state.did_resolver.write().await.register(doc);

    tracing::info!(did = %did, operator = %req.operator_id, "agent registered");
    Ok(Json(RegisterAgentResponse {
        did: did.to_string(),
        public_key_hex: pub_key_hex,
    }))
}

pub async fn get_agent(
    State(state): State<AppState>,
    Path(did_str): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let did = AgentDid::new(&did_str);

    // Prefer persistent store for the authoritative DID document.
    if let Some(store) = &state.store {
        let row = store.agents.get(&did).await.map_err(|e| {
            (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() })))
        })?;
        return Ok(Json(json!({
            "did": row.did,
            "operator_id": row.operator_id,
            "public_key_hex": row.public_key_hex,
            "kyb_verified": row.kyb_verified,
            "active": row.active,
        })));
    }

    let resolver = state.did_resolver.read().await;
    let doc = resolver.resolve(&did).map_err(|e| {
        (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() })))
    })?;
    Ok(Json(serde_json::to_value(doc).unwrap()))
}

pub async fn deactivate_agent(
    State(state): State<AppState>,
    Path(did_str): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let did = AgentDid::new(&did_str);
    if let Some(store) = &state.store {
        store.agents.deactivate(&did).await.map_err(|e| {
            (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() })))
        })?;
    }
    state.did_resolver.write().await.deactivate(&did).ok();
    Ok(Json(json!({ "deactivated": did_str })))
}
