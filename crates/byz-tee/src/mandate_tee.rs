//! byz-mandate-tee — mandate enforcement service running inside SGX enclave.
//!
//! Exposes a minimal internal HTTP API consumed only by the gateway (never by rails).
//! All mandate state, signing keys, and policy decisions live inside this enclave.
//!
//! Remote attestation (DCAP quote) is produced by Gramine and verified by the gateway
//! before trusting any response from this service.

use anyhow::Result;
use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use byz_common::{ActionType, AgentDid, ByzResult, Counterparty, SpendMandate};
use byz_crypto::DilithiumKeypair;
use byz_mandate::engine::{ComplianceResult, MandateEngine, MandateStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Clone)]
struct TeeState {
    engine: Arc<RwLock<MandateEngine>>,
    /// Gateway signing key — generated fresh inside enclave, never leaves SGX boundary.
    signing_key: Arc<DilithiumKeypair>,
}

#[derive(Debug, Deserialize)]
struct CheckRequest {
    agent_did: String,
    action_type: ActionType,
    amount_cents: Option<u64>,
    counterparty: Option<Counterparty>,
}

#[derive(Debug, Serialize)]
struct CheckResponse {
    compliant: bool,
    mandate_hash: String,
    /// ML-DSA signature by the enclave's key over (agent_did, mandate_hash, compliant, ts)
    enclave_signature: String,
}

async fn mandate_check(
    State(state): State<TeeState>,
    Json(req): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, Json<serde_json::Value>)> {
    let did = AgentDid::new(&req.agent_did);
    let engine = state.engine.read().await;
    let result = engine
        .check(&did, &req.action_type, req.amount_cents, req.counterparty.as_ref())
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?;

    let payload = format!(
        "{}:{}:{}:{}",
        req.agent_did,
        result.mandate_hash,
        result.compliant,
        result.checked_at.timestamp_millis()
    );
    let sig = state.signing_key.sign(payload.as_bytes()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;

    Ok(Json(CheckResponse {
        compliant: result.compliant,
        mandate_hash: result.mandate_hash,
        enclave_signature: hex::encode(sig.as_bytes()),
    }))
}

#[derive(Debug, Deserialize)]
struct RegisterMandateRequest {
    mandate: SpendMandate,
}

async fn register_mandate(
    State(state): State<TeeState>,
    Json(req): Json<RegisterMandateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state.engine.write().await.store_mut().insert(req.mandate);
    Ok(Json(serde_json::json!({ "status": "registered" })))
}

#[derive(Debug, Serialize)]
struct AttestationResponse {
    pubkey_hex: String,
    mrenclave: String,
}

async fn attestation(
    State(state): State<TeeState>,
) -> Json<AttestationResponse> {
    let mrenclave = std::env::var("BYZ_MRENCLAVE").unwrap_or_else(|_| "dev".to_string());
    Json(AttestationResponse {
        pubkey_hex: state.signing_key.public_key.to_hex(),
        mrenclave,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "byz_mandate_tee=info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Keys are generated fresh inside the enclave on every boot.
    // The public key is exposed via attestation report so the gateway can verify responses.
    let signing_key = DilithiumKeypair::generate();
    tracing::info!(
        pubkey_prefix = &signing_key.public_key.to_hex()[..16],
        "mandate-tee enclave started — signing key generated inside SGX boundary"
    );

    let state = TeeState {
        engine: Arc::new(RwLock::new(MandateEngine::new(MandateStore::new()))),
        signing_key: Arc::new(signing_key),
    };

    let port: u16 = std::env::var("MANDATE_ENGINE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9001);

    let app = Router::new()
        .route("/internal/mandate/check", post(mandate_check))
        .route("/internal/mandate/register", post(register_mandate))
        .route("/internal/attestation", get(attestation))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    tracing::info!(port, "mandate-tee listening (enclave-internal only)");
    axum::serve(listener, app).await?;
    Ok(())
}
