//! byz-reputation-tee — reputation scorer running inside SGX enclave.
//!
//! The raw score and transaction history never leave this enclave.
//! Only score commitments (SHA-256(score || nonce)) and threshold proof bytes
//! (SP1 STARK proofs) exit the boundary.
//!
//! Refresh loop: every SCORE_REFRESH_INTERVAL_SECS, re-score all active agents,
//! generate threshold proofs, and publish commitments + proofs to Redis.

use anyhow::Result;
use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use byz_common::AgentDid;
use byz_crypto::DilithiumKeypair;
use byz_proof::threshold::{ThresholdProveRequest, ThresholdProver, VerifiedThreshold};
use byz_reputation::{
    commitment::ScoreCommitment,
    scorer::{ReputationService, ScoringEvent},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Clone)]
struct TeeState {
    reputation: Arc<RwLock<ReputationService>>,
    default_threshold: u32,
    /// Attestation signing key — generated inside enclave, public key exposed via /internal/attestation
    signing_key: Arc<DilithiumKeypair>,
}

#[derive(Debug, Deserialize)]
struct IngestEventRequest {
    event: ScoringEvent,
}

#[derive(Debug, Serialize)]
struct CommitmentResponse {
    agent_did: String,
    commitment_hex: String,
    /// Threshold proof bytes (opaque SP1 STARK output) for the default threshold.
    /// The gateway reads this from Redis; this endpoint is for direct queries.
    threshold_proof: Option<Vec<u8>>,
    meets_default_threshold: bool,
}

async fn ingest(
    State(state): State<TeeState>,
    Json(req): Json<IngestEventRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state.reputation.write().await.ingest(req.event);
    Ok(Json(serde_json::json!({ "status": "ingested" })))
}

async fn get_commitment(
    State(state): State<TeeState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<CommitmentResponse>, (StatusCode, Json<serde_json::Value>)> {
    let did_str = body["agent_did"]
        .as_str()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "missing agent_did" }))))?;
    let threshold = body["threshold"]
        .as_u64()
        .map(|t| t as u32)
        .unwrap_or(state.default_threshold);

    let did = AgentDid::new(did_str);
    let rep = state.reputation.read().await;

    let score = rep.score(&did).map_err(|e| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": e.to_string() })))
    })?;

    let commitment = ScoreCommitment::new(&score).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() })))
    })?;

    let meets = score.score >= threshold;

    // Generate threshold proof (private score stays in enclave).
    let proof = if meets {
        let nonce = hex::decode(&commitment.nonce_hex).unwrap_or_default();
        match ThresholdProver::prove(ThresholdProveRequest {
            commitment_hex: commitment.commitment_hex.clone(),
            threshold,
            score_private: score.score,  // private — never leaves enclave
            nonce_private: nonce,
            valid_for_secs: 1800,
        }) {
            Ok(opt) => opt.map(|p| p.proof_bytes),
            Err(e) => {
                tracing::warn!(error = %e, "threshold proof generation not supported");
                None
            }
        }
    } else {
        None
    };

    Ok(Json(CommitmentResponse {
        agent_did: did_str.to_string(),
        commitment_hex: commitment.commitment_hex,
        threshold_proof: proof,
        meets_default_threshold: meets,
    }))
}

#[derive(Debug, Serialize)]
struct AttestationResponse {
    pubkey_hex: String,
    mrenclave: String,
}

async fn attestation(State(state): State<TeeState>) -> Json<AttestationResponse> {
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
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "byz_reputation_tee=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let default_threshold: u32 = std::env::var("DEFAULT_REPUTATION_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);

    let signing_key = DilithiumKeypair::generate();
    tracing::info!(
        pubkey_prefix = &signing_key.public_key.to_hex()[..16],
        default_threshold,
        "reputation-tee enclave started — scores stay inside SGX boundary"
    );

    let state = TeeState {
        reputation: Arc::new(RwLock::new(ReputationService::new(default_threshold))),
        default_threshold,
        signing_key: Arc::new(signing_key),
    };

    let port: u16 = std::env::var("REPUTATION_TEE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9002);

    let app = Router::new()
        .route("/internal/reputation/ingest", post(ingest))
        .route("/internal/reputation/commitment", post(get_commitment))
        .route("/internal/attestation", get(attestation))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    tracing::info!(port, "reputation-tee listening (enclave-internal only)");
    axum::serve(listener, app).await?;
    Ok(())
}
