//! Runtime registration and provenance submission.
//!
//! A runtime key is admitted deliberately, out of band — it is the trust root for
//! the entire off-chain signal, so an agent must never be able to cause one to be
//! registered.
//!
//! Submissions report what was rejected and why rather than silently dropping it.
//! A low acceptance rate almost always means a misconfigured runtime rather than
//! a misbehaving agent, and an operator needs to learn that from the response
//! instead of from an unexplained limit weeks later.

use axum::{extract::State, http::StatusCode, Json};
use byz_common::AgentDid;
use byz_crypto::DilithiumPublicKey;
use byz_provenance::{ProvenanceBundle, ProvenanceVerifier, SignedProvenance};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::AppState;

type ApiError = (StatusCode, Json<Value>);

#[derive(Debug, Deserialize)]
pub struct RegisterRuntimeRequest {
    pub runtime_id: String,
    /// ML-DSA public key, hex-encoded.
    pub public_key_hex: String,
}

pub async fn register_runtime(
    State(state): State<AppState>,
    Json(req): Json<RegisterRuntimeRequest>,
) -> Result<Json<Value>, ApiError> {
    let key = DilithiumPublicKey::from_hex(&req.public_key_hex).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid runtime public key: {e}") })),
        )
    })?;

    state
        .runtimes
        .write()
        .await
        .register(req.runtime_id.clone(), key);

    Ok(Json(json!({
        "runtime_id": req.runtime_id,
        "registered": true,
        "runtimes_known": state.runtimes.read().await.len(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct RevokeRuntimeRequest {
    pub runtime_id: String,
}

pub async fn revoke_runtime(
    State(state): State<AppState>,
    Json(req): Json<RevokeRuntimeRequest>,
) -> Result<Json<Value>, ApiError> {
    state.runtimes.write().await.revoke(&req.runtime_id);
    Ok(Json(
        json!({ "runtime_id": req.runtime_id, "revoked": true }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct SubmitProvenanceRequest {
    pub agent_did: AgentDid,
    pub events: Vec<SignedProvenance>,
}

#[derive(Debug, Serialize)]
pub struct SubmitProvenanceResponse {
    pub accepted: usize,
    pub rejected: usize,
    /// Why each rejected event contributed nothing.
    pub rejections: Vec<String>,
    pub acceptance_rate_bps: u32,
    /// Merkle commitment over everything accepted for this agent so far. This is
    /// the value that lands in an attestation's `ev` field.
    pub evidence_ref: String,
    pub weighted_total: u64,
    pub human_approvals: u32,
}

/// Accept runtime-signed execution traces.
///
/// Unsigned or unverifiable events are ignored outright rather than
/// down-weighted: partial credit would be an incentive to flood the endpoint with
/// cheap unverifiable claims.
pub async fn submit_provenance(
    State(state): State<AppState>,
    Json(req): Json<SubmitProvenanceRequest>,
) -> Result<Json<SubmitProvenanceResponse>, ApiError> {
    let (verified, rejections) = {
        let registry = state.runtimes.read().await;
        let mut verifier = ProvenanceVerifier::new(&registry, req.agent_did.clone());
        verifier.verify_batch(&req.events)
    };

    let rejection_text: Vec<String> = rejections.iter().map(|r| r.describe()).collect();
    let rejected_count = rejections.len();

    // Accumulate against everything previously accepted for this agent, so the
    // commitment covers the whole history rather than the latest batch.
    let all = {
        let mut store = state.provenance.write().await;
        let entry = store.entry(req.agent_did.to_string()).or_default();
        entry.extend(verified.iter().map(|v| v.signed.clone()));
        entry.clone()
    };

    let rejected_total = {
        let mut counts = state.provenance_rejected.write().await;
        let c = counts.entry(req.agent_did.to_string()).or_insert(0);
        *c += rejected_count;
        *c
    };

    // Rebuild the bundle from the accumulated events. They were verified on the
    // way in, so this re-wraps rather than re-checks.
    let verified_all: Vec<byz_provenance::VerifiedProvenance> = all
        .into_iter()
        .map(|signed| byz_provenance::VerifiedProvenance { signed })
        .collect();

    let bundle = ProvenanceBundle::build(req.agent_did.clone(), verified_all, rejected_total)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    let response = SubmitProvenanceResponse {
        accepted: verified.len(),
        rejected: rejected_count,
        rejections: rejection_text,
        acceptance_rate_bps: bundle.stats.acceptance_rate_bps(),
        evidence_ref: bundle.evidence_ref(),
        weighted_total: bundle.stats.weighted_total,
        human_approvals: bundle.stats.human_approvals,
    };

    state
        .evidence_refs
        .write()
        .await
        .insert(req.agent_did.to_string(), bundle.evidence_ref());

    // Corroboration reaches the scorer. Bounded and additive: it raises
    // confidence in settlements the agent already made, and can never
    // manufacture standing on its own.
    state.reputation.write().await.ingest_provenance(
        &req.agent_did,
        byz_reputation::ProvenanceSummary {
            weighted_total: bundle.stats.weighted_total,
            human_approvals: bundle.stats.human_approvals,
            verified_count: bundle.stats.verified_count,
        },
    );

    Ok(Json(response))
}

/// Current evidence commitment and summary for one agent.
pub async fn get_provenance(
    State(state): State<AppState>,
    axum::extract::Path(did): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiError> {
    let agent_did = AgentDid::new(&did);
    let events = state
        .provenance
        .read()
        .await
        .get(&did)
        .cloned()
        .unwrap_or_default();
    let rejected = state
        .provenance_rejected
        .read()
        .await
        .get(&did)
        .copied()
        .unwrap_or(0);

    let verified: Vec<byz_provenance::VerifiedProvenance> = events
        .into_iter()
        .map(|signed| byz_provenance::VerifiedProvenance { signed })
        .collect();

    let bundle = ProvenanceBundle::build(agent_did, verified, rejected).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
    })?;

    Ok(Json(json!({
        "agent_did": did,
        "evidence_ref": bundle.evidence_ref(),
        "stats": bundle.stats,
    })))
}
