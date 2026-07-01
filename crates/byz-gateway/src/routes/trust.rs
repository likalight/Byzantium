//! POST /v1/trust-check — the core hot-path endpoint.
//!
//! Target: < 200ms end-to-end.
//! Pipeline:
//!   1. Mandate compliance (O(1) in-memory, includes daily cap check)
//!   2. Reputation threshold — Redis proof cache first, in-memory score fallback
//!   3. Sign and return a PassToken (ML-DSA, microseconds)
//!   4. Record spend against daily cap (fire-and-forget tokio task)

use axum::{extract::State, http::StatusCode, Json};
use byz_common::{PassToken, TrustCheckRequest, TrustCheckResponse, TrustVerdict};
use byz_proof::threshold::ThresholdVerifier;
use chrono::Utc;
use serde_json::{json, Value};
use tracing::Instrument as _;
use uuid::Uuid;

use crate::state::AppState;
use crate::webhooks::WebhookEvent;

pub async fn trust_check(
    State(state): State<AppState>,
    Json(req): Json<TrustCheckRequest>,
) -> Result<Json<TrustCheckResponse>, (StatusCode, Json<Value>)> {
    // Create the root span for this request and instrument the inner async
    // block so the span is propagated correctly across await points without
    // changing the function signature (which axum requires to be a plain async fn).
    let span = tracing::info_span!(
        "trust_check",
        agent_did   = %req.agent_did,
        action_type = ?req.action_type,
        amount_cents = req.amount_cents,
        verdict      = tracing::field::Empty,
        "otel.kind"  = "server",
    );
    trust_check_inner(state, req).instrument(span).await
}

async fn trust_check_inner(
    state: AppState,
    req: TrustCheckRequest,
) -> Result<Json<TrustCheckResponse>, (StatusCode, Json<Value>)> {
    let start = std::time::Instant::now();
    let request_id = Uuid::new_v4();

    tracing::info!(
        request_id = %request_id,
        agent_did  = %req.agent_did,
        rail_id    = %req.rail_id,
        "trust-check",
    );

    // ── Step 1: mandate compliance ────────────────────────────────────────────
    let compliance = async {
        let engine = state.mandate_engine.read().await;
        engine
            .check(&req.agent_did, &req.action_type, req.amount_cents, req.counterparty.as_ref())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))))
    }
    .instrument(tracing::info_span!(
        "mandate_check",
        agent_did    = %req.agent_did,
        action_type  = ?req.action_type,
        amount_cents = req.amount_cents,
    ))
    .await?;

    if !compliance.compliant {
        let latency = start.elapsed().as_millis() as u64;
        let label = verdict_label(&compliance.verdict);
        tracing::Span::current().record("verdict", label);
        state.metrics.record_trust_check(label, latency);
        tracing::warn!(request_id = %request_id, verdict = label, latency_ms = latency);
        return Ok(Json(TrustCheckResponse {
            verdict: compliance.verdict,
            token: None,
            request_id,
            checked_at: Utc::now(),
            latency_ms: latency,
        }));
    }

    // ── Step 2: reputation threshold ──────────────────────────────────────────
    let rep_ok = check_reputation(&state, &req.agent_did)
        .instrument(tracing::info_span!(
            "reputation_score",
            agent_did = %req.agent_did,
            cache_hit = tracing::field::Empty,
        ))
        .await?;

    if !rep_ok {
        let latency = start.elapsed().as_millis() as u64;
        tracing::Span::current().record("verdict", "FLAG");
        state.metrics.record_trust_check("FLAG", latency);
        let event = WebhookEvent {
            event_type: "trust.check".to_string(),
            agent_did: req.agent_did.to_string(),
            verdict: "FLAG".to_string(),
            request_id: request_id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            payload: json!({ "reason": "reputation below threshold" }),
        };
        let w = state.webhooks.clone();
        tokio::spawn(async move { w.dispatch(event).await; });
        return Ok(Json(TrustCheckResponse {
            verdict: TrustVerdict::Flag { reason: "reputation below threshold".to_string() },
            token: None,
            request_id,
            checked_at: Utc::now(),
            latency_ms: latency,
        }));
    }

    // ── Step 3: sign PassToken ────────────────────────────────────────────────
    let valid_until = Utc::now() + chrono::Duration::seconds(30);
    let payload = format!(
        "{}:{}:{}:{}",
        req.agent_did, compliance.mandate_hash, true, valid_until.timestamp()
    );
    let sig = state
        .gateway_keypair
        .sign(payload.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))))?;

    let token = PassToken {
        agent_did: req.agent_did.clone(),
        verdict: TrustVerdict::Pass,
        mandate_hash: compliance.mandate_hash,
        reputation_threshold_met: true,
        valid_until,
        signature: sig.as_bytes().to_vec(),
    };

    let latency = start.elapsed().as_millis() as u64;
    tracing::Span::current().record("verdict", "PASS");
    state.metrics.record_trust_check("PASS", latency);
    tracing::info!(request_id = %request_id, agent_did = %req.agent_did, verdict = "PASS", latency_ms = latency);

    // ── Webhook: dispatch PASS event ──────────────────────────────────────────
    {
        let event = WebhookEvent {
            event_type: "trust.check".to_string(),
            agent_did: req.agent_did.to_string(),
            verdict: "PASS".to_string(),
            request_id: request_id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            payload: json!({ "latency_ms": latency }),
        };
        let w = state.webhooks.clone();
        tokio::spawn(async move { w.dispatch(event).await; });
    }

    // ── Step 4: record spend (fire-and-forget) ────────────────────────────────
    if let Some(amt) = req.amount_cents {
        let s2 = state.clone();
        let did2 = req.agent_did.clone();
        tokio::spawn(async move {
            s2.mandate_engine.write().await.record_spend(&did2, amt);
        });
    }

    // ── Billing: record usage for this trust check (fire-and-forget) ─────────
    {
        let meter = state.usage_meter.clone();
        tokio::spawn(async move { meter.record("default").await; });
    }

    Ok(Json(TrustCheckResponse {
        verdict: TrustVerdict::Pass,
        token: Some(token),
        request_id,
        checked_at: Utc::now(),
        latency_ms: latency,
    }))
}

fn verdict_label(v: &TrustVerdict) -> &'static str {
    match v {
        TrustVerdict::Pass        => "PASS",
        TrustVerdict::Flag { .. } => "FLAG",
        TrustVerdict::Block { .. } => "BLOCK",
    }
}

/// Try Redis proof cache first; fall back to in-memory score check.
async fn check_reputation(
    state: &AppState,
    agent_did: &byz_common::AgentDid,
) -> Result<bool, (StatusCode, Json<Value>)> {
    // Fast path: cached ZK threshold proof in Redis
    if let Some(store) = &state.store {
        match store.proof_cache.get_threshold_proof(agent_did).await {
            Ok(Some(proof)) => {
                state.metrics.record_proof_cache_hit();
                return Ok(ThresholdVerifier::verify(&proof));
            }
            Ok(None) => {
                state.metrics.record_proof_cache_miss();
            }
            Err(e) => {
                tracing::warn!(error = %e, "proof cache read failed — falling back to in-memory");
                state.metrics.record_proof_cache_miss();
            }
        }
    }

    // Neo4j graph score (if store is available)
    if let Some(store) = &state.store {
        match store.reputation_graph.compute_score(agent_did).await {
            Ok(score) => {
                let threshold = state.config.reputation.default_threshold;
                return Ok(score >= threshold);
            }
            Err(e) => tracing::warn!(error = %e, "neo4j score failed, using in-memory"),
        }
    }

    // Fallback: raw score from in-memory reputation service (no ZK)
    state
        .reputation
        .read()
        .await
        .meets_threshold(agent_did, None)
        .map(|(ok, _)| ok)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))))
}
