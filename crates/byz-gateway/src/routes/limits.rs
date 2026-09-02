//! Limit issuance and presentation.
//!
//! Two endpoints carry the whole thesis:
//!
//! - `POST /v1/limits/issue` turns attested history into a signed limit.
//! - `POST /v1/limits/verify` accepts a limit *presented by an agent* and decides
//!   whether a specific draw is permitted.
//!
//! The second is the one that demonstrates portability. It does not care where
//! the attestation was issued or which chain the agent came from; it verifies a
//! signature, applies FX and the asset-class haircut, nets the result against
//! recorded exposure, and answers. Adding a chain costs a verifier, not a bridge.

use axum::{extract::State, http::StatusCode, Json};
use byz_common::{
    ActionType, AgentDid, AssetClass, Currency, DrawRequest, KycTier, LimitAttestation, LimitScope,
    Money, PrincipalStanding,
};
use byz_underwrite::{AttestationIssuer, PreviousLimit, UnderwritingInput, UnderwritingOutcome};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::AppState;

type ApiError = (StatusCode, Json<Value>);

fn bad_request(msg: impl Into<String>) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": msg.into() })),
    )
}

fn server_error(msg: impl Into<String>) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": msg.into() })),
    )
}

// ─────────────────────────── principal registration ──────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterPrincipalRequest {
    pub agent_did: AgentDid,
    pub principal_ref: String,
    pub kyc_tier: KycTier,
    pub sanctions_clear: bool,
    #[serde(default)]
    pub jurisdiction: String,
    #[serde(default)]
    pub entity_age_days: u32,
}

/// Bind an agent to a KYC'd principal.
///
/// Nothing can be underwritten before this: standing is the gate, and the
/// principal is also the level at which limits consolidate, so an operator
/// cannot multiply their ceiling by registering more agents.
pub async fn register_principal(
    State(state): State<AppState>,
    Json(req): Json<RegisterPrincipalRequest>,
) -> Result<Json<Value>, ApiError> {
    if req.principal_ref.trim().is_empty() {
        return Err(bad_request("principal_ref is required"));
    }

    {
        let mut rep = state.reputation.write().await;
        rep.bind_principal(&req.agent_did, req.principal_ref.clone());
    }

    let agent_count = {
        let rep = state.reputation.read().await;
        rep.agents_for_principal(&req.principal_ref).len().max(1) as u32
    };

    let standing = PrincipalStanding {
        principal_ref: req.principal_ref.clone(),
        kyc_tier: req.kyc_tier,
        sanctions_clear: req.sanctions_clear,
        jurisdiction: req.jurisdiction,
        entity_age_days: req.entity_age_days,
        agent_count,
    };

    state
        .standings
        .write()
        .await
        .insert(req.agent_did.to_string(), standing.clone());
    state.persist_standing(&req.agent_did, &standing).await;

    Ok(Json(json!({
        "agent_did": req.agent_did.as_str(),
        "principal_ref": req.principal_ref,
        "kyc_tier": req.kyc_tier,
        "eligible": standing.is_eligible(),
        "agents_under_principal": agent_count,
    })))
}

// ────────────────────────────────── issuance ─────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct IssueLimitRequest {
    pub agent_did: AgentDid,
    #[serde(default)]
    pub ccy: Option<Currency>,
    #[serde(default)]
    pub chains: Vec<String>,
    #[serde(default)]
    pub asset_classes: Vec<AssetClass>,
    #[serde(default)]
    pub counterparty_classes: Vec<String>,
    #[serde(default)]
    pub action_types: Vec<ActionType>,
}

#[derive(Debug, Serialize)]
pub struct IssueLimitResponse {
    pub issued: bool,
    pub attestation: Option<LimitAttestation>,
    pub tier: String,
    pub score: u32,
    /// Human-readable trail of every control that shaped the limit.
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

pub async fn issue_limit(
    State(state): State<AppState>,
    Json(req): Json<IssueLimitRequest>,
) -> Result<Json<IssueLimitResponse>, ApiError> {
    let ccy = req.ccy.unwrap_or(Currency::Usd);

    let standing = state.standing_for(&req.agent_did).await.ok_or_else(|| {
        bad_request("agent has no registered principal — call /v1/principals first")
    })?;

    let reputation = state.reputation.read().await.detail(&req.agent_did);
    let exposure = state.mandate_engine.read().await.exposure(&req.agent_did);
    let previous = state.previous_limit_for(&req.agent_did).await;

    let scope = LimitScope::any()
        .with_chains(req.chains)
        .with_asset_classes(req.asset_classes)
        .with_counterparty_classes(req.counterparty_classes)
        .with_action_types(req.action_types);

    let input = UnderwritingInput {
        agent_did: req.agent_did.clone(),
        reputation: reputation.clone(),
        standing,
        exposure,
        previous,
        ccy,
        scope,
    };

    let issue_started = std::time::Instant::now();
    let decision = state.underwriter.underwrite(&input);
    let reasons = decision.explain();
    state.metrics.record_limit_issued(
        decision.is_issued(),
        issue_started.elapsed().as_millis() as u64,
    );

    match decision.outcome {
        UnderwritingOutcome::Refused { ref cause } => Ok(Json(IssueLimitResponse {
            issued: false,
            attestation: None,
            tier: decision.tier.as_str().to_string(),
            score: reputation.score,
            reasons,
            refusal: Some(cause.describe()),
        })),
        UnderwritingOutcome::Issued => {
            // The mandate the attestation refreshes, so enforcement and issuance
            // agree on the same numbers.
            let mandate =
                byz_mandate::MandateBuilder::from_decision(&decision, "underwriter", Vec::new())
                    .map_err(|e| server_error(e.to_string()))?;
            let mandate_hash = mandate.mandate_root.clone().unwrap_or_default();

            {
                let mut engine = state.mandate_engine.write().await;
                engine.store_mut().insert(mandate);
            }

            let ttl = state.underwriter.config().attestation_ttl_secs;
            // When runtime-signed provenance exists, the attestation commits to
            // that Merkle root rather than to a summary of the decision inputs.
            let evidence_ref = state
                .evidence_refs
                .read()
                .await
                .get(req.agent_did.as_str())
                .cloned();
            let attestation = state
                .issuer
                .issue_with_evidence(
                    &decision,
                    &reputation,
                    input_principal_ref(&state, &req.agent_did).await,
                    mandate_hash,
                    ttl,
                    evidence_ref,
                )
                .map_err(|e| server_error(e.to_string()))?;

            state.last_limits.write().await.insert(
                req.agent_did.to_string(),
                PreviousLimit {
                    lim_window: decision.lim_window,
                    issued_at: attestation.nbf,
                },
            );
            state.persist_issued_limit(&attestation, &reasons).await;

            Ok(Json(IssueLimitResponse {
                issued: true,
                tier: decision.tier.as_str().to_string(),
                score: reputation.score,
                attestation: Some(attestation),
                reasons,
                refusal: None,
            }))
        }
    }
}

async fn input_principal_ref(state: &AppState, did: &AgentDid) -> String {
    state
        .standings
        .read()
        .await
        .get(did.as_str())
        .map(|s| s.principal_ref.clone())
        .unwrap_or_default()
}

// ─────────────────────────────── presentation ────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct VerifyLimitRequest {
    pub attestation: LimitAttestation,
    pub draw: DrawInput,
    /// Supply this and a retry returns the original answer instead of
    /// committing the exposure a second time.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DrawInput {
    pub amount_minor: u64,
    pub currency: Currency,
    pub asset_class: AssetClass,
    pub chain: String,
    pub action_type: ActionType,
    #[serde(default)]
    pub counterparty_class: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    #[serde(default)]
    pub agent_did: Option<AgentDid>,
    #[serde(default)]
    pub principal_ref: Option<String>,
    /// When the cutoff takes effect. A future instant schedules the revocation
    /// instead of killing credentials that are in flight right now.
    #[serde(default)]
    pub effective_from: Option<DateTime<Utc>>,
}

/// Kill the outstanding attestations for an agent or an entire principal.
pub async fn revoke_limits(
    State(state): State<AppState>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    if req.agent_did.is_none() && req.principal_ref.is_none() {
        return Err(bad_request("one of agent_did or principal_ref is required"));
    }
    let effective_from = req.effective_from.unwrap_or_else(Utc::now);

    {
        let mut reg = state.revocations.write().await;
        if let Some(ref did) = req.agent_did {
            reg.revoke_agent(did.to_string(), effective_from);
        }
        if let Some(ref prn) = req.principal_ref {
            reg.revoke_principal(prn.clone(), effective_from);
        }
    }
    // A revocation that does not survive a restart brings the credential back.
    if let Some(ref did) = req.agent_did {
        state
            .persist_revocation(&did.to_string(), "agent", effective_from)
            .await;
    }
    if let Some(ref prn) = req.principal_ref {
        state
            .persist_revocation(prn, "principal", effective_from)
            .await;
    }

    Ok(Json(json!({
        "revoked": true,
        "agent_did": req.agent_did.as_ref().map(|d| d.to_string()),
        "principal_ref": req.principal_ref,
        "effective_from": effective_from,
        "scheduled": effective_from > Utc::now(),
    })))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyLimitResponse {
    pub permitted: bool,
    /// The draw converted into the attestation's unit of account, after the
    /// asset-class haircut.
    pub effective_minor: u64,
    pub effective_ccy: String,
    pub window_used_minor: u64,
    pub fee_minor: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

/// Verify a presented attestation and decide one draw against it.
///
/// The signature is checked against this gateway's issuer key. An attestation
/// carries a `issuer_pubkey`, but a self-described key proves nothing on its own,
/// so it is deliberately not trusted here.
pub async fn verify_limit(
    State(state): State<AppState>,
    Json(req): Json<VerifyLimitRequest>,
) -> Result<Json<VerifyLimitResponse>, ApiError> {
    let started = std::time::Instant::now();

    // A retry must not commit the exposure again.
    if let Some(ref key) = req.idempotency_key {
        if let Some(cached) = state.idempotency.read().await.get(key) {
            state.metrics.record_idempotent_replay();
            return Ok(Json(
                serde_json::from_value(cached).map_err(|e| server_error(e.to_string()))?,
            ));
        }
    }

    AttestationIssuer::verify(&req.attestation, state.issuer.public_key()).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": format!("attestation rejected: {e}") })),
        )
    })?;

    // A valid signature is not enough — the outstanding set may have been killed
    // since it was issued.
    if let Some(reason) = state.revocations.read().await.check(&req.attestation) {
        state
            .metrics
            .record_authorisation(false, true, started.elapsed().as_millis() as u64);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": reason.describe(), "revoked": true })),
        ));
    }

    // Convert into the attestation's unit of account and widen by the haircut.
    // An unhedged multi-currency window is a larger position than the number on
    // the attestation suggests, and this is where that is accounted for.
    let raw = Money::new(req.draw.amount_minor, req.draw.currency);
    let effective = state
        .fx
        .convert_with_haircut(&raw, req.attestation.ccy, req.draw.asset_class)
        .map_err(|e| bad_request(e.to_string()))?;

    let fee = req
        .attestation
        .fee_for(&effective)
        .map(|m| m.minor_units)
        .unwrap_or(0);

    // Reading exposure, deciding, and reserving the capacity must be one
    // indivisible step. Splitting them lets two concurrent draws each observe an
    // empty window and both succeed, which is exactly the overspend the window
    // exists to prevent. Holding the write guard across all three closes it.
    let (permitted, window_used, refusal) = {
        let mut engine = state.mandate_engine.write().await;
        let exposure = engine.exposure(&req.attestation.sub);
        let window_used = exposure
            .total_committed()
            .unwrap_or(Money::zero(req.attestation.ccy));

        let draw = DrawRequest {
            amount: effective,
            asset_class: req.draw.asset_class,
            chain: req.draw.chain,
            action_type: req.draw.action_type,
            counterparty_class: req.draw.counterparty_class,
            window_used,
        };

        match req.attestation.permits(&draw, chrono::Utc::now()) {
            Ok(()) => {
                engine.record_commit(&req.attestation.sub, effective);
                (true, window_used, None)
            }
            Err(refusal) => (false, window_used, Some(refusal.describe())),
        }
    };

    if permitted {
        state.persist_exposure(&req.attestation.sub).await;
    }

    let response = VerifyLimitResponse {
        permitted,
        effective_minor: effective.minor_units,
        effective_ccy: effective.currency.code().to_string(),
        window_used_minor: window_used.minor_units,
        fee_minor: fee,
        refusal,
    };

    state
        .metrics
        .record_authorisation(permitted, false, started.elapsed().as_millis() as u64);

    if let Some(ref key) = req.idempotency_key {
        if let Ok(v) = serde_json::to_value(&response) {
            state.idempotency.write().await.put(key.clone(), v);
        }
    }

    Ok(Json(response))
}

// ──────────────────────────────── settlement ─────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SettleRequest {
    pub agent_did: AgentDid,
    pub amount_minor: u64,
    pub currency: Currency,
    /// Supply this and a retried settlement does not consume the window twice.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// False when the draw failed, which releases the exposure instead of
    /// consuming window capacity.
    pub settled: bool,
}

/// Resolve a previously committed draw. This is what closes the feedback loop:
/// exposure is released or consumed, and the outcome reaches the scorer.
pub async fn settle_draw(
    State(state): State<AppState>,
    Json(req): Json<SettleRequest>,
) -> Result<Json<Value>, ApiError> {
    if let Some(ref key) = req.idempotency_key {
        if let Some(cached) = state.idempotency.read().await.get(key) {
            state.metrics.record_idempotent_replay();
            return Ok(Json(cached));
        }
    }

    let amount = Money::new(req.amount_minor, req.currency);

    {
        let mut engine = state.mandate_engine.write().await;
        if req.settled {
            engine.record_settled(&req.agent_did, amount);
        } else {
            engine.record_released(&req.agent_did, amount);
        }
    }

    {
        use byz_common::ReceiptOutcome;
        use byz_reputation::ScoringEvent;
        let outcome = if req.settled {
            ReceiptOutcome::Success
        } else {
            ReceiptOutcome::Failed {
                reason: "draw not settled".to_string(),
            }
        };
        state
            .reputation
            .write()
            .await
            .ingest(ScoringEvent::new(req.agent_did.clone(), outcome, false).with_amount(amount));
    }

    state.persist_exposure(&req.agent_did).await;
    state.metrics.record_settlement(req.settled);

    let exposure = state.mandate_engine.read().await.exposure(&req.agent_did);
    let response = json!({
        "agent_did": req.agent_did.as_str(),
        "settled": req.settled,
        "at_risk_minor": exposure.at_risk.minor_units,
        "window_used_minor": exposure.window_used.minor_units,
    });

    if let Some(ref key) = req.idempotency_key {
        state
            .idempotency
            .write()
            .await
            .put(key.clone(), response.clone());
    }

    Ok(Json(response))
}
