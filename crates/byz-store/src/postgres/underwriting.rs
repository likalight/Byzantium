//! Persistence for the underwriting layer.
//!
//! Three of these tables matter more than they look. **Exposure** must survive a
//! restart or a window's capacity gets handed out twice. **Issued limits** must
//! survive one or the per-window growth cap is defeated by restarting the
//! process. **Revocation cutoffs** must survive one or a killed credential comes
//! back to life.

use byz_common::{
    AgentDid, ByzResult, ByzantiumError, Currency, ExposureSnapshot, KycTier, Money,
    PrincipalStanding,
};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::sync::Arc;

fn ccy_of(code: &str) -> Currency {
    Currency::from_code(code).unwrap_or(Currency::Usd)
}

fn kyc_of(s: &str) -> KycTier {
    match s {
        "basic" => KycTier::Basic,
        "verified" => KycTier::Verified,
        "institutional" => KycTier::Institutional,
        _ => KycTier::Unverified,
    }
}

/// A previously issued limit, enough to rate-cap the next one.
#[derive(Debug, Clone)]
pub struct IssuedLimitRow {
    pub agent_did: String,
    pub principal_ref: String,
    pub tier: String,
    pub lim_window: Money,
    pub lim_single: Money,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct UnderwritingRepository {
    db: Arc<PgPool>,
}

impl UnderwritingRepository {
    pub fn new(db: Arc<PgPool>) -> Self {
        Self { db }
    }

    // ── Principal standing ───────────────────────────────────────────────────

    pub async fn upsert_standing(
        &self,
        agent_did: &AgentDid,
        standing: &PrincipalStanding,
    ) -> ByzResult<()> {
        sqlx::query(
            r#"
            INSERT INTO principal_standings
                (agent_did, principal_ref, kyc_tier, sanctions_clear, jurisdiction, entity_age_days)
            VALUES ($1,$2,$3,$4,$5,$6)
            ON CONFLICT (agent_did) DO UPDATE
              SET principal_ref   = EXCLUDED.principal_ref,
                  kyc_tier        = EXCLUDED.kyc_tier,
                  sanctions_clear = EXCLUDED.sanctions_clear,
                  jurisdiction    = EXCLUDED.jurisdiction,
                  entity_age_days = EXCLUDED.entity_age_days,
                  updated_at      = NOW()
            "#,
        )
        .bind(agent_did.as_str())
        .bind(&standing.principal_ref)
        .bind(standing.kyc_tier.as_str())
        .bind(standing.sanctions_clear)
        .bind(&standing.jurisdiction)
        .bind(standing.entity_age_days as i32)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    /// Load standing, with `agent_count` computed from the table rather than
    /// stored — a stale count is a way to hand a principal more ceiling than it
    /// should have.
    pub async fn get_standing(&self, agent_did: &AgentDid) -> ByzResult<Option<PrincipalStanding>> {
        let row = sqlx::query(
            r#"
            SELECT s.principal_ref, s.kyc_tier, s.sanctions_clear, s.jurisdiction,
                   s.entity_age_days,
                   (SELECT COUNT(*) FROM principal_standings p
                     WHERE p.principal_ref = s.principal_ref) AS agent_count
            FROM principal_standings s
            WHERE s.agent_did = $1
            "#,
        )
        .bind(agent_did.as_str())
        .fetch_optional(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(row.map(|r| PrincipalStanding {
            principal_ref: r.get::<String, _>("principal_ref"),
            kyc_tier: kyc_of(&r.get::<String, _>("kyc_tier")),
            sanctions_clear: r.get::<bool, _>("sanctions_clear"),
            jurisdiction: r.get::<String, _>("jurisdiction"),
            entity_age_days: r.get::<i32, _>("entity_age_days") as u32,
            agent_count: r.get::<i64, _>("agent_count").max(1) as u32,
        }))
    }

    // ── Issued limits ────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub async fn record_issued_limit(
        &self,
        agent_did: &AgentDid,
        principal_ref: &str,
        tier: &str,
        lim_single: Money,
        lim_window: Money,
        window_secs: u64,
        fee_bps: u32,
        collateral_bps: u32,
        collateral_required: Money,
        liability_model: &str,
        guarantor: &str,
        guarantee_covered: Money,
        evidence_ref: &str,
        mandate_hash: &str,
        reasons: &serde_json::Value,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> ByzResult<()> {
        sqlx::query(
            r#"
            INSERT INTO issued_limits
                (agent_did, principal_ref, tier, ccy, lim_single_minor, lim_window_minor,
                 window_secs, fee_bps, collateral_bps, collateral_required_minor,
                 liability_model, guarantor, guarantee_covered_minor,
                 evidence_ref, mandate_hash, reasons, issued_at, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
            "#,
        )
        .bind(agent_did.as_str())
        .bind(principal_ref)
        .bind(tier)
        .bind(lim_window.currency.code())
        .bind(lim_single.minor_units as i64)
        .bind(lim_window.minor_units as i64)
        .bind(window_secs as i64)
        .bind(fee_bps as i32)
        .bind(collateral_bps as i32)
        .bind(collateral_required.minor_units as i64)
        .bind(liability_model)
        .bind(guarantor)
        .bind(guarantee_covered.minor_units as i64)
        .bind(evidence_ref)
        .bind(mandate_hash)
        .bind(reasons)
        .bind(issued_at)
        .bind(expires_at)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    /// The most recent limit issued to an agent, which bounds how fast the next
    /// one may grow.
    pub async fn latest_limit(&self, agent_did: &AgentDid) -> ByzResult<Option<IssuedLimitRow>> {
        let row = sqlx::query(
            r#"
            SELECT agent_did, principal_ref, tier, ccy,
                   lim_single_minor, lim_window_minor, issued_at, expires_at
            FROM issued_limits
            WHERE agent_did = $1
            ORDER BY issued_at DESC
            LIMIT 1
            "#,
        )
        .bind(agent_did.as_str())
        .fetch_optional(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(row.map(|r| {
            let ccy = ccy_of(&r.get::<String, _>("ccy"));
            IssuedLimitRow {
                agent_did: r.get("agent_did"),
                principal_ref: r.get("principal_ref"),
                tier: r.get("tier"),
                lim_single: Money::new(r.get::<i64, _>("lim_single_minor") as u64, ccy),
                lim_window: Money::new(r.get::<i64, _>("lim_window_minor") as u64, ccy),
                issued_at: r.get("issued_at"),
                expires_at: r.get("expires_at"),
            }
        }))
    }

    // ── Exposure ─────────────────────────────────────────────────────────────

    pub async fn save_exposure(&self, snapshot: &ExposureSnapshot) -> ByzResult<()> {
        sqlx::query(
            r#"
            INSERT INTO agent_exposure
                (agent_did, ccy, at_risk_minor, window_used_minor, window_start, open_draws, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,NOW())
            ON CONFLICT (agent_did) DO UPDATE
              SET ccy               = EXCLUDED.ccy,
                  at_risk_minor     = EXCLUDED.at_risk_minor,
                  window_used_minor = EXCLUDED.window_used_minor,
                  window_start      = EXCLUDED.window_start,
                  open_draws        = EXCLUDED.open_draws,
                  updated_at        = NOW()
            "#,
        )
        .bind(snapshot.agent_did.as_str())
        .bind(snapshot.ccy.code())
        .bind(snapshot.at_risk.minor_units as i64)
        .bind(snapshot.window_used.minor_units as i64)
        .bind(snapshot.window_start)
        .bind(snapshot.open_draws as i32)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    /// Every agent's exposure, for rehydrating the ledger at startup.
    pub async fn load_all_exposure(&self) -> ByzResult<Vec<ExposureSnapshot>> {
        let rows = sqlx::query(
            "SELECT agent_did, ccy, at_risk_minor, window_used_minor, window_start, open_draws
             FROM agent_exposure",
        )
        .fetch_all(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let ccy = ccy_of(&r.get::<String, _>("ccy"));
                ExposureSnapshot {
                    agent_did: AgentDid::new(r.get::<String, _>("agent_did")),
                    ccy,
                    at_risk: Money::new(r.get::<i64, _>("at_risk_minor") as u64, ccy),
                    window_used: Money::new(r.get::<i64, _>("window_used_minor") as u64, ccy),
                    window_start: r.get("window_start"),
                    open_draws: r.get::<i32, _>("open_draws") as u32,
                }
            })
            .collect())
    }

    // ── Runtime keys ─────────────────────────────────────────────────────────

    pub async fn register_runtime(&self, runtime_id: &str, public_key_hex: &str) -> ByzResult<()> {
        sqlx::query(
            r#"
            INSERT INTO provenance_runtimes (runtime_id, public_key_hex)
            VALUES ($1,$2)
            ON CONFLICT (runtime_id) DO UPDATE
              SET public_key_hex = EXCLUDED.public_key_hex,
                  revoked_at     = NULL
            "#,
        )
        .bind(runtime_id)
        .bind(public_key_hex)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn revoke_runtime(&self, runtime_id: &str) -> ByzResult<()> {
        sqlx::query("UPDATE provenance_runtimes SET revoked_at = NOW() WHERE runtime_id = $1")
            .bind(runtime_id)
            .execute(&*self.db)
            .await
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    /// Live runtime keys, for rebuilding the registry at startup.
    pub async fn load_active_runtimes(&self) -> ByzResult<Vec<(String, String)>> {
        let rows = sqlx::query(
            "SELECT runtime_id, public_key_hex FROM provenance_runtimes WHERE revoked_at IS NULL",
        )
        .fetch_all(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| (r.get("runtime_id"), r.get("public_key_hex")))
            .collect())
    }

    // ── Provenance events ────────────────────────────────────────────────────

    /// Store one verified event. `ON CONFLICT DO NOTHING` makes the unique
    /// `(agent, session, seq)` index a second line of replay defence behind the
    /// verifier, so a retried batch cannot inflate an agent's evidence.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_provenance_event(
        &self,
        agent_did: &AgentDid,
        session_id: uuid::Uuid,
        seq: u64,
        kind: &str,
        payload_hash: &str,
        label: Option<&str>,
        ok: bool,
        runtime_id: &str,
        occurred_at: DateTime<Utc>,
    ) -> ByzResult<bool> {
        let result = sqlx::query(
            r#"
            INSERT INTO provenance_events
                (agent_did, session_id, seq, kind, payload_hash, label, ok, runtime_id, occurred_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT (agent_did, session_id, seq) DO NOTHING
            "#,
        )
        .bind(agent_did.as_str())
        .bind(session_id)
        .bind(seq as i64)
        .bind(kind)
        .bind(payload_hash)
        .bind(label)
        .bind(ok)
        .bind(runtime_id)
        .bind(occurred_at)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    // ── Revocation ───────────────────────────────────────────────────────────

    /// Cutoffs only move forward. `GREATEST` in the conflict clause is what stops
    /// a later write with an earlier timestamp from resurrecting a killed
    /// credential.
    pub async fn set_revocation_cutoff(
        &self,
        subject: &str,
        subject_kind: &str,
        effective_from: DateTime<Utc>,
        reason: &str,
    ) -> ByzResult<()> {
        sqlx::query(
            r#"
            INSERT INTO revocation_cutoffs (subject, subject_kind, effective_from, reason)
            VALUES ($1,$2,$3,$4)
            ON CONFLICT (subject, subject_kind) DO UPDATE
              SET effective_from = GREATEST(revocation_cutoffs.effective_from, EXCLUDED.effective_from),
                  reason         = EXCLUDED.reason
            "#,
        )
        .bind(subject)
        .bind(subject_kind)
        .bind(effective_from)
        .bind(reason)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn lift_revocation(&self, subject: &str, subject_kind: &str) -> ByzResult<()> {
        sqlx::query("DELETE FROM revocation_cutoffs WHERE subject = $1 AND subject_kind = $2")
            .bind(subject)
            .bind(subject_kind)
            .execute(&*self.db)
            .await
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    /// All cutoffs, for rebuilding the registry at startup.
    pub async fn load_revocations(&self) -> ByzResult<Vec<(String, String, DateTime<Utc>)>> {
        let rows =
            sqlx::query("SELECT subject, subject_kind, effective_from FROM revocation_cutoffs")
                .fetch_all(&*self.db)
                .await
                .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get("subject"),
                    r.get("subject_kind"),
                    r.get("effective_from"),
                )
            })
            .collect())
    }
}
