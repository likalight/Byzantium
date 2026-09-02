//! Loading persisted state back into memory at startup, and writing it through
//! as it changes.
//!
//! The gateway keeps its hot state in memory because the authorisation path has
//! a latency budget that a database round trip would eat. That is a reasonable
//! trade, but only if the memory is a *cache* of something durable rather than
//! the only copy. Before this module existed it was the only copy, and three
//! things broke on every restart:
//!
//! - **Issued limits vanished**, so the per-window growth cap could be defeated
//!   simply by restarting the process — an agent went straight back to whatever
//!   its score allowed.
//! - **Revocations were lifted**, bringing killed credentials back to life.
//! - **Exposure reset to zero**, letting a window's capacity be spent twice.
//!
//! Writes go to memory first and to the store afterwards. A failed write is
//! logged rather than propagated, because losing a persistence write is
//! recoverable at the next hydration whereas refusing an authorisation that
//! should have succeeded is not.

use byz_common::{AgentDid, ExposureSnapshot};
use byz_crypto::DilithiumPublicKey;
use byz_mandate::exposure::ExposureRecord;
use byz_underwrite::PreviousLimit;
use serde::Serialize;

use crate::state::AppState;

/// What came back from the store, for the startup log.
#[derive(Debug, Default, Clone, Serialize)]
pub struct HydrationReport {
    pub standings: usize,
    pub limits: usize,
    pub exposures: usize,
    pub runtimes: usize,
    pub revocations: usize,
}

impl HydrationReport {
    pub fn is_empty(&self) -> bool {
        self.standings + self.limits + self.exposures + self.runtimes + self.revocations == 0
    }
}

impl AppState {
    /// Restore durable state into memory. Safe to call once, at startup.
    ///
    /// A store that is unreachable is not fatal — the gateway runs in-memory —
    /// but it is loud, because running without one silently reintroduces every
    /// failure above.
    pub async fn hydrate(&self) -> HydrationReport {
        let mut report = HydrationReport::default();
        let Some(ref store) = self.store else {
            tracing::warn!(
                "no persistent store configured — limits, revocations and exposure will not \
                 survive a restart. Acceptable for local development only."
            );
            return report;
        };
        let repo = &store.underwriting;

        // ── Runtime signing keys ────────────────────────────────────────────
        match repo.load_active_runtimes().await {
            Ok(rows) => {
                let mut reg = self.runtimes.write().await;
                for (id, hex) in rows {
                    match DilithiumPublicKey::from_hex(&hex) {
                        Ok(key) => {
                            reg.register(id, key);
                            report.runtimes += 1;
                        }
                        Err(e) => tracing::error!(error = %e, "stored runtime key is unreadable"),
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "could not load runtime keys"),
        }

        // ── Revocation cutoffs ──────────────────────────────────────────────
        match repo.load_revocations().await {
            Ok(rows) => {
                let mut reg = self.revocations.write().await;
                for (subject, kind, effective_from) in rows {
                    match kind.as_str() {
                        "principal" => reg.revoke_principal(subject, effective_from),
                        _ => reg.revoke_agent(subject, effective_from),
                    }
                    report.revocations += 1;
                }
            }
            Err(e) => tracing::error!(error = %e, "could not load revocations"),
        }

        // ── Exposure ────────────────────────────────────────────────────────
        match repo.load_all_exposure().await {
            Ok(snapshots) => {
                let records: Vec<ExposureRecord> = snapshots
                    .iter()
                    .map(|s| ExposureRecord {
                        agent_did: s.agent_did.to_string(),
                        ccy: s.ccy,
                        at_risk_minor: s.at_risk.minor_units,
                        window_used_minor: s.window_used.minor_units,
                        window_start: s.window_start,
                        open_draws: s.open_draws,
                    })
                    .collect();
                report.exposures = records.len();
                self.mandate_engine
                    .write()
                    .await
                    .ledger_mut()
                    .import(records);
            }
            Err(e) => tracing::error!(error = %e, "could not load exposure"),
        }

        // Standing and prior limits are loaded lazily per agent on first use —
        // there is no bounded set to preload, and a cold read is cheap next to
        // the underwriting itself.

        if report.is_empty() {
            tracing::info!("store connected; nothing to restore yet");
        } else {
            tracing::info!(?report, "restored persisted state");
        }
        report
    }

    /// Standing for an agent, from memory or falling back to the store.
    pub async fn standing_for(
        &self,
        agent_did: &AgentDid,
    ) -> Option<byz_common::PrincipalStanding> {
        if let Some(s) = self.standings.read().await.get(agent_did.as_str()) {
            return Some(s.clone());
        }
        let store = self.store.as_ref()?;
        match store.underwriting.get_standing(agent_did).await {
            Ok(Some(s)) => {
                self.standings
                    .write()
                    .await
                    .insert(agent_did.to_string(), s.clone());
                Some(s)
            }
            Ok(None) => None,
            Err(e) => {
                tracing::error!(error = %e, "could not read standing");
                None
            }
        }
    }

    /// The last limit issued to an agent, which bounds how fast the next may
    /// grow. Falls back to the store so a restart cannot reset the rate cap.
    pub async fn previous_limit_for(&self, agent_did: &AgentDid) -> Option<PreviousLimit> {
        if let Some(p) = self.last_limits.read().await.get(agent_did.as_str()) {
            return Some(p.clone());
        }
        let store = self.store.as_ref()?;
        match store.underwriting.latest_limit(agent_did).await {
            Ok(Some(row)) => {
                let prev = PreviousLimit {
                    lim_window: row.lim_window,
                    issued_at: row.issued_at,
                };
                self.last_limits
                    .write()
                    .await
                    .insert(agent_did.to_string(), prev.clone());
                Some(prev)
            }
            Ok(None) => None,
            Err(e) => {
                tracing::error!(error = %e, "could not read the previous limit");
                None
            }
        }
    }

    /// Persist current exposure for an agent. Called after every commit or
    /// settlement, so a restart cannot hand the same window capacity out twice.
    pub async fn persist_exposure(&self, agent_did: &AgentDid) {
        let Some(ref store) = self.store else { return };
        let snapshot: ExposureSnapshot = self.mandate_engine.read().await.exposure(agent_did);
        if let Err(e) = store.underwriting.save_exposure(&snapshot).await {
            tracing::error!(error = %e, agent = %agent_did, "could not persist exposure");
        }
    }

    pub async fn persist_standing(
        &self,
        agent_did: &AgentDid,
        standing: &byz_common::PrincipalStanding,
    ) {
        let Some(ref store) = self.store else { return };
        if let Err(e) = store
            .underwriting
            .upsert_standing(agent_did, standing)
            .await
        {
            tracing::error!(error = %e, "could not persist standing");
        }
    }

    pub async fn persist_runtime(&self, runtime_id: &str, public_key_hex: &str) {
        let Some(ref store) = self.store else { return };
        if let Err(e) = store
            .underwriting
            .register_runtime(runtime_id, public_key_hex)
            .await
        {
            tracing::error!(error = %e, "could not persist runtime key");
        }
    }

    pub async fn persist_runtime_revocation(&self, runtime_id: &str) {
        let Some(ref store) = self.store else { return };
        if let Err(e) = store.underwriting.revoke_runtime(runtime_id).await {
            tracing::error!(error = %e, "could not persist runtime revocation");
        }
    }

    pub async fn persist_revocation(
        &self,
        subject: &str,
        kind: &str,
        effective_from: chrono::DateTime<chrono::Utc>,
    ) {
        let Some(ref store) = self.store else { return };
        if let Err(e) = store
            .underwriting
            .set_revocation_cutoff(subject, kind, effective_from, "")
            .await
        {
            tracing::error!(error = %e, "could not persist revocation");
        }
    }

    /// Record an issued limit, so the growth cap survives a restart.
    #[allow(clippy::too_many_arguments)]
    pub async fn persist_issued_limit(
        &self,
        attestation: &byz_common::LimitAttestation,
        reasons: &[String],
    ) {
        let Some(ref store) = self.store else { return };
        let ccy = attestation.ccy;
        let guarantee = attestation.guarantee.clone();
        let reasons_json = serde_json::to_value(reasons).unwrap_or(serde_json::Value::Null);

        if let Err(e) = store
            .underwriting
            .record_issued_limit(
                &attestation.sub,
                &attestation.prn,
                attestation.tier.as_str(),
                attestation.lim_single,
                attestation.lim_window,
                attestation.window_secs,
                attestation.fee_bps,
                attestation.collateral_bps,
                attestation
                    .collateral_required
                    .unwrap_or(byz_common::Money::zero(ccy)),
                guarantee
                    .as_ref()
                    .map(|g| g.model.as_str())
                    .unwrap_or("bureau"),
                guarantee
                    .as_ref()
                    .map(|g| g.guarantor.as_str())
                    .unwrap_or(""),
                guarantee
                    .as_ref()
                    .map(|g| g.covered)
                    .unwrap_or(byz_common::Money::zero(ccy)),
                &attestation.ev,
                &attestation.mandate_hash,
                &reasons_json,
                attestation.nbf,
                attestation.exp,
            )
            .await
        {
            tracing::error!(error = %e, "could not persist the issued limit");
        }
    }

    /// Persist one verified provenance event.
    #[allow(clippy::too_many_arguments)]
    pub async fn persist_provenance(&self, signed: &byz_provenance::SignedProvenance) {
        let Some(ref store) = self.store else { return };
        let e = &signed.event;
        if let Err(err) = store
            .underwriting
            .insert_provenance_event(
                &e.agent_did,
                e.session_id,
                e.seq,
                e.kind.as_str(),
                &e.payload_hash,
                e.label.as_deref(),
                e.ok,
                &signed.runtime_id,
                e.at,
            )
            .await
        {
            tracing::error!(error = %err, "could not persist a provenance event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::config::Config;
    use byz_common::Currency;

    #[tokio::test]
    async fn hydrating_without_a_store_is_safe_and_empty() {
        // The in-memory development path must still work, just loudly.
        let state = AppState::new(Config::default());
        let report = state.hydrate().await;
        assert!(report.is_empty());
    }

    #[tokio::test]
    async fn lookups_fall_back_to_memory_when_there_is_no_store() {
        let state = AppState::new(Config::default());
        let did = AgentDid::new("did:byz:nobody");
        assert!(state.standing_for(&did).await.is_none());
        assert!(state.previous_limit_for(&did).await.is_none());
        // And persisting is a no-op rather than a panic.
        state.persist_exposure(&did).await;
    }

    #[tokio::test]
    async fn a_standing_written_to_memory_is_read_back() {
        let state = AppState::new(Config::default());
        let did = AgentDid::new("did:byz:a");
        let standing = byz_common::PrincipalStanding {
            principal_ref: "sha256:acme".into(),
            kyc_tier: byz_common::KycTier::Verified,
            sanctions_clear: true,
            jurisdiction: "SG".into(),
            entity_age_days: 400,
            agent_count: 1,
        };
        state
            .standings
            .write()
            .await
            .insert(did.to_string(), standing.clone());

        let got = state.standing_for(&did).await.expect("standing missing");
        assert_eq!(got.principal_ref, "sha256:acme");
        assert_eq!(got.kyc_tier, byz_common::KycTier::Verified);
    }

    #[tokio::test]
    async fn exposure_survives_an_import() {
        // Mirrors what hydration does: rebuild the ledger from stored rows.
        let state = AppState::new(Config::default());
        let did = AgentDid::new("did:byz:a");

        let record = ExposureRecord {
            agent_did: did.to_string(),
            ccy: Currency::Usd,
            at_risk_minor: 2_500,
            window_used_minor: 7_000,
            window_start: chrono::Utc::now(),
            open_draws: 1,
        };
        state
            .mandate_engine
            .write()
            .await
            .ledger_mut()
            .import(vec![record]);

        let snapshot = state.mandate_engine.read().await.exposure(&did);
        assert_eq!(snapshot.window_used.minor_units, 7_000);
        assert_eq!(snapshot.at_risk.minor_units, 2_500);
    }
}
