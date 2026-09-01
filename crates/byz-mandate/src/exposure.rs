//! Exposure tracking.
//!
//! Exposure is the state a limits system exists to protect, and it was previously
//! a plain `HashMap` living inside the engine: it reset to zero on every restart,
//! and every gateway replica kept its own private copy. Both of those are ways to
//! hand out a window's worth of limit more than once.
//!
//! The ledger is a trait for exactly that reason. The in-memory implementation
//! here is correct for a single process and can be exported and rehydrated across
//! restarts; a shared implementation backed by Redis or Postgres slots in behind
//! the same interface to close the multi-replica gap without touching the engine.
//!
//! Two quantities are tracked separately, because they answer different questions:
//!
//! - `window_used` — settled inside the current window. Historical.
//! - `at_risk` — committed and not yet resolved. This is the number that actually
//!   matters, and counting transactions instead of it is how a limits system ends
//!   up watching the wrong variable.

use byz_common::{AgentDid, Currency, ExposureSnapshot, Money};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default rolling window, matching the historical 24h daily cap.
pub const DEFAULT_WINDOW_SECS: u64 = 24 * 60 * 60;

/// Serializable exposure state for one agent, so a ledger can survive a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureRecord {
    pub agent_did: String,
    pub ccy: Currency,
    pub at_risk_minor: u64,
    pub window_used_minor: u64,
    pub window_start: DateTime<Utc>,
    pub open_draws: u32,
}

/// Where committed and settled value is accounted for.
pub trait ExposureLedger: Send + Sync {
    fn snapshot(&self, agent_did: &AgentDid, ccy: Currency) -> ExposureSnapshot;

    /// Value committed but not yet resolved.
    fn record_commit(&mut self, agent_did: &AgentDid, amount: Money);

    /// A committed draw settled successfully.
    fn record_settled(&mut self, agent_did: &AgentDid, amount: Money);

    /// A committed draw failed and its exposure is released.
    fn record_released(&mut self, agent_did: &AgentDid, amount: Money);

    fn reset(&mut self, agent_did: &AgentDid);

    /// Roll the window forward if it has elapsed.
    fn refresh(&mut self, agent_did: &AgentDid, window_secs: u64);

    fn export(&self) -> Vec<ExposureRecord>;

    fn import(&mut self, records: Vec<ExposureRecord>);
}

#[derive(Debug, Clone)]
struct Window {
    ccy: Currency,
    at_risk: u64,
    window_used: u64,
    window_start: DateTime<Utc>,
    open_draws: u32,
}

impl Window {
    fn new(ccy: Currency) -> Self {
        Self {
            ccy,
            at_risk: 0,
            window_used: 0,
            window_start: Utc::now(),
            open_draws: 0,
        }
    }

    /// Rolling the window clears settled value but never clears `at_risk`:
    /// an unresolved commitment is still outstanding on the other side of a
    /// window boundary.
    fn refresh(&mut self, window_secs: u64) {
        if Utc::now() - self.window_start > Duration::seconds(window_secs as i64) {
            self.window_used = 0;
            self.window_start = Utc::now();
        }
    }
}

/// Single-process ledger. Correct for one gateway; export/import keeps it correct
/// across restarts of that gateway.
#[derive(Debug, Default)]
pub struct InMemoryExposureLedger {
    windows: HashMap<String, Window>,
    window_secs: u64,
}

impl InMemoryExposureLedger {
    pub fn new() -> Self {
        Self {
            windows: HashMap::new(),
            window_secs: DEFAULT_WINDOW_SECS,
        }
    }

    pub fn with_window_secs(mut self, secs: u64) -> Self {
        self.window_secs = secs;
        self
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }

    fn entry(&mut self, agent_did: &AgentDid, ccy: Currency) -> &mut Window {
        let secs = self.window_secs;
        let w = self
            .windows
            .entry(agent_did.as_str().to_string())
            .or_insert_with(|| Window::new(ccy));
        w.refresh(secs);
        w
    }

    pub fn tracked_agents(&self) -> usize {
        self.windows.len()
    }
}

impl ExposureLedger for InMemoryExposureLedger {
    fn snapshot(&self, agent_did: &AgentDid, ccy: Currency) -> ExposureSnapshot {
        match self.windows.get(agent_did.as_str()) {
            Some(w) => {
                // Read-side window roll, so a stale window never reports spent
                // value that has already aged out.
                let elapsed =
                    Utc::now() - w.window_start > Duration::seconds(self.window_secs as i64);
                ExposureSnapshot {
                    agent_did: agent_did.clone(),
                    ccy: w.ccy,
                    at_risk: Money::new(w.at_risk, w.ccy),
                    window_used: Money::new(if elapsed { 0 } else { w.window_used }, w.ccy),
                    window_start: if elapsed { Utc::now() } else { w.window_start },
                    open_draws: w.open_draws,
                }
            }
            None => ExposureSnapshot::empty(agent_did.clone(), ccy),
        }
    }

    fn record_commit(&mut self, agent_did: &AgentDid, amount: Money) {
        let w = self.entry(agent_did, amount.currency);
        w.at_risk = w.at_risk.saturating_add(amount.minor_units);
        w.open_draws = w.open_draws.saturating_add(1);
    }

    fn record_settled(&mut self, agent_did: &AgentDid, amount: Money) {
        let w = self.entry(agent_did, amount.currency);
        w.at_risk = w.at_risk.saturating_sub(amount.minor_units);
        w.window_used = w.window_used.saturating_add(amount.minor_units);
        w.open_draws = w.open_draws.saturating_sub(1);
    }

    fn record_released(&mut self, agent_did: &AgentDid, amount: Money) {
        let w = self.entry(agent_did, amount.currency);
        w.at_risk = w.at_risk.saturating_sub(amount.minor_units);
        w.open_draws = w.open_draws.saturating_sub(1);
    }

    fn reset(&mut self, agent_did: &AgentDid) {
        self.windows.remove(agent_did.as_str());
    }

    fn refresh(&mut self, agent_did: &AgentDid, window_secs: u64) {
        if let Some(w) = self.windows.get_mut(agent_did.as_str()) {
            w.refresh(window_secs);
        }
    }

    fn export(&self) -> Vec<ExposureRecord> {
        self.windows
            .iter()
            .map(|(did, w)| ExposureRecord {
                agent_did: did.clone(),
                ccy: w.ccy,
                at_risk_minor: w.at_risk,
                window_used_minor: w.window_used,
                window_start: w.window_start,
                open_draws: w.open_draws,
            })
            .collect()
    }

    fn import(&mut self, records: Vec<ExposureRecord>) {
        for r in records {
            self.windows.insert(
                r.agent_did,
                Window {
                    ccy: r.ccy,
                    at_risk: r.at_risk_minor,
                    window_used: r.window_used_minor,
                    window_start: r.window_start,
                    open_draws: r.open_draws,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did() -> AgentDid {
        AgentDid::new("did:byz:a")
    }

    #[test]
    fn commit_then_settle_moves_value_from_at_risk_to_used() {
        let mut l = InMemoryExposureLedger::new();
        let d = did();
        l.record_commit(&d, Money::usd_cents(5_000));
        let s = l.snapshot(&d, Currency::Usd);
        assert_eq!(s.at_risk.minor_units, 5_000);
        assert_eq!(s.window_used.minor_units, 0);
        assert_eq!(s.open_draws, 1);

        l.record_settled(&d, Money::usd_cents(5_000));
        let s = l.snapshot(&d, Currency::Usd);
        assert_eq!(s.at_risk.minor_units, 0);
        assert_eq!(s.window_used.minor_units, 5_000);
        assert_eq!(s.open_draws, 0);
    }

    #[test]
    fn failed_draw_releases_exposure_without_consuming_the_window() {
        let mut l = InMemoryExposureLedger::new();
        let d = did();
        l.record_commit(&d, Money::usd_cents(9_000));
        l.record_released(&d, Money::usd_cents(9_000));
        let s = l.snapshot(&d, Currency::Usd);
        assert_eq!(s.at_risk.minor_units, 0);
        assert_eq!(
            s.window_used.minor_units, 0,
            "a failed draw consumed window capacity"
        );
    }

    #[test]
    fn total_committed_covers_both_quantities() {
        let mut l = InMemoryExposureLedger::new();
        let d = did();
        l.record_commit(&d, Money::usd_cents(1_000));
        l.record_settled(&d, Money::usd_cents(1_000));
        l.record_commit(&d, Money::usd_cents(400));
        let s = l.snapshot(&d, Currency::Usd);
        assert_eq!(s.total_committed().unwrap().minor_units, 1_400);
    }

    #[test]
    fn state_survives_export_and_reimport() {
        // The restart case: exposure must not silently return to zero.
        let mut l = InMemoryExposureLedger::new();
        let d = did();
        l.record_commit(&d, Money::usd_cents(7_000));
        l.record_settled(&d, Money::usd_cents(7_000));
        l.record_commit(&d, Money::usd_cents(2_500));
        let exported = l.export();

        let mut fresh = InMemoryExposureLedger::new();
        assert_eq!(fresh.snapshot(&d, Currency::Usd).window_used.minor_units, 0);
        fresh.import(exported);

        let s = fresh.snapshot(&d, Currency::Usd);
        assert_eq!(s.window_used.minor_units, 7_000);
        assert_eq!(s.at_risk.minor_units, 2_500);
    }

    #[test]
    fn export_roundtrips_through_json() {
        let mut l = InMemoryExposureLedger::new();
        l.record_commit(&did(), Money::usd_cents(1_234));
        let json = serde_json::to_string(&l.export()).unwrap();
        let back: Vec<ExposureRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].at_risk_minor, 1_234);
    }

    #[test]
    fn elapsed_window_clears_settled_but_keeps_outstanding() {
        let mut l = InMemoryExposureLedger::new().with_window_secs(1);
        let d = did();
        l.record_commit(&d, Money::usd_cents(3_000));
        l.record_settled(&d, Money::usd_cents(3_000));
        l.record_commit(&d, Money::usd_cents(800));

        // Age the window past its end.
        l.import(vec![ExposureRecord {
            agent_did: d.to_string(),
            ccy: Currency::Usd,
            at_risk_minor: 800,
            window_used_minor: 3_000,
            window_start: Utc::now() - Duration::seconds(10),
            open_draws: 1,
        }]);

        let s = l.snapshot(&d, Currency::Usd);
        assert_eq!(s.window_used.minor_units, 0, "settled value should age out");
        assert_eq!(
            s.at_risk.minor_units, 800,
            "unresolved commitment must not age out"
        );
    }

    #[test]
    fn reset_clears_an_agent() {
        let mut l = InMemoryExposureLedger::new();
        let d = did();
        l.record_commit(&d, Money::usd_cents(100));
        l.reset(&d);
        assert_eq!(l.snapshot(&d, Currency::Usd).at_risk.minor_units, 0);
        assert_eq!(l.tracked_agents(), 0);
    }

    #[test]
    fn settling_more_than_committed_does_not_underflow() {
        let mut l = InMemoryExposureLedger::new();
        let d = did();
        l.record_commit(&d, Money::usd_cents(100));
        l.record_settled(&d, Money::usd_cents(500));
        assert_eq!(l.snapshot(&d, Currency::Usd).at_risk.minor_units, 0);
    }
}
