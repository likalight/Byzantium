//! Behavioral reputation scorer.
//!
//! The model runs inside the SGX/SEV TEE in production — raw transaction
//! history never leaves the enclave. Only commitments and threshold-pass
//! signals are published.
//!
//! # Why this is not a compliance ratio
//!
//! A ratio of clean transactions to total transactions is trivially farmed: run
//! ten thousand one-cent transfers, reach a perfect ratio, then draw the whole
//! limit once and vanish. That is bust-out fraud, and it is how card portfolios
//! actually lose money.
//!
//! Four properties defend against it, and each is load-bearing:
//!
//! 1. **Value-weighted, not count-weighted.** A clean cent is not evidence about
//!    a clean million.
//! 2. **Sublinear in settled volume.** Score grows with the square root of value
//!    settled against a saturation point, so proving twice as much earns
//!    substantially less than twice the standing.
//! 3. **Recency-decayed.** Old clean history fades. An agent cannot bank standing
//!    and cash it in a year later.
//! 4. **Discounted for closed loops.** Volume with counterparties under the same
//!    principal counts for nothing, so an operator cannot trade with themselves
//!    into a limit.
//!
//! A new agent scores **zero**, not a neutral midpoint. A nonzero score for an
//! agent with no history is a free limit for anyone who can generate a keypair;
//! cold-start standing comes from the KYC'd principal instead, in `byz-underwrite`.
//!
//! Graph storage: Neo4j (production); in-memory for unit tests.

use byz_common::{AgentDid, AssetClass, ByzResult, Money, ReceiptOutcome, ReputationScore};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Tunables for the scoring model.
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    /// Settled value (minor units, unit of account) at which the depth term
    /// saturates at 1.0. Below it, standing grows with the square root of value.
    pub depth_saturation_minor: u128,
    /// Half-life for recency weighting.
    pub decay_half_life: Duration,
    /// Events retained per agent for velocity and concentration analysis.
    pub max_events: usize,
    /// A draw this many times larger than the trailing mean starts costing score.
    pub velocity_tolerance: f64,
    /// Maximum points deducted for a velocity anomaly.
    pub max_velocity_penalty: f64,
    /// Maximum points deducted for counterparty concentration.
    pub max_concentration_penalty: f64,
    /// Maximum points deducted for value-weighted mandate violations.
    pub max_violation_penalty: f64,
    /// Most that runtime-signed provenance can add to corroborated volume, in
    /// basis points. Bounded so an operator with a legitimate runtime cannot
    /// simply emit more events to buy standing.
    pub max_provenance_bonus_bps: u32,
    /// Weighted provenance volume at which the bonus saturates.
    pub provenance_saturation: u64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            // 100,000.00 in the unit of account.
            depth_saturation_minor: 10_000_000,
            decay_half_life: Duration::days(30),
            max_events: 512,
            velocity_tolerance: 4.0,
            max_velocity_penalty: 150.0,
            max_concentration_penalty: 120.0,
            max_violation_penalty: 400.0,
            max_provenance_bonus_bps: 2_000,
            provenance_saturation: 500,
        }
    }
}

/// Summary of an agent's verified execution provenance.
///
/// Deliberately a summary rather than the events: this crate should not depend
/// on the provenance crate, and the scorer has no business seeing traces.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvenanceSummary {
    /// Sum of per-kind weights across verified events.
    pub weighted_total: u64,
    pub human_approvals: u32,
    pub verified_count: usize,
}

/// An event ingested by the scorer (created from a LiabilityReceipt).
///
/// The legacy `amount_cents` field is retained so existing callers and stored
/// payloads keep working; `amount` supersedes it and wins when both are present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringEvent {
    pub agent_did: AgentDid,
    pub outcome: ReceiptOutcome,
    pub mandate_violated: bool,
    pub amount_cents: Option<u64>,
    /// Multicurrency amount, already converted to the unit of account.
    #[serde(default)]
    pub amount: Option<Money>,
    #[serde(default)]
    pub counterparty_id: Option<String>,
    #[serde(default)]
    pub asset_class: Option<AssetClass>,
    /// Defaults to now when absent.
    #[serde(default)]
    pub occurred_at: Option<DateTime<Utc>>,
}

impl ScoringEvent {
    pub fn new(agent_did: AgentDid, outcome: ReceiptOutcome, mandate_violated: bool) -> Self {
        Self {
            agent_did,
            outcome,
            mandate_violated,
            amount_cents: None,
            amount: None,
            counterparty_id: None,
            asset_class: None,
            occurred_at: None,
        }
    }

    pub fn with_amount(mut self, amount: Money) -> Self {
        self.amount_cents = Some(amount.minor_units);
        self.amount = Some(amount);
        self
    }

    pub fn with_counterparty(mut self, id: impl Into<String>) -> Self {
        self.counterparty_id = Some(id.into());
        self
    }

    pub fn with_asset_class(mut self, class: AssetClass) -> Self {
        self.asset_class = Some(class);
        self
    }

    pub fn at(mut self, when: DateTime<Utc>) -> Self {
        self.occurred_at = Some(when);
        self
    }

    fn minor_units(&self) -> u128 {
        self.amount
            .map(|m| m.minor_units as u128)
            .or(self.amount_cents.map(|c| c as u128))
            .unwrap_or(0)
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.occurred_at.unwrap_or_else(Utc::now)
    }
}

#[derive(Debug, Clone)]
struct EventRecord {
    at: DateTime<Utc>,
    minor: u128,
    settled: bool,
    violated: bool,
    counterparty: Option<String>,
}

/// Everything the underwriter needs about one agent's behavior. Richer than
/// `ReputationScore`, which stays wire-compatible for existing rails.
#[derive(Debug, Clone)]
pub struct ReputationDetail {
    pub agent_did: AgentDid,
    pub score: u32,
    pub compliance_rate: f64,
    pub violation_rate: f64,
    pub total_actions: u64,
    /// Recency-weighted settled value, wash volume already removed.
    pub weighted_settled_minor: u128,
    pub lifetime_settled_minor: u128,
    pub largest_single_minor: u64,
    pub distinct_counterparties: usize,
    pub principal_ref: Option<String>,
    pub first_seen: Option<DateTime<Utc>>,
    /// How much runtime-signed provenance corroborated this agent's settlements,
    /// in basis points of extra credited volume. Zero is the normal case and is
    /// not a mark against the agent.
    pub provenance_bonus_bps: u32,
    /// Empty when nothing suppressed the score. Populated so an adverse decision
    /// can be explained — retrofitting that onto an opaque model is not possible.
    pub penalties: Vec<PenaltyReason>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "penalty")]
pub enum PenaltyReason {
    /// Value-weighted mandate violations.
    Violations { points: u32, share_bps: u32 },
    /// A draw far larger than this agent's trailing norm.
    VelocitySpike { points: u32, ratio_x100: u32 },
    /// Volume concentrated in too few counterparties.
    Concentration { points: u32, hhi_x100: u32 },
    /// Volume with counterparties under the same principal, discounted to zero.
    WashVolume { discounted_minor: u128 },
}

impl PenaltyReason {
    pub fn describe(&self) -> String {
        match self {
            PenaltyReason::Violations { points, share_bps } => format!(
                "{points} points for mandate violations across {}% of settled value",
                *share_bps as f64 / 100.0
            ),
            PenaltyReason::VelocitySpike { points, ratio_x100 } => format!(
                "{points} points for a draw {}x this agent's trailing average",
                *ratio_x100 as f64 / 100.0
            ),
            PenaltyReason::Concentration { points, hhi_x100 } => format!(
                "{points} points for counterparty concentration (HHI {:.2})",
                *hhi_x100 as f64 / 100.0
            ),
            PenaltyReason::WashVolume { discounted_minor } => {
                format!("{discounted_minor} minor units of related-party volume discounted")
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
struct AgentStats {
    total: u64,
    successes: u64,
    violations: u64,
    lifetime_settled: u128,
    largest_single: u64,
    events: VecDeque<EventRecord>,
    principal_ref: Option<String>,
    first_seen: Option<DateTime<Utc>>,
}

/// In-memory reputation service.
/// Production replaces the maps with Neo4j queries + a model running in TEE.
pub struct ReputationService {
    scores: HashMap<String, AgentStats>,
    /// principal_ref -> agent DIDs. Limits consolidate at this level.
    principals: HashMap<String, HashSet<String>>,
    /// Counterparty ids known to belong to the same principal as a given agent.
    related: HashMap<String, HashSet<String>>,
    /// Verified provenance summary per agent.
    provenance: HashMap<String, ProvenanceSummary>,
    default_threshold: u32,
    config: ScoringConfig,
}

impl ReputationService {
    pub fn new(default_threshold: u32) -> Self {
        Self {
            scores: HashMap::new(),
            principals: HashMap::new(),
            related: HashMap::new(),
            provenance: HashMap::new(),
            default_threshold,
            config: ScoringConfig::default(),
        }
    }

    pub fn with_config(mut self, config: ScoringConfig) -> Self {
        self.config = config;
        self
    }

    pub fn config(&self) -> &ScoringConfig {
        &self.config
    }

    /// Bind an agent to its KYC'd principal. Required before the underwriter
    /// will issue anything, and the anchor that makes sybil splitting pointless.
    pub fn bind_principal(&mut self, did: &AgentDid, principal_ref: impl Into<String>) {
        let prn = principal_ref.into();
        let stats = self.scores.entry(did.as_str().to_string()).or_default();
        stats.principal_ref = Some(prn.clone());
        if stats.first_seen.is_none() {
            stats.first_seen = Some(Utc::now());
        }
        self.principals
            .entry(prn)
            .or_default()
            .insert(did.as_str().to_string());
    }

    /// Declare counterparties that share this agent's principal. Volume with them
    /// is self-dealing and earns nothing.
    pub fn mark_related_counterparty(
        &mut self,
        did: &AgentDid,
        counterparty_id: impl Into<String>,
    ) {
        self.related
            .entry(did.as_str().to_string())
            .or_default()
            .insert(counterparty_id.into());
    }

    /// All agent DIDs operated by a principal.
    pub fn agents_for_principal(&self, principal_ref: &str) -> Vec<AgentDid> {
        self.principals
            .get(principal_ref)
            .map(|set| set.iter().map(AgentDid::new).collect())
            .unwrap_or_default()
    }

    /// Record verified execution provenance for an agent.
    ///
    /// Only ever additive. Absent provenance means an operator has not integrated
    /// a runtime yet, which is an adoption gap rather than evidence of
    /// misbehaviour — penalising it would punish the wrong party.
    pub fn ingest_provenance(&mut self, did: &AgentDid, summary: ProvenanceSummary) {
        self.provenance.insert(did.as_str().to_string(), summary);
    }

    pub fn provenance_for(&self, did: &AgentDid) -> Option<&ProvenanceSummary> {
        self.provenance.get(did.as_str())
    }

    /// Corroboration bonus in basis points, saturating in provenance volume.
    fn provenance_bonus_bps(&self, did: &AgentDid) -> u32 {
        let Some(p) = self.provenance.get(did.as_str()) else {
            return 0;
        };
        if p.verified_count == 0 {
            return 0;
        }
        let saturation = self.config.provenance_saturation.max(1) as f64;
        let ratio = (p.weighted_total as f64 / saturation)
            .sqrt()
            .clamp(0.0, 1.0);
        (ratio * self.config.max_provenance_bonus_bps as f64).round() as u32
    }

    /// Ingest a scoring event (called after each receipt is finalized).
    pub fn ingest(&mut self, event: ScoringEvent) {
        let key = event.agent_did.to_string();
        let minor = event.minor_units();
        let at = event.timestamp();
        let settled = matches!(event.outcome, ReceiptOutcome::Success);
        let max_events = self.config.max_events;

        let stats = self.scores.entry(key).or_default();
        stats.total += 1;
        if settled {
            stats.successes += 1;
            stats.lifetime_settled = stats.lifetime_settled.saturating_add(minor);
        }
        if event.mandate_violated {
            stats.violations += 1;
        }
        if minor > stats.largest_single as u128 {
            stats.largest_single = minor.min(u64::MAX as u128) as u64;
        }
        if stats.first_seen.is_none() {
            stats.first_seen = Some(at);
        }

        stats.events.push_back(EventRecord {
            at,
            minor,
            settled,
            violated: event.mandate_violated,
            counterparty: event.counterparty_id,
        });
        while stats.events.len() > max_events {
            stats.events.pop_front();
        }
    }

    /// Recency weight for an event, halving every `decay_half_life`.
    fn decay_weight(&self, at: DateTime<Utc>, now: DateTime<Utc>) -> f64 {
        let age = (now - at).num_seconds().max(0) as f64;
        let half = self.config.decay_half_life.num_seconds().max(1) as f64;
        0.5f64.powf(age / half)
    }

    /// Full behavioral picture for one agent.
    pub fn detail(&self, did: &AgentDid) -> ReputationDetail {
        let now = Utc::now();
        let stats = match self.scores.get(did.as_str()) {
            Some(s) => s,
            None => {
                return ReputationDetail {
                    agent_did: did.clone(),
                    score: 0,
                    compliance_rate: 0.0,
                    violation_rate: 0.0,
                    total_actions: 0,
                    weighted_settled_minor: 0,
                    lifetime_settled_minor: 0,
                    largest_single_minor: 0,
                    distinct_counterparties: 0,
                    principal_ref: None,
                    first_seen: None,
                    provenance_bonus_bps: 0,
                    penalties: Vec::new(),
                }
            }
        };

        let related = self.related.get(did.as_str());
        let mut penalties = Vec::new();

        // ── Recency-weighted volume, with related-party volume removed ────────
        let mut weighted_settled = 0f64;
        let mut weighted_total = 0f64;
        let mut weighted_violated = 0f64;
        let mut wash_minor: u128 = 0;
        let mut by_counterparty: HashMap<&str, f64> = HashMap::new();

        for e in &stats.events {
            let w = self.decay_weight(e.at, now);
            let is_wash = e
                .counterparty
                .as_deref()
                .map(|cp| related.map(|r| r.contains(cp)).unwrap_or(false))
                .unwrap_or(false);

            if is_wash {
                wash_minor = wash_minor.saturating_add(e.minor);
                continue;
            }

            let v = e.minor as f64 * w;
            weighted_total += v;
            if e.settled {
                weighted_settled += v;
                if let Some(cp) = e.counterparty.as_deref() {
                    *by_counterparty.entry(cp).or_insert(0.0) += v;
                }
            }
            if e.violated {
                weighted_violated += v;
            }
        }

        if wash_minor > 0 {
            penalties.push(PenaltyReason::WashVolume {
                discounted_minor: wash_minor,
            });
        }

        // ── Compliance, weighted by value rather than by count ────────────────
        // With no valued events, fall back to the count ratio so that non-payment
        // action types still register as behavior.
        let compliance = if weighted_total > 0.0 {
            (weighted_settled / weighted_total).clamp(0.0, 1.0)
        } else if stats.total > 0 {
            stats.successes as f64 / stats.total as f64
        } else {
            0.0
        };

        // ── Sublinear depth ───────────────────────────────────────────────────
        // Corroborated volume is credited slightly more. Provenance does not
        // manufacture standing; it raises confidence in settlements the agent
        // already made.
        let bonus_bps = self.provenance_bonus_bps(did);
        let corroborated = weighted_settled * (1.0 + bonus_bps as f64 / 10_000.0);
        let saturation = self.config.depth_saturation_minor.max(1) as f64;
        let depth = (corroborated / saturation).sqrt().clamp(0.0, 1.0);

        let mut score = compliance * depth * 1000.0;

        // ── Violation penalty, value-weighted ─────────────────────────────────
        if weighted_total > 0.0 && weighted_violated > 0.0 {
            let share = (weighted_violated / weighted_total).clamp(0.0, 1.0);
            let pts = share * self.config.max_violation_penalty;
            score -= pts;
            penalties.push(PenaltyReason::Violations {
                points: pts.round() as u32,
                share_bps: (share * 10_000.0).round() as u32,
            });
        } else if stats.violations > 0 && stats.total > 0 {
            let share = stats.violations as f64 / stats.total as f64;
            let pts = share * self.config.max_violation_penalty;
            score -= pts;
            penalties.push(PenaltyReason::Violations {
                points: pts.round() as u32,
                share_bps: (share * 10_000.0).round() as u32,
            });
        }

        // ── Velocity anomaly ──────────────────────────────────────────────────
        if let Some((ratio, pts)) = self.velocity_penalty(stats, now) {
            score -= pts;
            penalties.push(PenaltyReason::VelocitySpike {
                points: pts.round() as u32,
                ratio_x100: (ratio * 100.0).round().min(u32::MAX as f64) as u32,
            });
        }

        // ── Counterparty concentration (Herfindahl) ───────────────────────────
        if weighted_settled > 0.0 && !by_counterparty.is_empty() {
            let hhi: f64 = by_counterparty
                .values()
                .map(|v| {
                    let share = v / weighted_settled;
                    share * share
                })
                .sum();
            if hhi > 0.5 {
                let pts = ((hhi - 0.5) / 0.5) * self.config.max_concentration_penalty;
                score -= pts;
                penalties.push(PenaltyReason::Concentration {
                    points: pts.round() as u32,
                    hhi_x100: (hhi * 100.0).round() as u32,
                });
            }
        }

        let distinct = by_counterparty.len();
        let violation_rate = if stats.total == 0 {
            0.0
        } else {
            stats.violations as f64 / stats.total as f64
        };

        ReputationDetail {
            agent_did: did.clone(),
            score: score.clamp(0.0, 1000.0) as u32,
            compliance_rate: compliance,
            violation_rate,
            total_actions: stats.total,
            weighted_settled_minor: weighted_settled.max(0.0) as u128,
            lifetime_settled_minor: stats.lifetime_settled,
            largest_single_minor: stats.largest_single,
            distinct_counterparties: distinct,
            principal_ref: stats.principal_ref.clone(),
            first_seen: stats.first_seen,
            provenance_bonus_bps: bonus_bps,
            penalties,
        }
    }

    /// Compare the largest draw in the last 24h against the trailing average of
    /// everything before it. Returns `(ratio, points)` when the spike is large
    /// enough to matter.
    fn velocity_penalty(&self, stats: &AgentStats, now: DateTime<Utc>) -> Option<(f64, f64)> {
        let cutoff = now - Duration::hours(24);
        let mut recent_max = 0u128;
        let mut trailing_sum = 0u128;
        let mut trailing_count = 0u64;

        for e in &stats.events {
            if e.at >= cutoff {
                recent_max = recent_max.max(e.minor);
            } else {
                trailing_sum = trailing_sum.saturating_add(e.minor);
                trailing_count += 1;
            }
        }

        // Needs a trailing baseline to be an anomaly rather than simply a start.
        if trailing_count < 3 || recent_max == 0 {
            return None;
        }
        let trailing_mean = trailing_sum as f64 / trailing_count as f64;
        if trailing_mean <= 0.0 {
            return None;
        }

        let ratio = recent_max as f64 / trailing_mean;
        if ratio <= self.config.velocity_tolerance {
            return None;
        }
        let over = ratio - self.config.velocity_tolerance;
        let pts = (over * 30.0).min(self.config.max_velocity_penalty);
        Some((ratio, pts))
    }

    pub fn score(&self, did: &AgentDid) -> ByzResult<ReputationScore> {
        let d = self.detail(did);
        Ok(ReputationScore {
            agent_did: did.clone(),
            score: d.score,
            compliance_rate: d.compliance_rate,
            violation_rate: d.violation_rate,
            total_actions: d.total_actions,
            computed_at: Utc::now(),
            commitment: None,
            commitment_nonce: None,
        })
    }

    /// Check if agent meets threshold. Returns (meets, score).
    /// The ZK proof (byz-proof) proves the same fact without exposing the raw score.
    pub fn meets_threshold(
        &self,
        did: &AgentDid,
        threshold: Option<u32>,
    ) -> ByzResult<(bool, u32)> {
        let t = threshold.unwrap_or(self.default_threshold);
        let rep = self.score(did)?;
        Ok((rep.score >= t, rep.score))
    }

    /// All agent DIDs currently tracked. Used by the background proof refresh job.
    pub fn all_agent_dids(&self) -> Vec<AgentDid> {
        self.scores.keys().map(AgentDid::new).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::Money;

    fn did(s: &str) -> AgentDid {
        AgentDid::new(s)
    }

    fn settle(svc: &mut ReputationService, d: &AgentDid, cents: u64, cp: &str, at: DateTime<Utc>) {
        svc.ingest(
            ScoringEvent::new(d.clone(), ReceiptOutcome::Success, false)
                .with_amount(Money::usd_cents(cents))
                .with_counterparty(cp)
                .at(at),
        );
    }

    #[test]
    fn unknown_agent_scores_zero_not_neutral() {
        let svc = ReputationService::new(400);
        let d = did("did:byz:brand-new");
        assert_eq!(svc.score(&d).unwrap().score, 0);
        assert!(!svc.meets_threshold(&d, None).unwrap().0);
    }

    #[test]
    fn tiny_clean_volume_earns_a_tiny_score() {
        // The bust-out defense: 500 clean one-dollar transfers is not evidence
        // that the agent can be trusted with a large draw.
        let mut svc = ReputationService::new(400);
        let d = did("did:byz:farmer");
        let now = Utc::now();
        for i in 0..500 {
            settle(
                &mut svc,
                &d,
                100,
                &format!("cp-{}", i % 40),
                now - Duration::minutes(i as i64),
            );
        }
        let s = svc.detail(&d);
        assert_eq!(s.compliance_rate, 1.0, "history is spotless");
        assert!(
            s.score < 250,
            "spotless but shallow history scored {}",
            s.score
        );
    }

    #[test]
    fn score_grows_sublinearly_with_settled_value() {
        let now = Utc::now();
        let build = |per_tx: u64| {
            let mut svc = ReputationService::new(400);
            let d = did("did:byz:a");
            for i in 0..40 {
                settle(
                    &mut svc,
                    &d,
                    per_tx,
                    &format!("cp-{}", i % 20),
                    now - Duration::minutes(i),
                );
            }
            svc.detail(&d).score
        };
        let small = build(1_000);
        let big = build(4_000);
        assert!(big > small);
        // Four times the value must not buy four times the standing.
        assert!(
            (big as f64) < (small as f64) * 4.0,
            "score scaled linearly: {small} -> {big}"
        );
    }

    #[test]
    fn violations_cost_more_when_they_carry_value() {
        let now = Utc::now();
        let mut svc = ReputationService::new(400);
        let clean = did("did:byz:clean");
        let dirty = did("did:byz:dirty");

        for i in 0..30 {
            settle(
                &mut svc,
                &clean,
                50_000,
                &format!("cp-{i}"),
                now - Duration::minutes(i),
            );
            settle(
                &mut svc,
                &dirty,
                50_000,
                &format!("cp-{i}"),
                now - Duration::minutes(i),
            );
        }
        // One large violating action on the dirty agent.
        svc.ingest(
            ScoringEvent::new(
                dirty.clone(),
                ReceiptOutcome::Failed {
                    reason: "cap".into(),
                },
                true,
            )
            .with_amount(Money::usd_cents(400_000))
            .with_counterparty("cp-x")
            .at(now),
        );

        let cs = svc.detail(&clean).score;
        let ds = svc.detail(&dirty);
        assert!(
            ds.score < cs,
            "violation did not reduce score: {} vs {}",
            ds.score,
            cs
        );
        assert!(ds
            .penalties
            .iter()
            .any(|p| matches!(p, PenaltyReason::Violations { .. })));
    }

    #[test]
    fn sudden_spike_is_penalized_as_velocity() {
        let now = Utc::now();
        let mut svc = ReputationService::new(400);
        let d = did("did:byz:spiker");
        // Steady trailing history, well outside the 24h window.
        for i in 0..20 {
            settle(
                &mut svc,
                &d,
                10_000,
                &format!("cp-{i}"),
                now - Duration::days(3 + i),
            );
        }
        let calm = svc.detail(&d).score;

        // A draw 50x the trailing mean, inside the last 24h.
        settle(&mut svc, &d, 500_000, "cp-new", now - Duration::hours(1));
        let spiked = svc.detail(&d);

        assert!(
            spiked
                .penalties
                .iter()
                .any(|p| matches!(p, PenaltyReason::VelocitySpike { .. })),
            "no velocity penalty recorded: {:?}",
            spiked.penalties
        );
        assert!(
            spiked.score < calm + 200,
            "spike was rewarded rather than damped"
        );
    }

    #[test]
    fn wash_volume_with_related_counterparties_earns_nothing() {
        let now = Utc::now();
        let mut svc = ReputationService::new(400);
        let d = did("did:byz:washer");
        svc.mark_related_counterparty(&d, "sibling-agent");
        for i in 0..40 {
            settle(
                &mut svc,
                &d,
                100_000,
                "sibling-agent",
                now - Duration::minutes(i),
            );
        }
        let s = svc.detail(&d);
        assert_eq!(
            s.weighted_settled_minor, 0,
            "self-dealing counted toward standing"
        );
        assert_eq!(s.score, 0);
        assert!(s
            .penalties
            .iter()
            .any(|p| matches!(p, PenaltyReason::WashVolume { .. })));
    }

    #[test]
    fn concentrated_counterparties_are_discounted() {
        let now = Utc::now();
        let mut spread = ReputationService::new(400);
        let mut narrow = ReputationService::new(400);
        let d = did("did:byz:a");

        for i in 0..40 {
            settle(
                &mut spread,
                &d,
                100_000,
                &format!("cp-{i}"),
                now - Duration::minutes(i),
            );
            settle(
                &mut narrow,
                &d,
                100_000,
                "cp-only",
                now - Duration::minutes(i),
            );
        }
        assert!(
            narrow.detail(&d).score < spread.detail(&d).score,
            "concentration was not penalized"
        );
        assert!(narrow
            .detail(&d)
            .penalties
            .iter()
            .any(|p| matches!(p, PenaltyReason::Concentration { .. })));
    }

    #[test]
    fn old_history_decays() {
        let now = Utc::now();
        let mut recent = ReputationService::new(400);
        let mut stale = ReputationService::new(400);
        let d = did("did:byz:a");

        for i in 0..40 {
            settle(
                &mut recent,
                &d,
                100_000,
                &format!("cp-{i}"),
                now - Duration::hours(i),
            );
            settle(
                &mut stale,
                &d,
                100_000,
                &format!("cp-{i}"),
                now - Duration::days(365),
            );
        }
        assert!(
            stale.detail(&d).score < recent.detail(&d).score,
            "year-old history scored the same as this week's"
        );
    }

    #[test]
    fn principal_binding_consolidates_agents() {
        let mut svc = ReputationService::new(400);
        let a = did("did:byz:a");
        let b = did("did:byz:b");
        svc.bind_principal(&a, "sha256:prn");
        svc.bind_principal(&b, "sha256:prn");
        let agents = svc.agents_for_principal("sha256:prn");
        assert_eq!(agents.len(), 2);
        assert_eq!(svc.detail(&a).principal_ref.as_deref(), Some("sha256:prn"));
    }

    #[test]
    fn legacy_amount_cents_events_still_score() {
        let mut svc = ReputationService::new(400);
        let d = did("did:byz:legacy");
        for _ in 0..30 {
            svc.ingest(ScoringEvent {
                agent_did: d.clone(),
                outcome: ReceiptOutcome::Success,
                mandate_violated: false,
                amount_cents: Some(100_000),
                amount: None,
                counterparty_id: None,
                asset_class: None,
                occurred_at: None,
            });
        }
        assert!(
            svc.detail(&d).score > 0,
            "legacy events produced no standing"
        );
    }

    #[test]
    fn corroborated_settlements_score_above_uncorroborated_ones() {
        let now = Utc::now();
        let build = |with_provenance: bool| {
            let mut svc = ReputationService::new(400);
            let d = did("did:byz:a");
            for i in 0..40 {
                settle(
                    &mut svc,
                    &d,
                    50_000,
                    &format!("cp-{}", i % 20),
                    now - Duration::hours(i),
                );
            }
            if with_provenance {
                svc.ingest_provenance(
                    &d,
                    ProvenanceSummary {
                        weighted_total: 400,
                        human_approvals: 20,
                        verified_count: 200,
                    },
                );
            }
            svc.detail(&d)
        };
        let bare = build(false);
        let corroborated = build(true);

        assert_eq!(bare.provenance_bonus_bps, 0);
        assert!(corroborated.provenance_bonus_bps > 0);
        assert!(
            corroborated.score > bare.score,
            "runtime-signed evidence made no difference: {} vs {}",
            corroborated.score,
            bare.score
        );
    }

    #[test]
    fn the_provenance_bonus_saturates() {
        // Otherwise an operator with a legitimate runtime buys standing by
        // emitting more events rather than by settling more value.
        let now = Utc::now();
        let build = |weighted: u64| {
            let mut svc = ReputationService::new(400);
            let d = did("did:byz:a");
            for i in 0..40 {
                settle(
                    &mut svc,
                    &d,
                    50_000,
                    &format!("cp-{}", i % 20),
                    now - Duration::hours(i),
                );
            }
            svc.ingest_provenance(
                &d,
                ProvenanceSummary {
                    weighted_total: weighted,
                    human_approvals: 0,
                    verified_count: 1,
                },
            );
            svc.detail(&d).provenance_bonus_bps
        };
        let modest = build(500);
        let enormous = build(50_000_000);
        assert_eq!(enormous, ScoringConfig::default().max_provenance_bonus_bps);
        assert!(
            enormous <= modest + 1,
            "the bonus kept growing past saturation"
        );
    }

    #[test]
    fn provenance_alone_cannot_manufacture_standing() {
        // No settlements, mountains of traces: still nothing.
        let mut svc = ReputationService::new(400);
        let d = did("did:byz:talker");
        svc.ingest_provenance(
            &d,
            ProvenanceSummary {
                weighted_total: 1_000_000,
                human_approvals: 5_000,
                verified_count: 900_000,
            },
        );
        assert_eq!(svc.detail(&d).score, 0);
    }

    #[test]
    fn event_buffer_is_bounded() {
        let mut svc = ReputationService::new(400).with_config(ScoringConfig {
            max_events: 10,
            ..Default::default()
        });
        let d = did("did:byz:a");
        let now = Utc::now();
        for i in 0..100 {
            settle(&mut svc, &d, 1_000, "cp", now - Duration::minutes(i));
        }
        // Lifetime counters keep the full history even though the buffer is small.
        assert_eq!(svc.detail(&d).total_actions, 100);
    }
}
