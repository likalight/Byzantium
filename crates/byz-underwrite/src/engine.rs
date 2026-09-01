//! The underwriting engine.
//!
//! `MandateBuilder::per_tx_cap_cents` takes a number an operator types.
//! `ReputationService` produces a 0–1000 composite. Before this crate existed
//! those two never touched: the score was reduced to a single boolean by
//! `meets_threshold` and thrown away. This is the function that connects them.
//!
//! # The controls, and why each one is here
//!
//! - **Standing gates, behavior earns.** An unverified or sanctioned principal
//!   gets nothing regardless of history. A strong KYC tier raises the ceiling but
//!   never the floor beyond cold start.
//! - **Sublinear in value.** The score already grows with the square root of
//!   settled value; the limit is linear in the score, so the limit grows with the
//!   square root of value.
//! - **Experience cap.** A limit is never a large multiple of the largest single
//!   action the agent has actually completed. This is what stops a long tail of
//!   small clean transfers from unlocking one enormous draw.
//! - **Rate cap.** A limit rises by a bounded fraction per window. Even a perfect
//!   run cannot step straight to the ceiling.
//! - **Principal consolidation.** The ceiling is shared across every agent a
//!   principal operates, so splitting one agent into ten divides the limit
//!   instead of multiplying it.
//!
//! Every one of these can refuse or reduce, and each records a typed
//! [`DecisionReason`]. Adverse-action reasoning has to be built in from the
//! start — it cannot be retrofitted onto an opaque model.

use byz_common::{
    AgentDid, Currency, ExposureSnapshot, KycTier, LimitScope, Money, PrincipalStanding, RiskTier,
};
use byz_reputation::{PenaltyReason, ReputationDetail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Tunables for limit issuance.
#[derive(Debug, Clone)]
pub struct UnderwritingConfig {
    /// Maximum proportional increase over the previous limit, in basis points.
    /// 5_000 = +50% per window.
    pub max_increase_bps: u32,
    /// Minimum absolute increase allowed per window, in minor units. Without
    /// this a limit that starts near zero can never grow proportionally.
    pub min_absolute_step_minor: u64,
    /// A limit may not exceed this multiple of the largest single completed
    /// action. Zero disables the check.
    pub experience_multiple: u64,
    /// Rolling exposure window.
    pub window_secs: u64,
    /// Attestation lifetime. Short, so revocation is a matter of not reissuing.
    pub attestation_ttl_secs: u64,
    /// Below this score an agent gets the cold-start floor only, never an
    /// earned limit.
    pub min_score_to_earn: u32,
}

impl Default for UnderwritingConfig {
    fn default() -> Self {
        Self {
            max_increase_bps: 5_000,
            // 500.00 in the unit of account.
            min_absolute_step_minor: 50_000,
            experience_multiple: 10,
            window_secs: 30 * 24 * 60 * 60,
            attestation_ttl_secs: 3_600,
            min_score_to_earn: 50,
        }
    }
}

/// A previously issued limit, used to bound how fast the next one may grow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousLimit {
    pub lim_window: Money,
    pub issued_at: DateTime<Utc>,
}

/// Everything the underwriter needs to decide.
#[derive(Debug, Clone)]
pub struct UnderwritingInput {
    pub agent_did: AgentDid,
    pub reputation: ReputationDetail,
    pub standing: PrincipalStanding,
    pub exposure: ExposureSnapshot,
    pub previous: Option<PreviousLimit>,
    pub ccy: Currency,
    pub scope: LimitScope,
}

/// One step in the decision, retained so an adverse outcome can be explained.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "step")]
pub enum DecisionReason {
    ColdStartFloor {
        minor: u64,
        kyc_tier: String,
    },
    EarnedFromScore {
        score: u32,
        minor: u64,
    },
    CappedByKycCeiling {
        ceiling_minor: u64,
    },
    CappedByExperience {
        largest_single_minor: u64,
        multiple: u64,
        capped_to_minor: u64,
    },
    CappedByPrincipalConsolidation {
        agent_count: u32,
        share_minor: u64,
    },
    CappedByIncreaseRate {
        previous_minor: u64,
        allowed_minor: u64,
    },
    OutstandingExposure {
        at_risk_minor: u64,
    },
    ScorePenalty {
        detail: String,
    },
    /// Runtime-signed execution evidence corroborated the settlement history.
    ProvenanceCorroboration {
        bonus_bps: u32,
    },
}

impl DecisionReason {
    pub fn describe(&self) -> String {
        match self {
            DecisionReason::ColdStartFloor { minor, kyc_tier } => {
                format!("cold-start floor of {minor} minor units from {kyc_tier} standing")
            }
            DecisionReason::EarnedFromScore { score, minor } => {
                format!("score {score} earned {minor} minor units")
            }
            DecisionReason::CappedByKycCeiling { ceiling_minor } => {
                format!("capped at the KYC tier ceiling of {ceiling_minor} minor units")
            }
            DecisionReason::CappedByExperience {
                largest_single_minor,
                multiple,
                capped_to_minor,
            } => format!(
                "capped to {capped_to_minor} — {multiple}x the largest completed action of {largest_single_minor}"
            ),
            DecisionReason::CappedByPrincipalConsolidation { agent_count, share_minor } => format!(
                "capped to {share_minor} — the principal ceiling shared across {agent_count} agents"
            ),
            DecisionReason::CappedByIncreaseRate { previous_minor, allowed_minor } => format!(
                "growth capped at {allowed_minor} this window, up from {previous_minor}"
            ),
            DecisionReason::OutstandingExposure { at_risk_minor } => {
                format!("{at_risk_minor} minor units are committed but unsettled")
            }
            DecisionReason::ScorePenalty { detail } => detail.clone(),
            DecisionReason::ProvenanceCorroboration { bonus_bps } => format!(
                "runtime-signed provenance corroborated {}% more settled value",
                *bonus_bps as f64 / 100.0
            ),
        }
    }
}

/// Why no limit could be issued.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "cause")]
pub enum RefusalCause {
    /// No verified principal behind the agent.
    PrincipalUnverified,
    /// Sanctions screening not clear.
    SanctionsNotClear,
    /// Agent is not bound to the principal being underwritten.
    PrincipalBindingMissing,
    /// Every control resolved to zero.
    NoHeadroom,
}

impl RefusalCause {
    pub fn describe(&self) -> String {
        match self {
            RefusalCause::PrincipalUnverified => {
                "no verified principal is bound to this agent".to_string()
            }
            RefusalCause::SanctionsNotClear => {
                "the principal has not cleared sanctions screening".to_string()
            }
            RefusalCause::PrincipalBindingMissing => {
                "the agent is not bound to the principal presented".to_string()
            }
            RefusalCause::NoHeadroom => "the controls resolved to a zero limit".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum UnderwritingOutcome {
    Issued,
    Refused { cause: RefusalCause },
}

#[derive(Debug, Clone)]
pub struct UnderwritingDecision {
    pub agent_did: AgentDid,
    pub outcome: UnderwritingOutcome,
    pub tier: RiskTier,
    pub lim_single: Money,
    pub lim_window: Money,
    pub window_secs: u64,
    pub ccy: Currency,
    pub scope: LimitScope,
    /// Headroom left after currently committed exposure. Informational — the
    /// binding check happens at draw time against the window cap.
    pub available: Money,
    /// Risk capital the agent must post for this limit to be live. This is where
    /// the fee tier comes from: a proven agent ties up less capital, and the
    /// released capital is the entire saving. Presenting the lower fee as a
    /// growth subsidy would not survive contact with a payments risk team.
    pub collateral_required: Money,
    pub reasons: Vec<DecisionReason>,
}

impl UnderwritingDecision {
    pub fn is_issued(&self) -> bool {
        matches!(self.outcome, UnderwritingOutcome::Issued)
    }

    pub fn explain(&self) -> Vec<String> {
        self.reasons.iter().map(DecisionReason::describe).collect()
    }
}

pub struct Underwriter {
    config: UnderwritingConfig,
}

impl Underwriter {
    pub fn new(config: UnderwritingConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &UnderwritingConfig {
        &self.config
    }

    /// What share of the window a single transaction may consume, by tier.
    /// This bounds loss given default on any one event — a weaker agent may hold
    /// a window limit but cannot spend it in one move.
    fn single_share_bps(tier: RiskTier) -> u32 {
        match tier {
            RiskTier::A1 | RiskTier::A2 | RiskTier::A3 => 4_000,
            RiskTier::B1 | RiskTier::B2 | RiskTier::B3 => 3_000,
            RiskTier::C1 | RiskTier::C2 | RiskTier::C3 => 2_000,
            RiskTier::D1 | RiskTier::D2 | RiskTier::D3 => 1_000,
        }
    }

    fn refuse(
        input: &UnderwritingInput,
        cause: RefusalCause,
        tier: RiskTier,
        reasons: Vec<DecisionReason>,
    ) -> UnderwritingDecision {
        UnderwritingDecision {
            agent_did: input.agent_did.clone(),
            outcome: UnderwritingOutcome::Refused { cause },
            tier,
            lim_single: Money::zero(input.ccy),
            lim_window: Money::zero(input.ccy),
            window_secs: 0,
            ccy: input.ccy,
            scope: input.scope.clone(),
            available: Money::zero(input.ccy),
            collateral_required: Money::zero(input.ccy),
            reasons,
        }
    }

    pub fn underwrite(&self, input: &UnderwritingInput) -> UnderwritingDecision {
        let ccy = input.ccy;
        let tier = RiskTier::from_score(input.reputation.score);
        let mut reasons: Vec<DecisionReason> = Vec::new();

        // Surface what suppressed the score, so a low limit is explainable.
        for p in &input.reputation.penalties {
            reasons.push(DecisionReason::ScorePenalty {
                detail: describe_penalty(p),
            });
        }
        // And what raised it, so a favourable one is equally explainable.
        if input.reputation.provenance_bonus_bps > 0 {
            reasons.push(DecisionReason::ProvenanceCorroboration {
                bonus_bps: input.reputation.provenance_bonus_bps,
            });
        }

        // ── Gate 1: standing ──────────────────────────────────────────────────
        if input.standing.kyc_tier == KycTier::Unverified {
            return Self::refuse(input, RefusalCause::PrincipalUnverified, tier, reasons);
        }
        if !input.standing.sanctions_clear {
            return Self::refuse(input, RefusalCause::SanctionsNotClear, tier, reasons);
        }
        // The agent must actually be bound to the principal being underwritten.
        if let Some(ref bound) = input.reputation.principal_ref {
            if bound != &input.standing.principal_ref {
                return Self::refuse(input, RefusalCause::PrincipalBindingMissing, tier, reasons);
            }
        }

        let ceiling = input.standing.kyc_tier.ceiling(ccy).minor_units as u128;
        let cold_start = input.standing.kyc_tier.cold_start_floor(ccy).minor_units as u128;
        reasons.push(DecisionReason::ColdStartFloor {
            minor: cold_start as u64,
            kyc_tier: input.standing.kyc_tier.as_str().to_string(),
        });

        // ── Earned component: linear in score, and score is sublinear in value ─
        let earned = if input.reputation.score < self.config.min_score_to_earn {
            0u128
        } else {
            ceiling.saturating_mul(input.reputation.score.min(1000) as u128) / 1000
        };
        reasons.push(DecisionReason::EarnedFromScore {
            score: input.reputation.score,
            minor: earned.min(u64::MAX as u128) as u64,
        });

        let mut window = cold_start.max(earned);

        // ── Experience cap ────────────────────────────────────────────────────
        // Never underwrite a large multiple of what the agent has actually done.
        // Cold start survives this: an agent with no completed actions is bounded
        // by standing alone, not by a multiple of zero.
        if self.config.experience_multiple > 0 && input.reputation.largest_single_minor > 0 {
            let cap = (input.reputation.largest_single_minor as u128)
                .saturating_mul(self.config.experience_multiple as u128)
                .max(cold_start);
            if cap < window {
                window = cap;
                reasons.push(DecisionReason::CappedByExperience {
                    largest_single_minor: input.reputation.largest_single_minor,
                    multiple: self.config.experience_multiple,
                    capped_to_minor: cap.min(u64::MAX as u128) as u64,
                });
            }
        }

        // ── KYC ceiling ───────────────────────────────────────────────────────
        if window > ceiling {
            window = ceiling;
            reasons.push(DecisionReason::CappedByKycCeiling {
                ceiling_minor: ceiling.min(u64::MAX as u128) as u64,
            });
        }

        // ── Principal consolidation ───────────────────────────────────────────
        // The ceiling belongs to the principal, not to each agent it spawns.
        let agent_count = input.standing.agent_count.max(1);
        if agent_count > 1 {
            let share = ceiling / agent_count as u128;
            if share < window {
                window = share;
                reasons.push(DecisionReason::CappedByPrincipalConsolidation {
                    agent_count,
                    share_minor: share.min(u64::MAX as u128) as u64,
                });
            }
        }

        // ── Rate cap against the previous limit ───────────────────────────────
        if let Some(ref prev) = input.previous {
            let prev_minor = prev.lim_window.minor_units as u128;
            let proportional = prev_minor
                .saturating_mul(10_000u128 + self.config.max_increase_bps as u128)
                / 10_000;
            let allowed = proportional
                .max(prev_minor.saturating_add(self.config.min_absolute_step_minor as u128));
            if window > allowed {
                window = allowed;
                reasons.push(DecisionReason::CappedByIncreaseRate {
                    previous_minor: prev.lim_window.minor_units,
                    allowed_minor: allowed.min(u64::MAX as u128) as u64,
                });
            }
        }

        if window == 0 {
            return Self::refuse(input, RefusalCause::NoHeadroom, tier, reasons);
        }

        let window_money = Money::new(window.min(u64::MAX as u128) as u64, ccy);
        let single = window_money.scale_bps(Self::single_share_bps(tier));

        // Committed-but-unsettled exposure does not shrink the limit; it is netted
        // at draw time. Recording it keeps the decision auditable.
        let committed = input
            .exposure
            .total_committed()
            .unwrap_or_else(|_| Money::zero(ccy));
        if !input.exposure.at_risk.is_zero() {
            reasons.push(DecisionReason::OutstandingExposure {
                at_risk_minor: input.exposure.at_risk.minor_units,
            });
        }
        let available = window_money
            .saturating_sub(&committed)
            .unwrap_or_else(|_| Money::zero(ccy));

        UnderwritingDecision {
            agent_did: input.agent_did.clone(),
            outcome: UnderwritingOutcome::Issued,
            tier,
            lim_single: single,
            lim_window: window_money,
            window_secs: self.config.window_secs,
            ccy,
            scope: input.scope.clone(),
            available,
            collateral_required: window_money.scale_bps(tier.collateral_bps()),
            reasons,
        }
    }
}

impl Default for Underwriter {
    fn default() -> Self {
        Self::new(UnderwritingConfig::default())
    }
}

fn describe_penalty(p: &PenaltyReason) -> String {
    p.describe()
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::AgentDid;
    use byz_common::ReceiptOutcome;
    use byz_reputation::{ReputationService, ScoringEvent};
    use chrono::Duration;

    fn standing(tier: KycTier, agents: u32) -> PrincipalStanding {
        PrincipalStanding {
            principal_ref: "sha256:prn".to_string(),
            kyc_tier: tier,
            sanctions_clear: true,
            jurisdiction: "SG".to_string(),
            entity_age_days: 400,
            agent_count: agents,
        }
    }

    /// Build a reputation detail by actually running the scorer, so these tests
    /// exercise the real score -> limit path rather than a hand-set number.
    fn earned_reputation(did: &AgentDid, per_tx_cents: u64, count: i64) -> ReputationDetail {
        let mut svc = ReputationService::new(400);
        svc.bind_principal(did, "sha256:prn");
        let now = Utc::now();
        for i in 0..count {
            svc.ingest(
                ScoringEvent::new(did.clone(), ReceiptOutcome::Success, false)
                    .with_amount(Money::usd_cents(per_tx_cents))
                    .with_counterparty(format!("cp-{}", i % 25))
                    .at(now - Duration::hours(i)),
            );
        }
        svc.detail(did)
    }

    fn input(
        did: &AgentDid,
        rep: ReputationDetail,
        st: PrincipalStanding,
        prev: Option<PreviousLimit>,
    ) -> UnderwritingInput {
        UnderwritingInput {
            agent_did: did.clone(),
            reputation: rep,
            standing: st,
            exposure: ExposureSnapshot::empty(did.clone(), Currency::Usd),
            previous: prev,
            ccy: Currency::Usd,
            scope: LimitScope::any().with_chains(vec!["base".into(), "solana".into()]),
        }
    }

    #[test]
    fn unverified_principal_gets_nothing() {
        let did = AgentDid::new("did:byz:a");
        let rep = earned_reputation(&did, 100_000, 40);
        let d = Underwriter::default().underwrite(&input(
            &did,
            rep,
            standing(KycTier::Unverified, 1),
            None,
        ));
        assert!(!d.is_issued());
        assert_eq!(
            d.outcome,
            UnderwritingOutcome::Refused {
                cause: RefusalCause::PrincipalUnverified
            }
        );
        assert_eq!(d.lim_window.minor_units, 0);
    }

    #[test]
    fn sanctioned_principal_is_refused_despite_perfect_history() {
        let did = AgentDid::new("did:byz:a");
        let rep = earned_reputation(&did, 500_000, 60);
        let mut st = standing(KycTier::Institutional, 1);
        st.sanctions_clear = false;
        let d = Underwriter::default().underwrite(&input(&did, rep, st, None));
        assert_eq!(
            d.outcome,
            UnderwritingOutcome::Refused {
                cause: RefusalCause::SanctionsNotClear
            }
        );
    }

    #[test]
    fn brand_new_agent_gets_only_the_cold_start_floor() {
        let did = AgentDid::new("did:byz:new");
        let mut svc = ReputationService::new(400);
        svc.bind_principal(&did, "sha256:prn");
        let rep = svc.detail(&did);
        assert_eq!(rep.score, 0);

        let d = Underwriter::default().underwrite(&input(
            &did,
            rep,
            standing(KycTier::Verified, 1),
            None,
        ));
        assert!(d.is_issued());
        assert_eq!(
            d.lim_window,
            KycTier::Verified.cold_start_floor(Currency::Usd),
            "a new agent should get the standing floor and nothing more"
        );
    }

    #[test]
    fn limit_grows_sublinearly_with_settled_value() {
        let did = AgentDid::new("did:byz:a");
        let uw = Underwriter::new(UnderwritingConfig {
            // Isolate the score -> limit curve from the other caps.
            experience_multiple: 0,
            ..Default::default()
        });
        let small = uw
            .underwrite(&input(
                &did,
                earned_reputation(&did, 100_000, 40),
                standing(KycTier::Institutional, 1),
                None,
            ))
            .lim_window
            .minor_units;
        let large = uw
            .underwrite(&input(
                &did,
                earned_reputation(&did, 900_000, 40),
                standing(KycTier::Institutional, 1),
                None,
            ))
            .lim_window
            .minor_units;

        assert!(large > small);
        assert!(
            (large as f64) < (small as f64) * 9.0,
            "9x the value bought {}x the limit — growth is not sublinear",
            large as f64 / small as f64
        );
    }

    #[test]
    fn experience_cap_blocks_the_bust_out_shape() {
        // Many small clean transfers must not unlock a limit far beyond anything
        // the agent has ever actually completed.
        let did = AgentDid::new("did:byz:farmer");
        let rep = earned_reputation(&did, 200, 400);
        let largest = rep.largest_single_minor;
        let d = Underwriter::default().underwrite(&input(
            &did,
            rep,
            standing(KycTier::Institutional, 1),
            None,
        ));
        assert!(d.is_issued());
        let floor = KycTier::Institutional
            .cold_start_floor(Currency::Usd)
            .minor_units;
        let bound = (largest * 10).max(floor);
        assert!(
            d.lim_window.minor_units <= bound,
            "limit {} exceeded the experience bound {}",
            d.lim_window.minor_units,
            bound
        );
    }

    #[test]
    fn kyc_ceiling_is_a_hard_stop() {
        let did = AgentDid::new("did:byz:a");
        let rep = earned_reputation(&did, 5_000_000, 200);
        let d = Underwriter::new(UnderwritingConfig {
            experience_multiple: 0,
            ..Default::default()
        })
        .underwrite(&input(&did, rep, standing(KycTier::Basic, 1), None));
        assert!(
            d.lim_window.minor_units <= KycTier::Basic.ceiling(Currency::Usd).minor_units,
            "basic tier exceeded its ceiling"
        );
    }

    #[test]
    fn splitting_into_many_agents_divides_the_limit() {
        let did = AgentDid::new("did:byz:a");
        let uw = Underwriter::new(UnderwritingConfig {
            experience_multiple: 0,
            ..Default::default()
        });
        let solo = uw
            .underwrite(&input(
                &did,
                earned_reputation(&did, 900_000, 60),
                standing(KycTier::Verified, 1),
                None,
            ))
            .lim_window
            .minor_units;
        let split = uw
            .underwrite(&input(
                &did,
                earned_reputation(&did, 900_000, 60),
                standing(KycTier::Verified, 10),
                None,
            ))
            .lim_window
            .minor_units;
        assert!(
            split < solo,
            "sybil split did not reduce the per-agent limit"
        );
    }

    #[test]
    fn increase_rate_is_capped_per_window() {
        let did = AgentDid::new("did:byz:a");
        let prev = PreviousLimit {
            lim_window: Money::usd_cents(100_000),
            issued_at: Utc::now() - Duration::days(30),
        };
        let d = Underwriter::new(UnderwritingConfig {
            experience_multiple: 0,
            ..Default::default()
        })
        .underwrite(&input(
            &did,
            earned_reputation(&did, 5_000_000, 200),
            standing(KycTier::Institutional, 1),
            Some(prev),
        ));
        // +50% proportional, or a 500.00 absolute step, whichever is larger.
        // +50% of 100_000 is 150_000, which is also 100_000 plus the 50_000
        // absolute step: the two controls coincide at this previous limit.
        let allowed = 150_000u64;
        assert_eq!(d.lim_window.minor_units, allowed);
        assert!(d
            .reasons
            .iter()
            .any(|r| matches!(r, DecisionReason::CappedByIncreaseRate { .. })));
    }

    #[test]
    fn a_small_limit_can_still_grow_by_the_absolute_step() {
        let did = AgentDid::new("did:byz:a");
        // 1.00 USD previous limit: +50% is a single cent, which would freeze it.
        let prev = PreviousLimit {
            lim_window: Money::usd_cents(100),
            issued_at: Utc::now() - Duration::days(30),
        };
        let d = Underwriter::new(UnderwritingConfig {
            experience_multiple: 0,
            ..Default::default()
        })
        .underwrite(&input(
            &did,
            earned_reputation(&did, 900_000, 60),
            standing(KycTier::Verified, 1),
            Some(prev),
        ));
        assert_eq!(d.lim_window.minor_units, 100 + 50_000);
    }

    #[test]
    fn single_cap_is_a_fraction_of_the_window() {
        let did = AgentDid::new("did:byz:a");
        let d = Underwriter::new(UnderwritingConfig {
            experience_multiple: 0,
            ..Default::default()
        })
        .underwrite(&input(
            &did,
            earned_reputation(&did, 900_000, 60),
            standing(KycTier::Institutional, 1),
            None,
        ));
        assert!(d.is_issued());
        assert!(
            d.lim_single.minor_units < d.lim_window.minor_units,
            "a single draw could consume the whole window"
        );
        let expected = d
            .lim_window
            .scale_bps(Underwriter::single_share_bps(d.tier));
        assert_eq!(d.lim_single, expected);
    }

    #[test]
    fn binding_mismatch_is_refused() {
        let did = AgentDid::new("did:byz:a");
        let mut rep = earned_reputation(&did, 100_000, 40);
        rep.principal_ref = Some("sha256:someone-else".to_string());
        let d = Underwriter::default().underwrite(&input(
            &did,
            rep,
            standing(KycTier::Verified, 1),
            None,
        ));
        assert_eq!(
            d.outcome,
            UnderwritingOutcome::Refused {
                cause: RefusalCause::PrincipalBindingMissing
            }
        );
    }

    #[test]
    fn decision_is_explainable() {
        let did = AgentDid::new("did:byz:a");
        let d = Underwriter::default().underwrite(&input(
            &did,
            earned_reputation(&did, 100_000, 40),
            standing(KycTier::Verified, 1),
            None,
        ));
        let explanation = d.explain();
        assert!(!explanation.is_empty());
        assert!(explanation.iter().any(|r| r.contains("earned")));
    }

    #[test]
    fn collateral_scales_down_as_the_tier_improves() {
        let did = AgentDid::new("did:byz:a");
        let uw = Underwriter::new(UnderwritingConfig {
            experience_multiple: 0,
            ..Default::default()
        });
        let weak = uw.underwrite(&input(
            &did,
            earned_reputation(&did, 10_000, 20),
            standing(KycTier::Institutional, 1),
            None,
        ));
        let strong = uw.underwrite(&input(
            &did,
            earned_reputation(&did, 900_000, 80),
            standing(KycTier::Institutional, 1),
            None,
        ));
        assert!(
            strong.tier < weak.tier,
            "expected a better band for more history"
        );
        assert!(
            strong.tier.collateral_bps() < weak.tier.collateral_bps(),
            "a better tier did not release capital"
        );
        assert_eq!(
            strong.collateral_required,
            strong.lim_window.scale_bps(strong.tier.collateral_bps())
        );
    }

    #[test]
    fn a_refused_decision_requires_no_collateral() {
        let did = AgentDid::new("did:byz:a");
        let d = Underwriter::default().underwrite(&input(
            &did,
            earned_reputation(&did, 100_000, 40),
            standing(KycTier::Unverified, 1),
            None,
        ));
        assert!(d.collateral_required.is_zero());
    }

    #[test]
    fn outstanding_exposure_reduces_available_headroom() {
        let did = AgentDid::new("did:byz:a");
        let mut inp = input(
            &did,
            earned_reputation(&did, 900_000, 60),
            standing(KycTier::Institutional, 1),
            None,
        );
        inp.exposure.at_risk = Money::usd_cents(25_000);
        let d = Underwriter::new(UnderwritingConfig {
            experience_multiple: 0,
            ..Default::default()
        })
        .underwrite(&inp);
        assert_eq!(
            d.available.minor_units,
            d.lim_window.minor_units.saturating_sub(25_000)
        );
        assert!(d
            .reasons
            .iter()
            .any(|r| matches!(r, DecisionReason::OutstandingExposure { .. })));
    }
}
