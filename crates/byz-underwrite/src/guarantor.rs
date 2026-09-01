//! Who bears the loss — the bureau/underwriter fork, made pluggable.
//!
//! The recommendation is to launch as a **bureau**: attest, and let the relying
//! party carry the loss. It is capital-light and keeps the issuer out of lending.
//!
//! The reason it is a trait rather than an assumption is that the alternative has
//! to remain available without re-architecting. Visa is not the lender either —
//! issuers are — so a format where the risk-bearer is a separate, pluggable party
//! is the one that lets Visa, an issuer, or a reinsurer take the position later
//! without the attestation format or the underwriting engine changing.
//!
//! [`BackedGuarantor`] deliberately tracks finite capacity. A guarantor that says
//! yes to everything is not a guarantor, and modelling capacity is what forces
//! the question of what happens when it runs out — the answer being that coverage
//! degrades to the bureau model rather than silently over-committing.

use byz_common::{Currency, Guarantee, LiabilityModel, Money};

use crate::engine::UnderwritingDecision;

/// A party that may stand behind an issued limit.
pub trait Guarantor: Send + Sync {
    fn name(&self) -> &str;

    fn model(&self) -> LiabilityModel;

    /// What this guarantor will cover for a given decision.
    fn assess(&self, decision: &UnderwritingDecision) -> Guarantee;

    /// Remaining capacity, where the concept applies.
    fn capacity_remaining(&self) -> Option<Money> {
        None
    }
}

/// No recourse. The issuer states a limit and stands behind nothing.
#[derive(Debug, Clone, Default)]
pub struct BureauGuarantor;

impl Guarantor for BureauGuarantor {
    fn name(&self) -> &str {
        "bureau"
    }

    fn model(&self) -> LiabilityModel {
        LiabilityModel::Bureau
    }

    fn assess(&self, decision: &UnderwritingDecision) -> Guarantee {
        Guarantee::bureau(decision.ccy)
    }
}

/// Covers losses up to a finite capacity, in one unit of account.
#[derive(Debug, Clone)]
pub struct BackedGuarantor {
    name: String,
    ccy: Currency,
    capacity: u64,
    committed: u64,
    /// Share of a limit this guarantor will cover, in basis points. A guarantor
    /// covering 100% of a limit has no reason to care whether the limit is right.
    coverage_bps: u32,
}

impl BackedGuarantor {
    pub fn new(name: impl Into<String>, capacity: Money) -> Self {
        Self {
            name: name.into(),
            ccy: capacity.currency,
            capacity: capacity.minor_units,
            committed: 0,
            coverage_bps: 8_000,
        }
    }

    pub fn with_coverage_bps(mut self, bps: u32) -> Self {
        self.coverage_bps = bps.min(10_000);
        self
    }

    pub fn capacity(&self) -> Money {
        Money::new(self.capacity, self.ccy)
    }

    pub fn committed(&self) -> Money {
        Money::new(self.committed, self.ccy)
    }

    fn remaining(&self) -> u64 {
        self.capacity.saturating_sub(self.committed)
    }

    /// Reserve capacity against an issued limit. Returns what was actually
    /// committed, which may be less than requested near the capacity ceiling.
    pub fn commit(&mut self, amount: Money) -> Money {
        if amount.currency != self.ccy {
            return Money::zero(self.ccy);
        }
        let taken = amount.minor_units.min(self.remaining());
        self.committed = self.committed.saturating_add(taken);
        Money::new(taken, self.ccy)
    }

    /// Release capacity when a limit expires or is revoked.
    pub fn release(&mut self, amount: Money) {
        if amount.currency == self.ccy {
            self.committed = self.committed.saturating_sub(amount.minor_units);
        }
    }
}

impl Guarantor for BackedGuarantor {
    fn name(&self) -> &str {
        &self.name
    }

    fn model(&self) -> LiabilityModel {
        LiabilityModel::Underwritten
    }

    fn assess(&self, decision: &UnderwritingDecision) -> Guarantee {
        if decision.ccy != self.ccy || !decision.is_issued() {
            return Guarantee::bureau(decision.ccy);
        }
        let wanted = decision.lim_window.scale_bps(self.coverage_bps).minor_units;
        let covered = wanted.min(self.remaining());
        if covered == 0 {
            // Out of capacity: degrade to no recourse rather than promise cover
            // that does not exist.
            return Guarantee::bureau(decision.ccy);
        }
        Guarantee::underwritten(&self.name, Money::new(covered, self.ccy))
    }

    fn capacity_remaining(&self) -> Option<Money> {
        Some(Money::new(self.remaining(), self.ccy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Underwriter, UnderwritingConfig, UnderwritingInput};
    use byz_common::{
        AgentDid, AssetClass, ExposureSnapshot, KycTier, LimitScope, PrincipalStanding,
        ReceiptOutcome,
    };
    use byz_reputation::{ReputationService, ScoringEvent};
    use chrono::{Duration, Utc};

    fn decision() -> UnderwritingDecision {
        let did = AgentDid::new("did:byz:a");
        let mut svc = ReputationService::new(400);
        svc.bind_principal(&did, "sha256:acme");
        let now = Utc::now();
        for i in 0..60 {
            svc.ingest(
                ScoringEvent::new(did.clone(), ReceiptOutcome::Success, false)
                    .with_amount(Money::usd_cents(400_000))
                    .with_counterparty(format!("cp-{}", i % 25))
                    .at(now - Duration::hours(i)),
            );
        }
        Underwriter::new(UnderwritingConfig::default()).underwrite(&UnderwritingInput {
            agent_did: did.clone(),
            reputation: svc.detail(&did),
            standing: PrincipalStanding {
                principal_ref: "sha256:acme".into(),
                kyc_tier: KycTier::Institutional,
                sanctions_clear: true,
                jurisdiction: "SG".into(),
                entity_age_days: 900,
                agent_count: 1,
            },
            exposure: ExposureSnapshot::empty(did, Currency::Usd),
            previous: None,
            ccy: Currency::Usd,
            scope: LimitScope::any().with_asset_classes(vec![AssetClass::Stablecoin]),
        })
    }

    #[test]
    fn the_bureau_covers_nothing() {
        let g = BureauGuarantor;
        let guarantee = g.assess(&decision());
        assert_eq!(guarantee.model, LiabilityModel::Bureau);
        assert!(!guarantee.has_recourse());
        assert!(guarantee.covered.is_zero());
    }

    #[test]
    fn a_backed_guarantor_covers_a_share_and_names_itself() {
        let d = decision();
        let g = BackedGuarantor::new("visa-issuer-01", Money::usd_cents(100_000_000));
        let guarantee = g.assess(&d);
        assert_eq!(guarantee.model, LiabilityModel::Underwritten);
        assert_eq!(guarantee.guarantor, "visa-issuer-01");
        assert!(guarantee.has_recourse());
        assert!(
            guarantee.covered.minor_units < d.lim_window.minor_units,
            "full coverage leaves the guarantor indifferent to whether the limit is right"
        );
    }

    #[test]
    fn coverage_is_bounded_by_remaining_capacity() {
        let d = decision();
        let mut g = BackedGuarantor::new("small-guarantor", Money::usd_cents(1_000));
        let guarantee = g.assess(&d);
        assert!(guarantee.covered.minor_units <= 1_000);

        g.commit(Money::usd_cents(1_000));
        assert_eq!(g.capacity_remaining().unwrap().minor_units, 0);
    }

    #[test]
    fn an_exhausted_guarantor_degrades_to_the_bureau_model() {
        // Better to say there is no recourse than to promise cover that is gone.
        let d = decision();
        let mut g = BackedGuarantor::new("tapped-out", Money::usd_cents(500));
        g.commit(Money::usd_cents(500));
        assert_eq!(g.assess(&d).model, LiabilityModel::Bureau);
    }

    #[test]
    fn committing_more_than_capacity_takes_only_what_is_left() {
        let mut g = BackedGuarantor::new("g", Money::usd_cents(1_000));
        let taken = g.commit(Money::usd_cents(5_000));
        assert_eq!(taken.minor_units, 1_000);
        assert_eq!(g.committed().minor_units, 1_000);
    }

    #[test]
    fn releasing_frees_capacity_for_reuse() {
        let mut g = BackedGuarantor::new("g", Money::usd_cents(1_000));
        g.commit(Money::usd_cents(1_000));
        g.release(Money::usd_cents(400));
        assert_eq!(g.capacity_remaining().unwrap().minor_units, 400);
    }

    #[test]
    fn a_currency_mismatch_is_not_silently_covered() {
        let mut d = decision();
        d.ccy = Currency::Sgd;
        let g = BackedGuarantor::new("usd-only", Money::usd_cents(100_000_000));
        assert_eq!(g.assess(&d).model, LiabilityModel::Bureau);
    }

    #[test]
    fn a_refused_decision_is_never_guaranteed() {
        let did = AgentDid::new("did:byz:a");
        let mut svc = ReputationService::new(400);
        let refused = Underwriter::default().underwrite(&UnderwritingInput {
            agent_did: did.clone(),
            reputation: svc.detail(&did),
            standing: PrincipalStanding::unverified("sha256:x"),
            exposure: ExposureSnapshot::empty(did, Currency::Usd),
            previous: None,
            ccy: Currency::Usd,
            scope: LimitScope::any(),
        });
        let g = BackedGuarantor::new("g", Money::usd_cents(100_000_000));
        assert_eq!(g.assess(&refused).model, LiabilityModel::Bureau);
        let _ = &mut svc;
    }
}
