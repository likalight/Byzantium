//! Portable limit types — the artifact the underwriting layer actually produces.
//!
//! A [`LimitAttestation`] is a signed statement about an agent, not a copy of its
//! history. That is what lets it travel: a destination chain verifies a signature
//! rather than replaying a ledger, so adding a chain costs one verifier and no
//! bridge.
//!
//! It carries a limit rather than a score on purpose. A score offloads the
//! decision onto the relying party; a limit is the thing the issuer can be held
//! to.

use crate::errors::{ByzResult, ByzantiumError};
use crate::money::{AssetClass, Currency, Money};
use crate::types::{ActionType, AgentDid};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// KYC/KYB standing of the human or entity behind an agent.
///
/// Standing *gates*; it does not *score*. A strong tier opens a wider band but
/// earns no limit on its own — otherwise the system rewards paperwork instead of
/// behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KycTier {
    /// No verified principal. Cannot be issued a limit at all.
    Unverified,
    /// Individual, basic identity check.
    Basic,
    /// Individual or entity, full KYC/KYB.
    Verified,
    /// Regulated or institutional counterparty.
    Institutional,
}

impl KycTier {
    /// The highest limit this tier may ever reach, however good the behavior.
    pub fn ceiling(&self, ccy: Currency) -> Money {
        let per_major = ccy.minor_units_per_major();
        let majors: u64 = match self {
            KycTier::Unverified => 0,
            KycTier::Basic => 2_500,
            KycTier::Verified => 250_000,
            KycTier::Institutional => 5_000_000,
        };
        Money::new(majors.saturating_mul(per_major), ccy)
    }

    /// What a principal gets before the agent has any history at all.
    ///
    /// Cold start comes from standing alone. Note that `Unverified` gets nothing:
    /// a nonzero floor for an unverified principal is free money for anyone who
    /// can generate a keypair.
    pub fn cold_start_floor(&self, ccy: Currency) -> Money {
        let per_major = ccy.minor_units_per_major();
        let majors: u64 = match self {
            KycTier::Unverified => 0,
            KycTier::Basic => 25,
            KycTier::Verified => 500,
            KycTier::Institutional => 5_000,
        };
        Money::new(majors.saturating_mul(per_major), ccy)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KycTier::Unverified => "unverified",
            KycTier::Basic => "basic",
            KycTier::Verified => "verified",
            KycTier::Institutional => "institutional",
        }
    }
}

/// The principal behind one or more agents. Limits consolidate here — splitting
/// one agent into ten splits the limit rather than multiplying it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalStanding {
    /// Pseudonymous principal reference (a hash, never raw identity).
    pub principal_ref: String,
    pub kyc_tier: KycTier,
    pub sanctions_clear: bool,
    pub jurisdiction: String,
    pub entity_age_days: u32,
    /// How many agents this principal currently operates.
    pub agent_count: u32,
}

impl PrincipalStanding {
    pub fn unverified(principal_ref: impl Into<String>) -> Self {
        Self {
            principal_ref: principal_ref.into(),
            kyc_tier: KycTier::Unverified,
            sanctions_clear: false,
            jurisdiction: String::new(),
            entity_age_days: 0,
            agent_count: 1,
        }
    }

    /// A principal that fails this cannot be issued any limit, whatever the
    /// behavioral history says.
    pub fn is_eligible(&self) -> bool {
        self.sanctions_clear && self.kyc_tier > KycTier::Unverified
    }
}

/// Risk band. Maps to a fee tier and a collateral requirement, which is how a
/// lower fee is *earned* rather than subsidised: a proven agent ties up less
/// risk capital, and the released capital is the saving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskTier {
    A1,
    A2,
    A3,
    B1,
    B2,
    B3,
    C1,
    C2,
    C3,
    D1,
    D2,
    D3,
}

impl RiskTier {
    /// Bands are 1000/12 wide over the 0–1000 composite score.
    pub fn from_score(score: u32) -> Self {
        match score.min(1000) {
            917..=1000 => RiskTier::A1,
            834..=916 => RiskTier::A2,
            751..=833 => RiskTier::A3,
            667..=750 => RiskTier::B1,
            584..=666 => RiskTier::B2,
            501..=583 => RiskTier::B3,
            417..=500 => RiskTier::C1,
            334..=416 => RiskTier::C2,
            251..=333 => RiskTier::C3,
            167..=250 => RiskTier::D1,
            84..=166 => RiskTier::D2,
            _ => RiskTier::D3,
        }
    }

    /// Fee in basis points for a drawdown at this tier.
    pub fn fee_bps(&self) -> u32 {
        match self {
            RiskTier::A1 => 10,
            RiskTier::A2 => 15,
            RiskTier::A3 => 20,
            RiskTier::B1 => 30,
            RiskTier::B2 => 40,
            RiskTier::B3 => 55,
            RiskTier::C1 => 75,
            RiskTier::C2 => 100,
            RiskTier::C3 => 135,
            RiskTier::D1 => 180,
            RiskTier::D2 => 240,
            RiskTier::D3 => 320,
        }
    }

    /// Collateral required as a share of the limit, in basis points.
    /// The fee curve above is a consequence of this, not an independent knob.
    pub fn collateral_bps(&self) -> u32 {
        match self {
            RiskTier::A1 => 0,
            RiskTier::A2 => 250,
            RiskTier::A3 => 500,
            RiskTier::B1 => 1_000,
            RiskTier::B2 => 1_500,
            RiskTier::B3 => 2_250,
            RiskTier::C1 => 3_000,
            RiskTier::C2 => 4_000,
            RiskTier::C3 => 5_500,
            RiskTier::D1 => 7_000,
            RiskTier::D2 => 8_500,
            RiskTier::D3 => 10_000,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskTier::A1 => "A1",
            RiskTier::A2 => "A2",
            RiskTier::A3 => "A3",
            RiskTier::B1 => "B1",
            RiskTier::B2 => "B2",
            RiskTier::B3 => "B3",
            RiskTier::C1 => "C1",
            RiskTier::C2 => "C2",
            RiskTier::C3 => "C3",
            RiskTier::D1 => "D1",
            RiskTier::D2 => "D2",
            RiskTier::D3 => "D3",
        }
    }
}

/// Who bears the loss when a limit turns out to be wrong.
///
/// This is the fork that determines what kind of company issues the attestation,
/// and a relying party has to be told which one it is looking at — honoring a
/// limit is a materially different decision depending on whether there is
/// recourse behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityModel {
    /// The issuer attests; the relying party bears the loss. Capital-light, and
    /// adoption depends on the relying party trusting the issuer without
    /// recourse.
    Bureau,
    /// A named guarantor bears the loss up to `covered`. Easier to adopt, but a
    /// balance-sheet business with licensing consequences.
    Underwritten,
}

impl LiabilityModel {
    pub fn has_recourse(&self) -> bool {
        matches!(self, LiabilityModel::Underwritten)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LiabilityModel::Bureau => "bureau",
            LiabilityModel::Underwritten => "underwritten",
        }
    }
}

/// The liability position attached to an attestation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Guarantee {
    pub model: LiabilityModel,
    /// Who stands behind it. Empty under the bureau model.
    pub guarantor: String,
    /// How much of the limit is actually backed. Zero under the bureau model.
    pub covered: Money,
}

impl Guarantee {
    /// No recourse: the issuer states a limit and stands behind nothing.
    pub fn bureau(ccy: Currency) -> Self {
        Self {
            model: LiabilityModel::Bureau,
            guarantor: String::new(),
            covered: Money::zero(ccy),
        }
    }

    pub fn underwritten(guarantor: impl Into<String>, covered: Money) -> Self {
        Self {
            model: LiabilityModel::Underwritten,
            guarantor: guarantor.into(),
            covered,
        }
    }

    pub fn has_recourse(&self) -> bool {
        self.model.has_recourse() && !self.covered.is_zero()
    }
}

/// Where an attestation may be presented and what may be drawn against it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimitScope {
    /// Chain identifiers this limit is honored on. Empty means any chain.
    pub chains: Vec<String>,
    pub asset_classes: Vec<AssetClass>,
    /// Counterparty classes, e.g. "kyb_verified". Empty means unrestricted.
    pub counterparty_classes: Vec<String>,
    pub action_types: Vec<ActionType>,
}

impl LimitScope {
    pub fn any() -> Self {
        Self::default()
    }

    pub fn with_chains(mut self, chains: Vec<String>) -> Self {
        self.chains = chains;
        self
    }

    pub fn with_asset_classes(mut self, classes: Vec<AssetClass>) -> Self {
        self.asset_classes = classes;
        self
    }

    pub fn with_counterparty_classes(mut self, classes: Vec<String>) -> Self {
        self.counterparty_classes = classes;
        self
    }

    pub fn with_action_types(mut self, actions: Vec<ActionType>) -> Self {
        self.action_types = actions;
        self
    }

    pub fn permits_chain(&self, chain: &str) -> bool {
        self.chains.is_empty() || self.chains.iter().any(|c| c == chain)
    }

    pub fn permits_asset_class(&self, class: AssetClass) -> bool {
        self.asset_classes.is_empty() || self.asset_classes.contains(&class)
    }

    pub fn permits_counterparty_class(&self, class: &str) -> bool {
        self.counterparty_classes.is_empty() || self.counterparty_classes.iter().any(|c| c == class)
    }

    pub fn permits_action(&self, action: &ActionType) -> bool {
        self.action_types.is_empty() || self.action_types.contains(action)
    }
}

/// Current exposure carried by one agent, in a single unit of account.
///
/// `at_risk` is the controlled variable, not transaction count. A limits system
/// that watches how many transactions an agent has made rather than how much is
/// currently outstanding is watching the wrong number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureSnapshot {
    pub agent_did: AgentDid,
    pub ccy: Currency,
    /// Committed but not yet settled.
    pub at_risk: Money,
    /// Settled inside the current window.
    pub window_used: Money,
    pub window_start: DateTime<Utc>,
    pub open_draws: u32,
}

impl ExposureSnapshot {
    pub fn empty(agent_did: AgentDid, ccy: Currency) -> Self {
        Self {
            agent_did,
            ccy,
            at_risk: Money::zero(ccy),
            window_used: Money::zero(ccy),
            window_start: Utc::now(),
            open_draws: 0,
        }
    }

    /// Everything currently counting against the window cap.
    pub fn total_committed(&self) -> ByzResult<Money> {
        self.at_risk.checked_add(&self.window_used)
    }

    pub fn window_elapsed(&self, window_secs: u64) -> bool {
        Utc::now() - self.window_start > Duration::seconds(window_secs as i64)
    }
}

/// A drawdown being checked against an attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrawRequest {
    pub amount: Money,
    pub asset_class: AssetClass,
    pub chain: String,
    pub action_type: ActionType,
    pub counterparty_class: Option<String>,
    /// Exposure already committed in the current window, in the attestation's
    /// unit of account.
    pub window_used: Money,
}

/// Why a draw was refused. Kept as a typed value rather than a string because
/// adverse-action reasoning has to survive being logged and replayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum DrawRefusal {
    Expired,
    NotYetValid,
    ChainOutOfScope { chain: String },
    AssetClassOutOfScope { asset_class: String },
    CounterpartyClassOutOfScope { class: String },
    ActionOutOfScope,
    ExceedsSingle { requested: u64, cap: u64 },
    ExceedsWindow { would_reach: u64, cap: u64 },
}

impl DrawRefusal {
    pub fn describe(&self) -> String {
        match self {
            DrawRefusal::Expired => "attestation has expired".to_string(),
            DrawRefusal::NotYetValid => "attestation is not yet valid".to_string(),
            DrawRefusal::ChainOutOfScope { chain } => {
                format!("chain {chain} is not in the attestation scope")
            }
            DrawRefusal::AssetClassOutOfScope { asset_class } => {
                format!("asset class {asset_class} is not in the attestation scope")
            }
            DrawRefusal::CounterpartyClassOutOfScope { class } => {
                format!("counterparty class {class} is not in the attestation scope")
            }
            DrawRefusal::ActionOutOfScope => {
                "action type is not in the attestation scope".to_string()
            }
            DrawRefusal::ExceedsSingle { requested, cap } => {
                format!("draw of {requested} exceeds single-transaction cap of {cap}")
            }
            DrawRefusal::ExceedsWindow { would_reach, cap } => {
                format!("draw would reach {would_reach} against a window cap of {cap}")
            }
        }
    }
}

/// The portable credential. Short-lived by design: revocation becomes a matter of
/// declining to reissue, rather than propagating a revocation list — which is the
/// part of every credential system that fails in production.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitAttestation {
    /// Agent DID this limit belongs to.
    pub sub: AgentDid,
    /// Pseudonymous principal reference. Limits consolidate at this level.
    pub prn: String,
    /// Issuer DID.
    pub iss: String,
    pub tier: RiskTier,

    pub lim_single: Money,
    pub lim_window: Money,
    pub window_secs: u64,
    /// Unit of account. Both limits are denominated in this.
    pub ccy: Currency,

    pub scope: LimitScope,
    pub fee_bps: u32,
    pub collateral_bps: u32,

    pub nbf: DateTime<Utc>,
    pub exp: DateTime<Utc>,

    /// Hash of the evidence bundle behind this decision. A dispute is
    /// reconstructed against this without the underlying traces ever being
    /// published.
    pub ev: String,
    /// Hash of the mandate this attestation issued or refreshed.
    pub mandate_hash: String,

    /// Who bears the loss. Absent means the bureau model — no recourse — but
    /// stating it explicitly is better than making a relying party infer it.
    #[serde(default)]
    pub guarantee: Option<Guarantee>,

    /// Collateral the agent must have posted for this limit to be live, in the
    /// unit of account. Derived from the tier: a proven agent ties up less risk
    /// capital, and that released capital is what the lower fee actually is.
    #[serde(default)]
    pub collateral_required: Option<Money>,

    /// ML-DSA signature over `signing_payload()`.
    pub signature: Option<Vec<u8>>,
    pub issuer_pubkey: Option<String>,
}

impl LimitAttestation {
    /// Canonical bytes covered by the signature.
    ///
    /// `serde_json::Map` is a `BTreeMap` here, so key order is deterministic
    /// across processes — the signature stays verifiable on a different host.
    pub fn signing_payload(&self) -> ByzResult<Vec<u8>> {
        let mut chains = self.scope.chains.clone();
        chains.sort_unstable();
        let mut cp_classes = self.scope.counterparty_classes.clone();
        cp_classes.sort_unstable();
        let mut asset_classes: Vec<&str> = self
            .scope
            .asset_classes
            .iter()
            .map(|a| a.as_str())
            .collect();
        asset_classes.sort_unstable();

        let canonical = json!({
            "sub": self.sub.as_str(),
            "prn": self.prn,
            "iss": self.iss,
            "tier": self.tier.as_str(),
            "lim_single": self.lim_single.minor_units,
            "lim_window": self.lim_window.minor_units,
            "window_secs": self.window_secs,
            "ccy": self.ccy.code(),
            "scope_chains": chains,
            "scope_asset_classes": asset_classes,
            "scope_counterparty_classes": cp_classes,
            "scope_action_types": format!("{:?}", self.scope.action_types),
            "fee_bps": self.fee_bps,
            "collateral_bps": self.collateral_bps,
            "nbf": self.nbf.timestamp(),
            "exp": self.exp.timestamp(),
            "ev": self.ev,
            "mandate_hash": self.mandate_hash,
            "guarantee_model": self.guarantee.as_ref().map(|g| g.model.as_str()),
            "guarantee_guarantor": self.guarantee.as_ref().map(|g| g.guarantor.clone()),
            "guarantee_covered": self.guarantee.as_ref().map(|g| g.covered.minor_units),
            "collateral_required": self.collateral_required.map(|m| m.minor_units),
        });
        Ok(serde_json::to_vec(&canonical)?)
    }

    pub fn is_valid_at(&self, when: DateTime<Utc>) -> bool {
        when >= self.nbf && when <= self.exp
    }

    pub fn ttl_remaining(&self, when: DateTime<Utc>) -> Duration {
        self.exp - when
    }

    /// Check a drawdown against this attestation. Scope first, then amounts, so
    /// the refusal names the most specific reason.
    pub fn permits(&self, draw: &DrawRequest, now: DateTime<Utc>) -> Result<(), DrawRefusal> {
        if now < self.nbf {
            return Err(DrawRefusal::NotYetValid);
        }
        if now > self.exp {
            return Err(DrawRefusal::Expired);
        }
        if !self.scope.permits_chain(&draw.chain) {
            return Err(DrawRefusal::ChainOutOfScope {
                chain: draw.chain.clone(),
            });
        }
        if !self.scope.permits_asset_class(draw.asset_class) {
            return Err(DrawRefusal::AssetClassOutOfScope {
                asset_class: draw.asset_class.as_str().to_string(),
            });
        }
        if let Some(ref class) = draw.counterparty_class {
            if !self.scope.permits_counterparty_class(class) {
                return Err(DrawRefusal::CounterpartyClassOutOfScope {
                    class: class.clone(),
                });
            }
        }
        if !self.scope.permits_action(&draw.action_type) {
            return Err(DrawRefusal::ActionOutOfScope);
        }

        // Amounts are compared in the unit of account. Callers convert and apply
        // the asset-class haircut before building the DrawRequest.
        if draw.amount.minor_units > self.lim_single.minor_units {
            return Err(DrawRefusal::ExceedsSingle {
                requested: draw.amount.minor_units,
                cap: self.lim_single.minor_units,
            });
        }
        let would_reach = draw
            .window_used
            .minor_units
            .saturating_add(draw.amount.minor_units);
        if would_reach > self.lim_window.minor_units {
            return Err(DrawRefusal::ExceedsWindow {
                would_reach,
                cap: self.lim_window.minor_units,
            });
        }
        Ok(())
    }

    /// Fee owed on a permitted draw, at this attestation's tier.
    pub fn fee_for(&self, amount: &Money) -> ByzResult<Money> {
        if amount.currency != self.ccy {
            return Err(ByzantiumError::Internal(
                "fee must be computed in the attestation's unit of account".to_string(),
            ));
        }
        Ok(amount.scale_bps(self.fee_bps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation(single: u64, window: u64) -> LimitAttestation {
        let now = Utc::now();
        LimitAttestation {
            sub: AgentDid::new("did:byz:agent"),
            prn: "sha256:principal".to_string(),
            iss: "did:web:byzantium".to_string(),
            tier: RiskTier::B2,
            lim_single: Money::usd_cents(single),
            lim_window: Money::usd_cents(window),
            window_secs: 2_592_000,
            ccy: Currency::Usd,
            scope: LimitScope::any().with_chains(vec!["base".into(), "solana".into()]),
            fee_bps: RiskTier::B2.fee_bps(),
            collateral_bps: RiskTier::B2.collateral_bps(),
            nbf: now - Duration::minutes(1),
            exp: now + Duration::hours(1),
            ev: "sha256:evidence".to_string(),
            mandate_hash: "sha256:mandate".to_string(),
            guarantee: Some(Guarantee::bureau(Currency::Usd)),
            collateral_required: Some(Money::usd_cents(0)),
            signature: None,
            issuer_pubkey: None,
        }
    }

    fn draw(amount: u64, chain: &str, used: u64) -> DrawRequest {
        DrawRequest {
            amount: Money::usd_cents(amount),
            asset_class: AssetClass::Stablecoin,
            chain: chain.to_string(),
            action_type: ActionType::Payment,
            counterparty_class: None,
            window_used: Money::usd_cents(used),
        }
    }

    #[test]
    fn unverified_principal_is_never_eligible() {
        let p = PrincipalStanding::unverified("sha256:x");
        assert!(!p.is_eligible());
        assert_eq!(p.kyc_tier.cold_start_floor(Currency::Usd).minor_units, 0);
    }

    #[test]
    fn sanctioned_principal_is_ineligible_even_when_verified() {
        let mut p = PrincipalStanding::unverified("sha256:x");
        p.kyc_tier = KycTier::Institutional;
        p.sanctions_clear = false;
        assert!(!p.is_eligible());
    }

    #[test]
    fn tier_bands_are_monotonic_in_score() {
        assert_eq!(RiskTier::from_score(1000), RiskTier::A1);
        assert_eq!(RiskTier::from_score(0), RiskTier::D3);
        // Better score never yields a worse (higher-fee) tier.
        let mut prev = RiskTier::from_score(0).fee_bps();
        for s in (0..=1000).step_by(25) {
            let f = RiskTier::from_score(s).fee_bps();
            assert!(f <= prev, "fee rose at score {s}");
            prev = f;
        }
    }

    #[test]
    fn fees_track_collateral_downward() {
        assert!(RiskTier::A1.fee_bps() < RiskTier::D3.fee_bps());
        assert!(RiskTier::A1.collateral_bps() < RiskTier::D3.collateral_bps());
    }

    #[test]
    fn permits_a_draw_inside_every_bound() {
        let a = attestation(250_000, 2_000_000);
        assert!(a.permits(&draw(100_000, "base", 0), Utc::now()).is_ok());
    }

    #[test]
    fn refuses_chain_outside_scope() {
        let a = attestation(250_000, 2_000_000);
        let err = a
            .permits(&draw(1_000, "ethereum", 0), Utc::now())
            .unwrap_err();
        assert!(matches!(err, DrawRefusal::ChainOutOfScope { .. }));
    }

    #[test]
    fn refuses_over_single_cap() {
        let a = attestation(250_000, 2_000_000);
        let err = a
            .permits(&draw(250_001, "base", 0), Utc::now())
            .unwrap_err();
        assert!(matches!(err, DrawRefusal::ExceedsSingle { .. }));
    }

    #[test]
    fn refuses_when_window_would_be_breached() {
        let a = attestation(250_000, 2_000_000);
        let err = a
            .permits(&draw(200_000, "base", 1_900_000), Utc::now())
            .unwrap_err();
        assert!(matches!(err, DrawRefusal::ExceedsWindow { .. }));
    }

    #[test]
    fn refuses_after_expiry() {
        let mut a = attestation(250_000, 2_000_000);
        a.exp = Utc::now() - Duration::seconds(1);
        assert_eq!(
            a.permits(&draw(1, "base", 0), Utc::now()).unwrap_err(),
            DrawRefusal::Expired
        );
    }

    #[test]
    fn signing_payload_is_stable_across_scope_ordering() {
        let mut a = attestation(250_000, 2_000_000);
        let p1 = a.signing_payload().unwrap();
        a.scope.chains = vec!["solana".into(), "base".into()];
        let p2 = a.signing_payload().unwrap();
        assert_eq!(p1, p2, "scope ordering must not change the signed bytes");
    }

    #[test]
    fn signing_payload_changes_when_a_limit_changes() {
        let a = attestation(250_000, 2_000_000);
        let b = attestation(250_001, 2_000_000);
        assert_ne!(a.signing_payload().unwrap(), b.signing_payload().unwrap());
    }

    #[test]
    fn bureau_guarantee_carries_no_recourse() {
        let g = Guarantee::bureau(Currency::Usd);
        assert!(!g.has_recourse());
        assert!(g.covered.is_zero());
    }

    #[test]
    fn underwritten_guarantee_names_who_bears_the_loss() {
        let g = Guarantee::underwritten("visa-issuer-01", Money::usd_cents(500_000));
        assert!(g.has_recourse());
        assert_eq!(g.guarantor, "visa-issuer-01");
    }

    #[test]
    fn an_underwritten_guarantee_with_no_cover_has_no_recourse() {
        // Claiming a model without backing it is not recourse.
        let g = Guarantee::underwritten("someone", Money::usd_cents(0));
        assert!(!g.has_recourse());
    }

    #[test]
    fn forging_a_guarantee_changes_the_signed_bytes() {
        let a = attestation(250_000, 2_000_000);
        let mut b = attestation(250_000, 2_000_000);
        b.guarantee = Some(Guarantee::underwritten("visa", Money::usd_cents(2_000_000)));
        assert_ne!(
            a.signing_payload().unwrap(),
            b.signing_payload().unwrap(),
            "an attacker could upgrade a bureau attestation to an underwritten one"
        );
    }

    #[test]
    fn collateral_requirement_is_covered_by_the_signature() {
        let a = attestation(250_000, 2_000_000);
        let mut b = attestation(250_000, 2_000_000);
        b.collateral_required = Some(Money::usd_cents(999));
        assert_ne!(a.signing_payload().unwrap(), b.signing_payload().unwrap());
    }

    #[test]
    fn fee_is_charged_at_tier_rate() {
        let a = attestation(250_000, 2_000_000);
        // B2 is 40bps; 1000.00 USD -> 4.00 USD
        assert_eq!(
            a.fee_for(&Money::usd_cents(100_000)).unwrap().minor_units,
            400
        );
    }
}
