//! Multicurrency value types.
//!
//! The limits system has exactly one unit of account per attestation. Every
//! drawdown, whatever chain or asset it settles in, is converted into that unit
//! before it is netted against the window cap.
//!
//! The subtle part is the haircut. An open window denominated in one currency but
//! drawn in several is a larger real position than the number on the attestation
//! suggests, because the rate can move against the issuer before the window
//! closes. `AssetClass::haircut_bps` widens the recorded exposure to cover that,
//! which is why `AssetClass` is a scope field rather than a convenience label.

use crate::errors::{ByzResult, ByzantiumError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Unit of account. Limits are always denominated in one of these; the asset
/// actually drawn is described separately by [`AssetClass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[derive(Default)]
pub enum Currency {
    #[default]
    Usd,
    Sgd,
    Eur,
    Gbp,
    Jpy,
}

impl Currency {
    pub fn code(&self) -> &'static str {
        match self {
            Currency::Usd => "USD",
            Currency::Sgd => "SGD",
            Currency::Eur => "EUR",
            Currency::Gbp => "GBP",
            Currency::Jpy => "JPY",
        }
    }

    /// Decimal places in the minor unit. JPY has none — a "cent" of yen does not
    /// exist, so treating every currency as 1/100 silently inflates yen amounts
    /// by two orders of magnitude.
    pub fn exponent(&self) -> u32 {
        match self {
            Currency::Jpy => 0,
            _ => 2,
        }
    }

    pub fn minor_units_per_major(&self) -> u64 {
        10u64.pow(self.exponent())
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code.to_ascii_uppercase().as_str() {
            "USD" => Some(Currency::Usd),
            "SGD" => Some(Currency::Sgd),
            "EUR" => Some(Currency::Eur),
            "GBP" => Some(Currency::Gbp),
            "JPY" => Some(Currency::Jpy),
            _ => None,
        }
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// An amount in minor units of a specific currency.
///
/// Deliberately integer-only. Limits and exposure must never accumulate floating
/// point error — a limit that drifts is a limit that can be crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    pub minor_units: u64,
    pub currency: Currency,
}

impl Money {
    pub fn new(minor_units: u64, currency: Currency) -> Self {
        Self {
            minor_units,
            currency,
        }
    }

    /// Bridge for the legacy `amount_cents: u64` fields, which were USD-only.
    pub fn usd_cents(cents: u64) -> Self {
        Self {
            minor_units: cents,
            currency: Currency::Usd,
        }
    }

    pub fn zero(currency: Currency) -> Self {
        Self {
            minor_units: 0,
            currency,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.minor_units == 0
    }

    fn require_same_currency(&self, other: &Money) -> ByzResult<()> {
        if self.currency != other.currency {
            return Err(ByzantiumError::Internal(format!(
                "currency mismatch: {} vs {}",
                self.currency, other.currency
            )));
        }
        Ok(())
    }

    pub fn checked_add(&self, other: &Money) -> ByzResult<Money> {
        self.require_same_currency(other)?;
        let sum = self
            .minor_units
            .checked_add(other.minor_units)
            .ok_or_else(|| ByzantiumError::Internal("money addition overflowed u64".to_string()))?;
        Ok(Money {
            minor_units: sum,
            currency: self.currency,
        })
    }

    /// Saturating subtraction — exposure never goes negative.
    pub fn saturating_sub(&self, other: &Money) -> ByzResult<Money> {
        self.require_same_currency(other)?;
        Ok(Money {
            minor_units: self.minor_units.saturating_sub(other.minor_units),
            currency: self.currency,
        })
    }

    pub fn gt_amount(&self, other: &Money) -> ByzResult<bool> {
        self.require_same_currency(other)?;
        Ok(self.minor_units > other.minor_units)
    }

    /// Scale by basis points, rounding up. Rounding up matters: this is used for
    /// haircuts, and rounding a haircut down understates exposure.
    pub fn scale_bps(&self, bps: u32) -> Money {
        let scaled = (self.minor_units as u128 * bps as u128).div_ceil(10_000u128);
        Money {
            minor_units: scaled.min(u64::MAX as u128) as u64,
            currency: self.currency,
        }
    }

    pub fn to_major_string(&self) -> String {
        let per = self.currency.minor_units_per_major();
        if per == 1 {
            return format!("{} {}", self.minor_units, self.currency);
        }
        let major = self.minor_units / per;
        let minor = self.minor_units % per;
        format!(
            "{}.{:0width$} {}",
            major,
            minor,
            self.currency,
            width = self.currency.exponent() as usize
        )
    }
}

impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_major_string())
    }
}

/// What kind of asset is actually being drawn against the limit.
///
/// This is not decoration. The haircut it carries is the difference between the
/// stated limit and the real exposure the issuer is carrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetClass {
    /// Major fiat-referenced stablecoins settling near par.
    Stablecoin,
    /// Direct fiat balances in the unit of account or a closely managed peg.
    MajorFiat,
    /// Anything whose value against the unit of account can move materially
    /// inside a single window.
    Volatile,
}

impl AssetClass {
    /// Exposure widening applied when a drawdown in this class is recorded
    /// against a window denominated in the unit of account.
    pub fn haircut_bps(&self) -> u32 {
        match self {
            AssetClass::MajorFiat => 0,
            AssetClass::Stablecoin => 25,
            AssetClass::Volatile => 2_500,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AssetClass::Stablecoin => "stablecoin",
            AssetClass::MajorFiat => "major_fiat",
            AssetClass::Volatile => "volatile",
        }
    }
}

/// FX rates expressed against a single base currency.
///
/// Rates are applied at presentation, not at issuance — an attestation issued an
/// hour ago should not carry a stale rate into a settlement happening now.
#[derive(Debug, Clone)]
pub struct FxTable {
    base: Currency,
    /// Units of `currency` per one unit of `base`.
    per_base: HashMap<Currency, f64>,
}

impl FxTable {
    pub fn new(base: Currency) -> Self {
        let mut per_base = HashMap::new();
        per_base.insert(base, 1.0);
        Self { base, per_base }
    }

    pub fn with_rate(mut self, currency: Currency, units_per_base: f64) -> Self {
        self.per_base.insert(currency, units_per_base);
        self
    }

    pub fn base(&self) -> Currency {
        self.base
    }

    pub fn rate(&self, currency: Currency) -> Option<f64> {
        self.per_base.get(&currency).copied()
    }

    /// Convert into `to`, rounding up so conversion never understates exposure.
    pub fn convert(&self, amount: &Money, to: Currency) -> ByzResult<Money> {
        if amount.currency == to {
            return Ok(*amount);
        }
        let from_rate = self.rate(amount.currency).ok_or_else(|| {
            ByzantiumError::NotSupported(format!("no FX rate for {}", amount.currency))
        })?;
        let to_rate = self
            .rate(to)
            .ok_or_else(|| ByzantiumError::NotSupported(format!("no FX rate for {to}")))?;
        if from_rate <= 0.0 {
            return Err(ByzantiumError::Internal(format!(
                "non-positive FX rate for {}",
                amount.currency
            )));
        }

        // Normalise minor-unit exponents across currencies with different scales.
        let major = amount.minor_units as f64 / amount.currency.minor_units_per_major() as f64;
        let in_base = major / from_rate;
        let in_target_major = in_base * to_rate;
        let minor = (in_target_major * to.minor_units_per_major() as f64).ceil();

        if !minor.is_finite() || minor < 0.0 {
            return Err(ByzantiumError::Internal(
                "FX conversion produced an invalid amount".to_string(),
            ));
        }
        Ok(Money {
            minor_units: minor as u64,
            currency: to,
        })
    }

    /// Convert and then widen by the asset class haircut. This is the number that
    /// should be netted against a window cap.
    pub fn convert_with_haircut(
        &self,
        amount: &Money,
        to: Currency,
        class: AssetClass,
    ) -> ByzResult<Money> {
        let converted = self.convert(amount, to)?;
        let haircut = converted.scale_bps(class.haircut_bps());
        converted.checked_add(&haircut)
    }
}

impl Default for FxTable {
    fn default() -> Self {
        FxTable::new(Currency::Usd)
            .with_rate(Currency::Sgd, 1.34)
            .with_rate(Currency::Eur, 0.92)
            .with_rate(Currency::Gbp, 0.79)
            .with_rate(Currency::Jpy, 151.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpy_has_no_minor_units() {
        assert_eq!(Currency::Jpy.exponent(), 0);
        assert_eq!(Currency::Jpy.minor_units_per_major(), 1);
        let m = Money::new(5000, Currency::Jpy);
        assert_eq!(m.to_major_string(), "5000 JPY");
    }

    #[test]
    fn usd_formats_with_two_places() {
        assert_eq!(Money::usd_cents(250_000).to_major_string(), "2500.00 USD");
        assert_eq!(Money::usd_cents(5).to_major_string(), "0.05 USD");
    }

    #[test]
    fn addition_rejects_currency_mismatch() {
        let usd = Money::usd_cents(100);
        let sgd = Money::new(100, Currency::Sgd);
        assert!(usd.checked_add(&sgd).is_err());
    }

    #[test]
    fn subtraction_saturates_at_zero() {
        let a = Money::usd_cents(100);
        let b = Money::usd_cents(500);
        assert_eq!(a.saturating_sub(&b).unwrap().minor_units, 0);
    }

    #[test]
    fn scale_bps_rounds_up() {
        // 1 cent at 25bps is 0.0025 cents — must round to 1, not 0, or a haircut
        // on small amounts silently disappears.
        assert_eq!(Money::usd_cents(1).scale_bps(25).minor_units, 1);
        assert_eq!(Money::usd_cents(10_000).scale_bps(25).minor_units, 25);
    }

    #[test]
    fn identity_conversion_is_exact() {
        let fx = FxTable::default();
        let m = Money::usd_cents(123_456);
        assert_eq!(fx.convert(&m, Currency::Usd).unwrap(), m);
    }

    #[test]
    fn conversion_crosses_minor_unit_scales() {
        let fx = FxTable::default();
        // 100.00 USD -> JPY at 151, and JPY has no minor units.
        let converted = fx
            .convert(&Money::usd_cents(10_000), Currency::Jpy)
            .unwrap();
        assert_eq!(converted.currency, Currency::Jpy);
        assert_eq!(converted.minor_units, 15_100);
    }

    #[test]
    fn unknown_currency_rate_is_an_error() {
        let fx = FxTable::new(Currency::Usd);
        assert!(fx.convert(&Money::usd_cents(100), Currency::Sgd).is_err());
    }

    #[test]
    fn volatile_draw_widens_exposure() {
        let fx = FxTable::default();
        let stable = fx
            .convert_with_haircut(
                &Money::usd_cents(100_000),
                Currency::Usd,
                AssetClass::Stablecoin,
            )
            .unwrap();
        let volatile = fx
            .convert_with_haircut(
                &Money::usd_cents(100_000),
                Currency::Usd,
                AssetClass::Volatile,
            )
            .unwrap();
        let fiat = fx
            .convert_with_haircut(
                &Money::usd_cents(100_000),
                Currency::Usd,
                AssetClass::MajorFiat,
            )
            .unwrap();

        assert_eq!(fiat.minor_units, 100_000);
        assert_eq!(stable.minor_units, 100_250);
        assert_eq!(volatile.minor_units, 125_000);
        assert!(volatile.minor_units > stable.minor_units);
    }
}
