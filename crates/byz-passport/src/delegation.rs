//! Signed delegations between passport keys.
//!
//! A delegation is a statement by one key that another key may act on its behalf,
//! within a scope, until an expiry. The scope check is the load-bearing part: a
//! delegation may only ever narrow what the issuing key could already do.

use byz_common::{ActionType, AssetClass, Money};
use byz_crypto::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum DelegationError {
    #[error("delegation signature is invalid")]
    InvalidSignature,
    #[error("delegation is not yet valid")]
    NotYetValid,
    #[error("delegation has expired")]
    Expired,
    #[error("delegation widens scope: {0}")]
    WidensScope(String),
    #[error("delegation chain is broken at key {0}")]
    BrokenChain(String),
    #[error("delegation chain exceeds the maximum depth")]
    ChainTooDeep,
    #[error("key {0} is revoked")]
    KeyRevoked(String),
}

/// What a delegated key is permitted to do.
///
/// `None` on a bound means "inherit whatever the parent allows". An empty vector
/// on a list means the same thing — unrestricted relative to the parent, not
/// unrestricted absolutely.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DelegationScope {
    /// Largest single action this key may authorise.
    pub max_single: Option<Money>,
    /// Total this key may authorise across its lifetime.
    pub max_total: Option<Money>,
    pub actions: Vec<ActionType>,
    pub chains: Vec<String>,
    pub asset_classes: Vec<AssetClass>,
}

impl DelegationScope {
    pub fn unrestricted() -> Self {
        Self::default()
    }

    pub fn with_max_single(mut self, m: Money) -> Self {
        self.max_single = Some(m);
        self
    }

    pub fn with_max_total(mut self, m: Money) -> Self {
        self.max_total = Some(m);
        self
    }

    pub fn with_actions(mut self, a: Vec<ActionType>) -> Self {
        self.actions = a;
        self
    }

    pub fn with_chains(mut self, c: Vec<String>) -> Self {
        self.chains = c;
        self
    }

    pub fn with_asset_classes(mut self, c: Vec<AssetClass>) -> Self {
        self.asset_classes = c;
        self
    }

    /// Check that `self` is no wider than `parent`.
    ///
    /// Every bound must be at least as tight, and every list must be a subset.
    /// An unset bound inherits the parent's, so it can never be a widening.
    pub fn ensure_narrows(&self, parent: &DelegationScope) -> Result<(), DelegationError> {
        if let Some(parent_max) = parent.max_single {
            match self.max_single {
                None => {
                    return Err(DelegationError::WidensScope(
                        "child leaves max_single unbounded while the parent bounds it".into(),
                    ))
                }
                Some(child_max) => {
                    if child_max.currency != parent_max.currency {
                        return Err(DelegationError::WidensScope(format!(
                            "max_single currency {} does not match parent {}",
                            child_max.currency, parent_max.currency
                        )));
                    }
                    if child_max.minor_units > parent_max.minor_units {
                        return Err(DelegationError::WidensScope(format!(
                            "max_single {} exceeds parent {}",
                            child_max.minor_units, parent_max.minor_units
                        )));
                    }
                }
            }
        }

        if let Some(parent_total) = parent.max_total {
            match self.max_total {
                None => {
                    return Err(DelegationError::WidensScope(
                        "child leaves max_total unbounded while the parent bounds it".into(),
                    ))
                }
                Some(child_total) => {
                    if child_total.currency != parent_total.currency {
                        return Err(DelegationError::WidensScope(format!(
                            "max_total currency {} does not match parent {}",
                            child_total.currency, parent_total.currency
                        )));
                    }
                    if child_total.minor_units > parent_total.minor_units {
                        return Err(DelegationError::WidensScope(format!(
                            "max_total {} exceeds parent {}",
                            child_total.minor_units, parent_total.minor_units
                        )));
                    }
                }
            }
        }

        if !parent.actions.is_empty() {
            if self.actions.is_empty() {
                return Err(DelegationError::WidensScope(
                    "child allows all actions while the parent restricts them".into(),
                ));
            }
            for a in &self.actions {
                if !parent.actions.contains(a) {
                    return Err(DelegationError::WidensScope(format!(
                        "action {a:?} is not permitted by the parent"
                    )));
                }
            }
        }

        if !parent.chains.is_empty() {
            if self.chains.is_empty() {
                return Err(DelegationError::WidensScope(
                    "child allows all chains while the parent restricts them".into(),
                ));
            }
            for c in &self.chains {
                if !parent.chains.contains(c) {
                    return Err(DelegationError::WidensScope(format!(
                        "chain {c} is not permitted by the parent"
                    )));
                }
            }
        }

        if !parent.asset_classes.is_empty() {
            if self.asset_classes.is_empty() {
                return Err(DelegationError::WidensScope(
                    "child allows all asset classes while the parent restricts them".into(),
                ));
            }
            for c in &self.asset_classes {
                if !parent.asset_classes.contains(c) {
                    return Err(DelegationError::WidensScope(format!(
                        "asset class {} is not permitted by the parent",
                        c.as_str()
                    )));
                }
            }
        }

        Ok(())
    }

    /// Whether a concrete action falls inside this scope.
    pub fn permits(&self, amount: Option<&Money>, action: &ActionType, chain: &str) -> bool {
        if let (Some(max), Some(amt)) = (self.max_single, amount) {
            if amt.currency != max.currency || amt.minor_units > max.minor_units {
                return false;
            }
        }
        if !self.actions.is_empty() && !self.actions.contains(action) {
            return false;
        }
        if !self.chains.is_empty() && !self.chains.iter().any(|c| c == chain) {
            return false;
        }
        true
    }
}

/// A signed statement that `to_key_id` may act for `from_key_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub from_key_id: String,
    pub to_key_id: String,
    pub scope: DelegationScope,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: Option<Vec<u8>>,
}

impl Delegation {
    pub fn new(
        from_key_id: impl Into<String>,
        to_key_id: impl Into<String>,
        scope: DelegationScope,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            from_key_id: from_key_id.into(),
            to_key_id: to_key_id.into(),
            scope,
            issued_at: Utc::now(),
            expires_at,
            signature: None,
        }
    }

    /// Canonical bytes covered by the signature. Deterministic key ordering.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut actions: Vec<String> = self
            .scope
            .actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect();
        actions.sort();
        let mut chains = self.scope.chains.clone();
        chains.sort();
        let mut classes: Vec<&str> = self
            .scope
            .asset_classes
            .iter()
            .map(|c| c.as_str())
            .collect();
        classes.sort_unstable();

        let canonical = json!({
            "from": self.from_key_id,
            "to": self.to_key_id,
            "max_single": self.scope.max_single.map(|m| format!("{}:{}", m.minor_units, m.currency.code())),
            "max_total": self.scope.max_total.map(|m| format!("{}:{}", m.minor_units, m.currency.code())),
            "actions": actions,
            "chains": chains,
            "asset_classes": classes,
            "issued_at": self.issued_at.timestamp(),
            "expires_at": self.expires_at.timestamp(),
        });
        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    pub fn sign(&mut self, keypair: &DilithiumKeypair) -> Result<(), DelegationError> {
        let sig = keypair
            .sign(&self.signing_payload())
            .map_err(|_| DelegationError::InvalidSignature)?;
        self.signature = Some(sig.as_bytes().to_vec());
        Ok(())
    }

    pub fn verify(&self, issuer_key: &DilithiumPublicKey) -> Result<(), DelegationError> {
        let bytes = self
            .signature
            .as_ref()
            .ok_or(DelegationError::InvalidSignature)?;
        let sig = DilithiumSignature(bytes.clone());
        byz_crypto::dilithium::verify(&self.signing_payload(), &sig, issuer_key)
            .map_err(|_| DelegationError::InvalidSignature)?;

        let now = Utc::now();
        if now < self.issued_at {
            return Err(DelegationError::NotYetValid);
        }
        if now > self.expires_at {
            return Err(DelegationError::Expired);
        }
        Ok(())
    }

    pub fn is_active(&self, at: DateTime<Utc>) -> bool {
        at >= self.issued_at && at <= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::Currency;
    use chrono::Duration;

    fn scope(max: u64) -> DelegationScope {
        DelegationScope::unrestricted().with_max_single(Money::usd_cents(max))
    }

    #[test]
    fn a_narrower_scope_is_accepted() {
        let parent = scope(100_000);
        let child = scope(50_000);
        assert!(child.ensure_narrows(&parent).is_ok());
    }

    #[test]
    fn a_wider_amount_is_refused() {
        let parent = scope(50_000);
        let child = scope(100_000);
        assert!(matches!(
            child.ensure_narrows(&parent),
            Err(DelegationError::WidensScope(_))
        ));
    }

    #[test]
    fn an_unbounded_child_cannot_escape_a_bounded_parent() {
        // The subtle case: leaving a bound unset must not mean "unlimited".
        let parent = scope(50_000);
        let child = DelegationScope::unrestricted();
        assert!(matches!(
            child.ensure_narrows(&parent),
            Err(DelegationError::WidensScope(_))
        ));
    }

    #[test]
    fn an_empty_action_list_cannot_escape_a_restricted_parent() {
        let parent = DelegationScope::unrestricted().with_actions(vec![ActionType::Payment]);
        let child = DelegationScope::unrestricted();
        assert!(child.ensure_narrows(&parent).is_err());
    }

    #[test]
    fn a_chain_outside_the_parent_is_refused() {
        let parent = DelegationScope::unrestricted().with_chains(vec!["base".into()]);
        let child =
            DelegationScope::unrestricted().with_chains(vec!["base".into(), "solana".into()]);
        assert!(child.ensure_narrows(&parent).is_err());
    }

    #[test]
    fn a_currency_switch_is_treated_as_widening() {
        // Otherwise 100 JPY could pass a 100-cent USD bound.
        let parent = scope(50_000);
        let child =
            DelegationScope::unrestricted().with_max_single(Money::new(1_000, Currency::Jpy));
        assert!(child.ensure_narrows(&parent).is_err());
    }

    #[test]
    fn signature_roundtrips() {
        let kp = DilithiumKeypair::generate();
        let mut d = Delegation::new("k1", "k2", scope(1_000), Utc::now() + Duration::hours(1));
        d.sign(&kp).unwrap();
        assert!(d.verify(&kp.public_key).is_ok());
    }

    #[test]
    fn tampering_with_the_scope_breaks_the_signature() {
        let kp = DilithiumKeypair::generate();
        let mut d = Delegation::new("k1", "k2", scope(1_000), Utc::now() + Duration::hours(1));
        d.sign(&kp).unwrap();
        d.scope = scope(1_000_000);
        assert_eq!(
            d.verify(&kp.public_key),
            Err(DelegationError::InvalidSignature)
        );
    }

    #[test]
    fn an_expired_delegation_does_not_verify() {
        let kp = DilithiumKeypair::generate();
        let mut d = Delegation::new("k1", "k2", scope(1_000), Utc::now() - Duration::seconds(1));
        d.sign(&kp).unwrap();
        assert_eq!(d.verify(&kp.public_key), Err(DelegationError::Expired));
    }

    #[test]
    fn permits_checks_amount_action_and_chain() {
        let s = DelegationScope::unrestricted()
            .with_max_single(Money::usd_cents(1_000))
            .with_actions(vec![ActionType::Payment])
            .with_chains(vec!["base".into()]);

        assert!(s.permits(Some(&Money::usd_cents(999)), &ActionType::Payment, "base"));
        assert!(!s.permits(Some(&Money::usd_cents(1_001)), &ActionType::Payment, "base"));
        assert!(!s.permits(Some(&Money::usd_cents(10)), &ActionType::ApiCall, "base"));
        assert!(!s.permits(Some(&Money::usd_cents(10)), &ActionType::Payment, "solana"));
    }
}
