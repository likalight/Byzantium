//! The passport itself — keys, their roles, and the delegation graph between them.

use byz_common::{ActionType, AgentDid, Money};
use byz_crypto::{DilithiumKeypair, DilithiumPublicKey};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::delegation::{Delegation, DelegationError, DelegationScope};

/// Maximum delegation depth. Principal → agent → session is three levels; the
/// limit stops a cycle or a pathological chain from being walked forever.
pub const MAX_CHAIN_DEPTH: usize = 4;

#[derive(Debug, Error, PartialEq)]
pub enum PassportError {
    #[error("key {0} is not in this passport")]
    UnknownKey(String),
    #[error("key {0} is revoked")]
    KeyRevoked(String),
    #[error("key {0} is outside its validity window")]
    KeyNotActive(String),
    #[error("no delegation chain reaches the principal from key {0}")]
    NoChainToPrincipal(String),
    #[error("passport already has a principal key")]
    PrincipalAlreadySet,
    #[error(transparent)]
    Delegation(#[from] DelegationError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// The KYC'd principal. Root of the chain.
    Principal,
    /// A long-lived agent key, possibly one per chain.
    Agent,
    /// Short-lived and disposable. Compromise here must not touch standing.
    Session,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportKey {
    pub key_id: String,
    pub role: KeyRole,
    pub public_key_hex: String,
    pub not_before: DateTime<Utc>,
    pub not_after: Option<DateTime<Utc>>,
    pub revoked: bool,
    /// Set when this key replaced another during rotation. Standing follows the
    /// DID, so this is provenance rather than anything the scorer consults.
    pub replaces: Option<String>,
}

impl PassportKey {
    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        if self.revoked || at < self.not_before {
            return false;
        }
        match self.not_after {
            Some(end) => at <= end,
            None => true,
        }
    }

    pub fn public_key(&self) -> Result<DilithiumPublicKey, PassportError> {
        DilithiumPublicKey::from_hex(&self.public_key_hex)
            .map_err(|_| PassportError::UnknownKey(self.key_id.clone()))
    }
}

/// One agent's keys and the delegations between them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPassport {
    pub agent_did: AgentDid,
    pub principal_ref: String,
    keys: HashMap<String, PassportKey>,
    /// Indexed by the delegated-to key id. A key has at most one parent.
    delegations: HashMap<String, Delegation>,
    principal_key_id: Option<String>,
}

impl AgentPassport {
    pub fn new(agent_did: AgentDid, principal_ref: impl Into<String>) -> Self {
        Self {
            agent_did,
            principal_ref: principal_ref.into(),
            keys: HashMap::new(),
            delegations: HashMap::new(),
            principal_key_id: None,
        }
    }

    pub fn principal_key_id(&self) -> Option<&str> {
        self.principal_key_id.as_deref()
    }

    pub fn key(&self, key_id: &str) -> Option<&PassportKey> {
        self.keys.get(key_id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &PassportKey> {
        self.keys.values()
    }

    pub fn active_keys(&self, at: DateTime<Utc>) -> Vec<&PassportKey> {
        self.keys.values().filter(|k| k.is_active_at(at)).collect()
    }

    /// Install the principal key. The root of every chain in this passport.
    pub fn set_principal_key(
        &mut self,
        key_id: impl Into<String>,
        public_key: &DilithiumPublicKey,
    ) -> Result<(), PassportError> {
        if self.principal_key_id.is_some() {
            return Err(PassportError::PrincipalAlreadySet);
        }
        let key_id = key_id.into();
        self.keys.insert(
            key_id.clone(),
            PassportKey {
                key_id: key_id.clone(),
                role: KeyRole::Principal,
                public_key_hex: public_key.to_hex(),
                not_before: Utc::now(),
                not_after: None,
                revoked: false,
                replaces: None,
            },
        );
        self.principal_key_id = Some(key_id);
        Ok(())
    }

    /// Delegate from an existing key to a new one, enforcing scope narrowing.
    #[allow(clippy::too_many_arguments)]
    pub fn delegate(
        &mut self,
        parent_key_id: &str,
        parent_keypair: &DilithiumKeypair,
        new_key_id: impl Into<String>,
        new_public_key: &DilithiumPublicKey,
        role: KeyRole,
        scope: DelegationScope,
        ttl: Duration,
    ) -> Result<(), PassportError> {
        let parent = self
            .keys
            .get(parent_key_id)
            .ok_or_else(|| PassportError::UnknownKey(parent_key_id.to_string()))?;
        if parent.revoked {
            return Err(PassportError::KeyRevoked(parent_key_id.to_string()));
        }

        // A delegation may only narrow. Without this the chain is decorative.
        let parent_scope = self.effective_scope(parent_key_id)?;
        scope.ensure_narrows(&parent_scope)?;

        let new_key_id = new_key_id.into();
        let expires_at = Utc::now() + ttl;

        let mut delegation = Delegation::new(parent_key_id, new_key_id.clone(), scope, expires_at);
        delegation.sign(parent_keypair)?;

        self.keys.insert(
            new_key_id.clone(),
            PassportKey {
                key_id: new_key_id.clone(),
                role,
                public_key_hex: new_public_key.to_hex(),
                not_before: Utc::now(),
                not_after: Some(expires_at),
                revoked: false,
                replaces: None,
            },
        );
        self.delegations.insert(new_key_id, delegation);
        Ok(())
    }

    /// The scope a key actually has, which is the intersection down its chain.
    /// The principal key is unrestricted at this level — its real bound is the
    /// limit attestation, not the passport.
    pub fn effective_scope(&self, key_id: &str) -> Result<DelegationScope, PassportError> {
        match self.delegations.get(key_id) {
            None => Ok(DelegationScope::unrestricted()),
            Some(d) => Ok(d.scope.clone()),
        }
    }

    /// Walk from a key back to the principal, verifying every hop.
    ///
    /// Returns the chain ordered from the key upward. Any revoked, expired, or
    /// unverifiable hop breaks it.
    pub fn resolve_chain(&self, key_id: &str) -> Result<Vec<&Delegation>, PassportError> {
        let mut chain = Vec::new();
        let mut cursor = key_id.to_string();
        let now = Utc::now();

        for _ in 0..MAX_CHAIN_DEPTH {
            let key = self
                .keys
                .get(&cursor)
                .ok_or_else(|| PassportError::UnknownKey(cursor.clone()))?;
            if key.revoked {
                return Err(PassportError::KeyRevoked(cursor.clone()));
            }
            if !key.is_active_at(now) {
                return Err(PassportError::KeyNotActive(cursor.clone()));
            }
            if key.role == KeyRole::Principal {
                return Ok(chain);
            }

            let delegation = self
                .delegations
                .get(&cursor)
                .ok_or_else(|| PassportError::NoChainToPrincipal(cursor.clone()))?;

            let parent = self
                .keys
                .get(&delegation.from_key_id)
                .ok_or_else(|| PassportError::UnknownKey(delegation.from_key_id.clone()))?;
            if parent.revoked {
                return Err(PassportError::KeyRevoked(parent.key_id.clone()));
            }
            delegation.verify(&parent.public_key()?)?;

            chain.push(delegation);
            cursor = delegation.from_key_id.clone();
        }

        Err(PassportError::Delegation(DelegationError::ChainTooDeep))
    }

    /// Whether a key may authorise a concrete action, checking every scope on its
    /// chain rather than only its own.
    pub fn authorizes(
        &self,
        key_id: &str,
        amount: Option<&Money>,
        action: &ActionType,
        chain_id: &str,
    ) -> Result<bool, PassportError> {
        let chain = self.resolve_chain(key_id)?;
        for delegation in chain {
            if !delegation.scope.permits(amount, action, chain_id) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Revoke one key. Its descendants stop resolving because the chain breaks,
    /// so revoking a parent implicitly revokes everything beneath it.
    pub fn revoke_key(&mut self, key_id: &str) -> Result<(), PassportError> {
        let key = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| PassportError::UnknownKey(key_id.to_string()))?;
        key.revoked = true;
        Ok(())
    }

    /// Replace a key with a new one carrying the same delegation.
    ///
    /// Standing is attached to the agent DID, so rotation costs an operator
    /// nothing. Making rotation expensive is how systems end up full of keys
    /// nobody dares replace.
    pub fn rotate_key(
        &mut self,
        old_key_id: &str,
        new_key_id: impl Into<String>,
        new_public_key: &DilithiumPublicKey,
        parent_keypair: &DilithiumKeypair,
    ) -> Result<(), PassportError> {
        let old = self
            .keys
            .get(old_key_id)
            .ok_or_else(|| PassportError::UnknownKey(old_key_id.to_string()))?
            .clone();

        let new_key_id = new_key_id.into();

        if old.role == KeyRole::Principal {
            self.keys.insert(
                new_key_id.clone(),
                PassportKey {
                    key_id: new_key_id.clone(),
                    role: KeyRole::Principal,
                    public_key_hex: new_public_key.to_hex(),
                    not_before: Utc::now(),
                    not_after: None,
                    revoked: false,
                    replaces: Some(old_key_id.to_string()),
                },
            );
            self.principal_key_id = Some(new_key_id);
        } else {
            let old_delegation = self
                .delegations
                .get(old_key_id)
                .ok_or_else(|| PassportError::NoChainToPrincipal(old_key_id.to_string()))?
                .clone();

            let mut delegation = Delegation::new(
                old_delegation.from_key_id.clone(),
                new_key_id.clone(),
                old_delegation.scope.clone(),
                old_delegation.expires_at,
            );
            delegation.sign(parent_keypair)?;

            self.keys.insert(
                new_key_id.clone(),
                PassportKey {
                    key_id: new_key_id.clone(),
                    role: old.role,
                    public_key_hex: new_public_key.to_hex(),
                    not_before: Utc::now(),
                    not_after: old.not_after,
                    revoked: false,
                    replaces: Some(old_key_id.to_string()),
                },
            );
            self.delegations.insert(new_key_id, delegation);
        }

        if let Some(k) = self.keys.get_mut(old_key_id) {
            k.revoked = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::AssetClass;

    struct Fixture {
        passport: AgentPassport,
        principal_kp: DilithiumKeypair,
        agent_kp: DilithiumKeypair,
    }

    fn fixture() -> Fixture {
        let principal_kp = DilithiumKeypair::generate();
        let agent_kp = DilithiumKeypair::generate();
        let mut passport = AgentPassport::new(AgentDid::new("did:byz:agent"), "sha256:acme");
        passport
            .set_principal_key("prn-key", &principal_kp.public_key)
            .unwrap();
        passport
            .delegate(
                "prn-key",
                &principal_kp,
                "agent-key",
                &agent_kp.public_key,
                KeyRole::Agent,
                DelegationScope::unrestricted()
                    .with_max_single(Money::usd_cents(100_000))
                    .with_actions(vec![ActionType::Payment])
                    .with_chains(vec!["base".into(), "solana".into()])
                    .with_asset_classes(vec![AssetClass::Stablecoin]),
                Duration::days(365),
            )
            .unwrap();
        Fixture {
            passport,
            principal_kp,
            agent_kp,
        }
    }

    #[test]
    fn a_session_key_resolves_to_the_principal() {
        let mut f = fixture();
        let session_kp = DilithiumKeypair::generate();
        f.passport
            .delegate(
                "agent-key",
                &f.agent_kp,
                "session-1",
                &session_kp.public_key,
                KeyRole::Session,
                DelegationScope::unrestricted()
                    .with_max_single(Money::usd_cents(5_000))
                    .with_actions(vec![ActionType::Payment])
                    .with_chains(vec!["base".into()])
                    .with_asset_classes(vec![AssetClass::Stablecoin]),
                Duration::hours(1),
            )
            .unwrap();

        let chain = f.passport.resolve_chain("session-1").unwrap();
        assert_eq!(chain.len(), 2, "session -> agent -> principal");
    }

    #[test]
    fn a_session_key_cannot_grant_itself_more_than_the_agent_has() {
        let mut f = fixture();
        let session_kp = DilithiumKeypair::generate();
        // The agent is bounded at 100,000; this asks for ten times that.
        let err = f
            .passport
            .delegate(
                "agent-key",
                &f.agent_kp,
                "session-greedy",
                &session_kp.public_key,
                KeyRole::Session,
                DelegationScope::unrestricted()
                    .with_max_single(Money::usd_cents(1_000_000))
                    .with_actions(vec![ActionType::Payment])
                    .with_chains(vec!["base".into()])
                    .with_asset_classes(vec![AssetClass::Stablecoin]),
                Duration::hours(1),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PassportError::Delegation(DelegationError::WidensScope(_))
        ));
    }

    #[test]
    fn a_session_key_cannot_reach_a_chain_the_agent_lacks() {
        let mut f = fixture();
        let session_kp = DilithiumKeypair::generate();
        let err = f.passport.delegate(
            "agent-key",
            &f.agent_kp,
            "session-x",
            &session_kp.public_key,
            KeyRole::Session,
            DelegationScope::unrestricted()
                .with_max_single(Money::usd_cents(1_000))
                .with_actions(vec![ActionType::Payment])
                .with_chains(vec!["ethereum".into()])
                .with_asset_classes(vec![AssetClass::Stablecoin]),
            Duration::hours(1),
        );
        assert!(err.is_err());
    }

    #[test]
    fn authorization_checks_every_hop_not_just_the_leaf() {
        let mut f = fixture();
        let session_kp = DilithiumKeypair::generate();
        f.passport
            .delegate(
                "agent-key",
                &f.agent_kp,
                "session-1",
                &session_kp.public_key,
                KeyRole::Session,
                DelegationScope::unrestricted()
                    .with_max_single(Money::usd_cents(5_000))
                    .with_actions(vec![ActionType::Payment])
                    .with_chains(vec!["base".into()])
                    .with_asset_classes(vec![AssetClass::Stablecoin]),
                Duration::hours(1),
            )
            .unwrap();

        assert!(f
            .passport
            .authorizes(
                "session-1",
                Some(&Money::usd_cents(4_000)),
                &ActionType::Payment,
                "base"
            )
            .unwrap());
        assert!(!f
            .passport
            .authorizes(
                "session-1",
                Some(&Money::usd_cents(6_000)),
                &ActionType::Payment,
                "base"
            )
            .unwrap());
        assert!(!f
            .passport
            .authorizes(
                "session-1",
                Some(&Money::usd_cents(100)),
                &ActionType::Payment,
                "solana"
            )
            .unwrap());
    }

    #[test]
    fn revoking_the_agent_key_kills_its_sessions() {
        let mut f = fixture();
        let session_kp = DilithiumKeypair::generate();
        f.passport
            .delegate(
                "agent-key",
                &f.agent_kp,
                "session-1",
                &session_kp.public_key,
                KeyRole::Session,
                DelegationScope::unrestricted()
                    .with_max_single(Money::usd_cents(5_000))
                    .with_actions(vec![ActionType::Payment])
                    .with_chains(vec!["base".into()])
                    .with_asset_classes(vec![AssetClass::Stablecoin]),
                Duration::hours(1),
            )
            .unwrap();
        assert!(f.passport.resolve_chain("session-1").is_ok());

        f.passport.revoke_key("agent-key").unwrap();
        assert!(
            f.passport.resolve_chain("session-1").is_err(),
            "a session survived its parent being revoked"
        );
    }

    #[test]
    fn revoking_a_session_leaves_the_agent_intact() {
        let mut f = fixture();
        let session_kp = DilithiumKeypair::generate();
        f.passport
            .delegate(
                "agent-key",
                &f.agent_kp,
                "session-1",
                &session_kp.public_key,
                KeyRole::Session,
                DelegationScope::unrestricted()
                    .with_max_single(Money::usd_cents(5_000))
                    .with_actions(vec![ActionType::Payment])
                    .with_chains(vec!["base".into()])
                    .with_asset_classes(vec![AssetClass::Stablecoin]),
                Duration::hours(1),
            )
            .unwrap();

        f.passport.revoke_key("session-1").unwrap();
        assert!(f.passport.resolve_chain("session-1").is_err());
        assert!(
            f.passport.resolve_chain("agent-key").is_ok(),
            "a compromised session should not cost the agent its key"
        );
    }

    #[test]
    fn rotation_preserves_the_did_and_the_scope() {
        let mut f = fixture();
        let replacement = DilithiumKeypair::generate();
        let scope_before = f.passport.effective_scope("agent-key").unwrap();

        f.passport
            .rotate_key(
                "agent-key",
                "agent-key-v2",
                &replacement.public_key,
                &f.principal_kp,
            )
            .unwrap();

        // The DID — which is what standing attaches to — is untouched.
        assert_eq!(f.passport.agent_did.as_str(), "did:byz:agent");
        assert_eq!(
            f.passport.effective_scope("agent-key-v2").unwrap(),
            scope_before
        );
        assert!(f.passport.resolve_chain("agent-key-v2").is_ok());
        assert!(f.passport.key("agent-key").unwrap().revoked);
        assert_eq!(
            f.passport.key("agent-key-v2").unwrap().replaces.as_deref(),
            Some("agent-key")
        );
    }

    #[test]
    fn an_unknown_key_does_not_resolve() {
        let f = fixture();
        assert!(matches!(
            f.passport.resolve_chain("nope"),
            Err(PassportError::UnknownKey(_))
        ));
    }

    #[test]
    fn a_second_principal_key_is_refused() {
        let mut f = fixture();
        let other = DilithiumKeypair::generate();
        assert_eq!(
            f.passport.set_principal_key("prn-2", &other.public_key),
            Err(PassportError::PrincipalAlreadySet)
        );
    }

    #[test]
    fn a_forged_delegation_does_not_resolve() {
        // Someone who is not the agent tries to mint a session key.
        let mut f = fixture();
        let impostor = DilithiumKeypair::generate();
        let session_kp = DilithiumKeypair::generate();

        f.passport
            .delegate(
                "agent-key",
                &impostor, // wrong signer
                "session-forged",
                &session_kp.public_key,
                KeyRole::Session,
                DelegationScope::unrestricted()
                    .with_max_single(Money::usd_cents(1_000))
                    .with_actions(vec![ActionType::Payment])
                    .with_chains(vec!["base".into()])
                    .with_asset_classes(vec![AssetClass::Stablecoin]),
                Duration::hours(1),
            )
            .unwrap();

        assert!(
            f.passport.resolve_chain("session-forged").is_err(),
            "a delegation signed by the wrong key resolved"
        );
    }
}
