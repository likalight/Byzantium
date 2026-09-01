//! Revocation.
//!
//! Attestations live for minutes to hours, so the ordinary way to withdraw a
//! limit is to decline to reissue it. That is deliberate: distributing and
//! checking a per-credential revocation list is the part of every credential
//! system that fails in production, usually silently.
//!
//! What is still needed is a way to kill the *outstanding set* early — a
//! compromised agent, a principal that fails re-screening. So revocation here is
//! expressed as a cutoff rather than a list of identifiers: everything issued to
//! this subject before this instant is dead. That is O(1) to store, O(1) to
//! check, and cannot grow without bound.

use byz_common::LimitAttestation;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Why an attestation was refused at presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "revoked_by")]
pub enum RevocationReason {
    Agent {
        agent_did: String,
        effective_from: DateTime<Utc>,
    },
    Principal {
        principal_ref: String,
        effective_from: DateTime<Utc>,
    },
}

impl RevocationReason {
    pub fn describe(&self) -> String {
        match self {
            RevocationReason::Agent { agent_did, effective_from } => {
                format!("all attestations for {agent_did} issued before {effective_from} are revoked")
            }
            RevocationReason::Principal { principal_ref, effective_from } => format!(
                "all attestations under principal {principal_ref} issued before {effective_from} are revoked"
            ),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RevocationRegistry {
    /// agent DID -> cutoff.
    agents: HashMap<String, DateTime<Utc>>,
    /// principal ref -> cutoff. Kills every agent under that principal at once.
    principals: HashMap<String, DateTime<Utc>>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke everything issued to this agent before `effective_from`.
    ///
    /// Passing a future instant is legitimate and useful: it schedules a cutoff
    /// without invalidating credentials that are mid-flight right now.
    pub fn revoke_agent(&mut self, agent_did: impl Into<String>, effective_from: DateTime<Utc>) {
        let did = agent_did.into();
        let entry = self.agents.entry(did).or_insert(effective_from);
        // Cutoffs only ever move forward — un-revoking by re-revoking earlier
        // would be a way to resurrect a killed credential.
        if effective_from > *entry {
            *entry = effective_from;
        }
    }

    pub fn revoke_agent_now(&mut self, agent_did: impl Into<String>) {
        self.revoke_agent(agent_did, Utc::now());
    }

    pub fn revoke_principal(
        &mut self,
        principal_ref: impl Into<String>,
        effective_from: DateTime<Utc>,
    ) {
        let prn = principal_ref.into();
        let entry = self.principals.entry(prn).or_insert(effective_from);
        if effective_from > *entry {
            *entry = effective_from;
        }
    }

    pub fn revoke_principal_now(&mut self, principal_ref: impl Into<String>) {
        self.revoke_principal(principal_ref, Utc::now());
    }

    /// Deliberately explicit: lifting a revocation is an administrative act, not
    /// something that happens by a cutoff quietly ageing out.
    pub fn lift_agent(&mut self, agent_did: &str) {
        self.agents.remove(agent_did);
    }

    pub fn lift_principal(&mut self, principal_ref: &str) {
        self.principals.remove(principal_ref);
    }

    /// An attestation is revoked when **both** hold:
    ///
    /// 1. the cutoff has arrived (`now >= cutoff`), and
    /// 2. the attestation was issued before it (`nbf < cutoff`).
    ///
    /// The first condition is what makes a future cutoff a *scheduled*
    /// revocation rather than an immediate one — a principal can be marked for
    /// end-of-day revocation without killing credentials that are in flight
    /// right now. The second is what lets a reissue after the cutoff be live
    /// again without any bookkeeping.
    pub fn check(&self, attestation: &LimitAttestation) -> Option<RevocationReason> {
        let now = Utc::now();

        if let Some(&cutoff) = self.agents.get(attestation.sub.as_str()) {
            if now >= cutoff && attestation.nbf < cutoff {
                return Some(RevocationReason::Agent {
                    agent_did: attestation.sub.to_string(),
                    effective_from: cutoff,
                });
            }
        }
        if let Some(&cutoff) = self.principals.get(&attestation.prn) {
            if now >= cutoff && attestation.nbf < cutoff {
                return Some(RevocationReason::Principal {
                    principal_ref: attestation.prn.clone(),
                    effective_from: cutoff,
                });
            }
        }
        None
    }

    pub fn is_revoked(&self, attestation: &LimitAttestation) -> bool {
        self.check(attestation).is_some()
    }

    /// Drop cutoffs older than `older_than`, which are guaranteed to be
    /// unreachable once every attestation issued before them has expired.
    pub fn prune(&mut self, older_than: DateTime<Utc>) {
        self.agents.retain(|_, cutoff| *cutoff >= older_than);
        self.principals.retain(|_, cutoff| *cutoff >= older_than);
    }

    pub fn len(&self) -> usize {
        self.agents.len() + self.principals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::{AgentDid, Currency, Guarantee, LimitScope, Money, RiskTier};
    use chrono::Duration;

    fn attestation(sub: &str, prn: &str, issued_at: DateTime<Utc>) -> LimitAttestation {
        LimitAttestation {
            sub: AgentDid::new(sub),
            prn: prn.to_string(),
            iss: "did:web:byzantium".to_string(),
            tier: RiskTier::B2,
            lim_single: Money::usd_cents(1_000),
            lim_window: Money::usd_cents(10_000),
            window_secs: 86_400,
            ccy: Currency::Usd,
            scope: LimitScope::any(),
            fee_bps: 40,
            collateral_bps: 1_500,
            nbf: issued_at,
            exp: issued_at + Duration::hours(1),
            ev: "sha256:e".to_string(),
            mandate_hash: "sha256:m".to_string(),
            guarantee: Some(Guarantee::bureau(Currency::Usd)),
            collateral_required: None,
            signature: None,
            issuer_pubkey: None,
        }
    }

    #[test]
    fn nothing_is_revoked_by_default() {
        let r = RevocationRegistry::new();
        assert!(!r.is_revoked(&attestation("did:byz:a", "prn", Utc::now())));
    }

    #[test]
    fn revoking_an_agent_kills_its_outstanding_attestations() {
        let mut r = RevocationRegistry::new();
        let old = attestation("did:byz:a", "prn", Utc::now() - Duration::minutes(10));
        r.revoke_agent_now("did:byz:a");
        assert!(r.is_revoked(&old));
    }

    #[test]
    fn a_reissue_after_the_cutoff_is_live_again() {
        // The cutoff kills the outstanding set, not the agent forever.
        let mut r = RevocationRegistry::new();
        r.revoke_agent("did:byz:a", Utc::now() - Duration::minutes(5));
        let fresh = attestation("did:byz:a", "prn", Utc::now());
        assert!(!r.is_revoked(&fresh));
    }

    #[test]
    fn revoking_a_principal_kills_every_agent_under_it() {
        let mut r = RevocationRegistry::new();
        r.revoke_principal_now("sha256:acme");
        let a = attestation(
            "did:byz:a",
            "sha256:acme",
            Utc::now() - Duration::minutes(1),
        );
        let b = attestation(
            "did:byz:b",
            "sha256:acme",
            Utc::now() - Duration::minutes(1),
        );
        assert!(r.is_revoked(&a));
        assert!(r.is_revoked(&b));
    }

    #[test]
    fn one_principal_revocation_does_not_touch_another() {
        let mut r = RevocationRegistry::new();
        r.revoke_principal_now("sha256:acme");
        let other = attestation(
            "did:byz:c",
            "sha256:other",
            Utc::now() - Duration::minutes(1),
        );
        assert!(!r.is_revoked(&other));
    }

    #[test]
    fn a_cutoff_never_moves_backwards() {
        // Otherwise re-revoking with an earlier time resurrects killed credentials.
        let mut r = RevocationRegistry::new();
        let now = Utc::now();
        r.revoke_agent("did:byz:a", now);
        r.revoke_agent("did:byz:a", now - Duration::hours(1));

        let between = attestation("did:byz:a", "prn", now - Duration::minutes(30));
        assert!(
            r.is_revoked(&between),
            "an earlier cutoff un-revoked a credential"
        );
    }

    #[test]
    fn a_future_cutoff_leaves_current_credentials_alone() {
        let mut r = RevocationRegistry::new();
        r.revoke_agent("did:byz:a", Utc::now() + Duration::hours(1));
        assert!(!r.is_revoked(&attestation("did:byz:a", "prn", Utc::now())));
    }

    #[test]
    fn a_scheduled_cutoff_fires_once_it_arrives() {
        // The other half of the scheduling behaviour: harmless until the cutoff,
        // then it kills everything issued before it.
        let mut r = RevocationRegistry::new();
        let cutoff = Utc::now() - Duration::seconds(1);
        r.revoke_agent("did:byz:a", cutoff);
        let issued_before = attestation("did:byz:a", "prn", cutoff - Duration::minutes(1));
        assert!(r.is_revoked(&issued_before));
    }

    #[test]
    fn the_reason_names_which_rule_fired() {
        let mut r = RevocationRegistry::new();
        r.revoke_principal_now("sha256:acme");
        let a = attestation(
            "did:byz:a",
            "sha256:acme",
            Utc::now() - Duration::minutes(1),
        );
        assert!(matches!(
            r.check(&a),
            Some(RevocationReason::Principal { .. })
        ));
        assert!(r.check(&a).unwrap().describe().contains("sha256:acme"));
    }

    #[test]
    fn lifting_a_revocation_restores_the_agent() {
        let mut r = RevocationRegistry::new();
        r.revoke_agent_now("did:byz:a");
        let a = attestation("did:byz:a", "prn", Utc::now() - Duration::minutes(1));
        assert!(r.is_revoked(&a));
        r.lift_agent("did:byz:a");
        assert!(!r.is_revoked(&a));
    }

    #[test]
    fn pruning_drops_only_unreachable_cutoffs() {
        let mut r = RevocationRegistry::new();
        r.revoke_agent("did:byz:old", Utc::now() - Duration::days(30));
        r.revoke_agent("did:byz:new", Utc::now());
        r.prune(Utc::now() - Duration::days(1));
        assert_eq!(r.len(), 1);
    }
}
