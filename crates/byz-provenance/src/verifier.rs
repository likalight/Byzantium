//! Runtime signature verification and replay defense.
//!
//! Everything that reaches the scorer passes through here first. The verifier is
//! deliberately unforgiving: an event that fails any check is dropped with a
//! typed reason and contributes nothing. There is no partial credit, because
//! partial credit is an incentive to submit noise.

use byz_common::AgentDid;
use byz_crypto::{DilithiumPublicKey, DilithiumSignature};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::event::SignedProvenance;

/// Trusted runtime signing keys, by runtime id.
///
/// A runtime is registered out of band — this is the trust root for the whole
/// provenance signal, so admitting a key is a deliberate operational act rather
/// than something an agent can trigger.
#[derive(Debug, Default, Clone)]
pub struct RuntimeRegistry {
    keys: HashMap<String, DilithiumPublicKey>,
    revoked: HashSet<String>,
}

impl RuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, runtime_id: impl Into<String>, key: DilithiumPublicKey) {
        let id = runtime_id.into();
        self.revoked.remove(&id);
        self.keys.insert(id, key);
    }

    /// Revoking keeps the id known so previously accepted evidence can still be
    /// explained, while refusing anything new signed by it.
    pub fn revoke(&mut self, runtime_id: &str) {
        self.revoked.insert(runtime_id.to_string());
    }

    pub fn is_revoked(&self, runtime_id: &str) -> bool {
        self.revoked.contains(runtime_id)
    }

    pub fn key(&self, runtime_id: &str) -> Option<&DilithiumPublicKey> {
        if self.is_revoked(runtime_id) {
            return None;
        }
        self.keys.get(runtime_id)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Why an event contributed nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "rejected")]
pub enum RejectionReason {
    /// The signing runtime is not registered.
    UnknownRuntime { runtime_id: String },
    /// The runtime key has been revoked.
    RevokedRuntime { runtime_id: String },
    /// Signature did not verify against the runtime key.
    BadSignature,
    /// Event belongs to a different agent than the one being evaluated.
    AgentMismatch { expected: String, found: String },
    /// A sequence number was reused within a session.
    DuplicateSequence { session_id: Uuid, seq: u64 },
    /// Sequence numbers went backwards within a session.
    NonMonotonicSequence {
        session_id: Uuid,
        seq: u64,
        last: u64,
    },
}

impl RejectionReason {
    pub fn describe(&self) -> String {
        match self {
            RejectionReason::UnknownRuntime { runtime_id } => {
                format!("runtime {runtime_id} is not registered")
            }
            RejectionReason::RevokedRuntime { runtime_id } => {
                format!("runtime {runtime_id} has been revoked")
            }
            RejectionReason::BadSignature => "runtime signature did not verify".to_string(),
            RejectionReason::AgentMismatch { expected, found } => {
                format!("event belongs to {found}, not {expected}")
            }
            RejectionReason::DuplicateSequence { session_id, seq } => {
                format!("sequence {seq} was already seen in session {session_id}")
            }
            RejectionReason::NonMonotonicSequence {
                session_id,
                seq,
                last,
            } => {
                format!("sequence {seq} follows {last} in session {session_id}")
            }
        }
    }
}

/// An event that passed every check.
#[derive(Debug, Clone)]
pub struct VerifiedProvenance {
    pub signed: SignedProvenance,
}

/// Verifies a stream of provenance for one agent.
pub struct ProvenanceVerifier<'a> {
    registry: &'a RuntimeRegistry,
    agent_did: AgentDid,
    /// Highest sequence seen per session, for monotonicity.
    last_seq: HashMap<Uuid, u64>,
    /// Every (session, seq) seen, for replay detection.
    seen: HashSet<(Uuid, u64)>,
}

impl<'a> ProvenanceVerifier<'a> {
    pub fn new(registry: &'a RuntimeRegistry, agent_did: AgentDid) -> Self {
        Self {
            registry,
            agent_did,
            last_seq: HashMap::new(),
            seen: HashSet::new(),
        }
    }

    /// Verify one event. Order matters: callers should submit in sequence order
    /// within a session.
    pub fn verify(
        &mut self,
        signed: &SignedProvenance,
    ) -> Result<VerifiedProvenance, RejectionReason> {
        if signed.event.agent_did != self.agent_did {
            return Err(RejectionReason::AgentMismatch {
                expected: self.agent_did.to_string(),
                found: signed.event.agent_did.to_string(),
            });
        }

        if self.registry.is_revoked(&signed.runtime_id) {
            return Err(RejectionReason::RevokedRuntime {
                runtime_id: signed.runtime_id.clone(),
            });
        }
        let key = self.registry.key(&signed.runtime_id).ok_or_else(|| {
            RejectionReason::UnknownRuntime {
                runtime_id: signed.runtime_id.clone(),
            }
        })?;

        let payload = signed.event.signing_payload();
        let sig = DilithiumSignature(signed.signature.clone());
        byz_crypto::dilithium::verify(&payload, &sig, key)
            .map_err(|_| RejectionReason::BadSignature)?;

        let session = signed.event.session_id;
        let seq = signed.event.seq;

        if !self.seen.insert((session, seq)) {
            return Err(RejectionReason::DuplicateSequence {
                session_id: session,
                seq,
            });
        }
        if let Some(&last) = self.last_seq.get(&session) {
            if seq <= last {
                return Err(RejectionReason::NonMonotonicSequence {
                    session_id: session,
                    seq,
                    last,
                });
            }
        }
        self.last_seq.insert(session, seq);

        Ok(VerifiedProvenance {
            signed: signed.clone(),
        })
    }

    /// Verify a batch, returning what passed and why the rest did not.
    ///
    /// Rejected events are reported, never silently discarded — an operator whose
    /// runtime integration is misconfigured needs to find out from the response,
    /// not from an unexplained limit.
    pub fn verify_batch(
        &mut self,
        events: &[SignedProvenance],
    ) -> (Vec<VerifiedProvenance>, Vec<RejectionReason>) {
        let mut ok = Vec::new();
        let mut rejected = Vec::new();
        for e in events {
            match self.verify(e) {
                Ok(v) => ok.push(v),
                Err(r) => rejected.push(r),
            }
        }
        (ok, rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ProvenanceEvent, ProvenanceKind};
    use byz_crypto::DilithiumKeypair;

    fn signed_by(
        kp: &DilithiumKeypair,
        runtime_id: &str,
        did: &AgentDid,
        session: Uuid,
        seq: u64,
    ) -> SignedProvenance {
        let e = ProvenanceEvent::new(
            did.clone(),
            session,
            seq,
            ProvenanceKind::ToolCall,
            "sha256:x",
        );
        let sig = kp.sign(&e.signing_payload()).unwrap();
        SignedProvenance::new(e, runtime_id, sig.as_bytes().to_vec())
    }

    #[test]
    fn valid_runtime_signature_is_accepted() {
        let kp = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", kp.public_key.clone());
        let did = AgentDid::new("did:byz:a");
        let mut v = ProvenanceVerifier::new(&reg, did.clone());
        assert!(v
            .verify(&signed_by(&kp, "runtime-1", &did, Uuid::nil(), 1))
            .is_ok());
    }

    #[test]
    fn unregistered_runtime_contributes_nothing() {
        let kp = DilithiumKeypair::generate();
        let reg = RuntimeRegistry::new();
        let did = AgentDid::new("did:byz:a");
        let mut v = ProvenanceVerifier::new(&reg, did.clone());
        let err = v
            .verify(&signed_by(&kp, "rogue", &did, Uuid::nil(), 1))
            .unwrap_err();
        assert!(matches!(err, RejectionReason::UnknownRuntime { .. }));
    }

    #[test]
    fn agent_self_signed_evidence_is_worthless() {
        // The agent holds its own key and signs its own trace. Because that key is
        // not a registered runtime, the event contributes nothing at all.
        let agent_kp = DilithiumKeypair::generate();
        let runtime_kp = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", runtime_kp.public_key.clone());

        let did = AgentDid::new("did:byz:a");
        let e = ProvenanceEvent::new(
            did.clone(),
            Uuid::nil(),
            1,
            ProvenanceKind::Plan,
            "sha256:x",
        );
        let self_sig = agent_kp.sign(&e.signing_payload()).unwrap();
        // Even claiming to be the runtime does not help — the signature is checked
        // against the registered key.
        let forged = SignedProvenance::new(e, "runtime-1", self_sig.as_bytes().to_vec());

        let mut v = ProvenanceVerifier::new(&reg, did);
        assert_eq!(
            v.verify(&forged).unwrap_err(),
            RejectionReason::BadSignature
        );
    }

    #[test]
    fn revoked_runtime_is_refused() {
        let kp = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", kp.public_key.clone());
        reg.revoke("runtime-1");
        let did = AgentDid::new("did:byz:a");
        let mut v = ProvenanceVerifier::new(&reg, did.clone());
        let err = v
            .verify(&signed_by(&kp, "runtime-1", &did, Uuid::nil(), 1))
            .unwrap_err();
        assert!(matches!(err, RejectionReason::RevokedRuntime { .. }));
    }

    #[test]
    fn tampered_event_fails_verification() {
        let kp = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", kp.public_key.clone());
        let did = AgentDid::new("did:byz:a");

        let mut s = signed_by(&kp, "runtime-1", &did, Uuid::nil(), 1);
        s.event.ok = false; // flip a field after signing

        let mut v = ProvenanceVerifier::new(&reg, did);
        assert_eq!(v.verify(&s).unwrap_err(), RejectionReason::BadSignature);
    }

    #[test]
    fn replayed_event_is_rejected() {
        let kp = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", kp.public_key.clone());
        let did = AgentDid::new("did:byz:a");
        let session = Uuid::new_v4();
        let e = signed_by(&kp, "runtime-1", &did, session, 7);

        let mut v = ProvenanceVerifier::new(&reg, did);
        assert!(v.verify(&e).is_ok());
        assert!(matches!(
            v.verify(&e).unwrap_err(),
            RejectionReason::DuplicateSequence { .. }
        ));
    }

    #[test]
    fn out_of_order_sequence_is_rejected() {
        let kp = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", kp.public_key.clone());
        let did = AgentDid::new("did:byz:a");
        let session = Uuid::new_v4();

        let mut v = ProvenanceVerifier::new(&reg, did.clone());
        assert!(v
            .verify(&signed_by(&kp, "runtime-1", &did, session, 5))
            .is_ok());
        let err = v
            .verify(&signed_by(&kp, "runtime-1", &did, session, 3))
            .unwrap_err();
        assert!(matches!(err, RejectionReason::NonMonotonicSequence { .. }));
    }

    #[test]
    fn sequences_are_scoped_per_session() {
        let kp = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", kp.public_key.clone());
        let did = AgentDid::new("did:byz:a");
        let (s1, s2) = (Uuid::new_v4(), Uuid::new_v4());

        let mut v = ProvenanceVerifier::new(&reg, did.clone());
        assert!(v.verify(&signed_by(&kp, "runtime-1", &did, s1, 9)).is_ok());
        // Sequence 1 in a different session is fine.
        assert!(v.verify(&signed_by(&kp, "runtime-1", &did, s2, 1)).is_ok());
    }

    #[test]
    fn events_for_another_agent_are_rejected() {
        let kp = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", kp.public_key.clone());
        let mine = AgentDid::new("did:byz:mine");
        let theirs = AgentDid::new("did:byz:theirs");

        let mut v = ProvenanceVerifier::new(&reg, mine);
        let err = v
            .verify(&signed_by(&kp, "runtime-1", &theirs, Uuid::nil(), 1))
            .unwrap_err();
        assert!(matches!(err, RejectionReason::AgentMismatch { .. }));
    }

    #[test]
    fn batch_reports_rejections_rather_than_dropping_them() {
        let kp = DilithiumKeypair::generate();
        let rogue = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", kp.public_key.clone());
        let did = AgentDid::new("did:byz:a");
        let session = Uuid::new_v4();

        let good = signed_by(&kp, "runtime-1", &did, session, 1);
        let bad = signed_by(&rogue, "runtime-1", &did, session, 2);

        let mut v = ProvenanceVerifier::new(&reg, did);
        let (ok, rejected) = v.verify_batch(&[good, bad]);
        assert_eq!(ok.len(), 1);
        assert_eq!(rejected.len(), 1);
        assert!(!rejected[0].describe().is_empty());
    }
}
