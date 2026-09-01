//! Evidence bundles.
//!
//! Verified events are committed to a Merkle tree whose root becomes the `ev`
//! field on a limit attestation. That single hash is what makes the privacy
//! position workable: a dispute over a limit is settled by producing an inclusion
//! proof for the specific events in question, rather than by handing over an
//! agent's entire execution history.

use byz_common::{AgentDid, ByzResult, ByzantiumError};
use byz_crypto::{MerkleProof, MerkleTree};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::event::ProvenanceKind;
use crate::verifier::VerifiedProvenance;

/// Summary of a bundle, suitable for feeding the scorer without exposing events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleStats {
    pub verified_count: usize,
    pub rejected_count: usize,
    /// Sum of per-kind weights across verified events.
    pub weighted_total: u64,
    pub human_approvals: u32,
    pub payment_intents: u32,
    /// Share of verified events that reported failure, in basis points.
    pub failure_rate_bps: u32,
    pub distinct_sessions: usize,
    pub earliest: Option<DateTime<Utc>>,
    pub latest: Option<DateTime<Utc>>,
}

impl BundleStats {
    /// Share of submitted events that survived verification, in basis points.
    ///
    /// A low ratio is an integration problem worth surfacing: it usually means a
    /// runtime is misconfigured, not that an agent is misbehaving.
    pub fn acceptance_rate_bps(&self) -> u32 {
        let total = self.verified_count + self.rejected_count;
        if total == 0 {
            return 0;
        }
        ((self.verified_count as f64 / total as f64) * 10_000.0).round() as u32
    }
}

/// A Merkle commitment over verified provenance.
#[derive(Debug, Clone)]
pub struct ProvenanceBundle {
    pub agent_did: AgentDid,
    pub events: Vec<VerifiedProvenance>,
    pub stats: BundleStats,
    root_hex: String,
    tree: Option<MerkleTree>,
}

impl ProvenanceBundle {
    /// Build a bundle from verified events.
    ///
    /// `rejected_count` is carried through so the summary reflects how much was
    /// submitted and discarded, not only what was kept.
    pub fn build(
        agent_did: AgentDid,
        events: Vec<VerifiedProvenance>,
        rejected_count: usize,
    ) -> ByzResult<Self> {
        let mut weighted_total: u64 = 0;
        let mut human_approvals = 0u32;
        let mut payment_intents = 0u32;
        let mut failures = 0u32;
        let mut sessions: HashSet<uuid::Uuid> = HashSet::new();
        let mut earliest: Option<DateTime<Utc>> = None;
        let mut latest: Option<DateTime<Utc>> = None;

        for v in &events {
            let e = &v.signed.event;
            weighted_total = weighted_total.saturating_add(e.kind.weight() as u64);
            match e.kind {
                ProvenanceKind::HumanApproval => human_approvals += 1,
                ProvenanceKind::PaymentIntent => payment_intents += 1,
                _ => {}
            }
            if !e.ok {
                failures += 1;
            }
            sessions.insert(e.session_id);
            earliest = Some(earliest.map_or(e.at, |c| c.min(e.at)));
            latest = Some(latest.map_or(e.at, |c| c.max(e.at)));
        }

        let failure_rate_bps = if events.is_empty() {
            0
        } else {
            ((failures as f64 / events.len() as f64) * 10_000.0).round() as u32
        };

        let stats = BundleStats {
            verified_count: events.len(),
            rejected_count,
            weighted_total,
            human_approvals,
            payment_intents,
            failure_rate_bps,
            distinct_sessions: sessions.len(),
            earliest,
            latest,
        };

        // An empty bundle is legitimate — an agent may simply have no runtime
        // integration yet — so it commits to a well-defined empty root rather
        // than failing.
        if events.is_empty() {
            return Ok(Self {
                agent_did,
                events,
                stats,
                root_hex: String::new(),
                tree: None,
            });
        }

        let leaves: Vec<Vec<u8>> = events.iter().map(|v| v.signed.event.leaf_bytes()).collect();
        let tree = MerkleTree::new(&leaves);
        let root_hex = tree.root_hex();

        Ok(Self {
            agent_did,
            events,
            stats,
            root_hex,
            tree: Some(tree),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn root_hex(&self) -> &str {
        &self.root_hex
    }

    /// The value that goes into a limit attestation's `ev` field.
    pub fn evidence_ref(&self) -> String {
        if self.root_hex.is_empty() {
            "sha256:empty".to_string()
        } else {
            format!("sha256:{}", self.root_hex)
        }
    }

    /// Inclusion proof for one event, used to settle a dispute about a specific
    /// step without publishing the rest of the bundle.
    pub fn proof_for(&self, index: usize) -> ByzResult<MerkleProof> {
        let tree = self
            .tree
            .as_ref()
            .ok_or_else(|| ByzantiumError::Internal("bundle is empty".to_string()))?;
        tree.proof(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ProvenanceEvent, SignedProvenance};
    use crate::verifier::{ProvenanceVerifier, RuntimeRegistry};
    use byz_crypto::DilithiumKeypair;
    use uuid::Uuid;

    fn verified(n: u64, kinds: &[ProvenanceKind]) -> (AgentDid, Vec<VerifiedProvenance>) {
        let kp = DilithiumKeypair::generate();
        let mut reg = RuntimeRegistry::new();
        reg.register("runtime-1", kp.public_key.clone());
        let did = AgentDid::new("did:byz:a");
        let session = Uuid::new_v4();

        let mut signed = Vec::new();
        for i in 0..n {
            let kind = kinds[(i as usize) % kinds.len()];
            let e = ProvenanceEvent::new(did.clone(), session, i + 1, kind, format!("sha256:{i}"));
            let sig = kp.sign(&e.signing_payload()).unwrap();
            signed.push(SignedProvenance::new(
                e,
                "runtime-1",
                sig.as_bytes().to_vec(),
            ));
        }

        let mut v = ProvenanceVerifier::new(&reg, did.clone());
        let (ok, rejected) = v.verify_batch(&signed);
        assert!(rejected.is_empty());
        (did, ok)
    }

    #[test]
    fn bundle_commits_to_a_root() {
        let (did, events) = verified(8, &[ProvenanceKind::ToolCall]);
        let b = ProvenanceBundle::build(did, events, 0).unwrap();
        assert!(!b.root_hex().is_empty());
        assert!(b.evidence_ref().starts_with("sha256:"));
        assert_eq!(b.stats.verified_count, 8);
    }

    #[test]
    fn empty_bundle_is_valid_and_distinct() {
        let did = AgentDid::new("did:byz:a");
        let b = ProvenanceBundle::build(did, vec![], 0).unwrap();
        assert!(b.is_empty());
        assert_eq!(b.evidence_ref(), "sha256:empty");
        assert!(b.proof_for(0).is_err());
    }

    #[test]
    fn inclusion_proof_verifies_against_the_root() {
        let (did, events) = verified(6, &[ProvenanceKind::ToolCall, ProvenanceKind::Plan]);
        let b = ProvenanceBundle::build(did, events, 0).unwrap();
        let proof = b.proof_for(3).unwrap();
        assert!(proof.verify(b.root_hex()).is_ok());
    }

    #[test]
    fn different_events_produce_different_roots() {
        let (did1, e1) = verified(4, &[ProvenanceKind::ToolCall]);
        let (did2, e2) = verified(4, &[ProvenanceKind::Plan]);
        let b1 = ProvenanceBundle::build(did1, e1, 0).unwrap();
        let b2 = ProvenanceBundle::build(did2, e2, 0).unwrap();
        assert_ne!(b1.root_hex(), b2.root_hex());
    }

    #[test]
    fn stats_weight_human_approval_above_tool_calls() {
        let (did, approvals) = verified(4, &[ProvenanceKind::HumanApproval]);
        let (did2, calls) = verified(4, &[ProvenanceKind::ToolCall]);
        let a = ProvenanceBundle::build(did, approvals, 0).unwrap();
        let c = ProvenanceBundle::build(did2, calls, 0).unwrap();
        assert!(a.stats.weighted_total > c.stats.weighted_total);
        assert_eq!(a.stats.human_approvals, 4);
    }

    #[test]
    fn acceptance_rate_surfaces_a_broken_integration() {
        let (did, events) = verified(2, &[ProvenanceKind::ToolCall]);
        // Two accepted, eight rejected — a misconfigured runtime, not a bad agent.
        let b = ProvenanceBundle::build(did, events, 8).unwrap();
        assert_eq!(b.stats.acceptance_rate_bps(), 2_000);
    }
}
