//! Behavioral reputation scorer.
//!
//! The model runs inside the SGX/SEV TEE in production — raw transaction
//! history never leaves the enclave. Only commitments and threshold-pass
//! signals are published.
//!
//! Graph storage: Neo4j (production); in-memory HashMap for unit tests.

use byz_common::{AgentDid, ByzResult, ByzantiumError, ReceiptOutcome, ReputationScore};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An event ingested by the scorer (created from a LiabilityReceipt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringEvent {
    pub agent_did: AgentDid,
    pub outcome: ReceiptOutcome,
    pub mandate_violated: bool,
    pub amount_cents: Option<u64>,
}

/// Simple in-memory reputation service.
/// Production replaces the map with Neo4j queries + a model running in TEE.
pub struct ReputationService {
    scores: HashMap<String, AgentStats>,
    default_threshold: u32,
}

#[derive(Debug, Default, Clone)]
struct AgentStats {
    total: u64,
    successes: u64,
    violations: u64,
}

impl AgentStats {
    fn score(&self) -> u32 {
        if self.total == 0 {
            return 500; // neutral starting score for new agents
        }
        let compliance = self.successes as f64 / self.total as f64;
        let violation_penalty = (self.violations as f64 / self.total as f64) * 200.0;
        let raw = compliance * 1000.0 - violation_penalty;
        raw.clamp(0.0, 1000.0) as u32
    }

    fn compliance_rate(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        self.successes as f64 / self.total as f64
    }

    fn violation_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.violations as f64 / self.total as f64
    }
}

impl ReputationService {
    pub fn new(default_threshold: u32) -> Self {
        Self {
            scores: HashMap::new(),
            default_threshold,
        }
    }

    /// Ingest a scoring event (called after each receipt is finalized).
    pub fn ingest(&mut self, event: ScoringEvent) {
        let stats = self.scores.entry(event.agent_did.to_string()).or_default();
        stats.total += 1;
        match event.outcome {
            ReceiptOutcome::Success => stats.successes += 1,
            _ => {}
        }
        if event.mandate_violated {
            stats.violations += 1;
        }
    }

    pub fn score(&self, did: &AgentDid) -> ByzResult<ReputationScore> {
        let stats = self
            .scores
            .get(did.as_str())
            .cloned()
            .unwrap_or_default();

        Ok(ReputationScore {
            agent_did: did.clone(),
            score: stats.score(),
            compliance_rate: stats.compliance_rate(),
            violation_rate: stats.violation_rate(),
            total_actions: stats.total,
            computed_at: Utc::now(),
            commitment: None,
            commitment_nonce: None,
        })
    }

    /// Check if agent meets threshold. Returns (meets, score).
    /// The ZK proof (byz-proof) proves the same fact without exposing the raw score.
    pub fn meets_threshold(&self, did: &AgentDid, threshold: Option<u32>) -> ByzResult<(bool, u32)> {
        let t = threshold.unwrap_or(self.default_threshold);
        let rep = self.score(did)?;
        Ok((rep.score >= t, rep.score))
    }

    /// All agent DIDs currently tracked. Used by the background proof refresh job.
    pub fn all_agent_dids(&self) -> Vec<AgentDid> {
        self.scores.keys().map(|k| AgentDid::new(k)).collect()
    }
}
