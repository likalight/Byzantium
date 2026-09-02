//! Prometheus-style metrics counters for the gateway.
//! Exposed at GET /metrics in plain-text format.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    trust_checks_total: AtomicU64,
    trust_pass: AtomicU64,
    trust_flag: AtomicU64,
    trust_block: AtomicU64,
    latency_sum_ms: AtomicU64,
    proof_cache_hits: AtomicU64,
    proof_cache_misses: AtomicU64,
    receipts_created: AtomicU64,
    batches_sealed: AtomicU64,
    mandates_created: AtomicU64,
    agents_registered: AtomicU64,
    // ── Underwriting ────────────────────────────────────────────────────────
    limits_issued: AtomicU64,
    limits_refused: AtomicU64,
    issue_latency_sum_ms: AtomicU64,
    authorisations_total: AtomicU64,
    authorisations_permitted: AtomicU64,
    authorisations_refused: AtomicU64,
    auth_latency_sum_ms: AtomicU64,
    /// Refused because the outstanding set was revoked, as opposed to a limit
    /// being exceeded. Worth separating: one is normal, the other is an
    /// incident.
    authorisations_revoked: AtomicU64,
    settlements_ok: AtomicU64,
    settlements_failed: AtomicU64,
    provenance_accepted: AtomicU64,
    provenance_rejected: AtomicU64,
    idempotent_replays: AtomicU64,
}

impl Metrics {
    pub fn record_trust_check(&self, verdict: &str, latency_ms: u64) {
        self.inner
            .trust_checks_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .latency_sum_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        match verdict {
            "PASS" => {
                self.inner.trust_pass.fetch_add(1, Ordering::Relaxed);
            }
            "FLAG" => {
                self.inner.trust_flag.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.inner.trust_block.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_limit_issued(&self, issued: bool, latency_ms: u64) {
        self.inner
            .issue_latency_sum_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        if issued {
            self.inner.limits_issued.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.limits_refused.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `revoked` separates an incident from an ordinary limit refusal, because
    /// a rise in one means something very different from a rise in the other.
    pub fn record_authorisation(&self, permitted: bool, revoked: bool, latency_ms: u64) {
        self.inner
            .authorisations_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .auth_latency_sum_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        if permitted {
            self.inner
                .authorisations_permitted
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner
                .authorisations_refused
                .fetch_add(1, Ordering::Relaxed);
        }
        if revoked {
            self.inner
                .authorisations_revoked
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_settlement(&self, settled: bool) {
        if settled {
            self.inner.settlements_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner
                .settlements_failed
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A falling acceptance ratio here is almost always a misconfigured runtime
    /// rather than a misbehaving agent, which makes it the most useful early
    /// warning in the system.
    pub fn record_provenance(&self, accepted: usize, rejected: usize) {
        self.inner
            .provenance_accepted
            .fetch_add(accepted as u64, Ordering::Relaxed);
        self.inner
            .provenance_rejected
            .fetch_add(rejected as u64, Ordering::Relaxed);
    }

    pub fn record_idempotent_replay(&self) {
        self.inner
            .idempotent_replays
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_proof_cache_hit(&self) {
        self.inner.proof_cache_hits.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_proof_cache_miss(&self) {
        self.inner
            .proof_cache_misses
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_receipt_created(&self) {
        self.inner.receipts_created.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_batch_sealed(&self) {
        self.inner.batches_sealed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_mandate_created(&self) {
        self.inner.mandates_created.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_agent_registered(&self) {
        self.inner.agents_registered.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let i = &self.inner;
        let total = i.trust_checks_total.load(Ordering::Relaxed);
        let avg_latency = i
            .latency_sum_ms
            .load(Ordering::Relaxed)
            .checked_div(total)
            .unwrap_or(0);

        format!(
            "# HELP byz_trust_checks_total Total trust-check requests\n\
             # TYPE byz_trust_checks_total counter\n\
             byz_trust_checks_total {total}\n\
             # HELP byz_trust_pass_total Trust checks returning PASS\n\
             # TYPE byz_trust_pass_total counter\n\
             byz_trust_pass_total {}\n\
             # HELP byz_trust_flag_total Trust checks returning FLAG\n\
             # TYPE byz_trust_flag_total counter\n\
             byz_trust_flag_total {}\n\
             # HELP byz_trust_block_total Trust checks returning BLOCK\n\
             # TYPE byz_trust_block_total counter\n\
             byz_trust_block_total {}\n\
             # HELP byz_latency_avg_ms Average trust-check latency ms\n\
             # TYPE byz_latency_avg_ms gauge\n\
             byz_latency_avg_ms {avg_latency}\n\
             # HELP byz_proof_cache_hits_total Proof cache hits\n\
             # TYPE byz_proof_cache_hits_total counter\n\
             byz_proof_cache_hits_total {}\n\
             # HELP byz_proof_cache_misses_total Proof cache misses\n\
             # TYPE byz_proof_cache_misses_total counter\n\
             byz_proof_cache_misses_total {}\n\
             # HELP byz_receipts_created_total Receipts created\n\
             # TYPE byz_receipts_created_total counter\n\
             byz_receipts_created_total {}\n\
             # HELP byz_batches_sealed_total Receipt batches sealed\n\
             # TYPE byz_batches_sealed_total counter\n\
             byz_batches_sealed_total {}\n\
             # HELP byz_mandates_created_total Spend mandates created\n\
             # TYPE byz_mandates_created_total counter\n\
             byz_mandates_created_total {}\n\
             # HELP byz_agents_registered_total Agents registered\n\
             # TYPE byz_agents_registered_total counter\n\
             byz_agents_registered_total {}\n\
             # HELP byz_limits_issued_total Limits issued\n\
             # TYPE byz_limits_issued_total counter\n\
             byz_limits_issued_total {}\n\
             # HELP byz_limits_refused_total Underwriting refusals\n\
             # TYPE byz_limits_refused_total counter\n\
             byz_limits_refused_total {}\n\
             # HELP byz_issue_latency_ms_sum Cumulative issuance latency\n\
             # TYPE byz_issue_latency_ms_sum counter\n\
             byz_issue_latency_ms_sum {}\n\
             # HELP byz_authorisations_total Draw authorisations attempted\n\
             # TYPE byz_authorisations_total counter\n\
             byz_authorisations_total {}\n\
             # HELP byz_authorisations_permitted_total Draws permitted\n\
             # TYPE byz_authorisations_permitted_total counter\n\
             byz_authorisations_permitted_total {}\n\
             # HELP byz_authorisations_refused_total Draws refused\n\
             # TYPE byz_authorisations_refused_total counter\n\
             byz_authorisations_refused_total {}\n\
             # HELP byz_authorisations_revoked_total Draws refused because the credential was revoked\n\
             # TYPE byz_authorisations_revoked_total counter\n\
             byz_authorisations_revoked_total {}\n\
             # HELP byz_auth_latency_ms_sum Cumulative authorisation latency\n\
             # TYPE byz_auth_latency_ms_sum counter\n\
             byz_auth_latency_ms_sum {}\n\
             # HELP byz_settlements_ok_total Draws that settled\n\
             # TYPE byz_settlements_ok_total counter\n\
             byz_settlements_ok_total {}\n\
             # HELP byz_settlements_failed_total Draws reported as failed\n\
             # TYPE byz_settlements_failed_total counter\n\
             byz_settlements_failed_total {}\n\
             # HELP byz_provenance_accepted_total Runtime-signed events accepted\n\
             # TYPE byz_provenance_accepted_total counter\n\
             byz_provenance_accepted_total {}\n\
             # HELP byz_provenance_rejected_total Provenance events rejected\n\
             # TYPE byz_provenance_rejected_total counter\n\
             byz_provenance_rejected_total {}\n\
             # HELP byz_idempotent_replays_total Requests served from the idempotency cache\n\
             # TYPE byz_idempotent_replays_total counter\n\
             byz_idempotent_replays_total {}\n",
            i.trust_pass.load(Ordering::Relaxed),
            i.trust_flag.load(Ordering::Relaxed),
            i.trust_block.load(Ordering::Relaxed),
            i.proof_cache_hits.load(Ordering::Relaxed),
            i.proof_cache_misses.load(Ordering::Relaxed),
            i.receipts_created.load(Ordering::Relaxed),
            i.batches_sealed.load(Ordering::Relaxed),
            i.mandates_created.load(Ordering::Relaxed),
            i.agents_registered.load(Ordering::Relaxed),
            i.limits_issued.load(Ordering::Relaxed),
            i.limits_refused.load(Ordering::Relaxed),
            i.issue_latency_sum_ms.load(Ordering::Relaxed),
            i.authorisations_total.load(Ordering::Relaxed),
            i.authorisations_permitted.load(Ordering::Relaxed),
            i.authorisations_refused.load(Ordering::Relaxed),
            i.authorisations_revoked.load(Ordering::Relaxed),
            i.auth_latency_sum_ms.load(Ordering::Relaxed),
            i.settlements_ok.load(Ordering::Relaxed),
            i.settlements_failed.load(Ordering::Relaxed),
            i.provenance_accepted.load(Ordering::Relaxed),
            i.provenance_rejected.load(Ordering::Relaxed),
            i.idempotent_replays.load(Ordering::Relaxed),
        )
    }
}
