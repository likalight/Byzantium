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
    trust_checks_total:  AtomicU64,
    trust_pass:          AtomicU64,
    trust_flag:          AtomicU64,
    trust_block:         AtomicU64,
    latency_sum_ms:      AtomicU64,
    proof_cache_hits:    AtomicU64,
    proof_cache_misses:  AtomicU64,
    receipts_created:    AtomicU64,
    batches_sealed:      AtomicU64,
    mandates_created:    AtomicU64,
    agents_registered:   AtomicU64,
}

impl Metrics {
    pub fn record_trust_check(&self, verdict: &str, latency_ms: u64) {
        self.inner.trust_checks_total.fetch_add(1, Ordering::Relaxed);
        self.inner.latency_sum_ms.fetch_add(latency_ms, Ordering::Relaxed);
        match verdict {
            "PASS"  => { self.inner.trust_pass.fetch_add(1, Ordering::Relaxed); }
            "FLAG"  => { self.inner.trust_flag.fetch_add(1, Ordering::Relaxed); }
            _       => { self.inner.trust_block.fetch_add(1, Ordering::Relaxed); }
        }
    }

    pub fn record_proof_cache_hit(&self)  { self.inner.proof_cache_hits.fetch_add(1, Ordering::Relaxed); }
    pub fn record_proof_cache_miss(&self) { self.inner.proof_cache_misses.fetch_add(1, Ordering::Relaxed); }
    pub fn record_receipt_created(&self)  { self.inner.receipts_created.fetch_add(1, Ordering::Relaxed); }
    pub fn record_batch_sealed(&self)     { self.inner.batches_sealed.fetch_add(1, Ordering::Relaxed); }
    pub fn record_mandate_created(&self)  { self.inner.mandates_created.fetch_add(1, Ordering::Relaxed); }
    pub fn record_agent_registered(&self) { self.inner.agents_registered.fetch_add(1, Ordering::Relaxed); }

    pub fn render(&self) -> String {
        let i = &self.inner;
        let total = i.trust_checks_total.load(Ordering::Relaxed);
        let avg_latency = if total > 0 {
            i.latency_sum_ms.load(Ordering::Relaxed) / total
        } else { 0 };

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
             byz_agents_registered_total {}\n",
            i.trust_pass.load(Ordering::Relaxed),
            i.trust_flag.load(Ordering::Relaxed),
            i.trust_block.load(Ordering::Relaxed),
            i.proof_cache_hits.load(Ordering::Relaxed),
            i.proof_cache_misses.load(Ordering::Relaxed),
            i.receipts_created.load(Ordering::Relaxed),
            i.batches_sealed.load(Ordering::Relaxed),
            i.mandates_created.load(Ordering::Relaxed),
            i.agents_registered.load(Ordering::Relaxed),
        )
    }
}
