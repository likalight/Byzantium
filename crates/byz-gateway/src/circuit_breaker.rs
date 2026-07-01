use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct CircuitBreaker {
    name: String,
    failure_count: Arc<AtomicU32>,
    last_failure_ts: Arc<AtomicU64>,
    threshold: u32,        // failures before opening
    reset_after_secs: u64, // seconds before trying again (half-open)
}

impl CircuitBreaker {
    pub fn new(name: &str, threshold: u32, reset_after_secs: u64) -> Self {
        Self {
            name: name.to_string(),
            failure_count: Arc::new(AtomicU32::new(0)),
            last_failure_ts: Arc::new(AtomicU64::new(0)),
            threshold,
            reset_after_secs,
        }
    }

    pub fn is_open(&self) -> bool {
        let failures = self.failure_count.load(Ordering::Relaxed);
        if failures < self.threshold {
            return false;
        }
        let last = self.last_failure_ts.load(Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now - last > self.reset_after_secs {
            // reset to half-open
            self.failure_count.store(0, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub fn record_success(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= self.threshold {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.last_failure_ts.store(now, Ordering::Relaxed);
            tracing::warn!(
                circuit = %self.name,
                failures = count,
                "circuit breaker opened"
            );
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}
