//! Per-agent / per-key rate limiting — token bucket, in-memory.
//!
//! Each API key gets its own bucket: `rate_limit_per_min` tokens refilled per minute.
//! On every request one token is consumed. When empty: 429.
//!
//! No external dependency — uses DashMap + atomic counters so it's lock-free on
//! the read path. Refill happens lazily on each request (no background tick needed).

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use dashmap::DashMap;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::state::AppState;

#[derive(Debug)]
struct Bucket {
    tokens: std::sync::atomic::AtomicU32,
    last_refill: std::sync::Mutex<Instant>,
}

impl Bucket {
    fn new(capacity: u32) -> Self {
        Self {
            tokens: std::sync::atomic::AtomicU32::new(capacity),
            last_refill: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Refill based on elapsed time, then try to consume one token.
    /// Returns true if the request is allowed.
    fn try_consume(&self, capacity: u32) -> bool {
        let now = Instant::now();
        let mut last = self.last_refill.lock().unwrap();
        let elapsed = now.duration_since(*last);

        // Refill at `capacity` tokens per minute (proportionally per elapsed ms)
        if elapsed >= Duration::from_millis(100) {
            let refill = (elapsed.as_millis() as u32 * capacity) / 60_000;
            if refill > 0 {
                let current = self.tokens.load(std::sync::atomic::Ordering::Relaxed);
                let new = (current + refill).min(capacity);
                self.tokens.store(new, std::sync::atomic::Ordering::Relaxed);
                *last = now;
            }
        }

        // Compare-and-swap: decrement by 1 if > 0
        loop {
            let current = self.tokens.load(std::sync::atomic::Ordering::Acquire);
            if current == 0 {
                return false;
            }
            match self.tokens.compare_exchange(
                current,
                current - 1,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue, // another thread won the CAS, retry
            }
        }
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<DashMap<String, Bucket>>,
    capacity: u32,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            capacity: requests_per_minute.max(1),
        }
    }

    pub fn check(&self, key: &str) -> bool {
        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket::new(self.capacity));
        bucket.try_consume(self.capacity)
    }

    /// Returns the current token count for `key` without consuming any tokens.
    /// Returns `None` if the key has no bucket yet (i.e. no requests seen).
    pub fn remaining(&self, key: &str) -> Option<u32> {
        self.buckets
            .get(key)
            .map(|b| b.tokens.load(std::sync::atomic::Ordering::Relaxed))
    }
}

pub async fn per_key_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("anonymous");

    if !state.rate_limiter.check(key) {
        tracing::warn!(key_prefix = &key[..key.len().min(8)], "rate limit exceeded");
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate limit exceeded",
                "retry_after_ms": 1000,
            })),
        )
            .into_response();
        resp.headers_mut()
            .insert("Retry-After", HeaderValue::from_static("60"));
        return resp;
    }

    let mut response = next.run(request).await;
    let limit = state.config.gateway.rate_limit_per_min;
    let reset = (chrono::Utc::now() + chrono::Duration::seconds(60)).timestamp();

    {
        let hdrs = response.headers_mut();
        hdrs.insert(
            "X-RateLimit-Limit",
            HeaderValue::from_str(&limit.to_string()).unwrap(),
        );
        if let Some(remaining) = state.rate_limiter.remaining(key) {
            hdrs.insert(
                "X-RateLimit-Remaining",
                HeaderValue::from(remaining),
            );
        }
        hdrs.insert(
            "X-RateLimit-Reset",
            HeaderValue::from_str(&reset.to_string()).unwrap(),
        );
    }

    response
}
