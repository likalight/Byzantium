//! Idempotency for the money-moving endpoints.
//!
//! A client that does not hear back from an authorisation cannot tell a lost
//! response from a lost request, so it retries. Without a key that retry commits
//! the exposure a second time and quietly consumes double the window. Settlement
//! has the same problem in the other direction.
//!
//! The cache stores the response that was actually sent, so a replay returns the
//! original answer rather than re-running the decision. Re-deciding would be
//! wrong even if it were cheap: the second answer could differ from the one the
//! client already acted on.

use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a key is honoured. Long enough to cover a client retry budget,
/// short enough that the map cannot grow without bound.
pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

struct Entry {
    response: Value,
    stored_at: Instant,
}

#[derive(Default)]
pub struct IdempotencyCache {
    entries: HashMap<String, Entry>,
    ttl: Option<Duration>,
}

impl IdempotencyCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            ttl: Some(DEFAULT_TTL),
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    fn ttl(&self) -> Duration {
        self.ttl.unwrap_or(DEFAULT_TTL)
    }

    /// The response previously sent for this key, if it is still live.
    pub fn get(&self, key: &str) -> Option<Value> {
        let e = self.entries.get(key)?;
        if e.stored_at.elapsed() > self.ttl() {
            return None;
        }
        Some(e.response.clone())
    }

    /// Remember what was sent. Opportunistically evicts expired entries, so the
    /// map stays bounded without a background task.
    pub fn put(&mut self, key: impl Into<String>, response: Value) {
        let ttl = self.ttl();
        self.entries.retain(|_, e| e.stored_at.elapsed() <= ttl);
        self.entries.insert(
            key.into(),
            Entry {
                response,
                stored_at: Instant::now(),
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_replayed_key_returns_the_original_response() {
        // Not a fresh decision: the client already acted on the first answer.
        let mut c = IdempotencyCache::new();
        c.put("k1", json!({"permitted": true, "effective_minor": 1000}));
        assert_eq!(c.get("k1").unwrap()["effective_minor"], 1000);
    }

    #[test]
    fn an_unknown_key_is_a_miss() {
        assert!(IdempotencyCache::new().get("never-seen").is_none());
    }

    #[test]
    fn an_expired_entry_is_a_miss() {
        let mut c = IdempotencyCache::new().with_ttl(Duration::from_millis(1));
        c.put("k1", json!({"permitted": true}));
        std::thread::sleep(Duration::from_millis(5));
        assert!(c.get("k1").is_none());
    }

    #[test]
    fn expired_entries_are_evicted_on_write() {
        let mut c = IdempotencyCache::new().with_ttl(Duration::from_millis(1));
        c.put("old", json!({}));
        std::thread::sleep(Duration::from_millis(5));
        c.put("new", json!({}));
        assert_eq!(c.len(), 1, "the map grew without bound");
    }

    #[test]
    fn distinct_keys_do_not_collide() {
        let mut c = IdempotencyCache::new();
        c.put("a", json!({"v": 1}));
        c.put("b", json!({"v": 2}));
        assert_eq!(c.get("a").unwrap()["v"], 1);
        assert_eq!(c.get("b").unwrap()["v"], 2);
    }
}
