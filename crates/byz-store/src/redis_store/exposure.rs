//! Exposure shared across gateway replicas.
//!
//! The in-memory ledger in `byz-mandate` is correct for exactly one process. The
//! Kubernetes deployment runs three, and each one was handing out the full
//! window independently — a triple-spend that no test could catch, because every
//! test runs in a single process.
//!
//! # Why this is a Lua script and not three round trips
//!
//! Reading the window, deciding, and reserving capacity has to be one
//! indivisible operation. Doing it as `GET`, then a decision in Rust, then
//! `INCRBY` leaves a gap in which another replica reads the same figure and
//! reaches the same conclusion, and both commit. Redis executes a script
//! atomically against a single key, which closes that gap across every replica
//! at once — the same property the single-process fix gets from holding a write
//! guard, extended to the cluster.
//!
//! # Failure behaviour
//!
//! If Redis is unreachable, [`SharedExposure::try_commit`] returns an error and
//! the caller must **refuse the draw**. Falling back to local state under
//! partition is what turns an outage into an overspend, so the safe direction
//! here is to stop authorising rather than to guess.

use byz_common::{AgentDid, ByzResult, ByzantiumError};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

/// Result of an atomic check-and-reserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Capacity was reserved. `window_used_after` includes this draw.
    Reserved { window_used_after: u64 },
    /// Refused because the draw alone exceeds the per-transaction cap.
    ExceedsSingle { requested: u64, cap: u64 },
    /// Refused because it would breach the rolling window.
    ExceedsWindow { would_reach: u64, cap: u64 },
}

impl CommitOutcome {
    pub fn is_reserved(&self) -> bool {
        matches!(self, CommitOutcome::Reserved { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            CommitOutcome::Reserved { window_used_after } => {
                format!("reserved; {window_used_after} committed this window")
            }
            CommitOutcome::ExceedsSingle { requested, cap } => {
                format!("draw of {requested} exceeds single-transaction cap of {cap}")
            }
            CommitOutcome::ExceedsWindow { would_reach, cap } => {
                format!("draw would reach {would_reach} against a window cap of {cap}")
            }
        }
    }
}

/// Current exposure for one agent, as every replica sees it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SharedSnapshot {
    pub at_risk: u64,
    pub window_used: u64,
    pub open_draws: u32,
}

impl SharedSnapshot {
    pub fn total_committed(&self) -> u64 {
        self.at_risk.saturating_add(self.window_used)
    }
}

/// Check the caps and reserve, in one atomic step.
///
/// KEYS[1] exposure hash · ARGV: amount, lim_single, lim_window, window_secs
///
/// The window is expressed as a TTL on the hash rather than a stored timestamp,
/// so it rolls forward by expiry instead of by anyone remembering to reset it.
/// `at_risk` is included in the comparison because an unresolved commitment is
/// capacity already spoken for.
const COMMIT_SCRIPT: &str = r#"
local amount      = tonumber(ARGV[1])
local lim_single  = tonumber(ARGV[2])
local lim_window  = tonumber(ARGV[3])
local window_secs = tonumber(ARGV[4])

if amount > lim_single then
  return {0, amount, lim_single, 1}
end

local at_risk     = tonumber(redis.call('HGET', KEYS[1], 'at_risk') or 0)
local window_used = tonumber(redis.call('HGET', KEYS[1], 'window_used') or 0)
local committed   = at_risk + window_used
local would_reach = committed + amount

if would_reach > lim_window then
  return {0, would_reach, lim_window, 2}
end

redis.call('HINCRBY', KEYS[1], 'at_risk', amount)
redis.call('HINCRBY', KEYS[1], 'open_draws', 1)
-- Only set the expiry when the key is new, so a busy agent's window still ends.
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], window_secs)
end
return {1, would_reach, 0, 0}
"#;

/// Move a reservation into settled value, or release it.
///
/// KEYS[1] exposure hash · ARGV: amount, settled (1 or 0)
///
/// Both paths clamp at zero: a settlement larger than what was reserved must not
/// wrap `at_risk` around a u64 boundary.
const RESOLVE_SCRIPT: &str = r#"
local amount  = tonumber(ARGV[1])
local settled = tonumber(ARGV[2])

local at_risk = tonumber(redis.call('HGET', KEYS[1], 'at_risk') or 0)
local release = math.min(amount, at_risk)
redis.call('HSET', KEYS[1], 'at_risk', at_risk - release)

local open = tonumber(redis.call('HGET', KEYS[1], 'open_draws') or 0)
if open > 0 then
  redis.call('HSET', KEYS[1], 'open_draws', open - 1)
end

if settled == 1 then
  redis.call('HINCRBY', KEYS[1], 'window_used', amount)
end
return 1
"#;

#[derive(Clone)]
pub struct SharedExposure {
    conn: ConnectionManager,
    prefix: String,
}

impl SharedExposure {
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            prefix: "byz:exposure:".to_string(),
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn key(&self, agent_did: &AgentDid) -> String {
        format!("{}{}", self.prefix, agent_did.as_str())
    }

    /// Atomically check both caps and reserve capacity if they allow it.
    ///
    /// An error means Redis could not be reached, and the caller must refuse the
    /// draw rather than fall back to local state.
    pub async fn try_commit(
        &self,
        agent_did: &AgentDid,
        amount: u64,
        lim_single: u64,
        lim_window: u64,
        window_secs: u64,
    ) -> ByzResult<CommitOutcome> {
        let mut conn = self.conn.clone();
        let out: Vec<i64> = redis::Script::new(COMMIT_SCRIPT)
            .key(self.key(agent_did))
            .arg(amount)
            .arg(lim_single)
            .arg(lim_window)
            .arg(window_secs.max(1))
            .invoke_async(&mut conn)
            .await
            .map_err(|e| ByzantiumError::Cache(format!("exposure commit failed: {e}")))?;

        match (out.first().copied(), out.get(3).copied()) {
            (Some(1), _) => Ok(CommitOutcome::Reserved {
                window_used_after: out.get(1).copied().unwrap_or(0).max(0) as u64,
            }),
            (Some(0), Some(1)) => Ok(CommitOutcome::ExceedsSingle {
                requested: out.get(1).copied().unwrap_or(0).max(0) as u64,
                cap: out.get(2).copied().unwrap_or(0).max(0) as u64,
            }),
            (Some(0), Some(2)) => Ok(CommitOutcome::ExceedsWindow {
                would_reach: out.get(1).copied().unwrap_or(0).max(0) as u64,
                cap: out.get(2).copied().unwrap_or(0).max(0) as u64,
            }),
            _ => Err(ByzantiumError::Cache(
                "exposure script returned an unrecognised result".to_string(),
            )),
        }
    }

    /// Resolve a reservation: consume the window on success, release it on
    /// failure.
    pub async fn resolve(&self, agent_did: &AgentDid, amount: u64, settled: bool) -> ByzResult<()> {
        let mut conn = self.conn.clone();
        let _: i64 = redis::Script::new(RESOLVE_SCRIPT)
            .key(self.key(agent_did))
            .arg(amount)
            .arg(if settled { 1 } else { 0 })
            .invoke_async(&mut conn)
            .await
            .map_err(|e| ByzantiumError::Cache(format!("exposure resolve failed: {e}")))?;
        Ok(())
    }

    pub async fn snapshot(&self, agent_did: &AgentDid) -> ByzResult<SharedSnapshot> {
        let mut conn = self.conn.clone();
        let vals: Vec<Option<i64>> = conn
            .hget(
                self.key(agent_did),
                &["at_risk", "window_used", "open_draws"],
            )
            .await
            .map_err(|e| ByzantiumError::Cache(format!("exposure read failed: {e}")))?;

        Ok(SharedSnapshot {
            at_risk: vals.first().copied().flatten().unwrap_or(0).max(0) as u64,
            window_used: vals.get(1).copied().flatten().unwrap_or(0).max(0) as u64,
            open_draws: vals.get(2).copied().flatten().unwrap_or(0).max(0) as u32,
        })
    }

    /// Clear an agent's exposure. Administrative; not part of the draw path.
    pub async fn reset(&self, agent_did: &AgentDid) -> ByzResult<()> {
        let mut conn = self.conn.clone();
        let _: i64 = conn
            .del(self.key(agent_did))
            .await
            .map_err(|e| ByzantiumError::Cache(format!("exposure reset failed: {e}")))?;
        Ok(())
    }

    pub async fn ping(&self) -> ByzResult<()> {
        let mut conn = self.conn.clone();
        redis::cmd("PING")
            .query_async::<_, String>(&mut conn)
            .await
            .map_err(|e| ByzantiumError::Cache(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Lua is the load-bearing part, so these assert on its shape and
    // branches rather than requiring a live Redis. The behaviour against a real
    // server is covered by the integration suite.

    #[test]
    fn the_commit_script_checks_the_single_cap_before_reading_state() {
        // Cheapest refusal first, and it must not touch the hash at all.
        let single_check = COMMIT_SCRIPT.find("amount > lim_single").unwrap();
        let first_read = COMMIT_SCRIPT.find("HGET").unwrap();
        assert!(
            single_check < first_read,
            "the per-transaction cap should be rejected before any state is read"
        );
    }

    #[test]
    fn the_commit_script_counts_unresolved_commitments() {
        // Ignoring at_risk is exactly how concurrent draws overspend a window.
        assert!(COMMIT_SCRIPT.contains("local committed   = at_risk + window_used"));
        assert!(COMMIT_SCRIPT.contains("local would_reach = committed + amount"));
    }

    #[test]
    fn the_commit_script_reserves_and_decides_in_one_body() {
        // If the decision and the reservation were separate calls, two replicas
        // could each pass the check before either reserved.
        let decision = COMMIT_SCRIPT.find("would_reach > lim_window").unwrap();
        let reserve = COMMIT_SCRIPT.find("HINCRBY").unwrap();
        assert!(decision < reserve);
        assert!(
            COMMIT_SCRIPT.contains("EXPIRE"),
            "the window must roll forward on its own"
        );
    }

    #[test]
    fn the_window_expiry_is_only_set_once() {
        // Refreshing the TTL on every draw would give a busy agent a window that
        // never ends.
        assert!(COMMIT_SCRIPT.contains("if redis.call('TTL', KEYS[1]) < 0 then"));
    }

    #[test]
    fn resolving_clamps_the_release_at_what_was_reserved() {
        // Otherwise a settlement larger than the reservation wraps at_risk.
        assert!(RESOLVE_SCRIPT.contains("math.min(amount, at_risk)"));
    }

    #[test]
    fn only_a_settlement_consumes_the_window() {
        assert!(RESOLVE_SCRIPT.contains("if settled == 1 then"));
        assert!(RESOLVE_SCRIPT.contains("HINCRBY', KEYS[1], 'window_used'"));
    }

    #[test]
    fn outcomes_describe_themselves() {
        assert!(CommitOutcome::Reserved {
            window_used_after: 100
        }
        .is_reserved());
        let refused = CommitOutcome::ExceedsWindow {
            would_reach: 500,
            cap: 400,
        };
        assert!(!refused.is_reserved());
        assert!(refused.describe().contains("window cap"));
    }

    #[test]
    fn a_snapshot_sums_outstanding_and_settled() {
        let s = SharedSnapshot {
            at_risk: 250,
            window_used: 1_000,
            open_draws: 1,
        };
        assert_eq!(s.total_committed(), 1_250);
    }
}
