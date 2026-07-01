//! Mandate enforcement engine — the policy layer of the hot path.
//!
//! In production this runs inside an Intel SGX/SEV enclave (via Gramine).
//! The TEE ensures the mandate state cannot be bypassed in software.

use byz_common::{
    ActionType, AgentDid, ByzResult, ByzantiumError, Counterparty, SpendMandate, TrustVerdict,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub compliant: bool,
    pub verdict: TrustVerdict,
    pub mandate_id: Uuid,
    pub mandate_hash: String,
    pub checked_at: DateTime<Utc>,
}

struct DailyWindow {
    cents_spent: u64,
    window_start: DateTime<Utc>,
}

impl DailyWindow {
    fn new() -> Self {
        Self { cents_spent: 0, window_start: Utc::now() }
    }

    /// Reset window if more than 24h have elapsed.
    fn refresh(&mut self) {
        if Utc::now() - self.window_start > Duration::hours(24) {
            self.cents_spent = 0;
            self.window_start = Utc::now();
        }
    }

    fn add(&mut self, cents: u64) {
        self.cents_spent += cents;
    }

    fn would_exceed(&self, cents: u64, cap: u64) -> bool {
        self.cents_spent + cents > cap
    }
}

pub struct MandateStore {
    mandates: HashMap<Uuid, SpendMandate>,
    agent_index: HashMap<String, Uuid>,
}

impl MandateStore {
    pub fn new() -> Self {
        Self { mandates: HashMap::new(), agent_index: HashMap::new() }
    }

    pub fn insert(&mut self, mandate: SpendMandate) {
        let did = mandate.agent_did.to_string();
        let id = mandate.id;
        self.mandates.insert(id, mandate);
        self.agent_index.insert(did, id);
    }

    pub fn get(&self, id: Uuid) -> ByzResult<&SpendMandate> {
        self.mandates
            .get(&id)
            .ok_or_else(|| ByzantiumError::MandateNotFound(id.to_string()))
    }

    pub fn for_agent(&self, did: &AgentDid) -> ByzResult<&SpendMandate> {
        let id = self
            .agent_index
            .get(did.as_str())
            .ok_or_else(|| ByzantiumError::AgentNotFound(did.to_string()))?;
        self.get(*id)
    }

    pub fn revoke(&mut self, id: Uuid) -> ByzResult<()> {
        let mandate = self
            .mandates
            .get(&id)
            .ok_or_else(|| ByzantiumError::MandateNotFound(id.to_string()))?;
        self.agent_index.remove(&mandate.agent_did.to_string());
        self.mandates.remove(&id);
        Ok(())
    }

    pub fn all_ids(&self) -> Vec<Uuid> {
        self.mandates.keys().copied().collect()
    }
}

impl Default for MandateStore {
    fn default() -> Self { Self::new() }
}

pub struct MandateEngine {
    store: MandateStore,
    /// Rolling 24h spend windows per agent DID.
    daily_spend: HashMap<String, DailyWindow>,
}

impl MandateEngine {
    pub fn new(store: MandateStore) -> Self {
        Self { store, daily_spend: HashMap::new() }
    }

    pub fn check(
        &self,
        agent_did: &AgentDid,
        action: &ActionType,
        amount_cents: Option<u64>,
        counterparty: Option<&Counterparty>,
    ) -> ByzResult<ComplianceResult> {
        let mandate = match self.store.for_agent(agent_did) {
            Ok(m) => m,
            Err(_) => {
                return Ok(ComplianceResult {
                    compliant: false,
                    verdict: TrustVerdict::Block {
                        reason: "no active mandate found for agent".to_string(),
                    },
                    mandate_id: Uuid::nil(),
                    mandate_hash: String::new(),
                    checked_at: Utc::now(),
                })
            }
        };

        let mandate_hash = mandate
            .mandate_root
            .clone()
            .unwrap_or_else(|| mandate.id.to_string());

        if !mandate.is_active() {
            return Ok(ComplianceResult {
                compliant: false,
                verdict: TrustVerdict::Block { reason: "mandate expired or not yet active".to_string() },
                mandate_id: mandate.id,
                mandate_hash,
                checked_at: Utc::now(),
            });
        }

        if !mandate.allows_action(action) {
            return Ok(ComplianceResult {
                compliant: false,
                verdict: TrustVerdict::Block {
                    reason: format!("action type {action:?} not permitted by mandate"),
                },
                mandate_id: mandate.id,
                mandate_hash,
                checked_at: Utc::now(),
            });
        }

        if let Some(cp) = counterparty {
            if !mandate.allows_counterparty(&cp.id) {
                return Ok(ComplianceResult {
                    compliant: false,
                    verdict: TrustVerdict::Block {
                        reason: format!("counterparty {} not in mandate whitelist", cp.id),
                    },
                    mandate_id: mandate.id,
                    mandate_hash,
                    checked_at: Utc::now(),
                });
            }
        }

        if let Some(amt) = amount_cents {
            if !mandate.allows_amount(amt) {
                return Ok(ComplianceResult {
                    compliant: false,
                    verdict: TrustVerdict::Block {
                        reason: format!(
                            "amount {} cents exceeds per-tx cap {} cents",
                            amt, mandate.per_tx_cap_cents
                        ),
                    },
                    mandate_id: mandate.id,
                    mandate_hash,
                    checked_at: Utc::now(),
                });
            }

            // Daily cap check — uses the current window (immutable borrow is fine here
            // because we only commit the spend in `record_spend` after the action succeeds).
            if let Some(window) = self.daily_spend.get(agent_did.as_str()) {
                if window.would_exceed(amt, mandate.daily_cap_cents) {
                    return Ok(ComplianceResult {
                        compliant: false,
                        verdict: TrustVerdict::Block {
                            reason: format!(
                                "amount {} cents would exceed 24h daily cap of {} cents \
                                 ({} already spent this window)",
                                amt, mandate.daily_cap_cents, window.cents_spent
                            ),
                        },
                        mandate_id: mandate.id,
                        mandate_hash,
                        checked_at: Utc::now(),
                    });
                }
            }
        }

        Ok(ComplianceResult {
            compliant: true,
            verdict: TrustVerdict::Pass,
            mandate_id: mandate.id,
            mandate_hash,
            checked_at: Utc::now(),
        })
    }

    /// Record a successful spend against the daily cap.
    /// Call this only after a trust-check PASS and the action is confirmed.
    pub fn record_spend(&mut self, agent_did: &AgentDid, amount_cents: u64) {
        let window = self
            .daily_spend
            .entry(agent_did.as_str().to_string())
            .or_insert_with(DailyWindow::new);
        window.refresh();
        window.add(amount_cents);
    }

    /// Reset the daily window for an agent (e.g. after mandate revocation).
    pub fn reset_daily_spend(&mut self, agent_did: &AgentDid) {
        self.daily_spend.remove(agent_did.as_str());
    }

    pub fn store(&self) -> &MandateStore { &self.store }
    pub fn store_mut(&mut self) -> &mut MandateStore { &mut self.store }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::{ActionType, AgentDid, SpendMandate, TrustVerdict};
    use chrono::{Duration, Utc};
    use std::collections::HashSet;
    use uuid::Uuid;

    fn make_mandate(
        agent_did: &str,
        per_tx_cap: u64,
        daily_cap: u64,
        actions: Vec<ActionType>,
    ) -> SpendMandate {
        SpendMandate {
            id: Uuid::new_v4(),
            agent_did: AgentDid::new(agent_did),
            operator_id: "test-operator".to_string(),
            counterparty_whitelist: HashSet::from(["vendor-a".to_string()]),
            allowed_action_types: actions,
            per_tx_cap_cents: per_tx_cap,
            daily_cap_cents: daily_cap,
            valid_from: Utc::now() - Duration::hours(1),
            valid_until: Utc::now() + Duration::hours(23),
            mandate_root: None,
            signature: None,
            operator_pubkey: None,
        }
    }

    fn engine_with(mandate: SpendMandate) -> MandateEngine {
        let mut store = MandateStore::new();
        store.insert(mandate);
        MandateEngine::new(store)
    }

    #[test]
    fn pass_when_within_limits() {
        let did = AgentDid::new("did:byz:test-agent");
        let engine = engine_with(make_mandate("did:byz:test-agent", 5000, 50000, vec![ActionType::Payment]));

        let result = engine.check(&did, &ActionType::Payment, Some(1000), None).unwrap();
        assert!(result.compliant);
        assert_eq!(result.verdict, TrustVerdict::Pass);
    }

    #[test]
    fn block_when_no_mandate() {
        let did = AgentDid::new("did:byz:unknown");
        let engine = MandateEngine::new(MandateStore::new());

        let result = engine.check(&did, &ActionType::Payment, Some(100), None).unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn block_when_per_tx_cap_exceeded() {
        let did = AgentDid::new("did:byz:agent");
        let engine = engine_with(make_mandate("did:byz:agent", 1000, 100_000, vec![ActionType::Payment]));

        let result = engine.check(&did, &ActionType::Payment, Some(1001), None).unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn block_when_action_type_not_permitted() {
        let did = AgentDid::new("did:byz:agent");
        let engine = engine_with(make_mandate("did:byz:agent", 9999, 99999, vec![ActionType::Payment]));

        let result = engine.check(&did, &ActionType::DataAccess, None, None).unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn block_when_counterparty_not_in_whitelist() {
        let did = AgentDid::new("did:byz:agent");
        let engine = engine_with(make_mandate("did:byz:agent", 9999, 99999, vec![ActionType::Payment]));
        let cp = Counterparty { id: "vendor-b".to_string(), chain: None, address: None };

        let result = engine.check(&did, &ActionType::Payment, Some(100), Some(&cp)).unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn pass_when_counterparty_in_whitelist() {
        let did = AgentDid::new("did:byz:agent");
        let engine = engine_with(make_mandate("did:byz:agent", 9999, 99999, vec![ActionType::Payment]));
        let cp = Counterparty { id: "vendor-a".to_string(), chain: None, address: None };

        let result = engine.check(&did, &ActionType::Payment, Some(100), Some(&cp)).unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn block_when_daily_cap_exceeded() {
        let did = AgentDid::new("did:byz:agent");
        let mut engine = engine_with(make_mandate("did:byz:agent", 10_000, 20_000, vec![ActionType::Payment]));

        // Record two successful spends of 8000 = 16000 total
        engine.record_spend(&did, 8_000);
        engine.record_spend(&did, 8_000);

        // Third spend of 5000 would push to 21000 > 20000 daily cap
        let result = engine.check(&did, &ActionType::Payment, Some(5_000), None).unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn daily_cap_reset_clears_spend() {
        let did = AgentDid::new("did:byz:agent");
        let mut engine = engine_with(make_mandate("did:byz:agent", 10_000, 20_000, vec![ActionType::Payment]));
        engine.record_spend(&did, 19_999);

        // Reset the window
        engine.reset_daily_spend(&did);

        // Now a 5000 spend should be fine (no accumulated spend, within per-tx cap)
        let result = engine.check(&did, &ActionType::Payment, Some(5_000), None).unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn mandate_revocation_blocks_future_checks() {
        let did = AgentDid::new("did:byz:agent");
        let mandate = make_mandate("did:byz:agent", 5000, 50000, vec![ActionType::Payment]);
        let mandate_id = mandate.id;
        let mut engine = engine_with(mandate);

        // Passes before revocation
        let r = engine.check(&did, &ActionType::Payment, Some(100), None).unwrap();
        assert!(r.compliant);

        engine.store_mut().revoke(mandate_id).unwrap();

        // Blocked after revocation
        let r2 = engine.check(&did, &ActionType::Payment, Some(100), None).unwrap();
        assert!(!r2.compliant);
    }
}
