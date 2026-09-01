//! Mandate enforcement engine — the policy layer of the hot path.
//!
//! In production this runs inside an Intel SGX/SEV enclave (via Gramine).
//! The TEE ensures the mandate state cannot be bypassed in software.

use byz_common::{
    ActionType, AgentDid, ByzResult, ByzantiumError, Counterparty, Currency, ExposureSnapshot,
    Money, SpendMandate, TrustVerdict,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::exposure::{ExposureLedger, InMemoryExposureLedger};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub compliant: bool,
    pub verdict: TrustVerdict,
    pub mandate_id: Uuid,
    pub mandate_hash: String,
    pub checked_at: DateTime<Utc>,
}

pub struct MandateStore {
    mandates: HashMap<Uuid, SpendMandate>,
    agent_index: HashMap<String, Uuid>,
}

impl MandateStore {
    pub fn new() -> Self {
        Self {
            mandates: HashMap::new(),
            agent_index: HashMap::new(),
        }
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
    fn default() -> Self {
        Self::new()
    }
}

pub struct MandateEngine {
    store: MandateStore,
    /// Where committed and settled value is accounted for. Behind a trait so a
    /// shared, durable ledger can replace the single-process one without the
    /// engine changing.
    ledger: Box<dyn ExposureLedger>,
    /// Unit of account for the legacy cents-based entry points.
    base_ccy: Currency,
}

impl MandateEngine {
    pub fn new(store: MandateStore) -> Self {
        Self {
            store,
            ledger: Box::new(InMemoryExposureLedger::new()),
            base_ccy: Currency::Usd,
        }
    }

    /// Swap in a different exposure ledger — a shared one in a multi-replica
    /// deployment, where a per-process ledger would hand out the same window
    /// capacity once per replica.
    pub fn with_ledger(mut self, ledger: Box<dyn ExposureLedger>) -> Self {
        self.ledger = ledger;
        self
    }

    pub fn with_base_currency(mut self, ccy: Currency) -> Self {
        self.base_ccy = ccy;
        self
    }

    pub fn base_currency(&self) -> Currency {
        self.base_ccy
    }

    pub fn ledger(&self) -> &dyn ExposureLedger {
        self.ledger.as_ref()
    }

    pub fn ledger_mut(&mut self) -> &mut dyn ExposureLedger {
        self.ledger.as_mut()
    }

    /// Current exposure for an agent, as the underwriter consumes it.
    pub fn exposure(&self, agent_did: &AgentDid) -> ExposureSnapshot {
        self.ledger.snapshot(agent_did, self.base_ccy)
    }

    /// Record value committed but not yet settled. Callers that go through
    /// `record_commit` then `record_settled`/`record_released` get accurate
    /// at-risk accounting; `record_spend` alone remains supported.
    pub fn record_commit(&mut self, agent_did: &AgentDid, amount: Money) {
        self.ledger.record_commit(agent_did, amount);
    }

    pub fn record_settled(&mut self, agent_did: &AgentDid, amount: Money) {
        self.ledger.record_settled(agent_did, amount);
    }

    pub fn record_released(&mut self, agent_did: &AgentDid, amount: Money) {
        self.ledger.record_released(agent_did, amount);
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
                verdict: TrustVerdict::Block {
                    reason: "mandate expired or not yet active".to_string(),
                },
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

            // Window cap check. Both settled value and outstanding commitments
            // count: an unresolved draw is capacity that is already spoken for,
            // and ignoring it lets concurrent draws each see an empty window.
            let exposure = self.ledger.snapshot(agent_did, self.base_ccy);
            let committed = exposure
                .total_committed()
                .map(|m| m.minor_units)
                .unwrap_or(exposure.window_used.minor_units);
            if committed.saturating_add(amt) > mandate.daily_cap_cents {
                return Ok(ComplianceResult {
                    compliant: false,
                    verdict: TrustVerdict::Block {
                        reason: format!(
                            "amount {} cents would exceed 24h daily cap of {} cents \
                             ({} already committed this window)",
                            amt, mandate.daily_cap_cents, committed
                        ),
                    },
                    mandate_id: mandate.id,
                    mandate_hash,
                    checked_at: Utc::now(),
                });
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
        let amount = Money::new(amount_cents, self.base_ccy);
        // Settle directly: this entry point has no prior commit to draw down.
        self.ledger.record_commit(agent_did, amount);
        self.ledger.record_settled(agent_did, amount);
    }

    /// Reset the daily window for an agent (e.g. after mandate revocation).
    pub fn reset_daily_spend(&mut self, agent_did: &AgentDid) {
        self.ledger.reset(agent_did);
    }

    pub fn store(&self) -> &MandateStore {
        &self.store
    }
    pub fn store_mut(&mut self) -> &mut MandateStore {
        &mut self.store
    }
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
        let engine = engine_with(make_mandate(
            "did:byz:test-agent",
            5000,
            50000,
            vec![ActionType::Payment],
        ));

        let result = engine
            .check(&did, &ActionType::Payment, Some(1000), None)
            .unwrap();
        assert!(result.compliant);
        assert_eq!(result.verdict, TrustVerdict::Pass);
    }

    #[test]
    fn block_when_no_mandate() {
        let did = AgentDid::new("did:byz:unknown");
        let engine = MandateEngine::new(MandateStore::new());

        let result = engine
            .check(&did, &ActionType::Payment, Some(100), None)
            .unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn block_when_per_tx_cap_exceeded() {
        let did = AgentDid::new("did:byz:agent");
        let engine = engine_with(make_mandate(
            "did:byz:agent",
            1000,
            100_000,
            vec![ActionType::Payment],
        ));

        let result = engine
            .check(&did, &ActionType::Payment, Some(1001), None)
            .unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn block_when_action_type_not_permitted() {
        let did = AgentDid::new("did:byz:agent");
        let engine = engine_with(make_mandate(
            "did:byz:agent",
            9999,
            99999,
            vec![ActionType::Payment],
        ));

        let result = engine
            .check(&did, &ActionType::DataAccess, None, None)
            .unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn block_when_counterparty_not_in_whitelist() {
        let did = AgentDid::new("did:byz:agent");
        let engine = engine_with(make_mandate(
            "did:byz:agent",
            9999,
            99999,
            vec![ActionType::Payment],
        ));
        let cp = Counterparty {
            id: "vendor-b".to_string(),
            chain: None,
            address: None,
        };

        let result = engine
            .check(&did, &ActionType::Payment, Some(100), Some(&cp))
            .unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn pass_when_counterparty_in_whitelist() {
        let did = AgentDid::new("did:byz:agent");
        let engine = engine_with(make_mandate(
            "did:byz:agent",
            9999,
            99999,
            vec![ActionType::Payment],
        ));
        let cp = Counterparty {
            id: "vendor-a".to_string(),
            chain: None,
            address: None,
        };

        let result = engine
            .check(&did, &ActionType::Payment, Some(100), Some(&cp))
            .unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn block_when_daily_cap_exceeded() {
        let did = AgentDid::new("did:byz:agent");
        let mut engine = engine_with(make_mandate(
            "did:byz:agent",
            10_000,
            20_000,
            vec![ActionType::Payment],
        ));

        // Record two successful spends of 8000 = 16000 total
        engine.record_spend(&did, 8_000);
        engine.record_spend(&did, 8_000);

        // Third spend of 5000 would push to 21000 > 20000 daily cap
        let result = engine
            .check(&did, &ActionType::Payment, Some(5_000), None)
            .unwrap();
        assert!(!result.compliant);
        assert!(matches!(result.verdict, TrustVerdict::Block { .. }));
    }

    #[test]
    fn daily_cap_reset_clears_spend() {
        let did = AgentDid::new("did:byz:agent");
        let mut engine = engine_with(make_mandate(
            "did:byz:agent",
            10_000,
            20_000,
            vec![ActionType::Payment],
        ));
        engine.record_spend(&did, 19_999);

        // Reset the window
        engine.reset_daily_spend(&did);

        // Now a 5000 spend should be fine (no accumulated spend, within per-tx cap)
        let result = engine
            .check(&did, &ActionType::Payment, Some(5_000), None)
            .unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn mandate_revocation_blocks_future_checks() {
        let did = AgentDid::new("did:byz:agent");
        let mandate = make_mandate("did:byz:agent", 5000, 50000, vec![ActionType::Payment]);
        let mandate_id = mandate.id;
        let mut engine = engine_with(mandate);

        // Passes before revocation
        let r = engine
            .check(&did, &ActionType::Payment, Some(100), None)
            .unwrap();
        assert!(r.compliant);

        engine.store_mut().revoke(mandate_id).unwrap();

        // Blocked after revocation
        let r2 = engine
            .check(&did, &ActionType::Payment, Some(100), None)
            .unwrap();
        assert!(!r2.compliant);
    }
}
