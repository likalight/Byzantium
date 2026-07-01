//! Redis proof cache — pre-generated ZK proofs cached with TTL.
//!
//! The hot path (< 200ms) reads from this cache and verifies proof bytes.
//! It never generates proofs. The off-path proof-refresh job writes here.

use byz_common::{AgentDid, ByzResult, ByzantiumError};
use byz_proof::{threshold::VerifiedThreshold, CachedProofBundle};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

#[derive(Clone)]
pub struct ProofCache {
    mgr: ConnectionManager,
    ttl_secs: u64,
}

impl ProofCache {
    pub fn new(mgr: ConnectionManager, ttl_secs: u64) -> Self {
        Self { mgr, ttl_secs }
    }

    fn threshold_key(did: &AgentDid) -> String {
        format!("byz:proof:threshold:{}", did.as_str())
    }

    fn bundle_key(did: &AgentDid) -> String {
        format!("byz:proof:bundle:{}", did.as_str())
    }

    pub async fn get_threshold_proof(
        &self,
        did: &AgentDid,
    ) -> ByzResult<Option<VerifiedThreshold>> {
        let mut conn = self.mgr.clone();
        let raw: Option<String> = conn
            .get(Self::threshold_key(did))
            .await
            .map_err(|e| ByzantiumError::Cache(e.to_string()))?;

        match raw {
            None => Ok(None),
            Some(s) => {
                let proof: VerifiedThreshold =
                    serde_json::from_str(&s).map_err(ByzantiumError::Serialization)?;
                if proof.is_expired() {
                    Ok(None)
                } else {
                    Ok(Some(proof))
                }
            }
        }
    }

    pub async fn set_threshold_proof(
        &self,
        did: &AgentDid,
        proof: &VerifiedThreshold,
    ) -> ByzResult<()> {
        let mut conn = self.mgr.clone();
        let json = serde_json::to_string(proof).map_err(ByzantiumError::Serialization)?;
        conn.set_ex::<_, _, ()>(Self::threshold_key(did), json, self.ttl_secs)
            .await
            .map_err(|e| ByzantiumError::Cache(e.to_string()))?;
        Ok(())
    }

    pub async fn get_bundle(&self, did: &AgentDid) -> ByzResult<Option<CachedProofBundle>> {
        let mut conn = self.mgr.clone();
        let raw: Option<String> = conn
            .get(Self::bundle_key(did))
            .await
            .map_err(|e| ByzantiumError::Cache(e.to_string()))?;

        match raw {
            None => Ok(None),
            Some(s) => {
                let bundle: CachedProofBundle =
                    serde_json::from_str(&s).map_err(ByzantiumError::Serialization)?;
                if bundle.is_expired() {
                    Ok(None)
                } else {
                    Ok(Some(bundle))
                }
            }
        }
    }

    pub async fn set_bundle(&self, did: &AgentDid, bundle: &CachedProofBundle) -> ByzResult<()> {
        let mut conn = self.mgr.clone();
        let json = serde_json::to_string(bundle).map_err(ByzantiumError::Serialization)?;
        conn.set_ex::<_, _, ()>(Self::bundle_key(did), json, self.ttl_secs)
            .await
            .map_err(|e| ByzantiumError::Cache(e.to_string()))?;
        Ok(())
    }

    pub async fn invalidate(&self, did: &AgentDid) -> ByzResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn
            .del(&[Self::threshold_key(did), Self::bundle_key(did)])
            .await
            .map_err(|e| ByzantiumError::Cache(e.to_string()))?;
        Ok(())
    }

    /// Lightweight liveness check — issues a Redis PING command.
    pub async fn ping(&self) -> ByzResult<()> {
        let mut conn = self.mgr.clone();
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| ByzantiumError::Cache(e.to_string()))?;
        Ok(())
    }
}
