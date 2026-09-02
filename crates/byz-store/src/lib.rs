pub mod neo4j;
pub mod postgres;
pub mod redis_store;

pub use neo4j::ReputationGraph;
pub use postgres::{
    AgentRepository, ApiKeyRepository, ApiKeyRow, BatchRepository, Db, IssuedLimitRow,
    MandateRepository, ReceiptRepository, ReceiptRow, UnderwritingRepository,
};
pub use redis_store::{CommitOutcome, ProofCache, SharedExposure, SharedSnapshot};

use byz_common::config::Config;
use sqlx::PgPool;
use std::sync::Arc;

/// All persistence backends in one place — injected into AppState.
#[derive(Clone)]
pub struct Store {
    pub mandates: MandateRepository,
    pub agents: AgentRepository,
    pub receipts: ReceiptRepository,
    pub batches: BatchRepository,
    pub api_keys: ApiKeyRepository,
    pub proof_cache: ProofCache,
    /// Exposure shared across every gateway replica. The in-memory ledger is
    /// correct for one process; this is what makes more than one safe.
    pub exposure: SharedExposure,
    pub reputation_graph: ReputationGraph,
    /// Standing, issued limits, exposure, provenance and revocation cutoffs.
    pub underwriting: UnderwritingRepository,
    /// Shared PostgreSQL pool — exposed for lightweight health probes.
    pub pool: Db,
}

impl Store {
    pub async fn connect(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = PgPool::connect(&config.database.url).await?;
        let db = Arc::new(pool);

        let redis = redis::Client::open(config.redis.url.as_str())?;
        let redis_mgr = redis::aio::ConnectionManager::new(redis).await?;

        let neo4j = neo4rs::Graph::new(
            &config.neo4j.uri,
            &config.neo4j.username,
            &config.neo4j.password,
        )
        .await?;

        Ok(Self {
            mandates: MandateRepository::new(db.clone()),
            agents: AgentRepository::new(db.clone()),
            receipts: ReceiptRepository::new(db.clone()),
            batches: BatchRepository::new(db.clone()),
            api_keys: ApiKeyRepository::new(db.clone()),
            underwriting: UnderwritingRepository::new(db.clone()),
            proof_cache: ProofCache::new(redis_mgr.clone(), config.redis.proof_cache_ttl_secs),
            exposure: SharedExposure::new(redis_mgr),
            reputation_graph: ReputationGraph::new(neo4j),
            pool: db,
        })
    }
}
