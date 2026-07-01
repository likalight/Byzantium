//! Neo4j reputation graph — the behavioral data moat.
//!
//! Nodes: (:Agent {did, score, computed_at})
//! Edges: (:Agent)-[:TRANSACTED_WITH {action_type, amount_cents, outcome, ts}]->(:Agent)
//!        (:Agent)-[:ENDORSED {weight}]->(:Agent)  (cross-agent trust, v2)
//!
//! The raw score and transaction history never leave this layer.
//! Only commitments and threshold-proof pass/fail signals are exposed externally.

use byz_common::{AgentDid, ByzResult, ByzantiumError, ReputationScore};
use neo4rs::{query, Graph};

#[derive(Clone)]
pub struct ReputationGraph {
    graph: Graph,
}

impl ReputationGraph {
    pub fn new(graph: Graph) -> Self {
        Self { graph }
    }

    /// Ensure the graph schema exists (idempotent, run at startup).
    pub async fn ensure_schema(&self) -> ByzResult<()> {
        self.graph
            .run(query(
                "CREATE CONSTRAINT agent_did_unique IF NOT EXISTS
                 FOR (a:Agent) REQUIRE a.did IS UNIQUE",
            ))
            .await
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    /// Upsert an agent node with its latest score commitment.
    pub async fn upsert_agent(&self, score: &ReputationScore) -> ByzResult<()> {
        self.graph
            .run(
                query(
                    r#"
                    MERGE (a:Agent {did: $did})
                    SET a.score_commitment = $commitment,
                        a.compliance_rate  = $compliance,
                        a.violation_rate   = $violation,
                        a.total_actions    = $total,
                        a.updated_at       = $updated_at
                    "#,
                )
                .param("did", score.agent_did.as_str())
                .param("commitment", score.commitment.as_deref().unwrap_or(""))
                .param("compliance", score.compliance_rate)
                .param("violation", score.violation_rate)
                .param("total", score.total_actions as i64)
                .param("updated_at", score.computed_at.to_rfc3339()),
            )
            .await
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    /// Record a transaction edge between two agents.
    pub async fn record_transaction(
        &self,
        from_did: &AgentDid,
        to_id: &str,
        action_type: &str,
        amount_cents: Option<u64>,
        success: bool,
    ) -> ByzResult<()> {
        self.graph
            .run(
                query(
                    r#"
                    MERGE (a:Agent {did: $from_did})
                    MERGE (b:Counterparty {id: $to_id})
                    CREATE (a)-[:TRANSACTED_WITH {
                        action_type:   $action_type,
                        amount_cents:  $amount,
                        success:       $success,
                        ts:            datetime()
                    }]->(b)
                    "#,
                )
                .param("from_did", from_did.as_str())
                .param("to_id", to_id)
                .param("action_type", action_type)
                .param("amount", amount_cents.unwrap_or(0) as i64)
                .param("success", success),
            )
            .await
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    /// Compute a naive behavioral score from graph statistics.
    /// Production: run a GNN model inside the TEE; expose only commitment + proof.
    pub async fn compute_score(&self, did: &AgentDid) -> ByzResult<u32> {
        let mut result = self
            .graph
            .execute(
                query(
                    r#"
                    MATCH (a:Agent {did: $did})-[t:TRANSACTED_WITH]->()
                    RETURN
                        count(t)                             AS total,
                        sum(CASE WHEN t.success THEN 1 ELSE 0 END) AS successes
                    "#,
                )
                .param("did", did.as_str()),
            )
            .await
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        if let Ok(Some(row)) = result.next().await {
            let total: i64 = row.get("total").unwrap_or(0);
            let successes: i64 = row.get("successes").unwrap_or(0);
            if total == 0 {
                return Ok(500); // neutral score for new agents
            }
            let score = ((successes as f64 / total as f64) * 1000.0).clamp(0.0, 1000.0) as u32;
            Ok(score)
        } else {
            Ok(500)
        }
    }

    /// Retrieve neighboring agent DIDs (for graph-privacy ZK, v2+).
    pub async fn get_neighbors(&self, did: &AgentDid, depth: u32) -> ByzResult<Vec<AgentDid>> {
        let depth = depth.clamp(1, 3);
        let mut result = self
            .graph
            .execute(
                query(&format!(
                    "MATCH (a:Agent {{did: $did}})-[*1..{}]-(n:Agent) RETURN DISTINCT n.did AS did",
                    depth
                ))
                .param("did", did.as_str()),
            )
            .await
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        let mut neighbors = Vec::new();
        while let Ok(Some(row)) = result.next().await {
            if let Ok(d) = row.get::<String>("did") {
                neighbors.push(AgentDid::new(d));
            }
        }
        Ok(neighbors)
    }
}
