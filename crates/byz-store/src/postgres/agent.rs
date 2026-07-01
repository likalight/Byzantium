use byz_common::{AgentDid, ByzResult, ByzantiumError};
use byz_identity::did::DidDocument;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AgentRepository {
    db: Arc<PgPool>,
}

impl AgentRepository {
    pub fn new(db: Arc<PgPool>) -> Self {
        Self { db }
    }

    pub async fn insert(&self, doc: &DidDocument) -> ByzResult<()> {
        let primary_key = doc
            .verification_method
            .first()
            .map(|vm| vm.public_key_hex.as_str())
            .unwrap_or("");

        sqlx::query(
            r#"
            INSERT INTO agents (did, operator_id, public_key_hex, kyb_verified, active)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (did) DO UPDATE
              SET updated_at = NOW(),
                  kyb_verified = EXCLUDED.kyb_verified,
                  active = EXCLUDED.active
            "#,
        )
        .bind(&doc.id)
        .bind(&doc.operator_id)
        .bind(primary_key)
        .bind(doc.kyb_verified)
        .bind(doc.active)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(())
    }

    pub async fn get(&self, did: &AgentDid) -> ByzResult<AgentRow> {
        sqlx::query_as::<_, AgentRow>(
            "SELECT did, operator_id, public_key_hex, kyb_verified, active FROM agents WHERE did = $1",
        )
        .bind(did.as_str())
        .fetch_optional(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?
        .ok_or_else(|| ByzantiumError::AgentNotFound(did.to_string()))
    }

    pub async fn deactivate(&self, did: &AgentDid) -> ByzResult<()> {
        let result = sqlx::query(
            "UPDATE agents SET active = FALSE, updated_at = NOW() WHERE did = $1",
        )
        .bind(did.as_str())
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ByzantiumError::AgentNotFound(did.to_string()));
        }
        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct AgentRow {
    pub did: String,
    pub operator_id: String,
    pub public_key_hex: String,
    pub kyb_verified: bool,
    pub active: bool,
}
