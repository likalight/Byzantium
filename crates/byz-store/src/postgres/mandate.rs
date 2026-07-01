use byz_common::{AgentDid, ByzResult, ByzantiumError, SpendMandate};
use chrono::{DateTime, Utc};
use serde_json;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct MandateRepository {
    db: Arc<PgPool>,
}

impl MandateRepository {
    pub fn new(db: Arc<PgPool>) -> Self {
        Self { db }
    }

    pub async fn insert(&self, m: &SpendMandate) -> ByzResult<()> {
        let whitelist = serde_json::to_value(&m.counterparty_whitelist)
            .map_err(|e| ByzantiumError::Serialization(e))?;
        let action_types = serde_json::to_value(&m.allowed_action_types)
            .map_err(|e| ByzantiumError::Serialization(e))?;

        sqlx::query(
            r#"
            INSERT INTO mandates
                (id, agent_did, operator_id, counterparty_whitelist, allowed_action_types,
                 per_tx_cap_cents, daily_cap_cents, mandate_root, valid_from, valid_until)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT (id) DO UPDATE
              SET mandate_root = EXCLUDED.mandate_root,
                  valid_until  = EXCLUDED.valid_until
            "#,
        )
        .bind(m.id)
        .bind(m.agent_did.as_str())
        .bind(&m.operator_id)
        .bind(whitelist)
        .bind(action_types)
        .bind(m.per_tx_cap_cents as i64)
        .bind(m.daily_cap_cents as i64)
        .bind(&m.mandate_root)
        .bind(m.valid_from)
        .bind(m.valid_until)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(())
    }

    pub async fn get(&self, id: Uuid) -> ByzResult<SpendMandate> {
        let row = sqlx::query(
            "SELECT * FROM mandates WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?
        .ok_or_else(|| ByzantiumError::MandateNotFound(id.to_string()))?;

        self.row_to_mandate(row)
    }

    pub async fn for_agent(&self, did: &AgentDid) -> ByzResult<SpendMandate> {
        let row = sqlx::query(
            r#"
            SELECT * FROM mandates
            WHERE agent_did = $1 AND revoked_at IS NULL AND valid_until > NOW()
            ORDER BY valid_until DESC
            LIMIT 1
            "#,
        )
        .bind(did.as_str())
        .fetch_optional(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?
        .ok_or_else(|| ByzantiumError::AgentNotFound(did.to_string()))?;

        self.row_to_mandate(row)
    }

    pub async fn revoke(&self, id: Uuid) -> ByzResult<()> {
        let result = sqlx::query(
            "UPDATE mandates SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ByzantiumError::MandateNotFound(id.to_string()));
        }
        Ok(())
    }

    fn row_to_mandate(&self, row: sqlx::postgres::PgRow) -> ByzResult<SpendMandate> {
        use sqlx::Row;
        use std::collections::HashSet;

        let whitelist_val: serde_json::Value = row
            .try_get("counterparty_whitelist")
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        let counterparty_whitelist: HashSet<String> =
            serde_json::from_value(whitelist_val).map_err(ByzantiumError::Serialization)?;

        let actions_val: serde_json::Value = row
            .try_get("allowed_action_types")
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        let allowed_action_types = serde_json::from_value(actions_val)
            .map_err(ByzantiumError::Serialization)?;

        Ok(SpendMandate {
            id: row.try_get("id").map_err(|e| ByzantiumError::Database(e.to_string()))?,
            agent_did: AgentDid::new(
                row.try_get::<String, _>("agent_did")
                    .map_err(|e| ByzantiumError::Database(e.to_string()))?,
            ),
            operator_id: row
                .try_get("operator_id")
                .map_err(|e| ByzantiumError::Database(e.to_string()))?,
            counterparty_whitelist,
            allowed_action_types,
            per_tx_cap_cents: row
                .try_get::<i64, _>("per_tx_cap_cents")
                .map_err(|e| ByzantiumError::Database(e.to_string()))? as u64,
            daily_cap_cents: row
                .try_get::<i64, _>("daily_cap_cents")
                .map_err(|e| ByzantiumError::Database(e.to_string()))? as u64,
            valid_from: row
                .try_get::<DateTime<Utc>, _>("valid_from")
                .map_err(|e| ByzantiumError::Database(e.to_string()))?,
            valid_until: row
                .try_get::<DateTime<Utc>, _>("valid_until")
                .map_err(|e| ByzantiumError::Database(e.to_string()))?,
            mandate_root: row
                .try_get("mandate_root")
                .map_err(|e| ByzantiumError::Database(e.to_string()))?,
            signature: None,
            operator_pubkey: None,
        })
    }
}
