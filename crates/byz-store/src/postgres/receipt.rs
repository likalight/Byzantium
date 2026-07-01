use byz_common::{ByzResult, ByzantiumError, LiabilityReceipt};
use byz_crypto::sha256_hex;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

/// A row returned by [`ReceiptRepository::list`].
pub struct ReceiptRow {
    pub id: Uuid,
    pub agent_did: String,
    pub mandate_id: Uuid,
    pub rail_id: String,
    pub amount_cents: Option<i64>,
    pub outcome: String,
    pub timestamp: DateTime<Utc>,
    pub batch_id: Option<Uuid>,
}

#[derive(Clone)]
pub struct ReceiptRepository {
    db: Arc<PgPool>,
}

impl ReceiptRepository {
    pub fn new(db: Arc<PgPool>) -> Self {
        Self { db }
    }

    pub async fn insert(&self, r: &LiabilityReceipt) -> ByzResult<()> {
        let outcome = serde_json::to_string(&r.outcome)
            .map_err(ByzantiumError::Serialization)?;
        let leaf_hash = sha256_hex(r.canonical_hash_input().as_bytes());

        sqlx::query(
            r#"
            INSERT INTO receipts
                (id, agent_did, mandate_id, leaf_hash, rail_id, amount_cents, outcome, timestamp)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(r.id)
        .bind(r.agent_did.as_str())
        .bind(r.mandate_id)
        .bind(&leaf_hash)
        .bind(&r.rail_id)
        .bind(r.amount_cents.map(|a| a as i64))
        .bind(&outcome)
        .bind(r.timestamp)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(())
    }

    pub async fn assign_batch(&self, receipt_id: Uuid, batch_id: Uuid) -> ByzResult<()> {
        sqlx::query("UPDATE receipts SET batch_id = $1 WHERE id = $2")
            .bind(batch_id)
            .bind(receipt_id)
            .execute(&*self.db)
            .await
            .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    /// List receipts with optional filters and keyset cursor pagination.
    ///
    /// `cursor` is the last-seen receipt `id` from a previous page. When provided,
    /// only receipts with `id > cursor` are returned, giving stable forward pagination.
    /// Results are ordered by `id ASC` so the cursor is stable and monotonic.
    pub async fn list(
        &self,
        agent_did: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        limit: i64,
        cursor: Option<Uuid>,
    ) -> ByzResult<Vec<ReceiptRow>> {
        let rows = sqlx::query(
            r#"
            SELECT id, agent_did, mandate_id, rail_id, amount_cents, outcome, timestamp, batch_id
            FROM receipts
            WHERE ($1::text IS NULL OR agent_did = $1)
              AND ($2::timestamptz IS NULL OR timestamp >= $2)
              AND ($3::timestamptz IS NULL OR timestamp <= $3)
              AND ($5::uuid IS NULL OR id > $5)
            ORDER BY id ASC
            LIMIT $4
            "#,
        )
        .bind(agent_did)
        .bind(from)
        .bind(to)
        .bind(limit)
        .bind(cursor)
        .fetch_all(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(ReceiptRow {
                id: row.try_get("id").map_err(|e| ByzantiumError::Database(e.to_string()))?,
                agent_did: row.try_get("agent_did").map_err(|e| ByzantiumError::Database(e.to_string()))?,
                mandate_id: row.try_get("mandate_id").map_err(|e| ByzantiumError::Database(e.to_string()))?,
                rail_id: row.try_get("rail_id").map_err(|e| ByzantiumError::Database(e.to_string()))?,
                amount_cents: row.try_get("amount_cents").map_err(|e| ByzantiumError::Database(e.to_string()))?,
                outcome: row.try_get("outcome").map_err(|e| ByzantiumError::Database(e.to_string()))?,
                timestamp: row.try_get("timestamp").map_err(|e| ByzantiumError::Database(e.to_string()))?,
                batch_id: row.try_get("batch_id").map_err(|e| ByzantiumError::Database(e.to_string()))?,
            });
        }
        Ok(out)
    }

    /// Find which batch a receipt belongs to (for inclusion proof lookup).
    pub async fn batch_id_for_receipt(&self, receipt_id: Uuid) -> ByzResult<Option<Uuid>> {
        let row = sqlx::query_scalar::<_, Uuid>(
            "SELECT batch_id FROM receipts WHERE id = $1 AND batch_id IS NOT NULL",
        )
        .bind(receipt_id)
        .fetch_optional(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(row)
    }
}
