use byz_common::{ByzResult, ByzantiumError};
use byz_receipt::batch::ReceiptBatch;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct BatchRepository {
    db: Arc<PgPool>,
}

impl BatchRepository {
    pub fn new(db: Arc<PgPool>) -> Self {
        Self { db }
    }

    pub async fn insert(&self, b: &ReceiptBatch) -> ByzResult<()> {
        sqlx::query(
            r#"
            INSERT INTO receipt_batches (id, merkle_root, receipt_count, sealed_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(b.id)
        .bind(&b.merkle_root)
        .bind(b.receipt_count as i32)
        .bind(b.sealed_at)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn update_anchor(
        &self,
        id: Uuid,
        immudb_tx_id: Option<u64>,
        bitcoin_txid: Option<String>,
    ) -> ByzResult<()> {
        sqlx::query(
            r#"
            UPDATE receipt_batches
            SET immudb_tx_id = $1, bitcoin_txid = $2
            WHERE id = $3
            "#,
        )
        .bind(immudb_tx_id.map(|t| t as i64))
        .bind(&bitcoin_txid)
        .bind(id)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn get_root(&self, id: Uuid) -> ByzResult<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT merkle_root FROM receipt_batches WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?
        .ok_or_else(|| ByzantiumError::Internal(format!("batch {id} not found")))
    }
}
