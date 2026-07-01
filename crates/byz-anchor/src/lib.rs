pub mod bitcoin;
pub mod immudb;

pub use bitcoin::BitcoinAnchor;
pub use immudb::ImmudbClient;

use byz_common::ByzResult;
use byz_receipt::batch::ReceiptBatch;
use serde::{Deserialize, Serialize};

/// A record of where a batch root was anchored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRecord {
    pub batch_id: uuid::Uuid,
    pub batch_root: String,
    pub immudb_tx_id: Option<u64>,
    pub bitcoin_txid: Option<String>,
    pub anchored_at: chrono::DateTime<chrono::Utc>,
}

/// High-level anchor service: immudb (default) + Bitcoin (premium).
pub struct AnchorService {
    immudb: ImmudbClient,
    bitcoin: Option<BitcoinAnchor>,
}

impl AnchorService {
    pub fn new(immudb: ImmudbClient, bitcoin: Option<BitcoinAnchor>) -> Self {
        Self { immudb, bitcoin }
    }

    /// Anchor a batch root. Always writes to immudb; writes to Bitcoin only if configured.
    pub async fn anchor(&self, batch: &ReceiptBatch) -> ByzResult<AnchorRecord> {
        let immudb_tx_id = self.immudb.write_root(&batch.merkle_root, batch.id).await?;

        let bitcoin_txid = if let Some(btc) = &self.bitcoin {
            match btc.anchor_op_return(&batch.merkle_root).await {
                Ok(txid) => Some(txid),
                Err(e) => {
                    tracing::warn!(error = %e, "Bitcoin anchor failed; immudb record still valid");
                    None
                }
            }
        } else {
            None
        };

        Ok(AnchorRecord {
            batch_id: batch.id,
            batch_root: batch.merkle_root.clone(),
            immudb_tx_id: Some(immudb_tx_id),
            bitcoin_txid,
            anchored_at: chrono::Utc::now(),
        })
    }
}
