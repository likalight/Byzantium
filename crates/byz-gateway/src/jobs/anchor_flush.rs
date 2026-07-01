//! Background job: flush sealed receipt batches to immudb + Bitcoin.
//!
//! Runs every 5 minutes. Seals any pending receipt batch, then anchors the
//! Merkle root to immudb (always) and Bitcoin (if configured).

use byz_anchor::{AnchorService, ImmudbClient};
use byz_common::config::ImmudbConfig;
use crate::state::AppState;

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            run_once(&state).await;
        }
    });
}

async fn run_once(state: &AppState) {
    let batch = {
        let mut batcher = state.batcher.write().await;
        if batcher.is_empty() {
            return;
        }
        batcher.seal()
    };

    let cfg = &state.config.immudb;
    let immudb = ImmudbClient::new(
        &cfg.host,
        cfg.port,
        &cfg.username,
        &cfg.password,
        &cfg.database,
    );
    let anchor = AnchorService::new(immudb, None);

    match anchor.anchor(&batch).await {
        Ok(record) => {
            tracing::info!(
                batch_id = %record.batch_id,
                immudb_tx = ?record.immudb_tx_id,
                bitcoin_txid = ?record.bitcoin_txid,
                "batch anchored"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, batch_id = %batch.id, "anchor failed");
        }
    }
}
