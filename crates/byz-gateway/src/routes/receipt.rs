use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use byz_common::{ActionType, AgentDid, Counterparty, LiabilityReceipt, ReceiptOutcome};
use byz_crypto::DilithiumKeypair;
use byz_receipt::{batch::BatchInclusionProof, receipt::ReceiptSigner};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateReceiptRequest {
    pub agent_did: String,
    pub action_type: ActionType,
    pub counterparty: Option<Counterparty>,
    pub amount_cents: Option<u64>,
    pub outcome: ReceiptOutcome,
    pub mandate_id: Uuid,
    pub rail_id: String,
}

pub async fn create_receipt(
    State(state): State<AppState>,
    Json(req): Json<CreateReceiptRequest>,
) -> Result<Json<LiabilityReceipt>, (StatusCode, Json<Value>)> {
    let signer = ReceiptSigner::new(DilithiumKeypair::generate());
    let receipt = signer
        .create_and_sign(
            AgentDid::new(&req.agent_did),
            req.action_type,
            req.counterparty,
            req.amount_cents,
            req.outcome,
            req.mandate_id,
            req.rail_id,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))))?;

    // Persist to PostgreSQL.
    if let Some(store) = &state.store {
        store.receipts.insert(&receipt).await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
        })?;
    }

    // Add to in-memory batcher; persist batch when sealed.
    let sealed = state.batcher.write().await.add(receipt.clone());
    if let Some(batch) = sealed {
        tracing::info!(batch_id = %batch.id, count = batch.receipt_count, "batch auto-sealed");
        if let Some(store) = &state.store {
            if let Err(e) = store.batches.insert(&batch).await {
                tracing::warn!(error = %e, "failed to persist batch to PostgreSQL");
            }
            // Update each receipt's batch_id in the DB.
            for rid in &batch.receipt_ids {
                let _ = store.receipts.assign_batch(*rid, batch.id).await;
            }
        }
    }

    Ok(Json(receipt))
}

pub async fn inclusion_proof(
    State(state): State<AppState>,
    Path(receipt_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Look up which batch contains this receipt from PostgreSQL.
    if let Some(store) = &state.store {
        if let Ok(Some(batch_id)) = store.receipts.batch_id_for_receipt(receipt_id).await {
            let batch_root = store.batches.get_root(batch_id).await.map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
            })?;
            return Ok(Json(json!({
                "receipt_id": receipt_id,
                "batch_id": batch_id,
                "batch_root": batch_root,
                "note": "Merkle proof generation requires re-building the batch tree from stored receipts"
            })));
        }
    }
    Err((
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "receipt not yet batched or batch not found" })),
    ))
}

pub async fn seal_batch(
    State(state): State<AppState>,
    Path(_batch_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let batch = state.batcher.write().await.seal();
    if let Some(store) = &state.store {
        if let Err(e) = store.batches.insert(&batch).await {
            tracing::warn!(error = %e, "failed to persist sealed batch");
        }
        for rid in &batch.receipt_ids {
            let _ = store.receipts.assign_batch(*rid, batch.id).await;
        }
    }
    tracing::info!(batch_id = %batch.id, merkle_root = %batch.merkle_root, "batch force-sealed");
    Ok(Json(json!({
        "batch_id": batch.id,
        "merkle_root": batch.merkle_root,
        "receipt_count": batch.receipt_count,
        "sealed_at": batch.sealed_at,
    })))
}
