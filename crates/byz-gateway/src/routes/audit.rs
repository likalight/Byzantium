//! GET /v1/audit/receipts — regulator audit export.
//!
//! Returns receipt records with their Merkle inclusion proofs so regulators
//! and insurers can verify each receipt independently without trusting Byzantium.
//! Requires an audit-scoped API key (same Bearer mechanism, different key set).

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub agent_did: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub batch_id: Option<Uuid>,
    /// Opaque cursor: base64(last_seen_id_uuid_string) from previous page's `next_cursor` field.
    pub cursor: Option<String>,
}

fn default_limit() -> usize { 100 }

#[derive(Debug, Serialize)]
pub struct AuditReceiptEntry {
    pub receipt_id: Uuid,
    pub agent_did: String,
    pub action_type: String,
    pub amount_cents: Option<u64>,
    pub rail_id: String,
    pub outcome: String,
    pub timestamp: DateTime<Utc>,
    pub mandate_id: Uuid,
    pub batch_id: Option<Uuid>,
    pub batch_merkle_root: Option<String>,
    /// Merkle inclusion proof — verifiable with byz-crypto's MerkleProof::verify()
    pub inclusion_proof: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct AuditReceiptsResponse {
    pub receipts: Vec<AuditReceiptEntry>,
    pub total: usize,
    /// Opaque cursor to fetch the next page. `None` when there are no more results.
    /// Pass as `?cursor=<value>` on the next request.
    pub next_cursor: Option<String>,
}

/// Kept for backwards-compatibility with any callers that reference the old name.
pub type AuditResponse = AuditReceiptsResponse;

pub async fn list_receipts(
    State(state): State<AppState>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<AuditReceiptsResponse>, (StatusCode, Json<Value>)> {
    let limit = q.limit.min(1000);

    // Decode the opaque cursor to a UUID (keyset pagination anchor).
    let cursor_uuid: Option<Uuid> = match &q.cursor {
        None => None,
        Some(encoded) => {
            let bytes = B64
                .decode(encoded)
                .map_err(|_| (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid cursor" }))))?;
            let s = String::from_utf8(bytes)
                .map_err(|_| (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid cursor" }))))?;
            let id = Uuid::parse_str(&s)
                .map_err(|_| (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid cursor" }))))?;
            Some(id)
        }
    };

    // Try persistent store first; fall back to in-memory batcher for dev.
    if let Some(store) = &state.store {
        let rows = store
            .receipts
            .list(
                q.agent_did.as_deref(),
                q.from,
                q.to,
                limit as i64,
                cursor_uuid,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))))?;

        let entries: Vec<AuditReceiptEntry> = rows
            .into_iter()
            .map(|r| AuditReceiptEntry {
                receipt_id: r.id,
                agent_did: r.agent_did,
                action_type: String::new(), // not stored in DB schema column; outcome carries type info
                amount_cents: r.amount_cents.map(|a| a as u64),
                rail_id: r.rail_id,
                outcome: r.outcome,
                timestamp: r.timestamp,
                mandate_id: r.mandate_id,
                batch_id: r.batch_id,
                batch_merkle_root: None,
                inclusion_proof: None,
            })
            .collect();

        // If we got exactly `limit` rows there may be more; encode the last id as the cursor.
        let next_cursor = if entries.len() == limit {
            entries.last().map(|e| B64.encode(e.receipt_id.to_string()))
        } else {
            None
        };

        let total = entries.len();
        return Ok(Json(AuditReceiptsResponse {
            total,
            receipts: entries,
            next_cursor,
        }));
    }

    let batcher = state.batcher.read().await;
    let mut entries: Vec<AuditReceiptEntry> = Vec::new();

    for (batch, receipts) in batcher.sealed_batches() {
        for receipt in receipts {
            if let Some(ref did) = q.agent_did {
                if receipt.agent_did.as_str() != did.as_str() { continue; }
            }
            if let Some(from) = q.from {
                if receipt.timestamp < from { continue; }
            }
            if let Some(to) = q.to {
                if receipt.timestamp > to { continue; }
            }
            if let Some(bid) = q.batch_id {
                if bid != batch.id { continue; }
            }

            let proof = batcher
                .inclusion_proof(batch.id, receipt.id)
                .ok()
                .map(|p| serde_json::to_value(p).unwrap_or(Value::Null));

            entries.push(AuditReceiptEntry {
                receipt_id: receipt.id,
                agent_did: receipt.agent_did.to_string(),
                action_type: format!("{:?}", receipt.action_type),
                amount_cents: receipt.amount_cents,
                rail_id: receipt.rail_id.clone(),
                outcome: format!("{:?}", receipt.outcome),
                timestamp: receipt.timestamp,
                mandate_id: receipt.mandate_id,
                batch_id: Some(batch.id),
                batch_merkle_root: Some(batch.merkle_root.clone()),
                inclusion_proof: proof,
            });

            if entries.len() >= limit { break; }
        }
        if entries.len() >= limit { break; }
    }

    // Also include receipts from the current (unsealed) batch
    for receipt in batcher.pending_receipts() {
        if let Some(ref did) = q.agent_did {
            if receipt.agent_did.as_str() != did.as_str() { continue; }
        }
        entries.push(AuditReceiptEntry {
            receipt_id: receipt.id,
            agent_did: receipt.agent_did.to_string(),
            action_type: format!("{:?}", receipt.action_type),
            amount_cents: receipt.amount_cents,
            rail_id: receipt.rail_id.clone(),
            outcome: format!("{:?}", receipt.outcome),
            timestamp: receipt.timestamp,
            mandate_id: receipt.mandate_id,
            batch_id: None,
            batch_merkle_root: None,
            inclusion_proof: None,
        });
        if entries.len() >= limit { break; }
    }

    let total = entries.len();
    Ok(Json(AuditReceiptsResponse {
        total,
        receipts: entries,
        next_cursor: None, // in-memory batcher does not support cursor pagination
    }))
}

pub async fn get_batch_proof(
    State(state): State<AppState>,
    axum::extract::Path(batch_id): axum::extract::Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let batcher = state.batcher.read().await;
    let batch = batcher
        .get_batch(batch_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": "batch not found" }))))?;

    Ok(Json(json!({
        "batch_id": batch_id,
        "merkle_root": batch.merkle_root,
        "receipt_count": batch.receipt_count,
        "sealed_at": batch.sealed_at,
    })))
}
