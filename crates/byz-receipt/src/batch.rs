//! Receipt batching and Merkle tree generation — Component C.
//!
//! Receipts are accumulated until a size or time threshold is hit,
//! then committed as a Merkle batch. A regulator or insurer can verify
//! any single receipt's inclusion in the batch using only SHA-256 (WebCrypto-native).
//!
//! The batch Merkle root is then forwarded to byz-anchor for immudb/Bitcoin commitment.

use byz_common::{ByzResult, LiabilityReceipt};
use byz_crypto::merkle::{MerkleProof, MerkleTree};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Canonical bytes for a receipt leaf: SHA-256(receipt_id || agent_did || timestamp_ms).
/// Recipients can verify using only the receipt they hold.
fn receipt_leaf_bytes(receipt: &LiabilityReceipt) -> Vec<u8> {
    let input = format!(
        "{}:{}:{}",
        receipt.id,
        receipt.agent_did,
        receipt.timestamp.timestamp_millis()
    );
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    h.finalize().to_vec()
}

/// An immutable batch of receipts with their Merkle root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptBatch {
    pub id: Uuid,
    pub receipt_ids: Vec<Uuid>,
    /// SHA-256 Merkle root over all receipts in this batch
    pub merkle_root: String,
    pub sealed_at: DateTime<Utc>,
    pub receipt_count: usize,
    /// immudb transaction ID after anchoring (None until anchored)
    pub immudb_tx_id: Option<u64>,
    /// Bitcoin txid after OP_RETURN anchoring (None unless premium tier)
    pub bitcoin_txid: Option<String>,
}

/// Returns the inclusion proof for a specific receipt in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInclusionProof {
    pub batch_id: Uuid,
    pub batch_root: String,
    pub receipt_id: Uuid,
    /// SHA-256 of the receipt leaf bytes (verifiable by the receipt holder)
    pub receipt_leaf_hash: String,
    pub merkle_proof: MerkleProof,
}

impl BatchInclusionProof {
    /// Verify entirely client-side with WebCrypto-compatible SHA-256.
    pub fn verify(&self) -> ByzResult<()> {
        self.merkle_proof.verify(&self.batch_root)
    }
}

/// Accumulates receipts and seals them into batches.
pub struct ReceiptBatcher {
    pending: Vec<LiabilityReceipt>,
    batch_size: usize,
    sealed: Vec<(ReceiptBatch, Vec<LiabilityReceipt>)>,
}

impl ReceiptBatcher {
    pub fn new(batch_size: usize) -> Self {
        Self {
            pending: Vec::new(),
            batch_size: batch_size.max(1),
            sealed: Vec::new(),
        }
    }

    pub fn add(&mut self, receipt: LiabilityReceipt) -> Option<ReceiptBatch> {
        self.pending.push(receipt);
        if self.pending.len() >= self.batch_size {
            Some(self.seal())
        } else {
            None
        }
    }

    /// Force-seal the current batch regardless of size.
    pub fn seal(&mut self) -> ReceiptBatch {
        let receipts = std::mem::take(&mut self.pending);
        let batch = Self::build_batch(receipts.clone());
        self.sealed.push((batch.clone(), receipts));
        batch
    }

    fn build_batch(receipts: Vec<LiabilityReceipt>) -> ReceiptBatch {
        let leaves: Vec<Vec<u8>> = receipts.iter().map(receipt_leaf_bytes).collect();
        let tree = MerkleTree::new(&leaves);

        ReceiptBatch {
            id: Uuid::new_v4(),
            receipt_ids: receipts.iter().map(|r| r.id).collect(),
            merkle_root: tree.root_hex(),
            sealed_at: Utc::now(),
            receipt_count: receipts.len(),
            immudb_tx_id: None,
            bitcoin_txid: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// All sealed batches with their receipts — used by the audit API.
    pub fn sealed_batches(&self) -> &[(ReceiptBatch, Vec<LiabilityReceipt>)] {
        &self.sealed
    }

    /// Receipts in the current (unsealed) pending buffer.
    pub fn pending_receipts(&self) -> &[LiabilityReceipt] {
        &self.pending
    }

    /// Returns all sealed batches waiting to be persisted.
    pub fn pending_sealed_batches(&self) -> Vec<ReceiptBatch> {
        self.sealed.iter().map(|(b, _)| b.clone()).collect()
    }

    /// Look up a sealed batch by ID.
    pub fn get_batch(&self, id: Uuid) -> Option<&ReceiptBatch> {
        self.sealed.iter().find(|(b, _)| b.id == id).map(|(b, _)| b)
    }

    /// Generate an inclusion proof for a specific receipt in a sealed batch.
    pub fn inclusion_proof(
        &self,
        batch_id: Uuid,
        receipt_id: Uuid,
    ) -> ByzResult<BatchInclusionProof> {
        let (batch, receipts) = self
            .sealed
            .iter()
            .find(|(b, _)| b.id == batch_id)
            .ok_or_else(|| byz_common::ByzantiumError::Internal(format!("batch {batch_id} not found")))?;

        let idx = receipts
            .iter()
            .position(|r| r.id == receipt_id)
            .ok_or_else(|| {
                byz_common::ByzantiumError::Internal(format!(
                    "receipt {receipt_id} not in batch {batch_id}"
                ))
            })?;

        let leaves: Vec<Vec<u8>> = receipts.iter().map(receipt_leaf_bytes).collect();
        let tree = MerkleTree::new(&leaves);
        let proof = tree.proof(idx)?;

        Ok(BatchInclusionProof {
            batch_id,
            batch_root: batch.merkle_root.clone(),
            receipt_id,
            receipt_leaf_hash: proof.leaf_hash.clone(),
            merkle_proof: proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::{ActionType, AgentDid, ReceiptOutcome};

    fn make_receipt(i: u8) -> LiabilityReceipt {
        LiabilityReceipt {
            id: Uuid::new_v4(),
            agent_did: AgentDid::new(format!("did:byz:agent-{i}")),
            action_type: ActionType::Payment,
            counterparty: None,
            amount_cents: Some(1000),
            outcome: ReceiptOutcome::Success,
            mandate_id: Uuid::nil(),
            rail_id: "x402".to_string(),
            timestamp: Utc::now(),
            signature: None,
        }
    }

    #[test]
    fn batch_and_prove_inclusion() {
        let mut batcher = ReceiptBatcher::new(4);
        let receipts: Vec<_> = (0u8..4).map(make_receipt).collect();
        let ids: Vec<Uuid> = receipts.iter().map(|r| r.id).collect();

        let mut batch = None;
        for r in receipts {
            batch = batcher.add(r).or(batch);
        }
        let batch = batch.expect("batch should seal at 4 receipts");

        for id in &ids {
            let proof = batcher.inclusion_proof(batch.id, *id).unwrap();
            proof.verify().expect("inclusion proof must verify");
        }
    }
}
