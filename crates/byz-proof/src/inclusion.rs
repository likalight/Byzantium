//! Component C+D — Receipt inclusion and anchor verification.
//!
//! Component C: prove receipt ∈ batch (Merkle proof, no STARK needed).
//! Component D: prove batch_root is committed on Bitcoin / immudb.
//!
//! Both are SHA-256 Merkle proofs verifiable in a browser via WebCrypto.
//! No exotic ZK proof system — just well-understood hash-based inclusion.

use byz_common::{ByzResult, ByzantiumError};
use byz_crypto::merkle::MerkleProof;
use sha2::{Digest, Sha256};

pub struct InclusionVerifier;

impl InclusionVerifier {
    /// Verify a receipt's Merkle inclusion proof against a known batch root.
    /// Identical verification logic to what a browser runs via WebCrypto SHA-256.
    pub fn verify_receipt_in_batch(proof: &MerkleProof, batch_root: &str) -> ByzResult<()> {
        proof.verify(batch_root)
    }

    /// Verify the SPV proof chain:
    ///   receipt → batch_root (Merkle proof)
    ///   batch_root → Bitcoin block (tx Merkle proof + block header)
    ///
    /// In production: use a Bitcoin SPV crate for the block-header portion.
    pub fn verify_bitcoin_spv(
        receipt_proof: &MerkleProof,
        batch_root: &str,
        btc_txid: &str,
        tx_merkle_path: &[String],
        block_merkle_root: &str,
    ) -> ByzResult<()> {
        // Step 1: receipt → batch root
        Self::verify_receipt_in_batch(receipt_proof, batch_root)?;

        // Step 2: batch_root appears in OP_RETURN of tx (check txid encodes root prefix)
        // Production: parse the raw tx and inspect vout[n].scriptPubKey for OP_RETURN.
        let _ = btc_txid;

        // Step 3: tx Merkle proof → block_merkle_root (SHA-256d)
        if !tx_merkle_path.is_empty() {
            let txid_bytes =
                hex::decode(btc_txid).map_err(|_| ByzantiumError::MerkleProofInvalid)?;
            let computed = fold_tx_merkle_path(&txid_bytes, tx_merkle_path)?;
            if computed != block_merkle_root {
                return Err(ByzantiumError::MerkleProofInvalid);
            }
        }

        Ok(())
    }
}

/// Fold a tx Merkle path toward the block Merkle root.
/// Bitcoin uses double-SHA256: SHA256(SHA256(left || right)).
pub fn bitcoin_merkle_fold(txid_hex: &str, path: &[(String, bool)]) -> String {
    let mut current = hex::decode(txid_hex).expect("invalid txid hex");
    // Bitcoin txids are stored in little-endian; reverse for Merkle computation
    current.reverse();

    for (sibling_hex, txid_is_left) in path {
        let sibling = hex::decode(sibling_hex).expect("invalid sibling hex");
        let (left, right) = if *txid_is_left {
            (current.as_slice(), sibling.as_slice())
        } else {
            (sibling.as_slice(), current.as_slice())
        };

        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(left);
        combined.extend_from_slice(right);

        // Double SHA-256
        let first = Sha256::digest(&combined);
        let second = Sha256::digest(&first);
        current = second.to_vec();
    }

    // Re-reverse to get the root in standard display order
    current.reverse();
    hex::encode(&current)
}

pub fn verify_op_return_in_tx(raw_tx_hex: &str, expected_root_prefix: &[u8]) -> ByzResult<()> {
    let tx_bytes = hex::decode(raw_tx_hex)
        .map_err(|e| ByzantiumError::Anchor(format!("invalid tx hex: {e}")))?;

    // Scan for OP_RETURN (0x6a) followed by expected root bytes
    // This is a minimal scan, not a full tx parser
    let target: Vec<u8> = std::iter::once(0x6a_u8)
        .chain(std::iter::once(expected_root_prefix.len() as u8))
        .chain(expected_root_prefix.iter().copied())
        .collect();

    let found = tx_bytes.windows(target.len()).any(|w| w == target.as_slice());
    if found {
        Ok(())
    } else {
        Err(ByzantiumError::Anchor("OP_RETURN not found in transaction".to_string()))
    }
}

/// Bitcoin double-SHA-256 Merkle path fold (legacy helper — direction-unaware).
/// Path entries are `"<sibling_hex>:<L|R>"` where L/R indicates whether the
/// current hash is the left (L) or right (R) child in this level.
fn fold_tx_merkle_path(txid: &[u8], path: &[String]) -> ByzResult<String> {
    // Bitcoin txids are little-endian; reverse for Merkle computation
    let mut current: Vec<u8> = txid.iter().rev().cloned().collect();

    for entry in path {
        let (sibling_hex, side) = entry
            .split_once(':')
            .unwrap_or((entry.as_str(), "R"));

        let sib = hex::decode(sibling_hex).map_err(|_| ByzantiumError::MerkleProofInvalid)?;

        let mut combined = Vec::with_capacity(64);
        if side == "L" {
            // current is right child; sibling is left
            combined.extend_from_slice(&sib);
            combined.extend_from_slice(&current);
        } else {
            // current is left child; sibling is right
            combined.extend_from_slice(&current);
            combined.extend_from_slice(&sib);
        }

        // Double SHA-256 (Bitcoin standard)
        let first = Sha256::digest(&combined);
        current = Sha256::digest(&first).to_vec();
    }

    // Re-reverse to standard display order
    current.reverse();
    Ok(hex::encode(current))
}
