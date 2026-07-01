//! SHA-256 Merkle tree for receipt batching and credential attribute trees.
//!
//! Design: leaves are SHA-256(item_bytes), internal nodes are SHA-256(left || right).
//! Empty pairs are filled with the hash of an empty string.
//! Compatible with WebCrypto SHA-256 so a browser can verify independently.
//!
//! Inside STARK circuits, Poseidon2 replaces SHA-256 for efficiency.
//! The interface is identical; only the hash primitive changes.

use byz_common::errors::{ByzResult, ByzantiumError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

fn combine(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().to_vec()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// All tree levels: levels[0] = leaves, levels[last] = [root]
    levels: Vec<Vec<Vec<u8>>>,
}

impl MerkleTree {
    /// Build a Merkle tree from raw leaf data.
    /// Each item is hashed to produce its leaf node.
    pub fn new(items: &[Vec<u8>]) -> Self {
        assert!(!items.is_empty(), "Merkle tree requires at least one item");

        let leaves: Vec<Vec<u8>> = items.iter().map(|item| sha256(item)).collect();
        let mut levels = vec![leaves];

        loop {
            let current = levels.last().unwrap();
            if current.len() == 1 {
                break;
            }
            let mut next = Vec::new();
            let mut i = 0;
            while i < current.len() {
                let left = &current[i];
                let right = if i + 1 < current.len() {
                    &current[i + 1]
                } else {
                    left // duplicate last node when odd
                };
                next.push(combine(left, right));
                i += 2;
            }
            levels.push(next);
        }

        Self { levels }
    }

    /// The Merkle root as a hex string.
    pub fn root_hex(&self) -> String {
        hex::encode(self.levels.last().unwrap()[0].clone())
    }

    /// Root bytes.
    pub fn root(&self) -> &[u8] {
        &self.levels.last().unwrap()[0]
    }

    /// Generate an inclusion proof for the leaf at `index`.
    pub fn proof(&self, index: usize) -> ByzResult<MerkleProof> {
        let leaf_count = self.levels[0].len();
        if index >= leaf_count {
            return Err(ByzantiumError::MerkleProofInvalid);
        }

        let mut siblings = Vec::new();
        let mut current_index = index;

        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_index = if current_index % 2 == 0 {
                // left node — sibling is to the right (or self if last)
                (current_index + 1).min(level.len() - 1)
            } else {
                current_index - 1
            };
            siblings.push(MerkleSibling {
                hash: hex::encode(&level[sibling_index]),
                position: if current_index % 2 == 0 {
                    SiblingPosition::Right
                } else {
                    SiblingPosition::Left
                },
            });
            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf_index: index,
            leaf_hash: hex::encode(&self.levels[0][index]),
            siblings,
            root: self.root_hex(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SiblingPosition {
    Left,
    Right,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleSibling {
    pub hash: String,
    pub position: SiblingPosition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    /// SHA-256 of the original leaf data
    pub leaf_hash: String,
    pub siblings: Vec<MerkleSibling>,
    /// Expected root after applying all siblings
    pub root: String,
}

impl MerkleProof {
    /// Verify this proof against a known root hex string.
    /// Runs entirely in ~log2(N) SHA-256 operations — browser-verifiable via WebCrypto.
    pub fn verify(&self, expected_root: &str) -> ByzResult<()> {
        let mut current = hex::decode(&self.leaf_hash)
            .map_err(|_| ByzantiumError::MerkleProofInvalid)?;

        for sibling in &self.siblings {
            let sib_bytes = hex::decode(&sibling.hash)
                .map_err(|_| ByzantiumError::MerkleProofInvalid)?;
            current = match sibling.position {
                SiblingPosition::Right => combine(&current, &sib_bytes),
                SiblingPosition::Left => combine(&sib_bytes, &current),
            };
        }

        let computed_root = hex::encode(&current);
        if computed_root != expected_root {
            return Err(ByzantiumError::MerkleProofInvalid);
        }
        Ok(())
    }
}

/// Compute a leaf hash the same way MerkleTree does, for independent verification.
pub fn leaf_hash(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_verify_proof() {
        let items: Vec<Vec<u8>> = (0u8..8).map(|i| vec![i; 32]).collect();
        let tree = MerkleTree::new(&items);

        for i in 0..8 {
            let proof = tree.proof(i).unwrap();
            proof.verify(&tree.root_hex()).expect("proof must verify");
        }
    }

    #[test]
    fn tampered_leaf_fails() {
        let items: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 32]).collect();
        let tree = MerkleTree::new(&items);
        let mut proof = tree.proof(0).unwrap();
        proof.leaf_hash = hex::encode(vec![0xffu8; 32]); // tamper
        assert!(proof.verify(&tree.root_hex()).is_err());
    }

    #[test]
    fn single_leaf_tree() {
        let items = vec![b"solo receipt".to_vec()];
        let tree = MerkleTree::new(&items);
        let proof = tree.proof(0).unwrap();
        proof.verify(&tree.root_hex()).unwrap();
    }
}
