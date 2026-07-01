//! SP1 guest program — Component B: Reputation Threshold Proof.
//!
//! Proves: score s ≥ threshold T
//! Public inputs:  commitment = SHA-256(score_le_bytes || nonce), threshold T
//! Private inputs: score s, nonce (32 bytes)
//!
//! Circuit constraints:
//!   1. SHA-256(s.to_le_bytes() || nonce) == commitment   [opening check]
//!   2. s - T ≥ 0                                         [range check via subtraction]
//!
//! Range check uses subtraction with u32 arithmetic — no bit decomposition needed
//! because Rust's type system handles the u32 overflow at the language level,
//! but inside SP1 we assert the condition explicitly so the verifier enforces it.
//!
//! Build: cd programs && cargo prove build
//! Output: programs/elf/threshold-proof

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

fn sha256_commit(score: u32, nonce: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(score.to_le_bytes());
    h.update(nonce);
    hex::encode(h.finalize())
}

pub fn main() {
    // --- Read public inputs ---
    let commitment_hex: String = sp1_zkvm::io::read();
    let threshold: u32 = sp1_zkvm::io::read();

    // --- Read private witness (stays inside the zkVM; never revealed) ---
    let score: u32 = sp1_zkvm::io::read();
    let nonce: Vec<u8> = sp1_zkvm::io::read();

    // --- Constraint 1: commitment opening ---
    let computed = sha256_commit(score, &nonce);
    assert_eq!(
        computed, commitment_hex,
        "commitment opening failed: score does not match commitment"
    );

    // --- Constraint 2: range check (score ≥ threshold) ---
    assert!(
        score >= threshold,
        "score {} is below threshold {}",
        score,
        threshold
    );

    // --- Commit public outputs ---
    // The verifier reads these back via proof.public_values.read::<bool>()
    sp1_zkvm::io::commit(&true);
    sp1_zkvm::io::commit(&commitment_hex);
    sp1_zkvm::io::commit(&threshold);
}
