//! SP1 guest program: Credential Attribute Disclosure Proof.
//!
//! Proves: attr_leaf ∈ credential_tree rooted at cred_root
//!         AND predicate(attr_value) == true
//! Public inputs:  cred_root (hex), predicate_id (string)
//! Private inputs: attr_value (string), attr_salt (string), merkle_path: Vec<(String,bool)>
//!
//! Predicates supported:
//!   "is_kyb_verified"   → attr_value == "true"
//!   "age_over_18"       → attr_value.parse::<u32>() >= 18
//!   "jurisdiction_eu"   → EU country codes list
//!   "non_empty"         → attr_value.len() > 0

#![no_main]
sp1_zkvm::entrypoint!(main);
use sha2::{Digest, Sha256};

pub fn main() {
    // Public inputs
    let cred_root: String = sp1_zkvm::io::read();
    let predicate_id: String = sp1_zkvm::io::read();

    // Private witness
    let attr_value: String = sp1_zkvm::io::read();
    let attr_salt: String = sp1_zkvm::io::read();
    let merkle_path: Vec<(String, bool)> = sp1_zkvm::io::read();

    // Constraint 1: compute leaf hash = SHA256(attr_value || attr_salt)
    let mut h = Sha256::new();
    h.update(attr_value.as_bytes());
    h.update(attr_salt.as_bytes());
    let leaf_bytes = h.finalize();
    let mut current = hex_encode(&leaf_bytes);

    // Constraint 2: walk Merkle path to root
    for (sibling, is_right) in &merkle_path {
        let mut h = Sha256::new();
        if *is_right {
            h.update(hex_decode_or_panic(&current));
            h.update(hex_decode_or_panic(sibling));
        } else {
            h.update(hex_decode_or_panic(sibling));
            h.update(hex_decode_or_panic(&current));
        }
        current = hex_encode(&h.finalize());
    }
    assert_eq!(current, cred_root, "Merkle path does not reach cred_root");

    // Constraint 3: predicate check (private value, public predicate ID)
    let predicate_result = match predicate_id.as_str() {
        "is_kyb_verified" => attr_value == "true",
        "age_over_18"     => attr_value.parse::<u32>().unwrap_or(0) >= 18,
        "non_empty"       => !attr_value.is_empty(),
        "jurisdiction_eu" => ["DE","FR","NL","SE","FI","IT","ES","PL","AT","BE","CZ","DK","IE","PT","GR"].contains(&attr_value.as_str()),
        _                 => false,
    };
    assert!(predicate_result, "predicate '{}' failed", predicate_id);

    // Commit public outputs
    sp1_zkvm::io::commit(&cred_root);
    sp1_zkvm::io::commit(&predicate_id);
    sp1_zkvm::io::commit(&true);
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push(HEX[(b >> 4) as usize] as char); s.push(HEX[(b & 0xf) as usize] as char); }
    s
}

fn hex_decode_or_panic(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
}
