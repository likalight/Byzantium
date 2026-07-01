pub mod dilithium;
pub mod kyber;
pub mod merkle;

pub use dilithium::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
pub use kyber::{KyberKeypair, KyberPublicKey};
pub use merkle::{MerkleProof, MerkleTree};

/// SHA-256 hash of arbitrary bytes, returned as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// SHA-256 of two concatenated hashes (for Merkle node combining).
pub fn sha256_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().to_vec()
}
