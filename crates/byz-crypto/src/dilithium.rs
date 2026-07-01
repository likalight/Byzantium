//! ML-DSA (Dilithium3) post-quantum signatures — the signing primitive for
//! all Byzantium receipts, pass tokens, and mandate roots.
//!
//! Dilithium3 provides 128-bit classical / conjectured 128-bit post-quantum security.
//! We use detached signatures throughout so signature bytes never wrap the message.

use byz_common::errors::{ByzResult, ByzantiumError};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumPublicKey(pub Vec<u8>);

impl DilithiumPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> ByzResult<Self> {
        let bytes = hex::decode(s).map_err(|e| ByzantiumError::Crypto(e.to_string()))?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DilithiumPublicKey({}...)", &self.to_hex()[..16])
    }
}

#[derive(Clone)]
pub struct DilithiumSecretKey(Vec<u8>);

impl DilithiumSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumSignature(pub Vec<u8>);

impl DilithiumSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> ByzResult<Self> {
        let bytes = hex::decode(s).map_err(|e| ByzantiumError::Crypto(e.to_string()))?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for DilithiumSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DilithiumSignature({}...)", &self.to_hex()[..16])
    }
}

#[derive(Clone)]
pub struct DilithiumKeypair {
    pub public_key: DilithiumPublicKey,
    secret_key: DilithiumSecretKey,
}

impl DilithiumKeypair {
    /// Generate a fresh Dilithium3 keypair from OS randomness.
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Self {
            public_key: DilithiumPublicKey(pk.as_bytes().to_vec()),
            secret_key: DilithiumSecretKey(sk.as_bytes().to_vec()),
        }
    }

    /// Sign arbitrary bytes. Returns a detached signature.
    pub fn sign(&self, message: &[u8]) -> ByzResult<DilithiumSignature> {
        let sk = dilithium3::SecretKey::from_bytes(&self.secret_key.0)
            .map_err(|e| ByzantiumError::Crypto(format!("invalid secret key: {e}")))?;
        let sig = dilithium3::detached_sign(message, &sk);
        Ok(DilithiumSignature(sig.as_bytes().to_vec()))
    }
}

/// Verify a Dilithium3 detached signature.
pub fn verify(
    message: &[u8],
    signature: &DilithiumSignature,
    public_key: &DilithiumPublicKey,
) -> ByzResult<()> {
    let pk = dilithium3::PublicKey::from_bytes(&public_key.0)
        .map_err(|e| ByzantiumError::Crypto(format!("invalid public key: {e}")))?;
    let sig = dilithium3::DetachedSignature::from_bytes(&signature.0)
        .map_err(|e| ByzantiumError::Crypto(format!("invalid signature bytes: {e}")))?;
    dilithium3::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| ByzantiumError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = DilithiumKeypair::generate();
        let msg = b"agent:did:example:123 action:payment amount:5000";
        let sig = kp.sign(msg).unwrap();
        verify(msg, &sig, &kp.public_key).expect("valid signature must verify");
    }

    #[test]
    fn tampered_message_fails() {
        let kp = DilithiumKeypair::generate();
        let msg = b"original message";
        let sig = kp.sign(msg).unwrap();
        let result = verify(b"tampered message", &sig, &kp.public_key);
        assert!(result.is_err());
    }
}
