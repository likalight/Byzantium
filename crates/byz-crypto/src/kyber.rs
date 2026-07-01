//! Kyber-1024 post-quantum KEM — used for encrypted session key exchange
//! between agents and Byzantium nodes. Never used for signing (that's Dilithium).

use byz_common::errors::{ByzResult, ByzantiumError};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

#[derive(Clone)]
pub struct KyberPublicKey(Vec<u8>);

impl KyberPublicKey {
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

    /// Encapsulate: generate a shared secret and a ciphertext for this public key.
    /// Returns (shared_secret_hex, ciphertext_hex).
    pub fn encapsulate(&self) -> ByzResult<(String, String)> {
        let pk = kyber1024::PublicKey::from_bytes(&self.0)
            .map_err(|e| ByzantiumError::Crypto(format!("invalid kyber public key: {e}")))?;
        let (ss, ct) = kyber1024::encapsulate(&pk);
        Ok((hex::encode(ss.as_bytes()), hex::encode(ct.as_bytes())))
    }
}

impl std::fmt::Debug for KyberPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KyberPublicKey({}...)", &self.to_hex()[..16])
    }
}

#[derive(Clone)]
pub struct KyberSecretKey(Vec<u8>);

pub struct KyberKeypair {
    pub public_key: KyberPublicKey,
    secret_key: KyberSecretKey,
}

impl KyberKeypair {
    pub fn generate() -> Self {
        let (pk, sk) = kyber1024::keypair();
        Self {
            public_key: KyberPublicKey(pk.as_bytes().to_vec()),
            secret_key: KyberSecretKey(sk.as_bytes().to_vec()),
        }
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ciphertext_hex: &str) -> ByzResult<String> {
        let ct_bytes = hex::decode(ciphertext_hex)
            .map_err(|e| ByzantiumError::Crypto(e.to_string()))?;
        let sk = kyber1024::SecretKey::from_bytes(&self.secret_key.0)
            .map_err(|e| ByzantiumError::Crypto(format!("invalid secret key: {e}")))?;
        let ct = kyber1024::Ciphertext::from_bytes(&ct_bytes)
            .map_err(|e| ByzantiumError::Crypto(format!("invalid ciphertext: {e}")))?;
        let ss = kyber1024::decapsulate(&ct, &sk);
        Ok(hex::encode(ss.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let kp = KyberKeypair::generate();
        let (ss_enc, ct) = kp.public_key.encapsulate().unwrap();
        let ss_dec = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc, ss_dec, "shared secrets must match");
    }
}
