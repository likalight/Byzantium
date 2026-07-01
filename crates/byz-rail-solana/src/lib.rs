//! Byzantium Solana rail — SPL token transfer verification.
//!
//! Solana agents pay in SPL tokens (USDC, USDT on Solana).
//! This rail verifies a finalized Solana transaction before allowing an
//! agent action to proceed.
//!
//! Verification pipeline:
//!   1. Fetch transaction from Solana JSON-RPC
//!   2. Verify it's a confirmed/finalized SPL token transfer
//!   3. Assert `from`, `to`, `amount`, and `mint` match the expected values
//!   4. Byzantium trust-check on the sender's DID (did:sol:<base58-pubkey>)

pub mod error;
pub mod transfer;
pub mod verifier;

pub use error::SolanaRailError;
pub use transfer::{SolanaTransferProof, TransferStatus};
pub use verifier::SolanaVerifier;
