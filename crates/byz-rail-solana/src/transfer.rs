//! Solana SPL transfer proof — the data a payer passes to Byzantium.

use serde::{Deserialize, Serialize};

/// USDC mint on Solana mainnet
pub const USDC_MINT_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// USDT mint on Solana mainnet
pub const USDT_MINT_MAINNET: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaTransferProof {
    /// Finalized transaction signature (base58)
    pub signature: String,
    /// Expected sender wallet (base58 pubkey)
    pub from_wallet: String,
    /// Expected recipient wallet (base58 pubkey)
    pub to_wallet: String,
    /// SPL token mint address (base58)
    pub mint: String,
    /// Expected amount in the token's smallest unit (e.g. USDC = 6 decimals)
    pub amount: u64,
    /// Solana cluster: "mainnet-beta" | "devnet" | "testnet"
    pub cluster: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferStatus {
    Verified,
    NotFinalized,
    TransactionFailed,
    MintMismatch,
    AmountMismatch,
    SenderMismatch,
    RecipientMismatch,
    TrustBlocked,
}
