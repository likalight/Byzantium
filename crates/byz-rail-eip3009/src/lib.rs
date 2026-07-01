//! EIP-3009 transferWithAuthorization rail — Base L2 / EVM.
//!
//! EIP-3009 enables gasless USDC/USDT transfers: the payer signs an EIP-712
//! authorization off-chain; the recipient (or a relayer) submits it on-chain.
//! Byzantium validates the authorization before allowing the agent action to proceed.
//!
//! On-chain footprint: no custom contract needed. USDC/USDT already implement
//! IERC20Permit and IERC3009 on Base.
//!
//! Verification:
//!   1. Recover the signer from the EIP-712 structured hash + secp256k1 signature
//!   2. Assert signer == `from` address in the authorization
//!   3. Assert nonce has not been used (query Base RPC)
//!   4. Assert valid_before > now > valid_after

pub mod authorization;
pub mod error;
pub mod verifier;

pub use authorization::{TransferAuthorization, AuthorizationStatus};
pub use error::Eip3009Error;
pub use verifier::Eip3009Verifier;
