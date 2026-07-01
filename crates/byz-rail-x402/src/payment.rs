//! Payment proof validation helpers.

use crate::{error::X402Error, PaymentProof, PaymentRequired};

/// Validate that a proof matches the payment request.
/// Does NOT do on-chain verification — that requires an Ethereum RPC call.
/// Call `verify_on_chain` for full settlement assurance.
pub fn validate_proof_format(
    proof: &PaymentProof,
    required: &PaymentRequired,
) -> Result<(), X402Error> {
    if required.is_expired() {
        return Err(X402Error::Expired);
    }
    if proof.value < required.amount {
        return Err(X402Error::InsufficientAmount {
            expected: required.amount,
            got: proof.value,
        });
    }
    if proof.to.to_lowercase() != required.pay_to.to_lowercase() {
        return Err(X402Error::MissingProof(format!(
            "payment recipient mismatch: expected {}, got {}",
            required.pay_to, proof.to
        )));
    }
    if proof.chain_id != required.chain_id {
        return Err(X402Error::MissingProof(format!(
            "chain mismatch: expected {}, got {}",
            required.chain_id, proof.chain_id
        )));
    }
    if proof.signature.is_empty() {
        return Err(X402Error::BadSignature("empty signature".to_string()));
    }
    Ok(())
}

/// Parse an X-Payment-Proof header value into a PaymentProof.
pub fn parse_proof_header(header_value: &str) -> Result<PaymentProof, X402Error> {
    let decoded = base64::decode(header_value)
        .map_err(|e| X402Error::MissingProof(format!("base64 decode failed: {e}")))?;
    serde_json::from_slice(&decoded)
        .map_err(|e| X402Error::MissingProof(format!("json decode failed: {e}")))
}

/// Parse an X-Payment-Required header value into a PaymentRequired.
pub fn parse_required_header(header_value: &str) -> Result<PaymentRequired, X402Error> {
    let decoded = base64::decode(header_value)
        .map_err(|e| X402Error::MissingProof(format!("base64 decode failed: {e}")))?;
    serde_json::from_slice(&decoded)
        .map_err(|e| X402Error::MissingProof(format!("json decode failed: {e}")))
}
