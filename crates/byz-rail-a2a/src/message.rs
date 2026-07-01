//! A2A message helpers and DID extraction.

use crate::{A2AError, A2AMessage};
use byz_common::AgentDid;

/// Extract the sender DID from an A2A message params object.
/// Looks for `from_did`, `agent_did`, or `sender_did` fields.
pub fn extract_sender_did(msg: &A2AMessage) -> Result<AgentDid, A2AError> {
    let did = msg.params["from_did"]
        .as_str()
        .or_else(|| msg.params["agent_did"].as_str())
        .or_else(|| msg.params["sender_did"].as_str())
        .ok_or_else(|| A2AError::MissingDid(
            "could not find from_did / agent_did / sender_did in params".to_string()
        ))?;
    Ok(AgentDid::new(did))
}

/// Extract the recipient DID from an A2A message params object.
pub fn extract_recipient_did(msg: &A2AMessage) -> Result<AgentDid, A2AError> {
    let did = msg.params["to_did"]
        .as_str()
        .or_else(|| msg.params["target_did"].as_str())
        .or_else(|| msg.params["recipient_did"].as_str())
        .ok_or_else(|| A2AError::MissingDid(
            "could not find to_did / target_did / recipient_did in params".to_string()
        ))?;
    Ok(AgentDid::new(did))
}

/// Extract amount in cents if this is a payment delegation.
pub fn extract_amount_cents(msg: &A2AMessage) -> Option<u64> {
    msg.params["amount_cents"].as_u64()
        .or_else(|| {
            // USDC micro-units → cents
            msg.params["amount_usdc"].as_u64().map(|u| u / 10_000)
        })
}
