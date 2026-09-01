//! Trusted Agent Protocol binding, and a limit-attestation extension for it.
//!
//! Visa's Trusted Agent Protocol establishes that an agent talking to a merchant
//! is a legitimate agent rather than a bot, using HTTP Message Signatures
//! (RFC 9421) over existing web infrastructure. It answers *who is this*. It does
//! not answer *how much should this agent be trusted with* — that is underwriting,
//! and it is the gap this crate fills.
//!
//! # The extension
//!
//! A [`LimitAttestation`](byz_common::LimitAttestation) travels in a
//! `Limit-Attestation` request header, and **must appear in the signature's
//! covered components**. That requirement is the entire security argument: a
//! limit carried in an unsigned header can be swapped for a larger one in transit
//! by anyone on the path, which would make the extension worse than useless.
//! [`TapVerifier`] refuses a request whose attestation is not covered, rather than
//! treating coverage as advisory.
//!
//! Because the attestation is itself independently signed by its issuer, a
//! merchant ends up checking two signatures that answer two different questions:
//! the TAP signature says this request really came from this agent, and the
//! attestation signature says this issuer stands behind this limit.
//!
//! This is written to be proposable into TAP rather than to route around it. The
//! signature base construction follows RFC 9421 so an existing TAP verifier needs
//! one additional covered component, not a second protocol.

pub mod extension;
pub mod signature;

pub use extension::{
    attach_limit_attestation, extract_limit_attestation, TapExtensionError,
    LIMIT_ATTESTATION_HEADER,
};
pub use signature::{
    CoveredComponent, HttpMessage, SignatureParams, TapError, TapSigner, TapVerifier,
};
