//! Underwriting — turning behavioral history into a limit.
//!
//! This is the half of the system that decides *how much* an agent should be
//! trusted with. Everything else in Byzantium enforces a mandate; this crate
//! issues one.
//!
//! The distinction matters commercially. A mandate whose caps a human typed once
//! is a configuration file. A mandate whose caps are derived from attested
//! history, bounded by the principal's KYC standing, and re-issued as evidence
//! accumulates is an underwritten credit line — and it is portable, because the
//! result is a signed statement rather than a per-venue setting.

pub mod engine;
pub mod guarantor;
pub mod issuer;
pub mod revocation;

pub use engine::{
    DecisionReason, PreviousLimit, RefusalCause, Underwriter, UnderwritingConfig,
    UnderwritingDecision, UnderwritingInput, UnderwritingOutcome,
};
pub use guarantor::{BackedGuarantor, BureauGuarantor, Guarantor};
pub use issuer::{refusal_attestation, AttestationIssuer};
pub use revocation::{RevocationReason, RevocationRegistry};
