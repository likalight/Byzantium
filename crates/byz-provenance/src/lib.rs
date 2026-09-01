//! Execution provenance — signed evidence of what an agent actually did.
//!
//! Settlement history is public: anyone can read a chain. What nobody else holds
//! is the off-chain record of how an agent behaved between settlements — the
//! tool calls it made, the plans it committed to, the approvals a human gave. That
//! is the signal that makes underwriting an agent different from underwriting a
//! wallet, and it is the only part of the system that is genuinely not forkable.
//!
//! # The rule that makes it evidence
//!
//! **The runtime signs, not the agent.** An agent attesting to its own good
//! behavior is not evidence, it is a claim. Traces are signed at the point of
//! execution by a registered runtime key that the agent does not control.
//!
//! Unsigned traces are **ignored**, not down-weighted. Down-weighting creates an
//! incentive to flood the channel with cheap unverified claims in the hope that
//! some residual weight accrues; ignoring creates no such incentive. This is also
//! why runtime integration is the hardest adoption problem in the system — the
//! evidence cannot be collected after the fact.

pub mod bundle;
pub mod event;
pub mod verifier;

pub use bundle::{BundleStats, ProvenanceBundle};
pub use event::{ProvenanceEvent, ProvenanceKind, SignedProvenance};
pub use verifier::{ProvenanceVerifier, RejectionReason, RuntimeRegistry, VerifiedProvenance};
