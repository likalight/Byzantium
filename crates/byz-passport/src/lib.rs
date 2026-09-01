//! The Agent Passport — principal, agent, and session keys.
//!
//! Three levels, each delegating to the next:
//!
//! ```text
//!   principal  (KYC'd human or entity — where limits consolidate)
//!       │  signed delegation
//!   agent      (a DID, one or more signing keys, possibly one per chain)
//!       │  signed delegation, narrower scope, short expiry
//!   session    (individually revocable, disposable)
//! ```
//!
//! Two properties carry the design, and both are enforced rather than documented:
//!
//! **History attaches to the DID, not to a key.** Rotating or revoking a key
//! therefore does not reset standing. This sounds like a detail and is actually
//! the difference between an operator practising good key hygiene and refusing
//! to, because under the alternative every rotation costs them their limit.
//!
//! **Delegation narrows, never widens.** A session key cannot authorise more than
//! the agent key that issued it. Without this the whole chain is decorative: an
//! agent under a tight mandate would simply mint itself a permissive session key.

pub mod delegation;
pub mod passport;

pub use delegation::{Delegation, DelegationError, DelegationScope};
pub use passport::{AgentPassport, KeyRole, PassportError, PassportKey};
