//! Honoring a portable limit on the x402 rail.
//!
//! x402 answers *how does value move*: an agent hits a paid endpoint, gets a 402
//! describing the price, signs a stablecoin payment, and retries. What it has
//! never answered is *how much this agent should be allowed to spend* — the
//! facilitator either trusts a per-venue setting or waves everything through.
//!
//! This module lets a facilitator take that answer from an attestation the agent
//! presents, which is what makes a ceiling earned on one chain apply here without
//! any prior relationship with the agent.
//!
//! The header is `X-Limit-Attestation`, carrying the same base64url-encoded
//! credential the TAP extension uses, so a facilitator that already speaks TAP
//! reuses its verifier rather than learning a second format.

use base64::Engine as _;
use byz_common::{ActionType, AssetClass, Currency, DrawRequest, LimitAttestation, Money};
use byz_crypto::DilithiumPublicKey;
use byz_underwrite::{AttestationIssuer, RevocationRegistry};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::X402Error;

/// Header carrying the limit attestation on an x402 payment.
pub const LIMIT_ATTESTATION_HEADER: &str = "x-limit-attestation";

/// Outcome of checking a payment against a presented limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitCheck {
    pub permitted: bool,
    /// Amount in the attestation's unit of account, after the haircut.
    pub effective_minor: u64,
    /// Fee owed at the attestation's tier.
    pub fee_minor: u64,
    pub tier: String,
    /// Whether a guarantor stands behind this limit, or the facilitator is on
    /// its own if the agent defaults.
    pub has_recourse: bool,
    pub refusal: Option<String>,
}

pub fn decode_attestation(header_value: &str) -> Result<LimitAttestation, X402Error> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_value.trim())
        .map_err(|_| X402Error::BadSignature("limit attestation is not valid base64".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| X402Error::BadSignature(format!("limit attestation is not valid JSON: {e}")))
}

pub fn encode_attestation(attestation: &LimitAttestation) -> Result<String, X402Error> {
    let json =
        serde_json::to_vec(attestation).map_err(|e| X402Error::BadSignature(e.to_string()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
}

/// Decide an x402 payment against a presented attestation.
///
/// `window_used` is the exposure already committed for this agent, which the
/// caller supplies — the facilitator, not the agent, is the authority on how
/// much of a window has been consumed.
#[allow(clippy::too_many_arguments)]
pub fn check_payment_against_limit(
    attestation: &LimitAttestation,
    issuer_key: &DilithiumPublicKey,
    revocations: &RevocationRegistry,
    amount_usdc_micro: u64,
    chain: &str,
    window_used: Money,
) -> Result<LimitCheck, X402Error> {
    AttestationIssuer::verify(attestation, issuer_key)
        .map_err(|e| X402Error::BadSignature(format!("attestation rejected: {e}")))?;

    // A valid signature is not enough: the outstanding set may have been killed
    // since issuance.
    if let Some(reason) = revocations.check(attestation) {
        return Ok(LimitCheck {
            permitted: false,
            effective_minor: 0,
            fee_minor: 0,
            tier: attestation.tier.as_str().to_string(),
            has_recourse: false,
            refusal: Some(reason.describe()),
        });
    }

    // USDC is quoted in micro-units; the unit of account here is cents. Rounding
    // up keeps a sub-cent payment from consuming zero window.
    let cents = amount_usdc_micro.div_ceil(10_000);
    let raw = Money::new(cents, Currency::Usd);

    // A stablecoin still moves against the unit of account inside a window, so
    // the recorded exposure is widened accordingly.
    let haircut = raw.scale_bps(AssetClass::Stablecoin.haircut_bps());
    let effective = raw
        .checked_add(&haircut)
        .map_err(|e| X402Error::BadSignature(e.to_string()))?;

    let fee = attestation
        .fee_for(&effective)
        .map(|m| m.minor_units)
        .unwrap_or(0);
    let has_recourse = attestation
        .guarantee
        .as_ref()
        .map(|g| g.has_recourse())
        .unwrap_or(false);

    let draw = DrawRequest {
        amount: effective,
        asset_class: AssetClass::Stablecoin,
        chain: chain.to_string(),
        action_type: ActionType::Payment,
        counterparty_class: None,
        window_used,
    };

    match attestation.permits(&draw, Utc::now()) {
        Ok(()) => Ok(LimitCheck {
            permitted: true,
            effective_minor: effective.minor_units,
            fee_minor: fee,
            tier: attestation.tier.as_str().to_string(),
            has_recourse,
            refusal: None,
        }),
        Err(refusal) => Ok(LimitCheck {
            permitted: false,
            effective_minor: effective.minor_units,
            fee_minor: fee,
            tier: attestation.tier.as_str().to_string(),
            has_recourse,
            refusal: Some(refusal.describe()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::{AgentDid, Guarantee, LimitScope, RiskTier};
    use byz_crypto::DilithiumKeypair;
    use chrono::Duration;

    fn attestation(kp_hex: Option<String>, single: u64, window: u64) -> LimitAttestation {
        let now = Utc::now();
        LimitAttestation {
            sub: AgentDid::new("did:byz:a"),
            prn: "sha256:acme".into(),
            iss: "did:web:byzantium".into(),
            tier: RiskTier::B1,
            lim_single: Money::usd_cents(single),
            lim_window: Money::usd_cents(window),
            window_secs: 86_400,
            ccy: Currency::Usd,
            scope: LimitScope::any()
                .with_chains(vec!["base".into()])
                .with_asset_classes(vec![AssetClass::Stablecoin])
                .with_action_types(vec![ActionType::Payment]),
            fee_bps: RiskTier::B1.fee_bps(),
            collateral_bps: RiskTier::B1.collateral_bps(),
            nbf: now - Duration::minutes(1),
            exp: now + Duration::hours(1),
            ev: "sha256:e".into(),
            mandate_hash: "sha256:m".into(),
            guarantee: Some(Guarantee::bureau(Currency::Usd)),
            collateral_required: None,
            signature: None,
            issuer_pubkey: kp_hex,
        }
    }

    /// Sign with the raw keypair, since the issuer path needs a full decision.
    fn signed(kp: &DilithiumKeypair, single: u64, window: u64) -> LimitAttestation {
        let mut a = attestation(Some(kp.public_key.to_hex()), single, window);
        let payload = a.signing_payload().unwrap();
        a.signature = Some(kp.sign(&payload).unwrap().as_bytes().to_vec());
        a
    }

    #[test]
    fn a_payment_inside_the_limit_is_permitted() {
        let kp = DilithiumKeypair::generate();
        let a = signed(&kp, 100_000, 1_000_000);
        let r = check_payment_against_limit(
            &a,
            &kp.public_key,
            &RevocationRegistry::new(),
            500_000_000, // 500.00 USDC in micro-units
            "base",
            Money::zero(Currency::Usd),
        )
        .unwrap();
        assert!(r.permitted, "{:?}", r.refusal);
        assert_eq!(r.tier, "B1");
    }

    #[test]
    fn micro_units_convert_to_cents_and_take_a_haircut() {
        let kp = DilithiumKeypair::generate();
        let a = signed(&kp, 100_000, 1_000_000);
        let r = check_payment_against_limit(
            &a,
            &kp.public_key,
            &RevocationRegistry::new(),
            10_000_000, // 10.00 USDC
            "base",
            Money::zero(Currency::Usd),
        )
        .unwrap();
        // 1000 cents plus a 25bps haircut, rounded up.
        assert_eq!(r.effective_minor, 1_003);
    }

    #[test]
    fn a_sub_cent_payment_still_consumes_window() {
        let kp = DilithiumKeypair::generate();
        let a = signed(&kp, 100_000, 1_000_000);
        let r = check_payment_against_limit(
            &a,
            &kp.public_key,
            &RevocationRegistry::new(),
            1, // 0.000001 USDC
            "base",
            Money::zero(Currency::Usd),
        )
        .unwrap();
        assert!(
            r.effective_minor > 0,
            "a dust payment consumed no window at all"
        );
    }

    #[test]
    fn a_payment_over_the_single_cap_is_refused() {
        let kp = DilithiumKeypair::generate();
        let a = signed(&kp, 1_000, 1_000_000);
        let r = check_payment_against_limit(
            &a,
            &kp.public_key,
            &RevocationRegistry::new(),
            500_000_000,
            "base",
            Money::zero(Currency::Usd),
        )
        .unwrap();
        assert!(!r.permitted);
        assert!(r.refusal.unwrap().contains("single-transaction cap"));
    }

    #[test]
    fn a_chain_outside_the_scope_is_refused() {
        let kp = DilithiumKeypair::generate();
        let a = signed(&kp, 100_000, 1_000_000);
        let r = check_payment_against_limit(
            &a,
            &kp.public_key,
            &RevocationRegistry::new(),
            100_000,
            "solana",
            Money::zero(Currency::Usd),
        )
        .unwrap();
        assert!(!r.permitted);
    }

    #[test]
    fn a_revoked_attestation_is_refused_despite_a_valid_signature() {
        let kp = DilithiumKeypair::generate();
        let a = signed(&kp, 100_000, 1_000_000);
        let mut reg = RevocationRegistry::new();
        reg.revoke_agent_now("did:byz:a");

        let r = check_payment_against_limit(
            &a,
            &kp.public_key,
            &reg,
            100_000,
            "base",
            Money::zero(Currency::Usd),
        )
        .unwrap();
        assert!(!r.permitted);
        assert!(r.refusal.unwrap().contains("revoked"));
    }

    #[test]
    fn a_forged_attestation_is_rejected_outright() {
        let kp = DilithiumKeypair::generate();
        let impostor = DilithiumKeypair::generate();
        let a = signed(&impostor, 100_000, 1_000_000);
        assert!(check_payment_against_limit(
            &a,
            &kp.public_key,
            &RevocationRegistry::new(),
            100_000,
            "base",
            Money::zero(Currency::Usd),
        )
        .is_err());
    }

    #[test]
    fn window_exposure_is_honored() {
        let kp = DilithiumKeypair::generate();
        let a = signed(&kp, 100_000, 100_000);
        let r = check_payment_against_limit(
            &a,
            &kp.public_key,
            &RevocationRegistry::new(),
            500_000_000,
            "base",
            Money::usd_cents(99_000), // nearly the whole window already used
        )
        .unwrap();
        assert!(!r.permitted);
        assert!(r.refusal.unwrap().contains("window cap"));
    }

    #[test]
    fn header_roundtrips() {
        let kp = DilithiumKeypair::generate();
        let a = signed(&kp, 100_000, 1_000_000);
        let encoded = encode_attestation(&a).unwrap();
        let back = decode_attestation(&encoded).unwrap();
        assert_eq!(back.sub, a.sub);
        assert_eq!(back.lim_window, a.lim_window);
    }

    #[test]
    fn the_facilitator_is_told_whether_there_is_recourse() {
        let kp = DilithiumKeypair::generate();
        let mut a = attestation(Some(kp.public_key.to_hex()), 100_000, 1_000_000);
        a.guarantee = Some(Guarantee::underwritten(
            "visa-issuer-01",
            Money::usd_cents(500_000),
        ));
        let payload = a.signing_payload().unwrap();
        a.signature = Some(kp.sign(&payload).unwrap().as_bytes().to_vec());

        let r = check_payment_against_limit(
            &a,
            &kp.public_key,
            &RevocationRegistry::new(),
            100_000,
            "base",
            Money::zero(Currency::Usd),
        )
        .unwrap();
        assert!(r.has_recourse, "a backed limit did not report recourse");
    }
}
