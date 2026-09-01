//! RFC 9421 HTTP Message Signatures.
//!
//! The signature base is a newline-joined list of `"name": value` lines, one per
//! covered component, terminated by a `"@signature-params"` line carrying the
//! component list and its parameters. Both signer and verifier reconstruct that
//! string independently and must agree byte for byte, which is what makes the
//! covered-component list itself tamper-evident: changing which headers were
//! signed changes the final line, and the signature stops verifying.

use base64::Engine as _;
use byz_crypto::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum TapError {
    #[error("signature label {0} not found in Signature-Input")]
    MissingSignatureInput(String),
    #[error("signature label {0} not found in Signature")]
    MissingSignature(String),
    #[error("malformed Signature-Input: {0}")]
    MalformedSignatureInput(String),
    #[error("component {0} is referenced by the signature but absent from the message")]
    MissingComponent(String),
    #[error("unknown key id {0}")]
    UnknownKeyId(String),
    #[error("signature does not verify")]
    BadSignature,
    #[error("signature has expired")]
    Expired,
    #[error("signature created in the future")]
    CreatedInFuture,
    #[error("signature does not cover required component {0}")]
    ComponentNotCovered(String),
    #[error("content-digest does not match the body")]
    DigestMismatch,
    #[error("crypto failure: {0}")]
    Crypto(String),
}

/// A covered component: either a derived value (`@method`) or a header name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveredComponent(String);

impl CoveredComponent {
    pub fn new(name: impl AsRef<str>) -> Self {
        // Component identifiers are lowercase; headers are case-insensitive and
        // derived components are defined lowercase.
        Self(name.as_ref().to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_derived(&self) -> bool {
        self.0.starts_with('@')
    }
}

impl From<&str> for CoveredComponent {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// Parameters attached to a signature, per RFC 9421 §2.3.
#[derive(Debug, Clone, PartialEq)]
pub struct SignatureParams {
    pub created: i64,
    pub expires: Option<i64>,
    pub keyid: String,
    pub alg: String,
    pub nonce: Option<String>,
    /// TAP uses this to mark the application context.
    pub tag: Option<String>,
}

impl SignatureParams {
    pub fn new(keyid: impl Into<String>) -> Self {
        Self {
            created: Utc::now().timestamp(),
            expires: Some(Utc::now().timestamp() + 300),
            keyid: keyid.into(),
            alg: "ml-dsa-65".to_string(),
            nonce: None,
            tag: Some("byzantium-limits".to_string()),
        }
    }

    pub fn with_expires_in(mut self, secs: i64) -> Self {
        self.expires = Some(self.created + secs);
        self
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Serialised parameter list, e.g. `;created=1618884473;keyid="k1";alg="..."`.
    fn serialize(&self) -> String {
        let mut s = format!(";created={}", self.created);
        if let Some(exp) = self.expires {
            s.push_str(&format!(";expires={exp}"));
        }
        s.push_str(&format!(";keyid=\"{}\"", self.keyid));
        s.push_str(&format!(";alg=\"{}\"", self.alg));
        if let Some(ref n) = self.nonce {
            s.push_str(&format!(";nonce=\"{n}\""));
        }
        if let Some(ref t) = self.tag {
            s.push_str(&format!(";tag=\"{t}\""));
        }
        s
    }

    fn parse(input: &str) -> Result<Self, TapError> {
        let mut created = None;
        let mut expires = None;
        let mut keyid = None;
        let mut alg = None;
        let mut nonce = None;
        let mut tag = None;

        for part in input.split(';').skip(1) {
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| TapError::MalformedSignatureInput(part.to_string()))?;
            let v = v.trim_matches('"');
            match k {
                "created" => created = v.parse().ok(),
                "expires" => expires = v.parse().ok(),
                "keyid" => keyid = Some(v.to_string()),
                "alg" => alg = Some(v.to_string()),
                "nonce" => nonce = Some(v.to_string()),
                "tag" => tag = Some(v.to_string()),
                _ => {}
            }
        }

        Ok(Self {
            created: created
                .ok_or_else(|| TapError::MalformedSignatureInput("created missing".into()))?,
            expires,
            keyid: keyid
                .ok_or_else(|| TapError::MalformedSignatureInput("keyid missing".into()))?,
            alg: alg.unwrap_or_else(|| "ml-dsa-65".to_string()),
            nonce,
            tag,
        })
    }
}

/// The parts of an HTTP request a signature can cover.
#[derive(Debug, Clone)]
pub struct HttpMessage {
    pub method: String,
    pub target_uri: String,
    /// Header names are stored lowercase.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpMessage {
    pub fn new(method: impl Into<String>, target_uri: impl Into<String>) -> Self {
        Self {
            method: method.into().to_ascii_uppercase(),
            target_uri: target_uri.into(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.as_ref().to_ascii_lowercase(), value.into());
        self
    }

    pub fn set_header(&mut self, name: impl AsRef<str>, value: impl Into<String>) {
        self.headers
            .insert(name.as_ref().to_ascii_lowercase(), value.into());
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Compute and attach `Content-Digest`, so the body is covered transitively
    /// by signing that header rather than the bytes themselves.
    pub fn compute_content_digest(&mut self) {
        let digest = Sha256::digest(&self.body);
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        self.set_header("content-digest", format!("sha-256=:{b64}:"));
    }

    fn verify_content_digest(&self) -> Result<(), TapError> {
        let Some(header) = self.header("content-digest") else {
            return Ok(());
        };
        let digest = Sha256::digest(&self.body);
        let expected = format!(
            "sha-256=:{}:",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        if header != expected {
            return Err(TapError::DigestMismatch);
        }
        Ok(())
    }

    fn component_value(&self, c: &CoveredComponent) -> Result<String, TapError> {
        match c.as_str() {
            "@method" => Ok(self.method.clone()),
            "@target-uri" => Ok(self.target_uri.clone()),
            "@authority" => Ok(self
                .target_uri
                .split("://")
                .nth(1)
                .and_then(|rest| rest.split('/').next())
                .unwrap_or_default()
                .to_string()),
            "@path" => Ok(self
                .target_uri
                .split("://")
                .nth(1)
                .and_then(|rest| rest.find('/').map(|i| rest[i..].to_string()))
                .unwrap_or_else(|| "/".to_string())),
            name => self
                .header(name)
                .map(|s| s.to_string())
                .ok_or_else(|| TapError::MissingComponent(name.to_string())),
        }
    }
}

/// Build the RFC 9421 signature base.
pub fn signature_base(
    msg: &HttpMessage,
    components: &[CoveredComponent],
    params: &SignatureParams,
) -> Result<String, TapError> {
    let mut lines = String::new();
    for c in components {
        lines.push_str(&format!(
            "\"{}\": {}\n",
            c.as_str(),
            msg.component_value(c)?
        ));
    }
    let list = components
        .iter()
        .map(|c| format!("\"{}\"", c.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    lines.push_str(&format!(
        "\"@signature-params\": ({}){}",
        list,
        params.serialize()
    ));
    Ok(lines)
}

pub struct TapSigner {
    keyid: String,
    keypair: DilithiumKeypair,
}

impl TapSigner {
    pub fn new(keyid: impl Into<String>, keypair: DilithiumKeypair) -> Self {
        Self {
            keyid: keyid.into(),
            keypair,
        }
    }

    pub fn keyid(&self) -> &str {
        &self.keyid
    }

    pub fn public_key(&self) -> &DilithiumPublicKey {
        &self.keypair.public_key
    }

    /// Sign a message, attaching `Signature-Input` and `Signature`.
    ///
    /// If the message carries a body, `Content-Digest` is computed and added to
    /// the covered components automatically — signing a request while leaving its
    /// body uncovered is a mistake that should not be possible to make by
    /// omission.
    pub fn sign(
        &self,
        msg: &mut HttpMessage,
        components: &[CoveredComponent],
        label: &str,
    ) -> Result<(), TapError> {
        let mut components = components.to_vec();
        if !msg.body.is_empty() {
            msg.compute_content_digest();
            let digest = CoveredComponent::new("content-digest");
            if !components.contains(&digest) {
                components.push(digest);
            }
        }

        let params = SignatureParams::new(&self.keyid);
        let base = signature_base(msg, &components, &params)?;
        let sig = self
            .keypair
            .sign(base.as_bytes())
            .map_err(|e| TapError::Crypto(e.to_string()))?;

        let list = components
            .iter()
            .map(|c| format!("\"{}\"", c.as_str()))
            .collect::<Vec<_>>()
            .join(" ");
        msg.set_header(
            "signature-input",
            format!("{label}=({list}){}", params.serialize()),
        );
        msg.set_header(
            "signature",
            format!(
                "{label}=:{}:",
                base64::engine::general_purpose::STANDARD.encode(sig.as_bytes())
            ),
        );
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct TapVerifier {
    keys: HashMap<String, DilithiumPublicKey>,
    /// Components every signature must cover, whatever else it covers.
    required: Vec<CoveredComponent>,
}

impl TapVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_key(&mut self, keyid: impl Into<String>, key: DilithiumPublicKey) {
        self.keys.insert(keyid.into(), key);
    }

    /// Require that a component appear in every signature's covered list.
    ///
    /// This is how the limit-attestation extension is enforced: a header that is
    /// present but not covered can be replaced in transit, so an uncovered
    /// attestation must be rejected rather than trusted.
    pub fn require_component(&mut self, c: CoveredComponent) {
        if !self.required.contains(&c) {
            self.required.push(c);
        }
    }

    fn parse_labelled(header: &str, label: &str) -> Option<String> {
        for part in header.split(',') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix(&format!("{label}=")) {
                return Some(rest.to_string());
            }
        }
        None
    }

    pub fn verify(&self, msg: &HttpMessage, label: &str) -> Result<SignatureParams, TapError> {
        let input = msg
            .header("signature-input")
            .ok_or_else(|| TapError::MissingSignatureInput(label.to_string()))?;
        let sig_header = msg
            .header("signature")
            .ok_or_else(|| TapError::MissingSignature(label.to_string()))?;

        let input_value = Self::parse_labelled(input, label)
            .ok_or_else(|| TapError::MissingSignatureInput(label.to_string()))?;
        let sig_value = Self::parse_labelled(sig_header, label)
            .ok_or_else(|| TapError::MissingSignature(label.to_string()))?;

        // ("@method" "@target-uri" ...);created=...
        let close = input_value
            .find(')')
            .ok_or_else(|| TapError::MalformedSignatureInput(input_value.clone()))?;
        let list = &input_value[1..close];
        let param_str = &input_value[close + 1..];

        let components: Vec<CoveredComponent> = list
            .split_whitespace()
            .map(|s| CoveredComponent::new(s.trim_matches('"')))
            .collect();

        for r in &self.required {
            if !components.contains(r) {
                return Err(TapError::ComponentNotCovered(r.as_str().to_string()));
            }
        }

        let params = SignatureParams::parse(param_str)?;

        let now = Utc::now().timestamp();
        if params.created > now + 60 {
            return Err(TapError::CreatedInFuture);
        }
        if let Some(exp) = params.expires {
            if now > exp {
                return Err(TapError::Expired);
            }
        }

        msg.verify_content_digest()?;

        let key = self
            .keys
            .get(&params.keyid)
            .ok_or_else(|| TapError::UnknownKeyId(params.keyid.clone()))?;

        let base = signature_base(msg, &components, &params)?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sig_value.trim().trim_matches(':'))
            .map_err(|_| TapError::BadSignature)?;

        byz_crypto::dilithium::verify(base.as_bytes(), &DilithiumSignature(raw), key)
            .map_err(|_| TapError::BadSignature)?;

        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> HttpMessage {
        HttpMessage::new("POST", "https://merchant.example/checkout")
            .with_header("host", "merchant.example")
            .with_body(br#"{"item":"widget"}"#.to_vec())
    }

    fn components() -> Vec<CoveredComponent> {
        vec!["@method".into(), "@target-uri".into(), "@authority".into()]
    }

    #[test]
    fn signature_base_matches_the_rfc_shape() {
        let msg = HttpMessage::new("POST", "https://example.com/foo")
            .with_header("content-type", "application/json");
        let params = SignatureParams {
            created: 1618884473,
            expires: None,
            keyid: "test-key".to_string(),
            alg: "ml-dsa-65".to_string(),
            nonce: None,
            tag: None,
        };
        let base = signature_base(
            &msg,
            &[
                "@method".into(),
                "@target-uri".into(),
                "content-type".into(),
            ],
            &params,
        )
        .unwrap();

        assert!(base.starts_with("\"@method\": POST\n"));
        assert!(base.contains("\"@target-uri\": https://example.com/foo\n"));
        assert!(base.contains("\"content-type\": application/json\n"));
        assert!(base.ends_with(
            "\"@signature-params\": (\"@method\" \"@target-uri\" \"content-type\");created=1618884473;keyid=\"test-key\";alg=\"ml-dsa-65\""
        ));
    }

    #[test]
    fn a_signed_request_verifies() {
        let kp = DilithiumKeypair::generate();
        let signer = TapSigner::new("agent-key-1", kp.clone());
        let mut msg = message();
        signer.sign(&mut msg, &components(), "sig1").unwrap();

        let mut v = TapVerifier::new();
        v.register_key("agent-key-1", kp.public_key.clone());
        assert!(v.verify(&msg, "sig1").is_ok());
    }

    #[test]
    fn signing_a_body_covers_it_automatically() {
        let kp = DilithiumKeypair::generate();
        let signer = TapSigner::new("k", kp.clone());
        let mut msg = message();
        signer.sign(&mut msg, &components(), "sig1").unwrap();

        assert!(msg.header("content-digest").is_some());
        assert!(msg
            .header("signature-input")
            .unwrap()
            .contains("content-digest"));
    }

    #[test]
    fn a_swapped_body_is_rejected() {
        let kp = DilithiumKeypair::generate();
        let signer = TapSigner::new("k", kp.clone());
        let mut msg = message();
        signer.sign(&mut msg, &components(), "sig1").unwrap();

        msg.body = br#"{"item":"something-else"}"#.to_vec();

        let mut v = TapVerifier::new();
        v.register_key("k", kp.public_key.clone());
        assert_eq!(v.verify(&msg, "sig1"), Err(TapError::DigestMismatch));
    }

    #[test]
    fn a_changed_method_is_rejected() {
        let kp = DilithiumKeypair::generate();
        let signer = TapSigner::new("k", kp.clone());
        let mut msg = message();
        signer.sign(&mut msg, &components(), "sig1").unwrap();
        msg.method = "DELETE".to_string();

        let mut v = TapVerifier::new();
        v.register_key("k", kp.public_key.clone());
        assert_eq!(v.verify(&msg, "sig1"), Err(TapError::BadSignature));
    }

    #[test]
    fn an_unknown_key_id_is_rejected() {
        let kp = DilithiumKeypair::generate();
        let signer = TapSigner::new("nobody-knows-me", kp.clone());
        let mut msg = message();
        signer.sign(&mut msg, &components(), "sig1").unwrap();

        let v = TapVerifier::new();
        assert!(matches!(
            v.verify(&msg, "sig1"),
            Err(TapError::UnknownKeyId(_))
        ));
    }

    #[test]
    fn a_signature_from_another_key_is_rejected() {
        let real = DilithiumKeypair::generate();
        let impostor = DilithiumKeypair::generate();
        let signer = TapSigner::new("agent-key-1", impostor);
        let mut msg = message();
        signer.sign(&mut msg, &components(), "sig1").unwrap();

        let mut v = TapVerifier::new();
        v.register_key("agent-key-1", real.public_key.clone());
        assert_eq!(v.verify(&msg, "sig1"), Err(TapError::BadSignature));
    }

    #[test]
    fn an_expired_signature_is_rejected() {
        let kp = DilithiumKeypair::generate();
        let mut msg = message();
        msg.compute_content_digest();

        let params = SignatureParams {
            created: Utc::now().timestamp() - 1_000,
            expires: Some(Utc::now().timestamp() - 500),
            keyid: "k".into(),
            alg: "ml-dsa-65".into(),
            nonce: None,
            tag: None,
        };
        let comps = components();
        let base = signature_base(&msg, &comps, &params).unwrap();
        let sig = kp.sign(base.as_bytes()).unwrap();
        let list = comps
            .iter()
            .map(|c| format!("\"{}\"", c.as_str()))
            .collect::<Vec<_>>()
            .join(" ");
        msg.set_header(
            "signature-input",
            format!("sig1=({list}){}", params.serialize()),
        );
        msg.set_header(
            "signature",
            format!(
                "sig1=:{}:",
                base64::engine::general_purpose::STANDARD.encode(sig.as_bytes())
            ),
        );

        let mut v = TapVerifier::new();
        v.register_key("k", kp.public_key.clone());
        assert_eq!(v.verify(&msg, "sig1"), Err(TapError::Expired));
    }

    #[test]
    fn a_required_component_left_uncovered_is_rejected() {
        let kp = DilithiumKeypair::generate();
        let signer = TapSigner::new("k", kp.clone());
        let mut msg = message().with_header("x-important", "value");
        // Sign without covering x-important.
        signer.sign(&mut msg, &components(), "sig1").unwrap();

        let mut v = TapVerifier::new();
        v.register_key("k", kp.public_key.clone());
        v.require_component(CoveredComponent::new("x-important"));

        assert_eq!(
            v.verify(&msg, "sig1"),
            Err(TapError::ComponentNotCovered("x-important".into()))
        );
    }

    #[test]
    fn shrinking_the_covered_list_after_signing_is_rejected() {
        // The covered list is itself signed, via the @signature-params line, so
        // an attacker cannot quietly drop a component from it.
        let kp = DilithiumKeypair::generate();
        let signer = TapSigner::new("k", kp.clone());
        let mut msg = message();
        signer.sign(&mut msg, &components(), "sig1").unwrap();

        let tampered = msg
            .header("signature-input")
            .unwrap()
            .replace("\"@authority\" ", "")
            .replace(" \"@authority\"", "");
        msg.set_header("signature-input", tampered);

        let mut v = TapVerifier::new();
        v.register_key("k", kp.public_key.clone());
        assert_eq!(v.verify(&msg, "sig1"), Err(TapError::BadSignature));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let msg = message().with_header("X-Mixed-Case", "v");
        assert_eq!(msg.header("x-mixed-case"), Some("v"));
    }
}
