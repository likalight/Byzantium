//! The issuer signing key, and its lifetime.
//!
//! Every limit attestation, PassToken and delegation this gateway signs is
//! verified against one public key. Generating that key at startup — which is
//! what this service used to do — means every credential it has ever issued
//! becomes unverifiable the moment the process restarts. Nothing else in the
//! system matters if that happens.
//!
//! # Rotation, and why retired keys are kept
//!
//! Attestations are short-lived but not instantaneous. When a key is rotated,
//! credentials signed by the previous one are still in flight, so the old public
//! key stays in the verification set until everything it signed has expired.
//! Dropping it immediately would invalidate live credentials, which is the same
//! failure as regenerating on restart, just rarer and harder to diagnose.
//!
//! # On storing a private key in a file
//!
//! This is the minimum viable improvement over losing the key entirely, not the
//! production answer. In production the key belongs in a KMS or an HSM, and this
//! type is deliberately shaped so that swapping the backing store touches only
//! [`IssuerKeystore::load_or_create`]. The file is written with owner-only
//! permissions where the platform supports it.

use byz_common::{ByzResult, ByzantiumError};
use byz_crypto::{DilithiumKeypair, DilithiumPublicKey, DilithiumSecretKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKey {
    public_key_hex: String,
    secret_key_hex: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RetiredKey {
    public_key_hex: String,
    retired_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyFile {
    active: StoredKey,
    #[serde(default)]
    retired: Vec<RetiredKey>,
}

/// One public key as a relying party sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedKey {
    /// Key identifier: the first 16 hex characters of the public key.
    pub kid: String,
    pub public_key_hex: String,
    pub alg: String,
    pub status: String,
    pub since: DateTime<Utc>,
}

/// Debug is implemented by hand rather than derived: this type holds a private
/// key, and a derived impl would place it in any log line that formats the
/// surrounding state.
impl std::fmt::Debug for IssuerKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerKeystore")
            .field("kid", &self.active_kid())
            .field("persistent", &self.is_persistent())
            .field("retired", &self.retired.len())
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

pub struct IssuerKeystore {
    path: Option<PathBuf>,
    active: DilithiumKeypair,
    active_since: DateTime<Utc>,
    retired: Vec<RetiredKey>,
}

/// Short, stable identifier for a public key.
pub fn key_id(public_key_hex: &str) -> String {
    public_key_hex.chars().take(16).collect()
}

impl IssuerKeystore {
    /// Load the signing key from `path`, creating one on first run.
    ///
    /// A missing file is normal on a first start. A file that exists but cannot
    /// be parsed is not: that is a corrupted or truncated key, and silently
    /// generating a replacement would invalidate every outstanding credential
    /// without anyone noticing. It fails loudly instead.
    pub fn load_or_create(path: impl AsRef<Path>) -> ByzResult<Self> {
        let path = path.as_ref().to_path_buf();

        if path.exists() {
            let raw = std::fs::read_to_string(&path).map_err(|e| {
                ByzantiumError::Crypto(format!(
                    "cannot read signing key at {}: {e}",
                    path.display()
                ))
            })?;
            let file: KeyFile = serde_json::from_str(&raw).map_err(|e| {
                ByzantiumError::Crypto(format!(
                    "signing key at {} is present but unreadable ({e}). Refusing to generate a \
                     replacement — that would invalidate every credential already issued. Restore \
                     the file from backup, or move it aside deliberately to start a new key.",
                    path.display()
                ))
            })?;

            let keypair = DilithiumKeypair::from_parts(
                DilithiumPublicKey::from_hex(&file.active.public_key_hex)?,
                DilithiumSecretKey::from_hex(&file.active.secret_key_hex)?,
            );
            return Ok(Self {
                path: Some(path),
                active: keypair,
                active_since: file.active.created_at,
                retired: file.retired,
            });
        }

        let store = Self {
            path: Some(path),
            active: DilithiumKeypair::generate(),
            active_since: Utc::now(),
            retired: Vec::new(),
        };
        store.persist()?;
        Ok(store)
    }

    /// An ephemeral keystore for tests and throwaway local runs.
    ///
    /// Named so that choosing it is visible in a stack trace — this is the
    /// behaviour that used to be the default and caused the problem.
    pub fn ephemeral() -> Self {
        Self {
            path: None,
            active: DilithiumKeypair::generate(),
            active_since: Utc::now(),
            retired: Vec::new(),
        }
    }

    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    pub fn active(&self) -> &DilithiumKeypair {
        &self.active
    }

    pub fn active_kid(&self) -> String {
        key_id(&self.active.public_key.to_hex())
    }

    /// Replace the active key, keeping the previous public key for verification
    /// until credentials signed by it have expired.
    pub fn rotate(&mut self) -> ByzResult<()> {
        let previous = RetiredKey {
            public_key_hex: self.active.public_key.to_hex(),
            retired_at: Utc::now(),
        };
        self.retired.push(previous);
        self.active = DilithiumKeypair::generate();
        self.active_since = Utc::now();
        self.persist()
    }

    /// Drop retired keys older than `max_age`, which is safe once every
    /// credential they signed has expired.
    pub fn prune_retired(&mut self, max_age: chrono::Duration) -> ByzResult<usize> {
        let cutoff = Utc::now() - max_age;
        let before = self.retired.len();
        self.retired.retain(|k| k.retired_at >= cutoff);
        let dropped = before - self.retired.len();
        if dropped > 0 {
            self.persist()?;
        }
        Ok(dropped)
    }

    /// Whether a public key presented on a credential is one this issuer signs
    /// or recently signed with.
    pub fn accepts(&self, public_key_hex: &str) -> bool {
        self.active.public_key.to_hex() == public_key_hex
            || self
                .retired
                .iter()
                .any(|k| k.public_key_hex == public_key_hex)
    }

    /// Everything a relying party needs to verify our signatures.
    pub fn published(&self) -> Vec<PublishedKey> {
        let mut out = vec![PublishedKey {
            kid: self.active_kid(),
            public_key_hex: self.active.public_key.to_hex(),
            alg: "ml-dsa-65".to_string(),
            status: "active".to_string(),
            since: self.active_since,
        }];
        out.extend(self.retired.iter().map(|k| PublishedKey {
            kid: key_id(&k.public_key_hex),
            public_key_hex: k.public_key_hex.clone(),
            alg: "ml-dsa-65".to_string(),
            status: "retired".to_string(),
            since: k.retired_at,
        }));
        out
    }

    fn persist(&self) -> ByzResult<()> {
        let Some(ref path) = self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ByzantiumError::Crypto(format!("cannot create {}: {e}", parent.display()))
                })?;
            }
        }

        let file = KeyFile {
            active: StoredKey {
                public_key_hex: self.active.public_key.to_hex(),
                secret_key_hex: self.active.secret_key().to_hex(),
                created_at: self.active_since,
            },
            retired: self.retired.clone(),
        };
        let json = serde_json::to_string_pretty(&file)?;
        std::fs::write(path, json).map_err(|e| {
            ByzantiumError::Crypto(format!(
                "cannot write signing key to {}: {e}",
                path.display()
            ))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "byz-keystore-test-{}-{}",
            name,
            uuid::Uuid::new_v4()
        ));
        p
    }

    #[test]
    fn a_key_survives_a_restart() {
        // The whole point. A credential signed before a restart must still
        // verify after one.
        let path = temp_path("restart");
        let first = IssuerKeystore::load_or_create(&path).unwrap();
        let msg = b"attestation issued before the restart";
        let sig = first.active().sign(msg).unwrap();
        let pk_before = first.active().public_key.to_hex();
        drop(first);

        let second = IssuerKeystore::load_or_create(&path).unwrap();
        assert_eq!(second.active().public_key.to_hex(), pk_before);
        assert!(byz_crypto::dilithium::verify(msg, &sig, &second.active().public_key).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_corrupt_key_file_fails_loudly_rather_than_regenerating() {
        // Silently generating a replacement would invalidate every outstanding
        // credential with no signal that it had happened.
        let path = temp_path("corrupt");
        std::fs::write(&path, "{ this is not valid json").unwrap();
        let err = IssuerKeystore::load_or_create(&path).unwrap_err();
        assert!(err
            .to_string()
            .contains("Refusing to generate a replacement"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rotation_keeps_the_old_key_verifiable() {
        let path = temp_path("rotate");
        let mut ks = IssuerKeystore::load_or_create(&path).unwrap();

        let old_pk = ks.active().public_key.to_hex();
        let msg = b"signed just before rotation";
        let sig = ks.active().sign(msg).unwrap();

        ks.rotate().unwrap();

        assert_ne!(
            ks.active().public_key.to_hex(),
            old_pk,
            "rotation produced the same key"
        );
        assert!(
            ks.accepts(&old_pk),
            "the retired key was dropped while credentials were live"
        );
        assert!(ks.accepts(&ks.active().public_key.to_hex()));

        let retired = DilithiumPublicKey::from_hex(&old_pk).unwrap();
        assert!(byz_crypto::dilithium::verify(msg, &sig, &retired).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rotation_persists_across_a_restart() {
        let path = temp_path("rotate-persist");
        let mut ks = IssuerKeystore::load_or_create(&path).unwrap();
        let original = ks.active().public_key.to_hex();
        ks.rotate().unwrap();
        let rotated = ks.active().public_key.to_hex();
        drop(ks);

        let reloaded = IssuerKeystore::load_or_create(&path).unwrap();
        assert_eq!(reloaded.active().public_key.to_hex(), rotated);
        assert!(reloaded.accepts(&original), "retired key lost on restart");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pruning_drops_only_keys_past_the_overlap() {
        let path = temp_path("prune");
        let mut ks = IssuerKeystore::load_or_create(&path).unwrap();
        ks.rotate().unwrap();
        assert_eq!(ks.published().len(), 2);

        // Nothing is old enough yet.
        assert_eq!(ks.prune_retired(chrono::Duration::days(1)).unwrap(), 0);
        // Everything is, at a zero overlap.
        assert_eq!(ks.prune_retired(chrono::Duration::zero()).unwrap(), 1);
        assert_eq!(ks.published().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unknown_key_is_not_accepted() {
        let ks = IssuerKeystore::ephemeral();
        let stranger = DilithiumKeypair::generate();
        assert!(!ks.accepts(&stranger.public_key.to_hex()));
    }

    #[test]
    fn the_published_set_describes_the_active_key_first() {
        let mut ks = IssuerKeystore::ephemeral();
        ks.active = DilithiumKeypair::generate();
        let published = ks.published();
        assert_eq!(published[0].status, "active");
        assert_eq!(published[0].kid, ks.active_kid());
        assert_eq!(published[0].alg, "ml-dsa-65");
    }

    #[test]
    fn an_ephemeral_store_reports_itself_as_such() {
        assert!(!IssuerKeystore::ephemeral().is_persistent());
    }
}
