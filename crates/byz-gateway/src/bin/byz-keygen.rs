//! Generate an issuer signing key for provisioning.
//!
//! In production the gateway must not create its own key. Pods start with a
//! read-only root filesystem, they are replicated, and a key each pod invents
//! for itself would differ between replicas and vanish on restart — which is
//! the failure this whole mechanism exists to prevent.
//!
//! So the key is generated once, by a person, and delivered to every replica as
//! a Secret. This binary is that step.
//!
//! ```text
//! cargo run -p byz-gateway --bin byz-keygen -- --out signing-key.json
//! kubectl create secret generic byzantium-signing-key \
//!   --from-file=signing-key.json=./signing-key.json
//! ```
//!
//! The file contains a private key. Treat it the way you would treat one:
//! generate it on a trusted machine, put it straight into your secret manager,
//! and delete the local copy.

use byz_crypto::DilithiumKeypair;
use serde_json::json;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!(
            "byz-keygen — generate an issuer signing key\n\n\
             USAGE:\n    byz-keygen [--out <path>]\n\n\
             Writes a keyfile in the format `BYZ_SIGNING_KEY_PATH` expects.\n\
             Prints the public key and key id so you can confirm what was\n\
             deployed against GET /v1/issuer-keys.\n\n\
             Without --out the keyfile goes to stdout, for piping into a secret\n\
             manager without ever touching disk."
        );
        std::process::exit(0);
    }

    let out: Option<PathBuf> = args
        .iter()
        .position(|a| a == "--out" || a == "-o")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);

    let keypair = DilithiumKeypair::generate();
    let public_key_hex = keypair.public_key.to_hex();
    let kid: String = public_key_hex.chars().take(16).collect();

    let keyfile = json!({
        "active": {
            "public_key_hex": public_key_hex,
            "secret_key_hex": keypair.secret_key().to_hex(),
            "created_at": chrono::Utc::now(),
        },
        "retired": [],
    });
    let serialised = serde_json::to_string_pretty(&keyfile).expect("keyfile is serialisable");

    match out {
        Some(path) => {
            if path.exists() {
                // Overwriting an existing key would invalidate every credential
                // signed with it, which is not something to do by accident.
                eprintln!(
                    "error: {} already exists. Refusing to overwrite — that would \
                     invalidate every credential signed with the existing key. Move it \
                     aside deliberately if you intend to rotate.",
                    path.display()
                );
                std::process::exit(1);
            }
            if let Err(e) = std::fs::write(&path, &serialised) {
                eprintln!("error: could not write {}: {e}", path.display());
                std::process::exit(1);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            eprintln!("wrote {}", path.display());
        }
        None => println!("{serialised}"),
    }

    eprintln!("key id     {kid}");
    eprintln!("algorithm  ml-dsa-65 (Dilithium3)");
    eprintln!();
    eprintln!("Set BYZ_SIGNING_KEY_PATH to this file on every replica. They must all");
    eprintln!("use the same key, or a credential issued by one will not verify at another.");
}
