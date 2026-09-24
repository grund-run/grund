//! The instance secret key, and `grund init`, which generates it.
//!
//! One 32-byte key per instance. Each use gets its own subkey,
//! `HMAC-SHA256(key, "grund/<purpose>/v1")`, so a digest made for one purpose
//! can never be replayed as another. Rotating the key signs everyone out
//! (CSRF tokens change) and resets rate-limit windows; it does not touch
//! passwords, which are not peppered (see docs/design/auth.md).

use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::Context;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::ServeConfig;

#[derive(Clone)]
pub struct SecretKey([u8; 32]);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl SecretKey {
    /// Parses 64 hex characters. `source` names the variable or file in the
    /// error, so the operator knows what to fix.
    pub fn from_hex(text: &str, source: &str) -> anyhow::Result<Self> {
        let text = text.trim();
        let bytes = hex::decode(text)
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{source} must be 64 hex characters (32 random bytes); generate one with \
                 `grund init` or `openssl rand -hex 32`"
                )
            })?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        // A typed-in key ("0000…", "abab…") is not a secret. Random keys have
        // at least 20 distinct byte values with overwhelming probability.
        let distinct = key.iter().collect::<std::collections::BTreeSet<_>>().len();
        anyhow::ensure!(
            distinct >= 16,
            "{source} does not look random; generate one with `grund init` or `openssl rand -hex 32`"
        );
        Ok(Self(key))
    }

    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("the operating system provides randomness");
        Self(key)
    }

    /// The key `serve` runs with: GRUND_SECRET_KEY, else GRUND_SECRET_KEY_FILE,
    /// else (dev mode only, enforced by validation) a throwaway one.
    pub fn load(config: &ServeConfig) -> anyhow::Result<Self> {
        if let Some(text) = &config.secret_key {
            return Self::from_hex(text, "GRUND_SECRET_KEY");
        }
        if let Some(path) = &config.secret_key_file {
            let text = std::fs::read_to_string(path).with_context(|| {
                format!(
                    "read GRUND_SECRET_KEY_FILE {}; run `grund init` to create it",
                    path.display()
                )
            })?;
            return Self::from_hex(&text, "GRUND_SECRET_KEY_FILE");
        }
        tracing::warn!(
            "no secret key configured; using a throwaway one (GRUND_DEV_MODE). Every restart \
             signs everyone out"
        );
        Ok(Self::generate())
    }

    /// A purpose-bound subkey. Purposes are fixed strings in code.
    pub fn derive(&self, purpose: &str) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(b"grund/");
        mac.update(purpose.as_bytes());
        mac.update(b"/v1");
        mac.finalize().into_bytes().into()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// `grund init`: writes the files a fresh instance needs, keeping any that
/// already exist, and changes nothing else. Safe to run on every start, which
/// is what compose.yaml does.
#[derive(Clone, Debug, clap::Args)]
pub struct InitArgs {
    /// Where to write the generated files.
    #[arg(long, env = "GRUND_DATA_DIR", default_value = "/var/lib/grund")]
    pub data_dir: PathBuf,
}

pub const SECRET_KEY_FILE: &str = "secret.key";
pub const POSTGRES_PASSWORD_FILE: &str = "postgres-password";

pub fn init(args: &InitArgs) -> anyhow::Result<()> {
    std::fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("create GRUND_DATA_DIR {}", args.data_dir.display()))?;

    // Owner-only: nothing but grund reads the instance key.
    write_new(
        &args.data_dir.join(SECRET_KEY_FILE),
        0o600,
        &format!("{}\n", SecretKey::generate().to_hex()),
    )?;

    // World-readable within the volume: the postgres image reads its password
    // file as its own user after dropping root, so owner-only would stop the
    // database from initialising. The volume is mounted only into grund and
    // postgres, and the database is not published outside the compose network.
    let mut password = [0u8; 24];
    getrandom::fill(&mut password).expect("the operating system provides randomness");
    write_new(
        &args.data_dir.join(POSTGRES_PASSWORD_FILE),
        0o644,
        &format!("{}\n", hex::encode(password)),
    )?;
    Ok(())
}

/// Creates `path` with `contents`, or leaves an existing file untouched.
fn write_new(path: &Path, mode: u32, contents: &str) -> anyhow::Result<()> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(contents.as_bytes())
                .and_then(|()| file.sync_all())
                .with_context(|| format!("write {}", path.display()))?;
            tracing::info!(path = %path.display(), "generated");
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            tracing::info!(path = %path.display(), "exists; kept");
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("create {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_round_trips_through_its_hex_form() {
        let key = SecretKey::generate();
        let parsed = SecretKey::from_hex(&key.to_hex(), "test").unwrap();
        assert_eq!(parsed.0, key.0);
    }

    #[test]
    fn a_short_or_typed_in_key_is_refused_naming_its_source() {
        for text in ["abc", &"0".repeat(64), &"ab".repeat(32), "change-me"] {
            let error = SecretKey::from_hex(text, "GRUND_SECRET_KEY")
                .unwrap_err()
                .to_string();
            assert!(error.contains("GRUND_SECRET_KEY"), "{text}: {error}");
        }
    }

    #[test]
    fn subkeys_differ_by_purpose_and_are_stable() {
        let key = SecretKey::generate();
        assert_ne!(key.derive("csrf"), key.derive("throttle"));
        assert_eq!(key.derive("csrf"), key.derive("csrf"));
    }

    #[test]
    fn init_creates_the_files_once_and_never_overwrites_them() {
        let dir = std::env::temp_dir().join(format!("grund-init-{}", uuid::Uuid::now_v7()));
        let args = InitArgs {
            data_dir: dir.clone(),
        };
        init(&args).unwrap();
        let key = std::fs::read_to_string(dir.join(SECRET_KEY_FILE)).unwrap();
        SecretKey::from_hex(&key, "file").unwrap();
        init(&args).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join(SECRET_KEY_FILE)).unwrap(),
            key
        );
        let mode = std::fs::metadata(dir.join(SECRET_KEY_FILE))
            .unwrap()
            .permissions();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
