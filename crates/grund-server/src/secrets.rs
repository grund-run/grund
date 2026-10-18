//! The instance secret key, and `grund init`, which generates it.
//!
//! One 32-byte key per instance. Each use gets its own subkey,
//! `HMAC-SHA256(key, "grund/<purpose>/v1")`, so a digest made for one purpose
//! can never be replayed as another. Rotating the key signs everyone out
//! (CSRF tokens change) and resets rate-limit windows; it does not touch
//! passwords, which are not peppered: losing the key must not lock everyone out.

use std::{
    io::{Read, Write},
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
    /// error, so the operator knows what to fix. A key with fewer than 16
    /// distinct byte values ("0000…", "abab…") is refused as typed in:
    /// random keys have far more with overwhelming probability.
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
        anyhow::ensure!(
            config.dev_mode,
            "no production secret key: set GRUND_SECRET_KEY or GRUND_SECRET_KEY_FILE"
        );
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

    /// Read this host's privileged first-machine descriptor from standard input.
    #[arg(long)]
    pub local_machine_stdin: bool,
}

pub const SECRET_KEY_FILE: &str = "secret.key";
pub const POSTGRES_PASSWORD_FILE: &str = "postgres-password";
pub const LOCAL_MACHINE_FILE: &str = "local-machine.json";

/// Writes `secret.key` (owner-only: nothing but grund reads it) and
/// `postgres-password` into the data directory, keeping either if it exists.
///
/// The password file is world-readable within the volume because the
/// postgres image reads it as its own user after dropping root; owner-only
/// would stop the database from initialising. The volume is mounted only into
/// grund and postgres.
pub fn init(args: &InitArgs) -> anyhow::Result<()> {
    let descriptor = if args.local_machine_stdin {
        Some(read_local_machine(std::io::stdin().lock())?)
    } else {
        None
    };
    std::fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("create GRUND_DATA_DIR {}", args.data_dir.display()))?;
    if let Some(descriptor) = &descriptor {
        persist_local_machine(&args.data_dir, descriptor)?;
    }

    write_new(
        &args.data_dir.join(SECRET_KEY_FILE),
        0o600,
        &format!("{}\n", SecretKey::generate().to_hex()),
    )?;

    let mut password = [0u8; 24];
    getrandom::fill(&mut password).expect("the operating system provides randomness");
    write_new(
        &args.data_dir.join(POSTGRES_PASSWORD_FILE),
        0o644,
        &format!("{}\n", hex::encode(password)),
    )?;
    Ok(())
}

fn read_local_machine(
    reader: impl Read,
) -> anyhow::Result<grund_domain::machine::LocalMachineBootstrap> {
    let mut bytes = Vec::new();
    reader
        .take(65537)
        .read_to_end(&mut bytes)
        .context("read local machine descriptor from stdin")?;
    anyhow::ensure!(
        bytes.len() <= 65536,
        "local machine descriptor exceeds 65536 bytes"
    );
    crate::local_machine::decode(&bytes)
}

fn persist_local_machine(
    dir: &Path,
    descriptor: &grund_domain::machine::LocalMachineBootstrap,
) -> anyhow::Result<()> {
    let path = dir.join(LOCAL_MACHINE_FILE);
    if path.try_exists()? {
        anyhow::ensure!(
            crate::local_machine::load(&path)? == *descriptor,
            "local-machine.json already describes another identity; refusing replacement"
        );
        return Ok(());
    }
    let temporary = dir.join(format!(".local-machine-{}.json", uuid::Uuid::now_v7()));
    let result = (|| -> anyhow::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(descriptor)?)?;
        file.sync_all()?;
        match std::fs::hard_link(&temporary, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                anyhow::ensure!(
                    crate::local_machine::load(&path)? == *descriptor,
                    "local-machine.json already describes another identity; refusing replacement"
                );
            }
            Err(error) => return Err(error.into()),
        }
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    let removed = std::fs::remove_file(&temporary);
    result?;
    removed?;
    Ok(())
}

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
    fn loading_a_missing_production_secret_never_generates_a_throwaway_key() {
        #[derive(clap::Parser)]
        struct Harness {
            #[command(flatten)]
            config: ServeConfig,
        }
        use clap::Parser;
        let config =
            Harness::try_parse_from(["grund", "--database-url", "postgres://localhost/grund"])
                .unwrap()
                .config;
        assert!(SecretKey::load(&config).is_err());
    }

    #[test]
    fn local_init_reuses_one_descriptor_and_refuses_identity_replacement() {
        let dir = std::env::temp_dir().join(format!("grund-local-init-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        let descriptor = grund_domain::machine::LocalMachineBootstrap {
            machine_id: uuid::Uuid::now_v7(),
            name: grund_config::names::MachineName::parse("first-host").unwrap(),
            key: grund_domain::machine::MachineKey::from_bytes(key.verifying_key().as_bytes())
                .unwrap(),
            facts: grund_domain::machine::MachineFacts::default(),
        };
        persist_local_machine(&dir, &descriptor).unwrap();
        persist_local_machine(&dir, &descriptor).unwrap();
        let mut replacement = descriptor.clone();
        replacement.machine_id = uuid::Uuid::now_v7();
        assert!(persist_local_machine(&dir, &replacement).is_err());
        assert_eq!(
            crate::local_machine::load(&dir.join(LOCAL_MACHINE_FILE)).unwrap(),
            descriptor
        );
        let mode = std::fs::metadata(dir.join(LOCAL_MACHINE_FILE))
            .unwrap()
            .permissions();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn malformed_or_oversized_local_descriptors_never_become_configuration() {
        assert!(read_local_machine(std::io::Cursor::new(vec![b' '; 65537])).is_err());
        assert!(
            read_local_machine(std::io::Cursor::new(br#"{"machine_id":"not-an-id"}"#)).is_err()
        );
    }

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
            local_machine_stdin: false,
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
