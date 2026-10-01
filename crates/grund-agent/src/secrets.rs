//! The agent's cache of its replicas' secret values (grund-docs
//! design/apps.md §6.5, §7.1): fetched from the instance with
//! GetReplicaSecrets, kept on disk so a reboot during an instance outage
//! can start its apps again, and encrypted with a key derived from the
//! machine key (HKDF-SHA256, info `grund-secrets-cache-v1`, AES-256-GCM).
//!
//! That protects a copy of the data directory (a backup, a disk image), not
//! root on the running machine, which can read any container's environment
//! anyway. Values are never logged.

use std::{collections::BTreeMap, path::Path};

use anyhow::Context;
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    hkdf,
};
use serde::{Deserialize, Serialize};

/// The cache file, under the agent's data directory.
pub const CACHE_FILE: &str = "secrets.cache";

const INFO: &[u8] = b"grund-secrets-cache-v1";

/// One secret value of one replica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cached {
    pub name: String,
    pub version: u32,
    #[serde(with = "hex_bytes")]
    pub value: Vec<u8>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(text).map_err(serde::de::Error::custom)
    }
}

/// Every cached replica's values, by replica id.
pub type Values = BTreeMap<String, Vec<Cached>>;

struct Length;

impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        32
    }
}

/// The cache's key, from the machine key's seed.
pub fn key(machine_seed: &[u8; 32]) -> LessSafeKey {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(machine_seed);
    let mut bytes = [0u8; 32];
    prk.expand(&[INFO], Length)
        .and_then(|okm| okm.fill(&mut bytes))
        .expect("HKDF-SHA256 gives 32 bytes");
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &bytes).expect("a 32-byte AES key"))
}

/// The cache on disk, or empty when there is none or it does not open
/// (another machine key, a damaged file): the values are fetched again.
pub fn load(data_dir: &Path, key: &LessSafeKey) -> Values {
    let Ok(sealed) = std::fs::read(data_dir.join(CACHE_FILE)) else {
        return Values::new();
    };
    if sealed.len() < 12 + 16 {
        return Values::new();
    }
    let (nonce, rest) = sealed.split_at(12);
    let mut buffer = rest.to_vec();
    let Ok(nonce) = Nonce::try_assume_unique_for_key(nonce) else {
        return Values::new();
    };
    match key.open_in_place(nonce, Aad::from(INFO), &mut buffer) {
        Ok(plain) => serde_json::from_slice(plain).unwrap_or_default(),
        Err(_) => Values::new(),
    }
}

/// Writes the cache, under a temporary name renamed into place, 0600.
pub fn store(data_dir: &Path, key: &LessSafeKey, values: &Values) -> anyhow::Result<()> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).context("the system's random source")?;
    let mut sealed = serde_json::to_vec(values)?;
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(INFO),
        &mut sealed,
    )
    .map_err(|_| anyhow::anyhow!("seal the secrets cache"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealed);
    let temporary = data_dir.join(format!(".{CACHE_FILE}.{}", std::process::id()));
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&out)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, data_dir.join(CACHE_FILE)).context("write the secrets cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cache_opens_with_its_machine_key_and_not_another() {
        let dir = std::env::temp_dir().join(format!("grund-secrets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mine = key(&[1; 32]);
        let values = Values::from([(
            "replica".to_string(),
            vec![Cached {
                name: "db-password".into(),
                version: 3,
                value: b"hunter2".to_vec(),
            }],
        )]);
        store(&dir, &mine, &values).unwrap();
        let raw = std::fs::read(dir.join(CACHE_FILE)).unwrap();
        assert!(!raw.windows(7).any(|w| w == b"hunter2"));
        assert!(!raw.windows(11).any(|w| w == b"db-password"));
        assert_eq!(load(&dir, &mine), values);
        assert!(load(&dir, &key(&[2; 32])).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
