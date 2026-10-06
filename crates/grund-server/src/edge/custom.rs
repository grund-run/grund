//! Custom domains at the edge (grund-docs design/traffic.md §5.3): the
//! certificate and key of every custom domain the route table carries come
//! from the instance (`EdgeService/GetDomainCertificate`), which made the
//! key and holds it sealed, so every edge node serves the same certificate.
//! Port 80 answers their HTTP-01 challenges with the key authorization the
//! instance gives for that name and token (`EdgeService/GetHttpChallenge`),
//! asked when the validator comes.
//!
//! What is kept on disk, under `names/<name>/custom/`, is the chain and the
//! key sealed with ChaCha20-Poly1305 under a key derived from the edge's own
//! Ed25519 seed (0600), so an edge restarted while its instance does not
//! answer still serves its custom domains (fail-static, §6.7), and the file
//! alone, without the edge's key beside it, opens nothing.

use std::path::{Path, PathBuf};

use grund_proto::grund::edge::v1::{
    GetDomainCertificateRequest, GetDomainCertificateResponse, GetHttpChallengeRequest,
    GetHttpChallengeResponse,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::relay_certificate::{Instance, read_optional, refused_with, write_private};

/// A custom domain's certificate as the instance hands it over.
pub struct Delivered {
    pub chain_pem: String,
    pub key_pkcs8: Vec<u8>,
    pub version: i64,
}

impl std::fmt::Debug for Delivered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivered")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Asks the instance for the certificate of the custom domain `name`;
/// `None` while none is issued.
pub async fn fetch(instance: &Instance, name: &str) -> anyhow::Result<Option<Delivered>> {
    match instance
        .edge_call::<_, GetDomainCertificateResponse>(
            "GetDomainCertificate",
            &GetDomainCertificateRequest {
                name: name.to_string(),
                ..Default::default()
            },
        )
        .await
    {
        Ok(answer) => Ok(Some(Delivered {
            chain_pem: answer.chain_pem,
            key_pkcs8: answer.key_pkcs8,
            version: answer.version,
        })),
        Err(error) if refused_with(&error, "not_found") => Ok(None),
        Err(error) => Err(error),
    }
}

/// Asks the instance for the HTTP-01 answer to `token` for `name`.
pub async fn http01(
    instance: &Instance,
    name: &str,
    token: &str,
) -> anyhow::Result<Option<String>> {
    match instance
        .edge_call::<_, GetHttpChallengeResponse>(
            "GetHttpChallenge",
            &GetHttpChallengeRequest {
                name: name.to_string(),
                token: token.to_string(),
                ..Default::default()
            },
        )
        .await
    {
        Ok(answer) => Ok(Some(answer.key_authorization)),
        Err(error) if refused_with(&error, "not_found") => Ok(None),
        Err(error) => Err(error),
    }
}

/// The custom domains' certificates kept on the edge's disk.
#[derive(Clone)]
pub struct Kept {
    data_dir: PathBuf,
    seal_key: [u8; 32],
}

fn aad(name: &str) -> String {
    format!("grund/edge/custom-domain-key/{name}")
}

impl Kept {
    /// Under `data_dir`, sealed with a key derived from the edge's seed.
    pub fn new(data_dir: &Path, edge_seed: &[u8; 32]) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(edge_seed).expect("HMAC takes any key length");
        mac.update(b"grund/edge/custom-domain-keys/v1");
        Self {
            data_dir: data_dir.to_path_buf(),
            seal_key: mac.finalize().into_bytes().into(),
        }
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.data_dir.join("names").join(name).join("custom")
    }

    /// What is kept for `name`, if anything opens.
    pub fn load(&self, name: &str) -> anyhow::Result<Option<Delivered>> {
        let dir = self.dir(name);
        let (Some(chain), Some(sealed), Some(version)) = (
            read_optional(&dir.join("chain.pem"))?,
            read_optional(&dir.join("key.sealed"))?,
            read_optional(&dir.join("version"))?,
        ) else {
            return Ok(None);
        };
        let key =
            crate::certificates::unseal(&self.seal_key, &aad(name), &sealed).ok_or_else(|| {
                anyhow::anyhow!("the kept key of {name} does not open with this edge's key")
            })?;
        Ok(Some(Delivered {
            chain_pem: String::from_utf8(chain)?,
            key_pkcs8: key,
            version: String::from_utf8(version)?.trim().parse()?,
        }))
    }

    /// Keeps what the instance delivered for `name`.
    pub fn keep(&self, name: &str, delivered: &Delivered) -> anyhow::Result<()> {
        let dir = self.dir(name);
        let sealed = crate::certificates::seal(&self.seal_key, &aad(name), &delivered.key_pkcs8);
        write_private(&dir.join("key.sealed"), &sealed)?;
        write_private(&dir.join("chain.pem"), delivered.chain_pem.as_bytes())?;
        write_private(
            &dir.join("version"),
            delivered.version.to_string().as_bytes(),
        )?;
        Ok(())
    }

    /// Forgets `name`: it is no longer bound.
    pub fn forget(&self, name: &str) {
        let _ = std::fs::remove_dir_all(self.dir(name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kept_key_opens_only_with_the_edge_seed_that_sealed_it() {
        let dir = std::env::temp_dir().join(format!("grund-edge-custom-{}", uuid::Uuid::now_v7()));
        let kept = Kept::new(&dir, &[7; 32]);
        let delivered = Delivered {
            chain_pem: "chain".into(),
            key_pkcs8: b"secret key".to_vec(),
            version: 3,
        };
        kept.keep("app.example.com", &delivered).unwrap();
        let sealed = std::fs::read(dir.join("names/app.example.com/custom/key.sealed")).unwrap();
        assert!(!sealed.windows(10).any(|w| w == b"secret key"));
        let loaded = kept.load("app.example.com").unwrap().unwrap();
        assert_eq!(loaded.key_pkcs8, b"secret key");
        assert_eq!(loaded.version, 3);
        assert!(Kept::new(&dir, &[8; 32]).load("app.example.com").is_err());
        kept.forget("app.example.com");
        assert!(kept.load("app.example.com").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
