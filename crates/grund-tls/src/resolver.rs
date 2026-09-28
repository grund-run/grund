use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

/// A certificate chain and its key, loaded and checked, with what readiness
/// and renewal need to know about it.
#[derive(Debug)]
pub struct Served {
    /// What rustls hands a client.
    pub key: Arc<CertifiedKey>,
    /// The leaf's notBefore.
    pub not_before: SystemTime,
    /// The leaf's notAfter.
    pub not_after: SystemTime,
    /// The leaf's DNS names (subjectAltName).
    pub names: Vec<String>,
}

impl Served {
    /// A PEM chain (leaf first) and a PEM private key, as a user supplies
    /// them in files. Refused when the key does not match the leaf.
    pub fn from_pem(chain_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<Self> {
        let key = PrivateKeyDer::from_pem_slice(key_pem).context("parse the key PEM")?;
        Self::build(chain_pem, key)
    }

    /// A PEM chain (leaf first) and a PKCS#8 DER private key, as the
    /// instance stores its own.
    pub fn from_pkcs8(chain_pem: &[u8], key_pkcs8_der: &[u8]) -> anyhow::Result<Self> {
        Self::build(
            chain_pem,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8_der.to_vec())),
        )
    }

    fn build(chain_pem: &[u8], key: PrivateKeyDer<'static>) -> anyhow::Result<Self> {
        let chain = CertificateDer::pem_slice_iter(chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .context("parse the certificate PEM")?;
        let leaf = chain
            .first()
            .context("the certificate PEM holds no certificate")?;
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf)
            .map_err(|error| anyhow::anyhow!("parse the certificate: {error}"))?;
        let validity = parsed.validity();
        let at = |seconds: i64| {
            SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap_or(0))
        };
        let not_before = at(validity.not_before.timestamp());
        let not_after = at(validity.not_after.timestamp());
        let names = parsed
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|extension| {
                extension
                    .value
                    .general_names
                    .iter()
                    .filter_map(|name| match name {
                        x509_parser::extensions::GeneralName::DNSName(dns) => {
                            Some(dns.to_ascii_lowercase())
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let key = CertifiedKey::from_der(chain, key, &crate::provider())
            .context("the certificate and its key do not belong together")?;
        Ok(Self {
            key: Arc::new(key),
            not_before,
            not_after,
            names,
        })
    }

    /// Whether the leaf names `name`, directly or by a one-label wildcard.
    pub fn covers(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.names.iter().any(|candidate| {
            candidate == &name
                || candidate.strip_prefix("*.").is_some_and(|suffix| {
                    name.split_once('.')
                        .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix)
                })
        })
    }
}

/// A certificate and key kept in files (GRUND_TLS_CERT_FILE and its key,
/// or a relay's), loaded into a [`Resolver`] and loaded again whenever
/// either file's modification time changes, so a renewal by another tool
/// is picked up without a restart.
#[derive(Debug, Clone)]
pub struct Files {
    cert: PathBuf,
    key: PathBuf,
    seen: Option<(SystemTime, SystemTime)>,
}

impl Files {
    /// Files not read yet.
    pub fn new(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            cert: cert.into(),
            key: key.into(),
            seen: None,
        }
    }

    /// Loads the files into `resolver` if they changed since the last
    /// successful load (or were never loaded). Returns whether it loaded. On
    /// an error the resolver keeps what it served.
    pub fn reload_if_changed(&mut self, resolver: &Resolver) -> anyhow::Result<bool> {
        let modified = |path: &Path| {
            std::fs::metadata(path)
                .and_then(|m| m.modified())
                .with_context(|| format!("read {}", path.display()))
        };
        let now = (modified(&self.cert)?, modified(&self.key)?);
        if self.seen == Some(now) {
            return Ok(false);
        }
        let chain =
            std::fs::read(&self.cert).with_context(|| format!("read {}", self.cert.display()))?;
        let key =
            std::fs::read(&self.key).with_context(|| format!("read {}", self.key.display()))?;
        let served = Served::from_pem(&chain, &key)
            .with_context(|| format!("{} and {}", self.cert.display(), self.key.display()))?;
        resolver.set(served);
        self.seen = Some(now);
        Ok(true)
    }
}

/// The certificate a TLS endpoint serves right now. Cheap to clone; clones
/// share one slot, so whoever renews calls [`Resolver::set`] and every
/// endpoint built on a clone serves the new certificate from its next
/// handshake. Serves nothing (the handshake fails) until the first set.
#[derive(Debug, Clone, Default)]
pub struct Resolver {
    current: Arc<RwLock<Option<Arc<Served>>>>,
}

impl Resolver {
    /// Serves `served` from the next handshake on.
    pub fn set(&self, served: Served) {
        *self.current.write().expect("resolver lock") = Some(Arc::new(served));
    }

    /// What is served now, if anything.
    pub fn current(&self) -> Option<Arc<Served>> {
        self.current.read().expect("resolver lock").clone()
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current().map(|served| served.key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(names: &[&str]) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        (params.self_signed(&key).unwrap().pem(), key.serialize_pem())
    }

    #[test]
    fn a_chain_and_its_key_load_with_their_names_and_validity() {
        let (chain, key) = certificate(&["grund.example.com"]);
        let served = Served::from_pem(chain.as_bytes(), key.as_bytes()).unwrap();
        assert_eq!(served.names, ["grund.example.com"]);
        assert!(served.not_before < served.not_after);
        assert!(served.covers("GRUND.example.com"));
        assert!(!served.covers("other.example.com"));
    }

    #[test]
    fn a_key_that_is_not_the_certificates_is_refused() {
        let (chain, _) = certificate(&["grund.example.com"]);
        let (_, other_key) = certificate(&["grund.example.com"]);
        let error = Served::from_pem(chain.as_bytes(), other_key.as_bytes()).unwrap_err();
        assert!(
            format!("{error:#}").contains("do not belong together"),
            "{error:#}"
        );
    }

    #[test]
    fn a_wildcard_covers_one_label_only() {
        let (chain, key) = certificate(&["*.example.com"]);
        let served = Served::from_pem(chain.as_bytes(), key.as_bytes()).unwrap();
        assert!(served.covers("grund.example.com"));
        assert!(!served.covers("a.grund.example.com"));
        assert!(!served.covers("example.com"));
    }

    #[test]
    fn files_are_loaded_again_only_when_they_change() {
        let dir = std::env::temp_dir().join(format!(
            "grund-tls-files-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
        let (chain, key) = certificate(&["a.example.com"]);
        std::fs::write(&cert_path, chain).unwrap();
        std::fs::write(&key_path, key).unwrap();
        let resolver = Resolver::default();
        let mut files = Files::new(&cert_path, &key_path);
        assert!(files.reload_if_changed(&resolver).unwrap());
        assert!(!files.reload_if_changed(&resolver).unwrap());
        assert_eq!(resolver.current().unwrap().names, ["a.example.com"]);

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&cert_path, "not a certificate").unwrap();
        assert!(files.reload_if_changed(&resolver).is_err());
        assert_eq!(resolver.current().unwrap().names, ["a.example.com"]);

        let (chain, key) = certificate(&["b.example.com"]);
        std::fs::write(&key_path, key).unwrap();
        std::fs::write(&cert_path, chain).unwrap();
        assert!(files.reload_if_changed(&resolver).unwrap());
        assert_eq!(resolver.current().unwrap().names, ["b.example.com"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn every_clone_of_a_resolver_serves_what_was_set_last() {
        let resolver = Resolver::default();
        let clone = resolver.clone();
        assert!(clone.current().is_none());
        let (chain, key) = certificate(&["a.example.com"]);
        resolver.set(Served::from_pem(chain.as_bytes(), key.as_bytes()).unwrap());
        assert_eq!(clone.current().unwrap().names, ["a.example.com"]);
        let (chain, key) = certificate(&["b.example.com"]);
        resolver.set(Served::from_pem(chain.as_bytes(), key.as_bytes()).unwrap());
        assert_eq!(clone.current().unwrap().names, ["b.example.com"]);
    }
}
