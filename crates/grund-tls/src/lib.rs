//! Where grund's TLS terminates (grund-docs design/traffic.md §5.1).
//!
//! The rule is that the instance drives every ACME order, the private key is
//! made where TLS terminates, and only a CSR travels. This crate is the
//! terminating side. It has no ACME client and no database, so the instance's
//! own HTTPS listener, the relay and later the gate and the edge all use it
//! the same way:
//!
//! - [`KeyAndCsr::generate`] makes a key and a CSR for the names a terminator
//!   serves. The key stays with the terminator; the CSR goes to the instance.
//! - [`Resolver`] serves the current certificate, and is replaced in place
//!   when a renewal lands, so connections open before and after both work.
//! - [`Files`] loads a certificate and key from files into a resolver, and
//!   again when they change, for a terminator given its certificate.
//! - [`server_config`] builds a rustls configuration around a resolver.
//! - [`TlsListener`] accepts TLS connections for axum and answers ACME
//!   TLS-ALPN-01 (RFC 8737) from whatever [`Challenges`] it is given.
//!
//! The TLS-ALPN-01 certificate carries a critical acmeIdentifier extension
//! that rustls refuses to load through `ServerConfig::with_single_cert`
//! (`UnsupportedCriticalExtension`, traffic.md §5.1), so it is handed out
//! through a resolver that does not check it.

pub mod keys;
pub mod listener;
pub mod resolver;

pub use keys::KeyAndCsr;
pub use listener::{Challenges, NoChallenges, TlsListener};
pub use resolver::{Files, Resolver, Served};

use std::sync::Arc;

use anyhow::Context;

/// The ALPN protocol an ACME validator offers for TLS-ALPN-01 (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// The crypto provider every grund TLS endpoint uses. ring, not aws-lc-rs:
/// aws-lc-rs needs cmake to build on alpine, where grund's static binary is
/// built.
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A server configuration that serves whatever `resolver` holds, TLS 1.3 and
/// 1.2, no client certificates, offering `alpn` in order.
pub fn server_config(resolver: Resolver, alpn: &[&[u8]]) -> anyhow::Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("TLS versions")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// The configuration a TLS-ALPN-01 validator is answered with: a self-signed
/// certificate for `name` whose acmeIdentifier extension holds
/// `key_authorization_digest`, the SHA-256 of the challenge's key
/// authorization, offering only `acme-tls/1`.
pub fn tls_alpn01_config(
    name: &str,
    key_authorization_digest: &[u8],
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let key = rcgen::KeyPair::generate().context("generate the challenge key")?;
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()])
        .context("the challenge certificate's name")?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
        key_authorization_digest,
    )];
    let certificate = params
        .self_signed(&key)
        .context("sign the challenge certificate")?;
    let der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der())
        .map_err(|error| anyhow::anyhow!("the challenge key: {error}"))?;
    let signing =
        rustls::crypto::ring::sign::any_supported_type(&der).context("load the challenge key")?;
    let certified = rustls::sign::CertifiedKey::new(vec![certificate.der().clone()], signing);
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("TLS versions")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(Arc::new(certified))));
    config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct Fixed(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}
