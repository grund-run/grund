//! The crypto provider and client configuration every grund TLS endpoint uses,
//! without certificate generation, TLS listeners or server framework dependencies.

#![forbid(unsafe_code)]

pub mod kx;

use std::sync::Arc;

use anyhow::Context;

/// The crypto provider every grund TLS endpoint, server and client, uses:
/// ring, with [`kx::X25519MLKEM768`] ahead of ring's own key exchange groups
/// (X25519, then P-256 and P-384), so grund prefers the hybrid
/// post-quantum group and falls back to X25519. Not aws-lc-rs, which needs
/// cmake and a C toolchain to build on alpine, where grund's static binary
/// is built (grund-docs design/traffic.md §5.1).
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups.insert(0, kx::X25519MLKEM768);
    Arc::new(provider)
}

/// Installs [`provider`] as the process's default, for clients that build
/// their rustls configuration from it (reqwest without a preconfigured
/// configuration). Does nothing when a default is installed already, so
/// every grund client calls this rather than installing a provider itself.
pub fn install_default() {
    let _ = Arc::unwrap_or_clone(provider()).install_default();
}

/// A client configuration on [`provider`] that trusts `roots`, TLS 1.3 and
/// 1.2, with no client certificate.
pub fn client_config(roots: rustls::RootCertStore) -> anyhow::Result<rustls::ClientConfig> {
    Ok(rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("TLS versions")?
        .with_root_certificates(roots)
        .with_no_client_auth())
}
