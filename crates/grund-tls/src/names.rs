//! A certificate per name, for a terminator that serves many (the edge,
//! grund-docs design/traffic.md §6.1): the ClientHello's name picks the
//! certificate, and a validator offering `acme-tls/1` is answered from
//! [`Answers`] instead. A name with neither fails its handshake.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anyhow::Context;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::{ACME_TLS_ALPN, Answers, Resolver, Served};

/// The certificates served, by name: one [`Resolver`] each, replaced in
/// place on renewal. Cheap to clone; clones share them.
#[derive(Debug, Clone, Default)]
pub struct Names {
    by_name: Arc<RwLock<HashMap<String, Resolver>>>,
}

impl Names {
    /// The resolver for `name`, made empty if there is none: what is set in
    /// it is served for `name` from the next handshake on.
    pub fn resolver(&self, name: &str) -> Resolver {
        self.by_name
            .write()
            .expect("names lock")
            .entry(name.to_ascii_lowercase())
            .or_default()
            .clone()
    }

    /// Stops serving `name`.
    pub fn remove(&self, name: &str) {
        self.by_name
            .write()
            .expect("names lock")
            .remove(&name.to_ascii_lowercase());
    }

    /// What is served for `name` now.
    pub fn get(&self, name: &str) -> Option<Arc<Served>> {
        self.by_name
            .read()
            .expect("names lock")
            .get(&name.to_ascii_lowercase())
            .and_then(Resolver::current)
    }

    /// Every name with a resolver, served or not yet.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .by_name
            .read()
            .expect("names lock")
            .keys()
            .cloned()
            .collect();
        names.sort();
        names
    }
}

#[derive(Debug)]
struct ByName {
    names: Names,
    answers: Answers,
}

impl ResolvesServerCert for ByName {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?.to_ascii_lowercase();
        let validator = hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN));
        if validator {
            return self.answers.get(&name);
        }
        self.names.get(&name).map(|served| served.key.clone())
    }
}

/// A server configuration serving `names` by the ClientHello's name, with
/// TLS-ALPN-01 answered from `answers`, offering `alpn` and then
/// `acme-tls/1`, which only a validator negotiates.
pub fn names_server_config(
    names: Names,
    answers: Answers,
    alpn: &[&[u8]],
) -> anyhow::Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(crate::provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("TLS versions")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ByName { names, answers }));
    config.alpn_protocols = alpn
        .iter()
        .map(|p| p.to_vec())
        .chain(std::iter::once(ACME_TLS_ALPN.to_vec()))
        .collect();
    Ok(config)
}
