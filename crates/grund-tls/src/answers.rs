use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anyhow::Context;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha2::{Digest, Sha256};

use crate::{ACME_TLS_ALPN, Resolver};

/// The most answers held at once. A terminator has a handful of names; this
/// bounds what a misbehaving instance can make it hold.
pub const MAX_ANSWERS: usize = 100;

/// TLS-ALPN-01 answers a terminator holds in memory, by name, as its
/// instance hands them over. Cheap to clone; clones share the answers, so
/// the task that receives challenges inserts and every handshake sees them.
#[derive(Debug, Clone, Default)]
pub struct Answers {
    by_name: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl Answers {
    /// Answers TLS-ALPN-01 for `name` with `key_authorization` from the next
    /// handshake on, replacing an earlier answer for the name.
    pub fn insert(&self, name: &str, key_authorization: &str) -> anyhow::Result<()> {
        let name = name.to_ascii_lowercase();
        let digest = Sha256::digest(key_authorization.as_bytes());
        let key = crate::tls_alpn01_key(&name, &digest)?;
        let mut by_name = self.by_name.write().expect("answers lock");
        anyhow::ensure!(
            by_name.len() < MAX_ANSWERS || by_name.contains_key(&name),
            "more than {MAX_ANSWERS} challenges at once"
        );
        by_name.insert(name, Arc::new(key));
        Ok(())
    }

    /// Stops answering for `name`.
    pub fn remove(&self, name: &str) {
        self.by_name
            .write()
            .expect("answers lock")
            .remove(&name.to_ascii_lowercase());
    }

    /// The names answered now.
    pub fn names(&self) -> Vec<String> {
        self.by_name
            .read()
            .expect("answers lock")
            .keys()
            .cloned()
            .collect()
    }

    pub(crate) fn get(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        self.by_name
            .read()
            .expect("answers lock")
            .get(&name.to_ascii_lowercase())
            .cloned()
    }
}

#[derive(Debug)]
struct Answering {
    served: Resolver,
    answers: Answers,
}

impl ResolvesServerCert for Answering {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let validator = hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN));
        if validator {
            let name = hello.server_name()?;
            let answer = self.answers.get(name);
            if answer.is_some() {
                tracing::info!(%name, "tls: answered a TLS-ALPN-01 challenge");
            }
            return answer;
        }
        self.served.resolve(hello)
    }
}

/// A server configuration that serves what `resolver` holds, and answers a
/// ClientHello offering `acme-tls/1` from `answers` instead: for a
/// terminator whose accept loop is not a [`crate::TlsListener`]. `alpn` is
/// offered in order, with `acme-tls/1` last, so only a validator (which
/// offers nothing else) negotiates it. A validator asking for a name with no
/// answer fails its handshake.
pub fn answering_server_config(
    resolver: Resolver,
    answers: Answers,
    alpn: &[&[u8]],
) -> anyhow::Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(crate::provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("TLS versions")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Answering {
            served: resolver,
            answers,
        }));
    config.alpn_protocols = alpn
        .iter()
        .map(|p| p.to_vec())
        .chain(std::iter::once(ACME_TLS_ALPN.to_vec()))
        .collect();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::ServerName;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::Served;

    async fn serving(config: rustls::ServerConfig) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                });
            }
        });
        address
    }

    #[derive(Debug)]
    struct Anything;

    impl rustls::client::danger::ServerCertVerifier for Anything {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            crate::provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    async fn leaf(
        address: std::net::SocketAddr,
        name: &'static str,
        alpn: &[u8],
    ) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let mut config = rustls::ClientConfig::builder_with_provider(crate::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Anything))
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let stream = TcpStream::connect(address).await.ok()?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name).unwrap(), stream)
            .await
            .ok()?;
        let (_, connection) = tls.get_ref();
        Some((
            connection.peer_certificates()?.first()?.to_vec(),
            connection.alpn_protocol().map(<[u8]>::to_vec),
        ))
    }

    fn served(name: &str) -> (Served, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (
            Served::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap(),
            cert.der().to_vec(),
        )
    }

    #[tokio::test]
    async fn a_validator_gets_the_answer_and_everyone_else_the_certificate() {
        let resolver = Resolver::default();
        let (certificate, der) = served("relay.example.com");
        resolver.set(certificate);
        let answers = Answers::default();
        let address =
            serving(answering_server_config(resolver, answers.clone(), &[b"http/1.1"]).unwrap())
                .await;

        let (plain, alpn) = leaf(address, "relay.example.com", b"http/1.1")
            .await
            .unwrap();
        assert_eq!(plain, der);
        assert_eq!(alpn.as_deref(), Some(&b"http/1.1"[..]));
        assert!(
            leaf(address, "relay.example.com", ACME_TLS_ALPN)
                .await
                .is_none(),
            "no answer before the instance hands one over"
        );

        answers
            .insert("relay.example.com", "token.thumbprint")
            .unwrap();
        let (answer, alpn) = leaf(address, "relay.example.com", ACME_TLS_ALPN)
            .await
            .unwrap();
        assert_eq!(alpn.as_deref(), Some(ACME_TLS_ALPN));
        let (_, parsed) = x509_parser::parse_x509_certificate(&answer).unwrap();
        let extension = parsed
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("the acmeIdentifier extension");
        assert!(extension.critical);
        assert!(
            extension
                .value
                .ends_with(&Sha256::digest(b"token.thumbprint"))
        );
        assert!(
            leaf(address, "other.example.com", ACME_TLS_ALPN)
                .await
                .is_none()
        );
        let (still, _) = leaf(address, "relay.example.com", b"http/1.1")
            .await
            .unwrap();
        assert_eq!(still, der, "the answer never replaces the certificate");

        answers.remove("relay.example.com");
        assert!(answers.names().is_empty());
        assert!(
            leaf(address, "relay.example.com", ACME_TLS_ALPN)
                .await
                .is_none()
        );
    }
}
