use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    task::JoinHandle,
};
use tokio_rustls::{LazyConfigAcceptor, server::TlsStream};

use crate::ACME_TLS_ALPN;

/// How long a client gets to finish its handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Handshakes in progress at once; a connection beyond this is closed at once.
pub const MAX_HANDSHAKES: usize = 1024;

/// TLS-ALPN-01 lookups in progress at once. A lookup may cost a database
/// round trip, and anyone can offer `acme-tls/1`, so beyond this the
/// connection is closed instead of queued.
pub const MAX_CHALLENGE_LOOKUPS: usize = 8;

/// Where a [`TlsListener`] finds the answer to a TLS-ALPN-01 challenge: the
/// SHA-256 of the key authorization for `name`, if an order is waiting on
/// one. Whoever answers must answer on every replica, since the validator
/// connects to whichever one the name reaches.
pub trait Challenges: Clone + Send + Sync + 'static {
    /// The key authorization digest for `name` (lowercase, from SNI), or
    /// none.
    fn tls_alpn01(&self, name: &str) -> impl Future<Output = Option<Vec<u8>>> + Send;
}

/// Answers no challenge: for a listener serving a certificate from files.
#[derive(Debug, Clone, Copy)]
pub struct NoChallenges;

impl Challenges for NoChallenges {
    async fn tls_alpn01(&self, _: &str) -> Option<Vec<u8>> {
        None
    }
}

/// A TLS listener for `axum::serve`. Handshakes run in their own tasks, so a
/// slow client holds up nobody; a finished handshake is handed to axum. A
/// ClientHello offering `acme-tls/1` is answered from [`Challenges`] and then
/// closed, as RFC 8737 asks.
///
/// Its address is the peer's `SocketAddr`; wrap it with
/// `axum::serve::ListenerExt::tap_io` to get `ConnectInfo<SocketAddr>`.
pub struct TlsListener {
    connections: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    task: JoinHandle<()>,
}

impl TlsListener {
    /// Starts accepting on `listener`, serving `config`.
    pub fn new<C: Challenges>(
        listener: TcpListener,
        config: Arc<rustls::ServerConfig>,
        challenges: C,
    ) -> std::io::Result<Self> {
        let local = listener.local_addr()?;
        let (sender, connections) = mpsc::channel(128);
        let task = tokio::spawn(accept_loop(listener, config, challenges, sender));
        Ok(Self {
            connections,
            local,
            task,
        })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.connections.recv().await {
            Some(connection) => connection,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

async fn accept_loop<C: Challenges>(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    challenges: C,
    sender: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
) {
    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    let lookups = Arc::new(Semaphore::new(MAX_CHALLENGE_LOOKUPS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(error = %error, "https: accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = handshakes.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "https: too many handshakes in progress; closed");
            continue;
        };
        let (config, challenges, lookups, sender) = (
            config.clone(),
            challenges.clone(),
            lookups.clone(),
            sender.clone(),
        );
        tokio::spawn(async move {
            let handshake = handshake(stream, config, challenges, lookups);
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
                Ok(Some(tls)) => {
                    drop(permit);
                    let _ = sender.send((tls, peer)).await;
                }
                Ok(None) => {}
                Err(_) => tracing::debug!(%peer, "https: handshake timed out"),
            }
        });
    }
}

async fn handshake<C: Challenges>(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    challenges: C,
    lookups: Arc<Semaphore>,
) -> Option<TlsStream<TcpStream>> {
    let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
        .await
        .map_err(|error| tracing::debug!(error = %error, "https: no ClientHello"))
        .ok()?;
    let hello = start.client_hello();
    let validator = hello
        .alpn()
        .is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN));
    if !validator {
        return start
            .into_stream(config)
            .await
            .map_err(|error| tracing::debug!(error = %error, "https: handshake failed"))
            .ok();
    }
    let name = hello.server_name()?.to_ascii_lowercase();
    let _permit = lookups.try_acquire_owned().ok()?;
    let Some(digest) = challenges.tls_alpn01(&name).await else {
        tracing::debug!(%name, "https: acme-tls/1 for a name with no pending challenge");
        return None;
    };
    let answer = crate::tls_alpn01_config(&name, &digest)
        .map_err(
            |error| tracing::warn!(error = %error, "https: could not build the TLS-ALPN-01 answer"),
        )
        .ok()?;
    match start.into_stream(answer).await {
        Ok(_) => tracing::info!(%name, "https: answered a TLS-ALPN-01 challenge"),
        Err(error) => tracing::debug!(error = %error, "https: TLS-ALPN-01 handshake failed"),
    }
    None
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::ServerName;

    use super::*;
    use crate::{Resolver, Served};

    #[derive(Clone)]
    struct One(&'static str, Vec<u8>);

    impl Challenges for One {
        async fn tls_alpn01(&self, name: &str) -> Option<Vec<u8>> {
            (name == self.0).then(|| self.1.clone())
        }
    }

    fn served(name: &str) -> (Served, rustls::RootCertStore) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        (
            Served::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap(),
            roots,
        )
    }

    async fn connect(
        address: SocketAddr,
        name: &'static str,
        roots: rustls::RootCertStore,
        alpn: &[u8],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut config = rustls::ClientConfig::builder_with_provider(crate::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let stream = TcpStream::connect(address).await?;
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name).unwrap(), stream)
            .await
    }

    async fn listening<C: Challenges>(
        resolver: Resolver,
        challenges: C,
    ) -> (TlsListener, SocketAddr) {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = crate::server_config(resolver, &[b"http/1.1"]).unwrap();
        let listener = TlsListener::new(tcp, Arc::new(config), challenges).unwrap();
        let address = axum::serve::Listener::local_addr(&listener).unwrap();
        (listener, address)
    }

    #[tokio::test]
    async fn a_client_gets_the_certificate_set_last() {
        let resolver = Resolver::default();
        let (mut listener, address) = listening(resolver.clone(), NoChallenges).await;
        let (first, first_roots) = served("grund.example.com");
        resolver.set(first);
        let client = tokio::spawn(connect(
            address,
            "grund.example.com",
            first_roots,
            b"http/1.1",
        ));
        let (_io, peer) = axum::serve::Listener::accept(&mut listener).await;
        assert!(peer.ip().is_loopback());
        client.await.unwrap().unwrap();

        let (second, second_roots) = served("grund.example.com");
        resolver.set(second);
        let client = tokio::spawn(connect(
            address,
            "grund.example.com",
            second_roots,
            b"http/1.1",
        ));
        let _ = axum::serve::Listener::accept(&mut listener).await;
        client.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn nothing_is_served_before_a_certificate_is_set() {
        let (_listener, address) = listening(Resolver::default(), NoChallenges).await;
        let (_, roots) = served("grund.example.com");
        assert!(
            connect(address, "grund.example.com", roots, b"http/1.1")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_validator_gets_the_challenge_certificate_for_a_pending_name_only() {
        let digest = vec![7u8; 32];
        let (_listener, address) = listening(
            Resolver::default(),
            One("grund.example.com", digest.clone()),
        )
        .await;
        let certificate = capture(address, "grund.example.com").await.unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(&certificate).unwrap();
        let extension = parsed
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("the acmeIdentifier extension");
        assert!(extension.critical);
        assert!(extension.value.ends_with(&digest));
        assert!(capture(address, "other.example.com").await.is_none());
    }

    async fn capture(address: SocketAddr, name: &'static str) -> Option<Vec<u8>> {
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
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                crate::provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }
        let mut config = rustls::ClientConfig::builder_with_provider(crate::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Anything))
            .with_no_client_auth();
        config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
        let stream = TcpStream::connect(address).await.ok()?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name).unwrap(), stream)
            .await
            .ok()?;
        tls.get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| leaf.to_vec())
    }
}
