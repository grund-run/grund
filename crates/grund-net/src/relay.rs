//! grund's relay: the lighthouse every machine reaches from behind its NAT
//! (network.md §10).
//!
//! It is iroh-relay's own server code, served two ways:
//! - **the relay itself** ([`serve`]): WebSocket at `/relay` and the probe
//!   paths, inside an accept loop that sends every other request to an axum
//!   `Router`, so grund-server hosts it on its own HTTPS listener. iroh-relay
//!   downcasts the upgraded connection to its `MaybeTlsStream`, so this loop
//!   owns TLS and HTTP/1; `axum::serve` and hyper-util's `auto` builder
//!   break the handshake (network-verification.md §5, U13);
//! - **QUIC address discovery** ([`spawn_address_discovery`]), on its own UDP
//!   port (7842 by default). A machine learns its public address from it, and
//!   without it hole punching failed in every lab trial (network.md §10.1).
//!
//! Who may use the relay is an [`AccessControl`]: grund admits the keys of
//! machines enrolled in this instance and not revoked ([`AllowList`] is the
//! simple form).

use std::{
    collections::HashSet,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock},
};

use anyhow::Context;
use axum::{Router, body::Body, http::StatusCode, routing::get};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::Service as _};
use hyper_util::rt::TokioIo;
pub use iroh::EndpointId;
pub use iroh_relay::server::{Access, AccessControl, ClientRequest, ConnectionId};
use iroh_relay::{
    KeyCache,
    server::{
        Handlers, Metrics, QuicConfig, RelayService, Server, ServerConfig,
        http_server::RelayServiceWithNotify, streams::MaybeTlsStream,
    },
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// The UDP port of QUIC address discovery, iroh's default.
pub const ADDRESS_DISCOVERY_PORT: u16 = iroh_relay::defaults::DEFAULT_RELAY_QUIC_PORT;

/// The relay's WebSocket path.
pub const RELAY_PATH: &str = iroh_relay::http::RELAY_PATH;

/// iroh-relay's relay service, ready to be served beside other routes.
#[derive(Debug, Clone)]
pub struct Relay {
    service: RelayService,
}

impl Relay {
    /// A relay that admits whoever `access` admits.
    pub fn new(access: impl AccessControl) -> Self {
        let service = RelayService::new(
            Handlers::default(),
            hyper::HeaderMap::new(),
            None,
            KeyCache::new(1024),
            Arc::new(access),
            Arc::new(Metrics::default()),
        );
        Self { service }
    }

    /// Disconnects every connection of `endpoint_id`, for a key the host no
    /// longer admits: [`AccessControl`] is asked only when a connection
    /// starts. `false` when it had none.
    pub fn disconnect(&self, endpoint_id: EndpointId) -> bool {
        self.service.clients().disconnect(endpoint_id, None)
    }

    /// The probe routes iroh clients use (`/ping`, `/generate_204`). They are
    /// private to iroh-relay's standalone server, so the host router answers
    /// them; merge these into it.
    pub fn probe_routes() -> Router {
        Router::new()
            .route(
                iroh_relay::http::RELAY_PROBE_PATH,
                get(|| async { StatusCode::OK }),
            )
            .route("/generate_204", get(|| async { StatusCode::NO_CONTENT }))
    }
}

/// A fixed set of admitted keys, which can be replaced while running.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    keys: Arc<RwLock<HashSet<EndpointId>>>,
}

impl AllowList {
    /// Admits exactly `keys` from now on.
    pub fn set(&self, keys: impl IntoIterator<Item = EndpointId>) {
        *self.keys.write().expect("allow list lock") = keys.into_iter().collect();
    }
}

impl AccessControl for AllowList {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if self
            .keys
            .read()
            .expect("allow list lock")
            .contains(&request.endpoint_id())
        {
            Access::Allow
        } else {
            Access::Deny {
                reason: Some("not a machine of this grund".into()),
            }
        }
    }
}

/// Serves the relay at [`RELAY_PATH`] and `app` for everything else, on
/// `listener`, over TLS when `tls` is given. Runs until the listener fails.
pub async fn serve(
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    relay: Relay,
    app: Router,
) -> io::Result<()> {
    let acceptor = tls.map(TlsAcceptor::from);
    loop {
        let (stream, _) = listener.accept().await?;
        let (relay, app, acceptor) = (relay.clone(), app.clone(), acceptor.clone());
        tokio::spawn(async move {
            let io = match acceptor {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls) => MaybeTlsStream::Tls(tls),
                    Err(e) => {
                        tracing::debug!(error = %e, "relay: TLS handshake failed");
                        return;
                    }
                },
                None => MaybeTlsStream::Plain(stream),
            };
            let svc =
                hyper::service::service_fn(move |req: Request<Incoming>| route(&relay, &app, req));
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(io), svc)
                .with_upgrades()
                .await;
        });
    }
}

type Routed = Pin<Box<dyn Future<Output = io::Result<Response<Body>>> + Send>>;

fn route(relay: &Relay, app: &Router, req: Request<Incoming>) -> Routed {
    if req.uri().path() == RELAY_PATH {
        let notify = Arc::new(tokio::sync::Notify::new());
        let res = RelayServiceWithNotify::new(relay.service.clone(), notify)
            .call(req)
            .into_inner()
            .map(|r| {
                let (parts, body) = r.into_parts();
                Response::from_parts(parts, Body::new(body))
            })
            .map_err(|e| io::Error::other(e.to_string()));
        Box::pin(std::future::ready(res))
    } else {
        let app = app.clone();
        Box::pin(async move { app.oneshot(req).await.map_err(|e| match e {}) })
    }
}

/// Starts QUIC address discovery on `bind` (UDP), with `tls` (TLS 1.3, the
/// relay's certificate). Keep the returned server; dropping it stops it.
pub async fn spawn_address_discovery(
    bind: SocketAddr,
    tls: rustls::ServerConfig,
) -> anyhow::Result<Server> {
    let mut quic = QuicConfig::new(bind);
    quic.server_config = Some(tls);
    let mut config = ServerConfig::default();
    config.quic = Some(quic);
    Server::spawn(config)
        .await
        .context("start QUIC address discovery")
}

/// A TLS server config from PEM files, for the relay and address discovery.
pub fn tls_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("parse the certificate PEM")?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("parse the key PEM")?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("TLS versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the certificate and key")
}
