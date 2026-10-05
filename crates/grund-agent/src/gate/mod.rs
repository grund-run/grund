//! The gate (grund-docs design/traffic.md §7, §8): the part of the agent
//! that lets in published ports and hands each request to a ready copy of
//! its app. It is the one HTTP router on the traffic path: the edge only
//! moves connections, so every request is routed, balanced and retried here,
//! on the machine that runs the app.
//!
//! - **Entry streams** (`grund/entry/1`, [`entry`]): only from keys in the
//!   document's `entry_keys`; answered before any client byte reaches an
//!   app: accept, no ready copy, not placed here, or draining.
//! - **HTTP/1.1 and HTTP/2** on each stream (hyper), with §13's limits.
//! - **Per request** ([`Gate::route`]): the host must be one of the app's
//!   names, else 421 (§6.6: a browser coalescing two apps' connections must
//!   never be answered by the wrong app); the copies are looked up now, not
//!   when the connection opened; ready local copies first by two random
//!   choices on in-flight requests, then ready copies on other machines over
//!   the private network (with `Connection: close`, so the client's next
//!   connection lands on a machine with a ready copy), then a draining copy
//!   that still answers.
//! - **Retries** (§8.4, [`budget`]): a failed connect on any request; a reset
//!   before any response byte once, only for an idempotent method with an
//!   empty or buffered body of at most 64 KiB; never once a response began
//!   or for an app's own 5xx.
//! - **Headers** (§7.5): forwarding headers the client sent are removed and
//!   the gate's own set; hop-by-hop headers are removed both ways;
//!   `X-Request-Id` is added when missing; the app's platform address gets
//!   `Strict-Transport-Security`.
//! - **Draining** (§8.5): a draining copy gets no new requests unless nothing
//!   else answers, is reported idle when nothing is in flight to it, and has
//!   what is still open closed when it leaves the document. The whole gate
//!   drains when the agent stops: new streams are refused, open connections
//!   are asked to close, and in-flight requests get up to 10 s.
//!
//! Local copies are reached through [`Dial`] (the container runtime's
//! `connect`), remote ones with a TCP connect to their address over the
//! private network.

pub mod budget;
pub mod entry;
pub mod routes;

use std::{
    collections::HashSet,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use grund_proto::grund::agent::v1::DesiredState;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri, Version,
    body::{Body as _, Frame, Incoming, SizeHint},
    header::{self, HeaderName, HeaderValue},
};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use tokio::{net::TcpStream, sync::watch};
use tokio_util::sync::WaitForCancellationFutureOwned;

use routes::{AppRoute, Candidate, Copies, CopyState, Table, Target, Upstream};
pub use routes::{EndpointPort, RemoteCopy, ReplicaEndpoint, endpoints_from};

/// An error a body may carry.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The body type the gate passes on.
pub type Body = UnsyncBoxBody<Bytes, BoxError>;

/// The gate's limits (§13), each with its hard maximum in the design.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Time to read a request head (slow-loris clients). Max 60 s.
    pub head_timeout: Duration,
    /// Time to the app's response head. Max 1 h.
    pub response_timeout: Duration,
    /// An idle keep-alive connection is closed after this. Max 10 min.
    pub idle_timeout: Duration,
    /// An upgraded connection (WebSocket) with no bytes either way is closed
    /// after this. Max 24 h.
    pub upgraded_idle_timeout: Duration,
    /// The largest request body buffered so it can be retried.
    pub retry_body_bytes: usize,
    /// Request head: headers, and bytes.
    pub max_headers: usize,
    pub max_head_bytes: usize,
    /// How long a draining gate waits for in-flight requests. Max 60 s.
    pub agent_drain: Duration,
    /// How long a connect to a copy may take.
    pub connect_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            head_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(75),
            upgraded_idle_timeout: Duration::from_secs(600),
            retry_body_bytes: 64 * 1024,
            max_headers: 100,
            max_head_bytes: 64 * 1024,
            agent_drain: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(2),
        }
    }
}

/// How the gate reaches a copy, here or on another machine: a TCP
/// connection to its own address (grund-docs design/apps.md §12.2), which the
/// private network carries to it. [`Direct`] in the agent; tests stand in
/// their own servers.
pub trait Dial: Send + Sync + 'static {
    fn connect(
        &self,
        address: IpAddr,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send + '_>>;
}

/// [`Dial`] by connecting to the copy's address from this machine.
pub struct Direct;

impl Dial for Direct {
    fn connect(
        &self,
        address: IpAddr,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send + '_>> {
        Box::pin(async move { TcpStream::connect((address, port)).await })
    }
}

#[derive(Clone)]
struct Connector {
    dial: Arc<dyn Dial>,
    timeout: Duration,
}

impl tower_service::Service<Uri> for Connector {
    type Response = TokioIo<TcpStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let dial = self.dial.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let host = uri.host().unwrap_or_default().to_string();
            let port = uri.port_u16().unwrap_or(80);
            let connecting = async {
                let ip: IpAddr = host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse()
                    .map_err(|_| std::io::Error::other("not a copy's address"))?;
                dial.connect(ip, port).await
            };
            let stream = tokio::time::timeout(timeout, connecting)
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
                })??;
            let _ = stream.set_nodelay(true);
            Ok(TokioIo::new(stream))
        })
    }
}

fn authority(target: &Target) -> String {
    let (address, port) = match target {
        Target::Local { address, port, .. } | Target::Remote { address, port } => (address, port),
    };
    match address {
        IpAddr::V6(ip) => format!("[{ip}]:{port}"),
        IpAddr::V4(ip) => format!("{ip}:{port}"),
    }
}

/// Counters, for logs and tests.
#[derive(Debug, Default)]
pub struct Stats {
    pub streams: AtomicU64,
    pub refused: AtomicU64,
    pub requests: AtomicU64,
    pub retried: AtomicU64,
    pub misdirected: AtomicU64,
    pub remote: AtomicU64,
    pub failed: AtomicU64,
}

struct Inner {
    table: RwLock<Arc<Table>>,
    generation: AtomicU64,
    copies: Copies,
    entry_keys: RwLock<HashSet<String>>,
    draining: AtomicBool,
    shutdown: watch::Sender<bool>,
    connections: AtomicUsize,
    inflight: AtomicUsize,
    budget: budget::Budget,
    connector: Connector,
    http1: Client<Connector, Body>,
    h2c: Client<Connector, Body>,
    limits: Limits,
    stats: Stats,
}

/// The gate. Cheap to clone.
#[derive(Clone)]
pub struct Gate(Arc<Inner>);

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate").finish_non_exhaustive()
    }
}

struct ConnectionState {
    active: AtomicUsize,
    last: Mutex<Instant>,
    closing: AtomicBool,
}

/// While draining, how long a client connection must have nothing in
/// flight before the gate closes it. A client sending back to back gets
/// `Connection: close` on its next answer instead, so a request it sends as
/// the connection closes is never lost.
pub const DRAIN_QUIET: Duration = Duration::from_millis(250);

struct InFlight {
    copy: Arc<CopyState>,
    gate: Gate,
    connection: Arc<ConnectionState>,
}

impl InFlight {
    fn new(copy: Arc<CopyState>, gate: Gate, connection: Arc<ConnectionState>) -> Self {
        copy.inflight.fetch_add(1, Relaxed);
        gate.0.inflight.fetch_add(1, Relaxed);
        Self {
            copy,
            gate,
            connection,
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.copy.inflight.fetch_sub(1, Relaxed);
        self.gate.0.inflight.fetch_sub(1, Relaxed);
        *self.connection.last.lock().expect("connection lock") = Instant::now();
    }
}

struct RequestGuard(Arc<ConnectionState>);

impl RequestGuard {
    fn new(connection: Arc<ConnectionState>) -> Self {
        connection.active.fetch_add(1, Relaxed);
        Self(connection)
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Relaxed);
        *self.0.last.lock().expect("connection lock") = Instant::now();
    }
}

struct Tracked {
    inner: Body,
    closing: Pin<Box<WaitForCancellationFutureOwned>>,
    _guards: (InFlight, RequestGuard),
}

impl hyper::body::Body for Tracked {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if this.closing.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err("the copy left this machine".into())));
        }
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn empty() -> Body {
    full(Bytes::new())
}

fn answer(status: StatusCode, words: &str) -> Response<Body> {
    let mut response = Response::new(full(format!("{words}\n")));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert("x-grund-gate", HeaderValue::from_static("1"));
    response
}

/// Lowercase host of a request, without its port: `:authority` for
/// HTTP/2, `Host` for HTTP/1.1.
pub fn request_host<B>(request: &Request<B>) -> Option<String> {
    let raw = request
        .uri()
        .authority()
        .map(|a| a.host().to_string())
        .or_else(|| {
            let value = request.headers().get(header::HOST)?.to_str().ok()?;
            let authority: hyper::http::uri::Authority = value.parse().ok()?;
            Some(authority.host().to_string())
        })?;
    let host = raw.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const FORWARDING: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-server",
    "x-real-ip",
];

/// Removes hop-by-hop headers (RFC 9110 §7.6.1), with every header the
/// `Connection` header names. With `keep_upgrade`, `Upgrade` and a
/// `Connection: upgrade` survive, for a WebSocket passed through.
pub fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    let named: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect();
    let upgrade = headers.get(header::UPGRADE).cloned();
    for name in HOP_BY_HOP
        .iter()
        .copied()
        .chain(named.iter().map(String::as_str))
    {
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(name);
        }
    }
    if keep_upgrade && let Some(upgrade) = upgrade {
        headers.insert(header::UPGRADE, upgrade);
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    }
}

/// Replaces whatever forwarding headers the client sent with the gate's
/// own (§7.5), from the client's address as the edge saw it.
pub fn set_forwarding(headers: &mut HeaderMap, client: &str, host: &str) {
    for name in FORWARDING {
        headers.remove(*name);
    }
    let ip = client
        .parse::<std::net::SocketAddr>()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| client.to_string());
    let forwarded_for = if ip.contains(':') {
        format!("\"[{ip}]\"")
    } else {
        ip.clone()
    };
    let set = |headers: &mut HeaderMap, name: &'static str, value: String| {
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(name, value);
        }
    };
    set(headers, "x-forwarded-for", ip.clone());
    set(headers, "x-forwarded-proto", "https".into());
    set(headers, "x-forwarded-host", host.to_string());
    set(
        headers,
        "forwarded",
        format!("for={forwarded_for};proto=https;host={host}"),
    );
}

fn request_id() -> HeaderValue {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    HeaderValue::from_str(&hex::encode(bytes)).expect("hex is a header value")
}

fn random_below(n: usize) -> usize {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    (u64::from_le_bytes(bytes) % n.max(1) as u64) as usize
}

fn idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE
    )
}

fn wants_upgrade<B>(request: &Request<B>) -> bool {
    request.version() == Version::HTTP_11
        && request.headers().contains_key(header::UPGRADE)
        && request
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            })
}

enum RequestBody {
    Buffered(Bytes),
    Streaming(Incoming),
}

/// One client connection the gate serves: who it is and which app it was
/// opened for.
#[derive(Debug, Clone)]
pub struct EntryClient {
    /// The client's address as the edge saw it.
    pub client: String,
    /// The name the connection was opened for (the ClientHello's); every
    /// request on it must be for the same app.
    pub host: String,
}

impl Gate {
    /// A gate with nothing to route yet.
    pub fn new(dial: Arc<dyn Dial>, limits: Limits) -> Self {
        let connector = Connector {
            dial,
            timeout: limits.connect_timeout,
        };
        let http1 = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_timer(TokioTimer::new())
            .timer(TokioTimer::new())
            .build(connector.clone());
        let h2c = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_timer(TokioTimer::new())
            .timer(TokioTimer::new())
            .http2_only(true)
            .build(connector.clone());
        let (shutdown, _) = watch::channel(false);
        Self(Arc::new(Inner {
            table: RwLock::new(Arc::new(Table::default())),
            generation: AtomicU64::new(0),
            copies: Copies::default(),
            entry_keys: RwLock::new(HashSet::new()),
            draining: AtomicBool::new(false),
            shutdown,
            connections: AtomicUsize::new(0),
            inflight: AtomicUsize::new(0),
            budget: budget::Budget::default(),
            connector,
            http1,
            h2c,
            limits,
            stats: Stats::default(),
        }))
    }

    pub fn stats(&self) -> &Stats {
        &self.0.stats
    }

    /// Rebuilds the routes from the applied document, the apps loop's view
    /// of the local replicas and the ready copies elsewhere. Draining takes
    /// effect here, at once.
    pub fn update(
        &self,
        document: Option<&DesiredState>,
        local: &[ReplicaEndpoint],
        remote: &[RemoteCopy],
    ) {
        let table = routes::build(document, local, remote, &self.0.copies);
        *self.0.table.write().expect("table lock") = Arc::new(table);
        self.0
            .generation
            .store(document.map_or(0, |d| d.generation), Relaxed);
        *self.0.entry_keys.write().expect("entry keys lock") = document
            .map(|d| {
                d.entry_keys
                    .iter()
                    .map(|k| k.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
    }

    /// Whether `endpoint_id` may open entry streams here.
    pub fn is_entry_key(&self, endpoint_id: &str) -> bool {
        self.0
            .entry_keys
            .read()
            .expect("entry keys lock")
            .contains(&endpoint_id.to_ascii_lowercase())
    }

    /// The draining replicas of `document` with nothing in flight through
    /// the gate (apps.md §12.3). None until the gate routes by `document`
    /// itself, so a copy is never idle while the gate may still pick it.
    pub fn idle(&self, document: Option<&DesiredState>) -> Vec<String> {
        if document.map_or(0, |d| d.generation) != self.0.generation.load(Relaxed) {
            return Vec::new();
        }
        let draining: Vec<String> = document
            .map(|d| {
                d.replicas
                    .iter()
                    .filter(|r| {
                        r.state.as_known()
                            == Some(
                                grund_proto::grund::agent::v1::ReplicaState::REPLICA_STATE_DRAINING,
                            )
                    })
                    .map(|r| r.replica_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        self.0.copies.idle(&draining)
    }

    fn table(&self) -> Arc<Table> {
        self.0.table.read().expect("table lock").clone()
    }

    /// The answer to a new entry stream for `host` (§6.3, §8.5).
    pub fn admit(&self, host: &str) -> grund_entry::Answer {
        if self.0.draining.load(Relaxed) {
            return grund_entry::Answer::Draining;
        }
        let Some(app) = self.table().app_for(host) else {
            return grund_entry::Answer::NotPlacedHere;
        };
        match app.ready_local() {
            0 if app.ready_remote() || !app.draining_fallback() => grund_entry::Answer::NoReadyCopy,
            ready => grund_entry::Answer::Accept {
                ready: u16::try_from(ready).unwrap_or(u16::MAX),
            },
        }
    }

    /// Stops taking new streams, asks every open connection to close, and
    /// waits for in-flight requests up to the agent drain limit (§7.7).
    pub async fn drain(&self) {
        self.0.draining.store(true, Relaxed);
        let _ = self.0.shutdown.send(true);
        let deadline = Instant::now() + self.0.limits.agent_drain;
        while Instant::now() < deadline
            && (self.0.inflight.load(Relaxed) > 0 || self.0.connections.load(Relaxed) > 0)
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Serves HTTP/1.1 or HTTP/2 on one accepted client connection until
    /// it ends, is idle too long, or the gate drains.
    pub async fn serve<I>(&self, io: I, client: EntryClient)
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (keep, never) = tokio::sync::watch::channel(false);
        self.serve_until(io, client, never).await;
        drop(keep);
    }

    /// [`Gate::serve`], also closing the connection after its current
    /// request once `edge_stopping` turns true: the edge that handed it over
    /// is stopping.
    pub async fn serve_until<I>(
        &self,
        io: I,
        client: EntryClient,
        mut edge_stopping: tokio::sync::watch::Receiver<bool>,
    ) where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        self.0.connections.fetch_add(1, Relaxed);
        let connection = Arc::new(ConnectionState {
            active: AtomicUsize::new(0),
            last: Mutex::new(Instant::now()),
            closing: AtomicBool::new(false),
        });
        let gate = self.clone();
        let state = connection.clone();
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let (gate, client, state) = (gate.clone(), client.clone(), state.clone());
            async move {
                let http1 = request.version() < hyper::Version::HTTP_2;
                let mut response = gate.route(request, &client, state.clone()).await;
                if http1 && state.closing.load(Relaxed) {
                    response
                        .headers_mut()
                        .insert(header::CONNECTION, HeaderValue::from_static("close"));
                }
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let limits = &self.0.limits;
        let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(limits.head_timeout)
            .max_buf_size(limits.max_head_bytes.max(8192))
            .max_headers(limits.max_headers);
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_header_list_size(limits.max_head_bytes as u32)
            .max_concurrent_streams(256);
        let served = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
        tokio::pin!(served);
        let mut shutdown = self.0.shutdown.subscribe();
        let mut idle_check = tokio::time::interval(Duration::from_secs(1));
        let mut closing = false;
        let mut draining = false;
        let mut edge_may_stop = true;
        let mut quiet_check = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! {
                _ = served.as_mut() => break,
                changed = edge_stopping.changed(), if !draining && edge_may_stop => {
                    if changed.is_err() {
                        edge_may_stop = false;
                    } else if *edge_stopping.borrow() {
                        draining = true;
                        connection.closing.store(true, Relaxed);
                    }
                }
                changed = shutdown.changed(), if !draining => {
                    if changed.is_err() || *shutdown.borrow() {
                        draining = true;
                        connection.closing.store(true, Relaxed);
                    }
                }
                _ = quiet_check.tick(), if draining && !closing => {
                    let idle_for = connection.last.lock().expect("connection lock").elapsed();
                    if connection.active.load(Relaxed) == 0 && idle_for >= DRAIN_QUIET {
                        closing = true;
                        served.as_mut().graceful_shutdown();
                    }
                }
                _ = idle_check.tick(), if !closing => {
                    let idle_for = connection.last.lock().expect("connection lock").elapsed();
                    if connection.active.load(Relaxed) == 0 && idle_for >= limits.idle_timeout {
                        closing = true;
                        served.as_mut().graceful_shutdown();
                    }
                }
            }
        }
        self.0.connections.fetch_sub(1, Relaxed);
    }

    async fn route(
        &self,
        mut request: Request<Incoming>,
        client: &EntryClient,
        connection: Arc<ConnectionState>,
    ) -> Response<Body> {
        let guard = RequestGuard::new(connection.clone());
        self.0.stats.requests.fetch_add(1, Relaxed);
        let host = request_host(&request).unwrap_or_default();
        let table = self.table();
        let Some(app) = table.app_for(&client.host) else {
            return answer(
                StatusCode::MISDIRECTED_REQUEST,
                "This address is not served here.",
            );
        };
        if !app.serves(&host) {
            self.0.stats.misdirected.fetch_add(1, Relaxed);
            return answer(
                StatusCode::MISDIRECTED_REQUEST,
                "Misdirected request: open a new connection for this address.",
            );
        }
        self.0.budget.request(&app.app, Instant::now());
        let upgrade = wants_upgrade(&request).then(|| hyper::upgrade::on(&mut request));
        let (mut parts, body) = request.into_parts();
        strip_hop_by_hop(&mut parts.headers, upgrade.is_some());
        set_forwarding(&mut parts.headers, &client.client, &host);
        if !parts.headers.contains_key("x-request-id") {
            parts.headers.insert("x-request-id", request_id());
        }
        if let Ok(value) = HeaderValue::from_str(&host) {
            parts.headers.insert(header::HOST, value);
        }
        let retryable_method = idempotent(&parts.method);
        let body = if body.is_end_stream() {
            RequestBody::Buffered(Bytes::new())
        } else if body
            .size_hint()
            .upper()
            .is_some_and(|n| n as usize <= self.0.limits.retry_body_bytes)
        {
            match tokio::time::timeout(Duration::from_secs(30), body.collect()).await {
                Ok(Ok(collected)) => RequestBody::Buffered(collected.to_bytes()),
                _ => {
                    return answer(
                        StatusCode::BAD_REQUEST,
                        "The request's body did not arrive.",
                    );
                }
            }
        } else {
            RequestBody::Streaming(body)
        };
        let response = match (upgrade, body) {
            (Some(on_upgrade), RequestBody::Buffered(bytes)) if bytes.is_empty() => {
                self.upgrade(&app, &host, parts, on_upgrade, connection.clone())
                    .await
            }
            (_, RequestBody::Buffered(bytes)) => {
                self.forward_buffered(
                    &app,
                    &host,
                    parts,
                    bytes,
                    retryable_method,
                    connection.clone(),
                )
                .await
            }
            (_, RequestBody::Streaming(body)) => {
                self.forward_streaming(&app, &host, parts, body, connection.clone())
                    .await
            }
        };
        drop(guard);
        response
    }

    fn pick(&self, app: &AppRoute, tried: &[String]) -> Option<Candidate> {
        app.pick(tried, &mut random_below)
    }

    fn upstream_request(
        parts: &hyper::http::request::Parts,
        candidate: &Candidate,
        body: Body,
    ) -> Request<Body> {
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let mut request = Request::from_parts(parts.clone(), body);
        *request.uri_mut() = format!("http://{}{path}", authority(&candidate.target))
            .parse()
            .unwrap_or_default();
        *request.version_mut() = match candidate.upstream {
            Upstream::Http1 => Version::HTTP_11,
            Upstream::H2c => Version::HTTP_2,
        };
        if candidate.upstream == Upstream::H2c {
            request.headers_mut().remove(header::HOST);
        }
        request
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        app: &AppRoute,
        candidate: &Candidate,
        response: Response<Incoming>,
        version: Version,
        inflight: InFlight,
        connection: Arc<ConnectionState>,
        host: &str,
    ) -> Response<Body> {
        let (mut parts, body) = response.into_parts();
        strip_hop_by_hop(&mut parts.headers, false);
        if app.platform_host.as_deref() == Some(host)
            && !parts
                .headers
                .contains_key(header::STRICT_TRANSPORT_SECURITY)
        {
            parts.headers.insert(
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=31536000"),
            );
        }
        if !candidate.local {
            self.0.stats.remote.fetch_add(1, Relaxed);
            if version == Version::HTTP_11 {
                parts
                    .headers
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
            }
        }
        let closing = Box::pin(candidate.copy.closing.clone().cancelled_owned());
        let body = Tracked {
            inner: body.map_err(|e| -> BoxError { Box::new(e) }).boxed_unsync(),
            closing,
            _guards: (inflight, RequestGuard::new(connection)),
        };
        Response::from_parts(parts, body.boxed_unsync())
    }

    async fn forward_buffered(
        &self,
        app: &Arc<AppRoute>,
        host: &str,
        parts: hyper::http::request::Parts,
        bytes: Bytes,
        retryable_method: bool,
        connection: Arc<ConnectionState>,
    ) -> Response<Body> {
        let version = parts.version;
        let mut tried: Vec<String> = Vec::new();
        let mut resent = false;
        let mut current = app.clone();
        loop {
            let Some(candidate) = self.pick(&current, &tried) else {
                self.0.stats.failed.fetch_add(1, Relaxed);
                return answer(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "No copy of this app is ready. Try again in a moment.",
                );
            };
            tried.push(candidate.copy.replica_id.clone());
            let request = Self::upstream_request(&parts, &candidate, full(bytes.clone()));
            let inflight = InFlight::new(candidate.copy.clone(), self.clone(), connection.clone());
            let client = match candidate.upstream {
                Upstream::Http1 => &self.0.http1,
                Upstream::H2c => &self.0.h2c,
            };
            let sent =
                tokio::time::timeout(self.0.limits.response_timeout, client.request(request)).await;
            let retry = match sent {
                Ok(Ok(response)) => {
                    return self.finish(
                        app, &candidate, response, version, inflight, connection, host,
                    );
                }
                Err(_) => {
                    self.0.stats.failed.fetch_add(1, Relaxed);
                    return answer(
                        StatusCode::GATEWAY_TIMEOUT,
                        "The app did not answer in time.",
                    );
                }
                Ok(Err(error)) if error.is_connect() => {
                    candidate.copy.eject();
                    true
                }
                Ok(Err(_)) => {
                    candidate.copy.eject();
                    let again = retryable_method && !resent;
                    resent |= again;
                    again
                }
            };
            drop(inflight);
            if !retry
                || tried.len() > budget::MAX_RETRIES_PER_REQUEST
                || !self.0.budget.retry(&app.app, Instant::now())
            {
                self.0.stats.failed.fetch_add(1, Relaxed);
                return answer(
                    StatusCode::BAD_GATEWAY,
                    "The app closed the connection without answering.",
                );
            }
            self.0.stats.retried.fetch_add(1, Relaxed);
            if let Some(fresh) = self.table().app_for(host) {
                current = fresh;
            }
        }
    }

    async fn connect_for(
        &self,
        app: &AppRoute,
        tried: &mut Vec<String>,
    ) -> Option<(Candidate, TokioIo<TcpStream>)> {
        let mut connector = self.0.connector.clone();
        loop {
            let candidate = self.pick(app, tried)?;
            tried.push(candidate.copy.replica_id.clone());
            let uri: Uri = format!("http://{}/", authority(&candidate.target))
                .parse()
                .ok()?;
            match tower_service::Service::call(&mut connector, uri).await {
                Ok(io) => return Some((candidate, io)),
                Err(_) => {
                    candidate.copy.eject();
                    if tried.len() > budget::MAX_RETRIES_PER_REQUEST
                        || !self.0.budget.retry(&app.app, Instant::now())
                    {
                        return None;
                    }
                    self.0.stats.retried.fetch_add(1, Relaxed);
                }
            }
        }
    }

    async fn forward_streaming(
        &self,
        app: &Arc<AppRoute>,
        host: &str,
        parts: hyper::http::request::Parts,
        body: Incoming,
        connection: Arc<ConnectionState>,
    ) -> Response<Body> {
        let version = parts.version;
        let mut tried = Vec::new();
        let Some((candidate, io)) = self.connect_for(app, &mut tried).await else {
            self.0.stats.failed.fetch_add(1, Relaxed);
            return answer(
                StatusCode::SERVICE_UNAVAILABLE,
                "No copy of this app is ready. Try again in a moment.",
            );
        };
        let inflight = InFlight::new(candidate.copy.clone(), self.clone(), connection.clone());
        let request = Self::upstream_request(
            &parts,
            &candidate,
            body.map_err(|e| -> BoxError { Box::new(e) }).boxed_unsync(),
        );
        let sent = match candidate.upstream {
            Upstream::Http1 => {
                let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(io).await else {
                    return answer(
                        StatusCode::BAD_GATEWAY,
                        "The app closed the connection without answering.",
                    );
                };
                tokio::spawn(conn);
                tokio::time::timeout(self.0.limits.response_timeout, sender.send_request(request))
                    .await
            }
            Upstream::H2c => {
                let Ok((mut sender, conn)) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await
                else {
                    return answer(
                        StatusCode::BAD_GATEWAY,
                        "The app closed the connection without answering.",
                    );
                };
                tokio::spawn(conn);
                tokio::time::timeout(self.0.limits.response_timeout, sender.send_request(request))
                    .await
            }
        };
        match sent {
            Ok(Ok(response)) => self.finish(
                app, &candidate, response, version, inflight, connection, host,
            ),
            Ok(Err(_)) => {
                self.0.stats.failed.fetch_add(1, Relaxed);
                answer(
                    StatusCode::BAD_GATEWAY,
                    "The app closed the connection without answering.",
                )
            }
            Err(_) => {
                self.0.stats.failed.fetch_add(1, Relaxed);
                answer(
                    StatusCode::GATEWAY_TIMEOUT,
                    "The app did not answer in time.",
                )
            }
        }
    }

    async fn upgrade(
        &self,
        app: &Arc<AppRoute>,
        host: &str,
        parts: hyper::http::request::Parts,
        client_upgrade: hyper::upgrade::OnUpgrade,
        connection: Arc<ConnectionState>,
    ) -> Response<Body> {
        let mut tried = Vec::new();
        let Some((candidate, io)) = self.connect_for(app, &mut tried).await else {
            return answer(
                StatusCode::SERVICE_UNAVAILABLE,
                "No copy of this app is ready. Try again in a moment.",
            );
        };
        let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(io).await else {
            return answer(
                StatusCode::BAD_GATEWAY,
                "The app closed the connection without answering.",
            );
        };
        tokio::spawn(conn.with_upgrades());
        let mut request = Self::upstream_request(&parts, &candidate, empty());
        *request.version_mut() = Version::HTTP_11;
        let inflight = InFlight::new(candidate.copy.clone(), self.clone(), connection.clone());
        let mut response = match tokio::time::timeout(
            self.0.limits.response_timeout,
            sender.send_request(request),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                return answer(
                    StatusCode::BAD_GATEWAY,
                    "The app closed the connection without answering.",
                );
            }
            Err(_) => {
                return answer(
                    StatusCode::GATEWAY_TIMEOUT,
                    "The app did not answer in time.",
                );
            }
        };
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return self.finish(
                app,
                &candidate,
                response,
                Version::HTTP_11,
                inflight,
                connection,
                host,
            );
        }
        let app_upgrade = hyper::upgrade::on(&mut response);
        let idle = self.0.limits.upgraded_idle_timeout;
        let closing = candidate.copy.closing.clone();
        let guard = RequestGuard::new(connection);
        tokio::spawn(async move {
            let (Ok(client), Ok(app)) = (client_upgrade.await, app_upgrade.await) else {
                return;
            };
            let mut client = TokioIo::new(client);
            let mut app = TokioIo::new(app);
            let copying = copy_with_idle(&mut client, &mut app, idle);
            tokio::select! {
                () = closing.cancelled() => {}
                _ = copying => {}
            }
            drop((inflight, guard));
        });
        let (mut parts, _) = response.into_parts();
        parts.headers.remove(header::CONTENT_LENGTH);
        Response::from_parts(parts, empty())
    }
}

async fn copy_with_idle<A, B>(a: &mut A, b: &mut B, idle: Duration) -> std::io::Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let mut a_buf = vec![0u8; 16 * 1024];
    let mut b_buf = vec![0u8; 16 * 1024];
    let (mut a_open, mut b_open) = (true, true);
    while a_open || b_open {
        tokio::select! {
            read = ar.read(&mut a_buf), if a_open => match read? {
                0 => { a_open = false; bw.shutdown().await?; }
                n => bw.write_all(&a_buf[..n]).await?,
            },
            read = br.read(&mut b_buf), if b_open => match read? {
                0 => { b_open = false; aw.shutdown().await?; }
                n => aw.write_all(&b_buf[..n]).await?,
            },
            () = tokio::time::sleep(idle) => return Ok(()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
