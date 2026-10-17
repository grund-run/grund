//! `grund edge`: the entry edge (grund-docs design/traffic.md §6). It
//! accepts public TLS connections for app addresses, terminates TLS with a
//! certificate per name, picks a machine that runs the app and hands the
//! connection to that machine's gate over one `grund/entry/1` stream. It
//! decides only which machine; the gate routes every request.
//!
//! - It enrolls with its instance once, like a relay
//!   (GRUND_EDGE_ENROLLMENT_TOKEN from `grund edges token <host>`), with an
//!   Ed25519 key that is also its iroh key: machines accept entry streams
//!   from it because their documents list it among their entry keys.
//! - Its route table is watched from the instance and kept on disk
//!   ([`routes`], fail-static).
//! - Its certificates are ordered by the instance from CSRs made here and
//!   answered by TLS-ALPN-01 on its own 443 ([`certificates`]); a custom
//!   domain's comes whole from the instance, validated by HTTP-01 on its
//!   port 80 ([`custom`]).
//! - Machines are reached over iroh, through the instance's relays when no
//!   direct path punches, with iroh's default path timeouts ([`machines`]).
//! - Entry bytes are metered by address and path and reported every minute.

pub mod certificates;
pub mod custom;
pub mod machines;
pub mod proxy;
pub mod routes;
pub mod serve;

use std::{collections::HashSet, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use buffa::Message;
use clap::Args;

use crate::{relay_certificate::RelayKey, services::relays::Role};

/// `grund edge`.
#[derive(Clone, Debug, Args)]
pub struct EdgeCommand {
    /// Where the edge accepts TLS connections for app addresses.
    #[arg(long, env = "GRUND_EDGE_LISTEN", default_value = "0.0.0.0:443")]
    pub listen: SocketAddr,

    /// Where it answers plain HTTP with a redirect to https.
    #[arg(long, env = "GRUND_EDGE_HTTP_LISTEN", default_value = "0.0.0.0:80")]
    pub http_listen: SocketAddr,

    /// The UDP address its iroh endpoint binds. Unset: the uplink's
    /// addresses, on any port.
    #[arg(long, env = "GRUND_EDGE_IROH_LISTEN")]
    pub iroh_listen: Option<SocketAddr>,

    /// Where it keeps its key, its enrollment, its route table and its
    /// certificates (each file 0600).
    #[arg(
        long,
        env = "GRUND_EDGE_DATA_DIR",
        default_value = "/var/lib/grund/edge"
    )]
    pub data_dir: PathBuf,

    /// A one-time grund_edge_ token from `grund edges token <host>` on the
    /// instance: the edge enrolls its key with it at its first start, and
    /// ignores it once enrolled.
    #[arg(long, env = "GRUND_EDGE_ENROLLMENT_TOKEN", hide_env_values = true)]
    pub enrollment_token: Option<String>,

    /// The instance whose apps this edge serves, e.g.
    /// https://grund.example.com. Plain http only for loopback.
    #[arg(long = "grund-url", env = "GRUND_URL")]
    pub grund_url: String,

    /// Edge-only relay address for dialing, with the public relay's TLS hostname
    /// and a different port. Never sent to machines or stored in route tables.
    #[arg(long, env = "GRUND_EDGE_RELAY_URL_OVERRIDE")]
    pub relay_url_override: Option<String>,

    /// Open connections one source address may hold (default 256, at most
    /// 1024).
    #[arg(
        long,
        env = "GRUND_EDGE_CONNECTIONS_PER_ADDRESS",
        default_value_t = 256
    )]
    pub connections_per_address: usize,

    /// New TLS handshakes one source address may start each second (default
    /// 50, at most 200).
    #[arg(long, env = "GRUND_EDGE_HANDSHAKES_PER_ADDRESS", default_value_t = 50)]
    pub handshakes_per_address: u32,

    /// The sources (addresses or networks, comma-separated) whose
    /// connections start with a PROXY protocol header (v1 or v2) naming the
    /// client: an L4 proxy passing TLS through by SNI. From these the header
    /// is required; from anywhere else it is never read. Unset: the
    /// connection's own peer is the client.
    #[arg(long, env = "GRUND_EDGE_PROXY_PROTOCOL_FROM", value_delimiter = ',')]
    pub proxy_protocol_from: Vec<proxy::Source>,

    /// Milliseconds allowed for the complete dial, stream open and gate
    /// answer on each candidate (default 1500, at most 5000).
    #[arg(long, env = "GRUND_EDGE_SETUP_ATTEMPT_MS", default_value_t = 1500)]
    pub setup_attempt_ms: u64,

    /// Milliseconds for all candidates before forwarding client bytes
    /// (default 4000, at most 10000).
    #[arg(long, env = "GRUND_EDGE_SETUP_TOTAL_MS", default_value_t = 4000)]
    pub setup_total_ms: u64,

    /// Seconds to finish open connections on SIGTERM.
    #[arg(long, env = "GRUND_SHUTDOWN_GRACE", default_value_t = 10)]
    pub shutdown_grace: u64,
}

impl EdgeCommand {
    /// Refuses a configuration that cannot work, naming what to fix.
    pub fn validate(&self) -> anyhow::Result<()> {
        let origin = crate::config::PublicOrigin::parse(self.grund_url.trim_end_matches('/'))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "GRUND_URL must be the instance's origin, like https://grund.example.com"
                )
            })?;
        anyhow::ensure!(
            origin.https || origin.is_loopback(),
            "GRUND_URL must be https, except on loopback"
        );
        if let Some(url) = &self.relay_url_override {
            RelayDialOverride::parse(url)?;
        }
        if let Some(token) = &self.enrollment_token {
            anyhow::ensure!(
                token.starts_with(crate::services::relays::EDGE_TOKEN_PREFIX),
                "GRUND_EDGE_ENROLLMENT_TOKEN must be a grund_edge_ token from `grund edges token <host>`"
            );
        }
        anyhow::ensure!(
            (1..=1024).contains(&self.connections_per_address),
            "GRUND_EDGE_CONNECTIONS_PER_ADDRESS must be 1 to 1024"
        );
        anyhow::ensure!(
            (1..=200).contains(&self.handshakes_per_address),
            "GRUND_EDGE_HANDSHAKES_PER_ADDRESS must be 1 to 200"
        );
        anyhow::ensure!(
            (1..=5000).contains(&self.setup_attempt_ms),
            "GRUND_EDGE_SETUP_ATTEMPT_MS must be 1 to 5000"
        );
        anyhow::ensure!(
            (self.setup_attempt_ms..=10_000).contains(&self.setup_total_ms),
            "GRUND_EDGE_SETUP_TOTAL_MS must be at least GRUND_EDGE_SETUP_ATTEMPT_MS and at most 10000"
        );
        Ok(())
    }

    fn instance(&self) -> String {
        crate::config::PublicOrigin::parse(self.grund_url.trim_end_matches('/'))
            .map(|origin| origin.serialized)
            .unwrap_or_else(|| self.grund_url.trim_end_matches('/').to_string())
    }

    /// The edge's enrollment, made with the token at its first start.
    pub async fn enrollment(&self) -> anyhow::Result<RelayKey> {
        let instance = self.instance();
        if let Some(key) = RelayKey::load_as(&self.data_dir, Role::Edge).with_context(|| {
            format!(
                "the edge's enrollment in GRUND_EDGE_DATA_DIR {}",
                self.data_dir.display()
            )
        })? {
            anyhow::ensure!(
                key.instance == instance,
                "the edge in GRUND_EDGE_DATA_DIR {} is enrolled with {}, not GRUND_URL {instance}",
                self.data_dir.display(),
                key.instance
            );
            return Ok(key);
        }
        let token = self.enrollment_token.as_deref().context(
            "the edge is not enrolled with its instance: set GRUND_EDGE_ENROLLMENT_TOKEN (from \
             `grund edges token <host>` on the instance)",
        )?;
        let http =
            crate::relay_certificate::http_client(Some(crate::relay_certificate::CALL_TIMEOUT))?;
        let key = RelayKey::enroll_as(&self.data_dir, &instance, token, &http, Role::Edge)
            .await
            .context("GRUND_EDGE_ENROLLMENT_TOKEN: the instance did not enroll this edge")?;
        tracing::info!(edge_id = %key.relay_id, host = %key.host, "edge: enrolled with the instance");
        Ok(key)
    }
}

async fn report_usage(meter: Arc<serve::Edge>, key: RelayKey, http: reqwest::Client) {
    use grund_proto::grund::edge::v1::{ReportUsageRequest, ReportUsageResponse, Usage};
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pending: Vec<Usage> = Vec::new();
    let mut report_id = uuid::Uuid::now_v7();
    loop {
        tick.tick().await;
        for (name, path, bytes_in, bytes_out, connections) in meter.meter.take() {
            pending.push(Usage {
                name,
                path: path.to_string(),
                bytes_in,
                bytes_out,
                connections,
                ..Default::default()
            });
        }
        if pending.is_empty() {
            continue;
        }
        let path = "/grund.edge.v1.EdgeService/ReportUsage";
        let body = ReportUsageRequest {
            report_id: report_id.to_string(),
            usage: pending.iter().take(serve_limit()).cloned().collect(),
            ..Default::default()
        }
        .encode_to_vec();
        let headers = key.headers(path, &body);
        match crate::relay_certificate::unary::<ReportUsageResponse>(
            &http,
            &key.instance,
            path,
            &headers,
            body,
        )
        .await
        {
            Ok(_) => {
                let sent = pending.len().min(serve_limit());
                pending.drain(..sent);
                report_id = uuid::Uuid::now_v7();
            }
            Err(error) => {
                tracing::warn!(
                    error = format!("{error:#}"),
                    "edge: could not report usage; keeping it for the next report"
                )
            }
        }
    }
}

fn serve_limit() -> usize {
    crate::api::edge::MAX_USAGE_ROWS
}

/// Runs `grund edge` until SIGTERM or SIGINT.
pub async fn run(command: EdgeCommand) -> anyhow::Result<()> {
    command.validate()?;
    grund_crypto::install_default();
    std::fs::create_dir_all(&command.data_dir)
        .with_context(|| format!("create GRUND_EDGE_DATA_DIR {}", command.data_dir.display()))?;
    let tls_listener = tokio::net::TcpListener::bind(command.listen)
        .await
        .with_context(|| format!("bind GRUND_EDGE_LISTEN {}", command.listen))?;
    let http_listener = tokio::net::TcpListener::bind(command.http_listen)
        .await
        .with_context(|| format!("bind GRUND_EDGE_HTTP_LISTEN {}", command.http_listen))?;
    tracing::info!(tls = %command.listen, http = %command.http_listen, "edge: listening");
    let key = command.enrollment().await?;
    let routes = routes::Routes::load(&command.data_dir);
    let http = crate::relay_certificate::http_client(Some(crate::relay_certificate::CALL_TIMEOUT))?;
    let names = grund_tls::Names::default();
    let answers = grund_tls::Answers::default();
    let tls = Arc::new(grund_tls::names_server_config(
        names.clone(),
        answers.clone(),
        &[b"h2", b"http/1.1"],
    )?);
    tokio::spawn(routes::watch(routes.clone(), key.clone(), http.clone()));
    let mut changed = routes.subscribe();
    while routes.current().version.is_empty() {
        tracing::info!("edge: waiting for the first route table from the instance");
        let _ = changed.changed().await;
    }
    let relay_override = command
        .relay_url_override
        .as_deref()
        .map(RelayDialOverride::parse)
        .transpose()?;
    if let Some(override_url) = &relay_override {
        override_url.validate_table(&routes.current())?;
    }
    let relays = relay_urls(&routes, relay_override.as_ref());
    let binder = Binder {
        key: iroh::SecretKey::from_bytes(&key.seed()),
        iroh_listen: command.iroh_listen,
        relay_roots: relay_roots()?,
    };
    let endpoint = binder.bind(relays.clone()).await?;
    tracing::info!(edge = %endpoint.id(), host = %key.host, "edge: running");
    let pool = machines::Pool::new(endpoint.clone(), relay_override.clone());
    let edge = Arc::new(serve::Edge {
        routes: routes.clone(),
        pool: pool.clone(),
        tls,
        host: key.host.clone(),
        admission: serve::Admission::new(serve::PerAddress {
            connections: command.connections_per_address,
            handshakes_per_second: f64::from(command.handshakes_per_address),
        }),
        meter: serve::Meter::default(),
        setup_attempt: Duration::from_millis(command.setup_attempt_ms),
        setup_total: Duration::from_millis(command.setup_total_ms),
        proxy_from: command.proxy_protocol_from.clone(),
        clients: Default::default(),
    });
    let instance = crate::relay_certificate::Instance::new(key.clone())?;
    let certificates = certificates::EdgeCertificates::new(
        instance.clone(),
        names,
        answers,
        &command.data_dir,
        routes.clone(),
        custom::Kept::new(&command.data_dir, &key.seed()),
    );
    certificates.load();
    tokio::spawn(certificates.run());
    tokio::spawn(report_usage(edge.clone(), key.clone(), http.clone()));
    tokio::spawn(drain_paused(pool.clone(), routes.clone()));
    tokio::spawn(keep_relays(
        pool.clone(),
        routes.clone(),
        relay_override.clone(),
        relays,
    ));
    tokio::spawn(revive_relay(
        pool.clone(),
        routes.clone(),
        binder,
        relay_override,
        http.clone(),
    ));
    tokio::spawn({
        let pool = pool.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                pool.sweep().await;
            }
        }
    });
    let port80 = Arc::new(serve::Port80 {
        routes: routes.clone(),
        instance,
    });
    tokio::spawn(async move {
        loop {
            if let Ok((tcp, _)) = http_listener.accept().await {
                tokio::spawn(serve::http(port80.clone(), tcp));
            }
        }
    });
    let accepting = {
        let edge = edge.clone();
        async move {
            loop {
                match tls_listener.accept().await {
                    Ok((tcp, peer)) => {
                        tokio::spawn(serve::connection(edge.clone(), tcp, peer));
                    }
                    Err(error) => {
                        tracing::warn!(%error, "edge: accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    };
    tokio::select! {
        () = accepting => {}
        () = shutdown() => {}
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(command.shutdown_grace);
    let notified = pool.drain().await;
    let open = edge.clients.load(std::sync::atomic::Ordering::Relaxed);
    tracing::info!(
        clients = open,
        machines = notified,
        "edge: stopping; no new connections, the open ones close after their current request"
    );
    let draining = tokio::time::Instant::now();
    while edge.clients.load(std::sync::atomic::Ordering::Relaxed) > 0
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tracing::info!(
        left = edge.clients.load(std::sync::atomic::Ordering::Relaxed),
        elapsed_ms = draining.elapsed().as_millis() as u64,
        "edge: drained"
    );
    let _ = tokio::time::timeout_at(deadline, pool.endpoint().close()).await;
    Ok(())
}

async fn drain_paused(pool: machines::Pool, routes: routes::Routes) {
    let mut changed = routes.subscribe();
    let mut previous = HashSet::new();
    loop {
        let paused: HashSet<iroh::EndpointId> = routes
            .current()
            .by_name
            .values()
            .flat_map(|route| route.machines.iter())
            .filter_map(|(id, _, _, paused)| paused.then(|| id.parse().ok()).flatten())
            .collect();
        for id in paused.difference(&previous) {
            let pool = pool.clone();
            let id = *id;
            tokio::spawn(async move {
                if pool.drain_machine(id).await {
                    tracing::info!(
                        "edge: a machine preparing to migrate is draining its client connections"
                    );
                }
            });
        }
        previous = paused;
        if changed.changed().await.is_err() {
            return;
        }
    }
}

async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

#[derive(Debug, Clone)]
struct Binder {
    key: iroh::SecretKey,
    iroh_listen: Option<std::net::SocketAddr>,
    relay_roots: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
}

impl Binder {
    async fn bind(&self, relays: Vec<iroh::RelayUrl>) -> anyhow::Result<iroh::Endpoint> {
        grund_net::endpoint::bind_now(
            self.key.clone(),
            &grund_net::endpoint::NetConfig {
                relays,
                bind: match self.iroh_listen {
                    Some(addr) => grund_net::endpoint::Bind::Addrs(vec![addr]),
                    None => grund_net::endpoint::Bind::Uplinks(0),
                },
                relay_roots: self.relay_roots.clone(),
                path_idle: Duration::from_secs(5),
                path_keepalive: Duration::from_secs(1),
            },
            Vec::new(),
        )
        .await
        .context("bind the edge's iroh endpoint")
    }
}

#[derive(Debug, Clone)]
pub(super) struct RelayDialOverride {
    url: iroh::RelayUrl,
}

impl RelayDialOverride {
    fn parse(value: &str) -> anyhow::Result<Self> {
        let url: iroh::RelayUrl = value
            .parse()
            .context("GRUND_EDGE_RELAY_URL_OVERRIDE must be an https relay origin")?;
        anyhow::ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.port().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "GRUND_EDGE_RELAY_URL_OVERRIDE must be an https relay origin with an explicit port and no credentials, path, query or fragment"
        );
        Ok(Self { url })
    }

    fn validate_table(&self, table: &routes::Table) -> anyhow::Result<()> {
        anyhow::ensure!(
            table.relay_urls.iter().any(|public| public
                .parse::<iroh::RelayUrl>()
                .is_ok_and(|url| self.matches(&url))),
            "GRUND_EDGE_RELAY_URL_OVERRIDE hostname must match a public relay in the route table"
        );
        Ok(())
    }

    fn matches(&self, public: &iroh::RelayUrl) -> bool {
        public.scheme() == "https" && public.host_str() == self.url.host_str()
    }

    fn dial(&self, public: iroh::RelayUrl) -> iroh::RelayUrl {
        if self.matches(&public) {
            self.url.clone()
        } else {
            public
        }
    }
}

fn relay_urls(
    routes: &routes::Routes,
    override_url: Option<&RelayDialOverride>,
) -> Vec<iroh::RelayUrl> {
    routes
        .current()
        .relay_urls
        .iter()
        .filter_map(|u| u.parse().ok())
        .map(|url| match override_url {
            Some(dial) => dial.dial(url),
            None => url,
        })
        .collect()
}

/// How often the edge looks at its home relay while it is lost.
pub const RELAY_REVIVE_POLL: Duration = Duration::from_millis(250);
/// How long the home relay is lost before the edge asks whether it is back.
pub const RELAY_REVIVE_AFTER: Duration = Duration::from_secs(1);
/// The least time between two new endpoints.
pub const RELAY_REVIVE_COOLDOWN: Duration = Duration::from_secs(5);

async fn revive_relay(
    pool: machines::Pool,
    routes: routes::Routes,
    binder: Binder,
    override_url: Option<RelayDialOverride>,
    http: reqwest::Client,
) {
    let mut lost_since: Option<tokio::time::Instant> = None;
    let mut last_revival: Option<tokio::time::Instant> = None;
    loop {
        tokio::time::sleep(RELAY_REVIVE_POLL).await;
        let Some(home) = grund_net::endpoint::unanswering_home(&pool.endpoint()) else {
            lost_since = None;
            continue;
        };
        let since = *lost_since.get_or_insert_with(tokio::time::Instant::now);
        if since.elapsed() < RELAY_REVIVE_AFTER
            || last_revival.is_some_and(|at| at.elapsed() < RELAY_REVIVE_COOLDOWN)
            || pool.all_direct()
            || pool.has_open_streams()
        {
            continue;
        }
        let answered = http
            .get(grund_net::endpoint::relay_ping_url(&home))
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        if !answered {
            continue;
        }
        if pool.has_open_streams() {
            continue;
        }
        last_revival = Some(tokio::time::Instant::now());
        lost_since = None;
        pool.endpoint().close().await;
        loop {
            match binder
                .bind(relay_urls(&routes, override_url.as_ref()))
                .await
            {
                Ok(endpoint) => {
                    pool.replace_closed_endpoint(endpoint);
                    tracing::info!(relay = %home, "edge: the home relay answers again; dialing machines from a new endpoint rather than waiting out iroh's backoff");
                    break;
                }
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "edge: could not rebind after closing the old endpoint; retrying");
                    tokio::time::sleep(RELAY_REVIVE_COOLDOWN).await;
                }
            }
        }
    }
}

async fn keep_relays(
    pool: machines::Pool,
    routes: routes::Routes,
    override_url: Option<RelayDialOverride>,
    mut have: Vec<iroh::RelayUrl>,
) {
    let mut changed = routes.subscribe();
    while changed.changed().await.is_ok() {
        let endpoint = pool.endpoint();
        let wanted = relay_urls(&routes, override_url.as_ref());
        for url in have.iter().filter(|u| !wanted.contains(u)) {
            endpoint.remove_relay(url).await;
        }
        for url in wanted.iter().filter(|u| !have.contains(u)) {
            endpoint
                .insert_relay(url.clone(), Arc::new(iroh::RelayConfig::from(url.clone())))
                .await;
            tracing::info!(relay = %url, "edge: relay added");
        }
        have = wanted;
    }
}

fn relay_roots() -> anyhow::Result<Option<Vec<rustls::pki_types::CertificateDer<'static>>>> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let Some(path) = std::env::var_os("SSL_CERT_FILE") else {
        return Ok(None);
    };
    let pem = std::fs::read(&path)
        .with_context(|| format!("read SSL_CERT_FILE {}", path.to_string_lossy()))?;
    let roots: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
        .filter_map(Result::ok)
        .collect();
    Ok((!roots.is_empty()).then_some(roots))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reviving_a_slow_relay_closes_the_old_edge_before_rebinding() -> anyhow::Result<()> {
        grund_crypto::install_default();
        let ping = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let relay: iroh::RelayUrl = format!("http://{}/", ping.local_addr()?).parse()?;
        let ping_task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = ping.accept().await {
                tokio::spawn(async move {
                    let mut request = [0; 1024];
                    if let Ok(size) = socket.read(&mut request).await {
                        let status = if request[..size].starts_with(b"GET /ping ") {
                            "200 OK"
                        } else {
                            "503 Service Unavailable"
                        };
                        let reply = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = socket.write_all(reply.as_bytes()).await;
                    }
                });
            }
        });
        let dir = std::env::temp_dir().join(format!("grund-edge-revival-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir)?;
        let routes = routes::Routes::load(&dir);
        routes.install(&grund_proto::grund::edge::v1::RouteTable {
            version: "first".into(),
            relay_urls: vec![relay.to_string()],
            ..Default::default()
        })?;
        let binder = Binder {
            key: iroh::SecretKey::from_bytes(&[7; 32]),
            iroh_listen: None,
            relay_roots: None,
        };
        let old = binder.bind(vec![relay.clone()]).await?;
        let pool = machines::Pool::new(old.clone(), None);
        tokio::time::timeout(Duration::from_secs(5), async {
            while grund_net::endpoint::unanswering_home(&old).is_none() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        let http = reqwest::Client::new();
        anyhow::ensure!(
            http.get(grund_net::endpoint::relay_ping_url(&relay))
                .send()
                .await?
                .status()
                .is_success()
        );
        let revival = tokio::spawn(revive_relay(pool.clone(), routes, binder, None, http));
        let switched = tokio::time::timeout(Duration::from_secs(5), async {
            while pool.generation() == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok();
        let old_closed_before_switch = old.is_closed();
        let replacement_running = !pool.endpoint().is_closed();
        revival.abort();
        pool.endpoint().close().await;
        old.close().await;
        ping_task.abort();
        std::fs::remove_dir_all(dir)?;
        anyhow::ensure!(
            switched,
            "a recovered relay did not get a fresh edge endpoint"
        );
        anyhow::ensure!(
            old_closed_before_switch,
            "the edge registered its new endpoint before closing the old one"
        );
        anyhow::ensure!(
            replacement_running,
            "the replacement edge endpoint is not live"
        );
        Ok(())
    }
}
