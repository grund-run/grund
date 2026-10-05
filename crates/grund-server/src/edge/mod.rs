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
//!   answered by TLS-ALPN-01 on its own 443 ([`certificates`]).
//! - Machines are reached over iroh, through the instance's relays when no
//!   direct path punches, with iroh's default path timeouts ([`machines`]).
//! - Entry bytes are metered by address and path and reported every minute.

pub mod certificates;
pub mod machines;
pub mod proxy;
pub mod routes;
pub mod serve;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

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
    grund_tls::install_default();
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
    let relays = relay_urls(&routes);
    let binder = Binder {
        key: iroh::SecretKey::from_bytes(&key.seed()),
        iroh_listen: command.iroh_listen,
        relay_roots: relay_roots()?,
    };
    let endpoint = binder.bind(relays.clone()).await?;
    tracing::info!(edge = %endpoint.id(), host = %key.host, "edge: running");
    let pool = machines::Pool::new(endpoint.clone());
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
        proxy_from: command.proxy_protocol_from.clone(),
    });
    let certificates = certificates::EdgeCertificates::new(
        crate::relay_certificate::Instance::new(key.clone())?,
        names,
        answers,
        &command.data_dir,
        routes.clone(),
    );
    certificates.load();
    tokio::spawn(certificates.run());
    tokio::spawn(report_usage(edge.clone(), key.clone(), http.clone()));
    tokio::spawn(keep_relays(pool.clone(), routes.clone(), relays));
    tokio::spawn(revive_relay(
        pool.clone(),
        routes.clone(),
        binder,
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
    tokio::spawn(async move {
        loop {
            if let Ok((tcp, _)) = http_listener.accept().await {
                tokio::spawn(serve::http(tcp));
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
    tracing::info!("edge: stopping");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(command.shutdown_grace);
    let _ = tokio::time::timeout_at(deadline, pool.endpoint().close()).await;
    Ok(())
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
                path_idle: Duration::from_secs(15),
                path_keepalive: Duration::from_secs(5),
            },
            Vec::new(),
        )
        .await
        .context("bind the edge's iroh endpoint")
    }
}

fn relay_urls(routes: &routes::Routes) -> Vec<iroh::RelayUrl> {
    routes
        .current()
        .relay_urls
        .iter()
        .filter_map(|u| u.parse().ok())
        .collect()
}

/// How often the edge looks at its home relay while it is lost.
pub const RELAY_REVIVE_POLL: Duration = Duration::from_millis(250);
/// How long the home relay is lost before the edge asks whether it is back.
pub const RELAY_REVIVE_AFTER: Duration = Duration::from_secs(1);
/// The least time between two new endpoints.
pub const RELAY_REVIVE_COOLDOWN: Duration = Duration::from_secs(5);
/// How long streams on a replaced endpoint may carry on.
pub const REPLACED_ENDPOINT_GRACE: Duration = Duration::from_secs(60);

async fn revive_relay(
    pool: machines::Pool,
    routes: routes::Routes,
    binder: Binder,
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
        last_revival = Some(tokio::time::Instant::now());
        lost_since = None;
        if binder.iroh_listen.is_some_and(|a| a.port() != 0) {
            pool.endpoint().close().await;
        }
        match binder.bind(relay_urls(&routes)).await {
            Ok(endpoint) => {
                let old = pool.replace_endpoint(endpoint);
                tracing::info!(relay = %home, "edge: the home relay answers again; dialing machines from a new endpoint rather than waiting out iroh's backoff");
                tokio::spawn(async move {
                    tokio::time::sleep(REPLACED_ENDPOINT_GRACE).await;
                    old.close().await;
                });
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "edge: could not bind a new endpoint; keeping the one it has");
            }
        }
    }
}

async fn keep_relays(pool: machines::Pool, routes: routes::Routes, mut have: Vec<iroh::RelayUrl>) {
    let mut changed = routes.subscribe();
    while changed.changed().await.is_ok() {
        let endpoint = pool.endpoint();
        let wanted = relay_urls(&routes);
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
