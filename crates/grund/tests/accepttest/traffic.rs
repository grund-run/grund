use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::accepttest::{
    fixtures::{
        FakeRegistry, Given, Then, When, external_target,
        pebble::{Pebble, free_port},
        random_hex, testcase_configured,
    },
    machines::{Running, origin},
};

const APPS: &str = "/grund.app.v1.AppService";
const MACHINES: &str = "/grund.machine.v1.MachineService";

pub(super) struct Agent {
    dir: PathBuf,
    child: std::process::Child,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Agent {
    fn kill_container(&self, replica_id: &str) -> anyhow::Result<()> {
        let dir = self.dir.join("simulated-containers/kill");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(replica_id), b"")?;
        Ok(())
    }

    fn remote_file(&self) -> PathBuf {
        self.dir.join("remote-copies.json")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("agent.log")).unwrap_or_default()
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        let stopped = std::process::Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()?;
        anyhow::ensure!(stopped.success(), "kill -TERM failed");
        while self.child.try_wait()?.is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }

    fn start(&mut self) -> anyhow::Result<()> {
        self.child = spawn_agent(&self.dir)?;
        Ok(())
    }
}

fn spawn_agent(dir: &Path) -> anyhow::Result<std::process::Child> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("agent.log"))?;
    Ok(
        std::process::Command::new(crate::accepttest::fixtures::grund_binary())
            .args([
                "agent",
                "--app-runtime",
                "simulated",
                "--interval",
                "1",
                "--data-dir",
            ])
            .arg(dir)
            .arg("--policy")
            .arg(dir.join("policy.yaml"))
            .arg("--gate-remote-copies")
            .arg(dir.join("remote-copies.json"))
            .env_clear()
            .env("RUST_LOG", "grund_agent=debug,info")
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    )
}

async fn appears(within: Duration, before: usize, read: impl Fn() -> usize) -> Option<Instant> {
    let started = Instant::now();
    while started.elapsed() < within {
        if read() > before {
            return Some(Instant::now());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

fn simulated_address(replica_id: &str) -> Ipv4Addr {
    let digest = Sha256::digest(replica_id.as_bytes());
    Ipv4Addr::new(127, digest[0].max(1), digest[1], digest[2].clamp(1, 254))
}

pub(super) struct Stack {
    pub(super) pebble: Pebble,
    registry: FakeRegistry,
    pub(super) given: Given,
    pub(super) when: When,
    pub(super) then: Then,
    domain: String,
    edge_host: String,
    pub(super) edge_dir: PathBuf,
    pub(super) edge: Option<Running>,
    http_port: u16,
    pub(super) roots: Arc<rustls::RootCertStore>,
}

fn dir(prefix: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{prefix}-{}", random_hex(6)))
}

fn database_url(when: &When) -> String {
    when.testcase
        .fixture
        .database_url()
        .expect("a spawned instance has a database")
}

async fn a_stack() -> anyhow::Result<Option<Stack>> {
    a_stack_with(&[]).await
}

pub(super) async fn a_stack_with(extra: &[(&str, &str)]) -> anyhow::Result<Option<Stack>> {
    if external_target().is_some() {
        return Ok(None);
    }
    let Some(pebble) = Pebble::start(free_port()).await? else {
        return Ok(None);
    };
    let registry = FakeRegistry::start().await?;
    let domain = format!("apps-{}.localhost", random_hex(4));
    let edge_host = format!("edge-{}.localhost", random_hex(4));
    let relay_port = free_port();
    let mut env = pebble.acme_settings();
    env.extend([
        (
            "GRUND_INSECURE_REGISTRIES".to_string(),
            registry.host.clone(),
        ),
        ("GRUND_APP_DOMAIN".into(), domain.clone()),
        ("GRUND_EDGES".into(), edge_host.clone()),
        (
            "GRUND_RELAY_ADDRESS".into(),
            format!("127.0.0.1:{relay_port}"),
        ),
        (
            "GRUND_RELAY_URL".into(),
            format!("http://127.0.0.1:{relay_port}"),
        ),
    ]);
    env.push((
        "GRUND_DNS_RESOLVER".into(),
        format!("127.0.0.1:{}", pebble.dns_port),
    ));
    env.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let Some((given, when, then)) = testcase_configured(&pairs).await? else {
        return Ok(None);
    };
    let roots = pebble.roots().await?;
    let http_port = pebble.http_port;
    Ok(Some(Stack {
        pebble,
        registry,
        given,
        when,
        then,
        domain,
        edge_host,
        edge_dir: dir("edge"),
        edge: None,
        http_port,
        roots,
    }))
}

impl Stack {
    fn edges(&self, args: &[&str]) -> anyhow::Result<std::process::Output> {
        Ok(
            std::process::Command::new(crate::accepttest::fixtures::grund_binary())
                .arg("edges")
                .args(args)
                .env_clear()
                .env("DATABASE_URL", database_url(&self.when))
                .output()?,
        )
    }

    pub(super) fn start_edge(&mut self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.edge_dir)?;
        let mut command = std::process::Command::new(crate::accepttest::fixtures::grund_binary());
        if !self.edge_dir.join("edge.key").exists() {
            let output = self.edges(&["token", &self.edge_host])?;
            anyhow::ensure!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            command.env(
                "GRUND_EDGE_ENROLLMENT_TOKEN",
                String::from_utf8(output.stdout)?.trim(),
            );
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.edge_dir.join("edge.log"))?;
        command
            .arg("edge")
            .args(["--listen", &format!("127.0.0.1:{}", self.pebble.tls_port)])
            .args(["--http-listen", &format!("127.0.0.1:{}", self.http_port)])
            .args(["--iroh-listen", "127.0.0.1:0"])
            .args(["--grund-url", &origin(&self.when)])
            .arg("--data-dir")
            .arg(self.edge_dir.join("data"))
            .env("RUST_LOG", "grund_server=debug,info")
            .stdout(log.try_clone()?)
            .stderr(log);
        self.edge = Some(Running(command.spawn()?));
        Ok(())
    }

    pub(super) fn edge_log(&self) -> String {
        std::fs::read_to_string(self.edge_dir.join("edge.log")).unwrap_or_default()
    }

    async fn call(&self, procedure: &str, body: Value) -> anyhow::Result<Value> {
        self.when
            .calling(&format!("{APPS}/{procedure}"), &body.to_string())
            .await?;
        self.then
            .status(200)
            .map_err(|e| e.context(procedure.to_string()))?;
        self.then.json()
    }

    pub(super) async fn a_machine(&self, organisation: &str, name: &str) -> anyhow::Result<Agent> {
        self.when
            .calling(
                &format!("{MACHINES}/CreateJoinToken"),
                &json!({"organisation": organisation, "name": name}).to_string(),
            )
            .await?;
        let token = self.then.json()?["token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let dir = dir("traffic-agent");
        let url = origin(&self.when);
        let joined = {
            let dir = dir.clone();
            tokio::task::spawn_blocking(move || {
                std::process::Command::new(crate::accepttest::fixtures::grund_binary())
                    .arg("join")
                    .arg("--data-dir")
                    .arg(&dir)
                    .args(["--url", &url, &token])
                    .env_clear()
                    .env("RUST_LOG", "warn")
                    .output()
            })
            .await??
        };
        anyhow::ensure!(
            joined.status.success(),
            "{}",
            String::from_utf8_lossy(&joined.stderr)
        );
        let child = spawn_agent(&dir)?;
        Ok(Agent { dir, child })
    }

    pub(super) async fn deploy(
        &self,
        organisation: &str,
        app: &str,
        tag: &str,
        copies: u32,
    ) -> anyhow::Result<()> {
        self.registry.publish(&format!("acme/{app}"), tag);
        if self
            .call("GetApp", json!({"organisation": organisation, "name": app}))
            .await
            .is_err()
        {
            self.call(
                "CreateApp",
                json!({"organisation": organisation, "name": app, "settings": {
                    "copies": copies,
                    "rollout": {"minReadySeconds": 1, "readyDeadlineSeconds": 20, "drainSeconds": 5},
                    "rescheduleAfterSeconds": 60,
                }}),
            )
            .await?;
        }
        self.call(
            "Deploy",
            json!({"organisation": organisation, "name": app, "spec": {
                "image": self.registry.image(&format!("acme/{app}"), tag),
                "ports": [{"name": "web", "port": 8080, "protocol": "PROTOCOL_HTTP", "public": true}],
                "resources": {"memoryMib": "64", "cpuMillis": 100},
                "env": [{"name": "PORT", "value": "8080"}, {"name": "RELEASE", "value": tag}],
                "check": {"httpPath": "/", "port": 8080, "intervalMs": 500, "timeoutMs": 300},
                "stop": {"graceSeconds": 1},
            }}),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn app(&self, organisation: &str, app: &str) -> anyhow::Result<Value> {
        Ok(self
            .call("GetApp", json!({"organisation": organisation, "name": app}))
            .await?["app"]
            .clone())
    }

    pub(super) async fn until(
        &self,
        organisation: &str,
        app: &str,
        within: Duration,
        what: &str,
        done: impl Fn(&Value) -> bool,
    ) -> anyhow::Result<Value> {
        let started = Instant::now();
        loop {
            let value = self.app(organisation, app).await?;
            if done(&value) {
                return Ok(value);
            }
            anyhow::ensure!(
                started.elapsed() < within,
                "{what} within {within:?}: {value:#}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub(super) fn name_of(&self, organisation: &str, app: &str) -> String {
        format!("{app}-{organisation}.{}", self.domain)
    }

    pub(super) async fn connect(&self, name: &str) -> anyhow::Result<Conn> {
        Conn::open(name, self.pebble.tls_port, self.roots.clone(), None).await
    }

    pub(super) async fn served(&self, name: &str, within: Duration) -> anyhow::Result<()> {
        let started = Instant::now();
        loop {
            let attempt = async {
                let mut conn = self.connect(name).await?;
                let answer = conn.get(name, "/", &[]).await?;
                anyhow::ensure!(answer.status == 200, "{}", answer.text());
                Ok(())
            }
            .await;
            match attempt {
                Ok(()) => return Ok(()),
                Err(error) if started.elapsed() > within => {
                    return Err(error.context(format!(
                        "{name} served over https within {within:?}; edge log:\n{}",
                        self.edge_log()
                    )));
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }
}

fn running_replicas(app: &Value) -> Vec<(String, String)> {
    app["replicas"]
        .as_array()
        .map(|replicas| {
            replicas
                .iter()
                .filter(|r| r["state"] == "REPLICA_STATE_RUNNING" && r["observed"]["ready"] == true)
                .map(|r| {
                    (
                        r["replicaId"].as_str().unwrap_or_default().to_string(),
                        r["machineName"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn write_remote_copies(agents: &[(&str, &Agent)], app: &str, replicas: &[(String, String)]) {
    for (machine, agent) in agents {
        let elsewhere: Vec<Value> = replicas
            .iter()
            .filter(|(_, on)| on != machine)
            .map(|(id, on)| {
                json!({
                    "replica_id": id,
                    "app": app,
                    "machine_id": on,
                    "address": IpAddr::V4(simulated_address(id)).to_string(),
                    "ports": [8080],
                })
            })
            .collect();
        let _ = std::fs::write(
            agent.remote_file(),
            serde_json::to_vec(&elsewhere).unwrap_or_default(),
        );
    }
}

pub(super) struct Answer {
    pub(super) status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    pub(super) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(super) struct Conn {
    io: Box<dyn Io>,
    buffer: Vec<u8>,
    closed: bool,
}

struct Segmented {
    inner: TcpStream,
    segment: usize,
}

impl AsyncRead for Segmented {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Segmented {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let n = buf.len().min(self.segment);
        std::pin::Pin::new(&mut self.inner).poll_write(cx, &buf[..n])
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn client_config(
    roots: Arc<rustls::RootCertStore>,
    post_quantum_only: bool,
) -> rustls::ClientConfig {
    let mut provider = grund_tls::provider().as_ref().clone();
    if post_quantum_only {
        provider
            .kx_groups
            .retain(|g| g.name() == rustls::NamedGroup::X25519MLKEM768);
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

impl Conn {
    async fn open(
        name: &str,
        port: u16,
        roots: Arc<rustls::RootCertStore>,
        segments: Option<usize>,
    ) -> anyhow::Result<Self> {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
        tcp.set_nodelay(true)?;
        let server_name = rustls::pki_types::ServerName::try_from(name.to_string())?;
        let mut config = client_config(roots, segments.is_some());
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let io: Box<dyn Io> = match segments {
            Some(segment) => Box::new(
                tokio::time::timeout(
                    Duration::from_secs(10),
                    connector.connect(
                        server_name,
                        Segmented {
                            inner: tcp,
                            segment,
                        },
                    ),
                )
                .await??,
            ),
            None => Box::new(
                tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
                    .await??,
            ),
        };
        Ok(Self {
            io,
            buffer: Vec::new(),
            closed: false,
        })
    }

    pub(super) async fn get(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<Answer> {
        anyhow::ensure!(!self.closed, "the connection was closed");
        let mut request =
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: grund-accepttest\r\n");
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        self.io.write_all(request.as_bytes()).await?;
        self.io.flush().await?;
        let read = async {
            let head_end = loop {
                if let Some(at) = self.buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at;
                }
                let mut chunk = [0u8; 8192];
                let n = self.io.read(&mut chunk).await?;
                anyhow::ensure!(n > 0, "the connection closed before a response");
                self.buffer.extend_from_slice(&chunk[..n]);
            };
            let head = String::from_utf8_lossy(&self.buffer[..head_end]).into_owned();
            let mut lines = head.split("\r\n");
            let status: u16 = lines
                .next()
                .and_then(|l| l.split(' ').nth(1))
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| anyhow::anyhow!("no status line: {head}"))?;
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect();
            let length: usize = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            self.buffer.drain(..head_end + 4);
            while self.buffer.len() < length {
                let mut chunk = [0u8; 8192];
                let n = self.io.read(&mut chunk).await?;
                anyhow::ensure!(n > 0, "the connection closed inside a body");
                self.buffer.extend_from_slice(&chunk[..n]);
            }
            let body: Vec<u8> = self.buffer.drain(..length).collect();
            Ok::<_, anyhow::Error>(Answer {
                status,
                headers,
                body,
            })
        };
        let answer = tokio::time::timeout(Duration::from_secs(15), read).await??;
        if answer
            .header("connection")
            .is_some_and(|c| c.eq_ignore_ascii_case("close"))
        {
            self.closed = true;
        }
        Ok(answer)
    }
}

fn load_failure(
    worker: usize,
    started: SystemTime,
    phase: &str,
    error: impl std::fmt::Display,
) -> String {
    let started_unix_ms = started
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("worker={worker} started_unix_ms={started_unix_ms} phase={phase} error={error}")
}

#[derive(Default)]
struct Load {
    ok: AtomicU64,
    failed: AtomicU64,
    stop: AtomicBool,
    failures: Mutex<Vec<String>>,
}

fn load(
    stack: &Stack,
    name: &str,
    connections: usize,
) -> (Arc<Load>, Vec<tokio::task::JoinHandle<()>>) {
    let tally = Arc::new(Load::default());
    let handles = (0..connections)
        .map(|worker| {
            let (tally, name, port, roots) = (
                tally.clone(),
                name.to_string(),
                stack.pebble.tls_port,
                stack.roots.clone(),
            );
            tokio::spawn(async move {
                let mut conn: Option<Conn> = None;
                let mut accepted = false;
                while !tally.stop.load(Relaxed) {
                    if conn.as_ref().is_none_or(|c| c.closed) {
                        let started = SystemTime::now();
                        match Conn::open(&name, port, roots.clone(), None).await {
                            Ok(c) => {
                                conn = Some(c);
                                accepted = false;
                            }
                            Err(error) => {
                                tally.failed.fetch_add(1, Relaxed);
                                tally.failures.lock().push(load_failure(
                                    worker,
                                    started,
                                    "handshake",
                                    format_args!("{error:#}"),
                                ));
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                continue;
                            }
                        }
                    }
                    let Some(c) = conn.as_mut() else { continue };
                    let started = SystemTime::now();
                    match c.get(&name, "/?wait=5", &[]).await {
                        Ok(answer) if answer.status == 200 => {
                            accepted = true;
                            tally.ok.fetch_add(1, Relaxed);
                        }
                        Ok(answer) => {
                            let phase = if answer.status == 503
                                && answer.body == b"No machine is serving this app right now. Try again in a moment.\n"
                            {
                                "before_accept"
                            } else {
                                "after_accept"
                            };
                            tally.failed.fetch_add(1, Relaxed);
                            tally.failures.lock().push(load_failure(
                                worker,
                                started,
                                phase,
                                format_args!("HTTP {} {}", answer.status, answer.text()),
                            ));
                        }
                        Err(error) => {
                            tally.failed.fetch_add(1, Relaxed);
                            tally.failures.lock().push(load_failure(
                                worker,
                                started,
                                if accepted { "after_accept" } else { "accept_unconfirmed" },
                                format_args!("{error:#}"),
                            ));
                            conn = None;
                        }
                    }
                }
            })
        })
        .collect();
    (tally, handles)
}

const FAILOVER_WHOLE: Duration = Duration::from_secs(4);
const FAILOVER_EJECTED: Duration = Duration::from_millis(1200);

struct PausedAgent(u32);

impl PausedAgent {
    fn new(agent: &Agent) -> anyhow::Result<Self> {
        let pid = agent.child.id();
        let status = std::process::Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .status()?;
        anyhow::ensure!(status.success(), "could not SIGSTOP agent {pid}");
        Ok(Self(pid))
    }
}

impl Drop for PausedAgent {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .args(["-CONT", &self.0.to_string()])
            .status();
    }
}

#[derive(Debug, Clone)]
struct UnansweringGate {
    entered: Arc<AtomicU64>,
    client_bytes: Arc<AtomicU64>,
}

impl iroh::protocol::ProtocolHandler for UnansweringGate {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        while let Ok((_send, mut recv)) = connection.accept_bi().await {
            let counters = self.clone();
            tokio::spawn(async move {
                let mut length = [0u8; 2];
                if recv.read_exact(&mut length).await.is_ok() {
                    let length = usize::from(u16::from_be_bytes(length));
                    let mut header = vec![0u8; length.min(4096)];
                    if length <= 4096
                        && recv.read_exact(&mut header).await.is_ok()
                        && serde_json::from_slice::<Value>(&header)
                            .ok()
                            .and_then(|header| header["host"].as_str().map(str::to_string))
                            .is_some()
                    {
                        counters.entered.fetch_add(1, Relaxed);
                        let mut byte = [0u8; 1];
                        if matches!(
                            tokio::time::timeout(Duration::from_secs(6), AsyncReadExt::read(&mut recv, &mut byte)).await,
                            Ok(Ok(n)) if n > 0
                        ) {
                            counters.client_bytes.fetch_add(1, Relaxed);
                        }
                    }
                }
            });
        }
        Ok(())
    }
}

struct StandinGate {
    _router: iroh::protocol::Router,
    counters: UnansweringGate,
}

async fn unanswering_gate(agent: &Agent) -> anyhow::Result<StandinGate> {
    let seed: [u8; 32] =
        hex::decode(std::fs::read_to_string(agent.dir.join("machine.key"))?.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("the joined machine key is not 32 bytes"))?;
    let record: Value = serde_json::from_slice(&std::fs::read(agent.dir.join("machine.json"))?)?;
    let relays: Vec<iroh::RelayUrl> = record["network"]["relay_urls"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("the joined machine has no relays"))?
        .iter()
        .map(|url| {
            url.as_str()
                .ok_or_else(|| anyhow::anyhow!("non-string relay URL"))?
                .parse()
                .map_err(Into::into)
        })
        .collect::<anyhow::Result<_>>()?;
    let config = grund_net::endpoint::NetConfig {
        relays,
        bind: grund_net::endpoint::Bind::Addrs(vec!["127.0.0.1:0".parse()?]),
        ..Default::default()
    };
    let endpoint = grund_net::endpoint::bind(
        grund_net::key::secret_key(&seed),
        &config,
        vec![b"grund/entry/1".to_vec()],
    )
    .await?;
    let counters = UnansweringGate {
        entered: Arc::new(AtomicU64::new(0)),
        client_bytes: Arc::new(AtomicU64::new(0)),
    };
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(b"grund/entry/1", counters.clone())
        .spawn();
    Ok(StandinGate {
        _router: router,
        counters,
    })
}

async fn two_ready_copies(
    start_edge: bool,
) -> anyhow::Result<Option<(Stack, Agent, Agent, String, Vec<(String, String)>)>> {
    let Some(mut stack) = a_stack().await? else {
        return Ok(None);
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let a = stack.a_machine(&org, "box-a").await?;
    let b = stack.a_machine(&org, "box-b").await?;
    stack.deploy(&org, "failover", "1", 2).await?;
    let running = stack
        .until(
            &org,
            "failover",
            Duration::from_secs(40),
            "two ready copies on distinct machines",
            |app| {
                let copies = running_replicas(app);
                copies.len() == 2
                    && copies[0].1 != copies[1].1
                    && app["replicas"].as_array().is_some_and(|replicas| {
                        replicas
                            .iter()
                            .all(|replica| replica["observed"]["ready"] == true)
                    })
            },
        )
        .await?;
    let copies = running_replicas(&running);
    write_remote_copies(&[("box-a", &a), ("box-b", &b)], "failover", &copies);
    let name = stack.name_of(&org, "failover");
    if start_edge {
        stack.start_edge()?;
        stack.served(&name, Duration::from_secs(60)).await?;
    }
    Ok(Some((stack, a, b, name, copies)))
}

async fn new_failover_connection(
    stack: &Stack,
    name: &str,
    expected_replica: &str,
    budget: Duration,
) -> anyhow::Result<Duration> {
    let started = Instant::now();
    let attempt = async {
        let mut conn = stack.connect(name).await?;
        let answer = conn.get(name, "/?wait=5", &[]).await?;
        anyhow::ensure!(
            answer.status == 200 && answer.header("x-replica") == Some(expected_replica),
            "new connection got {} from {:?}, expected {expected_replica}: {}",
            answer.status,
            answer.header("x-replica"),
            answer.text(),
        );
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(budget, attempt).await??;
    Ok(started.elapsed())
}

async fn keep_healthy_while_failing(
    stack: &Stack,
    name: &str,
    healthy: &mut Conn,
    expected_replica: &str,
) -> anyhow::Result<()> {
    let answer = tokio::time::timeout(FAILOVER_WHOLE, healthy.get(name, "/?wait=5", &[])).await??;
    anyhow::ensure!(
        answer.status == 200 && answer.header("x-replica") == Some(expected_replica),
        "established healthy connection broke: {} {:?}\n{}",
        answer.status,
        answer.header("x-replica"),
        stack.edge_log()
    );
    Ok(())
}

async fn edge_falls_back_during_fault(
    stack: &Stack,
    name: &str,
    healthy: &mut Conn,
    healthy_replica: &str,
    gate_entered: Option<&AtomicU64>,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let mut fault_attempt_started = None;
    while started.elapsed() < Duration::from_secs(12) {
        let attempted_at = Instant::now();
        let latency = new_failover_connection(stack, name, healthy_replica, FAILOVER_WHOLE).await?;
        let faulty_answered = gate_entered
            .map(|entered| entered.load(Relaxed) > 0)
            .unwrap_or(latency >= Duration::from_millis(700));
        if faulty_answered {
            fault_attempt_started = Some(attempted_at);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::ensure!(
        fault_attempt_started.is_some(),
        "no new connection reached or waited for the faulty machine:\n{}",
        stack.edge_log()
    );
    anyhow::ensure!(
        started.elapsed() < Duration::from_secs(10),
        "the first failed candidate took too long: {:?}\n{}",
        started.elapsed(),
        stack.edge_log()
    );
    let fault_attempt_started = fault_attempt_started.expect("the fault was observed");
    for _ in 0..4 {
        anyhow::ensure!(
            fault_attempt_started.elapsed() < grund_server::edge::machines::EJECT_FIRST,
            "the ejection window elapsed before the next connection"
        );
        let latency =
            new_failover_connection(stack, name, healthy_replica, FAILOVER_EJECTED).await?;
        anyhow::ensure!(
            latency < FAILOVER_EJECTED,
            "an ejected machine delayed another connection by {latency:?}"
        );
    }
    keep_healthy_while_failing(stack, name, healthy, healthy_replica).await
}

#[tokio::test]
async fn an_unanswering_gate_is_ejected_before_it_can_receive_client_bytes() -> anyhow::Result<()> {
    let Some((mut stack, mut a, _b, name, copies)) = two_ready_copies(false).await? else {
        return Ok(());
    };
    let healthy_replica = copies
        .iter()
        .find(|(_, machine)| machine == "box-b")
        .ok_or_else(|| anyhow::anyhow!("no ready copy on box-b: {copies:?}"))?
        .0
        .as_str();
    a.child.kill()?;
    a.child.wait()?;
    let gate = unanswering_gate(&a).await?;
    stack.start_edge()?;
    stack.served(&name, Duration::from_secs(60)).await?;
    let mut established = stack.connect(&name).await?;
    let first = established.get(&name, "/", &[]).await?;
    anyhow::ensure!(
        first.status == 200 && first.header("x-replica") == Some(healthy_replica),
        "expected the healthy copy: {} {:?}",
        first.status,
        first.header("x-replica")
    );
    edge_falls_back_during_fault(
        &stack,
        &name,
        &mut established,
        healthy_replica,
        Some(&gate.counters.entered),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(7)).await;
    anyhow::ensure!(
        gate.counters.client_bytes.load(Relaxed) == 0,
        "the edge forwarded client bytes to a gate which never accepted entry"
    );
    Ok(())
}

#[tokio::test]
async fn a_stopped_agent_blackholes_setup_but_healthy_connections_stay_served() -> anyhow::Result<()>
{
    let Some((stack, a, b, name, copies)) = two_ready_copies(true).await? else {
        return Ok(());
    };
    let mut established = stack.connect(&name).await?;
    let first = established.get(&name, "/", &[]).await?;
    anyhow::ensure!(first.status == 200, "{}", first.text());
    let healthy_replica = first
        .header("x-replica")
        .ok_or_else(|| anyhow::anyhow!("no x-replica"))?;
    let faulty_machine = copies
        .iter()
        .find(|(replica, _)| replica != healthy_replica)
        .ok_or_else(|| anyhow::anyhow!("no second ready copy: {copies:?}"))?
        .1
        .as_str();
    let faulty = if faulty_machine == "box-a" { &a } else { &b };
    let _paused = PausedAgent::new(faulty)?;
    let paused_at = Instant::now();
    edge_falls_back_during_fault(&stack, &name, &mut established, healthy_replica, None).await?;
    while paused_at.elapsed() < Duration::from_secs(10) {
        new_failover_connection(&stack, &name, healthy_replica, FAILOVER_WHOLE).await?;
        keep_healthy_while_failing(&stack, &name, &mut established, healthy_replica).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[tokio::test]
async fn an_app_answers_over_https_through_the_edge_and_a_release_and_a_killed_copy_cost_no_request()
-> anyhow::Result<()> {
    let Some(mut stack) = a_stack().await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let a = stack.a_machine(&org, "box-a").await?;
    let b = stack.a_machine(&org, "box-b").await?;
    stack.deploy(&org, "hello", "1", 2).await?;
    let running = stack
        .until(
            &org,
            "hello",
            Duration::from_secs(40),
            "v1 on two machines",
            |app| {
                let copies = running_replicas(app);
                copies.len() == 2 && copies[0].1 != copies[1].1
            },
        )
        .await?;
    let agents = [("box-a", &a), ("box-b", &b)];
    write_remote_copies(&agents, "hello", &running_replicas(&running));
    stack.start_edge()?;
    let name = stack.name_of(&org, "hello");
    stack.served(&name, Duration::from_secs(60)).await?;

    let mut conn = stack.connect(&name).await?;
    let answer = conn
        .get(&name, "/", &[("X-Forwarded-For", "10.6.6.6")])
        .await?;
    anyhow::ensure!(answer.status == 200, "{}", answer.text());
    let text = answer.text();
    anyhow::ensure!(
        text.contains("X-Forwarded-Proto: https") || text.contains("x-forwarded-proto: https"),
        "{text}"
    );
    anyhow::ensure!(
        !text.contains("10.6.6.6"),
        "the client's forwarding header is replaced: {text}"
    );
    anyhow::ensure!(
        text.contains("x-forwarded-for: 127.0.0.1"),
        "the gate sets the client the edge saw: {text}"
    );
    anyhow::ensure!(
        answer.header("strict-transport-security") == Some("max-age=31536000"),
        "the app's address is HTTPS only"
    );

    let (tally, handles) = load(&stack, &name, 8);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before_kill = tally.ok.load(Relaxed);
    anyhow::ensure!(
        before_kill > 0,
        "the load runs: {:?}",
        tally.failures.lock()
    );
    let (victim, on) = running_replicas(&stack.app(&org, "hello").await?)[0].clone();
    if on == "box-a" { &a } else { &b }.kill_container(&victim)?;
    stack
        .until(
            &org,
            "hello",
            Duration::from_secs(30),
            "the killed copy restarted",
            |app| {
                app["replicas"].as_array().is_some_and(|r| {
                    r.iter().any(|r| {
                        r["replicaId"] == victim.as_str()
                            && r["observed"]["restarts"].as_u64() >= Some(1)
                            && r["observed"]["ready"] == true
                    })
                })
            },
        )
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    stack.deploy(&org, "hello", "2", 2).await?;
    let started = Instant::now();
    loop {
        let app = stack.app(&org, "hello").await?;
        write_remote_copies(&agents, "hello", &running_replicas(&app));
        if app["currentRelease"] == 2
            && app["rollout"]["state"] == "ROLLOUT_STATE_SUCCEEDED"
            && app["replicas"].as_array().is_some_and(|r| r.len() == 2)
        {
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(90),
            "v2 did not go live: {app:#}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    tally.stop.store(true, Relaxed);
    for handle in handles {
        let _ = handle.await;
    }
    let (ok, failed) = (tally.ok.load(Relaxed), tally.failed.load(Relaxed));
    eprintln!("traffic: {ok} requests served, {failed} failed, across a killed copy and a release");
    anyhow::ensure!(
        failed == 0,
        "{failed} of {} requests failed: {:?}\nagent a:\n{}\nagent b:\n{}",
        ok + failed,
        tally.failures.lock().iter().take(10).collect::<Vec<_>>(),
        a.log()
            .lines()
            .rev()
            .take(40)
            .collect::<Vec<_>>()
            .join("\n"),
        b.log()
            .lines()
            .rev()
            .take(40)
            .collect::<Vec<_>>()
            .join("\n")
    );
    anyhow::ensure!(ok > before_kill + 100, "requests kept being served: {ok}");
    Ok(())
}

#[tokio::test]
async fn the_edge_and_the_gate_keep_apps_apart_and_refuse_what_is_not_theirs() -> anyhow::Result<()>
{
    let Some(mut stack) = a_stack().await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let machine = stack.a_machine(&org, "box").await?;
    stack.deploy(&org, "photos", "1", 1).await?;
    stack.deploy(&org, "blog", "1", 1).await?;
    for app in ["photos", "blog"] {
        stack
            .until(&org, app, Duration::from_secs(40), "running", |a| {
                running_replicas(a).len() == 1
            })
            .await?;
    }
    stack.start_edge()?;
    let photos = stack.name_of(&org, "photos");
    let blog = stack.name_of(&org, "blog");
    stack.served(&photos, Duration::from_secs(60)).await?;
    stack.served(&blog, Duration::from_secs(60)).await?;

    let blog_copy = running_replicas(&stack.app(&org, "blog").await?)[0]
        .0
        .clone();
    let mut conn = stack.connect(&photos).await?;
    let answer = conn.get(&blog, "/", &[]).await?;
    anyhow::ensure!(
        answer.status == 421,
        "a foreign host on photos' connection: {} {}",
        answer.status,
        answer.text()
    );
    anyhow::ensure!(
        !answer.text().contains(&blog_copy),
        "it reached no copy of blog"
    );

    let segmented = Conn::open(
        &photos,
        stack.pebble.tls_port,
        stack.roots.clone(),
        Some(600),
    )
    .await;
    let mut segmented =
        segmented.map_err(|e| e.context("a post-quantum ClientHello in 600-byte segments"))?;
    anyhow::ensure!(segmented.get(&photos, "/", &[]).await?.status == 200);

    let unknown = format!("nobody-{}.{}", random_hex(3), stack.domain);
    anyhow::ensure!(
        stack.connect(&unknown).await.is_err(),
        "a name no app holds gets no certificate and no handshake"
    );

    let raw = {
        let mut tcp = TcpStream::connect(("127.0.0.1", stack.http_port)).await?;
        tcp.write_all(
            format!("GET /a/b?c=d HTTP/1.1\r\nHost: {photos}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
        let mut out = Vec::new();
        tcp.read_to_end(&mut out).await?;
        String::from_utf8_lossy(&out).into_owned()
    };
    anyhow::ensure!(raw.starts_with("HTTP/1.1 308"), "{raw}");
    anyhow::ensure!(
        raw.to_ascii_lowercase()
            .contains(&format!("location: https://{photos}/a/b?c=d")),
        "{raw}"
    );

    let suspended = std::process::Command::new(crate::accepttest::fixtures::grund_binary())
        .args([
            "apps",
            "suspend",
            &format!("{org}/blog"),
            "--reason",
            "an accepttest",
        ])
        .env_clear()
        .env("DATABASE_URL", database_url(&stack.when))
        .output()?;
    anyhow::ensure!(
        suspended.status.success(),
        "{}",
        String::from_utf8_lossy(&suspended.stderr)
    );
    let started = Instant::now();
    loop {
        let mut conn = stack.connect(&blog).await?;
        let answer = conn.get(&blog, "/", &[]).await?;
        if answer.status == 451 {
            anyhow::ensure!(!answer.text().contains(&blog_copy));
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(20),
            "suspension took effect: {}",
            answer.status
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let line = machine
        .log()
        .lines()
        .find(|l| l.contains("taking entry streams"))
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("the gate's endpoint: {}", machine.log()))?;
    let bound: Vec<std::net::SocketAddr> = line
        .split(['[', ']', ',', ' '])
        .filter_map(|part| part.trim().parse().ok())
        .collect();
    anyhow::ensure!(!bound.is_empty(), "{line}");
    let machine_key: String = sqlx::query_scalar(
        "SELECT public_key FROM grund_machines WHERE pool_name = 'box' ORDER BY registered_at DESC LIMIT 1",
    )
    .fetch_one(&mut <sqlx::PgConnection as sqlx::Connection>::connect(&database_url(&stack.when)).await?)
    .await?;
    let stranger = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(iroh::SecretKey::from_bytes(&[9; 32]))
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await?;
    let mut addr = iroh::EndpointAddr::new(machine_key.parse()?);
    for socket in &bound {
        addr = addr.with_ip_addr(*socket);
    }
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        stranger.connect(addr, b"grund/entry/1"),
    )
    .await
    .map_err(|_| anyhow::anyhow!("no connection to the gate's endpoint at {bound:?}"))??;
    let reason = tokio::time::timeout(Duration::from_secs(10), conn.closed()).await?;
    anyhow::ensure!(
        format!("{reason:?}").contains("403"),
        "a key that is not an entry key is closed with 403 before any stream is read: {reason:?}"
    );
    stranger.close().await;
    Ok(())
}

#[tokio::test]
async fn an_app_is_served_through_the_edge_while_grund_is_down_and_keeps_its_copies_when_it_returns()
-> anyhow::Result<()> {
    let Some(mut stack) = a_stack().await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let a = stack.a_machine(&org, "box-a").await?;
    let b = stack.a_machine(&org, "box-b").await?;
    stack.registry.publish("acme/steady", "1");
    stack
        .call(
            "CreateApp",
            json!({"organisation": org, "name": "steady", "settings": {
                "copies": 2,
                "rollout": {"minReadySeconds": 1, "readyDeadlineSeconds": 20, "drainSeconds": 5},
                "rescheduleAfterSeconds": 30,
            }}),
        )
        .await?;
    stack.deploy(&org, "steady", "1", 2).await?;
    let running = stack
        .until(
            &org,
            "steady",
            Duration::from_secs(40),
            "two copies on two machines",
            |app| {
                let copies = running_replicas(app);
                copies.len() == 2 && copies[0].1 != copies[1].1
            },
        )
        .await?;
    let before = running_replicas(&running);
    write_remote_copies(&[("box-a", &a), ("box-b", &b)], "steady", &before);
    stack.start_edge()?;
    let name = stack.name_of(&org, "steady");
    stack.served(&name, Duration::from_secs(60)).await?;

    let (tally, handles) = load(&stack, &name, 8);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let fixture = &stack.when.testcase.fixture;
    fixture.down_for(Duration::from_secs(40)).await?;
    let during = tally.ok.load(Relaxed);
    tokio::time::sleep(Duration::from_secs(15)).await;
    tally.stop.store(true, Relaxed);
    for handle in handles {
        let _ = handle.await;
    }
    let (ok, failed) = (tally.ok.load(Relaxed), tally.failed.load(Relaxed));
    eprintln!("grund down 40 s: {ok} requests served, {failed} failed ({during} by its return)");
    anyhow::ensure!(
        failed == 0,
        "{failed} of {} requests failed: {:?}\nedge:\n{}",
        ok + failed,
        tally.failures.lock().iter().take(10).collect::<Vec<_>>(),
        stack
            .edge_log()
            .lines()
            .rev()
            .take(30)
            .collect::<Vec<_>>()
            .join("\n")
    );
    anyhow::ensure!(
        ok > during,
        "requests kept being served after grund returned"
    );
    let after = running_replicas(&stack.app(&org, "steady").await?);
    anyhow::ensure!(
        after == before,
        "grund's return replaced copies that never stopped: {before:?} then {after:?}"
    );
    Ok(())
}

const EDGE_REDIALS_WITHIN: Duration = Duration::from_secs(2);

#[tokio::test]
async fn an_agent_restarted_under_load_costs_no_request_and_the_edge_redials_it_at_once()
-> anyhow::Result<()> {
    let Some(mut stack) = a_stack().await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let mut a = stack.a_machine(&org, "box-a").await?;
    let b = stack.a_machine(&org, "box-b").await?;
    stack.registry.publish("acme/steady", "1");
    stack
        .call(
            "CreateApp",
            json!({"organisation": org, "name": "steady", "settings": {
                "copies": 2,
                "rollout": {"minReadySeconds": 1, "readyDeadlineSeconds": 20, "drainSeconds": 5},
                "rescheduleAfterSeconds": 120,
            }}),
        )
        .await?;
    stack.deploy(&org, "steady", "1", 2).await?;
    let running = stack
        .until(
            &org,
            "steady",
            Duration::from_secs(40),
            "two copies on two machines",
            |app| {
                let copies = running_replicas(app);
                copies.len() == 2 && copies[0].1 != copies[1].1
            },
        )
        .await?;
    let copies = running_replicas(&running);
    write_remote_copies(&[("box-a", &a), ("box-b", &b)], "steady", &copies);
    stack.start_edge()?;
    let name = stack.name_of(&org, "steady");
    stack.served(&name, Duration::from_secs(60)).await?;

    let (tally, handles) = load(&stack, &name, 8);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let edge_log = |line: &'static str| {
        let dir = stack.edge_dir.clone();
        move || {
            std::fs::read_to_string(dir.join("edge.log"))
                .unwrap_or_default()
                .matches(line)
                .count()
        }
    };
    let (closed, answers) = (
        edge_log("a machine closed its connection"),
        edge_log("a machine answers again"),
    );
    let noticed = tokio::spawn(appears(Duration::from_secs(30), closed(), closed));
    let redialed = tokio::spawn(appears(Duration::from_secs(60), answers(), answers));
    let a_dir = a.dir.clone();
    let taking = move || {
        std::fs::read_to_string(a_dir.join("agent.log"))
            .unwrap_or_default()
            .matches("gate: taking entry streams")
            .count()
    };
    let taking_before = taking();
    a.stop().await?;
    let stopped = Instant::now();
    a.start()?;
    let back = appears(Duration::from_secs(30), taking_before, taking).await;
    let (noticed, redialed) = (noticed.await?, redialed.await?);
    tokio::time::sleep(Duration::from_secs(3)).await;
    tally.stop.store(true, Relaxed);
    for handle in handles {
        let _ = handle.await;
    }
    let (ok, failed) = (tally.ok.load(Relaxed), tally.failed.load(Relaxed));
    let noticed_after = noticed.map(|t| t.saturating_duration_since(stopped));
    let redialed_after = back
        .zip(redialed)
        .map(|(b, r)| r.saturating_duration_since(b));
    eprintln!(
        "agent restarted under load: {ok} served, {failed} failed; the edge noticed {noticed_after:?} after the agent stopped, and redialed {redialed_after:?} after it was back"
    );
    anyhow::ensure!(
        failed == 0,
        "{failed} of {} requests failed: {:?}",
        ok + failed,
        tally.failures.lock().iter().collect::<Vec<_>>()
    );
    anyhow::ensure!(
        noticed_after.is_some_and(|t| t <= Duration::from_secs(1)),
        "the edge did not notice the agent stop at once ({noticed_after:?}):\n{}",
        stack.edge_log()
    );
    anyhow::ensure!(
        redialed_after.is_some_and(|t| t <= EDGE_REDIALS_WITHIN),
        "the edge redialed only {redialed_after:?} after the agent was back:\n{}",
        stack.edge_log()
    );
    Ok(())
}

async fn same_key_restart(hold_stream: bool) -> anyhow::Result<()> {
    let Some(mut stack) = a_stack().await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let mut agent = stack.a_machine(&org, "box-a").await?;
    stack.deploy(&org, "abrupt-restart", "1", 1).await?;
    let running = stack
        .until(
            &org,
            "abrupt-restart",
            Duration::from_secs(40),
            "one ready copy",
            |app| {
                running_replicas(app).len() == 1 && app["replicas"][0]["observed"]["ready"] == true
            },
        )
        .await?;
    let copies = running_replicas(&running);
    write_remote_copies(&[("box-a", &agent)], "abrupt-restart", &copies);
    stack.start_edge()?;
    let name = stack.name_of(&org, "abrupt-restart");
    stack.served(&name, Duration::from_secs(60)).await?;
    let held = if hold_stream {
        let mut held = stack.connect(&name).await?;
        let slow = held.get(&name, "/?wait=6500", &[]).await?;
        anyhow::ensure!(
            slow.status == 200 && slow.header("x-replica") == Some(copies[0].0.as_str()),
            "the live machine lost a slow accepted request: {}",
            slow.status
        );
        anyhow::ensure!(
            !held.closed,
            "the slow response closed the long-lived stream"
        );
        Some(held)
    } else {
        None
    };

    let taking_before = agent.log().matches("gate: taking entry streams").count();
    agent.child.kill()?;
    agent.child.wait()?;
    agent.start()?;
    anyhow::ensure!(
        appears(Duration::from_secs(30), taking_before, || {
            agent.log().matches("gate: taking entry streams").count()
        })
        .await
        .is_some(),
        "restarted agent did not bring up its gate:\n{}",
        agent.log()
    );

    let started = Instant::now();
    let budget = if held.is_some() {
        Duration::from_secs(6)
    } else {
        Duration::from_secs(5)
    };
    let mut last_error = None;
    while started.elapsed() < budget {
        match new_failover_connection(&stack, &name, &copies[0].0, Duration::from_secs(2)).await {
            Ok(_) if started.elapsed() <= budget => {
                eprintln!(
                    "abrupt same-key restart served after {:?}",
                    started.elapsed()
                );
                return Ok(());
            }
            Ok(_) => break,
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!(
        "same-key agent restarted, but edge did not serve it within {budget:?}: {last_error:?}\nedge:\n{}\nagent:\n{}",
        stack.edge_log(),
        agent.log()
    )
}

#[tokio::test]
async fn a_killed_agent_restarting_on_a_new_port_is_reached_by_the_same_edge() -> anyhow::Result<()>
{
    same_key_restart(false).await
}

#[tokio::test]
async fn a_killed_agent_restarting_with_an_old_stream_open_is_reached_by_the_same_edge()
-> anyhow::Result<()> {
    same_key_restart(true).await
}

#[tokio::test]
async fn an_edge_stopped_under_load_finishes_every_request_it_took() -> anyhow::Result<()> {
    let Some(mut stack) = a_stack().await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let a = stack.a_machine(&org, "box-a").await?;
    stack.registry.publish("acme/steady", "1");
    stack
        .call(
            "CreateApp",
            json!({"organisation": org, "name": "steady", "settings": {
                "copies": 1,
                "rollout": {"minReadySeconds": 1, "readyDeadlineSeconds": 20, "drainSeconds": 1},
                "rescheduleAfterSeconds": 30,
            }}),
        )
        .await?;
    stack.deploy(&org, "steady", "1", 1).await?;
    let running = stack
        .until(&org, "steady", Duration::from_secs(40), "one copy", |app| {
            running_replicas(app).len() == 1
        })
        .await?;
    write_remote_copies(&[("box-a", &a)], "steady", &running_replicas(&running));
    stack.start_edge()?;
    let name = stack.name_of(&org, "steady");
    stack.served(&name, Duration::from_secs(60)).await?;

    let mut held = Vec::new();
    for _ in 0..8 {
        let (name, port, roots) = (name.clone(), stack.pebble.tls_port, stack.roots.clone());
        held.push(tokio::spawn(async move {
            let mut conn = Conn::open(&name, port, roots, None).await?;
            conn.get(&name, "/?wait=2000", &[]).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut edge = stack
        .edge
        .take()
        .ok_or_else(|| anyhow::anyhow!("the edge runs"))?;
    let stopped = std::process::Command::new("kill")
        .args(["-TERM", &edge.0.id().to_string()])
        .status()?;
    anyhow::ensure!(stopped.success());
    let mut statuses = Vec::new();
    for request in held {
        statuses.push(match request.await? {
            Ok(answer) => answer.status.to_string(),
            Err(error) => format!("{error:#}"),
        });
    }
    let exited = loop {
        if let Some(status) = edge.0.try_wait()? {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    eprintln!("edge stopped with 8 requests in flight: {statuses:?}, exit {exited}");
    anyhow::ensure!(
        statuses.iter().all(|s| s == "200"),
        "the edge cut requests it had taken: {statuses:?}\n{}",
        stack.edge_log()
    );
    anyhow::ensure!(
        stack.edge_log().contains("edge: drained"),
        "{}",
        stack.edge_log()
    );
    Ok(())
}

const EDGE_LISTENS_WITHIN: Duration = Duration::from_secs(2);

#[tokio::test]
async fn an_edge_restarted_while_grund_and_its_relay_are_down_answers_tls_at_once()
-> anyhow::Result<()> {
    let Some(mut stack) = a_stack().await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let a = stack.a_machine(&org, "box-a").await?;
    stack.registry.publish("acme/steady", "1");
    stack
        .call(
            "CreateApp",
            json!({"organisation": org, "name": "steady", "settings": {
                "copies": 1,
                "rollout": {"minReadySeconds": 1, "readyDeadlineSeconds": 20, "drainSeconds": 1},
                "rescheduleAfterSeconds": 30,
            }}),
        )
        .await?;
    stack.deploy(&org, "steady", "1", 1).await?;
    let running = stack
        .until(&org, "steady", Duration::from_secs(40), "one copy", |app| {
            running_replicas(app).len() == 1
        })
        .await?;
    write_remote_copies(&[("box-a", &a)], "steady", &running_replicas(&running));
    stack.start_edge()?;
    let name = stack.name_of(&org, "steady");
    stack.served(&name, Duration::from_secs(60)).await?;

    let fixture = stack.when.testcase.fixture.clone();
    let outage = tokio::spawn(async move { fixture.down_for(Duration::from_secs(15)).await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    stack.edge = None;
    stack.start_edge()?;
    let restarted = Instant::now();
    let mut answered = None;
    while restarted.elapsed() < Duration::from_secs(10) {
        if stack.connect(&name).await.is_ok() {
            answered = Some(restarted.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!("edge restarted without grund or its relay: TLS after {answered:?}");
    anyhow::ensure!(
        answered.is_some_and(|t| t <= EDGE_LISTENS_WITHIN),
        "the edge answered TLS only after {answered:?}, over {EDGE_LISTENS_WITHIN:?}:\n{}",
        stack.edge_log()
    );
    outage.await??;
    stack.served(&name, Duration::from_secs(60)).await?;
    Ok(())
}

#[tokio::test]
async fn an_edge_killed_while_the_ca_validates_its_name_still_gets_the_certificate_after_it_restarts()
-> anyhow::Result<()> {
    let Some(mut stack) = a_stack().await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let a = stack.a_machine(&org, "box-a").await?;
    stack.deploy(&org, "ordered", "1", 1).await?;
    let running = stack
        .until(
            &org,
            "ordered",
            Duration::from_secs(40),
            "a ready copy",
            |app| running_replicas(app).len() == 1,
        )
        .await?;
    write_remote_copies(&[("box-a", &a)], "ordered", &running_replicas(&running));
    stack.start_edge()?;
    let name = stack.name_of(&org, "ordered");
    let started = Instant::now();
    while !stack
        .edge_log()
        .contains("edge: answering a TLS-ALPN-01 challenge")
    {
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(60),
            "the CA never validated on the edge:\n{}",
            stack.edge_log()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stack.edge = None;
    let killed = Instant::now();
    tokio::time::sleep(Duration::from_secs(2)).await;
    stack.start_edge()?;
    stack.served(&name, Duration::from_secs(300)).await?;
    eprintln!(
        "an edge killed during validation served {name} {:?} after the kill",
        killed.elapsed()
    );
    Ok(())
}
