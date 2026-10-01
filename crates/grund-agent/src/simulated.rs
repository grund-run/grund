//! A container runtime that runs nothing (`--app-runtime simulated`), so the
//! whole apps flow (placement, documents, the agent's loop, readiness,
//! restarts, rollouts) runs against the real binaries on a machine without
//! root or containerd, for tests and demos. Each container is a file under
//! its directory:
//!
//! ```text
//!   <dir>/containers/<id>.json   the spec and its state
//!   <dir>/images/<digest>        a "pulled" image
//!   <dir>/kill/<id>              made by a test: the process "dies" (exit 137)
//! ```
//!
//! A container's environment steers it, as an image's behaviour would:
//! `GRUND_SIMULATE=crash` exits with code 1 a second after every start,
//! `GRUND_SIMULATE=unready` runs but fails its check (status 503). An image
//! whose reference contains `missing` cannot be pulled.
//!
//! While a container runs, it serves HTTP/1.1 like traefik/whoami, on its
//! own loopback address ([`address_of`], in 127.0.0.0/8) and the port in its
//! `PORT` variable (8080 without one), so the gate's traffic path runs end
//! to end: every answer names the replica and echoes the request line and
//! headers it received. `?wait=<ms>` holds the answer that long, so a test
//! can keep requests in flight. A kill drops its listener and every open
//! connection at once, as SIGKILL would.
//!
//! Where the agent runs as root, each container also gets a real network
//! namespace (`<dir>/netns/<id>`), so the private network's devices,
//! routes, filter and egress are exercised for real: while it runs, it
//! serves HTTP inside that namespace on `[::]` at each port in
//! `GRUND_SIMULATE_LISTEN` (comma-separated), answering `200` with
//! `simulated <id>` (or `503` when unready), and its check runs inside the
//! namespace as grund's containerd runtime's does.
//! `GRUND_SIMULATE_LISTEN_ON=ipv4` serves on `0.0.0.0` only, as an app that
//! binds IPv4 does.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::runtime::{
    AppsCapabilities, ContainerRuntime, ContainerSpec, ContainerStatus, ImageRef, Probe, TaskState,
};

/// The simulated runtime.
#[derive(Debug, Clone)]
pub struct SimulatedContainers {
    dir: PathBuf,
    servers: Arc<Mutex<HashMap<String, Server>>>,
}

#[derive(Debug)]
struct Server {
    started_at_ms: i64,
    stop: CancellationToken,
}

/// The loopback address a simulated container serves on: 127.a.b.c from
/// the SHA-256 of its id, never 127.0.0.1, so two containers on one host
/// can both listen on one port, as two network namespaces could.
pub fn address_of(id: &str) -> Ipv4Addr {
    let digest = Sha256::digest(id.as_bytes());
    Ipv4Addr::new(127, digest[0].max(1), digest[1], digest[2].clamp(1, 254))
}

fn port_of(spec: &ContainerSpec) -> u16 {
    spec.env
        .iter()
        .rev()
        .find(|(name, _)| name == "PORT")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(8080)
}

async fn whoami(
    id: String,
    request: hyper::Request<hyper::body::Incoming>,
    peer: SocketAddr,
) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, std::convert::Infallible> {
    let wait = request
        .uri()
        .query()
        .unwrap_or_default()
        .split('&')
        .find_map(|pair| pair.strip_prefix("wait="))
        .and_then(|ms| ms.parse::<u64>().ok())
        .unwrap_or(0)
        .min(60_000);
    if wait > 0 {
        tokio::time::sleep(Duration::from_millis(wait)).await;
    }
    let mut body = format!(
        "Hostname: {id}\nRemoteAddr: {peer}\n{} {} {:?}\n",
        request.method(),
        request.uri(),
        request.version()
    );
    for (name, value) in request.headers() {
        body.push_str(&format!(
            "{}: {}\n",
            name,
            String::from_utf8_lossy(value.as_bytes())
        ));
    }
    let mut response = hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from(body)));
    response.headers_mut().insert(
        "x-replica",
        hyper::header::HeaderValue::from_str(&id)
            .unwrap_or(hyper::header::HeaderValue::from_static("unknown")),
    );
    Ok(response)
}

async fn serve(id: String, listener: tokio::net::TcpListener, stop: CancellationToken) {
    loop {
        let accepted = tokio::select! {
            () = stop.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        let (id, stop) = (id.clone(), stop.clone());
        tokio::spawn(async move {
            let service =
                hyper::service::service_fn(move |request| whoami(id.clone(), request, peer));
            let connection = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .with_upgrades();
            tokio::select! {
                () = stop.cancelled() => {}
                _ = connection => {}
            }
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    spec: ContainerSpec,
    state: TaskState,
    started_at_ms: i64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

impl SimulatedContainers {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            servers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn stop_server(&self, id: &str) {
        if let Some(server) = self.servers.lock().expect("servers lock").remove(id) {
            server.stop.cancel();
        }
    }

    fn keep_servers(&self, records: &[Record]) {
        let mut servers = self.servers.lock().expect("servers lock");
        servers.retain(|id, server| {
            let running = records.iter().any(|r| {
                r.spec.id == *id
                    && matches!(r.state, TaskState::Running { .. })
                    && r.started_at_ms == server.started_at_ms
            });
            if !running {
                server.stop.cancel();
            }
            running
        });
        for record in records {
            if !matches!(record.state, TaskState::Running { .. })
                || servers.contains_key(&record.spec.id)
            {
                continue;
            }
            let address = SocketAddr::from((address_of(&record.spec.id), port_of(&record.spec)));
            let listener = match std::net::TcpListener::bind(address)
                .and_then(|l| l.set_nonblocking(true).map(|()| l))
                .and_then(tokio::net::TcpListener::from_std)
            {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::warn!(replica = %record.spec.id, %address, %error, "simulated: cannot listen");
                    continue;
                }
            };
            let stop = CancellationToken::new();
            tokio::spawn(serve(record.spec.id.clone(), listener, stop.clone()));
            servers.insert(
                record.spec.id.clone(),
                Server {
                    started_at_ms: record.started_at_ms,
                    stop,
                },
            );
        }
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join("containers").join(format!("{id}.json"))
    }

    fn read(&self, id: &str) -> Option<Record> {
        std::fs::read(self.path(id))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    fn write(&self, record: &Record) -> anyhow::Result<()> {
        std::fs::create_dir_all(self.dir.join("containers"))?;
        let path = self.path(&record.spec.id);
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, serde_json::to_vec(record)?)?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    fn behaviour(spec: &ContainerSpec) -> Option<&str> {
        spec.env
            .iter()
            .rev()
            .find(|(name, _)| name == "GRUND_SIMULATE")
            .map(|(_, value)| value.as_str())
    }

    fn advance(&self, mut record: Record) -> anyhow::Result<Record> {
        let kill = self.dir.join("kill").join(&record.spec.id);
        if let TaskState::Running { .. } = record.state {
            if kill.exists() {
                let _ = std::fs::remove_file(&kill);
                record.state = TaskState::Exited {
                    code: 137,
                    exited_at_unix_ms: now_ms(),
                };
                self.write(&record)?;
            } else if Self::behaviour(&record.spec) == Some("crash")
                && now_ms() - record.started_at_ms >= 1000
            {
                record.state = TaskState::Exited {
                    code: 1,
                    exited_at_unix_ms: now_ms(),
                };
                self.write(&record)?;
            }
        }
        Ok(record)
    }
}

fn listeners() -> &'static Mutex<HashMap<PathBuf, Arc<AtomicBool>>> {
    static LISTENERS: OnceLock<Mutex<HashMap<PathBuf, Arc<AtomicBool>>>> = OnceLock::new();
    LISTENERS.get_or_init(Default::default)
}

impl SimulatedContainers {
    fn netns(&self, id: &str) -> PathBuf {
        grund_net::netns::path(&self.dir.join("netns"), id)
    }

    fn ports(spec: &ContainerSpec) -> Vec<u16> {
        spec.env
            .iter()
            .rev()
            .find(|(name, _)| name == "GRUND_SIMULATE_LISTEN")
            .map(|(_, v)| v.split(',').filter_map(|p| p.trim().parse().ok()).collect())
            .unwrap_or_default()
    }

    fn listen(&self, record: &Record) {
        let netns = self.netns(&record.spec.id);
        if !grund_net::netns::is_namespace(&netns) {
            return;
        }
        let ports = Self::ports(&record.spec);
        if ports.is_empty() {
            return;
        }
        let mut all = listeners().lock().expect("listeners lock");
        if all.contains_key(&netns) {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        all.insert(netns.clone(), stop.clone());
        let unready = Self::behaviour(&record.spec) == Some("unready");
        let ipv4_only = record
            .spec
            .env
            .iter()
            .any(|(n, v)| n == "GRUND_SIMULATE_LISTEN_ON" && v == "ipv4");
        let body = format!("simulated {}", record.spec.id);
        for port in ports {
            let (netns, stop, body) = (netns.clone(), stop.clone(), body.clone());
            std::thread::spawn(move || {
                if grund_net::netns::enter(&netns).is_err() {
                    return;
                }
                let host = if ipv4_only { "0.0.0.0" } else { "::" };
                let Ok(listener) = std::net::TcpListener::bind((host, port)) else {
                    return;
                };
                let _ = listener.set_nonblocking(true);
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let mut request = [0u8; 2048];
                            let _ = stream.read(&mut request);
                            let status = if unready {
                                "503 Service Unavailable"
                            } else {
                                "200 OK"
                            };
                            let _ = write!(
                                stream,
                                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(20)),
                    }
                }
            });
        }
    }

    fn unlisten(&self, id: &str) {
        if let Some(stop) = listeners()
            .lock()
            .expect("listeners lock")
            .remove(&self.netns(id))
        {
            stop.store(true, Ordering::Relaxed);
        }
    }
}

impl ContainerRuntime for SimulatedContainers {
    async fn network_namespace(&self, id: &str) -> anyhow::Result<Option<PathBuf>> {
        if unsafe { libc::geteuid() } != 0 {
            return Ok(None);
        }
        match grund_net::netns::ensure(&self.dir.join("netns"), id) {
            Ok(path) => Ok(Some(path)),
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    async fn capabilities(&self) -> AppsCapabilities {
        AppsCapabilities {
            apps: true,
            reason: String::new(),
            arch: std::env::consts::ARCH.to_string(),
            memory_mib: 4096,
            cpu_millis: 4000,
        }
    }

    async fn prepare(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(self.dir.join("containers"))?;
        std::fs::create_dir_all(self.dir.join("images"))?;
        std::fs::create_dir_all(self.dir.join("kill"))?;
        Ok(())
    }

    async fn has_image(&self, image: &ImageRef) -> anyhow::Result<bool> {
        Ok(self.dir.join("images").join(&image.digest).exists())
    }

    async fn pull(&self, image: &ImageRef) -> anyhow::Result<()> {
        anyhow::ensure!(
            !image.reference.contains("missing"),
            "the registry has no {}",
            image.reference
        );
        std::fs::create_dir_all(self.dir.join("images"))?;
        std::fs::write(
            self.dir.join("images").join(&image.digest),
            &image.reference,
        )?;
        Ok(())
    }

    async fn create(&self, spec: &ContainerSpec) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.read(&spec.id).is_none(),
            "container {} exists",
            spec.id
        );
        anyhow::ensure!(
            self.dir.join("images").join(&spec.image.digest).exists(),
            "image {} is not pulled",
            spec.image.digest
        );
        let record = Record {
            spec: spec.clone(),
            state: TaskState::Running {
                pid: std::process::id(),
            },
            started_at_ms: now_ms(),
        };
        self.write(&record)?;
        self.listen(&record);
        Ok(())
    }

    async fn restart(&self, id: &str) -> anyhow::Result<()> {
        let mut record = self
            .read(id)
            .with_context(|| format!("no container {id}"))?;
        record.state = TaskState::Running {
            pid: std::process::id(),
        };
        record.started_at_ms = now_ms();
        self.write(&record)
    }

    async fn remove(&self, id: &str, _signal: &str, _grace: Duration) -> anyhow::Result<()> {
        self.stop_server(id);
        self.unlisten(id);
        grund_net::netns::remove(&self.dir.join("netns"), id)?;
        match std::fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn list(&self) -> anyhow::Result<Vec<ContainerStatus>> {
        let Ok(entries) = std::fs::read_dir(self.dir.join("containers")) else {
            return Ok(Vec::new());
        };
        let mut statuses = Vec::new();
        let mut records = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            let Some(record) = self.read(id) else {
                continue;
            };
            let record = self.advance(record)?;
            if matches!(record.state, TaskState::Running { .. }) {
                self.listen(&record);
            } else {
                self.unlisten(id);
            }
            records.push(record.clone());
            statuses.push(ContainerStatus {
                id: record.spec.id.clone(),
                spec_hash: record.spec.spec_hash.clone(),
                state: record.state.clone(),
                stop_signal: record.spec.stop_signal.clone(),
                stop_grace: record.spec.stop_grace,
            });
        }
        statuses.sort_by(|a, b| a.id.cmp(&b.id));
        self.keep_servers(&records);
        Ok(statuses)
    }

    async fn probe(&self, id: &str, probe: &Probe, timeout: Duration) -> Result<(), String> {
        let record = self
            .read(id)
            .ok_or_else(|| "no such container".to_string())?;
        if !matches!(record.state, TaskState::Running { .. }) {
            return Err("its process is not running".into());
        }
        let netns = self.netns(id);
        if grund_net::netns::is_namespace(&netns) && !Self::ports(&record.spec).is_empty() {
            return crate::probe::run(Some(netns), probe.clone(), timeout).await;
        }
        match Self::behaviour(&record.spec) {
            Some("unready") => Err("status 503".into()),
            _ => Ok(()),
        }
    }

    async fn address(&self, id: &str) -> Option<IpAddr> {
        let record = self.read(id)?;
        matches!(record.state, TaskState::Running { .. }).then(|| IpAddr::V4(address_of(id)))
    }
}
