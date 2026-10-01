//! The seam between `grund agent` and whatever runs containers on this
//! machine (grund-docs design/apps.md §7). The agent decides which replicas
//! should run, from the document its organisation signed, and when to
//! restart, stop and check them; a runtime (grund-containers: grund's own
//! containerd) makes each step so. The runtime decides nothing.
//!
//! Every call is idempotent and safe to repeat after a crash between two
//! calls: the agent's next pass plans again from [`ContainerRuntime::list`].
//! A runtime touches only its own containers (containerd namespace `grund`
//! on `/run/grund/containerd.sock`), never another runtime's on the same
//! machine.

use std::{collections::BTreeMap, future::Future, net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};

/// The label every grund container carries: its replica id.
pub const REPLICA_LABEL: &str = "grund.replica";
/// The label holding the hash of the spec it was created from.
pub const SPEC_HASH_LABEL: &str = "grund.spec-hash";
/// The label holding its stop signal, so a replica that left the document is
/// still stopped the way its release said (apps.md §7.3 rule 1).
pub const STOP_SIGNAL_LABEL: &str = "grund.stop-signal";
/// The label holding its stop grace, in whole seconds.
pub const STOP_GRACE_LABEL: &str = "grund.stop-grace";

/// An image pinned by digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageRef {
    /// For display and for the registry to fetch from: `name[:tag]` or
    /// `name@sha256:…`, as the release recorded it.
    pub reference: String,
    /// `sha256:<64 lowercase hex>`: what runs. The runtime refuses content
    /// whose digest differs.
    pub digest: String,
}

/// One container to create, for one replica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerSpec {
    /// The replica id; the container's id in the runtime.
    pub id: String,
    pub image: ImageRef,
    /// Replaces the image's entrypoint and command when not empty.
    pub command: Vec<String>,
    /// Plain settings and secret values together, in order; later entries
    /// win over the image's own.
    pub env: Vec<(String, String)>,
    /// Enforced as the cgroup's `memory.max`.
    pub memory_mib: u64,
    /// Enforced as a `cpu.max` quota.
    pub cpu_millis: u32,
    /// `SIGTERM`, `SIGINT`, `SIGQUIT`, `SIGUSR1`, `SIGUSR2` or `SIGHUP`.
    pub stop_signal: String,
    pub stop_grace: Duration,
    /// Labels to set on the container, beside the runtime's own
    /// ([`REPLICA_LABEL`], [`SPEC_HASH_LABEL`], [`STOP_SIGNAL_LABEL`],
    /// [`STOP_GRACE_LABEL`]).
    pub labels: BTreeMap<String, String>,
    /// The agent's hash of everything above but `env`'s secret values; a
    /// container whose hash differs is a different container.
    pub spec_hash: String,
}

/// Where a container's process is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TaskState {
    /// The container exists and has no process (never started, or its
    /// process was cleaned up).
    Created,
    Running {
        pid: u32,
    },
    /// Its process ended. `exited_at_unix_ms` is the runtime's clock.
    Exited {
        code: i32,
        exited_at_unix_ms: i64,
    },
}

/// One of the runtime's containers, as it is now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerStatus {
    pub id: String,
    /// From [`SPEC_HASH_LABEL`]; empty when missing.
    pub spec_hash: String,
    pub state: TaskState,
    /// From the stop labels, or `SIGTERM` and 30 s when missing.
    pub stop_signal: String,
    pub stop_grace: Duration,
}

/// A readiness check, made from the container's own network namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Probe {
    /// GET `path` on `127.0.0.1:port`; a 2xx or 3xx status passes.
    Http { port: u16, path: String },
    /// A TCP connect to `127.0.0.1:port` passes.
    Tcp { port: u16 },
}

/// What this machine can do with containers, reported in every heartbeat.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppsCapabilities {
    /// Containers can run here: root, cgroup v2 with the memory and cpu
    /// controllers, overlayfs, and a supported architecture.
    pub apps: bool,
    /// Why not, for the user, when `apps` is false.
    pub reason: String,
    /// `x86_64` or `aarch64`.
    pub arch: String,
    pub memory_mib: u64,
    pub cpu_millis: u32,
}

/// Runs containers on this machine.
pub trait ContainerRuntime: Send + Sync {
    /// What this machine can do. Cheap: no download, no daemon start.
    fn capabilities(&self) -> impl Future<Output = AppsCapabilities> + Send;

    /// Makes the runtime ready to run containers: on first use, fetches its
    /// pinned binaries (checked by SHA-256) and starts its daemon, then waits
    /// for its socket. Idempotent and cheap once ready.
    fn prepare(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Whether the image's content is all present, so a create will not
    /// fetch.
    fn has_image(&self, image: &ImageRef) -> impl Future<Output = anyhow::Result<bool>> + Send;

    /// Fetches the image by digest from its registry and unpacks it, for
    /// this machine's architecture. Present already: nothing.
    fn pull(&self, image: &ImageRef) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Creates the container (and its own network namespace with loopback
    /// up and nothing else) and starts its process. A container of that id
    /// already existing is an error: the agent removes it first.
    fn create(&self, spec: &ContainerSpec) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Starts a new process for an existing container whose process exited
    /// or was never started, discarding the old one.
    fn restart(&self, id: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Sends the stop signal, waits up to the grace, then kills, and removes
    /// the container with its snapshot and network namespace. An unknown id
    /// succeeds. Each call is independent: the agent runs stops side by side
    /// and never waits on one before a start (apps.md §7.3 rule 2).
    fn remove(
        &self,
        id: &str,
        signal: &str,
        grace: Duration,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Every container the runtime has in its namespace.
    fn list(&self) -> impl Future<Output = anyhow::Result<Vec<ContainerStatus>>> + Send;

    /// Runs `probe` from inside the running container's network namespace,
    /// within `timeout`. `Err` says why it failed, for the user.
    fn probe(
        &self,
        id: &str,
        probe: &Probe,
        timeout: Duration,
    ) -> impl Future<Output = Result<(), String>> + Send;

    /// Where the running container is reached from this machine and, over
    /// the private network, from the others: its own address, with no port
    /// mapping (grund-docs design/apps.md §12.2). `None` while it has none.
    fn address(&self, id: &str) -> impl Future<Output = Option<IpAddr>> + Send {
        let _ = id;
        async { None }
    }

    /// Opens a TCP connection to `port` of the running container: how the
    /// gate reaches a local copy (grund-docs design/traffic.md §7.4). By
    /// default, a connection to [`ContainerRuntime::address`] from this
    /// machine's own network namespace.
    fn connect(
        &self,
        id: &str,
        port: u16,
    ) -> impl Future<Output = std::io::Result<tokio::net::TcpStream>> + Send {
        async move {
            match self.address(id).await {
                Some(ip) => tokio::net::TcpStream::connect((ip, port)).await,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "the container has no address",
                )),
            }
        }
    }
}

/// The runtime of a machine that runs no containers.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoContainers;

impl ContainerRuntime for NoContainers {
    async fn capabilities(&self) -> AppsCapabilities {
        AppsCapabilities {
            reason: "this agent was started without a container runtime".into(),
            ..Default::default()
        }
    }

    async fn prepare(&self) -> anyhow::Result<()> {
        anyhow::bail!("this machine runs no containers")
    }

    async fn has_image(&self, _image: &ImageRef) -> anyhow::Result<bool> {
        Ok(false)
    }

    async fn pull(&self, _image: &ImageRef) -> anyhow::Result<()> {
        anyhow::bail!("this machine runs no containers")
    }

    async fn create(&self, _spec: &ContainerSpec) -> anyhow::Result<()> {
        anyhow::bail!("this machine runs no containers")
    }

    async fn restart(&self, _id: &str) -> anyhow::Result<()> {
        anyhow::bail!("this machine runs no containers")
    }

    async fn remove(&self, _id: &str, _signal: &str, _grace: Duration) -> anyhow::Result<()> {
        Ok(())
    }

    async fn list(&self) -> anyhow::Result<Vec<ContainerStatus>> {
        Ok(Vec::new())
    }

    async fn probe(&self, _id: &str, _probe: &Probe, _timeout: Duration) -> Result<(), String> {
        Err("this machine runs no containers".into())
    }
}
