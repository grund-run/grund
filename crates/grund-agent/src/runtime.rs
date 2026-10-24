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

use std::{
    collections::BTreeMap,
    future::Future,
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
    time::Duration,
};

use serde::{Deserialize, Serialize};

/// The label every grund container carries: its replica id.
pub const REPLICA_LABEL: &str = "grund.replica";
/// The immutable app identity retained after a replica leaves the desired document.
pub const APP_ID_LABEL: &str = "grund.app-id";
/// The label holding the hash of the spec it was created from.
pub const SPEC_HASH_LABEL: &str = "grund.spec-hash";
/// The label holding its stop signal, so a replica that left the document is
/// still stopped the way its release said (apps.md §7.3 rule 1).
pub const STOP_SIGNAL_LABEL: &str = "grund.stop-signal";
/// The label holding its stop grace, in whole seconds.
pub const STOP_GRACE_LABEL: &str = "grund.stop-grace";
/// Local-only record of the volumes mounted by a container. Never accepted as
/// authority: each source is checked against local policy and owner metadata.
pub const VOLUMES_LABEL: &str = "grund.volume-binds";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeBind {
    pub volume_id: String,
    pub app_id: String,
    pub name: String,
    /// Absolute path inside the container.
    pub path: String,
    /// Absolute host directory (already validated by the machine).
    pub source: String,
    pub managed: bool,
    /// An attached ext4 device, never an agent-provisioned directory.
    #[serde(default)]
    pub block_device: bool,
    /// Copy the image's files at `path` in before the first start, when the
    /// managed directory is empty ([`crate::volume::copy_up_begin`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub copy_up: bool,
}

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
    /// The container's `/etc/resolv.conf`, when the agent gave it a
    /// network: the machine's stub resolver (network.md §6.2). Read-only to
    /// the container. `None`: the image's own file, if any.
    #[serde(default)]
    pub resolv_conf: Option<String>,
    /// Agent-verified writable binds; empty for existing stateless apps.
    #[serde(default)]
    pub volumes: Vec<VolumeBind>,
    /// Machine-local roots; never supplied by the signed document.
    #[serde(default)]
    pub volume_roots: Vec<PathBuf>,
    /// Replaces the image's entrypoint and drops its cmd unless [`Self::cmd`]
    /// is set; `Some(vec![])` clears it. Never set together with `command`.
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    /// Replaces only the image's cmd; `Some(vec![])` clears it.
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    /// Absolute; `None` keeps the image's working directory.
    #[serde(default)]
    pub working_dir: Option<String>,
    /// Resolved like the image's own `User`; `None` keeps the image's.
    #[serde(default)]
    pub user: Option<String>,
}

/// Where a container's process is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TaskState {
    /// The runtime could not authoritatively determine the task's state.
    /// Recovery must leave it untouched until a later observation succeeds.
    Unknown,
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
    /// From [`APP_ID_LABEL`], so replacement fences never affect another app.
    pub app_id: String,
    /// From [`SPEC_HASH_LABEL`]; empty when missing.
    pub spec_hash: String,
    pub state: TaskState,
    /// The last applied network resolver, recovered from the runtime's
    /// persisted resolver configuration rather than the current network.
    #[serde(default)]
    pub network_resolver: Option<Ipv6Addr>,
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
    /// `args` run inside the container as its own process (its user,
    /// working directory and environment), with output discarded; exit 0
    /// passes and the timeout fails. Only the runtime can run it.
    Exec { args: Vec<String> },
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
    /// Memory and CPU already exclude the system reserve; false is a legacy total.
    #[serde(default)]
    pub resources_allocatable: bool,
}

/// A bounded output stream supplied by the runtime, never by the app document.
#[derive(Debug, Clone)]
pub struct LogSource {
    pub stream: &'static str,
    /// Oldest to newest paths; rotation keeps their inode identity.
    pub paths: Vec<PathBuf>,
}

/// Runtime-local app accounting, excluding VM monitor output and host overhead.
#[derive(Debug, Clone)]
pub struct Observation {
    pub cgroup: PathBuf,
    /// Changes when the running process changes.
    pub generation: String,
    pub logs: Vec<LogSource>,
    /// A bounded logger loss counter, separate from app output.
    pub capture_loss: Option<PathBuf>,
}

/// Receives stopped app output before runtime cleanup, without network delivery.
pub trait RemovalObserver: Send + Sync + std::fmt::Debug {
    /// Buffers a bounded final tail locally; the runtime bounds the attempt's deadline.
    fn collect<'a>(
        &'a self,
        id: &'a str,
        observation: Observation,
    ) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
    /// Releases retired identity and redaction references without gating runtime cleanup.
    fn removed<'a>(
        &'a self,
        id: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
    /// Records a failed final attempt, not an exact count of missing log records.
    fn loss(&self);
}

/// A fresh, local proof of finite limits and disposable-process attachment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimitProof {
    /// Exact finite CPU quota and period read back before and after attachment.
    pub cpu_verified: bool,
    /// Exact finite memory limit read back before and after attachment.
    pub memory_verified: bool,
    /// A disposable owned process was observed in the limited leaf.
    pub attachment_verified: bool,
    /// Any failure, including uncertain cleanup, prevents a positive proof.
    pub failure: Option<ResourceLimitFailure>,
}

impl ResourceLimitProof {
    /// Only complete verification with successful cleanup is a positive proof.
    pub fn is_positive(&self) -> bool {
        self.cpu_verified
            && self.memory_verified
            && self.attachment_verified
            && self.failure.is_none()
    }
}

/// Bounded, non-sensitive reasons a resource-limit proof could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceLimitFailure {
    /// The boot-owned cgroup hierarchy does not already delegate both controllers.
    BootDelegationUnavailable,
    /// An owned temporary leaf could not be established.
    LeafUnavailable,
    /// The finite CPU quota and period could not be written and verified.
    CpuLimitUnverified,
    /// The finite memory limit could not be written and verified.
    MemoryLimitUnverified,
    /// A bounded child with an unambiguous process identity could not be established.
    ChildUnavailable,
    /// The child's membership in the limited leaf could not be verified.
    AttachmentUnverified,
    /// Child reaping or owned-leaf removal could not be established.
    CleanupUnverified,
}

impl ResourceLimitFailure {
    /// Stable codes suitable for readiness observations; never contain host paths.
    pub const fn code(self) -> &'static str {
        match self {
            Self::BootDelegationUnavailable => "RESOURCE_BOOT_DELEGATION_UNAVAILABLE",
            Self::LeafUnavailable => "RESOURCE_PROBE_LEAF_UNAVAILABLE",
            Self::CpuLimitUnverified => "RESOURCE_CPU_LIMIT_UNVERIFIED",
            Self::MemoryLimitUnverified => "RESOURCE_MEMORY_LIMIT_UNVERIFIED",
            Self::ChildUnavailable => "RESOURCE_PROBE_CHILD_UNAVAILABLE",
            Self::AttachmentUnverified => "RESOURCE_ATTACHMENT_UNVERIFIED",
            Self::CleanupUnverified => "RESOURCE_PROBE_CLEANUP_UNVERIFIED",
        }
    }
}

/// Runs containers on this machine.
pub trait ContainerRuntime: Send + Sync {
    /// What this machine can do. Cheap: no download, no daemon start.
    fn capabilities(&self) -> impl Future<Output = AppsCapabilities> + Send;

    /// Actively proves local resource limits without preparing the runtime.
    /// Unsupported runtimes provide no proof. A positive result requires cleanup;
    /// implementations must not leave owned processes or leaves on cancellation.
    fn resource_limit_probe(&self) -> impl Future<Output = Option<ResourceLimitProof>> + Send {
        async { None }
    }

    /// Makes the runtime ready to run containers: on first use, fetches its
    /// pinned binaries (checked by SHA-256) and starts its daemon, then waits
    /// for its socket. Idempotent and cheap once ready.
    fn prepare(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Whether the image's content is all present, so a create will not
    /// fetch.
    fn has_image(&self, image: &ImageRef) -> impl Future<Output = anyhow::Result<bool>> + Send;
    /// Persistent machine storage root, separate from agent identity/secrets.
    fn volume_data_dir(&self) -> PathBuf {
        "/var/lib/grund".into()
    }

    /// Accounting paths for this app instance, absent for unsupported runtimes.
    fn observation(
        &self,
        id: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Observation>>> + Send {
        let _ = id;
        async { Ok(None) }
    }
    /// Installs local-only final-output collection for runtimes with durable capture.
    fn set_removal_observer(&self, observer: std::sync::Arc<dyn RemovalObserver>) {
        let _ = observer;
    }

    /// Fetches the image by digest from its registry and unpacks it, for
    /// this machine's architecture. Present already: nothing.
    /// `authorization`: the `Authorization` header to send the registry
    /// with every request of this pull (a private image,
    /// [`crate::registry_login`]); never kept.
    fn pull(
        &self,
        image: &ImageRef,
        authorization: Option<&str>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Makes container `id`'s own network namespace if it has none, and
    /// returns where it is bound, so the agent can give it its device on the
    /// private network before the container is created; the container is
    /// then created in that namespace. `None`: this runtime has no namespace
    /// to give, and its containers get no network. Idempotent.
    fn network_namespace(
        &self,
        id: &str,
    ) -> impl Future<Output = anyhow::Result<Option<PathBuf>>> + Send {
        let _ = id;
        async { Ok(None) }
    }

    /// Creates the container (and its own network namespace with loopback
    /// up, if [`ContainerRuntime::network_namespace`] made none) and starts
    /// its process. A container of that id
    /// already existing is an error: the agent removes it first.
    fn create(&self, spec: &ContainerSpec) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Starts a new process for an existing container whose process exited
    /// or was never started, discarding only a known non-running task.
    /// A task found running is adopted; an unknown state is left untouched.
    /// Recovery never signals a task that starts after its inspection;
    /// a runtime refusing to discard that now-running task defers recovery.
    fn restart(&self, id: &str) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// A restart of a stateful container must provide freshly validated
    /// mounts from the currently signed document and machine-local policy.
    fn restart_with_volumes(
        &self,
        id: &str,
        volumes: &[VolumeBind],
        roots: &[PathBuf],
    ) -> impl Future<Output = anyhow::Result<()>> + Send {
        let _ = (volumes, roots);
        self.restart(id)
    }

    /// Sends the stop signal, waits up to the grace, then kills, and removes
    /// the container with its snapshot and network namespace. An unknown id
    /// succeeds. Stops run concurrently; exclusive successors wait for their
    /// own app's predecessors, not unrelated apps (apps.md §7.3 rule 2).
    fn remove(
        &self,
        id: &str,
        signal: &str,
        grace: Duration,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Removes a stopped or absent task and its container without sending a signal.
    /// Returns false for a running or unknown task; inspection or deletion errors
    /// defer recovery. A running task racing deletion is never signalled.
    fn remove_stopped(&self, id: &str) -> impl Future<Output = anyhow::Result<bool>> + Send;

    /// Every container the runtime has in its namespace.
    fn list(&self) -> impl Future<Output = anyhow::Result<Vec<ContainerStatus>>> + Send;
    /// Binds still held by runtime containers, including stopped-but-not-yet
    /// removed containers. Used to fence deletion and another writer.
    fn mounted_volumes(
        &self,
    ) -> impl Future<Output = anyhow::Result<Vec<(String, VolumeBind)>>> + Send {
        async { Ok(Vec::new()) }
    }

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

    async fn pull(&self, _image: &ImageRef, _authorization: Option<&str>) -> anyhow::Result<()> {
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

    async fn remove_stopped(&self, _id: &str) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn list(&self) -> anyhow::Result<Vec<ContainerStatus>> {
        Ok(Vec::new())
    }

    async fn probe(&self, _id: &str, _probe: &Probe, _timeout: Duration) -> Result<(), String> {
        Err("this machine runs no containers".into())
    }
}
