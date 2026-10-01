//! grund-containers: grund's own containerd on a machine grund manages,
//! running an organisation's app replicas. It implements grund agent's
//! [`ContainerRuntime`] (grund-docs design/apps.md §7): the agent decides
//! which replicas run, restarts and stops them, and checks them; this makes
//! each step so, and decides nothing.
//!
//! ```text
//!   <data dir>/bin/containerd-2.4.1/   containerd, its runc shim and runc, pinned by SHA-256
//!   <data dir>/runtime/                containerd's root: content, snapshots, metadata
//!   <data dir>/agent/logs/<id>.log     each container's stdout and stderr
//!   <run dir>/containerd.sock          containerd's gRPC socket (ttrpc beside it)
//!   <run dir>/containerd/              containerd's state
//!   <run dir>/containerd.toml          its config, written before every start
//!   <run dir>/netns/<id>               each container's network namespace
//!   <run dir>/resolv/<id>              its /etc/resolv.conf, bound read-only
//! ```
//!
//! containerd is grund's own ([`daemon`]): its own sockets, root and state,
//! namespace `grund` only, and its own shim and runc first on its `PATH`, so
//! it coexists with Docker's containerd on `/run/containerd` and never
//! touches it. It is driven over its gRPC API with connectrpc
//! ([`client`]). Images are pulled by digest through containerd's Transfer
//! service, which fetches from the registry (anonymously: registry
//! credentials are not handled yet) and unpacks onto overlayfs.
//!
//! A container ([`spec`]) is unprivileged: Docker's default capabilities,
//! `noNewPrivileges`, its own pid, ipc, uts, mount and cgroup namespaces,
//! a network namespace of its own ([`netns`]), loopback only unless the
//! agent gives it a device on the private network first
//! ([`ContainerRuntime::network_namespace`]), its
//! memory, CPU and pids limits in `/sys/fs/cgroup/grund/<id>`, and nothing
//! from the host. Containers outlive the agent and containerd: each runs
//! under its own shim.

pub mod api {
    //! containerd's v2.4.1 API (the protos under `proto/`), generated at
    //! build time.
    #![allow(missing_docs, clippy::all)]
    connectrpc::include_generated!();
}
pub mod binaries;
pub mod capabilities;
pub mod client;
pub mod daemon;
pub mod image;
pub use grund_agent::probe;
pub use grund_net::netns;
pub mod rootfs;
pub mod spec;

use std::{
    collections::{BTreeMap, HashMap},
    hash::BuildHasher,
    path::PathBuf,
    sync::OnceLock,
    time::Duration,
};

use anyhow::Context;
use buffa::Message;
use buffa_types::google::protobuf::{Any, Empty};
use grund_agent::runtime::{
    AppsCapabilities, ContainerRuntime, ContainerSpec, ContainerStatus, ImageRef, Probe,
    REPLICA_LABEL, SPEC_HASH_LABEL, STOP_GRACE_LABEL, STOP_SIGNAL_LABEL, TaskState,
};

use crate::{
    api::containerd::{
        runc::v1::Options as RuncOptions,
        services::{
            containers::v1::{
                Container, CreateContainerRequest, DeleteContainerRequest, GetContainerRequest,
                ListContainersRequest, container::Runtime,
            },
            content::v1::ReadContentRequest,
            images::v1::GetImageRequest,
            snapshots::v1::{
                MountsRequest, PrepareSnapshotRequest, RemoveSnapshotRequest, StatSnapshotRequest,
            },
            tasks::v1::{
                CreateTaskRequest, DeleteTaskRequest, GetRequest, KillRequest, ListTasksRequest,
                StartRequest, WaitRequest,
            },
            transfer::v1::TransferRequest,
        },
        types::{
            Platform,
            transfer::{ImageStore, OCIRegistry, UnpackConfiguration},
        },
        v1::types::{Process, Status},
    },
    binaries::{Arch, Release},
    client::{Client, already_exists, failed, not_found},
    daemon::Supervisor,
    image::{Document, ImageConfig},
};

/// The only containerd namespace grund uses.
pub const NAMESPACE: &str = "grund";
/// The snapshotter images are unpacked onto.
pub const SNAPSHOTTER: &str = "overlayfs";
/// containerd's runtime for every container.
pub const RUNTIME: &str = "io.containerd.runc.v2";
/// The type URL of runc's runtime options.
pub const RUNC_OPTIONS_TYPE_URL: &str = "containerd.runc.v1.Options";
/// The type URL of a Transfer source naming a registry image.
pub const OCI_REGISTRY_TYPE_URL: &str = "containerd.types.transfer.OCIRegistry";
/// The type URL of a Transfer destination in the image store.
pub const IMAGE_STORE_TYPE_URL: &str = "containerd.types.transfer.ImageStore";
/// The label that keeps a container's snapshot from containerd's garbage
/// collector until the container is removed.
pub const GC_ROOT_LABEL: &str = "containerd.io/gc.root";
/// What the agent gets when a container has no stop labels.
pub const DEFAULT_STOP_SIGNAL: &str = "SIGTERM";
/// The grace a container without a grace label gets.
pub const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(30);
/// How long a `SIGKILL`ed process may take to be reaped before removal
/// gives up.
pub const KILL_WAIT: Duration = Duration::from_secs(10);
/// The largest manifest, index or config read from the content store.
pub const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;

/// How the runtime is set up. [`Config::default`] is a machine's: data in
/// `/var/lib/grund`, sockets and namespaces in `/run/grund`.
#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub run_dir: PathBuf,
    pub arch: Arch,
    /// What to fetch and the digests it must have.
    pub release: Release,
    /// How to start containerd; `None` decides from the host.
    pub supervisor: Option<Supervisor>,
    /// How long a start may take before its log is reported.
    pub start_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        let arch = Arch::of_host().unwrap_or(Arch::X86_64);
        Self {
            data_dir: "/var/lib/grund".into(),
            run_dir: "/run/grund".into(),
            arch,
            release: Release::pinned(arch),
            supervisor: None,
            start_timeout: Duration::from_secs(20),
        }
    }
}

impl Config {
    /// Where releases are unpacked.
    pub fn bin_root(&self) -> PathBuf {
        self.data_dir.join("bin")
    }
    /// The release's binaries.
    pub fn bin_dir(&self) -> PathBuf {
        self.bin_root().join(&self.release.name)
    }
    /// containerd's root.
    pub fn runtime_root(&self) -> PathBuf {
        self.data_dir.join("runtime")
    }
    /// containerd's state.
    pub fn state_dir(&self) -> PathBuf {
        self.run_dir.join("containerd")
    }
    /// containerd's gRPC socket.
    pub fn socket(&self) -> PathBuf {
        self.run_dir.join("containerd.sock")
    }
    /// containerd's ttrpc socket, which its shims use.
    pub fn ttrpc_socket(&self) -> PathBuf {
        self.run_dir.join("containerd.sock.ttrpc")
    }
    /// Where containerd's shims put their sockets.
    pub fn shim_socket_dir(&self) -> PathBuf {
        self.run_dir.join("s")
    }
    /// runc's state, which the shim would otherwise keep in
    /// `/run/containerd/runc`.
    pub fn runc_root(&self) -> PathBuf {
        self.run_dir.join("runc")
    }
    /// containerd's config file.
    pub fn config_file(&self) -> PathBuf {
        self.run_dir.join("containerd.toml")
    }
    /// Registry host settings for the Transfer service: none are written,
    /// so nothing in `/etc/containerd` or `/etc/docker` applies.
    pub fn registry_hosts_dir(&self) -> PathBuf {
        self.data_dir.join("runtime-registry-hosts")
    }
    /// Containers' output.
    pub fn log_dir(&self) -> PathBuf {
        self.data_dir.join("agent").join("logs")
    }
    /// containerd's own output, when it is not under systemd.
    pub fn containerd_log(&self) -> PathBuf {
        self.log_dir().join("containerd.log")
    }
    /// Containers' network namespaces.
    pub fn netns_dir(&self) -> PathBuf {
        self.run_dir.join("netns")
    }
    /// Container `id`'s `/etc/resolv.conf`, when the agent gave it one.
    pub fn resolv_conf(&self, id: &str) -> PathBuf {
        self.run_dir.join("resolv").join(id)
    }
    /// Scratch mount points for reading a root filesystem.
    pub fn scratch_dir(&self) -> PathBuf {
        self.run_dir.join("mnt")
    }
    /// Container `id`'s log file.
    pub fn container_log(&self, id: &str) -> PathBuf {
        self.log_dir().join(format!("{id}.log"))
    }
}

/// grund's own containerd, as a [`ContainerRuntime`].
#[derive(Debug)]
pub struct Containerd {
    config: Config,
    client: OnceLock<Client>,
    preparing: tokio::sync::Mutex<()>,
}

/// The signal number of a stop signal's name.
pub fn signal_number(name: &str) -> Option<u32> {
    let number = match name.trim_start_matches("SIG") {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "TERM" => libc::SIGTERM,
        _ => return None,
    };
    u32::try_from(number).ok()
}

/// The status the agent sees for a container's task, `None` meaning it has
/// none.
pub fn task_state(process: Option<&Process>) -> TaskState {
    let Some(process) = process else {
        return TaskState::Created;
    };
    match process.status.as_known() {
        Some(Status::RUNNING | Status::PAUSED | Status::PAUSING) => {
            TaskState::Running { pid: process.pid }
        }
        Some(Status::STOPPED) => TaskState::Exited {
            code: process.exit_status as i32,
            exited_at_unix_ms: process
                .exited_at
                .as_option()
                .map_or(0, |t| t.seconds * 1000 + i64::from(t.nanos / 1_000_000)),
        },
        _ => TaskState::Created,
    }
}

/// The labels a container is created with: the spec's, then the runtime's
/// four.
pub fn container_labels(spec: &ContainerSpec) -> BTreeMap<String, String> {
    let mut labels = spec.labels.clone();
    labels.insert(REPLICA_LABEL.into(), spec.id.clone());
    labels.insert(SPEC_HASH_LABEL.into(), spec.spec_hash.clone());
    labels.insert(STOP_SIGNAL_LABEL.into(), spec.stop_signal.clone());
    labels.insert(
        STOP_GRACE_LABEL.into(),
        spec.stop_grace.as_secs().to_string(),
    );
    labels
}

/// A container's stop signal and grace, from its labels.
pub fn stop_settings<S: BuildHasher>(labels: &HashMap<String, String, S>) -> (String, Duration) {
    let signal = labels
        .get(STOP_SIGNAL_LABEL)
        .filter(|s| signal_number(s).is_some())
        .cloned()
        .unwrap_or_else(|| DEFAULT_STOP_SIGNAL.into());
    let grace = labels
        .get(STOP_GRACE_LABEL)
        .and_then(|g| g.parse::<u64>().ok())
        .map_or(DEFAULT_STOP_GRACE, Duration::from_secs);
    (signal, grace)
}

fn valid_id(id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !id.is_empty()
            && id.len() <= 76
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && !id.starts_with('.'),
        "not a container id: {id:?}"
    );
    Ok(())
}

impl Containerd {
    /// A runtime with `config`. Nothing is fetched or started until
    /// [`ContainerRuntime::prepare`].
    pub fn new(config: Config) -> Self {
        Self {
            config,
            client: OnceLock::new(),
            preparing: tokio::sync::Mutex::new(()),
        }
    }

    /// Its configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The containerd client (lazy: connects on first call).
    pub fn client(&self) -> &Client {
        self.client
            .get_or_init(|| Client::new(&self.config.socket()))
    }

    /// containerd's version, when its socket answers within `timeout`.
    pub async fn version(&self, timeout: Duration) -> Option<String> {
        let client = self.client().version();
        match tokio::time::timeout(timeout, client.version(Empty::default())).await {
            Ok(Ok(response)) => Some(response.into_owned().version),
            _ => None,
        }
    }

    fn supervisor(&self) -> Supervisor {
        self.config.supervisor.unwrap_or_else(Supervisor::of_host)
    }

    async fn read_blob(&self, digest: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let request = ReadContentRequest {
            digest: digest.into(),
            ..Default::default()
        };
        let mut stream = match self.client().content().read(request).await {
            Ok(stream) => stream,
            Err(e) if not_found(&e) => return Ok(None),
            Err(e) => return Err(failed("read content", e)),
        };
        let mut bytes = Vec::new();
        loop {
            match stream.message().await {
                Ok(Some(chunk)) => {
                    bytes.extend_from_slice(&chunk.to_owned_message().data);
                    anyhow::ensure!(
                        bytes.len() <= MAX_METADATA_BYTES,
                        "{digest} is larger than {MAX_METADATA_BYTES} bytes"
                    );
                }
                Ok(None) => break,
                Err(e) if not_found(&e) => return Ok(None),
                Err(e) => return Err(failed("read content", e)),
            }
        }
        anyhow::ensure!(
            image::sha256_digest(&bytes) == digest,
            "the content store's {digest} does not hash to its digest"
        );
        Ok(Some(bytes))
    }

    /// The config of the image `digest` (an index or a manifest) for this
    /// machine, from the content store; `None` when some of it is missing.
    pub async fn image_config(&self, digest: &str) -> anyhow::Result<Option<ImageConfig>> {
        let Some(top) = self.read_blob(digest).await? else {
            return Ok(None);
        };
        let mut document = Document::parse(&top)?;
        if document.is_index() {
            let manifest = document
                .manifest_for(self.config.arch.oci())
                .with_context(|| {
                    format!(
                        "image {digest} has no linux/{} manifest",
                        self.config.arch.oci()
                    )
                })?
                .digest
                .clone();
            let Some(bytes) = self.read_blob(&manifest).await? else {
                return Ok(None);
            };
            document = Document::parse(&bytes)?;
        }
        let config = document
            .config
            .with_context(|| format!("image {digest}'s manifest names no config"))?;
        let Some(bytes) = self.read_blob(&config.digest).await? else {
            return Ok(None);
        };
        let config = ImageConfig::parse(&bytes)?;
        anyhow::ensure!(
            config.os.is_empty() || config.os == "linux",
            "image {digest} is for {}, not linux",
            config.os
        );
        Ok(Some(config))
    }

    async fn snapshot_exists(&self, key: &str) -> anyhow::Result<bool> {
        let request = StatSnapshotRequest {
            snapshotter: SNAPSHOTTER.into(),
            key: key.into(),
            ..Default::default()
        };
        match self.client().snapshots().stat(request).await {
            Ok(_) => Ok(true),
            Err(e) if not_found(&e) => Ok(false),
            Err(e) => Err(failed("stat a snapshot", e)),
        }
    }

    async fn get_container(&self, id: &str) -> anyhow::Result<Option<Container>> {
        let request = GetContainerRequest {
            id: id.into(),
            ..Default::default()
        };
        match self.client().containers().get(request).await {
            Ok(response) => Ok(response.into_owned().container.into_option()),
            Err(e) if not_found(&e) => Ok(None),
            Err(e) => Err(failed("get a container", e)),
        }
    }

    async fn get_task(&self, id: &str) -> anyhow::Result<Option<Process>> {
        let request = GetRequest {
            container_id: id.into(),
            ..Default::default()
        };
        match self.client().tasks().get(request).await {
            Ok(response) => Ok(response.into_owned().process.into_option()),
            Err(e) if not_found(&e) => Ok(None),
            Err(e) => Err(failed("get a task", e)),
        }
    }

    async fn ensure_snapshot(&self, id: &str, chain_id: &str) -> anyhow::Result<()> {
        let request = PrepareSnapshotRequest {
            snapshotter: SNAPSHOTTER.into(),
            key: id.into(),
            parent: chain_id.into(),
            labels: [(GC_ROOT_LABEL.to_string(), "grund".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        match self.client().snapshots().prepare(request).await {
            Ok(_) => Ok(()),
            Err(e) if already_exists(&e) => Ok(()),
            Err(e) => Err(failed("prepare the container's snapshot", e)),
        }
    }

    async fn mounts(&self, id: &str) -> anyhow::Result<Vec<api::containerd::types::Mount>> {
        let request = MountsRequest {
            snapshotter: SNAPSHOTTER.into(),
            key: id.into(),
            ..Default::default()
        };
        Ok(self
            .client()
            .snapshots()
            .mounts(request)
            .await
            .map_err(|e| failed("get the container's mounts", e))?
            .into_owned()
            .mounts)
    }

    async fn resolve_user(&self, id: &str, user: &str) -> anyhow::Result<spec::User> {
        if !spec::needs_passwd(user) {
            return spec::resolve_user(user, None, None);
        }
        let mounts = self.mounts(id).await?;
        let scratch = self.config.scratch_dir().join(id);
        let files = tokio::task::spawn_blocking(move || {
            rootfs::read_files(&mounts, &scratch, &["etc/passwd", "etc/group"])
        })
        .await?
        .context("mount the image to read its /etc/passwd")?;
        spec::resolve_user(user, files[0].as_deref(), files[1].as_deref())
    }

    fn ensure_netns(&self, id: &str) -> anyhow::Result<PathBuf> {
        netns::ensure(&self.config.netns_dir(), id)
            .with_context(|| format!("make container {id}'s network namespace"))
    }

    async fn image_chain_for(&self, container: &Container) -> anyhow::Result<String> {
        let digest = container
            .image
            .rsplit_once('@')
            .map(|(_, d)| d.to_string())
            .with_context(|| format!("container {} names no image digest", container.id))?;
        let config = self
            .image_config(&digest)
            .await?
            .with_context(|| format!("image {digest} is no longer in the content store"))?;
        config.chain_id()
    }

    async fn start_task(&self, container: &Container) -> anyhow::Result<()> {
        let id = container.id.as_str();
        self.ensure_netns(id)?;
        if !self.snapshot_exists(id).await? {
            let chain = self.image_chain_for(container).await?;
            self.ensure_snapshot(id, &chain).await?;
        }
        let rootfs = self.mounts(id).await?;
        let log = format!("file://{}", self.config.container_log(id).display());
        let tasks = self.client().tasks();
        let create = CreateTaskRequest {
            container_id: id.into(),
            rootfs,
            stdout: log.clone(),
            stderr: log,
            ..Default::default()
        };
        match tasks.create(create).await {
            Ok(_) => {}
            Err(e) if already_exists(&e) => {}
            Err(e) => return Err(failed("create the task", e)),
        }
        let start = StartRequest {
            container_id: id.into(),
            ..Default::default()
        };
        tasks
            .start(start)
            .await
            .map_err(|e| failed("start the task", e))?;
        Ok(())
    }

    async fn kill(&self, id: &str, signal: u32, all: bool) -> anyhow::Result<()> {
        let request = KillRequest {
            container_id: id.into(),
            signal,
            all,
            ..Default::default()
        };
        match self.client().tasks().kill(request).await {
            Ok(_) => Ok(()),
            Err(e) if not_found(&e) => Ok(()),
            Err(e) if e.code == connectrpc::ErrorCode::FailedPrecondition => Ok(()),
            Err(e) => Err(failed("signal the task", e)),
        }
    }

    async fn wait_exit(&self, id: &str, within: Duration) -> anyhow::Result<bool> {
        let request = WaitRequest {
            container_id: id.into(),
            ..Default::default()
        };
        match tokio::time::timeout(within, self.client().tasks().wait(request)).await {
            Err(_) => Ok(false),
            Ok(Ok(_)) => Ok(true),
            Ok(Err(e)) if not_found(&e) => Ok(true),
            Ok(Err(e)) => Err(failed("wait for the task", e)),
        }
    }

    async fn stop_task(&self, id: &str, signal: u32, grace: Duration) -> anyhow::Result<()> {
        let Some(process) = self.get_task(id).await? else {
            return Ok(());
        };
        if process.status.as_known() != Some(Status::STOPPED) {
            self.kill(id, signal, false).await?;
            if !self.wait_exit(id, grace).await? {
                let sigkill = u32::try_from(libc::SIGKILL).unwrap_or(9);
                self.kill(id, sigkill, true).await?;
                anyhow::ensure!(
                    self.wait_exit(id, KILL_WAIT).await?,
                    "container {id} did not exit {} s after SIGKILL",
                    KILL_WAIT.as_secs()
                );
            }
        }
        self.delete_task(id).await
    }

    async fn delete_task(&self, id: &str) -> anyhow::Result<()> {
        let request = DeleteTaskRequest {
            container_id: id.into(),
            ..Default::default()
        };
        match self.client().tasks().delete(request).await {
            Ok(_) => Ok(()),
            Err(e) if not_found(&e) => Ok(()),
            Err(e) => Err(failed("delete the task", e)),
        }
    }
}

fn any(type_url: &str, message: &impl Message) -> Any {
    Any {
        type_url: type_url.into(),
        value: message.encode_to_vec().into(),
        ..Default::default()
    }
}

impl ContainerRuntime for Containerd {
    async fn capabilities(&self) -> AppsCapabilities {
        capabilities::assess(&capabilities::HostFacts::read())
    }

    async fn prepare(&self) -> anyhow::Result<()> {
        let _preparing = self.preparing.lock().await;
        daemon::create_dirs(&self.config)?;
        if let Some(version) = self.version(Duration::from_secs(2)).await {
            tracing::debug!(version, "containerd answers");
            return Ok(());
        }
        let http = binaries::http_client()?;
        let started = std::time::Instant::now();
        let bin_dir =
            binaries::install(&http, &self.config.bin_root(), &self.config.release).await?;
        tracing::info!(
            dir = %bin_dir.display(),
            ms = started.elapsed().as_millis() as u64,
            "containerd and runc verified"
        );
        let config_file = self.config.config_file();
        tokio::fs::write(&config_file, daemon::config_toml(&self.config))
            .await
            .with_context(|| format!("write {}", config_file.display()))?;
        let supervisor = self.supervisor();
        daemon::start(&self.config, &bin_dir, supervisor).await?;
        let up = daemon::wait_until(self.config.start_timeout, || async {
            self.version(Duration::from_secs(1)).await.is_some()
        })
        .await;
        if !up {
            anyhow::bail!(
                "containerd did not answer on {} within {} s:\n{}",
                self.config.socket().display(),
                self.config.start_timeout.as_secs(),
                daemon::log_tail(&self.config, supervisor).await
            );
        }
        tracing::info!(
            ms = started.elapsed().as_millis() as u64,
            ?supervisor,
            "containerd started"
        );
        Ok(())
    }

    async fn has_image(&self, image: &ImageRef) -> anyhow::Result<bool> {
        let name = image::pinned_name(&image.reference, &image.digest)?;
        let request = GetImageRequest {
            name,
            ..Default::default()
        };
        let record = match self.client().images().get(request).await {
            Ok(response) => response.into_owned().image.into_option(),
            Err(e) if not_found(&e) => None,
            Err(e) => return Err(failed("get an image", e)),
        };
        let Some(record) = record else {
            return Ok(false);
        };
        if record.target.as_option().map(|t| t.digest.as_str()) != Some(image.digest.as_str()) {
            return Ok(false);
        }
        let Some(config) = self.image_config(&image.digest).await? else {
            return Ok(false);
        };
        self.snapshot_exists(&config.chain_id()?).await
    }

    async fn pull(&self, image: &ImageRef) -> anyhow::Result<()> {
        if self.has_image(image).await? {
            return Ok(());
        }
        let name = image::pinned_name(&image.reference, &image.digest)?;
        let platform = Platform {
            os: "linux".into(),
            architecture: self.config.arch.oci().into(),
            ..Default::default()
        };
        let source = OCIRegistry {
            reference: name.clone(),
            ..Default::default()
        };
        let destination = ImageStore {
            name: name.clone(),
            platforms: vec![platform.clone()],
            unpacks: vec![UnpackConfiguration {
                platform: platform.into(),
                snapshotter: SNAPSHOTTER.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let request = TransferRequest {
            source: any(OCI_REGISTRY_TYPE_URL, &source).into(),
            destination: any(IMAGE_STORE_TYPE_URL, &destination).into(),
            ..Default::default()
        };
        self.client()
            .transfer()
            .transfer(request)
            .await
            .map_err(|e| failed(&format!("pull {name}"), e))?;
        anyhow::ensure!(
            self.has_image(image).await?,
            "pulled {name}, but its content or unpacked layers are not all there"
        );
        Ok(())
    }

    async fn create(&self, spec: &ContainerSpec) -> anyhow::Result<()> {
        valid_id(&spec.id)?;
        anyhow::ensure!(
            signal_number(&spec.stop_signal).is_some(),
            "unknown stop signal {:?}",
            spec.stop_signal
        );
        if self.get_container(&spec.id).await?.is_some() {
            anyhow::bail!("container {} exists already", spec.id);
        }
        let name = image::pinned_name(&spec.image.reference, &spec.image.digest)?;
        let config = self
            .image_config(&spec.image.digest)
            .await?
            .with_context(|| format!("image {name} is not pulled"))?;
        self.ensure_snapshot(&spec.id, &config.chain_id()?).await?;
        let user = self
            .resolve_user(&spec.id, config.config.user.as_deref().unwrap_or_default())
            .await?;
        let netns = self.ensure_netns(&spec.id)?;
        let mut oci = spec::oci_spec(spec, &config, &user, &netns)?;
        if let Some(contents) = &spec.resolv_conf {
            let path = self.config.resolv_conf(&spec.id);
            std::fs::create_dir_all(path.parent().expect("a parent"))?;
            std::fs::write(&path, contents).with_context(|| format!("write {}", path.display()))?;
            oci["mounts"]
                .as_array_mut()
                .expect("mounts is a list")
                .push(serde_json::json!({
                    "destination": "/etc/resolv.conf",
                    "type": "bind",
                    "source": path.display().to_string(),
                    "options": ["rbind", "ro", "nosuid", "nodev", "noexec"],
                }));
        }
        let options = RuncOptions {
            binary_name: self
                .config
                .bin_dir()
                .join(binaries::RUNC)
                .display()
                .to_string(),
            root: self.config.runc_root().display().to_string(),
            ..Default::default()
        };
        let container = Container {
            id: spec.id.clone(),
            labels: container_labels(spec).into_iter().collect(),
            image: name,
            runtime: Runtime {
                name: RUNTIME.into(),
                options: any(RUNC_OPTIONS_TYPE_URL, &options).into(),
                ..Default::default()
            }
            .into(),
            spec: Any {
                type_url: spec::SPEC_TYPE_URL.into(),
                value: serde_json::to_vec(&oci)?.into(),
                ..Default::default()
            }
            .into(),
            snapshotter: SNAPSHOTTER.into(),
            snapshot_key: spec.id.clone(),
            ..Default::default()
        };
        let request = CreateContainerRequest {
            container: container.clone().into(),
            ..Default::default()
        };
        self.client()
            .containers()
            .create(request)
            .await
            .map_err(|e| failed("create the container", e))?;
        self.start_task(&container).await
    }

    async fn restart(&self, id: &str) -> anyhow::Result<()> {
        let container = self
            .get_container(id)
            .await?
            .with_context(|| format!("no container {id}"))?;
        let sigkill = u32::try_from(libc::SIGKILL).unwrap_or(9);
        self.stop_task(id, sigkill, Duration::ZERO).await?;
        self.start_task(&container).await
    }

    async fn remove(&self, id: &str, signal: &str, grace: Duration) -> anyhow::Result<()> {
        valid_id(id)?;
        let number = signal_number(signal).with_context(|| format!("unknown signal {signal:?}"))?;
        self.stop_task(id, number, grace).await?;
        let request = DeleteContainerRequest {
            id: id.into(),
            ..Default::default()
        };
        match self.client().containers().delete(request).await {
            Ok(_) => {}
            Err(e) if not_found(&e) => {}
            Err(e) => return Err(failed("delete the container", e)),
        }
        let request = RemoveSnapshotRequest {
            snapshotter: SNAPSHOTTER.into(),
            key: id.into(),
            ..Default::default()
        };
        match self.client().snapshots().remove(request).await {
            Ok(_) => {}
            Err(e) if not_found(&e) => {}
            Err(e) => return Err(failed("remove the container's snapshot", e)),
        }
        match std::fs::remove_file(self.config.resolv_conf(id)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e).context("remove the container's resolv.conf");
            }
            _ => {}
        }
        netns::remove(&self.config.netns_dir(), id)
            .with_context(|| format!("remove container {id}'s network namespace"))
    }

    async fn network_namespace(&self, id: &str) -> anyhow::Result<Option<PathBuf>> {
        self.ensure_netns(id).map(Some)
    }

    async fn list(&self) -> anyhow::Result<Vec<ContainerStatus>> {
        let request = ListContainersRequest {
            filters: vec![format!("labels.\"{REPLICA_LABEL}\"")],
            ..Default::default()
        };
        let containers = self
            .client()
            .containers()
            .list(request)
            .await
            .map_err(|e| failed("list containers", e))?
            .into_owned()
            .containers;
        let tasks: HashMap<String, Process> = self
            .client()
            .tasks()
            .list(ListTasksRequest::default())
            .await
            .map_err(|e| failed("list tasks", e))?
            .into_owned()
            .tasks
            .into_iter()
            .map(|p| {
                let id = if p.container_id.is_empty() {
                    p.id.clone()
                } else {
                    p.container_id.clone()
                };
                (id, p)
            })
            .collect();
        let mut statuses: Vec<ContainerStatus> = containers
            .into_iter()
            .map(|c| {
                let (stop_signal, stop_grace) = stop_settings(&c.labels);
                ContainerStatus {
                    state: task_state(tasks.get(&c.id)),
                    spec_hash: c.labels.get(SPEC_HASH_LABEL).cloned().unwrap_or_default(),
                    id: c.id,
                    stop_signal,
                    stop_grace,
                }
            })
            .collect();
        statuses.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(statuses)
    }

    async fn probe(&self, id: &str, probe: &Probe, timeout: Duration) -> Result<(), String> {
        valid_id(id).map_err(|e| e.to_string())?;
        let path = netns::path(&self.config.netns_dir(), id);
        if !netns::is_namespace(&path) {
            return Err("the container has no network namespace".into());
        }
        probe::run(Some(path), probe.clone(), timeout).await
    }

    async fn connect(&self, id: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        valid_id(id).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let path = netns::path(&self.config.netns_dir(), id);
        if !netns::is_namespace(&path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "the container has no network namespace",
            ));
        }
        probe::connect(path, port, Duration::from_secs(2)).await
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, time::Duration};

    use buffa_types::google::protobuf::Timestamp;

    use super::*;

    #[test]
    fn stop_signals_map_to_their_linux_numbers() {
        assert_eq!(signal_number("SIGTERM"), Some(15));
        assert_eq!(signal_number("SIGINT"), Some(2));
        assert_eq!(signal_number("SIGQUIT"), Some(3));
        assert_eq!(signal_number("SIGHUP"), Some(1));
        assert_eq!(signal_number("SIGUSR1"), Some(10));
        assert_eq!(signal_number("SIGUSR2"), Some(12));
        assert_eq!(signal_number("SIGKILL"), Some(9));
        assert_eq!(signal_number("SIGSTOP"), None);
        assert_eq!(signal_number("15"), None);
    }

    #[test]
    fn a_container_carries_the_specs_labels_and_the_runtimes_four() {
        let spec = ContainerSpec {
            id: "web-1".into(),
            image: ImageRef {
                reference: "nginx".into(),
                digest: format!("sha256:{}", "b".repeat(64)),
            },
            command: Vec::new(),
            env: Vec::new(),
            memory_mib: 64,
            cpu_millis: 100,
            stop_signal: "SIGQUIT".into(),
            stop_grace: Duration::from_millis(2500),
            labels: BTreeMap::from([
                ("grund.app".into(), "web".into()),
                (REPLICA_LABEL.into(), "spoofed".into()),
            ]),
            spec_hash: "abc".into(),
            resolv_conf: None,
        };
        let labels = container_labels(&spec);
        assert_eq!(labels[REPLICA_LABEL], "web-1");
        assert_eq!(labels[SPEC_HASH_LABEL], "abc");
        assert_eq!(labels[STOP_SIGNAL_LABEL], "SIGQUIT");
        assert_eq!(labels[STOP_GRACE_LABEL], "2");
        assert_eq!(labels["grund.app"], "web");
        let labels: HashMap<String, String> = labels.into_iter().collect();
        assert_eq!(
            stop_settings(&labels),
            ("SIGQUIT".into(), Duration::from_secs(2))
        );
        assert_eq!(
            stop_settings(&HashMap::<String, String>::new()),
            ("SIGTERM".into(), Duration::from_secs(30))
        );
    }

    #[test]
    fn task_status_becomes_the_agents_state() {
        assert_eq!(task_state(None), TaskState::Created);
        let running = Process {
            pid: 42,
            status: Status::RUNNING.into(),
            ..Default::default()
        };
        assert_eq!(task_state(Some(&running)), TaskState::Running { pid: 42 });
        let exited = Process {
            pid: 42,
            status: Status::STOPPED.into(),
            exit_status: 137,
            exited_at: Timestamp {
                seconds: 1_790_000_000,
                nanos: 250_000_000,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        assert_eq!(
            task_state(Some(&exited)),
            TaskState::Exited {
                code: 137,
                exited_at_unix_ms: 1_790_000_000_250
            }
        );
        let created = Process {
            status: Status::CREATED.into(),
            ..Default::default()
        };
        assert_eq!(task_state(Some(&created)), TaskState::Created);
    }

    #[test]
    fn ids_that_could_escape_a_directory_are_refused() {
        assert!(valid_id("web-v1-0-1").is_ok());
        for bad in ["", "..", "../x", "a/b", ".hidden", "a b", &"x".repeat(77)] {
            assert!(valid_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_default_config_is_a_machines() {
        let config = Config::default();
        assert_eq!(config.socket(), Path::new("/run/grund/containerd.sock"));
        assert_eq!(config.runtime_root(), Path::new("/var/lib/grund/runtime"));
        assert_eq!(config.state_dir(), Path::new("/run/grund/containerd"));
        assert_eq!(
            config.bin_dir(),
            Path::new("/var/lib/grund/bin/containerd-2.4.1")
        );
        assert_eq!(config.netns_dir(), Path::new("/run/grund/netns"));
        assert_eq!(config.shim_socket_dir(), Path::new("/run/grund/s"));
        assert_eq!(config.runc_root(), Path::new("/run/grund/runc"));
        assert_eq!(
            config.container_log("web-1"),
            Path::new("/var/lib/grund/agent/logs/web-1.log")
        );
    }
}
