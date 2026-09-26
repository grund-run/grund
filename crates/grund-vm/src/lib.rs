//! grund-vm: Firecracker microVMs on a machine grund manages, for an
//! organisation that asks for a machine on its own hardware. It implements
//! grund agent's [`VmRuntime`]: the agent decides which VMs should run, from
//! the desired state its organisation signed; this makes it so.
//!
//! ```text
//!   <data dir>/images/<sha256>       verified kernels and root filesystems
//!   <data dir>/budget.lock           held while a VM reserves its share
//!   <data dir>/vms/<id>/spec.json    the VM's shape and image (never its metadata:
//!                                    that holds a one-time token)
//!                       rootfs.ext4  its disk, a copy of the image grown to its size
//!                       fc.sock      Firecracker's API
//!                       firecracker.pid, firecracker.log
//! ```
//!
//! Every VM is its own Firecracker process in its own process group, with
//! its output in a file, so VMs outlive the agent: an agent restart finds
//! them by their pid files. The state lives on disk, not in memory.
//!
//! Isolation today is [`Network::Isolated`]: each Firecracker runs in a new
//! unprivileged user and network namespace with a tap `fc0` of its own, so
//! the guest reaches its metadata and nothing else. That needs no root and
//! gives no egress, so [`VmRuntime::capabilities`] says `egress: false`
//! and grund places no machine that must register there. Root hosts get the
//! jailer, grund's own bridge and NAT next.
//!
//! A VM's directory records its shape (size and image digests) but never
//! its metadata, which holds a one-time token. Budget is checked under an
//! exclusive flock on `<data dir>/budget.lock`, so two VMs starting at once
//! cannot both take the last share. A disk is a copy of the image, grown
//! sparsely to the VM's size, written under a temporary name and renamed
//! into place. The configuration names the guest after its id and gives it
//! its metadata (MMDS V2) on eth0.

pub mod api;
pub mod image;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use grund_agent::vm::{VmCapabilities, VmRuntime, VmSpec, VmState, VmStatus};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{api::Api, image::Images};

/// The kernel command line every VM starts from, before its network.
pub const BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off";

/// How long a stop waits for the guest to shut down before killing it.
pub const STOP_GRACE: Duration = Duration::from_secs(10);

/// How VMs are networked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// A tap alone in the VM's own user and network namespace: metadata
    /// only, no egress, no root.
    Isolated,
}

/// The most every VM on this machine may use together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub vcpus: u32,
    pub memory_mib: u32,
    pub disk_gib: u32,
}

/// How the runtime is set up.
#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    /// The Firecracker binary.
    pub firecracker: PathBuf,
    pub network: Network,
    pub budget: Budget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Shape {
    vcpus: u32,
    memory_mib: u32,
    disk_gib: u32,
    kernel_sha256: String,
    rootfs_sha256: String,
}

impl Shape {
    fn of(spec: &VmSpec) -> Self {
        Self {
            vcpus: spec.vcpus,
            memory_mib: spec.memory_mib,
            disk_gib: spec.disk_gib,
            kernel_sha256: spec.image.kernel.sha256.to_ascii_lowercase(),
            rootfs_sha256: spec.image.rootfs.sha256.to_ascii_lowercase(),
        }
    }
}

/// Firecracker microVMs on this machine.
#[derive(Clone)]
pub struct Firecracker {
    inner: Arc<Inner>,
}

struct Inner {
    config: Config,
    images: Images,
    children: Mutex<HashMap<String, tokio::process::Child>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Firecracker {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        std::fs::create_dir_all(config.data_dir.join("vms"))?;
        let images = Images::new(config.data_dir.join("images"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                images,
                children: Mutex::default(),
                locks: Mutex::default(),
            }),
        })
    }

    fn dir(&self, id: &str) -> PathBuf {
        self.inner.config.data_dir.join("vms").join(id)
    }

    fn lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.inner
            .locks
            .lock()
            .expect("lock map")
            .entry(id.to_string())
            .or_default()
            .clone()
    }

    fn state_of(&self, id: &str) -> VmState {
        let dir = self.dir(id);
        if let Some(child) = self.inner.children.lock().expect("children").get_mut(id)
            && let Ok(Some(status)) = child.try_wait()
        {
            return VmState::Exited {
                code: status.code(),
            };
        }
        match read_pid(&dir) {
            Some(pid) if process_alive(pid) => VmState::Running,
            Some(_) => VmState::Exited { code: None },
            None => VmState::Stopped,
        }
    }

    async fn start(&self, spec: &VmSpec) -> Result<(), String> {
        let dir = self.dir(&spec.id);
        let shape = Shape::of(spec);
        if read_shape(&dir).is_some_and(|recorded| recorded != shape) {
            self.kill(&spec.id).await;
            let _ = std::fs::remove_file(dir.join("rootfs.ext4"));
        }
        self.reserve(&spec.id, &shape)?;
        let kernel = self
            .inner
            .images
            .ensure(&spec.image.kernel)
            .await
            .map_err(|e| format!("kernel: {:#}", anyhow::Error::from(e)))?;
        let rootfs = self
            .inner
            .images
            .ensure(&spec.image.rootfs)
            .await
            .map_err(|e| format!("rootfs: {:#}", anyhow::Error::from(e)))?;
        let disk = dir.join("rootfs.ext4");
        if !disk.exists() {
            copy_disk(&rootfs, &disk, spec.disk_gib).map_err(|e| format!("disk: {e}"))?;
        }
        let pid = self.launch(&spec.id, &dir).await?;
        let api = Api::new(dir.join("fc.sock"));
        let configured = async {
            for (path, body) in boot_sequence(spec, &kernel) {
                api.put(path, &body).await?;
            }
            api.put("/actions", &json!({ "action_type": "InstanceStart" }))
                .await
        }
        .await;
        if let Err(error) = configured {
            signal(pid, libc::SIGKILL);
            return Err(format!("firecracker refused the VM: {error}"));
        }
        Ok(())
    }

    async fn launch(&self, id: &str, dir: &Path) -> Result<u32, String> {
        for stale in ["fc.sock", "firecracker.pid"] {
            let _ = std::fs::remove_file(dir.join(stale));
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("firecracker.log"))
            .map_err(|e| format!("log: {e}"))?;
        let err = log.try_clone().map_err(|e| format!("log: {e}"))?;
        let Network::Isolated = self.inner.config.network;
        let child = tokio::process::Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--net",
                "--",
                "sh",
                "-c",
                "ip link set lo up && ip tuntap add dev fc0 mode tap && ip link set fc0 up && exec \"$0\" --api-sock fc.sock",
            ])
            .arg(&self.inner.config.firecracker)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .process_group(0)
            .kill_on_drop(false)
            .spawn()
            .map_err(|e| format!("cannot start firecracker: {e}"))?;
        let pid = child.id().ok_or("firecracker exited at once")?;
        std::fs::write(dir.join("firecracker.pid"), pid.to_string())
            .map_err(|e| format!("pid file: {e}"))?;
        self.inner
            .children
            .lock()
            .expect("children")
            .insert(id.to_string(), child);
        let socket = dir.join("fc.sock");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            if !process_alive(pid) || Instant::now() > deadline {
                signal(pid, libc::SIGKILL);
                return Err(format!(
                    "firecracker did not open its API socket: {}",
                    log_tail(&dir.join("firecracker.log"))
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(pid)
    }

    fn reserve(&self, id: &str, shape: &Shape) -> Result<(), String> {
        let config = &self.inner.config;
        let dir = self.dir(id);
        std::fs::create_dir_all(&dir).map_err(|e| format!("directory: {e}"))?;
        let _lock = FileLock::acquire(&config.data_dir.join("budget.lock"))
            .map_err(|e| format!("budget lock: {e}"))?;
        let (vcpus, memory, disk) = self
            .shapes()
            .into_iter()
            .filter(|(other, _)| other != id)
            .fold((0u64, 0u64, 0u64), |(v, m, d), (_, s)| {
                (
                    v + u64::from(s.vcpus),
                    m + u64::from(s.memory_mib),
                    d + u64::from(s.disk_gib),
                )
            });
        let budget = config.budget;
        if vcpus + u64::from(shape.vcpus) > u64::from(budget.vcpus) {
            return Err("budget_exceeded: vcpus".into());
        }
        if memory + u64::from(shape.memory_mib) > u64::from(budget.memory_mib) {
            return Err("budget_exceeded: memory".into());
        }
        if disk + u64::from(shape.disk_gib) > u64::from(budget.disk_gib) {
            return Err("budget_exceeded: disk".into());
        }
        let tmp = dir.join("spec.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(shape).unwrap_or_default())
            .and_then(|()| std::fs::rename(&tmp, dir.join("spec.json")))
            .map_err(|e| format!("spec: {e}"))
    }

    fn shapes(&self) -> Vec<(String, Shape)> {
        let Ok(entries) = std::fs::read_dir(self.inner.config.data_dir.join("vms")) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| {
                let id = entry.file_name().to_string_lossy().into_owned();
                read_shape(&entry.path()).map(|shape| (id, shape))
            })
            .collect()
    }

    async fn kill(&self, id: &str) {
        let dir = self.dir(id);
        if let Some(pid) = read_pid(&dir) {
            signal(pid, libc::SIGKILL);
            wait_gone(pid, Duration::from_secs(5)).await;
        }
        if let Some(mut child) = self.inner.children.lock().expect("children").remove(id) {
            let _ = child.try_wait();
        }
    }
}

impl VmRuntime for Firecracker {
    async fn ensure(&self, spec: &VmSpec) -> anyhow::Result<VmStatus> {
        if !valid_id(&spec.id) {
            anyhow::bail!("a VM id is 1 to 63 of a-z, 0-9 and hyphens: {:?}", spec.id);
        }
        let lock = self.lock(&spec.id);
        let _held = lock.lock().await;
        let running = self.state_of(&spec.id) == VmState::Running;
        if running && read_shape(&self.dir(&spec.id)).as_ref() == Some(&Shape::of(spec)) {
            return Ok(VmStatus {
                id: spec.id.clone(),
                state: VmState::Running,
            });
        }
        let state = match self.start(spec).await {
            Ok(()) => VmState::Running,
            Err(reason) => {
                tracing::warn!(vm = %spec.id, %reason, "a VM could not start");
                VmState::Failed { reason }
            }
        };
        Ok(VmStatus {
            id: spec.id.clone(),
            state,
        })
    }

    async fn stop(&self, id: &str) -> anyhow::Result<()> {
        if !valid_id(id) {
            return Ok(());
        }
        let lock = self.lock(id);
        let _held = lock.lock().await;
        let dir = self.dir(id);
        if let Some(pid) = read_pid(&dir).filter(|pid| process_alive(*pid)) {
            let asked = Api::new(dir.join("fc.sock"))
                .put("/actions", &json!({ "action_type": "SendCtrlAltDel" }))
                .await;
            if asked.is_err() || !wait_gone(pid, STOP_GRACE).await {
                signal(pid, libc::SIGKILL);
                wait_gone(pid, Duration::from_secs(5)).await;
            }
        }
        self.inner.children.lock().expect("children").remove(id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn observe(&self) -> anyhow::Result<Vec<VmStatus>> {
        let mut statuses: Vec<VmStatus> = self
            .shapes()
            .into_iter()
            .map(|(id, _)| VmStatus {
                state: self.state_of(&id),
                id,
            })
            .collect();
        statuses.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(statuses)
    }

    async fn capabilities(&self) -> VmCapabilities {
        let budget = self.inner.config.budget;
        let (vcpus, memory) = self
            .shapes()
            .iter()
            .filter(|(id, _)| self.state_of(id) == VmState::Running)
            .fold((0u32, 0u32), |(v, m), (_, s)| {
                (v.saturating_add(s.vcpus), m.saturating_add(s.memory_mib))
            });
        VmCapabilities {
            kvm: kvm_usable(),
            root: false,
            egress: false,
            free_vcpus: budget.vcpus.saturating_sub(vcpus),
            free_memory_mib: budget.memory_mib.saturating_sub(memory),
        }
    }
}

fn boot_sequence(spec: &VmSpec, kernel: &Path) -> Vec<(&'static str, serde_json::Value)> {
    let boot_args = format!(
        "{BOOT_ARGS} ip=169.254.0.2::0.0.0.0:255.255.0.0:{}:eth0:off",
        spec.id
    );
    vec![
        (
            "/boot-source",
            json!({ "kernel_image_path": kernel, "boot_args": boot_args }),
        ),
        (
            "/drives/rootfs",
            json!({ "drive_id": "rootfs", "path_on_host": "rootfs.ext4",
                    "is_root_device": true, "is_read_only": false }),
        ),
        (
            "/machine-config",
            json!({ "vcpu_count": spec.vcpus, "mem_size_mib": spec.memory_mib }),
        ),
        (
            "/network-interfaces/eth0",
            json!({ "iface_id": "eth0", "host_dev_name": "fc0" }),
        ),
        (
            "/mmds/config",
            json!({ "version": "V2", "network_interfaces": ["eth0"] }),
        ),
        ("/mmds", spec.mmds.clone()),
    ]
}

/// A VM id names a directory and a guest: a DNS label.
pub fn valid_id(id: &str) -> bool {
    (1..=63).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}

fn read_shape(dir: &Path) -> Option<Shape> {
    serde_json::from_slice(&std::fs::read(dir.join("spec.json")).ok()?).ok()
}

fn read_pid(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(dir.join("firecracker.pid"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn copy_disk(image: &Path, disk: &Path, disk_gib: u32) -> std::io::Result<()> {
    let partial = disk.with_extension("partial");
    std::fs::copy(image, &partial)?;
    let file = std::fs::OpenOptions::new().write(true).open(&partial)?;
    let want = u64::from(disk_gib) * 1024 * 1024 * 1024;
    if file.metadata()?.len() < want {
        file.set_len(want)?;
    }
    std::fs::rename(partial, disk)
}

fn kvm_usable() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

fn process_alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|stat| {
            stat.rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .is_some_and(|state| state != "Z" && state != "X")
        })
        .unwrap_or(false)
}

fn signal(pid: u32, signal: libc::c_int) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        unsafe { libc::kill(pid, signal) };
    }
}

async fn wait_gone(pid: u32, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while process_alive(pid) {
        if Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

fn log_tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().rev().take(3).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

struct FileLock(std::fs::File);

impl FileLock {
    fn acquire(path: &Path) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(file))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vm_id_is_a_dns_label() {
        assert!(valid_id("vm-1"));
        assert!(!valid_id("VM-1"));
        assert!(!valid_id("-vm"));
        assert!(!valid_id("../etc"));
        assert!(!valid_id(&"a".repeat(64)));
    }

    #[test]
    fn a_shape_ignores_the_metadata_and_the_urls() {
        let spec = |url: &str, token: &str| VmSpec {
            id: "vm-1".into(),
            vcpus: 1,
            memory_mib: 256,
            disk_gib: 1,
            image: grund_agent::vm::VmImage {
                kernel: image::Artifact {
                    url: url.into(),
                    sha256: "AB".repeat(32),
                },
                rootfs: image::Artifact {
                    url: url.into(),
                    sha256: "cd".repeat(32),
                },
            },
            mmds: json!({ "grund": { "enrollment_token": token } }),
        };
        assert_eq!(
            Shape::of(&spec("https://a", "t1")),
            Shape::of(&spec("https://b", "t2"))
        );
        assert_eq!(Shape::of(&spec("x", "y")).kernel_sha256, "ab".repeat(32));
    }
}
