//! The seam between `grund agent` and whatever runs virtual machines on this
//! machine (grund-docs design/machines.md §7b). The agent decides which VMs
//! should run, from the desired state its organisation signed; a runtime
//! (grund-vm: Firecracker, its images, its budget and isolation) makes it
//! so. The agent never starts a process for a VM itself.
//!
//! A VM boots with a metadata document ([`metadata`]) that carries a one-time
//! `grund_join_` token, and the grund inside it runs `grund join --mmds` and
//! registers into the same organisation as a machine of its own.

use std::future::Future;

use serde::{Deserialize, Serialize};

/// What to boot, pinned by digest: the runtime refuses anything whose bytes
/// do not match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub url: String,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
}

/// A VM's image: a kernel and a root filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmImage {
    pub kernel: Artifact,
    pub rootfs: Artifact,
}

/// One VM the desired state asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmSpec {
    /// grund's id for the VM, stable for its life; the runtime names its
    /// files and processes after it.
    pub id: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub disk_gib: u32,
    pub image: VmImage,
    /// The metadata the guest reads (MMDS), built by [`metadata`]. It holds a
    /// one-time token: the runtime hands it to the guest and never logs or
    /// keeps it.
    pub mmds: serde_json::Value,
}

/// Where a VM is, as the runtime observed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VmState {
    /// Being prepared: image fetch, disk, network.
    Starting,
    Running,
    /// Stopped by [`VmRuntime::stop`].
    Stopped,
    /// It ended on its own.
    Exited {
        code: Option<i32>,
    },
    /// It could not be started or kept running; `reason` says why, for the
    /// user.
    Failed {
        reason: String,
    },
}

/// One VM the runtime knows of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmStatus {
    pub id: String,
    #[serde(flatten)]
    pub state: VmState,
}

/// What this machine can do with VMs, reported in every heartbeat so grund
/// places VMs only where they can run and reach it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmCapabilities {
    /// A usable /dev/kvm.
    pub kvm: bool,
    /// The runtime runs with root (jailer, its own bridge and taps) rather
    /// than in user namespaces.
    pub root: bool,
    /// Guests can reach the internet, so a guest can reach grund to register.
    pub egress: bool,
    /// What the runtime may still give out.
    pub free_vcpus: u32,
    pub free_memory_mib: u32,
}

/// Runs VMs on this machine. Every call is idempotent: `ensure` of a running
/// VM with the same spec changes nothing, and `stop` of a stopped or unknown
/// VM succeeds.
pub trait VmRuntime: Send + Sync {
    /// Makes the VM run as `spec` says, starting it if it is not running.
    fn ensure(&self, spec: &VmSpec) -> impl Future<Output = anyhow::Result<VmStatus>> + Send;

    /// Stops the VM and frees what it held; its disk goes with it.
    fn stop(&self, id: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Every VM the runtime knows of, including ones that exited or failed.
    fn observe(&self) -> impl Future<Output = anyhow::Result<Vec<VmStatus>>> + Send;

    /// What this machine can do.
    fn capabilities(&self) -> impl Future<Output = VmCapabilities> + Send;
}

/// The runtime of a machine that runs no VMs: no capability, nothing
/// observed, and a refusal for any VM it is asked to run.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoVms;

impl VmRuntime for NoVms {
    async fn ensure(&self, spec: &VmSpec) -> anyhow::Result<VmStatus> {
        Ok(VmStatus {
            id: spec.id.clone(),
            state: VmState::Failed {
                reason: "this machine runs no VMs".into(),
            },
        })
    }

    async fn stop(&self, _id: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn observe(&self) -> anyhow::Result<Vec<VmStatus>> {
        Ok(Vec::new())
    }

    async fn capabilities(&self) -> VmCapabilities {
        VmCapabilities::default()
    }
}

/// A runtime that boots no VM: each "VM" is this binary running
/// `grund join` with the VM's metadata, as the grund inside a real guest
/// does, with its own data directory. It lets the whole flow (a VM placed, a
/// token fetched, a machine registered into the organisation) run on a
/// machine without KVM, for tests and demos. It reports kvm and egress.
#[derive(Debug, Clone)]
pub struct SimulatedVms {
    dir: std::path::PathBuf,
}

impl SimulatedVms {
    pub fn new(dir: std::path::PathBuf) -> Self {
        Self { dir }
    }

    fn state_path(&self, id: &str) -> std::path::PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn write(&self, status: &VmStatus) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.state_path(&status.id), serde_json::to_vec(status)?)?;
        Ok(())
    }
}

impl VmRuntime for SimulatedVms {
    async fn ensure(&self, spec: &VmSpec) -> anyhow::Result<VmStatus> {
        if let Ok(text) = std::fs::read_to_string(self.state_path(&spec.id))
            && let Ok(status) = serde_json::from_str::<VmStatus>(&text)
            && status.state == VmState::Running
        {
            return Ok(status);
        }
        let guest = self.dir.join(&spec.id);
        let url = spec.mmds["grund"]["url"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let token = spec.mmds["grund"]["enrollment_token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let executable = std::env::current_exe()?;
        let output = tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(executable);
            command
                .arg("join")
                .arg("--data-dir")
                .arg(&guest)
                .arg("--url")
                .arg(url);
            if !token.is_empty() {
                command.arg(token);
            }
            command.env("RUST_LOG", "warn").output()
        })
        .await??;
        let state = if output.status.success() {
            VmState::Running
        } else {
            VmState::Failed {
                reason: String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .last()
                    .unwrap_or("grund join failed")
                    .chars()
                    .take(300)
                    .collect(),
            }
        };
        let status = VmStatus {
            id: spec.id.clone(),
            state,
        };
        self.write(&status)?;
        Ok(status)
    }

    async fn stop(&self, id: &str) -> anyhow::Result<()> {
        match std::fs::remove_file(self.state_path(id)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match std::fs::remove_dir_all(self.dir.join(id)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn observe(&self) -> anyhow::Result<Vec<VmStatus>> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Ok(Vec::new());
        };
        Ok(entries
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .filter_map(|text| serde_json::from_str(&text).ok())
            .collect())
    }

    async fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            kvm: true,
            root: false,
            egress: true,
            free_vcpus: 64,
            free_memory_mib: 65_536,
        }
    }
}

/// The metadata a VM boots with: where to register, the one-time token, and
/// its own id. `grund join --mmds` reads `.grund`.
pub fn metadata(
    vm_id: &str,
    grund_url: &str,
    enrollment_token: &str,
    expires_at: &str,
) -> serde_json::Value {
    serde_json::json!({
        "grund": {
            "url": grund_url,
            "enrollment_token": enrollment_token,
            "expires_at": expires_at,
        },
        "vm": { "id": vm_id },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_machine_without_vms_refuses_to_run_one_and_reports_no_capability() {
        let runtime = NoVms;
        let spec = VmSpec {
            id: "vm-1".into(),
            vcpus: 1,
            memory_mib: 256,
            disk_gib: 1,
            image: VmImage {
                kernel: Artifact {
                    url: "https://example.com/k".into(),
                    sha256: "0".repeat(64),
                },
                rootfs: Artifact {
                    url: "https://example.com/r".into(),
                    sha256: "0".repeat(64),
                },
            },
            mmds: metadata("vm-1", "https://grund.example.com", "grund_join_x", "later"),
        };
        assert!(matches!(
            runtime.ensure(&spec).await.unwrap().state,
            VmState::Failed { .. }
        ));
        assert_eq!(runtime.capabilities().await, VmCapabilities::default());
        assert!(runtime.observe().await.unwrap().is_empty());
    }

    #[test]
    fn the_metadata_is_what_grund_join_reads() {
        let document = metadata(
            "vm-1",
            "https://g.example",
            "grund_join_x",
            "2026-09-26T12:00:00Z",
        );
        assert_eq!(document["grund"]["url"], "https://g.example");
        assert_eq!(document["grund"]["enrollment_token"], "grund_join_x");
        assert_eq!(document["vm"]["id"], "vm-1");
    }

    #[test]
    fn a_status_serialises_its_state_flat() {
        let status = VmStatus {
            id: "vm-1".into(),
            state: VmState::Exited { code: Some(1) },
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["state"], "exited");
        assert_eq!(json["code"], 1);
    }
}
