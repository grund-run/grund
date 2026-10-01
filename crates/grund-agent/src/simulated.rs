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

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::runtime::{
    AppsCapabilities, ContainerRuntime, ContainerSpec, ContainerStatus, ImageRef, Probe, TaskState,
};

/// The simulated runtime.
#[derive(Debug, Clone)]
pub struct SimulatedContainers {
    dir: PathBuf,
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
        Self { dir }
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

impl ContainerRuntime for SimulatedContainers {
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
        self.write(&Record {
            spec: spec.clone(),
            state: TaskState::Running {
                pid: std::process::id(),
            },
            started_at_ms: now_ms(),
        })
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
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            let Some(record) = self.read(id) else {
                continue;
            };
            let record = self.advance(record)?;
            statuses.push(ContainerStatus {
                id: record.spec.id.clone(),
                spec_hash: record.spec.spec_hash.clone(),
                state: record.state.clone(),
                stop_signal: record.spec.stop_signal.clone(),
                stop_grace: record.spec.stop_grace,
            });
        }
        statuses.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(statuses)
    }

    async fn probe(&self, id: &str, _probe: &Probe, _timeout: Duration) -> Result<(), String> {
        let record = self
            .read(id)
            .ok_or_else(|| "no such container".to_string())?;
        if !matches!(record.state, TaskState::Running { .. }) {
            return Err("its process is not running".into());
        }
        match Self::behaviour(&record.spec) {
            Some("unready") => Err("status 503".into()),
            _ => Ok(()),
        }
    }
}
