//! cgroup v2 limits for jailed VMs, in the cgroup systemd delegated to the
//! agent (`Delegate=yes` on grund-agent.service).
//!
//! ```text
//!   <the agent's cgroup>/          delegated: grund may make children here
//!       agent/                     the agent itself, moved in at start, so
//!                                  the parent has no processes of its own
//!                                  (cgroup v2 lets controllers be enabled for
//!                                  children only then)
//!       vms/                       cpu and memory enabled for its children
//!           <short>/               one VM: made by the jailer, with cpu.max
//!                                  and memory.max
//! ```
//!
//! A VM's `cpu.max` is its vCPUs' worth of CPU time. Its `memory.max` is
//! the guest's memory plus [`MEMORY_OVERHEAD_MIB`] for Firecracker itself,
//! so the limit stops a runaway VMM and never a guest using its own RAM.
//!
//! Without a delegated cgroup (the agent not under systemd, or its unit
//! without `Delegate=yes`), VMs run without these limits, and
//! [`delegate`] says why.

use std::path::{Path, PathBuf};

/// Firecracker's own allowance above the guest's memory.
pub const MEMORY_OVERHEAD_MIB: u64 = 128;

const ROOT: &str = "/sys/fs/cgroup";

/// Where the jailer makes VMs' cgroups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cgroups {
    /// The parent of every VM's cgroup, relative to the cgroup root, as the
    /// jailer's `--parent-cgroup` takes it.
    pub parent: String,
}

impl Cgroups {
    /// The jailer's cgroup arguments for a VM of this size.
    pub fn args(&self, vcpus: u32, memory_mib: u32) -> Vec<String> {
        vec![
            "--cgroup-version".into(),
            "2".into(),
            "--parent-cgroup".into(),
            self.parent.clone(),
            "--cgroup".into(),
            format!("cpu.max={} 100000", u64::from(vcpus) * 100_000),
            "--cgroup".into(),
            format!(
                "memory.max={}",
                (u64::from(memory_mib) + MEMORY_OVERHEAD_MIB) * 1024 * 1024
            ),
        ]
    }

    /// The cgroup of the VM the jailer knows as `id`.
    pub fn of(&self, id: &str) -> PathBuf {
        Path::new(ROOT).join(&self.parent).join(id)
    }

    /// Removes the VM's cgroup, once it has no processes: the jailer wants
    /// to make it itself on the next launch.
    pub fn remove(&self, id: &str) {
        let _ = std::fs::remove_dir(self.of(id));
    }
}

/// The cgroup this process is in, from `/proc/self/cgroup` (cgroup v2's
/// `0::<path>` line).
pub fn own(proc_self_cgroup: &str) -> Option<String> {
    proc_self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|path| path.trim().to_string())
}

/// The delegated cgroup to build under: this process's own, or its parent
/// when an earlier start already moved it into `agent`.
pub fn base(own: &str) -> String {
    own.strip_suffix("/agent").unwrap_or(own).to_string()
}

/// Moves this process into `<its cgroup>/agent` and prepares `vms/` for the
/// jailer. The error says why VMs will run without limits.
pub fn delegate() -> Result<Cgroups, String> {
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .as_deref()
        .and_then(own)
        .ok_or("no cgroup v2 hierarchy")?;
    let base = base(&own);
    if base == "/" || base.is_empty() {
        return Err("the agent runs in the root cgroup".into());
    }
    let dir = Path::new(ROOT).join(base.trim_start_matches('/'));
    let write = |path: PathBuf, value: &str| {
        std::fs::write(&path, value).map_err(|e| format!("{}: {e}", path.display()))
    };
    let make = |path: PathBuf| match std::fs::create_dir(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(format!(
            "{}: {e} (is the agent's unit Delegate=yes?)",
            path.display()
        )),
    };
    make(dir.join("agent"))?;
    write(
        dir.join("agent/cgroup.procs"),
        &std::process::id().to_string(),
    )?;
    write(dir.join("cgroup.subtree_control"), "+cpu +memory")?;
    make(dir.join("vms"))?;
    write(dir.join("vms/cgroup.subtree_control"), "+cpu +memory")?;
    Ok(Cgroups {
        parent: format!("{}/vms", base.trim_start_matches('/')),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agents_cgroup_is_found_and_built_under_once() {
        assert_eq!(
            own("0::/system.slice/grund-agent.service\n").as_deref(),
            Some("/system.slice/grund-agent.service")
        );
        assert_eq!(own("1:name=systemd:/x\n"), None);
        assert_eq!(
            base("/system.slice/grund-agent.service/agent"),
            "/system.slice/grund-agent.service"
        );
        assert_eq!(
            base("/system.slice/grund-agent.service"),
            "/system.slice/grund-agent.service"
        );
    }

    #[test]
    fn a_vms_limits_are_its_vcpus_and_its_memory_with_the_vmms_allowance() {
        let cgroups = Cgroups {
            parent: "system.slice/grund-agent.service/vms".into(),
        };
        let args = cgroups.args(2, 512).join(" ");
        assert_eq!(
            args,
            "--cgroup-version 2 --parent-cgroup system.slice/grund-agent.service/vms --cgroup cpu.max=200000 100000 --cgroup memory.max=671088640"
        );
        assert_eq!(
            cgroups.of("0123456789abcdef"),
            Path::new("/sys/fs/cgroup/system.slice/grund-agent.service/vms/0123456789abcdef")
        );
    }
}
