//! Whether this machine can run grund's containers, from what the kernel
//! says: no download, no daemon, a few small files read.

use std::path::Path;

use grund_agent::runtime::AppsCapabilities;

use crate::binaries::Arch;

/// `CGROUP2_SUPER_MAGIC`: the filesystem of a cgroup v2 hierarchy.
pub const CGROUP2_MAGIC: i64 = 0x6367_7270;

/// What the machine's kernel and files say, gathered by [`HostFacts::read`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    pub euid: u32,
    /// The kernel's architecture name (`uname -m`).
    pub arch: String,
    /// Whether `/sys/fs/cgroup` is a cgroup v2 hierarchy.
    pub cgroup2: bool,
    /// `/sys/fs/cgroup/cgroup.controllers`.
    pub controllers: String,
    /// `/proc/filesystems`.
    pub filesystems: String,
    /// Whether the overlay module is on disk, to be loaded on first mount.
    pub overlay_module: bool,
    /// `/proc/meminfo`.
    pub meminfo: String,
    pub cpus: usize,
}

impl HostFacts {
    /// Reads this machine's facts.
    pub fn read() -> Self {
        let release = kernel_release();
        let overlay_module = !release.is_empty()
            && Path::new(&format!("/lib/modules/{release}/kernel/fs/overlayfs")).is_dir();
        Self {
            euid: unsafe { libc::geteuid() },
            arch: std::env::consts::ARCH.into(),
            cgroup2: fs_magic(Path::new("/sys/fs/cgroup")) == Some(CGROUP2_MAGIC),
            controllers: std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
                .unwrap_or_default(),
            filesystems: std::fs::read_to_string("/proc/filesystems").unwrap_or_default(),
            overlay_module,
            meminfo: std::fs::read_to_string("/proc/meminfo").unwrap_or_default(),
            cpus: std::thread::available_parallelism().map_or(1, |n| n.get()),
        }
    }
}

fn kernel_release() -> String {
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut name) } != 0 {
        return String::new();
    }
    let release: Vec<u8> = name
        .release
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&release).into_owned()
}

fn fs_magic(path: &Path) -> Option<i64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    Some(stat.f_type as i64)
}

/// What `facts` allow, with the first reason they do not.
pub fn assess(facts: &HostFacts) -> AppsCapabilities {
    let memory_mib = facts
        .meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| {
            rest.trim()
                .trim_end_matches("kB")
                .trim()
                .parse::<u64>()
                .ok()
        })
        .map_or(0, |kib| kib / 1024);
    let cpu_millis = u32::try_from(facts.cpus.saturating_mul(1000)).unwrap_or(u32::MAX);
    let controllers: Vec<&str> = facts.controllers.split_whitespace().collect();
    let overlay = facts
        .filesystems
        .lines()
        .any(|line| line.split_whitespace().last() == Some("overlay"));
    let reason = if Arch::parse(&facts.arch).is_none() {
        format!("containers run on x86_64 and aarch64, not {}", facts.arch)
    } else if facts.euid != 0 {
        "the agent does not run as root".to_string()
    } else if !facts.cgroup2 {
        "/sys/fs/cgroup is not cgroup v2".to_string()
    } else if !controllers.contains(&"memory") || !controllers.contains(&"cpu") {
        "cgroup v2 lacks the memory or cpu controller".to_string()
    } else if !overlay && !facts.overlay_module {
        "the kernel has no overlay filesystem".to_string()
    } else {
        String::new()
    };
    AppsCapabilities {
        apps: reason.is_empty(),
        reason,
        arch: facts.arch.clone(),
        memory_mib,
        cpu_millis,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capable() -> HostFacts {
        HostFacts {
            euid: 0,
            arch: "x86_64".into(),
            cgroup2: true,
            controllers: "cpuset cpu io memory hugetlb pids rdma misc\n".into(),
            filesystems: "nodev\tsysfs\nnodev\tproc\n\text4\nnodev\toverlay\n".into(),
            overlay_module: false,
            meminfo: "MemTotal:        2014412 kB\nMemFree:          1201212 kB\n".into(),
            cpus: 2,
        }
    }

    #[test]
    fn a_root_agent_on_cgroup_v2_with_overlay_can_run_apps() {
        let caps = assess(&capable());
        assert!(caps.apps, "{}", caps.reason);
        assert_eq!(caps.reason, "");
        assert_eq!(caps.arch, "x86_64");
        assert_eq!(caps.memory_mib, 1967);
        assert_eq!(caps.cpu_millis, 2000);
    }

    #[test]
    fn each_missing_piece_is_the_reason() {
        for (change, reason) in [
            (
                (|f: &mut HostFacts| f.arch = "riscv64".into()) as fn(&mut HostFacts),
                "containers run on x86_64 and aarch64, not riscv64",
            ),
            (|f| f.euid = 1000, "the agent does not run as root"),
            (|f| f.cgroup2 = false, "/sys/fs/cgroup is not cgroup v2"),
            (
                |f| f.controllers = "cpuset io pids".into(),
                "cgroup v2 lacks the memory or cpu controller",
            ),
            (
                |f| f.filesystems = "nodev\tproc\n".into(),
                "the kernel has no overlay filesystem",
            ),
        ] {
            let mut facts = capable();
            change(&mut facts);
            let caps = assess(&facts);
            assert!(!caps.apps);
            assert_eq!(caps.reason, reason);
        }
    }

    #[test]
    fn an_overlay_module_on_disk_is_enough() {
        let mut facts = capable();
        facts.filesystems = "nodev\tproc\n".into();
        facts.overlay_module = true;
        assert!(assess(&facts).apps);
        facts.arch = "aarch64".into();
        assert!(assess(&facts).apps);
    }
}
