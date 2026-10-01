//! grund's own containerd: its config, and starting it so it outlives the
//! agent.
//!
//! It never shares anything with a containerd already on the machine
//! (Docker's, on `/run/containerd`): its root, state, sockets and config are
//! grund's, it imports no other config (`imports = []`, where containerd's
//! default reads `/etc/containerd/conf.d`), it listens on no TCP port, and
//! the plugins grund does not use (CRI, NRI, the pod sandbox) are off. Its
//! shims' sockets are in `<run dir>/s`, not containerd's default
//! `/run/containerd/s`, and runc's state in `<run dir>/runc` (set per
//! container), not `/run/containerd/runc`. Its
//! `PATH` starts with grund's own binary directory, so the shim and runc it
//! runs are grund's, never `/usr/bin/containerd-shim-runc-v2`.
//!
//! On a systemd machine it runs as the transient unit `grund-containerd`
//! with `KillMode=process`, so stopping or restarting it leaves the
//! containers' shims, and so the apps, running (apps.md §7.3). Elsewhere it
//! is spawned in its own session with its output in a log file.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::Context;

use crate::Config;

/// The systemd unit containerd runs as.
pub const UNIT: &str = "grund-containerd.service";

/// The plugins grund's containerd does not load: Kubernetes' (CRI and the
/// pod sandbox), NRI (whose socket is shared, in `/var/run/nri`), the
/// `opt` plugin (which would create `/opt/containerd`), and the
/// snapshotters grund does not unpack onto.
pub const DISABLED_PLUGINS: [&str; 12] = [
    "io.containerd.grpc.v1.cri",
    "io.containerd.cri.v1.images",
    "io.containerd.cri.v1.runtime",
    "io.containerd.podsandbox.controller.v1.podsandbox",
    "io.containerd.sandbox.controller.v1.shim",
    "io.containerd.nri.v1.nri",
    "io.containerd.internal.v1.opt",
    "io.containerd.snapshotter.v1.blockfile",
    "io.containerd.snapshotter.v1.btrfs",
    "io.containerd.snapshotter.v1.devmapper",
    "io.containerd.snapshotter.v1.erofs",
    "io.containerd.snapshotter.v1.zfs",
];

fn toml_string(value: &Path) -> String {
    serde_json::to_string(&value.display().to_string()).unwrap_or_default()
}

/// containerd's config file for `config`, in containerd 2's version 4
/// format.
pub fn config_toml(config: &Config) -> String {
    let disabled = DISABLED_PLUGINS
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"version = 4
root = {root}
state = {state}
imports = []
disabled_plugins = [{disabled}]
oom_score = -999

[plugins.'io.containerd.server.v1.grpc']
  address = {grpc}
  uid = 0
  gid = 0

[plugins.'io.containerd.server.v1.ttrpc']
  address = {ttrpc}
  uid = 0
  gid = 0

[plugins.'io.containerd.server.v1.debug']
  address = ""

[plugins.'io.containerd.server.v1.metrics']
  address = ""

[plugins.'io.containerd.server.v1.grpc-tcp']
  address = ""

[plugins.'io.containerd.shim.v1.manager']
  socket_dir = {shim_sockets}

[plugins.'io.containerd.transfer.v1.local']
  config_path = {hosts}
"#,
        root = toml_string(&config.runtime_root()),
        state = toml_string(&config.state_dir()),
        grpc = toml_string(&config.socket()),
        ttrpc = toml_string(&config.ttrpc_socket()),
        shim_sockets = toml_string(&config.shim_socket_dir()),
        hosts = toml_string(&config.registry_hosts_dir()),
    )
}

/// The `PATH` containerd, and so its shims, run with: grund's binaries
/// first.
pub fn path_env(bin_dir: &Path) -> String {
    format!(
        "{}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        bin_dir.display()
    )
}

/// How containerd is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervisor {
    /// A transient systemd unit, when systemd is the init system.
    Systemd,
    /// A detached process in its own session.
    Detached,
}

impl Supervisor {
    /// systemd when it runs this machine (`/run/systemd/system` exists),
    /// else detached.
    pub fn of_host() -> Self {
        if Path::new("/run/systemd/system").is_dir() {
            Self::Systemd
        } else {
            Self::Detached
        }
    }
}

/// The `systemd-run` arguments that start containerd as [`UNIT`].
pub fn systemd_run_args(bin_dir: &Path, config_file: &Path) -> Vec<String> {
    vec![
        "--unit".into(),
        UNIT.into(),
        "--collect".into(),
        "--quiet".into(),
        "--description=grund's containerd".into(),
        "-p".into(),
        "KillMode=process".into(),
        "-p".into(),
        "Delegate=yes".into(),
        "-p".into(),
        "LimitNOFILE=1048576".into(),
        "-p".into(),
        "OOMScoreAdjust=-999".into(),
        "-p".into(),
        "Restart=on-failure".into(),
        "-p".into(),
        "RestartSec=1".into(),
        format!("--setenv=PATH={}", path_env(bin_dir)),
        bin_dir
            .join(crate::binaries::CONTAINERD)
            .display()
            .to_string(),
        "--config".into(),
        config_file.display().to_string(),
    ]
}

/// Starts containerd from `bin_dir` with the config already written to
/// `config.config_file()`.
pub async fn start(config: &Config, bin_dir: &Path, supervisor: Supervisor) -> anyhow::Result<()> {
    match supervisor {
        Supervisor::Systemd => start_unit(config, bin_dir).await,
        Supervisor::Detached => start_detached(config, bin_dir),
    }
}

async fn start_unit(config: &Config, bin_dir: &Path) -> anyhow::Result<()> {
    let active = tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", UNIT])
        .status()
        .await
        .context("run systemctl")?;
    if active.success() {
        return Ok(());
    }
    let _ = tokio::process::Command::new("systemctl")
        .args(["reset-failed", UNIT])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    let output = tokio::process::Command::new("systemd-run")
        .args(systemd_run_args(bin_dir, &config.config_file()))
        .output()
        .await
        .context("run systemd-run")?;
    if output.status.success() {
        return Ok(());
    }
    let restarted = tokio::process::Command::new("systemctl")
        .args(["start", UNIT])
        .output()
        .await
        .context("run systemctl start")?;
    anyhow::ensure!(
        restarted.status.success(),
        "systemd-run could not start {UNIT}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn start_detached(config: &Config, bin_dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;
    let log_path = config.containerd_log();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let mut command = std::process::Command::new(bin_dir.join(crate::binaries::CONTAINERD));
    command
        .arg("--config")
        .arg(config.config_file())
        .env("PATH", path_env(bin_dir))
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("spawn containerd")?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// The last lines containerd logged, to say why it did not come up.
pub async fn log_tail(config: &Config, supervisor: Supervisor) -> String {
    let text = match supervisor {
        Supervisor::Systemd => tokio::process::Command::new("journalctl")
            .args(["-u", UNIT, "-n", "15", "--no-pager", "-o", "cat"])
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default(),
        Supervisor::Detached => tokio::fs::read_to_string(config.containerd_log())
            .await
            .unwrap_or_default(),
    };
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

/// Waits until `answers` succeeds, at most `timeout`, polling every 100 ms.
pub async fn wait_until<F, Fut>(timeout: Duration, mut answers: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if answers().await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The directories containerd and the runtime need, created `0700` where
/// they hold state.
pub fn create_dirs(config: &Config) -> anyhow::Result<Vec<PathBuf>> {
    use std::os::unix::fs::DirBuilderExt;
    let dirs = vec![
        config.runtime_root(),
        config.state_dir(),
        config.run_dir.clone(),
        config.shim_socket_dir(),
        config.runc_root(),
        config.log_dir(),
        config.netns_dir(),
    ];
    for dir in &dirs {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
    }
    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_is_grunds_own_and_imports_nothing() {
        let config = Config::default();
        let toml = config_toml(&config);
        assert!(toml.starts_with("version = 4\n"));
        assert!(toml.contains("root = \"/var/lib/grund/runtime\"\n"));
        assert!(toml.contains("state = \"/run/grund/containerd\"\n"));
        assert!(toml.contains("imports = []\n"));
        assert!(toml.contains("  address = \"/run/grund/containerd.sock\"\n"));
        assert!(toml.contains("  address = \"/run/grund/containerd.sock.ttrpc\"\n"));
        assert!(toml.contains("io.containerd.grpc.v1.cri"));
        assert!(toml.contains("io.containerd.nri.v1.nri"));
        assert!(toml.contains("io.containerd.internal.v1.opt"));
        assert!(toml.contains("  socket_dir = \"/run/grund/s\"\n"));
        assert!(!toml.contains("/run/containerd"));
        assert!(!toml.contains("/var/lib/containerd"));
        assert!(!toml.contains("/etc/containerd"));
        for line in toml
            .lines()
            .filter(|l| l.trim_start().starts_with("address"))
        {
            assert!(
                line.contains("\"/run/grund/") || line.ends_with("\"\""),
                "only grund's sockets, no TCP: {line}"
            );
        }
    }

    #[test]
    fn the_config_follows_the_configured_directories() {
        let config = Config {
            data_dir: "/tmp/g data".into(),
            run_dir: "/tmp/g run".into(),
            ..Config::default()
        };
        let toml = config_toml(&config);
        assert!(toml.contains("root = \"/tmp/g data/runtime\""));
        assert!(toml.contains("address = \"/tmp/g run/containerd.sock\""));
    }

    #[test]
    fn containerd_runs_grunds_binaries_first_and_survives_its_own_stop() {
        let bin = Path::new("/var/lib/grund/bin/containerd-2.4.1");
        assert!(path_env(bin).starts_with("/var/lib/grund/bin/containerd-2.4.1:"));
        let args = systemd_run_args(bin, Path::new("/run/grund/containerd.toml"));
        let joined = args.join(" ");
        assert!(joined.starts_with("--unit grund-containerd.service --collect"));
        assert!(joined.contains("-p KillMode=process"));
        assert!(joined.contains("-p Delegate=yes"));
        assert!(joined.contains("-p LimitNOFILE=1048576"));
        assert!(
            joined.contains("--setenv=PATH=/var/lib/grund/bin/containerd-2.4.1:/usr/local/sbin")
        );
        assert!(joined.ends_with(
            "/var/lib/grund/bin/containerd-2.4.1/containerd --config /run/grund/containerd.toml"
        ));
    }
}
