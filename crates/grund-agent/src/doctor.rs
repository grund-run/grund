//! `grund doctor machine`: a read-only check of a machine for grund's agent:
//! what it runs on, whether the agent can run and is running, whether it
//! reaches its instance, and whether its clock agrees with it (grund-docs
//! design/self-hosted.md §5, §6.4). The VM checks come from the runtime
//! (`grund_vm::doctor`) and are passed in.
//!
//! Nothing is changed. Without root some checks cannot be answered; they
//! say so instead of guessing.

use std::{path::PathBuf, process::Command, time::Duration};

use grund_domain::doctor::{Check, Report};

use crate::join;

/// How far this machine's clock may be from its instance's before
/// registration refuses it (the enrollment proof's window).
pub const CLOCK_FAIL: Duration = Duration::from_secs(300);

/// How far it may be before it is worth fixing.
pub const CLOCK_WARN: Duration = Duration::from_secs(30);

/// Free space under the agent's data directory below which VMs will not fit.
pub const DISK_WARN_BYTES: u64 = 10 << 30;

/// `grund doctor machine`.
#[derive(Clone, Debug, clap::Args)]
pub struct MachineArgs {
    /// Where `grund join` kept the machine's identity.
    #[arg(
        long,
        env = "GRUND_AGENT_DATA_DIR",
        default_value = "/var/lib/grund/agent"
    )]
    pub data_dir: PathBuf,

    /// An instance to check against before this machine has joined one,
    /// e.g. https://grund.example.com. A joined machine checks its own.
    #[arg(long, env = "GRUND_URL")]
    pub url: Option<String>,
}

/// Runs the checks, with the VM runtime's after the host's. `own_revision`
/// is the commit this binary was built from, to compare with the instance's.
pub async fn run(args: &MachineArgs, vm_checks: Vec<Check>, own_revision: &str) -> Report {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut report = Report::new("machine");
    report.push(arch());
    report.push(kernel());
    report.push(memory());
    report.push(privilege());
    let systemd = systemd();
    let has_systemd = systemd.status == grund_domain::doctor::Status::Ok;
    report.push(systemd);
    report.push(agent_service(has_systemd));
    for check in vm_checks {
        report.push(check);
    }
    report.push(disk(&args.data_dir));
    instance(args, own_revision, &mut report).await;
    report
}

fn root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn arch() -> Check {
    match std::env::consts::ARCH {
        "x86_64" => Check::ok("arch", "x86_64"),
        "aarch64" => Check::warn(
            "arch",
            "aarch64: grund publishes x86_64 builds only so far",
            "install.sh refuses this machine until an aarch64 build is published",
        ),
        other => Check::fail(
            "arch",
            other.to_string(),
            "grund's agent runs on x86_64 (aarch64 later)",
        ),
    }
}

fn kernel() -> Check {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|p| p.parse::<u32>().ok());
    let version = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    if version >= (6, 1) {
        Check::ok("kernel", release)
    } else if version >= (5, 15) {
        Check::warn(
            "kernel",
            format!("{release}: below the tested 6.1"),
            "use a kernel from 6.1 (Debian 12 or newer)",
        )
    } else {
        Check::fail(
            "kernel",
            format!("{release}: below 5.15"),
            "use a kernel from 6.1 (Debian 12 or newer)",
        )
    }
}

fn memory() -> Check {
    let mib = join::facts().memory_mib;
    if mib >= 1024 {
        Check::ok("memory", format!("{mib} MiB"))
    } else {
        Check::fail(
            "memory",
            format!("{mib} MiB: below 1 GiB"),
            "the agent, a VM and its guest need at least 1 GiB",
        )
    }
}

fn privilege() -> Check {
    if root() {
        Check::ok(
            "privilege",
            "root: as the agent runs, so every check can be answered",
        )
    } else {
        Check::warn(
            "privilege",
            "not root: this run can only report, and some checks skip; the agent needs root",
            "run it as root (sudo grund doctor machine); a rootless agent is not built",
        )
    }
}

fn systemd() -> Check {
    if !std::path::Path::new("/run/systemd/system").is_dir() {
        return Check::fail(
            "systemd",
            "not running under systemd",
            "install.sh and grund-agent.service need systemd; elsewhere, supervise `grund agent` yourself",
        );
    }
    let version = Command::new("systemctl")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .nth(1)
                .map(str::to_string)
        })
        .unwrap_or_default();
    Check::ok("systemd", format!("systemd {version}"))
}

fn agent_service(has_systemd: bool) -> Check {
    if !has_systemd {
        return Check::skip("agent-service", "needs systemd");
    }
    let state = Command::new("systemctl")
        .args([
            "show",
            "grund-agent.service",
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let get = |key: &str| {
        state
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_default()
            .to_string()
    };
    match (get("LoadState").as_str(), get("ActiveState").as_str()) {
        ("loaded", "active") => Check::ok("agent-service", "grund-agent.service is running"),
        ("loaded", other) => Check::fail(
            "agent-service",
            format!("grund-agent.service is {other} ({})", get("SubState")),
            "journalctl -u grund-agent says why; systemctl restart grund-agent starts it again",
        ),
        _ => Check::skip(
            "agent-service",
            "grund-agent.service is not installed: this machine has not joined an instance",
        ),
    }
}

fn disk(data_dir: &std::path::Path) -> Check {
    let path = data_dir
        .ancestors()
        .find(|p| p.exists())
        .unwrap_or(std::path::Path::new("/"));
    let Some(free) = free_bytes(path) else {
        return Check::skip(
            "disk",
            format!("cannot read the free space of {}", path.display()),
        );
    };
    let gib = free as f64 / f64::from(1u32 << 30);
    let detail = format!("{gib:.1} GiB free under {}", path.display());
    if free < DISK_WARN_BYTES {
        Check::warn(
            "disk",
            detail,
            "VMs' images and disks need room: free space, or give VMs less (GRUND_VM_DISK_GIB)",
        )
    } else {
        Check::ok("disk", detail)
    }
}

fn free_bytes(path: &std::path::Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    Some(stat.f_bavail.saturating_mul(stat.f_frsize))
}

async fn instance(args: &MachineArgs, own: &str, report: &mut Report) {
    let record = join::read_record(&args.data_dir);
    let (url, machine) = match (&record, &args.url) {
        (Ok(Some(record)), _) => (
            record.instance_url.clone(),
            Some(format!("{} ({})", record.name, record.machine_id)),
        ),
        (_, Some(url)) => (url.trim_end_matches('/').to_string(), None),
        (Ok(None), None) => {
            report.push(Check::skip(
                "instance",
                "not joined, and no --url to check against",
            ));
            report.push(Check::skip("clock", "needs an instance to compare with"));
            return;
        }
        (Err(error), None) => {
            let fix = if root() {
                "check the file; grund join wrote it"
            } else {
                "run as root: the machine's identity is readable only by root"
            };
            report.push(Check::skip("instance", format!("{error:#}; {fix}")));
            report.push(Check::skip("clock", "needs an instance to compare with"));
            return;
        }
    };
    let http = match join::http_client() {
        Ok(http) => http,
        Err(error) => {
            report.push(Check::fail("instance", format!("{error:#}"), "report this"));
            return;
        }
    };
    let asked = std::time::SystemTime::now();
    let answer = http.get(format!("{url}/health/ready")).send().await;
    let answered = std::time::SystemTime::now();
    let response = match answer {
        Ok(response) => response,
        Err(error) => {
            report.push(Check::fail(
                "instance",
                format!("cannot reach {url}: {}", reqwest_reason(&error)),
                "check the machine's DNS and route to it, and that its certificate is trusted here (update-ca-certificates for a private CA)",
            ));
            report.push(Check::skip("clock", "needs the instance to answer"));
            return;
        }
    };
    let date = response
        .headers()
        .get("date")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| chrono::DateTime::parse_from_rfc2822(v).ok());
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    let revision = body["revision"].as_str().unwrap_or("unknown").to_string();
    let who = machine.map(|m| format!("{m} of ")).unwrap_or_default();
    let check = if !status.is_success() {
        Check::fail(
            "instance",
            format!("{who}{url}, which answers readiness {status}"),
            "the instance is up but not ready: grund doctor instance, on its machine, says why",
        )
    } else if record.as_ref().is_ok_and(Option::is_some) && own != revision && own != "unknown" {
        Check::warn(
            "instance",
            format!(
                "{who}{url} runs grund {}, this machine {}",
                short(&revision),
                short(own)
            ),
            "run the Machines page's install command on this machine again: it keeps the machine's identity and installs the instance's build (machines do not follow their instance yet)",
        )
    } else {
        Check::ok(
            "instance",
            format!("{who}{url} is ready, grund {}", short(&revision)),
        )
    };
    report.push(check);
    report.push(clock(date, asked, answered));
}

fn clock(
    date: Option<chrono::DateTime<chrono::FixedOffset>>,
    asked: std::time::SystemTime,
    answered: std::time::SystemTime,
) -> Check {
    let Some(date) = date else {
        return Check::skip("clock", "the instance sent no Date header");
    };
    let theirs = std::time::SystemTime::from(date);
    let round_trip = answered.duration_since(asked).unwrap_or_default();
    let ours = asked + round_trip / 2;
    let skew = ours
        .duration_since(theirs)
        .or_else(|e| Ok::<_, ()>(e.duration()))
        .unwrap_or_default();
    let seconds = skew.as_secs();
    let fix = "synchronise the clock (timedatectl set-ntp true, or chrony)";
    if skew > CLOCK_FAIL {
        Check::fail(
            "clock",
            format!(
                "{seconds} s from the instance's: registration refuses more than {} s",
                CLOCK_FAIL.as_secs()
            ),
            fix,
        )
    } else if skew > CLOCK_WARN {
        Check::warn("clock", format!("{seconds} s from the instance's"), fix)
    } else {
        Check::ok(
            "clock",
            format!("within {} s of the instance's", seconds.max(1)),
        )
    }
}

fn short(revision: &str) -> &str {
    revision.get(..12).unwrap_or(revision)
}

fn reqwest_reason(error: &reqwest::Error) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(inner) = source {
        text = format!("{text}: {inner}");
        source = inner.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clock_six_minutes_off_fails_and_one_second_off_passes() {
        let now = std::time::SystemTime::now();
        let at = |offset: i64| {
            Some(
                chrono::DateTime::<chrono::Utc>::from(now).fixed_offset()
                    + chrono::Duration::seconds(offset),
            )
        };
        assert_eq!(
            clock(at(360), now, now).status,
            grund_domain::doctor::Status::Fail
        );
        assert_eq!(
            clock(at(-360), now, now).status,
            grund_domain::doctor::Status::Fail
        );
        assert_eq!(
            clock(at(60), now, now).status,
            grund_domain::doctor::Status::Warn
        );
        assert_eq!(
            clock(at(0), now, now).status,
            grund_domain::doctor::Status::Ok
        );
    }
}
