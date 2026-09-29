//! What `grund doctor` checks for VMs on this machine: `/dev/kvm`, nftables
//! for the bridge, a foreign firewall that drops forwarded traffic, and the
//! cgroup systemd delegated to the agent. Read-only: the ruleset is listed,
//! never changed.

use std::{path::Path, process::Command};

use grund_domain::doctor::Check;

use crate::{net, running_as_root};

/// systemd's first release with `DelegateSubgroup=`, which grund-agent.service
/// needs for VM limits (cgroup.rs).
pub const DELEGATE_SUBGROUP_SYSTEMD: u32 = 254;

/// The VM checks, in the order `grund doctor` prints them.
pub fn checks() -> Vec<Check> {
    let kvm = kvm();
    let vms = kvm.status == grund_domain::doctor::Status::Ok;
    vec![kvm, nftables(vms), forward_drop(vms), cgroups()]
}

fn kvm() -> Check {
    if !Path::new("/dev/kvm").exists() {
        return Check::warn(
            "kvm",
            "no /dev/kvm: this machine runs no VMs",
            "turn on VT-x or AMD-V in the firmware, or on a VM enable nested virtualisation; the machine still joins without VMs",
        );
    }
    let opens = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    match (opens, running_as_root()) {
        (true, _) => Check::ok("kvm", "/dev/kvm opens: Firecracker VMs can run"),
        (false, false) => Check::skip(
            "kvm",
            "/dev/kvm exists, and this user cannot open it; the agent runs as root",
        ),
        (false, true) => Check::fail(
            "kvm",
            "/dev/kvm exists, and root cannot open it",
            "check the kvm module (lsmod | grep kvm) and whether another hypervisor holds it",
        ),
    }
}

fn nftables(vms: bool) -> Check {
    if !vms {
        return Check::skip("nftables", "only VMs need it");
    }
    let nft = Command::new("nft").arg("--version").output();
    match nft {
        Ok(output) if output.status.success() => Check::ok(
            "nftables",
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ),
        _ => Check::warn(
            "nftables",
            "no nft command: VMs get no network (grund's bridge needs its table inet grund)",
            "install nftables (install.sh does, on Debian and Ubuntu)",
        ),
    }
}

fn forward_drop(vms: bool) -> Check {
    if !vms {
        return Check::skip("forward-drop", "only VMs' traffic is forwarded");
    }
    if !running_as_root() {
        return Check::skip("forward-drop", "needs root to read the ruleset");
    }
    let listed = Command::new("nft").args(["list", "ruleset"]).output();
    match listed {
        Ok(output) if output.status.success() => {
            match net::foreign_forward_drop(&String::from_utf8_lossy(&output.stdout)) {
                None => Check::ok("forward-drop", "no other firewall drops forwarded traffic"),
                Some(why) => Check::warn(
                    "forward-drop",
                    format!("{why}: VMs here get no egress, so none is placed here"),
                    "run VMs on a machine without Docker, or allow grundbr0 in that chain yourself; grund adds no rule to Docker's chains (design/self-hosted.md §6.4, a decision not taken)",
                ),
            }
        }
        _ => Check::skip("forward-drop", "nft could not list the ruleset"),
    }
}

fn cgroups() -> Check {
    let controllers = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers");
    let Ok(controllers) = controllers else {
        return Check::fail(
            "cgroup",
            "no cgroup v2 hierarchy at /sys/fs/cgroup (v1 or hybrid)",
            "boot with the unified hierarchy (systemd.unified_cgroup_hierarchy=1, the default since systemd 247)",
        );
    };
    let controllers = controllers.trim().to_string();
    let missing: Vec<&str> = ["cpu", "memory"]
        .into_iter()
        .filter(|c| !controllers.split_whitespace().any(|have| have == *c))
        .collect();
    if !missing.is_empty() {
        return Check::fail(
            "cgroup",
            format!("cgroup v2 without {}", missing.join(" and ")),
            "enable the cpu and memory controllers in the kernel",
        );
    }
    let unit = unit_properties();
    let get = |key: &str| {
        unit.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_default()
    };
    if get("LoadState") != "loaded" {
        return Check::ok(
            "cgroup",
            format!(
                "cgroup v2 ({controllers}); grund-agent.service is not installed, so delegation is not checked"
            ),
        );
    }
    let delegated = get("Delegate") == "yes" && get("DelegateSubgroup") == "agent";
    let group = get("ControlGroup");
    let leaf = !group.is_empty()
        && Path::new("/sys/fs/cgroup")
            .join(group.trim_start_matches('/'))
            .join("agent")
            .is_dir();
    match (delegated, leaf, get("ActiveState")) {
        (true, true, _) => Check::ok(
            "cgroup",
            "grund-agent.service is delegated its cgroup, with the agent in its own leaf: VMs get CPU and memory limits",
        ),
        (true, false, "active") => Check::warn(
            "cgroup",
            format!(
                "grund-agent.service asks for delegation, but runs in {group} with no agent leaf: VMs run without limits"
            ),
            format!(
                "systemd {DELEGATE_SUBGROUP_SYSTEMD} or newer is needed for DelegateSubgroup=agent"
            ),
        ),
        (true, false, state) => Check::ok(
            "cgroup",
            format!("grund-agent.service is delegated its cgroup (not running: {state})"),
        ),
        (false, _, _) => Check::warn(
            "cgroup",
            "grund-agent.service has no Delegate=yes and DelegateSubgroup=agent: VMs run without CPU and memory limits",
            "run the Machines page's install command again; it writes the unit (systemd 254+)",
        ),
    }
}

fn unit_properties() -> Vec<(String, String)> {
    Command::new("systemctl")
        .args([
            "show",
            "grund-agent.service",
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "Delegate",
            "-p",
            "DelegateSubgroup",
            "-p",
            "ControlGroup",
        ])
        .output()
        .ok()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default()
}
