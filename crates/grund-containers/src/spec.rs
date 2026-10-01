//! The OCI runtime spec of a grund container, built from its image's config
//! and its [`ContainerSpec`]: Docker's defaults for an unprivileged
//! container (its capability set, masked and read-only paths, mounts),
//! `noNewPrivileges`, a cgroup of its own under `/grund` with the replica's
//! memory, CPU and pids limits, and its own namespaces, the network one
//! being the runtime's per-container namespace (with the agent's device on
//! the private network in it, when it gave one). Never privileged, no host
//! namespace, no device and no host path; the one file from the host is the
//! agent's `/etc/resolv.conf`, read-only, added beside this spec.
//!
//! What it leaves out, for now: a seccomp profile, user namespaces,
//! AppArmor/SELinux labels and `/etc/hosts`.

use std::path::Path;

use anyhow::Context;
use grund_agent::runtime::ContainerSpec;
use serde_json::{Value, json};

use crate::image::ImageConfig;

/// The type URL containerd records a runtime spec under.
pub const SPEC_TYPE_URL: &str = "types.containerd.io/opencontainers/runtime-spec/1/Spec";

/// Docker's default capability set (moby `oci/caps/defaults.go`).
pub const DEFAULT_CAPABILITIES: [&str; 14] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

/// Docker's default masked paths.
pub const MASKED_PATHS: [&str; 12] = [
    "/proc/asound",
    "/proc/acpi",
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];

/// Docker's default read-only paths.
pub const READONLY_PATHS: [&str; 5] = [
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];

/// The CFS period every container's CPU quota is over, in microseconds.
pub const CPU_PERIOD_US: u64 = 100_000;
/// The most processes a container may have.
pub const PIDS_LIMIT: i64 = 4096;
/// The `PATH` a container gets when its image sets none (Docker's).
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Who a container's process runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub additional_gids: Vec<u32>,
    /// From the image's `/etc/passwd` when the user is listed there.
    pub home: Option<String>,
}

/// Whether resolving `user` (an image's `User`) needs the image's
/// `/etc/passwd` and `/etc/group`: a name, or a uid without a gid.
pub fn needs_passwd(user: &str) -> bool {
    let user = user.trim();
    if user.is_empty() {
        return false;
    }
    match user.split_once(':') {
        Some((u, g)) => u.parse::<u32>().is_err() || g.parse::<u32>().is_err(),
        None => true,
    }
}

/// Resolves an image's `User` (`""`, `uid`, `uid:gid`, `name`,
/// `name:group`, …) the way Docker does, from the image's own
/// `/etc/passwd` and `/etc/group` when given. A name that is not listed is
/// refused.
pub fn resolve_user(user: &str, passwd: Option<&str>, group: Option<&str>) -> anyhow::Result<User> {
    let user = user.trim();
    if user.is_empty() {
        return Ok(User {
            uid: 0,
            gid: 0,
            additional_gids: Vec::new(),
            home: Some("/root".into()),
        });
    }
    let (user_part, group_part) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    let entries: Vec<Vec<&str>> = passwd
        .unwrap_or_default()
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .filter(|f| f.len() >= 7)
        .collect();
    let groups: Vec<Vec<&str>> = group
        .unwrap_or_default()
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .filter(|f| f.len() >= 4)
        .collect();
    let entry = match user_part.parse::<u32>() {
        Ok(uid) => entries
            .iter()
            .find(|f| f[2].parse::<u32>().ok() == Some(uid)),
        Err(_) => Some(entries.iter().find(|f| f[0] == user_part).with_context(|| {
            if passwd.is_some() {
                format!("the image's user {user_part:?} is not in its /etc/passwd")
            } else {
                format!("the image's user {user_part:?} is a name and the image has no /etc/passwd")
            }
        })?),
    };
    let uid = match user_part.parse::<u32>() {
        Ok(uid) => uid,
        Err(_) => entry
            .and_then(|f| f[2].parse().ok())
            .with_context(|| format!("the image's /etc/passwd has no uid for {user_part:?}"))?,
    };
    let gid = match group_part {
        Some(g) => match g.parse::<u32>() {
            Ok(gid) => gid,
            Err(_) => groups
                .iter()
                .find(|f| f[0] == g)
                .and_then(|f| f[2].parse().ok())
                .with_context(|| format!("the image's group {g:?} is not in its /etc/group"))?,
        },
        None => entry.and_then(|f| f[3].parse().ok()).unwrap_or(0),
    };
    let name = entry.map(|f| f[0]);
    let mut additional_gids: Vec<u32> = match (group_part, name) {
        (None, Some(name)) => groups
            .iter()
            .filter(|f| f[3].split(',').any(|member| member == name))
            .filter_map(|f| f[2].parse().ok())
            .filter(|g| *g != gid)
            .collect(),
        _ => Vec::new(),
    };
    additional_gids.sort_unstable();
    additional_gids.dedup();
    Ok(User {
        uid,
        gid,
        additional_gids,
        home: entry.map(|f| f[5].to_string()).filter(|h| !h.is_empty()),
    })
}

/// The process to run: the spec's command when it has one, else the
/// image's entrypoint followed by its cmd.
pub fn process_args(spec: &ContainerSpec, image: &ImageConfig) -> anyhow::Result<Vec<String>> {
    let args = if spec.command.is_empty() {
        let mut args = image.config.entrypoint.clone().unwrap_or_default();
        args.extend(image.config.cmd.clone().unwrap_or_default());
        args
    } else {
        spec.command.clone()
    };
    anyhow::ensure!(
        !args.is_empty(),
        "the image has no entrypoint or command and the replica names none"
    );
    Ok(args)
}

/// The environment: the image's, then the spec's, a later value for a name
/// replacing an earlier one in place; `PATH` and `HOME` defaulted as Docker
/// does when neither sets them.
pub fn process_env(spec: &ContainerSpec, image: &ImageConfig, user: &User) -> Vec<String> {
    let mut env: Vec<(String, String)> = Vec::new();
    let mut set = |name: &str, value: &str| match env.iter_mut().find(|(n, _)| n == name) {
        Some(entry) => entry.1 = value.to_string(),
        None => env.push((name.to_string(), value.to_string())),
    };
    for entry in image.config.env.iter().flatten() {
        let (name, value) = entry.split_once('=').unwrap_or((entry, ""));
        set(name, value);
    }
    for (name, value) in &spec.env {
        set(name, value);
    }
    if !env.iter().any(|(n, _)| n == "PATH") {
        env.insert(0, ("PATH".into(), DEFAULT_PATH.into()));
    }
    if !env.iter().any(|(n, _)| n == "HOME") {
        let home = user
            .home
            .clone()
            .unwrap_or_else(|| if user.uid == 0 { "/root" } else { "/" }.into());
        env.push(("HOME".into(), home));
    }
    env.into_iter().map(|(n, v)| format!("{n}={v}")).collect()
}

/// The CPU quota for `cpu_millis` over [`CPU_PERIOD_US`]: 1000 millis is
/// one whole CPU, 100 000 µs per period. None (no quota) for 0; never less
/// than the kernel's 1 ms minimum.
pub fn cpu_quota(cpu_millis: u32) -> Option<i64> {
    if cpu_millis == 0 {
        return None;
    }
    let quota = u64::from(cpu_millis) * CPU_PERIOD_US / 1000;
    Some(i64::try_from(quota.max(1000)).unwrap_or(i64::MAX))
}

/// The memory limit in bytes.
pub fn memory_bytes(memory_mib: u64) -> i64 {
    i64::try_from(memory_mib.saturating_mul(1024 * 1024)).unwrap_or(i64::MAX)
}

/// The container's cgroup, relative to the cgroup v2 root.
pub fn cgroup_path(id: &str) -> String {
    format!("/grund/{id}")
}

/// The whole OCI runtime spec, as containerd records it.
pub fn oci_spec(
    spec: &ContainerSpec,
    image: &ImageConfig,
    user: &User,
    netns: &Path,
) -> anyhow::Result<Value> {
    let args = process_args(spec, image)?;
    let env = process_env(spec, image, user);
    let cwd = image
        .config
        .working_dir
        .clone()
        .filter(|d| d.starts_with('/'))
        .unwrap_or_else(|| "/".into());
    let memory = memory_bytes(spec.memory_mib);
    let mut cpu = json!({ "period": CPU_PERIOD_US });
    if let Some(quota) = cpu_quota(spec.cpu_millis) {
        cpu["quota"] = json!(quota);
    }
    let hostname: String = spec.id.chars().take(63).collect();
    Ok(json!({
        "ociVersion": "1.2.0",
        "process": {
            "terminal": false,
            "user": {
                "uid": user.uid,
                "gid": user.gid,
                "additionalGids": user.additional_gids,
            },
            "args": args,
            "env": env,
            "cwd": cwd,
            "capabilities": {
                "bounding": DEFAULT_CAPABILITIES,
                "effective": DEFAULT_CAPABILITIES,
                "permitted": DEFAULT_CAPABILITIES,
            },
            "rlimits": [
                { "type": "RLIMIT_NOFILE", "hard": 524_288, "soft": 1024 }
            ],
            "noNewPrivileges": true,
        },
        "root": { "path": "rootfs", "readonly": false },
        "hostname": hostname,
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc",
              "options": ["nosuid", "noexec", "nodev"] },
            { "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
              "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
            { "destination": "/dev/pts", "type": "devpts", "source": "devpts",
              "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"] },
            { "destination": "/dev/shm", "type": "tmpfs", "source": "shm",
              "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"] },
            { "destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue",
              "options": ["nosuid", "noexec", "nodev"] },
            { "destination": "/sys", "type": "sysfs", "source": "sysfs",
              "options": ["nosuid", "noexec", "nodev", "ro"] },
            { "destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup",
              "options": ["nosuid", "noexec", "nodev", "relatime", "ro"] }
        ],
        "linux": {
            "cgroupsPath": cgroup_path(&spec.id),
            "resources": {
                "devices": [ { "allow": false, "access": "rwm" } ],
                "memory": { "limit": memory, "swap": memory },
                "cpu": cpu,
                "pids": { "limit": PIDS_LIMIT },
            },
            "namespaces": [
                { "type": "pid" },
                { "type": "ipc" },
                { "type": "uts" },
                { "type": "mount" },
                { "type": "cgroup" },
                { "type": "network", "path": netns.display().to_string() }
            ],
            "maskedPaths": MASKED_PATHS,
            "readonlyPaths": READONLY_PATHS,
        }
    }))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use grund_agent::runtime::ImageRef;

    use super::*;

    fn spec() -> ContainerSpec {
        ContainerSpec {
            id: "web-v1-0".into(),
            image: ImageRef {
                reference: "traefik/whoami:v1.11.0".into(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            command: Vec::new(),
            env: vec![
                ("GREETING".into(), "hello".into()),
                ("PATH".into(), "/app/bin".into()),
            ],
            memory_mib: 256,
            cpu_millis: 500,
            stop_signal: "SIGTERM".into(),
            stop_grace: Duration::from_secs(10),
            labels: BTreeMap::new(),
            spec_hash: "h".into(),
            resolv_conf: None,
        }
    }

    fn image() -> ImageConfig {
        ImageConfig::parse(
            br#"{"architecture":"amd64","os":"linux",
            "config":{"Env":["PATH=/usr/bin:/bin","LANG=C.UTF-8"],
              "Entrypoint":["/docker-entrypoint.sh"],"Cmd":["nginx","-g","daemon off;"],
              "WorkingDir":"/srv","User":"101:101"},
            "rootfs":{"type":"layers","diff_ids":["sha256:1111111111111111111111111111111111111111111111111111111111111111"]}}"#,
        )
        .unwrap()
    }

    fn root() -> User {
        resolve_user("", None, None).unwrap()
    }

    #[test]
    fn the_spec_runs_the_image_entrypoint_and_cmd_with_the_spec_env_last() {
        let user = resolve_user("101:101", None, None).unwrap();
        let oci = oci_spec(
            &spec(),
            &image(),
            &user,
            Path::new("/run/grund/netns/web-v1-0"),
        )
        .unwrap();
        let process = &oci["process"];
        assert_eq!(
            process["args"],
            json!(["/docker-entrypoint.sh", "nginx", "-g", "daemon off;"])
        );
        assert_eq!(
            process["env"],
            json!(["PATH=/app/bin", "LANG=C.UTF-8", "GREETING=hello", "HOME=/"])
        );
        assert_eq!(process["cwd"], "/srv");
        assert_eq!(
            process["user"],
            json!({"uid": 101, "gid": 101, "additionalGids": []})
        );
        assert_eq!(process["noNewPrivileges"], true);
        assert_eq!(process["terminal"], false);
        assert_eq!(
            process["capabilities"]["bounding"],
            json!(DEFAULT_CAPABILITIES)
        );
        assert!(process["capabilities"].get("ambient").is_none());
        assert!(process["capabilities"].get("inheritable").is_none());
    }

    #[test]
    fn a_command_replaces_both_entrypoint_and_cmd() {
        let mut spec = spec();
        spec.command = vec!["/whoami".into(), "--port".into(), "8080".into()];
        let oci = oci_spec(&spec, &image(), &root(), Path::new("/n")).unwrap();
        assert_eq!(oci["process"]["args"], json!(["/whoami", "--port", "8080"]));
        assert_eq!(
            oci["process"]["env"].as_array().unwrap().last().unwrap(),
            "HOME=/root"
        );
    }

    #[test]
    fn an_image_with_nothing_to_run_is_refused() {
        let image = ImageConfig::default();
        let error = oci_spec(&spec(), &image, &root(), Path::new("/n")).unwrap_err();
        assert!(
            error.to_string().contains("no entrypoint or command"),
            "{error}"
        );
    }

    #[test]
    fn an_image_without_path_gets_dockers_default() {
        let mut spec = spec();
        spec.env.clear();
        let oci = oci_spec(
            &spec,
            &ImageConfig {
                config: crate::image::ProcessConfig {
                    cmd: Some(vec!["/app".into()]),
                    ..Default::default()
                },
                ..Default::default()
            },
            &root(),
            Path::new("/n"),
        )
        .unwrap();
        assert_eq!(oci["process"]["env"][0], format!("PATH={DEFAULT_PATH}"));
        assert_eq!(oci["process"]["cwd"], "/");
    }

    #[test]
    fn the_limits_are_memory_max_a_cpu_quota_and_a_pids_limit() {
        let oci = oci_spec(&spec(), &image(), &root(), Path::new("/n")).unwrap();
        let linux = &oci["linux"];
        assert_eq!(linux["cgroupsPath"], "/grund/web-v1-0");
        assert_eq!(linux["resources"]["memory"]["limit"], 256 * 1024 * 1024);
        assert_eq!(linux["resources"]["memory"]["swap"], 256 * 1024 * 1024);
        assert_eq!(
            linux["resources"]["cpu"],
            json!({"quota": 50_000, "period": 100_000})
        );
        assert_eq!(linux["resources"]["pids"]["limit"], 4096);
        assert_eq!(
            linux["resources"]["devices"],
            json!([{"allow": false, "access": "rwm"}])
        );
    }

    #[test]
    fn cpu_millis_become_a_quota_over_a_100_ms_period() {
        assert_eq!(cpu_quota(0), None);
        assert_eq!(cpu_quota(1000), Some(100_000));
        assert_eq!(cpu_quota(250), Some(25_000));
        assert_eq!(cpu_quota(2500), Some(250_000));
        assert_eq!(cpu_quota(1), Some(1000));
        assert_eq!(cpu_quota(u32::MAX), Some(429_496_729_500));
    }

    #[test]
    fn the_container_has_its_own_namespaces_and_the_runtimes_network_namespace() {
        let oci = oci_spec(
            &spec(),
            &image(),
            &root(),
            Path::new("/run/grund/netns/web-v1-0"),
        )
        .unwrap();
        let namespaces = oci["linux"]["namespaces"].as_array().unwrap();
        let types: Vec<_> = namespaces
            .iter()
            .map(|n| n["type"].as_str().unwrap())
            .collect();
        assert_eq!(types, ["pid", "ipc", "uts", "mount", "cgroup", "network"]);
        assert_eq!(namespaces[5]["path"], "/run/grund/netns/web-v1-0");
        assert!(namespaces[..5].iter().all(|n| n.get("path").is_none()));
        assert!(!namespaces.iter().any(|n| n["type"] == "user"));
    }

    #[test]
    fn the_spec_mounts_nothing_from_the_host_and_masks_dockers_paths() {
        let oci = oci_spec(&spec(), &image(), &root(), Path::new("/n")).unwrap();
        for mount in oci["mounts"].as_array().unwrap() {
            assert!(
                [
                    "proc", "tmpfs", "devpts", "shm", "mqueue", "sysfs", "cgroup"
                ]
                .contains(&mount["source"].as_str().unwrap()),
                "{mount}"
            );
            assert_ne!(mount["type"], "bind");
        }
        let sys = oci["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/sys/fs/cgroup")
            .unwrap();
        assert!(sys["options"].as_array().unwrap().contains(&json!("ro")));
        assert_eq!(oci["linux"]["maskedPaths"], json!(MASKED_PATHS));
        assert_eq!(oci["linux"]["readonlyPaths"], json!(READONLY_PATHS));
        assert!(oci["linux"].get("devices").is_none());
        assert!(oci.get("hooks").is_none());
    }

    #[test]
    fn users_resolve_from_the_images_passwd_and_group() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nnginx:x:101:101:nginx:/var/cache/nginx:/sbin/nologin\napp:x:1000:1000::/home/app:/bin/sh\n";
        let group = "root:x:0:\nnginx:x:101:\napp:x:1000:\naudio:x:29:app,nginx\nvideo:x:44:app\n";
        let nginx = resolve_user("nginx", Some(passwd), Some(group)).unwrap();
        assert_eq!(
            (nginx.uid, nginx.gid, nginx.additional_gids.clone()),
            (101, 101, vec![29])
        );
        assert_eq!(nginx.home.as_deref(), Some("/var/cache/nginx"));
        let app = resolve_user("1000", Some(passwd), Some(group)).unwrap();
        assert_eq!(
            (app.uid, app.gid, app.additional_gids),
            (1000, 1000, vec![29, 44])
        );
        let mixed = resolve_user("app:audio", Some(passwd), Some(group)).unwrap();
        assert_eq!(
            (mixed.uid, mixed.gid, mixed.additional_gids),
            (1000, 29, vec![])
        );
        let unknown_uid = resolve_user("4242", Some(passwd), Some(group)).unwrap();
        assert_eq!((unknown_uid.uid, unknown_uid.gid), (4242, 0));
        let numeric = resolve_user("65534:65534", None, None).unwrap();
        assert_eq!((numeric.uid, numeric.gid), (65534, 65534));
        assert!(resolve_user("ghost", Some(passwd), Some(group)).is_err());
        assert!(resolve_user("nginx:nogroup", Some(passwd), Some(group)).is_err());
        let error = resolve_user("nginx", None, None).unwrap_err();
        assert!(error.to_string().contains("has no /etc/passwd"), "{error}");
    }

    #[test]
    fn only_names_and_a_bare_uid_need_the_images_passwd() {
        assert!(!needs_passwd(""));
        assert!(!needs_passwd("101:101"));
        assert!(needs_passwd("101"));
        assert!(needs_passwd("nginx"));
        assert!(needs_passwd("101:nginx"));
    }
}
