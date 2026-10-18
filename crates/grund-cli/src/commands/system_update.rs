use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Stdio,
    time::Duration,
};

use clap::{Args, Subcommand};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::process::Command;

use super::system::{
    self, ROOT, atomic_write, binary_identity, compose, failed, io, lock, platform, read_managed,
    release::{self, Channel, Release},
    run, secure_directory, setting,
};
use crate::{
    context::{Ctx, Global},
    error::{CliError, CliResult, Code},
    output::Output,
    progress::Progress,
};

/// Update only the client executable, or explicitly update the managed server.
#[derive(Debug, Args)]
pub struct UpdateArgs {
    #[command(flatten)]
    pub global: Global,
    #[arg(long, global = true, help = "Exact public release tag")]
    pub version: Option<String>,
    #[arg(
        long,
        global = true,
        value_enum,
        conflicts_with = "version",
        help = "Release channel; defaults to the installed release's channel"
    )]
    pub channel: Option<Channel>,
    #[arg(
        long,
        global = true,
        help = "Confirm executable replacement or server downtime"
    )]
    pub yes: bool,
    #[arg(long, global = true, help = "Show technical failure details")]
    pub verbose: bool,
    #[arg(
        long,
        global = true,
        help = "Resolve and show the update without downloading or mutating local state"
    )]
    pub dry_run: bool,
    #[command(subcommand)]
    pub target: Option<UpdateTarget>,
}

/// Server updates always take and validate a complete backup before migration.
#[derive(Debug, Subcommand)]
pub enum UpdateTarget {
    #[command(
        about = "Back up, check and update the installer-managed server; requires root and downtime",
        long_about = "Back up, check and update the installer-managed server; requires root and downtime. Only compose.yaml plus an optional root-owned compose.override.yaml are supported; alternate override names and ambient COMPOSE_FILE, COMPOSE_ENV_FILES, COMPOSE_PROFILES and COMPOSE_PROJECT_NAME are refused. Store any profiles in /opt/grund/.env so preflight, migration and systemd use the same selection. The effective current and candidate stacks must retain the canonical local PostgreSQL database, key/password files, named volumes, service commands and default network; only separate read-only TLS bind mounts are supported as extra primary-service mounts. Unsupported primary topology is refused before downtime. The backup covers PostgreSQL, the instance data volume, and managed configuration including compose.override.yaml when present. Other services' data and external TLS files are not backed up; protect those separately before updating."
    )]
    Server,
}

fn refuse_downgrade(installed: &str, selected: &str) -> CliResult<()> {
    if let Ok(old) = release::Version::parse(installed)
        && release::Version::parse(selected)? < old
    {
        return Err(CliError::new(Code::Conflict, "refusing to replace an installed release with an older release")
            .hint("server rollback requires restoring the database, data volume and configuration together"));
    }
    Ok(())
}

fn doctor_summary(bytes: &[u8]) -> CliResult<serde_json::Value> {
    let report: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| failed("server doctor did not return a valid report"))?;
    let status = report["status"]
        .as_str()
        .ok_or_else(|| failed("server doctor report has no status"))?;
    let checks = report["checks"]
        .as_array()
        .ok_or_else(|| failed("server doctor report has no checks"))?;
    if !matches!(status, "ok" | "warn") {
        let names = checks
            .iter()
            .filter(|check| check["status"] == "fail")
            .filter_map(|check| check["name"].as_str())
            .filter(|name| {
                name.len() <= 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(failed(format!(
            "server doctor did not pass; failed checks: {names}"
        )));
    }
    if !checks.iter().any(|check| {
        check["name"] == "migrations" && matches!(check["status"].as_str(), Some("ok" | "warn"))
    }) {
        return Err(failed("server doctor did not validate migration history"));
    }
    Ok(
        json!({"status":status,"checks":checks.iter().map(|check| json!({"name":check["name"],"status":check["status"]})).collect::<Vec<_>>()}),
    )
}

async fn checked_doctor(command: &mut Command, operation: &str) -> CliResult<serde_json::Value> {
    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    let result = tokio::time::timeout(Duration::from_secs(300), command.output())
        .await
        .map_err(|_| failed(format!("{operation} exceeded its five-minute deadline")))?
        .map_err(|_| failed(format!("could not execute {operation}")))?;
    let summary = doctor_summary(&result.stdout)?;
    if !result.status.success() {
        return Err(failed(format!("{operation} exited unsuccessfully")));
    }
    Ok(summary)
}

fn executable_destination(path: &Path) -> CliResult<fs::Metadata> {
    if !path.is_absolute()
        || path.file_name().is_none_or(|name| name != "grund")
        || path.starts_with("/usr/local/lib/grund/agent")
    {
        return Err(CliError::new(
            Code::Conflict,
            "cannot safely identify the client executable; refusing to replace an agent runtime or renamed executable",
        ));
    }
    let meta = fs::symlink_metadata(path).map_err(io)?;
    let parent = path
        .parent()
        .ok_or_else(|| failed("client executable has no parent directory"))?;
    let parent_meta = fs::symlink_metadata(parent).map_err(io)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || !parent_meta.is_dir()
        || parent_meta.mode() & 0o022 != 0
    {
        return Err(CliError::new(
            Code::PermissionDenied,
            "client executable and its directory must be real, non-shared-writable paths without hardlinks",
        ));
    }
    Ok(meta)
}

async fn binary_update(ctx: &Ctx, args: UpdateArgs) -> CliResult<Output> {
    let progress = Progress::new(ctx, args.yes, args.verbose);
    let (destination, original) = progress.step(
        "Checking this client",
        "Use the installed grund executable in a private, writable directory; use sudo when it is root-owned.",
        async {
            let destination = std::env::current_exe().map_err(io)?;
            let original = executable_destination(&destination)?;
            Ok((destination, original))
        },
    ).await?;
    let release = progress
        .step(
            "Finding the release",
            "Check the internet connection and access to git.kjuulh.io, then retry.",
            Release::resolve(args.version.as_deref(), args.channel, crate::VERSION),
        )
        .await?;
    refuse_downgrade(crate::VERSION, &release.tag)?;
    if args.dry_run {
        return Ok(Output::fields(
            json!({"dryRun":true,"operation":"update","target":"binary","installedVersion":crate::VERSION,"version":release.tag,"path":destination}),
        ));
    }
    if release.tag == crate::VERSION {
        return Ok(Output::with_text(
            json!({"operation":"update","target":"binary","version":release.tag,"changed":false,"path":destination}),
            progress.summary(
                "grund client is up to date",
                &[
                    ("Version", &release.tag),
                    ("Executable", &destination.to_string_lossy()),
                ],
            ),
        ));
    }
    ctx.confirm(
        args.yes,
        "Update this grund command, leaving the server and agent unchanged",
    )?;
    let parent = destination
        .parent()
        .ok_or_else(|| failed("client executable has no parent directory"))?;
    let operation_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(parent.join(".grund-update.lock"))
        .map_err(io)?;
    let lock_meta = operation_lock.metadata().map_err(io)?;
    if lock_meta.uid() != original.uid() || !lock_meta.is_file() || lock_meta.mode() & 0o077 != 0 {
        return Err(CliError::new(
            Code::PermissionDenied,
            "client update lock has an unsafe owner or permissions",
        ));
    }
    operation_lock
        .try_lock()
        .map_err(|_| CliError::new(Code::Conflict, "another client update is running"))?;
    let staging = tempfile::Builder::new()
        .prefix(".grund-update-")
        .tempdir_in(parent)
        .map_err(io)?;
    let candidate = staging.path().join("grund");
    progress
        .step(
            "Downloading the verified client",
            "Check internet access and free space in the executable directory, then retry.",
            async {
                release
                    .download(&release::binary_name()?, &candidate)
                    .await?;
                binary_identity(&candidate, &release.tag).await
            },
        )
        .await?;
    progress
        .step(
            "Replacing this client",
            "Check ownership and free space in the executable directory, then retry the update.",
            async {
                File::open(&candidate)
                    .and_then(|file| file.sync_all())
                    .map_err(io)?;
                let current = executable_destination(&destination)?;
                if (current.dev(), current.ino()) != (original.dev(), original.ino()) {
                    return Err(CliError::new(
                        Code::Conflict,
                        "client executable changed during update; staged release was not installed",
                    ));
                }
                fs::rename(&candidate, &destination).map_err(io)?;
                File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(io)?;
                Ok(())
            },
        )
        .await?;
    Ok(Output::with_text(
        json!({"operation":"update","target":"binary","version":release.tag,"changed":true,"path":destination,"serverChanged":false,"agentChanged":false}),
        progress.summary(
            "grund client updated",
            &[
                ("Version", &release.tag),
                ("Executable", &destination.to_string_lossy()),
                ("Server and agent", "Unchanged"),
            ],
        ),
    ))
}

fn validate_compose_context(root: &Path, ambient: impl Fn(&str) -> bool) -> CliResult<()> {
    for name in [
        "compose.override.yml",
        "docker-compose.override.yml",
        "docker-compose.override.yaml",
    ] {
        if system::present(&root.join(name))? {
            return Err(CliError::new(Code::Conflict, format!("unsupported Compose override file: {}", root.join(name).display()))
                .hint("Consolidate the override into the root-owned /opt/grund/compose.override.yaml before using grund update server, or maintain this deployment explicitly outside the managed updater."));
        }
    }
    for key in [
        "COMPOSE_FILE",
        "COMPOSE_ENV_FILES",
        "COMPOSE_PROFILES",
        "COMPOSE_PROJECT_NAME",
    ] {
        if ambient(key) {
            return Err(CliError::new(Code::Conflict, format!("{key} in the caller environment is unsupported for managed server updates"))
                .hint("Unset this variable. Keep configuration in /opt/grund/compose.yaml, compose.override.yaml and .env; put COMPOSE_PROFILES only in the managed .env."));
        }
    }
    if system::present(&root.join(".env"))? {
        let settings = read_managed(&root.join(".env"))?;
        for line in settings.lines() {
            let key = line.split(['=', ':', '#']).next().unwrap_or("").trim();
            let mut words = key.split_whitespace();
            let first = words.next().unwrap_or("");
            let key = if first == "export" {
                words.next().unwrap_or("")
            } else {
                first
            };
            if matches!(
                key,
                "COMPOSE_FILE" | "COMPOSE_ENV_FILES" | "COMPOSE_PROJECT_NAME"
            ) {
                return Err(CliError::new(Code::Conflict, format!("{key} in the managed .env is unsupported for server updates"))
                    .hint("Consolidate configuration into compose.yaml plus optional compose.override.yaml, keeping the installer-managed project name; otherwise maintain the deployment explicitly outside this updater."));
            }
        }
    }
    Ok(())
}

fn candidate_compose(root: &Path, staged: &Path, image: &str) -> CliResult<Command> {
    let mut command = compose(root);
    command
        .arg("-f")
        .arg(staged.join("compose.yaml"))
        .env("GRUND_IMAGE", image)
        .env("GRUND_PULL_POLICY", "missing");
    let override_file = root.join("compose.override.yaml");
    if system::present(&override_file)? {
        read_managed(&override_file)?;
        command.arg("-f").arg(override_file);
    }
    Ok(command)
}

fn unsupported_topology() -> CliError {
    CliError::new(Code::Conflict, "effective Compose topology is not covered by the managed server backup")
        .hint("Keep the managed local PostgreSQL database, password and instance-key files, named volumes, and default service commands/network. Only separate read-only TLS bind mounts are supported. External or redirected primary datasets require an independently managed backup and update.")
}

fn empty_compose_field(value: &serde_json::Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn overlapping_paths(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

fn managed_mount(mount: &serde_json::Value, source: &str, target: &str, read_only: bool) -> bool {
    mount["type"] == "volume"
        && mount["source"] == source
        && mount["target"] == target
        && mount["read_only"].as_bool().unwrap_or(false) == read_only
        && empty_compose_field(&mount["volume"])
}

fn compose_command_is(value: &serde_json::Value, expected: &[&str]) -> bool {
    value.as_array().is_some_and(|arguments| {
        arguments.len() == expected.len()
            && arguments
                .iter()
                .zip(expected)
                .all(|(argument, expected)| argument.as_str() == Some(*expected))
    })
}

fn validate_managed_topology(config: &serde_json::Value) -> CliResult<()> {
    let refuse = || Err(unsupported_topology());
    if config["name"] != "grund" {
        return refuse();
    }
    for (source, name) in [
        ("grund-data", "grund_grund-data"),
        ("grund-postgres", "grund_grund-postgres"),
    ] {
        let volume = &config["volumes"][source];
        if volume["name"] != name
            || volume["external"].as_bool().unwrap_or(false)
            || !matches!(volume["driver"].as_str(), None | Some("local"))
            || !empty_compose_field(&volume["driver_opts"])
        {
            return refuse();
        }
    }
    let network = &config["networks"]["default"];
    if network["name"] != "grund_default"
        || network["external"].as_bool().unwrap_or(false)
        || !matches!(network["driver"].as_str(), None | Some("bridge"))
        || !empty_compose_field(&network["driver_opts"])
        || !empty_compose_field(&network["ipam"])
    {
        return refuse();
    }
    for name in ["grund", "postgres", "init"] {
        let service = &config["services"][name];
        let networks = service["networks"]
            .as_object()
            .ok_or_else(unsupported_topology)?;
        if networks.len() != 1
            || !networks
                .get("default")
                .is_some_and(serde_json::Value::is_null)
        {
            return refuse();
        }
        for field in [
            "network_mode",
            "extra_hosts",
            "links",
            "external_links",
            "dns",
            "dns_search",
            "dns_opt",
            "domainname",
            "volumes_from",
            "tmpfs",
            "configs",
            "secrets",
            "devices",
            "profiles",
        ] {
            if !empty_compose_field(&service[field]) {
                return refuse();
            }
        }
    }
    for (name, service) in config["services"]
        .as_object()
        .ok_or_else(unsupported_topology)?
    {
        if name == "postgres" {
            continue;
        }
        if ["hostname", "container_name"].iter().any(|field| {
            service[*field]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case("postgres"))
        }) || service["networks"]["default"]["aliases"]
            .as_array()
            .is_some_and(|aliases| {
                aliases.iter().any(|alias| {
                    alias
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case("postgres"))
                })
            })
        {
            return refuse();
        }
    }
    let server = &config["services"]["grund"];
    let postgres = &config["services"]["postgres"];
    let init = &config["services"]["init"];
    if !compose_command_is(&server["command"], &["serve"])
        || !(server["entrypoint"].is_null()
            || compose_command_is(&server["entrypoint"], &["/grund"]))
        || !(postgres["command"].is_null()
            || compose_command_is(&postgres["command"], &["postgres"]))
        || !postgres["entrypoint"].is_null()
        || postgres["image"] != "postgres:18-alpine"
        || !compose_command_is(&init["command"], &["init", "--data-dir", "/var/lib/grund"])
        || !(init["entrypoint"].is_null() || compose_command_is(&init["entrypoint"], &["/grund"]))
    {
        return refuse();
    }
    let environment = server["environment"]
        .as_object()
        .ok_or_else(unsupported_topology)?;
    for (key, expected) in [
        ("DATABASE_URL", "postgres://grund@postgres:5432/grund"),
        (
            "GRUND_DATABASE_PASSWORD_FILE",
            "/var/lib/grund/postgres-password",
        ),
        ("GRUND_SECRET_KEY_FILE", "/var/lib/grund/secret.key"),
    ] {
        if environment.get(key).and_then(serde_json::Value::as_str) != Some(expected) {
            return refuse();
        }
    }
    if environment
        .get("GRUND_SECRET_KEY")
        .is_some_and(|value| !value.is_null())
        || environment.keys().any(|key| key.starts_with("PG"))
    {
        return refuse();
    }
    let pg_environment = postgres["environment"]
        .as_object()
        .ok_or_else(unsupported_topology)?;
    for (key, expected) in [
        ("POSTGRES_DB", "grund"),
        ("POSTGRES_USER", "grund"),
        ("POSTGRES_PASSWORD_FILE", "/run/grund/postgres-password"),
    ] {
        if pg_environment.get(key).and_then(serde_json::Value::as_str) != Some(expected) {
            return refuse();
        }
    }
    if pg_environment.keys().any(|key| {
        key.starts_with("PG")
            || (key.starts_with("POSTGRES_")
                && !matches!(
                    key.as_str(),
                    "POSTGRES_DB" | "POSTGRES_USER" | "POSTGRES_PASSWORD_FILE"
                ))
    }) {
        return refuse();
    }
    let pg_mounts = postgres["volumes"]
        .as_array()
        .ok_or_else(unsupported_topology)?;
    if pg_mounts.len() != 2
        || !pg_mounts
            .iter()
            .any(|mount| managed_mount(mount, "grund-postgres", "/var/lib/postgresql", false))
        || !pg_mounts
            .iter()
            .any(|mount| managed_mount(mount, "grund-data", "/run/grund", true))
    {
        return refuse();
    }
    let init_mounts = init["volumes"]
        .as_array()
        .ok_or_else(unsupported_topology)?;
    if init_mounts.len() != 1
        || !managed_mount(&init_mounts[0], "grund-data", "/var/lib/grund", false)
    {
        return refuse();
    }
    let mounts = server["volumes"]
        .as_array()
        .ok_or_else(unsupported_topology)?;
    if mounts
        .iter()
        .filter(|mount| managed_mount(mount, "grund-data", "/var/lib/grund", true))
        .count()
        != 1
    {
        return refuse();
    }
    for mount in mounts {
        if managed_mount(mount, "grund-data", "/var/lib/grund", true) {
            continue;
        }
        let target = mount["target"].as_str().ok_or_else(unsupported_topology)?;
        if !target.starts_with('/')
            || target
                .split('/')
                .skip(1)
                .any(|part| matches!(part, "" | "." | ".."))
        {
            return refuse();
        }
        let target = Path::new(target);
        if mount["type"] != "bind"
            || mount["read_only"] != true
            || [
                "/var/lib/grund",
                "/grund",
                "/etc/hosts",
                "/etc/resolv.conf",
                "/etc/nsswitch.conf",
                "/proc",
                "/sys",
                "/dev",
                "/bin",
                "/sbin",
                "/usr",
                "/lib",
                "/lib64",
            ]
            .iter()
            .any(|protected| overlapping_paths(target, Path::new(protected)))
            || !["GRUND_TLS_CERT_FILE", "GRUND_TLS_KEY_FILE"]
                .iter()
                .any(|key| {
                    environment
                        .get(*key)
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|file| {
                            Path::new(file).is_absolute() && Path::new(file).starts_with(target)
                        })
                })
        {
            return refuse();
        }
    }
    Ok(())
}

fn validate_managed_topologies(
    current: &serde_json::Value,
    candidate: &serde_json::Value,
) -> CliResult<()> {
    validate_managed_topology(current)?;
    validate_managed_topology(candidate)
}

async fn effective_compose(command: &mut Command) -> CliResult<serde_json::Value> {
    let bytes = run(
        command.args(["config", "--format", "json"]),
        "resolve effective managed Compose topology",
    )
    .await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| failed("Docker Compose did not return a valid effective configuration"))
}

fn readiness_address(mappings: &str) -> CliResult<SocketAddr> {
    let mut selected = None;
    for mapping in mappings
        .lines()
        .filter(|mapping| !mapping.trim().is_empty())
    {
        let mut address: SocketAddr = mapping
            .trim()
            .parse()
            .map_err(|_| failed("Docker reported an invalid server port mapping"))?;
        if address.port() == 0 {
            return Err(failed("Docker reported an unbound server port"));
        }
        if address.ip().is_unspecified() {
            address.set_ip(match address.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            });
        }
        if selected.is_none() || address.is_ipv4() {
            selected = Some(address);
        }
    }
    selected.ok_or_else(|| {
        failed("updated server has no published HTTP port for readiness verification")
    })
}

fn readiness_revision(body: &[u8], expected: &str) -> CliResult<String> {
    let report: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| failed("updated server readiness response is invalid"))?;
    let observed = report["revision"]
        .as_str()
        .ok_or_else(|| failed("updated server readiness response has no revision"))?;
    if observed != expected {
        return Err(failed(
            "running server revision does not match release.txt; update remains incomplete",
        ));
    }
    Ok(observed.to_owned())
}

async fn observe_revision(root: &Path, expected: &str) -> CliResult<String> {
    let mappings = run(
        compose(root).args(["port", "grund", "8080"]),
        "read updated server HTTP port mapping",
    )
    .await?;
    let mappings = std::str::from_utf8(&mappings)
        .map_err(|_| failed("Docker server port mapping is not UTF-8"))?;
    let address = readiness_address(mappings)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| failed("could not initialize local readiness client"))?;
    let mut response = client
        .get(format!("http://{address}/health/ready"))
        .send()
        .await
        .map_err(|_| failed("updated server readiness request failed or exceeded its deadline"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(failed("updated server readiness endpoint is not healthy"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| failed("updated server readiness transfer failed"))?
    {
        if body.len() + chunk.len() > 64 * 1024 {
            return Err(failed("updated server readiness response exceeds 64 KiB"));
        }
        body.extend_from_slice(&chunk);
    }
    readiness_revision(&body, expected)
}

fn switched_env(old: &str, image: &str) -> CliResult<String> {
    setting(old, "GRUND_IMAGE")?;
    let mut result = String::with_capacity(old.len() + image.len());
    for line in old.lines() {
        if line.starts_with("GRUND_IMAGE=") {
            result.push_str("GRUND_IMAGE=");
            result.push_str(image);
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }
    Ok(result)
}

async fn stream_to_file(
    command: &mut Command,
    destination: &Path,
    operation: &str,
) -> CliResult<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(io)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(file.try_clone().map_err(io)?))
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(1800), command.status())
        .await
        .map_err(|_| failed(format!("{operation} exceeded its 30-minute deadline")))?
        .map_err(|_| failed(format!("could not execute {operation}")))?;
    if !status.success() {
        return Err(failed(format!("{operation} failed; backup is incomplete")));
    }
    if file.metadata().map_err(io)?.len() == 0 {
        return Err(failed(format!("{operation} produced an empty backup")));
    }
    file.sync_all().map_err(io)
}

fn file_hash(path: &Path) -> CliResult<String> {
    let mut file = File::open(path).map_err(io)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(io)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

async fn backup(root: &Path, destination: &Path, version: &str, image: &str) -> CliResult<()> {
    stream_to_file(
        compose(root).args([
            "exec",
            "-T",
            "postgres",
            "pg_dump",
            "--host=/var/run/postgresql",
            "--port=5432",
            "--format=custom",
            "--username=grund",
            "--dbname=grund",
        ]),
        &destination.join("database.dump"),
        "consistent PostgreSQL backup",
    )
    .await?;
    stream_to_file(
        compose(root).args([
            "exec",
            "-T",
            "postgres",
            "tar",
            "-C",
            "/run/grund",
            "-cf",
            "-",
            ".",
        ]),
        &destination.join("grund-data.tar"),
        "instance data backup",
    )
    .await?;
    let mut validate = compose(root);
    validate
        .args(["exec", "-T", "postgres", "pg_restore", "--list"])
        .stdin(Stdio::from(
            File::open(destination.join("database.dump")).map_err(io)?,
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(300), validate.status())
        .await
        .map_err(|_| failed("backup validation exceeded its five-minute deadline"))?
        .map_err(io)?;
    if !status.success() {
        return Err(failed(
            "pg_restore rejected the backup; migration was not started",
        ));
    }
    let listing = run(
        Command::new("/usr/bin/tar")
            .args(["-tf"])
            .arg(destination.join("grund-data.tar")),
        "instance data archive validation",
    )
    .await?;
    let listing = String::from_utf8(listing)
        .map_err(|_| failed("instance data archive has invalid names"))?;
    for required in ["secret.key", "postgres-password"] {
        if !listing
            .lines()
            .any(|name| name.strip_prefix("./").unwrap_or(name) == required)
        {
            return Err(failed(format!(
                "instance data backup lacks {required}; migration was not started"
            )));
        }
    }
    let mut hashes = serde_json::Map::new();
    for name in [
        ".env",
        "compose.yaml",
        "compose.override.yaml",
        ".installer-domain",
        ".installer-version",
    ] {
        if system::present(&root.join(name))? {
            atomic_write(
                &destination.join(name),
                read_managed(&root.join(name))?.as_bytes(),
                0o600,
            )?;
            hashes.insert(name.to_owned(), json!(file_hash(&destination.join(name))?));
        }
    }
    for name in ["database.dump", "grund-data.tar"] {
        hashes.insert(name.to_owned(), json!(file_hash(&destination.join(name))?));
    }
    let manifest = json!({"format":1,"complete":true,"createdAt":chrono::Utc::now().to_rfc3339(),"installedVersion":version,"installedImage":image,"sha256":hashes,"scope":["PostgreSQL","instance data volume","managed configuration including optional compose.override.yaml"],"excluded":"Additional bind mounts, external volumes and other services' data"});
    atomic_write(
        &destination.join("complete.json"),
        &serde_json::to_vec_pretty(&manifest)
            .map_err(|_| failed("could not serialize backup completion record"))?,
        0o600,
    )?;
    File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(io)?;
    File::open(
        destination
            .parent()
            .ok_or_else(|| failed("backup has no parent"))?,
    )
    .and_then(|file| file.sync_all())
    .map_err(io)
}

fn recovery(backup: &Path) -> String {
    format!(
        "Keep the backup at {} and the update journal until recovery is verified. Stop the stack and verify every SHA-256 hash in complete.json before restoring. Restore database.dump with pg_restore into a fresh database; never merge it into a migrated database. Replace the instance volume from grund-data.tar, the saved .env/compose.yaml/compose.override.yaml (when present), and installer identity together with that database and the saved old image. Never start the old image against a migrated database. Additional bind mounts, external volumes and other services' data are not in this backup. Verify the restored stack before removing the backup or journal.",
        backup.display()
    )
}

fn refuse_incomplete_update(root: &Path) -> CliResult<()> {
    let journal = root.join(".server-update.json");
    if system::present(&journal)? {
        let contents = read_managed(&journal)?;
        let state: serde_json::Value = serde_json::from_str(&contents).map_err(|_| {
            failed("server update journal is invalid; inspect it before another update")
        })?;
        let backup = state["backupPath"]
            .as_str()
            .ok_or_else(|| failed("server update journal lacks its backup path"))?;
        return Err(CliError::new(Code::Conflict, format!("a previous server update needs deliberate recovery; backup retained at {backup}"))
            .hint(format!("{} Remove {} only after restoring the complete backup or verifying the new stack and recording its installed version.", recovery(Path::new(backup)), journal.display())));
    }
    Ok(())
}

async fn server_update(ctx: &Ctx, args: UpdateArgs) -> CliResult<Output> {
    let progress = Progress::new(ctx, args.yes, args.verbose);
    progress
        .step(
            "Checking server prerequisites",
            "Run sudo grund update server on the installer-managed Linux host with Docker running.",
            platform(true),
        )
        .await?;
    let root = Path::new(ROOT);
    validate_compose_context(root, |key| std::env::var_os(key).is_some())?;
    refuse_incomplete_update(root)?;
    let installed = system::installed_version(root, None)
        .await?
        .ok_or_else(|| CliError::new(Code::Conflict, "server is not installer-managed"))?;
    let release = progress
        .step(
            "Finding the server release",
            "Check the internet connection and access to git.kjuulh.io, then retry.",
            Release::resolve(args.version.as_deref(), args.channel, &installed),
        )
        .await?;
    refuse_downgrade(&installed, &release.tag)?;
    if args.dry_run {
        return Ok(Output::fields(
            json!({"dryRun":true,"operation":"update","target":"server","installedVersion":installed,"version":release.tag,"backupRequired":true,"downtime":true,"configPath":ROOT}),
        ));
    }
    if release.tag == installed {
        return Ok(Output::with_text(
            json!({"operation":"update","target":"server","version":release.tag,"changed":false}),
            progress.summary("grund server is up to date", &[("Version", &release.tag)]),
        ));
    }
    ctx.confirm(
        args.yes,
        "Pause grund, make a full backup and update this server",
    )?;
    secure_directory(root)?;
    let _lock = lock(&root.join(".operation.lock"))?;
    refuse_incomplete_update(root)?;
    validate_compose_context(root, |key| std::env::var_os(key).is_some())?;
    if system::installed_version(root, None).await?.as_deref() != Some(installed.as_str()) {
        return Err(CliError::new(
            Code::Conflict,
            "server release changed while resolving update",
        ));
    }
    let old_env = read_managed(&root.join(".env"))?;
    let old_image = setting(&old_env, "GRUND_IMAGE")?.to_owned();
    run(
        Command::new("/usr/bin/tar").arg("--version"),
        "archive prerequisite check",
    )
    .await?;
    let staged = tempfile::Builder::new()
        .prefix(".server-update-")
        .tempdir_in(root)
        .map_err(io)?;
    progress
        .step(
            "Downloading the verified server release",
            "Check internet access and free space under /opt/grund, then retry.",
            async {
                for name in ["compose.yaml", "image-digest.txt", "release.txt"] {
                    release.download(name, &staged.path().join(name)).await?;
                }
                let binary = staged.path().join("grund");
                release.download(&release::binary_name()?, &binary).await?;
                binary_identity(&binary, &release.tag).await?;
                Ok(())
            },
        )
        .await?;
    let revision = fs::read_to_string(staged.path().join("release.txt")).map_err(io)?;
    let revision = revision.trim();
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(failed("release.txt does not name a full public revision"));
    }
    let image = system::image_identity(&staged.path().join("image-digest.txt"))?;
    progress.step(
        "Preparing the server image",
        "Check Docker and access to the container registry, then retry; the running server has not been stopped.",
        async {
            run(
                Command::new("/usr/bin/docker").args(["pull", &image]),
                "pull immutable server image before downtime",
            ).await?;
            let current_topology = effective_compose(&mut compose(root)).await?;
            let candidate_topology =
                effective_compose(&mut candidate_compose(root, staged.path(), &image)?).await?;
            validate_managed_topologies(&current_topology, &candidate_topology)?;
            let candidate_version = run(
                candidate_compose(root, staged.path(), &image)?.args([
                    "run", "--rm", "--no-deps", "grund", "--version",
                ]),
                "new server image release identity check",
            ).await?;
            if candidate_version != format!("grund {}\n", release.tag).as_bytes() {
                return Err(failed(
                    "candidate compose configuration does not run the selected release; existing stack is unchanged",
                ));
            }
            Ok(())
        },
    ).await?;
    let preflight = progress
        .step(
            "Checking the server before downtime",
            "Run sudo grund doctor instance and resolve failing checks before retrying.",
            async {
                checked_doctor(
                    candidate_compose(root, staged.path(), &image)?.args([
                        "run",
                        "--rm",
                        "--no-deps",
                        "grund",
                        "doctor",
                        "--json",
                        "instance",
                    ]),
                    "new server doctor preflight",
                )
                .await
            },
        )
        .await?;
    let backups = root.join("backups");
    secure_directory(&backups)?;
    let backup_path = backups.join(format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%fZ"),
        uuid::Uuid::new_v4()
    ));
    secure_directory(&backup_path)?;
    let mut cutover_started = false;
    let operation: CliResult<(serde_json::Value, String)> = async {
        progress.step(
            "Pausing server writes",
            "Inspect the existing stack with sudo docker compose --project-directory /opt/grund logs grund.",
            async {
                run(compose(root).args(["stop", "grund"]), "stop server writes before backup").await?;
                Ok(())
            },
        ).await?;
        progress.step(
            "Saving and validating the complete backup",
            "Check free space under /opt/grund/backups; keep the backup directory and inspect the old stack before retrying.",
            backup(root, &backup_path, &installed, &old_image),
        ).await?;
        progress.step(
            "Recording the guarded server cutover",
            "Keep the update journal and complete backup; do not start an old image against a migrated database.",
            async {
        atomic_write(
            &root.join(".server-update.json"),
            &serde_json::to_vec(
                &json!({"version":release.tag,"image":image,"backupPath":backup_path}),
            )
            .map_err(|_| failed("could not serialize server update journal"))?,
            0o600,
        )?;
        cutover_started = true;
        atomic_write(
            &root.join(".env"),
            switched_env(&old_env, &image)?.as_bytes(),
            0o600,
        )?;
        atomic_write(
            &root.join("compose.yaml"),
            &fs::read(staged.path().join("compose.yaml")).map_err(io)?,
            0o600,
        )?;
        atomic_write(
            &root.join(".installer-version"),
            format!("{}\n", release.tag).as_bytes(),
            0o600,
        )?;
                Ok(())
            },
        ).await?;
        progress.step(
            "Migrating the server",
            "Keep the complete backup and update journal; follow the recovery instructions before restarting or restoring.",
            async {
                run(
                    compose(root).args(["run", "--rm", "--no-deps", "grund", "migrate"]),
                    "forward server migration",
                ).await?;
                Ok(())
            },
        ).await?;
        progress.step(
            "Starting the updated server",
            "Inspect the updated stack logs; retain the complete backup and update journal until recovery is verified.",
            async {
                run(
                    compose(root).args(["up", "--no-build", "-d", "--wait", "--wait-timeout", "180"]),
                    "start updated server and wait for health",
                ).await?;
                Ok(())
            },
        ).await?;
        let (report, observed_revision) = progress.step(
            "Checking the running server",
            "Inspect the updated stack logs; do not remove the update journal until health and the running release are verified.",
            async {
                let report = checked_doctor(
                    compose(root).args([
                        "exec", "-T", "grund", "/grund", "doctor", "--json", "instance",
                    ]),
                    "updated server doctor",
                ).await?;
                let observed_revision = observe_revision(root, revision).await?;
                Ok((report, observed_revision))
            },
        ).await?;
        fs::remove_file(root.join(".server-update.json")).map_err(io)?;
        File::open(root)
            .and_then(|file| file.sync_all())
            .map_err(io)?;
        Ok((report, observed_revision))
    }
    .await;
    let (postflight, observed_revision) = match operation {
        Ok(report) => report,
        Err(error) if cutover_started => return Err(failed(format!("server update failed after guarded cutover; migration may have started: {}; completed backup retained at {}", error.message, backup_path.display())).hint(recovery(&backup_path))),
        Err(error) => {
            let restarted = run(compose(root).args(["up", "--no-build", "-d", "--wait", "--wait-timeout", "180"]), "restart unchanged old server").await.is_ok();
            return Err(failed(format!("server update refused before migration: {}; old server restart {}; backup directory retained at {}", error.message, if restarted {"succeeded"}else{"failed"}, backup_path.display())).hint(format!("No migration was attempted. Old server restart {}. Inspect old stack logs; backup directory retained at {}. complete.json exists only for a validated, synced backup.", if restarted {"succeeded"}else{"failed"}, backup_path.display())));
        }
    };
    Ok(Output::with_text(
        json!({"operation":"update","target":"server","changed":true,"version":release.tag,"revision":observed_revision,"image":image,"backupPath":backup_path,"backupComplete":true,"migration":"succeeded","health":"succeeded","preflight":preflight,"postflight":postflight}),
        progress.summary(
            "grund server updated",
            &[
                ("Version", &release.tag),
                ("Health", "Ready; running revision verified"),
                ("Backup", &backup_path.to_string_lossy()),
                ("Client and agent", "Unchanged"),
            ],
        ),
    ))
}

/// Resolve a trusted public release and update the selected local component.
pub async fn update(ctx: &Ctx, args: UpdateArgs) -> CliResult<Output> {
    let progress = Progress::new(ctx, args.yes, args.verbose);
    let server = args.target.is_some();
    let result = if server {
        server_update(ctx, args).await
    } else {
        binary_update(ctx, args).await
    };
    result.map_err(|error| {
        if matches!(error.code, Code::ConfirmationRequired | Code::Usage) {
            error
        } else {
            progress.failure(
                error,
                if server { "Server update" } else { "Client update" },
                if server {
                    "Run sudo grund doctor instance; keep any update journal and complete backup before retrying."
                } else {
                    "Check executable ownership and internet access, then retry with --verbose for details."
                },
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unattended_update_flags_work_on_either_side_of_the_server_target() {
        use clap::Parser;

        for args in [
            vec![
                "grund",
                "update",
                "--yes",
                "--verbose",
                "--dry-run",
                "--json",
            ],
            vec![
                "grund",
                "update",
                "--yes",
                "--verbose",
                "--dry-run",
                "--json",
                "server",
            ],
            vec![
                "grund",
                "update",
                "server",
                "--yes",
                "--verbose",
                "--dry-run",
                "--json",
            ],
        ] {
            let parsed = crate::Standalone::try_parse_from(args).unwrap();
            let crate::Command::Update(args) = parsed.command else {
                panic!("expected an update");
            };
            assert!(args.yes && args.verbose && args.dry_run && args.global.json);
            let ctx = Ctx::new(args.global.clone());
            assert_eq!(ctx.format, crate::output::Format::Json);
            assert!(!ctx.interactive);
            assert!(ctx.confirm(args.yes, "must not prompt").is_ok());
            assert_eq!(
                ctx.confirm(false, "must refuse").unwrap_err().code,
                Code::ConfirmationRequired
            );
        }
    }

    fn managed_topology() -> serde_json::Value {
        json!({
            "name":"grund",
            "networks":{"default":{"name":"grund_default"}},
            "volumes":{
                "grund-data":{"name":"grund_grund-data"},
                "grund-postgres":{"name":"grund_grund-postgres"}
            },
            "services":{
                "grund":{
                    "command":["serve"],
                    "networks":{"default":null},
                    "environment":{
                        "DATABASE_URL":"postgres://grund@postgres:5432/grund",
                        "GRUND_DATABASE_PASSWORD_FILE":"/var/lib/grund/postgres-password",
                        "GRUND_SECRET_KEY_FILE":"/var/lib/grund/secret.key"
                    },
                    "volumes":[{"type":"volume","source":"grund-data","target":"/var/lib/grund","read_only":true}]
                },
                "postgres":{
                    "image":"postgres:18-alpine",
                    "networks":{"default":null},
                    "environment":{
                        "POSTGRES_DB":"grund",
                        "POSTGRES_USER":"grund",
                        "POSTGRES_PASSWORD_FILE":"/run/grund/postgres-password"
                    },
                    "volumes":[
                        {"type":"volume","source":"grund-postgres","target":"/var/lib/postgresql"},
                        {"type":"volume","source":"grund-data","target":"/run/grund","read_only":true}
                    ]
                },
                "init":{
                    "command":["init","--data-dir","/var/lib/grund"],
                    "networks":{"default":null},
                    "volumes":[{"type":"volume","source":"grund-data","target":"/var/lib/grund"}]
                }
            }
        })
    }

    #[test]
    fn managed_datasets_remain_covered_when_only_tls_mounts_change() {
        let current = managed_topology();
        let mut candidate = current.clone();
        candidate["services"]["grund"]["environment"]["GRUND_TLS_CERT_FILE"] =
            json!("/etc/grund/tls/cert.pem");
        candidate["services"]["grund"]["environment"]["GRUND_TLS_KEY_FILE"] =
            json!("/etc/grund/tls/key.pem");
        candidate["services"]["grund"]["volumes"].as_array_mut().unwrap().push(
            json!({"type":"bind","source":"/srv/tls","target":"/etc/grund/tls","read_only":true})
        );
        assert!(validate_managed_topologies(&current, &current).is_ok());
        assert!(validate_managed_topologies(&current, &candidate).is_ok());
        assert!(validate_managed_topologies(&candidate, &current).is_ok());
        candidate["volumes"]["grund-data"]["name"] = json!("another-instance");
        assert!(validate_managed_topologies(&current, &candidate).is_err());
    }

    #[test]
    fn unbacked_database_or_instance_keys_refuse_either_side_of_cutover() {
        let supported = managed_topology();
        for (key, value) in [
            (
                "DATABASE_URL",
                "postgres://grund:private-password@external:5432/grund",
            ),
            ("DATABASE_URL", "postgres://grund@postgres:5432/other"),
            (
                "DATABASE_URL",
                "postgres://grund@postgres:5432/grund?host=external",
            ),
            ("GRUND_DATABASE_PASSWORD_FILE", "/external/password"),
            ("GRUND_SECRET_KEY_FILE", "/external/key"),
            ("GRUND_SECRET_KEY", "private-inline-key"),
        ] {
            let mut redirected = supported.clone();
            redirected["services"]["grund"]["environment"][key] = json!(value);
            let error = validate_managed_topologies(&supported, &redirected).unwrap_err();
            assert!(!error.message.contains(value));
            assert!(validate_managed_topologies(&redirected, &supported).is_err());
        }
    }

    #[test]
    fn replaced_or_overlaid_primary_mounts_are_not_claimed_as_backed_up() {
        let supported = managed_topology();
        for (service, index, field, value) in [
            ("grund", 0, "source", json!("other-data")),
            ("grund", 0, "volume", json!({"subpath":"another-instance"})),
            ("postgres", 1, "source", json!("other-data")),
            ("postgres", 0, "source", json!("other-database")),
            ("init", 0, "source", json!("other-data")),
        ] {
            let mut overlaid = supported.clone();
            overlaid["services"][service]["volumes"][index][field] = value;
            assert!(validate_managed_topologies(&supported, &overlaid).is_err());
        }
        for target in [
            "/var/lib/grund/secret.key",
            "/var/lib/grund/postgres-password",
            "/var/lib",
            "/etc/hosts",
        ] {
            let mut overlaid = supported.clone();
            overlaid["services"]["grund"]["environment"]["GRUND_TLS_KEY_FILE"] = json!(target);
            overlaid["services"]["grund"]["volumes"]
                .as_array_mut()
                .unwrap()
                .push(json!({"type":"bind","source":"/external","target":target,"read_only":true}));
            assert!(validate_managed_topologies(&supported, &overlaid).is_err());
        }
        for field in ["tmpfs", "secrets", "configs", "volumes_from"] {
            let mut overlaid = supported.clone();
            overlaid["services"]["grund"][field] = json!(["/var/lib/grund"]);
            assert!(validate_managed_topologies(&supported, &overlaid).is_err());
        }
    }

    #[test]
    fn server_arguments_and_entrypoints_cannot_select_an_unbacked_dataset() {
        let supported = managed_topology();
        for flag in [
            "--database-url",
            "--database-password-file",
            "--secret-key-file",
            "--secret-key",
        ] {
            let mut overridden = supported.clone();
            overridden["services"]["grund"]["command"] = json!(["serve", flag, "unbacked"]);
            assert!(validate_managed_topologies(&supported, &overridden).is_err());
            overridden["services"]["grund"]["command"] = json!(["serve"]);
            overridden["services"]["grund"]["entrypoint"] =
                json!(["/grund", "serve", flag, "unbacked"]);
            assert!(validate_managed_topologies(&overridden, &supported).is_err());
        }
        let mut overridden = supported.clone();
        overridden["services"]["postgres"]["command"] = json!(["postgres", "-p", "5433"]);
        assert!(validate_managed_topologies(&supported, &overridden).is_err());
    }

    #[test]
    fn libpq_redirects_cannot_turn_a_local_backup_into_an_external_dump() {
        let supported = managed_topology();
        for key in [
            "PGHOST",
            "PGHOSTADDR",
            "PGPORT",
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGDATABASE",
            "PGUSER",
            "PGOPTIONS",
            "PGDATA",
        ] {
            let mut redirected = supported.clone();
            redirected["services"]["postgres"]["environment"][key] = json!("redirected");
            assert!(validate_managed_topologies(&supported, &redirected).is_err());
            assert!(validate_managed_topologies(&redirected, &supported).is_err());
        }
        for key in ["POSTGRES_PASSWORD", "POSTGRES_INITDB_ARGS"] {
            let mut redirected = supported.clone();
            redirected["services"]["postgres"]["environment"][key] = json!("unmanaged");
            assert!(validate_managed_topologies(&supported, &redirected).is_err());
        }
    }

    #[test]
    fn dns_and_external_volume_redirects_cannot_change_the_managed_database() {
        let supported = managed_topology();
        let mut redirected = supported.clone();
        redirected["services"]["grund"]["extra_hosts"] = json!({"postgres":"192.0.2.1"});
        assert!(validate_managed_topologies(&supported, &redirected).is_err());
        let mut redirected = supported.clone();
        redirected["services"]["other"] = json!({"networks":{"default":{"aliases":["postgres"]}}});
        assert!(validate_managed_topologies(&supported, &redirected).is_err());
        for field in ["external", "driver_opts"] {
            let mut redirected = supported.clone();
            redirected["volumes"]["grund-data"][field] = if field == "external" {
                json!(true)
            } else {
                json!({"device":"/external"})
            };
            assert!(validate_managed_topologies(&supported, &redirected).is_err());
        }
    }

    #[test]
    fn image_switch_preserves_other_configuration_and_refuses_ambiguity() {
        let original =
            "GRUND_DOMAIN=grund.example.com\nGRUND_IMAGE=old\nGRUND_SECRET_KEY_FILE=/secret\n";
        assert_eq!(
            switched_env(original, "new").unwrap(),
            "GRUND_DOMAIN=grund.example.com\nGRUND_IMAGE=new\nGRUND_SECRET_KEY_FILE=/secret\n"
        );
        assert!(switched_env("GRUND_IMAGE=old\nGRUND_IMAGE=other\n", "new").is_err());
    }

    #[test]
    fn explicit_selection_still_cannot_downgrade() {
        assert!(refuse_downgrade("v1.0.0", "v1.0.0-alpha.10").is_err());
        assert!(refuse_downgrade("v0.0.0-alpha.10", "v0.0.0-alpha.9").is_err());
        assert!(refuse_downgrade("v0.0.0-alpha.9", "v0.0.0-alpha.10").is_ok());
    }

    #[test]
    fn agent_runtime_and_ambiguous_paths_are_never_client_update_targets() {
        assert!(executable_destination(Path::new("/usr/local/lib/grund/agent/grund")).is_err());
        assert!(executable_destination(Path::new("grund")).is_err());
        assert!(executable_destination(Path::new("/usr/bin/custom-name")).is_err());
    }

    #[test]
    fn maintenance_reports_never_forward_doctor_details_or_secrets() {
        let report = br#"{"status":"warn","checks":[{"name":"migrations","status":"warn","detail":"private database details","fix":"sensitive settings"}]}"#;
        let summary = doctor_summary(report).unwrap().to_string();
        assert!(!summary.contains("private"));
        assert!(!summary.contains("sensitive"));
        assert!(doctor_summary(br#"{"status":"ok","checks":[]}"#).is_err());
    }

    #[tokio::test]
    async fn a_failed_backup_stream_never_has_a_completion_record() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("database.dump");
        let result = stream_to_file(
            Command::new("/bin/sh").args(["-c", "printf partial; exit 1"]),
            &destination,
            "backup",
        )
        .await;
        assert!(result.is_err());
        assert!(destination.exists());
        assert!(!directory.path().join("complete.json").exists());
    }

    #[tokio::test]
    async fn a_backup_never_overwrites_an_existing_backup_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("database.dump");
        fs::write(&destination, b"previous valid backup").unwrap();
        assert!(
            stream_to_file(
                Command::new("/bin/sh").args(["-c", "printf replacement"]),
                &destination,
                "backup"
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read(destination).unwrap(), b"previous valid backup");
    }

    #[test]
    fn wildcard_published_ports_are_checked_over_loopback() {
        assert_eq!(
            readiness_address("0.0.0.0:8080\n").unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            readiness_address("[::]:8080\n").unwrap(),
            "[::1]:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            readiness_address("[::]:8080\n0.0.0.0:8080\n").unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        for invalid in ["", "example.com:8080", "127.0.0.1:0", "127.0.0.1:8080/path"] {
            assert!(readiness_address(invalid).is_err());
        }
    }

    #[test]
    fn a_different_running_revision_cannot_complete_an_update() {
        let expected = "a".repeat(40);
        assert!(readiness_revision(br#"{"revision":"other"}"#, &expected).is_err());
        assert!(readiness_revision(br#"{"status":"healthy"}"#, &expected).is_err());
        assert_eq!(
            readiness_revision(
                format!(r#"{{"revision":"{expected}"}}"#).as_bytes(),
                &expected
            )
            .unwrap(),
            expected
        );
    }

    #[test]
    fn dangling_override_symlinks_are_not_silently_dropped_from_preflight() {
        let directory = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            directory.path().join("missing"),
            directory.path().join("compose.override.yaml"),
        )
        .unwrap();
        assert!(candidate_compose(directory.path(), directory.path(), "image").is_err());
    }

    #[test]
    fn alternate_override_files_cannot_escape_backup_and_preflight() {
        for name in [
            "compose.override.yml",
            "docker-compose.override.yml",
            "docker-compose.override.yaml",
        ] {
            let directory = tempfile::tempdir().unwrap();
            fs::write(directory.path().join(name), "services: {}").unwrap();
            assert!(validate_compose_context(directory.path(), |_| false).is_err());
            assert_eq!(
                fs::read_to_string(directory.path().join(name)).unwrap(),
                "services: {}"
            );
        }
    }

    #[test]
    fn ambient_compose_selection_cannot_differ_from_the_managed_configuration() {
        let directory = tempfile::tempdir().unwrap();
        for key in [
            "COMPOSE_FILE",
            "COMPOSE_ENV_FILES",
            "COMPOSE_PROFILES",
            "COMPOSE_PROJECT_NAME",
        ] {
            assert!(validate_compose_context(directory.path(), |name| name == key).is_err());
        }
        assert!(validate_compose_context(directory.path(), |_| false).is_ok());
    }
}
