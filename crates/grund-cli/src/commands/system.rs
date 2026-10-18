use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use clap::{Args, ValueEnum};
use serde_json::json;
use tokio::process::Command;

use crate::{
    context::{Ctx, Global},
    error::{CliError, CliResult, Code},
    output::Output,
};

#[path = "system/release.rs"]
pub(crate) mod release;

pub(crate) const ROOT: &str = "/opt/grund";
const SERVER_UNIT: &str = "/etc/systemd/system/grund-server.service";
const AGENT_MARKER: &str = "/var/lib/grund/.installer-agent";
const UPDATER_UNIT: &str = "/etc/systemd/system/grund-agent-updater.service";
const UPDATE_LOCK: &str = "/var/lib/grund/.update.lock";
const AGENT_INSTALLER: &str = include_str!("../../../grund-agent/install.sh");
const SERVER_SERVICE: &str = "# grund-managed-server-v1\n[Unit]\nDescription=grund self-hosted server\nWants=network-online.target\nAfter=network-online.target docker.service\nRequires=docker.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nWorkingDirectory=/opt/grund\nExecStart=/usr/bin/docker compose --project-directory /opt/grund up --no-build -d --wait --wait-timeout 180\nExecStop=/usr/bin/docker compose --project-directory /opt/grund stop\nTimeoutStartSec=300\nTimeoutStopSec=180\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n";

/// Install the self-hosted server or connect a machine, without signing in.
#[derive(Debug, Args)]
pub struct InstallArgs {
    #[command(flatten)]
    pub global: Global,
    #[arg(
        long,
        conflicts_with = "url",
        help = "DNS name for the self-hosted dashboard; requires root, systemd and Docker Compose v2"
    )]
    pub domain: Option<String>,
    #[arg(
        long,
        conflicts_with = "domain",
        help = "Instance HTTPS address for a machine-only installation; a new machine also needs --code"
    )]
    pub url: Option<String>,
    #[arg(
        long,
        help = "One-time machine enrollment code; existing identity is preserved"
    )]
    pub code: Option<String>,
    #[arg(long, help = "Exact public release tag, such as v0.0.0-alpha.4")]
    pub version: Option<String>,
    #[arg(
        long,
        value_enum,
        conflicts_with = "version",
        help = "Release channel; development builds require an explicit selection"
    )]
    pub channel: Option<release::Channel>,
    #[arg(long, help = "Do not install VM prerequisites")]
    pub no_vms: bool,
    #[arg(
        long,
        help = "Show the operation without downloading or changing this machine"
    )]
    pub dry_run: bool,
}

/// Which installer-managed services to remove; persistent state is retained.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Scope {
    Server,
    Agent,
    All,
}

/// Stop and remove installer-managed units, retaining all configuration and data.
#[derive(Debug, Args)]
pub struct UninstallArgs {
    #[command(flatten)]
    pub global: Global,
    #[arg(value_enum, default_value = "all")]
    pub scope: Scope,
    #[arg(long, help = "Confirm service removal")]
    pub yes: bool,
    #[arg(long, help = "Show exactly which managed services would be removed")]
    pub dry_run: bool,
}

pub(crate) fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Code::Failed, message)
}

pub(crate) fn io(error: std::io::Error) -> CliError {
    failed(format!("local filesystem operation failed: {error}"))
}

pub(crate) async fn run(command: &mut Command, operation: &str) -> CliResult<Vec<u8>> {
    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    let result = tokio::time::timeout(Duration::from_secs(1800), command.output())
        .await
        .map_err(|_| failed(format!("{operation} exceeded its 30-minute deadline")))?
        .map_err(|_| failed(format!("could not execute {operation}")))?;
    if !result.status.success() {
        return Err(failed(format!(
            "{operation} failed ({}); inspect local service/container logs",
            result.status
        )));
    }
    Ok(result.stdout)
}

pub(crate) async fn platform(docker: bool) -> CliResult<()> {
    if std::env::consts::OS != "linux" {
        return Err(CliError::usage("host service operations require Linux"));
    }
    let uid = run(Command::new("/usr/bin/id").arg("-u"), "root check").await?;
    host_platform(
        std::env::consts::OS,
        &uid,
        Path::new("/run/systemd/system").is_dir(),
    )?;
    run(
        Command::new("/usr/bin/systemctl").arg("--version"),
        "systemd prerequisite check",
    )
    .await?;
    if docker {
        run(
            Command::new("/usr/bin/docker").args(["compose", "version"]),
            "Docker Compose v2 prerequisite check",
        )
        .await?;
        run(
            Command::new("/usr/bin/docker").arg("info"),
            "Docker Engine prerequisite check",
        )
        .await?;
    }
    Ok(())
}

fn host_platform(os: &str, uid: &[u8], systemd: bool) -> CliResult<()> {
    if os != "linux" {
        return Err(CliError::usage("host service operations require Linux"));
    }
    if uid != b"0\n" {
        return Err(CliError::new(
            Code::PermissionDenied,
            "host service operations require root; no sudo is invoked",
        ));
    }
    if !systemd {
        return Err(CliError::usage("a running systemd system is required"));
    }
    Ok(())
}

pub(crate) fn secure_directory(path: &Path) -> CliResult<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(CliError::new(
                    Code::PermissionDenied,
                    format!(
                        "{} must be a root-owned non-writable real directory",
                        path.display()
                    ),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700).create(path).map_err(io)?;
        }
        Err(error) => return Err(io(error)),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io)
}

pub(crate) fn read_managed(path: &Path) -> CliResult<String> {
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(CliError::new(
            Code::PermissionDenied,
            format!(
                "{} must be a root-owned regular managed file",
                path.display()
            ),
        ));
    }
    fs::read_to_string(path).map_err(io)
}

pub(crate) fn lock(path: &Path) -> CliResult<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err(CliError::new(
            Code::PermissionDenied,
            "operation lock is not a private root-owned regular file",
        ));
    }
    file.try_lock()
        .map_err(|_| CliError::new(Code::Conflict, "another grund host operation is running"))?;
    Ok(file)
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> CliResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| failed("managed file has no parent directory"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(io)?;
    temporary.write_all(contents).map_err(io)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(io)?;
    temporary.as_file().sync_all().map_err(io)?;
    temporary.persist(path).map_err(|e| io(e.error))?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(io)
}

pub(crate) fn compose(root: &Path) -> Command {
    let mut command = Command::new("/usr/bin/docker");
    command.args(["compose", "--project-directory"]).arg(root);
    command.arg("--env-file").arg(root.join(".env"));
    command
        .env_remove("GRUND_IMAGE")
        .env_remove("GRUND_PULL_POLICY");
    command
}

fn domain_name(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub(crate) fn setting<'a>(env: &'a str, key: &str) -> CliResult<&'a str> {
    let prefix = format!("{key}=");
    let mut found = env.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = found
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| failed(format!("managed configuration lacks {key}")))?;
    if found.next().is_some() {
        return Err(failed(format!("managed configuration repeats {key}")));
    }
    Ok(value)
}

pub(crate) fn present(path: &Path) -> CliResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io(error)),
    }
}

pub(crate) fn installed(root: &Path, domain: Option<&str>) -> CliResult<Option<String>> {
    if let Ok(meta) = fs::symlink_metadata(root)
        && (!meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0)
    {
        return Err(CliError::new(
            Code::PermissionDenied,
            "managed root must be a real root-owned directory, not writable by others",
        ));
    }
    if !present(&root.join(".env"))? {
        if present(&root.join(".installer-domain"))? || present(&root.join("compose.yaml"))? {
            return Err(CliError::new(
                Code::Conflict,
                "incomplete existing configuration; restore or inspect it before installing",
            ));
        }
        return Ok(None);
    }
    let marker = read_managed(&root.join(".installer-domain"))?;
    if domain.is_some_and(|domain| marker.trim_end() != domain) {
        return Err(CliError::new(
            Code::Conflict,
            "existing installation belongs to another domain",
        ));
    }
    let env = read_managed(&root.join(".env"))?;
    setting(&env, "GRUND_IMAGE")?;
    read_managed(&root.join("compose.yaml"))?;
    let version = if present(&root.join(".installer-version"))? {
        read_managed(&root.join(".installer-version"))?
            .trim()
            .to_owned()
    } else {
        setting(&env, "GRUND_IMAGE")?
            .strip_prefix("git.kjuulh.io/grund/grund:")
            .unwrap_or("")
            .to_owned()
    };
    Ok(Some(version))
}

pub(crate) async fn installed_version(
    root: &Path,
    domain: Option<&str>,
) -> CliResult<Option<String>> {
    let existing = installed(root, domain)?;
    if existing.as_deref() != Some("") {
        return Ok(existing);
    }
    let output = run(
        compose(root).args(["exec", "-T", "grund", "/grund", "--version"]),
        "read existing managed server release identity",
    )
    .await?;
    let output = std::str::from_utf8(&output)
        .map_err(|_| failed("existing server reports an invalid version"))?;
    let tag = output
        .trim_end()
        .strip_prefix("grund ")
        .ok_or_else(|| failed("existing server reports an invalid version"))?;
    release::Version::parse(tag)?;
    Ok(Some(tag.to_owned()))
}

pub(crate) fn image_identity(path: &Path) -> CliResult<String> {
    let image = fs::read_to_string(path).map_err(io)?;
    let image = image.trim_end();
    let hash = image
        .strip_prefix("git.kjuulh.io/grund/grund@sha256:")
        .ok_or_else(|| failed("release does not name the fixed public immutable image"))?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(failed("release image checksum is invalid"));
    }
    Ok(image.to_owned())
}

pub(crate) async fn binary_identity(path: &Path, tag: &str) -> CliResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(io)?;
    let output = run(
        Command::new(path).arg("--version"),
        "verified binary identity check",
    )
    .await?;
    if output != format!("grund {tag}\n").as_bytes() {
        return Err(failed(
            "downloaded executable reports a different release; no executable was replaced",
        ));
    }
    Ok(())
}

async fn agent_install(
    directory: &Path,
    binary: &Path,
    url: &str,
    code: Option<&str>,
    no_vms: bool,
) -> CliResult<()> {
    let script = directory.join("current-agent-install.sh");
    atomic_write(&script, AGENT_INSTALLER.as_bytes(), 0o700)?;
    let mut command = Command::new("/bin/sh");
    command
        .arg(&script)
        .arg("--url")
        .arg(url)
        .arg("--binary")
        .arg(binary);
    if let Some(code) = code {
        command.arg("--code").arg(code);
    } else {
        command.arg("--prepare-only");
    }
    if no_vms {
        command.arg("--no-vms");
    }
    run(&mut command, "machine installation").await?;
    Ok(())
}

/// Install managed services without changing an existing server image or configuration.
pub async fn install(_ctx: &Ctx, args: InstallArgs) -> CliResult<Output> {
    let url = match (&args.domain, &args.url) {
        (Some(domain), None) if domain_name(domain) => format!("https://{domain}"),
        (None, Some(url)) => {
            let parsed = reqwest::Url::parse(url)
                .map_err(|_| CliError::usage("--url requires an HTTPS instance origin"))?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || parsed.username() != ""
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || parsed.path() != "/"
            {
                return Err(CliError::usage(
                    "--url requires an HTTPS instance origin without credentials or path",
                ));
            }
            url.trim_end_matches('/').to_owned()
        }
        _ => {
            return Err(CliError::usage(
                "choose --domain DNS-NAME or --url HTTPS-ORIGIN --code CODE",
            ));
        }
    };
    let updater_data = installed_updater_data_dir().await?;
    let agent_data = updater_data
        .as_deref()
        .unwrap_or(Path::new("/var/lib/grund/agent"));
    if args.url.is_some() && args.code.is_none() && !agent_data.join("machine.json").is_file() {
        return Err(CliError::usage(
            "a new machine installation requires --code; registered machines keep their identity",
        ));
    }
    refuse_agent_recovery(agent_data)?;
    if let Some(version) = &args.version {
        release::Version::parse(version)?;
    }
    if args.version.is_none()
        && args.channel.is_none()
        && release::Version::parse(crate::VERSION).is_err()
    {
        return Err(CliError::usage(
            "development builds require an explicit --version or --channel",
        ));
    }
    platform(args.domain.is_some()).await?;
    let root = Path::new(ROOT);
    if args.domain.is_some() {
        refuse_server_recovery(root)?;
    }
    let previous = if args.domain.is_some() {
        installed_version(root, args.domain.as_deref()).await?
    } else {
        None
    };
    if let (Some(previous), Some(requested)) = (&previous, &args.version)
        && previous != requested
    {
        return Err(
            CliError::new(Code::Conflict, "reinstall never changes the server release")
                .hint("use grund update server --version TAG"),
        );
    }
    if present(Path::new(SERVER_UNIT))?
        && args.domain.is_some()
        && read_managed(Path::new(SERVER_UNIT))? != SERVER_SERVICE
    {
        return Err(CliError::new(
            Code::Conflict,
            "grund-server.service is not managed by this installer",
        ));
    }
    if args.dry_run {
        return Ok(Output::fields(
            json!({"dryRun":true,"operation":"install","scope":if args.domain.is_some(){"server-and-agent"}else{"agent"},"url":url,"preserveExisting":previous.is_some(),"version":previous.as_deref().or(args.version.as_deref()).unwrap_or(""),"channel":args.channel.map(|c|format!("{c:?}").to_lowercase()).unwrap_or_default()}),
        ));
    }
    let _server_lock = if args.domain.is_some() {
        secure_directory(root)?;
        Some(lock(&root.join(".operation.lock"))?)
    } else {
        None
    };
    secure_directory(Path::new("/var/lib/grund"))?;
    let agent_lock = lock(Path::new(UPDATE_LOCK))?;
    let locked_updater_data = installed_updater_data_dir().await?;
    if locked_updater_data != updater_data {
        return Err(CliError::new(
            Code::Conflict,
            "machine updater configuration changed before the installation lock; retry",
        ));
    }
    refuse_agent_recovery(agent_data)?;
    if args.domain.is_some() {
        refuse_server_recovery(root)?;
    }
    let previous = if args.domain.is_some() {
        installed_version(root, args.domain.as_deref()).await?
    } else {
        previous
    };
    if let (Some(previous), Some(requested)) = (&previous, &args.version)
        && previous != requested
    {
        return Err(
            CliError::new(Code::Conflict, "reinstall never changes the server release")
                .hint("use grund update server --version TAG"),
        );
    }
    let selected = previous
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(args.version.as_deref());
    let release = release::Release::resolve(selected, args.channel, crate::VERSION).await?;
    let staging = tempfile::Builder::new()
        .prefix("grund-install-")
        .tempdir_in(if args.domain.is_some() {
            root
        } else {
            Path::new("/var/tmp")
        })
        .map_err(io)?;
    let binary = staging.path().join("grund");
    release.download(&release::binary_name()?, &binary).await?;
    binary_identity(&binary, &release.tag).await?;
    if args.domain.is_some() {
        for name in [
            "compose.yaml",
            "image-digest.txt",
            "release.txt",
            "agent-install.sh",
        ] {
            release.download(name, &staging.path().join(name)).await?;
        }
        let image = image_identity(&staging.path().join("image-digest.txt"))?;
        if previous.is_none() {
            let domain = args.domain.as_deref().unwrap_or_default();
            atomic_write(
                &root.join(".env"),
                format!("GRUND_DOMAIN={domain}\nGRUND_IMAGE={image}\nGRUND_PULL_POLICY=missing\n")
                    .as_bytes(),
                0o600,
            )?;
            atomic_write(
                &root.join("compose.yaml"),
                &fs::read(staging.path().join("compose.yaml")).map_err(io)?,
                0o600,
            )?;
            atomic_write(
                &root.join(".installer-domain"),
                format!("{domain}\n").as_bytes(),
                0o600,
            )?;
            atomic_write(
                &root.join(".installer-version"),
                format!("{}\n", release.tag).as_bytes(),
                0o600,
            )?;
        }
        atomic_write(Path::new(SERVER_UNIT), SERVER_SERVICE.as_bytes(), 0o644)?;
        run(
            Command::new("/usr/bin/systemctl").arg("daemon-reload"),
            "reload server unit",
        )
        .await?;
        run(
            Command::new("/usr/bin/systemctl").args(["enable", "--now", "grund-server.service"]),
            "enable and start server",
        )
        .await?;
        run(
            compose(root).args([
                "exec",
                "-T",
                "grund",
                "/grund",
                "probe",
                "--address",
                "127.0.0.1:8080",
            ]),
            "verify installed server readiness",
        )
        .await?;
    }
    drop(agent_lock);
    agent_install(
        staging.path(),
        &binary,
        &url,
        args.code.as_deref(),
        args.no_vms,
    )
    .await?;
    Ok(Output::fields(
        json!({"operation":"install","version":release.tag,"url":url,"serverInstalled":args.domain.is_some(),"agentPrepared":true,"enrollmentRequested":args.code.is_some(),"preservedExisting":previous.is_some(),"configPath":if args.domain.is_some(){ROOT}else{""},"agentBinary":"/usr/local/lib/grund/agent/grund","next":if args.domain.is_some() && args.code.is_none(){"Create the owner: docker compose --project-directory /opt/grund exec grund /grund setup-link; then obtain a code from Machines and rerun grund install --domain NAME --code CODE"}else{"Machine identity and persistent data are retained"}}),
    ))
}

fn refuse_server_recovery(root: &Path) -> CliResult<()> {
    if present(&root.join(".server-update.json"))? {
        return Err(CliError::new(
            Code::Conflict,
            "a server update needs deliberate recovery; installation cannot bypass its recovery journal",
        ).hint("Restore the complete backup or verify the updated stack before clearing /opt/grund/.server-update.json."));
    }
    Ok(())
}

fn managed_command(unit: &str, command: &str) -> bool {
    unit.lines().any(|line| {
        line.strip_prefix("ExecStart=")
            .and_then(|value| value.strip_prefix(command))
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(' '))
    })
}

fn updater_data_dir(unit: &str) -> CliResult<PathBuf> {
    let command = "/usr/local/lib/grund/agent/updater agent-supervisor";
    let mut start = None;
    let mut environment_data = false;
    for line in unit.lines().map(str::trim) {
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "EnvironmentFile" => {
                return Err(CliError::new(
                    Code::Conflict,
                    "machine updater uses EnvironmentFile; its data directory cannot be safely resolved",
                ));
            }
            "Environment" if value.contains("GRUND_AGENT_DATA_DIR") => environment_data = true,
            "ExecStart" if start.replace(value).is_some() => {
                return Err(CliError::new(
                    Code::Conflict,
                    "machine updater must have exactly one managed ExecStart",
                ));
            }
            _ => {}
        }
    }
    let start = start.ok_or_else(|| {
        CliError::new(
            Code::Conflict,
            "machine updater must have exactly one managed ExecStart",
        )
    })?;
    if start == command && !environment_data {
        return Ok(PathBuf::from("/var/lib/grund/agent"));
    }
    let data = start
        .strip_prefix(command)
        .and_then(|args| args.strip_prefix(" --data-dir "))
        .filter(|data| {
            data.starts_with('/')
                && data
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b))
        })
        .ok_or_else(|| {
            CliError::new(
                Code::Conflict,
                "machine updater must use a managed command with one simple absolute --data-dir",
            )
        })?;
    Ok(PathBuf::from(data))
}

async fn installed_updater_data_dir() -> CliResult<Option<PathBuf>> {
    let path = Path::new(UPDATER_UNIT);
    if !present(path)? {
        return Ok(None);
    }
    let unit = read_managed(path)?;
    let data = updater_data_dir(&unit)?;
    let overrides = run(
        Command::new("/usr/bin/systemctl").args([
            "show",
            "--value",
            "--property=EnvironmentFiles",
            "--property=DropInPaths",
            "grund-agent-updater.service",
        ]),
        "inspect machine updater overrides",
    )
    .await?;
    if !overrides.iter().all(u8::is_ascii_whitespace) {
        return Err(CliError::new(
            Code::Conflict,
            "machine updater uses EnvironmentFile or drop-ins; its data directory cannot be safely resolved",
        ));
    }
    if !unit
        .lines()
        .any(|line| line.trim_start().starts_with("ExecStart=") && line.contains(" --data-dir "))
    {
        let environment = run(
            Command::new("/usr/bin/systemctl").args([
                "show",
                "--value",
                "--property=Environment",
                "grund-agent-updater.service",
            ]),
            "inspect machine updater environment",
        )
        .await?;
        if String::from_utf8_lossy(&environment).contains("GRUND_AGENT_DATA_DIR") {
            return Err(CliError::new(
                Code::Conflict,
                "machine updater environment overrides its implicit data directory; use an explicit managed --data-dir",
            ));
        }
    }
    Ok(Some(data))
}

fn refuse_agent_recovery(data_dir: &Path) -> CliResult<()> {
    if present(&data_dir.join("update-journal.json"))? {
        return Err(CliError::new(
            Code::Conflict,
            "machine has an unresolved update journal; resolve it before installing or uninstalling",
        ));
    }
    Ok(())
}

fn managed_agent() -> CliResult<bool> {
    if !present(Path::new(AGENT_MARKER))? {
        return Ok(false);
    }
    if read_managed(Path::new(AGENT_MARKER))? != "grund-agent-v1\n" {
        return Err(CliError::new(
            Code::Conflict,
            "unrecognized machine installer marker",
        ));
    }
    let unit = Path::new("/etc/systemd/system/grund-agent.service");
    if !present(unit)? {
        return Ok(false);
    }
    if !managed_command(
        &read_managed(unit)?,
        "/usr/local/lib/grund/agent/grund agent",
    ) {
        return Err(CliError::new(
            Code::Conflict,
            "machine unit no longer uses the managed executable",
        ));
    }
    Ok(true)
}

/// Remove only marked units; never delete instance volumes, credentials or machine disks.
pub async fn uninstall(ctx: &Ctx, args: UninstallArgs) -> CliResult<Output> {
    platform(false).await?;
    let server = !matches!(args.scope, Scope::Agent) && present(Path::new(SERVER_UNIT))?;
    if server {
        installed(Path::new(ROOT), None)?
            .ok_or_else(|| CliError::new(Code::Conflict, "server configuration is unmanaged"))?;
        if read_managed(Path::new(SERVER_UNIT))? != SERVER_SERVICE {
            return Err(CliError::new(Code::Conflict, "server unit is unmanaged"));
        }
    }
    let agent = !matches!(args.scope, Scope::Server) && managed_agent()?;
    let updater_data = if agent {
        installed_updater_data_dir().await?
    } else {
        None
    };
    let agent_data = updater_data
        .as_deref()
        .unwrap_or(Path::new("/var/lib/grund/agent"));
    if agent {
        refuse_agent_recovery(agent_data)?;
    }
    let mut removed = Vec::new();
    if server {
        removed.push("grund-server.service");
    }
    if agent {
        let updater = Path::new(UPDATER_UNIT);
        if present(updater)? {
            removed.push("grund-agent-updater.service");
        }
        removed.push("grund-agent.service");
    }
    let retained = [
        "/opt/grund",
        "grund_grund-data",
        "grund_grund-postgres",
        "/var/lib/grund",
        "/usr/local/lib/grund/agent",
        "/usr/local/bin/grund",
    ];
    if args.dry_run {
        return Ok(Output::fields(
            json!({"dryRun":true,"operation":"uninstall","services":removed,"retained":retained}),
        ));
    }
    ctx.confirm(
        args.yes,
        "Stop and remove the managed grund services, keeping all data?",
    )?;
    let _server_lock = if server {
        Some(lock(&Path::new(ROOT).join(".operation.lock"))?)
    } else {
        None
    };
    let _agent_lock = if agent {
        Some(lock(Path::new(UPDATE_LOCK))?)
    } else {
        None
    };
    if agent {
        if installed_updater_data_dir().await? != updater_data {
            return Err(CliError::new(
                Code::Conflict,
                "machine updater configuration changed before the uninstall lock; retry",
            ));
        }
        refuse_agent_recovery(agent_data)?;
    }
    for unit in &removed {
        run(
            Command::new("/usr/bin/systemctl").args(["disable", "--now", unit]),
            "stop managed service",
        )
        .await?;
        fs::remove_file(PathBuf::from("/etc/systemd/system").join(unit)).map_err(io)?;
    }
    if !removed.is_empty() {
        run(
            Command::new("/usr/bin/systemctl").arg("daemon-reload"),
            "reload removed units",
        )
        .await?;
    }
    Ok(Output::fields(
        json!({"operation":"uninstall","removedServices":removed,"retained":retained,"next":"Revoke the retained machine identity from the instance dashboard if this host is retired. App/VM disks and host networking are not removed."}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_custom_updater_journal_fences_reinstall_and_uninstall() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("custom-agent");
        fs::create_dir(&data).unwrap();
        let unit = format!(
            "[Service]\nExecStart=/usr/local/lib/grund/agent/updater agent-supervisor --data-dir {}\n",
            data.display()
        );
        let preserved = updater_data_dir(&unit).unwrap();
        assert!(refuse_agent_recovery(&preserved).is_ok());
        fs::write(data.join("update-journal.json"), b"unresolved").unwrap();
        assert_eq!(
            refuse_agent_recovery(&preserved).unwrap_err().code,
            Code::Conflict
        );
    }

    #[test]
    fn ambiguous_or_unresolved_updater_directories_are_refused() {
        let command = "ExecStart=/usr/local/lib/grund/agent/updater agent-supervisor";
        for unit in [
            format!("{command} --data-dir /srv/grund --data-dir /other\n"),
            format!("{command}\n{command} --data-dir /srv/grund\n"),
            format!("EnvironmentFile=/etc/grund.env\n{command} --data-dir /srv/grund\n"),
            format!("Environment=GRUND_AGENT_DATA_DIR=/srv/grund\n{command}\n"),
            format!("{command} --data-dir /srv/grund%h\n"),
            format!("{command} --data-dir relative\n"),
        ] {
            assert!(updater_data_dir(&unit).is_err(), "{unit}");
        }
    }

    #[test]
    fn uninstall_rejects_similarly_named_or_commented_unmanaged_commands() {
        let command = "/usr/local/lib/grund/agent/updater agent-supervisor";
        assert!(managed_command(
            &format!("ExecStart={command} --data-dir /srv/grund\n"),
            command
        ));
        assert!(!managed_command(
            &format!("ExecStart={command}-other\n"),
            command
        ));
        assert!(!managed_command(
            &format!("# ExecStart={command}\n"),
            command
        ));
    }

    #[test]
    fn unsupported_hosts_are_refused_before_mutation() {
        assert!(host_platform("linux", b"1000\n", true).is_err());
        assert!(host_platform("macos", b"0\n", true).is_err());
        assert!(host_platform("linux", b"0\n", false).is_err());
        assert!(host_platform("linux", b"0\n", true).is_ok());
    }

    #[test]
    fn unmanaged_configuration_is_never_adopted_or_rewritten() {
        let root = tempfile::tempdir().unwrap();
        let original = b"GRUND_IMAGE=old-image\n";
        fs::write(root.path().join(".env"), original).unwrap();
        assert!(installed(root.path(), Some("grund.example.com")).is_err());
        assert_eq!(fs::read(root.path().join(".env")).unwrap(), original);
    }

    #[test]
    fn only_dns_names_can_enter_server_configuration() {
        for domain in ["grund.example.com", "a-b.example"] {
            assert!(domain_name(domain));
        }
        for domain in [
            "localhost",
            "https://example.com",
            "x.example\nGRUND_IMAGE=evil",
            "-x.example",
            "x..example",
            "x.example:443",
        ] {
            assert!(!domain_name(domain));
        }
    }

    #[test]
    fn duplicate_image_settings_are_not_ambiguous_reinstall_targets() {
        assert!(setting("GRUND_IMAGE=one\nGRUND_IMAGE=two\n", "GRUND_IMAGE").is_err());
        let env = "GRUND_IMAGE=git.kjuulh.io/grund/grund:v1.0.0\n";
        assert_eq!(
            setting(env, "GRUND_IMAGE").unwrap(),
            "git.kjuulh.io/grund/grund:v1.0.0"
        );
    }
}
