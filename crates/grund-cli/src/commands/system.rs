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
    progress::Progress,
};

#[path = "system/release.rs"]
pub(crate) mod release;

#[path = "system/local.rs"]
mod local;

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
    #[arg(
        long,
        help = "Use the local default without prompts or animated output"
    )]
    pub yes: bool,
    #[arg(long, global = true, help = "Show technical failure details")]
    pub verbose: bool,
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
    #[arg(long, global = true, help = "Show technical failure details")]
    pub verbose: bool,
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
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GRUND_")
            || key.as_encoded_bytes().starts_with(b"COMPOSE_")
        {
            command.env_remove(key);
        }
    }
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

/// Install services or add HTTPS to a local instance without changing its server image.
pub async fn install(ctx: &Ctx, args: InstallArgs) -> CliResult<Output> {
    let progress = Progress::new(ctx, args.yes, args.verbose);
    install_inner(ctx, args, &progress).await.map_err(|error| {
        if matches!(
            error.code,
            Code::Usage | Code::PermissionDenied | Code::Conflict
        ) {
            error
        } else {
            progress.failure(
                error,
                "Installation",
                "Run grund install --verbose for details.",
            )
        }
    })
}

async fn install_inner(ctx: &Ctx, mut args: InstallArgs, progress: &Progress) -> CliResult<Output> {
    progress
        .step(
            "Checking this machine",
            "Run grund install as root on a machine running Linux and systemd.",
            platform(false),
        )
        .await?;
    if args.code.is_some() && args.url.is_none() && args.domain.is_none() {
        return Err(CliError::usage(
            "Use --url HTTPS-ADDRESS with the machine setup code, or --domain NAME for this server.",
        ));
    }
    let default_setup = args.url.is_none() && args.domain.is_none();
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
    let root = Path::new(ROOT);
    let server = args.url.is_none();
    let previous = if server {
        refuse_server_recovery(root)?;
        installed_version(root, None).await?
    } else {
        None
    };
    let existing_domain = local::domain(root, previous.is_some())?;
    if server
        && previous.is_none()
        && args.domain.is_none()
        && ctx.interactive
        && !args.yes
        && !args.dry_run
    {
        eprint!("Do you have a domain for this server? (leave empty to run locally) ");
        std::io::stderr().flush().map_err(io)?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).map_err(io)?;
        if !answer.trim().is_empty() {
            args.domain = Some(answer.trim().to_owned());
        }
    }
    let target = local::target(
        args.domain.as_deref(),
        args.url.as_deref(),
        existing_domain.as_deref(),
    )?;
    let server = target.server;
    let updater_data = installed_updater_data_dir().await?;
    let agent_data = updater_data
        .as_deref()
        .unwrap_or(Path::new("/var/lib/grund/agent"));
    let registered = agent_data.join("machine.json").is_file();
    if !server && args.code.is_none() && !registered {
        return Err(CliError::usage(
            "a new machine needs --code; an already connected machine keeps its identity",
        ));
    }
    if server && previous.is_none() && target.domain.is_none() && registered {
        return Err(CliError::new(
            Code::Conflict,
            "This machine is already connected to an instance.",
        )
        .hint(
            "Keep that connection or explicitly remove it before creating a new local instance.",
        ));
    }
    refuse_agent_recovery(agent_data)?;
    if let (Some(previous), Some(requested)) = (&previous, &args.version)
        && previous != requested
    {
        return Err(
            CliError::new(Code::Conflict, "reinstall never changes the server release")
                .hint("use grund update server --version TAG"),
        );
    }
    if server
        && present(Path::new(SERVER_UNIT))?
        && read_managed(Path::new(SERVER_UNIT))? != SERVER_SERVICE
    {
        return Err(CliError::new(
            Code::Conflict,
            "the existing server service is not managed by this installer",
        ));
    }
    if args.dry_run {
        return Ok(Output::with_text(
            json!({"dryRun":true,"operation":"install","scope":if server{"server-and-agent"}else{"agent"},"url":target.url,"preserveExisting":previous.is_some(),"version":previous.as_deref().or(args.version.as_deref()).unwrap_or(""),"convertToTls":target.convert}),
            progress.summary(
                "Installation plan",
                &[
                    ("Address", &target.url),
                    (
                        "Changes",
                        if target.convert {
                            "Add HTTPS; keep data, identity and server version"
                        } else if server {
                            "Set up grund and this machine"
                        } else {
                            "Connect this machine"
                        },
                    ),
                ],
            ),
        ));
    }
    let _server_lock = if server {
        secure_directory(root)?;
        Some(lock(&root.join(".operation.lock"))?)
    } else {
        None
    };
    secure_directory(Path::new("/var/lib/grund"))?;
    let agent_lock = lock(Path::new(UPDATE_LOCK))?;
    if installed_updater_data_dir().await? != updater_data {
        return Err(CliError::new(
            Code::Conflict,
            "machine update settings changed before installation; retry",
        ));
    }
    refuse_agent_recovery(agent_data)?;
    if server {
        refuse_server_recovery(root)?;
        local::docker(progress).await?;
        local::recover_domain(root).await?;
        if installed_version(root, None).await? != previous
            || local::domain(root, previous.is_some())? != existing_domain
        {
            return Err(CliError::new(
                Code::Conflict,
                "server settings changed before installation; retry",
            ));
        }
    }
    let selected = previous
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(args.version.as_deref());
    let release = progress
        .step(
            "Finding grund",
            "Check the internet connection and requested version.",
            release::Release::resolve(selected, args.channel, crate::VERSION),
        )
        .await?;
    let staging = tempfile::Builder::new()
        .prefix("grund-install-")
        .tempdir_in(if server { root } else { Path::new("/var/tmp") })
        .map_err(io)?;
    let binary = staging.path().join("grund");
    progress
        .step(
            &format!("Downloading and checking grund {}", release.tag),
            "Check the internet connection, then retry.",
            async {
                release.download(&release::binary_name()?, &binary).await?;
                binary_identity(&binary, &release.tag).await?;
                if server {
                    for name in [
                        "compose.yaml",
                        "image-digest.txt",
                        "release.txt",
                        "agent-install.sh",
                    ] {
                        release.download(name, &staging.path().join(name)).await?;
                    }
                }
                Ok(())
            },
        )
        .await?;
    let local_bootstrap = server
        && (target.domain.is_none()
            || (default_setup && previous.is_none())
            || agent_data.join("local-bootstrap.json").is_file());
    let bootstrap = if local_bootstrap {
        Some(
            progress
                .step(
                    "Preparing this machine",
                    "Update grund to a release that supports local setup, then retry.",
                    async {
                        run(
                            Command::new(&binary)
                                .arg("prepare-local-machine")
                                .arg("--data-dir")
                                .arg(agent_data),
                            "prepare local machine identity",
                        )
                        .await
                    },
                )
                .await?,
        )
    } else {
        None
    };
    if server {
        let image = image_identity(&staging.path().join("image-digest.txt"))?;
        if previous.is_none() {
            let domain = target.domain.unwrap_or_default();
            let local_settings = if local_bootstrap {
                "GRUND_BIND=127.0.0.1\nGRUND_PORT=8080\nGRUND_LOCAL_MACHINE_FILE=/var/lib/grund/local-machine.json\n"
            } else {
                ""
            };
            atomic_write(&root.join(".env"),
                format!("GRUND_DOMAIN={domain}\nGRUND_PUBLIC_URL={}\nGRUND_IMAGE={image}\nGRUND_PULL_POLICY=missing\n{local_settings}", target.url).as_bytes(), 0o600)?;
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
        if let Some(bootstrap) = bootstrap {
            progress
                .step(
                    "Preparing your account setup",
                    "Run grund install --verbose to see which setup step failed.",
                    async {
                        local::input(
                            compose(root).args([
                                "run",
                                "--rm",
                                "-T",
                                "--no-deps",
                                "init",
                                "init",
                                "--data-dir",
                                "/var/lib/grund",
                                "--local-machine-stdin",
                            ]),
                            &bootstrap,
                            "save local machine identity",
                        )
                        .await
                        .map(|_| ())
                    },
                )
                .await?;
        }
        if target.convert {
            progress
                .step(
                    "Setting up HTTPS",
                    "Point the domain at this machine and allow incoming port 443, then retry.",
                    local::convert_domain(root, target.domain.unwrap_or_default()),
                )
                .await?;
        }
        progress
            .step(
                "Starting grund",
                "Run grund install --verbose to see why grund could not start.",
                async {
                    atomic_write(Path::new(SERVER_UNIT), SERVER_SERVICE.as_bytes(), 0o644)?;
                    run(
                        Command::new("/usr/bin/systemctl").arg("daemon-reload"),
                        "reload server service",
                    )
                    .await?;
                    run(
                        Command::new("/usr/bin/systemctl").args([
                            "enable",
                            "--now",
                            "grund-server.service",
                        ]),
                        "start server service",
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
                        "check server readiness",
                    )
                    .await
                    .map(|_| ())
                },
            )
            .await?;
    }
    drop(agent_lock);
    if !target.convert || !registered {
        let label = if local_bootstrap {
            "Getting this machine ready to connect"
        } else if args.code.is_some() || registered {
            "Connecting this machine"
        } else {
            "Preparing this machine"
        };
        progress
            .step(
                label,
                "Run grund install --verbose to see why this machine could not connect.",
                agent_install(
                    staging.path(),
                    &binary,
                    &target.url,
                    args.code.as_deref(),
                    args.no_vms,
                ),
            )
            .await?;
    }
    let setup_link = if local_bootstrap {
        let state = run(
            compose(root).args(["exec", "-T", "grund", "/grund", "local-machine"]),
            "check local owner setup",
        )
        .await?;
        let state: serde_json::Value = serde_json::from_slice(&state)
            .map_err(|_| failed("local setup returned an invalid response"))?;
        if state.is_null() {
            match run(
                compose(root).args(["exec", "-T", "grund", "/grund", "setup-link"]),
                "create owner setup link",
            )
            .await
            {
                Ok(output) => {
                    let text = std::str::from_utf8(&output)
                        .map_err(|_| failed("owner setup returned an invalid response"))?;
                    Some(
                        text.lines()
                            .map(str::trim)
                            .find(|line| {
                                line.starts_with("http") && line.contains("/signup/owner?token=")
                            })
                            .ok_or_else(|| failed("owner setup returned no link"))?
                            .to_owned(),
                    )
                }
                Err(error) => {
                    let state = run(
                        compose(root).args(["exec", "-T", "grund", "/grund", "local-machine"]),
                        "recheck claimed owner setup",
                    )
                    .await?;
                    let state: serde_json::Value = serde_json::from_slice(&state)
                        .map_err(|_| failed("local setup returned an invalid response"))?;
                    if state.is_null() {
                        return Err(error);
                    }
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    let remote = std::env::var("SSH_CONNECTION").ok();
    let tunnel = if target.domain.is_none() && server {
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname").map_err(io)?;
        let user = std::env::var("SUDO_USER")
            .ok()
            .filter(|user| !user.is_empty() && user != "root")
            .or_else(|| std::env::var("USER").ok());
        Some(local::tunnel(
            remote.as_deref(),
            user.as_deref(),
            hostname.trim(),
        )?)
    } else {
        None
    };
    let next = if setup_link.is_some() {
        "Open the setup link; this machine connects when you finish. Then run grund doctor machine."
    } else if !local_bootstrap && server && !registered && args.code.is_none() {
        "Create your owner account with grund setup-link in the server, then get a machine setup code from Machines."
    } else {
        "Run grund doctor machine to check this machine."
    };
    let mut summary = Vec::with_capacity(5);
    if remote.is_some()
        && let Some(tunnel) = tunnel.as_deref()
    {
        summary.push(("From your computer", tunnel));
    }
    if let Some(link) = setup_link.as_deref() {
        summary.push(("Setup link", link));
    } else {
        summary.push(("Address", target.url.as_ref()));
    }
    if remote.is_none()
        && let Some(tunnel) = tunnel.as_deref()
    {
        summary.push(("From another computer", tunnel));
    }
    if target.domain.is_none() && server {
        summary.push(("Security", "Local HTTP only; not encrypted. Use localhost or an SSH tunnel until you add a domain."));
    }
    summary.push(("Next", next));
    Ok(Output::with_text(
        json!({"operation":"install","version":release.tag,"url":target.url,"serverInstalled":server,"agentPrepared":true,"enrollmentRequested":args.code.is_some() || local_bootstrap,"preservedExisting":previous.is_some(),"configPath":if server {ROOT}else{""},"agentBinary":"/usr/local/lib/grund/agent/grund","setupLink":setup_link,"sshTunnel":tunnel,"next":next}),
        progress.summary("grund is ready", &summary),
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
    let progress = Progress::new(ctx, args.yes, args.verbose);
    uninstall_inner(ctx, args, &progress)
        .await
        .map_err(|error| {
            if matches!(
                error.code,
                Code::Usage | Code::ConfirmationRequired | Code::PermissionDenied | Code::Conflict
            ) {
                error
            } else {
                progress.failure(
                    error,
                    "Removal",
                    "Run grund uninstall --verbose for details.",
                )
            }
        })
}

async fn uninstall_inner(ctx: &Ctx, args: UninstallArgs, progress: &Progress) -> CliResult<Output> {
    progress
        .step(
            "Checking this machine",
            "Run grund uninstall as root on this machine.",
            platform(false),
        )
        .await?;
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
    ctx.confirm(args.yes, "Stop grund and its agent, keeping all data")?;
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
        let label = match *unit {
            "grund-server.service" => "Stopping grund",
            "grund-agent-updater.service" => "Stopping automatic updates",
            _ => "Disconnecting this machine",
        };
        progress
            .step(
                label,
                "Run grund uninstall --verbose to see which service could not stop.",
                async {
                    run(
                        Command::new("/usr/bin/systemctl").args(["disable", "--now", unit]),
                        "stop managed service",
                    )
                    .await?;
                    fs::remove_file(PathBuf::from("/etc/systemd/system").join(unit)).map_err(io)
                },
            )
            .await?;
    }
    if !removed.is_empty() {
        run(
            Command::new("/usr/bin/systemctl").arg("daemon-reload"),
            "reload removed units",
        )
        .await?;
    }
    Ok(Output::with_text(
        json!({"operation":"uninstall","removedServices":removed,"retained":retained,"next":"Revoke the retained machine identity from the instance dashboard if this host is retired. App/VM disks and host networking are not removed."}),
        progress.summary(
            if removed.is_empty() {
                "grund is already removed"
            } else {
                "grund is stopped"
            },
            &[
                ("Saved", "Your settings, identity and app data are kept"),
                (
                    "Next",
                    "If this machine is retired, revoke it from Machines in your dashboard",
                ),
            ],
        ),
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
