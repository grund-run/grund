//! `grund server`: the self-hosted dashboard on this computer, run with
//! Docker Compose and the grund-server image (grund-docs
//! design/cli-redesign.md §5). It drives the server; it never links it.

use std::{path::Path, process::Stdio, time::Duration};

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::{
    api::Api,
    commands::{
        Noun,
        system::{self, InstallArgs, ROOT, Scope, UninstallArgs, release},
        system_update::UpdateArgs,
    },
    context::Global,
    error::{CliError, CliResult, Code},
    output::Output,
};

/// `grund server`.
pub type ServerCommand = Noun<ServerAction>;

/// What `grund server` does.
#[derive(Debug, Subcommand)]
pub enum ServerAction {
    #[command(
        about = "Install the dashboard here, or add HTTPS to it; requires Linux, root, systemd and Docker Compose v2"
    )]
    Install(ServerInstallArgs),
    #[command(
        about = "Back up, check and update the dashboard; requires root and downtime",
        long_about = "Back up, check and update the installer-managed server; requires root and downtime. Only compose.yaml plus an optional root-owned compose.override.yaml are supported; alternate override names and ambient COMPOSE_FILE, COMPOSE_ENV_FILES, COMPOSE_PROFILES and COMPOSE_PROJECT_NAME are refused. Store any profiles in /opt/grund/.env so preflight, migration and systemd use the same selection. The effective current and candidate stacks must retain the canonical local PostgreSQL database, key/password files, named volumes, service commands and default network; only separate read-only TLS bind mounts are supported as extra primary-service mounts. Unsupported primary topology is refused before downtime. The backup covers PostgreSQL, the instance data volume, and managed configuration including compose.override.yaml when present. Other services' data and external TLS files are not backed up; protect those separately before updating."
    )]
    Update(ServerUpdateArgs),
    #[command(
        about = "Stop and remove the dashboard's services, keeping its configuration and data"
    )]
    Uninstall(ServerUninstallArgs),
    #[command(about = "The dashboard's release, address and whether it is ready")]
    Status,
    #[command(
        about = "Check the dashboard with its own settings, without changing it. Exits 1 when a check fails"
    )]
    Doctor,
    #[command(
        name = "setup-link",
        about = "Print the one-time link that creates the dashboard's owner, before any account exists"
    )]
    SetupLink,
    #[command(
        about = "The rollout of new builds to this dashboard's machines: show, pause, resume"
    )]
    Rollout {
        #[command(subcommand)]
        action: RolloutAction,
    },
}

/// What `grund server rollout` does.
#[derive(Debug, Subcommand)]
pub enum RolloutAction {
    #[command(about = "Whether machines are being updated, to which build, and which one is")]
    Status,
    #[command(about = "Offer no machine a new build; an update under way still finishes safely")]
    Pause,
    #[command(about = "Offer machines new builds again")]
    Resume,
}

fn installed() -> CliResult<()> {
    if Path::new(ROOT).join("compose.yaml").is_file() {
        return Ok(());
    }
    Err(
        CliError::new(Code::NotFound, "no dashboard is installed on this computer")
            .hint("sudo grund server install"),
    )
}

async fn in_container(args: &[&str]) -> CliResult<std::process::Output> {
    installed()?;
    let mut command = system::compose(Path::new(ROOT));
    command
        .args(["exec", "-T", "grund", "/grund"])
        .args(args)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    tokio::time::timeout(Duration::from_secs(300), command.output())
        .await
        .map_err(|_| {
            CliError::new(
                Code::Failed,
                "the dashboard did not answer within 5 minutes",
            )
        })?
        .map_err(|_| {
            CliError::new(Code::Failed, "could not run docker compose")
                .hint("run it as root on the dashboard's computer, with Docker running")
        })
}

fn refused(what: &str, output: &std::process::Output) -> CliError {
    CliError::new(
        Code::Failed,
        format!("the dashboard's {what} exited with {}", output.status),
    )
    .hint("sudo grund server status; sudo docker compose --project-directory /opt/grund logs grund")
}

/// Runs `grund server status`.
pub async fn status() -> CliResult<Output> {
    installed()?;
    let version = system::installed_version(Path::new(ROOT), None)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let settings = std::fs::read_to_string(Path::new(ROOT).join(".env")).unwrap_or_default();
    let address = settings
        .lines()
        .find_map(|line| line.strip_prefix("GRUND_PUBLIC_URL="))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    let mut value = json!({"version": version, "address": address, "configPath": ROOT});
    let local = Api::new("http://127.0.0.1:8080", None)?;
    match local.revision().await {
        Ok(revision) => {
            value["ready"] = json!(true);
            value["revision"] = json!(revision);
        }
        Err(error) => {
            value["ready"] = json!(false);
            value["detail"] = json!(error.message.clone());
        }
    }
    let text = format!(
        "version   {}\naddress   {}\nready     {}\n",
        value["version"]
            .as_str()
            .filter(|v| !v.is_empty())
            .unwrap_or("unknown"),
        value["address"].as_str().unwrap_or_default(),
        if value["ready"] == true {
            format!(
                "yes ({})",
                value["revision"]
                    .as_str()
                    .unwrap_or_default()
                    .chars()
                    .take(12)
                    .collect::<String>()
            )
        } else {
            format!("no: {}", value["detail"].as_str().unwrap_or_default())
        }
    );
    Ok(Output::with_text(value, text))
}

/// Runs `grund server doctor`: the instance's own checks, in its container.
pub async fn doctor() -> CliResult<Output> {
    let output = in_container(&["doctor", "--json", "instance"]).await?;
    let report: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| refused("doctor", &output))?;
    let checks = report["checks"].as_array().cloned().unwrap_or_default();
    let status = report["status"].as_str().unwrap_or("fail").to_string();
    let text = checks
        .iter()
        .map(|c| {
            let mut line = format!(
                "{:4}  {}: {}\n",
                c["status"].as_str().unwrap_or_default(),
                c["name"].as_str().unwrap_or_default(),
                c["detail"].as_str().unwrap_or_default()
            );
            if let Some(fix) = c["fix"].as_str().filter(|f| !f.is_empty()) {
                line.push_str(&format!("      fix: {fix}\n"));
            }
            line
        })
        .collect();
    let failed = status == "fail" || !output.status.success();
    let output = Output::with_text(json!({"status": status, "checks": checks}), text);
    Ok(if failed { output.exit(1) } else { output })
}

/// Runs `grund server setup-link`.
pub async fn setup_link() -> CliResult<Output> {
    let output = in_container(&["setup-link"]).await?;
    if !output.status.success() {
        return Err(refused("setup link", &output));
    }
    let link = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .rev()
        .find(|l| l.starts_with("http"))
        .map(str::to_string)
        .ok_or_else(|| refused("setup link", &output))?;
    Ok(Output::line(json!({"link": link}), "/link"))
}

/// Runs `grund server rollout …`.
pub async fn rollout(action: RolloutAction) -> CliResult<Output> {
    let verb = match action {
        RolloutAction::Status => "status",
        RolloutAction::Pause => "pause",
        RolloutAction::Resume => "resume",
    };
    let output = in_container(&["agent-updates", verb]).await?;
    if !output.status.success() {
        return Err(refused("rollout", &output));
    }
    let state: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| refused("rollout", &output))?;
    let mut value = json!({"paused": state["paused"].as_bool().unwrap_or(false)});
    if let Some(target) = state["target"]["revision"].as_str() {
        value["targetRevision"] = json!(target);
    }
    if let Some(machine) = state["active"]["machine_id"]
        .as_str()
        .or(state["active"]["guest_machine_id"].as_str())
    {
        value["updatingMachineId"] = json!(machine);
    }
    let text = format!(
        "rollout   {}\ntarget    {}\nupdating  {}\n",
        if value["paused"] == true {
            "paused (sudo grund server rollout resume)"
        } else {
            "offering new builds"
        },
        value["targetRevision"]
            .as_str()
            .map(|r| r.chars().take(12).collect::<String>())
            .unwrap_or_else(|| "none yet".into()),
        value["updatingMachineId"].as_str().unwrap_or("no machine")
    );
    Ok(Output::with_text(value, text))
}

/// `grund server install`.
#[derive(Debug, Args)]
pub struct ServerInstallArgs {
    #[arg(
        long,
        help = "DNS name for the dashboard, served over HTTPS; without it, the dashboard is local only"
    )]
    pub domain: Option<String>,
    #[arg(
        long,
        help = "One-time machine setup code; existing identity is preserved"
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
    #[arg(long, help = "Do not install what runs VMs")]
    pub no_vms: bool,
    #[arg(
        long,
        value_name = "FILE",
        help = "Install from a bundle (grund bundle create) instead of downloading; needed offline"
    )]
    pub from_bundle: Option<std::path::PathBuf>,
    #[arg(
        long,
        help = "Show what would happen without downloading or changing this computer"
    )]
    pub dry_run: bool,
    #[arg(long, help = "Do not ask, and show no animated output")]
    pub yes: bool,
    #[arg(long, help = "Show technical failure details")]
    pub verbose: bool,
}

impl ServerInstallArgs {
    /// The installation it stands for.
    pub fn into_install(self) -> InstallArgs {
        InstallArgs {
            global: Global::default(),
            domain: self.domain,
            url: None,
            code: self.code,
            version: self.version,
            channel: self.channel,
            no_vms: self.no_vms,
            from_bundle: self.from_bundle,
            dry_run: self.dry_run,
            yes: self.yes,
            verbose: self.verbose,
        }
    }
}

/// `grund server update`.
#[derive(Debug, Args)]
pub struct ServerUpdateArgs {
    #[arg(long, help = "Exact public release tag")]
    pub version: Option<String>,
    #[arg(
        long,
        value_enum,
        conflicts_with = "version",
        help = "Release channel; defaults to the installed release's channel"
    )]
    pub channel: Option<release::Channel>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Update from a bundle (grund bundle create) instead of downloading; needed offline"
    )]
    pub from_bundle: Option<std::path::PathBuf>,
    #[arg(long, help = "Confirm the downtime")]
    pub yes: bool,
    #[arg(long, help = "Show technical failure details")]
    pub verbose: bool,
    #[arg(
        long,
        help = "Resolve and show the update without downloading or changing anything"
    )]
    pub dry_run: bool,
}

impl ServerUpdateArgs {
    /// The update it stands for.
    pub fn into_update(self) -> UpdateArgs {
        UpdateArgs {
            global: Global::default(),
            version: self.version,
            channel: self.channel,
            yes: self.yes,
            verbose: self.verbose,
            dry_run: self.dry_run,
            from_bundle: self.from_bundle,
            pause: false,
            resume: false,
            server: true,
        }
    }
}

/// `grund server uninstall`.
#[derive(Debug, Args)]
pub struct ServerUninstallArgs {
    #[arg(long, help = "Confirm removing the dashboard's services")]
    pub yes: bool,
    #[arg(long, help = "Show exactly which services would be removed")]
    pub dry_run: bool,
    #[arg(long, help = "Show technical failure details")]
    pub verbose: bool,
}

impl ServerUninstallArgs {
    /// The removal it stands for.
    pub fn into_uninstall(self) -> UninstallArgs {
        UninstallArgs {
            global: Global::default(),
            scope: Scope::Server,
            yes: self.yes,
            dry_run: self.dry_run,
            verbose: self.verbose,
        }
    }
}
