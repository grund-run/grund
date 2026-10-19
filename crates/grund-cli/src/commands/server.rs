//! `grund server`: the self-hosted dashboard on this computer, run with
//! Docker Compose and the grund-server image (grund-docs
//! design/cli-redesign.md §5). It drives the server; it never links it.

use clap::{Args, Subcommand};

use crate::{
    commands::{
        Noun,
        system::{InstallArgs, Scope, UninstallArgs, release},
        system_update::UpdateArgs,
    },
    context::Global,
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
