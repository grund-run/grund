//! The `grund` binary. One binary, several roles, chosen by subcommand:
//!
//! - `serve`: the control plane (dashboard, API, background work);
//! - `migrate`: apply database migrations and exit;
//! - `init`: generate a fresh instance's secrets, keeping any that exist;
//! - `setup-link`: print the one-time link that creates a fresh instance's
//!   owner, with no mail (run where `serve` runs, with its settings);
//! - `doctor`: a read-only check of an instance (`doctor instance`, with
//!   `serve`'s settings) or of a machine (`doctor machine`), naming each
//!   problem and its fix; exits 1 when a check fails;
//! - `probe`: exit 0 when an instance's readiness answers 200, for container
//!   health checks (the image has no shell or curl);
//! - `join`: register this machine with an instance, with a one-time setup
//!   code (the machine agent, `grund-agent`);
//! - `agent`: keep it connected, and run the VMs its desired state asks for;
//! - `machine-follow`: inspect or pause this machine's explicit update opt-in;
//! - `agent-updates`: inspect, pause or resume the instance's machine rollout;
//! - `relay`: a relay for an instance's machines, on a host of its own;
//! - `relays`: mint enrollment tokens for relays, revoke and list them;
//! - `edge`: the entry edge, which terminates TLS for app addresses and
//!   hands each connection to a machine's gate;
//! - `edges`: mint enrollment tokens for edges, revoke and list them;
//!
//! The rest are the client commands of `grund-cli` (grund-docs
//! design/cli.md): `login`, `whoami`, `orgs`, `apps`, `machines`, `domains`,
//! `members`, `invitations`, `notifications`, `tokens`, `registries`, and the
//! CLI's self-description, `describe`, `schema`, `skill` and `mcp`. They are
//! what the dashboard does, over the same API.
//!
//! The same role commands are also two binaries of their own:
//! `grund-server` (serve, migrate, init, setup-link, doctor, probe, relay,
//! relay-token, edge, edge-token, rollout) and `grund-agent` (run, join,
//! doctor, follow). Both are built from this crate and parse with the same
//! definitions, so a role behaves the same whichever binary runs it.
//!
//! Official builds are the AGPL core alone. The `ee` feature adds grund's
//! commercial features from `ee/`, which are not licensed for production
//! use yet (`ee/LICENSE`); build with `--features ee` to develop or test
//! them.

mod probe;

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "grund",
    version = grund_cli::VERSION,
    about = "Deploy and run apps on machines you own.",
    args = grund_cli::context::Global::target_arguments()
)]
struct Cli {
    #[command(flatten)]
    telemetry: Telemetry,

    #[command(subcommand)]
    command: Command,
}

/// Logging and trace export, for the roles that run: the server, the
/// agent, a relay and an edge.
#[derive(clap::Args)]
pub struct Telemetry {
    #[arg(long, env = "GRUND_LOG_FORMAT", help = "Log line format. The image sets json", value_parser = ["compact", "json"], default_value = "compact", global = true)]
    pub log_format: String,

    #[arg(
        long,
        env = "RUST_LOG",
        help = "Log filter, in tracing's EnvFilter syntax",
        default_value = "grund=info,grund_server=info,grund_store=info,notmad=info,warn",
        global = true
    )]
    pub log: String,
    #[arg(
        long,
        env = "OTEL_EXPORTER_OTLP_ENDPOINT",
        global = true,
        help = "OTLP HTTP/protobuf collector base URL. Unset: tracing export is off"
    )]
    pub otel_exporter_otlp_endpoint: Option<String>,

    #[arg(
        long,
        env = "OTEL_SERVICE_NAME",
        global = true,
        help = "Service name in exported traces (default: grund, grund-relay or grund-edge)"
    )]
    pub otel_service_name: Option<String>,
}

#[derive(Parser)]
struct ContainerLogsArgs {
    #[arg(long)]
    container_logs: std::path::PathBuf,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        hide = true,
        about = "Run the control plane: dashboard, API and background work"
    )]
    Serve(Box<grund_server::config::ServeConfig>),
    #[command(hide = true, about = "Apply database migrations and exit")]
    Migrate(grund_server::config::DatabaseArgs),
    #[command(
        hide = true,
        about = "Generate the instance secret key and database password, keeping any that exist"
    )]
    Init(grund_server::secrets::InitArgs),
    #[command(
        hide = true,
        name = "setup-link",
        about = "Print a one-time link that creates this instance's owner account. Run it where grund serve runs, with the same settings, before any account exists"
    )]
    SetupLink(Box<grund_server::config::ServeConfig>),
    #[command(hide = true)]
    LocalMachine(Box<grund_server::config::ServeConfig>),
    #[command(hide = true)]
    PrepareLocalMachine(PrepareLocalMachineArgs),
    #[command(
        hide = true,
        about = "Exit 0 when the instance at --address answers 200 on --path, 1 otherwise"
    )]
    Probe(probe::ProbeArgs),
    #[command(
        hide = true,
        about = "Keep this machine connected to its instance and run what it asks for"
    )]
    Agent(AgentCommand),
    #[command(hide = true)]
    AgentSupervisor(grund_agent::supervisor::SupervisorArgs),
    #[command(
        hide = true,
        about = "Inspect, pause or resume this machine's explicitly enabled update following"
    )]
    MachineFollow(grund_agent::supervisor::FollowArgs),
    #[command(
        hide = true,
        about = "Inspect, pause or resume machine updates using the instance's local database"
    )]
    AgentUpdates(AgentUpdatesCommand),
    #[command(
        hide = true,
        about = "Run a relay for an instance's machines: iroh's relay and QUIC address discovery, admitting only the keys the instance does"
    )]
    Relay(grund_server::relay_command::RelayCommand),
    #[command(
        hide = true,
        about = "Mint a one-time enrollment token for a grund relay, revoke a relay, or list them"
    )]
    Relays(grund_server::relays_command::RelaysCommand),
    #[command(
        hide = true,
        about = "Run an entry edge: terminate TLS for app addresses and hand each connection to a machine that runs the app"
    )]
    Edge(grund_server::edge::EdgeCommand),
    #[command(
        hide = true,
        about = "Mint a one-time enrollment token for a grund edge, revoke an edge, or list them"
    )]
    Edges(grund_server::relays_command::EdgesCommand),
    #[command(flatten)]
    Client(grund_cli::Command),
}

#[derive(clap::Args)]
struct AgentUpdatesCommand {
    #[command(flatten)]
    database: grund_server::config::DatabaseArgs,
    #[command(subcommand)]
    action: AgentUpdatesAction,
}

#[derive(Subcommand)]
enum AgentUpdatesAction {
    Status,
    Pause,
    Resume,
}

async fn agent_updates(command: AgentUpdatesCommand) -> anyhow::Result<()> {
    use std::io::Write;

    use grund_server::services::agent_updates::{pause, resume, status};

    let state = match command.action {
        AgentUpdatesAction::Status => status(&command.database).await?,
        AgentUpdatesAction::Pause => pause(&command.database).await?,
        AgentUpdatesAction::Resume => resume(&command.database).await?,
    };
    let mut output = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, &state)?;
    output.write_all(b"\n")?;
    Ok(())
}

enum DoctorTarget {
    Instance(Box<grund_server::config::ServeConfig>),
    Machine(grund_agent::doctor::MachineArgs),
}

async fn doctor(json: bool, target: DoctorTarget) -> anyhow::Result<()> {
    let report = match target {
        DoctorTarget::Instance(config) => grund_server::doctor::run(*config).await,
        DoctorTarget::Machine(args) => {
            grund_agent::doctor::run(
                &args,
                grund_vm::doctor::checks(),
                grund_server::health::revision(),
            )
            .await
        }
    };
    if json {
        println!("{}", report.json());
    } else {
        print!("{}", report.text());
    }
    if report.failed() {
        std::process::exit(1);
    }
    Ok(())
}

#[derive(clap::Args)]
struct PrepareLocalMachineArgs {
    #[arg(
        long,
        env = "GRUND_AGENT_DATA_DIR",
        default_value = "/var/lib/grund/agent"
    )]
    data_dir: std::path::PathBuf,
}

#[derive(clap::Args)]
struct AgentCommand {
    #[command(flatten)]
    agent: grund_agent::agent::AgentArgs,

    #[arg(long, env = "GRUND_APP_RUNTIME", value_parser = ["containerd", "none", "simulated"], default_value = "containerd", help = "What runs apps' containers: containerd (grund's own, fetched and pinned the first time a replica runs; needs root and cgroup v2), none, or simulated (nothing runs; for tests and demos)")]
    app_runtime: String,

    #[arg(long, env = "GRUND_VM_RUNTIME", value_parser = ["none", "simulated", "firecracker"], default_value = "none", help = "What runs VMs: none, firecracker (microVMs, needs /dev/kvm), or simulated (each VM is `grund join` run with its metadata; for tests and demos)")]
    vm_runtime: String,

    #[arg(
        long,
        env = "GRUND_VM_FIRECRACKER",
        default_value = "firecracker",
        help = "The Firecracker binary, for --vm-runtime firecracker"
    )]
    vm_firecracker: std::path::PathBuf,

    #[arg(
        long,
        env = "GRUND_VM_JAILER",
        default_value = "jailer",
        help = "Firecracker's jailer, from the same release, for bridged VMs"
    )]
    vm_jailer: std::path::PathBuf,

    #[arg(long, env = "GRUND_VM_NETWORK", value_parser = ["auto", "bridged", "isolated"], default_value = "auto", help = "How VMs are networked: bridged (egress through grund's bridge and NAT; needs root), isolated (metadata only), or auto (bridged when root)")]
    vm_network: String,

    #[arg(
        long,
        env = "GRUND_VM_VCPUS",
        help = "vCPUs all VMs may use together. Default: all CPUs but one"
    )]
    vm_vcpus: Option<u32>,

    #[arg(
        long,
        env = "GRUND_VM_MEMORY_MIB",
        help = "Memory all VMs may use together, MiB. Default: half the host's"
    )]
    vm_memory_mib: Option<u32>,

    #[arg(
        long,
        env = "GRUND_VM_DISK_GIB",
        help = "Disk all VMs may use together, GiB. Default: 20"
    )]
    vm_disk_gib: Option<u32>,
}

fn firecracker(command: &AgentCommand) -> anyhow::Result<grund_vm::Firecracker> {
    let host = grund_vm::Budget::of_host();
    let root = grund_vm::running_as_root();
    let network = match (command.vm_network.as_str(), root) {
        ("isolated", _) | ("auto", false) => grund_vm::Network::Isolated,
        ("bridged", false) => anyhow::bail!(
            "--vm-network bridged needs root: it sets up grund's bridge and NAT (GRUND_VM_NETWORK)"
        ),
        _ => grund_vm::Network::Bridged,
    };
    grund_vm::Firecracker::new(grund_vm::Config {
        data_dir: command.agent.data_dir.join("vm"),
        firecracker: command.vm_firecracker.clone(),
        jailer: Some(command.vm_jailer.clone()),
        network,
        budget: grund_vm::Budget {
            vcpus: command.vm_vcpus.unwrap_or(host.vcpus),
            memory_mib: command.vm_memory_mib.unwrap_or(host.memory_mib),
            disk_gib: command.vm_disk_gib.unwrap_or(host.disk_gib),
        },
    })
}

async fn agent<R: grund_agent::vm::VmRuntime>(
    command: &AgentCommand,
    vms: R,
) -> anyhow::Result<()> {
    match command.app_runtime.as_str() {
        "simulated" => {
            let dir = command.agent.data_dir.join("simulated-containers");
            grund_agent::agent::run(
                &command.agent,
                vms,
                grund_agent::simulated::SimulatedContainers::new(dir),
            )
            .await
        }
        "containerd" => {
            grund_agent::agent::run(
                &command.agent,
                vms,
                grund_containers::Containerd::new(grund_containers::Config::default()),
            )
            .await
        }
        _ => grund_agent::agent::run(&command.agent, vms, grund_agent::runtime::NoContainers).await,
    }
}

#[derive(Parser)]
#[command(
    name = "grund-server",
    version = grund_cli::VERSION,
    about = "Run a grund instance, relay or edge"
)]
struct ServerCli {
    #[command(flatten)]
    telemetry: Telemetry,

    #[command(subcommand)]
    command: ServerCommand,
}

#[derive(Subcommand)]
enum ServerCommand {
    #[command(about = "Run the instance: dashboard, API and background work")]
    Serve(Box<grund_server::config::ServeConfig>),
    #[command(about = "Apply database migrations and exit")]
    Migrate(grund_server::config::DatabaseArgs),
    #[command(
        about = "Generate the instance secret key and database password, keeping any that exist"
    )]
    Init(grund_server::secrets::InitArgs),
    #[command(
        name = "setup-link",
        about = "Print a one-time link that creates this instance's owner account. Run it where the instance runs, with the same settings, before any account exists"
    )]
    SetupLink(Box<grund_server::config::ServeConfig>),
    #[command(hide = true)]
    LocalMachine(Box<grund_server::config::ServeConfig>),
    #[command(
        about = "Check the instance, with serve's settings, without changing it. Exits 1 when a check fails"
    )]
    Doctor(ServerDoctorArgs),
    #[command(about = "Exit 0 when the instance at --address answers 200 on --path, 1 otherwise")]
    Probe(probe::ProbeArgs),
    #[command(
        about = "Run a relay for an instance's machines: iroh's relay and QUIC address discovery, admitting only the keys the instance does"
    )]
    Relay(grund_server::relay_command::RelayCommand),
    #[command(
        name = "relay-token",
        about = "Mint a one-time enrollment token for a relay, revoke a relay, or list them"
    )]
    RelayToken(grund_server::relays_command::RelaysCommand),
    #[command(
        about = "Run an entry edge: terminate TLS for app addresses and hand each connection to a machine that runs the app"
    )]
    Edge(grund_server::edge::EdgeCommand),
    #[command(
        name = "edge-token",
        about = "Mint a one-time enrollment token for an edge, revoke an edge, or list them"
    )]
    EdgeToken(grund_server::relays_command::EdgesCommand),
    #[command(about = "Inspect, pause or resume the instance's machine update rollout")]
    Rollout(AgentUpdatesCommand),
}

#[derive(clap::Args)]
struct ServerDoctorArgs {
    #[arg(long, help = "Print one JSON document instead of one line per check")]
    json: bool,

    #[command(flatten)]
    config: Box<grund_server::config::ServeConfig>,
}

#[derive(Parser)]
#[command(
    name = "grund-agent",
    version = grund_cli::VERSION,
    about = "Run apps on this machine for its grund instance"
)]
struct AgentCli {
    #[command(flatten)]
    telemetry: Telemetry,

    #[command(subcommand)]
    command: AgentRole,
}

#[derive(Subcommand)]
enum AgentRole {
    #[command(about = "Keep this machine connected to its instance and run what it asks for")]
    Run(AgentCommand),
    #[command(about = "Register this machine with a grund instance, using a one-time setup code")]
    Join(grund_agent::join::JoinArgs),
    #[command(
        about = "Check this machine without changing it: prerequisites, the agent, its instance and the clock. As root, to answer every check. Exits 1 when a check fails"
    )]
    Doctor(AgentDoctorArgs),
    #[command(
        about = "Inspect, pause or resume this machine's explicitly enabled update following"
    )]
    Follow(grund_agent::supervisor::FollowArgs),
    #[command(about = "This machine as its files say: identity, last contact, following, update")]
    Status(grund_agent::status::StatusArgs),
    #[command(hide = true, alias = "agent-supervisor")]
    Supervisor(grund_agent::supervisor::SupervisorArgs),
    #[command(hide = true)]
    PrepareLocalMachine(PrepareLocalMachineArgs),
}

#[derive(clap::Args)]
struct AgentDoctorArgs {
    #[arg(long, help = "Print one JSON document instead of one line per check")]
    json: bool,

    #[command(flatten)]
    machine: grund_agent::doctor::MachineArgs,
}

enum Role {
    Server(ServerCommand),
    Agent(AgentRole),
}

impl Command {
    fn role(self) -> Result<Role, Box<grund_cli::Command>> {
        use Role::{Agent, Server};
        Ok(match self {
            Command::Serve(config) => Server(ServerCommand::Serve(config)),
            Command::Migrate(args) => Server(ServerCommand::Migrate(args)),
            Command::Init(args) => Server(ServerCommand::Init(args)),
            Command::SetupLink(config) => Server(ServerCommand::SetupLink(config)),
            Command::LocalMachine(config) => Server(ServerCommand::LocalMachine(config)),
            Command::PrepareLocalMachine(args) => Agent(AgentRole::PrepareLocalMachine(args)),
            Command::Probe(args) => Server(ServerCommand::Probe(args)),
            Command::Agent(command) => Agent(AgentRole::Run(command)),
            Command::AgentSupervisor(args) => Agent(AgentRole::Supervisor(args)),
            Command::MachineFollow(args) => Agent(AgentRole::Follow(args)),
            Command::AgentUpdates(command) => Server(ServerCommand::Rollout(command)),
            Command::Relay(command) => Server(ServerCommand::Relay(command)),
            Command::Relays(command) => Server(ServerCommand::RelayToken(command)),
            Command::Edge(command) => Server(ServerCommand::Edge(command)),
            Command::Edges(command) => Server(ServerCommand::EdgeToken(command)),
            Command::Client(command) => return Err(Box::new(command)),
        })
    }
}

/// The public command tree for a binary that adds optional commands, with
/// grouped help.
pub fn command() -> clap::Command {
    let root = [
        "log_format",
        "log",
        "otel_exporter_otlp_endpoint",
        "otel_service_name",
    ]
    .into_iter()
    .fold(Cli::command(), |root, id| {
        root.mut_arg(id, |arg| arg.hide(true))
    });
    grund_cli::help::with_grouped_help(root)
}

fn identify(revision: &'static str, built: &'static str) {
    grund_server::health::set_revision(revision);
    grund_server::health::set_build_time(built);
    grund_server::health::set_package(grund_cli::VERSION);
    grund_crypto::install_default();
}

fn container_logs(args: &[String]) -> Option<anyhow::Result<()>> {
    if !args.get(1).is_some_and(|arg| arg == "--container-logs") {
        return None;
    }
    Some(
        ContainerLogsArgs::try_parse_from(args)
            .map_err(anyhow::Error::from)
            .and_then(|capture| grund_agent::capture::run(&capture.container_logs)),
    )
}

#[derive(Debug, PartialEq, Eq)]
enum Invoked {
    Server,
    Agent,
}

fn invoked_as(args: &[String]) -> Option<Invoked> {
    let name = std::path::Path::new(args.first()?).file_name()?.to_str()?;
    match name {
        "grund-server" => Some(Invoked::Server),
        "grund-agent" => Some(Invoked::Agent),
        _ => None,
    }
}

fn runtime_doctor(args: &[String]) -> Option<(Invoked, Vec<String>)> {
    if args.get(1).is_none_or(|a| a != "doctor") {
        return None;
    }
    let (index, invoked) = args
        .iter()
        .enumerate()
        .skip(2)
        .find_map(|(i, a)| match a.as_str() {
            "instance" => Some((i, Invoked::Server)),
            "machine" => Some((i, Invoked::Agent)),
            _ => None,
        })?;
    let mut rewritten = args.to_vec();
    rewritten.remove(index);
    rewritten[0] = match invoked {
        Invoked::Server => "grund-server",
        Invoked::Agent => "grund-agent",
    }
    .to_string();
    Some((invoked, rewritten))
}

fn runtime_join(args: &[String]) -> bool {
    args.get(1).is_some_and(|a| a == "join")
        && args.iter().skip(2).any(|a| {
            ["--url", "--mmds", "--mmds-address", "--data-dir", "--name"]
                .iter()
                .any(|flag| a == flag || a.starts_with(&format!("{flag}=")))
        })
}

/// Runs the common grund binary with extensions supplied by this build. Run
/// by the name `grund-server` or `grund-agent` (a link to it), it is that
/// binary: it parses and runs that role's commands only.
pub async fn run_with_extensions(
    extensions_for: impl FnOnce(
        &grund_server::config::ServeConfig,
    ) -> anyhow::Result<
        Vec<std::sync::Arc<dyn grund_server::extension::Extension>>,
    >,
    revision: &'static str,
    built: &'static str,
) -> anyhow::Result<()> {
    identify(revision, built);
    let args: Vec<String> = std::env::args().collect();
    if let Some(result) = container_logs(&args) {
        return result;
    }
    if let Some((invoked, args)) = runtime_doctor(&args) {
        return match invoked {
            Invoked::Server => {
                let cli = ServerCli::parse_from(&args);
                run_role(Role::Server(cli.command), &cli.telemetry, extensions_for).await
            }
            Invoked::Agent => {
                let cli = AgentCli::parse_from(&args);
                run_role(Role::Agent(cli.command), &cli.telemetry, extensions_for).await
            }
        };
    }
    if runtime_join(&args) {
        let mut args = args;
        args[0] = "grund-agent".to_string();
        let cli = AgentCli::parse_from(&args);
        return run_role(Role::Agent(cli.command), &cli.telemetry, extensions_for).await;
    }
    match invoked_as(&args) {
        Some(Invoked::Server) => {
            let cli = ServerCli::parse_from(&args);
            return run_role(Role::Server(cli.command), &cli.telemetry, extensions_for).await;
        }
        Some(Invoked::Agent) => {
            let cli = AgentCli::parse_from(&args);
            return run_role(Role::Agent(cli.command), &cli.telemetry, extensions_for).await;
        }
        None => {}
    }
    let mut args = args;
    let original = args.len();
    let cli = loop {
        let parsed = command()
            .try_get_matches_from(&args)
            .and_then(|matches| <Cli as clap::FromArgMatches>::from_arg_matches(&matches));
        match parsed {
            Ok(cli) => break cli,
            Err(error) => {
                if args.len() < original + 3
                    && let Some(completed) = grund_cli::attended::complete(&args, &error).await
                {
                    args = completed;
                    continue;
                }
                match grund_cli::usage_error(&error, &args) {
                    Some(status) => std::process::exit(status),
                    None => error.exit(),
                }
            }
        }
    };
    if args.len() > original {
        grund_cli::attended::ran(&args);
    }
    match cli.command.role() {
        Ok(role) => run_role(role, &cli.telemetry, extensions_for).await,
        Err(client) => {
            let status = grund_cli::run(*client, command(), revision).await;
            std::process::exit(status);
        }
    }
}

/// Runs `grund-server` with extensions supplied by this build.
pub async fn run_server_with_extensions(
    extensions_for: impl FnOnce(
        &grund_server::config::ServeConfig,
    ) -> anyhow::Result<
        Vec<std::sync::Arc<dyn grund_server::extension::Extension>>,
    >,
    revision: &'static str,
    built: &'static str,
) -> anyhow::Result<()> {
    identify(revision, built);
    let cli = ServerCli::parse();
    run_role(Role::Server(cli.command), &cli.telemetry, extensions_for).await
}

/// Runs `grund-agent`.
pub async fn run_agent(revision: &'static str, built: &'static str) -> anyhow::Result<()> {
    identify(revision, built);
    let args: Vec<String> = std::env::args().collect();
    if let Some(result) = container_logs(&args) {
        return result;
    }
    let cli = AgentCli::parse_from(&args);
    run_role(Role::Agent(cli.command), &cli.telemetry, |_| Ok(Vec::new())).await
}

async fn run_role(
    role: Role,
    telemetry: &Telemetry,
    extensions_for: impl FnOnce(
        &grund_server::config::ServeConfig,
    ) -> anyhow::Result<
        Vec<std::sync::Arc<dyn grund_server::extension::Extension>>,
    >,
) -> anyhow::Result<()> {
    let to_stderr = matches!(
        role,
        Role::Server(
            ServerCommand::Doctor(_)
                | ServerCommand::SetupLink(_)
                | ServerCommand::LocalMachine(_)
                | ServerCommand::Rollout(_)
        ) | Role::Agent(
            AgentRole::Doctor(_)
                | AgentRole::PrepareLocalMachine(_)
                | AgentRole::Follow(_)
                | AgentRole::Status(_)
        )
    );
    let service = match &role {
        Role::Server(ServerCommand::Serve(_)) => Some("grund"),
        Role::Server(ServerCommand::Relay(_)) => Some("grund-relay"),
        Role::Server(ServerCommand::Edge(_)) => Some("grund-edge"),
        _ => None,
    };
    let provider = grund_server::telemetry::init(
        &telemetry.log,
        telemetry.log_format == "json",
        to_stderr,
        service.and(telemetry.otel_exporter_otlp_endpoint.as_deref()),
        telemetry.otel_service_name.as_deref(),
        service.unwrap_or("grund"),
    )?;
    let result = match role {
        Role::Server(command) => serve_role(command, extensions_for).await,
        Role::Agent(command) => agent_role(command).await,
    };
    if let Some(provider) = provider {
        match tokio::task::spawn_blocking(move || provider.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "OTLP trace export did not finish"),
            Err(error) => tracing::warn!(%error, "OTLP trace exporter could not shut down"),
        }
    }
    result
}

async fn serve_role(
    command: ServerCommand,
    extensions_for: impl FnOnce(
        &grund_server::config::ServeConfig,
    ) -> anyhow::Result<
        Vec<std::sync::Arc<dyn grund_server::extension::Extension>>,
    >,
) -> anyhow::Result<()> {
    match command {
        ServerCommand::Serve(mut config) => {
            config.validate()?;
            let extensions = extensions_for(&config)?;
            grund_server::serve(*config, extensions).await
        }
        ServerCommand::Migrate(args) => grund_server::migrate(args).await,
        ServerCommand::Init(args) => grund_server::secrets::init(&args),
        ServerCommand::SetupLink(config) => grund_server::setup_link::run(*config).await,
        ServerCommand::LocalMachine(config) => {
            match grund_server::local_machine::run(*config).await {
                Err(error)
                    if error
                        .downcast_ref::<grund_server::local_machine::Refused>()
                        .is_some() =>
                {
                    eprintln!(
                        "Local machine setup refused; inspect the saved installation identity."
                    );
                    std::process::exit(78);
                }
                result => result,
            }
        }
        ServerCommand::Doctor(args) => doctor(args.json, DoctorTarget::Instance(args.config)).await,
        ServerCommand::Probe(args) => probe::run(&args),
        ServerCommand::Relay(command) => grund_server::relay_command::run(command).await,
        ServerCommand::RelayToken(command) => grund_server::relays_command::run(command).await,
        ServerCommand::Edge(command) => grund_server::edge::run(command).await,
        ServerCommand::EdgeToken(command) => grund_server::relays_command::run_edges(command).await,
        ServerCommand::Rollout(command) => agent_updates(command).await,
    }
}

async fn agent_role(command: AgentRole) -> anyhow::Result<()> {
    match command {
        AgentRole::PrepareLocalMachine(args) => {
            let identity = grund_agent::local_bootstrap::prepare(&args.data_dir)?;
            println!("{}", serde_json::to_string(&identity)?);
            Ok(())
        }
        AgentRole::Doctor(args) => doctor(args.json, DoctorTarget::Machine(args.machine)).await,
        AgentRole::Join(args) => grund_agent::join::run(&args).await,
        AgentRole::Supervisor(args) => grund_agent::supervisor::run(&args).await,
        AgentRole::Follow(args) => grund_agent::supervisor::policy(&args),
        AgentRole::Status(args) => {
            grund_agent::status::run(&args, grund_server::health::revision())
        }
        AgentRole::Run(command) => {
            grund_agent::local_bootstrap::complete_pending(&command.agent.data_dir).await?;
            match command.vm_runtime.as_str() {
                "simulated" => {
                    let dir = command.agent.data_dir.join("simulated-vms");
                    agent(&command, grund_agent::vm::SimulatedVms::new(dir)).await
                }
                "firecracker" => agent(&command, firecracker(&command)?).await,
                _ => agent(&command, grund_agent::vm::NoVms).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_definitions_are_internally_consistent() {
        Cli::command().debug_assert();
        ServerCli::command().debug_assert();
        AgentCli::command().debug_assert();
    }

    #[test]
    fn the_combined_binary_takes_the_role_of_the_name_it_was_run_by() {
        let run = |name: &str| invoked_as(&[name.to_string(), "serve".to_string()]);
        assert_eq!(run("/grund-server"), Some(Invoked::Server));
        assert_eq!(run("/usr/local/bin/grund-agent"), Some(Invoked::Agent));
        assert_eq!(run("/grund"), None);
        assert_eq!(run("grund-server-old"), None);
    }

    #[test]
    fn the_older_doctor_targets_still_reach_the_role_doctors() {
        let words = |line: &str| line.split(' ').map(str::to_string).collect::<Vec<_>>();
        let (invoked, args) = runtime_doctor(&words("/grund doctor --json instance")).unwrap();
        assert_eq!(invoked, Invoked::Server);
        assert_eq!(args, words("grund-server doctor --json"));
        assert!(matches!(
            ServerCli::try_parse_from(&args).unwrap().command,
            ServerCommand::Doctor(_)
        ));
        let (invoked, args) = runtime_doctor(&words("grund doctor machine --json")).unwrap();
        assert_eq!(invoked, Invoked::Agent);
        assert!(matches!(
            AgentCli::try_parse_from(&args).unwrap().command,
            AgentRole::Doctor(_)
        ));
        assert!(runtime_doctor(&words("grund doctor --json")).is_none());
        assert!(runtime_doctor(&words("grund app show machine")).is_none());
    }

    #[test]
    fn a_join_with_the_agents_flags_still_reaches_the_agents_join() {
        let words = |line: &str| line.split(' ').map(str::to_string).collect::<Vec<_>>();
        assert!(runtime_join(&words("grund join --mmds")));
        assert!(runtime_join(&words(
            "grund join --url https://grund.example.com --data-dir /var/lib/grund/agent --name box CODE"
        )));
        assert!(runtime_join(&words(
            "grund join --url=https://grund.example.com CODE"
        )));
        assert!(!runtime_join(&words(
            "grund join https://grund.example.com --code CODE"
        )));
        assert!(!runtime_join(&words("grund app list --name x")));
        let mut args = words("grund-agent join --mmds");
        args[0] = "grund-agent".into();
        assert!(matches!(
            AgentCli::try_parse_from(&args).unwrap().command,
            AgentRole::Join(_)
        ));
    }

    #[test]
    fn the_supervisor_answers_to_the_name_older_updaters_call_it_by() {
        let cli =
            AgentCli::try_parse_from(["grund-agent", "agent-supervisor", "--identity"]).unwrap();
        assert!(matches!(cli.command, AgentRole::Supervisor(args) if args.identity));
    }

    #[test]
    fn the_combined_binary_runs_each_role_command_as_its_own_binary_would() {
        let cli = Cli::try_parse_from(["grund", "relays", "list"]).unwrap();
        assert!(matches!(
            cli.command.role(),
            Ok(Role::Server(ServerCommand::RelayToken(_)))
        ));
        let cli = Cli::try_parse_from(["grund", "app", "list"]).unwrap();
        assert!(cli.command.role().is_err());
    }

    #[test]
    fn an_unknown_subcommand_is_an_error_not_a_server() {
        assert!(Cli::try_parse_from(["grund", "serv"]).is_err());
    }
}
