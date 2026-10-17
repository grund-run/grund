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
//! The agent is part of this binary, so there is one artifact to build, sign
//! and ship.
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
    about = "grund: from zero to production, on your own premises"
)]
struct Cli {
    #[arg(long, env = "GRUND_LOG_FORMAT", help = "Log line format. The image sets json", value_parser = ["compact", "json"], default_value = "compact", global = true)]
    log_format: String,

    #[arg(
        long,
        env = "RUST_LOG",
        help = "Log filter, in tracing's EnvFilter syntax",
        default_value = "grund=info,grund_server=info,grund_store=info,notmad=info,warn",
        global = true
    )]
    log: String,
    #[arg(
        long,
        env = "OTEL_EXPORTER_OTLP_ENDPOINT",
        global = true,
        help = "OTLP HTTP/protobuf collector base URL. Unset: tracing export is off"
    )]
    otel_exporter_otlp_endpoint: Option<String>,

    #[arg(
        long,
        env = "OTEL_SERVICE_NAME",
        global = true,
        help = "Service name in exported traces (default: grund, grund-relay or grund-edge)"
    )]
    otel_service_name: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Run the control plane: dashboard, API and background work")]
    Serve(Box<grund_server::config::ServeConfig>),
    #[command(about = "Apply database migrations and exit")]
    Migrate(grund_server::config::DatabaseArgs),
    #[command(
        about = "Generate the instance secret key and database password, keeping any that exist"
    )]
    Init(grund_server::secrets::InitArgs),
    #[command(
        name = "setup-link",
        about = "Print a one-time link that creates this instance's owner account. Run it where grund serve runs, with the same settings, before any account exists"
    )]
    SetupLink(Box<grund_server::config::ServeConfig>),
    #[command(
        about = "Check this instance or machine without changing it: each problem and what to do. Exits 1 when a check fails"
    )]
    Doctor(DoctorCommand),
    #[command(about = "Exit 0 when the instance at --address answers 200 on --path, 1 otherwise")]
    Probe(probe::ProbeArgs),
    #[command(about = "Register this machine with a grund instance, using a one-time setup code")]
    Join(grund_agent::join::JoinArgs),
    #[command(about = "Keep this machine connected to its instance and run what it asks for")]
    Agent(AgentCommand),
    #[command(
        about = "Run a relay for an instance's machines: iroh's relay and QUIC address discovery, admitting only the keys the instance does"
    )]
    Relay(grund_server::relay_command::RelayCommand),
    #[command(
        about = "Mint a one-time enrollment token for a grund relay, revoke a relay, or list them"
    )]
    Relays(grund_server::relays_command::RelaysCommand),
    #[command(
        about = "Run an entry edge: terminate TLS for app addresses and hand each connection to a machine that runs the app"
    )]
    Edge(grund_server::edge::EdgeCommand),
    #[command(
        about = "Mint a one-time enrollment token for a grund edge, revoke an edge, or list them"
    )]
    Edges(grund_server::relays_command::EdgesCommand),
    #[command(flatten)]
    Client(grund_cli::Command),
}

#[derive(clap::Args)]
struct DoctorCommand {
    #[arg(
        long,
        global = true,
        help = "Print one JSON document instead of one line per check"
    )]
    json: bool,

    #[command(subcommand)]
    target: DoctorTarget,
}

#[derive(Subcommand)]
enum DoctorTarget {
    #[command(
        about = "The instance: run where grund serve runs, with its settings (docker compose exec grund /grund doctor instance)"
    )]
    Instance(Box<grund_server::config::ServeConfig>),
    #[command(
        about = "This machine, for grund's agent: prerequisites, the agent, its instance and the clock. As root, to answer every check"
    )]
    Machine(grund_agent::doctor::MachineArgs),
}

async fn doctor(command: DoctorCommand) -> anyhow::Result<()> {
    let report = match command.target {
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
    if command.json {
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

/// The public command tree for a binary that adds optional commands.
pub fn command() -> clap::Command {
    Cli::command()
}

/// Runs the common grund binary with extensions supplied by this build.
pub async fn run_with_extensions(
    extensions_for: impl FnOnce(
        &grund_server::config::ServeConfig,
    ) -> anyhow::Result<
        Vec<std::sync::Arc<dyn grund_server::extension::Extension>>,
    >,
    revision: &'static str,
    built: &'static str,
) -> anyhow::Result<()> {
    grund_server::health::set_revision(revision);
    grund_server::health::set_build_time(built);
    grund_crypto::install_default();
    let args: Vec<String> = std::env::args().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) => match grund_cli::usage_error(&error, &args) {
            Some(status) => std::process::exit(status),
            None => error.exit(),
        },
    };
    if let Command::Client(command) = cli.command {
        let status = grund_cli::run(command, Cli::command(), revision).await;
        std::process::exit(status);
    }
    let to_stderr = matches!(cli.command, Command::Doctor(_) | Command::SetupLink(_));
    let service = match &cli.command {
        Command::Serve(_) => Some("grund"),
        Command::Relay(_) => Some("grund-relay"),
        Command::Edge(_) => Some("grund-edge"),
        _ => None,
    };
    let provider = grund_server::telemetry::init(
        &cli.log,
        cli.log_format == "json",
        to_stderr,
        service.and(cli.otel_exporter_otlp_endpoint.as_deref()),
        cli.otel_service_name.as_deref(),
        service.unwrap_or("grund"),
    )?;
    let result = match cli.command {
        Command::Serve(mut config) => {
            config.validate()?;
            let extensions = extensions_for(&config)?;
            grund_server::serve(*config, extensions).await
        }
        Command::Migrate(args) => grund_server::migrate(args).await,
        Command::Init(args) => grund_server::secrets::init(&args),
        Command::SetupLink(config) => grund_server::setup_link::run(*config).await,
        Command::Probe(args) => probe::run(&args),
        Command::Doctor(command) => doctor(command).await,
        Command::Join(args) => grund_agent::join::run(&args).await,
        Command::Relay(command) => grund_server::relay_command::run(command).await,
        Command::Relays(command) => grund_server::relays_command::run(command).await,
        Command::Edge(command) => grund_server::edge::run(command).await,
        Command::Edges(command) => grund_server::relays_command::run_edges(command).await,
        Command::Client(_) => unreachable!("client commands returned above"),
        Command::Agent(command) => match command.vm_runtime.as_str() {
            "simulated" => {
                let dir = command.agent.data_dir.join("simulated-vms");
                agent(&command, grund_agent::vm::SimulatedVms::new(dir)).await
            }
            "firecracker" => agent(&command, firecracker(&command)?).await,
            _ => agent(&command, grund_agent::vm::NoVms).await,
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_procedure_a_person_or_a_token_can_call_has_a_cli_command_or_a_reason() {
        use grund_server::api::{AUTHORIZATION, Requirement};
        let reachable: Vec<&str> = AUTHORIZATION
            .iter()
            .filter(|(_, r)| {
                matches!(
                    r,
                    Requirement::Session
                        | Requirement::SessionOrToken
                        | Requirement::SessionOrFullToken
                        | Requirement::Public
                )
            })
            .map(|(p, _)| p.trim_start_matches('/'))
            .collect();
        for rpc in &reachable {
            let called = grund_cli::meta::uses(rpc);
            let excused = grund_cli::meta::NOT_IN_CLI.iter().any(|(p, _)| p == rpc);
            assert!(
                called != excused,
                "{rpc}: give it a CLI command, or a reason in meta::NOT_IN_CLI (not both)"
            );
        }
        for (rpc, why) in grund_cli::meta::NOT_IN_CLI {
            assert!(
                reachable.contains(rpc),
                "meta::NOT_IN_CLI names {rpc}, which no one can call"
            );
            assert!(!why.is_empty(), "{rpc}");
        }
        for leaf in grund_cli::meta::LEAVES {
            for rpc in leaf.rpcs {
                assert!(
                    reachable.contains(rpc),
                    "grund {} calls {rpc}, which is not in api::AUTHORIZATION",
                    leaf.path
                );
            }
        }
    }

    #[test]
    fn describe_json_is_the_one_in_the_repository() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schema/cli.json");
        let document = grund_cli::describe::document(&Cli::command(), &[]);
        let text = format!("{}\n", serde_json::to_string_pretty(&document).unwrap());
        if std::env::var_os("GRUND_WRITE_SCHEMA").is_some() {
            std::fs::write(path, &text).unwrap();
        }
        let stored = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            stored == text,
            "schema/cli.json is not what grund describe --json prints; regenerate it with \
             GRUND_WRITE_SCHEMA=1 cargo test -p grund describe_json"
        );
    }

    #[test]
    fn an_unknown_subcommand_is_an_error_not_a_server() {
        assert!(Cli::try_parse_from(["grund", "serv"]).is_err());
    }
}
