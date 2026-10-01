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
//! - `apps`: suspend an app's address, or lift its suspension.
//!
//! The agent is part of this binary, so there is one artifact to build, sign
//! and ship.
//!
//! Official builds are the AGPL core alone. The `ee` feature adds grund's
//! commercial features from `ee/`, which are not licensed for production
//! use yet (`ee/LICENSE`); build with `--features ee` to develop or test
//! them.

mod probe;

use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(
    name = "grund",
    version,
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
    #[command(about = "Suspend an app's address, or lift its suspension")]
    Apps(grund_server::apps_command::AppsCommand),
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    grund_server::health::set_revision(env!("GRUND_BUILD_REVISION"));
    grund_tls::install_default();
    let cli = Cli::parse();
    let to_stderr = matches!(cli.command, Command::Doctor(_) | Command::SetupLink(_));
    init_tracing(&cli, to_stderr);
    match cli.command {
        Command::Serve(mut config) => {
            config.validate()?;
            #[cfg(feature = "ee")]
            let extensions = grund_ee::extensions(&config)?;
            #[cfg(not(feature = "ee"))]
            let extensions = Vec::new();
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
        Command::Apps(command) => grund_server::apps_command::run(command).await,
        Command::Agent(command) => match command.vm_runtime.as_str() {
            "simulated" => {
                let dir = command.agent.data_dir.join("simulated-vms");
                agent(&command, grund_agent::vm::SimulatedVms::new(dir)).await
            }
            "firecracker" => agent(&command, firecracker(&command)?).await,
            _ => agent(&command, grund_agent::vm::NoVms).await,
        },
    }
}

fn init_tracing(cli: &Cli, to_stderr: bool) {
    let filter = EnvFilter::try_new(&cli.log).unwrap_or_else(|_| EnvFilter::new("grund=info,warn"));
    let registry = tracing_subscriber::registry().with(filter);
    let writer = move || -> Box<dyn std::io::Write> {
        if to_stderr {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        }
    };
    if cli.log_format == "json" {
        registry
            .with(fmt::layer().json().with_writer(writer))
            .init();
    } else {
        registry
            .with(fmt::layer().compact().with_writer(writer))
            .init();
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_command_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn an_unknown_subcommand_is_an_error_not_a_server() {
        assert!(Cli::try_parse_from(["grund", "serv"]).is_err());
    }
}
