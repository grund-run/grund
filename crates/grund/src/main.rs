//! The `grund` binary. One binary, several roles, chosen by subcommand:
//!
//! - `serve`: the control plane (dashboard, API, background work);
//! - `migrate`: apply database migrations and exit;
//! - `init`: generate a fresh instance's secrets, keeping any that exist;
//! - `probe`: exit 0 when an instance's readiness answers 200, for container
//!   health checks (the image has no shell or curl);
//! - `join`: register this machine with an instance, with a one-time setup
//!   code (the machine agent, `grund-agent`);
//! - `agent`: keep it connected, and run the VMs its desired state asks for.
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
    #[command(about = "Exit 0 when the instance at --address answers 200 on --path, 1 otherwise")]
    Probe(probe::ProbeArgs),
    #[command(about = "Register this machine with a grund instance, using a one-time setup code")]
    Join(grund_agent::join::JoinArgs),
    #[command(about = "Keep this machine connected to its instance and run what it asks for")]
    Agent(AgentCommand),
}

#[derive(clap::Args)]
struct AgentCommand {
    #[command(flatten)]
    agent: grund_agent::agent::AgentArgs,

    #[arg(long, env = "GRUND_VM_RUNTIME", value_parser = ["none", "simulated", "firecracker"], default_value = "none", help = "What runs VMs: none, firecracker (microVMs, needs /dev/kvm), or simulated (each VM is `grund join` run with its metadata; for tests and demos)")]
    vm_runtime: String,

    #[arg(
        long,
        env = "GRUND_VM_FIRECRACKER",
        default_value = "firecracker",
        help = "The Firecracker binary, for --vm-runtime firecracker"
    )]
    vm_firecracker: std::path::PathBuf,

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
        network,
        budget: grund_vm::Budget {
            vcpus: command.vm_vcpus.unwrap_or(host.vcpus),
            memory_mib: command.vm_memory_mib.unwrap_or(host.memory_mib),
            disk_gib: command.vm_disk_gib.unwrap_or(host.disk_gib),
        },
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    grund_server::health::set_revision(env!("GRUND_BUILD_REVISION"));
    let cli = Cli::parse();
    init_tracing(&cli);
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
        Command::Probe(args) => probe::run(&args),
        Command::Join(args) => grund_agent::join::run(&args).await,
        Command::Agent(command) => match command.vm_runtime.as_str() {
            "simulated" => {
                let dir = command.agent.data_dir.join("simulated-vms");
                grund_agent::agent::run(&command.agent, grund_agent::vm::SimulatedVms::new(dir))
                    .await
            }
            "firecracker" => grund_agent::agent::run(&command.agent, firecracker(&command)?).await,
            _ => grund_agent::agent::run(&command.agent, grund_agent::vm::NoVms).await,
        },
    }
}

fn init_tracing(cli: &Cli) {
    let filter = EnvFilter::try_new(&cli.log).unwrap_or_else(|_| EnvFilter::new("grund=info,warn"));
    let registry = tracing_subscriber::registry().with(filter);
    if cli.log_format == "json" {
        registry.with(fmt::layer().json()).init();
    } else {
        registry.with(fmt::layer().compact()).init();
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
