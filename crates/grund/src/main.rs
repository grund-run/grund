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

    #[arg(long, env = "GRUND_VM_RUNTIME", value_parser = ["none", "simulated"], default_value = "none", help = "What runs VMs: none, or simulated (each VM is `grund join` run with its metadata; for tests and demos)")]
    vm_runtime: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
