//! The `grund` binary. One binary, several roles, chosen by subcommand:
//!
//! - `serve`: the control plane (dashboard, API, background work);
//! - `migrate`: apply database migrations and exit;
//! - `init`: generate a fresh instance's secrets, keeping any that exist;
//! - `probe`: exit 0 when an instance's readiness answers 200, for container
//!   health checks (the image has no shell or curl).
//!
//! The agent that runs on each machine will be another subcommand of this
//! binary, so there is one artifact to build, sign and ship.

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli);
    match cli.command {
        Command::Serve(mut config) => {
            config.validate()?;
            grund_server::serve(*config).await
        }
        Command::Migrate(args) => grund_server::migrate(args).await,
        Command::Init(args) => grund_server::secrets::init(&args),
        Command::Probe(args) => probe::run(&args),
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
