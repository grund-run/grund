//! The `grund` client CLI (grund-docs design/cli.md): everything the
//! dashboard does, for people, scripts and coding agents, over the same
//! Connect API.
//!
//! - Every command prints protobuf JSON with `--output json` (`--json`),
//!   and fails with `grund.cli.v1.ErrorOutput` on stderr and an exit status
//!   per error code ([`error::Code`]).
//! - Nothing asks when nobody can answer: destructive commands need
//!   `--yes` then, and mutating ones take `--dry-run`.
//! - The CLI describes itself from the code that defines it: `grund
//!   describe` (the command tree from clap, the output shapes from the
//!   protobuf descriptors compiled into the binary), `grund schema`,
//!   `grund skill` (a SKILL.md for coding agents) and `grund mcp` (the same
//!   commands as MCP tools).
//!
//! The unified Linux binary adds operator commands (`serve`, `join`,
//! `agent`, …). The standalone client builds without those dependencies.
#![forbid(unsafe_code)]

pub mod api;
pub mod attended;
pub mod commands;
pub mod context;
pub mod credentials;
pub mod describe;
pub mod error;
pub mod help;
pub mod mcp;
pub mod meta;
pub mod output;
pub mod progress;
pub mod schema;
pub mod skill;

pub use commands::Command;
use context::Ctx;
use error::{CliError, Code};
use output::Format;

/// The release tag supplied by `GRUND_VERSION`, or the crate version for local builds.
pub const VERSION: &str = env!("GRUND_VERSION");

/// The version and revision the binary reports, such as `grund v0.0.0-alpha.1 (abc1234)`.
pub fn client_name(revision: &str) -> String {
    let short: String = revision.chars().take(12).collect();
    format!("grund {} ({short})", VERSION)
}

/// Runs a client command and returns the process's exit status. `root` is
/// the whole `grund` command, for `describe`, `skill` and `mcp`.
pub async fn run(command: Command, root: clap::Command, revision: &'static str) -> i32 {
    let ctx = Ctx::new(command.global().clone());
    let format = ctx.format;
    match commands::execute(command, &ctx, &root, revision).await {
        Ok(Some(output)) => {
            output::print(&output, format);
            output.status
        }
        Ok(None) => 0,
        Err(error) => {
            output::print_error(&error, format);
            error.code.exit_status()
        }
    }
}

/// For a command line clap refused: when it asked for JSON (`--json`,
/// `-o json`, `--output=json` or GRUND_OUTPUT=json) and names a client
/// command, prints the refusal as `grund.cli.v1.ErrorOutput` and returns
/// the exit status; `None` leaves the refusal to clap.
pub fn usage_error(error: &clap::Error, args: &[String]) -> Option<i32> {
    use clap::error::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        return None;
    }
    let mut arguments = args.iter().skip(1);
    let first = loop {
        let argument = arguments.next()?;
        if matches!(argument.as_str(), "--instance" | "--org") {
            arguments.next()?;
            continue;
        }
        if !argument.starts_with('-') {
            break argument;
        }
    };
    if !commands::CLIENT_NOUNS.contains(&first.as_str()) {
        return None;
    }
    let wants_json = args.iter().enumerate().any(|(i, a)| {
        a == "--json"
            || a == "--output=json"
            || a == "-ojson"
            || ((a == "-o" || a == "--output") && args.get(i + 1).is_some_and(|v| v == "json"))
    }) || std::env::var("GRUND_OUTPUT").is_ok_and(|v| v == "json");
    if !wants_json {
        return None;
    }
    let rendered = error.render().to_string();
    let message = rendered
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("the command line is not valid")
        .trim_start_matches("error: ")
        .to_string();
    let usage = rendered
        .lines()
        .find(|l| l.starts_with("Usage:"))
        .map(|l| l.trim_start_matches("Usage:").trim().to_string())
        .unwrap_or_default();
    let mut refusal = CliError::usage(message);
    if !usage.is_empty() {
        refusal = refusal.hint(format!(
            "usage: {usage}; grund describe --json lists every command"
        ));
    }
    output::print_error(&refusal, Format::Json);
    Some(Code::Usage.exit_status())
}

/// The client commands, for a parser of their own (`grund mcp` parses each
/// tool call with it).
#[derive(clap::Parser, Debug)]
#[command(
    name = "grund",
    version = VERSION,
    about = "Deploy and run apps on machines you own.",
    disable_help_subcommand = true,
    args = context::Global::target_arguments()
)]
pub struct Standalone {
    #[command(subcommand)]
    pub command: Command,
}

impl Standalone {
    /// The client command tree, with grouped help.
    pub fn root() -> clap::Command {
        help::with_grouped_help(<Self as clap::CommandFactory>::command())
    }

    /// Parses `args` as `grund` does, with grouped help.
    pub fn parse_args(args: &[String]) -> Result<Self, clap::Error> {
        let matches = Self::root().try_get_matches_from(args)?;
        <Self as clap::FromArgMatches>::from_arg_matches(&matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn standalone_targets_are_global_across_the_client_command_tree() {
        for args in [
            [
                "grund",
                "--instance",
                "https://flag.invalid",
                "--org",
                "flag-org",
                "app",
                "list",
            ],
            [
                "grund",
                "app",
                "--instance",
                "https://flag.invalid",
                "--org",
                "flag-org",
                "list",
            ],
            [
                "grund",
                "app",
                "list",
                "--instance",
                "https://flag.invalid",
                "--org",
                "flag-org",
            ],
        ] {
            let parsed = Standalone::try_parse_from(args).unwrap();
            let target = parsed.command.global();
            assert_eq!(target.instance.as_deref(), Some("https://flag.invalid"));
            assert_eq!(target.org.as_deref(), Some("flag-org"));
        }
    }
}
