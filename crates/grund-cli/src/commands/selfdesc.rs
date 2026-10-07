//! `grund describe`, `grund schema`, `grund skill`, `grund mcp`: the CLI
//! describing itself, from the code that defines it.

use std::path::PathBuf;

use clap::Subcommand;
use serde_json::json;

use crate::{
    context::{Ctx, Global},
    describe,
    error::{CliError, CliResult, Code},
    meta,
    output::Output,
    schema::Registry,
    skill,
};

/// `grund describe`.
#[derive(Debug, clap::Args)]
pub struct DescribeArgs {
    #[command(flatten)]
    pub global: Global,
    #[arg(
        value_name = "COMMAND",
        help = "Only this command and those under it, such as apps deploy"
    )]
    pub command: Vec<String>,
}

/// `grund schema`.
#[derive(Debug, clap::Args)]
pub struct SchemaArgs {
    #[command(flatten)]
    pub global: Global,
    #[arg(
        value_name = "WHAT",
        value_parser = ["grund.yaml", "output", "error", "message", "list"],
        help = "grund.yaml: the app file. output COMMAND: what a command prints with --json. error: what a failed command prints. message NAME: any protobuf message. list: every name"
    )]
    pub what: String,
    #[arg(
        value_name = "NAME",
        help = "For output: the command, such as apps status. For message: the full name, such as grund.app.v1.App"
    )]
    pub name: Vec<String>,
}

/// `grund skill`.
#[derive(Debug, clap::Args)]
pub struct SkillCommand {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub action: SkillAction,
}

/// What `grund skill` does.
#[derive(Debug, Subcommand)]
pub enum SkillAction {
    #[command(about = "Print SKILL.md: how to drive grund from a coding agent, and every command")]
    Print,
    #[command(about = "Write SKILL.md to DIR/grund/SKILL.md, where Claude Code finds skills")]
    Install {
        #[arg(long, value_name = "DIR", help = "Default: ~/.claude/skills")]
        dir: Option<PathBuf>,
    },
}

/// `grund mcp`.
#[derive(Debug, clap::Args)]
pub struct McpArgs {
    #[command(flatten)]
    pub global: Global,
}

/// Runs `grund describe`.
pub fn describe(root: &clap::Command, args: DescribeArgs) -> CliResult<Output> {
    let document = describe::document(root, &args.command);
    if document["commands"].as_array().is_none_or(Vec::is_empty) {
        return Err(CliError::new(
            Code::NotFound,
            format!("no command grund {}", args.command.join(" ")),
        )
        .hint("grund describe lists every command"));
    }
    let text = describe::text(&document);
    Ok(Output::with_text(document, text))
}

/// Runs `grund schema`.
pub fn schema(root: &clap::Command, args: SchemaArgs) -> CliResult<Output> {
    let registry = Registry::compiled();
    let value = match args.what.as_str() {
        "grund.yaml" => grund_domain::app::file::schema(),
        "error" => registry.schema("grund.cli.v1.ErrorOutput"),
        "output" => {
            let path = args.name.join(" ");
            let leaf = meta::leaf(&path)
                .filter(|l| !l.output.is_empty())
                .ok_or_else(|| {
                    CliError::usage(format!("no client command grund {path} with a JSON output"))
                        .field("name")
                        .hint("grund schema list")
                })?;
            registry.schema(leaf.output)
        }
        "message" => {
            let name = args.name.join("");
            if !registry.has_message(&name) {
                return Err(CliError::new(Code::NotFound, format!("no message {name}"))
                    .hint("grund schema list"));
            }
            registry.schema(&name)
        }
        _ => {
            let outputs: Vec<_> = describe::leaves(root)
                .into_iter()
                .filter_map(|(path, _, _)| {
                    meta::leaf(&path)
                        .filter(|l| !l.output.is_empty())
                        .map(|l| json!({"command": path, "output": l.output}))
                })
                .collect();
            json!({
                "files": ["grund.yaml"],
                "outputs": outputs,
                "error": "grund.cli.v1.ErrorOutput",
            })
        }
    };
    Ok(Output::json(value))
}

/// Runs `grund skill`: prints SKILL.md itself, or installs it.
pub fn skill(_ctx: &Ctx, root: &clap::Command, command: SkillCommand) -> CliResult<Option<Output>> {
    let text = skill::text(root);
    match command.action {
        SkillAction::Print => {
            print!("{text}");
            Ok(None)
        }
        SkillAction::Install { dir } => {
            let dir = match dir {
                Some(dir) => dir,
                None => std::env::var_os("HOME")
                    .map(|h| PathBuf::from(h).join(".claude").join("skills"))
                    .ok_or_else(|| CliError::usage("HOME is not set: give --dir").field("dir"))?,
            };
            let path = dir.join("grund").join("SKILL.md");
            std::fs::create_dir_all(path.parent().unwrap_or(&dir))?;
            std::fs::write(&path, text)?;
            Ok(Some(Output::line(
                json!({"path": path.display().to_string()}),
                "/path",
            )))
        }
    }
}
