//! `grund skill`: SKILL.md for coding agents. The workflows are written by
//! hand (`skill/SKILL.md`); the command reference under them is generated
//! from the same clap definition and metadata as `grund describe`.

use crate::{describe, meta};

const WORKFLOWS: &str = include_str!("../skill/SKILL.md");

/// The whole SKILL.md.
pub fn text(root: &clap::Command) -> String {
    let mut out = String::from(WORKFLOWS);
    out.push_str("\n## Every command\n\nGenerated from the CLI itself; `grund describe --json` has the same with types, defaults and output schemas.\n\n");
    for (path, command, args) in describe::leaves(root) {
        if !describe::is_client(&path) || path == "mcp" || path.starts_with("skill") {
            continue;
        }
        let mut usage = format!("grund {path}");
        for arg in args.iter().filter(|a| a.is_positional()) {
            let name = arg
                .get_value_names()
                .and_then(|n| n.first().map(ToString::to_string))
                .unwrap_or_else(|| arg.get_id().to_string().to_uppercase());
            let shown = if arg.is_last_set() {
                format!("-- {name}...")
            } else if arg.is_required_set() {
                name
            } else {
                format!("[{name}]")
            };
            usage.push(' ');
            usage.push_str(&shown);
        }
        let flags: Vec<String> = args
            .iter()
            .filter(|a| !a.is_positional() && !a.is_global_set())
            .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
            .collect();
        let about = command
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default();
        out.push_str(&format!("- `{usage}`: {about}."));
        if !flags.is_empty() {
            out.push_str(&format!(" Flags: {}.", flags.join(", ")));
        }
        if let Some(leaf) = meta::leaf(&path) {
            if !leaf.output.is_empty() {
                out.push_str(&format!(" JSON: `{}`.", leaf.output));
            }
            if leaf.destructive {
                out.push_str(" Destructive: needs --yes.");
            }
            if !leaf.stdin.is_empty() {
                out.push_str(&format!(" Stdin: {}.", leaf.stdin));
            }
        }
        out.push('\n');
    }
    out.push_str("\nEvery client command also takes --instance, --org, --output text|json|yaml and --json.\n\n## Exit codes\n\n");
    for code in describe::exit_codes().as_array().into_iter().flatten() {
        out.push_str(&format!(
            "- {} `{}`: {}\n",
            code["exit"],
            code["code"].as_str().unwrap_or_default(),
            code["meaning"].as_str().unwrap_or_default()
        ));
    }
    out
}
