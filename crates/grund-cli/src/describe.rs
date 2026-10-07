//! `grund describe`: the command tree as JSON, built from clap's definition
//! of the binary (arguments, types, defaults, environment variables,
//! choices), [`crate::meta::LEAVES`] (output, procedures, examples) and the
//! protobuf descriptors (output schemas). Nothing in it is written by hand
//! a second time.

use std::any::TypeId;

use clap::{Arg, ArgAction, builder::ValueRange};
use serde_json::{Map, Value, json};

use crate::{error::Code, meta, schema::Registry};

/// The JSON type of an argument's value.
pub fn value_type(arg: &Arg) -> &'static str {
    if matches!(
        arg.get_action(),
        ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Count
    ) {
        return if matches!(arg.get_action(), ArgAction::Count) {
            "integer"
        } else {
            "boolean"
        };
    }
    let id = arg.get_value_parser().type_id();
    let is = |t: TypeId| id == t;
    if [
        TypeId::of::<u8>(),
        TypeId::of::<u16>(),
        TypeId::of::<u32>(),
        TypeId::of::<u64>(),
        TypeId::of::<i32>(),
        TypeId::of::<i64>(),
        TypeId::of::<usize>(),
    ]
    .into_iter()
    .any(is)
    {
        "integer"
    } else if is(TypeId::of::<f64>()) || is(TypeId::of::<f32>()) {
        "number"
    } else {
        "string"
    }
}

fn many(arg: &Arg) -> bool {
    matches!(arg.get_action(), ArgAction::Append)
        || arg
            .get_num_args()
            .is_some_and(|r: ValueRange| r.max_values() > 1)
}

/// One argument as `grund describe` shows it.
pub fn argument(arg: &Arg) -> Value {
    let mut out = json!({
        "name": arg.get_id().as_str(),
        "type": value_type(arg),
    });
    if let Some(long) = arg.get_long() {
        out["flag"] = json!(format!("--{long}"));
    }
    if let Some(short) = arg.get_short() {
        out["short"] = json!(format!("-{short}"));
    }
    if arg.is_positional() {
        out["positional"] = json!(true);
        if arg.is_last_set() {
            out["after_double_dash"] = json!(true);
        }
    }
    if many(arg) {
        out["repeated"] = json!(true);
    }
    if arg.is_required_set() {
        out["required"] = json!(true);
    }
    let help = arg.get_help().map(ToString::to_string).unwrap_or_default();
    if !help.is_empty() {
        out["description"] = json!(help);
    }
    let values: Vec<String> = arg
        .get_possible_values()
        .iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| v.get_name().to_string())
        .collect();
    if !values.is_empty() && value_type(arg) != "boolean" {
        out["enum"] = json!(values);
    }
    let defaults: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|v| v.to_string_lossy().to_string())
        .collect();
    match defaults.as_slice() {
        [] => {}
        [one] if value_type(arg) != "boolean" => out["default"] = json!(one),
        [_] => {}
        many => out["default"] = json!(many),
    }
    if let Some(env) = arg.get_env() {
        out["env"] = json!(env.to_string_lossy());
    }
    if let Some(names) = arg.get_value_names() {
        out["value_name"] = json!(
            names
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    out
}

fn visible_args(command: &clap::Command) -> impl Iterator<Item = &Arg> {
    command
        .get_arguments()
        .filter(|a| !a.is_hide_set() && a.get_id() != "help" && a.get_id() != "version")
}

/// Each runnable command under `command`, with its path below the root and
/// the arguments inherited from its parents.
pub fn leaves(root: &clap::Command) -> Vec<(String, clap::Command, Vec<Arg>)> {
    let mut found = Vec::new();
    walk(root, "", &[], &mut found);
    found
}

fn walk(
    command: &clap::Command,
    path: &str,
    inherited: &[Arg],
    found: &mut Vec<(String, clap::Command, Vec<Arg>)>,
) {
    let mut args: Vec<Arg> = inherited.to_vec();
    for arg in visible_args(command) {
        if !args.iter().any(|a| a.get_id() == arg.get_id()) {
            args.push(arg.clone());
        }
    }
    let children: Vec<&clap::Command> = command
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .collect();
    if children.is_empty() {
        if !path.is_empty() {
            found.push((path.to_string(), command.clone(), args));
        }
        return;
    }
    let passed: Vec<Arg> = args
        .iter()
        .filter(|a| a.is_global_set() || a.is_positional() && !path.is_empty())
        .cloned()
        .collect();
    for child in children {
        let child_path = if path.is_empty() {
            child.get_name().to_string()
        } else {
            format!("{path} {}", child.get_name())
        };
        walk(child, &child_path, &passed, found);
    }
}

/// Whether `path` is one of the client commands (`grund login`, `grund
/// apps …`) rather than an operator's (`grund serve`, `grund join`, …).
pub fn is_client(path: &str) -> bool {
    let first = path.split(' ').next().unwrap_or_default();
    crate::commands::CLIENT_NOUNS.contains(&first)
}

/// The whole `grund describe --json` document.
pub fn document(root: &clap::Command, only: &[String]) -> Value {
    let registry = Registry::compiled();
    let wanted = only.join(" ");
    let mut commands = Vec::new();
    let mut outputs: Vec<&str> = vec!["grund.cli.v1.ErrorOutput", "grund.cli.v1.DryRun"];
    for (path, command, args) in leaves(root) {
        if !wanted.is_empty() && path != wanted && !path.starts_with(&format!("{wanted} ")) {
            continue;
        }
        let mut entry = json!({
            "path": path,
            "command": format!("grund {path}"),
        });
        let about = command
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default();
        if !about.is_empty() {
            entry["summary"] = json!(about);
        }
        entry["args"] = Value::Array(args.iter().map(argument).collect());
        if is_client(&path) {
            entry["audience"] = json!("client");
            if let Some(leaf) = meta::leaf(&path) {
                entry["mutates"] = json!(leaf.mutates);
                entry["destructive"] = json!(leaf.destructive);
                entry["dry_run"] = json!(args.iter().any(|a| a.get_id() == "dry_run"));
                if !leaf.output.is_empty() {
                    entry["output"] = json!({"$ref": format!("#/$defs/{}", leaf.output)});
                    outputs.push(leaf.output);
                }
                if !leaf.rpcs.is_empty() {
                    entry["rpcs"] = json!(leaf.rpcs);
                }
                if !leaf.stdin.is_empty() {
                    entry["stdin"] = json!(leaf.stdin);
                }
                entry["examples"] = json!(leaf.examples);
            }
        } else {
            entry["audience"] = json!("operator");
        }
        commands.push(entry);
    }
    let defs: Map<String, Value> = registry.definitions(&outputs).into_iter().collect();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "name": "grund",
        "version": env!("CARGO_PKG_VERSION"),
        "summary": "grund's one binary: the client commands (audience client) drive an instance over its Connect API as the dashboard does; the operator commands run the instance, its machines, relays and edges.",
        "conventions": {
            "output": "--output json (or --json, or GRUND_OUTPUT=json) prints one JSON document on stdout: the protobuf JSON of the message the command's output names. Fields at their default may be absent. 64-bit integers are strings.",
            "errors": "A failed command prints grund.cli.v1.ErrorOutput on stderr with --output json, and exits with its code's status.",
            "confirmation": "Commands marked destructive ask on a terminal, and need --yes when stdin or stderr is not one, or with --output json.",
            "dry_run": "--dry-run prints grund.cli.v1.DryRun (apps deploy: grund.cli.v1.DeployResult with dryRun set) and changes nothing. A release's dry run is checked by the instance as a deploy is.",
            "organisation": "--org, else GRUND_ORG, else grund orgs use, else the token's organisation, else the account's only one.",
            "credentials": "GRUND_TOKEN (a personal access token, grund_pat_…) and GRUND_INSTANCE, else the credentials file grund login writes (mode 0600; GRUND_CREDENTIALS_FILE, else $XDG_CONFIG_HOME/grund/credentials.yaml).",
        },
        "environment": [
            {"name": "GRUND_INSTANCE", "description": "The instance's address, as --instance."},
            {"name": "GRUND_TOKEN", "description": "A personal access token; overrides the credentials file. Never put a token on the command line."},
            {"name": "GRUND_ORG", "description": "The organisation, as --org."},
            {"name": "GRUND_OUTPUT", "description": "text, json or yaml, as --output."},
            {"name": "GRUND_CREDENTIALS_FILE", "description": "Where grund login keeps credentials."},
        ],
        "exit_codes": exit_codes(),
        "commands": commands,
        "$defs": defs,
    })
}

/// Every error code with its exit status and meaning.
pub fn exit_codes() -> Value {
    let mut codes = vec![json!({"code": "ok", "exit": 0, "meaning": "Done."})];
    for code in Code::ALL {
        codes.push(json!({
            "code": code.as_str(),
            "exit": code.exit_status(),
            "meaning": code.meaning(),
        }));
    }
    Value::Array(codes)
}

/// The commands as text: one line each, for people.
pub fn text(document: &Value) -> String {
    let mut out = String::new();
    for command in document["commands"].as_array().into_iter().flatten() {
        if command["audience"] != "client" {
            continue;
        }
        out.push_str(&format!(
            "{:<32} {}\n",
            command["command"].as_str().unwrap_or_default(),
            command["summary"].as_str().unwrap_or_default()
        ));
    }
    out.push_str("\ngrund describe --json for arguments, outputs, errors and examples.\n");
    out
}
