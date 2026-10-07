//! `grund mcp`: the client commands as Model Context Protocol tools over
//! stdio (newline-delimited JSON-RPC 2.0). Each tool is one command from
//! `grund describe`, its input schema made from the command's arguments,
//! and a call runs that command in this process with `--output json`,
//! exactly as typed on a command line would. Destructive tools take `yes`
//! like the flag, so a client sees and confirms them.
//!
//! Not tools: `login` and `logout` (a person signs in, in a terminal),
//! `mcp` and `skill`.

use clap::{Arg, Parser};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{
    Standalone,
    context::Ctx,
    describe,
    error::{CliError, CliResult, Code},
    meta,
    output::Format,
};

/// The protocol versions this server speaks, newest first.
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// A tool: its name, the command's path, and the command's arguments.
pub struct Tool {
    pub name: String,
    pub path: String,
    pub description: String,
    pub args: Vec<Arg>,
    pub leaf: &'static meta::Leaf,
}

/// The tools: one per client command but those a person runs.
pub fn tools(root: &clap::Command) -> Vec<Tool> {
    describe::leaves(root)
        .into_iter()
        .filter(|(path, _, _)| {
            describe::is_client(path)
                && !matches!(path.as_str(), "login" | "logout" | "mcp")
                && !path.starts_with("skill")
        })
        .filter_map(|(path, command, args)| {
            let leaf = meta::leaf(&path)?;
            let about = command
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();
            let mut description = format!("grund {path}: {about}.");
            if !leaf.output.is_empty() {
                description.push_str(&format!(" Answers {} as JSON.", leaf.output));
            }
            if leaf.destructive {
                description.push_str(" Destructive: set yes to true once the user agreed.");
            }
            Some(Tool {
                name: path.replace([' ', '-'], "_"),
                path,
                description,
                args: args
                    .into_iter()
                    .filter(|a| {
                        !matches!(
                            a.get_id().as_str(),
                            "output" | "json" | "log" | "log_format"
                        )
                    })
                    .collect(),
                leaf,
            })
        })
        .collect()
}

fn input_schema(tool: &Tool) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for arg in &tool.args {
        let described = describe::argument(arg);
        let mut property = json!({"type": described["type"]});
        if let Some(values) = described.get("enum") {
            property["enum"] = values.clone();
        }
        if let Some(text) = described.get("description") {
            property["description"] = text.clone();
        }
        if let Some(default) = described.get("default") {
            property["default"] = default.clone();
        }
        if described.get("repeated").is_some() {
            property = json!({"type": "array", "items": property});
        }
        if described.get("required").is_some() {
            required.push(arg.get_id().to_string());
        }
        properties.insert(arg.get_id().to_string(), property);
    }
    if !tool.leaf.stdin.is_empty() {
        properties.insert(
            "stdin".into(),
            json!({"type": "string", "description": tool.leaf.stdin}),
        );
        required.push("stdin".into());
    }
    json!({"type": "object", "properties": properties, "required": required, "additionalProperties": false})
}

fn text_of(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The command line a tool call stands for: the path's words, each
/// level's positionals, its flags, then `--` and a trailing argument.
pub fn argv(
    root: &clap::Command,
    tool: &Tool,
    input: &Map<String, Value>,
) -> CliResult<Vec<String>> {
    for key in input.keys() {
        if key != "stdin" && !tool.args.iter().any(|a| a.get_id() == key.as_str()) {
            return Err(
                CliError::usage(format!("{} takes no argument {key}", tool.name))
                    .field(key.clone()),
            );
        }
    }
    let values = |arg: &Arg| -> CliResult<Vec<String>> {
        match input.get(arg.get_id().as_str()) {
            None | Some(Value::Null) => Ok(vec![]),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    text_of(v)
                        .ok_or_else(|| CliError::usage(format!("{}: give strings", arg.get_id())))
                })
                .collect(),
            Some(value) => text_of(value).map(|v| vec![v]).ok_or_else(|| {
                CliError::usage(format!("{}: not a value", arg.get_id()))
                    .field(arg.get_id().to_string())
            }),
        }
    };
    let mut line = vec!["grund".to_string()];
    let mut node = root.clone();
    let mut trailing = Vec::new();
    for word in tool.path.split(' ') {
        node = node
            .find_subcommand(word)
            .cloned()
            .ok_or_else(|| CliError::new(Code::Failed, format!("no command {word}")))?;
        line.push(word.to_string());
        let mut own: Vec<&Arg> = node.get_arguments().filter(|a| a.is_positional()).collect();
        own.sort_by_key(|a| a.get_index().unwrap_or(0));
        for arg in own {
            if arg.is_last_set() {
                trailing.extend(values(arg)?);
            } else {
                line.extend(values(arg)?);
            }
        }
        for arg in node
            .get_arguments()
            .filter(|a| !a.is_positional() && !a.is_global_set())
        {
            push_flag(&mut line, arg, &values(arg)?);
        }
    }
    for arg in tool
        .args
        .iter()
        .filter(|a| a.is_global_set() && !a.is_positional())
    {
        push_flag(&mut line, arg, &values(arg)?);
    }
    line.extend(["--output".into(), "json".into()]);
    if !trailing.is_empty() {
        line.push("--".into());
        line.extend(trailing);
    }
    Ok(line)
}

fn push_flag(line: &mut Vec<String>, arg: &Arg, values: &[String]) {
    let Some(long) = arg.get_long() else { return };
    if describe::value_type(arg) == "boolean" {
        if values.first().is_some_and(|v| v == "true") {
            line.push(format!("--{long}"));
        }
        return;
    }
    for value in values {
        line.push(format!("--{long}"));
        line.push(value.clone());
    }
}

async fn call(
    root: &clap::Command,
    revision: &'static str,
    name: &str,
    input: Map<String, Value>,
) -> Value {
    let tools = tools(root);
    let Some(tool) = tools.iter().find(|t| t.name == name) else {
        return result_error(&CliError::usage(format!("no tool {name}")));
    };
    let line = match argv(root, tool, &input) {
        Ok(line) => line,
        Err(error) => return result_error(&error),
    };
    let parsed = match Standalone::try_parse_from(&line) {
        Ok(parsed) => parsed,
        Err(error) => {
            let message = error.render().to_string();
            let first = message
                .lines()
                .next()
                .unwrap_or("not a valid call")
                .trim_start_matches("error: ");
            return result_error(&CliError::usage(first.to_string()));
        }
    };
    let mut ctx = Ctx::new(parsed.command.global().clone());
    ctx.format = Format::Json;
    ctx.interactive = false;
    ctx.stdin = input
        .get("stdin")
        .and_then(Value::as_str)
        .map(str::to_string);
    match crate::commands::execute(parsed.command, &ctx, root, revision).await {
        Ok(Some(output)) => json!({
            "content": [{"type": "text", "text": serde_json::to_string(&output.value).unwrap_or_default()}],
            "structuredContent": output.value,
            "isError": false,
        }),
        Ok(None) => json!({"content": [], "isError": false}),
        Err(error) => result_error(&error),
    }
}

fn result_error(error: &CliError) -> Value {
    json!({
        "content": [{"type": "text", "text": error.json().to_string()}],
        "structuredContent": error.json(),
        "isError": true,
    })
}

/// Answers one JSON-RPC message; `None` for a notification.
pub async fn handle(
    root: &clap::Command,
    revision: &'static str,
    message: &Value,
) -> Option<Value> {
    let id = message.get("id").cloned()?;
    let method = message["method"].as_str().unwrap_or_default();
    let result = match method {
        "initialize" => {
            let asked = message["params"]["protocolVersion"]
                .as_str()
                .unwrap_or_default();
            let version = PROTOCOL_VERSIONS
                .iter()
                .find(|v| **v == asked)
                .copied()
                .unwrap_or(PROTOCOL_VERSIONS[0]);
            json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "grund", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Each tool is a grund CLI command run with --output json against the instance and credential of this process (grund login, or GRUND_INSTANCE and GRUND_TOKEN). An error result carries {error:{code,message,hint,field,reason}}.",
            })
        }
        "ping" => json!({}),
        "tools/list" => {
            let listed: Vec<Value> = tools(root)
                .iter()
                .map(|tool| {
                    json!({
                        "name": tool.name,
                        "title": format!("grund {}", tool.path),
                        "description": tool.description,
                        "inputSchema": input_schema(tool),
                        "annotations": {
                            "readOnlyHint": !tool.leaf.mutates,
                            "destructiveHint": tool.leaf.destructive,
                            "idempotentHint": !tool.leaf.mutates,
                            "openWorldHint": false,
                        },
                    })
                })
                .collect();
            json!({"tools": listed})
        }
        "tools/call" => {
            let name = message["params"]["name"].as_str().unwrap_or_default();
            let input = message["params"]["arguments"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            call(root, revision, name, input).await
        }
        _ => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("no method {method}")},
            }));
        }
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

/// Serves until stdin ends.
pub async fn serve(root: clap::Command, revision: &'static str) -> CliResult<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let answer = match serde_json::from_str::<Value>(&line) {
            Ok(message) => handle(&root, revision, &message).await,
            Err(_) => Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {"code": -32700, "message": "not JSON"},
            })),
        };
        if let Some(answer) = answer {
            stdout.write_all(format!("{answer}\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}
