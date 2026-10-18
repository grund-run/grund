//! Coordinated stack deployment through the public StackService.

use std::{
    io::{BufRead, IsTerminal, Read, Write},
    path::PathBuf,
    time::Duration,
};

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    api::Api,
    commands::{Noun, dry_run},
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::{self, Output},
};

use super::app_telemetry::{self, LogOptions, LogsArgs, MetricOptions, MetricsArgs};

const SERVICE: &str = "grund.stack.v1.StackService";
const MAX_FILE_BYTES: u64 = grund_config::stack::MAX_FILE_BYTES as u64;
const MAX_SECRET_INPUT_BYTES: u64 = 512 * 1024;

pub type StacksCommand = Noun<StacksAction>;

#[derive(Debug, Subcommand)]
pub enum StacksAction {
    #[command(about = "Deploy a complete stack, or preview the resolved bundle without changes")]
    Deploy(DeployArgs),
    #[command(about = "One bounded page of the organisation's stacks")]
    List {
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        page_size: u32,
        #[arg(long)]
        page_token: Option<String>,
    },
    #[command(about = "Actual stack and per-service readiness, placement and operation failure")]
    Status {
        #[arg(value_name = "STACK")]
        stack: String,
    },
    #[command(
        about = "Read one service's retained output, or follow it",
        long_about = "Read one stack service's retained app output, oldest received first. Output can contain sensitive data. With --follow, JSON is one ListAppLogsResponse per line and YAML is a stream of documents; Ctrl-C stops following."
    )]
    Logs {
        #[arg(value_name = "STACK")]
        stack: String,
        #[arg(long, value_name = "SERVICE")]
        service: String,
        #[command(flatten)]
        options: LogOptions,
    },
    #[command(about = "Measured CPU and memory for one service, including unknown values and gaps")]
    Metrics {
        #[arg(value_name = "STACK")]
        stack: String,
        #[arg(long, value_name = "SERVICE")]
        service: String,
        #[command(flatten)]
        options: MetricOptions,
    },
    #[command(about = "Restart the stack, or one service, without changing the bundle")]
    Restart {
        #[arg(value_name = "STACK")]
        stack: String,
        #[arg(long)]
        service: Option<String>,
        #[command(flatten)]
        mutation: Mutation,
    },
    #[command(about = "Deploy an earlier complete stack revision; this does not rewind data")]
    Rollback {
        #[arg(value_name = "STACK")]
        stack: String,
        #[arg(long)]
        revision: u32,
        #[command(flatten)]
        mutation: Mutation,
    },
    #[command(about = "Stop every service; retained volumes remain recoverable")]
    Delete {
        #[arg(value_name = "STACK")]
        stack: String,
        #[arg(long, help = "Do not ask; required without an interactive terminal")]
        yes: bool,
        #[command(flatten)]
        mutation: Mutation,
    },
    #[command(about = "Restore a deleted stack and its retained data before expiry")]
    Restore {
        #[arg(value_name = "STACK")]
        stack: String,
        #[command(flatten)]
        mutation: Mutation,
    },
}

#[derive(Debug, Args)]
pub struct Mutation {
    #[arg(
        long,
        help = "Require this stack version; by default read the current version first"
    )]
    pub expected_version: Option<i64>,
    #[arg(
        long,
        requires = "expected_version",
        help = "Reuse this key with the same --expected-version for identical retries; default: a new UUID"
    )]
    pub idempotency_key: Option<String>,
    #[arg(
        long,
        help = "Wait for the operation to succeed; report failed or halted operations as exit 9"
    )]
    pub wait: bool,
    #[arg(long, default_value_t = 1800, help = "Maximum seconds to wait")]
    pub timeout: u64,
    #[arg(
        long,
        help = "Resolve the deployment preview, or show the mutation request, without changing anything"
    )]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    #[arg(short = 'f', long, default_value = "grund.yaml", value_name = "FILE")]
    pub file: PathBuf,
    #[arg(
        long,
        help = "Update only this service; the file must still describe the complete unchanged bundle"
    )]
    pub service: Option<String>,
    #[arg(
        long,
        help = "Explicitly refresh this template service's pinned catalogue expansion"
    )]
    pub refresh_template: Option<String>,
    #[arg(
        long = "confirm-remove",
        value_name = "SERVICE",
        help = "Explicitly authorize removal of this omitted service, retaining its data; repeat for each removed service"
    )]
    pub confirmed_removals: Vec<String>,
    #[arg(
        long = "secret",
        value_name = "SERVICE/NAME",
        conflicts_with = "secrets_stdin",
        help = "Prompt without echo for an initial app secret; repeat for more. Values are never command-line arguments"
    )]
    pub secrets: Vec<String>,
    #[arg(
        long,
        help = "Read initial secrets from a protected stdin JSON object: {service:{name:value}}; never printed"
    )]
    pub secrets_stdin: bool,
    #[command(flatten)]
    pub mutation: Mutation,
}

fn rpc(method: &str) -> String {
    format!("{SERVICE}/{method}")
}

fn read_file(path: &std::path::Path) -> CliResult<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(CliError::usage("stack file exceeds 1 MiB").field(path.display().to_string()));
    }
    Ok(text)
}

fn secret_name(text: &str) -> CliResult<(&str, &str)> {
    let (service, name) = text
        .split_once('/')
        .ok_or_else(|| CliError::usage("--secret needs SERVICE/NAME, never a value"))?;
    if service.is_empty() || name.is_empty() || name.contains('/') || text.contains('=') {
        return Err(CliError::usage(
            "--secret needs SERVICE/NAME, never a value",
        ));
    }
    Ok((service, name))
}

fn secret_object(text: &str) -> CliResult<Vec<Value>> {
    let value: Value = serde_json::from_str(text).map_err(|_| {
        CliError::usage("secret stdin must be a JSON object {service:{name:value}}")
    })?;
    let services = value
        .as_object()
        .ok_or_else(|| CliError::usage("secret stdin must be a JSON object"))?;
    let mut secrets = Vec::new();
    for (service, entries) in services {
        let entries = entries.as_object().ok_or_else(|| {
            CliError::usage("each service in secret stdin must contain a JSON object")
        })?;
        for (name, value) in entries {
            let value = value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| CliError::usage("secret values must be nonempty JSON strings"))?;
            secrets.push(json!({"service": service, "name": name, "value": value}));
        }
    }
    Ok(secrets)
}

struct EchoRestore {
    state: String,
    tty: std::fs::File,
}

impl Drop for EchoRestore {
    fn drop(&mut self) {
        if let Ok(tty) = self.tty.try_clone() {
            let _ = std::process::Command::new("stty")
                .arg(&self.state)
                .stdin(tty)
                .status();
        }
        let _ = writeln!(&self.tty);
    }
}

fn prompt_secret(service: &str, name: &str) -> CliResult<String> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let saved = std::process::Command::new("stty")
        .arg("-g")
        .stdin(tty.try_clone()?)
        .output()?;
    if !saved.status.success() {
        return Err(CliError::new(
            Code::Failed,
            "could not read terminal echo settings",
        ));
    }
    let restore = EchoRestore {
        state: String::from_utf8_lossy(&saved.stdout).trim().to_string(),
        tty: tty.try_clone()?,
    };
    let status = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(tty.try_clone()?)
        .status()?;
    if !status.success() {
        return Err(CliError::new(
            Code::Failed,
            "could not disable terminal echo",
        ));
    }
    write!(tty, "Initial secret {service}/{name}: ")?;
    tty.flush()?;
    let mut value = String::new();
    std::io::BufReader::new(tty).read_line(&mut value)?;
    drop(restore);
    while value.ends_with(['\n', '\r']) {
        value.pop();
    }
    if value.is_empty() {
        return Err(CliError::usage("initial secret must not be empty"));
    }
    Ok(value)
}

fn launch_secrets(ctx: &Ctx, args: &DeployArgs) -> CliResult<Vec<Value>> {
    if args.secrets_stdin {
        let text = if let Some(text) = &ctx.stdin {
            if text.len() as u64 > MAX_SECRET_INPUT_BYTES {
                return Err(CliError::usage("secret stdin exceeds 512 KiB"));
            }
            text.clone()
        } else {
            if std::io::stdin().is_terminal() {
                return Err(CliError::usage(
                    "--secrets-stdin requires redirected protected input",
                ));
            }
            let mut text = String::new();
            std::io::stdin()
                .take(MAX_SECRET_INPUT_BYTES + 1)
                .read_to_string(&mut text)?;
            if text.len() as u64 > MAX_SECRET_INPUT_BYTES {
                return Err(CliError::usage("secret stdin exceeds 512 KiB"));
            }
            text
        };
        return secret_object(&text);
    }
    if !args.secrets.is_empty() && (!ctx.interactive || ctx.stdin.is_some()) {
        return Err(CliError::usage(
            "--secret needs an interactive terminal; use --secrets-stdin for automation",
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    args.secrets
        .iter()
        .map(|text| {
            let (service, name) = secret_name(text)?;
            if !names.insert((service, name)) {
                return Err(CliError::usage("duplicate --secret service/name"));
            }
            let value = prompt_secret(service, name)?;
            Ok(json!({"service": service, "name": name, "value": value}))
        })
        .collect()
}

async fn get(api: &Api, org: &str, name: &str) -> CliResult<Value> {
    api.call(&rpc("GetStack"), json!({"organisation": org, "name": name}))
        .await
}

fn version(value: &Value) -> CliResult<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .ok_or_else(|| CliError::new(Code::Failed, "stack response has no version"))
}

fn request(org: &str, name: &str, expected: i64, options: &Mutation) -> Value {
    json!({"organisation": org, "name": name, "expectedVersion": expected.to_string(),
        "idempotencyKey": options.idempotency_key.clone().unwrap_or_else(|| Uuid::now_v7().to_string())})
}

async fn finish(
    ctx: &Ctx,
    api: &Api,
    org: &str,
    mut answer: Value,
    options: &Mutation,
    deleting: bool,
) -> CliResult<Output> {
    if options.wait {
        let name = answer["stack"]["name"]
            .as_str()
            .ok_or_else(|| CliError::new(Code::Failed, "stack response has no name"))?
            .to_string();
        let until = tokio::time::Instant::now() + Duration::from_secs(options.timeout);
        loop {
            let status = answer["stack"]["status"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let failure = answer["stack"]["failure"].as_str().unwrap_or_default();
            let pending = answer["stack"]["operation"]
                .as_str()
                .is_some_and(|value| !value.is_empty());
            if !pending
                && (!failure.is_empty()
                    || matches!(status.as_str(), "failed" | "halted" | "degraded"))
            {
                return Err(CliError::new(
                    Code::RolloutFailed,
                    if failure.is_empty() {
                        format!("stack {name} is {status}")
                    } else {
                        failure.to_string()
                    },
                ));
            }
            if !pending && ((deleting && status == "deleted") || (!deleting && status == "ready")) {
                break;
            }
            if tokio::time::Instant::now() >= until {
                return Err(CliError::new(
                    Code::Unavailable,
                    format!("timed out waiting for stack {name}"),
                ));
            }
            output::progress(ctx.format, &format!("{name}: {status}"));
            tokio::time::sleep(Duration::from_secs(1)).await;
            answer = get(api, org, &name).await?;
        }
    }
    Ok(Output::fields(answer))
}

async fn service_app(api: &Api, org: &str, stack: &str, service: &str) -> CliResult<String> {
    let response = get(api, org, stack).await?;
    response["stack"]["services"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|candidate| candidate["name"] == service)
        .and_then(|candidate| candidate["appName"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| CliError::usage("unknown stack service").field("service"))
}

/// Follows a service using the app consumer's bounded cursors and cancellation.
pub async fn follow(ctx: &Ctx, stack: &str, service: &str, options: LogOptions) -> CliResult<()> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    let app = service_app(&api, &org, stack, service).await?;
    app_telemetry::follow(ctx, &api, &org, LogsArgs { app, options }).await
}

pub async fn run(ctx: &Ctx, action: StacksAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    match action {
        StacksAction::List {
            page_size,
            page_token,
        } => {
            let answer = api.call(&rpc("ListStacks"), json!({"organisation": org, "pageSize": page_size, "pageToken": page_token.unwrap_or_default()})).await?;
            Ok(Output::table(
                answer,
                "/stacks",
                &[
                    ("NAME", "/name"),
                    ("STATUS", "/status"),
                    ("REVISION", "/revision"),
                    ("VERSION", "/version"),
                    ("ADDRESS", "/address"),
                ],
            ))
        }
        StacksAction::Status { stack } => Ok(Output::fields(get(&api, &org, &stack).await?)),
        StacksAction::Logs {
            stack,
            service,
            options,
        } => {
            let app = service_app(&api, &org, &stack, &service).await?;
            app_telemetry::logs(&api, &org, LogsArgs { app, options }).await
        }
        StacksAction::Metrics {
            stack,
            service,
            options,
        } => {
            let app = service_app(&api, &org, &stack, &service).await?;
            app_telemetry::metrics(&api, &org, MetricsArgs { app, options }).await
        }
        StacksAction::Deploy(mut args) => {
            let yaml = read_file(&args.file)?;
            let definition = grund_config::stack::parse(&yaml).map_err(|error| {
                CliError::new(Code::Invalid, error.to_string())
                    .field(args.file.display().to_string())
            })?;
            let preview_request = json!({"organisation": org, "yaml": yaml, "service": args.service.as_deref().unwrap_or_default(), "refreshTemplate": args.refresh_template.as_deref().unwrap_or_default()});
            let preview = api
                .call(&rpc("PreviewStack"), preview_request.clone())
                .await?;
            if args.mutation.dry_run {
                return Ok(Output::fields(preview));
            }
            let expected = match args.mutation.expected_version {
                Some(expected) => expected,
                None if preview["preview"].is_object()
                    && preview["preview"]["expectedVersion"].is_null() =>
                {
                    0
                }
                None => version(&preview["preview"]["expectedVersion"])?,
            };
            if expected == 0 && !args.secrets_stdin {
                for (service, definition) in &definition.services {
                    for name in definition.app.secrets.values() {
                        let target = format!("{service}/{name}");
                        if !args.secrets.contains(&target) {
                            args.secrets.push(target);
                        }
                    }
                }
            }
            let secrets = launch_secrets(ctx, &args)?;
            let mut input = preview_request;
            input["idempotencyKey"] = json!(
                args.mutation
                    .idempotency_key
                    .clone()
                    .unwrap_or_else(|| Uuid::now_v7().to_string())
            );
            if expected > 0 || args.mutation.expected_version.is_some() {
                input["expectedVersion"] = json!(expected.to_string());
            }
            input["secrets"] = json!(secrets);
            input["confirmedRemovals"] = json!(args.confirmed_removals);
            let answer = api.call(&rpc("DeployStack"), input).await?;
            finish(ctx, &api, &org, answer, &args.mutation, false).await
        }
        action => {
            let (name, options, method, service, revision, yes) = match action {
                StacksAction::Restart {
                    stack,
                    service,
                    mutation,
                } => (stack, mutation, "RestartStack", service, None, false),
                StacksAction::Rollback {
                    stack,
                    revision,
                    mutation,
                } => (
                    stack,
                    mutation,
                    "RollbackStack",
                    None,
                    Some(revision),
                    false,
                ),
                StacksAction::Delete {
                    stack,
                    yes,
                    mutation,
                } => (stack, mutation, "DeleteStack", None, None, yes),
                StacksAction::Restore { stack, mutation } => {
                    (stack, mutation, "RestoreStack", None, None, false)
                }
                _ => unreachable!(),
            };
            let expected = match options.expected_version {
                Some(expected) => expected,
                None => version(&get(&api, &org, &name).await?["stack"]["version"])?,
            };
            let mut input = request(&org, &name, expected, &options);
            if let Some(service) = service {
                input["service"] = json!(service);
            }
            if let Some(revision) = revision {
                input["revision"] = json!(revision);
            }
            if options.dry_run {
                return Ok(dry_run(&[(rpc(method), input)], vec![]));
            }
            if method == "DeleteStack" {
                ctx.confirm(
                    yes,
                    &format!("Delete stack {name} and stop all its services"),
                )?;
            }
            let answer = api.call(&rpc(method), input).await?;
            finish(ctx, &api, &org, answer, &options, method == "DeleteStack").await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_input_is_an_object_of_nonempty_write_only_values() {
        for input in [
            "[]",
            r#"{"web":"hidden"}"#,
            r#"{"web":{"token":1}}"#,
            r#"{"web":{"token":""}}"#,
        ] {
            assert!(secret_object(input).is_err());
        }
        assert!(secret_name("web/token=hidden").is_err());
    }

    #[test]
    fn malformed_secret_json_never_echoes_the_input_in_an_error() {
        let error = secret_object("PRIVATE VALUE").unwrap_err();
        assert!(!error.to_string().contains("PRIVATE VALUE"));
    }
}
