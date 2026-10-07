//! `grund apps` (grund-docs design/cli.md §1): an organisation's apps, over
//! `grund.app.v1.AppService`.
//!
//! A change to what runs (image, env, ports, …) makes a release: the CLI
//! takes the newest release's spec, changes the one item, and deploys it,
//! as the dashboard's Settings does. Copies, placement and automatic
//! rollback are settings, not releases.

use std::{path::PathBuf, time::Duration};

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::{
    api::Api,
    commands::{Noun, changes, done, dry_run},
    context::{Ctx, set_if},
    error::{CliError, CliResult, Code},
    output::{self, Output},
};

const SERVICE: &str = "grund.app.v1.AppService";

/// `grund apps`.
pub type AppsCommand = Noun<AppsAction>;

/// What `grund apps` does.
#[derive(Debug, Subcommand)]
pub enum AppsAction {
    #[command(about = "The organisation's apps, by name")]
    List,
    #[command(about = "One app: settings, rollout, every copy and where it runs, secrets' names")]
    Get {
        #[arg(value_name = "APP")]
        app: String,
    },
    #[command(
        about = "Whether an app is live: health (no_release, rolling_out, live, degraded, failed, halted), copies ready of wanted, its rollout"
    )]
    Status {
        #[arg(value_name = "APP")]
        app: String,
    },
    #[command(about = "An app's releases, newest first, at most 100")]
    History {
        #[arg(value_name = "APP")]
        app: String,
    },
    #[command(about = "Make an app with no release; nothing runs until its first deploy")]
    Create {
        #[arg(
            value_name = "APP",
            help = "[a-z0-9-], 1 to 32 characters; it never changes"
        )]
        app: String,
        #[arg(long, value_name = "N", help = "Copies to run, 1 to 20. Default: 1")]
        copies: Option<u32>,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(
        about = "Deploy from grund.yaml (every app it declares, or APP) or from flags (--image …): a new release, rolled out. Makes an app that does not exist yet"
    )]
    Deploy(DeployArgs),
    #[command(about = "Change one setting of an app: a new release for what runs, or a setting")]
    Set(SetArgs),
    #[command(
        about = "A new release running an earlier one's contents, with the secrets' newest values"
    )]
    Rollback {
        #[arg(value_name = "APP")]
        app: String,
        #[arg(
            value_name = "RELEASE",
            help = "The release number to run again (grund apps history)"
        )]
        release: u32,
        #[command(flatten)]
        follow: Follow,
        #[arg(
            long,
            help = "Show the request and what would change instead of sending it"
        )]
        dry_run: bool,
    },
    #[command(
        about = "Delete an app: its copies stop and its name is free again; its releases stay in the history"
    )]
    Delete {
        #[arg(value_name = "APP")]
        app: String,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "An app's secrets: list their names and versions, set one from stdin")]
    Secrets {
        #[command(subcommand)]
        action: SecretsAction,
    },
}

/// What `grund apps secrets` does.
#[derive(Debug, Subcommand)]
pub enum SecretsAction {
    #[command(about = "The app's secrets: names and versions, never values")]
    List {
        #[arg(value_name = "APP")]
        app: String,
    },
    #[command(
        about = "Store a new version of a secret, its value read from stdin. Releases name it with grund apps set APP secret-env"
    )]
    Set {
        #[arg(value_name = "APP")]
        app: String,
        #[arg(value_name = "SECRET", help = "[a-z0-9][a-z0-9-]{0,62}")]
        secret: String,
        #[arg(
            long,
            help = "Keep a final newline of stdin; by default one is dropped"
        )]
        keep_newline: bool,
        #[arg(
            long,
            help = "Show the request (the value redacted) instead of sending it"
        )]
        dry_run: bool,
    },
}

/// Following a rollout until it ends.
#[derive(Debug, Clone, Args)]
pub struct Follow {
    #[arg(
        long,
        help = "Wait until the rollout is live or failed; exit 9 when it failed"
    )]
    pub wait: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 600,
        help = "With --wait: give up after this long (exit 8)"
    )]
    pub timeout: u64,
}

/// `grund apps deploy`.
#[derive(Debug, Args)]
pub struct DeployArgs {
    #[arg(
        value_name = "APP",
        help = "The app. Default: every app the file declares"
    )]
    pub app: Option<String>,

    #[arg(
        short = 'f',
        long,
        value_name = "FILE",
        help = "The grund.yaml to deploy. Default: ./grund.yaml when --image is not given"
    )]
    pub file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "REF",
        help = "Deploy from flags: the image, such as nginx:1.27 or ghcr.io/acme/shop@sha256:…",
        conflicts_with = "file"
    )]
    pub image: Option<String>,

    #[arg(
        long = "port",
        value_name = "NAME=PORT[/PROTOCOL]",
        help = "With --image: a port, protocol http (default), h2c or tcp. Repeat for more"
    )]
    pub ports: Vec<String>,

    #[arg(
        long = "public",
        value_name = "NAME",
        help = "With --image: make this port reachable at the app's address"
    )]
    pub public: Vec<String>,

    #[arg(
        long = "env",
        value_name = "KEY=VALUE",
        help = "With --image: an environment variable. Repeat for more"
    )]
    pub env: Vec<String>,

    #[arg(
        long = "secret-env",
        value_name = "ENV=SECRET",
        help = "With --image: hand the app's secret SECRET to it as ENV"
    )]
    pub secret_env: Vec<String>,

    #[arg(
        long,
        value_name = "MIB",
        help = "With --image: memory per copy, MiB. Default: 512"
    )]
    pub memory_mib: Option<u64>,

    #[arg(
        long,
        value_name = "VCPU",
        help = "With --image: CPU per copy, in vCPU (0.5 = half a CPU). Default: 1"
    )]
    pub cpu: Option<f64>,

    #[arg(
        long,
        value_name = "PATH",
        help = "With --image: ready when GET PATH answers 2xx or 3xx"
    )]
    pub check_http: Option<String>,

    #[arg(
        long,
        help = "With --image: ready when a TCP connect succeeds",
        conflicts_with = "check_http"
    )]
    pub check_tcp: bool,

    #[arg(
        long,
        value_name = "N",
        help = "Copies to run, 1 to 20 (a setting, applied before the release)"
    )]
    pub copies: Option<u32>,

    #[arg(
        long,
        value_name = "TEXT",
        help = "Where the deploy came from, shown in the history: a commit, a CI run. At most 200 bytes"
    )]
    pub note: Option<String>,

    #[arg(long, help = "Refuse an app that does not exist instead of making it")]
    pub no_create: bool,

    #[command(flatten)]
    pub follow: Follow,

    #[arg(
        long,
        help = "Check everything a deploy checks, resolve the image, and show the release it would make and what changes. Nothing is written"
    )]
    pub dry_run: bool,

    #[arg(
        last = true,
        value_name = "COMMAND",
        help = "With --image: the command and its arguments, after --, replacing the image's"
    )]
    pub command: Vec<String>,
}

/// `grund apps set`.
#[derive(Debug, Args)]
pub struct SetArgs {
    #[arg(value_name = "APP")]
    pub app: String,

    #[command(subcommand)]
    pub item: SetItem,

    #[arg(
        long,
        global = true,
        value_name = "TEXT",
        help = "For a new release: shown in the history"
    )]
    pub note: Option<String>,

    #[arg(
        long,
        global = true,
        help = "For a new release: wait until it is live or failed"
    )]
    pub wait: bool,

    #[arg(
        long,
        global = true,
        value_name = "SECONDS",
        default_value_t = 600,
        help = "With --wait: give up after this long"
    )]
    pub timeout: u64,

    #[arg(
        long,
        global = true,
        help = "Show the request and what changes instead of sending it"
    )]
    pub dry_run: bool,
}

/// One setting `grund apps set` changes.
#[derive(Debug, Subcommand)]
pub enum SetItem {
    #[command(about = "The image (a new release)")]
    Image {
        #[arg(value_name = "REF")]
        reference: String,
    },
    #[command(about = "Environment variables: set some, unset some (a new release)")]
    Env {
        #[arg(value_name = "KEY=VALUE")]
        set: Vec<String>,
        #[arg(
            long,
            value_name = "KEY",
            help = "Remove this variable. Repeat for more"
        )]
        unset: Vec<String>,
    },
    #[command(
        name = "secret-env",
        about = "Secrets handed to the app as environment variables (a new release)"
    )]
    SecretEnv {
        #[arg(value_name = "ENV=SECRET")]
        set: Vec<String>,
        #[arg(
            long,
            value_name = "ENV",
            help = "Stop handing this variable. Repeat for more"
        )]
        unset: Vec<String>,
    },
    #[command(about = "Replace the ports (a new release)")]
    Ports {
        #[arg(value_name = "NAME=PORT[/PROTOCOL]", required = true)]
        ports: Vec<String>,
        #[arg(
            long = "public",
            value_name = "NAME",
            help = "Reachable at the app's address. Repeat for more"
        )]
        public: Vec<String>,
    },
    #[command(about = "When a copy is ready (a new release)")]
    Check {
        #[arg(
            long,
            value_name = "PATH",
            group = "kind",
            help = "GET PATH answers 2xx or 3xx"
        )]
        http: Option<String>,
        #[arg(long, group = "kind", help = "A TCP connect succeeds")]
        tcp: bool,
        #[arg(
            long,
            group = "kind",
            help = "No check: ready once the process has run a while"
        )]
        none: bool,
        #[arg(
            long,
            value_name = "PORT",
            help = "The port to check. Default: the first"
        )]
        port: Option<u32>,
        #[arg(long, value_name = "MS", help = "500 to 60000. Default: 2000")]
        interval_ms: Option<u32>,
        #[arg(
            long,
            value_name = "MS",
            help = "100 to 30000, below the interval. Default: 1000"
        )]
        timeout_ms: Option<u32>,
    },
    #[command(about = "Memory and CPU per copy (a new release)")]
    Resources {
        #[arg(long, value_name = "MIB", help = "16 to 262144")]
        memory_mib: Option<u64>,
        #[arg(long, value_name = "VCPU", help = "0.01 to 64")]
        cpu: Option<f64>,
    },
    #[command(
        about = "The command and its arguments, after --, replacing the image's (a new release)"
    )]
    Command {
        #[arg(last = true, value_name = "ARG")]
        args: Vec<String>,
        #[arg(long, help = "Run what the image says again", conflicts_with = "args")]
        clear: bool,
    },
    #[command(about = "How many copies run, 1 to 20 (a setting)")]
    Copies {
        #[arg(value_name = "N")]
        copies: u32,
    },
    #[command(about = "Which machines run the copies and how they spread (a setting)")]
    Placement {
        #[arg(
            long = "label",
            value_name = "KEY=VALUE",
            help = "A label a machine must carry. Repeat for more"
        )]
        labels: Vec<String>,
        #[arg(long, value_parser = ["own", "hosted", "any"], help = "Own machines, hosted ones, or any")]
        kind: Option<String>,
        #[arg(
            long,
            value_name = "KEY",
            help = "Spread copies over this label's values, such as zone"
        )]
        spread_by: Option<String>,
        #[arg(long, value_name = "APP", help = "Prefer machines running this app")]
        near: Vec<String>,
        #[arg(long, value_name = "APP", help = "Avoid machines running this app")]
        apart: Vec<String>,
        #[arg(
            long = "machine",
            value_name = "NAME",
            help = "Only these machines, by name"
        )]
        machines: Vec<String>,
        #[arg(long, help = "Any machine, spread over machines: forget every rule")]
        clear: bool,
    },
    #[command(
        name = "auto-rollback",
        about = "Roll back on its own when a release fails (a setting)"
    )]
    AutoRollback {
        #[arg(value_parser = ["on", "off"])]
        value: String,
    },
}

const APPS: &[(&str, &str)] = &[
    ("NAME", "/name"),
    ("RELEASE", "/currentRelease"),
    ("COPIES", "/settings/copies"),
    ("ROLLOUT", "/rollout/state"),
];

const RELEASES: &[(&str, &str)] = &[
    ("RELEASE", "/number"),
    ("OUTCOME", "/outcome"),
    ("SOURCE", "/source"),
    ("IMAGE", "/spec/image"),
    ("BY", "/createdBy"),
    ("CREATED", "/createdAt"),
];

const SECRETS: &[(&str, &str)] = &[
    ("NAME", "/name"),
    ("VERSION", "/version"),
    ("UPDATED", "/updatedAt"),
];

/// Runs a `grund apps` verb.
pub async fn run(ctx: &Ctx, action: AppsAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    match action {
        AppsAction::List => {
            let answer = api
                .call(&format!("{SERVICE}/ListApps"), json!({"organisation": org}))
                .await?;
            Ok(Output::table(answer, "/apps", APPS))
        }
        AppsAction::Get { app } => Ok(Output::fields(get_app(&api, &org, &app).await?)),
        AppsAction::Status { app } => {
            let answer = get_app(&api, &org, &app).await?;
            Ok(Output::fields(status(&answer["app"])))
        }
        AppsAction::History { app } => {
            let answer = api
                .call(
                    &format!("{SERVICE}/ListReleases"),
                    json!({"organisation": org, "name": app}),
                )
                .await?;
            Ok(Output::table(answer, "/releases", RELEASES))
        }
        AppsAction::Create {
            app,
            copies,
            dry_run: preview,
        } => {
            let mut request = json!({"organisation": org, "name": app});
            if let Some(copies) = copies {
                request["settings"] = json!({"copies": copies});
            }
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/CreateApp"), request)],
                    vec![],
                ));
            }
            let answer = api.call(&format!("{SERVICE}/CreateApp"), request).await?;
            Ok(Output::fields(answer))
        }
        AppsAction::Deploy(args) => deploy(ctx, &api, &org, args).await,
        AppsAction::Set(args) => set(ctx, &api, &org, args).await,
        AppsAction::Rollback {
            app,
            release,
            follow,
            dry_run: preview,
        } => {
            let request = json!({"organisation": org, "name": app, "release": release});
            if preview {
                let releases = releases(&api, &org, &app).await?;
                let target = releases
                    .iter()
                    .find(|r| r["number"].as_u64() == Some(u64::from(release)))
                    .ok_or_else(|| {
                        CliError::new(Code::NotFound, format!("{app} has no release {release}"))
                            .hint(format!("grund apps history {app}"))
                    })?;
                let newest = releases.first().cloned().unwrap_or(Value::Null);
                return Ok(dry_run(
                    &[(format!("{SERVICE}/Rollback"), request)],
                    changes("/spec", &newest["spec"], &target["spec"]),
                ));
            }
            let answer = api.call(&format!("{SERVICE}/Rollback"), request).await?;
            let mut result = json!({"app": app, "release": answer["release"].clone()});
            if follow.wait {
                result["rollout"] =
                    wait(ctx, &api, &org, &app, &answer["release"], follow.timeout).await?;
            }
            Ok(Output::fields(result))
        }
        AppsAction::Delete {
            app,
            yes,
            dry_run: preview,
        } => {
            let request = json!({"organisation": org, "name": app});
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/DeleteApp"), request)],
                    vec![],
                ));
            }
            ctx.confirm(yes, &format!("Delete the app {app}; its copies stop"))?;
            api.call(&format!("{SERVICE}/DeleteApp"), request).await?;
            Ok(done(format!("Deleted {app}.")))
        }
        AppsAction::Secrets { action } => match action {
            SecretsAction::List { app } => {
                let answer = get_app(&api, &org, &app).await?;
                let secrets = answer["app"]["secrets"].clone();
                Ok(Output::table(
                    json!({"secrets": if secrets.is_null() { json!([]) } else { secrets }}),
                    "/secrets",
                    SECRETS,
                ))
            }
            SecretsAction::Set {
                app,
                secret,
                keep_newline,
                dry_run: preview,
            } => {
                let mut value = ctx.read_stdin("The secret's value")?;
                if !keep_newline && value.ends_with('\n') {
                    value.pop();
                    if value.ends_with('\r') {
                        value.pop();
                    }
                }
                if value.is_empty() {
                    return Err(CliError::usage(
                        "stdin is empty: give the secret's value on stdin",
                    )
                    .field("stdin"));
                }
                let request = json!({
                    "organisation": org,
                    "name": app,
                    "secret": secret,
                    "value": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value.as_bytes()),
                });
                if preview {
                    let mut shown = request.clone();
                    shown["value"] = json!("<redacted>");
                    return Ok(dry_run(&[(format!("{SERVICE}/SetSecret"), shown)], vec![]));
                }
                let answer = api.call(&format!("{SERVICE}/SetSecret"), request).await?;
                Ok(Output::fields(answer))
            }
        },
    }
}

async fn get_app(api: &Api, org: &str, app: &str) -> CliResult<Value> {
    api.call(
        &format!("{SERVICE}/GetApp"),
        json!({"organisation": org, "name": app}),
    )
    .await
}

async fn releases(api: &Api, org: &str, app: &str) -> CliResult<Vec<Value>> {
    let answer = api
        .call(
            &format!("{SERVICE}/ListReleases"),
            json!({"organisation": org, "name": app}),
        )
        .await?;
    Ok(answer["releases"].as_array().cloned().unwrap_or_default())
}

/// `grund.cli.v1.AppStatus` for an app as GetApp answers it.
pub fn status(app: &Value) -> Value {
    let current = app["currentRelease"].as_u64().unwrap_or(0);
    let wanted = app["settings"]["copies"].as_u64().unwrap_or(1);
    let replicas = app["replicas"].as_array().cloned().unwrap_or_default();
    let ready = replicas
        .iter()
        .filter(|r| {
            r["release"].as_u64() == Some(current)
                && r["state"].as_str().unwrap_or("REPLICA_STATE_RUNNING") == "REPLICA_STATE_RUNNING"
                && r["observed"]["ready"].as_bool() == Some(true)
        })
        .count() as u64;
    let rollout = app["rollout"].clone();
    let rollout_state = rollout["state"].as_str().unwrap_or_default();
    let health = if app["halted"].as_bool() == Some(true) {
        "halted"
    } else if rollout_state == "ROLLOUT_STATE_IN_PROGRESS" {
        "rolling_out"
    } else if rollout_state == "ROLLOUT_STATE_FAILED" {
        "failed"
    } else if current == 0 {
        "no_release"
    } else if ready < wanted {
        "degraded"
    } else {
        "live"
    };
    let mut status = json!({
        "app": app["name"].clone(),
        "health": health,
        "copiesWanted": wanted,
        "copiesReady": ready,
    });
    set_if(
        &mut status,
        "currentRelease",
        if current > 0 {
            json!(current)
        } else {
            Value::Null
        },
    );
    set_if(&mut status, "rollout", rollout);
    set_if(&mut status, "waiting", app["waiting"].clone());
    set_if(&mut status, "replicas", app["replicas"].clone());
    status
}

async fn wait(
    ctx: &Ctx,
    api: &Api,
    org: &str,
    app: &str,
    release: &Value,
    timeout: u64,
) -> CliResult<Value> {
    let number = release["number"].as_u64().unwrap_or(0);
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout);
    let mut last = String::new();
    loop {
        let answer = get_app(api, org, app).await?;
        let app_now = &answer["app"];
        let rollout = &app_now["rollout"];
        let state = rollout["state"].as_str().unwrap_or_default();
        let to = rollout["toRelease"].as_u64().unwrap_or(0);
        let now = status(app_now);
        let line = format!(
            "{app}: release {number} {} ({} of {} copies ready)",
            match (to == number, state) {
                (true, "ROLLOUT_STATE_IN_PROGRESS") => "rolling out",
                (true, "ROLLOUT_STATE_SUCCEEDED") => "live",
                (true, "ROLLOUT_STATE_FAILED") => "failed",
                (true, "ROLLOUT_STATE_SUPERSEDED") => "superseded",
                _ => "waiting",
            },
            now["copiesReady"],
            now["copiesWanted"]
        );
        if line != last {
            output::progress(ctx.format, &line);
            last = line;
        }
        if to == number {
            match state {
                "ROLLOUT_STATE_SUCCEEDED" => return Ok(rollout.clone()),
                "ROLLOUT_STATE_FAILED" | "ROLLOUT_STATE_SUPERSEDED" => {
                    let reason = rollout["reason"].as_str().unwrap_or("it did not go live");
                    let mut error = CliError::new(
                        Code::RolloutFailed,
                        format!("release {number} of {app} did not go live: {reason}"),
                    )
                    .hint(format!("grund apps status {app} --json shows each copy"));
                    error.reason = state
                        .trim_start_matches("ROLLOUT_STATE_")
                        .to_ascii_lowercase();
                    return Err(error);
                }
                _ => {}
            }
        } else if app_now["currentRelease"].as_u64().unwrap_or(0) >= number
            && state != "ROLLOUT_STATE_IN_PROGRESS"
        {
            return Ok(rollout.clone());
        }
        if std::time::Instant::now() > deadline {
            return Err(CliError::new(
                Code::Unavailable,
                format!("release {number} of {app} was not live after {timeout} s"),
            )
            .hint("it is still rolling out; grund apps status shows where it is"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn split_pair<'a>(text: &'a str, flag: &str) -> CliResult<(&'a str, &'a str)> {
    text.split_once('=')
        .filter(|(k, _)| !k.is_empty())
        .ok_or_else(|| CliError::usage(format!("{text} is not KEY=VALUE")).field(flag.to_string()))
}

fn port(text: &str, public: &[String]) -> CliResult<Value> {
    let (name, rest) = text.split_once('=').unwrap_or(("http", text));
    let (number, protocol) = rest.split_once('/').unwrap_or((rest, "http"));
    let number: u32 = number
        .parse()
        .ok()
        .filter(|n| (1..=65535).contains(n))
        .ok_or_else(|| CliError::usage(format!("{text}: the port is 1 to 65535")).field("port"))?;
    let protocol = match protocol {
        "http" => "PROTOCOL_HTTP",
        "h2c" => "PROTOCOL_H2C",
        "tcp" => "PROTOCOL_TCP",
        other => {
            return Err(CliError::usage(format!("{other} is not http, h2c or tcp")).field("port"));
        }
    };
    let mut port = json!({"name": name, "port": number, "protocol": protocol});
    if public.iter().any(|p| p == name) {
        port["public"] = json!(true);
    }
    Ok(port)
}

fn cpu_millis(cpu: f64) -> CliResult<u64> {
    let millis = (cpu * 1000.0).round();
    if !(10.0..=64000.0).contains(&millis) {
        return Err(CliError::usage("--cpu is 0.01 to 64 vCPU").field("cpu"));
    }
    Ok(millis as u64)
}

fn spec_from_flags(args: &DeployArgs, image: &str) -> CliResult<Value> {
    let mut spec = json!({"image": image});
    let ports = args
        .ports
        .iter()
        .map(|p| port(p, &args.public))
        .collect::<CliResult<Vec<_>>>()?;
    for public in &args.public {
        if !ports.iter().any(|p| p["name"] == json!(public)) {
            return Err(
                CliError::usage(format!("--public {public} names no --port")).field("public"),
            );
        }
    }
    set_if(&mut spec, "ports", ports);
    let env = args
        .env
        .iter()
        .map(|e| split_pair(e, "env").map(|(k, v)| json!({"name": k, "value": v})))
        .collect::<CliResult<Vec<_>>>()?;
    set_if(&mut spec, "env", env);
    let secrets = args
        .secret_env
        .iter()
        .map(|e| split_pair(e, "secret-env").map(|(k, v)| json!({"env": k, "secret": v})))
        .collect::<CliResult<Vec<_>>>()?;
    set_if(&mut spec, "secrets", secrets);
    let mut resources = json!({});
    if let Some(memory) = args.memory_mib {
        resources["memoryMib"] = json!(memory.to_string());
    }
    if let Some(cpu) = args.cpu {
        resources["cpuMillis"] = json!(cpu_millis(cpu)?);
    }
    set_if(&mut spec, "resources", resources);
    if let Some(path) = &args.check_http {
        spec["check"] = json!({"httpPath": path});
    } else if args.check_tcp {
        spec["check"] = json!({"tcp": true});
    }
    set_if(&mut spec, "command", args.command.clone());
    Ok(spec)
}

async fn exists(api: &Api, org: &str, app: &str) -> CliResult<bool> {
    match get_app(api, org, app).await {
        Ok(_) => Ok(true),
        Err(error) if error.code == Code::NotFound => {
            api.call(&format!("{SERVICE}/ListApps"), json!({"organisation": org}))
                .await?;
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

async fn deploy(ctx: &Ctx, api: &Api, org: &str, args: DeployArgs) -> CliResult<Output> {
    let note = args.note.clone().unwrap_or_default();
    let mut targets: Vec<(String, Value)> = Vec::new();
    if let Some(image) = &args.image {
        let app = args.app.clone().ok_or_else(|| {
            CliError::usage("with --image, name the app: grund apps deploy APP --image REF")
                .field("app")
        })?;
        let spec = spec_from_flags(&args, image)?;
        targets.push((app, json!({"spec": spec})));
    } else {
        let path = args
            .file
            .clone()
            .unwrap_or_else(|| PathBuf::from("grund.yaml"));
        let text = std::fs::read_to_string(&path).map_err(|e| {
            CliError::usage(format!("cannot read {}: {e}", path.display()))
                .field("file")
                .hint("give the file with -f, or deploy from flags with --image")
        })?;
        let names = grund_domain::app::file::declared_names(&text);
        let chosen = match &args.app {
            Some(app) => vec![app.clone()],
            None if names.is_empty() => {
                let problem = grund_domain::app::file::parse_app(&text, "")
                    .err()
                    .map(|e| (e.field, e.problem))
                    .unwrap_or_else(|| ("grund.yaml".into(), "declares no apps".into()));
                return Err(CliError::new(
                    Code::Invalid,
                    format!("{}: {}", path.display(), problem.1),
                )
                .field(problem.0));
            }
            None => names,
        };
        for app in chosen {
            if let Err(e) = grund_domain::app::file::parse_app(&text, &app) {
                return Err(CliError::new(
                    Code::Invalid,
                    format!("{}: {}", path.display(), e.problem),
                )
                .field(e.field));
            }
            targets.push((app, json!({"grundYaml": text})));
        }
    }
    let mut results = Vec::new();
    for (app, source) in targets {
        let present = exists(api, org, &app).await?;
        if !present && args.no_create {
            return Err(
                CliError::new(Code::NotFound, format!("no app {app} in {org}"))
                    .hint("leave out --no-create to make it"),
            );
        }
        let mut request = json!({"organisation": org, "name": app});
        for (key, value) in source.as_object().into_iter().flatten() {
            request[key] = value.clone();
        }
        set_if(&mut request, "note", note.clone());
        let mut create = json!({"organisation": org, "name": app});
        if let Some(copies) = args.copies {
            create["settings"] = json!({"copies": copies});
        }
        if args.dry_run {
            let mut calls = Vec::new();
            let mut entry = json!({"app": app, "dryRun": true});
            if present {
                if let Some(copies) = args.copies {
                    calls.push((
                        format!("{SERVICE}/Scale"),
                        json!({"organisation": org, "name": app, "copies": copies}),
                    ));
                }
                let mut preview = request.clone();
                preview["dryRun"] = json!(true);
                let answer = api.call(&format!("{SERVICE}/Deploy"), preview).await?;
                let newest = releases(api, org, &app)
                    .await?
                    .into_iter()
                    .next()
                    .unwrap_or(Value::Null);
                entry["release"] = answer["release"].clone();
                set_if(
                    &mut entry,
                    "changes",
                    changes("/spec", &newest["spec"], &answer["release"]["spec"]),
                );
            } else {
                entry["created"] = json!(true);
                calls.push((format!("{SERVICE}/CreateApp"), create));
            }
            calls.push((format!("{SERVICE}/Deploy"), request));
            entry["calls"] = calls
                .into_iter()
                .map(|(rpc, request)| json!({"rpc": rpc, "request": request}))
                .collect();
            results.push(entry);
            continue;
        }
        if !present {
            api.call(&format!("{SERVICE}/CreateApp"), create).await?;
        } else if let Some(copies) = args.copies {
            api.call(
                &format!("{SERVICE}/Scale"),
                json!({"organisation": org, "name": app, "copies": copies}),
            )
            .await?;
        }
        let answer = api.call(&format!("{SERVICE}/Deploy"), request).await?;
        output::progress(
            ctx.format,
            &format!(
                "{app}: release {} made",
                answer["release"]["number"].as_u64().unwrap_or(0)
            ),
        );
        let mut entry = json!({"app": app, "release": answer["release"].clone()});
        if !present {
            entry["created"] = json!(true);
        }
        results.push(entry);
    }
    if args.follow.wait && !args.dry_run {
        let mut failed = None;
        for entry in &mut results {
            let app = entry["app"].as_str().unwrap_or_default().to_string();
            match wait(ctx, api, org, &app, &entry["release"], args.follow.timeout).await {
                Ok(rollout) => entry["rollout"] = rollout,
                Err(error) => {
                    failed.get_or_insert(error);
                }
            }
        }
        if let Some(error) = failed {
            return Err(error);
        }
    }
    let value = json!({"apps": results});
    Ok(Output::table(
        value,
        "/apps",
        &[
            ("APP", "/app"),
            ("RELEASE", "/release/number"),
            ("IMAGE", "/release/spec/image"),
            ("CREATED", "/created"),
            ("ROLLOUT", "/rollout/state"),
        ],
    ))
}

fn upsert(list: &mut Vec<Value>, key: &str, name: &str, entry: Value) {
    match list.iter_mut().find(|e| e[key] == json!(name)) {
        Some(existing) => *existing = entry,
        None => list.push(entry),
    }
}

fn edit_spec(spec: &mut Value, item: &SetItem) -> CliResult<()> {
    match item {
        SetItem::Image { reference } => spec["image"] = json!(reference),
        SetItem::Env { set, unset } => {
            if set.is_empty() && unset.is_empty() {
                return Err(CliError::usage("give KEY=VALUE to set or --unset KEY").field("env"));
            }
            let mut env = spec["env"].as_array().cloned().unwrap_or_default();
            for pair in set {
                let (k, v) = split_pair(pair, "env")?;
                upsert(&mut env, "name", k, json!({"name": k, "value": v}));
            }
            env.retain(|e| !unset.iter().any(|u| e["name"] == json!(u)));
            spec["env"] = json!(env);
        }
        SetItem::SecretEnv { set, unset } => {
            if set.is_empty() && unset.is_empty() {
                return Err(
                    CliError::usage("give ENV=SECRET to set or --unset ENV").field("secret-env")
                );
            }
            let mut secrets = spec["secrets"].as_array().cloned().unwrap_or_default();
            for pair in set {
                let (k, v) = split_pair(pair, "secret-env")?;
                upsert(&mut secrets, "env", k, json!({"env": k, "secret": v}));
            }
            secrets.retain(|e| !unset.iter().any(|u| e["env"] == json!(u)));
            spec["secrets"] = json!(secrets);
        }
        SetItem::Ports { ports, public } => {
            let ports = ports
                .iter()
                .map(|p| port(p, public))
                .collect::<CliResult<Vec<_>>>()?;
            spec["ports"] = json!(ports);
        }
        SetItem::Check {
            http,
            tcp,
            none,
            port,
            interval_ms,
            timeout_ms,
        } => {
            if *none {
                if let Some(object) = spec.as_object_mut() {
                    object.remove("check");
                }
                return Ok(());
            }
            let mut check = match (http, tcp) {
                (Some(path), _) => json!({"httpPath": path}),
                (None, true) => json!({"tcp": true}),
                (None, false) => {
                    let existing = spec["check"].clone();
                    if existing.is_null() {
                        return Err(
                            CliError::usage("give --http PATH, --tcp or --none").field("check")
                        );
                    }
                    existing
                }
            };
            if let Some(port) = port {
                check["port"] = json!(port);
            }
            if let Some(ms) = interval_ms {
                check["intervalMs"] = json!(ms);
            }
            if let Some(ms) = timeout_ms {
                check["timeoutMs"] = json!(ms);
            }
            spec["check"] = check;
        }
        SetItem::Resources { memory_mib, cpu } => {
            if memory_mib.is_none() && cpu.is_none() {
                return Err(CliError::usage("give --memory-mib or --cpu").field("resources"));
            }
            if !spec["resources"].is_object() {
                spec["resources"] = json!({});
            }
            if let Some(memory) = memory_mib {
                spec["resources"]["memoryMib"] = json!(memory.to_string());
            }
            if let Some(cpu) = cpu {
                spec["resources"]["cpuMillis"] = json!(cpu_millis(*cpu)?);
            }
        }
        SetItem::Command { args, clear } => {
            if *clear || args.is_empty() {
                if !*clear {
                    return Err(
                        CliError::usage("give the command after --, or --clear").field("command")
                    );
                }
                if let Some(object) = spec.as_object_mut() {
                    object.remove("command");
                }
            } else {
                spec["command"] = json!(args);
            }
        }
        SetItem::Copies { .. } | SetItem::Placement { .. } | SetItem::AutoRollback { .. } => {}
    }
    Ok(())
}

fn edit_settings(settings: &mut Value, item: &SetItem) -> CliResult<()> {
    match item {
        SetItem::Placement {
            labels,
            kind,
            spread_by,
            near,
            apart,
            machines,
            clear,
        } => {
            if *clear {
                if let Some(object) = settings.as_object_mut() {
                    object.remove("placement");
                    object.remove("machines");
                }
                return Ok(());
            }
            if !settings["placement"].is_object() {
                settings["placement"] = json!({});
            }
            let placement = &mut settings["placement"];
            if !labels.is_empty() {
                let mut map = serde_json::Map::new();
                for pair in labels {
                    let (k, v) = split_pair(pair, "label")?;
                    map.insert(k.to_string(), json!(v));
                }
                placement["labels"] = Value::Object(map);
            }
            if let Some(kind) = kind {
                placement["kind"] = json!(match kind.as_str() {
                    "own" => "MACHINE_KIND_OWN",
                    "hosted" => "MACHINE_KIND_HOSTED",
                    _ => "MACHINE_KIND_UNSPECIFIED",
                });
            }
            if let Some(key) = spread_by {
                placement["spreadBy"] = json!(key);
            }
            if !near.is_empty() {
                placement["near"] = json!(near);
            }
            if !apart.is_empty() {
                placement["apart"] = json!(apart);
            }
            if !machines.is_empty() {
                settings["machines"] = json!(machines);
            }
        }
        SetItem::AutoRollback { value } => settings["autoRollback"] = json!(value == "on"),
        _ => {}
    }
    Ok(())
}

async fn set(ctx: &Ctx, api: &Api, org: &str, args: SetArgs) -> CliResult<Output> {
    let app = args.app.clone();
    match &args.item {
        SetItem::Copies { copies } => {
            let request = json!({"organisation": org, "name": app, "copies": copies});
            if args.dry_run {
                let current = get_app(api, org, &app).await?;
                return Ok(dry_run(
                    &[(format!("{SERVICE}/Scale"), request)],
                    changes(
                        "/settings/copies",
                        &current["app"]["settings"]["copies"],
                        &json!(copies),
                    ),
                ));
            }
            let answer = api.call(&format!("{SERVICE}/Scale"), request).await?;
            Ok(Output::fields(answer))
        }
        SetItem::Placement { .. } | SetItem::AutoRollback { .. } => {
            let current = get_app(api, org, &app).await?;
            let before = current["app"]["settings"].clone();
            let mut settings = before.clone();
            edit_settings(&mut settings, &args.item)?;
            let request = json!({"organisation": org, "name": app, "settings": settings});
            if args.dry_run {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/ConfigureApp"), request)],
                    changes("/settings", &before, &settings),
                ));
            }
            let answer = api
                .call(&format!("{SERVICE}/ConfigureApp"), request)
                .await?;
            Ok(Output::fields(answer))
        }
        item => {
            let newest = releases(api, org, &app)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    CliError::new(
                        Code::Conflict,
                        format!("{app} has no release to change yet"),
                    )
                    .hint(format!(
                        "deploy it first: grund apps deploy {app} --image REF"
                    ))
                })?;
            let before = newest["spec"].clone();
            let mut spec = before.clone();
            edit_spec(&mut spec, item)?;
            let mut request = json!({"organisation": org, "name": app, "spec": spec});
            set_if(&mut request, "note", args.note.clone().unwrap_or_default());
            if args.dry_run {
                let mut preview = request.clone();
                preview["dryRun"] = json!(true);
                let answer = api.call(&format!("{SERVICE}/Deploy"), preview).await?;
                let mut result = dry_run(
                    &[(format!("{SERVICE}/Deploy"), request)],
                    changes("/spec", &before, &answer["release"]["spec"]),
                );
                result.value["release"] = answer["release"].clone();
                return Ok(result);
            }
            let answer = api.call(&format!("{SERVICE}/Deploy"), request).await?;
            let mut result = json!({"app": app, "release": answer["release"].clone()});
            if args.wait {
                result["rollout"] =
                    wait(ctx, api, org, &app, &answer["release"], args.timeout).await?;
            }
            Ok(Output::fields(result))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_is_name_number_and_protocol() {
        assert_eq!(
            port("web=8080/h2c", &["web".into()]).unwrap(),
            json!({"name": "web", "port": 8080, "protocol": "PROTOCOL_H2C", "public": true})
        );
        assert_eq!(
            port("8080", &[]).unwrap(),
            json!({"name": "http", "port": 8080, "protocol": "PROTOCOL_HTTP"})
        );
        assert!(port("web=0", &[]).is_err());
        assert!(port("web=80/udp", &[]).is_err());
    }

    #[test]
    fn env_is_set_and_unset_by_name_keeping_the_rest() {
        let mut spec = json!({"image": "x", "env": [{"name": "A", "value": "1"}, {"name": "B", "value": "2"}]});
        edit_spec(
            &mut spec,
            &SetItem::Env {
                set: vec!["A=9".into(), "C=3".into()],
                unset: vec!["B".into()],
            },
        )
        .unwrap();
        assert_eq!(
            spec["env"],
            json!([{"name": "A", "value": "9"}, {"name": "C", "value": "3"}])
        );
    }

    #[test]
    fn status_says_live_only_when_every_wanted_copy_of_the_current_release_is_ready() {
        let app = json!({
            "name": "web",
            "currentRelease": 2,
            "settings": {"copies": 2},
            "rollout": {"toRelease": 2, "state": "ROLLOUT_STATE_SUCCEEDED"},
            "replicas": [
                {"release": 2, "state": "REPLICA_STATE_RUNNING", "observed": {"ready": true}},
                {"release": 2, "state": "REPLICA_STATE_RUNNING", "observed": {"ready": false}},
            ],
        });
        assert_eq!(status(&app)["health"], "degraded");
        let mut both = app.clone();
        both["replicas"][1]["observed"]["ready"] = json!(true);
        assert_eq!(status(&both)["health"], "live");
        assert_eq!(status(&json!({"name": "new"}))["health"], "no_release");
    }
}
