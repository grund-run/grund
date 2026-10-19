//! `grund status` and `grund doctor`: this computer (grund-docs
//! design/cli-redesign.md §3). On a machine they read grund's agent by
//! running it, never by linking it.

use std::{os::unix::fs::MetadataExt, path::PathBuf, process::Stdio, time::Duration};

use clap::Args;
use serde_json::{Value, json};

use crate::{
    api::Api,
    context::{Ctx, Global, Source},
    credentials,
    error::{CliError, CliResult, Code},
    output::Output,
};

const INSTALLED_AGENT: &str = "/usr/local/lib/grund/agent/grund";

/// `grund status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    #[command(flatten)]
    pub global: Global,
}

/// `grund doctor`.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[command(flatten)]
    pub global: Global,
}

pub(crate) fn agent() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("GRUND_AGENT_BIN").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(path)).filter(|p| p.is_file());
    }
    if std::path::Path::new(INSTALLED_AGENT).is_file() {
        return Some(PathBuf::from(INSTALLED_AGENT));
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("grund-agent"))
            .find(|candidate| candidate.is_file())
    })
}

pub(crate) async fn agent_json(agent: &PathBuf, args: &[&str]) -> Option<(bool, Value)> {
    let mut command = tokio::process::Command::new(agent);
    command
        .arg0("grund-agent")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .ok()?
        .ok()?;
    let value = serde_json::from_slice(&output.stdout).ok()?;
    Some((output.status.success(), value))
}

pub(crate) fn root() -> bool {
    std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
}

fn unix(value: &Value) -> String {
    value
        .as_i64()
        .map(|seconds| seconds.to_string())
        .unwrap_or_default()
}

async fn machine() -> Option<Value> {
    let agent = agent()?;
    if !root() {
        return Some(json!({"readable": false}));
    }
    let (_, status) = match agent_json(&agent, &["status"]).await {
        Some(answer) => answer,
        None => agent_json(&agent, &["machine-follow", "status"])
            .await
            .map(|(ok, follow)| {
                (
                    ok,
                    json!({"registered": true, "following": {
                        "enabled": follow["enabled"], "paused": follow["paused"],
                        "state": follow["status"]["state"],
                        "targetRevision": follow["status"]["target_revision"],
                        "failureCode": follow["status"]["failure_code"],
                    }, "update": {"phase": follow["phase"]}}),
                )
            })
            .unwrap_or((false, json!({"registered": false}))),
    };
    let mut machine =
        json!({"readable": true, "registered": status["registered"].as_bool().unwrap_or(false)});
    let set = |machine: &mut Value, key: &str, value: &Value| {
        if !value.is_null() && value != "" {
            machine[key] = value.clone();
        }
    };
    set(&mut machine, "revision", &status["agent"]["revision"]);
    set(&mut machine, "id", &status["machine"]["id"]);
    set(&mut machine, "name", &status["machine"]["name"]);
    set(&mut machine, "instance", &status["machine"]["instance"]);
    let contact = unix(&status["agent"]["lastContactUnix"]);
    set(&mut machine, "lastContactUnix", &json!(contact));
    set(&mut machine, "ready", &status["agent"]["ready"]);
    set(&mut machine, "following", &status["following"]["enabled"]);
    set(&mut machine, "paused", &status["following"]["paused"]);
    set(&mut machine, "updateState", &status["following"]["state"]);
    set(
        &mut machine,
        "targetRevision",
        &status["following"]["targetRevision"],
    );
    set(
        &mut machine,
        "failureCode",
        &status["following"]["failureCode"],
    );
    set(&mut machine, "updatePhase", &status["update"]["phase"]);
    Some(machine)
}

fn ago(unix: &str) -> String {
    let Ok(then) = unix.parse::<i64>() else {
        return "never reported".into();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    match (now - then).max(0) {
        s if s < 120 => format!("{s}s ago"),
        s if s < 7200 => format!("{}m ago", s / 60),
        s => format!("{}h ago", s / 3600),
    }
}

fn status_text(value: &Value) -> String {
    let mut lines = Vec::new();
    match &value["context"] {
        Value::Null if value["credentialSource"] == "GRUND_TOKEN" => {
            lines.push(("signed in", "GRUND_TOKEN and GRUND_INSTANCE".to_string()));
        }
        Value::Null => lines.push(("signed in", "no (grund auth login)".to_string())),
        context => {
            let mut what = format!(
                "{} ({})",
                context["name"].as_str().unwrap_or_default(),
                context["instance"].as_str().unwrap_or_default()
            );
            for key in ["organisation", "username"] {
                if let Some(v) = context[key].as_str() {
                    what.push_str(&format!(", {v}"));
                }
            }
            lines.push(("context", what));
        }
    }
    lines.push((
        "cli",
        value["version"].as_str().unwrap_or_default().to_string(),
    ));
    let machine = &value["machine"];
    if machine.is_object() {
        if machine["readable"] != true {
            lines.push((
                "machine",
                "run with sudo to read this machine's agent".into(),
            ));
        } else if machine["registered"] != true {
            lines.push((
                "machine",
                "not connected (sudo grund join <instance> --code <code>)".into(),
            ));
        } else {
            lines.push((
                "machine",
                format!(
                    "{} on {}, last contact {}",
                    machine["name"].as_str().unwrap_or("this machine"),
                    machine["instance"].as_str().unwrap_or("its instance"),
                    ago(machine["lastContactUnix"].as_str().unwrap_or_default())
                ),
            ));
            if let Some(revision) = machine["revision"].as_str() {
                lines.push(("agent", revision.chars().take(12).collect()));
            }
            let updates = match (
                machine["following"].as_bool(),
                machine["paused"].as_bool(),
                machine["updatePhase"].as_str(),
            ) {
                (_, _, Some(phase)) => format!("updating ({phase})"),
                (Some(true), Some(true), _) => "paused (sudo grund update --resume)".into(),
                (Some(true), _, _) => format!(
                    "following the instance ({})",
                    machine["updateState"].as_str().unwrap_or("waiting")
                ),
                _ => "not following the instance".into(),
            };
            lines.push(("updates", updates));
        }
    }
    let width = lines.iter().map(|(k, _)| k.len()).max().unwrap_or(0) + 2;
    lines
        .iter()
        .map(|(k, v)| format!("{k:width$}{v}\n"))
        .collect()
}

/// Runs `grund status`: the context, this CLI, and the machine when the
/// agent is installed here. It reads local files and runs the local agent;
/// it calls no instance.
pub async fn status(ctx: &Ctx) -> CliResult<Output> {
    let mut value = json!({"version": crate::VERSION});
    let from_env = std::env::var("GRUND_TOKEN").is_ok_and(|t| !t.trim().is_empty())
        && (ctx.global.instance.is_some() || std::env::var("GRUND_INSTANCE").is_ok());
    if from_env {
        value["credentialSource"] = json!("GRUND_TOKEN");
    } else if let Some(context) = ctx.context()? {
        let mut shown = json!({
            "name": context.name,
            "instance": context.url,
            "credential": context.kind(),
            "current": true,
        });
        crate::context::set_if(&mut shown, "username", context.username.clone());
        crate::context::set_if(&mut shown, "organisation", context.organisation.clone());
        value["context"] = shown;
    }
    if let Some(machine) = machine().await {
        value["machine"] = machine;
    }
    let text = status_text(&value);
    Ok(Output::with_text(value, text))
}

fn check(name: &str, status: &str, detail: impl Into<String>, fix: &str) -> Value {
    let mut check = json!({"name": name, "status": status, "detail": detail.into()});
    crate::context::set_if(&mut check, "fix", fix);
    check
}

async fn reach(ctx: &Ctx) -> Value {
    let instance = match ctx.instance() {
        Ok(instance) => instance,
        Err(error) if error.code == Code::NotSignedIn => {
            return check(
                "signed-in",
                "warn",
                "no instance is chosen",
                "grund auth login <instance>",
            );
        }
        Err(error) => return check("signed-in", "fail", error.message.clone(), &error.hint),
    };
    let credential = match ctx.credential(&instance) {
        Ok(credential) => credential,
        Err(error) => return check("signed-in", "fail", error.message.clone(), &error.hint),
    };
    let api = match Api::new(&instance, Some(credential.secret)) {
        Ok(api) => api,
        Err(error) => return check("signed-in", "fail", error.message.clone(), &error.hint),
    };
    let source = match credential.source {
        Source::Environment => "GRUND_TOKEN",
        Source::File => "the context",
    };
    match api
        .call("grund.account.v1.AccountService/GetViewer", json!({}))
        .await
    {
        Ok(_) => check(
            "signed-in",
            "ok",
            format!("{instance} answers and accepts the credential from {source}"),
            "",
        ),
        Err(error) if matches!(error.code, Code::Unauthenticated | Code::NotSignedIn) => check(
            "signed-in",
            "fail",
            format!("{instance} refuses the credential from {source}"),
            &format!("grund auth login {instance}"),
        ),
        Err(error) if error.code == Code::PermissionDenied => check(
            "signed-in",
            "ok",
            format!("{instance} answers; the credential from {source} is a token"),
            "",
        ),
        Err(error) => check(
            "signed-in",
            "fail",
            format!("cannot reach {instance}: {}", error.message),
            "check the address and this computer's network, then run grund doctor again",
        ),
    }
}

/// Runs `grund doctor`: this CLI, its config file, the instance it is
/// signed in to, and on a machine the agent's own checks. Exits 1 when a
/// check fails.
pub async fn doctor(ctx: &Ctx) -> CliResult<Output> {
    let mut checks = vec![check("cli", "ok", format!("grund {}", crate::VERSION), "")];
    let path = credentials::path()?;
    checks.push(match credentials::load() {
        Ok(file) => check(
            "config",
            "ok",
            format!("{} ({} contexts)", path.display(), file.contexts.len()),
            "",
        ),
        Err(error) => check("config", "fail", error.message.clone(), &error.hint),
    });
    checks.push(reach(ctx).await);
    if let Some(agent) = agent() {
        if !root() {
            checks.push(check(
                "machine",
                "warn",
                "grund's agent is installed here; its checks need root",
                "sudo grund doctor",
            ));
        } else {
            let answer = match agent_json(&agent, &["doctor", "--json"]).await {
                Some(answer) => Some(answer),
                None => agent_json(&agent, &["doctor", "--json", "machine"]).await,
            };
            match answer {
                Some((_, report)) => {
                    for item in report["checks"].as_array().into_iter().flatten() {
                        let mut item = item.clone();
                        if let Some(name) = item["name"].as_str() {
                            item["name"] = json!(format!("machine/{name}"));
                        }
                        checks.push(item);
                    }
                }
                None => checks.push(check(
                    "machine",
                    "fail",
                    format!("{} did not report its checks", agent.display()),
                    "sudo systemctl status grund-agent",
                )),
            }
        }
    }
    let worst = if checks.iter().any(|c| c["status"] == "fail") {
        "fail"
    } else if checks.iter().any(|c| c["status"] == "warn") {
        "warn"
    } else {
        "ok"
    };
    let text = checks
        .iter()
        .map(|c| {
            let mut line = format!(
                "{:4}  {}: {}\n",
                c["status"].as_str().unwrap_or_default(),
                c["name"].as_str().unwrap_or_default(),
                c["detail"].as_str().unwrap_or_default()
            );
            if let Some(fix) = c["fix"].as_str().filter(|f| !f.is_empty()) {
                line.push_str(&format!("      fix: {fix}\n"));
            }
            line
        })
        .collect();
    let output = Output::with_text(json!({"status": worst, "checks": checks}), text);
    Ok(if worst == "fail" {
        output.exit(1)
    } else {
        output
    })
}

async fn agent_status(agent: &PathBuf) -> Option<Value> {
    agent_json(agent, &["status"])
        .await
        .map(|(_, status)| status)
}

/// Pauses or resumes this machine's following of its instance's updates
/// (`grund update --pause|--resume`). Needs root and grund's agent.
pub async fn follow(pause: bool) -> CliResult<Output> {
    let agent = agent().ok_or_else(|| {
        CliError::new(
            Code::NotFound,
            "grund's agent is not installed on this computer",
        )
        .hint("sudo grund join <instance> --code <code>")
    })?;
    if !root() {
        return Err(CliError::new(
            Code::PermissionDenied,
            "pausing or resuming this machine's updates needs root",
        )
        .hint(if pause {
            "sudo grund update --pause"
        } else {
            "sudo grund update --resume"
        }));
    }
    let verb = if pause { "pause" } else { "resume" };
    let answer = match agent_json(&agent, &["follow", verb]).await {
        Some(answer) => Some(answer),
        None => agent_json(&agent, &["machine-follow", verb]).await,
    };
    match answer {
        Some((true, follow)) => {
            let message = if pause {
                "This machine no longer takes updates from its instance until sudo grund update --resume."
            } else {
                "This machine follows its instance's updates again."
            };
            Ok(Output::line(
                json!({"message": message, "following": follow}),
                "/message",
            ))
        }
        _ => Err(CliError::new(
            Code::Failed,
            format!("grund's agent could not {verb} following"),
        )
        .hint("this machine follows only after an install that enabled it; sudo grund doctor")),
    }
}

fn outcome(outcome: &str, detail: impl Into<String>, hint: &str) -> Value {
    let mut value = json!({"outcome": outcome, "detail": detail.into()});
    crate::context::set_if(&mut value, "hint", hint);
    value
}

/// Brings this machine's agent to the build its instance offers, through
/// the agent's own updater: it waits for the updater's next pass to take an
/// offer, and follows it until it is committed or rolled back. It never
/// names a revision. `None` on a computer without grund's agent.
pub async fn machine_update(dry_run: bool) -> CliResult<Option<Value>> {
    let Some(agent) = agent() else {
        return Ok(None);
    };
    if !root() {
        return Ok(Some(outcome(
            "unreadable",
            "grund's agent is installed here; updating it needs root",
            "sudo grund update",
        )));
    }
    let Some(status) = agent_status(&agent).await else {
        return Ok(Some(outcome(
            "unsupported",
            "this machine's agent predates updating from the machine; it updates when its instance offers",
            "sudo grund status",
        )));
    };
    if status["registered"] != true {
        return Ok(Some(outcome(
            "not_connected",
            "this machine is not connected to an instance",
            "sudo grund join <instance> --code <code>",
        )));
    }
    if status["following"]["enabled"] != true {
        return Ok(Some(outcome(
            "not_following",
            "this machine does not follow its instance's updates",
            "rerun sudo grund join <instance> to enable it",
        )));
    }
    if status["following"]["paused"] == true {
        return Ok(Some(outcome(
            "paused",
            "this machine's updates are paused (by its owner, or after a rolled-back update)",
            "sudo grund update --resume, then sudo grund update",
        )));
    }
    let running = status["agent"]["revision"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let instance = status["machine"]["instance"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let target = match Api::new(&instance, None)?.revision().await {
        Ok(revision) => revision.rsplit('+').next().unwrap_or_default().to_string(),
        Err(error) => {
            return Ok(Some(outcome(
                "unreachable",
                error.message.clone(),
                "sudo grund doctor",
            )));
        }
    };
    let result = |name: &str, detail: String, hint: &str| {
        let mut value = outcome(name, detail, hint);
        value["from"] = json!(running);
        value["target"] = json!(target);
        value
    };
    if !running.is_empty() && running == target && status["update"].is_null() {
        return Ok(Some(result(
            "current",
            format!("the agent runs {}, its instance's build", short(&target)),
            "",
        )));
    }
    if dry_run {
        return Ok(Some(result(
            "would_update",
            format!(
                "the agent runs {}; its instance offers {}",
                short(&running),
                short(&target)
            ),
            "",
        )));
    }
    let started = std::time::Instant::now();
    let mut seen_attempt = !status["update"].is_null();
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Some(now) = agent_status(&agent).await else {
            continue;
        };
        let state = now["following"]["state"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if !now["update"].is_null() {
            seen_attempt = true;
            if started.elapsed() > Duration::from_secs(20 * 60) {
                return Ok(Some(result(
                    "in_progress",
                    format!(
                        "an update is still {}",
                        now["update"]["phase"].as_str().unwrap_or("running")
                    ),
                    "sudo grund status",
                )));
            }
            continue;
        }
        if seen_attempt {
            let revision = now["agent"]["revision"].as_str().unwrap_or_default();
            return Ok(Some(match state.as_str() {
                "committed" => result(
                    "committed",
                    format!("the agent now runs {}", short(revision)),
                    "",
                ),
                "rolled_back" => result(
                    "rolled_back",
                    format!(
                        "the new build did not become healthy ({}); the agent runs {} again and following is paused",
                        now["following"]["failureCode"]
                            .as_str()
                            .unwrap_or("no code"),
                        short(revision)
                    ),
                    "sudo grund doctor; then sudo grund update --resume",
                ),
                other => result(
                    "ended",
                    format!(
                        "the update ended: {}",
                        if other.is_empty() { "no state" } else { other }
                    ),
                    "sudo grund status",
                ),
            }));
        }
        if started.elapsed() > Duration::from_secs(60) {
            return Ok(Some(result(
                "not_offered",
                format!(
                    "the instance offered no update within a minute; the agent runs {} and the instance {}",
                    short(&running),
                    short(&target)
                ),
                "an instance updates one machine at a time and can pause its rollout; this machine updates when offered",
            )));
        }
    }
}

fn short(revision: &str) -> String {
    revision.chars().take(12).collect()
}

/// The text lines for a machine update's outcome.
pub fn machine_update_text(machine: &Value) -> String {
    let mut text = format!(
        "machine  {}\n",
        machine["detail"].as_str().unwrap_or_default()
    );
    if let Some(hint) = machine["hint"].as_str().filter(|h| !h.is_empty()) {
        text.push_str(&format!("         {hint}\n"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_text_names_the_context_and_a_machine_needing_sudo() {
        let value = json!({
            "version": "v0.0.0-alpha.12",
            "context": {"name": "home", "instance": "https://grund.example.com", "organisation": "acme"},
            "machine": {"readable": false},
        });
        let text = status_text(&value);
        assert!(text.contains("home (https://grund.example.com), acme"));
        assert!(text.contains("run with sudo"));
    }

    #[test]
    fn a_paused_machine_says_how_to_resume() {
        let value = json!({
            "version": "v",
            "machine": {"readable": true, "registered": true, "name": "web-1",
                        "instance": "https://grund.example.com", "following": true, "paused": true},
        });
        assert!(status_text(&value).contains("paused (sudo grund update --resume)"));
    }
}
