use std::time::Duration;

use clap::Args;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    api::Api,
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::Output,
};

use super::app_telemetry::{FollowOutput, safe_text};

const SERVICE: &str = "grund.run.v1.RunService";
const POLL: Duration = Duration::from_secs(1);

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(value_name = "STACK")]
    pub stack: String,
    #[arg(long)]
    pub service: String,
    #[arg(long, default_value = "10m", value_parser = timeout)]
    pub timeout: Duration,
    #[arg(long)]
    pub idempotency_key: Option<String>,
    #[arg(
        long,
        help = "Check permission and capacity without starting a command"
    )]
    pub dry_run: bool,
    #[arg(
        last = true,
        required = true,
        value_name = "ARGS",
        allow_hyphen_values = true
    )]
    pub args: Vec<String>,
}

#[derive(Debug, Args)]
pub struct RunListArgs {
    pub stack: String,
    #[arg(long)]
    pub service: Option<String>,
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub page_size: u32,
    #[arg(long)]
    pub page_token: Option<String>,
}

#[derive(Debug, Args)]
pub struct RunLogsArgs {
    #[arg(value_name = "RUN_ID")]
    pub id: String,
    #[arg(long)]
    pub follow: bool,
    #[arg(long, default_value_t = 200, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub page_size: u32,
    #[arg(long)]
    pub page_token: Option<String>,
}

fn timeout(text: &str) -> Result<Duration, String> {
    let (number, factor) = if let Some(n) = text.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = text.strip_suffix('m') {
        (n, 60)
    } else {
        (text.strip_suffix('s').unwrap_or(text), 1)
    };
    number
        .parse::<u32>()
        .ok()
        .and_then(|n| n.checked_mul(factor))
        .filter(|n| (1..=3600).contains(n))
        .map(|seconds| Duration::from_secs(u64::from(seconds)))
        .ok_or_else(|| "use 1s to 1h (for example 30s or 10m)".to_string())
}

fn rpc(method: &str) -> String {
    format!("{SERVICE}/{method}")
}

fn logs_output(answer: Value) -> Output {
    use std::fmt::Write;
    let mut text = String::new();
    if answer["droppedRecords"].as_str().is_some_and(|n| n != "0")
        || answer["droppedRecords"].as_u64().is_some_and(|n| n != 0)
        || answer["gaps"].as_array().is_some_and(|g| !g.is_empty())
    {
        text.push_str("[run output has gaps or evicted history]\n");
    }
    for log in answer["logs"].as_array().into_iter().flatten() {
        let stream = match log["stream"].as_str() {
            Some("stderr") => "stderr",
            _ => "stdout",
        };
        let truncated = if log["truncated"].as_bool() == Some(true) {
            " truncated"
        } else {
            ""
        };
        let _ = writeln!(
            text,
            "[{stream}{truncated}] {}",
            safe_text(log["body"].as_str().unwrap_or_default())
        );
    }
    Output::with_text(answer, text)
}

fn outcome(value: &Value) -> Option<i32> {
    match value["state"].as_str()? {
        "RUN_STATE_SUCCEEDED" | "RUN_STATE_FAILED" => {
            if let Some(signal) = value["signal"].as_i64() {
                Some(
                    i32::try_from(signal)
                        .ok()
                        .filter(|n| (1..=127).contains(n))
                        .map_or(125, |n| 128 + n),
                )
            } else {
                Some(
                    value["exitCode"]
                        .as_i64()
                        .and_then(|n| i32::try_from(n).ok())
                        .filter(|n| (0..=255).contains(n))
                        .unwrap_or(125),
                )
            }
        }
        "RUN_STATE_TIMED_OUT" => Some(124),
        "RUN_STATE_CANCELLED" => Some(130),
        "RUN_STATE_UNKNOWN" | "RUN_STATE_NOT_STARTED" => Some(125),
        _ => None,
    }
}

fn finished(answer: Value, status: i32) -> Output {
    let run = &answer["run"];
    let id = safe_text(run["id"].as_str().unwrap_or_default());
    let state = safe_text(run["state"].as_str().unwrap_or("unknown"));
    let mut output =
        Output::with_text(answer, format!("Run {id}: {state} (exit {status})\n")).exit(status);
    output.text = crate::output::Text::Stream;
    output
}

async fn page(api: &Api, org: &str, id: &str, cursor: &mut String, size: u32) -> CliResult<Value> {
    let answer = api
        .call(
            &rpc("ListRunLogs"),
            json!({"organisation":org,"id":id,"pageSize":size,"pageToken":cursor}),
        )
        .await?;
    let next = answer["nextPageToken"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CliError::new(Code::Failed, "the instance did not return a run log cursor")
        })?;
    if next == cursor
        && answer["logs"]
            .as_array()
            .is_some_and(|logs| !logs.is_empty())
    {
        return Err(CliError::new(
            Code::Failed,
            "the instance did not advance the run log cursor",
        ));
    }
    *cursor = next.to_string();
    Ok(answer)
}

async fn wait(ctx: &Ctx, api: &Api, org: &str, id: &str, mut answer: Value) -> Output {
    use std::os::fd::AsFd;
    let stdout = match std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .and_then(FollowOutput::new)
    {
        Ok(stdout) => stdout,
        Err(_) => {
            eprintln!(
                "Run {}: cannot write output; inspect with grund stack run-status {}",
                safe_text(id),
                safe_text(id)
            );
            return finished(answer, 125);
        }
    };
    let mut cursor = String::new();
    let following = async {
        let mut terminal_seen = None;
        loop {
            let logs = page(api, org, id, &mut cursor, 200).await?;
            let caught_up = logs["logs"].as_array().is_none_or(Vec::is_empty);
            if !stdout.write_page(&logs_output(logs), ctx.format).await? {
                return Err(CliError::new(Code::Failed, "output was closed"));
            }
            answer = api
                .call(&rpc("GetRun"), json!({"organisation":org,"id":id}))
                .await?;
            if let Some(status) = outcome(&answer["run"]) {
                let elapsed = terminal_seen
                    .get_or_insert_with(tokio::time::Instant::now)
                    .elapsed();
                if (caught_up && elapsed >= Duration::from_secs(12))
                    || elapsed >= Duration::from_secs(15)
                {
                    eprintln!(
                        "Run {}: output delivery is best-effort; later records remain available through run-logs",
                        safe_text(id)
                    );
                    return Ok(status);
                }
            }
            if caught_up {
                tokio::time::sleep(POLL).await;
            }
        }
    };
    let result = tokio::select! {
        result = following => Some(result),
        _ = tokio::signal::ctrl_c() => None,
    };
    match result {
        Some(Ok(status)) => finished(answer, status),
        Some(Err(_)) => {
            let status = outcome(&answer["run"]);
            eprintln!(
                "Run {}: output or observation failed; inspect run-status and run-logs. {}",
                safe_text(id),
                if status.is_some() {
                    "The known outcome is retained."
                } else {
                    "The command may still be running."
                }
            );
            finished(answer, status.unwrap_or(125))
        }
        None => {
            if let Some(status) = outcome(&answer["run"]) {
                return finished(answer, status);
            }
            let cancel = api
                .call(
                    &rpc("CancelRun"),
                    json!({"organisation":org,"id":id,"idempotencyKey":Uuid::now_v7().to_string()}),
                )
                .await;
            match cancel {
                Ok(cancelled) => {
                    let confirmed = cancelled["run"]["stopConfirmed"].as_bool() == Some(true);
                    eprintln!(
                        "Run {}: cancellation requested; stop {}",
                        safe_text(id),
                        if confirmed {
                            "confirmed"
                        } else {
                            "not confirmed"
                        }
                    );
                    let status =
                        outcome(&cancelled["run"]).unwrap_or(if confirmed { 130 } else { 125 });
                    finished(cancelled, status)
                }
                Err(_) => {
                    eprintln!(
                        "Run {}: cancellation could not be confirmed; inspect run-status",
                        safe_text(id)
                    );
                    let status = outcome(&answer["run"]).unwrap_or(125);
                    finished(answer, status)
                }
            }
        }
    }
}

fn creation_error(error: CliError, dry_run: bool) -> CliError {
    if !dry_run && matches!(error.code, Code::Unavailable | Code::Failed) {
        CliError::new(
            Code::UnknownExecution,
            "could not confirm whether a run was created",
        )
        .hint("Inspect grund stack run-list before deciding whether to try again; do not retry with a new idempotency key.")
    } else {
        error
    }
}

/// Starts one command without changing the stack; following it never retries work.
pub async fn create(ctx: &Ctx, args: RunArgs) -> CliResult<Output> {
    if args.args.len() > 128
        || args.args.iter().map(String::len).sum::<usize>() > 32768
        || args.args.iter().any(|s| s.contains('\0'))
    {
        return Err(CliError::new(
            Code::Invalid,
            "use at most 128 arguments and 32 KiB, without NUL bytes",
        ));
    }
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    let key = args
        .idempotency_key
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let answer = api.call(&rpc("CreateRun"), json!({"organisation":org,"stack":args.stack,"service":args.service,"args":args.args,"timeoutSeconds":args.timeout.as_secs(),"idempotencyKey":key,"dryRun":args.dry_run})).await.map_err(|error| creation_error(error, args.dry_run))?;
    if args.dry_run {
        return Ok(Output::with_text(
            answer,
            "Run validated; nothing started.\n".into(),
        ));
    }
    let id = answer["run"]["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            creation_error(
                CliError::new(Code::Failed, "the instance did not return a run id"),
                false,
            )
        })?
        .to_string();
    eprintln!("Run {}", safe_text(&id));
    Ok(wait(ctx, &api, &org, &id, answer).await)
}

/// Reads one run and its retained argument audit attachment.
pub async fn status(ctx: &Ctx, id: String) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    Ok(Output::fields(
        api.call(&rpc("GetRun"), json!({"organisation":org,"id":id}))
            .await?,
    ))
}

/// Lists run metadata without argument bodies.
pub async fn list(ctx: &Ctx, args: RunListArgs) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    let answer = api.call(&rpc("ListRuns"), json!({"organisation":org,"stack":args.stack,"service":args.service.unwrap_or_default(),"pageSize":args.page_size,"pageToken":args.page_token.unwrap_or_default()})).await?;
    Ok(Output::table(
        answer,
        "/runs",
        &[
            ("ID", "/id"),
            ("SERVICE", "/service"),
            ("STATE", "/state"),
            ("EXIT", "/exitCode"),
        ],
    ))
}

/// Requests stop; confirmation and application outcome remain explicit.
pub async fn cancel(
    ctx: &Ctx,
    id: String,
    key: Option<String>,
    dry_run: bool,
) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    Ok(Output::fields(api.call(&rpc("CancelRun"), json!({"organisation":org,"id":id,"idempotencyKey":key.unwrap_or_else(|| Uuid::now_v7().to_string()),"dryRun":dry_run})).await?))
}

/// Reads isolated run output; following never creates or cancels a run.
pub async fn logs(ctx: &Ctx, args: RunLogsArgs) -> CliResult<Option<Output>> {
    use std::os::fd::AsFd;
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    let mut cursor = args.page_token.unwrap_or_default();
    if !args.follow {
        return Ok(Some(logs_output(
            page(&api, &org, &args.id, &mut cursor, args.page_size).await?,
        )));
    }
    let stdout = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .and_then(FollowOutput::new)
        .map_err(|_| CliError::new(Code::Failed, "cannot write run output"))?;
    let following = async {
        loop {
            let answer = page(&api, &org, &args.id, &mut cursor, args.page_size).await?;
            let caught_up = answer["logs"].as_array().is_none_or(Vec::is_empty);
            if !stdout.write_page(&logs_output(answer), ctx.format).await? {
                return Ok(None);
            }
            if caught_up {
                tokio::time::sleep(POLL).await;
            }
        }
    };
    tokio::select! {
        result = following => result,
        _ = tokio::signal::ctrl_c() => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Format;

    #[test]
    fn a_lost_creation_reply_reports_unknown_execution_not_retryable_unavailability() {
        for code in [Code::Unavailable, Code::Failed] {
            let error = creation_error(CliError::new(code, "unconfirmed response"), false);
            assert_eq!(error.code.exit_status(), 125);
            assert_eq!(error.code.as_str(), "unknown_execution");
        }
        assert_eq!(
            creation_error(CliError::new(Code::PermissionDenied, "not an owner"), false).code,
            Code::PermissionDenied,
        );
        assert_eq!(
            creation_error(CliError::new(Code::Unavailable, "offline"), true).code,
            Code::Unavailable,
        );
    }

    #[test]
    fn application_exit_codes_do_not_become_cli_error_codes() {
        for code in [0, 1, 23, 124, 125, 130, 255] {
            assert_eq!(
                outcome(&json!({"state":"RUN_STATE_FAILED","exitCode":code})),
                Some(code)
            );
        }
        assert_eq!(outcome(&json!({"state":"RUN_STATE_FAILED"})), Some(125));
        assert_eq!(outcome(&json!({"state":"RUN_STATE_RUNNING"})), None);
        assert_eq!(
            outcome(&json!({"state":"RUN_STATE_FAILED","signal":9})),
            Some(137)
        );
        assert_eq!(outcome(&json!({"state":"RUN_STATE_UNKNOWN"})), Some(125));
        assert_eq!(outcome(&json!({"state":"RUN_STATE_TIMED_OUT"})), Some(124));
    }

    #[test]
    fn deadline_input_cannot_overflow_or_exceed_one_hour() {
        assert_eq!(timeout("10m"), Ok(Duration::from_secs(600)));
        assert_eq!(timeout("1h"), Ok(Duration::from_secs(3600)));
        for invalid in ["0", "3601", "2h", "4294967295h", "-1s"] {
            assert!(timeout(invalid).is_err());
        }
    }

    #[test]
    fn run_output_cannot_inject_terminal_controls() {
        let output =
            logs_output(json!({"logs":[{"stream":"stderr","body":"\u{1b}[2Jsecret\u{202e}"}]}));
        let text = output.render(Format::Text);
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{202e}'));
        assert!(text.contains("stderr"));
    }

    #[test]
    fn the_final_run_outcome_stays_parseable_after_json_log_pages() {
        let logs = json!({"logs":[{"stream":"stdout","body":"first\nsecond"}]});
        let outcome = finished(
            json!({"run":{"id":"run-id","state":"RUN_STATE_FAILED","exitCode":23}}),
            23,
        );
        let stream = format!("{logs}\n{}", outcome.render(Format::Json));
        let received = stream
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(received[0]["logs"][0]["body"], "first\nsecond");
        assert_eq!(received[1]["run"]["exitCode"], 23);
        assert_eq!(outcome.status, 23);
    }
}
