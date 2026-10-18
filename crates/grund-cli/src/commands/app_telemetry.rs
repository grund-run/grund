use std::{
    fmt::Write as _,
    io,
    os::fd::{AsFd, OwnedFd},
    time::Duration,
};

use chrono::{DateTime, SecondsFormat, Utc};
use clap::Args;
use serde_json::{Value, json};

use crate::{
    api::Api,
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::{Format, Output},
};

const LOGS_RPC: &str = "grund.app.v1.AppTelemetryService/ListAppLogs";
const METRICS_RPC: &str = "grund.app.v1.AppTelemetryService/GetAppMetrics";
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Filters for retained app output and live following.
#[derive(Debug, Args)]
pub struct LogOptions {
    #[arg(
        long,
        help = "Drain all retained matching output, then follow until Ctrl-C; JSON lines or YAML documents"
    )]
    pub follow: bool,
    #[arg(
        long,
        value_name = "ID",
        help = "Only this app instance; --instance URL still selects the server"
    )]
    pub instance_id: Option<String>,
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..), help = "Only this release number")]
    pub release: Option<u32>,
    #[arg(
        long,
        value_name = "TIME",
        help = "Observed at or after RFC3339 time or duration ago (30s, 15m, 1h30m, 1d, 1w)"
    )]
    pub since: Option<String>,
    #[arg(
        long,
        value_name = "TIME",
        help = "Observed before RFC3339 time or duration ago; relative times are fixed when starting"
    )]
    pub until: Option<String>,
    #[arg(
        long,
        value_name = "TEXT",
        help = "Case-insensitive literal substring, at most 200 bytes"
    )]
    pub search: Option<String>,
    #[arg(long, value_parser = ["stdout", "stderr", "combined"], help = "Only this output stream; combined is older output without separate streams")]
    pub stream: Option<String>,
    #[arg(long, default_value_t = 200, value_name = "N", value_parser = clap::value_parser!(u16).range(1..=1000), help = "Maximum records for one read; with --follow, records per page, not a total limit")]
    pub limit: u16,
}

/// An app selector and its retained-output filters.
#[derive(Debug, Args)]
pub struct LogsArgs {
    #[arg(value_name = "APP")]
    pub app: String,
    #[command(flatten)]
    pub options: LogOptions,
}

/// The time range and identity filters for measured app usage.
#[derive(Debug, Args)]
pub struct MetricOptions {
    #[arg(long, default_value = "hour", value_parser = ["hour", "day", "week"], help = "Hour: 10-second buckets; day: 1-minute buckets; week: 10-minute buckets")]
    pub range: String,
    #[arg(
        long,
        value_name = "ID",
        help = "Only this app instance; --instance URL still selects the server"
    )]
    pub instance_id: Option<String>,
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..), help = "Only this release number")]
    pub release: Option<u32>,
}

/// An app selector and its measured-usage filters.
#[derive(Debug, Args)]
pub struct MetricsArgs {
    #[arg(value_name = "APP")]
    pub app: String,
    #[command(flatten)]
    pub options: MetricOptions,
}

/// Reads one bounded page without modifying the app or the instance.
pub async fn logs(api: &Api, org: &str, args: LogsArgs) -> CliResult<Output> {
    let request = logs_request(org, &args, Utc::now())?;
    let answer = api.call(LOGS_RPC, request).await?;
    let mut output = logs_output(answer, true);
    let _ = writeln!(
        output.own,
        "One page, at most {} records. Use --follow to drain all retained matches and wait for more.",
        args.options.limit
    );
    Ok(output)
}

/// Reads measured buckets without filling missing values or missing buckets.
pub async fn metrics(api: &Api, org: &str, args: MetricsArgs) -> CliResult<Output> {
    let mut request = json!({"organisation": org, "name": args.app, "range": args.options.range});
    if let Some(instance) = args.options.instance_id {
        request["instance"] = json!(instance);
    }
    if let Some(release) = args.options.release {
        request["release"] = json!(release);
    }
    let answer = api.call(METRICS_RPC, request).await?;
    Ok(metrics_output(answer))
}

/// Follows ingestion cursors, cancelling both requests and idle waits on Ctrl-C.
pub async fn follow(ctx: &Ctx, api: &Api, org: &str, args: LogsArgs) -> CliResult<()> {
    tokio::select! {
        signal = tokio::signal::ctrl_c() => signal.map_err(|error| {
            CliError::new(Code::Failed, format!("could not listen for Ctrl-C: {error}"))
        }),
        result = follow_pages(ctx, api, org, args) => result,
    }
}

async fn follow_pages(ctx: &Ctx, api: &Api, org: &str, args: LogsArgs) -> CliResult<()> {
    let mut request = logs_request(org, &args, Utc::now())?;
    let stdout = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .and_then(FollowOutput::new)
        .map_err(output_error)?;
    let mut first = true;
    let mut dropped = Value::Null;
    let mut gaps = Value::Null;
    let mut delivery_window = Value::Null;
    loop {
        let answer = api.call(LOGS_RPC, request.clone()).await?;
        let caught_up = advance_cursor(&mut request, &answer)?;
        let metadata = first
            || answer["droppedRecords"] != dropped
            || answer["gaps"] != gaps
            || answer["deliveryWindowHours"] != delivery_window;
        let mut output = logs_output(answer, metadata);
        if !stdout.write_page(&output, ctx.format).await? {
            return Ok(());
        }
        dropped = output.value["droppedRecords"].take();
        gaps = output.value["gaps"].take();
        delivery_window = output.value["deliveryWindowHours"].take();
        first = false;
        if caught_up {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

fn advance_cursor(request: &mut Value, answer: &Value) -> CliResult<bool> {
    let token = answer["nextPageToken"]
        .as_str()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            CliError::new(
                Code::Failed,
                "the instance did not return a log follow cursor",
            )
        })?;
    let caught_up = answer["logs"].as_array().is_none_or(Vec::is_empty);
    if !caught_up && request["pageToken"].as_str() == Some(token) {
        return Err(CliError::new(
            Code::Failed,
            "the instance did not advance the log cursor",
        ));
    }
    request["pageToken"] = json!(token);
    Ok(caught_up)
}

struct FollowOutput {
    fd: OwnedFd,
    original_flags: rustix::fs::OFlags,
    readiness: Option<tokio::io::unix::AsyncFd<OwnedFd>>,
}

impl FollowOutput {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        let original_flags = rustix::fs::fcntl_getfl(&fd)?;
        rustix::fs::fcntl_setfl(&fd, original_flags | rustix::fs::OFlags::NONBLOCK)?;
        let mut output = Self {
            fd,
            original_flags,
            readiness: None,
        };
        match tokio::io::unix::AsyncFd::new(output.fd.try_clone()?) {
            Ok(readiness) => output.readiness = Some(readiness),
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {}
            Err(error) => return Err(error),
        }
        Ok(output)
    }

    async fn write_page(&self, output: &Output, format: Format) -> CliResult<bool> {
        let text = match format {
            Format::Json => format!("{}\n", output.value),
            Format::Yaml => format!("---\n{}", output.render(Format::Yaml)),
            Format::Text => output.render(Format::Text),
        };
        let mut remaining = text.as_bytes();
        while !remaining.is_empty() {
            let result = if let Some(readiness) = &self.readiness {
                let mut ready = readiness.writable().await.map_err(output_error)?;
                match ready.try_io(|fd| {
                    rustix::io::write(fd.get_ref(), remaining).map_err(io::Error::from)
                }) {
                    Ok(result) => result,
                    Err(_) => continue,
                }
            } else {
                rustix::io::write(&self.fd, remaining).map_err(io::Error::from)
            };
            match result {
                Ok(0) => return Err(output_error(io::Error::from(io::ErrorKind::WriteZero))),
                Ok(written) => remaining = &remaining[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return Ok(false),
                Err(error) => return Err(output_error(error)),
            }
        }
        Ok(true)
    }
}

impl Drop for FollowOutput {
    fn drop(&mut self) {
        let _ = rustix::fs::fcntl_setfl(&self.fd, self.original_flags);
    }
}

fn output_error(error: io::Error) -> CliError {
    CliError::new(Code::Failed, format!("could not write app output: {error}"))
}

fn logs_request(org: &str, args: &LogsArgs, now: DateTime<Utc>) -> CliResult<Value> {
    let mut request =
        json!({"organisation": org, "name": args.app, "pageSize": args.options.limit});
    if let Some(instance) = &args.options.instance_id {
        request["instance"] = json!(instance);
    }
    if let Some(release) = args.options.release {
        request["release"] = json!(release);
    }
    if let Some(search) = &args.options.search {
        if search.len() > 200 {
            return Err(CliError::usage("--search is at most 200 bytes").field("search"));
        }
        request["search"] = json!(search);
    }
    if let Some(stream) = &args.options.stream {
        request["stream"] = json!(stream);
    }
    let since = args
        .options
        .since
        .as_deref()
        .map(|text| parse_time(text, now, "since"))
        .transpose()?;
    let until = args
        .options
        .until
        .as_deref()
        .map(|text| parse_time(text, now, "until"))
        .transpose()?;
    if since
        .zip(until)
        .is_some_and(|(since, until)| since >= until)
    {
        return Err(CliError::usage("--since must be earlier than --until").field("until"));
    }
    for (key, time) in [("since", since), ("until", until)] {
        if let Some(time) = time {
            request[key] = json!(time.to_rfc3339_opts(SecondsFormat::AutoSi, true));
        }
    }
    Ok(request)
}

fn parse_time(text: &str, now: DateTime<Utc>, field: &str) -> CliResult<DateTime<Utc>> {
    if let Ok(time) = DateTime::parse_from_rfc3339(text) {
        return Ok(time.with_timezone(&Utc));
    }
    let invalid = || {
        CliError::usage(format!(
            "--{field}: use an RFC3339 time or duration such as 30s, 15m or 1h30m"
        ))
        .field(field)
    };
    let mut seconds = 0i64;
    let mut rest = text;
    if rest.is_empty() {
        return Err(invalid());
    }
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(invalid());
        }
        let number = rest[..digits].parse::<i64>().map_err(|_| invalid())?;
        let unit = rest.as_bytes().get(digits).ok_or_else(invalid)?;
        let multiplier = match unit {
            b's' => 1,
            b'm' => 60,
            b'h' => 3600,
            b'd' => 86400,
            b'w' => 604800,
            _ => return Err(invalid()),
        };
        seconds = number
            .checked_mul(multiplier)
            .and_then(|value| seconds.checked_add(value))
            .ok_or_else(invalid)?;
        rest = &rest[digits + 1..];
    }
    chrono::TimeDelta::try_seconds(seconds)
        .and_then(|duration| now.checked_sub_signed(duration))
        .ok_or_else(invalid)
}

fn logs_output(answer: Value, metadata: bool) -> Output {
    let mut text = String::new();
    if metadata {
        text.push_str("Observed times are collection times, not app emission times. Output may contain sensitive data.\n");
        let _ = writeln!(
            text,
            "Retained: {} hours; payload bound: {} bytes (not database size).",
            known(&answer, "retentionHours"),
            known(&answer, "payloadLimitBytes")
        );
        let _ = writeln!(
            text,
            "Retained-history evictions for this app: {}. Collection or delivery gaps may also exist.",
            default_counter(&answer, "droppedRecords")
        );
        delivery_context(&answer, &mut text);
        if answer["gaps"]
            .as_array()
            .is_some_and(|gaps| !gaps.is_empty())
        {
            text.push_str(
                "Log gaps describe delivery coverage, not whether a quiet app emitted output.\n",
            );
        }
    }
    let logs = answer["logs"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if logs.is_empty() && metadata {
        text.push_str("No log records received for these filters.\n");
    }
    for log in logs {
        let truncated = if log["truncated"].as_bool() == Some(true) {
            " truncated"
        } else {
            ""
        };
        let _ = writeln!(
            text,
            "{} instance={} release={} stream={}{} | {}",
            known(log, "observedAt"),
            known(log, "instance"),
            known(log, "release"),
            known(log, "stream"),
            truncated,
            safe_text(log["body"].as_str().unwrap_or_default())
        );
    }
    Output::with_text(answer, text)
}

fn metrics_output(answer: Value) -> Output {
    let mut text = String::new();
    let _ = writeln!(
        text,
        "Range: {} to {}; buckets: {} seconds.",
        known(&answer, "since"),
        known(&answer, "until"),
        known(&answer, "bucketSeconds")
    );
    let _ = writeln!(
        text,
        "Retained: {} days; payload bound: {} bytes (not database size).",
        known(&answer, "retentionDays"),
        known(&answer, "payloadLimitBytes")
    );
    let _ = writeln!(
        text,
        "Memory accounting: {}.",
        known(&answer, "memoryAccounting")
    );
    text.push_str("CPU is measured in millicores; 1000 millicores = 1 vCPU. Memory values are bytes.\nMissing values and absent buckets are unknown, not zero; no interpolation.\n");
    delivery_context(&answer, &mut text);
    let points = answer["points"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if points.is_empty() {
        text.push_str("No measurements received for these filters.\n");
    } else {
        text.push_str("BUCKET\tINSTANCE\tRELEASE\tSAMPLES\tCPU AVG (mCPU)\tCPU RESERVED (mCPU)\tMEMORY AVG (B)\tMEMORY MAX (B)\tMEMORY RESERVED (B)\n");
        for point in points {
            let _ = writeln!(
                text,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                known(point, "at"),
                known(point, "instance"),
                known(point, "release"),
                default_counter(point, "samples"),
                known(point, "cpuMillis"),
                known(point, "reservedCpuMillis"),
                known(point, "memoryBytes"),
                known(point, "memoryMaxBytes"),
                known(point, "reservedMemoryBytes")
            );
        }
    }
    Output::with_text(answer, text)
}

fn delivery_context(answer: &Value, text: &mut String) {
    let _ = writeln!(
        text,
        "Eligible delivery window: {} hours; older buffered batches are rejected.",
        known(answer, "deliveryWindowHours")
    );
    for gap in answer["gaps"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let label = match gap["reason"].as_str() {
            Some("machine_offline") => "not received (machine offline)",
            Some("coverage_unknown") => "coverage unknown (history evicted)",
            _ => "coverage unknown",
        };
        let _ = writeln!(
            text,
            "GAP {} to {} instance={} machine={}: {}",
            known(gap, "since"),
            known(gap, "until"),
            known(gap, "instance"),
            known(gap, "machine"),
            label
        );
    }
}

fn known(value: &Value, field: &str) -> String {
    match &value[field] {
        Value::Null => "unknown".to_string(),
        Value::String(text) => safe_text(text),
        value => safe_text(&value.to_string()),
    }
}

fn default_counter(value: &Value, field: &str) -> String {
    if value[field].is_null() {
        "0".to_string()
    } else {
        known(value, field)
    }
}

fn safe_text(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control()
            || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            for escaped in character.escape_default() {
                safe.push(escaped);
            }
        } else {
            safe.push(character);
        }
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_full_pipe_stays_cancellable_and_a_closed_reader_ends_following() {
        let (reader, fd) = rustix::pipe::pipe().unwrap();
        let observer = fd.try_clone().unwrap();
        let original_flags = rustix::fs::fcntl_getfl(&observer).unwrap();
        let writer = FollowOutput::new(fd).unwrap();
        let chunk = [b'x'; 4096];
        loop {
            match rustix::io::write(&writer.fd, &chunk) {
                Ok(_) => {}
                Err(rustix::io::Errno::AGAIN) => break,
                result => panic!("could not fill output pipe: {result:?}"),
            }
        }
        let output = Output::fields(json!({"logs": [{"body": "still following"}]}));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                writer.write_page(&output, Format::Json),
            )
            .await
            .is_err()
        );
        drop(reader);
        assert!(!writer.write_page(&output, Format::Json).await.unwrap());
        drop(writer);
        assert_eq!(rustix::fs::fcntl_getfl(&observer).unwrap(), original_flags);
    }

    #[test]
    fn an_app_instance_filter_never_replaces_the_server_address() {
        use clap::Parser;

        let parsed = crate::Standalone::try_parse_from([
            "grund",
            "apps",
            "logs",
            "web",
            "--instance",
            "https://grund.example.com",
            "--instance-id",
            "copy-id",
            "--limit",
            "1000",
            "--stream",
            "combined",
        ])
        .unwrap();
        let crate::Command::Apps(command) = parsed.command else {
            panic!("expected apps")
        };
        assert_eq!(
            command.global.instance.as_deref(),
            Some("https://grund.example.com")
        );
        let super::super::apps::AppsAction::Logs(args) = command.action else {
            panic!("expected logs")
        };
        assert_eq!(args.options.instance_id.as_deref(), Some("copy-id"));
        for value in ["0", "1001"] {
            assert!(
                crate::Standalone::try_parse_from([
                    "grund", "apps", "logs", "web", "--limit", value
                ])
                .is_err()
            );
        }
        assert!(
            crate::Standalone::try_parse_from([
                "grund", "apps", "metrics", "web", "--range", "month"
            ])
            .is_err()
        );
    }

    #[test]
    fn relative_filters_share_one_clock_and_reject_overflow_or_reversed_ranges() {
        let now = "2026-10-18T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
        assert_eq!(
            parse_time("1h30m", now, "since").unwrap().to_rfc3339(),
            "2026-10-18T10:30:00+00:00"
        );
        assert_eq!(
            parse_time("2026-10-18T12:00:00+02:00", now, "since")
                .unwrap()
                .to_rfc3339(),
            "2026-10-18T10:00:00+00:00"
        );
        for invalid in ["", "-1h", "1", "1.5h", "1hgarbage", "9999999999999999999w"] {
            assert!(parse_time(invalid, now, "since").is_err(), "{invalid}");
        }
        let args = LogsArgs {
            app: "web".into(),
            options: LogOptions {
                follow: false,
                instance_id: None,
                release: None,
                since: Some("1m".into()),
                until: Some("1h".into()),
                search: None,
                stream: None,
                limit: 200,
            },
        };
        assert!(logs_request("acme", &args, now).is_err());
    }

    #[test]
    fn following_keeps_empty_page_cursors_and_drains_partial_backlog_pages() {
        let mut request = json!({"pageSize": 200});
        assert!(
            !advance_cursor(
                &mut request,
                &json!({"logs": [{"body": "old"}], "nextPageToken": "opaque-backlog"})
            )
            .unwrap()
        );
        assert_eq!(request["pageToken"], "opaque-backlog");
        assert!(advance_cursor(&mut request, &json!({"nextPageToken": "opaque-empty"})).unwrap());
        assert_eq!(request["pageToken"], "opaque-empty");
        assert!(
            !advance_cursor(
                &mut request,
                &json!({"logs": [{"body": "late upload"}], "nextPageToken": "opaque-late"})
            )
            .unwrap()
        );
        assert!(
            advance_cursor(
                &mut request,
                &json!({"logs": [{"body": "duplicate"}], "nextPageToken": "opaque-late"})
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_controls_cannot_erase_prefixes_or_add_forged_records() {
        let answer = json!({"logs": [{"observedAt": "2026-10-18T12:00:00Z", "instance": "copy\u{1b}[2J", "release": 3, "stream": "stderr", "body": "hello\r\u{1b}[2J\nforged\u{9b}31m\u{202e}text", "truncated": true}], "droppedRecords": "7"});
        let output = logs_output(answer, true);
        assert!(!output.own.contains('\u{1b}'));
        assert!(!output.own.contains('\r'));
        assert!(!output.own.contains('\u{9b}'));
        assert!(!output.own.contains('\u{202e}'));
        assert!(output.own.contains("stream=stderr truncated | hello\\r"));
        assert!(output.own.contains("\\nforged"));
    }

    #[test]
    fn missing_measurements_are_unknown_but_measured_zero_is_kept() {
        let output = metrics_output(
            json!({"points": [{"at": "2026-10-18T12:00:00Z", "instance": "copy", "release": 1, "samples": 1, "memoryBytes": 0.0, "reservedCpuMillis": 1000, "reservedMemoryBytes": "536870912"}], "memoryAccounting": "memory.current, including cache"}),
        );
        assert!(
            output
                .own
                .contains("\t1\tunknown\t1000\t0.0\tunknown\t536870912")
        );
    }
}
