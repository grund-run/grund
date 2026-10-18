use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use grund_proto::grund::app::v1::ListAppLogsRequest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{services::app_telemetry::AppTelemetryState, state::State};

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TelemetryQuery {
    pub search: String,
    pub instance: String,
    pub range: String,
    pub since: String,
    pub until: String,
    pub before: String,
}

impl TelemetryQuery {
    fn validate(&self) -> Result<&'static Range, String> {
        if !self.instance.is_empty() && Uuid::parse_str(&self.instance).is_err() {
            return Err("Instance must be a full instance identifier.".into());
        }
        if self.search.len() > 200 || self.search.contains('\0') {
            return Err("Search must be at most 200 bytes and cannot contain a null byte.".into());
        }
        range(&self.range).ok_or_else(|| "Choose live, 15m, 1h, 6h, 24h or 7d.".into())
    }
}

/// A time range offered by the telemetry tabs, and the metrics range it reads.
pub struct Range {
    pub key: &'static str,
    pub label: &'static str,
    pub metrics: &'static str,
    pub seconds: i64,
    pub logs: bool,
}

pub const RANGES: [Range; 6] = [
    Range {
        key: "live",
        label: "Live",
        metrics: "hour",
        seconds: 900,
        logs: true,
    },
    Range {
        key: "15m",
        label: "15m",
        metrics: "hour",
        seconds: 900,
        logs: true,
    },
    Range {
        key: "1h",
        label: "1h",
        metrics: "hour",
        seconds: 3600,
        logs: true,
    },
    Range {
        key: "6h",
        label: "6h",
        metrics: "day",
        seconds: 21600,
        logs: true,
    },
    Range {
        key: "24h",
        label: "24h",
        metrics: "day",
        seconds: 86400,
        logs: true,
    },
    Range {
        key: "7d",
        label: "7d",
        metrics: "week",
        seconds: 604800,
        logs: false,
    },
];

/// Resolves a range key; empty is live, and the earlier hour/day/week links still work.
pub fn range(key: &str) -> Option<&'static Range> {
    let key = match key {
        "" => "live",
        "hour" => "1h",
        "day" => "24h",
        "week" => "7d",
        key => key,
    };
    RANGES.iter().find(|range| range.key == key)
}

pub struct RangeLink {
    pub label: &'static str,
    pub href: String,
    pub current: bool,
    pub live: bool,
}

/// The one filter row of a telemetry tab.
pub struct Toolbar {
    pub action: String,
    pub range: &'static str,
    pub ranges: Vec<RangeLink>,
    pub search: Option<String>,
    pub instance: String,
    pub instances: Vec<(String, String)>,
    pub zoom: Option<Zoom>,
}

/// A time window chosen on the volume chart, with the link that leaves it.
pub struct Zoom {
    pub label: String,
    pub since: String,
    pub until: String,
    pub reset: String,
}

#[derive(Serialize)]
struct Link<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    range: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    search: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    instance: &'a str,
}

impl Toolbar {
    fn new(
        action: String,
        query: &TelemetryQuery,
        logs: bool,
        current_instances: &[String],
    ) -> Self {
        let current = range(&query.range).unwrap_or(&RANGES[0]);
        let ranges = RANGES
            .iter()
            .filter(|range| range.logs || !logs)
            .map(|range| {
                let link = Link {
                    range: if range.key == "live" { "" } else { range.key },
                    search: &query.search,
                    instance: &query.instance,
                };
                let query = serde_urlencoded::to_string(&link).unwrap_or_default();
                RangeLink {
                    label: range.label,
                    href: if query.is_empty() {
                        action.clone()
                    } else {
                        format!("{action}?{query}")
                    },
                    current: range.key == current.key,
                    live: range.key == "live",
                }
            })
            .collect();
        let mut instances: Vec<(String, String)> = current_instances
            .iter()
            .chain((!query.instance.is_empty()).then_some(&query.instance))
            .map(|instance| (instance.clone(), short(instance)))
            .collect();
        instances.sort();
        instances.dedup();
        if instances.len() > 1 {
            instances.insert(
                0,
                (
                    String::new(),
                    format!("All instances ({})", instances.len()),
                ),
            );
        } else {
            instances.clear();
        }
        Self {
            action,
            range: if current.key == "live" {
                ""
            } else {
                current.key
            },
            ranges,
            search: logs.then(|| query.search.clone()),
            instance: query.instance.clone(),
            instances,
            zoom: None,
        }
    }
}

/// The last four hex digits of an instance identifier, as the charts and log lines show it.
pub fn short(instance: &str) -> String {
    let digits: String = instance.chars().filter(char::is_ascii_hexdigit).collect();
    digits[digits.len().saturating_sub(4)..].to_string()
}

/// A run of log text with the classes its ANSI SGR codes selected.
pub struct Span {
    pub class: String,
    pub text: String,
}

pub struct LogLine {
    pub cursor: String,
    pub iso: String,
    pub clock: String,
    pub millis: String,
    pub title: String,
    pub instance: String,
    pub short: String,
    pub stream: String,
    pub spans: Vec<Span>,
    pub truncated: bool,
}

impl LogLine {
    fn new(log: grund_proto::grund::app::v1::AppLog) -> Self {
        let observed = log.observed_at.as_option().and_then(at);
        Self {
            iso: observed
                .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                .unwrap_or_default(),
            clock: observed
                .map(|at| at.format("%H:%M:%S").to_string())
                .unwrap_or_else(|| "--:--:--".into()),
            millis: observed
                .map(|at| at.format("%.3f").to_string())
                .unwrap_or_default(),
            title: observed
                .map(|at| {
                    format!(
                        "Collected {}. Collection time, not necessarily when the app wrote it.",
                        at.format("%Y-%m-%d %H:%M:%S%.3f UTC")
                    )
                })
                .unwrap_or_else(|| "Collection time not reported.".into()),
            short: short(&log.instance),
            instance: log.instance,
            stream: log.stream,
            spans: ansi(&log.body),
            truncated: log.truncated,
            cursor: log.cursor,
        }
    }
}

/// Splits app output into styled runs. Only colour, bold and dim SGR codes
/// style text; every other control or direction character stays visible as
/// an inert `\u{…}` escape, so output cannot move the cursor or reorder text.
pub fn ansi(body: &str) -> Vec<Span> {
    let mut spans: Vec<Span> = Vec::new();
    let mut bold = false;
    let mut dim = false;
    let mut colour: Option<&'static str> = None;
    let mut rest = body;
    let mut push = |text: &str, bold: bool, dim: bool, colour: Option<&'static str>| {
        if text.is_empty() {
            return;
        }
        let class = [
            bold.then_some("ansi-bold"),
            dim.then_some("ansi-dim"),
            colour,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        match spans.last_mut() {
            Some(last) if last.class == class => last.text.push_str(&inert_text(text)),
            _ => spans.push(Span {
                class,
                text: inert_text(text),
            }),
        }
    };
    while let Some(start) = rest.find("\u{1b}[") {
        let params = &rest[start + 2..];
        let end = params.find(|ch: char| !(ch.is_ascii_digit() || ch == ';'));
        match end {
            Some(end) if params[end..].starts_with('m') => {
                push(&rest[..start], bold, dim, colour);
                let mut codes = params[..end].split(';');
                while let Some(code) = codes.next() {
                    match code.parse::<u8>().unwrap_or(0) {
                        38 | 48 => {
                            let skip = if codes.next() == Some("2") { 3 } else { 1 };
                            codes.by_ref().take(skip).for_each(drop);
                        }
                        0 => (bold, dim, colour) = (false, false, None),
                        1 => bold = true,
                        2 => dim = true,
                        22 => (bold, dim) = (false, false),
                        39 => colour = None,
                        code @ (31..=36 | 91..=96) => {
                            colour = Some(
                                [
                                    "ansi-red",
                                    "ansi-green",
                                    "ansi-yellow",
                                    "ansi-blue",
                                    "ansi-magenta",
                                    "ansi-cyan",
                                ][usize::from(code % 30 - 1)],
                            )
                        }
                        _ => {}
                    }
                }
                rest = &params[end + 1..];
            }
            _ => {
                push(&rest[..start + 1], bold, dim, colour);
                rest = &rest[start + 1..];
            }
        }
    }
    push(rest, bold, dim, colour);
    spans
}

#[derive(Default)]
pub struct RestartControls {
    pub action: String,
    pub csrf: String,
    pub manages: bool,
    pub single_copy: bool,
    pub current_instances: Vec<String>,
    pub separate_instances: Vec<Uuid>,
}

impl RestartControls {
    pub fn required(&self, logs: &[LogLine]) -> bool {
        self.manages
            && self.current_instances.iter().any(|instance| {
                !Uuid::parse_str(instance).is_ok_and(|id| self.separate_instances.contains(&id))
                    && logs
                        .iter()
                        .any(|log| log.instance == *instance && log.stream == "combined")
                    && !logs.iter().any(|log| {
                        log.instance == *instance
                            && matches!(log.stream.as_str(), "stdout" | "stderr")
                    })
            })
    }
}

pub struct LogsPage {
    pub bar: Toolbar,
    pub error: String,
    pub organisation: String,
    pub name: String,
    pub lines: Vec<LogLine>,
    pub instances: bool,
    pub since: String,
    pub until: String,
    pub forward: String,
    pub older: String,
    pub older_href: String,
    pub foot: String,
    pub restart: RestartControls,
}

pub struct MetricsPage {
    pub bar: Toolbar,
    pub error: String,
    pub organisation: String,
    pub name: String,
}

fn time(value: &str) -> Result<Option<DateTime<Utc>>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    DateTime::parse_from_rfc3339(value)
        .map(|value| Some(value.with_timezone(&Utc)))
        .map_err(|_| "Times must include a timezone, for example 2026-10-18T12:00:00Z.".into())
}

fn at(value: &Timestamp) -> Option<DateTime<Utc>> {
    u32::try_from(value.nanos)
        .ok()
        .and_then(|nanos| DateTime::from_timestamp(value.seconds, nanos))
}

pub fn inert_text(value: &str) -> String {
    value.chars().fold(String::new(), |mut text, ch| {
        if ch.is_control() && ch != '\n' && ch != '\t' || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            use std::fmt::Write;
            let _ = write!(text, "\\u{{{:04x}}}", u32::from(ch));
        } else {
            text.push(ch);
        }
        text
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn render(
    state: &State,
    organisation_id: Uuid,
    app_id: Uuid,
    organisation: &str,
    name: &str,
    base: &str,
    tab: &str,
    query: TelemetryQuery,
    restart: RestartControls,
    instances: &[String],
) -> String {
    if tab == "logs" {
        let mut bar = Toolbar::new(format!("{base}/logs"), &query, true, instances);
        let mut page = LogsPage {
            instances: !bar.instances.is_empty() && query.instance.is_empty(),
            bar: Toolbar::new(String::new(), &TelemetryQuery::default(), true, &[]),
            error: String::new(),
            organisation: organisation.into(),
            name: name.into(),
            lines: Vec::new(),
            since: String::new(),
            until: String::new(),
            forward: String::new(),
            older: String::new(),
            older_href: String::new(),
            foot: String::new(),
            restart,
        };
        let request = (|| {
            let range = query.validate()?;
            let now = Utc::now();
            let zoomed = time(&query.since)?.zip(time(&query.until)?);
            if let Some((since, until)) = zoomed {
                if since >= until || until - since > chrono::Duration::days(7) {
                    return Err("Choose a time window of at most seven days.".to_string());
                }
                bar.zoom = Some(Zoom {
                    label: format!("{}–{}", since.format("%H:%M"), until.format("%H:%M")),
                    since: query.since.clone(),
                    until: query.until.clone(),
                    reset: bar
                        .ranges
                        .iter()
                        .find(|link| link.current)
                        .map(|link| link.href.clone())
                        .unwrap_or_default(),
                });
            }
            let (since, until) = zoomed.map_or_else(
                || {
                    let since = now - chrono::Duration::seconds(range.seconds);
                    (
                        DateTime::from_timestamp(since.timestamp(), 0).unwrap_or(since),
                        None,
                    )
                },
                |(since, until)| (since, Some(until)),
            );
            let stamp = |at: DateTime<Utc>| {
                Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32)
            };
            page.since = since.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
            page.until = until
                .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
                .unwrap_or_default();
            Ok(ListAppLogsRequest {
                organisation: organisation.into(),
                name: name.into(),
                instance: query.instance.clone(),
                since: stamp(since).into(),
                until: until.map(|at| stamp(at).into()).unwrap_or_default(),
                search: query.search.clone(),
                page_size: 200,
                page_token: query.before.clone(),
                newest_first: true,
                ..Default::default()
            })
        })();
        match request {
            Err(error) => page.error = error,
            Ok(request) => match state
                .app_telemetry()
                .logs(organisation_id, app_id, &request)
                .await
            {
                Err(error) => {
                    tracing::warn!(error = %error, "app logs query failed");
                    page.error = error
                        .downcast_ref::<crate::services::app_telemetry::Invalid>()
                        .map(|error| error.to_string())
                        .unwrap_or_else(|| "Logs could not be loaded. Try again.".into());
                }
                Ok(response) => {
                    page.forward = response.next_page_token;
                    page.older = response.previous_page_token;
                    if !page.older.is_empty() {
                        let older = TelemetryQuery {
                            before: page.older.clone(),
                            range: bar.range.into(),
                            ..query
                        };
                        page.older_href = format!(
                            "{}?{}",
                            bar.action,
                            serde_urlencoded::to_string(&older).unwrap_or_default()
                        );
                    }
                    page.lines = response.logs.into_iter().map(LogLine::new).collect();
                    page.foot = format!(
                        "Kept {} hours, up to {} MiB per organisation.",
                        response.retention_hours,
                        response.payload_limit_bytes / 1_048_576
                    );
                    if response.dropped_records > 0 {
                        page.foot.push_str(&format!(
                            " {} older records were removed at these limits.",
                            response.dropped_records
                        ));
                    }
                }
            },
        }
        page.bar = bar;
        crate::templates::compiled::pages::app_logs::render(&page)
    } else {
        let mut page = MetricsPage {
            bar: Toolbar::new(format!("{base}/metrics"), &query, false, instances),
            error: String::new(),
            organisation: organisation.into(),
            name: name.into(),
        };
        if let Err(error) = query.validate() {
            page.error = error;
        }
        crate::templates::compiled::pages::app_metrics::render(&page)
    }
}

/// Style-guide example lines: stdout, stderr, ANSI, an inert control byte and a truncated record.
pub fn example_lines() -> Vec<LogLine> {
    let start = DateTime::from_timestamp(1_760_788_800, 0).unwrap();
    [
        (
            "stdout",
            "GET /api/orders 200 \u{1b}[2m12ms\u{1b}[0m",
            false,
        ),
        (
            "stdout",
            "\u{1b}[32mINFO\u{1b}[0m worker: processed batch size=64",
            false,
        ),
        (
            "stderr",
            "\u{1b}[31;1mERROR\u{1b}[0m payment provider timeout after 5000ms",
            false,
        ),
        (
            "stderr",
            "\u{1b}[33mWARN\u{1b}[0m <script> is text and \u{1b}]0;title\u{7} is inert",
            false,
        ),
        ("stdout", "Example: a record cut at the 8 KiB limit", true),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (stream, body, truncated))| {
        LogLine::new(grund_proto::grund::app::v1::AppLog {
            cursor: format!("example-{index}"),
            observed_at: Timestamp::from_unix(start.timestamp() + index as i64, 125_000_000).into(),
            instance: format!("019a0000-0000-7000-8000-00000000{:04x}", 0x3f2a + index % 2),
            stream: stream.into(),
            body: body.into(),
            truncated,
            ..Default::default()
        })
    })
    .collect()
}

/// A style-guide example of the logs filter row, zoomed into a window.
pub fn example_toolbar() -> Toolbar {
    let query = TelemetryQuery {
        range: "1h".into(),
        search: "timeout".into(),
        ..Default::default()
    };
    let mut bar = Toolbar::new(
        "#sg-telemetry".into(),
        &query,
        true,
        &[
            "019a0000-0000-7000-8000-000000003f2a".into(),
            "019a0000-0000-7000-8000-000000009c1e".into(),
        ],
    );
    bar.zoom = Some(Zoom {
        label: "10:34–10:37".into(),
        since: "2026-10-18T10:34:00Z".into(),
        until: "2026-10-18T10:37:00Z".into(),
        reset: "#sg-telemetry".into(),
    });
    bar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earlier_hour_day_and_week_links_open_the_matching_range_and_unknown_ones_are_refused() {
        assert_eq!(range("").unwrap().key, "live");
        assert_eq!(range("hour").unwrap().key, "1h");
        assert_eq!(range("day").unwrap().metrics, "day");
        assert_eq!(range("week").unwrap().key, "7d");
        assert_eq!(range("6h").unwrap().metrics, "day");
        assert!(range("30d").is_none());
        let query = TelemetryQuery {
            range: "30d".into(),
            ..Default::default()
        };
        assert!(query.validate().is_err());
    }

    #[test]
    fn range_links_keep_search_and_instance_and_logs_offer_no_range_beyond_retention() {
        let instance = Uuid::from_u128(7).to_string();
        let query = TelemetryQuery {
            range: "6h".into(),
            search: "a b".into(),
            instance: instance.clone(),
            ..Default::default()
        };
        let logs = Toolbar::new("/o/apps/a/logs".into(), &query, true, &[]);
        assert!(!logs.ranges.iter().any(|link| link.label == "7d"));
        let six = logs.ranges.iter().find(|link| link.current).unwrap();
        assert_eq!(six.label, "6h");
        assert_eq!(
            six.href,
            format!("/o/apps/a/logs?range=6h&search=a+b&instance={instance}")
        );
        let live = logs.ranges.iter().find(|link| link.live).unwrap();
        assert!(!live.href.contains("range="));
        let metrics = Toolbar::new("/o/apps/a/metrics".into(), &query, false, &[]);
        assert!(metrics.search.is_none());
        assert!(metrics.ranges.iter().any(|link| link.label == "7d"));
    }

    #[test]
    fn the_instance_picker_appears_only_when_there_is_more_than_one_instance() {
        let one = vec![Uuid::from_u128(1).to_string()];
        let query = TelemetryQuery::default();
        assert!(
            Toolbar::new(String::new(), &query, false, &one)
                .instances
                .is_empty()
        );
        let two = vec![one[0].clone(), Uuid::from_u128(0xabcd).to_string()];
        let bar = Toolbar::new(String::new(), &query, false, &two);
        assert_eq!(
            bar.instances[0],
            (String::new(), "All instances (2)".into())
        );
        assert_eq!(bar.instances[2].1, "abcd");
        let retired = TelemetryQuery {
            instance: Uuid::from_u128(9).to_string(),
            ..Default::default()
        };
        assert_eq!(
            Toolbar::new(String::new(), &retired, false, &one)
                .instances
                .len(),
            3
        );
    }

    #[test]
    fn historical_combined_output_does_not_restart_replaced_or_upgraded_instances() {
        let mut controls = RestartControls {
            manages: true,
            current_instances: vec!["running".into(), "draining".into()],
            ..Default::default()
        };
        let record = |instance: &str, stream: &str| {
            LogLine::new(grund_proto::grund::app::v1::AppLog {
                instance: instance.into(),
                stream: stream.into(),
                ..Default::default()
            })
        };
        let mut logs = vec![record("removed", "combined")];
        assert!(!controls.required(&logs));
        logs.push(record("running", "combined"));
        assert!(controls.required(&logs));
        logs.push(record("running", "stderr"));
        assert!(!controls.required(&logs));
        logs.push(record("draining", "combined"));
        assert!(controls.required(&logs));
        controls
            .current_instances
            .retain(|instance| instance != "draining");
        assert!(!controls.required(&logs));
        logs.push(record("running", "stdout"));
        assert!(!controls.required(&logs));
        let upgraded = Uuid::from_u128(7);
        controls.current_instances = vec![upgraded.to_string()];
        controls.separate_instances = vec![upgraded];
        let combined_only = vec![record(&upgraded.to_string(), "combined")];
        assert!(!controls.required(&combined_only));
        controls.separate_instances.clear();
        assert!(controls.required(&combined_only));
        controls.manages = false;
        controls.current_instances.push("removed".into());
        assert!(!controls.required(&logs));
    }

    #[test]
    fn app_output_cannot_supply_markup_or_terminal_and_direction_controls() {
        use sedge_rt::Render;
        let line = LogLine::new(grund_proto::grund::app::v1::AppLog {
            cursor: "1".into(),
            instance: "instance".into(),
            stream: "stderr".into(),
            body: "<script>alert(1)</script>\u{1b}[31mred\u{1b}[2J\u{1b}]0;t\u{7}\u{202e}".into(),
            truncated: true,
            ..Default::default()
        });
        let mut html = String::new();
        crate::templates::compiled::components::LogRow {
            line: &line,
            instance: true,
        }
        .render(&mut html);
        assert!(!html.contains("<script>"));
        assert!(!html.contains('\u{1b}'));
        assert!(!html.contains('\u{7}'));
        assert!(!html.contains('\u{202e}'));
        assert!(html.contains(
            r#"<span class="ansi-red">red\u{001b}[2J\u{001b}]0;t\u{0007}\u{202e}</span>"#
        ));
    }

    #[test]
    fn colour_bold_and_dim_codes_style_text_and_resets_end_them() {
        let spans =
            ansi("a\u{1b}[1;32mb\u{1b}[22mc\u{1b}[0md\u{1b}[94me\u{1b}[39mf\u{1b}[38;5;2mg");
        let runs: Vec<(&str, &str)> = spans
            .iter()
            .map(|span| (span.class.as_str(), span.text.as_str()))
            .collect();
        assert_eq!(
            runs,
            [
                ("", "a"),
                ("ansi-bold ansi-green", "b"),
                ("ansi-green", "c"),
                ("", "d"),
                ("ansi-blue", "e"),
                ("", "fg"),
            ]
        );
    }
}
