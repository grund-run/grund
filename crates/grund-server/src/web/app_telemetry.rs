use std::collections::BTreeMap;

use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use grund_proto::grund::app::v1::{
    AppMetricPoint, AppTelemetryGap, GetAppMetricsRequest, ListAppLogsRequest,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{services::app_telemetry::AppTelemetryState, state::State};

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TelemetryQuery {
    pub search: String,
    pub instance: String,
    pub release: String,
    pub since: String,
    pub until: String,
    pub stream: String,
    pub range: String,
    pub follow: String,
    pub cursor: String,
}

impl TelemetryQuery {
    fn validate(&self) -> Result<u32, String> {
        if !self.instance.is_empty() && Uuid::parse_str(&self.instance).is_err() {
            return Err("Instance must be a full instance identifier.".into());
        }
        if self.search.len() > 200 || self.search.contains('\0') {
            return Err("Search must be at most 200 bytes and cannot contain a null byte.".into());
        }
        if !matches!(self.stream.as_str(), "" | "stdout" | "stderr" | "combined") {
            return Err("Choose stdout, stderr, combined or every stream.".into());
        }
        if !matches!(self.range.as_str(), "" | "hour" | "day" | "week") {
            return Err("Choose hour, day or week.".into());
        }
        if self.release.is_empty() {
            Ok(0)
        } else {
            self.release
                .parse::<u32>()
                .ok()
                .filter(|release| *release > 0 && *release <= i32::MAX as u32)
                .ok_or_else(|| {
                    "Release must be a positive whole number below 2,147,483,648.".into()
                })
        }
    }
}

pub struct LogView {
    pub cursor: String,
    pub at: String,
    pub instance: String,
    pub release: u32,
    pub stream: String,
    pub body: String,
    pub truncated: bool,
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
    pub fn required(&self, logs: &[LogView]) -> bool {
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
    pub action: String,
    pub organisation: String,
    pub name: String,
    pub query: TelemetryQuery,
    pub logs: Vec<LogView>,
    pub cursor: String,
    pub next: String,
    pub error: String,
    pub limits: String,
    pub loss: String,
    pub gaps: Vec<String>,
    pub since_json: String,
    pub until_json: String,
    pub restart: RestartControls,
}

pub struct ChartDot {
    pub x: f64,
    pub y: f64,
    pub label: String,
}

pub struct ChartSeries {
    pub label: &'static str,
    pub kind: &'static str,
    pub path: String,
    pub dots: Vec<ChartDot>,
}

pub struct ChartGap {
    pub x: f64,
    pub width: f64,
    pub label: String,
    pub offline: bool,
}

pub struct TimeSeriesChart {
    pub title: String,
    pub unit: &'static str,
    pub ceiling: String,
    pub start: String,
    pub end: String,
    pub summary: String,
    pub series: Vec<ChartSeries>,
    pub gaps: Vec<ChartGap>,
}

pub struct MetricsPage {
    pub action: String,
    pub query: TelemetryQuery,
    pub error: String,
    pub limits: String,
    pub charts: Vec<TimeSeriesChart>,
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

fn display_time(value: Option<&Timestamp>) -> String {
    value
        .and_then(at)
        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Not reported".into())
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
) -> String {
    if tab == "logs" {
        let mut page = LogsPage {
            action: format!("{base}/logs"),
            organisation: organisation.into(),
            name: name.into(),
            query,
            logs: Vec::new(),
            cursor: String::new(),
            next: String::new(),
            error: String::new(),
            limits: String::new(),
            loss: String::new(),
            gaps: Vec::new(),
            since_json: String::new(),
            until_json: String::new(),
            restart,
        };
        let request = (|| {
            let release = page.query.validate()?;
            let since = time(&page.query.since)?;
            let until = time(&page.query.until)?;
            if since
                .zip(until)
                .is_some_and(|(since, until)| since >= until)
            {
                return Err("Since must be before until.".to_string());
            }
            if since
                .zip(until)
                .is_some_and(|(since, until)| until - since > chrono::Duration::days(7))
            {
                return Err("Time ranges cannot exceed seven days.".to_string());
            }
            page.since_json = since.map(|at| at.to_rfc3339()).unwrap_or_default();
            page.until_json = until.map(|at| at.to_rfc3339()).unwrap_or_default();
            Ok(ListAppLogsRequest {
                organisation: organisation.into(),
                name: name.into(),
                instance: page.query.instance.clone(),
                release,
                since: since
                    .map(|at| {
                        Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32)
                            .into()
                    })
                    .unwrap_or_default(),
                until: until
                    .map(|at| {
                        Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32)
                            .into()
                    })
                    .unwrap_or_default(),
                search: page.query.search.clone(),
                stream: page.query.stream.clone(),
                page_size: 200,
                page_token: page.query.cursor.clone(),
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
                    page.error = error.downcast_ref::<crate::services::app_telemetry::Invalid>()
                        .map(|error| error.to_string())
                        .unwrap_or_else(|| "Logs could not be loaded. Offline coverage is unknown. Check the filters and try again.".into());
                }
                Ok(response) => {
                    page.gaps = response.gaps.iter().filter_map(gap_label).collect();
                    page.cursor = response.next_page_token;
                    page.logs = response
                        .logs
                        .into_iter()
                        .map(|log| LogView {
                            cursor: log.cursor,
                            at: display_time(log.observed_at.as_option()),
                            instance: log.instance,
                            release: log.release,
                            stream: log.stream,
                            body: inert_text(&log.body),
                            truncated: log.truncated,
                        })
                        .collect();
                    page.limits = format!(
                        "Retained for up to {} hours; {} bytes of accounted log storage per organisation. Oldest output is removed at either limit. Eligible offline batch delivery window: {} hours; spool capacity can be tighter.",
                        response.retention_hours,
                        response.payload_limit_bytes,
                        response.delivery_window_hours
                    );
                    page.loss = format!(
                        "Known records removed by retention or organisation limits: {}. Collection and offline losses are not included.",
                        response.dropped_records
                    );
                    let next_query = TelemetryQuery {
                        cursor: page.cursor.clone(),
                        ..page.query
                    };
                    page.next = format!(
                        "{}?{}",
                        page.action,
                        serde_urlencoded::to_string(&next_query).unwrap_or_default()
                    );
                    page.query = next_query;
                }
            },
        }
        crate::templates::compiled::pages::app_logs::render(&page)
    } else {
        let mut page = MetricsPage {
            action: format!("{base}/metrics"),
            query,
            error: String::new(),
            limits: String::new(),
            charts: Vec::new(),
        };
        match page.query.validate() {
            Err(error) => page.error = error,
            Ok(release) => {
                let request = GetAppMetricsRequest {
                    organisation: organisation.into(),
                    name: name.into(),
                    range: page.query.range.clone(),
                    instance: page.query.instance.clone(),
                    release,
                    ..Default::default()
                };
                match state
                    .app_telemetry()
                    .metrics(organisation_id, app_id, &request)
                    .await
                {
                    Err(error) => {
                        tracing::warn!(error = %error, "app metrics query failed");
                        page.error = error.downcast_ref::<crate::services::app_telemetry::Invalid>()
                            .map(|error| error.to_string())
                            .unwrap_or_else(|| "Measurements could not be loaded. Offline coverage is unknown. Check the filters and try again.".into());
                    }
                    Ok(response) => {
                        page.limits = format!(
                            "{} second buckets. Retained for up to {} days; {} bytes of accounted metric storage per organisation. Eligible offline batch delivery window: {} hours; spool capacity can be tighter.",
                            response.bucket_seconds,
                            response.retention_days,
                            response.payload_limit_bytes,
                            response.delivery_window_hours
                        );
                        if let Some((start, end)) = response
                            .since
                            .as_option()
                            .and_then(at)
                            .zip(response.until.as_option().and_then(at))
                        {
                            let mut instances: BTreeMap<(String, u32), Vec<AppMetricPoint>> =
                                BTreeMap::new();
                            for point in response.points {
                                instances
                                    .entry((point.instance.clone(), point.release))
                                    .or_default()
                                    .push(point);
                            }
                            for gap in &response.gaps {
                                if !instances
                                    .keys()
                                    .any(|(instance, _)| instance == &gap.instance)
                                {
                                    instances.entry((gap.instance.clone(), 0)).or_default();
                                }
                            }
                            if instances.len() > 32 {
                                page.error = "More than 32 instances match. Filter by instance or release to draw charts.".into();
                                instances.clear();
                            }
                            for ((instance, release), mut points) in instances {
                                points.sort_by_key(|point| {
                                    point.at.as_option().map(|at| (at.seconds, at.nanos))
                                });
                                let label = if release == 0 {
                                    instance.clone()
                                } else {
                                    format!("{instance} · release {release}")
                                };
                                page.charts.push(chart(
                                    &format!("CPU · {label}"),
                                    false,
                                    &points,
                                    start,
                                    end,
                                    response.bucket_seconds,
                                ));
                                page.charts.push(chart(
                                    &format!("Memory · {label}"),
                                    true,
                                    &points,
                                    start,
                                    end,
                                    response.bucket_seconds,
                                ));
                                for chart in page.charts.iter_mut().rev().take(2) {
                                    chart.gaps = chart_gaps(&response.gaps, &instance, start, end);
                                }
                            }
                        }
                    }
                }
            }
        }
        crate::templates::compiled::pages::app_metrics::render(&page)
    }
}

type MetricSeries = (
    &'static str,
    &'static str,
    fn(&AppMetricPoint) -> Option<f64>,
);

fn chart(
    title: &str,
    memory: bool,
    points: &[AppMetricPoint],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    bucket: u32,
) -> TimeSeriesChart {
    let unit = if memory { "MiB" } else { "millicores" };
    let scale = if memory { 1_048_576.0 } else { 1.0 };
    let values: &[MetricSeries] = if memory {
        &[
            ("Average", "measured", |point| point.memory_bytes),
            ("Maximum", "maximum", |point| point.memory_max_bytes),
            ("Reservation", "reservation", |point| {
                Some(point.reserved_memory_bytes as f64)
            }),
        ]
    } else {
        &[
            ("Average", "measured", |point| point.cpu_millis),
            ("Reservation", "reservation", |point| {
                Some(f64::from(point.reserved_cpu_millis))
            }),
        ]
    };
    let ceiling = values
        .iter()
        .flat_map(|(_, _, value)| {
            points
                .iter()
                .filter(|point| point.samples > 0)
                .filter_map(value)
        })
        .filter(|value| value.is_finite() && *value >= 0.0)
        .fold(0.0, f64::max);
    let y_max = if ceiling > 0.0 { ceiling * 1.1 } else { scale };
    let duration = (end - start).num_milliseconds().max(1) as f64;
    let max_gap = chrono::Duration::seconds(i64::from(bucket));
    let mut series = Vec::with_capacity(values.len());
    let mut measured_peak = 0.0_f64;
    let mut measured = 0_usize;
    for (index, &(label, kind, value)) in values.iter().enumerate() {
        let mut path = String::new();
        let mut dots = Vec::new();
        let mut previous = None;
        let mut points = points
            .iter()
            .map(|point| {
                if point.samples == 0 {
                    return None;
                }
                point
                    .at
                    .as_option()
                    .and_then(at)
                    .zip(value(point))
                    .filter(|(_, value)| value.is_finite() && *value >= 0.0)
                    .filter(|(at, _)| *at >= start && *at <= end)
            })
            .peekable();
        while let Some(current) = points.next() {
            let Some((at, value)) = current else {
                previous = None;
                continue;
            };
            if index == 0 {
                measured += 1;
                measured_peak = measured_peak.max(value);
            }
            let x = 48.0 + (at - start).num_milliseconds() as f64 / duration * 556.0;
            let y = 180.0 - value / y_max * 160.0;
            let connected = previous
                .is_some_and(|previous: DateTime<Utc>| at > previous && at - previous <= max_gap);
            use std::fmt::Write;
            let _ = write!(path, "{} {x:.2} {y:.2} ", if connected { "L" } else { "M" });
            if !connected
                && !points
                    .peek()
                    .and_then(Option::as_ref)
                    .is_some_and(|(next, _)| *next > at && *next - at <= max_gap)
            {
                dots.push(ChartDot {
                    x,
                    y,
                    label: format!(
                        "{}: {:.2} {unit} at {}",
                        label,
                        value / scale,
                        at.format("%Y-%m-%d %H:%M:%S UTC")
                    ),
                });
            }
            previous = Some(at);
        }
        series.push(ChartSeries {
            label,
            kind,
            path,
            dots,
        });
    }
    TimeSeriesChart {
        title: title.into(),
        unit,
        ceiling: format!("{:.1}", y_max / scale),
        start: start.format("%d %b %H:%M UTC").to_string(),
        end: end.format("%d %b %H:%M UTC").to_string(),
        summary: if measured == 0 {
            "No measurements received. Reservations alone do not measure usage.".into()
        } else {
            format!(
                "{measured} measured buckets. Highest measured average: {:.2} {unit}. Missing buckets are gaps, not zero.",
                measured_peak / scale
            )
        },
        series,
        gaps: Vec::new(),
    }
}

pub fn chart_specimen(memory: bool, empty: bool) -> TimeSeriesChart {
    let start = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let points = [Some(100.0), Some(160.0), None, Some(80.0), Some(120.0)]
        .into_iter()
        .enumerate()
        .map(|(index, cpu_millis)| AppMetricPoint {
            at: Timestamp::from_unix(start.timestamp() + index as i64 * 10, 0).into(),
            cpu_millis,
            memory_bytes: cpu_millis.map(|value| value * 1_048_576.0),
            memory_max_bytes: cpu_millis.map(|value| value * 1.2 * 1_048_576.0),
            reserved_memory_bytes: 256 * 1_048_576,
            reserved_cpu_millis: 250,
            samples: u32::from(cpu_millis.is_some()),
            ..Default::default()
        })
        .collect::<Vec<_>>();
    let mut chart = chart(
        if memory {
            "Example memory with offline coverage"
        } else {
            "Example CPU"
        },
        memory,
        if empty { &[] } else { &points },
        start,
        start + chrono::Duration::seconds(40),
        10,
    );
    if memory && !empty {
        chart.gaps = chart_gaps(
            &[AppTelemetryGap {
                since: Timestamp::from_unix(start.timestamp() + 20, 0).into(),
                until: Timestamp::from_unix(start.timestamp() + 30, 0).into(),
                instance: "example-instance".into(),
                machine: "example-machine".into(),
                reason: "machine_offline".into(),
                ..Default::default()
            }],
            "example-instance",
            start,
            start + chrono::Duration::seconds(40),
        );
    }
    chart
}

fn gap_label(gap: &AppTelemetryGap) -> Option<String> {
    let reason = match gap.reason.as_str() {
        "machine_offline" => "not received (machine offline)",
        "coverage_unknown" => "coverage unknown (received history evicted)",
        _ => return None,
    };
    Some(format!(
        "{} – {} · instance {} · machine {}: {reason}",
        display_time(gap.since.as_option()),
        display_time(gap.until.as_option()),
        gap.instance,
        gap.machine
    ))
}

fn chart_gaps(
    gaps: &[AppTelemetryGap],
    instance: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Vec<ChartGap> {
    let duration = (end - start).num_milliseconds().max(1) as f64;
    gaps.iter()
        .filter(|gap| gap.instance == instance)
        .take(1024)
        .filter_map(|gap| {
            let label = gap_label(gap)?;
            let since = gap.since.as_option().and_then(at)?.max(start);
            let until = gap.until.as_option().and_then(at)?.min(end);
            (since < until).then(|| ChartGap {
                x: 48.0 + (since - start).num_milliseconds() as f64 / duration * 556.0,
                width: (until - since).num_milliseconds() as f64 / duration * 556.0,
                label,
                offline: gap.reason == "machine_offline",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_combined_output_does_not_restart_replaced_or_upgraded_instances() {
        let mut controls = RestartControls {
            manages: true,
            current_instances: vec!["running".into(), "draining".into()],
            ..Default::default()
        };
        let record = |instance: &str, stream: &str| LogView {
            cursor: String::new(),
            at: String::new(),
            instance: instance.into(),
            release: 1,
            stream: stream.into(),
            body: String::new(),
            truncated: false,
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
    fn missing_buckets_break_the_line_and_measured_zero_remains_visible() {
        let start = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let points = [0, 10, 30]
            .into_iter()
            .map(|offset| AppMetricPoint {
                at: Timestamp::from_unix(start.timestamp() + offset, 0).into(),
                cpu_millis: Some(0.0),
                samples: 1,
                reserved_cpu_millis: 250,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let chart = chart(
            "CPU",
            false,
            &points,
            start,
            start + chrono::Duration::seconds(40),
            10,
        );
        let usage = &chart.series[0];
        assert_eq!(usage.path.matches('M').count(), 2);
        assert_eq!(usage.path.matches('L').count(), 1);
        assert_eq!(usage.dots.first().unwrap().y, 180.0);
    }

    #[test]
    fn connected_samples_do_not_fill_line_dash_gaps_with_point_markers() {
        let start = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let points = (0..256)
            .map(|index| AppMetricPoint {
                at: Timestamp::from_unix(start.timestamp() + index * 10, 0).into(),
                memory_bytes: Some(32.0 * 1_048_576.0),
                memory_max_bytes: Some(40.0 * 1_048_576.0),
                reserved_memory_bytes: 64 * 1_048_576,
                samples: 1,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let chart = chart(
            "Memory",
            true,
            &points,
            start,
            start + chrono::Duration::seconds(2560),
            10,
        );
        for series in &chart.series {
            assert!(series.dots.is_empty());
            assert_eq!(series.path.matches('M').count(), 1);
            assert_eq!(series.path.matches('L').count(), 255);
        }
    }

    #[test]
    fn an_unavailable_cpu_sample_is_not_drawn_as_zero() {
        let start = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let points = [AppMetricPoint {
            at: Timestamp::from_unix(start.timestamp(), 0).into(),
            cpu_millis: None,
            reserved_cpu_millis: 250,
            samples: 1,
            ..Default::default()
        }];
        let chart = chart(
            "CPU",
            false,
            &points,
            start,
            start + chrono::Duration::seconds(10),
            10,
        );
        assert!(chart.series[0].dots.is_empty());
        assert_eq!(chart.series[1].dots.len(), 1);
    }

    #[test]
    fn app_output_cannot_supply_markup_or_terminal_and_direction_controls() {
        use sedge_rt::Render;
        let log = LogView {
            cursor: "1".into(),
            at: "now".into(),
            instance: "instance".into(),
            release: 1,
            stream: "stdout".into(),
            body: inert_text("<script>alert(1)</script>\u{001b}[31m\u{202e}"),
            truncated: true,
        };
        let mut html = String::new();
        crate::templates::compiled::components::OutputRow { log: &log }.render(&mut html);
        assert!(!html.contains("<script>"));
        assert!(!html.contains('\u{001b}'));
        assert!(!html.contains('\u{202e}'));
        assert!(html.contains("\\u{001b}"));
    }
}
