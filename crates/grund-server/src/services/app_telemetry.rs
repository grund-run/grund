//! Customer app telemetry, independent of the server's operational exporter.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::Message;
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Duration, Utc};
use grund_proto::grund::{agent::v1 as agent, app::v1 as app};
use grund_store::app_telemetry::{self as store, Identity, Log, Sample};
use hmac::{Hmac, Mac};
use opentelemetry_proto::tonic::{
    collector::{logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest},
    common::v1::{InstrumentationScope, any_value::Value},
    metrics::v1::{metric::Data, number_data_point},
    resource::v1::Resource,
};
use prost::Message as ProstMessage;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{services::agents::MachineCaller, state::State};

/// A malformed request, safe to expose without leaking SQL or resource existence.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Invalid(pub &'static str);

const FORWARD: u8 = 1;
const BACKWARD: u8 = 2;
const VOLUME_BUCKETS: i64 = 180;
const VOLUME_STEPS: [i64; 13] = [
    10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600,
];

/// The smallest bucket that covers `seconds` in at most 180 buckets, and never
/// shorter than the agent's 10 s collection interval: records arrive in
/// batches, so a shorter bucket alternates between a batch and nothing.
pub fn volume_bucket(seconds: i64) -> i64 {
    VOLUME_STEPS
        .into_iter()
        .find(|step| seconds <= step * VOLUME_BUCKETS)
        .unwrap_or(VOLUME_STEPS[VOLUME_STEPS.len() - 1])
}

fn valid(condition: bool, message: &'static str) -> Result<()> {
    if !condition {
        return Err(Invalid(message).into());
    }
    Ok(())
}

fn id(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value).map_err(|_| Invalid("expected a UUID").into())
}

fn identity(resource: Option<Resource>) -> Result<Identity> {
    let resource = resource.ok_or(Invalid("resource identity is required"))?;
    valid(
        resource.attributes.len() == 5 && resource.dropped_attributes_count == 0,
        "exactly five resource identity attributes are required",
    )?;
    let mut attributes = BTreeMap::new();
    for attribute in resource.attributes {
        valid(
            !attributes.contains_key(&attribute.key),
            "duplicate resource attribute",
        )?;
        attributes.insert(attribute.key, attribute.value.and_then(|v| v.value));
    }
    let string = |key: &str| -> Result<Uuid> {
        match attributes.get(key) {
            Some(Some(Value::StringValue(value))) => id(value),
            _ => Err(Invalid("resource identifier must be a UUID string").into()),
        }
    };
    let release = match attributes.get("grund.release.number") {
        Some(Some(Value::IntValue(value))) if (1..=i32::MAX as i64).contains(value) => {
            *value as i32
        }
        _ => return Err(Invalid("release number must be a positive integer").into()),
    };
    Ok(Identity {
        organisation_id: string("grund.organisation.id")?,
        app_id: string("grund.app.id")?,
        instance_id: string("grund.instance.id")?,
        machine_id: string("grund.machine.id")?,
        release,
    })
}

fn scope(value: Option<&InstrumentationScope>, schema: &str) -> Result<()> {
    valid(schema.len() <= 200, "schema URL is too long")?;
    if let Some(value) = value {
        valid(
            value.name.len() <= 64
                && value.version.len() <= 64
                && value.attributes.is_empty()
                && value.dropped_attributes_count == 0,
            "unsupported instrumentation scope",
        )?;
    }
    Ok(())
}

fn observed(nanos: u64) -> Result<DateTime<Utc>> {
    valid(
        nanos > 0 && nanos <= i64::MAX as u64,
        "a valid Unix nanosecond timestamp is required",
    )?;
    Ok(DateTime::from_timestamp_nanos(nanos as i64))
}

#[derive(Clone, Copy)]
enum Wire {
    Logs,
    Metrics,
    ResourceLogs,
    ResourceMetrics,
    Resource,
    ScopeLogs,
    ScopeMetrics,
    Scope,
    Log,
    Metric,
    Gauge,
    Point,
    Attribute,
    Scalar,
}

fn varint(bytes: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.first().ok_or(Invalid("truncated OTLP field"))?;
        *bytes = &bytes[1..];
        valid(shift < 63 || byte <= 1, "invalid OTLP varint")?;
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(Invalid("invalid OTLP varint").into())
}

fn wire(mut bytes: &[u8], kind: Wire, budget: &mut usize) -> Result<()> {
    let mut counts = [0u16; 13];
    while !bytes.is_empty() {
        valid(*budget > 0, "too many OTLP fields")?;
        *budget -= 1;
        let key = varint(&mut bytes)?;
        let tag = (key >> 3) as usize;
        let encoding = key & 7;
        valid((1..counts.len()).contains(&tag), "unsupported OTLP field")?;
        counts[tag] = counts[tag]
            .checked_add(1)
            .ok_or(Invalid("too many OTLP fields"))?;
        let (child, expected, maximum, length) = match (kind, tag) {
            (Wire::Logs, 1) => (Some(Wire::ResourceLogs), 2, 128, 262144),
            (Wire::Metrics, 1) => (Some(Wire::ResourceMetrics), 2, 128, 262144),
            (Wire::ResourceLogs | Wire::ResourceMetrics, 1) => (Some(Wire::Resource), 2, 1, 2048),
            (Wire::ResourceLogs, 2) => (Some(Wire::ScopeLogs), 2, 1, 262144),
            (Wire::ResourceMetrics, 2) => (Some(Wire::ScopeMetrics), 2, 1, 262144),
            (
                Wire::ResourceLogs | Wire::ResourceMetrics | Wire::ScopeLogs | Wire::ScopeMetrics,
                3,
            ) => (None, 2, 1, 200),
            (Wire::Resource, 1) => (Some(Wire::Attribute), 2, 5, 256),
            (Wire::Resource, 2) => (None, 0, 1, 0),
            (Wire::ScopeLogs | Wire::ScopeMetrics, 1) => (Some(Wire::Scope), 2, 1, 256),
            (Wire::ScopeLogs, 2) => (Some(Wire::Log), 2, 512, 8704),
            (Wire::ScopeMetrics, 2) => (Some(Wire::Metric), 2, 4, 32768),
            (Wire::Scope, 1 | 2) => (None, 2, 1, 64),
            (Wire::Scope, 4) => (None, 0, 1, 0),
            (Wire::Log, 1 | 11) => (None, 1, 1, 0),
            (Wire::Log, 5) => (Some(Wire::Scalar), 2, 1, 8200),
            (Wire::Log, 6) => (Some(Wire::Attribute), 2, 2, 256),
            (Wire::Log, 2 | 7) => (None, 0, 1, 0),
            (Wire::Log, 8) => (None, 5, 1, 0),
            (Wire::Log, 3 | 9 | 10 | 12) => (None, 2, 1, 200),
            (Wire::Metric, 1..=3) => (None, 2, 1, 200),
            (Wire::Metric, 5) => (Some(Wire::Gauge), 2, 1, 32768),
            (Wire::Gauge, 1) => (Some(Wire::Point), 2, 128, 128),
            (Wire::Point, 2 | 3 | 4 | 6) => (None, 1, 1, 0),
            (Wire::Point, 8) => (None, 0, 1, 0),
            (Wire::Attribute, 1) => (None, 2, 1, 64),
            (Wire::Attribute, 2) => (Some(Wire::Scalar), 2, 1, 128),
            (Wire::Scalar, 1) => (None, 2, 1, 8192),
            (Wire::Scalar, 2 | 3) => (None, 0, 1, 0),
            _ => return Err(Invalid("unsupported OTLP field or nesting").into()),
        };
        valid(
            encoding == expected && counts[tag] <= maximum,
            "invalid OTLP field type or cardinality",
        )?;
        let size = match encoding {
            0 => {
                varint(&mut bytes)?;
                continue;
            }
            1 => 8,
            2 => {
                let size = varint(&mut bytes)?;
                valid(size <= length, "OTLP field too long")?;
                size as usize
            }
            5 => 4,
            _ => return Err(Invalid("unsupported OTLP wire type").into()),
        };
        valid(size <= bytes.len(), "truncated OTLP field")?;
        let (field, rest) = bytes.split_at(size);
        if let Some(child) = child {
            wire(field, child, budget)?;
        }
        bytes = rest;
    }
    Ok(())
}

fn parse(log_bytes: &[u8], metric_bytes: &[u8]) -> Result<(Vec<Log>, Vec<Sample>)> {
    valid(
        log_bytes.len() + metric_bytes.len() <= 256 * 1024,
        "telemetry exceeds 256 KiB",
    )?;
    let mut budget = 32_768;
    wire(log_bytes, Wire::Logs, &mut budget)?;
    wire(metric_bytes, Wire::Metrics, &mut budget)?;
    let logs =
        ExportLogsServiceRequest::decode(log_bytes).map_err(|_| Invalid("invalid OTLP logs"))?;
    let metrics = ExportMetricsServiceRequest::decode(metric_bytes)
        .map_err(|_| Invalid("invalid OTLP metrics"))?;
    valid(
        logs.resource_logs.len() <= 128 && metrics.resource_metrics.len() <= 128,
        "too many resources",
    )?;
    let mut parsed_logs = Vec::new();
    for resource in logs.resource_logs {
        valid(
            resource.schema_url.len() <= 200 && resource.scope_logs.len() <= 1,
            "unsupported log resource nesting",
        )?;
        let identity = identity(resource.resource)?;
        for scoped in resource.scope_logs {
            scope(scoped.scope.as_ref(), &scoped.schema_url)?;
            for record in scoped.log_records {
                valid(parsed_logs.len() < 512, "more than 512 log records")?;
                valid(
                    record.attributes.len() == 2
                        && record.dropped_attributes_count == 0
                        && record.trace_id.is_empty()
                        && record.span_id.is_empty()
                        && record.severity_number == 0
                        && record.severity_text.is_empty()
                        && record.event_name.is_empty()
                        && record.flags == 0,
                    "unsupported log attributes",
                )?;
                let body = match record.body.and_then(|v| v.value) {
                    Some(Value::StringValue(value)) => value,
                    _ => return Err(Invalid("log body must be a string").into()),
                };
                valid(
                    body.len() <= 8192 && !body.contains('\0'),
                    "log body exceeds 8 KiB or contains NUL",
                )?;
                let mut stream = None;
                let mut truncated = None;
                for attribute in record.attributes {
                    match (
                        attribute.key.as_str(),
                        attribute.value.and_then(|v| v.value),
                    ) {
                        ("log.iostream", Some(Value::StringValue(value)))
                            if stream.is_none()
                                && matches!(value.as_str(), "stdout" | "stderr" | "combined") =>
                        {
                            stream = Some(value)
                        }
                        ("grund.log.truncated", Some(Value::BoolValue(value)))
                            if truncated.is_none() =>
                        {
                            truncated = Some(value)
                        }
                        _ => {
                            return Err(
                                Invalid("invalid log stream or truncation attribute").into()
                            );
                        }
                    }
                }
                let at = observed(if record.observed_time_unix_nano == 0 {
                    record.time_unix_nano
                } else {
                    record.observed_time_unix_nano
                })?;
                parsed_logs.push(Log {
                    identity: identity.clone(),
                    at,
                    stream: stream.ok_or(Invalid("log stream required"))?,
                    body,
                    truncated: truncated.ok_or(Invalid("truncation flag required"))?,
                });
            }
        }
    }
    let mut parsed_samples = Vec::new();
    let mut instances = BTreeSet::new();
    for resource in metrics.resource_metrics {
        valid(
            resource.schema_url.len() <= 200 && resource.scope_metrics.len() == 1,
            "exactly one metric scope per instance is required",
        )?;
        let identity = identity(resource.resource)?;
        valid(
            instances.insert(identity.instance_id),
            "duplicate metric resource for an instance",
        )?;
        let mut values: BTreeMap<u64, [Option<number_data_point::Value>; 4]> = BTreeMap::new();
        let mut names = BTreeSet::new();
        for scoped in resource.scope_metrics {
            scope(scoped.scope.as_ref(), &scoped.schema_url)?;
            valid(
                (2..=4).contains(&scoped.metrics.len()),
                "metrics require reservations and optional measured usage",
            )?;
            for metric in scoped.metrics {
                let index = match metric.name.as_str() {
                    "grund.app.cpu.millicores" => 0,
                    "grund.app.memory.bytes" => 1,
                    "grund.app.reserved.cpu.millicores" => 2,
                    "grund.app.reserved.memory.bytes" => 3,
                    _ => return Err(Invalid("unsupported metric name").into()),
                };
                valid(
                    names.insert(index)
                        && metric.description.len() <= 200
                        && metric.unit.len() <= 32
                        && metric.metadata.is_empty(),
                    "duplicate or unsupported metric metadata",
                )?;
                let gauge = match metric.data {
                    Some(Data::Gauge(value)) => value,
                    _ => return Err(Invalid("only gauge metrics are accepted").into()),
                };
                valid(
                    !gauge.data_points.is_empty() && gauge.data_points.len() <= 128,
                    "invalid metric point count",
                )?;
                for point in gauge.data_points {
                    valid(
                        point.attributes.is_empty()
                            && point.exemplars.is_empty()
                            && point.flags == 0
                            && point.start_time_unix_nano == 0,
                        "unsupported metric point attributes",
                    )?;
                    observed(point.time_unix_nano)?;
                    let value = point.value.ok_or(Invalid("metric value required"))?;
                    match value {
                        number_data_point::Value::AsDouble(value) => valid(
                            index == 0
                                && value.is_finite()
                                && (0.0..=1_000_000_000.0).contains(&value),
                            "invalid CPU measurement",
                        )?,
                        number_data_point::Value::AsInt(value) => valid(
                            value >= 0
                                && (index != 2 || value <= i32::MAX as i64)
                                && (index != 0 || value <= 1_000_000_000),
                            "invalid integer measurement",
                        )?,
                    }
                    let values = values.entry(point.time_unix_nano).or_insert([None; 4]);
                    valid(
                        values[index].replace(value).is_none(),
                        "duplicate metric timestamp",
                    )?;
                }
            }
        }
        for (at, values) in values {
            valid(parsed_samples.len() < 128, "more than 128 instance samples")?;
            let integer = |index: usize| -> Result<Option<i64>> {
                match values[index] {
                    Some(number_data_point::Value::AsInt(value)) => Ok(Some(value)),
                    None => Ok(None),
                    _ => Err(Invalid("memory and reservations require integer gauges").into()),
                }
            };
            let cpu_millis = values[0].map(|v| match v {
                number_data_point::Value::AsDouble(v) => v,
                number_data_point::Value::AsInt(v) => v as f64,
            });
            parsed_samples.push(Sample {
                identity: identity.clone(),
                at: observed(at)?,
                cpu_millis,
                memory_bytes: integer(1)?,
                reserved_cpu_millis: integer(2)?.ok_or(Invalid("CPU reservation required"))? as i32,
                reserved_memory_bytes: integer(3)?.ok_or(Invalid("memory reservation required"))?,
            });
        }
    }
    valid(
        !parsed_logs.is_empty() || !parsed_samples.is_empty(),
        "empty telemetry batch",
    )?;
    Ok((parsed_logs, parsed_samples))
}

fn timestamp(at: DateTime<Utc>) -> Timestamp {
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32)
}

fn request_time(value: Option<&Timestamp>) -> Result<Option<DateTime<Utc>>> {
    value
        .map(|t| {
            valid(
                (0..1_000_000_000).contains(&t.nanos),
                "invalid timestamp nanos",
            )?;
            DateTime::from_timestamp(t.seconds, t.nanos as u32)
                .ok_or_else(|| Invalid("invalid timestamp").into())
        })
        .transpose()
}

/// App telemetry service handle obtained through [`AppTelemetryState`].
pub struct AppTelemetry {
    state: State,
}

impl AppTelemetry {
    fn policy(&self) -> store::Policy {
        store::Policy {
            log_bytes: self.state.config.app_log_payload_bytes,
            metric_bytes: self.state.config.app_metric_payload_bytes,
            log_seconds: self.state.config.app_log_retention_hours as i64 * 3600,
            metric_seconds: self.state.config.app_metric_retention_days as i64 * 86400,
            receipts: self.state.config.app_telemetry_receipts,
            receipt_seconds: self.state.config.app_telemetry_receipt_retention_hours as i64 * 3600,
        }
    }

    /// Validates bounded standard OTLP before opening a database transaction.
    pub async fn export(
        &self,
        caller: &MachineCaller,
        request: &agent::ExportTelemetryRequest,
    ) -> Result<agent::ExportTelemetryResponse> {
        valid(
            buffa::Message::encoded_len(request) <= 256 * 1024,
            "telemetry batch exceeds 256 KiB",
        )?;
        let batch = id(&request.batch_id)?;
        let org = caller.organisation_id.ok_or(store::IngestError::Identity)?;
        let (logs, samples) = parse(&request.logs_otlp, &request.metrics_otlp)?;
        let digest = Sha256::digest(request.encode_to_vec());
        let (accepted_logs, accepted_samples) = store::ingest(
            &self.state.pool,
            org,
            caller.machine_id,
            batch,
            &digest,
            &logs,
            &samples,
            self.policy(),
        )
        .await?;
        Ok(agent::ExportTelemetryResponse {
            accepted_logs: accepted_logs as u32,
            accepted_samples: accepted_samples as u32,
            ..Default::default()
        })
    }

    fn token(&self, org: Uuid, app: Uuid, filter: &[u8; 32], cursor: i64) -> String {
        self.mint(FORWARD, org, app, filter, cursor)
    }

    fn mint(&self, kind: u8, org: Uuid, app: Uuid, filter: &[u8; 32], cursor: i64) -> String {
        let mut bytes = Vec::with_capacity(105);
        bytes.push(kind);
        bytes.extend_from_slice(org.as_bytes());
        bytes.extend_from_slice(app.as_bytes());
        bytes.extend_from_slice(filter);
        bytes.extend_from_slice(&cursor.to_be_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.state.secret.derive("app-log-cursor"))
            .expect("HMAC key");
        mac.update(&bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn cursor(&self, token: &str, org: Uuid, app: Uuid, filter: &[u8; 32]) -> Result<i64> {
        if token.is_empty() {
            return Ok(0);
        }
        self.read(FORWARD, token, org, app, filter)
    }

    fn read(&self, kind: u8, token: &str, org: Uuid, app: Uuid, filter: &[u8; 32]) -> Result<i64> {
        valid(token.len() <= 160, "invalid page token")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| Invalid("invalid page token"))?;
        valid(bytes.len() == 105, "invalid page token")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.state.secret.derive("app-log-cursor"))
            .expect("HMAC key");
        mac.update(&bytes[..73]);
        mac.verify_slice(&bytes[73..])
            .map_err(|_| Invalid("invalid page token"))?;
        valid(
            bytes[0] == kind
                && bytes[1..17] == *org.as_bytes()
                && bytes[17..33] == *app.as_bytes()
                && bytes[33..65] == *filter,
            "page token belongs to different app or filters",
        )?;
        let cursor = i64::from_be_bytes(bytes[65..73].try_into().expect("validated token length"));
        valid(cursor >= 0, "invalid page token")?;
        Ok(cursor)
    }

    /// Reads already-authorized live app logs; filters and cursors remain tenant-bound.
    pub async fn logs(
        &self,
        org: Uuid,
        app_id: Uuid,
        request: &app::ListAppLogsRequest,
    ) -> Result<app::ListAppLogsResponse> {
        valid(
            (0..=1000).contains(&request.page_size)
                && request.search.len() <= 200
                && !request.search.contains('\0'),
            "invalid page size or search",
        )?;
        valid(
            matches!(
                request.stream.as_str(),
                "" | "stdout" | "stderr" | "combined"
            ),
            "invalid stream",
        )?;
        let instance = if request.instance.is_empty() {
            None
        } else {
            Some(id(&request.instance)?)
        };
        valid(request.release <= i32::MAX as u32, "invalid release")?;
        let since = request_time(request.since.as_option())?;
        let until = request_time(request.until.as_option())?;
        valid(
            since
                .zip(until)
                .is_none_or(|(since, until)| since <= until && until - since <= Duration::days(7)),
            "invalid time range; maximum seven days",
        )?;
        let mut bound = request.clone();
        bound.page_token.clear();
        bound.page_size = 0;
        bound.organisation.clear();
        bound.name.clear();
        bound.newest_first = false;
        let filter: [u8; 32] = Sha256::digest(bound.encode_to_vec()).into();
        let (after, before) = match (request.newest_first, request.page_token.is_empty()) {
            (false, _) => (
                self.cursor(&request.page_token, org, app_id, &filter)?,
                None,
            ),
            (true, true) => (0, Some(i64::MAX)),
            (true, false) => (
                0,
                Some(self.read(BACKWARD, &request.page_token, org, app_id, &filter)?),
            ),
        };
        let through = store::highwater(&self.state.pool, org).await?;
        valid(after <= through, "page token is ahead of retained cursor")?;
        let size = if request.page_size == 0 {
            200
        } else {
            request.page_size as i64
        };
        let policy = self.policy();
        let rows = store::logs(
            &self.state.pool,
            org,
            app_id,
            store::LogFilter {
                instance,
                release: (request.release > 0).then_some(request.release as i32),
                since,
                until,
                search: &request.search,
                stream: &request.stream,
                after,
                through,
                limit: size,
                before,
            },
            policy.log_seconds,
        )
        .await?;
        let next = if rows.len() == size as usize && before.is_none() {
            rows.last().map_or(through, |r| r.cursor)
        } else {
            through
        };
        let previous = match rows.first() {
            Some(first) if before.is_some() && rows.len() == size as usize => {
                self.mint(BACKWARD, org, app_id, &filter, first.cursor)
            }
            _ => String::new(),
        };
        let logs = rows
            .into_iter()
            .map(|row| app::AppLog {
                cursor: self.token(org, app_id, &filter, row.cursor),
                observed_at: timestamp(row.observed_at).into(),
                instance: row.instance_id.to_string(),
                release: row.release as u32,
                machine: row.machine_id.to_string(),
                stream: row.stream,
                body: row.body,
                truncated: row.truncated,
                ..Default::default()
            })
            .collect();
        let until = until.unwrap_or_else(Utc::now);
        let gaps = grund_store::app_telemetry_gaps::query(
            &self.state.pool,
            org,
            app_id,
            instance,
            (request.release > 0).then_some(request.release as i32),
            since
                .unwrap_or(until - Duration::seconds(policy.log_seconds))
                .max(Utc::now() - Duration::seconds(policy.log_seconds)),
            until,
        )
        .await
        .map_err(gap_error)?
        .into_iter()
        .map(gap_message)
        .collect();
        Ok(app::ListAppLogsResponse {
            logs,
            next_page_token: self.token(org, app_id, &filter, next),
            previous_page_token: previous,
            retention_hours: self.state.config.app_log_retention_hours,
            payload_limit_bytes: policy.log_bytes as u64,
            dropped_records: store::losses(&self.state.pool, org, app_id).await? as u64,
            gaps,
            delivery_window_hours: self.state.config.app_telemetry_batch_max_age_hours,
            ..Default::default()
        })
    }

    /// Counts already-authorized live app logs per stream and bucket.
    pub async fn volume(
        &self,
        org: Uuid,
        app_id: Uuid,
        request: &app::GetAppLogVolumeRequest,
    ) -> Result<app::GetAppLogVolumeResponse> {
        valid(
            request.search.len() <= 200 && !request.search.contains('\0'),
            "invalid search",
        )?;
        let instance = if request.instance.is_empty() {
            None
        } else {
            Some(id(&request.instance)?)
        };
        valid(request.release <= i32::MAX as u32, "invalid release")?;
        let policy = self.policy();
        let until = request_time(request.until.as_option())?.unwrap_or_else(Utc::now);
        let since = request_time(request.since.as_option())?
            .unwrap_or(until - Duration::seconds(policy.log_seconds));
        valid(
            since < until && until - since <= Duration::days(7),
            "invalid time range; maximum seven days",
        )?;
        let bucket = volume_bucket((until - since).num_seconds().max(1));
        let release = (request.release > 0).then_some(request.release as i32);
        let buckets = store::volume(
            &self.state.pool,
            org,
            app_id,
            instance,
            release,
            since,
            until,
            &request.search,
            bucket,
            policy.log_seconds,
        )
        .await?
        .into_iter()
        .map(|row| app::AppLogVolumeBucket {
            at: timestamp(row.at).into(),
            stdout: row.stdout as u64,
            stderr: row.stderr as u64,
            combined: row.combined as u64,
            ..Default::default()
        })
        .collect();
        let gaps = grund_store::app_telemetry_gaps::query(
            &self.state.pool,
            org,
            app_id,
            instance,
            release,
            since.max(Utc::now() - Duration::seconds(policy.log_seconds)),
            until,
        )
        .await
        .map_err(gap_error)?
        .into_iter()
        .map(gap_message)
        .collect();
        Ok(app::GetAppLogVolumeResponse {
            buckets,
            bucket_seconds: bucket as u32,
            since: timestamp(since).into(),
            until: timestamp(until).into(),
            gaps,
            retention_hours: self.state.config.app_log_retention_hours,
            ..Default::default()
        })
    }

    /// Positive separate-stream evidence for current instances, independent of display filters.
    pub async fn separate_capture(&self, org: Uuid, app_id: Uuid) -> Result<Vec<Uuid>> {
        Ok(
            store::separate_capture(&self.state.pool, org, app_id, self.policy().log_seconds)
                .await?,
        )
    }

    /// Reads measured instance buckets; no synthetic zeros or interpolation.
    pub async fn metrics(
        &self,
        org: Uuid,
        app_id: Uuid,
        request: &app::GetAppMetricsRequest,
    ) -> Result<app::GetAppMetricsResponse> {
        let (seconds, bucket) = match request.range.as_str() {
            "" | "hour" => (3600, 10),
            "day" => (86400, 60),
            "week" => (604800, 600),
            _ => return Err(Invalid("range must be hour, day or week").into()),
        };
        valid(request.release <= i32::MAX as u32, "invalid release")?;
        let instance = if request.instance.is_empty() {
            None
        } else {
            Some(id(&request.instance)?)
        };
        let until = Utc::now();
        let since = until - Duration::seconds(seconds);
        let policy = self.policy();
        let rows = store::metrics(
            &self.state.pool,
            org,
            app_id,
            instance,
            (request.release > 0).then_some(request.release as i32),
            since,
            until,
            bucket,
            policy.metric_seconds,
        )
        .await?;
        ensure!(
            rows.len() <= 50_000,
            Invalid("too many instance buckets; filter by instance or release")
        );
        let gaps = grund_store::app_telemetry_gaps::query(
            &self.state.pool,
            org,
            app_id,
            instance,
            (request.release > 0).then_some(request.release as i32),
            since.max(until - Duration::seconds(policy.metric_seconds)),
            until,
        )
        .await
        .map_err(gap_error)?
        .into_iter()
        .map(gap_message)
        .collect();
        Ok(app::GetAppMetricsResponse {
            points: rows
                .into_iter()
                .map(|row| app::AppMetricPoint {
                    at: timestamp(row.at).into(),
                    instance: row.instance_id.to_string(),
                    release: row.release as u32,
                    cpu_millis: row.cpu_millis,
                    memory_bytes: row.memory_bytes,
                    memory_max_bytes: row.memory_max_bytes,
                    reserved_cpu_millis: row.reserved_cpu_millis as u32,
                    reserved_memory_bytes: row.reserved_memory_bytes as u64,
                    samples: row.samples as u32,
                    ..Default::default()
                })
                .collect(),
            bucket_seconds: bucket as u32,
            since: timestamp(since).into(),
            until: timestamp(until).into(),
            retention_days: self.state.config.app_metric_retention_days,
            payload_limit_bytes: policy.metric_bytes as u64,
            memory_accounting: "cgroup memory.current, including cache".into(),
            gaps,
            delivery_window_hours: self.state.config.app_telemetry_batch_max_age_hours,
            ..Default::default()
        })
    }
}

fn gap_message(gap: grund_store::app_telemetry_gaps::Gap) -> app::AppTelemetryGap {
    app::AppTelemetryGap {
        since: timestamp(gap.since).into(),
        until: timestamp(gap.until).into(),
        instance: gap.instance_id.to_string(),
        machine: gap.machine_id.to_string(),
        reason: if gap.offline {
            "machine_offline"
        } else {
            "coverage_unknown"
        }
        .into(),
        ..Default::default()
    }
}

fn gap_error(error: sqlx::Error) -> anyhow::Error {
    if matches!(&error, sqlx::Error::Protocol(message) if message.starts_with("too ")) {
        Invalid("offline coverage is unknown: too much history; filter by instance or release")
            .into()
    } else {
        error.into()
    }
}

/// Constructs the customer telemetry service without I/O.
pub trait AppTelemetryState {
    fn app_telemetry(&self) -> AppTelemetry;
}
impl AppTelemetryState for State {
    fn app_telemetry(&self) -> AppTelemetry {
        AppTelemetry {
            state: self.clone(),
        }
    }
}

/// Bounded periodic reclamation; read-time expiry remains authoritative.
pub struct TelemetrySweeper {
    state: State,
}
impl TelemetrySweeper {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}
impl notmad::Component for TelemetrySweeper {
    fn info(&self) -> notmad::ComponentInfo {
        "grund/app-telemetry-sweeper".into()
    }
    async fn run(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<(), notmad::MadError> {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut after = None;
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    match store::sweep(&self.state.pool, self.state.app_telemetry().policy(), after).await {
                        Ok(next) => after = next,
                        Err(error) => tracing::warn!(error = %error, "app telemetry sweep failed; read expiry remains enforced"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "app_telemetry_tests.rs"]
mod tests;
