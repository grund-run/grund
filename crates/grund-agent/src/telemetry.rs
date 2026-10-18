use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use buffa::Message as BuffaMessage;
use grund_proto::grund::agent::v1::{
    ExportTelemetryRequest, ExportTelemetryResponse, GetReplicaSecretsRequest,
    GetReplicaSecretsResponse, Replica,
};
use opentelemetry_proto::tonic::{
    collector::{logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest},
    common::v1::{AnyValue, KeyValue, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    metrics::v1::{
        Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric, number_data_point,
    },
    resource::v1::Resource,
};
use parking_lot::Mutex;
use prost::Message as ProstMessage;
use sha2::{Digest, Sha256};

use crate::{
    agent::Link,
    apps::Shared,
    join::Record,
    runtime::{ContainerRuntime, Observation},
    telemetry_spool::{Cursor, MAX_BATCH, Spool},
    telemetry_tail::{self, Redactor},
};

const EVERY: Duration = Duration::from_secs(10);
const MAX_CPU_GAP: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Cpu {
    previous: Option<(String, u64, Instant)>,
}

impl Cpu {
    fn sample(&mut self, identity: String, usage: Option<u64>, now: Instant) -> Option<f64> {
        let Some(usage) = usage else {
            self.previous = None;
            return None;
        };
        let previous = self.previous.replace((identity.clone(), usage, now));
        let (old_identity, old_usage, before) = previous?;
        let elapsed = now.saturating_duration_since(before);
        if identity != old_identity
            || usage < old_usage
            || elapsed.is_zero()
            || elapsed > MAX_CPU_GAP
        {
            return None;
        }
        Some((usage - old_usage) as f64 / elapsed.as_secs_f64() / 1000.0)
    }
}

fn small_file(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn cpu_usage(cgroup: &Path) -> Option<u64> {
    small_file(&cgroup.join("cpu.stat"))?
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "usage_usec")
                .then(|| fields.next()?.parse().ok())
                .flatten()
        })
}

fn value(value: any_value::Value) -> AnyValue {
    AnyValue { value: Some(value) }
}

fn attribute(key: &str, value: any_value::Value) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(self::value(value)),
        ..Default::default()
    }
}

fn resource(document: &grund_proto::grund::agent::v1::DesiredState, replica: &Replica) -> Resource {
    resource_values(
        &document.organisation_id,
        &replica.app_id,
        replica.release,
        &replica.replica_id,
        &document.machine_id,
    )
}

fn resource_values(
    organisation: &str,
    app: &str,
    release: u32,
    instance: &str,
    machine: &str,
) -> Resource {
    Resource {
        attributes: vec![
            attribute(
                "grund.organisation.id",
                any_value::Value::StringValue(organisation.into()),
            ),
            attribute("grund.app.id", any_value::Value::StringValue(app.into())),
            attribute(
                "grund.release.number",
                any_value::Value::IntValue(i64::from(release)),
            ),
            attribute(
                "grund.instance.id",
                any_value::Value::StringValue(instance.into()),
            ),
            attribute(
                "grund.machine.id",
                any_value::Value::StringValue(machine.into()),
            ),
        ],
        ..Default::default()
    }
}

fn log_record(body: String, stream: &str, truncated: bool, time: u64) -> LogRecord {
    LogRecord {
        time_unix_nano: time,
        observed_time_unix_nano: time,
        body: Some(value(any_value::Value::StringValue(body))),
        attributes: vec![
            attribute("log.iostream", any_value::Value::StringValue(stream.into())),
            attribute(
                "grund.log.truncated",
                any_value::Value::BoolValue(truncated),
            ),
        ],
        ..Default::default()
    }
}

fn observe_capture_loss(
    spool: &Arc<Mutex<Spool>>,
    instance: &str,
    observation: &Observation,
) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let Some(path) = &observation.capture_loss else {
        return Ok(());
    };
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(129).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 128,
        "app capture loss counter exceeds its bound"
    );
    let text = std::str::from_utf8(&bytes)?;
    let mut fields = text.split_whitespace();
    let epoch = uuid::Uuid::parse_str(
        fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing capture counter epoch"))?,
    )?;
    let count: u64 = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing capture counter value"))?
        .parse()?;
    anyhow::ensure!(fields.next().is_none(), "unexpected capture counter fields");
    let mut spool = spool.lock();
    let before = spool.capture_dropped_bytes();
    spool.capture_loss(instance, epoch.to_string(), count)?;
    if spool.capture_dropped_bytes() != before {
        tracing::warn!(
            capture_dropped_bytes = spool.capture_dropped_bytes(),
            "app capture discarded bytes; this is not an exact missing-record count"
        );
    }
    Ok(())
}

pub(crate) fn drain_final(
    spool: Arc<Mutex<Spool>>,
    identity: Option<crate::telemetry_spool::Identity>,
    observation: Observation,
    secrets: Option<Arc<Vec<crate::secrets::Cached>>>,
) -> anyhow::Result<()> {
    let Some(identity) = identity else {
        let mut spool = spool.lock();
        spool.drop_records(1);
        spool.advance(BTreeMap::new())?;
        tracing::warn!(
            "final app output discarded because no retained signed identity is available"
        );
        return Ok(());
    };
    let known = secrets
        .as_ref()
        .map(|values| values.as_slice())
        .unwrap_or_default();
    if !identity.secrets.iter().all(|(name, version)| {
        known
            .iter()
            .any(|s| &s.name == name && s.version == *version)
    }) {
        let mut spool = spool.lock();
        spool.drop_records(1);
        spool.advance(BTreeMap::new())?;
        tracing::warn!(
            "final app output discarded because required redaction values are unavailable"
        );
        return Ok(());
    }
    spool.lock().remember([identity.clone()])?;
    if observe_capture_loss(&spool, &identity.instance, &observation).is_err() {
        tracing::warn!("app capture byte-loss counter unavailable; final log collection continues");
    }
    let redactor = Redactor::new(known);
    let resource = resource_values(
        &identity.organisation,
        &identity.app,
        identity.release,
        &identity.instance,
        &identity.machine,
    );
    let mut batch = Batch::new(spool.clone());
    for source in observation.logs {
        let key = format!("{}:{}", identity.instance, source.stream);
        let cursor = spool.lock().cursor(&key);
        let (lines, final_cursor, dropped) =
            telemetry_tail::read_final(&source, cursor, &redactor)?;
        spool.lock().drop_records(dropped);
        let time = unix_nanos();
        for line in lines {
            if line.truncated {
                spool.lock().drop_records(1);
            }
            batch.log(
                &identity.instance,
                &resource,
                log_record(line.body, source.stream, line.truncated, time),
                &key,
                line.cursor,
            )?;
        }
        batch.updates.insert(key, final_cursor);
    }
    batch.flush()
}

fn gauge(name: &str, unit: &str, number: number_data_point::Value, time: u64) -> Metric {
    Metric {
        name: name.into(),
        unit: unit.into(),
        data: Some(metric::Data::Gauge(Gauge {
            data_points: vec![NumberDataPoint {
                time_unix_nano: time,
                value: Some(number),
                ..Default::default()
            }],
        })),
        ..Default::default()
    }
}

fn int_metric(name: &str, unit: &str, number: u64, time: u64) -> Option<Metric> {
    Some(gauge(
        name,
        unit,
        number_data_point::Value::AsInt(number.try_into().ok()?),
        time,
    ))
}

struct Batch {
    spool: Arc<Mutex<Spool>>,
    logs: ExportLogsServiceRequest,
    metrics: ExportMetricsServiceRequest,
    log_resources: HashMap<String, usize>,
    updates: BTreeMap<String, Cursor>,
    size: usize,
    records: usize,
}

impl Batch {
    fn new(spool: Arc<Mutex<Spool>>) -> Self {
        Self {
            spool,
            logs: Default::default(),
            metrics: Default::default(),
            log_resources: HashMap::new(),
            updates: BTreeMap::new(),
            size: 0,
            records: 0,
        }
    }

    fn reserve(&mut self, size: usize, log: bool, metric: bool) -> anyhow::Result<()> {
        if self.size + size > MAX_BATCH - 256
            || (log && self.records >= 512)
            || (metric && self.metrics.resource_metrics.len() >= 128)
        {
            self.flush()?;
        }
        self.size += size;
        Ok(())
    }

    fn metric(&mut self, sample: ResourceMetrics) -> anyhow::Result<()> {
        self.reserve(sample.encoded_len() + 16, false, true)?;
        self.metrics.resource_metrics.push(sample);
        Ok(())
    }

    fn log(
        &mut self,
        instance: &str,
        resource: &Resource,
        record: LogRecord,
        key: &str,
        cursor: Cursor,
    ) -> anyhow::Result<()> {
        if !self.log_resources.contains_key(instance) && self.log_resources.len() >= 128 {
            self.flush()?;
        }
        self.reserve(
            resource.encoded_len() + record.encoded_len() + 48,
            true,
            false,
        )?;
        let index = *self
            .log_resources
            .entry(instance.into())
            .or_insert_with(|| {
                let index = self.logs.resource_logs.len();
                self.logs.resource_logs.push(ResourceLogs {
                    resource: Some(resource.clone()),
                    scope_logs: vec![ScopeLogs::default()],
                    ..Default::default()
                });
                index
            });
        self.logs.resource_logs[index].scope_logs[0]
            .log_records
            .push(record);
        self.records += 1;
        self.updates.insert(key.into(), cursor);
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        if self.records == 0 && self.metrics.resource_metrics.is_empty() {
            if !self.updates.is_empty() {
                self.spool
                    .lock()
                    .advance(std::mem::take(&mut self.updates))?;
            }
            return Ok(());
        }
        let mut spool = self.spool.lock();
        let request = ExportTelemetryRequest {
            batch_id: uuid::Uuid::now_v7().to_string(),
            logs_otlp: self.logs.encode_to_vec(),
            metrics_otlp: self.metrics.encode_to_vec(),
            dropped_records: spool.dropped(),
            ..Default::default()
        };
        anyhow::ensure!(
            BuffaMessage::encoded_len(&request) as usize <= MAX_BATCH,
            "telemetry batch exceeds its encoded bound"
        );
        spool.push(
            &request,
            std::mem::take(&mut self.updates),
            (self.records + self.metrics.resource_metrics.len()) as u64,
        )?;
        self.logs.resource_logs.clear();
        self.metrics.resource_metrics.clear();
        self.log_resources.clear();
        self.size = 0;
        self.records = 0;
        Ok(())
    }
}

struct Instance {
    replica: Replica,
    observation: Observation,
    secrets: Option<Arc<Vec<crate::secrets::Cached>>>,
}

struct Collector {
    spool: Arc<Mutex<Spool>>,
    cpu: HashMap<String, Cpu>,
    redactions: HashMap<String, (Arc<Vec<crate::secrets::Cached>>, Redactor)>,
}

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

impl Collector {
    fn trim_legacy(
        &self,
        source: &crate::runtime::LogSource,
        key: &str,
        recover_only: bool,
    ) -> anyhow::Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if source.stream != "combined" {
            return Ok(());
        }
        let mut cursor = self.spool.lock().cursor(key);
        let Some(path) = source.paths.first() else {
            return Ok(());
        };
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let metadata = file.metadata()?;
        if metadata.ino() != cursor.inode || metadata.dev() != cursor.device {
            return Ok(());
        }
        if !cursor.resetting
            && (recover_only || metadata.len() <= crate::capture::SEGMENT_BYTES * 4)
        {
            return Ok(());
        }
        if !cursor.resetting {
            cursor.resetting = true;
            let mut spool = self.spool.lock();
            spool.drop_records(1);
            spool.advance(BTreeMap::from([(key.into(), cursor.clone())]))?;
        }
        file.set_len(0)?;
        file.sync_all()?;
        cursor.offset = 0;
        cursor.skipping = false;
        cursor.resetting = false;
        self.spool
            .lock()
            .advance(BTreeMap::from([(key.into(), cursor)]))
    }

    fn collect(
        &mut self,
        document: grund_proto::grund::agent::v1::DesiredState,
        instances: Vec<Instance>,
    ) -> anyhow::Result<()> {
        let mut batch = Batch::new(self.spool.clone());
        let time = unix_nanos();
        let wanted: BTreeSet<_> = document
            .replicas
            .iter()
            .flat_map(|replica| {
                ["stdout", "stderr", "combined"]
                    .map(|stream| format!("{}:{stream}", replica.replica_id))
            })
            .collect();
        let mut active = BTreeSet::new();
        for instance in &instances {
            let replica = &instance.replica;
            active.insert(replica.replica_id.clone());
            let cgroup = &instance.observation.cgroup;
            let inode = std::fs::metadata(cgroup).ok().map(|m| (m.dev(), m.ino()));
            let identity = format!("{}:{inode:?}", instance.observation.generation);
            let now = Instant::now();
            let time = unix_nanos();
            let usage = (!instance.observation.generation.is_empty())
                .then(|| cpu_usage(cgroup))
                .flatten();
            let cpu = self
                .cpu
                .entry(replica.replica_id.clone())
                .or_default()
                .sample(identity, usage, now);
            let memory = small_file(&cgroup.join("memory.current"))
                .and_then(|s| s.trim().parse::<u64>().ok());
            let mut metrics = Vec::with_capacity(4);
            if let Some(cpu) = cpu {
                metrics.push(gauge(
                    "grund.app.cpu.millicores",
                    "{millicores}",
                    number_data_point::Value::AsDouble(cpu),
                    time,
                ));
            }
            if let Some(memory) =
                memory.and_then(|m| int_metric("grund.app.memory.bytes", "By", m, time))
            {
                metrics.push(memory);
            }
            if metrics.is_empty() {
                continue;
            }
            if let Some(metric) = int_metric(
                "grund.app.reserved.cpu.millicores",
                "{millicores}",
                u64::from(replica.cpu_millis),
                time,
            ) {
                metrics.push(metric);
            }
            if let Some(metric) = replica
                .memory_mib
                .checked_mul(1024 * 1024)
                .and_then(|m| int_metric("grund.app.reserved.memory.bytes", "By", m, time))
            {
                metrics.push(metric);
            }
            batch.metric(ResourceMetrics {
                resource: Some(resource(&document, replica)),
                scope_metrics: vec![ScopeMetrics {
                    metrics,
                    ..Default::default()
                }],
                ..Default::default()
            })?;
        }
        batch.flush()?;
        self.cpu.retain(|id, _| active.contains(id));
        self.redactions.retain(|id, _| active.contains(id));
        for instance in instances {
            let replica = &instance.replica;
            if observe_capture_loss(&self.spool, &replica.replica_id, &instance.observation)
                .is_err()
            {
                tracing::warn!(
                    "app capture byte-loss counter unavailable; log collection continues"
                );
            }
            let Some(secrets) = instance.secrets else {
                continue;
            };
            if self
                .redactions
                .get(&replica.replica_id)
                .is_none_or(|(known, _)| !Arc::ptr_eq(known, &secrets))
            {
                self.redactions.insert(
                    replica.replica_id.clone(),
                    (secrets.clone(), Redactor::new(&secrets)),
                );
            }
            let redactor = &self.redactions[&replica.replica_id].1;
            let resource = resource(&document, replica);
            for source in &instance.observation.logs {
                let key = format!("{}:{}", replica.replica_id, source.stream);
                self.trim_legacy(source, &key, true)?;
                let cursor = self.spool.lock().cursor(&key);
                let result = telemetry_tail::read(source, cursor, redactor);
                let (lines, final_cursor, dropped) = match result {
                    Ok(result) => result,
                    Err(_) => {
                        tracing::warn!("app log source unavailable; retaining its offset");
                        continue;
                    }
                };
                self.spool.lock().drop_records(dropped);
                for line in lines {
                    if line.truncated {
                        self.spool.lock().drop_records(1);
                    }
                    let record = log_record(line.body, source.stream, line.truncated, time);
                    batch.log(&replica.replica_id, &resource, record, &key, line.cursor)?;
                }
                batch.updates.insert(key.clone(), final_cursor);
                if source.stream == "combined" {
                    batch.flush()?;
                    self.trim_legacy(source, &key, false)?;
                }
            }
        }
        batch.flush()?;
        self.spool.lock().retain_cursors(&wanted);
        let spool = self.spool.lock();
        tracing::debug!(
            dropped_records = spool.dropped(),
            capture_dropped_bytes = spool.capture_dropped_bytes(),
            shutdown_loss_events = spool.shutdown_loss_events(),
            rejected_batch_attempts = spool.rejected_batch_attempts(),
            expired_window_batch_attempts = spool.expired_window_batch_attempts(),
            "app telemetry collection completed"
        );
        Ok(())
    }
}

pub(crate) async fn run<C: ContainerRuntime + 'static>(
    runtime: Arc<C>,
    link: Link,
    shared: Arc<Shared>,
    data_dir: PathBuf,
    record: Record,
    lease_id: Option<String>,
) {
    let mut scope = Sha256::new();
    for part in [
        record.instance_url.as_str(),
        record.machine_id.as_str(),
        record.organisation_id.as_str(),
        lease_id.as_deref().unwrap_or(""),
    ] {
        scope.update((part.len() as u64).to_le_bytes());
        scope.update(part.as_bytes());
    }
    let scope = hex::encode(scope.finalize());
    let spool = loop {
        let directory = data_dir.join("telemetry");
        let scope = scope.clone();
        match tokio::task::spawn_blocking(move || Spool::open(directory, &scope)).await {
            Ok(Ok(spool)) => break Arc::new(Mutex::new(spool)),
            _ => {
                tracing::warn!(
                    "app telemetry spool unavailable; retrying local storage in ten seconds"
                );
                tokio::time::sleep(EVERY).await;
            }
        }
    };
    loop {
        let install_shared = shared.clone();
        let install_spool = spool.clone();
        if matches!(
            tokio::task::spawn_blocking(move || crate::telemetry_final::install(
                &install_shared,
                install_spool
            ))
            .await,
            Ok(Ok(()))
        ) {
            break;
        }
        tracing::warn!(
            "app telemetry identity state unavailable; retrying local storage in ten seconds"
        );
        tokio::time::sleep(EVERY).await;
    }
    tokio::spawn(refresh_redactions(link.clone(), shared.clone()));
    tokio::spawn(export(link, spool.clone()));
    let mut collector = Collector {
        spool,
        cpu: HashMap::new(),
        redactions: HashMap::new(),
    };
    let mut tick = tokio::time::interval(EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let document = shared.desired.lock().expect("shared lock").clone();
        let Some(document) = document.filter(|d| {
            d.machine_id == record.machine_id && d.organisation_id == record.organisation_id
        }) else {
            continue;
        };
        let mut instances = Vec::with_capacity(document.replicas.len());
        for replica in &document.replicas {
            let observation = match runtime.observation(&replica.replica_id).await {
                Ok(Some(observation)) => observation,
                _ => continue,
            };
            let secrets = shared
                .telemetry_secrets
                .lock()
                .entry(replica.replica_id.clone())
                .or_default()
                .clone();
            let secrets = (replica.secrets.is_empty()
                || replica.secrets.iter().all(|wanted| {
                    secrets
                        .iter()
                        .any(|value| value.name == wanted.name && value.version == wanted.version)
                }))
            .then_some(secrets);
            instances.push(Instance {
                replica: replica.clone(),
                observation,
                secrets,
            });
        }
        let collection_shared = shared.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _collection = collection_shared.telemetry.collection.lock();
            let losses = collection_shared
                .telemetry
                .pending_loss
                .swap(0, std::sync::atomic::Ordering::AcqRel);
            if losses != 0 {
                let _ = collector.spool.lock().shutdown_loss(losses);
            }
            let result = collector.collect(document, instances);
            (collector, result)
        })
        .await;
        match result {
            Ok((returned, result)) => {
                collector = returned;
                if result.is_err() {
                    tracing::warn!("app telemetry collection failed; retrying next interval");
                }
            }
            Err(_) => {
                tracing::warn!("app telemetry collection worker stopped");
                return;
            }
        }
    }
}

async fn refresh_redactions(link: Link, shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let document = shared.desired.lock().expect("shared lock").clone();
        let Some(document) = document else {
            continue;
        };
        for replica in document.replicas {
            let available = {
                let secrets = shared.telemetry_secrets.lock();
                replica.secrets.is_empty()
                    || secrets.get(&replica.replica_id).is_some_and(|values| {
                        replica.secrets.iter().all(|wanted| {
                            values
                                .iter()
                                .any(|v| v.name == wanted.name && v.version == wanted.version)
                        })
                    })
            };
            if available {
                continue;
            }
            let result: anyhow::Result<GetReplicaSecretsResponse> = link
                .call(
                    "GetReplicaSecrets",
                    &GetReplicaSecretsRequest {
                        replica_id: replica.replica_id.clone(),
                        ..Default::default()
                    },
                )
                .await;
            let Ok(response) = result else {
                continue;
            };
            if !shared
                .telemetry
                .identities
                .lock()
                .contains_key(&replica.replica_id)
            {
                continue;
            }
            let mut secrets = shared.telemetry_secrets.lock();
            let values = secrets.entry(replica.replica_id).or_default();
            let values = Arc::make_mut(values);
            for secret in response.secrets {
                if !values.iter().any(|v| {
                    v.name == secret.name && v.version == secret.version && v.value == secret.value
                }) {
                    values.push(crate::secrets::Cached {
                        name: secret.name,
                        version: secret.version,
                        value: secret.value,
                    });
                }
            }
        }
    }
}

async fn export(link: Link, spool: Arc<Mutex<Spool>>) {
    let mut exported_bytes = 0u64;
    let mut exported_batches = 0u64;
    let mut accepted_records = 0u64;
    let mut reported = Instant::now();
    loop {
        if reported.elapsed() >= Duration::from_secs(60) {
            let stats = spool.lock();
            tracing::info!(
                exported_bytes,
                exported_batches,
                accepted_records,
                rejected_batch_attempts = stats.rejected_batch_attempts(),
                expired_window_batch_attempts = stats.expired_window_batch_attempts(),
                "app telemetry exports since collector start and durable rejection totals"
            );
            reported = Instant::now();
        }
        let read = spool.clone();
        let next = tokio::task::spawn_blocking(move || read.lock().next()).await;
        let request = match next {
            Ok(Ok(Some(request))) => request,
            _ => {
                tokio::time::sleep(EVERY).await;
                continue;
            }
        };
        let response: anyhow::Result<ExportTelemetryResponse> = link
            .call_service("AppTelemetryService", "ExportTelemetry", &request)
            .await;
        let refusal = response
            .as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<crate::agent::TelemetryRefused>());
        let permanent = refusal.is_some_and(crate::agent::TelemetryRefused::permanent);
        let expired_window = refusal.is_some_and(|error| error.expired_window);
        let rejected = refusal.is_some();
        let retry_after = refusal
            .and_then(|e| e.retry_after)
            .unwrap_or(EVERY)
            .max(EVERY);
        if let Ok(response) = &response {
            exported_bytes =
                exported_bytes.saturating_add(u64::from(BuffaMessage::encoded_len(&request)));
            exported_batches = exported_batches.saturating_add(1);
            accepted_records = accepted_records.saturating_add(
                u64::from(response.accepted_logs) + u64::from(response.accepted_samples),
            );
        }
        if response.is_ok() || permanent {
            let ack = spool.clone();
            let id = request.batch_id;
            let result = tokio::task::spawn_blocking(move || {
                let mut spool = ack.lock();
                if permanent {
                    spool.reject(&id, expired_window)
                } else {
                    spool.acknowledge(&id)
                }
            })
            .await;
            if !matches!(result, Ok(Ok(()))) {
                tracing::warn!(
                    "app telemetry acknowledgement could not be persisted; batch may replay"
                );
                tokio::time::sleep(EVERY).await;
            }
        } else {
            if rejected {
                let stats = spool.clone();
                let persisted = tokio::task::spawn_blocking(move || {
                    stats.lock().rejection_attempt(expired_window)
                })
                .await;
                if !matches!(persisted, Ok(Ok(()))) {
                    tracing::warn!("app telemetry rejection attempt could not be persisted");
                }
            }
            tracing::debug!(
                "app telemetry export unavailable; bounded local buffering remains active"
            );
            let mut jitter = [0u8; 2];
            let _ = getrandom::fill(&mut jitter);
            tokio::time::sleep(
                retry_after + Duration::from_millis(u64::from(u16::from_le_bytes(jitter)) % 1000),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_uses_monotonic_delta_and_never_invents_reset_or_gap_zeros() {
        let mut cpu = Cpu::default();
        let now = Instant::now();
        assert_eq!(cpu.sample("one".into(), Some(1_000_000), now), None);
        assert_eq!(
            cpu.sample("one".into(), Some(6_000_000), now + EVERY),
            Some(500.0)
        );
        assert_eq!(cpu.sample("one".into(), Some(100), now + EVERY * 2), None);
        assert_eq!(cpu.sample("one".into(), Some(200), now + EVERY * 6), None);
        assert_eq!(cpu.sample("two".into(), Some(300), now + EVERY * 7), None);
        assert_eq!(cpu.sample("two".into(), None, now + EVERY * 8), None);
        assert_eq!(cpu.sample("two".into(), Some(400), now + EVERY * 9), None);
        assert_eq!(
            cpu.sample("two".into(), Some(400), now + EVERY * 10),
            Some(0.0)
        );
    }

    #[test]
    fn batches_split_metrics_and_logs_without_starving_later_instances() {
        let root = std::env::temp_dir().join(format!("grund-batches-{}", uuid::Uuid::now_v7()));
        let spool = Arc::new(Mutex::new(Spool::open(root.clone(), "scope").unwrap()));
        let mut batch = Batch::new(spool.clone());
        for _ in 0..129 {
            batch.metric(ResourceMetrics::default()).unwrap();
        }
        for i in 0..513 {
            batch
                .log(
                    "instance",
                    &Resource::default(),
                    LogRecord {
                        body: Some(value(any_value::Value::StringValue(format!("line-{i}")))),
                        ..Default::default()
                    },
                    "instance:stdout",
                    Cursor {
                        offset: i,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        batch.flush().unwrap();
        let mut samples = 0;
        let mut records = 0;
        let mut spool = spool.lock();
        while let Some(request) = spool.next().unwrap() {
            assert!(BuffaMessage::encoded_len(&request) as usize <= MAX_BATCH);
            let metrics =
                ExportMetricsServiceRequest::decode(request.metrics_otlp.as_ref()).unwrap();
            let logs = ExportLogsServiceRequest::decode(request.logs_otlp.as_ref()).unwrap();
            assert!(metrics.resource_metrics.len() <= 128);
            let count: usize = logs
                .resource_logs
                .iter()
                .flat_map(|r| &r.scope_logs)
                .map(|s| s.log_records.len())
                .sum();
            assert!(count <= 512);
            samples += metrics.resource_metrics.len();
            records += count;
            spool.acknowledge(&request.batch_id).unwrap();
        }
        assert_eq!(samples, 129);
        assert_eq!(records, 513);
        drop(spool);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_secret_fragments_never_reach_the_durable_otlp_body() {
        let root = std::env::temp_dir().join(format!("grund-redaction-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("stdout.0");
        let secret = b"redaction-test-secret-value";
        let mut bytes = b"key=redaction-test-secret-value\nkey=redaction-test-".to_vec();
        bytes.extend_from_slice(b"\nsecret-value!\n");
        bytes.extend(std::iter::repeat_n(b'x', telemetry_tail::MAX_LINE - 5));
        bytes.extend_from_slice(secret);
        bytes.push(b'\n');
        std::fs::write(&path, bytes).unwrap();
        let redactor = Redactor::new(&[crate::secrets::Cached {
            name: "key".into(),
            version: 1,
            value: secret.to_vec(),
        }]);
        let source = crate::runtime::LogSource {
            stream: "stdout",
            paths: vec![path],
        };
        let (lines, _, _) = telemetry_tail::read(&source, Cursor::default(), &redactor).unwrap();
        let spool = Arc::new(Mutex::new(
            Spool::open(root.join("spool"), "scope").unwrap(),
        ));
        let mut batch = Batch::new(spool.clone());
        for line in lines {
            assert!(!line.body.contains("redaction-test-"));
            assert!(!line.body.contains("secret-value"));
            batch
                .log(
                    "instance",
                    &Resource::default(),
                    LogRecord {
                        body: Some(value(any_value::Value::StringValue(line.body))),
                        ..Default::default()
                    },
                    "instance:stdout",
                    line.cursor,
                )
                .unwrap();
        }
        batch.flush().unwrap();
        for entry in std::fs::read_dir(root.join("spool")).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(secret.len()).any(|bytes| bytes == secret));
        }
        let request = spool.lock().next().unwrap().unwrap();
        let logs = ExportLogsServiceRequest::decode(request.logs_otlp.as_ref()).unwrap();
        assert_eq!(logs.resource_logs[0].scope_logs[0].log_records.len(), 4);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn more_than_128_log_instances_are_split_instead_of_rejected_after_offset_advance() {
        let root =
            std::env::temp_dir().join(format!("grund-log-resources-{}", uuid::Uuid::now_v7()));
        let spool = Arc::new(Mutex::new(Spool::open(root.clone(), "scope").unwrap()));
        let mut batch = Batch::new(spool.clone());
        for i in 0..129 {
            let id = format!("instance-{i}");
            batch
                .log(
                    &id,
                    &Resource::default(),
                    log_record(id.clone(), "stdout", false, 1),
                    &format!("{id}:stdout"),
                    Cursor {
                        offset: 1,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        batch.flush().unwrap();
        let mut instances = 0;
        let mut spool = spool.lock();
        while let Some(request) = spool.next().unwrap() {
            let logs = ExportLogsServiceRequest::decode(request.logs_otlp.as_ref()).unwrap();
            assert!(logs.resource_logs.len() <= 128);
            instances += logs.resource_logs.len();
            spool.acknowledge(&request.batch_id).unwrap();
        }
        assert_eq!(instances, 129);
        drop(spool);
        std::fs::remove_dir_all(root).unwrap();
    }
}
