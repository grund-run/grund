//! Bounded disposable app telemetry, serialized only within an organisation.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgConnection, PgPool};
use uuid::Uuid;

#[path = "app_telemetry_rollup.rs"]
mod rollup;

/// Conservative per-log row/index allowance, in addition to UTF-8 body bytes.
pub const LOG_ROW_BYTES: i64 = 384;
/// Accounted bytes for each raw or weighted-rollup metric row.
pub const METRIC_ROW_BYTES: i64 = 384;

/// A recorded placement, retained after its replica stops.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub organisation_id: Uuid,
    pub app_id: Uuid,
    pub instance_id: Uuid,
    pub machine_id: Uuid,
    pub release: i32,
}

/// A validated log record before ingestion.
pub struct Log {
    pub identity: Identity,
    pub at: DateTime<Utc>,
    pub stream: String,
    pub body: String,
    pub truncated: bool,
}

/// A validated instance sample; absent measurements remain absent.
pub struct Sample {
    pub identity: Identity,
    pub at: DateTime<Utc>,
    pub cpu_millis: Option<f64>,
    pub memory_bytes: Option<i64>,
    pub reserved_cpu_millis: i32,
    pub reserved_memory_bytes: i64,
}

/// Validated accounted storage policy; it is not a physical SQL byte ceiling.
#[derive(Clone, Copy)]
pub struct Policy {
    pub log_bytes: i64,
    pub metric_bytes: i64,
    pub log_seconds: i64,
    pub metric_seconds: i64,
    pub receipts: i32,
    pub receipt_seconds: i64,
}

/// Ingestion failures with safe caller-visible classifications.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("the resource is not a recorded placement for this machine")]
    Identity,
    #[error("the batch identifier was already used with a different payload")]
    Conflict,
    #[error("telemetry receipt capacity reached; retry after retention expires")]
    Capacity,
    #[error(transparent)]
    Store(#[from] sqlx::Error),
}

async fn lock(connection: &mut PgConnection, org: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO grund_app_telemetry_usage (organisation_id) VALUES ($1) ON CONFLICT (organisation_id) DO UPDATE SET organisation_id = EXCLUDED.organisation_id")
        .bind(org).execute(connection).await?;
    Ok(())
}

async fn prune(
    connection: &mut PgConnection,
    org: Uuid,
    policy: Policy,
    incoming_logs: i64,
    incoming_metrics: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "WITH expired AS MATERIALIZED (SELECT cursor,payload_bytes FROM grund_app_logs WHERE organisation_id = $1 AND observed_at <= statement_timestamp() - make_interval(secs => $2::bigint::double precision) ORDER BY observed_at LIMIT 1024), budget AS (SELECT greatest(log_bytes + $3 - $4 - COALESCE((SELECT sum(payload_bytes) FROM expired),0),0) AS deficit FROM grund_app_telemetry_usage WHERE organisation_id = $1), oldest AS MATERIALIZED (SELECT cursor,payload_bytes FROM grund_app_logs WHERE organisation_id = $1 AND (SELECT deficit > 0 FROM budget) AND cursor NOT IN (SELECT cursor FROM expired) ORDER BY cursor LIMIT 4096), candidates AS (SELECT cursor FROM (SELECT cursor,sum(payload_bytes) OVER (ORDER BY cursor) - payload_bytes AS preceding FROM oldest) l WHERE preceding < (SELECT deficit FROM budget)), deleted AS (DELETE FROM grund_app_logs WHERE organisation_id = $1 AND cursor IN (SELECT cursor FROM candidates UNION SELECT cursor FROM expired) RETURNING app_id,payload_bytes), losses AS (INSERT INTO grund_app_telemetry_losses (organisation_id,app_id,dropped_records) SELECT $1,app_id,count(*) FROM deleted GROUP BY app_id ON CONFLICT (organisation_id,app_id) DO UPDATE SET dropped_records = grund_app_telemetry_losses.dropped_records + EXCLUDED.dropped_records) UPDATE grund_app_telemetry_usage SET log_bytes = log_bytes - COALESCE((SELECT sum(payload_bytes) FROM deleted),0) WHERE organisation_id = $1")
        .bind(org).bind(policy.log_seconds).bind(incoming_logs).bind(policy.log_bytes).execute(&mut *connection).await?;
    rollup::maintain(&mut *connection, org, policy, incoming_metrics).await?;
    sqlx::query("WITH deleted AS (DELETE FROM grund_app_telemetry_batches WHERE organisation_id = $1 AND (machine_id, batch_id) IN (SELECT machine_id, batch_id FROM grund_app_telemetry_batches WHERE organisation_id = $1 AND received_at <= statement_timestamp() - make_interval(secs => $2::bigint::double precision) ORDER BY received_at LIMIT 4096) RETURNING 1) UPDATE grund_app_telemetry_usage SET receipts = receipts - (SELECT count(*)::int FROM deleted) WHERE organisation_id = $1")
        .bind(org).bind(policy.receipt_seconds).execute(&mut *connection).await?;
    sqlx::query("DELETE FROM grund_app_telemetry_losses WHERE organisation_id = $1 AND app_id IN (SELECT l.app_id FROM grund_app_telemetry_losses l LEFT JOIN grund_apps a ON a.organisation_id = l.organisation_id AND a.app_id = l.app_id WHERE l.organisation_id = $1 AND (a.app_id IS NULL OR a.deleted_at <= statement_timestamp() - interval '7 days') ORDER BY l.app_id LIMIT 1024)")
        .bind(org).execute(&mut *connection).await?;
    crate::app_telemetry_gaps::prune(&mut *connection, org).await?;
    sqlx::query("DELETE FROM grund_app_telemetry_instances WHERE organisation_id = $1 AND instance_id IN (SELECT instance_id FROM grund_app_telemetry_instances WHERE organisation_id = $1 AND stopped_at <= statement_timestamp() - interval '7 days' LIMIT 1024)")
        .bind(org).execute(connection).await?;
    Ok(())
}

/// Inserts one batch atomically with identity validation, eviction and its receipt.
/// Cursor allocation occurs under the tenant lock, so a later commit cannot hide
/// below a cursor already returned to a follower.
#[allow(clippy::too_many_arguments)]
pub async fn ingest(
    pool: &PgPool,
    org: Uuid,
    machine: Uuid,
    batch: Uuid,
    digest: &[u8],
    logs: &[Log],
    samples: &[Sample],
    policy: Policy,
) -> Result<(i32, i32), IngestError> {
    let mut tx = pool.begin().await?;
    lock(&mut tx, org).await?;
    let current: Option<Uuid> = sqlx::query_scalar("SELECT machine_id FROM grund_machines WHERE machine_id = $1 AND pool_organisation_id = $2 AND state != 'revoked' FOR SHARE")
        .bind(machine).bind(org).fetch_optional(&mut *tx).await?;
    if current.is_none() {
        return Err(IngestError::Identity);
    }
    if let Some((previous, accepted_logs, accepted_samples)) = sqlx::query_as::<_, (Vec<u8>, i32, i32)>("SELECT digest, accepted_logs, accepted_samples FROM grund_app_telemetry_batches WHERE organisation_id = $1 AND machine_id = $2 AND batch_id = $3")
        .bind(org).bind(machine).bind(batch).fetch_optional(&mut *tx).await? {
        return if previous == digest { Ok((accepted_logs, accepted_samples)) } else { Err(IngestError::Conflict) };
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let mut identities: Vec<&Identity> = Vec::new();
    for identity in logs
        .iter()
        .map(|l| &l.identity)
        .chain(samples.iter().map(|s| &s.identity))
    {
        if identity.organisation_id != org || identity.machine_id != machine {
            return Err(IngestError::Identity);
        }
        if !identities.contains(&identity) {
            identities.push(identity);
        }
    }
    for identity in identities {
        let placement: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT i.placed_at FROM grund_app_telemetry_instances i JOIN grund_apps a ON a.app_id = i.app_id AND a.organisation_id = i.organisation_id WHERE i.organisation_id = $1 AND i.instance_id = $2 AND i.machine_id = $3 AND i.app_id = $4 AND i.release = $5 AND a.deleted_at IS NULL AND (i.stopped_at IS NULL OR i.stopped_at > statement_timestamp() - interval '7 days')")
            .bind(org).bind(identity.instance_id).bind(machine).bind(identity.app_id).bind(identity.release).fetch_optional(&mut *tx).await?;
        let Some(placed) = placement else {
            return Err(IngestError::Identity);
        };
        for at in logs
            .iter()
            .filter(|l| l.identity == *identity)
            .map(|l| l.at)
            .chain(
                samples
                    .iter()
                    .filter(|s| s.identity == *identity)
                    .map(|s| s.at),
            )
        {
            if at < placed - chrono::Duration::seconds(30)
                || at > now + chrono::Duration::seconds(30)
            {
                return Err(IngestError::Identity);
            }
        }
    }
    let retained_logs = logs
        .iter()
        .filter(|l| l.at > now - chrono::Duration::seconds(policy.log_seconds));
    let retained_samples = samples
        .iter()
        .filter(|s| s.at > now - chrono::Duration::seconds(policy.metric_seconds));
    let log_bytes = retained_logs
        .clone()
        .map(|l| l.body.len() as i64 + LOG_ROW_BYTES)
        .sum::<i64>();
    let accepted_samples = retained_samples.clone().count() as i32;
    let metric_bytes = i64::from(accepted_samples) * METRIC_ROW_BYTES;
    prune(&mut tx, org, policy, log_bytes, metric_bytes).await?;
    let (mut cursor, used_logs, used_metrics, receipts): (i64, i64, i64, i32) = sqlx::query_as("SELECT cursor, log_bytes, metric_bytes, receipts FROM grund_app_telemetry_usage WHERE organisation_id = $1").bind(org).fetch_one(&mut *tx).await?;
    if receipts >= policy.receipts
        || used_logs + log_bytes > policy.log_bytes
        || used_metrics + metric_bytes > policy.metric_bytes
    {
        return Err(IngestError::Capacity);
    }
    let accepted_logs = retained_logs.clone().count() as i32;
    if accepted_logs > 0 {
        let mut query = sqlx::QueryBuilder::new(
            "INSERT INTO grund_app_logs (organisation_id,cursor,app_id,instance_id,machine_id,release,observed_at,stream,body,truncated,payload_bytes) ",
        );
        query.push_values(retained_logs, |mut row, log| {
            cursor += 1;
            row.push_bind(org)
                .push_bind(cursor)
                .push_bind(log.identity.app_id)
                .push_bind(log.identity.instance_id)
                .push_bind(machine)
                .push_bind(log.identity.release)
                .push_bind(log.at)
                .push_bind(&log.stream)
                .push_bind(&log.body)
                .push_bind(log.truncated)
                .push_bind(log.body.len() as i64 + LOG_ROW_BYTES);
        });
        query.build().execute(&mut *tx).await?;
    }
    if accepted_samples > 0 {
        let mut query = sqlx::QueryBuilder::new(
            "INSERT INTO grund_app_metrics (organisation_id,cursor,app_id,instance_id,machine_id,release,observed_at,cpu_millis,memory_bytes,reserved_cpu_millis,reserved_memory_bytes) ",
        );
        query.push_values(retained_samples, |mut row, sample| {
            cursor += 1;
            row.push_bind(org)
                .push_bind(cursor)
                .push_bind(sample.identity.app_id)
                .push_bind(sample.identity.instance_id)
                .push_bind(machine)
                .push_bind(sample.identity.release)
                .push_bind(sample.at)
                .push_bind(sample.cpu_millis)
                .push_bind(sample.memory_bytes)
                .push_bind(sample.reserved_cpu_millis)
                .push_bind(sample.reserved_memory_bytes);
        });
        query.build().execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE grund_app_telemetry_usage SET cursor = $2, log_bytes = log_bytes + $3, metric_bytes = metric_bytes + $4, receipts = receipts + 1 WHERE organisation_id = $1")
        .bind(org).bind(cursor).bind(log_bytes).bind(metric_bytes).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO grund_app_telemetry_batches (organisation_id,machine_id,batch_id,digest,accepted_logs,accepted_samples) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(org).bind(machine).bind(batch).bind(digest).bind(accepted_logs).bind(accepted_samples).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((accepted_logs, accepted_samples))
}

/// Stored logs in ingestion order, not observed-time order.
#[derive(FromRow)]
pub struct LogRow {
    pub cursor: i64,
    pub observed_at: DateTime<Utc>,
    pub instance_id: Uuid,
    pub machine_id: Uuid,
    pub release: i32,
    pub stream: String,
    pub body: String,
    pub truncated: bool,
}

/// Validated log filters, including an immutable per-query high-water mark.
pub struct LogFilter<'a> {
    pub instance: Option<Uuid>,
    pub release: Option<i32>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub search: &'a str,
    pub stream: &'a str,
    pub after: i64,
    pub through: i64,
    pub limit: i64,
}

/// The latest committed tenant ingestion cursor; absent tenants start at zero.
pub async fn highwater(pool: &PgPool, org: Uuid) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query_scalar(
        "SELECT cursor FROM grund_app_telemetry_usage WHERE organisation_id = $1",
    )
    .bind(org)
    .fetch_optional(pool)
    .await?
    .unwrap_or(0))
}

/// Returns only live-app retained logs, with literal rather than pattern search.
pub async fn logs(
    pool: &PgPool,
    org: Uuid,
    app: Uuid,
    filter: LogFilter<'_>,
    retention: i64,
) -> Result<Vec<LogRow>, sqlx::Error> {
    sqlx::query_as("SELECT l.cursor,l.observed_at,l.instance_id,l.machine_id,l.release,l.stream,l.body,l.truncated FROM grund_app_logs l WHERE l.organisation_id = $1 AND l.app_id = $2 AND EXISTS(SELECT 1 FROM grund_apps a WHERE a.organisation_id = $1 AND a.app_id = $2 AND a.deleted_at IS NULL) AND l.cursor > $3 AND l.cursor <= $4 AND l.observed_at > statement_timestamp() - make_interval(secs => $5::bigint::double precision) AND ($6::uuid IS NULL OR l.instance_id = $6) AND ($7::int IS NULL OR l.release = $7) AND ($8::timestamptz IS NULL OR l.observed_at >= $8) AND ($9::timestamptz IS NULL OR l.observed_at < $9) AND ($10 = '' OR strpos(lower(l.body), lower($10)) > 0) AND ($11 = '' OR l.stream = $11) ORDER BY l.cursor LIMIT $12")
        .bind(org).bind(app).bind(filter.after).bind(filter.through).bind(retention).bind(filter.instance).bind(filter.release).bind(filter.since).bind(filter.until).bind(filter.search).bind(filter.stream).bind(filter.limit).fetch_all(pool).await
}

/// One instance bucket; null usage values are never filled with zero.
#[derive(FromRow)]
pub struct MetricRow {
    pub at: DateTime<Utc>,
    pub instance_id: Uuid,
    pub release: i32,
    pub cpu_millis: Option<f64>,
    pub memory_bytes: Option<f64>,
    pub memory_max_bytes: Option<f64>,
    pub reserved_cpu_millis: i32,
    pub reserved_memory_bytes: i64,
    pub samples: i64,
}

/// Aggregates only measured buckets; absent buckets are represented by gaps.
#[allow(clippy::too_many_arguments)]
pub async fn metrics(
    pool: &PgPool,
    org: Uuid,
    app: Uuid,
    instance: Option<Uuid>,
    release: Option<i32>,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    bucket: i32,
    retention: i64,
) -> Result<Vec<MetricRow>, sqlx::Error> {
    rollup::query(
        pool, org, app, instance, release, since, until, bucket, retention,
    )
    .await
}

/// Retention/quota evictions for this app, excluding un-attributable agent loss.
pub async fn losses(pool: &PgPool, org: Uuid, app: Uuid) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query_scalar("SELECT dropped_records FROM grund_app_telemetry_losses WHERE organisation_id = $1 AND app_id = $2").bind(org).bind(app).fetch_optional(pool).await?.unwrap_or(0))
}

/// Sweeps at most 32 tenants per pass, rotating with an opaque internal cursor.
pub async fn sweep(
    pool: &PgPool,
    policy: Policy,
    after: Option<Uuid>,
) -> Result<Option<Uuid>, sqlx::Error> {
    let orgs: Vec<Uuid> = sqlx::query_scalar("SELECT organisation_id FROM ((SELECT organisation_id FROM grund_app_telemetry_usage WHERE ($1::uuid IS NULL OR organisation_id > $1) ORDER BY organisation_id LIMIT 32) UNION (SELECT DISTINCT organisation_id FROM grund_app_telemetry_instances WHERE ($1::uuid IS NULL OR organisation_id > $1) ORDER BY organisation_id LIMIT 32)) tenants ORDER BY organisation_id LIMIT 32").bind(after).fetch_all(pool).await?;
    for org in &orgs {
        let mut tx = pool.begin().await?;
        lock(&mut tx, *org).await?;
        prune(&mut tx, *org, policy, 0, 0).await?;
        tx.commit().await?;
    }
    Ok(if orgs.len() == 32 {
        orgs.last().copied()
    } else {
        None
    })
}
