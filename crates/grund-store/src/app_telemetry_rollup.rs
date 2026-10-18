use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::{METRIC_ROW_BYTES, MetricRow, Policy};

pub(super) async fn maintain(
    connection: &mut PgConnection,
    org: Uuid,
    policy: Policy,
    incoming_metrics: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"WITH raw AS (
            DELETE FROM grund_app_metrics
            WHERE organisation_id = $1 AND cursor IN (
                SELECT cursor FROM grund_app_metrics
                WHERE organisation_id = $1
                  AND observed_at <= statement_timestamp() - make_interval(secs => $2::double precision)
                ORDER BY observed_at, cursor LIMIT 1024
            ) RETURNING 1
        ), rolled AS (
            DELETE FROM grund_app_metric_rollups
            WHERE organisation_id = $1 AND (instance_id, bucket_seconds, observed_at) IN (
                SELECT instance_id, bucket_seconds, observed_at FROM grund_app_metric_rollups
                WHERE organisation_id = $1
                  AND observed_at <= statement_timestamp() - make_interval(secs => $2::double precision)
                ORDER BY observed_at, instance_id, bucket_seconds LIMIT 1024
            ) RETURNING 1
        )
        UPDATE grund_app_telemetry_usage
        SET metric_bytes = metric_bytes - ((SELECT count(*) FROM raw) + (SELECT count(*) FROM rolled)) * $3
        WHERE organisation_id = $1"#,
    )
    .bind(org)
    .bind(policy.metric_seconds)
    .bind(METRIC_ROW_BYTES)
    .execute(&mut *connection)
    .await?;

    sqlx::query("SELECT set_config('grund.telemetry_compacting', 'on', true)")
        .execute(&mut *connection)
        .await?;

    sqlx::query(
        r#"WITH source AS (
            DELETE FROM grund_app_metrics
            WHERE organisation_id = $1 AND cursor IN (
                SELECT cursor FROM grund_app_metrics
                WHERE organisation_id = $1
                  AND observed_at > statement_timestamp() - make_interval(secs => $2::double precision)
                  AND observed_at < date_bin(interval '1 minute', statement_timestamp() - interval '1 hour',
                                             timestamptz '1970-01-01 00:00:00+00')
                ORDER BY observed_at, cursor LIMIT 1024
            ) RETURNING *
        ), sized AS (
            SELECT *, CASE WHEN observed_at < date_bin(interval '10 minutes', statement_timestamp() - interval '1 day',
                                                       timestamptz '1970-01-01 00:00:00+00')
                           THEN 600 ELSE 60 END AS seconds FROM source
        ), grouped AS MATERIALIZED (
            SELECT organisation_id, app_id, instance_id, machine_id, release, seconds AS bucket_seconds,
                   date_bin(make_interval(secs => seconds), observed_at,
                            timestamptz '1970-01-01 00:00:00+00') AS observed_at,
                   coalesce(sum(cpu_millis), 0)::float8 AS cpu_sum, count(cpu_millis) AS cpu_count,
                   coalesce(sum(memory_bytes), 0) AS memory_sum, count(memory_bytes) AS memory_count,
                   max(memory_bytes) AS memory_max_bytes, count(*) AS samples,
                   bit_or(1::bigint << floor(extract(epoch FROM observed_at -
                       date_bin(make_interval(secs => seconds), observed_at,
                                timestamptz '1970-01-01 00:00:00+00')) / 10)::int) AS coverage_mask,
                   max(reserved_cpu_millis) AS reserved_cpu_millis,
                   max(reserved_memory_bytes) AS reserved_memory_bytes
            FROM sized GROUP BY organisation_id, app_id, instance_id, machine_id, release, seconds,
                date_bin(make_interval(secs => seconds), observed_at, timestamptz '1970-01-01 00:00:00+00')
            HAVING date_bin(make_interval(secs => seconds), observed_at, timestamptz '1970-01-01 00:00:00+00')
                   > statement_timestamp() - make_interval(secs => $2::double precision)
        ), uncovered AS (
            UPDATE grund_app_telemetry_instances i
            SET metric_coverage_lost_before = greatest(i.metric_coverage_lost_before, d.coverage_end)
            FROM (
                SELECT organisation_id, instance_id, max(observed_at + interval '10 seconds') AS coverage_end
                FROM sized
                WHERE date_bin(make_interval(secs => seconds), observed_at, timestamptz '1970-01-01 00:00:00+00')
                      <= statement_timestamp() - make_interval(secs => $2::double precision)
                GROUP BY organisation_id, instance_id
            ) d
            WHERE i.organisation_id = d.organisation_id AND i.instance_id = d.instance_id
              AND (i.metric_coverage_lost_before IS NULL OR i.metric_coverage_lost_before < d.coverage_end)
            RETURNING 1
        ), written AS (
            INSERT INTO grund_app_metric_rollups AS target
                (organisation_id, app_id, instance_id, machine_id, release, bucket_seconds, observed_at,
                 cpu_sum, cpu_count, memory_sum, memory_count, memory_max_bytes, samples,
                 coverage_mask, reserved_cpu_millis, reserved_memory_bytes)
            SELECT organisation_id, app_id, instance_id, machine_id, release, bucket_seconds, observed_at,
                   cpu_sum, cpu_count, memory_sum, memory_count, memory_max_bytes, samples,
                   coverage_mask, reserved_cpu_millis, reserved_memory_bytes FROM grouped WHERE true
            ON CONFLICT (organisation_id, instance_id, bucket_seconds, observed_at) DO UPDATE
            SET cpu_sum = target.cpu_sum + EXCLUDED.cpu_sum,
                cpu_count = target.cpu_count + EXCLUDED.cpu_count,
                memory_sum = target.memory_sum + EXCLUDED.memory_sum,
                memory_count = target.memory_count + EXCLUDED.memory_count,
                memory_max_bytes = greatest(target.memory_max_bytes, EXCLUDED.memory_max_bytes),
                samples = target.samples + EXCLUDED.samples,
                coverage_mask = target.coverage_mask | EXCLUDED.coverage_mask,
                reserved_cpu_millis = greatest(target.reserved_cpu_millis, EXCLUDED.reserved_cpu_millis),
                reserved_memory_bytes = greatest(target.reserved_memory_bytes, EXCLUDED.reserved_memory_bytes)
            RETURNING 1
        ), created AS (
            SELECT count(*) AS rows FROM grouped g
            WHERE NOT EXISTS (
                SELECT 1 FROM grund_app_metric_rollups r
                WHERE r.organisation_id = g.organisation_id AND r.instance_id = g.instance_id
                  AND r.bucket_seconds = g.bucket_seconds AND r.observed_at = g.observed_at
            )
        )
        UPDATE grund_app_telemetry_usage
        SET metric_bytes = metric_bytes + ((SELECT rows FROM created) - (SELECT count(*) FROM source)) * $3
        WHERE organisation_id = $1 AND (SELECT count(*) FROM written) >= 0"#,
    )
    .bind(org)
    .bind(policy.metric_seconds)
    .bind(METRIC_ROW_BYTES)
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        r#"WITH source AS (
            DELETE FROM grund_app_metric_rollups
            WHERE organisation_id = $1 AND (instance_id, bucket_seconds, observed_at) IN (
                SELECT instance_id, bucket_seconds, observed_at FROM grund_app_metric_rollups
                WHERE organisation_id = $1 AND bucket_seconds = 60
                  AND observed_at > statement_timestamp() - make_interval(secs => $2::double precision)
                  AND observed_at < date_bin(interval '10 minutes', statement_timestamp() - interval '1 day',
                                             timestamptz '1970-01-01 00:00:00+00')
                ORDER BY observed_at, instance_id, bucket_seconds LIMIT 1024
            ) RETURNING *
        ), grouped AS MATERIALIZED (
            SELECT organisation_id, app_id, instance_id, machine_id, release,
                   date_bin(interval '10 minutes', observed_at, timestamptz '1970-01-01 00:00:00+00') AS observed_at,
                   sum(cpu_sum)::float8 AS cpu_sum, sum(cpu_count)::bigint AS cpu_count,
                   sum(memory_sum) AS memory_sum, sum(memory_count)::bigint AS memory_count,
                   max(memory_max_bytes) AS memory_max_bytes, sum(samples)::bigint AS samples,
                   bit_or(coverage_mask << (extract(epoch FROM observed_at -
                       date_bin(interval '10 minutes', observed_at,
                                timestamptz '1970-01-01 00:00:00+00'))::int / 10)) AS coverage_mask,
                   max(reserved_cpu_millis) AS reserved_cpu_millis,
                   max(reserved_memory_bytes) AS reserved_memory_bytes
            FROM source GROUP BY organisation_id, app_id, instance_id, machine_id, release,
                date_bin(interval '10 minutes', observed_at, timestamptz '1970-01-01 00:00:00+00')
            HAVING date_bin(interval '10 minutes', observed_at, timestamptz '1970-01-01 00:00:00+00')
                   > statement_timestamp() - make_interval(secs => $2::double precision)
        ), uncovered AS (
            UPDATE grund_app_telemetry_instances i
            SET metric_coverage_lost_before = greatest(i.metric_coverage_lost_before, d.coverage_end)
            FROM (
                SELECT organisation_id, instance_id,
                       max(observed_at + make_interval(secs => bucket_seconds)) AS coverage_end
                FROM source
                WHERE date_bin(interval '10 minutes', observed_at, timestamptz '1970-01-01 00:00:00+00')
                      <= statement_timestamp() - make_interval(secs => $2::double precision)
                GROUP BY organisation_id, instance_id
            ) d
            WHERE i.organisation_id = d.organisation_id AND i.instance_id = d.instance_id
              AND (i.metric_coverage_lost_before IS NULL OR i.metric_coverage_lost_before < d.coverage_end)
            RETURNING 1
        ), written AS (
            INSERT INTO grund_app_metric_rollups AS target
                (organisation_id, app_id, instance_id, machine_id, release, bucket_seconds, observed_at,
                 cpu_sum, cpu_count, memory_sum, memory_count, memory_max_bytes, samples,
                 coverage_mask, reserved_cpu_millis, reserved_memory_bytes)
            SELECT organisation_id, app_id, instance_id, machine_id, release, 600, observed_at,
                   cpu_sum, cpu_count, memory_sum, memory_count, memory_max_bytes, samples,
                   coverage_mask, reserved_cpu_millis, reserved_memory_bytes FROM grouped WHERE true
            ON CONFLICT (organisation_id, instance_id, bucket_seconds, observed_at) DO UPDATE
            SET cpu_sum = target.cpu_sum + EXCLUDED.cpu_sum,
                cpu_count = target.cpu_count + EXCLUDED.cpu_count,
                memory_sum = target.memory_sum + EXCLUDED.memory_sum,
                memory_count = target.memory_count + EXCLUDED.memory_count,
                memory_max_bytes = greatest(target.memory_max_bytes, EXCLUDED.memory_max_bytes),
                samples = target.samples + EXCLUDED.samples,
                coverage_mask = target.coverage_mask | EXCLUDED.coverage_mask,
                reserved_cpu_millis = greatest(target.reserved_cpu_millis, EXCLUDED.reserved_cpu_millis),
                reserved_memory_bytes = greatest(target.reserved_memory_bytes, EXCLUDED.reserved_memory_bytes)
            RETURNING 1
        ), created AS (
            SELECT count(*) AS rows FROM grouped g
            WHERE NOT EXISTS (
                SELECT 1 FROM grund_app_metric_rollups r
                WHERE r.organisation_id = g.organisation_id AND r.instance_id = g.instance_id
                  AND r.bucket_seconds = 600 AND r.observed_at = g.observed_at
            )
        )
        UPDATE grund_app_telemetry_usage
        SET metric_bytes = metric_bytes + ((SELECT rows FROM created) - (SELECT count(*) FROM source)) * $3
        WHERE organisation_id = $1 AND (SELECT count(*) FROM written) >= 0"#,
    )
    .bind(org)
    .bind(policy.metric_seconds)
    .bind(METRIC_ROW_BYTES)
    .execute(&mut *connection)
    .await?;

    sqlx::query("SELECT set_config('grund.telemetry_compacting', 'off', true)")
        .execute(&mut *connection)
        .await?;

    sqlx::query(
        r#"WITH budget AS MATERIALIZED (
            SELECT least(4096, greatest(0, (metric_bytes + $2 - $3 + $4 - 1) / $4)) AS rows
            FROM grund_app_telemetry_usage WHERE organisation_id = $1
        ), oldest_raw AS MATERIALIZED (
            SELECT observed_at, cursor FROM grund_app_metrics
            WHERE organisation_id = $1 AND (SELECT rows > 0 FROM budget)
            ORDER BY observed_at, cursor LIMIT (SELECT rows FROM budget)
        ), oldest_rollups AS MATERIALIZED (
            SELECT observed_at, instance_id, bucket_seconds FROM grund_app_metric_rollups
            WHERE organisation_id = $1 AND (SELECT rows > 0 FROM budget)
            ORDER BY observed_at, instance_id, bucket_seconds LIMIT (SELECT rows FROM budget)
        ), oldest AS MATERIALIZED (
            SELECT * FROM (
                SELECT observed_at, 0 AS kind, cursor, NULL::uuid AS instance_id, 0 AS bucket_seconds FROM oldest_raw
                UNION ALL
                SELECT observed_at, 1, 0::bigint, instance_id, bucket_seconds FROM oldest_rollups
            ) both_tables ORDER BY observed_at, kind, cursor, instance_id, bucket_seconds
            LIMIT (SELECT rows FROM budget)
        ), raw AS (
            DELETE FROM grund_app_metrics WHERE organisation_id = $1
              AND cursor IN (SELECT cursor FROM oldest WHERE kind = 0) RETURNING 1
        ), rolled AS (
            DELETE FROM grund_app_metric_rollups WHERE organisation_id = $1
              AND (instance_id, bucket_seconds, observed_at) IN (
                  SELECT instance_id, bucket_seconds, observed_at FROM oldest WHERE kind = 1
              ) RETURNING 1
        )
        UPDATE grund_app_telemetry_usage
        SET metric_bytes = metric_bytes - ((SELECT count(*) FROM raw) + (SELECT count(*) FROM rolled)) * $4
        WHERE organisation_id = $1"#,
    )
    .bind(org)
    .bind(incoming_metrics)
    .bind(policy.metric_bytes)
    .bind(METRIC_ROW_BYTES)
    .execute(connection)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn query(
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
    sqlx::query_as(
        r#"WITH measurements AS (
            SELECT observed_at, instance_id, release, cpu_millis AS cpu_sum,
                   (cpu_millis IS NOT NULL)::int::bigint AS cpu_count,
                   memory_bytes::numeric AS memory_sum, (memory_bytes IS NOT NULL)::int::bigint AS memory_count,
                   memory_bytes AS memory_max_bytes, reserved_cpu_millis, reserved_memory_bytes, 1::bigint AS samples
            FROM grund_app_metrics
            WHERE organisation_id = $1 AND app_id = $2
              AND ($3::uuid IS NULL OR instance_id = $3) AND ($4::int IS NULL OR release = $4)
              AND observed_at >= $5 AND observed_at <= $6
              AND observed_at > statement_timestamp() - make_interval(secs => $8::double precision)
            UNION ALL
            SELECT observed_at, instance_id, release, cpu_sum, cpu_count, memory_sum, memory_count,
                   memory_max_bytes, reserved_cpu_millis, reserved_memory_bytes, samples
            FROM grund_app_metric_rollups
            WHERE organisation_id = $1 AND app_id = $2
              AND ($3::uuid IS NULL OR instance_id = $3) AND ($4::int IS NULL OR release = $4)
              AND observed_at > $5 - interval '10 minutes'
              AND observed_at + make_interval(secs => bucket_seconds) > $5 AND observed_at <= $6
              AND observed_at > statement_timestamp() - make_interval(secs => $8::double precision)
        )
        SELECT to_timestamp(floor(extract(epoch FROM observed_at) / $7::int) * $7::int) AS at,
               instance_id, release,
               (sum(cpu_sum) / nullif(sum(cpu_count), 0))::float8 AS cpu_millis,
               (sum(memory_sum) / nullif(sum(memory_count), 0))::float8 AS memory_bytes,
               max(memory_max_bytes)::float8 AS memory_max_bytes,
               max(reserved_cpu_millis) AS reserved_cpu_millis,
               max(reserved_memory_bytes) AS reserved_memory_bytes, sum(samples)::bigint AS samples
        FROM measurements
        WHERE EXISTS (SELECT 1 FROM grund_apps WHERE organisation_id = $1 AND app_id = $2 AND deleted_at IS NULL)
        GROUP BY at, instance_id, release ORDER BY at, instance_id, release"#,
    )
    .bind(org)
    .bind(app)
    .bind(instance)
    .bind(release)
    .bind(since)
    .bind(until)
    .bind(bucket)
    .bind(retention)
    .fetch_all(pool)
    .await
}
