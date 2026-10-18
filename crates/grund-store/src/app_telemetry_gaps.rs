//! Bounded presence outages and received-measurement coverage for app read annotations.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

type InstanceIntervals = BTreeMap<Uuid, Vec<(DateTime<Utc>, DateTime<Utc>)>>;

const MAX_GAPS: usize = 1024;
const MAX_COVERAGE: usize = 65_536;

/// A half-open missing interval, with authoritative offline or evicted-history attribution.
#[derive(Debug, sqlx::FromRow)]
pub struct Gap {
    pub since: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub instance_id: Uuid,
    pub machine_id: Uuid,
    pub offline: bool,
}

#[derive(sqlx::FromRow)]
struct Coverage {
    instance_id: Uuid,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct CoverageRow {
    instance_id: Uuid,
    since: DateTime<Utc>,
    bucket_seconds: i32,
    coverage_mask: i64,
}

/// Reclaims outage history under the caller's organisation usage lock.
pub async fn prune(connection: &mut PgConnection, org: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM grund_app_telemetry_outages WHERE organisation_id=$1 AND ended_at <= statement_timestamp() - interval '7 days'")
        .bind(org).execute(connection).await?;
    Ok(())
}

/// Reads only placed app intervals, subtracting all retained raw and replayed rollups.
/// Log consumers must not infer emission counts or completeness from these intervals.
#[allow(clippy::too_many_arguments)]
pub async fn query(
    pool: &PgPool,
    org: Uuid,
    app: Uuid,
    instance: Option<Uuid>,
    release: Option<i32>,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Vec<Gap>, sqlx::Error> {
    let until = until.min(Utc::now());
    let since = since
        .max(until - Duration::days(7))
        .max(Utc::now() - Duration::days(7));
    if since >= until {
        return Ok(Vec::new());
    }
    let mut transaction = pool.begin().await?;
    sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY; SET LOCAL statement_timeout = '5s'")
        .execute(&mut *transaction).await?;
    let gaps = sqlx::query_as::<_, Gap>(
        "WITH placements AS MATERIALIZED ( \
           SELECT instance_id,machine_id,placed_at,stopped_at,metric_coverage_lost_before FROM grund_app_telemetry_instances \
           WHERE organisation_id=$1 AND app_id=$2 AND ($3::uuid IS NULL OR instance_id=$3) \
             AND ($4::integer IS NULL OR release=$4) AND placed_at < $6 \
             AND (stopped_at IS NULL OR stopped_at > $5) ORDER BY placed_at,instance_id LIMIT 1025), \
         outages AS ( \
           SELECT i.instance_id,i.machine_id,greatest(o.started_at,i.placed_at,i.metric_coverage_lost_before,$5) AS since, \
             least(o.ended_at,coalesce(i.stopped_at,$6),$6) AS until \
           FROM placements i JOIN grund_app_telemetry_outages o ON o.organisation_id=$1 AND o.machine_id=i.machine_id \
           WHERE o.ended_at > $5 AND o.started_at < $6 \
           UNION ALL \
           SELECT i.instance_id,i.machine_id,greatest(p.last_seen_at + interval '30 seconds',i.placed_at,i.metric_coverage_lost_before,$5), \
             least(coalesce(i.stopped_at,$6),$6) \
           FROM placements i JOIN grund_machine_presence p ON p.machine_id=i.machine_id \
           JOIN grund_machines m ON m.machine_id=i.machine_id AND m.pool_organisation_id=$1 \
           WHERE p.telemetry_organisation_id=$1 AND p.last_seen_at + interval '30 seconds' < $6) \
         SELECT since,until,instance_id,machine_id,true AS offline FROM outages WHERE since < until \
         UNION ALL SELECT greatest(placed_at,$5),least(metric_coverage_lost_before,coalesce(stopped_at,$6),$6), \
           instance_id,machine_id,false FROM placements \
           WHERE metric_coverage_lost_before > greatest(placed_at,$5) \
             AND least(metric_coverage_lost_before,coalesce(stopped_at,$6),$6) > greatest(placed_at,$5) \
         UNION ALL SELECT $5,$6,'00000000-0000-0000-0000-000000000000'::uuid,'00000000-0000-0000-0000-000000000000'::uuid,false \
           WHERE (SELECT count(*) FROM placements)>1024 LIMIT 1025",
    )
    .bind(org).bind(app).bind(instance).bind(release).bind(since).bind(until)
    .fetch_all(&mut *transaction).await?;
    if gaps.len() > MAX_GAPS || gaps.iter().any(|gap| gap.instance_id.is_nil()) {
        return Err(sqlx::Error::Protocol(
            "too many outage placements; filter by instance or release".into(),
        ));
    }
    if gaps.is_empty() {
        transaction.commit().await?;
        return Ok(gaps);
    }
    let mut instances: Vec<_> = gaps.iter().map(|gap| gap.instance_id).collect();
    instances.sort_unstable();
    instances.dedup();
    let coverage = sqlx::query_as::<_, CoverageRow>(
        "SELECT instance_id,to_timestamp(floor(extract(epoch FROM observed_at)/10)*10) AS since, \
           10::integer AS bucket_seconds,1::bigint AS coverage_mask \
         FROM grund_app_metrics WHERE organisation_id=$1 AND app_id=$2 AND instance_id=ANY($7) \
           AND ($3::uuid IS NULL OR instance_id=$3) AND ($4::integer IS NULL OR release=$4) \
           AND observed_at >= $5 - interval '10 seconds' AND observed_at < $6 \
         UNION ALL \
         SELECT instance_id,observed_at,bucket_seconds,coverage_mask \
         FROM grund_app_metric_rollups WHERE organisation_id=$1 AND app_id=$2 AND instance_id=ANY($7) \
           AND ($3::uuid IS NULL OR instance_id=$3) AND ($4::integer IS NULL OR release=$4) \
           AND observed_at >= $5 - interval '600 seconds' AND observed_at < $6 LIMIT 65537",
    )
    .bind(org).bind(app).bind(instance).bind(release).bind(since).bind(until)
    .bind(&instances)
    .fetch_all(&mut *transaction).await?;
    if coverage.len() > MAX_COVERAGE {
        return Err(sqlx::Error::Protocol(
            "too much outage coverage; filter by instance or release".into(),
        ));
    }
    transaction.commit().await?;
    let coverage = expand_coverage(coverage, &gaps)?;
    subtract(gaps, coverage)
}

fn expand_coverage(rows: Vec<CoverageRow>, gaps: &[Gap]) -> Result<Vec<Coverage>, sqlx::Error> {
    let mut windows = InstanceIntervals::new();
    for gap in gaps {
        windows
            .entry(gap.instance_id)
            .or_default()
            .push((gap.since, gap.until));
    }
    for ranges in windows.values_mut() {
        ranges.sort_unstable();
    }
    let mut result = Vec::new();
    for row in rows {
        let Some(windows) = windows.get(&row.instance_id) else {
            continue;
        };
        let mut mask = row.coverage_mask as u64;
        while mask != 0 {
            let start = mask.trailing_zeros();
            let width = (mask >> start).trailing_ones();
            mask &= !(((1_u64 << width) - 1) << start);
            let since = row.since + Duration::seconds(i64::from(start) * 10);
            let until = (row.since + Duration::seconds(i64::from(start + width) * 10))
                .min(row.since + Duration::seconds(i64::from(row.bucket_seconds)));
            let first = windows.partition_point(|(_, end)| *end <= since);
            for &(gap_start, gap_end) in &windows[first..] {
                if gap_start >= until {
                    break;
                }
                result.push(Coverage {
                    instance_id: row.instance_id,
                    since: since.max(gap_start),
                    until: until.min(gap_end),
                });
                if result.len() > MAX_COVERAGE {
                    return Err(sqlx::Error::Protocol(
                        "too much fragmented outage evidence; filter by instance or release".into(),
                    ));
                }
            }
        }
    }
    Ok(result)
}

fn subtract(gaps: Vec<Gap>, coverage: Vec<Coverage>) -> Result<Vec<Gap>, sqlx::Error> {
    let mut by_instance = InstanceIntervals::new();
    for row in coverage {
        by_instance
            .entry(row.instance_id)
            .or_default()
            .push((row.since, row.until));
    }
    for rows in by_instance.values_mut() {
        rows.sort_unstable();
        let mut merged = 0;
        for index in 0..rows.len() {
            let (start, end) = rows[index];
            if merged > 0 && rows[merged - 1].1 >= start {
                rows[merged - 1].1 = rows[merged - 1].1.max(end);
            } else {
                rows[merged] = (start, end);
                merged += 1;
            }
        }
        rows.truncate(merged);
    }
    let mut result = Vec::new();
    for gap in gaps {
        let mut cursor = gap.since;
        if let Some(rows) = by_instance.get(&gap.instance_id) {
            for &(start, end) in rows {
                if end <= cursor {
                    continue;
                }
                if start >= gap.until {
                    break;
                }
                if start > cursor {
                    result.push(Gap {
                        since: cursor,
                        until: start.min(gap.until),
                        instance_id: gap.instance_id,
                        machine_id: gap.machine_id,
                        offline: gap.offline,
                    });
                }
                cursor = cursor.max(end);
                if cursor >= gap.until {
                    break;
                }
                if result.len() > MAX_GAPS {
                    return Err(sqlx::Error::Protocol(
                        "too many outage fragments; filter by instance or release".into(),
                    ));
                }
            }
        }
        if cursor < gap.until {
            result.push(Gap {
                since: cursor,
                until: gap.until,
                instance_id: gap.instance_id,
                machine_id: gap.machine_id,
                offline: gap.offline,
            });
        }
        if result.len() > MAX_GAPS {
            return Err(sqlx::Error::Protocol(
                "too many outage fragments; filter by instance or release".into(),
            ));
        }
    }
    result.sort_unstable_by_key(|gap| (gap.since, gap.instance_id));
    Ok(result)
}

#[cfg(test)]
#[path = "app_telemetry_gap_tests.rs"]
mod tests;
