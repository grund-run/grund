//! The traffic path's reads and writes (migration 0016; grund-docs
//! design/traffic.md §6.7, §8.1): which machines run a copy of which app,
//! suspended apps, and the entry bytes edges report.

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{PgConnection, PgExecutor, types::Json};
use uuid::Uuid;

/// One running copy of a live app, or a live app with none (`replica_id`
/// unset), with what the route table and documents need of it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RouteRow {
    pub app_id: Uuid,
    pub organisation_id: Uuid,
    pub app_name: String,
    pub organisation_slug: String,
    pub app_created_at: DateTime<Utc>,
    pub suspended: bool,
    /// The spec of the app's current release, if it has one.
    pub current_spec: Option<Json<grund_domain::app::AppSpec>>,
    pub replica_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub spec: Option<Json<grund_domain::app::AppSpec>>,
    /// The machine's key, lowercase hex: its iroh endpoint id.
    pub machine_key: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub relay_url: Option<String>,
}

/// Every live app and its running (not draining) copies, oldest app first.
pub async fn route_rows(executor: impl PgExecutor<'_>) -> Result<Vec<RouteRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.app_id, a.organisation_id, a.name AS app_name, o.slug AS organisation_slug, \
                a.created_at AS app_created_at, (s.app_id IS NOT NULL) AS suspended, \
                cur.spec AS current_spec, r.replica_id, r.machine_id, rel.spec, m.public_key AS machine_key, \
                p.last_seen_at, \
                (SELECT ns.home_relay_url FROM grund_network_slots ns \
                  WHERE ns.machine_id = r.machine_id AND ns.freed_at IS NULL \
                  ORDER BY ns.assigned_at DESC LIMIT 1) AS relay_url \
           FROM grund_apps a \
           JOIN grund_organisations o ON o.organisation_id = a.organisation_id \
           LEFT JOIN grund_app_suspensions s ON s.app_id = a.app_id \
           LEFT JOIN grund_releases cur ON cur.app_id = a.app_id AND cur.number = a.current_release \
           LEFT JOIN grund_replicas r ON r.app_id = a.app_id AND r.state = 'running' \
           LEFT JOIN grund_releases rel ON rel.app_id = r.app_id AND rel.number = r.release \
           LEFT JOIN grund_machines m ON m.machine_id = r.machine_id AND m.state <> 'revoked' \
           LEFT JOIN grund_machine_presence p ON p.machine_id = r.machine_id \
          WHERE a.deleted_at IS NULL \
          ORDER BY a.created_at, a.app_id, r.machine_id, r.replica_id",
    )
    .fetch_all(executor)
    .await
}

/// A live app's name and its organisation's slug, with when it was made.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AppNameRow {
    pub app_id: Uuid,
    pub app_name: String,
    pub organisation_slug: String,
    pub app_created_at: DateTime<Utc>,
}

/// Every live app whose `<app>-<organisation>` is `label`, oldest first:
/// the first holds the address (traffic.md §2, "address").
pub async fn apps_named(
    executor: impl PgExecutor<'_>,
    label: &str,
) -> Result<Vec<AppNameRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.app_id, a.name AS app_name, o.slug AS organisation_slug, a.created_at AS app_created_at \
           FROM grund_apps a JOIN grund_organisations o ON o.organisation_id = a.organisation_id \
          WHERE a.deleted_at IS NULL AND a.name || '-' || o.slug = $1 \
          ORDER BY a.created_at, a.app_id",
    )
    .bind(label)
    .fetch_all(executor)
    .await
}

/// The slug of an organisation.
pub async fn organisation_slug(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT slug FROM grund_organisations WHERE organisation_id = $1")
        .bind(organisation_id)
        .fetch_optional(executor)
        .await
}

/// Suspends an app, or changes why. True when it was not suspended before.
pub async fn suspend(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
    reason: &str,
) -> Result<bool, sqlx::Error> {
    let inserted: Option<bool> = sqlx::query_scalar(
        "INSERT INTO grund_app_suspensions (app_id, reason) VALUES ($1, $2) \
         ON CONFLICT (app_id) DO UPDATE SET reason = EXCLUDED.reason \
         RETURNING (xmax = 0)",
    )
    .bind(app_id)
    .bind(reason)
    .fetch_optional(executor)
    .await?;
    Ok(inserted.unwrap_or(false))
}

/// Lifts a suspension. True when there was one.
pub async fn lift(executor: impl PgExecutor<'_>, app_id: Uuid) -> Result<bool, sqlx::Error> {
    let done = sqlx::query("DELETE FROM grund_app_suspensions WHERE app_id = $1")
        .bind(app_id)
        .execute(executor)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// The live app `name` of the organisation `slug`.
pub async fn app_by_slug(
    executor: impl PgExecutor<'_>,
    slug: &str,
    name: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT a.app_id FROM grund_apps a JOIN grund_organisations o ON o.organisation_id = a.organisation_id \
          WHERE o.slug = $1 AND a.name = $2 AND a.deleted_at IS NULL",
    )
    .bind(slug)
    .bind(name)
    .fetch_optional(executor)
    .await
}

/// One address's bytes on one path, as an edge reports them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRow {
    pub name: String,
    pub path: String,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub connections: i64,
}

/// Adds a report's usage to `day`, once per `report_id`. False when the
/// report was counted before.
pub async fn record_usage(
    connection: &mut PgConnection,
    report_id: Uuid,
    edge_id: Uuid,
    day: NaiveDate,
    usage: &[UsageRow],
) -> Result<bool, sqlx::Error> {
    let fresh = sqlx::query(
        "INSERT INTO grund_entry_usage_reports (report_id, edge_id) VALUES ($1, $2) \
         ON CONFLICT (report_id) DO NOTHING",
    )
    .bind(report_id)
    .bind(edge_id)
    .execute(&mut *connection)
    .await?
    .rows_affected()
        > 0;
    if !fresh {
        return Ok(false);
    }
    for row in usage {
        sqlx::query(
            "INSERT INTO grund_entry_usage (day, name, path, bytes_in, bytes_out, connections) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (day, name, path) DO UPDATE SET \
               bytes_in = grund_entry_usage.bytes_in + EXCLUDED.bytes_in, \
               bytes_out = grund_entry_usage.bytes_out + EXCLUDED.bytes_out, \
               connections = grund_entry_usage.connections + EXCLUDED.connections",
        )
        .bind(day)
        .bind(&row.name)
        .bind(&row.path)
        .bind(row.bytes_in)
        .bind(row.bytes_out)
        .bind(row.connections)
        .execute(&mut *connection)
        .await?;
    }
    Ok(true)
}

/// The usage of `day`, by name and path.
pub async fn usage_of(
    executor: impl PgExecutor<'_>,
    day: NaiveDate,
) -> Result<Vec<UsageRow>, sqlx::Error> {
    let rows: Vec<(String, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT name, path, bytes_in, bytes_out, connections FROM grund_entry_usage \
          WHERE day = $1 ORDER BY name, path",
    )
    .bind(day)
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(name, path, bytes_in, bytes_out, connections)| UsageRow {
            name,
            path,
            bytes_in,
            bytes_out,
            connections,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn a_report_is_counted_once_and_adds_to_its_day(pool: PgPool) {
        let day = NaiveDate::from_ymd_opt(2026, 10, 1).unwrap();
        let row = UsageRow {
            name: "photos-kasper.grund.run".into(),
            path: "relay".into(),
            bytes_in: 10,
            bytes_out: 100,
            connections: 1,
        };
        let (first, second, edge) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mut tx = pool.begin().await.unwrap();
        assert!(
            record_usage(&mut tx, first, edge, day, std::slice::from_ref(&row))
                .await
                .unwrap()
        );
        assert!(
            !record_usage(&mut tx, first, edge, day, std::slice::from_ref(&row))
                .await
                .unwrap()
        );
        assert!(
            record_usage(&mut tx, second, edge, day, std::slice::from_ref(&row))
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
        assert_eq!(
            usage_of(&pool, day).await.unwrap(),
            vec![UsageRow {
                bytes_in: 20,
                bytes_out: 200,
                connections: 2,
                ..row
            }]
        );
    }
}
