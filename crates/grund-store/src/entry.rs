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
    pub current_spec: Option<Json<grund_config::app::spec::AppSpec>>,
    pub replica_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub spec: Option<Json<grund_config::app::spec::AppSpec>>,
    pub ready: bool,
    pub migration_paused: bool,
    /// The machine's key, lowercase hex: its iroh endpoint id.
    pub machine_key: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub relay_url: Option<String>,
}

/// Every live app and its running (not draining) copies, oldest app first.
pub async fn route_rows(executor: impl PgExecutor<'_>) -> Result<Vec<RouteRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.app_id, a.organisation_id, COALESCE(stack.name,a.name) AS app_name, o.slug AS organisation_slug, \
                COALESCE((stack.state->'revisions'->'1'->>'created_at')::timestamptz,a.created_at) AS app_created_at, (s.app_id IS NOT NULL) AS suspended, \
                cur.spec AS current_spec, r.replica_id, r.machine_id, rel.spec, \
                COALESCE(rs.ready, false) AS ready, \
                (pause.machine_id IS NOT NULL) AS migration_paused, \
                m.public_key AS machine_key, p.last_seen_at, \
                (SELECT ns.home_relay_url FROM grund_network_slots ns \
                  WHERE ns.machine_id = r.machine_id AND ns.freed_at IS NULL \
                  ORDER BY ns.assigned_at DESC LIMIT 1) AS relay_url \
           FROM grund_apps a \
           JOIN grund_organisations o ON o.organisation_id = a.organisation_id \
           LEFT JOIN grund_stack_members member ON member.organisation_id=a.organisation_id AND member.app_id=a.app_id \
           LEFT JOIN grund_stacks stack ON stack.organisation_id=member.organisation_id AND stack.stack_id=member.stack_id \
           LEFT JOIN grund_app_suspensions s ON s.app_id = a.app_id \
           LEFT JOIN grund_releases cur ON cur.app_id = a.app_id AND cur.number = a.current_release \
           LEFT JOIN grund_replicas r ON r.app_id = a.app_id AND r.state = 'running' \
           LEFT JOIN grund_releases rel ON rel.app_id = r.app_id AND rel.number = r.release \
           LEFT JOIN grund_replica_status rs ON rs.replica_id = r.replica_id AND rs.machine_id = r.machine_id \
           LEFT JOIN grund_machines m ON m.machine_id = r.machine_id AND m.state <> 'revoked' \
           LEFT JOIN grund_machine_presence p ON p.machine_id = r.machine_id \
           LEFT JOIN grund_machine_migration_pauses pause \
             ON pause.machine_id = m.machine_id AND pause.expires_at > clock_timestamp() \
          WHERE a.deleted_at IS NULL AND (member.app_id IS NULL OR (stack.status NOT IN ('deleted','deleting') \
            AND stack.state->'revisions'->(stack.state->>'desired_revision')->>'public_service'=member.service)) \
          ORDER BY app_created_at, a.app_id, r.machine_id, r.replica_id",
    )
    .fetch_all(executor)
    .await
}

/// Records a bounded pause for a provider-owned management machine, or clears
/// only the migration that set it. An unknown provider id has the same result
/// as a revoked machine.
pub async fn set_migration_pause(
    executor: impl PgExecutor<'_>,
    provider_machine_id: &str,
    migration_id: Uuid,
    paused: bool,
) -> Result<bool, sqlx::Error> {
    if paused {
        let row: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO grund_machine_migration_pauses (machine_id, migration_id, expires_at) \
             SELECT machine_id, $2, clock_timestamp() + interval '120 seconds' \
               FROM grund_machines WHERE provider_machine_id = $1 \
                 AND pool = 'management' AND state <> 'revoked' \
               ORDER BY registered_at DESC LIMIT 1 \
             ON CONFLICT (machine_id) DO UPDATE SET migration_id = EXCLUDED.migration_id, \
                 expires_at = CASE WHEN grund_machine_migration_pauses.migration_id = EXCLUDED.migration_id \
                   THEN grund_machine_migration_pauses.expires_at ELSE EXCLUDED.expires_at END, \
                 clear_requested_at = CASE WHEN grund_machine_migration_pauses.migration_id = EXCLUDED.migration_id \
                   THEN grund_machine_migration_pauses.clear_requested_at ELSE NULL END, \
                 recovery_heartbeat_at = CASE WHEN grund_machine_migration_pauses.migration_id = EXCLUDED.migration_id \
                   THEN grund_machine_migration_pauses.recovery_heartbeat_at ELSE NULL END \
               WHERE grund_machine_migration_pauses.migration_id = EXCLUDED.migration_id \
                  OR grund_machine_migration_pauses.expires_at <= clock_timestamp() \
             RETURNING machine_id",
        )
        .bind(provider_machine_id)
        .bind(migration_id)
        .fetch_optional(executor)
        .await?;
        Ok(row.is_some())
    } else {
        sqlx::query_scalar(
            "WITH machine AS (SELECT machine_id FROM grund_machines \
               WHERE provider_machine_id = $1 AND pool = 'management' AND state <> 'revoked' \
               ORDER BY registered_at DESC LIMIT 1), \
             settling AS (UPDATE grund_machine_migration_pauses p \
               SET clear_requested_at = clock_timestamp(), \
                   expires_at = clock_timestamp() + interval '10 seconds' \
               FROM machine m WHERE p.machine_id = m.machine_id AND p.migration_id = $2 \
                 AND p.clear_requested_at IS NULL RETURNING p.machine_id) \
             SELECT EXISTS(SELECT 1 FROM machine)",
        )
        .bind(provider_machine_id)
        .bind(migration_id)
        .fetch_one(executor)
        .await
    }
}

/// Clears a settling pause only after this agent has both heartbeated and
/// reported one of its own running copies ready since Fleet's restore clear.
pub async fn finish_settled_pause(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "DELETE FROM grund_machine_migration_pauses pause \
         WHERE pause.machine_id = $1 AND pause.clear_requested_at IS NOT NULL \
           AND pause.expires_at > clock_timestamp() \
           AND pause.recovery_heartbeat_at > pause.clear_requested_at \
           AND EXISTS (SELECT 1 FROM grund_replicas r \
             JOIN grund_replica_status rs ON rs.replica_id = r.replica_id \
               AND rs.machine_id = r.machine_id \
             WHERE r.machine_id = pause.machine_id AND r.state = 'running' \
               AND rs.state = 'running' AND rs.ready \
               AND rs.observed_at > pause.clear_requested_at) \
         RETURNING pause.migration_id",
    )
    .bind(machine_id)
    .fetch_optional(executor)
    .await
}

/// Remove expired pauses when building the next route table, recording which
/// migrations had to fall back to their deadline.
pub async fn expire_migration_pauses(
    executor: impl PgExecutor<'_>,
) -> Result<Vec<(Uuid, Uuid, bool, DateTime<Utc>)>, sqlx::Error> {
    sqlx::query_as(
        "DELETE FROM grund_machine_migration_pauses WHERE expires_at <= clock_timestamp() \
         RETURNING machine_id, migration_id, (clear_requested_at IS NOT NULL), expires_at",
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
        "SELECT a.app_id, COALESCE(stack.name,a.name) AS app_name, o.slug AS organisation_slug, \
           COALESCE((stack.state->'revisions'->'1'->>'created_at')::timestamptz,a.created_at) AS app_created_at \
         FROM grund_apps a JOIN grund_organisations o ON o.organisation_id=a.organisation_id \
         LEFT JOIN grund_stack_members member ON member.organisation_id=a.organisation_id AND member.app_id=a.app_id \
         LEFT JOIN grund_stacks stack ON stack.organisation_id=member.organisation_id AND stack.stack_id=member.stack_id \
         WHERE a.deleted_at IS NULL AND COALESCE(stack.name,a.name)||'-'||o.slug=$1 \
           AND (member.app_id IS NULL OR (stack.status NOT IN ('deleted','deleting') \
             AND stack.state->'revisions'->(stack.state->>'desired_revision')->>'public_service'=member.service)) \
         ORDER BY app_created_at,a.app_id",
    )
    .bind(label)
    .fetch_all(executor)
    .await
}

/// An ordinary app name, or the stable owning stack name for its selected public
/// service. Nonpublic members deliberately have no independent shared address.
pub async fn public_name(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(stack.name,a.name) FROM grund_apps a \
         LEFT JOIN grund_stack_members member ON member.organisation_id=a.organisation_id AND member.app_id=a.app_id \
         LEFT JOIN grund_stacks stack ON stack.organisation_id=member.organisation_id AND stack.stack_id=member.stack_id \
         WHERE a.app_id=$1 AND a.deleted_at IS NULL AND (member.app_id IS NULL OR (stack.status NOT IN ('deleted','deleting') \
           AND stack.state->'revisions'->(stack.state->>'desired_revision')->>'public_service'=member.service))",
    ).bind(app_id).fetch_optional(executor).await
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
        "SELECT a.app_id FROM grund_apps a JOIN grund_organisations o ON o.organisation_id=a.organisation_id \
         LEFT JOIN grund_stack_members member ON member.organisation_id=a.organisation_id AND member.app_id=a.app_id \
         LEFT JOIN grund_stacks stack ON stack.organisation_id=member.organisation_id AND stack.stack_id=member.stack_id \
         WHERE o.slug=$1 AND COALESCE(stack.name,a.name)=$2 AND a.deleted_at IS NULL \
           AND (member.app_id IS NULL OR (stack.status NOT IN ('deleted','deleting') \
             AND stack.state->'revisions'->(stack.state->>'desired_revision')->>'public_service'=member.service))",
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
    async fn a_stack_address_survives_public_child_changes_and_keeps_collision_precedence(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        use grund_config::app::spec::{AppName, AppSettings};
        use grund_domain::app::AppEvent;
        let (org, other, stack, first, second, ordinary) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        let at = Utc::now();
        let mut connection = pool.acquire().await?;
        for (id, slug) in [(org, "blue-one"), (other, "one")] {
            sqlx::query("INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) \
                VALUES($1,$2,'personal',$3,1)").bind(id).bind(slug).bind(at)
                .execute(&mut *connection).await?;
        }
        for (id, tenant, name, created_at) in [
            (first, org, "sfirst", at),
            (second, org, "ssecond", at + chrono::Duration::seconds(10)),
            (
                ordinary,
                other,
                "shop-blue",
                at + chrono::Duration::seconds(5),
            ),
        ] {
            crate::apps::apply_app(
                id,
                1,
                &AppEvent::Created {
                    organisation_id: tenant,
                    name: AppName::parse(name)?,
                    settings: AppSettings::default(),
                    created_by: Uuid::nil(),
                    created_at,
                },
                &mut connection,
            )
            .await?;
        }
        let state = serde_json::json!({
            "desired_revision": 1,
            "revisions": {
                "1": {"created_at": at, "public_service": "web"},
                "2": {"created_at": at + chrono::Duration::seconds(10), "public_service": "api"}
            }
        });
        sqlx::query(
            "INSERT INTO grund_stacks(organisation_id,stack_id,name,state,status,stream_version) \
            VALUES($1,$2,'shop',$3,'deploying',1)",
        )
        .bind(org)
        .bind(stack)
        .bind(sqlx::types::Json(state))
        .execute(&mut *connection)
        .await?;
        for (app, service, name) in [(first, "web", "sfirst"), (second, "api", "ssecond")] {
            sqlx::query("INSERT INTO grund_stack_members(organisation_id,stack_id,service,app_id,app_name,exclusive) \
                VALUES($1,$2,$3,$4,$5,false)").bind(org).bind(stack).bind(service).bind(app).bind(name)
                .execute(&mut *connection).await?;
        }
        assert_eq!(public_name(&pool, first).await?.as_deref(), Some("shop"));
        assert_eq!(public_name(&pool, second).await?, None);
        assert_eq!(apps_named(&pool, "shop-blue-one").await?[0].app_id, first);
        assert!(apps_named(&pool, "sfirst-blue-one").await?.is_empty());
        sqlx::query("UPDATE grund_stacks SET state=jsonb_set(state,'{desired_revision}','2') WHERE organisation_id=$1 AND stack_id=$2")
            .bind(org).bind(stack).execute(&mut *connection).await?;
        let holders = apps_named(&pool, "shop-blue-one").await?;
        assert_eq!(
            holders.iter().map(|row| row.app_id).collect::<Vec<_>>(),
            [second, ordinary]
        );
        assert_eq!(public_name(&pool, first).await?, None);
        assert_eq!(public_name(&pool, second).await?.as_deref(), Some("shop"));
        assert_eq!(app_by_slug(&pool, "blue-one", "shop").await?, Some(second));
        assert_eq!(app_by_slug(&pool, "blue-one", "ssecond").await?, None);
        let rows = route_rows(&pool).await?;
        assert!(!rows.iter().any(|row| row.app_id == first));
        assert_eq!(
            rows.iter()
                .find(|row| row.app_id == second)
                .unwrap()
                .app_name,
            "shop"
        );
        sqlx::query(
            "UPDATE grund_stacks SET status='deleting' WHERE organisation_id=$1 AND stack_id=$2",
        )
        .bind(org)
        .bind(stack)
        .execute(&mut *connection)
        .await?;
        assert_eq!(public_name(&pool, second).await?, None);
        assert_eq!(app_by_slug(&pool, "blue-one", "shop").await?, None);
        assert_eq!(
            apps_named(&pool, "shop-blue-one")
                .await?
                .iter()
                .map(|row| row.app_id)
                .collect::<Vec<_>>(),
            [ordinary]
        );
        assert!(
            !route_rows(&pool)
                .await?
                .iter()
                .any(|row| row.app_id == second)
        );
        Ok(())
    }

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
