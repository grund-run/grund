//! Apps, their releases and replicas (grund-docs design/apps.md §10.2): the
//! read model of the grund-app streams ([`apply_app`]), what machines report
//! about replicas, and sealed secret values.

use chrono::{DateTime, Utc};
use grund_domain::app::{AppEvent, DrainReason, PlaceReason};
use serde_json::{Value, json};
use sqlx::{FromRow, PgConnection, PgExecutor, types::Json};
use uuid::Uuid;

/// Applies one app event at `version`. Every event after `Created` first
/// claims its version on the app's row; one at or below it was applied
/// already and changes nothing.
pub async fn apply_app(
    app_id: Uuid,
    version: i64,
    event: &AppEvent,
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    if let AppEvent::Created {
        organisation_id,
        name,
        settings,
        created_by,
        created_at,
    } = event
    {
        sqlx::query(
            "INSERT INTO grund_apps (app_id, organisation_id, name, settings, created_by, created_at, stream_version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (app_id) DO UPDATE SET organisation_id = EXCLUDED.organisation_id, \
               name = EXCLUDED.name, settings = EXCLUDED.settings, created_by = EXCLUDED.created_by, \
               created_at = EXCLUDED.created_at, stream_version = EXCLUDED.stream_version \
             WHERE grund_apps.stream_version < EXCLUDED.stream_version",
        )
        .bind(app_id)
        .bind(organisation_id)
        .bind(name.as_str())
        .bind(Json(settings))
        .bind(created_by)
        .bind(created_at)
        .bind(version)
        .execute(&mut *connection)
        .await?;
        activity(
            connection,
            app_id,
            version,
            *created_at,
            "created",
            json!({}),
        )
        .await?;
        return Ok(());
    }
    let claimed = sqlx::query(
        "UPDATE grund_apps SET stream_version = $2 WHERE app_id = $1 AND stream_version < $2",
    )
    .bind(app_id)
    .bind(version)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Ok(());
    }
    match event {
        AppEvent::Created { .. } => {}
        AppEvent::Configured {
            settings,
            configured_by,
            configured_at,
        } => {
            sqlx::query("UPDATE grund_apps SET settings = $2 WHERE app_id = $1")
                .bind(app_id)
                .bind(Json(settings))
                .execute(&mut *connection)
                .await?;
            activity(
                connection,
                app_id,
                version,
                *configured_at,
                "configured",
                json!({ "copies": settings.copies, "by": configured_by }),
            )
            .await?;
        }
        AppEvent::ReleaseCreated { release } => {
            sqlx::query(
                "INSERT INTO grund_releases (app_id, number, spec, image_digest, platforms, \
                   secret_versions, source, rollback_of, note, created_by, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                 ON CONFLICT (app_id, number) DO NOTHING",
            )
            .bind(app_id)
            .bind(release.number as i32)
            .bind(Json(&release.spec))
            .bind(&release.image_digest)
            .bind(Json(&release.platforms))
            .bind(Json(&release.secret_versions))
            .bind(release.source.as_str())
            .bind(release.rollback_of.map(|n| n as i32))
            .bind(&release.note)
            .bind(release.created_by)
            .bind(release.created_at)
            .execute(&mut *connection)
            .await?;
            sqlx::query("UPDATE grund_apps SET halted = false WHERE app_id = $1")
                .bind(app_id)
                .execute(&mut *connection)
                .await?;
            activity(
                connection,
                app_id,
                version,
                release.created_at,
                "release_created",
                json!({
                    "release": release.number,
                    "image": release.spec.image,
                    "source": release.source.as_str(),
                    "rollback_of": release.rollback_of,
                    "by": release.created_by,
                }),
            )
            .await?;
        }
        AppEvent::RolloutStarted {
            rollout_id,
            from,
            to,
            started_at,
        } => {
            sqlx::query("UPDATE grund_apps SET rollout = $2 WHERE app_id = $1")
                .bind(app_id)
                .bind(json!({
                    "rollout_id": rollout_id,
                    "from": from,
                    "to": to,
                    "state": "in_progress",
                    "started_at": started_at,
                }))
                .execute(&mut *connection)
                .await?;
            set_outcome(connection, app_id, *to, "rolling_out", None, None).await?;
            activity(
                connection,
                app_id,
                version,
                *started_at,
                "rollout_started",
                json!({ "from": from, "to": to }),
            )
            .await?;
        }
        AppEvent::ReplicaPlaced {
            replica_id,
            slot,
            release,
            machine_id,
            placement,
            reason,
            placed_at,
        } => {
            sqlx::query(
                "INSERT INTO grund_replicas (replica_id, app_id, organisation_id, machine_id, slot, \
                   release, placement, state, placed_at) \
                 SELECT $1, $2, a.organisation_id, $3, $4, $5, $6, 'running', $7 \
                 FROM grund_apps a WHERE a.app_id = $2 \
                 ON CONFLICT (replica_id) DO NOTHING",
            )
            .bind(replica_id)
            .bind(app_id)
            .bind(machine_id)
            .bind(*slot as i32)
            .bind(*release as i32)
            .bind(*placement as i64)
            .bind(placed_at)
            .execute(&mut *connection)
            .await?;
            activity(
                connection,
                app_id,
                version,
                *placed_at,
                "replica_placed",
                json!({
                    "replica_id": replica_id,
                    "slot": slot,
                    "release": release,
                    "machine_id": machine_id,
                    "reason": place_reason(*reason),
                }),
            )
            .await?;
        }
        AppEvent::ReplicaDraining {
            replica_id,
            reason,
            draining_at,
        } => {
            sqlx::query(
                "UPDATE grund_replicas SET state = 'draining', draining_since = $2 WHERE replica_id = $1",
            )
            .bind(replica_id)
            .bind(draining_at)
            .execute(&mut *connection)
            .await?;
            let replica = replica_brief(connection, *replica_id).await?;
            activity(
                connection,
                app_id,
                version,
                *draining_at,
                "replica_draining",
                json!({
                    "replica_id": replica_id,
                    "reason": drain_reason(*reason),
                    "replica": replica,
                }),
            )
            .await?;
        }
        AppEvent::ReplicaRemoved {
            replica_id,
            removed_at,
        } => {
            let replica = replica_brief(connection, *replica_id).await?;
            sqlx::query("DELETE FROM grund_replicas WHERE replica_id = $1")
                .bind(replica_id)
                .execute(&mut *connection)
                .await?;
            activity(
                connection,
                app_id,
                version,
                *removed_at,
                "replica_removed",
                json!({ "replica_id": replica_id, "replica": replica }),
            )
            .await?;
        }
        AppEvent::ReplicaLost {
            replica_id,
            machine_id,
            lost_at,
        } => {
            let replica = replica_brief(connection, *replica_id).await?;
            sqlx::query("DELETE FROM grund_replicas WHERE replica_id = $1")
                .bind(replica_id)
                .execute(&mut *connection)
                .await?;
            activity(
                connection,
                app_id,
                version,
                *lost_at,
                "replica_lost",
                json!({ "replica_id": replica_id, "machine_id": machine_id, "replica": replica }),
            )
            .await?;
        }
        AppEvent::RolloutSucceeded {
            rollout_id,
            succeeded_at,
        } => {
            let to = end_rollout(
                connection,
                app_id,
                *rollout_id,
                "succeeded",
                None,
                *succeeded_at,
            )
            .await?;
            activity(
                connection,
                app_id,
                version,
                *succeeded_at,
                "rollout_succeeded",
                json!({ "release": to }),
            )
            .await?;
        }
        AppEvent::RolloutFailed {
            rollout_id,
            reason,
            rolled_back,
            failed_at,
        } => {
            let to = end_rollout(
                connection,
                app_id,
                *rollout_id,
                "failed",
                Some(reason),
                *failed_at,
            )
            .await?;
            if let Some(to) = to {
                set_outcome(
                    connection,
                    app_id,
                    to,
                    "failed",
                    Some(reason),
                    Some(*failed_at),
                )
                .await?;
            }
            sqlx::query("UPDATE grund_apps SET halted = $2 WHERE app_id = $1")
                .bind(app_id)
                .bind(!rolled_back)
                .execute(&mut *connection)
                .await?;
            activity(
                connection,
                app_id,
                version,
                *failed_at,
                "rollout_failed",
                json!({ "release": to, "reason": reason, "rolled_back": rolled_back }),
            )
            .await?;
        }
        AppEvent::RolloutSuperseded {
            rollout_id,
            by,
            superseded_at,
        } => {
            let to = end_rollout(
                connection,
                app_id,
                *rollout_id,
                "superseded",
                None,
                *superseded_at,
            )
            .await?;
            if let Some(to) = to {
                set_outcome(
                    connection,
                    app_id,
                    to,
                    "superseded",
                    None,
                    Some(*superseded_at),
                )
                .await?;
            }
            activity(
                connection,
                app_id,
                version,
                *superseded_at,
                "rollout_superseded",
                json!({ "release": to, "by": by }),
            )
            .await?;
        }
        AppEvent::CurrentReleaseSet { release, set_at } => {
            sqlx::query(
                "UPDATE grund_releases SET outcome = 'replaced' \
                 WHERE app_id = $1 AND outcome = 'live' AND number <> $2",
            )
            .bind(app_id)
            .bind(*release as i32)
            .execute(&mut *connection)
            .await?;
            set_outcome(connection, app_id, *release, "live", None, Some(*set_at)).await?;
            sqlx::query("UPDATE grund_apps SET current_release = $2 WHERE app_id = $1")
                .bind(app_id)
                .bind(*release as i32)
                .execute(&mut *connection)
                .await?;
            activity(
                connection,
                app_id,
                version,
                *set_at,
                "current_release_set",
                json!({ "release": release }),
            )
            .await?;
        }
        AppEvent::Deleted {
            deleted_by,
            deleted_at,
        } => {
            sqlx::query("UPDATE grund_apps SET deleted_at = $2 WHERE app_id = $1")
                .bind(app_id)
                .bind(deleted_at)
                .execute(&mut *connection)
                .await?;
            activity(
                connection,
                app_id,
                version,
                *deleted_at,
                "deleted",
                json!({ "by": deleted_by }),
            )
            .await?;
        }
    }
    Ok(())
}

fn place_reason(reason: PlaceReason) -> &'static str {
    match reason {
        PlaceReason::Scale => "scale",
        PlaceReason::Rollout => "rollout",
        PlaceReason::ReplaceLost => "replace_lost",
        PlaceReason::Spread => "spread",
    }
}

fn drain_reason(reason: DrainReason) -> &'static str {
    match reason {
        DrainReason::Replaced => "replaced",
        DrainReason::NoRoom => "no_room",
        DrainReason::ScaledDown => "scaled_down",
        DrainReason::NoRelease => "no_release",
        DrainReason::Deleted => "deleted",
    }
}

async fn replica_brief(
    connection: &mut PgConnection,
    replica_id: Uuid,
) -> Result<Value, sqlx::Error> {
    let row: Option<(i32, i32, Uuid)> = sqlx::query_as(
        "SELECT slot, release, machine_id FROM grund_replicas WHERE replica_id = $1",
    )
    .bind(replica_id)
    .fetch_optional(&mut *connection)
    .await?;
    Ok(row.map_or(Value::Null, |(slot, release, machine_id)| {
        json!({ "slot": slot, "release": release, "machine_id": machine_id })
    }))
}

async fn activity(
    connection: &mut PgConnection,
    app_id: Uuid,
    version: i64,
    at: DateTime<Utc>,
    kind: &str,
    detail: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_app_activity (app_id, version, at, kind, detail) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (app_id, version) DO NOTHING",
    )
    .bind(app_id)
    .bind(version)
    .bind(at)
    .bind(kind)
    .bind(detail)
    .execute(connection)
    .await?;
    Ok(())
}

async fn set_outcome(
    connection: &mut PgConnection,
    app_id: Uuid,
    number: u32,
    outcome: &str,
    reason: Option<&str>,
    ended_at: Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_releases SET outcome = $3, reason = $4, ended_at = $5 \
         WHERE app_id = $1 AND number = $2",
    )
    .bind(app_id)
    .bind(number as i32)
    .bind(outcome)
    .bind(reason.map(|r| r.chars().take(1000).collect::<String>()))
    .bind(ended_at)
    .execute(connection)
    .await?;
    Ok(())
}

async fn end_rollout(
    connection: &mut PgConnection,
    app_id: Uuid,
    rollout_id: Uuid,
    state: &str,
    reason: Option<&str>,
    at: DateTime<Utc>,
) -> Result<Option<u32>, sqlx::Error> {
    let to: Option<Option<i64>> = sqlx::query_scalar(
        "UPDATE grund_apps SET rollout = rollout || jsonb_build_object('state', $3::text, \
           'reason', $4::text, 'ended_at', $5::timestamptz) \
         WHERE app_id = $1 AND rollout->>'rollout_id' = $2::text \
         RETURNING (rollout->>'to')::bigint",
    )
    .bind(app_id)
    .bind(rollout_id.to_string())
    .bind(state)
    .bind(reason)
    .bind(at)
    .fetch_optional(connection)
    .await?;
    Ok(to.flatten().map(|n| n as u32))
}

/// An app as stored.
#[derive(Debug, Clone, FromRow)]
pub struct AppRow {
    pub app_id: Uuid,
    pub organisation_id: Uuid,
    pub name: String,
    pub settings: Json<grund_domain::app::AppSettings>,
    pub current_release: Option<i32>,
    pub rollout: Option<Value>,
    pub halted: bool,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub waiting: Value,
}

macro_rules! select_apps {
    ($tail:literal) => {
        concat!(
            "SELECT app_id, organisation_id, name, settings, current_release, rollout, halted, \
               created_at, deleted_at, waiting FROM grund_apps ",
            $tail
        )
    };
}

/// A live app of the organisation, by name.
pub async fn app_by_name(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    name: &str,
) -> Result<Option<AppRow>, sqlx::Error> {
    sqlx::query_as(select_apps!(
        "WHERE organisation_id = $1 AND name = $2 AND deleted_at IS NULL"
    ))
    .bind(organisation_id)
    .bind(name)
    .fetch_optional(executor)
    .await
}

pub async fn app(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Option<AppRow>, sqlx::Error> {
    sqlx::query_as(select_apps!("WHERE app_id = $1"))
        .bind(app_id)
        .fetch_optional(executor)
        .await
}

/// The organisation's live apps, by name.
pub async fn organisation_apps(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<AppRow>, sqlx::Error> {
    sqlx::query_as(select_apps!(
        "WHERE organisation_id = $1 AND deleted_at IS NULL ORDER BY name LIMIT 500"
    ))
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

pub async fn count_live_apps(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_apps WHERE organisation_id = $1 AND deleted_at IS NULL",
    )
    .bind(organisation_id)
    .fetch_one(executor)
    .await
}

/// Apps the reconciler should look at: live ones, and deleted ones that
/// still have replicas.
pub async fn apps_to_reconcile(
    executor: impl PgExecutor<'_>,
) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.app_id, a.organisation_id FROM grund_apps a \
         WHERE a.deleted_at IS NULL OR EXISTS (SELECT 1 FROM grund_replicas r WHERE r.app_id = a.app_id) \
         ORDER BY a.organisation_id, a.app_id",
    )
    .fetch_all(executor)
    .await
}

/// Records the slots the reconciler could not place, and when it looked.
pub async fn set_waiting(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
    waiting: &Value,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_apps SET waiting = $2, reconciled_at = $3 \
         WHERE app_id = $1 AND (waiting IS DISTINCT FROM $2 OR reconciled_at IS NULL \
           OR reconciled_at < $3 - interval '10 seconds')",
    )
    .bind(app_id)
    .bind(waiting)
    .bind(at)
    .execute(executor)
    .await?;
    Ok(())
}

/// A release as stored.
#[derive(Debug, Clone, FromRow)]
pub struct ReleaseRow {
    pub app_id: Uuid,
    pub number: i32,
    pub spec: Json<grund_domain::app::AppSpec>,
    pub image_digest: String,
    pub platforms: Json<Vec<String>>,
    pub secret_versions: Json<Vec<grund_domain::app::SecretVersion>>,
    pub source: String,
    pub rollback_of: Option<i32>,
    pub note: String,
    pub created_by: Uuid,
    pub created_by_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub outcome: Option<String>,
    pub reason: Option<String>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// The app's releases, newest first.
pub async fn releases(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
    limit: i64,
) -> Result<Vec<ReleaseRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.app_id, r.number, r.spec, r.image_digest, r.platforms, r.secret_versions, r.source, \
           r.rollback_of, r.note, r.created_by, a.username AS created_by_name, r.created_at, \
           r.outcome, r.reason, r.ended_at \
         FROM grund_releases r LEFT JOIN grund_accounts a ON a.account_id = r.created_by \
         WHERE r.app_id = $1 ORDER BY r.number DESC LIMIT $2",
    )
    .bind(app_id)
    .bind(limit)
    .fetch_all(executor)
    .await
}

/// A replica with what its machine last said about it.
#[derive(Debug, Clone, FromRow)]
pub struct ReplicaRow {
    pub replica_id: Uuid,
    pub app_id: Uuid,
    pub machine_id: Uuid,
    pub machine_name: Option<String>,
    pub slot: i32,
    pub release: i32,
    pub state: String,
    pub placed_at: DateTime<Utc>,
    pub observed_state: Option<String>,
    pub ready: Option<bool>,
    pub ready_since: Option<DateTime<Utc>>,
    pub restarts: Option<i32>,
    pub last_exit_code: Option<i32>,
    pub reason: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// The app's replicas, by slot, newest placement first within a slot.
pub async fn app_replicas(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Vec<ReplicaRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.replica_id, r.app_id, r.machine_id, m.pool_name AS machine_name, r.slot, r.release, \
           r.state, r.placed_at, s.state AS observed_state, s.ready, s.ready_since, s.restarts, \
           s.last_exit_code, s.reason, s.observed_at, p.last_seen_at \
         FROM grund_replicas r \
         LEFT JOIN grund_replica_status s ON s.replica_id = r.replica_id AND s.machine_id = r.machine_id \
         LEFT JOIN grund_machines m ON m.machine_id = r.machine_id \
         LEFT JOIN grund_machine_presence p ON p.machine_id = r.machine_id \
         WHERE r.app_id = $1 ORDER BY r.slot, r.placement DESC",
    )
    .bind(app_id)
    .fetch_all(executor)
    .await
}

/// What the reconciler needs about each replica of an app.
#[derive(Debug, Clone, FromRow)]
pub struct StatusRow {
    pub replica_id: Uuid,
    pub state: String,
    pub ready: bool,
    pub ready_since: Option<DateTime<Utc>>,
    pub ever_ready: bool,
    pub restarts: i32,
    pub last_exit_code: i32,
    pub reason: String,
}

/// The reports for the app's replicas, from the machine each is placed on.
pub async fn app_statuses(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Vec<StatusRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT s.replica_id, s.state, s.ready, s.ready_since, s.ever_ready, s.restarts, \
           s.last_exit_code, s.reason \
         FROM grund_replica_status s JOIN grund_replicas r \
           ON r.replica_id = s.replica_id AND r.machine_id = s.machine_id \
         WHERE r.app_id = $1",
    )
    .bind(app_id)
    .fetch_all(executor)
    .await
}

/// One replica as a machine reports it.
#[derive(Debug, Clone)]
pub struct Report<'a> {
    pub replica_id: Uuid,
    pub state: &'a str,
    pub ready: bool,
    /// When it became ready, as the instance reckons it from the agent's
    /// "ready for".
    pub ready_since: Option<DateTime<Utc>>,
    pub restarts: i32,
    pub last_exit_code: i32,
    pub reason: &'a str,
}

/// Records what a machine reports about its replicas, only for replicas
/// placed on it, and says whether anything the reconciler decides on
/// (state, readiness, restarts) changed. A replica's `ready_since` stays as
/// first recorded while it stays ready, so a reported duration's jitter does
/// not move it.
pub async fn record_reports(
    connection: &mut PgConnection,
    machine_id: Uuid,
    reports: &[Report<'_>],
    at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let mut changed = false;
    for report in reports {
        let before: Option<(String, bool, i32)> = sqlx::query_as(
            "SELECT state, ready, restarts FROM grund_replica_status WHERE replica_id = $1",
        )
        .bind(report.replica_id)
        .fetch_optional(&mut *connection)
        .await?;
        let written = sqlx::query(
            "INSERT INTO grund_replica_status (replica_id, machine_id, state, ready, ready_since, \
               ever_ready, restarts, last_exit_code, reason, observed_at) \
             SELECT $1, $2, $3, $4, $5, $4, $6, $7, $8, $9 \
             FROM grund_replicas r WHERE r.replica_id = $1 AND r.machine_id = $2 \
             ON CONFLICT (replica_id) DO UPDATE SET \
               state = EXCLUDED.state, ready = EXCLUDED.ready, \
               ready_since = CASE WHEN EXCLUDED.ready AND grund_replica_status.ready \
                                  THEN grund_replica_status.ready_since \
                                  WHEN EXCLUDED.ready THEN EXCLUDED.ready_since ELSE NULL END, \
               ever_ready = grund_replica_status.ever_ready OR EXCLUDED.ready, \
               restarts = EXCLUDED.restarts, last_exit_code = EXCLUDED.last_exit_code, \
               reason = EXCLUDED.reason, observed_at = EXCLUDED.observed_at \
             WHERE grund_replica_status.machine_id = EXCLUDED.machine_id",
        )
        .bind(report.replica_id)
        .bind(machine_id)
        .bind(report.state)
        .bind(report.ready)
        .bind(report.ready_since)
        .bind(report.restarts)
        .bind(report.last_exit_code)
        .bind(report.reason.chars().take(500).collect::<String>())
        .bind(at)
        .execute(&mut *connection)
        .await?
        .rows_affected();
        let now = (report.state.to_string(), report.ready, report.restarts);
        if written > 0 && before.as_ref() != Some(&now) {
            changed = true;
        }
    }
    Ok(changed)
}

/// The status rows of one machine's replicas, to tell what a report
/// changed.
pub async fn machine_statuses(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
) -> Result<Vec<StatusRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT replica_id, state, ready, ready_since, ever_ready, restarts, last_exit_code, reason \
         FROM grund_replica_status WHERE machine_id = $1",
    )
    .bind(machine_id)
    .fetch_all(executor)
    .await
}

/// Forgets reports about replicas that are gone, after an hour.
pub async fn sweep_statuses(executor: impl PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM grund_replica_status s WHERE observed_at < clock_timestamp() - interval '1 hour' \
         AND NOT EXISTS (SELECT 1 FROM grund_replicas r WHERE r.replica_id = s.replica_id)",
    )
    .execute(executor)
    .await?
    .rows_affected())
}

/// A replica a machine should run, with its release, for its document.
#[derive(Debug, Clone, FromRow)]
pub struct PlacedRow {
    pub replica_id: Uuid,
    pub app_id: Uuid,
    pub app_name: String,
    pub slot: i32,
    pub release: i32,
    pub placement: i64,
    pub state: String,
    pub spec: Json<grund_domain::app::AppSpec>,
    pub image_digest: String,
    pub secret_versions: Json<Vec<grund_domain::app::SecretVersion>>,
}

/// The replicas placed on a machine, in a stable order.
pub async fn machine_replicas(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
) -> Result<Vec<PlacedRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.replica_id, r.app_id, a.name AS app_name, r.slot, r.release, r.placement, r.state, \
           rel.spec, rel.image_digest, rel.secret_versions \
         FROM grund_replicas r \
         JOIN grund_apps a ON a.app_id = r.app_id \
         JOIN grund_releases rel ON rel.app_id = r.app_id AND rel.number = r.release \
         WHERE r.machine_id = $1 ORDER BY r.replica_id",
    )
    .bind(machine_id)
    .fetch_all(executor)
    .await
}

/// The machines the replicas of `app_id` are on, to rebuild their
/// documents.
pub async fn app_machines(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT DISTINCT machine_id FROM grund_replicas WHERE app_id = $1")
        .bind(app_id)
        .fetch_all(executor)
        .await
}

/// Memory and CPU the replicas of other apps reserve, per machine of the
/// organisation.
pub async fn reservations(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    except_app: Uuid,
) -> Result<Vec<(Uuid, i64, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.machine_id, COALESCE(sum((rel.spec->>'memory_mib')::bigint), 0)::bigint, \
           COALESCE(sum((rel.spec->>'cpu_millis')::bigint), 0)::bigint \
         FROM grund_replicas r JOIN grund_releases rel ON rel.app_id = r.app_id AND rel.number = r.release \
         WHERE r.organisation_id = $1 AND r.app_id <> $2 GROUP BY r.machine_id",
    )
    .bind(organisation_id)
    .bind(except_app)
    .fetch_all(executor)
    .await
}

/// One line of an app's history.
#[derive(Debug, Clone, FromRow)]
pub struct ActivityRow {
    pub version: i64,
    pub at: DateTime<Utc>,
    pub kind: String,
    pub detail: Value,
}

/// The app's history, newest first.
pub async fn activity_of(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
    limit: i64,
) -> Result<Vec<ActivityRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT version, at, kind, detail FROM grund_app_activity WHERE app_id = $1 \
         ORDER BY version DESC LIMIT $2",
    )
    .bind(app_id)
    .bind(limit)
    .fetch_all(executor)
    .await
}

/// Stores the next version of a secret and returns its number.
pub async fn insert_secret(
    connection: &mut PgConnection,
    app_id: Uuid,
    organisation_id: Uuid,
    name: &str,
    seal: impl FnOnce(i32) -> Vec<u8>,
    created_by: Uuid,
) -> Result<(i32, DateTime<Utc>), sqlx::Error> {
    sqlx::query("SELECT 1 FROM grund_apps WHERE app_id = $1 FOR UPDATE")
        .bind(app_id)
        .execute(&mut *connection)
        .await?;
    let version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(max(version), 0) + 1 FROM grund_app_secrets WHERE app_id = $1 AND name = $2",
    )
    .bind(app_id)
    .bind(name)
    .fetch_one(&mut *connection)
    .await?;
    let sealed = seal(version);
    sqlx::query_scalar(
        "INSERT INTO grund_app_secrets (app_id, organisation_id, name, version, sealed, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING created_at",
    )
    .bind(app_id)
    .bind(organisation_id)
    .bind(name)
    .bind(version)
    .bind(sealed)
    .bind(created_by)
    .fetch_one(connection)
    .await
    .map(|at| (version, at))
}

/// The newest version of each of the app's secrets.
pub async fn latest_secrets(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Vec<(String, i32, DateTime<Utc>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT DISTINCT ON (name) name, version, created_at FROM grund_app_secrets \
         WHERE app_id = $1 ORDER BY name, version DESC",
    )
    .bind(app_id)
    .fetch_all(executor)
    .await
}

/// One version of a secret, sealed.
pub async fn secret_value(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
    name: &str,
    version: i32,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT sealed FROM grund_app_secrets WHERE app_id = $1 AND name = $2 AND version = $3",
    )
    .bind(app_id)
    .bind(name)
    .bind(version)
    .fetch_optional(executor)
    .await
}

/// A replica placed on `machine_id`, with its release's secret versions:
/// what GetReplicaSecrets may answer for.
pub async fn placed_replica(
    executor: impl PgExecutor<'_>,
    machine_id: Uuid,
    replica_id: Uuid,
) -> Result<Option<PlacedRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.replica_id, r.app_id, a.name AS app_name, r.slot, r.release, r.placement, r.state, \
           rel.spec, rel.image_digest, rel.secret_versions \
         FROM grund_replicas r \
         JOIN grund_apps a ON a.app_id = r.app_id \
         JOIN grund_releases rel ON rel.app_id = r.app_id AND rel.number = r.release \
         WHERE r.machine_id = $1 AND r.replica_id = $2",
    )
    .bind(machine_id)
    .bind(replica_id)
    .fetch_optional(executor)
    .await
}
