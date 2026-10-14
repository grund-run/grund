//! Version-guarded volume read model and physical cleanup outbox.
use chrono::{DateTime, Utc};
use grund_domain::volume::VolumeEvent;
use sqlx::{FromRow, PgConnection, PgExecutor};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct VolumeRow {
    pub organisation_id: Uuid,
    pub app_id: Uuid,
    pub volume_id: Uuid,
    pub name: String,
    pub path: String,
    pub source: Option<String>,
    pub size_gib: Option<i64>,
    pub backup: bool,
    pub machine_id: Option<Uuid>,
    pub slot: Option<i32>,
    pub detachment_pending: bool,
    pub status: String,
    pub purge_after: Option<DateTime<Utc>>,
    pub measured_bytes: Option<i64>,
    pub measured_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub stream_version: i64,
}

macro_rules! select_volumes {
    ($where:literal) => {
        concat!("SELECT organisation_id, app_id, volume_id, name, path, source, size_gib, backup, machine_id, slot, detachment_pending, status, measured_bytes, measured_at, created_at, deleted_at, purge_after, stream_version FROM grund_volumes ", $where)
    };
}

pub async fn app_volumes(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    app_id: Uuid,
) -> Result<Vec<VolumeRow>, sqlx::Error> {
    sqlx::query_as(select_volumes!(
        "WHERE organisation_id = $1 AND app_id = $2 AND status <> 'deleted' ORDER BY name"
    ))
    .bind(organisation_id)
    .bind(app_id)
    .fetch_all(executor)
    .await
}

pub async fn all_app_volumes(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    app_id: Uuid,
) -> Result<Vec<VolumeRow>, sqlx::Error> {
    sqlx::query_as(select_volumes!(
        "WHERE organisation_id = $1 AND app_id = $2 ORDER BY name"
    ))
    .bind(organisation_id)
    .bind(app_id)
    .fetch_all(executor)
    .await
}

pub async fn by_name(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    app_id: Uuid,
    name: &str,
) -> Result<Option<VolumeRow>, sqlx::Error> {
    sqlx::query_as(select_volumes!(
        "WHERE organisation_id = $1 AND app_id = $2 AND name = $3"
    ))
    .bind(organisation_id)
    .bind(app_id)
    .bind(name)
    .fetch_optional(executor)
    .await
}

pub async fn volume(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    app_id: Uuid,
    volume_id: Uuid,
) -> Result<Option<VolumeRow>, sqlx::Error> {
    sqlx::query_as(select_volumes!(
        "WHERE organisation_id = $1 AND app_id = $2 AND volume_id = $3 AND status <> 'deleted'"
    ))
    .bind(organisation_id)
    .bind(app_id)
    .bind(volume_id)
    .fetch_optional(executor)
    .await
}

/// Includes tombstones so backend erasure acknowledgements can be retried
/// after a committed response was lost.
pub async fn any_volume(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    app_id: Uuid,
    volume_id: Uuid,
) -> Result<Option<VolumeRow>, sqlx::Error> {
    sqlx::query_as(select_volumes!(
        "WHERE organisation_id = $1 AND app_id = $2 AND volume_id = $3"
    ))
    .bind(organisation_id)
    .bind(app_id)
    .bind(volume_id)
    .fetch_optional(executor)
    .await
}

pub async fn machine_mounts(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
) -> Result<Vec<VolumeRow>, sqlx::Error> {
    sqlx::query_as(select_volumes!("WHERE organisation_id = $1 AND machine_id = $2 AND status IN ('attached','awaiting_backend','detaching_backend') ORDER BY app_id, name"))
        .bind(organisation_id).bind(machine_id).fetch_all(executor).await
}

#[derive(Debug, Clone, FromRow)]
pub struct CleanupRow {
    pub volume_id: Uuid,
    pub app_id: Uuid,
}

pub async fn pending_cleanup(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
) -> Result<Vec<CleanupRow>, sqlx::Error> {
    sqlx::query_as("SELECT volume_id, app_id FROM grund_volume_cleanup WHERE organisation_id = $1 AND machine_id = $2 AND acknowledged_at IS NULL ORDER BY volume_id")
        .bind(organisation_id).bind(machine_id).fetch_all(executor).await
}

pub async fn pending_ack(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
    app_id: Uuid,
    volume_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM grund_volume_cleanup WHERE organisation_id = $1 AND machine_id = $2 AND app_id = $3 AND volume_id = $4 AND acknowledged_at IS NULL)")
        .bind(organisation_id).bind(machine_id).bind(app_id).bind(volume_id).fetch_one(executor).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receipt {
    New,
    Existing(Uuid),
    Conflict,
}

/// Claim an idempotent command in the same transaction as its effect.
/// PostgreSQL's unique index serializes racing claims; a retry can only
/// observe a receipt after the first command has committed.
pub async fn reserve_receipt(
    conn: &mut PgConnection,
    org: Uuid,
    app: Uuid,
    key: &str,
    operation: &str,
    request_hash: &[u8],
    result_id: Uuid,
) -> Result<Receipt, sqlx::Error> {
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO grund_volume_idempotency (organisation_id, app_id, idempotency_key, operation, request_hash, result_id) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING RETURNING result_id")
        .bind(org).bind(app).bind(key).bind(operation).bind(request_hash).bind(result_id)
        .fetch_optional(&mut *conn).await?;
    if inserted.is_some() {
        return Ok(Receipt::New);
    }
    let (same, existing): (bool, Uuid) = sqlx::query_as(
        "SELECT operation = $4 AND request_hash = $5, result_id \
         FROM grund_volume_idempotency WHERE organisation_id = $1 AND app_id = $2 AND idempotency_key = $3")
        .bind(org).bind(app).bind(key).bind(operation).bind(request_hash)
        .fetch_one(&mut *conn).await?;
    Ok(if same {
        Receipt::Existing(existing)
    } else {
        Receipt::Conflict
    })
}

pub async fn restore_attempt_status(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    app: Uuid,
    attempt: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT status FROM grund_volume_backup_attempts WHERE organisation_id = $1 AND app_id = $2 AND attempt_id = $3 AND operation = 'restore'")
        .bind(org).bind(app).bind(attempt).fetch_optional(executor).await
}

/// Latest restore attempt into a new volume, scoped to its app.
pub async fn restore_status(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    app_id: Uuid,
    volume_id: Uuid,
) -> Result<Option<(String, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT status, failure_class FROM grund_volume_backup_attempts \
        WHERE organisation_id = $1 AND app_id = $2 AND destination_volume_id = $3 \
        AND operation = 'restore' ORDER BY created_at DESC, attempt_id DESC LIMIT 1",
    )
    .bind(organisation_id)
    .bind(app_id)
    .bind(volume_id)
    .fetch_optional(executor)
    .await
}

/// One definition for inline projection and transactional replay.
pub async fn apply_volume(
    volume_id: Uuid,
    version: i64,
    event: &VolumeEvent,
    conn: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    match event {
        VolumeEvent::Requested {
            organisation_id,
            app_id,
            name,
            path,
            source,
            backup,
            size_gib,
            requested_at,
        } => {
            sqlx::query("INSERT INTO grund_volumes (organisation_id, app_id, volume_id, name, path, source, size_gib, backup, status, created_at, stream_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'requested',$9,$10) ON CONFLICT (organisation_id, volume_id) DO UPDATE SET stream_version = EXCLUDED.stream_version WHERE grund_volumes.stream_version < EXCLUDED.stream_version")
                .bind(organisation_id).bind(app_id).bind(volume_id).bind(name).bind(path).bind(source).bind(size_gib.map(|size| size as i64)).bind(backup).bind(requested_at).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::RestoreReserved { machine_id, .. } => {
            sqlx::query("UPDATE grund_volumes SET machine_id = $2, stream_version = $3 WHERE volume_id = $1 AND stream_version < $3")
                .bind(volume_id).bind(machine_id).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::Placed { machine_id, .. } => {
            sqlx::query("UPDATE grund_volumes SET machine_id = $2, status = 'available', stream_version = $3 WHERE volume_id = $1 AND stream_version < $3")
                .bind(volume_id).bind(machine_id).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::BackendPlacementPrepared {
            machine_id, slot, ..
        } => {
            sqlx::query("UPDATE grund_volumes SET machine_id = $2, slot = $3, status = 'awaiting_backend', stream_version = $4 WHERE volume_id = $1 AND stream_version < $4")
                .bind(volume_id).bind(machine_id).bind(i32::from(*slot)).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::BackendAttached { .. } => {
            sqlx::query("UPDATE grund_volumes SET status = 'attached', stream_version = $2 WHERE volume_id = $1 AND stream_version < $2")
                .bind(volume_id).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::BackendReceiptInvalidated { .. } => {
            sqlx::query("UPDATE grund_volumes SET status = 'awaiting_backend', stream_version = $2 WHERE volume_id = $1 AND stream_version < $2")
                .bind(volume_id).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::BackendDetachmentStarted { .. } => {
            sqlx::query("UPDATE grund_volumes SET detachment_pending = true, status = CASE WHEN status IN ('pending_deletion','deleting') THEN status ELSE 'detaching_backend' END, stream_version = $2 WHERE volume_id = $1 AND stream_version < $2")
                .bind(volume_id).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::BackendDetached { .. } => {
            sqlx::query("UPDATE grund_volumes SET detachment_pending = false, slot = NULL, status = CASE WHEN status IN ('pending_deletion','deleting') THEN status ELSE 'available' END, stream_version = $2 WHERE volume_id = $1 AND stream_version < $2")
                .bind(volume_id).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::Attached {
            machine_id, path, ..
        } => {
            sqlx::query("UPDATE grund_volumes SET machine_id = $2, path = $3, status = 'attached', stream_version = $4 WHERE volume_id = $1 AND stream_version < $4")
                .bind(volume_id).bind(machine_id).bind(path).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::Detached { .. } => {
            sqlx::query("UPDATE grund_volumes SET status = 'available', stream_version = $2 WHERE volume_id = $1 AND stream_version < $2")
                .bind(volume_id).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::BackupPolicySet { backup, .. } => {
            sqlx::query("UPDATE grund_volumes SET backup = $2, stream_version = $3 WHERE volume_id = $1 AND stream_version < $3")
                .bind(volume_id).bind(backup).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::DeleteRequested {
            machine_id,
            requested_at,
            purge_after,
        } => {
            let updated: Option<Uuid> = sqlx::query_scalar("UPDATE grund_volumes SET status = CASE WHEN $2::timestamptz IS NULL THEN 'deleting' ELSE 'pending_deletion' END, purge_after = $2, stream_version = $3 WHERE volume_id = $1 AND stream_version < $3 RETURNING organisation_id")
                .bind(volume_id).bind(purge_after).bind(version).fetch_optional(&mut *conn).await?;
            if let (Some(org), Some(machine_id), None) = (updated, machine_id, purge_after) {
                sqlx::query("INSERT INTO grund_volume_cleanup (organisation_id, app_id, volume_id, machine_id, requested_at, stream_version) SELECT $1, app_id, $2, $3, $4, $5 FROM grund_volumes WHERE volume_id = $2 AND source IS NULL AND size_gib IS NULL ON CONFLICT (organisation_id, volume_id) DO UPDATE SET stream_version = EXCLUDED.stream_version WHERE grund_volume_cleanup.stream_version < EXCLUDED.stream_version")
                    .bind(org).bind(volume_id).bind(machine_id).bind(requested_at).bind(version).execute(&mut *conn).await?;
            }
        }
        VolumeEvent::Restored { status, .. } => {
            let next = match status {
                grund_domain::volume::VolumeStatus::Available => "available",
                grund_domain::volume::VolumeStatus::AwaitingBackend => "awaiting_backend",
                grund_domain::volume::VolumeStatus::DetachingBackend => "detaching_backend",
                _ => "requested",
            };
            sqlx::query("UPDATE grund_volumes SET status = $2, purge_after = NULL, stream_version = $3 WHERE volume_id = $1 AND stream_version < $3")
                .bind(volume_id).bind(next).bind(version).execute(&mut *conn).await?;
        }
        VolumeEvent::PurgeRequested { requested_at, .. } => {
            let updated: Option<(Uuid, Option<Uuid>)> = sqlx::query_as("UPDATE grund_volumes SET status = 'deleting', purge_after = NULL, stream_version = $2 WHERE volume_id = $1 AND stream_version < $2 RETURNING organisation_id, machine_id")
                .bind(volume_id).bind(version).fetch_optional(&mut *conn).await?;
            if let Some((org, Some(machine))) = updated {
                sqlx::query("INSERT INTO grund_volume_cleanup (organisation_id, app_id, volume_id, machine_id, requested_at, stream_version) SELECT $1, app_id, $2, $3, $4, $5 FROM grund_volumes WHERE volume_id = $2 AND source IS NULL AND size_gib IS NULL ON CONFLICT (organisation_id, volume_id) DO UPDATE SET stream_version = EXCLUDED.stream_version WHERE grund_volume_cleanup.stream_version < EXCLUDED.stream_version")
                    .bind(org).bind(volume_id).bind(machine).bind(requested_at).bind(version).execute(&mut *conn).await?;
            }
        }
        VolumeEvent::Deleted { deleted_at } => {
            let updated: Option<Uuid> = sqlx::query_scalar("UPDATE grund_volumes SET status = 'deleted', deleted_at = $2, stream_version = $3 WHERE volume_id = $1 AND stream_version < $3 RETURNING organisation_id")
                .bind(volume_id).bind(deleted_at).bind(version).fetch_optional(&mut *conn).await?;
            if let Some(org) = updated {
                sqlx::query("UPDATE grund_volume_cleanup SET acknowledged_at = $3, stream_version = $4 WHERE organisation_id = $1 AND volume_id = $2 AND stream_version < $4")
                    .bind(org).bind(volume_id).bind(deleted_at).bind(version).execute(&mut *conn).await?;
            }
        }
    }
    Ok(())
}
