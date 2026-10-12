//! Durable volume backup configuration, agent work leases and verified points.
//! Secret bytes remain sealed; callers open them only after machine ownership
//! and current placement have been checked in PostgreSQL.

use std::path::{Component, Path};

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct BackupConfig {
    pub organisation_id: Uuid,
    pub app_id: Uuid,
    pub volume_id: Uuid,
    pub endpoint: String,
    pub bucket: String,
    pub repo_prefix: String,
    pub sealed_access_key: Vec<u8>,
    pub sealed_secret: Vec<u8>,
    pub sealed_password: Vec<u8>,
    pub sealed_session: Option<Vec<u8>>,
    pub version: i64,
    pub next_due_at: DateTime<Utc>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub last_probe_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct RecoveryPoint {
    pub snapshot_id: String,
    pub completed_at: DateTime<Utc>,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct BackupAttempt {
    pub organisation_id: Uuid,
    pub app_id: Uuid,
    pub volume_id: Uuid,
    pub attempt_id: Uuid,
    pub machine_id: Uuid,
    pub placement_generation: i64,
    pub operation: String,
    pub source_volume_id: Uuid,
    pub destination_volume_id: Option<Uuid>,
    pub snapshot_id: Option<String>,
}

pub async fn config(
    pool: &PgPool,
    org: Uuid,
    app: Uuid,
    volume: Uuid,
) -> Result<Option<BackupConfig>, sqlx::Error> {
    sqlx::query_as("SELECT c.organisation_id,c.app_id,c.volume_id,c.endpoint,c.bucket,c.repo_prefix,c.sealed_access_key,c.sealed_secret,c.sealed_password,c.sealed_session,c.version,c.next_due_at,c.last_success_at,c.last_verified_at,c.last_probe_at,c.last_error FROM grund_volume_backup_configs c JOIN grund_volumes v ON v.organisation_id=c.organisation_id AND v.volume_id=c.volume_id WHERE c.organisation_id=$1 AND c.app_id=$2 AND c.volume_id=$3 AND v.app_id=$2 AND v.status NOT IN ('deleting','deleted')")
        .bind(org).bind(app).bind(volume).fetch_optional(pool).await
}

pub async fn locked_config(
    tx: &mut Transaction<'_, Postgres>,
    org: Uuid,
    app: Uuid,
    volume: Uuid,
) -> Result<Option<BackupConfig>, sqlx::Error> {
    sqlx::query_as("SELECT organisation_id,app_id,volume_id,endpoint,bucket,repo_prefix,sealed_access_key,sealed_secret,sealed_password,sealed_session,version,next_due_at,last_success_at,last_verified_at,last_probe_at,last_error FROM grund_volume_backup_configs WHERE organisation_id=$1 AND app_id=$2 AND volume_id=$3 FOR UPDATE")
        .bind(org).bind(app).bind(volume).fetch_optional(&mut **tx).await
}

pub async fn save_config(
    tx: &mut Transaction<'_, Postgres>,
    c: &BackupConfig,
) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query("INSERT INTO grund_volume_backup_configs (organisation_id,app_id,volume_id,endpoint,bucket,repo_prefix,sealed_access_key,sealed_secret,sealed_password,sealed_session,version,next_due_at,last_probe_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp(),$12) ON CONFLICT (organisation_id,volume_id) DO UPDATE SET sealed_access_key=EXCLUDED.sealed_access_key,sealed_secret=EXCLUDED.sealed_secret,sealed_password=EXCLUDED.sealed_password,sealed_session=EXCLUDED.sealed_session,version=EXCLUDED.version WHERE grund_volume_backup_configs.version + 1 = EXCLUDED.version AND grund_volume_backup_configs.app_id=EXCLUDED.app_id AND grund_volume_backup_configs.endpoint=EXCLUDED.endpoint AND grund_volume_backup_configs.bucket=EXCLUDED.bucket AND grund_volume_backup_configs.repo_prefix=EXCLUDED.repo_prefix")
        .bind(c.organisation_id).bind(c.app_id).bind(c.volume_id).bind(&c.endpoint).bind(&c.bucket).bind(&c.repo_prefix).bind(&c.sealed_access_key).bind(&c.sealed_secret).bind(&c.sealed_password).bind(&c.sealed_session).bind(c.version).bind(c.last_probe_at)
        .execute(&mut **tx).await?;
    Ok(rows.rows_affected() == 1)
}

pub async fn points(
    pool: &PgPool,
    org: Uuid,
    app: Uuid,
    volume: Uuid,
) -> Result<Vec<RecoveryPoint>, sqlx::Error> {
    sqlx::query_as("SELECT p.snapshot_id,p.completed_at,p.verified_at FROM grund_volume_backup_points p JOIN grund_volumes v ON v.organisation_id=p.organisation_id AND v.volume_id=p.volume_id WHERE p.organisation_id=$1 AND p.app_id=$2 AND p.volume_id=$3 AND v.app_id=$2 AND v.status NOT IN ('deleting','deleted') AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts a WHERE a.organisation_id=p.organisation_id AND a.volume_id=p.volume_id AND a.snapshot_id=p.snapshot_id AND a.operation='prune' AND a.attempts>0) ORDER BY p.completed_at DESC,p.snapshot_id DESC LIMIT 100")
        .bind(org).bind(app).bind(volume).fetch_all(pool).await
}

/// The archived root is captured from the actual signed path the agent read,
/// so a fresh machine may restore without reproducing the old agent data dir.
pub async fn archived_path(
    pool: &PgPool,
    org: Uuid,
    app: Uuid,
    volume: Uuid,
    snapshot: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT p.archived_path FROM grund_volume_backup_points p JOIN grund_volumes v ON v.organisation_id=p.organisation_id AND v.volume_id=p.volume_id WHERE p.organisation_id=$1 AND p.app_id=$2 AND p.volume_id=$3 AND p.snapshot_id=$4 AND v.app_id=$2 AND v.status NOT IN ('deleting','deleted')")
        .bind(org).bind(app).bind(volume).bind(snapshot).fetch_optional(pool).await
}

/// Committed work is the only authority for an agent to receive credentials.
/// The input machine identity must already be verified by AgentService auth.
pub async fn lease_machine(
    pool: &PgPool,
    machine: Uuid,
) -> Result<Option<BackupAttempt>, sqlx::Error> {
    let signed_document_applied: bool = sqlx::query_scalar(
        "SELECT COALESCE(p.applied_generation >= d.generation, false) FROM grund_machine_documents d LEFT JOIN grund_machine_presence p ON p.machine_id=d.machine_id WHERE d.machine_id=$1",
    )
    .bind(machine)
    .fetch_optional(pool)
    .await?
    .unwrap_or(false);
    if !signed_document_applied {
        return Ok(None);
    }
    let due: Option<BackupAttempt> = sqlx::query_as("WITH due AS (SELECT a.organisation_id,a.attempt_id FROM grund_volume_backup_attempts a JOIN grund_volumes v ON v.organisation_id=a.organisation_id AND v.volume_id=a.volume_id JOIN grund_volume_backup_configs c ON c.organisation_id=a.organisation_id AND c.volume_id=a.volume_id LEFT JOIN grund_volumes dest ON dest.organisation_id=a.organisation_id AND dest.volume_id=a.destination_volume_id JOIN grund_machines m ON m.machine_id=a.machine_id AND m.pool_organisation_id=a.organisation_id AND m.state='active' AND m.pool <> 'management' AND m.cordoned_at IS NULL WHERE a.machine_id=$1 AND a.operation<>'prune' AND a.app_id=v.app_id AND c.app_id=v.app_id AND ((a.operation='restore' AND v.status IN ('attached','available')) OR (a.operation<>'restore' AND v.status='attached')) AND v.backup AND a.placement_generation=v.stream_version AND (CASE WHEN a.operation='restore' THEN dest.app_id=a.app_id AND dest.status='requested' AND dest.source IS NULL ELSE v.machine_id=$1 END) AND a.status IN ('pending','leased') AND a.next_attempt_at<=clock_timestamp() AND (a.leased_until IS NULL OR a.leased_until<clock_timestamp()) AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts other WHERE other.organisation_id=a.organisation_id AND other.volume_id=a.volume_id AND other.attempt_id<>a.attempt_id AND other.status='leased' AND other.leased_until>clock_timestamp()) ORDER BY a.next_attempt_at,a.attempt_id FOR UPDATE OF a SKIP LOCKED LIMIT 1) UPDATE grund_volume_backup_attempts a SET status='leased',attempts=a.attempts+1,leased_until=clock_timestamp()+interval '7 hours' FROM due WHERE a.organisation_id=due.organisation_id AND a.attempt_id=due.attempt_id RETURNING a.organisation_id,a.app_id,a.volume_id,a.attempt_id,a.machine_id,a.placement_generation,a.operation,a.source_volume_id,a.destination_volume_id,a.snapshot_id")
        .bind(machine).fetch_optional(pool).await?;
    if due.is_some() {
        return Ok(due);
    }
    let mut tx = pool.begin().await?;
    let point: Option<(Uuid, Uuid, String, Uuid)> = sqlx::query_as("SELECT p.organisation_id,p.volume_id,p.snapshot_id,a.attempt_id FROM grund_volume_backup_points p JOIN grund_volume_backup_attempts a ON a.organisation_id=p.organisation_id AND a.volume_id=p.volume_id AND a.snapshot_id=p.snapshot_id JOIN grund_volumes v ON v.organisation_id=a.organisation_id AND v.volume_id=a.volume_id JOIN grund_volume_backup_configs c ON c.organisation_id=a.organisation_id AND c.volume_id=a.volume_id JOIN grund_machines m ON m.machine_id=a.machine_id AND m.pool_organisation_id=a.organisation_id AND m.state='active' AND m.pool <> 'management' AND m.cordoned_at IS NULL WHERE a.machine_id=$1 AND a.operation='prune' AND a.app_id=v.app_id AND c.app_id=v.app_id AND v.status='attached' AND v.backup AND v.machine_id=$1 AND a.placement_generation=v.stream_version AND a.status IN ('pending','leased') AND a.next_attempt_at<=clock_timestamp() AND (a.leased_until IS NULL OR a.leased_until<clock_timestamp()) AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts other WHERE other.organisation_id=a.organisation_id AND other.volume_id=a.volume_id AND other.attempt_id<>a.attempt_id AND other.status='leased' AND other.leased_until>clock_timestamp()) AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts r WHERE r.organisation_id=a.organisation_id AND r.volume_id=a.volume_id AND r.snapshot_id=a.snapshot_id AND r.operation='restore' AND r.status IN ('pending','leased')) ORDER BY a.next_attempt_at,a.attempt_id FOR UPDATE OF p SKIP LOCKED LIMIT 1")
        .bind(machine).fetch_optional(&mut *tx).await?;
    let Some((org, volume, snapshot, attempt)) = point else {
        return Ok(None);
    };
    let due = sqlx::query_as("UPDATE grund_volume_backup_attempts a SET status='leased',attempts=a.attempts+1,leased_until=clock_timestamp()+interval '7 hours' WHERE a.organisation_id=$1 AND a.attempt_id=$2 AND a.status IN ('pending','leased') AND (a.leased_until IS NULL OR a.leased_until<clock_timestamp()) AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts other WHERE other.organisation_id=$1 AND other.volume_id=$3 AND other.attempt_id<>a.attempt_id AND other.status='leased' AND other.leased_until>clock_timestamp()) AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts r WHERE r.organisation_id=$1 AND r.volume_id=$3 AND r.snapshot_id=$4 AND r.operation='restore' AND r.status IN ('pending','leased')) RETURNING a.organisation_id,a.app_id,a.volume_id,a.attempt_id,a.machine_id,a.placement_generation,a.operation,a.source_volume_id,a.destination_volume_id,a.snapshot_id")
        .bind(org).bind(attempt).bind(volume).bind(snapshot).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    Ok(due)
}

/// One pass schedules overdue work without relying on an in-memory timer.
/// A partial or failed attempt blocks a duplicate until its lease expires.
pub async fn schedule(pool: &PgPool) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE grund_volume_backup_attempts a SET status='failed',leased_until=NULL,failure_class='source' FROM grund_volumes v WHERE a.organisation_id=v.organisation_id AND a.volume_id=v.volume_id AND a.placement_generation<>v.stream_version AND a.status IN ('pending','leased')")
        .execute(pool).await?;
    let backup = sqlx::query("INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,status,next_attempt_at) SELECT c.organisation_id,c.app_id,c.volume_id,gen_random_uuid(),v.machine_id,v.stream_version,'backup',v.volume_id,'pending',c.next_due_at FROM grund_volume_backup_configs c JOIN grund_volumes v ON v.organisation_id=c.organisation_id AND v.volume_id=c.volume_id WHERE v.app_id=c.app_id AND v.machine_id IS NOT NULL AND v.status='attached' AND v.backup AND c.next_due_at<=clock_timestamp() AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts a WHERE a.organisation_id=c.organisation_id AND a.volume_id=c.volume_id AND a.operation='backup' AND a.status IN ('pending','leased')) ON CONFLICT DO NOTHING")
        .execute(pool).await?.rows_affected();
    Ok(backup)
}

pub async fn schedule_probe(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,snapshot_id,status) SELECT c.organisation_id,c.app_id,c.volume_id,gen_random_uuid(),v.machine_id,v.stream_version,'probe',v.volume_id,p.snapshot_id,'pending' FROM grund_volume_backup_configs c JOIN grund_volumes v ON v.organisation_id=c.organisation_id AND v.volume_id=c.volume_id JOIN LATERAL (SELECT snapshot_id FROM grund_volume_backup_points WHERE organisation_id=c.organisation_id AND volume_id=c.volume_id ORDER BY completed_at DESC LIMIT 1) p ON true WHERE v.app_id=c.app_id AND v.machine_id IS NOT NULL AND v.status='attached' AND v.backup AND (c.last_probe_at IS NULL OR c.last_probe_at<=clock_timestamp()-interval '7 days') AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts a WHERE a.organisation_id=c.organisation_id AND a.volume_id=c.volume_id AND a.operation='probe' AND a.status IN ('pending','leased')) ON CONFLICT DO NOTHING")
        .execute(pool).await?;
    Ok(result.rows_affected())
}

/// Forget only points older than the newest seven *verified completed*
/// snapshots. Failed attempts and an unverified restic snapshot never count.
pub async fn schedule_prune(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("WITH ranked AS (SELECT p.organisation_id,p.app_id,p.volume_id,p.snapshot_id,p.completed_at,row_number() OVER (PARTITION BY p.organisation_id,p.volume_id ORDER BY p.completed_at DESC,p.snapshot_id DESC) AS rank FROM grund_volume_backup_points p) INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,snapshot_id,status) SELECT p.organisation_id,p.app_id,p.volume_id,gen_random_uuid(),v.machine_id,v.stream_version,'prune',v.volume_id,p.snapshot_id,'pending' FROM ranked p JOIN grund_volumes v ON v.organisation_id=p.organisation_id AND v.volume_id=p.volume_id JOIN grund_volume_backup_configs c ON c.organisation_id=p.organisation_id AND c.volume_id=p.volume_id WHERE p.rank>7 AND v.app_id=p.app_id AND v.machine_id IS NOT NULL AND v.status='attached' AND v.backup AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts a WHERE a.organisation_id=p.organisation_id AND a.volume_id=p.volume_id AND a.operation='prune' AND a.status IN ('pending','leased')) AND NOT EXISTS (SELECT 1 FROM grund_volume_backup_attempts a WHERE a.organisation_id=p.organisation_id AND a.volume_id=p.volume_id AND a.operation IN ('backup','probe','restore') AND a.status='leased') ON CONFLICT DO NOTHING")
        .execute(pool).await?;
    Ok(result.rows_affected())
}

/// Restores are acknowledged in one transaction and placed in the aggregate
/// by a separate idempotent pass, so a server crash cannot strand a verified
/// managed directory while reporting it mounted.
pub async fn completed_restores(pool: &PgPool) -> Result<Vec<BackupAttempt>, sqlx::Error> {
    sqlx::query_as("SELECT a.organisation_id,a.app_id,a.volume_id,a.attempt_id,a.machine_id,a.placement_generation,a.operation,a.source_volume_id,a.destination_volume_id,a.snapshot_id FROM grund_volume_backup_attempts a JOIN grund_volumes d ON d.organisation_id=a.organisation_id AND d.volume_id=a.destination_volume_id WHERE a.operation='restore' AND a.status='completed' AND d.app_id=a.app_id AND d.status='requested' AND d.source IS NULL ORDER BY a.completed_at,a.attempt_id LIMIT 16")
        .fetch_all(pool).await
}

/// A stale machine, revoked volume, replaced lease or mismatched point can
/// neither complete a point nor advance last-good. DB clock is authoritative.
#[allow(clippy::too_many_arguments)]
pub async fn complete(
    pool: &PgPool,
    machine: Uuid,
    attempt: Uuid,
    generation: i64,
    success: bool,
    snapshot: &str,
    failure: &str,
    source_path: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    if success {
        let pruning: Option<(Uuid, Uuid, Option<String>)> = sqlx::query_as("SELECT organisation_id,volume_id,snapshot_id FROM grund_volume_backup_attempts WHERE attempt_id=$1 AND machine_id=$2 AND operation='prune'")
            .bind(attempt).bind(machine).fetch_optional(&mut *tx).await?;
        if let Some((org, volume, Some(point))) = pruning {
            let present: Option<i32> = sqlx::query_scalar("SELECT 1 FROM grund_volume_backup_points WHERE organisation_id=$1 AND volume_id=$2 AND snapshot_id=$3 FOR UPDATE")
                .bind(org).bind(volume).bind(point).fetch_optional(&mut *tx).await?;
            if present.is_none() {
                return Ok(false);
            }
        }
    }
    let row: Option<BackupAttempt> = sqlx::query_as("SELECT a.organisation_id,a.app_id,a.volume_id,a.attempt_id,a.machine_id,a.placement_generation,a.operation,a.source_volume_id,a.destination_volume_id,a.snapshot_id FROM grund_volume_backup_attempts a JOIN grund_volumes v ON v.organisation_id=a.organisation_id AND v.volume_id=a.volume_id LEFT JOIN grund_volumes dest ON dest.organisation_id=a.organisation_id AND dest.volume_id=a.destination_volume_id WHERE a.attempt_id=$1 AND a.machine_id=$2 AND v.app_id=a.app_id AND ((a.operation='restore' AND v.status IN ('attached','available')) OR (a.operation<>'restore' AND v.status='attached')) AND a.placement_generation=$3 AND v.stream_version=$3 AND (CASE WHEN a.operation='restore' THEN dest.app_id=a.app_id AND dest.status='requested' AND dest.source IS NULL ELSE v.machine_id=$2 END) AND a.status='leased' AND a.leased_until>clock_timestamp() FOR UPDATE OF a")
        .bind(attempt).bind(machine).bind(generation).fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        return Ok(false);
    };
    if success
        && ((row.operation == "backup"
            && (snapshot.len() != 64 || !snapshot.bytes().all(|b| b.is_ascii_hexdigit())))
            || (row.operation != "backup" && row.snapshot_id.as_deref() != Some(snapshot)))
    {
        return Ok(false);
    }
    if success && row.operation == "prune" {
        let reserved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grund_volume_backup_attempts WHERE organisation_id=$1 AND volume_id=$2 AND snapshot_id=$3 AND operation='restore' AND status IN ('pending','leased'))")
            .bind(row.organisation_id).bind(row.volume_id).bind(snapshot).fetch_one(&mut *tx).await?;
        if reserved {
            return Ok(false);
        }
    }
    if success && row.operation == "backup" {
        let path = Path::new(source_path);
        if source_path.len() > 4096
            || source_path.bytes().any(|b| b.is_ascii_control())
            || !path.is_absolute()
            || path == Path::new("/")
            || !path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Ok(false);
        }
        let bound_source: Option<String> = sqlx::query_scalar("SELECT source FROM grund_volumes WHERE organisation_id=$1 AND app_id=$2 AND volume_id=$3")
            .bind(row.organisation_id).bind(row.app_id).bind(row.source_volume_id).fetch_one(&mut *tx).await?;
        let owned_suffix = format!("/volumes/{}", row.source_volume_id);
        if !bound_source.as_ref().map_or_else(
            || source_path.len() > owned_suffix.len() && source_path.ends_with(&owned_suffix),
            |host| host == source_path,
        ) {
            return Ok(false);
        }
    }
    if success {
        sqlx::query("UPDATE grund_volume_backup_attempts SET status='completed',snapshot_id=$2,leased_until=NULL,completed_at=clock_timestamp() WHERE organisation_id=$1 AND attempt_id=$3")
            .bind(row.organisation_id).bind(snapshot).bind(row.attempt_id).execute(&mut *tx).await?;
        match row.operation.as_str() {
            "backup" => {
                sqlx::query("INSERT INTO grund_volume_backup_points (organisation_id,app_id,volume_id,snapshot_id,archived_path,completed_at,verified_at) VALUES ($1,$2,$3,$4,$5,clock_timestamp(),clock_timestamp()) ON CONFLICT DO NOTHING")
                    .bind(row.organisation_id).bind(row.app_id).bind(row.volume_id).bind(snapshot).bind(source_path).execute(&mut *tx).await?;
                sqlx::query("UPDATE grund_volume_backup_configs SET last_success_at=clock_timestamp(),last_verified_at=clock_timestamp(),last_error=NULL,next_due_at=clock_timestamp()+interval '1 day' WHERE organisation_id=$1 AND volume_id=$2")
                    .bind(row.organisation_id).bind(row.volume_id).execute(&mut *tx).await?;
            }
            "probe" => {
                sqlx::query("UPDATE grund_volume_backup_configs SET last_probe_at=clock_timestamp(),last_verified_at=clock_timestamp(),last_error=NULL WHERE organisation_id=$1 AND volume_id=$2")
                .bind(row.organisation_id).bind(row.volume_id).execute(&mut *tx).await?;
            }
            "prune" => {
                sqlx::query("DELETE FROM grund_volume_backup_points WHERE organisation_id=$1 AND volume_id=$2 AND snapshot_id=$3")
                .bind(row.organisation_id).bind(row.volume_id).bind(snapshot).execute(&mut *tx).await?;
            }
            "restore" => {}
            _ => return Ok(false),
        }
    } else {
        let class = match failure {
            "source" | "unavailable" | "integrity" | "timeout" | "permission" => failure,
            _ => "unavailable",
        };
        sqlx::query("UPDATE grund_volume_backup_attempts SET status=CASE WHEN operation='restore' THEN 'failed' ELSE 'pending' END,leased_until=NULL,failure_class=$3,next_attempt_at=clock_timestamp()+make_interval(secs => LEAST(300, power(2,LEAST(attempts,8))::int)) WHERE organisation_id=$1 AND attempt_id=$2")
            .bind(row.organisation_id).bind(row.attempt_id).bind(class).execute(&mut *tx).await?;
        if row.operation != "restore" {
            sqlx::query("UPDATE grund_volume_backup_configs SET last_error=$3 WHERE organisation_id=$1 AND volume_id=$2")
                .bind(row.organisation_id).bind(row.volume_id).bind(class).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn a_reserved_point_survives_prune_completion_until_restore_fails(pool: PgPool) {
        let (org, app, source, destination, machine, prune, restore) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        let snapshot = "a".repeat(64);
        sqlx::query("INSERT INTO grund_volumes (organisation_id,app_id,volume_id,name,path,backup,machine_id,status,created_at,stream_version) VALUES ($1,$2,$3,'source','/source',true,$4,'attached',clock_timestamp(),1),($1,$2,$5,'destination','/destination',false,NULL,'requested',clock_timestamp(),1)")
            .bind(org).bind(app).bind(source).bind(machine).bind(destination)
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO grund_volume_backup_points (organisation_id,app_id,volume_id,snapshot_id,archived_path,completed_at,verified_at) VALUES ($1,$2,$3,$4,'/source',clock_timestamp(),clock_timestamp())")
            .bind(org).bind(app).bind(source).bind(&snapshot).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,snapshot_id,status,attempts,leased_until) VALUES ($1,$2,$3,$4,$5,1,'prune',$3,$6,'leased',1,clock_timestamp()+interval '1 hour')")
            .bind(org).bind(app).bind(source).bind(prune).bind(machine).bind(&snapshot)
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,destination_volume_id,snapshot_id,status) VALUES ($1,$2,$3,$4,$5,1,'restore',$3,$6,$7,'pending')")
            .bind(org).bind(app).bind(source).bind(restore).bind(machine).bind(destination).bind(&snapshot)
            .execute(&pool).await.unwrap();

        assert!(
            !complete(&pool, machine, prune, 1, true, &snapshot, "", "")
                .await
                .unwrap()
        );
        assert!(
            archived_path(&pool, org, app, source, &snapshot)
                .await
                .unwrap()
                .is_some()
        );
        sqlx::query("UPDATE grund_volume_backup_attempts SET status='failed' WHERE organisation_id=$1 AND attempt_id=$2")
            .bind(org).bind(restore).execute(&pool).await.unwrap();
        assert!(
            complete(&pool, machine, prune, 1, true, &snapshot, "", "")
                .await
                .unwrap()
        );
        assert!(
            archived_path(&pool, org, app, source, &snapshot)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn prune_waits_for_point_reservation_and_runs_after_restore_fails(pool: PgPool) {
        let (org, app, volume, machine, prune, restore) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        let snapshot = "b".repeat(64);
        sqlx::query("INSERT INTO grund_machines (machine_id,pool,home_organisation_id,name,state,public_key,pool_organisation_id,pool_name,minted_by,registered_at,key_registered_at,stream_version) VALUES ($1,'organisation',$2,'own','active',$3,$2,'own','account:owner',clock_timestamp(),clock_timestamp(),1)")
            .bind(machine).bind(org).bind("a".repeat(64)).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO grund_machine_documents (machine_id,generation,key_id,payload,signature,issued_at) VALUES ($1,1,$1,'',decode(repeat('00',64),'hex'),clock_timestamp())")
            .bind(machine).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO grund_machine_presence (machine_id,last_seen_at,applied_generation) VALUES ($1,clock_timestamp(),1)")
            .bind(machine).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO grund_volumes (organisation_id,app_id,volume_id,name,path,backup,machine_id,status,created_at,stream_version) VALUES ($1,$2,$3,'source','/source',true,$4,'attached',clock_timestamp(),1)")
            .bind(org).bind(app).bind(volume).bind(machine).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO grund_volume_backup_configs (organisation_id,app_id,volume_id,endpoint,bucket,repo_prefix,sealed_access_key,sealed_secret,sealed_password,version,next_due_at) VALUES ($1,$2,$3,'https://s3.example','backup','repo',decode('00','hex'),decode('00','hex'),decode('00','hex'),1,clock_timestamp()+interval '1 day')")
            .bind(org).bind(app).bind(volume).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO grund_volume_backup_points (organisation_id,app_id,volume_id,snapshot_id,archived_path,completed_at,verified_at) VALUES ($1,$2,$3,$4,'/source',clock_timestamp(),clock_timestamp())")
            .bind(org).bind(app).bind(volume).bind(&snapshot).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,snapshot_id,status) VALUES ($1,$2,$3,$4,$5,1,'prune',$3,$6,'pending')")
            .bind(org).bind(app).bind(volume).bind(prune).bind(machine).bind(&snapshot)
            .execute(&pool).await.unwrap();

        let mut reservation = pool.begin().await.unwrap();
        sqlx::query("SELECT 1 FROM grund_volume_backup_points WHERE organisation_id=$1 AND volume_id=$2 AND snapshot_id=$3 FOR UPDATE")
            .bind(org).bind(volume).bind(&snapshot).fetch_one(&mut *reservation).await.unwrap();
        assert!(lease_machine(&pool, machine).await.unwrap().is_none());
        sqlx::query("INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,snapshot_id,status) VALUES ($1,$2,$3,$4,$5,1,'restore',$3,$6,'pending')")
            .bind(org).bind(app).bind(volume).bind(restore).bind(machine).bind(&snapshot)
            .execute(&mut *reservation).await.unwrap();
        reservation.commit().await.unwrap();
        assert!(lease_machine(&pool, machine).await.unwrap().is_none());
        sqlx::query("UPDATE grund_volume_backup_attempts SET status='failed' WHERE organisation_id=$1 AND attempt_id=$2")
            .bind(org).bind(restore).execute(&pool).await.unwrap();
        assert_eq!(
            lease_machine(&pool, machine)
                .await
                .unwrap()
                .map(|a| a.attempt_id),
            Some(prune)
        );
    }
}
