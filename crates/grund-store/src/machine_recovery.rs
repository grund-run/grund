//! Disconnect policies and replacement activity for a current pool member.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// An app's disconnect policy, including volumes absent from its current release.
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryPolicy {
    pub app_id: Uuid,
    pub has_volumes: bool,
    pub reschedule_after_seconds: i64,
}

/// A copy removed during this machine's current silence and its first successor's
/// placement. Placement does not imply that the successor is ready.
#[derive(Debug, Clone, FromRow)]
pub struct Replacement {
    pub app_id: Uuid,
    pub app_name: String,
    pub instance_id: Uuid,
    pub slot: i32,
    pub lost_at: DateTime<Utc>,
    pub placed_at: Option<DateTime<Utc>>,
    pub machine_name: Option<String>,
    pub reschedule_after_seconds: i64,
}

/// Policies for apps currently allocated here. The stateful definition matches
/// reconciliation: any nondeleted app-owned volume pins its instances.
pub async fn policies(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
) -> Result<Vec<RecoveryPolicy>, sqlx::Error> {
    sqlx::query_as(
        "WITH machine AS (SELECT machine_id FROM grund_machines WHERE machine_id=$2 AND pool_organisation_id=$1), \
         allocated AS ( \
           SELECT r.app_id FROM grund_replicas r JOIN machine m ON m.machine_id=r.machine_id WHERE r.organisation_id=$1 \
           UNION SELECT v.app_id FROM grund_volumes v JOIN machine m ON m.machine_id=v.machine_id \
             WHERE v.organisation_id=$1 AND v.status <> 'deleted' \
         ) \
         SELECT a.app_id, COALESCE((a.settings->>'reschedule_after_seconds')::bigint,120) AS reschedule_after_seconds, \
           EXISTS(SELECT 1 FROM grund_volumes v WHERE v.organisation_id=$1 AND v.app_id=a.app_id AND v.status <> 'deleted') AS has_volumes \
         FROM grund_apps a JOIN allocated p ON p.app_id=a.app_id WHERE a.organisation_id=$1 ORDER BY a.app_id",
    ).bind(organisation_id).bind(machine_id).fetch_all(executor).await
}

/// Copies lost since the latest contact, restricted to this tenant and current
/// pool membership. Previous disconnects and previous tenants' leases are excluded.
pub async fn replacements(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
) -> Result<Vec<Replacement>, sqlx::Error> {
    sqlx::query_as(
        "WITH machine AS ( \
           SELECT m.machine_id, GREATEST(COALESCE(p.last_seen_at,m.registered_at),m.key_registered_at) AS silence_since \
           FROM grund_machines m LEFT JOIN grund_machine_presence p ON p.machine_id=m.machine_id \
           WHERE m.machine_id=$2 AND m.pool_organisation_id=$1 \
         ) \
         SELECT a.app_id, a.name AS app_name, (lost.detail->>'replica_id')::uuid AS instance_id, \
           (lost.detail->'replica'->>'slot')::integer AS slot, lost.at AS lost_at, successor.at AS placed_at, successor.machine_name, \
           COALESCE((a.settings->>'reschedule_after_seconds')::bigint,120) AS reschedule_after_seconds \
         FROM machine m JOIN grund_app_activity lost ON lost.kind='replica_lost' \
           AND lost.detail->>'machine_id'=m.machine_id::text AND lost.at >= m.silence_since \
         JOIN grund_apps a ON a.app_id=lost.app_id AND a.organisation_id=$1 AND a.deleted_at IS NULL \
         LEFT JOIN LATERAL ( \
           SELECT placed.at, destination.pool_name AS machine_name FROM grund_app_activity placed \
           JOIN grund_machines destination ON destination.machine_id::text=placed.detail->>'machine_id' \
             AND destination.pool_organisation_id=$1 \
           WHERE placed.app_id=a.app_id AND placed.kind='replica_placed' AND placed.version>lost.version \
             AND placed.detail->>'slot'=lost.detail->'replica'->>'slot' \
           ORDER BY placed.version LIMIT 1 \
         ) successor ON true ORDER BY lost.at DESC, a.name, slot",
    ).bind(organisation_id).bind(machine_id).fetch_all(executor).await
}
