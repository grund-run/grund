//! Current tenant-scoped machine allocations, separate from measured host usage.

use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Reservations held on a current pool member. Counts exclude draining instances;
/// CPU and memory include them until their allocation is removed.
#[derive(Debug, Clone, Default, FromRow)]
pub struct MachineSummary {
    pub machine_id: Uuid,
    pub apps: i64,
    pub instances: i64,
    pub cpu_millis: i64,
    pub memory_mib: i64,
    pub disk_gib: i64,
    pub disk_unbounded: bool,
}

/// A current app allocation. Volume observed states are lifecycle projection
/// states, while instance observed states come from the machine's last report.
#[derive(Debug, Clone, FromRow)]
pub struct MachineWorkload {
    pub app_id: Uuid,
    pub app_name: String,
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub desired: String,
    pub observed: String,
    pub cpu_millis: i64,
    pub memory_mib: i64,
    pub disk_gib: Option<i64>,
    pub measured_bytes: Option<i64>,
}

/// Every current pool member, including empty machines. App allocations use the
/// same release reservations as placement; desired-running VMs reserve all three
/// resources. Unsized managed volumes and host paths make disk totals incomplete.
pub async fn summaries(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<MachineSummary>, sqlx::Error> {
    sqlx::query_as(
        "WITH machines AS ( \
           SELECT machine_id FROM grund_machines WHERE pool_organisation_id = $1 \
         ), instances AS ( \
           SELECT r.machine_id, count(DISTINCT r.app_id) FILTER (WHERE r.state = 'running') AS apps, \
             count(*) FILTER (WHERE r.state = 'running') AS instances, \
             COALESCE(sum((rel.spec->>'cpu_millis')::bigint), 0)::bigint AS cpu_millis, \
             COALESCE(sum((rel.spec->>'memory_mib')::bigint), 0)::bigint AS memory_mib \
           FROM grund_replicas r JOIN machines m ON m.machine_id = r.machine_id \
           JOIN grund_apps a ON a.app_id = r.app_id AND a.organisation_id = $1 \
           JOIN grund_releases rel ON rel.app_id = r.app_id AND rel.number = r.release \
           WHERE r.organisation_id = $1 GROUP BY r.machine_id \
         ), volumes AS ( \
           SELECT v.machine_id, \
             COALESCE(sum(v.size_gib) FILTER (WHERE v.source IS NULL), 0)::bigint AS disk_gib, \
             bool_or(v.size_gib IS NULL OR v.source IS NOT NULL) AS disk_unbounded \
           FROM grund_volumes v JOIN machines m ON m.machine_id = v.machine_id \
           JOIN grund_apps a ON a.app_id = v.app_id AND a.organisation_id = $1 \
           WHERE v.organisation_id = $1 AND v.status <> 'deleted' AND v.deleted_at IS NULL \
           GROUP BY v.machine_id \
         ), vms AS ( \
           SELECT v.host_machine_id AS machine_id, sum(v.vcpus::bigint * 1000)::bigint AS cpu_millis, \
             sum(v.memory_mib)::bigint AS memory_mib, sum(v.disk_gib)::bigint AS disk_gib \
           FROM grund_vms v JOIN machines m ON m.machine_id = v.host_machine_id \
           WHERE v.organisation_id = $1 AND v.state = 'running' GROUP BY v.host_machine_id \
         ) \
         SELECT m.machine_id, COALESCE(i.apps, 0) AS apps, COALESCE(i.instances, 0) AS instances, \
           COALESCE(i.cpu_millis, 0) + COALESCE(vm.cpu_millis, 0) AS cpu_millis, \
           COALESCE(i.memory_mib, 0) + COALESCE(vm.memory_mib, 0) AS memory_mib, \
           COALESCE(v.disk_gib, 0) + COALESCE(vm.disk_gib, 0) AS disk_gib, \
           COALESCE(v.disk_unbounded, false) AS disk_unbounded \
         FROM machines m LEFT JOIN instances i ON i.machine_id = m.machine_id \
         LEFT JOIN volumes v ON v.machine_id = m.machine_id \
         LEFT JOIN vms vm ON vm.machine_id = m.machine_id ORDER BY m.machine_id",
    )
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// Placed app instances and nondeleted volumes on a current member. Both tenant
/// and pool membership are checked, so old lease allocations cannot disclose a
/// previous tenant's apps to the machine's next owner.
pub async fn workloads(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
) -> Result<Vec<MachineWorkload>, sqlx::Error> {
    sqlx::query_as(
        "WITH machine AS ( \
           SELECT machine_id FROM grund_machines WHERE pool_organisation_id = $1 AND machine_id = $2 \
         ) \
         SELECT a.app_id, a.name AS app_name, r.replica_id AS id, \
           a.name || '-' || (r.slot + 1)::text AS name, 'instance'::text AS kind, \
           r.state AS desired, COALESCE(s.state, '') AS observed, \
           COALESCE((rel.spec->>'cpu_millis')::bigint, 0) AS cpu_millis, \
           COALESCE((rel.spec->>'memory_mib')::bigint, 0) AS memory_mib, \
           NULL::bigint AS disk_gib, NULL::bigint AS measured_bytes \
         FROM grund_replicas r JOIN machine m ON m.machine_id = r.machine_id \
         JOIN grund_apps a ON a.app_id = r.app_id AND a.organisation_id = $1 \
         JOIN grund_releases rel ON rel.app_id = r.app_id AND rel.number = r.release \
         LEFT JOIN grund_replica_status s ON s.replica_id = r.replica_id AND s.machine_id = r.machine_id \
         WHERE r.organisation_id = $1 \
         UNION ALL \
         SELECT a.app_id, a.name AS app_name, v.volume_id AS id, v.name, 'volume'::text AS kind, \
           CASE WHEN v.status IN ('pending_deletion', 'deleting') THEN 'deleted' ELSE 'present' END AS desired, \
           v.status AS observed, 0::bigint AS cpu_millis, 0::bigint AS memory_mib, \
           CASE WHEN v.source IS NULL THEN v.size_gib ELSE NULL END AS disk_gib, v.measured_bytes \
         FROM grund_volumes v JOIN machine m ON m.machine_id = v.machine_id \
         JOIN grund_apps a ON a.app_id = v.app_id AND a.organisation_id = $1 \
         WHERE v.organisation_id = $1 AND v.status <> 'deleted' AND v.deleted_at IS NULL \
         ORDER BY app_name, kind, name, id",
    )
    .bind(organisation_id)
    .bind(machine_id)
    .fetch_all(executor)
    .await
}

/// Fresh direct socket addresses from active slots in this tenant's network.
/// Freed slots and machines no longer in the current pool disclose nothing.
pub async fn addresses(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    machine_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT address FROM grund_network_slots s \
         JOIN grund_networks n ON n.network_id = s.network_id AND n.organisation_id = $1 \
         JOIN grund_machines m ON m.machine_id = s.machine_id AND m.pool_organisation_id = $1 \
         CROSS JOIN LATERAL unnest(s.direct_addrs) AS address \
         WHERE s.machine_id = $2 AND s.freed_at IS NULL \
           AND s.direct_addrs_at >= clock_timestamp() - interval '5 minutes' ORDER BY address",
    )
    .bind(organisation_id)
    .bind(machine_id)
    .fetch_all(executor)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    async fn app(pool: &PgPool, organisation_id: Uuid, name: &str) -> anyhow::Result<Uuid> {
        let app_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO grund_apps (app_id, organisation_id, name, settings, created_by, created_at, stream_version) \
             VALUES ($1, $2, $3, '{}', $1, clock_timestamp(), 1)",
        )
        .bind(app_id)
        .bind(organisation_id)
        .bind(name)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO grund_releases (app_id, number, spec, image_digest, source, created_by, created_at) \
             VALUES ($1, 1, '{\"cpu_millis\":250,\"memory_mib\":512}', \
               'sha256:' || repeat('a', 64), 'api', $1, clock_timestamp())",
        )
        .bind(app_id)
        .execute(pool)
        .await?;
        Ok(app_id)
    }

    async fn fixture(pool: &PgPool) -> anyhow::Result<(Uuid, Uuid, Uuid)> {
        let organisation_id = Uuid::now_v7();
        let machine_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO grund_machines (machine_id, pool, home_organisation_id, name, state, public_key, \
               pool_organisation_id, pool_name, minted_by, registered_at, key_registered_at, stream_version) \
             VALUES ($1, 'organisation', $2, 'own', 'active', repeat('a', 64), \
               $2, 'own', 'owner', clock_timestamp(), clock_timestamp(), 1)",
        )
        .bind(machine_id)
        .bind(organisation_id)
        .execute(pool)
        .await?;
        let app_id = app(pool, organisation_id, "web").await?;
        Ok((organisation_id, machine_id, app_id))
    }

    async fn instance(
        pool: &PgPool,
        organisation_id: Uuid,
        machine_id: Uuid,
        app_id: Uuid,
        slot: i32,
        state: &str,
    ) -> anyhow::Result<Uuid> {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO grund_replicas (replica_id, app_id, organisation_id, machine_id, slot, \
               release, placement, state, placed_at) \
             VALUES ($1, $2, $3, $4, $5, 1, 0, $6, clock_timestamp())",
        )
        .bind(id)
        .bind(app_id)
        .bind(organisation_id)
        .bind(machine_id)
        .bind(slot)
        .bind(state)
        .execute(pool)
        .await?;
        Ok(id)
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn draining_instances_and_desired_vms_hold_resources_while_unsized_disks_stay_unknown(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let (org, machine, app) = fixture(&pool).await?;
        let empty = summaries(&pool, org).await?.remove(0);
        assert_eq!(
            (
                empty.apps,
                empty.instances,
                empty.cpu_millis,
                empty.memory_mib,
                empty.disk_gib
            ),
            (0, 0, 0, 0, 0),
        );
        assert!(!empty.disk_unbounded);
        assert!(workloads(&pool, org, machine).await?.is_empty());
        instance(&pool, org, machine, app, 0, "running").await?;
        instance(&pool, org, machine, app, 1, "running").await?;
        let draining = instance(&pool, org, machine, app, 0, "draining").await?;
        sqlx::query(
            "INSERT INTO grund_replica_status (replica_id, machine_id, state, ready, observed_at) \
             VALUES ($1, $2, 'stopping', false, clock_timestamp())",
        )
        .bind(draining)
        .bind(machine)
        .execute(&pool)
        .await?;
        for state in ["running", "stopped"] {
            sqlx::query(
                "INSERT INTO grund_vms (vm_id, organisation_id, host_machine_id, name, vcpus, memory_mib, \
                   disk_gib, kernel_url, kernel_sha256, rootfs_url, rootfs_sha256, state, observed_state, created_by) \
                 VALUES ($1, $2, $3, $4, 2, 2048, 8, 'kernel', repeat('b', 64), \
                   'rootfs', repeat('c', 64), $4, 'failed', $1)",
            )
            .bind(Uuid::now_v7())
            .bind(org)
            .bind(machine)
            .bind(state)
            .execute(&pool)
            .await?;
        }
        for (name, size, source, status) in [
            ("sized", Some(10_i64), None, "deleting"),
            ("managed", None, None, "attached"),
            ("host", None, Some("/srv/data"), "attached"),
            ("gone", Some(100), None, "deleted"),
        ] {
            sqlx::query(
                "INSERT INTO grund_volumes (organisation_id, app_id, volume_id, name, path, source, \
                   size_gib, machine_id, status, measured_bytes, measured_at, created_at, stream_version) \
                 VALUES ($1, $2, $3, $4, '/data', $5, $6, $7, $8, \
                   CASE WHEN $6::bigint IS NOT NULL THEN 123 ELSE NULL END, \
                   CASE WHEN $6::bigint IS NOT NULL THEN clock_timestamp() ELSE NULL END, clock_timestamp(), 1)",
            )
            .bind(org)
            .bind(app)
            .bind(Uuid::now_v7())
            .bind(name)
            .bind(source)
            .bind(size)
            .bind(machine)
            .bind(status)
            .execute(&pool)
            .await?;
        }
        let summary = summaries(&pool, org).await?.remove(0);
        assert_eq!((summary.apps, summary.instances), (1, 2));
        assert_eq!((summary.cpu_millis, summary.memory_mib), (2750, 3584));
        assert_eq!(summary.disk_gib, 18);
        assert!(summary.disk_unbounded);
        let rows = workloads(&pool, org, machine).await?;
        assert_eq!(rows.len(), 6);
        let draining = rows.iter().find(|row| row.id == draining).unwrap();
        assert_eq!(
            (draining.desired.as_str(), draining.observed.as_str()),
            ("draining", "stopping")
        );
        assert_eq!(draining.cpu_millis, 250);
        assert!(
            rows.iter()
                .any(|row| row.kind == "instance" && row.observed.is_empty())
        );
        let sized = rows.iter().find(|row| row.name == "sized").unwrap();
        assert_eq!(sized.disk_gib, Some(10));
        assert_eq!(sized.measured_bytes, Some(123));
        assert_eq!(
            (sized.desired.as_str(), sized.observed.as_str()),
            ("deleted", "deleting")
        );
        let managed = rows.iter().find(|row| row.name == "managed").unwrap();
        assert_eq!((managed.disk_gib, managed.measured_bytes), (None, None));
        sqlx::query("UPDATE grund_volumes SET status = 'deleted' WHERE organisation_id = $1 AND name = 'managed'")
            .bind(org).execute(&pool).await?;
        assert!(summaries(&pool, org).await?.remove(0).disk_unbounded);
        sqlx::query("UPDATE grund_volumes SET status = 'deleted' WHERE organisation_id = $1 AND name = 'host'")
            .bind(org).execute(&pool).await?;
        assert!(!summaries(&pool, org).await?.remove(0).disk_unbounded);
        Ok(())
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn current_pool_membership_and_allocation_tenant_both_guard_old_lease_history(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let (org, machine, own_app) = fixture(&pool).await?;
        let other_org = Uuid::now_v7();
        let other_app = app(&pool, other_org, "private").await?;
        instance(&pool, org, machine, own_app, 0, "running").await?;
        instance(&pool, other_org, machine, other_app, 0, "running").await?;
        sqlx::query(
            "INSERT INTO grund_volumes (organisation_id, app_id, volume_id, name, path, size_gib, \
               machine_id, status, created_at, stream_version) \
             VALUES ($1, $2, $3, 'private', '/data', 99, $4, 'attached', clock_timestamp(), 1)",
        )
        .bind(other_org)
        .bind(other_app)
        .bind(Uuid::now_v7())
        .bind(machine)
        .execute(&pool)
        .await?;
        assert!(summaries(&pool, other_org).await?.is_empty());
        assert!(workloads(&pool, other_org, machine).await?.is_empty());
        let summary = summaries(&pool, org).await?.remove(0);
        assert_eq!(
            (
                summary.apps,
                summary.instances,
                summary.cpu_millis,
                summary.disk_gib
            ),
            (1, 1, 250, 0)
        );
        let rows = workloads(&pool, org, machine).await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].app_id, own_app);
        sqlx::query("UPDATE grund_machines SET pool_organisation_id = $2 WHERE machine_id = $1")
            .bind(machine)
            .bind(other_org)
            .execute(&pool)
            .await?;
        assert!(summaries(&pool, org).await?.is_empty());
        assert!(workloads(&pool, org, machine).await?.is_empty());
        let rows = workloads(&pool, other_org, machine).await?;
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.app_id == other_app));
        let summary = summaries(&pool, other_org).await?.remove(0);
        assert_eq!(
            (summary.apps, summary.instances, summary.disk_gib),
            (1, 1, 99)
        );
        Ok(())
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn disconnect_policies_pin_any_owned_volume_and_replacement_history_tracks_current_silence(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        use crate::machine_recovery::{policies, replacements};
        use serde_json::json;
        let (org, machine, app_id) = fixture(&pool).await?;
        let replica = instance(&pool, org, machine, app_id, 0, "running").await?;
        let policy = policies(&pool, org, machine).await?.remove(0);
        assert!(!policy.has_volumes);
        assert_eq!(policy.reschedule_after_seconds, 120);
        sqlx::query("INSERT INTO grund_volumes (organisation_id,app_id,volume_id,name,path,machine_id,status,created_at,stream_version) VALUES ($1,$2,$3,'old-mount','/data',$4,'available',clock_timestamp(),1)")
            .bind(org).bind(app_id).bind(Uuid::now_v7()).bind(machine).execute(&pool).await?;
        assert!(policies(&pool, org, machine).await?.remove(0).has_volumes);
        sqlx::query("UPDATE grund_volumes SET status='deleted' WHERE app_id=$1")
            .bind(app_id)
            .execute(&pool)
            .await?;
        assert!(!policies(&pool, org, machine).await?.remove(0).has_volumes);
        sqlx::query("DELETE FROM grund_replicas WHERE replica_id=$1")
            .bind(replica)
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO grund_app_activity (app_id,version,at,kind,detail) VALUES ($1,2,clock_timestamp(),'replica_lost',$2)")
            .bind(app_id).bind(json!({"replica_id":replica,"machine_id":machine,"replica":{"slot":0}}))
            .execute(&pool).await?;
        let history = replacements(&pool, org, machine).await?;
        assert_eq!(history[0].instance_id, replica);
        assert!(history[0].placed_at.is_none());
        assert!(
            replacements(&pool, Uuid::now_v7(), machine)
                .await?
                .is_empty()
        );
        let destination = Uuid::now_v7();
        sqlx::query("INSERT INTO grund_machines (machine_id,pool,home_organisation_id,name,state,public_key,pool_organisation_id,pool_name,minted_by,registered_at,key_registered_at,stream_version) VALUES ($1,'organisation',$2,'second','active',repeat('b',64),$2,'second','owner',clock_timestamp(),clock_timestamp(),1)")
            .bind(destination).bind(org).execute(&pool).await?;
        sqlx::query("INSERT INTO grund_app_activity (app_id,version,at,kind,detail) VALUES ($1,3,clock_timestamp(),'replica_placed',$2)")
            .bind(app_id).bind(json!({"replica_id":Uuid::now_v7(),"machine_id":destination,"slot":0}))
            .execute(&pool).await?;
        let history = replacements(&pool, org, machine).await?;
        assert!(
            history[0]
                .placed_at
                .is_some_and(|at| at >= history[0].lost_at)
        );
        assert_eq!(history[0].machine_name.as_deref(), Some("second"));
        sqlx::query("INSERT INTO grund_machine_presence (machine_id,last_seen_at) VALUES ($1,clock_timestamp())").bind(machine).execute(&pool).await?;
        assert!(replacements(&pool, org, machine).await?.is_empty());
        Ok(())
    }
}
