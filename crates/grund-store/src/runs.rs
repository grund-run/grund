//! Version-guarded run read models and erasable argument bodies.

use grund_domain::run::{Event, Run};
use mire::{Aggregate, HandledEvent, TransactionalEventHandler};
use sqlx::{PgConnection, PgExecutor, types::Json};
use uuid::Uuid;

#[cfg(test)]
#[path = "runs_tests.rs"]
mod tests;
/// Tenant-bound projection row; arguments deliberately live elsewhere.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Row {
    pub run_id: Uuid,
    pub state: Json<Run>,
    pub stream_version: i64,
}

pub async fn get(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    id: Uuid,
) -> Result<Option<Row>, sqlx::Error> {
    sqlx::query_as(
        "SELECT run_id,state,stream_version FROM grund_runs WHERE organisation_id=$1 AND run_id=$2",
    )
    .bind(org)
    .bind(id)
    .fetch_optional(executor)
    .await
}

/// Read access expires independently of whether the physical sweep has run.
pub async fn args(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    id: Uuid,
) -> Result<Option<Vec<String>>, sqlx::Error> {
    let value: Option<Json<Vec<String>>> = sqlx::query_scalar("SELECT p.args FROM grund_run_payloads p JOIN grund_runs r USING(organisation_id,run_id) WHERE p.organisation_id=$1 AND p.run_id=$2 AND (r.args_expire_at IS NULL OR r.args_expire_at>clock_timestamp())")
        .bind(org).bind(id).fetch_optional(executor).await?;
    Ok(value.map(|v| v.0))
}

pub async fn list(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    stack: Uuid,
    service: &str,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<Row>, sqlx::Error> {
    sqlx::query_as("SELECT run_id,state,stream_version FROM grund_runs WHERE organisation_id=$1 AND stack_id=$2 AND ($3='' OR service=$3) AND ($4::uuid IS NULL OR run_id>$4) ORDER BY run_id LIMIT $5")
        .bind(org).bind(stack).bind(service).bind(after).bind(limit.clamp(1,101)).fetch_all(executor).await
}

/// One fold definition serves both inline writes and transactional catch-up.
pub async fn apply(
    id: Uuid,
    version: i64,
    event: &Event,
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    let before: Option<(Json<Run>, i64)> =
        sqlx::query_as("SELECT state,stream_version FROM grund_runs WHERE run_id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *connection)
            .await?;
    if before.as_ref().is_some_and(|(_, v)| *v >= version) {
        return Ok(());
    }
    if before.as_ref().map_or(0, |(_, v)| *v) != version - 1 {
        return Err(sqlx::Error::Protocol(
            "run projection requires contiguous history".into(),
        ));
    }
    let mut state = before.map(|(s, _)| s.0).unwrap_or_default();
    state.apply(event);
    let request = state
        .request
        .as_ref()
        .ok_or_else(|| sqlx::Error::Protocol("run projection requires creation history".into()))?;
    sqlx::query("INSERT INTO grund_runs(organisation_id,run_id,stack_id,service,app_id,release,machine_id,state,outstanding,deadline,args_expire_at,stream_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(organisation_id,run_id) DO UPDATE SET state=EXCLUDED.state,outstanding=EXCLUDED.outstanding,args_expire_at=LEAST(grund_runs.args_expire_at,EXCLUDED.args_expire_at),stream_version=EXCLUDED.stream_version WHERE grund_runs.stream_version<EXCLUDED.stream_version")
        .bind(request.organisation_id).bind(id).bind(request.stack_id).bind(&request.service).bind(request.app_id).bind(request.release.number as i32).bind(request.machine_id).bind(Json(&state)).bind(state.outstanding()).bind(request.deadline).bind(state.args_expire_at()).bind(version).execute(&mut *connection).await?;
    if matches!(event, Event::Requested { .. }) {
        sqlx::query("INSERT INTO grund_run_inputs(organisation_id,run_id,app_id,release,secret_versions) SELECT $1,$2,$3,$4,$5 FROM grund_releases WHERE app_id=$3 AND number=$4 ON CONFLICT DO NOTHING")
            .bind(request.organisation_id).bind(id).bind(request.app_id).bind(request.release.number as i32).bind(Json(&request.release.secret_versions)).execute(&mut *connection).await?;
        for secret in &request.release.secret_versions {
            sqlx::query("INSERT INTO grund_run_secret_pins(organisation_id,run_id,app_id,name,version) SELECT $1,$2,$3,$4,$5 FROM grund_run_inputs i JOIN grund_app_secrets s ON s.app_id=$3 AND s.name=$4 AND s.version=$5 WHERE i.organisation_id=$1 AND i.run_id=$2 ON CONFLICT DO NOTHING")
                .bind(request.organisation_id).bind(id).bind(request.app_id).bind(&secret.name).bind(secret.version as i32).execute(&mut *connection).await?;
        }
        sqlx::query("INSERT INTO grund_app_telemetry_instances(organisation_id,instance_id,app_id,machine_id,release,placed_at,run_id) VALUES($1,$2,$2,$3,$4,$5,$2) ON CONFLICT DO NOTHING")
            .bind(request.organisation_id).bind(id).bind(request.machine_id).bind(request.release.number as i32).bind(request.requested_at).execute(&mut *connection).await?;
        sqlx::query("UPDATE grund_runs r SET log_bytes_received=GREATEST(log_bytes_received,COALESCE((SELECT SUM(payload_bytes) FROM grund_app_logs l WHERE l.organisation_id=$1 AND l.app_id=$2 AND l.instance_id=$2),0)) WHERE r.organisation_id=$1 AND r.run_id=$2")
            .bind(request.organisation_id).bind(id).execute(&mut *connection).await?;
    }
    if state.stop_confirmed {
        sqlx::query("UPDATE grund_app_telemetry_instances SET stopped_at=$3 WHERE organisation_id=$1 AND instance_id=$2 AND run_id=$2")
            .bind(request.organisation_id).bind(id).bind(state.finished_at).execute(&mut *connection).await?;
        sqlx::query("DELETE FROM grund_run_inputs WHERE organisation_id=$1 AND run_id=$2")
            .bind(request.organisation_id)
            .bind(id)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

/// Pins are retained while any execution can still be alive.
pub async fn outstanding_machine(
    executor: impl PgExecutor<'_>,
    machine: Uuid,
) -> Result<Vec<Row>, sqlx::Error> {
    sqlx::query_as("SELECT run_id,state,stream_version FROM grund_runs WHERE machine_id=$1 AND outstanding ORDER BY run_id")
        .bind(machine).fetch_all(executor).await
}

/// Only an unrevoked pending attempt may obtain arguments or pull credentials.
pub async fn authorised(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    machine: Uuid,
    id: Uuid,
    attempt: Option<Uuid>,
) -> Result<Option<Row>, sqlx::Error> {
    let row: Option<Row> = sqlx::query_as("SELECT r.run_id,r.state,r.stream_version FROM grund_runs r JOIN grund_machines m ON m.machine_id=r.machine_id JOIN grund_apps a ON a.organisation_id=r.organisation_id AND a.app_id=r.app_id JOIN grund_stacks s ON s.organisation_id=r.organisation_id AND s.stack_id=r.stack_id JOIN grund_organisations o ON o.organisation_id=r.organisation_id WHERE r.organisation_id=$1 AND r.machine_id=$2 AND r.run_id=$3 AND r.outstanding AND r.deadline>clock_timestamp() AND m.pool_organisation_id=$1 AND m.state IN ('active','leased') AND a.deleted_at IS NULL AND o.deleted_at IS NULL AND s.status NOT IN ('deleting','deleted') AND r.state->>'status'='pending' AND r.state->>'cancel_requested_at' IS NULL")
        .bind(org).bind(machine).bind(id).fetch_optional(executor).await?;
    Ok(row.filter(|r| {
        attempt.is_none_or(|a| {
            r.state
                .0
                .request
                .as_ref()
                .is_some_and(|r| r.attempt_id == a)
        })
    }))
}

/// Bounded physical reclamation never determines access permission.
pub async fn sweep(executor: impl PgExecutor<'_>) -> Result<(), sqlx::Error> {
    sqlx::query("WITH payloads AS (DELETE FROM grund_run_payloads WHERE (organisation_id,run_id) IN (SELECT organisation_id,run_id FROM grund_runs WHERE args_expire_at<=clock_timestamp() ORDER BY args_expire_at LIMIT 1000)), receipts AS (DELETE FROM grund_run_requests WHERE (organisation_id,caller_id,method,request_key) IN (SELECT organisation_id,caller_id,method,request_key FROM grund_run_requests WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 1000)) SELECT 1")
        .execute(executor).await?;
    Ok(())
}

pub const SUBSCRIPTION: &str = "grund-run-read-model-v1";
pub struct Projection;
impl TransactionalEventHandler for Projection {
    type Aggregate = Run;
    async fn handle(
        &self,
        event: HandledEvent<Event>,
        connection: &mut PgConnection,
    ) -> anyhow::Result<()> {
        let id = crate::projections::stream_uuid(event.stream_id(), "grund-run")?;
        apply(id, event.stream_version(), &event.event, connection).await?;
        Ok(())
    }
}

/// A host cannot disappear while its own or a currently hosted guest's task may execute.
pub async fn blocking_machine(
    executor: impl PgExecutor<'_>,
    machine: Uuid,
) -> Result<Vec<Row>, sqlx::Error> {
    sqlx::query_as("SELECT run_id,state,stream_version FROM grund_runs WHERE outstanding AND (machine_id=$1 OR machine_id IN (SELECT machine_id FROM grund_vms WHERE host_machine_id=$1 AND machine_id IS NOT NULL)) ORDER BY run_id")
        .bind(machine).fetch_all(executor).await
}
