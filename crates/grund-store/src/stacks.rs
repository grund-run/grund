//! Version-guarded stack projections and tenant-scoped reconciliation evidence.

#[cfg(test)]
mod tests;

use grund_domain::stack::{Event, Stack};
use mire::{Aggregate, HandledEvent, TransactionalEventHandler};
use sqlx::{PgConnection, PgExecutor, types::Json};
use uuid::Uuid;

/// The rebuildable view and its concurrency version.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Row {
    pub stack_id: Uuid,
    pub state: Json<Stack>,
    pub stream_version: i64,
}

/// Stack ownership also gates direct app mutation throughout recovery retention.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Member {
    pub organisation_id: Uuid,
    pub stack_id: Uuid,
    pub service: String,
    pub app_id: Uuid,
    pub app_name: String,
    pub exclusive: bool,
    pub enabled: bool,
    pub stopping: bool,
    pub operation_id: Option<Uuid>,
    pub required_generation: i64,
}

/// Finds an organisation's stack, including its recoverable deleted identity.
pub async fn by_name(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    name: &str,
) -> Result<Option<Row>, sqlx::Error> {
    sqlx::query_as("SELECT stack_id,state,stream_version FROM grund_stacks WHERE organisation_id=$1 AND name=$2")
        .bind(org).bind(name).fetch_optional(executor).await
}

/// Reads one stack without allowing a caller to cross organisation boundaries.
pub async fn get(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    id: Uuid,
) -> Result<Option<Row>, sqlx::Error> {
    sqlx::query_as("SELECT stack_id,state,stream_version FROM grund_stacks WHERE organisation_id=$1 AND stack_id=$2")
        .bind(org).bind(id).fetch_optional(executor).await
}

/// Lists at most the caller's bounded page in stable identity order.
pub async fn list(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    limit: i64,
    after: Option<Uuid>,
    allowed_apps: Option<&[String]>,
) -> Result<Vec<Row>, sqlx::Error> {
    sqlx::query_as("SELECT stack_id,state,stream_version FROM grund_stacks s WHERE organisation_id=$1 AND ($2::uuid IS NULL OR stack_id>$2) AND ($4::text[] IS NULL OR (EXISTS (SELECT 1 FROM grund_stack_members m WHERE m.organisation_id=s.organisation_id AND m.stack_id=s.stack_id) AND NOT EXISTS (SELECT 1 FROM grund_stack_members m WHERE m.organisation_id=s.organisation_id AND m.stack_id=s.stack_id AND NOT (m.app_name=ANY($4))))) ORDER BY stack_id LIMIT $3")
        .bind(org).bind(after).bind(limit.clamp(1,101)).bind(allowed_apps).fetch_all(executor).await
}

/// Resolves only an app's authoritative organisation-scoped owning stack.
pub async fn member(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    app: Uuid,
) -> Result<Option<Member>, sqlx::Error> {
    sqlx::query_as("SELECT organisation_id,stack_id,service,app_id,app_name,exclusive,enabled,stopping,operation_id,required_generation FROM grund_stack_members WHERE organisation_id=$1 AND app_id=$2")
        .bind(org).bind(app).fetch_optional(executor).await
}

/// Returns the stack's service identities, including retained removed services.
pub async fn members(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    stack: Uuid,
) -> Result<Vec<Member>, sqlx::Error> {
    sqlx::query_as("SELECT organisation_id,stack_id,service,app_id,app_name,exclusive,enabled,stopping,operation_id,required_generation FROM grund_stack_members WHERE organisation_id=$1 AND stack_id=$2 ORDER BY service")
        .bind(org).bind(stack).fetch_all(executor).await
}

/// Live sibling service names for an already-authorized app, within its organisation.
pub async fn live_service_links(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    app: Uuid,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as("SELECT sibling.service,sibling.app_name FROM grund_stack_members owner JOIN grund_stack_members sibling ON sibling.organisation_id=owner.organisation_id AND sibling.stack_id=owner.stack_id JOIN grund_apps a ON a.organisation_id=sibling.organisation_id AND a.app_id=sibling.app_id WHERE owner.organisation_id=$1 AND owner.app_id=$2 AND a.deleted_at IS NULL ORDER BY sibling.service")
        .bind(org).bind(app).fetch_all(executor).await
}

/// Requires the complete owned bundle, including retained children, in the app grant.
pub async fn allowed(
    executor: impl PgExecutor<'_>,
    org: Uuid,
    stack: Uuid,
    apps: &[String],
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM grund_stack_members WHERE organisation_id=$1 AND stack_id=$2) AND NOT EXISTS (SELECT 1 FROM grund_stack_members WHERE organisation_id=$1 AND stack_id=$2 AND NOT (app_name=ANY($3)))")
        .bind(org).bind(stack).bind(apps).fetch_one(executor).await
}

/// Updates disposable coordinator gates only within the owning stack transaction.
pub async fn gate(
    connection: &mut PgConnection,
    org: Uuid,
    stack: Uuid,
    service: &str,
    enabled: bool,
    stopping: bool,
    operation: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE grund_stack_members SET enabled=$4,stopping=$5,operation_id=$6,required_generation=CASE WHEN operation_id IS DISTINCT FROM $6 OR stopping IS DISTINCT FROM $5 THEN 0 ELSE required_generation END WHERE organisation_id=$1 AND stack_id=$2 AND service=$3")
        .bind(org).bind(stack).bind(service).bind(enabled).bind(stopping).bind(operation).execute(connection).await?;
    Ok(())
}

/// Applies one fact; inline writes and catch-up use this single definition.
pub async fn apply(
    id: Uuid,
    version: i64,
    event: &Event,
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    let before: Option<(Json<Stack>, i64)> = sqlx::query_as(
        "SELECT state,stream_version FROM grund_stacks WHERE stack_id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *connection)
    .await?;
    if before.as_ref().is_some_and(|(_, v)| *v >= version) {
        return Ok(());
    }
    if before.as_ref().map_or(0, |(_, previous)| *previous) != version - 1 {
        return Err(sqlx::Error::Protocol(
            "stack projection requires contiguous history".into(),
        ));
    }
    let mut state = before.map(|(s, _)| s.0).unwrap_or_default();
    state.apply(event);
    if !state.exists {
        return Err(sqlx::Error::Protocol(
            "stack projection requires creation history".into(),
        ));
    }
    sqlx::query("INSERT INTO grund_stacks(organisation_id,stack_id,name,state,status,machine_id,stream_version) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(organisation_id,stack_id) DO UPDATE SET state=EXCLUDED.state,status=EXCLUDED.status,machine_id=EXCLUDED.machine_id,stream_version=EXCLUDED.stream_version WHERE grund_stacks.stream_version<EXCLUDED.stream_version")
        .bind(state.organisation_id).bind(id).bind(&state.name).bind(Json(&state)).bind(state.status.as_str()).bind(state.machine_id).bind(version).execute(&mut *connection).await?;
    if let Event::RevisionRequested { revision, .. } = event {
        for (name, service) in &revision.services {
            sqlx::query("INSERT INTO grund_stack_members(organisation_id,stack_id,service,app_id,app_name,exclusive) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(organisation_id,stack_id,service) DO UPDATE SET exclusive=EXCLUDED.exclusive WHERE grund_stack_members.app_id=EXCLUDED.app_id")
                .bind(state.organisation_id).bind(id).bind(name).bind(service.app_id).bind(&service.app_name).bind(service.exclusive).execute(&mut *connection).await?;
        }
    }
    Ok(())
}

/// Rebuild subscription changes only when projection meaning changes.
pub const SUBSCRIPTION: &str = "grund-stack-read-model-v1";

/// Catch-up uses the same transactional projection as the command write path.
pub struct Projection;

impl TransactionalEventHandler for Projection {
    type Aggregate = Stack;

    async fn handle(
        &self,
        event: HandledEvent<Event>,
        connection: &mut PgConnection,
    ) -> anyhow::Result<()> {
        let id = crate::projections::stream_uuid(event.stream_id(), "grund-stack")?;
        apply(id, event.stream_version(), &event.event, connection).await?;
        Ok(())
    }
}
