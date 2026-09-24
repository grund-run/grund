//! grund's PostgreSQL store.
//!
//! Two migrators share one database: [`MIGRATOR`] owns every `grund_*` table,
//! and mire owns `es_*` (the event log). Both run at startup before anything
//! is served, and both are idempotent and serialised by advisory locks, so
//! replicas starting together are safe.

pub mod accounts;
pub mod outbox;
pub mod projections;
pub mod sessions;
pub mod throttle;
pub mod tokens;
pub mod work;

use anyhow::Context;
use sqlx::PgPool;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// Applies grund's migrations and mire's, in that order.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR.run(pool).await.context("apply grund migrations")?;
    mire::EventStore::new(pool.clone())
        .migrate()
        .await
        .context("apply mire (event store) migrations")?;
    Ok(())
}
