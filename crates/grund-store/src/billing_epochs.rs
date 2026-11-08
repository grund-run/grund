//! Durable, one-way destination activation and short transaction admission.
//!
//! Lock the permanent destination row before touching epoch or financial outbox
//! rows. Never hold its lock across a network call. URL bindings must be the
//! configured nonsecret destination, never a token or credential-bearing URL.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct EpochBinding {
    url: String,
    mode: String,
    activated_at: DateTime<Utc>,
    retired_at: Option<DateTime<Utc>>,
}

/// Activates a fresh destination, or resumes the exact same active binding.
/// A retired UUID can never be activated again, even against its original URL.
/// The timestamp is stable across restarts of the same epoch.
pub async fn activate(
    pool: &PgPool,
    epoch: Uuid,
    url: &str,
    mode: &str,
) -> Result<DateTime<Utc>, sqlx::Error> {
    if epoch.is_nil()
        || url.is_empty()
        || url.contains(['@', '?', '#'])
        || !matches!(mode, "sandbox" | "live")
    {
        return Err(sqlx::Error::Protocol(
            "billing epoch requires a nonsecret URL and sandbox/live mode".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    let previous: Option<Uuid> = sqlx::query_scalar(
        "SELECT epoch FROM grund_billing_destination WHERE singleton FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let existing = sqlx::query_as::<_, EpochBinding>(
        "SELECT url, mode, activated_at, retired_at FROM grund_billing_epochs WHERE epoch = $1",
    )
    .bind(epoch)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(binding) = existing {
        if binding.url != url || binding.mode != mode {
            return Err(sqlx::Error::Protocol(
                "billing epoch destination binding differs".into(),
            ));
        }
        if binding.retired_at.is_some() || previous != Some(epoch) {
            return Err(sqlx::Error::Protocol("billing epoch is retired".into()));
        }
        tx.commit().await?;
        return Ok(binding.activated_at);
    }
    let activated_at = sqlx::query_scalar(
        "INSERT INTO grund_billing_epochs (epoch, url, mode) VALUES ($1, $2, $3) RETURNING activated_at",
    )
    .bind(epoch)
    .bind(url)
    .bind(mode)
    .fetch_one(&mut *tx)
    .await?;
    if let Some(previous) = previous {
        sqlx::query(
            "UPDATE grund_billing_epochs SET retired_at = clock_timestamp() WHERE epoch = $1",
        )
        .bind(previous)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE grund_billing_destination SET epoch = $1 WHERE singleton")
        .bind(epoch)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(activated_at)
}

/// Reads the active epoch with a shared admission lock. Call inside the
/// caller's existing transaction so activation waits until its writes commit.
/// Autocommit callers get only a point-in-time read, not durable admission.
pub async fn current(connection: &mut PgConnection) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT epoch FROM grund_billing_destination WHERE singleton FOR SHARE")
        .fetch_one(connection)
        .await
}

/// Admits only the active nonnil writer, holding the same lock as `current`.
pub async fn check(connection: &mut PgConnection, epoch: Uuid) -> Result<bool, sqlx::Error> {
    Ok(current(connection).await? == Some(epoch) && !epoch.is_nil())
}

/// Returns the original activation boundary, including for retired epochs.
/// This does not acquire admission: samplers must also call `check` in the
/// transaction which advances their cursor and enqueues their observations.
pub async fn activated_at(
    connection: &mut PgConnection,
    epoch: Uuid,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    sqlx::query_scalar("SELECT activated_at FROM grund_billing_epochs WHERE epoch = $1")
        .bind(epoch)
        .fetch_optional(connection)
        .await
}
