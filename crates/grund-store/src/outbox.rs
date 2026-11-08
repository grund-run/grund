//! Work to do after commit (skills `messaging` §2): mail, resolving
//! password-reset requests, and account events for an optional operator-owned
//! endpoint. Rows are written in the transaction of the change they announce
//! and claimed by the drain with `SKIP LOCKED`.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor, PgPool};
use uuid::Uuid;

/// What a row asks for. The strings match the table's CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    VerifyEmailMail,
    PasswordResetMail,
    SignupExistingMail,
    PasswordResetRequested,
    AccountConfirmed,
    InvitationMail,
    BillingOrganisation,
    BillingMachineCount,
    BillingMachineChange,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::VerifyEmailMail => "mail.verify_email",
            Kind::PasswordResetMail => "mail.password_reset",
            Kind::SignupExistingMail => "mail.signup_existing",
            Kind::PasswordResetRequested => "auth.password_reset_requested",
            Kind::AccountConfirmed => "insights.account",
            Kind::InvitationMail => "mail.invitation",
            Kind::BillingOrganisation => "billing.organisation",
            Kind::BillingMachineCount => "billing.machine_count",
            Kind::BillingMachineChange => "billing.machine_change",
        }
    }

    pub fn is_billing(self) -> bool {
        matches!(
            self,
            Kind::BillingOrganisation | Kind::BillingMachineCount | Kind::BillingMachineChange
        )
    }

    pub fn parse(value: &str) -> Option<Self> {
        if value == "account.confirmed" {
            return Some(Kind::AccountConfirmed);
        }
        [
            Kind::VerifyEmailMail,
            Kind::PasswordResetMail,
            Kind::SignupExistingMail,
            Kind::PasswordResetRequested,
            Kind::AccountConfirmed,
            Kind::InvitationMail,
            Kind::BillingOrganisation,
            Kind::BillingMachineCount,
            Kind::BillingMachineChange,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == value)
    }
}

/// Queues a row. A second row with the same id is ignored, so a retried cause
/// never queues twice.
#[tracing::instrument(name = "store.outbox.enqueue", skip_all)]
pub async fn enqueue(
    connection: &mut PgConnection,
    outbox_id: Uuid,
    kind: Kind,
    recipient: &str,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    if kind.is_billing() {
        return Err(sqlx::Error::Protocol(
            "financial work requires enqueue_billing".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO grund_outbox (outbox_id, kind, recipient, payload) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (outbox_id) DO NOTHING",
    )
    .bind(outbox_id)
    .bind(kind.as_str())
    .bind(recipient)
    .bind(payload)
    .execute(connection)
    .await?;
    Ok(())
}

/// Queues a financial fact in the caller's existing transaction. The active
/// writer may persist a late old/unknown-origin fact, but it is immediately
/// superseded without changing its identity, payload or origin.
pub async fn enqueue_billing(
    connection: &mut PgConnection,
    outbox_id: Uuid,
    kind: Kind,
    writer_epoch: Uuid,
    origin_epoch: Option<Uuid>,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    if !kind.is_billing() || origin_epoch.is_some_and(|epoch| epoch.is_nil()) {
        return Err(sqlx::Error::Protocol(
            "invalid financial outbox kind or origin".into(),
        ));
    }
    if !crate::billing_epochs::check(&mut *connection, writer_epoch).await? {
        return Err(sqlx::Error::Protocol(
            "billing writer epoch is not active".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO grund_outbox (outbox_id, kind, recipient, payload, billing_epoch, superseded_at) \
         VALUES ($1, $2, '', $3, $4, CASE WHEN $4 IS DISTINCT FROM $5 THEN clock_timestamp() END) \
         ON CONFLICT (outbox_id) DO NOTHING",
    )
    .bind(outbox_id)
    .bind(kind.as_str())
    .bind(payload)
    .bind(origin_epoch)
    .bind(writer_epoch)
    .execute(connection)
    .await?;
    Ok(())
}

/// A claimed row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Claimed {
    pub outbox_id: Uuid,
    pub kind: String,
    pub recipient: String,
    pub payload: serde_json::Value,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub billing_epoch: Option<Uuid>,
}

/// Claims up to `limit` due rows, leasing each for `lease` (its
/// `next_attempt_at` moves out, so another replica skips it until then).
#[tracing::instrument(name = "store.outbox.claim", skip_all)]
pub async fn claim(
    pool: &PgPool,
    limit: i64,
    lease: Duration,
    writer_epoch: Option<Uuid>,
) -> Result<Vec<Claimed>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let admitted = match writer_epoch {
        Some(epoch) => crate::billing_epochs::current(&mut tx)
            .await?
            .filter(|active| *active == epoch),
        None => None,
    };
    let rows = sqlx::query_as::<_, Claimed>(
        "WITH due AS ( \
           SELECT outbox_id FROM grund_outbox \
           WHERE delivered_at IS NULL AND superseded_at IS NULL \
             AND next_attempt_at <= clock_timestamp() \
             AND (kind NOT IN ('billing.organisation', 'billing.machine_count', 'billing.machine_change') \
                  OR billing_epoch = $3) \
           ORDER BY next_attempt_at, created_at \
           FOR UPDATE SKIP LOCKED LIMIT $1) \
         UPDATE grund_outbox o SET attempts = o.attempts + 1, \
           next_attempt_at = clock_timestamp() + make_interval(secs => $2) \
         FROM due WHERE o.outbox_id = due.outbox_id \
         RETURNING o.outbox_id, o.kind, o.recipient, o.payload, o.attempts, o.created_at, o.billing_epoch",
    )
    .bind(limit)
    .bind(lease.as_secs_f64())
    .bind(admitted)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows)
}

/// Marks a row done and scrubs its recipient and payload, which may hold a
/// live link or an account's details.
#[tracing::instrument(name = "store.outbox.delivered", skip_all)]
pub async fn delivered(executor: impl PgExecutor<'_>, outbox_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_outbox SET delivered_at = clock_timestamp(), recipient = '', payload = '{}', last_error = NULL \
         WHERE outbox_id = $1 AND superseded_at IS NULL \
           AND kind NOT IN ('billing.organisation', 'billing.machine_count', 'billing.machine_change')",
    )
    .bind(outbox_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Schedules the next attempt after a failure: 2^attempts seconds, at most
/// five minutes. `error` must be generic: no provider text, no secrets.
#[tracing::instrument(name = "store.outbox.failed", skip_all)]
pub async fn failed(
    executor: impl PgExecutor<'_>,
    outbox_id: Uuid,
    attempts: i32,
    error: &str,
) -> Result<(), sqlx::Error> {
    let delay = 2f64.powi(attempts.clamp(0, 9)).min(300.0);
    sqlx::query(
        "UPDATE grund_outbox SET next_attempt_at = clock_timestamp() + make_interval(secs => $2), last_error = $3 \
         WHERE outbox_id = $1 AND superseded_at IS NULL \
           AND kind NOT IN ('billing.organisation', 'billing.machine_count', 'billing.machine_change')",
    )
    .bind(outbox_id)
    .bind(delay)
    .bind(error.chars().take(200).collect::<String>())
    .execute(executor)
    .await?;
    Ok(())
}

/// Rows not yet delivered.
pub async fn pending(executor: impl PgExecutor<'_>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_outbox WHERE delivered_at IS NULL AND superseded_at IS NULL",
    )
    .fetch_one(executor)
    .await
}

/// Mail awaiting delivery; non-mail outbox work does not depend on SMTP.
pub async fn pending_mail(executor: impl PgExecutor<'_>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_outbox WHERE delivered_at IS NULL AND kind LIKE 'mail.%'",
    )
    .fetch_one(executor)
    .await
}

/// Deletes rows delivered longer ago than `retention`. Bounded per pass.
pub async fn prune(executor: impl PgExecutor<'_>, retention: Duration) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_outbox WHERE outbox_id IN ( \
           SELECT outbox_id FROM grund_outbox \
           WHERE superseded_at IS NULL \
             AND delivered_at < clock_timestamp() - make_interval(secs => $1) LIMIT 1000)",
    )
    .bind(retention.as_secs_f64())
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Retains at most `limit` pending old/unknown-origin financial facts without
/// changing any delivery, lease, identity, payload, attempt or error fields.
/// A stale writer cannot supersede the current destination's work.
pub async fn supersede_billing(
    pool: &PgPool,
    writer_epoch: Uuid,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    if !crate::billing_epochs::check(&mut tx, writer_epoch).await? {
        return Ok(0);
    }
    let result = sqlx::query(
        "WITH stale AS ( \
           SELECT outbox_id FROM grund_outbox \
           WHERE delivered_at IS NULL AND superseded_at IS NULL \
             AND kind IN ('billing.organisation', 'billing.machine_count', 'billing.machine_change') \
             AND billing_epoch IS DISTINCT FROM $1 \
           ORDER BY created_at, outbox_id FOR UPDATE SKIP LOCKED LIMIT $2) \
         UPDATE grund_outbox o SET superseded_at = clock_timestamp() \
         FROM stale WHERE o.outbox_id = stale.outbox_id",
    )
    .bind(writer_epoch)
    .bind(limit)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result.rows_affected())
}

/// Completes only still-current financial work. A late old-target response
/// cannot erase a superseded fact, even before the supersession sweep runs.
pub async fn delivered_billing(
    pool: &PgPool,
    outbox_id: Uuid,
    writer_epoch: Uuid,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    if !crate::billing_epochs::check(&mut tx, writer_epoch).await? {
        return Ok(false);
    }
    let result = sqlx::query(
        "UPDATE grund_outbox SET delivered_at = clock_timestamp(), recipient = '', payload = '{}', last_error = NULL \
         WHERE outbox_id = $1 AND billing_epoch = $2 \
           AND delivered_at IS NULL AND superseded_at IS NULL \
           AND kind IN ('billing.organisation', 'billing.machine_count', 'billing.machine_change')",
    )
    .bind(outbox_id)
    .bind(writer_epoch)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result.rows_affected() != 0)
}

/// Retries only still-current financial work, preserving superseded facts.
/// `error` must contain generic text, never provider secrets.
pub async fn failed_billing(
    pool: &PgPool,
    outbox_id: Uuid,
    writer_epoch: Uuid,
    attempts: i32,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    if !crate::billing_epochs::check(&mut tx, writer_epoch).await? {
        return Ok(false);
    }
    let delay = 2f64.powi(attempts.clamp(0, 9)).min(300.0);
    let result = sqlx::query(
        "UPDATE grund_outbox SET next_attempt_at = clock_timestamp() + make_interval(secs => $3), last_error = $4 \
         WHERE outbox_id = $1 AND billing_epoch = $2 \
           AND delivered_at IS NULL AND superseded_at IS NULL \
           AND kind IN ('billing.organisation', 'billing.machine_count', 'billing.machine_change')",
    )
    .bind(outbox_id)
    .bind(writer_epoch)
    .bind(delay)
    .bind(error.chars().take(200).collect::<String>())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result.rows_affected() != 0)
}
