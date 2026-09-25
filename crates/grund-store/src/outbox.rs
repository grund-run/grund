//! Work to do after commit (skills `messaging` §2): mail, resolving
//! password-reset requests, and reports to grund insights. Rows are written in the transaction of the change
//! they announce and claimed by the drain with `SKIP LOCKED`, so replicas
//! share the work without doing any of it twice at once.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// What a row asks for. The strings match the table's CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    VerifyEmailMail,
    PasswordResetMail,
    SignupExistingMail,
    PasswordResetRequested,
    InsightsAccount,
    InvitationMail,
    BillingOrganisation,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::VerifyEmailMail => "mail.verify_email",
            Kind::PasswordResetMail => "mail.password_reset",
            Kind::SignupExistingMail => "mail.signup_existing",
            Kind::PasswordResetRequested => "auth.password_reset_requested",
            Kind::InsightsAccount => "insights.account",
            Kind::InvitationMail => "mail.invitation",
            Kind::BillingOrganisation => "billing.organisation",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Kind::VerifyEmailMail,
            Kind::PasswordResetMail,
            Kind::SignupExistingMail,
            Kind::PasswordResetRequested,
            Kind::InsightsAccount,
            Kind::InvitationMail,
            Kind::BillingOrganisation,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == value)
    }
}

/// Queues a row. A second row with the same id is ignored, so a retried cause
/// never queues twice.
pub async fn enqueue(
    connection: &mut PgConnection,
    outbox_id: Uuid,
    kind: Kind,
    recipient: &str,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
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

/// A claimed row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Claimed {
    pub outbox_id: Uuid,
    pub kind: String,
    pub recipient: String,
    pub payload: serde_json::Value,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
}

/// Claims up to `limit` due rows, leasing each for `lease` (its
/// `next_attempt_at` moves out, so another replica skips it until then).
pub async fn claim(
    executor: impl PgExecutor<'_>,
    limit: i64,
    lease: Duration,
) -> Result<Vec<Claimed>, sqlx::Error> {
    sqlx::query_as::<_, Claimed>(
        "WITH due AS ( \
           SELECT outbox_id FROM grund_outbox \
           WHERE delivered_at IS NULL AND next_attempt_at <= clock_timestamp() \
           ORDER BY next_attempt_at, created_at \
           FOR UPDATE SKIP LOCKED LIMIT $1) \
         UPDATE grund_outbox o SET attempts = o.attempts + 1, \
           next_attempt_at = clock_timestamp() + make_interval(secs => $2) \
         FROM due WHERE o.outbox_id = due.outbox_id \
         RETURNING o.outbox_id, o.kind, o.recipient, o.payload, o.attempts, o.created_at",
    )
    .bind(limit)
    .bind(lease.as_secs_f64())
    .fetch_all(executor)
    .await
}

/// Marks a row done and scrubs its recipient and payload, which may hold a
/// live link or an account's details.
pub async fn delivered(executor: impl PgExecutor<'_>, outbox_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_outbox SET delivered_at = clock_timestamp(), recipient = '', payload = '{}', last_error = NULL \
         WHERE outbox_id = $1",
    )
    .bind(outbox_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Schedules the next attempt after a failure: 2^attempts seconds, at most
/// five minutes. `error` must be generic: no provider text, no secrets.
pub async fn failed(
    executor: impl PgExecutor<'_>,
    outbox_id: Uuid,
    attempts: i32,
    error: &str,
) -> Result<(), sqlx::Error> {
    let delay = 2f64.powi(attempts.clamp(0, 9)).min(300.0);
    sqlx::query(
        "UPDATE grund_outbox SET next_attempt_at = clock_timestamp() + make_interval(secs => $2), last_error = $3 \
         WHERE outbox_id = $1",
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
    sqlx::query_scalar("SELECT count(*) FROM grund_outbox WHERE delivered_at IS NULL")
        .fetch_one(executor)
        .await
}

/// Deletes rows delivered longer ago than `retention`. Bounded per pass.
pub async fn prune(executor: impl PgExecutor<'_>, retention: Duration) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_outbox WHERE outbox_id IN ( \
           SELECT outbox_id FROM grund_outbox \
           WHERE delivered_at < clock_timestamp() - make_interval(secs => $1) LIMIT 1000)",
    )
    .bind(retention.as_secs_f64())
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
