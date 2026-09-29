//! Read-only questions `grund doctor` asks the database. Nothing here writes.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// The server's version and this database's size.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Database {
    pub version: String,
    pub size_bytes: i64,
}

pub async fn database(pool: &PgPool) -> Result<Database, sqlx::Error> {
    sqlx::query_as::<_, Database>(
        "SELECT current_setting('server_version') AS version, \
         pg_database_size(current_database()) AS size_bytes",
    )
    .fetch_one(pool)
    .await
}

/// How the migrations this binary carries compare with what the database
/// has applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migrations {
    /// Carried by this binary.
    pub known: usize,
    /// Carried and applied.
    pub applied: usize,
    /// Carried, not applied yet: `grund serve` applies them on start.
    pub pending: Vec<i64>,
    /// Applied by a build newer than this one.
    pub unknown: Vec<i64>,
    /// Applied, but not with the SQL this binary carries, or failed.
    pub changed: Vec<i64>,
}

pub async fn migrations(pool: &PgPool) -> Result<Migrations, sqlx::Error> {
    let applied: Vec<(i64, Vec<u8>, bool)> = match sqlx::query_as(
        "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(error)
            if error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42P01") =>
        {
            Vec::new()
        }
        Err(error) => return Err(error),
    };
    let known: Vec<_> = crate::MIGRATOR
        .iter()
        .filter(|m| m.migration_type.is_up_migration())
        .collect();
    let mut report = Migrations {
        known: known.len(),
        applied: 0,
        pending: Vec::new(),
        unknown: Vec::new(),
        changed: Vec::new(),
    };
    for migration in &known {
        match applied
            .iter()
            .find(|(version, _, _)| *version == migration.version)
        {
            None => report.pending.push(migration.version),
            Some((_, checksum, success)) => {
                if !success || checksum.as_slice() != &*migration.checksum {
                    report.changed.push(migration.version);
                } else {
                    report.applied += 1;
                }
            }
        }
    }
    report.unknown = applied
        .iter()
        .map(|(version, _, _)| *version)
        .filter(|version| !known.iter().any(|m| m.version == *version))
        .collect();
    Ok(report)
}

/// The stored certificate for a subject, as the ordering side left it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Certificate {
    pub names: Vec<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub renew_at: Option<DateTime<Utc>>,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

pub async fn certificate(pool: &PgPool, subject: &str) -> Result<Option<Certificate>, sqlx::Error> {
    sqlx::query_as::<_, Certificate>(
        "SELECT names, not_before, not_after, renew_at, attempts, next_attempt_at, last_error \
         FROM grund_certificates WHERE subject = $1",
    )
    .bind(subject)
    .fetch_optional(pool)
    .await
}

/// Mail waiting in the outbox (`mail.*` rows; insights and billing reports
/// are other work).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Mail {
    pub pending: i64,
    /// Waiting after at least one failed delivery.
    pub failing: i64,
    pub oldest: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

pub async fn mail(pool: &PgPool) -> Result<Mail, sqlx::Error> {
    sqlx::query_as::<_, Mail>(
        "SELECT count(*) AS pending, count(*) FILTER (WHERE attempts > 0) AS failing, \
         min(created_at) AS oldest, \
         (SELECT last_error FROM grund_outbox WHERE delivered_at IS NULL AND kind LIKE 'mail.%' \
          AND last_error IS NOT NULL ORDER BY next_attempt_at DESC LIMIT 1) AS last_error \
         FROM grund_outbox WHERE delivered_at IS NULL AND kind LIKE 'mail.%'",
    )
    .fetch_one(pool)
    .await
}

/// How many accounts exist: none means the instance has no owner yet.
pub async fn accounts(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM grund_accounts")
        .fetch_one(pool)
        .await
}
