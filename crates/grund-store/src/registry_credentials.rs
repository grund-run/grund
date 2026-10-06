//! Registry credentials (grund-docs design/apps.md §6.5): one sealed login
//! per organisation and registry host. Sealing and opening are the
//! server's; this stores bytes.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// A stored credential, still sealed.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SealedCredential {
    pub organisation_id: Uuid,
    pub host: String,
    pub username: String,
    pub sealed_password: Vec<u8>,
    pub version: i32,
}

/// A credential as the dashboard lists it: never the password.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CredentialView {
    pub host: String,
    pub username: String,
    pub version: i32,
    pub updated_by: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// The version the next credential for `host` takes, with the
/// organisation's row locked so two writers cannot both take it, or `None`
/// when the organisation already has `max` credentials and `host` is not
/// one of them.
pub async fn next_version(
    connection: &mut PgConnection,
    organisation_id: Uuid,
    host: &str,
    max: i64,
) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query("SELECT 1 FROM grund_organisations WHERE organisation_id = $1 FOR UPDATE")
        .bind(organisation_id)
        .execute(&mut *connection)
        .await?;
    let (current, count): (Option<i32>, i64) = sqlx::query_as(
        "SELECT (SELECT version FROM grund_registry_credentials \
                 WHERE organisation_id = $1 AND host = $2), \
                (SELECT count(*) FROM grund_registry_credentials WHERE organisation_id = $1)",
    )
    .bind(organisation_id)
    .bind(host)
    .fetch_one(&mut *connection)
    .await?;
    Ok(match current {
        Some(version) => Some(version + 1),
        None if count < max => Some(1),
        None => None,
    })
}

/// Stores `host`'s credential at `version`, replacing the one before.
pub async fn put(
    connection: &mut PgConnection,
    credential: &SealedCredential,
    updated_by: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_registry_credentials \
           (organisation_id, host, username, sealed_password, version, updated_by) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (organisation_id, host) DO UPDATE SET username = EXCLUDED.username, \
           sealed_password = EXCLUDED.sealed_password, version = EXCLUDED.version, \
           updated_by = EXCLUDED.updated_by, updated_at = clock_timestamp()",
    )
    .bind(credential.organisation_id)
    .bind(&credential.host)
    .bind(&credential.username)
    .bind(&credential.sealed_password)
    .bind(credential.version)
    .bind(updated_by)
    .execute(connection)
    .await?;
    Ok(())
}

/// Removes `host`'s credential. `false` when the organisation has none for
/// it.
pub async fn remove(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    host: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_registry_credentials WHERE organisation_id = $1 AND host = $2",
    )
    .bind(organisation_id)
    .bind(host)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// The organisation's credentials, by host, without their passwords.
pub async fn list(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<CredentialView>, sqlx::Error> {
    sqlx::query_as::<_, CredentialView>(
        "SELECT c.host, c.username, c.version, a.username AS updated_by, c.updated_at \
         FROM grund_registry_credentials c \
         LEFT JOIN grund_accounts a ON a.account_id = c.updated_by \
         WHERE c.organisation_id = $1 ORDER BY c.host",
    )
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// The organisation's credential for `host`, sealed.
pub async fn for_host(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    host: &str,
) -> Result<Option<SealedCredential>, sqlx::Error> {
    sqlx::query_as::<_, SealedCredential>(
        "SELECT organisation_id, host, username, sealed_password, version \
         FROM grund_registry_credentials WHERE organisation_id = $1 AND host = $2",
    )
    .bind(organisation_id)
    .bind(host)
    .fetch_optional(executor)
    .await
}

/// The credential for `host` of the organisation that owns `app_id`.
pub async fn for_app(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
    host: &str,
) -> Result<Option<SealedCredential>, sqlx::Error> {
    sqlx::query_as::<_, SealedCredential>(
        "SELECT c.organisation_id, c.host, c.username, c.sealed_password, c.version \
         FROM grund_apps a JOIN grund_registry_credentials c \
           ON c.organisation_id = a.organisation_id AND c.host = $2 \
         WHERE a.app_id = $1",
    )
    .bind(app_id)
    .bind(host)
    .fetch_optional(executor)
    .await
}
