//! Reads of accounts, and the plain rows that belong to them: addresses,
//! password hashes and linked identities.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// How someone names their account when signing in.
#[derive(Debug, Clone)]
pub enum Lookup<'a> {
    Email(&'a str),
    Username(&'a str),
}

/// What sign-in needs to decide.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginRecord {
    pub account_id: Uuid,
    pub username: String,
    pub email: String,
    pub email_normalized: String,
    pub email_verified: bool,
    pub phc: Option<String>,
}

macro_rules! login_select {
    ($where:literal) => {
        concat!(
            "SELECT a.account_id, a.username, e.email, e.email_normalized, \
               a.email_verified_at IS NOT NULL AS email_verified, p.phc \
             FROM grund_accounts a \
             JOIN grund_account_emails e ON e.account_id = a.account_id \
             LEFT JOIN grund_passwords p ON p.account_id = a.account_id ",
            $where
        )
    };
}

/// The account a sign-in names, by normalised email or username.
pub async fn login_record(
    executor: impl PgExecutor<'_>,
    lookup: Lookup<'_>,
) -> Result<Option<LoginRecord>, sqlx::Error> {
    let (query, value) = match lookup {
        Lookup::Email(email) => (login_select!("WHERE e.email_normalized = $1"), email),
        Lookup::Username(name) => (login_select!("WHERE a.username = $1"), name),
    };
    sqlx::query_as::<_, LoginRecord>(query)
        .bind(value)
        .fetch_optional(executor)
        .await
}

/// The account with this id, as sign-in sees it.
pub async fn login_record_by_id(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
) -> Result<Option<LoginRecord>, sqlx::Error> {
    sqlx::query_as::<_, LoginRecord>(login_select!("WHERE a.account_id = $1"))
        .bind(account_id)
        .fetch_optional(executor)
        .await
}

/// What a report to grund insights says about a confirmed account.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConfirmedAccount {
    pub account_id: Uuid,
    pub username: String,
    pub email: String,
    pub registered_at: DateTime<Utc>,
    pub verified_at: DateTime<Utc>,
}

/// The account, if its address is confirmed. Reads the read model, so inside
/// the unit of work that confirmed it, it sees the confirmation.
pub async fn confirmed(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
) -> Result<Option<ConfirmedAccount>, sqlx::Error> {
    sqlx::query_as::<_, ConfirmedAccount>(
        "SELECT a.account_id, a.username, e.email, a.registered_at, a.email_verified_at AS verified_at \
         FROM grund_accounts a JOIN grund_account_emails e ON e.account_id = a.account_id \
         WHERE a.account_id = $1 AND a.email_verified_at IS NOT NULL",
    )
    .bind(account_id)
    .fetch_optional(executor)
    .await
}

/// Whether a username is taken.
pub async fn username_taken(
    executor: impl PgExecutor<'_>,
    username: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM grund_accounts WHERE username = $1)")
        .bind(username)
        .fetch_one(executor)
        .await
}

/// Stores the address of a new account. Fails with a unique violation on
/// `grund_account_emails_normalized_idx` when another account has it.
pub async fn insert_email(
    connection: &mut PgConnection,
    account_id: Uuid,
    email: &str,
    normalized: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO grund_account_emails (account_id, email, email_normalized) VALUES ($1, $2, $3)")
        .bind(account_id)
        .bind(email)
        .bind(normalized)
        .execute(connection)
        .await?;
    Ok(())
}

/// Sets (or replaces) an account's password hash.
pub async fn set_password(
    connection: &mut PgConnection,
    account_id: Uuid,
    phc: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_passwords (account_id, phc) VALUES ($1, $2) \
         ON CONFLICT (account_id) DO UPDATE SET phc = EXCLUDED.phc, updated_at = clock_timestamp()",
    )
    .bind(account_id)
    .bind(phc)
    .execute(connection)
    .await?;
    Ok(())
}

/// Replaces a hash only if it is still `old`: a rehash at sign-in never
/// overwrites a password changed meanwhile.
pub async fn upgrade_password(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    old: &str,
    new: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE grund_passwords SET phc = $3, updated_at = clock_timestamp() WHERE account_id = $1 AND phc = $2")
        .bind(account_id)
        .bind(old)
        .bind(new)
        .execute(executor)
        .await?;
    Ok(())
}

/// One organisation the viewer belongs to.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MembershipView {
    pub organisation_id: Uuid,
    pub slug: String,
    pub role: String,
}

/// The signed-in person, as pages and the API show them.
#[derive(Debug, Clone)]
pub struct Viewer {
    pub account_id: Uuid,
    pub username: String,
    pub email: String,
    pub registered_at: DateTime<Utc>,
    pub memberships: Vec<MembershipView>,
}

/// The viewer for an account id, or `None` if it does not exist.
pub async fn viewer(
    connection: &mut PgConnection,
    account_id: Uuid,
) -> Result<Option<Viewer>, sqlx::Error> {
    let row: Option<(String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT a.username, e.email, a.registered_at FROM grund_accounts a \
         JOIN grund_account_emails e ON e.account_id = a.account_id WHERE a.account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(&mut *connection)
    .await?;
    let Some((username, email, registered_at)) = row else {
        return Ok(None);
    };
    let memberships = sqlx::query_as::<_, MembershipView>(
        "SELECT m.organisation_id, o.slug, m.role FROM grund_memberships m \
         JOIN grund_organisations o ON o.organisation_id = m.organisation_id \
         WHERE m.account_id = $1 ORDER BY o.slug",
    )
    .bind(account_id)
    .fetch_all(&mut *connection)
    .await?;
    Ok(Some(Viewer {
        account_id,
        username,
        email,
        registered_at,
        memberships,
    }))
}

/// The account a social identity is linked to.
pub async fn identity_account(
    executor: impl PgExecutor<'_>,
    provider: &str,
    subject: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT account_id FROM grund_identities WHERE provider = $1 AND subject = $2",
    )
    .bind(provider)
    .bind(subject)
    .fetch_optional(executor)
    .await
}

/// Links a social identity. Fails with a unique violation when the identity
/// or the account's slot for that provider is already taken.
pub async fn insert_identity(
    connection: &mut PgConnection,
    identity_id: Uuid,
    provider: &str,
    subject: &str,
    account_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO grund_identities (identity_id, provider, subject, account_id) VALUES ($1, $2, $3, $4)")
        .bind(identity_id)
        .bind(provider)
        .bind(subject)
        .bind(account_id)
        .execute(connection)
        .await?;
    Ok(())
}
