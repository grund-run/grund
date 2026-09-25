//! Reads of organisations and their members, and the plain rows that go with
//! them: invitations (address and link digest), the single-organisation
//! instance's row, and which organisation an account used last.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// An organisation as one of its members sees it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Membership {
    pub organisation_id: Uuid,
    pub slug: String,
    pub kind: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// The organisation `slug`, if `account_id` is a member. `None` both when it
/// does not exist and when the account is not a member, so a caller cannot
/// tell the two apart.
pub async fn membership(
    executor: impl PgExecutor<'_>,
    slug: &str,
    account_id: Uuid,
) -> Result<Option<Membership>, sqlx::Error> {
    sqlx::query_as::<_, Membership>(
        "SELECT o.organisation_id, o.slug, o.kind, m.role, o.created_at FROM grund_organisations o \
         JOIN grund_memberships m ON m.organisation_id = o.organisation_id \
         WHERE o.slug = $1 AND m.account_id = $2",
    )
    .bind(slug)
    .bind(account_id)
    .fetch_optional(executor)
    .await
}

/// Every organisation the account belongs to, by slug.
pub async fn memberships_of(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
) -> Result<Vec<Membership>, sqlx::Error> {
    sqlx::query_as::<_, Membership>(
        "SELECT o.organisation_id, o.slug, o.kind, m.role, o.created_at FROM grund_memberships m \
         JOIN grund_organisations o ON o.organisation_id = m.organisation_id \
         WHERE m.account_id = $1 ORDER BY o.slug",
    )
    .bind(account_id)
    .fetch_all(executor)
    .await
}

/// A member, as the members page lists them.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MemberRow {
    pub account_id: Uuid,
    pub username: String,
    pub email: String,
    pub role: String,
    pub joined_at: Option<DateTime<Utc>>,
}

/// The organisation's members: owners first, then admins, then members, each
/// by username.
pub async fn members(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<MemberRow>, sqlx::Error> {
    sqlx::query_as::<_, MemberRow>(
        "SELECT a.account_id, a.username, e.email, m.role, m.joined_at FROM grund_memberships m \
         JOIN grund_accounts a ON a.account_id = m.account_id \
         JOIN grund_account_emails e ON e.account_id = m.account_id \
         WHERE m.organisation_id = $1 \
         ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, a.username",
    )
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// Whether the organisation has a member with this normalised address.
pub async fn has_member_with_email(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    email_normalized: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_memberships m \
         JOIN grund_account_emails e ON e.account_id = m.account_id \
         WHERE m.organisation_id = $1 AND e.email_normalized = $2)",
    )
    .bind(organisation_id)
    .bind(email_normalized)
    .fetch_one(executor)
    .await
}

/// Whether a slug is used, by an organisation or an account: the two share
/// one namespace.
pub async fn slug_taken(executor: impl PgExecutor<'_>, slug: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_organisations WHERE slug = $1) \
             OR EXISTS (SELECT 1 FROM grund_accounts WHERE username = $1)",
    )
    .bind(slug)
    .fetch_one(executor)
    .await
}

/// A new invitation's plain row.
#[derive(Debug, Clone)]
pub struct NewInvitation<'a> {
    pub invitation_id: Uuid,
    pub organisation_id: Uuid,
    pub token_digest: &'a [u8; 32],
    pub email: &'a str,
    pub email_normalized: &'a str,
    pub role: &'a str,
    pub invited_by: Uuid,
    pub expires_at: DateTime<Utc>,
}

/// Stores an invitation, withdrawing any pending one to the same address in
/// the same organisation (the stream records that as `Replaced`).
pub async fn insert_invitation(
    connection: &mut PgConnection,
    invitation: &NewInvitation<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_invitations SET withdrawn_at = clock_timestamp() \
         WHERE organisation_id = $1 AND email_normalized = $2 \
           AND accepted_at IS NULL AND withdrawn_at IS NULL",
    )
    .bind(invitation.organisation_id)
    .bind(invitation.email_normalized)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO grund_invitations \
           (invitation_id, organisation_id, token_digest, email, email_normalized, role, invited_by, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(invitation.invitation_id)
    .bind(invitation.organisation_id)
    .bind(&invitation.token_digest[..])
    .bind(invitation.email)
    .bind(invitation.email_normalized)
    .bind(invitation.role)
    .bind(invitation.invited_by)
    .bind(invitation.expires_at)
    .execute(connection)
    .await?;
    Ok(())
}

/// A pending invitation, as the members page lists it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingRow {
    pub invitation_id: Uuid,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub expires_at: DateTime<Utc>,
}

/// The organisation's invitations that are neither used, withdrawn nor
/// expired, newest first.
pub async fn pending_invitations(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<PendingRow>, sqlx::Error> {
    sqlx::query_as::<_, PendingRow>(
        "SELECT i.invitation_id, i.email, i.role, a.username AS invited_by, i.expires_at \
         FROM grund_invitations i JOIN grund_accounts a ON a.account_id = i.invited_by \
         WHERE i.organisation_id = $1 AND i.accepted_at IS NULL AND i.withdrawn_at IS NULL \
           AND i.expires_at > clock_timestamp() \
         ORDER BY i.created_at DESC",
    )
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// What an invitation link opens.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InvitationView {
    pub invitation_id: Uuid,
    pub organisation_id: Uuid,
    pub slug: String,
    pub email: String,
    pub email_normalized: String,
    pub role: String,
    pub invited_by: String,
}

/// The invitation behind a link, if it is still usable.
pub async fn open_invitation(
    executor: impl PgExecutor<'_>,
    token_digest: &[u8; 32],
) -> Result<Option<InvitationView>, sqlx::Error> {
    sqlx::query_as::<_, InvitationView>(
        "SELECT i.invitation_id, i.organisation_id, o.slug, i.email, i.email_normalized, i.role, \
                a.username AS invited_by \
         FROM grund_invitations i \
         JOIN grund_organisations o ON o.organisation_id = i.organisation_id \
         JOIN grund_accounts a ON a.account_id = i.invited_by \
         WHERE i.token_digest = $1 AND i.accepted_at IS NULL AND i.withdrawn_at IS NULL \
           AND i.expires_at > clock_timestamp()",
    )
    .bind(&token_digest[..])
    .fetch_optional(executor)
    .await
}

/// Marks an invitation used.
pub async fn mark_accepted(
    connection: &mut PgConnection,
    invitation_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_invitations SET accepted_at = clock_timestamp() WHERE invitation_id = $1",
    )
    .bind(invitation_id)
    .execute(connection)
    .await?;
    Ok(())
}

/// Marks an invitation withdrawn.
pub async fn mark_withdrawn(
    connection: &mut PgConnection,
    invitation_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_invitations SET withdrawn_at = clock_timestamp() WHERE invitation_id = $1",
    )
    .bind(invitation_id)
    .execute(connection)
    .await?;
    Ok(())
}

/// Claims the instance's one organisation. Fails with a unique violation on
/// `grund_instance_pkey` when another sign-up claimed it first.
pub async fn claim_instance(
    connection: &mut PgConnection,
    organisation_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO grund_instance (organisation_id) VALUES ($1)")
        .bind(organisation_id)
        .execute(connection)
        .await?;
    Ok(())
}

/// The instance's organisation, once its first account exists.
pub async fn instance(executor: impl PgExecutor<'_>) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT organisation_id FROM grund_instance")
        .fetch_optional(executor)
        .await
}

/// Remembers the organisation an account opened last.
pub async fn remember_last(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    organisation_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_account_preferences (account_id, last_organisation_id) VALUES ($1, $2) \
         ON CONFLICT (account_id) DO UPDATE SET last_organisation_id = EXCLUDED.last_organisation_id, \
           updated_at = clock_timestamp() \
         WHERE grund_account_preferences.last_organisation_id IS DISTINCT FROM EXCLUDED.last_organisation_id",
    )
    .bind(account_id)
    .bind(organisation_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// The slug of the organisation `/` should open: the one used last if the
/// account is still a member, else its first by slug.
pub async fn landing(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT o.slug FROM grund_memberships m \
         JOIN grund_organisations o ON o.organisation_id = m.organisation_id \
         LEFT JOIN grund_account_preferences p \
           ON p.account_id = m.account_id AND p.last_organisation_id = m.organisation_id \
         WHERE m.account_id = $1 \
         ORDER BY (p.account_id IS NULL), o.slug LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(executor)
    .await
}
