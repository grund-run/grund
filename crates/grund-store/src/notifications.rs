//! Recipient-scoped inbox projection and verified-address invitation queries.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor, PgPool};
use uuid::Uuid;

use crate::organisations::InvitationView;

/// A retained notification visible to its recipient.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NotificationRow {
    pub account_id: Uuid,
    pub id: Uuid,
    pub organisation_id: Option<Uuid>,
    pub source_kind: String,
    pub source_id: Uuid,
    pub kind: String,
    pub resource_name: String,
    pub href: String,
    pub created_at: DateTime<Utc>,
    pub read_at: Option<DateTime<Utc>>,
    pub repeat_count: i32,
}

impl NotificationRow {
    /// Factual display text; no event payload or user-supplied reason is stored.
    pub fn text(&self) -> String {
        let action = match self.kind.as_str() {
            "invitation.received" => "Invited to",
            "release.failed" => "Release failed for",
            "release.rolled_back" => "Release rolled back for",
            "machine.out_of_service" => "Machine out of service:",
            "machine.disconnected" => "Machine disconnected:",
            "domain.certificate_issued" => "Certificate issued for",
            "domain.certificate_failing" => "Certificate failing for",
            "hosted_machine.ready" => "Hosted machine ready:",
            "hosted_machine.failed" => "Hosted machine creation failed:",
            "operator.host_unreachable" => "Fleet host unreachable:",
            "operator.migration_timeout" => "Migration timed out:",
            "operator.migration_failed" => "Migration settle failed:",
            "operator.lease_failed" => "Lease failed:",
            _ => "Notification for",
        };
        format!("{action} {}", self.resource_name)
    }
}

fn permitted(kind: &str, operator: bool) -> bool {
    match kind {
        "release.failed"
        | "release.rolled_back"
        | "machine.out_of_service"
        | "machine.disconnected"
        | "domain.certificate_issued"
        | "domain.certificate_failing"
        | "hosted_machine.ready"
        | "hosted_machine.failed" => !operator,
        "operator.host_unreachable"
        | "operator.migration_timeout"
        | "operator.migration_failed"
        | "operator.lease_failed" => operator,
        _ => false,
    }
}

fn safe_href(href: &str) -> bool {
    href.starts_with('/')
        && !href.starts_with("//")
        && href.len() <= 512
        && !href.bytes().any(|byte| matches!(byte, b'?' | b'#' | b'\\'))
        && !href.chars().any(char::is_whitespace)
}

fn validate(
    kind: &str,
    resource_name: &str,
    href: &str,
    operator: bool,
) -> Result<(), sqlx::Error> {
    if permitted(kind, operator)
        && !resource_name.is_empty()
        && resource_name.chars().count() <= 253
        && safe_href(href)
    {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol("invalid notification fact".into()))
    }
}

async fn prune_account(conn: &mut PgConnection, account_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "WITH ranked AS (SELECT id, row_number() OVER (ORDER BY created_at DESC, id DESC) AS position \
         FROM grund_notifications WHERE account_id = $1) \
         DELETE FROM grund_notifications n USING ranked r \
         WHERE n.account_id = $1 AND n.id = r.id \
           AND (r.position > 1000 OR n.created_at <= clock_timestamp() - interval '90 days')",
    )
    .bind(account_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "WITH ranked AS (SELECT source_kind, source_id, \
           row_number() OVER (ORDER BY created_at DESC, source_id DESC, source_kind DESC) AS position \
         FROM grund_notification_sources WHERE account_id = $1) \
         DELETE FROM grund_notification_sources s USING ranked r \
         WHERE s.account_id = $1 AND s.source_kind = r.source_kind AND s.source_id = r.source_id \
           AND (r.position > 10000 OR s.created_at <= clock_timestamp() - interval '90 days')",
    )
    .bind(account_id)
    .execute(conn)
    .await?;
    Ok(())
}

struct Fact<'a> {
    source_kind: &'a str,
    kind: &'a str,
    source_id: Uuid,
    resource_name: &'a str,
    href: &'a str,
    occurred_at: DateTime<Utc>,
    operator: bool,
}

async fn emit(
    conn: &mut PgConnection,
    organisation_id: Uuid,
    fact: Fact<'_>,
) -> Result<(), sqlx::Error> {
    validate(fact.kind, fact.resource_name, fact.href, fact.operator)?;
    let accounts: Vec<Uuid> = sqlx::query_scalar(
        "SELECT account_id FROM grund_memberships \
         WHERE organisation_id = $1 AND $2::timestamptz > clock_timestamp() - interval '90 days' \
           AND (joined_at IS NULL OR joined_at <= $2) \
         ORDER BY account_id FOR KEY SHARE",
    )
    .bind(organisation_id)
    .bind(fact.occurred_at)
    .fetch_all(&mut *conn)
    .await?;
    for account_id in accounts {
        insert_for(conn, account_id, Some(organisation_id), &fact).await?;
    }
    Ok(())
}

async fn insert_for(
    conn: &mut PgConnection,
    account_id: Uuid,
    organisation_id: Option<Uuid>,
    fact: &Fact<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 51448))")
        .bind(account_id)
        .execute(&mut *conn)
        .await?;
    let already_seen: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_notification_sources \
         WHERE account_id = $1 AND source_kind = $2 AND source_id = $3) \
         OR EXISTS (SELECT 1 FROM grund_notifications \
         WHERE account_id = $1 AND source_kind = $2 AND source_id = $3)",
    )
    .bind(account_id)
    .bind(fact.source_kind)
    .bind(fact.source_id)
    .fetch_one(&mut *conn)
    .await?;
    if already_seen {
        return Ok(());
    }
    let collapsed: Option<Uuid> = if fact.operator {
        sqlx::query_scalar(
            "UPDATE grund_notifications SET repeat_count = repeat_count + 1, read_at = NULL \
             WHERE account_id = $1 AND id = ( \
               SELECT id FROM grund_notifications WHERE account_id = $1 AND organisation_id = $2 \
                 AND kind = $3 AND href = $4 AND resource_name = $5 \
                 AND created_at > $6::timestamptz - interval '10 minutes' \
                 AND created_at <= $6 \
                 AND repeat_count < 2147483647 ORDER BY created_at DESC, id DESC LIMIT 1) \
             RETURNING id",
        )
        .bind(account_id)
        .bind(organisation_id)
        .bind(fact.kind)
        .bind(fact.href)
        .bind(fact.resource_name)
        .bind(fact.occurred_at)
        .fetch_optional(&mut *conn)
        .await?
    } else {
        None
    };
    if collapsed.is_none() {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO grund_notifications \
             (account_id, id, organisation_id, source_kind, source_id, kind, resource_name, href, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(account_id)
        .bind(id)
        .bind(organisation_id)
        .bind(fact.source_kind)
        .bind(fact.source_id)
        .bind(fact.kind)
        .bind(fact.resource_name)
        .bind(fact.href)
        .bind(fact.occurred_at)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query(
        "INSERT INTO grund_notification_sources (account_id, source_kind, source_id, created_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(account_id)
    .bind(fact.source_kind)
    .bind(fact.source_id)
    .bind(fact.occurred_at)
    .execute(&mut *conn)
    .await?;
    prune_account(conn, account_id).await
}

/// Delivers a committed organisation fact to current members within its transaction.
pub async fn emit_org(
    conn: &mut PgConnection,
    organisation_id: Uuid,
    kind: &str,
    source_id: Uuid,
    resource_name: &str,
    href: &str,
    occurred_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    emit(
        conn,
        organisation_id,
        Fact {
            source_kind: kind,
            kind,
            source_id,
            resource_name,
            href,
            occurred_at,
            operator: false,
        },
    )
    .await
}

/// Delivers an operator-only fact; matching recent facts collapse into one row.
pub async fn emit_operator(
    conn: &mut PgConnection,
    organisation_id: Uuid,
    kind: &str,
    source_id: Uuid,
    resource_name: &str,
    href: &str,
    occurred_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    emit(
        conn,
        organisation_id,
        Fact {
            source_kind: kind,
            kind,
            source_id,
            resource_name,
            href,
            occurred_at,
            operator: true,
        },
    )
    .await
}

/// Delivers an invitation only to an account whose matching address is verified.
pub async fn emit_invitation(
    conn: &mut PgConnection,
    invitation_id: Uuid,
    organisation_id: Uuid,
    resource_name: &str,
) -> Result<(), sqlx::Error> {
    if resource_name.is_empty() || resource_name.chars().count() > 253 {
        return Err(sqlx::Error::Protocol(
            "invalid invitation resource name".into(),
        ));
    }
    let account: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT a.account_id, i.created_at FROM grund_invitations i \
         JOIN grund_account_emails e ON e.email_normalized = i.email_normalized \
         JOIN grund_accounts a ON a.account_id = e.account_id \
         JOIN grund_organisations o ON o.organisation_id = i.organisation_id \
         WHERE i.invitation_id = $1 AND i.organisation_id = $2 \
           AND a.email_verified_at IS NOT NULL AND o.deleted_at IS NULL \
           AND i.accepted_at IS NULL AND i.withdrawn_at IS NULL \
           AND i.created_at > clock_timestamp() - interval '90 days' \
           AND i.expires_at > clock_timestamp() \
           AND NOT EXISTS (SELECT 1 FROM grund_memberships m \
                           WHERE m.organisation_id = i.organisation_id AND m.account_id = a.account_id) \
         FOR SHARE OF i",
    )
    .bind(invitation_id)
    .bind(organisation_id)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((account_id, occurred_at)) = account {
        insert_for(
            conn,
            account_id,
            Some(organisation_id),
            &Fact {
                source_kind: "invitation",
                kind: "invitation.received",
                source_id: invitation_id,
                resource_name,
                href: "/",
                occurred_at,
                operator: false,
            },
        )
        .await?;
    }
    Ok(())
}

/// An actionable invitation addressed to the signed-in account.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingInvitation {
    pub invitation_id: Uuid,
    pub organisation_id: Uuid,
    pub slug: String,
    pub role: String,
}

/// Pending invitations appear after sign-up only once the address is verified.
pub async fn pending_for_account(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
) -> Result<Vec<PendingInvitation>, sqlx::Error> {
    sqlx::query_as::<_, PendingInvitation>(
        "SELECT i.invitation_id, i.organisation_id, o.slug, i.role \
         FROM grund_accounts a \
         JOIN grund_account_emails e ON e.account_id = a.account_id \
         JOIN grund_invitations i ON i.email_normalized = e.email_normalized \
         JOIN grund_organisations o ON o.organisation_id = i.organisation_id \
         WHERE a.account_id = $1 AND a.email_verified_at IS NOT NULL \
           AND o.deleted_at IS NULL AND i.accepted_at IS NULL AND i.withdrawn_at IS NULL \
           AND i.expires_at > clock_timestamp() \
           AND NOT EXISTS (SELECT 1 FROM grund_memberships m \
                           WHERE m.account_id = a.account_id AND m.organisation_id = i.organisation_id) \
         ORDER BY i.created_at DESC, i.invitation_id DESC",
    )
    .bind(account_id)
    .fetch_all(executor)
    .await
}

const INVITATION_FOR_ACCOUNT: &str = "SELECT i.invitation_id, i.organisation_id, o.slug, i.email, i.email_normalized, i.role, \
            inviter.username AS invited_by \
     FROM grund_invitations i \
     JOIN grund_organisations o ON o.organisation_id = i.organisation_id \
     JOIN grund_accounts inviter ON inviter.account_id = i.invited_by \
     JOIN grund_account_emails e ON e.email_normalized = i.email_normalized \
     JOIN grund_accounts a ON a.account_id = e.account_id \
     WHERE a.account_id = $1 AND a.email_verified_at IS NOT NULL \
       AND i.invitation_id = $2 AND o.deleted_at IS NULL \
       AND i.accepted_at IS NULL AND i.withdrawn_at IS NULL AND i.expires_at > clock_timestamp() \
       AND NOT EXISTS (SELECT 1 FROM grund_memberships m \
                       WHERE m.account_id = a.account_id AND m.organisation_id = i.organisation_id)";

/// Finds a still-actionable invitation without exposing a link token.
pub async fn invitation_for_account(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    invitation_id: Uuid,
) -> Result<Option<InvitationView>, sqlx::Error> {
    sqlx::query_as::<_, InvitationView>(INVITATION_FOR_ACCOUNT)
        .bind(account_id)
        .bind(invitation_id)
        .fetch_optional(executor)
        .await
}

/// Locks the invitation and verified address while its event is committed.
pub async fn invitation_for_account_in(
    conn: &mut PgConnection,
    account_id: Uuid,
    invitation_id: Uuid,
) -> Result<Option<InvitationView>, sqlx::Error> {
    sqlx::query_as::<_, InvitationView>(
        "SELECT i.invitation_id, i.organisation_id, o.slug, i.email, i.email_normalized, i.role, \
                inviter.username AS invited_by \
         FROM grund_invitations i \
         JOIN grund_organisations o ON o.organisation_id = i.organisation_id \
         JOIN grund_accounts inviter ON inviter.account_id = i.invited_by \
         JOIN grund_account_emails e ON e.email_normalized = i.email_normalized \
         JOIN grund_accounts a ON a.account_id = e.account_id \
         WHERE a.account_id = $1 AND a.email_verified_at IS NOT NULL \
           AND i.invitation_id = $2 AND o.deleted_at IS NULL \
           AND i.accepted_at IS NULL AND i.withdrawn_at IS NULL AND i.expires_at > clock_timestamp() \
           AND NOT EXISTS (SELECT 1 FROM grund_memberships m \
                           WHERE m.account_id = a.account_id AND m.organisation_id = i.organisation_id) \
         FOR UPDATE OF i, a, e",
    )
        .bind(account_id)
        .bind(invitation_id)
        .fetch_optional(conn)
        .await
}

/// Withdraws a pending invitation only when the verified invitee acts on it.
pub async fn decline_in(
    conn: &mut PgConnection,
    account_id: Uuid,
    invitation_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_invitations i SET withdrawn_at = clock_timestamp() \
         FROM grund_account_emails e JOIN grund_accounts a ON a.account_id = e.account_id \
         WHERE i.invitation_id = $2 AND a.account_id = $1 \
           AND e.email_normalized = i.email_normalized AND a.email_verified_at IS NOT NULL \
           AND i.accepted_at IS NULL AND i.withdrawn_at IS NULL \
           AND i.expires_at > clock_timestamp()",
    )
    .bind(account_id)
    .bind(invitation_id)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Returns at most `limit` inbox rows using the descending timestamp/UUID key.
pub async fn list(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    unread_only: bool,
    limit: i64,
    cursor: Option<(DateTime<Utc>, Uuid)>,
    organisation_scope: Option<Uuid>,
) -> Result<Vec<NotificationRow>, sqlx::Error> {
    sqlx::query_as::<_, NotificationRow>(
        "SELECT n.account_id, n.id, n.organisation_id, n.source_kind, n.source_id, n.kind, \
                n.resource_name, n.href, n.created_at, n.read_at, n.repeat_count \
         FROM grund_notifications n \
         WHERE n.account_id = $1 AND n.created_at > clock_timestamp() - interval '90 days' \
           AND ($2 = false OR n.read_at IS NULL) \
           AND ($3::timestamptz IS NULL OR (n.created_at, n.id) < ($3, $4)) \
           AND ($5::uuid IS NULL OR n.organisation_id = $5) \
           AND (n.organisation_id IS NULL OR EXISTS (SELECT 1 FROM grund_memberships m \
                WHERE m.account_id = $1 AND m.organisation_id = n.organisation_id) \
                OR (n.kind = 'invitation.received' AND EXISTS ( \
                  SELECT 1 FROM grund_invitations i JOIN grund_account_emails e \
                    ON e.email_normalized = i.email_normalized \
                  JOIN grund_accounts a ON a.account_id = e.account_id \
                  WHERE i.invitation_id = n.source_id AND i.organisation_id = n.organisation_id \
                    AND a.account_id = $1 AND EXISTS (SELECT 1 FROM grund_organisations o \
                      WHERE o.organisation_id = i.organisation_id AND o.deleted_at IS NULL) \
                    AND a.email_verified_at IS NOT NULL AND i.accepted_at IS NULL \
                    AND i.withdrawn_at IS NULL AND i.expires_at > clock_timestamp()))) \
         ORDER BY n.created_at DESC, n.id DESC LIMIT $6",
    )
    .bind(account_id)
    .bind(unread_only)
    .bind(cursor.as_ref().map(|(at, _)| *at))
    .bind(cursor.map(|(_, id)| id))
    .bind(organisation_scope)
    .bind(limit.clamp(1, 101))
    .fetch_all(executor)
    .await
}

/// One recipient-first indexed unread count; an organisation-bound PAT sees only its organisation.
pub async fn count(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    organisation_scope: Option<Uuid>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_notifications n \
         WHERE n.account_id = $1 AND n.read_at IS NULL \
           AND n.created_at > clock_timestamp() - interval '90 days' \
           AND ($2::uuid IS NULL OR n.organisation_id = $2) \
           AND (n.organisation_id IS NULL OR EXISTS (SELECT 1 FROM grund_memberships m \
                 WHERE m.account_id = $1 AND m.organisation_id = n.organisation_id) \
                OR (n.kind = 'invitation.received' AND EXISTS ( \
                  SELECT 1 FROM grund_invitations i JOIN grund_account_emails e \
                    ON e.email_normalized = i.email_normalized \
                  JOIN grund_accounts a ON a.account_id = e.account_id \
                  WHERE i.invitation_id = n.source_id AND i.organisation_id = n.organisation_id \
                    AND a.account_id = $1 AND EXISTS (SELECT 1 FROM grund_organisations o \
                      WHERE o.organisation_id = i.organisation_id AND o.deleted_at IS NULL) \
                    AND a.email_verified_at IS NOT NULL AND i.accepted_at IS NULL \
                    AND i.withdrawn_at IS NULL AND i.expires_at > clock_timestamp())))",
    )
    .bind(account_id)
    .bind(organisation_scope)
    .fetch_one(executor)
    .await
}

/// Sets read time, returning false when the row is absent or outside the caller's audience.
pub async fn mark_read(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    id: Uuid,
    organisation_scope: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_notifications n SET read_at = COALESCE(n.read_at, clock_timestamp()) \
         WHERE n.account_id = $1 AND n.id = $2 \
           AND n.created_at > clock_timestamp() - interval '90 days' \
           AND ($3::uuid IS NULL OR n.organisation_id = $3) \
           AND (n.organisation_id IS NULL OR EXISTS (SELECT 1 FROM grund_memberships m \
                WHERE m.account_id = $1 AND m.organisation_id = n.organisation_id) \
                OR (n.kind = 'invitation.received' AND EXISTS ( \
                  SELECT 1 FROM grund_invitations i JOIN grund_account_emails e \
                    ON e.email_normalized = i.email_normalized \
                  JOIN grund_accounts a ON a.account_id = e.account_id \
                  WHERE i.invitation_id = n.source_id AND i.organisation_id = n.organisation_id \
                    AND a.account_id = $1 AND EXISTS (SELECT 1 FROM grund_organisations o \
                      WHERE o.organisation_id = i.organisation_id AND o.deleted_at IS NULL) \
                    AND a.email_verified_at IS NOT NULL AND i.accepted_at IS NULL \
                    AND i.withdrawn_at IS NULL AND i.expires_at > clock_timestamp())))",
    )
    .bind(account_id)
    .bind(id)
    .bind(organisation_scope)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Marks only currently visible unread rows, never rows outside the bound account/org.
pub async fn mark_all(
    executor: impl PgExecutor<'_>,
    account_id: Uuid,
    organisation_scope: Option<Uuid>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_notifications n SET read_at = clock_timestamp() \
         WHERE n.account_id = $1 AND n.read_at IS NULL \
           AND n.created_at > clock_timestamp() - interval '90 days' \
           AND ($2::uuid IS NULL OR n.organisation_id = $2) \
           AND (n.organisation_id IS NULL OR EXISTS (SELECT 1 FROM grund_memberships m \
                WHERE m.account_id = $1 AND m.organisation_id = n.organisation_id) \
                OR (n.kind = 'invitation.received' AND EXISTS ( \
                  SELECT 1 FROM grund_invitations i JOIN grund_account_emails e \
                    ON e.email_normalized = i.email_normalized \
                  JOIN grund_accounts a ON a.account_id = e.account_id \
                  WHERE i.invitation_id = n.source_id AND i.organisation_id = n.organisation_id \
                    AND a.account_id = $1 AND EXISTS (SELECT 1 FROM grund_organisations o \
                      WHERE o.organisation_id = i.organisation_id AND o.deleted_at IS NULL) \
                    AND a.email_verified_at IS NOT NULL AND i.accepted_at IS NULL \
                    AND i.withdrawn_at IS NULL AND i.expires_at > clock_timestamp())))",
    )
    .bind(account_id)
    .bind(organisation_scope)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Deletes at most 1000 old inbox rows and 1000 old source keys per pass.
pub async fn sweep(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query(
        "WITH expired AS (SELECT account_id, id FROM grund_notifications \
             WHERE created_at <= clock_timestamp() - interval '90 days' \
             ORDER BY created_at, account_id, id LIMIT 1000 FOR UPDATE SKIP LOCKED) \
         DELETE FROM grund_notifications n USING expired e \
         WHERE n.account_id = e.account_id AND n.id = e.id",
    )
    .execute(pool)
    .await?
    .rows_affected();
    let sources = sqlx::query(
        "WITH expired AS (SELECT account_id, source_kind, source_id FROM grund_notification_sources \
             WHERE created_at <= clock_timestamp() - interval '90 days' \
             ORDER BY created_at, account_id, source_id LIMIT 1000 FOR UPDATE SKIP LOCKED) \
         DELETE FROM grund_notification_sources s USING expired e \
         WHERE s.account_id = e.account_id AND s.source_kind = e.source_kind AND s.source_id = e.source_id",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(rows + sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn operator_repeats_collapse_once_without_crossing_audiences(pool: PgPool) {
        let operator_org = Uuid::now_v7();
        let outsider_org = Uuid::now_v7();
        let operator = Uuid::now_v7();
        let outsider = Uuid::now_v7();
        for (organisation_id, account_id) in [(operator_org, operator), (outsider_org, outsider)] {
            sqlx::query(
                "INSERT INTO grund_memberships \
                 (organisation_id, account_id, role, stream_version, joined_at) \
                 VALUES ($1, $2, 'member', 1, clock_timestamp())",
            )
            .bind(organisation_id)
            .bind(account_id)
            .execute(&pool)
            .await
            .unwrap();
        }
        let at = Utc::now();
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        for source in [first, second, first] {
            let mut tx = pool.begin().await.unwrap();
            emit_operator(
                &mut tx,
                operator_org,
                "operator.migration_timeout",
                source,
                "host-a",
                "/operator/pool",
                at,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let rows = list(&pool, operator, false, 10, None, None).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].repeat_count, 2);
        assert_eq!(count(&pool, operator, None).await.unwrap(), 1);
        assert!(
            list(&pool, outsider, false, 10, None, None)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(count(&pool, outsider, None).await.unwrap(), 0);
        assert!(
            list(&pool, operator, false, 10, None, Some(outsider_org))
                .await
                .unwrap()
                .is_empty()
        );
    }
}
