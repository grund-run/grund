//! Custom domains' read model (migration 0020; grund-docs
//! website/design/app-domains.md §3): the projection of the
//! `grund-custom-domain` streams, and the reads the service, the pages and
//! the route table make of it.

use chrono::{DateTime, Utc};
use grund_domain::custom_domain::{Domain, DomainEvent};
use mire::{HandledEvent, TransactionalEventHandler};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// Subscription id; bump the suffix to rebuild the read model.
pub const DOMAIN_SUBSCRIPTION: &str = "grund-custom-domain-read-model-v1";

/// Applies one custom-domain event at `version` to `grund_domains`.
pub async fn apply_domain(
    domain_id: Uuid,
    version: i64,
    event: &DomainEvent,
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    match event {
        DomainEvent::Added {
            organisation_id,
            name,
            token,
            added_by,
            added_at,
        } => {
            sqlx::query(
                "INSERT INTO grund_domains \
                   (domain_id, organisation_id, name, token, state, added_by, added_at, stream_version) \
                 VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7) \
                 ON CONFLICT (domain_id) DO NOTHING",
            )
            .bind(domain_id)
            .bind(organisation_id)
            .bind(name.as_str())
            .bind(token)
            .bind(added_by)
            .bind(added_at)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        DomainEvent::Verified { verified_at, .. } => {
            sqlx::query(
                "UPDATE grund_domains SET state = 'verified', verified_at = $2, check_error = NULL, \
                        stream_version = $3 \
                  WHERE domain_id = $1 AND stream_version < $3",
            )
            .bind(domain_id)
            .bind(verified_at)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        DomainEvent::Bound {
            app_id, bound_at, ..
        } => {
            sqlx::query(
                "UPDATE grund_domains SET state = 'bound', app_id = $2, bound_at = $3, stream_version = $4 \
                  WHERE domain_id = $1 AND stream_version < $4",
            )
            .bind(domain_id)
            .bind(app_id)
            .bind(bound_at)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        DomainEvent::Unbound { .. } => {
            sqlx::query(
                "UPDATE grund_domains SET state = 'verified', app_id = NULL, bound_at = NULL, \
                        stream_version = $2 \
                  WHERE domain_id = $1 AND stream_version < $2",
            )
            .bind(domain_id)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        DomainEvent::Removed { removed_at, .. } => {
            sqlx::query(
                "UPDATE grund_domains SET state = 'removed', app_id = NULL, removed_at = $2, \
                        stream_version = $3 \
                  WHERE domain_id = $1 AND stream_version < $3",
            )
            .bind(domain_id)
            .bind(removed_at)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        DomainEvent::AppDomainEnabled { .. } => {
            sqlx::query(
                "UPDATE grund_domains SET is_app_domain = true, stream_version = $2 \
                  WHERE domain_id = $1 AND stream_version < $2",
            )
            .bind(domain_id)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        DomainEvent::GeneratedFromParent {
            parent_domain_id,
            parent_domain,
            managed_app_id,
            ..
        } => {
            sqlx::query(
                "UPDATE grund_domains SET parent_domain_id = $2, parent_domain = $3, \
                        managed_app_id = $4, stream_version = $5 \
                  WHERE domain_id = $1 AND stream_version < $5",
            )
            .bind(domain_id)
            .bind(parent_domain_id)
            .bind(parent_domain.as_str())
            .bind(managed_app_id)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        DomainEvent::GeneratedReassigned {
            app_id,
            reassigned_at,
            ..
        } => {
            sqlx::query(
                "UPDATE grund_domains SET managed_app_id=$2, \
                 app_id=CASE WHEN state='bound' THEN $2 ELSE app_id END, \
                 bound_at=CASE WHEN state='bound' THEN $3 ELSE bound_at END,stream_version=$4 \
                 WHERE domain_id=$1 AND stream_version<$4",
            )
            .bind(domain_id)
            .bind(app_id)
            .bind(reassigned_at)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        DomainEvent::AppDomainAllocationSet { enabled, .. } => {
            sqlx::query(
                "UPDATE grund_domains SET assignment_disabled = $2, stream_version = $3 \
                  WHERE domain_id = $1 AND stream_version < $3",
            )
            .bind(domain_id)
            .bind(!enabled)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
    }
    Ok(())
}

/// The custom-domain read model, for a `mire::ProjectionRunner`.
pub struct DomainProjection;

impl TransactionalEventHandler for DomainProjection {
    type Aggregate = Domain;

    async fn handle(
        &self,
        event: HandledEvent<DomainEvent>,
        connection: &mut PgConnection,
    ) -> anyhow::Result<()> {
        let id = crate::projections::stream_uuid(
            event.stream_id(),
            grund_domain::custom_domain::CUSTOM_DOMAIN_CATEGORY,
        )?;
        apply_domain(id, event.stream_version(), &event.event, connection).await?;
        Ok(())
    }
}

/// One custom domain as the dashboard and the API show it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainRow {
    pub domain_id: Uuid,
    pub organisation_id: Uuid,
    pub name: String,
    pub token: String,
    pub state: String,
    pub app_id: Option<Uuid>,
    pub is_app_domain: bool,
    pub parent_domain_id: Option<Uuid>,
    pub parent_domain: Option<String>,
    pub managed_app_id: Option<Uuid>,
    pub managed_app_name: Option<String>,
    pub assignment_disabled: bool,
    /// The bound app's name, while it is live.
    pub app_name: Option<String>,
    pub added_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub bound_at: Option<DateTime<Utc>>,
    pub checked_at: Option<DateTime<Utc>>,
    pub check_error: Option<String>,
    /// The certificate's expiry, once one is issued.
    pub certificate_not_after: Option<DateTime<Utc>>,
    /// The certificate's last failure, a stable code.
    pub certificate_error: Option<String>,
    /// Whether a certificate is wanted for it (it is bound and this
    /// instance orders).
    pub certificate_wanted: bool,
    /// Persistent observations of the six setup boundaries.
    pub steps: sqlx::types::Json<Vec<crate::domain_setup::Step>>,
    /// Consecutive failed ACME attempts, reset after successful issuance.
    pub certificate_attempts: i32,
    /// When the certificate worker may next attempt this subject.
    pub certificate_next_attempt_at: Option<DateTime<Utc>>,
}

macro_rules! select_rows {
    ($where:literal) => {
        concat!(
            "SELECT d.domain_id, d.organisation_id, d.name, d.token, d.state, d.app_id, \
            d.is_app_domain, d.parent_domain_id, d.parent_domain, d.managed_app_id, d.assignment_disabled, \
            managed.name AS managed_app_name, \
            a.name AS app_name, d.added_at, d.verified_at, d.bound_at, d.checked_at, d.check_error, \
            c.not_after AS certificate_not_after, c.last_error AS certificate_error, \
            (c.subject IS NOT NULL) AS certificate_wanted, \
            coalesce(s.steps, grund_domain_setup_waiting()) AS steps, \
            coalesce(c.attempts, 0) AS certificate_attempts, \
            CASE WHEN c.subject IS NULL OR d.state <> 'bound' THEN NULL \
                 WHEN c.chain_pem IS NULL THEN c.next_attempt_at \
                 WHEN c.renew_at IS NULL AND c.ari_check_at IS NULL THEN NULL \
                 ELSE greatest(c.next_attempt_at, least(c.renew_at, c.ari_check_at)) END \
                AS certificate_next_attempt_at \
       FROM grund_domains d \
       LEFT JOIN grund_apps a ON a.app_id = d.app_id AND a.deleted_at IS NULL \
       LEFT JOIN grund_apps managed ON managed.app_id = d.managed_app_id AND managed.deleted_at IS NULL \
       LEFT JOIN grund_certificates c ON c.subject = 'domain:' || d.domain_id::text \
       LEFT JOIN grund_domain_setup s ON s.domain_id = d.domain_id ",
            $where
        )
    };
}

/// The organisation's domains that are not removed, by name.
pub async fn list(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Vec<DomainRow>, sqlx::Error> {
    sqlx::query_as(select_rows!(
        "WHERE d.organisation_id = $1 AND d.state <> 'removed' ORDER BY d.name"
    ))
    .bind(organisation_id)
    .fetch_all(executor)
    .await
}

/// The organisation's domain `name`, if it has not removed it.
pub async fn by_name(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    name: &str,
) -> Result<Option<DomainRow>, sqlx::Error> {
    sqlx::query_as(select_rows!(
        "WHERE d.organisation_id = $1 AND d.name = $2 AND d.state <> 'removed'"
    ))
    .bind(organisation_id)
    .bind(name)
    .fetch_optional(executor)
    .await
}

/// Serializes hierarchy decisions across organisations for this transaction.
pub async fn lock_hierarchy_policy(executor: impl PgExecutor<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('grund-domain-hierarchy-policy', 0))",
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// The organisation's live enabled parent, if configured.
pub async fn configured_parent(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<Option<DomainRow>, sqlx::Error> {
    sqlx::query_as(select_rows!(
        "WHERE d.organisation_id = $1 AND d.is_app_domain AND d.state <> 'removed'"
    ))
    .bind(organisation_id)
    .fetch_optional(executor)
    .await
}

/// The app's latest managed assignment, preferring live rows over removed history.
pub async fn managed_assignment(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    app_id: Uuid,
) -> Result<Option<DomainRow>, sqlx::Error> {
    sqlx::query_as(select_rows!(
        "WHERE d.organisation_id = $1 AND d.managed_app_id = $2 \
         ORDER BY (d.state <> 'removed') DESC, d.added_at DESC, d.domain_id DESC LIMIT 1"
    ))
    .bind(organisation_id)
    .bind(app_id)
    .fetch_optional(executor)
    .await
}

/// Whether the organisation's parent still has any live generated children.
pub async fn has_live_children(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    parent_domain_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_domains \
          WHERE organisation_id = $1 AND parent_domain_id = $2 AND state <> 'removed')",
    )
    .bind(organisation_id)
    .bind(parent_domain_id)
    .fetch_one(executor)
    .await
}

/// Whether a foreign claimed namespace contains the name, or a foreign verified
/// descendant would fall inside a proposed parent namespace.
pub async fn foreign_namespace_overlap(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
    name: &str,
    include_descendants: bool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_domains \
          WHERE organisation_id <> $1 AND state IN ('verified', 'bound') \
            AND ((is_app_domain AND ($2 = name OR right($2, length(name) + 1) = '.' || name)) \
              OR ($3 AND (name = $2 OR right(name, length($2) + 1) = '.' || $2))))",
    )
    .bind(organisation_id)
    .bind(name)
    .bind(include_descendants)
    .fetch_one(executor)
    .await
}

/// The domains bound to an app, by name.
pub async fn bound_to(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Vec<DomainRow>, sqlx::Error> {
    sqlx::query_as(select_rows!(
        "WHERE d.app_id = $1 AND d.state = 'bound' ORDER BY d.name"
    ))
    .bind(app_id)
    .fetch_all(executor)
    .await
}

/// The organisation that holds `name` verified or bound, if any.
pub async fn holder(
    executor: impl PgExecutor<'_>,
    name: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT organisation_id FROM grund_domains WHERE name = $1 AND state IN ('verified', 'bound')",
    )
    .bind(name)
    .fetch_optional(executor)
    .await
}

/// When the cool-down on `name` ends for an organisation other than
/// `organisation_id`: the latest release of the name by another
/// organisation after it was verified, plus `cooldown_seconds`, if that is
/// still ahead.
pub async fn cooling_until(
    executor: impl PgExecutor<'_>,
    name: &str,
    organisation_id: Uuid,
    cooldown_seconds: f64,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT max(removed_at) + make_interval(secs => $3) FROM grund_domains \
          WHERE name = $1 AND state = 'removed' AND verified_at IS NOT NULL \
            AND organisation_id <> $2 \
         HAVING max(removed_at) + make_interval(secs => $3) > clock_timestamp()",
    )
    .bind(name)
    .bind(organisation_id)
    .bind(cooldown_seconds)
    .fetch_optional(executor)
    .await
}

/// How many ordinary custom domains the organisation has that are not removed.
pub async fn count_live(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_domains \
          WHERE organisation_id = $1 AND state <> 'removed' AND parent_domain_id IS NULL",
    )
    .bind(organisation_id)
    .fetch_one(executor)
    .await
}

/// How many ordinary custom domains the organisation added in the last day,
/// removed ones included.
pub async fn added_today(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_domains \
          WHERE organisation_id = $1 AND parent_domain_id IS NULL \
            AND added_at > clock_timestamp() - interval '1 day'",
    )
    .bind(organisation_id)
    .fetch_one(executor)
    .await
}

/// How many domains are bound to the app.
pub async fn count_bound(executor: impl PgExecutor<'_>, app_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM grund_domains WHERE app_id = $1 AND state = 'bound'")
        .bind(app_id)
        .fetch_one(executor)
        .await
}

/// Records a verification check that did not find the token.
pub async fn record_check(
    executor: impl PgExecutor<'_>,
    domain_id: Uuid,
    error: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_domains SET checked_at = clock_timestamp(), check_error = $2 WHERE domain_id = $1",
    )
    .bind(domain_id)
    .bind(error)
    .execute(executor)
    .await?;
    Ok(())
}

/// A bound domain as the route table and the signed documents need it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct BoundName {
    pub domain_id: Uuid,
    pub name: String,
    pub app_id: Uuid,
}

/// Every bound domain of a live app, by name.
pub async fn bound_names(executor: impl PgExecutor<'_>) -> Result<Vec<BoundName>, sqlx::Error> {
    sqlx::query_as(
        "SELECT d.domain_id, d.name, d.app_id FROM grund_domains d \
           JOIN grund_apps a ON a.app_id = d.app_id AND a.deleted_at IS NULL \
          WHERE d.state = 'bound' ORDER BY d.name",
    )
    .fetch_all(executor)
    .await
}

/// The bound domain `name` of a live app, if there is one.
pub async fn bound_name(
    executor: impl PgExecutor<'_>,
    name: &str,
) -> Result<Option<BoundName>, sqlx::Error> {
    sqlx::query_as(
        "SELECT d.domain_id, d.name, d.app_id FROM grund_domains d \
           JOIN grund_apps a ON a.app_id = d.app_id AND a.deleted_at IS NULL \
          WHERE d.state = 'bound' AND d.name = $1",
    )
    .bind(name)
    .fetch_optional(executor)
    .await
}

/// The domains bound to the app, of every machine's document.
pub async fn names_of_app(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT name FROM grund_domains WHERE app_id = $1 AND state = 'bound' ORDER BY name",
    )
    .bind(app_id)
    .fetch_all(executor)
    .await
}

/// The first verified bound hostname of an app, for the app list's public link.
pub async fn first_bound_name(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT name FROM grund_domains WHERE app_id = $1 AND state = 'bound' ORDER BY name LIMIT 1",
    )
    .bind(app_id)
    .fetch_optional(executor)
    .await
}

/// The spec of the app's current release, or of its newest while none is
/// live yet.
pub async fn current_spec(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Option<sqlx::types::Json<grund_config::app::spec::AppSpec>>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT r.spec FROM grund_apps a JOIN grund_releases r ON r.app_id = a.app_id \
          WHERE a.app_id = $1 AND a.deleted_at IS NULL \
          ORDER BY (r.number = a.current_release) IS TRUE DESC, r.number DESC LIMIT 1",
    )
    .bind(app_id)
    .fetch_optional(executor)
    .await
}

/// The certificate's subject for a custom domain.
pub fn certificate_subject(domain_id: Uuid) -> String {
    format!("domain:{domain_id}")
}

/// Wants a certificate for a bound domain: the organisation's, its key
/// made and sealed by the instance, validated by HTTP-01 at the edges.
/// Nothing changes when one is already wanted for the same name.
pub async fn want_certificate(
    executor: impl PgExecutor<'_>,
    domain_id: Uuid,
    organisation_id: Uuid,
    name: &str,
    directory: &str,
    profile: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_certificates (subject, names, directory, profile, challenge, owner, terminator) \
         VALUES ($1, ARRAY[$2], $3, $4, 'http-01', $5, 'instance') \
         ON CONFLICT (subject) DO NOTHING",
    )
    .bind(certificate_subject(domain_id))
    .bind(name)
    .bind(directory)
    .bind(profile)
    .bind(format!("organisation:{organisation_id}"))
    .execute(executor)
    .await?;
    Ok(())
}

/// Drops a custom domain's certificate, its orders and its challenges:
/// it is no longer bound. Revoking it at the CA is not built.
pub async fn drop_certificate(
    connection: &mut PgConnection,
    domain_id: Uuid,
) -> Result<(), sqlx::Error> {
    let subject = certificate_subject(domain_id);
    sqlx::query("DELETE FROM grund_acme_challenges WHERE subject = $1")
        .bind(&subject)
        .execute(&mut *connection)
        .await?;
    sqlx::query("DELETE FROM grund_certificates WHERE subject = $1")
        .bind(&subject)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

/// A custom domain's issued certificate, its key still sealed.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainCertificate {
    pub chain_pem: String,
    pub sealed_key: Vec<u8>,
    pub version: i64,
}

/// The issued certificate of the bound domain `domain_id`, if any.
pub async fn certificate(
    executor: impl PgExecutor<'_>,
    domain_id: Uuid,
) -> Result<Option<DomainCertificate>, sqlx::Error> {
    sqlx::query_as(
        "SELECT chain_pem, sealed_key, version FROM grund_certificates \
          WHERE subject = $1 AND chain_pem IS NOT NULL AND sealed_key IS NOT NULL",
    )
    .bind(certificate_subject(domain_id))
    .fetch_optional(executor)
    .await
}

#[cfg(test)]
mod tests {
    use grund_config::app::spec::{AppName, AppSettings};
    use grund_domain::{
        app::AppCommand,
        custom_domain::{DomainCommand, DomainName},
    };
    use mire::EventStore;
    use sqlx::PgPool;

    use super::*;
    use crate::work::Work;

    async fn event_store(pool: &PgPool) -> EventStore {
        crate::migrate(pool).await.unwrap();
        EventStore::new(pool.clone())
    }

    async fn parent(events: &EventStore, organisation_id: Uuid, name: &str) -> Uuid {
        let domain_id = Uuid::now_v7();
        let mut work = Work::begin(events, Uuid::now_v7(), "test").await.unwrap();
        lock_hierarchy_policy(&mut **work.sql()).await.unwrap();
        for command in [
            DomainCommand::Add {
                actor: Uuid::nil(),
                organisation_id,
                name: DomainName::parse(name).unwrap(),
                token: format!("grund-verify-{}", "a".repeat(43)),
                at: Utc::now(),
            },
            DomainCommand::Verify {
                actor: Uuid::nil(),
                at: Utc::now(),
            },
            DomainCommand::EnableAppDomain {
                actor: Uuid::nil(),
                at: Utc::now(),
            },
        ] {
            work.domain(domain_id, command).await.unwrap();
        }
        work.commit().await.unwrap();
        domain_id
    }

    async fn generation(
        work: &mut Work<'_>,
        organisation_id: Uuid,
        parent_domain_id: Uuid,
        app_id: Uuid,
        name: &str,
    ) -> DomainCommand {
        let authority = work
            .load_domain(parent_domain_id)
            .await
            .unwrap()
            .app_domain_authority(parent_domain_id)
            .unwrap();
        DomainCommand::Generate {
            actor: Uuid::nil(),
            organisation_id,
            name: DomainName::parse(name).unwrap(),
            token: format!("grund-verify-{}", "b".repeat(43)),
            authority,
            app_id,
            at: Utc::now(),
        }
    }

    async fn generated(
        events: &EventStore,
        organisation_id: Uuid,
        parent_domain_id: Uuid,
        app_id: Uuid,
        name: &str,
    ) -> Uuid {
        let domain_id = Uuid::now_v7();
        let mut work = Work::begin(events, Uuid::now_v7(), "test").await.unwrap();
        lock_hierarchy_policy(&mut **work.sql()).await.unwrap();
        let command = generation(&mut work, organisation_id, parent_domain_id, app_id, name).await;
        work.domain(domain_id, command).await.unwrap();
        work.commit().await.unwrap();
        domain_id
    }

    #[sqlx::test(migrations = false)]
    async fn public_child_reassignment_keeps_the_real_hostname_authority_and_certificate(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let events = event_store(&pool).await;
        let (org, old_app, new_app) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let parent = parent(&events, org, "apps.example.com").await;
        let child = generated(&events, org, parent, old_app, "shop.apps.example.com").await;
        want_certificate(
            &pool,
            child,
            org,
            "shop.apps.example.com",
            "https://ca.invalid/directory",
            "test-profile",
        )
        .await?;
        let before = by_name(&pool, org, "shop.apps.example.com").await?.unwrap();
        let certificate: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(c) FROM grund_certificates c WHERE subject=$1")
                .bind(certificate_subject(child))
                .fetch_one(&pool)
                .await?;
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await?;
        work.domain(
            child,
            DomainCommand::ReassignGenerated {
                actor: Uuid::nil(),
                expected_app_id: old_app,
                app_id: new_app,
                at: Utc::now(),
            },
        )
        .await?;
        work.commit().await?;
        let after = by_name(&pool, org, "shop.apps.example.com").await?.unwrap();
        assert_eq!(after.domain_id, child);
        assert_eq!(after.managed_app_id, Some(new_app));
        assert_eq!(after.app_id, Some(new_app));
        assert_eq!(after.name, before.name);
        assert_eq!(after.token, before.token);
        assert_eq!(after.parent_domain_id, before.parent_domain_id);
        assert_eq!(after.parent_domain, before.parent_domain);
        assert_eq!(after.verified_at, before.verified_at);
        assert_eq!(after.assignment_disabled, before.assignment_disabled);
        let retained: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(c) FROM grund_certificates c WHERE subject=$1")
                .bind(certificate_subject(child))
                .fetch_one(&pool)
                .await?;
        assert_eq!(retained, certificate);
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn foreign_namespaces_use_dns_label_boundaries_and_verified_live_ownership(pool: PgPool) {
        let events = event_store(&pool).await;
        let (owner, foreign) = (Uuid::now_v7(), Uuid::now_v7());
        let namespace = parent(&events, foreign, "apps.example.com").await;
        for name in [
            "apps.example.com",
            "shop.apps.example.com",
            "a.b.apps.example.com",
        ] {
            assert!(
                foreign_namespace_overlap(&pool, owner, name, false)
                    .await
                    .unwrap()
            );
            assert!(
                !foreign_namespace_overlap(&pool, foreign, name, true)
                    .await
                    .unwrap()
            );
        }
        for name in [
            "notapps.example.com",
            "apps.example.com.other.net",
            "example.com",
        ] {
            assert!(
                !foreign_namespace_overlap(&pool, owner, name, false)
                    .await
                    .unwrap()
            );
        }
        assert!(
            foreign_namespace_overlap(&pool, owner, "example.com", true)
                .await
                .unwrap()
        );
        let exact = add(&pool, foreign, "api.other.example.com", 1).await;
        assert!(
            !foreign_namespace_overlap(&pool, owner, "other.example.com", true)
                .await
                .unwrap()
        );
        apply(&pool, exact, 2, verified()).await;
        assert!(
            foreign_namespace_overlap(&pool, owner, "other.example.com", true)
                .await
                .unwrap()
        );
        assert!(
            !foreign_namespace_overlap(&pool, owner, "other.example.com", false)
                .await
                .unwrap()
        );
        assert!(
            !foreign_namespace_overlap(&pool, owner, "x.api.other.example.com", false)
                .await
                .unwrap()
        );
        apply(
            &pool,
            namespace,
            4,
            DomainEvent::Bound {
                app_id: Uuid::now_v7(),
                bound_by: Uuid::nil(),
                bound_at: Utc::now(),
            },
        )
        .await;
        assert!(
            foreign_namespace_overlap(&pool, owner, "shop.apps.example.com", false)
                .await
                .unwrap()
        );
        for domain in [namespace, exact] {
            apply(
                &pool,
                domain,
                5,
                DomainEvent::Removed {
                    removed_by: Uuid::nil(),
                    removed_at: Utc::now(),
                },
            )
            .await;
        }
        assert!(
            !foreign_namespace_overlap(&pool, owner, "example.com", true)
                .await
                .unwrap()
        );
    }

    #[sqlx::test(migrations = false)]
    async fn one_live_parent_per_organisation_is_enforced_by_the_database(pool: PgPool) {
        let events = event_store(&pool).await;
        let organisation = Uuid::now_v7();
        let first = parent(&events, organisation, "apps.example.com").await;
        let second = add(&pool, organisation, "other.example.com", 1).await;
        apply(&pool, second, 2, verified()).await;
        let mut connection = pool.acquire().await.unwrap();
        let refused = apply_domain(
            second,
            3,
            &DomainEvent::AppDomainEnabled {
                enabled_by: Uuid::nil(),
                enabled_at: Utc::now(),
            },
            &mut connection,
        )
        .await
        .unwrap_err();
        assert_eq!(
            refused
                .as_database_error()
                .and_then(|error| error.constraint()),
            Some("grund_domains_app_domain_idx")
        );
        drop(connection);
        assert_eq!(
            configured_parent(&pool, organisation)
                .await
                .unwrap()
                .unwrap()
                .domain_id,
            first
        );
        assert!(
            configured_parent(&pool, Uuid::now_v7())
                .await
                .unwrap()
                .is_none()
        );
        apply(
            &pool,
            first,
            4,
            DomainEvent::Removed {
                removed_by: Uuid::nil(),
                removed_at: Utc::now(),
            },
        )
        .await;
        apply(
            &pool,
            second,
            3,
            DomainEvent::AppDomainEnabled {
                enabled_by: Uuid::nil(),
                enabled_at: Utc::now(),
            },
        )
        .await;
        assert_eq!(
            configured_parent(&pool, organisation)
                .await
                .unwrap()
                .unwrap()
                .domain_id,
            second
        );
    }

    #[sqlx::test(migrations = false)]
    async fn a_managed_app_has_one_live_assignment_and_cannot_bind_it_to_another_app(pool: PgPool) {
        let events = event_store(&pool).await;
        let (organisation, app) = (Uuid::now_v7(), Uuid::now_v7());
        let parent_id = parent(&events, organisation, "apps.example.com").await;
        let child = generated(
            &events,
            organisation,
            parent_id,
            app,
            "shop.apps.example.com",
        )
        .await;
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
        lock_hierarchy_policy(&mut **work.sql()).await.unwrap();
        let command = generation(
            &mut work,
            organisation,
            parent_id,
            app,
            "other.apps.example.com",
        )
        .await;
        let refused = work.domain(Uuid::now_v7(), command).await.unwrap_err();
        assert_eq!(
            refused.unique_violation().as_deref(),
            Some("grund_domains_managed_assignment_idx")
        );
        drop(work);
        let refused = sqlx::query("UPDATE grund_domains SET app_id = $2 WHERE domain_id = $1")
            .bind(child)
            .bind(Uuid::now_v7())
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(
            refused
                .as_database_error()
                .and_then(|error| error.constraint()),
            Some("grund_domains_managed_binding_check")
        );
        let refused =
            sqlx::query("UPDATE grund_domains SET parent_domain = NULL WHERE domain_id = $1")
                .bind(child)
                .execute(&pool)
                .await
                .unwrap_err();
        assert_eq!(
            refused
                .as_database_error()
                .and_then(|error| error.constraint()),
            Some("grund_domains_provenance_check")
        );
        assert!(
            has_live_children(&pool, organisation, parent_id)
                .await
                .unwrap()
        );
        assert!(
            !has_live_children(&pool, Uuid::now_v7(), parent_id)
                .await
                .unwrap()
        );
        assert_eq!(count_live(&pool, organisation).await.unwrap(), 1);
        assert_eq!(added_today(&pool, organisation).await.unwrap(), 1);
        apply(
            &pool,
            child,
            2,
            DomainEvent::GeneratedFromParent {
                parent_domain_id: Uuid::now_v7(),
                parent_domain: DomainName::parse("other.example.com").unwrap(),
                managed_app_id: Uuid::now_v7(),
                parent_verified_at: Utc::now(),
                generated_by: Uuid::nil(),
                generated_at: Utc::now(),
            },
        )
        .await;
        let row = managed_assignment(&pool, organisation, app)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.parent_domain_id, Some(parent_id));
        assert_eq!(row.parent_domain.as_deref(), Some("apps.example.com"));
        assert_eq!(row.managed_app_id, Some(app));
    }

    #[sqlx::test(migrations = false)]
    async fn explicit_opt_out_and_parent_provenance_survive_unbinding_removal_and_replay(
        pool: PgPool,
    ) {
        let events = event_store(&pool).await;
        let (organisation, app) = (Uuid::now_v7(), Uuid::now_v7());
        let parent_id = parent(&events, organisation, "apps.example.com").await;
        let child = generated(
            &events,
            organisation,
            parent_id,
            app,
            "shop.apps.example.com",
        )
        .await;
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
        work.app(
            app,
            AppCommand::Create {
                actor: Uuid::nil(),
                organisation_id: organisation,
                name: AppName::parse("shop").unwrap(),
                settings: AppSettings::default(),
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        work.domain(
            child,
            DomainCommand::Unbind {
                actor: Uuid::nil(),
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        work.commit().await.unwrap();
        let row = managed_assignment(&pool, organisation, app)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "verified");
        assert!(row.assignment_disabled);
        assert_eq!(row.app_name, None);
        assert_eq!(row.managed_app_name.as_deref(), Some("shop"));
        assert_eq!(row.parent_domain_id, Some(parent_id));
        assert_eq!(row.parent_domain.as_deref(), Some("apps.example.com"));
        assert_eq!(row.managed_app_id, Some(app));
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
        work.domain(
            child,
            DomainCommand::Bind {
                actor: Uuid::nil(),
                app_id: app,
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        work.domain(
            child,
            DomainCommand::UnbindForAppDeletion {
                actor: Uuid::nil(),
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        work.commit().await.unwrap();
        assert!(
            !managed_assignment(&pool, organisation, app)
                .await
                .unwrap()
                .unwrap()
                .assignment_disabled
        );
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
        work.domain(
            child,
            DomainCommand::Remove {
                actor: Uuid::nil(),
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        work.commit().await.unwrap();
        apply(
            &pool,
            child,
            3,
            DomainEvent::AppDomainAllocationSet {
                enabled: true,
                changed_by: Uuid::nil(),
                changed_at: Utc::now(),
            },
        )
        .await;
        let row = managed_assignment(&pool, organisation, app)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "removed");
        assert!(row.assignment_disabled);
        assert_eq!(row.parent_domain_id, Some(parent_id));
        assert_eq!(row.managed_app_id, Some(app));
        assert!(
            !has_live_children(&pool, organisation, parent_id)
                .await
                .unwrap()
        );
        assert!(
            managed_assignment(&pool, Uuid::now_v7(), app)
                .await
                .unwrap()
                .is_none()
        );
        let replacement = generated(
            &events,
            organisation,
            parent_id,
            app,
            "new.apps.example.com",
        )
        .await;
        sqlx::query("UPDATE grund_domains SET added_at = clock_timestamp() + interval '1 day' WHERE domain_id = $1")
            .bind(child)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            managed_assignment(&pool, organisation, app)
                .await
                .unwrap()
                .unwrap()
                .domain_id,
            replacement
        );
        assert_eq!(added_today(&pool, organisation).await.unwrap(), 1);
    }

    #[sqlx::test(migrations = false)]
    async fn a_failed_hostname_rename_rolls_back_the_old_binding_and_all_new_events(pool: PgPool) {
        let events = event_store(&pool).await;
        let (organisation, app) = (Uuid::now_v7(), Uuid::now_v7());
        let parent_id = parent(&events, organisation, "apps.example.com").await;
        let old = generated(
            &events,
            organisation,
            parent_id,
            app,
            "shop.apps.example.com",
        )
        .await;
        let occupied = add(&pool, Uuid::now_v7(), "taken.apps.example.com", 1).await;
        apply(&pool, occupied, 2, verified()).await;
        let new = Uuid::now_v7();
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
        lock_hierarchy_policy(&mut **work.sql()).await.unwrap();
        work.domain(
            old,
            DomainCommand::Remove {
                actor: Uuid::nil(),
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        let command = generation(
            &mut work,
            organisation,
            parent_id,
            app,
            "taken.apps.example.com",
        )
        .await;
        let refused = work.domain(new, command).await.unwrap_err();
        assert_eq!(
            refused.unique_violation().as_deref(),
            Some("grund_domains_claimed_idx")
        );
        drop(work);
        let row = managed_assignment(&pool, organisation, app)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.domain_id, old);
        assert_eq!(row.state, "bound");
        assert_eq!(row.name, "shop.apps.example.com");
        assert!(!row.assignment_disabled);
        assert!(
            by_name(&pool, organisation, "taken.apps.example.com")
                .await
                .unwrap()
                .is_none()
        );
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
        let old_state = work.load_domain(old).await.unwrap();
        assert_eq!(old_state.app_id, Some(app));
        assert!(!old_state.removed);
        assert!(!work.load_domain(new).await.unwrap().exists);
    }

    #[sqlx::test(migrations = false)]
    async fn a_default_hostname_collision_rolls_back_app_creation_and_generated_allocation(
        pool: PgPool,
    ) {
        let events = event_store(&pool).await;
        let organisation = Uuid::now_v7();
        let parent_id = parent(&events, organisation, "apps.example.com").await;
        let occupied = add(&pool, Uuid::now_v7(), "shop.apps.example.com", 1).await;
        apply(&pool, occupied, 2, verified()).await;
        let (app, child) = (Uuid::now_v7(), Uuid::now_v7());
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
        lock_hierarchy_policy(&mut **work.sql()).await.unwrap();
        work.app(
            app,
            AppCommand::Create {
                actor: Uuid::nil(),
                organisation_id: organisation,
                name: AppName::parse("shop").unwrap(),
                settings: AppSettings::default(),
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        let command = generation(
            &mut work,
            organisation,
            parent_id,
            app,
            "shop.apps.example.com",
        )
        .await;
        let refused = work.domain(child, command).await.unwrap_err();
        assert_eq!(
            refused.unique_violation().as_deref(),
            Some("grund_domains_claimed_idx")
        );
        drop(work);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_apps WHERE app_id = $1")
            .bind(app)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert!(
            managed_assignment(&pool, organisation, app)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !has_live_children(&pool, organisation, parent_id)
                .await
                .unwrap()
        );
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
        assert!(!work.load_app(app).await.unwrap().exists);
        assert!(!work.load_domain(child).await.unwrap().exists);
    }

    async fn add(pool: &PgPool, organisation_id: Uuid, name: &str, version: i64) -> Uuid {
        let domain_id = Uuid::now_v7();
        let mut connection = pool.acquire().await.unwrap();
        apply_domain(
            domain_id,
            version,
            &DomainEvent::Added {
                organisation_id,
                name: DomainName::parse(name).unwrap(),
                token: format!("grund-verify-{}", "a".repeat(43)),
                added_by: Uuid::nil(),
                added_at: Utc::now(),
            },
            &mut connection,
        )
        .await
        .unwrap();
        domain_id
    }

    async fn apply(pool: &PgPool, domain_id: Uuid, version: i64, event: DomainEvent) {
        let mut connection = pool.acquire().await.unwrap();
        apply_domain(domain_id, version, &event, &mut connection)
            .await
            .unwrap();
    }

    fn verified() -> DomainEvent {
        DomainEvent::Verified {
            verified_by: Uuid::nil(),
            verified_at: Utc::now(),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_name_is_verified_by_one_organisation_at_a_time(pool: PgPool) {
        let (first, second) = (Uuid::now_v7(), Uuid::now_v7());
        let mine = add(&pool, first, "app.example.com", 1).await;
        let theirs = add(&pool, second, "app.example.com", 1).await;
        apply(&pool, mine, 2, verified()).await;
        let mut connection = pool.acquire().await.unwrap();
        let refused = apply_domain(theirs, 2, &verified(), &mut connection).await;
        assert_eq!(
            refused
                .unwrap_err()
                .as_database_error()
                .and_then(|e| e.constraint().map(str::to_string))
                .as_deref(),
            Some("grund_domains_claimed_idx")
        );
        assert_eq!(holder(&pool, "app.example.com").await.unwrap(), Some(first));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_released_name_cools_down_for_other_organisations_only(pool: PgPool) {
        let (first, second) = (Uuid::now_v7(), Uuid::now_v7());
        let mine = add(&pool, first, "app.example.com", 1).await;
        apply(&pool, mine, 2, verified()).await;
        apply(
            &pool,
            mine,
            3,
            DomainEvent::Removed {
                removed_by: Uuid::nil(),
                removed_at: Utc::now(),
            },
        )
        .await;
        assert!(
            cooling_until(&pool, "app.example.com", second, 3600.0)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            cooling_until(&pool, "app.example.com", first, 3600.0)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            cooling_until(&pool, "app.example.com", second, 0.0)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(holder(&pool, "app.example.com").await.unwrap(), None);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_replayed_event_changes_nothing(pool: PgPool) {
        let organisation = Uuid::now_v7();
        let domain = add(&pool, organisation, "app.example.com", 1).await;
        apply(&pool, domain, 2, verified()).await;
        apply(
            &pool,
            domain,
            3,
            DomainEvent::Removed {
                removed_by: Uuid::nil(),
                removed_at: Utc::now(),
            },
        )
        .await;
        apply(&pool, domain, 2, verified()).await;
        assert!(list(&pool, organisation).await.unwrap().is_empty());
    }
}
