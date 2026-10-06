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
}

macro_rules! select_rows {
    ($where:literal) => {
        concat!(
            "SELECT d.domain_id, d.organisation_id, d.name, d.token, d.state, d.app_id, \
            a.name AS app_name, d.added_at, d.verified_at, d.bound_at, d.checked_at, d.check_error, \
            c.not_after AS certificate_not_after, c.last_error AS certificate_error, \
            (c.subject IS NOT NULL) AS certificate_wanted \
       FROM grund_domains d \
       LEFT JOIN grund_apps a ON a.app_id = d.app_id AND a.deleted_at IS NULL \
       LEFT JOIN grund_certificates c ON c.subject = 'domain:' || d.domain_id::text ",
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

/// How many domains the organisation has that are not removed.
pub async fn count_live(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_domains WHERE organisation_id = $1 AND state <> 'removed'",
    )
    .bind(organisation_id)
    .fetch_one(executor)
    .await
}

/// How many domains the organisation added in the last day, removed ones
/// included.
pub async fn added_today(
    executor: impl PgExecutor<'_>,
    organisation_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM grund_domains \
          WHERE organisation_id = $1 AND added_at > clock_timestamp() - interval '1 day'",
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

/// The spec of the app's current release, or of its newest while none is
/// live yet.
pub async fn current_spec(
    executor: impl PgExecutor<'_>,
    app_id: Uuid,
) -> Result<Option<sqlx::types::Json<grund_domain::app::AppSpec>>, sqlx::Error> {
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
    use grund_domain::custom_domain::DomainName;
    use sqlx::PgPool;

    use super::*;

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
