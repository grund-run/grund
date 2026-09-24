//! The read models of the account and organisation streams.
//!
//! Each `apply_*` function is the single definition of what an event means for
//! the read model. The write path ([`crate::work::Work`]) calls it inside the
//! transaction that records the event; [`Projections`] calls it again from a
//! `mire::ProjectionRunner` for catch-up and rebuilds. Every statement is
//! guarded by `stream_version`, so an older event never moves a row back and
//! a replay changes nothing.

use grund_domain::{
    account::{Account, AccountEvent},
    organisation::{Organisation, OrganisationEvent},
};
use mire::{HandledEvent, TransactionalEventHandler};
use sqlx::PgConnection;
use uuid::Uuid;

/// Subscription ids; bump the suffix to rebuild a read model from scratch.
pub const ACCOUNT_SUBSCRIPTION: &str = "grund-account-read-model-v1";
pub const ORGANISATION_SUBSCRIPTION: &str = "grund-organisation-read-model-v1";

/// Applies one account event at `version` to `grund_accounts`.
pub async fn apply_account(
    account_id: Uuid,
    version: i64,
    event: &AccountEvent,
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    match event {
        AccountEvent::Registered {
            username,
            organisation_id,
            registered_at,
            ..
        } => {
            sqlx::query(
                "INSERT INTO grund_accounts \
                   (account_id, username, organisation_id, registered_at, stream_version) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (account_id) DO UPDATE SET \
                   username = EXCLUDED.username, organisation_id = EXCLUDED.organisation_id, \
                   registered_at = EXCLUDED.registered_at, stream_version = EXCLUDED.stream_version \
                 WHERE grund_accounts.stream_version < EXCLUDED.stream_version",
            )
            .bind(account_id)
            .bind(username.as_str())
            .bind(organisation_id)
            .bind(registered_at)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        AccountEvent::EmailVerified { verified_at, .. } => {
            sqlx::query(
                "UPDATE grund_accounts SET email_verified_at = $2, stream_version = $3 \
                 WHERE account_id = $1 AND stream_version < $3",
            )
            .bind(account_id)
            .bind(verified_at)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        AccountEvent::PasswordChanged { .. } | AccountEvent::IdentityLinked { .. } => {
            sqlx::query(
                "UPDATE grund_accounts SET stream_version = $2 WHERE account_id = $1 AND stream_version < $2",
            )
            .bind(account_id)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
    }
    Ok(())
}

/// Applies one organisation event at `version` to `grund_organisations` and
/// `grund_memberships`.
pub async fn apply_organisation(
    organisation_id: Uuid,
    version: i64,
    event: &OrganisationEvent,
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    match event {
        OrganisationEvent::Created {
            slug, created_at, ..
        } => {
            sqlx::query(
                "INSERT INTO grund_organisations (organisation_id, slug, kind, created_at, stream_version) \
                 VALUES ($1, $2, 'personal', $3, $4) \
                 ON CONFLICT (organisation_id) DO UPDATE SET \
                   slug = EXCLUDED.slug, created_at = EXCLUDED.created_at, \
                   stream_version = EXCLUDED.stream_version \
                 WHERE grund_organisations.stream_version < EXCLUDED.stream_version",
            )
            .bind(organisation_id)
            .bind(slug.as_str())
            .bind(created_at)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        OrganisationEvent::MemberAdded {
            account_id, role, ..
        } => {
            sqlx::query(
                "INSERT INTO grund_memberships (organisation_id, account_id, role, stream_version) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (organisation_id, account_id) DO UPDATE SET \
                   role = EXCLUDED.role, stream_version = EXCLUDED.stream_version \
                 WHERE grund_memberships.stream_version < EXCLUDED.stream_version",
            )
            .bind(organisation_id)
            .bind(account_id)
            .bind(role.as_str())
            .bind(version)
            .execute(&mut *connection)
            .await?;
            sqlx::query(
                "UPDATE grund_organisations SET stream_version = $2 \
                 WHERE organisation_id = $1 AND stream_version < $2",
            )
            .bind(organisation_id)
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
    }
    Ok(())
}

/// The id inside a stream id such as `grund-account-<uuid>`.
pub fn stream_uuid(stream_id: &str, category: &str) -> anyhow::Result<Uuid> {
    stream_id
        .strip_prefix(category)
        .and_then(|rest| rest.strip_prefix('-'))
        .ok_or_else(|| anyhow::anyhow!("stream {stream_id} is not in category {category}"))
        .and_then(|id| Ok(Uuid::parse_str(id)?))
}

/// The account read model, for a `mire::ProjectionRunner`.
pub struct AccountProjection;

impl TransactionalEventHandler for AccountProjection {
    type Aggregate = Account;

    async fn handle(
        &self,
        event: HandledEvent<AccountEvent>,
        connection: &mut PgConnection,
    ) -> anyhow::Result<()> {
        let id = stream_uuid(event.stream_id(), grund_domain::account::ACCOUNT_CATEGORY)?;
        apply_account(id, event.stream_version(), &event.event, connection).await?;
        Ok(())
    }
}

/// The organisation read model, for a `mire::ProjectionRunner`.
pub struct OrganisationProjection;

impl TransactionalEventHandler for OrganisationProjection {
    type Aggregate = Organisation;

    async fn handle(
        &self,
        event: HandledEvent<OrganisationEvent>,
        connection: &mut PgConnection,
    ) -> anyhow::Result<()> {
        let id = stream_uuid(
            event.stream_id(),
            grund_domain::organisation::ORGANISATION_CATEGORY,
        )?;
        apply_organisation(id, event.stream_version(), &event.event, connection).await?;
        Ok(())
    }
}
