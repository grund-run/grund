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
    machine::{Machine, MachineEvent, Pool},
    organisation::{Organisation, OrganisationEvent},
};
use mire::{HandledEvent, TransactionalEventHandler};
use sqlx::PgConnection;
use uuid::Uuid;

/// Subscription ids; bump the suffix to rebuild a read model from scratch.
pub const ACCOUNT_SUBSCRIPTION: &str = "grund-account-read-model-v1";
pub const ORGANISATION_SUBSCRIPTION: &str = "grund-organisation-read-model-v1";
pub const MACHINE_SUBSCRIPTION: &str = "grund-machine-read-model-v1";

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
/// `grund_memberships`. Every event after `Created` first claims its version
/// on the organisation's row; an event at or below the row's version was
/// applied already and changes nothing, which is what makes a removal safe to
/// replay.
pub async fn apply_organisation(
    organisation_id: Uuid,
    version: i64,
    event: &OrganisationEvent,
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    if let OrganisationEvent::Created {
        slug,
        kind,
        created_at,
        ..
    } = event
    {
        sqlx::query(
            "INSERT INTO grund_organisations (organisation_id, slug, kind, created_at, stream_version) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (organisation_id) DO UPDATE SET \
               slug = EXCLUDED.slug, kind = EXCLUDED.kind, created_at = EXCLUDED.created_at, \
               stream_version = EXCLUDED.stream_version \
             WHERE grund_organisations.stream_version < EXCLUDED.stream_version",
        )
        .bind(organisation_id)
        .bind(slug.as_str())
        .bind(kind.as_str())
        .bind(created_at)
        .bind(version)
        .execute(&mut *connection)
        .await?;
        return Ok(());
    }
    let claimed = sqlx::query(
        "UPDATE grund_organisations SET stream_version = $2 \
         WHERE organisation_id = $1 AND stream_version < $2",
    )
    .bind(organisation_id)
    .bind(version)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Ok(());
    }
    match event {
        OrganisationEvent::Created { .. } => {}
        OrganisationEvent::MemberAdded {
            account_id,
            role,
            added_at,
        } => {
            sqlx::query(
                "INSERT INTO grund_memberships (organisation_id, account_id, role, stream_version, joined_at) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (organisation_id, account_id) DO UPDATE SET \
                   role = EXCLUDED.role, stream_version = EXCLUDED.stream_version, \
                   joined_at = EXCLUDED.joined_at",
            )
            .bind(organisation_id)
            .bind(account_id)
            .bind(role.as_str())
            .bind(version)
            .bind(added_at)
            .execute(&mut *connection)
            .await?;
        }
        OrganisationEvent::MemberRoleChanged {
            account_id, role, ..
        } => {
            sqlx::query(
                "UPDATE grund_memberships SET role = $3, stream_version = $4 \
                 WHERE organisation_id = $1 AND account_id = $2",
            )
            .bind(organisation_id)
            .bind(account_id)
            .bind(role.as_str())
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        OrganisationEvent::MemberRemoved { account_id, .. } => {
            sqlx::query(
                "DELETE FROM grund_memberships WHERE organisation_id = $1 AND account_id = $2",
            )
            .bind(organisation_id)
            .bind(account_id)
            .execute(&mut *connection)
            .await?;
        }
        OrganisationEvent::Renamed {
            from,
            to,
            renamed_at,
            ..
        } => {
            sqlx::query("UPDATE grund_organisations SET slug = $2 WHERE organisation_id = $1")
                .bind(organisation_id)
                .bind(to.as_str())
                .execute(&mut *connection)
                .await?;
            sqlx::query(
                "DELETE FROM grund_organisation_aliases WHERE slug = $1 AND organisation_id = $2",
            )
            .bind(to.as_str())
            .bind(organisation_id)
            .execute(&mut *connection)
            .await?;
            sqlx::query(
                "INSERT INTO grund_organisation_aliases (slug, organisation_id, created_at) \
                 VALUES ($1, $2, $3) ON CONFLICT (slug) DO NOTHING",
            )
            .bind(from.as_str())
            .bind(organisation_id)
            .bind(renamed_at)
            .execute(&mut *connection)
            .await?;
        }
        OrganisationEvent::DeletionRequested {
            request_id,
            requested_at,
            ..
        } => {
            sqlx::query(
                "UPDATE grund_organisations SET deletion_requested_at = $2, deletion_request_id = $3, \
                   deletion_refusal = NULL WHERE organisation_id = $1",
            )
            .bind(organisation_id)
            .bind(requested_at)
            .bind(request_id)
            .execute(&mut *connection)
            .await?;
        }
        OrganisationEvent::DeletionCancelled { reason, .. } => {
            let reason: String = reason.chars().take(500).collect();
            sqlx::query(
                "UPDATE grund_organisations SET deletion_requested_at = NULL, deletion_request_id = NULL, \
                   deletion_refusal = $2 WHERE organisation_id = $1",
            )
            .bind(organisation_id)
            .bind(reason)
            .execute(&mut *connection)
            .await?;
        }
        OrganisationEvent::Deleted { deleted_at, .. } => {
            sqlx::query(
                "UPDATE grund_organisations SET deleted_at = $2 WHERE organisation_id = $1",
            )
            .bind(organisation_id)
            .bind(deleted_at)
            .execute(&mut *connection)
            .await?;
            sqlx::query("DELETE FROM grund_memberships WHERE organisation_id = $1")
                .bind(organisation_id)
                .execute(&mut *connection)
                .await?;
        }
        OrganisationEvent::InvitationIssued { .. }
        | OrganisationEvent::InvitationWithdrawn { .. }
        | OrganisationEvent::InvitationAccepted { .. } => {}
    }
    Ok(())
}

/// Applies one machine event at `version` to `grund_machines`. Every event
/// after `Registered` claims its version on the machine's row first, so a
/// replay changes nothing.
pub async fn apply_machine(
    machine_id: Uuid,
    version: i64,
    event: &MachineEvent,
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    if let MachineEvent::Registered {
        pool,
        name,
        key,
        minted_by,
        facts,
        registered_at,
        provider_machine_id,
        ..
    } = event
    {
        let (home, state) = match pool {
            Pool::Management => (None, "available"),
            Pool::Organisation { organisation_id } => (Some(*organisation_id), "active"),
        };
        sqlx::query(
            "INSERT INTO grund_machines (machine_id, pool, home_organisation_id, name, state, \
               public_key, pool_organisation_id, pool_name, facts, minted_by, registered_at, \
               key_registered_at, stream_version, provider_machine_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $3, CASE WHEN $3 IS NULL THEN NULL ELSE $4 END, \
               $7, $8, $9, $9, $10, $11) \
             ON CONFLICT (machine_id) DO NOTHING",
        )
        .bind(machine_id)
        .bind(pool.as_str())
        .bind(home)
        .bind(name.as_str())
        .bind(state)
        .bind(key.as_hex())
        .bind(sqlx::types::Json(facts))
        .bind(minted_by)
        .bind(registered_at)
        .bind(version)
        .bind(provider_machine_id)
        .execute(&mut *connection)
        .await?;
        return Ok(());
    }
    let claimed = sqlx::query(
        "UPDATE grund_machines SET stream_version = $2 WHERE machine_id = $1 AND stream_version < $2",
    )
    .bind(machine_id)
    .bind(version)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Ok(());
    }
    match event {
        MachineEvent::Registered { .. } => {}
        MachineEvent::Leased {
            lease_id,
            organisation_id,
            name,
            leased_at,
            ..
        } => {
            sqlx::query(
                "UPDATE grund_machines SET state = 'leased', lease_id = $2, \
                   lessee_organisation_id = $3, lease_name = $4, leased_at = $5, \
                   pool_organisation_id = $3, pool_name = $4 \
                 WHERE machine_id = $1",
            )
            .bind(machine_id)
            .bind(lease_id)
            .bind(organisation_id)
            .bind(name.as_str())
            .bind(leased_at)
            .execute(&mut *connection)
            .await?;
        }
        MachineEvent::LeaseEnded { .. } => {
            sqlx::query(
                "UPDATE grund_machines SET state = 'returning', lease_id = NULL, \
                   lessee_organisation_id = NULL, lease_name = NULL, leased_at = NULL, \
                   pool_organisation_id = NULL, pool_name = NULL \
                 WHERE machine_id = $1",
            )
            .bind(machine_id)
            .execute(&mut *connection)
            .await?;
        }
        MachineEvent::Reregistered {
            key,
            facts,
            reregistered_at,
            ..
        } => {
            sqlx::query(
                "UPDATE grund_machines SET state = 'available', public_key = $2, facts = $3, \
                   key_registered_at = $4 \
                 WHERE machine_id = $1",
            )
            .bind(machine_id)
            .bind(key.as_hex())
            .bind(sqlx::types::Json(facts))
            .bind(reregistered_at)
            .execute(&mut *connection)
            .await?;
        }
        MachineEvent::Revoked { revoked_at, .. } => {
            sqlx::query(
                "UPDATE grund_machines SET state = 'revoked', public_key = NULL, revoked_at = $2, \
                   lease_id = NULL, lessee_organisation_id = NULL, lease_name = NULL, \
                   leased_at = NULL, pool_organisation_id = NULL, pool_name = NULL \
                 WHERE machine_id = $1",
            )
            .bind(machine_id)
            .bind(revoked_at)
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

/// The machine read model, for a `mire::ProjectionRunner`.
pub struct MachineProjection;

impl TransactionalEventHandler for MachineProjection {
    type Aggregate = Machine;

    async fn handle(
        &self,
        event: HandledEvent<MachineEvent>,
        connection: &mut PgConnection,
    ) -> anyhow::Result<()> {
        let id = stream_uuid(event.stream_id(), grund_domain::machine::MACHINE_CATEGORY)?;
        apply_machine(id, event.stream_version(), &event.event, connection).await?;
        Ok(())
    }
}
