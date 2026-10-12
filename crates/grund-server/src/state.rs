//! What the process opens once, shared by every request and component.
//!
//! Handlers never reach into these fields for domain work: they ask for a
//! service through its extension trait (`state.accounts()`), defined at the
//! bottom of the file that defines the service.

use std::{sync::Arc, time::Instant};

use crate::{
    config::ServeConfig,
    extension::Extensions,
    secrets::SecretKey,
    services::{billing::Billing, entitlements::Entitlements, passwords::Passwords},
};

/// Cheap to clone: every field is an `Arc`, a pool or a handle.
#[derive(Clone)]
pub struct State {
    pub config: Arc<ServeConfig>,
    pub pool: sqlx::PgPool,
    pub events: mire::EventStore,
    pub nats: Option<async_nats::Client>,
    pub secret: Arc<SecretKey>,
    /// What HTTPS serves, and the ACME work behind it (certificates.rs).
    pub certificates: crate::certificates::Certificates,
    pub health: nostatus::StatusState,
    pub passwords: Passwords,
    pub entitlements: Arc<Entitlements>,
    /// The billing shim: free, or a billing service (GRUND_BILLING_URL).
    pub billing: Billing,
    /// Where the management pool gets machines: none, or a capacity provider
    /// (GRUND_CAPACITY_URL).
    pub capacity: crate::services::capacity::Capacity,
    /// Starts organisation deletions, which wait on billing (sagas.rs).
    pub deletions: crate::sagas::Deletions,
    /// Features built outside the core (the commercial `ee/`), if this
    /// binary includes them.
    pub extensions: Extensions,
    pub started: Instant,
    /// Wakes the control link's long polls when a document changes.
    pub wakes: crate::wakes::Wakes,
    /// Since when this instance has been hearing its machines (hearing.rs).
    pub hearing: Arc<crate::hearing::Hearing>,
}

impl State {
    /// The organisation that operates hosted infrastructure. Public builds
    /// continue using their configured legacy operator.
    pub async fn operator_organisation(&self) -> anyhow::Result<Option<uuid::Uuid>> {
        for extension in self.extensions.iter() {
            if let Some(organisation_id) = extension.operator_organisation(self).await? {
                return Ok(Some(organisation_id));
            }
        }
        if self
            .extensions
            .iter()
            .any(|extension| extension.replaces_builtin_hosted())
        {
            return Ok(None);
        }
        use crate::services::machines::MachinesState;
        self.machines().operator().await
    }

    /// Resolves an extension-owned machine identifier within its organisation.
    pub async fn machine_id(
        &self,
        organisation_id: uuid::Uuid,
        public_id: uuid::Uuid,
    ) -> anyhow::Result<uuid::Uuid> {
        for extension in self.extensions.iter() {
            if let Some(machine_id) = extension
                .machine_alias(self, organisation_id, public_id)
                .await?
            {
                return Ok(machine_id);
            }
        }
        Ok(public_id)
    }

    /// Public identifiers for hosted VM placements, from the active provider.
    pub async fn vm_aliases(
        &self,
        organisation_id: uuid::Uuid,
    ) -> anyhow::Result<Vec<(uuid::Uuid, uuid::Uuid, chrono::DateTime<chrono::Utc>)>> {
        if self
            .extensions
            .iter()
            .any(|extension| extension.replaces_builtin_hosted())
        {
            let mut aliases = Vec::new();
            for extension in self.extensions.iter() {
                aliases.extend(extension.vm_aliases(self, organisation_id).await?);
            }
            aliases.extend(
                grund_store::machines::organisation_machines(&self.pool, organisation_id)
                    .await?
                    .into_iter()
                    .filter(|row| row.pool == "management")
                    .filter_map(|row| Some((row.lease_id?, row.machine_id, row.leased_at?))),
            );
            Ok(aliases)
        } else {
            Ok(grund_store::machines::hosted_vm_orders(&self.pool, organisation_id).await?)
        }
    }
}
