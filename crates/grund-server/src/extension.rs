//! Optional features attach routes, services and capacity providers through
//! this seam without changing the public server's default hosted behavior.

use std::{future::Future, pin::Pin, sync::Arc};

use chrono::{DateTime, Utc};
use connectrpc::Router as ConnectRouter;
use notmad::{Component, ComponentInfo, MadError};
use sqlx::PgConnection;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    api::Requirement,
    config::ServeConfig,
    services::{
        capacity::CapacityProvider,
        machines::{HostedEnrollment, LeaseRecorder},
    },
    state::State,
    web::pages::{NavLink, TypedViewer},
};

/// A way to sign in that an extension offers on the sign-in page.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoginProvider {
    pub id: String,
    pub name: String,
    pub icon: &'static str,
}

/// An additional way to add a machine, shown only when an extension allows it.
pub struct MachineAddOption {
    pub title: &'static str,
    pub href: String,
}

/// An extension-owned machine visible in an organisation's machine list.
pub struct ExternalMachine {
    pub id: Uuid,
    pub machine_id: Option<Uuid>,
    pub name: String,
    pub state: String,
    pub remove_href: String,
    /// A safe OS label for externally provisioned machines; physical host identity stays hidden.
    pub os: Option<&'static str>,
}

/// Public virtual-machine identifier, underlying machine identifier and lease start.
pub type VmAlias = (Uuid, Uuid, DateTime<Utc>);

/// A worker owned by an optional extension and drained with the server.
pub type ExtensionWorker = Pin<Box<dyn Future<Output = Result<(), MadError>> + Send>>;

/// A feature built outside the core.
pub trait Extension: Send + Sync + 'static {
    /// Its name, for logs.
    fn name(&self) -> &'static str;

    /// Routes to merge into the page router, under the same middleware as
    /// the core's pages.
    fn routes(&self) -> axum::Router<State>;

    /// Opt out of the legacy provider's routes and services when this extension
    /// supplies replacements. The default keeps public hosted behavior intact.
    fn replaces_builtin_hosted(&self) -> bool {
        false
    }

    /// Connect services contributed by this extension.
    fn connect_services(&self, router: ConnectRouter, _state: &State) -> ConnectRouter {
        router
    }

    fn connect_service_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// Required caller for each contributed procedure. Unlisted procedures are denied.
    fn authorization(&self) -> &'static [(&'static str, Requirement)] {
        &[]
    }

    /// Procedures returning one-time secrets that must not be cached or compressed.
    fn secret_procedures(&self) -> &'static [&'static str] {
        &[]
    }

    fn navigation(&self, _viewer: &TypedViewer) -> Vec<NavLink> {
        Vec::new()
    }

    fn operator_organisation<'a>(
        &'a self,
        _state: &'a State,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Uuid>>> + Send + 'a>> {
        Box::pin(async { Ok(None) })
    }

    fn migration_timeout<'a>(
        &'a self,
        _state: &'a State,
        _connection: &'a mut PgConnection,
        _machine_id: Uuid,
        _migration_id: Uuid,
        _at: DateTime<Utc>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn capacity_provider(
        &self,
        _config: &ServeConfig,
    ) -> anyhow::Result<Option<Arc<dyn CapacityProvider>>> {
        Ok(None)
    }

    fn hosted_enrollment(&self, _state: &State) -> Option<Box<dyn HostedEnrollment>> {
        None
    }

    fn lease_recorder(&self, _state: &State) -> Option<Box<dyn LeaseRecorder>> {
        None
    }

    fn machine_add_option<'a>(
        &'a self,
        _state: &'a State,
        _organisation_id: Uuid,
        _slug: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<MachineAddOption>>> + Send + 'a>> {
        Box::pin(async { Ok(None) })
    }

    fn machine_listings<'a>(
        &'a self,
        _state: &'a State,
        _organisation_id: Uuid,
        _slug: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<ExternalMachine>>> + Send + 'a>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn machine_alias<'a>(
        &'a self,
        _state: &'a State,
        _organisation_id: Uuid,
        _public_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Uuid>>> + Send + 'a>> {
        Box::pin(async { Ok(None) })
    }

    fn vm_aliases<'a>(
        &'a self,
        _state: &'a State,
        _organisation_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<VmAlias>>> + Send + 'a>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Long-running work drained before the outbox.
    fn worker(&self, _state: State, _cancellation: CancellationToken) -> Option<ExtensionWorker> {
        None
    }

    /// Providers to offer on the sign-in page, already filtered by what the
    /// instance is entitled to.
    fn login_providers(&self, _state: &State) -> Vec<LoginProvider> {
        Vec::new()
    }
}

/// Runs extension workers under the same shutdown lifecycle as the core.
pub struct ExtensionWork(pub State);

impl Component for ExtensionWork {
    fn info(&self) -> ComponentInfo {
        "grund/extensions".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let work: Vec<_> = self
            .0
            .extensions
            .iter()
            .filter_map(|extension| extension.worker(self.0.clone(), cancellation.clone()))
            .collect();
        if work.is_empty() {
            cancellation.cancelled().await;
            return Ok(());
        }
        futures_util::future::try_join_all(work).await?;
        Ok(())
    }
}

/// The extensions this binary was built with.
pub type Extensions = Arc<Vec<Arc<dyn Extension>>>;
