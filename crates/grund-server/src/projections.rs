//! Keeps the read models converging on the event log. The write path applies
//! projections in its own transaction, so this runner is normally idle; it is
//! what catches up a read model after a rollback and what rebuilds one when
//! its subscription id is bumped.

use mire::ProjectionRunner;
use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;

use crate::state::State;

/// The notmad component. A database outage stops the runner; it is built
/// again and restarted (`restart::until_cancelled`) rather than taking the
/// process down.
pub struct Projections {
    state: State,
}

impl Projections {
    pub fn new(state: &State) -> Self {
        Self {
            state: state.clone(),
        }
    }

    fn runner(&self) -> ProjectionRunner {
        let state = &self.state;
        ProjectionRunner::builder(state.events.clone())
            .idle_backstop_interval(std::time::Duration::from_secs(10))
            .subscribe_transactional(
                grund_store::projections::ACCOUNT_SUBSCRIPTION,
                grund_store::projections::AccountProjection,
            )
            .subscribe_transactional(
                grund_store::projections::ORGANISATION_SUBSCRIPTION,
                grund_store::projections::OrganisationProjection,
            )
            .subscribe_transactional(
                grund_store::projections::MACHINE_SUBSCRIPTION,
                grund_store::projections::MachineProjection,
            )
            .subscribe_transactional(
                grund_store::projections::APP_SUBSCRIPTION,
                grund_store::projections::AppProjection,
            )
            .subscribe(
                crate::sagas::DELETION_TRIGGER_SUBSCRIPTION,
                crate::sagas::DeletionTrigger::new(&state.deletions),
            )
            .build()
    }
}

impl Component for Projections {
    fn info(&self) -> ComponentInfo {
        "grund/projections".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        crate::restart::until_cancelled("projections", cancellation.clone(), || {
            self.runner().run(cancellation.clone())
        })
        .await
        .map_err(MadError::Inner)
    }
}
