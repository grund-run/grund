//! Keeps the read models converging on the event log. The write path applies
//! projections in its own transaction, so this runner is normally idle; it is
//! what catches up a read model after a rollback and what rebuilds one when
//! its subscription id is bumped.

use mire::ProjectionRunner;
use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;

use crate::state::State;

/// The notmad component.
pub struct Projections {
    runner: std::sync::Mutex<Option<ProjectionRunner>>,
}

impl Projections {
    pub fn new(state: &State) -> Self {
        let runner = ProjectionRunner::builder(state.events.clone())
            .idle_backstop_interval(std::time::Duration::from_secs(10))
            .subscribe_transactional(
                grund_store::projections::ACCOUNT_SUBSCRIPTION,
                grund_store::projections::AccountProjection,
            )
            .subscribe_transactional(
                grund_store::projections::ORGANISATION_SUBSCRIPTION,
                grund_store::projections::OrganisationProjection,
            )
            .build();
        Self {
            runner: std::sync::Mutex::new(Some(runner)),
        }
    }
}

impl Component for Projections {
    fn info(&self) -> ComponentInfo {
        "grund/projections".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let runner = self.runner.lock().expect("projection runner lock").take();
        let Some(runner) = runner else {
            return Ok(());
        };
        runner.run(cancellation).await.map_err(MadError::Inner)
    }
}
