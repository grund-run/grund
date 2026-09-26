//! Reclaims space: expired sessions, links and rate-limit windows. Expiry is
//! enforced on every read, so a missed pass never extends anything; it only
//! leaves rows around longer.

use std::time::Duration;

use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;

use crate::state::State;

/// How often the sweeper runs.
pub const INTERVAL: Duration = Duration::from_secs(600);

/// The notmad component.
pub struct Sweeper {
    state: State,
}

impl Sweeper {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn pass(&self) -> Result<(u64, u64, u64, u64), sqlx::Error> {
        let pool = &self.state.pool;
        Ok((
            grund_store::sessions::sweep(pool).await?,
            grund_store::tokens::sweep(pool).await?,
            grund_store::throttle::sweep(pool).await?,
            grund_store::social::sweep(pool).await?,
        ))
    }
}

impl Component for Sweeper {
    fn info(&self) -> ComponentInfo {
        "grund/sweeper".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let mut tick = tokio::time::interval(INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                _ = tick.tick() => match self.pass().await {
                    Ok((sessions, tokens, windows, flows)) => {
                        tracing::debug!(sessions, tokens, windows, flows, "sweep done");
                    }
                    Err(error) => tracing::warn!(error = %error, "sweep failed; retrying next tick"),
                },
            }
        }
    }
}
