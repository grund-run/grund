//! The HTTP listener, as a notmad component.
//!
//! notmad installs the signal handlers, cancels every component when one
//! arrives, and drains them in the order they were added. This one is added
//! first, so it stops taking requests before the work behind it stops.

use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;

use crate::state::State;

pub struct Http {
    state: State,
}

impl Http {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

impl Component for Http {
    fn info(&self) -> ComponentInfo {
        "grund/http".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let address = self.state.config.listen;
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(anyhow::Error::from)?;
        tracing::info!(%address, public_url = %self.state.config.public_url, "grund listening");

        let app = crate::web::router(self.state.clone())
            .into_make_service_with_connect_info::<std::net::SocketAddr>();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { cancellation.cancelled().await })
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
}
