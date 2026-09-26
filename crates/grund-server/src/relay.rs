//! grund's relay, as a notmad component (grund-docs design/network.md §10):
//! grund-net's relay on its own listener, and QUIC address discovery when a
//! certificate is configured. Off unless GRUND_RELAY_ADDRESS is set.
//!
//! The relay admits a connection only if the key that proved itself in the
//! relay handshake is the current key of a machine registered with this
//! instance: a revoked machine's key is cleared, so it is refused from its
//! next connection. A connection admitted before the revocation lasts until
//! it drops; the membership list, not the relay, is what cuts a revoked
//! machine off from its peers.

use std::sync::Arc;

use anyhow::Context;
use grund_net::relay::{Access, AccessControl, ClientRequest, Relay};
use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;

use crate::state::State;

/// Admits the keys of this instance's registered, unrevoked machines.
#[derive(Debug, Clone)]
pub struct MachineAccess {
    pool: sqlx::PgPool,
}

impl MachineAccess {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl AccessControl for MachineAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let key = request.endpoint_id().to_string();
        match grund_store::machines::key_is_current(&self.pool, &key).await {
            Ok(true) => Access::Allow,
            Ok(false) => Access::Deny {
                reason: Some("not a machine of this grund".into()),
            },
            Err(error) => {
                tracing::warn!(error = %error, "relay: could not check a machine key; refusing");
                Access::Deny {
                    reason: Some("grund could not check the key; try again".into()),
                }
            }
        }
    }
}

pub struct RelayServer {
    state: State,
}

impl RelayServer {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

impl Component for RelayServer {
    fn info(&self) -> ComponentInfo {
        "grund/relay".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let config = &self.state.config.relay;
        let Some(address) = config.relay_address else {
            cancellation.cancelled().await;
            return Ok(());
        };
        let tls = match (&config.relay_tls_cert_file, &config.relay_tls_key_file) {
            (Some(cert), Some(key)) => Some(
                grund_net::relay::tls_from_pem(
                    &std::fs::read(cert).context("read GRUND_RELAY_TLS_CERT_FILE")?,
                    &std::fs::read(key).context("read GRUND_RELAY_TLS_KEY_FILE")?,
                )
                .context("the relay's certificate")?,
            ),
            _ => None,
        };
        let _discovery = match (config.relay_quic_address, &tls) {
            (Some(bind), Some(tls)) => {
                Some(grund_net::relay::spawn_address_discovery(bind, tls.clone()).await?)
            }
            _ => None,
        };
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(anyhow::Error::from)?;
        tracing::info!(
            %address,
            url = config.relay_url.as_deref().unwrap_or_default(),
            tls = tls.is_some(),
            quic = ?config.relay_quic_address,
            "relay listening"
        );
        let relay = Relay::new(MachineAccess::new(self.state.pool.clone()));
        tokio::select! {
            served = grund_net::relay::serve(listener, tls.map(Arc::new), relay, Relay::probe_routes()) => {
                served.map_err(anyhow::Error::from)?;
            }
            () = cancellation.cancelled() => {}
        }
        Ok(())
    }
}
