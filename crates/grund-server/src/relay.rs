//! grund's relay, as a notmad component (grund-docs design/network.md §10):
//! grund-net's relay on its own listener, and QUIC address discovery when a
//! certificate is configured. Off unless GRUND_RELAY_ADDRESS is set.
//!
//! The relay admits a connection only if the key that proved itself in the
//! relay handshake is the current key of a machine registered with this
//! instance: a revoked machine's key is cleared, so it is refused. A
//! connection admitted before the revocation is cut by a sweep that checks
//! every connected key again each [`SWEEP_INTERVAL`] and disconnects those
//! no longer current (network.md §10.2). A sweep, not a hook on
//! RevokeMachine, because the revocation may reach another replica than the
//! one holding the connection.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use grund_net::relay::{Access, AccessControl, ClientRequest, ConnectionId, EndpointId, Relay};
use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;

use crate::state::State;

/// How often the connected keys are checked again.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(2);

/// Admits the keys of this instance's registered, unrevoked machines, and
/// remembers which are connected. Clones share what they remember.
#[derive(Debug, Clone)]
pub struct MachineAccess {
    pool: sqlx::PgPool,
    connected: Arc<Mutex<HashMap<EndpointId, HashSet<ConnectionId>>>>,
}

impl MachineAccess {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            pool,
            connected: Arc::default(),
        }
    }

    /// The connected keys that are no longer a registered machine's.
    pub async fn stale(&self) -> anyhow::Result<Vec<EndpointId>> {
        let connected: Vec<EndpointId> = self
            .connected
            .lock()
            .expect("relay connections lock")
            .keys()
            .copied()
            .collect();
        if connected.is_empty() {
            return Ok(Vec::new());
        }
        let keys: Vec<String> = connected.iter().map(ToString::to_string).collect();
        let current = grund_store::machines::current_keys_among(&self.pool, &keys).await?;
        Ok(connected
            .into_iter()
            .filter(|id| !current.contains(&id.to_string()))
            .collect())
    }
}

impl AccessControl for MachineAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let key = request.endpoint_id().to_string();
        match grund_store::machines::key_is_current(&self.pool, &key).await {
            Ok(true) => {
                self.connected
                    .lock()
                    .expect("relay connections lock")
                    .entry(request.endpoint_id())
                    .or_default()
                    .insert(request.connection_id());
                Access::Allow
            }
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

    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        let mut connected = self.connected.lock().expect("relay connections lock");
        if let Some(connections) = connected.get_mut(&endpoint_id) {
            connections.remove(&connection_id);
            if connections.is_empty() {
                connected.remove(&endpoint_id);
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
        let access = MachineAccess::new(self.state.pool.clone());
        let relay = Relay::new(access.clone());
        tokio::select! {
            served = grund_net::relay::serve(listener, tls.map(Arc::new), relay.clone(), Relay::probe_routes()) => {
                served.map_err(anyhow::Error::from)?;
            }
            () = sweep(&access, &relay) => {}
            () = cancellation.cancelled() => {}
        }
        Ok(())
    }
}

async fn sweep(access: &MachineAccess, relay: &Relay) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        match access.stale().await {
            Ok(stale) => {
                for endpoint_id in stale {
                    if relay.disconnect(endpoint_id) {
                        tracing::info!(%endpoint_id, "relay: cut a key that is no longer a machine's");
                    }
                }
            }
            Err(error) => tracing::warn!(error = %error, "relay: could not check connected keys"),
        }
    }
}
