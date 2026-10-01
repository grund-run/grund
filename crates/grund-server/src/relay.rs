//! grund's relays (grund-docs design/network.md §10): who they admit, the
//! relay inside `grund serve`, and `grund relay` on its own host.
//!
//! **One access policy.** A relay admits a key only if it is the current key
//! of a machine registered with the instance and not revoked, or the
//! instance's own key (grund-store `relay_keys_among`). The relay in `grund
//! serve` asks the database ([`Database`]); a `grund relay` elsewhere asks
//! its instance over HTTPS ([`Callout`], answered by `api/relay_access.rs`
//! from the same query). Either way [`RelayAccess`] asks when a connection
//! starts, and [`sweep`] asks again for every connected key each
//! [`SWEEP_INTERVAL`], cutting those no longer admitted: a sweep rather than
//! a hook on RevokeMachine, because the revocation may reach another replica,
//! or another host, than the one holding the connection.
//!
//! When the policy cannot be asked, a new connection is refused and open ones
//! are kept until it can: deny by default, without turning a blip in grund
//! into every machine losing its relay.
//!
//! Metering and per-plan limits (hosted relays only, network.md §14) are not
//! built. They belong where a key is admitted ([`RelayAccess`]'s
//! `on_connect` and `on_disconnect`, which know the key and the connection)
//! and in iroh-relay's per-client rate limit.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    str::FromStr,
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

/// The most keys one access question may carry: 200 hex keys and their
/// quoting fit the instance's 16 KiB request limit. A sweep of more keys
/// asks in turns.
pub const MAX_KEYS_PER_CHECK: usize = 200;

/// Which of some keys a relay may admit.
pub trait KeyPolicy: Clone + std::fmt::Debug + Send + Sync + 'static {
    /// The subset of `keys` that may use the relay now.
    fn admitted(
        &self,
        keys: &[EndpointId],
    ) -> impl Future<Output = anyhow::Result<HashSet<EndpointId>>> + Send;
}

/// The policy read from the instance's own database.
#[derive(Debug, Clone)]
pub struct Database {
    pool: sqlx::PgPool,
}

impl Database {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl KeyPolicy for Database {
    async fn admitted(&self, keys: &[EndpointId]) -> anyhow::Result<HashSet<EndpointId>> {
        if keys.is_empty() {
            return Ok(HashSet::new());
        }
        let hex: Vec<String> = keys.iter().map(ToString::to_string).collect();
        let found = grund_store::machines::relay_keys_among(&self.pool, &hex).await?;
        Ok(keys
            .iter()
            .filter(|k| found.contains(&k.to_string()))
            .copied()
            .collect())
    }
}

/// The policy asked of an instance over HTTPS, as `grund relay` does:
/// `POST <instance>/relay/v1/access/current`, signed by the relay's own key
/// when it is enrolled, or with the shared bearer token (deprecated).
#[derive(Debug, Clone)]
pub struct Callout {
    http: reqwest::Client,
    url: String,
    credential: Credential,
}

#[derive(Debug, Clone)]
enum Credential {
    Token(String),
    Relay(Box<crate::relay_certificate::RelayKey>),
}

/// How long one access question to the instance may take.
pub const CALLOUT_TIMEOUT: Duration = Duration::from_secs(3);

impl Callout {
    /// A callout to the instance at `instance` (its origin) with `token`.
    pub fn new(instance: &str, token: &str) -> anyhow::Result<Self> {
        grund_tls::install_default();
        let http = reqwest::Client::builder()
            .timeout(CALLOUT_TIMEOUT)
            .connect_timeout(Duration::from_secs(2))
            .user_agent("grund-relay")
            .build()
            .context("build the HTTP client for the access callout")?;
        Ok(Self {
            http,
            url: format!("{}/relay/v1/access/current", instance.trim_end_matches('/')),
            credential: Credential::Token(token.to_string()),
        })
    }

    /// A callout to the instance at `instance`, signed by the enrolled
    /// relay's `key`.
    pub fn signed(instance: &str, key: crate::relay_certificate::RelayKey) -> anyhow::Result<Self> {
        let mut callout = Self::new(instance, "")?;
        callout.http = crate::relay_certificate::http_client(Some(CALLOUT_TIMEOUT))?;
        callout.credential = Credential::Relay(Box::new(key));
        Ok(callout)
    }
}

impl KeyPolicy for Callout {
    async fn admitted(&self, keys: &[EndpointId]) -> anyhow::Result<HashSet<EndpointId>> {
        let body = serde_json::json!({
            "keys": keys.iter().map(ToString::to_string).collect::<Vec<_>>()
        });
        let body = serde_json::to_vec(&body)?;
        let mut request = self
            .http
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        request = match &self.credential {
            Credential::Token(token) => request.bearer_auth(token),
            Credential::Relay(key) => key
                .headers("/relay/v1/access/current", &body)
                .into_iter()
                .fold(request, |request, (name, value)| {
                    request.header(name, value)
                }),
        };
        let response = request
            .body(body)
            .send()
            .await
            .context("ask the instance which keys to admit")?;
        let status = response.status();
        anyhow::ensure!(
            status.is_success(),
            "the instance answered the access check with {status}"
        );
        let answer: serde_json::Value = response.json().await?;
        Ok(answer["admitted"]
            .as_array()
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| k.as_str())
                    .filter_map(|k| EndpointId::from_str(k).ok())
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// Admits whoever `policy` admits, and remembers which keys are connected.
/// Clones share what they remember.
#[derive(Debug, Clone)]
pub struct RelayAccess<P> {
    policy: P,
    connected: Arc<Mutex<HashMap<EndpointId, HashSet<ConnectionId>>>>,
}

impl<P: KeyPolicy> RelayAccess<P> {
    pub fn new(policy: P) -> Self {
        Self {
            policy,
            connected: Arc::default(),
        }
    }

    /// The policy this relay asks.
    pub fn policy(&self) -> &P {
        &self.policy
    }

    /// The connected keys that are no longer admitted.
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
        let mut admitted = HashSet::new();
        for chunk in connected.chunks(MAX_KEYS_PER_CHECK) {
            admitted.extend(self.policy.admitted(chunk).await?);
        }
        Ok(connected
            .into_iter()
            .filter(|id| !admitted.contains(id))
            .collect())
    }
}

impl<P: KeyPolicy> AccessControl for RelayAccess<P> {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let key = request.endpoint_id();
        match self.policy.admitted(&[key]).await {
            Ok(admitted) if admitted.contains(&key) => {
                self.connected
                    .lock()
                    .expect("relay connections lock")
                    .entry(key)
                    .or_default()
                    .insert(request.connection_id());
                Access::Allow
            }
            Ok(_) => Access::Deny {
                reason: Some("not a machine of this grund".into()),
            },
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "relay: could not check a machine key; refusing");
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

/// Checks every connected key again each `interval`, and cuts those no
/// longer admitted. Runs until dropped.
pub async fn sweep<P: KeyPolicy>(access: &RelayAccess<P>, relay: &Relay, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        match access.stale().await {
            Ok(stale) => {
                for endpoint_id in stale {
                    if relay.disconnect(endpoint_id) {
                        tracing::info!(%endpoint_id, "relay: cut a key that is no longer a machine's");
                    }
                }
            }
            Err(error) => tracing::warn!(
                error = %format!("{error:#}"),
                "relay: could not check connected keys; keeping them until grund answers"
            ),
        }
    }
}

/// The relay inside `grund serve`, as a notmad component: grund-net's relay
/// on its own listener, and QUIC address discovery when a certificate is
/// configured: its own files, or, when its URL is on GRUND_DOMAIN or on a
/// name the instance adds to its own certificate, the instance's
/// certificate itself. Off unless GRUND_RELAY_ADDRESS is set.
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
                crate::relay_command::RelayTls::Files {
                    cert: cert.clone(),
                    key: key.clone(),
                }
                .server_config()?,
            ),
            _ if self.state.config.relay_serves_instance_certificate() => {
                use crate::certificates::CertificatesState;
                Some(
                    crate::relay_command::RelayTls::Instance(
                        crate::relay_certificate::InstanceTls {
                            resolver: self.state.certificates().resolver(),
                            answers: Default::default(),
                        },
                    )
                    .server_config()?,
                )
            }
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
        let access = RelayAccess::new(Database::new(self.state.pool.clone()));
        let relay = Relay::new(access.clone());
        tokio::select! {
            served = grund_net::relay::serve(listener, tls.map(Arc::new), relay.clone(), Relay::probe_routes()) => {
                served.map_err(anyhow::Error::from)?;
            }
            () = sweep(&access, &relay, SWEEP_INTERVAL) => {}
            () = cancellation.cancelled() => {}
        }
        Ok(())
    }
}
