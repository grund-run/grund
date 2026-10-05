//! The instance's side of the traffic path (grund-docs design/traffic.md
//! §6.7, §7.3, §11): app addresses, the keys machines take entry streams
//! from, the edges' route table, and the entry bytes edges meter.
//!
//! - **An app's address** is `<app>-<organisation>.<GRUND_APP_DOMAIN>` for an
//!   app with a public `http` or `h2c` port. Two apps can spell the same
//!   label (`a-b` in `cde`, `a` in `b-cde`): the one made first holds it,
//!   and the other has no address until it is renamed or deleted. The rule
//!   is the same in documents and in the route table, because both ask
//!   [`Entry::address`].
//! - **Entry keys**: every active edge whose host is in GRUND_EDGES. They go
//!   into every machine's signed document; when the set changes, every
//!   machine with a copy gets a new document ([`EntryKeys`], a notmad
//!   component, polling every 5 s).
//! - **The route table**: per address, the machines with a running (not
//!   draining) copy that were seen in the last 30 s (apps.md §9.2), their
//!   keys and home relays, and whether the app is suspended. Its version is
//!   a digest of its content, so an edge holding the newest table waits.

use std::{collections::BTreeMap, time::Duration};

use buffa::Message;
use chrono::Utc;
use grund_proto::grund::edge::v1 as edge;
use notmad::{Component, ComponentInfo, MadError};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::state::State;

/// The longest WatchRoutes waits for a change.
pub const LONG_POLL: Duration = Duration::from_secs(10);

/// How often the entry keys are compared with what documents carry.
pub const ENTRY_KEYS_EVERY: Duration = Duration::from_secs(5);

/// The traffic path's flows.
#[derive(Clone)]
pub struct Entry {
    state: State,
}

/// Whether an app's spec publishes a port the gate routes.
pub fn publishes(spec: &grund_domain::app::AppSpec) -> bool {
    use grund_domain::app::spec::Protocol;
    spec.ports
        .iter()
        .any(|p| p.public && matches!(p.protocol, Protocol::Http | Protocol::H2c))
}

/// The route table's version: a digest of its routes and relays.
pub fn version_of(routes: &[edge::Route], relay_urls: &[String]) -> String {
    let mut hasher = Sha256::new();
    for route in routes {
        let bytes = route.encode_to_vec();
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    for url in relay_urls {
        hasher.update(url.as_bytes());
        hasher.update([0]);
    }
    hex::encode(&hasher.finalize()[..16])
}

impl Entry {
    /// GRUND_APP_DOMAIN.
    pub fn app_domain(&self) -> Option<&str> {
        self.state.config.entry.app_domain.as_deref()
    }

    /// The address of the app `app_id`, named `app_name` in the
    /// organisation with `slug`, if it holds one.
    pub async fn address(
        &self,
        executor: &mut sqlx::PgConnection,
        app_id: Uuid,
        app_name: &str,
        slug: &str,
    ) -> anyhow::Result<Option<String>> {
        let Some(domain) = self.app_domain() else {
            return Ok(None);
        };
        let label = format!("{app_name}-{slug}");
        let holders = grund_store::entry::apps_named(&mut *executor, &label).await?;
        Ok(holders
            .first()
            .filter(|holder| holder.app_id == app_id)
            .map(|_| format!("{label}.{domain}")))
    }

    /// The iroh endpoint ids of the active edges, sorted.
    pub async fn entry_keys(
        &self,
        executor: &mut sqlx::PgConnection,
    ) -> anyhow::Result<Vec<String>> {
        let hosts = &self.state.config.entry.edges;
        if hosts.is_empty() {
            return Ok(Vec::new());
        }
        let mut keys: Vec<String> = grund_store::relays::active_edge_keys(&mut *executor, hosts)
            .await?
            .into_iter()
            .map(hex::encode)
            .collect();
        keys.sort();
        Ok(keys)
    }

    /// The relays machines are homed on: those the instance hands out.
    pub fn relay_urls(&self) -> Vec<String> {
        self.state
            .config
            .relay
            .urls()
            .into_iter()
            .map(|u| u.trim_end_matches('/').to_string())
            .collect()
    }

    /// The route table as it stands.
    pub async fn route_table(&self) -> anyhow::Result<edge::RouteTable> {
        let rows = grund_store::entry::route_rows(&self.state.pool).await;
        self.state.hearing.observe(&rows);
        let rows = rows?;
        let Some(domain) = self.app_domain() else {
            let relay_urls = self.relay_urls();
            return Ok(edge::RouteTable {
                version: version_of(&[], &relay_urls),
                issued_at_unix: Utc::now().timestamp(),
                relay_urls,
                ..Default::default()
            });
        };
        let now = Utc::now();
        let mut held: BTreeMap<String, Uuid> = BTreeMap::new();
        let mut routes: BTreeMap<Uuid, edge::Route> = BTreeMap::new();
        for row in &rows {
            let name = format!("{}-{}.{domain}", row.app_name, row.organisation_slug);
            match held.get(&name) {
                Some(holder) if *holder != row.app_id => continue,
                _ => {
                    held.insert(name.clone(), row.app_id);
                }
            }
            let route = routes.entry(row.app_id).or_insert_with(|| edge::Route {
                name: name.clone(),
                app_id: row.app_id.to_string(),
                suspended: row.suspended,
                ..Default::default()
            });
            let (Some(machine_id), Some(spec), Some(key)) =
                (row.machine_id, row.spec.as_ref(), row.machine_key.as_ref())
            else {
                continue;
            };
            if row.suspended
                || !publishes(&spec.0)
                || !crate::services::agents::connected(
                    self.state.hearing.seen(row.last_seen_at),
                    now,
                )
                || route
                    .machines
                    .iter()
                    .any(|m| m.machine_id == machine_id.to_string())
            {
                continue;
            }
            route.machines.push(edge::RouteMachine {
                machine_id: machine_id.to_string(),
                endpoint_id: key.clone(),
                relay_url: row.relay_url.clone().unwrap_or_default(),
                ..Default::default()
            });
        }
        let mut routes: Vec<edge::Route> = routes
            .into_values()
            .filter(|r| !r.machines.is_empty() || published_any(&rows, r))
            .collect();
        routes.sort_by(|a, b| a.name.cmp(&b.name));
        let relay_urls = self.relay_urls();
        Ok(edge::RouteTable {
            version: version_of(&routes, &relay_urls),
            issued_at_unix: now.timestamp(),
            routes,
            relay_urls,
            ..Default::default()
        })
    }

    /// The route table once its version differs from `since`, or `None`
    /// after [`LONG_POLL`].
    pub async fn watch_routes(&self, since: &str) -> anyhow::Result<Option<edge::RouteTable>> {
        let deadline = tokio::time::Instant::now() + LONG_POLL;
        let mut wakes = self.state.wakes.subscribe();
        loop {
            let table = self.route_table().await?;
            if table.version != since {
                return Ok(Some(table));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
            }
            crate::wakes::Wakes::wait(&mut wakes).await;
        }
    }

    /// Adds an edge's report of entry bytes, once per report id.
    pub async fn record_usage(
        &self,
        edge_id: Uuid,
        report_id: Uuid,
        usage: Vec<grund_store::entry::UsageRow>,
    ) -> anyhow::Result<bool> {
        let mut tx = self.state.pool.begin().await?;
        let counted = grund_store::entry::record_usage(
            &mut tx,
            report_id,
            edge_id,
            Utc::now().date_naive(),
            &usage,
        )
        .await?;
        tx.commit().await?;
        Ok(counted)
    }

    /// Whether `name` is an address the route table carries now: what an
    /// edge may ask a certificate for.
    pub async fn routes_name(&self, name: &str) -> anyhow::Result<bool> {
        Ok(self
            .route_table()
            .await?
            .routes
            .iter()
            .any(|r| r.name == name))
    }
}

fn published_any(rows: &[grund_store::entry::RouteRow], route: &edge::Route) -> bool {
    rows.iter().any(|row| {
        row.app_id.to_string() == route.app_id
            && [row.spec.as_ref(), row.current_spec.as_ref()]
                .into_iter()
                .flatten()
                .any(|s| publishes(&s.0))
    })
}

/// The traffic path's flows.
pub trait EntryState {
    fn entry(&self) -> Entry;
}

impl EntryState for State {
    fn entry(&self) -> Entry {
        Entry {
            state: self.clone(),
        }
    }
}

/// Republishes the document of every machine with a copy when the entry
/// keys change: an edge enrolled, was revoked, or left GRUND_EDGES.
pub struct EntryKeys {
    state: State,
}

impl EntryKeys {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn once(&self, last: &mut Option<Vec<String>>) -> anyhow::Result<()> {
        use crate::services::agents::AgentsState;
        let mut connection = self.state.pool.acquire().await?;
        let keys = self.state.entry().entry_keys(&mut connection).await?;
        if last.as_ref() == Some(&keys) {
            return Ok(());
        }
        let machines: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT machine_id FROM grund_replicas ORDER BY machine_id",
        )
        .fetch_all(&mut *connection)
        .await?;
        drop(connection);
        if last.is_some() {
            for machine in &machines {
                self.state.agents().publish(*machine).await?;
            }
            tracing::info!(
                edges = keys.len(),
                machines = machines.len(),
                "entry keys changed; machines get new documents"
            );
        }
        *last = Some(keys);
        Ok(())
    }
}

impl Component for EntryKeys {
    fn info(&self) -> ComponentInfo {
        "grund/entry-keys".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let mut last = None;
        loop {
            if let Err(error) = self.once(&mut last).await {
                tracing::warn!(error = format!("{error:#}"), "entry keys: could not check");
            }
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                () = tokio::time::sleep(ENTRY_KEYS_EVERY) => {}
            }
        }
    }
}
