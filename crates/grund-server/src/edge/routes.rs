//! The edge's route table (grund-docs design/traffic.md §6.7): watched from
//! the instance over the edge's signed calls, and kept on disk, so an edge
//! whose instance does not answer keeps serving the last table it had
//! (fail-static). New apps and moved copies wait for the instance.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use buffa::Message;
use grund_proto::grund::edge::v1::{RouteTable, WatchRoutesRequest, WatchRoutesResponse};
use tokio::sync::watch;

use crate::relay_certificate::RelayKey;

/// Where the last table is kept.
pub const ROUTES_FILE: &str = "routes.pb";

/// The largest table the edge accepts.
pub const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;

/// One address as the edge serves it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Route {
    pub name: String,
    pub suspended: bool,
    /// The machines' endpoint ids, with the relays to dial each through:
    /// its home relay, or every relay of the table when it reported none.
    pub machines: Vec<(String, Vec<String>)>,
}

/// The table in force.
#[derive(Debug, Clone, Default)]
pub struct Table {
    pub version: String,
    pub by_name: HashMap<String, Arc<Route>>,
    pub relay_urls: Vec<String>,
}

impl Table {
    pub fn from_proto(table: &RouteTable) -> Self {
        let by_name = table
            .routes
            .iter()
            .map(|route| {
                let name = route.name.to_ascii_lowercase();
                (
                    name.clone(),
                    Arc::new(Route {
                        name,
                        suspended: route.suspended,
                        machines: route
                            .machines
                            .iter()
                            .map(|m| {
                                let relays = if m.relay_url.is_empty() {
                                    table.relay_urls.clone()
                                } else {
                                    vec![m.relay_url.clone()]
                                };
                                (m.endpoint_id.clone(), relays)
                            })
                            .collect(),
                    }),
                )
            })
            .collect();
        Self {
            version: table.version.clone(),
            by_name,
            relay_urls: table.relay_urls.clone(),
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<Route>> {
        self.by_name.get(&name.to_ascii_lowercase()).cloned()
    }
}

/// The table, shared by the accept loop and the certificates.
#[derive(Debug, Clone)]
pub struct Routes {
    current: Arc<RwLock<Arc<Table>>>,
    changed: watch::Sender<String>,
    file: PathBuf,
}

impl Routes {
    /// The table kept in `data_dir`, or an empty one.
    pub fn load(data_dir: &Path) -> Self {
        let file = data_dir.join(ROUTES_FILE);
        let table = std::fs::read(&file)
            .ok()
            .filter(|bytes| bytes.len() <= MAX_TABLE_BYTES)
            .and_then(|bytes| RouteTable::decode_from_slice(&bytes).ok())
            .map(|table| Table::from_proto(&table))
            .unwrap_or_default();
        if !table.version.is_empty() {
            tracing::info!(
                routes = table.by_name.len(),
                "edge: serving the route table kept on disk"
            );
        }
        let (changed, _) = watch::channel(table.version.clone());
        Self {
            current: Arc::new(RwLock::new(Arc::new(table))),
            changed,
            file,
        }
    }

    pub fn current(&self) -> Arc<Table> {
        self.current.read().expect("routes lock").clone()
    }

    /// Changes whenever a new table is in force.
    pub fn subscribe(&self) -> watch::Receiver<String> {
        self.changed.subscribe()
    }

    /// Puts `table` in force and keeps it on disk.
    pub fn install(&self, table: &RouteTable) -> anyhow::Result<()> {
        let bytes = table.encode_to_vec();
        let temporary = self.file.with_extension("tmp");
        std::fs::write(&temporary, &bytes)?;
        std::fs::rename(&temporary, &self.file)?;
        let table = Table::from_proto(table);
        let version = table.version.clone();
        tracing::info!(routes = table.by_name.len(), %version, "edge: a new route table is in force");
        *self.current.write().expect("routes lock") = Arc::new(table);
        self.changed.send_replace(version);
        Ok(())
    }
}

/// Watches the instance's route table for ever, retrying with jittered
/// backoff up to a minute while it does not answer.
pub async fn watch(routes: Routes, key: RelayKey, http: reqwest::Client) {
    let mut retry = Duration::from_secs(1);
    loop {
        let path = "/grund.edge.v1.EdgeService/WatchRoutes";
        let body = WatchRoutesRequest {
            since_version: routes.current().version.clone(),
            ..Default::default()
        }
        .encode_to_vec();
        let headers = key.headers(path, &body);
        let answer: anyhow::Result<WatchRoutesResponse> =
            crate::relay_certificate::unary(&http, &key.instance, path, &headers, body).await;
        match answer {
            Ok(answer) => {
                retry = Duration::from_secs(1);
                if let Some(table) = answer.table.as_option()
                    && let Err(error) = routes.install(table)
                {
                    tracing::warn!(
                        error = format!("{error:#}"),
                        "edge: could not keep the route table"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    error = format!("{error:#}"),
                    retry_in_seconds = retry.as_secs(),
                    "edge: the instance did not answer for the route table; serving the last one"
                );
                tokio::time::sleep(retry.mul_f64(1.0 + crate::acme::unit_random() / 2.0)).await;
                retry = (retry * 2).min(Duration::from_secs(60));
            }
        }
    }
}
