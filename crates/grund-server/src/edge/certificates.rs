//! The edge's certificates (grund-docs design/traffic.md §5, §17 item 3):
//! one per name, for its own host and for every address its route table
//! carries, each with a key made here, ordered by the instance through the
//! CSR flow (`grund.certificates.v1`) and validated by TLS-ALPN-01 on the
//! edge's own 443. What is kept on disk is served from the first handshake,
//! whether or not the instance or the CA answers.
//!
//! This is the step before a wildcard: a `*.<app domain>` certificate needs
//! DNS-01, and the `acme.grund.run` responder is not built (§5.2). A
//! certificate per address costs one order per new app; against Let's
//! Encrypt that counts towards 50 per registered domain a week until the
//! app domain is on the Public Suffix List (§5.5).

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use grund_proto::grund::certificates::v1::CertificateState;
use grund_tls::{Answers, Names};

use crate::relay_certificate::{Instance, Store};

/// How often a name with nothing pending is looked at again.
pub const ISSUED_RECHECK: Duration = Duration::from_secs(3600);

/// How often a name with an order in flight is looked at again.
pub const ORDERING_RECHECK: Duration = Duration::from_secs(20);

/// Keeps the edge's certificates.
pub struct EdgeCertificates {
    instance: Instance,
    names: Names,
    answers: Answers,
    data_dir: PathBuf,
    routes: super::routes::Routes,
}

fn store_for(data_dir: &Path, name: &str) -> Store {
    Store::new(&data_dir.join("names").join(name))
}

impl EdgeCertificates {
    pub fn new(
        instance: Instance,
        names: Names,
        answers: Answers,
        data_dir: &Path,
        routes: super::routes::Routes,
    ) -> Self {
        Self {
            instance,
            names,
            answers,
            data_dir: data_dir.to_path_buf(),
            routes,
        }
    }

    fn wanted(&self) -> BTreeSet<String> {
        let mut wanted: BTreeSet<String> = self.routes.current().by_name.keys().cloned().collect();
        wanted.insert(self.instance.key().host.clone());
        wanted
    }

    /// Serves what is kept on disk for every name wanted now.
    pub fn load(&self) {
        for name in self.wanted() {
            if self.names.get(&name).is_none() {
                match store_for(&self.data_dir, &name).load(&self.names.resolver(&name)) {
                    Ok(Some(_)) => {
                        tracing::debug!(%name, "edge: serving the certificate kept on disk")
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(%name, error = format!("{error:#}"), "edge: a kept certificate does not load")
                    }
                }
            }
        }
    }

    async fn reconcile_name(&self, name: &str) -> anyhow::Result<Duration> {
        let names = vec![name.to_string()];
        let store = store_for(&self.data_dir, name);
        let certificate = match self.instance.get_for(&names).await? {
            Some(certificate) => certificate,
            None => {
                let (_, csr) = store.pending(name)?;
                tracing::info!(%name, "edge: asking the instance for a certificate");
                self.instance.request_for(&names, &csr).await?
            }
        };
        let resolver = self.names.resolver(name);
        if !certificate.chain_pem.is_empty() {
            let serving = resolver.current().map(|served| served.not_after);
            let differs = match serving {
                None => true,
                Some(_) => store_chain(&store) != Some(certificate.chain_pem.clone()),
            };
            if differs {
                match store.install(&certificate.chain_pem, &resolver) {
                    Ok(()) => {
                        tracing::info!(%name, version = certificate.version, "edge: serving a certificate from the instance")
                    }
                    Err(error) => {
                        tracing::warn!(%name, error = format!("{error:#}"), "edge: not serving the instance's chain")
                    }
                }
            }
        }
        Ok(match certificate.state.as_known() {
            Some(CertificateState::CERTIFICATE_STATE_CSR_WANTED) => {
                let (_, csr) = store.fresh(name)?;
                tracing::info!(%name, "edge: renewal is due; sending a CSR for a new key");
                self.instance.request_for(&names, &csr).await?;
                ORDERING_RECHECK
            }
            Some(CertificateState::CERTIFICATE_STATE_ISSUED) => {
                self.answers.remove(name);
                ISSUED_RECHECK
            }
            _ => ORDERING_RECHECK,
        })
    }

    async fn pass(&self, due: &mut HashMap<String, Instant>) -> Duration {
        let wanted = self.wanted();
        for name in self.names.names() {
            if !wanted.contains(&name) {
                self.names.remove(&name);
                self.answers.remove(&name);
                due.remove(&name);
            }
        }
        self.load();
        let now = Instant::now();
        for name in &wanted {
            if due.get(name).is_some_and(|at| *at > now) {
                continue;
            }
            let next = match self.reconcile_name(name).await {
                Ok(next) => next,
                Err(error) => {
                    tracing::warn!(%name, error = format!("{error:#}"), "edge: could not get a certificate from the instance; serving what it has");
                    Duration::from_secs(30).mul_f64(1.0 + crate::acme::unit_random() / 2.0)
                }
            };
            due.insert(name.clone(), Instant::now() + next);
        }
        due.values()
            .min()
            .map_or(ORDERING_RECHECK, |at| {
                at.saturating_duration_since(Instant::now())
            })
            .clamp(Duration::from_millis(200), ORDERING_RECHECK)
    }

    async fn watch(&self, due: &mut HashMap<String, Instant>) -> anyhow::Result<()> {
        use grund_proto::grund::certificates::v1::__buffa::oneof::watch_challenges_response::Event;
        let mut watch = self.instance.watch().await?;
        while let Some(event) = watch.next().await? {
            match event {
                Event::Challenge(challenge) => {
                    self.answers
                        .insert(&challenge.name, &challenge.key_authorization)?;
                    self.instance.answering(&challenge.token).await?;
                    tracing::info!(name = %challenge.name, "edge: answering a TLS-ALPN-01 challenge");
                }
                Event::CsrWanted(wanted) => {
                    for name in wanted.names {
                        due.remove(&name);
                    }
                    return Ok(());
                }
                Event::Issued(issued) => {
                    for name in issued.names {
                        due.remove(&name);
                    }
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Runs for ever: a pass over the names, then the challenge watch while
    /// anything is ordered, with the route table's changes waking it.
    pub async fn run(self) {
        let mut due: HashMap<String, Instant> = HashMap::new();
        let mut changed = self.routes.subscribe();
        loop {
            let wait = self.pass(&mut due).await;
            let watching = async {
                match self.watch(&mut due).await {
                    Ok(()) => {}
                    Err(error) if crate::relay_certificate::refused_with(&error, "not_found") => {
                        tokio::time::sleep(wait).await
                    }
                    Err(error) => {
                        tracing::debug!(
                            error = format!("{error:#}"),
                            "edge: the certificate watch ended"
                        );
                        tokio::time::sleep(wait.min(Duration::from_secs(5))).await
                    }
                }
            };
            tokio::select! {
                () = watching => {}
                _ = changed.changed() => {}
                () = tokio::time::sleep(wait.max(Duration::from_secs(1))) => {}
            }
        }
    }
}

fn store_chain(store: &Store) -> Option<String> {
    store.chain()
}
