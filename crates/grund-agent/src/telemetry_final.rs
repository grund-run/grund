use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};

use parking_lot::Mutex;

use crate::{
    apps::Shared,
    runtime::{Observation, RemovalObserver},
    telemetry_spool::{Identity, Spool},
};

const MAX_IDENTITIES: usize = 4096;

pub(crate) struct State {
    pub(crate) identities: Mutex<BTreeMap<String, Identity>>,
    pub(crate) spool: OnceLock<Arc<Mutex<Spool>>>,
    pub(crate) pending_loss: std::sync::atomic::AtomicU64,
    pub(crate) collection: Mutex<()>,
    dirty: std::sync::atomic::AtomicBool,
    persisting: std::sync::atomic::AtomicBool,
    final_slots: Arc<tokio::sync::Semaphore>,
    ready: tokio::sync::watch::Sender<bool>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            identities: Mutex::default(),
            spool: OnceLock::new(),
            pending_loss: std::sync::atomic::AtomicU64::new(0),
            collection: Mutex::new(()),
            dirty: std::sync::atomic::AtomicBool::new(false),
            persisting: std::sync::atomic::AtomicBool::new(false),
            final_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            ready: tokio::sync::watch::Sender::new(false),
        }
    }
}

pub(crate) fn remember(
    shared: &Shared,
    document: Option<&grund_proto::grund::agent::v1::DesiredState>,
) {
    let Some(document) = document else {
        return;
    };
    let mut identities = shared.telemetry.identities.lock();
    let mut changed = false;
    for replica in &document.replicas {
        if identities.contains_key(&replica.replica_id) {
            continue;
        }
        if identities.len() >= MAX_IDENTITIES {
            tracing::warn!(
                "app telemetry identity capacity reached; final output may be discarded"
            );
            break;
        }
        let identity = Identity::from_document(document, replica);
        identities.insert(identity.instance.clone(), identity);
        changed = true;
    }
    drop(identities);
    if changed {
        shared
            .telemetry
            .dirty
            .store(true, std::sync::atomic::Ordering::Release);
    }
    persist(shared.telemetry.clone());
}

pub(crate) fn install(shared: &Shared, spool: Arc<Mutex<Spool>>) -> anyhow::Result<()> {
    let mut identities = shared.telemetry.identities.lock();
    for (id, identity) in spool.lock().identities() {
        if identities.len() >= MAX_IDENTITIES {
            break;
        }
        identities.entry(id).or_insert(identity);
    }
    spool.lock().remember(identities.values().cloned())?;
    drop(identities);
    let _ = shared.telemetry.spool.set(spool);
    shared.telemetry.ready.send_replace(true);
    Ok(())
}

pub(crate) fn prune(shared: &Shared, keep: &BTreeSet<String>) {
    let mut identities = shared.telemetry.identities.lock();
    let before = identities.len();
    identities.retain(|id, _| keep.contains(id));
    let changed = before != identities.len();
    drop(identities);
    shared
        .telemetry_secrets
        .lock()
        .retain(|id, _| keep.contains(id));
    if changed {
        shared
            .telemetry
            .dirty
            .store(true, std::sync::atomic::Ordering::Release);
    }
    persist(shared.telemetry.clone());
}

fn persist(state: Arc<State>) {
    use std::sync::atomic::Ordering;
    if state.spool.get().is_none()
        || !state.dirty.load(Ordering::Acquire)
        || state.persisting.swap(true, Ordering::AcqRel)
    {
        return;
    }
    tokio::task::spawn_blocking(move || {
        state.dirty.store(false, Ordering::Release);
        let identities = state.identities.lock().clone();
        let keep = identities.keys().cloned().collect();
        let result = (|| {
            let mut spool = state
                .spool
                .get()
                .expect("initialized telemetry spool")
                .lock();
            spool.remember(identities.into_values())?;
            spool.retain_instances(&keep)
        })();
        if result.is_err() {
            state.dirty.store(true, Ordering::Release);
            tracing::warn!(
                "app telemetry identity checkpoint unavailable; application cleanup remains independent"
            );
        }
        state.persisting.store(false, Ordering::Release);
    });
}

struct Removal {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Removal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AppOutputRemovalObserver")
    }
}

pub(crate) fn observer(shared: Arc<Shared>) -> Arc<dyn RemovalObserver> {
    Arc::new(Removal { shared })
}

impl RemovalObserver for Removal {
    fn collect<'a>(
        &'a self,
        id: &'a str,
        observation: Observation,
    ) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
        let shared = self.shared.clone();
        let id = id.to_string();
        Box::pin(async move {
            let mut ready = shared.telemetry.ready.subscribe();
            ready.wait_for(|ready| *ready).await?;
            let permit = shared.telemetry.final_slots.clone().acquire_owned().await?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let _collection = shared.telemetry.collection.lock();
                let spool = shared
                    .telemetry
                    .spool
                    .get()
                    .ok_or_else(|| anyhow::anyhow!("app output spool is not ready"))?
                    .clone();
                let identity = shared.telemetry.identities.lock().get(&id).cloned();
                let secrets = shared.telemetry_secrets.lock().get(&id).cloned();
                crate::telemetry::drain_final(spool, identity, observation, secrets)
            })
            .await??;
            Ok(())
        })
    }

    fn removed<'a>(
        &'a self,
        id: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
        let shared = self.shared.clone();
        let id = id.to_string();
        Box::pin(async move {
            shared.telemetry.identities.lock().remove(&id);
            shared.telemetry_secrets.lock().remove(&id);
            shared
                .telemetry
                .dirty
                .store(true, std::sync::atomic::Ordering::Release);
            persist(shared.telemetry.clone());
            Ok(())
        })
    }

    fn loss(&self) {
        self.shared
            .telemetry
            .pending_loss
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grund_proto::grund::agent::v1::{DesiredState, Replica};
    use opentelemetry_proto::tonic::{
        collector::logs::v1::ExportLogsServiceRequest, common::v1::any_value,
    };
    use prost::Message;
    use std::io::Write;

    #[tokio::test]
    async fn shutdown_output_survives_desired_removal_and_collector_restart() {
        let root =
            std::env::temp_dir().join(format!("grund-final-output-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("stdout.0");
        std::fs::write(&path, b"before\n").unwrap();
        let loss = root.join("dropped-bytes");
        let epoch = uuid::Uuid::now_v7();
        std::fs::write(&loss, format!("{epoch} 100")).unwrap();
        let id = uuid::Uuid::now_v7().to_string();
        let replica = Replica {
            replica_id: id.clone(),
            app_id: uuid::Uuid::now_v7().to_string(),
            release: 7,
            ..Default::default()
        };
        let document = DesiredState {
            organisation_id: uuid::Uuid::now_v7().to_string(),
            machine_id: uuid::Uuid::now_v7().to_string(),
            replicas: vec![replica],
            ..Default::default()
        };
        let observation = Observation {
            cgroup: root.join("absent-cgroup"),
            generation: String::new(),
            logs: vec![crate::runtime::LogSource {
                stream: "stdout",
                paths: vec![path.clone()],
            }],
            capture_loss: Some(loss.clone()),
        };
        {
            let shared = Arc::new(Shared::default());
            remember(&shared, Some(&document));
            let spool = Arc::new(Mutex::new(
                Spool::open(root.join("spool"), "scope").unwrap(),
            ));
            install(&shared, spool).unwrap();
            observer(shared)
                .collect(&id, observation.clone())
                .await
                .unwrap();
        }
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"shutdown\n")
            .unwrap();
        std::fs::write(&loss, format!("{epoch} 150")).unwrap();
        let shared = Arc::new(Shared::default());
        let spool = Arc::new(Mutex::new(
            Spool::open(root.join("spool"), "scope").unwrap(),
        ));
        install(&shared, spool.clone()).unwrap();
        observer(shared.clone())
            .collect(&id, observation)
            .await
            .unwrap();
        let mut bodies = Vec::new();
        assert_eq!(spool.lock().capture_dropped_bytes(), 150);
        let mut spool = spool.lock();
        while let Some(batch) = spool.next().unwrap() {
            let logs = ExportLogsServiceRequest::decode(batch.logs_otlp.as_ref()).unwrap();
            for resource in logs.resource_logs {
                for scope in resource.scope_logs {
                    for record in scope.log_records {
                        if let Some(any_value::Value::StringValue(body)) =
                            record.body.and_then(|b| b.value)
                        {
                            bodies.push(body);
                        }
                    }
                }
            }
            spool.acknowledge(&batch.batch_id).unwrap();
        }
        assert_eq!(bodies, ["before", "shutdown"]);
        drop(spool);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn retired_plaintext_is_pruned_but_running_final_drain_authority_is_kept() {
        let shared = Arc::new(Shared::default());
        let document = DesiredState {
            replicas: vec![Replica {
                replica_id: "retired".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        remember(&shared, Some(&document));
        shared.telemetry_secrets.lock().insert(
            "retired".into(),
            Arc::new(vec![crate::secrets::Cached {
                name: "secret".into(),
                version: 1,
                value: b"value".to_vec(),
            }]),
        );
        prune(&shared, &BTreeSet::from(["retired".into()]));
        assert!(shared.telemetry_secrets.lock().contains_key("retired"));
        prune(&shared, &BTreeSet::new());
        assert!(shared.telemetry_secrets.lock().is_empty());
        assert!(shared.telemetry.identities.lock().is_empty());
    }
}
