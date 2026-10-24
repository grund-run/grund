//! A machine with no instance: the runtime behind `grund up`.
//!
//! It runs the agent's own apps loop ([`crate::apps`]) against a
//! [`ContainerRuntime`], fed by documents the local caller builds instead of
//! documents an instance signs. There is no control link, so images are
//! pulled anonymously and secret values come from the cache the caller
//! writes before the loop starts. Every document passes the same
//! [`check_features`] the signed path applies, and generations only move
//! forward. The signed path in [`crate::agent`] is not used and not changed.
//! It keeps no database: only the documents it is given, what the runtime
//! observes and the agent's usual encrypted secret cache file.

use std::{path::PathBuf, sync::Arc};

use grund_proto::grund::agent::v1::{DesiredState, ReplicaObserved};

use crate::{
    agent::{Refusal, check_features},
    apps::{Apps, Shared},
    policy::Policy,
    runtime::ContainerRuntime,
    secrets,
};

pub struct Local<C> {
    apps: Apps<C>,
    shared: Arc<Shared>,
}

impl<C: ContainerRuntime + 'static> Local<C> {
    /// Writes `secret_values` (by replica id) to the encrypted cache under
    /// `data_dir`, keyed from `seed`, replacing any cache already there, and
    /// prepares the loop. `policy.volume_roots` bounds the host directories a
    /// replica may bind.
    pub fn new(
        runtime: Arc<C>,
        policy: Policy,
        data_dir: PathBuf,
        seed: &[u8; 32],
        secret_values: &secrets::Values,
    ) -> anyhow::Result<Self> {
        secrets::store(&data_dir, &secrets::key(seed), secret_values)?;
        let shared = Arc::new(Shared::default());
        let apps = Apps::new(runtime, None, shared.clone(), policy, data_dir, seed);
        Ok(Self { apps, shared })
    }

    pub fn handle(&self) -> Handle {
        Handle {
            shared: self.shared.clone(),
        }
    }

    pub async fn run(self) {
        self.apps.run().await;
    }
}

#[derive(Clone)]
pub struct Handle {
    shared: Arc<Shared>,
}

impl Handle {
    /// Applies `state` when it passes [`check_features`] and its generation is
    /// newer than the one applied; the loop acts on it at once.
    pub fn apply(&self, state: DesiredState) -> Result<(), Refusal> {
        check_features(&state)?;
        {
            let mut desired = self.shared.desired.lock().expect("shared lock");
            if desired
                .as_ref()
                .is_some_and(|current| state.generation <= current.generation)
            {
                return Err(Refusal::Older);
            }
            *desired = Some(state);
        }
        self.shared.document.notify_one();
        Ok(())
    }

    pub fn reports(&self) -> Vec<ReplicaObserved> {
        self.shared.reports.lock().expect("shared lock").clone()
    }

    /// Why the loop refused replicas in its last pass.
    pub fn refusals(&self) -> Vec<String> {
        self.shared.refusals.lock().expect("shared lock").clone()
    }

    /// Whether the loop has observed the runtime its documents need.
    pub fn runtime_ready(&self) -> bool {
        self.shared
            .runtime_ready
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simulated::SimulatedContainers;
    use grund_proto::grund::agent::v1::{Argv, Image, Replica};

    fn local(name: &str) -> (Local<SimulatedContainers>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("grund-local-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let local = Local::new(
            Arc::new(SimulatedContainers::new(dir.join("runtime"))),
            Policy::default(),
            dir.clone(),
            &[9; 32],
            &secrets::Values::new(),
        )
        .unwrap();
        (local, dir)
    }

    fn document(generation: u64) -> DesiredState {
        DesiredState {
            generation,
            required_features: vec!["replicas".into()],
            replicas: vec![Replica {
                replica_id: "web-1".into(),
                app: "web".into(),
                release: 1,
                image: buffa::MessageField::from(Image {
                    reference: "traefik/whoami:v1.10".into(),
                    digest: format!("sha256:{}", "e".repeat(64)),
                    ..Default::default()
                }),
                memory_mib: 64,
                cpu_millis: 100,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn a_document_applies_and_only_a_newer_generation_replaces_it() {
        let (local, dir) = local("generations");
        let handle = local.handle();
        assert_eq!(handle.apply(document(1)), Ok(()));
        assert_eq!(handle.apply(document(1)), Err(Refusal::Older));
        assert_eq!(handle.apply(document(2)), Ok(()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_local_document_passes_the_same_feature_checks_as_a_signed_one() {
        let (local, dir) = local("features");
        let handle = local.handle();
        let mut unknown = document(1);
        unknown.required_features.push("future-storage".into());
        assert_eq!(
            handle.apply(unknown),
            Err(Refusal::UnknownFeature("future-storage".into()))
        );
        let mut overridden = document(1);
        overridden.replicas[0].cmd = buffa::MessageField::from(Argv {
            args: vec!["serve".into()],
            ..Default::default()
        });
        assert_eq!(
            handle.apply(overridden.clone()),
            Err(Refusal::MissingProcessFeature)
        );
        overridden.required_features.push("process-overrides".into());
        assert_eq!(handle.apply(overridden), Ok(()));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
