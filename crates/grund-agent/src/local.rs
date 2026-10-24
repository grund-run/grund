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
//!
//! **Its network** ([`Local::with_network`]): the replicas get addresses on
//! a private network of one member, this machine, carried by grund-net's
//! mesh exactly as on a fleet machine, but with no iroh endpoint and no
//! relay: every packet stays on this machine. Instead of an instance
//! signing the membership list, it is built here from the apps loop's own
//! endpoints, with a newer epoch whenever a replica's address, ports or
//! readiness change. Every port of a replica is reachable from the others
//! (`AppReplica::open`), as on a Compose network. The stub resolver answers `<app>.grund.internal` and,
//! with a stack, `<app>.<stack>.grund.internal`, for ready replicas only,
//! and forwards other names to the resolvers in `/etc/resolv.conf`. Unlike
//! the agent, it never routes the host's own resolver to the stub. It needs
//! root (`CAP_NET_ADMIN`) for the TUN device.

use std::{
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, bail};
use grund_net::{
    membership::{AppReplica, Member, MembershipList, Port, Transport, replica_address},
    mesh::{Mesh, MeshConfig},
};
use grund_proto::grund::agent::v1::{DesiredState, ReplicaObserved};
use iroh::EndpointId;
use tokio::sync::watch;

use crate::{
    agent::{Refusal, check_features},
    apps::{Apps, NetworkAccess, ReplicaEndpoint, Shared},
    policy::Policy,
    runtime::ContainerRuntime,
    secrets,
};

pub const SLOT: u16 = 1;

pub const LOCAL_ID: &str = "local";

pub const MAX_TUN_NAME: usize = 15;

/// A project's private network. Keep `prefix` with the project so its
/// replicas keep their addresses across runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNetwork {
    /// A /48 in `fd00::/8`, such as one from [`random_prefix`].
    pub prefix: Ipv6Addr,
    /// The host's device for this network. It must differ from every other
    /// project's and from the agent's `grund0`.
    pub tun_name: String,
    /// The stack the replicas are services of, so `<app>.<stack>` resolves
    /// beside `<app>`. Each replica's `stack_search` must then be
    /// `<stack>.grund.internal`.
    pub stack: Option<String>,
}

/// A fresh /48 in `fd00::/8` with a random 40-bit global id, as grund gives
/// an organisation's network.
pub fn random_prefix() -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    getrandom::fill(&mut octets[1..6]).expect("the operating system provides randomness");
    Ipv6Addr::from(octets)
}

pub struct Local<C> {
    apps: Apps<C>,
    shared: Arc<Shared>,
    own: EndpointId,
    network: Option<Network>,
}

struct Network {
    config: LocalNetwork,
    own: EndpointId,
    mesh: Mesh,
    lists: watch::Sender<Option<MembershipList>>,
}

impl<C: ContainerRuntime + 'static> Local<C> {
    /// Writes `secret_values` (by replica id) to the encrypted cache under
    /// `data_dir`, keyed from `seed`, replacing any cache already there, and
    /// prepares the loop. `policy.volume_roots` bounds the host directories a
    /// replica may bind. `seed` is also the machine's key on its network.
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
        Ok(Self {
            apps,
            shared,
            own: grund_net::key::endpoint_id(seed),
            network: None,
        })
    }

    /// Gives the replicas addresses and names on `config`'s network once
    /// [`Local::run`] brings it up. Refuses a prefix outside `fd00::/8` or
    /// longer than /48, a stack that is not a DNS label, and a device name
    /// that is empty, longer than [`MAX_TUN_NAME`], not alphanumeric with
    /// `-` and `_`, or the agent's own.
    pub fn with_network(mut self, config: LocalNetwork) -> anyhow::Result<Self> {
        let name = &config.tun_name;
        if name.is_empty()
            || name.len() > MAX_TUN_NAME
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!(
                "network device name {name:?} must be 1 to {MAX_TUN_NAME} letters, digits, - or _"
            );
        }
        if name == crate::net::TUN_NAME {
            bail!("network device name {name:?} is the agent's own");
        }
        let probe = AppReplica {
            app: "probe".into(),
            replica_id: "probe".into(),
            address: replica_address(config.prefix, SLOT, "probe"),
            ports: Vec::new(),
            ready: false,
            aliases: config
                .stack
                .iter()
                .map(|stack| format!("probe.{stack}"))
                .collect(),
            open: true,
        };
        list(&config, self.own, 0, vec![probe])
            .validate()
            .with_context(|| format!("network {} for stack {:?}", config.prefix, config.stack))?;
        let mesh = Mesh::new(
            self.own,
            MeshConfig {
                tun_name: config.tun_name.clone(),
                relays: Vec::new(),
            },
        );
        let lists = watch::channel(None).0;
        let handle = Arc::new(std::sync::OnceLock::new());
        let _ = handle.set(mesh.clone());
        self.apps = self.apps.with_network(NetworkAccess {
            lists: lists.subscribe(),
            mesh: handle,
            own: self.own.to_string(),
        });
        self.network = Some(Network {
            config,
            own: self.own,
            mesh,
            lists,
        });
        Ok(self)
    }

    pub fn handle(&self) -> Handle {
        Handle {
            shared: self.shared.clone(),
        }
    }

    /// Runs the loop, and the network when it has one. Returns only when the
    /// network or its resolver fails.
    pub async fn run(self) -> anyhow::Result<()> {
        let Some(network) = self.network else {
            self.apps.run().await;
            return Ok(());
        };
        tokio::select! {
            () = self.apps.run() => Ok(()),
            result = network.mesh.run(network.lists.subscribe()) => result,
            () = publish(&network, self.shared.endpoints()) => Ok(()),
            result = resolve(&network) => result,
        }
    }
}

async fn publish(network: &Network, mut endpoints: watch::Receiver<Vec<ReplicaEndpoint>>) {
    let mut epoch = 0;
    let mut published: Option<Vec<AppReplica>> = None;
    loop {
        let apps = app_replicas(&network.config, &endpoints.borrow_and_update());
        if published.as_ref() != Some(&apps) {
            let next = list(&network.config, network.own, epoch + 1, apps.clone());
            match next.validate() {
                Ok(()) => {
                    epoch += 1;
                    network.lists.send_replace(Some(next));
                    published = Some(apps);
                }
                Err(error) => {
                    tracing::warn!(%error, "local network: list not published; names keep the last one")
                }
            }
        }
        if endpoints.changed().await.is_err() {
            return;
        }
    }
}

async fn resolve(network: &Network) -> anyhow::Result<()> {
    let own = network.mesh.up().await;
    let mut segments = own.segments();
    segments[7] = grund_net::dns::RESOLVER_HOST;
    let address = Ipv6Addr::from(segments);
    network.mesh.add_address(address)?;
    let socket = crate::net::bind_resolver(address).await?;
    let upstreams = grund_net::dns::upstreams(
        &std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
        network.config.prefix,
    );
    tracing::info!(%address, ?upstreams, "local network: resolving *.grund.internal");
    grund_net::dns::serve(socket, network.lists.subscribe(), network.own, upstreams)
        .await
        .context("the stub resolver stopped")
}

fn app_replicas(config: &LocalNetwork, endpoints: &[ReplicaEndpoint]) -> Vec<AppReplica> {
    let mut apps: Vec<AppReplica> = endpoints
        .iter()
        .filter(|e| !e.draining)
        .filter_map(|e| {
            let IpAddr::V6(address) = e.address else {
                return None;
            };
            if address != replica_address(config.prefix, SLOT, &e.replica_id) {
                return None;
            }
            let mut ports: Vec<Port> = e
                .ports
                .iter()
                .map(|p| Port {
                    transport: Transport::Tcp,
                    port: p.port,
                })
                .collect();
            ports.sort();
            ports.dedup();
            Some(AppReplica {
                app: e.app.clone(),
                replica_id: e.replica_id.clone(),
                address,
                ports,
                ready: e.ready,
                aliases: config
                    .stack
                    .iter()
                    .map(|stack| format!("{}.{stack}", e.app))
                    .collect(),
                open: true,
            })
        })
        .collect();
    apps.sort_by(|a, b| a.replica_id.cmp(&b.replica_id));
    apps
}

fn list(
    config: &LocalNetwork,
    own: EndpointId,
    epoch: u64,
    apps: Vec<AppReplica>,
) -> MembershipList {
    MembershipList {
        network_id: LOCAL_ID.into(),
        epoch,
        prefix: config.prefix,
        issued_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64),
        members: vec![Member {
            machine_id: LOCAL_ID.into(),
            endpoint_id: own.to_string(),
            slot: SLOT,
            name: None,
            ports: Vec::new(),
            relay_url: None,
            apps,
            direct_addrs: Vec::new(),
        }],
        relays: Vec::new(),
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
    use crate::{apps::EndpointPort, simulated::SimulatedContainers};
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

    fn network(stack: Option<&str>) -> LocalNetwork {
        LocalNetwork {
            prefix: "fd12:3456:789a::".parse().unwrap(),
            tun_name: "gup-shop".into(),
            stack: stack.map(Into::into),
        }
    }

    fn endpoint(config: &LocalNetwork, id: &str, ready: bool, draining: bool) -> ReplicaEndpoint {
        ReplicaEndpoint {
            replica_id: id.into(),
            app: "web".into(),
            address: IpAddr::V6(replica_address(config.prefix, SLOT, id)),
            ports: [8080, 80, 8080]
                .into_iter()
                .map(|port| EndpointPort {
                    name: format!("p{port}"),
                    port,
                    protocol: "http".into(),
                })
                .collect(),
            ready,
            draining,
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
        overridden
            .required_features
            .push("process-overrides".into());
        assert_eq!(handle.apply(overridden), Ok(()));
        let mut restarting = document(2);
        restarting.replicas[0].restart =
            buffa::MessageField::from(grund_proto::grund::agent::v1::RestartPolicy {
                mode: grund_proto::grund::agent::v1::RestartMode::RESTART_MODE_NEVER.into(),
                ..Default::default()
            });
        assert_eq!(
            handle.apply(restarting.clone()),
            Err(Refusal::MissingRestartFeature)
        );
        restarting.required_features.push("restart-policy".into());
        assert_eq!(handle.apply(restarting), Ok(()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_network_is_refused_for_a_bad_device_name_prefix_or_stack() {
        for (tun_name, prefix, stack) in [
            ("", "fd12:3456:789a::", None),
            ("grund-up-shop-01", "fd12:3456:789a::", None),
            ("gup shop", "fd12:3456:789a::", None),
            ("grund0", "fd12:3456:789a::", None),
            ("gup-shop", "fc12:3456:789a::", None),
            ("gup-shop", "fd12:3456:789a:1::", None),
            ("gup-shop", "fd12:3456:789a::", Some("Shop_1")),
        ] {
            let (local, dir) = local("refused");
            let config = LocalNetwork {
                prefix: prefix.parse().unwrap(),
                tun_name: tun_name.into(),
                stack: stack.map(Into::into),
            };
            assert!(
                local.with_network(config.clone()).is_err(),
                "{config:?} was accepted"
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
        let (local, dir) = local("accepted");
        assert!(local.with_network(network(Some("shop"))).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_list_names_addressed_replicas_that_are_not_draining() {
        let config = network(Some("shop"));
        let mut elsewhere = endpoint(&config, "web-3", true, false);
        elsewhere.address = "127.0.0.1".parse().unwrap();
        let apps = app_replicas(
            &config,
            &[
                endpoint(&config, "web-2", false, false),
                endpoint(&config, "web-1", true, false),
                endpoint(&config, "web-0", true, true),
                elsewhere,
            ],
        );
        assert_eq!(
            apps.iter()
                .map(|a| (a.replica_id.as_str(), a.ready))
                .collect::<Vec<_>>(),
            [("web-1", true), ("web-2", false)]
        );
        assert_eq!(apps[0].aliases, ["web.shop"]);
        assert!(apps.iter().all(|a| a.open));
        assert_eq!(
            apps[0].ports,
            [80, 8080].map(|port| Port {
                transport: Transport::Tcp,
                port
            })
        );
        assert!(
            app_replicas(
                &network(None),
                &[endpoint(&network(None), "web-1", true, false)]
            )[0]
            .aliases
            .is_empty()
        );
    }

    async fn next(
        publishing: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
        lists: &mut watch::Receiver<Option<MembershipList>>,
    ) -> MembershipList {
        tokio::select! {
            () = publishing.as_mut() => panic!("publishing stopped"),
            changed = lists.changed() => changed.unwrap(),
        }
        lists.borrow_and_update().clone().unwrap()
    }

    #[tokio::test]
    async fn each_change_in_the_endpoints_is_a_newer_epoch() {
        let (local, dir) = local("epochs");
        let local = local.with_network(network(Some("shop"))).unwrap();
        let network = local.network.as_ref().unwrap();
        let config = network.config.clone();
        let mut lists = network.lists.subscribe();
        let endpoints = watch::channel(Vec::new()).0;
        let publishing = publish(network, endpoints.subscribe());
        tokio::pin!(publishing);
        let first = next(&mut publishing, &mut lists).await;
        assert_eq!((first.epoch, first.members[0].apps.len()), (1, 0));
        endpoints.send_replace(vec![endpoint(&config, "web-1", false, false)]);
        let second = next(&mut publishing, &mut lists).await;
        assert_eq!(second.epoch, 2);
        assert!(!second.members[0].apps[0].ready);
        endpoints.send_replace(vec![endpoint(&config, "web-1", true, false)]);
        let third = next(&mut publishing, &mut lists).await;
        assert_eq!(third.epoch, 3);
        assert!(third.members[0].apps[0].ready);
        assert_eq!(third.member_by_id(&local.own).map(|m| m.slot), Some(SLOT));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
