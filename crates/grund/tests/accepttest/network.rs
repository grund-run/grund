use std::{
    net::Ipv6Addr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use crate::accepttest::fixtures::{
    Given, Then, When,
    netlab::{Lab, PUBLIC_URL, RELAY_URL},
    random_hex, testcase_in_lab,
};

const MACHINES: &str = "/grund.machine.v1.MachineService";

struct Net {
    lab: Arc<Lab>,
    given: Given,
    when: When,
    then: Then,
    owner: String,
}

struct Machine {
    node: &'static str,
    name: String,
    dir: PathBuf,
    record: Value,
}

impl Machine {
    fn id(&self) -> String {
        self.record["machine_id"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn slot(&self) -> u16 {
        self.record["network"]["slot"].as_u64().unwrap_or_default() as u16
    }

    fn prefix(&self) -> Ipv6Addr {
        self.record["network"]["prefix"]
            .as_str()
            .unwrap_or_default()
            .parse()
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
    }

    fn host(&self, host: u16) -> Ipv6Addr {
        let mut segments = self.prefix().segments();
        segments[3] = self.slot();
        segments[7] = host;
        Ipv6Addr::from(segments)
    }

    fn address(&self) -> Ipv6Addr {
        self.host(1)
    }

    fn resolver(&self) -> Ipv6Addr {
        self.host(0x53)
    }

    fn fqdn(&self) -> String {
        format!("{}.machines.grund.internal", self.name)
    }

    fn endpoint_id(&self) -> String {
        let seed = std::fs::read_to_string(self.dir.join("machine.key")).unwrap_or_default();
        let seed: [u8; 32] = hex::decode(seed.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0; 32]);
        grund_net::key::endpoint_id(&seed).to_string()
    }

    fn seed(&self) -> String {
        std::fs::read_to_string(self.dir.join("machine.key"))
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    fn status(&self) -> Value {
        std::fs::read_to_string(self.dir.join("network.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null)
    }

    fn peer(&self, other: &Machine) -> Value {
        let id = other.endpoint_id();
        self.status()["mesh"]["peers"]
            .as_array()
            .and_then(|peers| {
                peers
                    .iter()
                    .find(|p| p["endpoint_id"] == id.as_str())
                    .cloned()
            })
            .unwrap_or(Value::Null)
    }

    fn path_to(&self, other: &Machine) -> String {
        self.peer(other)["path"]
            .as_str()
            .unwrap_or("none")
            .to_string()
    }

    fn counter(&self, name: &str) -> u64 {
        self.status()["mesh"]["counters"][name]
            .as_u64()
            .unwrap_or_default()
    }

    fn relays(&self) -> Vec<Value> {
        self.status()["relays"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    fn relay(&self, url: &str) -> Value {
        self.relays()
            .into_iter()
            .find(|r| r["url"].as_str().is_some_and(|u| u.starts_with(url)))
            .unwrap_or(Value::Null)
    }

    fn epoch(&self) -> u64 {
        self.status()["mesh"]["epoch"].as_u64().unwrap_or_default()
    }
}

async fn eventually<F, Fut>(within: Duration, mut condition: F) -> Option<Duration>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < within {
        if condition().await {
            return Some(start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

async fn a_lab() -> anyhow::Result<Option<Net>> {
    let Some(lab) = Lab::start().await? else {
        return Ok(None);
    };
    a_lab_with(lab, &[]).await
}

async fn a_lab_with(lab: Arc<Lab>, env: &[(&str, &str)]) -> anyhow::Result<Option<Net>> {
    let (given, when, then) = testcase_in_lab(lab.clone(), env).await?;
    let owner = given.a_signed_in_account().await?.username;
    Ok(Some(Net {
        lab,
        given,
        when,
        then,
        owner,
    }))
}

impl Net {
    async fn join_token(
        &self,
        when: &When,
        then: &Then,
        organisation: &str,
        name: &str,
    ) -> anyhow::Result<String> {
        when.calling(
            &format!("{MACHINES}/CreateJoinToken"),
            &json!({"organisation": organisation, "name": name}).to_string(),
        )
        .await?;
        then.status(200)?;
        Ok(then.json()?["token"]
            .as_str()
            .unwrap_or_default()
            .to_string())
    }

    async fn join(&self, node: &'static str, name: &str) -> anyhow::Result<Machine> {
        let token = self
            .join_token(&self.when, &self.then, &self.owner, name)
            .await?;
        self.join_with(node, name, &token).await
    }

    async fn join_with(
        &self,
        node: &'static str,
        name: &str,
        token: &str,
    ) -> anyhow::Result<Machine> {
        self.join_with_env(node, name, token, &[]).await
    }

    async fn join_with_env(
        &self,
        node: &'static str,
        name: &str,
        token: &str,
        env: &[(&str, &str)],
    ) -> anyhow::Result<Machine> {
        let dir = self.lab.work.join(format!("agent-{node}"));
        let ca = self.lab.ca.to_string_lossy().into_owned();
        let out = self
            .lab
            .run_async(
                node,
                &[
                    "env",
                    &format!("SSL_CERT_FILE={ca}"),
                    "RUST_LOG=warn",
                    env!("CARGO_BIN_EXE_grund"),
                    "join",
                    "--url",
                    PUBLIC_URL,
                    "--data-dir",
                    &dir.to_string_lossy(),
                    token,
                ],
            )
            .await?;
        anyhow::ensure!(
            out.status.success(),
            "grund join in {node}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let record: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("machine.json"))?)?;
        anyhow::ensure!(
            record["network"]["relay_urls"]
                .as_array()
                .is_some_and(|r| !r.is_empty()),
            "the machine is told grund's relays: {record}"
        );
        self.lab.spawn(
            node,
            &[
                env!("CARGO_BIN_EXE_grund"),
                "agent",
                "--vm-runtime",
                "simulated",
                "--data-dir",
                &dir.to_string_lossy(),
            ],
            &[
                &[
                    ("SSL_CERT_FILE", ca.as_str()),
                    ("RUST_LOG", "grund_agent=debug,grund_net=debug,info"),
                ][..],
                env,
            ]
            .concat(),
            &format!("agent-{node}.log"),
        )?;
        let machine = Machine {
            node,
            name: name.to_string(),
            dir,
            record,
        };
        let up = eventually(Duration::from_secs(30), || async {
            machine.status()["mesh"]["address"] == machine.address().to_string()
        })
        .await;
        anyhow::ensure!(
            up.is_some(),
            "{node} never came up at {}: {}\n{}",
            machine.address(),
            machine.status(),
            self.log(&format!("agent-{node}.log"))
        );
        self.lab
            .use_resolver(node, &machine.resolver().to_string())?;
        Ok(machine)
    }

    fn log(&self, name: &str) -> String {
        std::fs::read_to_string(self.lab.work.join(name)).unwrap_or_default()
    }

    async fn pings(&self, from: &Machine, to: &str) -> bool {
        self.lab
            .succeeds(
                from.node,
                &["ping", "-6", "-c", "2", "-i", "0.2", "-W", "2", to],
            )
            .await
    }

    async fn reaches_by_name(
        &self,
        from: &Machine,
        to: &Machine,
        within: Duration,
    ) -> Option<Duration> {
        let name = to.fqdn();
        eventually(within, || self.pings(from, &name)).await
    }
}

fn ipv4_of(addrs: &Value) -> Vec<String> {
    addrs
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(|s| {
                    s.rsplit_once(':')
                        .map(|(ip, _)| ip)
                        .unwrap_or(s)
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn two_machines_join_then_reach_each_other_by_name_over_a_path_punched_through_nat()
-> anyhow::Result<()> {
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    for (device, address) in [
        ("docker0", "172.17.0.1/16"),
        ("wg0", "10.99.0.5/24"),
        ("tailscale0", "100.101.1.2/32"),
    ] {
        let out = net
            .lab
            .run_async("a", &["ip", "link", "add", device, "type", "dummy"])
            .await?;
        anyhow::ensure!(out.status.success(), "{out:?}");
        net.lab
            .run_async("a", &["ip", "addr", "add", address, "dev", device])
            .await?;
        net.lab
            .run_async("a", &["ip", "link", "set", device, "up"])
            .await?;
    }
    let a = net.join("a", "web-1").await?;
    let b = net.join("b", "db").await?;

    let reached = net.reaches_by_name(&a, &b, Duration::from_secs(30)).await;
    anyhow::ensure!(
        reached.is_some(),
        "a never reached {} by name: {}\n{}",
        b.fqdn(),
        a.status(),
        net.log("agent-a.log")
    );
    anyhow::ensure!(
        net.reaches_by_name(&b, &a, Duration::from_secs(10))
            .await
            .is_some(),
        "b never reached {} by name",
        a.fqdn()
    );
    let direct = eventually(Duration::from_secs(30), || async {
        net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("direct")
    })
    .await;
    anyhow::ensure!(
        direct.is_some(),
        "the path from a to b never turned direct: {}",
        a.status()
    );

    let out = net
        .lab
        .run_async(
            "a",
            &["getent", "ahostsv6", "cache.machines.grund.internal"],
        )
        .await?;
    anyhow::ensure!(
        !out.status.success(),
        "a name that is no member's resolves: {out:?}"
    );
    let out = net
        .lab
        .run_async("a", &["getent", "ahostsv6", &b.fqdn()])
        .await?;
    anyhow::ensure!(
        String::from_utf8_lossy(&out.stdout).contains(&b.address().to_string()),
        "{out:?}"
    );

    anyhow::ensure!(
        ipv4_of(&a.status()["bound"])
            .iter()
            .all(|ip| ip == "10.1.0.2"),
        "a binds only its uplink: {}",
        a.status()["bound"]
    );
    let offered = ipv4_of(&b.peer(&a)["direct_addrs"]);
    for never in ["172.17.0.1", "10.99.0.5", "100.101.1.2"] {
        anyhow::ensure!(
            !offered.iter().any(|ip| ip == never),
            "a offered {never} to b: {offered:?}"
        );
    }
    anyhow::ensure!(
        offered
            .iter()
            .any(|ip| ip == crate::accepttest::fixtures::netlab::NAT_A),
        "b knows a by its NAT's public address: {offered:?}"
    );
    eprintln!("by name after {reached:?}, direct after {direct:?}; b knows a at {offered:?}");
    let _ = &net.given;
    Ok(())
}

#[tokio::test]
async fn traffic_moves_to_the_relay_when_direct_udp_is_cut_and_back_when_it_returns()
-> anyhow::Result<()> {
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some()
    );
    let direct = || async {
        net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("direct")
    };
    anyhow::ensure!(
        eventually(Duration::from_secs(30), direct).await.is_some(),
        "{}",
        a.status()
    );

    net.lab.cut_direct_udp().await?;
    let relayed = eventually(Duration::from_secs(20), || async {
        net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("relay")
    })
    .await;
    anyhow::ensure!(relayed.is_some(), "never over the relay: {}", a.status());
    anyhow::ensure!(
        net.pings(&a, &b.fqdn()).await && net.pings(&b, &a.fqdn()).await,
        "traffic does not flow over the relay"
    );

    net.lab.restore_direct_udp().await?;
    let back = eventually(Duration::from_secs(90), direct).await;
    anyhow::ensure!(back.is_some(), "never direct again: {}", a.status());
    eprintln!("over the relay after {relayed:?}, direct again after {back:?}");
    Ok(())
}

const DIRECT_AGAIN_WITHIN: Duration = Duration::from_secs(10);
const PAST_IROH_SCHEDULED_RETRY: Duration = Duration::from_secs(15);
const NEVER_PUNCHES_FOR: Duration = Duration::from_secs(100);
const PROBES_IN_100_S: u64 = 5;

#[tokio::test]
async fn a_direct_path_cut_past_iroh_retry_comes_back_within_seconds_through_a_probe()
-> anyhow::Result<()> {
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some()
    );
    let direct = || async {
        net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("direct")
    };
    anyhow::ensure!(
        eventually(Duration::from_secs(30), direct).await.is_some(),
        "{}",
        a.status()
    );

    net.lab.cut_direct_udp().await?;
    let relayed = eventually(Duration::from_secs(20), || async {
        net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("relay")
    })
    .await;
    anyhow::ensure!(relayed.is_some(), "never over the relay: {}", a.status());
    tokio::time::sleep(PAST_IROH_SCHEDULED_RETRY).await;
    anyhow::ensure!(
        net.pings(&a, &b.fqdn()).await,
        "traffic does not flow over the relay"
    );

    net.lab.restore_direct_udp().await?;
    let back = eventually(DIRECT_AGAIN_WITHIN, direct).await;
    anyhow::ensure!(
        back.is_some(),
        "not direct again within {DIRECT_AGAIN_WITHIN:?}: {}",
        a.status()
    );
    eprintln!(
        "over the relay after {relayed:?}; cut {PAST_IROH_SCHEDULED_RETRY:?} more; direct again after {back:?}; probes a {} b {}",
        a.counter("probes_sent"),
        b.counter("probes_sent")
    );
    Ok(())
}

#[tokio::test]
async fn a_peer_that_never_punches_costs_a_few_probes_on_a_backoff() -> anyhow::Result<()> {
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some()
    );
    net.lab.cut_direct_udp().await?;
    anyhow::ensure!(
        eventually(Duration::from_secs(20), || async {
            net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("relay")
        })
        .await
        .is_some(),
        "never over the relay: {}",
        a.status()
    );
    let (sent_a, sent_b) = (a.counter("probes_sent"), b.counter("probes_sent"));
    let (bytes_a, bytes_b) = (a.counter("probe_bytes"), b.counter("probe_bytes"));
    let start = Instant::now();
    while start.elapsed() < NEVER_PUNCHES_FOR {
        anyhow::ensure!(
            net.pings(&a, &b.address().to_string()).await,
            "traffic stopped over the relay: {}",
            a.status()
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let probes = [
        a.counter("probes_sent") - sent_a,
        b.counter("probes_sent") - sent_b,
    ];
    let bytes = [
        a.counter("probe_bytes") - bytes_a,
        b.counter("probe_bytes") - bytes_b,
    ];
    eprintln!(
        "relayed {NEVER_PUNCHES_FOR:?}: probes a {} b {}, answered a {} b {}, failed a {} b {}, bytes a {} b {}; path {}",
        probes[0],
        probes[1],
        a.counter("probes_answered"),
        b.counter("probes_answered"),
        a.counter("probes_failed"),
        b.counter("probes_failed"),
        bytes[0],
        bytes[1],
        a.path_to(&b)
    );
    anyhow::ensure!(
        probes.iter().all(|&p| (1..=PROBES_IN_100_S).contains(&p)),
        "probes {probes:?} in {NEVER_PUNCHES_FOR:?}, expected 1 to {PROBES_IN_100_S} a side"
    );
    anyhow::ensure!(
        a.path_to(&b).starts_with("relay"),
        "the path left the relay with UDP cut: {}",
        a.status()
    );
    Ok(())
}

#[tokio::test]
async fn a_revoked_machine_is_dropped_by_its_peers_within_seconds() -> anyhow::Result<()> {
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some()
    );
    let epoch = a.epoch();

    let revoked_at = Instant::now();
    net.when
        .calling(
            &format!("{MACHINES}/RevokeMachine"),
            &json!({"organisation": net.owner, "machineId": b.id()}).to_string(),
        )
        .await?;
    net.then.status(200)?;
    let answered = revoked_at.elapsed();
    let dropped = eventually(Duration::from_secs(10), || async {
        a.epoch() > epoch && a.peer(&b).is_null()
    })
    .await;
    anyhow::ensure!(dropped.is_some(), "a still holds b: {}", a.status());
    anyhow::ensure!(
        dropped.unwrap() <= Duration::from_secs(5),
        "a dropped b after {dropped:?}, past the 5 s target"
    );
    anyhow::ensure!(
        !net.pings(&a, &b.address().to_string()).await,
        "a still reaches b"
    );
    anyhow::ensure!(
        !net.pings(&b, &a.address().to_string()).await,
        "b still reaches a"
    );
    let out = net
        .lab
        .run_async("a", &["getent", "ahostsv6", &b.fqdn()])
        .await?;
    anyhow::ensure!(
        !out.status.success(),
        "b's name still resolves on a: {out:?}"
    );
    eprintln!("RevokeMachine answered in {answered:?}; a dropped b {dropped:?} after that");
    Ok(())
}

#[tokio::test]
async fn a_machine_of_another_account_is_refused_and_its_names_are_its_own() -> anyhow::Result<()> {
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "shared").await?;
    let (other_given, other_when, other_then) = net.when.testcase.another_browser();
    let intruder = other_given.a_signed_in_account().await?.username;
    let token = net
        .join_token(&other_when, &other_then, &intruder, "shared")
        .await?;
    let c = net.join_with("c", "shared", &token).await?;
    anyhow::ensure!(a.prefix() != c.prefix(), "two accounts share a prefix");

    let out = net
        .lab
        .run_async("c", &["getent", "ahostsv6", &c.fqdn()])
        .await?;
    anyhow::ensure!(
        String::from_utf8_lossy(&out.stdout).contains(&c.address().to_string())
            && !String::from_utf8_lossy(&out.stdout).contains(&a.address().to_string()),
        "the same name in another account is that account's machine: {out:?}"
    );
    anyhow::ensure!(
        !net.pings(&c, &a.address().to_string()).await,
        "c reaches a"
    );

    let received = a.counter("received");
    let refused = a.counter("refused_non_members");
    let inject = |key: String| {
        let lab = net.lab.clone();
        let (ca, to, src) = (
            lab.ca.to_string_lossy().into_owned(),
            a.endpoint_id(),
            c.address().to_string(),
        );
        let dst = a.address().to_string();
        async move {
            lab.run_async(
                "c",
                &[
                    &crate::accepttest::fixtures::netlab::lab_binary().to_string_lossy(),
                    "inject",
                    "--key",
                    &key,
                    "--relay",
                    RELAY_URL,
                    "--relay-root",
                    &ca,
                    "--to",
                    &to,
                    "--src",
                    &src,
                    "--dst",
                    &dst,
                ],
            )
            .await
        }
    };
    let out = inject(c.seed()).await?;
    let answer = String::from_utf8_lossy(&out.stdout).to_string();
    anyhow::ensure!(
        eventually(Duration::from_secs(5), || async {
            a.counter("refused_non_members") > refused
        })
        .await
        .is_some(),
        "a did not refuse the other account's machine: {answer} {}",
        a.status()
    );
    let unknown = inject(random_hex(32)).await?;
    anyhow::ensure!(
        a.counter("received") == received,
        "a took packets from outside its network: {answer} / {}",
        String::from_utf8_lossy(&unknown.stdout)
    );
    eprintln!(
        "another account's machine: {answer}; an unknown key: {}",
        String::from_utf8_lossy(&unknown.stdout)
    );
    Ok(())
}

#[tokio::test]
async fn a_machine_whose_uplink_address_changes_rebinds_and_is_reached_again() -> anyhow::Result<()>
{
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some()
    );

    let moved_at = Instant::now();
    for step in [
        vec!["ip", "addr", "add", "10.1.0.3/24", "dev", "eth0"],
        vec!["ip", "addr", "del", "10.1.0.2/24", "dev", "eth0"],
        vec!["ip", "route", "replace", "default", "via", "10.1.0.1"],
    ] {
        let out = net.lab.run_async("a", &step).await?;
        anyhow::ensure!(out.status.success(), "{step:?}: {out:?}");
    }
    let rebound = eventually(Duration::from_secs(10), || async {
        a.status()["rebinds"].as_u64().unwrap_or_default() >= 1
            && ipv4_of(&a.status()["bound"]) == vec!["10.1.0.3".to_string()]
    })
    .await;
    anyhow::ensure!(rebound.is_some(), "a did not rebind: {}", a.status());
    let again = net.reaches_by_name(&a, &b, Duration::from_secs(30)).await;
    anyhow::ensure!(again.is_some(), "a never reached b again: {}", a.status());
    anyhow::ensure!(
        net.reaches_by_name(&b, &a, Duration::from_secs(30))
            .await
            .is_some(),
        "b never reached a again: {}",
        b.status()
    );
    eprintln!(
        "rebound after {rebound:?}, reached b again {again:?} later ({:?} in all)",
        moved_at.elapsed()
    );
    Ok(())
}

#[tokio::test]
async fn a_relay_behind_a_tls_proxy_with_address_discovery_elsewhere_still_punches_and_relays()
-> anyhow::Result<()> {
    let Some(iroh_relay) = std::env::var("GRUND_ACCEPT_IROH_RELAY")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        eprintln!("skipped: needs iroh-relay 1.2.0's binary at GRUND_ACCEPT_IROH_RELAY");
        return Ok(());
    };
    let Some(lab) = Lab::start().await? else {
        return Ok(());
    };
    let bin = crate::accepttest::fixtures::netlab::lab_binary();
    let (cert, key) = (
        lab.cert.to_string_lossy().into_owned(),
        lab.key.to_string_lossy().into_owned(),
    );
    lab.spawn(
        "lh",
        &[
            &bin.to_string_lossy(),
            "forward",
            "--listen",
            "tcp:198.51.100.1:8443",
            "--tls-cert",
            &cert,
            "--tls-key",
            &key,
            "--to",
            "tcp:127.0.0.1:8444",
        ],
        &[],
        "relay-proxy.log",
    )?;
    let config = lab.work.join("iroh-relay-qad.toml");
    std::fs::write(
        &config,
        format!(
            "enable_relay = false\nenable_quic_addr_discovery = true\nenable_metrics = false\n\
             [tls]\ncert_mode = \"Manual\"\ndangerous_http_only = true\n\
             manual_cert_path = \"{cert}\"\nmanual_key_path = \"{key}\"\n\
             quic_bind_addr = \"198.51.100.1:7842\"\n"
        ),
    )?;
    lab.spawn(
        "lh",
        &[&iroh_relay, "--config-path", &config.to_string_lossy()],
        &[("RUST_LOG", "info")],
        "iroh-relay-qad.log",
    )?;
    let Some(net) = a_lab_with(
        lab,
        &[
            ("GRUND_RELAY_ADDRESS", "127.0.0.1:8444"),
            ("GRUND_RELAY_TLS_CERT_FILE", ""),
            ("GRUND_RELAY_TLS_KEY_FILE", ""),
            ("GRUND_RELAY_QUIC_ADDRESS", ""),
        ],
    )
    .await?
    else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    let reached = net.reaches_by_name(&a, &b, Duration::from_secs(30)).await;
    anyhow::ensure!(reached.is_some(), "a never reached b: {}", a.status());
    let direct = || async {
        net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("direct")
    };
    let punched = eventually(Duration::from_secs(30), direct).await;
    anyhow::ensure!(
        punched.is_some(),
        "no punch with address discovery apart from the relay: {}\n{}",
        a.status(),
        net.log("iroh-relay-qad.log")
    );
    net.lab.cut_direct_udp().await?;
    let relayed = eventually(Duration::from_secs(20), || async {
        net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("relay")
    })
    .await;
    anyhow::ensure!(
        relayed.is_some(),
        "the proxied relay did not carry traffic: {}",
        a.status()
    );
    let listening = net.lab.run_async("lh", &["ss", "-lntup"]).await?;
    eprintln!(
        "by name {reached:?}, direct {punched:?}, relayed {relayed:?}; lh listens:\n{}",
        String::from_utf8_lossy(&listening.stdout)
    );
    Ok(())
}

#[tokio::test]
async fn names_and_paths_keep_working_from_the_last_list_while_grund_is_down() -> anyhow::Result<()>
{
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some()
    );
    let direct = eventually(Duration::from_secs(30), || async {
        net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("direct")
    })
    .await;
    anyhow::ensure!(direct.is_some(), "never direct: {}", a.status());
    let epoch = a.epoch();

    let failures = || {
        net.log("agent-a.log")
            .matches("GetMembership failed")
            .count()
    };
    let before = failures();
    anyhow::ensure!(net.lab.stop("grund.log"), "grund was not running");
    let noticed = eventually(Duration::from_secs(30), || async { failures() > before }).await;
    anyhow::ensure!(
        noticed.is_some(),
        "a never lost grund:\n{}",
        net.log("agent-a.log")
    );
    tokio::time::sleep(Duration::from_secs(12)).await;
    anyhow::ensure!(
        a.epoch() == epoch,
        "the list changed without grund: {}",
        a.status()
    );
    let out = net
        .lab
        .run_async("a", &["getent", "ahostsv6", &b.fqdn()])
        .await?;
    anyhow::ensure!(
        String::from_utf8_lossy(&out.stdout).contains(&b.address().to_string()),
        "b's name stopped resolving with grund down: {out:?}"
    );
    anyhow::ensure!(
        net.pings(&a, &b.fqdn()).await && net.pings(&b, &a.fqdn()).await,
        "the members lost each other with grund down: {}",
        a.status()
    );
    eprintln!("a noticed grund was gone after {noticed:?}; names and the direct path held");
    Ok(())
}

#[tokio::test]
async fn a_new_address_beside_the_bound_one_is_a_network_change_not_a_rebind() -> anyhow::Result<()>
{
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some()
    );
    let before = a.status()["network_changes"].as_u64().unwrap_or_default();

    let out = net
        .lab
        .run_async("a", &["ip", "addr", "add", "10.1.0.9/24", "dev", "eth0"])
        .await?;
    anyhow::ensure!(out.status.success(), "{out:?}");
    let told = eventually(Duration::from_secs(10), || async {
        a.status()["network_changes"].as_u64().unwrap_or_default() > before
    })
    .await;
    anyhow::ensure!(told.is_some(), "iroh was not told: {}", a.status());
    anyhow::ensure!(
        a.status()["rebinds"].as_u64() == Some(0)
            && ipv4_of(&a.status()["bound"]) == vec!["10.1.0.2".to_string()],
        "a rebound for an address beside the one it holds: {}",
        a.status()
    );
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(10))
            .await
            .is_some(),
        "a lost b after the change: {}",
        a.status()
    );
    eprintln!("network_change after {told:?}, no rebind");
    Ok(())
}

const RELAY_TOKEN: &str = "relay-token-0123456789abcdef01234567";

fn relays_elsewhere(relays: &str) -> Vec<(&'static str, String)> {
    vec![
        ("GRUND_RELAY_ADDRESS", String::new()),
        ("GRUND_RELAY_URL", String::new()),
        ("GRUND_RELAY_TLS_CERT_FILE", String::new()),
        ("GRUND_RELAY_TLS_KEY_FILE", String::new()),
        ("GRUND_RELAY_QUIC_ADDRESS", String::new()),
        ("GRUND_RELAYS", relays.to_string()),
        ("GRUND_RELAY_ACCESS_TOKEN", RELAY_TOKEN.to_string()),
    ]
}

fn as_env<'a>(settings: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    settings.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

#[tokio::test]
async fn grund_relay_on_its_own_host_carries_the_mesh_and_a_second_is_picked_up_without_a_rejoin()
-> anyhow::Result<()> {
    use crate::accepttest::fixtures::netlab::{RELAY_1, RELAY_2};
    let Some(lab) = Lab::start().await? else {
        return Ok(());
    };
    let first = format!("https://{RELAY_1}");
    let second = format!("https://{RELAY_2}");
    lab.spawn_relay("rl1", RELAY_1, RELAY_TOKEN)?;
    let settings = relays_elsewhere(&format!("lab-1={first}"));
    let Some(net) = a_lab_with(lab, &as_env(&settings)).await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        a.record["network"]["relay_urls"] == json!([first]),
        "{}",
        a.record
    );
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some(),
        "a never reached b through grund relay: {}\n{}",
        a.status(),
        net.log("relay-rl1.log")
    );
    let punched = eventually(Duration::from_secs(30), || async {
        net.pings(&a, &b.address().to_string()).await && a.path_to(&b).starts_with("direct")
    })
    .await;
    anyhow::ensure!(
        punched.is_some(),
        "no punch via grund relay's address discovery: {}",
        a.status()
    );
    anyhow::ensure!(a.relay(&first)["connected"] == true, "{}", a.status());
    let epoch = a.epoch();

    net.lab.spawn_relay("rl2", RELAY_2, RELAY_TOKEN)?;
    let both = relays_elsewhere(&format!("lab-1={first},lab-2={second}"));
    net.when
        .testcase
        .fixture
        .restart_in_lab(&as_env(&both))
        .await?;
    let picked = eventually(Duration::from_secs(30), || async {
        !a.relay(&second).is_null() && !b.relay(&second).is_null() && a.epoch() > epoch
    })
    .await;
    anyhow::ensure!(
        picked.is_some(),
        "the second relay never reached the machines: {}",
        a.status()
    );
    anyhow::ensure!(
        a.status()["rebinds"] == 0 && a.counter("endpoints_attached") == 1,
        "a picked up the relay by rebinding: {}",
        a.status()
    );
    let hinted = eventually(Duration::from_secs(20), || async {
        let home = b
            .relays()
            .into_iter()
            .find(|r| r["home"] == true && r["connected"] == true)
            .and_then(|r| {
                r["url"]
                    .as_str()
                    .map(|u| u.trim_end_matches('/').to_string())
            });
        home.is_some() && a.peer(&b)["relay_hint"].as_str() == home.as_deref()
    })
    .await;
    anyhow::ensure!(
        hinted.is_some(),
        "a does not know b's home relay: a {} / b {}",
        a.status(),
        b.status()
    );

    net.lab.stop("relay-rl1.log");
    net.lab.cut_direct_udp().await?;
    let moved = eventually(Duration::from_secs(60), || async {
        net.pings(&a, &b.address().to_string()).await
            && a.path_to(&b).starts_with(&format!("relay {second}"))
    })
    .await;
    anyhow::ensure!(
        moved.is_some(),
        "with the first relay gone and no direct UDP, a never reached b over the second: {}\nb: {}\n{}",
        a.status(),
        b.status(),
        net.log("relay-rl2.log")
    );
    anyhow::ensure!(net.pings(&b, &a.fqdn()).await, "b does not reach a by name");
    eprintln!(
        "by name and direct through grund relay; second relay picked up {picked:?} after grund restarted; over it {moved:?} after the first stopped"
    );
    Ok(())
}

#[tokio::test]
async fn grund_relay_on_its_own_host_refuses_a_revoked_machine() -> anyhow::Result<()> {
    use crate::accepttest::fixtures::netlab::RELAY_1;
    let Some(lab) = Lab::start().await? else {
        return Ok(());
    };
    let first = format!("https://{RELAY_1}");
    lab.spawn_relay("rl1", RELAY_1, RELAY_TOKEN)?;
    let settings = relays_elsewhere(&first);
    let Some(net) = a_lab_with(lab, &as_env(&settings)).await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some()
    );
    anyhow::ensure!(
        eventually(Duration::from_secs(10), || async {
            b.relay(&first)["connected"] == true
        })
        .await
        .is_some(),
        "{}",
        b.status()
    );

    net.when
        .calling(
            &format!("{MACHINES}/RevokeMachine"),
            &json!({"organisation": net.owner, "machineId": b.id()}).to_string(),
        )
        .await?;
    net.then.status(200)?;
    let cut = eventually(Duration::from_secs(15), || async {
        b.relay(&first)["connected"] == false
    })
    .await;
    anyhow::ensure!(
        cut.is_some(),
        "the relay kept the revoked machine: {}",
        b.status()
    );
    let denied = eventually(Duration::from_secs(30), || async {
        b.relay(&first)["denied"]
            .as_str()
            .is_some_and(|reason| reason.contains("not a machine"))
    })
    .await;
    anyhow::ensure!(
        denied.is_some(),
        "the revoked machine was not refused at reconnect: {}\n{}",
        b.status(),
        net.log("relay-rl1.log")
    );
    anyhow::ensure!(
        a.relay(&first)["connected"] == true,
        "the relay dropped a machine still in the network: {}",
        a.status()
    );
    eprintln!("revoked: cut after {cut:?}, refused at reconnect after {denied:?} more");
    Ok(())
}

#[tokio::test]
async fn names_resolve_through_systemd_resolved_which_the_agent_points_at_the_stub()
-> anyhow::Result<()> {
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let Some(bus) = net.lab.start_resolved("a").await? else {
        eprintln!(
            "skipped: the lab cannot run systemd-resolved here (needs /etc/subuid, newuidmap, \
             dbus-daemon and systemd-resolved); the D-Bus calls are tested against a fake"
        );
        return Ok(());
    };
    let token = net
        .join_token(&net.when, &net.then, &net.owner, "a")
        .await?;
    let a = net
        .join_with_env("a", "a", &token, &[("DBUS_SYSTEM_BUS_ADDRESS", &bus)])
        .await?;
    let b = net.join("b", "b").await?;
    net.lab.use_resolver("a", "127.0.0.53")?;
    net.lab
        .set_nsswitch("a", "files resolve [!UNAVAIL=return] dns")?;
    let configured = eventually(Duration::from_secs(10), || async {
        a.status()["host_resolver"]["state"] == "configured"
    })
    .await;
    anyhow::ensure!(
        configured.is_some(),
        "the agent did not configure resolved: {}\n{}",
        a.status(),
        net.log("resolved-a.log")
    );
    let resolvectl = |args: Vec<String>| {
        let lab = net.lab.clone();
        let bus = bus.clone();
        async move {
            let mut all = vec![
                "env".to_string(),
                format!("DBUS_SYSTEM_BUS_ADDRESS={bus}"),
                "resolvectl".into(),
            ];
            all.extend(args);
            let all: Vec<&str> = all.iter().map(String::as_str).collect();
            lab.run_async("a", &all)
                .await
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        }
    };
    let link = resolvectl(vec!["status".into(), "grund0".into()]).await?;
    anyhow::ensure!(
        link.contains(&a.resolver().to_string())
            && link.contains("~grund.internal")
            && link.contains("-DefaultRoute"),
        "resolved's view of grund0: {link}"
    );
    let answer = resolvectl(vec!["query".into(), b.fqdn()]).await?;
    anyhow::ensure!(
        answer.contains(&b.address().to_string()),
        "resolved did not answer {} from the stub: {answer}",
        b.fqdn()
    );
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some(),
        "a did not reach b by name through resolved"
    );
    let unknown = net
        .lab
        .run_async(
            "a",
            &["getent", "ahostsv6", "cache.machines.grund.internal"],
        )
        .await?;
    anyhow::ensure!(
        !unknown.status.success(),
        "a non-member resolves through resolved"
    );

    let pid = net
        .lab
        .pid_of("agent-a.log")
        .map(|p| p.to_string())
        .unwrap_or_default();
    let out = std::process::Command::new("kill")
        .args(["-TERM", &pid])
        .output()?;
    anyhow::ensure!(out.status.success(), "{out:?}");
    let reverted = eventually(Duration::from_secs(10), || async {
        net.log("agent-a.log")
            .contains("settings for grund0 reverted")
    })
    .await;
    anyhow::ensure!(reverted.is_some(), "the agent did not revert on SIGTERM");
    let after = resolvectl(vec!["status".into()]).await?;
    anyhow::ensure!(
        !after.contains("~grund.internal"),
        "grund0's settings outlived the agent: {after}"
    );
    eprintln!("resolved routed ~grund.internal on grund0 to the stub; reverted on SIGTERM");
    Ok(())
}

const ECHO_SERVER: &str = r#"
import socket, sys
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", int(sys.argv[1])))
s.listen(16)
while True:
    c, _ = s.accept()
    c.sendall(c.recv(64))
    c.close()
"#;

const ECHO_CLIENT: &str = r#"
import socket, sys
c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)
c.sendall(b"hello")
sys.exit(0 if c.recv(64) == b"hello" else 1)
"#;

impl Net {
    async fn echoes(&self, from: &Machine, to: &Machine, port: u16) -> bool {
        self.lab
            .succeeds(
                from.node,
                &[
                    "python3",
                    "-c",
                    ECHO_CLIENT,
                    &to.address().to_string(),
                    &port.to_string(),
                ],
            )
            .await
    }

    async fn declare(&self, machine: &Machine, ports: Value) -> anyhow::Result<()> {
        self.when
            .calling(
                &format!("{MACHINES}/DeclareMachinePorts"),
                &json!({"organisation": self.owner, "machineId": machine.id(), "ports": ports})
                    .to_string(),
            )
            .await?;
        self.then.status(200)?;
        Ok(())
    }
}

#[tokio::test]
async fn a_member_reaches_only_the_ports_another_declares_and_a_change_applies_at_once()
-> anyhow::Result<()> {
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    anyhow::ensure!(
        net.reaches_by_name(&a, &b, Duration::from_secs(30))
            .await
            .is_some()
    );
    for port in ["8080", "8081"] {
        net.lab.spawn(
            "b",
            &["python3", "-c", ECHO_SERVER, port],
            &[],
            &format!("echo-{port}.log"),
        )?;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let listening = net.lab.run_async("b", &["ss", "-ltn"]).await?;
    anyhow::ensure!(
        String::from_utf8_lossy(&listening.stdout).contains(":8081"),
        "{listening:?}"
    );

    anyhow::ensure!(
        !net.echoes(&a, &b, 8080).await,
        "an undeclared port answered"
    );
    anyhow::ensure!(
        eventually(Duration::from_secs(3), || async {
            b.counter("dropped_closed_in") > 0
        })
        .await
        .is_some(),
        "b did not count what it dropped: {}",
        b.status()
    );

    let agent_b = net.lab.pid_of("agent-b.log");
    let epoch = b.epoch();
    net.declare(
        &b,
        json!([{"transport": "NETWORK_TRANSPORT_TCP", "port": 8080}]),
    )
    .await?;
    anyhow::ensure!(
        net.then.json()?["machine"]["networkPorts"]
            == json!([{"transport": "NETWORK_TRANSPORT_TCP", "port": 8080}]),
        "{}",
        net.then.body()?
    );
    let opened = eventually(Duration::from_secs(10), || net.echoes(&a, &b, 8080)).await;
    anyhow::ensure!(
        opened.is_some(),
        "the declared port never opened: {}",
        b.status()
    );
    anyhow::ensure!(b.epoch() > epoch, "the change did not come as a new list");
    anyhow::ensure!(
        net.lab.pid_of("agent-b.log") == agent_b,
        "the agent was restarted"
    );
    anyhow::ensure!(
        eventually(Duration::from_secs(3), || async {
            a.counter("admitted_replies") > 0
        })
        .await
        .is_some(),
        "a, which declares nothing, took b's replies as something else: {}",
        a.status()
    );
    anyhow::ensure!(
        !net.echoes(&a, &b, 8081).await,
        "a port next to the declared one answered"
    );
    anyhow::ensure!(
        net.pings(&a, &b.fqdn()).await,
        "ping stopped working once ports were declared"
    );

    net.declare(&b, json!([])).await?;
    let closed = eventually(Duration::from_secs(10), || async {
        !net.echoes(&a, &b, 8080).await
    })
    .await;
    anyhow::ensure!(closed.is_some(), "closing the port did not close it");
    eprintln!("declared port open {opened:?} after the call; closed again {closed:?} after");
    Ok(())
}

#[tokio::test]
async fn a_revocation_reaches_a_member_that_cannot_reach_grund_through_the_members_it_talks_to()
-> anyhow::Result<()> {
    let Some(net) = a_lab().await? else {
        return Ok(());
    };
    let a = net.join("a", "a").await?;
    let b = net.join("b", "b").await?;
    let c = net.join("c", "c").await?;
    for (from, to) in [(&c, &a), (&c, &b), (&a, &b)] {
        anyhow::ensure!(
            net.reaches_by_name(from, to, Duration::from_secs(30))
                .await
                .is_some(),
            "{} never reached {}",
            from.node,
            to.node
        );
    }
    let cut = net.lab.work.join("cut-grund.nft");
    std::fs::write(
        &cut,
        format!(
            "table inet cut {{\n  chain out {{\n    type filter hook output priority 0; policy accept;\n    \
             ip daddr {} tcp dport 443 drop\n  }}\n}}\n",
            crate::accepttest::fixtures::netlab::LIGHTHOUSE
        ),
    )?;
    let out = net
        .lab
        .run_async("c", &["nft", "-f", &cut.to_string_lossy()])
        .await?;
    anyhow::ensure!(out.status.success(), "{out:?}");
    net.lab.spawn(
        "c",
        &["ping", "-6", "-i", "0.2", &a.address().to_string()],
        &[],
        "ping-c-a.log",
    )?;
    let failures = || {
        net.log("agent-c.log")
            .matches("GetMembership failed")
            .count()
    };
    let before = failures();
    anyhow::ensure!(
        eventually(Duration::from_secs(30), || async { failures() > before })
            .await
            .is_some(),
        "c still reaches grund"
    );
    let epoch = c.epoch();

    let revoked_at = Instant::now();
    net.when
        .calling(
            &format!("{MACHINES}/RevokeMachine"),
            &json!({"organisation": net.owner, "machineId": b.id()}).to_string(),
        )
        .await?;
    net.then.status(200)?;
    let heard = eventually(Duration::from_secs(10), || async {
        c.epoch() > epoch && c.peer(&b).is_null()
    })
    .await;
    anyhow::ensure!(
        heard.is_some(),
        "c never heard of the revocation: {}\n{}",
        c.status(),
        net.log("agent-c.log")
    );
    anyhow::ensure!(
        c.status()["lists_from_members"]
            .as_u64()
            .unwrap_or_default()
            >= 1
            && net.log("agent-c.log").contains("handed on by a member"),
        "c's new list did not come by gossip: {}",
        c.status()
    );
    anyhow::ensure!(
        heard.unwrap() <= Duration::from_secs(5),
        "gossip took {heard:?}, past the 5 s bound"
    );
    anyhow::ensure!(
        !net.pings(&c, &b.address().to_string()).await,
        "c still reaches b"
    );
    anyhow::ensure!(net.pings(&c, &a.fqdn()).await, "c lost a");
    eprintln!(
        "c, cut off from grund, dropped b {heard:?} after the revocation ({:?} in all)",
        revoked_at.elapsed()
    );
    Ok(())
}
