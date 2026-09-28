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
            record["network"]["relay_urls"] == json!([RELAY_URL]),
            "the machine is told grund's relay: {record}"
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
                ("SSL_CERT_FILE", &ca),
                ("RUST_LOG", "grund_agent=debug,grund_net=debug,info"),
            ],
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
