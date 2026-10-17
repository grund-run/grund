use std::time::{Duration, Instant};

use buffa::Message;
use grund_proto::grund::app::v1::ErrorReason;
use serde_json::{Value, json};

use crate::accepttest::{
    fixtures::{FakeRegistry, Then, When, random_hex, testcase, testcase_configured},
    machines::origin,
};

const APPS: &str = "/grund.app.v1.AppService";
const MACHINES: &str = "/grund.machine.v1.MachineService";

pub(super) struct Agent {
    pub(super) dir: std::path::PathBuf,
    child: std::process::Child,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Agent {
    pub(super) fn has_exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    pub(super) fn containers(&self) -> Vec<Value> {
        let Ok(entries) = std::fs::read_dir(self.dir.join("simulated-containers/containers"))
        else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| std::fs::read(e.path()).ok())
            .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
            .collect()
    }

    fn lose_task(&self, replica_id: &str) -> anyhow::Result<()> {
        let dir = self.dir.join("simulated-containers/lost");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(replica_id), b"")?;
        Ok(())
    }

    fn kill_container(&self, replica_id: &str) -> anyhow::Result<()> {
        let dir = self.dir.join("simulated-containers/kill");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(replica_id), b"")?;
        Ok(())
    }
}

pub(super) fn data_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("apps-{}", random_hex(6)))
}

pub(super) async fn a_machine(
    when: &When,
    then: &Then,
    organisation: &str,
    name: &str,
) -> anyhow::Result<Agent> {
    when.calling(
        &format!("{MACHINES}/CreateJoinToken"),
        &json!({"organisation": organisation, "name": name}).to_string(),
    )
    .await?;
    then.status(200)?;
    let token = then.json()?["token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let dir = data_dir();
    let url = origin(when);
    let joined = {
        let dir = dir.clone();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(crate::accepttest::fixtures::grund_binary())
                .arg("join")
                .arg("--data-dir")
                .arg(&dir)
                .args(["--url", &url, &token])
                .env_clear()
                .env("RUST_LOG", "warn")
                .output()
        })
        .await??
    };
    anyhow::ensure!(
        joined.status.success(),
        "{}",
        String::from_utf8_lossy(&joined.stderr)
    );
    a_running_agent(dir)
}

pub(super) fn a_running_agent(dir: std::path::PathBuf) -> anyhow::Result<Agent> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("agent.log"))?;
    let mut command = std::process::Command::new(crate::accepttest::fixtures::grund_binary());
    command
        .args([
            "agent",
            "--app-runtime",
            "simulated",
            "--interval",
            "1",
            "--data-dir",
        ])
        .arg(&dir)
        .arg("--policy")
        .arg(dir.join("policy.yaml"))
        .env_clear()
        .env("RUST_LOG", "grund_agent=info")
        .stdout(log.try_clone()?)
        .stderr(log);
    if let Some(restic) = std::env::var_os("GRUND_ACCEPT_RESTIC_BIN") {
        command.env("GRUND_RESTIC_BIN", restic);
    }
    let child = command.spawn()?;
    Ok(Agent { dir, child })
}

pub(super) async fn call(
    when: &When,
    then: &Then,
    procedure: &str,
    body: Value,
) -> anyhow::Result<Value> {
    when.calling(&format!("{APPS}/{procedure}"), &body.to_string())
        .await?;
    then.json()
}

pub(super) async fn app(
    when: &When,
    then: &Then,
    organisation: &str,
    name: &str,
) -> anyhow::Result<Value> {
    let answer = call(
        when,
        then,
        "GetApp",
        json!({"organisation": organisation, "name": name}),
    )
    .await?;
    then.status(200)?;
    Ok(answer["app"].clone())
}

pub(super) async fn until(
    when: &When,
    then: &Then,
    organisation: &str,
    name: &str,
    within: Duration,
    what: &str,
    done: impl Fn(&Value) -> bool,
) -> anyhow::Result<Value> {
    let started = Instant::now();
    loop {
        let app = app(when, then, organisation, name).await?;
        if done(&app) {
            return Ok(app);
        }
        anyhow::ensure!(
            started.elapsed() < within,
            "{what} did not happen within {within:?}: {app:#}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(super) fn ready_on(app: &Value, release: u64) -> usize {
    app["replicas"]
        .as_array()
        .map(|replicas| {
            replicas
                .iter()
                .filter(|r| {
                    r["release"].as_u64() == Some(release)
                        && r["observed"]["ready"] == true
                        && r["state"] == "REPLICA_STATE_RUNNING"
                })
                .count()
        })
        .unwrap_or(0)
}

pub(super) fn live(app: &Value, release: u64) -> bool {
    app["currentRelease"].as_u64() == Some(release)
        && app["rollout"]["state"] == "ROLLOUT_STATE_SUCCEEDED"
}

pub(super) fn spec(image: &str, env: Value) -> Value {
    json!({
        "image": image,
        "ports": [{"name": "http", "port": 80}],
        "resources": {"memoryMib": "128", "cpuMillis": 100},
        "env": env,
        "check": {"httpPath": "/", "intervalMs": 500, "timeoutMs": 200},
        "stop": {"graceSeconds": 1},
    })
}

pub(super) fn quick(copies: u32) -> Value {
    json!({
        "copies": copies,
        "rollout": {"minReadySeconds": 1, "readyDeadlineSeconds": 10, "drainSeconds": 1},
        "rescheduleAfterSeconds": 30,
    })
}

#[tokio::test]
async fn an_app_runs_rolls_out_rolls_back_on_its_own_and_restarts_a_killed_copy()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    let agent = a_machine(&when, &then, org, "box").await?;
    let v1 = registry.publish("acme/hello", "1");

    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "hello", "settings": quick(2)}),
    )
    .await?;
    then.status(200)?;
    let deployed = call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "hello", "spec": spec(&registry.image("acme/hello", "1"), json!([])), "note": "first"}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(deployed["release"]["number"] == 1, "{deployed}");
    anyhow::ensure!(deployed["release"]["imageDigest"] == v1, "{deployed}");
    anyhow::ensure!(
        deployed["release"]["platforms"] == json!(["aarch64", "x86_64"]),
        "{deployed}"
    );

    let running = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(30),
        "v1 live on 2 copies",
        |a| live(a, 1) && ready_on(a, 1) == 2,
    )
    .await?;
    anyhow::ensure!(running["replicas"][0]["machineName"] == "box", "{running}");
    when.calling(
        &format!("{MACHINES}/ListMachines"),
        &json!({"organisation": org}).to_string(),
    )
    .await?;
    then.status(200)?;
    let capabilities = &then.json()?["machines"][0]["capabilities"];
    anyhow::ensure!(
        capabilities["apps"] == true
            && capabilities["arch"] == std::env::consts::ARCH
            && capabilities["memoryMib"] == "4096",
        "the machine's apps capability is shown as it reported it: {capabilities}"
    );
    let containers = agent.containers();
    anyhow::ensure!(containers.len() == 2, "{containers:?}");
    anyhow::ensure!(
        containers.iter().all(|c| c["spec"]["image"]["digest"] == v1
            && c["spec"]["image"]["reference"]
                .as_str()
                .is_some_and(|r| r.ends_with(&format!("acme/hello@{v1}")))),
        "every container runs the digest, never the tag: {containers:?}"
    );

    registry.publish("acme/hello", "2");
    call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "hello", "spec": spec(&registry.image("acme/hello", "2"), json!([]))}),
    )
    .await?;
    then.status(200)?;
    let started = Instant::now();
    loop {
        let app = app(&when, &then, org, "hello").await?;
        let ready = ready_on(&app, 1) + ready_on(&app, 2);
        anyhow::ensure!(
            ready >= 2,
            "fewer than two ready copies during the rollout: {app:#}"
        );
        if live(&app, 2) && ready_on(&app, 2) == 2 {
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(45),
            "v2 did not go live: {app:#}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    registry.publish("acme/hello", "3");
    call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "hello",
               "spec": spec(&registry.image("acme/hello", "3"), json!([{"name": "GRUND_SIMULATE", "value": "unready"}]))}),
    )
    .await?;
    then.status(200)?;
    let failed = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(40),
        "v3 failing and rolling back",
        |a| a["rollout"]["toRelease"] == 3 && a["rollout"]["state"] == "ROLLOUT_STATE_FAILED",
    )
    .await?;
    anyhow::ensure!(failed["currentRelease"] == 2, "{failed:#}");
    when.calling(
        "/grund.notification.v1.NotificationService/ListNotifications",
        "{}",
    )
    .await?;
    then.status(200)?;
    let inbox = then.json()?;
    let failures: Vec<&Value> = inbox["notifications"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no notifications array: {inbox}"))?
        .iter()
        .filter(|item| {
            item["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("release."))
        })
        .collect();
    anyhow::ensure!(
        failures.len() == 1,
        "failed rollout creates one fact: {inbox}"
    );
    outsider_when
        .calling(
            "/grund.notification.v1.NotificationService/ListNotifications",
            "{}",
        )
        .await?;
    outsider_then.status(200)?;
    let other = outsider_then.json()?;
    anyhow::ensure!(
        other
            .get("notifications")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "unrelated account sees no organisation's release: {other}"
    );
    anyhow::ensure!(
        failed["rollout"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("status 503")),
        "the reason names the last answer: {failed:#}"
    );
    let back = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(20),
        "only v2 left",
        |a| ready_on(a, 2) == 2 && a["replicas"].as_array().is_some_and(|r| r.len() == 2),
    )
    .await?;
    let releases = call(
        &when,
        &then,
        "ListReleases",
        json!({"organisation": org, "name": "hello"}),
    )
    .await?;
    let outcomes: Vec<&str> = releases["releases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["outcome"].as_str().unwrap_or_default())
        .collect();
    anyhow::ensure!(
        outcomes
            == vec![
                "RELEASE_OUTCOME_FAILED",
                "RELEASE_OUTCOME_LIVE",
                "RELEASE_OUTCOME_REPLACED"
            ],
        "{releases:#}"
    );

    let victim = back["replicas"][0]["replicaId"]
        .as_str()
        .unwrap()
        .to_string();
    agent.kill_container(&victim)?;
    until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(20),
        "the killed copy restarted",
        |a| {
            a["replicas"].as_array().is_some_and(|replicas| {
                replicas.iter().any(|r| {
                    r["replicaId"] == victim.as_str()
                        && r["observed"]["restarts"] == 1
                        && r["observed"]["ready"] == true
                })
            })
        },
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn a_copy_whose_task_is_gone_after_a_reboot_runs_again_under_its_own_id() -> anyhow::Result<()>
{
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let agent = a_machine(&when, &then, org, "box").await?;
    registry.publish("acme/hello", "1");
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "hello", "settings": quick(1)}),
    )
    .await?;
    then.status(200)?;
    call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "hello", "spec": spec(&registry.image("acme/hello", "1"), json!([]))}),
    )
    .await?;
    then.status(200)?;
    let running = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(30),
        "v1 live on 1 copy",
        |a| live(a, 1) && ready_on(a, 1) == 1,
    )
    .await?;
    let copy = running["replicas"][0]["replicaId"]
        .as_str()
        .unwrap()
        .to_string();

    agent.lose_task(&copy)?;
    let consumed = std::time::Instant::now();
    while agent
        .dir
        .join("simulated-containers/lost")
        .join(&copy)
        .exists()
    {
        anyhow::ensure!(
            consumed.elapsed() < Duration::from_secs(10),
            "the agent never looked at the copy"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let started_again = |agent: &Agent| {
        agent
            .containers()
            .iter()
            .any(|c| c["spec"]["id"] == copy.as_str() && c["task_lost"] == false)
    };
    until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(30),
        "the copy ran again after its task was lost",
        |a| {
            started_again(&agent)
                && a["replicas"].as_array().is_some_and(|replicas| {
                    replicas.len() == 1
                        && replicas[0]["replicaId"] == copy.as_str()
                        && replicas[0]["observed"]["ready"] == true
                })
        },
    )
    .await
    .map_err(|error| error.context(format!("containers: {:?}", agent.containers())))?;
    Ok(())
}

#[tokio::test]
async fn a_secret_reaches_only_its_replica_and_never_the_api() -> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let agent = a_machine(&when, &then, org, "box").await?;
    registry.publish("acme/db", "1");
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "db", "settings": quick(1)}),
    )
    .await?;
    then.status(200)?;
    let mut with_secret = spec(&registry.image("acme/db", "1"), json!([]));
    with_secret["secrets"] = json!([{"env": "PASSWORD", "secret": "db-password"}]);
    call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "db", "spec": with_secret}),
    )
    .await?;
    then.status(400)?.connect_code("invalid_argument")?;

    let value = format!("hunter-{}", random_hex(8));
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&value);
    call(
        &when,
        &then,
        "SetSecret",
        json!({"organisation": org, "name": "db", "secret": "db-password", "value": encoded}),
    )
    .await?;
    then.status(200)?;
    call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "db", "spec": with_secret}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        !then.json()?.to_string().contains(&value),
        "a deploy's answer never carries a secret value"
    );
    let app = until(
        &when,
        &then,
        org,
        "db",
        Duration::from_secs(30),
        "db live",
        |a| live(a, 1),
    )
    .await?;
    anyhow::ensure!(
        app["secrets"][0]["name"] == "db-password" && app["secrets"][0]["version"] == 1,
        "{app}"
    );
    anyhow::ensure!(
        !app.to_string().contains(&value),
        "GetApp never carries a secret value"
    );
    let containers = agent.containers();
    anyhow::ensure!(
        containers[0]["spec"]["env"]
            .as_array()
            .is_some_and(|env| env.iter().any(|e| e == &json!(["PASSWORD", value]))),
        "the replica got the value: {containers:?}"
    );
    let cache = std::fs::read(agent.dir.join("secrets.cache"))?;
    anyhow::ensure!(
        !cache.windows(value.len()).any(|w| w == value.as_bytes()),
        "the agent's cache is encrypted"
    );
    Ok(())
}

#[tokio::test]
async fn a_second_organisation_cannot_see_or_touch_an_app() -> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _agent = a_machine(&when, &then, org, "box").await?;
    registry.publish("acme/hello", "1");
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "hello", "settings": quick(1)}),
    )
    .await?;
    then.status(200)?;
    call(&when, &then, "Deploy", json!({"organisation": org, "name": "hello", "spec": spec(&registry.image("acme/hello", "1"), json!([]))})).await?;
    then.status(200)?;
    let running = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(30),
        "hello live",
        |a| live(a, 1),
    )
    .await?;
    let replica_id = running["replicas"][0]["replicaId"]
        .as_str()
        .unwrap()
        .to_string();

    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    let stranger = outsider.a_signed_in_account().await?;
    for (procedure, body) in [
        ("GetApp", json!({"organisation": org, "name": "hello"})),
        ("ListApps", json!({"organisation": org})),
        (
            "ListReleases",
            json!({"organisation": org, "name": "hello"}),
        ),
        (
            "Deploy",
            json!({"organisation": org, "name": "hello", "spec": spec(&registry.image("acme/hello", "1"), json!([]))}),
        ),
        (
            "Scale",
            json!({"organisation": org, "name": "hello", "copies": 3}),
        ),
        (
            "SetSecret",
            json!({"organisation": org, "name": "hello", "secret": "x", "value": ""}),
        ),
        (
            "Rollback",
            json!({"organisation": org, "name": "hello", "release": 1}),
        ),
        ("DeleteApp", json!({"organisation": org, "name": "hello"})),
    ] {
        outsider_when
            .calling(&format!("{APPS}/{procedure}"), &body.to_string())
            .await?;
        outsider_then.status(404)?.connect_code("not_found")?;
    }
    outsider_when
        .calling(
            &format!("{APPS}/GetApp"),
            &json!({"organisation": stranger.username, "name": "hello"}).to_string(),
        )
        .await?;
    outsider_then.status(404)?.connect_code("not_found")?;

    let their = a_machine(&outsider_when, &outsider_then, &stranger.username, "theirs").await?;
    let record: Value =
        serde_json::from_str(&std::fs::read_to_string(their.dir.join("machine.json"))?)?;
    let key = crate::accepttest::machines::device_key(&their.dir)?;
    crate::accepttest::machines::signed_agent_call(
        &outsider_when,
        record["machine_id"].as_str().unwrap_or_default(),
        &key,
        "GetReplicaSecrets",
        &json!({"replicaId": replica_id}).to_string(),
    )
    .await?;
    outsider_then.status(404)?.connect_code("not_found")?;
    crate::accepttest::machines::signed_agent_call(
        &outsider_when,
        record["machine_id"].as_str().unwrap_or_default(),
        &key,
        "GetReplicaSecrets",
        &json!({"replicaId": uuid_like()}).to_string(),
    )
    .await?;
    outsider_then.status(404)?.connect_code("not_found")?;
    let after = app(&when, &then, org, "hello").await?;
    anyhow::ensure!(
        after["settings"]["copies"] == 1 && after["currentRelease"] == 1,
        "{after}"
    );
    Ok(())
}

pub(super) fn reason(error: &Value) -> String {
    detail(error)
        .map(|detail| detail.reason)
        .unwrap_or_default()
}

fn detail(error: &Value) -> Option<ErrorReason> {
    use base64::Engine;
    error["details"]
        .as_array()?
        .iter()
        .find(|d| d["type"] == "grund.app.v1.ErrorReason")
        .and_then(|d| d["value"].as_str())
        .and_then(|v| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(v.trim_end_matches('='))
                .ok()
        })
        .and_then(|bytes| ErrorReason::decode_from_slice(&bytes).ok())
}

pub(super) fn uuid_like() -> String {
    let hex = random_hex(16);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[tokio::test]
async fn a_copy_on_a_machine_that_stops_answering_is_started_on_another() -> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    let mut first = a_machine(&when, &then, org, "one").await?;
    let _second = a_machine(&when, &then, org, "two").await?;
    registry.publish("acme/hello", "1");
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "hello", "settings": quick(2)}),
    )
    .await?;
    then.status(200)?;
    call(&when, &then, "Deploy", json!({"organisation": org, "name": "hello", "spec": spec(&registry.image("acme/hello", "1"), json!([]))})).await?;
    then.status(200)?;
    let spread = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(30),
        "two copies on two machines",
        |a| {
            live(a, 1)
                && a["replicas"]
                    .as_array()
                    .is_some_and(|r| r.len() == 2 && r[0]["machineName"] != r[1]["machineName"])
        },
    )
    .await?;
    let on_one = spread["replicas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["machineName"] == "one")
        .map(|r| r["replicaId"].clone())
        .unwrap();
    first.kill();
    let moved = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(90),
        "the lost copy started on two",
        |a| {
            a["replicas"].as_array().is_some_and(|r| {
                r.len() == 2
                    && r.iter()
                        .all(|x| x["machineName"] == "two" && x["observed"]["ready"] == true)
                    && !r.iter().any(|x| x["replicaId"] == on_one)
            })
        },
    )
    .await?;
    anyhow::ensure!(moved["currentRelease"] == 1, "{moved}");
    when.calling(
        "/grund.notification.v1.NotificationService/ListNotifications",
        "{}",
    )
    .await?;
    then.status(200)?;
    let inbox = then.json()?;
    anyhow::ensure!(
        inbox["notifications"].as_array().is_some_and(|items| items
            .iter()
            .filter(|item| item["kind"] == "machine.disconnected")
            .count()
            == 1),
        "one disconnected-machine fact after the reschedule window: {inbox}"
    );
    outsider_when
        .calling(
            "/grund.notification.v1.NotificationService/ListNotifications",
            "{}",
        )
        .await?;
    outsider_then.status(200)?;
    let unrelated = outsider_then.json()?;
    anyhow::ensure!(
        unrelated
            .get("notifications")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "disconnected machine leaked to another organisation: {unrelated}"
    );
    Ok(())
}

#[tokio::test]
async fn a_deleted_app_reserves_its_name_until_restored_without_affecting_another_organisation()
-> anyhow::Result<()> {
    let (given, when, then) = testcase().await?;
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let (other, other_when, other_then) = given.testcase.another_browser();
    let other_org = other.a_signed_in_account().await?.username;
    let request = json!({"organisation": org, "name": "recover-me"});
    call(&when, &then, "CreateApp", request.clone()).await?;
    then.status(200)?;
    call(&when, &then, "CreateApp", request.clone()).await?;
    then.status(400)?.connect_code("failed_precondition")?;
    let active = then.json()?;
    let active_detail =
        detail(&active).ok_or_else(|| anyhow::anyhow!("missing detail: {active}"))?;
    anyhow::ensure!(
        active_detail.reason == "name_taken"
            && active_detail.deleted_at.as_option().is_none()
            && active_detail.purge_after.as_option().is_none(),
        "active names retain their reason without recovery dates: {active}"
    );

    let deleted = call(&when, &then, "DeleteApp", request.clone()).await?;
    then.status(200)?;
    let deadline = chrono::DateTime::parse_from_rfc3339(
        deleted["purgeAfter"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing deadline: {deleted}"))?,
    )?;
    call(&when, &then, "CreateApp", request.clone()).await?;
    then.status(400)?.connect_code("failed_precondition")?;
    let refused = then.json()?;
    let reserved = detail(&refused).ok_or_else(|| anyhow::anyhow!("missing detail: {refused}"))?;
    let raw_deleted = reserved
        .deleted_at
        .as_option()
        .ok_or_else(|| anyhow::anyhow!("missing deletion time: {refused}"))?;
    let raw_deadline = reserved
        .purge_after
        .as_option()
        .ok_or_else(|| anyhow::anyhow!("missing restore deadline: {refused}"))?;
    let deleted_at = deadline - chrono::Duration::days(7);
    anyhow::ensure!(
        reserved.reason == "name_reserved_for_restore"
            && (raw_deleted.seconds, raw_deleted.nanos)
                == (
                    deleted_at.timestamp(),
                    deleted_at.timestamp_subsec_nanos() as i32
                )
            && (raw_deadline.seconds, raw_deadline.nanos)
                == (
                    deadline.timestamp(),
                    deadline.timestamp_subsec_nanos() as i32
                ),
        "structured recovery times do not match the recorded RFC3339 deadline: {refused}"
    );
    let expected = format!(
        "recover-me was deleted on {} and can be restored until {}.",
        deleted_at.format("%-d %b %Y %H:%M:%S UTC"),
        deadline.format("%-d %b %Y %H:%M:%S UTC")
    );
    anyhow::ensure!(
        refused["message"].as_str() == Some(expected.as_str()),
        "recovery conflict does not explain the recorded times: {refused}"
    );
    when.visiting(&format!("/{org}/apps")).await?;
    then.status(200)?
        .body_contains(&expected)?
        .body_contains("<span>Restore</span>")?;
    let deploy = format!("/{org}/deploy");
    when.submitting(
        &deploy,
        &deploy,
        &[
            ("mode", "premade"),
            ("template", "nats"),
            ("name", "recover-me"),
        ],
    )
    .await?;
    then.status(422)?
        .body_contains(&expected)?
        .body_contains(&format!("/{org}/apps?q=recover-me#restorable-apps"))?;

    call(
        &other_when,
        &other_then,
        "CreateApp",
        json!({"organisation": other_org, "name": "recover-me"}),
    )
    .await?;
    other_then.status(200)?;
    call(&other_when, &other_then, "CreateApp", request.clone()).await?;
    other_then.status(404)?.connect_code("not_found")?;
    call(&when, &then, "RestoreApp", request.clone()).await?;
    then.status(200)?;
    call(&when, &then, "CreateApp", request).await?;
    then.status(400)?.connect_code("failed_precondition")?;
    anyhow::ensure!(
        reason(&then.json()?) == "name_taken",
        "restored names are active conflicts"
    );
    Ok(())
}

#[tokio::test]
async fn a_grund_yaml_deploys_and_an_unknown_tag_is_refused_with_its_reason() -> anyhow::Result<()>
{
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "shop"}),
    )
    .await?;
    then.status(200)?;
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "shop"}),
    )
    .await?;
    then.status(400)?.connect_code("failed_precondition")?;

    call(&when, &then, "Deploy", json!({"organisation": org, "name": "shop", "spec": spec(&registry.image("acme/shop", "nope"), json!([]))})).await?;
    then.status(400)?.connect_code("failed_precondition")?;
    anyhow::ensure!(
        reason(&then.json()?) == "image_unresolved",
        "{}",
        then.json()?
    );

    registry.publish("acme/shop", "2026-10-01");
    let file = format!(
        "apps:\n  shop:\n    image: {}\n    copies: 2\n    ports:\n      - name: http\n        port: 8080\n    check:\n      http: /healthz\n",
        registry.image("acme/shop", "2026-10-01")
    );
    let made = call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "shop", "grundYaml": file}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(made["release"]["source"] == "RELEASE_SOURCE_FILE", "{made}");
    anyhow::ensure!(made["release"]["spec"]["check"]["port"] == 8080, "{made}");
    let shop = until(
        &when,
        &then,
        org,
        "shop",
        Duration::from_secs(10),
        "the copies waiting",
        |a| a["waiting"][0]["reason"] == "no_machine",
    )
    .await?;
    anyhow::ensure!(shop["settings"]["copies"] == 2, "{shop}");
    anyhow::ensure!(
        shop["waiting"][0]["message"]
            .as_str()
            .is_some_and(|m| m == "Waiting for a machine."),
        "with no machine the copies wait and say why: {shop}"
    );
    call(&when, &then, "Deploy", json!({"organisation": org, "name": "shop", "grundYaml": "apps:\n  shop:\n    image: nginx\n    copis: 3\n"})).await?;
    then.status(400)?.connect_code("invalid_argument")?;
    let refused = then.json()?.to_string();
    anyhow::ensure!(
        refused.contains("apps.shop.copis") && refused.contains("line 4, column 5"),
        "the refusal names the field, line and column: {refused}"
    );
    call(&when, &then, "Deploy", json!({"organisation": org, "name": "shop", "grundYaml": "[apps.shop]\nimage = \"nginx\"\n"})).await?;
    then.status(400)?.connect_code("invalid_argument")?;
    Ok(())
}

#[tokio::test]
async fn an_external_release_replays_once_and_refuses_changed_content_or_owner()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    registry.publish("acme/forest", "one");
    registry.publish("acme/forest", "two");
    let image = registry.image("acme/forest", "one");
    let desired = spec(&image, json!([]));
    let missing = call(
        &when,
        &then,
        "PreviewDeploy",
        json!({"organisation":org,"name":"forest","spec":desired,"createIfMissing":true}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        missing["createsApp"] == true
            && missing
                .get("expectedVersion")
                .is_none_or(|version| version == "0"),
        "{missing}"
    );
    call(
        &when,
        &then,
        "GetApp",
        json!({"organisation":org,"name":"forest"}),
    )
    .await?;
    then.status(404)?;
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation":org,"name":"forest"}),
    )
    .await?;
    then.status(200)?;
    let plan = call(
        &when,
        &then,
        "PreviewDeploy",
        json!({"organisation":org,"name":"forest","spec":desired,"domains":["app.example.test"]}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        plan["createsApp"] != true
            && plan["changes"]
                .as_array()
                .is_some_and(|changes| changes.iter().any(|c| c["field"] == "image")
                    && changes.iter().any(|c| c["field"] == "domains")),
        "{plan}"
    );
    let origin = json!({
        "forestOrganisation":"acme", "destination":"dev-primary", "project":"pilot",
        "intentId":uuid::Uuid::now_v7().to_string(),
        "artifactId":uuid::Uuid::now_v7().to_string()
    });
    let deploy = json!({
        "organisation":org,"name":"forest","spec":desired,
        "externalRelease":origin,"expectedVersion":plan["expectedVersion"],
    });
    let made = call(&when, &then, "Deploy", deploy.clone()).await?;
    then.status(200)?;
    let replayed = call(&when, &then, "Deploy", deploy.clone()).await?;
    then.status(200)?;
    anyhow::ensure!(
        replayed["release"]["number"] == made["release"]["number"],
        "{replayed}"
    );
    let history = call(
        &when,
        &then,
        "ListReleases",
        json!({"organisation":org,"name":"forest"}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        history["releases"]
            .as_array()
            .is_some_and(|rows| rows.len() == 1),
        "{history}"
    );
    let changed = json!({"organisation":org,"name":"forest",
        "spec":spec(&registry.image("acme/forest","two"),json!([])),
        "externalRelease":origin});
    let refused = call(&when, &then, "Deploy", changed).await?;
    then.status(409)?.connect_code("already_exists")?;
    anyhow::ensure!(reason(&refused) == "external_release_conflict", "{refused}");
    let another = json!({"organisation":org,"name":"forest","spec":desired,
    "externalRelease":{
        "forestOrganisation":"acme","destination":"dev-primary","project":"intruder",
        "intentId":uuid::Uuid::now_v7().to_string(),
        "artifactId":uuid::Uuid::now_v7().to_string()
    }});
    let refused = call(&when, &then, "Deploy", another).await?;
    then.status(400)?.connect_code("failed_precondition")?;
    anyhow::ensure!(reason(&refused) == "external_owner_conflict", "{refused}");
    let stale = call(
        &when,
        &then,
        "Deploy",
        json!({"organisation":org,"name":"forest",
        "spec":desired,"expectedVersion":"0"}),
    )
    .await?;
    then.status(409)?.connect_code("aborted")?;
    anyhow::ensure!(reason(&stale) == "version_conflict", "{stale}");
    Ok(())
}

#[tokio::test]
async fn an_app_made_on_the_dashboard_shows_its_copies_ready_and_its_versions() -> anyhow::Result<()>
{
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let _agent = a_machine(&when, &then, &org, "desk").await?;
    let digest = registry.publish("acme/hello", "1");
    let page = format!("/{org}/apps");
    when.visiting(&page).await?;
    then.status(200)?
        .body_contains("Deploy your first app")?
        .body_contains(&format!("href=\"/{org}/deploy\""))?;
    when.submitting(
        &format!("/{org}/deploy"),
        &format!("/{org}/deploy"),
        &[
            ("mode", "custom"),
            ("name", "hello"),
            ("image", &registry.image("acme/hello", "1")),
            ("exposure", "private"),
            ("port", "80"),
            ("check", "http"),
            ("check_path", "/"),
            ("copies", "1"),
        ],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("/{org}/apps/hello?done=created"))?;
    let app_page = format!("/{org}/apps/hello");
    let started = Instant::now();
    loop {
        when.visiting(&app_page).await?;
        then.status(200)?;
        let body = then.body()?;
        if body.contains(">Live</span>") {
            anyhow::ensure!(body.contains(">Live</span>"), "the pill says Live: {body}");
            anyhow::ensure!(body.contains("v1 · deployed"), "{body}");
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(30),
            "not live: {body}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    when.visiting(&format!("{app_page}/deployments")).await?;
    then.status(200)?
        .body_contains(">Ready<")?
        .body_contains("Copy 1 of 1 · v1")?
        .body_contains("on desk")?
        .body_contains(&digest[..19])?
        .body_contains("from the dashboard")?;
    when.visiting(&format!("{app_page}/settings?edit=file"))
        .await?;
    then.status(200)?.body_contains("\n  hello:\n")?;
    let settings = format!("{app_page}/settings");
    when.submitting(
        &settings,
        &format!("{app_page}/secrets"),
        &[("variable", "TOKEN"), ("value", "s3cr3t-value")],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("{app_page}/settings?done=secret"))?;
    when.visiting(&format!("{settings}?edit=secrets")).await?;
    then.status(200)?
        .body_contains("secret token · version 1")?;
    anyhow::ensure!(
        !then.body()?.contains("s3cr3t-value"),
        "a secret is never shown"
    );
    when.visiting(&format!("{settings}?edit=file")).await?;
    then.status(200)?
        .body_contains("TOKEN: token")?
        .body_lacks("s3cr3t-value")?;

    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    outsider_when.visiting(&app_page).await?;
    outsider_then.status(404)?;
    Ok(())
}

#[tokio::test]
async fn the_apps_list_shows_each_image_with_its_icon_and_where_to_reach_it_and_finds_by_name()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_INSECURE_REGISTRIES", &registry.host),
        ("GRUND_APP_DOMAIN", "apps.accept.test"),
    ])
    .await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.clone();
    registry.publish("acme/postgres", "16");
    registry.publish("acme/shop", "1");
    for (name, image, public) in [
        ("db", registry.image("acme/postgres", "16"), false),
        ("shop", registry.image("acme/shop", "1"), true),
    ] {
        call(
            &when,
            &then,
            "CreateApp",
            json!({"organisation": org, "name": name}),
        )
        .await?;
        then.status(200)?;
        let mut spec = spec(&image, json!([]));
        spec["ports"][0]["public"] = json!(public);
        call(
            &when,
            &then,
            "Deploy",
            json!({"organisation": org, "name": name, "spec": spec}),
        )
        .await?;
        then.status(200)?;
    }

    let page = format!("/{org}/apps");
    when.visiting(&page).await?;
    then.status(200)?
        .body_contains(&format!("https://shop-{org}.apps.accept.test"))?
        .body_contains("db.grund.internal:80")?
        .body_contains("data-copy=\"db.grund.internal:80\"")?
        .body_contains("postgres:16</p>")?
        .body_contains(&format!("href=\"/{org}/apps/shop/deployments\""))?
        .body_contains(&format!("href=\"/{org}/apps/shop/settings?edit=delete\""))?
        .body_contains(&format!("href=\"/{org}/apps/shop/settings?edit=image\""))?
        .body_lacks("Deploy your first app")?;
    let body = then.body()?;
    let (db, shop) = (body.find(">db<"), body.find(">shop<"));
    anyhow::ensure!(
        db.is_some() && shop.is_some() && db < shop,
        "sorted by name: {body}"
    );

    when.visiting(&format!("{page}?q=SHO&view=grid&sort=created"))
        .await?;
    then.status(200)?
        .body_contains("class=\"items items-grid\"")?
        .body_contains(">shop<")?
        .body_lacks(">db<")?
        .body_contains("1 of 2 apps match")?;

    when.visiting(&format!("/{org}/domains")).await?;
    then.status(200)?
        .body_contains(&format!("https://shop-{org}.apps.accept.test"))?
        .body_lacks(">db<")?
        .body_contains("No domains of your own yet")?
        .body_contains("Add a domain")?;

    when.visiting(&format!("/{org}")).await?;
    then.status(200)?
        .body_contains(&format!("https://shop-{org}.apps.accept.test"))?
        .body_contains("db.grund.internal:80")?;

    when.visiting(&format!("/{org}/apps/shop")).await?;
    then.status(200)?
        .carries_the_security_headers()?
        .body_contains("class=\"shell\"")?
        .body_contains(&format!("https://shop-{org}.apps.accept.test"))?
        .body_lacks(" style=")?;
    when.visiting(&format!("/{org}/apps/db")).await?;
    then.status(200)?
        .body_contains("db.grund.internal:80")?
        .body_lacks(&format!("https://db-{org}"))?;
    Ok(())
}

#[tokio::test]
async fn the_deploy_page_finds_the_port_an_image_declares_and_its_copy_gets_ready()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let _agent = a_machine(&when, &then, &org, "desk").await?;
    registry.publish_exposing("acme/api", "2", &["9090/tcp", "8080/tcp", "53/udp"]);
    let deploy = format!("/{org}/deploy");
    when.visiting(&deploy).await?;
    then.status(200)?.carries_the_security_headers()?;
    let initial = then.body()?;
    for field in ["env", "secrets"] {
        anyhow::ensure!(
            initial.matches(&format!("name=\"{field}_key\"")).count() == 1
                && initial.matches(&format!("name=\"{field}_value\"")).count() == 1,
            "{field} starts with one editable row"
        );
    }
    when.submitting(
        &deploy,
        &deploy,
        &[
            ("mode", "custom"),
            ("name", "api"),
            ("image", &registry.image("acme/api", "2")),
            ("exposure", "private"),
            ("port", ""),
            ("copies", "1"),
            ("env_key", "GREETING"),
            ("env_value", "hej"),
            ("env_key", ""),
            ("env_value", ""),
            ("secrets_key", "API_TOKEN"),
            ("secrets_value", "s3cr3t-value"),
            ("check", "http"),
            ("check_path", "/"),
            ("memory", "128"),
            ("cpu", "0.1"),
            ("stop_signal", "SIGTERM"),
            ("stop_grace", "1"),
        ],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("/{org}/apps/api?done=created"))?;
    let app_page = format!("/{org}/apps/api");
    let started = Instant::now();
    loop {
        when.visiting(&app_page).await?;
        then.status(200)?;
        let body = then.body()?;
        if body.contains(">Live</span>") {
            when.visiting(&format!("{app_page}/settings?edit=file"))
                .await?;
            then.status(200)?;
            let body = then.body()?;
            anyhow::ensure!(
                body.contains("port: 8080"),
                "the lowest TCP port it declares: {body}"
            );
            anyhow::ensure!(body.contains("GREETING: hej"), "{body}");
            anyhow::ensure!(body.contains("API_TOKEN: api-token"), "{body}");
            anyhow::ensure!(!body.contains("s3cr3t-value"), "a secret is never shown");
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(30),
            "not live: {body}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    outsider_when.visiting(&deploy).await?;
    outsider_then.status(404)?;
    Ok(())
}

#[tokio::test]
async fn the_deploy_page_refuses_what_the_api_would_and_makes_nothing() -> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_INSECURE_REGISTRIES", &registry.host),
        ("GRUND_APP_DOMAIN", "apps.accept.test"),
    ])
    .await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.clone();
    registry.publish_exposing("acme/web", "1", &["80/tcp"]);
    registry.publish("acme/bare", "1");
    let deploy = format!("/{org}/deploy");
    let web = registry.image("acme/web", "1");
    let bare = registry.image("acme/bare", "1");
    let unknown = registry.image("acme/web", "nope");
    let custom = |name: &'static str, image: String, secret: &'static str| {
        vec![
            ("mode", "custom".to_string()),
            ("name", name.to_string()),
            ("image", image),
            ("exposure", "public".to_string()),
            ("copies", "1".to_string()),
            (
                "secrets_key",
                if secret.is_empty() { "" } else { "TOKEN" }.to_string(),
            ),
            ("secrets_value", secret.to_string()),
        ]
    };
    for (fields, expected) in [
        (
            custom("Bad Name", web.clone(), "topsecret"),
            "Use only letters a–z, digits and single hyphens between them.",
        ),
        (
            custom("bare", bare.clone(), ""),
            "The image declares no port; enter the one it listens on.",
        ),
        (
            custom("lost", unknown.clone(), ""),
            "has no such image or tag.",
        ),
        (
            vec![
                ("mode", "custom".to_string()),
                ("name", "big".to_string()),
                ("image", web.clone()),
                ("copies", "21".to_string()),
            ],
            "Use 1 to 20.",
        ),
        (
            vec![
                ("mode", "custom".to_string()),
                ("name", "envs".to_string()),
                ("image", web.clone()),
                ("env_key", "OK".to_string()),
                ("env_value", "1".to_string()),
                ("env_key", "".to_string()),
                ("env_value", "not a setting".to_string()),
            ],
            "Row 2: give the value a name.",
        ),
        (
            vec![
                ("mode", "premade".to_string()),
                ("template", "postgres".to_string()),
            ],
            "Choose one of the apps.",
        ),
        (
            vec![
                ("mode", "premade".to_string()),
                ("template", "nats".to_string()),
                ("exposure", "public".to_string()),
            ],
            "NATS has no HTTP port to publish. Choose Private.",
        ),
    ] {
        let fields: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        when.submitting(&deploy, &deploy, &fields).await?;
        then.status(422)?
            .carries_the_security_headers()?
            .body_contains("Nothing was deployed.")?
            .body_contains(expected)?
            .body_lacks("topsecret")?;
    }
    then.body_lacks("Enter them again")?;
    when.submitting(
        &deploy,
        &deploy,
        &[
            ("mode", "custom"),
            ("name", "Bad Name"),
            ("image", &web),
            ("env_key", "DEPLOY_GREETING"),
            ("env_value", "retain-non-secret"),
            ("secrets_key", "TOKEN"),
            ("secrets_value", "topsecret"),
        ],
    )
    .await?;
    then.status(422)?
        .body_contains("Enter them again")?
        .body_contains("value=\"Bad Name\"")?
        .body_contains("value=\"DEPLOY_GREETING\"")?
        .body_contains("value=\"retain-non-secret\"")?
        .body_lacks("topsecret")?;
    let refused = then.body()?;
    anyhow::ensure!(
        refused.matches("name=\"secrets_key\"").count() == 1
            && refused.matches("name=\"secrets_value\"").count() == 1,
        "a refused deployment resets secrets to one empty row"
    );

    when.submitting(
        &deploy,
        &deploy,
        &[
            ("mode", "custom"),
            ("name", "taken"),
            ("image", &web),
            ("exposure", "public"),
        ],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("/{org}/apps/taken?done=created"))?;
    when.submitting(
        &deploy,
        &deploy,
        &[("mode", "custom"), ("name", "taken"), ("image", &web)],
    )
    .await?;
    then.status(422)?
        .body_contains("An app of that name already exists here.")?;

    let listed = call(&when, &then, "ListApps", json!({"organisation": org})).await?;
    let names: Vec<&str> = listed["apps"]
        .as_array()
        .map(|apps| apps.iter().filter_map(|a| a["name"].as_str()).collect())
        .unwrap_or_default();
    anyhow::ensure!(
        names == ["taken"],
        "only the app that was accepted: {names:?}"
    );
    when.visiting(&format!("/{org}/apps")).await?;
    then.status(200)?
        .body_contains(&format!("https://taken-{org}.apps.accept.test"))?;

    when.visiting(&format!("/{org}/templates")).await?;
    then.status(200)?
        .body_contains("Needs storage")?
        .body_contains(&format!("href=\"/{org}/deploy?template=nats\""))?;
    when.visiting(&format!("{deploy}?template=whoami")).await?;
    then.status(200)?.carries_the_security_headers()?;
    Ok(())
}

#[tokio::test]
async fn exposure_uses_release_ports_without_contacting_the_registry_on_get() -> anyhow::Result<()>
{
    let registry = FakeRegistry::start().await?;
    let image = registry.image("acme/ports", "1");
    registry.publish_exposing("acme/ports", "1", &["8080/tcp", "53/udp"]);
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username;
    when.submitting(
        &format!("/{org}/deploy"),
        &format!("/{org}/deploy"),
        &[
            ("mode", "custom"),
            ("name", "ports"),
            ("image", &image),
            ("exposure", "private"),
            ("port", "8080"),
        ],
    )
    .await?;
    then.status(303)?;
    let calls_after_deploy = registry.manifest_calls();
    for _ in 0..2 {
        when.visiting(&format!("/{org}/apps/ports/settings?edit=exposure"))
            .await?;
        then.status(200)?
            .body_contains("The image listens on 8080. Empty: no port.")?;
    }
    anyhow::ensure!(
        registry.manifest_calls() == calls_after_deploy,
        "opening Exposure must not ask the registry again"
    );
    Ok(())
}

#[tokio::test]
async fn the_app_page_shows_how_it_is_and_changes_it_through_its_tabs_making_releases()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_INSECURE_REGISTRIES", &registry.host),
        ("GRUND_APP_DOMAIN", "apps.accept.test"),
    ])
    .await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let _agent = a_machine(&when, &then, &org, "desk").await?;
    let first = registry.publish("acme/hello", "1");
    let second = registry.publish("acme/hello", "2");
    when.submitting(
        &format!("/{org}/deploy"),
        &format!("/{org}/deploy"),
        &[
            ("mode", "custom"),
            ("name", "hello"),
            ("image", &registry.image("acme/hello", "1")),
            ("exposure", "public"),
            ("port", "80"),
            ("check", "http"),
            ("check_path", "/"),
            ("copies", "1"),
        ],
    )
    .await?;
    then.status(303)?;
    let page = format!("/{org}/apps/hello");
    let started = Instant::now();
    loop {
        when.visiting(&page).await?;
        then.status(200)?;
        let body = then.body()?;
        if body.contains(">Live</span>") {
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(30),
            "not live: {body}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    then.body_contains(">Live</span>")?
        .body_contains(&format!("https://hello-{org}.apps.accept.test"))?
        .body_contains("Reachable at")?
        .body_contains(&format!(">· {org}</span>"))?
        .body_lacks("is live on")?
        .body_contains(&format!("by <strong>{org}</strong> from the dashboard"))?
        .body_lacks("View logs")?
        .body_contains("<span class=\"btn-label\">Deploy app</span>")?
        .body_lacks("Deploy change")?
        .body_contains("</svg>Update image</a>")?
        .body_contains(&format!("href=\"/{org}/apps/hello/settings?edit=image\""))?;
    let body = then.body()?;
    anyhow::ensure!(
        body.matches("btn-primary").count() == 1,
        "the top bar's Deploy app is the page's only primary button"
    );

    for (tab, words) in [
        ("", "Latest activity"),
        ("/deployments", "Releases"),
        ("/logs", "Logs are coming"),
        ("/metrics", "Metrics are coming"),
        ("/settings", "Configured"),
        ("/settings?edit=image", "The tag is resolved now."),
    ] {
        when.visiting(&format!("{page}{tab}")).await?;
        then.status(200)
            .and_then(|t| t.carries_the_security_headers())
            .and_then(|t| t.header("cache-control", "no-store"))
            .and_then(|t| t.body_contains(words))
            .and_then(|t| t.body_lacks(" style="))
            .and_then(|t| t.body_lacks(" onclick="))
            .map_err(|error| error.context(format!("{page}{tab}")))?;
    }
    then.body_contains("id=\"version\">Image</h2>")?;
    when.visiting(&format!("{page}/deploy")).await?;
    then.status(404)?;

    let settings = format!("{page}/settings");
    when.visiting(&settings).await?;
    then.status(200)?.body_contains(&format!(
        "acme/hello:1 · {}",
        &first.trim_start_matches("sha256:")[..12]
    ))?;
    when.submitting(
        &settings,
        &format!("{page}/settings/release"),
        &[("part", "image"), ("image", "nope")],
    )
    .await?;
    then.status(422)?
        .body_contains("Nothing was released. Check the field marked below.")?
        .body_contains("id=\"version\">Image</h2>")?
        .body_contains("aria-invalid=\"true\"")?
        .body_contains("value=\"nope\"")?;
    when.submitting(
        &settings,
        &format!("{page}/settings/release"),
        &[("part", "image"), ("image", "2")],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("{page}/settings?done=released"))?;
    when.visiting(&settings).await?;
    then.status(200)?.body_contains(&format!(
        "acme/hello:2 · {}",
        &second.trim_start_matches("sha256:")[..12]
    ))?;
    when.submitting(
        &settings,
        &format!("{page}/secrets"),
        &[("variable", "API_KEY"), ("value", "s3cr3t-value")],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("{page}/settings?done=secret"))?;

    when.submitting(
        &settings,
        &format!("{page}/settings/release"),
        &[
            ("part", "env"),
            ("env_key", "GREETING"),
            ("env_value", "hallo"),
            ("exposure", "private"),
        ],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("{page}/settings?done=released"))?;
    when.submitting(
        &settings,
        &format!("{page}/settings/release"),
        &[
            ("part", "exposure"),
            ("exposure", "public"),
            ("port", "99999"),
        ],
    )
    .await?;
    then.status(422)?
        .body_contains("Nothing was released. Check the field marked below.")?
        .body_contains("A port is a number from 1 to 65535.")?
        .body_contains("id=\"exposure\">Exposure</h2>")?
        .body_contains("value=\"99999\"")?;
    when.submitting(
        &settings,
        &format!("{page}/secrets/remove"),
        &[("variable", "API_KEY")],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("{page}/settings?done=secret-removed"))?;

    let releases = call(
        &when,
        &then,
        "ListReleases",
        json!({"organisation": org, "name": "hello"}),
    )
    .await?;
    then.status(200)?;
    let releases = releases["releases"].as_array().cloned().unwrap_or_default();
    let digest_of = |number: u64| {
        releases
            .iter()
            .find(|r| r["number"].as_u64() == Some(number))
            .and_then(|r| r["imageDigest"].as_str())
            .unwrap_or_default()
            .to_string()
    };
    anyhow::ensure!(releases.len() == 5, "v1 to v5: {releases:#?}");
    anyhow::ensure!(digest_of(1) == first, "v1 is the first image");
    for number in [2, 3, 4, 5] {
        anyhow::ensure!(
            digest_of(number) == second,
            "a change of settings keeps v2's image: v{number} {releases:#?}"
        );
    }
    when.visiting(&settings).await?;
    then.status(200)?
        .body_contains("1: GREETING")?
        .body_lacks("API_KEY")?
        .body_contains(&format!(
            "<a class=\"tile\" href=\"/{org}/apps/hello/settings?edit=secrets\">"
        ))?;
    when.visiting(&format!("{settings}?edit=env")).await?;
    then.status(200)?
        .body_contains("value=\"GREETING\"")?
        .body_contains("value=\"hallo\"")?
        .body_contains("Saving makes release v")?;
    when.visiting(&format!("{settings}?edit=secrets")).await?;
    then.status(200)?
        .body_contains("not read by the app")?
        .body_lacks("s3cr3t-value")?;
    when.visiting(&format!("{settings}?edit=volumes")).await?;
    then.status(200)?;

    let yaml = format!("{page}/grund.yaml");
    when.visiting(&yaml).await?;
    then.status(200)?
        .header("content-type", "application/yaml; charset=utf-8")?
        .header("content-disposition", "attachment; filename=\"grund.yaml\"")?
        .body_contains("\n  hello:\n")?
        .body_contains("GREETING: hallo\n")?;
    let file = then.body()?;
    let schema_line = format!(
        "# yaml-language-server: $schema={}/schema/grund.json\n",
        when.origin_a_browser_sends(None)
    );
    anyhow::ensure!(file.starts_with(&schema_line), "{file}");
    when.submitting(
        &settings,
        &format!("{page}/settings/file"),
        &[(
            "file",
            &file.replace("    image:", "    copies: 99\n    image:"),
        )],
    )
    .await?;
    then.status(422)?
        .body_contains("Nothing was released. Check the file.")?
        .body_contains("apps.hello.copies: use 1 to 20.")?
        .body_contains("id=\"as-file\">grund.yaml</h2>")?;
    when.submitting(
        &settings,
        &format!("{page}/settings/file"),
        &[(
            "file",
            &file.replace("    image:", "    copis: 2\n    image:"),
        )],
    )
    .await?;
    then.status(422)?
        .body_contains("apps.hello.copis: line ")?
        .body_contains("unknown field `copis`")?;
    when.submitting(
        &settings,
        &format!("{page}/settings/file"),
        &[("file", &file.replace("GREETING: hallo", "GREETING: moin"))],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("{page}/settings?done=released-file"))?;
    let releases = call(
        &when,
        &then,
        "ListReleases",
        json!({"organisation": org, "name": "hello"}),
    )
    .await?;
    let newest = &releases["releases"][0];
    anyhow::ensure!(
        newest["source"] == "RELEASE_SOURCE_FILE" && newest["spec"]["env"][0]["value"] == "moin",
        "the file made the newest release: {newest:#}"
    );

    let deployments = format!("{page}/deployments");
    when.submitting(&deployments, &format!("{page}/releases/1/rollback"), &[])
        .await?;
    then.status(303)?
        .redirects_to(&format!("{page}/deployments?done=rolled-back"))?;
    when.visiting(&deployments).await?;
    then.status(200)?
        .body_contains("id=\"v7\"")?
        .body_contains(&format!("Rolled back to v1 by {org}"))?;

    when.submitting(
        &settings,
        &format!("{page}/settings/copies"),
        &[("copies", "2"), ("auto_rollback", "off")],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("{page}/settings?done=saved"))?;
    let shown = app(&when, &then, &org, "hello").await?;
    anyhow::ensure!(
        shown["settings"]["copies"] == 2 && shown["settings"]["autoRollback"] != true,
        "{shown:#}"
    );

    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    for tab in [
        "",
        "/deployments",
        "/logs",
        "/metrics",
        "/settings",
        "/grund.yaml",
    ] {
        outsider_when.visiting(&format!("{page}{tab}")).await?;
        outsider_then
            .status(404)
            .map_err(|error| error.context(format!("{page}{tab}")))?;
    }

    when.visiting(&settings).await?;
    then.status(200)?
        .body_contains("?edit=check\">")?
        .body_lacks(&format!(
            "<a class=\"tile\" href=\"/{org}/apps/hello/settings?edit=check\">"
        ))?;
    when.submitting(
        &settings,
        &format!("{page}/settings/release"),
        &[("part", "check"), ("check", "")],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("{page}/settings?done=released"))?;
    when.visiting(&settings).await?;
    then.status(200)?.body_contains(&format!(
        "<a class=\"tile\" href=\"/{org}/apps/hello/settings?edit=check\">"
    ))?;

    when.submitting(&settings, &format!("{page}/delete"), &[("confirm", "hell")])
        .await?;
    then.status(422)?
        .body_contains("Nothing was deleted.")?
        .body_contains("Type hello exactly to delete it.")?;
    app(&when, &then, &org, "hello").await?;
    when.submitting(
        &settings,
        &format!("{page}/delete"),
        &[("confirm", "hello")],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("/{org}/apps?done=deleted"))?;
    Ok(())
}
