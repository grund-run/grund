use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, ensure};
use buffa::Message;
use grund_agent::runtime::{ContainerRuntime, TaskState};
use grund_proto::grund::run::v1::ErrorReason;
use serde_json::{Value, json};

use crate::accepttest::{
    apps::{a_machine, app, data_dir},
    fixtures::{
        FakeRegistry, Given, Then, When, external_target, grund_binary, random_hex,
        testcase_configured,
    },
    machines::origin,
    stacks::token,
};

const RUNS: &str = "/grund.run.v1.RunService";
const STACKS: &str = "/grund.stack.v1.StackService";
const STACK: &str = "oneoff";

async fn rpc(
    when: &When,
    then: &Then,
    service: &str,
    method: &str,
    body: Value,
) -> anyhow::Result<Value> {
    when.calling(&format!("{service}/{method}"), &body.to_string())
        .await?;
    then.json()
}

fn requests(org: &str, id: &str) -> [(&'static str, Value); 5] {
    [
        (
            "CreateRun",
            json!({"organisation":org,"stack":STACK,"service":"web","args":["exit23"],"idempotencyKey":"auth-probe"}),
        ),
        ("GetRun", json!({"organisation":org,"id":id})),
        ("ListRuns", json!({"organisation":org,"stack":STACK})),
        (
            "CancelRun",
            json!({"organisation":org,"id":id,"idempotencyKey":"auth-cancel"}),
        ),
        ("ListRunLogs", json!({"organisation":org,"id":id})),
    ]
}

async fn denied(
    when: &When,
    then: &Then,
    org: &str,
    id: &str,
    bearer: Option<&str>,
    code: &str,
) -> anyhow::Result<()> {
    for (method, body) in requests(org, id) {
        let headers = bearer
            .map(|value| vec![("Authorization", value)])
            .unwrap_or_default();
        when.calling_with(&format!("{RUNS}/{method}"), &body.to_string(), &headers)
            .await?;
        then.connect_code(code)
            .with_context(|| format!("{method} accepted a forbidden caller"))?;
    }
    Ok(())
}

fn yaml(image: &str) -> String {
    format!(
        "stack:\n  name: {STACK}\n  services:\n    web:\n      image: {image}\n      resources:\n        memory: 64 MiB\n        cpu: 0.1\n      release:\n        min_ready: 0\n        ready_deadline: 90\n        drain: 1\n    db:\n      image: {image}\n      volumes:\n        data:\n          path: /data\n      resources:\n        memory: 64 MiB\n        cpu: 0.1\n      release:\n        min_ready: 0\n        ready_deadline: 90\n        drain: 1\n"
    )
}

async fn deploy(when: &When, then: &Then, org: &str, image: &str) -> anyhow::Result<Value> {
    let value = rpc(
        when,
        then,
        STACKS,
        "DeployStack",
        json!({"organisation":org,"yaml":yaml(image),"idempotencyKey":"deploy"}),
    )
    .await?;
    then.status(200)?;
    Ok(value["stack"].clone())
}

async fn stack(when: &When, then: &Then, org: &str) -> anyhow::Result<Value> {
    let value = rpc(
        when,
        then,
        STACKS,
        "GetStack",
        json!({"organisation":org,"name":STACK}),
    )
    .await?;
    then.status(200)?;
    Ok(value["stack"].clone())
}

async fn ready(when: &When, then: &Then, org: &str) -> anyhow::Result<Value> {
    let until = Instant::now() + Duration::from_secs(180);
    loop {
        let value = stack(when, then, org).await?;
        if value["status"] == "ready" && value["operation"].as_str().is_none_or(str::is_empty) {
            return Ok(value);
        }
        if Instant::now() >= until || value["status"] == "halted" {
            let mut children = Vec::new();
            for service in value["services"].as_array().into_iter().flatten() {
                if let Some(name) = service["appName"].as_str() {
                    children.push(app(when, then, org, name).await?);
                }
            }
            anyhow::bail!(
                "stack never became ready: {value}; children: {children:?}; server: {}",
                when.testcase.fixture.log()
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn service<'a>(stack: &'a Value, name: &str) -> anyhow::Result<&'a Value> {
    stack["services"]
        .as_array()
        .context("stack services missing")?
        .iter()
        .find(|value| value["name"] == name)
        .context("stack service missing")
}

fn reason(error: &Value) -> anyhow::Result<String> {
    let detail = error["details"]
        .as_array()
        .context("run error details missing")?
        .iter()
        .find(|value| value["type"] == "grund.run.v1.ErrorReason")
        .context("run ErrorReason missing")?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD.decode(
        detail["value"]
            .as_str()
            .context("error reason value missing")?
            .trim_end_matches('='),
    )?;
    Ok(ErrorReason::decode_from_slice(&bytes)?.reason)
}

#[tokio::test]
async fn every_run_method_requires_a_current_owner_session_and_refuses_owner_issued_pats()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    registry.publish("accept/run", "1");
    deploy(&when, &then, org, &registry.image("accept/run", "1")).await?;
    let id = uuid::Uuid::now_v7().to_string();
    for (method, body) in requests(org, &id) {
        rpc(&when, &then, RUNS, method, body).await?;
        match method {
            "CreateRun" => {
                then.connect_code("failed_precondition")?;
            }
            "ListRuns" => {
                then.status(200)?;
            }
            _ => {
                then.connect_code("not_found")?;
            }
        }
    }
    let (_, anonymous, anonymous_then) = given.testcase.another_browser();
    denied(
        &anonymous,
        &anonymous_then,
        org,
        &id,
        None,
        "unauthenticated",
    )
    .await?;
    for (name, scope) in [
        ("run-full", "TOKEN_SCOPE_FULL"),
        ("run-deploy", "TOKEN_SCOPE_DEPLOY"),
    ] {
        let bearer = token(&when, &then, org, name, scope, &[]).await?;
        denied(
            &anonymous,
            &anonymous_then,
            org,
            &id,
            Some(&bearer),
            "permission_denied",
        )
        .await?;
    }
    let (member_given, member_when, member_then) = given.testcase.another_browser();
    let member = member_given.a_signed_in_account().await?;
    when.inviting(org, &member.email, "member").await?;
    then.status(303)?;
    let link = member_when
        .the_mailed_link(
            &member.email,
            &format!("Join {org} on grund"),
            "/invite?token=",
        )
        .await?;
    member_when.visiting(&link).await?;
    member_then.status(200)?;
    member_when
        .submitting_on_current_page("/invite", &[("token", &member_given.last_token()?)])
        .await?;
    member_then.status(303)?;
    denied(
        &member_when,
        &member_then,
        org,
        &id,
        None,
        "permission_denied",
    )
    .await?;
    let (foreign_given, foreign_when, foreign_then) = given.testcase.another_browser();
    foreign_given.a_signed_in_account().await?;
    denied(&foreign_when, &foreign_then, org, &id, None, "not_found").await?;
    ensure!(given.testcase.fixture.sql(&format!("UPDATE grund_memberships SET role = 'member' WHERE account_id = (SELECT account_id FROM grund_accounts WHERE username = '{org}') AND organisation_id = (SELECT organisation_id FROM grund_organisations WHERE slug = '{org}')")).await? == 1, "owner grant was not revoked");
    denied(&when, &then, org, &id, None, "permission_denied").await?;
    Ok(())
}

#[tokio::test]
async fn a_simulated_agent_is_not_a_supported_run_runtime_and_selected_volumes_are_never_dropped()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _agent = a_machine(&when, &then, org, "unsupported-run-box").await?;
    registry.publish("accept/run", "1");
    deploy(&when, &then, org, &registry.image("accept/run", "1")).await?;
    let before = ready(&when, &then, org).await?;
    for (selected, expected) in [
        ("web", "run_agent_unsupported"),
        ("db", "run_volumes_unsupported"),
    ] {
        let error = rpc(&when, &then, RUNS, "CreateRun", json!({"organisation":org,"stack":STACK,"service":selected,"args":["never-run"],"idempotencyKey":selected})).await?;
        then.connect_code("failed_precondition")?;
        ensure!(
            reason(&error)? == expected,
            "wrong admission refusal: {error}"
        );
    }
    let after = stack(&when, &then, org).await?;
    ensure!(
        before["version"] == after["version"] && before["revision"] == after["revision"],
        "refused run mutated the stack"
    );
    ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_runs")
            .await?
            == 0,
        "refused admission created a run"
    );
    Ok(())
}

struct Process {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
}

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Process {
    fn spawn(mut command: Command, dir: &Path, label: &str) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let stdout = dir.join(format!("{label}-{}.stdout", random_hex(4)));
        let stderr = dir.join(format!("{label}-{}.stderr", random_hex(4)));
        let child = command
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&stdout)?)
            .stderr(std::fs::File::create(&stderr)?)
            .spawn()?;
        Ok(Self {
            child,
            stdout,
            stderr,
        })
    }

    async fn finish(&mut self, within: Duration) -> anyhow::Result<Output> {
        let until = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(Output {
                    code: status.code(),
                    stdout: std::fs::read_to_string(&self.stdout)?,
                    stderr: std::fs::read_to_string(&self.stderr)?,
                });
            }
            ensure!(
                Instant::now() < until,
                "process did not finish: {}",
                std::fs::read_to_string(&self.stderr).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn kill(&mut self) -> anyhow::Result<()> {
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }
}

fn cli_command(home: &Path, instance: &str, args: &[&str]) -> Command {
    let mut command = Command::new(grund_binary());
    command
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("GRUND_INSTANCE", instance)
        .current_dir(home);
    command
}

async fn cli(home: &Path, instance: &str, args: &[&str]) -> anyhow::Result<Output> {
    let mut process = Process::spawn(cli_command(home, instance, args), home, "reattach")?;
    process.finish(Duration::from_secs(30)).await
}

async fn cli_session(home: &Path, when: &When, then: &Then) -> anyhow::Result<()> {
    let instance = origin(when);
    let command = cli_command(
        home,
        &instance,
        &["auth", "login", &instance, "--json", "--no-browser"],
    );
    let mut login = Process::spawn(command, home, "login")?;
    let until = Instant::now() + Duration::from_secs(30);
    let uri = loop {
        let output = std::fs::read_to_string(&login.stderr)?;
        if let Some(uri) = output
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find_map(|line| line["verificationUriComplete"].as_str().map(str::to_owned))
        {
            break uri;
        }
        ensure!(
            Instant::now() < until && login.child.try_wait()?.is_none(),
            "CLI device login failed: {output}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let path = &uri[uri
        .find("/device")
        .context("device verification URI missing")?..];
    when.visiting(path).await?;
    then.status(200)?;
    let html = then.body()?;
    let prefix = "name=\"login\" value=\"";
    let value = html
        .split_once(prefix)
        .context("device approval form missing")?
        .1
        .split('"')
        .next()
        .context("device approval login missing")?;
    when.submitting(
        path,
        "/device",
        &[("login", value), ("decision", "approve")],
    )
    .await?;
    then.status(200)?;
    let output = login.finish(Duration::from_secs(30)).await?;
    ensure!(
        output.code == Some(0),
        "CLI login failed: {}",
        output.stderr
    );
    Ok(())
}

fn spawn_agent(dir: &Path) -> anyhow::Result<Process> {
    let mut command = Command::new(grund_binary());
    command
        .args([
            "agent",
            "--app-runtime",
            "containerd",
            "--interval",
            "1",
            "--data-dir",
        ])
        .arg(dir)
        .arg("--policy")
        .arg(dir.join("policy.yaml"))
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("RUST_LOG", "grund_agent=info,grund_containers=info,warn");
    Process::spawn(command, dir, "agent")
}

async fn real_agent(when: &When, then: &Then, org: &str) -> anyhow::Result<(PathBuf, Process)> {
    let value = rpc(
        when,
        then,
        "/grund.machine.v1.MachineService",
        "CreateJoinToken",
        json!({"organisation":org,"name":"real-run-box"}),
    )
    .await?;
    then.status(200)?;
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    let token = value["token"]
        .as_str()
        .context("machine join token missing")?;
    let output = when
        .testcase
        .fixture
        .running(&[
            "join",
            "--data-dir",
            dir.to_str().context("non-UTF8 machine directory")?,
            "--url",
            &origin(when),
            token,
        ])
        .await?;
    ensure!(output.success, "machine join failed: {}", output.stderr);
    let process = spawn_agent(&dir)?;
    Ok((dir, process))
}

async fn running_pid(id: &str) -> anyhow::Result<u32> {
    let runtime = grund_containers::Containerd::new(grund_containers::Config::default());
    let task = runtime
        .list_runs()
        .await?
        .into_iter()
        .find(|task| task.id == id)
        .context("real containerd run task missing")?;
    match task.state {
        TaskState::Running { pid } => Ok(pid),
        state => anyhow::bail!("real containerd task is not running: {state:?}"),
    }
}

async fn process_absent(id: &str) -> anyhow::Result<()> {
    let runtime = grund_containers::Containerd::new(grund_containers::Config::default());
    ensure!(
        !runtime
            .list_runs()
            .await?
            .iter()
            .any(|task| task.id == id && matches!(task.state, TaskState::Running { .. })),
        "server claimed stop while real containerd still runs the task"
    );
    Ok(())
}

fn argv(mode: &str, marker: &str, sentinel: &str) -> Vec<String> {
    [
        mode,
        marker,
        sentinel,
        "two words",
        "",
        "*",
        "$(touch /must-not-exist)",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

async fn get_run(when: &When, then: &Then, org: &str, id: &str) -> anyhow::Result<Value> {
    let value = rpc(
        when,
        then,
        RUNS,
        "GetRun",
        json!({"organisation":org,"id":id}),
    )
    .await?;
    then.status(200)?;
    Ok(value["run"].clone())
}

async fn run_until(
    when: &When,
    then: &Then,
    org: &str,
    id: &str,
    state: &str,
) -> anyhow::Result<Value> {
    let until = Instant::now() + Duration::from_secs(90);
    loop {
        let run = get_run(when, then, org, id).await?;
        if run["state"] == state {
            return Ok(run);
        }
        ensure!(
            Instant::now() < until,
            "run never reached {state}: {run}; server: {}",
            when.testcase.fixture.log()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn create(
    when: &When,
    then: &Then,
    org: &str,
    args: &[String],
    timeout: u32,
    key: &str,
) -> anyhow::Result<Value> {
    let value = rpc(when, then, RUNS, "CreateRun", json!({"organisation":org,"stack":STACK,"service":"web","args":args,"timeoutSeconds":timeout,"idempotencyKey":key})).await?;
    then.status(200)?;
    Ok(value["run"].clone())
}

async fn logs(when: &When, then: &Then, org: &str, id: &str) -> anyhow::Result<Vec<Value>> {
    let mut cursor = String::new();
    let mut result = Vec::new();
    for _ in 0..20 {
        let page = rpc(
            when,
            then,
            RUNS,
            "ListRunLogs",
            json!({"organisation":org,"id":id,"pageSize":1000,"pageToken":cursor}),
        )
        .await?;
        then.status(200)?;
        ensure!(
            page["gaps"]
                .as_array()
                .is_none_or(|gaps| gaps.iter().all(|gap| gap["reason"] == "machine_offline"))
                && page["droppedRecords"].as_str().unwrap_or("0") == "0"
                && page["droppedRecords"].as_u64().unwrap_or(0) == 0,
            "real run proof lost output: {page}"
        );
        let records = page["logs"].as_array().cloned().unwrap_or_default();
        ensure!(
            records.iter().all(|record| record["truncated"] != true),
            "real run proof truncated process output"
        );
        cursor = page["nextPageToken"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let empty = records.is_empty();
        result.extend(records);
        if empty {
            return Ok(result);
        }
    }
    anyhow::bail!("run logs did not finish within 20 pages")
}

async fn observed_once(
    when: &When,
    then: &Then,
    org: &str,
    id: &str,
    marker: &str,
) -> anyhow::Result<()> {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let records = logs(when, then, org, id).await?;
        let stdout = records
            .iter()
            .filter(|row| {
                row["stream"] == "stdout"
                    && row["body"]
                        .as_str()
                        .is_some_and(|body| body.contains(&format!("grund-run-stdout:{marker}")))
            })
            .count();
        let stderr = records
            .iter()
            .filter(|row| {
                row["stream"] == "stderr"
                    && row["body"]
                        .as_str()
                        .is_some_and(|body| body.contains(&format!("grund-run-stderr:{marker}")))
            })
            .count();
        ensure!(
            stdout <= 1 && stderr <= 1,
            "run executed twice: {records:?}"
        );
        if stdout == 1 && stderr == 1 {
            return Ok(());
        }
        ensure!(
            Instant::now() < until,
            "both real process streams were not delivered: {records:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn private_arguments(given: &Given, sentinel: &str, agent: &Process) -> anyhow::Result<()> {
    let fixture = &given.testcase.fixture;
    for table in ["es_events", "grund_run_requests", "grund_runs"] {
        ensure!(fixture.count(&format!("SELECT count(*) FROM {table} t WHERE position('{sentinel}' in to_jsonb(t)::text) > 0")).await? == 0, "argument sentinel leaked to {table}");
    }
    ensure!(fixture.count(&format!("SELECT count(*) FROM grund_run_payloads t WHERE position('{sentinel}' in to_jsonb(t)::text) > 0")).await? > 0, "arguments were never attached to the access-controlled payload");
    ensure!(fixture.count(&format!("SELECT count(*) FROM grund_machine_documents WHERE position(convert_to('{sentinel}', 'UTF8') in payload) > 0")).await? == 0, "arguments leaked into signed desired state");
    ensure!(
        !fixture.log().contains(sentinel),
        "arguments leaked to the server log"
    );
    ensure!(
        !std::fs::read_to_string(&agent.stdout)?.contains(sentinel)
            && !std::fs::read_to_string(&agent.stderr)?.contains(sentinel),
        "arguments leaked to the agent log"
    );
    let receipt_root = agent
        .stderr
        .parent()
        .context("agent log directory missing")?
        .join("runs");
    let mut receipts = 0;
    for entry in std::fs::read_dir(receipt_root)? {
        let directory = entry?.path();
        for name in ["claim.json", "receipt.json"] {
            match std::fs::read_to_string(directory.join(name)) {
                Ok(bytes) => {
                    receipts += 1;
                    ensure!(
                        !bytes.contains(sentinel),
                        "argument sentinel leaked into an agent launch/exit receipt"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    ensure!(
        receipts > 0,
        "real execution left no durable launch/exit receipt"
    );
    Ok(())
}

#[tokio::test]
async fn real_container_entrypoint_exit23_cli_replay_cancellation_and_restart_deadlines_are_end_to_end()
-> anyhow::Result<()> {
    if std::env::var("GRUND_ACCEPT_RUN_CONTAINERD").ok().as_deref() != Some("1") {
        eprintln!(
            "skipped real run execution: set GRUND_ACCEPT_RUN_CONTAINERD=1 and GRUND_ACCEPT_RUN_IMAGE to the published sha256 image built from tests/accepttest/fixtures/run-image; requires a disposable root Linux cgroup-v2/overlayfs host, not the simulated runtime"
        );
        return Ok(());
    }
    ensure!(
        external_target().is_none(),
        "real run acceptance owns its server/database; unset GRUND_ACCEPT_URL"
    );
    let uid = Command::new("id").arg("-u").output()?;
    ensure!(
        uid.status.success() && uid.stdout == b"0\n",
        "real containerd run acceptance needs root on a disposable host"
    );
    ensure!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "real run acceptance needs cgroup v2"
    );
    let image = std::env::var("GRUND_ACCEPT_RUN_IMAGE").context(
        "publish fixtures/run-image and set GRUND_ACCEPT_RUN_IMAGE=registry/repository@sha256:...",
    )?;
    ensure!(
        image
            .split_once("@sha256:")
            .is_some_and(|(_, digest)| digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "GRUND_ACCEPT_RUN_IMAGE must be an immutable image digest"
    );
    let insecure = std::env::var("GRUND_ACCEPT_RUN_INSECURE_REGISTRY").ok();
    if let Some(host) = &insecure {
        ensure!(
            host.strip_prefix("127.0.0.1:")
                .is_some_and(|port| port.parse::<u16>().is_ok())
                && image.starts_with(&format!("{host}/")),
            "insecure acceptance registry must be a loopback host:port matching the fixture image"
        );
        let hosts = Path::new("/var/lib/grund/runtime-registry-hosts").join(host);
        std::fs::create_dir_all(&hosts)?;
        std::fs::write(
            hosts.join("hosts.toml"),
            format!(
                "server = \"http://{host}\"\n[host.\"http://{host}\"]\n  capabilities = [\"pull\", \"resolve\"]\n"
            ),
        )?;
    }
    let settings = insecure
        .as_deref()
        .map(|host| vec![("GRUND_INSECURE_REGISTRIES", host)])
        .unwrap_or_default();
    let Some((given, when, then)) = testcase_configured(&settings).await? else {
        anyhow::bail!("real run fixture cannot attach to an external target");
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let (agent_dir, mut agent) = real_agent(&when, &then, org).await?;
    deploy(&when, &then, org, &image).await?;
    let before = ready(&when, &then, org).await?;
    let web = service(&before, "web")?;
    let app_name = web["appName"].as_str().context("web backing app missing")?;
    let app_before = app(&when, &then, org, app_name).await?;
    let releases_before = rpc(
        &when,
        &then,
        "/grund.app.v1.AppService",
        "ListReleases",
        json!({"organisation":org,"name":app_name}),
    )
    .await?;
    then.status(200)?;
    let fixture = &given.testcase.fixture;
    let replicas_before = fixture.count("SELECT count(*) FROM grund_replicas").await?;
    let volumes_before = fixture.count("SELECT count(*) FROM grund_volumes").await?;
    let error = rpc(&when, &then, RUNS, "CreateRun", json!({"organisation":org,"stack":STACK,"service":"db","args":["exit23"],"idempotencyKey":"reject-volume"})).await?;
    then.connect_code("failed_precondition")?;
    ensure!(
        reason(&error)? == "run_volumes_unsupported",
        "selected persistent volume was not refused: {error}"
    );
    let home = data_dir();
    std::fs::create_dir_all(&home)?;
    cli_session(&home, &when, &then).await?;
    let marker = format!("exit23-{}", random_hex(6));
    let sentinel = format!("private-{}@accept.invalid", random_hex(10));
    let args = argv("exit23", &marker, &sentinel);
    let mut cli_args = vec![
        "stack",
        "run",
        STACK,
        "--org",
        org,
        "--service",
        "web",
        "--timeout",
        "60s",
        "--idempotency-key",
        "real-cli-exit23",
        "--",
    ];
    cli_args.extend(args.iter().map(String::as_str));
    let instance = origin(&when);
    let mut process = Process::spawn(cli_command(&home, &instance, &cli_args), &home, "run")?;
    let output = process.finish(Duration::from_secs(90)).await?;
    ensure!(
        output.code == Some(23),
        "real CLI did not propagate process exit23: {:?}: {}{}",
        output.code,
        output.stdout,
        output.stderr
    );
    ensure!(
        output
            .stdout
            .contains(&format!("grund-run-stdout:{marker}"))
            && output
                .stdout
                .contains(&format!("grund-run-stderr:{marker}")),
        "CLI did not follow both process streams: {}{}",
        output.stdout,
        output.stderr
    );
    ensure!(
        !output.stdout.contains('\u{1b}') && !output.stderr.contains(&sentinel),
        "CLI leaked arguments or terminal controls"
    );
    let listed = rpc(
        &when,
        &then,
        RUNS,
        "ListRuns",
        json!({"organisation":org,"stack":STACK}),
    )
    .await?;
    then.status(200)?;
    let listed_runs = listed["runs"].as_array().context("run list missing")?;
    ensure!(
        listed_runs.len() == 1 && listed_runs[0]["args"].as_array().is_none_or(Vec::is_empty),
        "run list duplicated execution or exposed arguments: {listed}"
    );
    let id = listed_runs[0]["id"].as_str().context("run id missing")?;
    ensure!(
        output.stderr.contains(id),
        "CLI omitted the committed run id"
    );
    let finished = get_run(&when, &then, org, id).await?;
    ensure!(
        finished["state"] == "RUN_STATE_FAILED"
            && finished["exitCode"] == 23
            && finished["args"] == json!(args),
        "audit outcome/argv mismatch: {finished}"
    );
    ensure!(
        finished["stackRevision"] == before["revision"]
            && finished["release"] == web["desiredRelease"]
            && finished["imageDigest"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:")),
        "run did not pin the applied immutable release: {finished}"
    );
    for field in [
        "requesterId",
        "machineId",
        "requestedAt",
        "startedAt",
        "finishedAt",
        "deadline",
    ] {
        ensure!(
            finished[field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "run audit missing {field}: {finished}"
        );
    }
    let requester = finished["requesterId"]
        .as_str()
        .context("requester missing")?;
    ensure!(fixture.count(&format!("SELECT count(*) FROM grund_accounts WHERE username = '{org}' AND account_id = '{requester}'")).await? == 1, "audit requester is not the authenticated owner");
    let requested = chrono::DateTime::parse_from_rfc3339(
        finished["requestedAt"]
            .as_str()
            .context("requested timestamp missing")?,
    )?;
    let started = chrono::DateTime::parse_from_rfc3339(
        finished["startedAt"]
            .as_str()
            .context("started timestamp missing")?,
    )?;
    let ended = chrono::DateTime::parse_from_rfc3339(
        finished["finishedAt"]
            .as_str()
            .context("finished timestamp missing")?,
    )?;
    ensure!(
        requested <= started && started <= ended,
        "run audit timestamps are out of lifecycle order"
    );
    observed_once(&when, &then, org, id, &marker).await?;
    let event_count = fixture
        .count(&format!(
            "SELECT count(*) FROM es_events WHERE stream_id = 'grund-run-{id}'"
        ))
        .await?;
    ensure!(
        event_count >= 3,
        "real execution has no lifecycle audit events"
    );
    let mut replay = Process::spawn(cli_command(&home, &instance, &cli_args), &home, "replay")?;
    let replay = replay.finish(Duration::from_secs(30)).await?;
    ensure!(
        replay.code == Some(23) && replay.stderr.contains(id),
        "CLI replay lost the original outcome: {}{}",
        replay.stdout,
        replay.stderr
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    observed_once(&when, &then, org, id, &marker).await?;
    ensure!(
        fixture
            .count(&format!(
                "SELECT count(*) FROM es_events WHERE stream_id = 'grund-run-{id}'"
            ))
            .await?
            == event_count
            && fixture.count("SELECT count(*) FROM grund_runs").await? == 1,
        "idempotency replay produced another run or lifecycle"
    );
    let status = cli(
        &home,
        &instance,
        &["stack", "run-status", id, "--org", org, "--json"],
    )
    .await?;
    ensure!(
        status.code == Some(0)
            && serde_json::from_str::<Value>(&status.stdout)?["run"]["exitCode"] == 23,
        "CLI status reattachment lost the child outcome: {}{}",
        status.stdout,
        status.stderr
    );
    let saved_logs = cli(
        &home,
        &instance,
        &["stack", "run-logs", id, "--org", org, "--json"],
    )
    .await?;
    ensure!(
        saved_logs.code == Some(0)
            && saved_logs
                .stdout
                .contains(&format!("grund-run-stdout:{marker}"))
            && saved_logs
                .stdout
                .contains(&format!("grund-run-stderr:{marker}")),
        "CLI log reattachment lost either stream: {}{}",
        saved_logs.stdout,
        saved_logs.stderr
    );
    let mut conflict = args.clone();
    conflict[2] = "changed-private-argument".into();
    rpc(&when, &then, RUNS, "CreateRun", json!({"organisation":org,"stack":STACK,"service":"web","args":conflict,"timeoutSeconds":60,"idempotencyKey":"real-cli-exit23"})).await?;
    then.connect_code("already_exists")?;
    private_arguments(&given, &sentinel, &agent).await?;
    let app_after = app(&when, &then, org, app_name).await?;
    let releases_after = rpc(
        &when,
        &then,
        "/grund.app.v1.AppService",
        "ListReleases",
        json!({"organisation":org,"name":app_name}),
    )
    .await?;
    then.status(200)?;
    ensure!(
        releases_before == releases_after,
        "run mutated the pinned image, spec, command or release history"
    );
    let after = stack(&when, &then, org).await?;
    ensure!(
        before["version"] == after["version"]
            && before["revision"] == after["revision"]
            && app_before["version"] == app_after["version"]
            && app_before["currentRelease"] == app_after["currentRelease"]
            && app_before["settings"] == app_after["settings"],
        "run changed stack/app deployment configuration"
    );
    ensure!(
        fixture.count("SELECT count(*) FROM grund_replicas").await? == replicas_before
            && fixture.count("SELECT count(*) FROM grund_volumes").await? == volumes_before,
        "run allocated an app replica or changed persistent mounts"
    );
    let ordinary = rpc(
        &when,
        &then,
        "/grund.app.v1.AppTelemetryService",
        "ListAppLogs",
        json!({"organisation":org,"name":app_name,"pageSize":1000}),
    )
    .await?;
    then.status(200)?;
    ensure!(
        !ordinary.to_string().contains(&marker),
        "unfiltered app logs exposed owner-only run output"
    );
    let (foreign_given, foreign_when, foreign_then) = given.testcase.another_browser();
    let foreign = foreign_given.a_signed_in_account().await?;
    for selected_org in [org, foreign.username.as_str()] {
        for method in ["GetRun", "CancelRun", "ListRunLogs"] {
            rpc(
                &foreign_when,
                &foreign_then,
                RUNS,
                method,
                json!({"organisation":selected_org,"id":id,"idempotencyKey":"foreign-cancel"}),
            )
            .await?;
            foreign_then.connect_code("not_found")?;
        }
    }
    let marker = format!("cancel-{}", random_hex(6));
    let hold = create(
        &when,
        &then,
        org,
        &argv("hold", &marker, "cancel-private"),
        60,
        "hold-cancel",
    )
    .await?;
    let hold_id = hold["id"].as_str().context("hold run id missing")?;
    run_until(&when, &then, org, hold_id, "RUN_STATE_RUNNING").await?;
    let blocked = rpc(&when, &then, RUNS, "CreateRun", json!({"organisation":org,"stack":STACK,"service":"web","args":argv("hold", "must-not-start", "private"),"timeoutSeconds":60,"idempotencyKey":"second-active"})).await?;
    then.connect_code("failed_precondition")?;
    ensure!(
        reason(&blocked)? == "run_outstanding",
        "one-service admission fence allowed a second process: {blocked}"
    );
    observed_once(&when, &then, org, hold_id, &marker).await?;
    let held_pid = running_pid(hold_id).await?;
    agent.kill()?;
    agent = spawn_agent(&agent_dir)?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let adopted = get_run(&when, &then, org, hold_id).await?;
    ensure!(
        adopted["state"] == "RUN_STATE_RUNNING" && adopted["deadline"] == hold["deadline"],
        "agent restart changed the existing attempt/deadline: {adopted}"
    );
    ensure!(
        running_pid(hold_id).await? == held_pid,
        "agent restart replaced rather than adopted the original real process"
    );
    observed_once(&when, &then, org, hold_id, &marker).await?;
    let stop = cli(
        &home,
        &instance,
        &[
            "stack",
            "run-cancel",
            hold_id,
            "--org",
            org,
            "--idempotency-key",
            "cli-cancel",
            "--json",
        ],
    )
    .await?;
    ensure!(
        stop.code == Some(0),
        "CLI run cancellation failed: {}{}",
        stop.stdout,
        stop.stderr
    );
    for key in ["cancel-one", "cancel-two"] {
        rpc(
            &when,
            &then,
            RUNS,
            "CancelRun",
            json!({"organisation":org,"id":hold_id,"idempotencyKey":key}),
        )
        .await?;
        then.status(200)?;
    }
    let cancelled = run_until(&when, &then, org, hold_id, "RUN_STATE_CANCELLED").await?;
    ensure!(
        cancelled["stopConfirmed"] == true,
        "cancelled was reported without confirmed process absence"
    );
    process_absent(hold_id).await?;
    observed_once(&when, &then, org, hold_id, &marker).await?;
    agent.kill()?;
    let queued_marker = format!("queued-{}", random_hex(6));
    let queued = create(
        &when,
        &then,
        org,
        &argv("hold", &queued_marker, "queued-private"),
        60,
        "cancel-before-start",
    )
    .await?;
    let queued_id = queued["id"].as_str().context("queued run id missing")?;
    rpc(
        &when,
        &then,
        RUNS,
        "CancelRun",
        json!({"organisation":org,"id":queued_id,"idempotencyKey":"queued-cancel"}),
    )
    .await?;
    then.status(200)?;
    agent = spawn_agent(&agent_dir)?;
    let cancelled = run_until(&when, &then, org, queued_id, "RUN_STATE_CANCELLED").await?;
    ensure!(
        cancelled["stopConfirmed"] == true
            && cancelled["startedAt"].as_str().is_none_or(str::is_empty),
        "cancel-before-start executed the task: {cancelled}"
    );
    ensure!(
        logs(&when, &then, org, queued_id).await?.is_empty(),
        "cancelled queued run produced process output"
    );
    process_absent(queued_id).await?;
    let marker = format!("deadline-{}", random_hex(6));
    let timed = create(
        &when,
        &then,
        org,
        &argv("hold", &marker, "deadline-private"),
        30,
        "deadline-restart",
    )
    .await?;
    let timed_id = timed["id"].as_str().context("deadline run id missing")?;
    run_until(&when, &then, org, timed_id, "RUN_STATE_RUNNING").await?;
    observed_once(&when, &then, org, timed_id, &marker).await?;
    let timed_pid = running_pid(timed_id).await?;
    agent.kill()?;
    let deadline = chrono::DateTime::parse_from_rfc3339(
        timed["deadline"]
            .as_str()
            .context("absolute deadline missing")?,
    )?;
    let delay = (deadline.with_timezone(&chrono::Utc) - chrono::Utc::now())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(delay + Duration::from_secs(2)).await;
    ensure!(
        running_pid(timed_id).await? == timed_pid,
        "deadline fixture did not preserve the running process across agent downtime"
    );
    agent = spawn_agent(&agent_dir)?;
    let expired = run_until(&when, &then, org, timed_id, "RUN_STATE_TIMED_OUT").await?;
    ensure!(
        expired["stopConfirmed"] == true && expired["deadline"] == timed["deadline"],
        "restart reset the original deadline or invented task absence: {expired}"
    );
    process_absent(timed_id).await?;
    observed_once(&when, &then, org, timed_id, &marker).await?;
    fixture.restart_with(&[]).await?;
    ensure!(
        get_run(&when, &then, org, id).await?["exitCode"] == 23,
        "server restart lost the audited child exit"
    );
    let current = stack(&when, &then, org).await?;
    rpc(&when, &then, STACKS, "DeleteStack", json!({"organisation":org,"name":STACK,"expectedVersion":current["version"],"idempotencyKey":"cleanup"})).await?;
    then.status(200)?;
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        if stack(&when, &then, org).await?["status"] == "deleted" {
            break;
        }
        ensure!(
            Instant::now() < until,
            "real-runtime stack cleanup did not finish"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    agent.kill()?;
    Ok(())
}
