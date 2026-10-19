use std::{
    io::{BufRead, Write},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::Duration,
};

use grund_cli::{meta, schema::Registry};
use serde_json::{Value, json};

use crate::accepttest::{
    apps::{a_machine, data_dir},
    fixtures::{FakeRegistry, Then, When, grund_binary, testcase_configured},
    machines::origin,
};

struct Shell {
    home: std::path::PathBuf,
    env: Vec<(String, String)>,
    registry: Registry,
}

struct Ran {
    status: i32,
    stdout: String,
    stderr: String,
}

impl Ran {
    fn json(&self) -> anyhow::Result<Value> {
        serde_json::from_str(&self.stdout).map_err(|e| {
            anyhow::anyhow!(
                "stdout is not JSON ({e}): {}\nstderr: {}",
                self.stdout,
                self.stderr
            )
        })
    }

    fn error(&self) -> anyhow::Result<Value> {
        let error: Value = serde_json::from_str(self.stderr.trim())
            .map_err(|e| anyhow::anyhow!("stderr is not JSON ({e}): {}", self.stderr))?;
        Registry::compiled()
            .conforms(&error, "grund.cli.v1.ErrorOutput")
            .map_err(anyhow::Error::msg)?;
        Ok(error["error"].clone())
    }
}

impl Shell {
    fn fresh(env: &[(&str, &str)]) -> anyhow::Result<Self> {
        let home = data_dir();
        std::fs::create_dir_all(&home)?;
        let mut all: Vec<(String, String)> = vec![
            ("HOME".into(), home.display().to_string()),
            (
                "XDG_CONFIG_HOME".into(),
                home.join(".config").display().to_string(),
            ),
        ];
        all.extend(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        Ok(Shell {
            home,
            env: all,
            registry: Registry::compiled(),
        })
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(grund_binary());
        command
            .args(args)
            .current_dir(&self.home)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        command
    }

    async fn run_with(&self, args: &[&str], stdin: &str) -> anyhow::Result<Ran> {
        let mut command = self.command(args);
        let stdin = stdin.to_string();
        let output =
            tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
                let mut child = command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                child
                    .stdin
                    .take()
                    .expect("piped")
                    .write_all(stdin.as_bytes())?;
                child.wait_with_output()
            })
            .await??;
        Ok(Ran {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    async fn run(&self, args: &[&str]) -> anyhow::Result<Ran> {
        self.run_with(args, "").await
    }

    async fn json(&self, path: &str, args: &[&str]) -> anyhow::Result<Value> {
        self.json_with(path, args, "").await
    }

    async fn json_with(&self, path: &str, args: &[&str], stdin: &str) -> anyhow::Result<Value> {
        let mut all: Vec<&str> = path.split(' ').collect();
        if let ["app", "set", item] = all[..] {
            all = vec!["app", "set", args[0], item];
            all.extend_from_slice(&args[1..]);
        } else {
            all.extend_from_slice(args);
        }
        all.push("--json");
        let ran = self.run_with(&all, stdin).await?;
        anyhow::ensure!(
            ran.status == 0,
            "grund {path} {args:?} exited {}: {}{}",
            ran.status,
            ran.stdout,
            ran.stderr
        );
        let value = ran.json()?;
        let output = if args.contains(&"--dry-run") && path != "app deploy" {
            "grund.cli.v1.DryRun"
        } else {
            meta::leaf(path)
                .map(|l| l.output)
                .ok_or_else(|| anyhow::anyhow!("no metadata for {path}"))?
        };
        self.registry.conforms(&value, output).map_err(|e| {
            anyhow::anyhow!("grund {path} printed what {output} is not: {e}\n{value:#}")
        })?;
        Ok(value)
    }
}

async fn a_token(
    when: &When,
    then: &Then,
    org: &str,
    name: &str,
    scope: &str,
) -> anyhow::Result<String> {
    let page = format!("/{org}/settings/tokens");
    when.submitting(
        &page,
        &page,
        &[("name", name), ("days", "30"), ("scope", scope)],
    )
    .await?;
    then.status(200)?;
    let html = then.body()?;
    let start = html
        .find("grund_pat_")
        .ok_or_else(|| anyhow::anyhow!("no token on the page: {html}"))?;
    Ok(html[start..start + "grund_pat_".len() + 43].to_string())
}

#[tokio::test]
async fn hosted_machine_commands_explain_when_the_instance_has_no_hosted_service()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let token = a_token(&when, &then, &owner.username, "hosted-client", "full").await?;
    let instance = origin(&when);
    let shell = Shell::fresh(&[("GRUND_INSTANCE", &instance), ("GRUND_TOKEN", &token)])?;
    for args in [
        vec!["machine", "offers", "--json"],
        vec![
            "machine", "add", "hosted-1", "--hosted", "--size", "small", "--json",
        ],
    ] {
        let ran = shell.run(&args).await?;
        anyhow::ensure!(
            ran.status == 8,
            "unsupported hosted command was not explained: {}",
            ran.stderr
        );
        let error = ran.error()?;
        anyhow::ensure!(error["reason"] == "hosted_service_required", "{error}");
        anyhow::ensure!(
            error.get("rpc").is_none(),
            "raw RPC failure leaked instead of the supported-surface refusal"
        );
    }
    Ok(())
}

fn grund_yaml(image: &str) -> String {
    format!(
        "apps:\n  shop:\n    image: {image}\n    ports:\n      - name: http\n        port: 80\n    resources:\n      memory: 64\n      cpu: 0.1\n    check:\n      http: /\n      interval_ms: 500\n      timeout_ms: 200\n    stop:\n      grace: 1\n    release:\n      min_ready: 1\n      ready_deadline: 20\n      drain: 1\n"
    )
}

#[tokio::test]
async fn an_agent_with_a_token_deploys_from_grund_yaml_reads_status_scales_rolls_back_and_deletes()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _machine = a_machine(&when, &then, org, "m1").await?;
    let _second = a_machine(&when, &then, org, "m2").await?;
    let token = a_token(&when, &then, org, "agent", "full").await?;
    let instance = origin(&when);
    let shell = Shell::fresh(&[("GRUND_INSTANCE", &instance), ("GRUND_TOKEN", &token)])?;

    let me = shell.json("auth status", &[]).await?;
    anyhow::ensure!(
        me["credential"] == "token" && me["organisation"] == org,
        "{me:#}"
    );
    anyhow::ensure!(me["token"]["scope"] == "TOKEN_SCOPE_FULL", "{me:#}");

    registry.publish("acme/shop", "1");
    std::fs::write(
        shell.home.join("grund.yaml"),
        grund_yaml(&registry.image("acme/shop", "1")),
    )?;
    let planned = shell.json("app deploy", &["--dry-run"]).await?;
    anyhow::ensure!(
        planned["apps"][0]["created"] == true && planned["apps"][0]["dryRun"] == true,
        "{planned:#}"
    );
    let apps = shell.json("app list", &[]).await?;
    anyhow::ensure!(
        apps["apps"].as_array().is_none_or(Vec::is_empty),
        "a dry run made an app: {apps:#}"
    );

    let deployed = shell
        .json(
            "app deploy",
            &["-f", "grund.yaml", "--wait", "--timeout", "60"],
        )
        .await?;
    let first = &deployed["apps"][0];
    anyhow::ensure!(
        first["app"] == "shop"
            && first["created"] == true
            && first["release"]["number"] == 1
            && first["rollout"]["state"] == "ROLLOUT_STATE_SUCCEEDED",
        "{deployed:#}"
    );
    let status = shell.json("app status", &["shop"]).await?;
    anyhow::ensure!(
        status["health"] == "live" && status["copiesReady"] == 1,
        "{status:#}"
    );

    let stale = shell
        .run(&[
            "app",
            "deploy",
            "shop",
            "-f",
            "grund.yaml",
            "--expected-version",
            "0",
            "--json",
        ])
        .await?;
    anyhow::ensure!(
        stale.status == 6 && stale.error()?["reason"] == "version_conflict",
        "stale version was accepted: {}{}",
        stale.stdout,
        stale.stderr
    );
    let mixed = shell
        .run(&[
            "app",
            "deploy",
            "shop",
            "-f",
            "grund.yaml",
            "--expected-version",
            "1",
            "--copies",
            "2",
            "--json",
        ])
        .await?;
    anyhow::ensure!(
        mixed.status == 2 && mixed.error()?["field"] == "expected_version",
        "precondition with a pre-deploy scale was accepted: {}{}",
        mixed.stdout,
        mixed.stderr
    );

    let scaled = shell.json("app set copies", &["shop", "2"]).await?;
    anyhow::ensure!(scaled["app"]["settings"]["copies"] == 2, "{scaled:#}");
    let mut ready = Value::Null;
    for _ in 0..120 {
        ready = shell.json("app status", &["shop"]).await?;
        if ready["copiesReady"] == 2 && ready["health"] == "live" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    anyhow::ensure!(
        ready["copiesReady"] == 2,
        "two copies never got ready: {ready:#}"
    );

    registry.publish("acme/shop", "2");
    let image = registry.image("acme/shop", "2");
    let preview = shell
        .json("app set image", &["shop", &image, "--dry-run"])
        .await?;
    anyhow::ensure!(
        preview["changes"].as_array().is_some_and(|c| c
            .iter()
            .any(|c| c["path"] == "/spec/image" && c["after"] == json!(image))),
        "{preview:#}"
    );
    anyhow::ensure!(
        preview["release"]["number"] == 2,
        "the preview names the next release: {preview:#}"
    );
    let history = shell.json("app history", &["shop"]).await?;
    anyhow::ensure!(
        history["releases"].as_array().map(Vec::len) == Some(1),
        "a dry run made a release: {history:#}"
    );

    let changed = shell
        .json(
            "app set image",
            &["shop", &image, "--wait", "--timeout", "60"],
        )
        .await?;
    anyhow::ensure!(
        changed["release"]["number"] == 2
            && changed["rollout"]["state"] == "ROLLOUT_STATE_SUCCEEDED",
        "{changed:#}"
    );
    let back = shell
        .json("app rollback", &["shop", "1", "--wait", "--timeout", "60"])
        .await?;
    anyhow::ensure!(
        back["release"]["number"] == 3
            && back["release"]["rollbackOf"] == 1
            && back["release"]["spec"]["image"] == json!(registry.image("acme/shop", "1")),
        "{back:#}"
    );

    let refused = shell.run(&["app", "delete", "shop", "--json"]).await?;
    anyhow::ensure!(
        refused.status == 2,
        "exit {}: {}",
        refused.status,
        refused.stderr
    );
    anyhow::ensure!(
        refused.error()?["code"] == "confirmation_required",
        "{}",
        refused.stderr
    );
    let deletion = shell.json("app delete", &["shop", "--yes"]).await?;
    let deadline = deletion["message"]
        .as_str()
        .and_then(|message| message.strip_prefix("Deletion scheduled for shop; restore before "))
        .and_then(|message| message.strip_suffix('.'))
        .ok_or_else(|| anyhow::anyhow!("missing deletion deadline: {deletion}"))?;
    let deadline = chrono::DateTime::parse_from_rfc3339(deadline)?;
    let expected = format!(
        "shop was deleted on {} and can be restored until {}.",
        (deadline - chrono::Duration::days(7)).format("%-d %b %Y %H:%M:%S UTC"),
        deadline.format("%-d %b %Y %H:%M:%S UTC")
    );
    let conflict = shell.run(&["app", "create", "shop", "--json"]).await?;
    anyhow::ensure!(
        conflict.status == 6
            && conflict.error()?["reason"] == "name_reserved_for_restore"
            && conflict.error()?["message"] == expected,
        "CLI JSON name conflict: {} {}",
        conflict.status,
        conflict.stderr
    );
    let text = shell.run(&["app", "create", "shop"]).await?;
    anyhow::ensure!(
        text.status == 6 && text.stderr.contains(&expected),
        "CLI text name conflict: {} {}",
        text.status,
        text.stderr
    );
    let gone = shell.run(&["app", "show", "shop", "--json"]).await?;
    anyhow::ensure!(
        gone.status == 5 && gone.error()?["code"] == "not_found",
        "{}",
        gone.stderr
    );

    let deploy_only = a_token(&when, &then, org, "ci", "deploy").await?;
    let ci = Shell::fresh(&[("GRUND_INSTANCE", &instance), ("GRUND_TOKEN", &deploy_only)])?;
    ci.json("app create", &["web"]).await?;
    let denied = ci.run(&["app", "delete", "web", "--yes", "--json"]).await?;
    anyhow::ensure!(
        denied.status == 4 && denied.error()?["code"] == "permission_denied",
        "a deploy token deleted an app: {} {}",
        denied.status,
        denied.stderr
    );
    let machines = ci.run(&["machine", "list", "--json"]).await?;
    anyhow::ensure!(
        machines.status == 4,
        "a deploy token listed machines: {}",
        machines.stdout
    );
    let listed = shell.json("machine list", &[]).await?;
    anyhow::ensure!(
        listed["machines"].as_array().map(Vec::len) == Some(2),
        "{listed:#}"
    );
    let tokens = shell.run(&["auth", "token", "list", "--json"]).await?;
    anyhow::ensure!(
        tokens.status == 4,
        "a full token reached the token service, which needs a person: {}",
        tokens.stdout
    );
    anyhow::ensure!(
        !given.testcase.fixture.log().contains(&token),
        "grund's log carries the token"
    );
    Ok(())
}

#[tokio::test]
async fn a_token_reaches_only_its_own_organisation_from_the_cli() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let token = a_token(&when, &then, org, "agent", "full").await?;
    let other_org = given.a_fresh_name("team");
    when.submitting("/orgs/new", "/orgs/new", &[("slug", &other_org)])
        .await?;
    then.status(303)?;
    let shell = Shell::fresh(&[("GRUND_INSTANCE", &origin(&when)), ("GRUND_TOKEN", &token)])?;
    let ran = shell
        .run(&["app", "list", "--org", &other_org, "--json"])
        .await?;
    anyhow::ensure!(
        ran.status == 5 && ran.error()?["code"] == "not_found",
        "a token reached another organisation: {} {}",
        ran.status,
        ran.stderr
    );
    let ran = shell
        .run(&["member", "list", "--org", &other_org, "--json"])
        .await?;
    anyhow::ensure!(ran.status == 5, "{} {}", ran.status, ran.stderr);
    Ok(())
}
#[tokio::test]
async fn client_targets_work_before_or_after_the_noun_and_keep_default_precedence()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let instance = origin(&when);
    let token = a_token(&when, &then, org, "context", "full").await?;
    let mut shell = Shell::fresh(&[])?;
    shell
        .json_with("auth login", &[&instance, "--with-token"], &token)
        .await?;
    let app = given.a_fresh_name("context");
    shell.json("app create", &[&app]).await?;
    let saved = shell.json("app list", &[]).await?;
    anyhow::ensure!(
        saved["apps"]
            .as_array()
            .is_some_and(|apps| apps.iter().any(|a| a["name"] == app)),
        "saved target defaults did not reach the owned app"
    );

    shell.env.extend([
        ("GRUND_INSTANCE".into(), "http://127.0.0.1:1".into()),
        ("GRUND_ORG".into(), "missing-target-org".into()),
    ]);
    let environment = shell.run(&["app", "list", "--json"]).await?;
    anyhow::ensure!(
        environment.status == 3 && environment.error()?["code"] == "not_signed_in",
        "environment instance did not override saved instance"
    );
    shell.env.retain(|(key, _)| key != "GRUND_INSTANCE");
    shell.env.push(("GRUND_INSTANCE".into(), instance.clone()));
    let environment = shell.run(&["app", "list", "--json"]).await?;
    anyhow::ensure!(
        environment.status == 5 && environment.error()?["code"] == "not_found",
        "environment organisation did not override saved organisation"
    );

    for args in [
        vec![
            "--instance",
            &instance,
            "--org",
            org,
            "app",
            "list",
            "--json",
        ],
        vec![
            "app",
            "--instance",
            &instance,
            "--org",
            org,
            "list",
            "--json",
        ],
        vec![
            "app",
            "list",
            "--instance",
            &instance,
            "--org",
            org,
            "--json",
        ],
        vec![
            "--instance",
            "http://127.0.0.1:1",
            "--org",
            "missing-target-org",
            "app",
            "list",
            "--instance",
            &instance,
            "--org",
            org,
            "--json",
        ],
    ] {
        let ran = shell.run(&args).await?;
        anyhow::ensure!(ran.status == 0, "target flags were refused: {}", ran.stderr);
        let listed = ran.json()?;
        anyhow::ensure!(
            listed["apps"]
                .as_array()
                .is_some_and(|apps| apps.iter().any(|a| a["name"] == app)),
            "explicit target flags did not override defaults"
        );
    }
    let bad = shell
        .run(&[
            "--instance",
            &instance,
            "--org",
            org,
            "app",
            "--frobnicate",
            "--json",
        ])
        .await?;
    anyhow::ensure!(
        bad.status == 2 && bad.error()?["code"] == "usage",
        "prefixed client targets lost the JSON usage error"
    );
    Ok(())
}

fn first_json_line(reader: &mut impl BufRead) -> anyhow::Result<Value> {
    let mut line = String::new();
    loop {
        line.clear();
        anyhow::ensure!(
            reader.read_line(&mut line)? > 0,
            "grund auth login said nothing on stderr"
        );
        if let Ok(value) = serde_json::from_str::<Value>(line.trim()) {
            return Ok(value);
        }
    }
}

async fn logging_in(shell: &Shell, instance: &str) -> anyhow::Result<(std::process::Child, Value)> {
    let mut child = shell
        .command(&["auth", "login", instance, "--json", "--no-browser"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().expect("piped");
    let started = tokio::task::spawn_blocking(move || {
        let mut reader = std::io::BufReader::new(stderr);
        first_json_line(&mut reader)
    })
    .await??;
    Ok((child, started))
}

async fn finished(child: std::process::Child) -> anyhow::Result<Ran> {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || child.wait_with_output()),
    )
    .await???;
    Ok(Ran {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn hidden(html: &str, name: &str) -> Option<String> {
    let at = html.find(&format!("name=\"{name}\" value=\""))?;
    let rest = &html[at + name.len() + 15..];
    Some(rest[..rest.find('"')?].to_string())
}

#[tokio::test]
async fn grund_login_is_approved_once_in_the_browser_and_logout_revokes_the_session()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let instance = origin(&when);
    let shell = Shell::fresh(&[])?;

    let (child, started) = logging_in(&shell, &instance).await?;
    anyhow::ensure!(started["event"] == "approve_in_browser", "{started}");
    let uri = started["verificationUriComplete"]
        .as_str()
        .unwrap_or_default();
    let path = &uri[uri.find("/device").unwrap_or(0)..];
    let code = started["userCode"].as_str().unwrap_or_default().to_string();
    when.visiting(path).await?;
    then.status(200)?
        .body_contains(&code)?
        .body_contains("grund 0.1.0")?
        .body_contains("Approve")?;
    let html = then.body()?;
    let login = hidden(&html, "login").ok_or_else(|| anyhow::anyhow!("no login field: {html}"))?;

    let (_, stranger_when, stranger_then) = given.testcase.another_browser();
    stranger_when.visiting(path).await?;
    stranger_then.status_in(&[302, 303])?;

    when.submitting(
        path,
        "/device",
        &[("login", &login), ("decision", "approve")],
    )
    .await?;
    then.status(200)?.body_contains("Approved")?;
    let ran = finished(child).await?;
    anyhow::ensure!(
        ran.status == 0,
        "grund auth login exited {}: {}{}",
        ran.status,
        ran.stdout,
        ran.stderr
    );
    let result = ran.json()?;
    Registry::compiled()
        .conforms(&result, "grund.cli.v1.LoginResult")
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        result["credential"] == "session"
            && result["username"] == org.as_str()
            && result["organisation"] == org.as_str(),
        "{result:#}"
    );
    let file = std::path::PathBuf::from(result["credentialsFile"].as_str().unwrap_or_default());
    anyhow::ensure!(
        std::fs::metadata(&file)?.permissions().mode() & 0o777 == 0o600,
        "the credentials file is not 0600"
    );
    let stored = std::fs::read_to_string(&file)?;
    anyhow::ensure!(
        stored.contains("grund_cli_"),
        "{file:?} holds no CLI session"
    );
    anyhow::ensure!(
        !ran.stdout.contains("grund_cli_") && !ran.stderr.contains("grund_cli_"),
        "grund auth login printed the session's secret"
    );

    when.submitting(
        path,
        "/device",
        &[("login", &login), ("decision", "approve")],
    )
    .await?;
    then.status(409)?;

    let me = shell.json("auth status", &[]).await?;
    anyhow::ensure!(
        me["credential"] == "session" && me["username"] == org.as_str(),
        "{me:#}"
    );
    let made = shell
        .json(
            "auth token create",
            &["--name", "from the cli", "--scope", "full"],
        )
        .await?;
    anyhow::ensure!(
        made["secret"]
            .as_str()
            .is_some_and(|s| s.starts_with("grund_pat_"))
            && made["token"]["scope"] == "TOKEN_SCOPE_FULL",
        "{made:#}"
    );
    let bounded = shell
        .json(
            "auth token create",
            &[
                "--name",
                "app deployer",
                "--scope",
                "deploy",
                "--apps",
                "shop,worker",
            ],
        )
        .await?;
    anyhow::ensure!(
        bounded["token"]["apps"] == json!(["shop", "worker"]),
        "CLI token creation did not return its app restriction"
    );
    let listed = shell.json("auth token list", &[]).await?;
    anyhow::ensure!(
        listed["tokens"].as_array().is_some_and(|tokens| {
            tokens.iter().any(|token| token["name"] == "from the cli")
                && tokens.iter().any(|token| {
                    token["name"] == "app deployer" && token["apps"] == json!(["shop", "worker"])
                })
        }),
        "the token list did not include both tokens with the restriction"
    );
    shell.json("org list", &[]).await?;
    when.visiting("/settings/sessions").await?;
    then.status(200)?.body_contains("grund 0.1.0")?;

    let cookie = given
        .the_session_cookie()
        .ok_or_else(|| anyhow::anyhow!("no session cookie"))?;
    let (_, bare_when, bare_then) = given.testcase.another_browser();
    bare_when
        .calling_with(
            "/grund.account.v1.AccountService/GetViewer",
            "{}",
            &[("Authorization", &format!("Bearer grund_cli_{cookie}"))],
        )
        .await?;
    bare_then.status(401)?;

    let out = shell.json("auth logout", &[]).await?;
    anyhow::ensure!(
        out["message"]
            .as_str()
            .is_some_and(|m| m.contains("revoked")),
        "{out:#}"
    );
    let after = shell.run(&["auth", "status", "--json"]).await?;
    anyhow::ensure!(
        after.status == 3,
        "whoami after logout exited {}: {}",
        after.status,
        after.stdout
    );
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_sessions WHERE kind = 'cli' AND revoked_at IS NULL")
            .await?
            == 0,
        "logout left the CLI session live"
    );

    let (child, started) = logging_in(&shell, &instance).await?;
    let uri = started["verificationUriComplete"]
        .as_str()
        .unwrap_or_default();
    let path = &uri[uri.find("/device").unwrap_or(0)..];
    when.visiting(path).await?;
    let login = hidden(&then.body()?, "login").ok_or_else(|| anyhow::anyhow!("no login field"))?;
    when.submitting(path, "/device", &[("login", &login), ("decision", "deny")])
        .await?;
    then.status(200)?.body_contains("Denied")?;
    let ran = finished(child).await?;
    anyhow::ensure!(
        ran.status == 3,
        "a denied login exited {}: {}",
        ran.status,
        ran.stderr
    );
    Ok(())
}

#[tokio::test]
async fn the_cli_describes_itself_and_refuses_a_bad_line_as_json_without_an_instance()
-> anyhow::Result<()> {
    let shell = Shell::fresh(&[])?;
    let described = shell.run(&["describe", "--json"]).await?;
    anyhow::ensure!(described.status == 0, "{}", described.stderr);
    let document = described.json()?;
    anyhow::ensure!(
        document["commands"]
            .as_array()
            .is_some_and(|c| c.iter().any(|c| c["path"] == "app deploy"
                && c["output"]["$ref"] == "#/$defs/grund.cli.v1.DeployResult")),
        "describe has no apps deploy"
    );
    let bad = shell
        .run(&["app", "deploy", "--frobnicate", "--json"])
        .await?;
    anyhow::ensure!(
        bad.status == 2 && bad.error()?["code"] == "usage",
        "{} {}",
        bad.status,
        bad.stderr
    );
    let unsigned = shell.run(&["app", "list", "--json"]).await?;
    anyhow::ensure!(
        unsigned.status == 3 && unsigned.error()?["code"] == "not_signed_in",
        "{} {}",
        unsigned.status,
        unsigned.stderr
    );
    let skill = shell.run(&["skill", "print"]).await?;
    anyhow::ensure!(
        skill.stdout.starts_with("---\nname: grund\n")
            && skill.stdout.contains("`grund app deploy"),
        "{}",
        skill.stdout
    );
    let mut mcp = shell
        .command(&["mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut input = mcp.stdin.take().expect("piped");
    writeln!(
        input,
        "{}",
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    )?;
    writeln!(
        input,
        "{}",
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
    )?;
    writeln!(
        input,
        "{}",
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    )?;
    writeln!(
        input,
        "{}",
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "app_list", "arguments": {}}})
    )?;
    drop(input);
    let output = tokio::task::spawn_blocking(move || mcp.wait_with_output()).await??;
    let answers: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(answers.len() == 3, "{answers:#?}");
    anyhow::ensure!(
        answers[0]["result"]["serverInfo"]["name"] == "grund",
        "{answers:#?}"
    );
    let tools = answers[1]["result"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let delete = tools
        .iter()
        .find(|t| t["name"] == "app_delete")
        .ok_or_else(|| anyhow::anyhow!("no app_delete tool"))?;
    anyhow::ensure!(
        delete["annotations"]["destructiveHint"] == true,
        "{delete:#}"
    );
    anyhow::ensure!(
        !tools.iter().any(|t| t["name"] == "auth_login"),
        "auth login is a tool"
    );
    anyhow::ensure!(
        answers[2]["result"]["isError"] == true
            && answers[2]["result"]["structuredContent"]["error"]["code"] == "not_signed_in",
        "{:#}",
        answers[2]
    );
    Ok(())
}

async fn approved_cli_session(shell: &Shell, when: &When, then: &Then) -> anyhow::Result<()> {
    let (child, started) = logging_in(shell, &origin(when)).await?;
    let uri = started["verificationUriComplete"]
        .as_str()
        .unwrap_or_default();
    let path = &uri[uri.find("/device").unwrap_or(0)..];
    when.visiting(path).await?;
    then.status(200)?;
    let html = then.body()?;
    let login = hidden(&html, "login").ok_or_else(|| anyhow::anyhow!("no login field: {html}"))?;
    when.submitting(
        path,
        "/device",
        &[("login", &login), ("decision", "approve")],
    )
    .await?;
    then.status(200)?;
    let result = finished(child).await?;
    anyhow::ensure!(result.status == 0, "CLI login failed: {}", result.stderr);
    Ok(())
}

#[tokio::test]
async fn the_notifications_cli_lists_json_and_marks_only_its_own_items_read() -> anyhow::Result<()>
{
    let Some((given, when, then)) = crate::accepttest::fixtures::testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (guest, guest_when, guest_then) = given.testcase.another_browser();
    let account = guest.a_signed_in_account().await?;
    when.inviting(&owner.username, &account.email, "member")
        .await?;
    then.status(303)?;
    let instance = origin(&guest_when);
    let shell = Shell::fresh(&[("GRUND_INSTANCE", &instance)])?;
    approved_cli_session(&shell, &guest_when, &guest_then).await?;
    let listed = shell.json("notification", &["--unread"]).await?;
    let items = listed["notifications"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("CLI JSON missing notifications: {listed}"))?;
    anyhow::ensure!(items.len() == 1, "one unread invitation: {listed}");
    let id = items[0]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("notification missing id: {listed}"))?;
    anyhow::ensure!(!id.is_empty());
    shell.json("notification read", &[id]).await?;
    let unread = shell.json("notification", &["--unread"]).await?;
    anyhow::ensure!(
        unread
            .get("notifications")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "read item remains unread: {unread}"
    );
    let all = shell.json("notification", &[]).await?;
    anyhow::ensure!(
        all["notifications"]
            .as_array()
            .is_some_and(|items| items.len() == 1),
        "read item vanished from all items: {all}"
    );
    Ok(())
}

#[tokio::test]
async fn a_full_token_configures_app_addresses_and_the_cli_defaults_or_replaces_the_label()
-> anyhow::Result<()> {
    let Some(stack) = crate::accepttest::traffic::a_stack_with(&[]).await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username;
    let (when, then) = (&stack.when, &stack.then);
    let token = a_token(when, then, &org, "domain manager", "full").await?;
    let instance = origin(when);
    let shell = Shell::fresh(&[("GRUND_INSTANCE", &instance), ("GRUND_TOKEN", &token)])?;
    shell.json("app create", &["hello"]).await?;
    let parent = crate::accepttest::domains::a_custom_name();
    let added = shell.json("domain add", &[&parent]).await?;
    stack
        .pebble
        .set_txt(
            added["domain"]["verificationRecordName"]
                .as_str()
                .unwrap_or_default(),
            added["domain"]["verificationRecordValue"]
                .as_str()
                .unwrap_or_default(),
        )
        .await?;
    shell.json("domain verify", &[&parent]).await?;
    let preview = shell
        .json("domain app-domain", &[&parent, "--dry-run"])
        .await?;
    anyhow::ensure!(
        preview["calls"][0]["rpc"] == "grund.domain.v1.DomainService/ConfigureAppDomain"
            && preview["calls"][0]["request"]["name"] == parent,
        "wrong namespace preview: {preview}"
    );
    let before = shell.json("domain show", &[&parent]).await?;
    anyhow::ensure!(
        before["domain"]["isAppDomain"] != true,
        "preview enabled the parent: {before}"
    );
    let configured = shell.json("domain app-domain", &[&parent]).await?;
    anyhow::ensure!(
        configured["domain"]["isAppDomain"] == true,
        "the CLI did not enable the parent: {configured}"
    );
    let default_name = format!("hello.{parent}");
    let default = shell.json("domain show", &[&default_name]).await?;
    anyhow::ensure!(
        default["domain"]["parentDomain"] == parent
            && default["domain"]["managedAppName"] == "hello"
            && default["domain"]["setupSteps"].as_array().map(Vec::len) == Some(6),
        "default app address lacks parent authority or progress: {default}"
    );
    let preview = shell
        .json("domain subdomain", &["hello", "admin", "--dry-run"])
        .await?;
    anyhow::ensure!(
        preview["calls"][0]["rpc"] == "grund.domain.v1.DomainService/SetAppSubdomain"
            && preview["calls"][0]["request"]["app"] == "hello"
            && preview["calls"][0]["request"]["subdomain"] == "admin",
        "wrong subdomain preview: {preview}"
    );
    shell.json("domain show", &[&default_name]).await?;
    let chosen_name = format!("admin.{parent}");
    let chosen = shell.json("domain subdomain", &["hello", "admin"]).await?;
    anyhow::ensure!(
        chosen["domain"]["name"] == chosen_name && chosen["domain"]["app"] == "hello",
        "the CLI did not select the customer-owned label: {chosen}"
    );
    let previous = shell
        .run(&["domain", "show", &default_name, "--json"])
        .await?;
    anyhow::ensure!(
        previous.status != 0 && previous.error()?["code"] == "not_found",
        "the previous hostname survived the rename: {} {}",
        previous.stdout,
        previous.stderr
    );
    let defaulted = shell.json("domain subdomain", &["hello"]).await?;
    anyhow::ensure!(
        defaulted["domain"]["name"] == default_name
            && defaulted["domain"]["setupSteps"].as_array().map(Vec::len) == Some(6),
        "omitting the CLI label did not restore the app-name default: {defaulted}"
    );
    let second_org = stack.given.a_fresh_name("team");
    when.submitting("/orgs/new", "/orgs/new", &[("slug", &second_org)])
        .await?;
    then.status(303)?;
    for args in [
        vec![
            "domain",
            "app-domain",
            parent.as_str(),
            "--org",
            second_org.as_str(),
            "--json",
        ],
        vec![
            "domain",
            "subdomain",
            "hello",
            "www",
            "--org",
            second_org.as_str(),
            "--json",
        ],
    ] {
        let foreign = shell.run(&args).await?;
        anyhow::ensure!(
            foreign.status != 0 && foreign.error()?["code"] == "not_found",
            "the token borrowed its maker's access to a second organisation: {} {}",
            foreign.stdout,
            foreign.stderr
        );
    }
    Ok(())
}

#[tokio::test]
async fn contexts_name_an_instance_its_credential_and_organisation_and_the_older_file_migrates()
-> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let instance = origin(&when);
    let host = instance
        .split_once("://")
        .map_or(instance.as_str(), |(_, h)| h);
    let token = a_token(&when, &then, org, "contexts", "full").await?;
    let shell = Shell::fresh(&[])?;
    let config = shell.home.join(".config").join("grund");
    std::fs::create_dir_all(&config)?;
    let older = config.join("credentials.yaml");
    std::fs::write(
        &older,
        format!("current: {instance}\ninstances:\n- url: {instance}\n  credential: {token}\n"),
    )?;
    std::fs::set_permissions(&older, std::fs::Permissions::from_mode(0o600))?;

    let listed = shell.json("context list", &[]).await?;
    anyhow::ensure!(
        listed["current"] == host
            && listed["contexts"][0]["instance"] == instance
            && listed["contexts"][0]["credential"] == "token"
            && !listed.to_string().contains(&token),
        "the older file did not become one current context: {listed}"
    );
    anyhow::ensure!(
        !older.exists() && config.join("credentials.yaml.old").exists(),
        "the older file was not kept as credentials.yaml.old"
    );
    let mode = std::fs::metadata(config.join("config.yaml"))?
        .permissions()
        .mode();
    anyhow::ensure!(mode & 0o777 == 0o600, "config.yaml is mode {mode:o}");

    let login = shell
        .json_with(
            "auth login",
            &[&instance, "--with-token", "--context", "ci"],
            &token,
        )
        .await?;
    anyhow::ensure!(login["context"] == "ci", "{login}");
    let listed = shell.json("context list", &[]).await?;
    anyhow::ensure!(
        listed["current"] == "ci" && listed["contexts"].as_array().map(Vec::len) == Some(2),
        "login --context did not add and choose ci: {listed}"
    );

    let app = given.a_fresh_name("ctx");
    shell.json("app create", &[&app]).await?;
    shell.json("context use", &[host]).await?;
    let elsewhere = shell
        .json("app list", &["--context", "ci", "--org", org])
        .await?;
    anyhow::ensure!(
        elsewhere["apps"]
            .as_array()
            .is_some_and(|apps| apps.iter().any(|a| a["name"] == app)),
        "--context did not reach ci's instance"
    );
    let shown = shell.json("context show", &["ci"]).await?;
    anyhow::ensure!(
        shown["name"] == "ci" && shown["current"].is_null(),
        "context show: {shown}"
    );

    shell.json("context rename", &["ci", "pipeline"]).await?;
    shell.json("context use", &["pipeline"]).await?;
    shell.json("org use", &[org]).await?;
    let shown = shell.json("context show", &[]).await?;
    anyhow::ensure!(
        shown["name"] == "pipeline" && shown["organisation"] == org && shown["current"] == true,
        "org use did not set the current context's organisation: {shown}"
    );

    let missing = shell
        .run(&["app", "list", "--context", "nowhere", "--json"])
        .await?;
    anyhow::ensure!(
        missing.status == 5 && missing.error()?["code"] == "not_found",
        "an unknown context was not refused: {}",
        missing.stderr
    );

    shell.json("context remove", &["pipeline", "--yes"]).await?;
    let listed = shell.json("context list", &[]).await?;
    anyhow::ensure!(
        listed["current"] == host && listed["contexts"].as_array().map(Vec::len) == Some(1),
        "removing the current context did not leave the other current: {listed}"
    );
    Ok(())
}
