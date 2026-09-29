use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::accepttest::{
    fixtures::{
        Given, Then, When,
        client::{self, Origin},
        external_target,
        pebble::{Pebble, SHORT_PROFILE_SECONDS, free_port},
        random_hex, testcase_configured,
    },
    machines::{
        Running, a_machine_key, a_member, comes_online_trusting, origin, signed_agent_call,
    },
};

const CERTIFICATES: &str = "/grund.certificates.v1.CertificateService";
const ENROLL_RELAY: &str = "/grund.relay.v1.RelayEnrollmentService/EnrollRelay";

async fn eventually<T, F, Fut>(what: &str, within: Duration, mut probe: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let deadline = Instant::now() + within;
    loop {
        match probe().await {
            Ok(value) => return Ok(value),
            Err(error) if Instant::now() > deadline => {
                return Err(error.context(format!("{what} within {within:?}")));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

fn a_relay_host() -> String {
    format!("relay-{}.localhost", random_hex(4))
}

fn settings(pairs: &[(String, String)]) -> Vec<(&str, &str)> {
    pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

struct Instance {
    given: Given,
    when: When,
    then: Then,
}

async fn an_instance_ordering_for(
    pebble: &Pebble,
    relays: &[(&str, u16)],
    extra: &[(&str, &str)],
) -> anyhow::Result<Option<Instance>> {
    let mut env = pebble.acme_settings();
    env.push((
        "GRUND_RELAYS".into(),
        relays
            .iter()
            .map(|(host, port)| format!("https://{host}:{port}"))
            .collect::<Vec<_>>()
            .join(","),
    ));
    for (name, value) in extra {
        env.retain(|(key, _)| key != name);
        env.push((name.to_string(), value.to_string()));
    }
    Ok(testcase_configured(&settings(&env))
        .await?
        .map(|(given, when, then)| Instance { given, when, then }))
}

fn database_url(when: &When) -> String {
    when.testcase
        .fixture
        .database_url()
        .expect("a spawned instance has a database")
}

fn grund_relays(when: &When, args: &[&str]) -> anyhow::Result<std::process::Output> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_grund"))
        .arg("relays")
        .args(args)
        .env_clear()
        .env("DATABASE_URL", database_url(when))
        .output()?)
}

fn a_token_for(when: &When, host: &str) -> anyhow::Result<String> {
    let output = grund_relays(when, &["token", host])?;
    anyhow::ensure!(
        output.status.success(),
        "grund relays token: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let token = String::from_utf8(output.stdout)?.trim().to_string();
    anyhow::ensure!(token.starts_with("grund_relay_"), "{token}");
    Ok(token)
}

fn log_path(dir: &Path) -> PathBuf {
    dir.join("relay.log")
}

fn a_relay_process(
    when: &When,
    dir: &Path,
    token: Option<&str>,
    port: u16,
) -> anyhow::Result<Running> {
    std::fs::create_dir_all(dir)?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path(dir))?;
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_grund"));
    command
        .arg("relay")
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .args(["--quic-listen", &format!("127.0.0.1:{}", free_port())])
        .args(["--grund-url", &origin(when)])
        .arg("--data-dir")
        .arg(dir.join("data"))
        .env_clear()
        .env("RUST_LOG", "grund_server=debug,grund_tls=info,info")
        .stdout(std::process::Stdio::from(log.try_clone()?))
        .stderr(std::process::Stdio::from(log));
    if let Some(token) = token {
        command.env("GRUND_RELAY_ENROLLMENT_TOKEN", token);
    }
    Ok(Running(command.spawn()?))
}

fn relay_log(dir: &Path) -> String {
    std::fs::read_to_string(log_path(dir)).unwrap_or_default()
}

fn a_relay_dir() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("rc-{}", random_hex(6)))
}

async fn served_leaf(
    host: &str,
    port: u16,
    roots: Arc<rustls::RootCertStore>,
) -> anyhow::Result<Vec<u8>> {
    let mut origin = Origin::parse(&format!("https://{host}:{port}"))?;
    origin.connect = Some(("127.0.0.1".into(), port));
    origin.roots = Some(roots);
    client::leaf_certificate(&origin).await
}

async fn remote_row(when: &When, subject: &str) -> anyhow::Result<(String, bool, bool)> {
    let mut connection =
        <sqlx::PgConnection as sqlx::Connection>::connect(&database_url(when)).await?;
    Ok(sqlx::query_as(
        "SELECT terminator, sealed_key IS NULL, csr IS NOT NULL FROM grund_certificates WHERE subject = $1",
    )
    .bind(subject)
    .fetch_one(&mut connection)
    .await?)
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0)
}

#[tokio::test]
async fn a_relay_on_a_host_of_its_own_gets_its_certificate_from_its_grund_renews_it_and_a_machine_trusts_it()
-> anyhow::Result<()> {
    if external_target().is_some() {
        return Ok(());
    }
    let Some(pebble) = Pebble::start(free_port()).await? else {
        return Ok(());
    };
    let host = a_relay_host();
    let relay_url = format!("https://{host}:{}", pebble.tls_port);
    let Some(Instance { given, when, then }) = an_instance_ordering_for(
        &pebble,
        &[(&host, pebble.tls_port)],
        &[("GRUND_ACME_PROFILE", "short")],
    )
    .await?
    else {
        return Ok(());
    };
    let token = a_token_for(&when, &host)?;
    let dir = a_relay_dir();
    let relay = a_relay_process(&when, &dir, Some(&token), pebble.tls_port)?;
    let roots = pebble.roots().await?;

    let first = eventually(
        "the relay serving a certificate from its grund",
        Duration::from_secs(60),
        || served_leaf(&host, pebble.tls_port, roots.clone()),
    )
    .await
    .map_err(|error| {
        error.context(format!(
            "relay:\n{}\n--- grund:\n{}",
            relay_log(&dir),
            when.testcase.fixture.log()
        ))
    })?;
    anyhow::ensure!(
        relay_log(&dir).contains("answered a TLS-ALPN-01 challenge"),
        "the CA validated on the relay's own listener:\n{}",
        relay_log(&dir)
    );
    anyhow::ensure!(
        !relay_log(&dir).contains(&token) && !when.testcase.fixture.log().contains(&token),
        "the enrollment token is never logged"
    );
    let (terminator, no_key, csr) = remote_row(&when, &format!("relay:{host}")).await?;
    anyhow::ensure!(
        terminator == "remote" && no_key && csr,
        "grund holds the relay's CSR and never its key"
    );
    let data = dir.join("data");
    for file in ["relay.key", "relay.json", "tls/key.der", "tls/chain.pem"] {
        anyhow::ensure!(mode(&data.join(file)) == 0o600, "{file} is 0600");
    }
    let first_key = std::fs::read(data.join("tls/key.der"))?;

    let renewed = eventually(
        "a renewed certificate on the relay",
        Duration::from_secs(SHORT_PROFILE_SECONDS * 4),
        || async {
            let now = served_leaf(&host, pebble.tls_port, roots.clone()).await?;
            anyhow::ensure!(now != first, "still the first certificate");
            Ok(now)
        },
    )
    .await
    .map_err(|error| {
        error.context(format!(
            "relay:\n{}\n--- grund:\n{}",
            relay_log(&dir),
            when.testcase.fixture.log()
        ))
    })?;
    anyhow::ensure!(renewed != first);
    anyhow::ensure!(
        std::fs::read(data.join("tls/key.der"))? != first_key,
        "a renewal is a new key, made on the relay"
    );
    anyhow::ensure!(
        relay_log(&dir).contains("renewal is due"),
        "the instance asked for a fresh CSR"
    );

    let owner = given.a_signed_in_account().await?;
    let (key, enrolled) = a_member(&when, &then, &owner.username, "relayed").await?;
    anyhow::ensure!(
        enrolled["network"]["relayUrls"] == json!([relay_url]),
        "{enrolled}"
    );
    let trust = Some(pebble.root_ders().await?);
    let mut online = false;
    for _ in 0..20 {
        if comes_online_trusting(&relay_url, &key, trust.clone()).await? {
            online = true;
            break;
        }
    }
    anyhow::ensure!(
        online,
        "a machine trusts the relay's certificate and is admitted by its signed access check:\n{}",
        relay_log(&dir)
    );
    anyhow::ensure!(
        !comes_online_trusting(&relay_url, &a_machine_key(), trust).await?,
        "a key grund does not know is still refused"
    );
    drop(relay);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

struct TestRelay {
    relay_id: String,
    key: SigningKey,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn enrolling(when: &When, token: &str, key: &SigningKey) -> anyhow::Result<()> {
    let signed_at = now();
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    let proof = format!(
        "grund-relay-enroll-v1\n{}\n{signed_at}\n{digest}",
        origin(when)
    );
    let body = json!({
        "token": token,
        "relayPublicKey": STANDARD.encode(key.verifying_key().to_bytes()),
        "signedAtUnix": signed_at.to_string(),
        "signature": STANDARD.encode(key.sign(proof.as_bytes()).to_bytes()),
    })
    .to_string();
    when.calling(ENROLL_RELAY, &body).await?;
    Ok(())
}

async fn an_enrolled_relay(when: &When, then: &Then, host: &str) -> anyhow::Result<TestRelay> {
    let token = a_token_for(when, host)?;
    let key = a_machine_key();
    enrolling(when, &token, &key).await?;
    then.status(200)?;
    let answer = then.json()?;
    anyhow::ensure!(answer["host"] == host, "{answer}");
    Ok(TestRelay {
        relay_id: answer["relayId"].as_str().unwrap_or_default().to_string(),
        key,
    })
}

fn signed(relay: &TestRelay, path: &str, body: &[u8]) -> Vec<(String, String)> {
    let signed_at = now();
    let message = format!(
        "grund-agent-request-v1\n{path}\n{signed_at}\n{}",
        hex::encode(Sha256::digest(body))
    );
    vec![
        ("x-grund-relay".into(), relay.relay_id.clone()),
        ("x-grund-signed-at".into(), signed_at.to_string()),
        (
            "x-grund-signature".into(),
            STANDARD.encode(relay.key.sign(message.as_bytes()).to_bytes()),
        ),
    ]
}

fn a_csr(names: &[&str]) -> anyhow::Result<String> {
    let key = rcgen::KeyPair::generate()?;
    let csr =
        rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())?
            .serialize_request(&key)?;
    Ok(STANDARD.encode(csr.der()))
}

async fn relay_calling(
    when: &When,
    relay: &TestRelay,
    procedure: &str,
    body: &Value,
) -> anyhow::Result<(u16, Value)> {
    let path = format!("{CERTIFICATES}/{procedure}");
    let body = body.to_string();
    let headers = signed(relay, &path, body.as_bytes());
    let mut all: Vec<(&str, &str)> = vec![
        ("Content-Type", "application/json"),
        ("Connect-Protocol-Version", "1"),
    ];
    all.extend(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let response = client::send(
        &when.testcase.fixture.origin,
        "POST",
        &path,
        &all,
        Some(body.as_bytes()),
    )
    .await?;
    Ok((
        response.status,
        serde_json::from_slice(&response.body).unwrap_or_default(),
    ))
}

fn envelope(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(&(content.len() as u32).to_be_bytes());
    out.extend_from_slice(content);
    out
}

fn stream_error(status: u16, body: &[u8]) -> String {
    if status != 200 {
        return serde_json::from_slice::<Value>(body).unwrap_or_default()["code"]
            .as_str()
            .unwrap_or("none")
            .to_string();
    }
    let mut rest = body;
    while rest.len() >= 5 {
        let length = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        let (flags, content) = (rest[0], &rest[5..5 + length.min(rest.len() - 5)]);
        if flags & 2 == 2 {
            return serde_json::from_slice::<Value>(content).unwrap_or_default()["error"]["code"]
                .as_str()
                .unwrap_or("none")
                .to_string();
        }
        rest = &rest[(5 + length).min(rest.len())..];
    }
    "none".into()
}

async fn watching(
    when: &When,
    headers: &[(String, String)],
    body: &[u8],
) -> anyhow::Result<String> {
    let mut all: Vec<(&str, &str)> = vec![
        ("Content-Type", "application/connect+json"),
        ("Connect-Protocol-Version", "1"),
    ];
    all.extend(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let response = client::send(
        &when.testcase.fixture.origin,
        "POST",
        &format!("{CERTIFICATES}/WatchChallenges"),
        &all,
        Some(body),
    )
    .await?;
    Ok(stream_error(response.status, &response.body))
}

async fn relay_watching(when: &When, relay: &TestRelay) -> anyhow::Result<String> {
    let body = envelope(b"{}");
    let headers = signed(relay, &format!("{CERTIFICATES}/WatchChallenges"), &body);
    watching(when, &headers, &body).await
}

#[tokio::test]
async fn a_relay_gets_nothing_but_its_own_host_and_an_unenrolled_revoked_or_other_caller_nothing_at_all()
-> anyhow::Result<()> {
    if external_target().is_some() {
        return Ok(());
    }
    let Some(pebble) = Pebble::prepare(free_port())? else {
        return Ok(());
    };
    let (mine, theirs) = (a_relay_host(), a_relay_host());
    let Some(Instance { given, when, then }) = an_instance_ordering_for(
        &pebble,
        &[(&mine, 7443), (&theirs, 7444)],
        &[("GRUND_ACME_RETRY_BASE", "3600")],
    )
    .await?
    else {
        return Ok(());
    };
    let relay = an_enrolled_relay(&when, &then, &mine).await?;
    let other = an_enrolled_relay(&when, &then, &theirs).await?;

    for names in [
        vec![theirs.as_str()],
        vec![mine.as_str(), theirs.as_str()],
        vec!["elsewhere.example.com"],
    ] {
        let (status, answer) = relay_calling(
            &when,
            &relay,
            "RequestCertificate",
            &json!({"names": names, "csr": a_csr(&names)?}),
        )
        .await?;
        anyhow::ensure!(
            status == 404 && answer["code"] == "not_found",
            "{names:?} is refused as absent: {status} {answer}"
        );
    }
    let (status, answer) = relay_calling(&when, &relay, "GetCertificate", &json!({})).await?;
    anyhow::ensure!(status == 404 && answer["code"] == "not_found", "{answer}");
    anyhow::ensure!(
        relay_watching(&when, &relay).await? == "not_found",
        "a watch with nothing asked for is absent too"
    );
    let (status, answer) = relay_calling(
        &when,
        &relay,
        "RequestCertificate",
        &json!({"names": [mine], "csr": a_csr(&[&theirs])?}),
    )
    .await?;
    anyhow::ensure!(
        status == 400 && answer["code"] == "invalid_argument",
        "a CSR for another name: {status} {answer}"
    );

    let (status, answer) = relay_calling(
        &when,
        &other,
        "RequestCertificate",
        &json!({"names": [theirs], "csr": a_csr(&[&theirs])?}),
    )
    .await?;
    anyhow::ensure!(status == 200, "{status} {answer}");
    let (status, answer) = relay_calling(&when, &relay, "GetCertificate", &json!({})).await?;
    anyhow::ensure!(
        status == 404,
        "one relay never sees another's certificate: {status} {answer}"
    );
    let (status, _) = relay_calling(
        &when,
        &relay,
        "AnswerChallenge",
        &json!({"token": "anything"}),
    )
    .await?;
    anyhow::ensure!(status == 404);

    let stranger = TestRelay {
        relay_id: relay.relay_id.clone(),
        key: a_machine_key(),
    };
    let (status, answer) = relay_calling(&when, &stranger, "GetCertificate", &json!({})).await?;
    anyhow::ensure!(
        status == 401 && answer["code"] == "unauthenticated",
        "a key that is not the relay's: {status} {answer}"
    );
    anyhow::ensure!(relay_watching(&when, &stranger).await? == "unauthenticated");
    anyhow::ensure!(
        watching(&when, &[], &envelope(b"{}")).await? == "unauthenticated",
        "no credential at all, on the stream"
    );

    let owner = given.a_signed_in_account().await?;
    let (machine_key, enrolled) = a_member(&when, &then, &owner.username, "gate").await?;
    let machine_id = enrolled["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let path = format!("{CERTIFICATES}/WatchChallenges");
    let body = envelope(b"{}");
    let signed_at = now();
    let message = format!(
        "grund-agent-request-v1\n{path}\n{signed_at}\n{}",
        hex::encode(Sha256::digest(&body))
    );
    let machine_headers = vec![
        ("x-grund-machine".to_string(), machine_id.clone()),
        ("x-grund-signed-at".to_string(), signed_at.to_string()),
        (
            "x-grund-signature".to_string(),
            STANDARD.encode(machine_key.sign(message.as_bytes()).to_bytes()),
        ),
    ];
    anyhow::ensure!(
        watching(&when, &machine_headers, &body).await? == "not_found",
        "a machine, with no gate yet, has no certificate to watch"
    );
    signed_agent_call(
        &when,
        &machine_id,
        &machine_key,
        "GetMembership",
        r#"{"sinceEpoch": "0"}"#,
    )
    .await?;
    then.status(200)?;
    let machine_on_relay_header = signed(
        &TestRelay {
            relay_id: machine_id.clone(),
            key: machine_key.clone(),
        },
        &path,
        &body,
    );
    anyhow::ensure!(
        watching(&when, &machine_on_relay_header, &body).await? == "unauthenticated",
        "a machine's key never passes as a relay's"
    );
    when.calling("/grund.account.v1.AccountService/GetViewer", "{}")
        .await?;
    then.status(200)?;
    let cookie = then
        .testcase
        .data()
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    anyhow::ensure!(
        watching(&when, &[("Cookie".into(), cookie)], &body).await? == "unauthenticated",
        "a signed-in person is not a terminator"
    );

    let revoked = grund_relays(&when, &["revoke", &mine])?;
    anyhow::ensure!(revoked.status.success());
    let (status, _) = relay_calling(&when, &relay, "GetCertificate", &json!({})).await?;
    anyhow::ensure!(
        status == 401,
        "a revoked relay is refused from its next call"
    );
    anyhow::ensure!(relay_watching(&when, &relay).await? == "unauthenticated");
    let body = json!({"keys": []}).to_string();
    let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
    let access = signed(&relay, "/relay/v1/access/current", body.as_bytes());
    headers.extend(access.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    when.requesting_with(
        "POST",
        "/relay/v1/access/current",
        &headers,
        Some(body.as_bytes()),
    )
    .await?;
    then.status(401)?;
    let access = signed(&other, "/relay/v1/access/current", body.as_bytes());
    let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
    headers.extend(access.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    when.requesting_with(
        "POST",
        "/relay/v1/access/current",
        &headers,
        Some(body.as_bytes()),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        then.json()? == json!({"admitted": []}),
        "an enrolled relay asks the access check with its own key, and no shared token is set"
    );

    let unlisted = a_token_for(&when, "unlisted.example.com")?;
    enrolling(&when, &unlisted, &a_machine_key()).await?;
    then.status(403)?.connect_code("permission_denied")?;
    let used = a_token_for(&when, &mine)?;
    let key = a_machine_key();
    enrolling(&when, &used, &key).await?;
    then.status(200)?;
    enrolling(&when, &used, &a_machine_key()).await?;
    then.status(403)?;
    let reused = a_token_for(&when, &mine)?;
    enrolling(&when, &reused, &key).await?;
    then.status(400)?.connect_code("failed_precondition")?;
    Ok(())
}

#[tokio::test]
async fn a_second_instances_relay_and_its_tokens_are_refused() -> anyhow::Result<()> {
    if external_target().is_some() {
        return Ok(());
    }
    let Some(pebble) = Pebble::prepare(free_port())? else {
        return Ok(());
    };
    let host = a_relay_host();
    let shared = "relay-token-0123456789abcdef01234567";
    let Some(first) = an_instance_ordering_for(
        &pebble,
        &[(&host, 7443)],
        &[("GRUND_RELAY_ACCESS_TOKEN", shared)],
    )
    .await?
    else {
        return Ok(());
    };
    let Some(second) = an_instance_ordering_for(
        &pebble,
        &[(&host, 7443)],
        &[(
            "GRUND_RELAY_ACCESS_TOKEN",
            "another-instances-token-0123456789abcdef",
        )],
    )
    .await?
    else {
        return Ok(());
    };
    let theirs = an_enrolled_relay(&second.when, &second.then, &host).await?;
    let (status, answer) = relay_calling(
        &first.when,
        &theirs,
        "RequestCertificate",
        &json!({"names": [host], "csr": a_csr(&[&host])?}),
    )
    .await?;
    anyhow::ensure!(
        status == 401 && answer["code"] == "unauthenticated",
        "a relay of another instance is unknown here: {status} {answer}"
    );
    anyhow::ensure!(relay_watching(&first.when, &theirs).await? == "unauthenticated");

    let their_token = a_token_for(&second.when, &host)?;
    enrolling(&first.when, &their_token, &a_machine_key()).await?;
    first.then.status(403)?.connect_code("permission_denied")?;

    let body = json!({"keys": []}).to_string();
    first
        .when
        .requesting_with(
            "POST",
            "/relay/v1/access/current",
            &[
                ("Content-Type", "application/json"),
                (
                    "Authorization",
                    "Bearer another-instances-token-0123456789abcdef",
                ),
            ],
            Some(body.as_bytes()),
        )
        .await?;
    first.then.status(401)?;
    first
        .when
        .requesting_with(
            "POST",
            "/relay/v1/access/current",
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &format!("Bearer {shared}")),
            ],
            Some(body.as_bytes()),
        )
        .await?;
    first.then.status(200)?;
    let _ = first.given;
    let _ = second.given;
    Ok(())
}

#[tokio::test]
async fn with_its_grunds_ca_unreachable_a_relay_keeps_serving_its_stored_certificate()
-> anyhow::Result<()> {
    if external_target().is_some() {
        return Ok(());
    }
    let Some(mut pebble) = Pebble::start(free_port()).await? else {
        return Ok(());
    };
    let host = a_relay_host();
    let Some(Instance { when, .. }) =
        an_instance_ordering_for(&pebble, &[(&host, pebble.tls_port)], &[]).await?
    else {
        return Ok(());
    };
    let token = a_token_for(&when, &host)?;
    let dir = a_relay_dir();
    let relay = a_relay_process(&when, &dir, Some(&token), pebble.tls_port)?;
    let roots = pebble.roots().await?;
    let issued = eventually("a first certificate", Duration::from_secs(60), || {
        served_leaf(&host, pebble.tls_port, roots.clone())
    })
    .await
    .map_err(|error| error.context(relay_log(&dir)))?;

    pebble.stop();
    let mut connection =
        <sqlx::PgConnection as sqlx::Connection>::connect(&database_url(&when)).await?;
    sqlx::query("UPDATE grund_certificates SET renew_at = clock_timestamp() WHERE subject = $1")
        .bind(format!("relay:{host}"))
        .execute(&mut connection)
        .await?;
    eventually(
        "a renewal failing with the CA gone",
        Duration::from_secs(60),
        || async {
            let mut connection =
                <sqlx::PgConnection as sqlx::Connection>::connect(&database_url(&when)).await?;
            let failed: Option<String> =
                sqlx::query_scalar("SELECT last_error FROM grund_certificates WHERE subject = $1")
                    .bind(format!("relay:{host}"))
                    .fetch_one(&mut connection)
                    .await?;
            anyhow::ensure!(
                failed.as_deref() == Some("acme_unreachable"),
                "last_error is {failed:?}"
            );
            Ok(())
        },
    )
    .await
    .map_err(|error| {
        error.context(format!(
            "relay:\n{}\n--- grund:\n{}",
            relay_log(&dir),
            when.testcase.fixture.log()
        ))
    })?;
    anyhow::ensure!(
        relay_log(&dir).contains("renewal is due"),
        "the relay was asked for a fresh CSR and sent it"
    );
    anyhow::ensure!(
        served_leaf(&host, pebble.tls_port, roots.clone()).await? == issued,
        "the relay serves what it has while its grund cannot order"
    );

    drop(relay);
    let restarted = a_relay_process(&when, &dir, None, pebble.tls_port)?;
    let after = eventually(
        "the stored certificate after the relay restarted",
        Duration::from_secs(15),
        || served_leaf(&host, pebble.tls_port, roots.clone()),
    )
    .await
    .map_err(|error| error.context(relay_log(&dir)))?;
    anyhow::ensure!(after == issued, "served from its own disk");
    drop(restarted);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test]
async fn a_relay_beside_grund_serves_the_instances_own_certificate_under_both_names()
-> anyhow::Result<()> {
    if external_target().is_some() {
        return Ok(());
    }
    let Some(pebble) = Pebble::start(free_port()).await? else {
        return Ok(());
    };
    let domain = format!("grund-{}.localhost", random_hex(4));
    let relay_host = a_relay_host();
    let relay_port = free_port();
    let mut env = pebble.grund_settings(&domain);
    env.push((
        "GRUND_RELAY_ADDRESS".into(),
        format!("127.0.0.1:{relay_port}"),
    ));
    env.push((
        "GRUND_RELAY_URL".into(),
        format!("https://{relay_host}:{relay_port}"),
    ));
    env.push((
        "GRUND_RELAY_QUIC_ADDRESS".into(),
        format!("127.0.0.1:{}", free_port()),
    ));
    let Some((_, when, _)) = testcase_configured(&settings(&env)).await? else {
        return Ok(());
    };
    let roots = pebble.roots().await?;
    let https = eventually(
        "the instance's certificate",
        Duration::from_secs(60),
        || served_leaf(&domain, pebble.tls_port, roots.clone()),
    )
    .await
    .map_err(|error| error.context(when.testcase.fixture.log()))?;
    let relay = eventually(
        "the relay beside it serving the same certificate",
        Duration::from_secs(20),
        || served_leaf(&relay_host, relay_port, roots.clone()),
    )
    .await
    .map_err(|error| error.context(when.testcase.fixture.log()))?;
    anyhow::ensure!(relay == https, "one certificate, one key, both names");
    anyhow::ensure!(
        pebble.issued_count() == 1,
        "one order for both names:\n{}",
        pebble.log()
    );
    Ok(())
}
