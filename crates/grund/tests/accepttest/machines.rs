use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::accepttest::fixtures::{Given, Then, When, testcase_configured, testcase_with_mail};

const ENROLL: &str = "/grund.agent.v1.MachineEnrollmentService/EnrollMachine";
const POOL: &str = "/grund.machine.v1.ManagementPoolService";
const MACHINES: &str = "/grund.machine.v1.MachineService";

pub(super) fn a_machine_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("randomness");
    SigningKey::from_bytes(&seed)
}

pub(super) fn origin(when: &When) -> String {
    format!("http://{}", when.testcase.fixture.origin.authority())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn enrollment(
    origin: &str,
    token: &str,
    key: &SigningKey,
    signed_at: i64,
    hostname: &str,
) -> String {
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    let message = format!("grund-enroll-v1\n{origin}\n{signed_at}\n{digest}");
    json!({
        "token": token,
        "machinePublicKey": STANDARD.encode(key.verifying_key().to_bytes()),
        "signedAtUnix": signed_at.to_string(),
        "signature": STANDARD.encode(key.sign(message.as_bytes()).to_bytes()),
        "facts": {"hostname": hostname, "arch": "x86_64", "cpus": 2},
    })
    .to_string()
}

async fn enrolling(
    when: &When,
    token: &str,
    key: &SigningKey,
    hostname: &str,
) -> anyhow::Result<()> {
    let body = enrollment(&origin(when), token, key, now(), hostname);
    when.calling(ENROLL, &body).await?;
    Ok(())
}

fn json(then: &Then) -> anyhow::Result<Value> {
    then.json()
}

async fn operator_testcase() -> anyhow::Result<Option<(Given, When, Then, String)>> {
    let operator = format!("ops-{}", crate::accepttest::fixtures::random_hex(4));
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_OPERATOR_ORGANISATION", &operator)]).await?
    else {
        return Ok(None);
    };
    given.a_signed_in_account_named(&operator).await?;
    Ok(Some((given, when, then, operator)))
}

async fn minting(when: &When, then: &Then, procedure: &str, body: Value) -> anyhow::Result<String> {
    when.calling(procedure, &body.to_string()).await?;
    then.status(200)?;
    let token = json(then)?["token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    anyhow::ensure!(!token.is_empty(), "no token in {}", json(then)?);
    Ok(token)
}

#[tokio::test]
async fn a_management_token_registers_into_the_management_pool_and_pins_both_keys()
-> anyhow::Result<()> {
    let Some((_, when, then, _)) = operator_testcase().await? else {
        return Ok(());
    };
    let token = minting(
        &when,
        &then,
        &format!("{POOL}/CreateRegistrationToken"),
        json!({}),
    )
    .await?;
    anyhow::ensure!(token.starts_with("grund_reg_"), "{token}");

    enrolling(&when, &token, &a_machine_key(), "gm-01.fleet").await?;
    then.status(200)?;
    let enrolled = json(&then)?;
    anyhow::ensure!(enrolled["pool"] == "POOL_MANAGEMENT", "{enrolled}");
    anyhow::ensure!(enrolled["machineName"] == "gm-01", "{enrolled}");
    anyhow::ensure!(
        enrolled["instanceKey"]["purpose"] == "KEY_PURPOSE_INSTANCE",
        "{enrolled}"
    );
    anyhow::ensure!(
        enrolled["trustKey"]["purpose"] == "KEY_PURPOSE_MANAGEMENT",
        "{enrolled}"
    );
    anyhow::ensure!(
        enrolled["instanceKey"]["keyId"] != enrolled["trustKey"]["keyId"],
        "{enrolled}"
    );

    when.calling(&format!("{POOL}/ListPoolMachines"), "{}")
        .await?;
    then.status(200)?;
    let listed = json(&then)?;
    anyhow::ensure!(
        listed["machines"][0]["machineId"] == enrolled["machineId"],
        "{listed}"
    );
    anyhow::ensure!(
        listed["machines"][0]["state"] == "MACHINE_STATE_AVAILABLE",
        "{listed}"
    );
    Ok(())
}

#[tokio::test]
async fn a_join_token_registers_into_its_organisation_under_its_key() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let token = minting(
        &when,
        &then,
        &format!("{MACHINES}/CreateJoinToken"),
        json!({"organisation": owner.username, "name": "closet"}),
    )
    .await?;
    anyhow::ensure!(token.starts_with("grund_join_"), "{token}");

    enrolling(
        &when,
        &token,
        &a_machine_key(),
        "ignored-because-the-token-binds-a-name",
    )
    .await?;
    then.status(200)?;
    let enrolled = json(&then)?;
    anyhow::ensure!(enrolled["pool"] == "POOL_ORGANISATION", "{enrolled}");
    anyhow::ensure!(enrolled["machineName"] == "closet", "{enrolled}");
    anyhow::ensure!(
        enrolled["trustKey"]["purpose"] == "KEY_PURPOSE_ORGANISATION",
        "{enrolled}"
    );

    when.calling(
        &format!("{MACHINES}/GetOrganisationKey"),
        &json!({"organisation": owner.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["key"] == enrolled["trustKey"],
        "{}",
        json(&then)?
    );

    when.calling(
        &format!("{MACHINES}/ListMachines"),
        &json!({"organisation": owner.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    let listed = json(&then)?;
    anyhow::ensure!(listed["machines"][0]["name"] == "closet", "{listed}");
    anyhow::ensure!(
        listed["machines"][0]["state"] == "MACHINE_STATE_ACTIVE",
        "{listed}"
    );
    anyhow::ensure!(
        listed["machines"][0]["organisation"] == owner.username,
        "{listed}"
    );
    Ok(())
}

#[tokio::test]
async fn a_replay_by_the_same_key_returns_the_same_machine_and_no_other_key_gets_one()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let token = minting(
        &when,
        &then,
        &format!("{MACHINES}/CreateJoinToken"),
        json!({"organisation": owner.username}),
    )
    .await?;
    let key = a_machine_key();
    enrolling(&when, &token, &key, "box").await?;
    then.status(200)?;
    let first = json(&then)?["machineId"].clone();
    enrolling(&when, &token, &key, "box").await?;
    then.status(200)?;
    anyhow::ensure!(json(&then)?["machineId"] == first, "{}", json(&then)?);

    enrolling(&when, &token, &a_machine_key(), "box").await?;
    then.status(403)?.connect_code("permission_denied")?;
    Ok(())
}

#[tokio::test]
async fn used_expired_unknown_and_malformed_tokens_fail_identically() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let mint = || async {
        minting(
            &when,
            &then,
            &format!("{MACHINES}/CreateJoinToken"),
            json!({"organisation": owner.username}),
        )
        .await
    };
    let used = mint().await?;
    enrolling(&when, &used, &a_machine_key(), "first").await?;
    then.status(200)?;

    let Some(database) = when.testcase.fixture.database_url() else {
        eprintln!("skipped: expiring a token needs the spawned instance's database");
        return Ok(());
    };
    let expired = mint().await?;
    let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(&database).await?;
    sqlx::Executor::execute(
        &mut connection,
        "UPDATE grund_machine_tokens SET created_at = created_at - interval '1 hour', \
           expires_at = clock_timestamp() - interval '1 second' WHERE consumed_at IS NULL",
    )
    .await?;

    let unknown = format!("grund_join_{}", "a".repeat(52));
    let mut answers = Vec::new();
    for token in [
        used.as_str(),
        expired.as_str(),
        unknown.as_str(),
        "grund_join_nope",
        "nope",
    ] {
        enrolling(&when, token, &a_machine_key(), "second").await?;
        then.status(403)?.connect_code("permission_denied")?;
        let body = json(&then)?;
        answers.push((body["message"].clone(), body["details"].clone()));
    }
    anyhow::ensure!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "the answers differ: {answers:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_bad_proof_is_refused_and_leaves_the_token_usable() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let token = minting(
        &when,
        &then,
        &format!("{MACHINES}/CreateJoinToken"),
        json!({"organisation": owner.username}),
    )
    .await?;
    let key = a_machine_key();
    for body in [
        enrollment("https://another.example", &token, &key, now(), "box"),
        enrollment(&origin(&when), &token, &key, now() - 600, "box"),
    ] {
        when.calling(ENROLL, &body).await?;
        then.status(400)?.connect_code("invalid_argument")?;
    }
    enrolling(&when, &token, &key, "box").await?;
    then.status(200)?;
    Ok(())
}

#[tokio::test]
async fn a_lease_puts_the_machine_in_the_lessee_pool_with_a_grant_the_management_key_signed()
-> anyhow::Result<()> {
    let Some((given, when, then, _)) = operator_testcase().await? else {
        return Ok(());
    };
    let token = minting(
        &when,
        &then,
        &format!("{POOL}/CreateRegistrationToken"),
        json!({}),
    )
    .await?;
    enrolling(&when, &token, &a_machine_key(), "gm-02").await?;
    then.status(200)?;
    let enrolled = json(&then)?;
    let machine_id = enrolled["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let management = STANDARD.decode(
        enrolled["trustKey"]["publicKey"]
            .as_str()
            .unwrap_or_default(),
    )?;

    let (lessee, lessee_when, lessee_then) = given.testcase.another_browser();
    let tenant = lessee.a_signed_in_account().await?;

    when.calling(
        &format!("{POOL}/LeaseMachine"),
        &json!({"machineId": machine_id, "organisation": tenant.username, "name": "web-1"})
            .to_string(),
    )
    .await?;
    then.status(200)?;
    let leased = json(&then)?;
    anyhow::ensure!(
        leased["machine"]["state"] == "MACHINE_STATE_LEASED",
        "{leased}"
    );
    anyhow::ensure!(
        leased["machine"]["lease"]["organisation"] == tenant.username,
        "{leased}"
    );

    let payload = STANDARD.decode(leased["grant"]["payload"].as_str().unwrap_or_default())?;
    let signature = STANDARD.decode(leased["grant"]["signature"].as_str().unwrap_or_default())?;
    let verifying = VerifyingKey::from_bytes(&management.as_slice().try_into()?)?;
    let signed = [b"grund-lease-grant-v1\n".as_slice(), &payload].concat();
    verifying.verify(&signed, &Signature::from_slice(&signature)?)?;
    anyhow::ensure!(
        verifying
            .verify(
                &[b"grund-desired-state-v1\n".as_slice(), &payload].concat(),
                &Signature::from_slice(&signature)?
            )
            .is_err(),
        "a lease grant must not verify for another purpose"
    );

    lessee_when
        .calling(
            &format!("{MACHINES}/GetOrganisationKey"),
            &json!({"organisation": tenant.username}).to_string(),
        )
        .await?;
    lessee_then.status(200)?;
    let organisation_key = STANDARD.decode(
        json(&lessee_then)?["key"]["publicKey"]
            .as_str()
            .unwrap_or_default(),
    )?;
    anyhow::ensure!(
        payload
            .windows(32)
            .any(|w| w == organisation_key.as_slice()),
        "the grant names the lessee's organisation key"
    );
    anyhow::ensure!(
        payload
            .windows(machine_id.len())
            .any(|w| w == machine_id.as_bytes()),
        "the grant names the machine"
    );

    lessee_when
        .calling(
            &format!("{MACHINES}/ListMachines"),
            &json!({"organisation": tenant.username}).to_string(),
        )
        .await?;
    lessee_then.status(200)?;
    let listed = json(&lessee_then)?;
    anyhow::ensure!(listed["machines"][0]["name"] == "web-1", "{listed}");
    anyhow::ensure!(
        listed["machines"][0]["state"] == "MACHINE_STATE_LEASED",
        "{listed}"
    );

    lessee_when
        .calling(
            &format!("{MACHINES}/RevokeMachine"),
            &json!({"organisation": tenant.username, "machineId": machine_id}).to_string(),
        )
        .await?;
    lessee_then
        .status(400)?
        .connect_code("failed_precondition")?;
    Ok(())
}

#[tokio::test]
async fn an_ended_lease_needs_a_wiped_machine_with_a_new_key_before_the_next() -> anyhow::Result<()>
{
    let Some((given, when, then, _)) = operator_testcase().await? else {
        return Ok(());
    };
    let token = minting(
        &when,
        &then,
        &format!("{POOL}/CreateRegistrationToken"),
        json!({}),
    )
    .await?;
    let old_key = a_machine_key();
    enrolling(&when, &token, &old_key, "gm-03").await?;
    then.status(200)?;
    let machine_id = json(&then)?["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let (lessee, lessee_when, lessee_then) = given.testcase.another_browser();
    let tenant = lessee.a_signed_in_account().await?;
    when.calling(
        &format!("{POOL}/LeaseMachine"),
        &json!({"machineId": machine_id, "organisation": tenant.username}).to_string(),
    )
    .await?;
    then.status(200)?;

    when.calling(
        &format!("{POOL}/EndLease"),
        &json!({"machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["machine"]["state"] == "MACHINE_STATE_RETURNING",
        "{}",
        json(&then)?
    );
    lessee_when
        .calling(
            &format!("{MACHINES}/ListMachines"),
            &json!({"organisation": tenant.username}).to_string(),
        )
        .await?;
    lessee_then.status(200)?;
    anyhow::ensure!(
        json(&lessee_then)?["machines"]
            .as_array()
            .is_none_or(|m| m.is_empty()),
        "{}",
        json(&lessee_then)?
    );
    when.calling(
        &format!("{POOL}/LeaseMachine"),
        &json!({"machineId": machine_id, "organisation": tenant.username}).to_string(),
    )
    .await?;
    then.status(400)?.connect_code("failed_precondition")?;

    let again = minting(
        &when,
        &then,
        &format!("{POOL}/CreateReregistrationToken"),
        json!({"machineId": machine_id}),
    )
    .await?;
    enrolling(&when, &again, &old_key, "gm-03").await?;
    then.status(400)?.connect_code("failed_precondition")?;
    enrolling(&when, &again, &a_machine_key(), "gm-03").await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["machineId"] == machine_id.as_str(),
        "{}",
        json(&then)?
    );

    when.calling(
        &format!("{POOL}/GetPoolMachine"),
        &json!({"machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["machine"]["state"] == "MACHINE_STATE_AVAILABLE",
        "{}",
        json(&then)?
    );
    Ok(())
}

#[tokio::test]
async fn another_organisation_cannot_see_or_revoke_a_machine() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let token = minting(
        &when,
        &then,
        &format!("{MACHINES}/CreateJoinToken"),
        json!({"organisation": owner.username}),
    )
    .await?;
    enrolling(&when, &token, &a_machine_key(), "box").await?;
    then.status(200)?;
    let machine_id = json(&then)?["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    let other = outsider.a_signed_in_account().await?;
    for (procedure, body) in [
        (
            "GetMachine",
            json!({"organisation": owner.username, "machineId": machine_id}),
        ),
        (
            "RevokeMachine",
            json!({"organisation": owner.username, "machineId": machine_id}),
        ),
        ("ListMachines", json!({"organisation": owner.username})),
        ("CreateJoinToken", json!({"organisation": owner.username})),
        (
            "GetMachine",
            json!({"organisation": other.username, "machineId": machine_id}),
        ),
        (
            "RevokeMachine",
            json!({"organisation": other.username, "machineId": machine_id}),
        ),
    ] {
        outsider_when
            .calling(&format!("{MACHINES}/{procedure}"), &body.to_string())
            .await?;
        outsider_then
            .status(404)?
            .connect_code("not_found")
            .map_err(|e| e.context(format!("{procedure} {body}")))?;
    }

    when.calling(
        &format!("{MACHINES}/RevokeMachine"),
        &json!({"organisation": owner.username, "machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["machine"]["state"] == "MACHINE_STATE_REVOKED",
        "{}",
        json(&then)?
    );
    Ok(())
}

#[tokio::test]
async fn only_owners_and_admins_of_the_operator_organisation_run_the_management_pool()
-> anyhow::Result<()> {
    let Some((given, when, _, operator)) = operator_testcase().await? else {
        return Ok(());
    };
    let (guest, guest_when, guest_then) = given.testcase.another_browser();
    let member = guest.a_signed_in_account().await?;

    guest_when
        .calling(&format!("{POOL}/ListPoolMachines"), "{}")
        .await?;
    guest_then.status(404)?.connect_code("not_found")?;
    guest_when
        .calling(&format!("{POOL}/CreateRegistrationToken"), "{}")
        .await?;
    guest_then.status(404)?.connect_code("not_found")?;

    when.inviting(&operator, &member.email, "member").await?;
    let link = guest_when
        .the_mailed_link(
            &member.email,
            &format!("Join {operator} on grund"),
            "/invite?token=",
        )
        .await?;
    guest_when.visiting(&link).await?;
    let token = guest.last_token()?;
    guest_when
        .submitting_on_current_page("/invite", &[("token", &token)])
        .await?;
    guest_then.redirects_to(&format!("/{operator}"))?;

    guest_when
        .calling(&format!("{POOL}/ListPoolMachines"), "{}")
        .await?;
    guest_then.status(200)?;
    guest_when
        .calling(&format!("{POOL}/CreateRegistrationToken"), "{}")
        .await?;
    guest_then.status(403)?.connect_code("permission_denied")?;
    Ok(())
}

#[tokio::test]
async fn an_instance_without_an_operator_organisation_has_no_management_pool() -> anyhow::Result<()>
{
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;
    when.calling(&format!("{POOL}/ListPoolMachines"), "{}")
        .await?;
    then.status(404)?.connect_code("not_found")?;
    Ok(())
}

fn join_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "join-{}",
        crate::accepttest::fixtures::random_hex(6)
    ))
}

async fn grund_join(
    dir: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> std::process::Output {
    let mut command = std::process::Command::new(crate::accepttest::fixtures::grund_binary());
    command
        .arg("join")
        .arg("--data-dir")
        .arg(dir)
        .args(args)
        .env_clear()
        .env("RUST_LOG", "warn");
    for (name, value) in env {
        command.env(name, value);
    }
    tokio::task::spawn_blocking(move || command.output().expect("run grund join"))
        .await
        .expect("grund join's thread")
}

fn record(dir: &std::path::Path) -> anyhow::Result<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(
        dir.join("machine.json"),
    )?)?)
}

async fn a_fake_mmds(document: Value) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?.to_string();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let document = document.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                let n = socket.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..n]).to_string();
                let lower = request.to_ascii_lowercase();
                let (status, body) = if request.starts_with("PUT /latest/api/token ")
                    && lower.contains("x-metadata-token-ttl-seconds:")
                {
                    ("200 OK", "mmds-session".to_string())
                } else if request.starts_with("GET / ")
                    && lower.contains("x-metadata-token: mmds-session")
                {
                    ("200 OK", document.to_string())
                } else {
                    ("401 Unauthorized", String::new())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok(address)
}

#[tokio::test]
async fn grund_join_registers_a_customer_machine_and_a_second_run_changes_nothing()
-> anyhow::Result<()> {
    if crate::accepttest::fixtures::external_target().is_some() {
        eprintln!("skipped: grund join signs for a loopback origin of a spawned instance");
        return Ok(());
    }
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let token = minting(
        &when,
        &then,
        &format!("{MACHINES}/CreateJoinToken"),
        json!({"organisation": owner.username}),
    )
    .await?;
    let dir = join_dir();
    let url = origin(&when);

    let first = grund_join(&dir, &["--url", &url, "--name", "closet", &token], &[]).await;
    let stdout = String::from_utf8_lossy(&first.stdout);
    anyhow::ensure!(
        first.status.success(),
        "grund join failed: {stdout}{}",
        String::from_utf8_lossy(&first.stderr)
    );
    anyhow::ensure!(stdout.contains("registered as closet"), "{stdout}");
    let kept = record(&dir)?;
    anyhow::ensure!(kept["pool"] == "organisation", "{kept}");
    anyhow::ensure!(kept["trust_key"]["purpose"] == "organisation", "{kept}");
    anyhow::ensure!(kept["instance_url"] == url.as_str(), "{kept}");
    anyhow::ensure!(kept["network"]["key"]["purpose"] == "network", "{kept}");
    anyhow::ensure!(kept["network"]["slot"] == 1, "{kept}");
    let key_mode = std::fs::metadata(dir.join("machine.key"))?.permissions();
    anyhow::ensure!(std::os::unix::fs::PermissionsExt::mode(&key_mode) & 0o777 == 0o600);

    let second = grund_join(&dir, &["--url", &url, &token], &[]).await;
    anyhow::ensure!(second.status.success());
    anyhow::ensure!(
        String::from_utf8_lossy(&second.stdout).contains("already registered as closet")
    );

    when.calling(
        &format!("{MACHINES}/ListMachines"),
        &json!({"organisation": owner.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    let listed = json(&then)?;
    anyhow::ensure!(
        listed["machines"].as_array().map(Vec::len) == Some(1),
        "{listed}"
    );
    anyhow::ensure!(
        listed["machines"][0]["machineId"] == kept["machine_id"],
        "{listed}"
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[tokio::test]
async fn grund_join_reads_a_grund_machines_assignment_from_mmds() -> anyhow::Result<()> {
    let Some((_, when, then, _)) = operator_testcase().await? else {
        return Ok(());
    };
    let token = minting(
        &when,
        &then,
        &format!("{POOL}/CreateRegistrationToken"),
        json!({"name": "gm-7"}),
    )
    .await?;
    let mmds = a_fake_mmds(json!({
        "grund": {"url": origin(&when), "enrollment_token": token, "expires_at": "later", "assignment_id": "a-1"},
        "fleet": {"machine_id": "fm-123"},
    }))
    .await?;
    let dir = join_dir();
    let joined = grund_join(&dir, &["--mmds"], &[("GRUND_MMDS_ADDRESS", &mmds)]).await;
    anyhow::ensure!(
        joined.status.success(),
        "grund join --mmds failed: {}{}",
        String::from_utf8_lossy(&joined.stdout),
        String::from_utf8_lossy(&joined.stderr)
    );
    let kept = record(&dir)?;
    anyhow::ensure!(kept["pool"] == "management", "{kept}");
    anyhow::ensure!(kept["trust_key"]["purpose"] == "management", "{kept}");

    when.calling(
        &format!("{POOL}/GetPoolMachine"),
        &json!({"machineId": kept["machine_id"]}).to_string(),
    )
    .await?;
    then.status(200)?;
    let machine = json(&then)?;
    anyhow::ensure!(machine["machine"]["name"] == "gm-7", "{machine}");
    anyhow::ensure!(
        machine["machine"]["facts"]["fleetMachineId"] == "fm-123",
        "{machine}"
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[tokio::test]
async fn grund_join_says_why_a_refused_code_was_refused() -> anyhow::Result<()> {
    if crate::accepttest::fixtures::external_target().is_some() {
        eprintln!("skipped: grund join signs for a loopback origin of a spawned instance");
        return Ok(());
    }
    let Some((given, when, _)) = testcase_with_mail().await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;
    let dir = join_dir();
    let unknown = format!("grund_join_{}", "b".repeat(52));
    let refused = grund_join(&dir, &["--url", &origin(&when), &unknown], &[]).await;
    let stderr = String::from_utf8_lossy(&refused.stderr);
    anyhow::ensure!(!refused.status.success(), "an unknown code registered");
    anyhow::ensure!(stderr.contains("token_invalid"), "{stderr}");
    anyhow::ensure!(
        !dir.join("machine.json").exists(),
        "a refused join left a record"
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test]
async fn the_operator_organisation_may_be_named_by_its_id() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let operator = given.a_signed_in_account().await?;
    when.calling(
        "/grund.organisation.v1.OrganisationService/GetOrganisation",
        &json!({"slug": operator.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    let organisation_id = json(&then)?["organisation"]["organisationId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    when.calling(&format!("{POOL}/ListPoolMachines"), "{}")
        .await?;
    then.status(404)?.connect_code("not_found")?;

    when.testcase
        .fixture
        .restart_with(&[("GRUND_OPERATOR_ORGANISATION", &organisation_id)])
        .await?;
    when.calling(&format!("{POOL}/ListPoolMachines"), "{}")
        .await?;
    then.status(200)?;
    minting(
        &when,
        &then,
        &format!("{POOL}/CreateRegistrationToken"),
        json!({}),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn a_capacity_provider_provisions_rebuilds_and_releases_a_pool_machine() -> anyhow::Result<()>
{
    use crate::accepttest::fixtures::{CAPACITY_TOKEN, FakeCapacity};
    let capacity = FakeCapacity::start().await?;
    let operator = format!("ops-{}", crate::accepttest::fixtures::random_hex(4));
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_OPERATOR_ORGANISATION", &operator),
        ("GRUND_CAPACITY_URL", &capacity.url),
        ("GRUND_CAPACITY_TOKEN", CAPACITY_TOKEN),
    ])
    .await?
    else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;

    when.calling(
        &format!("{POOL}/ProvisionPoolMachine"),
        &json!({"name": "gm-9"}).to_string(),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["providerMachineId"] == "fm-1",
        "{}",
        json(&then)?
    );
    let provision = capacity.calls("ProvisionMachine");
    anyhow::ensure!(provision.len() == 1, "{provision:?}");
    anyhow::ensure!(
        provision[0].authorization.as_deref() == Some(&*format!("Bearer {CAPACITY_TOKEN}")),
        "{provision:?}"
    );
    let token = provision[0].body["enrollmentToken"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    anyhow::ensure!(token.starts_with("grund_reg_"), "{token}");
    anyhow::ensure!(
        provision[0].body["grundUrl"] == origin(&when).as_str(),
        "{provision:?}"
    );
    anyhow::ensure!(
        provision[0].body["idempotencyKey"]
            .as_str()
            .is_some_and(|k| !k.is_empty()),
        "{provision:?}"
    );

    let booted = join_dir();
    let joined = grund_join(&booted, &["--url", &origin(&when), &token], &[]).await;
    anyhow::ensure!(
        joined.status.success(),
        "{}",
        String::from_utf8_lossy(&joined.stderr)
    );
    let machine_id = record(&booted)?["machine_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    when.calling(
        &format!("{POOL}/GetPoolMachine"),
        &json!({"machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    let machine = json(&then)?;
    anyhow::ensure!(machine["machine"]["name"] == "gm-9", "{machine}");
    anyhow::ensure!(
        machine["machine"]["providerMachineId"] == "fm-1",
        "{machine}"
    );

    let (lessee, lessee_when, lessee_then) = given.testcase.another_browser();
    let tenant = lessee.a_signed_in_account().await?;
    when.calling(
        &format!("{POOL}/LeaseMachine"),
        &json!({"machineId": machine_id, "organisation": tenant.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    lessee_when
        .calling(
            &format!("{MACHINES}/GetMachine"),
            &json!({"organisation": tenant.username, "machineId": machine_id}).to_string(),
        )
        .await?;
    lessee_then.status(200)?;
    anyhow::ensure!(
        json(&lessee_then)?["machine"]
            .get("providerMachineId")
            .is_none(),
        "the lessee does not see the provider's id: {}",
        json(&lessee_then)?
    );

    capacity.unavailable_for("RebuildMachine", true);
    when.calling(
        &format!("{POOL}/EndLease"),
        &json!({"machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    let ended = json(&then)?;
    anyhow::ensure!(
        ended["machine"]["state"] == "MACHINE_STATE_RETURNING",
        "{ended}"
    );
    anyhow::ensure!(ended["providerStep"] == "PROVIDER_STEP_FAILED", "{ended}");

    capacity.unavailable_for("RebuildMachine", false);
    when.calling(
        &format!("{POOL}/RebuildPoolMachine"),
        &json!({"machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["providerStep"] == "PROVIDER_STEP_REQUESTED",
        "{}",
        json(&then)?
    );
    let rebuilds = capacity.calls("RebuildMachine");
    let rebuild = rebuilds
        .last()
        .ok_or_else(|| anyhow::anyhow!("no rebuild call"))?;
    anyhow::ensure!(rebuild.body["providerMachineId"] == "fm-1", "{rebuild:?}");
    let again = rebuild.body["enrollmentToken"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    anyhow::ensure!(
        again.starts_with("grund_reg_") && again != token,
        "{rebuild:?}"
    );

    let rebuilt = join_dir();
    let rejoined = grund_join(&rebuilt, &["--url", &origin(&when), &again], &[]).await;
    anyhow::ensure!(
        rejoined.status.success(),
        "{}",
        String::from_utf8_lossy(&rejoined.stderr)
    );
    anyhow::ensure!(record(&rebuilt)?["machine_id"] == machine_id.as_str());
    when.calling(
        &format!("{POOL}/GetPoolMachine"),
        &json!({"machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    let machine = json(&then)?;
    anyhow::ensure!(
        machine["machine"]["state"] == "MACHINE_STATE_AVAILABLE",
        "{machine}"
    );
    anyhow::ensure!(
        machine["machine"]["providerMachineId"] == "fm-1",
        "{machine}"
    );

    when.calling(
        &format!("{POOL}/RevokePoolMachine"),
        &json!({"machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["providerStep"] == "PROVIDER_STEP_REQUESTED",
        "{}",
        json(&then)?
    );
    let released = capacity.calls("ReleaseMachine");
    anyhow::ensure!(
        released.len() == 1 && released[0].body["providerMachineId"] == "fm-1",
        "{released:?}"
    );
    std::fs::remove_dir_all(booted)?;
    std::fs::remove_dir_all(rebuilt)?;
    Ok(())
}

#[tokio::test]
async fn without_a_capacity_provider_the_pool_is_filled_by_hand() -> anyhow::Result<()> {
    let Some((_, when, then, _)) = operator_testcase().await? else {
        return Ok(());
    };
    when.calling(&format!("{POOL}/ProvisionPoolMachine"), "{}")
        .await?;
    then.status(400)?.connect_code("failed_precondition")?;
    Ok(())
}

#[tokio::test]
async fn a_machine_that_registers_before_the_provider_answers_still_gets_its_provider_id()
-> anyhow::Result<()> {
    use crate::accepttest::fixtures::{CAPACITY_TOKEN, FakeCapacity};
    let capacity = FakeCapacity::start().await?;
    let operator = format!("ops-{}", crate::accepttest::fixtures::random_hex(4));
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_OPERATOR_ORGANISATION", &operator),
        ("GRUND_CAPACITY_URL", &capacity.url),
        ("GRUND_CAPACITY_TOKEN", CAPACITY_TOKEN),
    ])
    .await?
    else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;
    let booted = join_dir();
    capacity.boot_before_answering(booted.clone());

    when.calling(&format!("{POOL}/ProvisionPoolMachine"), "{}")
        .await?;
    then.status(200)?;
    let machine_id = record(&booted)?["machine_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    when.calling(
        &format!("{POOL}/GetPoolMachine"),
        &json!({"machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    let machine = json(&then)?;
    anyhow::ensure!(
        machine["machine"]["providerMachineId"] == "fm-1",
        "{machine}"
    );
    std::fs::remove_dir_all(booted)?;
    Ok(())
}

async fn grund_agent_once(dir: &std::path::Path) -> std::process::Output {
    let mut command = std::process::Command::new(crate::accepttest::fixtures::grund_binary());
    command
        .args(["agent", "--once", "--vm-runtime", "simulated", "--data-dir"])
        .arg(dir)
        .env_clear()
        .env("RUST_LOG", "grund_agent=info");
    tokio::task::spawn_blocking(move || command.output().expect("run grund agent"))
        .await
        .expect("grund agent's thread")
}

pub(super) async fn signed_agent_call(
    when: &When,
    machine_id: &str,
    key: &SigningKey,
    procedure: &str,
    body: &str,
) -> anyhow::Result<()> {
    let path = format!("/grund.agent.v1.AgentService/{procedure}");
    let signed_at = now();
    let message = format!(
        "grund-agent-request-v1\n{path}\n{signed_at}\n{}",
        hex::encode(Sha256::digest(body.as_bytes()))
    );
    let signature = STANDARD.encode(key.sign(message.as_bytes()).to_bytes());
    when.calling_with(
        &path,
        body,
        &[
            ("x-grund-machine", machine_id),
            ("x-grund-signed-at", &signed_at.to_string()),
            ("x-grund-signature", &signature),
        ],
    )
    .await?;
    Ok(())
}

pub(super) fn device_key(dir: &std::path::Path) -> anyhow::Result<SigningKey> {
    let seed: [u8; 32] = hex::decode(std::fs::read_to_string(dir.join("machine.key"))?.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("a machine key is 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

const IMAGE: &str = r#"{"kernel": {"url": "https://images.accept.test/vmlinux", "sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
                       "rootfs": {"url": "https://images.accept.test/rootfs.ext4", "sha256": "2222222222222222222222222222222222222222222222222222222222222222"}}"#;

#[tokio::test]
async fn a_device_stays_connected_and_runs_a_vm_that_joins_the_same_organisation()
-> anyhow::Result<()> {
    if crate::accepttest::fixtures::external_target().is_some() {
        eprintln!("skipped: the agent signs for a loopback origin of a spawned instance");
        return Ok(());
    }
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let token = minting(
        &when,
        &then,
        &format!("{MACHINES}/CreateJoinToken"),
        json!({"organisation": owner.username, "name": "haze"}),
    )
    .await?;
    let device = join_dir();
    let joined = grund_join(&device, &["--url", &origin(&when), &token], &[]).await;
    anyhow::ensure!(
        joined.status.success(),
        "{}",
        String::from_utf8_lossy(&joined.stderr)
    );
    let device_id = record(&device)?["machine_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let list_path = format!("{MACHINES}/ListMachines");
    let list_body = json!({"organisation": owner.username}).to_string();

    when.calling(&list_path, &list_body).await?;
    anyhow::ensure!(
        json(&then)?["machines"][0].get("connected").is_none(),
        "{}",
        json(&then)?
    );

    let beat = grund_agent_once(&device).await;
    anyhow::ensure!(
        beat.status.success(),
        "{}",
        String::from_utf8_lossy(&beat.stderr)
    );
    when.calling(&list_path, &list_body).await?;
    let listed = json(&then)?;
    anyhow::ensure!(listed["machines"][0]["connected"] == true, "{listed}");
    anyhow::ensure!(
        listed["machines"][0]["capabilities"]["kvm"] == true,
        "{listed}"
    );
    let reported = |value: &Value| value.as_str().is_some_and(|gib| gib != "0");
    anyhow::ensure!(
        reported(&listed["machines"][0]["facts"]["diskGib"])
            && reported(&listed["machines"][0]["capabilities"]["diskGib"]),
        "the agent reports its disk at join and in its heartbeat: {listed}"
    );

    let run = format!(
        r#"{{"organisation": "{}", "onMachineId": "{device_id}", "name": "vm1", "vcpus": 1, "memoryMib": 512, "diskGib": 2, "image": {IMAGE}}}"#,
        owner.username
    );
    when.calling(&format!("{MACHINES}/RunVm"), &run).await?;
    then.status(200)?;
    let vm_id = json(&then)?["vm"]["vmId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let applied = grund_agent_once(&device).await;
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    anyhow::ensure!(logs.contains("applied a new desired state"), "{logs}");
    when.calling(
        &format!("{MACHINES}/ListVms"),
        &json!({"organisation": owner.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    let vms = json(&then)?;
    anyhow::ensure!(vms["vms"][0]["vmId"] == vm_id.as_str(), "{vms}");
    anyhow::ensure!(
        vms["vms"][0]["observedState"] == "VM_OBSERVED_STATE_RUNNING",
        "{vms}"
    );
    let guest_id = vms["vms"][0]["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    anyhow::ensure!(
        !guest_id.is_empty(),
        "the VM registered as a machine: {vms}"
    );

    when.calling(&list_path, &list_body).await?;
    let listed = json(&then)?;
    let guest = listed["machines"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["machineId"] == guest_id.as_str()))
        .ok_or_else(|| {
            anyhow::anyhow!("the VM's machine is in the organisation's pool: {listed}")
        })?;
    anyhow::ensure!(guest["name"] == "vm1", "{guest}");
    anyhow::ensure!(guest["state"] == "MACHINE_STATE_ACTIVE", "{guest}");

    when.calling(
        &format!("{MACHINES}/StopVm"),
        &json!({"organisation": owner.username, "vmId": vm_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    grund_agent_once(&device).await;
    when.calling(
        &format!("{MACHINES}/ListVms"),
        &json!({"organisation": owner.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["vms"][0]["observedState"] == "VM_OBSERVED_STATE_STOPPED",
        "{}",
        json(&then)?
    );
    std::fs::remove_dir_all(device)?;
    Ok(())
}

#[tokio::test]
async fn the_control_link_answers_only_a_live_machine_that_signed_the_request() -> anyhow::Result<()>
{
    if crate::accepttest::fixtures::external_target().is_some() {
        eprintln!("skipped: needs a machine registered with a spawned instance");
        return Ok(());
    }
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let token = minting(
        &when,
        &then,
        &format!("{MACHINES}/CreateJoinToken"),
        json!({"organisation": owner.username}),
    )
    .await?;
    let device = join_dir();
    let joined = grund_join(&device, &["--url", &origin(&when), &token], &[]).await;
    anyhow::ensure!(joined.status.success());
    let machine_id = record(&device)?["machine_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let key = device_key(&device)?;

    signed_agent_call(&when, &machine_id, &key, "Heartbeat", "{}").await?;
    then.status(200)?;

    when.calling("/grund.agent.v1.AgentService/Heartbeat", "{}")
        .await?;
    then.status(401)?.connect_code("unauthenticated")?;
    signed_agent_call(&when, &machine_id, &a_machine_key(), "Heartbeat", "{}").await?;
    then.status(401)?.connect_code("unauthenticated")?;
    let other_path = "/grund.agent.v1.AgentService/Heartbeat".to_string();
    let signed_at = now();
    let message = format!(
        "grund-agent-request-v1\n{other_path}\n{signed_at}\n{}",
        hex::encode(Sha256::digest(b"{\"agentVersion\": \"x\"}"))
    );
    when.calling_with(
        &other_path,
        "{}",
        &[
            ("x-grund-machine", &machine_id),
            ("x-grund-signed-at", &signed_at.to_string()),
            (
                "x-grund-signature",
                &STANDARD.encode(key.sign(message.as_bytes()).to_bytes()),
            ),
        ],
    )
    .await?;
    then.status(401)?.connect_code("unauthenticated")?;

    signed_agent_call(
        &when,
        &machine_id,
        &key,
        "GetMachineJoinToken",
        &json!({"vmId": "01a0dd99-5679-7622-9f19-01b55c3ccf2f"}).to_string(),
    )
    .await?;
    then.status(404)?.connect_code("not_found")?;

    let run = format!(
        r#"{{"organisation": "{}", "onMachineId": "{machine_id}", "name": "vm1", "vcpus": 1, "memoryMib": 512, "diskGib": 2, "image": {IMAGE}}}"#,
        owner.username
    );
    when.calling(&format!("{MACHINES}/RunVm"), &run).await?;
    then.status(400)?.connect_code("failed_precondition")?;

    when.calling(
        &format!("{MACHINES}/RevokeMachine"),
        &json!({"organisation": owner.username, "machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    signed_agent_call(&when, &machine_id, &key, "Heartbeat", "{}").await?;
    then.status(401)?.connect_code("unauthenticated")?;
    std::fs::remove_dir_all(device)?;
    Ok(())
}

fn setup_command(page: &str) -> anyhow::Result<Vec<String>> {
    let start = page
        .find("grund join --url ")
        .ok_or_else(|| anyhow::anyhow!("the page shows no setup command"))?;
    let line = &page[start..];
    let end = line.find('<').unwrap_or(line.len());
    Ok(line[..end]
        .split_whitespace()
        .skip(2)
        .map(|arg| arg.replace("&#x2f;", "/"))
        .collect())
}

#[tokio::test]
async fn the_machines_page_adds_a_device_shows_it_connected_and_runs_a_vm_on_it()
-> anyhow::Result<()> {
    if crate::accepttest::fixtures::external_target().is_some() {
        eprintln!("skipped: grund join signs for a loopback origin of a spawned instance");
        return Ok(());
    }
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let page = format!("/{}/machines", owner.username);

    when.visiting(&page).await?;
    then.status(200)?
        .body_contains("No machines yet.")?
        .body_contains("Get a setup code")?
        .body_contains("That needs a connected machine with KVM.")?;

    when.submitting(&page, &format!("{page}/add"), &[("name", "desk")])
        .await?;
    then.status(200)?
        .header("cache-control", "no-store")?
        .body_contains("The code works once and is not shown again.")?
        .body_contains("aria-label=\"Copy the command\"")?
        .body_contains("data-copy=\"grund join --url ")?;
    let args = setup_command(&then.body()?)?;
    anyhow::ensure!(args[0] == "--url" && args[1] == origin(&when), "{args:?}");
    anyhow::ensure!(args[2].starts_with("grund_join_"), "{args:?}");

    when.visiting(&page).await?;
    then.status(200)?.body_lacks(&args[2])?;

    let device = join_dir();
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let joined = grund_join(&device, &arg_refs, &[]).await;
    anyhow::ensure!(
        joined.status.success(),
        "{}",
        String::from_utf8_lossy(&joined.stderr)
    );
    let device_id = record(&device)?["machine_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    when.visiting(&page).await?;
    then.status(200)?
        .body_contains("desk")?
        .body_contains("Not connected yet")?;

    grund_agent_once(&device).await;
    when.visiting(&page).await?;
    then.status(200)?
        .body_contains("Runs VMs")?
        .body_contains(&format!(
            r#"name="host" value="{device_id}" checked><span>desk</span>"#
        ))?;

    let sha = |c: char| c.to_string().repeat(64);
    let (kernel_sha, rootfs_sha) = (sha('1'), sha('2'));
    let run = |name: &'static str, vcpus: &'static str| {
        vec![
            ("host", device_id.clone()),
            ("vm_name", name.to_string()),
            ("vcpus", vcpus.to_string()),
            ("memory_mib", "512".to_string()),
            ("disk_gib", "2".to_string()),
            (
                "kernel_url",
                "https://images.accept.test/vmlinux".to_string(),
            ),
            ("kernel_sha256", kernel_sha.clone()),
            (
                "rootfs_url",
                "https://images.accept.test/rootfs.ext4".to_string(),
            ),
            ("rootfs_sha256", rootfs_sha.clone()),
        ]
    };
    let fields = run("vm1", "one");
    let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    when.submitting(&page, &format!("{page}/vms"), &refs)
        .await?;
    then.status(200)?
        .body_contains("vCPUs, memory and disk are whole numbers.")?
        .body_contains("value=\"vm1\"")?;

    let fields = run("vm1", "1");
    let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    when.submitting(&page, &format!("{page}/vms"), &refs)
        .await?;
    then.redirects_to(&format!("{page}?done=running"))?;

    grund_agent_once(&device).await;
    when.visiting(&page).await?;
    then.status(200)?
        .body_contains("vm1")?
        .body_contains("on desk · 1 vCPU, 512 MiB, 2 GiB")?
        .body_contains("Running")?;
    let body = then.body()?.replace("&#x2f;", "/");
    let stop = body
        .split("/machines/vms/")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or_else(|| anyhow::anyhow!("the page offers no stop"))?
        .to_string();
    when.submitting(&page, &format!("{page}/vms/{stop}"), &[])
        .await?;
    then.redirects_to(&format!("{page}?done=stopped"))?;

    when.submitting(&page, &format!("{page}/{device_id}/remove"), &[])
        .await?;
    then.redirects_to(&format!("{page}?done=removed"))?;
    when.visiting(&format!("{page}?done=removed")).await?;
    then.status(200)?
        .body_contains("Machine removed.")?
        .body_lacks(&format!("{device_id}/remove"))?;
    std::fs::remove_dir_all(device)?;
    Ok(())
}

#[tokio::test]
async fn a_member_sees_the_machines_page_but_cannot_add_or_remove() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (guest, guest_when, guest_then) = given.testcase.another_browser();
    let member = guest.a_signed_in_account().await?;
    when.inviting(&owner.username, &member.email, "member")
        .await?;
    let link = guest_when
        .the_mailed_link(
            &member.email,
            &format!("Join {} on grund", owner.username),
            "/invite?token=",
        )
        .await?;
    guest_when.visiting(&link).await?;
    let token = guest.last_token()?;
    guest_when
        .submitting_on_current_page("/invite", &[("token", &token)])
        .await?;
    let page = format!("/{}/machines", owner.username);

    guest_when.visiting(&page).await?;
    guest_then
        .status(200)?
        .body_contains("Machines")?
        .body_lacks("Get a setup code")?;
    guest_when
        .submitting(&page, &format!("{page}/add"), &[("name", "sneak")])
        .await?;
    guest_then.redirects_to(&format!("{page}?error=not-allowed"))?;
    let _ = then;
    Ok(())
}

pub(super) async fn a_member(
    when: &When,
    then: &Then,
    organisation: &str,
    name: &str,
) -> anyhow::Result<(SigningKey, Value)> {
    let token = minting(
        when,
        then,
        &format!("{MACHINES}/CreateJoinToken"),
        json!({"organisation": organisation, "name": name}),
    )
    .await?;
    let key = a_machine_key();
    enrolling(when, &token, &key, name).await?;
    then.status(200)?;
    Ok((key, json(then)?))
}

fn membership(
    then: &Then,
    network_key: &Value,
) -> anyhow::Result<grund_net::membership::MembershipList> {
    let answer = json(then)?;
    let list = &answer["list"];
    anyhow::ensure!(list["keyId"] == network_key["keyId"], "{answer}");
    let pinned: [u8; 32] = STANDARD
        .decode(network_key["publicKey"].as_str().unwrap_or_default())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("a network key is 32 bytes"))?;
    let signed = grund_net::membership::SignedList {
        body: STANDARD.decode(list["body"].as_str().unwrap_or_default())?,
        signature: STANDARD.decode(list["signature"].as_str().unwrap_or_default())?,
    };
    Ok(signed.verify(&VerifyingKey::from_bytes(&pinned)?)?)
}

fn slots(list: &grund_net::membership::MembershipList) -> Vec<(String, u16)> {
    let mut slots: Vec<(String, u16)> = list
        .members
        .iter()
        .map(|m| (m.endpoint_id.clone(), m.slot))
        .collect();
    slots.sort_by_key(|(_, slot)| *slot);
    slots
}

pub(super) fn endpoint(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

#[tokio::test]
async fn an_organisations_machines_share_its_signed_network_and_a_revoked_one_leaves_it()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (a, first) = a_member(&when, &then, &owner.username, "net-a").await?;
    let (b, second) = a_member(&when, &then, &owner.username, "net-b").await?;
    let network = &first["network"];
    anyhow::ensure!(
        network["key"]["purpose"] == "KEY_PURPOSE_NETWORK",
        "{first}"
    );
    anyhow::ensure!(
        network["slot"] == 1 && second["network"]["slot"] == 2,
        "{second}"
    );
    anyhow::ensure!(
        second["network"]["networkId"] == network["networkId"],
        "{second}"
    );
    anyhow::ensure!(second["network"]["key"] == network["key"], "{second}");
    let prefix: std::net::Ipv6Addr = network["prefix"].as_str().unwrap_or_default().parse()?;
    anyhow::ensure!(
        prefix.octets()[0] == 0xfd && prefix.octets()[6..].iter().all(|b| *b == 0),
        "{prefix}"
    );
    let a_id = first["machineId"].as_str().unwrap_or_default().to_string();
    let b_id = second["machineId"].as_str().unwrap_or_default().to_string();

    signed_agent_call(&when, &a_id, &a, "GetMembership", r#"{"sinceEpoch": "0"}"#).await?;
    then.status(200)?;
    let list = membership(&then, &network["key"])?;
    anyhow::ensure!(list.network_id == network["networkId"].as_str().unwrap_or_default());
    anyhow::ensure!(list.prefix == prefix);
    anyhow::ensure!(
        slots(&list) == vec![(endpoint(&a), 1), (endpoint(&b), 2)],
        "{list:?}"
    );
    anyhow::ensure!(
        list.member_by_name("net-a").map(|m| m.slot) == Some(1)
            && list.member_by_name("net-b").map(|m| m.slot) == Some(2),
        "every member is named as in its pool: {list:?}"
    );
    let epoch = list.epoch;

    when.calling(
        &format!("{MACHINES}/RevokeMachine"),
        &json!({"organisation": owner.username, "machineId": b_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    signed_agent_call(
        &when,
        &a_id,
        &a,
        "GetMembership",
        &json!({"sinceEpoch": epoch.to_string()}).to_string(),
    )
    .await?;
    then.status(200)?;
    let after = membership(&then, &network["key"])?;
    anyhow::ensure!(after.epoch > epoch, "{after:?}");
    anyhow::ensure!(slots(&after) == vec![(endpoint(&a), 1)], "{after:?}");
    signed_agent_call(&when, &b_id, &b, "GetMembership", r#"{"sinceEpoch": "0"}"#).await?;
    then.status(401)?;

    let (c, third) = a_member(&when, &then, &owner.username, "net-c").await?;
    anyhow::ensure!(
        third["network"]["slot"] == 3,
        "a freed slot is held for 24 hours: {third}"
    );
    let c_id = third["machineId"].as_str().unwrap_or_default().to_string();
    signed_agent_call(&when, &c_id, &c, "GetMembership", r#"{"sinceEpoch": "0"}"#).await?;
    then.status(200)?;
    anyhow::ensure!(
        slots(&membership(&then, &network["key"])?) == vec![(endpoint(&a), 1), (endpoint(&c), 3)]
    );

    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    let stranger = outsider.a_signed_in_account().await?;
    let (s, theirs) = a_member(&outsider_when, &outsider_then, &stranger.username, "net-s").await?;
    anyhow::ensure!(
        theirs["network"]["networkId"] != network["networkId"],
        "{theirs}"
    );
    anyhow::ensure!(theirs["network"]["prefix"] != network["prefix"], "{theirs}");
    signed_agent_call(
        &outsider_when,
        theirs["machineId"].as_str().unwrap_or_default(),
        &s,
        "GetMembership",
        &json!({"networkId": network["networkId"], "sinceEpoch": "0"}).to_string(),
    )
    .await?;
    outsider_then.status(404)?;
    Ok(())
}

#[tokio::test]
async fn a_waiting_member_hears_of_a_revocation_within_seconds() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (a, first) = a_member(&when, &then, &owner.username, "wait-a").await?;
    let (_, second) = a_member(&when, &then, &owner.username, "wait-b").await?;
    let a_id = first["machineId"].as_str().unwrap_or_default().to_string();
    let (_, machine_when, machine_then) = given.testcase.another_browser();
    signed_agent_call(
        &machine_when,
        &a_id,
        &a,
        "GetMembership",
        r#"{"sinceEpoch": "0"}"#,
    )
    .await?;
    let epoch = membership(&machine_then, &first["network"]["key"])?.epoch;

    let since = json!({"sinceEpoch": epoch.to_string()}).to_string();
    let started = std::time::Instant::now();
    let waiting = signed_agent_call(&machine_when, &a_id, &a, "GetMembership", &since);
    let revoking = async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        when.calling(
            &format!("{MACHINES}/RevokeMachine"),
            &json!({"organisation": owner.username, "machineId": second["machineId"]}).to_string(),
        )
        .await
    };
    let (waited, revoked) = tokio::join!(waiting, revoking);
    waited?;
    revoked?;
    then.status(200)?;
    machine_then.status(200)?;
    let list = membership(&machine_then, &first["network"]["key"])?;
    anyhow::ensure!(list.epoch > epoch && list.members.len() == 1, "{list:?}");
    anyhow::ensure!(
        started.elapsed() < std::time::Duration::from_secs(8),
        "the answer came when membership changed, not at the end of the wait: {:?}",
        started.elapsed()
    );
    Ok(())
}

async fn relayed_endpoint(relay: &str, key: &SigningKey) -> anyhow::Result<iroh::Endpoint> {
    relayed_endpoint_trusting(relay, key, None).await
}

pub(super) async fn relayed_endpoint_trusting(
    relay: &str,
    key: &SigningKey,
    roots: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
) -> anyhow::Result<iroh::Endpoint> {
    let config = grund_net::endpoint::NetConfig {
        relays: vec![relay.parse::<iroh::RelayUrl>()?],
        bind: grund_net::endpoint::Bind::Addrs(vec!["127.0.0.1:0".parse()?]),
        relay_roots: roots,
        ..Default::default()
    };
    grund_net::endpoint::bind(grund_net::key::secret_key(&key.to_bytes()), &config, vec![]).await
}

pub(super) fn relay_connected(endpoint: &iroh::Endpoint) -> bool {
    use iroh::Watcher;
    endpoint
        .home_relay_status()
        .get()
        .iter()
        .any(|status| status.is_connected())
}

async fn comes_online_through(relay: &str, key: &SigningKey) -> anyhow::Result<bool> {
    comes_online_trusting(relay, key, None).await
}

pub(super) async fn comes_online_trusting(
    relay: &str,
    key: &SigningKey,
    roots: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
) -> anyhow::Result<bool> {
    let endpoint = relayed_endpoint_trusting(relay, key, roots).await?;
    let online = tokio::time::timeout(std::time::Duration::from_secs(1), endpoint.online())
        .await
        .is_ok();
    endpoint.close().await;
    Ok(online)
}

#[tokio::test]
async fn the_relay_admits_only_registered_machines_that_are_not_revoked() -> anyhow::Result<()> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let relay = format!("http://127.0.0.1:{port}");
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_RELAY_ADDRESS", &format!("127.0.0.1:{port}")),
        ("GRUND_RELAY_URL", &relay),
    ])
    .await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (key, enrolled) = a_member(&when, &then, &owner.username, "relayed").await?;
    anyhow::ensure!(
        enrolled["network"]["relayUrls"] == json!([relay]),
        "{enrolled}"
    );

    anyhow::ensure!(
        comes_online_through(&relay, &key).await?,
        "a registered machine is admitted"
    );
    anyhow::ensure!(
        !comes_online_through(&relay, &a_machine_key()).await?,
        "a key grund does not know is refused"
    );

    let held = relayed_endpoint(&relay, &key).await?;
    anyhow::ensure!(
        relay_connected(&held),
        "the machine holds a relay connection"
    );
    when.calling(
        &format!("{MACHINES}/RevokeMachine"),
        &json!({"organisation": owner.username, "machineId": enrolled["machineId"]}).to_string(),
    )
    .await?;
    then.status(200)?;
    let revoked = std::time::Instant::now();
    while relay_connected(&held) {
        anyhow::ensure!(
            revoked.elapsed() < std::time::Duration::from_secs(8),
            "the relay cuts a connection admitted before the revocation"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    held.close().await;
    anyhow::ensure!(
        !comes_online_through(&relay, &key).await?,
        "a revoked machine is refused from its next connection"
    );
    Ok(())
}

#[tokio::test]
async fn the_machines_page_offers_the_configured_installer_and_vm_image() -> anyhow::Result<()> {
    let kernel_sha = "a".repeat(64);
    let rootfs_sha = "b".repeat(64);
    let Some((given, when, then)) = testcase_configured(&[
        (
            "GRUND_AGENT_INSTALL_URL",
            "https://example.accept.test/install.sh",
        ),
        ("GRUND_VM_KERNEL_URL", "https://images.accept.test/vmlinux"),
        ("GRUND_VM_KERNEL_SHA256", &kernel_sha),
        (
            "GRUND_VM_ROOTFS_URL",
            "https://images.accept.test/guest.ext4",
        ),
        ("GRUND_VM_ROOTFS_SHA256", &rootfs_sha),
    ])
    .await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let page = format!("/{}/machines", owner.username);

    when.submitting(&page, &format!("{page}/add"), &[("name", "desk")])
        .await?;
    let body = then.status(200)?.body()?.replace("&#x2f;", "/");
    let expected = format!(
        "curl -fsSL https://example.accept.test/install.sh | sudo sh -s -- --url {} --code grund_join_",
        origin(&when)
    );
    anyhow::ensure!(body.contains(&expected), "{body}");

    let token = body
        .split("--code ")
        .nth(1)
        .and_then(|rest| rest.split('<').next())
        .unwrap_or_default()
        .to_string();
    let device = join_dir();
    let joined = grund_join(&device, &["--url", &origin(&when), &token], &[]).await;
    anyhow::ensure!(
        joined.status.success(),
        "{}",
        String::from_utf8_lossy(&joined.stderr)
    );
    grund_agent_once(&device).await;
    when.visiting(&page).await?;
    then.status(200)?
        .body_contains(&format!("value=\"{kernel_sha}\""))?
        .body_contains(&format!("value=\"{rootfs_sha}\""))?;
    let body = then.body()?.replace("&#x2f;", "/");
    anyhow::ensure!(
        body.contains("value=\"https://images.accept.test/guest.ext4\""),
        "{body}"
    );
    std::fs::remove_dir_all(device)?;
    Ok(())
}

#[tokio::test]
async fn an_instance_serving_its_installer_hands_out_its_script_and_its_own_binary()
-> anyhow::Result<()> {
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_SERVE_INSTALLER", "true")]).await?
    else {
        return Ok(());
    };
    when.visiting("/install").await?;
    then.status(200)?
        .header("content-type", "text/x-shellscript; charset=utf-8")?
        .header("cache-control", "no-cache")?;
    anyhow::ensure!(
        then.body()? == include_str!("../../../grund-agent/install.sh"),
        "/install is not the install.sh this binary was built with"
    );

    let name = format!("grund-{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let executable = std::path::Path::new(crate::accepttest::fixtures::grund_binary());
    let expected = {
        let path = executable.to_path_buf();
        tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
            let mut file = std::fs::File::open(path)?;
            let mut hasher = Sha256::new();
            std::io::copy(&mut file, &mut hasher)?;
            Ok(hex::encode(hasher.finalize()))
        })
        .await??
    };
    when.visiting(&format!("/install/{name}.sha256")).await?;
    then.status(200)?;
    anyhow::ensure!(
        then.body()? == format!("{expected}\n"),
        "the served SHA-256 is not the running binary's"
    );
    when.requesting("HEAD", &format!("/install/{name}")).await?;
    then.status(200)?
        .header("content-type", "application/octet-stream")?
        .header(
            "content-length",
            &std::fs::metadata(executable)?.len().to_string(),
        )?;
    when.visiting("/install/grund-plan9-mips").await?;
    then.status(404)?;

    let owner = given.a_signed_in_account().await?;
    let page = format!("/{}/machines", owner.username);
    when.submitting(&page, &format!("{page}/add"), &[("name", "desk")])
        .await?;
    let body = then.status(200)?.body()?.replace("&#x2f;", "/");
    let origin = origin(&when);
    let offered =
        format!("curl -fsSL {origin}/install | sudo sh -s -- --url {origin} --code grund_join_");
    anyhow::ensure!(
        body.contains(&offered) && body.contains(" --from-instance"),
        "{body}"
    );
    Ok(())
}

#[tokio::test]
async fn an_instance_serves_no_installer_unless_told_to() -> anyhow::Result<()> {
    let (_, when, then) = crate::accepttest::fixtures::testcase().await?;
    when.visiting("/install").await?;
    then.status_in(&[303, 404])?.body_lacks("#!/bin/sh")?;
    when.visiting(&format!(
        "/install/grund-{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ))
    .await?;
    then.status_in(&[303, 404])?
        .header_lacks("content-type", "application/octet-stream")?;
    Ok(())
}

pub(super) struct Running(pub(super) std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct RelayCertificate {
    ca: rustls::pki_types::CertificateDer<'static>,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

fn a_relay_certificate(dir: &std::path::Path) -> anyhow::Result<RelayCertificate> {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate()?)?;
    let mut leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])?;
    leaf.is_ca = rcgen::IsCa::ExplicitNoCa;
    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = rcgen::KeyPair::generate()?;
    let leaf = leaf.signed_by(&leaf_key, &ca)?;
    std::fs::create_dir_all(dir)?;
    let (cert, key) = (dir.join("relay.crt"), dir.join("relay.key"));
    std::fs::write(&cert, leaf.pem())?;
    std::fs::write(&key, leaf_key.serialize_pem())?;
    Ok(RelayCertificate {
        ca: ca.der().clone(),
        cert,
        key,
    })
}

fn free_port() -> anyhow::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

const RELAY_TOKEN: &str = "relay-token-0123456789abcdef01234567";

#[tokio::test]
async fn a_relay_on_its_own_admits_only_what_grund_answers_and_cuts_a_revoked_machine()
-> anyhow::Result<()> {
    let port = free_port()?;
    let relay = format!("https://127.0.0.1:{port}");
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_RELAYS", &format!("lab={relay}")),
        ("GRUND_RELAY_ACCESS_TOKEN", RELAY_TOKEN),
    ])
    .await?
    else {
        return Ok(());
    };
    let certificate = a_relay_certificate(&join_dir())?;
    let log = std::fs::File::create(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("grund-relay-{port}.log")),
    )?;
    let _relay = Running(
        std::process::Command::new(crate::accepttest::fixtures::grund_binary())
            .arg("relay")
            .args(["--listen", &format!("127.0.0.1:{port}")])
            .args(["--quic-listen", &format!("127.0.0.1:{}", free_port()?)])
            .arg("--tls-cert-file")
            .arg(&certificate.cert)
            .arg("--tls-key-file")
            .arg(&certificate.key)
            .args(["--grund-url", &origin(&when), "--access-token", RELAY_TOKEN])
            .env_clear()
            .env("RUST_LOG", "grund_server=debug,info")
            .stdout(std::process::Stdio::from(log.try_clone()?))
            .stderr(std::process::Stdio::from(log))
            .spawn()?,
    );
    let owner = given.a_signed_in_account().await?;
    let (key, enrolled) = a_member(&when, &then, &owner.username, "relayed").await?;
    anyhow::ensure!(
        enrolled["network"]["relayUrls"] == json!([relay]),
        "machines are told the relay from GRUND_RELAYS: {enrolled}"
    );
    let machine_id = enrolled["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    signed_agent_call(
        &when,
        &machine_id,
        &key,
        "GetMembership",
        r#"{"sinceEpoch": "0"}"#,
    )
    .await?;
    then.status(200)?;
    let list = membership(&then, &enrolled["network"]["key"])?;
    anyhow::ensure!(
        list.relays
            == vec![grund_net::membership::Relay {
                url: relay.clone(),
                region: Some("lab".into())
            }],
        "the signed list names the relay: {list:?}"
    );

    let roots = Some(vec![certificate.ca.clone()]);
    let mut admitted = false;
    for _ in 0..20 {
        if comes_online_trusting(&relay, &key, roots.clone()).await? {
            admitted = true;
            break;
        }
    }
    anyhow::ensure!(
        admitted,
        "a registered machine is admitted by the relay on its own"
    );
    anyhow::ensure!(
        !comes_online_trusting(&relay, &a_machine_key(), roots.clone()).await?,
        "a key grund does not know is refused"
    );

    let held = relayed_endpoint_trusting(&relay, &key, roots.clone()).await?;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), held.online()).await;
    anyhow::ensure!(
        relay_connected(&held),
        "the machine holds a relay connection"
    );
    when.calling(
        &format!("{MACHINES}/RevokeMachine"),
        &json!({"organisation": owner.username, "machineId": machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    let revoked = std::time::Instant::now();
    while relay_connected(&held) {
        anyhow::ensure!(
            revoked.elapsed() < std::time::Duration::from_secs(8),
            "the relay on its own cuts a connection admitted before the revocation"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    held.close().await;
    anyhow::ensure!(
        !comes_online_trusting(&relay, &key, roots).await?,
        "a revoked machine is refused from its next connection"
    );
    Ok(())
}

#[tokio::test]
async fn the_access_check_needs_the_relay_token_and_answers_as_iroh_relay_expects()
-> anyhow::Result<()> {
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_RELAY_ACCESS_TOKEN", RELAY_TOKEN)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (key, _) = a_member(&when, &then, &owner.username, "checked").await?;
    let member = endpoint(&key);
    let stranger = endpoint(&a_machine_key());
    let bearer = format!("Bearer {RELAY_TOKEN}");

    for token in ["Bearer wrong-token-0123456789abcdef0123456", ""] {
        when.requesting_with(
            "POST",
            "/relay/v1/access",
            &[("Authorization", token), ("X-Iroh-NodeId", &member)],
            None,
        )
        .await?;
        then.status(401)?;
    }
    when.requesting_with(
        "POST",
        "/relay/v1/access",
        &[("Authorization", &bearer), ("X-Iroh-NodeId", &member)],
        None,
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        then.body()? == "true",
        "iroh-relay admits only on the body true"
    );
    when.requesting_with(
        "POST",
        "/relay/v1/access",
        &[("Authorization", &bearer), ("X-Iroh-NodeId", &stranger)],
        None,
    )
    .await?;
    then.status(403)?;

    let body = json!({"keys": [member, stranger]}).to_string();
    when.requesting_with(
        "POST",
        "/relay/v1/access/current",
        &[
            ("Authorization", &bearer),
            ("Content-Type", "application/json"),
        ],
        Some(body.as_bytes()),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        then.json()? == json!({"admitted": [member]}),
        "{}",
        then.body()?
    );
    let too_many = json!({"keys": vec![stranger.clone(); 201]}).to_string();
    when.requesting_with(
        "POST",
        "/relay/v1/access/current",
        &[
            ("Authorization", &bearer),
            ("Content-Type", "application/json"),
        ],
        Some(too_many.as_bytes()),
    )
    .await?;
    then.status_in(&[400, 413])?;
    Ok(())
}

#[tokio::test]
async fn without_a_relay_token_there_is_no_access_check() -> anyhow::Result<()> {
    let Some((_, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    when.requesting_with(
        "POST",
        "/relay/v1/access",
        &[
            ("Authorization", "Bearer anything"),
            ("X-Iroh-NodeId", &endpoint(&a_machine_key())),
        ],
        None,
    )
    .await?;
    then.status(404)?;
    Ok(())
}

#[tokio::test]
async fn declared_ports_reach_the_signed_list_and_only_the_owning_organisation_declares_them()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (key, enrolled) = a_member(&when, &then, &owner.username, "db-1").await?;
    let machine_id = enrolled["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let declare = |organisation: &str, ports: Value| {
        json!({"organisation": organisation, "machineId": machine_id, "ports": ports}).to_string()
    };
    let procedure = format!("{MACHINES}/DeclareMachinePorts");

    when.calling(
        &procedure,
        &declare(
            &owner.username,
            json!([
                {"transport": "NETWORK_TRANSPORT_TCP", "port": 5432},
                {"transport": "NETWORK_TRANSPORT_TCP", "port": 22},
                {"transport": "NETWORK_TRANSPORT_UDP", "port": 5432},
                {"transport": "NETWORK_TRANSPORT_TCP", "port": 22},
            ]),
        ),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["machine"]["networkPorts"]
            == json!([
                {"transport": "NETWORK_TRANSPORT_TCP", "port": 22},
                {"transport": "NETWORK_TRANSPORT_TCP", "port": 5432},
                {"transport": "NETWORK_TRANSPORT_UDP", "port": 5432},
            ]),
        "sorted, once each: {}",
        then.body()?
    );
    signed_agent_call(
        &when,
        &machine_id,
        &key,
        "GetMembership",
        r#"{"sinceEpoch": "0"}"#,
    )
    .await?;
    then.status(200)?;
    let list = membership(&then, &enrolled["network"]["key"])?;
    let ports: Vec<(grund_net::membership::Transport, u16)> = list
        .members
        .iter()
        .find(|m| m.machine_id == machine_id)
        .map(|m| m.ports.iter().map(|p| (p.transport, p.port)).collect())
        .unwrap_or_default();
    use grund_net::membership::Transport::{Tcp, Udp};
    anyhow::ensure!(
        ports == vec![(Tcp, 22), (Tcp, 5432), (Udp, 5432)],
        "the signed list carries the declared ports: {list:?}"
    );

    for bad in [
        json!([{"transport": "NETWORK_TRANSPORT_TCP", "port": 0}]),
        json!([{"transport": "NETWORK_TRANSPORT_TCP", "port": 70000}]),
        json!([{"transport": "NETWORK_TRANSPORT_UNSPECIFIED", "port": 22}]),
        json!(
            (1..=65)
                .map(|p| json!({"transport": "NETWORK_TRANSPORT_TCP", "port": p}))
                .collect::<Vec<_>>()
        ),
    ] {
        when.calling(&procedure, &declare(&owner.username, bad.clone()))
            .await?;
        then.status(400)?;
    }

    let (intruder_given, intruder_when, intruder_then) = given.testcase.another_browser();
    let intruder = intruder_given.a_signed_in_account().await?;
    intruder_when
        .calling(&procedure, &declare(&intruder.username, json!([])))
        .await?;
    intruder_then.status(404)?;
    intruder_when
        .calling(&procedure, &declare(&owner.username, json!([])))
        .await?;
    intruder_then.status_in(&[403, 404])?;

    when.calling(&procedure, &declare(&owner.username, json!([])))
        .await?;
    then.status(200)?;
    anyhow::ensure!(
        json(&then)?["machine"]["networkPorts"]
            .as_array()
            .is_none_or(|a| a.is_empty()),
        "{}",
        then.body()?
    );
    Ok(())
}

#[tokio::test]
async fn a_members_reported_home_relay_goes_into_the_list_only_when_it_is_one_of_grunds()
-> anyhow::Result<()> {
    let relay = "https://relay-1.example.com";
    let Some((given, when, then)) = testcase_configured(&[("GRUND_RELAYS", relay)]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (key, enrolled) = a_member(&when, &then, &owner.username, "hinted").await?;
    let machine_id = enrolled["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let hint_after = |reported: &str| {
        let (when, then, key, machine_id, network_key) = (
            &when,
            &then,
            &key,
            machine_id.clone(),
            enrolled["network"]["key"].clone(),
        );
        let body = json!({"sinceEpoch": "0", "homeRelayUrl": reported}).to_string();
        async move {
            signed_agent_call(when, &machine_id, key, "GetMembership", &body).await?;
            then.status(200)?;
            let list = membership(then, &network_key)?;
            Ok::<_, anyhow::Error>(
                list.members
                    .iter()
                    .find(|m| m.machine_id == machine_id)
                    .and_then(|m| m.relay_url.clone()),
            )
        }
    };
    anyhow::ensure!(hint_after("").await?.is_none());
    anyhow::ensure!(
        hint_after(&format!("{relay}/")).await? == Some(relay.to_string()),
        "a reported home relay that is grund's goes into the list"
    );
    anyhow::ensure!(
        hint_after("https://evil.example.com/").await? == Some(relay.to_string()),
        "a relay grund does not run is ignored"
    );
    anyhow::ensure!(hint_after("").await?.is_none(), "reporting none clears it");
    Ok(())
}
