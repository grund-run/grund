use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::accepttest::fixtures::{Given, Then, When, testcase_configured, testcase_with_mail};

const ENROLL: &str = "/grund.agent.v1.MachineEnrollmentService/EnrollMachine";
const POOL: &str = "/grund.machine.v1.ManagementPoolService";
const MACHINES: &str = "/grund.machine.v1.MachineService";

fn a_machine_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("randomness");
    SigningKey::from_bytes(&seed)
}

fn origin(when: &When) -> String {
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
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_grund"));
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
