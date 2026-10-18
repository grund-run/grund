use std::time::Duration;

use crate::accepttest::fixtures::{Given, mail_count, testcase_configured};

const SINGLE: &[(&str, &str)] = &[("GRUND_ORGANISATIONS", "single")];
const ACCOUNTS: &str = "SELECT count(*) FROM grund_accounts";

struct LocalDescriptor {
    path: std::path::PathBuf,
    machine_id: uuid::Uuid,
    public_key: String,
}

impl LocalDescriptor {
    fn new() -> anyhow::Result<Self> {
        let machine_id = uuid::Uuid::now_v7();
        let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
        let public_key = hex::encode(key.verifying_key().as_bytes());
        let path = std::env::temp_dir().join(format!("grund-local-{machine_id}.json"));
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "machine_id": machine_id,
                "name": "first-host",
                "key": public_key,
                "facts": {
                    "hostname": "actual-install-host", "arch": "x86_64", "cpu_model": "host-cpu",
                    "cpus": 4, "memory_mib": 8192, "disk_gib": 80, "os": "Debian",
                    "kernel": "linux", "agent_version": env!("CARGO_PKG_VERSION"),
                    "fleet_machine_id": ""
                }
            }))?,
        )?;
        Ok(Self {
            path,
            machine_id,
            public_key,
        })
    }
}

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[tokio::test]
async fn claiming_the_owner_atomically_registers_and_recovers_the_first_local_machine()
-> anyhow::Result<()> {
    let descriptor = LocalDescriptor::new()?;
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_ORGANISATIONS", "single"),
        (
            "GRUND_LOCAL_MACHINE_FILE",
            descriptor.path.to_str().unwrap(),
        ),
        ("RUST_LOG", "sqlx=debug"),
    ])
    .await?
    else {
        return Ok(());
    };
    let pending = given.testcase.fixture.running(&["local-machine"]).await?;
    anyhow::ensure!(pending.success && pending.stdout.trim() == "null");
    let older = given.testcase.fixture.setup_link().await?;
    let link = given.testcase.fixture.setup_link().await?;
    let owner = given.a_fresh_name("localowner");
    anyhow::ensure!(
        posting_the_owner_form(&given, &older, &owner, "a long enough password here").await? == 200
    );
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_machines")
            .await?
            == 0
    );
    anyhow::ensure!(
        posting_the_owner_form(&given, &link, &owner, "a long enough password here").await? == 303
    );
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_machines")
            .await?
            == 1
    );
    anyhow::ensure!(given.testcase.fixture.count(&format!(
        "SELECT count(*) FROM grund_machines m JOIN grund_accounts a ON a.organisation_id = m.home_organisation_id \
         WHERE m.machine_id = '{}' AND m.public_key = '{}' AND m.pool = 'organisation' AND m.state = 'active' \
         AND m.name = 'first-host' AND m.facts->>'hostname' = 'actual-install-host'",
        descriptor.machine_id, descriptor.public_key
    )).await? == 1);
    let ready = given.testcase.fixture.running(&["local-machine"]).await?;
    anyhow::ensure!(ready.success, "local recovery failed");
    let response: grund_proto::grund::agent::v1::EnrollMachineResponse =
        serde_json::from_str(&ready.stdout)?;
    anyhow::ensure!(response.machine_id == descriptor.machine_id.to_string());
    anyhow::ensure!(
        response.pool.as_known() == Some(grund_proto::grund::agent::v1::Pool::POOL_ORGANISATION)
    );
    anyhow::ensure!(
        response.instance_key.as_option().is_some()
            && response.trust_key.as_option().is_some()
            && response.network.as_option().is_some()
    );
    let network = response.network.as_option().unwrap();
    anyhow::ensure!(network.slot > 0 && network.key.as_option().is_some());
    let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
    super::machines::signed_agent_call(&when, &response.machine_id, &key, "Heartbeat", "{}")
        .await?;
    then.status(200)?;
    super::machines::signed_agent_call(
        &when,
        &response.machine_id,
        &key,
        "GetMembership",
        r#"{"sinceEpoch":"0"}"#,
    )
    .await?;
    then.status(200)?;
    use base64::Engine;
    let membership = then.json()?;
    let signed = grund_net::membership::SignedList {
        body: base64::engine::general_purpose::STANDARD
            .decode(membership["list"]["body"].as_str().unwrap_or_default())?,
        signature: base64::engine::general_purpose::STANDARD
            .decode(membership["list"]["signature"].as_str().unwrap_or_default())?,
    };
    let pinned: [u8; 32] = network
        .key
        .as_option()
        .unwrap()
        .public_key
        .as_slice()
        .try_into()?;
    let list = signed.verify(&ed25519_dalek::VerifyingKey::from_bytes(&pinned)?)?;
    anyhow::ensure!(
        list.member_by_name("first-host").map(|member| member.slot) == Some(network.slot as u16)
    );
    given.testcase.fixture.sql("DELETE FROM grund_machine_tokens; UPDATE grund_setup_links SET created_at = clock_timestamp() - interval '2 years', expires_at = clock_timestamp() - interval '1 year'").await?;
    let recovered = given.testcase.fixture.running(&["local-machine"]).await?;
    anyhow::ensure!(recovered.success);
    let again: grund_proto::grund::agent::v1::EnrollMachineResponse =
        serde_json::from_str(&recovered.stdout)?;
    anyhow::ensure!(
        again == response,
        "a lost reply changed the registered identity"
    );
    given
        .testcase
        .fixture
        .sql(&format!(
            "UPDATE grund_machines SET public_key = '{}' WHERE machine_id = '{}'",
            hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                    .verifying_key()
                    .as_bytes()
            ),
            descriptor.machine_id
        ))
        .await?;
    anyhow::ensure!(
        !given
            .testcase
            .fixture
            .running(&["local-machine"])
            .await?
            .success
    );
    given.testcase.fixture.sql(&format!("UPDATE grund_machines SET public_key = '{}', home_organisation_id = '{}' WHERE machine_id = '{}'",
        descriptor.public_key, uuid::Uuid::now_v7(), descriptor.machine_id)).await?;
    anyhow::ensure!(
        !given
            .testcase
            .fixture
            .running(&["local-machine"])
            .await?
            .success
    );
    given
        .testcase
        .fixture
        .sql(&format!(
            "UPDATE grund_machines SET home_organisation_id = '{}' WHERE machine_id = '{}'",
            response.organisation_id, descriptor.machine_id
        ))
        .await?;
    when.calling(
        "/grund.machine.v1.MachineService/RevokeMachine",
        &serde_json::json!({"organisation": owner, "machineId": response.machine_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    let refused = given.testcase.fixture.running(&["local-machine"]).await?;
    anyhow::ensure!(!refused.success && refused.code == Some(78));
    super::machines::signed_agent_call(&when, &response.machine_id, &key, "Heartbeat", "{}")
        .await?;
    then.status(401)?;
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_machines")
            .await?
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn a_local_registration_conflict_cannot_commit_the_owner_or_consume_the_setup_link()
-> anyhow::Result<()> {
    let descriptor = LocalDescriptor::new()?;
    let Some((given, _, _)) = testcase_configured(&[
        ("GRUND_ORGANISATIONS", "single"),
        (
            "GRUND_LOCAL_MACHINE_FILE",
            descriptor.path.to_str().unwrap(),
        ),
    ])
    .await?
    else {
        return Ok(());
    };
    given.testcase.fixture.sql(&format!(
        "INSERT INTO grund_machines (machine_id, pool, name, state, public_key, minted_by, registered_at, key_registered_at, stream_version) \
         VALUES ('{}', 'management', 'conflict', 'available', '{}', 'test', clock_timestamp(), clock_timestamp(), 1)",
        uuid::Uuid::now_v7(), descriptor.public_key
    )).await?;
    let link = given.testcase.fixture.setup_link().await?;
    let status = posting_the_owner_form(
        &given,
        &link,
        &given.a_fresh_name("conflict"),
        "a long enough password here",
    )
    .await?;
    anyhow::ensure!(status != 303);
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 0);
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_organisations")
            .await?
            == 0
    );
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_setup_links WHERE used_at IS NULL")
            .await?
            == 1
    );
    Ok(())
}

fn token_of(link: &str) -> String {
    link.split_once("token=")
        .map(|(_, token)| token.to_string())
        .unwrap_or_default()
}

async fn posting_the_owner_form(
    given: &Given,
    link: &str,
    username: &str,
    password: &str,
) -> anyhow::Result<u16> {
    let when = crate::accepttest::fixtures::When {
        testcase: given.testcase.clone(),
    };
    when.visiting(link).await?;
    let has_form = given
        .testcase
        .data()
        .last
        .as_ref()
        .is_some_and(|page| page.text().contains("name=\"csrf\""));
    if !has_form {
        when.visiting("/login").await?;
    }
    when.submitting_on_current_page(
        "/signup/owner",
        &[
            ("token", &token_of(link)),
            ("username", username),
            ("email", &format!("{username}@accept.test")),
            ("password", password),
        ],
    )
    .await?;
    let status = given.testcase.data().last.as_ref().map_or(0, |r| r.status);
    Ok(status)
}

#[tokio::test]
async fn a_setup_link_creates_the_signed_in_owner_and_sends_no_mail() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    when.visiting("/signup").await?;
    then.status(403)?
        .body_contains("no owner yet")?
        .body_contains("setup-link")?;

    let ran = given.testcase.fixture.running(&["setup-link"]).await?;
    anyhow::ensure!(ran.success, "{}", ran.stderr);
    let link = ran.setup_link_path().expect("a link");
    anyhow::ensure!(
        ran.stdout.matches("grund_setup_").count() == 1,
        "the link was not printed exactly once"
    );
    when.visiting(&link).await?;
    then.status(200)?
        .header("referrer-policy", "same-origin")?
        .header_contains("cache-control", "no-store")?
        .header_contains("cache-control", "no-transform")?
        .body_contains("Create the owner")?;
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 0);

    let owner = given.a_fresh_name("owner");
    let password = "a long enough password here";
    let status = posting_the_owner_form(&given, &link, &owner, password).await?;
    anyhow::ensure!(status == 303, "the owner form answered {status}");
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_machines")
            .await?
            == 0,
        "an install without a local descriptor must not register a machine"
    );
    then.redirects_to(&format!("/{owner}"))?;
    when.visiting_home().await?;
    then.status(200)?.body_contains(&format!(
        "<span class=\"org-switch-name\">{owner}</span><span class=\"org-switch-role\">Owner</span>"
    ))?;

    when.submitting(&format!("/{owner}"), "/logout", &[])
        .await?;
    when.signing_in(&owner, password).await?;
    then.status(303)?;

    tokio::time::sleep(Duration::from_secs(3)).await;
    anyhow::ensure!(
        mail_count(&given, &format!("{owner}@accept.test")).await? == 0,
        "the owner was mailed"
    );
    let token = token_of(&link);
    anyhow::ensure!(
        !given.testcase.fixture.log().contains(&token),
        "grund's log carries the setup link"
    );
    anyhow::ensure!(
        !ran.stderr.contains(&token),
        "the command's standard error carries the setup link"
    );
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_setup_links WHERE used_at IS NOT NULL AND account_id IS NOT NULL")
            .await?
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn a_setup_link_works_once() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    let status = posting_the_owner_form(
        &given,
        &link,
        &given.a_fresh_name("owner"),
        "a long enough password here",
    )
    .await?;
    anyhow::ensure!(status == 303, "the first use answered {status}");

    let (stranger, stranger_when, stranger_then) = given.testcase.another_browser();
    stranger_when.visiting(&link).await?;
    stranger_then.status(200)?.body_contains("expired")?;
    let status = posting_the_owner_form(
        &stranger,
        &link,
        &stranger.a_fresh_name("second"),
        "a long enough password here",
    )
    .await?;
    anyhow::ensure!(status == 200, "the second use answered {status}");
    stranger_then
        .body_contains("expired")?
        .sets_no_session_cookie()?;
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 1);
    Ok(())
}

#[tokio::test]
async fn an_expired_setup_link_creates_nothing() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    when.visiting(&link).await?;
    then.status(200)?.body_contains("Create the owner")?;
    let changed = given
        .testcase
        .fixture
        .sql(
            "UPDATE grund_setup_links SET created_at = clock_timestamp() - interval '2 hours', \
             expires_at = clock_timestamp() - interval '1 hour'",
        )
        .await?;
    anyhow::ensure!(changed == 1);
    when.submitting_on_current_page(
        "/signup/owner",
        &[
            ("token", &token_of(&link)),
            ("username", &given.a_fresh_name("late")),
            ("email", "late@accept.test"),
            ("password", "a long enough password here"),
        ],
    )
    .await?;
    then.status(200)?
        .body_contains("expired")?
        .sets_no_session_cookie()?;
    when.visiting(&link).await?;
    then.body_contains("expired")?;
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 0);
    Ok(())
}

#[tokio::test]
async fn two_posts_of_one_setup_link_at_once_make_one_owner() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    let (first, _, _) = given.testcase.another_browser();
    let (second, _, _) = given.testcase.another_browser();
    let password = "a long enough password here";
    let (one, two) = (first.a_fresh_name("racer"), second.a_fresh_name("racer"));
    let (a, b) = tokio::join!(
        posting_the_owner_form(&first, &link, &one, password),
        posting_the_owner_form(&second, &link, &two, password),
    );
    let mut statuses = [a?, b?];
    statuses.sort_unstable();
    anyhow::ensure!(
        statuses == [200, 303],
        "one post creates the owner and the other finds the link used: {statuses:?}"
    );
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 1);
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_organisations")
            .await?
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn no_setup_link_is_minted_once_the_instance_has_an_account() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    given.the_owner().await?;
    let ran = given.testcase.fixture.running(&["setup-link"]).await?;
    anyhow::ensure!(
        !ran.success,
        "setup-link succeeded after an account existed"
    );
    anyhow::ensure!(
        ran.stderr.contains("already has an account"),
        "{}",
        ran.stderr
    );
    anyhow::ensure!(
        !ran.stdout.contains("grund_setup_"),
        "a setup URL was emitted"
    );
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_setup_links WHERE used_at IS NULL")
            .await?
            == 0
    );
    Ok(())
}

#[tokio::test]
async fn a_newer_setup_link_retires_the_older_one() -> anyhow::Result<()> {
    let Some((given, _when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let older = given.testcase.fixture.setup_link().await?;
    let newer = given.testcase.fixture.setup_link().await?;
    anyhow::ensure!(older != newer);
    let password = "a long enough password here";
    let status =
        posting_the_owner_form(&given, &older, &given.a_fresh_name("old"), password).await?;
    anyhow::ensure!(status == 200, "the older link answered {status}");
    then.body_contains("expired")?;
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 0);
    let status =
        posting_the_owner_form(&given, &newer, &given.a_fresh_name("new"), password).await?;
    anyhow::ensure!(status == 303, "the newer link answered {status}");
    Ok(())
}

#[tokio::test]
async fn a_setup_link_does_not_work_on_another_instance() -> anyhow::Result<()> {
    let Some((given, _when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let Some((elsewhere, _, elsewhere_then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    let password = "a long enough password here";
    let status = posting_the_owner_form(
        &elsewhere,
        &link,
        &elsewhere.a_fresh_name("thief"),
        password,
    )
    .await?;
    anyhow::ensure!(status == 200, "another instance answered {status}");
    elsewhere_then
        .body_contains("expired")?
        .sets_no_session_cookie()?;
    anyhow::ensure!(elsewhere.testcase.fixture.count(ACCOUNTS).await? == 0);

    let status =
        posting_the_owner_form(&given, &link, &given.a_fresh_name("owner"), password).await?;
    anyhow::ensure!(status == 303, "its own instance answered {status}");
    then.status(303)?;
    Ok(())
}

#[tokio::test]
async fn a_form_that_does_not_validate_keeps_the_setup_link() -> anyhow::Result<()> {
    let Some((given, _when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    for (username, password, message) in [
        ("admin", "a long enough password here", "reserved"),
        ("fine-name", "short", "12 characters"),
    ] {
        let status = posting_the_owner_form(&given, &link, username, password).await?;
        anyhow::ensure!(status == 422, "{username}: {status}");
        then.body_contains(message)?.sets_no_session_cookie()?;
    }
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 0);
    let status = posting_the_owner_form(
        &given,
        &link,
        &given.a_fresh_name("owner"),
        "a long enough password here",
    )
    .await?;
    anyhow::ensure!(status == 303, "{status}");
    Ok(())
}

#[tokio::test]
async fn a_multi_instance_requires_owner_setup_before_open_signup() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    when.visiting("/signup").await?;
    then.status(403)?.body_contains("no owner yet")?;
    let owner = given.the_owner().await?;
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_organisations WHERE slug = 'admin'")
            .await?
            == 1,
        "the setup link must create the reserved operator organisation"
    );
    when.calling(
        "/grund.organisation.v1.OrganisationService/DeleteOrganisation",
        r#"{"slug":"admin","confirmSlug":"admin"}"#,
    )
    .await?;
    then.status(400)?.connect_code("failed_precondition")?;
    when.calling(
        "/grund.organisation.v1.OrganisationService/RenameOrganisation",
        &serde_json::json!({"slug": "admin", "newSlug": given.a_fresh_name("away")}).to_string(),
    )
    .await?;
    then.status(400)?.connect_code("failed_precondition")?;
    when.visiting(&format!("/{}", owner.username)).await?;
    then.status(200)?;
    let (_, stranger_when, stranger_then) = given.testcase.another_browser();
    stranger_when.visiting("/signup").await?;
    stranger_then
        .status(200)?
        .body_contains("Create an account")?;
    Ok(())
}

#[tokio::test]
async fn closed_multi_signup_still_allows_the_owner_setup_link() -> anyhow::Result<()> {
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_SIGNUP_ENABLED", "false")]).await?
    else {
        return Ok(());
    };
    let owner = given.the_owner().await?;
    when.visiting(&format!("/{}", owner.username)).await?;
    then.status(200)?;
    let (_, visitor, visitor_result) = given.testcase.another_browser();
    visitor.visiting("/signup").await?;
    visitor_result.status(403)?.body_contains("invite-only")?;
    Ok(())
}

#[tokio::test]
async fn competing_multi_setup_requests_create_one_owner() -> anyhow::Result<()> {
    let Some((given, _, _)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    let (first, _, _) = given.testcase.another_browser();
    let (second, _, _) = given.testcase.another_browser();
    let first_name = first.a_fresh_name("first");
    let second_name = second.a_fresh_name("second");
    let (a, b) = tokio::join!(
        posting_the_owner_form(&first, &link, &first_name, "long enough password"),
        posting_the_owner_form(&second, &link, &second_name, "long enough password"),
    );
    let mut statuses = [a?, b?];
    statuses.sort_unstable();
    anyhow::ensure!(statuses == [200, 303], "setup race: {statuses:?}");
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 1);
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_organisations WHERE slug = 'admin'")
            .await?
            == 1
    );
    Ok(())
}
