use std::time::Duration;

use serde_json::{Value, json};

use crate::accepttest::{
    apps::{a_machine, call, live, quick, ready_on, reason, spec, until, uuid_like},
    fixtures::{FakeRegistry, random_hex, testcase_configured},
    machines::{device_key, signed_agent_call},
};

fn registries(org: &str) -> String {
    format!("/{org}/settings/registries")
}

#[tokio::test]
async fn a_private_image_deploys_and_runs_with_the_organisations_registry_credential()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let agent = a_machine(&when, &then, org, "box").await?;
    let password = format!("pw-{}", random_hex(12));
    registry.make_private("acme/secret", "robot", &password);
    let digest = registry.publish("acme/secret", "1");
    let image = registry.image("acme/secret", "1");
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "secret", "settings": quick(1)}),
    )
    .await?;
    then.status(200)?;
    let deploy = json!({"organisation": org, "name": "secret", "spec": spec(&image, json!([]))});

    let refused = call(&when, &then, "Deploy", deploy.clone()).await?;
    then.status(400)?;
    anyhow::ensure!(reason(&refused) == "image_unresolved", "{refused}");
    anyhow::ensure!(
        refused["message"]
            .as_str()
            .is_some_and(|m| m.contains(&format!(
                "set a credential for {} under Organisation, Registries",
                registry.host
            ))),
        "the refusal says where to set a credential: {refused}"
    );

    let page = registries(org);
    when.submitting(
        &page,
        &page,
        &[
            ("host", &registry.host),
            ("username", "robot"),
            ("password", "not-the-password"),
        ],
    )
    .await?;
    then.redirects_to(&format!("{page}?done=set"))?;
    let refused = call(&when, &then, "Deploy", deploy.clone()).await?;
    then.status(400)?;
    anyhow::ensure!(
        refused["message"]
            .as_str()
            .is_some_and(|m| m.contains("refused the credential")),
        "{refused}"
    );

    when.submitting(
        &page,
        &page,
        &[
            ("host", &format!("http://{}/", registry.host)),
            ("username", "robot"),
            ("password", &password),
        ],
    )
    .await?;
    then.redirects_to(&format!("{page}?done=set"))?;
    when.visiting(&page).await?;
    then.status(200)?
        .header("cache-control", "no-store")?
        .body_contains(&registry.host)?
        .body_contains("as robot")?
        .body_lacks(&password)?
        .body_lacks("not-the-password")?;

    let deployed = call(&when, &then, "Deploy", deploy.clone()).await?;
    then.status(200)?;
    anyhow::ensure!(
        deployed["release"]["imageDigest"] == digest.as_str(),
        "{deployed}"
    );
    until(
        &when,
        &then,
        org,
        "secret",
        Duration::from_secs(30),
        "the private image running",
        |a| live(a, 1) && ready_on(a, 1) == 1,
    )
    .await?;
    anyhow::ensure!(
        agent
            .dir
            .join("simulated-containers/images")
            .join(format!("{digest}.authorized"))
            .exists(),
        "the machine did not pull with the organisation's login"
    );
    anyhow::ensure!(
        registry.logins() >= 2,
        "both the instance and the machine log in: {}",
        registry.logins()
    );

    let fixture = &given.testcase.fixture;
    let agent_log = std::fs::read_to_string(agent.dir.join("agent.log")).unwrap_or_default();
    anyhow::ensure!(
        !fixture.log().contains(&password) && !agent_log.contains(&password),
        "a log carries the registry password"
    );
    anyhow::ensure!(
        fixture
            .count(&format!(
                "SELECT count(*) FROM grund_registry_credentials \
                 WHERE position(convert_to('{password}', 'UTF8') in sealed_password) > 0"
            ))
            .await?
            == 0,
        "the password is stored unsealed"
    );
    anyhow::ensure!(
        fixture
            .count(&format!(
                "SELECT count(*) FROM es_events \
                 WHERE data::text LIKE '%{password}%' OR metadata::text LIKE '%{password}%'"
            ))
            .await?
            == 0,
        "an event carries the registry password"
    );
    anyhow::ensure!(
        fixture
            .count(&format!(
                "SELECT count(*) FROM grund_machine_documents \
                 WHERE position(convert_to('{password}', 'UTF8') in payload) > 0"
            ))
            .await?
            == 0,
        "a signed document carries the registry password"
    );

    when.visiting(&page).await?;
    when.submitting_on_current_page(
        &format!("{page}/remove"),
        &[("host", registry.host.as_str())],
    )
    .await?;
    then.redirects_to(&format!("{page}?done=removed"))?;
    call(&when, &then, "Deploy", deploy).await?;
    then.status(400)?;
    Ok(())
}

#[tokio::test]
async fn another_account_can_neither_see_nor_change_a_credential_nor_have_one_handed_to_its_machine()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _agent = a_machine(&when, &then, org, "box").await?;
    let password = format!("pw-{}", random_hex(12));
    registry.make_private("acme/secret", "robot", &password);
    registry.publish("acme/secret", "1");
    let page = registries(org);
    when.submitting(
        &page,
        &page,
        &[
            ("host", &registry.host),
            ("username", "robot"),
            ("password", &password),
        ],
    )
    .await?;
    then.redirects_to(&format!("{page}?done=set"))?;
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "secret", "settings": quick(1)}),
    )
    .await?;
    call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "secret", "spec": spec(&registry.image("acme/secret", "1"), json!([]))}),
    )
    .await?;
    then.status(200)?;
    let running = until(
        &when,
        &then,
        org,
        "secret",
        Duration::from_secs(30),
        "the private image running",
        |a| live(a, 1),
    )
    .await?;
    let replica_id = running["replicas"][0]["replicaId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let (stranger_given, stranger, stranger_then) = given.testcase.another_browser();
    let stranger_account = stranger_given.a_signed_in_account().await?;
    let theirs = registries(&stranger_account.username);
    stranger.visiting(&page).await?;
    stranger_then.status(404)?.body_lacks("as robot")?;
    stranger.visiting(&theirs).await?;
    stranger_then
        .status(200)?
        .body_lacks(&registry.host)?
        .body_lacks("as robot")?;
    stranger
        .submitting_on_current_page(
            &page,
            &[
                ("host", &registry.host),
                ("username", "mallory"),
                ("password", "theirs"),
            ],
        )
        .await?;
    stranger_then.status(404)?;
    stranger.visiting(&theirs).await?;
    stranger
        .submitting_on_current_page(
            &format!("{page}/remove"),
            &[("host", registry.host.as_str())],
        )
        .await?;
    stranger_then.status(404)?;
    stranger.visiting(&theirs).await?;
    stranger
        .submitting_on_current_page(
            &format!("{theirs}/remove"),
            &[("host", registry.host.as_str())],
        )
        .await?;
    stranger_then.redirects_to(&format!("{theirs}?error=gone"))?;
    when.visiting(&page).await?;
    then.status(200)?.body_contains("as robot")?;

    let their_machine = a_machine(
        &stranger,
        &stranger_then,
        &stranger_account.username,
        "theirs",
    )
    .await?;
    let record: Value = serde_json::from_str(&std::fs::read_to_string(
        their_machine.dir.join("machine.json"),
    )?)?;
    let machine_id = record["machine_id"].as_str().unwrap_or_default();
    let key = device_key(&their_machine.dir)?;
    for replica in [replica_id.clone(), uuid_like()] {
        signed_agent_call(
            &stranger,
            machine_id,
            &key,
            "GetPullCredential",
            &json!({"replicaId": replica}).to_string(),
        )
        .await?;
        stranger_then.status(404)?.connect_code("not_found")?;
        stranger_then.body_lacks(&password)?;
    }
    stranger
        .calling(
            "/grund.agent.v1.AgentService/GetPullCredential",
            &json!({"replicaId": replica_id}).to_string(),
        )
        .await?;
    stranger_then.status(401)?.connect_code("unauthenticated")?;
    Ok(())
}

#[tokio::test]
async fn a_member_sees_logins_and_their_own_tokens_but_changes_neither_and_their_token_cannot_deploy()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let (guest, guest_when, guest_then) = given.testcase.another_browser();
    let member = guest.a_signed_in_account().await?;
    when.inviting(org, &member.email, "member").await?;
    let link = guest_when
        .the_mailed_link(
            &member.email,
            &format!("Join {org} on grund"),
            "/invite?token=",
        )
        .await?;
    guest_when.visiting(&link).await?;
    let token = guest.last_token()?;
    guest_when
        .submitting_on_current_page("/invite", &[("token", &token)])
        .await?;
    guest_then.redirects_to(&format!("/{org}"))?;

    let page = registries(org);
    when.submitting(
        &page,
        &page,
        &[
            ("host", &registry.host),
            ("username", "robot"),
            ("password", "pw-owner"),
        ],
    )
    .await?;
    then.redirects_to(&format!("{page}?done=set"))?;
    let tokens = format!("/{org}/settings/tokens");
    when.submitting(&tokens, &tokens, &[("name", "owners-ci"), ("days", "7")])
        .await?;
    then.status(200)?;

    guest_when.visiting(&page).await?;
    guest_then
        .status(200)?
        .body_contains("as robot")?
        .body_lacks("Save login")?;
    guest_when
        .submitting_on_current_page(
            &page,
            &[
                ("host", &registry.host),
                ("username", "mallory"),
                ("password", "pw-member"),
            ],
        )
        .await?;
    guest_then.status(403)?;
    guest_when.visiting(&page).await?;
    guest_when
        .submitting_on_current_page(
            &format!("{page}/remove"),
            &[("host", registry.host.as_str())],
        )
        .await?;
    guest_then.redirects_to(&format!("{page}?error=not-allowed"))?;
    when.visiting(&page).await?;
    then.body_contains("as robot")?.body_lacks("mallory")?;

    guest_when.visiting(&tokens).await?;
    guest_then.status(200)?.body_lacks("owners-ci")?;
    guest_when
        .submitting_on_current_page(&tokens, &[("name", "members-ci"), ("days", "7")])
        .await?;
    guest_then.status(200)?;
    let html = guest_then.body()?;
    let start = html
        .find("grund_pat_")
        .ok_or_else(|| anyhow::anyhow!("no token shown"))?;
    let member_token = html[start..start + "grund_pat_".len() + 43].to_string();
    when.visiting(&tokens).await?;
    then.body_contains("owners-ci")?
        .body_contains("members-ci")?;

    let (_, ci, ci_then) = given.testcase.another_browser();
    let bearer = format!("Bearer {member_token}");
    ci.calling_with(
        "/grund.app.v1.AppService/ListApps",
        &json!({"organisation": org}).to_string(),
        &[("Authorization", &bearer)],
    )
    .await?;
    ci_then.status(200)?;
    ci.calling_with(
        "/grund.app.v1.AppService/CreateApp",
        &json!({"organisation": org, "name": "nope"}).to_string(),
        &[("Authorization", &bearer)],
    )
    .await?;
    ci_then.status(403)?.connect_code("permission_denied")?;
    Ok(())
}
