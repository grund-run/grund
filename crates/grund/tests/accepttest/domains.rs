use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::accepttest::{
    fixtures::{Then, When, random_hex},
    traffic::{Stack, a_stack_with},
};

const DOMAINS: &str = "/grund.domain.v1.DomainService";

async fn domain_call(
    when: &When,
    then: &Then,
    procedure: &str,
    body: Value,
) -> anyhow::Result<(u16, Value)> {
    when.calling(&format!("{DOMAINS}/{procedure}"), &body.to_string())
        .await?;
    let status = (200..600)
        .find(|code| then.status(*code).is_ok())
        .unwrap_or(0);
    Ok((status, then.json().unwrap_or_default()))
}

fn domain_reason(error: &Value) -> String {
    use base64::Engine;
    error["details"]
        .as_array()
        .and_then(|d| {
            d.iter()
                .find(|d| d["type"] == "grund.domain.v1.ErrorReason")
        })
        .and_then(|d| d["value"].as_str())
        .and_then(|v| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(v.trim_end_matches('='))
                .ok()
        })
        .map(|bytes| String::from_utf8_lossy(bytes.get(2..).unwrap_or_default()).to_string())
        .unwrap_or_default()
}

fn refused_with(answer: &(u16, Value), status: u16, reason: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        answer.0 == status && domain_reason(&answer.1) == reason,
        "wanted {status} {reason}, got {} {}",
        answer.0,
        answer.1
    );
    Ok(())
}

fn a_custom_name() -> String {
    format!("shop-{}.example.com", random_hex(4))
}

async fn added(when: &When, then: &Then, org: &str, name: &str) -> anyhow::Result<Value> {
    let answer = domain_call(
        when,
        then,
        "AddDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    anyhow::ensure!(answer.0 == 200, "AddDomain {name}: {}", answer.1);
    Ok(answer.1["domain"].clone())
}

async fn verified(
    stack: &Stack,
    when: &When,
    then: &Then,
    org: &str,
    name: &str,
) -> anyhow::Result<()> {
    let domain = added(when, then, org, name).await?;
    stack
        .pebble
        .set_txt(
            domain["verificationRecordName"]
                .as_str()
                .unwrap_or_default(),
            domain["verificationRecordValue"]
                .as_str()
                .unwrap_or_default(),
        )
        .await?;
    let answer = domain_call(
        when,
        then,
        "VerifyDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    anyhow::ensure!(
        answer.0 == 200 && answer.1["domain"]["status"] == "DOMAIN_STATUS_VERIFIED",
        "VerifyDomain {name}: {}",
        answer.1
    );
    Ok(())
}

async fn status_of(when: &When, then: &Then, org: &str, name: &str) -> anyhow::Result<Value> {
    let answer = domain_call(
        when,
        then,
        "GetDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    Ok(answer.1["domain"].clone())
}

#[tokio::test]
async fn concurrent_publication_and_last_domain_removal_cannot_both_succeed() -> anyhow::Result<()>
{
    let Some(stack) = a_stack_with(&[("GRUND_APP_DOMAINS", "custom-only")]).await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    stack
        .deploy_with_exposure(&org, "hello", "1", 1, false)
        .await?;
    let (when, then) = (&stack.when, &stack.then);
    let name = a_custom_name();
    verified(&stack, when, then, &org, &name).await?;
    let bound = domain_call(
        when,
        then,
        "BindDomain",
        json!({"organisation": org, "name": name, "app": "hello"}),
    )
    .await?;
    anyhow::ensure!(bound.0 == 200, "{bound:?}");
    when.calling(
        "/grund.app.v1.AppService/ListReleases",
        &json!({"organisation": org, "name": "hello"}).to_string(),
    )
    .await?;
    then.status(200)?;
    let mut spec = then.json()?["releases"][0]["spec"].clone();
    spec["ports"][0]["public"] = json!(true);
    let public = json!({"organisation": org, "name": "hello", "spec": spec}).to_string();
    let unbind = json!({"organisation": org, "name": name}).to_string();
    let unbind_path = format!("{DOMAINS}/UnbindDomain");
    let headers = &[
        ("Content-Type", "application/json"),
        ("Connect-Protocol-Version", "1"),
    ];
    let (publish, remove) = tokio::join!(
        when.send(
            "POST",
            "/grund.app.v1.AppService/Deploy",
            headers,
            Some(public.as_bytes())
        ),
        when.send("POST", &unbind_path, headers, Some(unbind.as_bytes()))
    );
    let (publish, remove) = (publish?, remove?);
    anyhow::ensure!(
        (publish.status == 200 && remove.status == 400)
            || (publish.status == 400 && remove.status == 200),
        "public release {}: {}; last-domain unbind {}: {}",
        publish.status,
        publish.text(),
        remove.status,
        remove.text()
    );
    let state = status_of(when, then, &org, &name).await?;
    if publish.status == 200 {
        anyhow::ensure!(
            state["app"] == "hello",
            "public app lost its only domain: {state}"
        );
        let refusal: Value = serde_json::from_slice(&remove.body)?;
        refused_with(&(remove.status, refusal), 400, "last_public_domain")?;
    } else {
        anyhow::ensure!(
            state["status"] == "DOMAIN_STATUS_VERIFIED",
            "unbound domain remained attached: {state}"
        );
        let refusal: Value = serde_json::from_slice(&publish.body)?;
        anyhow::ensure!(
            refusal["message"]
                .as_str()
                .is_some_and(|s| s.contains("verified custom domain")),
            "the unbound app was published: {refusal}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn custom_only_apps_need_a_bound_domain_before_publication_and_never_get_a_shared_address()
-> anyhow::Result<()> {
    let Some(mut stack) = a_stack_with(&[("GRUND_APP_DOMAINS", "custom-only")]).await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let _machine = stack.a_machine(&org, "box").await?;
    stack
        .deploy_with_exposure(&org, "hello", "1", 1, false)
        .await?;
    stack.start_edge()?;
    let (when, then) = (&stack.when, &stack.then);
    let app_path = format!("/{org}/apps/hello");
    when.visiting(&app_path).await?;
    then.status(200)?.body_contains("hello.grund.internal")?;
    when.visiting(&format!("/{org}/domains")).await?;
    then.status(200)?
        .body_contains("No default app addresses")?;

    when.calling(
        "/grund.app.v1.AppService/ListReleases",
        &json!({"organisation": org, "name": "hello"}).to_string(),
    )
    .await?;
    then.status(200)?;
    let private = then.json()?["releases"][0]["spec"].clone();
    let mut public = private.clone();
    public["ports"][0]["public"] = json!(true);
    let publish = json!({"organisation": org, "name": "hello", "spec": public});
    when.calling("/grund.app.v1.AppService/Deploy", &publish.to_string())
        .await?;
    then.status(400)?;
    anyhow::ensure!(
        then.json()?["message"]
            .as_str()
            .is_some_and(|s| s.contains("verified custom domain")),
        "public deployment without a bound domain was not refused"
    );

    let name = a_custom_name();
    verified(&stack, when, then, &org, &name).await?;
    let domains_page = format!("/{org}/domains");
    when.visiting(&domains_page).await?;
    then.status(200)?
        .body_contains("No default app addresses")?
        .body_contains("value=\"hello\"")?;
    when.submitting_on_current_page(
        &format!("{domains_page}/bind"),
        &[("name", name.as_str()), ("app", "hello")],
    )
    .await?;
    then.redirects_to(&format!("{domains_page}?done=bound#custom"))?;
    let bound = status_of(when, then, &org, &name).await?;
    anyhow::ensure!(bound["app"] == "hello", "{bound}");
    when.calling("/grund.app.v1.AppService/Deploy", &publish.to_string())
        .await?;
    then.status(200)?;
    stack.served(&name, Duration::from_secs(90)).await?;
    anyhow::ensure!(
        stack.connect(&stack.name_of(&org, "hello")).await.is_err(),
        "the custom-only app got a shared TLS address"
    );
    let mut conn = stack.connect(&name).await?;
    let response = conn.get(&name, "/", &[]).await?;
    anyhow::ensure!(
        response.status == 200 && response.text().contains(&name),
        "{}",
        response.text()
    );
    when.visiting(&app_path).await?;
    then.status(200)?
        .body_contains(&format!("https://{name}"))?
        .body_lacks(&stack.name_of(&org, "hello"))?;
    when.visiting(&format!("/{org}/apps")).await?;
    then.status(200)?
        .body_contains(&format!("https://{name}"))?
        .body_lacks(&stack.name_of(&org, "hello"))?;

    refused_with(
        &domain_call(
            when,
            then,
            "UnbindDomain",
            json!({"organisation": org, "name": name}),
        )
        .await?,
        400,
        "last_public_domain",
    )?;
    when.calling(
        "/grund.app.v1.AppService/Deploy",
        &json!({"organisation": org, "name": "hello", "spec": private}).to_string(),
    )
    .await?;
    then.status(200)?;
    let private_release = then.json()?["release"]["number"]
        .as_u64()
        .unwrap_or_default();
    stack
        .until(
            &org,
            "hello",
            Duration::from_secs(60),
            "private release is live",
            |app| app["currentRelease"].as_u64() == Some(private_release),
        )
        .await?;
    let unbound = domain_call(
        when,
        then,
        "UnbindDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    anyhow::ensure!(
        unbound.0 == 200 && unbound.1["domain"]["status"] == "DOMAIN_STATUS_VERIFIED",
        "{unbound:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while stack.connect(&name).await.is_ok() {
        anyhow::ensure!(
            Instant::now() < deadline,
            "the edge kept routing a private app's former domain"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

#[tokio::test]
async fn a_verified_domain_bound_to_an_app_is_served_through_the_edge_with_a_certificate_validated_by_http01()
-> anyhow::Result<()> {
    let Some(mut stack) = a_stack_with(&[]).await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let (outsider, outsider_when, outsider_then) = stack.given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    let _machine = stack.a_machine(&org, "box").await?;
    stack.deploy(&org, "hello", "1", 1).await?;
    stack.start_edge()?;
    let address = stack.name_of(&org, "hello");
    stack.served(&address, Duration::from_secs(60)).await?;
    let (when, then) = (&stack.when, &stack.then);
    let name = a_custom_name();

    let domain = added(when, then, &org, &name).await?;
    anyhow::ensure!(
        domain["status"] == "DOMAIN_STATUS_PENDING"
            && domain["verificationRecordName"] == format!("_grund.{name}").as_str()
            && domain["verificationRecordValue"]
                .as_str()
                .is_some_and(|v| v.starts_with("grund-verify-") && v.len() == 56),
        "{domain}"
    );
    let token = domain["verificationRecordValue"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let unverified = domain_call(
        when,
        then,
        "VerifyDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    refused_with(&unverified, 400, "verification_failed")?;
    anyhow::ensure!(
        unverified.1["message"]
            .as_str()
            .is_some_and(|m| m.contains("No TXT record")),
        "{}",
        unverified.1
    );
    refused_with(
        &domain_call(
            when,
            then,
            "BindDomain",
            json!({"organisation": org, "name": name, "app": "hello"}),
        )
        .await?,
        400,
        "not_verified",
    )?;
    stack
        .pebble
        .set_txt(&format!("_grund.{name}"), "grund-verify-someone-elses")
        .await?;
    refused_with(
        &domain_call(
            when,
            then,
            "VerifyDomain",
            json!({"organisation": org, "name": name}),
        )
        .await?,
        400,
        "verification_failed",
    )?;
    let shown = status_of(when, then, &org, &name).await?;
    anyhow::ensure!(
        shown["status"] == "DOMAIN_STATUS_ERROR"
            && shown["problem"]
                .as_str()
                .is_some_and(|p| p.contains("does not hold")),
        "{shown}"
    );
    anyhow::ensure!(
        stack.connect(&name).await.is_err(),
        "the edge answered a domain that is not verified"
    );

    stack
        .pebble
        .set_txt(&format!("_grund.{name}"), &token)
        .await?;
    let answer = domain_call(
        when,
        then,
        "VerifyDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    anyhow::ensure!(
        answer.1["domain"]["status"] == "DOMAIN_STATUS_VERIFIED",
        "{}",
        answer.1
    );
    let answer = domain_call(
        when,
        then,
        "BindDomain",
        json!({"organisation": org, "name": name, "app": "hello"}),
    )
    .await?;
    anyhow::ensure!(
        answer.0 == 200 && answer.1["domain"]["app"] == "hello",
        "{}",
        answer.1
    );

    let started = Instant::now();
    loop {
        let shown = status_of(when, then, &org, &name).await?;
        if shown["status"] == "DOMAIN_STATUS_CERTIFICATE_ISSUED" {
            anyhow::ensure!(shown["certificateExpiresAt"].is_string(), "{shown}");
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(90),
            "no certificate for {name}: {shown}\nedge log:\n{}\npebble log:\n{}",
            stack.edge_log(),
            stack.pebble.log()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    when.calling(
        "/grund.notification.v1.NotificationService/ListNotifications",
        "{}",
    )
    .await?;
    then.status(200)?;
    let notifications = then.json()?;
    anyhow::ensure!(
        notifications["notifications"]
            .as_array()
            .is_some_and(|items| items
                .iter()
                .filter(|item| {
                    item["kind"] == "domain.certificate_issued"
                        && item["text"]
                            .as_str()
                            .is_some_and(|text| text.contains(&name))
                })
                .count()
                == 1),
        "certificate issuance has one fact: {notifications}"
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
        "certificate for another org leaked: {unrelated}"
    );
    stack.served(&name, Duration::from_secs(60)).await?;
    let mut conn = stack.connect(&name).await?;
    let served = conn.get(&name, "/", &[]).await?;
    anyhow::ensure!(
        served.status == 200 && served.text().contains(&name),
        "the app did not see its custom domain as the host: {}",
        served.text()
    );
    let foreign = conn.get("nobody.example.com", "/", &[]).await?;
    anyhow::ensure!(
        foreign.status == 421,
        "a foreign name on the custom domain's connection: {}",
        foreign.status
    );
    anyhow::ensure!(
        stack
            .edge_log()
            .contains("an HTTP-01 challenge for a custom domain"),
        "the edge did not answer HTTP-01:\n{}",
        stack.edge_log()
    );
    let kept = stack.edge_dir.join("data/names").join(&name).join("custom");
    anyhow::ensure!(
        kept.join("key.sealed").exists() && !kept.join("key.der").exists(),
        "the edge keeps the custom domain's key sealed"
    );
    let fixture = &stack.given.testcase.fixture;
    anyhow::ensure!(
        fixture
            .count(
                "SELECT count(*) FROM grund_certificates WHERE subject LIKE 'domain:%' \
                 AND owner LIKE 'organisation:%' AND terminator = 'instance' AND challenge = 'http-01' \
                 AND sealed_key IS NOT NULL AND csr IS NULL AND chain_pem IS NOT NULL"
            )
            .await?
            == 1,
        "the certificate is the organisation's, its key sealed on the instance"
    );

    when.visiting(&format!("/{org}/domains")).await?;
    then.status(200)?
        .body_contains(&name)?
        .body_contains("Serving hello at https:")?;
    when.visiting(&format!("/{org}/apps/hello")).await?;
    then.status(200)?
        .body_contains(&format!("https://{name}"))?;

    let answer = domain_call(
        when,
        then,
        "UnbindDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    anyhow::ensure!(
        answer.1["domain"]["status"] == "DOMAIN_STATUS_VERIFIED",
        "{}",
        answer.1
    );
    let started = Instant::now();
    while stack.connect(&name).await.is_ok() {
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(30),
            "the edge kept serving an unbound domain"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let answer = domain_call(
        when,
        then,
        "RemoveDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    anyhow::ensure!(answer.0 == 200, "{}", answer.1);
    let gone = domain_call(
        when,
        then,
        "GetDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    refused_with(&gone, 404, "not_found")?;
    anyhow::ensure!(
        fixture
            .count("SELECT count(*) FROM grund_certificates WHERE subject LIKE 'domain:%'")
            .await?
            == 0,
        "a removed domain's certificate stays"
    );
    Ok(())
}

#[tokio::test]
async fn another_organisation_can_neither_claim_a_bound_domain_nor_see_or_touch_it()
-> anyhow::Result<()> {
    let Some(stack) = a_stack_with(&[]).await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let _machine = stack.a_machine(&org, "box").await?;
    stack.deploy(&org, "hello", "1", 1).await?;
    let (when, then) = (&stack.when, &stack.then);
    let name = a_custom_name();
    verified(&stack, when, then, &org, &name).await?;
    let answer = domain_call(
        when,
        then,
        "BindDomain",
        json!({"organisation": org, "name": name, "app": "hello"}),
    )
    .await?;
    anyhow::ensure!(answer.0 == 200, "{}", answer.1);

    let (stranger_given, stranger, stranger_then) = stack.given.testcase.another_browser();
    let theirs = stranger_given.a_signed_in_account().await?.username;
    refused_with(
        &domain_call(
            &stranger,
            &stranger_then,
            "AddDomain",
            json!({"organisation": theirs, "name": name}),
        )
        .await?,
        409,
        "domain_taken",
    )?;
    refused_with(
        &domain_call(
            &stranger,
            &stranger_then,
            "AddDomain",
            json!({"organisation": theirs, "name": format!("x.{}", stack.name_of(&theirs, "y"))}),
        )
        .await?,
        400,
        "name_reserved",
    )?;
    for (procedure, body) in [
        ("ListDomains", json!({"organisation": org})),
        ("GetDomain", json!({"organisation": org, "name": name})),
        (
            "AddDomain",
            json!({"organisation": org, "name": a_custom_name()}),
        ),
        ("VerifyDomain", json!({"organisation": org, "name": name})),
        (
            "BindDomain",
            json!({"organisation": org, "name": name, "app": "hello"}),
        ),
        ("UnbindDomain", json!({"organisation": org, "name": name})),
        ("RemoveDomain", json!({"organisation": org, "name": name})),
    ] {
        let answer = domain_call(&stranger, &stranger_then, procedure, body).await?;
        anyhow::ensure!(
            answer.0 == 404 && answer.1["code"] == "not_found",
            "{procedure} on another organisation: {} {}",
            answer.0,
            answer.1
        );
    }
    let page = format!("/{org}/domains");
    stranger.visiting(&page).await?;
    stranger_then.status(404)?.body_lacks(&name)?;
    stranger.visiting(&format!("/{theirs}/domains")).await?;
    stranger_then.status(200)?.body_lacks(&name)?;
    for action in ["verify", "bind", "unbind", "remove"] {
        stranger.visiting(&format!("/{theirs}/domains")).await?;
        stranger
            .submitting_on_current_page(
                &format!("{page}/{action}"),
                &[("name", name.as_str()), ("app", "hello")],
            )
            .await?;
        stranger_then.status(404)?;
    }
    stranger.visiting(&format!("/{theirs}/domains")).await?;
    stranger
        .submitting_on_current_page(&page, &[("name", "other.example.com")])
        .await?;
    stranger_then.status(404)?;
    let still = status_of(when, then, &org, &name).await?;
    anyhow::ensure!(
        still["status"] != "DOMAIN_STATUS_VERIFIED" && still["app"] == "hello",
        "{still}"
    );

    let unverified = a_custom_name();
    added(when, then, &org, &unverified).await?;
    refused_with(
        &domain_call(
            when,
            then,
            "BindDomain",
            json!({"organisation": org, "name": unverified, "app": "hello"}),
        )
        .await?,
        400,
        "not_verified",
    )?;
    when.visiting(&page).await?;
    when.submitting_on_current_page(
        &format!("{page}/bind"),
        &[("name", unverified.as_str()), ("app", "hello")],
    )
    .await?;
    then.redirects_to(&format!("{page}?error=not-verified#custom"))?;
    Ok(())
}

#[tokio::test]
async fn a_released_domain_cools_down_for_other_organisations_but_not_the_one_that_released_it()
-> anyhow::Result<()> {
    let cooldown = Duration::from_secs(6);
    let Some(stack) =
        a_stack_with(&[("GRUND_DOMAIN_COOLDOWN", &cooldown.as_secs().to_string())]).await?
    else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let (when, then) = (&stack.when, &stack.then);
    let name = a_custom_name();
    verified(&stack, when, then, &org, &name).await?;
    let removed = domain_call(
        when,
        then,
        "RemoveDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    anyhow::ensure!(removed.0 == 200, "{}", removed.1);
    let released = Instant::now();

    let (stranger_given, stranger, stranger_then) = stack.given.testcase.another_browser();
    let theirs = stranger_given.a_signed_in_account().await?.username;
    refused_with(
        &domain_call(
            &stranger,
            &stranger_then,
            "AddDomain",
            json!({"organisation": theirs, "name": name}),
        )
        .await?,
        400,
        "domain_cooling_down",
    )?;
    stranger.visiting(&format!("/{theirs}/domains")).await?;
    stranger
        .submitting_on_current_page(&format!("/{theirs}/domains"), &[("name", name.as_str())])
        .await?;
    stranger_then
        .status(422)?
        .body_contains("released recently")?;

    let again = added(when, then, &org, &name).await?;
    anyhow::ensure!(again["status"] == "DOMAIN_STATUS_PENDING", "{again}");
    let removed = domain_call(
        when,
        then,
        "RemoveDomain",
        json!({"organisation": org, "name": name}),
    )
    .await?;
    anyhow::ensure!(removed.0 == 200, "{}", removed.1);
    refused_with(
        &domain_call(
            &stranger,
            &stranger_then,
            "AddDomain",
            json!({"organisation": theirs, "name": name}),
        )
        .await?,
        400,
        "domain_cooling_down",
    )?;

    if let Some(left) = (cooldown + Duration::from_millis(500)).checked_sub(released.elapsed()) {
        tokio::time::sleep(left).await;
    }
    verified(&stack, &stranger, &stranger_then, &theirs, &name).await?;
    refused_with(
        &domain_call(
            when,
            then,
            "AddDomain",
            json!({"organisation": org, "name": name}),
        )
        .await?,
        409,
        "domain_taken",
    )?;
    Ok(())
}

#[tokio::test]
async fn a_bound_domain_without_an_edge_records_one_certificate_failure() -> anyhow::Result<()> {
    let Some(stack) = a_stack_with(&[]).await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let organisation = owner.username;
    let (outsider, outsider_when, outsider_then) = stack.given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    let _machine = stack.a_machine(&organisation, "box").await?;
    stack.deploy(&organisation, "hello", "1", 1).await?;
    let name = a_custom_name();
    let (when, then) = (&stack.when, &stack.then);
    verified(&stack, when, then, &organisation, &name).await?;
    let bound = domain_call(
        when,
        then,
        "BindDomain",
        json!({"organisation": organisation, "name": name, "app": "hello"}),
    )
    .await?;
    anyhow::ensure!(bound.0 == 200, "domain did not bind: {}", bound.1);
    let started = Instant::now();
    loop {
        let status = status_of(when, then, &organisation, &name).await?;
        if status["status"] == "DOMAIN_STATUS_ERROR" {
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(90),
            "certificate order did not fail without an edge: {status}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
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
            .filter(|item| item["kind"] == "domain.certificate_failing")
            .count()
            == 1),
        "first certificate failure created one fact: {inbox}"
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
        "certificate failure for another org leaked: {unrelated}"
    );
    Ok(())
}
