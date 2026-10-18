use std::time::Duration;

use serde_json::{Value, json};

use super::{
    apps::{a_machine, call, live, quick, reason, spec, until},
    fixtures::{FakeRegistry, random_hex, testcase_configured},
};

fn approval(org: &str, name: &str, update: &Value, key: &str) -> Value {
    json!({
        "organisation": org, "name": name,
        "baseRelease": update["baseRelease"], "baseDigest": update["currentDigest"],
        "targetReference": update["candidates"][0]["reference"],
        "targetDigest": update["candidates"][0]["digest"], "idempotencyKey": key,
    })
}

#[tokio::test]
async fn a_mutable_tag_is_explicit_pinned_on_apply_and_replayed_after_the_base_moves()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let password = format!("update-password-{}", random_hex(12));
    registry.make_private("acme/updates", "robot", &password);
    let registries = format!("/{org}/settings/registries");
    when.submitting(
        &registries,
        &registries,
        &[
            ("host", registry.host.as_str()),
            ("username", "robot"),
            ("password", password.as_str()),
        ],
    )
    .await?;
    then.redirects_to(&format!("{registries}?done=set"))?;
    let _agent = a_machine(&when, &then, org, "updates").await?;
    let a = registry.publish("acme/updates", "stable");
    let image = registry.image("acme/updates", "stable");
    let desired = spec(&image, json!([{"name":"CUSTOM","value":"preserved"}]));
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation":org,"name":"updates","settings":quick(1)}),
    )
    .await?;
    then.status(200)?;
    let deployed = call(
        &when,
        &then,
        "Deploy",
        json!({"organisation":org,"name":"updates","spec":desired}),
    )
    .await?;
    then.status(200)?;
    until(
        &when,
        &then,
        org,
        "updates",
        Duration::from_secs(35),
        "first release live",
        |app| live(app, 1),
    )
    .await?;
    let read = json!({"organisation":org,"name":"updates"});
    let calls = registry.manifest_calls();
    let never = call(&when, &then, "GetAppUpdate", read.clone()).await?;
    then.status(200)?;
    anyhow::ensure!(
        never["update"]["state"] == "APP_UPDATE_STATE_NOT_CHECKED",
        "{never}"
    );
    anyhow::ensure!(
        registry.manifest_calls() == calls,
        "a cached read contacted the registry"
    );
    let current = call(&when, &then, "CheckAppUpdate", read.clone()).await?;
    then.status(200)?;
    anyhow::ensure!(
        current["update"]["state"] == "APP_UPDATE_STATE_CURRENT",
        "{current}"
    );
    let b = registry.publish("acme/updates", "stable");
    let cached = call(&when, &then, "GetAppUpdate", read.clone()).await?;
    then.status(200)?;
    anyhow::ensure!(
        cached["update"]["state"] == "APP_UPDATE_STATE_CURRENT",
        "{cached}"
    );
    let checked = call(&when, &then, "CheckAppUpdate", read.clone()).await?;
    then.status(200)?;
    let update = &checked["update"];
    let mut unoffered = approval(org, "updates", update, "not-offered");
    unoffered["targetDigest"] = Value::String(format!("sha256:{}", "f".repeat(64)));
    let calls = registry.manifest_calls();
    let refused = call(&when, &then, "ApplyAppUpdate", unoffered).await?;
    then.status(400)?.connect_code("failed_precondition")?;
    anyhow::ensure!(reason(&refused) == "update_not_available", "{refused}");
    anyhow::ensure!(
        registry.manifest_calls() == calls,
        "unoffered target reached a registry"
    );
    anyhow::ensure!(
        update["state"] == "APP_UPDATE_STATE_AVAILABLE"
            && update["currentDigest"] == a
            && update["candidates"][0]["digest"] == b,
        "{checked}"
    );
    let request = approval(org, "updates", update, "first-update");
    let c = registry.publish("acme/updates", "stable");
    let changed = call(&when, &then, "ApplyAppUpdate", request.clone()).await?;
    then.status(200)?;
    anyhow::ensure!(
        changed["release"]["number"] == 2 && changed["release"]["imageDigest"] == b,
        "the moving tag replaced the approved digest: {changed}"
    );
    let mut expected = deployed["release"]["spec"].clone();
    expected["image"] = Value::String(image.clone());
    anyhow::ensure!(
        changed["release"]["spec"] == expected,
        "custom settings changed: {changed}"
    );
    let replayed = call(&when, &then, "ApplyAppUpdate", request.clone()).await?;
    then.status(200)?;
    anyhow::ensure!(replayed["release"]["number"] == 2, "{replayed}");
    until(
        &when,
        &then,
        org,
        "updates",
        Duration::from_secs(35),
        "approved B live",
        |app| live(app, 2),
    )
    .await?;
    let mut stale = request.clone();
    stale["idempotencyKey"] = "stale-base".into();
    let error = call(&when, &then, "ApplyAppUpdate", stale).await?;
    then.status(409)?.connect_code("aborted")?;
    anyhow::ensure!(reason(&error) == "update_stale", "{error}");
    let mut conflict = request.clone();
    conflict["targetDigest"] = Value::String(c.clone());
    let error = call(&when, &then, "ApplyAppUpdate", conflict).await?;
    then.status(409)?.connect_code("already_exists")?;
    anyhow::ensure!(reason(&error) == "idempotency_conflict", "{error}");
    let checked_c = call(&when, &then, "CheckAppUpdate", read.clone()).await?;
    then.status(200)?;
    let approved_c = approval(org, "updates", &checked_c["update"], "second-update");
    let release_c = call(&when, &then, "ApplyAppUpdate", approved_c).await?;
    then.status(200)?;
    anyhow::ensure!(
        release_c["release"]["number"] == 3 && release_c["release"]["imageDigest"] == c,
        "{release_c}"
    );
    until(
        &when,
        &then,
        org,
        "updates",
        Duration::from_secs(35),
        "approved C live",
        |app| live(app, 3),
    )
    .await?;
    let replayed = call(&when, &then, "ApplyAppUpdate", request.clone()).await?;
    then.status(200)?;
    anyhow::ensure!(
        replayed["release"]["number"] == 2,
        "retained request did not replay: {replayed}"
    );
    let history = call(&when, &then, "ListReleases", read.clone()).await?;
    then.status(200)?;
    anyhow::ensure!(
        history["releases"]
            .as_array()
            .is_some_and(|releases| releases.len() == 3),
        "{history}"
    );
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    let calls = registry.manifest_calls();
    for (method, body) in [
        ("GetAppUpdate", read.clone()),
        ("CheckAppUpdate", read),
        ("ApplyAppUpdate", request),
    ] {
        call(&outsider_when, &outsider_then, method, body).await?;
        outsider_then.status(404)?.connect_code("not_found")?;
    }
    anyhow::ensure!(
        registry.manifest_calls() == calls,
        "denied tenant performed registry work"
    );
    anyhow::ensure!(
        registry.logins() > 0,
        "private image checks did not authenticate"
    );
    anyhow::ensure!(
        !checked.to_string().contains(&password)
            && !given.testcase.fixture.log().contains(&password),
        "a response or log exposed the credential"
    );
    anyhow::ensure!(given.testcase.fixture.count(&format!(
        "SELECT count(*) FROM grund_app_update_checks WHERE observation::text LIKE '%{password}%'"
    )).await? == 0, "the discovery cache contains credentials");
    Ok(())
}

#[tokio::test]
async fn a_tag_and_digest_pin_can_be_checked_but_a_digest_only_image_stays_pinned()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _agent = a_machine(&when, &then, org, "pins").await?;
    let digest = registry.publish("acme/pins", "stable");
    let tag_pin = format!("{}@{digest}", registry.image("acme/pins", "stable"));
    let digest_only = format!("{}/acme/pins@{digest}", registry.host);
    for (name, image) in [("tag-pin", tag_pin), ("digest-pin", digest_only)] {
        call(
            &when,
            &then,
            "CreateApp",
            json!({"organisation":org,"name":name,"settings":quick(1)}),
        )
        .await?;
        then.status(200)?;
        call(
            &when,
            &then,
            "Deploy",
            json!({"organisation":org,"name":name,"spec":spec(&image,json!([]))}),
        )
        .await?;
        then.status(200)?;
        until(
            &when,
            &then,
            org,
            name,
            Duration::from_secs(35),
            "pinned release live",
            |app| live(app, 1),
        )
        .await?;
    }
    let moved = registry.publish("acme/pins", "stable");
    let offered = call(
        &when,
        &then,
        "CheckAppUpdate",
        json!({"organisation":org,"name":"tag-pin"}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        offered["update"]["state"] == "APP_UPDATE_STATE_AVAILABLE"
            && offered["update"]["candidates"][0]["digest"] == moved,
        "{offered}"
    );
    let calls = registry.manifest_calls();
    let pinned = call(
        &when,
        &then,
        "CheckAppUpdate",
        json!({"organisation":org,"name":"digest-pin"}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        pinned["update"]["state"] == "APP_UPDATE_STATE_PINNED",
        "{pinned}"
    );
    anyhow::ensure!(
        registry.manifest_calls() == calls,
        "digest-only image watched a tag"
    );
    let updated = call(
        &when,
        &then,
        "ApplyAppUpdate",
        approval(org, "tag-pin", &offered["update"], "replace-pin"),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        updated["release"]["spec"]["image"]
            .as_str()
            .is_some_and(|image| image.ends_with(&format!("@{moved}"))),
        "{updated}"
    );
    registry.make_private("acme/pins", "unconfigured", "not-stored");
    let failed = call(
        &when,
        &then,
        "CheckAppUpdate",
        json!({"organisation":org,"name":"tag-pin"}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        failed["update"]["state"] == "APP_UPDATE_STATE_ERROR"
            && failed["update"]["reason"] == "image_unresolved",
        "{failed}"
    );
    Ok(())
}
