use serde_json::{Value, json};

use crate::accepttest::fixtures::{
    FakeRegistry, Then, When, testcase, testcase_configured, testcase_with_mail,
};

const SERVICE: &str = "/grund.stack.v1.StackService";

async fn call(when: &When, then: &Then, method: &str, body: Value) -> anyhow::Result<Value> {
    when.calling(&format!("{SERVICE}/{method}"), &body.to_string())
        .await?;
    then.json()
}

async fn token(
    when: &When,
    then: &Then,
    org: &str,
    name: &str,
    scope: &str,
    apps: &[String],
) -> anyhow::Result<String> {
    when.calling(
        "/grund.token.v1.TokenService/CreateToken",
        &json!({"organisation":org,"name":name,"scope":scope,"apps":apps}).to_string(),
    )
    .await?;
    then.status(200)?;
    Ok(format!(
        "Bearer {}",
        then.json()?["secret"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("token secret absent"))?
    ))
}

async fn token_call(
    when: &When,
    then: &Then,
    bearer: &str,
    method: &str,
    body: Value,
) -> anyhow::Result<Value> {
    when.calling_with(
        &format!("{SERVICE}/{method}"),
        &body.to_string(),
        &[("Authorization", bearer)],
    )
    .await?;
    then.json()
}

#[tokio::test]
async fn stack_tokens_read_only_complete_authorised_bundles_before_pagination() -> anyhow::Result<()>
{
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (_, client, result) = given.testcase.another_browser();
    registry.publish("acme/web", "1");
    let image = registry.image("acme/web", "1");
    let yaml = |name: &str| {
        format!(
            "stack:\n  name: {name}\n  services:\n    web:\n      image: {image}\n    sibling:\n      image: {image}\n      env:\n        PRIVATE_METADATA: sibling-only\n      volumes:\n        data:\n          path: /data\n"
        )
    };
    let mut bundles = Vec::new();
    for name in ["hidden", "visible", "continued"] {
        let created = call(
            &when,
            &then,
            "DeployStack",
            json!({"organisation":owner.username,"yaml":yaml(name),"idempotencyKey":name}),
        )
        .await?;
        then.status(200)?;
        bundles.push(created["stack"].clone());
    }
    let apps = bundles[1..]
        .iter()
        .flat_map(|bundle| bundle["services"].as_array().into_iter().flatten())
        .map(|service| {
            service["appName"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow::anyhow!("backing app name absent: {service}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let bounded = token(
        &when,
        &then,
        &owner.username,
        "bundle-reader",
        "TOKEN_SCOPE_DEPLOY",
        &apps,
    )
    .await?;
    let partial = token(
        &when,
        &then,
        &owner.username,
        "one-child",
        "TOKEN_SCOPE_DEPLOY",
        &apps[..1],
    )
    .await?;
    let deploy = token(
        &when,
        &then,
        &owner.username,
        "org-reader",
        "TOKEN_SCOPE_DEPLOY",
        &[],
    )
    .await?;
    let full = token(
        &when,
        &then,
        &owner.username,
        "org-writer",
        "TOKEN_SCOPE_FULL",
        &[],
    )
    .await?;
    for bearer in [&bounded, &deploy] {
        for (method, fields) in [
            ("GetStack", json!({"name":"visible"})),
            ("PreviewStack", json!({"yaml":yaml("visible")})),
        ] {
            let mut body = fields;
            body["organisation"] = json!(owner.username);
            let read = token_call(&client, &result, bearer, method, body).await?;
            result.status(200)?;
            let entity = if method == "GetStack" {
                &read["stack"]
            } else {
                &read["preview"]
            };
            anyhow::ensure!(
                entity["services"].as_array().is_some_and(|s| s.len() == 2),
                "{read}"
            );
            if method == "GetStack" {
                anyhow::ensure!(
                    entity["yaml"] == yaml("visible")
                        && entity["volumes"].as_array().is_some_and(|v| v.len() == 1),
                    "the complete grant should include sibling configuration and owned data: {read}"
                );
            }
        }
        for method in [
            "DeployStack",
            "RestartStack",
            "RollbackStack",
            "DeleteStack",
            "RestoreStack",
        ] {
            let refused = token_call(
                &client,
                &result,
                bearer,
                method,
                json!({"organisation":owner.username}),
            )
            .await?;
            result.status(403)?.connect_code("permission_denied")?;
            anyhow::ensure!(
                refused["message"] == "stack changes need a full token",
                "{refused}"
            );
        }
    }
    let inspections = registry.manifest_calls();
    for (name, bearer) in [
        ("visible", &partial),
        ("hidden", &bounded),
        ("new-stack", &bounded),
    ] {
        for (method, fields) in [
            ("GetStack", json!({"name":name})),
            ("PreviewStack", json!({"yaml":yaml(name)})),
        ] {
            let mut body = fields;
            body["organisation"] = json!(owner.username);
            token_call(&client, &result, bearer, method, body).await?;
            result
                .status(404)?
                .connect_code("not_found")?
                .body_lacks("sibling-only")?
                .body_lacks("/data")?
                .body_lacks(&image)?;
        }
    }
    anyhow::ensure!(
        registry.manifest_calls() == inspections,
        "unauthorised previews inspected external images"
    );
    let page = token_call(
        &client,
        &result,
        &bounded,
        "ListStacks",
        json!({"organisation":owner.username,"pageSize":1}),
    )
    .await?;
    result.status(200)?;
    anyhow::ensure!(
        page["stacks"].as_array().is_some_and(|s| s.len() == 1)
            && page["stacks"][0]["name"] == "visible",
        "scope filtering must precede the page limit: {page}"
    );
    let next = token_call(
        &client,
        &result,
        &bounded,
        "ListStacks",
        json!({"organisation":owner.username,"pageSize":1,"pageToken":page["nextPageToken"]}),
    )
    .await?;
    result.status(200)?;
    anyhow::ensure!(
        page["nextPageToken"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
            && next["stacks"].as_array().is_some_and(|s| s.len() == 1)
            && next["stacks"][0]["name"] == "continued"
            && next["nextPageToken"].as_str().is_none_or(str::is_empty),
        "scope-filtered continuation lost or repeated a stack: {next}"
    );
    let empty = token_call(
        &client,
        &result,
        &partial,
        "ListStacks",
        json!({"organisation":owner.username}),
    )
    .await?;
    result
        .status(200)?
        .body_lacks("sibling-only")?
        .body_lacks("/data")?;
    anyhow::ensure!(
        empty["stacks"].as_array().is_none_or(Vec::is_empty),
        "{empty}"
    );
    token_call(
        &client, &result, &full, "DeployStack",
        json!({"organisation":owner.username,"yaml":yaml("full-created"),"idempotencyKey":"full-created"}),
    ).await?;
    result.status(200)?;
    Ok(())
}

#[tokio::test]
async fn stack_authentication_and_tenant_checks_precede_invalid_input() -> anyhow::Result<()> {
    let (given, when, then) = testcase().await?;
    call(
        &when,
        &then,
        "ListStacks",
        json!({"organisation": "missing"}),
    )
    .await?;
    then.status(401)?.connect_code("unauthenticated")?;
    let owner = given.a_signed_in_account().await?;
    let (outsider, other_when, other_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    for (method, fields) in [
        ("GetStack", json!({"name":"missing"})),
        ("ListStacks", json!({"pageSize":-1})),
        ("PreviewStack", json!({"yaml":"invalid"})),
        ("DeployStack", json!({"yaml":"invalid"})),
        ("RestartStack", json!({"name":"missing"})),
        ("RollbackStack", json!({"name":"missing"})),
        ("DeleteStack", json!({"name":"missing"})),
        ("RestoreStack", json!({"name":"missing"})),
    ] {
        let mut body = fields;
        body["organisation"] = json!(owner.username);
        call(&other_when, &other_then, method, body).await?;
        other_then.status(404)?.connect_code("not_found")?;
    }
    call(
        &when,
        &then,
        "ListStacks",
        json!({"organisation":owner.username,"pageSize":-1}),
    )
    .await?;
    then.status(400)?.connect_code("invalid_argument")?;
    when.calling(
        "/grund.token.v1.TokenService/CreateToken",
        &json!({"organisation":owner.username,"name":"bounded","apps":["web"]}).to_string(),
    )
    .await?;
    then.status(200)?;
    let secret = then.json()?["secret"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("token secret absent"))?
        .to_string();
    let bearer = format!("Bearer {secret}");
    for method in [
        "DeployStack",
        "RestartStack",
        "RollbackStack",
        "DeleteStack",
        "RestoreStack",
    ] {
        other_when
            .calling_with(
                &format!("{SERVICE}/{method}"),
                &json!({"organisation":owner.username}).to_string(),
                &[("Authorization", &bearer)],
            )
            .await?;
        other_then.status(403)?.connect_code("permission_denied")?;
        anyhow::ensure!(
            other_then.json()?["message"] == "stack changes need a full token",
            "the token refusal must reach clients unchanged"
        );
    }
    for (method, status) in [
        ("GetStack", 404),
        ("ListStacks", 200),
        ("PreviewStack", 400),
    ] {
        other_when
            .calling_with(
                &format!("{SERVICE}/{method}"),
                &json!({"organisation":owner.username}).to_string(),
                &[("Authorization", &bearer)],
            )
            .await?;
        other_then.status(status)?;
    }
    let second_org = given.a_fresh_name("team");
    when.submitting("/orgs/new", "/orgs/new", &[("slug", &second_org)])
        .await?;
    then.status(303)?;
    when.calling(
        "/grund.token.v1.TokenService/CreateToken",
        &json!({"organisation":owner.username,"name":"organisation-token"}).to_string(),
    )
    .await?;
    then.status(200)?;
    let secret = then.json()?["secret"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("token secret absent"))?
        .to_string();
    let bearer = format!("Bearer {secret}");
    other_when
        .calling_with(
            &format!("{SERVICE}/ListStacks"),
            &json!({"organisation":second_org}).to_string(),
            &[("Authorization", &bearer)],
        )
        .await?;
    other_then.status(404)?.connect_code("not_found")?;
    other_when
        .calling_with(
            &format!("{SERVICE}/DeployStack"),
            &json!({
                "organisation":owner.username,
                "yaml":"invalid",
                "idempotencyKey":"scope-removal",
                "confirmedRemovals":["web"],
            })
            .to_string(),
            &[("Authorization", &bearer)],
        )
        .await?;
    other_then.status(403)?.connect_code("permission_denied")?;
    anyhow::ensure!(
        other_then.json()?["message"] == "stack changes need a full token",
        "unrestricted deploy tokens must receive the same refusal"
    );
    Ok(())
}

#[tokio::test]
async fn stack_preview_is_read_only_and_deploy_replays_with_bounded_continuation()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    registry.publish("acme/web", "1");
    let yaml = |name: &str| {
        format!(
            "stack:\n  name: {name}\n  services:\n    web:\n      image: {}\n",
            registry.image("acme/web", "1")
        )
    };
    let preview = call(
        &when,
        &then,
        "PreviewStack",
        json!({"organisation":owner.username,"yaml":yaml("shop")}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(preview["preview"]["services"].is_array(), "{preview}");
    let empty = call(
        &when,
        &then,
        "ListStacks",
        json!({"organisation":owner.username}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        empty["stacks"].as_array().is_none_or(Vec::is_empty),
        "preview created a stack"
    );
    let request =
        json!({"organisation":owner.username,"yaml":yaml("shop"),"idempotencyKey":"create-shop"});
    let mut unknown_removal = request.clone();
    unknown_removal["confirmedRemovals"] = json!(["missing"]);
    call(&when, &then, "DeployStack", unknown_removal).await?;
    then.status(400)?.connect_code("invalid_argument")?;
    let refused = call(
        &when,
        &then,
        "ListStacks",
        json!({"organisation":owner.username}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        refused["stacks"].as_array().is_none_or(Vec::is_empty),
        "unknown removal confirmation created a stack"
    );
    let first = call(&when, &then, "DeployStack", request.clone()).await?;
    then.status(200)?;
    let replay = call(&when, &then, "DeployStack", request).await?;
    then.status(200)?;
    anyhow::ensure!(
        first["stack"]["id"] == replay["stack"]["id"]
            && first["stack"]["revision"] == replay["stack"]["revision"],
        "replay created another revision"
    );
    call(&when, &then, "DeployStack", json!({"organisation":owner.username,"yaml":yaml("changed"),"idempotencyKey":"create-shop"})).await?;
    then.status(409)?.connect_code("already_exists")?;
    call(&when, &then, "RestartStack", json!({"organisation":owner.username,"name":"shop","expectedVersion":"0","idempotencyKey":"stale"})).await?;
    then.status(409)?.connect_code("aborted")?;
    call(&when, &then, "DeployStack", json!({"organisation":owner.username,"yaml":yaml("second"),"idempotencyKey":"create-second"})).await?;
    then.status(200)?;
    let page = call(
        &when,
        &then,
        "ListStacks",
        json!({"organisation":owner.username,"pageSize":1}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        page["stacks"]
            .as_array()
            .is_some_and(|stacks| stacks.len() == 1),
        "{page}"
    );
    let token = page["nextPageToken"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing continuation: {page}"))?;
    let next = call(
        &when,
        &then,
        "ListStacks",
        json!({"organisation":owner.username,"pageSize":1,"pageToken":token}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        next["stacks"]
            .as_array()
            .is_some_and(|stacks| stacks.len() == 1),
        "{next}"
    );
    anyhow::ensure!(
        page["stacks"][0]["id"] != next["stacks"][0]["id"],
        "continuation repeated a stack"
    );
    Ok(())
}

#[tokio::test]
async fn members_read_stacks_but_cannot_mutate_even_with_valid_session_credentials()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (guest, guest_when, guest_then) = given.testcase.another_browser();
    let member = guest.a_signed_in_account().await?;
    when.inviting(&owner.username, &member.email, "member")
        .await?;
    then.status(303)?;
    let link = guest_when
        .the_mailed_link(
            &member.email,
            &format!("Join {} on grund", owner.username),
            "/invite?token=",
        )
        .await?;
    guest_when.visiting(&link).await?;
    guest_then.status(200)?;
    let token = guest.last_token()?;
    guest_when
        .submitting_on_current_page("/invite", &[("token", &token)])
        .await?;
    guest_then.status(303)?;
    call(
        &guest_when,
        &guest_then,
        "ListStacks",
        json!({"organisation":owner.username}),
    )
    .await?;
    guest_then.status(200)?;
    for method in [
        "DeployStack",
        "RestartStack",
        "RollbackStack",
        "DeleteStack",
        "RestoreStack",
    ] {
        call(
            &guest_when,
            &guest_then,
            method,
            json!({"organisation":owner.username}),
        )
        .await?;
        guest_then.status(403)?.connect_code("permission_denied")?;
    }
    Ok(())
}

#[tokio::test]
async fn raw_stack_file_bound_survives_json_escaping_and_request_envelopes() -> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    registry.publish("acme/web", "1");
    let mut yaml = format!(
        "stack:\n  name: raw-bound\n  services:\n    web:\n      image: {}\n",
        registry.image("acme/web", "1"),
    );
    yaml.extend(std::iter::repeat_n('\n', 1024 * 1024 - yaml.len()));
    let mut input = json!({
        "organisation": owner.username,
        "yaml": yaml,
        "service": "",
        "refreshTemplate": "",
    });
    when.calling(
        &format!("{SERVICE}/PreviewStack"),
        &input.to_string().replace("\\n", "\\u000a"),
    )
    .await?;
    then.status(200)?;
    input["idempotencyKey"] = json!("raw-boundary");
    when.calling(
        &format!("{SERVICE}/DeployStack"),
        &input.to_string().replace("\\n", "\\u000a"),
    )
    .await?;
    then.status(200)?;
    let deployed = then.json()?;
    let version = deployed["stack"]["version"].clone();
    input["yaml"] = json!(format!("{yaml}\n"));
    input["expectedVersion"] = version;
    input["idempotencyKey"] = json!("oversized-boundary");
    for (method, body) in [
        (
            "PreviewStack",
            json!({"organisation": owner.username, "yaml": input["yaml"]}),
        ),
        ("DeployStack", input),
    ] {
        call(&when, &then, method, body).await?;
        then.status(400)?.connect_code("invalid_argument")?;
    }
    Ok(())
}
