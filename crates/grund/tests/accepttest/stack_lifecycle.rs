use crate::accepttest::{
    apps::{a_machine, app, ready_on},
    fixtures::{FakeRegistry, Then, When, testcase_configured},
    stacks::{token, token_call},
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const SERVICE: &str = "/grund.stack.v1.StackService";

async fn call(when: &When, then: &Then, method: &str, input: Value) -> anyhow::Result<Value> {
    when.calling(&format!("{SERVICE}/{method}"), &input.to_string())
        .await?;
    then.json()
}

async fn ready(when: &When, then: &Then, org: &str) -> anyhow::Result<Value> {
    let started = Instant::now();
    loop {
        let value = call(
            when,
            then,
            "GetStack",
            json!({"organisation":org,"name":"ordered"}),
        )
        .await?;
        then.status(200)?;
        let stack = &value["stack"];
        if stack["status"] == "ready" && stack["operation"].as_str().is_none_or(str::is_empty) {
            return Ok(stack.clone());
        }
        ensure!(
            stack["status"] != "halted" && started.elapsed() < Duration::from_secs(60),
            "stack did not converge: {stack}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn child(stack: &Value, name: &str) -> anyhow::Result<Value> {
    stack["services"]
        .as_array()
        .context("service list")?
        .iter()
        .find(|service| service["name"] == name)
        .cloned()
        .context("named service")
}

fn yaml(producer: &str, consumer: Option<&str>) -> String {
    let mut yaml = format!(
        "stack:\n  name: ordered\n  services:\n    producer:\n      image: {producer}\n      ports:\n        - name: http\n          port: 80\n          protocol: http\n      resources:\n        memory: 128 MiB\n        cpu: 0.1\n      release:\n        min_ready: 0\n        ready_deadline: 30\n        drain: 1\n"
    );
    if let Some(image) = consumer {
        yaml.push_str(&format!("    consumer:\n      image: {image}\n      depends_on: [producer]\n      env:\n        UPSTREAM_URL: ${{{{ producer.url }}}}\n      resources:\n        memory: 128 MiB\n        cpu: 0.1\n      release:\n        min_ready: 0\n        ready_deadline: 30\n        drain: 1\n"));
    }
    yaml
}

#[tokio::test]
async fn dependencies_start_after_success_and_removal_rollback_preserves_owned_identities()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _agent = a_machine(&when, &then, org, "stack-box").await?;
    registry.publish("acme/producer", "1");
    registry.publish("acme/consumer", "1");
    registry.publish("acme/consumer", "2");
    let producer_image = registry.image("acme/producer", "1");
    let first = yaml(&producer_image, Some(&registry.image("acme/consumer", "1")));
    call(
        &when,
        &then,
        "DeployStack",
        json!({"organisation":org,"yaml":first,"idempotencyKey":"initial"}),
    )
    .await?;
    then.status(200)?;
    let first = ready(&when, &then, org).await?;
    let producer = child(&first, "producer")?;
    let consumer = child(&first, "consumer")?;
    let producer_name = producer["appName"].as_str().context("producer app name")?;
    ensure!(
        producer_name.starts_with("ordered-producer-")
            && consumer["appName"]
                .as_str()
                .is_some_and(|name| name.starts_with("ordered-consumer-")),
        "members are not named for their stack and service: {first}"
    );
    let producer_before = app(&when, &then, org, producer_name).await?;
    ensure!(
        ready_on(&producer_before, 1) == 1,
        "producer must have completed its rollout"
    );
    let producer_copy = producer_before["replicas"][0]["replicaId"].clone();
    let second_yaml = yaml(&producer_image, Some(&registry.image("acme/consumer", "2")));
    let pending = call(&when,&then,"DeployStack",json!({"organisation":org,"yaml":second_yaml,"service":"consumer","expectedVersion":first["version"],"idempotencyKey":"consumer-update"})).await?;
    then.status(200)?;
    let pending_consumer = child(&pending["stack"], "consumer")?;
    ensure!(
        pending_consumer["desiredRelease"] == 2
            && pending_consumer["observedRunningReleases"] == json!([1])
            && child(&pending["stack"], "producer")?["ready"] == 1,
        "mutation response confused its desired replacement with the running old copy: {pending}"
    );
    let second = ready(&when, &then, org).await?;
    let producer_after = app(&when, &then, org, producer_name).await?;
    ensure!(
        producer_after["replicas"][0]["replicaId"] == producer_copy,
        "selected-service update replaced its dependency"
    );
    let consumer_name = consumer["appName"].as_str().context("consumer app name")?;
    ensure!(
        child(&second, "producer")?["appName"] == producer_name
            && child(&second, "consumer")?["appName"] == consumer_name,
        "an update renamed a member: {second}"
    );
    ensure!(
        ready_on(&app(&when, &then, org, consumer_name).await?, 2) == 1,
        "consumer update never started behind its successful dependency"
    );
    let reduced = yaml(&producer_image, None);
    let plan = call(
        &when,
        &then,
        "PreviewStack",
        json!({"organisation":org,"yaml":reduced}),
    )
    .await?;
    then.status(200)?;
    ensure!(
        plan["preview"]["removedServices"] == json!(["consumer"]),
        "preview omitted destructive intent"
    );
    let mut removal = json!({"organisation":org,"yaml":reduced,"expectedVersion":second["version"],"idempotencyKey":"remove-consumer"});
    call(&when, &then, "DeployStack", removal.clone()).await?;
    then.status(400)?.connect_code("invalid_argument")?;
    let unchanged = call(
        &when,
        &then,
        "GetStack",
        json!({"organisation":org,"name":"ordered"}),
    )
    .await?;
    then.status(200)?;
    ensure!(
        unchanged["stack"]["revision"] == second["revision"],
        "unconfirmed omission changed the committed bundle"
    );
    removal["confirmedRemovals"] = json!(["consumer"]);
    call(&when, &then, "DeployStack", removal).await?;
    then.status(200)?;
    let removed = ready(&when, &then, org).await?;
    ensure!(
        removed["services"]
            .as_array()
            .context("remaining services")?
            .iter()
            .all(|service| service["name"] != "consumer"),
        "removed child remains desired"
    );
    when.calling(
        "/grund.app.v1.AppService/RestoreApp",
        &json!({"organisation":org,"name":consumer_name}).to_string(),
    )
    .await?;
    then.connect_code("failed_precondition")?;
    call(&when,&then,"RollbackStack",json!({"organisation":org,"name":"ordered","revision":second["revision"],"expectedVersion":removed["version"],"idempotencyKey":"restore-prior-bundle"})).await?;
    then.status(200)?;
    let restored = ready(&when, &then, org).await?;
    ensure!(
        child(&restored, "consumer")?["appId"] == consumer["appId"]
            && child(&restored, "consumer")?["appName"] == consumer_name,
        "rollback changed retained app ownership"
    );
    ensure!(
        ready_on(&app(&when, &then, org, consumer_name).await?, 3) == 1,
        "retained consumer did not run its restored pinned image"
    );
    Ok(())
}

#[tokio::test]
async fn a_restart_distinguishes_its_unassigned_successor_from_the_running_execution()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _agent = a_machine(&when, &then, org, "stack-box").await?;
    registry.publish("acme/producer", "1");
    call(
        &when, &then, "DeployStack",
        json!({"organisation": org, "yaml": yaml(&registry.image("acme/producer", "1"), None), "idempotencyKey": "initial"}),
    ).await?;
    then.status(200)?;
    let before = ready(&when, &then, org).await?;
    let pending = call(
        &when, &then, "RestartStack",
        json!({"organisation": org, "name": "ordered", "service": "producer", "expectedVersion": before["version"], "idempotencyKey": "restart"}),
    ).await?;
    then.status(200)?;
    let pending_service = child(&pending["stack"], "producer")?;
    ensure!(
        pending_service["desiredRelease"].as_u64().unwrap_or(0) == 0
            && pending_service["observedRunningReleases"] == json!([1])
            && pending_service["ready"].as_u64().unwrap_or(0) == 0,
        "restart claimed an execution before its child release was assigned: {pending}"
    );
    let completed = ready(&when, &then, org).await?;
    let completed_service = child(&completed, "producer")?;
    ensure!(
        completed["revision"] == before["revision"]
            && completed_service["desiredRelease"] == 2
            && completed_service["observedRunningReleases"] == json!([2]),
        "completed restart did not report its actual new execution: {completed}"
    );
    Ok(())
}

async fn stack_volumes(when: &When, then: &Then, org: &str, app: &str) -> anyhow::Result<Value> {
    when.calling(
        "/grund.volume.v1.VolumeService/ListVolumes",
        &json!({"organisation": org, "app": app}).to_string(),
    )
    .await?;
    then.status(200)?;
    Ok(then.json()?["volumes"].clone())
}

#[tokio::test]
async fn a_stack_restored_after_its_volume_was_purged_runs_on_a_fresh_empty_volume()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let agent = a_machine(&when, &then, org, "stack-box").await?;
    registry.publish("acme/db", "1");
    let file = format!(
        "stack:\n  name: ordered\n  services:\n    db:\n      image: {}\n      volumes:\n        data:\n          path: /data\n      resources:\n        memory: 128 MiB\n        cpu: 0.1\n      release:\n        min_ready: 0\n        ready_deadline: 30\n        drain: 1\n",
        registry.image("acme/db", "1")
    );
    call(
        &when,
        &then,
        "DeployStack",
        json!({"organisation":org,"yaml":file,"idempotencyKey":"initial"}),
    )
    .await?;
    then.status(200)?;
    let first = ready(&when, &then, org).await?;
    let db = child(&first, "db")?;
    let db_name = db["appName"].as_str().context("db app name")?;
    let original = stack_volumes(&when, &then, org, db_name).await?;
    ensure!(
        original.as_array().is_some_and(|v| v.len() == 1) && original[0]["status"] == "attached",
        "the first deploy attached one volume: {original}"
    );
    let original = original[0].clone();
    let original_id = original["volumeId"].as_str().context("volume ID")?;
    let original_root = agent.dir.join("volumes").join(original_id);
    std::fs::write(original_root.join("customer-marker"), b"purged later")?;

    call(&when,&then,"DeleteStack",json!({"organisation":org,"name":"ordered","expectedVersion":first["version"],"idempotencyKey":"delete"})).await?;
    then.status(200)?;
    let started = Instant::now();
    let deleted = loop {
        let value = call(
            &when,
            &then,
            "GetStack",
            json!({"organisation":org,"name":"ordered"}),
        )
        .await?;
        then.status(200)?;
        if value["stack"]["status"] == "deleted" {
            break value["stack"].clone();
        }
        ensure!(
            started.elapsed() < Duration::from_secs(60),
            "stack deletion did not finish: {value}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let pending = stack_volumes(&when, &then, org, db_name).await?;
    ensure!(
        pending[0]["status"] == "pending_deletion",
        "deletion retains the volume: {pending}"
    );
    when.calling(
        "/grund.volume.v1.VolumeService/PurgeVolumeNow",
        &json!({
            "organisation": org,
            "app": db_name,
            "volumeId": original_id,
            "expectedVersion": pending[0]["version"],
            "reason": "verified test data cleanup"
        })
        .to_string(),
    )
    .await?;
    then.status(200)?;
    let started = Instant::now();
    while original_root.exists()
        || !stack_volumes(&when, &then, org, db_name)
            .await?
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        ensure!(
            started.elapsed() < Duration::from_secs(45),
            "the purge was not erased and acknowledged"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    call(&when,&then,"RestoreStack",json!({"organisation":org,"name":"ordered","expectedVersion":deleted["version"],"idempotencyKey":"restore"})).await?;
    then.status(200)?;
    let restored = ready(&when, &then, org).await?;
    ensure!(
        child(&restored, "db")?["appId"] == db["appId"],
        "restore kept the service's app identity: {restored}"
    );
    let fresh = stack_volumes(&when, &then, org, db_name).await?;
    ensure!(
        fresh.as_array().is_some_and(|v| v.len() == 1),
        "one fresh volume: {fresh}"
    );
    let fresh = &fresh[0];
    let fresh_id = fresh["volumeId"].as_str().context("fresh volume ID")?;
    ensure!(
        fresh_id != original_id
            && fresh["status"] == "attached"
            && fresh["name"] == original["name"]
            && fresh["path"] == original["path"]
            && fresh["backup"] == original["backup"],
        "the fresh volume matches the declaration under a new identity: {fresh} vs {original}"
    );
    let fresh_root = agent.dir.join("volumes").join(fresh_id);
    ensure!(
        fresh_root.exists() && !fresh_root.join("customer-marker").exists(),
        "the fresh volume is a new empty directory"
    );
    ensure!(
        agent.containers().iter().any(|container| {
            container["spec"]["volumes"][0]["source"] == fresh_root.to_string_lossy().as_ref()
        }),
        "the restored service mounts the fresh volume: {:?}",
        agent.containers()
    );
    Ok(())
}

fn stack_reason(error: &Value) -> String {
    use base64::Engine;
    error["details"]
        .as_array()
        .and_then(|d| d.iter().find(|d| d["type"] == "grund.stack.v1.ErrorReason"))
        .and_then(|d| d["value"].as_str())
        .and_then(|v| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(v.trim_end_matches('='))
                .ok()
        })
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_default()
}

fn pinned(web: &str) -> String {
    let service = |name: &str, cpu: &str| {
        format!(
            "    {name}:\n      image: {{image}}\n      resources:\n        memory: 64 MiB\n        cpu: {cpu}\n      release:\n        min_ready: 0\n        ready_deadline: 30\n        drain: 1\n"
        )
    };
    format!(
        "stack:\n  name: ordered\n  machines: [cap-box]\n  services:\n{}{}{}",
        service("db", "2.5"),
        service("restore", "0.1"),
        web
    )
}

#[tokio::test]
async fn a_rollout_whose_peak_exceeds_every_eligible_machine_is_refused_and_one_that_fits_deploys()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _agent = a_machine(&when, &then, org, "cap-box").await?;
    registry.publish("acme/service", "1");
    let image = registry.image("acme/service", "1");
    let web = |copies: u32, cpu: &str| {
        format!(
            "    web:\n      image: {{image}}\n      copies: {copies}\n      restart: rolling\n      resources:\n        memory: 64 MiB\n        cpu: {cpu}\n      release:\n        min_ready: 0\n        ready_deadline: 30\n        drain: 1\n        max_surge: 1\n        max_unavailable: 0\n"
        )
    };
    let file = |web: String| pinned(&web).replace("{image}", &image);
    call(
        &when,
        &then,
        "DeployStack",
        json!({"organisation":org,"yaml":file(web(1, "0.5")),"idempotencyKey":"first"}),
    )
    .await?;
    then.status(200)?;
    let first = ready(&when, &then, org).await?;

    let wedged = file(web(2, "0.35"));
    let preview = call(
        &when,
        &then,
        "PreviewStack",
        json!({"organisation":org,"yaml":wedged}),
    )
    .await?;
    then.connect_code("failed_precondition")?;
    let message = preview["message"].as_str().unwrap_or_default();
    ensure!(
        message.contains("stack.services.web")
            && message.contains("3800 mCPU")
            && message.contains("allocatable 3750 mCPU"),
        "preview did not name the service and its peak against the machine: {preview}"
    );
    let refused = call(&when,&then,"DeployStack",json!({"organisation":org,"yaml":wedged,"expectedVersion":first["version"],"idempotencyKey":"wedged"})).await?;
    then.connect_code("failed_precondition")?;
    ensure!(
        refused["message"] == preview["message"]
            && stack_reason(&refused).contains("insufficient_capacity"),
        "deploy accepted or misreported a revision that can never fit: {refused}"
    );
    let unchanged = call(
        &when,
        &then,
        "GetStack",
        json!({"organisation":org,"name":"ordered"}),
    )
    .await?;
    then.status(200)?;
    ensure!(
        unchanged["stack"]["revision"] == first["revision"]
            && unchanged["stack"]["status"] == "ready",
        "refused revision changed the stack: {unchanged}"
    );

    call(&when,&then,"DeployStack",json!({"organisation":org,"yaml":file(web(2, "0.3")),"expectedVersion":first["version"],"idempotencyKey":"fits"})).await?;
    then.status(200)?;
    let second = ready(&when, &then, org).await?;
    ensure!(
        second["revision"] != first["revision"]
            && child(&second, "web")?["ready"] == 2
            && second["failure"].as_str().is_none_or(str::is_empty),
        "a rollout that fits did not reach ready: {second}"
    );
    Ok(())
}

#[tokio::test]
async fn an_app_restricted_deploy_token_redeploys_only_the_stack_it_covers() -> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let (_, client, result) = given.testcase.another_browser();
    let _agent = a_machine(&when, &then, org, "stack-box").await?;
    registry.publish("acme/web", "1");
    registry.publish("acme/web", "2");
    let stack = |name: &str, tag: &str, extra: &str| {
        let image = registry.image("acme/web", tag);
        format!(
            "stack:\n  name: {name}\n  services:\n    web:\n      image: {image}\n      resources:\n        memory: 64 MiB\n        cpu: 0.1\n      release:\n        min_ready: 0\n        ready_deadline: 30\n        drain: 1\n{extra}"
        )
    };
    for name in ["ordered", "other"] {
        call(
            &when,
            &then,
            "DeployStack",
            json!({"organisation":org,"yaml":stack(name, "1", ""),"idempotencyKey":name}),
        )
        .await?;
        then.status(200)?;
    }
    let first = ready(&when, &then, org).await?;
    let apps = vec![
        child(&first, "web")?["appName"]
            .as_str()
            .context("web app name")?
            .to_string(),
    ];
    let bot = token(
        &when,
        &then,
        org,
        "release-bot",
        "TOKEN_SCOPE_DEPLOY",
        &apps,
    )
    .await?;
    for widening in [
        json!({"confirmedRemovals":["web"]}),
        json!({"secrets":[{"service":"web","name":"api-key","value":"never-stored"}]}),
        json!({"refreshTemplate":"web"}),
    ] {
        let mut body = json!({"organisation":org,"yaml":stack("ordered", "2", ""),
            "expectedVersion":first["version"],"idempotencyKey":"widen"});
        for (key, value) in widening.as_object().into_iter().flatten() {
            body[key] = value.clone();
        }
        let refused = token_call(&client, &result, &bot, "DeployStack", body).await?;
        result.status(403)?.connect_code("permission_denied")?;
        ensure!(
            refused["message"]
                == "an app-restricted token cannot remove services, set secrets or refresh templates",
            "{refused}"
        );
    }
    let sidecar = "    sidecar:\n      image: busybox\n";
    for (name, extra, key) in [
        ("other", "", "other"),
        ("other", "", "other-bot"),
        ("brand-new", "", "brand-new"),
        ("ordered", sidecar, "sidecar"),
    ] {
        let refused = token_call(
            &client,
            &result,
            &bot,
            "DeployStack",
            json!({"organisation":org,"yaml":stack(name, "2", extra),"idempotencyKey":key}),
        )
        .await?;
        result.status(404)?.connect_code("not_found")?;
        ensure!(refused.get("stack").is_none(), "{refused}");
    }
    let request = json!({"organisation":org,"yaml":stack("ordered", "2", ""),
        "expectedVersion":first["version"],"idempotencyKey":"forest-intent-1"});
    let deployed = token_call(&client, &result, &bot, "DeployStack", request.clone()).await?;
    result.status(200)?;
    ensure!(
        deployed["stack"]["revision"] == 2
            && deployed["stack"]["yaml"] == stack("ordered", "2", ""),
        "{deployed}"
    );
    let replayed = token_call(&client, &result, &bot, "DeployStack", request).await?;
    result.status(200)?;
    ensure!(replayed["stack"]["revision"] == 2, "{replayed}");
    ready(&when, &then, org).await?;
    ensure!(
        ready_on(&app(&when, &then, org, &apps[0]).await?, 2) == 1,
        "the token's release never went live"
    );
    Ok(())
}
