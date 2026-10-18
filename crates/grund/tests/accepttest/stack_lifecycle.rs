use crate::accepttest::{
    apps::{a_machine, app, ready_on},
    fixtures::{FakeRegistry, Then, When, testcase_configured},
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
        child(&restored, "consumer")?["appId"] == consumer["appId"],
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
