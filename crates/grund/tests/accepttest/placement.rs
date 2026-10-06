use std::{collections::BTreeMap, time::Duration};

use serde_json::{Value, json};

use crate::accepttest::{
    apps::{a_machine, call, live, ready_on, spec, until},
    fixtures::{FakeRegistry, Then, When, testcase_configured},
};

const MACHINES: &str = "/grund.machine.v1.MachineService";

async fn machine_ids(
    when: &When,
    then: &Then,
    organisation: &str,
) -> anyhow::Result<BTreeMap<String, String>> {
    when.calling(
        &format!("{MACHINES}/ListMachines"),
        &json!({"organisation": organisation}).to_string(),
    )
    .await?;
    then.status(200)?;
    Ok(then.json()?["machines"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| {
            (
                m["name"].as_str().unwrap_or_default().to_string(),
                m["machineId"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect())
}

async fn machine_call(
    when: &When,
    then: &Then,
    procedure: &str,
    body: Value,
) -> anyhow::Result<Value> {
    when.calling(&format!("{MACHINES}/{procedure}"), &body.to_string())
        .await?;
    then.json()
}

fn running_on(app: &Value) -> Vec<String> {
    let mut on: Vec<String> = app["replicas"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["state"] == "REPLICA_STATE_RUNNING")
        .map(|r| r["machineName"].as_str().unwrap_or_default().to_string())
        .collect();
    on.sort();
    on
}

fn settings(copies: u32, placement: Value) -> Value {
    json!({
        "copies": copies,
        "rollout": {"minReadySeconds": 1, "readyDeadlineSeconds": 30, "drainSeconds": 1},
        "rescheduleAfterSeconds": 30,
        "placement": placement,
    })
}

#[tokio::test]
async fn copies_spread_over_zones_and_leave_a_machine_taken_out_of_service_with_none_missing()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _a1 = a_machine(&when, &then, org, "a1").await?;
    let _a2 = a_machine(&when, &then, org, "a2").await?;
    let _b1 = a_machine(&when, &then, org, "b1").await?;
    let ids = machine_ids(&when, &then, org).await?;
    for (name, zone) in [("a1", "a"), ("a2", "a"), ("b1", "b")] {
        let labelled = machine_call(
            &when,
            &then,
            "SetMachineLabels",
            json!({"organisation": org, "machineId": ids[name], "labels": {"zone": zone}}),
        )
        .await?;
        then.status(200)?;
        anyhow::ensure!(labelled["machine"]["labels"]["zone"] == zone, "{labelled}");
    }
    registry.publish("acme/hello", "1");
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "hello", "settings": settings(2, json!({"spreadBy": "zone"}))}),
    )
    .await?;
    then.status(200)?;
    call(&when, &then, "Deploy", json!({"organisation": org, "name": "hello", "spec": spec(&registry.image("acme/hello", "1"), json!([]))})).await?;
    then.status(200)?;
    let spread = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(30),
        "one copy in each zone",
        |a| live(a, 1) && ready_on(a, 1) == 2,
    )
    .await?;
    let on = running_on(&spread);
    anyhow::ensure!(
        on.contains(&"b1".to_string()) && on.len() == 2,
        "zone b has a copy: {on:?}"
    );
    anyhow::ensure!(
        spread["settings"]["placement"]["spreadBy"] == "zone",
        "{spread}"
    );

    let out = machine_call(
        &when,
        &then,
        "SetMachineInService",
        json!({"organisation": org, "machineId": ids["b1"], "inService": false}),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(out["machine"]["outOfServiceSince"].is_string(), "{out}");
    let fewest = std::cell::Cell::new(2);
    let moved = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(60),
        "both copies off b1",
        |a| {
            fewest.set(fewest.get().min(ready_on(a, 1)));
            ready_on(a, 1) == 2 && !running_on(a).contains(&"b1".to_string())
        },
    )
    .await;
    let moved = moved?;
    anyhow::ensure!(fewest.get() == 2, "a copy was missing while b1 emptied");
    anyhow::ensure!(
        running_on(&moved) == vec!["a1".to_string(), "a2".to_string()],
        "the spread falls back to machines: {:?}",
        running_on(&moved)
    );

    when.visiting(&format!("/{org}/machines")).await?;
    then.status(200)?
        .body_contains("zone=a")?
        .body_contains("Out of service")?
        .body_contains("Put back in service")?;

    machine_call(
        &when,
        &then,
        "SetMachineInService",
        json!({"organisation": org, "machineId": ids["b1"], "inService": true}),
    )
    .await?;
    then.status(200)?;
    machine_call(
        &when,
        &then,
        "SetMachineLabels",
        json!({"organisation": org, "machineId": ids["a1"], "labels": {"Zone": "a"}}),
    )
    .await?;
    then.status(400)?.connect_code("invalid_argument")?;
    Ok(())
}

#[tokio::test]
async fn copies_leave_a_machine_whose_label_no_longer_matches_and_the_app_says_what_it_waits_for()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _one = a_machine(&when, &then, org, "one").await?;
    let _two = a_machine(&when, &then, org, "two").await?;
    let ids = machine_ids(&when, &then, org).await?;
    for name in ["one", "two"] {
        machine_call(
            &when,
            &then,
            "SetMachineLabels",
            json!({"organisation": org, "machineId": ids[name], "labels": {"disk": "ssd"}}),
        )
        .await?;
        then.status(200)?;
    }
    registry.publish("acme/hello", "1");
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "hello", "settings": settings(2, json!({"labels": {"disk": "ssd"}}))}),
    )
    .await?;
    then.status(200)?;
    call(&when, &then, "Deploy", json!({"organisation": org, "name": "hello", "spec": spec(&registry.image("acme/hello", "1"), json!([]))})).await?;
    then.status(200)?;
    until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(30),
        "two copies, one on each",
        |a| live(a, 1) && ready_on(a, 1) == 2 && running_on(a) == ["one", "two"],
    )
    .await?;
    machine_call(
        &when,
        &then,
        "SetMachineLabels",
        json!({"organisation": org, "machineId": ids["two"], "labels": {}}),
    )
    .await?;
    then.status(200)?;
    until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(60),
        "both copies on one",
        |a| ready_on(a, 1) == 2 && running_on(a) == ["one", "one"],
    )
    .await?;
    call(
        &when,
        &then,
        "ConfigureApp",
        json!({"organisation": org, "name": "hello", "settings": settings(2, json!({"labels": {"disk": "nvme"}}))}),
    )
    .await?;
    then.status(200)?;
    let waiting = until(
        &when,
        &then,
        org,
        "hello",
        Duration::from_secs(30),
        "the app waiting for an nvme machine",
        |a| a["waiting"][0]["reason"] == "no_matching_machine",
    )
    .await?;
    anyhow::ensure!(
        waiting["waiting"][0]["message"] == "Waiting for a machine labelled disk=nvme.",
        "{waiting}"
    );
    anyhow::ensure!(
        ready_on(&waiting, 1) == 2,
        "nothing to move to: the copies stay where they run"
    );
    when.visiting(&format!("/{org}/apps/hello/settings"))
        .await?;
    then.status(200)?.body_contains("Labelled disk=nvme")?;
    when.visiting(&format!("/{org}/apps/hello")).await?;
    then.status(200)?
        .body_contains("2 of 2 copies running. Waiting for a machine labelled disk=nvme.")?;
    Ok(())
}

#[tokio::test]
async fn another_organisation_cannot_label_a_machine_or_take_it_out_of_service()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let _mine = a_machine(&when, &then, org, "mine").await?;
    let id = machine_ids(&when, &then, org).await?["mine"].clone();
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    let stranger = outsider.a_signed_in_account().await?;
    for organisation in [org, stranger.username.as_str()] {
        for (procedure, body) in [
            (
                "SetMachineLabels",
                json!({"organisation": organisation, "machineId": id, "labels": {"zone": "x"}}),
            ),
            (
                "SetMachineInService",
                json!({"organisation": organisation, "machineId": id, "inService": false}),
            ),
        ] {
            machine_call(&outsider_when, &outsider_then, procedure, body).await?;
            outsider_then.status(404)?.connect_code("not_found")?;
        }
    }
    let unchanged = machine_call(
        &when,
        &then,
        "GetMachine",
        json!({"organisation": org, "machineId": id}),
    )
    .await?;
    anyhow::ensure!(
        unchanged["machine"]["labels"]
            .as_object()
            .is_none_or(|l| l.is_empty())
            && unchanged["machine"]["outOfServiceSince"].is_null(),
        "{unchanged}"
    );
    Ok(())
}
