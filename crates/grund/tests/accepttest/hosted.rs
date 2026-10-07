use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::accepttest::{
    apps::{Agent, a_running_agent, call, data_dir, live, quick, ready_on, spec, until},
    fixtures::{FakeRegistry, Then, When, random_hex, testcase_configured},
    machines::origin,
};

const POOL: &str = "/grund.machine.v1.ManagementPoolService";
const MACHINES: &str = "/grund.machine.v1.MachineService";

async fn joined_with(when: &When, token: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = data_dir();
    let url = origin(when);
    let token = token.to_string();
    let joined = {
        let dir = dir.clone();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(crate::accepttest::fixtures::grund_binary())
                .arg("join")
                .arg("--data-dir")
                .arg(&dir)
                .args(["--url", &url, &token])
                .env_clear()
                .env("RUST_LOG", "warn")
                .output()
        })
        .await??
    };
    anyhow::ensure!(
        joined.status.success(),
        "{}",
        String::from_utf8_lossy(&joined.stderr)
    );
    Ok(dir)
}

async fn exits_within(agent: &mut Agent, within: Duration, why: &str) -> anyhow::Result<()> {
    let started = Instant::now();
    while !agent.has_exited() {
        anyhow::ensure!(
            started.elapsed() < within,
            "the agent did not end within {within:?} when {why}: {}",
            std::fs::read_to_string(agent.dir.join("agent.log")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

async fn pool_call(
    when: &When,
    then: &Then,
    procedure: &str,
    body: Value,
) -> anyhow::Result<Value> {
    when.calling(&format!("{POOL}/{procedure}"), &body.to_string())
        .await?;
    then.status(200)?;
    then.json()
}

#[tokio::test]
async fn a_leased_machine_runs_its_lessees_apps_and_drops_them_when_the_lease_ends()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let operator = format!("ops-{}", random_hex(4));
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_OPERATOR_ORGANISATION", &operator),
        ("GRUND_INSECURE_REGISTRIES", &registry.host),
    ])
    .await?
    else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;
    let token = pool_call(
        &when,
        &then,
        "CreateRegistrationToken",
        json!({"name": "gm-1"}),
    )
    .await?["token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let dir = joined_with(&when, &token).await?;
    let record: Value = serde_json::from_slice(&std::fs::read(dir.join("machine.json"))?)?;
    anyhow::ensure!(record["pool"] == "management", "{record}");
    let machine_id = record["machine_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let mut agent = a_running_agent(dir.clone())?;

    let (lessee, lessee_when, lessee_then) = given.testcase.another_browser();
    let tenant = lessee.a_signed_in_account().await?;
    let org = tenant.username.as_str();
    pool_call(
        &when,
        &then,
        "LeaseMachine",
        json!({"machineId": machine_id, "organisation": org, "name": "web-1"}),
    )
    .await?;
    exits_within(&mut agent, Duration::from_secs(20), "it was leased").await?;
    let mut agent = a_running_agent(dir.clone())?;
    let started = Instant::now();
    while !dir.join("lease.json").exists() {
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(20),
            "the agent kept no lease"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let lease: Value = serde_json::from_slice(&std::fs::read(dir.join("lease.json"))?)?;
    anyhow::ensure!(
        lease["organisation_key"]["purpose"] == "organisation",
        "{lease}"
    );
    anyhow::ensure!(
        lease["network"]["slot"].as_u64().unwrap_or(0) >= 1,
        "{lease}"
    );

    registry.publish("acme/hello", "1");
    call(
        &lessee_when,
        &lessee_then,
        "CreateApp",
        json!({"organisation": org, "name": "hello", "settings": quick(1)}),
    )
    .await?;
    lessee_then.status(200)?;
    call(
        &lessee_when,
        &lessee_then,
        "Deploy",
        json!({"organisation": org, "name": "hello", "spec": spec(&registry.image("acme/hello", "1"), json!([])), "note": "first"}),
    )
    .await?;
    lessee_then.status(200)?;
    until(
        &lessee_when,
        &lessee_then,
        org,
        "hello",
        Duration::from_secs(60),
        "a copy ready on the leased machine",
        |app| live(app, 1) && ready_on(app, 1) == 1,
    )
    .await?;
    anyhow::ensure!(agent.containers().len() == 1, "{:?}", agent.containers());

    pool_call(&when, &then, "EndLease", json!({"machineId": machine_id})).await?;
    exits_within(&mut agent, Duration::from_secs(20), "its lease ended").await?;
    let agent = a_running_agent(dir.clone())?;
    let started = Instant::now();
    while !agent.containers().is_empty() {
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(20),
            "the lessee's copy still runs after the lease ended: {:?}",
            agent.containers()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    anyhow::ensure!(
        !dir.join("lease.json").exists() && !dir.join("applied.json").exists(),
        "a machine whose lease ended keeps nothing of the lessee's"
    );
    lessee_when
        .calling(
            &format!("{MACHINES}/ListMachines"),
            &json!({"organisation": org}).to_string(),
        )
        .await?;
    lessee_then.status(200)?;
    let listed = lessee_then.json()?;
    anyhow::ensure!(
        listed["machines"].as_array().is_none_or(|m| m.is_empty()),
        "{listed}"
    );
    Ok(())
}

#[tokio::test]
async fn the_operator_leases_ends_and_revokes_on_the_pool_page_which_no_one_else_sees()
-> anyhow::Result<()> {
    let operator = format!("ops-{}", random_hex(4));
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_OPERATOR_ORGANISATION", &operator)]).await?
    else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;
    let token = pool_call(
        &when,
        &then,
        "CreateRegistrationToken",
        json!({"name": "gm-p"}),
    )
    .await?["token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let dir = joined_with(&when, &token).await?;
    let record: Value = serde_json::from_slice(&std::fs::read(dir.join("machine.json"))?)?;
    let machine_id = record["machine_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    when.visiting(&format!("/{operator}/machines")).await?;
    then.status(200)?.body_contains("Management pool")?;
    when.visiting(&format!("/{operator}/pool")).await?;
    then.status(200)?
        .body_contains("gm-p")?
        .body_contains("Available")?
        .body_contains("Lease it")?
        .body_lacks("Search apps")?
        .body_lacks(">Add machine<")?;

    let (lessee, lessee_when, lessee_then) = given.testcase.another_browser();
    let tenant = lessee.a_signed_in_account().await?;
    let org = tenant.username.clone();
    lessee_when.visiting(&format!("/{org}/pool")).await?;
    lessee_then.status(404)?;
    lessee_when.visiting(&format!("/{operator}/pool")).await?;
    lessee_then.status(404)?;
    lessee_when.visiting(&format!("/{org}/machines")).await?;
    lessee_then.status(200)?.body_lacks("Management pool")?;

    when.submitting(
        &format!("/{operator}/pool"),
        &format!("/{operator}/pool/{machine_id}/lease"),
        &[("organisation", &org), ("name", "web-1")],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("/{operator}/pool?done=leased"))?;
    when.visiting(&format!("/{operator}/pool?done=leased"))
        .await?;
    then.status(200)?
        .body_contains("Machine leased.")?
        .body_contains(&format!("Leased to {org} as web-1"))?;
    lessee_when.visiting(&format!("/{org}/machines")).await?;
    lessee_then
        .status(200)?
        .body_contains("web-1")?
        .body_contains(">Hosted<")?;

    when.submitting(
        &format!("/{operator}/pool"),
        &format!("/{operator}/pool/{machine_id}/lease"),
        &[("organisation", &org), ("name", "web-2")],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("/{operator}/pool?error=not-available"))?;

    when.submitting(
        &format!("/{operator}/pool"),
        &format!("/{operator}/pool/{machine_id}/end"),
        &[],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("/{operator}/pool?done=ended-by-hand"))?;
    when.visiting(&format!("/{operator}/pool")).await?;
    then.status(200)?.body_contains("Returning")?;
    lessee_when.visiting(&format!("/{org}/machines")).await?;
    lessee_then.status(200)?.body_lacks("web-1")?;

    lessee_when
        .submitting_with_token(
            &format!("/{operator}/pool/{machine_id}/revoke"),
            "forged",
            &[],
        )
        .await?;
    lessee_then.status_in(&[403, 404])?;

    when.submitting(
        &format!("/{operator}/pool"),
        &format!("/{operator}/pool/{machine_id}/revoke"),
        &[],
    )
    .await?;
    then.status(303)?
        .redirects_to(&format!("/{operator}/pool?done=revoked-by-hand"))?;
    when.visiting(&format!("/{operator}/pool")).await?;
    then.status(200)?
        .body_lacks("gm-p")?
        .body_contains("No machines in the pool.")?;
    Ok(())
}
