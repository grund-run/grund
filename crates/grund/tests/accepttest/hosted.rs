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
async fn migration_pause_requires_capacity_token_and_only_its_owner_can_clear_it()
-> anyhow::Result<()> {
    use crate::accepttest::fixtures::{CAPACITY_TOKEN, FakeCapacity};

    let capacity = FakeCapacity::start().await?;
    let operator = format!("ops-{}", random_hex(4));
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_OPERATOR_ORGANISATION", &operator),
        ("GRUND_CAPACITY_URL", &capacity.url),
        ("GRUND_CAPACITY_TOKEN", CAPACITY_TOKEN),
    ])
    .await?
    else {
        return Ok(());
    };
    let Some(database_url) = when.testcase.fixture.database_url() else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    let token = pool_call(
        &when,
        &then,
        "CreateRegistrationToken",
        json!({"name": "gm-pause"}),
    )
    .await?["token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let dir = joined_with(&when, &token).await?;
    let record: Value = serde_json::from_slice(&std::fs::read(dir.join("machine.json"))?)?;
    let machine_id = record["machine_id"].as_str().unwrap_or_default();
    let provider_id = "8eb3976b-130b-4437-923d-27b58d20f921";
    let pool = sqlx::PgPool::connect(&database_url).await?;
    sqlx::query("UPDATE grund_machines SET provider_machine_id = $1 WHERE machine_id = $2")
        .bind(provider_id)
        .bind(sqlx::types::Uuid::parse_str(machine_id)?)
        .execute(&pool)
        .await?;
    let procedure = format!("{POOL}/SetMigrationPause");
    let migration_id = "60fe5784-ac41-4113-a4e8-16ef838106bc";
    let other_migration = "35d10c1d-f471-47e7-845d-2eddf0e6dc5a";
    let pause = json!({"providerMachineId":provider_id,"migrationId":migration_id,"paused":true});
    when.calling(&procedure, &pause.to_string()).await?;
    then.status(401)?.connect_code("unauthenticated")?;
    when.calling_with(
        &procedure,
        &pause.to_string(),
        &[("Authorization", "Bearer wrong")],
    )
    .await?;
    then.status(401)?.connect_code("unauthenticated")?;
    when.calling_with(
        &procedure,
        &pause.to_string(),
        &[("Authorization", &format!("Bearer {CAPACITY_TOKEN}"))],
    )
    .await?;
    then.status(200)?;
    let recorded: String = sqlx::query_scalar(
        "SELECT migration_id::text FROM grund_machine_migration_pauses WHERE machine_id = $1 AND expires_at > now()",
    )
    .bind(sqlx::types::Uuid::parse_str(machine_id)?)
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        recorded == migration_id,
        "wrong migration paused: {recorded}"
    );
    let other_pause =
        json!({"providerMachineId":provider_id,"migrationId":other_migration,"paused":true});
    when.calling_with(
        &procedure,
        &other_pause.to_string(),
        &[("Authorization", &format!("Bearer {CAPACITY_TOKEN}"))],
    )
    .await?;
    then.status(404)?.connect_code("not_found")?;
    let clear =
        json!({"providerMachineId":provider_id,"migrationId":other_migration,"paused":false});
    when.calling_with(
        &procedure,
        &clear.to_string(),
        &[("Authorization", &format!("Bearer {CAPACITY_TOKEN}"))],
    )
    .await?;
    then.status(200)?;
    let still_paused: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM grund_machine_migration_pauses WHERE machine_id = $1)",
    )
    .bind(sqlx::types::Uuid::parse_str(machine_id)?)
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(still_paused, "a different migration cleared the drain");
    let clear = json!({"providerMachineId":provider_id,"migrationId":migration_id,"paused":false});
    when.calling_with(
        &procedure,
        &clear.to_string(),
        &[("Authorization", &format!("Bearer {CAPACITY_TOKEN}"))],
    )
    .await?;
    then.status(200)?;
    let deadline_seconds: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM expires_at - clear_requested_at)::float8 \
         FROM grund_machine_migration_pauses WHERE machine_id = $1",
    )
    .bind(sqlx::types::Uuid::parse_str(machine_id)?)
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        (9.0..=11.0).contains(&deadline_seconds),
        "Fleet clear released the machine before recovery or lacked its 10s deadline: {deadline_seconds}"
    );
    when.calling_with(
        &procedure,
        &pause.to_string(),
        &[("Authorization", &format!("Bearer {CAPACITY_TOKEN}"))],
    )
    .await?;
    then.status(200)?;
    let retry_deadline_seconds: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM expires_at - clear_requested_at)::float8 \
         FROM grund_machine_migration_pauses WHERE machine_id = $1",
    )
    .bind(sqlx::types::Uuid::parse_str(machine_id)?)
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        (retry_deadline_seconds - deadline_seconds).abs() < 0.001,
        "repeated pause reopened a settled migration"
    );
    let expired = sqlx::query(
        "UPDATE grund_machine_migration_pauses \
         SET expires_at = clock_timestamp() - interval '1 millisecond' \
         WHERE machine_id = $1 AND migration_id = $2",
    )
    .bind(sqlx::types::Uuid::parse_str(machine_id)?)
    .bind(sqlx::types::Uuid::parse_str(migration_id)?)
    .execute(&pool)
    .await?
    .rows_affected();
    anyhow::ensure!(
        expired == 1,
        "migration pause disappeared before deadline setup"
    );
    let started = Instant::now();
    let inbox = loop {
        when.calling(
            "/grund.notification.v1.NotificationService/ListNotifications",
            "{}",
        )
        .await?;
        then.status(200)?;
        let inbox = then.json()?;
        if inbox["notifications"].as_array().is_some_and(|items| {
            items
                .iter()
                .filter(|item| item["kind"] == "operator.migration_timeout")
                .count()
                == 1
        }) {
            break inbox;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(180),
            "settling expiry did not notify operator: {inbox}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    anyhow::ensure!(
        inbox["notifications"].as_array().is_some_and(|items| items
            .iter()
            .filter(|item| item["kind"] == "operator.migration_timeout")
            .count()
            == 1),
        "migration timeout duplicated: {inbox}"
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
        "operator timeout reached another org: {unrelated}"
    );
    Ok(())
}

#[tokio::test]
async fn a_leased_machine_runs_its_lessees_apps_and_drops_them_when_the_lease_ends()
-> anyhow::Result<()> {
    use crate::accepttest::fixtures::{CAPACITY_TOKEN, FakeCapacity};

    let capacity = FakeCapacity::start().await?;
    let registry = FakeRegistry::start().await?;
    let operator = format!("ops-{}", random_hex(4));
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_OPERATOR_ORGANISATION", &operator),
        ("GRUND_INSECURE_REGISTRIES", &registry.host),
        ("GRUND_CAPACITY_URL", &capacity.url),
        ("GRUND_CAPACITY_TOKEN", CAPACITY_TOKEN),
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
    let database_url = when
        .testcase
        .fixture
        .database_url()
        .ok_or_else(|| anyhow::anyhow!("hosted acceptance needs its database"))?;
    let pool = sqlx::PgPool::connect(&database_url).await?;
    let provider_id = "157f7772-b947-49a6-8183-943def0c0200";
    let machine_uuid = sqlx::types::Uuid::parse_str(&machine_id)?;
    sqlx::query("UPDATE grund_machines SET provider_machine_id = $1 WHERE machine_id = $2")
        .bind(provider_id)
        .bind(machine_uuid)
        .execute(&pool)
        .await?;
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
    let agent = a_running_agent(dir.clone())?;
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
    lessee_when
        .calling(
            &format!("{MACHINES}/ListMachines"),
            &json!({"organisation": org}).to_string(),
        )
        .await?;
    lessee_then.status(200)?;
    let customer_id = lessee_then.json()?["machines"][0]["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let shown = call(
        &lessee_when,
        &lessee_then,
        "GetApp",
        json!({"organisation": org, "name": "hello"}),
    )
    .await?;
    anyhow::ensure!(
        !customer_id.is_empty()
            && customer_id != machine_id
            && shown["app"]["replicas"][0]["machineId"] == customer_id,
        "{shown}"
    );

    let procedure = format!("{POOL}/SetMigrationPause");
    let migration_id = "08097eb6-5a81-481a-9dde-16c93a354501";
    let bearer = format!("Bearer {CAPACITY_TOKEN}");
    let pause = json!({"providerMachineId":provider_id,"migrationId":migration_id,"paused":true});
    when.calling_with(
        &procedure,
        &pause.to_string(),
        &[("Authorization", &bearer)],
    )
    .await?;
    then.status(200)?;
    drop(agent);
    let clear = json!({"providerMachineId":provider_id,"migrationId":migration_id,"paused":false});
    when.calling_with(
        &procedure,
        &clear.to_string(),
        &[("Authorization", &bearer)],
    )
    .await?;
    then.status(200)?;
    let pending: (bool, bool) = sqlx::query_as(
        "SELECT clear_requested_at IS NOT NULL, recovery_heartbeat_at IS NULL \
         FROM grund_machine_migration_pauses WHERE machine_id = $1",
    )
    .bind(machine_uuid)
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        pending == (true, true),
        "Fleet's restore cleared a ready copy before its moved agent heartbeated: {pending:?}"
    );
    let mut agent = a_running_agent(dir.clone())?;
    let started = Instant::now();
    loop {
        let paused: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM grund_machine_migration_pauses WHERE machine_id = $1)",
        )
        .bind(machine_uuid)
        .fetch_one(&pool)
        .await?;
        if !paused {
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(9),
            "the restored agent did not verify a ready copy before the migration deadline"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::ensure!(
        agent.containers().len() == 1,
        "the migration was released before its copy ran: {:?}",
        agent.containers()
    );

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

#[tokio::test]
async fn only_the_operator_can_grant_hosted_access_to_a_customer() -> anyhow::Result<()> {
    let operator = format!("ops-{}", random_hex(4));
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_OPERATOR_ORGANISATION", &operator)]).await?
    else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;
    let (customer, customer_when, customer_then) = given.testcase.another_browser();
    let org = customer.a_signed_in_account().await?.username;
    let service = "/grund.operator.v1.OperatorService";

    when.visiting(&format!("/{operator}/admin?tab=organisations"))
        .await?;
    then.status(200)?.body_contains("Organisations")?;
    customer_when.visiting(&format!("/{org}/admin")).await?;
    customer_then.status(404)?;
    customer_when
        .visiting(&format!("/{operator}/admin"))
        .await?;
    customer_then.status(404)?;
    customer_when
        .calling(
            &format!("{service}/SetHostedEntitlement"),
            &json!({"organisation": org, "enabled": true}).to_string(),
        )
        .await?;
    customer_then.status(404)?;

    when.calling(
        &format!("{service}/SetHostedEntitlement"),
        &json!({"organisation": org, "enabled": true}).to_string(),
    )
    .await?;
    then.status(200)?;
    when.calling(&format!("{service}/ListEntitlements"), "{}")
        .await?;
    then.status(200)?;
    let listed = then.json()?;
    anyhow::ensure!(
        listed["organisations"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|row| row["organisation"] == org && row["enabled"] == true)),
        "{listed}"
    );
    when.calling(
        &format!("{service}/SetHostedEntitlement"),
        &json!({"organisation": org, "enabled": false}).to_string(),
    )
    .await?;
    then.status(200)?;
    when.calling(&format!("{service}/ListEntitlements"), "{}")
        .await?;
    then.status(200)?;
    let listed = then.json()?;
    anyhow::ensure!(
        listed["organisations"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|row| row["organisation"] == org && !row["enabled"].as_bool().unwrap_or(false))),
        "{listed}"
    );
    Ok(())
}

#[tokio::test]
async fn operator_hosts_hide_retired_inventory_without_losing_state_counts() -> anyhow::Result<()> {
    use crate::accepttest::fixtures::{CAPACITY_TOKEN, FakeCapacity};

    let capacity = FakeCapacity::start().await?;
    capacity.set_inventory_hosts(vec![
        json!({"id":"01a117d6-85c5-757f-96ac-b734364ba89e","name":"lab-a-retired-01a117d6-85c5-757f-96ac-b734364ba89e","state":"retired"}),
        json!({"id":"old-2","name":"retired-two","state":"retired"}),
        json!({"id":"live-1","name":"live-host","state":"ready",
            "vcpus":4,"allocatedVcpus":2,"memoryMib":"4096","allocatedMemoryMib":"2048",
            "diskGib":"20","allocatedDiskGib":"8","machineCount":2}),
    ]);
    let operator = format!("ops-{}", random_hex(4));
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_OPERATOR_ORGANISATION", &operator),
        ("GRUND_CAPACITY_URL", &capacity.url),
        ("GRUND_CAPACITY_TOKEN", CAPACITY_TOKEN),
    ])
    .await?
    else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;

    when.visiting(&format!("/{operator}/admin")).await?;
    then.status(200)?
        .body_contains("live-host")?
        .body_contains("vCPU 2/4")?
        .body_contains("RAM 2/4 GB")?
        .body_contains("Disk 8/20 GB")?
        .body_contains("Retired")?
        .body_lacks("lab-a-retired-01a117d6-85c5-757f-96ac-b734364ba89e")?
        .body_lacks("retired-two")?;
    anyhow::ensure!(capacity.calls("ListInventoryHosts").len() == 2);

    when.visiting(&format!("/{operator}/admin?host_filter=retired"))
        .await?;
    then.status(200)?
        .body_contains("lab-a")?
        .body_contains("retired-two")?
        .body_contains("01a117d6")?
        .body_lacks("lab-a-retired-01a117d6-85c5-757f-96ac-b734364ba89e")?
        .body_lacks("live-host")?;
    Ok(())
}

#[tokio::test]
async fn entitled_customer_orders_and_removes_an_opaque_machine_without_cross_organisation_access()
-> anyhow::Result<()> {
    use crate::accepttest::fixtures::{CAPACITY_TOKEN, FakeCapacity};

    let capacity = FakeCapacity::start().await?;
    let operator = format!("ops-{}", random_hex(4));
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_OPERATOR_ORGANISATION", &operator),
        ("GRUND_CAPACITY_URL", &capacity.url),
        ("GRUND_CAPACITY_TOKEN", CAPACITY_TOKEN),
    ])
    .await?
    else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;
    let (customer, customer_when, customer_then) = given.testcase.another_browser();
    let organisation = customer.a_signed_in_account().await?.username;
    let (stranger, stranger_when, stranger_then) = given.testcase.another_browser();
    let other = stranger.a_signed_in_account().await?.username;

    customer_when
        .calling(
            &format!("{MACHINES}/ListHostedOffers"),
            &json!({"organisation":organisation}).to_string(),
        )
        .await?;
    customer_then.status(403)?;
    stranger_when.calling(&format!("{MACHINES}/CreateHostedMachine"),
        &json!({"organisation":other,"name":"other-1","size":"small","region":"test-region","idempotencyKey":"denied"}).to_string()).await?;
    stranger_then.status(403)?;

    when.calling(
        "/grund.operator.v1.OperatorService/SetHostedEntitlement",
        &json!({"organisation":organisation,"enabled":true}).to_string(),
    )
    .await?;
    then.status(200)?;
    customer_when
        .visiting(&format!("/{organisation}/machines/add?mode=hosted"))
        .await?;
    customer_then
        .status(200)?
        .body_contains("No capacity in this size")?
        .body_lacks("fm-1")?;
    customer_when
        .calling(
            &format!("{MACHINES}/ListHostedOffers"),
            &json!({"organisation":organisation}).to_string(),
        )
        .await?;
    customer_then.status(200)?;
    let offer = customer_then.json()?;
    anyhow::ensure!(
        !offer["offers"][0]["available"].as_bool().unwrap_or(false),
        "{offer}"
    );
    let create = json!({"organisation":organisation,"name":"first-1","size":"small","region":"test-region","idempotencyKey":"hosted-first-1"});
    customer_when
        .calling(
            &format!("{MACHINES}/CreateHostedMachine"),
            &create.to_string(),
        )
        .await?;
    customer_then.status(429)?;
    customer_then.body_contains("No capacity in this size")?;
    anyhow::ensure!(capacity.calls("ProvisionMachine").is_empty());

    capacity.set_can_place(true);
    customer_when
        .calling(
            &format!("{MACHINES}/CreateHostedMachine"),
            &create.to_string(),
        )
        .await?;
    customer_then.status(200)?;
    let created = customer_then.json()?;
    let public_id = created["machine"]["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    anyhow::ensure!(
        !public_id.is_empty()
            && created["machine"]["hosted"] == true
            && created["machine"]["state"] == "MACHINE_STATE_JOINING",
        "{created}"
    );
    for forbidden in [
        "fm-1", "fleet", "provider", "lease", "pool", "hostId", "host_id",
    ] {
        anyhow::ensure!(
            !created
                .to_string()
                .to_lowercase()
                .contains(&forbidden.to_lowercase()),
            "{created}"
        );
    }
    customer_when
        .calling(
            &format!("{MACHINES}/CreateHostedMachine"),
            &create.to_string(),
        )
        .await?;
    customer_then.status(200)?;
    anyhow::ensure!(customer_then.json()?["machine"]["machineId"] == public_id);
    anyhow::ensure!(capacity.calls("ProvisionMachine").len() == 1);
    stranger_when
        .calling(
            &format!("{MACHINES}/GetMachine"),
            &json!({"organisation":organisation,"machineId":public_id}).to_string(),
        )
        .await?;
    stranger_then.status(404)?;
    stranger_when
        .calling(
            &format!("{MACHINES}/RemoveHostedMachine"),
            &json!({"organisation":other,"machineId":public_id}).to_string(),
        )
        .await?;
    stranger_then.status(404)?;

    customer_when
        .calling(
            &format!("{MACHINES}/ListMachines"),
            &json!({"organisation":organisation}).to_string(),
        )
        .await?;
    customer_then.status(200)?;
    let joining = customer_then.json()?;
    anyhow::ensure!(
        joining["machines"][0]["state"] == "MACHINE_STATE_JOINING"
            && joining["machines"][0]["machineId"] == public_id,
        "{joining}"
    );
    let token = capacity.calls("ProvisionMachine")[0].body["enrollmentToken"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let _dir = joined_with(&customer_when, &token).await?;
    customer_when
        .calling(
            &format!("{MACHINES}/GetMachine"),
            &json!({"organisation":organisation,"machineId":public_id}).to_string(),
        )
        .await?;
    customer_then.status(200)?;
    let joined = customer_then.json()?;
    anyhow::ensure!(
        joined["machine"]["machineId"] == public_id
            && joined["machine"]["hosted"] == true
            && joined["machine"]["facts"]["os"] == "Linux",
        "{joined}"
    );
    customer_when
        .calling(
            "/grund.notification.v1.NotificationService/ListNotifications",
            "{}",
        )
        .await?;
    customer_then.status(200)?;
    let inbox = customer_then.json()?;
    anyhow::ensure!(
        inbox["notifications"].as_array().is_some_and(|items| items
            .iter()
            .filter(|item| item["kind"] == "hosted_machine.ready")
            .count()
            == 1),
        "hosted readiness notifies its customer once: {inbox}"
    );
    stranger_when
        .calling(
            "/grund.notification.v1.NotificationService/ListNotifications",
            "{}",
        )
        .await?;
    stranger_then.status(200)?;
    let other_inbox = stranger_then.json()?;
    anyhow::ensure!(
        other_inbox
            .get("notifications")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "another organisation saw hosted readiness: {other_inbox}"
    );
    for forbidden in ["fm-1", "fleet", "provider", "lease", "pool"] {
        anyhow::ensure!(
            !joined.to_string().to_lowercase().contains(forbidden),
            "{joined}"
        );
    }
    customer_when
        .visiting(&format!("/{organisation}/machines"))
        .await?;
    customer_then
        .status(200)?
        .body_contains("Hosted")?
        .body_contains("first-1")?
        .body_lacks("fm-1")?;
    capacity.unavailable_for("RebuildMachine", true);
    customer_when
        .calling(
            &format!("{MACHINES}/RemoveHostedMachine"),
            &json!({"organisation":organisation,"machineId":public_id}).to_string(),
        )
        .await?;
    customer_then.status(200)?;
    anyhow::ensure!(capacity.calls("RebuildMachine").len() == 1);
    capacity.unavailable_for("RebuildMachine", false);
    let started = Instant::now();
    while capacity.calls("RebuildMachine").len() < 2 {
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(45),
            "the cancelled hosted lease was not retried for a wipe"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    customer_when
        .calling(
            &format!("{MACHINES}/ListMachines"),
            &json!({"organisation":organisation}).to_string(),
        )
        .await?;
    customer_then.status(200)?;
    anyhow::ensure!(
        customer_then.json()?["machines"]
            .as_array()
            .is_none_or(|rows| rows.is_empty())
    );
    Ok(())
}

#[tokio::test]
async fn a_refused_hosted_creation_notifies_only_the_customer_once() -> anyhow::Result<()> {
    use crate::accepttest::fixtures::{CAPACITY_TOKEN, FakeCapacity};

    let capacity = FakeCapacity::start().await?;
    let operator = format!("ops-{}", random_hex(4));
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_OPERATOR_ORGANISATION", &operator),
        ("GRUND_CAPACITY_URL", &capacity.url),
        ("GRUND_CAPACITY_TOKEN", CAPACITY_TOKEN),
    ])
    .await?
    else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;
    let (customer, customer_when, customer_then) = given.testcase.another_browser();
    let account = customer.a_signed_in_account().await?;
    let (stranger, stranger_when, stranger_then) = given.testcase.another_browser();
    stranger.a_signed_in_account().await?;
    when.calling(
        "/grund.operator.v1.OperatorService/SetHostedEntitlement",
        &json!({"organisation": account.username, "enabled": true}).to_string(),
    )
    .await?;
    then.status(200)?;
    capacity.set_can_place(true);
    capacity.refuse_for("ProvisionMachine", true);
    let create = json!({
        "organisation": account.username, "name": "refused-1",
        "size": "small", "region": "test-region", "idempotencyKey": "hosted-refused-1",
    })
    .to_string();
    customer_when
        .calling(&format!("{MACHINES}/CreateHostedMachine"), &create)
        .await?;
    customer_then.status(429)?;
    customer_when
        .calling(
            "/grund.notification.v1.NotificationService/ListNotifications",
            "{}",
        )
        .await?;
    customer_then.status(200)?;
    let inbox = customer_then.json()?;
    anyhow::ensure!(
        inbox["notifications"].as_array().is_some_and(|items| items
            .iter()
            .filter(|item| item["kind"] == "hosted_machine.failed")
            .count()
            == 1),
        "refused order creates exactly one failure fact: {inbox}"
    );
    stranger_when
        .calling(
            "/grund.notification.v1.NotificationService/ListNotifications",
            "{}",
        )
        .await?;
    stranger_then.status(200)?;
    let unrelated = stranger_then.json()?;
    anyhow::ensure!(
        unrelated
            .get("notifications")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "unrelated account saw hosted failure: {unrelated}"
    );
    Ok(())
}
