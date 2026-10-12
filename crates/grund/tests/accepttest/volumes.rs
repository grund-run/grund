use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use serde_json::{Value, json};

use crate::accepttest::{
    apps::{a_machine, a_running_agent, app, call, live, quick, spec, until},
    fixtures::{FakeRegistry, testcase_configured},
};

const VOLUMES: &str = "/grund.volume.v1.VolumeService";

async fn list(
    when: &crate::accepttest::fixtures::When,
    then: &crate::accepttest::fixtures::Then,
    organisation: &str,
    app: &str,
) -> anyhow::Result<Value> {
    when.calling(
        &format!("{VOLUMES}/ListVolumes"),
        &json!({"organisation": organisation, "app": app}).to_string(),
    )
    .await?;
    then.status(200)?;
    then.json()
}

#[tokio::test]
async fn an_app_owned_directory_survives_release_and_agent_restart_then_erases_on_app_delete()
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
    registry.publish("acme/storage", "1");
    registry.publish("acme/storage", "2");
    call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "storage", "settings": quick(1)}),
    )
    .await?;
    then.status(200)?;
    let mut first = spec(&registry.image("acme/storage", "1"), json!([]));
    first["volumes"] = json!([{"name": "data", "path": "/data", "backup": false}]);
    call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "storage", "spec": first}),
    )
    .await?;
    then.status(200)?;
    until(
        &when,
        &then,
        org,
        "storage",
        Duration::from_secs(45),
        "first release",
        |app| live(app, 1),
    )
    .await?;

    let listed = list(&when, &then, org, "storage").await?;
    let volumes = listed["volumes"].as_array().context("volumes array")?;
    ensure!(volumes.len() == 1, "one app-owned volume: {listed}");
    let volume_id = volumes[0]["volumeId"].as_str().context("volume ID")?;
    ensure!(
        volumes[0]["status"] == "attached",
        "volume was attached: {listed}"
    );
    let root = agent.dir.join("volumes").join(volume_id);
    let marker = root.join("customer-marker");
    let containers = agent.containers();
    ensure!(
        containers.len() == 1,
        "first replica has one container: {containers:?}"
    );
    ensure!(
        containers[0]["spec"]["volumes"][0]["source"] == root.to_string_lossy().as_ref()
            && containers[0]["spec"]["volumes"][0]["path"] == "/data",
        "replica mounts the verified app-owned directory: {containers:?}"
    );
    std::fs::write(&marker, b"written before release")?;

    let mut second = spec(&registry.image("acme/storage", "2"), json!([]));
    second["volumes"] = json!([{"name": "data", "path": "/data", "backup": false}]);
    call(
        &when,
        &then,
        "Deploy",
        json!({"organisation": org, "name": "storage", "spec": second}),
    )
    .await?;
    then.status(200)?;
    until(
        &when,
        &then,
        org,
        "storage",
        Duration::from_secs(45),
        "replacement release",
        |app| live(app, 2),
    )
    .await?;
    ensure!(
        std::fs::read(&marker)? == b"written before release",
        "release retained the bytes"
    );
    ensure!(
        agent.containers().iter().all(|c| c["spec"]["volumes"]
            .as_array()
            .is_some_and(|v| v.len() == 1)),
        "one bind per active container"
    );

    let data_dir = agent.dir.clone();
    drop(agent);
    let agent = a_running_agent(data_dir)?;
    until(
        &when,
        &then,
        org,
        "storage",
        Duration::from_secs(45),
        "agent restart",
        |app| live(app, 2),
    )
    .await?;
    ensure!(
        std::fs::read(&marker)? == b"written before release",
        "restart retained the bytes"
    );
    ensure!(
        app(&when, &then, org, "storage").await?["replicas"]
            .as_array()
            .is_some_and(|r| r.len() == 1),
        "single writer"
    );

    call(
        &when,
        &then,
        "DeleteApp",
        json!({"organisation": org, "name": "storage", "confirmVolumeCount": 1}),
    )
    .await?;
    then.status(200)?;
    let deadline = Instant::now() + Duration::from_secs(45);
    while root.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    ensure!(
        !root.exists(),
        "signed machine tombstone erased the managed directory"
    );
    drop(agent);
    Ok(())
}

#[tokio::test]
async fn a_verified_s3_point_restores_its_bytes_to_a_different_own_machine() -> anyhow::Result<()> {
    let Some(restic) = std::env::var_os("GRUND_ACCEPT_RESTIC_BIN") else {
        eprintln!("skipped: set GRUND_ACCEPT_RESTIC_BIN to the pinned restic executable");
        return Ok(());
    };
    ensure!(
        std::path::Path::new(&restic).is_absolute(),
        "restic test executable must have an absolute path"
    );
    let endpoint = if let Ok(upstream) = std::env::var("GRUND_ACCEPT_S3_UPSTREAM") {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    if let Ok(mut server) = tokio::net::TcpStream::connect(upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
            }
        });
        endpoint
    } else {
        std::env::var("GRUND_ACCEPT_S3_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:59010".into())
    };
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let left = a_machine(&when, &then, org, "box-a").await?;
    let right = a_machine(&when, &then, org, "box-b").await?;
    when.calling(
        "/grund.machine.v1.MachineService/ListMachines",
        &json!({"organisation": org}).to_string(),
    )
    .await?;
    then.status(200)?;
    let machines = then.json()?;
    let machines = machines["machines"].as_array().context("own machines")?;
    let id_of = |name: &str| -> anyhow::Result<&str> {
        machines
            .iter()
            .find(|machine| machine["name"] == name)
            .and_then(|machine| machine["machineId"].as_str())
            .context("joined machine identity")
    };
    let left_id = id_of("box-a")?;
    let right_id = id_of("box-b")?;
    registry.publish("acme/backup", "1");
    call(
        &when,
        &then,
        "CreateApp",
        json!({
            "organisation": org, "name": "backup", "settings": quick(1)
        }),
    )
    .await?;
    then.status(200)?;
    let mut release = spec(&registry.image("acme/backup", "1"), json!([]));
    release["volumes"] = json!([{"name":"data","path":"/data","backup":true}]);
    call(
        &when,
        &then,
        "Deploy",
        json!({
            "organisation":org,"name":"backup","spec":release
        }),
    )
    .await?;
    then.status(200)?;
    until(
        &when,
        &then,
        org,
        "backup",
        Duration::from_secs(45),
        "backup source live",
        |app| live(app, 1),
    )
    .await?;
    let listed = list(&when, &then, org, "backup").await?;
    let source = &listed["volumes"][0];
    let volume_id = source["volumeId"].as_str().context("source volume ID")?;
    let source_machine = source["machineId"].as_str().context("source machine ID")?;
    let (source_agent, target_agent, target_machine) = if source_machine == left_id {
        (&left, &right, right_id)
    } else {
        ensure!(
            source_machine == right_id,
            "source is on an enrolled own machine"
        );
        (&right, &left, left_id)
    };
    let original = source_agent.dir.join("volumes").join(volume_id);
    std::fs::write(
        original.join("customer-marker"),
        b"off-machine recovery marker",
    )?;
    when.calling(&format!("{VOLUMES}/SetBackupDestination"), &json!({
        "organisation":org,"app":"backup","volumeId":volume_id,"expectedVersion":"0",
        "idempotencyKey":"setup-backup-scenario","endpoint":endpoint,"bucket":"grund-backup-test",
        "accessKeyId":"grund-local","secretAccessKey":"grund-local-backup-test-only"
    }).to_string()).await?;
    then.status(200)?;
    let started = Instant::now();
    let snapshot = loop {
        when.calling(
            &format!("{VOLUMES}/ListRecoveryPoints"),
            &json!({
                "organisation":org,"app":"backup","volumeId":volume_id
            })
            .to_string(),
        )
        .await?;
        then.status(200)?;
        let points = then.json()?;
        if let Some(snapshot) = points["points"][0]["snapshotId"].as_str() {
            break snapshot.to_string();
        }
        ensure!(
            started.elapsed() < Duration::from_secs(150),
            "no verified recovery point; backup did not complete"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    ensure!(
        snapshot.len() == 64,
        "exact restic snapshot ID was verified"
    );
    let source_version = list(&when, &then, org, "backup").await?["volumes"][0]["version"].clone();
    ensure!(
        !source_version.is_null(),
        "source stream version is present"
    );
    when.calling(
        &format!("{VOLUMES}/RestoreRecoveryPoint"),
        &json!({
            "organisation":org,"app":"backup","sourceVolumeId":volume_id,
            "snapshotId":snapshot,"idempotencyKey":"restore-backup-scenario",
            "expectedVersion":source_version,"newVolumeName":"recovered",
            "targetContainerPath":"/recovered","targetMachineId":target_machine,
            "confirmNewVolume":true
        })
        .to_string(),
    )
    .await?;
    then.status(200)?;
    let restore = then.json()?;
    let new_id = restore["newVolumeId"].as_str().context("new volume ID")?;
    ensure!(new_id != volume_id, "restore allocated a different volume");
    let marker = target_agent
        .dir
        .join("volumes")
        .join(new_id)
        .join("customer-marker");
    let started = Instant::now();
    loop {
        when.calling(
            &format!("{VOLUMES}/GetVolumeStatus"),
            &json!({
                "organisation":org,"app":"backup","volumeId":new_id
            })
            .to_string(),
        )
        .await?;
        then.status(200)?;
        let status = then.json()?;
        if status["volume"]["restoreStatus"] == "completed"
            && status["volume"]["status"] == "available"
        {
            break;
        }
        ensure!(
            status["volume"]["restoreStatus"] != "failed",
            "restore failed: {status}"
        );
        ensure!(
            started.elapsed() < Duration::from_secs(150),
            "restore to second machine did not complete: {status}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    ensure!(
        std::fs::read(&marker)? == b"off-machine recovery marker",
        "verified recovery point preserved exact customer bytes"
    );
    ensure!(
        std::fs::read(original.join("customer-marker"))? == b"off-machine recovery marker",
        "source was never overwritten"
    );
    call(
        &when,
        &then,
        "DeleteApp",
        json!({
            "organisation":org,"name":"backup","confirmVolumeCount":2
        }),
    )
    .await?;
    then.status(200)?;
    let deadline = Instant::now() + Duration::from_secs(45);
    while (original.exists() || marker.exists()) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    ensure!(
        !original.exists() && !marker.exists(),
        "both app-owned managed directories were erased after deletion"
    );
    Ok(())
}
