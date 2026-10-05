use std::time::{Duration, Instant};

use crate::accepttest::fixtures::{Fixture, client, external_target, testcase_configured};

#[tokio::test]
async fn grund_rides_out_its_database_going_away_and_is_ready_again_when_it_is_back()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let fixture = &given.testcase.fixture;

    fixture.database_away_for(Duration::from_secs(8)).await?;
    tokio::time::sleep(Duration::from_secs(12)).await;

    anyhow::ensure!(
        fixture.is_running(),
        "grund exited while its database was away:\n{}",
        fixture.log()
    );
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        when.requesting("GET", "/health/ready").await?;
        if then.status(200).is_ok() {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "grund was not ready again 45 s after its database came back:\n{}",
            fixture.log()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    when.requesting("GET", "/health/live").await?;
    then.status(200)?;
    let log = fixture.log();
    anyhow::ensure!(
        log.contains("starting it again"),
        "the projection runner was not started again:\n{log}"
    );
    anyhow::ensure!(
        fixture.is_running(),
        "grund exited after its database came back"
    );
    Ok(())
}

async fn answers(fixture: &Fixture, path: &str) -> Option<u16> {
    client::send(&fixture.origin, "GET", path, &[], None)
        .await
        .ok()
        .map(|response| response.status)
}

#[tokio::test]
async fn grund_started_while_its_database_refuses_waits_for_it_and_is_ready_without_a_restart()
-> anyhow::Result<()> {
    if external_target().is_some() {
        return Ok(());
    }
    let fixture = Fixture::spawn_while_its_database_refuses(&[]).await?;
    let started = Instant::now();
    while answers(&fixture, "/health/live").await != Some(200) {
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(20),
            "liveness never answered while waiting:\n{}",
            fixture.log()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let ready = client::send(&fixture.origin, "GET", "/health/ready", &[], None).await?;
    anyhow::ensure!(ready.status == 503, "ready while waiting: {}", ready.status);
    let body: serde_json::Value = serde_json::from_slice(&ready.body)?;
    anyhow::ensure!(
        body["checks"][0]["name"] == "postgres" && body["checks"][0]["status"] == "unhealthy",
        "readiness does not say PostgreSQL is missing: {body}"
    );
    anyhow::ensure!(answers(&fixture, "/").await == Some(503));
    tokio::time::sleep(Duration::from_secs(5)).await;
    anyhow::ensure!(
        fixture.is_running(),
        "grund gave up on its database:\n{}",
        fixture.log()
    );

    fixture.database_accepts_connections().await?;
    let took = fixture
        .becomes_ready_within(Duration::from_secs(30))
        .await?;
    anyhow::ensure!(fixture.is_running(), "grund restarted to get ready");
    anyhow::ensure!(
        fixture
            .log()
            .contains("waiting for it (GRUND_DATABASE_WAIT)"),
        "the wait is not logged:\n{}",
        fixture.log()
    );
    eprintln!("ready {took:?} after the database accepted connections");
    Ok(())
}

#[tokio::test]
async fn grund_gives_up_on_its_database_after_grund_database_wait_naming_both() -> anyhow::Result<()>
{
    if external_target().is_some() {
        return Ok(());
    }
    let fixture =
        Fixture::spawn_while_its_database_refuses(&[("GRUND_DATABASE_WAIT", "3")]).await?;
    let started = Instant::now();
    while fixture.is_running() {
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(30),
            "grund still waits past GRUND_DATABASE_WAIT"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let log = fixture.log();
    anyhow::ensure!(
        log.contains("GRUND_DATABASE_WAIT (3 s)") && log.contains("DATABASE_URL"),
        "the refusal does not name both variables:\n{log}"
    );
    Ok(())
}
