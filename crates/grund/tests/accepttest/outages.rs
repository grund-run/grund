use std::time::{Duration, Instant};

use crate::accepttest::fixtures::testcase_configured;

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
