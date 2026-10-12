use std::time::{Duration, Instant};

use crate::accepttest::fixtures::{client, testcase, testcase_configured};

#[tokio::test]
async fn liveness_answers_ok_as_json_and_is_never_cached() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;

    when.requesting("GET", "/health/live").await?;

    then.status(200)?
        .header_contains("content-type", "application/json")?
        .header("cache-control", "no-store")?
        .json_field_is_set("status")?;
    Ok(())
}

#[tokio::test]
async fn readiness_reports_the_revision_and_its_checks() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;

    when.requesting("GET", "/health/ready").await?;

    then.status(200)?
        .header("cache-control", "no-store")?
        .json_field_is_set("revision")?
        .json_field_is_set("version")?;
    let body = then.json()?;
    let checks = body["checks"].as_array().cloned().unwrap_or_default();
    anyhow::ensure!(
        checks
            .iter()
            .any(|c| c["name"] == "postgres" && c["status"] == "healthy"),
        "readiness does not report a healthy postgres check: {body}"
    );
    anyhow::ensure!(
        checks.iter().all(|c| c.get("message").is_none()),
        "readiness leaks check error text: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn mail_readiness_counts_only_mail_waiting_for_smtp() -> anyhow::Result<()> {
    let Some((given, _, _)) = testcase_configured(&[("GRUND_SMTP_URL", "")]).await? else {
        return Ok(());
    };
    let fixture = &given.testcase.fixture;
    fixture
        .sql(
            "INSERT INTO grund_outbox (outbox_id, kind, recipient, payload, next_attempt_at) \
             VALUES ('00000000-0000-0000-0000-000000000001', 'insights.account', '', '{}', \
             clock_timestamp() + interval '1 hour')",
        )
        .await?;
    let mail_status = || async {
        let response = client::send(&fixture.origin, "GET", "/health/ready", &[], None).await?;
        let body: serde_json::Value = serde_json::from_slice(&response.body)?;
        Ok::<_, anyhow::Error>(
            body["checks"]
                .as_array()
                .and_then(|checks| checks.iter().find(|check| check["name"] == "mail"))
                .and_then(|check| check["status"].as_str())
                .map(str::to_string),
        )
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if mail_status().await?.as_deref() == Some("healthy") {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "non-mail work degraded mail readiness"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    fixture
        .sql(
            "INSERT INTO grund_outbox (outbox_id, kind, recipient, payload, next_attempt_at) \
             VALUES ('00000000-0000-0000-0000-000000000002', 'mail.verify_email', 'person@example.test', \
             '{\"username\":\"person\",\"link\":\"https://example.test/verify?token=secret\"}', \
             clock_timestamp() + interval '1 hour')",
        )
        .await?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if mail_status().await?.as_deref() == Some("unhealthy") {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "undeliverable mail did not degrade readiness"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[tokio::test]
async fn every_response_carries_the_security_headers() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;

    for path in ["/health/live", "/definitely/not/a/page"] {
        when.requesting("GET", path).await?;
        then.carries_the_security_headers()
            .map_err(|error| error.context(path))?;
    }
    Ok(())
}
