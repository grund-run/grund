use crate::accepttest::fixtures::testcase;

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
async fn every_response_carries_the_security_headers() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;

    for path in ["/health/live", "/definitely/not/a/page"] {
        when.requesting("GET", path).await?;
        then.carries_the_security_headers()
            .map_err(|error| error.context(path))?;
    }
    Ok(())
}
