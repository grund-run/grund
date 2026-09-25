use std::time::Duration;

use crate::accepttest::fixtures::{FakeInsights, INSIGHTS_TOKEN, testcase_configured};

async fn reporting_to(
    insights: &FakeInsights,
) -> anyhow::Result<
    Option<(
        crate::accepttest::fixtures::Given,
        crate::accepttest::fixtures::When,
        crate::accepttest::fixtures::Then,
    )>,
> {
    testcase_configured(&[
        ("GRUND_INSIGHTS_URL", &insights.url),
        ("GRUND_INSIGHTS_TOKEN", INSIGHTS_TOKEN),
    ])
    .await
}

#[tokio::test]
async fn a_confirmed_account_is_reported_once_with_the_token_and_nothing_more() -> anyhow::Result<()>
{
    let insights = FakeInsights::start(&[]).await?;
    let Some((given, when, _then)) = reporting_to(&insights).await? else {
        return Ok(());
    };

    let account = given.an_account().await?;

    let reports = insights.wait_for(1, Duration::from_secs(15)).await?;
    let report = &reports[0];
    assert_eq!(report.path, "/v1/accounts");
    assert_eq!(
        report.authorization.as_deref(),
        Some(format!("Bearer {INSIGHTS_TOKEN}").as_str())
    );
    let body = report.body.as_object().expect("a JSON object");
    let mut keys: Vec<&str> = body.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "account_id",
            "email",
            "instance",
            "method",
            "registered_at",
            "username",
            "verified_at"
        ]
    );
    assert_eq!(body["username"], account.username.as_str());
    assert_eq!(body["email"], account.email.as_str());
    assert_eq!(body["method"], "password");
    assert_eq!(body["instance"], "127.0.0.1");

    when.signing_in(&account.username, &account.password)
        .await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(insights.reports().len(), 1, "one report per account");
    Ok(())
}

#[tokio::test]
async fn an_account_whose_address_is_not_confirmed_is_not_reported() -> anyhow::Result<()> {
    let insights = FakeInsights::start(&[]).await?;
    let Some((given, _when, _then)) = reporting_to(&insights).await? else {
        return Ok(());
    };

    given.an_unconfirmed_account().await?;

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(insights.reports().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_report_insights_could_not_take_is_sent_again() -> anyhow::Result<()> {
    let insights = FakeInsights::start(&[503, 401]).await?;
    let Some((given, _when, _then)) = reporting_to(&insights).await? else {
        return Ok(());
    };

    given.an_account().await?;

    let reports = insights.wait_for(3, Duration::from_secs(30)).await?;
    assert!(
        reports
            .iter()
            .all(|r| r.body["account_id"] == reports[0].body["account_id"]),
        "the same report each time"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(insights.reports().len(), 3, "delivered on the third try");
    Ok(())
}

#[tokio::test]
async fn without_insights_configured_nothing_is_queued_or_sent() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };

    given.an_account().await?;

    let url = given
        .testcase
        .fixture
        .database_url()
        .expect("a spawned instance has its own database");
    let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(&url).await?;
    let queued: i64 =
        sqlx::query_scalar("SELECT count(*) FROM grund_outbox WHERE kind = 'insights.account'")
            .fetch_one(&mut connection)
            .await?;
    assert_eq!(queued, 0);
    Ok(())
}
