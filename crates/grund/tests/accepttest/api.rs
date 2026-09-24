use crate::accepttest::fixtures::{testcase, testcase_with_mail};

const GET_VIEWER: &str = "/grund.account.v1.AccountService/GetViewer";
const LIST_SESSIONS: &str = "/grund.account.v1.AccountService/ListSessions";
const REVOKE_SESSION: &str = "/grund.account.v1.AccountService/RevokeSession";

#[tokio::test]
async fn an_api_call_without_a_session_is_unauthenticated() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;

    when.calling(GET_VIEWER, "{}").await?;
    then.status(401)?.connect_code("unauthenticated")?;
    when.calling_with(
        GET_VIEWER,
        "{}",
        &[("Authorization", "Bearer grund_pat_nope")],
    )
    .await?;
    then.status(401)?.connect_code("unauthenticated")?;
    Ok(())
}

#[tokio::test]
async fn the_viewer_is_the_signed_in_account_with_its_organisation() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;

    when.calling(GET_VIEWER, "{}").await?;
    then.status(200)?.header("cache-control", "no-store")?;
    let viewer = then.json()?["viewer"].clone();
    anyhow::ensure!(viewer["username"] == account.username.as_str(), "{viewer}");
    anyhow::ensure!(viewer["email"] == account.email.as_str(), "{viewer}");
    let memberships = viewer["memberships"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    anyhow::ensure!(memberships.len() == 1, "{viewer}");
    anyhow::ensure!(
        memberships[0]["organisationSlug"] == account.username.as_str(),
        "{viewer}"
    );
    anyhow::ensure!(memberships[0]["role"] == "ROLE_OWNER", "{viewer}");
    Ok(())
}

#[tokio::test]
async fn a_call_from_another_site_is_refused_even_with_the_session_cookie() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;

    when.calling_with(GET_VIEWER, "{}", &[("Origin", "https://evil.example")])
        .await?;
    then.status(403)?.connect_code("permission_denied")?;
    when.calling_with(GET_VIEWER, "{}", &[("Sec-Fetch-Site", "cross-site")])
        .await?;
    then.status(403)?.connect_code("permission_denied")?;
    Ok(())
}

#[tokio::test]
async fn sessions_are_listed_for_the_caller_only_and_another_accounts_is_not_found()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let (_, second_device, _) = given.testcase.another_browser();
    second_device
        .signing_in(&account.username, &account.password)
        .await?;

    let (other_given, other, other_then) = given.testcase.another_browser();
    other_given.a_signed_in_account().await?;
    other.calling(LIST_SESSIONS, "{}").await?;
    other_then.status(200)?;
    let other_session = other_then.json()?["sessions"][0]["sessionId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    when.calling(LIST_SESSIONS, "{}").await?;
    then.status(200)?;
    let sessions = then.json()?["sessions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    anyhow::ensure!(
        sessions.len() == 2,
        "expected this account's two sessions: {sessions:?}"
    );
    anyhow::ensure!(
        sessions.iter().filter(|s| s["current"] == true).count() == 1,
        "{sessions:?}"
    );
    anyhow::ensure!(
        sessions
            .iter()
            .all(|s| s["sessionId"] != other_session.as_str()),
        "another account's session is listed"
    );

    when.calling(
        REVOKE_SESSION,
        &format!("{{\"sessionId\":\"{other_session}\"}}"),
    )
    .await?;
    then.status(404)?.connect_code("not_found")?;
    other.calling(GET_VIEWER, "{}").await?;
    other_then.status(200)?;

    let second = sessions
        .iter()
        .find(|s| s["current"] != true)
        .and_then(|s| s["sessionId"].as_str())
        .unwrap_or_default();
    when.calling(REVOKE_SESSION, &format!("{{\"sessionId\":\"{second}\"}}"))
        .await?;
    then.status(200)?;
    second_device.calling(GET_VIEWER, "{}").await?;
    anyhow::ensure!(
        second_device
            .testcase
            .data()
            .last
            .as_ref()
            .map(|r| r.status)
            == Some(401),
        "the revoked device still works"
    );

    when.calling(REVOKE_SESSION, "{\"sessionId\":\"not-a-uuid\"}")
        .await?;
    then.status(400)?.connect_code("invalid_argument")?;
    Ok(())
}

#[tokio::test]
async fn an_oversized_request_is_refused_before_it_is_decoded() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;
    let big = format!("{{\"sessionId\":\"{}\"}}", "x".repeat(40 * 1024));

    when.calling(REVOKE_SESSION, &big).await?;
    then.status_in(&[400, 413, 429])?;
    Ok(())
}
