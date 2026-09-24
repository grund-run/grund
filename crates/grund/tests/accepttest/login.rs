use crate::accepttest::fixtures::{testcase, testcase_configured, testcase_with_mail};

const INVALID: &str = "That email, username or password is not right.";

#[tokio::test]
async fn signing_in_by_username_or_email_sets_an_http_only_lax_session_cookie() -> anyhow::Result<()>
{
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.an_account().await?;

    for login in [account.username.clone(), account.email.to_uppercase()] {
        when.signing_in(&login, &account.password).await?;
        then.redirects_to("/")?;
        let cookie = then.sets_cookie("grund_session")?;
        anyhow::ensure!(cookie.contains("HttpOnly"), "{cookie}");
        anyhow::ensure!(cookie.contains("SameSite=Lax"), "{cookie}");
        anyhow::ensure!(cookie.contains("Path=/"), "{cookie}");
        let https = given.testcase.fixture.origin.tls;
        anyhow::ensure!(
            cookie.starts_with("__Host-") == https && cookie.contains("Secure") == https,
            "{cookie}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_unknown_account_and_a_wrong_password_get_the_same_answer_in_the_same_time()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.an_account().await?;
    let unknown = given.a_fresh_name("nobody");

    when.signing_in(&unknown, "some wrong password").await?;
    then.status(200)?
        .body_contains(INVALID)?
        .sets_no_session_cookie()?;
    let unknown_page = then.page_without_its_token()?;
    when.signing_in(&account.username, "some wrong password")
        .await?;
    then.status(200)?
        .body_contains(INVALID)?
        .sets_no_session_cookie()?;
    let wrong_page = then
        .page_without_its_token()?
        .replace(&account.username, &unknown);
    anyhow::ensure!(unknown_page == wrong_page, "the two answers differ");

    let (_, timer, _) = given.testcase.another_browser();
    let nobody = given.a_fresh_name("nobody");
    let (unknown_time, wrong_time) = timer
        .timing_sign_ins_alternately(
            (&nobody, "wrong password one"),
            (&account.email, "wrong password two"),
            9,
        )
        .await?;
    let (fast, slow) = if unknown_time < wrong_time {
        (unknown_time, wrong_time)
    } else {
        (wrong_time, unknown_time)
    };
    anyhow::ensure!(
        slow.as_secs_f64() < fast.as_secs_f64() * 1.5 + 0.01,
        "median sign-in times differ: unknown {unknown_time:?}, wrong password {wrong_time:?}"
    );
    Ok(())
}

#[tokio::test]
async fn signing_in_again_rotates_the_session_and_the_old_token_stops_working() -> anyhow::Result<()>
{
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let first = given.the_session_cookie().expect("signed in");

    when.signing_in(&account.username, &account.password)
        .await?;
    then.redirects_to("/")?;
    let second = given.the_session_cookie().expect("signed in again");
    anyhow::ensure!(first != second, "the session token did not change");

    let (_, replay, replay_then) = given.testcase.another_browser();
    let name = if given.testcase.fixture.origin.tls {
        "__Host-grund_session"
    } else {
        "grund_session"
    };
    replay
        .requesting_with("GET", "/", &[("Cookie", &format!("{name}={first}"))], None)
        .await?;
    replay_then.status(303)?;
    Ok(())
}

#[tokio::test]
async fn signing_out_ends_the_session() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;
    let token = given.the_session_cookie().expect("signed in");

    when.visiting("/").await?;
    when.submitting_on_current_page("/logout", &[]).await?;
    then.redirects_to("/login")?;

    let (_, replay, replay_then) = given.testcase.another_browser();
    let name = if given.testcase.fixture.origin.tls {
        "__Host-grund_session"
    } else {
        "grund_session"
    };
    replay
        .requesting_with(
            "GET",
            "/settings/sessions",
            &[("Cookie", &format!("{name}={token}"))],
            None,
        )
        .await?;
    replay_then.status(303)?;
    Ok(())
}

#[tokio::test]
async fn an_account_name_locks_after_repeated_failures_whether_or_not_it_exists()
-> anyhow::Result<()> {
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_LOGIN_FAILURES_PER_ACCOUNT", "3")]).await?
    else {
        return Ok(());
    };
    let account = given.an_account().await?;
    let unknown = given.a_fresh_name("ghost");

    for name in [account.username.as_str(), unknown.as_str()] {
        for _ in 0..3 {
            when.signing_in(name, "wrong password here").await?;
            then.status(200)?.body_contains(INVALID)?;
        }
        when.signing_in(name, "wrong password here").await?;
        then.status(429)?
            .body_contains("Too many attempts for this account")?;
    }
    when.signing_in(&account.username, &account.password)
        .await?;
    then.status(429)?.sets_no_session_cookie()?;
    Ok(())
}

#[tokio::test]
async fn pages_that_need_a_session_send_the_browser_to_sign_in_and_back() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;

    when.visiting("/settings/sessions").await?;
    then.redirects_to("/login?return_to=%2Fsettings%2Fsessions")?;
    when.visiting("/login?return_to=//evil.example").await?;
    then.status(200)?.body_lacks("evil.example")?;
    Ok(())
}
