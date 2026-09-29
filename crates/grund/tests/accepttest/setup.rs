use std::time::Duration;

use crate::accepttest::fixtures::{Given, mail_count, testcase_configured};

const SINGLE: &[(&str, &str)] = &[("GRUND_ORGANISATIONS", "single")];
const ACCOUNTS: &str = "SELECT count(*) FROM grund_accounts";

fn token_of(link: &str) -> String {
    link.split_once("token=")
        .map(|(_, token)| token.to_string())
        .unwrap_or_default()
}

async fn posting_the_owner_form(
    given: &Given,
    link: &str,
    username: &str,
    password: &str,
) -> anyhow::Result<u16> {
    let when = crate::accepttest::fixtures::When {
        testcase: given.testcase.clone(),
    };
    when.visiting(link).await?;
    let has_form = given
        .testcase
        .data()
        .last
        .as_ref()
        .is_some_and(|page| page.text().contains("name=\"csrf\""));
    if !has_form {
        when.visiting("/login").await?;
    }
    when.submitting_on_current_page(
        "/signup/owner",
        &[
            ("token", &token_of(link)),
            ("username", username),
            ("email", &format!("{username}@accept.test")),
            ("password", password),
        ],
    )
    .await?;
    let status = given.testcase.data().last.as_ref().map_or(0, |r| r.status);
    Ok(status)
}

#[tokio::test]
async fn a_setup_link_creates_the_signed_in_owner_and_sends_no_mail() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    when.visiting("/signup").await?;
    then.status(403)?
        .body_contains("no owner yet")?
        .body_contains("setup-link")?;

    let ran = given.testcase.fixture.running(&["setup-link"]).await?;
    anyhow::ensure!(ran.success, "{}", ran.stderr);
    let link = ran.setup_link_path().expect("a link");
    anyhow::ensure!(
        ran.stdout.matches("grund_setup_").count() == 1,
        "the link is printed once: {}",
        ran.stdout
    );
    when.visiting(&link).await?;
    then.status(200)?
        .header("referrer-policy", "same-origin")?
        .header("cache-control", "no-store")?
        .body_contains("Create the owner")?;
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 0);

    let owner = given.a_fresh_name("owner");
    let password = "a long enough password here";
    let status = posting_the_owner_form(&given, &link, &owner, password).await?;
    anyhow::ensure!(status == 303, "the owner form answered {status}");
    then.redirects_to(&format!("/{owner}"))?;
    when.visiting_home().await?;
    then.status(200)?
        .body_contains(&format!("owner of {owner}"))?;

    when.submitting(&format!("/{owner}"), "/logout", &[])
        .await?;
    when.signing_in(&owner, password).await?;
    then.status(303)?;

    tokio::time::sleep(Duration::from_secs(3)).await;
    anyhow::ensure!(
        mail_count(&given, &format!("{owner}@accept.test")).await? == 0,
        "the owner was mailed"
    );
    let token = token_of(&link);
    anyhow::ensure!(
        !given.testcase.fixture.log().contains(&token),
        "grund's log carries the setup link"
    );
    anyhow::ensure!(
        !ran.stderr.contains(&token),
        "the command's standard error carries the setup link"
    );
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_setup_links WHERE used_at IS NOT NULL AND account_id IS NOT NULL")
            .await?
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn a_setup_link_works_once() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    let status = posting_the_owner_form(
        &given,
        &link,
        &given.a_fresh_name("owner"),
        "a long enough password here",
    )
    .await?;
    anyhow::ensure!(status == 303, "the first use answered {status}");

    let (stranger, stranger_when, stranger_then) = given.testcase.another_browser();
    stranger_when.visiting(&link).await?;
    stranger_then.status(200)?.body_contains("expired")?;
    let status = posting_the_owner_form(
        &stranger,
        &link,
        &stranger.a_fresh_name("second"),
        "a long enough password here",
    )
    .await?;
    anyhow::ensure!(status == 200, "the second use answered {status}");
    stranger_then
        .body_contains("expired")?
        .sets_no_session_cookie()?;
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 1);
    Ok(())
}

#[tokio::test]
async fn an_expired_setup_link_creates_nothing() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    when.visiting(&link).await?;
    then.status(200)?.body_contains("Create the owner")?;
    let changed = given
        .testcase
        .fixture
        .sql(
            "UPDATE grund_setup_links SET created_at = clock_timestamp() - interval '2 hours', \
             expires_at = clock_timestamp() - interval '1 hour'",
        )
        .await?;
    anyhow::ensure!(changed == 1);
    when.submitting_on_current_page(
        "/signup/owner",
        &[
            ("token", &token_of(&link)),
            ("username", &given.a_fresh_name("late")),
            ("email", "late@accept.test"),
            ("password", "a long enough password here"),
        ],
    )
    .await?;
    then.status(200)?
        .body_contains("expired")?
        .sets_no_session_cookie()?;
    when.visiting(&link).await?;
    then.body_contains("expired")?;
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 0);
    Ok(())
}

#[tokio::test]
async fn two_posts_of_one_setup_link_at_once_make_one_owner() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    let (first, _, _) = given.testcase.another_browser();
    let (second, _, _) = given.testcase.another_browser();
    let password = "a long enough password here";
    let (one, two) = (first.a_fresh_name("racer"), second.a_fresh_name("racer"));
    let (a, b) = tokio::join!(
        posting_the_owner_form(&first, &link, &one, password),
        posting_the_owner_form(&second, &link, &two, password),
    );
    let mut statuses = [a?, b?];
    statuses.sort_unstable();
    anyhow::ensure!(
        statuses == [200, 303],
        "one post creates the owner and the other finds the link used: {statuses:?}"
    );
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 1);
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_organisations")
            .await?
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn no_setup_link_is_minted_once_the_instance_has_an_account() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    given.the_owner().await?;
    let ran = given.testcase.fixture.running(&["setup-link"]).await?;
    anyhow::ensure!(
        !ran.success,
        "setup-link succeeded after an account existed"
    );
    anyhow::ensure!(
        ran.stderr.contains("already has an account"),
        "{}",
        ran.stderr
    );
    anyhow::ensure!(!ran.stdout.contains("grund_setup_"), "{}", ran.stdout);
    anyhow::ensure!(
        given
            .testcase
            .fixture
            .count("SELECT count(*) FROM grund_setup_links WHERE used_at IS NULL")
            .await?
            == 0
    );
    Ok(())
}

#[tokio::test]
async fn a_newer_setup_link_retires_the_older_one() -> anyhow::Result<()> {
    let Some((given, _when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let older = given.testcase.fixture.setup_link().await?;
    let newer = given.testcase.fixture.setup_link().await?;
    anyhow::ensure!(older != newer);
    let password = "a long enough password here";
    let status =
        posting_the_owner_form(&given, &older, &given.a_fresh_name("old"), password).await?;
    anyhow::ensure!(status == 200, "the older link answered {status}");
    then.body_contains("expired")?;
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 0);
    let status =
        posting_the_owner_form(&given, &newer, &given.a_fresh_name("new"), password).await?;
    anyhow::ensure!(status == 303, "the newer link answered {status}");
    Ok(())
}

#[tokio::test]
async fn a_setup_link_does_not_work_on_another_instance() -> anyhow::Result<()> {
    let Some((given, _when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let Some((elsewhere, _, elsewhere_then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    let password = "a long enough password here";
    let status = posting_the_owner_form(
        &elsewhere,
        &link,
        &elsewhere.a_fresh_name("thief"),
        password,
    )
    .await?;
    anyhow::ensure!(status == 200, "another instance answered {status}");
    elsewhere_then
        .body_contains("expired")?
        .sets_no_session_cookie()?;
    anyhow::ensure!(elsewhere.testcase.fixture.count(ACCOUNTS).await? == 0);

    let status =
        posting_the_owner_form(&given, &link, &given.a_fresh_name("owner"), password).await?;
    anyhow::ensure!(status == 303, "its own instance answered {status}");
    then.status(303)?;
    Ok(())
}

#[tokio::test]
async fn a_form_that_does_not_validate_keeps_the_setup_link() -> anyhow::Result<()> {
    let Some((given, _when, then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let link = given.testcase.fixture.setup_link().await?;
    for (username, password, message) in [
        ("admin", "a long enough password here", "reserved"),
        ("fine-name", "short", "12 characters"),
    ] {
        let status = posting_the_owner_form(&given, &link, username, password).await?;
        anyhow::ensure!(status == 422, "{username}: {status}");
        then.body_contains(message)?.sets_no_session_cookie()?;
    }
    anyhow::ensure!(given.testcase.fixture.count(ACCOUNTS).await? == 0);
    let status = posting_the_owner_form(
        &given,
        &link,
        &given.a_fresh_name("owner"),
        "a long enough password here",
    )
    .await?;
    anyhow::ensure!(status == 303, "{status}");
    Ok(())
}

#[tokio::test]
async fn a_multi_organisation_instance_has_no_setup_link() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let ran = given.testcase.fixture.running(&["setup-link"]).await?;
    anyhow::ensure!(!ran.success);
    anyhow::ensure!(
        ran.stderr.contains("GRUND_ORGANISATIONS is multi"),
        "{}",
        ran.stderr
    );
    anyhow::ensure!(!ran.stdout.contains("grund_setup_"));
    when.visiting("/signup/owner?token=grund_setup_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .await?;
    then.status(200)?.body_contains("expired")?;
    when.visiting("/signup").await?;
    then.status(200)?.body_contains("Create an account")?;
    Ok(())
}
