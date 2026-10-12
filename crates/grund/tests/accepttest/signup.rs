use std::time::{Duration, Instant};

use crate::accepttest::fixtures::{DEFAULT_SMTP_URL, testcase_configured, testcase_with_mail};

#[tokio::test]
async fn a_new_account_can_sign_in_only_after_confirming_its_email() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.an_unconfirmed_account().await?;

    when.signing_in(&account.username, &account.password)
        .await?;
    then.status(200)?
        .body_contains("Confirm your email first")?
        .sets_no_session_cookie()?;

    let newest = when
        .the_newest_of_mailed_links(&account.email, "Confirm your email", "/verify?token=", 2)
        .await?;
    when.visiting(&newest).await?;
    then.status(200)?
        .header("referrer-policy", "same-origin")?
        .body_contains("Confirm email")?;
    let token = given.last_token()?;
    when.submitting_on_current_page("/verify", &[("token", &token)])
        .await?;
    then.status(200)?.body_contains("Your email is confirmed")?;

    when.signing_in(&account.username, &account.password)
        .await?;
    then.redirects_to("/")?;
    when.visiting_home().await?;
    then.status(200)?.body_contains(&format!(
        "aria-label=\"{}: account menu\"",
        account.username
    ))?;
    Ok(())
}

#[tokio::test]
async fn smtp_outage_keeps_verification_queued_until_sending_recovers() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let smtp_url = format!("smtp://{}", listener.local_addr()?);
    drop(listener);
    let Some((given, when, then)) = testcase_configured(&[("GRUND_SMTP_URL", &smtp_url)]).await?
    else {
        return Ok(());
    };
    let account =
        tokio::time::timeout(Duration::from_secs(10), given.an_unconfirmed_account()).await??;
    then.redirects_to("/signup/sent")?;
    let fixture = &given.testcase.fixture;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let waiting = fixture
            .count("SELECT count(*) FROM grund_outbox WHERE kind = 'mail.verify_email' AND delivered_at IS NULL AND last_error IS NOT NULL AND recipient <> '' AND payload ? 'link'")
            .await?;
        if waiting == 1 {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "verification mail was not retained after SMTP refusal"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let smtp_url = std::env::var("GRUND_ACCEPT_SMTP_URL")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_SMTP_URL.to_string());
    fixture
        .restart_with(&[("GRUND_SMTP_URL", &smtp_url)])
        .await?;
    let link = when
        .the_mailed_link(&account.email, "Confirm your email", "/verify?token=")
        .await?;
    when.visiting(&link).await?;
    then.status(200)?.body_contains("Confirm email")?;
    when.submitting_on_current_page("/verify", &[("token", &given.last_token()?)])
        .await?;
    then.status(200)?.body_contains("Your email is confirmed")?;
    anyhow::ensure!(
        fixture
            .count("SELECT count(*) FROM grund_outbox WHERE kind = 'mail.verify_email' AND delivered_at IS NOT NULL AND recipient = '' AND payload = '{}'::jsonb")
            .await? == 1,
        "delivered verification mail was not scrubbed"
    );
    Ok(())
}

#[tokio::test]
async fn the_first_link_still_confirms_after_signing_in_mailed_a_second() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.an_unconfirmed_account().await?;
    let first = when
        .the_mailed_link(&account.email, "Confirm your email", "/verify?token=")
        .await?;
    when.signing_in(&account.username, &account.password)
        .await?;
    then.body_contains("Confirm your email first")?;
    let second = when
        .the_newest_of_mailed_links(&account.email, "Confirm your email", "/verify?token=", 2)
        .await?;
    let oldest = when
        .the_oldest_of_mailed_links(&account.email, "Confirm your email", "/verify?token=", 2)
        .await?;
    assert_eq!(oldest, first, "the first mail is the oldest");
    assert_ne!(first, second, "signing in mailed a new link");

    when.visiting(&first).await?;
    then.status(200)?.body_contains("Confirm email")?;
    let token = given.last_token()?;
    when.submitting_on_current_page("/verify", &[("token", &token)])
        .await?;
    then.status(200)?.body_contains("Your email is confirmed")?;

    when.visiting(&second).await?;
    then.status(200)?.body_contains("This link has expired")?;
    Ok(())
}

#[tokio::test]
async fn a_verification_link_works_once() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.an_unconfirmed_account().await?;
    let link = when
        .the_mailed_link(&account.email, "Confirm your email", "/verify?token=")
        .await?;

    when.visiting(&link).await?;
    let token = given.last_token()?;
    when.submitting_on_current_page("/verify", &[("token", &token)])
        .await?;
    then.status(200)?;
    when.visiting(&link).await?;
    then.status(200)?.body_contains("This link has expired")?;
    Ok(())
}

#[tokio::test]
async fn signing_up_with_an_address_that_has_an_account_answers_the_same_and_mails_its_owner()
-> anyhow::Result<()> {
    let Some((given, when, _)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let existing = given.an_account().await?;
    let (_, stranger, stranger_then) = given.testcase.another_browser();

    stranger
        .signing_up(
            &given.a_fresh_name("copy"),
            &existing.email.to_uppercase(),
            "another long password",
        )
        .await?;
    stranger_then.redirects_to("/signup/sent")?;
    when.the_mailed_link(
        &existing.email,
        "You already have a grund account",
        "/reset",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn a_taken_username_is_said_plainly_and_nothing_is_created() -> anyhow::Result<()> {
    let Some((given, _, _)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let existing = given.an_unconfirmed_account().await?;
    let (_, other, other_then) = given.testcase.another_browser();

    other
        .signing_up(
            &existing.username.to_uppercase(),
            "someone.else@accept.test",
            "another long password",
        )
        .await?;
    other_then
        .status(422)?
        .body_contains("That username is taken.")?;
    Ok(())
}

#[tokio::test]
async fn an_invalid_sign_up_names_each_field_that_is_wrong() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    given.ensure_first_owner().await?;
    when.signing_up("-x", "not-an-address", "short").await?;
    then.status(422)?
        .body_contains("Use 3 to 32 characters.")?
        .body_contains("Enter an email address like name@example.com.")?
        .body_contains("Use at least 12 characters.")?;
    Ok(())
}
