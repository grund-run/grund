use crate::accepttest::fixtures::testcase_with_mail;

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
        .header("referrer-policy", "no-referrer")?
        .body_contains("Confirm email")?;
    let token = given.last_token()?;
    when.submitting_on_current_page("/verify", &[("token", &token)])
        .await?;
    then.status(200)?.body_contains("Your email is confirmed")?;

    when.signing_in(&account.username, &account.password)
        .await?;
    then.redirects_to("/")?;
    when.visiting("/").await?;
    then.status(200)?
        .body_contains(&format!("Signed in as {}", account.username))?;
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
    let Some((_given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };

    when.signing_up("-x", "not-an-address", "short").await?;
    then.status(422)?
        .body_contains("Use 3 to 32 characters.")?
        .body_contains("Enter an email address like name@example.com.")?
        .body_contains("Use at least 12 characters.")?;
    Ok(())
}
