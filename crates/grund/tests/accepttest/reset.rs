use crate::accepttest::fixtures::{mail_count, testcase_with_mail};

#[tokio::test]
async fn a_reset_request_answers_the_same_for_known_and_unknown_addresses() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.an_account().await?;
    let unknown = format!("{}@accept.test", given.a_fresh_name("nobody"));

    when.submitting("/reset", "/reset", &[("email", &unknown)])
        .await?;
    then.redirects_to("/reset/sent")?;
    when.submitting("/reset", "/reset", &[("email", &account.email)])
        .await?;
    then.redirects_to("/reset/sent")?;

    when.the_mailed_link(
        &account.email,
        "Reset your grund password",
        "/reset/confirm?token=",
    )
    .await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    anyhow::ensure!(
        mail_count(&given, &unknown).await? == 0,
        "mail was sent to an address with no account"
    );
    Ok(())
}

#[tokio::test]
async fn a_reset_link_sets_the_password_once_and_signs_every_device_out() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let (_, other, other_then) = given.testcase.another_browser();

    other
        .submitting("/reset", "/reset", &[("email", &account.email)])
        .await?;
    let link = other
        .the_mailed_link(
            &account.email,
            "Reset your grund password",
            "/reset/confirm?token=",
        )
        .await?;
    other.visiting(&link).await?;
    other_then
        .status(200)?
        .header("referrer-policy", "same-origin")?;
    let token = link.split("token=").nth(1).unwrap_or_default().to_string();
    other
        .submitting_on_current_page(
            "/reset/confirm",
            &[("token", &token), ("password", "short")],
        )
        .await?;
    other_then
        .status(422)?
        .body_contains("Use at least 12 characters.")?;
    other
        .submitting_on_current_page(
            "/reset/confirm",
            &[("token", &token), ("password", "a brand new long password")],
        )
        .await?;
    other_then
        .status(200)?
        .body_contains("Your password is set")?;

    when.visiting_home().await?;
    then.status(303)?;
    other
        .signing_in(&account.username, &account.password)
        .await?;
    other_then.status(200)?;
    other
        .signing_in(&account.username, "a brand new long password")
        .await?;
    other_then.redirects_to("/")?;
    other.visiting(&link).await?;
    other_then.body_contains("This link has expired")?;
    Ok(())
}

#[tokio::test]
async fn a_reset_confirms_an_address_that_someone_else_signed_up_with_first() -> anyhow::Result<()>
{
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let squatted = given.an_unconfirmed_account().await?;

    when.submitting("/reset", "/reset", &[("email", &squatted.email)])
        .await?;
    let link = when
        .the_mailed_link(
            &squatted.email,
            "Reset your grund password",
            "/reset/confirm?token=",
        )
        .await?;
    when.visiting(&link).await?;
    let token = link.split("token=").nth(1).unwrap_or_default().to_string();
    when.submitting_on_current_page(
        "/reset/confirm",
        &[
            ("token", &token),
            ("password", "the rightful owner's password"),
        ],
    )
    .await?;
    then.status(200)?;
    when.signing_in(&squatted.email, "the rightful owner's password")
        .await?;
    then.redirects_to("/")?;
    when.signing_in(&squatted.email, &squatted.password).await?;
    then.status(200)?.sets_no_session_cookie()?;
    Ok(())
}
