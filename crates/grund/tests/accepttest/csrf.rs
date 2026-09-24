use crate::accepttest::fixtures::{testcase, testcase_with_mail};

#[tokio::test]
async fn a_form_without_its_token_is_refused() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;
    let origin = when.testcase.fixture.origin.serialized();

    when.visiting("/login").await?;
    when.posting_raw(
        "/login",
        &[("login", "someone"), ("password", "whatever it is")],
        Some(&origin),
    )
    .await?;
    then.status(403)?.body_contains("This form has expired")?;
    when.posting_raw(
        "/login",
        &[("csrf", "forged"), ("login", "someone"), ("password", "x")],
        Some(&origin),
    )
    .await?;
    then.status(403)?;
    Ok(())
}

#[tokio::test]
async fn a_form_posted_from_another_site_is_refused_even_with_a_valid_token() -> anyhow::Result<()>
{
    let (_given, when, then) = testcase().await?;

    let page = when.send("GET", "/reset", &[], None).await?;
    let csrf = crate::accepttest::fixtures::csrf_of(&page.text()).expect("csrf");
    when.posting_raw(
        "/reset",
        &[("csrf", &csrf), ("email", "a@example.com")],
        Some("https://evil.example"),
    )
    .await?;
    then.status(403)?;
    let body = format!("csrf={csrf}&email=a%40example.com");
    when.requesting_with(
        "POST",
        "/reset",
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Sec-Fetch-Site", "cross-site"),
        ],
        Some(body.as_bytes()),
    )
    .await?;
    then.status(403)?;
    Ok(())
}

#[tokio::test]
async fn a_signed_in_form_needs_the_token_bound_to_that_session() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let stale = {
        let page = when.send("GET", "/login", &[], None).await?;
        crate::accepttest::fixtures::csrf_of(&page.text()).expect("csrf")
    };
    given.a_signed_in_account().await?;

    when.submitting_with_token("/logout", &stale, &[]).await?;
    then.status(403)?;
    when.visiting("/").await?;
    then.status(200)?;
    Ok(())
}
