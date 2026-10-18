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
    when.visiting_home().await?;
    then.status(200)?;
    Ok(())
}

#[tokio::test]
async fn image_update_forms_refuse_csrf_before_membership_or_input_validation() -> anyhow::Result<()>
{
    let (_given, when, then) = testcase().await?;
    when.visiting("/login").await?;
    let origin = when.form_origin();
    for action in ["check", "apply"] {
        when.posting_raw(
            &format!("/missing/apps/missing/updates/{action}"),
            &[("base_release", "not-a-number")],
            Some(&origin),
        )
        .await?;
        then.status(403)?.body_contains("This form has expired")?;
    }
    Ok(())
}

#[tokio::test]
async fn credential_reveal_refuses_forged_forms_and_never_reads_a_user_entered_secret()
-> anyhow::Result<()> {
    use base64::Engine;
    use serde_json::json;

    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = &owner.username;
    crate::accepttest::apps::call(
        &when,
        &then,
        "CreateApp",
        json!({"organisation": org, "name": "database"}),
    )
    .await?;
    then.status(200)?;
    let secret = "user-entered-credential-reveal-test";
    crate::accepttest::apps::call(
        &when,
        &then,
        "SetSecret",
        json!({
            "organisation": org,
            "name": "database",
            "secret": "postgres-password",
            "value": base64::engine::general_purpose::STANDARD.encode(secret)
        }),
    )
    .await?;
    then.status(200)?;
    let action = format!("/{org}/apps/database/credentials/reveal");
    let page = format!("/{org}/apps/database");
    when.visiting(&page).await?;
    then.status(200)?.body_lacks(secret)?;
    let csrf = crate::accepttest::fixtures::csrf_of(&then.body()?).expect("csrf");
    let origin = when.form_origin();
    for token in [None, Some("forged")] {
        let mut fields = vec![("variable", "postgres-password")];
        if let Some(token) = token {
            fields.push(("csrf", token));
        }
        when.posting_raw(&action, &fields, Some(&origin)).await?;
        then.status(403)?.body_lacks(secret)?;
    }
    let (_other_given, other_when, _other_then) = given.testcase.another_browser();
    let other_page = other_when.send("GET", "/login", &[], None).await?;
    let other_csrf = crate::accepttest::fixtures::csrf_of(&other_page.text()).expect("csrf");
    when.submitting_with_token(&action, &other_csrf, &[("variable", "postgres-password")])
        .await?;
    then.status(403)?.body_lacks(secret)?;
    when.submitting_with_token(&action, &csrf, &[("variable", "postgres-password")])
        .await?;
    then.status(404)?
        .header("cache-control", "no-store, no-transform")?
        .header("referrer-policy", "same-origin")?
        .body_lacks(secret)?;
    when.visiting(&action).await?;
    then.status(405)?.body_lacks(secret)?;
    Ok(())
}
