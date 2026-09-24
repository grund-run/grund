use crate::accepttest::fixtures::testcase_with_mail;

fn revoke_action(html: &str) -> Option<String> {
    html.split("action=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|action| action.starts_with("/settings/sessions/") && action.ends_with("/revoke"))
        .map(str::to_string)
}

#[tokio::test]
async fn the_sessions_page_lists_every_device_and_signs_one_out() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let (_, laptop, laptop_then) = given.testcase.another_browser();
    laptop.signing_in(&account.email, &account.password).await?;
    laptop_then.redirects_to("/")?;

    when.visiting("/settings/sessions").await?;
    then.status(200)?.body_contains("This device")?;
    let page = when.send("GET", "/settings/sessions", &[], None).await?;
    let action = revoke_action(&page.text()).expect("the other device has a sign-out form");
    when.visiting("/settings/sessions").await?;
    when.submitting_on_current_page(&action, &[]).await?;
    then.redirects_to("/settings/sessions?done=revoked")?;

    laptop.visiting("/").await?;
    laptop_then.status(303)?;
    when.visiting("/").await?;
    then.status(200)?;
    Ok(())
}

#[tokio::test]
async fn another_accounts_session_is_not_found_and_keeps_working() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;

    let (victim_given, victim, _) = given.testcase.another_browser();
    let victim_account = victim_given.a_signed_in_account().await?;
    let (_, victim_laptop, victim_laptop_then) = given.testcase.another_browser();
    victim_laptop
        .signing_in(&victim_account.username, &victim_account.password)
        .await?;
    victim_laptop_then.redirects_to("/")?;
    let page = victim.send("GET", "/settings/sessions", &[], None).await?;
    let victim_action = revoke_action(&page.text()).expect("the victim's other device");

    when.visiting("/settings/sessions").await?;
    when.submitting_on_current_page(&victim_action, &[]).await?;
    then.status(404)?;
    victim_laptop.visiting("/").await?;
    victim_laptop_then.status(200)?;

    when.visiting("/settings/sessions").await?;
    when.submitting_on_current_page("/settings/sessions/not-a-uuid/revoke", &[])
        .await?;
    then.status(404)?;
    Ok(())
}

#[tokio::test]
async fn signing_out_everywhere_else_keeps_only_this_device() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let (_, phone, phone_then) = given.testcase.another_browser();
    phone
        .signing_in(&account.username, &account.password)
        .await?;

    when.visiting("/settings/sessions").await?;
    when.submitting_on_current_page("/settings/sessions/revoke-others", &[])
        .await?;
    then.redirects_to("/settings/sessions?done=others")?;
    phone.visiting("/").await?;
    phone_then.status(303)?;
    when.visiting("/").await?;
    then.status(200)?;
    Ok(())
}
