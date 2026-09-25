use std::time::{Duration, Instant};

use crate::accepttest::fixtures::{
    BILLING_MANAGE_URL, BILLING_TOKEN, DeletionAnswer, FakeBilling, Given, Then, When,
    testcase_configured, testcase_with_mail,
};

async fn a_team(given: &Given, when: &When, then: &Then) -> anyhow::Result<String> {
    let slug = given.a_fresh_name("team");
    when.submitting("/orgs/new", "/orgs/new", &[("slug", &slug)])
        .await?;
    then.redirects_to(&format!("/{slug}"))?;
    Ok(slug)
}

async fn eventually_status(
    when: &When,
    then: &Then,
    path: &str,
    status: u16,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        when.visiting(path).await?;
        if then.status(status).is_ok() {
            return Ok(());
        }
        anyhow::ensure!(Instant::now() < deadline, "{path} never answered {status}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn billed_by(billing: &FakeBilling) -> anyhow::Result<Option<(Given, When, Then)>> {
    testcase_configured(&[
        ("GRUND_BILLING_URL", &billing.url),
        ("GRUND_BILLING_TOKEN", BILLING_TOKEN),
    ])
    .await
}

#[tokio::test]
async fn a_renamed_organisation_redirects_its_members_and_keeps_its_old_name_from_others()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;
    let old = a_team(&given, &when, &then).await?;
    let new = given.a_fresh_name("renamed");

    when.submitting(
        &format!("/{old}/settings"),
        &format!("/{old}/settings/rename"),
        &[("slug", &new)],
    )
    .await?;
    then.redirects_to(&format!("/{new}/settings?done=renamed"))?;
    when.visiting(&format!("/{old}/members?x=1")).await?;
    then.status(308)?
        .header("location", &format!("/{new}/members?x=1"))?;

    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    outsider_when.visiting(&format!("/{old}")).await?;
    outsider_then.status(404)?;
    outsider_when
        .submitting("/orgs/new", "/orgs/new", &[("slug", &old)])
        .await?;
    outsider_then
        .status(200)?
        .body_contains("That name is taken.")?;

    when.submitting(
        &format!("/{new}/settings"),
        &format!("/{new}/settings/rename"),
        &[("slug", &old)],
    )
    .await?;
    then.redirects_to(&format!("/{old}/settings?done=renamed"))?;
    when.visiting(&format!("/{old}")).await?;
    then.status(200)?;
    Ok(())
}

#[tokio::test]
async fn deleting_needs_the_typed_name_then_the_organisation_is_gone_and_its_name_stays_taken()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let team = a_team(&given, &when, &then).await?;

    when.submitting(
        &format!("/{team}/settings"),
        &format!("/{team}/settings/delete"),
        &[("confirm", "not-it")],
    )
    .await?;
    then.status(200)?
        .body_contains(&format!("Type {team} exactly"))?;
    when.submitting(
        &format!("/{team}/settings"),
        &format!("/{team}/settings/delete"),
        &[("confirm", &team)],
    )
    .await?;
    then.redirects_to(&format!("/{team}/settings"))?;

    eventually_status(&when, &then, &format!("/{team}"), 404).await?;
    when.visiting("/").await?;
    then.redirects_to(&format!("/{}", account.username))?;
    when.submitting("/orgs/new", "/orgs/new", &[("slug", &team)])
        .await?;
    then.status(200)?.body_contains("That name is taken.")?;
    Ok(())
}

#[tokio::test]
async fn the_instance_organisation_cannot_be_deleted() -> anyhow::Result<()> {
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_ORGANISATIONS", "single")]).await?
    else {
        return Ok(());
    };
    let admin = given.a_signed_in_account().await?;
    let org = admin.username.clone();
    when.submitting(
        &format!("/{org}/settings"),
        &format!("/{org}/settings/delete"),
        &[("confirm", &org)],
    )
    .await?;
    then.status(200)?.body_contains("an instance needs it")?;
    when.visiting(&format!("/{org}")).await?;
    then.status(200)?;
    Ok(())
}

#[tokio::test]
async fn owners_see_the_billing_services_plan_and_its_link() -> anyhow::Result<()> {
    let billing = FakeBilling::start(DeletionAnswer::Allow).await?;
    let Some((given, when, then)) = billed_by(&billing).await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;

    when.visiting(&format!("/{}/settings", account.username))
        .await?;
    then.status(200)?
        .body_contains("Pro")?
        .body_contains("Manage billing")?
        .body_contains(
            BILLING_MANAGE_URL
                .trim_start_matches("https://")
                .split('/')
                .next()
                .unwrap_or_default(),
        )?;
    let calls = billing.calls("GetAccount");
    anyhow::ensure!(!calls.is_empty(), "no GetAccount call");
    anyhow::ensure!(
        calls[0].authorization.as_deref() == Some(format!("Bearer {BILLING_TOKEN}").as_str()),
        "{calls:?}"
    );

    let created = billing
        .wait_for("RecordOrganisation", 1, Duration::from_secs(15))
        .await?;
    anyhow::ensure!(
        created[0].body["change"] == "ORGANISATION_CHANGE_CREATED",
        "{created:?}"
    );
    anyhow::ensure!(
        created[0].body["slug"] == account.username.as_str(),
        "{created:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_deletion_billing_refuses_leaves_the_organisation_with_the_reason() -> anyhow::Result<()>
{
    let billing = FakeBilling::start(DeletionAnswer::Refuse("An invoice is unpaid.")).await?;
    let Some((given, when, then)) = billed_by(&billing).await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;
    let team = a_team(&given, &when, &then).await?;

    when.submitting(
        &format!("/{team}/settings"),
        &format!("/{team}/settings/delete"),
        &[("confirm", &team)],
    )
    .await?;
    billing
        .wait_for("CheckDeletion", 1, Duration::from_secs(15))
        .await?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        when.visiting(&format!("/{team}/settings")).await?;
        if then.body_contains("An invoice is unpaid.").is_ok() {
            break;
        }
        anyhow::ensure!(Instant::now() < deadline, "the refusal never showed");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    then.status(200)?.body_contains(&format!("Delete {team}"))?;
    Ok(())
}

#[tokio::test]
async fn a_deletion_waits_while_billing_is_down_and_completes_once_it_answers() -> anyhow::Result<()>
{
    let billing = FakeBilling::start(DeletionAnswer::Unavailable).await?;
    let Some((given, when, then)) = billed_by(&billing).await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;
    let team = a_team(&given, &when, &then).await?;

    when.submitting(
        &format!("/{team}/settings"),
        &format!("/{team}/settings/delete"),
        &[("confirm", &team)],
    )
    .await?;
    billing
        .wait_for("CheckDeletion", 1, Duration::from_secs(15))
        .await?;
    when.visiting(&format!("/{team}/settings")).await?;
    then.status(200)?
        .body_contains(&format!("Deleting {team}"))?
        .body_contains("http-equiv=\"refresh\"")?;

    billing.answer_deletions(DeletionAnswer::Allow);
    eventually_status(&when, &then, &format!("/{team}"), 404).await?;
    let changes = billing
        .wait_for("RecordOrganisation", 3, Duration::from_secs(15))
        .await?;
    anyhow::ensure!(
        changes
            .iter()
            .any(|c| c.body["change"] == "ORGANISATION_CHANGE_DELETED"
                && c.body["slug"] == team.as_str()),
        "{changes:?}"
    );
    Ok(())
}
