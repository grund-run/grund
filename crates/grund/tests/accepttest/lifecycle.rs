use std::time::{Duration, Instant};

use crate::accepttest::fixtures::{
    AccountAnswer, BILLING_TOKEN, DeletionAnswer, FakeBilling, Given, Then, When,
    testcase_configured, testcase_with_mail,
};

const ORGS: &str = "/grund.organisation.v1.OrganisationService";

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
    when.visiting(&format!("/{old}/settings/members?x=1"))
        .await?;
    then.status(308)?
        .header("location", &format!("/{new}/settings/members?x=1"))?;
    when.visiting(&format!("/{new}/members?x=1")).await?;
    then.status(308)?
        .header("location", &format!("/{new}/settings/members?x=1"))?;

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
    let admin = given.the_owner().await?;
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
async fn owners_see_their_billing_account_in_organisation_settings() -> anyhow::Result<()> {
    let billing = FakeBilling::start(DeletionAnswer::Allow).await?;
    let Some((given, when, then)) = billed_by(&billing).await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;

    let path = format!("/{}/settings", account.username);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        when.visiting(&path).await?;
        then.status(200)?;
        if then.body_contains("Pro").is_ok() {
            then.body_lacks(&format!("/{}/settings/billing", account.username))?;
            break;
        }
        anyhow::ensure!(Instant::now() < deadline, "billing plan never showed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[tokio::test]
async fn settings_omits_an_uncached_plan_without_waiting_and_shows_it_after_one_refresh()
-> anyhow::Result<()> {
    let billing = FakeBilling::start_with_account(
        DeletionAnswer::Allow,
        AccountAnswer::Delayed(Duration::from_millis(1800)),
    )
    .await?;
    let Some((given, when, then)) = billed_by(&billing).await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let path = format!("/{}/settings", account.username);
    tokio::time::timeout(Duration::from_secs(1), when.visiting(&path)).await??;
    then.status(200)?
        .body_contains("Managed by")?
        .body_lacks("<p class=\"row-name\">Plan</p>")?
        .body_lacks("Billing is unavailable")?;
    billing
        .wait_for("GetAccount", 1, Duration::from_secs(5))
        .await?;
    when.visiting(&path).await?;
    then.status(200)?;
    anyhow::ensure!(
        billing.calls("GetAccount").len() == 1,
        "duplicate account refresh"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        when.visiting(&path).await?;
        if then.body_contains("<p class=\"row-name\">Plan</p>").is_ok()
            && then.body_contains("Pro").is_ok()
        {
            break;
        }
        anyhow::ensure!(Instant::now() < deadline, "billing plan never showed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[tokio::test]
async fn settings_omits_an_unavailable_plan_without_misreporting_it_as_free() -> anyhow::Result<()>
{
    let billing =
        FakeBilling::start_with_account(DeletionAnswer::Allow, AccountAnswer::Unavailable).await?;
    let Some((given, when, then)) = billed_by(&billing).await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let path = format!("/{}/settings", account.username);
    when.visiting(&path).await?;
    then.status(200)?
        .body_lacks("<p class=\"row-name\">Plan</p>")?
        .body_lacks("Billing is unavailable")?
        .body_lacks("Nothing is charged.")?;
    billing
        .wait_for("GetAccount", 1, Duration::from_secs(5))
        .await?;
    when.visiting(&path).await?;
    then.status(200)?
        .body_lacks("<p class=\"row-name\">Plan</p>")?
        .body_lacks("Billing is unavailable")?
        .body_lacks("Nothing is charged.")?;
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
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if billing.calls("RecordOrganisation").iter().any(|call| {
            call.body["change"] == "ORGANISATION_CHANGE_DELETED"
                && call.body["slug"] == team.as_str()
        }) {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "billing did not record the deletion"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[tokio::test]
async fn the_api_manages_organisations_and_hides_other_peoples() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let slug = given.a_fresh_name("api");

    when.calling(
        &format!("{ORGS}/CreateOrganisation"),
        &format!(r#"{{"slug":"{slug}"}}"#),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(then.json()?["organisation"]["role"] == "ROLE_OWNER");

    when.calling(&format!("{ORGS}/ListOrganisations"), "{}")
        .await?;
    let listed: Vec<String> = then.json()?["organisations"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|o| o["slug"].as_str().map(str::to_string))
        .collect();
    anyhow::ensure!(
        listed.contains(&slug) && listed.contains(&account.username),
        "{listed:?}"
    );

    when.calling(
        &format!("{ORGS}/InviteMember"),
        &format!(r#"{{"slug":"{slug}","email":"friend-{slug}@accept.test","role":"ROLE_MEMBER"}}"#),
    )
    .await?;
    then.status(200)?;
    when.calling(
        &format!("{ORGS}/ListInvitations"),
        &format!(r#"{{"slug":"{slug}"}}"#),
    )
    .await?;
    anyhow::ensure!(then.json()?["invitations"].as_array().map(Vec::len) == Some(1));

    when.calling(
        &format!("{ORGS}/InviteMember"),
        &format!(r#"{{"slug":"{slug}","email":"x@accept.test","role":"ROLE_OWNER"}}"#),
    )
    .await?;
    then.status(400)?.connect_code("invalid_argument")?;

    when.calling(
        &format!("{ORGS}/ListMembers"),
        &format!(r#"{{"slug":"{slug}"}}"#),
    )
    .await?;
    let members = then.json()?["members"].clone();
    let me = members[0]["accountId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    when.calling(
        &format!("{ORGS}/RemoveMember"),
        &format!(r#"{{"slug":"{slug}","accountId":"{me}"}}"#),
    )
    .await?;
    then.status_in(&[400, 412])?
        .connect_code("failed_precondition")?;

    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    for method in ["GetOrganisation", "ListMembers", "ListInvitations"] {
        outsider_when
            .calling(
                &format!("{ORGS}/{method}"),
                &format!(r#"{{"slug":"{slug}"}}"#),
            )
            .await?;
        outsider_then
            .status(404)
            .and_then(|t| t.connect_code("not_found"))
            .map_err(|e| e.context(method))?;
    }
    outsider_when
        .calling(
            &format!("{ORGS}/DeleteOrganisation"),
            &format!(r#"{{"slug":"{slug}","confirmSlug":"{slug}"}}"#),
        )
        .await?;
    outsider_then.status(404)?;

    let renamed = given.a_fresh_name("api-renamed");
    when.calling(
        &format!("{ORGS}/RenameOrganisation"),
        &format!(r#"{{"slug":"{slug}","newSlug":"{renamed}"}}"#),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(then.json()?["organisation"]["slug"] == renamed.as_str());
    when.calling(
        &format!("{ORGS}/DeleteOrganisation"),
        &format!(r#"{{"slug":"{renamed}","confirmSlug":"{renamed}"}}"#),
    )
    .await?;
    then.status(200)?;
    eventually_status(&when, &then, &format!("/{renamed}"), 404).await?;
    Ok(())
}
