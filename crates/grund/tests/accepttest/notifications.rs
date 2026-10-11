use serde_json::{Value, json};

use crate::accepttest::fixtures::testcase_with_mail;

const NOTIFICATIONS: &str = "/grund.notification.v1.NotificationService";

async fn call(
    when: &crate::accepttest::fixtures::When,
    then: &crate::accepttest::fixtures::Then,
    method: &str,
    body: Value,
) -> anyhow::Result<Value> {
    when.calling(&format!("{NOTIFICATIONS}/{method}"), &body.to_string())
        .await?;
    then.status(200)?;
    then.json()
}

fn items(value: &Value) -> anyhow::Result<&[Value]> {
    match value.get("notifications") {
        None => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => anyhow::bail!("notification list is malformed: {value}"),
    }
}

fn unread_count(answer: &Value) -> Option<u64> {
    if answer["count"].is_null() {
        return Some(0);
    }
    answer["count"]
        .as_u64()
        .or_else(|| answer["count"].as_str()?.parse().ok())
}

#[tokio::test]
async fn invitations_reach_only_the_verified_recipient_and_can_be_declined_without_a_link()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (recipient, recipient_when, recipient_then) = given.testcase.another_browser();
    let invited = recipient.a_signed_in_account().await?;
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    let outsider_account = outsider.a_signed_in_account().await?;

    when.inviting(&owner.username, &invited.email, "member")
        .await?;
    then.status(303)?;
    recipient_when
        .visiting(&format!("/{}", invited.username))
        .await?;
    recipient_then
        .status(200)?
        .body_contains(&owner.username)?
        .body_contains("Accept")?
        .body_contains("Decline")?
        .body_lacks("/invite?token=")?;
    recipient_when.visiting("/notifications").await?;
    recipient_then.status(200)?.body_contains(&owner.username)?;
    let found = call(
        &recipient_when,
        &recipient_then,
        "ListNotifications",
        json!({}),
    )
    .await?;
    let invitations = items(&found)?;
    anyhow::ensure!(invitations.len() == 1, "one invitation fact: {found}");
    let notification_id = invitations[0]["id"].as_str().unwrap_or_default();
    let invitation_id = invitations[0]["sourceId"].as_str().unwrap_or_default();
    anyhow::ensure!(!notification_id.is_empty(), "id missing: {found}");

    let other = call(
        &outsider_when,
        &outsider_then,
        "ListNotifications",
        json!({}),
    )
    .await?;
    anyhow::ensure!(items(&other)?.is_empty(), "other account saw: {other}");
    outsider_when
        .visiting(&format!("/{}", outsider_account.username))
        .await?;
    outsider_then.body_lacks(&owner.username)?;
    outsider_when
        .calling(
            &format!("{NOTIFICATIONS}/MarkRead"),
            &json!({"id": notification_id}).to_string(),
        )
        .await?;
    anyhow::ensure!(
        outsider_then.status(404).is_ok() || outsider_then.status(400).is_ok(),
        "foreign notification was accepted"
    );
    outsider_when
        .submitting(
            &format!("/{}", outsider_account.username),
            &format!("/invitations/{invitation_id}/decline"),
            &[],
        )
        .await?;
    outsider_then.status(404)?;
    recipient_when
        .submitting("/notifications", "/notifications/read-all", &[])
        .await?;
    recipient_then.redirects_to("/notifications")?;
    let unread = call(&recipient_when, &recipient_then, "CountUnread", json!({})).await?;
    anyhow::ensure!(
        unread_count(&unread) == Some(0),
        "mark all left unread: {unread}"
    );
    let still_there = call(
        &recipient_when,
        &recipient_then,
        "ListNotifications",
        json!({}),
    )
    .await?;
    anyhow::ensure!(
        items(&still_there)?.len() == 1,
        "mark all deleted history: {still_there}"
    );

    let path = format!("/invitations/{invitation_id}/decline");
    recipient_when
        .submitting(&format!("/{}", invited.username), &path, &[])
        .await?;
    recipient_then.status(303)?;
    recipient_when
        .visiting(&format!("/{}", invited.username))
        .await?;
    recipient_then.body_lacks(&path)?;
    let owner_view = call(&when, &then, "ListNotifications", json!({})).await?;
    anyhow::ensure!(
        items(&owner_view)?.is_empty(),
        "sender got recipient fact: {owner_view}"
    );
    Ok(())
}

#[tokio::test]
async fn accepting_and_reading_invitations_updates_only_the_recipient() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (guest, guest_when, guest_then) = given.testcase.another_browser();
    let account = guest.a_signed_in_account().await?;
    when.inviting(&owner.username, &account.email, "member")
        .await?;
    let found = call(
        &guest_when,
        &guest_then,
        "ListNotifications",
        json!({"unreadOnly": true}),
    )
    .await?;
    let item = items(&found)?
        .first()
        .ok_or_else(|| anyhow::anyhow!("invitation missing: {found}"))?;
    let id = item["id"].as_str().unwrap_or_default();
    let invitation_id = item["sourceId"].as_str().unwrap_or_default();
    anyhow::ensure!(!id.is_empty() && !invitation_id.is_empty());
    let count = call(&guest_when, &guest_then, "CountUnread", json!({})).await?;
    anyhow::ensure!(unread_count(&count) == Some(1), "{count}");
    call(&guest_when, &guest_then, "MarkRead", json!({"id": id})).await?;
    let count = call(&guest_when, &guest_then, "CountUnread", json!({})).await?;
    anyhow::ensure!(unread_count(&count) == Some(0), "{count}");
    let path = format!("/invitations/{invitation_id}/accept");
    guest_when
        .submitting(&format!("/{}", account.username), &path, &[])
        .await?;
    guest_then.redirects_to(&format!("/{}", owner.username))?;
    guest_when.visiting(&format!("/{}", owner.username)).await?;
    guest_then.status(200)?;
    let owner_items = call(&when, &then, "ListNotifications", json!({})).await?;
    anyhow::ensure!(
        items(&owner_items)?.is_empty(),
        "sender saw recipient's fact: {owner_items}"
    );
    when.calling(
        "/grund.organisation.v1.OrganisationService/ListMembers",
        &json!({"slug": owner.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    let members = then.json()?;
    let account_id = members["members"]
        .as_array()
        .and_then(|members| {
            members
                .iter()
                .find(|member| member["username"] == account.username)
        })
        .and_then(|member| member["accountId"].as_str())
        .ok_or_else(|| anyhow::anyhow!("new member absent: {members}"))?;
    when.calling(
        "/grund.organisation.v1.OrganisationService/RemoveMember",
        &json!({"slug": owner.username, "accountId": account_id}).to_string(),
    )
    .await?;
    then.status(200)?;
    let removed = call(&guest_when, &guest_then, "ListNotifications", json!({})).await?;
    anyhow::ensure!(
        items(&removed)?.is_empty(),
        "removed member retained organisation facts: {removed}"
    );
    Ok(())
}

#[tokio::test]
async fn an_invitation_sent_before_verification_is_visible_after_verification() -> anyhow::Result<()>
{
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (recipient, recipient_when, recipient_then) = given.testcase.another_browser();
    let account = recipient.an_unconfirmed_account().await?;
    when.inviting(&owner.username, &account.email, "member")
        .await?;
    then.status(303)?;
    recipient_when
        .following_the_mailed_link(&account.email, "Confirm your email", "/verify?token=")
        .await?;
    recipient_when
        .submitting_on_current_page("/verify", &[("token", &recipient.last_token()?)])
        .await?;
    recipient_then.status(200)?;
    recipient_when
        .signing_in(&account.username, &account.password)
        .await?;
    recipient_then.status(303)?;
    recipient_when
        .visiting(&format!("/{}", account.username))
        .await?;
    recipient_then
        .status(200)?
        .body_contains(&owner.username)?
        .body_contains("Accept")?;
    let inbox = call(
        &recipient_when,
        &recipient_then,
        "ListNotifications",
        json!({}),
    )
    .await?;
    anyhow::ensure!(
        items(&inbox)?
            .iter()
            .filter(|item| item["kind"] == "invitation.received")
            .count()
            == 1,
        "verified address has one invitation fact: {inbox}"
    );
    Ok(())
}

#[tokio::test]
async fn out_of_service_is_one_fact_for_the_machine_owner_not_another_organisation()
-> anyhow::Result<()> {
    let (given, when, then) = crate::accepttest::fixtures::testcase().await?;
    let owner = given.a_signed_in_account().await?;
    let (other, other_when, other_then) = given.testcase.another_browser();
    let stranger = other.a_signed_in_account().await?;
    let _agent =
        crate::accepttest::apps::a_machine(&when, &then, &owner.username, "notify-box").await?;
    when.calling(
        "/grund.machine.v1.MachineService/ListMachines",
        &json!({"organisation": owner.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    let machines = then.json()?;
    let machine_id = machines["machines"][0]["machineId"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("machine missing identifier: {machines}"))?;
    let body = json!({"organisation": owner.username, "machineId": machine_id, "inService": false})
        .to_string();
    when.calling(
        "/grund.machine.v1.MachineService/SetMachineInService",
        &body,
    )
    .await?;
    then.status(200)?;
    when.calling(
        "/grund.machine.v1.MachineService/SetMachineInService",
        &body,
    )
    .await?;
    then.status(200)?;
    let inbox = call(&when, &then, "ListNotifications", json!({})).await?;
    let service: Vec<&Value> = items(&inbox)?
        .iter()
        .filter(|item| item["kind"] == "machine.out_of_service")
        .collect();
    anyhow::ensure!(
        service.len() == 1,
        "repeated transition produced duplicates: {inbox}"
    );
    let unrelated = call(&other_when, &other_then, "ListNotifications", json!({})).await?;
    anyhow::ensure!(
        items(&unrelated)?.is_empty(),
        "another organisation saw machine: {unrelated}"
    );
    when.inviting(&owner.username, &stranger.email, "member")
        .await?;
    then.status(303)?;
    let invite = call(&other_when, &other_then, "ListNotifications", json!({})).await?;
    let invitation_id = items(&invite)?
        .iter()
        .find(|item| item["kind"] == "invitation.received")
        .and_then(|item| item["sourceId"].as_str())
        .ok_or_else(|| anyhow::anyhow!("late joiner invitation missing: {invite}"))?;
    other_when
        .submitting(
            &format!("/{}", stranger.username),
            &format!("/invitations/{invitation_id}/accept"),
            &[],
        )
        .await?;
    other_then.status(303)?;
    let after = call(&other_when, &other_then, "ListNotifications", json!({})).await?;
    anyhow::ensure!(
        items(&after)?
            .iter()
            .all(|item| item["kind"] != "machine.out_of_service"),
        "joining after the transition delivered historical machine facts: {after}"
    );
    Ok(())
}
