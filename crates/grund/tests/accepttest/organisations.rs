use crate::accepttest::fixtures::{Given, testcase_configured, testcase_with_mail};

fn page(given: &Given) -> String {
    given
        .testcase
        .data()
        .last
        .as_ref()
        .map(|r| r.text())
        .unwrap_or_default()
}

fn ids_in_actions(html: &str, before: &str, after: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find(before) {
        let tail = &rest[start + before.len()..];
        let id: String = tail
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
            .collect();
        if id.len() == 36 && tail[id.len()..].starts_with(after) {
            ids.push(id);
        }
        rest = tail;
    }
    ids
}

#[tokio::test]
async fn a_new_account_lands_on_its_own_organisation() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;

    when.visiting("/").await?;
    then.redirects_to(&format!("/{}", account.username))?;
    when.visiting_home().await?;
    then.status(200)?
        .body_contains("Overview")?
        .body_contains(&format!("owner of {}", account.username))?;
    Ok(())
}

#[tokio::test]
async fn an_organisation_is_not_found_for_someone_outside_it_on_every_page() -> anyhow::Result<()> {
    let Some((given, _, _)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;

    outsider_when.visiting("/no-such-organisation").await?;
    let absent = outsider_then.status(404)?.page_without_its_token()?;
    for path in ["", "/members", "/settings", "/settings/members"] {
        outsider_when
            .visiting(&format!("/{}{path}", owner.username))
            .await?;
        outsider_then
            .status(404)?
            .is_the_page(&absent)
            .map_err(|e| e.context(format!("/{}{path}", owner.username)))?;
    }

    outsider_when.visiting_home().await?;
    outsider_when
        .submitting_on_current_page(
            &format!("/{}/settings/members/invite", owner.username),
            &[("email", "someone@accept.test"), ("role", "member")],
        )
        .await?;
    outsider_then.status(404)?;
    Ok(())
}

#[tokio::test]
async fn an_invited_account_joins_with_its_role_and_a_member_cannot_invite() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (guest, guest_when, guest_then) = given.testcase.another_browser();
    let member = guest.a_signed_in_account().await?;

    when.inviting(&owner.username, &member.email, "member")
        .await?;
    then.redirects_to(&format!(
        "/{}/settings/members?done=invited",
        owner.username
    ))?;

    let link = guest_when
        .the_mailed_link(
            &member.email,
            &format!("Join {} on grund", owner.username),
            "/invite?token=",
        )
        .await?;
    guest_when.visiting(&link).await?;
    guest_then
        .status(200)?
        .header("referrer-policy", "same-origin")?
        .body_contains(&format!("Join {}", owner.username))?;
    let token = guest.last_token()?;
    guest_when
        .submitting_on_current_page("/invite", &[("token", &token)])
        .await?;
    guest_then.redirects_to(&format!("/{}", owner.username))?;

    guest_when
        .visiting(&format!("/{}/settings/members", owner.username))
        .await?;
    guest_then
        .status(200)?
        .body_contains(&owner.username)?
        .body_contains(&member.username)?
        .body_lacks("Send invitation")?;
    guest_when
        .submitting_on_current_page(
            &format!("/{}/settings/members/invite", owner.username),
            &[("email", "friend@accept.test"), ("role", "member")],
        )
        .await?;
    guest_then.status(403)?;

    guest_when.visiting(&link).await?;
    guest_then.body_contains("This invitation has expired")?;
    Ok(())
}

#[tokio::test]
async fn an_invitation_to_a_new_address_creates_a_confirmed_account_inside_it() -> anyhow::Result<()>
{
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let address = format!("{}@accept.test", given.a_fresh_name("new"));
    when.inviting(&owner.username, &address, "admin").await?;
    then.redirects_to(&format!(
        "/{}/settings/members?done=invited",
        owner.username
    ))?;

    let (stranger, stranger_when, stranger_then) = given.testcase.another_browser();
    let link = stranger_when
        .the_mailed_link(&address, "Join", "/invite?token=")
        .await?;
    stranger_when.visiting(&link).await?;
    stranger_then
        .status(200)?
        .body_contains("Create account and join")?
        .body_contains(&address)?;
    let token = stranger.last_token()?;
    let username = stranger.a_fresh_name("joined");
    stranger_when
        .submitting_on_current_page(
            "/invite",
            &[
                ("token", &token),
                ("username", &username),
                ("password", "a long enough password here"),
            ],
        )
        .await?;
    stranger_then.redirects_to(&format!("/{}", owner.username))?;
    stranger_when
        .visiting(&format!("/{}/settings/members", owner.username))
        .await?;
    stranger_then
        .status(200)?
        .body_contains(&username)?
        .body_contains("Send invitation")?;
    stranger_when.visiting(&format!("/{username}")).await?;
    stranger_then.status(200)?;
    assert_eq!(
        crate::accepttest::fixtures::mail_count(&given, &address).await?,
        1,
        "the invitation was the only mail: the address needed no confirmation"
    );
    Ok(())
}

#[tokio::test]
async fn an_invitation_opened_by_another_account_admits_nobody() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let address = format!("{}@accept.test", given.a_fresh_name("meant"));
    when.inviting(&owner.username, &address, "member").await?;
    then.status(303)?;

    let (other, other_when, other_then) = given.testcase.another_browser();
    other.a_signed_in_account().await?;
    let link = other_when
        .the_mailed_link(&address, "Join", "/invite?token=")
        .await?;
    other_when.visiting(&link).await?;
    other_then
        .status(200)?
        .body_contains("whose address is not")?
        .body_lacks("Create account and join")?;
    let token = link.split("token=").nth(1).unwrap_or_default().to_string();
    other_when
        .submitting_on_current_page("/invite", &[("token", &token)])
        .await?;
    other_then
        .status(200)?
        .body_contains("whose address is not")?;
    other_when.visiting(&format!("/{}", owner.username)).await?;
    other_then.status(404)?;
    Ok(())
}

#[tokio::test]
async fn a_withdrawn_invitation_stops_working() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let address = format!("{}@accept.test", given.a_fresh_name("gone"));
    when.inviting(&owner.username, &address, "member").await?;
    when.visiting(&format!("/{}/settings/members", owner.username))
        .await?;
    then.body_contains(&address)?;
    let before = format!("/{}/settings/invitations/", owner.username);
    let ids = ids_in_actions(&page(&given), &before, "/revoke");
    anyhow::ensure!(ids.len() == 1, "one pending invitation, got {ids:?}");
    when.submitting_on_current_page(&format!("{before}{}/revoke", ids[0]), &[])
        .await?;
    then.redirects_to(&format!(
        "/{}/settings/members?done=revoked",
        owner.username
    ))?;

    let (_, stranger_when, stranger_then) = given.testcase.another_browser();
    let link = stranger_when
        .the_mailed_link(&address, "Join", "/invite?token=")
        .await?;
    stranger_when.visiting(&link).await?;
    stranger_then.body_contains("This invitation has expired")?;
    Ok(())
}

#[tokio::test]
async fn the_last_owner_cannot_leave_and_an_admin_cannot_remove_an_owner() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let (guest, guest_when, guest_then) = given.testcase.another_browser();
    let admin = guest.a_signed_in_account().await?;
    when.inviting(&owner.username, &admin.email, "admin")
        .await?;
    let link = guest_when
        .the_mailed_link(&admin.email, "Join", "/invite?token=")
        .await?;
    guest_when.visiting(&link).await?;
    let token = guest.last_token()?;
    guest_when
        .submitting_on_current_page("/invite", &[("token", &token)])
        .await?;

    when.visiting(&format!("/{}/settings/members", owner.username))
        .await?;
    let members = format!("/{}/settings/members/", owner.username);
    let removable = ids_in_actions(&page(&given), &members, "/remove");
    anyhow::ensure!(
        removable.len() == 2,
        "the owner sees two remove forms (leave and the admin): {removable:?}"
    );
    let admin_id = ids_in_actions(&page(&given), &members, "/role")
        .into_iter()
        .next()
        .expect("the owner can change the admin's role");
    let owner_id = removable
        .iter()
        .find(|id| **id != admin_id)
        .cloned()
        .expect("the owner's own leave form");

    when.submitting_on_current_page(&format!("{members}{owner_id}/remove"), &[])
        .await?;
    then.redirects_to(&format!(
        "/{}/settings/members?error=last-owner",
        owner.username
    ))?;

    guest_when
        .visiting(&format!("/{}/settings/members", owner.username))
        .await?;
    guest_when
        .submitting_on_current_page(&format!("{members}{owner_id}/remove"), &[])
        .await?;
    guest_then.redirects_to(&format!(
        "/{}/settings/members?error=not-allowed",
        owner.username
    ))?;

    when.visiting(&format!("/{}/settings/members", owner.username))
        .await?;
    when.submitting_on_current_page(&format!("{members}{admin_id}/role"), &[("role", "owner")])
        .await?;
    then.redirects_to(&format!("/{}/settings/members?done=role", owner.username))?;
    when.visiting(&format!("/{}/settings/members", owner.username))
        .await?;
    when.submitting_on_current_page(&format!("{members}{owner_id}/remove"), &[])
        .await?;
    then.redirects_to("/")?;
    when.visiting(&format!("/{}", owner.username)).await?;
    then.status(404)?;
    Ok(())
}

#[tokio::test]
async fn creating_an_organisation_makes_its_creator_the_owner_and_names_are_one_namespace()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.a_signed_in_account().await?;
    let slug = given.a_fresh_name("team");

    when.submitting("/orgs/new", "/orgs/new", &[("slug", &slug)])
        .await?;
    then.redirects_to(&format!("/{slug}"))?;
    when.visiting(&format!("/{slug}")).await?;
    then.status(200)?
        .body_contains(&format!("owner of {slug}"))?;

    for (taken, message) in [
        (slug.as_str(), "That name is taken."),
        (account.username.as_str(), "That name is taken."),
        ("orgs", "reserved"),
    ] {
        when.submitting("/orgs/new", "/orgs/new", &[("slug", taken)])
            .await?;
        then.status(200)
            .and_then(|then| then.body_contains(message))
            .map_err(|e| e.context(taken.to_string()))?;
    }
    Ok(())
}

#[tokio::test]
async fn a_single_organisation_instance_is_invite_only_after_its_admin() -> anyhow::Result<()> {
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_ORGANISATIONS", "single")]).await?
    else {
        return Ok(());
    };
    when.visiting("/signup").await?;
    then.status(200)?.body_contains("becomes its admin")?;
    let admin = given.a_signed_in_account().await?;
    when.visiting_home().await?;
    then.status(200)?
        .body_contains(&format!("owner of {}", admin.username))?
        .body_lacks("New organisation")?;
    when.visiting("/orgs/new").await?;
    then.status(404)?;

    let (stranger, stranger_when, stranger_then) = given.testcase.another_browser();
    stranger_when.visiting("/signup").await?;
    stranger_then.status(403)?.body_contains("invite-only")?;
    let name = stranger.a_fresh_name("late");
    stranger_when
        .submitting(
            "/login",
            "/signup",
            &[
                ("username", &name),
                ("email", &format!("{name}@accept.test")),
                ("password", "a long enough password here"),
            ],
        )
        .await?;
    stranger_then.status(403)?.body_contains("invite-only")?;

    let address = format!("{}@accept.test", stranger.a_fresh_name("team"));
    when.inviting(&admin.username, &address, "member").await?;
    let link = stranger_when
        .the_mailed_link(&address, "Join", "/invite?token=")
        .await?;
    stranger_when.visiting(&link).await?;
    let token = stranger.last_token()?;
    let username = stranger.a_fresh_name("teammate");
    stranger_when
        .submitting_on_current_page(
            "/invite",
            &[
                ("token", &token),
                ("username", &username),
                ("password", "a long enough password here"),
            ],
        )
        .await?;
    stranger_then.redirects_to(&format!("/{}", admin.username))?;
    stranger_when.visiting(&format!("/{username}")).await?;
    stranger_then.status(404)?;
    stranger_when.visiting("/").await?;
    stranger_then.redirects_to(&format!("/{}", admin.username))?;
    Ok(())
}
