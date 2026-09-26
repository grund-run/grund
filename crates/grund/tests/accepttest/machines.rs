use std::time::Duration;

use crate::accepttest::fixtures::{
    ENROLL, Enroll, Given, MACHINES, MachineKey, Then, When, testcase, testcase_with_mail,
};

const LIST: &str = "/grund.machine.v1.MachineService/ListMachines";
const REVOKE: &str = "/grund.machine.v1.MachineService/RevokeMachine";

async fn machines_of(
    when: &When,
    then: &Then,
    slug: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    when.calling(LIST, &serde_json::json!({ "slug": slug }).to_string())
        .await?;
    then.status(200)?;
    Ok(then.json()?["machines"]
        .as_array()
        .cloned()
        .unwrap_or_default())
}

async fn an_owner(given: &Given) -> anyhow::Result<String> {
    Ok(given.a_signed_in_account().await?.username)
}

#[tokio::test]
async fn a_machine_enrolls_with_its_token_and_a_replay_with_the_same_key_gets_the_same_machine()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let slug = an_owner(&given).await?;
    let token = given
        .an_enrollment_token(&when, &then, &slug, "", 0)
        .await?;
    let (_, machine, machine_then) = given.testcase.another_browser();
    let key = MachineKey::new();

    machine.enrolling(&Enroll::new(&token, &key)).await?;
    machine_then
        .status(200)?
        .header("cache-control", "no-store")?;
    let enrolled = machine_then.json()?;
    let machine_id = enrolled["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    anyhow::ensure!(enrolled["machineName"] == "kasper-s-nuc", "{enrolled}");
    anyhow::ensure!(enrolled["heartbeatIntervalSeconds"] == 30, "{enrolled}");
    anyhow::ensure!(
        enrolled["controlUrls"][0] == given.testcase.fixture.origin.serialized().as_str(),
        "{enrolled}"
    );

    machine.enrolling(&Enroll::new(&token, &key)).await?;
    machine_then.status(200)?;
    anyhow::ensure!(
        machine_then.json()?["machineId"] == machine_id.as_str(),
        "a replay with the same key returns the same machine"
    );

    machine
        .enrolling(&Enroll::new(&token, &MachineKey::new()))
        .await?;
    machine_then
        .status(403)?
        .error_reason("permission_denied", "token_invalid")?;

    let listed = machines_of(&when, &then, &slug).await?;
    anyhow::ensure!(listed.len() == 1, "{listed:?}");
    anyhow::ensure!(listed[0]["machineId"] == machine_id.as_str(), "{listed:?}");
    anyhow::ensure!(
        listed[0]["publicKey"] == key.public_base64url().as_str(),
        "{listed:?}"
    );
    anyhow::ensure!(
        listed[0]["mintedBy"]
            .as_str()
            .is_some_and(|m| m.starts_with("user:")),
        "{listed:?}"
    );
    anyhow::ensure!(listed[0]["facts"]["arch"] == "x86_64", "{listed:?}");
    Ok(())
}

#[tokio::test]
async fn unknown_used_expired_and_malformed_tokens_all_fail_the_same_way() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let slug = an_owner(&given).await?;
    let used = given
        .an_enrollment_token(&when, &then, &slug, "", 0)
        .await?;
    let expiring = given
        .an_enrollment_token(&when, &then, &slug, "", 1)
        .await?;
    let (_, machine, machine_then) = given.testcase.another_browser();
    machine
        .enrolling(&Enroll::new(&used, &MachineKey::new()))
        .await?;
    machine_then.status(200)?;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let unknown = format!("grund_enr_{}", "a".repeat(52));
    let mut answers = Vec::new();
    for token in [
        unknown.as_str(),
        used.as_str(),
        expiring.as_str(),
        "grund_enr_nope",
    ] {
        machine
            .enrolling(&Enroll::new(token, &MachineKey::new()))
            .await?;
        machine_then
            .status(403)?
            .error_reason("permission_denied", "token_invalid")?;
        answers.push(machine_then.json()?);
    }
    anyhow::ensure!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "every refusal must read the same: {answers:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_bad_proof_is_refused_before_the_token_is_used() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let slug = an_owner(&given).await?;
    let token = given
        .an_enrollment_token(&when, &then, &slug, "", 0)
        .await?;
    let (_, machine, machine_then) = given.testcase.another_browser();
    let key = MachineKey::new();

    let for_another_grund = Enroll {
        signed_for: Some("https://another-grund.example"),
        ..Enroll::new(&token, &key)
    };
    machine.enrolling(&for_another_grund).await?;
    machine_then
        .status(400)?
        .error_reason("invalid_argument", "proof_invalid")?;

    let stale = Enroll {
        clock_offset_seconds: -600,
        ..Enroll::new(&token, &key)
    };
    machine.enrolling(&stale).await?;
    machine_then
        .status(400)?
        .error_reason("invalid_argument", "proof_invalid")?;

    machine.enrolling(&Enroll::new(&token, &key)).await?;
    machine_then.status(200)?;
    Ok(())
}

#[tokio::test]
async fn a_token_binds_the_machine_to_its_organisation_and_name_and_other_people_see_nothing()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let slug = an_owner(&given).await?;
    let token = given
        .an_enrollment_token(&when, &then, &slug, "web-1", 0)
        .await?;
    let (_, machine, machine_then) = given.testcase.another_browser();
    let key = MachineKey::new();
    let named = Enroll {
        requested_name: "something-else",
        ..Enroll::new(&token, &key)
    };
    machine.enrolling(&named).await?;
    machine_then.status(200)?;
    anyhow::ensure!(machine_then.json()?["machineName"] == "web-1");
    let machine_id = machine_then.json()?["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let again = given
        .an_enrollment_token(&when, &then, &slug, "web-1", 0)
        .await?;
    machine
        .enrolling(&Enroll::new(&again, &MachineKey::new()))
        .await?;
    machine_then
        .status(400)?
        .error_reason("failed_precondition", "machine_name_taken")?;

    let (other_given, other, other_then) = given.testcase.another_browser();
    let other_slug = an_owner(&other_given).await?;
    anyhow::ensure!(
        machines_of(&other, &other_then, &other_slug)
            .await?
            .is_empty()
    );
    other
        .calling(LIST, &serde_json::json!({ "slug": slug }).to_string())
        .await?;
    other_then.status(404)?.connect_code("not_found")?;
    other
        .calling(
            REVOKE,
            &serde_json::json!({ "slug": other_slug, "machineId": machine_id }).to_string(),
        )
        .await?;
    other_then.status(404)?.connect_code("not_found")?;
    other
        .calling(
            &format!("{MACHINES}/CreateEnrollmentToken"),
            &serde_json::json!({ "slug": slug }).to_string(),
        )
        .await?;
    other_then.status(404)?.connect_code("not_found")?;
    Ok(())
}

#[tokio::test]
async fn a_revoked_machine_is_listed_as_revoked_and_its_token_no_longer_answers()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let slug = an_owner(&given).await?;
    let token = given
        .an_enrollment_token(&when, &then, &slug, "", 0)
        .await?;
    let (_, machine, machine_then) = given.testcase.another_browser();
    let key = MachineKey::new();
    machine.enrolling(&Enroll::new(&token, &key)).await?;
    machine_then.status(200)?;
    let machine_id = machine_then.json()?["machineId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let revoke = serde_json::json!({ "slug": slug, "machineId": machine_id }).to_string();
    when.calling(REVOKE, &revoke).await?;
    then.status(200)?;
    when.calling(REVOKE, &revoke).await?;
    then.status(200)?;
    let listed = machines_of(&when, &then, &slug).await?;
    anyhow::ensure!(listed[0]["revokedAt"].is_string(), "{listed:?}");

    machine.enrolling(&Enroll::new(&token, &key)).await?;
    machine_then
        .status(403)?
        .error_reason("permission_denied", "token_invalid")?;
    Ok(())
}

#[tokio::test]
async fn a_token_answers_five_calls_at_most() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let slug = an_owner(&given).await?;
    let token = given
        .an_enrollment_token(&when, &then, &slug, "", 0)
        .await?;
    let (_, machine, machine_then) = given.testcase.another_browser();
    let key = MachineKey::new();
    for _ in 0..5 {
        machine.enrolling(&Enroll::new(&token, &key)).await?;
        machine_then.status(200)?;
    }
    machine.enrolling(&Enroll::new(&token, &key)).await?;
    machine_then
        .status(429)?
        .error_reason("resource_exhausted", "rate_limited")?;
    Ok(())
}

#[tokio::test]
async fn minting_needs_a_session_and_enrolling_needs_none() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;
    when.calling(
        &format!("{MACHINES}/CreateEnrollmentToken"),
        r#"{"slug":"anyone"}"#,
    )
    .await?;
    then.status(401)?.connect_code("unauthenticated")?;
    when.calling_with(
        ENROLL,
        r#"{"token":"grund_enr_nope"}"#,
        &[("Origin", "https://evil.example")],
    )
    .await?;
    then.status(400)?
        .error_reason("invalid_argument", "proof_invalid")?;
    Ok(())
}
