use std::time::{Duration, Instant};

use crate::accepttest::fixtures::{
    AccountAnswer, BILLING_TOKEN, DeletionAnswer, FakeBilling, testcase_configured,
};

#[tokio::test]
async fn enabling_billing_backfills_organisations_created_while_billing_was_off()
-> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let billing =
        FakeBilling::start_with_account(DeletionAnswer::Allow, AccountAnswer::Free).await?;
    given
        .testcase
        .fixture
        .restart_with(&[
            ("GRUND_BILLING_URL", &billing.url),
            ("GRUND_BILLING_TOKEN", BILLING_TOKEN),
            (
                "GRUND_BILLING_EPOCH",
                "00000000-0000-0000-0000-000000000001",
            ),
        ])
        .await?;

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if billing.calls("RecordOrganisation").iter().any(|call| {
            call.body["slug"] == owner.username
                && call.body["change"] == "ORGANISATION_CHANGE_CREATED"
        }) {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "existing organisation was not seeded as a creation"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[tokio::test]
async fn a_billing_service_without_a_billing_page_keeps_the_owners_settings_link_hidden()
-> anyhow::Result<()> {
    let billing =
        FakeBilling::start_with_account(DeletionAnswer::Allow, AccountAnswer::Free).await?;
    let Some((given, when, then)) = testcase_configured(&[
        ("GRUND_BILLING_URL", &billing.url),
        ("GRUND_BILLING_TOKEN", BILLING_TOKEN),
        (
            "GRUND_BILLING_EPOCH",
            "00000000-0000-0000-0000-000000000001",
        ),
    ])
    .await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    when.visiting(&format!("/{}/settings", owner.username))
        .await?;
    then.status(200)?
        .body_contains("Managed by")?
        .body_lacks(&format!("href=\"/{}/settings/billing\"", owner.username))?;
    Ok(())
}

#[tokio::test]
async fn a_new_epoch_reseeds_without_forwarding_old_or_unknown_financial_work() -> anyhow::Result<()>
{
    use serde_json::json;
    use uuid::Uuid;
    let old = FakeBilling::start(DeletionAnswer::Allow).await?;
    let new = FakeBilling::start(DeletionAnswer::Allow).await?;
    let old_epoch = Uuid::now_v7();
    let new_epoch = Uuid::now_v7();
    let Some((given, _, _)) = testcase_configured(&[
        ("GRUND_BILLING_URL", &old.url),
        ("GRUND_BILLING_TOKEN", BILLING_TOKEN),
        ("GRUND_BILLING_EPOCH", &old_epoch.to_string()),
    ])
    .await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let pool = sqlx::PgPool::connect(&given.testcase.fixture.database_url().unwrap()).await?;
    let old_seed = {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(call) = old
                .calls("RecordOrganisation")
                .into_iter()
                .find(|call| call.body["slug"] == owner.username)
            {
                break call.body;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "old ledger did not receive normal owner organisation"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let held = Uuid::now_v7();
    let unknown = Uuid::now_v7();
    let held_payload = json!({"eventId":held,"idempotencyKey":held,"organisationId":old_seed["organisationId"],
        "sampledAt":chrono::Utc::now().to_rfc3339(),"machines":7});
    let leased = Uuid::now_v7();
    let mut tx = pool.begin().await?;
    grund_store::outbox::enqueue_billing(
        &mut tx,
        held,
        grund_store::outbox::Kind::BillingMachineCount,
        old_epoch,
        Some(old_epoch),
        &held_payload,
    )
    .await?;
    sqlx::query("UPDATE grund_outbox SET next_attempt_at=clock_timestamp()+interval '1 day',attempts=3,last_error='retained attempt' WHERE outbox_id=$1")
        .bind(held).execute(&mut *tx).await?;
    grund_store::outbox::enqueue_billing(
        &mut tx,
        leased,
        grund_store::outbox::Kind::BillingMachineCount,
        old_epoch,
        Some(old_epoch),
        &json!({"eventId":leased,"machines":8}),
    )
    .await?;
    sqlx::query("UPDATE grund_outbox SET next_attempt_at=clock_timestamp()+interval '5 minutes',attempts=1 WHERE outbox_id=$1")
        .bind(leased).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO grund_outbox(outbox_id,kind,payload) VALUES($1,'billing.machine_change',$2)",
    )
    .bind(unknown)
    .bind(json!({"eventId":unknown,"legacy":true}))
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE grund_outbox SET next_attempt_at=clock_timestamp()+interval '1 day' WHERE outbox_id=$1")
        .bind(unknown).execute(&mut *tx).await?;
    tx.commit().await?;
    let replica = given
        .testcase
        .fixture
        .spawn_replica(&[
            ("GRUND_BILLING_URL", &new.url),
            ("GRUND_BILLING_EPOCH", &new_epoch.to_string()),
        ])
        .await?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let new_seed = loop {
        let seed = new
            .calls("RecordOrganisation")
            .into_iter()
            .find(|call| call.body["slug"] == owner.username);
        let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_outbox WHERE outbox_id IN ($1,$2,$3) AND superseded_at IS NOT NULL AND delivered_at IS NULL")
            .bind(held).bind(unknown).bind(leased).fetch_one(&pool).await?;
        if retained == 3
            && let Some(seed) = seed
        {
            let delivered: bool = sqlx::query_scalar(
                "SELECT delivered_at IS NOT NULL FROM grund_outbox WHERE outbox_id=$1",
            )
            .bind(Uuid::parse_str(seed.body["eventId"].as_str().unwrap())?)
            .fetch_one(&pool)
            .await?;
            if delivered {
                break seed.body;
            }
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "new epoch did not seed and retain old work"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    anyhow::ensure!(new_seed["eventId"] != old_seed["eventId"]);
    let current = Uuid::now_v7();
    let mut tx = pool.begin().await?;
    grund_store::outbox::enqueue_billing(
        &mut tx, current, grund_store::outbox::Kind::BillingMachineCount,
        new_epoch, Some(new_epoch), &json!({"eventId":current,"idempotencyKey":current,
            "organisationId":old_seed["organisationId"],"sampledAt":chrono::Utc::now().to_rfc3339(),"machines":0}),
    ).await?;
    tx.commit().await?;
    let financial = new
        .wait_for("RecordMachineCount", 1, Duration::from_secs(15))
        .await?;
    anyhow::ensure!(
        financial
            .iter()
            .all(|call| call.body["eventId"] == current.to_string())
    );
    anyhow::ensure!(old.calls("RecordMachineCount").is_empty());
    given
        .testcase
        .fixture
        .restart_with(&[
            ("GRUND_BILLING_URL", &new.url),
            ("GRUND_BILLING_EPOCH", &new_epoch.to_string()),
        ])
        .await?;
    anyhow::ensure!(
        new.calls("RecordOrganisation")
            .iter()
            .filter(|call| call.body["slug"] == owner.username)
            .count()
            == 1
    );
    grund_store::outbox::prune(&pool, Duration::ZERO).await?;
    let preserved: (serde_json::Value, i32, Option<String>) =
        sqlx::query_as("SELECT payload,attempts,last_error FROM grund_outbox WHERE outbox_id=$1")
            .bind(held)
            .fetch_one(&pool)
            .await?;
    anyhow::ensure!(preserved == (held_payload, 3, Some("retained attempt".into())));
    drop(replica);
    Ok(())
}

#[tokio::test]
async fn unconfigured_billing_keeps_financial_work_while_normal_mail_still_delivers()
-> anyhow::Result<()> {
    let Some((given, _, _)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let pool = sqlx::PgPool::connect(&given.testcase.fixture.database_url().unwrap()).await?;
    let id = uuid::Uuid::now_v7();
    let payload = serde_json::json!({"legacy":"must remain held"});
    sqlx::query(
        "INSERT INTO grund_outbox(outbox_id,kind,payload) VALUES($1,'billing.machine_change',$2)",
    )
    .bind(id)
    .bind(&payload)
    .execute(&pool)
    .await?;
    given.a_signed_in_account().await?;
    let held: (serde_json::Value, i32, bool) = sqlx::query_as(
        "SELECT payload,attempts,delivered_at IS NULL FROM grund_outbox WHERE outbox_id=$1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(held == (payload, 0, true));
    Ok(())
}
