use std::time::Duration;

use chrono::{DateTime, Utc};
use grund_store::{
    billing_epochs,
    outbox::{self, Kind},
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const URL: &str = "https://billing.example.test";

async fn activate(pool: &PgPool, epoch: Uuid) -> DateTime<Utc> {
    billing_epochs::activate(pool, epoch, URL, "sandbox")
        .await
        .unwrap()
}

async fn enqueue(pool: &PgPool, id: Uuid, writer: Uuid, origin: Option<Uuid>) {
    let mut tx = pool.begin().await.unwrap();
    outbox::enqueue_billing(
        &mut tx,
        id,
        Kind::BillingMachineChange,
        writer,
        origin,
        &json!({"event_id": id, "quantity": 3}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn concurrent_activation_has_one_winner_and_never_reactivates_the_retired_epoch(
    pool: PgPool,
) {
    grund_store::MIGRATOR.run(&pool).await.unwrap();
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    let (a, b) = tokio::join!(
        billing_epochs::activate(&pool, first, URL, "sandbox"),
        billing_epochs::activate(&pool, second, URL, "sandbox"),
    );
    a.unwrap();
    b.unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let current = billing_epochs::current(&mut connection)
        .await
        .unwrap()
        .unwrap();
    let retired = if current == first { second } else { first };
    let timestamp = billing_epochs::activated_at(&mut connection, current)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(activate(&pool, current).await, timestamp);
    assert!(
        billing_epochs::activate(&pool, retired, URL, "sandbox")
            .await
            .is_err()
    );
    let retired_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT retired_at FROM grund_billing_epochs WHERE epoch = $1")
            .bind(retired)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(retired_at.is_some());
    assert_eq!(
        billing_epochs::current(&mut connection).await.unwrap(),
        Some(current)
    );
}

#[sqlx::test(migrations = false)]
async fn an_epoch_binding_cannot_change_endpoint_or_mode_and_restart_keeps_its_boundary(
    pool: PgPool,
) {
    grund_store::MIGRATOR.run(&pool).await.unwrap();
    let epoch = Uuid::now_v7();
    let boundary = activate(&pool, epoch).await;
    assert!(
        billing_epochs::activate(&pool, epoch, "https://other.example.test", "sandbox")
            .await
            .is_err()
    );
    assert!(
        billing_epochs::activate(&pool, epoch, URL, "live")
            .await
            .is_err()
    );
    assert!(
        billing_epochs::activate(&pool, Uuid::nil(), URL, "sandbox")
            .await
            .is_err()
    );
    assert_eq!(activate(&pool, epoch).await, boundary);
}

#[sqlx::test(migrations = false)]
async fn activation_waits_for_an_admitted_producers_transaction(pool: PgPool) {
    grund_store::MIGRATOR.run(&pool).await.unwrap();
    let old = Uuid::now_v7();
    let new = Uuid::now_v7();
    activate(&pool, old).await;
    let mut tx = pool.begin().await.unwrap();
    assert!(billing_epochs::check(&mut tx, old).await.unwrap());
    let other_pool = pool.clone();
    let mut activation =
        tokio::spawn(
            async move { billing_epochs::activate(&other_pool, new, URL, "sandbox").await },
        );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut activation)
            .await
            .is_err()
    );
    let id = Uuid::now_v7();
    outbox::enqueue_billing(
        &mut tx,
        id,
        Kind::BillingOrganisation,
        old,
        Some(old),
        &json!({"id": id}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    activation.await.unwrap().unwrap();
    assert!(
        outbox::claim(&pool, 10, Duration::from_secs(30), Some(new))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(outbox::supersede_billing(&pool, new, 10).await.unwrap(), 1);
}

#[sqlx::test(migrations = false)]
async fn stale_writers_cannot_enqueue_claim_complete_fail_or_supersede_new_work(pool: PgPool) {
    grund_store::MIGRATOR.run(&pool).await.unwrap();
    let old = Uuid::now_v7();
    let new = Uuid::now_v7();
    let old_id = Uuid::now_v7();
    let new_id = Uuid::now_v7();
    activate(&pool, old).await;
    enqueue(&pool, old_id, old, Some(old)).await;
    assert_eq!(
        outbox::claim(&pool, 10, Duration::from_secs(30), Some(old))
            .await
            .unwrap()
            .len(),
        1
    );
    activate(&pool, new).await;
    enqueue(&pool, new_id, new, Some(new)).await;
    let mut tx = pool.begin().await.unwrap();
    assert!(
        outbox::enqueue_billing(
            &mut tx,
            Uuid::now_v7(),
            Kind::BillingOrganisation,
            old,
            Some(old),
            &json!({})
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    assert!(
        outbox::claim(&pool, 10, Duration::from_secs(30), Some(old))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!outbox::delivered_billing(&pool, old_id, old).await.unwrap());
    assert!(!outbox::delivered_billing(&pool, new_id, old).await.unwrap());
    assert!(
        !outbox::failed_billing(&pool, old_id, old, 7, "late failure")
            .await
            .unwrap()
    );
    assert!(
        !outbox::failed_billing(&pool, new_id, old, 7, "late failure")
            .await
            .unwrap()
    );
    assert_eq!(outbox::supersede_billing(&pool, old, 10).await.unwrap(), 0);
    let current = outbox::claim(&pool, 10, Duration::from_secs(30), Some(new))
        .await
        .unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].outbox_id, new_id);
    assert_eq!(current[0].billing_epoch, Some(new));
    assert_eq!(outbox::supersede_billing(&pool, new, 10).await.unwrap(), 1);
    assert!(!outbox::delivered_billing(&pool, old_id, old).await.unwrap());
    assert!(!outbox::delivered_billing(&pool, old_id, new).await.unwrap());
    assert!(outbox::delivered_billing(&pool, new_id, new).await.unwrap());
}

#[derive(Debug, PartialEq, sqlx::FromRow)]
struct Fact {
    outbox_id: Uuid,
    kind: String,
    recipient: String,
    payload: serde_json::Value,
    attempts: i32,
    next_attempt_at: DateTime<Utc>,
    last_error: Option<String>,
    delivered_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    billing_epoch: Option<Uuid>,
}

async fn facts(pool: &PgPool) -> Vec<Fact> {
    sqlx::query_as(
        "SELECT outbox_id, kind, recipient, payload, attempts, next_attempt_at, last_error, \
         delivered_at, created_at, billing_epoch FROM grund_outbox ORDER BY outbox_id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn old_and_unknown_facts_keep_every_field_through_bounded_supersession_and_pruning(
    pool: PgPool,
) {
    grund_store::MIGRATOR.run(&pool).await.unwrap();
    let old = Uuid::now_v7();
    let new = Uuid::now_v7();
    activate(&pool, old).await;
    for origin in [Some(old), None] {
        for seconds in [-60.0f64, 30.0, 300.0] {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO grund_outbox (outbox_id, kind, recipient, payload, billing_epoch, attempts, \
                 next_attempt_at, last_error, created_at) \
                 VALUES ($1, 'billing.machine_change', '', $2, $3, 4, \
                 clock_timestamp() + make_interval(secs => $4), 'preserve failure', \
                 clock_timestamp() - interval '60 days')",
            )
            .bind(id)
            .bind(json!({"id": id, "original": true}))
            .bind(origin)
            .bind(seconds)
            .execute(&pool)
            .await
            .unwrap();
        }
    }
    let before = facts(&pool).await;
    activate(&pool, new).await;
    assert!(
        outbox::claim(&pool, 20, Duration::from_secs(30), Some(new))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(outbox::supersede_billing(&pool, new, 2).await.unwrap(), 2);
    assert_eq!(outbox::supersede_billing(&pool, new, 20).await.unwrap(), 4);
    assert_eq!(outbox::supersede_billing(&pool, new, 20).await.unwrap(), 0);
    for fact in &before {
        outbox::delivered(&pool, fact.outbox_id).await.unwrap();
        outbox::failed(&pool, fact.outbox_id, 9, "must not replace error")
            .await
            .unwrap();
        assert!(
            !outbox::delivered_billing(&pool, fact.outbox_id, old)
                .await
                .unwrap()
        );
        assert!(
            !outbox::failed_billing(&pool, fact.outbox_id, new, 9, "must not replace error")
                .await
                .unwrap()
        );
    }
    assert_eq!(outbox::prune(&pool, Duration::ZERO).await.unwrap(), 0);
    assert_eq!(facts(&pool).await, before);
    assert_eq!(outbox::pending(&pool).await.unwrap(), 0);
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM grund_outbox WHERE superseded_at IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained, 6);
}

#[sqlx::test(migrations = false)]
async fn current_writers_retain_late_old_and_unknown_origins_without_retagging_them(pool: PgPool) {
    grund_store::MIGRATOR.run(&pool).await.unwrap();
    let old = Uuid::now_v7();
    let new = Uuid::now_v7();
    activate(&pool, old).await;
    activate(&pool, new).await;
    let old_id = Uuid::now_v7();
    let unknown_id = Uuid::now_v7();
    enqueue(&pool, old_id, new, Some(old)).await;
    enqueue(&pool, unknown_id, new, None).await;
    let before = facts(&pool).await;
    assert_eq!(
        before
            .iter()
            .find(|fact| fact.outbox_id == old_id)
            .unwrap()
            .billing_epoch,
        Some(old)
    );
    assert_eq!(
        before
            .iter()
            .find(|fact| fact.outbox_id == unknown_id)
            .unwrap()
            .billing_epoch,
        None
    );
    assert!(
        outbox::claim(&pool, 10, Duration::from_secs(30), Some(new))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(outbox::supersede_billing(&pool, new, 10).await.unwrap(), 0);
    assert_eq!(outbox::prune(&pool, Duration::ZERO).await.unwrap(), 0);
    assert_eq!(facts(&pool).await, before);
    let superseded: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_outbox WHERE superseded_at IS NOT NULL AND delivered_at IS NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(superseded, 2);
}

#[sqlx::test(migrations = false)]
async fn billing_disabled_holds_financial_payloads_while_mail_and_current_billing_still_complete(
    pool: PgPool,
) {
    grund_store::MIGRATOR.run(&pool).await.unwrap();
    let epoch = Uuid::now_v7();
    let billing_id = Uuid::now_v7();
    let mail_id = Uuid::now_v7();
    activate(&pool, epoch).await;
    enqueue(&pool, billing_id, epoch, Some(epoch)).await;
    let mut tx = pool.begin().await.unwrap();
    assert!(
        outbox::enqueue(
            &mut tx,
            Uuid::now_v7(),
            Kind::BillingOrganisation,
            "",
            &json!({})
        )
        .await
        .is_err()
    );
    assert!(
        outbox::enqueue_billing(
            &mut tx,
            Uuid::now_v7(),
            Kind::VerifyEmailMail,
            epoch,
            Some(epoch),
            &json!({})
        )
        .await
        .is_err()
    );
    outbox::enqueue(
        &mut tx,
        mail_id,
        Kind::VerifyEmailMail,
        "member@example.test",
        &json!({"link": "secret"}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mail = outbox::claim(&pool, 10, Duration::from_secs(30), None)
        .await
        .unwrap();
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].outbox_id, mail_id);
    assert_eq!(mail[0].billing_epoch, None);
    outbox::delivered(&pool, mail_id).await.unwrap();
    outbox::delivered(&pool, billing_id).await.unwrap();
    let billing = outbox::claim(&pool, 10, Duration::from_secs(30), Some(epoch))
        .await
        .unwrap();
    assert_eq!(billing.len(), 1);
    assert_eq!(billing[0].outbox_id, billing_id);
    assert_ne!(billing[0].payload, json!({}));
    assert!(
        outbox::failed_billing(&pool, billing_id, epoch, 1, "temporary failure")
            .await
            .unwrap()
    );
    assert!(
        outbox::delivered_billing(&pool, billing_id, epoch)
            .await
            .unwrap()
    );
    assert_eq!(outbox::prune(&pool, Duration::ZERO).await.unwrap(), 2);
    assert_eq!(outbox::pending(&pool).await.unwrap(), 0);
}
