use std::time::Duration;

use chrono::Utc;
use grund_domain::{
    account::{Account, AccountCommand, AccountEvent, RegistrationMethod},
    names::Username,
    organisation::OrganisationCommand,
};
use grund_store::{
    accounts, projections, sessions, throttle,
    tokens::{self, Purpose},
    work::Work,
};
use mire::EventStore;
use sqlx::PgPool;
use uuid::Uuid;

async fn store(pool: &PgPool) -> EventStore {
    grund_store::migrate(pool).await.unwrap();
    EventStore::new(pool.clone())
}

fn name(prefix: &str) -> Username {
    Username::parse(&format!(
        "{prefix}-{}",
        &Uuid::now_v7().simple().to_string()[20..]
    ))
    .unwrap()
}

async fn register(events: &EventStore, username: &Username) -> Uuid {
    let account_id = Uuid::now_v7();
    let organisation_id = Uuid::now_v7();
    let mut work = Work::begin(events, Uuid::now_v7(), "test").await.unwrap();
    work.account(
        account_id,
        AccountCommand::Register {
            username: username.clone(),
            organisation_id,
            method: RegistrationMethod::Password,
            at: Utc::now(),
        },
    )
    .await
    .unwrap();
    work.organisation(
        organisation_id,
        OrganisationCommand::Create {
            kind: grund_domain::organisation::OrganisationKind::Personal,
            slug: username.clone(),
            owner: account_id,
            at: Utc::now(),
        },
    )
    .await
    .unwrap();
    let email = format!("{username}@example.com");
    accounts::insert_email(work.sql(), account_id, &email, &email)
        .await
        .unwrap();
    work.commit().await.unwrap();
    account_id
}

#[sqlx::test(migrations = false)]
async fn a_registration_writes_the_account_its_organisation_and_the_owner_membership(pool: PgPool) {
    let events = store(&pool).await;
    let username = name("owner");
    let account_id = register(&events, &username).await;

    let mut connection = pool.acquire().await.unwrap();
    let viewer = accounts::viewer(&mut connection, account_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(viewer.username, username.as_str());
    assert_eq!(viewer.memberships.len(), 1);
    assert_eq!(viewer.memberships[0].slug, username.as_str());
    assert_eq!(viewer.memberships[0].role, "owner");
}

#[sqlx::test(migrations = false)]
async fn replaying_an_event_or_an_older_one_leaves_the_read_model_unchanged(pool: PgPool) {
    let events = store(&pool).await;
    let username = name("replay");
    let account_id = register(&events, &username).await;
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.account(
        account_id,
        AccountCommand::VerifyEmail {
            email_digest: "d".into(),
            at: Utc::now(),
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();

    let read = || async {
        sqlx::query_as::<_, (String, Option<chrono::DateTime<Utc>>, i64)>(
            "SELECT username, email_verified_at, stream_version FROM grund_accounts WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let before = read().await;
    assert_eq!(before.2, 2);

    let mut connection = pool.acquire().await.unwrap();
    let registered = AccountEvent::Registered {
        username: Username::parse("someone-else").unwrap(),
        organisation_id: Uuid::nil(),
        method: RegistrationMethod::Password,
        registered_at: Utc::now(),
    };
    projections::apply_account(account_id, 1, &registered, &mut connection)
        .await
        .unwrap();
    projections::apply_account(
        account_id,
        2,
        &AccountEvent::EmailVerified {
            email_digest: "d".into(),
            verified_at: Utc::now(),
        },
        &mut connection,
    )
    .await
    .unwrap();
    assert_eq!(read().await, before);
}

#[sqlx::test(migrations = false)]
async fn a_second_account_with_the_same_username_is_refused_by_its_index(pool: PgPool) {
    let events = store(&pool).await;
    let username = name("taken");
    register(&events, &username).await;

    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    let error = work
        .account(
            Uuid::now_v7(),
            AccountCommand::Register {
                username: username.clone(),
                organisation_id: Uuid::now_v7(),
                method: RegistrationMethod::Password,
                at: Utc::now(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.unique_violation().as_deref(),
        Some("grund_accounts_username_idx")
    );
    drop(work);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_accounts WHERE username = $1")
        .bind(username.as_str())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = false)]
async fn a_long_stream_loads_from_its_snapshot_to_the_same_state_as_a_full_replay(pool: PgPool) {
    let events = store(&pool).await;
    let account_id = register(&events, &name("long")).await;
    for i in 0..230 {
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
        work.account(
            account_id,
            AccountCommand::VerifyEmail {
                email_digest: format!("d{i}"),
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        work.commit().await.unwrap();
    }
    let snapshot_stream = format!("grund-account-{account_id}-snapshot");
    let mut snapshots = 0i64;
    for _ in 0..50 {
        snapshots = sqlx::query_scalar("SELECT count(*) FROM es_events WHERE stream_id = $1")
            .bind(&snapshot_stream)
            .fetch_one(&pool)
            .await
            .unwrap();
        if snapshots >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        snapshots >= 2,
        "expected snapshots at versions 100 and 200, found {snapshots}"
    );

    let full = events
        .load::<Account>(&account_id.to_string())
        .await
        .unwrap()
        .unwrap();
    let snapshotted = events
        .load_snapshotted::<Account>(&account_id.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(full.version, 231);
    assert_eq!(snapshotted.version, full.version);
    assert_eq!(snapshotted.state, full.state);
}

#[sqlx::test(migrations = false)]
async fn a_throttle_window_counts_hits_and_a_new_window_starts_again(pool: PgPool) {
    store(&pool).await;
    let key = [9u8; 32];
    let window = Duration::from_secs(2);
    let first = throttle::hit(&pool, throttle::Scope::LoginFailure, &key, window)
        .await
        .unwrap();
    let second = throttle::hit(&pool, throttle::Scope::LoginFailure, &key, window)
        .await
        .unwrap();
    assert_eq!(second, first + 1);
    assert_eq!(
        throttle::count(&pool, throttle::Scope::LoginFailure, &key, window)
            .await
            .unwrap(),
        second
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(
        throttle::count(&pool, throttle::Scope::LoginFailure, &key, window)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        throttle::hit(&pool, throttle::Scope::LoginFailure, &key, window)
            .await
            .unwrap(),
        1
    );
    throttle::clear(&pool, throttle::Scope::LoginFailure, &key)
        .await
        .unwrap();
    assert_eq!(
        throttle::count(&pool, throttle::Scope::LoginFailure, &key, window)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test(migrations = false)]
async fn a_reset_link_works_once_and_a_newer_one_replaces_it(pool: PgPool) {
    let events = store(&pool).await;
    let username = name("link");
    let account_id = register(&events, &username).await;
    let email = format!("{username}@example.com");
    let (old, new) = ([1u8; 32], [2u8; 32]);
    let mut tx = pool.begin().await.unwrap();
    tokens::issue(
        &mut tx,
        &old,
        Purpose::ResetPassword,
        account_id,
        &email,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    tokens::issue(
        &mut tx,
        &new,
        Purpose::ResetPassword,
        account_id,
        &email,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut connection = pool.acquire().await.unwrap();
    assert!(
        tokens::redeem(&mut connection, &old, Purpose::ResetPassword)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        tokens::redeem(&mut connection, &new, Purpose::VerifyEmail)
            .await
            .unwrap()
            .is_none()
    );
    let redeemed = tokens::redeem(&mut connection, &new, Purpose::ResetPassword)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(redeemed.account_id, account_id);
    assert!(
        tokens::redeem(&mut connection, &new, Purpose::ResetPassword)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = false)]
async fn every_unexpired_verification_link_works_until_one_is_used(pool: PgPool) {
    let events = store(&pool).await;
    let username = name("verify");
    let account_id = register(&events, &username).await;
    let email = format!("{username}@example.com");
    let (first, second) = ([3u8; 32], [4u8; 32]);
    let mut tx = pool.begin().await.unwrap();
    for digest in [&first, &second] {
        tokens::issue(
            &mut tx,
            digest,
            Purpose::VerifyEmail,
            account_id,
            &email,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    assert!(
        tokens::peek(&pool, &first, Purpose::VerifyEmail)
            .await
            .unwrap()
            .is_some()
    );
    let mut connection = pool.acquire().await.unwrap();
    let redeemed = tokens::redeem(&mut connection, &first, Purpose::VerifyEmail)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(redeemed.account_id, account_id);
    assert!(
        tokens::redeem(&mut connection, &second, Purpose::VerifyEmail)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = false)]
async fn an_account_cannot_revoke_another_accounts_session(pool: PgPool) {
    store(&pool).await;
    let (owner, intruder) = (Uuid::now_v7(), Uuid::now_v7());
    let session_id = Uuid::now_v7();
    let mut connection = pool.acquire().await.unwrap();
    sessions::insert(
        &mut connection,
        sessions::NewSession {
            session_id,
            token_digest: &[3u8; 32],
            account_id: owner,
            max_age: Duration::from_secs(3600),
            user_agent: "test",
            client_address: "",
        },
    )
    .await
    .unwrap();
    assert!(!sessions::revoke(&pool, intruder, session_id).await.unwrap());
    assert!(
        sessions::find(&pool, &[3u8; 32], Duration::from_secs(3600))
            .await
            .unwrap()
            .is_some()
    );
    assert!(sessions::revoke(&pool, owner, session_id).await.unwrap());
    assert!(
        sessions::find(&pool, &[3u8; 32], Duration::from_secs(3600))
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = false)]
async fn replaying_an_organisation_stream_never_brings_a_removed_member_back(pool: PgPool) {
    use grund_domain::organisation::{Departure, OrganisationEvent, OrganisationKind, Role};
    grund_store::migrate(&pool).await.unwrap();
    let organisation_id = Uuid::now_v7();
    let (owner, member) = (Uuid::now_v7(), Uuid::now_v7());
    let at = Utc::now();
    let events = [
        OrganisationEvent::Created {
            slug: name("replay"),
            kind: OrganisationKind::Shared,
            created_by: owner,
            created_at: at,
        },
        OrganisationEvent::MemberAdded {
            account_id: owner,
            role: Role::Owner,
            added_at: at,
        },
        OrganisationEvent::MemberAdded {
            account_id: member,
            role: Role::Member,
            added_at: at,
        },
        OrganisationEvent::MemberRemoved {
            account_id: member,
            departure: Departure::Removed,
            removed_by: owner,
            removed_at: at,
        },
    ];
    let mut connection = pool.acquire().await.unwrap();
    for _ in 0..2 {
        for (offset, event) in events.iter().enumerate() {
            projections::apply_organisation(
                organisation_id,
                offset as i64 + 1,
                event,
                &mut connection,
            )
            .await
            .unwrap();
        }
    }
    let members: Vec<Uuid> =
        sqlx::query_scalar("SELECT account_id FROM grund_memberships WHERE organisation_id = $1")
            .bind(organisation_id)
            .fetch_all(&mut *connection)
            .await
            .unwrap();
    assert_eq!(members, vec![owner]);
    let kind: String =
        sqlx::query_scalar("SELECT kind FROM grund_organisations WHERE organisation_id = $1")
            .bind(organisation_id)
            .fetch_one(&mut *connection)
            .await
            .unwrap();
    assert_eq!(kind, "shared");
}
