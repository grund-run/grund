use chrono::{Duration, Utc};
use grund_domain::app::{
    AppCommand, AppEvent, AppName, AppSettings, PlaceReason, ReleaseSource,
    spec::{AppSpec, StopSpec},
};
use grund_store::{
    apps::{self, Report},
    work::Work,
};
use mire::EventStore;
use sqlx::PgPool;
use uuid::Uuid;

async fn store(pool: &PgPool) -> EventStore {
    grund_store::migrate(pool).await.unwrap();
    EventStore::new(pool.clone())
}

fn spec() -> AppSpec {
    AppSpec {
        image: "nginx".into(),
        command: Vec::new(),
        ports: Vec::new(),
        memory_mib: 128,
        cpu_millis: 100,
        env: Vec::new(),
        volumes: Vec::new(),
        secrets: Vec::new(),
        check: None,
        stop: StopSpec::default(),
    }
}

async fn create(events: &EventStore, organisation_id: Uuid, name: &str) -> Uuid {
    let app_id = Uuid::now_v7();
    let mut work = Work::begin(events, Uuid::now_v7(), "test").await.unwrap();
    work.app(
        app_id,
        AppCommand::Create {
            actor: Uuid::nil(),
            organisation_id,
            name: AppName::parse(name).unwrap(),
            settings: AppSettings::default(),
            at: Utc::now(),
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();
    app_id
}

async fn release(events: &EventStore, app_id: Uuid) -> u32 {
    let mut work = Work::begin(events, Uuid::now_v7(), "test").await.unwrap();
    let made = work
        .app(
            app_id,
            AppCommand::Release {
                actor: Uuid::nil(),
                spec: spec(),
                image_digest: format!("sha256:{}", "d".repeat(64)),
                platforms: Vec::new(),
                exposed_ports: Some(vec![80, 443]),
                secret_versions: Vec::new(),
                source: ReleaseSource::Api,
                rollback_of: None,
                note: String::new(),
                rollout_id: Uuid::now_v7(),
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
    work.commit().await.unwrap();
    made.iter()
        .find_map(|e| match e {
            AppEvent::ReleaseCreated { release } => Some(release.number),
            _ => None,
        })
        .unwrap()
}

async fn decide(
    events: &EventStore,
    app_id: Uuid,
    decide: impl Fn(&grund_domain::app::App) -> Vec<AppEvent>,
) {
    let mut work = Work::begin(events, Uuid::now_v7(), "test").await.unwrap();
    work.app_decide(app_id, |app| Ok((decide(app), ())))
        .await
        .unwrap();
    work.commit().await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn a_release_is_rolling_out_then_live_and_the_one_before_is_replaced(pool: PgPool) {
    let events = store(&pool).await;
    let organisation_id = Uuid::now_v7();
    let app_id = create(&events, organisation_id, "shop").await;
    let machine_id = Uuid::now_v7();
    let first = release(&events, app_id).await;
    let replica_id = Uuid::now_v7();
    decide(&events, app_id, |app| {
        let rollout = app.rollout.clone().unwrap();
        vec![
            AppEvent::ReplicaPlaced {
                replica_id,
                slot: 0,
                release: first,
                machine_id,
                placement: 0,
                reason: PlaceReason::Rollout,
                placed_at: Utc::now(),
            },
            AppEvent::RolloutSucceeded {
                rollout_id: rollout.rollout_id,
                succeeded_at: Utc::now(),
            },
            AppEvent::CurrentReleaseSet {
                release: first,
                set_at: Utc::now(),
            },
        ]
    })
    .await;
    let second = release(&events, app_id).await;
    decide(&events, app_id, |app| {
        let rollout = app.rollout.clone().unwrap();
        vec![
            AppEvent::RolloutSucceeded {
                rollout_id: rollout.rollout_id,
                succeeded_at: Utc::now(),
            },
            AppEvent::CurrentReleaseSet {
                release: second,
                set_at: Utc::now(),
            },
        ]
    })
    .await;

    let app = apps::app(&pool, app_id).await.unwrap().unwrap();
    assert_eq!(app.current_release, Some(2));
    assert_eq!(app.rollout.unwrap()["state"], "succeeded");
    let releases = apps::releases(&pool, app_id, 100).await.unwrap();
    let outcomes: Vec<(i32, Option<String>)> = releases
        .iter()
        .map(|r| (r.number, r.outcome.clone()))
        .collect();
    assert_eq!(
        outcomes,
        vec![(2, Some("live".into())), (1, Some("replaced".into()))]
    );
    let placed = apps::machine_replicas(&pool, machine_id).await.unwrap();
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].app_name, "shop");
    let activity = apps::activity_of(&pool, app_id, 100).await.unwrap();
    assert!(activity.iter().any(|a| a.kind == "replica_placed"));

    let mut connection = pool.acquire().await.unwrap();
    let stream: Vec<(i64, serde_json::Value)> = sqlx::query_as(
        "SELECT stream_version, data FROM es_events WHERE stream_id = $1 ORDER BY stream_version",
    )
    .bind(format!("grund-app-{app_id}"))
    .fetch_all(&mut *connection)
    .await
    .unwrap();
    assert_eq!(stream.len(), 10);
    for (version, data) in stream {
        let event: AppEvent = serde_json::from_value(data).unwrap();
        apps::apply_app(app_id, version, &event, &mut connection)
            .await
            .unwrap();
    }
    let again = apps::releases(&pool, app_id, 100).await.unwrap();
    assert_eq!(
        again.iter().map(|r| r.outcome.clone()).collect::<Vec<_>>(),
        releases
            .iter()
            .map(|r| r.outcome.clone())
            .collect::<Vec<_>>()
    );
}

#[sqlx::test(migrations = false)]
async fn two_live_apps_of_one_organisation_cannot_share_a_name(pool: PgPool) {
    let events = store(&pool).await;
    let organisation_id = Uuid::now_v7();
    create(&events, organisation_id, "shop").await;
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    let error = work
        .app(
            Uuid::now_v7(),
            AppCommand::Create {
                actor: Uuid::nil(),
                organisation_id,
                name: AppName::parse("shop").unwrap(),
                settings: AppSettings::default(),
                at: Utc::now(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.unique_violation().as_deref(),
        Some("grund_apps_name_idx")
    );
    create(&events, Uuid::now_v7(), "shop").await;
}

#[sqlx::test(migrations = false)]
async fn deletion_retains_backup_and_name_until_test_clock_purges_it(pool: PgPool) {
    use grund_domain::volume::VolumeCommand;
    use grund_store::volumes;

    let events = store(&pool).await;
    let org = Uuid::now_v7();
    let app = create(&events, org, "photos").await;
    let volume = Uuid::now_v7();
    let start = Utc::now();
    let due = start + Duration::days(7);
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.volume(
        volume,
        VolumeCommand::Request {
            organisation_id: org,
            app_id: app,
            name: "data".into(),
            path: "/data".into(),
            source: None,
            backup: true,
            at: start,
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();
    sqlx::query("INSERT INTO grund_volume_backup_points (organisation_id,app_id,volume_id,snapshot_id,archived_path,completed_at,verified_at) VALUES ($1,$2,$3,'point-a','/data',$4,$4)")
        .bind(org).bind(app).bind(volume).bind(start).execute(&pool).await.unwrap();
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.app(
        app,
        AppCommand::Delete {
            actor: Uuid::nil(),
            at: start,
            purge_after: due,
        },
    )
    .await
    .unwrap();
    work.volume(
        volume,
        VolumeCommand::Delete {
            at: start,
            purge_after: due,
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();

    assert!(
        apps::app_by_name(&pool, org, "photos")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(apps::restorable_apps(&pool, org).await.unwrap().len(), 1);
    assert_eq!(
        volumes::app_volumes(&pool, org, app).await.unwrap()[0].status,
        "pending_deletion"
    );
    let point_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM grund_volume_backup_points WHERE volume_id=$1")
            .bind(volume)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(point_count, 1);
    let early: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_volumes WHERE volume_id=$1 AND status='pending_deletion' AND purge_after <= $2")
        .bind(volume).bind(due - Duration::seconds(1)).fetch_one(&pool).await.unwrap();
    assert_eq!(early, 0);
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.volume(
        volume,
        VolumeCommand::Restore {
            at: due - Duration::seconds(1),
        },
    )
    .await
    .unwrap();
    work.app(
        app,
        AppCommand::Restore {
            actor: Uuid::nil(),
            at: due - Duration::seconds(1),
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();
    assert!(
        apps::app_by_name(&pool, org, "photos")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        volumes::app_volumes(&pool, org, app).await.unwrap()[0].status,
        "requested"
    );
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM grund_volume_backup_points WHERE volume_id=$1")
            .bind(volume)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained, 1);

    let next_due = due + Duration::days(7);
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.app(
        app,
        AppCommand::Delete {
            actor: Uuid::nil(),
            at: due,
            purge_after: next_due,
        },
    )
    .await
    .unwrap();
    work.volume(
        volume,
        VolumeCommand::Delete {
            at: due,
            purge_after: next_due,
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.volume(volume, VolumeCommand::Purge { at: next_due })
        .await
        .unwrap();
    work.volume(
        volume,
        VolumeCommand::FinalizeWithoutErasure { at: next_due },
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM grund_volume_backup_points WHERE volume_id=$1")
        .bind(volume)
        .execute(&mut **work.sql())
        .await
        .unwrap();
    work.app(app, AppCommand::Purge { at: next_due })
        .await
        .unwrap();
    work.commit().await.unwrap();
    assert!(
        volumes::app_volumes(&pool, org, app)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(apps::restorable_apps(&pool, org).await.unwrap().is_empty());
    create(&events, org, "photos").await;
}

#[sqlx::test(migrations = false)]
async fn a_report_counts_only_from_the_machine_a_replica_is_placed_on(pool: PgPool) {
    let events = store(&pool).await;
    let app_id = create(&events, Uuid::now_v7(), "web").await;
    let number = release(&events, app_id).await;
    let (machine_id, stranger) = (Uuid::now_v7(), Uuid::now_v7());
    let replica_id = Uuid::now_v7();
    decide(&events, app_id, |_| {
        vec![AppEvent::ReplicaPlaced {
            replica_id,
            slot: 0,
            release: number,
            machine_id,
            placement: 0,
            reason: PlaceReason::Rollout,
            placed_at: Utc::now(),
        }]
    })
    .await;
    let report = |ready: bool, since: chrono::DateTime<Utc>| Report {
        replica_id,
        state: "running",
        ready,
        ready_since: ready.then_some(since),
        restarts: 0,
        last_exit_code: 0,
        reason: "",
        idle: false,
    };
    let mut connection = pool.acquire().await.unwrap();
    let t0 = Utc::now();
    assert!(
        !apps::record_reports(&mut connection, stranger, &[report(true, t0)], t0)
            .await
            .unwrap()
    );
    assert!(apps::app_statuses(&pool, app_id).await.unwrap().is_empty());
    assert!(
        apps::record_reports(&mut connection, machine_id, &[report(true, t0)], t0)
            .await
            .unwrap()
    );
    let later = t0 + Duration::seconds(5);
    assert!(
        !apps::record_reports(
            &mut connection,
            machine_id,
            &[report(true, later - Duration::milliseconds(4900))],
            later
        )
        .await
        .unwrap()
    );
    let status = &apps::app_statuses(&pool, app_id).await.unwrap()[0];
    assert_eq!(
        status.ready_since.unwrap().timestamp_millis(),
        t0.timestamp_millis()
    );
    assert!(status.ever_ready);
    assert!(
        apps::record_reports(&mut connection, machine_id, &[report(false, later)], later)
            .await
            .unwrap()
    );
    let status = &apps::app_statuses(&pool, app_id).await.unwrap()[0];
    assert!(status.ready_since.is_none());
    assert!(status.ever_ready);
}

#[sqlx::test(migrations = false)]
async fn each_new_secret_value_is_the_next_version(pool: PgPool) {
    let events = store(&pool).await;
    let organisation_id = Uuid::now_v7();
    let app_id = create(&events, organisation_id, "db").await;
    let mut connection = pool.acquire().await.unwrap();
    for expected in 1..=2 {
        let (version, _) = apps::insert_secret(
            &mut connection,
            app_id,
            organisation_id,
            "password",
            |v| format!("sealed-{v}").into_bytes(),
            Uuid::nil(),
        )
        .await
        .unwrap();
        assert_eq!(version, expected);
    }
    let latest = apps::latest_secrets(&pool, app_id).await.unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].1, 2);
    assert_eq!(
        apps::secret_value(&pool, app_id, "password", 1)
            .await
            .unwrap(),
        Some(b"sealed-1".to_vec())
    );
}

#[sqlx::test(migrations = false)]
async fn the_list_shows_the_release_an_app_runs_or_its_newest_before_one_is_live(pool: PgPool) {
    let events = store(&pool).await;
    let organisation_id = Uuid::now_v7();
    let shop = create(&events, organisation_id, "shop").await;
    let first = release(&events, shop).await;
    decide(&events, shop, |app| {
        let rollout = app.rollout.clone().unwrap();
        vec![
            AppEvent::RolloutSucceeded {
                rollout_id: rollout.rollout_id,
                succeeded_at: Utc::now(),
            },
            AppEvent::CurrentReleaseSet {
                release: first,
                set_at: Utc::now(),
            },
        ]
    })
    .await;
    release(&events, shop).await;
    let fresh = create(&events, organisation_id, "fresh").await;
    release(&events, fresh).await;
    release(&events, fresh).await;
    create(&events, organisation_id, "empty").await;
    let elsewhere = create(&events, Uuid::now_v7(), "other").await;
    release(&events, elsewhere).await;

    let mut running: Vec<(Uuid, i32)> = apps::running_releases(&pool, organisation_id)
        .await
        .unwrap()
        .iter()
        .map(|r| (r.app_id, r.number))
        .collect();
    running.sort();
    let mut expected = vec![(shop, 1), (fresh, 2)];
    expected.sort();
    assert_eq!(running, expected);
}

#[sqlx::test(migrations = false)]
async fn legacy_release_ports_are_filled_once_without_changing_known_metadata(pool: PgPool) {
    let events = store(&pool).await;
    let app_id = create(&events, Uuid::now_v7(), "legacy").await;
    release(&events, app_id).await;
    let row = apps::releases(&pool, app_id, 1).await.unwrap().remove(0);
    assert_eq!(row.exposed_ports.as_ref().unwrap().0, vec![80, 443]);
    sqlx::query("UPDATE grund_releases SET exposed_ports = NULL WHERE app_id = $1")
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();
    apps::cache_release_ports(&pool, app_id, row.number, "sha256:wrong", &[1])
        .await
        .unwrap();
    assert!(
        apps::releases(&pool, app_id, 1).await.unwrap()[0]
            .exposed_ports
            .is_none()
    );
    apps::cache_release_ports(&pool, app_id, row.number, &row.image_digest, &[])
        .await
        .unwrap();
    apps::cache_release_ports(&pool, app_id, row.number, &row.image_digest, &[9999])
        .await
        .unwrap();
    assert_eq!(
        apps::releases(&pool, app_id, 1).await.unwrap()[0]
            .exposed_ports
            .as_ref()
            .unwrap()
            .0,
        Vec::<u16>::new()
    );
}
