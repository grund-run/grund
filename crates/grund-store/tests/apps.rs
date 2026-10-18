use chrono::{Duration, Utc};
use grund_config::app::spec::{AppName, AppSettings, AppSpec, StopSpec};
use grund_domain::app::{AppCommand, AppEvent, ExternalRelease, PlaceReason, ReleaseSource};
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
                external_release: None,
                request: None,
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
async fn external_release_identity_and_owner_rebuild_from_app_events(pool: PgPool) {
    let events = store(&pool).await;
    let organisation_id = Uuid::now_v7();
    let app_id = create(&events, organisation_id, "forest").await;
    let origin = ExternalRelease {
        forest_organisation: "customer".into(),
        destination: "dev".into(),
        project: "shop".into(),
        intent_id: Uuid::now_v7(),
        artifact_id: Uuid::now_v7(),
        request_digest: [7; 32],
    };
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.app(
        app_id,
        AppCommand::Release {
            actor: Uuid::nil(),
            spec: spec(),
            image_digest: format!("sha256:{}", "d".repeat(64)),
            platforms: Vec::new(),
            exposed_ports: None,
            secret_versions: Vec::new(),
            source: ReleaseSource::File,
            external_release: Some(origin.clone()),
            request: None,
            rollback_of: None,
            note: String::new(),
            rollout_id: Uuid::now_v7(),
            at: Utc::now(),
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();

    let expected: (Uuid, Vec<u8>, i32) = sqlx::query_as(
        "SELECT artifact_id, request_digest, release_number FROM grund_app_external_releases WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        expected,
        (origin.artifact_id, origin.request_digest.to_vec(), 1)
    );

    sqlx::query("DELETE FROM grund_app_external_releases WHERE app_id = $1")
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM grund_app_external_owners WHERE app_id = $1")
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE grund_apps SET stream_version = 0 WHERE app_id = $1")
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let stream: Vec<(i64, serde_json::Value)> = sqlx::query_as(
        "SELECT stream_version, data FROM es_events WHERE stream_id = $1 ORDER BY stream_version",
    )
    .bind(format!("grund-app-{app_id}"))
    .fetch_all(&mut *connection)
    .await
    .unwrap();
    for (version, data) in stream {
        let event: AppEvent = serde_json::from_value(data).unwrap();
        apps::apply_app(app_id, version, &event, &mut connection)
            .await
            .unwrap();
    }
    let restored: (Uuid, Vec<u8>, i32) = sqlx::query_as(
        "SELECT artifact_id, request_digest, release_number FROM grund_app_external_releases WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let owner: (String, String, String) = sqlx::query_as(
        "SELECT forest_organisation, destination, project FROM grund_app_external_owners WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restored, expected);
    assert_eq!(owner, ("customer".into(), "dev".into(), "shop".into()));

    let at = Utc::now();
    let due = at + Duration::days(7);
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.app(
        app_id,
        AppCommand::Delete {
            actor: Uuid::nil(),
            at,
            purge_after: due,
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.app(app_id, AppCommand::Purge { at: due })
        .await
        .unwrap();
    work.commit().await.unwrap();
    let replacement = create(&events, organisation_id, "forest").await;
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    let refusal = work
        .app(
            replacement,
            AppCommand::Release {
                actor: Uuid::nil(),
                spec: spec(),
                image_digest: format!("sha256:{}", "d".repeat(64)),
                platforms: Vec::new(),
                exposed_ports: None,
                secret_versions: Vec::new(),
                source: ReleaseSource::File,
                external_release: Some(origin.clone()),
                request: None,
                rollback_of: None,
                note: String::new(),
                rollout_id: Uuid::now_v7(),
                at: Utc::now(),
            },
        )
        .await
        .unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("external release key conflicts with its app event"),
        "{refusal}"
    );
    drop(work);
    assert!(
        apps::releases(&pool, replacement, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let owner_app: Uuid = sqlx::query_scalar(
        "SELECT app_id FROM grund_app_external_releases WHERE organisation_id = $1 \
         AND forest_organisation = $2 AND destination = $3 AND intent_id = $4 AND app_name = $5",
    )
    .bind(organisation_id)
    .bind("customer")
    .bind("dev")
    .bind(origin.intent_id)
    .bind("forest")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner_app, app_id);
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
            size_gib: None,
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
async fn early_purge_queues_machine_erasure_and_waits_for_acknowledgement(pool: PgPool) {
    use grund_domain::volume::VolumeCommand;
    use grund_store::volumes;

    let events = store(&pool).await;
    let org = Uuid::now_v7();
    let app = create(&events, org, "cleanup").await;
    let volume = Uuid::now_v7();
    let machine = Uuid::now_v7();
    let actor = Uuid::now_v7();
    let at = Utc::now();
    let deadline = at + Duration::days(7);
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.volume(
        volume,
        VolumeCommand::Request {
            organisation_id: org,
            app_id: app,
            name: "data".into(),
            path: "/data".into(),
            source: None,
            backup: false,
            size_gib: None,
            at,
        },
    )
    .await
    .unwrap();
    work.volume(
        volume,
        VolumeCommand::Place {
            machine_id: machine,
            at,
        },
    )
    .await
    .unwrap();
    work.volume(
        volume,
        VolumeCommand::Delete {
            at,
            purge_after: deadline,
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();

    let mut work = Work::begin(&events, Uuid::now_v7(), &actor.to_string())
        .await
        .unwrap();
    work.volume(
        volume,
        VolumeCommand::PurgeNow {
            actor,
            reason: "owned synthetic app cleanup".into(),
            at,
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();
    let row = volumes::volume(&pool, org, app, volume)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "deleting");
    assert_eq!(row.purge_after, None);
    let audit: serde_json::Value = sqlx::query_scalar(
        "SELECT data FROM es_events WHERE stream_id = $1 AND data->>'type' = 'purge_requested'",
    )
    .bind(format!("grund-volume-{volume}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit["actor"], actor.to_string());
    assert_eq!(audit["reason"], "owned synthetic app cleanup");
    assert_eq!(
        audit["requested_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<Utc>>()
            .unwrap(),
        at
    );
    let cleanup: (Uuid, Option<chrono::DateTime<Utc>>) = sqlx::query_as(
        "SELECT machine_id, acknowledged_at FROM grund_volume_cleanup WHERE organisation_id=$1 AND volume_id=$2",
    )
    .bind(org).bind(volume).fetch_one(&pool).await.unwrap();
    assert_eq!(cleanup, (machine, None));

    let mut work = Work::begin(&events, Uuid::now_v7(), "agent").await.unwrap();
    work.volume(
        volume,
        VolumeCommand::ConfirmDeleted {
            machine_id: machine,
            at,
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();
    let row = volumes::any_volume(&pool, org, app, volume)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "deleted");
    let acknowledged: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT acknowledged_at FROM grund_volume_cleanup WHERE organisation_id=$1 AND volume_id=$2")
            .bind(org).bind(volume).fetch_one(&pool).await.unwrap();
    assert_eq!(
        acknowledged.unwrap().timestamp_micros(),
        at.timestamp_micros()
    );
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

#[sqlx::test(migrations = false)]
async fn a_returning_lease_keeps_the_app_and_volume_but_removes_its_fenced_replica(pool: PgPool) {
    use grund_domain::{
        app::{DrainReason, reconcile::reconcile_with_volumes},
        volume::VolumeCommand,
    };

    let events = store(&pool).await;
    let organisation_id = Uuid::now_v7();
    let app_id = create(&events, organisation_id, "retained").await;
    let release = release(&events, app_id).await;
    let machine_id = Uuid::now_v7();
    let replica_id = Uuid::now_v7();
    let volume_id = Uuid::now_v7();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO grund_machines (machine_id,pool,name,state,public_key, \
         returning_organisation_id,minted_by,registered_at,key_registered_at,stream_version) \
         VALUES ($1,'management','holder','returning',repeat('a',64),$2,'test', \
                 clock_timestamp(),clock_timestamp(),1)",
    )
    .bind(machine_id)
    .bind(organisation_id)
    .execute(&pool)
    .await
    .unwrap();
    decide(&events, app_id, |app| {
        let rollout = app.rollout.as_ref().unwrap();
        vec![
            AppEvent::ReplicaPlaced {
                replica_id,
                slot: 0,
                release,
                machine_id,
                placement: 0,
                reason: PlaceReason::Rollout,
                placed_at: now,
            },
            AppEvent::RolloutSucceeded {
                rollout_id: rollout.rollout_id,
                succeeded_at: now,
            },
            AppEvent::CurrentReleaseSet {
                release,
                set_at: now,
            },
        ]
    })
    .await;
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    for command in [
        VolumeCommand::Request {
            organisation_id,
            app_id,
            name: "data".into(),
            path: "/data".into(),
            source: None,
            backup: false,
            size_gib: Some(1),
            at: now,
        },
        VolumeCommand::Place {
            machine_id,
            at: now,
        },
        VolumeCommand::PrepareBackend {
            machine_id,
            slot: 1,
            at: now,
        },
        VolumeCommand::ConfirmBackendAttachment {
            machine_id,
            at: now,
        },
    ] {
        work.volume(volume_id, command).await.unwrap();
    }
    work.commit().await.unwrap();

    assert_eq!(
        apps::ended_lease_machines(&pool, organisation_id, app_id)
            .await
            .unwrap(),
        vec![(machine_id, false)]
    );
    let mut work = Work::begin(&events, Uuid::now_v7(), "grund/apps")
        .await
        .unwrap();
    let (draining, ()) = work
        .app_decide(app_id, |app| {
            let decision = reconcile_with_volumes(
                app,
                &[],
                &[],
                &[(machine_id, false)],
                now,
                true,
                &mut Uuid::now_v7,
            );
            Ok((decision.events, ()))
        })
        .await
        .unwrap();
    assert!(
        matches!(draining.as_slice(), [AppEvent::ReplicaDraining { replica_id: id, reason: DrainReason::LeaseEnded, .. }] if *id == replica_id)
    );
    work.commit().await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM grund_replicas WHERE replica_id=$1")
        .bind(replica_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "draining");

    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.volume(
        volume_id,
        VolumeCommand::BeginBackendDetachment {
            machine_id,
            at: now,
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();
    assert_eq!(
        apps::ended_lease_machines(&pool, organisation_id, app_id)
            .await
            .unwrap(),
        vec![(machine_id, false)],
        "starting a detach is not physical confirmation"
    );
    let mut work = Work::begin(&events, Uuid::now_v7(), "test").await.unwrap();
    work.volume(
        volume_id,
        VolumeCommand::ConfirmBackendDetachment {
            machine_id,
            at: now,
        },
    )
    .await
    .unwrap();
    work.commit().await.unwrap();
    let detached = apps::ended_lease_machines(&pool, organisation_id, app_id)
        .await
        .unwrap();
    assert_eq!(detached, vec![(machine_id, true)]);
    let mut work = Work::begin(&events, Uuid::now_v7(), "grund/apps")
        .await
        .unwrap();
    let (removed, ()) = work
        .app_decide(app_id, |app| {
            let decision =
                reconcile_with_volumes(app, &[], &[], &detached, now, true, &mut Uuid::now_v7);
            Ok((decision.events, ()))
        })
        .await
        .unwrap();
    assert!(
        matches!(removed.as_slice(), [AppEvent::ReplicaRemoved { replica_id: id, .. }] if *id == replica_id)
    );
    work.commit().await.unwrap();
    assert!(
        apps::app_machines(&pool, app_id).await.unwrap().is_empty(),
        "no stale writer may block the returning provider lease"
    );
    let retained: (String, Option<i32>) =
        sqlx::query_as("SELECT status,slot FROM grund_volumes WHERE volume_id=$1")
            .bind(volume_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained, ("available".into(), None));
    let app: (Option<i32>, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT current_release,deleted_at FROM grund_apps WHERE app_id=$1")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(app, (Some(release as i32), None));
}

#[sqlx::test(migrations = false)]
async fn update_cache_is_tenant_scoped_and_hidden_as_soon_as_the_running_base_changes(
    pool: PgPool,
) {
    use grund_domain::app::updates::{ImageUpdate, UpdateState};
    let events = store(&pool).await;
    let tenant = Uuid::now_v7();
    let other = Uuid::now_v7();
    let app_id = create(&events, tenant, "same-name").await;
    let other_app = create(&events, other, "same-name").await;
    release(&events, app_id).await;
    release(&events, other_app).await;
    for id in [app_id, other_app] {
        decide(&events, id, |_| {
            vec![AppEvent::CurrentReleaseSet {
                release: 1,
                set_at: Utc::now(),
            }]
        })
        .await;
    }
    let update = ImageUpdate {
        base_release: 1,
        current_image: "docker.io/library/nginx:latest".into(),
        current_digest: format!("sha256:{}", "d".repeat(64)),
        checked_at: Some(Utc::now()),
        state: UpdateState::Current,
        reason: "current".into(),
        candidates: Vec::new(),
    };
    assert!(
        apps::save_update_check(&pool, tenant, app_id, &update)
            .await
            .unwrap()
    );
    assert_eq!(
        apps::update_check(&pool, tenant, app_id)
            .await
            .unwrap()
            .unwrap()
            .0,
        update
    );
    assert!(
        apps::update_check(&pool, other, app_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        apps::update_check(&pool, other, other_app)
            .await
            .unwrap()
            .is_none()
    );
    assert!(apps::update_checks(&pool, other).await.unwrap().is_empty());
    assert!(
        !apps::save_update_check(&pool, other, app_id, &update)
            .await
            .unwrap()
    );
    release(&events, app_id).await;
    decide(&events, app_id, |_| {
        vec![AppEvent::CurrentReleaseSet {
            release: 2,
            set_at: Utc::now(),
        }]
    })
    .await;
    assert!(
        apps::update_check(&pool, tenant, app_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !apps::save_update_check(&pool, tenant, app_id, &update)
            .await
            .unwrap()
    );
}
