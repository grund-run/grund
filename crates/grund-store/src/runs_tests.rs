use super::*;
use crate::work::Work;
use chrono::{Duration, Utc};
use grund_domain::{
    app::{Release, ReleaseSource},
    run::{Command, Request, Status},
};
use sqlx::PgPool;

async fn request(pool: &PgPool) -> anyhow::Result<Request> {
    let declared =
        grund_config::app::file::parse_app("apps:\n  web:\n    image: nginx:1\n", "web")?;
    let at = Utc::now();
    let app = Uuid::now_v7();
    let release = Release {
        number: 1,
        spec: declared.spec,
        image_digest: format!("sha256:{}", "a".repeat(64)),
        platforms: vec![],
        exposed_ports: None,
        secret_versions: vec![],
        source: ReleaseSource::File,
        rollback_of: None,
        note: String::new(),
        created_by: Uuid::nil(),
        created_at: at,
        external_release: None,
        request: None,
    };
    sqlx::query("INSERT INTO grund_releases(app_id,number,spec,image_digest,source,created_by,created_at) VALUES($1,1,$2,$3,'file',$4,$5)")
        .bind(app).bind(Json(&release.spec)).bind(&release.image_digest).bind(Uuid::nil()).bind(at).execute(pool).await?;
    Ok(Request {
        organisation_id: Uuid::now_v7(),
        stack_id: Uuid::now_v7(),
        stack_name: "prod".into(),
        service: "web".into(),
        stack_revision: 1,
        app_id: app,
        app_name: "backing-web".into(),
        release,
        settings: Default::default(),
        machine_id: Uuid::now_v7(),
        requester_id: Uuid::now_v7(),
        attempt_id: Uuid::now_v7(),
        requested_at: at,
        deadline: at + Duration::minutes(10),
    })
}

#[sqlx::test(migrations = "./migrations")]
async fn arguments_are_erasable_but_never_copied_into_audit_or_receipts(
    pool: PgPool,
) -> anyhow::Result<()> {
    let events = mire::EventStore::new(pool.clone());
    events.migrate().await?;
    let mut request = request(&pool).await?;
    request.requested_at -= Duration::days(9);
    request.deadline -= Duration::days(9);
    let id = Uuid::now_v7();
    let sentinel = "private-email-sentinel@example.invalid";
    let mut work = Work::begin(&events, Uuid::now_v7(), "test-owner").await?;
    work.run(id, Command::Request(request.clone())).await?;
    sqlx::query("INSERT INTO grund_run_payloads(organisation_id,run_id,args) VALUES($1,$2,$3)")
        .bind(request.organisation_id)
        .bind(id)
        .bind(Json(vec!["--delete-account", sentinel]))
        .execute(&mut **work.sql())
        .await?;
    sqlx::query("INSERT INTO grund_run_requests(organisation_id,caller_id,method,request_key,fingerprint,run_id) VALUES($1,$2,'create','request-one',$3,$4)").bind(request.organisation_id).bind(request.requester_id).bind(vec![7u8;32]).bind(id).execute(&mut **work.sql()).await?;
    work.commit().await?;
    assert_eq!(
        args(&pool, request.organisation_id, id).await?.unwrap()[1],
        sentinel
    );
    assert!(get(&pool, Uuid::now_v7(), id).await?.is_none());
    assert!(args(&pool, Uuid::now_v7(), id).await?.is_none());
    let durable: String = sqlx::query_scalar(
        "SELECT string_agg(row_to_json(e)::text,'') FROM es_events e WHERE stream_id=$1",
    )
    .bind(format!("grund-run-{id}"))
    .fetch_one(&pool)
    .await?;
    let receipt: String = sqlx::query_scalar("SELECT row_to_json(r)::text FROM grund_run_requests r WHERE organisation_id=$1 AND run_id=$2").bind(request.organisation_id).bind(id).fetch_one(&pool).await?;
    assert!(!durable.contains(sentinel));
    assert!(!receipt.contains(sentinel));
    let at = Utc::now() - Duration::days(8);
    let mut work = Work::begin(&events, Uuid::now_v7(), "test-observer").await?;
    work.run(
        id,
        Command::Observe {
            machine_id: request.machine_id,
            attempt_id: request.attempt_id,
            status: Status::Succeeded,
            started_at: None,
            at,
            exit_code: Some(0),
            signal: None,
            stop_confirmed: true,
        },
    )
    .await?;
    work.commit().await?;
    assert!(args(&pool, request.organisation_id, id).await?.is_none());
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_run_payloads WHERE run_id=$1")
        .bind(id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(before, 1);
    sweep(&pool).await?;
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_run_payloads WHERE run_id=$1")
        .bind(id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(after, 0);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn projection_replay_never_moves_a_finished_run_backwards(
    pool: PgPool,
) -> anyhow::Result<()> {
    let request = request(&pool).await?;
    let id = Uuid::now_v7();
    let created = Event::Requested {
        request: request.clone(),
    };
    let finished = Event::Finished {
        status: Status::Failed,
        at: Utc::now(),
        exit_code: Some(23),
        signal: None,
        reason: "process_exited".into(),
    };
    let mut tx = pool.begin().await?;
    apply(id, 1, &created, &mut tx).await?;
    apply(id, 2, &finished, &mut tx).await?;
    apply(id, 1, &created, &mut tx).await?;
    apply(id, 2, &finished, &mut tx).await?;
    tx.commit().await?;
    let row = get(&pool, request.organisation_id, id).await?.unwrap();
    assert_eq!(row.stream_version, 2);
    assert_eq!(row.state.0.exit_code, Some(23));
    assert!(!row.state.0.outstanding());
    let pinned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM grund_run_inputs WHERE organisation_id=$1 AND run_id=$2",
    )
    .bind(request.organisation_id)
    .bind(id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(pinned, 0);
    let other = Uuid::now_v7();
    let mut tx = pool.begin().await?;
    assert!(apply(other, 2, &finished, &mut tx).await.is_err());
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn uncertain_execution_holds_the_service_fence_and_capacity_until_absence(
    pool: PgPool,
) -> anyhow::Result<()> {
    let request = request(&pool).await?;
    let first = Uuid::now_v7();
    let mut tx = pool.begin().await?;
    apply(
        first,
        1,
        &Event::Requested {
            request: request.clone(),
        },
        &mut tx,
    )
    .await?;
    apply(
        first,
        2,
        &Event::ExecutionUncertain { at: Utc::now() },
        &mut tx,
    )
    .await?;
    tx.commit().await?;
    let row = get(&pool, request.organisation_id, first).await?.unwrap();
    assert!(row.state.0.outstanding());
    let reserved = crate::apps::reservations(&pool, request.organisation_id, Uuid::nil()).await?;
    assert_eq!(
        reserved[0].memory_mib,
        request.release.spec.memory_mib as i64
    );
    let mut competing = pool.begin().await?;
    let conflict = apply(
        Uuid::now_v7(),
        1,
        &Event::Requested {
            request: request.clone(),
        },
        &mut competing,
    )
    .await
    .unwrap_err();
    assert_eq!(
        conflict
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("23505")
    );
    competing.rollback().await?;
    let mut tx = pool.begin().await?;
    apply(
        first,
        3,
        &Event::Finished {
            status: Status::Unknown,
            at: Utc::now(),
            exit_code: None,
            signal: None,
            reason: "execution_uncertain".into(),
        },
        &mut tx,
    )
    .await?;
    let next = Uuid::now_v7();
    apply(
        next,
        1,
        &Event::Requested {
            request: request.clone(),
        },
        &mut tx,
    )
    .await?;
    tx.commit().await?;
    assert!(
        get(&pool, request.organisation_id, next)
            .await?
            .unwrap()
            .state
            .0
            .outstanding()
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn rolling_back_a_request_leaves_no_projection_payload_or_event(
    pool: PgPool,
) -> anyhow::Result<()> {
    let events = mire::EventStore::new(pool.clone());
    events.migrate().await?;
    let request = request(&pool).await?;
    let id = Uuid::now_v7();
    {
        let mut work = Work::begin(&events, Uuid::now_v7(), "test").await?;
        work.run(id, Command::Request(request.clone())).await?;
        sqlx::query("INSERT INTO grund_run_payloads(organisation_id,run_id,args) VALUES($1,$2,'[\"command\"]')").bind(request.organisation_id).bind(id).execute(&mut **work.sql()).await?;
    }
    assert!(get(&pool, request.organisation_id, id).await?.is_none());
    assert!(args(&pool, request.organisation_id, id).await?.is_none());
    let root = events.load::<Run>(&id.to_string()).await?;
    assert!(root.is_none());
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_requests_admit_exactly_one_service_execution(
    pool: PgPool,
) -> anyhow::Result<()> {
    let request = request(&pool).await?;
    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first_request = request.clone();
    let second_request = request.clone();
    let first = tokio::spawn(async move {
        let mut tx = first_pool.begin().await?;
        apply(
            Uuid::now_v7(),
            1,
            &Event::Requested {
                request: first_request,
            },
            &mut tx,
        )
        .await?;
        tx.commit().await
    });
    let second = tokio::spawn(async move {
        let mut tx = second_pool.begin().await?;
        apply(
            Uuid::now_v7(),
            1,
            &Event::Requested {
                request: second_request,
            },
            &mut tx,
        )
        .await?;
        tx.commit().await
    });
    let a = first.await?;
    let b = second.await?;
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let error = if let Err(error) = a {
        error
    } else {
        b.unwrap_err()
    };
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23505")
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn run_output_cannot_leak_through_unfiltered_app_logs_or_metrics(
    pool: PgPool,
) -> anyhow::Result<()> {
    use crate::app_telemetry::{self as telemetry, Identity, IngestError, Log, Policy, Sample};
    let request = request(&pool).await?;
    let org = request.organisation_id;
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) VALUES($1,'run-logs','shared',clock_timestamp(),1)")
        .bind(org).execute(&pool).await?;
    sqlx::query("INSERT INTO grund_machines(machine_id,pool,home_organisation_id,name,state,public_key,pool_organisation_id,pool_name,minted_by,registered_at,key_registered_at,stream_version) VALUES($1,'organisation',$2,'machine','active',$3,$2,'machine','test',clock_timestamp(),clock_timestamp(),1)")
        .bind(request.machine_id).bind(org).bind("a".repeat(64)).execute(&pool).await?;
    sqlx::query("INSERT INTO grund_apps(app_id,organisation_id,name,settings,created_by,created_at,stream_version) VALUES($1,$2,'app',$3,$4,clock_timestamp(),1)")
        .bind(request.app_id).bind(org).bind(Json(&request.settings)).bind(Uuid::nil()).execute(&pool).await?;
    let mut tx = pool.begin().await?;
    apply(
        id,
        1,
        &Event::Requested {
            request: request.clone(),
        },
        &mut tx,
    )
    .await?;
    tx.commit().await?;
    let identity = Identity {
        organisation_id: org,
        app_id: request.app_id,
        instance_id: id,
        machine_id: request.machine_id,
        release: 1,
    };
    let policy = Policy {
        log_bytes: 1024 * 1024,
        metric_bytes: 1024 * 1024,
        log_seconds: 86400,
        metric_seconds: 86400,
        receipts: 100,
        receipt_seconds: 86400,
    };
    let logs = [Log {
        identity: identity.clone(),
        at: Utc::now(),
        stream: "stderr".into(),
        body: "run-only-output-sentinel".into(),
        truncated: false,
    }];
    telemetry::ingest(
        &pool,
        org,
        request.machine_id,
        Uuid::now_v7(),
        &[1; 32],
        &logs,
        &[],
        policy,
    )
    .await?;
    let through = telemetry::highwater(&pool, org).await?;
    let ordinary = telemetry::logs(
        &pool,
        org,
        request.app_id,
        telemetry::LogFilter {
            instance: None,
            release: None,
            since: None,
            until: None,
            search: "",
            stream: "",
            after: 0,
            through,
            limit: 100,
            before: None,
        },
        86400,
    )
    .await?;
    assert!(ordinary.is_empty());
    let stored: (Uuid, String) = sqlx::query_as(
        "SELECT app_id,body FROM grund_app_logs WHERE organisation_id=$1 AND instance_id=$2",
    )
    .bind(org)
    .bind(id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(stored, (id, "run-only-output-sentinel".into()));
    let samples = [Sample {
        identity: identity.clone(),
        at: Utc::now(),
        cpu_millis: Some(10.0),
        memory_bytes: None,
        reserved_cpu_millis: 100,
        reserved_memory_bytes: 1024,
    }];
    assert!(matches!(
        telemetry::ingest(
            &pool,
            org,
            request.machine_id,
            Uuid::now_v7(),
            &[2; 32],
            &[],
            &samples,
            policy
        )
        .await,
        Err(IngestError::Identity)
    ));
    let mut spoofed = identity;
    spoofed.app_id = Uuid::now_v7();
    let spoofed = [Log {
        identity: spoofed,
        at: Utc::now(),
        stream: "stdout".into(),
        body: "spoof".into(),
        truncated: false,
    }];
    assert!(matches!(
        telemetry::ingest(
            &pool,
            org,
            request.machine_id,
            Uuid::now_v7(),
            &[3; 32],
            &spoofed,
            &[],
            policy
        )
        .await,
        Err(IngestError::Identity)
    ));
    sqlx::query("UPDATE grund_runs SET log_bytes_received=10485760-$3 WHERE organisation_id=$1 AND run_id=$2").bind(org).bind(id).bind((logs[0].body.len() as i64+telemetry::LOG_ROW_BYTES)*2).execute(&pool).await?;
    let batch = Uuid::now_v7();
    for _ in 0..3 {
        telemetry::ingest(
            &pool,
            org,
            request.machine_id,
            Uuid::now_v7(),
            &[4; 32],
            &logs,
            &[],
            policy,
        )
        .await?;
    }
    let usage: (i64,i64) = sqlx::query_as("SELECT log_bytes_received,dropped_records FROM grund_runs WHERE organisation_id=$1 AND run_id=$2").bind(org).bind(id).fetch_one(&pool).await?;
    assert_eq!(usage, (10485760, 1));
    let accepted = telemetry::ingest(
        &pool,
        org,
        request.machine_id,
        batch,
        &[5; 32],
        &logs,
        &[],
        policy,
    )
    .await?;
    let replay = telemetry::ingest(
        &pool,
        org,
        request.machine_id,
        batch,
        &[5; 32],
        &logs,
        &[],
        policy,
    )
    .await?;
    assert_eq!(accepted, replay);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn source_releases_cannot_be_collected_until_execution_absence_is_confirmed(
    pool: PgPool,
) -> anyhow::Result<()> {
    let request = request(&pool).await?;
    let id = Uuid::now_v7();
    let mut tx = pool.begin().await?;
    apply(
        id,
        1,
        &Event::Requested {
            request: request.clone(),
        },
        &mut tx,
    )
    .await?;
    tx.commit().await?;
    let mut deletion = pool.begin().await?;
    let refusal = sqlx::query("DELETE FROM grund_releases WHERE app_id=$1 AND number=1")
        .bind(request.app_id)
        .execute(&mut *deletion)
        .await
        .unwrap_err();
    assert_eq!(
        refusal
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("23503")
    );
    deletion.rollback().await?;
    let mut tx = pool.begin().await?;
    apply(
        id,
        2,
        &Event::Finished {
            status: Status::NotStarted,
            at: Utc::now(),
            exit_code: None,
            signal: None,
            reason: "not_started".into(),
        },
        &mut tx,
    )
    .await?;
    tx.commit().await?;
    sqlx::query("DELETE FROM grund_releases WHERE app_id=$1 AND number=1")
        .bind(request.app_id)
        .execute(&pool)
        .await?;
    assert_eq!(
        get(&pool, request.organisation_id, id)
            .await?
            .unwrap()
            .state
            .0
            .request
            .unwrap()
            .release
            .image_digest,
        request.release.image_digest
    );
    sqlx::query("DELETE FROM grund_runs WHERE organisation_id=$1 AND run_id=$2")
        .bind(request.organisation_id)
        .bind(id)
        .execute(&pool)
        .await?;
    let mut tx = pool.begin().await?;
    apply(
        id,
        1,
        &Event::Requested {
            request: request.clone(),
        },
        &mut tx,
    )
    .await?;
    apply(
        id,
        2,
        &Event::Finished {
            status: Status::NotStarted,
            at: Utc::now(),
            exit_code: None,
            signal: None,
            reason: "not_started".into(),
        },
        &mut tx,
    )
    .await?;
    tx.commit().await?;
    assert_eq!(
        get(&pool, request.organisation_id, id)
            .await?
            .unwrap()
            .stream_version,
        2
    );
    Ok(())
}
