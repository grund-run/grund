use super::*;
use chrono::DateTime;
use grund_domain::{
    app::{AppCommand, Release, ReleaseSource},
    stack::{Command, Kind, Operation, Revision, Service, Status, Step},
};
use std::collections::BTreeMap;

async fn fixture(
    pool: &sqlx::PgPool,
) -> anyhow::Result<(mire::EventStore, Uuid, Uuid, Revision, Operation)> {
    let (org, id, app) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    let at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    sqlx::query("INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) VALUES($1,'stack-history','personal',$2,1)")
        .bind(org).bind(at).execute(pool).await?;
    let declared =
        grund_config::app::file::parse_app("apps:\n  web:\n    image: nginx:1\n", "web")?;
    let settings = grund_config::app::spec::AppSettings::validate(declared.settings)?;
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
    let service = Service {
        app_id: app,
        app_name: "backing".into(),
        release,
        settings: settings.clone(),
        depends_on: vec![],
        exclusive: false,
        template: None,
    };
    let revision = Revision {
        number: 1,
        yaml: "stack:\n  name: shop\n  services:\n    web:\n      image: nginx:1\n".into(),
        services: BTreeMap::from([("web".into(), service)]),
        public_service: None,
        public_port: None,
        created_at: at,
        created_by: Uuid::nil(),
        rollback_of: None,
    };
    let operation = Operation {
        id: Uuid::now_v7(),
        kind: Kind::Deploy,
        target_revision: 1,
        previous_revision: 0,
        order: vec!["web".into()],
        cursor: 0,
        step: Step::Pending,
        started_at: at,
        deadline: at + chrono::Duration::seconds(1800),
        compensating: false,
        failure: None,
        releases: BTreeMap::new(),
        halting: false,
    };
    let events = mire::EventStore::new(pool.clone());
    events.migrate().await?;
    let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test").await?;
    work.stack(
        id,
        Command::Create {
            organisation_id: org,
            name: "shop".into(),
        },
    )
    .await?;
    work.app(
        app,
        AppCommand::Create {
            actor: Uuid::nil(),
            organisation_id: org,
            name: grund_config::app::spec::AppName::parse("backing")?,
            settings,
            at,
        },
    )
    .await?;
    work.app(app, AppCommand::AssignStack { stack_id: id, at })
        .await?;
    work.stack(
        id,
        Command::Revise {
            revision: revision.clone(),
            operation: operation.clone(),
        },
    )
    .await?;
    work.commit().await?;
    Ok((events, org, id, revision, operation))
}

#[sqlx::test(migrations = "./migrations")]
async fn an_inline_writer_cannot_skip_unreplayed_projection_history(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let (events, org, id, revision, mut operation) = fixture(&pool).await?;
    sqlx::query("DELETE FROM grund_stack_members WHERE organisation_id=$1 AND stack_id=$2")
        .bind(org)
        .bind(id)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM grund_stacks WHERE organisation_id=$1 AND stack_id=$2")
        .bind(org)
        .bind(id)
        .execute(&pool)
        .await?;
    let mut connection = pool.acquire().await?;
    apply(
        id,
        1,
        &Event::Created {
            organisation_id: org,
            name: "shop".into(),
        },
        &mut connection,
    )
    .await?;
    drop(connection);
    operation.failure = Some("capacity".into());
    let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test").await?;
    let rejected = work
        .stack(
            id,
            Command::Advance {
                operation: operation.clone(),
                status: Status::Waiting,
                machine_id: None,
                failure: Some("capacity".into()),
            },
        )
        .await;
    assert!(matches!(
        rejected,
        Err(crate::work::WorkError::Database(sqlx::Error::Protocol(_)))
    ));
    drop(work);
    assert_eq!(
        events
            .load::<Stack>(&id.to_string())
            .await?
            .unwrap()
            .version,
        2
    );
    let mut connection = pool.acquire().await?;
    let mut original = operation.clone();
    original.failure = None;
    apply(
        id,
        2,
        &Event::RevisionRequested {
            revision,
            operation: original,
        },
        &mut connection,
    )
    .await?;
    drop(connection);
    let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test").await?;
    work.stack(
        id,
        Command::Advance {
            operation,
            status: Status::Waiting,
            machine_id: None,
            failure: Some("capacity".into()),
        },
    )
    .await?;
    work.commit().await?;
    let row = get(&pool, org, id).await?.unwrap();
    assert_eq!(row.stream_version, 3);
    assert_eq!(
        row.state.0,
        events.load::<Stack>(&id.to_string()).await?.unwrap().state
    );
    let member = members(&pool, org, id).await?.pop().unwrap();
    assert_eq!(
        member.app_id,
        row.state.0.revisions[&1].services["web"].app_id
    );
    assert_eq!(member.service, "web");
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn a_long_stack_operation_hydrates_identically_from_snapshot_and_history(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let (events, _, id, _, mut operation) = fixture(&pool).await?;
    let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test").await?;
    for i in 0..110 {
        operation.failure = if i % 2 == 0 {
            Some("capacity".into())
        } else {
            None
        };
        work.stack(
            id,
            Command::Advance {
                operation: operation.clone(),
                status: Status::Waiting,
                machine_id: None,
                failure: operation.failure.clone(),
            },
        )
        .await?;
    }
    work.commit().await?;
    let full = events.load::<Stack>(&id.to_string()).await?.unwrap();
    assert_eq!(full.version, 112);
    events.save_snapshot(&full).await?;
    let cached = events
        .load_snapshotted::<Stack>(&id.to_string())
        .await?
        .unwrap();
    assert_eq!(cached.version, full.version);
    assert_eq!(cached.state, full.state);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn a_stack_grant_must_include_removed_children_not_only_the_current_revision(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let (events, org, id, mut revision, mut operation) = fixture(&pool).await?;
    let mut surviving = revision.services.remove("web").unwrap();
    surviving.app_id = Uuid::now_v7();
    surviving.app_name = "survivor".into();
    let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test").await?;
    work.app(
        surviving.app_id,
        AppCommand::Create {
            actor: Uuid::nil(),
            organisation_id: org,
            name: grund_config::app::spec::AppName::parse(&surviving.app_name)?,
            settings: surviving.settings.clone(),
            at: revision.created_at,
        },
    )
    .await?;
    work.app(
        surviving.app_id,
        AppCommand::AssignStack {
            stack_id: id,
            at: revision.created_at,
        },
    )
    .await?;
    work.commit().await?;
    revision.number = 2;
    revision.services.insert("survivor".into(), surviving);
    revision.yaml =
        "stack:\n  name: shop\n  services:\n    survivor:\n      image: nginx:1\n".into();
    operation.id = Uuid::now_v7();
    operation.target_revision = 2;
    operation.previous_revision = 1;
    operation.order = vec!["survivor".into()];
    let mut connection = pool.acquire().await?;
    apply(
        id,
        3,
        &Event::RevisionRequested {
            revision,
            operation,
        },
        &mut connection,
    )
    .await?;
    drop(connection);
    let current_only = vec!["survivor".to_string()];
    let complete = vec!["survivor".to_string(), "backing".to_string()];
    assert!(!allowed(&pool, org, id, &current_only).await?);
    assert!(allowed(&pool, org, id, &complete).await?);
    assert!(!allowed(&pool, Uuid::now_v7(), id, &complete).await?);
    assert!(!allowed(&pool, org, id, &[]).await?);
    assert!(
        list(&pool, org, 1, None, Some(&current_only))
            .await?
            .is_empty()
    );
    assert_eq!(
        list(&pool, org, 1, None, Some(&complete)).await?[0].stack_id,
        id
    );
    assert_eq!(list(&pool, org, 1, None, None).await?[0].stack_id, id);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn service_navigation_omits_deleted_siblings_and_never_crosses_organisations(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let (events, org, stack, mut revision, mut operation) = fixture(&pool).await?;
    let app = revision.services["web"].app_id;
    let mut sibling = revision.services["web"].clone();
    sibling.app_id = Uuid::now_v7();
    sibling.app_name = "worker".into();
    let sibling_id = sibling.app_id;
    let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test").await?;
    work.app(
        sibling_id,
        AppCommand::Create {
            actor: Uuid::nil(),
            organisation_id: org,
            name: grund_config::app::spec::AppName::parse("worker")?,
            settings: sibling.settings.clone(),
            at: revision.created_at,
        },
    )
    .await?;
    work.app(
        sibling_id,
        AppCommand::AssignStack {
            stack_id: stack,
            at: revision.created_at,
        },
    )
    .await?;
    work.commit().await?;
    revision.number = 2;
    revision.services.insert("worker".into(), sibling);
    operation.target_revision = 2;
    let mut connection = pool.acquire().await?;
    apply(
        stack,
        3,
        &Event::RevisionRequested {
            revision,
            operation,
        },
        &mut connection,
    )
    .await?;
    drop(connection);
    assert!(
        live_service_links(&pool, Uuid::now_v7(), app)
            .await?
            .is_empty()
    );
    sqlx::query("UPDATE grund_apps SET deleted_at=clock_timestamp() WHERE app_id=$1")
        .bind(sibling_id)
        .execute(&pool)
        .await?;
    assert_eq!(
        live_service_links(&pool, org, app).await?,
        vec![("web".into(), "backing".into())],
    );
    Ok(())
}
