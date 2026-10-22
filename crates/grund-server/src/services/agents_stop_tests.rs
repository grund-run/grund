use super::{tests::state, *};
use grund_config::app::spec::{AppName, AppSettings};
use grund_domain::{
    app::{AppCommand, AppEvent, DrainReason, PlaceReason, ReleaseSource},
    stack::{Command, Kind, Operation, Revision, Service, Step},
    volume::VolumeCommand,
};
use grund_store::work::Work;
use std::collections::BTreeMap;

struct HostedReplica {
    organisation_id: Uuid,
    stack_id: Uuid,
    app_id: Uuid,
    replica_id: Uuid,
    machine_id: Uuid,
    operation_id: Uuid,
}

async fn hosted_replica(state: &State, mount: &str) -> anyhow::Result<HostedReplica> {
    let organisation_id = Uuid::now_v7();
    let stack_id = Uuid::now_v7();
    let app_id = Uuid::now_v7();
    let replica_id = Uuid::now_v7();
    let machine_id = Uuid::now_v7();
    let at = Utc::now();
    sqlx::query(
        "INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) \
         VALUES($1,$3,'personal',$2,1)",
    )
    .bind(organisation_id)
    .bind(at)
    .bind(organisation_id.simple().to_string())
    .execute(&state.pool)
    .await?;
    sqlx::query(
        "INSERT INTO grund_machines(machine_id,pool,name,state,public_key,pool_organisation_id, \
         pool_name,minted_by,registered_at,key_registered_at,stream_version) \
         VALUES($1,'management',replace($1::text,'-',''),'available',$4,$2,replace($1::text,'-',''),'test',$3,$3,1)",
    )
    .bind(machine_id)
    .bind(organisation_id)
    .bind(at)
    .bind(machine_id.simple().to_string().repeat(2))
    .execute(&state.pool)
    .await?;
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
    work.allow_stack(stack_id);
    work.stack(
        stack_id,
        Command::Create {
            organisation_id,
            name: "hosted-stop".into(),
        },
    )
    .await?;
    let settings = AppSettings::default();
    work.app(
        app_id,
        AppCommand::Create {
            actor: Uuid::nil(),
            organisation_id,
            name: AppName::parse("storage")?,
            settings: settings.clone(),
            at,
        },
    )
    .await?;
    work.app(app_id, AppCommand::AssignStack { stack_id, at })
        .await?;
    let mut spec = grund_domain::app::templates::find("redis")
        .unwrap()
        .spec(false)
        .unwrap();
    spec.ports.clear();
    spec.secrets.clear();
    spec.volumes[0].size_gib = Some(8);
    let volume_spec = spec.volumes[0].clone();
    work.app(
        app_id,
        AppCommand::Release {
            actor: Uuid::nil(),
            spec,
            image_digest: format!("sha256:{}", "a".repeat(64)),
            platforms: Vec::new(),
            exposed_ports: None,
            secret_versions: Vec::new(),
            source: ReleaseSource::File,
            external_release: None,
            request: None,
            rollback_of: None,
            note: String::new(),
            rollout_id: Uuid::now_v7(),
            at,
        },
    )
    .await?;
    work.app_decide(app_id, |_| {
        Ok((
            vec![AppEvent::ReplicaPlaced {
                replica_id,
                slot: 0,
                release: 1,
                machine_id,
                placement: 0,
                reason: PlaceReason::Scale,
                placed_at: at,
            }],
            (),
        ))
    })
    .await?;
    let app = work.load_app(app_id).await?;
    let operation = Operation {
        id: Uuid::now_v7(),
        kind: Kind::Deploy,
        target_revision: 1,
        previous_revision: 0,
        order: vec!["storage".into()],
        cursor: 0,
        step: Step::Pending,
        started_at: at,
        deadline: at + Duration::minutes(5),
        compensating: false,
        failure: None,
        releases: BTreeMap::new(),
        halting: false,
    };
    work.stack(
        stack_id,
        Command::Revise {
            revision: Revision {
                number: 1,
                yaml: String::new(),
                services: BTreeMap::from([(
                    "storage".into(),
                    Service {
                        app_id,
                        app_name: "storage".into(),
                        release: app.releases[0].clone(),
                        settings,
                        depends_on: Vec::new(),
                        exclusive: true,
                        template: Some("redis".into()),
                    },
                )]),
                public_service: None,
                public_port: None,
                created_at: at,
                created_by: Uuid::nil(),
                rollback_of: None,
            },
            operation: operation.clone(),
        },
    )
    .await?;
    let operation_id = Uuid::now_v7();
    work.stack(
        stack_id,
        Command::Operate {
            operation: Operation {
                id: operation_id,
                kind: Kind::Delete,
                step: Step::Stopping,
                ..operation
            },
            at,
        },
    )
    .await?;
    if mount != "missing" {
        let volume_id = Uuid::now_v7();
        for command in [
            VolumeCommand::Request {
                organisation_id,
                app_id,
                name: volume_spec.name,
                path: volume_spec.path,
                source: None,
                backup: false,
                size_gib: Some(8),
                at,
            },
            VolumeCommand::Place { machine_id, at },
            VolumeCommand::PrepareBackend {
                machine_id,
                slot: 1,
                at,
            },
            VolumeCommand::ConfirmBackendAttachment { machine_id, at },
        ] {
            work.volume(volume_id, command).await?;
        }
        if mount == "invalidated" {
            work.volume(
                volume_id,
                VolumeCommand::InvalidateBackendAttachment { machine_id, at },
            )
            .await?;
        } else if mount == "detached" {
            work.volume(
                volume_id,
                VolumeCommand::BeginBackendDetachment { machine_id, at },
            )
            .await?;
            work.volume(
                volume_id,
                VolumeCommand::ConfirmBackendDetachment { machine_id, at },
            )
            .await?;
        }
    }
    work.commit().await?;
    Ok(HostedReplica {
        organisation_id,
        stack_id,
        app_id,
        replica_id,
        machine_id,
        operation_id,
    })
}

async fn drain(state: &State, replica: &HostedReplica) -> anyhow::Result<()> {
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
    work.allow_stack(replica.stack_id);
    work.app_decide(replica.app_id, |_| {
        Ok((
            vec![AppEvent::ReplicaDraining {
                replica_id: replica.replica_id,
                reason: DrainReason::Deleted,
                draining_at: Utc::now(),
            }],
            (),
        ))
    })
    .await?;
    work.commit().await?;
    Ok(())
}

async fn receipts(state: &State, replica: &HostedReplica) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM grund_stack_receipts WHERE organisation_id=$1 AND stack_id=$2",
    )
    .bind(replica.organisation_id)
    .bind(replica.stack_id)
    .fetch_one(&state.pool)
    .await?)
}

#[sqlx::test(migrations = false)]
async fn hosted_stop_directives_survive_missing_invalidated_and_detached_mount_receipts(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let state = state(pool).await;
    for mount in ["missing", "invalidated", "detached", "unacknowledged"] {
        let replica = hosted_replica(&state, mount).await?;
        state.agents().publish(replica.machine_id).await?;
        let omitted = agents::document(&state.pool, replica.machine_id)
            .await?
            .unwrap();
        let running = agent::DesiredState::decode_from_slice(&omitted.payload)?;
        assert!(running.replicas.is_empty(), "{mount}");
        let member_stopping = matches!(mount, "missing" | "invalidated");
        let mut tx = state.pool.begin().await?;
        grund_store::stacks::gate(
            &mut tx,
            replica.organisation_id,
            replica.stack_id,
            "storage",
            false,
            member_stopping,
            Some(replica.operation_id),
        )
        .await?;
        sqlx::query("UPDATE grund_stack_members SET required_generation=$2 WHERE app_id=$1")
            .bind(replica.app_id)
            .bind(omitted.generation)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        if mount != "missing" {
            drain(&state, &replica).await?;
        }
        state.agents().publish(replica.machine_id).await?;
        let document = agents::document(&state.pool, replica.machine_id)
            .await?
            .unwrap();
        let desired = agent::DesiredState::decode_from_slice(&document.payload)?;
        assert_eq!(desired.replicas.len(), 1, "{mount}");
        let directive = &desired.replicas[0];
        assert!(directive.stopping, "{mount}");
        assert_eq!(directive.replica_id, replica.replica_id.to_string());
        assert_eq!(directive.operation_id, replica.operation_id.to_string());
        assert!(directive.volumes.is_empty(), "{mount}");
        assert!(
            !desired
                .required_features
                .iter()
                .any(|feature| { matches!(feature.as_str(), "volumes" | "block-volumes") })
        );
        let member =
            grund_store::stacks::member(&state.pool, replica.organisation_id, replica.app_id)
                .await?
                .unwrap();
        assert_eq!(member.required_generation, document.generation, "{mount}");
        if mount == "missing" {
            drain(&state, &replica).await?;
        }
        state.agents().publish(replica.machine_id).await?;
        let current = agents::document(&state.pool, replica.machine_id)
            .await?
            .unwrap();
        let member =
            grund_store::stacks::member(&state.pool, replica.organisation_id, replica.app_id)
                .await?
                .unwrap();
        assert_eq!(member.required_generation, document.generation);
        let caller = MachineCaller {
            machine_id: replica.machine_id,
            organisation_id: Some(replica.organisation_id),
            endpoint_key_prefix: [b'a'; 12],
            registration_key: replica.machine_id.simple().to_string().repeat(2),
            signed_at: Utc::now(),
        };
        state
            .agents()
            .report(
                &caller,
                current.generation as u64,
                VmReports {
                    states: &[],
                    updates: &[],
                },
                &[],
                Some(&[]),
                &[],
            )
            .await?;
        assert_eq!(receipts(&state, &replica).await?, 0);
        let terminal = ReplicaReport {
            replica_id: replica.replica_id,
            state: "exited",
            ready: false,
            ready_for_ms: 0,
            restarts: 0,
            last_exit_code: 0,
            reason: String::new(),
            idle: false,
            applied_generation: current.generation as u64,
            operation_id: Some(replica.operation_id),
        };
        for stale in [
            ReplicaReport {
                operation_id: Some(Uuid::now_v7()),
                ..terminal.clone()
            },
            ReplicaReport {
                applied_generation: omitted.generation as u64,
                ..terminal.clone()
            },
            ReplicaReport {
                applied_generation: current.generation as u64 + 1,
                ..terminal.clone()
            },
        ] {
            state
                .agents()
                .report(
                    &caller,
                    current.generation as u64,
                    VmReports {
                        states: &[],
                        updates: &[],
                    },
                    &[],
                    Some(&[stale]),
                    &[],
                )
                .await?;
            assert_eq!(receipts(&state, &replica).await?, 0, "{mount}");
        }
        let wrong_machine_id = Uuid::now_v7();
        let wrong_machine = MachineCaller {
            machine_id: wrong_machine_id,
            registration_key: wrong_machine_id.simple().to_string().repeat(2),
            ..caller.clone()
        };
        sqlx::query(
            "INSERT INTO grund_machines(machine_id,pool,name,state,public_key,pool_organisation_id, \
             pool_name,minted_by,registered_at,key_registered_at,stream_version) \
             VALUES($1,'management',replace($1::text,'-',''),'available',$4,$2,replace($1::text,'-',''),'test',$3,$3,1)",
        )
        .bind(wrong_machine.machine_id)
        .bind(replica.organisation_id)
        .bind(Utc::now())
        .bind(&wrong_machine.registration_key)
        .execute(&state.pool)
        .await?;
        state
            .agents()
            .report(
                &wrong_machine,
                current.generation as u64,
                VmReports {
                    states: &[],
                    updates: &[],
                },
                &[],
                Some(std::slice::from_ref(&terminal)),
                &[],
            )
            .await?;
        assert_eq!(receipts(&state, &replica).await?, 0);
        for _ in 0..2 {
            state
                .agents()
                .report(
                    &caller,
                    current.generation as u64,
                    VmReports {
                        states: &[],
                        updates: &[],
                    },
                    &[],
                    Some(std::slice::from_ref(&terminal)),
                    &[],
                )
                .await?;
            assert_eq!(receipts(&state, &replica).await?, 1);
        }
    }
    Ok(())
}
