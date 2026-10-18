//! Rebuildable rollout read models and disposable signed-heartbeat observations.

use chrono::{DateTime, Utc};
use grund_domain::agent_updates::{
    AgentUpdates, Attempt, CompletedAttempt, Event, ProviderUpdateFence, PublicBuild, rollout_id,
};
use mire::{HandledEvent, TransactionalEventHandler};
use sqlx::{Executor, PgConnection, Postgres};
use uuid::Uuid;

/// Bump this identity to rebuild the rollout read model from its event stream.
pub const SUBSCRIPTION: &str = "grund-agent-updates-read-model-v1";

/// A disposable observation bound to the machine's current registration.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct UpdateObservation {
    pub machine_id: Uuid,
    pub registration_key: String,
    pub boot_id: Uuid,
    pub revision: String,
    pub ready: bool,
    pub observed_at: DateTime<Utc>,
}

/// Reads the latest independently observed heartbeat for this machine.
pub async fn update_observation<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    machine_id: Uuid,
) -> Result<Option<UpdateObservation>, sqlx::Error> {
    sqlx::query_as::<_, UpdateObservation>(
        "SELECT machine_id, registration_key, boot_id, revision, ready, observed_at \
         FROM grund_agent_update_observations WHERE machine_id = $1",
    )
    .bind(machine_id)
    .fetch_optional(executor)
    .await
}

/// Replays a terminal report even after a later attempt has completed.
pub async fn completed_update_attempt<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    attempt_id: Uuid,
) -> Result<Option<Attempt>, sqlx::Error> {
    Ok(sqlx::query_scalar::<_, sqlx::types::Json<Attempt>>(
        "SELECT attempt FROM grund_agent_update_completed_attempts WHERE attempt_id = $1",
    )
    .bind(attempt_id)
    .fetch_optional(executor)
    .await?
    .map(|attempt| attempt.0))
}
/// Records a heartbeat without turning transport observations into event truth.
pub async fn record_update_observation(
    connection: &mut PgConnection,
    machine_id: Uuid,
    registration_key: &str,
    boot_id: Uuid,
    revision: &str,
    ready: bool,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_agent_update_observations \
         (machine_id, registration_key, boot_id, revision, ready, observed_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (machine_id) DO UPDATE SET registration_key = EXCLUDED.registration_key, \
         boot_id = EXCLUDED.boot_id, revision = EXCLUDED.revision, ready = EXCLUDED.ready, \
         observed_at = EXCLUDED.observed_at \
         WHERE grund_agent_update_observations.observed_at < EXCLUDED.observed_at",
    )
    .bind(machine_id)
    .bind(registration_key)
    .bind(boot_id)
    .bind(revision)
    .bind(ready)
    .bind(at)
    .execute(connection)
    .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct RolloutRow {
    initialized: bool,
    generation: i64,
    target: Option<sqlx::types::Json<PublicBuild>>,
    paused: bool,
    active: Option<sqlx::types::Json<Attempt>>,
    last_completed: Option<sqlx::types::Json<CompletedAttempt>>,
    attempt_sequence: i64,
    migration_holds: sqlx::types::Json<std::collections::BTreeMap<Uuid, Uuid>>,
    closed_migrations: sqlx::types::Json<std::collections::BTreeMap<Uuid, Uuid>>,
    pending_provider_release: Option<sqlx::types::Json<ProviderUpdateFence>>,
    stream_version: i64,
}

/// Reads the disposable singleton view and the stream version it represents.
pub async fn get<'e>(
    executor: impl Executor<'e, Database = Postgres>,
) -> Result<Option<(AgentUpdates, i64)>, sqlx::Error> {
    let row = sqlx::query_as::<_, RolloutRow>(
        "SELECT initialized, generation, target, paused, active, last_completed, stream_version, \
         attempt_sequence, migration_holds, closed_migrations, pending_provider_release \
         FROM grund_agent_updates WHERE rollout_id = $1",
    )
    .bind(rollout_id())
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|row| {
        (
            AgentUpdates {
                initialized: row.initialized,
                generation: row.generation as u64,
                target: row.target.map(|value| value.0),
                paused: row.paused,
                active: row.active.map(|value| value.0),
                last_completed: row.last_completed.map(|value| value.0),
                attempt_sequence: row.attempt_sequence as u64,
                migration_holds: row.migration_holds.0,
                closed_migrations: row.closed_migrations.0,
                pending_provider_release: row.pending_provider_release.map(|value| value.0),
            },
            row.stream_version,
        )
    }))
}

/// Applies an event with the same version fence on inline writes and replay.
pub async fn apply_agent_updates(
    version: i64,
    event: &Event,
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    let id = rollout_id();
    match event {
        Event::Initialized { .. } => {
            sqlx::query(
                "INSERT INTO grund_agent_updates (rollout_id, initialized, stream_version) VALUES ($1, TRUE, $2) \
                 ON CONFLICT (rollout_id) DO UPDATE SET initialized = TRUE, stream_version = EXCLUDED.stream_version \
                 WHERE grund_agent_updates.stream_version < EXCLUDED.stream_version",
            )
            .bind(id).bind(version).execute(&mut *connection).await?;
        }
        Event::TargetSelected {
            generation, target, ..
        } => {
            sqlx::query(
                "UPDATE grund_agent_updates SET generation = $2, target = $3, stream_version = $4 \
                 WHERE rollout_id = $1 AND stream_version < $4",
            )
            .bind(id)
            .bind(*generation as i64)
            .bind(sqlx::types::Json(target))
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        Event::RolloutPaused { .. } | Event::RolloutResumed { .. } => {
            sqlx::query(
                "UPDATE grund_agent_updates SET paused = $2, stream_version = $3 \
                 WHERE rollout_id = $1 AND stream_version < $3",
            )
            .bind(id)
            .bind(matches!(event, Event::RolloutPaused { .. }))
            .bind(version)
            .execute(&mut *connection)
            .await?;
        }
        Event::AttemptOffered { attempt, .. }
        | Event::ProviderReservationRequested { attempt, .. }
        | Event::AttemptAuthorized { attempt, .. }
        | Event::CandidateHealthVerified { attempt, .. }
        | Event::AttemptFailed { attempt, .. } => {
            sqlx::query(
                "UPDATE grund_agent_updates SET active = $2, paused = CASE WHEN $3 THEN TRUE ELSE paused END, \
                 attempt_sequence = GREATEST(attempt_sequence, $5), \
                 stream_version = $4 WHERE rollout_id = $1 AND stream_version < $4",
            )
            .bind(id).bind(sqlx::types::Json(attempt)).bind(matches!(event, Event::AttemptFailed { .. })).bind(version)
            .bind(attempt.sequence as i64)
            .execute(&mut *connection).await?;
        }
        Event::AttemptSucceeded { attempt, .. } | Event::AttemptRolledBack { attempt, .. } => {
            sqlx::query(
                "UPDATE grund_agent_updates SET active = NULL, last_completed = $2, \
                 paused = CASE WHEN $3 THEN TRUE ELSE paused END, pending_provider_release = $5, stream_version = $4 \
                 WHERE rollout_id = $1 AND stream_version < $4",
            )
            .bind(id).bind(sqlx::types::Json(attempt)).bind(matches!(event, Event::AttemptRolledBack { .. })).bind(version)
            .bind(attempt.provider_fence.as_ref().map(sqlx::types::Json))
            .execute(&mut *connection).await?;
            sqlx::query(
                "INSERT INTO grund_agent_update_completed_attempts (attempt_id, attempt, stream_version) \
                 VALUES ($1, $2, $3) ON CONFLICT (attempt_id) DO UPDATE \
                 SET attempt = EXCLUDED.attempt, stream_version = EXCLUDED.stream_version \
                 WHERE grund_agent_update_completed_attempts.stream_version < EXCLUDED.stream_version",
            )
            .bind(attempt.id).bind(sqlx::types::Json(attempt)).bind(version)
            .execute(&mut *connection).await?;
        }
        Event::OfferCancelled { attempt, .. } => {
            sqlx::query(
                "UPDATE grund_agent_updates SET active = NULL, pending_provider_release = $3, stream_version = $2 \
                 WHERE rollout_id = $1 AND stream_version < $2",
            )
            .bind(id).bind(version).bind(attempt.provider_fence.as_ref().map(sqlx::types::Json))
            .execute(&mut *connection).await?;
        }
        Event::MigrationHeld {
            machine_id,
            migration_id,
            ..
        } => {
            sqlx::query(
                "UPDATE grund_agent_updates SET migration_holds = jsonb_set(migration_holds, ARRAY[$2], to_jsonb($3::text)), \
                 stream_version = $4 WHERE rollout_id = $1 AND stream_version < $4",
            ).bind(id).bind(machine_id.to_string()).bind(migration_id.to_string()).bind(version)
                .execute(&mut *connection).await?;
        }
        Event::MigrationCleared {
            machine_id,
            migration_id,
            ..
        } => {
            sqlx::query(
                "UPDATE grund_agent_updates SET migration_holds = CASE WHEN migration_holds->>$2 = $3 \
                 THEN migration_holds - $2 ELSE migration_holds END, \
                 closed_migrations = jsonb_set(closed_migrations, ARRAY[$2], \
                    to_jsonb(GREATEST((closed_migrations->>$2)::uuid, ($3::text)::uuid))), stream_version = $4 \
                 WHERE rollout_id = $1 AND stream_version < $4",
            ).bind(id).bind(machine_id.to_string()).bind(migration_id.to_string()).bind(version)
                .execute(&mut *connection).await?;
        }
        Event::ProviderReleaseAcknowledged { reservation, .. } => {
            sqlx::query(
                "UPDATE grund_agent_updates SET pending_provider_release = CASE WHEN pending_provider_release = $2 \
                 THEN NULL ELSE pending_provider_release END, stream_version = $3 \
                 WHERE rollout_id = $1 AND stream_version < $3",
            ).bind(id).bind(sqlx::types::Json(reservation)).bind(version)
                .execute(&mut *connection).await?;
        }
    }
    Ok(())
}

/// Transactional catch-up uses exactly the projection used by `Work`.
pub struct AgentUpdatesProjection;

impl TransactionalEventHandler for AgentUpdatesProjection {
    type Aggregate = AgentUpdates;

    async fn handle(
        &self,
        event: HandledEvent<Event>,
        connection: &mut PgConnection,
    ) -> anyhow::Result<()> {
        let id = crate::projections::stream_uuid(
            event.stream_id(),
            grund_domain::agent_updates::CATEGORY,
        )?;
        anyhow::ensure!(id == rollout_id(), "unexpected agent rollout stream");
        apply_agent_updates(event.stream_version(), &event.event, connection).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grund_domain::agent_updates::Command;
    use mire::Command as _;
    use sqlx::PgPool;

    #[sqlx::test(migrations = "./migrations")]
    async fn replay_and_older_events_cannot_unpause_or_reoccupy_a_completed_slot(pool: PgPool) {
        let at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let mut connection = pool.acquire().await.unwrap();
        let mut state = AgentUpdates::default();
        let mut version = 0;
        let mut history = Vec::new();
        let target = PublicBuild::main(&"b".repeat(40)).unwrap();
        let commands = [
            Command::Initialize { at },
            Command::Select { target, at },
            Command::Offer {
                attempt_id: Uuid::from_u128(1),
                machine_id: Uuid::from_u128(2),
                registration_key: "a".repeat(64),
                generation: 1,
                previous_revision: "a".repeat(40),
                at,
                expires_at: at + chrono::Duration::minutes(10),
            },
        ];
        for command in commands {
            for event in command.handle(&state).unwrap() {
                mire::Aggregate::apply(&mut state, &event);
                version += 1;
                apply_agent_updates(version, &event, &mut connection)
                    .await
                    .unwrap();
                history.push((version, event));
            }
        }
        let fence = state.active.as_ref().unwrap().fence();
        for command in [
            Command::Begin {
                fence: fence.clone(),
                boot_id: Uuid::from_u128(3),
                provider_permit: None,
                at,
            },
            Command::Rollback {
                fence,
                boot_id: Uuid::from_u128(4),
                at,
            },
        ] {
            for event in command.handle(&state).unwrap() {
                mire::Aggregate::apply(&mut state, &event);
                version += 1;
                apply_agent_updates(version, &event, &mut connection)
                    .await
                    .unwrap();
                history.push((version, event));
            }
        }
        let receipt = completed_update_attempt(&mut *connection, Uuid::from_u128(1))
            .await
            .unwrap()
            .unwrap();
        let next_fence = grund_domain::agent_updates::Fence {
            attempt_id: Uuid::from_u128(5),
            machine_id: Uuid::from_u128(6),
            registration_key: "b".repeat(64),
            generation: state.generation,
        };
        for command in [
            Command::Resume { at },
            Command::Offer {
                attempt_id: next_fence.attempt_id,
                machine_id: next_fence.machine_id,
                registration_key: next_fence.registration_key.clone(),
                generation: next_fence.generation,
                previous_revision: "a".repeat(40),
                at,
                expires_at: at + chrono::Duration::minutes(10),
            },
            Command::Begin {
                fence: next_fence.clone(),
                boot_id: Uuid::from_u128(7),
                provider_permit: None,
                at,
            },
            Command::Health {
                fence: next_fence.clone(),
                boot_id: Uuid::from_u128(8),
                at,
            },
            Command::Commit {
                fence: next_fence,
                boot_id: Uuid::from_u128(8),
                at,
            },
        ] {
            for event in command.handle(&state).unwrap() {
                mire::Aggregate::apply(&mut state, &event);
                version += 1;
                apply_agent_updates(version, &event, &mut connection)
                    .await
                    .unwrap();
                history.push((version, event));
            }
        }
        let expected = get(&mut *connection).await.unwrap().unwrap();
        assert_eq!(expected, (state, version));
        for (version, event) in history.iter().rev().chain(history.iter()) {
            apply_agent_updates(*version, event, &mut connection)
                .await
                .unwrap();
        }
        assert_eq!(get(&mut *connection).await.unwrap().unwrap(), expected);
        assert_eq!(
            completed_update_attempt(&mut *connection, Uuid::from_u128(1))
                .await
                .unwrap(),
            Some(receipt)
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn old_heartbeats_cannot_replace_new_registration_health(pool: PgPool) {
        let at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let machine = Uuid::from_u128(1);
        let mut connection = pool.acquire().await.unwrap();
        record_update_observation(
            &mut connection,
            machine,
            &"b".repeat(64),
            Uuid::from_u128(3),
            &"b".repeat(40),
            true,
            at,
        )
        .await
        .unwrap();
        record_update_observation(
            &mut connection,
            machine,
            &"a".repeat(64),
            Uuid::from_u128(2),
            &"a".repeat(40),
            false,
            at - chrono::Duration::seconds(1),
        )
        .await
        .unwrap();
        let observation = update_observation(&mut *connection, machine)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observation.registration_key, "b".repeat(64));
        assert!(observation.ready);
    }

    async fn transact(
        events: &mire::EventStore,
        command: Command,
    ) -> Result<Vec<Event>, crate::work::WorkError> {
        let mut work = crate::work::Work::begin(events, Uuid::now_v7(), "test").await?;
        let emitted = work.agent_updates(command).await?;
        work.commit().await?;
        Ok(emitted)
    }

    #[sqlx::test(migrations = false)]
    async fn concurrent_first_writers_create_one_singleton_and_offer_only_one_machine(
        pool: PgPool,
    ) {
        crate::migrate(&pool).await.unwrap();
        let events = mire::EventStore::new(pool.clone());
        let at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let (first, second) = tokio::join!(
            transact(&events, Command::Initialize { at }),
            transact(&events, Command::Initialize { at }),
        );
        assert_eq!(first.unwrap().len() + second.unwrap().len(), 1);
        transact(
            &events,
            Command::Select {
                target: PublicBuild::main(&"b".repeat(40)).unwrap(),
                at,
            },
        )
        .await
        .unwrap();
        let offer = |id| Command::Offer {
            attempt_id: Uuid::from_u128(id),
            machine_id: Uuid::from_u128(id + 10),
            registration_key: "a".repeat(64),
            generation: 1,
            previous_revision: "a".repeat(40),
            at,
            expires_at: at + chrono::Duration::minutes(10),
        };
        let (first, second) =
            tokio::join!(transact(&events, offer(1)), transact(&events, offer(2)));
        let (winner, loser) = if first.is_ok() {
            (first, second)
        } else {
            (second, first)
        };
        assert_eq!(winner.unwrap().len(), 1);
        assert!(matches!(
            loser,
            Err(crate::work::WorkError::AgentUpdates(
                grund_domain::agent_updates::Error::SlotOccupied
            ))
        ));
        let (state, _) = get(&pool).await.unwrap().unwrap();
        assert!(state.active.is_some());
        let streams: i64 =
            sqlx::query_scalar("SELECT count(*) FROM es_streams WHERE stream_id = $1")
                .bind(format!(
                    "{}-{}",
                    grund_domain::agent_updates::CATEGORY,
                    rollout_id()
                ))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(streams, 1);
    }

    #[sqlx::test(migrations = false)]
    async fn a_long_rollout_stream_loads_the_same_state_from_snapshot_and_full_history(
        pool: PgPool,
    ) {
        crate::migrate(&pool).await.unwrap();
        let events = mire::EventStore::new(pool.clone());
        let at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        transact(&events, Command::Initialize { at }).await.unwrap();
        let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test")
            .await
            .unwrap();
        for _ in 0..55 {
            work.agent_updates(Command::Pause { at }).await.unwrap();
            work.agent_updates(Command::Resume { at }).await.unwrap();
        }
        work.commit().await.unwrap();
        let full = events
            .load::<AgentUpdates>(&rollout_id().to_string())
            .await
            .unwrap()
            .unwrap();
        events.save_snapshot(&full).await.unwrap();
        let snapshotted = events
            .load_snapshotted::<AgentUpdates>(&rollout_id().to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(full.version, 111);
        assert_eq!(snapshotted.version, full.version);
        assert_eq!(snapshotted.state, full.state);
    }

    #[sqlx::test(migrations = false)]
    async fn lifecycle_and_provider_migration_fences_cancel_offers_but_never_steal_an_authorized_slot(
        pool: PgPool,
    ) {
        crate::migrate(&pool).await.unwrap();
        let events = mire::EventStore::new(pool.clone());
        let at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let machine_id = Uuid::now_v7();
        transact(&events, Command::Initialize { at }).await.unwrap();
        transact(
            &events,
            Command::Select {
                target: PublicBuild::main(&"b".repeat(40)).unwrap(),
                at,
            },
        )
        .await
        .unwrap();
        let offer = || Command::Offer {
            attempt_id: Uuid::now_v7(),
            machine_id,
            registration_key: "a".repeat(64),
            generation: 1,
            previous_revision: "a".repeat(40),
            at,
            expires_at: at + chrono::Duration::minutes(10),
        };
        transact(&events, offer()).await.unwrap();
        let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test")
            .await
            .unwrap();
        let cancelled = work
            .load_agent_updates()
            .await
            .unwrap()
            .active
            .unwrap()
            .fence();
        work.guard_machine_update(machine_id, at).await.unwrap();
        work.commit().await.unwrap();
        assert!(
            transact(
                &events,
                Command::Begin {
                    fence: cancelled,
                    boot_id: Uuid::now_v7(),
                    provider_permit: None,
                    at
                }
            )
            .await
            .is_err()
        );
        assert!(get(&pool).await.unwrap().unwrap().0.active.is_none());
        transact(&events, offer()).await.unwrap();
        let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test")
            .await
            .unwrap();
        let authorized = work
            .load_agent_updates()
            .await
            .unwrap()
            .active
            .unwrap()
            .fence();
        work.agent_updates(Command::Begin {
            fence: authorized,
            boot_id: Uuid::now_v7(),
            provider_permit: None,
            at,
        })
        .await
        .unwrap();
        work.commit().await.unwrap();
        let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test")
            .await
            .unwrap();
        assert!(matches!(
            work.guard_machine_update(machine_id, at).await,
            Err(crate::work::WorkError::AgentUpdates(
                grund_domain::agent_updates::Error::LifecycleBlocked
            ))
        ));
        drop(work);
        assert_eq!(
            get(&pool).await.unwrap().unwrap().0.active.unwrap().phase,
            grund_domain::agent_updates::Phase::Authorized
        );
    }
    #[sqlx::test(migrations = false)]
    async fn migration_hold_and_begin_serialize_with_exactly_one_winner(pool: PgPool) {
        crate::migrate(&pool).await.unwrap();
        let events = mire::EventStore::new(pool.clone());
        let at = Utc::now();
        let machine_id = Uuid::now_v7();
        let migration_id = Uuid::now_v7();
        transact(&events, Command::Initialize { at }).await.unwrap();
        transact(
            &events,
            Command::Select {
                target: PublicBuild::main(&"b".repeat(40)).unwrap(),
                at,
            },
        )
        .await
        .unwrap();
        transact(
            &events,
            Command::Offer {
                attempt_id: Uuid::now_v7(),
                machine_id,
                registration_key: "a".repeat(64),
                generation: 1,
                previous_revision: "a".repeat(40),
                at,
                expires_at: at + chrono::Duration::minutes(10),
            },
        )
        .await
        .unwrap();
        let fence = get(&pool).await.unwrap().unwrap().0.active.unwrap().fence();
        let (held, begun) = tokio::join!(
            transact(
                &events,
                Command::HoldMigration {
                    machine_id,
                    migration_id,
                    at
                }
            ),
            transact(
                &events,
                Command::Begin {
                    fence,
                    boot_id: Uuid::now_v7(),
                    provider_permit: None,
                    at
                }
            ),
        );
        assert_ne!(held.is_ok(), begun.is_ok());
        let state = get(&pool).await.unwrap().unwrap().0;
        assert_ne!(
            state.migration_holds.contains_key(&machine_id),
            state.active.unwrap().authorized_at.is_some()
        );
    }

    #[sqlx::test(migrations = false)]
    async fn reservation_cancel_and_release_projection_replay_preserve_restart_safety(
        pool: PgPool,
    ) {
        crate::migrate(&pool).await.unwrap();
        let events = mire::EventStore::new(pool.clone());
        let at = Utc::now();
        let machine_id = Uuid::now_v7();
        transact(&events, Command::Initialize { at }).await.unwrap();
        transact(
            &events,
            Command::Select {
                target: PublicBuild::main(&"b".repeat(40)).unwrap(),
                at,
            },
        )
        .await
        .unwrap();
        transact(
            &events,
            Command::Offer {
                attempt_id: Uuid::now_v7(),
                machine_id,
                registration_key: "a".repeat(64),
                generation: 1,
                previous_revision: "a".repeat(40),
                at,
                expires_at: at + chrono::Duration::minutes(10),
            },
        )
        .await
        .unwrap();
        let fence = get(&pool).await.unwrap().unwrap().0.active.unwrap().fence();
        let requested = transact(
            &events,
            Command::ReserveProvider {
                fence: fence.clone(),
                provider_machine_id: "provider-machine".into(),
                controller_id: Uuid::now_v7(),
                at,
            },
        )
        .await
        .unwrap();
        let mut work = crate::work::Work::begin(&events, Uuid::now_v7(), "test")
            .await
            .unwrap();
        work.guard_machine_update(machine_id, at).await.unwrap();
        let migration_id = Uuid::now_v7();
        work.agent_updates(Command::HoldMigration {
            machine_id,
            migration_id,
            at,
        })
        .await
        .unwrap();
        work.commit().await.unwrap();
        let restarted = mire::EventStore::new(pool.clone());
        let root = restarted
            .load::<AgentUpdates>(&rollout_id().to_string())
            .await
            .unwrap()
            .unwrap();
        let reservation = root.state.pending_provider_release.clone().unwrap();
        assert!(root.state.active.is_none());
        assert_eq!(
            root.state.migration_holds.get(&machine_id),
            Some(&migration_id)
        );
        assert_eq!(get(&pool).await.unwrap().unwrap().0, root.state);
        let emitted = transact(
            &restarted,
            Command::AcknowledgeProviderRelease {
                reservation: reservation.clone(),
                at,
            },
        )
        .await
        .unwrap();
        let acknowledged = get(&pool).await.unwrap().unwrap();
        let mut connection = pool.acquire().await.unwrap();
        for event in &emitted {
            apply_agent_updates(acknowledged.1, event, &mut connection)
                .await
                .unwrap();
        }
        for event in &requested {
            apply_agent_updates(acknowledged.1 - 1, event, &mut connection)
                .await
                .unwrap();
        }
        assert_eq!(get(&mut *connection).await.unwrap().unwrap(), acknowledged);
    }
}
