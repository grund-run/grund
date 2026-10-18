use super::*;
use crate::services::capacity::{
    Capacity, CapacityError, CapacityFuture, CapacityProvider, InventorySize, Offer,
    ProviderUpdateFence,
};
use clap::Parser;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
use tokio::sync::Semaphore;

struct Provider {
    outcome: AtomicU8,
    wait: bool,
    entered: Semaphore,
    proceed: Semaphore,
    release_unavailable: AtomicBool,
    closed: AtomicU64,
}

impl Provider {
    fn new(wait: bool) -> Arc<Self> {
        Arc::new(Self {
            outcome: AtomicU8::new(0),
            wait,
            entered: Semaphore::new(0),
            proceed: Semaphore::new(0),
            release_unavailable: AtomicBool::new(false),
            closed: AtomicU64::new(0),
        })
    }
}

fn unrelated<T>() -> Result<T, CapacityError> {
    Err(CapacityError::Refused(
        "operation is outside this update test".into(),
    ))
}

impl CapacityProvider for Provider {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn acquire_machine_update_fence<'a>(
        &'a self,
        reservation: &'a ProviderUpdateFence,
    ) -> CapacityFuture<'a, Result<bool, CapacityError>> {
        Box::pin(async move {
            self.entered.add_permits(1);
            if self.wait {
                self.proceed.acquire().await.unwrap().forget();
            }
            match self.outcome.load(Ordering::SeqCst) {
                1 => Ok(false),
                2 => Err(CapacityError::Unavailable),
                _ => Ok(reservation.sequence > self.closed.load(Ordering::SeqCst)),
            }
        })
    }
    fn release_machine_update_fence<'a>(
        &'a self,
        reservation: &'a ProviderUpdateFence,
    ) -> CapacityFuture<'a, Result<u64, CapacityError>> {
        Box::pin(async move {
            if self.release_unavailable.load(Ordering::SeqCst) {
                return Err(CapacityError::Unavailable);
            }
            self.closed
                .fetch_max(reservation.sequence, Ordering::SeqCst);
            Ok(self.closed.load(Ordering::SeqCst))
        })
    }
    fn offers(&self) -> CapacityFuture<'_, Result<Vec<Offer>, CapacityError>> {
        Box::pin(async { unrelated() })
    }
    fn inventory_sizes(&self) -> CapacityFuture<'_, Result<Vec<InventorySize>, CapacityError>> {
        Box::pin(async { unrelated() })
    }
    fn get_provision<'a>(
        &'a self,
        _: &'a str,
    ) -> CapacityFuture<'a, Result<Option<String>, CapacityError>> {
        Box::pin(async { unrelated() })
    }
    fn provision<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: DateTime<Utc>,
        _: &'a str,
        _: &'a str,
    ) -> CapacityFuture<'a, Result<String, CapacityError>> {
        Box::pin(async { unrelated() })
    }
    fn rebuild<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CapacityFuture<'a, Result<(), CapacityError>> {
        Box::pin(async { unrelated() })
    }
    fn release<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a [Uuid],
        _: &'a [(Uuid, Uuid)],
    ) -> CapacityFuture<'a, Result<(), CapacityError>> {
        Box::pin(async { unrelated() })
    }
}

#[derive(Parser)]
struct TestConfig {
    #[command(flatten)]
    config: crate::config::ServeConfig,
}

async fn state(pool: sqlx::PgPool, provider: Option<Arc<Provider>>) -> State {
    grund_store::migrate(&pool).await.unwrap();
    let mut config =
        TestConfig::try_parse_from(["test", "--database-url", "postgres://unused/test"])
            .unwrap()
            .config;
    config.agent_updates_paused = false;
    config.license_key = None;
    config.license_key_file = None;
    let secret = Arc::new(crate::secrets::SecretKey::generate());
    let events = mire::EventStore::new(pool.clone());
    let certificates =
        crate::certificates::Certificates::new(&config, pool.clone(), secret.clone());
    let hearing = Arc::new(crate::hearing::Hearing::new(Utc::now()));
    let health = crate::health::registry(
        pool.clone(),
        hearing.clone(),
        None,
        false,
        &certificates,
        &config,
    );
    let entitlements = Arc::new(crate::entitlements(&config).unwrap());
    State {
        config: Arc::new(config),
        pool,
        events: events.clone(),
        nats: None,
        secret,
        certificates,
        health,
        passwords: crate::services::passwords::Passwords::new().unwrap(),
        entitlements,
        billing: crate::services::billing::Billing::Free,
        capacity: provider.map_or(Capacity::None, |provider| Capacity::Provider(provider)),
        deletions: crate::sagas::Deletions::new(events),
        extensions: Arc::new(Vec::new()),
        started: std::time::Instant::now(),
        wakes: crate::wakes::Wakes::default(),
        hearing,
    }
}

async fn offered(state: &State, managed: bool) -> (MachineCaller, Uuid, Uuid) {
    use grund_domain::machine::{MachineCommand, MachineFacts, MachineKey, Pool};
    let now = Utc::now();
    let machine_id = Uuid::now_v7();
    let boot_id = Uuid::now_v7();
    let attempt_id = Uuid::now_v7();
    let caller = MachineCaller {
        machine_id,
        organisation_id: None,
        endpoint_key_prefix: [b'0'; 12],
        registration_key: "07".repeat(32),
    };
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    work.machine(
        machine_id,
        MachineCommand::Register {
            pool: Pool::Management,
            name: grund_config::names::MachineName::parse("test-machine").unwrap(),
            key: MachineKey::from_bytes(&[7; 32]).unwrap(),
            token_id: Uuid::now_v7(),
            minted_by: "account:test".into(),
            facts: MachineFacts::default(),
            provider_machine_id: managed.then(|| "provider-machine".into()),
            at: now,
        },
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO grund_machine_presence (machine_id, last_seen_at) VALUES ($1, $2)")
        .bind(machine_id)
        .bind(now)
        .execute(&mut **work.sql())
        .await
        .unwrap();
    work.record_update_observation(
        machine_id,
        &caller.registration_key,
        boot_id,
        &"a".repeat(40),
        true,
        now,
    )
    .await
    .unwrap();
    work.agent_updates(Command::Initialize { at: now })
        .await
        .unwrap();
    work.agent_updates(Command::Select {
        target: PublicBuild::main(&"b".repeat(40)).unwrap(),
        at: now,
    })
    .await
    .unwrap();
    work.agent_updates(Command::Offer {
        attempt_id,
        machine_id,
        registration_key: caller.registration_key.clone(),
        generation: 1,
        previous_revision: "a".repeat(40),
        at: now,
        expires_at: now + OFFER_TTL,
    })
    .await
    .unwrap();
    work.commit().await.unwrap();
    (caller, attempt_id, boot_id)
}

async fn rollout(state: &State) -> AgentUpdates {
    grund_store::agent_updates::get(&state.pool)
        .await
        .unwrap()
        .unwrap()
        .0
}

#[sqlx::test(migrations = false)]
async fn provider_refusal_and_unavailability_never_authorize_and_both_queue_release(
    pool: sqlx::PgPool,
) {
    let provider = Provider::new(false);
    let state = state(pool, Some(provider.clone())).await;
    let (caller, attempt_id, boot_id) = offered(&state, true).await;
    provider.outcome.store(1, Ordering::SeqCst);
    assert!(
        !state
            .agent_updates()
            .begin(&caller, attempt_id, 1, boot_id)
            .await
            .unwrap()
    );
    let pending = rollout(&state).await.pending_provider_release.unwrap();
    let management = machines::current_key(&state.pool, KeyPurpose::Management.as_str(), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.controller_id, management.key_id);
    monitor(&state).await.unwrap();
    assert!(rollout(&state).await.pending_provider_release.is_none());
    assert!(provider.closed.load(Ordering::SeqCst) >= pending.sequence);

    let now = Utc::now();
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    let next_id = Uuid::now_v7();
    work.agent_updates(Command::Offer {
        attempt_id: next_id,
        machine_id: caller.machine_id,
        registration_key: caller.registration_key.clone(),
        generation: 1,
        previous_revision: "a".repeat(40),
        at: now,
        expires_at: now + OFFER_TTL,
    })
    .await
    .unwrap();
    work.commit().await.unwrap();
    provider.outcome.store(2, Ordering::SeqCst);
    assert!(
        !state
            .agent_updates()
            .begin(&caller, next_id, 1, boot_id)
            .await
            .unwrap()
    );
    assert!(rollout(&state).await.pending_provider_release.is_some());
}

#[sqlx::test(migrations = false)]
async fn own_machine_authorization_is_unchanged_without_a_provider(pool: sqlx::PgPool) {
    let state = state(pool, None).await;
    let (caller, attempt_id, boot_id) = offered(&state, false).await;
    assert!(
        state
            .agent_updates()
            .begin(&caller, attempt_id, 1, boot_id)
            .await
            .unwrap()
    );
    assert!(
        rollout(&state)
            .await
            .active
            .unwrap()
            .provider_fence
            .is_none()
    );
}

#[sqlx::test(migrations = false)]
async fn a_managed_machine_without_its_provider_cannot_authorize(pool: sqlx::PgPool) {
    let state = state(pool, None).await;
    let (caller, attempt_id, boot_id) = offered(&state, true).await;
    assert!(
        !state
            .agent_updates()
            .begin(&caller, attempt_id, 1, boot_id)
            .await
            .unwrap()
    );
    assert!(rollout(&state).await.active.is_none());
    assert!(rollout(&state).await.pending_provider_release.is_some());
}

#[sqlx::test(migrations = false)]
async fn migration_cancels_inflight_acquisition_without_holding_work_over_the_provider_call(
    pool: sqlx::PgPool,
) {
    use crate::services::entry::EntryState;
    let provider = Provider::new(true);
    let state = state(pool, Some(provider.clone())).await;
    let (caller, attempt_id, boot_id) = offered(&state, true).await;
    let service = state.agent_updates();
    let mut beginning = Box::pin(service.begin(&caller, attempt_id, 1, boot_id));
    tokio::select! {
        result = &mut beginning => panic!("acquisition unexpectedly completed: {result:?}"),
        permit = provider.entered.acquire() => permit.unwrap().forget(),
    }
    let migration_id = Uuid::now_v7();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            state
                .entry()
                .set_migration_pause("provider-machine", migration_id, true)
        )
        .await
        .unwrap()
        .unwrap()
    );
    let pending = rollout(&state).await.pending_provider_release.unwrap();
    monitor(&state).await.unwrap();
    assert!(provider.closed.load(Ordering::SeqCst) >= pending.sequence);
    provider.proceed.add_permits(1);
    assert!(!beginning.await.unwrap());
    assert!(rollout(&state).await.active.is_none());
    sqlx::query("UPDATE grund_machine_migration_pauses SET expires_at = clock_timestamp() - interval '1 second'")
        .execute(&state.pool).await.unwrap();
    state.entry().expire_migration_pauses().await.unwrap();
    assert_eq!(
        rollout(&state)
            .await
            .migration_holds
            .get(&caller.machine_id),
        Some(&migration_id)
    );
    state
        .entry()
        .set_migration_pause("provider-machine", Uuid::now_v7(), false)
        .await
        .unwrap();
    assert_eq!(
        rollout(&state)
            .await
            .migration_holds
            .get(&caller.machine_id),
        Some(&migration_id)
    );
    state
        .entry()
        .set_migration_pause("provider-machine", migration_id, false)
        .await
        .unwrap();
    assert!(rollout(&state).await.migration_holds.is_empty());
}

#[sqlx::test(migrations = false)]
async fn abandoned_acquisition_release_is_retried_after_restarting_the_monitor(pool: sqlx::PgPool) {
    let provider = Provider::new(true);
    let state = state(pool, Some(provider.clone())).await;
    let (caller, attempt_id, boot_id) = offered(&state, true).await;
    let service = state.agent_updates();
    let mut beginning = Box::pin(service.begin(&caller, attempt_id, 1, boot_id));
    tokio::select! {
        result = &mut beginning => panic!("acquisition unexpectedly completed: {result:?}"),
        permit = provider.entered.acquire() => permit.unwrap().forget(),
    }
    drop(beginning);
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    sweep(&mut work, Utc::now() + OFFER_TTL).await.unwrap();
    work.commit().await.unwrap();
    provider.release_unavailable.store(true, Ordering::SeqCst);
    assert!(monitor(&state).await.is_err());
    let pending = rollout(&state).await.pending_provider_release.unwrap();
    let mut restarted = state.clone();
    restarted.events = mire::EventStore::new(state.pool.clone());
    provider.release_unavailable.store(false, Ordering::SeqCst);
    monitor(&restarted).await.unwrap();
    assert!(rollout(&restarted).await.pending_provider_release.is_none());
    provider.proceed.add_permits(1);
    assert!(
        !restarted
            .capacity()
            .acquire_machine_update_fence(&pending)
            .await
            .is_ok_and(|allowed| allowed)
    );
}

#[sqlx::test(migrations = false)]
async fn a_positive_provider_grant_cannot_authorize_after_core_policy_changes(pool: sqlx::PgPool) {
    let provider = Provider::new(true);
    let state = state(pool, Some(provider.clone())).await;
    let (caller, attempt_id, boot_id) = offered(&state, true).await;
    let service = state.agent_updates();
    let mut beginning = Box::pin(service.begin(&caller, attempt_id, 1, boot_id));
    tokio::select! {
        result = &mut beginning => panic!("acquisition unexpectedly completed: {result:?}"),
        permit = provider.entered.acquire() => permit.unwrap().forget(),
    }
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    work.agent_updates(Command::Pause { at: Utc::now() })
        .await
        .unwrap();
    work.commit().await.unwrap();
    provider.proceed.add_permits(1);
    assert!(!beginning.await.unwrap());
    let rollout = rollout(&state).await;
    assert!(rollout.active.is_none());
    assert!(rollout.pending_provider_release.is_some());
    assert_eq!(provider.closed.load(Ordering::SeqCst), 0);
}

#[sqlx::test(migrations = false)]
async fn uncertain_authorized_updates_retain_the_fence_and_rollback_release_survives_restart(
    pool: sqlx::PgPool,
) {
    let provider = Provider::new(false);
    let state = state(pool, Some(provider.clone())).await;
    let (caller, attempt_id, boot_id) = offered(&state, true).await;
    assert!(
        state
            .agent_updates()
            .begin(&caller, attempt_id, 1, boot_id)
            .await
            .unwrap()
    );
    let authorized = rollout(&state).await.active.unwrap();
    let reservation = authorized.provider_fence.unwrap();
    assert!(
        state
            .agent_updates()
            .report(
                &caller,
                attempt_id,
                1,
                "failed",
                boot_id,
                &"a".repeat(40),
                Some(Failure::Offline),
            )
            .await
            .unwrap()
            .0
    );
    monitor(&state).await.unwrap();
    assert!(rollout(&state).await.active.is_some());
    assert!(rollout(&state).await.pending_provider_release.is_none());
    assert_eq!(provider.closed.load(Ordering::SeqCst), 0);
    let rollback_boot = Uuid::now_v7();
    state
        .agent_updates()
        .observe(&caller, rollback_boot, &"a".repeat(40), true)
        .await
        .unwrap();
    assert!(
        state
            .agent_updates()
            .report(
                &caller,
                attempt_id,
                1,
                "rolled_back",
                rollback_boot,
                &"a".repeat(40),
                None,
            )
            .await
            .unwrap()
            .0
    );
    assert!(rollout(&state).await.active.is_none());
    provider.release_unavailable.store(true, Ordering::SeqCst);
    assert!(monitor(&state).await.is_err());
    assert_eq!(
        rollout(&state).await.pending_provider_release.as_ref(),
        Some(&reservation)
    );
    let mut restarted = state.clone();
    restarted.events = mire::EventStore::new(state.pool.clone());
    provider.release_unavailable.store(false, Ordering::SeqCst);
    monitor(&restarted).await.unwrap();
    assert!(rollout(&restarted).await.pending_provider_release.is_none());
    assert!(provider.closed.load(Ordering::SeqCst) >= reservation.sequence);
    let now = Utc::now();
    let other_machine = Uuid::now_v7();
    let other_attempt = Uuid::now_v7();
    let mut work = Work::begin(&restarted.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    work.agent_updates(Command::Resume { at: now })
        .await
        .unwrap();
    work.agent_updates(Command::Offer {
        attempt_id: other_attempt,
        machine_id: other_machine,
        registration_key: "08".repeat(32),
        generation: 1,
        previous_revision: "a".repeat(40),
        at: now,
        expires_at: now + OFFER_TTL,
    })
    .await
    .unwrap();
    let other_fence = work
        .load_agent_updates()
        .await
        .unwrap()
        .active
        .unwrap()
        .fence();
    work.agent_updates(Command::Begin {
        fence: other_fence,
        boot_id: Uuid::now_v7(),
        provider_permit: None,
        at: now,
    })
    .await
    .unwrap();
    work.commit().await.unwrap();
    assert!(
        !restarted
            .agent_updates()
            .begin(&caller, attempt_id, 1, boot_id)
            .await
            .unwrap()
    );
    assert_eq!(rollout(&restarted).await.active.unwrap().id, other_attempt);
    assert!(
        restarted
            .agent_updates()
            .report(
                &caller,
                attempt_id,
                1,
                "rolled_back",
                rollback_boot,
                &"a".repeat(40),
                None,
            )
            .await
            .unwrap()
            .0
    );
}

#[sqlx::test(migrations = false)]
async fn clearing_an_unacknowledged_prepare_fences_its_delayed_arrival_after_restart(
    pool: sqlx::PgPool,
) {
    use crate::services::entry::EntryState;
    let state = state(pool, None).await;
    let (caller, _, _) = offered(&state, true).await;
    let migration_id = Uuid::now_v7();
    state
        .entry()
        .set_migration_pause("provider-machine", migration_id, false)
        .await
        .unwrap();
    let mut restarted = state.clone();
    restarted.events = mire::EventStore::new(state.pool.clone());
    assert!(
        restarted
            .entry()
            .set_migration_pause("provider-machine", migration_id, true)
            .await
            .is_err()
    );
    let rollout = rollout(&restarted).await;
    assert!(rollout.migration_holds.is_empty());
    assert_eq!(
        rollout.closed_migrations.get(&caller.machine_id),
        Some(&migration_id)
    );
    let hydrated = restarted
        .events
        .load::<AgentUpdates>(&grund_domain::agent_updates::rollout_id().to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hydrated.state, rollout);
}
