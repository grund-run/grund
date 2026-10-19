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
    release_pending: AtomicBool,
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
            release_pending: AtomicBool::new(false),
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
    ) -> CapacityFuture<'a, Result<bool, CapacityError>> {
        Box::pin(async move {
            if self.release_unavailable.load(Ordering::SeqCst) {
                return Err(CapacityError::Unavailable);
            }
            if self.release_pending.load(Ordering::SeqCst) {
                return Ok(false);
            }
            self.closed
                .fetch_max(reservation.sequence, Ordering::SeqCst);
            Ok(self.closed.load(Ordering::SeqCst) >= reservation.sequence)
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
    ) -> CapacityFuture<'a, Result<bool, CapacityError>> {
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

async fn registered(state: &State, managed: bool) -> (MachineCaller, Uuid) {
    registered_machine(
        state,
        managed,
        None,
        if managed {
            "managed-machine"
        } else {
            "own-machine"
        },
        [if managed { 7 } else { 8 }; 32],
    )
    .await
}

async fn registered_machine(
    state: &State,
    managed: bool,
    organisation_id: Option<Uuid>,
    name: &str,
    key: [u8; 32],
) -> (MachineCaller, Uuid) {
    use grund_domain::machine::{MachineCommand, MachineFacts, MachineKey, Pool};
    let now = Utc::now();
    let machine_id = Uuid::now_v7();
    let boot_id = Uuid::now_v7();
    let caller = MachineCaller {
        machine_id,
        organisation_id,
        endpoint_key_prefix: [b'0'; 12],
        registration_key: hex::encode(key),
        signed_at: now,
    };
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    work.machine(
        machine_id,
        MachineCommand::Register {
            pool: organisation_id.map_or(Pool::Management, |organisation_id| Pool::Organisation {
                organisation_id,
            }),
            name: grund_config::names::MachineName::parse(name).unwrap(),
            key: MachineKey::from_bytes(&key).unwrap(),
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
    work.commit().await.unwrap();
    (caller, boot_id)
}

async fn offered(state: &State, managed: bool) -> (MachineCaller, Uuid, Uuid) {
    let (caller, boot_id) = registered(state, managed).await;
    let attempt_id = Uuid::now_v7();
    let now = Utc::now();
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test")
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
async fn a_machine_without_following_cannot_reserve_or_steal_the_update_slot(pool: sqlx::PgPool) {
    let state = state(pool, None).await;
    let (managed, boot) = registered(&state, true).await;
    assert!(
        state
            .agent_updates()
            .poll(&managed, false, "x86_64", &"a".repeat(40), boot)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !state
            .agent_updates()
            .begin(&managed, Uuid::now_v7(), 0, boot)
            .await
            .unwrap()
    );
    let idle = rollout(&state).await;
    assert!(idle.active.is_none());
    assert_eq!(idle.attempt_sequence, 0);
    assert!(idle.pending_provider_release.is_none());

    let (following, attempt, following_boot) = offered(&state, false).await;
    assert!(
        state
            .agent_updates()
            .begin(&following, attempt, 1, following_boot)
            .await
            .unwrap()
    );
    let rejected = state
        .agent_updates()
        .begin(&managed, attempt, 1, boot)
        .await
        .unwrap_err();
    assert_eq!(
        rejected.downcast_ref::<grund_domain::agent_updates::Error>(),
        Some(&grund_domain::agent_updates::Error::StaleFence)
    );
    let snapshot = rollout(&state).await;
    let authorized = snapshot
        .active
        .as_ref()
        .and_then(ActiveUpdate::executable)
        .unwrap();
    assert_eq!(authorized.machine_id, following.machine_id);
    assert_eq!(authorized.phase, Phase::Authorized);
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
            .as_ref()
            .and_then(ActiveUpdate::executable)
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
    provider.release_pending.store(true, Ordering::SeqCst);
    monitor(&restarted).await.unwrap();
    assert_eq!(
        rollout(&restarted).await.pending_provider_release,
        Some(pending.clone())
    );
    assert_eq!(provider.closed.load(Ordering::SeqCst), 0);
    provider.release_pending.store(false, Ordering::SeqCst);
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
    let snapshot = rollout(&state).await;
    let authorized = snapshot
        .active
        .as_ref()
        .and_then(ActiveUpdate::executable)
        .unwrap();
    let reservation = authorized.provider_fence.clone().unwrap();
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
        .as_ref()
        .and_then(ActiveUpdate::executable)
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
    assert_eq!(
        rollout(&restarted).await.active.unwrap().id(),
        other_attempt
    );
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

async fn record_update_events(state: &State, events: Vec<grund_domain::agent_updates::Event>) {
    let mut root = state
        .events
        .load::<AgentUpdates>(&grund_domain::agent_updates::rollout_id().to_string())
        .await
        .unwrap()
        .unwrap();
    let base = root.version;
    root.record_many(events.clone());
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    work.scope().save(&mut root).await.unwrap();
    for (offset, event) in events.iter().enumerate() {
        grund_store::agent_updates::apply_agent_updates(
            base + offset as i64 + 1,
            event,
            work.sql(),
        )
        .await
        .unwrap();
    }
    work.commit().await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn a_vm_slot_and_receipt_never_offer_or_accept_an_executable_update(pool: sqlx::PgPool) {
    use grund_domain::agent_updates::{Event, vm as domain_vm};
    use mire::Command as _;

    let provider = Provider::new(false);
    let state = state(pool, Some(provider.clone())).await;
    let (caller, boot_id) = registered(&state, true).await;
    let now = Utc::now();
    let attempt_id = Uuid::now_v7();
    let request = domain_vm::Request {
        id: attempt_id,
        vm_id: Uuid::now_v7(),
        organisation_id: Uuid::now_v7(),
        host_machine_id: Uuid::now_v7(),
        guest_machine_id: caller.machine_id,
        host_registration_key: "a".repeat(64),
        guest_registration_key: caller.registration_key.clone(),
        request_hash: "c".repeat(64),
        fingerprint: "d".repeat(64),
        source: domain_vm::ImageIdentity {
            kernel_sha256: "e".repeat(64),
            rootfs_sha256: "f".repeat(64),
        },
        target: domain_vm::Target {
            kernel_url: "https://artifacts.example/kernel".into(),
            kernel_sha256: "1".repeat(64),
            rootfs_url: "https://artifacts.example/rootfs".into(),
            rootfs_sha256: "2".repeat(64),
        },
        expected_update_version: 0,
        original_in_service: true,
        old_os_boot_id: None,
        launch_nonce: Uuid::now_v7(),
        deadline: now + Duration::minutes(5),
    };
    let events = domain_vm::Command::Request { request, at: now }
        .handle(&rollout(&state).await)
        .unwrap();
    record_update_events(&state, events).await;
    let occupied = rollout(&state).await;

    assert!(
        state
            .agent_updates()
            .poll(&caller, true, "x86_64", &"a".repeat(40), boot_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !state
            .agent_updates()
            .begin(&caller, attempt_id, occupied.generation, boot_id)
            .await
            .unwrap()
    );
    assert_eq!(provider.entered.available_permits(), 0);
    for phase in ["candidate_health", "committed", "rolled_back", "failed"] {
        let (accepted, permit) = state
            .agent_updates()
            .report(
                &caller,
                attempt_id,
                occupied.generation,
                phase,
                boot_id,
                &"a".repeat(40),
                Some(Failure::Offline),
            )
            .await
            .unwrap();
        assert!(!accepted);
        assert!(permit.is_none());
    }
    let mut work = Work::begin(&state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    assert_eq!(
        sweep(&mut work, now + ATTEMPT_TIMEOUT + Duration::seconds(1))
            .await
            .unwrap(),
        occupied
    );
    work.commit().await.unwrap();
    assert_eq!(rollout(&state).await, occupied);

    let mut receipt = occupied
        .active
        .as_ref()
        .and_then(ActiveUpdate::vm)
        .unwrap()
        .clone();
    receipt.phase = domain_vm::Phase::Cancelled;
    receipt.completed_at = Some(now);
    record_update_events(
        &state,
        vec![Event::VmCompleted {
            attempt: receipt,
            at: now,
        }],
    )
    .await;
    assert!(
        !state
            .agent_updates()
            .begin(&caller, attempt_id, occupied.generation, boot_id)
            .await
            .unwrap()
    );
    let (accepted, permit) = state
        .agent_updates()
        .report(
            &caller,
            attempt_id,
            occupied.generation,
            "committed",
            boot_id,
            &"a".repeat(40),
            None,
        )
        .await
        .unwrap();
    assert!(!accepted);
    assert!(permit.is_none());
    assert_eq!(provider.entered.available_permits(), 0);
}

struct ReadyVm {
    state: State,
    organisation_id: Uuid,
    vm_id: Uuid,
    host: MachineCaller,
}

impl ReadyVm {
    fn request(&self) -> vm::VmUpdateRequest {
        vm::VmUpdateRequest {
            expected_version: 0,
            rootfs_sha256: "2".repeat(64),
            idempotency_key: Uuid::now_v7().to_string(),
        }
    }
}

async fn ready_vm(pool: sqlx::PgPool) -> ReadyVm {
    let mut state = state(pool, None).await;
    let config = Arc::make_mut(&mut state.config);
    config.vm_updates_enabled = true;
    config.machine_defaults.vm_rootfs_url = Some("https://artifacts.example/new-rootfs".into());
    config.machine_defaults.vm_rootfs_sha256 = Some("2".repeat(64));
    let organisation_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO grund_organisations (organisation_id,slug,kind,created_at,stream_version) \
         VALUES ($1,'vm-owner','personal',$2,1)",
    )
    .bind(organisation_id)
    .bind(Utc::now())
    .execute(&state.pool)
    .await
    .unwrap();
    let (host, _) = registered_machine(&state, false, Some(organisation_id), "host", [9; 32]).await;
    let (guest, _) =
        registered_machine(&state, false, Some(organisation_id), "guest", [10; 32]).await;
    grund_store::agents::heartbeat(
        &state.pool,
        host.machine_id,
        "test",
        &serde_json::json!({"arch":"x86_64","vm_replacement_version":1}),
        Utc::now(),
    )
    .await
    .unwrap();
    grund_store::agents::record_runtime_heartbeat(
        &state.pool,
        host.machine_id,
        &grund_store::agents::RuntimeHeartbeat {
            registration_key: host.registration_key.clone(),
            signed_at: Utc::now(),
            runtime_ready: true,
            guest_boot: None,
        },
    )
    .await
    .unwrap();
    let vm_id = Uuid::now_v7();
    grund_store::agents::insert_vm(
        &state.pool,
        &grund_store::agents::NewVm {
            vm_id,
            organisation_id,
            host_machine_id: host.machine_id,
            name: "own-vm",
            vcpus: 2,
            memory_mib: 512,
            disk_gib: 8,
            kernel_url: "https://artifacts.example/kernel",
            kernel_sha256: "9204218e8bcca6ac23848d74f45df2eb19d7f31e8277840a7d145a0df8b078d2",
            rootfs_url: "https://artifacts.example/old-rootfs",
            rootfs_sha256: &"1".repeat(64),
            created_by: Uuid::now_v7(),
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE grund_vms SET machine_id=$2 WHERE vm_id=$1")
        .bind(vm_id)
        .bind(guest.machine_id)
        .execute(&state.pool)
        .await
        .unwrap();
    ReadyVm {
        state,
        organisation_id,
        vm_id,
        host,
    }
}

#[sqlx::test(migrations = false)]
async fn local_data_blocks_replacement_until_managed_erasure_is_acknowledged(pool: sqlx::PgPool) {
    use crate::services::{apps::AppsState, volumes::VolumesState};
    use grund_domain::volume::VolumeCommand;

    let fixture = ready_vm(pool).await;
    let service = fixture.state.agent_updates();
    let guest = grund_store::agents::vm(&fixture.state.pool, fixture.vm_id)
        .await
        .unwrap()
        .unwrap()
        .machine_id
        .unwrap();
    let actor = Uuid::now_v7();
    let app = fixture
        .state
        .apps()
        .create(
            actor,
            fixture.organisation_id,
            "local-data",
            Default::default(),
        )
        .await
        .unwrap();
    for (name, source) in [("managed", None), ("external", Some("/owner/data"))] {
        let volume = Uuid::now_v7();
        let at = Utc::now();
        let mut work = Work::begin(&fixture.state.events, Uuid::now_v7(), "test")
            .await
            .unwrap();
        work.volume(
            volume,
            VolumeCommand::Request {
                organisation_id: fixture.organisation_id,
                app_id: app.row.app_id,
                name: name.into(),
                path: "/data".into(),
                source: source.map(str::to_owned),
                backup: false,
                size_gib: None,
                at,
            },
        )
        .await
        .unwrap();
        work.commit().await.unwrap();
        for command in [
            VolumeCommand::Attach {
                machine_id: guest,
                path: "/owned/data".into(),
                at,
            },
            VolumeCommand::Delete {
                at,
                purge_after: at + Duration::days(7),
            },
            VolumeCommand::PurgeNow {
                actor,
                reason: "owned test data is no longer needed".into(),
                at,
            },
        ] {
            let mut work = Work::begin(&fixture.state.events, Uuid::now_v7(), "test")
                .await
                .unwrap();
            work.volume(volume, command).await.unwrap();
            work.commit().await.unwrap();
            let error = service
                .request_vm_update(
                    fixture.organisation_id,
                    fixture.vm_id,
                    "account:owner",
                    fixture.request(),
                )
                .await
                .unwrap_err();
            assert!(matches!(
                error.downcast_ref::<vm::VmUpdateError>(),
                Some(vm::VmUpdateError::Blocked(_))
            ));
            assert!(rollout(&fixture.state).await.active.is_none());
        }
        if source.is_none() {
            fixture
                .state
                .volumes()
                .acknowledge(fixture.organisation_id, guest, app.row.app_id, volume)
                .await
                .unwrap();
        } else {
            let mut work = Work::begin(&fixture.state.events, Uuid::now_v7(), "test")
                .await
                .unwrap();
            work.volume(volume, VolumeCommand::FinalizeWithoutErasure { at })
                .await
                .unwrap();
            work.commit().await.unwrap();
        }
        let view = service
            .vm_update(fixture.organisation_id, fixture.vm_id)
            .await
            .unwrap();
        assert_eq!(view.eligible, source.is_none());
        assert!(rollout(&fixture.state).await.active.is_none());
    }
}

#[sqlx::test(migrations = false)]
async fn foreign_vm_requests_hide_existence_before_disabled_policy_or_invalid_keys(
    pool: sqlx::PgPool,
) {
    let mut fixture = ready_vm(pool).await;
    Arc::make_mut(&mut fixture.state.config).vm_updates_enabled = false;
    let foreign = Uuid::now_v7();
    let service = fixture.state.agent_updates();
    let mut request = fixture.request();
    request.idempotency_key = "invalid".into();
    let error = service
        .request_vm_update(foreign, fixture.vm_id, "account:foreign", request.clone())
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<vm::VmUpdateError>(),
        Some(vm::VmUpdateError::NotFound)
    ));
    let error = service.vm_update(foreign, fixture.vm_id).await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<vm::VmUpdateError>(),
        Some(vm::VmUpdateError::NotFound)
    ));
    let error = service
        .cancel_vm_update(
            foreign,
            fixture.vm_id,
            "account:foreign",
            Uuid::now_v7(),
            "invalid",
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<vm::VmUpdateError>(),
        Some(vm::VmUpdateError::NotFound)
    ));
    let error = service
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            request,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<vm::VmUpdateError>(),
        Some(vm::VmUpdateError::Invalid(_))
    ));
    let error = service
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            fixture.request(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<vm::VmUpdateError>(),
        Some(vm::VmUpdateError::Blocked(_))
    ));
    assert!(rollout(&fixture.state).await.active.is_none());
}

#[sqlx::test(migrations = false)]
async fn an_identical_vm_request_replays_its_published_operation_without_advancing_the_slot(
    pool: sqlx::PgPool,
) {
    use buffa::Message;

    let fixture = ready_vm(pool).await;
    let service = fixture.state.agent_updates();
    let request = fixture.request();
    let (first, concurrent_replay) = tokio::join!(
        service.request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            request.clone()
        ),
        service.request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            request.clone()
        ),
    );
    let first = first.unwrap();
    let concurrent_replay = concurrent_replay.unwrap();
    assert_eq!(concurrent_replay.attempt_id, first.attempt_id);
    assert_eq!(concurrent_replay.update_version, first.update_version);
    let before = rollout(&fixture.state).await;
    assert_eq!(before.attempt_sequence, 1);
    let attempt = before.active.as_ref().and_then(ActiveUpdate::vm).unwrap();
    assert_eq!(first.attempt_id, Some(attempt.id));
    assert_eq!(first.phase, "preparing");
    assert!(first.legacy_guest);
    assert!(first.can_cancel);
    let document = grund_store::agents::document(&fixture.state.pool, fixture.host.machine_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(document.generation, 1);
    assert_eq!(
        attempt.operation.document_generation,
        Some(document.generation)
    );
    let desired =
        grund_proto::grund::agent::v1::DesiredState::decode_from_slice(&document.payload).unwrap();
    let machine = desired
        .machines
        .iter()
        .find(|m| m.vm_id == fixture.vm_id.to_string())
        .unwrap();
    assert_eq!(
        machine.state.as_known(),
        Some(grund_proto::grund::agent::v1::VmDesiredState::VM_DESIRED_STATE_RUNNING)
    );
    assert_eq!(
        machine.update.as_option().unwrap().attempt_id,
        attempt.id.to_string()
    );
    let replay = service
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            request,
        )
        .await
        .unwrap();
    assert_eq!(replay.attempt_id, first.attempt_id);
    assert_eq!(replay.update_version, first.update_version);
    assert_eq!(rollout(&fixture.state).await, before);
    let unchanged = grund_store::agents::document(&fixture.state.pool, fixture.host.machine_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.generation, document.generation);
    assert_eq!(unchanged.payload, document.payload);
}

#[sqlx::test(migrations = false)]
async fn reusing_a_vm_request_key_for_different_input_conflicts_even_while_the_slot_is_busy(
    pool: sqlx::PgPool,
) {
    let fixture = ready_vm(pool).await;
    let service = fixture.state.agent_updates();
    let request = fixture.request();
    service
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            request.clone(),
        )
        .await
        .unwrap();
    let before = rollout(&fixture.state).await;
    for changed in [
        vm::VmUpdateRequest {
            expected_version: 1,
            ..request.clone()
        },
        vm::VmUpdateRequest {
            rootfs_sha256: "3".repeat(64),
            ..request.clone()
        },
    ] {
        let error = service
            .request_vm_update(
                fixture.organisation_id,
                fixture.vm_id,
                "account:owner",
                changed,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<vm::VmUpdateError>(),
            Some(vm::VmUpdateError::AlreadyExists)
        ));
        assert_eq!(rollout(&fixture.state).await, before);
    }
}

#[sqlx::test(migrations = false)]
async fn stale_vm_versions_or_unapproved_images_leave_the_update_slot_unreserved(
    pool: sqlx::PgPool,
) {
    let fixture = ready_vm(pool).await;
    let service = fixture.state.agent_updates();
    let before = rollout(&fixture.state).await;
    let request = fixture.request();
    for stale in [
        vm::VmUpdateRequest {
            expected_version: 1,
            ..request.clone()
        },
        vm::VmUpdateRequest {
            rootfs_sha256: "3".repeat(64),
            ..request.clone()
        },
    ] {
        let error = service
            .request_vm_update(
                fixture.organisation_id,
                fixture.vm_id,
                "account:owner",
                stale,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<vm::VmUpdateError>(),
            Some(vm::VmUpdateError::Stale)
        ));
        assert_eq!(rollout(&fixture.state).await, before);
    }
    let accepted = service
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            request,
        )
        .await
        .unwrap();
    assert!(accepted.attempt_id.is_some());
}

#[sqlx::test(migrations = false)]
async fn concurrent_vm_requests_reserve_one_slot_and_exclude_executable_offers(pool: sqlx::PgPool) {
    let fixture = ready_vm(pool).await;
    let service = fixture.state.agent_updates();
    let (first, second) = tokio::join!(
        service.request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:first",
            fixture.request()
        ),
        service.request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:second",
            fixture.request()
        ),
    );
    let (winner, loser) = match (first, second) {
        (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
        results => panic!("exactly one VM request must reserve the slot: {results:?}"),
    };
    assert!(matches!(
        loser.downcast_ref::<vm::VmUpdateError>(),
        Some(vm::VmUpdateError::Blocked(_))
    ));
    let occupied = rollout(&fixture.state).await;
    assert_eq!(occupied.attempt_sequence, 1);
    assert_eq!(
        occupied.active.as_ref().unwrap().id(),
        winner.attempt_id.unwrap()
    );
    let now = Utc::now();
    let mut work = Work::begin(&fixture.state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    let error = work
        .agent_updates(Command::Offer {
            attempt_id: Uuid::now_v7(),
            machine_id: fixture.host.machine_id,
            registration_key: fixture.host.registration_key.clone(),
            generation: occupied.generation,
            previous_revision: "a".repeat(40),
            at: now,
            expires_at: now + OFFER_TTL,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        grund_store::work::WorkError::AgentUpdates(
            grund_domain::agent_updates::Error::SlotOccupied
        )
    ));
    work.commit().await.unwrap();
    assert_eq!(rollout(&fixture.state).await, occupied);
}

#[sqlx::test(migrations = false)]
async fn an_expired_prepare_requests_bounded_cleanup_without_releasing_the_vm_slot(
    pool: sqlx::PgPool,
) {
    use grund_domain::agent_updates::vm as domain_vm;

    let fixture = ready_vm(pool).await;
    let service = fixture.state.agent_updates();
    service
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            fixture.request(),
        )
        .await
        .unwrap();
    let before = rollout(&fixture.state).await;
    let preparing = before.active.as_ref().and_then(ActiveUpdate::vm).unwrap();
    let now = preparing.offered_at + Duration::minutes(16);
    let mut work = Work::begin(
        &fixture.state.events,
        Uuid::now_v7(),
        "instance:agent-update-monitor",
    )
    .await
    .unwrap();
    vm::reconcile(&fixture.state, &mut work, now).await.unwrap();
    work.commit().await.unwrap();
    let after = rollout(&fixture.state).await;
    let cancelling = after.active.as_ref().and_then(ActiveUpdate::vm).unwrap();
    assert!(after.paused);
    assert_eq!(after.attempt_sequence, before.attempt_sequence);
    assert_eq!(cancelling.id, preparing.id);
    assert_eq!(cancelling.phase, domain_vm::Phase::Cancelling);
    assert_eq!(cancelling.failure, Some(domain_vm::Failure::Timeout));
    assert_eq!(cancelling.operation.action, domain_vm::Action::Rollback);
    assert_eq!(
        cancelling.operation.sequence,
        preparing.operation.sequence + 1
    );
    assert_ne!(
        cancelling.operation.launch_nonce,
        preparing.operation.launch_nonce
    );
    assert_eq!(cancelling.operation.deadline, now + Duration::minutes(5));
    assert!(cancelling.authorized_at.is_none());
    assert!(after.last_completed.is_none());
    let error = service
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            fixture.request(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<vm::VmUpdateError>(),
        Some(vm::VmUpdateError::Blocked(_))
    ));
    assert_eq!(rollout(&fixture.state).await, after);
}

#[sqlx::test(migrations = false)]
async fn cancellation_replays_one_cleanup_operation_while_disabled_and_rejects_key_repointing(
    pool: sqlx::PgPool,
) {
    use grund_domain::agent_updates::vm as domain_vm;

    let mut fixture = ready_vm(pool).await;
    let (other_guest, _) = registered_machine(
        &fixture.state,
        false,
        Some(fixture.organisation_id),
        "other-guest",
        [11; 32],
    )
    .await;
    let other_vm = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO grund_vms (vm_id,organisation_id,host_machine_id,name,vcpus,memory_mib,disk_gib, \
         kernel_url,kernel_sha256,rootfs_url,rootfs_sha256,state,machine_id,created_by) \
         SELECT $2,organisation_id,host_machine_id,'other-vm',vcpus,memory_mib,disk_gib, \
         kernel_url,kernel_sha256,rootfs_url,rootfs_sha256,state,$3,created_by \
         FROM grund_vms WHERE vm_id=$1",
    )
    .bind(fixture.vm_id)
    .bind(other_vm)
    .bind(other_guest.machine_id)
    .execute(&fixture.state.pool)
    .await
    .unwrap();
    let requested = fixture
        .state
        .agent_updates()
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            fixture.request(),
        )
        .await
        .unwrap();
    let attempt_id = requested.attempt_id.unwrap();
    let before = rollout(&fixture.state).await;
    let prepare = before.active.as_ref().and_then(ActiveUpdate::vm).unwrap();
    let initial_document =
        grund_store::agents::document(&fixture.state.pool, fixture.host.machine_id)
            .await
            .unwrap()
            .unwrap();
    Arc::make_mut(&mut fixture.state.config).vm_updates_enabled = false;
    let service = fixture.state.agent_updates();
    let key = Uuid::now_v7().to_string();
    let first = service
        .cancel_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            attempt_id,
            &key,
        )
        .await
        .unwrap();
    assert_eq!(first.attempt_id, Some(attempt_id));
    assert_eq!(first.phase, "cancelling");
    assert!(first.paused);
    assert!(!first.can_cancel);
    let cancelling = rollout(&fixture.state).await;
    let cleanup = cancelling
        .active
        .as_ref()
        .and_then(ActiveUpdate::vm)
        .unwrap();
    assert_eq!(cleanup.operation.action, domain_vm::Action::Rollback);
    assert_eq!(cleanup.operation.sequence, prepare.operation.sequence + 1);
    assert_ne!(
        cleanup.operation.launch_nonce,
        prepare.operation.launch_nonce
    );
    assert!(cleanup.authorized_at.is_none());
    assert!(cleanup.candidate_launch.is_none());
    assert_eq!(cancelling.attempt_sequence, before.attempt_sequence);
    assert!(cancelling.last_completed.is_none());
    let document = grund_store::agents::document(&fixture.state.pool, fixture.host.machine_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(document.generation, initial_document.generation + 1);
    assert_eq!(
        cleanup.operation.document_generation,
        Some(document.generation)
    );
    let replay = service
        .cancel_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            attempt_id,
            &key,
        )
        .await
        .unwrap();
    assert_eq!(replay.attempt_id, first.attempt_id);
    assert_eq!(replay.update_version, first.update_version);
    assert_eq!(rollout(&fixture.state).await, cancelling);
    for (vm_id, changed_attempt) in [(fixture.vm_id, Uuid::now_v7()), (other_vm, Uuid::now_v7())] {
        let error = service
            .cancel_vm_update(
                fixture.organisation_id,
                vm_id,
                "account:owner",
                changed_attempt,
                &key,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<vm::VmUpdateError>(),
            Some(vm::VmUpdateError::AlreadyExists)
        ));
        assert_eq!(rollout(&fixture.state).await, cancelling);
    }
    let unchanged = grund_store::agents::document(&fixture.state.pool, fixture.host.machine_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.generation, document.generation);
    assert_eq!(unchanged.payload, document.payload);
    let mut work =
        grund_store::work::Work::begin(&fixture.state.events, Uuid::now_v7(), "account:owner")
            .await
            .unwrap();
    work.agent_updates(grund_domain::agent_updates::Command::Vm(
        domain_vm::Command::HostAcknowledged {
            fence: cleanup.fence().unwrap(),
            evidence: domain_vm::HostEvidence::StagingCancelled {
                old_process: domain_vm::ProcessIdentity {
                    process_id: 123,
                    start_time_ticks: 1,
                    host_boot_id: Uuid::now_v7(),
                },
            },
            at: Utc::now(),
        },
    ))
    .await
    .unwrap();
    work.commit().await.unwrap();
    let terminal = service
        .cancel_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            attempt_id,
            &key,
        )
        .await
        .unwrap();
    assert_eq!(terminal.phase, "cancelled");
    let error = service
        .cancel_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            attempt_id,
            &Uuid::now_v7().to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<vm::VmUpdateError>(),
        Some(vm::VmUpdateError::Blocked(_))
    ));
    assert!(rollout(&fixture.state).await.active.is_none());
    Arc::make_mut(&mut fixture.state.config).vm_updates_enabled = true;
    let service = fixture.state.agent_updates();
    let before_resume = service
        .vm_update(fixture.organisation_id, fixture.vm_id)
        .await
        .unwrap();
    assert!(before_resume.paused);
    assert!(!before_resume.eligible);
    let mut work = Work::begin(
        &fixture.state.events,
        Uuid::now_v7(),
        "instance:local-admin",
    )
    .await
    .unwrap();
    work.agent_updates(grund_domain::agent_updates::Command::Resume { at: Utc::now() })
        .await
        .unwrap();
    work.commit().await.unwrap();
    let resumed = service
        .vm_update(fixture.organisation_id, fixture.vm_id)
        .await
        .unwrap();
    assert!(!resumed.paused);
    assert!(resumed.eligible);
    let mut retry = fixture.request();
    retry.expected_version = resumed.update_version;
    let retried = service
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            retry,
        )
        .await
        .unwrap();
    assert_ne!(retried.attempt_id, terminal.attempt_id);
    assert_eq!(retried.phase, "preparing");
    assert!(!retried.paused);
}

#[sqlx::test(migrations = false)]
async fn a_current_unready_guest_revokes_cached_health_before_commit(pool: sqlx::PgPool) {
    use crate::services::agents::AgentsState;
    use grund_domain::agent_updates::{Event, vm as domain_vm};

    let fixture = ready_vm(pool).await;
    fixture
        .state
        .agent_updates()
        .request_vm_update(
            fixture.organisation_id,
            fixture.vm_id,
            "account:owner",
            fixture.request(),
        )
        .await
        .unwrap();
    let mut attempt = rollout(&fixture.state)
        .await
        .active
        .as_ref()
        .and_then(ActiveUpdate::vm)
        .unwrap()
        .clone();
    let now = Utc::now();
    let host_boot_id = Uuid::now_v7();
    attempt.phase = domain_vm::Phase::CandidateRunning;
    attempt.authorized_at = Some(now);
    attempt.old_process = Some(domain_vm::ProcessIdentity {
        process_id: 10,
        start_time_ticks: 1,
        host_boot_id,
    });
    attempt.candidate_process = Some(domain_vm::ProcessIdentity {
        process_id: 11,
        start_time_ticks: 2,
        host_boot_id,
    });
    attempt.old_process_exited = true;
    attempt.root_fenced = true;
    attempt.operation.sequence = 3;
    attempt.operation.action = domain_vm::Action::StartCandidate;
    attempt.operation.launch_nonce = Uuid::now_v7();
    attempt.operation.document_generation = None;
    attempt.used_launch_nonces[1] = Some(Uuid::now_v7());
    attempt.used_launch_nonces[2] = Some(attempt.operation.launch_nonce);
    record_update_events(
        &fixture.state,
        vec![Event::VmTransitioned { attempt, at: now }],
    )
    .await;
    fixture
        .state
        .agents()
        .publish(fixture.host.machine_id)
        .await
        .unwrap();
    let mut work = Work::begin(&fixture.state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    vm::reconcile(&fixture.state, &mut work, Utc::now())
        .await
        .unwrap();
    work.commit().await.unwrap();
    let attempt = rollout(&fixture.state)
        .await
        .active
        .as_ref()
        .and_then(ActiveUpdate::vm)
        .unwrap()
        .clone();
    let launch = attempt.candidate_launch.as_ref().unwrap();
    fixture
        .state
        .agents()
        .publish(attempt.guest_machine_id)
        .await
        .unwrap();
    let guest_document =
        grund_store::agents::document(&fixture.state.pool, attempt.guest_machine_id)
            .await
            .unwrap()
            .unwrap();
    let proof = domain_vm::GuestBootProof {
        guest_machine_id: attempt.guest_machine_id,
        guest_registration_key: attempt.guest_registration_key.clone(),
        attempt_id: attempt.id,
        attempt_sequence: attempt.sequence,
        launch_sequence: launch.sequence,
        launch_nonce: launch.launch_nonce,
        document_generation: launch.document_generation.unwrap(),
        guest_document_generation: guest_document.generation,
        current_guest_document_generation: guest_document.generation,
        os_boot_id: Uuid::now_v7(),
        pid1_context: launch.launch_nonce,
        image: attempt.target.identity(),
        runtime_ready: true,
        cpu_probe: true,
        memory_probe: true,
        attachment_probe: true,
        probe_failed: false,
        observed_at: Utc::now(),
    };
    let mut work = Work::begin(&fixture.state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    work.agent_updates(grund_domain::agent_updates::Command::Vm(
        domain_vm::Command::VerifyGuest {
            attempt_id: attempt.id,
            proof,
            at: Utc::now(),
        },
    ))
    .await
    .unwrap();
    work.commit().await.unwrap();
    grund_store::agents::heartbeat(
        &fixture.state.pool,
        attempt.guest_machine_id,
        "test",
        &serde_json::json!({"arch":"x86_64"}),
        Utc::now(),
    )
    .await
    .unwrap();
    grund_store::agents::record_runtime_heartbeat(
        &fixture.state.pool,
        attempt.guest_machine_id,
        &grund_store::agents::RuntimeHeartbeat {
            registration_key: attempt.guest_registration_key.clone(),
            signed_at: Utc::now(),
            runtime_ready: false,
            guest_boot: None,
        },
    )
    .await
    .unwrap();
    let mut work = Work::begin(&fixture.state.events, Uuid::now_v7(), "test")
        .await
        .unwrap();
    vm::reconcile(&fixture.state, &mut work, Utc::now())
        .await
        .unwrap();
    work.commit().await.unwrap();
    let after = rollout(&fixture.state).await;
    let active = after.active.as_ref().and_then(ActiveUpdate::vm).unwrap();
    assert_eq!(active.phase, domain_vm::Phase::Verifying);
    assert_eq!(active.operation.action, domain_vm::Action::StartCandidate);
    assert_eq!(active.operation.sequence, launch.sequence);
    assert!(active.guest_boot_proof.is_none());
    assert!(active.committed_at.is_none());
}
