//! The unit of work: one transaction that records events, applies their read
//! models and writes whatever plain rows go with them, committed once
//! (skills `event-sourcing` §4, DECISIONS D-7).
//!
//! A command is decided purely (`mire::Command::handle`), its events are
//! recorded and saved, and each event is projected at its stream version, all
//! before the commit. Aggregates load from their latest snapshot after an
//! explicit row lock, so writers to one stream queue instead of conflicting.
//! Snapshots are written after the commit, best-effort: a failed snapshot costs
//! a longer load later, never the write that triggered it.

use grund_domain::{
    account::{Account, AccountCommand, AccountError, AccountEvent},
    agent_updates::{
        ActiveUpdate, AgentUpdates, Command as AgentUpdatesCommand, Error as AgentUpdatesError,
        Event as AgentUpdatesEvent, rollout_id, vm,
    },
    app::{App, AppCommand, AppError, AppEvent},
    custom_domain::{Domain, DomainCommand, DomainError, DomainEvent},
    machine::{Machine, MachineCommand, MachineError, MachineEvent},
    organisation::{Organisation, OrganisationCommand, OrganisationError, OrganisationEvent},
    stack::{Command as StackCommand, Error as StackError, Event as StackEvent, Stack},
    volume::{Volume, VolumeCommand, VolumeError, VolumeEvent},
};
use mire::{AggregateRoot, EventMetadata, EventStore, EventStoreError, Snapshot, TransactionScope};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::projections;

/// Why a unit of work failed.
#[derive(Debug, thiserror::Error)]
pub enum WorkError {
    #[error(transparent)]
    Account(#[from] AccountError),
    #[error(transparent)]
    AgentUpdates(#[from] AgentUpdatesError),
    #[error(transparent)]
    Organisation(#[from] OrganisationError),
    #[error(transparent)]
    Machine(#[from] MachineError),
    #[error(transparent)]
    App(#[from] AppError),
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Volume(#[from] VolumeError),
    #[error(transparent)]
    Stack(#[from] StackError),
    #[error("event store: {0}")]
    Events(#[from] EventStoreError),
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
}

impl WorkError {
    /// The unique index this write collided with, when that is the failure.
    pub fn unique_violation(&self) -> Option<String> {
        let database = match self {
            WorkError::Database(error) => error.as_database_error(),
            WorkError::Events(EventStoreError::Database(error)) => error.as_database_error(),
            _ => None,
        }?;
        (database.code().as_deref() == Some("23505"))
            .then(|| database.constraint().unwrap_or_default().to_string())
    }
}

enum Touched {
    Account(Uuid, Account, i64, i64),
    AgentUpdates(Uuid, Box<AgentUpdates>, i64, i64),
    Organisation(Uuid, Organisation, i64, i64),
    Machine(Uuid, Machine, i64, i64),
    App(Uuid, App, i64, i64),
    Domain(Uuid, Domain, i64, i64),
    Volume(Uuid, Volume, i64, i64),
    Stack(Uuid, Stack, i64, i64),
}

/// A transaction spanning the event log, the read models and plain tables.
pub struct Work<'a> {
    store: &'a EventStore,
    scope: TransactionScope<'a>,
    metadata: EventMetadata,
    touched: Vec<Touched>,
    stack_owner: Option<Uuid>,
}

impl<'a> Work<'a> {
    /// Opens a transaction. `correlation_id` (usually the request id) and
    /// `actor` are recorded as metadata on every event.
    pub async fn begin(
        store: &'a EventStore,
        correlation_id: Uuid,
        actor: &str,
    ) -> Result<Self, WorkError> {
        Ok(Self {
            store,
            scope: store.begin_transaction().await?,
            metadata: EventMetadata {
                correlation_id: Some(correlation_id),
                causation_id: None,
                actor: Some(actor.to_string()),
            },
            touched: Vec::new(),
            stack_owner: None,
        })
    }

    /// Decides `command` against the account's current state, then records,
    /// saves and projects the events it produced. Returns those events; none
    /// means the command was already satisfied.
    pub async fn account(
        &mut self,
        account_id: Uuid,
        command: AccountCommand,
    ) -> Result<Vec<AccountEvent>, WorkError> {
        let mut root = self.load::<Account>(account_id).await?;
        let base = root.version;
        let events = mire::Command::handle(command, &root.state)?;
        if events.is_empty() {
            return Ok(events);
        }
        root.set_metadata(self.metadata.clone());
        root.record_many(events.clone());
        self.scope.save(&mut root).await?;
        for (offset, event) in events.iter().enumerate() {
            projections::apply_account(
                account_id,
                base + 1 + offset as i64,
                event,
                self.scope.tx(),
            )
            .await?;
        }
        self.touched
            .push(Touched::Account(account_id, root.state, base, root.version));
        Ok(events)
    }

    /// As [`Work::account`], for an organisation.
    pub async fn organisation(
        &mut self,
        organisation_id: Uuid,
        command: OrganisationCommand,
    ) -> Result<Vec<OrganisationEvent>, WorkError> {
        let mut root = self.load::<Organisation>(organisation_id).await?;
        let base = root.version;
        let events = mire::Command::handle(command, &root.state)?;
        if events.is_empty() {
            return Ok(events);
        }
        root.set_metadata(self.metadata.clone());
        root.record_many(events.clone());
        self.scope.save(&mut root).await?;
        for (offset, event) in events.iter().enumerate() {
            projections::apply_organisation(
                organisation_id,
                base + 1 + offset as i64,
                event,
                self.scope.tx(),
            )
            .await?;
        }
        self.touched.push(Touched::Organisation(
            organisation_id,
            root.state,
            base,
            root.version,
        ));
        Ok(events)
    }

    /// As [`Work::account`], for a machine.
    pub async fn machine(
        &mut self,
        machine_id: Uuid,
        command: MachineCommand,
    ) -> Result<Vec<MachineEvent>, WorkError> {
        let lifecycle_at = match &command {
            MachineCommand::Register { .. }
            | MachineCommand::DeclarePorts { .. }
            | MachineCommand::SetLabels { .. } => None,
            MachineCommand::Lease { at, .. }
            | MachineCommand::EndLease { at, .. }
            | MachineCommand::Reregister { at, .. }
            | MachineCommand::LinkProvider { at, .. }
            | MachineCommand::Revoke { at, .. }
            | MachineCommand::SetInService { at, .. } => Some(*at),
        };
        if let Some(at) = lifecycle_at {
            self.guard_machine_update(machine_id, at).await?;
        }
        self.persist_machine(machine_id, command).await
    }

    async fn persist_machine(
        &mut self,
        machine_id: Uuid,
        command: MachineCommand,
    ) -> Result<Vec<MachineEvent>, WorkError> {
        let mut root = self.load::<Machine>(machine_id).await?;
        let base = root.version;
        let events = mire::Command::handle(command, &root.state)?;
        if events.is_empty() {
            return Ok(events);
        }
        root.set_metadata(self.metadata.clone());
        root.record_many(events.clone());
        self.scope.save(&mut root).await?;
        for (offset, event) in events.iter().enumerate() {
            projections::apply_machine(
                machine_id,
                base + 1 + offset as i64,
                event,
                self.scope.tx(),
            )
            .await?;
        }
        self.touched
            .push(Touched::Machine(machine_id, root.state, base, root.version));
        Ok(events)
    }

    /// As [`Work::account`], for an app.
    pub async fn app(
        &mut self,
        app_id: Uuid,
        command: AppCommand,
    ) -> Result<Vec<AppEvent>, WorkError> {
        let (events, ()) = self
            .app_decide(app_id, |app| {
                mire::Command::handle(command, app).map(|events| (events, ()))
            })
            .await?;
        Ok(events)
    }

    /// Loads the app under its stream lock, lets `decide` choose the events
    /// from its current state (a pure decision, such as the reconciler's),
    /// then records, saves and projects them. `decide` also returns whatever
    /// else it found, for the caller.
    pub async fn app_decide<T>(
        &mut self,
        app_id: Uuid,
        decide: impl FnOnce(&App) -> Result<(Vec<AppEvent>, T), AppError>,
    ) -> Result<(Vec<AppEvent>, T), WorkError> {
        let mut root = self.load::<App>(app_id).await?;
        if let Some(stack_id) = root.state.stack_owner
            && Some(stack_id) != self.stack_owner
        {
            return Err(AppError::StackOwned { stack_id }.into());
        }
        let base = root.version;
        let (events, found) = decide(&root.state)?;
        if events.is_empty() {
            return Ok((events, found));
        }
        root.set_metadata(self.metadata.clone());
        root.record_many(events.clone());
        self.scope.save(&mut root).await?;
        for (offset, event) in events.iter().enumerate() {
            crate::apps::apply_app(app_id, base + 1 + offset as i64, event, self.scope.tx())
                .await?;
        }
        self.touched
            .push(Touched::App(app_id, root.state, base, root.version));
        Ok((events, found))
    }

    /// Authorizes child decisions only for this explicitly selected owning stack.
    pub fn allow_stack(&mut self, stack_id: Uuid) {
        self.stack_owner = Some(stack_id);
    }

    /// Loads the owning stack under its stream lock.
    pub async fn load_stack(&mut self, id: Uuid) -> Result<Stack, WorkError> {
        Ok(self.load::<Stack>(id).await?.state)
    }

    /// Records and projects a stack decision in the same transaction as its apps.
    pub async fn stack(
        &mut self,
        id: Uuid,
        command: StackCommand,
    ) -> Result<Vec<StackEvent>, WorkError> {
        let mut root = self.load::<Stack>(id).await?;
        let base = root.version;
        let events = mire::Command::handle(command, &root.state)?;
        if events.is_empty() {
            return Ok(events);
        }
        root.set_metadata(self.metadata.clone());
        root.record_many(events.clone());
        self.scope.save(&mut root).await?;
        for (offset, event) in events.iter().enumerate() {
            crate::stacks::apply(id, base + 1 + offset as i64, event, self.scope.tx()).await?;
        }
        self.touched
            .push(Touched::Stack(id, root.state, base, root.version));
        Ok(events)
    }

    /// Records and projects a volume decision in this app's transaction.
    pub async fn volume(
        &mut self,
        volume_id: Uuid,
        command: VolumeCommand,
    ) -> Result<Vec<VolumeEvent>, WorkError> {
        let mut root = self.load::<Volume>(volume_id).await?;
        let base = root.version;
        let events = mire::Command::handle(command, &root.state)?;
        if events.is_empty() {
            return Ok(events);
        }
        root.set_metadata(self.metadata.clone());
        root.record_many(events.clone());
        self.scope.save(&mut root).await?;
        for (offset, event) in events.iter().enumerate() {
            crate::volumes::apply_volume(
                volume_id,
                base + 1 + offset as i64,
                event,
                self.scope.tx(),
            )
            .await?;
        }
        self.touched
            .push(Touched::Volume(volume_id, root.state, base, root.version));
        Ok(events)
    }

    pub async fn load_volume(&mut self, volume_id: Uuid) -> Result<Volume, WorkError> {
        Ok(self.load::<Volume>(volume_id).await?.state)
    }

    /// As [`Work::account`], for a custom domain.
    pub async fn domain(
        &mut self,
        domain_id: Uuid,
        command: DomainCommand,
    ) -> Result<Vec<DomainEvent>, WorkError> {
        let mut root = self.load::<Domain>(domain_id).await?;
        let base = root.version;
        let events = mire::Command::handle(command, &root.state)?;
        if events.is_empty() {
            return Ok(events);
        }
        root.set_metadata(self.metadata.clone());
        root.record_many(events.clone());
        self.scope.save(&mut root).await?;
        for (offset, event) in events.iter().enumerate() {
            crate::domains::apply_domain(
                domain_id,
                base + 1 + offset as i64,
                event,
                self.scope.tx(),
            )
            .await?;
        }
        self.touched
            .push(Touched::Domain(domain_id, root.state, base, root.version));
        Ok(events)
    }

    /// The organisation's state, under its stream lock, without recording
    /// anything.
    pub async fn load_organisation(
        &mut self,
        organisation_id: Uuid,
    ) -> Result<Organisation, WorkError> {
        Ok(self.load::<Organisation>(organisation_id).await?.state)
    }

    /// The domain's state, under its stream lock, without recording
    /// anything.
    pub async fn load_domain(&mut self, domain_id: Uuid) -> Result<Domain, WorkError> {
        Ok(self.load::<Domain>(domain_id).await?.state)
    }

    /// The app's state, under its stream lock, without recording anything.
    pub async fn load_app(&mut self, app_id: Uuid) -> Result<App, WorkError> {
        Ok(self.load::<App>(app_id).await?.state)
    }
    /// Serializes a lifecycle or provider migration against executable replacement.
    pub async fn guard_machine_update(
        &mut self,
        machine_id: Uuid,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), WorkError> {
        let rollout = self.load_agent_updates().await?;
        if let Some(attempt) = rollout
            .active
            .filter(|attempt| attempt.owns_machine(machine_id))
        {
            if attempt.authorized() {
                return Err(AgentUpdatesError::LifecycleBlocked.into());
            }
            let Some(attempt) = attempt.executable() else {
                return Err(AgentUpdatesError::VmUpdateConflict.into());
            };
            self.agent_updates(AgentUpdatesCommand::Cancel {
                fence: attempt.fence(),
                at,
            })
            .await?;
        }
        Ok(())
    }

    /// Only the captured guest of this prepared VM attempt may be cordoned.
    /// This does not authorize quiesce or bypass another lifecycle guard.
    pub async fn cordon_for_vm_update(&mut self, attempt_id: Uuid) -> Result<(), WorkError> {
        let rollout = self.load_agent_updates().await?;
        let attempt = rollout
            .active
            .as_ref()
            .and_then(ActiveUpdate::vm)
            .filter(|a| {
                a.id == attempt_id && matches!(a.phase, vm::Phase::Prepared | vm::Phase::Draining)
            })
            .ok_or(AgentUpdatesError::StaleFence)?;
        if rollout.paused {
            return Err(AgentUpdatesError::Paused.into());
        }
        let id = attempt.guest_machine_id;
        self.persist_machine(
            id,
            MachineCommand::SetInService {
                actor: attempt_id,
                organisation_id: attempt.organisation_id,
                in_service: false,
                at: chrono::Utc::now(),
            },
        )
        .await?;
        Ok(())
    }

    /// Loads the singleton after an advisory lock that also serializes creation.
    pub async fn load_agent_updates(&mut self) -> Result<AgentUpdates, WorkError> {
        Ok(self.load_agent_updates_root().await?.state)
    }

    async fn load_agent_updates_root(&mut self) -> Result<AggregateRoot<AgentUpdates>, WorkError> {
        sqlx::query("SELECT pg_advisory_xact_lock(7428173965021841::bigint)")
            .execute(&mut **self.scope.tx())
            .await?;
        self.load::<AgentUpdates>(rollout_id()).await
    }

    /// Decides and projects an implicit singleton command in this transaction.
    pub async fn agent_updates(
        &mut self,
        command: AgentUpdatesCommand,
    ) -> Result<Vec<AgentUpdatesEvent>, WorkError> {
        let mut root = self.load_agent_updates_root().await?;
        if let AgentUpdatesCommand::Vm(vm::Command::Request { request, .. }) = &command {
            if let Some(receipt) = self
                .completed_vm_update_request(request.organisation_id, &request.request_hash)
                .await?
            {
                return if receipt.fingerprint == request.fingerprint
                    && receipt.vm_id == request.vm_id
                {
                    Ok(vec![])
                } else {
                    Err(AgentUpdatesError::RequestConflict.into())
                };
            }
            let replay = root
                .state
                .active
                .as_ref()
                .and_then(ActiveUpdate::vm)
                .is_some_and(|a| a.request_hash == request.request_hash);
            if !replay {
                let host = sqlx::query_scalar::<_, Uuid>(
                    "SELECT host_machine_id FROM grund_vms WHERE vm_id = $1 AND organisation_id = $2",
                ).bind(request.vm_id).bind(request.organisation_id)
                    .fetch_optional(&mut **self.scope.tx()).await?;
                if host != Some(request.host_machine_id) {
                    return Err(AgentUpdatesError::StaleFence.into());
                }
                crate::agents::lock_generation(self.scope.tx(), request.host_machine_id).await?;
                let version = sqlx::query_scalar::<_, i64>(
                    "SELECT update_stream_version FROM grund_vms \
                     WHERE vm_id = $1 AND organisation_id = $2 FOR UPDATE",
                )
                .bind(request.vm_id)
                .bind(request.organisation_id)
                .fetch_optional(&mut **self.scope.tx())
                .await?;
                if version != Some(request.expected_update_version) {
                    return Err(AgentUpdatesError::StaleFence.into());
                }
            }
        }
        if matches!(&command, AgentUpdatesCommand::Vm(_))
            && let Some(attempt) = root.state.active.as_ref().and_then(ActiveUpdate::vm)
        {
            crate::agents::lock_generation(self.scope.tx(), attempt.host_machine_id).await?;
        }
        let base = root.version;
        let drain_attempt = match &command {
            AgentUpdatesCommand::Vm(vm::Command::BeginDrain { attempt_id, .. }) => {
                Some(*attempt_id)
            }
            _ => None,
        };
        let events = mire::Command::handle(command, &root.state)?;
        if events.is_empty() {
            return Ok(events);
        }
        if let Some(attempt_id) = drain_attempt {
            self.cordon_for_vm_update(attempt_id).await?;
        }
        root.set_metadata(self.metadata.clone());
        root.record_many(events.clone());
        self.scope.save(&mut root).await?;
        for (offset, event) in events.iter().enumerate() {
            crate::agent_updates::apply_agent_updates(
                base + 1 + offset as i64,
                event,
                self.scope.tx(),
            )
            .await?;
        }
        for event in &events {
            if let AgentUpdatesEvent::VmCompleted { attempt, at } = event {
                self.persist_machine(
                    attempt.guest_machine_id,
                    MachineCommand::SetInService {
                        actor: attempt.id,
                        organisation_id: attempt.organisation_id,
                        in_service: attempt.original_in_service,
                        at: *at,
                    },
                )
                .await?;
            }
        }
        self.touched.push(Touched::AgentUpdates(
            rollout_id(),
            Box::new(root.state),
            base,
            root.version,
        ));
        Ok(events)
    }

    /// Records disposable health evidence in the caller's heartbeat transaction.
    pub async fn record_update_observation(
        &mut self,
        machine_id: Uuid,
        registration_key: &str,
        boot_id: Uuid,
        revision: &str,
        ready: bool,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), WorkError> {
        crate::agent_updates::record_update_observation(
            self.scope.tx(),
            machine_id,
            registration_key,
            boot_id,
            revision,
            ready,
            at,
        )
        .await?;
        Ok(())
    }

    /// Reads the latest independently observed heartbeat inside this transaction.
    pub async fn update_observation(
        &mut self,
        machine_id: Uuid,
    ) -> Result<Option<crate::agent_updates::UpdateObservation>, WorkError> {
        Ok(crate::agent_updates::update_observation(&mut **self.scope.tx(), machine_id).await?)
    }

    /// Replays a terminal attempt after newer machines have completed.
    pub async fn completed_update_attempt(
        &mut self,
        attempt_id: Uuid,
    ) -> Result<Option<grund_domain::agent_updates::Attempt>, WorkError> {
        Ok(
            crate::agent_updates::completed_update_attempt(&mut **self.scope.tx(), attempt_id)
                .await?,
        )
    }

    pub async fn completed_vm_update_attempt(
        &mut self,
        organisation_id: Uuid,
        attempt_id: Uuid,
    ) -> Result<Option<vm::VmAttempt>, WorkError> {
        Ok(crate::agent_updates::completed_vm_update_attempt(
            &mut **self.scope.tx(),
            organisation_id,
            attempt_id,
        )
        .await?)
    }

    pub async fn completed_vm_update_request(
        &mut self,
        organisation_id: Uuid,
        request_hash: &str,
    ) -> Result<Option<vm::VmAttempt>, WorkError> {
        Ok(crate::agent_updates::completed_vm_update_request(
            &mut **self.scope.tx(),
            organisation_id,
            request_hash,
        )
        .await?)
    }

    async fn load<A: Snapshot>(&mut self, id: Uuid) -> Result<AggregateRoot<A>, WorkError> {
        let id = id.to_string();
        let stream_id = format!("{}-{id}", A::stream_category());
        sqlx::query("SELECT 1 FROM es_streams WHERE stream_id = $1 FOR UPDATE")
            .bind(&stream_id)
            .execute(&mut **self.scope.tx())
            .await?;
        Ok(match self.scope.load_snapshotted::<A>(&id).await? {
            Some(root) => root,
            None => AggregateRoot::new(&id),
        })
    }

    /// The transaction, for the plain rows that commit with the events.
    pub fn sql(&mut self) -> &mut Transaction<'static, Postgres> {
        self.scope.tx()
    }

    /// The event transaction, so extensions can record their aggregates and
    /// inline projections atomically with core machine and app decisions.
    pub fn scope(&mut self) -> &mut TransactionScope<'a> {
        &mut self.scope
    }

    /// Whether this transaction recorded changes through its core aggregate methods.
    pub fn has_changes(&self) -> bool {
        !self.touched.is_empty()
    }

    /// Commits, then snapshots every aggregate whose version crossed a
    /// snapshot boundary, in the background.
    pub async fn commit(self) -> Result<(), WorkError> {
        let Work {
            store,
            scope,
            touched,
            ..
        } = self;
        scope.commit().await?;
        for touched in touched {
            match touched {
                Touched::Account(id, state, before, after) => {
                    snapshot::<Account>(store, id, state, before, after)
                }
                Touched::AgentUpdates(id, state, before, after) => {
                    snapshot::<AgentUpdates>(store, id, *state, before, after)
                }
                Touched::Organisation(id, state, before, after) => {
                    snapshot::<Organisation>(store, id, state, before, after)
                }
                Touched::Machine(id, state, before, after) => {
                    snapshot::<Machine>(store, id, state, before, after)
                }
                Touched::App(id, state, before, after) => {
                    snapshot::<App>(store, id, state, before, after)
                }
                Touched::Domain(id, state, before, after) => {
                    snapshot::<Domain>(store, id, state, before, after)
                }
                Touched::Volume(id, state, before, after) => {
                    snapshot::<Volume>(store, id, state, before, after)
                }
                Touched::Stack(id, state, before, after) => {
                    snapshot::<Stack>(store, id, state, before, after)
                }
            }
        }
        Ok(())
    }
}

fn snapshot<A: Snapshot + 'static>(store: &EventStore, id: Uuid, state: A, before: i64, after: i64)
where
    A::Event: Send,
{
    let frequency = A::SNAPSHOT_FREQUENCY;
    if frequency <= 0 || after / frequency <= before / frequency {
        return;
    }
    let store = store.clone();
    tokio::spawn(async move {
        let stream_id = format!("{}-{id}", A::stream_category());
        let root = AggregateRoot::from_snapshot(stream_id, state, after);
        if let Err(error) = store.save_snapshot(&root).await {
            tracing::warn!(error = %error, "snapshot failed; the next load replays more events");
        }
    });
}
