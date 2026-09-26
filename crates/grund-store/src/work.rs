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
    organisation::{Organisation, OrganisationCommand, OrganisationError, OrganisationEvent},
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
    Organisation(#[from] OrganisationError),
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
    Organisation(Uuid, Organisation, i64, i64),
}

/// A transaction spanning the event log, the read models and plain tables.
pub struct Work<'a> {
    store: &'a EventStore,
    scope: TransactionScope<'a>,
    metadata: EventMetadata,
    touched: Vec<Touched>,
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
                Touched::Organisation(id, state, before, after) => {
                    snapshot::<Organisation>(store, id, state, before, after)
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
