//! Stack ownership, immutable bundle revisions and durable ordered operations.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use grund_config::app::spec::AppSettings;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::Release;

/// One stable service identity and the exact app release selected by a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub app_id: Uuid,
    pub app_name: String,
    pub release: Release,
    pub settings: AppSettings,
    pub depends_on: Vec<String>,
    pub exclusive: bool,
    pub template: Option<String>,
}

impl Service {
    /// Resolves restart executions without substituting a different pinned secret set.
    pub fn execution_release(
        &self,
        name: &str,
        operation: Option<&Operation>,
        app: &crate::app::App,
    ) -> u32 {
        if let Some(operation) = operation {
            if let Some(number) = operation.releases.get(name) {
                return *number;
            }
            if operation.order.iter().any(|service| service == name) {
                return self.release.number;
            }
        }
        app.current_release
            .filter(|number| {
                app.release(*number).is_some_and(|release| {
                    release.spec == self.release.spec
                        && release.image_digest == self.release.image_digest
                        && release.secret_versions == self.release.secret_versions
                })
            })
            .unwrap_or(self.release.number)
    }
}

/// An immutable complete desired bundle; values of secrets are never included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    pub number: u32,
    pub yaml: String,
    pub services: BTreeMap<String, Service>,
    pub public_service: Option<String>,
    pub public_port: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub rollback_of: Option<u32>,
}

/// Durable customer-visible operation categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Deploy,
    Restart,
    Rollback,
    Delete,
    Restore,
}

/// A service transition waits for real receipts before advancing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    #[default]
    Pending,
    Applying,
    Stopping,
}

/// The bounded cursor and immutable identity of a committed operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub id: Uuid,
    pub kind: Kind,
    pub target_revision: u32,
    pub previous_revision: u32,
    pub order: Vec<String>,
    pub cursor: usize,
    pub step: Step,
    pub started_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    pub compensating: bool,
    pub failure: Option<String>,
    #[serde(default)]
    pub releases: BTreeMap<String, u32>,
    #[serde(default)]
    pub halting: bool,
}

/// Stack status does not imply simultaneous process or database changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    NonExistent,
    Waiting,
    Deploying,
    Ready,
    Degraded,
    RollingBack,
    Halted,
    Deleting,
    Deleted,
}

impl Status {
    /// The stable CLI/API status, without implementation details.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NonExistent => "non_existent",
            Self::Waiting => "waiting",
            Self::Deploying => "deploying",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::RollingBack => "rolling_back",
            Self::Halted => "halted",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
        }
    }
}

/// One aggregate owns every service's app identity throughout recovery retention.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stack {
    pub exists: bool,
    pub organisation_id: Uuid,
    pub name: String,
    pub revisions: BTreeMap<u32, Revision>,
    pub desired_revision: u32,
    pub applied_revision: u32,
    pub machine_id: Option<Uuid>,
    pub operation: Option<Operation>,
    pub status: Status,
    pub failure: Option<String>,
    pub purge_after: Option<DateTime<Utc>>,
}

/// Past-tense facts contain only definitions and opaque pinned secret versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-stack")]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    Created {
        organisation_id: Uuid,
        name: String,
    },
    RevisionRequested {
        revision: Revision,
        operation: Operation,
    },
    OperationRequested {
        operation: Operation,
    },
    OperationAdvanced {
        operation: Operation,
        status: Status,
        machine_id: Option<Uuid>,
        failure: Option<String>,
    },
    OperationCompleted {
        applied_revision: u32,
        status: Status,
        purge_after: Option<DateTime<Utc>>,
        failure: Option<String>,
    },
    HealthChanged {
        status: Status,
    },
}

impl mire::Aggregate for Stack {
    type Event = Event;

    fn stream_category() -> &'static str {
        "grund-stack"
    }

    fn apply(&mut self, event: &Event) {
        match event {
            Event::Created {
                organisation_id,
                name,
            } => {
                self.exists = true;
                self.organisation_id = *organisation_id;
                self.name.clone_from(name);
                self.status = Status::Waiting;
            }
            Event::RevisionRequested {
                revision,
                operation,
            } => {
                self.desired_revision = revision.number;
                self.revisions.insert(revision.number, revision.clone());
                self.operation = Some(operation.clone());
                self.status = if operation.kind == Kind::Rollback {
                    Status::RollingBack
                } else {
                    Status::Waiting
                };
                self.failure = None;
            }
            Event::OperationRequested { operation } => {
                self.status = match operation.kind {
                    Kind::Delete => Status::Deleting,
                    Kind::Rollback => Status::RollingBack,
                    _ => Status::Waiting,
                };
                self.operation = Some(operation.clone());
                self.failure = None;
            }
            Event::OperationAdvanced {
                operation,
                status,
                machine_id,
                failure,
            } => {
                self.operation = Some(operation.clone());
                self.status = *status;
                self.machine_id = *machine_id;
                self.failure.clone_from(failure);
            }
            Event::OperationCompleted {
                applied_revision,
                status,
                purge_after,
                failure,
            } => {
                self.applied_revision = *applied_revision;
                self.operation = None;
                self.status = *status;
                self.purge_after = *purge_after;
                self.failure.clone_from(failure);
                if *status == Status::Deleted {
                    self.machine_id = None;
                }
            }
            Event::HealthChanged { status } => self.status = *status,
        }
    }
}

impl mire::Snapshot for Stack {
    const SNAPSHOT_VERSION: i32 = 1;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

/// Commands serialize lifecycle intent; deletion may supersede unfinished work.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    Create {
        organisation_id: Uuid,
        name: String,
    },
    Revise {
        revision: Revision,
        operation: Operation,
    },
    Operate {
        operation: Operation,
        at: DateTime<Utc>,
    },
    Compensate {
        operation_id: Uuid,
        revision: Revision,
        operation: Operation,
    },
    Advance {
        operation: Operation,
        status: Status,
        machine_id: Option<Uuid>,
        failure: Option<String>,
    },
    Complete {
        operation_id: Uuid,
        applied_revision: u32,
        status: Status,
        purge_after: Option<DateTime<Utc>>,
        failure: Option<String>,
    },
    Health {
        status: Status,
    },
}

/// Stable lifecycle refusal categories.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("no such stack")]
    NotFound,
    #[error("stack already exists")]
    Exists,
    #[error("another stack operation is active")]
    Busy,
    #[error("stack operation changed")]
    Conflict,
    #[error("stack cannot perform that transition")]
    Invalid,
}

impl mire::Command for Command {
    type Aggregate = Stack;
    type Error = Error;
    type Events = Vec<Event>;

    fn handle(self, state: &Stack) -> Result<Vec<Event>, Error> {
        if let Self::Create {
            organisation_id,
            name,
        } = self
        {
            return if state.exists {
                Err(Error::Exists)
            } else {
                Ok(vec![Event::Created {
                    organisation_id,
                    name,
                }])
            };
        }
        if !state.exists {
            return Err(Error::NotFound);
        }
        match self {
            Self::Create { .. } => Err(Error::Invalid),
            Self::Revise {
                revision,
                operation,
            } => {
                if state.operation.is_some() {
                    return Err(Error::Busy);
                }
                if state.status == Status::Deleted
                    || revision.number != state.desired_revision + 1
                    || operation.target_revision != revision.number
                    || revision.services.is_empty()
                    || revision.services.len() > 10
                {
                    return Err(Error::Invalid);
                }
                for (name, service) in &revision.services {
                    if state
                        .revisions
                        .values()
                        .filter_map(|r| r.services.get(name))
                        .any(|old| old.app_id != service.app_id)
                    {
                        return Err(Error::Invalid);
                    }
                }
                Ok(vec![Event::RevisionRequested {
                    revision,
                    operation,
                }])
            }
            Self::Compensate {
                operation_id,
                revision,
                operation,
            } => {
                if state
                    .operation
                    .as_ref()
                    .is_none_or(|o| o.id != operation_id)
                    || operation.id != operation_id
                {
                    return Err(Error::Conflict);
                }
                if !operation.compensating
                    || revision.number != state.desired_revision + 1
                    || revision.number != operation.target_revision
                    || revision.services.is_empty()
                    || revision.services.len() > 10
                {
                    return Err(Error::Invalid);
                }
                Ok(vec![Event::RevisionRequested {
                    revision,
                    operation,
                }])
            }
            Self::Operate { operation, at } => {
                if state.operation.as_ref().is_some_and(|current| {
                    operation.kind != Kind::Delete || current.id == operation.id
                }) {
                    return Err(Error::Busy);
                }
                if operation.kind == Kind::Restore {
                    if state.status != Status::Deleted
                        || !state.purge_after.is_some_and(|due| at < due)
                    {
                        return Err(Error::NotFound);
                    }
                } else if state.status == Status::Deleted {
                    return Err(Error::NotFound);
                }
                Ok(vec![Event::OperationRequested { operation }])
            }
            Self::Advance {
                operation,
                status,
                machine_id,
                failure,
            } => {
                let current = state.operation.as_ref().ok_or(Error::Conflict)?;
                if current.id != operation.id {
                    return Err(Error::Conflict);
                }
                if current == &operation
                    && state.status == status
                    && state.machine_id == machine_id
                    && state.failure == failure
                {
                    return Ok(vec![]);
                }
                Ok(vec![Event::OperationAdvanced {
                    operation,
                    status,
                    machine_id,
                    failure,
                }])
            }
            Self::Complete {
                operation_id,
                applied_revision,
                status,
                purge_after,
                failure,
            } => {
                if state
                    .operation
                    .as_ref()
                    .is_none_or(|o| o.id != operation_id)
                {
                    return Err(Error::Conflict);
                }
                Ok(vec![Event::OperationCompleted {
                    applied_revision,
                    status,
                    purge_after,
                    failure,
                }])
            }
            Self::Health { status } => {
                if state.operation.is_some()
                    || !matches!(status, Status::Ready | Status::Degraded)
                    || !matches!(state.status, Status::Ready | Status::Degraded)
                {
                    return Err(Error::Invalid);
                }
                Ok(if state.status == status {
                    vec![]
                } else {
                    vec![Event::HealthChanged { status }]
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mire::{Aggregate, Command as _};

    #[test]
    fn an_expired_deleted_stack_cannot_be_restored() {
        let at = DateTime::from_timestamp(1_000, 0).unwrap();
        let state = Stack {
            exists: true,
            status: Status::Deleted,
            purge_after: Some(at),
            ..Stack::default()
        };
        let operation = Operation {
            id: Uuid::nil(),
            kind: Kind::Restore,
            target_revision: 1,
            previous_revision: 1,
            order: vec![],
            cursor: 0,
            step: Step::Pending,
            started_at: at,
            deadline: at,
            compensating: false,
            failure: None,
            releases: BTreeMap::new(),
            halting: false,
        };
        assert_eq!(
            Command::Operate { operation, at }.handle(&state),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn deletion_supersedes_every_active_non_delete_and_fences_its_worker() {
        let at = DateTime::from_timestamp(1_000, 0).unwrap();
        for kind in [Kind::Deploy, Kind::Restart, Kind::Rollback, Kind::Restore] {
            for status in [Status::Waiting, Status::Deploying, Status::RollingBack] {
                let former = Operation {
                    id: Uuid::from_u128(1),
                    kind,
                    target_revision: 2,
                    previous_revision: 1,
                    order: vec!["consumer".into(), "producer".into()],
                    cursor: 0,
                    step: Step::Applying,
                    started_at: at,
                    deadline: at + chrono::Duration::minutes(30),
                    compensating: false,
                    failure: None,
                    releases: BTreeMap::new(),
                    halting: false,
                };
                let mut deletion = former.clone();
                deletion.id = Uuid::from_u128(2);
                deletion.kind = Kind::Delete;
                deletion.step = Step::Pending;
                let mut state = Stack {
                    exists: true,
                    status,
                    operation: Some(former.clone()),
                    ..Stack::default()
                };
                for event in (Command::Operate {
                    operation: deletion.clone(),
                    at,
                })
                .handle(&state)
                .unwrap()
                {
                    state.apply(&event);
                }
                assert_eq!(state.status, Status::Deleting);
                assert_eq!(state.operation.as_ref(), Some(&deletion));
                assert_eq!(
                    Command::Advance {
                        operation: former.clone(),
                        status: Status::Ready,
                        machine_id: None,
                        failure: None,
                    }
                    .handle(&state),
                    Err(Error::Conflict)
                );
                assert_eq!(
                    Command::Complete {
                        operation_id: former.id,
                        applied_revision: 2,
                        status: Status::Ready,
                        purge_after: None,
                        failure: None,
                    }
                    .handle(&state),
                    Err(Error::Conflict)
                );
                assert_eq!(
                    Command::Compensate {
                        operation_id: former.id,
                        revision: Revision {
                            number: 3,
                            yaml: String::new(),
                            services: BTreeMap::new(),
                            public_service: None,
                            public_port: None,
                            created_at: at,
                            created_by: Uuid::nil(),
                            rollback_of: Some(1),
                        },
                        operation: former,
                    }
                    .handle(&state),
                    Err(Error::Conflict)
                );
                assert_eq!(
                    Command::Operate {
                        operation: deletion,
                        at,
                    }
                    .handle(&state),
                    Err(Error::Busy)
                );
            }
        }
    }

    #[test]
    fn a_fresh_deletion_supersedes_a_timed_out_deletion_without_unfencing_its_worker() {
        let at = DateTime::from_timestamp(1_000, 0).unwrap();
        let expired = Operation {
            id: Uuid::from_u128(1),
            kind: Kind::Delete,
            target_revision: 1,
            previous_revision: 1,
            order: vec!["consumer".into(), "producer".into()],
            cursor: 1,
            step: Step::Stopping,
            started_at: at,
            deadline: at,
            compensating: false,
            failure: Some("operation_deadline".into()),
            releases: BTreeMap::new(),
            halting: false,
        };
        let mut retry = expired.clone();
        retry.id = Uuid::from_u128(2);
        retry.cursor = 0;
        retry.step = Step::Pending;
        retry.failure = None;
        retry.deadline = at + chrono::Duration::minutes(30);
        let mut state = Stack {
            exists: true,
            status: Status::Deleting,
            operation: Some(expired.clone()),
            failure: expired.failure.clone(),
            ..Stack::default()
        };
        for event in (Command::Operate {
            operation: retry.clone(),
            at,
        })
        .handle(&state)
        .unwrap()
        {
            state.apply(&event);
        }
        assert_eq!(state.status, Status::Deleting);
        assert!(state.failure.is_none());
        assert_eq!(state.operation.as_ref(), Some(&retry));
        assert_eq!(
            Command::Advance {
                operation: expired,
                status: Status::Deleting,
                machine_id: None,
                failure: Some("operation_deadline".into()),
            }
            .handle(&state),
            Err(Error::Conflict)
        );
    }

    #[test]
    fn a_stale_worker_cannot_complete_a_new_operation() {
        let at = DateTime::from_timestamp(1_000, 0).unwrap();
        let operation = Operation {
            id: Uuid::from_u128(1),
            kind: Kind::Delete,
            target_revision: 1,
            previous_revision: 1,
            order: vec![],
            cursor: 0,
            step: Step::Pending,
            started_at: at,
            deadline: at,
            compensating: false,
            failure: None,
            releases: BTreeMap::new(),
            halting: false,
        };
        let state = Stack {
            exists: true,
            operation: Some(operation),
            ..Stack::default()
        };
        assert_eq!(
            Command::Complete {
                operation_id: Uuid::from_u128(2),
                applied_revision: 1,
                status: Status::Deleted,
                purge_after: Some(at),
                failure: None
            }
            .handle(&state),
            Err(Error::Conflict)
        );
        let mut replay = Stack::default();
        replay.apply(&Event::Created {
            organisation_id: Uuid::nil(),
            name: "shop".into(),
        });
        assert_eq!(
            serde_json::from_str::<Stack>(&serde_json::to_string(&replay).unwrap()).unwrap(),
            replay
        );
    }
}
