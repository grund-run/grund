//! App-owned volume identities and their auditable attachment/deletion lifecycle.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const VOLUME_CATEGORY: &str = "grund-volume";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeStatus {
    Requested,
    Available,
    Attached,
    Deleting,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-volume")]
pub enum VolumeEvent {
    Requested {
        organisation_id: Uuid,
        app_id: Uuid,
        name: String,
        path: String,
        source: Option<String>,
        backup: bool,
        requested_at: DateTime<Utc>,
    },
    RestoreReserved {
        machine_id: Uuid,
        reserved_at: DateTime<Utc>,
    },
    Placed {
        machine_id: Uuid,
        placed_at: DateTime<Utc>,
    },
    Attached {
        machine_id: Uuid,
        path: String,
        attached_at: DateTime<Utc>,
    },
    Detached {
        detached_at: DateTime<Utc>,
    },
    BackupPolicySet {
        backup: bool,
        set_at: DateTime<Utc>,
    },
    DeleteRequested {
        machine_id: Option<Uuid>,
        requested_at: DateTime<Utc>,
    },
    Deleted {
        deleted_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Volume {
    pub organisation_id: Option<Uuid>,
    pub app_id: Option<Uuid>,
    pub name: String,
    pub path: String,
    pub source: Option<String>,
    pub backup: bool,
    pub machine_id: Option<Uuid>,
    pub status: Option<VolumeStatus>,
    pub requested_at: Option<DateTime<Utc>>,
}

impl mire::Aggregate for Volume {
    type Event = VolumeEvent;
    fn stream_category() -> &'static str {
        VOLUME_CATEGORY
    }
    fn apply(&mut self, event: &Self::Event) {
        match event {
            VolumeEvent::Requested {
                organisation_id,
                app_id,
                name,
                path,
                source,
                backup,
                requested_at,
            } => {
                self.organisation_id = Some(*organisation_id);
                self.app_id = Some(*app_id);
                self.name = name.clone();
                self.path = path.clone();
                self.source = source.clone();
                self.backup = *backup;
                self.requested_at = Some(*requested_at);
                self.status = Some(VolumeStatus::Requested);
            }
            VolumeEvent::RestoreReserved { machine_id, .. } => self.machine_id = Some(*machine_id),
            VolumeEvent::Placed { machine_id, .. } => {
                self.machine_id = Some(*machine_id);
                self.status = Some(VolumeStatus::Available);
            }
            VolumeEvent::Attached {
                machine_id, path, ..
            } => {
                self.machine_id = Some(*machine_id);
                self.path = path.clone();
                self.status = Some(VolumeStatus::Attached);
            }
            VolumeEvent::Detached { .. } => self.status = Some(VolumeStatus::Available),
            VolumeEvent::BackupPolicySet { backup, .. } => self.backup = *backup,
            VolumeEvent::DeleteRequested { .. } => self.status = Some(VolumeStatus::Deleting),
            VolumeEvent::Deleted { .. } => self.status = Some(VolumeStatus::Deleted),
        }
    }
}

impl mire::Snapshot for Volume {
    const SNAPSHOT_VERSION: i32 = 1;
    const SNAPSHOT_FREQUENCY: i64 = 100;
}

#[derive(Debug, Clone)]
pub enum VolumeCommand {
    Request {
        organisation_id: Uuid,
        app_id: Uuid,
        name: String,
        path: String,
        source: Option<String>,
        backup: bool,
        at: DateTime<Utc>,
    },
    ReserveRestore {
        machine_id: Uuid,
        at: DateTime<Utc>,
    },
    Place {
        machine_id: Uuid,
        at: DateTime<Utc>,
    },
    Attach {
        machine_id: Uuid,
        path: String,
        at: DateTime<Utc>,
    },
    Detach {
        at: DateTime<Utc>,
    },
    Delete {
        at: DateTime<Utc>,
    },
    FinalizeWithoutErasure {
        at: DateTime<Utc>,
    },
    ConfirmDeleted {
        machine_id: Uuid,
        at: DateTime<Utc>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("volume does not exist for this app")]
    NotFound,
    #[error("volume already exists with another source")]
    SourceChanged,
    #[error("volume belongs to another app")]
    WrongOwner,
    #[error("volume is being deleted")]
    Deleting,
    #[error("volume is attached to another machine; stop and fence its writer first")]
    WriterPresent,
    #[error(
        "volume is already placed on another machine; restore into a new app-owned volume to recover"
    )]
    MachineChanged,
    #[error("volume must be detached first")]
    Attached,
    #[error("volume deletion was not requested on this machine")]
    InvalidAcknowledgement,
}

impl mire::Command for VolumeCommand {
    type Aggregate = Volume;
    type Error = VolumeError;
    type Events = Vec<VolumeEvent>;
    fn handle(self, state: &Volume) -> Result<Self::Events, Self::Error> {
        use VolumeCommand as C;
        use VolumeEvent as E;
        use VolumeStatus as S;
        Ok(match self {
            C::Request {
                organisation_id,
                app_id,
                name,
                path,
                source,
                backup,
                at,
            } => {
                if let Some(status) = state.status {
                    if status == S::Deleting || status == S::Deleted {
                        return Err(VolumeError::Deleting);
                    }
                    if state.organisation_id != Some(organisation_id)
                        || state.app_id != Some(app_id)
                        || state.name != name
                    {
                        return Err(VolumeError::WrongOwner);
                    }
                    if state.source != source {
                        return Err(VolumeError::SourceChanged);
                    }
                    if state.backup != backup {
                        vec![E::BackupPolicySet { backup, set_at: at }]
                    } else {
                        vec![]
                    }
                } else {
                    vec![E::Requested {
                        organisation_id,
                        app_id,
                        name,
                        path,
                        source,
                        backup,
                        requested_at: at,
                    }]
                }
            }
            C::ReserveRestore { machine_id, at } => match (state.status, state.machine_id) {
                (Some(S::Requested), None) => vec![E::RestoreReserved {
                    machine_id,
                    reserved_at: at,
                }],
                (Some(S::Requested), Some(existing)) if existing == machine_id => vec![],
                _ => return Err(VolumeError::MachineChanged),
            },
            C::Place { machine_id, at } => match (state.status, state.machine_id) {
                (None | Some(S::Deleting | S::Deleted), _) => return Err(VolumeError::Deleting),
                (_, Some(existing)) if existing != machine_id => {
                    return Err(VolumeError::MachineChanged);
                }
                (Some(S::Requested), _) => vec![E::Placed {
                    machine_id,
                    placed_at: at,
                }],
                _ => vec![],
            },
            C::Attach {
                machine_id,
                path,
                at,
            } => match (state.status, state.machine_id) {
                (None, _) => return Err(VolumeError::NotFound),
                (Some(S::Deleting | S::Deleted), _) => return Err(VolumeError::Deleting),
                (_, Some(existing)) if existing != machine_id => {
                    return Err(VolumeError::MachineChanged);
                }
                (Some(S::Attached), _) if state.path != path => vec![E::Attached {
                    machine_id,
                    path,
                    attached_at: at,
                }],
                (Some(S::Attached), _) => vec![],
                _ => vec![E::Attached {
                    machine_id,
                    path,
                    attached_at: at,
                }],
            },
            C::Detach { at } => match state.status {
                None => return Err(VolumeError::NotFound),
                Some(S::Deleting | S::Deleted) => return Err(VolumeError::Deleting),
                Some(S::Attached) => vec![E::Detached { detached_at: at }],
                _ => vec![],
            },
            C::Delete { at } => match state.status {
                None => return Err(VolumeError::NotFound),
                Some(S::Deleting | S::Deleted) => vec![],
                _ => vec![E::DeleteRequested {
                    machine_id: state.machine_id,
                    requested_at: at,
                }],
            },
            C::FinalizeWithoutErasure { at } => match state.status {
                Some(S::Deleted) => vec![],
                Some(S::Deleting) if state.machine_id.is_none() || state.source.is_some() => {
                    vec![E::Deleted { deleted_at: at }]
                }
                _ => return Err(VolumeError::InvalidAcknowledgement),
            },
            C::ConfirmDeleted { machine_id, at } => match state.status {
                Some(S::Deleted) => vec![],
                Some(S::Deleting)
                    if state.machine_id == Some(machine_id) && state.source.is_none() =>
                {
                    vec![E::Deleted { deleted_at: at }]
                }
                _ => return Err(VolumeError::InvalidAcknowledgement),
            },
        })
    }
}
