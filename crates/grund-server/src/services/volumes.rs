//! Volume decisions use the app's transaction and mire stream lock; the
//! customer machine alone performs physical creation and managed-dir erasure.
use crate::{services::agents::AgentsState, state::State};
use chrono::Utc;
use grund_domain::{
    app::spec::VolumeSpec,
    volume::{VolumeCommand, VolumeError},
};
use grund_store::{
    volumes::{self, VolumeRow},
    work::Work,
};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum VolumesError {
    #[error("no such volume of this app")]
    NotFound,
    #[error("a volume named {0} already exists with another source")]
    SourceChanged(String),
    #[error("the volume changed; read it again before changing it")]
    Conflict,
    #[error(
        "another replica may still write this volume; stop and fence it before changing attachment"
    )]
    WriterPresent,
    #[error(
        "volumes on another machine cannot be moved automatically; restore into a new volume instead"
    )]
    MachineChanged,
    #[error("only an own machine of this app's organisation can hold a volume")]
    InvalidMachine,
    #[error("{0}")]
    Invalid(String),
    #[error("a restored volume cannot be mounted until its exact recovery point has been verified")]
    RestoreNotReady,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Clone)]
pub struct Volumes {
    state: State,
}
pub trait VolumesState {
    fn volumes(&self) -> Volumes;
}
impl VolumesState for State {
    fn volumes(&self) -> Volumes {
        Volumes {
            state: self.clone(),
        }
    }
}

impl Volumes {
    pub async fn list(&self, org: Uuid, app: Uuid) -> Result<Vec<VolumeRow>, VolumesError> {
        Ok(volumes::app_volumes(&self.state.pool, org, app)
            .await
            .map_err(anyhow::Error::from)?)
    }
    pub async fn get(
        &self,
        org: Uuid,
        app: Uuid,
        volume_id: Uuid,
    ) -> Result<VolumeRow, VolumesError> {
        volumes::volume(&self.state.pool, org, app, volume_id)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(VolumesError::NotFound)
    }
    /// Resolve a release's names in the app scope; absent names remain owned
    /// and untouched. The caller co-commits these events with ReleaseCreated.
    pub async fn resolve_release_in(
        &self,
        work: &mut Work<'_>,
        org: Uuid,
        app: Uuid,
        specs: &[VolumeSpec],
    ) -> Result<(), VolumesError> {
        for spec in specs {
            let existing = volumes::by_name(&mut **work.sql(), org, app, &spec.name)
                .await
                .map_err(anyhow::Error::from)?;
            let id = existing.as_ref().map_or_else(
                || Uuid::new_v5(&app, spec.name.as_bytes()),
                |row| row.volume_id,
            );
            if existing
                .as_ref()
                .is_some_and(|row| row.source != spec.source)
            {
                return Err(VolumesError::SourceChanged(spec.name.clone()));
            }
            if existing.as_ref().is_some_and(|row| {
                matches!(
                    row.status.as_str(),
                    "pending_deletion" | "deleting" | "deleted"
                )
            }) {
                return Err(VolumesError::Invalid(
                    "a deleted volume name cannot be reused in this app".into(),
                ));
            }
            if let Some(row) = &existing {
                self.restore_ready(work.sql(), org, app, row).await?;
            }
            work.volume(
                id,
                VolumeCommand::Request {
                    organisation_id: org,
                    app_id: app,
                    name: spec.name.clone(),
                    path: spec.path.clone(),
                    source: spec.source.clone(),
                    backup: spec.backup,
                    at: Utc::now(),
                },
            )
            .await
            .map_err(volume_work)?;
        }
        Ok(())
    }
    /// Bind all volumes in this release to its sole machine under the same
    /// placement decision. Existing placement is immutable in M1.
    pub async fn place_release_in(
        &self,
        work: &mut Work<'_>,
        org: Uuid,
        app: Uuid,
        machine: Uuid,
        specs: &[VolumeSpec],
    ) -> Result<(), VolumesError> {
        for spec in specs {
            let row = volumes::by_name(&mut **work.sql(), org, app, &spec.name)
                .await
                .map_err(anyhow::Error::from)?
                .ok_or(VolumesError::NotFound)?;
            self.restore_ready(work.sql(), org, app, &row).await?;
            work.volume(
                row.volume_id,
                VolumeCommand::Place {
                    machine_id: machine,
                    at: Utc::now(),
                },
            )
            .await
            .map_err(volume_work)?;
            work.volume(
                row.volume_id,
                VolumeCommand::Attach {
                    machine_id: machine,
                    path: spec.path.clone(),
                    at: Utc::now(),
                },
            )
            .await
            .map_err(volume_work)?;
        }
        Ok(())
    }
    async fn restore_ready(
        &self,
        conn: &mut sqlx::PgConnection,
        org: Uuid,
        app: Uuid,
        row: &VolumeRow,
    ) -> Result<(), VolumesError> {
        if let Some((attempt, _)) = volumes::restore_status(conn, org, app, row.volume_id)
            .await
            .map_err(anyhow::Error::from)?
            && (attempt != "completed" || row.status == "requested")
        {
            return Err(VolumesError::RestoreNotReady);
        }
        Ok(())
    }

    /// App deletion and ALL owned volume delete requests share a transaction.
    pub async fn delete_app_in(
        &self,
        work: &mut Work<'_>,
        org: Uuid,
        app: Uuid,
        purge_after: chrono::DateTime<Utc>,
    ) -> Result<Vec<Uuid>, VolumesError> {
        let rows = volumes::app_volumes(&mut **work.sql(), org, app)
            .await
            .map_err(anyhow::Error::from)?;
        let mut machines = Vec::new();
        for row in rows {
            work.volume(
                row.volume_id,
                VolumeCommand::Delete {
                    at: Utc::now(),
                    purge_after,
                },
            )
            .await
            .map_err(volume_work)?;
            if let Some(machine) = row.machine_id {
                machines.push(machine);
            }
        }
        Ok(machines)
    }
    pub async fn create(
        &self,
        actor: Uuid,
        org: Uuid,
        app: Uuid,
        spec: VolumeSpec,
        key: &str,
        hash: &[u8],
    ) -> Result<VolumeRow, VolumesError> {
        let spec = validate_spec(spec)?;
        let id = Uuid::new_v5(&app, spec.name.as_bytes());
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string())
            .await
            .map_err(volume_work)?;
        let owner = work.load_app(app).await.map_err(volume_work)?;
        if !owner.exists || owner.deleted || owner.organisation_id != org {
            return Err(VolumesError::NotFound);
        }
        match volumes::reserve_receipt(work.sql(), org, app, key, "create_volume", hash, id)
            .await
            .map_err(anyhow::Error::from)?
        {
            volumes::Receipt::Conflict => return Err(VolumesError::Conflict),
            volumes::Receipt::Existing(existing) => {
                return volumes::volume(&mut **work.sql(), org, app, existing)
                    .await
                    .map_err(anyhow::Error::from)?
                    .ok_or(VolumesError::NotFound);
            }
            volumes::Receipt::New => {}
        }
        if owner.settings.copies != 1 {
            return Err(VolumesError::Invalid(
                "an app with volumes has exactly one copy".into(),
            ));
        }
        self.resolve_release_in(&mut work, org, app, std::slice::from_ref(&spec))
            .await?;
        work.commit().await.map_err(volume_work)?;
        self.get(org, app, id).await
    }
    /// The API requires both the expected version and the precise app owner.
    pub async fn mutate(
        &self,
        actor: Uuid,
        org: Uuid,
        app: Uuid,
        id: Uuid,
        version: i64,
        operation: Operation,
    ) -> Result<VolumeRow, VolumesError> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string())
            .await
            .map_err(volume_work)?;
        let owner = work.load_app(app).await.map_err(volume_work)?;
        if !owner.exists || owner.deleted || owner.organisation_id != org {
            return Err(VolumesError::NotFound);
        }
        let row = volumes::volume(&mut **work.sql(), org, app, id)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(VolumesError::NotFound)?;
        if row.stream_version != version {
            return Err(VolumesError::Conflict);
        }
        let active_writer: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM grund_replicas r \
             JOIN grund_releases rel ON rel.app_id = r.app_id AND rel.number = r.release \
             WHERE r.organisation_id = $1 AND r.app_id = $2 \
             AND COALESCE(rel.spec->'volumes', '[]'::jsonb) @> jsonb_build_array(jsonb_build_object('name', $3::text)))"
        ).bind(org).bind(app).bind(&row.name).fetch_one(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
        if active_writer && matches!(operation, Operation::Detach | Operation::Delete) {
            return Err(VolumesError::WriterPresent);
        }
        let command = match operation {
            Operation::Attach(machine) => {
                self.restore_ready(work.sql(), org, app, &row).await?;
                let eligible: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM grund_machines m JOIN grund_machine_presence p ON p.machine_id = m.machine_id WHERE m.machine_id = $1 AND m.pool_organisation_id = $2 AND m.state = 'active' AND m.pool <> 'management' AND m.minted_by LIKE 'account:%' AND m.cordoned_at IS NULL AND p.capabilities->>'volumes' = 'true')")
                    .bind(machine).bind(org).fetch_one(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
                if !eligible {
                    return Err(VolumesError::InvalidMachine);
                }
                let others = volumes::app_volumes(&mut **work.sql(), org, app)
                    .await
                    .map_err(anyhow::Error::from)?;
                if others.iter().any(|other| {
                    other.volume_id != id
                        && other.status == "attached"
                        && other.machine_id.is_some_and(|pinned| pinned != machine)
                }) {
                    return Err(VolumesError::MachineChanged);
                }
                VolumeCommand::Attach {
                    machine_id: machine,
                    path: row.path.clone(),
                    at: Utc::now(),
                }
            }
            Operation::Detach => VolumeCommand::Detach { at: Utc::now() },
            Operation::Delete => {
                let at: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                    .fetch_one(&mut **work.sql())
                    .await
                    .map_err(anyhow::Error::from)?;
                VolumeCommand::Delete {
                    at,
                    purge_after: at
                        + chrono::Duration::from_std(self.state.config.volume_delete_window)
                            .map_err(anyhow::Error::from)?,
                }
            }
        };
        if matches!(operation, Operation::Delete) {
            sqlx::query("DELETE FROM grund_volume_backup_attempts WHERE organisation_id = $1 AND app_id = $2 AND volume_id = $3 AND status IN ('pending','leased')")
                .bind(org).bind(app).bind(id).execute(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
        }
        work.volume(id, command).await.map_err(volume_work)?;
        if let Some(machine) = row.machine_id.or(match operation {
            Operation::Attach(machine) => Some(machine),
            _ => None,
        }) {
            self.state.agents().publish_in(work.sql(), machine).await?;
        }
        work.commit().await.map_err(volume_work)?;
        self.state.wakes.documents_changed();
        volumes::all_app_volumes(&self.state.pool, org, app)
            .await
            .map_err(anyhow::Error::from)?
            .into_iter()
            .find(|v| v.volume_id == id)
            .ok_or(VolumesError::NotFound)
    }
    /// Re-activates an app-owned volume while its pending-deletion deadline holds.
    pub async fn restore(
        &self,
        actor: Uuid,
        org: Uuid,
        app: Uuid,
        id: Uuid,
        version: i64,
    ) -> Result<VolumeRow, VolumesError> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string())
            .await
            .map_err(volume_work)?;
        let owner = work.load_app(app).await.map_err(volume_work)?;
        if !owner.exists || owner.deleted || owner.organisation_id != org {
            return Err(VolumesError::NotFound);
        }
        let row = volumes::volume(&mut **work.sql(), org, app, id)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(VolumesError::NotFound)?;
        if row.stream_version != version {
            return Err(VolumesError::Conflict);
        }
        let at: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **work.sql())
            .await
            .map_err(anyhow::Error::from)?;
        if row.status != "pending_deletion" || !row.purge_after.is_some_and(|due| at < due) {
            return Err(VolumesError::NotFound);
        }
        work.volume(id, VolumeCommand::Restore { at })
            .await
            .map_err(volume_work)?;
        if let Some(machine) = row.machine_id {
            self.state.agents().publish_in(work.sql(), machine).await?;
        }
        work.commit().await.map_err(volume_work)?;
        self.state.wakes.documents_changed();
        self.get(org, app, id).await
    }
    /// A bounded purge pass uses an injectable instant so expiry boundaries can
    /// be exercised deterministically; production supplies PostgreSQL time.
    pub async fn purge_due(&self, at: chrono::DateTime<Utc>) -> Result<usize, VolumesError> {
        let due: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
            "SELECT organisation_id, app_id, volume_id FROM grund_volumes \
             WHERE status = 'pending_deletion' AND purge_after <= $1 \
             ORDER BY purge_after, volume_id LIMIT 100",
        )
        .bind(at)
        .fetch_all(&self.state.pool)
        .await
        .map_err(anyhow::Error::from)?;
        let mut count = 0;
        for (org, app, id) in due {
            let mut work = Work::begin(&self.state.events, Uuid::now_v7(), "grund/purge")
                .await
                .map_err(volume_work)?;
            let state = work.load_volume(id).await.map_err(volume_work)?;
            if state.organisation_id != Some(org)
                || state.app_id != Some(app)
                || !state.purge_after.is_some_and(|due| at >= due)
                || state.status != Some(grund_domain::volume::VolumeStatus::PendingDeletion)
            {
                continue;
            }
            let row = volumes::volume(&mut **work.sql(), org, app, id)
                .await
                .map_err(anyhow::Error::from)?
                .ok_or(VolumesError::NotFound)?;
            work.volume(id, VolumeCommand::Purge { at })
                .await
                .map_err(volume_work)?;
            sqlx::query("DELETE FROM grund_volume_backup_attempts WHERE organisation_id = $1 AND app_id = $2 AND volume_id = $3")
                .bind(org).bind(app).bind(id).execute(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
            sqlx::query("DELETE FROM grund_volume_backup_points WHERE organisation_id = $1 AND app_id = $2 AND volume_id = $3")
                .bind(org).bind(app).bind(id).execute(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
            sqlx::query("DELETE FROM grund_volume_backup_configs WHERE organisation_id = $1 AND app_id = $2 AND volume_id = $3")
                .bind(org).bind(app).bind(id).execute(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
            if row.source.is_some() || row.machine_id.is_none() {
                work.volume(id, VolumeCommand::FinalizeWithoutErasure { at })
                    .await
                    .map_err(volume_work)?;
            }
            if let Some(machine) = row.machine_id {
                self.state.agents().publish_in(work.sql(), machine).await?;
            }
            work.commit().await.map_err(volume_work)?;
            count += 1;
        }
        if count > 0 {
            self.state.wakes.documents_changed();
        }
        Ok(count)
    }
    /// An authenticated machine acknowledges only its own pending erasure.
    pub async fn acknowledge(
        &self,
        org: Uuid,
        machine: Uuid,
        app: Uuid,
        id: Uuid,
    ) -> Result<(), VolumesError> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), "grund/agent")
            .await
            .map_err(volume_work)?;
        if !volumes::pending_ack(&mut **work.sql(), org, machine, app, id)
            .await
            .map_err(anyhow::Error::from)?
        {
            return Ok(());
        }
        work.volume(
            id,
            VolumeCommand::ConfirmDeleted {
                machine_id: machine,
                at: Utc::now(),
            },
        )
        .await
        .map_err(volume_work)?;
        self.state.agents().publish_in(work.sql(), machine).await?;
        work.commit().await.map_err(volume_work)?;
        self.state.wakes.documents_changed();
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub enum Operation {
    Attach(Uuid),
    Detach,
    Delete,
}

fn volume_work(error: grund_store::work::WorkError) -> VolumesError {
    match error {
        grund_store::work::WorkError::Volume(VolumeError::SourceChanged) => {
            VolumesError::SourceChanged("volume".into())
        }
        grund_store::work::WorkError::Volume(VolumeError::Deleting) => VolumesError::Conflict,
        grund_store::work::WorkError::Volume(VolumeError::MachineChanged) => {
            VolumesError::MachineChanged
        }
        grund_store::work::WorkError::Volume(
            VolumeError::WriterPresent | VolumeError::Attached,
        ) => VolumesError::WriterPresent,
        grund_store::work::WorkError::Volume(VolumeError::NotFound | VolumeError::WrongOwner) => {
            VolumesError::NotFound
        }
        other => VolumesError::Internal(other.into()),
    }
}

fn validate_spec(spec: VolumeSpec) -> Result<VolumeSpec, VolumesError> {
    if grund_domain::app::AppName::parse(&spec.name).map_or(true, |name| name.as_str() != spec.name)
    {
        return Err(VolumesError::Invalid(
            "volume name must be 1-32 lowercase letters, digits or single hyphens".into(),
        ));
    }
    let safe_path = |path: &str| {
        path.len() <= 4096
            && path.starts_with('/')
            && path != "/"
            && !path.bytes().any(|b| b.is_ascii_control())
            && path
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != "..")
    };
    if !safe_path(&spec.path) {
        return Err(VolumesError::Invalid(
            "mount path must be a canonical absolute directory".into(),
        ));
    }
    if spec
        .source
        .as_ref()
        .is_some_and(|source| !safe_path(source))
    {
        return Err(VolumesError::Invalid(
            "existing source must be a canonical absolute host directory".into(),
        ));
    }
    Ok(spec)
}
