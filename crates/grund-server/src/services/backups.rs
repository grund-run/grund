//! Per-volume encrypted S3 backup config and durable machine-scoped work.
//! The instance secret is part of the recovery set: back it up separately
//! from PostgreSQL and the bucket. Operators with this key can decrypt data.

use std::time::Duration;

use anyhow::{Context, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use grund_domain::{app::spec::VolumeSpec, volume::VolumeCommand};
use grund_proto::grund::agent::v1::{BackupOperation, BackupWork};
use grund_store::{
    backup::{self, BackupConfig, RecoveryPoint},
    volumes::{self, Receipt},
    work::Work,
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use uuid::Uuid;

use crate::{
    services::{agents::AgentsState, volumes::VolumesState},
    state::State,
};

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("no such backup or app-owned volume")]
    NotFound,
    #[error("backup destination version changed")]
    Conflict,
    #[error("this volume is not an attached, managed, backup-requested volume")]
    Ineligible,
    #[error("invalid backup destination: {0}")]
    Invalid(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct BackupView {
    pub enabled: bool,
    pub endpoint: String,
    pub bucket: String,
    pub next_due: Option<DateTime<Utc>>,
    pub last_verified: Option<DateTime<Utc>>,
    pub version: i64,
    pub last_error: Option<String>,
}

#[derive(Clone)]
pub struct Backups {
    state: State,
}
pub trait BackupsState {
    fn backups(&self) -> Backups;
}
impl BackupsState for State {
    fn backups(&self) -> Backups {
        Backups {
            state: self.clone(),
        }
    }
}

fn key(state: &State) -> LessSafeKey {
    let key = state.secret.derive("volume-backups");
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).expect("32-byte backup sealing key"))
}

fn associated(org: Uuid, app: Uuid, volume: Uuid, version: i64, field: &str) -> Vec<u8> {
    format!("grund-volume-backup-v1\n{org}\n{app}\n{volume}\n{version}\n{field}").into_bytes()
}

fn seal(
    key: &LessSafeKey,
    org: Uuid,
    app: Uuid,
    volume: Uuid,
    version: i64,
    field: &str,
    plain: &str,
) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("operating system random generator");
    let mut out = nonce.to_vec();
    let mut ciphertext = plain.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(associated(org, app, volume, version, field)),
        &mut ciphertext,
    )
    .expect("AES-GCM sealing within supported size");
    out.extend_from_slice(&ciphertext);
    out
}

fn open(
    key: &LessSafeKey,
    c: &BackupConfig,
    field: &str,
    ciphertext: &[u8],
) -> anyhow::Result<String> {
    ensure!(
        ciphertext.len() >= 28,
        "sealed backup credential is truncated"
    );
    let (nonce, bytes) = ciphertext.split_at(12);
    let mut buf = bytes.to_vec();
    let plain = key
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).context("invalid backup nonce")?,
            Aad::from(associated(
                c.organisation_id,
                c.app_id,
                c.volume_id,
                c.version,
                field,
            )),
            &mut buf,
        )
        .map_err(|_| {
            anyhow::anyhow!("stored backup credential does not open under instance secret")
        })?;
    Ok(std::str::from_utf8(plain)?.to_owned())
}

fn destination(
    endpoint: &str,
    bucket: &str,
    access: &str,
    secret: &str,
    session: &str,
) -> Result<(), BackupError> {
    let acceptable = endpoint.starts_with("https://")
        || endpoint.starts_with("http://127.0.0.1:")
        || endpoint.starts_with("http://localhost:");
    let host = endpoint
        .split_once("://")
        .map(|(_, host)| host)
        .unwrap_or("");
    if !acceptable
        || host.is_empty()
        || host.contains(['/', '?', '#', '@', '\n', '\r', ' '])
        || endpoint.len() > 255
    {
        return Err(BackupError::Invalid(
            "endpoint must be an HTTPS origin (loopback HTTP is only for local tests)".into(),
        ));
    }
    if bucket.len() < 3
        || bucket.len() > 63
        || !bucket
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || bucket.starts_with(['.', '-'])
        || bucket.ends_with(['.', '-'])
    {
        return Err(BackupError::Invalid(
            "bucket must be a valid S3 bucket name".into(),
        ));
    }
    if access.is_empty()
        || access.len() > 256
        || secret.is_empty()
        || secret.len() > 8192
        || session.len() > 8192
        || [access, secret, session].iter().any(|v| v.contains('\0'))
    {
        return Err(BackupError::Invalid(
            "S3 credentials are missing or exceed supported size".into(),
        ));
    }
    Ok(())
}

fn view(c: &BackupConfig) -> BackupView {
    BackupView {
        enabled: true,
        endpoint: c.endpoint.clone(),
        bucket: c.bucket.clone(),
        next_due: Some(c.next_due_at),
        last_verified: c.last_verified_at,
        version: c.version,
        last_error: c.last_error.clone(),
    }
}

impl Backups {
    /// Configure (or rotate keys for) a signed, locally authorized volume on
    /// own machine. A destination may not be silently repointed to another
    /// bucket: doing so would make existing recovery points disappear.
    #[allow(clippy::too_many_arguments)]
    pub async fn setup(
        &self,
        org: Uuid,
        app: Uuid,
        volume: Uuid,
        expected_version: i64,
        endpoint: &str,
        bucket: &str,
        access: &str,
        secret: &str,
        session: &str,
        idempotency_key: &str,
        request_hash: &[u8],
    ) -> Result<BackupView, BackupError> {
        destination(endpoint, bucket, access, secret, session)?;
        let mut tx = self.state.pool.begin().await.map_err(anyhow::Error::from)?;
        let row: Option<(bool, Option<i64>)> = sqlx::query_as("SELECT backup,size_gib FROM grund_volumes WHERE organisation_id=$1 AND app_id=$2 AND volume_id=$3 AND status='attached' AND machine_id IS NOT NULL FOR UPDATE")
            .bind(org).bind(app).bind(volume).fetch_optional(&mut *tx).await.map_err(anyhow::Error::from)?;
        match row {
            None => return Err(BackupError::NotFound),
            Some((false, _)) | Some((_, Some(_))) => return Err(BackupError::Ineligible),
            _ => {}
        }
        if idempotency_key.is_empty()
            || idempotency_key.len() > 128
            || !idempotency_key.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || request_hash.len() != 32
        {
            return Err(BackupError::Invalid(
                "idempotency key or request digest is invalid".into(),
            ));
        }
        match volumes::reserve_receipt(
            &mut tx,
            org,
            app,
            idempotency_key,
            "setup_backup",
            request_hash,
            volume,
        )
        .await
        .map_err(anyhow::Error::from)?
        {
            Receipt::New => {}
            Receipt::Existing(_) => return self.get(org, app, volume).await,
            Receipt::Conflict => return Err(BackupError::Conflict),
        }
        let old = backup::locked_config(&mut tx, org, app, volume)
            .await
            .map_err(anyhow::Error::from)?;
        let version = old.as_ref().map_or(1, |old| old.version + 1);
        if expected_version != version - 1 {
            return Err(BackupError::Conflict);
        }
        if old
            .as_ref()
            .is_some_and(|c| c.endpoint != endpoint || c.bucket != bucket)
        {
            return Err(BackupError::Invalid(
                "repointing an existing backup repository would strand verified points".into(),
            ));
        }
        let mut password_bytes = [0u8; 32];
        getrandom::fill(&mut password_bytes).expect("operating system random generator");
        let repository_password = if let Some(old) = &old {
            open(&key(&self.state), old, "password", &old.sealed_password)
                .map_err(BackupError::Internal)?
        } else {
            URL_SAFE_NO_PAD.encode(password_bytes)
        };
        let config = BackupConfig {
            organisation_id: org,
            app_id: app,
            volume_id: volume,
            endpoint: endpoint.to_owned(),
            bucket: bucket.to_owned(),
            repo_prefix: old.as_ref().map_or_else(
                || format!("grund/{}", Uuid::now_v7().simple()),
                |c| c.repo_prefix.clone(),
            ),
            sealed_access_key: seal(
                &key(&self.state),
                org,
                app,
                volume,
                version,
                "access",
                access,
            ),
            sealed_secret: seal(
                &key(&self.state),
                org,
                app,
                volume,
                version,
                "secret",
                secret,
            ),
            sealed_session: if session.is_empty() {
                None
            } else {
                Some(seal(
                    &key(&self.state),
                    org,
                    app,
                    volume,
                    version,
                    "session",
                    session,
                ))
            },
            sealed_password: seal(
                &key(&self.state),
                org,
                app,
                volume,
                version,
                "password",
                &repository_password,
            ),
            version,
            next_due_at: old.as_ref().map_or_else(Utc::now, |c| c.next_due_at),
            last_success_at: old.as_ref().and_then(|c| c.last_success_at),
            last_verified_at: old.as_ref().and_then(|c| c.last_verified_at),
            last_probe_at: old.as_ref().and_then(|c| c.last_probe_at),
            last_error: old.as_ref().and_then(|c| c.last_error.clone()),
        };
        if !backup::save_config(&mut tx, &config)
            .await
            .map_err(anyhow::Error::from)?
        {
            return Err(BackupError::Conflict);
        }
        tx.commit().await.map_err(anyhow::Error::from)?;
        Ok(view(&config))
    }

    pub async fn get(&self, org: Uuid, app: Uuid, volume: Uuid) -> Result<BackupView, BackupError> {
        let volume_row = volumes::volume(&self.state.pool, org, app, volume)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(BackupError::NotFound)?;
        if volume_row.size_gib.is_some() {
            return self
                .state
                .volume_backend()
                .ok_or(BackupError::Ineligible)?
                .backup_view(&self.state.pool, org, app, volume)
                .await
                .map_err(BackupError::Internal);
        }
        let configured = backup::config(&self.state.pool, org, app, volume)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(configured.as_ref().map(view).unwrap_or(BackupView {
            enabled: false,
            endpoint: String::new(),
            bucket: String::new(),
            next_due: None,
            last_verified: None,
            version: 0,
            last_error: None,
        }))
    }

    pub async fn list_points(
        &self,
        org: Uuid,
        app: Uuid,
        volume: Uuid,
    ) -> Result<Vec<RecoveryPoint>, BackupError> {
        let row = volumes::volume(&self.state.pool, org, app, volume)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(BackupError::NotFound)?;
        if row.size_gib.is_some() {
            return self
                .state
                .volume_backend()
                .ok_or(BackupError::Ineligible)?
                .recovery_points(&self.state.pool, org, app, volume)
                .await
                .map_err(BackupError::Internal);
        }
        Ok(backup::points(&self.state.pool, org, app, volume)
            .await
            .map_err(anyhow::Error::from)?)
    }

    /// Returns the exact existing repository password only to the API's
    /// explicitly owner-authorized one-time export response. Never render it
    /// in a page, log, general status response or a machine document.
    pub async fn export_key(
        &self,
        org: Uuid,
        app: Uuid,
        volume: Uuid,
    ) -> Result<String, BackupError> {
        if volumes::volume(&self.state.pool, org, app, volume)
            .await
            .map_err(anyhow::Error::from)?
            .is_some_and(|row| row.size_gib.is_some())
        {
            return Err(BackupError::Ineligible);
        }
        let config = backup::config(&self.state.pool, org, app, volume)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(BackupError::NotFound)?;
        open(
            &key(&self.state),
            &config,
            "password",
            &config.sealed_password,
        )
        .map_err(BackupError::Internal)
    }

    pub async fn restore_status(
        &self,
        org: Uuid,
        app: Uuid,
        volume: Uuid,
    ) -> Result<Option<(String, Option<String>)>, BackupError> {
        let row = volumes::volume(&self.state.pool, org, app, volume)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(BackupError::NotFound)?;
        if row.size_gib.is_some() {
            return self
                .state
                .volume_backend()
                .ok_or(BackupError::Ineligible)?
                .restore_status(&self.state.pool, org, app, volume)
                .await
                .map_err(BackupError::Internal);
        }
        volumes::restore_status(&self.state.pool, org, app, volume)
            .await
            .map_err(|error| BackupError::Internal(error.into()))
    }

    pub async fn restore_attempt_status(
        &self,
        org: Uuid,
        app: Uuid,
        source: Uuid,
        attempt: Uuid,
    ) -> Result<Option<String>, BackupError> {
        let row = volumes::volume(&self.state.pool, org, app, source)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(BackupError::NotFound)?;
        if row.size_gib.is_some() {
            return self
                .state
                .volume_backend()
                .ok_or(BackupError::Ineligible)?
                .restore_attempt_status(&self.state.pool, org, app, attempt)
                .await
                .map_err(BackupError::Internal);
        }
        volumes::restore_attempt_status(&self.state.pool, org, app, attempt)
            .await
            .map_err(|error| BackupError::Internal(error.into()))
    }

    /// Reserve a new app-owned volume for an exact recovery point. Own-machine
    /// directories wait for a verified probe; hosted drives wait for a fenced
    /// same-host snapshot restore before attachment is confirmed.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_restore(
        &self,
        org: Uuid,
        app: Uuid,
        source: Uuid,
        snapshot: &str,
        new_volume: Uuid,
        name: &str,
        path: &str,
        machine: Uuid,
        expected_source_version: i64,
        idempotency_key: &str,
        request_hash: &[u8],
    ) -> Result<Uuid, BackupError> {
        let snapshot_uuid = Uuid::parse_str(snapshot).ok();
        if (snapshot.len() != 64 || !snapshot.bytes().all(|b| b.is_ascii_hexdigit()))
            && snapshot_uuid.is_none()
        {
            return Err(BackupError::Invalid(
                "an exact recovery-point ID is required".into(),
            ));
        }
        if grund_domain::app::spec::AppName::parse(name).map_or(true, |n| n.as_str() != name) {
            return Err(BackupError::Invalid(
                "new volume name must be 1-32 lowercase letters, digits and single hyphens".into(),
            ));
        }
        if Uuid::new_v5(&app, name.as_bytes()) != new_volume || new_volume == source {
            return Err(BackupError::Invalid(
                "new volume identity does not match its app-scoped name".into(),
            ));
        }
        if path.len() > 4096
            || !path.starts_with('/')
            || path == "/"
            || path.bytes().any(|b| b.is_ascii_control())
            || path
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(BackupError::Invalid(
                "new container path must be a canonical absolute directory".into(),
            ));
        }
        let attempt_id = Uuid::now_v7();
        let mut work = Work::begin(&self.state.events, attempt_id, "grund/restore")
            .await
            .map_err(|e| BackupError::Internal(e.into()))?;
        work.app_decide(app, |current| {
            if current.exists && !current.deleted && current.organisation_id == org {
                Ok((vec![], ()))
            } else {
                Err(grund_domain::app::AppError::NotFound)
            }
        })
        .await
        .map_err(|_| BackupError::NotFound)?;
        if idempotency_key.is_empty()
            || idempotency_key.len() > 128
            || !idempotency_key.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || request_hash.len() != 32
        {
            return Err(BackupError::Invalid(
                "idempotency key or request digest is invalid".into(),
            ));
        }
        match volumes::reserve_receipt(
            work.sql(),
            org,
            app,
            idempotency_key,
            "restore",
            request_hash,
            attempt_id,
        )
        .await
        .map_err(anyhow::Error::from)?
        {
            Receipt::New => {}
            Receipt::Existing(id) => return Ok(id),
            Receipt::Conflict => return Err(BackupError::Conflict),
        }
        work.load_volume(source)
            .await
            .map_err(|_| BackupError::NotFound)?;
        let source_row = volumes::volume(&mut **work.sql(), org, app, source)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(BackupError::NotFound)?;
        if source_row.stream_version != expected_source_version {
            return Err(BackupError::Conflict);
        }
        let already_named: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM grund_volumes WHERE app_id=$1 AND name=$2)",
        )
        .bind(app)
        .bind(name)
        .fetch_one(&mut **work.sql())
        .await
        .map_err(anyhow::Error::from)?;
        if already_named {
            return Err(BackupError::Conflict);
        }
        if let Some(size_gib) = source_row.size_gib {
            let snapshot_id = snapshot_uuid.ok_or_else(|| {
                BackupError::Invalid("a hosted recovery-point ID must be a snapshot UUID".into())
            })?;
            if !source_row.backup
                || !matches!(
                    source_row.status.as_str(),
                    "attached" | "available" | "lost"
                )
            {
                return Err(BackupError::Ineligible);
            }
            if source_row.status == "lost" && source_row.lost_snapshot_id.is_none() {
                return Err(BackupError::Ineligible);
            }
            let backend = self.state.volume_backend().ok_or(BackupError::Ineligible)?;
            let spec = VolumeSpec {
                name: name.to_owned(),
                path: path.to_owned(),
                source: None,
                size_gib: Some(size_gib as u64),
                backup: false,
            };
            work.volume(
                new_volume,
                VolumeCommand::Request {
                    organisation_id: org,
                    app_id: app,
                    name: spec.name.clone(),
                    path: spec.path.clone(),
                    source: None,
                    backup: false,
                    size_gib: spec.size_gib,
                    at: Utc::now(),
                },
            )
            .await
            .map_err(|e| BackupError::Internal(e.into()))?;
            self.state
                .volumes()
                .place_release_in(&mut work, org, app, machine, &[spec])
                .await
                .map_err(|e| BackupError::Internal(e.into()))?;
            backend
                .reserve_restore(
                    work.sql(),
                    org,
                    app,
                    source,
                    snapshot_id,
                    new_volume,
                    machine,
                    attempt_id,
                )
                .await
                .map_err(BackupError::Internal)?;
            self.state
                .agents()
                .publish_in(work.sql(), machine)
                .await
                .map_err(BackupError::Internal)?;
            work.commit()
                .await
                .map_err(|e| BackupError::Internal(e.into()))?;
            self.state.wakes.documents_changed();
            return Ok(attempt_id);
        }
        let eligible: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM grund_machines m JOIN grund_machine_presence p ON p.machine_id = m.machine_id WHERE m.machine_id=$1 AND m.pool_organisation_id=$2 AND m.state='active' AND m.pool <> 'management' AND m.minted_by LIKE 'account:%' AND m.cordoned_at IS NULL AND p.capabilities->>'volumes' = 'true')")
            .bind(machine).bind(org).fetch_one(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
        if !eligible {
            return Err(BackupError::NotFound);
        }
        if !matches!(source_row.status.as_str(), "attached" | "available") {
            return Err(BackupError::Ineligible);
        }
        let present: Option<i32> = sqlx::query_scalar("SELECT 1 FROM grund_volume_backup_points WHERE organisation_id=$1 AND app_id=$2 AND volume_id=$3 AND snapshot_id=$4 FOR UPDATE")
            .bind(org).bind(app).bind(source).bind(snapshot).fetch_optional(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
        if present.is_none() {
            return Err(BackupError::NotFound);
        }
        let attempted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grund_volume_backup_attempts WHERE organisation_id=$1 AND volume_id=$2 AND snapshot_id=$3 AND operation='prune' AND (attempts>0 OR status='completed'))")
            .bind(org).bind(source).bind(snapshot).fetch_one(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
        if attempted {
            return Err(BackupError::Conflict);
        }
        sqlx::query("UPDATE grund_volume_backup_attempts SET status='failed',failure_class='source' WHERE organisation_id=$1 AND volume_id=$2 AND snapshot_id=$3 AND operation='prune' AND status='pending' AND attempts=0")
            .bind(org).bind(source).bind(snapshot).execute(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
        let pruning: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grund_volume_backup_attempts WHERE organisation_id=$1 AND volume_id=$2 AND snapshot_id=$3 AND operation='prune' AND status IN ('pending','leased'))")
            .bind(org).bind(source).bind(snapshot).fetch_one(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
        if pruning {
            return Err(BackupError::Conflict);
        }
        work.volume(
            new_volume,
            VolumeCommand::Request {
                organisation_id: org,
                app_id: app,
                name: name.to_owned(),
                path: path.to_owned(),
                source: None,
                backup: false,
                size_gib: None,
                at: Utc::now(),
            },
        )
        .await
        .map_err(|e| BackupError::Internal(e.into()))?;
        work.volume(
            new_volume,
            VolumeCommand::ReserveRestore {
                machine_id: machine,
                at: Utc::now(),
            },
        )
        .await
        .map_err(|e| BackupError::Internal(e.into()))?;
        sqlx::query("INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,destination_volume_id,snapshot_id,status) VALUES ($1,$2,$3,$4,$5,$6,'restore',$3,$7,$8,'pending')")
            .bind(org).bind(app).bind(source).bind(attempt_id).bind(machine).bind(source_row.stream_version).bind(new_volume).bind(snapshot)
            .execute(&mut **work.sql()).await.map_err(anyhow::Error::from)?;
        self.state
            .agents()
            .publish_in(work.sql(), machine)
            .await
            .map_err(BackupError::Internal)?;
        work.commit()
            .await
            .map_err(|e| BackupError::Internal(e.into()))?;
        self.state.wakes.documents_changed();
        Ok(attempt_id)
    }

    pub async fn for_machine(&self, machine: Uuid) -> Result<Option<BackupWork>, BackupError> {
        let Some(a) = backup::lease_machine(&self.state.pool, machine)
            .await
            .map_err(anyhow::Error::from)?
        else {
            return Ok(None);
        };
        let c = backup::config(&self.state.pool, a.organisation_id, a.app_id, a.volume_id)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(BackupError::NotFound)?;
        let source = volumes::volume(
            &self.state.pool,
            a.organisation_id,
            a.app_id,
            a.source_volume_id,
        )
        .await
        .map_err(anyhow::Error::from)?
        .ok_or(BackupError::NotFound)?;
        let k = key(&self.state);
        let operation = match a.operation.as_str() {
            "backup" => BackupOperation::BACKUP_OPERATION_BACKUP,
            "restore" => BackupOperation::BACKUP_OPERATION_RESTORE,
            "probe" => BackupOperation::BACKUP_OPERATION_PROBE,
            "prune" => BackupOperation::BACKUP_OPERATION_PRUNE,
            _ => {
                return Err(BackupError::Internal(anyhow::anyhow!(
                    "invalid stored backup operation"
                )));
            }
        };
        let source_path = if matches!(a.operation.as_str(), "restore" | "probe") {
            backup::archived_path(
                &self.state.pool,
                a.organisation_id,
                a.app_id,
                a.source_volume_id,
                a.snapshot_id.as_deref().ok_or(BackupError::NotFound)?,
            )
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(BackupError::NotFound)?
        } else {
            source.source.unwrap_or_default()
        };
        Ok(Some(BackupWork {
            attempt_id: a.attempt_id.to_string(),
            volume_id: a.volume_id.to_string(),
            app_id: a.app_id.to_string(),
            placement_generation: u64::try_from(a.placement_generation)
                .map_err(anyhow::Error::from)?,
            operation: operation.into(),
            source_volume_id: a.source_volume_id.to_string(),
            destination_volume_id: a
                .destination_volume_id
                .map_or_else(String::new, |id| id.to_string()),
            snapshot_id: a.snapshot_id.unwrap_or_default(),
            endpoint: c.endpoint.clone(),
            bucket: c.bucket.clone(),
            repo_prefix: c.repo_prefix.clone(),
            access_key_id: open(&k, &c, "access", &c.sealed_access_key)
                .map_err(BackupError::Internal)?,
            secret_access_key: open(&k, &c, "secret", &c.sealed_secret)
                .map_err(BackupError::Internal)?,
            session_token: c
                .sealed_session
                .as_ref()
                .map(|b| open(&k, &c, "session", b))
                .transpose()
                .map_err(BackupError::Internal)?
                .unwrap_or_default(),
            repository_password: open(&k, &c, "password", &c.sealed_password)
                .map_err(BackupError::Internal)?,
            organisation_id: a.organisation_id.to_string(),
            source_path,
            ..Default::default()
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn ack(
        &self,
        machine: Uuid,
        attempt: Uuid,
        generation: i64,
        success: bool,
        snapshot: &str,
        failure: &str,
        source_path: &str,
    ) -> Result<bool, BackupError> {
        Ok(backup::complete(
            &self.state.pool,
            machine,
            attempt,
            generation,
            success,
            snapshot,
            failure,
            source_path,
        )
        .await
        .map_err(anyhow::Error::from)?)
    }

    pub async fn schedule(&self) -> anyhow::Result<()> {
        backup::schedule(&self.state.pool).await?;
        backup::schedule_probe(&self.state.pool).await?;
        backup::schedule_prune(&self.state.pool).await?;
        self.place_restores().await?;
        Ok(())
    }
    async fn place_restores(&self) -> anyhow::Result<()> {
        for attempt in backup::completed_restores(&self.state.pool).await? {
            let Some(destination) = attempt.destination_volume_id else {
                continue;
            };
            let mut work =
                Work::begin(&self.state.events, attempt.attempt_id, "grund/restore").await?;
            let live = work
                .app_decide(attempt.app_id, |current| {
                    if current.exists
                        && !current.deleted
                        && current.organisation_id == attempt.organisation_id
                    {
                        Ok((vec![], true))
                    } else {
                        Ok((vec![], false))
                    }
                })
                .await?
                .1;
            if !live {
                continue;
            }
            work.volume(
                destination,
                VolumeCommand::Place {
                    machine_id: attempt.machine_id,
                    at: Utc::now(),
                },
            )
            .await?;
            work.commit().await?;
        }
        Ok(())
    }
}

/// PostgreSQL due times, rather than this process's uptime, drive backup work.
pub struct BackupScheduler {
    state: State,
}
impl BackupScheduler {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}
impl notmad::Component for BackupScheduler {
    fn info(&self) -> notmad::ComponentInfo {
        "grund/volume-backups".into()
    }
    async fn run(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<(), notmad::MadError> {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                _ = tick.tick() => if let Err(error) = self.state.backups().schedule().await {
                    tracing::warn!(error=%error, "backup schedule unavailable; due attempts remain in PostgreSQL");
                },
            }
        }
    }
}
