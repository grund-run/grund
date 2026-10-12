//! VolumeService: every call resolves both organisation membership and a live
//! app before touching an app-owned volume. Foreign ids are not_found.
use crate::{
    api::{Principal, principal},
    services::{
        BackupsState, OrganisationsState, VolumesState,
        backups::{BackupError, BackupView},
        volumes::{Operation, VolumesError},
    },
    state::State,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::{Message, MessageField, MessageView};
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_domain::app::spec::VolumeSpec;
use grund_proto::grund::volume::v1::{
    self as proto, AttachVolumeRequest, AttachVolumeResponse, CreateVolumeRequest,
    CreateVolumeResponse, DeleteVolumeRequest, DeleteVolumeResponse, DetachVolumeRequest,
    DetachVolumeResponse, ExportBackupKeyRequest, ExportBackupKeyResponse,
    GetBackupDestinationRequest, GetBackupDestinationResponse, GetVolumeRequest, GetVolumeResponse,
    GetVolumeStatusRequest, GetVolumeStatusResponse, ListRecoveryPointsRequest,
    ListRecoveryPointsResponse, ListVolumesRequest, ListVolumesResponse,
    RestoreRecoveryPointRequest, RestoreRecoveryPointResponse, SetBackupDestinationRequest,
    SetBackupDestinationResponse, VolumeService,
};
use grund_store::{apps, organisations::Membership, volumes::VolumeRow};
use ring::{digest, hmac};
use uuid::Uuid;

pub struct VolumeApi {
    state: State,
}
impl VolumeApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Manage,
    Owner,
}

impl VolumeApi {
    async fn member(
        &self,
        caller: &Principal,
        slug: &str,
        access: Access,
    ) -> Result<Membership, ConnectError> {
        let membership = self
            .state
            .organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "volume membership lookup failed");
                ConnectError::internal("membership lookup failed")
            })?
            .filter(|m| caller.reaches(m.organisation_id))
            .ok_or_else(|| ConnectError::not_found("no such organisation"))?;
        if access == Access::Manage && !matches!(membership.role.as_str(), "owner" | "admin") {
            return Err(ConnectError::permission_denied(
                "only owners and admins change an app's storage",
            ));
        }
        if access == Access::Owner && membership.role != "owner" {
            return Err(ConnectError::permission_denied(
                "only the organisation owner may export or configure backup keys",
            ));
        }
        Ok(membership)
    }
    async fn app(
        &self,
        caller: &Principal,
        slug: &str,
        app: &str,
        access: Access,
    ) -> Result<(Uuid, Uuid), ConnectError> {
        let member = self.member(caller, slug, access).await?;
        let row = apps::app_by_name(&self.state.pool, member.organisation_id, app)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "volume app lookup failed");
                ConnectError::internal("app lookup failed")
            })?
            .ok_or_else(|| ConnectError::not_found("no such app"))?;
        Ok((member.organisation_id, row.app_id))
    }
}

fn id(id: &str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(id)
        .map_err(|_| ConnectError::invalid_argument("volume and machine IDs must be UUIDs"))
}
fn key(key: &str) -> Result<(), ConnectError> {
    if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(ConnectError::invalid_argument(
            "idempotency_key must be 1-128 printable ASCII characters",
        ));
    }
    Ok(())
}
fn failed(error: VolumesError) -> ConnectError {
    let message = error.to_string();
    match error {
        VolumesError::NotFound => ConnectError::not_found(message),
        VolumesError::Conflict => ConnectError::aborted(message),
        VolumesError::Invalid(_) | VolumesError::SourceChanged(_) => {
            ConnectError::invalid_argument(message)
        }
        VolumesError::MachineChanged
        | VolumesError::InvalidMachine
        | VolumesError::WriterPresent
        | VolumesError::RestoreNotReady => ConnectError::failed_precondition(message),
        VolumesError::Internal(cause) => {
            tracing::error!(error = %format!("{cause:#}"), "volume operation failed");
            ConnectError::internal("volume operation failed")
        }
    }
}
fn backup_failed(error: BackupError) -> ConnectError {
    let message = error.to_string();
    match error {
        BackupError::NotFound => ConnectError::not_found(message),
        BackupError::Conflict => ConnectError::aborted(message),
        BackupError::Ineligible => ConnectError::failed_precondition(message),
        BackupError::Invalid(_) => ConnectError::invalid_argument(message),
        BackupError::Internal(cause) => {
            tracing::error!(error = %format!("{cause:#}"), "backup operation failed");
            ConnectError::internal("backup operation failed")
        }
    }
}
fn timestamp<P: buffa::ProtoBox<Timestamp>>(at: DateTime<Utc>) -> MessageField<Timestamp, P> {
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into()
}
fn message(row: &VolumeRow) -> proto::Volume {
    proto::Volume {
        volume_id: row.volume_id.to_string(),
        app_id: row.app_id.to_string(),
        name: row.name.clone(),
        path: row.path.clone(),
        source: row.source.clone().unwrap_or_default(),
        backup: row.backup,
        machine_id: row.machine_id.map_or_else(String::new, |id| id.to_string()),
        status: row.status.clone(),
        measured_bytes: row.measured_bytes.map(|n| n as u64),
        measured_at: row.measured_at.map(timestamp).unwrap_or_default(),
        version: row.stream_version,
        ..Default::default()
    }
}
fn destination(view: BackupView) -> proto::BackupDestination {
    proto::BackupDestination {
        enabled: view.enabled,
        endpoint: view.endpoint,
        bucket: view.bucket,
        retention_count: 7,
        last_verified_at: view.last_verified.map(timestamp).unwrap_or_default(),
        next_due_at: view.next_due.map(timestamp).unwrap_or_default(),
        version: view.version,
        last_error: view.last_error.unwrap_or_default(),
        ..Default::default()
    }
}
fn owned<'a, V: MessageView<'a>>(view: &V) -> Result<V::Owned, ConnectError> {
    view.to_owned_message()
        .map_err(|_| ConnectError::invalid_argument("request does not decode"))
}

fn cursor_key(state: &State) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, &state.secret.derive("volume-page-token"))
}
fn encode_cursor(state: &State, org: Uuid, app: Uuid, volume: Uuid, snapshot: &str) -> String {
    let mut payload = Vec::with_capacity(16 * 3 + snapshot.len() + 32);
    payload.extend_from_slice(org.as_bytes());
    payload.extend_from_slice(app.as_bytes());
    payload.extend_from_slice(volume.as_bytes());
    payload.extend_from_slice(snapshot.as_bytes());
    payload.extend_from_slice(hmac::sign(&cursor_key(state), &payload).as_ref());
    URL_SAFE_NO_PAD.encode(payload)
}
fn decode_cursor(
    state: &State,
    token: &str,
    org: Uuid,
    app: Uuid,
    volume: Uuid,
) -> Result<String, ConnectError> {
    let bad = || ConnectError::invalid_argument("invalid page token");
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| bad())?;
    if bytes.len() != 16 * 3 + 64 + 32
        || bytes[..16] != *org.as_bytes()
        || bytes[16..32] != *app.as_bytes()
        || bytes[32..48] != *volume.as_bytes()
    {
        return Err(bad());
    }
    hmac::verify(&cursor_key(state), &bytes[..112], &bytes[112..]).map_err(|_| bad())?;
    std::str::from_utf8(&bytes[48..112])
        .map(str::to_owned)
        .map_err(|_| bad())
}

#[allow(refining_impl_trait)]
impl VolumeService for VolumeApi {
    async fn list_volumes(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListVolumesRequest>,
    ) -> ServiceResult<ListVolumesResponse> {
        let caller = principal(&ctx)?;
        let (org, app) = self
            .app(&caller, request.organisation, request.app, Access::Read)
            .await?;
        let volumes = self.state.volumes().list(org, app).await.map_err(failed)?;
        Response::ok(ListVolumesResponse {
            volumes: volumes.iter().map(message).collect(),
            ..Default::default()
        })
    }
    async fn get_volume(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetVolumeRequest>,
    ) -> ServiceResult<GetVolumeResponse> {
        let caller = principal(&ctx)?;
        let (org, app) = self
            .app(&caller, request.organisation, request.app, Access::Read)
            .await?;
        let row = self
            .state
            .volumes()
            .get(org, app, id(request.volume_id)?)
            .await
            .map_err(failed)?;
        Response::ok(GetVolumeResponse {
            volume: MessageField::from(message(&row)),
            ..Default::default()
        })
    }
    async fn get_volume_status(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetVolumeStatusRequest>,
    ) -> ServiceResult<GetVolumeStatusResponse> {
        let caller = principal(&ctx)?;
        let (org, app) = self
            .app(&caller, request.organisation, request.app, Access::Read)
            .await?;
        let row = self
            .state
            .volumes()
            .get(org, app, id(request.volume_id)?)
            .await
            .map_err(failed)?;
        let mut volume = message(&row);
        if let Some((status, failure)) =
            grund_store::volumes::restore_status(&self.state.pool, org, app, row.volume_id)
                .await
                .map_err(|e| failed(VolumesError::Internal(e.into())))?
        {
            volume.restore_status = status;
            volume.restore_failure_class = failure.unwrap_or_default();
        }
        Response::ok(GetVolumeStatusResponse {
            volume: MessageField::from(volume),
            ..Default::default()
        })
    }
    async fn create_volume(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateVolumeRequest>,
    ) -> ServiceResult<CreateVolumeResponse> {
        let caller = principal(&ctx)?;
        key(request.idempotency_key)?;
        let request: CreateVolumeRequest = owned(&*request)?;
        let hash = digest::digest(&digest::SHA256, &request.encode_to_vec());
        let (org, app) = self
            .app(&caller, &request.organisation, &request.app, Access::Manage)
            .await?;
        let row = self
            .state
            .volumes()
            .create(
                caller.account_id,
                org,
                app,
                VolumeSpec {
                    name: request.name,
                    path: request.path,
                    source: (!request.source.is_empty()).then_some(request.source),
                    backup: request.backup,
                },
                &request.idempotency_key,
                hash.as_ref(),
            )
            .await
            .map_err(failed)?;
        Response::ok(CreateVolumeResponse {
            volume: MessageField::from(message(&row)),
            ..Default::default()
        })
    }
    async fn attach_volume(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AttachVolumeRequest>,
    ) -> ServiceResult<AttachVolumeResponse> {
        let caller = principal(&ctx)?;
        let (org, app) = self
            .app(&caller, request.organisation, request.app, Access::Manage)
            .await?;
        let row = self
            .state
            .volumes()
            .mutate(
                caller.account_id,
                org,
                app,
                id(request.volume_id)?,
                request.expected_version,
                Operation::Attach(id(request.machine_id)?),
            )
            .await
            .map_err(failed)?;
        Response::ok(AttachVolumeResponse {
            volume: MessageField::from(message(&row)),
            ..Default::default()
        })
    }
    async fn detach_volume(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DetachVolumeRequest>,
    ) -> ServiceResult<DetachVolumeResponse> {
        let caller = principal(&ctx)?;
        let (org, app) = self
            .app(&caller, request.organisation, request.app, Access::Manage)
            .await?;
        let row = self
            .state
            .volumes()
            .mutate(
                caller.account_id,
                org,
                app,
                id(request.volume_id)?,
                request.expected_version,
                Operation::Detach,
            )
            .await
            .map_err(failed)?;
        Response::ok(DetachVolumeResponse {
            volume: MessageField::from(message(&row)),
            ..Default::default()
        })
    }
    async fn delete_volume(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteVolumeRequest>,
    ) -> ServiceResult<DeleteVolumeResponse> {
        let caller = principal(&ctx)?;
        let (org, app) = self
            .app(&caller, request.organisation, request.app, Access::Manage)
            .await?;
        let row = self
            .state
            .volumes()
            .mutate(
                caller.account_id,
                org,
                app,
                id(request.volume_id)?,
                request.expected_version,
                Operation::Delete,
            )
            .await
            .map_err(failed)?;
        Response::ok(DeleteVolumeResponse {
            volume: MessageField::from(message(&row)),
            ..Default::default()
        })
    }
    async fn set_backup_destination(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetBackupDestinationRequest>,
    ) -> ServiceResult<SetBackupDestinationResponse> {
        let caller = principal(&ctx)?;
        key(request.idempotency_key)?;
        let request: SetBackupDestinationRequest = owned(&*request)?;
        let hash = digest::digest(&digest::SHA256, &request.encode_to_vec());
        let (org, app) = self
            .app(&caller, &request.organisation, &request.app, Access::Owner)
            .await?;
        let view = self
            .state
            .backups()
            .setup(
                org,
                app,
                id(&request.volume_id)?,
                request.expected_version,
                &request.endpoint,
                &request.bucket,
                &request.access_key_id,
                &request.secret_access_key,
                &request.session_token,
                &request.idempotency_key,
                hash.as_ref(),
            )
            .await
            .map_err(backup_failed)?;
        Response::ok(SetBackupDestinationResponse {
            destination: MessageField::from(destination(view)),
            ..Default::default()
        })
    }
    async fn get_backup_destination(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetBackupDestinationRequest>,
    ) -> ServiceResult<GetBackupDestinationResponse> {
        let caller = principal(&ctx)?;
        let (org, app) = self
            .app(&caller, request.organisation, request.app, Access::Read)
            .await?;
        let view = self
            .state
            .backups()
            .get(org, app, id(request.volume_id)?)
            .await
            .map_err(backup_failed)?;
        Response::ok(GetBackupDestinationResponse {
            destination: MessageField::from(destination(view)),
            ..Default::default()
        })
    }
    async fn list_recovery_points(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRecoveryPointsRequest>,
    ) -> ServiceResult<ListRecoveryPointsResponse> {
        let caller = principal(&ctx)?;
        let (org, app) = self
            .app(&caller, request.organisation, request.app, Access::Read)
            .await?;
        let volume = id(request.volume_id)?;
        let after = if request.page_token.is_empty() {
            None
        } else {
            Some(decode_cursor(
                &self.state,
                request.page_token,
                org,
                app,
                volume,
            )?)
        };
        let points = self
            .state
            .backups()
            .list_points(org, app, volume)
            .await
            .map_err(backup_failed)?;
        let start = after.as_ref().map_or(Ok(0), |after| {
            points
                .iter()
                .position(|p| &p.snapshot_id == after)
                .map(|i| i + 1)
                .ok_or_else(|| ConnectError::invalid_argument("expired page token"))
        })?;
        let limit = if request.page_size <= 0 {
            50
        } else {
            request.page_size.min(100) as usize
        };
        let next_page_token = if points.len() > start + limit {
            encode_cursor(
                &self.state,
                org,
                app,
                volume,
                &points[start + limit - 1].snapshot_id,
            )
        } else {
            String::new()
        };
        let points = points
            .into_iter()
            .skip(start)
            .take(limit)
            .map(|p| proto::RecoveryPoint {
                snapshot_id: p.snapshot_id,
                verified_at: timestamp(p.verified_at),
                completed_at: timestamp(p.completed_at),
                ..Default::default()
            })
            .collect();
        Response::ok(ListRecoveryPointsResponse {
            points,
            next_page_token,
            ..Default::default()
        })
    }
    async fn restore_recovery_point(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RestoreRecoveryPointRequest>,
    ) -> ServiceResult<RestoreRecoveryPointResponse> {
        let caller = principal(&ctx)?;
        key(request.idempotency_key)?;
        if !request.confirm_new_volume {
            return Err(ConnectError::failed_precondition(
                "confirm_new_volume is required; restore only creates a new volume",
            ));
        }
        let request: RestoreRecoveryPointRequest = owned(&*request)?;
        let hash = digest::digest(&digest::SHA256, &request.encode_to_vec());
        let (org, app) = self
            .app(&caller, &request.organisation, &request.app, Access::Manage)
            .await?;
        let new_volume = Uuid::new_v5(&app, request.new_volume_name.as_bytes());
        let attempt = self
            .state
            .backups()
            .request_restore(
                org,
                app,
                id(&request.source_volume_id)?,
                &request.snapshot_id,
                new_volume,
                &request.new_volume_name,
                &request.target_container_path,
                id(&request.target_machine_id)?,
                request.expected_version,
                &request.idempotency_key,
                hash.as_ref(),
            )
            .await
            .map_err(backup_failed)?;
        let status =
            grund_store::volumes::restore_attempt_status(&self.state.pool, org, app, attempt)
                .await
                .map_err(|e| backup_failed(BackupError::Internal(e.into())))?
                .unwrap_or_else(|| "pending".into());
        Response::ok(RestoreRecoveryPointResponse {
            new_volume_id: new_volume.to_string(),
            attempt_id: attempt.to_string(),
            status,
            ..Default::default()
        })
    }
    async fn export_backup_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ExportBackupKeyRequest>,
    ) -> ServiceResult<ExportBackupKeyResponse> {
        let caller = principal(&ctx)?;
        let (org, app) = self
            .app(&caller, request.organisation, request.app, Access::Owner)
            .await?;
        let repository_password = self
            .state
            .backups()
            .export_key(org, app, id(request.volume_id)?)
            .await
            .map_err(backup_failed)?;
        Response::ok(ExportBackupKeyResponse {
            repository_password,
            ..Default::default()
        })
    }
}
