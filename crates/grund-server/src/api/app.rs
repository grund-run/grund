//! `grund.app.v1.AppService`: an organisation's apps (grund-docs
//! design/apps.md §3.2). Members get and list; owners and admins change.
//! An organisation the caller is not a member of, an organisation a token
//! is not for, and an app that is not the organisation's, are not_found
//! alike. A token acts as the account that made it, with that account's
//! role (`api::AUTHORIZATION` says which of these procedures it may call).

use buffa::{EnumValue, MessageField, MessageView};
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_domain::app::{
    AppSettings, ReleaseSource,
    spec::{
        AppSpec, CheckKind, CheckSpec, EnvVar, PortSpec, Protocol, SecretEnv, SettingsInput,
        StopSpec,
    },
};
use grund_proto::grund::app::v1::{
    self as proto, AppService, ConfigureAppRequest, ConfigureAppResponse, CreateAppRequest,
    CreateAppResponse, DeleteAppRequest, DeleteAppResponse, DeployRequest, DeployResponse,
    ErrorReason, GetAppRequest, GetAppResponse, ListAppsRequest, ListAppsResponse,
    ListReleasesRequest, ListReleasesResponse, RollbackRequest, RollbackResponse, ScaleRequest,
    ScaleResponse, SetSecretRequest, SetSecretResponse,
};
use grund_store::{apps::ReleaseRow, organisations::Membership};

use crate::{
    api::{Principal, principal},
    services::{
        OrganisationsState,
        apps::{AppView, AppsError, AppsState, DeployInput},
    },
    state::State,
};

/// The service implementation.
pub struct AppApi {
    state: State,
}

impl AppApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

fn timestamp<P: buffa::ProtoBox<Timestamp>>(at: DateTime<Utc>) -> MessageField<Timestamp, P> {
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into()
}

fn refusal(error: ConnectError, reason: &str) -> ConnectError {
    error.with_detail(ErrorDetail::from_message(
        "grund.app.v1.ErrorReason",
        &ErrorReason {
            reason: reason.to_string(),
            ..Default::default()
        },
    ))
}

fn failed(error: AppsError) -> ConnectError {
    let reason = error.reason();
    let message = error.to_string();
    let base = match &error {
        AppsError::NotFound | AppsError::ReleaseNotFound => ConnectError::not_found(message),
        AppsError::NameTaken | AppsError::AppLimit => ConnectError::failed_precondition(message),
        AppsError::Spec(_) | AppsError::ImageUnsupported(_) => {
            ConnectError::invalid_argument(message)
        }
        AppsError::ImageUnresolved(_) => ConnectError::failed_precondition(message),
        AppsError::Internal(cause) => {
            tracing::error!(error = %format!("{cause:#}"), "app API call failed");
            ConnectError::internal("grund could not finish that")
        }
    };
    refusal(base, reason)
}

/// The settings a request gives, `None` for each it leaves out.
pub fn settings_input(settings: Option<&proto::AppSettings>) -> SettingsInput {
    let Some(settings) = settings else {
        return SettingsInput::default();
    };
    let rollout = settings.rollout.as_option();
    SettingsInput {
        copies: Some(settings.copies).filter(|c| *c > 0),
        max_surge: rollout.and_then(|r| r.max_surge),
        max_unavailable: rollout.and_then(|r| r.max_unavailable),
        min_ready_seconds: rollout.and_then(|r| r.min_ready_seconds),
        ready_deadline_seconds: rollout.map(|r| r.ready_deadline_seconds).filter(|s| *s > 0),
        drain_seconds: rollout.and_then(|r| r.drain_seconds),
        machines: settings.machines.clone(),
        reschedule_after_seconds: Some(settings.reschedule_after_seconds).filter(|s| *s > 0),
        auto_rollback: settings.auto_rollback,
    }
}

/// The domain spec a request carries, before validation.
pub fn spec_input(spec: &proto::AppSpec) -> AppSpec {
    AppSpec {
        image: spec.image.clone(),
        command: spec.command.clone(),
        ports: spec
            .ports
            .iter()
            .map(|p| PortSpec {
                name: p.name.clone(),
                port: u16::try_from(p.port).unwrap_or(0),
                protocol: match p.protocol.as_known() {
                    Some(proto::Protocol::PROTOCOL_H2C) => Protocol::H2c,
                    Some(proto::Protocol::PROTOCOL_TCP) => Protocol::Tcp,
                    _ => Protocol::Http,
                },
                public: p.public,
            })
            .collect(),
        memory_mib: spec.resources.as_option().map_or(0, |r| r.memory_mib),
        cpu_millis: spec.resources.as_option().map_or(0, |r| r.cpu_millis),
        env: spec
            .env
            .iter()
            .map(|e| EnvVar {
                name: e.name.clone(),
                value: e.value.clone(),
            })
            .collect(),
        secrets: spec
            .secrets
            .iter()
            .map(|s| SecretEnv {
                env: s.env.clone(),
                secret: s.secret.clone(),
            })
            .collect(),
        check: spec.check.as_option().map(|c| CheckSpec {
            kind: match &c.kind {
                Some(proto::check::Kind::HttpPath(path)) => CheckKind::Http { path: path.clone() },
                Some(proto::check::Kind::Tcp(_)) => CheckKind::Tcp,
                None => CheckKind::Http {
                    path: String::new(),
                },
            },
            port: u16::try_from(c.port).unwrap_or(u16::MAX),
            interval_ms: c.interval_ms,
            timeout_ms: c.timeout_ms,
        }),
        stop: spec.stop.as_option().map_or(
            StopSpec {
                signal: String::new(),
                grace_seconds: 0,
            },
            |s| StopSpec {
                signal: s.signal.clone(),
                grace_seconds: s.grace_seconds,
            },
        ),
    }
}

/// The wire form of a spec.
pub fn spec_message(spec: &AppSpec) -> proto::AppSpec {
    proto::AppSpec {
        image: spec.image.clone(),
        command: spec.command.clone(),
        ports: spec
            .ports
            .iter()
            .map(|p| proto::Port {
                name: p.name.clone(),
                port: u32::from(p.port),
                protocol: match p.protocol {
                    Protocol::Http => proto::Protocol::PROTOCOL_HTTP,
                    Protocol::H2c => proto::Protocol::PROTOCOL_H2C,
                    Protocol::Tcp => proto::Protocol::PROTOCOL_TCP,
                }
                .into(),
                public: p.public,
                ..Default::default()
            })
            .collect(),
        resources: MessageField::from(proto::Resources {
            memory_mib: spec.memory_mib,
            cpu_millis: spec.cpu_millis,
            ..Default::default()
        }),
        env: spec
            .env
            .iter()
            .map(|e| proto::EnvVar {
                name: e.name.clone(),
                value: e.value.clone(),
                ..Default::default()
            })
            .collect(),
        secrets: spec
            .secrets
            .iter()
            .map(|s| proto::SecretEnv {
                env: s.env.clone(),
                secret: s.secret.clone(),
                ..Default::default()
            })
            .collect(),
        check: spec
            .check
            .as_ref()
            .map(|c| {
                MessageField::from(proto::Check {
                    kind: Some(match &c.kind {
                        CheckKind::Http { path } => proto::check::Kind::HttpPath(path.clone()),
                        CheckKind::Tcp => proto::check::Kind::Tcp(true),
                    }),
                    port: u32::from(c.port),
                    interval_ms: c.interval_ms,
                    timeout_ms: c.timeout_ms,
                    ..Default::default()
                })
            })
            .unwrap_or_default(),
        stop: MessageField::from(proto::Stop {
            signal: spec.stop.signal.clone(),
            grace_seconds: spec.stop.grace_seconds,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn settings_message(settings: &AppSettings) -> proto::AppSettings {
    proto::AppSettings {
        copies: settings.copies,
        rollout: MessageField::from(proto::Rollout {
            max_surge: Some(settings.rollout.max_surge),
            max_unavailable: Some(settings.rollout.max_unavailable),
            min_ready_seconds: Some(settings.rollout.min_ready_seconds),
            ready_deadline_seconds: settings.rollout.ready_deadline_seconds,
            drain_seconds: Some(settings.rollout.drain_seconds),
            ..Default::default()
        }),
        machines: settings.machines.clone(),
        reschedule_after_seconds: settings.reschedule_after_seconds,
        auto_rollback: Some(settings.auto_rollback),
        ..Default::default()
    }
}

fn observed_state(state: Option<&str>) -> EnumValue<proto::ObservedState> {
    match state {
        Some("pulling") => proto::ObservedState::OBSERVED_STATE_PULLING,
        Some("starting") => proto::ObservedState::OBSERVED_STATE_STARTING,
        Some("running") => proto::ObservedState::OBSERVED_STATE_RUNNING,
        Some("exited") => proto::ObservedState::OBSERVED_STATE_EXITED,
        Some("failed") => proto::ObservedState::OBSERVED_STATE_FAILED,
        Some("refused") => proto::ObservedState::OBSERVED_STATE_REFUSED,
        _ => proto::ObservedState::OBSERVED_STATE_UNSPECIFIED,
    }
    .into()
}

fn rollout_message(rollout: &serde_json::Value) -> Option<proto::RolloutStatus> {
    let at = |key: &str| {
        rollout[key]
            .as_str()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| timestamp(t.with_timezone(&Utc)))
            .unwrap_or_default()
    };
    Some(proto::RolloutStatus {
        rollout_id: rollout["rollout_id"].as_str()?.to_string(),
        from_release: rollout["from"].as_u64().unwrap_or(0) as u32,
        to_release: rollout["to"].as_u64()? as u32,
        state: match rollout["state"].as_str() {
            Some("in_progress") => proto::RolloutState::ROLLOUT_STATE_IN_PROGRESS,
            Some("succeeded") => proto::RolloutState::ROLLOUT_STATE_SUCCEEDED,
            Some("failed") => proto::RolloutState::ROLLOUT_STATE_FAILED,
            Some("superseded") => proto::RolloutState::ROLLOUT_STATE_SUPERSEDED,
            _ => proto::RolloutState::ROLLOUT_STATE_UNSPECIFIED,
        }
        .into(),
        reason: rollout["reason"].as_str().unwrap_or_default().to_string(),
        started_at: at("started_at"),
        ended_at: at("ended_at"),
        ..Default::default()
    })
}

/// The wire form of an app.
pub fn app_message(view: &AppView) -> proto::App {
    let now = Utc::now();
    let row = &view.row;
    proto::App {
        app_id: row.app_id.to_string(),
        name: row.name.clone(),
        settings: MessageField::from(settings_message(&row.settings.0)),
        current_release: row.current_release.unwrap_or(0) as u32,
        rollout: row
            .rollout
            .as_ref()
            .and_then(rollout_message)
            .map(MessageField::from)
            .unwrap_or_default(),
        replicas: view
            .replicas
            .iter()
            .map(|r| proto::Replica {
                replica_id: r.replica_id.to_string(),
                slot: r.slot as u32,
                release: r.release as u32,
                machine_id: r.machine_id.to_string(),
                machine_name: r.machine_name.clone().unwrap_or_default(),
                state: match r.state.as_str() {
                    "draining" => proto::ReplicaState::REPLICA_STATE_DRAINING,
                    _ => proto::ReplicaState::REPLICA_STATE_RUNNING,
                }
                .into(),
                observed: MessageField::from(proto::ReplicaObservation {
                    state: observed_state(r.observed_state.as_deref()),
                    ready: r.ready.unwrap_or(false),
                    ready_since: r.ready_since.map(timestamp).unwrap_or_default(),
                    restarts: r.restarts.unwrap_or(0).max(0) as u32,
                    last_exit_code: r.last_exit_code.unwrap_or(0),
                    reason: r.reason.clone().unwrap_or_default(),
                    observed_at: r.observed_at.map(timestamp).unwrap_or_default(),
                    machine_connected: r
                        .last_seen_at
                        .is_some_and(|seen| now - seen <= chrono::Duration::seconds(30)),
                    ..Default::default()
                }),
                placed_at: timestamp(r.placed_at),
                ..Default::default()
            })
            .collect(),
        waiting: row
            .waiting
            .as_array()
            .map(|waiting| {
                waiting
                    .iter()
                    .map(|w| proto::Waiting {
                        slot: w["slot"].as_u64().unwrap_or(0) as u32,
                        reason: w["reason"].as_str().unwrap_or_default().to_string(),
                        message: w["message"].as_str().unwrap_or_default().to_string(),
                        ..Default::default()
                    })
                    .collect()
            })
            .unwrap_or_default(),
        secrets: view
            .secrets
            .iter()
            .map(|(name, version, at)| proto::SecretInfo {
                name: name.clone(),
                version: *version as u32,
                updated_at: timestamp(*at),
                ..Default::default()
            })
            .collect(),
        created_at: timestamp(row.created_at),
        halted: row.halted,
        ..Default::default()
    }
}

/// The wire form of a release.
pub fn release_message(row: &ReleaseRow) -> proto::Release {
    proto::Release {
        number: row.number as u32,
        spec: MessageField::from(spec_message(&row.spec.0)),
        image_digest: row.image_digest.clone(),
        platforms: row.platforms.0.clone(),
        secret_versions: row
            .secret_versions
            .0
            .iter()
            .map(|s| proto::SecretInfo {
                name: s.name.clone(),
                version: s.version,
                ..Default::default()
            })
            .collect(),
        source: match row.source.as_str() {
            "dashboard" => proto::ReleaseSource::RELEASE_SOURCE_DASHBOARD,
            "api" => proto::ReleaseSource::RELEASE_SOURCE_API,
            "file" => proto::ReleaseSource::RELEASE_SOURCE_FILE,
            "rollback" => proto::ReleaseSource::RELEASE_SOURCE_ROLLBACK,
            _ => proto::ReleaseSource::RELEASE_SOURCE_UNSPECIFIED,
        }
        .into(),
        rollback_of: row.rollback_of.unwrap_or(0) as u32,
        created_by: row.created_by_name.clone().unwrap_or_default(),
        created_at: timestamp(row.created_at),
        outcome: match row.outcome.as_deref() {
            Some("rolling_out") => proto::ReleaseOutcome::RELEASE_OUTCOME_ROLLING_OUT,
            Some("live") => proto::ReleaseOutcome::RELEASE_OUTCOME_LIVE,
            Some("replaced") => proto::ReleaseOutcome::RELEASE_OUTCOME_REPLACED,
            Some("failed") => proto::ReleaseOutcome::RELEASE_OUTCOME_FAILED,
            Some("superseded") => proto::ReleaseOutcome::RELEASE_OUTCOME_SUPERSEDED,
            _ => proto::ReleaseOutcome::RELEASE_OUTCOME_UNSPECIFIED,
        }
        .into(),
        reason: row.reason.clone().unwrap_or_default(),
        ended_at: row.ended_at.map(timestamp).unwrap_or_default(),
        ..Default::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Manage,
}

impl AppApi {
    async fn member(
        &self,
        caller: &Principal,
        slug: &str,
        needed: Access,
    ) -> Result<Membership, ConnectError> {
        let membership = self
            .state
            .organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(|e| failed(AppsError::Internal(e)))?
            .filter(|m| caller.reaches(m.organisation_id))
            .ok_or_else(|| ConnectError::not_found("no such organisation"))?;
        if needed == Access::Manage && !matches!(membership.role.as_str(), "owner" | "admin") {
            return Err(ConnectError::permission_denied(
                "only owners and admins change an organisation's apps",
            ));
        }
        Ok(membership)
    }
}

fn owned<'a, V: MessageView<'a>>(view: &V) -> Result<V::Owned, ConnectError> {
    view.to_owned_message()
        .map_err(|_| ConnectError::invalid_argument("the request does not decode"))
}

#[allow(refining_impl_trait)]
impl AppService for AppApi {
    async fn create_app(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateAppRequest>,
    ) -> ServiceResult<CreateAppResponse> {
        let caller = principal(&ctx)?;
        let request: CreateAppRequest = owned(&*request)?;
        let membership = self
            .member(&caller, &request.organisation, Access::Manage)
            .await?;
        let view = self
            .state
            .apps()
            .create(
                caller.account_id,
                membership.organisation_id,
                &request.name,
                settings_input(request.settings.as_option()),
            )
            .await
            .map_err(failed)?;
        Response::ok(CreateAppResponse {
            app: MessageField::from(app_message(&view)),
            ..Default::default()
        })
    }

    async fn get_app(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetAppRequest>,
    ) -> ServiceResult<GetAppResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let view = self
            .state
            .apps()
            .get(membership.organisation_id, request.name)
            .await
            .map_err(failed)?;
        Response::ok(GetAppResponse {
            app: MessageField::from(app_message(&view)),
            ..Default::default()
        })
    }

    async fn list_apps(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListAppsRequest>,
    ) -> ServiceResult<ListAppsResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let views = self
            .state
            .apps()
            .list(membership.organisation_id)
            .await
            .map_err(failed)?;
        Response::ok(ListAppsResponse {
            apps: views.iter().map(app_message).collect(),
            ..Default::default()
        })
    }

    async fn deploy(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeployRequest>,
    ) -> ServiceResult<DeployResponse> {
        let caller = principal(&ctx)?;
        let request: DeployRequest = owned(&*request)?;
        let membership = self
            .member(&caller, &request.organisation, Access::Manage)
            .await?;
        let input = match &request.source {
            Some(proto::deploy_request::Source::Spec(spec)) => DeployInput::Spec(spec_input(spec)),
            Some(proto::deploy_request::Source::GrundToml(text)) => DeployInput::File(text.clone()),
            None => {
                return Err(refusal(
                    ConnectError::invalid_argument("give a spec or a grund.toml"),
                    "spec_invalid",
                ));
            }
        };
        let release = self
            .state
            .apps()
            .deploy(
                caller.account_id,
                membership.organisation_id,
                &request.name,
                input,
                ReleaseSource::Api,
                &request.note,
            )
            .await
            .map_err(failed)?;
        Response::ok(DeployResponse {
            release: MessageField::from(release_message(&release)),
            ..Default::default()
        })
    }

    async fn list_releases(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListReleasesRequest>,
    ) -> ServiceResult<ListReleasesResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Read)
            .await?;
        let releases = self
            .state
            .apps()
            .releases(membership.organisation_id, request.name)
            .await
            .map_err(failed)?;
        Response::ok(ListReleasesResponse {
            releases: releases.iter().map(release_message).collect(),
            ..Default::default()
        })
    }

    async fn rollback(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RollbackRequest>,
    ) -> ServiceResult<RollbackResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let release = self
            .state
            .apps()
            .rollback(
                caller.account_id,
                membership.organisation_id,
                request.name,
                request.release,
            )
            .await
            .map_err(failed)?;
        Response::ok(RollbackResponse {
            release: MessageField::from(release_message(&release)),
            ..Default::default()
        })
    }

    async fn scale(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScaleRequest>,
    ) -> ServiceResult<ScaleResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let view = self
            .state
            .apps()
            .scale(
                caller.account_id,
                membership.organisation_id,
                request.name,
                request.copies,
            )
            .await
            .map_err(failed)?;
        Response::ok(ScaleResponse {
            app: MessageField::from(app_message(&view)),
            ..Default::default()
        })
    }

    async fn configure_app(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ConfigureAppRequest>,
    ) -> ServiceResult<ConfigureAppResponse> {
        let caller = principal(&ctx)?;
        let request: ConfigureAppRequest = owned(&*request)?;
        let membership = self
            .member(&caller, &request.organisation, Access::Manage)
            .await?;
        let view = self
            .state
            .apps()
            .configure(
                caller.account_id,
                membership.organisation_id,
                &request.name,
                settings_input(request.settings.as_option()),
            )
            .await
            .map_err(failed)?;
        Response::ok(ConfigureAppResponse {
            app: MessageField::from(app_message(&view)),
            ..Default::default()
        })
    }

    async fn set_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetSecretRequest>,
    ) -> ServiceResult<SetSecretResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        let (name, version, at) = self
            .state
            .apps()
            .set_secret(
                caller.account_id,
                membership.organisation_id,
                request.name,
                request.secret,
                request.value,
            )
            .await
            .map_err(failed)?;
        Response::ok(SetSecretResponse {
            secret: MessageField::from(proto::SecretInfo {
                name,
                version: version as u32,
                updated_at: timestamp(at),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    async fn delete_app(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteAppRequest>,
    ) -> ServiceResult<DeleteAppResponse> {
        let caller = principal(&ctx)?;
        let membership = self
            .member(&caller, request.organisation, Access::Manage)
            .await?;
        self.state
            .apps()
            .delete(caller.account_id, membership.organisation_id, request.name)
            .await
            .map_err(failed)?;
        Response::ok(DeleteAppResponse::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spec_survives_the_wire_both_ways() {
        let spec = AppSpec {
            image: "ghcr.io/acme/shop:1".into(),
            command: vec!["./shop".into()],
            ports: vec![PortSpec {
                name: "http".into(),
                port: 8080,
                protocol: Protocol::H2c,
                public: true,
            }],
            memory_mib: 256,
            cpu_millis: 500,
            env: vec![EnvVar {
                name: "A".into(),
                value: "b".into(),
            }],
            secrets: vec![SecretEnv {
                env: "P".into(),
                secret: "p".into(),
            }],
            check: Some(CheckSpec {
                kind: CheckKind::Tcp,
                port: 8080,
                interval_ms: 2000,
                timeout_ms: 1000,
            }),
            stop: StopSpec::default(),
        };
        assert_eq!(spec_input(&spec_message(&spec)), spec);
    }
}
