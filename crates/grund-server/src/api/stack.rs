//! Organisation-scoped stack reads and full-token or session-authorised changes.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::{MessageField, MessageView};
use buffa_types::google::protobuf::Timestamp;
use connectrpc::{
    ConnectError, ErrorDetail, RequestContext, Response, ServiceRequest, ServiceResult,
};
use grund_proto::grund::stack::v1::{self as proto, *};
use uuid::Uuid;

use crate::{
    api::{Principal, principal},
    services::{
        OrganisationsState,
        stacks::{Error, InputSecret, Preview, ServiceView, StackView, StacksState, VolumeView},
        tokens::{TokenCaller, TokenScope},
    },
    state::State,
};

pub struct StackApi {
    state: State,
}

impl StackApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn member(
        &self,
        caller: &Principal,
        slug: &str,
        manage: bool,
    ) -> Result<Uuid, ConnectError> {
        let membership = self
            .state
            .organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(|error| failed(Error::Internal(error)))?
            .filter(|member| caller.reaches(member.organisation_id))
            .ok_or_else(|| ConnectError::not_found("no such organisation"))?;
        if manage && !matches!(membership.role.as_str(), "owner" | "admin") {
            return Err(ConnectError::permission_denied(
                "only owners and admins change stacks",
            ));
        }
        Ok(membership.organisation_id)
    }
}

fn failed(error: Error) -> ConnectError {
    let base = match &error {
        Error::NotFound => ConnectError::not_found(error.to_string()),
        Error::Invalid(_) => ConnectError::invalid_argument(error.to_string()),
        Error::Conflict => ConnectError::aborted(error.to_string()),
        Error::IdempotencyConflict => ConnectError::already_exists(error.to_string()),
        Error::Busy | Error::Owned => ConnectError::failed_precondition(error.to_string()),
        Error::Internal(cause) => {
            tracing::error!(error = %format!("{cause:#}"), "stack API call failed");
            ConnectError::internal("grund could not finish that")
        }
    };
    base.with_detail(ErrorDetail::from_message(
        "grund.stack.v1.ErrorReason",
        &ErrorReason {
            reason: error.reason().to_string(),
            ..Default::default()
        },
    ))
}

fn service(view: ServiceView) -> proto::Service {
    proto::Service {
        name: view.name,
        app_id: view.app_id.to_string(),
        image: view.image,
        status: view.status,
        ready: view.ready,
        copies: view.copies,
        desired_release: view.release,
        observed_running_releases: view.observed_running_releases,
        exclusive: view.exclusive,
        app_name: view.app_name,
        template: view.template.unwrap_or_default(),
        volume_intents: view.volume_intents.into_iter().map(volume_intent).collect(),
        ..Default::default()
    }
}

fn volume_intent(view: crate::services::stacks::VolumeIntent) -> proto::VolumeIntent {
    proto::VolumeIntent {
        name: view.name,
        path: view.path,
        kind: view.kind,
        size_gib: view.size_gib,
        backup_requested: view.backup_requested,
        backup_policy: view.backup_policy,
        ..Default::default()
    }
}

fn volume(view: VolumeView) -> proto::Volume {
    proto::Volume {
        service: view.service,
        app_id: view.app_id.to_string(),
        app_name: view.app_name,
        volume_id: view.volume_id.to_string(),
        storage: MessageField::from(volume_intent(view.storage)),
        status: view.status,
        retained: view.retained,
        purge_after: view
            .purge_after
            .map(|at| {
                MessageField::from(Timestamp::from_unix(
                    at.timestamp(),
                    at.timestamp_subsec_nanos() as i32,
                ))
            })
            .unwrap_or_default(),
        ..Default::default()
    }
}

fn stack(view: StackView) -> proto::Stack {
    proto::Stack {
        id: view.id.to_string(),
        name: view.name,
        status: view.status,
        version: view.version,
        revision: view.revision,
        machine_id: view.machine_id.map(|id| id.to_string()).unwrap_or_default(),
        address: view.address.unwrap_or_default(),
        services: view.services.into_iter().map(service).collect(),
        operation: view.operation.unwrap_or_default(),
        failure: view.failure.unwrap_or_default(),
        yaml: view.yaml,
        volumes: view.volumes.into_iter().map(volume).collect(),
        ..Default::default()
    }
}

fn preview(view: Preview) -> proto::Preview {
    proto::Preview {
        name: view.name,
        expected_version: view.expected_version,
        services: view.services.into_iter().map(service).collect(),
        memory_mib: view.memory_mib,
        cpu_millis: view.cpu_millis,
        peak_memory_mib: view.peak_memory_mib,
        peak_cpu_millis: view.peak_cpu_millis,
        selected_machine: view
            .selected_machine
            .map(|id| id.to_string())
            .unwrap_or_default(),
        waiting: view.waiting.unwrap_or_default(),
        removed_services: view.removed_services,
        ..Default::default()
    }
}

fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn owned<'a, V: MessageView<'a>>(view: &V) -> Result<V::Owned, ConnectError> {
    view.to_owned_message()
        .map_err(|_| ConnectError::invalid_argument("the request does not decode"))
}

fn changes(ctx: &RequestContext) -> Result<(), ConnectError> {
    if ctx
        .extensions()
        .get::<TokenCaller>()
        .is_some_and(|token| token.scope != TokenScope::Full || token.apps.is_some())
    {
        return Err(ConnectError::permission_denied(
            "stack changes need a full token",
        ));
    }
    Ok(())
}

fn mutation(expected: Option<i64>, key: &str, create: bool) -> Result<(), ConnectError> {
    if expected.is_none() && !create {
        return Err(ConnectError::invalid_argument(
            "expected_version is required",
        ));
    }
    if expected.is_some_and(|version| version < 0) {
        return Err(ConnectError::invalid_argument(
            "expected_version must not be negative",
        ));
    }
    if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(ConnectError::invalid_argument(
            "idempotency_key must be 1–128 printable ASCII bytes",
        ));
    }
    Ok(())
}

fn cursor(org: Uuid, after: Uuid) -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(org.as_bytes());
    bytes[16..].copy_from_slice(after.as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

fn page(org: Uuid, size: i32, token: &str) -> Result<(u32, Option<Uuid>), ConnectError> {
    if size < 0 {
        return Err(ConnectError::invalid_argument(
            "page_size must not be negative",
        ));
    }
    let limit = if size == 0 { 50 } else { size.min(100) as u32 };
    if token.is_empty() {
        return Ok((limit, None));
    }
    let invalid = || ConnectError::invalid_argument("invalid page_token for this organisation");
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| invalid())?;
    if bytes.len() != 32 || &bytes[..16] != org.as_bytes() {
        return Err(invalid());
    }
    Ok((
        limit,
        Some(Uuid::from_slice(&bytes[16..]).map_err(|_| invalid())?),
    ))
}

#[allow(refining_impl_trait)]
impl StackService for StackApi {
    async fn preview_stack(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PreviewStackRequest>,
    ) -> ServiceResult<PreviewStackResponse> {
        let caller = principal(&ctx)?;
        let org = self.member(&caller, request.organisation, false).await?;
        let view = self
            .state
            .stacks()
            .preview(
                org,
                request.yaml,
                optional(request.service),
                optional(request.refresh_template),
                caller.apps.as_deref(),
            )
            .await
            .map_err(failed)?;
        Response::ok(PreviewStackResponse {
            preview: MessageField::from(preview(view)),
            ..Default::default()
        })
    }

    async fn deploy_stack(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeployStackRequest>,
    ) -> ServiceResult<DeployStackResponse> {
        let caller = principal(&ctx)?;
        let input: DeployStackRequest = owned(&*request)?;
        let org = self.member(&caller, &input.organisation, true).await?;
        changes(&ctx)?;
        mutation(input.expected_version, &input.idempotency_key, true)?;
        let view = self
            .state
            .stacks()
            .deploy(
                caller.account_id,
                org,
                &input.yaml,
                optional(&input.service),
                optional(&input.refresh_template),
                input.expected_version,
                &input.idempotency_key,
                input
                    .secrets
                    .into_iter()
                    .map(|secret| InputSecret {
                        service: secret.service,
                        name: secret.name,
                        value: secret.value,
                    })
                    .collect(),
                input.confirmed_removals,
            )
            .await
            .map_err(failed)?;
        Response::ok(DeployStackResponse {
            stack: MessageField::from(stack(view)),
            ..Default::default()
        })
    }

    async fn get_stack(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetStackRequest>,
    ) -> ServiceResult<GetStackResponse> {
        let caller = principal(&ctx)?;
        let org = self.member(&caller, request.organisation, false).await?;
        let view = self
            .state
            .stacks()
            .get(org, request.name, caller.apps.as_deref())
            .await
            .map_err(failed)?;
        Response::ok(GetStackResponse {
            stack: MessageField::from(stack(view)),
            ..Default::default()
        })
    }

    async fn list_stacks(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListStacksRequest>,
    ) -> ServiceResult<ListStacksResponse> {
        let caller = principal(&ctx)?;
        let org = self.member(&caller, request.organisation, false).await?;
        let (limit, after) = page(org, request.page_size, request.page_token)?;
        let mut views = self
            .state
            .stacks()
            .list(org, limit, after, caller.apps.as_deref())
            .await
            .map_err(failed)?;
        let next_page_token = if views.len() > limit as usize {
            views.truncate(limit as usize);
            views
                .last()
                .map(|view| cursor(org, view.id))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Response::ok(ListStacksResponse {
            stacks: views.into_iter().map(stack).collect(),
            next_page_token,
            ..Default::default()
        })
    }

    async fn restart_stack(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RestartStackRequest>,
    ) -> ServiceResult<RestartStackResponse> {
        let caller = principal(&ctx)?;
        let org = self.member(&caller, request.organisation, true).await?;
        changes(&ctx)?;
        mutation(request.expected_version, request.idempotency_key, false)?;
        let view = self
            .state
            .stacks()
            .restart(
                caller.account_id,
                org,
                request.name,
                optional(request.service),
                request.expected_version,
                request.idempotency_key,
            )
            .await
            .map_err(failed)?;
        Response::ok(RestartStackResponse {
            stack: MessageField::from(stack(view)),
            ..Default::default()
        })
    }

    async fn rollback_stack(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RollbackStackRequest>,
    ) -> ServiceResult<RollbackStackResponse> {
        let caller = principal(&ctx)?;
        let org = self.member(&caller, request.organisation, true).await?;
        changes(&ctx)?;
        mutation(request.expected_version, request.idempotency_key, false)?;
        let view = self
            .state
            .stacks()
            .rollback(
                caller.account_id,
                org,
                request.name,
                request.revision,
                request.expected_version,
                request.idempotency_key,
            )
            .await
            .map_err(failed)?;
        Response::ok(RollbackStackResponse {
            stack: MessageField::from(stack(view)),
            ..Default::default()
        })
    }

    async fn delete_stack(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteStackRequest>,
    ) -> ServiceResult<DeleteStackResponse> {
        let caller = principal(&ctx)?;
        let org = self.member(&caller, request.organisation, true).await?;
        changes(&ctx)?;
        mutation(request.expected_version, request.idempotency_key, false)?;
        let view = self
            .state
            .stacks()
            .delete(
                caller.account_id,
                org,
                request.name,
                request.expected_version,
                request.idempotency_key,
            )
            .await
            .map_err(failed)?;
        Response::ok(DeleteStackResponse {
            stack: MessageField::from(stack(view)),
            ..Default::default()
        })
    }

    async fn restore_stack(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RestoreStackRequest>,
    ) -> ServiceResult<RestoreStackResponse> {
        let caller = principal(&ctx)?;
        let org = self.member(&caller, request.organisation, true).await?;
        changes(&ctx)?;
        mutation(request.expected_version, request.idempotency_key, false)?;
        let view = self
            .state
            .stacks()
            .restore(
                caller.account_id,
                org,
                request.name,
                request.expected_version,
                request.idempotency_key,
            )
            .await
            .map_err(failed)?;
        Response::ok(RestoreStackResponse {
            stack: MessageField::from(stack(view)),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_full_organisation_tokens_or_sessions_can_change_stacks() {
        for (scope, apps, permitted) in [
            (TokenScope::Deploy, None, false),
            (TokenScope::Deploy, Some(vec!["web".to_string()]), false),
            (TokenScope::Full, Some(vec!["web".to_string()]), false),
            (TokenScope::Full, None, true),
        ] {
            let mut extensions = http::Extensions::new();
            extensions.insert(TokenCaller {
                account_id: Uuid::now_v7(),
                token_id: Uuid::now_v7(),
                organisation_id: Uuid::now_v7(),
                scope,
                apps: apps.map(std::sync::Arc::from),
            });
            let ctx = RequestContext::new(http::HeaderMap::new()).with_extensions(extensions);
            if permitted {
                changes(&ctx).unwrap();
            } else {
                assert_eq!(
                    changes(&ctx).unwrap_err().code,
                    connectrpc::ErrorCode::PermissionDenied
                );
            }
        }
        let mut extensions = http::Extensions::new();
        extensions.insert(crate::api::Caller {
            account_id: Uuid::now_v7(),
            session_id: Uuid::now_v7(),
        });
        changes(&RequestContext::new(http::HeaderMap::new()).with_extensions(extensions)).unwrap();
    }

    #[test]
    fn continuation_is_bounded_and_cannot_be_repointed_at_another_organisation() {
        let org = Uuid::now_v7();
        let after = Uuid::now_v7();
        assert_eq!(page(org, 0, "").unwrap(), (50, None));
        assert_eq!(
            page(org, 1000, &cursor(org, after)).unwrap(),
            (100, Some(after))
        );
        assert!(page(Uuid::now_v7(), 50, &cursor(org, after)).is_err());
        assert!(page(org, -1, "").is_err());
        assert!(page(org, 50, "garbage").is_err());
    }

    #[test]
    fn mutations_require_a_version_and_a_printable_idempotency_key() {
        assert!(mutation(None, "key", false).is_err());
        assert!(mutation(None, "key", true).is_ok());
        assert!(mutation(Some(2), "", false).is_err());
        assert!(mutation(Some(-1), "key", false).is_err());
        assert!(mutation(Some(2), "bad\nkey", false).is_err());
        assert!(mutation(Some(2), &"x".repeat(129), false).is_err());
        assert!(mutation(Some(2), "key", false).is_ok());
    }
}
