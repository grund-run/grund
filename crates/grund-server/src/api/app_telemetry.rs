//! Machine-signed customer telemetry ingestion and member-authorized app reads.

use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_proto::grund::{agent::v1 as agent, app::v1 as app};
use uuid::Uuid;

use crate::{
    api::principal,
    services::{
        OrganisationsState,
        agents::MachineCaller,
        app_telemetry::{AppTelemetryState, Invalid},
        apps::AppsState,
    },
    state::State,
};

fn eligible_batch(batch_id: &str, now_millis: i64, max_age_hours: u32) -> Result<(), ConnectError> {
    let id = Uuid::parse_str(batch_id)
        .map_err(|_| ConnectError::invalid_argument("batch_id must be a UUIDv7"))?;
    if id.get_version_num() != 7 || id.get_variant() != uuid::Variant::RFC4122 {
        return Err(ConnectError::invalid_argument("batch_id must be a UUIDv7"));
    }
    let mut timestamp = [0u8; 8];
    timestamp[2..].copy_from_slice(&id.as_bytes()[..6]);
    let created_millis = i64::from_be_bytes(timestamp);
    if created_millis > now_millis + 30_000 {
        return Err(ConnectError::invalid_argument("batch_id is in the future"));
    }
    if now_millis - created_millis > i64::from(max_age_hours) * 3_600_000 {
        return Err(ConnectError::out_of_range("batch delivery window expired"));
    }
    Ok(())
}

fn failed(error: anyhow::Error) -> ConnectError {
    if let Some(error) = error.downcast_ref::<Invalid>() {
        return ConnectError::invalid_argument(error.to_string());
    }
    if let Some(error) = error.downcast_ref::<grund_store::app_telemetry::IngestError>() {
        use grund_store::app_telemetry::IngestError;
        match error {
            IngestError::Identity => return ConnectError::not_found("no such app placement"),
            IngestError::Conflict => return ConnectError::already_exists(error.to_string()),
            IngestError::Capacity => return ConnectError::resource_exhausted(error.to_string()),
            IngestError::Store(_) => {}
        }
    }
    tracing::warn!(error = %error, "app telemetry unavailable");
    ConnectError::unavailable("app telemetry is temporarily unavailable")
}

/// Member and scoped-token query service.
pub struct AppTelemetryApi {
    state: State,
}
impl AppTelemetryApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn app(
        &self,
        ctx: &RequestContext,
        organisation: &str,
        name: &str,
    ) -> Result<(Uuid, Uuid), ConnectError> {
        let caller = principal(ctx)?;
        let member = self
            .state
            .organisations()
            .membership(organisation, caller.account_id)
            .await
            .map_err(failed)?
            .filter(|m| caller.reaches(m.organisation_id))
            .filter(|m| matches!(m.role.as_str(), "owner" | "admin" | "member"))
            .ok_or_else(|| ConnectError::not_found("no such app"))?;
        caller.check_app(name)?;
        let view = self
            .state
            .apps()
            .get(member.organisation_id, name)
            .await
            .map_err(|error| match error {
                crate::services::apps::AppsError::NotFound => {
                    ConnectError::not_found("no such app")
                }
                error => failed(error.into()),
            })?;
        Ok((member.organisation_id, view.row.app_id))
    }
}

#[allow(refining_impl_trait)]
impl app::AppTelemetryService for AppTelemetryApi {
    async fn list_app_logs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, app::ListAppLogsRequest>,
    ) -> ServiceResult<app::ListAppLogsResponse> {
        let (org, app) = self.app(&ctx, request.organisation, request.name).await?;
        let response = self
            .state
            .app_telemetry()
            .logs(org, app, &request.to_owned_message())
            .await
            .map_err(failed)?;
        Response::ok(response)
    }

    async fn get_app_metrics(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, app::GetAppMetricsRequest>,
    ) -> ServiceResult<app::GetAppMetricsResponse> {
        let (org, app) = self.app(&ctx, request.organisation, request.name).await?;
        let response = self
            .state
            .app_telemetry()
            .metrics(org, app, &request.to_owned_message())
            .await
            .map_err(failed)?;
        Response::ok(response)
    }
}

/// Existing-machine-key ingestion service, never a public OTLP endpoint.
pub struct AgentTelemetryApi {
    state: State,
}
impl AgentTelemetryApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}
#[allow(refining_impl_trait)]
impl agent::AppTelemetryService for AgentTelemetryApi {
    async fn export_telemetry(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, agent::ExportTelemetryRequest>,
    ) -> ServiceResult<agent::ExportTelemetryResponse> {
        let caller = ctx
            .extensions()
            .get::<MachineCaller>()
            .ok_or_else(|| ConnectError::unauthenticated("sign with the machine key"))?;
        eligible_batch(
            request.batch_id,
            chrono::Utc::now().timestamp_millis(),
            self.state.config.app_telemetry_batch_max_age_hours,
        )?;
        let response = self
            .state
            .app_telemetry()
            .export(caller, &request.to_owned_message())
            .await
            .map_err(failed)?;
        Response::ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(at: i64) -> String {
        let mut bytes = [0; 16];
        bytes[..6].copy_from_slice(&at.to_be_bytes()[2..]);
        bytes[6] = 0x70;
        bytes[8] = 0x80;
        Uuid::from_bytes(bytes).to_string()
    }

    #[test]
    fn batch_delivery_includes_the_exact_age_boundary_but_not_one_millisecond_later() {
        let created = 1_800_000_000_000;
        let id = batch(created);
        assert!(eligible_batch(&id, created, 6).is_ok());
        assert!(eligible_batch(&id, created + 6 * 3_600_000, 6).is_ok());
        assert_eq!(
            eligible_batch(&id, created + 6 * 3_600_000 + 1, 6)
                .unwrap_err()
                .code,
            connectrpc::ErrorCode::OutOfRange
        );
        assert!(eligible_batch(&id, created + 7 * 3_600_000, 8).is_ok());
    }

    #[test]
    fn ordinary_machine_clock_skew_does_not_discard_fresh_batches() {
        let now = 1_800_000_000_000;
        assert!(eligible_batch(&batch(now + 1), now, 6).is_ok());
        assert!(eligible_batch(&batch(now + 30_000), now, 6).is_ok());
        assert_eq!(
            eligible_batch(&batch(now + 30_001), now, 6)
                .unwrap_err()
                .code,
            connectrpc::ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn excessive_future_skew_or_unsupported_ids_never_enter_the_receipt_store() {
        let now = 1_800_000_000_000;
        for id in [
            batch(now + 30_001),
            "not-a-uuid".into(),
            Uuid::nil().to_string(),
            "00000000-0000-4000-8000-000000000000".into(),
            "00000000-0000-7000-c000-000000000000".into(),
        ] {
            assert_eq!(
                eligible_batch(&id, now, 6).unwrap_err().code,
                connectrpc::ErrorCode::InvalidArgument
            );
        }
    }

    #[test]
    fn a_re_signed_batch_stays_ineligible_after_its_receipt_expires() {
        let created = 1_800_000_000_000;
        let id = batch(created);
        assert!(eligible_batch(&id, created, 6).is_ok());
        for accepted_after in [0, 6 * 3_600_000] {
            let receipt_expiry = created + accepted_after + 7 * 3_600_000;
            assert_eq!(
                eligible_batch(&id, receipt_expiry, 6).unwrap_err().code,
                connectrpc::ErrorCode::OutOfRange
            );
        }
    }
}
