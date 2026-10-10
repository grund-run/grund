//! Operator-only inventory and hosted access over Connect.

use buffa::MessageField;
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_proto::grund::operator::v1 as proto;
use grund_proto::grund::operator::v1::OperatorService;
use grund_store::{machines, operator};
use serde_json::Value;

use crate::{
    api::{Caller, caller},
    services::{
        capacity::protobuf_i64,
        machines::{Access, MachinesState},
        operator_inventory::OperatorInventory,
    },
    state::State,
};

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "operator request failed");
    ConnectError::internal("the operator request could not be completed")
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_owned()
}

fn number(value: &Value, key: &str) -> i64 {
    protobuf_i64(&value[key])
}

fn time(value: &Value, key: &str) -> MessageField<Timestamp, buffa::Inline<Timestamp>> {
    let Some(at) = value[key]
        .as_str()
        .and_then(|raw| raw.parse::<DateTime<Utc>>().ok())
    else {
        return MessageField::default();
    };
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into()
}

fn capacity(
    value: &Value,
    prefix: &str,
) -> MessageField<proto::ResourceCapacity, buffa::Inline<proto::ResourceCapacity>> {
    let (cpus, memory, disk) = if prefix == "allocated" {
        ("allocatedVcpus", "allocatedMemoryMib", "allocatedDiskGib")
    } else {
        ("vcpus", "memoryMib", "diskGib")
    };
    proto::ResourceCapacity {
        vcpus: number(value, cpus) as i32,
        memory_mib: number(value, memory),
        disk_gib: number(value, disk),
        ..Default::default()
    }
    .into()
}

fn host(value: &Value) -> proto::Host {
    proto::Host {
        id: text(value, "id"),
        name: text(value, "name"),
        state: text(value, "state"),
        provider: text(value, "provider"),
        region: text(value, "region"),
        capacity: capacity(value, "capacity"),
        allocated: capacity(value, "allocated"),
        kernel: text(value, "hostKernel"),
        firecracker_version: text(value, "firecrackerVersion"),
        reachable: value["reachable"].as_bool().unwrap_or(false),
        last_seen_at: time(value, "lastHeartbeatAt"),
        machine_count: number(value, "machineCount") as i32,
        cordon_reason: text(value, "cordonReason"),
        ..Default::default()
    }
}

fn fleet_machine(value: &Value) -> proto::FleetMachine {
    proto::FleetMachine {
        id: text(value, "id"),
        host_id: text(value, "hostId"),
        state: text(value, "state"),
        size: text(value, "size"),
        region: text(value, "region"),
        reason: text(value, "reason"),
        assigned: value["assigned"].as_bool().unwrap_or(false),
        updated_at: time(value, "updatedAt"),
        ..Default::default()
    }
}

fn pool(value: &Value) -> proto::Pool {
    proto::Pool {
        id: text(value, "id"),
        name: text(value, "name"),
        size: text(value, "size"),
        region: text(value, "region"),
        desired: number(value, "desired") as i32,
        warm: number(value, "warm") as i32,
        ready: number(value, "ready") as i32,
        unschedulable_reason: text(value, "unschedulableReason"),
        ..Default::default()
    }
}

fn failure(value: &Value) -> proto::Failure {
    proto::Failure {
        machine_id: text(value, "machineId"),
        host_id: text(value, "hostId"),
        state: text(value, "state"),
        reason: text(value, "reason"),
        updated_at: time(value, "updatedAt"),
        ..Default::default()
    }
}

/// Operator inventory API; every method checks the operator organisation first.
pub struct OperatorApi {
    state: State,
}

impl OperatorApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn access(&self, caller: &Caller, needed: Access) -> Result<(), ConnectError> {
        match self
            .state
            .machines()
            .operator_access(caller.account_id)
            .await
            .map_err(internal)?
        {
            None => Err(ConnectError::not_found("no such operator inventory")),
            Some(Access::Read) if needed == Access::Manage => Err(ConnectError::permission_denied(
                "only operator owners and admins may change inventory",
            )),
            Some(_) => Ok(()),
        }
    }

    async fn list(
        &self,
        method: &str,
        size: i32,
        token: &str,
        host_id: &str,
    ) -> Result<Value, ConnectError> {
        OperatorInventory::new(&self.state)
            .list(method, size, token, host_id)
            .await
            .map_err(|error| {
                tracing::warn!(%error, method, "operator inventory unavailable");
                ConnectError::unavailable("operator inventory is unavailable")
            })
    }

    async fn change_host(
        &self,
        method: &str,
        host_id: &str,
        reason: &str,
    ) -> Result<proto::Host, ConnectError> {
        let result = OperatorInventory::new(&self.state)
            .host_action(method, host_id, reason)
            .await
            .map_err(|error| {
                tracing::warn!(%error, method, "operator host change refused");
                ConnectError::failed_precondition("host change could not be completed")
            })?;
        result
            .get("host")
            .map(host)
            .ok_or_else(|| internal("capacity host response is missing"))
    }
}

#[allow(refining_impl_trait)]
impl OperatorService for OperatorApi {
    async fn list_hosts(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListHostsRequest>,
    ) -> ServiceResult<proto::ListHostsResponse> {
        self.access(&caller(&ctx)?, Access::Read).await?;
        let answer = self
            .list(
                "ListInventoryHosts",
                request.page_size,
                request.page_token,
                "",
            )
            .await?;
        Response::ok(proto::ListHostsResponse {
            hosts: answer["hosts"]
                .as_array()
                .into_iter()
                .flatten()
                .map(host)
                .collect(),
            next_page_token: text(&answer, "nextPageToken"),
            ..Default::default()
        })
    }

    async fn list_fleet_machines(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListFleetMachinesRequest>,
    ) -> ServiceResult<proto::ListFleetMachinesResponse> {
        self.access(&caller(&ctx)?, Access::Read).await?;
        let answer = self
            .list(
                "ListInventoryMachines",
                request.page_size,
                request.page_token,
                request.host_id,
            )
            .await?;
        Response::ok(proto::ListFleetMachinesResponse {
            machines: answer["machines"]
                .as_array()
                .into_iter()
                .flatten()
                .map(fleet_machine)
                .collect(),
            next_page_token: text(&answer, "nextPageToken"),
            ..Default::default()
        })
    }

    async fn list_pools(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListPoolsRequest>,
    ) -> ServiceResult<proto::ListPoolsResponse> {
        self.access(&caller(&ctx)?, Access::Read).await?;
        let answer = self
            .list(
                "ListInventoryPools",
                request.page_size,
                request.page_token,
                "",
            )
            .await?;
        Response::ok(proto::ListPoolsResponse {
            pools: answer["pools"]
                .as_array()
                .into_iter()
                .flatten()
                .map(pool)
                .collect(),
            next_page_token: text(&answer, "nextPageToken"),
            ..Default::default()
        })
    }

    async fn list_failures(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListFailuresRequest>,
    ) -> ServiceResult<proto::ListFailuresResponse> {
        self.access(&caller(&ctx)?, Access::Read).await?;
        let answer = self
            .list(
                "ListInventoryFailures",
                request.page_size,
                request.page_token,
                "",
            )
            .await?;
        Response::ok(proto::ListFailuresResponse {
            failures: answer["failures"]
                .as_array()
                .into_iter()
                .flatten()
                .map(failure)
                .collect(),
            next_page_token: text(&answer, "nextPageToken"),
            ..Default::default()
        })
    }

    async fn cordon_host(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::CordonHostRequest>,
    ) -> ServiceResult<proto::CordonHostResponse> {
        self.access(&caller(&ctx)?, Access::Manage).await?;
        Response::ok(proto::CordonHostResponse {
            host: MessageField::from(
                self.change_host("CordonInventoryHost", request.host_id, request.reason)
                    .await?,
            ),
            ..Default::default()
        })
    }

    async fn uncordon_host(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::UncordonHostRequest>,
    ) -> ServiceResult<proto::UncordonHostResponse> {
        self.access(&caller(&ctx)?, Access::Manage).await?;
        Response::ok(proto::UncordonHostResponse {
            host: MessageField::from(
                self.change_host("UncordonInventoryHost", request.host_id, "")
                    .await?,
            ),
            ..Default::default()
        })
    }

    async fn drain_host(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::DrainHostRequest>,
    ) -> ServiceResult<proto::DrainHostResponse> {
        self.access(&caller(&ctx)?, Access::Manage).await?;
        Response::ok(proto::DrainHostResponse {
            host: MessageField::from(
                self.change_host("DrainInventoryHost", request.host_id, "")
                    .await?,
            ),
            ..Default::default()
        })
    }

    async fn list_entitlements(
        &self,
        ctx: RequestContext,
        _: ServiceRequest<'_, proto::ListEntitlementsRequest>,
    ) -> ServiceResult<proto::ListEntitlementsResponse> {
        self.access(&caller(&ctx)?, Access::Read).await?;
        let organisations = operator::hosted_organisations(&self.state.pool)
            .await
            .map_err(internal)?;
        Response::ok(proto::ListEntitlementsResponse {
            organisations: organisations
                .into_iter()
                .map(|organisation| proto::HostedEntitlement {
                    organisation: organisation.slug,
                    enabled: organisation.enabled,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn set_hosted_entitlement(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::SetHostedEntitlementRequest>,
    ) -> ServiceResult<proto::SetHostedEntitlementResponse> {
        self.access(&caller(&ctx)?, Access::Manage).await?;
        let organisation_id =
            machines::live_organisation_by_slug(&self.state.pool, request.organisation)
                .await
                .map_err(internal)?
                .ok_or_else(|| ConnectError::not_found("no such organisation"))?;
        self.state
            .machines()
            .grant_hosted(organisation_id, request.enabled)
            .await
            .map_err(internal)?;
        Response::ok(proto::SetHostedEntitlementResponse {
            organisation: proto::HostedEntitlement {
                organisation: request.organisation.to_owned(),
                enabled: request.enabled,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_api_keeps_protobuf_json_host_capacity() {
        let source = serde_json::json!({
            "id": "host-id",
            "name": "test-host",
            "vcpus": 2,
            "memoryMib": "1536",
            "diskGib": "6",
            "allocatedVcpus": 1,
            "allocatedMemoryMib": "512",
            "allocatedDiskGib": "2"
        });
        let mapped = host(&source);
        let total = mapped.capacity.as_option().unwrap();
        let used = mapped.allocated.as_option().unwrap();
        assert_eq!(
            (
                total.memory_mib - used.memory_mib,
                total.disk_gib - used.disk_gib
            ),
            (1024, 4)
        );
        assert_eq!(total.vcpus - used.vcpus, 1);
    }
}
