//! Operator-only inventory from the configured capacity provider. Access is
//! checked by the page and Connect handlers before any provider call.

use serde_json::{Value, json};

use crate::{
    services::capacity::{Capacity, CapacityError},
    state::State,
};

/// The operator's capacity-provider view. No customer handler calls this type.
#[derive(Clone)]
pub struct OperatorInventory {
    capacity: Capacity,
}

impl OperatorInventory {
    /// Builds the inventory reader for this instance.
    pub fn new(state: &State) -> Self {
        Self {
            capacity: state.capacity.clone(),
        }
    }

    /// Reads one page of a provider inventory resource.
    pub async fn list(
        &self,
        method: &str,
        page_size: i32,
        page_token: &str,
        host_id: &str,
    ) -> Result<Value, CapacityError> {
        self.capacity
            .call(
                method,
                &json!({
                    "pageSize": page_size,
                    "pageToken": page_token,
                    "hostId": host_id,
                }),
            )
            .await
    }

    /// Changes host admission or begins draining it.
    pub async fn host_action(
        &self,
        method: &str,
        host_id: &str,
        reason: &str,
    ) -> Result<Value, CapacityError> {
        self.capacity
            .call(method, &json!({ "hostId": host_id, "reason": reason }))
            .await
    }
}
