//! The access check `grund relay`s ask (grund-docs design/network.md
//! §10.2): which keys a relay of this instance may admit, answered by the
//! same policy as the relay in this process ([`crate::relay::Database`]).
//!
//! - `POST /relay/v1/access` is iroh-relay's `access.http` callout: the key
//!   in `X-Iroh-NodeId`, and `200` with the body `true` to admit it. An
//!   upstream iroh-relay configured with this URL and the token works too.
//! - `POST /relay/v1/access/current` asks for many keys at once, `{"keys":
//!   [...]}` to `{"admitted": [...]}`: what `grund relay` sends when a
//!   machine connects, and every sweep of the keys connected to it.
//!
//! Both need `Authorization: Bearer <GRUND_RELAY_ACCESS_TOKEN>`, compared in
//! constant time. Without the token configured they answer 404, as if they
//! did not exist.

use std::str::FromStr;

use axum::{
    Json, Router,
    body::Bytes,
    extract::State as AxumState,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use grund_net::relay::EndpointId;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::{
    relay::{Database, KeyPolicy, MAX_KEYS_PER_CHECK},
    state::State,
};

/// The access routes, to merge into the API router.
pub fn router(state: State) -> Router {
    Router::new()
        .route("/relay/v1/access", post(one))
        .route("/relay/v1/access/current", post(many))
        .with_state(state)
}

fn refused(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "code": code }))).into_response()
}

fn unauthorised(state: &State, headers: &HeaderMap) -> Option<Response> {
    let Some(expected) = state.config.relay.relay_access_token.as_deref() else {
        return Some(refused(StatusCode::NOT_FOUND, "not_found"));
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) {
        None
    } else {
        Some(refused(StatusCode::UNAUTHORIZED, "unauthenticated"))
    }
}

async fn one(AxumState(state): AxumState<State>, headers: HeaderMap) -> Response {
    if let Some(response) = unauthorised(&state, &headers) {
        return response;
    }
    let Some(key) = headers
        .get("x-iroh-nodeid")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| EndpointId::from_str(v.trim()).ok())
    else {
        return refused(StatusCode::BAD_REQUEST, "invalid_key");
    };
    match Database::new(state.pool.clone()).admitted(&[key]).await {
        Ok(admitted) if admitted.contains(&key) => (StatusCode::OK, "true").into_response(),
        Ok(_) => (StatusCode::FORBIDDEN, "false").into_response(),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "relay access: could not check a key");
            refused(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}

async fn many(AxumState(state): AxumState<State>, headers: HeaderMap, body: Bytes) -> Response {
    if let Some(response) = unauthorised(&state, &headers) {
        return response;
    }
    let Ok(request) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid_body");
    };
    let Some(keys) = request["keys"].as_array() else {
        return refused(StatusCode::BAD_REQUEST, "invalid_body");
    };
    if keys.len() > MAX_KEYS_PER_CHECK {
        return refused(StatusCode::BAD_REQUEST, "too_many_keys");
    }
    let Some(keys) = keys
        .iter()
        .map(|k| k.as_str().and_then(|k| EndpointId::from_str(k).ok()))
        .collect::<Option<Vec<_>>>()
    else {
        return refused(StatusCode::BAD_REQUEST, "invalid_key");
    };
    match Database::new(state.pool.clone()).admitted(&keys).await {
        Ok(admitted) => {
            let admitted: Vec<String> = keys
                .iter()
                .filter(|k| admitted.contains(*k))
                .map(ToString::to_string)
                .collect();
            Json(json!({ "admitted": admitted })).into_response()
        }
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "relay access: could not check keys");
            refused(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}
