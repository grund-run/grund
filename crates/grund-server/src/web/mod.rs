//! The HTTP surface: health, pages and (later) the API, behind one set of
//! security headers.
//!
//! ```text
//!   request ─► trace ─► security headers ─► panic guard ─► timeout
//!           ─► /health/live, /health/ready
//!           └► pages (server-rendered minijinja)
//! ```

use axum::{
    Router,
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use tower_http::{
    catch_panic::CatchPanicLayer, set_header::SetResponseHeaderLayer, timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{health, state::State};

/// Everything a page may load comes from this origin: no inline script or
/// style, no framing, forms post only here. Loosening a directive is a
/// reviewed code change, never configuration.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; \
    form-action 'self'; frame-ancestors 'none'";

const PERMISSIONS_POLICY: &str =
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()";

/// The whole HTTP surface. The security headers sit outside the timeout and
/// the panic guard, so their answers carry them too; a handler that must be
/// stricter (no-referrer on a page whose URL carries a token) sets its own and
/// the layer leaves it alone. The trace span records method and path only,
/// because query strings carry tokens.
pub fn router(state: State) -> Router {
    let timeout = state.config.request_timeout;
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .fallback(not_found)
        .with_state(state)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            timeout,
        ))
        .layer(CatchPanicLayer::new())
        .layer(header_layer(header::CONTENT_SECURITY_POLICY, CSP))
        .layer(header_layer(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(header_layer(header::REFERRER_POLICY, "strict-origin-when-cross-origin"))
        .layer(header_layer(header::X_FRAME_OPTIONS, "DENY"))
        .layer(header_layer(
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ))
        .layer(header_layer(
            HeaderName::from_static("permissions-policy"),
            PERMISSIONS_POLICY,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(|request: &Request| {
            tracing::info_span!("request", method = %request.method(), path = %request.uri().path())
        }))
}

fn header_layer(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}
