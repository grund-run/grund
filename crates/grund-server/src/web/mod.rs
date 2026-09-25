//! The HTTP surface: health, pages and static files, behind one set of
//! security headers.
//!
//! ```text
//!   request ─► trace ─► security headers ─► panic guard ─► timeout ─► body limit
//!           ─► request context (request id; failed pages rendered and logged)
//!           ─► /health/live, /health/ready, /static/*
//!           └► pages (server-rendered minijinja)
//! ```

pub mod assets;
pub mod browser;
pub mod pages;

use axum::{
    Router,
    extract::{Request, State as AxumState},
    http::{HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use minijinja::context;
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer, trace::TraceLayer,
};
use uuid::Uuid;

use crate::{health, state::State, web::browser::RequestId};

/// Everything a page may load comes from this origin: no inline script or
/// style, no framing, forms post only here. Loosening a directive is a
/// reviewed code change, never configuration.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; \
    form-action 'self'; frame-ancestors 'none'";

const PERMISSIONS_POLICY: &str =
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()";

/// The largest request body grund accepts. The biggest form field is a
/// 1024-byte password.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// The whole HTTP surface. The security headers sit outside the timeout and
/// the panic guard, so their answers carry them too; a handler that must be
/// stricter sets its own and the layer leaves it alone: a page whose URL
/// carries a token sends `Referrer-Policy: same-origin`, so the token never
/// reaches another site. Not `no-referrer`: under it a browser posts that
/// page's form with `Origin: null`, which the origin check refuses. The trace span records method and path only,
/// because query strings carry tokens.
pub fn router(state: State) -> Router {
    let timeout = state.config.request_timeout;
    let extensions = state
        .extensions
        .iter()
        .fold(Router::new(), |router, extension| {
            router.merge(extension.routes())
        });
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/static/{*path}", get(assets::serve))
        .route("/", get(pages::home))
        .route("/login", get(pages::login_form).post(pages::login))
        .route("/logout", post(pages::logout))
        .route("/signup", get(pages::signup_form).post(pages::signup))
        .route("/signup/sent", get(pages::signup_sent))
        .route("/verify", get(pages::verify_form).post(pages::verify))
        .route("/reset", get(pages::reset_form).post(pages::reset))
        .route("/reset/sent", get(pages::reset_sent))
        .route("/reset/confirm", get(pages::reset_confirm_form).post(pages::reset_confirm))
        .route("/settings/sessions", get(pages::sessions_page))
        .route("/settings/sessions/revoke-others", post(pages::revoke_other_sessions))
        .route("/settings/sessions/{id}/revoke", post(pages::revoke_session))
        .route("/licenses", get(pages::licenses))
        .route("/style-guide", get(pages::style_guide))
        .merge(extensions)
        .fallback(pages::not_found)
        .layer(middleware::from_fn_with_state(state.clone(), request_context))
        .with_state(state.clone())
        .merge(crate::api::router(state))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(StatusCode::SERVICE_UNAVAILABLE, timeout))
        .layer(CatchPanicLayer::new())
        .layer(header_layer(header::CONTENT_SECURITY_POLICY, CSP))
        .layer(header_layer(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(header_layer(header::REFERRER_POLICY, "strict-origin-when-cross-origin"))
        .layer(header_layer(header::X_FRAME_OPTIONS, "DENY"))
        .layer(header_layer(HeaderName::from_static("cross-origin-opener-policy"), "same-origin"))
        .layer(header_layer(HeaderName::from_static("permissions-policy"), PERMISSIONS_POLICY))
        .layer(TraceLayer::new_for_http().make_span_with(|request: &Request| {
            tracing::info_span!("request", method = %request.method(), path = %request.uri().path())
        }))
}

fn header_layer(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
}

/// Mints the request id every log line and error page refers to, echoes it
/// in `X-Request-Id`, turns a failed handler into the generic error page, and
/// turns axum's plain-text rejection of an unreadable form into a page. A
/// caller's own `X-Request-Id` is never trusted.
pub async fn request_context(
    AxumState(state): AxumState<State>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = Uuid::now_v7();
    request.extensions_mut().insert(RequestId(request_id));
    let mut response = next.run(request).await;
    let plain_text = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/plain"));
    if let Some(pages::Failed(error)) = response.extensions().get::<pages::Failed>().cloned() {
        response = pages::internal_error(&state, request_id, &error);
    } else if plain_text
        && matches!(
            response.status(),
            StatusCode::BAD_REQUEST
                | StatusCode::UNPROCESSABLE_ENTITY
                | StatusCode::UNSUPPORTED_MEDIA_TYPE
                | StatusCode::PAYLOAD_TOO_LARGE
        )
    {
        response = bad_form(&state, response.status(), request_id);
    }
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

fn bad_form(state: &State, status: StatusCode, request_id: Uuid) -> Response {
    let html = state
        .templates
        .render(
            "pages/error.html.jinja",
            context! {
                title => "That form could not be read",
                text => "Go back, reload the page and try again.",
                request_id => request_id.to_string(),
            },
        )
        .unwrap_or_default();
    let mut response = (status, axum::response::Html(html)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
