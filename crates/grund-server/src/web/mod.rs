//! The HTTP surface: health, pages and static files, behind one set of
//! security headers.
//!
//! ```text
//!   request ─► trace ─► security headers ─► panic guard ─► timeout ─► body limit
//!           ├► pages: compression ─► sedx ─► request context ─► pages
//!           ├► static files: request context (no sedx or dynamic compression)
//!           └► Connect: compression ─► secret response policy ─► API
//! ```

macro_rules! member_or_return {
    ($state:expr, $browser:expr, $uri:expr, $slug:expr) => {
        match $crate::web::orgs::member_of($state, $browser, $uri, $slug).await {
            Ok(found) => found,
            Err(response) => return Ok(*response),
        }
    };
}

pub mod about;
pub mod app_telemetry;
pub mod apps;
pub mod assets;
pub mod browser;
pub mod device;
pub mod domains;
pub mod install;
pub mod machine_detail;
pub mod machines;
pub mod notifications;
pub mod orgs;
pub mod pages;
pub mod placement;
pub mod registries;
pub mod resources;
pub mod time;
pub mod tokens;

use axum::{
    Router,
    extract::{Request, State as AxumState},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::{CompressionLayer, predicate::Predicate},
    limit::RequestBodyLimitLayer,
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{
    health,
    state::State,
    web::browser::{RequestId, RequestStart},
};

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
    assets::warm_up();
    let timeout = state.config.request_timeout;
    let extensions = state
        .extensions
        .iter()
        .fold(Router::new(), |router, extension| {
            router.merge(extension.routes())
        });

    let installer = if state.config.machine_defaults.serve_installer {
        Router::new()
            .route("/install", get(install::script))
            .route("/install/{file}", get(install::file))
    } else {
        Router::new()
    };
    let static_files = Router::new()
        .route("/static/{*path}", get(assets::serve))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_context,
        ))
        .with_state(state.clone());
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route(grund_config::app::file::SCHEMA_PATH, get(assets::schema))
        .route("/", get(orgs::landing))
        .route("/login", get(pages::login_form).post(pages::login))
        .route("/logout", post(pages::logout))
        .route("/signup", get(pages::signup_form).post(pages::signup))
        .route("/signup/sent", get(pages::signup_sent))
        .route(
            crate::setup_link::PATH,
            get(pages::owner_form).post(pages::owner_signup),
        )
        .route("/verify", get(pages::verify_form).post(pages::verify))
        .route("/reset", get(pages::reset_form).post(pages::reset))
        .route("/reset/sent", get(pages::reset_sent))
        .route(
            "/reset/confirm",
            get(pages::reset_confirm_form).post(pages::reset_confirm),
        )
        .route("/settings/sessions", get(pages::sessions_page))
        .route("/device", get(device::device_page).post(device::decide))
        .route(
            "/settings/sessions/revoke-others",
            post(pages::revoke_other_sessions),
        )
        .route(
            "/settings/sessions/{id}/revoke",
            post(pages::revoke_session),
        )
        .route("/licenses", get(pages::licenses))
        .route("/style-guide", get(pages::style_guide))
        .route("/notifications", get(notifications::page))
        .route("/notifications/read-all", post(notifications::mark_all))
        .route("/notifications/{id}/read", post(notifications::mark_read))
        .route(
            "/invitations/{invitation}/accept",
            post(orgs::accept_account_invitation),
        )
        .route(
            "/invitations/{invitation}/decline",
            post(orgs::decline_account_invitation),
        )
        .route("/orgs/new", get(orgs::new_form).post(orgs::create))
        .route(
            "/invite",
            get(orgs::invitation_page).post(orgs::accept_invitation),
        )
        .route("/{org}", get(orgs::overview))
        .route("/{org}/members", get(orgs::members_moved))
        .route("/{org}/settings/members", get(orgs::members_page))
        .route("/{org}/settings/members/invite", post(orgs::invite))
        .route(
            "/{org}/settings/members/{account}/role",
            post(orgs::change_role),
        )
        .route(
            "/{org}/settings/members/{account}/remove",
            post(orgs::remove_member),
        )
        .route(
            "/{org}/settings/invitations/{invitation}/revoke",
            post(orgs::revoke_invitation),
        )
        .route("/{org}/apps", get(apps::apps_page))
        .route("/{org}/deploy", get(apps::deploy_page).post(apps::create))
        .route(
            "/{org}/domains",
            get(domains::domains_page).post(domains::add),
        )
        .route("/{org}/domains/verify", post(domains::verify))
        .route("/{org}/domains/check", post(domains::check))
        .route(
            "/{org}/domains/app-domain",
            post(domains::configure_app_domain),
        )
        .route("/{org}/domains/bind", post(domains::bind))
        .route("/{org}/domains/unbind", post(domains::unbind))
        .route("/{org}/domains/remove", post(domains::remove))
        .route("/{org}/templates", get(apps::templates_page))
        .route("/{org}/apps/{app}", get(apps::app_page))
        .route("/{org}/apps/{app}/deployments", get(apps::deployments_page))
        .route("/{org}/apps/{app}/logs", get(apps::logs_page))
        .route("/{org}/apps/{app}/metrics", get(apps::metrics_page))
        .route("/{org}/apps/{app}/settings", get(apps::settings_page))
        .route("/{org}/apps/{app}/restart", post(apps::restart))
        .route("/{org}/apps/{app}/updates/check", post(apps::check_update))
        .route("/{org}/apps/{app}/updates/apply", post(apps::apply_update))
        .route("/{org}/apps/{app}/settings/copies", post(apps::configure))
        .route(
            "/{org}/apps/{app}/settings/domains",
            post(apps::domain_settings),
        )
        .route(
            "/{org}/apps/{app}/settings/placement",
            post(placement::save),
        )
        .route(
            "/{org}/apps/{app}/settings/release",
            post(apps::release_settings),
        )
        .route(
            "/{org}/apps/{app}/volumes/{volume}/backup",
            post(apps::set_volume_backup),
        )
        .route(
            "/{org}/apps/{app}/volumes/{volume}/restore",
            post(apps::restore_volume),
        )
        .route(
            "/{org}/apps/{app}/volumes/{volume}/undo-delete",
            post(apps::undo_volume_deletion),
        )
        .route(
            "/{org}/apps/{app}/volumes/{volume}/change",
            post(apps::change_volume),
        )
        .route("/{org}/apps/{app}/secrets", post(apps::set_secret))
        .route(
            "/{org}/apps/{app}/credentials/reveal",
            post(apps::reveal_credential),
        )
        .route(
            "/{org}/apps/{app}/secrets/remove",
            post(apps::remove_secret),
        )
        .route(
            "/{org}/apps/{app}/releases/{number}/rollback",
            post(apps::rollback),
        )
        .route("/{org}/apps/{app}/delete", post(apps::delete))
        .route("/{org}/apps/{app}/restore", post(apps::restore_app))
        .route("/{org}/apps/{app}/grund.yaml", get(apps::file))
        .route("/{org}/apps/{app}/settings/file", post(apps::apply_file))
        .route("/{org}/machines", get(machines::machines_page))
        .route(
            "/{org}/machines/add",
            get(machines::add_page).post(machines::add),
        )
        .route("/{org}/machines/{machine}", get(machine_detail::page))
        .route("/{org}/machines/vms", post(machines::run_vm))
        .route("/{org}/machines/vms/{vm}/stop", post(machines::stop_vm))
        .route("/{org}/machines/{machine}/remove", post(machines::remove))
        .route("/{org}/machines/{machine}/service", post(machines::service))
        .route("/{org}/machines/{machine}/labels", post(machines::labels))
        .route(
            "/{org}/settings/tokens",
            get(tokens::tokens_page).post(tokens::create),
        )
        .route(
            "/{org}/settings/tokens/{token}/revoke",
            post(tokens::revoke),
        )
        .route(
            "/{org}/settings/registries",
            get(registries::registries_page).post(registries::set),
        )
        .route(
            "/{org}/settings/registries/remove",
            post(registries::remove),
        )
        .route("/{org}/settings/about", get(about::about_page))
        .route("/{org}/settings", get(orgs::settings_page))
        .route("/{org}/settings/rename", post(orgs::rename))
        .route("/{org}/settings/delete", post(orgs::delete))
        .route(
            "/{org}/settings/cancel-deletion",
            post(orgs::cancel_deletion),
        )
        .merge(installer)
        .merge(extensions)
        .fallback(pages::not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_context,
        ))
        .layer(middleware::from_fn(sedx::middleware))
        .layer(compression())
        .layer(middleware::from_fn(prefer_compression))
        .with_state(state.clone())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .merge(static_files)
        .merge(
            crate::api::router(state.clone())
                .layer(middleware::from_fn(secret_rpc_policy))
                .layer(compression())
                .layer(middleware::from_fn(prefer_compression))
                .layer(axum::Extension(state.extensions.clone())),
        )
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            timeout,
        ))
        .layer(CatchPanicLayer::new())
        .layer(header_layer(header::CONTENT_SECURITY_POLICY, CSP))
        .layer(header_layer(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(header_layer(
            header::REFERRER_POLICY,
            "strict-origin-when-cross-origin",
        ))
        .layer(header_layer(header::X_FRAME_OPTIONS, "DENY"))
        .layer(header_layer(
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ))
        .layer(header_layer(
            HeaderName::from_static("permissions-policy"),
            PERMISSIONS_POLICY,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(crate::telemetry::request_span)
                .on_response(
                    |response: &Response, _: std::time::Duration, span: &tracing::Span| {
                        span.record("http.response.status_code", response.status().as_u16());
                        if let Some(code) = response
                            .headers()
                            .get("grpc-status")
                            .and_then(|v| v.to_str().ok())
                        {
                            span.record("rpc.grpc.status_code", code);
                        }
                    },
                ),
        )
}

#[derive(Clone)]
struct Compressible;

impl Predicate for Compressible {
    fn should_compress<B>(&self, response: &axum::http::Response<B>) -> bool
    where
        B: http_body::Body,
    {
        let headers = response.headers();
        let size = response.body().size_hint().exact().or_else(|| {
            headers
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
        });
        size.is_some_and(|size| size >= 1024) && compressible_headers(headers)
    }
}

fn compressible_headers(headers: &HeaderMap) -> bool {
    let allowed_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            matches!(
                value.trim(),
                "text/html"
                    | "text/css"
                    | "text/javascript"
                    | "application/javascript"
                    | "application/json"
                    | "application/connect+json"
                    | "application/problem+json"
                    | "image/svg+xml"
            )
        });
    allowed_type
        && !headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
}

fn compression() -> CompressionLayer<Compressible> {
    CompressionLayer::new()
        .no_deflate()
        .compress_when(Compressible)
}

async fn prefer_compression(mut request: Request, next: Next) -> Response {
    if let Some(encoding) = assets::preferred_encoding(request.headers(), false, true) {
        request.headers_mut().insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static(encoding.unwrap_or("identity")),
        );
    }
    next.run(request).await
}

async fn secret_rpc_policy(request: Request, next: Next) -> Response {
    let secret = matches!(
        request.uri().path(),
        "/grund.token.v1.TokenService/CreateToken"
            | "/grund.login.v1.DeviceLoginService/StartDeviceLogin"
            | "/grund.login.v1.DeviceLoginService/PollDeviceLogin"
            | "/grund.machine.v1.MachineService/CreateJoinToken"
            | "/grund.agent.v1.AgentService/GetMachineJoinToken"
            | "/grund.agent.v1.AgentService/GetReplicaSecrets"
            | "/grund.agent.v1.AgentService/GetPullCredential"
    );
    let secret = secret
        || request
            .extensions()
            .get::<crate::extension::Extensions>()
            .is_some_and(|extensions| {
                extensions.iter().any(|extension| {
                    extension
                        .secret_procedures()
                        .contains(&request.uri().path())
                })
            });
    let mut response = next.run(request).await;
    if secret {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-transform"),
        );
    }
    response
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
    request
        .extensions_mut()
        .insert(RequestStart(std::time::Instant::now()));
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

fn bad_form(_state: &State, status: StatusCode, request_id: Uuid) -> Response {
    let request_id = request_id.to_string();
    let html = crate::templates::compiled::pages::error::render(&pages::ErrorPage {
        title: "That form could not be read",
        text: "Go back, reload the page and try again.",
        request_id: &request_id,
    });
    let mut response = (status, axum::response::Html(html)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use grund_config::names::{NameError, Username};
    use http_body_util::BodyExt;
    use std::convert::Infallible;
    use tower::ServiceExt;

    async fn encoded(
        accept: &'static str,
        content_type: &'static str,
        bytes: usize,
        cache: &'static str,
    ) -> Response {
        let service = tower::service_fn(move |_: Request<Body>| async move {
            let mut response = Response::new(Body::from("x".repeat(bytes)));
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
            response
                .headers_mut()
                .append(header::VARY, HeaderValue::from_static("sedx-layout"));
            Ok::<_, Infallible>(response)
        });
        use tower::Layer;
        middleware::from_fn(prefer_compression)
            .layer(compression().layer(service))
            .oneshot(
                Request::builder()
                    .header(header::ACCEPT_ENCODING, accept)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .map(Body::new)
    }

    #[tokio::test]
    async fn compression_respects_threshold_media_type_and_no_transform() {
        for (kind, bytes, cache, compress) in [
            ("text/html", 1023, "no-store", false),
            ("text/html", 1024, "no-store", true),
            ("application/connect+json", 2048, "no-store", true),
            ("text/event-stream", 2048, "no-store", false),
            ("application/grpc", 2048, "no-store", false),
            ("text/html", 2048, "no-store, no-transform", false),
            (
                "application/connect+json",
                2048,
                "no-store, No-Transform",
                false,
            ),
        ] {
            let response = encoded("gzip", kind, bytes, cache).await;
            assert_eq!(
                response.headers().get(header::CONTENT_ENCODING).is_some(),
                compress,
                "{kind}, {bytes} bytes, {cache}"
            );
            let varies: Vec<_> = response
                .headers()
                .get_all(header::VARY)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect();
            assert!(varies.contains(&"sedx-layout"));
            if compress {
                assert!(varies.contains(&"accept-encoding"));
            }
        }
    }
    #[tokio::test]
    async fn identity_response_still_varies_by_encoding() {
        let response = encoded("identity", "text/html", 2048, "no-store").await;
        assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
        let varies: Vec<_> = response
            .headers()
            .get_all(header::VARY)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert!(varies.contains(&"sedx-layout"));
        assert!(varies.contains(&"accept-encoding"));
    }

    #[tokio::test]
    async fn already_encoded_content_is_not_encoded_twice() {
        use tower::Layer;
        let response = compression()
            .layer(tower::service_fn(|_: Request<Body>| async {
                let mut response = Response::new(Body::from("x".repeat(2048)));
                response
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                response
                    .headers_mut()
                    .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                Ok::<_, Infallible>(response)
            }))
            .oneshot(
                Request::builder()
                    .header(header::ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], "x".repeat(2048).as_bytes());
    }

    #[tokio::test]
    async fn gzip_body_round_trips_without_losing_sedx_vary() {
        use std::io::Read as _;
        let response = encoded("gzip", "text/html", 2048, "no-store").await;
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
        assert!(
            response
                .headers()
                .get_all(header::VARY)
                .iter()
                .any(|value| value == "sedx-layout")
        );
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, vec![b'x'; 2048]);
    }

    #[tokio::test]
    async fn client_weights_choose_only_gzip_or_identity_for_dynamic_content() {
        for (accept, gzip) in [
            ("br, zstd, gzip", true),
            ("br, zstd", false),
            ("gzip;q=0.8, identity;q=0.3", true),
            ("gzip;q=0.3, identity;q=0.8", false),
            ("gzip;q=0, identity;q=1", false),
            ("gzip, identity", true),
        ] {
            let response = encoded(accept, "application/json", 2048, "no-store").await;
            assert_eq!(
                response.headers().get(header::CONTENT_ENCODING),
                gzip.then_some(&HeaderValue::from_static("gzip")),
                "{accept}"
            );
        }
    }

    #[tokio::test]
    async fn secret_connect_json_is_never_compressed() {
        use tower::Layer;
        let service = tower::service_fn(|_: Request<Body>| async {
            let mut response = Response::new(Body::from("x".repeat(2048)));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/connect+json"),
            );
            Ok::<_, Infallible>(response)
        });
        let service = middleware::from_fn(prefer_compression)
            .layer(compression().layer(middleware::from_fn(secret_rpc_policy).layer(service)));
        for (path, secret) in [
            ("/grund.token.v1.TokenService/CreateToken", true),
            ("/grund.agent.v1.AgentService/GetReplicaSecrets", true),
            ("/grund.agent.v1.AgentService/GetPullCredential", true),
            ("/grund.machine.v1.MachineService/GetMachine", false),
        ] {
            let response = service
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::ACCEPT_ENCODING, "gzip")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.headers().get(header::CONTENT_ENCODING),
                (!secret).then_some(&HeaderValue::from_static("gzip")),
                "{path}"
            );
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL),
                secret.then_some(&HeaderValue::from_static("no-store, no-transform")),
                "{path}"
            );
        }
    }

    #[test]
    fn no_organisation_can_take_a_top_level_path_of_the_dashboard() {
        for path in [
            "health",
            "static",
            "login",
            "logout",
            "signup",
            "verify",
            "reset",
            "settings",
            "licenses",
            "notifications",
            "style-guide",
            "orgs",
            "invitations",
            "invite",
            "auth",
            "api",
            "install",
        ] {
            assert_eq!(Username::parse(path), Err(NameError::Reserved), "/{path}");
        }
    }
}
