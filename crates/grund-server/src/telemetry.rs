use std::{
    fmt as std_fmt, io,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::Context as _;
use axum::{extract::MatchedPath, http::HeaderMap};
use opentelemetry::{
    Context, Key,
    propagation::{Extractor, Injector, TextMapPropagator},
    trace::TraceContextExt,
};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    resource::{EnvResourceDetector, ResourceDetector},
    trace::{SdkTracerProvider, span_processor_with_async_runtime::BatchSpanProcessor},
};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{
    EnvFilter,
    fmt::{
        self, FmtContext, FormatEvent, FormatFields,
        format::{self, Writer},
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Initialises logging and, only when an endpoint is supplied, OTLP HTTP/protobuf tracing.
/// Keep the returned provider alive until all work has drained, then shut it down.
pub fn init(
    log: &str,
    json: bool,
    to_stderr: bool,
    endpoint: Option<&str>,
    service_name: Option<&str>,
    default_service: &str,
) -> anyhow::Result<Option<SdkTracerProvider>> {
    let filter = EnvFilter::try_new(log).unwrap_or_else(|_| EnvFilter::new("grund=info,warn"));
    let writer = move || -> Box<dyn io::Write> {
        if to_stderr {
            Box::new(io::stderr())
        } else {
            Box::new(io::stdout())
        }
    };
    let provider = if let Some(endpoint) = endpoint {
        anyhow::ensure!(
            endpoint.starts_with("http://") || endpoint.starts_with("https://"),
            "OTEL_EXPORTER_OTLP_ENDPOINT must be an http or https URL"
        );
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("build OTLP HTTP client")?;
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(format!("{}/v1/traces", endpoint.trim_end_matches('/')))
            .with_http_client(client)
            .build()
            .context("build OTLP HTTP/protobuf exporter")?;
        let resource = if let Some(name) = service_name {
            Resource::builder()
                .with_service_name(name.to_owned())
                .build()
        } else if EnvResourceDetector::new()
            .detect()
            .get_ref(&Key::new("service.name"))
            .is_some()
        {
            Resource::builder().build()
        } else {
            Resource::builder()
                .with_service_name(default_service.to_owned())
                .build()
        };
        let processor =
            BatchSpanProcessor::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor)
            .with_resource(resource)
            .build();
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        Some(provider)
    } else {
        None
    };
    if json {
        if let Some(provider) = &provider {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .json()
                        .event_format(TraceJson)
                        .with_writer(writer),
                )
                .with(tracing_opentelemetry::layer().with_tracer(
                    opentelemetry::trace::TracerProvider::tracer(provider, "grund"),
                ))
                .init();
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(writer))
                .init();
        }
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().compact().with_writer(writer))
            .with(provider.as_ref().map(|provider| {
                tracing_opentelemetry::layer().with_tracer(
                    opentelemetry::trace::TracerProvider::tracer(provider, "grund"),
                )
            }))
            .init();
    }
    ENABLED.store(provider.is_some(), Ordering::Relaxed);
    Ok(provider)
}

struct TraceJson;

impl<S, N> FormatEvent<S, N> for TraceJson
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std_fmt::Result {
        let mut line = String::new();
        format::Format::default()
            .json()
            .format_event(ctx, Writer::new(&mut line), event)?;
        let trace_id = ctx.event_scope().and_then(|_| current_trace_id());
        if let Some(trace_id) = trace_id
            && let Some(body) = line.strip_suffix("}\n")
        {
            return writeln!(writer, "{body},\"trace_id\":\"{trace_id}\"}}");
        }
        writer.write_str(&line)
    }
}

/// Returns the active trace ID for logs and rendered pages, or None when export is off.
pub fn current_trace_id() -> Option<String> {
    if !ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let context = tracing::Span::current().context();
    let otel_span = context.span();
    let span_context = otel_span.span_context();
    span_context
        .is_valid()
        .then(|| span_context.trace_id().to_string())
}

struct Headers<'a>(&'a HeaderMap);

impl Extractor for Headers<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(axum::http::HeaderName::as_str).collect()
    }
}

struct OutboundHeaders<'a>(&'a mut HeaderMap);

impl Injector for OutboundHeaders<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(key), Ok(value)) = (key.parse::<axum::http::HeaderName>(), value.parse()) {
            self.0.insert(key, value);
        }
    }
}

/// Extracts a W3C traceparent and tracestate from an inbound HTTP request.
pub fn parent(headers: &HeaderMap) -> Context {
    if !ENABLED.load(Ordering::Relaxed) {
        return Context::new();
    }
    TraceContextPropagator::new().extract(&Headers(headers))
}

/// Adds the active trace context to a reqwest call without altering other headers.
pub fn propagate(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if !ENABLED.load(Ordering::Relaxed) {
        return request;
    }
    let context = tracing::Span::current().context();
    if !context.span().span_context().is_valid() {
        return request;
    }
    let mut headers = HeaderMap::new();
    TraceContextPropagator::new().inject_context(&context, &mut OutboundHeaders(&mut headers));
    request.headers(headers)
}

/// Returns the axum route template rather than request-controlled path components.
pub fn route(request: &axum::extract::Request) -> &str {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched")
}

/// Creates a server span with safe route templates and a verified Connect procedure.
pub fn request_span(request: &axum::extract::Request) -> tracing::Span {
    let route = route(request);
    let procedure = request
        .uri()
        .path()
        .starts_with("/grund.")
        .then(|| {
            crate::api::AUTHORIZATION
                .iter()
                .find(|(name, _)| *name == request.uri().path())
                .map(|(name, _)| *name)
        })
        .flatten();
    let span = tracing::info_span!(
        "http_request",
        otel.kind = "server",
        otel.name = procedure.unwrap_or(route),
        "http.request.method" = %request.method(),
        "http.route" = route,
        "http.response.status_code" = tracing::field::Empty,
        "rpc.system" = if procedure.is_some() { "connect" } else { "" },
        "rpc.method" = procedure.unwrap_or(""),
        "rpc.grpc.status_code" = tracing::field::Empty,
        "machine_key_prefix" = tracing::field::Empty,
        "rpc.connect.code" = tracing::field::Empty,
    );
    if ENABLED.load(Ordering::Relaxed) {
        let _ = span.set_parent(parent(request.headers()));
    }
    span
}

/// Records the resolved Connect code without reading or logging a response body.
pub fn connect_code<T>(result: &Result<T, connectrpc::ConnectError>) {
    tracing::Span::current().record(
        "rpc.connect.code",
        result
            .as_ref()
            .err()
            .map_or("ok", |error| error.code.as_str()),
    );
}
