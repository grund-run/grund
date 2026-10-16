//! Static files embedded in the binary. CSS, JS and SVG have precompressed
//! representations prepared at build time; URLs with the current content hash
//! may be cached immutably, while bare URLs revalidate.

use std::sync::LazyLock;

use axum::{
    body::{Body, Bytes},
    extract::{OriginalUri, Path},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

const CSS: &str = include_str!("../../assets/grund.css");
const JS: &str = include_str!("../../assets/grund.js");
const INTER: &[u8] = include_bytes!("../../assets/fonts/inter-latin.woff2");
const MONO: &[u8] = include_bytes!("../../assets/fonts/jetbrains-mono-latin.woff2");
const MARK: &str = include_str!("../../assets/mark.svg");
const CSS_BR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/grund.css.br"));
const CSS_GZIP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/grund.css.gz"));
const JS_BR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/grund.js.br"));
const JS_GZIP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/grund.js.gz"));
const SEDX_BR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sedx.js.br"));
const SEDX_GZIP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sedx.js.gz"));
const MARK_BR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mark.svg.br"));
const MARK_GZIP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mark.svg.gz"));

/// The full texts of the fonts' licenses, for /licenses.
pub const INTER_LICENSE: &str = include_str!("../../assets/licenses/inter.txt");
pub const MONO_LICENSE: &str = include_str!("../../assets/licenses/jetbrains-mono.txt");

/// Product-logo sources, usage conditions and trademark attribution for /licenses.
pub const LOGO_NOTICES: &str = include_str!("../../assets/logos/NOTICE.txt");

static SCHEMA: LazyLock<String> = LazyLock::new(grund_domain::app::file::schema_text);

static CSS_ASSET: LazyLock<Asset> = LazyLock::new(|| {
    Asset::compressed(CSS.as_bytes(), CSS_BR, CSS_GZIP, "text/css; charset=utf-8")
});
static JS_ASSET: LazyLock<Asset> = LazyLock::new(|| {
    Asset::compressed(
        JS.as_bytes(),
        JS_BR,
        JS_GZIP,
        "text/javascript; charset=utf-8",
    )
});
static SEDX_ASSET: LazyLock<Asset> = LazyLock::new(|| {
    Asset::compressed(
        sedx::JS.as_bytes(),
        SEDX_BR,
        SEDX_GZIP,
        "text/javascript; charset=utf-8",
    )
});
static MARK_ASSET: LazyLock<Asset> =
    LazyLock::new(|| Asset::compressed(MARK.as_bytes(), MARK_BR, MARK_GZIP, "image/svg+xml"));
static INTER_ASSET: LazyLock<Asset> = LazyLock::new(|| Asset::uncompressed(INTER, "font/woff2"));
static MONO_ASSET: LazyLock<Asset> = LazyLock::new(|| Asset::uncompressed(MONO, "font/woff2"));

struct Representation {
    bytes: Bytes,
    etag: HeaderValue,
}

impl Representation {
    fn new(bytes: Bytes) -> Self {
        let etag = HeaderValue::from_str(&format!("\"{}\"", hex::encode(Sha256::digest(&bytes))))
            .expect("hex ETag");
        Self { bytes, etag }
    }
}

struct Asset {
    identity: Representation,
    br: Option<Representation>,
    gzip: Option<Representation>,
    version: String,
    content_type: HeaderValue,
}

impl Asset {
    fn uncompressed(body: &'static [u8], content_type: &'static str) -> Self {
        Self {
            identity: Representation::new(Bytes::from_static(body)),
            br: None,
            gzip: None,
            version: hex::encode(&Sha256::digest(body)[..8]),
            content_type: HeaderValue::from_static(content_type),
        }
    }

    fn compressed(
        body: &'static [u8],
        br: &'static [u8],
        gzip: &'static [u8],
        content_type: &'static str,
    ) -> Self {
        let mut asset = Self::uncompressed(body, content_type);
        if !br.is_empty() {
            asset.br = Some(Representation::new(Bytes::from_static(br)));
        }
        if !gzip.is_empty() {
            asset.gzip = Some(Representation::new(Bytes::from_static(gzip)));
        }
        asset
    }
}

/// Prepares the embedded assets' representation hashes before serving requests.
pub fn warm_up() {
    LazyLock::force(&CSS_ASSET);
    LazyLock::force(&JS_ASSET);
    LazyLock::force(&SEDX_ASSET);
    LazyLock::force(&MARK_ASSET);
    LazyLock::force(&INTER_ASSET);
    LazyLock::force(&MONO_ASSET);
}

/// Where signed-in pages load the script from.
pub fn js_href() -> String {
    format!("/static/grund.js?v={}", JS_ASSET.version)
}

/// Where signed-in pages load sedx's script from.
pub fn sedx_href() -> String {
    format!("/static/sedx.js?v={}", SEDX_ASSET.version)
}

/// Where pages link the stylesheet from.
pub fn css_href() -> String {
    format!("/static/grund.css?v={}", CSS_ASSET.version)
}

/// Only URLs carrying the current content hash may be cached immutably.
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const REVALIDATE: &str = "public, max-age=0, must-revalidate";
/// Fonts and the mark keep their names across builds, so they revalidate daily.
pub const A_DAY: &str = "public, max-age=86400";

/// The schema changes only with a new build, and editors fetch it often.
pub const AN_HOUR: &str = "public, max-age=3600";

/// `GET /schema/grund.json`: the JSON Schema of grund.yaml, for editors.
/// Public and the same for everyone, so any origin may fetch it.
pub async fn schema() -> Response {
    let mut response = SCHEMA.as_str().into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/schema+json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(AN_HOUR));
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// Serves one embedded file, or 404.
pub async fn serve(
    Path(path): Path<String>,
    OriginalUri(uri): OriginalUri,
    request_headers: HeaderMap,
) -> Response {
    let (asset, versioned): (&Asset, bool) = match path.as_str() {
        "grund.css" => (&CSS_ASSET, true),
        "grund.js" => (&JS_ASSET, true),
        "sedx.js" => (&SEDX_ASSET, true),
        "fonts/inter-latin.woff2" => (&INTER_ASSET, false),
        "fonts/jetbrains-mono-latin.woff2" => (&MONO_ASSET, false),
        "favicon.svg" | "mark.svg" => (&MARK_ASSET, false),
        _ => return (StatusCode::NOT_FOUND, "not found\n").into_response(),
    };
    let cache = if versioned
        && uri
            .query()
            .is_some_and(|query| query.strip_prefix("v=") == Some(asset.version.as_str()))
    {
        IMMUTABLE
    } else if versioned {
        REVALIDATE
    } else {
        A_DAY
    };

    let mut response = Response::new(Body::empty());
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    let Some((representation, encoding)) = select_representation(asset, &request_headers) else {
        *response.status_mut() = StatusCode::NOT_ACCEPTABLE;
        return response;
    };
    if if_none_match(&request_headers, &representation.etag) {
        *response.status_mut() = StatusCode::NOT_MODIFIED;
    } else {
        *response.body_mut() = Body::from(representation.bytes.clone());
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&representation.bytes.len().to_string())
                .expect("static content length"),
        );
    }
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, asset.content_type.clone());
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    headers.insert(header::ETAG, representation.etag.clone());
    if let Some(encoding) = encoding {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
    }
    response
}

fn select_representation<'a>(
    asset: &'a Asset,
    headers: &HeaderMap,
) -> Option<(&'a Representation, Option<&'static str>)> {
    match preferred_encoding(headers, asset.br.is_some(), asset.gzip.is_some())? {
        Some("br") => asset
            .br
            .as_ref()
            .map(|representation| (representation, Some("br"))),
        Some("gzip") => asset
            .gzip
            .as_ref()
            .map(|representation| (representation, Some("gzip"))),
        _ => Some((&asset.identity, None)),
    }
}

pub(crate) fn preferred_encoding(
    headers: &HeaderMap,
    br_available: bool,
    gzip_available: bool,
) -> Option<Option<&'static str>> {
    if !headers.contains_key(header::ACCEPT_ENCODING) {
        return Some(None);
    }
    let mut br = None;
    let mut gzip = None;
    let mut identity = None;
    let mut wildcard = None;
    for field in headers.get_all(header::ACCEPT_ENCODING).iter() {
        let Ok(field) = field.to_str() else {
            continue;
        };
        for item in field.split(',') {
            let (coding, q) = match item.trim().split_once(';') {
                Some((coding, param)) => {
                    let q = param
                        .trim()
                        .strip_prefix("q=")
                        .and_then(parse_quality)
                        .unwrap_or(0);
                    (coding.trim(), q)
                }
                None => (item.trim(), 1000),
            };
            let slot = if coding.eq_ignore_ascii_case("br") {
                &mut br
            } else if coding.eq_ignore_ascii_case("gzip") {
                &mut gzip
            } else if coding.eq_ignore_ascii_case("identity") {
                &mut identity
            } else if coding == "*" {
                &mut wildcard
            } else {
                continue;
            };
            *slot = Some(slot.unwrap_or(0).max(q));
        }
    }
    let wildcard_seen = wildcard.is_some();
    let wildcard = wildcard.unwrap_or(0);
    let identity = identity.unwrap_or(if wildcard_seen && wildcard == 0 {
        0
    } else {
        1000
    });
    let mut best = (identity, None);
    for (quality, encoding) in [
        (gzip.unwrap_or(wildcard), "gzip", gzip_available),
        (br.unwrap_or(wildcard), "br", br_available),
    ]
    .into_iter()
    .filter(|(_, _, available)| *available)
    .map(|(quality, encoding, _)| (quality, encoding))
    {
        if quality > 0 && quality >= best.0 {
            best = (quality, Some(encoding));
        }
    }
    (best.0 > 0).then_some(best.1)
}

fn parse_quality(value: &str) -> Option<u16> {
    let (whole, decimal) = value.split_once('.').unwrap_or((value, ""));
    if decimal.len() > 3 || !decimal.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => Some(
            decimal
                .bytes()
                .fold(0, |q, digit| q * 10 + u16::from(digit - b'0'))
                * 10u16.pow(3 - decimal.len() as u32),
        ),
        "1" if decimal.bytes().all(|byte| byte == b'0') => Some(1000),
        _ => None,
    }
}

fn if_none_match(headers: &HeaderMap, etag: &HeaderValue) -> bool {
    let etag = etag.to_str().expect("hex ETag");
    headers.get_all(header::IF_NONE_MATCH).iter().any(|field| {
        field.to_str().is_ok_and(|field| {
            field.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::Request, routing::get as route_get};
    use http_body_util::BodyExt;
    use std::io::Read;
    use tower::ServiceExt;

    async fn get(path: &str, accept_encoding: Option<&str>, etag: Option<&str>) -> Response {
        let mut request = Request::builder().uri(path);
        if let Some(accept_encoding) = accept_encoding {
            request = request.header(header::ACCEPT_ENCODING, accept_encoding);
        }
        if let Some(etag) = etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        Router::new()
            .route("/static/{*path}", route_get(serve))
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body(response: Response) -> Bytes {
        response.into_body().collect().await.unwrap().to_bytes()
    }

    #[tokio::test]
    async fn embedded_assets_negotiate_decodable_encodings_and_distinct_etags() {
        for (path, original) in [
            ("/static/grund.css", CSS.as_bytes()),
            ("/static/grund.js", JS.as_bytes()),
            ("/static/sedx.js", sedx::JS.as_bytes()),
            ("/static/mark.svg", MARK.as_bytes()),
        ] {
            let identity = get(path, None, None).await;
            assert_eq!(identity.status(), StatusCode::OK);
            assert_eq!(identity.headers()[header::VARY], "Accept-Encoding");
            assert!(!identity.headers().contains_key(header::CONTENT_ENCODING));
            let identity_etag = identity.headers()[header::ETAG].clone();
            assert_eq!(body(identity).await, original);

            let br = get(path, Some("gzip;q=0.3, br;q=1"), None).await;
            assert_eq!(br.headers()[header::CONTENT_ENCODING], "br");
            assert_ne!(br.headers()[header::ETAG], identity_etag);
            let br_bytes = body(br).await;
            assert!(br_bytes.len() * 10 <= original.len() * 9);
            let mut decoded = Vec::new();
            brotli::Decompressor::new(br_bytes.as_ref(), 4096)
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, original);

            let gzip = get(path, Some("br;q=0, gzip;q=1"), None).await;
            assert_eq!(gzip.headers()[header::CONTENT_ENCODING], "gzip");
            assert_ne!(gzip.headers()[header::ETAG], identity_etag);
            let gzip_bytes = body(gzip).await;
            assert!(gzip_bytes.len() * 10 <= original.len() * 9);
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(gzip_bytes.as_ref())
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, original);
        }
    }

    #[tokio::test]
    async fn weighted_preferences_and_identity_exclusion_are_respected() {
        let identity = get("/static/grund.css", Some("br;q=0.5, gzip;q=0.2"), None).await;
        assert!(!identity.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(body(identity).await, CSS.as_bytes());

        let gzip = get(
            "/static/grund.css",
            Some("br;q=0.1, gzip;q=0.8, identity;q=0"),
            None,
        )
        .await;
        assert_eq!(gzip.headers()[header::CONTENT_ENCODING], "gzip");

        let br = get(
            "/static/grund.css",
            Some("gzip;q=0, *;q=1, identity;q=0"),
            None,
        )
        .await;
        assert_eq!(br.headers()[header::CONTENT_ENCODING], "br");

        let refused = get(
            "/static/grund.css",
            Some("br;q=0,gzip;q=0,identity;q=0"),
            None,
        )
        .await;
        assert_eq!(refused.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(refused.headers()[header::VARY], "Accept-Encoding");
        assert!(body(refused).await.is_empty());

        let refused_zstd = get("/static/grund.css", Some("zstd, identity;q=0"), None).await;
        assert_eq!(refused_zstd.status(), StatusCode::NOT_ACCEPTABLE);

        let refused_font = get(
            "/static/fonts/inter-latin.woff2",
            Some("br, gzip, identity;q=0"),
            None,
        )
        .await;
        assert_eq!(refused_font.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn conditional_get_uses_the_selected_representation_and_only_matching_versions_are_immutable()
     {
        let href = css_href();
        let br = get(&href, Some("br"), None).await;
        assert_eq!(br.headers()[header::CACHE_CONTROL], IMMUTABLE);
        let etag = br.headers()[header::ETAG].to_str().unwrap().to_owned();

        let not_modified = get(&href, Some("br"), Some(&format!("W/{etag}"))).await;
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(not_modified.headers()[header::CONTENT_ENCODING], "br");
        assert_eq!(not_modified.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(not_modified.headers()[header::ETAG], etag.as_str());
        assert!(body(not_modified).await.is_empty());

        let identity = get(&href, None, Some(&etag)).await;
        assert_eq!(identity.status(), StatusCode::OK);
        let bare = get("/static/grund.css", None, None).await;
        assert_eq!(bare.headers()[header::CACHE_CONTROL], REVALIDATE);
        let stale = get("/static/grund.css?v=stale", None, None).await;
        assert_eq!(stale.headers()[header::CACHE_CONTROL], REVALIDATE);
        let font = get("/static/fonts/inter-latin.woff2", Some("br, gzip"), None).await;
        assert_eq!(font.status(), StatusCode::OK);
        assert!(!font.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(font.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(body(font).await, INTER);
    }
}
