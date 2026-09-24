//! Static files, embedded in the binary: the stylesheet, the fonts and the
//! icon. The stylesheet is linked with a content hash in its query, so it is
//! cached for a year and a new build is fetched at once.

use std::sync::LazyLock;

use axum::{
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

const CSS: &str = include_str!("../../assets/grund.css");
const INTER: &[u8] = include_bytes!("../../assets/fonts/inter-latin.woff2");
const MONO: &[u8] = include_bytes!("../../assets/fonts/jetbrains-mono-latin.woff2");
const FAVICON: &str = include_str!("../../assets/favicon.svg");

/// The full texts of the fonts' licenses, for /licenses.
pub const INTER_LICENSE: &str = include_str!("../../assets/licenses/inter.txt");
pub const MONO_LICENSE: &str = include_str!("../../assets/licenses/jetbrains-mono.txt");

static CSS_VERSION: LazyLock<String> =
    LazyLock::new(|| hex::encode(&Sha256::digest(CSS.as_bytes())[..8]));

/// Where pages link the stylesheet from.
pub fn css_href() -> String {
    format!("/static/grund.css?v={}", *CSS_VERSION)
}

/// The stylesheet's URL changes with its content, so it may be kept forever.
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// Fonts and the icon keep their names across builds, so they revalidate daily.
pub const A_DAY: &str = "public, max-age=86400";

/// Serves one embedded file, or 404.
pub async fn serve(Path(path): Path<String>) -> Response {
    let (body, content_type, cache): (&'static [u8], &str, &str) = match path.as_str() {
        "grund.css" => (CSS.as_bytes(), "text/css; charset=utf-8", IMMUTABLE),
        "fonts/inter-latin.woff2" => (INTER, "font/woff2", A_DAY),
        "fonts/jetbrains-mono-latin.woff2" => (MONO, "font/woff2", A_DAY),
        "favicon.svg" => (FAVICON.as_bytes(), "image/svg+xml", A_DAY),
        _ => return (StatusCode::NOT_FOUND, "not found\n").into_response(),
    };
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).expect("static content type"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    response
}
