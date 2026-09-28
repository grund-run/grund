//! The instance's own agent installer, with GRUND_SERVE_INSTALLER: `GET
//! /install` is crates/grund-agent/install.sh as this binary was built with
//! it, and `GET /install/grund-linux-<arch>` is this very executable, with
//! its SHA-256 beside it. A machine then installs the build its instance
//! runs from the instance alone, whether that build was published or built
//! from a clone (grund-docs design/self-hosted.md §6.2).
//!
//! The binary is read from `/proc/self/exe`, so an upgrade that replaces the
//! file on disk keeps serving the build that is running until the restart.
//! Nothing is signed yet (design/self-hosted.md §7.2): the SHA-256 guards the
//! download against truncation, and trust in the bytes is trust in the
//! instance's TLS, as it is for the script itself.

use std::io::Read;

use axum::{
    body::Body,
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

/// The installer script, as this binary was built with it.
pub const SCRIPT: &str = include_str!("../../../grund-agent/install.sh");

const EXECUTABLE: &str = "/proc/self/exe";

static DIGEST: OnceCell<String> = OnceCell::const_new();

/// The file name this instance serves its binary under, for the system and
/// architecture it was built for: `grund-linux-x86_64` on the published
/// builds. install.sh asks for `grund-linux-$(uname -m)`, so a machine of
/// another architecture gets a 404 rather than a binary it cannot run.
pub fn binary_name() -> String {
    format!("grund-{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Refuses GRUND_SERVE_INSTALLER at startup when this process cannot read
/// its own executable, instead of failing the first machine that asks.
pub fn check() -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(target_os = "linux"),
        "GRUND_SERVE_INSTALLER needs Linux: grund serves its own executable from {EXECUTABLE}"
    );
    std::fs::File::open(EXECUTABLE)
        .and_then(|mut file| file.read(&mut [0u8; 4]))
        .map_err(|error| {
            anyhow::anyhow!(
                "GRUND_SERVE_INSTALLER is on, but grund cannot read its own executable \
                 ({EXECUTABLE}): {error}. Turn it off, or set GRUND_AGENT_INSTALL_URL instead"
            )
        })?;
    Ok(())
}

/// `GET /install`: the script.
pub async fn script() -> Response {
    let mut response = SCRIPT.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

/// `GET /install/{file}`: this executable, or its SHA-256 as 64 lowercase
/// hex characters and a newline. Both keep their names across builds, so
/// neither may be cached without revalidating.
pub async fn file(Path(file): Path<String>) -> Response {
    let name = binary_name();
    let response = if file == name {
        binary().await
    } else if file == format!("{name}.sha256") {
        digest().await.map(|digest| {
            let mut response = format!("{digest}\n").into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            response
        })
    } else {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };
    match response {
        Ok(mut response) => {
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            response
        }
        Err(error) => {
            tracing::error!(error = format!("{error:#}"), "serving the installer failed");
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable\n").into_response()
        }
    }
}

async fn binary() -> anyhow::Result<Response> {
    let file = tokio::fs::File::open(EXECUTABLE).await?;
    let length = file.metadata().await?.len();
    let mut response = Body::from_stream(tokio_util::io::ReaderStream::new(file)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    Ok(response)
}

async fn digest() -> anyhow::Result<String> {
    DIGEST
        .get_or_try_init(|| async {
            tokio::task::spawn_blocking(|| -> anyhow::Result<String> {
                let mut file = std::fs::File::open(EXECUTABLE)?;
                let mut hasher = Sha256::new();
                let mut buffer = vec![0u8; 1 << 20];
                loop {
                    let read = file.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
                Ok(hex::encode(hasher.finalize()))
            })
            .await?
        })
        .await
        .cloned()
}
