use std::{sync::Arc, time::Duration};

use anyhow::Context;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Clone, Debug)]
pub struct Origin {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let url = url.trim_end_matches('/');
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            anyhow::bail!("{url}: expected an http:// or https:// origin");
        };
        anyhow::ensure!(!rest.contains('/'), "{url}: an origin has no path");
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse().with_context(|| format!("{url}: bad port"))?,
            ),
            None => (rest, if tls { 443 } else { 80 }),
        };
        Ok(Self {
            tls,
            host: host.to_string(),
            port,
        })
    }

    pub fn serialized(&self) -> String {
        format!(
            "{}://{}",
            if self.tls { "https" } else { "http" },
            self.authority()
        )
    }

    pub fn authority(&self) -> String {
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub async fn send(
    origin: &Origin,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> anyhow::Result<Response> {
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: grund-accepttest\r\n",
        origin.authority()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    let mut request = request.into_bytes();
    if let Some(body) = body {
        request.extend_from_slice(body);
    }

    let exchange = async {
        let tcp = TcpStream::connect((origin.host.as_str(), origin.port))
            .await
            .with_context(|| format!("connect to {}:{}", origin.host, origin.port))?;
        let raw = if origin.tls {
            let server_name = rustls::pki_types::ServerName::try_from(origin.host.clone())?;
            let stream = tls_connector()
                .connect(server_name, tcp)
                .await
                .context("TLS handshake")?;
            roundtrip(stream, &request).await?
        } else {
            roundtrip(tcp, &request).await?
        };
        parse(&raw, method == "HEAD")
    };
    tokio::time::timeout(Duration::from_secs(15), exchange)
        .await
        .with_context(|| format!("{method} {path}: no complete response within 15 s"))?
}

async fn roundtrip<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
) -> anyhow::Result<Vec<u8>> {
    stream.write_all(request).await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    if let Err(error) = stream.read_to_end(&mut raw).await {
        anyhow::ensure!(!raw.is_empty(), "read response: {error}");
    }
    Ok(raw)
}

fn tls_connector() -> tokio_rustls::TlsConnector {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn parse(raw: &[u8], head: bool) -> anyhow::Result<Response> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("response has no end of headers")?;
    let head_text = std::str::from_utf8(&raw[..split]).context("response headers are not UTF-8")?;
    let mut lines = head_text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .with_context(|| format!("bad status line {status_line:?}"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked"));
    if chunked && !head {
        body = dechunk(&body)?;
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

fn dechunk(mut data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("truncated chunk size")?;
        let size_text = std::str::from_utf8(&data[..line_end])?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_text, 16)
            .with_context(|| format!("bad chunk size {size_text:?}"))?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        anyhow::ensure!(data.len() >= size + 2, "truncated chunk");
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}
