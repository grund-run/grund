use std::{collections::BTreeMap, io::Write, path::Path, time::Duration};

use clap::ValueEnum;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{CliError, CliResult, Code};

const ORIGIN: &str = "https://git.kjuulh.io";
const MAX_METADATA: u64 = 1024 * 1024;
const MAX_BINARY: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Channel {
    Stable,
    Alpha,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    base: [u64; 3],
    alpha: Option<u64>,
}

impl Version {
    pub fn parse(tag: &str) -> CliResult<Self> {
        let invalid = || {
            CliError::usage("version must be vX.Y.Z or vX.Y.Z-alpha.N (N starts at 1)")
                .field("version")
        };
        let raw = tag.strip_prefix('v').ok_or_else(invalid)?;
        let (base, alpha) = match raw.split_once("-alpha.") {
            Some((base, number)) => (base, Some(number)),
            None => (raw, None),
        };
        let number = |s: &str| -> CliResult<u64> {
            if s.is_empty()
                || !s.bytes().all(|b| b.is_ascii_digit())
                || (s.len() > 1 && s.starts_with('0'))
            {
                return Err(invalid());
            }
            s.parse().map_err(|_| invalid())
        };
        let mut parts = base.split('.');
        let base = [
            number(parts.next().ok_or_else(invalid)?)?,
            number(parts.next().ok_or_else(invalid)?)?,
            number(parts.next().ok_or_else(invalid)?)?,
        ];
        if parts.next().is_some() {
            return Err(invalid());
        }
        let alpha = alpha.map(number).transpose()?;
        if alpha == Some(0) {
            return Err(invalid());
        }
        Ok(Self { base, alpha })
    }

    pub fn channel(&self) -> Channel {
        if self.alpha.is_some() {
            Channel::Alpha
        } else {
            Channel::Stable
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.base
            .cmp(&other.base)
            .then_with(|| match (self.alpha, other.alpha) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (Some(a), Some(b)) => a.cmp(&b),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Deserialize)]
struct Advertisement {
    tag_name: String,
    draft: bool,
}

pub struct Release {
    pub tag: String,
    client: reqwest::Client,
    checksums: BTreeMap<String, String>,
}

fn failure(message: impl Into<String>) -> CliError {
    CliError::new(Code::Unavailable, message)
}

fn client() -> CliResult<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .user_agent("grund-release-client")
        .build()
        .map_err(|_| failure("could not initialize the public release client"))
}

async fn response(client: &reqwest::Client, path: &str) -> CliResult<reqwest::Response> {
    let response = client
        .get(format!("{ORIGIN}{path}"))
        .send()
        .await
        .map_err(|_| failure("public release request failed or exceeded its deadline"))?;
    if !response.status().is_success() {
        return Err(failure(format!(
            "public release request returned HTTP {}",
            response.status()
        )));
    }
    Ok(response)
}

async fn bytes(client: &reqwest::Client, path: &str) -> CliResult<Vec<u8>> {
    let mut response = response(client, path).await?;
    let mut result = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| failure("public metadata transfer failed"))?
    {
        if result.len() as u64 + chunk.len() as u64 > MAX_METADATA {
            return Err(failure("public release metadata exceeds 1 MiB"));
        }
        result.extend_from_slice(&chunk);
    }
    Ok(result)
}

pub fn checksums(text: &str) -> CliResult<BTreeMap<String, String>> {
    let invalid = || failure("SHA256SUMS has an invalid or duplicate entry");
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let (hash, name) = line.split_once("  ").ok_or_else(invalid)?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || name.is_empty()
            || name.starts_with('.')
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || result.insert(name.to_owned(), hash.to_owned()).is_some()
        {
            return Err(invalid());
        }
    }
    if result.is_empty() {
        return Err(invalid());
    }
    Ok(result)
}

fn select(advertisements: Vec<Advertisement>, channel: Channel) -> Option<String> {
    advertisements
        .into_iter()
        .filter(|release| !release.draft)
        .filter_map(|release| {
            Version::parse(&release.tag_name)
                .ok()
                .map(|version| (version, release.tag_name))
        })
        .filter(|(version, _)| channel == Channel::Alpha || version.alpha.is_none())
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, tag)| tag)
}

impl Release {
    pub async fn resolve(
        version: Option<&str>,
        channel: Option<Channel>,
        installed: &str,
    ) -> CliResult<Self> {
        let client = client()?;
        let tag = if let Some(tag) = version {
            Version::parse(tag)?;
            let body = bytes(
                &client,
                &format!("/api/v1/repos/grund/grund/releases/tags/{tag}"),
            )
            .await?;
            let release: Advertisement = serde_json::from_slice(&body)
                .map_err(|_| failure("invalid public release advertisement"))?;
            if release.draft || release.tag_name != tag {
                return Err(failure("requested release is not publicly advertised"));
            }
            tag.to_owned()
        } else {
            let channel = channel
                .or_else(|| Version::parse(installed).ok().map(|v| v.channel()))
                .ok_or_else(|| {
                    CliError::usage("development builds require an explicit --version or --channel")
                })?;
            let mut best: Option<(Version, String)> = None;
            for page in 1..=1000 {
                let body = bytes(
                    &client,
                    &format!("/api/v1/repos/grund/grund/releases?limit=100&page={page}"),
                )
                .await?;
                let releases: Vec<Advertisement> = serde_json::from_slice(&body)
                    .map_err(|_| failure("invalid public release list"))?;
                let finished = releases.is_empty();
                if let Some(tag) = select(releases, channel) {
                    let version = Version::parse(&tag)?;
                    if best.as_ref().is_none_or(|(old, _)| version > *old) {
                        best = Some((version, tag));
                    }
                }
                if finished {
                    break;
                }
                if page == 1000 {
                    return Err(failure(
                        "public release pagination exceeded 1000 pages; use --version",
                    ));
                }
            }
            best.map(|(_, tag)| tag).ok_or_else(|| {
                CliError::new(
                    Code::NotFound,
                    "no published release exists in this channel; alpha requires --channel alpha",
                )
            })?
        };
        let body = bytes(
            &client,
            &format!("/api/packages/grund/generic/grund/{tag}/SHA256SUMS"),
        )
        .await?;
        let manifest =
            std::str::from_utf8(&body).map_err(|_| failure("SHA256SUMS is not UTF-8"))?;
        Ok(Self {
            tag,
            client,
            checksums: checksums(manifest)?,
        })
    }

    pub async fn download(&self, name: &str, destination: &Path) -> CliResult<()> {
        let expected = self
            .checksums
            .get(name)
            .ok_or_else(|| failure(format!("release has no checksum for {name}")))?;
        let limit = if name.starts_with("grund-") {
            MAX_BINARY
        } else {
            MAX_METADATA
        };
        let path = format!("/api/packages/grund/generic/grund/{}/{name}", self.tag);
        let mut response = response(&self.client, &path).await?;
        let mut temporary = tempfile::NamedTempFile::new_in(
            destination
                .parent()
                .ok_or_else(|| failure("artifact destination has no parent"))?,
        )
        .map_err(|e| failure(format!("could not stage artifact: {e}")))?;
        let mut size = 0u64;
        let mut digest = Sha256::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| failure("release artifact transfer failed"))?
        {
            size += chunk.len() as u64;
            if size > limit {
                return Err(failure("release artifact exceeds its size limit"));
            }
            digest.update(&chunk);
            temporary
                .write_all(&chunk)
                .map_err(|e| failure(format!("could not stage artifact: {e}")))?;
        }
        publish_verified(temporary, destination, expected, size, digest)
    }
}

fn publish_verified(
    temporary: tempfile::NamedTempFile,
    destination: &Path,
    expected: &str,
    size: u64,
    digest: Sha256,
) -> CliResult<()> {
    if size == 0 || format!("{:x}", digest.finalize()) != expected {
        return Err(failure(
            "artifact failed SHA-256 verification; the destination is unchanged",
        ));
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| failure(format!("could not sync artifact: {e}")))?;
    temporary
        .persist(destination)
        .map_err(|e| failure(format!("could not publish verified artifact: {e}")))?;
    Ok(())
}

pub fn binary_name() -> CliResult<String> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        _ => {
            return Err(CliError::usage(
                "this operating system has no supported release binary",
            ));
        }
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => {
            return Err(CliError::usage(
                "this architecture has no supported release binary",
            ));
        }
    };
    Ok(format!("grund-{os}-{arch}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_failure_leaves_the_previous_executable_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("grund");
        std::fs::write(&destination, b"previous executable").unwrap();
        let mut staged = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        staged.write_all(b"corrupt candidate").unwrap();
        let mut hash = Sha256::new();
        hash.update(b"corrupt candidate");
        assert!(publish_verified(staged, &destination, &"0".repeat(64), 17, hash).is_err());
        assert_eq!(std::fs::read(destination).unwrap(), b"previous executable");
    }

    #[test]
    fn alpha_numbers_order_numerically_and_stable_wins_its_base() {
        assert!(
            Version::parse("v1.2.3-alpha.10").unwrap() > Version::parse("v1.2.3-alpha.9").unwrap()
        );
        assert!(Version::parse("v1.2.3").unwrap() > Version::parse("v1.2.3-alpha.100").unwrap());
        for invalid in [
            "1.2.3",
            "v01.2.3",
            "v1.2.3-beta.1",
            "v1.2.3-alpha.0",
            "v1.2.3-alpha.01",
            "v1.2.3+dev",
            "v1.2.3/evil",
        ] {
            assert!(Version::parse(invalid).is_err());
        }
    }

    #[test]
    fn stable_selection_excludes_alphas_and_all_selection_excludes_drafts() {
        let releases = || {
            vec![
                Advertisement {
                    tag_name: "v2.0.0-alpha.10".into(),
                    draft: false,
                },
                Advertisement {
                    tag_name: "v1.0.0".into(),
                    draft: false,
                },
                Advertisement {
                    tag_name: "v9.0.0".into(),
                    draft: true,
                },
            ]
        };
        assert_eq!(
            select(releases(), Channel::Stable).as_deref(),
            Some("v1.0.0")
        );
        assert_eq!(
            select(releases(), Channel::Alpha).as_deref(),
            Some("v2.0.0-alpha.10")
        );
    }

    #[test]
    fn checksum_duplicates_and_unsafe_names_are_refused() {
        let hash = "a".repeat(64);
        assert!(
            checksums(&format!(
                "{hash}  grund-linux-amd64\n{hash}  grund-linux-amd64\n"
            ))
            .is_err()
        );
        assert!(checksums(&format!("{hash}  ../grund\n")).is_err());
        assert!(checksums(&format!("{}  grund\n", hash.to_uppercase())).is_err());
        assert_eq!(checksums(&format!("{hash}  grund\n")).unwrap().len(), 1);
    }
}
