//! The runtime's own binaries: containerd's static release and runc, pinned
//! by version and SHA-256, fetched on first use from their GitHub releases.
//!
//! ```text
//!   <data dir>/bin/containerd-2.4.1/containerd
//!                                   containerd-shim-runc-v2
//!                                   runc
//! ```
//!
//! A fetch lands in a directory no other fetch uses
//! (`.containerd-2.4.1.<uuid>`), every file is checked against its pinned
//! digest, and only then is the directory renamed into place, so a
//! half-written or tampered binary is never run. An installed directory is
//! checked again, file by file, before containerd is started from it.

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::Context;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

/// containerd's pinned release.
pub const CONTAINERD_VERSION: &str = "2.4.1";
/// runc's pinned release.
pub const RUNC_VERSION: &str = "1.5.1";

/// The binaries the runtime runs, by name in its directory.
pub const CONTAINERD: &str = "containerd";
/// containerd's runc shim, found by containerd on its `PATH`.
pub const SHIM: &str = "containerd-shim-runc-v2";
/// runc, found by the shim through the container's runtime options.
pub const RUNC: &str = "runc";

/// A machine architecture grund runs containers on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// This machine's, when it is one grund supports.
    pub fn of_host() -> Option<Self> {
        Self::parse(std::env::consts::ARCH)
    }

    /// From the kernel's (and Rust's) name: `x86_64` or `aarch64`.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "x86_64" => Some(Self::X86_64),
            "aarch64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// The kernel's name, as [`grund_agent::runtime::AppsCapabilities`]
    /// reports it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// The OCI (Go) name, as image platforms and release files use it.
    pub fn oci(self) -> &'static str {
        match self {
            Self::X86_64 => "amd64",
            Self::Aarch64 => "arm64",
        }
    }
}

/// A file to fetch, and the SHA-256 (lowercase hex) it must have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    /// `https://`, `http://` or `file://`. Plain http is safe because
    /// nothing is used before its digest matches.
    pub url: String,
    pub sha256: String,
}

/// Everything the runtime fetches, and the digests of what it unpacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// The directory name under `<data dir>/bin`.
    pub name: String,
    /// containerd's static release tarball.
    pub containerd_tarball: Pinned,
    /// `bin/containerd` inside the tarball.
    pub containerd_sha256: String,
    /// `bin/containerd-shim-runc-v2` inside the tarball.
    pub shim_sha256: String,
    /// The runc binary.
    pub runc: Pinned,
}

impl Release {
    /// containerd 2.4.1 and runc 1.5.1 for `arch`, from their GitHub
    /// releases. The digests were computed from those files on 2026-10-01
    /// and match the `.sha256sum` files both projects publish.
    pub fn pinned(arch: Arch) -> Self {
        let (tarball, containerd, shim, runc) = match arch {
            Arch::X86_64 => (
                "02ad3a7e80d7d2c018c7134d5eca7e301283db6895f100b957fb52ad8e5a30fd",
                "45b43413b415efbc163ce2de800abd22cc86a1ae35a5e0685f91ea66bdb2c568",
                "ce5d6a694226f602baa2e1f44c43df7b0bd41888baf6f5d5d550dccc7de23241",
                "177df879d50c913eb205e898d5c1c05a18f574053c0ce5524c471208eaf06f6f",
            ),
            Arch::Aarch64 => (
                "d3aba9347650505df79858bb9cbf1be52080fd8145f72dd9308d4936f487fb74",
                "5dd4de632c8d89d5872bcac9e05098a4787881c27f7fa4c0891a748c7924b94f",
                "55efdab310bfbd4ebd7791b9ec8049802b4001d6ea0767ba14e1fe3379845d99",
                "ca70e7dbd6616ca782a59b5d3ac86909123fdaa9fa3f89dcf29051c70eee7ce9",
            ),
        };
        let goarch = arch.oci();
        Self {
            name: format!("containerd-{CONTAINERD_VERSION}"),
            containerd_tarball: Pinned {
                url: format!(
                    "https://github.com/containerd/containerd/releases/download/v{CONTAINERD_VERSION}/containerd-static-{CONTAINERD_VERSION}-linux-{goarch}.tar.gz"
                ),
                sha256: tarball.into(),
            },
            containerd_sha256: containerd.into(),
            shim_sha256: shim.into(),
            runc: Pinned {
                url: format!(
                    "https://github.com/opencontainers/runc/releases/download/v{RUNC_VERSION}/runc.{goarch}"
                ),
                sha256: runc.into(),
            },
        }
    }

    fn expected(&self) -> [(&'static str, &str); 3] {
        [
            (CONTAINERD, self.containerd_sha256.as_str()),
            (SHIM, self.shim_sha256.as_str()),
            (RUNC, self.runc.sha256.as_str()),
        ]
    }
}

/// The HTTP client releases are fetched with: grund's TLS provider
/// (grund-tls), and a bounded connect.
pub fn http_client() -> anyhow::Result<reqwest::Client> {
    grund_tls::install_default();
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build an HTTP client")
}

/// Why the binaries could not be had.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("{url} has SHA-256 {got}, not the pinned {want}")]
    Digest {
        url: String,
        want: String,
        got: String,
    },
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Makes sure `<bin root>/<release name>` holds the release's binaries,
/// each with its pinned digest, fetching them if it does not. Returns the
/// directory.
pub async fn install(
    http: &reqwest::Client,
    bin_root: &Path,
    release: &Release,
) -> Result<PathBuf, FetchError> {
    let dir = bin_root.join(&release.name);
    if verify_dir(&dir, release).await.is_ok() {
        return Ok(dir);
    }
    tokio::fs::create_dir_all(bin_root)
        .await
        .with_context(|| format!("create {}", bin_root.display()))?;
    let staging = bin_root.join(format!(
        ".{}.{}",
        release.name,
        uuid::Uuid::now_v7().simple()
    ));
    let result = stage(http, &staging, release).await;
    if let Err(error) = result {
        let _ = tokio::fs::remove_dir_all(&staging).await;
        return Err(error);
    }
    if tokio::fs::metadata(&dir).await.is_ok() {
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    tokio::fs::rename(&staging, &dir)
        .await
        .with_context(|| format!("move {} into place", dir.display()))?;
    verify_dir(&dir, release).await?;
    Ok(dir)
}

async fn stage(
    http: &reqwest::Client,
    staging: &Path,
    release: &Release,
) -> Result<(), FetchError> {
    tokio::fs::create_dir_all(staging)
        .await
        .with_context(|| format!("create {}", staging.display()))?;
    let tarball = staging.join("containerd.tar.gz");
    fetch_verified(http, &release.containerd_tarball, &tarball).await?;
    let into = staging.to_path_buf();
    let from = tarball.clone();
    tokio::task::spawn_blocking(move || unpack(&from, &into))
        .await
        .map_err(anyhow::Error::from)??;
    tokio::fs::remove_file(&tarball).await.ok();
    fetch_verified(http, &release.runc, &staging.join(RUNC)).await?;
    for name in [CONTAINERD, SHIM, RUNC] {
        tokio::fs::set_permissions(staging.join(name), std::fs::Permissions::from_mode(0o755))
            .await
            .with_context(|| format!("chmod {name}"))?;
    }
    verify_dir(staging, release).await
}

fn unpack(tarball: &Path, into: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(tarball)?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut found = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let name = match path.to_str() {
            Some("bin/containerd") => CONTAINERD,
            Some("bin/containerd-shim-runc-v2") => SHIM,
            _ => continue,
        };
        let mut out = std::fs::File::create(into.join(name))?;
        std::io::copy(&mut entry, &mut out)?;
        out.sync_all()?;
        found += 1;
    }
    anyhow::ensure!(
        found == 2,
        "the containerd tarball lacks bin/containerd or bin/containerd-shim-runc-v2"
    );
    Ok(())
}

/// Checks every binary in `dir` against the release's digests.
pub async fn verify_dir(dir: &Path, release: &Release) -> Result<(), FetchError> {
    for (name, want) in release.expected() {
        let path = dir.join(name);
        let got = file_sha256(&path)
            .await
            .with_context(|| format!("read {}", path.display()))?;
        if got != want {
            return Err(FetchError::Digest {
                url: path.display().to_string(),
                want: want.into(),
                got,
            });
        }
    }
    Ok(())
}

/// Fetches `pinned` to `to` (created new), and removes it again unless its
/// digest is the pinned one.
pub async fn fetch_verified(
    http: &reqwest::Client,
    pinned: &Pinned,
    to: &Path,
) -> Result<(), FetchError> {
    if let Err(error) = fetch(http, &pinned.url, to).await {
        let _ = tokio::fs::remove_file(to).await;
        return Err(error.into());
    }
    let got = file_sha256(to).await.context("hash the download")?;
    if !got.eq_ignore_ascii_case(&pinned.sha256) {
        let _ = tokio::fs::remove_file(to).await;
        return Err(FetchError::Digest {
            url: pinned.url.clone(),
            want: pinned.sha256.clone(),
            got,
        });
    }
    Ok(())
}

async fn fetch(http: &reqwest::Client, url: &str, to: &Path) -> anyhow::Result<()> {
    let mut out = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .await
        .with_context(|| format!("create {}", to.display()))?;
    if let Some(path) = url.strip_prefix("file://") {
        let mut source = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("open {path}"))?;
        tokio::io::copy(&mut source, &mut out).await?;
    } else if url.starts_with("https://") || url.starts_with("http://") {
        let mut response = http
            .get(url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("fetch {url}"))?;
        while let Some(chunk) = response
            .chunk()
            .await
            .with_context(|| format!("fetch {url}"))?
        {
            out.write_all(&chunk).await?;
        }
    } else {
        anyhow::bail!("unsupported URL {url}");
    }
    out.sync_all().await?;
    Ok(())
}

/// The lowercase hex SHA-256 of a file.
pub async fn file_sha256(path: &Path) -> std::io::Result<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(hex::encode(hasher.finalize()))
    })
    .await
    .map_err(std::io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "grund-containers-bin-{}",
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn tarball(dir: &Path, containerd: &[u8], shim: &[u8]) -> PathBuf {
        let path = dir.join("containerd.tar.gz");
        let file = std::fs::File::create(&path).unwrap();
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            file,
            flate2::Compression::fast(),
        ));
        for (name, body) in [
            ("bin/containerd", containerd),
            ("bin/containerd-shim-runc-v2", shim),
            ("bin/ctr", b"ctr".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, body).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    fn release(dir: &Path) -> Release {
        let tarball = tarball(dir, b"containerd", b"shim");
        std::fs::write(dir.join("runc.src"), b"runc").unwrap();
        Release {
            name: "containerd-test".into(),
            containerd_tarball: Pinned {
                url: format!("file://{}", tarball.display()),
                sha256: sha(&std::fs::read(&tarball).unwrap()),
            },
            containerd_sha256: sha(b"containerd"),
            shim_sha256: sha(b"shim"),
            runc: Pinned {
                url: format!("file://{}", dir.join("runc.src").display()),
                sha256: sha(b"runc"),
            },
        }
    }

    #[tokio::test]
    async fn a_verified_release_is_unpacked_into_place_with_only_its_three_binaries() {
        let dir = scratch();
        let release = release(&dir);
        let http = http_client().unwrap();
        let bin = install(&http, &dir.join("bin"), &release).await.unwrap();
        assert_eq!(bin, dir.join("bin/containerd-test"));
        let mut names: Vec<_> = std::fs::read_dir(&bin)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["containerd", "containerd-shim-runc-v2", "runc"]);
        assert_eq!(std::fs::read(bin.join("runc")).unwrap(), b"runc");
        let mode = std::fs::metadata(bin.join("runc"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        let again = install(&http, &dir.join("bin"), &release).await.unwrap();
        assert_eq!(again, bin);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_tampered_download_is_refused_and_leaves_nothing_behind() {
        let dir = scratch();
        let mut release = release(&dir);
        std::fs::write(dir.join("runc.src"), b"runc, but tampered").unwrap();
        let http = http_client().unwrap();
        let error = install(&http, &dir.join("bin"), &release)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, FetchError::Digest { want, .. } if *want == sha(b"runc")),
            "{error}"
        );
        assert_eq!(std::fs::read_dir(dir.join("bin")).unwrap().count(), 0);
        release.containerd_sha256 = sha(b"another containerd");
        std::fs::write(dir.join("runc.src"), b"runc").unwrap();
        let error = install(&http, &dir.join("bin"), &release)
            .await
            .unwrap_err();
        assert!(matches!(error, FetchError::Digest { .. }), "{error}");
        assert_eq!(std::fs::read_dir(dir.join("bin")).unwrap().count(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn an_installed_binary_changed_on_disk_is_fetched_again() {
        let dir = scratch();
        let release = release(&dir);
        let http = http_client().unwrap();
        let bin = install(&http, &dir.join("bin"), &release).await.unwrap();
        std::fs::write(bin.join("containerd"), b"swapped").unwrap();
        assert!(verify_dir(&bin, &release).await.is_err());
        install(&http, &dir.join("bin"), &release).await.unwrap();
        assert_eq!(
            std::fs::read(bin.join("containerd")).unwrap(),
            b"containerd"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_pinned_releases_name_both_architectures_files() {
        let x86 = Release::pinned(Arch::X86_64);
        assert!(
            x86.containerd_tarball
                .url
                .ends_with("containerd-static-2.4.1-linux-amd64.tar.gz")
        );
        assert!(x86.runc.url.ends_with("/v1.5.1/runc.amd64"));
        let arm = Release::pinned(Arch::Aarch64);
        assert!(
            arm.containerd_tarball
                .url
                .ends_with("containerd-static-2.4.1-linux-arm64.tar.gz")
        );
        assert!(arm.runc.url.ends_with("/v1.5.1/runc.arm64"));
        for release in [x86, arm] {
            for digest in [
                &release.containerd_tarball.sha256,
                &release.containerd_sha256,
                &release.shim_sha256,
                &release.runc.sha256,
            ] {
                assert_eq!(digest.len(), 64);
                assert!(
                    digest
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                );
            }
        }
    }
}
