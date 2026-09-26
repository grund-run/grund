//! Verified artifacts: a kernel or root filesystem named by URL and pinned by
//! SHA-256, fetched once into `<data dir>/images/<sha256>` and reused.
//!
//! A download lands under a name no other fetch uses and is renamed into
//! place only once its digest matches, so two VMs starting at once never
//! write the same file, and a half-written file is never used. A cached file
//! whose digest no longer matches is fetched again.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

pub use grund_agent::vm::Artifact;

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("image_url_unsupported")]
    Unsupported,
    #[error("image_digest_mismatch")]
    Digest,
    #[error("image_fetch_failed")]
    Fetch(#[source] anyhow::Error),
}

/// The cache of verified artifacts.
#[derive(Debug, Clone)]
pub struct Images {
    dir: PathBuf,
    http: reqwest::Client,
}

impl Images {
    pub fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .build()
            .map_err(std::io::Error::other)?;
        Ok(Self { dir, http })
    }

    /// The local path of `artifact`, fetching and verifying it if needed.
    pub async fn ensure(&self, artifact: &Artifact) -> Result<PathBuf, ImageError> {
        let digest = artifact.sha256.to_ascii_lowercase();
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ImageError::Digest);
        }
        let target = self.dir.join(&digest);
        if target.exists() && file_digest(&target).await.ok().as_deref() == Some(&digest) {
            return Ok(target);
        }
        let partial = self.dir.join(format!(
            ".{digest}.{}.partial",
            uuid::Uuid::now_v7().simple()
        ));
        let fetched = self.fetch(&artifact.url, &partial).await;
        let verified = match fetched {
            Ok(()) => file_digest(&partial)
                .await
                .map_err(|e| ImageError::Fetch(e.into())),
            Err(error) => Err(error),
        };
        match verified {
            Ok(got) if got == digest => {
                tokio::fs::rename(&partial, &target)
                    .await
                    .map_err(|e| ImageError::Fetch(e.into()))?;
                Ok(target)
            }
            Ok(_) => {
                let _ = tokio::fs::remove_file(&partial).await;
                Err(ImageError::Digest)
            }
            Err(error) => {
                let _ = tokio::fs::remove_file(&partial).await;
                Err(error)
            }
        }
    }

    async fn fetch(&self, url: &str, to: &Path) -> Result<(), ImageError> {
        let mut out = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(to)
            .await
            .map_err(|e| ImageError::Fetch(e.into()))?;
        if let Some(path) = url.strip_prefix("file://") {
            let mut source = tokio::fs::File::open(path)
                .await
                .map_err(|e| ImageError::Fetch(e.into()))?;
            tokio::io::copy(&mut source, &mut out)
                .await
                .map_err(|e| ImageError::Fetch(e.into()))?;
        } else if url.starts_with("https://") {
            let mut response = self
                .http
                .get(url)
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| ImageError::Fetch(e.into()))?;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| ImageError::Fetch(e.into()))?
            {
                out.write_all(&chunk)
                    .await
                    .map_err(|e| ImageError::Fetch(e.into()))?;
            }
        } else {
            return Err(ImageError::Unsupported);
        }
        out.sync_all()
            .await
            .map_err(|e| ImageError::Fetch(e.into()))?;
        Ok(())
    }
}

/// The lowercase hex SHA-256 of a file.
pub async fn file_digest(path: &Path) -> std::io::Result<String> {
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
        let dir = std::env::temp_dir().join(format!("grund-vm-image-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_file_is_cached_by_its_digest_and_a_wrong_digest_is_refused() {
        let dir = scratch();
        let source = dir.join("kernel");
        std::fs::write(&source, b"a kernel").unwrap();
        let sha256 = hex::encode(Sha256::digest(b"a kernel"));
        let images = Images::new(dir.join("images")).unwrap();
        let artifact = Artifact {
            url: format!("file://{}", source.display()),
            sha256: sha256.clone(),
        };
        let cached = images.ensure(&artifact).await.unwrap();
        assert_eq!(cached, dir.join("images").join(&sha256));
        assert_eq!(std::fs::read(&cached).unwrap(), b"a kernel");
        assert_eq!(
            std::fs::read(&source).unwrap(),
            b"a kernel",
            "the source is untouched"
        );
        let wrong = Artifact {
            sha256: "0".repeat(64),
            ..artifact.clone()
        };
        assert!(matches!(
            images.ensure(&wrong).await,
            Err(ImageError::Digest)
        ));
        let leftovers: Vec<_> = std::fs::read_dir(dir.join("images"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".partial"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a refused fetch leaves nothing behind"
        );
        let ftp = Artifact {
            url: "ftp://example.com/x".into(),
            sha256: "1".repeat(64),
        };
        assert!(matches!(
            images.ensure(&ftp).await,
            Err(ImageError::Unsupported)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
