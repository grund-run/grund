//! Images as the runtime sees them: a reference normalised the way Docker
//! does (`nginx` is `docker.io/library/nginx`), named in containerd as
//! `<name>@<digest>`, and read from the content store from its index (or
//! manifest) down to its config and the chain id of its layers.

use anyhow::Context;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// A Docker manifest list or OCI index.
pub const INDEX_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];
/// A Docker or OCI image manifest.
pub const MANIFEST_TYPES: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// The repository part of `reference`, normalised: a registry host
/// (`docker.io` when none is named), and `library/` for Docker Hub's
/// official images. Tag and digest are dropped.
pub fn normalize_name(reference: &str) -> anyhow::Result<String> {
    let without_digest = reference.split('@').next().unwrap_or_default();
    let name = match without_digest.rfind(':') {
        Some(colon) if !without_digest[colon..].contains('/') => &without_digest[..colon],
        _ => without_digest,
    };
    anyhow::ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/:".contains(&b))
            && !name.starts_with('/')
            && !name.ends_with('/')
            && !name.contains("//"),
        "not an image reference: {reference:?}"
    );
    let (domain, path) = match name.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            (first, rest.to_string())
        }
        _ => ("docker.io", name.to_string()),
    };
    let domain = if domain == "index.docker.io" {
        "docker.io"
    } else {
        domain
    };
    anyhow::ensure!(
        path.bytes().all(|b| !b.is_ascii_uppercase()),
        "image repository names are lowercase: {reference:?}"
    );
    let path = if domain == "docker.io" && !path.contains('/') {
        format!("library/{path}")
    } else {
        path
    };
    Ok(format!("{domain}/{path}"))
}

/// Whether `digest` is `sha256:` and 64 lowercase hex digits.
pub fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// containerd's name for an image pinned by digest, and what the registry is
/// asked for: `<normalised name>@<digest>`.
pub fn pinned_name(reference: &str, digest: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        valid_digest(digest),
        "image digest must be sha256:<64 lowercase hex>, not {digest:?}"
    );
    Ok(format!("{}@{digest}", normalize_name(reference)?))
}

/// `sha256:<hex>` of `bytes`.
pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// The chain id of a stack of layers (the OCI image spec's definition): the
/// first diff id, then `sha256(parent + " " + diff_id)` for each next one.
/// It names the committed snapshot an image is unpacked to.
pub fn chain_id(diff_ids: &[String]) -> Option<String> {
    let mut ids = diff_ids.iter();
    let mut chain = ids.next()?.clone();
    for id in ids {
        chain = sha256_digest(format!("{chain} {id}").as_bytes());
    }
    Some(chain)
}

/// A content descriptor inside an index or manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub digest: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub platform: Option<Platform>,
}

/// The platform of one manifest in an index.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(default)]
    pub variant: Option<String>,
}

/// An index or manifest: whichever fields the document has.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Document {
    #[serde(rename = "mediaType", default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
    #[serde(default)]
    pub config: Option<Descriptor>,
}

impl Document {
    /// Parses an index or manifest.
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes).context("parse an image index or manifest")
    }

    /// Whether this is an index (it lists manifests) rather than a manifest.
    pub fn is_index(&self) -> bool {
        match self.media_type.as_deref() {
            Some(t) if INDEX_TYPES.contains(&t) => true,
            Some(t) if MANIFEST_TYPES.contains(&t) => false,
            _ => self.config.is_none() && !self.manifests.is_empty(),
        }
    }

    /// The manifest for `linux/<oci arch>` in an index. For arm64 a
    /// `v8` variant or none matches.
    pub fn manifest_for(&self, oci_arch: &str) -> Option<&Descriptor> {
        self.manifests.iter().find(|m| {
            m.platform.as_ref().is_some_and(|p| {
                p.os == "linux"
                    && p.architecture == oci_arch
                    && (oci_arch != "arm64"
                        || matches!(p.variant.as_deref(), None | Some("") | Some("v8")))
            })
        })
    }
}

/// The parts of an image's config the runtime uses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub config: ProcessConfig,
    #[serde(default)]
    pub rootfs: RootFs,
}

/// How the image says to run it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ProcessConfig {
    #[serde(rename = "User", default)]
    pub user: Option<String>,
    #[serde(rename = "Env", default)]
    pub env: Option<Vec<String>>,
    #[serde(rename = "Entrypoint", default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", default)]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: Option<String>,
}

/// The image's layers, as uncompressed digests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct RootFs {
    #[serde(default)]
    pub diff_ids: Vec<String>,
}

impl ImageConfig {
    /// Parses an image config.
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes).context("parse an image config")
    }

    /// The chain id of its layers.
    pub fn chain_id(&self) -> anyhow::Result<String> {
        chain_id(&self.rootfs.diff_ids).context("the image has no layers")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_normalised_the_way_docker_does() {
        for (reference, name) in [
            ("nginx", "docker.io/library/nginx"),
            ("nginx:1.27", "docker.io/library/nginx"),
            ("nginx@sha256:abc", "docker.io/library/nginx"),
            ("traefik/whoami:v1.11.0", "docker.io/traefik/whoami"),
            ("docker.io/nginx", "docker.io/library/nginx"),
            ("index.docker.io/library/nginx", "docker.io/library/nginx"),
            ("ghcr.io/grund-run/app:main", "ghcr.io/grund-run/app"),
            ("localhost:5000/app:1", "localhost:5000/app"),
            ("localhost/app", "localhost/app"),
            (
                "registry.example.com:8443/team/app",
                "registry.example.com:8443/team/app",
            ),
        ] {
            assert_eq!(normalize_name(reference).unwrap(), name, "{reference}");
        }
        for bad in ["", "/nginx", "nginx/", "Nginx", "a//b", "nginx bad"] {
            assert!(normalize_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_pinned_name_needs_a_full_sha256_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            pinned_name("nginx:latest", &digest).unwrap(),
            format!("docker.io/library/nginx@{digest}")
        );
        for bad in [
            "sha256:abc".to_string(),
            format!("sha512:{}", "a".repeat(64)),
            format!("sha256:{}", "A".repeat(64)),
        ] {
            assert!(pinned_name("nginx", &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_chain_id_of_one_layer_is_its_diff_id_and_then_chains() {
        assert_eq!(chain_id(&[]), None);
        let a = sha256_digest(b"a");
        let b = sha256_digest(b"b");
        let c = sha256_digest(b"c");
        assert_eq!(chain_id(std::slice::from_ref(&a)), Some(a.clone()));
        let ab = sha256_digest(format!("{a} {b}").as_bytes());
        assert_eq!(chain_id(&[a.clone(), b.clone()]), Some(ab.clone()));
        let abc = sha256_digest(format!("{ab} {c}").as_bytes());
        assert_eq!(chain_id(&[a, b, c]), Some(abc));
    }

    #[test]
    fn the_chain_id_matches_a_real_image() {
        let config = ImageConfig::parse(
            br#"{"rootfs":{"type":"layers","diff_ids":[
                "sha256:844eea3cbc1988804eb56f1667f5a207108d1b9f178d25d03359b03b3521eed8",
                "sha256:ab60ddbdc8b2a3bf1a8c0e1f2f8d2a3b5ab6e2a3a8f6b7d7c6b0fdb5e5d1d0b1"]}}"#,
        )
        .unwrap();
        let first = "sha256:844eea3cbc1988804eb56f1667f5a207108d1b9f178d25d03359b03b3521eed8";
        let second = "sha256:ab60ddbdc8b2a3bf1a8c0e1f2f8d2a3b5ab6e2a3a8f6b7d7c6b0fdb5e5d1d0b1";
        assert_eq!(
            config.chain_id().unwrap(),
            sha256_digest(format!("{first} {second}").as_bytes())
        );
    }

    #[test]
    fn an_index_yields_this_architectures_linux_manifest() {
        let index = Document::parse(
            br#"{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests":[
              {"digest":"sha256:arm7","platform":{"architecture":"arm","os":"linux","variant":"v7"}},
              {"digest":"sha256:win","platform":{"architecture":"amd64","os":"windows"}},
              {"digest":"sha256:amd","platform":{"architecture":"amd64","os":"linux"}},
              {"digest":"sha256:arm64","platform":{"architecture":"arm64","os":"linux","variant":"v8"}}
            ]}"#,
        )
        .unwrap();
        assert!(index.is_index());
        assert_eq!(index.manifest_for("amd64").unwrap().digest, "sha256:amd");
        assert_eq!(index.manifest_for("arm64").unwrap().digest, "sha256:arm64");
        assert!(index.manifest_for("riscv64").is_none());
        let manifest = Document::parse(
            br#"{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cfg","size":2}}"#,
        )
        .unwrap();
        assert!(!manifest.is_index());
        assert_eq!(manifest.config.unwrap().digest, "sha256:cfg");
    }
}
