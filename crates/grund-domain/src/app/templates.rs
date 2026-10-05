//! The premade apps the dashboard offers (Deploy app → Premade, and the
//! Templates page): a short, plain list of specs, each image pinned by
//! digest. Only apps that work without a volume are deployable; the ones
//! that need storage are listed as coming with it (grund-docs
//! design/apps.md §4, M4). The format is deliberately this list, so that
//! templates as files can replace it without touching the pages.

use super::spec::{AppSpec, CheckKind, CheckSpec, PortSpec, Protocol, StopSpec};

/// One premade app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// Its key in addresses, and the name a new app gets by default.
    pub key: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    /// The image, its tag kept for people and its digest for grund. Empty
    /// for one that needs storage.
    pub image: &'static str,
    /// `(name, port, protocol)`; the first is the app's main port.
    pub ports: &'static [(&'static str, u16, Protocol)],
    /// The port that may be given a public HTTP address, by name.
    pub publishable: Option<&'static str>,
    /// An HTTP ready check: the port's name and the path.
    pub check: Option<(&'static str, &'static str)>,
    pub memory_mib: u64,
    pub cpu_millis: u32,
    /// Needs a volume, which grund does not have yet: shown, never deployed.
    pub needs_storage: bool,
}

const NATS_IMAGE: &str =
    "nats:2.10-alpine@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927";
const WHOAMI_IMAGE: &str = "traefik/whoami:v1.11.0@sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab";
const NGINX_IMAGE: &str =
    "nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10";

const fn storage(key: &'static str, title: &'static str, summary: &'static str) -> Template {
    Template {
        key,
        title,
        summary,
        image: "",
        ports: &[],
        publishable: None,
        check: None,
        memory_mib: 0,
        cpu_millis: 0,
        needs_storage: true,
    }
}

/// Every premade app, deployable ones first.
pub const CATALOGUE: &[Template] = &[
    Template {
        key: "nats",
        title: "NATS",
        summary: "A messaging server for your apps, without persistence: JetStream needs storage.",
        image: NATS_IMAGE,
        ports: &[
            ("client", 4222, Protocol::Tcp),
            ("monitor", 8222, Protocol::Http),
        ],
        publishable: None,
        check: Some(("monitor", "/healthz")),
        memory_mib: 256,
        cpu_millis: 500,
        needs_storage: false,
    },
    Template {
        key: "whoami",
        title: "whoami",
        summary: "Traefik's tiny web server that answers with the request it got. Good for a first deploy.",
        image: WHOAMI_IMAGE,
        ports: &[("http", 80, Protocol::Http)],
        publishable: Some("http"),
        check: Some(("http", "/health")),
        memory_mib: 64,
        cpu_millis: 100,
        needs_storage: false,
    },
    Template {
        key: "nginx",
        title: "nginx",
        summary: "A web server showing its welcome page, ready to serve your own files from an image built on it.",
        image: NGINX_IMAGE,
        ports: &[("http", 80, Protocol::Http)],
        publishable: Some("http"),
        check: Some(("http", "/")),
        memory_mib: 128,
        cpu_millis: 250,
        needs_storage: false,
    },
    storage("postgres", "PostgreSQL", "A relational database."),
    storage(
        "redis",
        "Redis",
        "An in-memory store that keeps its data on disk.",
    ),
    storage("minio", "MinIO", "S3-compatible object storage."),
];

/// The template with this key.
pub fn find(key: &str) -> Option<&'static Template> {
    CATALOGUE.iter().find(|t| t.key == key)
}

impl Template {
    /// The spec this template deploys, with its publishable port public
    /// when `public`. `None` for one that needs storage.
    pub fn spec(&self, public: bool) -> Option<AppSpec> {
        if self.needs_storage {
            return None;
        }
        let port_of = |name: &str| {
            self.ports
                .iter()
                .find(|(n, _, _)| *n == name)
                .map_or(0, |(_, port, _)| *port)
        };
        Some(AppSpec {
            image: self.image.to_string(),
            command: Vec::new(),
            ports: self
                .ports
                .iter()
                .map(|(name, port, protocol)| PortSpec {
                    name: name.to_string(),
                    port: *port,
                    protocol: *protocol,
                    public: public && self.publishable == Some(*name),
                })
                .collect(),
            memory_mib: self.memory_mib,
            cpu_millis: self.cpu_millis,
            env: Vec::new(),
            secrets: Vec::new(),
            check: self.check.map(|(port, path)| CheckSpec {
                kind: CheckKind::Http {
                    path: path.to_string(),
                },
                port: port_of(port),
                interval_ms: 0,
                timeout_ms: 0,
            }),
            stop: StopSpec::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::spec::{AppName, ImageReference};

    #[test]
    fn every_deployable_template_is_a_valid_spec_pinned_by_digest() {
        for template in CATALOGUE.iter().filter(|t| !t.needs_storage) {
            AppName::parse(template.key).expect("its key is an app name");
            let reference = ImageReference::parse(template.image).expect("a reference");
            assert!(reference.digest.is_some(), "{} is pinned", template.key);
            assert!(reference.tag.is_some(), "{} keeps its tag", template.key);
            for public in [false, true] {
                let spec = template.spec(public).expect("deployable");
                spec.validate()
                    .unwrap_or_else(|e| panic!("{}: {e}", template.key));
            }
        }
    }

    #[test]
    fn only_a_publishable_port_is_ever_public() {
        let nats = find("nats").unwrap().spec(true).unwrap();
        assert!(nats.ports.iter().all(|p| !p.public));
        let whoami = find("whoami").unwrap().spec(true).unwrap();
        assert!(whoami.ports[0].public);
        assert!(!find("whoami").unwrap().spec(false).unwrap().ports[0].public);
    }

    #[test]
    fn a_template_that_needs_storage_is_never_deployed() {
        let postgres = find("postgres").unwrap();
        assert!(postgres.needs_storage);
        assert!(postgres.spec(false).is_none());
        assert!(find("unknown").is_none());
    }
}
