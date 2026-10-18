//! The premade apps the dashboard offers. Deployable images are pinned by
//! digest; unavailable entries explain why they cannot be deployed.

use grund_config::app::spec::{
    AppSpec, CheckKind, CheckSpec, EnvVar, PortSpec, Protocol, StopSpec, VolumeSpec,
};

/// The app-owned data directory and its default hosted capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateStorage {
    pub path: &'static str,
    pub size_gib: u64,
}

/// One premade app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// Its key in addresses, and the name a new app gets by default.
    pub key: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    /// The image, its tag kept for people and its digest for grund. Empty
    /// only when the template is unavailable.
    pub image: &'static str,
    /// The complete entrypoint and arguments, or empty to use the image defaults.
    pub command: &'static [&'static str],
    /// Nonsecret settings; credentials are supplied through `secret_variables`.
    pub env: &'static [(&'static str, &'static str)],
    /// Environment variables whose values must be generated and stored as secrets.
    pub secret_variables: &'static [&'static str],
    /// `(name, port, protocol)`; the first is the app's main port.
    pub ports: &'static [(&'static str, u16, Protocol)],
    /// The port that may be given a public HTTP address, by name.
    pub publishable: Option<&'static str>,
    /// An HTTP ready check: the port's name and the path. Otherwise the main
    /// port receives a TCP check.
    pub check: Option<(&'static str, &'static str)>,
    pub memory_mib: u64,
    pub cpu_millis: u32,
    pub storage: Option<TemplateStorage>,
    /// Why this app cannot currently be deployed.
    pub unavailable: Option<&'static str>,
}

const NATS_IMAGE: &str =
    "nats:2.10-alpine@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927";
const WHOAMI_IMAGE: &str = "traefik/whoami:v1.11.0@sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab";
const NGINX_IMAGE: &str =
    "nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10";
const POSTGRES_IMAGE: &str =
    "postgres:17.11-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const REDIS_IMAGE: &str =
    "redis:7.4.11-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499";

/// Every premade app, including unavailable entries.
pub const CATALOGUE: &[Template] = &[
    Template {
        key: "nats",
        title: "NATS",
        summary: "A messaging server for your apps, without persistence: JetStream needs storage.",
        image: NATS_IMAGE,
        command: &[],
        env: &[],
        secret_variables: &[],
        ports: &[
            ("client", 4222, Protocol::Tcp),
            ("monitor", 8222, Protocol::Http),
        ],
        publishable: None,
        check: Some(("monitor", "/healthz")),
        memory_mib: 256,
        cpu_millis: 500,
        storage: None,
        unavailable: None,
    },
    Template {
        key: "whoami",
        title: "whoami",
        summary: "Traefik's tiny web server that answers with the request it got. Good for a first deploy.",
        image: WHOAMI_IMAGE,
        command: &[],
        env: &[],
        secret_variables: &[],
        ports: &[("http", 80, Protocol::Http)],
        publishable: Some("http"),
        check: Some(("http", "/health")),
        memory_mib: 64,
        cpu_millis: 100,
        storage: None,
        unavailable: None,
    },
    Template {
        key: "nginx",
        title: "nginx",
        summary: "A web server showing its welcome page, ready to serve your own files from an image built on it.",
        image: NGINX_IMAGE,
        command: &[],
        env: &[],
        secret_variables: &[],
        ports: &[("http", 80, Protocol::Http)],
        publishable: Some("http"),
        check: Some(("http", "/")),
        memory_mib: 128,
        cpu_millis: 250,
        storage: None,
        unavailable: None,
    },
    Template {
        key: "postgres",
        title: "PostgreSQL",
        summary: "A relational database.",
        image: POSTGRES_IMAGE,
        command: &[
            "/bin/sh",
            "-ec",
            "chown postgres:postgres /var/lib/postgresql/data; exec /usr/local/bin/docker-entrypoint.sh postgres -c 'listen_addresses=*'",
        ],
        env: &[
            ("POSTGRES_USER", "grund"),
            ("POSTGRES_DB", "grund"),
            ("PGDATA", "/var/lib/postgresql/data/pgdata"),
        ],
        secret_variables: &["POSTGRES_PASSWORD"],
        ports: &[("postgres", 5432, Protocol::Tcp)],
        publishable: None,
        check: None,
        memory_mib: 512,
        cpu_millis: 500,
        storage: Some(TemplateStorage {
            path: "/var/lib/postgresql/data",
            size_gib: 10,
        }),
        unavailable: None,
    },
    Template {
        key: "redis",
        title: "Redis",
        summary: "A password-protected in-memory store. Abrupt power loss can lose about one second of writes.",
        image: REDIS_IMAGE,
        command: &[
            "/bin/sh",
            "-ec",
            "exec /usr/local/bin/docker-entrypoint.sh redis-server --dir /data --appendonly yes --appendfsync everysec --requirepass \"${REDIS_PASSWORD:?REDIS_PASSWORD must be set}\"",
        ],
        env: &[],
        secret_variables: &["REDIS_PASSWORD"],
        ports: &[("redis", 6379, Protocol::Tcp)],
        publishable: None,
        check: None,
        memory_mib: 256,
        cpu_millis: 500,
        storage: Some(TemplateStorage {
            path: "/data",
            size_gib: 1,
        }),
        unavailable: None,
    },
    Template {
        key: "minio",
        title: "MinIO",
        summary: "S3-compatible object storage.",
        image: "",
        command: &[],
        env: &[],
        secret_variables: &[],
        ports: &[],
        publishable: None,
        check: None,
        memory_mib: 0,
        cpu_millis: 0,
        storage: Some(TemplateStorage {
            path: "/data",
            size_gib: 10,
        }),
        unavailable: Some("MinIO no longer publishes public images; coming later"),
    },
];

/// The template with this key.
pub fn find(key: &str) -> Option<&'static Template> {
    CATALOGUE.iter().find(|t| t.key == key)
}

impl Template {
    /// The local-machine spec, or `None` when unavailable. Only its publishable
    /// port can become public. Storage uses one app-owned volume; hosted callers
    /// set its capacity and backup policy before launch.
    pub fn spec(&self, public: bool) -> Option<AppSpec> {
        if self.unavailable.is_some() {
            return None;
        }
        let check = if let Some((name, path)) = self.check {
            self.ports
                .iter()
                .find(|(port_name, _, _)| *port_name == name)
                .map(|(_, port, _)| CheckSpec {
                    kind: CheckKind::Http {
                        path: path.to_string(),
                    },
                    port: *port,
                    interval_ms: 0,
                    timeout_ms: 0,
                })
        } else {
            self.ports.first().map(|(_, port, _)| CheckSpec {
                kind: CheckKind::Tcp,
                port: *port,
                interval_ms: 0,
                timeout_ms: 0,
            })
        };
        Some(AppSpec {
            image: self.image.to_string(),
            command: self.command.iter().map(|value| (*value).into()).collect(),
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
            env: self
                .env
                .iter()
                .map(|(name, value)| EnvVar {
                    name: (*name).into(),
                    value: (*value).into(),
                })
                .collect(),
            volumes: self
                .storage
                .iter()
                .map(|storage| VolumeSpec {
                    name: "data".into(),
                    path: storage.path.into(),
                    source: None,
                    size_gib: None,
                    backup: false,
                })
                .collect(),
            secrets: Vec::new(),
            check,
            stop: StopSpec::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grund_config::app::spec::{AppName, ImageReference};

    #[test]
    fn every_available_template_is_a_valid_spec_pinned_by_digest() {
        for template in CATALOGUE.iter().filter(|t| t.unavailable.is_none()) {
            AppName::parse(template.key).expect("its key is an app name");
            let reference = ImageReference::parse(template.image).expect("a reference");
            assert!(reference.digest.is_some(), "{} is pinned", template.key);
            assert!(reference.tag.is_some(), "{} keeps its tag", template.key);
            for public in [false, true] {
                let spec = template.spec(public).expect("available");
                let spec = spec
                    .validate()
                    .unwrap_or_else(|e| panic!("{}: {e}", template.key));
                let text = grund_config::app::file::render(
                    template.key,
                    &spec,
                    &grund_config::app::spec::AppSettings::default(),
                    "x",
                );
                assert_eq!(
                    grund_config::app::file::parse_app(&text, template.key)
                        .unwrap()
                        .spec,
                    spec
                );
            }
        }
    }

    #[test]
    fn only_a_publishable_port_is_ever_public() {
        for template in CATALOGUE {
            let Some(spec) = template.spec(true) else {
                continue;
            };
            for port in spec.ports {
                assert_eq!(
                    port.public,
                    template.publishable == Some(port.name.as_str())
                );
            }
            assert!(
                template
                    .spec(false)
                    .unwrap()
                    .ports
                    .iter()
                    .all(|port| !port.public)
            );
        }
    }

    #[test]
    fn databases_keep_one_app_owned_local_data_volume_and_credentials_out_of_plain_env() {
        for key in ["postgres", "redis"] {
            let template = find(key).unwrap();
            let storage = template.storage.unwrap();
            let spec = template.spec(false).unwrap().validate().unwrap();
            let [volume] = spec.volumes.as_slice() else {
                panic!("{key} must have one data volume");
            };
            assert_eq!(volume.name, "data");
            assert_eq!(volume.path, storage.path);
            assert_eq!(volume.source, None);
            assert_eq!(volume.size_gib, None);
            assert!(!volume.backup);
            for variable in template.secret_variables {
                assert!(spec.env.iter().all(|env| env.name != *variable));
            }
            let check = spec.check.unwrap();
            assert_eq!(check.kind, CheckKind::Tcp);
            assert_eq!(check.port, spec.ports[0].port);
        }
    }

    #[test]
    fn postgres_initializes_below_the_volume_root_so_a_filesystem_can_have_lost_found() {
        let spec = find("postgres").unwrap().spec(false).unwrap();
        let pgdata = spec.env.iter().find(|env| env.name == "PGDATA").unwrap();
        assert!(
            pgdata
                .value
                .starts_with(&format!("{}/", spec.volumes[0].path))
        );
    }

    #[test]
    fn unavailable_templates_cannot_produce_a_deployable_spec() {
        let minio = find("minio").unwrap();
        assert!(minio.unavailable.is_some());
        assert!(minio.spec(false).is_none());
        assert!(minio.spec(true).is_none());
        assert!(find("unknown").is_none());
    }
}
