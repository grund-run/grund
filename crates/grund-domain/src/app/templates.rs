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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Template {
    /// Its key in addresses, and the name a new app gets by default.
    pub key: &'static str,
    /// Templates of one family share credentials and connection outputs, and a
    /// stack service may move between them: each is the same product at
    /// another major version, and its start script converts the data.
    pub family: &'static str,
    /// The product's major version, pinned with the image; `None` when a newer
    /// image is always a drop-in replacement.
    pub major: Option<&'static str>,
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
    /// `(signal, grace seconds)` when SIGTERM and 30 seconds do not stop the image cleanly.
    pub stop: Option<(&'static str, u32)>,
    pub storage: Option<TemplateStorage>,
    /// Why this app cannot currently be deployed.
    pub unavailable: Option<&'static str>,
}

const NATS_IMAGE: &str =
    "nats:2.10-alpine@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927";
const WHOAMI_IMAGE: &str = "traefik/whoami:v1.11.0@sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab";
const NGINX_IMAGE: &str =
    "nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10";
const POSTGRES_17_IMAGE: &str =
    "postgres:17.11-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const POSTGRES_18_IMAGE: &str =
    "postgres:18.7-alpine@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015";
const REDIS_IMAGE: &str =
    "redis:7.4.11-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499";
const SEAWEEDFS_IMAGE: &str = "chrislusf/seaweedfs:4.48@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d";
const CLICKHOUSE_IMAGE: &str = "clickhouse/clickhouse-server:25.8.33.6@sha256:0152dd511befe6a2c2ef53e930726179669b08116da78500b37c51c96ff5ee77";

/// Every premade app, including unavailable entries.
pub const CATALOGUE: &[Template] = &[
    Template {
        key: "nats",
        family: "nats",
        major: None,
        title: "NATS",
        summary: "A stateless messaging server; stacks can opt into persistent JetStream.",
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
        stop: None,
        storage: None,
        unavailable: None,
    },
    Template {
        key: "whoami",
        family: "whoami",
        major: None,
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
        stop: None,
        storage: None,
        unavailable: None,
    },
    Template {
        key: "nginx",
        family: "nginx",
        major: None,
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
        stop: None,
        storage: None,
        unavailable: None,
    },
    Template {
        key: "postgres",
        family: "postgres",
        major: Some("17"),
        title: "PostgreSQL 17",
        summary: "A relational database.",
        image: POSTGRES_17_IMAGE,
        command: &["/bin/sh", "-ec", include_str!("postgres-start.sh")],
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
        stop: Some(("SIGINT", 120)),
        storage: Some(TemplateStorage {
            path: "/var/lib/postgresql/data",
            size_gib: 10,
        }),
        unavailable: None,
    },
    Template {
        key: "postgres-18",
        family: "postgres",
        major: Some("18"),
        title: "PostgreSQL 18",
        summary: "A relational database. Deploying it over a PostgreSQL 17 volume upgrades the data in place and keeps the 17 copy for a rollback.",
        image: POSTGRES_18_IMAGE,
        command: &["/bin/sh", "-ec", include_str!("postgres-start.sh")],
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
        stop: Some(("SIGINT", 120)),
        storage: Some(TemplateStorage {
            path: "/var/lib/postgresql/data",
            size_gib: 10,
        }),
        unavailable: None,
    },
    Template {
        key: "redis",
        family: "redis",
        major: None,
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
        stop: None,
        storage: Some(TemplateStorage {
            path: "/data",
            size_gib: 1,
        }),
        unavailable: None,
    },
    Template {
        key: "seaweedfs",
        family: "seaweedfs",
        major: None,
        title: "SeaweedFS",
        summary: "S3-compatible object storage.",
        image: SEAWEEDFS_IMAGE,
        command: &["/bin/sh", "-ec", include_str!("seaweedfs-start.sh")],
        env: &[],
        secret_variables: &["S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"],
        ports: &[("s3", 8333, Protocol::Http)],
        publishable: None,
        check: None,
        memory_mib: 512,
        cpu_millis: 500,
        stop: None,
        storage: Some(TemplateStorage {
            path: "/data",
            size_gib: 10,
        }),
        unavailable: None,
    },
    Template {
        key: "clickhouse",
        family: "clickhouse",
        major: None,
        title: "ClickHouse",
        summary: "A private analytics database with authenticated query readiness.",
        image: CLICKHOUSE_IMAGE,
        command: &["/bin/bash", "-ec", include_str!("clickhouse-start.sh")],
        env: &[("CLICKHOUSE_DB", "grund")],
        secret_variables: &["CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD"],
        ports: &[
            ("http", 8123, Protocol::Http),
            ("native", 9000, Protocol::Tcp),
        ],
        publishable: None,
        check: Some(("http", "/ping")),
        memory_mib: 1024,
        cpu_millis: 500,
        stop: None,
        storage: Some(TemplateStorage {
            path: "/var/lib/clickhouse",
            size_gib: 10,
        }),
        unavailable: None,
    },
];

const NATS_JETSTREAM: Template = Template {
    command: &["/bin/sh", "-ec", include_str!("nats-start.sh")],
    secret_variables: &["NATS_AUTH_TOKEN"],
    check: Some(("monitor", "/healthz?js-enabled-only=true")),
    storage: Some(TemplateStorage {
        path: "/data",
        size_gib: 1,
    }),
    ..CATALOGUE[0]
};

/// Resolves the existing NATS template's explicit persistence option.
pub fn resolve(key: &str, jetstream: bool) -> Option<&'static Template> {
    if key == "nats" && jetstream {
        Some(&NATS_JETSTREAM)
    } else {
        find(key)
    }
}

/// The template with this key.
pub fn find(key: &str) -> Option<&'static Template> {
    CATALOGUE.iter().find(|t| t.key == key)
}

/// The family of the template with this key.
pub fn family(key: &str) -> Option<&'static str> {
    find(key).map(|t| t.family)
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
        let mut spec = AppSpec {
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
            stop: self
                .stop
                .map_or_else(StopSpec::default, |(signal, grace_seconds)| StopSpec {
                    signal: signal.into(),
                    grace_seconds,
                }),
        };
        self.configure_resources(&mut spec);
        Some(spec)
    }

    /// Recomputes store limits after stack resource and volume selection.
    pub fn configure_resources(&self, spec: &mut AppSpec) {
        if self.family == "nats" && self.storage.is_some() {
            let memory = spec.memory_mib * 1024 * 1024 / 2;
            let disk =
                spec.volumes.first().and_then(|v| v.size_gib).unwrap_or(1) * 1024 * 1024 * 1024;
            for (name, value) in [("NATS_MAX_MEM", memory), ("NATS_MAX_FILE", disk)] {
                if let Some(env) = spec.env.iter_mut().find(|env| env.name == name) {
                    env.value = value.to_string();
                } else {
                    spec.env.push(EnvVar {
                        name: name.into(),
                        value: value.to_string(),
                    });
                }
            }
        }
        if self.family == "clickhouse" {
            let value = (spec.memory_mib * 1024 * 1024 * 3 / 4).to_string();
            if let Some(env) = spec
                .env
                .iter_mut()
                .find(|env| env.name == "CLICKHOUSE_MAX_SERVER_MEMORY_USAGE")
            {
                env.value = value;
            } else {
                spec.env.push(EnvVar {
                    name: "CLICKHOUSE_MAX_SERVER_MEMORY_USAGE".into(),
                    value,
                });
            }
        }
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
    fn stateful_templates_keep_one_app_owned_data_volume_and_credentials_out_of_plain_env() {
        for key in ["postgres", "postgres-18", "redis", "seaweedfs"] {
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
    fn postgres_stops_with_a_fast_shutdown_so_pooled_sessions_cannot_hold_it_until_sigkill() {
        for key in ["postgres", "postgres-18"] {
            let spec = find(key).unwrap().spec(false).unwrap().validate().unwrap();
            assert_eq!(spec.stop.signal, "SIGINT");
            assert!(spec.stop.grace_seconds > StopSpec::default().grace_seconds);
        }
        for template in CATALOGUE.iter().filter(|t| t.family != "postgres") {
            if let Some(spec) = template.spec(false) {
                assert_eq!(spec.stop, StopSpec::default(), "{}", template.key);
            }
        }
    }

    #[test]
    fn each_postgres_major_is_pinned_and_differs_only_in_image_so_a_service_can_move_between_them()
    {
        let majors: Vec<_> = CATALOGUE
            .iter()
            .filter(|t| t.family == "postgres")
            .collect();
        assert_eq!(
            majors.iter().map(|t| t.major.unwrap()).collect::<Vec<_>>(),
            ["17", "18"]
        );
        let base = majors[0].spec(false).unwrap();
        for template in &majors {
            let reference = ImageReference::parse(template.image).unwrap();
            assert!(
                reference
                    .tag
                    .unwrap()
                    .starts_with(&format!("{}.", template.major.unwrap()))
            );
            let mut spec = template.spec(false).unwrap();
            assert_eq!(template.secret_variables, majors[0].secret_variables);
            spec.image = base.image.clone();
            assert_eq!(spec, base, "{}", template.key);
        }
        assert_eq!(family("postgres-18"), Some("postgres"));
        assert_eq!(family("redis"), Some("redis"));
        assert_eq!(family("mysql"), None);
        for template in CATALOGUE.iter().filter(|t| t.family != "postgres") {
            assert_eq!(template.family, template.key);
            assert_eq!(template.major, None);
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
}
