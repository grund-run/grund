use grund_config::app::file::{
    FileApp, FileCheck, FilePort, FileProtocol, FileResources, GrundFile, Memory,
};
use grund_config::app::spec::{CheckKind, Protocol};
use grund_config::stack::{Definition, PublicTarget, Service};
use grund_domain::app::templates;

pub(super) const OPTIONS: &[(&str, &str)] = &[
    ("basic", "Basic stack"),
    ("web-data", "Web + PostgreSQL + Redis"),
    ("proxy", "App + Caddy"),
];

pub(super) fn yaml(key: &str, schema_url: &str) -> Option<String> {
    let template_service = |key: &str| Service {
        template: Some(key.into()),
        depends_on: Vec::new(),
        restart: None,
        app: FileApp::default(),
    };
    let (public, services) = match key {
        "basic" => (
            PublicTarget {
                service: "web".into(),
                port: templates::find("whoami")?.publishable?.into(),
            },
            [("web".into(), template_service("whoami"))]
                .into_iter()
                .collect(),
        ),
        "web-data" => {
            let nginx = templates::find("nginx")?;
            let spec = nginx.spec(false)?.validate().ok()?;
            let app = FileApp {
                image: spec.image,
                command: spec.command,
                ports: spec
                    .ports
                    .into_iter()
                    .map(|port| FilePort {
                        name: port.name,
                        port: port.port,
                        protocol: Some(match port.protocol {
                            Protocol::Http => FileProtocol::Http,
                            Protocol::H2c => FileProtocol::H2c,
                            Protocol::Tcp => FileProtocol::Tcp,
                        }),
                        public: false,
                    })
                    .collect(),
                resources: Some(FileResources {
                    memory: Some(Memory::Mib(spec.memory_mib)),
                    cpu: Some(f64::from(spec.cpu_millis) / 1000.0),
                }),
                check: spec.check.map(|check| {
                    let (http, tcp) = match check.kind {
                        CheckKind::Http { path } => (Some(path), None),
                        CheckKind::Tcp => (None, Some(check.port)),
                    };
                    let port = http.as_ref().map(|_| check.port);
                    FileCheck {
                        http,
                        tcp,
                        port,
                        interval_ms: Some(check.interval_ms),
                        timeout_ms: Some(check.timeout_ms),
                    }
                }),
                env: [
                    ("DATABASE_URL".into(), "${{ postgres.url }}".into()),
                    ("REDIS_URL".into(), "${{ redis.url }}".into()),
                ]
                .into_iter()
                .collect(),
                ..FileApp::default()
            };
            (
                PublicTarget {
                    service: "web".into(),
                    port: nginx.publishable?.into(),
                },
                [
                    (
                        "web".into(),
                        Service {
                            template: None,
                            depends_on: vec!["postgres".into(), "redis".into()],
                            restart: None,
                            app,
                        },
                    ),
                    ("postgres".into(), template_service("postgres")),
                    ("redis".into(), template_service("redis")),
                ]
                .into_iter()
                .collect(),
            )
        }
        "proxy" => (
            PublicTarget {
                service: "proxy".into(),
                port: "http".into(),
            },
            [
                ("web".into(), template_service("whoami")),
                (
                    "proxy".into(),
                    Service {
                        template: None,
                        depends_on: vec!["web".into()],
                        restart: None,
                        app: FileApp {
                            image: "caddy:2-alpine".into(),
                            command: vec![
                                "/bin/sh".into(),
                                "-ec".into(),
                                "exec caddy reverse-proxy --from :8080 --to \"$UPSTREAM\"".into(),
                            ],
                            ports: vec![FilePort {
                                name: "http".into(),
                                port: 8080,
                                protocol: Some(FileProtocol::Http),
                                public: false,
                            }],
                            env: [("UPSTREAM".into(), "${{ web.url }}".into())]
                                .into_iter()
                                .collect(),
                            resources: Some(FileResources {
                                memory: Some(Memory::Mib(128)),
                                cpu: Some(0.25),
                            }),
                            check: Some(FileCheck {
                                http: Some("/".into()),
                                port: Some(8080),
                                tcp: None,
                                interval_ms: None,
                                timeout_ms: None,
                            }),
                            ..FileApp::default()
                        },
                    },
                ),
            ]
            .into_iter()
            .collect(),
        ),
        _ => return None,
    };
    let body = grund_config::yaml::to_string(&GrundFile {
        stack: Some(Definition {
            name: "my-stack".into(),
            machines: Vec::new(),
            placement: None,
            public: Some(public),
            services,
        }),
        ..GrundFile::default()
    });
    Some(format!(
        "# yaml-language-server: $schema={schema_url}\n{body}"
    ))
}

#[cfg(test)]
mod tests {
    use grund_config::stack::{ConnectionRef, Restart};

    use super::*;

    const SCHEMA_URL: &str = "https://grund.example/schema/grund.json";

    fn starter(key: &str) -> Definition {
        grund_config::stack::parse(&yaml(key, SCHEMA_URL).expect("known starter"))
            .expect("starter is a valid stack file")
    }

    #[test]
    fn every_starter_parses_and_expands_with_the_current_catalogue() {
        for (key, _) in OPTIONS {
            let definition = starter(key);
            let expanded: Vec<_> = definition
                .services
                .iter()
                .map(|(name, service)| {
                    let spec = service.template.as_deref().map(|key| {
                        templates::find(key)
                            .expect("starter uses an existing catalogue entry")
                            .spec(false)
                            .expect("starter uses an available catalogue entry")
                    });
                    definition
                        .service(name, spec)
                        .unwrap_or_else(|error| panic!("{key}/{name}: {error}"))
                })
                .collect();
            grund_config::stack::validate_expanded(&expanded).expect("expanded starter fits");
            assert_eq!(
                expanded
                    .iter()
                    .flat_map(|(spec, _, _)| &spec.ports)
                    .filter(|port| port.public)
                    .count(),
                1,
                "{key} exposes exactly one public port"
            );
        }
    }

    #[test]
    fn web_data_connects_to_generated_database_credentials_without_literal_secrets() {
        let definition = starter("web-data");
        assert_eq!(definition.services.len(), 3);
        let web = &definition.services["web"];
        assert!(web.template.is_none());
        assert_eq!(web.depends_on, ["postgres", "redis"]);
        assert!(web.app.secrets.is_empty());
        let (spec, _, references) = definition.service("web", None).unwrap();
        assert!(spec.env.is_empty());
        assert_eq!(
            references,
            [
                ConnectionRef {
                    env: "DATABASE_URL".into(),
                    service: "postgres".into(),
                    output: "url".into(),
                },
                ConnectionRef {
                    env: "REDIS_URL".into(),
                    service: "redis".into(),
                    output: "url".into(),
                },
            ]
        );
        for key in ["postgres", "redis"] {
            let service = &definition.services[key];
            assert_eq!(service.template.as_deref(), Some(key));
            let template = templates::find(key).unwrap();
            assert!(!template.secret_variables.is_empty());
            let (spec, _, references) = definition.service(key, template.spec(false)).unwrap();
            assert!(references.is_empty());
            assert_eq!(service.restart(&spec), Restart::Exclusive);
            assert!(spec.ports.iter().all(|port| !port.public));
            assert!(
                spec.env
                    .iter()
                    .all(|env| { !template.secret_variables.contains(&env.name.as_str()) })
            );
            assert!(spec.secrets.is_empty());
        }
        let public = definition.public.unwrap();
        assert_eq!(
            (public.service.as_str(), public.port.as_str()),
            ("web", "http")
        );
    }

    #[test]
    fn the_proxy_routes_its_only_public_port_to_the_private_web_service() {
        let definition = starter("proxy");
        assert_eq!(definition.services.len(), 2);
        assert_eq!(
            definition.services["web"].template.as_deref(),
            Some("whoami")
        );
        assert!(definition.services["web"].depends_on.is_empty());
        let proxy = &definition.services["proxy"];
        assert_eq!(proxy.depends_on, ["web"]);
        let (spec, _, references) = definition.service("proxy", None).unwrap();
        assert_eq!(spec.image, "caddy:2-alpine");
        assert_eq!(
            spec.command,
            [
                "/bin/sh",
                "-ec",
                "exec caddy reverse-proxy --from :8080 --to \"$UPSTREAM\"",
            ]
        );
        assert!(spec.env.is_empty());
        assert_eq!(
            references,
            [ConnectionRef {
                env: "UPSTREAM".into(),
                service: "web".into(),
                output: "url".into(),
            }]
        );
        assert_eq!(spec.ports.len(), 1);
        assert_eq!(spec.ports[0].name, "http");
        assert_eq!(spec.ports[0].port, 8080);
        assert_eq!(spec.ports[0].protocol, Protocol::Http);
        assert!(spec.ports[0].public);
        let (upstream, _, _) = definition
            .service("web", templates::find("whoami").unwrap().spec(false))
            .unwrap();
        assert!(upstream.ports.iter().all(|port| !port.public));
    }

    #[test]
    fn an_unknown_starter_is_not_replaced_with_another_file() {
        assert!(yaml("unknown", SCHEMA_URL).is_none());
        assert!(yaml("", SCHEMA_URL).is_none());
    }
}
