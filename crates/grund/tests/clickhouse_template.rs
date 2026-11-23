mod template_support;

use std::process::{Command, Output};

use grund_config::stack::TemplateSettings;
use grund_domain::app::templates;
use template_support::{Fixture, Mount};
use uuid::Uuid;

#[test]
#[ignore = "requires Linux bridge access, Docker, and the catalogue's pinned ClickHouse image already provisioned locally"]
fn clickhouse_authenticates_without_an_admin_and_keeps_rows_after_copy_recreation() {
    let template = templates::resolve("clickhouse", None).expect("ClickHouse template exists");
    let mut fixture = Fixture::new(template, &[]);
    fixture.start(Some(Mount::Writable));
    fixture.wait_until_ready();
    assert_ping_and_query(&fixture);
    assert_authentication_required(&fixture);
    assert_memory_limit(&fixture);
    assert_access_management_denied(&fixture);
    assert_no_admin_user(&fixture);

    let database = format!("grund_acceptance_{}", Uuid::new_v4().simple());
    query(
        &fixture,
        &format!(
            "CREATE DATABASE {database}; \
             CREATE TABLE {database}.events \
             (id UInt8, payload String) ENGINE = MergeTree ORDER BY id"
        ),
    );
    let marker = Uuid::new_v4().simple().to_string();
    query(
        &fixture,
        &format!("INSERT INTO {database}.events VALUES (1, '{marker}')"),
    );
    let select = format!("SELECT payload FROM {database}.events WHERE id = 1");
    assert_eq!(query(&fixture, &select), marker);

    fixture.remove_copy();
    fixture.start(Some(Mount::Writable));
    fixture.wait_until_ready();
    assert_ping_and_query(&fixture);
    assert_authentication_required(&fixture);
    assert_memory_limit(&fixture);
    assert_access_management_denied(&fixture);
    assert_no_admin_user(&fixture);
    assert_eq!(
        query(&fixture, &select),
        marker,
        "rows survive removal and recreation of the copy with its original volume and credentials",
    );
}

#[test]
#[ignore = "requires Linux bridge access, Docker, and the catalogue's pinned ClickHouse image already provisioned locally"]
fn clickhouse_admin_keeps_both_credentials_and_access_objects_after_restart_and_copy_recreation() {
    let settings = TemplateSettings {
        admin: true,
        ..TemplateSettings::default()
    };
    let template = templates::resolve("clickhouse", Some(&settings))
        .expect("ClickHouse admin template exists");
    let mut fixture = Fixture::new(template, &[]);
    fixture.start(Some(Mount::Writable));
    fixture.wait_until_ready();
    assert_both_credentials_authenticate(&fixture);
    assert_access_management_denied(&fixture);
    assert_authentication_required(&fixture);

    let prefix = format!("grund_acceptance_{}", Uuid::new_v4().simple());
    for sql in access_statements(&prefix) {
        admin_query(&fixture, &sql);
    }
    let inspect = format!(
        "SHOW CREATE USER {prefix}_user; \
         SHOW CREATE ROLE {prefix}_role; \
         SHOW CREATE SETTINGS PROFILE {prefix}_profile; \
         SHOW CREATE QUOTA {prefix}_quota"
    );
    let objects = admin_query(&fixture, &inspect);
    assert_eq!(
        objects.lines().count(),
        4,
        "all access objects were created"
    );

    fixture.successful(
        Command::new("docker")
            .args(["restart", "--time", "30", fixture.id()])
            .output()
            .expect("restart the existing ClickHouse copy"),
        "restart ClickHouse with its original credentials and volume",
    );
    fixture.wait_until_ready();
    assert_both_credentials_authenticate(&fixture);
    assert_access_management_denied(&fixture);
    assert_eq!(
        admin_query(&fixture, &inspect),
        objects,
        "access-created objects survive a restart",
    );

    fixture.remove_copy();
    fixture.start(Some(Mount::Writable));
    fixture.wait_until_ready();
    assert_both_credentials_authenticate(&fixture);
    assert_access_management_denied(&fixture);
    assert_authentication_required(&fixture);
    assert_eq!(
        admin_query(&fixture, &inspect),
        objects,
        "access-created objects survive copy recreation with the original volume and credentials",
    );
}

#[test]
#[ignore = "requires Docker and the catalogue's pinned ClickHouse image already provisioned locally"]
fn clickhouse_refuses_a_read_only_owned_volume() {
    let template = templates::find("clickhouse").expect("ClickHouse template exists");
    let mut fixture = Fixture::new(template, &[]);
    fixture.start(Some(Mount::ReadOnly));
    fixture.assert_startup_refused();
}

#[test]
#[ignore = "requires Docker and the catalogue's pinned ClickHouse image already provisioned locally"]
fn clickhouse_refuses_an_absent_memory_bound() {
    let template = templates::find("clickhouse").expect("ClickHouse template exists");
    let mut fixture = Fixture::new(template, &["CLICKHOUSE_MAX_SERVER_MEMORY_USAGE"]);
    fixture.start(Some(Mount::Writable));
    fixture.assert_startup_refused();
}

fn assert_ping_and_query(fixture: &Fixture) {
    let port = fixture
        .template
        .ports
        .iter()
        .find(|(name, _, _)| *name == "http")
        .expect("ClickHouse HTTP port")
        .1;
    assert_eq!(fixture.http_get(port, "/ping").trim(), "Ok.");
    assert_eq!(query(fixture, "SELECT 1"), "1");
}

fn assert_memory_limit(fixture: &Fixture) {
    let limit: u64 = query(
        fixture,
        "SELECT value FROM system.server_settings WHERE name = 'max_server_memory_usage'",
    )
    .parse()
    .expect("ClickHouse exposes its configured server memory limit");
    assert_eq!(limit, fixture.memory_mib * 1024 * 1024 * 3 / 4);
}

fn assert_authentication_required(fixture: &Fixture) {
    for credential in [
        Credential::Missing,
        Credential::Wrong,
        Credential::DefaultUser,
    ] {
        let output = client(fixture, "SELECT 1", credential);
        assert!(
            !output.status.success(),
            "ClickHouse accepted absent or incorrect credentials",
        );
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("AUTHENTICATION_FAILED") || error.contains("REQUIRED_PASSWORD"),
            "ClickHouse must reject authentication rather than fail for an unrelated reason: {}",
            fixture.redact(&error),
        );
    }
}

fn assert_access_management_denied(fixture: &Fixture) {
    let prefix = format!("grund_denied_{}", Uuid::new_v4().simple());
    for sql in access_statements(&prefix) {
        let output = client(fixture, &sql, Credential::Correct);
        assert!(
            !output.status.success(),
            "the normal ClickHouse user must not create access-management objects",
        );
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("ACCESS_DENIED"),
            "ClickHouse must deny access management rather than fail for an unrelated reason: {}",
            fixture.redact(&error),
        );
    }
}

fn assert_no_admin_user(fixture: &Fixture) {
    assert!(
        !fixture
            .template
            .secret_variables
            .iter()
            .any(|name| name.starts_with("CLICKHOUSE_ADMIN_")),
        "the default template must not generate admin credentials",
    );
    let access_management = fixture.successful(
        fixture.exec(&[
            "clickhouse",
            "extract-from-config",
            "--config-file",
            "/var/lib/clickhouse/preprocessed_configs/users.xml",
            "--key",
            "users.*.access_management",
            "--try",
        ]),
        "inspect the running copy's configured access-management users",
    );
    assert!(
        access_management
            .lines()
            .all(|value| matches!(value, "0" | "false")),
        "the default copy must not configure an access-management user",
    );
    fixture.successful(
        fixture.exec(&[
            "/bin/sh",
            "-ec",
            r#"objects=$(find /var/lib/clickhouse/access -type f -name '*.sql' -print -quit); test -z "$objects""#,
        ]),
        "the default copy must not create SQL-managed access objects",
    );
}

fn access_statements(prefix: &str) -> [String; 4] {
    [
        format!("CREATE USER {prefix}_user IDENTIFIED WITH no_password HOST LOCAL"),
        format!("CREATE ROLE {prefix}_role"),
        format!("CREATE SETTINGS PROFILE {prefix}_profile SETTINGS max_threads = 1"),
        format!("CREATE QUOTA {prefix}_quota FOR INTERVAL 1 HOUR MAX QUERIES = 100"),
    ]
}

fn assert_both_credentials_authenticate(fixture: &Fixture) {
    assert!(
        fixture.credential("CLICKHOUSE_USER") != fixture.credential("CLICKHOUSE_ADMIN_USER"),
        "the administrator must have a separate username",
    );
    assert!(
        fixture.credential("CLICKHOUSE_PASSWORD")
            != fixture.credential("CLICKHOUSE_ADMIN_PASSWORD"),
        "the administrator must have a separate password",
    );
    assert!(
        query(fixture, "SELECT currentUser()") == fixture.credential("CLICKHOUSE_USER"),
        "the original normal credentials must still authenticate as the original user",
    );
    assert!(
        admin_query(fixture, "SELECT currentUser()") == fixture.credential("CLICKHOUSE_ADMIN_USER"),
        "the original admin credentials must still authenticate as the original administrator",
    );
}

fn admin_query(fixture: &Fixture, sql: &str) -> String {
    fixture.successful(
        client(fixture, sql, Credential::Admin),
        "execute an administrator ClickHouse query over its non-loopback address",
    )
}

fn query(fixture: &Fixture, sql: &str) -> String {
    fixture.successful(
        client(fixture, sql, Credential::Correct),
        "execute an authenticated ClickHouse query over its non-loopback address",
    )
}

enum Credential {
    Correct,
    Admin,
    Missing,
    Wrong,
    DefaultUser,
}

fn client(fixture: &Fixture, sql: &str, credential: Credential) -> Output {
    let script = match credential {
        Credential::Correct => {
            r#"exec clickhouse-client --host "$1" --connect_timeout 2 --receive_timeout 5 --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery --query "$2""#
        }
        Credential::Admin => {
            r#"exec clickhouse-client --host "$1" --connect_timeout 2 --receive_timeout 5 --user "$CLICKHOUSE_ADMIN_USER" --password "$CLICKHOUSE_ADMIN_PASSWORD" --multiquery --query "$2""#
        }
        Credential::Missing => {
            r#"exec clickhouse-client --host "$1" --connect_timeout 2 --receive_timeout 5 --user "$CLICKHOUSE_USER" --password '' --query "$2""#
        }
        Credential::Wrong => {
            r#"exec clickhouse-client --host "$1" --connect_timeout 2 --receive_timeout 5 --user "$CLICKHOUSE_USER" --password "${CLICKHOUSE_PASSWORD}-wrong" --query "$2""#
        }
        Credential::DefaultUser => {
            r#"exec clickhouse-client --host "$1" --connect_timeout 2 --receive_timeout 5 --user default --password '' --query "$2""#
        }
    };
    fixture.exec(&[
        "/bin/sh",
        "-ec",
        script,
        "clickhouse-template-client",
        &fixture.address,
        sql,
    ])
}
