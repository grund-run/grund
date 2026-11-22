mod template_support;

use std::process::Output;

use grund_domain::app::templates;
use template_support::{Fixture, Mount};
use uuid::Uuid;

#[test]
#[ignore = "requires Linux bridge access, Docker, and the catalogue's pinned ClickHouse image already provisioned locally"]
fn clickhouse_authenticates_and_keeps_rows_after_copy_recreation() {
    let template = templates::find("clickhouse").expect("ClickHouse template exists");
    let mut fixture = Fixture::new(template, &[]);
    fixture.start(Some(Mount::Writable));
    fixture.wait_until_ready();
    assert_ping_and_query(&fixture);
    assert_authentication_required(&fixture);
    assert_memory_limit(&fixture);

    query(
        &fixture,
        "CREATE DATABASE grund_template_acceptance; \
         CREATE TABLE grund_template_acceptance.events \
         (id UInt8, payload String) ENGINE = MergeTree ORDER BY id",
    );
    let marker = Uuid::new_v4().simple().to_string();
    query(
        &fixture,
        &format!("INSERT INTO grund_template_acceptance.events VALUES (1, '{marker}')"),
    );
    assert_eq!(
        query(
            &fixture,
            "SELECT payload FROM grund_template_acceptance.events WHERE id = 1"
        ),
        marker,
    );

    fixture.remove_copy();
    fixture.start(Some(Mount::Writable));
    fixture.wait_until_ready();
    assert_ping_and_query(&fixture);
    assert_authentication_required(&fixture);
    assert_memory_limit(&fixture);
    assert_eq!(
        query(
            &fixture,
            "SELECT payload FROM grund_template_acceptance.events WHERE id = 1"
        ),
        marker,
        "rows survive removal and recreation of the copy with its original volume and credentials",
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

fn query(fixture: &Fixture, sql: &str) -> String {
    fixture.successful(
        client(fixture, sql, Credential::Correct),
        "execute an authenticated ClickHouse query over its non-loopback address",
    )
}

enum Credential {
    Correct,
    Missing,
    Wrong,
    DefaultUser,
}

fn client(fixture: &Fixture, sql: &str, credential: Credential) -> Output {
    let script = match credential {
        Credential::Correct => {
            r#"exec clickhouse-client --host "$1" --connect_timeout 2 --receive_timeout 5 --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery --query "$2""#
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
