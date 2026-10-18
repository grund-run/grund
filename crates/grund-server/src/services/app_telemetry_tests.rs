use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use buffa::Message;
use chrono::{Duration, Utc};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use grund_proto::grund::{agent::v1 as agent, app::v1 as app};
use opentelemetry_proto::tonic::{
    collector::{logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest},
    common::v1::{AnyValue, KeyValue, any_value::Value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    metrics::v1::{
        Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric::Data,
        number_data_point,
    },
    resource::v1::Resource,
};
use prost::Message as ProstMessage;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use super::*;
use crate::services::{SessionsState, agents::request_message};

#[path = "app_telemetry_tests/rollups.rs"]
mod rollups;

#[derive(Parser)]
struct TestConfig {
    #[command(flatten)]
    config: crate::config::ServeConfig,
}

async fn state(pool: PgPool) -> State {
    grund_store::migrate(&pool).await.unwrap();
    let mut config =
        TestConfig::try_parse_from(["test", "--database-url", "postgres://unused/test"])
            .unwrap()
            .config;
    config.license_key = None;
    config.license_key_file = None;
    let secret = Arc::new(crate::secrets::SecretKey::generate());
    let events = mire::EventStore::new(pool.clone());
    let certificates =
        crate::certificates::Certificates::new(&config, pool.clone(), secret.clone());
    let hearing = Arc::new(crate::hearing::Hearing::new(Utc::now()));
    let health = crate::health::registry(
        pool.clone(),
        hearing.clone(),
        None,
        false,
        &certificates,
        &config,
    );
    let entitlements = Arc::new(crate::entitlements(&config).unwrap());
    State {
        config: Arc::new(config),
        pool,
        events: events.clone(),
        nats: None,
        secret,
        certificates,
        health,
        passwords: crate::services::passwords::Passwords::new().unwrap(),
        entitlements,
        billing: crate::services::billing::Billing::Free,
        capacity: crate::services::capacity::Capacity::None,
        deletions: crate::sagas::Deletions::new(events),
        extensions: Arc::new(Vec::new()),
        started: std::time::Instant::now(),
        wakes: crate::wakes::Wakes::default(),
        hearing,
    }
}

struct Placement {
    identity: Identity,
    key: SigningKey,
    slug: String,
}

async fn placed(state: &State) -> Placement {
    let org = Uuid::now_v7();
    let app = Uuid::now_v7();
    let instance = Uuid::now_v7();
    let machine = Uuid::now_v7();
    let slug = org.simple().to_string();
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let key = SigningKey::from_bytes(&seed);
    sqlx::query("INSERT INTO grund_organisations (organisation_id,slug,kind,created_at,stream_version) VALUES ($1,$2,'shared',clock_timestamp(),1)")
        .bind(org).bind(&slug).execute(&state.pool).await.unwrap();
    sqlx::query("INSERT INTO grund_machines (machine_id,pool,home_organisation_id,name,state,public_key,pool_organisation_id,pool_name,minted_by,registered_at,key_registered_at,stream_version) VALUES ($1,'organisation',$2,'machine','active',$3,$2,'machine','test',clock_timestamp(),clock_timestamp(),1)")
        .bind(machine).bind(org).bind(hex::encode(key.verifying_key().to_bytes())).execute(&state.pool).await.unwrap();
    sqlx::query("INSERT INTO grund_apps (app_id,organisation_id,name,settings,created_by,created_at,stream_version) VALUES ($1,$2,'app',$3,$4,clock_timestamp(),1)")
        .bind(app).bind(org).bind(sqlx::types::Json(grund_config::app::spec::AppSettings::default())).bind(Uuid::nil()).execute(&state.pool).await.unwrap();
    sqlx::query("INSERT INTO grund_replicas (replica_id,app_id,organisation_id,machine_id,slot,release,placement,state,placed_at) VALUES ($1,$2,$3,$4,0,1,1,'running',clock_timestamp() - interval '8 days')")
        .bind(instance).bind(app).bind(org).bind(machine).execute(&state.pool).await.unwrap();
    Placement {
        identity: Identity {
            organisation_id: org,
            app_id: app,
            instance_id: instance,
            machine_id: machine,
            release: 1,
        },
        key,
        slug,
    }
}

fn attr(key: &str, value: Value) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue { value: Some(value) }),
        ..Default::default()
    }
}

fn resource(identity: &Identity) -> Resource {
    Resource {
        attributes: vec![
            attr(
                "grund.organisation.id",
                Value::StringValue(identity.organisation_id.to_string()),
            ),
            attr(
                "grund.app.id",
                Value::StringValue(identity.app_id.to_string()),
            ),
            attr(
                "grund.instance.id",
                Value::StringValue(identity.instance_id.to_string()),
            ),
            attr(
                "grund.machine.id",
                Value::StringValue(identity.machine_id.to_string()),
            ),
            attr(
                "grund.release.number",
                Value::IntValue(identity.release as i64),
            ),
        ],
        ..Default::default()
    }
}

fn batch(
    identity: &Identity,
    body: &str,
    at: chrono::DateTime<Utc>,
) -> agent::ExportTelemetryRequest {
    let at = at.timestamp_nanos_opt().unwrap() as u64;
    let logs = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(resource(identity)),
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: at,
                    observed_time_unix_nano: at,
                    body: Some(AnyValue {
                        value: Some(Value::StringValue(body.into())),
                    }),
                    attributes: vec![
                        attr("log.iostream", Value::StringValue("stdout".into())),
                        attr("grund.log.truncated", Value::BoolValue(false)),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    agent::ExportTelemetryRequest {
        batch_id: Uuid::now_v7().to_string(),
        logs_otlp: logs.encode_to_vec(),
        ..Default::default()
    }
}

async fn signed(
    state: &State,
    placement: &Placement,
    batch: &agent::ExportTelemetryRequest,
    valid_signature: bool,
) -> (StatusCode, Vec<u8>) {
    let path = "/grund.agent.v1.AppTelemetryService/ExportTelemetry";
    let bytes = batch.encode_to_vec();
    let at = Utc::now().timestamp();
    let signature = placement.key.sign(&request_message(
        if valid_signature { path } else { "/different" },
        at,
        &bytes,
    ));
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/proto")
        .header("connect-protocol-version", "1")
        .header("x-grund-machine", placement.identity.machine_id.to_string())
        .header("x-grund-signed-at", at.to_string())
        .header("x-grund-signature", STANDARD.encode(signature.to_bytes()))
        .body(Body::from(bytes))
        .unwrap();
    let response = crate::web::router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
}

async fn query(
    state: &State,
    slug: &str,
    account: Uuid,
    request: app::ListAppLogsRequest,
) -> (StatusCode, Vec<u8>) {
    let mut connection = state.pool.acquire().await.unwrap();
    let (token, _) = state
        .sessions()
        .start_cli(&mut connection, account, &Default::default())
        .await
        .unwrap();
    drop(connection);
    let request = app::ListAppLogsRequest {
        organisation: slug.into(),
        name: "app".into(),
        ..request
    };
    let request = Request::builder()
        .method("POST")
        .uri("/grund.app.v1.AppTelemetryService/ListAppLogs")
        .header("content-type", "application/proto")
        .header("connect-protocol-version", "1")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(request.encode_to_vec()))
        .unwrap();
    let response = crate::api::router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
}

#[sqlx::test]
async fn signed_log_batches_larger_than_forms_cross_the_full_http_surface(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let mut request = batch(&owner.identity, &"x".repeat(8192), Utc::now());
    let mut logs = ExportLogsServiceRequest::decode(request.logs_otlp.as_ref()).unwrap();
    let record = logs.resource_logs[0].scope_logs[0].log_records[0].clone();
    logs.resource_logs[0].scope_logs[0].log_records = vec![record; 3];
    request.logs_otlp = logs.encode_to_vec();
    assert!(request.encoded_len() as usize > crate::web::MAX_BODY_BYTES);
    let (status, response) = signed(&state, &owner, &request, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        agent::ExportTelemetryResponse::decode_from_slice(&response)
            .unwrap()
            .accepted_logs,
        3
    );
}

#[sqlx::test]
async fn signed_ingestion_refuses_tampering_and_foreign_resource_identities(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let other = placed(&state).await;
    let batch = batch(&owner.identity, "measured", Utc::now());
    assert_eq!(
        signed(&state, &owner, &batch, false).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        signed(&state, &other, &batch, true).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(signed(&state, &owner, &batch, true).await.0, StatusCode::OK);
    assert_eq!(signed(&state, &owner, &batch, true).await.0, StatusCode::OK);
    let mut conflicting = batch.clone();
    conflicting.dropped_records = 1;
    assert_eq!(
        signed(&state, &owner, &conflicting, true).await.0,
        StatusCode::CONFLICT
    );
    for part in ["app", "instance", "release", "machine"] {
        let mut identity = owner.identity.clone();
        match part {
            "app" => identity.app_id = other.identity.app_id,
            "instance" => identity.instance_id = other.identity.instance_id,
            "machine" => identity.machine_id = other.identity.machine_id,
            _ => identity.release = 2,
        }
        let forged = super::tests::batch(&identity, "forged identity", Utc::now());
        assert_eq!(
            signed(&state, &owner, &forged, true).await.0,
            StatusCode::NOT_FOUND
        );
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_app_logs")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    for role in ["owner", "admin", "member"] {
        let account = Uuid::now_v7();
        sqlx::query("INSERT INTO grund_memberships (organisation_id,account_id,role,stream_version) VALUES ($1,$2,$3,1)").bind(owner.identity.organisation_id).bind(account).bind(role).execute(&state.pool).await.unwrap();
        let (status, bytes) = query(&state, &owner.slug, account, Default::default()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            app::ListAppLogsResponse::decode_from_slice(&bytes)
                .unwrap()
                .logs[0]
                .body,
            "measured"
        );
        assert_eq!(
            query(&state, &other.slug, account, Default::default())
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        query(&state, &owner.slug, Uuid::now_v7(), Default::default())
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE grund_apps SET deleted_at = clock_timestamp() WHERE app_id = $1")
        .bind(owner.identity.app_id)
        .execute(&state.pool)
        .await
        .unwrap();
    let count = state
        .app_telemetry()
        .logs(
            owner.identity.organisation_id,
            owner.identity.app_id,
            &Default::default(),
        )
        .await
        .unwrap()
        .logs
        .len();
    assert_eq!(count, 0);
}

#[sqlx::test]
async fn cursor_is_filter_bound_advances_when_empty_and_keeps_late_uploads(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let org = owner.identity.organisation_id;
    let app = owner.identity.app_id;
    let first = state
        .app_telemetry()
        .logs(org, app, &Default::default())
        .await
        .unwrap();
    assert!(!first.next_page_token.is_empty());
    let late = batch(
        &owner.identity,
        "literal%_match",
        Utc::now() - Duration::minutes(30),
    );
    assert_eq!(signed(&state, &owner, &late, true).await.0, StatusCode::OK);
    let next_request = app::ListAppLogsRequest {
        page_token: first.next_page_token,
        ..Default::default()
    };
    let next = state
        .app_telemetry()
        .logs(org, app, &next_request)
        .await
        .unwrap();
    assert_eq!(next.logs.len(), 1);
    let mut changed = next_request.clone();
    changed.search = "other".into();
    assert!(
        state
            .app_telemetry()
            .logs(org, app, &changed)
            .await
            .is_err()
    );
    let request = app::ListAppLogsRequest {
        search: "%_".into(),
        ..Default::default()
    };
    assert_eq!(
        state
            .app_telemetry()
            .logs(org, app, &request)
            .await
            .unwrap()
            .logs
            .len(),
        1
    );
    let request = app::ListAppLogsRequest {
        search: "absent".into(),
        ..Default::default()
    };
    let empty = state
        .app_telemetry()
        .logs(org, app, &request)
        .await
        .unwrap();
    assert!(empty.logs.is_empty());
    assert_ne!(
        empty.next_page_token,
        state.app_telemetry().token(
            org,
            app,
            &Sha256::digest(
                app::ListAppLogsRequest {
                    search: "absent".into(),
                    ..Default::default()
                }
                .encode_to_vec()
            )
            .into(),
            0
        )
    );
    let request = app::ListAppLogsRequest {
        page_token: next.next_page_token,
        ..Default::default()
    };
    assert!(
        state
            .app_telemetry()
            .logs(org, app, &request)
            .await
            .unwrap()
            .logs
            .is_empty()
    );
}

#[sqlx::test]
async fn quotas_evict_once_expiry_is_hard_and_stopped_placements_can_replay(pool: PgPool) {
    let mut state = state(pool).await;
    Arc::make_mut(&mut state.config).app_log_payload_bytes = 600;
    let owner = placed(&state).await;
    let old = batch(&owner.identity, "old", Utc::now() - Duration::minutes(1));
    assert_eq!(signed(&state, &owner, &old, true).await.0, StatusCode::OK);
    let newer = batch(&owner.identity, &"x".repeat(100), Utc::now());
    assert_eq!(signed(&state, &owner, &newer, true).await.0, StatusCode::OK);
    assert_eq!(signed(&state, &owner, &newer, true).await.0, StatusCode::OK);
    let result = state
        .app_telemetry()
        .logs(
            owner.identity.organisation_id,
            owner.identity.app_id,
            &Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(result.logs.len(), 1);
    assert_eq!(result.dropped_records, 1);
    sqlx::query("UPDATE grund_app_logs SET observed_at = clock_timestamp() - interval '25 hours'")
        .execute(&state.pool)
        .await
        .unwrap();
    assert!(
        state
            .app_telemetry()
            .logs(
                owner.identity.organisation_id,
                owner.identity.app_id,
                &Default::default()
            )
            .await
            .unwrap()
            .logs
            .is_empty()
    );
    sqlx::query("DELETE FROM grund_replicas WHERE replica_id = $1")
        .bind(owner.identity.instance_id)
        .execute(&state.pool)
        .await
        .unwrap();
    let delayed = batch(
        &owner.identity,
        "delayed",
        Utc::now() - Duration::seconds(30),
    );
    assert_eq!(
        signed(&state, &owner, &delayed, true).await.0,
        StatusCode::OK
    );
    sqlx::query("UPDATE grund_machines SET pool_organisation_id = $2 WHERE machine_id = $1")
        .bind(owner.identity.machine_id)
        .bind(Uuid::now_v7())
        .execute(&state.pool)
        .await
        .unwrap();
    assert_eq!(
        signed(
            &state,
            &owner,
            &batch(&owner.identity, "old tenant", Utc::now()),
            true
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[test]
fn malformed_nested_otlp_and_wrong_metric_types_are_refused_before_storage() {
    assert!(parse(&[10, 255], &[]).is_err());
    assert!(wire(&[42, 2, 10, 0], Wire::Scalar, &mut 100).is_err());
    let identity = Identity {
        organisation_id: Uuid::now_v7(),
        app_id: Uuid::now_v7(),
        instance_id: Uuid::now_v7(),
        machine_id: Uuid::now_v7(),
        release: 1,
    };
    let mut batch = batch(&identity, "valid", Utc::now());
    assert!(parse(&batch.logs_otlp, &[]).is_ok());
    batch.logs_otlp = vec![0; 262145];
    assert!(parse(&batch.logs_otlp, &[]).is_err());
    let at = Utc::now().timestamp_nanos_opt().unwrap() as u64;
    let gauge = |name: &str, value| Metric {
        name: name.into(),
        data: Some(Data::Gauge(Gauge {
            data_points: vec![NumberDataPoint {
                time_unix_nano: at,
                value: Some(value),
                ..Default::default()
            }],
        })),
        ..Default::default()
    };
    let mut metrics = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(resource(&identity)),
            scope_metrics: vec![ScopeMetrics {
                metrics: vec![
                    gauge(
                        "grund.app.reserved.cpu.millicores",
                        number_data_point::Value::AsInt(100),
                    ),
                    gauge(
                        "grund.app.reserved.memory.bytes",
                        number_data_point::Value::AsInt(1024),
                    ),
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let (_, samples) = parse(&[], &metrics.encode_to_vec()).unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].cpu_millis, None);
    assert_eq!(samples[0].memory_bytes, None);
    metrics.resource_metrics[0].scope_metrics[0]
        .metrics
        .push(gauge(
            "grund.app.memory.bytes",
            number_data_point::Value::AsDouble(2.0),
        ));
    let error = parse(&[], &metrics.encode_to_vec()).err().unwrap();
    assert_eq!(
        error.downcast_ref::<Invalid>().unwrap().0,
        "invalid CPU measurement"
    );
}

#[sqlx::test]
async fn metric_buckets_preserve_missing_values_and_absent_buckets(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let now = Utc::now();
    let samples = [
        Sample {
            identity: owner.identity.clone(),
            at: now - Duration::seconds(40),
            cpu_millis: None,
            memory_bytes: Some(123),
            reserved_cpu_millis: 100,
            reserved_memory_bytes: 1024,
        },
        Sample {
            identity: owner.identity.clone(),
            at: now,
            cpu_millis: Some(0.0),
            memory_bytes: None,
            reserved_cpu_millis: 100,
            reserved_memory_bytes: 1024,
        },
    ];
    let policy = state.app_telemetry().policy();
    store::ingest(
        &state.pool,
        owner.identity.organisation_id,
        owner.identity.machine_id,
        Uuid::now_v7(),
        &[1; 32],
        &[],
        &samples,
        policy,
    )
    .await
    .unwrap();
    let result = state
        .app_telemetry()
        .metrics(
            owner.identity.organisation_id,
            owner.identity.app_id,
            &Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(result.bucket_seconds, 10);
    assert_eq!(result.points.len(), 2);
    assert_eq!(result.points[0].cpu_millis, None);
    assert_eq!(result.points[0].memory_bytes, Some(123.0));
    assert_eq!(result.points[1].cpu_millis, Some(0.0));
    assert_eq!(result.points[1].memory_bytes, None);
    assert!(
        result.points[1].at.as_option().unwrap().seconds
            - result.points[0].at.as_option().unwrap().seconds
            >= 30
    );
}

#[sqlx::test]
async fn receipt_capacity_backpressures_new_batches_but_replays_and_sweeping_work(pool: PgPool) {
    let mut state = state(pool).await;
    Arc::make_mut(&mut state.config).app_telemetry_receipts = 1;
    let owner = placed(&state).await;
    let first = batch(&owner.identity, "first", Utc::now());
    let next = batch(&owner.identity, "next", Utc::now());
    assert_eq!(signed(&state, &owner, &first, true).await.0, StatusCode::OK);
    assert_eq!(
        signed(&state, &owner, &next, true).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(signed(&state, &owner, &first, true).await.0, StatusCode::OK);
    sqlx::query("UPDATE grund_app_telemetry_batches SET received_at = clock_timestamp() - interval '8 days'").execute(&state.pool).await.unwrap();
    store::sweep(&state.pool, state.app_telemetry().policy(), None)
        .await
        .unwrap();
    assert_eq!(signed(&state, &owner, &next, true).await.0, StatusCode::OK);
    let receipts: i32 = sqlx::query_scalar(
        "SELECT receipts FROM grund_app_telemetry_usage WHERE organisation_id = $1",
    )
    .bind(owner.identity.organisation_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(receipts, 1);
}

#[sqlx::test]
async fn concurrent_batches_have_monotonic_committed_cursors_and_independent_tenant_quotas(
    pool: PgPool,
) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let other = placed(&state).await;
    let first = batch(&owner.identity, "first", Utc::now());
    let second = batch(&owner.identity, "second", Utc::now());
    let third = batch(&other.identity, "third", Utc::now());
    let (first, second, third) = tokio::join!(
        signed(&state, &owner, &first, true),
        signed(&state, &owner, &second, true),
        signed(&state, &other, &third, true)
    );
    assert_eq!(
        (first.0, second.0, third.0),
        (StatusCode::OK, StatusCode::OK, StatusCode::OK)
    );
    let request = app::ListAppLogsRequest {
        page_size: 1,
        ..Default::default()
    };
    let first = state
        .app_telemetry()
        .logs(
            owner.identity.organisation_id,
            owner.identity.app_id,
            &request,
        )
        .await
        .unwrap();
    assert_eq!(first.logs.len(), 1);
    let second = state
        .app_telemetry()
        .logs(
            owner.identity.organisation_id,
            owner.identity.app_id,
            &app::ListAppLogsRequest {
                page_token: first.next_page_token,
                ..request
            },
        )
        .await
        .unwrap();
    assert_eq!(second.logs.len(), 1);
    assert_ne!(first.logs[0].body, second.logs[0].body);
    let other = state
        .app_telemetry()
        .logs(
            other.identity.organisation_id,
            other.identity.app_id,
            &Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(other.logs.len(), 1);
    assert_eq!(other.logs[0].body, "third");
}

#[sqlx::test]
async fn a_full_week_for_twenty_instances_is_returned_without_truncation(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let instances: Vec<_> = (0..20).map(|_| Uuid::now_v7()).collect();
    sqlx::query("INSERT INTO grund_replicas (replica_id,app_id,organisation_id,machine_id,slot,release,placement,state,placed_at) SELECT instance_id,$1,$2,$3,position::int,1,1,'running',clock_timestamp() - interval '8 days' FROM unnest($4::uuid[]) WITH ORDINALITY AS instances(instance_id,position)")
        .bind(owner.identity.app_id).bind(owner.identity.organisation_id).bind(owner.identity.machine_id).bind(&instances).execute(&state.pool).await.unwrap();
    sqlx::query("INSERT INTO grund_app_metrics (organisation_id,cursor,app_id,instance_id,machine_id,release,observed_at,cpu_millis,memory_bytes,reserved_cpu_millis,reserved_memory_bytes) SELECT $1,(position - 1) * 1008 + bucket + 1,$2,instance_id,$3,1,date_bin(interval '10 minutes',clock_timestamp(),timestamptz '1970-01-01 00:00:00+00') - make_interval(secs => bucket * 600),10,123,100,1024 FROM unnest($4::uuid[]) WITH ORDINALITY AS instances(instance_id,position) CROSS JOIN generate_series(0,1007) AS bucket")
        .bind(owner.identity.organisation_id).bind(owner.identity.app_id).bind(owner.identity.machine_id).bind(&instances).execute(&state.pool).await.unwrap();
    let result = state
        .app_telemetry()
        .metrics(
            owner.identity.organisation_id,
            owner.identity.app_id,
            &app::GetAppMetricsRequest {
                range: "week".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result.points.len(), 20 * 1008);
    for instance in instances {
        let instance = instance.to_string();
        assert_eq!(
            result
                .points
                .iter()
                .filter(|point| point.instance == instance)
                .count(),
            1008
        );
    }
}

#[sqlx::test]
async fn expired_late_uploads_free_quota_before_live_history_is_evicted(pool: PgPool) {
    let mut state = state(pool).await;
    Arc::make_mut(&mut state.config).app_log_payload_bytes = 968;
    Arc::make_mut(&mut state.config).app_metric_payload_bytes = 768;
    let owner = placed(&state).await;
    let org = owner.identity.organisation_id;
    let app = owner.identity.app_id;
    let now = Utc::now();
    let policy = state.app_telemetry().policy();
    for (body, at, cpu) in [
        ("live", now - Duration::seconds(40), 1.0),
        ("late", now - Duration::hours(1), 2.0),
    ] {
        let logs = [Log {
            identity: owner.identity.clone(),
            at,
            stream: "stdout".into(),
            body: body.repeat(25),
            truncated: false,
        }];
        let samples = [Sample {
            identity: owner.identity.clone(),
            at,
            cpu_millis: Some(cpu),
            memory_bytes: Some(123),
            reserved_cpu_millis: 100,
            reserved_memory_bytes: 1024,
        }];
        store::ingest(
            &state.pool,
            org,
            owner.identity.machine_id,
            Uuid::now_v7(),
            &[1; 32],
            &logs,
            &samples,
            policy,
        )
        .await
        .unwrap();
    }
    sqlx::query("UPDATE grund_app_logs SET observed_at = clock_timestamp() - interval '25 hours' WHERE organisation_id = $1 AND body = $2")
        .bind(org).bind("late".repeat(25)).execute(&state.pool).await.unwrap();
    sqlx::query("UPDATE grund_app_metrics SET observed_at = clock_timestamp() - interval '8 days' WHERE organisation_id = $1 AND cpu_millis = 2")
        .bind(org).execute(&state.pool).await.unwrap();
    let logs = [Log {
        identity: owner.identity.clone(),
        at: now,
        stream: "stdout".into(),
        body: "next".repeat(25),
        truncated: false,
    }];
    let samples = [Sample {
        identity: owner.identity.clone(),
        at: now,
        cpu_millis: Some(3.0),
        memory_bytes: Some(123),
        reserved_cpu_millis: 100,
        reserved_memory_bytes: 1024,
    }];
    store::ingest(
        &state.pool,
        org,
        owner.identity.machine_id,
        Uuid::now_v7(),
        &[2; 32],
        &logs,
        &samples,
        policy,
    )
    .await
    .unwrap();
    let logs = state
        .app_telemetry()
        .logs(org, app, &Default::default())
        .await
        .unwrap();
    assert_eq!(logs.logs.len(), 2);
    assert_eq!(logs.logs[0].body, "live".repeat(25));
    assert_eq!(logs.logs[1].body, "next".repeat(25));
    assert_eq!(logs.dropped_records, 1);
    let metrics = state
        .app_telemetry()
        .metrics(org, app, &Default::default())
        .await
        .unwrap();
    assert_eq!(
        metrics
            .points
            .iter()
            .map(|point| point.cpu_millis)
            .collect::<Vec<_>>(),
        [Some(1.0), Some(3.0)]
    );
    let usage: (i64, i64) = sqlx::query_as(
        "SELECT log_bytes,metric_bytes FROM grund_app_telemetry_usage WHERE organisation_id = $1",
    )
    .bind(org)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(usage, (968, 768));
}

#[sqlx::test]
async fn stopped_placements_expire_even_when_the_old_agent_never_uploaded(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let org = owner.identity.organisation_id;
    let usage: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM grund_app_telemetry_usage WHERE organisation_id = $1",
    )
    .bind(org)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(usage, 0);
    sqlx::query("DELETE FROM grund_replicas WHERE replica_id = $1")
        .bind(owner.identity.instance_id)
        .execute(&state.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE grund_app_telemetry_instances SET stopped_at = clock_timestamp() - interval '8 days' WHERE organisation_id = $1").bind(org).execute(&state.pool).await.unwrap();
    store::sweep(&state.pool, state.app_telemetry().policy(), None)
        .await
        .unwrap();
    let identities: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM grund_app_telemetry_instances WHERE organisation_id = $1",
    )
    .bind(org)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(identities, 0);
}

#[sqlx::test]
async fn delayed_shutdown_observations_are_accepted_while_the_placement_is_retained(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let org = owner.identity.organisation_id;
    let app = owner.identity.app_id;
    sqlx::query("DELETE FROM grund_replicas WHERE replica_id = $1")
        .bind(owner.identity.instance_id)
        .execute(&state.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE grund_app_telemetry_instances SET stopped_at = clock_timestamp() - interval '2 hours' WHERE organisation_id = $1")
        .bind(org)
        .execute(&state.pool)
        .await
        .unwrap();
    let at = Utc::now();
    let final_logs = batch(&owner.identity, "shutdown completed", at);
    assert_eq!(
        signed(&state, &owner, &final_logs, true).await.0,
        StatusCode::OK
    );
    let samples = [Sample {
        identity: owner.identity.clone(),
        at,
        cpu_millis: None,
        memory_bytes: Some(123),
        reserved_cpu_millis: 100,
        reserved_memory_bytes: 1024,
    }];
    store::ingest(
        &state.pool,
        org,
        owner.identity.machine_id,
        Uuid::now_v7(),
        &[1; 32],
        &[],
        &samples,
        state.app_telemetry().policy(),
    )
    .await
    .unwrap();
    let logs = state
        .app_telemetry()
        .logs(org, app, &Default::default())
        .await
        .unwrap();
    assert_eq!(logs.logs.len(), 1);
    assert_eq!(logs.logs[0].body, "shutdown completed");
    let metrics = state
        .app_telemetry()
        .metrics(org, app, &Default::default())
        .await
        .unwrap();
    assert_eq!(metrics.points.len(), 1);
    assert_eq!(metrics.points[0].memory_bytes, Some(123.0));
    sqlx::query("UPDATE grund_app_telemetry_instances SET stopped_at = clock_timestamp() - interval '8 days' WHERE organisation_id = $1")
        .bind(org)
        .execute(&state.pool)
        .await
        .unwrap();
    let outside_history = batch(&owner.identity, "history expired", Utc::now());
    assert_eq!(
        signed(&state, &owner, &outside_history, true).await.0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test]
async fn loss_metadata_expires_for_old_deleted_apps_but_survives_active_and_recoverable_apps(
    pool: PgPool,
) {
    let state = state(pool).await;
    let active = placed(&state).await.identity;
    let expired = placed(&state).await.identity;
    let recent = placed(&state).await.identity;
    let orphan = Uuid::now_v7();
    sqlx::query("INSERT INTO grund_app_telemetry_losses (organisation_id,app_id,dropped_records) VALUES ($1,$2,7),($3,$4,8),($5,$6,9),($1,$7,1)")
        .bind(active.organisation_id).bind(active.app_id)
        .bind(expired.organisation_id).bind(expired.app_id)
        .bind(recent.organisation_id).bind(recent.app_id).bind(orphan)
        .execute(&state.pool).await.unwrap();
    sqlx::query("UPDATE grund_apps SET deleted_at = clock_timestamp() - interval '8 days' WHERE app_id = $1")
        .bind(expired.app_id).execute(&state.pool).await.unwrap();
    sqlx::query("UPDATE grund_apps SET deleted_at = clock_timestamp() - interval '6 days' WHERE app_id = $1")
        .bind(recent.app_id).execute(&state.pool).await.unwrap();
    store::sweep(&state.pool, state.app_telemetry().policy(), None)
        .await
        .unwrap();
    assert_eq!(
        store::losses(&state.pool, active.organisation_id, active.app_id)
            .await
            .unwrap(),
        7
    );
    assert_eq!(
        store::losses(&state.pool, recent.organisation_id, recent.app_id)
            .await
            .unwrap(),
        9
    );
    assert_eq!(
        store::losses(&state.pool, expired.organisation_id, expired.app_id)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store::losses(&state.pool, active.organisation_id, orphan)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test]
async fn separate_capture_evidence_survives_log_filters_but_not_expiry_or_instance_removal(
    pool: PgPool,
) {
    let mut state = state(pool).await;
    let owner = placed(&state).await;
    let other = placed(&state).await;
    let org = owner.identity.organisation_id;
    let app_id = owner.identity.app_id;
    let separate = batch(
        &owner.identity,
        "separate output",
        Utc::now() - Duration::hours(2),
    );
    assert_eq!(
        signed(&state, &owner, &separate, true).await.0,
        StatusCode::OK
    );
    let mut combined = batch(&owner.identity, "legacy output", Utc::now());
    let mut payload = ExportLogsServiceRequest::decode(combined.logs_otlp.as_ref()).unwrap();
    payload.resource_logs[0].scope_logs[0].log_records[0].attributes[0] =
        attr("log.iostream", Value::StringValue("combined".into()));
    combined.logs_otlp = payload.encode_to_vec();
    assert_eq!(
        signed(&state, &owner, &combined, true).await.0,
        StatusCode::OK
    );
    let filtered = state
        .app_telemetry()
        .logs(
            org,
            app_id,
            &app::ListAppLogsRequest {
                stream: "combined".into(),
                search: "legacy".into(),
                page_size: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        filtered
            .logs
            .iter()
            .map(|log| (log.stream.as_str(), log.body.as_str()))
            .collect::<Vec<_>>(),
        [("combined", "legacy output")]
    );
    assert_eq!(
        state
            .app_telemetry()
            .separate_capture(org, app_id)
            .await
            .unwrap(),
        [owner.identity.instance_id]
    );
    assert!(
        state
            .app_telemetry()
            .separate_capture(other.identity.organisation_id, app_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        state
            .app_telemetry()
            .separate_capture(org, other.identity.app_id)
            .await
            .unwrap()
            .is_empty()
    );
    Arc::make_mut(&mut state.config).app_log_retention_hours = 1;
    assert!(
        state
            .app_telemetry()
            .separate_capture(org, app_id)
            .await
            .unwrap()
            .is_empty()
    );
    Arc::make_mut(&mut state.config).app_log_retention_hours = 24;
    sqlx::query("DELETE FROM grund_replicas WHERE organisation_id=$1 AND replica_id=$2")
        .bind(org)
        .bind(owner.identity.instance_id)
        .execute(&state.pool)
        .await
        .unwrap();
    assert!(
        state
            .app_telemetry()
            .separate_capture(org, app_id)
            .await
            .unwrap()
            .is_empty()
    );
}
