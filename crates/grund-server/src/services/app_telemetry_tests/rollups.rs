use super::*;
use grund_store::app_telemetry::{METRIC_ROW_BYTES, MetricRow, Policy};

fn aligned(age: Duration, seconds: i64) -> chrono::DateTime<Utc> {
    let timestamp = (Utc::now() - age).timestamp().div_euclid(seconds) * seconds;
    chrono::DateTime::from_timestamp(timestamp, 0).unwrap()
}

fn sample(
    placement: &Placement,
    at: chrono::DateTime<Utc>,
    cpu_millis: Option<f64>,
    memory_bytes: Option<i64>,
) -> Sample {
    Sample {
        identity: placement.identity.clone(),
        at,
        cpu_millis,
        memory_bytes,
        reserved_cpu_millis: 100,
        reserved_memory_bytes: 1024,
    }
}

async fn upload(state: &State, placement: &Placement, samples: &[Sample], policy: Policy) {
    assert_eq!(
        store::ingest(
            &state.pool,
            placement.identity.organisation_id,
            placement.identity.machine_id,
            Uuid::now_v7(),
            &[1; 32],
            &[],
            samples,
            policy,
        )
        .await
        .unwrap(),
        (0, samples.len() as i32)
    );
}

async fn sweep(state: &State, policy: Policy) {
    store::sweep(&state.pool, policy, None).await.unwrap();
}

async fn points(state: &State, placement: &Placement, bucket: i32) -> Vec<MetricRow> {
    store::metrics(
        &state.pool,
        placement.identity.organisation_id,
        placement.identity.app_id,
        None,
        None,
        Utc::now() - Duration::days(7),
        Utc::now(),
        bucket,
        state.app_telemetry().policy().metric_seconds,
    )
    .await
    .unwrap()
}

async fn accounted_rows(state: &State, org: Uuid) -> (i64, i64, i64) {
    let rows: (i64, i64, i64) = sqlx::query_as(
        "SELECT metric_bytes, (SELECT count(*) FROM grund_app_metrics WHERE organisation_id = $1), \
         (SELECT count(*) FROM grund_app_metric_rollups WHERE organisation_id = $1) \
         FROM grund_app_telemetry_usage WHERE organisation_id = $1",
    )
    .bind(org)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(rows.0, (rows.1 + rows.2) * METRIC_ROW_BYTES);
    rows
}

async fn seed_raw(state: &State, owner: &Placement, at: chrono::DateTime<Utc>, count: i64) {
    sqlx::query(
        "INSERT INTO grund_app_metrics \
         (organisation_id,cursor,app_id,instance_id,machine_id,release,observed_at,cpu_millis,memory_bytes,reserved_cpu_millis,reserved_memory_bytes) \
         SELECT $1, n, $2, $3, $4, 1, $5, 10, 123, 100, 1024 FROM generate_series(1,$6::bigint) n",
    )
    .bind(owner.identity.organisation_id)
    .bind(owner.identity.app_id)
    .bind(owner.identity.instance_id)
    .bind(owner.identity.machine_id)
    .bind(at)
    .bind(count)
    .execute(&state.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO grund_app_telemetry_usage (organisation_id,cursor,metric_bytes) VALUES ($1,$2,$2 * $3) ON CONFLICT (organisation_id) DO UPDATE SET cursor = greatest(grund_app_telemetry_usage.cursor,EXCLUDED.cursor), metric_bytes = grund_app_telemetry_usage.metric_bytes + EXCLUDED.metric_bytes")
        .bind(owner.identity.organisation_id).bind(count).bind(METRIC_ROW_BYTES)
        .execute(&state.pool).await.unwrap();
}

async fn seed_minutes(state: &State, owner: &Placement, at: chrono::DateTime<Utc>, count: i64) {
    sqlx::query(
        "INSERT INTO grund_app_metric_rollups \
         (organisation_id,app_id,instance_id,machine_id,release,observed_at,bucket_seconds, \
          cpu_sum,cpu_count,memory_sum,memory_count,memory_max_bytes,samples,coverage_mask,reserved_cpu_millis,reserved_memory_bytes) \
         SELECT $1,$2,$3,$4,1,$5 + make_interval(secs => n * 60),60,10,1,123,1,123,1,1,100,1024 \
         FROM generate_series(0,$6::bigint - 1) n",
    )
    .bind(owner.identity.organisation_id)
    .bind(owner.identity.app_id)
    .bind(owner.identity.instance_id)
    .bind(owner.identity.machine_id)
    .bind(at)
    .bind(count)
    .execute(&state.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO grund_app_telemetry_usage (organisation_id,metric_bytes) VALUES ($1,$2 * $3) ON CONFLICT (organisation_id) DO UPDATE SET metric_bytes = grund_app_telemetry_usage.metric_bytes + EXCLUDED.metric_bytes")
        .bind(owner.identity.organisation_id).bind(count).bind(METRIC_ROW_BYTES)
        .execute(&state.pool).await.unwrap();
}

#[sqlx::test]
async fn complete_buckets_move_to_minutes_then_ten_minutes_without_restarting_placements(
    pool: PgPool,
) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let policy = state.app_telemetry().policy();
    let samples = [
        sample(
            &owner,
            aligned(Duration::minutes(20), 10),
            Some(1.0),
            Some(10),
        ),
        sample(&owner, aligned(Duration::hours(2), 60), Some(2.0), Some(20)),
        sample(&owner, aligned(Duration::days(2), 600), Some(3.0), Some(30)),
    ];
    upload(&state, &owner, &samples, policy).await;
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (1152, 1, 2)
    );
    let tiers: Vec<i32> = sqlx::query_scalar("SELECT bucket_seconds FROM grund_app_metric_rollups WHERE organisation_id = $1 ORDER BY bucket_seconds")
        .bind(owner.identity.organisation_id).fetch_all(&state.pool).await.unwrap();
    assert_eq!(tiers, [60, 600]);
    let running: String =
        sqlx::query_scalar("SELECT state FROM grund_replicas WHERE replica_id = $1")
            .bind(owner.identity.instance_id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(running, "running");
    assert_eq!(points(&state, &owner, 600).await.len(), 3);
}

#[sqlx::test]
async fn late_raw_and_unequal_minute_weights_preserve_means_maxima_and_original_sample_counts(
    pool: PgPool,
) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let policy = state.app_telemetry().policy();
    let at = aligned(Duration::hours(2), 600);
    let initial = [
        sample(&owner, at, Some(10.0), Some(100)),
        sample(&owner, at + Duration::seconds(10), None, Some(900)),
        sample(&owner, at + Duration::seconds(20), Some(30.0), None),
        sample(&owner, at + Duration::minutes(1), Some(100.0), Some(500)),
    ];
    upload(&state, &owner, &initial, policy).await;
    sweep(&state, policy).await;
    let mut late = sample(&owner, at + Duration::seconds(30), Some(50.0), None);
    late.reserved_cpu_millis = 400;
    late.reserved_memory_bytes = 4096;
    upload(&state, &owner, &[late], policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (1152, 1, 2)
    );
    let mixed = points(&state, &owner, 600).await;
    assert_eq!(mixed.len(), 1);
    assert_eq!(mixed[0].cpu_millis, Some(47.5));
    assert_eq!(mixed[0].memory_bytes, Some(500.0));
    assert_eq!(mixed[0].memory_max_bytes, Some(900.0));
    assert_eq!(mixed[0].samples, 5);
    assert_eq!(mixed[0].reserved_cpu_millis, 400);
    assert_eq!(mixed[0].reserved_memory_bytes, 4096);
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (768, 0, 2)
    );
    sqlx::query("UPDATE grund_app_metric_rollups SET observed_at = observed_at - interval '2 days' WHERE organisation_id = $1")
        .bind(owner.identity.organisation_id).execute(&state.pool).await.unwrap();
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (384, 0, 1)
    );
    let coarse = points(&state, &owner, 600).await;
    assert_eq!(coarse[0].cpu_millis, mixed[0].cpu_millis);
    assert_eq!(coarse[0].memory_bytes, mixed[0].memory_bytes);
    assert_eq!(coarse[0].memory_max_bytes, mixed[0].memory_max_bytes);
    assert_eq!(coarse[0].samples, 5);
    upload(
        &state,
        &owner,
        &[sample(
            &owner,
            at - Duration::days(2),
            Some(210.0),
            Some(100),
        )],
        policy,
    )
    .await;
    sweep(&state, policy).await;
    sweep(&state, policy).await;
    let merged = points(&state, &owner, 600).await;
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].cpu_millis, Some(80.0));
    assert_eq!(merged[0].memory_bytes, Some(400.0));
    assert_eq!(merged[0].memory_max_bytes, Some(900.0));
    assert_eq!(merged[0].samples, 6);
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (384, 0, 1)
    );
}

#[sqlx::test]
async fn unknown_measurements_stay_unknown_after_both_compaction_levels(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let policy = state.app_telemetry().policy();
    let at = aligned(Duration::hours(2), 600);
    upload(
        &state,
        &owner,
        &[
            sample(&owner, at, None, None),
            sample(&owner, at + Duration::seconds(10), None, None),
        ],
        policy,
    )
    .await;
    sweep(&state, policy).await;
    sqlx::query("UPDATE grund_app_metric_rollups SET observed_at = observed_at - interval '2 days' WHERE organisation_id = $1")
        .bind(owner.identity.organisation_id).execute(&state.pool).await.unwrap();
    sweep(&state, policy).await;
    let rows = points(&state, &owner, 600).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].cpu_millis, None);
    assert_eq!(rows[0].memory_bytes, None);
    assert_eq!(rows[0].memory_max_bytes, None);
    assert_eq!(rows[0].samples, 2);
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (384, 0, 1)
    );
}

#[sqlx::test]
async fn a_partial_source_group_is_merged_exactly_once_on_the_next_bounded_pass(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let policy = state.app_telemetry().policy();
    seed_raw(&state, &owner, aligned(Duration::hours(2), 60), 1025).await;
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (768, 1, 1)
    );
    let mixed = points(&state, &owner, 60).await;
    assert_eq!(mixed.len(), 1);
    assert_eq!(mixed[0].samples, 1025);
    sweep(&state, policy).await;
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (384, 0, 1)
    );
    let compacted = points(&state, &owner, 60).await;
    assert_eq!(compacted[0].samples, 1025);
    assert_eq!(compacted[0].cpu_millis, Some(10.0));
    assert_eq!(compacted[0].memory_bytes, Some(123.0));
}

#[sqlx::test]
async fn minute_promotion_also_stops_after_one_bounded_source_batch(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let policy = state.app_telemetry().policy();
    seed_minutes(&state, &owner, aligned(Duration::days(3), 600), 1025).await;
    sweep(&state, policy).await;
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_app_metric_rollups WHERE organisation_id = $1 AND bucket_seconds = 60")
        .bind(owner.identity.organisation_id).fetch_one(&state.pool).await.unwrap();
    assert_eq!(remaining, 1);
    assert_eq!(
        points(&state, &owner, 600)
            .await
            .iter()
            .map(|row| row.samples)
            .sum::<i64>(),
        1025
    );
    accounted_rows(&state, owner.identity.organisation_id).await;
    sweep(&state, policy).await;
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_app_metric_rollups WHERE organisation_id = $1 AND bucket_seconds = 60")
        .bind(owner.identity.organisation_id).fetch_one(&state.pool).await.unwrap();
    assert_eq!(remaining, 0);
    assert_eq!(
        points(&state, &owner, 600)
            .await
            .iter()
            .map(|row| row.samples)
            .sum::<i64>(),
        1025
    );
    accounted_rows(&state, owner.identity.organisation_id).await;
}

#[sqlx::test]
async fn expiry_is_bounded_per_table_and_is_enforced_before_sweeping_finishes(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let policy = state.app_telemetry().policy();
    seed_raw(&state, &owner, aligned(Duration::days(8), 60), 1025).await;
    seed_minutes(&state, &owner, aligned(Duration::days(10), 600), 1025).await;
    let expired = store::metrics(
        &state.pool,
        owner.identity.organisation_id,
        owner.identity.app_id,
        None,
        None,
        Utc::now() - Duration::days(11),
        Utc::now(),
        600,
        policy.metric_seconds,
    )
    .await
    .unwrap();
    assert!(expired.is_empty());
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (768, 1, 1)
    );
    let expired = store::metrics(
        &state.pool,
        owner.identity.organisation_id,
        owner.identity.app_id,
        None,
        None,
        Utc::now() - Duration::days(11),
        Utc::now(),
        600,
        policy.metric_seconds,
    )
    .await
    .unwrap();
    assert!(expired.is_empty());
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (0, 0, 0)
    );
}

#[sqlx::test]
async fn an_aggregate_straddling_the_hard_retention_cutoff_is_not_returned(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let at = aligned(Duration::hours(2), 600);
    seed_minutes(&state, &owner, at, 1).await;
    sqlx::query(
        "UPDATE grund_app_metric_rollups SET bucket_seconds = 600 WHERE organisation_id = $1",
    )
    .bind(owner.identity.organisation_id)
    .execute(&state.pool)
    .await
    .unwrap();
    let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    let retention = (now - at - Duration::minutes(5)).num_seconds();
    let rows = store::metrics(
        &state.pool,
        owner.identity.organisation_id,
        owner.identity.app_id,
        None,
        None,
        at - Duration::hours(1),
        now,
        600,
        retention,
    )
    .await
    .unwrap();
    assert!(rows.is_empty());
    let mut policy = state.app_telemetry().policy();
    policy.metric_seconds = retention;
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (0, 0, 0)
    );
}

#[sqlx::test]
async fn quota_evicts_the_oldest_observation_across_raw_and_rollups_not_the_ingestion_cursor(
    pool: PgPool,
) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let other = placed(&state).await;
    let policy = state.app_telemetry().policy();
    let now = aligned(Duration::minutes(10), 600);
    seed_minutes(&state, &owner, now + Duration::minutes(1), 1).await;
    seed_raw(&state, &owner, now, 1).await;
    seed_raw(&state, &other, now - Duration::minutes(1), 1).await;
    let mut small = policy;
    small.metric_bytes = METRIC_ROW_BYTES;
    upload(&state, &owner, &[], small).await;
    let remaining = points(&state, &owner, 60).await;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].at, now + Duration::minutes(1));
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (384, 0, 1)
    );
    assert_eq!(
        accounted_rows(&state, other.identity.organisation_id).await,
        (384, 1, 0)
    );
    upload(
        &state,
        &owner,
        &[sample(
            &owner,
            now + Duration::minutes(2),
            Some(20.0),
            Some(456),
        )],
        small,
    )
    .await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (384, 1, 0)
    );
    let remaining = points(&state, &owner, 60).await;
    assert_eq!(remaining[0].at, now + Duration::minutes(2));
}

#[sqlx::test]
async fn an_overfull_tenant_is_evicted_in_bounded_quota_passes(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    seed_raw(&state, &owner, aligned(Duration::minutes(5), 10), 4098).await;
    let mut policy = state.app_telemetry().policy();
    policy.metric_bytes = METRIC_ROW_BYTES;
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (768, 2, 0)
    );
    sweep(&state, policy).await;
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (384, 1, 0)
    );
}

#[sqlx::test]
async fn aggregate_reads_keep_tenant_instance_release_and_deleted_app_boundaries(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let other = placed(&state).await;
    let policy = state.app_telemetry().policy();
    upload(
        &state,
        &owner,
        &[sample(
            &owner,
            aligned(Duration::hours(2), 60),
            Some(10.0),
            Some(100),
        )],
        policy,
    )
    .await;
    upload(
        &state,
        &other,
        &[sample(
            &other,
            aligned(Duration::hours(2), 60),
            Some(99.0),
            Some(900),
        )],
        policy,
    )
    .await;
    sweep(&state, policy).await;
    assert_eq!(points(&state, &owner, 60).await[0].cpu_millis, Some(10.0));
    for (org, instance, release) in [
        (other.identity.organisation_id, None, None),
        (
            owner.identity.organisation_id,
            Some(other.identity.instance_id),
            None,
        ),
        (owner.identity.organisation_id, None, Some(2)),
    ] {
        let rows = store::metrics(
            &state.pool,
            org,
            owner.identity.app_id,
            instance,
            release,
            Utc::now() - Duration::days(1),
            Utc::now(),
            60,
            policy.metric_seconds,
        )
        .await
        .unwrap();
        assert!(rows.is_empty());
    }
    sqlx::query("UPDATE grund_apps SET deleted_at = statement_timestamp() WHERE app_id = $1")
        .bind(owner.identity.app_id)
        .execute(&state.pool)
        .await
        .unwrap();
    assert!(points(&state, &owner, 60).await.is_empty());
}

#[sqlx::test]
async fn migration_reaccounts_existing_0040_rows_and_preserves_receipts_and_cursors(pool: PgPool) {
    let prior = sqlx::migrate::Migrator::with_migrations(
        grund_store::MIGRATOR
            .iter()
            .filter(|migration| migration.version <= 40)
            .cloned()
            .collect(),
    );
    prior.run(&pool).await.unwrap();
    let org = Uuid::now_v7();
    let app = Uuid::now_v7();
    let instance = Uuid::now_v7();
    let machine = Uuid::now_v7();
    sqlx::query("INSERT INTO grund_app_telemetry_usage (organisation_id,log_bytes,metric_bytes,receipts,cursor) VALUES ($1,9999,9999,1,7)")
        .bind(org).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO grund_app_logs (organisation_id,cursor,app_id,instance_id,machine_id,release,observed_at,stream,body,truncated,payload_bytes) VALUES ($1,5,$2,$3,$4,1,statement_timestamp(),'stdout','é',false,130)")
        .bind(org).bind(app).bind(instance).bind(machine).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO grund_app_metrics (organisation_id,cursor,app_id,instance_id,machine_id,release,observed_at,cpu_millis,memory_bytes,reserved_cpu_millis,reserved_memory_bytes) VALUES ($1,6,$2,$3,$4,1,statement_timestamp(),NULL,123,100,1024)")
        .bind(org).bind(app).bind(instance).bind(machine).execute(&pool).await.unwrap();
    let batch = Uuid::now_v7();
    sqlx::query("INSERT INTO grund_app_telemetry_batches (organisation_id,machine_id,batch_id,digest,accepted_logs,accepted_samples) VALUES ($1,$2,$3,$4,1,1)")
        .bind(org).bind(machine).bind(batch).bind(&[1u8;32][..]).execute(&pool).await.unwrap();
    grund_store::migrate(&pool).await.unwrap();
    let usage: (i64, i64, i32, i64) = sqlx::query_as("SELECT log_bytes,metric_bytes,receipts,cursor FROM grund_app_telemetry_usage WHERE organisation_id = $1")
        .bind(org).fetch_one(&pool).await.unwrap();
    assert_eq!(usage, (386, 384, 1, 7));
    let replay: (i32, i32) = sqlx::query_as("SELECT accepted_logs,accepted_samples FROM grund_app_telemetry_batches WHERE organisation_id = $1 AND machine_id = $2 AND batch_id = $3")
        .bind(org).bind(machine).bind(batch).fetch_one(&pool).await.unwrap();
    assert_eq!(replay, (1, 1));
    let constraint =
        sqlx::query("UPDATE grund_app_logs SET payload_bytes = 130 WHERE organisation_id = $1")
            .bind(org)
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(
        constraint.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    let constraint =
        sqlx::query("UPDATE grund_app_metrics SET payload_bytes = 128 WHERE organisation_id = $1")
            .bind(org)
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(
        constraint.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    let charge: i64 = sqlx::query_scalar(
        "SELECT payload_bytes FROM grund_app_metrics WHERE organisation_id = $1",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(charge, METRIC_ROW_BYTES);
}

#[sqlx::test]
async fn utc_bucket_edges_keep_each_original_sample_in_exactly_one_bucket(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let policy = state.app_telemetry().policy();
    let at = aligned(Duration::hours(2), 600);
    upload(
        &state,
        &owner,
        &[
            sample(&owner, at + Duration::seconds(59), Some(10.0), Some(100)),
            sample(&owner, at + Duration::seconds(60), Some(20.0), Some(200)),
            sample(&owner, at + Duration::seconds(599), Some(30.0), Some(300)),
            sample(&owner, at + Duration::seconds(600), Some(40.0), Some(400)),
        ],
        policy,
    )
    .await;
    sweep(&state, policy).await;
    let minutes = points(&state, &owner, 60).await;
    assert_eq!(
        minutes.iter().map(|row| row.at).collect::<Vec<_>>(),
        [
            at,
            at + Duration::minutes(1),
            at + Duration::minutes(9),
            at + Duration::minutes(10),
        ]
    );
    assert!(minutes.iter().all(|row| row.samples == 1));
    sqlx::query("UPDATE grund_app_metric_rollups SET observed_at = observed_at - interval '2 days' WHERE organisation_id = $1")
        .bind(owner.identity.organisation_id).execute(&state.pool).await.unwrap();
    sweep(&state, policy).await;
    let coarse = points(&state, &owner, 600).await;
    assert_eq!(coarse.len(), 2);
    assert_eq!(coarse[0].at, at - Duration::days(2));
    assert_eq!(coarse[0].samples, 3);
    assert_eq!(coarse[0].cpu_millis, Some(20.0));
    assert_eq!(coarse[0].memory_max_bytes, Some(300.0));
    assert_eq!(coarse[1].at, at - Duration::days(2) + Duration::minutes(10));
    assert_eq!(coarse[1].samples, 1);
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (768, 0, 2)
    );
}

#[sqlx::test]
async fn a_rejected_batch_rolls_back_compaction_eviction_and_accounting_together(pool: PgPool) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    seed_raw(&state, &owner, aligned(Duration::hours(2), 60), 1025).await;
    let before = accounted_rows(&state, owner.identity.organisation_id).await;
    let mut policy = state.app_telemetry().policy();
    policy.metric_bytes = 0;
    let batch = Uuid::now_v7();
    let result = store::ingest(
        &state.pool,
        owner.identity.organisation_id,
        owner.identity.machine_id,
        batch,
        &[1; 32],
        &[],
        &[sample(&owner, Utc::now(), Some(10.0), Some(100))],
        policy,
    )
    .await;
    assert!(matches!(result, Err(store::IngestError::Capacity)));
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        before
    );
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM grund_app_telemetry_batches WHERE organisation_id = $1 AND batch_id = $2")
        .bind(owner.identity.organisation_id).bind(batch).fetch_one(&state.pool).await.unwrap();
    assert_eq!(receipts, 0);
}

#[sqlx::test]
async fn retention_boundary_discard_marks_received_coverage_unknown_for_both_tiers(pool: PgPool) {
    let state = state(pool).await;
    for rolled in [false, true] {
        let owner = placed(&state).await;
        let at = aligned(Duration::days(2), 600);
        let observed = at + Duration::minutes(5);
        if rolled {
            seed_minutes(&state, &owner, observed, 1).await;
        } else {
            seed_raw(&state, &owner, observed, 1).await;
        }
        sqlx::query("UPDATE grund_app_telemetry_instances SET placed_at = $3 WHERE organisation_id = $1 AND instance_id = $2")
            .bind(owner.identity.organisation_id).bind(owner.identity.instance_id).bind(at)
            .execute(&state.pool).await.unwrap();
        sqlx::query("INSERT INTO grund_app_telemetry_outages (organisation_id,machine_id,started_at,ended_at) VALUES ($1,$2,$3,$4)")
            .bind(owner.identity.organisation_id).bind(owner.identity.machine_id)
            .bind(at + Duration::minutes(4)).bind(at + Duration::minutes(7))
            .execute(&state.pool).await.unwrap();
        let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        let mut policy = state.app_telemetry().policy();
        policy.metric_seconds = (now - at - Duration::minutes(4)).num_seconds();
        sweep(&state, policy).await;
        assert_eq!(
            accounted_rows(&state, owner.identity.organisation_id).await,
            (0, 0, 0)
        );
        let gaps = grund_store::app_telemetry_gaps::query(
            &state.pool,
            owner.identity.organisation_id,
            owner.identity.app_id,
            Some(owner.identity.instance_id),
            None,
            at + Duration::minutes(4),
            at + Duration::minutes(7),
        )
        .await
        .unwrap();
        assert!(
            gaps.iter()
                .any(|gap| !gap.offline && gap.since <= observed && gap.until > observed)
        );
    }
}

#[sqlx::test]
async fn compaction_preserves_offline_coverage_but_real_quota_eviction_invalidates_it(
    pool: PgPool,
) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let policy = state.app_telemetry().policy();
    let at = aligned(Duration::hours(2), 600);
    upload(
        &state,
        &owner,
        &[sample(&owner, at, Some(10.0), Some(100))],
        policy,
    )
    .await;
    sweep(&state, policy).await;
    let cutoff: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT metric_coverage_lost_before FROM grund_app_telemetry_instances WHERE organisation_id = $1 AND instance_id = $2",
    )
    .bind(owner.identity.organisation_id)
    .bind(owner.identity.instance_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(cutoff, None);
    sqlx::query("UPDATE grund_app_metric_rollups SET observed_at = observed_at - interval '2 days' WHERE organisation_id = $1")
        .bind(owner.identity.organisation_id).execute(&state.pool).await.unwrap();
    sweep(&state, policy).await;
    let cutoff: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT metric_coverage_lost_before FROM grund_app_telemetry_instances WHERE organisation_id = $1 AND instance_id = $2",
    )
    .bind(owner.identity.organisation_id)
    .bind(owner.identity.instance_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(cutoff, None);
    let mut small = policy;
    small.metric_bytes = METRIC_ROW_BYTES;
    upload(
        &state,
        &owner,
        &[sample(&owner, Utc::now(), Some(20.0), Some(200))],
        small,
    )
    .await;
    let cutoff: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT metric_coverage_lost_before FROM grund_app_telemetry_instances WHERE organisation_id = $1 AND instance_id = $2",
    )
    .bind(owner.identity.organisation_id)
    .bind(owner.identity.instance_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(cutoff, Some(at - Duration::days(2) + Duration::minutes(10)));
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (384, 1, 0)
    );
}

#[sqlx::test]
async fn sparse_coverage_masks_preserve_only_received_ten_second_slots_across_late_merges_and_tiers(
    pool: PgPool,
) {
    let state = state(pool).await;
    let owner = placed(&state).await;
    let policy = state.app_telemetry().policy();
    let at = aligned(Duration::hours(2), 600);
    upload(
        &state,
        &owner,
        &[
            sample(&owner, at + Duration::seconds(10), Some(10.0), Some(100)),
            sample(&owner, at + Duration::seconds(19), None, None),
            sample(&owner, at + Duration::seconds(70), Some(20.0), Some(200)),
            sample(&owner, at + Duration::seconds(80), None, None),
            sample(&owner, at + Duration::seconds(590), Some(30.0), Some(300)),
        ],
        policy,
    )
    .await;
    sweep(&state, policy).await;
    let masks: Vec<i64> = sqlx::query_scalar(
        "SELECT coverage_mask FROM grund_app_metric_rollups WHERE organisation_id = $1 ORDER BY observed_at",
    ).bind(owner.identity.organisation_id).fetch_all(&state.pool).await.unwrap();
    assert_eq!(masks, [2, 6, 32]);
    upload(
        &state,
        &owner,
        &[sample(
            &owner,
            at + Duration::seconds(40),
            Some(40.0),
            Some(400),
        )],
        policy,
    )
    .await;
    sweep(&state, policy).await;
    let mask: i64 = sqlx::query_scalar(
        "SELECT coverage_mask FROM grund_app_metric_rollups WHERE organisation_id = $1 AND observed_at = $2",
    ).bind(owner.identity.organisation_id).bind(at).fetch_one(&state.pool).await.unwrap();
    assert_eq!(mask, (1 << 1) | (1 << 4));
    sqlx::query("UPDATE grund_app_metric_rollups SET observed_at = observed_at - interval '2 days' WHERE organisation_id = $1")
        .bind(owner.identity.organisation_id).execute(&state.pool).await.unwrap();
    sweep(&state, policy).await;
    let mask: i64 = sqlx::query_scalar(
        "SELECT coverage_mask FROM grund_app_metric_rollups WHERE organisation_id = $1",
    )
    .bind(owner.identity.organisation_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(
        mask,
        (1i64 << 1) | (1i64 << 4) | (1i64 << 7) | (1i64 << 8) | (1i64 << 59)
    );
    upload(
        &state,
        &owner,
        &[sample(
            &owner,
            at - Duration::days(2) + Duration::seconds(570),
            Some(50.0),
            Some(500),
        )],
        policy,
    )
    .await;
    sweep(&state, policy).await;
    let mask: i64 = sqlx::query_scalar(
        "SELECT coverage_mask FROM grund_app_metric_rollups WHERE organisation_id = $1",
    )
    .bind(owner.identity.organisation_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(
        mask,
        (1i64 << 1) | (1i64 << 4) | (1i64 << 7) | (1i64 << 8) | (1i64 << 57) | (1i64 << 59)
    );
    assert_eq!(points(&state, &owner, 600).await[0].samples, 7);
    assert_eq!(
        accounted_rows(&state, owner.identity.organisation_id).await,
        (384, 0, 1)
    );
}
