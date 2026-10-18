use super::*;

fn t(second: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(second, 0).unwrap()
}

#[test]
fn replayed_intervals_split_a_long_outage_without_inventing_cpu_values() {
    let instance = Uuid::from_u128(1);
    let machine = Uuid::from_u128(2);
    let result = subtract(
        vec![Gap {
            since: t(0),
            until: t(28_800),
            instance_id: instance,
            machine_id: machine,
            offline: true,
        }],
        vec![
            Coverage {
                instance_id: instance,
                since: t(7200),
                until: t(7800),
            },
            Coverage {
                instance_id: instance,
                since: t(7790),
                until: t(8400),
            },
            Coverage {
                instance_id: instance,
                since: t(28_790),
                until: t(28_800),
            },
            Coverage {
                instance_id: Uuid::from_u128(3),
                since: t(0),
                until: t(28_800),
            },
        ],
    )
    .unwrap();
    assert_eq!(
        result
            .iter()
            .map(|gap| (gap.since, gap.until))
            .collect::<Vec<_>>(),
        vec![(t(0), t(7200)), (t(8400), t(28_790))]
    );
}

#[test]
fn complete_replay_removes_the_gap_and_half_open_boundaries_do_not_overlap() {
    let instance = Uuid::from_u128(1);
    let gap = || Gap {
        since: t(10),
        until: t(20),
        instance_id: instance,
        machine_id: Uuid::from_u128(2),
        offline: true,
    };
    assert!(
        subtract(
            vec![gap()],
            vec![Coverage {
                instance_id: instance,
                since: t(10),
                until: t(20)
            }]
        )
        .unwrap()
        .is_empty()
    );
    let result = subtract(
        vec![gap()],
        vec![
            Coverage {
                instance_id: instance,
                since: t(0),
                until: t(10),
            },
            Coverage {
                instance_id: instance,
                since: t(20),
                until: t(30),
            },
        ],
    )
    .unwrap();
    assert_eq!((result[0].since, result[0].until), (t(10), t(20)));
}

#[test]
fn fragmented_replay_is_refused_rather_than_returning_unbounded_annotations() {
    let instance = Uuid::from_u128(1);
    let coverage = (0..1025)
        .map(|index| Coverage {
            instance_id: instance,
            since: t(index * 20 + 10),
            until: t(index * 20 + 20),
        })
        .collect();
    assert!(
        subtract(
            vec![Gap {
                since: t(0),
                until: t(21_000),
                instance_id: instance,
                machine_id: Uuid::nil(),
                offline: true
            }],
            coverage
        )
        .is_err()
    );
}

async fn placement(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid, DateTime<Utc>) {
    let org = Uuid::now_v7();
    let app = Uuid::now_v7();
    let instance = Uuid::now_v7();
    let machine = Uuid::now_v7();
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO grund_organisations (organisation_id,slug,kind,created_at,stream_version) VALUES ($1,$2,'shared',$3,1)")
        .bind(org).bind(org.simple().to_string()).bind(now).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO grund_machines (machine_id,pool,home_organisation_id,name,state,public_key,pool_organisation_id,pool_name,minted_by,registered_at,key_registered_at,stream_version) VALUES ($1,'organisation',$2,$5,'active',$3,$2,$5,'test',$4,$4,1)")
        .bind(machine).bind(org).bind(format!("{0}{0}", machine.simple())).bind(now).bind(machine.simple().to_string()).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO grund_app_telemetry_instances (organisation_id,instance_id,app_id,machine_id,release,placed_at) VALUES ($1,$2,$3,$4,1,$5)")
        .bind(org).bind(instance).bind(app).bind(machine).bind(now - Duration::days(8)).execute(pool).await.unwrap();
    (org, app, instance, machine, now)
}

async fn seen(pool: &PgPool, machine: Uuid, at: DateTime<Utc>) {
    sqlx::query("INSERT INTO grund_machine_presence (machine_id,last_seen_at) VALUES ($1,$2) ON CONFLICT (machine_id) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at")
        .bind(machine).bind(at).execute(pool).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn reconnect_history_and_ongoing_windows_are_scoped_to_the_actual_placement(pool: PgPool) {
    let (org, app, instance, machine, now) = placement(&pool).await;
    let first = now - Duration::hours(8);
    seen(&pool, machine, first).await;
    let ongoing = query(&pool, org, app, Some(instance), None, first, now)
        .await
        .unwrap();
    assert_eq!(ongoing.len(), 1);
    assert_eq!(
        (ongoing[0].since, ongoing[0].until),
        (first + Duration::seconds(30), now)
    );
    seen(&pool, machine, now).await;
    let window = first + Duration::hours(2);
    let result = query(&pool, org, app, Some(instance), Some(1), window, now)
        .await
        .unwrap();
    assert_eq!((result[0].since, result[0].until), (window, now));
    assert!(
        query(&pool, Uuid::now_v7(), app, None, None, first, now)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        query(&pool, org, Uuid::now_v7(), None, None, first, now)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        query(&pool, org, app, Some(Uuid::now_v7()), None, first, now)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        query(&pool, org, app, None, Some(2), first, now)
            .await
            .unwrap()
            .is_empty()
    );
    sqlx::query("UPDATE grund_app_telemetry_instances SET stopped_at=$3 WHERE organisation_id=$1 AND instance_id=$2")
        .bind(org).bind(instance).bind(window + Duration::minutes(5)).execute(&pool).await.unwrap();
    let stopped = query(&pool, org, app, None, None, window, now)
        .await
        .unwrap();
    assert_eq!(stopped[0].until, window + Duration::minutes(5));
}

#[sqlx::test(migrations = "./migrations")]
async fn quiet_logs_and_unknown_cpu_without_disconnection_are_not_offline(pool: PgPool) {
    let (org, app, instance, machine, now) = placement(&pool).await;
    seen(&pool, machine, now - Duration::seconds(30)).await;
    seen(&pool, machine, now).await;
    let gaps = query(
        &pool,
        org,
        app,
        Some(instance),
        None,
        now - Duration::hours(1),
        now,
    )
    .await
    .unwrap();
    assert!(
        query(
            &pool,
            org,
            app,
            Some(instance),
            None,
            now,
            now + Duration::hours(1)
        )
        .await
        .unwrap()
        .is_empty()
    );
    assert!(gaps.is_empty());
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM grund_app_telemetry_outages WHERE organisation_id=$1",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_cpu_replay_is_received_and_quota_eviction_cannot_resurrect_an_offline_claim(
    pool: PgPool,
) {
    let (org, app, instance, machine, now) = placement(&pool).await;
    let first = now - Duration::hours(8);
    seen(&pool, machine, first).await;
    seen(&pool, machine, now).await;
    let received = DateTime::from_timestamp(
        (first + Duration::hours(2)).timestamp().div_euclid(10) * 10,
        0,
    )
    .unwrap();
    sqlx::query("INSERT INTO grund_app_metrics (organisation_id,cursor,app_id,instance_id,machine_id,release,observed_at,cpu_millis,memory_bytes,reserved_cpu_millis,reserved_memory_bytes) VALUES ($1,1,$2,$3,$4,1,$5,NULL,NULL,100,1000)")
        .bind(org).bind(app).bind(instance).bind(machine).bind(received).execute(&pool).await.unwrap();
    let gaps = query(&pool, org, app, None, None, first, now)
        .await
        .unwrap();
    assert_eq!(gaps.len(), 2);
    assert_eq!(gaps[0].until, received);
    assert_eq!(gaps[1].since, received + Duration::seconds(10));
    sqlx::query("DELETE FROM grund_app_metrics WHERE organisation_id=$1")
        .bind(org)
        .execute(&pool)
        .await
        .unwrap();
    let gaps = query(&pool, org, app, None, None, first, now)
        .await
        .unwrap();
    assert_eq!(gaps.len(), 2);
    assert!(!gaps[0].offline);
    assert_eq!(gaps[0].until, received + Duration::seconds(10));
    assert!(gaps[1].offline);
    assert_eq!(gaps[1].since, received + Duration::seconds(10));
}

#[sqlx::test(migrations = "./migrations")]
async fn machine_transfer_cannot_attach_the_previous_tenants_presence_history(pool: PgPool) {
    let (org, app, instance, machine, now) = placement(&pool).await;
    seen(&pool, machine, now - Duration::hours(8)).await;
    let (other_org, _, _, _, _) = placement(&pool).await;
    sqlx::query("UPDATE grund_machines SET pool_organisation_id=$2 WHERE machine_id=$1")
        .bind(machine)
        .bind(other_org)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO grund_app_telemetry_instances (organisation_id,instance_id,app_id,machine_id,release,placed_at) VALUES ($1,$2,$3,$4,1,$5)")
        .bind(other_org).bind(instance).bind(app).bind(machine).bind(now - Duration::hours(8)).execute(&pool).await.unwrap();
    assert!(
        query(
            &pool,
            other_org,
            app,
            None,
            None,
            now - Duration::hours(8),
            now
        )
        .await
        .unwrap()
        .is_empty()
    );
    seen(&pool, machine, now).await;
    assert!(
        query(
            &pool,
            other_org,
            app,
            None,
            None,
            now - Duration::hours(8),
            now
        )
        .await
        .unwrap()
        .is_empty()
    );
    assert!(
        query(&pool, org, app, None, None, now - Duration::hours(8), now)
            .await
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn outage_history_is_bounded_and_expired_history_is_unreadable_before_pruning(pool: PgPool) {
    let (org, app, _, machine, now) = placement(&pool).await;
    sqlx::query("INSERT INTO grund_app_telemetry_outages (organisation_id,machine_id,started_at,ended_at) SELECT $1,$2,$3 - make_interval(secs => n * 60 + 30),$3 - make_interval(secs => n * 60) FROM generate_series(1,1024) n")
        .bind(org).bind(machine).bind(now - Duration::hours(1)).execute(&pool).await.unwrap();
    seen(&pool, machine, now - Duration::minutes(1)).await;
    seen(&pool, machine, now).await;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM grund_app_telemetry_outages WHERE organisation_id=$1",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1024);
    sqlx::query("UPDATE grund_app_telemetry_outages SET started_at=started_at - interval '8 days',ended_at=ended_at - interval '8 days' WHERE organisation_id=$1")
        .bind(org).execute(&pool).await.unwrap();
    assert!(
        query(
            &pool,
            org,
            app,
            None,
            None,
            now - Duration::days(9),
            now - Duration::days(8)
        )
        .await
        .unwrap()
        .is_empty()
    );
    let mut connection = pool.acquire().await.unwrap();
    prune(&mut connection, org).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM grund_app_telemetry_outages WHERE organisation_id=$1",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn compacted_coverage_preserves_sparse_slots_and_collapses_full_masks() {
    let instance = Uuid::from_u128(1);
    let gaps = [Gap {
        since: t(0),
        until: t(600),
        instance_id: instance,
        machine_id: Uuid::from_u128(2),
        offline: true,
    }];
    let received = expand_coverage(
        vec![CoverageRow {
            instance_id: instance,
            since: t(0),
            bucket_seconds: 600,
            coverage_mask: (1_i64 << 60) - 1,
        }],
        &gaps,
    )
    .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!((received[0].since, received[0].until), (t(0), t(600)));
    let received = expand_coverage(
        vec![CoverageRow {
            instance_id: instance,
            since: t(0),
            bucket_seconds: 600,
            coverage_mask: 1 | (1_i64 << 59),
        }],
        &gaps,
    )
    .unwrap();
    let result = subtract(gaps.into(), received).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!((result[0].since, result[0].until), (t(10), t(590)));
}

#[test]
fn received_masks_are_clipped_to_actual_outages_and_missing_evidence_is_not_truncated() {
    let instance = Uuid::from_u128(1);
    let gaps = [Gap {
        since: t(15),
        until: t(25),
        instance_id: instance,
        machine_id: Uuid::from_u128(2),
        offline: true,
    }];
    let received = expand_coverage(
        vec![CoverageRow {
            instance_id: instance,
            since: t(0),
            bucket_seconds: 60,
            coverage_mask: 63,
        }],
        &gaps,
    )
    .unwrap();
    assert_eq!((received[0].since, received[0].until), (t(15), t(25)));
    let gaps = [Gap {
        since: t(0),
        until: t(1_000_000),
        instance_id: instance,
        machine_id: Uuid::from_u128(2),
        offline: true,
    }];
    let rows = (0..=MAX_COVERAGE)
        .map(|_| CoverageRow {
            instance_id: instance,
            since: t(0),
            bucket_seconds: 10,
            coverage_mask: 1,
        })
        .collect();
    assert!(expand_coverage(rows, &gaps).is_err());
}
