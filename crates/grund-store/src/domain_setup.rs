//! Durable custom-domain observations and independently leased setup checks.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgExecutor, PgPool, types::Json};
use uuid::Uuid;

/// The outcome of one factual setup observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Waiting,
    InProgress,
    Done,
    Failed,
}

impl StepState {
    /// The stable representation shared by the API, dashboard and CLI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::InProgress => "in_progress",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

/// One persistent setup step, with the observation and its retry deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub name: String,
    pub state: StepState,
    pub detail: String,
    pub checked_at: Option<DateTime<Utc>>,
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// The six steps before there is any evidence about a bound domain.
pub fn waiting_steps() -> Vec<Step> {
    [
        "dns_record",
        "edge_reachable",
        "certificate_requested",
        "challenge_passed",
        "certificate_issued",
        "serving_https",
    ]
    .into_iter()
    .map(|name| Step {
        name: name.into(),
        state: StepState::Waiting,
        detail: String::new(),
        checked_at: None,
        next_retry_at: None,
    })
    .collect()
}

/// Coalesces an immediate check with any in-flight check. False for an unbound,
/// removed or deleted-app domain. It does not bypass a CA retry deadline.
pub async fn request_check(
    executor: impl PgExecutor<'_>,
    domain_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_domain_setup s SET requested = requested + 1, next_check_at = clock_timestamp() \
         WHERE s.domain_id = $1 AND EXISTS (SELECT 1 FROM grund_domains d \
           JOIN grund_apps a ON a.app_id = d.app_id AND a.deleted_at IS NULL \
           WHERE d.domain_id = s.domain_id AND d.state = 'bound')",
    )
    .bind(domain_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// One checker lease. A new holder token is minted for every attempt.
#[derive(Debug, sqlx::FromRow)]
pub struct Claim {
    pub domain_id: Uuid,
    pub generation: Uuid,
    pub name: String,
    pub steps: Json<Vec<Step>>,
    pub checked_at: DateTime<Utc>,
    pub next_check_at: DateTime<Utc>,
}

/// Claims the oldest due bound domain without waiting on another checker.
/// Due after 59 seconds, leaving one second for an available checker to poll.
pub async fn claim(
    executor: impl PgExecutor<'_>,
    holder: Uuid,
) -> Result<Option<Claim>, sqlx::Error> {
    sqlx::query_as(
        "WITH due AS (SELECT s.domain_id, d.name FROM grund_domain_setup s \
           JOIN grund_domains d ON d.domain_id = s.domain_id AND d.state = 'bound' \
           JOIN grund_apps a ON a.app_id = d.app_id AND a.deleted_at IS NULL \
           WHERE s.next_check_at <= clock_timestamp() \
             AND (s.leased_until IS NULL OR s.leased_until <= clock_timestamp()) \
           ORDER BY s.next_check_at, s.domain_id FOR UPDATE OF s SKIP LOCKED LIMIT 1) \
         UPDATE grund_domain_setup s SET leased_by = $1, \
           leased_until = clock_timestamp() + interval '30 seconds', leased_request = requested, \
           next_check_at = clock_timestamp() + interval '59 seconds' \
         FROM due WHERE s.domain_id = due.domain_id \
         RETURNING s.domain_id, s.generation, due.name, s.steps, clock_timestamp() AS checked_at, s.next_check_at",
    )
    .bind(holder)
    .fetch_optional(executor)
    .await
}

/// Writes only the DNS, edge and HTTPS observations, retaining concurrent ACME
/// progress. A stale lease or a changed binding writes nothing.
pub async fn finish(
    pool: &PgPool,
    claim: &Claim,
    holder: Uuid,
    observations: &[Step; 3],
) -> Result<bool, sqlx::Error> {
    let ready =
        observations[0].state == StepState::Done && observations[1].state == StepState::Done;
    let mut tx = pool.begin().await?;
    let pending = sqlx::query_scalar::<_, bool>(
        "SELECT s.recovery_pending FROM grund_domain_setup s \
         WHERE s.domain_id = $1 AND s.generation = $2 AND s.leased_by = $3 \
           AND s.leased_until > clock_timestamp() \
           AND EXISTS (SELECT 1 FROM grund_domains d JOIN grund_apps a ON a.app_id = d.app_id \
             AND a.deleted_at IS NULL WHERE d.domain_id = s.domain_id AND d.state = 'bound') \
         FOR UPDATE OF s",
    )
    .bind(claim.domain_id)
    .bind(claim.generation)
    .bind(holder)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(pending) = pending else {
        return Ok(false);
    };
    if ready && pending {
        sqlx::query(
            "WITH recovered AS (UPDATE grund_certificates c \
             SET next_attempt_at = greatest(clock_timestamp(), coalesce(retry_not_before, clock_timestamp())) \
             FROM grund_domain_setup s WHERE s.domain_id = $1 AND c.subject = 'domain:' || s.domain_id::text \
               AND c.chain_pem IS NULL AND c.last_error = 'authorization_failed' \
               AND (c.leased_until IS NULL OR c.leased_until <= clock_timestamp()) \
               AND (s.recovered_failure_at IS NULL OR s.recovered_failure_at < c.updated_at) \
             RETURNING c.updated_at, c.next_attempt_at) \
             UPDATE grund_domain_setup SET recovered_failure_at = recovered.updated_at, recovery_pending = false, \
               steps = jsonb_set(steps, ARRAY[(CASE WHEN steps->2->>'state' <> 'done' THEN 2 \
                   WHEN steps->3->>'state' <> 'done' THEN 3 ELSE 4 END)::text, 'next_retry_at'], \
                   to_jsonb(recovered.next_attempt_at)) \
             FROM recovered WHERE domain_id = $1",
        )
        .bind(claim.domain_id)
        .execute(&mut *tx)
        .await?;
    }
    let written = sqlx::query(
        "UPDATE grund_domain_setup SET steps = jsonb_set(jsonb_set(jsonb_set(steps, '{0}', $4), '{1}', $5), '{5}', $6), \
           recovery_pending = CASE WHEN $7 THEN recovery_pending ELSE true END, \
           leased_by = NULL, leased_until = NULL, leased_request = NULL, \
           next_check_at = CASE WHEN requested <> leased_request THEN clock_timestamp() ELSE next_check_at END \
         WHERE domain_id = $1 AND generation = $2 AND leased_by = $3 AND leased_until > clock_timestamp()",
    )
    .bind(claim.domain_id)
    .bind(claim.generation)
    .bind(holder)
    .bind(Json(&observations[0]))
    .bind(Json(&observations[1]))
    .bind(Json(&observations[2]))
    .bind(ready)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(written.rows_affected() == 1)
}

/// Publishes an unpredictable, short-lived HTTP-01 probe only for the current
/// binding and checker lease. Expiry also cleans up attempts cancelled mid-probe.
pub async fn put_probe(
    executor: impl PgExecutor<'_>,
    claim: &Claim,
    holder: Uuid,
    token: &str,
    value: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO grund_acme_challenges(kind, name, token, key_authorization, expires_at, subject) \
         SELECT 'http-01', d.name, $4, $5, clock_timestamp() + interval '45 seconds', \
                'domain:' || d.domain_id::text \
         FROM grund_domains d JOIN grund_domain_setup s ON s.domain_id = d.domain_id \
         WHERE d.domain_id = $1 AND d.state = 'bound' AND s.generation = $2 \
           AND s.leased_by = $3 AND s.leased_until > clock_timestamp()",
    )
    .bind(claim.domain_id)
    .bind(claim.generation)
    .bind(holder)
    .bind(token)
    .bind(value)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Records a real ACME boundary while the caller still owns its certificate
/// lease. Call before releasing the lease, in the outcome transaction.
pub async fn certificate_step(
    executor: impl PgExecutor<'_>,
    claim: &crate::certificates::Claim,
    holder: Uuid,
    position: i32,
    state: StepState,
    detail: &str,
    next_retry_at: Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_domain_setup s SET steps = grund_domain_setup_step(steps, $3, $4, $5, clock_timestamp(), $6), \
            next_check_at = coalesce(next_check_at, clock_timestamp()) \
         WHERE 'domain:' || s.domain_id::text = $1 \
           AND s.generation = $7 \
           AND NOT ($4 = 'in_progress' AND steps->$3->>'state' = 'done') \
           AND EXISTS (SELECT 1 FROM grund_domains d WHERE d.domain_id = s.domain_id AND d.state = 'bound') \
           AND EXISTS (SELECT 1 FROM grund_certificates c WHERE c.subject = $1 AND c.leased_by = $2 \
                       AND c.leased_until > clock_timestamp())",
    )
    .bind(&claim.subject)
    .bind(holder)
    .bind(position)
    .bind(state.as_str())
    .bind(detail)
    .bind(next_retry_at)
    .bind(claim.setup_generation)
    .execute(executor)
    .await?;
    Ok(())
}

/// Records the unfinished ACME boundary's failure without erasing completed
/// boundaries. The CA retry floor is written independently of ordinary backoff.
pub async fn certificate_failed(
    executor: impl PgExecutor<'_>,
    claim: &crate::certificates::Claim,
    holder: Uuid,
    delay_seconds: f64,
    code: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_domain_setup s SET steps = grund_domain_setup_step(steps, \
            CASE WHEN steps->2->>'state' <> 'done' THEN 2 \
                 WHEN steps->3->>'state' <> 'done' THEN 3 ELSE 4 END, \
            'failed', 'Certificate attempt failed (' || $4 || ').', clock_timestamp(), \
            clock_timestamp() + make_interval(secs => $3)), \
            next_check_at = coalesce(next_check_at, clock_timestamp()) \
         WHERE 'domain:' || s.domain_id::text = $1 \
           AND s.generation = $5 \
           AND EXISTS (SELECT 1 FROM grund_domains d WHERE d.domain_id = s.domain_id AND d.state = 'bound') \
           AND EXISTS (SELECT 1 FROM grund_certificates c WHERE c.subject = $1 AND c.leased_by = $2 \
                       AND c.leased_until > clock_timestamp() AND c.chain_pem IS NULL)",
    )
    .bind(&claim.subject)
    .bind(holder)
    .bind(delay_seconds)
    .bind(code)
    .bind(claim.setup_generation)
    .execute(executor)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::{self, Challenge, Desired};

    async fn bound(pool: &PgPool) -> (Uuid, Uuid, String) {
        let domain = Uuid::now_v7();
        let organisation = Uuid::now_v7();
        let app = Uuid::now_v7();
        sqlx::query("INSERT INTO grund_apps(app_id, organisation_id, name, settings, created_by, created_at, stream_version) \
                     VALUES ($1, $2, 'app', '{}', $2, clock_timestamp(), 1)")
            .bind(app).bind(organisation).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO grund_domains(domain_id, organisation_id, name, token, state, app_id, added_by, \
                     added_at, verified_at, bound_at, stream_version) \
                     VALUES ($1, $2, 'app.example.com', $3, 'bound', $4, $2, clock_timestamp(), \
                             clock_timestamp(), clock_timestamp(), 3)")
            .bind(domain).bind(organisation).bind(format!("grund-verify-{}", "a".repeat(43)))
            .bind(app).execute(pool).await.unwrap();
        let subject = crate::domains::certificate_subject(domain);
        certificates::desire(
            pool,
            &Desired {
                subject: subject.clone(),
                names: vec!["app.example.com".into()],
                directory: "https://ca.example/directory".into(),
                profile: "classic".into(),
                challenge: Challenge::Http01,
            },
        )
        .await
        .unwrap();
        (domain, organisation, subject)
    }

    fn observations(claim: &Claim, ready: bool) -> [Step; 3] {
        [0, 1, 5].map(|index| {
            let mut step = waiting_steps().swap_remove(index);
            step.state = if ready && index != 5 {
                StepState::Done
            } else {
                StepState::Failed
            };
            step.checked_at = Some(claim.checked_at);
            step.next_retry_at = Some(claim.next_check_at);
            step
        })
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn concurrent_check_requests_are_coalesced_without_losing_the_leased_request(
        pool: PgPool,
    ) {
        let (domain, _, _) = bound(&pool).await;
        let holder = Uuid::now_v7();
        let first = claim(&pool, holder).await.unwrap().unwrap();
        assert!(claim(&pool, Uuid::now_v7()).await.unwrap().is_none());
        assert!(request_check(&pool, domain).await.unwrap());
        assert!(request_check(&pool, domain).await.unwrap());
        assert!(
            finish(&pool, &first, holder, &observations(&first, false))
                .await
                .unwrap()
        );
        let second = claim(&pool, Uuid::now_v7()).await.unwrap().unwrap();
        assert_eq!(second.domain_id, domain);
        assert!(claim(&pool, Uuid::now_v7()).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_changed_binding_discards_stale_observations_and_probe_publications(pool: PgPool) {
        let (domain, organisation, _) = bound(&pool).await;
        let holder = Uuid::now_v7();
        let old = claim(&pool, holder).await.unwrap().unwrap();
        let old_certificate = certificates::claim(&pool, holder, 600.0)
            .await
            .unwrap()
            .unwrap();
        sqlx::query("UPDATE grund_domains SET state = 'verified', app_id = NULL, bound_at = NULL WHERE domain_id = $1")
            .bind(domain).execute(&pool).await.unwrap();
        assert!(!request_check(&pool, domain).await.unwrap());
        assert!(
            !put_probe(&pool, &old, holder, "probe", "answer")
                .await
                .unwrap()
        );
        assert!(
            !finish(&pool, &old, holder, &observations(&old, true))
                .await
                .unwrap()
        );
        let row = crate::domains::by_name(&pool, organisation, "app.example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(
            row.steps
                .0
                .iter()
                .all(|step| step.state == StepState::Waiting)
        );
        sqlx::query("UPDATE grund_domains SET state = 'bound', app_id = \
                     (SELECT app_id FROM grund_apps WHERE organisation_id = $2), bound_at = clock_timestamp() WHERE domain_id = $1")
            .bind(domain).bind(organisation).execute(&pool).await.unwrap();
        assert!(
            !put_probe(&pool, &old, holder, "probe", "answer")
                .await
                .unwrap()
        );
        assert!(
            !finish(&pool, &old, holder, &observations(&old, true))
                .await
                .unwrap()
        );
        assert_ne!(
            claim(&pool, Uuid::now_v7())
                .await
                .unwrap()
                .unwrap()
                .generation,
            old.generation
        );
        certificates::claim(&pool, holder, 600.0)
            .await
            .unwrap()
            .unwrap();
        certificate_step(
            &pool,
            &old_certificate,
            holder,
            4,
            StepState::Done,
            "Stale certificate.",
            None,
        )
        .await
        .unwrap();
        let row = crate::domains::by_name(&pool, organisation, "app.example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(
            row.steps
                .0
                .iter()
                .all(|step| step.state == StepState::Waiting)
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn edge_recovery_shortens_only_local_authorization_backoff_and_never_creates_an_order(
        pool: PgPool,
    ) {
        let (domain, _, subject) = bound(&pool).await;
        let cert_holder = Uuid::now_v7();
        let cert_claim = certificates::claim(&pool, cert_holder, 600.0)
            .await
            .unwrap()
            .unwrap();
        certificate_step(
            &pool,
            &cert_claim,
            cert_holder,
            2,
            StepState::Done,
            "Order accepted.",
            None,
        )
        .await
        .unwrap();
        certificate_failed(
            &pool,
            &cert_claim,
            cert_holder,
            43200.0,
            "authorization_failed",
        )
        .await
        .unwrap();
        certificates::retry_floor(&pool, &subject, cert_holder, Some(3600.0))
            .await
            .unwrap();
        certificates::record_failure(
            &pool,
            &subject,
            cert_holder,
            43200.0,
            "authorization_failed",
        )
        .await
        .unwrap();
        sqlx::query("UPDATE grund_domain_setup SET recovery_pending = true WHERE domain_id = $1")
            .bind(domain)
            .execute(&pool)
            .await
            .unwrap();
        let holder = Uuid::now_v7();
        let checked = claim(&pool, holder).await.unwrap().unwrap();
        finish(&pool, &checked, holder, &observations(&checked, true))
            .await
            .unwrap();
        let (next, floor): (DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
            "SELECT next_attempt_at, retry_not_before FROM grund_certificates WHERE subject = $1",
        )
        .bind(&subject)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(next, floor);
        assert!(
            certificates::claim(&pool, Uuid::now_v7(), 600.0)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(certificates::order_count(&pool, &subject).await.unwrap(), 0);
        sqlx::query("UPDATE grund_certificates SET retry_not_before = NULL, updated_at = clock_timestamp() WHERE subject = $1")
            .bind(&subject).execute(&pool).await.unwrap();
        sqlx::query("UPDATE grund_domain_setup SET recovery_pending = true WHERE domain_id = $1")
            .bind(domain)
            .execute(&pool)
            .await
            .unwrap();
        request_check(&pool, domain).await.unwrap();
        let recovered = claim(&pool, holder).await.unwrap().unwrap();
        finish(&pool, &recovered, holder, &observations(&recovered, true))
            .await
            .unwrap();
        assert!(
            certificates::claim(&pool, Uuid::now_v7(), 600.0)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(certificates::order_count(&pool, &subject).await.unwrap(), 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn rate_limits_and_stolen_certificate_leases_do_not_become_setup_success(pool: PgPool) {
        let (_, organisation, subject) = bound(&pool).await;
        let old = Uuid::now_v7();
        let old_claim = certificates::claim(&pool, old, 0.0).await.unwrap().unwrap();
        let holder = Uuid::now_v7();
        certificates::claim(&pool, holder, 600.0)
            .await
            .unwrap()
            .unwrap();
        certificate_step(&pool, &old_claim, old, 3, StepState::Done, "Stale.", None)
            .await
            .unwrap();
        assert!(
            !certificates::insert_order(
                &pool,
                Uuid::now_v7(),
                &subject,
                old,
                "https://ca.example/order/1",
                None
            )
            .await
            .unwrap()
        );
        assert!(
            !certificates::put_challenge(
                &pool,
                &subject,
                old,
                certificates::ChallengeAnswer {
                    kind: Challenge::Http01,
                    name: "app.example.com",
                    token: "stale",
                    key_authorization: "answer",
                },
                60.0
            )
            .await
            .unwrap()
        );
        certificates::record_failure(&pool, &subject, holder, 43200.0, "acme_rate_limited")
            .await
            .unwrap();
        let holder = Uuid::now_v7();
        let checked = claim(&pool, holder).await.unwrap().unwrap();
        finish(&pool, &checked, holder, &observations(&checked, true))
            .await
            .unwrap();
        assert!(
            certificates::claim(&pool, Uuid::now_v7(), 600.0)
                .await
                .unwrap()
                .is_none()
        );
        let row = crate::domains::by_name(&pool, organisation, "app.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.steps.0[3].state, StepState::Waiting);
        assert_eq!(row.certificate_attempts, 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_dns_recovery_during_an_active_order_is_remembered_and_consumed_only_once(
        pool: PgPool,
    ) {
        let (domain, _, subject) = bound(&pool).await;
        let cert_holder = Uuid::now_v7();
        certificates::claim(&pool, cert_holder, 600.0)
            .await
            .unwrap()
            .unwrap();
        let checker = Uuid::now_v7();
        let wrong = claim(&pool, checker).await.unwrap().unwrap();
        finish(&pool, &wrong, checker, &observations(&wrong, false))
            .await
            .unwrap();
        request_check(&pool, domain).await.unwrap();
        let corrected = claim(&pool, checker).await.unwrap().unwrap();
        finish(&pool, &corrected, checker, &observations(&corrected, true))
            .await
            .unwrap();
        certificates::record_failure(
            &pool,
            &subject,
            cert_holder,
            43200.0,
            "authorization_failed",
        )
        .await
        .unwrap();
        request_check(&pool, domain).await.unwrap();
        let recovered = claim(&pool, checker).await.unwrap().unwrap();
        finish(&pool, &recovered, checker, &observations(&recovered, true))
            .await
            .unwrap();
        assert!(
            certificates::claim(&pool, cert_holder, 600.0)
                .await
                .unwrap()
                .is_some()
        );
        certificates::record_failure(
            &pool,
            &subject,
            cert_holder,
            43200.0,
            "authorization_failed",
        )
        .await
        .unwrap();
        request_check(&pool, domain).await.unwrap();
        let unchanged = claim(&pool, checker).await.unwrap().unwrap();
        finish(&pool, &unchanged, checker, &observations(&unchanged, true))
            .await
            .unwrap();
        assert!(
            certificates::claim(&pool, Uuid::now_v7(), 600.0)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(certificates::order_count(&pool, &subject).await.unwrap(), 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn an_issued_certificate_reports_its_next_eligible_work_until_the_domain_is_unbound(
        pool: PgPool,
    ) {
        let (domain, organisation, subject) = bound(&pool).await;
        let holder = Uuid::now_v7();
        certificates::claim(&pool, holder, 600.0)
            .await
            .unwrap()
            .unwrap();
        let order = Uuid::now_v7();
        assert!(
            certificates::insert_order(
                &pool,
                order,
                &subject,
                holder,
                "https://ca.example/order/1",
                None
            )
            .await
            .unwrap()
        );
        let now = Utc::now();
        let ari_check_at = now + chrono::Duration::hours(6);
        assert!(
            certificates::record_issued(
                &pool,
                &subject,
                holder,
                order,
                &certificates::Issued {
                    chain_pem: "chain".into(),
                    sealed_key: Some(vec![1]),
                    not_before: now,
                    not_after: now + chrono::Duration::days(90),
                    renew_at: now + chrono::Duration::days(60),
                    ari_check_at: Some(ari_check_at),
                }
            )
            .await
            .unwrap()
        );
        let row = crate::domains::by_name(&pool, organisation, "app.example.com")
            .await
            .unwrap()
            .unwrap();
        let next = row.certificate_next_attempt_at.unwrap();
        assert!((next - ari_check_at).num_microseconds().unwrap().abs() < 2);
        sqlx::query("UPDATE grund_domains SET state = 'verified', app_id = NULL, bound_at = NULL WHERE domain_id = $1")
            .bind(domain).execute(&pool).await.unwrap();
        let row = crate::domains::by_name(&pool, organisation, "app.example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(row.certificate_next_attempt_at.is_none());
    }
}
