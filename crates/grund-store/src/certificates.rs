//! Certificates the instance orders by ACME (migration 0010): the account per
//! directory, what each subject should serve and does, the orders placed,
//! and the challenges waiting for a validator.
//!
//! One replica acts on a subject at a time: [`claim`] takes the row with
//! `SKIP LOCKED` and a lease, and every write that ends the work names the
//! holder, so a replica whose lease was taken over writes nothing. Sealing
//! is the caller's: this module stores the bytes it is given.

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

/// How a subject's names are proven. The strings match the tables' CHECKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    TlsAlpn01,
    Http01,
}

impl Challenge {
    pub fn as_str(self) -> &'static str {
        match self {
            Challenge::TlsAlpn01 => "tls-alpn-01",
            Challenge::Http01 => "http-01",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Challenge::TlsAlpn01, Challenge::Http01]
            .into_iter()
            .find(|c| c.as_str() == value)
    }
}

/// What a subject should be served with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    pub subject: String,
    pub names: Vec<String>,
    pub directory: String,
    pub profile: String,
    pub challenge: Challenge,
}

/// Records what `desired.subject` should serve. When its names, directory
/// or profile differ from what was ordered before, a new order is due now
/// and any pending order is abandoned; the current chain keeps being served
/// until the new one lands. Returns whether anything changed.
pub async fn desire(pool: &PgPool, desired: &Desired) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let existing = sqlx::query_as::<_, (Vec<String>, String, String, String)>(
        "SELECT names, directory, profile, challenge FROM grund_certificates WHERE subject = $1 FOR UPDATE",
    )
    .bind(&desired.subject)
    .fetch_optional(&mut *tx)
    .await?;
    let changed = match existing {
        None => {
            sqlx::query(
                "INSERT INTO grund_certificates (subject, names, directory, profile, challenge) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&desired.subject)
            .bind(&desired.names)
            .bind(&desired.directory)
            .bind(&desired.profile)
            .bind(desired.challenge.as_str())
            .execute(&mut *tx)
            .await?;
            true
        }
        Some((names, directory, profile, challenge)) => {
            let reorder = names != desired.names
                || directory != desired.directory
                || profile != desired.profile;
            if reorder {
                sqlx::query(
                    "UPDATE grund_certificates SET names = $2, directory = $3, profile = $4, \
                     challenge = $5, renew_at = clock_timestamp(), ari_check_at = NULL, attempts = 0, \
                     next_attempt_at = clock_timestamp(), last_error = NULL, updated_at = clock_timestamp() \
                     WHERE subject = $1",
                )
                .bind(&desired.subject)
                .bind(&desired.names)
                .bind(&desired.directory)
                .bind(&desired.profile)
                .bind(desired.challenge.as_str())
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "UPDATE grund_acme_orders SET status = 'abandoned', sealed_key = NULL, \
                     error = 'superseded', finished_at = clock_timestamp() \
                     WHERE subject = $1 AND status = 'pending'",
                )
                .bind(&desired.subject)
                .execute(&mut *tx)
                .await?;
            } else if challenge != desired.challenge.as_str() {
                sqlx::query(
                    "UPDATE grund_certificates SET challenge = $2, updated_at = clock_timestamp() WHERE subject = $1",
                )
                .bind(&desired.subject)
                .bind(desired.challenge.as_str())
                .execute(&mut *tx)
                .await?;
            }
            reorder || challenge != desired.challenge.as_str()
        }
    };
    tx.commit().await?;
    Ok(changed)
}

/// A subject's current chain, as every replica serves it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Stored {
    pub version: i64,
    pub chain_pem: String,
    pub sealed_key: Option<Vec<u8>>,
}

/// The subject's chain, only if its version is not `known` (0: none known).
pub async fn stored_if_changed(
    executor: impl PgExecutor<'_>,
    subject: &str,
    known: i64,
) -> Result<Option<Stored>, sqlx::Error> {
    sqlx::query_as::<_, Stored>(
        "SELECT version, chain_pem, sealed_key FROM grund_certificates \
         WHERE subject = $1 AND chain_pem IS NOT NULL AND version <> $2",
    )
    .bind(subject)
    .bind(known)
    .fetch_optional(executor)
    .await
}

/// Work a replica has claimed on one subject.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Claim {
    pub subject: String,
    pub names: Vec<String>,
    pub directory: String,
    pub profile: String,
    pub challenge: String,
    pub attempts: i32,
    pub chain_pem: Option<String>,
    /// A new order is due (none issued yet, or the renewal time passed);
    /// otherwise only the CA's renewal information is.
    pub order_due: bool,
    /// `instance` (the key is made and sealed here) or `remote` (the
    /// terminator sent `csr`).
    pub terminator: String,
    /// A remote terminator's CSR, unspent whenever an order is due.
    pub csr: Option<Vec<u8>>,
}

/// Claims the subject whose work is most overdue, for `lease_seconds`: an
/// order when there is no chain or its renewal time passed, or an ARI check
/// when that is due. A remote terminator's order is due only while it has an
/// unspent CSR; until it sends one, it is asked for one instead
/// ([`remote_status`]). None when nothing is due or another replica holds it.
pub async fn claim(
    executor: impl PgExecutor<'_>,
    holder: Uuid,
    lease_seconds: f64,
) -> Result<Option<Claim>, sqlx::Error> {
    sqlx::query_as::<_, Claim>(
        "WITH due AS ( \
           SELECT subject FROM grund_certificates \
            WHERE next_attempt_at <= clock_timestamp() \
              AND (leased_until IS NULL OR leased_until < clock_timestamp()) \
              AND ((( chain_pem IS NULL OR renew_at <= clock_timestamp()) \
                    AND (terminator = 'instance' OR NOT csr_spent)) \
                   OR (chain_pem IS NOT NULL AND ari_check_at <= clock_timestamp())) \
            ORDER BY next_attempt_at, subject \
            FOR UPDATE SKIP LOCKED LIMIT 1) \
         UPDATE grund_certificates c SET leased_by = $1, \
                leased_until = clock_timestamp() + make_interval(secs => $2) \
           FROM due WHERE c.subject = due.subject \
         RETURNING c.subject, c.names, c.directory, c.profile, c.challenge, c.attempts, c.chain_pem, \
                   ((c.chain_pem IS NULL OR c.renew_at <= clock_timestamp()) \
                    AND (c.terminator = 'instance' OR NOT c.csr_spent)) AS order_due, \
                   c.terminator, c.csr",
    )
    .bind(holder)
    .bind(lease_seconds)
    .fetch_optional(executor)
    .await
}

/// A certificate that was issued, as it is stored.
#[derive(Debug, Clone)]
pub struct Issued {
    pub chain_pem: String,
    pub sealed_key: Option<Vec<u8>>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub renew_at: DateTime<Utc>,
    pub ari_check_at: Option<DateTime<Utc>>,
}

/// Stores a new chain for `subject`, ends `order_id` as valid and releases
/// the lease, in one statement. A remote terminator's CSR is spent by it. False (nothing written) when `holder` no
/// longer holds the subject.
pub async fn record_issued(
    executor: impl PgExecutor<'_>,
    subject: &str,
    holder: Uuid,
    order_id: Uuid,
    issued: &Issued,
) -> Result<bool, sqlx::Error> {
    let written = sqlx::query_scalar::<_, String>(
        "WITH written AS ( \
           UPDATE grund_certificates SET chain_pem = $3, sealed_key = $4, not_before = $5, not_after = $6, \
                  renew_at = $7, ari_check_at = $8, version = version + 1, attempts = 0, last_error = NULL, \
                  csr_spent = (terminator = 'remote'), \
                  next_attempt_at = clock_timestamp(), leased_by = NULL, leased_until = NULL, \
                  updated_at = clock_timestamp() \
            WHERE subject = $1 AND leased_by = $2 RETURNING subject), \
         finished AS ( \
           UPDATE grund_acme_orders SET status = 'valid', sealed_key = NULL, finished_at = clock_timestamp() \
            WHERE order_id = $9 AND status = 'pending' AND EXISTS (SELECT 1 FROM written)) \
         SELECT subject FROM written",
    )
    .bind(subject)
    .bind(holder)
    .bind(&issued.chain_pem)
    .bind(&issued.sealed_key)
    .bind(issued.not_before)
    .bind(issued.not_after)
    .bind(issued.renew_at)
    .bind(issued.ari_check_at)
    .bind(order_id)
    .fetch_optional(executor)
    .await?;
    Ok(written.is_some())
}

/// Records a failed attempt: the next one waits `delay_seconds` (the
/// caller's backoff, already honouring any Retry-After), and `error` is a
/// stable code. Releases the lease. False when `holder` no longer held it.
pub async fn record_failure(
    executor: impl PgExecutor<'_>,
    subject: &str,
    holder: Uuid,
    delay_seconds: f64,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_certificates SET attempts = attempts + 1, \
                next_attempt_at = clock_timestamp() + make_interval(secs => $3), last_error = $4, \
                leased_by = NULL, leased_until = NULL, updated_at = clock_timestamp() \
          WHERE subject = $1 AND leased_by = $2",
    )
    .bind(subject)
    .bind(holder)
    .bind(delay_seconds)
    .bind(error)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Records the CA's renewal information: when to renew, and when to ask
/// again. Releases the lease. False when `holder` no longer held it.
pub async fn record_renewal_info(
    executor: impl PgExecutor<'_>,
    subject: &str,
    holder: Uuid,
    renew_at: DateTime<Utc>,
    ari_check_at: Option<DateTime<Utc>>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_certificates SET renew_at = $3, ari_check_at = $4, \
                leased_by = NULL, leased_until = NULL, updated_at = clock_timestamp() \
          WHERE subject = $1 AND leased_by = $2",
    )
    .bind(subject)
    .bind(holder)
    .bind(renew_at)
    .bind(ari_check_at)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Releases the lease without changing anything else.
pub async fn release(
    executor: impl PgExecutor<'_>,
    subject: &str,
    holder: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_certificates SET leased_by = NULL, leased_until = NULL \
          WHERE subject = $1 AND leased_by = $2",
    )
    .bind(subject)
    .bind(holder)
    .execute(executor)
    .await?;
    Ok(())
}

/// Makes a new order for `subject` due now, e.g. because its stored key can
/// no longer be opened.
pub async fn order_now(executor: impl PgExecutor<'_>, subject: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_certificates SET renew_at = clock_timestamp(), next_attempt_at = clock_timestamp() \
          WHERE subject = $1",
    )
    .bind(subject)
    .execute(executor)
    .await?;
    Ok(())
}

/// An order placed and not yet finished.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingOrder {
    pub order_id: Uuid,
    pub url: String,
    pub sealed_key: Option<Vec<u8>>,
}

/// The subject's pending order, if one was placed and not finished.
pub async fn pending_order(
    executor: impl PgExecutor<'_>,
    subject: &str,
) -> Result<Option<PendingOrder>, sqlx::Error> {
    sqlx::query_as::<_, PendingOrder>(
        "SELECT order_id, url, sealed_key FROM grund_acme_orders WHERE subject = $1 AND status = 'pending'",
    )
    .bind(subject)
    .fetch_optional(executor)
    .await
}

/// Records an order just placed, with the sealed key behind its CSR. A
/// subject has at most one pending order; a second is refused by the unique
/// index.
pub async fn insert_order(
    executor: impl PgExecutor<'_>,
    order_id: Uuid,
    subject: &str,
    url: &str,
    sealed_key: Option<&[u8]>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_acme_orders (order_id, subject, url, sealed_key, status) VALUES ($1, $2, $3, $4, 'pending')",
    )
    .bind(order_id)
    .bind(subject)
    .bind(url)
    .bind(sealed_key)
    .execute(executor)
    .await?;
    Ok(())
}

/// Ends a pending order as `invalid` or `abandoned`, dropping its key.
pub async fn finish_order(
    executor: impl PgExecutor<'_>,
    order_id: Uuid,
    status: &str,
    error: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_acme_orders SET status = $2, error = $3, sealed_key = NULL, finished_at = clock_timestamp() \
          WHERE order_id = $1 AND status = 'pending'",
    )
    .bind(order_id)
    .bind(status)
    .bind(error)
    .execute(executor)
    .await?;
    Ok(())
}

/// How many orders were placed for `subject`, finished or not.
pub async fn order_count(executor: impl PgExecutor<'_>, subject: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM grund_acme_orders WHERE subject = $1")
        .bind(subject)
        .fetch_one(executor)
        .await
}

/// The sealed account credentials for `directory`, if an account exists.
pub async fn account(
    executor: impl PgExecutor<'_>,
    directory: &str,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar("SELECT credentials FROM grund_acme_accounts WHERE directory = $1")
        .bind(directory)
        .fetch_optional(executor)
        .await
}

/// Stores a new account's sealed credentials, unless another replica stored
/// one first; returns what is stored afterwards, which the caller uses.
pub async fn insert_account(
    pool: &PgPool,
    directory: &str,
    credentials: &[u8],
) -> Result<Vec<u8>, sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_acme_accounts (directory, credentials) VALUES ($1, $2) ON CONFLICT (directory) DO NOTHING",
    )
    .bind(directory)
    .bind(credentials)
    .execute(pool)
    .await?;
    sqlx::query_scalar("SELECT credentials FROM grund_acme_accounts WHERE directory = $1")
        .bind(directory)
        .fetch_one(pool)
        .await
}

/// Forgets the account for `directory`, so the next order makes a new one.
pub async fn delete_account(
    executor: impl PgExecutor<'_>,
    directory: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM grund_acme_accounts WHERE directory = $1")
        .bind(directory)
        .execute(executor)
        .await?;
    Ok(())
}

/// Publishes a challenge's key authorization for `subject` for
/// `ttl_seconds`, so every replica answers it (or hands it to the subject's
/// terminator), and drops expired ones.
pub async fn put_challenge(
    pool: &PgPool,
    subject: &str,
    kind: Challenge,
    name: &str,
    token: &str,
    key_authorization: &str,
    ttl_seconds: f64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM grund_acme_challenges WHERE expires_at < clock_timestamp()")
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO grund_acme_challenges (kind, name, token, key_authorization, expires_at, subject) \
         VALUES ($1, $2, $3, $4, clock_timestamp() + make_interval(secs => $5), $6) \
         ON CONFLICT (kind, name, token) DO UPDATE SET key_authorization = EXCLUDED.key_authorization, \
                expires_at = EXCLUDED.expires_at, subject = EXCLUDED.subject, answering_at = NULL",
    )
    .bind(kind.as_str())
    .bind(name)
    .bind(token)
    .bind(key_authorization)
    .bind(ttl_seconds)
    .bind(subject)
    .execute(pool)
    .await?;
    Ok(())
}

/// Removes a challenge once its authorization is decided.
pub async fn remove_challenge(
    pool: &PgPool,
    kind: Challenge,
    name: &str,
    token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM grund_acme_challenges WHERE kind = $1 AND name = $2 AND token = $3")
        .bind(kind.as_str())
        .bind(name)
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

/// The newest unexpired TLS-ALPN-01 key authorization of `subject` for
/// `name`.
pub async fn tls_alpn01(
    executor: impl PgExecutor<'_>,
    subject: &str,
    name: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT key_authorization FROM grund_acme_challenges \
          WHERE kind = 'tls-alpn-01' AND subject = $1 AND name = $2 AND expires_at > clock_timestamp() \
          ORDER BY expires_at DESC LIMIT 1",
    )
    .bind(subject)
    .bind(name)
    .fetch_optional(executor)
    .await
}

/// The unexpired HTTP-01 key authorization of `subject` for `token`.
pub async fn http01(
    executor: impl PgExecutor<'_>,
    subject: &str,
    token: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT key_authorization FROM grund_acme_challenges \
          WHERE kind = 'http-01' AND subject = $1 AND token = $2 AND expires_at > clock_timestamp() LIMIT 1",
    )
    .bind(subject)
    .bind(token)
    .fetch_optional(executor)
    .await
}

/// A challenge waiting on a remote terminator.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PendingChallenge {
    pub kind: String,
    pub name: String,
    pub token: String,
    pub key_authorization: String,
}

/// The unexpired challenges of `subject`, oldest first.
pub async fn challenges_of(
    executor: impl PgExecutor<'_>,
    subject: &str,
) -> Result<Vec<PendingChallenge>, sqlx::Error> {
    sqlx::query_as::<_, PendingChallenge>(
        "SELECT kind, name, token, key_authorization FROM grund_acme_challenges \
          WHERE subject = $1 AND expires_at > clock_timestamp() ORDER BY expires_at, token",
    )
    .bind(subject)
    .fetch_all(executor)
    .await
}

/// Records that `subject`'s terminator answers the challenge with `token`.
/// False when `subject` has no such unexpired challenge.
pub async fn mark_answering(
    executor: impl PgExecutor<'_>,
    subject: &str,
    token: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE grund_acme_challenges SET answering_at = clock_timestamp() \
          WHERE subject = $1 AND token = $2 AND expires_at > clock_timestamp()",
    )
    .bind(subject)
    .bind(token)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Whether `subject`'s terminator said it answers the challenge with
/// `token`.
pub async fn answering(
    executor: impl PgExecutor<'_>,
    subject: &str,
    token: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM grund_acme_challenges \
          WHERE subject = $1 AND token = $2 AND answering_at IS NOT NULL AND expires_at > clock_timestamp())",
    )
    .bind(subject)
    .bind(token)
    .fetch_one(executor)
    .await
}

/// What a remote terminator asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRequest {
    pub owner: String,
    pub subject: String,
    pub names: Vec<String>,
    pub csr: Vec<u8>,
    pub directory: String,
    pub profile: String,
    pub challenge: Challenge,
}

/// Records a remote terminator's CSR for `request.subject`. The same names
/// and CSR change nothing. Anything else replaces what was asked before,
/// abandons a pending order and makes a new one due now; the current chain
/// stays until the new one is issued. Refused (false, nothing written) when
/// the subject exists under another owner or with the instance's own key.
/// Returns whether the request was recorded (changed or already so).
pub async fn request_remote(pool: &PgPool, request: &RemoteRequest) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let existing = sqlx::query_as::<_, (String, String, Vec<String>, Option<Vec<u8>>)>(
        "SELECT owner, terminator, names, csr FROM grund_certificates WHERE subject = $1 FOR UPDATE",
    )
    .bind(&request.subject)
    .fetch_optional(&mut *tx)
    .await?;
    match existing {
        None => {
            sqlx::query(
                "INSERT INTO grund_certificates (subject, owner, terminator, names, directory, profile, challenge, csr) \
                 VALUES ($1, $2, 'remote', $3, $4, $5, $6, $7)",
            )
            .bind(&request.subject)
            .bind(&request.owner)
            .bind(&request.names)
            .bind(&request.directory)
            .bind(&request.profile)
            .bind(request.challenge.as_str())
            .bind(&request.csr)
            .execute(&mut *tx)
            .await?;
        }
        Some((owner, terminator, _, _)) if owner != request.owner || terminator != "remote" => {
            return Ok(false);
        }
        Some((_, _, names, csr))
            if names == request.names && csr.as_deref() == Some(&request.csr[..]) => {}
        Some(_) => {
            sqlx::query(
                "UPDATE grund_certificates SET names = $2, directory = $3, profile = $4, challenge = $5, \
                        csr = $6, csr_spent = false, renew_at = clock_timestamp(), ari_check_at = NULL, \
                        attempts = 0, next_attempt_at = clock_timestamp(), last_error = NULL, \
                        updated_at = clock_timestamp() \
                  WHERE subject = $1",
            )
            .bind(&request.subject)
            .bind(&request.names)
            .bind(&request.directory)
            .bind(&request.profile)
            .bind(request.challenge.as_str())
            .bind(&request.csr)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE grund_acme_orders SET status = 'abandoned', sealed_key = NULL, \
                 error = 'superseded', finished_at = clock_timestamp() \
                 WHERE subject = $1 AND status = 'pending'",
            )
            .bind(&request.subject)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

/// Where a remote terminator's certificate stands.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RemoteStatus {
    pub names: Vec<String>,
    pub chain_pem: Option<String>,
    pub version: i64,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub renew_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    /// Renewal (or a first order) is due, and the CSR it has is spent.
    pub wants_csr: bool,
    /// The chain is current and nothing is due.
    pub issued: bool,
}

/// `subject`'s certificate, if `owner` has one there.
pub async fn remote_status(
    executor: impl PgExecutor<'_>,
    owner: &str,
    subject: &str,
) -> Result<Option<RemoteStatus>, sqlx::Error> {
    sqlx::query_as::<_, RemoteStatus>(
        "SELECT names, chain_pem, version, not_before, not_after, renew_at, last_error, \
                (csr_spent AND (chain_pem IS NULL OR renew_at <= clock_timestamp())) AS wants_csr, \
                (chain_pem IS NOT NULL AND renew_at > clock_timestamp()) AS issued \
           FROM grund_certificates WHERE owner = $1 AND subject = $2 AND terminator = 'remote'",
    )
    .bind(owner)
    .bind(subject)
    .fetch_optional(executor)
    .await
}

/// Every remote certificate of `owner` whose subject starts with `prefix`,
/// with its subject, in subject order.
pub async fn remote_statuses(
    executor: impl PgExecutor<'_>,
    owner: &str,
    prefix: &str,
) -> Result<Vec<(String, RemoteStatus)>, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct Row {
        subject: String,
        #[sqlx(flatten)]
        status: RemoteStatus,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT subject, names, chain_pem, version, not_before, not_after, renew_at, last_error, \
                (csr_spent AND (chain_pem IS NULL OR renew_at <= clock_timestamp())) AS wants_csr, \
                (chain_pem IS NOT NULL AND renew_at > clock_timestamp()) AS issued \
           FROM grund_certificates \
          WHERE owner = $1 AND starts_with(subject, $2) AND terminator = 'remote' \
          ORDER BY subject",
    )
    .bind(owner)
    .bind(prefix)
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().map(|r| (r.subject, r.status)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired(subject: &str) -> Desired {
        Desired {
            subject: subject.into(),
            names: vec!["grund.example.com".into()],
            directory: "https://acme.example/dir".into(),
            profile: "classic".into(),
            challenge: Challenge::TlsAlpn01,
        }
    }

    fn issued() -> Issued {
        let now = Utc::now();
        Issued {
            chain_pem: "chain".into(),
            sealed_key: Some(vec![1, 2, 3]),
            not_before: now,
            not_after: now + chrono::Duration::days(90),
            renew_at: now + chrono::Duration::days(60),
            ari_check_at: Some(now + chrono::Duration::hours(6)),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn one_replica_claims_a_subject_while_another_is_refused(pool: PgPool) {
        desire(&pool, &desired("instance")).await.unwrap();
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let claimed = claim(&pool, a, 300.0).await.unwrap().unwrap();
        assert!(claimed.order_due);
        assert!(claim(&pool, b, 300.0).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_replica_whose_lease_was_taken_writes_nothing(pool: PgPool) {
        desire(&pool, &desired("instance")).await.unwrap();
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        claim(&pool, a, 0.0).await.unwrap().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        claim(&pool, b, 300.0).await.unwrap().unwrap();
        let order = Uuid::now_v7();
        insert_order(
            &pool,
            order,
            "instance",
            "https://acme.example/order/1",
            None,
        )
        .await
        .unwrap();
        assert!(
            !record_issued(&pool, "instance", a, order, &issued())
                .await
                .unwrap()
        );
        assert!(
            !record_failure(&pool, "instance", a, 60.0, "x")
                .await
                .unwrap()
        );
        assert!(
            record_issued(&pool, "instance", b, order, &issued())
                .await
                .unwrap()
        );
        let stored = stored_if_changed(&pool, "instance", 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.version, 1);
        assert!(
            stored_if_changed(&pool, "instance", 1)
                .await
                .unwrap()
                .is_none()
        );
        assert!(pending_order(&pool, "instance").await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn an_issued_certificate_is_not_due_until_its_renewal_time(pool: PgPool) {
        desire(&pool, &desired("instance")).await.unwrap();
        let holder = Uuid::now_v7();
        claim(&pool, holder, 300.0).await.unwrap().unwrap();
        let order = Uuid::now_v7();
        insert_order(
            &pool,
            order,
            "instance",
            "https://acme.example/order/1",
            None,
        )
        .await
        .unwrap();
        record_issued(&pool, "instance", holder, order, &issued())
            .await
            .unwrap();
        assert!(claim(&pool, holder, 300.0).await.unwrap().is_none());
        assert!(!desire(&pool, &desired("instance")).await.unwrap());
        let mut other = desired("instance");
        other.names.push("www.grund.example.com".into());
        assert!(desire(&pool, &other).await.unwrap());
        assert!(
            claim(&pool, holder, 300.0)
                .await
                .unwrap()
                .unwrap()
                .order_due
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_failure_waits_out_its_delay(pool: PgPool) {
        desire(&pool, &desired("instance")).await.unwrap();
        let holder = Uuid::now_v7();
        claim(&pool, holder, 300.0).await.unwrap().unwrap();
        assert!(
            record_failure(&pool, "instance", holder, 3600.0, "unreachable")
                .await
                .unwrap()
        );
        assert!(claim(&pool, holder, 300.0).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_subject_has_one_pending_order_at_a_time(pool: PgPool) {
        desire(&pool, &desired("instance")).await.unwrap();
        let url = "https://acme.example/order/1";
        insert_order(&pool, Uuid::now_v7(), "instance", url, Some(b"k"))
            .await
            .unwrap();
        assert!(
            insert_order(&pool, Uuid::now_v7(), "instance", url, None)
                .await
                .is_err()
        );
        let pending = pending_order(&pool, "instance").await.unwrap().unwrap();
        finish_order(&pool, pending.order_id, "invalid", "authorization_failed")
            .await
            .unwrap();
        assert!(pending_order(&pool, "instance").await.unwrap().is_none());
        assert_eq!(order_count(&pool, "instance").await.unwrap(), 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_challenge_is_answered_until_it_expires(pool: PgPool) {
        put_challenge(
            &pool,
            "instance",
            Challenge::TlsAlpn01,
            "grund.example.com",
            "tok",
            "ka",
            60.0,
        )
        .await
        .unwrap();
        put_challenge(
            &pool,
            "instance",
            Challenge::Http01,
            "grund.example.com",
            "tok2",
            "ka2",
            0.0,
        )
        .await
        .unwrap();
        assert_eq!(
            tls_alpn01(&pool, "instance", "grund.example.com")
                .await
                .unwrap()
                .as_deref(),
            Some("ka")
        );
        assert!(
            tls_alpn01(&pool, "instance", "other.example.com")
                .await
                .unwrap()
                .is_none()
        );
        assert!(http01(&pool, "instance", "tok2").await.unwrap().is_none());
        remove_challenge(&pool, Challenge::TlsAlpn01, "grund.example.com", "tok")
            .await
            .unwrap();
        assert!(
            tls_alpn01(&pool, "instance", "grund.example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn the_first_account_stored_for_a_directory_wins(pool: PgPool) {
        let first = insert_account(&pool, "https://acme.example/dir", b"one")
            .await
            .unwrap();
        let second = insert_account(&pool, "https://acme.example/dir", b"two")
            .await
            .unwrap();
        assert_eq!(first, b"one");
        assert_eq!(second, b"one");
        assert_eq!(
            account(&pool, "https://acme.example/dir").await.unwrap(),
            Some(b"one".to_vec())
        );
    }

    fn remote(csr: &[u8]) -> RemoteRequest {
        RemoteRequest {
            owner: "instance".into(),
            subject: "relay:relay.example.com".into(),
            names: vec!["relay.example.com".into()],
            csr: csr.to_vec(),
            directory: "https://acme.example/dir".into(),
            profile: "classic".into(),
            challenge: Challenge::TlsAlpn01,
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_remote_csr_is_ordered_once_then_a_fresh_one_is_wanted(pool: PgPool) {
        let subject = "relay:relay.example.com";
        assert!(request_remote(&pool, &remote(b"csr-1")).await.unwrap());
        let holder = Uuid::now_v7();
        let claimed = claim(&pool, holder, 300.0).await.unwrap().unwrap();
        assert!(claimed.order_due);
        assert_eq!(claimed.terminator, "remote");
        assert_eq!(claimed.csr.as_deref(), Some(&b"csr-1"[..]));
        let order = Uuid::now_v7();
        insert_order(&pool, order, subject, "https://acme.example/order/1", None)
            .await
            .unwrap();
        let mut due_now = issued();
        due_now.sealed_key = None;
        due_now.renew_at = Utc::now() - chrono::Duration::seconds(1);
        due_now.ari_check_at = None;
        assert!(
            record_issued(&pool, subject, holder, order, &due_now)
                .await
                .unwrap()
        );
        assert!(claim(&pool, holder, 300.0).await.unwrap().is_none());
        let status = remote_status(&pool, "instance", subject)
            .await
            .unwrap()
            .unwrap();
        assert!(status.wants_csr && !status.issued);
        assert_eq!(status.version, 1);

        assert!(request_remote(&pool, &remote(b"csr-1")).await.unwrap());
        assert!(claim(&pool, holder, 300.0).await.unwrap().is_none());
        assert!(request_remote(&pool, &remote(b"csr-2")).await.unwrap());
        let claimed = claim(&pool, holder, 300.0).await.unwrap().unwrap();
        assert!(claimed.order_due);
        assert_eq!(claimed.csr.as_deref(), Some(&b"csr-2"[..]));
        let status = remote_status(&pool, "instance", subject)
            .await
            .unwrap()
            .unwrap();
        assert!(!status.wants_csr);
        assert!(
            status.chain_pem.is_some(),
            "the old chain stays until the new one"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_remote_request_cannot_take_over_another_owners_subject_or_the_instances(
        pool: PgPool,
    ) {
        request_remote(&pool, &remote(b"csr-1")).await.unwrap();
        let mut other = remote(b"csr-2");
        other.owner = "organisation:0190c7d2-0000-7000-8000-000000000001".into();
        assert!(!request_remote(&pool, &other).await.unwrap());
        assert!(
            remote_status(&pool, &other.owner, &other.subject)
                .await
                .unwrap()
                .is_none()
        );
        desire(&pool, &desired("instance")).await.unwrap();
        let mut instance = remote(b"csr-3");
        instance.subject = "instance".into();
        assert!(!request_remote(&pool, &instance).await.unwrap());
        assert!(
            remote_status(&pool, "instance", "instance")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_terminator_sees_only_its_own_challenges_and_says_when_it_answers(pool: PgPool) {
        let subject = "relay:relay.example.com";
        put_challenge(
            &pool,
            subject,
            Challenge::TlsAlpn01,
            "relay.example.com",
            "tok",
            "ka",
            60.0,
        )
        .await
        .unwrap();
        assert!(challenges_of(&pool, "instance").await.unwrap().is_empty());
        assert!(
            tls_alpn01(&pool, "instance", "relay.example.com")
                .await
                .unwrap()
                .is_none()
        );
        let pending = challenges_of(&pool, subject).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].token, "tok");
        assert!(!answering(&pool, subject, "tok").await.unwrap());
        assert!(
            !mark_answering(&pool, "relay:other.example.com", "tok")
                .await
                .unwrap()
        );
        assert!(mark_answering(&pool, subject, "tok").await.unwrap());
        assert!(answering(&pool, subject, "tok").await.unwrap());
    }
}
