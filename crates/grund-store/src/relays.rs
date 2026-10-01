//! `grund relay`s and `grund edge`s enrolled with the instance (migrations
//! 0014, 0016): one-time tokens minted for a host, and the terminator each
//! enrolled under its own key. `role` is `relay` or `edge`. One active
//! terminator per role and host; enrolling a host again revokes the one it
//! had.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// An enrolled relay.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RelayRow {
    pub relay_id: Uuid,
    pub host: String,
    pub public_key: Vec<u8>,
    pub state: String,
    pub role: String,
    pub enrolled_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Stores a token (its digest only) that enrolls one relay for `host`
/// within `ttl_seconds`.
pub async fn insert_token(
    executor: impl PgExecutor<'_>,
    role: &str,
    digest: &[u8; 32],
    host: &str,
    ttl_seconds: f64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_relay_tokens (token_digest, host, expires_at, role) \
         VALUES ($1, $2, clock_timestamp() + make_interval(secs => $3), $4)",
    )
    .bind(&digest[..])
    .bind(host)
    .bind(ttl_seconds)
    .bind(role)
    .execute(executor)
    .await?;
    Ok(())
}

/// A token, locked, with the key of the relay it enrolled, if it did.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TokenRow {
    pub host: String,
    pub expires_at: DateTime<Utc>,
    pub relay_id: Option<Uuid>,
    pub consumed_key: Option<Vec<u8>>,
}

/// The token with `digest` for `role`, locked for the enrollment's
/// transaction.
pub async fn token_for_update(
    connection: &mut PgConnection,
    role: &str,
    digest: &[u8; 32],
) -> Result<Option<TokenRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT t.host, t.expires_at, t.relay_id, r.public_key AS consumed_key \
           FROM grund_relay_tokens t LEFT JOIN grund_relays r ON r.relay_id = t.relay_id \
          WHERE t.token_digest = $1 AND t.role = $2 FOR UPDATE OF t",
    )
    .bind(&digest[..])
    .bind(role)
    .fetch_optional(connection)
    .await
}

/// Whether `public_key` belongs to any relay, active or revoked: a key is
/// enrolled once.
pub async fn key_known(
    executor: impl PgExecutor<'_>,
    public_key: &[u8],
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM grund_relays WHERE public_key = $1)")
        .bind(public_key)
        .fetch_one(executor)
        .await
}

/// Enrolls `public_key` as a new relay for the token's host, revoking the
/// relay the host had, and consumes the token, in the caller's transaction.
pub async fn enroll(
    connection: &mut PgConnection,
    role: &str,
    digest: &[u8; 32],
    relay_id: Uuid,
    host: &str,
    public_key: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_relays SET state = 'revoked', revoked_at = clock_timestamp() \
          WHERE host = $1 AND state = 'active' AND role = $2",
    )
    .bind(host)
    .bind(role)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO grund_relays (relay_id, host, public_key, state, role) \
         VALUES ($1, $2, $3, 'active', $4)",
    )
    .bind(relay_id)
    .bind(host)
    .bind(public_key)
    .bind(role)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE grund_relay_tokens SET relay_id = $2, consumed_at = clock_timestamp() \
          WHERE token_digest = $1 AND consumed_at IS NULL",
    )
    .bind(&digest[..])
    .bind(relay_id)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// The relay with `relay_id`, whatever its state.
pub async fn relay(
    executor: impl PgExecutor<'_>,
    relay_id: Uuid,
) -> Result<Option<RelayRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT relay_id, host, public_key, state, role, enrolled_at, revoked_at FROM grund_relays WHERE relay_id = $1",
    )
    .bind(relay_id)
    .fetch_optional(executor)
    .await
}

/// Every terminator of `role`, newest first.
pub async fn list(executor: impl PgExecutor<'_>, role: &str) -> Result<Vec<RelayRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT relay_id, host, public_key, state, role, enrolled_at, revoked_at FROM grund_relays \
          WHERE role = $1 ORDER BY enrolled_at DESC, relay_id",
    )
    .bind(role)
    .fetch_all(executor)
    .await
}

/// The public keys of every active edge whose host is in `hosts`.
pub async fn active_edge_keys(
    executor: impl PgExecutor<'_>,
    hosts: &[String],
) -> Result<Vec<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT public_key FROM grund_relays \
          WHERE role = 'edge' AND state = 'active' AND host = ANY($1) ORDER BY host",
    )
    .bind(hosts)
    .fetch_all(executor)
    .await
}

/// Revokes the active terminator of `role` for `host`, and any unused token
/// for it. Returns how many were revoked (0 or 1).
pub async fn revoke_host(
    executor: impl PgExecutor<'_>,
    role: &str,
    host: &str,
) -> Result<u64, sqlx::Error> {
    let revoked = sqlx::query_scalar::<_, i64>(
        "WITH revoked AS ( \
           UPDATE grund_relays SET state = 'revoked', revoked_at = clock_timestamp() \
            WHERE host = $1 AND state = 'active' AND role = $2 RETURNING relay_id), \
         unused AS ( \
           DELETE FROM grund_relay_tokens WHERE host = $1 AND consumed_at IS NULL AND role = $2) \
         SELECT count(*) FROM revoked",
    )
    .bind(host)
    .bind(role)
    .fetch_one(executor)
    .await?;
    Ok(u64::try_from(revoked).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn enrolling_a_host_again_revokes_the_relay_it_had(pool: PgPool) {
        let (first, second) = (Uuid::now_v7(), Uuid::now_v7());
        for (token, relay_id, key) in [
            ([1u8; 32], first, [1u8; 32]),
            ([2u8; 32], second, [2u8; 32]),
        ] {
            insert_token(&pool, "relay", &token, "relay.example.com", 60.0)
                .await
                .unwrap();
            let mut tx = pool.begin().await.unwrap();
            let row = token_for_update(&mut tx, "relay", &token)
                .await
                .unwrap()
                .unwrap();
            assert!(row.relay_id.is_none());
            enroll(&mut tx, "relay", &token, relay_id, &row.host, &key)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        assert_eq!(relay(&pool, first).await.unwrap().unwrap().state, "revoked");
        assert_eq!(relay(&pool, second).await.unwrap().unwrap().state, "active");
        assert!(key_known(&pool, &[1u8; 32]).await.unwrap());
        let mut tx = pool.begin().await.unwrap();
        let used = token_for_update(&mut tx, "relay", &[2u8; 32])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(used.relay_id, Some(second));
        assert_eq!(used.consumed_key.as_deref(), Some(&[2u8; 32][..]));
        drop(tx);

        insert_token(&pool, "edge", &[3u8; 32], "relay.example.com", 60.0)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(
            token_for_update(&mut tx, "relay", &[3u8; 32])
                .await
                .unwrap()
                .is_none(),
            "an edge's token never enrolls a relay"
        );
        let edge = Uuid::now_v7();
        enroll(
            &mut tx,
            "edge",
            &[3u8; 32],
            edge,
            "relay.example.com",
            &[3u8; 32],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            relay(&pool, second).await.unwrap().unwrap().state,
            "active",
            "an edge on the same host leaves the relay alone"
        );
        assert_eq!(
            active_edge_keys(&pool, &["relay.example.com".to_string()])
                .await
                .unwrap(),
            vec![vec![3u8; 32]]
        );
        assert_eq!(
            revoke_host(&pool, "relay", "relay.example.com")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            revoke_host(&pool, "relay", "relay.example.com")
                .await
                .unwrap(),
            0
        );
        assert_eq!(relay(&pool, edge).await.unwrap().unwrap().state, "active");
        assert!(
            list(&pool, "relay")
                .await
                .unwrap()
                .iter()
                .all(|r| r.state == "revoked")
        );
    }
}
