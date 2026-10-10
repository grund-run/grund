//! Operator-only organisation inventory for hosted access.

use sqlx::{FromRow, PgExecutor};

/// One live organisation and its hosted-machine access decision.
#[derive(Debug, FromRow)]
pub struct HostedOrganisation {
    pub slug: String,
    pub enabled: bool,
}

/// Live organisations, including those for which access has never been granted.
pub async fn hosted_organisations(
    executor: impl PgExecutor<'_>,
) -> Result<Vec<HostedOrganisation>, sqlx::Error> {
    sqlx::query_as(
        "SELECT o.slug, COALESCE(e.enabled, false) AS enabled \
         FROM grund_organisations o \
         LEFT JOIN grund_hosted_entitlements e ON e.organisation_id = o.organisation_id \
         WHERE o.deleted_at IS NULL ORDER BY o.slug",
    )
    .fetch_all(executor)
    .await
}
