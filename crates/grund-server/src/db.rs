//! Opening the PostgreSQL pool.

use std::str::FromStr;

use anyhow::Context;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::config::DatabaseArgs;

/// Connects with the configured bounds: a pool that never waits longer than
/// `acquire_timeout` for a connection, and a `statement_timeout` on every
/// connection, so one stuck statement cannot hold a request forever.
pub async fn connect(args: &DatabaseArgs) -> anyhow::Result<PgPool> {
    let mut options = PgConnectOptions::from_str(&args.database_url)
        .context("DATABASE_URL is not a valid PostgreSQL URL")?
        .application_name("grund")
        .options([(
            "statement_timeout",
            format!("{}", args.database_statement_timeout.as_millis()),
        )]);
    if let Some(path) = &args.database_password_file {
        let password = std::fs::read_to_string(path)
            .with_context(|| format!("read GRUND_DATABASE_PASSWORD_FILE {}", path.display()))?;
        options = options.password(password.trim_end_matches(['\n', '\r']));
    }
    PgPoolOptions::new()
        .max_connections(args.database_max_connections)
        .acquire_timeout(args.database_acquire_timeout)
        .connect_with(options)
        .await
        .context("connect to PostgreSQL (DATABASE_URL)")
}
