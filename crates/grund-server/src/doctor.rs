//! `grund doctor instance`: a read-only check of an instance, run where
//! `grund serve` runs and with its settings (`docker compose exec grund
//! /grund doctor instance`). It names each problem and what to do about it
//! (grund-docs design/self-hosted.md §6.4, self-hosting.md "Doctor").
//!
//! Nothing is written: no migration, no key, no certificate order, no mail.
//! The SMTP check connects and says hello, and sends nothing.

use std::{path::Path, time::Duration};

use grund_domain::doctor::{Check, Report};
use grund_store::doctor as store;
use nostatus::CheckStatus;

use crate::{
    certificates::{self, SUBJECT},
    config::{OrganisationMode, ServeConfig},
    db, keys,
    secrets::SecretKey,
};

/// How long doctor waits for PostgreSQL before saying it cannot reach it.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Free space below which the instance's disk is a failure.
pub const DISK_FAIL_BYTES: u64 = 1 << 30;

/// Free space below which the instance's disk is a warning.
pub const DISK_WARN_BYTES: u64 = 5 << 30;

/// Runs every check and returns what it found.
pub async fn run(mut config: ServeConfig) -> Report {
    let mut report = Report::new("instance");
    if let Err(error) = config.validate() {
        report.push(Check::fail(
            "config",
            format!("{error:#}"),
            "set the variable it names (grund serve --help, .env.example); grund serve refuses to start until then",
        ));
        return report;
    }
    report.push(Check::ok(
        "config",
        "grund serve would accept these settings",
    ));

    let secret = secret_key(&config, &mut report);
    let mut database_args = config.database.clone();
    database_args.database_acquire_timeout =
        database_args.database_acquire_timeout.min(CONNECT_TIMEOUT);
    database_args.database_max_connections = 4;
    let pool = match db::connect(&database_args).await {
        Ok(pool) => Some(pool),
        Err(error) => {
            report.push(Check::fail(
                "database",
                format!("{error:#}"),
                "check DATABASE_URL and GRUND_DATABASE_PASSWORD_FILE, and that PostgreSQL runs (docker compose ps postgres)",
            ));
            None
        }
    };
    if let Some(pool) = &pool {
        database(pool, &mut report).await;
        migrations(pool, &mut report).await;
        instance_keys(pool, secret.as_ref(), &mut report).await;
        owner(pool, &config, &mut report).await;
    } else {
        for name in ["migrations", "instance-keys", "owner"] {
            report.push(Check::skip(name, "needs the database"));
        }
    }
    public_url(&config, &mut report);
    certificate(&config, pool.as_ref(), &mut report).await;
    mail(&config, pool.as_ref(), &mut report).await;
    nats(&config, &mut report).await;
    disk(&config, &mut report);
    report
}

fn secret_key(config: &ServeConfig, report: &mut Report) -> Option<SecretKey> {
    if config.secret_key.is_none() && config.secret_key_file.is_none() {
        report.push(Check::warn(
            "secret-key",
            "none configured: a throwaway key is made on every start (GRUND_DEV_MODE)",
            "for an instance people use, set GRUND_SECRET_KEY_FILE (grund init writes it) and turn GRUND_DEV_MODE off",
        ));
        return None;
    }
    match SecretKey::load(config) {
        Ok(secret) => {
            let source = if config.secret_key.is_some() {
                "GRUND_SECRET_KEY".to_string()
            } else {
                config
                    .secret_key_file
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            };
            report.push(Check::ok("secret-key", format!("read from {source}")));
            Some(secret)
        }
        Err(error) => {
            report.push(Check::fail(
                "secret-key",
                format!("{error:#}"),
                "restore the key file from the backup of the grund-data volume; a new key cannot open what the old one sealed",
            ));
            None
        }
    }
}

async fn database(pool: &sqlx::PgPool, report: &mut Report) {
    match store::database(pool).await {
        Ok(db) => report.push(Check::ok(
            "database",
            format!(
                "PostgreSQL {}, {} used",
                db.version,
                bytes(u64::try_from(db.size_bytes).unwrap_or(0))
            ),
        )),
        Err(error) => report.push(Check::fail(
            "database",
            format!("connected, but a query failed: {error}"),
            "check that DATABASE_URL names grund's database and its user may read it",
        )),
    }
}

async fn migrations(pool: &sqlx::PgPool, report: &mut Report) {
    let migrations = match store::migrations(pool).await {
        Ok(migrations) => migrations,
        Err(error) => {
            report.push(Check::fail(
                "migrations",
                format!("could not read them: {error}"),
                "check that DATABASE_URL names grund's database",
            ));
            return;
        }
    };
    let versions = |list: &[i64]| {
        list.iter()
            .map(|v| format!("{v:04}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if !migrations.unknown.is_empty() {
        report.push(Check::fail(
            "migrations",
            format!(
                "the database has migrations this build does not know ({}): a newer grund migrated it",
                versions(&migrations.unknown)
            ),
            "run the newer build again (GRUND_IMAGE); migrations are forward-only, so going back needs the backup taken before the upgrade",
        ));
    } else if !migrations.changed.is_empty() {
        report.push(Check::fail(
            "migrations",
            format!(
                "applied migrations differ from this build's, or failed ({})",
                versions(&migrations.changed)
            ),
            "grund serve refuses to start on this; run the build that applied them, and report it",
        ));
    } else if !migrations.pending.is_empty() {
        report.push(Check::warn(
            "migrations",
            format!(
                "{} of {} applied; {} waiting ({})",
                migrations.applied,
                migrations.known,
                migrations.pending.len(),
                versions(&migrations.pending)
            ),
            "grund serve applies them on start: back up first (self-hosting.md, Backups), then docker compose up -d",
        ));
    } else {
        report.push(Check::ok(
            "migrations",
            format!("{} of {} applied", migrations.applied, migrations.known),
        ));
    }
}

async fn instance_keys(pool: &sqlx::PgPool, secret: Option<&SecretKey>, report: &mut Report) {
    let Some(secret) = secret else {
        report.push(Check::skip(
            "instance-keys",
            "needs a configured secret key",
        ));
        return;
    };
    match keys::Keys::new(std::sync::Arc::new(secret.clone()))
        .mismatched(pool)
        .await
    {
        Ok(mismatched) if mismatched.is_empty() => report.push(Check::ok(
            "instance-keys",
            "the secret key derives every key machines pinned",
        )),
        Ok(mismatched) => report.push(Check::fail(
            "instance-keys",
            format!(
                "{} of the instance's keys do not match the secret key: it changed since they were made",
                mismatched.len()
            ),
            "restore the previous secret key (the grund-data volume's backup); grund serve refuses to start with this one",
        )),
        Err(error) => report.push(Check::skip(
            "instance-keys",
            format!("not readable yet ({error}); grund serve makes them on its first start"),
        )),
    }
}

async fn owner(pool: &sqlx::PgPool, config: &ServeConfig, report: &mut Report) {
    match store::accounts(pool).await {
        Ok(0) if config.organisations == OrganisationMode::Single => report.push(Check::warn(
            "owner",
            "no account yet: the instance has no owner, and sign-up is closed until it has",
            "docker compose exec grund /grund setup-link, then open the link it prints",
        )),
        Ok(count) => report.push(Check::ok(
            "owner",
            match count {
                1 => "1 account".to_string(),
                n => format!("{n} accounts"),
            },
        )),
        Err(error) => report.push(Check::skip("owner", format!("not readable yet ({error})"))),
    }
}

fn public_url(config: &ServeConfig, report: &mut Report) {
    let origin = config.public_origin();
    let url = &origin.serialized;
    let domain = config.tls.domain.as_deref();
    let host = origin.host.as_str();
    let check = match (config.tls.enabled(), origin.https) {
        (true, false) => Check::warn(
            "public-url",
            format!(
                "{url}, but grund serves HTTPS itself: links in mail and the Machines page's command point at plain http"
            ),
            "unset GRUND_PUBLIC_URL (it follows GRUND_DOMAIN) or set it to the https origin",
        ),
        (true, true) if domain.is_some_and(|d| d != host) => Check::warn(
            "public-url",
            format!(
                "{url}, but the certificate is for {}: browsers and machines will refuse it",
                domain.unwrap_or_default()
            ),
            "set GRUND_PUBLIC_URL to https://<GRUND_DOMAIN>, or unset it",
        ),
        (true, true) => Check::ok(
            "public-url",
            format!("{url}, served over HTTPS by grund itself"),
        ),
        (false, true) if config.trusted_proxy_hops == 0 => Check::warn(
            "public-url",
            format!(
                "{url}, terminated in front of grund, with GRUND_TRUSTED_PROXY_HOPS=0: every request looks like the proxy's"
            ),
            "set GRUND_TRUSTED_PROXY_HOPS to the number of proxies in front, or turn the per-address limits off",
        ),
        (false, true) => Check::ok(
            "public-url",
            format!(
                "{url}, terminated in front of grund ({} proxy hops trusted)",
                config.trusted_proxy_hops
            ),
        ),
        (false, false) if origin.is_loopback() => Check::warn(
            "public-url",
            format!("{url}: only this machine can reach it, so no other machine can join"),
            "for machines on other hosts, set GRUND_DOMAIN (self-hosting.md, HTTPS)",
        ),
        (false, false) => Check::warn(
            "public-url",
            format!("{url}: plain http on a network address, allowed only by GRUND_DEV_MODE"),
            "set GRUND_DOMAIN, and turn GRUND_DEV_MODE off",
        ),
    };
    report.push(check);
}

async fn certificate(config: &ServeConfig, pool: Option<&sqlx::PgPool>, report: &mut Report) {
    let tls = &config.tls;
    if let (Some(cert), Some(key)) = (&tls.tls_cert_file, &tls.tls_key_file) {
        let resolver = grund_tls::Resolver::default();
        let loaded = grund_tls::Files::new(cert, key).reload_if_changed(&resolver);
        let check = match (loaded, resolver.current()) {
            (Ok(_), Some(served)) => expiry(
                &served.names.join(", "),
                served.not_before,
                served.not_after,
                "replace GRUND_TLS_CERT_FILE and GRUND_TLS_KEY_FILE; grund re-reads them when they change",
            ),
            (Err(error), _) => Check::fail(
                "certificate",
                format!("GRUND_TLS_CERT_FILE and GRUND_TLS_KEY_FILE: {error:#}"),
                "give grund a PEM chain (leaf first) and its key, readable by uid 65532",
            ),
            (Ok(_), None) => Check::fail(
                "certificate",
                "the files hold no certificate",
                "give grund a PEM chain (leaf first) and its key",
            ),
        };
        report.push(check);
        return;
    }
    let Some(domain) = tls.domain.as_deref() else {
        report.push(Check::skip(
            "certificate",
            "no GRUND_DOMAIN or GRUND_TLS_CERT_FILE: grund serves no HTTPS",
        ));
        return;
    };
    let Some(pool) = pool else {
        report.push(Check::skip("certificate", "needs the database"));
        return;
    };
    let fix_order = format!(
        "{domain} must point at this machine and 443 must reach it from the internet (TLS-ALPN-01); docker compose logs grund says what the CA answered"
    );
    let check = match store::certificate(pool, SUBJECT).await {
        Err(error) => Check::skip(
            "certificate",
            format!("not readable yet ({error}); grund serve records it on start"),
        ),
        Ok(None) => Check::warn(
            "certificate",
            format!("none recorded for {domain} yet"),
            "start grund serve: it records what to order, then orders it",
        ),
        Ok(Some(row)) => match (row.not_before, row.not_after) {
            (Some(not_before), Some(not_after)) if row.names.iter().any(|n| n == domain) => {
                let mut check = expiry(
                    &row.names.join(", "),
                    not_before.into(),
                    not_after.into(),
                    &fix_order,
                );
                if check.status == grund_domain::doctor::Status::Ok
                    && let Some(renew_at) = row.renew_at
                {
                    check.detail = format!(
                        "{}; renewal from {}",
                        check.detail,
                        renew_at.format("%Y-%m-%d")
                    );
                }
                if row.attempts > 0 {
                    check = Check::warn(
                        "certificate",
                        format!(
                            "{}; renewal failed {} times (last error: {})",
                            check.detail,
                            row.attempts,
                            row.last_error.as_deref().unwrap_or("unknown")
                        ),
                        fix_order.clone(),
                    );
                }
                check
            }
            (Some(_), Some(_)) => Check::warn(
                "certificate",
                format!(
                    "stored for {}, not {domain}; a new one is ordered",
                    row.names.join(", ")
                ),
                "wait for the order; docker compose logs grund shows it",
            ),
            _ => Check::fail(
                "certificate",
                format!(
                    "no certificate for {domain} yet: {} attempts, last error {}, next at {}",
                    row.attempts,
                    row.last_error.as_deref().unwrap_or("none"),
                    row.next_attempt_at.format("%Y-%m-%d %H:%M:%S UTC")
                ),
                fix_order,
            ),
        },
    };
    report.push(check);
}

fn expiry(
    names: &str,
    not_before: std::time::SystemTime,
    not_after: std::time::SystemTime,
    fix: &str,
) -> Check {
    let until = chrono::DateTime::<chrono::Utc>::from(not_after).format("%Y-%m-%d");
    match certificates::expiry_status(not_before, not_after, std::time::SystemTime::now()) {
        CheckStatus::Healthy => Check::ok("certificate", format!("{names}, valid until {until}")),
        CheckStatus::Degraded => Check::warn(
            "certificate",
            format!("{names} expires soon, on {until}"),
            fix,
        ),
        CheckStatus::Unhealthy => {
            Check::fail("certificate", format!("{names} expired on {until}"), fix)
        }
    }
}

async fn mail(config: &ServeConfig, pool: Option<&sqlx::PgPool>, report: &mut Report) {
    let waiting = match pool {
        Some(pool) => store::mail(pool).await.ok(),
        None => None,
    };
    let pending = waiting.as_ref().map_or(0, |w| w.pending);
    let Some(url) = &config.smtp_url else {
        report.push(Check::warn(
            "mail",
            format!(
                "GRUND_SMTP_URL is unset: password reset and invitations cannot be mailed ({pending} waiting)"
            ),
            "set GRUND_SMTP_URL to your provider (.env.example, mail); waiting mail goes out once it is",
        ));
        return;
    };
    use lettre::{AsyncSmtpTransport, Tokio1Executor};
    let transport: AsyncSmtpTransport<Tokio1Executor> =
        match AsyncSmtpTransport::<Tokio1Executor>::from_url(url) {
            Ok(builder) => builder.timeout(Some(Duration::from_secs(10))).build(),
            Err(_) => {
                report.push(Check::fail(
                    "mail",
                    "GRUND_SMTP_URL is not a valid SMTP URL",
                    "smtp://user:password@host:587?tls=required, or smtps://…:465",
                ));
                return;
            }
        };
    let answered = transport.test_connection().await;
    let check = match (answered, &waiting) {
        (Ok(true), Some(w)) if w.failing > 0 => Check::warn(
            "mail",
            format!(
                "the SMTP server answers, but {} of {pending} waiting mails failed before (last error: {})",
                w.failing,
                w.last_error.as_deref().unwrap_or("unknown")
            ),
            "check the provider's account and GRUND_MAIL_FROM; grund retries with backoff",
        ),
        (Ok(true), _) => Check::ok(
            "mail",
            format!("the SMTP server answers; {pending} waiting"),
        ),
        (Ok(false), _) => Check::fail(
            "mail",
            "the SMTP server did not accept a connection",
            "check GRUND_SMTP_URL's host, port and TLS mode",
        ),
        (Err(error), _) => Check::fail(
            "mail",
            format!("cannot reach the SMTP server: {}", smtp_error(&error)),
            "check GRUND_SMTP_URL's host, port, TLS mode and credentials; mail waits until it works",
        ),
    };
    report.push(check);
}

fn smtp_error(error: &lettre::transport::smtp::Error) -> &'static str {
    if error.is_timeout() {
        "timed out"
    } else if error.is_tls() {
        "TLS failed"
    } else if error.is_permanent() {
        "refused"
    } else if error.is_transient() {
        "temporarily refused"
    } else {
        "connection failed"
    }
}

async fn nats(config: &ServeConfig, report: &mut Report) {
    let Some(url) = &config.nats_url else {
        report.push(Check::skip(
            "nats",
            "not configured: background work is found by polling",
        ));
        return;
    };
    let mut options = async_nats::ConnectOptions::new()
        .name("grund-doctor")
        .connection_timeout(Duration::from_secs(5));
    if let Some(path) = &config.nats_creds_file {
        options = match options.credentials_file(path).await {
            Ok(options) => options,
            Err(error) => {
                report.push(Check::fail(
                    "nats",
                    format!("GRUND_NATS_CREDS_FILE: {error}"),
                    "check the credentials file",
                ));
                return;
            }
        };
    }
    let connected =
        tokio::time::timeout(Duration::from_secs(6), options.connect(url.as_str())).await;
    report.push(match connected {
        Ok(Ok(_)) => Check::ok("nats", "connected"),
        _ => Check::fail(
            "nats",
            "cannot connect to GRUND_NATS_URL; grund serve refuses to start without it",
            "start NATS (docker compose ps nats), or unset GRUND_NATS_URL to poll instead",
        ),
    });
}

fn disk(config: &ServeConfig, report: &mut Report) {
    let path = config
        .secret_key_file
        .as_deref()
        .and_then(Path::parent)
        .unwrap_or(Path::new("/"));
    let Some(free) = free_bytes(path) else {
        report.push(Check::skip(
            "disk",
            format!("cannot read the free space of {}", path.display()),
        ));
        return;
    };
    let detail = format!(
        "{} free on the filesystem of {}",
        bytes(free),
        path.display()
    );
    let fix =
        "free space on the Docker host: PostgreSQL stops accepting writes when its disk is full";
    report.push(if free < DISK_FAIL_BYTES {
        Check::fail("disk", detail, fix)
    } else if free < DISK_WARN_BYTES {
        Check::warn("disk", detail, fix)
    } else {
        Check::ok("disk", detail)
    });
}

/// Free bytes for an unprivileged writer on the filesystem holding `path`.
pub fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    Some(stat.f_bavail.saturating_mul(stat.f_frsize))
}

/// A size for people: GiB, MiB or KiB with one decimal.
pub fn bytes(n: u64) -> String {
    let n = n as f64;
    if n >= (1u64 << 30) as f64 {
        format!("{:.1} GiB", n / (1u64 << 30) as f64)
    } else if n >= (1u64 << 20) as f64 {
        format!("{:.1} MiB", n / (1u64 << 20) as f64)
    } else {
        format!("{:.1} KiB", n / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_in_the_largest_whole_unit() {
        assert_eq!(bytes(3 << 30), "3.0 GiB");
        assert_eq!(bytes(1536 << 10), "1.5 MiB");
        assert_eq!(bytes(2048), "2.0 KiB");
    }

    #[test]
    fn the_root_filesystem_has_a_free_space() {
        assert!(free_bytes(Path::new("/")).is_some());
        assert!(free_bytes(Path::new("/no/such/path/for/grund")).is_none());
    }
}
