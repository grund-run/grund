//! Custom domains (grund-docs website/design/app-domains.md §3,
//! design/traffic.md §3.2, §5.3): an organisation adds a name it owns,
//! proves it with a TXT record at `_grund.<name>` holding a token grund
//! made, binds it to one of its apps, and the edges serve the app on it
//! with a certificate the instance orders.
//!
//! - **Who holds a name.** One organisation at a time, from verification
//!   until it removes the name (the read model's unique index decides a
//!   race). A name that was verified and then removed cools down for
//!   GRUND_DOMAIN_COOLDOWN before another organisation can add or verify it;
//!   the organisation that released it can take it back at once.
//! - **What is never a custom domain**: a name on the instance's app domain
//!   (GRUND_APP_DOMAIN, whose addresses grund gives out), the instance's own
//!   domain, and the edges' hosts.
//! - **The certificate** exists while the domain is bound: the
//!   organisation's, its key made and sealed here, ordered by the
//!   certificates worker and validated by HTTP-01 at the edges, which take
//!   the key and chain from [`Domains::certificate_for_edge`].
//! - **Machines** learn a bound name as one of the app's hostnames in their
//!   signed documents, committed with the binding, so the gate admits it.

use std::{net::SocketAddr, time::Duration};

use chrono::{DateTime, Utc};
use grund_domain::{
    custom_domain::{DomainCommand, DomainError, DomainName, DomainNameError},
    organisation::Role,
};
use grund_store::{
    domains::{self, DomainRow},
    organisations::Membership,
    work::{Work, WorkError},
};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    services::{agents::AgentsState, apps::lock_app_domain_policy, entry::publishes},
    state::State,
};

/// Domains one organisation may hold, removed ones not counted
/// (traffic.md §13).
pub const MAX_PER_ORGANISATION: i64 = 50;

/// Domains one organisation may add in a day: new orders share one ACME
/// account's 300 per 3 hours (traffic.md §5.5, §13).
pub const MAX_ADDED_PER_DAY: i64 = 20;

/// Custom domains bound to one app (traffic.md §13).
pub const MAX_PER_APP: i64 = 10;

/// How long one TXT lookup may take.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Where a domain is, as the dashboard says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Added; its TXT record has not been found yet.
    Pending,
    /// Proved; not bound to an app.
    Verified,
    /// Bound; its certificate is on its way, or this instance orders none.
    Bound,
    /// Bound with an issued certificate; setup steps report actual HTTPS observations.
    Issued,
    /// The last verification check or certificate order failed.
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Verified => "verified",
            Status::Bound => "bound",
            Status::Issued => "issued",
            Status::Error => "error",
        }
    }
}

/// A custom domain as the page and the API show it.
#[derive(Debug, Clone)]
pub struct DomainView {
    pub name: String,
    pub status: Status,
    /// `pending`, `verified` or `bound`: the read model's state.
    pub state: String,
    /// The TXT record that proves it: its name and value.
    pub txt_name: String,
    pub txt_value: String,
    pub app_name: Option<String>,
    pub is_app_domain: bool,
    pub parent_domain: Option<String>,
    pub managed_app_name: Option<String>,
    pub added_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub bound_at: Option<DateTime<Utc>>,
    pub certificate_not_after: Option<DateTime<Utc>>,
    /// What went wrong last, in words, when `status` is `Error`.
    pub problem: Option<String>,
    pub steps: Vec<grund_store::domain_setup::Step>,
    pub certificate_attempts: i32,
    pub certificate_next_attempt_at: Option<DateTime<Utc>>,
}

fn view(row: DomainRow) -> DomainView {
    let name = DomainName::parse(&row.name).ok();
    let check_problem = row.check_error.as_deref().map(check_words);
    let certificate_problem = row
        .certificate_error
        .as_deref()
        .map(|code| certificate_words(code, &row.name));
    let status = match row.state.as_str() {
        "pending" if check_problem.is_some() => Status::Error,
        "pending" => Status::Pending,
        "verified" => Status::Verified,
        "bound" if row.app_name.is_none() => Status::Error,
        "bound" if row.certificate_not_after.is_some() => Status::Issued,
        "bound" if certificate_problem.is_some() => Status::Error,
        _ => Status::Bound,
    };
    let problem = match status {
        Status::Error if row.state == "pending" => check_problem,
        Status::Error if row.app_name.is_none() => {
            Some("The app it was bound to is gone; bind it to another or remove it.".into())
        }
        Status::Error => certificate_problem,
        _ => None,
    };
    DomainView {
        txt_name: if row.parent_domain.is_some() {
            String::new()
        } else {
            name.as_ref()
                .map(DomainName::verification_name)
                .unwrap_or_default()
        },
        txt_value: if row.parent_domain.is_some() {
            String::new()
        } else {
            row.token
        },
        is_app_domain: row.is_app_domain,
        parent_domain: row.parent_domain,
        name: row.name,
        status,
        state: row.state,
        app_name: row.app_name,
        managed_app_name: row.managed_app_name,
        added_at: row.added_at,
        verified_at: row.verified_at,
        bound_at: row.bound_at,
        certificate_not_after: row.certificate_not_after,
        steps: if row.steps.0.is_empty() {
            grund_store::domain_setup::waiting_steps()
        } else {
            row.steps.0
        },
        certificate_attempts: row.certificate_attempts,
        certificate_next_attempt_at: row.certificate_next_attempt_at,
        problem,
    }
}

fn check_words(code: &str) -> String {
    match code {
        "no_record" => "No TXT record was found at that name yet. DNS changes can take a few minutes to appear.",
        "wrong_value" => "A TXT record is there, but it does not hold this domain's value.",
        _ => "grund could not ask DNS for the record. Try again in a minute.",
    }
    .into()
}

fn certificate_words(code: &str, name: &str) -> String {
    match code {
        "authorization_failed" => format!(
            "The certificate authority did not validate {name}. Check its domain record and port 80 access to grund's edge."
        ),
        "acme_rate_limited" => {
            "The certificate authority is limiting new certificates; grund tries again later."
                .into()
        }
        "acme_unreachable" => {
            "The certificate authority did not answer; grund tries again later.".into()
        }
        _ => "The certificate could not be ordered yet; grund tries again later.".into(),
    }
}

/// Why a domain call was refused. Each maps to a stable reason.
#[derive(Debug, thiserror::Error)]
pub enum DomainsError {
    #[error("no such domain")]
    NotFound,
    #[error("only owners and admins change an organisation's domains")]
    NotAllowed,
    #[error("{0}")]
    Invalid(#[from] DomainNameError),
    #[error("{0} is grund's own; it cannot be a custom domain")]
    Reserved(String),
    #[error("this organisation already has that domain")]
    Exists,
    #[error("another organisation on this grund holds that domain")]
    Taken,
    #[error("that domain was released recently; it can be added again after {0}")]
    CoolingDown(DateTime<Utc>),
    #[error("an organisation has at most {MAX_PER_ORGANISATION} domains")]
    Limit,
    #[error("an organisation adds at most {MAX_ADDED_PER_DAY} domains a day")]
    DailyLimit,
    #[error("the domain is not verified yet")]
    NotVerified,
    #[error("{0}")]
    VerificationFailed(String),
    #[error("no such app")]
    AppNotFound,
    #[error("that app has no public HTTP port to serve a domain on")]
    AppNotPublic,
    #[error("make the app private or bind another domain before removing its last public domain")]
    LastPublicDomain,
    #[error("an app has at most {MAX_PER_APP} custom domains")]
    AppLimit,
    #[error("{0}")]
    NamespaceConflict(String),
    #[error("configure a verified organisation app domain first")]
    AppDomainRequired,
    #[error(
        "an app subdomain must be one lowercase DNS label, 1–63 letters, digits or hyphens, without a leading or trailing hyphen"
    )]
    InvalidSubdomain,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl DomainsError {
    /// The stable machine reason.
    pub fn reason(&self) -> &'static str {
        match self {
            DomainsError::NotFound => "not_found",
            DomainsError::NotAllowed => "permission_denied",
            DomainsError::Invalid(_) => "name_invalid",
            DomainsError::Reserved(_) => "name_reserved",
            DomainsError::Exists => "domain_exists",
            DomainsError::Taken => "domain_taken",
            DomainsError::CoolingDown(_) => "domain_cooling_down",
            DomainsError::Limit => "domain_limit",
            DomainsError::DailyLimit => "domain_rate_limited",
            DomainsError::NotVerified => "not_verified",
            DomainsError::VerificationFailed(_) => "verification_failed",
            DomainsError::AppNotFound => "app_not_found",
            DomainsError::AppNotPublic => "app_not_public",
            DomainsError::LastPublicDomain => "last_public_domain",
            DomainsError::AppLimit => "app_domain_limit",
            DomainsError::NamespaceConflict(_) => "namespace_conflict",
            DomainsError::AppDomainRequired => "app_domain_required",
            DomainsError::InvalidSubdomain => "subdomain_invalid",
            DomainsError::Internal(_) => "internal",
        }
    }
}

impl From<WorkError> for DomainsError {
    fn from(error: WorkError) -> Self {
        match error.unique_violation().as_deref() {
            Some("grund_domains_claimed_idx") => return DomainsError::Taken,
            Some("grund_domains_name_idx") => return DomainsError::Exists,
            Some("grund_domains_app_domain_idx" | "grund_domains_managed_assignment_idx") => {
                return DomainsError::NamespaceConflict(
                    "the organisation's app-domain assignment changed; retry the request".into(),
                );
            }
            _ => {}
        }
        match error {
            WorkError::Domain(DomainError::NotFound) => DomainsError::NotFound,
            WorkError::Domain(DomainError::NotVerified) => DomainsError::NotVerified,
            WorkError::Domain(DomainError::AlreadyExists) => DomainsError::Exists,
            WorkError::Domain(DomainError::InvalidAuthority) => DomainsError::NotVerified,
            WorkError::Domain(DomainError::ManagedAppMismatch) => DomainsError::NamespaceConflict(
                "a generated app address cannot be moved to another app; change its subdomain instead".into(),
            ),
            WorkError::Domain(DomainError::InvalidGeneratedName) => DomainsError::InvalidSubdomain,
            other => DomainsError::Internal(other.into()),
        }
    }
}

impl From<sqlx::Error> for DomainsError {
    fn from(error: sqlx::Error) -> Self {
        DomainsError::Internal(error.into())
    }
}

/// What a TXT lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Found,
    /// A stable code: `no_record`, `wrong_value` or `lookup_failed`.
    Missing(&'static str),
}

/// Looks for `token` among the TXT records at `name`, asking `server` or
/// the system's resolvers. A fresh resolver each time, so a record the
/// customer just added is not hidden by a cached answer from before.
pub async fn lookup_txt(server: Option<SocketAddr>, name: &str, token: &str) -> Lookup {
    use hickory_resolver::{
        Resolver,
        config::{ConnectionConfig, NameServerConfig, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
    };
    let builder = match server {
        Some(server) => {
            let connection = |mut config: ConnectionConfig| {
                config.port = server.port();
                config
            };
            let name_server = NameServerConfig::new(
                server.ip(),
                true,
                vec![
                    connection(ConnectionConfig::udp()),
                    connection(ConnectionConfig::tcp()),
                ],
            );
            Ok(Resolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![name_server]),
                TokioRuntimeProvider::default(),
            ))
        }
        None => Resolver::builder_tokio(),
    };
    let resolver = match builder.and_then(|mut builder| {
        builder.options_mut().cache_size = 0;
        builder.options_mut().timeout = Duration::from_secs(2);
        builder.build()
    }) {
        Ok(resolver) => resolver,
        Err(error) => {
            tracing::warn!(%error, "domains: could not make a DNS resolver");
            return Lookup::Missing("lookup_failed");
        }
    };
    let fqdn = format!("{}.", name.trim_end_matches('.'));
    let answer = tokio::time::timeout(LOOKUP_TIMEOUT, resolver.txt_lookup(fqdn)).await;
    match answer {
        Ok(Ok(lookup)) => {
            let values: Vec<String> = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    hickory_resolver::proto::rr::RData::TXT(txt) => Some(
                        txt.txt_data
                            .iter()
                            .map(|part| String::from_utf8_lossy(part).into_owned())
                            .collect::<String>(),
                    ),
                    _ => None,
                })
                .collect();
            if values.iter().any(|value| value.trim() == token) {
                Lookup::Found
            } else if values.is_empty() {
                Lookup::Missing("no_record")
            } else {
                Lookup::Missing("wrong_value")
            }
        }
        Ok(Err(error)) if error.is_no_records_found() || error.is_nx_domain() => {
            Lookup::Missing("no_record")
        }
        Ok(Err(error)) => {
            tracing::info!(%name, %error, "domains: TXT lookup failed");
            Lookup::Missing("lookup_failed")
        }
        Err(_) => Lookup::Missing("lookup_failed"),
    }
}

/// A fresh verification token: `grund-verify-` and 32 random bytes in
/// base62.
pub fn new_token() -> String {
    format!("grund-verify-{}", crate::crypto::random_base62())
}

/// Custom domains' flows.
#[derive(Clone)]
pub struct Domains {
    state: State,
}

fn manages(membership: &Membership) -> bool {
    Role::parse(&membership.role).is_some_and(Role::manages_members)
}

fn app_hostname(label: &str, parent: &str) -> Result<DomainName, DomainsError> {
    if !(1..=63).contains(&label.len())
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || matches!(label, "_grund" | "_acme-challenge" | "*")
    {
        return Err(DomainsError::InvalidSubdomain);
    }
    Ok(DomainName::parse(&format!("{label}.{parent}"))?)
}

impl Domains {
    fn reserved(&self, name: &DomainName) -> Option<String> {
        let config = &self.state.config;
        let mut parents: Vec<String> = Vec::new();
        parents.extend(config.entry.app_domain.clone());
        parents.extend(config.tls.domain.clone());
        parents.extend(config.entry.edges.iter().cloned());
        if let Some(origin) = config
            .public_url
            .as_deref()
            .and_then(crate::config::PublicOrigin::parse)
        {
            parents.push(origin.host);
        }
        parents.into_iter().find(|parent| name.is_within(parent))
    }

    /// The organisation's domains, by name.
    pub async fn list(&self, organisation_id: Uuid) -> Result<Vec<DomainView>, DomainsError> {
        Ok(domains::list(&self.state.pool, organisation_id)
            .await?
            .into_iter()
            .map(view)
            .collect())
    }

    /// The organisation's domain `name`.
    pub async fn get(&self, organisation_id: Uuid, name: &str) -> Result<DomainView, DomainsError> {
        self.row(organisation_id, name).await.map(view)
    }

    /// Schedules a bound domain's setup checks now, or verifies its ownership record.
    pub async fn check_now(
        &self,
        actor: Uuid,
        membership: &Membership,
        name: &str,
    ) -> Result<DomainView, DomainsError> {
        if !manages(membership) {
            return Err(DomainsError::NotAllowed);
        }
        let row = self.row(membership.organisation_id, name).await?;
        if row.state == "pending" {
            return self.verify(actor, membership, name).await;
        }
        if row.state == "bound" {
            grund_store::domain_setup::request_check(&self.state.pool, row.domain_id).await?;
        }
        self.get(membership.organisation_id, name).await
    }

    /// The domains bound to an app.
    pub async fn of_app(&self, app_id: Uuid) -> Result<Vec<DomainView>, DomainsError> {
        Ok(domains::bound_to(&self.state.pool, app_id)
            .await?
            .into_iter()
            .map(view)
            .collect())
    }

    async fn row(&self, organisation_id: Uuid, name: &str) -> Result<DomainRow, DomainsError> {
        let Ok(name) = DomainName::parse(name) else {
            return Err(DomainsError::NotFound);
        };
        domains::by_name(&self.state.pool, organisation_id, name.as_str())
            .await?
            .ok_or(DomainsError::NotFound)
    }

    async fn lock_binding(
        &self,
        work: &mut Work<'_>,
        initial: &DomainRow,
    ) -> Result<DomainRow, DomainsError> {
        domains::lock_hierarchy_policy(&mut **work.sql()).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("grund-domain-binding:{}", initial.domain_id))
            .execute(&mut **work.sql())
            .await?;
        domains::by_name(&mut **work.sql(), initial.organisation_id, &initial.name)
            .await?
            .filter(|row| row.domain_id == initial.domain_id)
            .ok_or(DomainsError::NotFound)
    }

    async fn lock_apps(
        &self,
        work: &mut Work<'_>,
        app_ids: &mut [Uuid],
    ) -> Result<(), DomainsError> {
        app_ids.sort_unstable();
        for (index, app_id) in app_ids.iter().enumerate() {
            if index == 0 || *app_id != app_ids[index - 1] {
                lock_app_domain_policy(work.sql(), *app_id).await?;
            }
        }
        Ok(())
    }

    async fn held_elsewhere(
        &self,
        connection: &mut PgConnection,
        organisation_id: Uuid,
        name: &DomainName,
    ) -> Result<(), DomainsError> {
        if domains::holder(&mut *connection, name.as_str())
            .await?
            .is_some_and(|holder| holder != organisation_id)
        {
            return Err(DomainsError::Taken);
        }
        if let Some(until) = domains::cooling_until(
            &mut *connection,
            name.as_str(),
            organisation_id,
            self.state.config.entry.domain_cooldown as f64,
        )
        .await?
        {
            return Err(DomainsError::CoolingDown(until));
        }
        if domains::foreign_namespace_overlap(
            &mut *connection,
            organisation_id,
            name.as_str(),
            false,
        )
        .await?
        {
            return Err(DomainsError::NamespaceConflict(
                "another organisation owns the app-domain namespace above this name".into(),
            ));
        }
        Ok(())
    }

    /// Enables a verified name as the organisation's app-address namespace.
    pub async fn configure_app_domain(
        &self,
        actor: Uuid,
        membership: &Membership,
        name: &str,
    ) -> Result<DomainView, DomainsError> {
        if !manages(membership) {
            return Err(DomainsError::NotAllowed);
        }
        let initial = self.row(membership.organisation_id, name).await?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let row = self.lock_binding(&mut work, &initial).await?;
        if row.verified_at.is_none() {
            return Err(DomainsError::NotVerified);
        }
        if row.parent_domain_id.is_some() {
            return Err(DomainsError::NamespaceConflict(
                "a generated app address cannot itself be an app domain".into(),
            ));
        }
        if let Some(parent) =
            domains::configured_parent(&mut **work.sql(), membership.organisation_id).await?
            && parent.domain_id != row.domain_id
        {
            return Err(DomainsError::NamespaceConflict(
                "release the current app domain's generated addresses and remove it before choosing another".into(),
            ));
        }
        let name = DomainName::parse(&row.name)?;
        if let Some(parent) = self.reserved(&name) {
            return Err(DomainsError::Reserved(parent));
        }
        self.held_elsewhere(work.sql(), membership.organisation_id, &name)
            .await?;
        if domains::foreign_namespace_overlap(
            &mut **work.sql(),
            membership.organisation_id,
            &row.name,
            true,
        )
        .await?
        {
            return Err(DomainsError::NamespaceConflict(
                "another organisation holds a verified name inside this app-domain namespace"
                    .into(),
            ));
        }
        work.domain(
            row.domain_id,
            DomainCommand::EnableAppDomain {
                actor,
                at: Utc::now(),
            },
        )
        .await?;
        let apps =
            grund_store::apps::organisation_apps(&mut **work.sql(), membership.organisation_id)
                .await?;
        for app in &apps {
            self.allocate_app_domain_in(
                &mut work,
                actor,
                membership.organisation_id,
                app.app_id,
                &app.name,
            )
            .await?;
        }
        work.commit().await?;
        self.state.wakes.documents_changed();
        self.get(membership.organisation_id, &row.name).await
    }

    /// Reserves an app's default address inside its creation or restoration transaction.
    pub async fn allocate_app_domain_in(
        &self,
        work: &mut Work<'_>,
        actor: Uuid,
        organisation_id: Uuid,
        app_id: Uuid,
        _app_name: &str,
    ) -> Result<(), DomainsError> {
        domains::lock_hierarchy_policy(&mut **work.sql()).await?;
        let Some(app_name) = grund_store::entry::public_name(&mut **work.sql(), app_id).await?
        else {
            return Ok(());
        };
        let Some(parent) = domains::configured_parent(&mut **work.sql(), organisation_id).await?
        else {
            return Ok(());
        };
        if let Some(existing) =
            domains::managed_assignment(&mut **work.sql(), organisation_id, app_id).await?
        {
            if existing.assignment_disabled || existing.state == "removed" {
                return Ok(());
            }
            if existing.parent_domain_id != Some(parent.domain_id) {
                return Err(DomainsError::NamespaceConflict(
                    "release the app's previous generated address before changing its parent"
                        .into(),
                ));
            }
            if existing.app_id == Some(app_id) && existing.state == "bound" {
                return Ok(());
            }
            let existing = self.lock_binding(work, &existing).await?;
            self.lock_apps(work, &mut [app_id]).await?;
            if domains::count_bound(&mut **work.sql(), app_id).await? >= MAX_PER_APP {
                return Err(DomainsError::AppLimit);
            }
            work.domain(
                existing.domain_id,
                DomainCommand::Bind {
                    actor,
                    app_id,
                    at: Utc::now(),
                },
            )
            .await?;
            self.want_public_certificate(
                work.sql(),
                existing.domain_id,
                organisation_id,
                app_id,
                &existing.name,
            )
            .await?;
        } else {
            self.lock_apps(work, &mut [app_id]).await?;
            let name = app_hostname(&app_name, &parent.name)?;
            self.generate_in(work, actor, organisation_id, app_id, name, &parent)
                .await?;
        }
        self.publish_apps(work.sql(), &[app_id]).await?;
        Ok(())
    }

    /// Moves the stack's real public bindings when its selected child changes.
    /// The caller commits this with RevisionRequested and wakes documents.
    #[allow(clippy::too_many_arguments)]
    pub async fn rebind_stack_public_in(
        &self,
        work: &mut Work<'_>,
        actor: Uuid,
        organisation_id: Uuid,
        stack_id: Uuid,
        previous: Option<Uuid>,
        selected: Option<Uuid>,
        stack_name: &str,
    ) -> Result<(), DomainsError> {
        domains::lock_hierarchy_policy(&mut **work.sql()).await?;
        let stack = work.load_stack(stack_id).await?;
        if stack.organisation_id != organisation_id || stack.name != stack_name {
            return Err(DomainsError::NotFound);
        }
        let public = stack
            .revisions
            .get(&stack.desired_revision)
            .and_then(|revision| {
                revision
                    .public_service
                    .as_ref()
                    .and_then(|name| revision.services.get(name))
                    .map(|service| service.app_id)
            });
        if public != selected {
            return Err(DomainsError::NamespaceConflict(
                "the stack's public service changed".into(),
            ));
        }
        let members =
            grund_store::stacks::members(&mut **work.sql(), organisation_id, stack_id).await?;
        let mut apps: Vec<_> = members.iter().map(|member| member.app_id).collect();
        apps.sort_unstable();
        if previous
            .into_iter()
            .chain(selected)
            .any(|id| !apps.contains(&id))
        {
            return Err(DomainsError::NamespaceConflict(
                "public bindings require the same owning stack".into(),
            ));
        }
        self.lock_apps(work, &mut apps).await?;
        for app_id in apps.iter().copied() {
            let app = work.load_app(app_id).await?;
            if app.organisation_id != organisation_id || app.stack_owner != Some(stack_id) {
                return Err(DomainsError::NamespaceConflict(
                    "public bindings require the same owning stack".into(),
                ));
            }
        }
        let Some(selected) = selected else {
            self.publish_apps(work.sql(), &apps).await?;
            return Ok(());
        };
        let rows = domains::list(&mut **work.sql(), organisation_id).await?;
        let sources: Vec<_> = rows
            .into_iter()
            .filter(|row| {
                row.managed_app_id
                    .or(row.app_id)
                    .is_some_and(|id| id != selected && apps.contains(&id))
            })
            .collect();
        let moved_bound = sources.iter().filter(|row| row.app_id.is_some()).count() as i64;
        if domains::count_bound(&mut **work.sql(), selected).await? + moved_bound > MAX_PER_APP {
            return Err(DomainsError::AppLimit);
        }
        for row in sources {
            let row = self.lock_binding(work, &row).await?;
            if let Some(owner) = row.managed_app_id {
                work.domain(
                    row.domain_id,
                    DomainCommand::ReassignGenerated {
                        actor,
                        expected_app_id: owner,
                        app_id: selected,
                        at: Utc::now(),
                    },
                )
                .await?;
            } else if row.app_id.is_some() {
                work.domain(
                    row.domain_id,
                    DomainCommand::Bind {
                        actor,
                        app_id: selected,
                        at: Utc::now(),
                    },
                )
                .await?;
            }
        }
        self.allocate_app_domain_in(work, actor, organisation_id, selected, stack_name)
            .await?;
        self.publish_apps(work.sql(), &apps).await?;
        Ok(())
    }

    /// Atomically replaces an app's generated address with a chosen single label.
    pub async fn set_app_subdomain(
        &self,
        actor: Uuid,
        membership: &Membership,
        app_name: &str,
        subdomain: &str,
    ) -> Result<DomainView, DomainsError> {
        if !manages(membership) {
            return Err(DomainsError::NotAllowed);
        }
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        domains::lock_hierarchy_policy(&mut **work.sql()).await?;
        let parent = domains::configured_parent(&mut **work.sql(), membership.organisation_id)
            .await?
            .ok_or(DomainsError::AppDomainRequired)?;
        let app =
            grund_store::apps::app_by_name(&mut **work.sql(), membership.organisation_id, app_name)
                .await?
                .ok_or(DomainsError::AppNotFound)?;
        let label = if subdomain.is_empty() {
            &app.name
        } else {
            subdomain
        };
        let name = app_hostname(label, &parent.name)?;
        let previous =
            domains::managed_assignment(&mut **work.sql(), membership.organisation_id, app.app_id)
                .await?;
        let previous = match previous {
            Some(previous) if previous.state != "removed" => {
                Some(self.lock_binding(&mut work, &previous).await?)
            }
            _ => None,
        };
        self.lock_apps(&mut work, &mut [app.app_id]).await?;
        if let Some(previous) = &previous
            && previous.name == name.as_str()
        {
            if previous.app_id.is_none()
                && domains::count_bound(&mut **work.sql(), app.app_id).await? >= MAX_PER_APP
            {
                return Err(DomainsError::AppLimit);
            }
            work.domain(
                previous.domain_id,
                DomainCommand::Bind {
                    actor,
                    app_id: app.app_id,
                    at: Utc::now(),
                },
            )
            .await?;
            self.want_public_certificate(
                work.sql(),
                previous.domain_id,
                membership.organisation_id,
                app.app_id,
                &previous.name,
            )
            .await?;
        } else {
            if let Some(previous) = &previous {
                work.domain(
                    previous.domain_id,
                    DomainCommand::Remove {
                        actor,
                        at: Utc::now(),
                    },
                )
                .await?;
                domains::drop_certificate(work.sql(), previous.domain_id).await?;
            }
            self.generate_in(
                &mut work,
                actor,
                membership.organisation_id,
                app.app_id,
                name.clone(),
                &parent,
            )
            .await?;
        }
        self.publish_apps(work.sql(), &[app.app_id]).await?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        self.get(membership.organisation_id, name.as_str()).await
    }

    async fn generate_in(
        &self,
        work: &mut Work<'_>,
        actor: Uuid,
        organisation_id: Uuid,
        app_id: Uuid,
        name: DomainName,
        parent: &DomainRow,
    ) -> Result<(), DomainsError> {
        self.held_elsewhere(work.sql(), organisation_id, &name)
            .await?;
        if domains::by_name(&mut **work.sql(), organisation_id, name.as_str())
            .await?
            .is_some()
        {
            return Err(DomainsError::Exists);
        }
        if domains::count_bound(&mut **work.sql(), app_id).await? >= MAX_PER_APP {
            return Err(DomainsError::AppLimit);
        }
        let authority = work
            .load_domain(parent.domain_id)
            .await?
            .app_domain_authority(parent.domain_id)
            .map_err(|error| DomainsError::from(WorkError::Domain(error)))?;
        let domain_id = Uuid::now_v7();
        work.domain(
            domain_id,
            DomainCommand::Generate {
                actor,
                organisation_id,
                name: name.clone(),
                token: new_token(),
                authority,
                app_id,
                at: Utc::now(),
            },
        )
        .await?;
        self.want_public_certificate(
            work.sql(),
            domain_id,
            organisation_id,
            app_id,
            name.as_str(),
        )
        .await?;
        Ok(())
    }

    async fn want_public_certificate(
        &self,
        connection: &mut PgConnection,
        domain_id: Uuid,
        organisation_id: Uuid,
        app_id: Uuid,
        name: &str,
    ) -> Result<(), DomainsError> {
        let Some((directory, profile)) = self.state.certificates.ordering() else {
            return Ok(());
        };
        let current_public = domains::current_spec(&mut *connection, app_id)
            .await?
            .is_some_and(|spec| publishes(&spec.0));
        let public = current_public
            || grund_store::apps::releases(&mut *connection, app_id, 1)
                .await?
                .first()
                .is_some_and(|release| publishes(&release.spec.0));
        if public {
            domains::want_certificate(
                &mut *connection,
                domain_id,
                organisation_id,
                name,
                &directory,
                &profile,
            )
            .await?;
        }
        Ok(())
    }

    /// Adds `name` to the organisation, pending its TXT record.
    pub async fn add(
        &self,
        actor: Uuid,
        membership: &Membership,
        name: &str,
    ) -> Result<DomainView, DomainsError> {
        if !manages(membership) {
            return Err(DomainsError::NotAllowed);
        }
        let name = DomainName::parse(name)?;
        if let Some(parent) = self.reserved(&name) {
            return Err(DomainsError::Reserved(parent));
        }
        let organisation_id = membership.organisation_id;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        domains::lock_hierarchy_policy(&mut **work.sql()).await?;
        if domains::by_name(&mut **work.sql(), organisation_id, name.as_str())
            .await?
            .is_some()
        {
            return Err(DomainsError::Exists);
        }
        self.held_elsewhere(work.sql(), organisation_id, &name)
            .await?;
        if domains::count_live(&mut **work.sql(), organisation_id).await? >= MAX_PER_ORGANISATION {
            return Err(DomainsError::Limit);
        }
        if domains::added_today(&mut **work.sql(), organisation_id).await? >= MAX_ADDED_PER_DAY {
            return Err(DomainsError::DailyLimit);
        }
        work.domain(
            Uuid::now_v7(),
            DomainCommand::Add {
                actor,
                organisation_id,
                name: name.clone(),
                token: new_token(),
                at: Utc::now(),
            },
        )
        .await?;
        work.commit().await?;
        tracing::info!(%organisation_id, domain = %name, "domains: added");
        self.get(organisation_id, name.as_str()).await
    }

    /// Looks for the domain's TXT record now, and verifies the domain if it
    /// holds the token. A record that is not there yet is recorded and
    /// refused with why.
    pub async fn verify(
        &self,
        actor: Uuid,
        membership: &Membership,
        name: &str,
    ) -> Result<DomainView, DomainsError> {
        if !manages(membership) {
            return Err(DomainsError::NotAllowed);
        }
        let row = self.row(membership.organisation_id, name).await?;
        if row.state != "pending" {
            return Ok(view(row));
        }
        let name = DomainName::parse(&row.name)
            .map_err(|_| DomainsError::Internal(anyhow::anyhow!("a stored name does not parse")))?;
        let found = lookup_txt(
            self.state.config.entry.dns_resolver,
            &name.verification_name(),
            &row.token,
        )
        .await;
        if let Lookup::Missing(code) = found {
            domains::record_check(&self.state.pool, row.domain_id, Some(code)).await?;
            return Err(DomainsError::VerificationFailed(check_words(code)));
        }
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let row = self.lock_binding(&mut work, &row).await?;
        self.held_elsewhere(work.sql(), membership.organisation_id, &name)
            .await?;
        work.domain(
            row.domain_id,
            DomainCommand::Verify {
                actor,
                at: Utc::now(),
            },
        )
        .await?;
        domains::record_check(&mut **work.sql(), row.domain_id, None).await?;
        work.commit().await?;
        tracing::info!(organisation_id = %membership.organisation_id, domain = %name, "domains: verified");
        self.get(membership.organisation_id, name.as_str()).await
    }

    /// Binds a verified domain to one of the organisation's apps. In
    /// custom-only mode it may be bound before the app is public, so the
    /// first public release can be made without a shared address.
    pub async fn bind(
        &self,
        actor: Uuid,
        membership: &Membership,
        name: &str,
        app_name: &str,
    ) -> Result<DomainView, DomainsError> {
        if !manages(membership) {
            return Err(DomainsError::NotAllowed);
        }
        let initial = self.row(membership.organisation_id, name).await?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let row = self.lock_binding(&mut work, &initial).await?;
        let app =
            grund_store::apps::app_by_name(&mut **work.sql(), membership.organisation_id, app_name)
                .await?
                .ok_or(DomainsError::AppNotFound)?;
        if row.state == "pending" {
            return Err(DomainsError::NotVerified);
        }
        if row
            .managed_app_id
            .is_some_and(|managed| managed != app.app_id)
        {
            return Err(DomainsError::NamespaceConflict(
                "a generated app address cannot be moved to another app; change its subdomain instead".into(),
            ));
        }
        if row.app_id == Some(app.app_id) {
            return Ok(view(row));
        }
        let mut app_ids = vec![app.app_id];
        app_ids.extend(row.app_id);
        self.lock_apps(&mut work, &mut app_ids).await?;
        let spec = domains::current_spec(&mut **work.sql(), app.app_id).await?;
        if row.managed_app_id.is_none()
            && self.state.config.entry.app_domains != crate::config::AppDomains::CustomOnly
            && !spec.is_some_and(|spec| publishes(&spec.0))
        {
            return Err(DomainsError::AppNotPublic);
        }
        if let Some(previous) = row.app_id {
            self.require_other_domain(work.sql(), previous).await?;
        }
        if domains::count_bound(&mut **work.sql(), app.app_id).await? >= MAX_PER_APP {
            return Err(DomainsError::AppLimit);
        }
        work.domain(
            row.domain_id,
            DomainCommand::Bind {
                actor,
                app_id: app.app_id,
                at: Utc::now(),
            },
        )
        .await?;
        self.want_public_certificate(
            work.sql(),
            row.domain_id,
            membership.organisation_id,
            app.app_id,
            &row.name,
        )
        .await?;
        self.publish_apps(work.sql(), &app_ids).await?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        tracing::info!(organisation_id = %membership.organisation_id, domain = %row.name, app = %app.name, "domains: bound");
        self.get(membership.organisation_id, &row.name).await
    }

    /// Unbinds a domain; it stays verified, and its certificate goes.
    pub async fn unbind(
        &self,
        actor: Uuid,
        membership: &Membership,
        name: &str,
    ) -> Result<DomainView, DomainsError> {
        if !manages(membership) {
            return Err(DomainsError::NotAllowed);
        }
        let initial = self.row(membership.organisation_id, name).await?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let row = self.lock_binding(&mut work, &initial).await?;
        if let Some(app_id) = row.app_id {
            self.lock_apps(&mut work, &mut [app_id]).await?;
            self.require_other_domain(work.sql(), app_id).await?;
        }
        work.domain(
            row.domain_id,
            DomainCommand::Unbind {
                actor,
                at: Utc::now(),
            },
        )
        .await?;
        domains::drop_certificate(work.sql(), row.domain_id).await?;
        let apps: Vec<Uuid> = row.app_id.into_iter().collect();
        self.publish_apps(work.sql(), &apps).await?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        self.get(membership.organisation_id, &row.name).await
    }

    /// Removes a domain from the organisation, unbinding it first. A
    /// verified name then cools down for other organisations.
    pub async fn remove(
        &self,
        actor: Uuid,
        membership: &Membership,
        name: &str,
    ) -> Result<(), DomainsError> {
        if !manages(membership) {
            return Err(DomainsError::NotAllowed);
        }
        let initial = self.row(membership.organisation_id, name).await?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        let row = self.lock_binding(&mut work, &initial).await?;
        if row.is_app_domain
            && domains::has_live_children(
                &mut **work.sql(),
                membership.organisation_id,
                row.domain_id,
            )
            .await?
        {
            return Err(DomainsError::NamespaceConflict(
                "remove this app domain's generated addresses before removing the parent".into(),
            ));
        }
        if let Some(app_id) = row.app_id {
            self.lock_apps(&mut work, &mut [app_id]).await?;
            self.require_other_domain(work.sql(), app_id).await?;
        }
        work.domain(
            row.domain_id,
            DomainCommand::Remove {
                actor,
                at: Utc::now(),
            },
        )
        .await?;
        domains::drop_certificate(work.sql(), row.domain_id).await?;
        let apps: Vec<Uuid> = row.app_id.into_iter().collect();
        self.publish_apps(work.sql(), &apps).await?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        tracing::info!(organisation_id = %membership.organisation_id, domain = %row.name, "domains: removed");
        Ok(())
    }

    /// Unbinds every domain of an app being deleted, inside its deletion.
    pub async fn unbind_app_in(
        &self,
        work: &mut Work<'_>,
        actor: Uuid,
        app_id: Uuid,
    ) -> Result<(), WorkError> {
        for row in domains::bound_to(&mut **work.sql(), app_id).await? {
            work.domain(
                row.domain_id,
                DomainCommand::UnbindForAppDeletion {
                    actor,
                    at: Utc::now(),
                },
            )
            .await?;
            domains::drop_certificate(work.sql(), row.domain_id).await?;
        }
        Ok(())
    }

    async fn require_other_domain(
        &self,
        connection: &mut PgConnection,
        app_id: Uuid,
    ) -> Result<(), DomainsError> {
        if self.state.config.entry.app_domains != crate::config::AppDomains::CustomOnly
            || domains::count_bound(&mut *connection, app_id).await? != 1
        {
            return Ok(());
        }
        let current_public = domains::current_spec(&mut *connection, app_id)
            .await?
            .is_some_and(|spec| publishes(&spec.0));
        let next_public = grund_store::apps::releases(&mut *connection, app_id, 1)
            .await?
            .first()
            .is_some_and(|release| publishes(&release.spec.0));
        if current_public || next_public {
            return Err(DomainsError::LastPublicDomain);
        }
        Ok(())
    }

    async fn publish_apps(
        &self,
        connection: &mut PgConnection,
        apps: &[Uuid],
    ) -> anyhow::Result<()> {
        let mut machines = Vec::new();
        for app_id in apps {
            machines.extend(grund_store::apps::app_machines(&mut *connection, *app_id).await?);
        }
        machines.sort();
        machines.dedup();
        for machine_id in machines {
            self.state
                .agents()
                .publish_in(connection, machine_id)
                .await?;
        }
        Ok(())
    }

    /// The certificate and its key for the bound domain `name`, opened for
    /// an edge that routes it; `None` while none is issued.
    pub async fn certificate_for_edge(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<(String, Vec<u8>, i64)>> {
        let Some(bound) = domains::bound_name(&self.state.pool, name).await? else {
            return Ok(None);
        };
        let Some(stored) = domains::certificate(&self.state.pool, bound.domain_id).await? else {
            return Ok(None);
        };
        let subject = domains::certificate_subject(bound.domain_id);
        let key = self
            .state
            .certificates
            .unseal_certificate_key(&subject, &stored.sealed_key)
            .ok_or_else(|| {
                anyhow::anyhow!("the certificate key of {name} does not open with GRUND_SECRET_KEY")
            })?;
        Ok(Some((stored.chain_pem, key, stored.version)))
    }

    /// The HTTP-01 key authorization for `token`, if an order for the bound
    /// domain `name` waits on it.
    pub async fn http01(&self, name: &str, token: &str) -> anyhow::Result<Option<String>> {
        let Some(bound) = domains::bound_name(&self.state.pool, name).await? else {
            return Ok(None);
        };
        Ok(grund_store::certificates::http01(
            &self.state.pool,
            &domains::certificate_subject(bound.domain_id),
            token,
        )
        .await?)
    }
}

/// Custom domains' flows.
pub trait DomainsState {
    fn domains(&self) -> Domains;
}

impl DomainsState for State {
    fn domains(&self) -> Domains {
        Domains {
            state: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(state: &str) -> DomainRow {
        DomainRow {
            domain_id: Uuid::nil(),
            organisation_id: Uuid::nil(),
            name: "app.example.com".into(),
            token: new_token(),
            state: state.into(),
            app_id: (state == "bound").then(Uuid::nil),
            app_name: (state == "bound").then(|| "web".to_string()),
            is_app_domain: false,
            parent_domain_id: None,
            parent_domain: None,
            managed_app_id: None,
            managed_app_name: None,
            assignment_disabled: false,
            added_at: Utc::now(),
            verified_at: None,
            bound_at: None,
            checked_at: None,
            check_error: None,
            certificate_not_after: None,
            certificate_error: None,
            certificate_wanted: state == "bound",
            steps: sqlx::types::Json(Vec::new()),
            certificate_attempts: 0,
            certificate_next_attempt_at: None,
        }
    }

    #[test]
    fn a_domain_says_where_it_is() {
        assert_eq!(view(row("pending")).status, Status::Pending);
        assert_eq!(view(row("verified")).status, Status::Verified);
        assert_eq!(view(row("bound")).status, Status::Bound);
        let mut issued = row("bound");
        issued.certificate_not_after = Some(Utc::now());
        issued.certificate_error = Some("acme_unreachable".into());
        assert_eq!(view(issued).status, Status::Issued);
        let mut failing = row("bound");
        failing.certificate_error = Some("authorization_failed".into());
        let failing = view(failing);
        assert_eq!(failing.status, Status::Error);
        let mut unchecked = row("pending");
        unchecked.check_error = Some("no_record".into());
        assert_eq!(view(unchecked).status, Status::Error);
        let mut orphan = row("bound");
        orphan.app_name = None;
        assert_eq!(view(orphan).status, Status::Error);
    }

    #[test]
    fn the_record_to_add_is_under_grunds_label() {
        let shown = view(row("pending"));
        assert_eq!(shown.txt_name, "_grund.app.example.com");
        assert!(shown.txt_value.starts_with("grund-verify-"));
        assert_eq!(shown.txt_value.len(), "grund-verify-".len() + 43);
    }

    #[test]
    fn app_labels_are_single_lowercase_dns_labels_not_control_records() {
        for label in ["api", "www", "admin", "a", "web-2"] {
            assert_eq!(
                app_hostname(label, "example.com").unwrap().as_str(),
                format!("{label}.example.com")
            );
        }
        for label in [
            "",
            "_grund",
            "_acme-challenge",
            "*",
            "a.b",
            "-a",
            "a-",
            "Web",
            "a/b",
        ] {
            assert!(
                matches!(
                    app_hostname(label, "example.com"),
                    Err(DomainsError::InvalidSubdomain)
                ),
                "{label}"
            );
        }
        assert!(matches!(
            app_hostname(&"a".repeat(64), "example.com"),
            Err(DomainsError::InvalidSubdomain)
        ));
    }

    #[test]
    fn a_generated_address_reports_parent_authority_without_a_child_txt_challenge() {
        let mut generated = row("bound");
        generated.parent_domain = Some("example.com".into());
        let shown = view(generated);
        assert_eq!(shown.parent_domain.as_deref(), Some("example.com"));
        assert!(shown.txt_name.is_empty());
        assert!(shown.txt_value.is_empty());
    }
}
