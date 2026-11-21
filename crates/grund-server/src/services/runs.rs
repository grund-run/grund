//! Durable single-attempt stack executions and pinned machine input authorization.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use grund_domain::{
    organisation::Role,
    run::{Command, Request, Status},
};
use grund_proto::grund::{agent::v1 as agent, run::v1 as proto};
use grund_store::{
    apps, machines, runs as store, stacks,
    work::{Work, WorkError},
};
use ring::hmac;
use serde::Serialize;
use sqlx::{PgConnection, types::Json};
use uuid::Uuid;

use crate::{
    services::{
        agents::{AgentsState, MachineCaller},
        apps::{machine_view, open},
    },
    state::State,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no such run, stack or service")]
    NotFound,
    #[error("only organisation owners may access runs")]
    Owner,
    #[error("invalid run input")]
    Invalid,
    #[error("idempotency key was used with different input")]
    Idempotency,
    #[error("{0}")]
    Precondition(&'static str),
    #[error("run changed concurrently")]
    Conflict,
    #[error("run storage unavailable")]
    Internal(#[from] anyhow::Error),
}
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}
impl From<WorkError> for Error {
    fn from(e: WorkError) -> Self {
        match e {
            WorkError::Run(grund_domain::run::Error::NotFound) => Self::NotFound,
            WorkError::Run(_) => Self::Precondition("run_attempt_unauthorised"),
            WorkError::Events(mire::EventStoreError::ConcurrencyConflict { .. }) => Self::Conflict,
            e => Self::Internal(e.into()),
        }
    }
}
impl Error {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotFound => "run_not_found",
            Self::Owner => "run_owner_required",
            Self::Invalid => "run_invalid_input",
            Self::Idempotency => "run_idempotency_conflict",
            Self::Precondition(reason) => reason,
            Self::Conflict => "run_conflict",
            Self::Internal(_) => "run_unavailable",
        }
    }
}

struct Fingerprint(hmac::Context);
impl std::io::Write for Fingerprint {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct Runs {
    state: State,
}
impl Runs {
    fn digest(&self, value: &impl Serialize) -> Result<Vec<u8>, Error> {
        let mut writer = Fingerprint(hmac::Context::with_key(&hmac::Key::new(
            hmac::HMAC_SHA256,
            &self.state.secret.derive("run-requests"),
        )));
        serde_json::to_writer(&mut writer, value).map_err(anyhow::Error::from)?;
        Ok(writer.0.sign().as_ref().to_vec())
    }

    /// Every RPC, including receipt replay, rechecks current owner membership.
    pub async fn owner(&self, slug: &str, actor: Uuid) -> Result<Uuid, Error> {
        let (org,role): (Uuid,String) = sqlx::query_as("SELECT o.organisation_id,m.role FROM grund_organisations o JOIN grund_memberships m USING(organisation_id) WHERE o.slug=$1 AND m.account_id=$2 AND o.deleted_at IS NULL")
            .bind(slug).bind(actor).fetch_optional(&self.state.pool).await?.ok_or(Error::NotFound)?;
        if Role::parse(&role) != Some(Role::Owner) {
            return Err(Error::Owner);
        }
        Ok(org)
    }

    async fn lock(&self, work: &mut Work<'_>, org: Uuid, actor: Option<Uuid>) -> Result<(), Error> {
        grund_store::domains::lock_hierarchy_policy(&mut **work.sql()).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("grund-apps-placement:{org}"))
            .execute(&mut **work.sql())
            .await?;
        if let Some(actor) = actor {
            let role: Option<String> = sqlx::query_scalar("SELECT m.role FROM grund_memberships m JOIN grund_organisations o USING(organisation_id) WHERE m.organisation_id=$1 AND m.account_id=$2 AND o.deleted_at IS NULL FOR SHARE OF m,o")
                .bind(org).bind(actor).fetch_optional(&mut **work.sql()).await?;
            if role.as_deref() != Some("owner") {
                return Err(Error::Owner);
            }
        }
        Ok(())
    }

    fn key(key: &str) -> Result<(), Error> {
        if !(1..=128).contains(&key.len())
            || !key.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    async fn replay(
        &self,
        conn: &mut PgConnection,
        org: Uuid,
        actor: Uuid,
        method: &str,
        key: &str,
        digest: &[u8],
    ) -> Result<Option<store::Row>, Error> {
        let receipt: Option<(Vec<u8>, Uuid)> = sqlx::query_as("SELECT fingerprint,run_id FROM grund_run_requests WHERE organisation_id=$1 AND caller_id=$2 AND method=$3 AND request_key=$4 AND expires_at>clock_timestamp()")
            .bind(org).bind(actor).bind(method).bind(key).fetch_optional(&mut *conn).await?;
        match receipt {
            Some((before, id)) if before == digest => Ok(Some(
                store::get(conn, org, id).await?.ok_or(Error::NotFound)?,
            )),
            Some(_) => Err(Error::Idempotency),
            None => Ok(None),
        }
    }

    async fn receipt(
        &self,
        conn: &mut PgConnection,
        org: Uuid,
        actor: Uuid,
        method: &str,
        key: &str,
        digest: &[u8],
        id: Uuid,
    ) -> Result<(), Error> {
        sqlx::query("DELETE FROM grund_run_requests WHERE organisation_id=$1 AND caller_id=$2 AND method=$3 AND request_key=$4 AND expires_at<=clock_timestamp()")
            .bind(org).bind(actor).bind(method).bind(key).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO grund_run_requests(organisation_id,caller_id,method,request_key,fingerprint,run_id) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(org).bind(actor).bind(method).bind(key).bind(digest).bind(id).execute(conn).await?;
        Ok(())
    }

    async fn stack(
        &self,
        conn: &mut PgConnection,
        org: Uuid,
        name: &str,
    ) -> Result<stacks::Row, Error> {
        let row = if let Ok(id) = Uuid::parse_str(name) {
            stacks::get(conn, org, id).await?
        } else {
            stacks::by_name(conn, org, name).await?
        };
        row.ok_or(Error::NotFound)
    }

    /// Admission and every durable side row share the existing placement transaction.
    pub async fn create(
        &self,
        actor: Uuid,
        org: Uuid,
        input: &proto::CreateRunRequest,
    ) -> Result<Option<store::Row>, Error> {
        Self::key(&input.idempotency_key)?;
        if input.args.is_empty()
            || input.args.len() > 128
            || input.args.iter().map(String::len).sum::<usize>() > 32768
            || input.args.iter().any(|a| a.contains('\0'))
            || input.timeout_seconds > 3600
            || input.service.is_empty()
        {
            return Err(Error::Invalid);
        }
        let digest = self.digest(&(
            &input.stack,
            &input.service,
            &input.args,
            input.timeout_seconds,
        ))?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        self.lock(&mut work, org, Some(actor)).await?;
        if !input.dry_run
            && let Some(row) = self
                .replay(
                    work.sql(),
                    org,
                    actor,
                    "create",
                    &input.idempotency_key,
                    &digest,
                )
                .await?
        {
            return Ok(Some(row));
        }
        let stack = self.stack(work.sql(), org, &input.stack).await?;
        let state = &stack.state.0;
        if state.operation.is_some()
            || state.status != grund_domain::stack::Status::Ready
            || state.applied_revision != state.desired_revision
        {
            return Err(Error::Precondition("run_stack_unstable"));
        }
        let revision = state
            .revisions
            .get(&state.applied_revision)
            .ok_or(Error::Precondition("run_inputs_unavailable"))?;
        let service = revision
            .services
            .get(&input.service)
            .ok_or(Error::NotFound)?;
        if !service.release.spec.volumes.is_empty() {
            return Err(Error::Precondition("run_volumes_unsupported"));
        }
        let app = work.load_app(service.app_id).await?;
        if app.deleted || app.rollout.is_some() {
            return Err(Error::Precondition("run_stack_unstable"));
        }
        let execution = service.execution_release(&input.service, None, &app);
        if app.current_release != Some(execution) {
            return Err(Error::Precondition("run_stack_unstable"));
        }
        let release = app
            .release(execution)
            .ok_or(Error::Precondition("run_inputs_unavailable"))?
            .clone();
        if release.spec != service.release.spec
            || release.image_digest != service.release.image_digest
            || release.secret_versions != service.release.secret_versions
        {
            return Err(Error::Precondition("run_inputs_unavailable"));
        }
        let machine_id = state
            .machine_id
            .ok_or(Error::Precondition("run_machine_unavailable"))?;
        let machine = machines::organisation_machine(&mut **work.sql(), org, machine_id)
            .await?
            .ok_or(Error::Precondition("run_machine_unavailable"))?;
        if !machine
            .capabilities
            .as_ref()
            .is_some_and(|c| c.0["runs_v1"].as_bool() == Some(true))
        {
            return Err(Error::Precondition("run_agent_unsupported"));
        }
        let migrating: bool = sqlx::query_scalar("WITH scope AS (SELECT $1::uuid AS machine_id UNION SELECT host_machine_id FROM grund_vms WHERE machine_id=$1) SELECT EXISTS(SELECT 1 FROM grund_agent_updates u CROSS JOIN scope s WHERE u.migration_holds ? s.machine_id::text) OR EXISTS(SELECT 1 FROM grund_machine_migration_pauses p JOIN scope s USING(machine_id)) OR EXISTS(SELECT 1 FROM grund_vms WHERE machine_id=$1 AND state<>'running') OR EXISTS(SELECT 1 FROM grund_machines m JOIN scope s USING(machine_id) WHERE m.state NOT IN ('active','leased'))")
            .bind(machine_id).fetch_one(&mut **work.sql()).await?;
        if migrating {
            return Err(Error::Precondition("run_machine_unavailable"));
        }
        let occupied = apps::reservations(&mut **work.sql(), org, Uuid::nil()).await?;
        let view = machine_view(
            &machine,
            occupied.iter().find(|r| r.machine_id == machine_id),
        );
        if !matches!(machine.state.as_str(), "active" | "leased")
            || view.cordoned
            || !view.apps
            || !view.connected(Utc::now())
        {
            return Err(Error::Precondition("run_machine_unavailable"));
        }
        if view
            .reserved_memory_mib
            .saturating_add(release.spec.memory_mib)
            > view.allocatable_memory_mib()
            || view
                .reserved_cpu_millis
                .saturating_add(release.spec.cpu_millis)
                > view.allocatable_cpu_millis()
            || (view.max_replica_memory_mib > 0
                && release.spec.memory_mib > view.max_replica_memory_mib)
            || (view.max_replica_cpu_millis > 0
                && release.spec.cpu_millis > view.max_replica_cpu_millis)
        {
            return Err(Error::Precondition("run_insufficient_capacity"));
        }
        let outstanding: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grund_runs WHERE organisation_id=$1 AND stack_id=$2 AND service=$3 AND outstanding)")
            .bind(org).bind(stack.stack_id).bind(&input.service).fetch_one(&mut **work.sql()).await?;
        if outstanding {
            return Err(Error::Precondition("run_outstanding"));
        }
        for secret in &release.secret_versions {
            if apps::secret_value(
                &mut **work.sql(),
                service.app_id,
                &secret.name,
                secret.version as i32,
            )
            .await?
            .is_none()
            {
                return Err(Error::Precondition("run_inputs_unavailable"));
            }
        }
        if input.dry_run {
            return Ok(None);
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **work.sql())
            .await?;
        let id = Uuid::now_v7();
        let secret_count = release.secret_versions.len() as i64;
        work.run(
            id,
            Command::Request(Request {
                organisation_id: org,
                stack_id: stack.stack_id,
                stack_name: state.name.clone(),
                service: input.service.clone(),
                stack_revision: state.applied_revision,
                app_id: service.app_id,
                app_name: service.app_name.clone(),
                release,
                settings: service.settings.clone(),
                machine_id,
                requester_id: actor,
                attempt_id: Uuid::now_v7(),
                requested_at: now,
                deadline: now
                    + Duration::seconds(if input.timeout_seconds == 0 {
                        600
                    } else {
                        i64::from(input.timeout_seconds)
                    }),
            }),
        )
        .await?;
        let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grund_run_inputs WHERE organisation_id=$1 AND run_id=$2) AND (SELECT COUNT(*) FROM grund_run_secret_pins WHERE organisation_id=$1 AND run_id=$2)=$3")
            .bind(org).bind(id).bind(secret_count).fetch_one(&mut **work.sql()).await?;
        if !pinned {
            return Err(Error::Precondition("run_inputs_unavailable"));
        }
        sqlx::query("INSERT INTO grund_run_payloads(organisation_id,run_id,args) VALUES($1,$2,$3)")
            .bind(org)
            .bind(id)
            .bind(Json(&input.args))
            .execute(&mut **work.sql())
            .await?;
        self.receipt(
            work.sql(),
            org,
            actor,
            "create",
            &input.idempotency_key,
            &digest,
            id,
        )
        .await?;
        self.state
            .agents()
            .publish_in(work.sql(), machine_id)
            .await?;
        let row = store::get(&mut **work.sql(), org, id)
            .await?
            .ok_or(Error::NotFound)?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        Ok(Some(row))
    }

    /// Called only after trusted provider proof that this registration cannot execute.
    /// Revocation, lease expiry, missed heartbeats and an accepted delete are not proof.
    pub async fn confirm_machine_fenced(
        &self,
        org: Uuid,
        machine: Uuid,
        registration_key: &str,
    ) -> Result<(), Error> {
        let mut work =
            Work::begin(&self.state.events, Uuid::now_v7(), "grund/machine-fence").await?;
        self.lock(&mut work, org, None).await?;
        let current: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grund_machines WHERE machine_id=$1 AND pool_organisation_id=$2 AND public_key=$3)")
            .bind(machine).bind(org).bind(registration_key).fetch_one(&mut **work.sql()).await?;
        if !current {
            return Err(Error::Precondition("run_attempt_unauthorised"));
        }
        for row in store::outstanding_machine(&mut **work.sql(), machine).await? {
            let request = row.state.0.request.as_ref().ok_or(Error::NotFound)?;
            if request.organisation_id != org {
                return Err(Error::NotFound);
            }
            work.run(
                row.run_id,
                Command::Observe {
                    machine_id: machine,
                    attempt_id: request.attempt_id,
                    status: Status::Unknown,
                    started_at: None,
                    at: Utc::now(),
                    exit_code: None,
                    signal: None,
                    stop_confirmed: true,
                },
            )
            .await?;
        }
        self.state.agents().publish_in(work.sql(), machine).await?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        Ok(())
    }

    pub async fn get(&self, org: Uuid, id: Uuid) -> Result<store::Row, Error> {
        store::get(&self.state.pool, org, id)
            .await?
            .ok_or(Error::NotFound)
    }

    pub async fn cancel(
        &self,
        actor: Uuid,
        org: Uuid,
        id: Uuid,
        key: &str,
        dry_run: bool,
    ) -> Result<store::Row, Error> {
        Self::key(key)?;
        let digest = self.digest(&id)?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        self.lock(&mut work, org, Some(actor)).await?;
        if !dry_run
            && let Some(row) = self
                .replay(work.sql(), org, actor, "cancel", key, &digest)
                .await?
        {
            return Ok(row);
        }
        let row = store::get(&mut **work.sql(), org, id)
            .await?
            .ok_or(Error::NotFound)?;
        if dry_run {
            return Ok(row);
        }
        work.run(
            id,
            Command::Cancel {
                at: Utc::now(),
                timed_out: false,
            },
        )
        .await?;
        self.receipt(work.sql(), org, actor, "cancel", key, &digest, id)
            .await?;
        let machine = row
            .state
            .0
            .request
            .as_ref()
            .ok_or(Error::NotFound)?
            .machine_id;
        self.state.agents().publish_in(work.sql(), machine).await?;
        let row = store::get(&mut **work.sql(), org, id)
            .await?
            .ok_or(Error::NotFound)?;
        work.commit().await?;
        self.state.wakes.documents_changed();
        Ok(row)
    }

    fn cursor(&self, org: Uuid, stack: Uuid, service: &str, after: Uuid) -> Result<String, Error> {
        let mut bytes = after.as_bytes().to_vec();
        bytes.extend(self.digest(&("list", org, stack, service, after))?);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub async fn list(
        &self,
        org: Uuid,
        input: &proto::ListRunsRequest,
    ) -> Result<(Vec<store::Row>, String), Error> {
        if input.stack.is_empty()
            || !(0..=100).contains(&input.page_size)
            || input.page_token.len() > 128
        {
            return Err(Error::Invalid);
        }
        let mut conn = self.state.pool.acquire().await?;
        let stack = self.stack(&mut conn, org, &input.stack).await?;
        let after = if input.page_token.is_empty() {
            None
        } else {
            let bytes = URL_SAFE_NO_PAD
                .decode(&input.page_token)
                .map_err(|_| Error::Invalid)?;
            if bytes.len() != 48 {
                return Err(Error::Invalid);
            }
            let id = Uuid::from_slice(&bytes[..16]).map_err(|_| Error::Invalid)?;
            let expected = self.cursor(org, stack.stack_id, &input.service, id)?;
            if !bool::from(subtle::ConstantTimeEq::ct_eq(
                expected.as_bytes(),
                input.page_token.as_bytes(),
            )) {
                return Err(Error::Invalid);
            }
            Some(id)
        };
        let size = if input.page_size == 0 {
            50
        } else {
            input.page_size as usize
        };
        let mut rows = store::list(
            &mut *conn,
            org,
            stack.stack_id,
            &input.service,
            after,
            size as i64 + 1,
        )
        .await?;
        let more = rows.len() > size;
        rows.truncate(size);
        let next = if more {
            self.cursor(
                org,
                stack.stack_id,
                &input.service,
                rows.last().ok_or(Error::Invalid)?.run_id,
            )?
        } else {
            String::new()
        };
        Ok((rows, next))
    }

    /// Only this pinned machine and still-startable attempt may resolve private input.
    pub async fn input(
        &self,
        caller: &MachineCaller,
        id: Uuid,
        attempt: Uuid,
    ) -> Result<Option<agent::GetRunInputResponse>, Error> {
        let Some(org) = caller.organisation_id else {
            return Ok(None);
        };
        let mut tx = self.state.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("grund-apps-placement:{org}"))
            .execute(&mut *tx)
            .await?;
        let Some(row) =
            store::authorised(&mut *tx, org, caller.machine_id, id, Some(attempt)).await?
        else {
            return Ok(None);
        };
        let request = row.state.0.request.as_ref().ok_or(Error::NotFound)?;
        let Some(args) = store::args(&mut *tx, org, id).await? else {
            return Ok(None);
        };
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(
                &ring::aead::AES_256_GCM,
                &self.state.secret.derive("app-secrets"),
            )
            .map_err(|_| Error::Precondition("run_inputs_unavailable"))?,
        );
        let mut env: Vec<agent::EnvVar> = request
            .release
            .spec
            .env
            .iter()
            .map(|e| agent::EnvVar {
                name: e.name.clone(),
                value: e.value.clone(),
                ..Default::default()
            })
            .collect();
        for binding in &request.release.spec.secrets {
            let secret = request
                .release
                .secret_versions
                .iter()
                .find(|s| s.name == binding.secret)
                .ok_or(Error::Precondition("run_inputs_unavailable"))?;
            let sealed = apps::secret_value(
                &mut *tx,
                request.app_id,
                &secret.name,
                secret.version as i32,
            )
            .await?
            .ok_or(Error::Precondition("run_inputs_unavailable"))?;
            let value = open(
                &key,
                request.app_id,
                &secret.name,
                secret.version as i32,
                &sealed,
            )
            .ok_or(Error::Precondition("run_inputs_unavailable"))?;
            let value = String::from_utf8(value)
                .map_err(|_| Error::Precondition("run_inputs_unavailable"))?;
            env.retain(|e| e.name != binding.env);
            env.push(agent::EnvVar {
                name: binding.env.clone(),
                value,
                ..Default::default()
            });
        }
        tx.commit().await?;
        Ok(Some(agent::GetRunInputResponse {
            args,
            env,
            ..Default::default()
        }))
    }

    /// Reports never accept caller-supplied text into audit events.
    pub async fn report(
        &self,
        caller: &MachineCaller,
        observations: &[agent::RunObserved],
    ) -> Result<(), Error> {
        let Some(org) = caller.organisation_id else {
            return Err(Error::NotFound);
        };
        if observations.len() > 128 {
            return Err(Error::Invalid);
        }
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), "grund/agent-run").await?;
        self.lock(&mut work, org, None).await?;
        let now = Utc::now();
        let mut changed = false;
        for observation in observations {
            let id = Uuid::parse_str(&observation.run_id).map_err(|_| Error::Invalid)?;
            let attempt = Uuid::parse_str(&observation.attempt_id).map_err(|_| Error::Invalid)?;
            let row = store::get(&mut **work.sql(), org, id)
                .await?
                .ok_or(Error::NotFound)?;
            let request = row.state.0.request.as_ref().ok_or(Error::NotFound)?;
            if request.machine_id != caller.machine_id || request.attempt_id != attempt {
                return Err(Error::Precondition("run_attempt_unauthorised"));
            }
            let status = status(observation.state.as_known().ok_or(Error::Invalid)?)
                .ok_or(Error::Invalid)?;
            let at = observation
                .finished_at
                .as_option()
                .map(time)
                .transpose()?
                .unwrap_or(now);
            if at < request.requested_at || at > now + Duration::seconds(30) {
                return Err(Error::Invalid);
            }
            let events = work
                .run(
                    id,
                    Command::Observe {
                        machine_id: caller.machine_id,
                        attempt_id: attempt,
                        status,
                        started_at: observed_start(
                            observation.started_at.as_option(),
                            request.requested_at,
                        )?,
                        at,
                        exit_code: observation.exit_code,
                        signal: observation.signal,
                        stop_confirmed: observation.stop_confirmed,
                    },
                )
                .await?;
            changed |= !events.is_empty();
        }
        if changed {
            self.state
                .agents()
                .publish_in(work.sql(), caller.machine_id)
                .await?;
        }
        work.commit().await?;
        if changed {
            self.state.wakes.documents_changed();
        }
        Ok(())
    }

    /// Reconciliation revokes late/deleted starts and preserves uncertainty reservations.
    pub async fn reconcile(&self) -> Result<(), Error> {
        let mut after: Option<(Uuid, Uuid)> = None;
        loop {
            let rows: Vec<(Uuid,Uuid)> = sqlx::query_as("SELECT organisation_id,run_id FROM grund_runs WHERE outstanding AND NOT(state->>'status'='unknown' AND state->>'cancel_requested_at' IS NOT NULL) AND ($1::uuid IS NULL OR (organisation_id,run_id)>($1,$2)) ORDER BY organisation_id,run_id LIMIT 100")
                .bind(after.map(|(org,_)|org)).bind(after.map(|(_,id)|id)).fetch_all(&self.state.pool).await?;
            if rows.is_empty() {
                break;
            }
            after = rows.last().copied();
            for (org, id) in rows {
                if let Err(error) = self.reconcile_one(org, id).await {
                    tracing::warn!(run_id=%id,reason=error.reason(),"run turn failed; retrying next tick");
                }
            }
        }
        store::sweep(&self.state.pool).await?;
        Ok(())
    }

    async fn reconcile_one(&self, org: Uuid, id: Uuid) -> Result<(), Error> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), "grund/runs").await?;
        self.lock(&mut work, org, None).await?;
        let Some(row) = store::get(&mut **work.sql(), org, id).await? else {
            return Ok(());
        };
        if !row.state.0.outstanding() {
            return Ok(());
        }
        let request = row.state.0.request.as_ref().ok_or(Error::NotFound)?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **work.sql())
            .await?;
        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grund_apps a JOIN grund_stacks s ON s.organisation_id=a.organisation_id AND s.stack_id=$3 JOIN grund_machines m ON m.machine_id=$4 JOIN grund_organisations o ON o.organisation_id=a.organisation_id WHERE a.organisation_id=$1 AND a.app_id=$2 AND a.deleted_at IS NULL AND o.deleted_at IS NULL AND s.status NOT IN ('deleting','deleted') AND m.pool_organisation_id=$1 AND m.state IN ('active','leased'))")
                .bind(org).bind(request.app_id).bind(request.stack_id).bind(request.machine_id).fetch_one(&mut **work.sql()).await?;
        let mut changed = false;
        if now >= request.deadline || !live {
            changed |= !work
                .run(
                    id,
                    Command::Cancel {
                        at: now,
                        timed_out: now >= request.deadline,
                    },
                )
                .await?
                .is_empty();
        }
        let connected: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grund_machine_presence WHERE machine_id=$1 AND last_seen_at>clock_timestamp()-interval '30 seconds')")
                .bind(request.machine_id).fetch_one(&mut **work.sql()).await?;
        if !connected {
            changed |= !work
                .run(id, Command::Uncertain { at: now })
                .await?
                .is_empty();
        }
        if changed {
            self.state
                .agents()
                .publish_in(work.sql(), request.machine_id)
                .await?;
        }
        work.commit().await?;
        if changed {
            self.state.wakes.documents_changed();
        }
        Ok(())
    }
}

fn observed_start(
    value: Option<&buffa_types::google::protobuf::Timestamp>,
    requested_at: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, Error> {
    value
        .map(time)
        .transpose()
        .map(|started| started.map(|at| at.max(requested_at)))
}

fn time(value: &buffa_types::google::protobuf::Timestamp) -> Result<DateTime<Utc>, Error> {
    if !(0..1_000_000_000).contains(&value.nanos) {
        return Err(Error::Invalid);
    }
    DateTime::from_timestamp(value.seconds, value.nanos as u32).ok_or(Error::Invalid)
}

pub fn status(value: proto::RunState) -> Option<Status> {
    use proto::RunState::*;
    Some(match value {
        RUN_STATE_UNSPECIFIED => return None,
        RUN_STATE_PENDING => Status::Pending,
        RUN_STATE_RUNNING => Status::Running,
        RUN_STATE_CANCELLING => Status::Cancelling,
        RUN_STATE_SUCCEEDED => Status::Succeeded,
        RUN_STATE_FAILED => Status::Failed,
        RUN_STATE_CANCELLED => Status::Cancelled,
        RUN_STATE_TIMED_OUT => Status::TimedOut,
        RUN_STATE_NOT_STARTED => Status::NotStarted,
        RUN_STATE_UNKNOWN => Status::Unknown,
    })
}

/// Builds a separate signed desired collection without argument bodies or service endpoints.
pub async fn desired(
    connection: &mut PgConnection,
    machine: Uuid,
) -> anyhow::Result<Vec<agent::DesiredRun>> {
    let mut desired = Vec::new();
    for row in store::outstanding_machine(&mut *connection, machine).await? {
        let run = row.state.0;
        let request = run
            .request
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("run request missing"))?;
        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM grund_apps a JOIN grund_stacks s ON s.organisation_id=a.organisation_id AND s.stack_id=$3 JOIN grund_machines m ON m.machine_id=$4 JOIN grund_organisations o ON o.organisation_id=a.organisation_id WHERE a.organisation_id=$1 AND a.app_id=$2 AND a.deleted_at IS NULL AND o.deleted_at IS NULL AND s.status NOT IN ('deleting','deleted') AND m.pool_organisation_id=$1 AND m.state IN ('active','leased'))")
            .bind(request.organisation_id).bind(request.app_id).bind(request.stack_id).bind(machine).fetch_one(&mut *connection).await?;
        let mut replica = super::agents::replica_message(&apps::PlacedRow {
            replica_id: row.run_id,
            app_id: request.app_id,
            app_name: request.app_name.clone(),
            slot: 0,
            release: request.release.number as i32,
            placement: 0,
            state: "running".into(),
            spec: Json(request.release.spec.clone()),
            image_digest: request.release.image_digest.clone(),
            secret_versions: Json(request.release.secret_versions.clone()),
        });
        replica.command.clear();
        replica.hostnames.clear();
        replica.ports.clear();
        replica.check = Default::default();
        replica.volumes.clear();
        replica.stack_search = format!("{}.grund.internal", request.stack_name);
        replica.stop = agent::ReplicaStop {
            signal: "SIGTERM".into(),
            grace_seconds: 10,
            ..Default::default()
        }
        .into();
        desired.push(agent::DesiredRun {
            run_id: row.run_id.to_string(),
            attempt_id: request.attempt_id.to_string(),
            replica: replica.into(),
            deadline: buffa_types::google::protobuf::Timestamp::from_unix(
                request.deadline.timestamp(),
                request.deadline.timestamp_subsec_nanos() as i32,
            )
            .into(),
            cancel: run.cancel_requested_at.is_some() || Utc::now() >= request.deadline || !live,
            ..Default::default()
        });
    }
    Ok(desired)
}

pub trait RunsState {
    fn runs(&self) -> Runs;
}
impl RunsState for State {
    fn runs(&self) -> Runs {
        Runs {
            state: self.clone(),
        }
    }
}

pub struct Worker {
    state: State,
}
impl Worker {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}
impl notmad::Component for Worker {
    fn info(&self) -> notmad::ComponentInfo {
        "grund/runs".into()
    }
    async fn run(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<(), notmad::MadError> {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                _ = tick.tick() => if let Err(error) = self.state.runs().reconcile().await { tracing::warn!(reason=error.reason(), "run reconciliation failed; retrying next tick"); }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa_types::google::protobuf::Timestamp;

    #[test]
    fn approximate_host_start_times_cannot_precede_the_committed_request() {
        let requested = DateTime::from_timestamp(1_000, 700_000_000).unwrap();
        let rounded_boot_start = Timestamp::from_unix(1_000, 200_000_000);
        assert_eq!(
            observed_start(Some(&rounded_boot_start), requested).unwrap(),
            Some(requested)
        );
        let later = Timestamp::from_unix(1_000, 800_000_000);
        assert_eq!(
            observed_start(Some(&later), requested).unwrap(),
            Some(DateTime::from_timestamp(1_000, 800_000_000).unwrap())
        );
        assert_eq!(observed_start(None, requested).unwrap(), None);
    }
}
