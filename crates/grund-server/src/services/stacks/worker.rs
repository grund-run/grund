use super::*;
use grund_domain::volume::VolumeCommand;
use tokio_util::sync::CancellationToken;

const RECONCILE_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

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
        "grund/stacks".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), notmad::MadError> {
        let mut tick = tokio::time::interval(RECONCILE_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                _ = tick.tick() => {
                    if let Err(error) = self.state.stacks().reconcile_all().await {
                        tracing::warn!(error = %error, "stack coordinator pass failed; retrying next tick");
                    }
                }
            }
        }
    }
}

impl Stacks {
    pub async fn reconcile_all(&self) -> Result<(), Error> {
        let mut after = None;
        loop {
            let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
                "SELECT organisation_id,stack_id FROM grund_stacks WHERE status <> 'deleted' \
                 AND ($1::uuid IS NULL OR (organisation_id,stack_id)>($1,$2)) \
                 ORDER BY organisation_id,stack_id LIMIT 100",
            )
            .bind(after.map(|(org, _): (Uuid, Uuid)| org))
            .bind(after.map(|(_, id)| id))
            .fetch_all(&self.state.pool)
            .await?;
            if rows.is_empty() {
                return Ok(());
            }
            after = rows.last().copied();
            for (org, id) in rows {
                if let Err(error) = self.reconcile_one(org, id).await {
                    tracing::warn!(stack_id = %id, reason = error.reason(), "stack turn failed; retrying next tick");
                }
            }
        }
    }

    pub async fn reconcile_one(&self, org: Uuid, id: Uuid) -> Result<(), Error> {
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), "stack-coordinator").await?;
        self.lock(&mut work, org).await?;
        work.allow_stack(id);
        let stack = work.load_stack(id).await?;
        if !stack.exists || stack.organisation_id != org {
            return Err(Error::NotFound);
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **work.sql())
            .await?;
        let Some(mut op) = stack.operation.clone() else {
            if !matches!(stack.status, Status::Ready | Status::Degraded) {
                return Ok(());
            }
            let revision = stack
                .revisions
                .get(&stack.applied_revision)
                .context("applied stack revision exists")?;
            if self
                .group_recovery_allowed(&mut work, &stack, id, revision, now)
                .await?
            {
                let mut recovery = operation(
                    Kind::Restart,
                    revision.number,
                    revision.number,
                    order(revision)?,
                    now,
                );
                recovery.failure = Some("machine_unreachable".into());
                work.stack(
                    id,
                    Command::Operate {
                        operation: recovery,
                        at: now,
                    },
                )
                .await?;
                return self.finish_turn(work, org, id, stack.machine_id).await;
            }
            let ready = self
                .maintain_gates(&mut work, &stack, id, revision, now)
                .await?;
            work.stack(
                id,
                Command::Health {
                    status: if ready {
                        Status::Ready
                    } else {
                        Status::Degraded
                    },
                },
            )
            .await?;
            return self.finish_turn(work, org, id, stack.machine_id).await;
        };
        let revision = stack
            .revisions
            .get(&op.target_revision)
            .context("target stack revision exists")?
            .clone();

        if op.kind == Kind::Delete || op.halting {
            self.stop_turn(&mut work, &stack, id, &revision, &mut op, now)
                .await?;
            return self.finish_turn(work, org, id, stack.machine_id).await;
        }
        if now >= op.deadline {
            self.fail_turn(&mut work, &stack, id, op, "operation_deadline", now)
                .await?;
            return self.finish_turn(work, org, id, stack.machine_id).await;
        }
        if let Some(name) = op.order.get(op.cursor).cloned()
            && !revision.services.contains_key(&name)
        {
            let service = retained_service(&stack, &name).context("retained service exists")?;
            if op.step != Step::Stopping {
                store::gate(work.sql(), org, id, &name, false, true, Some(op.id)).await?;
                op.step = Step::Stopping;
            } else if work.load_app(service.app_id).await?.replicas.is_empty() {
                let deadline = now
                    + Duration::from_std(self.state.config.volume_delete_window)
                        .map_err(anyhow::Error::from)?;
                self.delete_child(&mut work, org, service.app_id, now, deadline)
                    .await?;
                op.cursor += 1;
                op.step = Step::Pending;
            }
            work.stack(
                id,
                Command::Advance {
                    operation: op.clone(),
                    status: operation_status(&op),
                    machine_id: stack.machine_id,
                    failure: op.failure.clone(),
                },
            )
            .await?;
            return self.finish_turn(work, org, id, stack.machine_id).await;
        }
        let recovering = self
            .group_recovery_allowed(&mut work, &stack, id, &revision, now)
            .await?;
        if recovering {
            let placement = self
                .choose_machine(work.sql(), org, &revision, None, Some(id))
                .await?;
            let Some(machine) = placement.machine else {
                work.stack(
                    id,
                    Command::Advance {
                        operation: op,
                        status: Status::Waiting,
                        machine_id: stack.machine_id,
                        failure: Some("machine_unreachable".into()),
                    },
                )
                .await?;
                return self.finish_turn(work, org, id, stack.machine_id).await;
            };
            let machine_name: String =
                sqlx::query_scalar("SELECT pool_name FROM grund_machines WHERE machine_id=$1")
                    .bind(machine)
                    .fetch_one(&mut **work.sql())
                    .await?;
            for service in revision.services.values() {
                let app = work.load_app(service.app_id).await?;
                if app.deleted {
                    continue;
                }
                let mut settings = app.settings.clone();
                settings.machines = vec![machine_name.clone()];
                settings.auto_rollback = false;
                work.app(
                    service.app_id,
                    AppCommand::Configure {
                        actor: Uuid::nil(),
                        settings,
                        at: now,
                    },
                )
                .await?;
            }
            work.stack(
                id,
                Command::Advance {
                    operation: op.clone(),
                    status: operation_status(&op),
                    machine_id: Some(machine),
                    failure: Some("machine_unreachable".into()),
                },
            )
            .await?;
            self.reserve(&mut work, org, id, placement.memory, placement.cpu)
                .await?;
            return self.finish_turn(work, org, id, Some(machine)).await;
        }
        if op.cursor >= op.order.len() {
            if self.revision_ready(&mut work, &revision, &op, now).await? {
                work.stack(
                    id,
                    Command::Complete {
                        operation_id: op.id,
                        applied_revision: revision.number,
                        status: Status::Ready,
                        purge_after: None,
                        failure: op.failure.clone(),
                    },
                )
                .await?;
                let (memory, cpu) = totals(&revision);
                self.reserve(&mut work, org, id, memory, cpu).await?;
            }
            return self.finish_turn(work, org, id, stack.machine_id).await;
        }
        let placement = self
            .choose_machine(work.sql(), org, &revision, stack.machine_id, Some(id))
            .await?;
        let Some(machine) = placement.machine else {
            work.stack(
                id,
                Command::Advance {
                    operation: op,
                    status: Status::Waiting,
                    machine_id: stack.machine_id,
                    failure: stack.failure.clone(),
                },
            )
            .await?;
            work.commit().await?;
            return Ok(());
        };
        self.reserve(&mut work, org, id, placement.memory, placement.cpu)
            .await?;
        if stack.machine_id != Some(machine) || stack.status == Status::Waiting {
            work.stack(
                id,
                Command::Advance {
                    operation: op.clone(),
                    status: operation_status(&op),
                    machine_id: Some(machine),
                    failure: op.failure.clone(),
                },
            )
            .await?;
        }
        self.maintain_active_gates(&mut work, org, id, &revision, &op, now)
            .await?;
        let name = op.order[op.cursor].clone();
        let service = revision
            .services
            .get(&name)
            .context("target service exists")?;
        let app = work.load_app(service.app_id).await?;
        if op.step == Step::Pending {
            if !op.compensating
                && !self
                    .dependencies_ready(&mut work, &revision, &op, service, now)
                    .await?
            {
                return self.finish_turn(work, org, id, Some(machine)).await;
            }
            let machine_name: String =
                sqlx::query_scalar("SELECT pool_name FROM grund_machines WHERE machine_id=$1")
                    .bind(machine)
                    .fetch_one(&mut **work.sql())
                    .await?;
            if app.deleted {
                self.restore_child(&mut work, org, service.app_id, Uuid::nil(), now)
                    .await?;
                if revision
                    .public_service
                    .as_ref()
                    .and_then(|name| revision.services.get(name))
                    .is_some_and(|public| public.app_id == service.app_id)
                {
                    self.state
                        .domains()
                        .rebind_stack_public_in(
                            &mut work,
                            Uuid::nil(),
                            org,
                            id,
                            Some(service.app_id),
                            Some(service.app_id),
                            &stack.name,
                        )
                        .await
                        .map_err(anyhow::Error::from)?;
                }
            }
            let mut settings = service.settings.clone();
            settings.machines = vec![machine_name];
            settings.auto_rollback = false;
            work.app(
                service.app_id,
                AppCommand::Configure {
                    actor: Uuid::nil(),
                    settings,
                    at: now,
                },
            )
            .await?;
            self.state
                .volumes()
                .resolve_release_in(
                    &mut work,
                    org,
                    service.app_id,
                    &service.release.spec.volumes,
                )
                .await
                .map_err(anyhow::Error::from)?;
            let next = app.latest_release().map_or(1, |r| r.number + 1);
            let number = op.releases.get(&name).copied().unwrap_or(next);
            if next != number {
                return Err(Error::Conflict);
            }
            work.app(service.app_id, release_command(&service.release, now))
                .await?;
            op.releases.insert(name.clone(), number);
            store::gate(work.sql(), org, id, &name, true, false, Some(op.id)).await?;
            op.step = Step::Applying;
            work.stack(
                id,
                Command::Advance {
                    operation: op.clone(),
                    status: operation_status(&op),
                    machine_id: Some(machine),
                    failure: op.failure.clone(),
                },
            )
            .await?;
        } else if app.halted {
            self.fail_turn(&mut work, &stack, id, op, "service_readiness", now)
                .await?;
        } else {
            let number = execution_release(&op, &name, service);
            if self
                .service_ready(&mut work, service, number, now, true)
                .await?
            {
                op.cursor += 1;
                op.step = Step::Pending;
                work.stack(
                    id,
                    Command::Advance {
                        operation: op.clone(),
                        status: operation_status(&op),
                        machine_id: Some(machine),
                        failure: op.failure.clone(),
                    },
                )
                .await?;
            }
        }
        self.finish_turn(work, org, id, Some(machine)).await
    }

    async fn group_recovery_allowed(
        &self,
        work: &mut Work<'_>,
        stack: &Stack,
        id: Uuid,
        revision: &Revision,
        now: DateTime<Utc>,
    ) -> Result<bool, Error> {
        let Some(machine_id) = stack.machine_id else {
            return Ok(false);
        };
        let Some(machine) = machines::machine(&mut **work.sql(), machine_id).await? else {
            return Ok(false);
        };
        let seen = self.state.hearing.seen(machine.last_seen_at);
        if !recovery_due(seen, now, 0) {
            return Ok(false);
        }
        let retained_volume: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM grund_volumes v JOIN grund_stack_members m \
             ON m.organisation_id=v.organisation_id AND m.app_id=v.app_id \
             WHERE m.organisation_id=$1 AND m.stack_id=$2 AND v.status<>'deleted')",
        )
        .bind(stack.organisation_id)
        .bind(id)
        .fetch_one(&mut **work.sql())
        .await?;
        if retained_volume
            || revision
                .services
                .values()
                .any(|service| service.exclusive || !service.release.spec.volumes.is_empty())
        {
            return Ok(false);
        }
        for member in store::members(&mut **work.sql(), stack.organisation_id, id).await? {
            let service = revision
                .services
                .get(&member.service)
                .or_else(|| retained_service(stack, &member.service))
                .context("owned service exists in revision history")?;
            let app = work.load_app(member.app_id).await?;
            if member.exclusive
                || service.exclusive
                || !service.release.spec.volumes.is_empty()
                || app
                    .target()
                    .and_then(|number| app.release(number))
                    .is_some_and(|release| !release.spec.volumes.is_empty())
                || !recovery_due(seen, now, app.settings.reschedule_after_seconds)
                || !recovery_due(seen, now, service.settings.reschedule_after_seconds)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) async fn restore_child(
        &self,
        work: &mut Work<'_>,
        org: Uuid,
        app_id: Uuid,
        actor: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        let app = work.load_app(app_id).await?;
        if !app.deleted {
            return Ok(());
        }
        for volume in grund_store::volumes::app_volumes(&mut **work.sql(), org, app_id).await? {
            if volume.status == "pending_deletion" && volume.purge_after == app.purge_after {
                work.volume(volume.volume_id, VolumeCommand::Restore { at: now })
                    .await?;
            }
        }
        work.app(app_id, AppCommand::Restore { actor, at: now })
            .await?;
        Ok(())
    }

    async fn delete_child(
        &self,
        work: &mut Work<'_>,
        org: Uuid,
        app_id: Uuid,
        now: DateTime<Utc>,
        deadline: DateTime<Utc>,
    ) -> Result<(), Error> {
        let app = work.load_app(app_id).await?;
        if !app.replicas.is_empty() {
            return Err(Error::Conflict);
        }
        if app.deleted {
            if app.purge_after.is_none() {
                return Ok(());
            }
            work.app_decide(app_id, |app| {
                Ok((
                    if app.purge_after.is_some_and(|due| due < deadline) {
                        vec![grund_domain::app::AppEvent::Deleted {
                            deleted_by: Uuid::nil(),
                            deleted_at: now,
                            purge_after: Some(deadline),
                        }]
                    } else {
                        Vec::new()
                    },
                    (),
                ))
            })
            .await?;
        } else {
            work.app(
                app_id,
                AppCommand::Delete {
                    actor: Uuid::nil(),
                    at: now,
                    purge_after: deadline,
                },
            )
            .await?;
        }
        self.state
            .volumes()
            .delete_app_in(work, org, app_id, deadline)
            .await
            .map_err(anyhow::Error::from)?;
        sqlx::query("DELETE FROM grund_volume_backup_attempts WHERE organisation_id=$1 AND app_id=$2 AND status IN ('pending','leased')")
            .bind(org).bind(app_id).execute(&mut **work.sql()).await?;
        self.state
            .domains()
            .unbind_app_in(work, Uuid::nil(), app_id)
            .await?;
        Ok(())
    }

    async fn reserve(
        &self,
        work: &mut Work<'_>,
        org: Uuid,
        id: Uuid,
        memory: u64,
        cpu: u64,
    ) -> Result<(), Error> {
        sqlx::query("UPDATE grund_stacks SET reserved_memory_mib=$3,reserved_cpu_millis=$4 WHERE organisation_id=$1 AND stack_id=$2")
            .bind(org).bind(id).bind(i64::try_from(memory).context("stack memory fits bigint")?)
            .bind(i64::try_from(cpu).context("stack CPU fits bigint")?).execute(&mut **work.sql()).await?;
        Ok(())
    }

    async fn finish_turn(
        &self,
        mut work: Work<'_>,
        org: Uuid,
        id: Uuid,
        machine: Option<Uuid>,
    ) -> Result<(), Error> {
        if !work.has_changes() {
            work.commit().await?;
            return Ok(());
        }
        let mut touched: BTreeSet<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT r.machine_id FROM grund_replicas r JOIN grund_stack_members m \
             ON m.app_id=r.app_id AND m.organisation_id=r.organisation_id WHERE m.organisation_id=$1 AND m.stack_id=$2 \
             UNION SELECT DISTINCT v.machine_id FROM grund_volumes v JOIN grund_stack_members m \
             ON m.app_id=v.app_id AND m.organisation_id=v.organisation_id WHERE m.organisation_id=$1 AND m.stack_id=$2 AND v.machine_id IS NOT NULL")
            .bind(org).bind(id).fetch_all(&mut **work.sql()).await?.into_iter().collect();
        touched.extend(machine);
        for machine in touched {
            self.state.agents().publish_in(work.sql(), machine).await?;
        }
        work.commit().await?;
        self.state.wakes.apps_changed();
        self.state.wakes.documents_changed();
        Ok(())
    }

    async fn service_ready(
        &self,
        work: &mut Work<'_>,
        service: &Service,
        number: u32,
        now: DateTime<Utc>,
        old_gone: bool,
    ) -> Result<bool, Error> {
        let app = work.load_app(service.app_id).await?;
        if app.deleted || app.halted || app.current_release != Some(number) || app.rollout.is_some()
        {
            return Ok(false);
        }
        let rows = apps::app_replicas(&mut **work.sql(), service.app_id).await?;
        Ok(replicas_ready(
            &rows,
            number,
            service.settings.copies,
            service.settings.rollout.min_ready_seconds,
            now,
            old_gone,
            |seen| self.state.hearing.seen(seen),
        ))
    }

    async fn dependencies_ready(
        &self,
        work: &mut Work<'_>,
        revision: &Revision,
        op: &Operation,
        service: &Service,
        now: DateTime<Utc>,
    ) -> Result<bool, Error> {
        for name in &service.depends_on {
            let dependency = revision
                .services
                .get(name)
                .context("validated dependency exists")?;
            let number = self.effective_release(work, op, name, dependency).await?;
            if !self
                .service_ready(work, dependency, number, now, false)
                .await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn revision_ready(
        &self,
        work: &mut Work<'_>,
        revision: &Revision,
        op: &Operation,
        now: DateTime<Utc>,
    ) -> Result<bool, Error> {
        for (name, service) in &revision.services {
            let number = self.effective_release(work, op, name, service).await?;
            if !self.service_ready(work, service, number, now, true).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn effective_release(
        &self,
        work: &mut Work<'_>,
        op: &Operation,
        name: &str,
        service: &Service,
    ) -> Result<u32, Error> {
        let app = work.load_app(service.app_id).await?;
        Ok(service.execution_release(name, Some(op), &app))
    }

    async fn maintain_active_gates(
        &self,
        work: &mut Work<'_>,
        org: Uuid,
        id: Uuid,
        revision: &Revision,
        op: &Operation,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        for member in store::members(&mut **work.sql(), org, id).await? {
            let Some(service) = revision.services.get(&member.service) else {
                continue;
            };
            let turn_reached = op
                .order
                .iter()
                .position(|name| name == &member.service)
                .is_none_or(|position| position <= op.cursor);
            let enabled = turn_reached
                && (op.compensating
                    || self
                        .dependencies_ready(work, revision, op, service, now)
                        .await?);
            if member.enabled != enabled || member.stopping || member.operation_id != Some(op.id) {
                store::gate(
                    work.sql(),
                    org,
                    id,
                    &member.service,
                    enabled,
                    false,
                    Some(op.id),
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn maintain_gates(
        &self,
        work: &mut Work<'_>,
        stack: &Stack,
        id: Uuid,
        revision: &Revision,
        now: DateTime<Utc>,
    ) -> Result<bool, Error> {
        let mut health = BTreeMap::new();
        for (name, service) in &revision.services {
            let app = work.load_app(service.app_id).await?;
            let number = app.target().unwrap_or(service.release.number);
            health.insert(
                name.clone(),
                self.service_ready(work, service, number, now, false)
                    .await?,
            );
        }
        for member in store::members(&mut **work.sql(), stack.organisation_id, id).await? {
            if let Some(service) = revision.services.get(&member.service) {
                let enabled = service
                    .depends_on
                    .iter()
                    .all(|name| health.get(name) == Some(&true));
                if member.enabled != enabled || member.stopping {
                    store::gate(
                        work.sql(),
                        stack.organisation_id,
                        id,
                        &member.service,
                        enabled,
                        false,
                        member.operation_id,
                    )
                    .await?;
                }
            }
        }
        Ok(health.values().all(|ready| *ready))
    }

    async fn stop_turn(
        &self,
        work: &mut Work<'_>,
        stack: &Stack,
        id: Uuid,
        revision: &Revision,
        op: &mut Operation,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        if op.cursor < op.order.len() {
            let name = op.order[op.cursor].clone();
            let service = revision
                .services
                .get(&name)
                .or_else(|| retained_service(stack, &name))
                .context("stopped service exists")?;
            let app = work.load_app(service.app_id).await?;
            if op.step != Step::Stopping {
                store::gate(
                    work.sql(),
                    stack.organisation_id,
                    id,
                    &name,
                    false,
                    true,
                    Some(op.id),
                )
                .await?;
                op.step = Step::Stopping;
            } else if app.replicas.is_empty() {
                op.cursor += 1;
                op.step = Step::Pending;
            }
            work.stack(
                id,
                Command::Advance {
                    operation: op.clone(),
                    status: if op.kind == Kind::Delete {
                        Status::Deleting
                    } else {
                        Status::RollingBack
                    },
                    machine_id: stack.machine_id,
                    failure: op.failure.clone(),
                },
            )
            .await?;
        } else {
            let deleting = op.kind == Kind::Delete;
            let purge_after = if deleting {
                let deadline = now
                    + Duration::from_std(self.state.config.volume_delete_window)
                        .map_err(anyhow::Error::from)?;
                let deadline: DateTime<Utc> = sqlx::query_scalar(
                    "SELECT GREATEST($3,MAX(a.purge_after),MAX(v.purge_after)) \
                     FROM grund_stack_members member \
                     JOIN grund_apps a ON a.organisation_id=member.organisation_id AND a.app_id=member.app_id \
                     LEFT JOIN grund_volumes v ON v.organisation_id=member.organisation_id AND v.app_id=member.app_id \
                     WHERE member.organisation_id=$1 AND member.stack_id=$2",
                )
                .bind(stack.organisation_id)
                .bind(id)
                .bind(deadline)
                .fetch_one(&mut **work.sql())
                .await?;
                for member in store::members(&mut **work.sql(), stack.organisation_id, id).await? {
                    self.delete_child(work, stack.organisation_id, member.app_id, now, deadline)
                        .await?;
                }
                Some(deadline)
            } else {
                None
            };
            work.stack(
                id,
                Command::Complete {
                    operation_id: op.id,
                    applied_revision: stack.applied_revision,
                    status: if deleting {
                        Status::Deleted
                    } else {
                        Status::Halted
                    },
                    purge_after,
                    failure: op.failure.clone(),
                },
            )
            .await?;
            self.reserve(work, stack.organisation_id, id, 0, 0).await?;
        }
        Ok(())
    }

    async fn fail_turn(
        &self,
        work: &mut Work<'_>,
        stack: &Stack,
        id: Uuid,
        mut op: Operation,
        category: &str,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        if op.compensating {
            work.stack(
                id,
                Command::Complete {
                    operation_id: op.id,
                    applied_revision: stack.applied_revision,
                    status: Status::Halted,
                    purge_after: None,
                    failure: Some("rollback_failed".into()),
                },
            )
            .await?;
            return Ok(());
        }
        reverse_attempted(&mut op);
        op.failure = Some(category.into());
        op.compensating = true;
        op.cursor = 0;
        op.step = Step::Pending;
        op.deadline = now + Duration::seconds(1800);
        if op.previous_revision == 0 {
            op.order = order(
                stack
                    .revisions
                    .get(&op.target_revision)
                    .context("failed target revision exists")?,
            )?;
            op.order.reverse();
            op.halting = true;
            work.stack(
                id,
                Command::Advance {
                    operation: op,
                    status: Status::RollingBack,
                    machine_id: stack.machine_id,
                    failure: Some(category.into()),
                },
            )
            .await?;
            return Ok(());
        }
        let mut prior = stack
            .revisions
            .get(&op.previous_revision)
            .context("prior complete revision exists")?
            .clone();
        let target = stack
            .revisions
            .get(&op.target_revision)
            .context("failed target revision exists")?;
        let mut removed = order(target)?;
        removed.reverse();
        removed.retain(|name| !prior.services.contains_key(name));
        removed.extend(
            op.order
                .iter()
                .filter(|name| prior.services.contains_key(*name))
                .cloned(),
        );
        op.order = removed;
        prior.number = stack.desired_revision + 1;
        prior.rollback_of = Some(op.previous_revision);
        prior.created_at = now;
        prior.created_by = Uuid::nil();
        op.kind = Kind::Rollback;
        op.target_revision = prior.number;
        op.releases.clear();
        for name in &op.order {
            if let Some(service) = prior.services.get_mut(name) {
                let app = work.load_app(service.app_id).await?;
                service.release.number = app.latest_release().map_or(1, |r| r.number + 1);
                op.releases.insert(name.clone(), service.release.number);
            }
        }
        let previous_public = stack
            .revisions
            .get(&stack.desired_revision)
            .and_then(|revision| {
                revision
                    .public_service
                    .as_ref()
                    .and_then(|name| revision.services.get(name))
            })
            .map(|service| service.app_id);
        let restored_public = prior
            .public_service
            .as_ref()
            .and_then(|name| prior.services.get(name))
            .map(|service| service.app_id);
        work.stack(
            id,
            Command::Compensate {
                operation_id: op.id,
                revision: prior,
                operation: op,
            },
        )
        .await?;
        self.state
            .domains()
            .rebind_stack_public_in(
                work,
                Uuid::nil(),
                stack.organisation_id,
                id,
                previous_public,
                restored_public,
                &stack.name,
            )
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
}

fn operation_status(op: &Operation) -> Status {
    if op.compensating || op.kind == Kind::Rollback {
        Status::RollingBack
    } else {
        Status::Deploying
    }
}

fn reverse_attempted(op: &mut Operation) {
    op.order
        .truncate(op.cursor + usize::from(op.step != Step::Pending));
    op.order.reverse();
}
fn execution_release(op: &Operation, name: &str, service: &Service) -> u32 {
    op.releases
        .get(name)
        .copied()
        .unwrap_or(service.release.number)
}

fn retained_service<'a>(stack: &'a Stack, name: &str) -> Option<&'a Service> {
    stack
        .revisions
        .values()
        .rev()
        .find_map(|revision| revision.services.get(name))
}

fn recovery_due(seen: Option<DateTime<Utc>>, now: DateTime<Utc>, reschedule_seconds: u32) -> bool {
    seen.is_some_and(|seen| {
        let elapsed = now - seen;
        elapsed > grund_domain::app::placement::UNREACHABLE_AFTER
            && elapsed >= Duration::seconds(i64::from(reschedule_seconds))
    })
}

fn replica_ready(
    row: &apps::ReplicaRow,
    release: u32,
    min_ready: u32,
    now: DateTime<Utc>,
    seen: Option<DateTime<Utc>>,
) -> bool {
    row.release == release as i32
        && row.state == "running"
        && row.observed_state.as_deref() == Some("running")
        && row.ready == Some(true)
        && row
            .ready_since
            .is_some_and(|since| now - since >= Duration::seconds(i64::from(min_ready)))
        && seen.is_some_and(|seen| now - seen <= grund_domain::app::placement::UNREACHABLE_AFTER)
}

fn replicas_ready(
    rows: &[apps::ReplicaRow],
    release: u32,
    copies: u32,
    min_ready: u32,
    now: DateTime<Utc>,
    old_gone: bool,
    seen: impl Fn(Option<DateTime<Utc>>) -> Option<DateTime<Utc>>,
) -> bool {
    let ready = rows
        .iter()
        .filter(|row| replica_ready(row, release, min_ready, now, seen(row.last_seen_at)))
        .count();
    ready == copies as usize && (!old_gone || rows.len() == ready)
}

fn release_command(release: &Release, at: DateTime<Utc>) -> AppCommand {
    AppCommand::Release {
        actor: Uuid::nil(),
        spec: release.spec.clone(),
        image_digest: release.image_digest.clone(),
        platforms: release.platforms.clone(),
        exposed_ports: release.exposed_ports.clone(),
        secret_versions: release.secret_versions.clone(),
        source: release.source,
        external_release: release.external_release.clone(),
        request: None,
        rollback_of: release.rollback_of,
        note: release.note.clone(),
        rollout_id: Uuid::now_v7(),
        at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(step: Step, cursor: usize) -> Operation {
        let at = DateTime::from_timestamp(1_000, 0).unwrap();
        Operation {
            id: Uuid::from_u128(1),
            kind: Kind::Deploy,
            target_revision: 2,
            previous_revision: 1,
            order: vec!["database".into(), "worker".into(), "web".into()],
            cursor,
            step,
            started_at: at,
            deadline: at + Duration::seconds(1800),
            compensating: false,
            failure: None,
            releases: BTreeMap::new(),
            halting: false,
        }
    }

    fn replica(now: DateTime<Utc>) -> apps::ReplicaRow {
        apps::ReplicaRow {
            replica_id: Uuid::from_u128(2),
            app_id: Uuid::from_u128(3),
            machine_id: Uuid::from_u128(4),
            machine_name: Some("machine".into()),
            machine_pool: Some("organisation".into()),
            slot: 0,
            release: 2,
            state: "running".into(),
            placed_at: now - Duration::seconds(60),
            observed_state: Some("running".into()),
            ready: Some(true),
            ready_since: Some(now - Duration::seconds(10)),
            restarts: Some(0),
            last_exit_code: None,
            reason: None,
            observed_at: Some(now),
            last_seen_at: Some(now),
        }
    }

    #[test]
    fn compensation_reverses_started_services_without_starting_waiting_dependents() {
        let mut op = operation(Step::Applying, 1);
        reverse_attempted(&mut op);
        assert_eq!(op.order, vec!["worker", "database"]);
        let mut waiting = operation(Step::Pending, 1);
        reverse_attempted(&mut waiting);
        assert_eq!(waiting.order, vec!["database"]);
        let mut first = operation(Step::Pending, 0);
        reverse_attempted(&mut first);
        assert!(first.order.is_empty());
    }

    #[test]
    fn compensation_includes_a_removal_that_has_started_draining() {
        let mut op = operation(Step::Stopping, 0);
        reverse_attempted(&mut op);
        assert_eq!(op.order, vec!["database"]);
    }

    #[test]
    fn stateless_recovery_waits_for_both_unreachable_and_reschedule_thresholds() {
        let now = DateTime::from_timestamp(1_000, 0).unwrap();
        assert!(!recovery_due(None, now, 0));
        assert!(!recovery_due(Some(now - Duration::seconds(30)), now, 0));
        assert!(recovery_due(Some(now - Duration::seconds(31)), now, 0));
        assert!(!recovery_due(Some(now - Duration::seconds(59)), now, 60));
        assert!(recovery_due(Some(now - Duration::seconds(60)), now, 60));
        assert!(!recovery_due(Some(now + Duration::seconds(1)), now, 0));
    }

    #[test]
    fn dependency_readiness_requires_the_target_release_and_full_minimum_ready_duration() {
        let now = DateTime::from_timestamp(1_000, 0).unwrap();
        let mut row = replica(now);
        assert!(replica_ready(&row, 2, 10, now, Some(now)));
        assert!(!replica_ready(&row, 1, 10, now, Some(now)));
        row.ready_since = Some(now - Duration::seconds(9));
        assert!(!replica_ready(&row, 2, 10, now, Some(now)));
        row.ready_since = Some(now - Duration::seconds(10));
        row.state = "draining".into();
        assert!(!replica_ready(&row, 2, 10, now, Some(now)));
    }

    #[test]
    fn stale_machine_observations_do_not_unlock_dependents() {
        let now = DateTime::from_timestamp(1_000, 0).unwrap();
        let row = replica(now);
        assert!(!replica_ready(
            &row,
            2,
            10,
            now,
            Some(now - Duration::seconds(31))
        ));
        assert!(!replica_ready(&row, 2, 10, now, None));
    }

    #[test]
    fn a_ready_replacement_does_not_finish_while_an_old_generation_is_still_draining() {
        let now = DateTime::from_timestamp(1_000, 0).unwrap();
        let replacement = replica(now);
        let mut old = replica(now);
        old.replica_id = Uuid::from_u128(5);
        old.release = 1;
        old.state = "draining".into();
        old.observed_state = Some("exited".into());
        let mut rows = vec![replacement, old];
        assert!(!replicas_ready(&rows, 2, 1, 10, now, true, |seen| seen));
        rows.pop();
        assert!(replicas_ready(&rows, 2, 1, 10, now, true, |seen| seen));
    }
}
