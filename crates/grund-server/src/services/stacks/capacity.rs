use super::*;

#[cfg(test)]
mod tests;

impl Stacks {
    pub(super) async fn transition_reservation(
        &self,
        connection: &mut PgConnection,
        org: Uuid,
        revision: &Revision,
        stack_id: Option<Uuid>,
    ) -> Result<(u64, u64), Error> {
        let live: Vec<(Uuid, i64, i64, i32)> = if let Some(id) = stack_id {
            sqlx::query_as("SELECT r.app_id,(rel.spec->>'memory_mib')::bigint,(rel.spec->>'cpu_millis')::bigint,r.release FROM grund_replicas r JOIN grund_releases rel ON rel.app_id=r.app_id AND rel.number=r.release JOIN grund_stack_members sm ON sm.app_id=r.app_id AND sm.organisation_id=r.organisation_id WHERE sm.organisation_id=$1 AND sm.stack_id=$2")
                .bind(org).bind(id).fetch_all(&mut *connection).await?
        } else {
            Vec::new()
        };
        let previous = if let Some(id) = stack_id {
            store::get(&mut *connection, org, id)
                .await?
                .map(|r| r.state.0)
        } else {
            None
        };
        reservation(revision, previous.as_ref(), &live)
    }
}

fn reservation(
    revision: &Revision,
    previous: Option<&Stack>,
    live: &[(Uuid, i64, i64, i32)],
) -> Result<(u64, u64), Error> {
    let mut current_memory = live
        .iter()
        .map(|(_, m, _, _)| (*m).max(0) as u64)
        .sum::<u64>();
    let mut current_cpu = live
        .iter()
        .map(|(_, _, c, _)| (*c).max(0) as u64)
        .sum::<u64>();
    let active = previous
        .and_then(|s| s.operation.as_ref())
        .filter(|o| o.target_revision == revision.number);
    let ordered;
    let planned: &[String] = match active {
        Some(op) => &op.order[op.cursor..],
        None => {
            ordered = order(revision)?;
            &ordered
        }
    };
    for (name, service) in &revision.services {
        if planned.contains(name) {
            continue;
        }
        let old_memory = live
            .iter()
            .filter(|(app, _, _, _)| *app == service.app_id)
            .map(|(_, m, _, _)| (*m).max(0) as u64)
            .sum::<u64>();
        let old_cpu = live
            .iter()
            .filter(|(app, _, _, _)| *app == service.app_id)
            .map(|(_, _, c, _)| (*c).max(0) as u64)
            .sum::<u64>();
        current_memory += (service.release.spec.memory_mib * u64::from(service.settings.copies))
            .saturating_sub(old_memory);
        current_cpu += (u64::from(service.release.spec.cpu_millis)
            * u64::from(service.settings.copies))
        .saturating_sub(old_cpu);
    }
    let mut peak_memory = current_memory;
    let mut peak_cpu = current_cpu;
    for name in planned {
        let Some(service) = revision.services.get(name) else {
            if let Some(retained) = previous.and_then(|state| {
                state
                    .revisions
                    .values()
                    .rev()
                    .find_map(|r| r.services.get(name))
            }) {
                for (_, memory, cpu, _) in
                    live.iter().filter(|(app, _, _, _)| *app == retained.app_id)
                {
                    current_memory = current_memory.saturating_sub((*memory).max(0) as u64);
                    current_cpu = current_cpu.saturating_sub((*cpu).max(0) as u64);
                }
            }
            continue;
        };
        let owned: Vec<_> = live
            .iter()
            .filter(|(app, _, _, _)| *app == service.app_id)
            .collect();
        let old_memory = owned
            .iter()
            .map(|(_, m, _, _)| (*m).max(0) as u64)
            .sum::<u64>();
        let old_cpu = owned
            .iter()
            .map(|(_, _, c, _)| (*c).max(0) as u64)
            .sum::<u64>();
        let new_memory = service.release.spec.memory_mib * u64::from(service.settings.copies);
        let new_cpu =
            u64::from(service.release.spec.cpu_millis) * u64::from(service.settings.copies);
        let replacing = previous.is_none_or(|state| {
            if let Some(op) = state
                .operation
                .as_ref()
                .filter(|o| o.target_revision == revision.number)
            {
                return op.order.contains(name);
            }
            state
                .revisions
                .get(&state.applied_revision)
                .and_then(|r| r.services.get(name))
                .is_none_or(|s| {
                    s.release.spec != service.release.spec
                        || s.release.image_digest != service.release.image_digest
                        || s.settings != service.settings
                })
        });
        let (transition_memory, transition_cpu) =
            if service.exclusive || owned.is_empty() || !replacing {
                (old_memory.max(new_memory), old_cpu.max(new_cpu))
            } else {
                let count = service.settings.copies as usize;
                let target = active.and_then(|op| {
                    op.releases.get(name).copied().or_else(|| {
                        (!matches!(op.kind, Kind::Restart | Kind::Restore))
                            .then_some(service.release.number)
                    })
                });
                let already_created = target.map_or(0, |target| {
                    owned
                        .iter()
                        .filter(|(_, _, _, release)| *release == target as i32)
                        .count()
                });
                let missing = count.saturating_sub(already_created);
                let bound = count + service.settings.rollout.max_surge as usize;
                let mut memory: Vec<_> = owned
                    .iter()
                    .map(|(_, m, _, _)| (*m).max(0) as u64)
                    .chain(std::iter::repeat_n(
                        service.release.spec.memory_mib,
                        missing,
                    ))
                    .collect();
                let mut cpu: Vec<_> = owned
                    .iter()
                    .map(|(_, _, c, _)| (*c).max(0) as u64)
                    .chain(std::iter::repeat_n(
                        u64::from(service.release.spec.cpu_millis),
                        missing,
                    ))
                    .collect();
                memory.sort_unstable_by(|a, b| b.cmp(a));
                cpu.sort_unstable_by(|a, b| b.cmp(a));
                (
                    old_memory.max(memory.into_iter().take(bound).sum()),
                    old_cpu.max(cpu.into_iter().take(bound).sum()),
                )
            };
        peak_memory =
            peak_memory.max(current_memory.saturating_sub(old_memory) + transition_memory);
        peak_cpu = peak_cpu.max(current_cpu.saturating_sub(old_cpu) + transition_cpu);
        current_memory = current_memory.saturating_sub(old_memory) + new_memory;
        current_cpu = current_cpu.saturating_sub(old_cpu) + new_cpu;
    }
    Ok((peak_memory, peak_cpu))
}
