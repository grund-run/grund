use super::*;

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

impl Stacks {
    fn fingerprint(&self, value: &impl Serialize) -> Result<Vec<u8>, Error> {
        let mut writer = Fingerprint(hmac::Context::with_key(&hmac::Key::new(
            hmac::HMAC_SHA256,
            &self.state.secret.derive("stack-requests"),
        )));
        serde_json::to_writer(&mut writer, value).map_err(anyhow::Error::from)?;
        Ok(writer.0.sign().as_ref().to_vec())
    }

    async fn replay(
        &self,
        connection: &mut PgConnection,
        org: Uuid,
        method: &str,
        request_key: &str,
        fingerprint: &[u8],
    ) -> Result<Option<StackView>, Error> {
        if !(1..=128).contains(&request_key.len())
            || !request_key
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(invalid(
                "idempotency_key",
                "use 1 to 128 printable ASCII characters",
            ));
        }
        let receipt:Option<(Vec<u8>,Json<StackView>)>=sqlx::query_as("SELECT fingerprint,response FROM grund_stack_requests WHERE organisation_id=$1 AND method=$2 AND request_key=$3 AND expires_at>clock_timestamp()")
            .bind(org).bind(method).bind(request_key).fetch_optional(connection).await?;
        match receipt {
            Some((digest, response)) if digest == fingerprint => Ok(Some(response.0)),
            Some(_) => Err(Error::IdempotencyConflict),
            None => Ok(None),
        }
    }

    async fn receipt(
        &self,
        work: &mut Work<'_>,
        org: Uuid,
        method: &str,
        request_key: &str,
        fingerprint: &[u8],
        response: &StackView,
    ) -> Result<(), Error> {
        sqlx::query("DELETE FROM grund_stack_requests WHERE organisation_id=$1 AND method=$2 AND request_key=$3 AND expires_at<=clock_timestamp()")
            .bind(org).bind(method).bind(request_key).execute(&mut **work.sql()).await?;
        sqlx::query("INSERT INTO grund_stack_requests(organisation_id,method,request_key,fingerprint,response) VALUES($1,$2,$3,$4,$5)")
            .bind(org).bind(method).bind(request_key).bind(fingerprint).bind(Json(response)).execute(&mut **work.sql()).await?;
        Ok(())
    }

    async fn pending(&self, work: &mut Work<'_>, org: Uuid, id: Uuid) -> Result<StackView, Error> {
        let row = store::get(&mut **work.sql(), org, id)
            .await?
            .ok_or(Error::NotFound)?;
        let state = row.state.0;
        let revision = state
            .revisions
            .get(&state.desired_revision)
            .ok_or(Error::NotFound)?;
        Ok(StackView {
            id,
            name: state.name.clone(),
            status: state.status.as_str().into(),
            version: row.stream_version,
            revision: state.desired_revision,
            machine_id: state.machine_id,
            address: None,
            services: self.service_views(work.sql(), &state, revision).await?,
            volumes: volume_views(&mut **work.sql(), &state, revision, id).await?,
            operation: state.operation.as_ref().map(|o| o.id.to_string()),
            failure: state.failure.clone(),
            yaml: revision.yaml.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn deploy(
        &self,
        actor: Uuid,
        org: Uuid,
        yaml: &str,
        selected: Option<&str>,
        refresh: Option<&str>,
        expected: Option<i64>,
        request_key: &str,
        secrets: Vec<InputSecret>,
        mut confirmed_removals: Vec<String>,
        allowed_apps: Option<&[String]>,
    ) -> Result<StackView, Error> {
        if let Some(apps) = allowed_apps {
            let name = stack::parse(yaml)?.name;
            let row = store::by_name(&self.state.pool, org, &name)
                .await?
                .ok_or(Error::NotFound)?;
            self.require_scope(org, row.stack_id, apps).await?;
        }
        confirmed_removals.sort_unstable();
        let digest = self.fingerprint(&(
            yaml,
            selected,
            refresh,
            expected,
            &secrets,
            &confirmed_removals,
        ))?;
        {
            let mut connection = self.state.pool.acquire().await?;
            if let Some(response) = self
                .replay(&mut connection, org, "deploy", request_key, &digest)
                .await?
            {
                return Ok(response);
            }
        }
        let (definition, mut revision, mut changed, before) = self
            .prepare(org, yaml, selected, refresh, allowed_apps)
            .await?;
        let id = before.as_ref().map_or_else(Uuid::now_v7, |r| r.stack_id);
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        self.lock(&mut work, org).await?;
        if let Some(response) = self
            .replay(work.sql(), org, "deploy", request_key, &digest)
            .await?
        {
            return Ok(response);
        }
        let current = store::by_name(&mut **work.sql(), org, &definition.name).await?;
        match &current {
            Some(row) if Some(row.stream_version) != expected => return Err(Error::Conflict),
            None if expected.is_some_and(|v| v != 0) => return Err(Error::Conflict),
            Some(row) if row.stack_id != id => return Err(Error::Conflict),
            _ => {}
        }
        let previous = if current.is_some() {
            work.load_stack(id).await?
        } else {
            Stack::default()
        };
        if previous.operation.is_some() {
            return Err(Error::Busy);
        }
        if previous.status == Status::Deleted {
            return Err(Error::NotFound);
        }
        let removed = removed_services(&previous, &revision);
        if confirmed_removals != removed {
            return Err(invalid(
                "confirmed_removals",
                "confirm exactly the names of the services removed by this file",
            ));
        }
        if apps::app_by_name_including_deleted(&mut **work.sql(), org, &definition.name)
            .await?
            .is_some()
        {
            return Err(invalid("stack.name", "that name is reserved by an app"));
        }
        let mut live_apps = apps::count_live_apps(&mut **work.sql(), org).await?;
        let mut seen = BTreeSet::new();
        for secret in &secrets {
            if !seen.insert((secret.service.as_str(), secret.name.as_str()))
                || !revision.services.contains_key(&secret.service)
                || selected.is_some_and(|s| s != secret.service)
                || !grund_config::app::spec::secret_name_ok(&secret.name)
                || secret.name.starts_with("stack-ref-")
                || secret.value.len() > MAX_SECRET_BYTES
                || secret.value.contains('\0')
            {
                return Err(invalid(
                    "secrets",
                    "invalid, duplicate or out-of-scope secret input",
                ));
            }
            if revision.services[&secret.service]
                .template
                .as_deref()
                .and_then(|id| {
                    grund_domain::app::templates::resolve(
                        id,
                        definition.services[&secret.service].settings.as_ref(),
                    )
                })
                .is_some_and(|template| {
                    template.secret_variables.iter().any(|variable| {
                        crate::services::apps::secret_name_for(variable) == secret.name
                    })
                })
            {
                return Err(invalid(
                    "secrets",
                    "template credentials cannot be supplied",
                ));
            }
            if !revision.services[&secret.service]
                .release
                .spec
                .secrets
                .iter()
                .any(|s| s.secret == secret.name)
            {
                return Err(invalid(
                    "secrets",
                    "input is not referenced by the target service",
                ));
            }
            if !changed.contains(&secret.service) {
                changed.push(secret.service.clone());
            }
        }
        let sealing = key(&self.state);
        for (name, service) in &mut revision.services {
            let existing = work.load_app(service.app_id).await?;
            if existing.exists && existing.stack_owner != Some(id) {
                return Err(Error::Owned);
            }
            if let Some(selected) = &definition.services[name].data_volume {
                let volume =
                    grund_store::volumes::by_name(&mut **work.sql(), org, service.app_id, selected)
                        .await?
                        .ok_or_else(|| {
                            invalid(
                                format!("stack.services.{name}.data_volume"),
                                "the selected data volume is unavailable",
                            )
                        })?;
                work.load_volume(volume.volume_id).await?;
                let volume = self
                    .selected_data_volume(
                        work.sql(),
                        org,
                        name,
                        &definition.services[name],
                        retained_service(&previous.revisions, name),
                        previous.machine_id,
                    )
                    .await?
                    .expect("an explicit data volume");
                let desired = service
                    .release
                    .spec
                    .volumes
                    .first()
                    .expect("a stateful template");
                if desired.name != volume.name
                    || desired.path != volume.path
                    || desired.size_gib != volume.size_gib.map(|size| size as u64)
                    || definition.services[name]
                        .app
                        .volumes
                        .get("data")
                        .is_none_or(|overlay| overlay.backup.is_none())
                        && desired.backup != volume.backup
                {
                    return Err(Error::Conflict);
                }
            }
            if !existing.exists || existing.deleted {
                live_apps += 1;
            }
            if live_apps > MAX_APPS_PER_ORGANISATION {
                return Err(invalid("stack.services", "organisation app limit exceeded"));
            }
            let template = service.template.as_deref().and_then(|id| {
                grund_domain::app::templates::resolve(
                    id,
                    definition.services[name].settings.as_ref(),
                )
            });
            if let Some(template) = template {
                reuse_template_credential_pins(name, service, template, &previous.revisions);
            }
            for secret in &service.release.spec.secrets {
                let generated = template.is_some_and(|template| {
                    template.secret_variables.iter().any(|variable| {
                        *variable == secret.env
                            && crate::services::apps::secret_name_for(variable) == secret.secret
                    })
                });
                if secret.secret.starts_with("stack-ref-")
                    || !existing.exists && generated
                    || secrets
                        .iter()
                        .any(|input| input.service == *name && input.name == secret.secret)
                {
                    continue;
                }
                if generated
                    && !previous.revisions.values().any(|revision| {
                        revision.services.get(name).is_some_and(|prior| {
                            prior.app_id == service.app_id
                                && prior
                                    .release
                                    .spec
                                    .secrets
                                    .iter()
                                    .any(|binding| binding.env == secret.env)
                        })
                    })
                    && !service
                        .release
                        .secret_versions
                        .iter()
                        .any(|v| v.name == secret.secret)
                    && existing
                        .releases
                        .iter()
                        .all(|r| r.spec.secrets.iter().all(|s| s.env != secret.env))
                {
                    continue;
                }
                let pinned = service
                    .release
                    .secret_versions
                    .iter()
                    .find(|version| version.name == secret.secret)
                    .ok_or_else(|| {
                        invalid(
                            format!("stack.services.{name}.secrets"),
                            "an initial secret value is required separately from the file",
                        )
                    })?;
                let sealed = apps::secret_value(
                    &mut **work.sql(),
                    service.app_id,
                    &pinned.name,
                    pinned.version as i32,
                )
                .await?
                .ok_or_else(|| invalid("secrets", "the pinned secret version is unavailable"))?;
                if generated {
                    let provenance: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM grund_template_credentials \
                         WHERE organisation_id=$1 AND app_id=$2 AND name=$3 AND version=$4 AND template=$5)",
                    )
                    .bind(org)
                    .bind(service.app_id)
                    .bind(&pinned.name)
                    .bind(pinned.version as i32)
                    .bind(
                        service
                            .template
                            .as_deref()
                            .and_then(grund_domain::app::templates::family),
                    )
                    .fetch_one(&mut **work.sql())
                    .await?;
                    if !provenance
                        || open(
                            &sealing,
                            service.app_id,
                            &pinned.name,
                            pinned.version as i32,
                            &sealed,
                        )
                        .is_none()
                    {
                        return Err(invalid(
                            "secrets",
                            "the pinned template credential is unavailable",
                        ));
                    }
                }
            }
            if let Some(template) = template
                && template.secret_variables.iter().any(|variable| {
                    !service.release.spec.secrets.iter().any(|secret| {
                        secret.env == *variable
                            && secret.secret == crate::services::apps::secret_name_for(variable)
                    })
                })
            {
                return Err(invalid(
                    format!("stack.services.{name}.template"),
                    "the retained template has no canonical credential binding",
                ));
            }
        }
        if revision.services.values().any(|service| {
            service
                .release
                .spec
                .volumes
                .iter()
                .any(|volume| volume.size_gib.is_some())
        }) && self.state.volume_backend().is_none()
        {
            return Err(invalid(
                "stack.services",
                "hosted block volumes require an installed storage backend",
            ));
        }
        if let Some(error) = self
            .choose_machine(
                work.sql(),
                org,
                &revision,
                previous.machine_id,
                previous.exists.then_some(id),
            )
            .await?
            .insufficient()
        {
            return Err(error);
        }
        if !previous.exists {
            work.stack(
                id,
                Command::Create {
                    organisation_id: org,
                    name: definition.name.clone(),
                },
            )
            .await?;
        }
        work.allow_stack(id);
        for (name, service) in &mut revision.services {
            let existing = work.load_app(service.app_id).await?;
            if !existing.exists {
                service.app_name = free_member_name(
                    work.sql(),
                    org,
                    &definition.name,
                    name,
                    std::mem::take(&mut service.app_name),
                    retained_service(&previous.revisions, name).is_none(),
                )
                .await?;
                work.app(
                    service.app_id,
                    AppCommand::Create {
                        actor,
                        organisation_id: org,
                        name: AppName::parse(&service.app_name)?,
                        settings: service.settings.clone(),
                        at: revision.created_at,
                    },
                )
                .await?;
                work.app(
                    service.app_id,
                    AppCommand::AssignStack {
                        stack_id: id,
                        at: revision.created_at,
                    },
                )
                .await?;
                if let Some(template) = service.template.as_deref().and_then(|id| {
                    grund_domain::app::templates::resolve(
                        id,
                        definition.services[name].settings.as_ref(),
                    )
                }) {
                    service.release.secret_versions.extend(
                        crate::services::apps::generate_template_credentials_in(
                            &mut work,
                            &sealing,
                            actor,
                            org,
                            service.app_id,
                            template,
                        )
                        .await
                        .map_err(anyhow::Error::from)?,
                    );
                }
            } else if existing.stack_owner != Some(id) {
                return Err(Error::Owned);
            }
            if existing.exists
                && let Some(template) = service.template.as_deref().and_then(|id| {
                    grund_domain::app::templates::resolve(
                        id,
                        definition.services[name].settings.as_ref(),
                    )
                })
            {
                let generated = crate::services::apps::generate_missing_template_credentials_in(
                    &mut work,
                    &sealing,
                    actor,
                    org,
                    service.app_id,
                    template,
                    &service.release.secret_versions,
                )
                .await
                .map_err(anyhow::Error::from)?;
                service.release.secret_versions.extend(generated);
            }
            if existing.deleted {
                self.restore_child(
                    &mut work,
                    org,
                    service.app_id,
                    actor,
                    revision.created_at,
                    &service.release.spec.volumes,
                )
                .await?;
            }
            if changed.contains(name) {
                service.release.number = existing.releases.last().map_or(1, |r| r.number + 1);
                service.release.created_by = actor;
                service.release.created_at = revision.created_at;
            }
            for supplied in secrets.iter().filter(|s| s.service == *name) {
                let (version, _) = apps::insert_secret(
                    work.sql(),
                    service.app_id,
                    org,
                    &supplied.name,
                    |version| {
                        seal(
                            &sealing,
                            service.app_id,
                            &supplied.name,
                            version,
                            supplied.value.as_bytes(),
                        )
                    },
                    actor,
                )
                .await?;
                service
                    .release
                    .secret_versions
                    .retain(|s| s.name != supplied.name);
                service.release.secret_versions.push(SecretVersion {
                    name: supplied.name.clone(),
                    version: version as u32,
                });
            }
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
        }
        for name in order(&revision)? {
            let service_definition = &definition.services[&name];
            let template = match &service_definition.template {
                Some(id) => {
                    grund_domain::app::templates::resolve(id, service_definition.settings.as_ref())
                        .and_then(|t| t.spec(false))
                }
                None => None,
            };
            let (_, _, refs) = definition.service(&name, template)?;
            for reference in refs {
                let producer = &revision.services[&reference.service];
                let value = self
                    .output(
                        &mut work,
                        &sealing,
                        &definition.name,
                        producer,
                        &reference.service,
                        &reference.output,
                    )
                    .await?;
                let consumer = revision
                    .services
                    .get_mut(&name)
                    .expect("validated consumer");
                let secret_name = format!(
                    "stack-ref-{}",
                    hex::encode(&Sha256::digest(reference.env.as_bytes())[..12])
                );
                let pinned = consumer
                    .release
                    .secret_versions
                    .iter()
                    .find(|v| v.name == secret_name)
                    .map(|v| v.version);
                let unchanged = if let Some(version) = pinned {
                    apps::secret_value(
                        &mut **work.sql(),
                        consumer.app_id,
                        &secret_name,
                        version as i32,
                    )
                    .await?
                    .and_then(|sealed| {
                        open(
                            &sealing,
                            consumer.app_id,
                            &secret_name,
                            version as i32,
                            &sealed,
                        )
                    })
                    .is_some_and(|plain| plain == value.as_bytes())
                } else {
                    false
                };
                if !unchanged {
                    if selected.is_some_and(|s| s != name) {
                        return Err(invalid(
                            "service",
                            "a sibling connection changes; include that consumer in a full deploy",
                        ));
                    }
                    let (version, _) = apps::insert_secret(
                        work.sql(),
                        consumer.app_id,
                        org,
                        &secret_name,
                        |version| {
                            seal(
                                &sealing,
                                consumer.app_id,
                                &secret_name,
                                version,
                                value.as_bytes(),
                            )
                        },
                        actor,
                    )
                    .await?;
                    consumer
                        .release
                        .secret_versions
                        .retain(|v| v.name != secret_name);
                    consumer.release.secret_versions.push(SecretVersion {
                        name: secret_name,
                        version: version as u32,
                    });
                    if !changed.contains(&name) {
                        changed.push(name.clone());
                    }
                }
            }
        }
        for (name, service) in &mut revision.services {
            service.release.secret_versions.retain(|v| {
                service
                    .release
                    .spec
                    .secrets
                    .iter()
                    .any(|s| s.secret == v.name)
            });
            for secret in &service.release.spec.secrets {
                let pinned = service
                    .release
                    .secret_versions
                    .iter()
                    .find(|v| v.name == secret.secret)
                    .ok_or_else(|| {
                        invalid(
                            format!("stack.services.{name}.secrets"),
                            "an initial secret value is required separately from the file",
                        )
                    })?;
                if apps::secret_value(
                    &mut **work.sql(),
                    service.app_id,
                    &pinned.name,
                    pinned.version as i32,
                )
                .await?
                .is_none()
                {
                    return Err(invalid(
                        "secrets",
                        "the pinned secret version is unavailable",
                    ));
                }
            }
            if changed.contains(name) || previous.applied_revision == 0 {
                let app = work.load_app(service.app_id).await?;
                service.release.number = app.releases.last().map_or(1, |r| r.number + 1);
                service.release.created_by = actor;
            }
        }
        revision.created_by = actor;
        stack::validate_expanded(&revision.services)?;
        let ordered = order(&revision)?;
        changed.sort_by_key(|n| ordered.iter().position(|o| o == n));
        if previous.applied_revision == 0 {
            changed = ordered;
        }
        let mut transitions = previous
            .revisions
            .get(&previous.desired_revision)
            .map(order)
            .transpose()?
            .unwrap_or_default();
        transitions.reverse();
        transitions.retain(|name| removed.contains(name));
        transitions.append(&mut changed);
        let op = operation(
            Kind::Deploy,
            revision.number,
            previous.applied_revision,
            transitions,
            revision.created_at,
        );
        let public = revision
            .public_service
            .as_ref()
            .and_then(|name| revision.services.get(name))
            .map(|s| s.app_id);
        let old_public = previous
            .revisions
            .get(&previous.desired_revision)
            .and_then(|r| r.public_service.as_ref().and_then(|n| r.services.get(n)))
            .map(|s| s.app_id);
        work.stack(
            id,
            Command::Revise {
                revision,
                operation: op,
            },
        )
        .await?;
        self.state
            .domains()
            .rebind_stack_public_in(
                &mut work,
                actor,
                org,
                id,
                old_public,
                public,
                &definition.name,
            )
            .await
            .map_err(anyhow::Error::from)?;
        let response = self.pending(&mut work, org, id).await?;
        self.receipt(&mut work, org, "deploy", request_key, &digest, &response)
            .await?;
        work.commit().await?;
        self.state.wakes.apps_changed();
        Ok(response)
    }

    async fn output(
        &self,
        work: &mut Work<'_>,
        sealing: &LessSafeKey,
        stack_name: &str,
        producer: &Service,
        service_name: &str,
        output: &str,
    ) -> Result<String, Error> {
        if producer.template.as_deref() == Some("seaweedfs") {
            match output {
                "access_key_id" => {
                    return Self::credential(work, sealing, producer, "S3_ACCESS_KEY_ID").await;
                }
                "secret_access_key" => {
                    return Self::credential(work, sealing, producer, "S3_SECRET_ACCESS_KEY").await;
                }
                "region" => return Ok("us-east-1".into()),
                _ => {}
            }
        }
        let host = format!("{service_name}.{stack_name}.grund.internal");
        if output == "host" {
            return Ok(host);
        }
        let ports = &producer.release.spec.ports;
        if output == "port" && producer.template.is_some() {
            return ports
                .first()
                .map(|p| p.port.to_string())
                .ok_or_else(|| invalid("env", "producer exports no port"));
        }
        if output != "url" && output != "admin_url" {
            return Err(invalid("env", "producer does not export that output"));
        }
        let port = ports
            .iter()
            .find(|p| matches!(p.protocol, Protocol::Http | Protocol::H2c));
        let family = producer
            .template
            .as_deref()
            .and_then(grund_domain::app::templates::family);
        if output == "admin_url" && !exports_admin_url(producer) {
            return Err(invalid(
                "env",
                "admin_url requires a ClickHouse producer with settings.admin enabled",
            ));
        }
        if family == Some("nats") && producer.release.spec.volumes.is_empty() {
            return Err(invalid("env", "a NATS URL requires settings.jetstream"));
        }
        if !matches!(family, Some("postgres" | "redis" | "nats" | "clickhouse")) {
            return port
                .map(|p| format!("http://{host}:{}", p.port))
                .ok_or_else(|| invalid("env", "producer exports no HTTP URL"));
        }
        let (scheme, variable, port, user, database) = match family {
            Some("postgres") => ("postgresql", "POSTGRES_PASSWORD", 5432, "grund", "grund"),
            Some("redis") => ("redis", "REDIS_PASSWORD", 6379, "", "0"),
            Some("nats") => ("nats", "NATS_AUTH_TOKEN", 4222, "", ""),
            Some("clickhouse") if output == "admin_url" => {
                ("http", "CLICKHOUSE_ADMIN_PASSWORD", 8123, "", "grund")
            }
            Some("clickhouse") => ("http", "CLICKHOUSE_PASSWORD", 8123, "", "grund"),
            _ => return Err(invalid("env", "template URL unavailable")),
        };
        let password = Self::credential(work, sealing, producer, variable).await?;
        let generated_user;
        let user = if family == Some("clickhouse") {
            let variable = if output == "admin_url" {
                "CLICKHOUSE_ADMIN_USER"
            } else {
                "CLICKHOUSE_USER"
            };
            generated_user = Self::credential(work, sealing, producer, variable).await?;
            generated_user.as_str()
        } else {
            user
        };
        let mut url = reqwest::Url::parse(&format!("{scheme}://{host}:{port}/{database}"))
            .context("validated template URL")?;
        if family == Some("clickhouse") {
            url.set_path("/");
            url.query_pairs_mut().append_pair("database", database);
        }
        url.set_username(if family == Some("nats") {
            &password
        } else {
            user
        })
        .map_err(|_| invalid("env", "template username cannot be encoded"))?;
        if family != Some("nats") {
            url.set_password(Some(&password))
                .map_err(|_| invalid("env", "template password cannot be encoded"))?;
        }
        Ok(url.into())
    }

    async fn credential(
        work: &mut Work<'_>,
        sealing: &LessSafeKey,
        producer: &Service,
        variable: &str,
    ) -> Result<String, Error> {
        let secret = producer
            .release
            .spec
            .secrets
            .iter()
            .find(|s| s.env == variable)
            .ok_or_else(|| invalid("env", "template has no generated credential binding"))?;
        let version = producer
            .release
            .secret_versions
            .iter()
            .find(|v| v.name == secret.secret)
            .ok_or_else(|| invalid("env", "template credential version unavailable"))?;
        let sealed = apps::secret_value(
            &mut **work.sql(),
            producer.app_id,
            &version.name,
            version.version as i32,
        )
        .await?
        .ok_or_else(|| invalid("env", "template credential version unavailable"))?;
        let bytes = open(
            sealing,
            producer.app_id,
            &version.name,
            version.version as i32,
            &sealed,
        )
        .context("template credential cannot be opened")?;
        String::from_utf8(bytes)
            .context("template credential must be UTF-8")
            .map_err(Into::into)
    }

    pub async fn restart(
        &self,
        actor: Uuid,
        org: Uuid,
        name: &str,
        service: Option<&str>,
        expected: Option<i64>,
        request_key: &str,
    ) -> Result<StackView, Error> {
        self.start(
            actor,
            org,
            name,
            Kind::Restart,
            service,
            None,
            expected,
            request_key,
        )
        .await
    }
    pub async fn delete(
        &self,
        actor: Uuid,
        org: Uuid,
        name: &str,
        expected: Option<i64>,
        request_key: &str,
    ) -> Result<StackView, Error> {
        self.start(
            actor,
            org,
            name,
            Kind::Delete,
            None,
            None,
            expected,
            request_key,
        )
        .await
    }
    pub async fn restore(
        &self,
        actor: Uuid,
        org: Uuid,
        name: &str,
        expected: Option<i64>,
        request_key: &str,
    ) -> Result<StackView, Error> {
        self.start(
            actor,
            org,
            name,
            Kind::Restore,
            None,
            None,
            expected,
            request_key,
        )
        .await
    }
    pub async fn rollback(
        &self,
        actor: Uuid,
        org: Uuid,
        name: &str,
        revision: u32,
        expected: Option<i64>,
        request_key: &str,
    ) -> Result<StackView, Error> {
        self.start(
            actor,
            org,
            name,
            Kind::Rollback,
            None,
            Some(revision),
            expected,
            request_key,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start(
        &self,
        actor: Uuid,
        org: Uuid,
        name: &str,
        kind: Kind,
        selected: Option<&str>,
        target: Option<u32>,
        expected: Option<i64>,
        request_key: &str,
    ) -> Result<StackView, Error> {
        let method = match kind {
            Kind::Restart => "restart",
            Kind::Delete => "delete",
            Kind::Restore => "restore",
            Kind::Rollback => "rollback",
            Kind::Deploy => "deploy",
        };
        let digest = self.fingerprint(&(name, kind, selected, target, expected))?;
        let mut work = Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
        self.lock(&mut work, org).await?;
        if let Some(response) = self
            .replay(work.sql(), org, method, request_key, &digest)
            .await?
        {
            return Ok(response);
        }
        let row = store::by_name(&mut **work.sql(), org, name)
            .await?
            .ok_or(Error::NotFound)?;
        if expected != Some(row.stream_version) {
            return Err(Error::Conflict);
        }
        let state = work.load_stack(row.stack_id).await?;
        if state.operation.is_some() && kind != Kind::Delete {
            return Err(Error::Busy);
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **work.sql())
            .await?;
        if kind == Kind::Restore
            && (state.status != Status::Deleted
                || !state.purge_after.is_some_and(|deadline| now < deadline))
        {
            return Err(Error::NotFound);
        }
        let mut revision = state
            .revisions
            .get(&target.unwrap_or(state.desired_revision))
            .cloned()
            .ok_or(Error::NotFound)?;
        let mut ordered = order(&revision)?;
        if let Some(name) = selected {
            if !revision.services.contains_key(name) {
                return Err(invalid("service", "unknown service"));
            }
            ordered.retain(|n| n == name);
        }
        if kind == Kind::Delete {
            ordered = deletion_order(&state)?;
        }
        work.allow_stack(row.stack_id);
        for (name, service) in revision.services.iter().filter(|_| kind != Kind::Delete) {
            for version in &service.release.secret_versions {
                if apps::secret_value(
                    &mut **work.sql(),
                    service.app_id,
                    &version.name,
                    version.version as i32,
                )
                .await?
                .is_none()
                {
                    return Err(invalid(
                        format!("stack.services.{name}.secrets"),
                        "pinned secret version unavailable",
                    ));
                }
            }
        }
        if matches!(kind, Kind::Restore | Kind::Rollback) {
            for service in revision.services.values() {
                self.restore_child(
                    &mut work,
                    org,
                    service.app_id,
                    actor,
                    now,
                    &service.release.spec.volumes,
                )
                .await?;
            }
        }
        if kind == Kind::Rollback {
            let current = state
                .revisions
                .get(&state.desired_revision)
                .ok_or(Error::NotFound)?;
            for (name, service) in &revision.services {
                if service.template.is_some()
                    && service.exclusive
                    && current
                        .services
                        .get(name)
                        .is_some_and(|s| s.release.image_digest != service.release.image_digest)
                {
                    return Err(invalid(
                        "revision",
                        "stateful template downgrade requires a reviewed restore; data is not rolled back",
                    ));
                }
            }
            let mut teardown = order(current)?;
            teardown.reverse();
            teardown.retain(|name| !revision.services.contains_key(name));
            teardown.append(&mut ordered);
            ordered = teardown;
            revision.rollback_of = target;
            revision.number = state.desired_revision + 1;
            revision.created_by = actor;
            revision.created_at = now;
            for service in revision.services.values_mut() {
                let app = work.load_app(service.app_id).await?;
                let original = service.release.number;
                service.release.number = app.releases.last().map_or(1, |r| r.number + 1);
                service.release.source = ReleaseSource::Rollback;
                service.release.rollback_of = Some(original);
                service.release.created_by = actor;
                service.release.created_at = revision.created_at;
            }
            let op = operation(kind, revision.number, state.applied_revision, ordered, now);
            let public = revision
                .public_service
                .as_ref()
                .and_then(|name| revision.services.get(name))
                .map(|s| s.app_id);
            let old_public = current
                .public_service
                .as_ref()
                .and_then(|name| current.services.get(name))
                .map(|s| s.app_id);
            work.stack(
                row.stack_id,
                Command::Revise {
                    revision,
                    operation: op,
                },
            )
            .await?;
            self.state
                .domains()
                .rebind_stack_public_in(
                    &mut work,
                    actor,
                    org,
                    row.stack_id,
                    old_public,
                    public,
                    name,
                )
                .await
                .map_err(anyhow::Error::from)?;
        } else {
            let op = operation(kind, revision.number, state.applied_revision, ordered, now);
            let operation_id = op.id;
            work.stack(
                row.stack_id,
                Command::Operate {
                    operation: op,
                    at: now,
                },
            )
            .await?;
            if kind == Kind::Restore {
                let public = revision
                    .public_service
                    .as_ref()
                    .and_then(|name| revision.services.get(name))
                    .map(|service| service.app_id);
                self.state
                    .domains()
                    .rebind_stack_public_in(
                        &mut work,
                        actor,
                        org,
                        row.stack_id,
                        public,
                        public,
                        name,
                    )
                    .await
                    .map_err(anyhow::Error::from)?;
            }
            if kind == Kind::Delete {
                for member in store::members(&mut **work.sql(), org, row.stack_id).await? {
                    store::gate(
                        work.sql(),
                        org,
                        row.stack_id,
                        &member.service,
                        false,
                        false,
                        Some(operation_id),
                    )
                    .await?;
                }
                let machines: Vec<Uuid> = sqlx::query_scalar("SELECT DISTINCT r.machine_id FROM grund_replicas r JOIN grund_stack_members sm ON sm.organisation_id=r.organisation_id AND sm.app_id=r.app_id WHERE sm.organisation_id=$1 AND sm.stack_id=$2")
                    .bind(org).bind(row.stack_id).fetch_all(&mut **work.sql()).await?;
                for machine in machines {
                    self.state.agents().publish_in(work.sql(), machine).await?;
                }
            }
        }
        let response = self.pending(&mut work, org, row.stack_id).await?;
        self.receipt(&mut work, org, method, request_key, &digest, &response)
            .await?;
        work.commit().await?;
        self.state.wakes.apps_changed();
        self.state.wakes.documents_changed();
        Ok(response)
    }
}

fn reuse_template_credential_pins(
    name: &str,
    service: &mut Service,
    template: &grund_domain::app::templates::Template,
    revisions: &BTreeMap<u32, Revision>,
) {
    for variable in template.secret_variables {
        let secret_name = crate::services::apps::secret_name_for(variable);
        if service
            .release
            .secret_versions
            .iter()
            .any(|pin| pin.name == secret_name)
        {
            continue;
        }
        if let Some(pin) = revisions.values().rev().find_map(|revision| {
            let prior = revision.services.get(name)?;
            if prior.app_id != service.app_id
                || !prior
                    .release
                    .spec
                    .secrets
                    .iter()
                    .any(|binding| binding.env == *variable && binding.secret == secret_name)
            {
                return None;
            }
            prior
                .release
                .secret_versions
                .iter()
                .find(|pin| pin.name == secret_name)
        }) {
            service.release.secret_versions.push(pin.clone());
        }
    }
}

fn deletion_order(state: &Stack) -> Result<Vec<String>, Error> {
    let mut services = BTreeMap::new();
    for revision in state.revisions.values().rev() {
        for (name, service) in &revision.services {
            services.entry(name.as_str()).or_insert(service);
        }
    }
    let mut completed = BTreeSet::new();
    let mut result = Vec::with_capacity(services.len());
    while result.len() < services.len() {
        let next = services
            .iter()
            .find(|(name, service)| {
                !completed.contains(**name)
                    && service
                        .depends_on
                        .iter()
                        .all(|dependency| completed.contains(dependency.as_str()))
            })
            .map(|(name, _)| *name)
            .ok_or_else(|| invalid("stack.services", "dependency cycle"))?;
        completed.insert(next);
        result.push(next.to_owned());
    }
    result.reverse();
    Ok(result)
}

async fn free_member_name(
    connection: &mut PgConnection,
    org: Uuid,
    stack_name: &str,
    service: &str,
    mut name: String,
    generated: bool,
) -> Result<String, Error> {
    for _ in 0..NAME_ATTEMPTS {
        if apps::app_by_name_including_deleted(&mut *connection, org, &name)
            .await?
            .is_none()
            && store::by_name(&mut *connection, org, &name)
                .await?
                .is_none()
        {
            return Ok(name);
        }
        if !generated {
            break;
        }
        name = member_app_name(stack_name, service);
    }
    Err(Error::Conflict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use grund_domain::{
        app::{AppEvent, PlaceReason},
        volume::VolumeCommand,
    };
    use std::sync::Arc;

    #[sqlx::test(migrations = false)]
    async fn compensation_keeps_the_previous_singleton_and_drains_its_crash_looping_successor(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, true).await?;
        let at = Utc::now();
        sqlx::query("UPDATE grund_machines SET minted_by='account:test' WHERE machine_id=$1")
            .bind(bundle.machine)
            .execute(&state.pool)
            .await?;
        sqlx::query("INSERT INTO grund_machine_presence(machine_id,last_seen_at,capabilities) VALUES($1,$2,$3)")
            .bind(bundle.machine).bind(at).bind(Json(serde_json::json!({
                "apps": true, "stack_services": true, "resources_allocatable": true,
                "volumes": true, "arch": "x86_64", "memory_mib": 4096, "cpu_millis": 4000
            }))).execute(&state.pool).await?;
        sqlx::query("INSERT INTO grund_replica_status(replica_id,machine_id,state,ready,ready_since,ever_ready,observed_at) \
            SELECT replica_id,machine_id,'running',true,$2,true,$3 FROM grund_replicas WHERE machine_id=$1")
            .bind(bundle.machine).bind(at - Duration::minutes(1)).bind(at)
            .execute(&state.pool).await?;
        let old = apps::app_replicas(&state.pool, bundle.consumer).await?[0].replica_id;
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(bundle.id);
        for id in [bundle.producer, bundle.consumer] {
            let app = work.load_app(id).await?;
            let rollout_id = app.rollout.unwrap().rollout_id;
            work.app_decide(id, |_| {
                Ok((
                    vec![
                        AppEvent::RolloutSucceeded {
                            rollout_id,
                            succeeded_at: at,
                        },
                        AppEvent::CurrentReleaseSet {
                            release: 1,
                            set_at: at,
                        },
                    ],
                    (),
                ))
            })
            .await?;
        }
        work.stack(
            bundle.id,
            Command::Complete {
                operation_id: bundle.former.id,
                applied_revision: 1,
                status: Status::Ready,
                purge_after: None,
                failure: None,
            },
        )
        .await?;
        let mut revision = work.load_stack(bundle.id).await?.revisions[&1].clone();
        revision.number = 2;
        let service = revision.services.get_mut("consumer").unwrap();
        service.exclusive = false;
        service.settings.auto_rollback = false;
        service.settings.rollout.min_ready_seconds = 0;
        service.release.number = 2;
        service
            .release
            .spec
            .env
            .push(grund_config::app::spec::EnvVar {
                name: "UPDATE".into(),
                value: "new".into(),
            });
        let op = operation(Kind::Deploy, 2, 1, vec!["consumer".into()], at);
        work.stack(
            bundle.id,
            Command::Revise {
                revision,
                operation: op,
            },
        )
        .await?;
        work.commit().await?;
        let stacks = state.stacks();
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        state
            .apps()
            .reconcile_app(bundle.consumer, bundle.org)
            .await?;
        let replicas = apps::app_replicas(&state.pool, bundle.consumer).await?;
        let failed = replicas
            .iter()
            .find(|r| r.release == 2)
            .context("surge placed")?
            .replica_id;
        sqlx::query("INSERT INTO grund_replica_status(replica_id,machine_id,state,ready,ever_ready,restarts,last_exit_code,observed_at) \
            VALUES($1,$2,'exited',false,false,3,1,clock_timestamp())")
            .bind(failed).bind(bundle.machine).execute(&state.pool).await?;
        state
            .apps()
            .reconcile_app(bundle.consumer, bundle.org)
            .await?;
        assert!(
            apps::app(&state.pool, bundle.consumer)
                .await?
                .unwrap()
                .halted
        );
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        let compensating = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .state
            .0;
        assert!(compensating.operation.as_ref().unwrap().compensating);
        assert_eq!(
            compensating.revisions[&3].services["consumer"]
                .release
                .number,
            1
        );
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        state
            .apps()
            .reconcile_app(bundle.consumer, bundle.org)
            .await?;
        let replicas = apps::app_replicas(&state.pool, bundle.consumer).await?;
        assert!(
            replicas
                .iter()
                .any(|r| r.replica_id == old && r.state == "running")
        );
        assert!(
            replicas
                .iter()
                .any(|r| r.replica_id == failed && r.state == "draining")
        );
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        assert!(
            store::get(&state.pool, bundle.org, bundle.id)
                .await?
                .unwrap()
                .state
                .0
                .operation
                .is_some()
        );
        let member = store::member(&state.pool, bundle.org, bundle.consumer)
            .await?
            .unwrap();
        let mut connection = state.pool.acquire().await?;
        assert!(
            apps::record_stack_receipt(
                &mut connection,
                bundle.org,
                bundle.machine,
                failed,
                member.required_generation,
                member.operation_id.unwrap(),
            )
            .await?
        );
        drop(connection);
        state
            .apps()
            .reconcile_app(bundle.consumer, bundle.org)
            .await?;
        for _ in 0..3 {
            stacks.reconcile_one(bundle.org, bundle.id).await?;
        }
        let restored = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .state
            .0;
        assert_eq!(restored.status, Status::Ready);
        assert!(restored.operation.is_none());
        assert_eq!(
            restored.revisions[&restored.applied_revision].rollback_of,
            Some(1)
        );
        assert_ne!(restored.failure.as_deref(), Some("rollback_failed"));
        let app = apps::app(&state.pool, bundle.consumer).await?.unwrap();
        assert!(!app.halted);
        assert_eq!(app.current_release, Some(1));
        assert_eq!(
            apps::releases(&state.pool, bundle.consumer, 100)
                .await?
                .len(),
            2
        );
        let replicas = apps::app_replicas(&state.pool, bundle.consumer).await?;
        assert_eq!(replicas.len(), 1);
        assert_eq!(replicas[0].replica_id, old);
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn supplied_secrets_cannot_replace_generated_clickhouse_admin_credentials(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, false).await?;
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(bundle.id);
        work.stack(
            bundle.id,
            Command::Complete {
                operation_id: bundle.former.id,
                applied_revision: 1,
                status: Status::Ready,
                purge_after: None,
                failure: None,
            },
        )
        .await?;
        let mut revision = work.load_stack(bundle.id).await?.revisions[&1].clone();
        revision.number = 2;
        revision.yaml = revision.yaml.replace(
            "      image: redis\n      restart: exclusive\n    consumer:",
            "      template: clickhouse\n      settings: {admin: true}\n      restart: exclusive\n    consumer:",
        );
        let definition = stack::parse(&revision.yaml)?;
        let template = grund_domain::app::templates::resolve(
            "clickhouse",
            definition.services["producer"].settings.as_ref(),
        )
        .unwrap();
        let producer = revision.services.get_mut("producer").unwrap();
        producer.template = Some("clickhouse".into());
        producer.release.spec = expand_service(&definition, "producer", Some(template), None)?.0;
        let operation = operation(Kind::Deploy, 2, 1, vec!["producer".into()], Utc::now());
        work.stack(
            bundle.id,
            Command::Revise {
                revision: revision.clone(),
                operation: operation.clone(),
            },
        )
        .await?;
        work.stack(
            bundle.id,
            Command::Complete {
                operation_id: operation.id,
                applied_revision: 2,
                status: Status::Ready,
                purge_after: None,
                failure: None,
            },
        )
        .await?;
        work.commit().await?;
        let row = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap();
        for name in ["clickhouse-admin-user", "clickhouse-admin-password"] {
            assert!(matches!(
                state.stacks().deploy(
                    Uuid::nil(), bundle.org, &revision.yaml, Some("producer"), None,
                    Some(row.stream_version), &Uuid::now_v7().to_string(),
                    vec![InputSecret { service: "producer".into(), name: name.into(), value: "supplied".into() }],
                    Vec::new(), None,
                ).await,
                Err(Error::Invalid(SpecError { problem, .. }))
                    if problem == "template credentials cannot be supplied"
            ));
        }
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn preview_and_deploy_refuse_admin_urls_without_an_enabled_clickhouse_producer(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let stacks = state.stacks();
        let org = Uuid::now_v7();
        for producer in [
            "template: clickhouse",
            "template: clickhouse\n      settings: {admin: false}",
            "template: redis",
            "image: redis",
        ] {
            let yaml = format!(
                "stack:\n  name: admin-refusal\n  services:\n    consumer:\n      image: redis\n      depends_on: [producer]\n      env:\n        ADMIN_URL: '${{{{ producer.admin_url }}}}'\n    producer:\n      {producer}\n"
            );
            assert!(matches!(
                stacks.preview(org, &yaml, None, None, None).await,
                Err(Error::Invalid(SpecError { problem, .. }))
                    if problem.contains("admin_url requires")
            ));
            assert!(matches!(
                stacks
                    .deploy(
                        Uuid::nil(), org, &yaml, None, None, None,
                        &Uuid::now_v7().to_string(), Vec::new(), Vec::new(), None,
                    )
                    .await,
                Err(Error::Invalid(SpecError { problem, .. }))
                    if problem.contains("admin_url requires")
            ));
        }
        assert!(
            store::by_name(&state.pool, org, "admin-refusal")
                .await?
                .is_none()
        );
        assert!(apps::organisation_apps(&state.pool, org).await?.is_empty());
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn clickhouse_admin_toggles_reuse_pins_without_rotating_the_application_credentials(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, false).await?;
        let stacks = state.stacks();
        let sealing = key(&state);
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        let mut revision = work.load_stack(bundle.id).await?.revisions[&1].clone();
        let mut producer = revision.services["producer"].clone();
        producer.template = Some("clickhouse".into());
        producer.release.secret_versions.clear();
        let mut revisions = BTreeMap::new();
        let mut application_url = None;
        let mut admin_url = None;
        for (index, enabled) in [false, true, true, false, true].into_iter().enumerate() {
            let yaml = format!(
                "stack:\n  name: ordered\n  services:\n    producer:\n      template: clickhouse\n      settings: {{admin: {enabled}}}\n"
            );
            let definition = stack::parse(&yaml)?;
            let template = grund_domain::app::templates::resolve(
                "clickhouse",
                definition.services["producer"].settings.as_ref(),
            )
            .unwrap();
            let (spec, _, _) =
                expand_service(&definition, "producer", Some(template), Some(&producer))?;
            producer.release.spec = spec;
            reuse_template_credential_pins("producer", &mut producer, template, &revisions);
            let generated = crate::services::apps::generate_missing_template_credentials_in(
                &mut work,
                &sealing,
                Uuid::nil(),
                bundle.org,
                bundle.producer,
                template,
                &producer.release.secret_versions,
            )
            .await?;
            assert_eq!(generated.len(), if index < 2 { 2 } else { 0 });
            producer.release.secret_versions.extend(generated);
            producer.release.secret_versions.retain(|pin| {
                producer
                    .release
                    .spec
                    .secrets
                    .iter()
                    .any(|binding| binding.secret == pin.name)
            });
            assert_eq!(
                producer.release.secret_versions.len(),
                if enabled { 4 } else { 2 }
            );
            assert!(
                producer
                    .release
                    .secret_versions
                    .iter()
                    .all(|pin| pin.version == 1)
            );
            let url = stacks
                .output(&mut work, &sealing, "ordered", &producer, "producer", "url")
                .await?;
            if let Some(expected) = &application_url {
                assert!(
                    &url == expected,
                    "the ordinary URL must survive every admin toggle"
                );
            } else {
                application_url = Some(url.clone());
            }
            let url = reqwest::Url::parse(&url)?;
            assert!(url.scheme() == "http" && url.port() == Some(8123));
            assert!(url.path() == "/" && url.query() == Some("database=grund"));
            let output = stacks
                .output(
                    &mut work,
                    &sealing,
                    "ordered",
                    &producer,
                    "producer",
                    "admin_url",
                )
                .await;
            if enabled {
                let output = output?;
                if let Some(expected) = &admin_url {
                    assert!(
                        &output == expected,
                        "re-enabling admin must reuse its original credentials"
                    );
                } else {
                    admin_url = Some(output.clone());
                }
                let admin = reqwest::Url::parse(&output)?;
                assert!(admin.username().starts_with("grund_"));
                assert!(
                    admin
                        .username()
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                );
                assert!(admin.username() != url.username());
                assert!(admin.password() != url.password());
                assert!(admin.scheme() == url.scheme() && admin.host() == url.host());
                assert!(
                    admin.port() == url.port()
                        && admin.path() == url.path()
                        && admin.query() == url.query()
                );
                for variable in ["CLICKHOUSE_ADMIN_USER", "CLICKHOUSE_ADMIN_PASSWORD"] {
                    let mut missing = producer.clone();
                    missing
                        .release
                        .spec
                        .secrets
                        .retain(|binding| binding.env != variable);
                    assert!(matches!(
                        stacks
                            .output(
                                &mut work,
                                &sealing,
                                "ordered",
                                &missing,
                                "producer",
                                "admin_url"
                            )
                            .await,
                        Err(Error::Invalid(_))
                    ));
                    let mut missing = producer.clone();
                    let name = crate::services::apps::secret_name_for(variable);
                    missing
                        .release
                        .secret_versions
                        .retain(|pin| pin.name != name);
                    assert!(matches!(
                        stacks
                            .output(
                                &mut work,
                                &sealing,
                                "ordered",
                                &missing,
                                "producer",
                                "admin_url"
                            )
                            .await,
                        Err(Error::Invalid(_))
                    ));
                }
            } else {
                assert!(matches!(output, Err(Error::Invalid(_))));
            }
            revision.number = index as u32 + 1;
            revision
                .services
                .insert("producer".into(), producer.clone());
            revisions.insert(revision.number, revision.clone());
        }
        let counts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT name,count(*) FROM grund_app_secrets WHERE organisation_id=$1 AND app_id=$2 GROUP BY name ORDER BY name",
        )
        .bind(bundle.org)
        .bind(bundle.producer)
        .fetch_all(&mut **work.sql())
        .await?;
        assert_eq!(counts.len(), 4);
        assert!(counts.iter().all(|(_, count)| *count == 1));
        crate::services::apps::generate_template_credentials_in(
            &mut work,
            &sealing,
            Uuid::nil(),
            bundle.org,
            bundle.producer,
            grund_domain::app::templates::resolve(
                "clickhouse",
                Some(&grund_config::stack::TemplateSettings {
                    admin: true,
                    ..Default::default()
                }),
            )
            .unwrap(),
        )
        .await?;
        assert!(
            stacks
                .output(
                    &mut work,
                    &sealing,
                    "ordered",
                    &producer,
                    "producer",
                    "admin_url"
                )
                .await?
                == admin_url.unwrap(),
            "admin output must use its release pins, not newer stored values"
        );
        producer.template = Some("redis".into());
        assert!(matches!(
            stacks
                .output(
                    &mut work,
                    &sealing,
                    "ordered",
                    &producer,
                    "producer",
                    "admin_url"
                )
                .await,
            Err(Error::Invalid(_))
        ));
        Ok(())
    }

    #[derive(Parser)]
    struct TestConfig {
        #[command(flatten)]
        config: crate::config::ServeConfig,
    }

    async fn state(pool: sqlx::PgPool) -> anyhow::Result<State> {
        grund_store::migrate(&pool).await?;
        let mut config =
            TestConfig::try_parse_from(["test", "--database-url", "postgres://unused/test"])?
                .config;
        config.license_key = None;
        config.license_key_file = None;
        let secret = Arc::new(crate::secrets::SecretKey::generate());
        let events = mire::EventStore::new(pool.clone());
        let certificates =
            crate::certificates::Certificates::new(&config, pool.clone(), secret.clone());
        let hearing = Arc::new(crate::hearing::Hearing::new(Utc::now()));
        let health = crate::health::registry(
            pool.clone(),
            hearing.clone(),
            None,
            false,
            &certificates,
            &config,
        );
        let entitlements = Arc::new(crate::entitlements(&config)?);
        Ok(State {
            config: Arc::new(config),
            pool,
            events: events.clone(),
            nats: None,
            secret,
            certificates,
            health,
            passwords: crate::services::passwords::Passwords::new()?,
            entitlements,
            billing: crate::services::billing::Billing::Free,
            capacity: crate::services::capacity::Capacity::None,
            deletions: crate::sagas::Deletions::new(events),
            extensions: Arc::new(Vec::new()),
            started: std::time::Instant::now(),
            wakes: crate::wakes::Wakes::default(),
            hearing,
        })
    }

    #[sqlx::test(migrations = false)]
    async fn hosted_access_refuses_new_selections_without_blocking_own_or_existing_apps(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        use crate::services::apps::AppsError;
        use grund_config::app::spec::{AppSettings, SettingsInput};

        let state = state(pool).await?;
        let org = Uuid::now_v7();
        let actor = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO grund_organisations \
             (organisation_id,slug,kind,created_at,stream_version) \
             VALUES($1,$2,'personal',clock_timestamp(),1)",
        )
        .bind(org)
        .bind("admission")
        .execute(&state.pool)
        .await?;
        assert!(!state.hosted_access(org).await?);
        let hosted = || SettingsInput {
            kind: "hosted".into(),
            ..Default::default()
        };
        let apps = state.apps();
        assert!(matches!(
            apps.create(actor, org, "new-hosted", hosted()).await,
            Err(AppsError::HostedAccessRequired)
        ));
        assert!(apps::organisation_apps(&state.pool, org).await?.is_empty());
        apps.create(actor, org, "own", SettingsInput::default())
            .await?;
        assert!(matches!(
            apps.configure(actor, org, "own", hosted()).await,
            Err(AppsError::HostedAccessRequired)
        ));
        assert_eq!(
            apps.get(org, "own").await?.row.settings.0.placement.kind,
            None
        );

        let existing = Uuid::now_v7();
        let mut work = Work::begin(&state.events, Uuid::now_v7(), &actor.to_string()).await?;
        work.app(
            existing,
            AppCommand::Create {
                actor,
                organisation_id: org,
                name: AppName::parse("existing-hosted")?,
                settings: AppSettings::validate(hosted())?,
                at: Utc::now(),
            },
        )
        .await?;
        work.commit().await?;
        let mut settings = hosted();
        settings.copies = Some(2);
        assert_eq!(
            apps.configure(actor, org, "existing-hosted", settings)
                .await?
                .row
                .settings
                .0
                .copies,
            2
        );
        apps.configure(actor, org, "existing-hosted", SettingsInput::default())
            .await?;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn a_generated_member_name_is_drawn_again_while_held_and_a_retained_one_never(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let org = Uuid::now_v7();
        let actor = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO grund_organisations \
             (organisation_id,slug,kind,created_at,stream_version) \
             VALUES($1,'names','personal',clock_timestamp(),1)",
        )
        .bind(org)
        .execute(&state.pool)
        .await?;
        state
            .apps()
            .create(actor, org, "shop-web-held", Default::default())
            .await?;
        sqlx::query(
            "INSERT INTO grund_stacks(organisation_id,stack_id,name,state,status,stream_version) \
             VALUES($1,$2,'shop-db-held',$3,'ready',1)",
        )
        .bind(org)
        .bind(Uuid::now_v7())
        .bind(Json(Stack::default()))
        .execute(&state.pool)
        .await?;
        let mut connection = state.pool.acquire().await?;
        for (service, held) in [("web", "shop-web-held"), ("db", "shop-db-held")] {
            let name =
                free_member_name(&mut connection, org, "shop", service, held.into(), true).await?;
            assert_ne!(name, held);
            assert!(name.starts_with(&format!("shop-{service}-")), "{name}");
            assert_eq!(name.len(), format!("shop-{service}-").len() + 4, "{name}");
            assert!(matches!(
                free_member_name(&mut connection, org, "shop", service, held.into(), false).await,
                Err(Error::Conflict)
            ));
        }
        assert_eq!(
            free_member_name(
                &mut connection,
                org,
                "shop",
                "web",
                "sabuhs2me7sonlzb3v3h4b3cw72".into(),
                false
            )
            .await?,
            "sabuhs2me7sonlzb3v3h4b3cw72"
        );
        Ok(())
    }

    struct TransactionAdmission(tokio::sync::Barrier);

    impl crate::extension::Extension for TransactionAdmission {
        fn name(&self) -> &'static str {
            "transaction-admission"
        }

        fn routes(&self) -> axum::Router<State> {
            axum::Router::new()
        }

        fn hosted_access<'a>(
            &'a self,
            _state: &'a State,
            connection: &'a mut PgConnection,
            org: Uuid,
        ) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
            Box::pin(async move {
                self.0.wait().await;
                Ok(sqlx::query_scalar(
                    "SELECT false FROM grund_organisations WHERE organisation_id=$1",
                )
                .bind(org)
                .fetch_one(connection)
                .await?)
            })
        }
    }

    #[sqlx::test(migrations = false)]
    async fn concurrent_hosted_transitions_finish_when_work_occupies_every_available_pool_slot(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        use crate::services::apps::AppsError;
        use grund_config::app::spec::SettingsInput;

        let mut state = state(pool).await?;
        state.extensions = Arc::new(vec![Arc::new(TransactionAdmission(
            tokio::sync::Barrier::new(2),
        ))]);
        let first_org = Uuid::now_v7();
        let second_org = Uuid::now_v7();
        let actor = Uuid::now_v7();
        let apps = state.apps();
        for (org, name) in [(first_org, "first"), (second_org, "second")] {
            sqlx::query(
                "INSERT INTO grund_organisations \
                 (organisation_id,slug,kind,created_at,stream_version) \
                 VALUES($1,$2,'personal',clock_timestamp(),1)",
            )
            .bind(org)
            .bind(name)
            .execute(&state.pool)
            .await?;
            apps.create(actor, org, name, SettingsInput::default())
                .await?;
        }
        let held_slots = state.pool.options().get_max_connections().saturating_sub(2);
        let mut held = Vec::with_capacity(held_slots as usize);
        for _ in 0..held_slots {
            held.push(state.pool.acquire().await?);
        }
        let hosted = || SettingsInput {
            kind: "hosted".into(),
            ..Default::default()
        };
        let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                apps.configure(actor, first_org, "first", hosted()),
                apps.configure(actor, second_org, "second", hosted()),
            )
        })
        .await?;
        assert!(matches!(first, Err(AppsError::HostedAccessRequired)));
        assert!(matches!(second, Err(AppsError::HostedAccessRequired)));
        drop(held);
        for (org, name) in [(first_org, "first"), (second_org, "second")] {
            assert_eq!(
                apps.get(org, name).await?.row.settings.0.placement.kind,
                None
            );
        }
        Ok(())
    }

    struct PlacementStorage(std::sync::atomic::AtomicBool);

    impl crate::services::volumes::VolumeBackend for PlacementStorage {
        fn template_available<'a>(
            &'a self,
            _conn: &'a mut PgConnection,
            _machine: &'a machines::MachineRow,
            _size_gib: u64,
        ) -> crate::services::volumes::BackendFuture<'a, bool> {
            Box::pin(async { Ok(self.0.load(std::sync::atomic::Ordering::SeqCst)) })
        }

        fn eligible<'a>(
            &'a self,
            _conn: &'a mut PgConnection,
            _machine: &'a machines::MachineRow,
            _owned: &'a [grund_store::volumes::VolumeRow],
        ) -> crate::services::volumes::BackendFuture<'a, bool> {
            Box::pin(async { Ok(false) })
        }

        fn mount_ready<'a>(
            &'a self,
            _conn: &'a mut PgConnection,
            _volume: &'a grund_store::volumes::VolumeRow,
        ) -> crate::services::volumes::BackendFuture<'a, bool> {
            unreachable!("placement does not issue mounts")
        }

        fn recovery_points<'a>(
            &'a self,
            _pool: &'a sqlx::PgPool,
            _org: Uuid,
            _app: Uuid,
            _volume: Uuid,
        ) -> crate::services::volumes::BackendFuture<'a, Vec<grund_store::backup::RecoveryPoint>>
        {
            unreachable!("placement does not list recovery points")
        }

        fn backup_view<'a>(
            &'a self,
            _pool: &'a sqlx::PgPool,
            _org: Uuid,
            _app: Uuid,
            _volume: Uuid,
        ) -> crate::services::volumes::BackendFuture<'a, crate::services::backups::BackupView>
        {
            unreachable!("placement does not read backup status")
        }

        fn reserve_restore<'a>(
            &'a self,
            _conn: &'a mut PgConnection,
            _org: Uuid,
            _app: Uuid,
            _source: Uuid,
            _snapshot: Uuid,
            _new_volume: Uuid,
            _machine: Uuid,
            _attempt: Uuid,
        ) -> crate::services::volumes::BackendFuture<'a, ()> {
            unreachable!("placement does not request restores")
        }

        fn restore_status<'a>(
            &'a self,
            _pool: &'a sqlx::PgPool,
            _org: Uuid,
            _app: Uuid,
            _volume: Uuid,
        ) -> crate::services::volumes::BackendFuture<'a, Option<(String, Option<String>)>> {
            unreachable!("placement does not read restore status")
        }

        fn restore_attempt_status<'a>(
            &'a self,
            _pool: &'a sqlx::PgPool,
            _org: Uuid,
            _app: Uuid,
            _attempt: Uuid,
        ) -> crate::services::volumes::BackendFuture<'a, Option<String>> {
            unreachable!("placement does not read restore attempts")
        }
    }

    struct PlacementExtension(Arc<PlacementStorage>);

    impl crate::extension::Extension for PlacementExtension {
        fn name(&self) -> &'static str {
            "placement-storage"
        }

        fn routes(&self) -> axum::Router<State> {
            axum::Router::new()
        }

        fn volume_backend(
            &self,
            _state: &State,
        ) -> Option<Arc<dyn crate::services::volumes::VolumeBackend>> {
            Some(self.0.clone())
        }
    }

    #[sqlx::test(migrations = false)]
    async fn first_hosted_templates_need_new_disk_capacity_not_retained_volume_eligibility(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let mut state = state(pool).await?;
        let backend = Arc::new(PlacementStorage(std::sync::atomic::AtomicBool::new(true)));
        state.extensions = Arc::new(vec![Arc::new(PlacementExtension(backend.clone()))]);
        let org = Uuid::now_v7();
        let machine = Uuid::now_v7();
        let at = Utc::now();
        sqlx::query("INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) VALUES($1,'first-hosted','personal',$2,1)")
            .bind(org).bind(at).execute(&state.pool).await?;
        sqlx::query("INSERT INTO grund_machines(machine_id,pool,name,state,public_key,pool_organisation_id,pool_name,lease_id,minted_by,registered_at,key_registered_at,stream_version) VALUES($1,'management','physical','leased',repeat('a',64),$2,'hosted',$3,'test',$4,$4,1)")
            .bind(machine).bind(org).bind(Uuid::now_v7()).bind(at).execute(&state.pool).await?;
        sqlx::query("INSERT INTO grund_machine_presence(machine_id,last_seen_at,capabilities) VALUES($1,$2,$3)")
            .bind(machine).bind(at).bind(Json(serde_json::json!({
                "apps": true, "stack_services": true, "resources_allocatable": true,
                "arch": "x86_64", "memory_mib": 4096, "cpu_millis": 2000
            }))).execute(&state.pool).await?;
        let stacks = state.stacks();
        let mut conn = state.pool.acquire().await?;
        for template in ["postgres", "redis", "seaweedfs"] {
            let mut spec = grund_domain::app::templates::find(template)
                .unwrap()
                .spec(false)
                .unwrap();
            let size = grund_domain::app::templates::find(template)
                .unwrap()
                .storage
                .unwrap()
                .size_gib;
            for volume in &mut spec.volumes {
                volume.size_gib = Some(size);
            }
            let mut settings = grund_config::app::spec::AppSettings::default();
            settings.placement.kind = Some(grund_config::app::spec::MachineKind::Hosted);
            let app_id = Uuid::now_v7();
            let revision = Revision {
                number: 1,
                yaml: format!(
                    "stack:\n  name: first\n  services:\n    storage:\n      template: {template}\n"
                ),
                services: BTreeMap::from([(
                    "storage".into(),
                    Service {
                        app_id,
                        app_name: "storage".into(),
                        release: Release {
                            number: 1,
                            spec,
                            image_digest: String::new(),
                            platforms: Vec::new(),
                            exposed_ports: None,
                            secret_versions: Vec::new(),
                            source: ReleaseSource::File,
                            rollback_of: None,
                            note: String::new(),
                            created_by: Uuid::nil(),
                            created_at: at,
                            external_release: None,
                            request: None,
                        },
                        settings,
                        depends_on: Vec::new(),
                        exclusive: true,
                        template: Some(template.into()),
                    },
                )]),
                public_service: None,
                public_port: None,
                created_at: at,
                created_by: Uuid::nil(),
                rollback_of: None,
            };
            assert_eq!(
                stacks
                    .choose_machine(&mut conn, org, &revision, None, None)
                    .await?
                    .machine,
                Some(machine),
                "{template} must be placeable before its first disk is allocated"
            );
            backend.0.store(false, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                stacks
                    .choose_machine(&mut conn, org, &revision, None, None)
                    .await?
                    .machine,
                None,
                "{template} must still pass fresh-host, lease, disk and slot preflight"
            );
            backend.0.store(true, std::sync::atomic::Ordering::SeqCst);
            let volume = Uuid::now_v7();
            sqlx::query("INSERT INTO grund_volumes(organisation_id,app_id,volume_id,name,path,status,size_gib,backup,created_at,stream_version) VALUES($1,$2,$3,'data','/data','requested',$4,true,$5,1)")
                .bind(org).bind(app_id).bind(volume).bind(size as i64).bind(at).execute(&mut *conn).await?;
            assert_eq!(
                stacks
                    .choose_machine(&mut conn, org, &revision, None, None)
                    .await?
                    .machine,
                None,
                "{template} retained volumes must still pass backend eligibility"
            );
            sqlx::query("DELETE FROM grund_volumes WHERE volume_id=$1")
                .bind(volume)
                .execute(&mut *conn)
                .await?;
        }
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn a_leased_hosted_machine_takes_own_disk_directories_without_a_storage_backend(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let org = Uuid::now_v7();
        let machine = Uuid::now_v7();
        let app_id = Uuid::now_v7();
        let at = Utc::now();
        sqlx::query("INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) VALUES($1,'hosted-disk','personal',$2,1)")
            .bind(org).bind(at).execute(&state.pool).await?;
        sqlx::query("INSERT INTO grund_machines(machine_id,pool,name,state,public_key,pool_organisation_id,pool_name,lease_id,minted_by,registered_at,key_registered_at,stream_version) VALUES($1,'management','physical','leased',repeat('a',64),$2,'hosted',$3,'hosted:test',$4,$4,1)")
            .bind(machine).bind(org).bind(Uuid::now_v7()).bind(at).execute(&state.pool).await?;
        let capabilities = |volumes: bool| {
            Json(serde_json::json!({
                "apps": true, "stack_services": true, "resources_allocatable": true,
                "volumes": volumes, "arch": "x86_64", "memory_mib": 4096, "cpu_millis": 2000
            }))
        };
        sqlx::query("INSERT INTO grund_machine_presence(machine_id,last_seen_at,capabilities) VALUES($1,$2,$3)")
            .bind(machine).bind(at).bind(capabilities(false)).execute(&state.pool).await?;
        let spec = grund_domain::app::templates::find("postgres")
            .unwrap()
            .spec(false)
            .unwrap();
        assert!(
            spec.volumes
                .iter()
                .all(|v| v.size_gib.is_none() && v.source.is_none())
        );
        let revision = Revision {
            number: 1,
            yaml: "stack:\n  name: shop\n  services:\n    db:\n      template: postgres\n".into(),
            services: BTreeMap::from([(
                "db".into(),
                Service {
                    app_id,
                    app_name: "db".into(),
                    release: Release {
                        number: 1,
                        spec: spec.clone(),
                        image_digest: String::new(),
                        platforms: Vec::new(),
                        exposed_ports: None,
                        secret_versions: Vec::new(),
                        source: ReleaseSource::File,
                        rollback_of: None,
                        note: String::new(),
                        created_by: Uuid::nil(),
                        created_at: at,
                        external_release: None,
                        request: None,
                    },
                    settings: grund_config::app::spec::AppSettings::default(),
                    depends_on: Vec::new(),
                    exclusive: true,
                    template: Some("postgres".into()),
                },
            )]),
            public_service: None,
            public_port: None,
            created_at: at,
            created_by: Uuid::nil(),
            rollback_of: None,
        };
        let stacks = state.stacks();
        let mut conn = state.pool.acquire().await?;
        assert_eq!(
            stacks
                .choose_machine(&mut conn, org, &revision, None, None)
                .await?
                .machine,
            None,
            "a machine that does not report volume support holds no directories"
        );
        sqlx::query("UPDATE grund_machine_presence SET capabilities=$2 WHERE machine_id=$1")
            .bind(machine)
            .bind(capabilities(true))
            .execute(&mut *conn)
            .await?;
        assert_eq!(
            stacks
                .choose_machine(&mut conn, org, &revision, None, None)
                .await?
                .machine,
            Some(machine),
            "a leased hosted machine holds directories on its own disk"
        );
        drop(conn);

        let volume = Uuid::now_v7();
        let data = spec.volumes[0].clone();
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.volume(
            volume,
            VolumeCommand::Request {
                organisation_id: org,
                app_id,
                name: data.name.clone(),
                path: data.path.clone(),
                source: None,
                backup: false,
                size_gib: None,
                at,
            },
        )
        .await?;
        work.commit().await?;
        let status = || {
            sqlx::query_as::<_, (String, Option<Uuid>)>(
                "SELECT status, machine_id FROM grund_volumes WHERE volume_id=$1",
            )
            .bind(volume)
            .fetch_one(&state.pool)
        };
        assert_eq!(status().await?, ("requested".into(), None));
        let mut block = data.clone();
        block.size_gib = Some(10);
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        assert!(
            matches!(
                state
                    .volumes()
                    .place_release_in(&mut work, org, app_id, machine, &[block])
                    .await,
                Err(crate::services::volumes::VolumesError::InvalidMachine)
            ),
            "a hosted block still needs the storage backend"
        );
        drop(work);
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        state
            .volumes()
            .place_release_in(&mut work, org, app_id, machine, std::slice::from_ref(&data))
            .await?;
        work.commit().await?;
        assert_eq!(status().await?, ("attached".into(), Some(machine)));

        sqlx::query("UPDATE grund_machines SET state='returning', returning_organisation_id=pool_organisation_id, pool_organisation_id=NULL WHERE machine_id=$1")
            .bind(machine).execute(&state.pool).await?;
        let mut conn = state.pool.acquire().await?;
        assert_eq!(
            stacks
                .choose_machine(&mut conn, org, &revision, None, None)
                .await?
                .machine,
            None,
            "a returning machine is wiped and holds nothing"
        );
        Ok(())
    }

    struct Bundle {
        org: Uuid,
        id: Uuid,
        producer: Uuid,
        consumer: Uuid,
        volume: Uuid,
        machine: Uuid,
        former: Operation,
    }

    async fn bundle(state: &State, running: bool) -> anyhow::Result<Bundle> {
        let org = Uuid::now_v7();
        let id = Uuid::now_v7();
        let machine = Uuid::now_v7();
        let volume = Uuid::now_v7();
        let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&state.pool)
            .await?;
        sqlx::query("INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) VALUES($1,'lifecycle','personal',$2,1)")
            .bind(org).bind(at).execute(&state.pool).await?;
        if running {
            sqlx::query("INSERT INTO grund_machines(machine_id,pool,home_organisation_id,name,state,public_key,pool_organisation_id,pool_name,minted_by,registered_at,key_registered_at,stream_version) VALUES($1,'organisation',$2,'worker','active',repeat('a',64),$2,'worker','test',$3,$3,1)")
                .bind(machine).bind(org).bind(at).execute(&state.pool).await?;
        }
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(id);
        work.stack(
            id,
            Command::Create {
                organisation_id: org,
                name: "ordered".into(),
            },
        )
        .await?;
        let mut services = BTreeMap::new();
        for name in ["producer", "consumer"] {
            let app_id = Uuid::now_v7();
            let settings = grund_config::app::spec::AppSettings::default();
            work.app(
                app_id,
                AppCommand::Create {
                    actor: Uuid::nil(),
                    organisation_id: org,
                    name: AppName::parse(name)?,
                    settings: settings.clone(),
                    at,
                },
            )
            .await?;
            work.app(app_id, AppCommand::AssignStack { stack_id: id, at })
                .await?;
            let mut spec = grund_domain::app::templates::find("redis")
                .unwrap()
                .spec(false)
                .context("Redis catalogue entry is available")?;
            spec.volumes.clear();
            spec.secrets.clear();
            if name == "consumer" {
                spec.ports = vec![grund_config::app::spec::PortSpec {
                    name: "http".into(),
                    port: 8080,
                    protocol: grund_config::app::spec::Protocol::Http,
                    public: true,
                }];
            }
            work.app(
                app_id,
                AppCommand::Release {
                    actor: Uuid::nil(),
                    spec,
                    image_digest: format!("sha256:{}", "a".repeat(64)),
                    platforms: Vec::new(),
                    exposed_ports: None,
                    secret_versions: Vec::new(),
                    source: ReleaseSource::File,
                    external_release: None,
                    request: None,
                    rollback_of: None,
                    note: String::new(),
                    rollout_id: Uuid::now_v7(),
                    at,
                },
            )
            .await?;
            if running {
                work.app_decide(app_id, |_| {
                    Ok((
                        vec![AppEvent::ReplicaPlaced {
                            replica_id: Uuid::now_v7(),
                            slot: 0,
                            release: 1,
                            machine_id: machine,
                            placement: 0,
                            reason: PlaceReason::Scale,
                            placed_at: at,
                        }],
                        (),
                    ))
                })
                .await?;
            }
            let app = work.load_app(app_id).await?;
            services.insert(
                name.into(),
                Service {
                    app_id,
                    app_name: name.into(),
                    release: app.releases[0].clone(),
                    settings,
                    depends_on: if name == "consumer" {
                        vec!["producer".into()]
                    } else {
                        Vec::new()
                    },
                    exclusive: true,
                    template: None,
                },
            );
        }
        let producer = services["producer"].app_id;
        let consumer = services["consumer"].app_id;
        work.volume(
            volume,
            VolumeCommand::Request {
                organisation_id: org,
                app_id: producer,
                name: "data".into(),
                path: "/data".into(),
                source: None,
                backup: false,
                size_gib: None,
                at,
            },
        )
        .await?;
        let former = operation(
            Kind::Deploy,
            1,
            0,
            vec!["producer".into(), "consumer".into()],
            at,
        );
        work.stack(
            id,
            Command::Revise {
                revision: Revision {
                    number: 1,
                    yaml: "stack:\n  name: ordered\n  public: {service: consumer, port: http}\n  services:\n    producer:\n      image: redis\n      restart: exclusive\n    consumer:\n      image: redis\n      restart: exclusive\n      depends_on: [producer]\n      ports: [{name: http, port: 8080, protocol: http}]\n".into(),
                    services,
                    public_service: Some("consumer".into()),
                    public_port: Some("http".into()),
                    created_at: at,
                    created_by: Uuid::nil(),
                    rollback_of: None,
                },
                operation: former.clone(),
            },
        )
        .await?;
        work.commit().await?;
        Ok(Bundle {
            org,
            id,
            producer,
            consumer,
            volume,
            machine,
            former,
        })
    }

    async fn release_both_members(
        state: &State,
        bundle: &Bundle,
        public: bool,
    ) -> anyhow::Result<()> {
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(bundle.id);
        let stack = work.load_stack(bundle.id).await?;
        let mut revision = stack.revisions[&stack.desired_revision].clone();
        if let Some(op) = &stack.operation {
            work.stack(
                bundle.id,
                Command::Complete {
                    operation_id: op.id,
                    applied_revision: revision.number,
                    status: Status::Ready,
                    purge_after: None,
                    failure: None,
                },
            )
            .await?;
        }
        let previous = revision
            .public_service
            .as_ref()
            .map(|name| revision.services[name].app_id);
        revision.number += 1;
        revision.public_service = None;
        revision.public_port = None;
        revision.yaml = "stack:\n  name: ordered\n  public:\n    - {service: producer, port: http}\n    - {service: consumer, port: http}\n  services:\n    producer:\n      image: redis\n      restart: exclusive\n      ports: [{name: http, port: 8080, protocol: h2c}]\n    consumer:\n      image: redis\n      restart: exclusive\n      depends_on: [producer]\n      ports: [{name: http, port: 8080, protocol: http}]\n".into();
        if !public {
            revision.yaml = revision.yaml.replace(
                "  public:\n    - {service: producer, port: http}\n    - {service: consumer, port: http}\n",
                "",
            );
        }
        for (name, service) in &mut revision.services {
            service.release.spec.ports = vec![grund_config::app::spec::PortSpec {
                name: "http".into(),
                port: 8080,
                protocol: if name == "producer" {
                    Protocol::H2c
                } else {
                    Protocol::Http
                },
                public,
            }];
            work.app(
                service.app_id,
                AppCommand::Release {
                    actor: Uuid::nil(),
                    spec: service.release.spec.clone(),
                    image_digest: service.release.image_digest.clone(),
                    platforms: Vec::new(),
                    exposed_ports: None,
                    secret_versions: Vec::new(),
                    source: ReleaseSource::File,
                    external_release: None,
                    request: None,
                    rollback_of: None,
                    note: String::new(),
                    rollout_id: Uuid::now_v7(),
                    at: Utc::now(),
                },
            )
            .await?;
            service.release = work
                .load_app(service.app_id)
                .await?
                .releases
                .last()
                .unwrap()
                .clone();
            sqlx::query("UPDATE grund_replicas SET release=$2 WHERE app_id=$1")
                .bind(service.app_id)
                .bind(service.release.number as i32)
                .execute(&mut **work.sql())
                .await?;
        }
        let op = operation(
            Kind::Deploy,
            revision.number,
            stack.applied_revision,
            order(&revision)?,
            Utc::now(),
        );
        work.stack(
            bundle.id,
            Command::Revise {
                revision,
                operation: op,
            },
        )
        .await?;
        state
            .domains()
            .rebind_stack_public_in(
                &mut work,
                Uuid::nil(),
                bundle.org,
                bundle.id,
                previous,
                None,
                "ordered",
            )
            .await?;
        work.commit().await?;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn public_members_keep_their_bound_domains_and_edge_routes_after_another_stack_release(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        use crate::services::entry::EntryState;
        use grund_domain::custom_domain::{DomainCommand, DomainName};
        let mut state = state(pool).await?;
        let config = Arc::get_mut(&mut state.config).unwrap();
        config.entry.app_domains = crate::config::AppDomains::CustomOnly;
        config.tls.acme_directory = Some("https://acme.example.test/directory".into());
        state.certificates = crate::certificates::Certificates::new(
            &state.config,
            state.pool.clone(),
            state.secret.clone(),
        );
        let bundle = bundle(&state, true).await?;
        release_both_members(&state, &bundle, false).await?;
        let at = Utc::now();
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        for name in ["gateway.example.test", "queue.example.test"] {
            let domain = Uuid::now_v7();
            work.domain(
                domain,
                DomainCommand::Add {
                    actor: Uuid::nil(),
                    organisation_id: bundle.org,
                    name: DomainName::parse(name)?,
                    token: format!("grund-verify-{}", "b".repeat(43)),
                    at,
                },
            )
            .await?;
            work.domain(
                domain,
                DomainCommand::Verify {
                    actor: Uuid::nil(),
                    at,
                },
            )
            .await?;
        }
        work.commit().await?;
        let membership = grund_store::organisations::Membership {
            organisation_id: bundle.org,
            slug: "lifecycle".into(),
            kind: "personal".into(),
            role: "owner".into(),
            created_at: at,
            deletion_requested_at: None,
            deletion_request_id: None,
            deletion_refusal: None,
        };
        for (domain, app_name) in [
            ("gateway.example.test", "producer"),
            ("queue.example.test", "consumer"),
        ] {
            state
                .domains()
                .bind(Uuid::nil(), &membership, domain, app_name)
                .await?;
        }
        for app in [bundle.producer, bundle.consumer] {
            let spec = grund_store::domains::current_spec(&state.pool, app)
                .await?
                .unwrap();
            assert!(spec.ports.iter().all(|port| !port.public));
        }
        let custom_certificates = || {
            sqlx::query_as::<_, (Vec<String>, String)>(
                "SELECT names,challenge FROM grund_certificates \
                 WHERE names && ARRAY['gateway.example.test','queue.example.test']::text[] \
                 ORDER BY names",
            )
            .fetch_all(&state.pool)
        };
        assert!(custom_certificates().await?.is_empty());
        release_both_members(&state, &bundle, true).await?;
        assert_eq!(
            custom_certificates().await?,
            vec![
                (
                    vec!["gateway.example.test".to_string()],
                    "http-01".to_string()
                ),
                (
                    vec!["queue.example.test".to_string()],
                    "http-01".to_string()
                ),
            ],
        );
        let parent = Uuid::now_v7();
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        for command in [
            DomainCommand::Add {
                actor: Uuid::nil(),
                organisation_id: bundle.org,
                name: DomainName::parse("apps.example.test")?,
                token: format!("grund-verify-{}", "a".repeat(43)),
                at,
            },
            DomainCommand::Verify {
                actor: Uuid::nil(),
                at,
            },
            DomainCommand::EnableAppDomain {
                actor: Uuid::nil(),
                at,
            },
        ] {
            work.domain(parent, command).await?;
        }
        state
            .domains()
            .rebind_stack_public_in(
                &mut work,
                Uuid::nil(),
                bundle.org,
                bundle.id,
                None,
                None,
                "ordered",
            )
            .await?;
        work.commit().await?;
        sqlx::query("INSERT INTO grund_machine_presence(machine_id,last_seen_at) VALUES($1,clock_timestamp())")
            .bind(bundle.machine).execute(&state.pool).await?;
        sqlx::query("INSERT INTO grund_replica_status(replica_id,machine_id,state,ready,observed_at) \
            SELECT replica_id,machine_id,'running',true,clock_timestamp() FROM grund_replicas WHERE machine_id=$1")
            .bind(bundle.machine).execute(&state.pool).await?;
        for release in 0..2 {
            if release != 0 {
                release_both_members(&state, &bundle, true).await?;
            }
            let table = state.entry().route_table().await?;
            for (app, custom, generated) in [
                (
                    bundle.producer,
                    "gateway.example.test",
                    "producer.apps.example.test",
                ),
                (
                    bundle.consumer,
                    "queue.example.test",
                    "consumer.apps.example.test",
                ),
            ] {
                let assignment =
                    grund_store::domains::managed_assignment(&state.pool, bundle.org, app)
                        .await?
                        .unwrap();
                assert_eq!(assignment.name, generated);
                assert_eq!(assignment.app_id, Some(app));
                for name in [custom, generated] {
                    let route = table
                        .routes
                        .iter()
                        .find(|route| route.name == name)
                        .unwrap();
                    assert_eq!(route.app_id, app.to_string());
                    assert_eq!(route.machines.len(), 1);
                    assert_eq!(route.machines[0].machine_id, bundle.machine.to_string());
                    assert_eq!(route.machines[0].ready_copies, 1);
                }
            }
            assert!(
                !table
                    .routes
                    .iter()
                    .any(|route| route.name == "ordered.apps.example.test")
            );
        }
        Ok(())
    }
    #[sqlx::test(migrations = false)]
    async fn restoring_a_multi_public_stack_restores_each_managed_address_before_capacity_is_available(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        use grund_domain::custom_domain::{DomainCommand, DomainName};
        let state = state(pool).await?;
        let bundle = bundle(&state, false).await?;
        release_both_members(&state, &bundle, true).await?;
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        let at = Utc::now();
        let parent = Uuid::now_v7();
        for command in [
            DomainCommand::Add {
                actor: Uuid::nil(),
                organisation_id: bundle.org,
                name: DomainName::parse("restore.example.test")?,
                token: format!("grund-verify-{}", "c".repeat(43)),
                at,
            },
            DomainCommand::Verify {
                actor: Uuid::nil(),
                at,
            },
            DomainCommand::EnableAppDomain {
                actor: Uuid::nil(),
                at,
            },
        ] {
            work.domain(parent, command).await?;
        }
        state
            .domains()
            .rebind_stack_public_in(
                &mut work,
                Uuid::nil(),
                bundle.org,
                bundle.id,
                None,
                None,
                "ordered",
            )
            .await?;
        let stack = work.load_stack(bundle.id).await?;
        work.stack(
            bundle.id,
            Command::Complete {
                operation_id: stack.operation.unwrap().id,
                applied_revision: stack.desired_revision,
                status: Status::Ready,
                purge_after: None,
                failure: None,
            },
        )
        .await?;
        work.commit().await?;
        let before = grund_store::domains::list(&state.pool, bundle.org).await?;
        let version = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .stream_version;
        state
            .stacks()
            .delete(
                Uuid::nil(),
                bundle.org,
                "ordered",
                Some(version),
                "delete-multi",
            )
            .await?;
        for _ in 0..5 {
            state.stacks().reconcile_one(bundle.org, bundle.id).await?;
        }
        let deleted = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap();
        assert_eq!(deleted.state.status, Status::Deleted);
        state
            .stacks()
            .restore(
                Uuid::nil(),
                bundle.org,
                "ordered",
                Some(deleted.stream_version),
                "restore-multi",
            )
            .await?;
        for app in [bundle.producer, bundle.consumer] {
            let assignment = grund_store::domains::managed_assignment(&state.pool, bundle.org, app)
                .await?
                .unwrap();
            assert_eq!(assignment.app_id, Some(app));
            assert!(
                before
                    .iter()
                    .any(|row| row.domain_id == assignment.domain_id && row.app_id == Some(app))
            );
        }
        state.stacks().reconcile_one(bundle.org, bundle.id).await?;
        assert_eq!(
            store::get(&state.pool, bundle.org, bundle.id)
                .await?
                .unwrap()
                .state
                .status,
            Status::Waiting
        );
        Ok(())
    }

    async fn snapshot(state: &State) -> anyhow::Result<serde_json::Value> {
        Ok(sqlx::query_scalar::<_, Json<serde_json::Value>>(
            "SELECT jsonb_build_object( \
             'stacks',(SELECT jsonb_agg(to_jsonb(s) ORDER BY stack_id) FROM grund_stacks s), \
             'apps',(SELECT jsonb_agg(to_jsonb(a) ORDER BY app_id) FROM grund_apps a), \
             'volumes',(SELECT jsonb_agg(to_jsonb(v) ORDER BY volume_id) FROM grund_volumes v), \
             'requests',(SELECT jsonb_agg(to_jsonb(r) ORDER BY request_key) FROM grund_stack_requests r), \
             'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY stack_id,service) FROM grund_stack_members m), \
             'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY stack_id,operation_id,replica_id) FROM grund_stack_receipts r), \
             'events',(SELECT count(*) FROM es_events))"
        ).fetch_one(&state.pool).await?.0)
    }

    async fn delete_retained_bundle(
        state: &State,
        bundle: &Bundle,
        at: DateTime<Utc>,
        deadline: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(bundle.id);
        let deletion = operation(Kind::Delete, 1, 0, Vec::new(), at);
        work.stack(
            bundle.id,
            Command::Operate {
                operation: deletion.clone(),
                at,
            },
        )
        .await?;
        for app in [bundle.producer, bundle.consumer] {
            work.app(
                app,
                AppCommand::Delete {
                    actor: Uuid::nil(),
                    at,
                    purge_after: deadline,
                },
            )
            .await?;
            state
                .domains()
                .unbind_app_in(&mut work, Uuid::nil(), app)
                .await?;
        }
        work.volume(
            bundle.volume,
            VolumeCommand::Delete {
                at,
                purge_after: deadline,
            },
        )
        .await?;
        work.stack(
            bundle.id,
            Command::Complete {
                operation_id: deletion.id,
                applied_revision: 1,
                status: Status::Deleted,
                purge_after: Some(deadline),
                failure: None,
            },
        )
        .await?;
        work.commit().await?;
        Ok(())
    }

    async fn retained_template(
        state: &State,
        bundle: &Bundle,
        template: &str,
        size_gib: Option<u64>,
    ) -> anyhow::Result<Service> {
        let catalogue = grund_domain::app::templates::find(template).unwrap();
        let mut spec = catalogue.spec(false).unwrap();
        spec.volumes[0].size_gib = size_gib;
        spec.volumes[0].backup = true;
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(bundle.id);
        work.app(
            bundle.producer,
            AppCommand::Release {
                actor: Uuid::nil(),
                spec,
                image_digest: format!("sha256:{}", "a".repeat(64)),
                platforms: Vec::new(),
                exposed_ports: None,
                secret_versions: Vec::new(),
                source: ReleaseSource::File,
                external_release: None,
                request: None,
                rollback_of: None,
                note: String::new(),
                rollout_id: Uuid::now_v7(),
                at: Utc::now(),
            },
        )
        .await?;
        let mut prior =
            work.load_stack(bundle.id).await?.revisions[&1].services["producer"].clone();
        prior.template = Some(template.into());
        prior.release = work
            .load_app(bundle.producer)
            .await?
            .releases
            .last()
            .unwrap()
            .clone();
        work.commit().await?;
        Ok(prior)
    }

    fn data_selection(template: &str, name: &str, overlay: &str) -> Definition {
        stack::parse(&format!(
            "stack:\n  name: ordered\n  services:\n    producer:\n      template: {template}\n      data_volume: {name}\n{overlay}"
        ))
        .unwrap()
    }

    async fn volume_commands(
        state: &State,
        id: Uuid,
        commands: Vec<VolumeCommand>,
    ) -> anyhow::Result<()> {
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        for command in commands {
            work.volume(id, command).await?;
        }
        work.commit().await?;
        Ok(())
    }

    async fn selectable_volume(
        state: &State,
        bundle: &Bundle,
        prior: &Service,
        name: &str,
    ) -> anyhow::Result<Uuid> {
        let id = Uuid::now_v7();
        let current = &prior.release.spec.volumes[0];
        let at = Utc::now();
        volume_commands(
            state,
            id,
            vec![
                VolumeCommand::Request {
                    organisation_id: bundle.org,
                    app_id: prior.app_id,
                    name: name.into(),
                    path: current.path.clone(),
                    source: None,
                    backup: false,
                    size_gib: current.size_gib,
                    at,
                },
                VolumeCommand::Place {
                    machine_id: bundle.machine,
                    at,
                },
            ],
        )
        .await?;
        Ok(id)
    }

    #[sqlx::test(migrations = false)]
    async fn every_stateful_template_selects_ready_same_app_data_without_resizing_or_replacing_it(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, true).await?;
        let stacks = state.stacks();
        for template in ["postgres", "redis", "seaweedfs"] {
            let prior = retained_template(&state, &bundle, template, None).await?;
            let name = format!("{template}-restored");
            let id = selectable_volume(&state, &bundle, &prior, &name).await?;
            sqlx::query("INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,destination_volume_id,snapshot_id,status) VALUES ($1,$2,$3,$4,$5,1,'restore',$3,$6,'fixture-point','completed')")
                .bind(bundle.org).bind(bundle.producer).bind(bundle.volume)
                .bind(Uuid::now_v7()).bind(bundle.machine).bind(id)
                .execute(&state.pool).await?;
            let definition = data_selection(template, &name, "");
            let before = snapshot(&state).await?;
            let mut connection = state.pool.acquire().await?;
            let selected = stacks
                .selected_data_volume(
                    &mut connection,
                    bundle.org,
                    "producer",
                    &definition.services["producer"],
                    Some(&prior),
                    Some(bundle.machine),
                )
                .await?
                .context("a completed same-app restore is selectable")?;
            assert_eq!(selected.volume_id, id);
            assert_eq!(selected.app_id, prior.app_id);
            assert_eq!(selected.organisation_id, bundle.org);
            assert_eq!(selected.path, prior.release.spec.volumes[0].path);
            assert_eq!(
                selected.size_gib, None,
                "own-machine data must not become a catalogue-sized block"
            );
            assert!(
                !selected.backup,
                "restore policy is not inherited from the source release"
            );
            let catalogue = grund_domain::app::templates::find(template);
            let (spec, _, _) = expand_service(&definition, "producer", catalogue, Some(&prior))?;
            assert_eq!(spec.volumes.len(), 1);
            assert_eq!(spec.volumes[0].name, name);
            assert_eq!(spec.volumes[0].path, selected.path);
            assert_eq!(spec.volumes[0].size_gib, None);
            let explicit = data_selection(
                template,
                &name,
                "      volumes:\n        data: {backup: daily}\n",
            );
            let (spec, _, _) = expand_service(&explicit, "producer", catalogue, Some(&prior))?;
            assert!(
                spec.volumes[0].backup,
                "canonical data policy applies to the renamed mount"
            );
            drop(connection);
            assert_eq!(
                snapshot(&state).await?,
                before,
                "selection must not mutate either disk or app"
            );

            let hosted = retained_template(&state, &bundle, template, Some(37)).await?;
            let hosted_id =
                selectable_volume(&state, &bundle, &hosted, &format!("{template}-block")).await?;
            let persisted = grund_store::volumes::any_volume(
                &state.pool,
                bundle.org,
                bundle.producer,
                hosted_id,
            )
            .await?
            .unwrap();
            assert_eq!(persisted.size_gib, Some(37));
            let (spec, _, _) = expand_service(&definition, "producer", catalogue, Some(&hosted))?;
            assert_eq!(
                spec.volumes[0].size_gib,
                Some(37),
                "a retained nondefault capacity must not reset to the catalogue default"
            );
            let mut wrong_kind = definition.clone();
            wrong_kind
                .services
                .get_mut("producer")
                .unwrap()
                .app
                .placement = Some(grund_config::app::file::FilePlacement {
                kind: Some(grund_config::app::file::FileMachineKind::Own),
                ..Default::default()
            });
            assert!(matches!(
                expand_service(&wrong_kind, "producer", catalogue, Some(&hosted)),
                Err(Error::Invalid(_))
            ));
        }
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn data_selection_never_falls_back_to_an_empty_disk_or_crosses_app_and_tenant_boundaries(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, true).await?;
        let stacks = state.stacks();
        let foreign_org = Uuid::now_v7();
        sqlx::query("INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) VALUES($1,'foreign','personal',clock_timestamp(),1)")
            .bind(foreign_org).execute(&state.pool).await?;
        for template in ["postgres", "redis", "seaweedfs"] {
            let prior = retained_template(&state, &bundle, template, None).await?;
            let name = format!("{template}-restored");
            selectable_volume(&state, &bundle, &prior, &name).await?;
            let mut foreign = prior.clone();
            foreign.app_id = bundle.consumer;
            selectable_volume(&state, &bundle, &foreign, &format!("{template}-other-app")).await?;
            let mut wrong_capacity = prior.clone();
            wrong_capacity.release.spec.volumes[0].size_gib = Some(37);
            let at = Utc::now();
            volume_commands(
                &state,
                Uuid::now_v7(),
                vec![
                    VolumeCommand::Request {
                        organisation_id: bundle.org,
                        app_id: prior.app_id,
                        name: format!("{template}-import"),
                        path: prior.release.spec.volumes[0].path.clone(),
                        source: Some("/srv/import".into()),
                        backup: false,
                        size_gib: None,
                        at,
                    },
                    VolumeCommand::Place {
                        machine_id: bundle.machine,
                        at,
                    },
                ],
            )
            .await?;
            let before = snapshot(&state).await?;
            let mut connection = state.pool.acquire().await?;
            for (selected, org, retained, machine) in [
                (
                    format!("{template}-restroed"),
                    bundle.org,
                    Some(&prior),
                    Some(bundle.machine),
                ),
                (
                    format!("{template}-other-app"),
                    bundle.org,
                    Some(&prior),
                    Some(bundle.machine),
                ),
                (
                    name.clone(),
                    foreign_org,
                    Some(&prior),
                    Some(bundle.machine),
                ),
                (name.clone(), bundle.org, None, Some(bundle.machine)),
                (name.clone(), bundle.org, Some(&prior), None),
                (name.clone(), bundle.org, Some(&prior), Some(Uuid::now_v7())),
                (
                    name.clone(),
                    bundle.org,
                    Some(&wrong_capacity),
                    Some(bundle.machine),
                ),
                (
                    format!("{template}-import"),
                    bundle.org,
                    Some(&prior),
                    Some(bundle.machine),
                ),
            ] {
                let definition = data_selection(template, &selected, "");
                assert!(
                    matches!(
                        stacks
                            .selected_data_volume(
                                &mut connection,
                                org,
                                "producer",
                                &definition.services["producer"],
                                retained,
                                machine,
                            )
                            .await,
                        Err(Error::Invalid(_))
                    ),
                    "{template}: missing, first-deploy, foreign or misplaced data must be refused"
                );
            }
            drop(connection);
            assert_eq!(
                snapshot(&state).await?,
                before,
                "refusals must allocate nothing and emit no events"
            );
        }
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn only_completed_restores_with_a_live_canonical_mount_can_be_selected(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, true).await?;
        let stacks = state.stacks();
        for template in ["postgres", "redis", "seaweedfs"] {
            let prior = retained_template(&state, &bundle, template, None).await?;
            let name = format!("{template}-restored");
            let id = selectable_volume(&state, &bundle, &prior, &name).await?;
            let attempt = Uuid::now_v7();
            sqlx::query("INSERT INTO grund_volume_backup_attempts (organisation_id,app_id,volume_id,attempt_id,machine_id,placement_generation,operation,source_volume_id,destination_volume_id,snapshot_id,status) VALUES ($1,$2,$3,$4,$5,1,'restore',$3,$6,'fixture-point','pending')")
                .bind(bundle.org).bind(bundle.producer).bind(bundle.volume)
                .bind(attempt).bind(bundle.machine).bind(id)
                .execute(&state.pool).await?;
            let definition = data_selection(template, &name, "");
            for status in ["pending", "leased", "failed", "completed"] {
                sqlx::query("UPDATE grund_volume_backup_attempts SET status=$3 WHERE organisation_id=$1 AND attempt_id=$2")
                    .bind(bundle.org).bind(attempt).bind(status).execute(&state.pool).await?;
                let before = snapshot(&state).await?;
                let mut connection = state.pool.acquire().await?;
                let result = stacks
                    .selected_data_volume(
                        &mut connection,
                        bundle.org,
                        "producer",
                        &definition.services["producer"],
                        Some(&prior),
                        Some(bundle.machine),
                    )
                    .await;
                if status == "completed" {
                    assert_eq!(result?.unwrap().volume_id, id);
                } else {
                    assert!(
                        matches!(result, Err(Error::Invalid(_))),
                        "{template}: {status} restore must remain unmountable"
                    );
                }
                drop(connection);
                assert_eq!(snapshot(&state).await?, before);
            }
            volume_commands(
                &state,
                id,
                vec![VolumeCommand::Attach {
                    machine_id: bundle.machine,
                    path: "/wrong-path".into(),
                    at: Utc::now(),
                }],
            )
            .await?;
            let before = snapshot(&state).await?;
            let mut connection = state.pool.acquire().await?;
            assert!(matches!(
                stacks
                    .selected_data_volume(
                        &mut connection,
                        bundle.org,
                        "producer",
                        &definition.services["producer"],
                        Some(&prior),
                        Some(bundle.machine),
                    )
                    .await,
                Err(Error::Invalid(_))
            ));
            drop(connection);
            assert_eq!(snapshot(&state).await?, before);
            volume_commands(
                &state,
                id,
                vec![
                    VolumeCommand::Attach {
                        machine_id: bundle.machine,
                        path: prior.release.spec.volumes[0].path.clone(),
                        at: Utc::now(),
                    },
                    VolumeCommand::Delete {
                        at: Utc::now(),
                        purge_after: Utc::now() + chrono::Duration::days(1),
                    },
                ],
            )
            .await?;
            let before = snapshot(&state).await?;
            let mut connection = state.pool.acquire().await?;
            assert!(matches!(
                stacks
                    .selected_data_volume(
                        &mut connection,
                        bundle.org,
                        "producer",
                        &definition.services["producer"],
                        Some(&prior),
                        Some(bundle.machine),
                    )
                    .await,
                Err(Error::Invalid(_))
            ));
            drop(connection);
            assert_eq!(snapshot(&state).await?, before);

            let hosted = retained_template(&state, &bundle, template, Some(37)).await?;
            let name = format!("{template}-detaching");
            let id = selectable_volume(&state, &bundle, &hosted, &name).await?;
            volume_commands(
                &state,
                id,
                vec![
                    VolumeCommand::PrepareBackend {
                        machine_id: bundle.machine,
                        slot: 1,
                        at: Utc::now(),
                    },
                    VolumeCommand::ConfirmBackendAttachment {
                        machine_id: bundle.machine,
                        at: Utc::now(),
                    },
                    VolumeCommand::BeginBackendDetachment {
                        machine_id: bundle.machine,
                        at: Utc::now(),
                    },
                ],
            )
            .await?;
            let definition = data_selection(template, &name, "");
            for lost in [false, true] {
                if lost {
                    volume_commands(
                        &state,
                        id,
                        vec![VolumeCommand::DeclareLost {
                            host_id: Uuid::now_v7(),
                            host_name: "lost-host".into(),
                            snapshot_id: None,
                            at: Utc::now(),
                        }],
                    )
                    .await?;
                }
                let before = snapshot(&state).await?;
                let mut connection = state.pool.acquire().await?;
                assert!(matches!(
                    stacks
                        .selected_data_volume(
                            &mut connection,
                            bundle.org,
                            "producer",
                            &definition.services["producer"],
                            Some(&hosted),
                            Some(bundle.machine),
                        )
                        .await,
                    Err(Error::Invalid(_))
                ));
                drop(connection);
                assert_eq!(snapshot(&state).await?, before);
            }
        }
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn seaweedfs_consumers_receive_both_release_pinned_keys_and_missing_pins_fail_closed(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, false).await?;
        let stacks = state.stacks();
        let sealing = key(&state);
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(bundle.id);
        let template = grund_domain::app::templates::find("seaweedfs")
            .context("SeaweedFS catalogue entry is available")?;
        let mut spec = template.spec(false).context("SeaweedFS is available")?;
        for variable in template.secret_variables {
            spec.secrets.push(SecretEnv {
                env: (*variable).into(),
                secret: crate::services::apps::secret_name_for(variable),
            });
        }
        let pinned = crate::services::apps::generate_template_credentials_in(
            &mut work,
            &sealing,
            Uuid::nil(),
            bundle.org,
            bundle.producer,
            template,
        )
        .await?;
        work.app(
            bundle.producer,
            AppCommand::Release {
                actor: Uuid::nil(),
                spec,
                image_digest: format!("sha256:{}", "a".repeat(64)),
                platforms: Vec::new(),
                exposed_ports: None,
                secret_versions: pinned,
                source: ReleaseSource::File,
                external_release: None,
                request: None,
                rollback_of: None,
                note: String::new(),
                rollout_id: Uuid::now_v7(),
                at: Utc::now(),
            },
        )
        .await?;
        let mut producer =
            work.load_stack(bundle.id).await?.revisions[&1].services["producer"].clone();
        producer.template = Some(template.key.into());
        producer.release = work
            .load_app(bundle.producer)
            .await?
            .releases
            .last()
            .context("producer has a released credential pair")?
            .clone();
        let newer = crate::services::apps::generate_template_credentials_in(
            &mut work,
            &sealing,
            Uuid::nil(),
            bundle.org,
            bundle.producer,
            template,
        )
        .await?;
        work.commit().await?;

        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        assert_eq!(
            stacks
                .output(&mut work, &sealing, "ordered", &producer, "producer", "url")
                .await?,
            "http://producer.ordered.grund.internal:8333"
        );
        for (index, (output, variable)) in [
            ("access_key_id", "S3_ACCESS_KEY_ID"),
            ("secret_access_key", "S3_SECRET_ACCESS_KEY"),
        ]
        .into_iter()
        .enumerate()
        {
            let name = crate::services::apps::secret_name_for(variable);
            let pinned = producer
                .release
                .secret_versions
                .iter()
                .find(|version| version.name == name)
                .context("producer release pins each credential")?;
            let latest = newer
                .iter()
                .find(|version| version.name == name)
                .context("a newer credential exists")?;
            assert!(latest.version > pinned.version);
            let sealed = apps::secret_value(
                &mut **work.sql(),
                producer.app_id,
                &name,
                pinned.version as i32,
            )
            .await?
            .context("pinned credential is stored")?;
            let expected = open(
                &sealing,
                producer.app_id,
                &name,
                pinned.version as i32,
                &sealed,
            )
            .context("pinned credential opens independently")?;
            let latest_sealed = apps::secret_value(
                &mut **work.sql(),
                producer.app_id,
                &name,
                latest.version as i32,
            )
            .await?
            .context("newer credential is stored")?;
            let latest_value = open(
                &sealing,
                producer.app_id,
                &name,
                latest.version as i32,
                &latest_sealed,
            )
            .context("newer credential opens independently")?;
            assert!(expected != latest_value, "credential versions must differ");
            let resolved = stacks
                .output(
                    &mut work, &sealing, "ordered", &producer, "producer", output,
                )
                .await?;
            assert!(
                resolved.as_bytes() == expected.as_slice(),
                "consumer must receive the released credential, not a newer or regenerated key"
            );

            let mut missing_binding = producer.clone();
            missing_binding
                .release
                .spec
                .secrets
                .retain(|binding| binding.env != variable);
            assert!(matches!(
                stacks
                    .output(
                        &mut work,
                        &sealing,
                        "ordered",
                        &missing_binding,
                        "producer",
                        output,
                    )
                    .await,
                Err(Error::Invalid(_))
            ));
            let mut missing_pin = producer.clone();
            missing_pin
                .release
                .secret_versions
                .retain(|version| version.name != name);
            assert!(matches!(
                stacks
                    .output(
                        &mut work,
                        &sealing,
                        "ordered",
                        &missing_pin,
                        "producer",
                        output,
                    )
                    .await,
                Err(Error::Invalid(_))
            ));
            let removed = sqlx::query(
                "DELETE FROM grund_app_secrets \
                 WHERE organisation_id=$1 AND app_id=$2 AND name=$3 AND version=$4",
            )
            .bind(bundle.org)
            .bind(producer.app_id)
            .bind(&name)
            .bind(pinned.version as i32)
            .execute(&mut **work.sql())
            .await?;
            assert_eq!(removed.rows_affected(), 1);
            assert!(matches!(
                stacks
                    .output(
                        &mut work, &sealing, "ordered", &producer, "producer", output
                    )
                    .await,
                Err(Error::Invalid(_))
            ));
            let remaining: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM grund_app_secrets WHERE organisation_id=$1 AND app_id=$2",
            )
            .bind(bundle.org)
            .bind(producer.app_id)
            .fetch_one(&mut **work.sql())
            .await?;
            assert_eq!(remaining, 3 - index as i64);
        }
        work.commit().await?;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn first_deploy_compensation_retains_children_and_volume_without_a_purge_deadline(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, false).await?;
        let mut compensation = bundle.former.clone();
        compensation.order.reverse();
        compensation.halting = true;
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.stack(
            bundle.id,
            Command::Advance {
                operation: compensation,
                status: Status::RollingBack,
                machine_id: None,
                failure: Some("dependent failed readiness".into()),
            },
        )
        .await?;
        work.commit().await?;
        for _ in 0..6 {
            state.stacks().reconcile_one(bundle.org, bundle.id).await?;
        }
        let stack = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap();
        assert_eq!(stack.state.status, Status::Halted);
        for app_id in [bundle.producer, bundle.consumer] {
            let app = apps::app(&state.pool, app_id).await?.unwrap();
            assert!(app.deleted_at.is_none() && app.purge_after.is_none());
        }
        let volume = grund_store::volumes::any_volume(
            &state.pool,
            bundle.org,
            bundle.producer,
            bundle.volume,
        )
        .await?
        .unwrap();
        assert!(volume.purge_after.is_none());
        assert_ne!(volume.status, "pending_deletion");
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn accepted_restore_cancels_every_child_deadline_before_waiting_for_capacity(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let mut state = state(pool).await?;
        Arc::get_mut(&mut state.config).unwrap().entry.app_domains =
            crate::config::AppDomains::CustomOnly;
        let bundle = bundle(&state, false).await?;
        let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&state.pool)
            .await?;
        use grund_domain::custom_domain::{DomainCommand, DomainName};
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        let parent = Uuid::now_v7();
        for command in [
            DomainCommand::Add {
                actor: Uuid::nil(),
                organisation_id: bundle.org,
                name: DomainName::parse("apps.example.test")?,
                token: format!("grund-verify-{}", "a".repeat(43)),
                at,
            },
            DomainCommand::Verify {
                actor: Uuid::nil(),
                at,
            },
            DomainCommand::EnableAppDomain {
                actor: Uuid::nil(),
                at,
            },
        ] {
            work.domain(parent, command).await?;
        }
        state
            .domains()
            .rebind_stack_public_in(
                &mut work,
                Uuid::nil(),
                bundle.org,
                bundle.id,
                None,
                Some(bundle.consumer),
                "ordered",
            )
            .await?;
        work.commit().await?;
        let public_before =
            grund_store::domains::managed_assignment(&state.pool, bundle.org, bundle.consumer)
                .await?
                .unwrap();
        delete_retained_bundle(&state, &bundle, at, at + chrono::Duration::hours(1)).await?;
        assert!(
            grund_store::domains::managed_assignment(&state.pool, bundle.org, bundle.consumer,)
                .await?
                .unwrap()
                .app_id
                .is_none()
        );
        let version = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .stream_version;
        state
            .stacks()
            .restore(
                Uuid::nil(),
                bundle.org,
                "ordered",
                Some(version),
                "restore-before-capacity",
            )
            .await?;
        for app_id in [bundle.producer, bundle.consumer] {
            let app = apps::app(&state.pool, app_id).await?.unwrap();
            assert!(app.deleted_at.is_none() && app.purge_after.is_none());
        }
        let public_after =
            grund_store::domains::managed_assignment(&state.pool, bundle.org, bundle.consumer)
                .await?
                .unwrap();
        assert_eq!(public_after.domain_id, public_before.domain_id);
        assert_eq!(public_after.app_id, Some(bundle.consumer));
        state.stacks().reconcile_one(bundle.org, bundle.id).await?;
        let stack = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap();
        assert_eq!(stack.state.status, Status::Waiting);
        let volume = grund_store::volumes::any_volume(
            &state.pool,
            bundle.org,
            bundle.producer,
            bundle.volume,
        )
        .await?
        .unwrap();
        assert!(volume.purge_after.is_none());
        assert_ne!(volume.status, "pending_deletion");
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn expired_restore_records_nothing_and_restores_no_child_or_volume(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, false).await?;
        let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()-interval '1 second'")
            .fetch_one(&state.pool)
            .await?;
        delete_retained_bundle(&state, &bundle, at, at).await?;
        let before = snapshot(&state).await?;
        let version = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .stream_version;
        for _ in 0..2 {
            assert!(matches!(
                state
                    .stacks()
                    .restore(Uuid::nil(), bundle.org, "ordered", Some(version), "expired")
                    .await,
                Err(Error::NotFound)
            ));
            assert_eq!(snapshot(&state).await?, before);
        }
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn deleting_a_capacity_wait_supersedes_and_replays_without_starting_children(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, false).await?;
        let stacks = state.stacks();
        let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&state.pool)
            .await?;
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(bundle.id);
        let mut revision = work.load_stack(bundle.id).await?.revisions[&1].clone();
        work.stack(
            bundle.id,
            Command::Complete {
                operation_id: bundle.former.id,
                applied_revision: 1,
                status: Status::Ready,
                purge_after: None,
                failure: None,
            },
        )
        .await?;
        work.app(
            bundle.consumer,
            AppCommand::Delete {
                actor: Uuid::nil(),
                at,
                purge_after: at + Duration::hours(1),
            },
        )
        .await?;
        revision.number = 2;
        revision.services.remove("consumer");
        revision.public_service = None;
        let waiting = operation(Kind::Deploy, 2, 1, vec!["producer".into()], at);
        work.stack(
            bundle.id,
            Command::Revise {
                revision,
                operation: waiting,
            },
        )
        .await?;
        work.commit().await?;
        let version = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .stream_version;
        assert!(matches!(
            stacks
                .delete(
                    Uuid::nil(),
                    bundle.org,
                    "ordered",
                    Some(version - 1),
                    "stale"
                )
                .await,
            Err(Error::Conflict)
        ));
        let response = stacks
            .delete(Uuid::nil(), bundle.org, "ordered", Some(version), "delete")
            .await?;
        assert_eq!(response.status, "deleting");
        assert_ne!(response.operation, Some(bundle.former.id.to_string()));
        let deletion = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .state
            .0
            .operation
            .unwrap();
        assert_eq!(deletion.order, ["consumer", "producer"]);
        let before_replay = snapshot(&state).await?;
        let replay = stacks
            .delete(Uuid::nil(), bundle.org, "ordered", Some(version), "delete")
            .await?;
        assert_eq!(
            serde_json::to_value(response)?,
            serde_json::to_value(replay)?
        );
        assert_eq!(snapshot(&state).await?, before_replay);
        for app in [bundle.producer, bundle.consumer] {
            assert!(!state.apps().reconcile_app(app, bundle.org).await?);
            assert_eq!(apps::app_replicas(&state.pool, app).await?.len(), 0);
        }
        for _ in 0..5 {
            stacks.reconcile_one(bundle.org, bundle.id).await?;
        }
        let deleted = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap();
        assert_eq!(deleted.state.0.status, Status::Deleted);
        let deadline = deleted.state.0.purge_after.unwrap();
        for app in [bundle.producer, bundle.consumer] {
            assert_eq!(
                apps::app(&state.pool, app).await?.unwrap().purge_after,
                Some(deadline)
            );
        }
        let volume = grund_store::volumes::any_volume(
            &state.pool,
            bundle.org,
            bundle.producer,
            bundle.volume,
        )
        .await?
        .unwrap();
        assert_eq!(volume.status, "pending_deletion");
        assert_eq!(volume.purge_after, Some(deadline));
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn active_deletion_keeps_producers_until_their_turn_and_requires_current_stop_receipts(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, true).await?;
        let stacks = state.stacks();
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        let mut former = bundle.former.clone();
        former.step = Step::Applying;
        work.stack(
            bundle.id,
            Command::Advance {
                operation: former.clone(),
                status: Status::Deploying,
                machine_id: Some(bundle.machine),
                failure: None,
            },
        )
        .await?;
        work.commit().await?;
        let version = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .stream_version;
        stacks
            .delete(
                Uuid::nil(),
                bundle.org,
                "ordered",
                Some(version),
                "delete-active",
            )
            .await?;
        let deletion = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .state
            .0
            .operation
            .unwrap();
        assert_eq!(deletion.order, ["consumer", "producer"]);
        assert!(
            !state
                .apps()
                .reconcile_app(bundle.producer, bundle.org)
                .await?
        );
        for app in [bundle.consumer, bundle.producer] {
            stacks.reconcile_one(bundle.org, bundle.id).await?;
            state.apps().reconcile_app(app, bundle.org).await?;
            let replicas = apps::app_replicas(&state.pool, app).await?;
            assert_eq!(replicas.len(), 1);
            assert_eq!(replicas[0].state, "draining");
            if app == bundle.consumer {
                let producer = apps::app_replicas(&state.pool, bundle.producer).await?;
                assert_eq!(producer.len(), 1);
                assert_eq!(producer[0].state, "running");
            }
            let member = store::member(&state.pool, bundle.org, app).await?.unwrap();
            assert!(member.required_generation > 0);
            let mut connection = state.pool.acquire().await?;
            assert!(
                !apps::record_stack_receipt(
                    &mut connection,
                    bundle.org,
                    bundle.machine,
                    replicas[0].replica_id,
                    member.required_generation,
                    former.id,
                )
                .await?
            );
            drop(connection);
            state.apps().reconcile_app(app, bundle.org).await?;
            stacks.reconcile_one(bundle.org, bundle.id).await?;
            assert!(
                apps::app(&state.pool, app)
                    .await?
                    .unwrap()
                    .deleted_at
                    .is_none()
            );
            assert_eq!(apps::app_replicas(&state.pool, app).await?.len(), 1);
            let volume = grund_store::volumes::any_volume(
                &state.pool,
                bundle.org,
                bundle.producer,
                bundle.volume,
            )
            .await?
            .unwrap();
            assert_eq!(volume.purge_after, None);
            let mut connection = state.pool.acquire().await?;
            assert!(
                apps::record_stack_receipt(
                    &mut connection,
                    bundle.org,
                    bundle.machine,
                    replicas[0].replica_id,
                    member.required_generation,
                    deletion.id,
                )
                .await?
            );
            drop(connection);
            state.apps().reconcile_app(app, bundle.org).await?;
            assert!(apps::app_replicas(&state.pool, app).await?.is_empty());
            stacks.reconcile_one(bundle.org, bundle.id).await?;
        }
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        let deleted = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap();
        assert_eq!(deleted.state.0.status, Status::Deleted);
        let deadline = deleted.state.0.purge_after;
        for app in [bundle.producer, bundle.consumer] {
            assert_eq!(
                apps::app(&state.pool, app).await?.unwrap().purge_after,
                deadline
            );
        }
        let volume = grund_store::volumes::any_volume(
            &state.pool,
            bundle.org,
            bundle.producer,
            bundle.volume,
        )
        .await?
        .unwrap();
        assert_eq!(volume.purge_after, deadline);
        Ok(())
    }

    async fn expired_deletion_waits_for_fenced_stop(
        pool: sqlx::PgPool,
        retry: bool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, true).await?;
        let stacks = state.stacks();
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        let mut former = bundle.former.clone();
        former.step = Step::Applying;
        work.stack(
            bundle.id,
            Command::Advance {
                operation: former,
                status: Status::Deploying,
                machine_id: Some(bundle.machine),
                failure: None,
            },
        )
        .await?;
        work.commit().await?;
        let version = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap()
            .stream_version;
        stacks
            .delete(
                Uuid::nil(),
                bundle.org,
                "ordered",
                Some(version),
                "delete-expiring",
            )
            .await?;
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        state
            .apps()
            .reconcile_app(bundle.consumer, bundle.org)
            .await?;
        let consumer = apps::app_replicas(&state.pool, bundle.consumer).await?;
        let consumer_gate = store::member(&state.pool, bundle.org, bundle.consumer)
            .await?
            .unwrap();
        let mut connection = state.pool.acquire().await?;
        assert!(
            apps::record_stack_receipt(
                &mut connection,
                bundle.org,
                bundle.machine,
                consumer[0].replica_id,
                consumer_gate.required_generation,
                consumer_gate.operation_id.unwrap(),
            )
            .await?
        );
        drop(connection);
        state
            .apps()
            .reconcile_app(bundle.consumer, bundle.org)
            .await?;
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        state
            .apps()
            .reconcile_app(bundle.producer, bundle.org)
            .await?;
        let blocked = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap();
        let mut expired = blocked.state.0.operation.unwrap();
        assert_eq!(expired.cursor, 1);
        assert_eq!(expired.step, Step::Stopping);
        expired.deadline = expired.started_at - Duration::seconds(1);
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.stack(
            bundle.id,
            Command::Advance {
                operation: expired.clone(),
                status: Status::Deleting,
                machine_id: Some(bundle.machine),
                failure: None,
            },
        )
        .await?;
        work.commit().await?;
        let old_gate = store::member(&state.pool, bundle.org, bundle.producer)
            .await?
            .unwrap();
        let producer = apps::app_replicas(&state.pool, bundle.producer).await?;
        assert_eq!(producer.len(), 1);
        assert_eq!(producer[0].state, "draining");
        assert!(old_gate.required_generation > 0);
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        let view = stacks.get(bundle.org, "ordered", None).await?;
        assert_eq!(view.failure.as_deref(), Some("operation_deadline"));
        assert_eq!(view.status, "deleting");
        assert_eq!(view.operation, Some(expired.id.to_string()));
        let timed_out = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap();
        let mut expected = expired.clone();
        expected.failure = Some("operation_deadline".into());
        assert_eq!(timed_out.state.0.operation.as_ref(), Some(&expected));
        assert_eq!(timed_out.state.0.machine_id, Some(bundle.machine));
        assert!(timed_out.state.0.purge_after.is_none());
        for app_id in [bundle.consumer, bundle.producer] {
            let app = apps::app(&state.pool, app_id).await?.unwrap();
            assert!(app.deleted_at.is_none());
            assert!(app.purge_after.is_none());
            let gate = store::member(&state.pool, bundle.org, app_id)
                .await?
                .unwrap();
            assert!(!gate.enabled);
            assert!(gate.stopping);
            assert_eq!(gate.operation_id, Some(expired.id));
        }
        let volume = grund_store::volumes::any_volume(
            &state.pool,
            bundle.org,
            bundle.producer,
            bundle.volume,
        )
        .await?
        .unwrap();
        assert!(volume.purge_after.is_none());
        assert_ne!(volume.status, "pending_deletion");
        let before = snapshot(&state).await?;
        for _ in 0..3 {
            stacks.reconcile_one(bundle.org, bundle.id).await?;
        }
        assert_eq!(snapshot(&state).await?, before);
        for app in [bundle.consumer, bundle.producer] {
            assert!(!state.apps().reconcile_app(app, bundle.org).await?);
        }
        let operation_id = if retry {
            let response = stacks
                .delete(
                    Uuid::nil(),
                    bundle.org,
                    "ordered",
                    Some(timed_out.stream_version),
                    "delete-retry",
                )
                .await?;
            assert_eq!(response.status, "deleting");
            assert!(response.failure.is_none());
            let operation_id = Uuid::parse_str(response.operation.as_deref().unwrap())?;
            assert_ne!(operation_id, expired.id);
            let before_replay = snapshot(&state).await?;
            let replay = stacks
                .delete(
                    Uuid::nil(),
                    bundle.org,
                    "ordered",
                    Some(timed_out.stream_version),
                    "delete-retry",
                )
                .await?;
            assert_eq!(
                serde_json::to_value(response)?,
                serde_json::to_value(replay)?
            );
            assert_eq!(snapshot(&state).await?, before_replay);
            for _ in 0..3 {
                stacks.reconcile_one(bundle.org, bundle.id).await?;
            }
            operation_id
        } else {
            expired.id
        };
        let gate = store::member(&state.pool, bundle.org, bundle.producer)
            .await?
            .unwrap();
        assert_eq!(gate.operation_id, Some(operation_id));
        assert!(gate.required_generation > 0);
        if !retry {
            assert_eq!(gate.required_generation, old_gate.required_generation);
        }
        assert!(
            !state
                .apps()
                .reconcile_app(bundle.consumer, bundle.org)
                .await?
        );
        assert!(
            apps::app_replicas(&state.pool, bundle.consumer)
                .await?
                .is_empty()
        );
        let mut connection = state.pool.acquire().await?;
        if retry {
            assert!(gate.required_generation > old_gate.required_generation);
            assert!(
                !apps::record_stack_receipt(
                    &mut connection,
                    bundle.org,
                    bundle.machine,
                    producer[0].replica_id,
                    gate.required_generation,
                    expired.id,
                )
                .await?
            );
        }
        for (machine, generation) in [
            (Uuid::now_v7(), gate.required_generation),
            (bundle.machine, gate.required_generation - 1),
        ] {
            assert!(
                !apps::record_stack_receipt(
                    &mut connection,
                    bundle.org,
                    machine,
                    producer[0].replica_id,
                    generation,
                    operation_id,
                )
                .await?
            );
        }
        drop(connection);
        state
            .apps()
            .reconcile_app(bundle.producer, bundle.org)
            .await?;
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        assert_eq!(
            apps::app_replicas(&state.pool, bundle.producer)
                .await?
                .len(),
            1
        );
        let mut connection = state.pool.acquire().await?;
        assert!(
            apps::record_stack_receipt(
                &mut connection,
                bundle.org,
                bundle.machine,
                producer[0].replica_id,
                gate.required_generation,
                operation_id,
            )
            .await?
        );
        drop(connection);
        state
            .apps()
            .reconcile_app(bundle.producer, bundle.org)
            .await?;
        assert!(
            apps::app_replicas(&state.pool, bundle.producer)
                .await?
                .is_empty()
        );
        let completed_after: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&state.pool)
            .await?;
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        let deleted = store::get(&state.pool, bundle.org, bundle.id)
            .await?
            .unwrap();
        assert_eq!(deleted.state.0.status, Status::Deleted);
        assert!(deleted.state.0.operation.is_none());
        assert!(deleted.state.0.failure.is_none());
        let deadline = deleted.state.0.purge_after.unwrap();
        assert!(deadline >= completed_after + Duration::days(7));
        assert!(deadline <= Utc::now() + Duration::from_std(state.config.volume_delete_window)?);
        for app_id in [bundle.consumer, bundle.producer] {
            let app = apps::app(&state.pool, app_id).await?.unwrap();
            assert!(app.deleted_at.is_some());
            assert_eq!(app.purge_after, Some(deadline));
            assert!(apps::app_replicas(&state.pool, app_id).await?.is_empty());
        }
        let volume = grund_store::volumes::any_volume(
            &state.pool,
            bundle.org,
            bundle.producer,
            bundle.volume,
        )
        .await?
        .unwrap();
        assert_eq!(volume.status, "pending_deletion");
        assert_eq!(volume.purge_after, Some(deadline));
        let view = stacks.get(bundle.org, "ordered", None).await?;
        assert_eq!(view.status, "deleted");
        assert!(view.failure.is_none());
        let completed = snapshot(&state).await?;
        stacks.reconcile_one(bundle.org, bundle.id).await?;
        assert_eq!(snapshot(&state).await?, completed);
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn expired_deletion_reports_once_and_finishes_retention_only_after_current_stop_receipt(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        expired_deletion_waits_for_fenced_stop(pool, false).await
    }

    #[sqlx::test(migrations = false)]
    async fn expired_deletion_accepts_fresh_fenced_retry_and_replays_without_restarting_children(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        expired_deletion_waits_for_fenced_stop(pool, true).await
    }

    struct PurgedStack {
        org: Uuid,
        id: Uuid,
        app_id: Uuid,
        machine: Uuid,
        purged: Uuid,
        data: grund_config::app::spec::VolumeSpec,
    }

    async fn purged_template_stack(state: &State) -> anyhow::Result<PurgedStack> {
        let org = Uuid::now_v7();
        let id = Uuid::now_v7();
        let app_id = Uuid::now_v7();
        let machine = Uuid::now_v7();
        let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&state.pool)
            .await?;
        sqlx::query("INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) VALUES($1,'purged','personal',$2,1)")
            .bind(org).bind(at).execute(&state.pool).await?;
        sqlx::query("INSERT INTO grund_machines(machine_id,pool,name,state,public_key,pool_organisation_id,pool_name,lease_id,minted_by,registered_at,key_registered_at,stream_version) VALUES($1,'management','physical','leased',repeat('a',64),$2,'hosted',$3,'hosted:test',$4,$4,1)")
            .bind(machine).bind(org).bind(Uuid::now_v7()).bind(at).execute(&state.pool).await?;
        sqlx::query("INSERT INTO grund_machine_presence(machine_id,last_seen_at,capabilities) VALUES($1,$2,$3)")
            .bind(machine).bind(at).bind(Json(serde_json::json!({
                "apps": true, "stack_services": true, "resources_allocatable": true,
                "volumes": true, "arch": "x86_64", "memory_mib": 4096, "cpu_millis": 2000
            }))).execute(&state.pool).await?;
        let mut spec = grund_domain::app::templates::find("postgres")
            .unwrap()
            .spec(false)
            .unwrap();
        spec.volumes[0].backup = true;
        let data = spec.volumes[0].clone();
        assert!(data.size_gib.is_none() && data.source.is_none());
        let settings = grund_config::app::spec::AppSettings::default();
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(id);
        work.stack(
            id,
            Command::Create {
                organisation_id: org,
                name: "shop".into(),
            },
        )
        .await?;
        work.app(
            app_id,
            AppCommand::Create {
                actor: Uuid::nil(),
                organisation_id: org,
                name: AppName::parse("shop-db")?,
                settings: settings.clone(),
                at,
            },
        )
        .await?;
        work.app(app_id, AppCommand::AssignStack { stack_id: id, at })
            .await?;
        work.app(
            app_id,
            AppCommand::Release {
                actor: Uuid::nil(),
                spec: spec.clone(),
                image_digest: format!("sha256:{}", "a".repeat(64)),
                platforms: Vec::new(),
                exposed_ports: None,
                secret_versions: Vec::new(),
                source: ReleaseSource::File,
                external_release: None,
                request: None,
                rollback_of: None,
                note: String::new(),
                rollout_id: Uuid::now_v7(),
                at,
            },
        )
        .await?;
        state
            .volumes()
            .resolve_release_in(&mut work, org, app_id, &spec.volumes)
            .await?;
        state
            .volumes()
            .place_release_in(&mut work, org, app_id, machine, &spec.volumes)
            .await?;
        let release = work.load_app(app_id).await?.releases[0].clone();
        let deploy = operation(Kind::Deploy, 1, 0, vec!["db".into()], at);
        work.stack(
            id,
            Command::Revise {
                revision: Revision {
                    number: 1,
                    yaml: "stack:\n  name: shop\n  services:\n    db:\n      template: postgres\n      volumes:\n        data:\n          backup: daily\n".into(),
                    services: BTreeMap::from([(
                        "db".into(),
                        Service {
                            app_id,
                            app_name: "shop-db".into(),
                            release,
                            settings,
                            depends_on: Vec::new(),
                            exclusive: true,
                            template: Some("postgres".into()),
                        },
                    )]),
                    public_service: None,
                    public_port: None,
                    created_at: at,
                    created_by: Uuid::nil(),
                    rollback_of: None,
                },
                operation: deploy.clone(),
            },
        )
        .await?;
        work.stack(
            id,
            Command::Complete {
                operation_id: deploy.id,
                applied_revision: 1,
                status: Status::Ready,
                purge_after: None,
                failure: None,
            },
        )
        .await?;
        work.commit().await?;
        let deadline = at + chrono::Duration::hours(1);
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(id);
        let deletion = operation(Kind::Delete, 1, 1, Vec::new(), at);
        work.stack(
            id,
            Command::Operate {
                operation: deletion.clone(),
                at,
            },
        )
        .await?;
        work.app(
            app_id,
            AppCommand::Delete {
                actor: Uuid::nil(),
                at,
                purge_after: deadline,
            },
        )
        .await?;
        state
            .volumes()
            .delete_app_in(&mut work, org, app_id, deadline)
            .await?;
        work.stack(
            id,
            Command::Complete {
                operation_id: deletion.id,
                applied_revision: 1,
                status: Status::Deleted,
                purge_after: Some(deadline),
                failure: None,
            },
        )
        .await?;
        work.commit().await?;
        let retained = grund_store::volumes::app_volumes(&state.pool, org, app_id).await?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].status, "pending_deletion");
        let purged = retained[0].volume_id;
        state
            .volumes()
            .purge_now(
                Uuid::nil(),
                org,
                app_id,
                purged,
                retained[0].stream_version,
                "verified test data cleanup".into(),
            )
            .await?;
        state
            .volumes()
            .acknowledge(org, machine, app_id, purged)
            .await?;
        let rows = grund_store::volumes::all_app_volumes(&state.pool, org, app_id).await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "deleted");
        Ok(PurgedStack {
            org,
            id,
            app_id,
            machine,
            purged,
            data,
        })
    }

    async fn assert_fresh_volume(
        state: &State,
        purged: &PurgedStack,
    ) -> anyhow::Result<grund_store::volumes::VolumeRow> {
        let rows =
            grund_store::volumes::all_app_volumes(&state.pool, purged.org, purged.app_id).await?;
        assert_eq!(rows.len(), 2, "{rows:?}");
        let old = rows
            .iter()
            .find(|row| row.volume_id == purged.purged)
            .unwrap();
        assert_eq!(old.status, "deleted");
        let fresh = rows
            .iter()
            .find(|row| row.volume_id != purged.purged)
            .unwrap();
        assert_ne!(fresh.status, "deleted");
        assert_eq!(fresh.name, purged.data.name);
        assert_eq!(fresh.path, purged.data.path);
        assert_eq!(fresh.source, purged.data.source);
        assert_eq!(fresh.size_gib, None);
        assert!(fresh.backup);
        assert!(fresh.purge_after.is_none());
        Ok(fresh.clone())
    }

    #[sqlx::test(migrations = false)]
    async fn restoring_a_stack_whose_volume_was_purged_requests_a_fresh_volume_and_advances(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let purged = purged_template_stack(&state).await?;
        let version = store::get(&state.pool, purged.org, purged.id)
            .await?
            .unwrap()
            .stream_version;
        state
            .stacks()
            .restore(
                Uuid::nil(),
                purged.org,
                "shop",
                Some(version),
                "restore-purged",
            )
            .await?;
        let requested = assert_fresh_volume(&state, &purged).await?;
        assert_eq!(requested.status, "requested");
        state.stacks().reconcile_one(purged.org, purged.id).await?;
        let stack = store::get(&state.pool, purged.org, purged.id)
            .await?
            .unwrap()
            .state
            .0;
        let op = stack.operation.unwrap();
        assert_eq!(op.kind, Kind::Restore);
        assert_eq!(op.step, Step::Applying);
        assert_eq!(stack.machine_id, Some(purged.machine));
        assert_eq!(
            assert_fresh_volume(&state, &purged).await?.volume_id,
            requested.volume_id
        );
        state
            .apps()
            .reconcile_app(purged.app_id, purged.org)
            .await?;
        let attached = assert_fresh_volume(&state, &purged).await?;
        assert_eq!(attached.volume_id, requested.volume_id);
        assert_eq!(attached.status, "attached");
        assert_eq!(attached.machine_id, Some(purged.machine));
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn an_in_flight_restore_wedged_on_a_purged_volume_requests_it_and_compensates_without_duplicating(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let purged = purged_template_stack(&state).await?;
        let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&state.pool)
            .await?;
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(purged.id);
        work.stack(
            purged.id,
            Command::Operate {
                operation: operation(Kind::Restore, 1, 1, vec!["db".into()], at),
                at,
            },
        )
        .await?;
        work.app(
            purged.app_id,
            AppCommand::Restore {
                actor: Uuid::nil(),
                at,
            },
        )
        .await?;
        work.commit().await?;
        let stacks = state.stacks();
        stacks.reconcile_one(purged.org, purged.id).await?;
        let current = || async {
            anyhow::Ok(
                store::get(&state.pool, purged.org, purged.id)
                    .await?
                    .unwrap()
                    .state
                    .0,
            )
        };
        let stack = current().await?;
        let mut op = stack.operation.clone().unwrap();
        assert_eq!(op.step, Step::Applying);
        let fresh = assert_fresh_volume(&state, &purged).await?;
        assert_eq!(fresh.status, "requested");

        op.deadline = at - chrono::Duration::seconds(1);
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(purged.id);
        work.stack(
            purged.id,
            Command::Advance {
                operation: op,
                status: stack.status,
                machine_id: stack.machine_id,
                failure: None,
            },
        )
        .await?;
        work.commit().await?;
        stacks.reconcile_one(purged.org, purged.id).await?;
        let stack = current().await?;
        assert_eq!(stack.status, Status::RollingBack);
        let op = stack.operation.unwrap();
        assert!(op.compensating && op.kind == Kind::Rollback);
        assert_eq!(op.order, vec!["db".to_string()]);
        assert_eq!(op.step, Step::Pending);
        stacks.reconcile_one(purged.org, purged.id).await?;
        let op = current().await?.operation.unwrap();
        assert!(op.compensating && op.step == Step::Applying);
        assert_eq!(
            assert_fresh_volume(&state, &purged).await?.volume_id,
            fresh.volume_id
        );
        Ok(())
    }

    struct PinnedShop {
        org: Uuid,
        id: Uuid,
    }

    async fn pinned_shop_rolling_web(
        state: &State,
        web_cpu: u32,
        busy_cpu: u32,
    ) -> anyhow::Result<PinnedShop> {
        let org = Uuid::now_v7();
        let id = Uuid::now_v7();
        let machine = Uuid::now_v7();
        let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&state.pool)
            .await?;
        sqlx::query("INSERT INTO grund_organisations(organisation_id,slug,kind,created_at,stream_version) VALUES($1,'capacity','personal',$2,1)")
            .bind(org).bind(at).execute(&state.pool).await?;
        sqlx::query("INSERT INTO grund_machines(machine_id,pool,home_organisation_id,name,state,public_key,pool_organisation_id,pool_name,minted_by,registered_at,key_registered_at,stream_version) VALUES($1,'organisation',$2,'butik-01','active',repeat('a',64),$2,'butik-01','test',$3,$3,1)")
            .bind(machine).bind(org).bind(at).execute(&state.pool).await?;
        sqlx::query("INSERT INTO grund_machine_presence(machine_id,last_seen_at,capabilities) VALUES($1,$2,$3)")
            .bind(machine).bind(at).bind(Json(serde_json::json!({
                "apps": true, "stack_services": true, "resources_allocatable": true,
                "arch": "x86_64", "memory_mib": 3683, "cpu_millis": 1750
            }))).execute(&state.pool).await?;
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(id);
        work.stack(
            id,
            Command::Create {
                organisation_id: org,
                name: "shop".into(),
            },
        )
        .await?;
        let mut spec = grund_domain::app::templates::find("redis")
            .unwrap()
            .spec(false)
            .context("Redis catalogue entry is available")?;
        spec.volumes.clear();
        spec.secrets.clear();
        spec.memory_mib = 256;
        let mut services = BTreeMap::new();
        for (name, cpu, member) in [
            ("db", 500, true),
            ("restore", 100, true),
            ("web", 500, true),
            ("other", busy_cpu, false),
        ] {
            if !member && busy_cpu == 0 {
                continue;
            }
            let app_id = Uuid::now_v7();
            let settings = grund_config::app::spec::AppSettings::default();
            work.app(
                app_id,
                AppCommand::Create {
                    actor: Uuid::nil(),
                    organisation_id: org,
                    name: AppName::parse(name)?,
                    settings: settings.clone(),
                    at,
                },
            )
            .await?;
            if member {
                work.app(app_id, AppCommand::AssignStack { stack_id: id, at })
                    .await?;
            }
            let mut spec = spec.clone();
            spec.cpu_millis = cpu;
            work.app(
                app_id,
                AppCommand::Release {
                    actor: Uuid::nil(),
                    spec,
                    image_digest: format!("sha256:{}", "a".repeat(64)),
                    platforms: Vec::new(),
                    exposed_ports: None,
                    secret_versions: Vec::new(),
                    source: ReleaseSource::File,
                    external_release: None,
                    request: None,
                    rollback_of: None,
                    note: String::new(),
                    rollout_id: Uuid::now_v7(),
                    at,
                },
            )
            .await?;
            work.app_decide(app_id, |_| {
                Ok((
                    vec![AppEvent::ReplicaPlaced {
                        replica_id: Uuid::now_v7(),
                        slot: 0,
                        release: 1,
                        machine_id: machine,
                        placement: 0,
                        reason: PlaceReason::Scale,
                        placed_at: at,
                    }],
                    (),
                ))
            })
            .await?;
            if member {
                let app = work.load_app(app_id).await?;
                services.insert(
                    name.to_string(),
                    Service {
                        app_id,
                        app_name: name.into(),
                        release: app.releases[0].clone(),
                        settings,
                        depends_on: Vec::new(),
                        exclusive: false,
                        template: None,
                    },
                );
            }
        }
        let yaml = "stack:\n  name: shop\n  machines: [butik-01]\n  services:\n    db:\n      image: redis\n    restore:\n      image: redis\n    web:\n      image: redis\n";
        let first = Revision {
            number: 1,
            yaml: yaml.into(),
            services,
            public_service: None,
            public_port: None,
            created_at: at,
            created_by: Uuid::nil(),
            rollback_of: None,
        };
        let deploy = operation(
            Kind::Deploy,
            1,
            0,
            vec!["db".into(), "restore".into(), "web".into()],
            at,
        );
        work.stack(
            id,
            Command::Revise {
                revision: first.clone(),
                operation: deploy.clone(),
            },
        )
        .await?;
        work.stack(
            id,
            Command::Complete {
                operation_id: deploy.id,
                applied_revision: 1,
                status: Status::Ready,
                purge_after: None,
                failure: None,
            },
        )
        .await?;
        let mut second = first;
        second.number = 2;
        second.yaml = yaml.replace(
            "    web:\n      image: redis\n",
            "    web:\n      image: redis\n      copies: 2\n      restart: rolling\n      release: {max_surge: 1, max_unavailable: 0}\n",
        );
        let web = second.services.get_mut("web").unwrap();
        web.release.number = 2;
        web.release.spec.cpu_millis = web_cpu;
        web.settings.copies = 2;
        web.settings.rollout.max_surge = 1;
        web.settings.rollout.max_unavailable = 0;
        work.stack(
            id,
            Command::Revise {
                revision: second,
                operation: operation(Kind::Deploy, 2, 1, vec!["web".into()], at),
            },
        )
        .await?;
        work.commit().await?;
        Ok(PinnedShop { org, id })
    }

    #[sqlx::test(migrations = false)]
    async fn an_active_rollout_whose_peak_exceeds_its_only_machine_fails_with_insufficient_capacity(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let shop = pinned_shop_rolling_web(&state, 350, 0).await?;
        let stacks = state.stacks();
        let stack = store::get(&state.pool, shop.org, shop.id).await?.unwrap();
        let revision = stack.state.0.revisions[&2].clone();
        let placement = stacks
            .choose_machine(
                &mut *state.pool.acquire().await?,
                shop.org,
                &revision,
                None,
                Some(shop.id),
            )
            .await?;
        assert_eq!(placement.machine, None);
        assert_eq!(
            (placement.cpu, placement.exceeds),
            (1800, Some((3683, 1750)))
        );
        let refusal = placement.insufficient().unwrap();
        assert_eq!(refusal.reason(), "insufficient_capacity");
        assert_eq!(
            refusal.to_string(),
            "stack.services.web: the rollout peak of 1800 mCPU / 1280 MiB exceeds the largest eligible machine's allocatable 1750 mCPU / 3683 MiB"
        );
        stacks.reconcile_one(shop.org, shop.id).await?;
        let stack = store::get(&state.pool, shop.org, shop.id)
            .await?
            .unwrap()
            .state
            .0;
        assert_eq!(stack.status, Status::RollingBack);
        assert_eq!(stack.failure.as_deref(), Some("insufficient_capacity"));
        let op = stack.operation.unwrap();
        assert!(op.compensating && op.kind == Kind::Rollback);
        assert_eq!(op.failure.as_deref(), Some("insufficient_capacity"));
        assert!(op.order.is_empty() && op.releases.is_empty());
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn a_rollout_that_fits_an_empty_machine_waits_without_failing_while_it_is_busy(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let shop = pinned_shop_rolling_web(&state, 300, 200).await?;
        let stacks = state.stacks();
        let stack = store::get(&state.pool, shop.org, shop.id).await?.unwrap();
        let revision = stack.state.0.revisions[&2].clone();
        let placement = stacks
            .choose_machine(
                &mut *state.pool.acquire().await?,
                shop.org,
                &revision,
                None,
                Some(shop.id),
            )
            .await?;
        assert_eq!((placement.machine, placement.cpu), (None, 1700));
        assert!(placement.exceeds.is_none() && placement.insufficient().is_none());
        stacks.reconcile_one(shop.org, shop.id).await?;
        let stack = store::get(&state.pool, shop.org, shop.id)
            .await?
            .unwrap()
            .state
            .0;
        assert_eq!(stack.status, Status::Waiting);
        assert_eq!(stack.failure, None);
        assert_eq!(stack.operation.unwrap().failure, None);
        Ok(())
    }
    #[sqlx::test(migrations = false)]
    async fn template_urls_use_the_release_pinned_credentials(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let state = state(pool).await?;
        let bundle = bundle(&state, false).await?;
        let stacks = state.stacks();
        let sealing = key(&state);
        let mut work = Work::begin(&state.events, Uuid::now_v7(), "test").await?;
        work.allow_stack(bundle.id);
        for family in ["nats", "clickhouse"] {
            let settings = grund_config::stack::TemplateSettings {
                jetstream: family == "nats",
                ..Default::default()
            };
            let template = grund_domain::app::templates::resolve(family, Some(&settings)).unwrap();
            let mut producer =
                work.load_stack(bundle.id).await?.revisions[&1].services["producer"].clone();
            producer.template = Some(family.into());
            producer.release.spec = template.spec(false).unwrap();
            for variable in template.secret_variables {
                producer.release.spec.secrets.push(SecretEnv {
                    env: (*variable).into(),
                    secret: crate::services::apps::secret_name_for(variable),
                });
            }
            producer.release.secret_versions =
                crate::services::apps::generate_template_credentials_in(
                    &mut work,
                    &sealing,
                    Uuid::nil(),
                    bundle.org,
                    bundle.producer,
                    template,
                )
                .await?;
            let variable = if family == "nats" {
                "NATS_AUTH_TOKEN"
            } else {
                "CLICKHOUSE_PASSWORD"
            };
            let password = Stacks::credential(&mut work, &sealing, &producer, variable).await?;
            let user = if family == "nats" {
                password.clone()
            } else {
                Stacks::credential(&mut work, &sealing, &producer, "CLICKHOUSE_USER").await?
            };
            if family == "clickhouse" {
                assert!(user.starts_with("grund_"));
                assert!(user.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
            }
            crate::services::apps::generate_template_credentials_in(
                &mut work,
                &sealing,
                Uuid::nil(),
                bundle.org,
                bundle.producer,
                template,
            )
            .await?;
            let url = stacks
                .output(&mut work, &sealing, "ordered", &producer, "producer", "url")
                .await?;
            let url = reqwest::Url::parse(&url)?;
            assert!(url.username() == user);
            if family == "nats" {
                assert!(url.scheme() == "nats" && url.password().is_none());
            } else {
                assert!(url.scheme() == "http" && url.password() == Some(password.as_str()));
                assert!(url.path() == "/" && url.query() == Some("database=grund"));
            }
            producer.release.secret_versions.clear();
            assert!(
                stacks
                    .output(&mut work, &sealing, "ordered", &producer, "producer", "url")
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
}
