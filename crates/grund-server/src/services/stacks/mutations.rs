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
    ) -> Result<StackView, Error> {
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
        let (definition, mut revision, mut changed, before) =
            self.prepare(org, yaml, selected, refresh, None).await?;
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
                .and_then(grund_domain::app::templates::find)
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
        for (name, service) in &revision.services {
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
            let template = service
                .template
                .as_deref()
                .and_then(grund_domain::app::templates::find);
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
                    .bind(service.template.as_deref())
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
        self.choose_machine(
            work.sql(),
            org,
            &revision,
            previous.machine_id,
            previous.exists.then_some(id),
        )
        .await?;
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
                if apps::app_by_name_including_deleted(&mut **work.sql(), org, &service.app_name)
                    .await?
                    .is_some()
                {
                    return Err(Error::Conflict);
                }
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
                if let Some(template) = service
                    .template
                    .as_deref()
                    .and_then(grund_domain::app::templates::find)
                {
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
            if existing.deleted {
                self.restore_child(&mut work, org, service.app_id, actor, revision.created_at)
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
                Some(id) => grund_domain::app::templates::find(id).and_then(|t| t.spec(false)),
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
        if output != "url" {
            return Err(invalid("env", "producer does not export that output"));
        }
        let port = ports
            .iter()
            .find(|p| matches!(p.protocol, Protocol::Http | Protocol::H2c));
        if producer.template.is_none()
            || !matches!(producer.template.as_deref(), Some("postgres" | "redis"))
        {
            return port
                .map(|p| format!("http://{host}:{}", p.port))
                .ok_or_else(|| invalid("env", "producer exports no HTTP URL"));
        }
        let (scheme, variable, port, user, database) = match producer.template.as_deref() {
            Some("postgres") => ("postgresql", "POSTGRES_PASSWORD", 5432, "grund", "grund"),
            Some("redis") => ("redis", "REDIS_PASSWORD", 6379, "", "0"),
            _ => return Err(invalid("env", "template URL unavailable")),
        };
        let password = Self::credential(work, sealing, producer, variable).await?;
        let mut url = reqwest::Url::parse(&format!("{scheme}://{host}:{port}/{database}"))
            .context("validated template URL")?;
        url.set_username(user)
            .map_err(|_| invalid("env", "template username cannot be encoded"))?;
        url.set_password(Some(&password))
            .map_err(|_| invalid("env", "template password cannot be encoded"))?;
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
        if state
            .operation
            .as_ref()
            .is_some_and(|operation| kind != Kind::Delete || operation.kind == Kind::Delete)
        {
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
                self.restore_child(&mut work, org, service.app_id, actor, now)
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use grund_domain::{
        app::{AppEvent, PlaceReason},
        volume::VolumeCommand,
    };
    use std::sync::Arc;

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
}
