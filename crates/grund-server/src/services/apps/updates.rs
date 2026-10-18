use super::*;
use grund_domain::app::{
    ReleaseRequest,
    updates::{UpdateCandidate, UpdateState, discovery_references, updated_spec},
};

pub use grund_domain::app::updates::ImageUpdate;

#[derive(Debug, Clone)]
pub struct ApplyImageUpdate {
    pub base_release: u32,
    pub base_digest: String,
    pub target_reference: String,
    pub target_digest: String,
    pub request_id: String,
    pub source: ReleaseSource,
}

impl ApplyImageUpdate {
    fn identity(&self) -> Result<ReleaseRequest, AppsError> {
        if self.request_id.is_empty()
            || self.request_id.len() > 128
            || !self
                .request_id
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(AppsError::Spec(SpecError {
                field: "idempotency_key".into(),
                problem: "use 1 to 128 printable non-space ASCII characters".into(),
            }));
        }
        if !grund_config::app::spec::is_digest(&self.base_digest)
            || !grund_config::app::spec::is_digest(&self.target_digest)
        {
            return Err(AppsError::Spec(SpecError {
                field: "digest".into(),
                problem: "use sha256: and 64 lowercase hexadecimal digits".into(),
            }));
        }
        ImageReference::parse(&self.target_reference)?;
        let mut context = ring::digest::Context::new(&ring::digest::SHA256);
        context.update(b"grund-app-image-update-v1\n");
        context.update(&self.base_release.to_be_bytes());
        for value in [
            self.base_digest.as_str(),
            self.target_reference.as_str(),
            self.target_digest.as_str(),
            self.source.as_str(),
        ] {
            context.update(&(value.len() as u64).to_be_bytes());
            context.update(value.as_bytes());
        }
        let digest = context.finish();
        let mut fingerprint = [0; 32];
        fingerprint.copy_from_slice(digest.as_ref());
        Ok(ReleaseRequest {
            id: self.request_id.clone(),
            fingerprint,
        })
    }

    pub(super) fn validate_base(&self, app: &App) -> Result<(), AppsError> {
        if !app.exists || app.deleted {
            return Err(AppsError::NotFound);
        }
        if app.rollout.is_some() {
            return Err(AppsError::UpdateRollout);
        }
        if app.current_release != Some(self.base_release)
            || app
                .release(self.base_release)
                .is_none_or(|release| release.image_digest != self.base_digest)
        {
            return Err(AppsError::UpdateStale);
        }
        Ok(())
    }

    pub(super) fn candidate<'a>(
        &self,
        update: &'a ImageUpdate,
    ) -> Result<&'a UpdateCandidate, AppsError> {
        if update.state != UpdateState::Available {
            return Err(AppsError::UpdateNotOffered);
        }
        if update.base_release != self.base_release || update.current_digest != self.base_digest {
            return Err(AppsError::UpdateStale);
        }
        update
            .candidates
            .iter()
            .find(|candidate| {
                candidate.reference == self.target_reference
                    && candidate.digest == self.target_digest
            })
            .ok_or(AppsError::UpdateNotOffered)
    }
}

pub(super) fn retained_request(
    app: &App,
    request: &ReleaseRequest,
) -> Result<Option<u32>, AppsError> {
    let Some(release) = app.releases.iter().find(|release| {
        release
            .request
            .as_ref()
            .is_some_and(|old| old.id == request.id)
    }) else {
        return Ok(None);
    };
    if release
        .request
        .as_ref()
        .is_some_and(|old| old.fingerprint == request.fingerprint)
    {
        Ok(Some(release.number))
    } else {
        Err(AppsError::UpdateRequestConflict)
    }
}

impl Apps {
    pub async fn get_update(
        &self,
        organisation_id: Uuid,
        name: &str,
    ) -> Result<ImageUpdate, AppsError> {
        let row = self.live(organisation_id, name).await?;
        if let Some(update) =
            apps::update_check(&self.state.pool, organisation_id, row.app_id).await?
        {
            return Ok(update.0);
        }
        let Some(number) = row.current_release else {
            return Ok(ImageUpdate::not_checked(0, String::new(), String::new()));
        };
        let base = apps::release(&self.state.pool, row.app_id, number)
            .await?
            .ok_or(AppsError::ReleaseNotFound)?;
        Ok(ImageUpdate::not_checked(
            number as u32,
            base.spec.0.image,
            base.image_digest,
        ))
    }

    pub async fn check_update(
        &self,
        organisation_id: Uuid,
        name: &str,
    ) -> Result<ImageUpdate, AppsError> {
        let row = self.live(organisation_id, name).await?;
        let number = row.current_release.ok_or(AppsError::UpdateNoBase)?;
        let base = apps::release(&self.state.pool, row.app_id, number)
            .await?
            .ok_or(AppsError::ReleaseNotFound)?;
        let references = discovery_references(&base.spec.0.image)?;
        let mut update = ImageUpdate::not_checked(
            number as u32,
            base.spec.0.image.clone(),
            base.image_digest.clone(),
        );
        update.checked_at = Some(Utc::now());
        let pinned = ImageReference::parse(&base.spec.0.image)?.tag.is_none();
        let discovery = async {
            let mut failed = false;
            for (reference, kind, label) in references {
                let resolved = self
                    .registry(organisation_id, &reference)
                    .await?
                    .resolve(&reference)
                    .await;
                match resolved {
                    Ok(resolved) if resolved.digest != base.image_digest => {
                        let candidate = UpdateCandidate {
                            reference: reference.to_string(),
                            digest: resolved.digest,
                            kind,
                            label,
                        };
                        if !update.candidates.iter().any(|old| {
                            old.reference == candidate.reference && old.digest == candidate.digest
                        }) {
                            update.candidates.push(candidate);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => failed = true,
                }
            }
            Ok::<bool, AppsError>(failed)
        };
        let failed = match tokio::time::timeout(std::time::Duration::from_secs(25), discovery).await
        {
            Ok(Ok(failed)) => failed,
            Ok(Err(error)) => return Err(error),
            Err(_) => true,
        };
        let (state, reason) = if failed {
            (UpdateState::Error, "image_unresolved")
        } else if !update.candidates.is_empty() {
            (UpdateState::Available, "update_available")
        } else if pinned {
            (UpdateState::Pinned, "image_pinned")
        } else {
            (UpdateState::Current, "current")
        };
        update.state = state;
        update.reason = reason.into();
        if !apps::save_update_check(&self.state.pool, organisation_id, row.app_id, &update).await? {
            return Err(AppsError::UpdateStale);
        }
        Ok(update)
    }

    pub async fn apply_update(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        name: &str,
        input: ApplyImageUpdate,
    ) -> Result<ReleaseRow, AppsError> {
        let row = self.live(organisation_id, name).await?;
        let request = input.identity()?;
        {
            let mut work =
                Work::begin(&self.state.events, Uuid::now_v7(), &actor.to_string()).await?;
            lock_app_domain_policy(work.sql(), row.app_id).await?;
            let app = work.load_app(row.app_id).await?;
            if app.organisation_id != organisation_id || app.deleted {
                return Err(AppsError::NotFound);
            }
            if let Some(number) = retained_request(&app, &request)? {
                return apps::release(&mut **work.sql(), row.app_id, number as i32)
                    .await?
                    .ok_or(AppsError::ReleaseNotFound);
            }
            input.validate_base(&app)?;
        }
        let update = apps::update_check(&self.state.pool, organisation_id, row.app_id)
            .await?
            .ok_or(AppsError::UpdateNotOffered)?;
        let candidate = input.candidate(&update.0)?;
        let base = apps::release(&self.state.pool, row.app_id, input.base_release as i32)
            .await?
            .ok_or(AppsError::ReleaseNotFound)?;
        let spec = updated_spec(&base.spec.0, candidate)?;
        let reference = ImageReference::parse(&candidate.reference)?;
        let pinned = reference.pinned(&candidate.digest);
        let inspection = tokio::time::timeout(
            std::time::Duration::from_secs(25),
            self.inspect(organisation_id, &pinned),
        )
        .await
        .map_err(|_| {
            AppsError::ImageUnresolved("the image registry did not answer in time".into())
        })??;
        if inspection.resolved.digest != input.target_digest {
            return Err(AppsError::UpdateStale);
        }
        let secret_versions = self.secret_versions(row.app_id, &spec).await?;
        let command = AppCommand::Release {
            actor,
            spec,
            image_digest: input.target_digest.clone(),
            platforms: inspection.resolved.platforms,
            exposed_ports: Some(inspection.exposed_ports),
            secret_versions,
            source: input.source,
            external_release: None,
            request: Some(request),
            rollback_of: None,
            note: "Image update".into(),
            rollout_id: Uuid::now_v7(),
            at: Utc::now(),
        };
        self.record_release_checked(actor, row.app_id, command, None, None, Some(&input))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_check_cannot_approve_an_earlier_partial_candidate() {
        let input = ApplyImageUpdate {
            base_release: 7,
            base_digest: format!("sha256:{}", "a".repeat(64)),
            target_reference: "example/app:1".into(),
            target_digest: format!("sha256:{}", "b".repeat(64)),
            request_id: "approval".into(),
            source: ReleaseSource::Api,
        };
        let mut update =
            ImageUpdate::not_checked(7, "example/app:1".into(), input.base_digest.clone());
        update.candidates.push(UpdateCandidate {
            reference: input.target_reference.clone(),
            digest: input.target_digest.clone(),
            kind: grund_domain::app::updates::CandidateKind::Tag,
            label: "Same tag".into(),
        });
        update.state = UpdateState::Available;
        assert!(input.candidate(&update).is_ok());
        for state in [
            UpdateState::Error,
            UpdateState::NotChecked,
            UpdateState::Current,
            UpdateState::Pinned,
        ] {
            update.state = state;
            assert!(matches!(
                input.candidate(&update),
                Err(AppsError::UpdateNotOffered)
            ));
        }
    }
}
