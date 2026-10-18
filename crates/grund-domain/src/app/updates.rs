//! Explicit image discovery for a running release; it never changes non-image settings.

use chrono::{DateTime, Utc};
use grund_config::app::spec::{AppSpec, ImageReference, SpecError};
use serde::{Deserialize, Serialize};

use super::templates::CATALOGUE;

/// A cached observation, not a version ordering guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    NotChecked,
    Current,
    Available,
    Pinned,
    Error,
}

/// Why an image is offered, without claiming template provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    Tag,
    Catalogue,
}

/// One explicitly approvable reference and immutable digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCandidate {
    pub reference: String,
    pub digest: String,
    pub kind: CandidateKind,
    pub label: String,
}

/// The last explicit check of one running release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageUpdate {
    pub base_release: u32,
    pub current_image: String,
    pub current_digest: String,
    pub checked_at: Option<DateTime<Utc>>,
    pub state: UpdateState,
    pub reason: String,
    pub candidates: Vec<UpdateCandidate>,
}

impl ImageUpdate {
    /// An absent or stale cache is not an up-to-date result.
    pub fn not_checked(number: u32, image: String, digest: String) -> Self {
        Self {
            base_release: number,
            current_image: image,
            current_digest: digest,
            checked_at: None,
            state: UpdateState::NotChecked,
            reason: "not_checked".into(),
            candidates: Vec::new(),
        }
    }
}

/// References worth checking, bounded by the fixed catalogue and one watched tag.
pub fn discovery_references(
    image: &str,
) -> Result<Vec<(ImageReference, CandidateKind, String)>, SpecError> {
    let current = ImageReference::parse(image)?;
    let mut references = Vec::new();
    if current.tag.is_some() {
        let mut tag = current.clone();
        tag.digest = None;
        references.push((tag, CandidateKind::Tag, "Same tag".into()));
    }
    for template in CATALOGUE.iter().filter(|template| !template.needs_storage) {
        let reference = ImageReference::parse(template.image)?;
        if reference.registry == current.registry && reference.repository == current.repository {
            references.push((
                reference,
                CandidateKind::Catalogue,
                format!("{} catalogue image suggestion", template.title),
            ));
        }
    }
    Ok(references)
}

/// Copy the approved base, replacing only its image reference.
pub fn updated_spec(base: &AppSpec, candidate: &UpdateCandidate) -> Result<AppSpec, SpecError> {
    let original = ImageReference::parse(&base.image)?;
    let mut reference = ImageReference::parse(&candidate.reference)?;
    if original.digest.is_some() || candidate.kind == CandidateKind::Catalogue {
        reference.digest = Some(candidate.digest.clone());
    }
    let mut spec = base.clone();
    spec.image = reference.to_string();
    spec.validate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_pin_is_removed_only_for_discovery_and_a_digest_only_reference_is_not_watched() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let refs = discovery_references(&format!("example.com/shop:stable@{digest}")).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0.tag.as_deref(), Some("stable"));
        assert_eq!(refs[0].0.digest, None);
        assert!(
            discovery_references(&format!("example.com/shop@{digest}"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn catalogue_matches_repository_not_provenance_and_preserves_custom_settings() {
        let mut base = CATALOGUE[2].spec(false).unwrap();
        base.image = format!("nginx:old@sha256:{}", "a".repeat(64));
        base.memory_mib = 512;
        base.command = vec!["custom".into()];
        base.env.push(grund_config::app::spec::EnvVar {
            name: "MODE".into(),
            value: "mine".into(),
        });
        if let Some(check) = &mut base.check {
            check.interval_ms = 3700;
            check.timeout_ms = 700;
        }
        let base = base.validate().unwrap();
        let refs = discovery_references(&base.image).unwrap();
        let (reference, kind, label) = refs
            .into_iter()
            .find(|(_, kind, _)| *kind == CandidateKind::Catalogue)
            .unwrap();
        let candidate = UpdateCandidate {
            digest: reference.digest.clone().unwrap(),
            reference: reference.to_string(),
            kind,
            label,
        };
        let updated = updated_spec(&base, &candidate).unwrap();
        let mut expected = base;
        expected.image = updated.image.clone();
        assert_eq!(updated, expected);
    }
}
