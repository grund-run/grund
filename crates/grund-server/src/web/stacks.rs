//! Organisation-scoped stack pages and protected forms calling the shared stack service.

use std::{borrow::Cow, collections::BTreeMap};

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{StatusCode, Uri},
    response::IntoResponse,
};
use grund_store::organisations::Membership;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        sessions::Session,
        stacks::{
            Error, InputSecret, Preview, ServiceView, StackView, StacksState, VolumeIntent,
            VolumeView,
        },
    },
    state::State,
    web::{
        apps::manages,
        browser::Browser,
        orgs::Member,
        pages::{PageError, PageResult, forged, not_found_page, redirect, signed_in_typed},
    },
};

type Errors = BTreeMap<&'static str, String>;

pub struct ListPage<'a> {
    pub slug: &'a str,
    pub stacks: &'a [StackView],
    pub next: Option<Uuid>,
}

pub struct DetailPage<'a> {
    pub slug: &'a str,
    pub stack: &'a StackView,
    pub manages: bool,
    pub csrf: &'a str,
    pub action: Action,
    pub form: &'a ActionForm,
    pub errors: &'a Errors,
}

pub struct DeployPage<'a> {
    pub slug: &'a str,
    pub manages: bool,
    pub csrf: &'a str,
    pub form: &'a DeployForm,
    pub preview: Option<&'a Preview>,
    pub errors: &'a Errors,
    pub secret_names: Vec<(String, String)>,
}

#[derive(Default, Deserialize)]
pub struct ListQuery {
    pub after: Option<Uuid>,
}

#[derive(Default, Deserialize)]
pub struct DetailQuery {
    #[serde(default)]
    pub action: Action,
    #[serde(default)]
    pub service: String,
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    None,
    Restart,
    Rollback,
    Delete,
    Restore,
}

impl Action {
    pub fn path(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Restart => "restart",
            Self::Rollback => "rollback",
            Self::Delete => "delete",
            Self::Restore => "restore",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Restart => "Restart",
            Self::Rollback => "Roll back",
            Self::Delete => "Delete stack",
            Self::Restore => "Restore stack",
        }
    }
}

#[derive(Default, Deserialize)]
pub struct ActionForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    pub expected_version: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub confirmation: String,
}

#[derive(Default)]
pub struct DeployForm {
    csrf: String,
    pub file: String,
    pub service: String,
    pub refresh_template: String,
    pub confirmed_removals: String,
    pub expected_version: String,
    pub key: String,
    pub secrets: Vec<(String, String)>,
}

impl DeployForm {
    fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        let mut form = Self::default();
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for (name, value) in pairs {
            match name.as_str() {
                "csrf" => form.csrf = value,
                "file" => form.file = value,
                "service" => form.service = value,
                "refresh_template" => form.refresh_template = value,
                "confirmed_removals" => form.confirmed_removals = value,
                "expected_version" => form.expected_version = value,
                "key" => form.key = value,
                "secrets_key" => keys.push(value),
                "secrets_value" => values.push(value),
                _ => {}
            }
        }
        for index in 0..keys.len().max(values.len()) {
            let key = keys.get(index).cloned().unwrap_or_default();
            let value = values
                .get_mut(index)
                .map(std::mem::take)
                .unwrap_or_default();
            if !key.is_empty() || !value.is_empty() {
                form.secrets.push((key, value));
            }
        }
        form
    }

    fn take_secrets(&mut self) -> Result<Vec<InputSecret>, &'static str> {
        if self.secrets.len() > 100 {
            return Err("At most 100 launch secrets are accepted. Enter their values again.");
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut inputs = Vec::with_capacity(self.secrets.len());
        for (binding, value) in &mut self.secrets {
            let Some((service, name)) = binding.split_once('.') else {
                return Err("Use service.NAME for each secret. Enter its value again.");
            };
            if service.is_empty()
                || name.is_empty()
                || !seen.insert(binding.clone())
                || value.is_empty()
            {
                return Err(
                    "Each secret needs a unique service.NAME and a value. Enter its value again.",
                );
            }
            if value.len() > 65_536 {
                return Err("A secret may contain at most 65536 bytes. Enter its value again.");
            }
            inputs.push(InputSecret {
                service: service.to_owned(),
                name: name.to_owned(),
                value: std::mem::take(value),
            });
        }
        Ok(inputs)
    }
}

fn selected(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn expected(value: &str, create: bool) -> Result<Option<i64>, &'static str> {
    if value.is_empty() && create {
        return Ok(None);
    }
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .map(Some)
        .ok_or("The stack version is missing or invalid. Reload the page before trying again.")
}

fn key_error(key: &str) -> Option<&'static str> {
    Uuid::try_parse(key)
        .is_err()
        .then_some("The operation key is invalid. Reload the page before trying again.")
}

fn field_error(field: &'static str, message: impl Into<String>) -> Errors {
    BTreeMap::from([(field, message.into())])
}

fn service_error(error: Error) -> Result<Errors, PageError> {
    match error {
        Error::Internal(error) => Err(PageError::from(error)),
        Error::Invalid(error) => Ok(field_error(
            if error.field == "confirmed_removals" {
                "confirmed_removals"
            } else {
                "file"
            },
            format!("{}: {}", error.field, error.problem),
        )),
        Error::Conflict => Ok(field_error(
            "expected_version",
            "The stack changed. Reload it and preview the change again.",
        )),
        Error::IdempotencyConflict => Ok(field_error(
            "key",
            "This operation key was already used for a different request. Reload the page before trying again.",
        )),
        Error::Busy => Ok(field_error(
            "operation",
            "A stack operation is still running.",
        )),
        Error::Owned => Ok(field_error(
            "operation",
            "This resource is managed by its stack.",
        )),
        Error::NotFound => Ok(field_error("operation", "The stack was not found.")),
    }
}

pub fn status(status: &str) -> (&str, &'static str) {
    match status {
        "ready" => ("Ready", "ok"),
        "waiting" => ("Waiting", "orange"),
        "deploying" => ("Deploying", "blue"),
        "rolling_back" => ("Rolling back", "blue"),
        "deleting" => ("Deleting", "blue"),
        "deleted" => ("Deleted", "muted"),
        "halted" => ("Halted", "danger"),
        "degraded" => ("Degraded", "orange"),
        other => (other, "muted"),
    }
}

pub fn service_source(service: &ServiceView) -> Cow<'_, str> {
    match &service.template {
        Some(template) => format!("Template {template} · {}", service.image).into(),
        None => Cow::Borrowed(&service.image),
    }
}

pub fn service_progress(service: &ServiceView) -> String {
    use std::fmt::Write;

    let mut detail = String::with_capacity(96 + service.observed_running_releases.len() * 12);
    let _ = write!(
        detail,
        "{} / {} target ready · Desired release ",
        service.ready, service.copies,
    );
    if service.release == 0 {
        detail.push_str("pending");
    } else {
        let _ = write!(detail, "{}", service.release);
    }
    if service.observed_running_releases.is_empty() {
        detail.push_str(" · No fresh running observations");
    } else {
        detail.push_str(" · Observed running ");
        for (index, release) in service.observed_running_releases.iter().enumerate() {
            if index != 0 {
                detail.push_str(", ");
            }
            let _ = write!(detail, "{release}");
        }
    }
    detail
}

pub fn storage_policy(storage: &VolumeIntent) -> Cow<'static, str> {
    match storage.size_gib {
        None => "Own machine · No enforced quota · No automatic backup".into(),
        Some(size) => format!(
            "Hosted · {size} GiB fixed capacity · No resize · {}",
            if storage.backup_requested {
                "Daily snapshots requested; check Storage for a verified recovery point"
            } else {
                "No automatic backup requested"
            },
        )
        .into(),
    }
}

pub fn volume_detail(volume: &VolumeView) -> Cow<'static, str> {
    let mut detail = storage_policy(&volume.storage);
    if let Some(deadline) = volume.purge_after {
        use std::fmt::Write;
        let _ = write!(
            detail.to_mut(),
            " · Scheduled purge {}",
            deadline.format("%Y-%m-%d %H:%M UTC"),
        );
    }
    detail
}

pub async fn list(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<ListQuery>,
) -> PageResult {
    let mut stacks = state
        .stacks()
        .list(member.membership.organisation_id, 50, query.after, None)
        .await?;
    let next = (stacks.len() > 50).then(|| stacks[49].id);
    stacks.truncate(50);
    signed_in_typed(
        &state,
        &member.browser,
        &member.session,
        Some(&member.membership),
        StatusCode::OK,
        "Stacks",
        "stacks",
        None,
        None,
        None,
        |_, _| {
            crate::templates::compiled::pages::stacks::render(&ListPage {
                slug: &member.membership.slug,
                stacks: &stacks,
                next,
            })
        },
    )
    .await
}

pub async fn detail(
    AxumState(state): AxumState<State>,
    member: Member,
    Path((_, name)): Path<(String, String)>,
    Query(query): Query<DetailQuery>,
) -> PageResult {
    let stack = match state
        .stacks()
        .get(member.membership.organisation_id, &name, None)
        .await
    {
        Ok(stack) => stack,
        Err(Error::NotFound) => return not_found_page(&state, &member.browser),
        Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
    };
    if !query.service.is_empty()
        && !stack
            .services
            .iter()
            .any(|service| service.name == query.service)
    {
        return not_found_page(&state, &member.browser);
    }
    let form = ActionForm {
        expected_version: stack.version.to_string(),
        key: Uuid::new_v4().to_string(),
        service: query.service,
        ..Default::default()
    };
    render_detail(
        &state,
        &member.browser,
        &member.session,
        &member.membership,
        &stack,
        query.action,
        &form,
        &Errors::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn render_detail(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    stack: &StackView,
    action: Action,
    form: &ActionForm,
    errors: &Errors,
) -> PageResult {
    signed_in_typed(
        state,
        browser,
        session,
        Some(membership),
        if errors.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        },
        &stack.name,
        "stacks",
        None,
        stack.operation.as_ref().map(|_| 3),
        None,
        |_, csrf| {
            crate::templates::compiled::pages::stack_detail::render(&DetailPage {
                slug: &membership.slug,
                stack,
                manages: manages(membership),
                csrf,
                action,
                form,
                errors,
            })
        },
    )
    .await
}

#[derive(Default, Deserialize)]
pub struct DeployQuery {
    pub stack: Option<String>,
    #[serde(default)]
    pub service: String,
}

pub async fn deploy_page(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<DeployQuery>,
) -> PageResult {
    let mut form = DeployForm {
        key: Uuid::new_v4().to_string(),
        service: query.service,
        ..Default::default()
    };
    if let Some(name) = query.stack {
        let stack = match state
            .stacks()
            .get(member.membership.organisation_id, &name, None)
            .await
        {
            Ok(stack) => stack,
            Err(Error::NotFound) => return not_found_page(&state, &member.browser),
            Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
        };
        if !form.service.is_empty()
            && !stack
                .services
                .iter()
                .any(|service| service.name == form.service)
        {
            return not_found_page(&state, &member.browser);
        }
        form.file = stack.yaml;
        form.expected_version = stack.version.to_string();
    }
    render_deploy(
        &state,
        &member.browser,
        &member.session,
        &member.membership,
        &form,
        None,
        &Errors::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn render_deploy(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    form: &DeployForm,
    preview: Option<&Preview>,
    errors: &Errors,
) -> PageResult {
    signed_in_typed(
        state,
        browser,
        session,
        Some(membership),
        if errors.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        },
        "Deploy stack",
        "stack-deploy",
        None,
        None,
        None,
        |_, csrf| {
            crate::templates::compiled::pages::stack_deploy::render(&DeployPage {
                slug: &membership.slug,
                manages: manages(membership),
                csrf,
                form,
                preview,
                errors,
                secret_names: form
                    .secrets
                    .iter()
                    .map(|(name, _)| (name.clone(), String::new()))
                    .collect(),
            })
        },
    )
    .await
}

pub async fn preview(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> PageResult {
    let mut form = DeployForm::from_pairs(pairs);
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    match state
        .stacks()
        .preview(
            membership.organisation_id,
            &form.file,
            selected(&form.service),
            selected(&form.refresh_template),
            None,
        )
        .await
    {
        Ok(preview) => {
            form.expected_version = if preview.expected_version == 0 {
                String::new()
            } else {
                preview.expected_version.to_string()
            };
            render_deploy(
                &state,
                &browser,
                &session,
                &membership,
                &form,
                Some(&preview),
                &Errors::new(),
            )
            .await
        }
        Err(Error::NotFound) => not_found_page(&state, &browser),
        Err(error) => {
            render_deploy(
                &state,
                &browser,
                &session,
                &membership,
                &form,
                None,
                &service_error(error)?,
            )
            .await
        }
    }
}

pub async fn deploy(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> PageResult {
    let mut form = DeployForm::from_pairs(pairs);
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let result: Result<(), Errors> = match expected(&form.expected_version, true) {
        Err(message) => Err(field_error("expected_version", message)),
        Ok(expected) => match key_error(&form.key) {
            Some(message) => Err(field_error("key", message)),
            None => match form.take_secrets() {
                Err(message) => Err(field_error("secrets", message)),
                Ok(secrets) => match state
                    .stacks()
                    .deploy(
                        session.account_id,
                        membership.organisation_id,
                        &form.file,
                        selected(&form.service),
                        selected(&form.refresh_template),
                        expected,
                        &form.key,
                        secrets,
                        form.confirmed_removals
                            .split(',')
                            .map(str::trim)
                            .filter(|name| !name.is_empty())
                            .map(str::to_owned)
                            .collect(),
                    )
                    .await
                {
                    Ok(stack) => return Ok(redirect(&format!("/{slug}/stacks/{}", stack.name))),
                    Err(Error::NotFound) => return not_found_page(&state, &browser),
                    Err(error) => Err(service_error(error)?),
                },
            },
        },
    };
    let errors = result.unwrap_err();
    render_deploy(
        &state,
        &browser,
        &session,
        &membership,
        &form,
        None,
        &errors,
    )
    .await
}

pub async fn mutate(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name, action)): Path<(String, String, String)>,
    Form(form): Form<ActionForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let action = match action.as_str() {
        "restart" => Action::Restart,
        "rollback" => Action::Rollback,
        "delete" => Action::Delete,
        "restore" => Action::Restore,
        _ => return not_found_page(&state, &browser),
    };
    let stack = match state
        .stacks()
        .get(membership.organisation_id, &name, None)
        .await
    {
        Ok(stack) => stack,
        Err(Error::NotFound) => return not_found_page(&state, &browser),
        Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
    };
    if !form.service.is_empty()
        && !stack
            .services
            .iter()
            .any(|service| service.name == form.service)
    {
        return not_found_page(&state, &browser);
    }
    let mut errors = Errors::new();
    let version = match expected(&form.expected_version, false) {
        Ok(version) => version,
        Err(message) => {
            errors.insert("expected_version", message.into());
            None
        }
    };
    if let Some(message) = key_error(&form.key) {
        errors.insert("key", message.into());
    }
    let revision = form
        .revision
        .parse::<u32>()
        .ok()
        .filter(|revision| *revision > 0);
    if action == Action::Rollback && revision.is_none() {
        errors.insert(
            "revision",
            "Enter a revision number greater than zero.".into(),
        );
    }
    if action == Action::Delete && form.confirmation != name {
        errors.insert(
            "confirmation",
            "Enter the stack name to confirm deletion.".into(),
        );
    }
    if errors.is_empty() {
        let stacks = state.stacks();
        let result = match action {
            Action::Restart => {
                stacks
                    .restart(
                        session.account_id,
                        membership.organisation_id,
                        &name,
                        selected(&form.service),
                        version,
                        &form.key,
                    )
                    .await
            }
            Action::Rollback => {
                stacks
                    .rollback(
                        session.account_id,
                        membership.organisation_id,
                        &name,
                        revision.unwrap(),
                        version,
                        &form.key,
                    )
                    .await
            }
            Action::Delete => {
                stacks
                    .delete(
                        session.account_id,
                        membership.organisation_id,
                        &name,
                        version,
                        &form.key,
                    )
                    .await
            }
            Action::Restore => {
                stacks
                    .restore(
                        session.account_id,
                        membership.organisation_id,
                        &name,
                        version,
                        &form.key,
                    )
                    .await
            }
            Action::None => unreachable!(),
        };
        match result {
            Ok(_) => return Ok(redirect(&format!("/{slug}/stacks/{name}"))),
            Err(Error::NotFound) => return not_found_page(&state, &browser),
            Err(error) => errors = service_error(error)?,
        }
    }
    render_detail(
        &state,
        &browser,
        &session,
        &membership,
        &stack,
        action,
        &form,
        &errors,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_existing_stack_never_accepts_a_missing_or_nonpositive_version() {
        for value in ["", "0", "-1", "9223372036854775808"] {
            assert!(expected(value, false).is_err());
        }
        assert_eq!(expected("", true), Ok(None));
        assert_eq!(expected("7", false), Ok(Some(7)));
    }

    #[test]
    fn launch_secrets_remain_separate_from_the_file_and_are_consumed_once() {
        let mut form = DeployForm::from_pairs(vec![
            ("file".into(), "name: shop".into()),
            ("secrets_key".into(), "web.PASSWORD".into()),
            ("secrets_value".into(), "not-in-the-file".into()),
        ]);
        let secrets = form.take_secrets().unwrap();
        assert_eq!(secrets[0].service, "web");
        assert_eq!(secrets[0].value, "not-in-the-file");
        assert!(!form.file.contains(&secrets[0].value));
        assert!(form.secrets[0].1.is_empty());
        assert!(form.take_secrets().is_err());
    }

    #[test]
    fn duplicate_or_unscoped_secret_bindings_are_refused() {
        for bindings in [
            vec!["PASSWORD"],
            vec!["web.PASSWORD", "web.PASSWORD"],
            vec![".PASSWORD"],
        ] {
            let mut form = DeployForm {
                secrets: bindings
                    .into_iter()
                    .map(|key| (key.into(), "secret".into()))
                    .collect(),
                ..Default::default()
            };
            assert!(form.take_secrets().is_err());
        }
    }

    #[test]
    fn a_refused_form_keeps_the_file_but_never_renders_launch_secret_values() {
        let form = DeployForm {
            file: "name: shop\nservices: {}".into(),
            secrets: vec![("web.PASSWORD".into(), "never-echo-this-value".into())],
            ..Default::default()
        };
        let errors = field_error("file", "Check the service definition.");
        let html = crate::templates::compiled::pages::stack_deploy::render(&DeployPage {
            slug: "shop",
            manages: true,
            csrf: "csrf",
            form: &form,
            preview: None,
            errors: &errors,
            secret_names: vec![("web.PASSWORD".into(), String::new())],
        });
        assert!(html.contains("name: shop"));
        assert!(html.contains("aria-invalid=\"true\""));
        assert!(!html.contains("never-echo-this-value"));
    }
}
