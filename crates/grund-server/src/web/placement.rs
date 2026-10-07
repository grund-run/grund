//! An app's Placement setting (`?edit=placement`, grund-docs
//! design/apps.md §5.6, §9.2): where its copies may run, how they spread,
//! which apps they keep near or apart from, and how long an unreachable
//! machine keeps them. Every choice that has a fixed set of answers is a
//! card or a chip, and every value that comes from the organisation
//! (machine names, the label keys and values set on machines, app names)
//! is offered from what exists, so nothing has to be guessed. Saving
//! makes no release (§3.4).

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    Form,
    extract::{Path, State as AxumState},
    http::Uri,
};
use grund_domain::app::{AppSettings, spec::SettingsInput};
use grund_store::organisations::Membership;
use minijinja::{Value, context};

use crate::{
    services::{
        apps::{AppsError, AppsState},
        machines::MachinesState,
    },
    state::State,
    web::{
        apps::{Refusal, Refused, app_view, manages},
        browser::Browser,
        pages::{PageError, PageResult, forged, redirect},
    },
};

/// The Placement form as posted, or as the saved settings fill it: the
/// two choices the settings do not record (which card is chosen) and
/// the settings themselves.
#[derive(Debug, Clone, Default)]
pub struct PlacementForm {
    pub mode: String,
    pub spread: String,
    pub input: SettingsInput,
}

impl PlacementForm {
    /// The form for settings as saved: the cards follow from the values.
    pub fn of(settings: &AppSettings) -> Self {
        Self {
            input: settings.as_input(),
            ..Self::default()
        }
    }

    fn from_pairs(posted: &[(String, String)], saved: &AppSettings) -> (Self, Refusal) {
        let one = |key: &str| {
            posted
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default()
        };
        let all = |key: &str| -> Vec<String> {
            posted
                .iter()
                .filter(|(k, v)| k == key && !v.trim().is_empty())
                .map(|(_, v)| v.trim().to_string())
                .collect()
        };
        let mut refusal = Refusal::default();
        let mode = match one("mode").as_str() {
            mode @ ("machines" | "labels") => mode.to_string(),
            _ => "anywhere".to_string(),
        };
        let spread = match one("spread").as_str() {
            "label" => "label".to_string(),
            _ => "machines".to_string(),
        };
        let mut input = saved.as_input();
        input.machines = if mode == "machines" {
            all("machines")
        } else {
            Vec::new()
        };
        let picked: Vec<(String, String)> = if mode == "labels" {
            all("label")
                .iter()
                .filter_map(|pair| pair.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        } else {
            Vec::new()
        };
        let keys = posted.iter().filter(|(k, _)| k == "labels_key");
        let mut values = posted
            .iter()
            .filter(|(k, _)| k == "labels_value")
            .map(|(_, v)| v.trim().to_string());
        let typed: Vec<(String, String)> = keys
            .map(|(_, k)| (k.trim().to_string(), values.next().unwrap_or_default()))
            .filter(|(k, _)| !k.is_empty())
            .collect();
        input.labels = picked.into_iter().chain(typed).collect();
        input.kind = one("kind");
        input.spread_by = if spread == "label" {
            one("spread_by")
        } else {
            String::new()
        };
        input.near = all("near");
        input.apart = all("apart");
        match one("reschedule_after").as_str() {
            "" => input.reschedule_after_seconds = None,
            text => match text.parse::<u32>() {
                Ok(seconds) if (30..=3600).contains(&seconds) => {
                    input.reschedule_after_seconds = Some(seconds);
                }
                _ => refusal.add("reschedule_after", "Use 30 to 3600 seconds."),
            },
        }
        if mode == "machines" && input.machines.is_empty() {
            refusal.add("machines", "Choose at least one machine.");
        }
        if mode == "labels" && input.labels.is_empty() {
            refusal.add("label", "Choose at least one label.");
        }
        if spread == "label" && input.spread_by.is_empty() {
            refusal.add("spread_by", "Enter a label key, such as zone.");
        }
        (
            Self {
                mode,
                spread,
                input,
            },
            refusal,
        )
    }
}

fn field_of(spec_field: &str) -> &'static str {
    let head = spec_field
        .trim_start_matches("placement.")
        .split(['.', '['])
        .next()
        .unwrap_or_default();
    match head {
        "machines" => "machines",
        "labels" => "labels",
        "kind" => "kind",
        "spread_by" => "spread_by",
        "near" => "near",
        "apart" => "apart",
        "reschedule_after_seconds" => "reschedule_after",
        _ => "placement",
    }
}

/// The fields the Placement form can mark.
pub const FIELDS: &[&str] = &[
    "machines",
    "label",
    "labels",
    "kind",
    "spread_by",
    "near",
    "apart",
    "reschedule_after",
    "placement",
];

fn sorted(items: impl IntoIterator<Item = String>) -> Vec<String> {
    items
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn options(values: &[String]) -> Vec<(String, String)> {
    values.iter().map(|v| (v.clone(), v.clone())).collect()
}

/// What the Placement form shows: the cards chosen, the chips on offer
/// (the organisation's machines, the labels set on them, its other apps)
/// with the chosen ones checked, and what the field suggests.
pub fn view(
    form: &PlacementForm,
    machines: &[(String, BTreeMap<String, String>)],
    apps: &[String],
    app: &str,
    errors: &BTreeMap<&str, &str>,
) -> Value {
    let input = &form.input;
    let set_on_machines: Vec<(String, String)> = machines
        .iter()
        .flat_map(|(_, labels)| labels.iter().map(|(k, v)| (k.clone(), v.clone())))
        .collect();
    let known: BTreeSet<String> = set_on_machines
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let mode = match form.mode.as_str() {
        "" if !input.machines.is_empty() => "machines",
        "" if input
            .labels
            .iter()
            .any(|(k, v)| known.contains(&format!("{k}={v}"))) =>
        {
            "labels"
        }
        "" => "anywhere",
        mode => mode,
    };
    let (picked, typed): (Vec<_>, Vec<_>) = input
        .labels
        .iter()
        .cloned()
        .partition(|(k, v)| mode == "labels" && known.contains(&format!("{k}={v}")));
    let picked: Vec<String> = picked.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let machine_names = sorted(
        machines
            .iter()
            .map(|(name, _)| name.clone())
            .chain(input.machines.iter().cloned()),
    );
    let app_names = sorted(
        apps.iter()
            .filter(|name| name.as_str() != app)
            .cloned()
            .chain(input.near.iter().cloned())
            .chain(input.apart.iter().cloned()),
    );
    let spread = match form.spread.as_str() {
        "" if !input.spread_by.is_empty() => "label",
        "" => "machines",
        spread => spread,
    };
    let kind = input.kind.as_str();
    let mut advanced = Vec::new();
    match kind {
        "own" => advanced.push("Your own machines".to_string()),
        "hosted" => advanced.push("Machines hosted by grund".to_string()),
        _ => {}
    }
    if !typed.is_empty() {
        let pairs: Vec<String> = typed.iter().map(|(k, v)| format!("{k}={v}")).collect();
        advanced.push(format!("labelled {}", pairs.join(", ")));
    }
    let summary = if advanced.is_empty() {
        "None set".to_string()
    } else {
        let mut words = advanced.join(", ");
        if let Some(first) = words.get(..1) {
            words.replace_range(..1, &first.to_uppercase());
        }
        words
    };
    let open = !advanced.is_empty()
        || !errors.get("labels").unwrap_or(&"").is_empty()
        || !errors.get("kind").unwrap_or(&"").is_empty();
    context! {
        mode,
        modes => vec![
            context! { value => "anywhere", title => "Anywhere", tag => "Recommended", icon => "globe", text => "Any machine that fits." },
            context! { value => "machines", title => "Specific machines", icon => "server", text => "Run only on selected machines." },
            context! { value => "labels", title => "By labels", icon => "tag", text => "Run on machines with matching labels." },
        ],
        machines => options(&machine_names),
        chosen_machines => if mode == "machines" { input.machines.clone() } else { Vec::new() },
        labels => options(&sorted(known.iter().cloned().chain(picked.iter().cloned()))),
        chosen_labels => picked,
        typed_labels => typed,
        label_keys => sorted(set_on_machines.iter().map(|(k, _)| k.clone())),
        label_values => sorted(set_on_machines.iter().map(|(_, v)| v.clone())),
        spread,
        spreads => vec![
            context! { value => "machines", title => "Spread across machines", text => "Copies go to different machines first." },
            context! { value => "label", title => "Spread across label", text => "Copies go to different values of a label first, such as zones." },
        ],
        spread_by => input.spread_by,
        apps => options(&app_names),
        near => input.near,
        apart => input.apart,
        kind,
        kinds => [("", "Any"), ("own", "Your own"), ("hosted", "Hosted by grund")],
        reschedule_after => input.reschedule_after_seconds.map(|s| s.to_string()).unwrap_or_default(),
        advanced => summary,
        advanced_open => open,
    }
}

/// The Placement form's context for `app`, from the organisation's
/// machines and apps.
pub async fn context_for(
    state: &State,
    membership: &Membership,
    app: &str,
    form: &PlacementForm,
    errors: &BTreeMap<&str, &str>,
) -> Result<Value, PageError> {
    let machines: Vec<(String, BTreeMap<String, String>)> = state
        .machines()
        .organisation_machines(membership.organisation_id)
        .await?
        .into_iter()
        .map(|row| {
            let labels = row
                .labels
                .0
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            (row.pool_name.unwrap_or(row.name), labels)
        })
        .collect();
    let apps: Vec<String> =
        grund_store::apps::organisation_apps(&state.pool, membership.organisation_id)
            .await
            .map_err(anyhow::Error::from)?
            .into_iter()
            .map(|row| row.name)
            .collect();
    Ok(view(form, &machines, &apps, app, errors))
}

/// `POST /{org}/apps/{app}/settings/placement`: which machines the copies
/// run on and how they spread (grund-docs design/apps.md §5.6). No new
/// release; copies that no longer match move, one at a time. A refusal
/// shows the form again as posted, with the field marked.
pub async fn save(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, name)): Path<(String, String)>,
    Form(posted): Form<Vec<(String, String)>>,
) -> PageResult {
    let csrf = posted
        .iter()
        .find(|(k, _)| k == "csrf")
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();
    if !browser.form_is_genuine(csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    if !manages(&membership) {
        return Ok(redirect(&format!("/{slug}/apps/{name}?error=not-allowed")));
    }
    let apps = state.apps();
    let view = match apps.get(membership.organisation_id, &name).await {
        Ok(view) => view,
        Err(AppsError::NotFound) => return Ok(redirect(&format!("/{slug}/apps?error=gone"))),
        Err(error) => return Err(PageError::from(anyhow::anyhow!(error))),
    };
    let (form, mut refusal) = PlacementForm::from_pairs(&posted, &view.row.settings.0);
    if refusal.fields.is_empty() {
        match apps
            .configure(
                session.account_id,
                membership.organisation_id,
                &name,
                form.input.clone(),
            )
            .await
        {
            Ok(_) => {
                return Ok(redirect(&format!(
                    "/{slug}/apps/{name}/settings?done=saved"
                )));
            }
            Err(AppsError::NotFound) => {
                return Ok(redirect(&format!("/{slug}/apps?error=gone")));
            }
            Err(AppsError::Spec(spec)) => {
                let mut problem = spec.problem.clone();
                if let Some(first) = problem.get(..1) {
                    problem.replace_range(..1, &first.to_uppercase());
                }
                refusal.add(field_of(&spec.field), format!("{problem}."));
            }
            Err(error) => refusal = crate::web::apps::refusal(&error),
        }
    }
    refusal.banner = "Nothing was saved. Check the field marked below.".into();
    app_view(
        &state,
        &browser,
        &session,
        &membership,
        &name,
        "settings",
        (String::new(), String::new()),
        Refused {
            part: "placement",
            refusal,
            placement: Some(form),
            ..Refused::default()
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved() -> AppSettings {
        AppSettings::default()
    }

    fn post(pairs: &[(&str, &str)]) -> (PlacementForm, Refusal) {
        let posted: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        PlacementForm::from_pairs(&posted, &saved())
    }

    #[test]
    fn only_the_chosen_cards_fields_are_read() {
        let (form, refusal) = post(&[
            ("mode", "anywhere"),
            ("machines", "web-1"),
            ("label", "zone=a"),
            ("spread", "machines"),
            ("spread_by", "zone"),
        ]);
        assert!(refusal.fields.is_empty());
        assert!(form.input.machines.is_empty());
        assert!(form.input.labels.is_empty());
        assert!(form.input.spread_by.is_empty());
    }

    #[test]
    fn picked_labels_and_typed_labels_are_both_required() {
        let (form, refusal) = post(&[
            ("mode", "labels"),
            ("label", "zone=a"),
            ("labels_key", "disk"),
            ("labels_value", "ssd"),
            ("labels_key", ""),
            ("labels_value", ""),
            ("spread", "label"),
            ("spread_by", "zone"),
            ("near", "db"),
            ("reschedule_after", "300"),
        ]);
        assert!(refusal.fields.is_empty());
        assert_eq!(
            form.input.labels,
            vec![("zone".into(), "a".into()), ("disk".into(), "ssd".into())]
        );
        assert_eq!(form.input.spread_by, "zone");
        assert_eq!(form.input.near, vec!["db".to_string()]);
        assert_eq!(form.input.reschedule_after_seconds, Some(300));
    }

    #[test]
    fn a_chosen_card_without_its_value_is_refused_at_its_field() {
        let (_, refusal) = post(&[
            ("mode", "machines"),
            ("spread", "label"),
            ("reschedule_after", "10"),
        ]);
        let fields: Vec<&str> = refusal.fields.keys().copied().collect();
        assert_eq!(fields, vec!["machines", "reschedule_after", "spread_by"]);
    }

    #[test]
    fn an_empty_wait_is_the_default() {
        let (form, refusal) = post(&[("reschedule_after", "")]);
        assert!(refusal.fields.is_empty());
        assert_eq!(form.input.reschedule_after_seconds, None);
    }

    #[test]
    fn settings_errors_land_on_their_field() {
        assert_eq!(field_of("placement.spread_by"), "spread_by");
        assert_eq!(field_of("placement.near[2]"), "near");
        assert_eq!(field_of("machines[0]"), "machines");
        assert_eq!(field_of("reschedule_after_seconds"), "reschedule_after");
    }

    fn machines() -> Vec<(String, BTreeMap<String, String>)> {
        vec![
            (
                "web-1".into(),
                BTreeMap::from([("zone".into(), "a".into())]),
            ),
            (
                "web-2".into(),
                BTreeMap::from([("zone".into(), "b".into())]),
            ),
        ]
    }

    fn shown(settings: AppSettings) -> Value {
        view(
            &PlacementForm::of(&settings),
            &machines(),
            &["shop".into(), "db".into()],
            "shop",
            &BTreeMap::new(),
        )
    }

    #[test]
    fn the_saved_settings_choose_the_card_and_offer_what_exists() {
        let page = shown(AppSettings::default());
        assert_eq!(page.get_attr("mode").unwrap().as_str(), Some("anywhere"));
        assert_eq!(page.get_attr("spread").unwrap().as_str(), Some("machines"));
        assert_eq!(page.get_attr("apps").unwrap().len(), Some(1));
        assert_eq!(page.get_attr("labels").unwrap().len(), Some(2));
        let settings = AppSettings {
            machines: vec!["web-2".into()],
            ..AppSettings::default()
        };
        assert_eq!(
            shown(settings).get_attr("mode").unwrap().as_str(),
            Some("machines")
        );
    }

    #[test]
    fn a_label_no_machine_carries_is_kept_under_advanced_filters() {
        let mut settings = AppSettings::default();
        settings.placement.labels =
            BTreeMap::from([("zone".into(), "a".into()), ("disk".into(), "nvme".into())]);
        let page = shown(settings);
        assert_eq!(page.get_attr("mode").unwrap().as_str(), Some("labels"));
        assert_eq!(page.get_attr("chosen_labels").unwrap().len(), Some(1));
        assert_eq!(page.get_attr("typed_labels").unwrap().len(), Some(1));
        assert!(page.get_attr("advanced_open").unwrap().is_true());
    }
}
