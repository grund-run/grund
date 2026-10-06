//! Every page and mail template, embedded in the binary (skills D-21), in one
//! minijinja environment. `.html.jinja` templates autoescape; `.txt.jinja`
//! mail bodies do not.

use std::sync::Arc;

use anyhow::Context;
use minijinja::{Environment, UndefinedBehavior, Value};

macro_rules! embedded {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_str!(concat!("../templates/", $name)))),*]
    };
}

/// Every template, by name.
pub const TEMPLATES: &[(&str, &str)] = embedded![
    "base.html.jinja",
    "layout-auth.html.jinja",
    "layout-app.html.jinja",
    "components/icons.html.jinja",
    "components/ui.html.jinja",
    "components/forms.html.jinja",
    "components/lists.html.jinja",
    "components/images.html.jinja",
    "components/shell.html.jinja",
    "components/catalogue.html.jinja",
    "pages/login.html.jinja",
    "pages/signup.html.jinja",
    "pages/signup-owner.html.jinja",
    "pages/message.html.jinja",
    "pages/verify.html.jinja",
    "pages/reset.html.jinja",
    "pages/reset-confirm.html.jinja",
    "pages/error.html.jinja",
    "pages/home.html.jinja",
    "pages/sessions.html.jinja",
    "pages/licenses.html.jinja",
    "pages/style-guide.html.jinja",
    "pages/members.html.jinja",
    "pages/machines.html.jinja",
    "pages/apps.html.jinja",
    "pages/app.html.jinja",
    "pages/deploy.html.jinja",
    "pages/domains.html.jinja",
    "pages/templates.html.jinja",
    "pages/org-settings.html.jinja",
    "pages/tokens.html.jinja",
    "pages/registries.html.jinja",
    "pages/org-new.html.jinja",
    "pages/no-organisation.html.jinja",
    "pages/invite.html.jinja",
    "mail/verify_email.txt.jinja",
    "mail/verify_email.html.jinja",
    "mail/password_reset.txt.jinja",
    "mail/password_reset.html.jinja",
    "mail/signup_existing.txt.jinja",
    "mail/signup_existing.html.jinja",
    "mail/invitation.txt.jinja",
    "mail/invitation.html.jinja",
];

/// The template environment. Cheap to clone.
#[derive(Clone)]
pub struct Templates {
    env: Arc<Environment<'static>>,
}

impl Templates {
    /// Loads every template, then `extra` (from extensions). Fails at
    /// startup, naming the template, if one does not parse.
    pub fn new(extra: &[(&'static str, &'static str)]) -> anyhow::Result<Self> {
        let mut env = Environment::new();
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        for (name, source) in TEMPLATES.iter().chain(extra) {
            env.add_template(name, source)
                .with_context(|| format!("parse template {name}"))?;
        }
        env.add_global(
            "css_href",
            Value::from_safe_string(crate::web::assets::css_href()),
        );
        env.add_global(
            "js_href",
            Value::from_safe_string(crate::web::assets::js_href()),
        );
        Ok(Self { env: Arc::new(env) })
    }

    /// Renders `name` with `context`.
    pub fn render(&self, name: &str, context: Value) -> anyhow::Result<String> {
        self.env
            .get_template(name)
            .with_context(|| format!("template not found: {name}"))?
            .render(context)
            .with_context(|| format!("render template {name}"))
    }
}

/// What a page may not write itself: a class or style attribute, or the
/// raw markup of a component (a control, a form, an icon, a menu). Pages
/// call the macros in `components/` instead, so one change to a component
/// reaches every page. Returns each offence with its line number.
pub fn raw_component_markup(source: &str) -> Vec<String> {
    const REFUSED: &[&str] = &[
        "class=",
        "style=",
        "<button",
        "<input",
        "<select",
        "<textarea",
        "<form",
        "<svg",
        "<details",
        "<img",
        "<script",
        "<style",
    ];
    source
        .lines()
        .enumerate()
        .flat_map(|(index, line)| {
            REFUSED
                .iter()
                .filter(move |needle| line.contains(**needle))
                .map(move |needle| format!("line {}: {needle}", index + 1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_page_writes_component_markup_itself() {
        let offences: Vec<String> = TEMPLATES
            .iter()
            .filter(|(name, _)| name.starts_with("pages/"))
            .flat_map(|(name, source)| {
                raw_component_markup(source)
                    .into_iter()
                    .map(move |offence| format!("{name} {offence}"))
            })
            .collect();
        assert!(
            offences.is_empty(),
            "pages call the macros in components/ (see the style guide): {offences:#?}"
        );
    }

    #[test]
    fn a_hand_written_button_or_class_is_refused() {
        assert_eq!(
            raw_component_markup("<p>ok</p>\n<button class=\"btn\">Go</button>"),
            vec!["line 2: class=", "line 2: <button"]
        );
        assert!(raw_component_markup("{{ ui.button(\"Go\") }} <a href=\"/\">home</a>").is_empty());
    }

    #[test]
    fn every_template_parses_and_every_component_is_registered() {
        Templates::new(&[]).expect("templates parse");
        let registered: Vec<&str> = TEMPLATES.iter().map(|(name, _)| *name).collect();
        let on_disk =
            std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/components"))
                .expect("components directory")
                .map(|entry| {
                    format!(
                        "components/{}",
                        entry.expect("entry").file_name().to_string_lossy()
                    )
                })
                .filter(|name| !registered.contains(&name.as_str()))
                .collect::<Vec<_>>();
        assert!(on_disk.is_empty(), "not embedded: {on_disk:?}");
    }

    #[test]
    fn every_colour_token_has_a_swatch_on_the_style_guide() {
        let css = include_str!("../assets/grund.css");
        let root = &css[css.find(":root {").expect(":root")..];
        let root = &root[..root.find('}').expect("end of :root")];
        let colours: Vec<&str> = root
            .lines()
            .filter_map(|line| line.trim().strip_prefix("--"))
            .filter(|line| line.contains('#'))
            .filter_map(|line| line.split(':').next())
            .collect();
        let shown: Vec<&str> = crate::web::pages::SWATCHES
            .iter()
            .map(|(name, _)| *name)
            .collect();
        let missing: Vec<&&str> = colours
            .iter()
            .filter(|name| !shown.contains(name))
            .collect();
        assert!(
            missing.is_empty(),
            "add these to SWATCHES and .sg-*: {missing:?}"
        );
        for name in shown {
            assert!(
                css.contains(&format!(".sg-{name} {{")),
                "no .sg-{name} rule"
            );
        }
    }
}
