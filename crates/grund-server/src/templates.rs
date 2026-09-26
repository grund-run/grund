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
    "components/ui.html.jinja",
    "pages/login.html.jinja",
    "pages/signup.html.jinja",
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
    "pages/org-settings.html.jinja",
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
