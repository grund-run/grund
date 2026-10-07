//! The CLI's errors: a stable code, an exit status per code, and the JSON
//! shape `grund.cli.v1.ErrorOutput` printed on stderr with `--output json`.

use serde_json::{Value, json};

/// What went wrong, as scripts and agents act on it. Each has one exit
/// status; `grund describe` lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Usage,
    ConfirmationRequired,
    OrganisationRequired,
    NotSignedIn,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    Invalid,
    Unavailable,
    RolloutFailed,
    Failed,
}

impl Code {
    /// Every code, in the order `grund describe` lists them.
    pub const ALL: &[Code] = &[
        Code::Usage,
        Code::ConfirmationRequired,
        Code::OrganisationRequired,
        Code::NotSignedIn,
        Code::Unauthenticated,
        Code::PermissionDenied,
        Code::NotFound,
        Code::Conflict,
        Code::Invalid,
        Code::Unavailable,
        Code::RolloutFailed,
        Code::Failed,
    ];

    /// The stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Usage => "usage",
            Code::ConfirmationRequired => "confirmation_required",
            Code::OrganisationRequired => "organisation_required",
            Code::NotSignedIn => "not_signed_in",
            Code::Unauthenticated => "unauthenticated",
            Code::PermissionDenied => "permission_denied",
            Code::NotFound => "not_found",
            Code::Conflict => "conflict",
            Code::Invalid => "invalid",
            Code::Unavailable => "unavailable",
            Code::RolloutFailed => "rollout_failed",
            Code::Failed => "failed",
        }
    }

    /// The process's exit status.
    pub fn exit_status(self) -> i32 {
        match self {
            Code::Failed => 1,
            Code::Usage | Code::ConfirmationRequired | Code::OrganisationRequired => 2,
            Code::NotSignedIn | Code::Unauthenticated => 3,
            Code::PermissionDenied => 4,
            Code::NotFound => 5,
            Code::Conflict => 6,
            Code::Invalid => 7,
            Code::Unavailable => 8,
            Code::RolloutFailed => 9,
        }
    }

    /// What it means, for `grund describe`.
    pub fn meaning(self) -> &'static str {
        match self {
            Code::Usage => {
                "The command line is wrong: an unknown flag, a missing argument or a bad value."
            }
            Code::ConfirmationRequired => {
                "A destructive command needs --yes when nobody can be asked."
            }
            Code::OrganisationRequired => {
                "More than one organisation could be meant: pass --org or run grund orgs use."
            }
            Code::NotSignedIn => {
                "No credential: run grund login, or set GRUND_TOKEN and GRUND_INSTANCE."
            }
            Code::Unauthenticated => {
                "The instance refused the credential: unknown, revoked or expired."
            }
            Code::PermissionDenied => {
                "The credential may not do this: the role, or the token's scope."
            }
            Code::NotFound => {
                "No such organisation, app, release, machine, domain, member or token, or not one the credential reaches."
            }
            Code::Conflict => {
                "The current state refuses it: a name taken, a limit reached, a rollout halted."
            }
            Code::Invalid => "The instance refused the input; field names it when known.",
            Code::Unavailable => {
                "The instance could not be reached or could not answer now; retrying may work."
            }
            Code::RolloutFailed => "With --wait: the release did not go live.",
            Code::Failed => "Anything else.",
        }
    }
}

/// What a failed command says.
#[derive(Debug, Clone)]
pub struct Details {
    pub code: Code,
    pub message: String,
    pub hint: String,
    pub field: String,
    pub reason: String,
    pub rpc: String,
}

/// A failed command: its [`Details`], boxed so results stay small.
#[derive(Debug, Clone)]
pub struct CliError(Box<Details>);

impl std::ops::Deref for CliError {
    type Target = Details;

    fn deref(&self) -> &Details {
        &self.0
    }
}

impl std::ops::DerefMut for CliError {
    fn deref_mut(&mut self) -> &mut Details {
        &mut self.0
    }
}

impl CliError {
    /// An error with a code and a message.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        CliError(Box::new(Details {
            code,
            message: message.into(),
            hint: String::new(),
            field: String::new(),
            reason: String::new(),
            rpc: String::new(),
        }))
    }

    /// The same, with what to do about it.
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = hint.into();
        self
    }

    /// The same, naming the flag, argument or file path it is about.
    pub fn field(mut self, field: impl Into<String>) -> Self {
        self.field = field.into();
        self
    }

    /// A usage error.
    pub fn usage(message: impl Into<String>) -> Self {
        CliError::new(Code::Usage, message)
    }

    /// `grund.cli.v1.ErrorOutput` as JSON; empty fields are left out.
    pub fn json(&self) -> Value {
        let mut error = serde_json::Map::new();
        error.insert("code".into(), json!(self.code.as_str()));
        error.insert("message".into(), json!(self.message));
        for (key, value) in [
            ("hint", &self.hint),
            ("field", &self.field),
            ("reason", &self.reason),
            ("rpc", &self.rpc),
        ] {
            if !value.is_empty() {
                error.insert(key.into(), json!(value));
            }
        }
        json!({ "error": error })
    }

    /// The text form, for a person.
    pub fn text(&self) -> String {
        let mut text = format!("error: {}", self.message);
        if !self.reason.is_empty() {
            text.push_str(&format!(" ({})", self.reason));
        }
        if !self.hint.is_empty() {
            text.push_str(&format!("\nhint: {}", self.hint));
        }
        text
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        CliError::new(Code::Failed, error.to_string())
    }
}

/// A command's result.
pub type CliResult<T> = Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_one_exit_status_and_a_meaning() {
        for code in Code::ALL {
            assert!(!code.meaning().is_empty());
            assert!((1..=9).contains(&code.exit_status()), "{}", code.as_str());
        }
    }

    #[test]
    fn an_error_prints_only_the_fields_it_has() {
        let error = CliError::new(Code::NotFound, "no such app").hint("grund apps list");
        assert_eq!(
            error.json(),
            json!({"error": {"code": "not_found", "message": "no such app", "hint": "grund apps list"}})
        );
    }
}
