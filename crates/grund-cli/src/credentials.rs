//! The CLI's file (grund-docs design/cli-redesign.md §8): named contexts,
//! each an instance, the credential for it, the account it signs in as and
//! the organisation commands act on there, and which context is current.
//! YAML, mode 0600; a file others can read is refused, not used. The older
//! credentials file, one entry per instance, is read too and migrated.

use std::{
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::error::{CliError, CliResult, Code};

/// The whole file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    /// The context commands use without --context or GRUND_CONTEXT.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub current: String,
    #[serde(default)]
    pub contexts: Vec<Context>,
}

/// One context.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    /// What `--context` and `grund context use` call it.
    pub name: String,
    /// The instance's origin, such as https://grund.example.com.
    #[serde(rename = "instance")]
    pub url: String,
    /// `grund_cli_…` from `grund auth login`, or `grund_pat_…` from
    /// `grund auth login --with-token`.
    pub credential: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// The organisation commands act on without --org or GRUND_ORG.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub organisation: String,
}

impl Context {
    /// `session` for a `grund auth login` session, `token` for a personal
    /// access token.
    pub fn kind(&self) -> &'static str {
        if self.credential.starts_with("grund_cli_") {
            "session"
        } else {
            "token"
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    #[serde(default)]
    current: String,
    #[serde(default)]
    instances: Vec<LegacyInstance>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyInstance {
    url: String,
    credential: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    organisation: String,
}

impl From<Legacy> for Credentials {
    fn from(legacy: Legacy) -> Self {
        let mut file = Credentials::default();
        let mut current = String::new();
        for instance in legacy.instances {
            let name = file.free_name(&name_for(&instance.url));
            if instance.url == legacy.current {
                current = name.clone();
            }
            file.contexts.push(Context {
                name,
                url: instance.url,
                credential: instance.credential,
                username: instance.username,
                organisation: instance.organisation,
            });
        }
        file.current = current;
        file
    }
}

/// The name a context for `url` gets by default: its host, and port when
/// it has one.
pub fn name_for(url: &str) -> String {
    url.split_once("://")
        .map_or(url, |(_, rest)| rest)
        .to_string()
}

fn config_dir() -> CliResult<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|config| config.join("grund"))
        .ok_or_else(|| {
            CliError::new(Code::Failed, "neither HOME nor XDG_CONFIG_HOME is set")
                .hint("set GRUND_CONFIG, or GRUND_TOKEN and GRUND_INSTANCE")
        })
}

/// Where the file is: GRUND_CONFIG, else GRUND_CREDENTIALS_FILE (its
/// earlier name), else `$XDG_CONFIG_HOME/grund/config.yaml`, else
/// `~/.config/grund/config.yaml`.
pub fn path() -> CliResult<PathBuf> {
    for variable in ["GRUND_CONFIG", "GRUND_CREDENTIALS_FILE"] {
        if let Some(file) = std::env::var_os(variable).filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(file));
        }
    }
    Ok(config_dir()?.join("config.yaml"))
}

/// The file at [`path`]. Where neither variable names a file and only the
/// older `credentials.yaml` exists beside it, that one is migrated:
/// written as `config.yaml`, then renamed `credentials.yaml.old`.
pub fn load() -> CliResult<Credentials> {
    let path = path()?;
    let named = ["GRUND_CONFIG", "GRUND_CREDENTIALS_FILE"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|v| !v.is_empty()));
    if !named && !path.exists() {
        let legacy = config_dir()?.join("credentials.yaml");
        if legacy.exists() {
            let file = Credentials::load(&legacy)?;
            file.save(&path)?;
            std::fs::rename(&legacy, legacy.with_extension("yaml.old")).map_err(|e| {
                CliError::new(
                    Code::Failed,
                    format!("cannot rename {}: {e}", legacy.display()),
                )
            })?;
            return Ok(file);
        }
    }
    Credentials::load(&path)
}

impl Credentials {
    /// The file at `path`, or an empty one when there is none. The older
    /// format, one entry per instance, is read as one context per instance.
    pub fn load(path: &Path) -> CliResult<Self> {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(CliError::new(
                    Code::Failed,
                    format!("cannot read {}: {e}", path.display()),
                ));
            }
        };
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::new(
                Code::Failed,
                format!(
                    "{} can be read by other users, so grund does not use it",
                    path.display()
                ),
            )
            .hint(format!("chmod 600 {}", path.display())));
        }
        let text = std::fs::read_to_string(path).map_err(|e| {
            CliError::new(Code::Failed, format!("cannot read {}: {e}", path.display()))
        })?;
        grund_config::yaml::from_str::<Self>(&text)
            .or_else(|e| {
                grund_config::yaml::from_str::<Legacy>(&text)
                    .map(Self::from)
                    .map_err(|_| e)
            })
            .map_err(|e| {
                CliError::new(
                    Code::Failed,
                    format!(
                        "{} is not a grund config file: {}",
                        path.display(),
                        e.problem()
                    ),
                )
            })
    }

    /// Writes the file at `path`, mode 0600, through a temporary file
    /// beside it so a reader never sees half of it.
    pub fn save(&self, path: &Path) -> CliResult<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        let temporary = dir.join(format!(".config.{}.tmp", std::process::id()));
        let text = format!(
            "# Written by grund. Holds credentials: keep it mode 0600.\n{}",
            grund_config::yaml::to_string(self)
        );
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    }

    /// The context called `name`.
    pub fn context(&self, name: &str) -> Option<&Context> {
        self.contexts.iter().find(|c| c.name == name)
    }

    /// The context called `name`, to change.
    pub fn context_mut(&mut self, name: &str) -> Option<&mut Context> {
        self.contexts.iter_mut().find(|c| c.name == name)
    }

    /// A context for `url`: the current one when it is for `url`, else the
    /// first.
    pub fn for_instance(&self, url: &str) -> Option<&Context> {
        self.context(&self.current)
            .filter(|c| c.url == url)
            .or_else(|| self.contexts.iter().find(|c| c.url == url))
    }

    /// `name`, or `name-2`, `name-3`, … when a context has it.
    pub fn free_name(&self, name: &str) -> String {
        let mut candidate = name.to_string();
        let mut n = 2;
        while self.context(&candidate).is_some() {
            candidate = format!("{name}-{n}");
            n += 1;
        }
        candidate
    }

    /// Adds or replaces the context of its name and makes it current.
    pub fn put(&mut self, context: Context) {
        self.current = context.name.clone();
        self.contexts.retain(|c| c.name != context.name);
        self.contexts.push(context);
    }

    /// Forgets the context called `name`; another becomes current if it was.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.contexts.len();
        self.contexts.retain(|c| c.name != name);
        if self.current == name {
            self.current = self
                .contexts
                .first()
                .map(|c| c.name.clone())
                .unwrap_or_default();
        }
        self.contexts.len() != before
    }
}

/// An instance address as typed, made an origin: `https://` added when no
/// scheme is given, no path, and plain http only to a loopback address.
pub fn origin(text: &str) -> CliResult<String> {
    let text = text.trim().trim_end_matches('/');
    let with_scheme = if text.contains("://") {
        text.to_string()
    } else {
        format!("https://{text}")
    };
    let (scheme, authority) = with_scheme
        .split_once("://")
        .ok_or_else(|| CliError::usage("give the instance as https://grund.example.com"))?;
    let scheme = scheme.to_ascii_lowercase();
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return Err(CliError::usage(format!(
            "{text} is not an instance address; give it as https://grund.example.com"
        ))
        .field("instance"));
    }
    let authority = authority.to_ascii_lowercase();
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default().to_string()
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority.clone(), |(h, _)| h.to_string())
    };
    let loopback = host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match scheme.as_str() {
        "https" => {}
        "http" if loopback => {}
        "http" => {
            return Err(
                CliError::usage("plain http is only for a loopback address; use https")
                    .field("instance"),
            );
        }
        other => {
            return Err(
                CliError::usage(format!("{other}:// is not http or https")).field("instance")
            );
        }
    }
    Ok(format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_becomes_an_origin_and_plain_http_is_for_loopback_only() {
        assert_eq!(
            origin("grund.example.com").unwrap(),
            "https://grund.example.com"
        );
        assert_eq!(
            origin("https://Grund.Example.com/").unwrap(),
            "https://grund.example.com"
        );
        assert_eq!(
            origin("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            origin("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
        assert!(origin("http://grund.example.com").is_err());
        assert!(origin("https://grund.example.com/path").is_err());
        assert!(origin("ftp://grund.example.com").is_err());
    }

    fn context(name: &str, url: &str) -> Context {
        Context {
            name: name.into(),
            url: url.into(),
            credential: "grund_cli_x".into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_file_is_written_0600_and_one_others_can_read_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grund").join("config.yaml");
        let mut file = Credentials::default();
        file.put(Context {
            username: "kasper".into(),
            organisation: "acme".into(),
            ..context("grund.example.com", "https://grund.example.com")
        });
        file.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(Credentials::load(&path).unwrap(), file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused = Credentials::load(&path).unwrap_err();
        assert!(refused.hint.contains("chmod 600"));
    }

    #[test]
    fn an_older_credentials_file_reads_as_one_context_per_instance_keeping_the_current_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        std::fs::write(
            &path,
            "current: https://b.example\ninstances:\n- url: https://a.example\n  credential: grund_cli_a\n  organisation: acme\n- url: https://b.example:8443\n  credential: grund_pat_b\n- url: https://b.example\n  credential: grund_cli_c\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let file = Credentials::load(&path).unwrap();
        let names: Vec<&str> = file.contexts.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a.example", "b.example:8443", "b.example"]);
        assert_eq!(file.current, "b.example");
        assert_eq!(file.context("a.example").unwrap().organisation, "acme");
        assert_eq!(file.context("b.example:8443").unwrap().kind(), "token");
    }

    #[test]
    fn a_second_context_for_a_taken_name_gets_a_number() {
        let mut file = Credentials::default();
        file.put(context("home", "https://a.example"));
        assert_eq!(file.free_name("home"), "home-2");
        file.put(context("home-2", "https://b.example"));
        assert_eq!(file.free_name("home"), "home-3");
    }

    #[test]
    fn a_context_for_an_instance_prefers_the_current_one() {
        let mut file = Credentials::default();
        file.put(context("first", "https://a.example"));
        file.put(context("second", "https://a.example"));
        assert_eq!(
            file.for_instance("https://a.example").unwrap().name,
            "second"
        );
        file.current = "first".into();
        assert_eq!(
            file.for_instance("https://a.example").unwrap().name,
            "first"
        );
    }

    #[test]
    fn removing_the_current_context_makes_another_current() {
        let mut file = Credentials::default();
        file.put(context("a", "https://a.example"));
        file.put(context("b", "https://b.example"));
        assert_eq!(file.current, "b");
        assert!(file.remove("b"));
        assert_eq!(file.current, "a");
    }
}
