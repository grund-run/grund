//! The credentials file (grund-docs design/cli.md §2): one entry per
//! instance, with its credential, the account it signs in as and the
//! default organisation. YAML, mode 0600; a file others can read is
//! refused, not used.

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
    /// The instance commands use without --instance or GRUND_INSTANCE.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub current: String,
    #[serde(default)]
    pub instances: Vec<Instance>,
}

/// One instance signed in to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    /// Its origin, such as https://grund.example.com.
    pub url: String,
    /// `grund_cli_…` from `grund login`, or `grund_pat_…` from
    /// `grund login --with-token`.
    pub credential: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// The organisation commands act on without --org or GRUND_ORG.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub organisation: String,
}

/// Where the file is: GRUND_CREDENTIALS_FILE, else
/// `$XDG_CONFIG_HOME/grund/credentials.yaml`, else
/// `~/.config/grund/credentials.yaml`.
pub fn path() -> CliResult<PathBuf> {
    if let Some(file) = std::env::var_os("GRUND_CREDENTIALS_FILE") {
        return Ok(PathBuf::from(file));
    }
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| {
            CliError::new(Code::Failed, "neither HOME nor XDG_CONFIG_HOME is set")
                .hint("set GRUND_CREDENTIALS_FILE, or GRUND_TOKEN and GRUND_INSTANCE")
        })?;
    Ok(config.join("grund").join("credentials.yaml"))
}

impl Credentials {
    /// The file at `path`, or an empty one when there is none.
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
        grund_domain::yaml::from_str(&text).map_err(|e| {
            CliError::new(
                Code::Failed,
                format!(
                    "{} is not a credentials file: {}",
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
        let temporary = dir.join(format!(".credentials.{}.tmp", std::process::id()));
        let text = format!(
            "# Written by grund login. Holds credentials: keep it mode 0600.\n{}",
            grund_domain::yaml::to_string(self)
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

    /// The entry for `url`.
    pub fn instance(&self, url: &str) -> Option<&Instance> {
        self.instances.iter().find(|i| i.url == url)
    }

    /// Adds or replaces the entry for its URL and makes it current.
    pub fn put(&mut self, instance: Instance) {
        self.current = instance.url.clone();
        self.instances.retain(|i| i.url != instance.url);
        self.instances.push(instance);
    }

    /// Forgets `url`; another entry becomes current if it was.
    pub fn remove(&mut self, url: &str) -> bool {
        let before = self.instances.len();
        self.instances.retain(|i| i.url != url);
        if self.current == url {
            self.current = self
                .instances
                .first()
                .map(|i| i.url.clone())
                .unwrap_or_default();
        }
        self.instances.len() != before
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

    #[test]
    fn the_file_is_written_0600_and_one_others_can_read_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grund").join("credentials.yaml");
        let mut credentials = Credentials::default();
        credentials.put(Instance {
            url: "https://grund.example.com".into(),
            credential: "grund_cli_x".into(),
            username: "kasper".into(),
            organisation: "acme".into(),
        });
        credentials.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(Credentials::load(&path).unwrap(), credentials);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused = Credentials::load(&path).unwrap_err();
        assert!(refused.hint.contains("chmod 600"));
    }

    #[test]
    fn removing_the_current_instance_makes_another_current() {
        let mut credentials = Credentials::default();
        for url in ["https://a.example", "https://b.example"] {
            credentials.put(Instance {
                url: url.into(),
                credential: "c".into(),
                ..Default::default()
            });
        }
        assert_eq!(credentials.current, "https://b.example");
        assert!(credentials.remove("https://b.example"));
        assert_eq!(credentials.current, "https://a.example");
    }
}
