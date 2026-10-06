//! The machine's own policy (grund-docs design/apps.md §6.4): what no
//! document may ask of this machine, whoever signed it. The owner writes
//! `/etc/grund/policy.toml`; the instance cannot change it, and learns it
//! only from the agent's heartbeat so it does not place what will be
//! refused.
//!
//! The file was `/etc/grund/policy.toml` until 2026-10-06. An agent that
//! finds only that file reads it, writes the same policy as `policy.yaml`
//! beside it, logs that it did, and leaves the old file in place, so no
//! machine loses its policy on upgrade. That fallback goes in a later
//! release.
//!
//! A document cannot ask for a privileged container, added capabilities,
//! host namespaces, devices or host paths at all: the replica message has
//! no field for any of them, and the runtime never grants them. What the
//! policy checks is what a document can say: the image's pin, the
//! resources, and the shape of the command and environment.

use std::path::Path;

use anyhow::Context;
use grund_proto::grund::agent::v1::Replica;
use serde::{Deserialize, Serialize};

/// Where the owner's policy lives.
pub const POLICY_FILE: &str = "/etc/grund/policy.yaml";

/// The owner's rules. Every key is optional; a missing file is the default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// Run containers at all.
    pub apps: bool,
    /// The most memory one replica may reserve, MiB; 0: no limit beyond the
    /// machine.
    pub max_replica_memory_mib: u64,
    /// The most CPU one replica may reserve, thousandths; 0: no limit.
    pub max_replica_cpu_millis: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            apps: true,
            max_replica_memory_mib: 0,
            max_replica_cpu_millis: 0,
        }
    }
}

impl Policy {
    /// The policy at `path`, or the default when there is none. When
    /// `path` is missing and an older `policy.toml` sits beside it, that
    /// file's policy is the one used, and is written to `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => grund_domain::yaml::from_str(&text)
                .with_context(|| format!("{} does not parse as grund's policy", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => match legacy_file(path) {
                Some(old) => Self::migrate(&old, path),
                None => Ok(Self::default()),
            },
            Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
        }
    }

    fn migrate(old: &Path, path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(old).with_context(|| format!("read {}", old.display()))?;
        let policy: Self = toml::from_str(&text)
            .with_context(|| format!("{} does not parse as grund's policy", old.display()))?;
        match write_beside(old, path, &policy.to_yaml()) {
            Ok(()) => tracing::info!(
                from = %old.display(),
                to = %path.display(),
                "read the machine's policy from its old TOML file and wrote it as YAML; the TOML file is no longer read and may be removed"
            ),
            Err(error) => tracing::warn!(
                from = %old.display(),
                to = %path.display(),
                error = format!("{error:#}"),
                "read the machine's policy from its old TOML file but could not write it as YAML; using it, and trying again at the next start"
            ),
        }
        Ok(policy)
    }

    /// The policy as `/etc/grund/policy.yaml` holds it.
    pub fn to_yaml(&self) -> String {
        format!(
            "# This machine's policy: what no app may ask of it. Read by grund agent at start.\n{}",
            grund_domain::yaml::to_string(self)
        )
    }

    /// Why this machine refuses `replica`, or `None` when it may run.
    pub fn refuses(&self, replica: &Replica) -> Option<String> {
        if !self.apps {
            return Some("this machine's owner turned apps off".into());
        }
        let image = replica.image.as_option();
        let digest = image.map(|i| i.digest.as_str()).unwrap_or_default();
        if !grund_domain::app::spec::is_digest(digest) {
            return Some("the image is not pinned by sha256 digest".into());
        }
        let reference = image.map(|i| i.reference.as_str()).unwrap_or_default();
        if grund_domain::app::spec::ImageReference::parse(reference).is_err() {
            return Some("the image reference does not parse".into());
        }
        if self.max_replica_memory_mib > 0 && replica.memory_mib > self.max_replica_memory_mib {
            return Some(format!(
                "it asks for {} MiB of memory; this machine allows {} MiB per copy",
                replica.memory_mib, self.max_replica_memory_mib
            ));
        }
        if self.max_replica_cpu_millis > 0 && replica.cpu_millis > self.max_replica_cpu_millis {
            return Some(format!(
                "it asks for {} thousandths of a CPU; this machine allows {} per copy",
                replica.cpu_millis, self.max_replica_cpu_millis
            ));
        }
        if replica.memory_mib == 0 || replica.cpu_millis == 0 {
            return Some("it asks for no memory or no CPU".into());
        }
        if replica.command.iter().any(|a| a.contains('\0'))
            || replica.env.iter().any(|e| {
                e.name.is_empty() || e.name.contains(['=', '\0']) || e.value.contains('\0')
            })
            || replica
                .secret_env
                .iter()
                .any(|e| e.env.is_empty() || e.env.contains(['=', '\0']))
        {
            return Some("its command or environment is malformed".into());
        }
        if replica
            .secret_env
            .iter()
            .any(|e| !replica.secrets.iter().any(|s| s.name == e.secret))
        {
            return Some("it hands the app a secret its release does not name".into());
        }
        None
    }
}

fn legacy_file(path: &Path) -> Option<std::path::PathBuf> {
    let old = path.with_extension("toml");
    (old != path && old.is_file()).then_some(old)
}

fn write_beside(old: &Path, path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let partial = path.with_extension("yaml.partial");
    let mut file =
        std::fs::File::create(&partial).with_context(|| format!("create {}", partial.display()))?;
    file.write_all(text.as_bytes())?;
    file.set_permissions(std::fs::metadata(old)?.permissions())?;
    file.sync_all()?;
    std::fs::rename(&partial, path).with_context(|| format!("rename to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use grund_proto::grund::agent::v1::{Image, SecretEnv};

    use super::*;

    fn replica() -> Replica {
        Replica {
            replica_id: "r".into(),
            image: buffa::MessageField::from(Image {
                reference: "nginx:1.27".into(),
                digest: format!("sha256:{}", "a".repeat(64)),
                ..Default::default()
            }),
            memory_mib: 512,
            cpu_millis: 1000,
            ..Default::default()
        }
    }

    #[test]
    fn an_unpinned_image_is_refused_whatever_the_policy() {
        let mut r = replica();
        r.image = buffa::MessageField::from(Image {
            reference: "nginx:1.27".into(),
            digest: String::new(),
            ..Default::default()
        });
        assert!(Policy::default().refuses(&r).unwrap().contains("pinned"));
        assert_eq!(Policy::default().refuses(&replica()), None);
    }

    #[test]
    fn the_owners_caps_and_switch_are_kept() {
        let capped = Policy {
            max_replica_memory_mib: 256,
            ..Policy::default()
        };
        assert!(capped.refuses(&replica()).unwrap().contains("256 MiB"));
        let off = Policy {
            apps: false,
            ..Policy::default()
        };
        assert!(off.refuses(&replica()).is_some());
    }

    #[test]
    fn a_secret_the_release_does_not_name_is_refused() {
        let mut r = replica();
        r.secret_env.push(SecretEnv {
            env: "PASSWORD".into(),
            secret: "db".into(),
            ..Default::default()
        });
        assert!(Policy::default().refuses(&r).unwrap().contains("secret"));
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("grund-policy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_policy_file_with_an_unknown_key_is_refused_and_a_missing_one_is_the_default() {
        let dir = scratch("load");
        assert_eq!(
            Policy::load(&dir.join("none.yaml")).unwrap(),
            Policy::default()
        );
        std::fs::write(dir.join("p.yaml"), "max_replica_memory_mib: 1024\n").unwrap();
        assert_eq!(
            Policy::load(&dir.join("p.yaml"))
                .unwrap()
                .max_replica_memory_mib,
            1024
        );
        std::fs::write(dir.join("bad.yaml"), "apps: true\nprivileged: true\n").unwrap();
        let error = format!("{:#}", Policy::load(&dir.join("bad.yaml")).unwrap_err());
        assert!(error.contains("line 2, column 1"), "{error}");
        assert!(error.contains("privileged"), "{error}");
        std::fs::write(dir.join("yes.yaml"), "apps: no\n").unwrap();
        assert!(Policy::load(&dir.join("yes.yaml")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_old_toml_policy_is_kept_and_written_as_yaml_beside_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("migrate");
        let old = dir.join("policy.toml");
        std::fs::write(&old, "apps = false\nmax_replica_cpu_millis = 500\n").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o640)).unwrap();
        let path = dir.join("policy.yaml");
        let policy = Policy::load(&path).unwrap();
        let expected = Policy {
            apps: false,
            max_replica_cpu_millis: 500,
            ..Policy::default()
        };
        assert_eq!(policy, expected);
        assert!(old.is_file());
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.starts_with("# "), "{written}");
        assert!(written.contains("apps: false\n"), "{written}");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        std::fs::write(&old, "apps = true\n").unwrap();
        assert_eq!(Policy::load(&path).unwrap(), expected);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_old_policy_that_cannot_be_written_is_still_used() {
        let dir = scratch("readonly");
        let old = dir.join("policy.toml");
        std::fs::write(&old, "max_replica_memory_mib = 256\n").unwrap();
        let beside = dir.join("policy.yaml");
        std::fs::create_dir(dir.join("policy.yaml.partial")).unwrap();
        assert_eq!(Policy::load(&beside).unwrap().max_replica_memory_mib, 256);
        assert!(!beside.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_old_policy_that_does_not_parse_stops_the_agent() {
        let dir = scratch("broken");
        std::fs::write(dir.join("policy.toml"), "privileged = true\n").unwrap();
        assert!(Policy::load(&dir.join("policy.yaml")).is_err());
        assert!(!dir.join("policy.yaml").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
