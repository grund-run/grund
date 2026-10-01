//! The machine's own policy (grund-docs design/apps.md §6.4): what no
//! document may ask of this machine, whoever signed it. The owner writes
//! `/etc/grund/policy.toml`; the instance cannot change it, and learns it
//! only from the agent's heartbeat so it does not place what will be
//! refused.
//!
//! A document cannot ask for a privileged container, added capabilities,
//! host namespaces, devices or host paths at all: the replica message has
//! no field for any of them, and the runtime never grants them. What the
//! policy checks is what a document can say: the image's pin, the
//! resources, and the shape of the command and environment.

use std::path::Path;

use anyhow::Context;
use grund_proto::grund::agent::v1::Replica;
use serde::Deserialize;

/// Where the owner's policy lives.
pub const POLICY_FILE: &str = "/etc/grund/policy.toml";

/// The owner's rules. Every key is optional; a missing file is the default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
    /// The policy at `path`, or the default when there is none.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .with_context(|| format!("{} does not parse as grund's policy", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
        }
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

    #[test]
    fn a_policy_file_with_an_unknown_key_is_refused_and_a_missing_one_is_the_default() {
        let dir = std::env::temp_dir().join(format!("grund-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            Policy::load(&dir.join("none.toml")).unwrap(),
            Policy::default()
        );
        std::fs::write(dir.join("p.toml"), "max_replica_memory_mib = 1024\n").unwrap();
        assert_eq!(
            Policy::load(&dir.join("p.toml"))
                .unwrap()
                .max_replica_memory_mib,
            1024
        );
        std::fs::write(dir.join("bad.toml"), "privileged = true\n").unwrap();
        assert!(Policy::load(&dir.join("bad.toml")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
