//! `grund-agent status`: this machine as its own files say, as one JSON
//! document for `grund status` to read. It reads only; it calls nothing.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// `grund-agent status`.
#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    #[arg(
        long,
        env = "GRUND_AGENT_DATA_DIR",
        default_value = "/var/lib/grund/agent"
    )]
    pub data_dir: PathBuf,
}

fn read(path: &Path) -> anyhow::Result<Option<Value>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The document: `registered`, and with a registration the machine, the
/// agent's last report, following and any update in progress. `revision`
/// is this executable's build.
pub fn report(data_dir: &Path, revision: &str) -> anyhow::Result<Value> {
    let mut status = json!({"registered": false, "revision": revision});
    let Some(record) = read(&data_dir.join(crate::join::RECORD_FILE))? else {
        return Ok(status);
    };
    status["registered"] = json!(true);
    status["machine"] = json!({
        "id": record["machine_id"],
        "name": record["name"],
        "instance": record["instance_url"],
        "organisationId": record["organisation_id"],
        "registeredAtUnix": record["registered_at_unix"],
    });
    if let Some(health) = read(&data_dir.join("update-health.json"))? {
        status["agent"] = json!({
            "revision": health["revision"],
            "ready": health["ready"],
            "lastContactUnix": health["observed_at_unix"],
        });
    }
    if let Some(policy) = read(&data_dir.join("follow.json"))? {
        let mut following = json!({
            "enabled": policy["enabled"],
            "paused": policy["paused"],
        });
        if let Some(observed) = read(&data_dir.join("follow-status.json"))? {
            following["state"] = observed["state"].clone();
            following["targetRevision"] = observed["target_revision"].clone();
            following["failureCode"] = observed["failure_code"].clone();
            following["observedAtUnix"] = observed["observed_at_unix"].clone();
        }
        status["following"] = following;
    }
    if let Some(journal) = read(&data_dir.join("update-journal.json"))? {
        status["update"] = json!({
            "attemptId": journal["offer"]["attempt_id"],
            "target": journal["offer"]["target"]["revision"],
            "phase": journal["phase"],
        });
    }
    Ok(status)
}

/// Prints [`report`] for `args`.
pub fn run(args: &StatusArgs, revision: &str) -> anyhow::Result<()> {
    println!("{}", report(&args.data_dir, revision)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("grund-status-{}", uuid::Uuid::now_v7()));
            std::fs::create_dir_all(&path).unwrap();
            Dir(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_unregistered_machine_says_so_and_nothing_else() {
        let dir = Dir::new();
        let status = report(dir.path(), "abc").unwrap();
        assert_eq!(status, json!({"registered": false, "revision": "abc"}));
    }

    #[test]
    fn a_following_machine_reports_its_identity_last_contact_and_update() {
        let dir = Dir::new();
        let write = |name: &str, value: Value| {
            std::fs::write(dir.path().join(name), value.to_string()).unwrap();
        };
        write(
            "machine.json",
            json!({"machine_id": "m-1", "name": "web-1", "instance_url": "https://grund.example.com",
                   "organisation_id": "o-1", "registered_at_unix": 10, "trust_key": {"secret": "x"}}),
        );
        write(
            "update-health.json",
            json!({"revision": "r1", "ready": true, "observed_at_unix": 99, "registration_key": "k"}),
        );
        write("follow.json", json!({"enabled": true, "paused": false}));
        write(
            "follow-status.json",
            json!({"state": "candidate", "target_revision": "r2", "observed_at_unix": 100}),
        );
        write(
            "update-journal.json",
            json!({"offer": {"attempt_id": "a-1", "target": {"revision": "r2"}}, "phase": "candidate"}),
        );
        let status = report(dir.path(), "r1").unwrap();
        assert_eq!(status["machine"]["name"], "web-1");
        assert_eq!(status["agent"]["lastContactUnix"], 99);
        assert_eq!(status["following"]["state"], "candidate");
        assert_eq!(status["update"]["phase"], "candidate");
        let text = status.to_string();
        assert!(!text.contains("trust_key") && !text.contains("registration_key"));
    }
}
