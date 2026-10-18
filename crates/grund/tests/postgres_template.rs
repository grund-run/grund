use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    net::IpAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

use grund_domain::app::templates;
use uuid::Uuid;

#[test]
#[ignore = "requires Docker and the catalogue's pinned PostgreSQL image already provisioned locally"]
fn postgres_template_repairs_lost_host_authentication_after_restart() {
    let template = templates::find("postgres").expect("PostgreSQL template exists");
    checked(
        &["version", "--format", "{{.Server.Version}}"],
        "Docker is available",
    );
    checked(
        &["image", "inspect", "--format", "{{.Id}}", template.image],
        "the pinned PostgreSQL image must be provisioned before this opt-in test (never pulled here)",
    );

    let mut fixture = Postgres::new();
    fixture.start(template);
    fixture.wait_until_listening();
    let marker = Uuid::new_v4().simple().to_string();
    fixture.query(
        &format!(
            "CREATE TABLE template_restart_marker (value text NOT NULL); \
             INSERT INTO template_restart_marker VALUES ('{marker}');"
        ),
        "a non-loopback SCRAM client seeds the database",
    );
    fixture.reject_wrong_password();
    fixture.assert_broad_rule_count("1");

    fixture.exec(
        &[
            "/bin/sh",
            "-ec",
            r#"umask 077
awk '!($1 == "host" && $2 == "all" && $3 == "all" && $4 == "all" && $5 == "scram-sha-256" && NF == 5)' "$PGDATA/pg_hba.conf" > "$PGDATA/pg_hba.conf.regression"
chown postgres:postgres "$PGDATA/pg_hba.conf.regression"
mv "$PGDATA/pg_hba.conf.regression" "$PGDATA/pg_hba.conf""#,
        ],
        "remove only the broad SCRAM host rule from the persisted cluster",
    );
    fixture.assert_broad_rule_count("0");
    fixture.restart();
    assert_eq!(
        fixture.query(
            "SELECT value FROM template_restart_marker",
            "a client reconnects after the persisted host authentication line was lost",
        ),
        marker,
        "the repaired cluster retains its committed marker",
    );
    fixture.reject_wrong_password();
    fixture.assert_broad_rule_count("1");

    fixture.restart();
    assert_eq!(
        fixture.query(
            "SELECT value FROM template_restart_marker",
            "a client reconnects after a second restart",
        ),
        marker,
    );
    fixture.reject_wrong_password();
    fixture.assert_broad_rule_count("1");

    fixture.exec(
        &[
            "/bin/sh",
            "-ec",
            r#"rm "$PGDATA/postgresql.conf" "$PGDATA/pg_hba.conf" "$PGDATA/pg_ident.conf""#,
        ],
        "remove the cluster's configuration files without removing its data",
    );
    fixture.restart();
    assert_eq!(
        fixture.query(
            "SELECT value FROM template_restart_marker",
            "a client reconnects after missing cluster configuration files are regenerated",
        ),
        marker,
    );
    fixture.reject_wrong_password();
    fixture.assert_broad_rule_count("1");
    assert_eq!(
        fixture.query(
            "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL",
            "the recovered authentication file has no invalid rules",
        ),
        "0",
    );
}

struct Postgres {
    directory: PathBuf,
    name: String,
    network: Option<String>,
    volume: Option<String>,
    container: Option<String>,
    address: String,
}

impl Postgres {
    fn new() -> Self {
        let name = format!("grund-pg-auth-{}", Uuid::new_v4().simple());
        let directory = std::env::temp_dir().join(&name);
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .expect("create private PostgreSQL test directory");
        Self {
            directory,
            name,
            network: None,
            volume: None,
            container: None,
            address: String::new(),
        }
    }

    fn start(&mut self, template: &templates::Template) {
        let envfile = self.directory.join("postgres.env");
        let mut credentials = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&envfile)
            .expect("create private PostgreSQL environment file");
        for (key, value) in template.env {
            writeln!(credentials, "{key}={value}").expect("write template environment");
        }
        writeln!(credentials, "POSTGRES_PASSWORD={}", Uuid::new_v4().simple())
            .expect("write generated PostgreSQL credential");
        drop(credentials);

        self.network = Some(checked(
            &["network", "create", "--internal", &self.name],
            "create an isolated owned test network",
        ));
        self.volume = Some(checked(
            &["volume", "create", &self.name],
            "create an owned test data volume",
        ));
        let mount = format!(
            "type=volume,source={},target={}",
            self.volume.as_deref().unwrap(),
            template
                .storage
                .expect("PostgreSQL has persistent data")
                .path,
        );
        let envfile = envfile.to_str().expect("environment path is UTF-8");
        let mut args = vec![
            "create",
            "--pull=never",
            "--name",
            &self.name,
            "--network",
            self.network.as_deref().unwrap(),
            "--mount",
            &mount,
            "--env-file",
            envfile,
            "--entrypoint",
            template
                .command
                .first()
                .expect("PostgreSQL template has a command"),
            template.image,
        ];
        args.extend_from_slice(&template.command[1..]);
        self.container = Some(checked(
            &args,
            "create the exact shipped PostgreSQL template",
        ));
        checked(&["start", self.id()], "start the PostgreSQL template");
        self.address = checked(
            &[
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                self.id(),
            ],
            "find the container's isolated eth0 address",
        );
        let address: IpAddr = self.address.parse().expect("container has an IP address");
        assert!(
            !address.is_loopback() && !address.is_unspecified(),
            "the client must exercise host authentication, not loopback trust",
        );
    }

    fn id(&self) -> &str {
        self.container.as_deref().expect("test owns a container")
    }

    fn exec(&self, args: &[&str], context: &str) -> String {
        let mut command = vec!["exec", self.id()];
        command.extend_from_slice(args);
        checked(&command, context)
    }

    fn wait_until_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let output = docker(&[
                "exec",
                self.id(),
                "pg_isready",
                "-h",
                &self.address,
                "-t",
                "1",
            ]);
            if output.status.success() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "PostgreSQL did not begin listening on its non-loopback address: {}",
                String::from_utf8_lossy(&output.stderr),
            );
            thread::sleep(Duration::from_millis(200));
        }
    }

    fn restart(&self) {
        checked(
            &["restart", "--time", "10", self.id()],
            "restart the existing cluster",
        );
        self.wait_until_listening();
    }

    fn client(&self, sql: &str, wrong_password: bool) -> Output {
        let script = if wrong_password {
            r#"export PGPASSWORD="${POSTGRES_PASSWORD}-wrong"
export PGCONNECT_TIMEOUT=2
exec psql -X -w -v ON_ERROR_STOP=1 -At -h "$1" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$2""#
        } else {
            r#"export PGPASSWORD="$POSTGRES_PASSWORD"
export PGCONNECT_TIMEOUT=2
exec psql -X -w -v ON_ERROR_STOP=1 -At -h "$1" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$2""#
        };
        docker(&[
            "exec",
            self.id(),
            "/bin/sh",
            "-ec",
            script,
            "psql",
            &self.address,
            sql,
        ])
    }

    fn query(&self, sql: &str, context: &str) -> String {
        successful(self.client(sql, false), context)
    }

    fn reject_wrong_password(&self) {
        let output = self.client("SELECT 1", true);
        assert_eq!(
            output.status.code(),
            Some(2),
            "psql must reject the wrong-password connection: {}",
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn assert_broad_rule_count(&self, expected: &str) {
        assert_eq!(
            self.query(
                "SELECT count(*) FROM pg_hba_file_rules \
                 WHERE type = 'host' AND database = ARRAY['all']::text[] \
                 AND user_name = ARRAY['all']::text[] AND address = 'all' \
                 AND auth_method = 'scram-sha-256' AND error IS NULL",
                "inspect parsed broad SCRAM host authentication rules",
            ),
            expected,
            "there is exactly one repaired broad host rule and no duplicate on restart",
        );
    }
}

impl Drop for Postgres {
    fn drop(&mut self) {
        if let Some(id) = &self.container {
            let _ = Command::new("docker").args(["rm", "--force", id]).output();
        }
        if let Some(id) = &self.volume {
            let _ = Command::new("docker").args(["volume", "rm", id]).output();
        }
        if let Some(id) = &self.network {
            let _ = Command::new("docker").args(["network", "rm", id]).output();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn docker(args: &[&str]) -> Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("execute Docker (required for this explicitly ignored regression)")
}

fn checked(args: &[&str], context: &str) -> String {
    successful(docker(args), context)
}

fn successful(output: Output, context: &str) -> String {
    assert!(
        output.status.success(),
        "{context}: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout)
        .expect("Docker/PostgreSQL output is UTF-8")
        .trim()
        .to_owned()
}
