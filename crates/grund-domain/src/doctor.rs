//! What `grund doctor` found, and the two forms it prints: one line per check
//! for people and `grep`, or one JSON document for scripts. Both are stable:
//! check names and statuses are part of the interface, the wording of a
//! detail is not.
//!
//! ```text
//! grund doctor: instance
//! ok    database        PostgreSQL 18.1; 12 of 12 migrations applied
//! fail  certificate     no certificate for grund.example.com yet (last error: acme_unreachable)
//!       fix: check that grund.example.com points at this machine and 443 reaches it
//! summary: 1 fail, 0 warn, 1 ok, 0 skip
//! ```

use serde::Serialize;

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Nothing to do.
    Ok,
    /// Works, but something is missing or will break; the fix says what.
    Warn,
    /// Broken; the fix says what to do. Makes the exit code non-zero.
    Fail,
    /// Not checked here: it does not apply, or it needs root.
    Skip,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "fail",
            Status::Skip => "skip",
        }
    }
}

/// One check: a stable name, what was seen, and what to do about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Check {
    pub fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, Status::Ok, detail, None)
    }

    pub fn skip(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, Status::Skip, detail, None)
    }

    pub fn warn(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self::new(name, Status::Warn, detail, Some(fix.into()))
    }

    pub fn fail(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self::new(name, Status::Fail, detail, Some(fix.into()))
    }

    fn new(name: &str, status: Status, detail: impl Into<String>, fix: Option<String>) -> Self {
        Self {
            name: name.to_string(),
            status,
            detail: one_line(&detail.into()),
            fix: fix.map(|fix| one_line(&fix)),
        }
    }
}

/// Every check of one run, in the order they ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// `instance` or `machine`.
    pub target: String,
    pub checks: Vec<Check>,
}

impl Report {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            checks: Vec::new(),
        }
    }

    pub fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    /// Whether any check failed: the exit code is then 1.
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|c| c.status == Status::Fail)
    }

    fn count(&self, status: Status) -> usize {
        self.checks.iter().filter(|c| c.status == status).count()
    }

    /// The form for people and `grep '^fail '`.
    pub fn text(&self) -> String {
        let mut out = format!("grund doctor: {}\n", self.target);
        for check in &self.checks {
            out.push_str(&format!(
                "{:<5} {:<15} {}\n",
                check.status.as_str(),
                check.name,
                check.detail
            ));
            if let Some(fix) = &check.fix {
                out.push_str(&format!("      fix: {fix}\n"));
            }
        }
        out.push_str(&format!(
            "summary: {} fail, {} warn, {} ok, {} skip\n",
            self.count(Status::Fail),
            self.count(Status::Warn),
            self.count(Status::Ok),
            self.count(Status::Skip)
        ));
        out
    }

    /// The form for scripts: `{"target", "status", "checks": [...]}`, where
    /// `status` is the worst of the checks'.
    pub fn json(&self) -> String {
        let worst = if self.failed() {
            Status::Fail
        } else if self.count(Status::Warn) > 0 {
            Status::Warn
        } else {
            Status::Ok
        };
        serde_json::json!({
            "target": self.target,
            "status": worst,
            "checks": self.checks,
        })
        .to_string()
    }
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        let mut report = Report::new("instance");
        report.push(Check::ok("database", "PostgreSQL 18.1"));
        report.push(Check::fail(
            "certificate",
            "none yet\nfor grund.example.com",
            "point the name here",
        ));
        report
    }

    #[test]
    fn a_failed_check_is_a_line_starting_with_fail_and_its_fix_follows() {
        let text = report().text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "grund doctor: instance");
        assert!(lines[1].starts_with("ok    database        "));
        assert_eq!(
            lines[2],
            "fail  certificate     none yet for grund.example.com"
        );
        assert_eq!(lines[3], "      fix: point the name here");
        assert_eq!(lines[4], "summary: 1 fail, 0 warn, 1 ok, 0 skip");
    }

    #[test]
    fn the_json_names_the_worst_status_and_every_check() {
        let json: serde_json::Value = serde_json::from_str(&report().json()).unwrap();
        assert_eq!(json["status"], "fail");
        assert_eq!(json["checks"][1]["name"], "certificate");
        assert_eq!(json["checks"][0].get("fix"), None);
    }

    #[test]
    fn only_a_failure_fails_the_run() {
        let mut report = Report::new("machine");
        report.push(Check::warn("kvm", "no /dev/kvm", "no VMs here"));
        report.push(Check::skip("forward-drop", "needs root"));
        assert!(!report.failed());
        report.push(Check::fail("systemd", "none", "use systemd"));
        assert!(report.failed());
    }
}
