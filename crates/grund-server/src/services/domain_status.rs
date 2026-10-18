//! One observed domain status and only the DNS records still needed.

use std::borrow::Cow;

use grund_store::domain_setup::{Step, StepState};

use super::domains::{DomainView, Status};

/// The shared presentation used by the dashboard and domain RPC responses.
pub struct SetupSummary<'a> {
    pub sentence: Cow<'a, str>,
    pub tone: &'static str,
    pub records: Vec<(&'static str, Cow<'a, str>, &'a str)>,
    pub failed: bool,
    pub working: bool,
}

fn step<'a>(view: &'a DomainView, name: &str) -> Option<&'a Step> {
    view.steps.iter().find(|step| step.name == name)
}

fn done(view: &DomainView, name: &str) -> bool {
    step(view, name).is_some_and(|step| step.state == StepState::Done)
}

fn failed(view: &DomainView, name: &str) -> bool {
    step(view, name).is_some_and(|step| step.state == StepState::Failed)
}

fn observed_target(detail: &str) -> Option<&str> {
    let (addresses, rest) = detail
        .strip_prefix("Addresses: ")?
        .split_once(". CNAME: ")?;
    let (aliases, _) = rest.split_once(". Configured edge addresses: ")?;
    if aliases != "none observed" && !aliases.is_empty() {
        Some(aliases)
    } else if addresses != "none" && !addresses.is_empty() {
        Some(addresses)
    } else {
        None
    }
}

fn dns_answer_missing(detail: &str) -> bool {
    detail.starts_with("Addresses: none. CNAME: none observed. ")
        && (detail.ends_with("DNS answered NXDOMAIN.")
            || detail.ends_with("DNS returned no address records."))
}

/// Derives status from current setup observations, never from a stored certificate alone.
pub fn summarize<'a>(view: &'a DomainView, edge_target: Option<&'a str>) -> SetupSummary<'a> {
    let unverified = view.parent_domain.is_none() && view.verified_at.is_none();
    let dns_done = done(view, "dns_record");
    let bound = view.app_name.is_some();
    let needs_routing = !dns_done && (unverified || bound);
    let target = edge_target.filter(|target| !target.is_empty());
    let mut records = Vec::with_capacity(
        usize::from(unverified) + usize::from(needs_routing && target.is_some()),
    );
    if unverified && !view.txt_name.is_empty() && !view.txt_value.is_empty() {
        records.push((
            "TXT",
            Cow::Borrowed(view.txt_name.as_str()),
            view.txt_value.as_str(),
        ));
    }
    if let Some(target) = target.filter(|_| needs_routing) {
        let name = if let Some(parent) = view.parent_domain.as_deref() {
            Cow::Owned(format!("*.{parent}"))
        } else {
            Cow::Borrowed(view.name.as_str())
        };
        records.push(("CNAME", name, target));
    }
    let (sentence, tone, is_failed, working) = if unverified {
        if let Some(problem) = view
            .problem
            .as_deref()
            .filter(|problem| !problem.is_empty())
        {
            (
                Cow::Owned(format!("Not working: {problem}")),
                "danger",
                true,
                false,
            )
        } else {
            (
                Cow::Borrowed("Waiting for DNS: add the records below"),
                "orange",
                false,
                false,
            )
        }
    } else if !bound && view.state == "bound" {
        (
            Cow::Borrowed("Not working: the app is gone; choose another app"),
            "danger",
            true,
            false,
        )
    } else if !bound && !view.is_app_domain {
        (
            Cow::Borrowed("Verified: choose an app to serve here"),
            "blue",
            false,
            false,
        )
    } else if !dns_done && bound {
        if target.is_none() {
            (
                Cow::Borrowed("Not working: no domain target is configured"),
                "danger",
                true,
                false,
            )
        } else if let Some(dns) =
            step(view, "dns_record").filter(|step| step.state == StepState::Failed)
        {
            if dns_answer_missing(&dns.detail) {
                (
                    Cow::Borrowed("Waiting for DNS: add the record below"),
                    "orange",
                    false,
                    false,
                )
            } else if let (Some(observed), Some(target)) = (observed_target(&dns.detail), target) {
                (
                    Cow::Owned(format!(
                        "Not working: the record points at {observed}, it should point at {target}"
                    )),
                    "danger",
                    true,
                    false,
                )
            } else {
                (
                    Cow::Borrowed("Not working: the DNS check failed"),
                    "danger",
                    true,
                    false,
                )
            }
        } else {
            (
                Cow::Borrowed("Waiting for DNS: add the record below"),
                "orange",
                false,
                false,
            )
        }
    } else if !bound {
        (
            Cow::Borrowed("Verified: used for your apps' addresses"),
            "blue",
            false,
            false,
        )
    } else if failed(view, "edge_reachable") {
        (
            Cow::Borrowed("Not working: this domain could not reach your app"),
            "danger",
            true,
            false,
        )
    } else if done(view, "serving_https") {
        records.clear();
        (
            Cow::Owned(format!("Working: https://{} serves your app", view.name)),
            "ok",
            false,
            true,
        )
    } else if failed(view, "serving_https") {
        (
            Cow::Borrowed("Not working: the HTTPS check failed"),
            "danger",
            true,
            false,
        )
    } else if [
        "certificate_requested",
        "challenge_passed",
        "certificate_issued",
    ]
    .iter()
    .any(|name| failed(view, name))
        || view.status == Status::Error
    {
        let sentence = view
            .problem
            .as_deref()
            .filter(|problem| !problem.is_empty())
            .map_or_else(
                || Cow::Borrowed("Not working: the certificate could not be issued"),
                |problem| Cow::Owned(format!("Not working: {problem}")),
            );
        (sentence, "danger", true, false)
    } else if done(view, "certificate_issued") || view.status == Status::Issued {
        (Cow::Borrowed("Checking HTTPS"), "orange", false, false)
    } else {
        (
            Cow::Borrowed("Getting a certificate (usually a minute)"),
            "orange",
            false,
            false,
        )
    };
    SetupSummary {
        sentence,
        tone,
        records,
        failed: is_failed,
        working,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use grund_store::domain_setup::waiting_steps;

    use super::*;

    fn domain() -> DomainView {
        DomainView {
            name: "app.example.com".into(),
            status: Status::Bound,
            state: "bound".into(),
            txt_name: "_grund.app.example.com".into(),
            txt_value: "ownership-token".into(),
            app_name: Some("app".into()),
            is_app_domain: false,
            parent_domain: None,
            managed_app_name: None,
            added_at: Utc::now(),
            verified_at: Some(Utc::now()),
            bound_at: Some(Utc::now()),
            certificate_not_after: None,
            problem: None,
            steps: waiting_steps(),
            certificate_attempts: 0,
            certificate_next_attempt_at: None,
        }
    }

    fn set(view: &mut DomainView, name: &str, state: StepState, detail: &str) {
        let step = view
            .steps
            .iter_mut()
            .find(|step| step.name == name)
            .unwrap();
        step.state = state;
        step.detail = detail.into();
    }

    #[test]
    fn waiting_for_dns_takes_precedence_over_a_stale_certificate_failure() {
        let mut view = domain();
        view.status = Status::Error;
        view.problem = Some("A previous certificate attempt failed".into());
        set(&mut view, "certificate_issued", StepState::Failed, "failed");
        let summary = summarize(&view, Some("edge.example.com"));
        assert!(!summary.failed);
        assert!(!summary.working);
        assert_eq!(summary.records.len(), 1);
        set(&mut view, "dns_record", StepState::Done, "matched");
        assert!(summarize(&view, Some("edge.example.com")).failed);
    }

    #[test]
    fn a_stored_certificate_does_not_prove_https_is_working() {
        let mut view = domain();
        view.status = Status::Issued;
        view.certificate_not_after = Some(Utc::now());
        set(&mut view, "dns_record", StepState::Done, "matched");
        assert!(!summarize(&view, Some("edge.example.com")).working);
        set(&mut view, "serving_https", StepState::Done, "verified");
        assert!(summarize(&view, Some("edge.example.com")).working);
        set(
            &mut view,
            "dns_record",
            StepState::Failed,
            "Addresses: 192.0.2.1. CNAME: wrong.example.com. Configured edge addresses: 192.0.2.2. Not all observed addresses match.",
        );
        let summary = summarize(&view, Some("edge.example.com"));
        assert!(summary.failed);
        assert!(!summary.working);
        assert_eq!(summary.records.len(), 1);
    }

    #[test]
    fn completed_records_and_inherited_ownership_are_not_requested_again() {
        let mut view = domain();
        view.verified_at = None;
        view.state = "pending".into();
        view.status = Status::Pending;
        view.app_name = None;
        assert_eq!(summarize(&view, Some("edge.example.com")).records.len(), 2);
        view.verified_at = Some(Utc::now());
        view.state = "verified".into();
        view.status = Status::Verified;
        assert!(
            summarize(&view, Some("edge.example.com"))
                .records
                .is_empty()
        );
        view.parent_domain = Some("example.com".into());
        view.verified_at = None;
        view.app_name = Some("app".into());
        let summary = summarize(&view, Some("edge.example.com"));
        assert_eq!(summary.records.len(), 1);
        assert_eq!(summary.records[0].0, "CNAME");
        assert_eq!(summary.records[0].1, "*.example.com");
        set(&mut view, "dns_record", StepState::Done, "matched");
        assert!(
            summarize(&view, Some("edge.example.com"))
                .records
                .is_empty()
        );
        view.app_name = None;
        view.parent_domain = None;
        view.verified_at = Some(Utc::now());
        view.is_app_domain = true;
        set(&mut view, "dns_record", StepState::Waiting, "");
        assert!(
            summarize(&view, Some("edge.example.com"))
                .records
                .is_empty()
        );
    }

    #[test]
    fn an_absent_answer_is_waiting_but_a_wrong_record_is_a_failure() {
        let mut view = domain();
        set(
            &mut view,
            "dns_record",
            StepState::Failed,
            "Addresses: none. CNAME: none observed. Configured edge addresses: 192.0.2.2. Not all observed addresses match. DNS answered NXDOMAIN.",
        );
        assert!(!summarize(&view, Some("edge.example.com")).failed);
        set(
            &mut view,
            "dns_record",
            StepState::Failed,
            "Addresses: 192.0.2.1. CNAME: wrong.example.com. Configured edge addresses: 192.0.2.2. Not all observed addresses match.",
        );
        assert!(summarize(&view, Some("edge.example.com")).failed);
        set(
            &mut view,
            "dns_record",
            StepState::Failed,
            "unrecognized diagnostic format",
        );
        let summary = summarize(&view, Some("edge.example.com"));
        assert!(summary.failed);
        assert!(!summary.working);
        assert_eq!(observed_target("unrecognized diagnostic format"), None);
        assert!(!summary.sentence.contains("unrecognized diagnostic format"));
    }
}
