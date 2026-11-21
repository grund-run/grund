//! Bounded single-attempt executions; argument bodies never enter durable history.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Immutable execution inputs, excluding arguments and resolved secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub organisation_id: Uuid,
    pub stack_id: Uuid,
    pub stack_name: String,
    pub service: String,
    pub stack_revision: u32,
    pub app_id: Uuid,
    pub app_name: String,
    pub release: crate::app::Release,
    pub settings: grund_config::app::spec::AppSettings,
    pub machine_id: Uuid,
    pub requester_id: Uuid,
    pub attempt_id: Uuid,
    pub requested_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
}

/// Unknown executions retain their capacity and service fence until absence is proven.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    NonExistent,
    Pending,
    Running,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    NotStarted,
    Unknown,
}

impl Status {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::TimedOut
                | Self::NotStarted
                | Self::Unknown
        )
    }
}

/// A lifecycle contains only a handful of facts and deliberately needs no snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub request: Option<Request>,
    pub status: Status,
    pub started_at: Option<DateTime<Utc>>,
    pub cancel_requested_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub reason: String,
    pub stop_confirmed: bool,
}

impl Run {
    /// Execution uncertainty expires arguments from the original deadline, not report time.
    pub fn args_expire_at(&self) -> Option<DateTime<Utc>> {
        if self.status == Status::Unknown {
            self.request
                .as_ref()
                .map(|r| r.deadline + Duration::days(7))
        } else {
            self.finished_at.map(|at| at + Duration::days(7))
        }
    }

    pub fn outstanding(&self) -> bool {
        self.request.is_some() && !self.stop_confirmed
    }
}

/// Metadata-only audit facts; no argv or runtime/provider error strings are accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, mire::EventData)]
#[serde(tag = "type", rename_all = "snake_case")]
#[mire(entity = "grund-run")]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    Requested {
        request: Request,
    },
    Started {
        at: DateTime<Utc>,
    },
    CancellationRequested {
        at: DateTime<Utc>,
        reason: String,
    },
    Finished {
        status: Status,
        at: DateTime<Utc>,
        exit_code: Option<i32>,
        signal: Option<i32>,
        reason: String,
    },
    ExecutionUncertain {
        at: DateTime<Utc>,
    },
}

impl mire::Aggregate for Run {
    type Event = Event;
    fn stream_category() -> &'static str {
        "grund-run"
    }
    fn apply(&mut self, event: &Event) {
        match event {
            Event::Requested { request } => {
                self.request = Some(request.clone());
                self.status = Status::Pending;
            }
            Event::Started { at } => {
                self.started_at = Some(*at);
                if self.cancel_requested_at.is_none() && self.status != Status::Unknown {
                    self.status = Status::Running;
                }
            }
            Event::CancellationRequested { at, reason } => {
                self.cancel_requested_at = Some(*at);
                self.reason.clone_from(reason);
                if self.status != Status::Unknown {
                    self.status = Status::Cancelling;
                }
            }
            Event::Finished {
                status,
                at,
                exit_code,
                signal,
                reason,
            } => {
                self.status = *status;
                self.finished_at = Some(*at);
                self.exit_code = *exit_code;
                self.signal = *signal;
                self.reason.clone_from(reason);
                self.stop_confirmed = true;
            }
            Event::ExecutionUncertain { at } => {
                self.status = Status::Unknown;
                self.finished_at = Some(*at);
                self.reason = "execution_uncertain".into();
            }
        }
    }
}

/// Commands distinguish verified process exit from a stop request or missed heartbeat.
pub enum Command {
    Request(Box<Request>),
    Cancel {
        at: DateTime<Utc>,
        timed_out: bool,
    },
    Observe {
        machine_id: Uuid,
        attempt_id: Uuid,
        status: Status,
        started_at: Option<DateTime<Utc>>,
        at: DateTime<Utc>,
        exit_code: Option<i32>,
        signal: Option<i32>,
        stop_confirmed: bool,
    },
    Uncertain {
        at: DateTime<Utc>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no such run")]
    NotFound,
    #[error("run attempt is not authorised")]
    StaleAttempt,
    #[error("invalid run observation")]
    InvalidObservation,
}

impl mire::Command for Command {
    type Aggregate = Run;
    type Error = Error;
    type Events = Vec<Event>;
    fn handle(self, run: &Run) -> Result<Vec<Event>, Error> {
        if let Self::Request(request) = self {
            return if run.request.is_none() {
                Ok(vec![Event::Requested { request: *request }])
            } else {
                Ok(vec![])
            };
        }
        let request = run.request.as_ref().ok_or(Error::NotFound)?;
        match self {
            Self::Request(_) => unreachable!(),
            Self::Cancel { at, timed_out } => {
                if run.stop_confirmed || run.cancel_requested_at.is_some() {
                    return Ok(vec![]);
                }
                Ok(vec![Event::CancellationRequested {
                    at,
                    reason: if timed_out {
                        "deadline_exceeded"
                    } else {
                        "cancel_requested"
                    }
                    .into(),
                }])
            }
            Self::Uncertain { at } => {
                if run.stop_confirmed || run.status == Status::Unknown {
                    return Ok(vec![]);
                }
                Ok(vec![Event::ExecutionUncertain { at }])
            }
            Self::Observe {
                machine_id,
                attempt_id,
                status,
                started_at,
                at,
                exit_code,
                signal,
                stop_confirmed,
            } => {
                if machine_id != request.machine_id || attempt_id != request.attempt_id {
                    return Err(Error::StaleAttempt);
                }
                if run.stop_confirmed {
                    return Ok(vec![]);
                }
                if exit_code.is_some_and(|n| !(0..=255).contains(&n))
                    || signal.is_some_and(|n| !(1..=127).contains(&n))
                    || (exit_code.is_some() && signal.is_some())
                {
                    return Err(Error::InvalidObservation);
                }
                if at < request.requested_at {
                    return Err(Error::InvalidObservation);
                }
                let mut events = Vec::new();
                if let Some(started) = started_at.filter(|_| run.started_at.is_none()) {
                    if started < request.requested_at || started > at {
                        return Err(Error::InvalidObservation);
                    }
                    events.push(Event::Started { at: started });
                }
                if status == Status::Unknown {
                    if stop_confirmed {
                        events.push(Event::Finished {
                            status: Status::Unknown,
                            at,
                            exit_code: None,
                            signal: None,
                            reason: "execution_uncertain".into(),
                        });
                    } else if run.status != Status::Unknown {
                        events.push(Event::ExecutionUncertain { at });
                    }
                } else if status.terminal() {
                    if !stop_confirmed {
                        return Err(Error::InvalidObservation);
                    }
                    let (status, reason) = if status == Status::TimedOut {
                        (Status::TimedOut, "deadline_exceeded")
                    } else if status == Status::Cancelled {
                        (Status::Cancelled, "cancel_requested")
                    } else if exit_code.is_some() || signal.is_some() {
                        (
                            if exit_code == Some(0) {
                                Status::Succeeded
                            } else {
                                Status::Failed
                            },
                            "process_exited",
                        )
                    } else if run.reason == "deadline_exceeded" || at >= request.deadline {
                        (Status::TimedOut, "deadline_exceeded")
                    } else if run.cancel_requested_at.is_some() {
                        (Status::Cancelled, "cancel_requested")
                    } else if status == Status::NotStarted {
                        (Status::NotStarted, "not_started")
                    } else {
                        return Err(Error::InvalidObservation);
                    };
                    events.push(Event::Finished {
                        status,
                        at,
                        exit_code,
                        signal,
                        reason: reason.into(),
                    });
                } else if !matches!(
                    status,
                    Status::Pending | Status::Running | Status::Cancelling
                ) {
                    return Err(Error::InvalidObservation);
                }
                Ok(events)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mire::{Aggregate, Command as _};

    fn pending() -> Run {
        let declared =
            grund_config::app::file::parse_app("apps:\n  web:\n    image: nginx:1\n", "web")
                .unwrap();
        let settings = grund_config::app::spec::AppSettings::validate(declared.settings).unwrap();
        let release = crate::app::Release {
            number: 1,
            spec: declared.spec,
            image_digest: "sha256:pinned".into(),
            platforms: vec![],
            exposed_ports: None,
            secret_versions: vec![],
            source: crate::app::ReleaseSource::File,
            note: String::new(),
            created_at: Utc::now(),
            created_by: Uuid::nil(),
            rollback_of: None,
            external_release: None,
            request: None,
        };
        let at = Utc::now();
        let mut run = Run::default();
        run.apply(&Event::Requested {
            request: Request {
                organisation_id: Uuid::now_v7(),
                stack_id: Uuid::now_v7(),
                stack_name: "prod".into(),
                service: "web".into(),
                stack_revision: 1,
                app_id: Uuid::now_v7(),
                app_name: "web".into(),
                release,
                settings,
                machine_id: Uuid::now_v7(),
                requester_id: Uuid::now_v7(),
                attempt_id: Uuid::now_v7(),
                requested_at: at,
                deadline: at + Duration::minutes(10),
            },
        });
        run
    }

    #[test]
    fn uncertainty_keeps_the_fence_and_expires_from_the_original_deadline() {
        let mut run = pending();
        let deadline = run.request.as_ref().unwrap().deadline;
        for event in (Command::Uncertain {
            at: deadline + Duration::days(2),
        })
        .handle(&run)
        .unwrap()
        {
            run.apply(&event);
        }
        assert!(run.outstanding());
        assert_eq!(run.args_expire_at(), Some(deadline + Duration::days(7)));
        assert!(
            (Command::Uncertain { at: deadline })
                .handle(&run)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_verified_exit_wins_over_a_timeout_request() {
        let mut run = pending();
        let request = run.request.clone().unwrap();
        for event in (Command::Cancel {
            at: request.deadline,
            timed_out: true,
        })
        .handle(&run)
        .unwrap()
        {
            run.apply(&event);
        }
        for event in (Command::Observe {
            machine_id: request.machine_id,
            attempt_id: request.attempt_id,
            status: Status::Succeeded,
            started_at: None,
            at: request.deadline,
            exit_code: Some(0),
            signal: None,
            stop_confirmed: true,
        })
        .handle(&run)
        .unwrap()
        {
            run.apply(&event);
        }
        assert_eq!(run.status, Status::Succeeded);
        assert!(!run.outstanding());
        assert!(
            (Command::Cancel {
                at: request.deadline,
                timed_out: true
            })
            .handle(&run)
            .unwrap()
            .is_empty()
        );
    }
    #[test]
    fn cancellation_racing_a_start_keeps_stop_intent_until_absence() {
        let mut run = pending();
        let request = run.request.clone().unwrap();
        for event in (Command::Cancel {
            at: request.requested_at,
            timed_out: false,
        })
        .handle(&run)
        .unwrap()
        {
            run.apply(&event);
        }
        for event in (Command::Observe {
            machine_id: request.machine_id,
            attempt_id: request.attempt_id,
            status: Status::Running,
            started_at: Some(request.requested_at),
            at: request.requested_at,
            exit_code: None,
            signal: None,
            stop_confirmed: false,
        })
        .handle(&run)
        .unwrap()
        {
            run.apply(&event);
        }
        assert_eq!(run.status, Status::Cancelling);
        assert!(run.outstanding());
        assert!(
            (Command::Cancel {
                at: request.deadline,
                timed_out: false
            })
            .handle(&run)
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn wrong_machine_or_attempt_cannot_change_a_run() {
        let run = pending();
        let request = run.request.as_ref().unwrap();
        for (machine_id, attempt_id) in [
            (Uuid::now_v7(), request.attempt_id),
            (request.machine_id, Uuid::now_v7()),
        ] {
            assert!(matches!(
                (Command::Observe {
                    machine_id,
                    attempt_id,
                    status: Status::Succeeded,
                    started_at: None,
                    at: request.deadline,
                    exit_code: Some(0),
                    signal: None,
                    stop_confirmed: true
                })
                .handle(&run),
                Err(Error::StaleAttempt)
            ));
        }
    }

    #[test]
    fn confirmed_timeout_retains_exit_evidence_and_cannot_be_overwritten() {
        let mut run = pending();
        let request = run.request.clone().unwrap();
        for event in (Command::Observe {
            machine_id: request.machine_id,
            attempt_id: request.attempt_id,
            status: Status::TimedOut,
            started_at: None,
            at: request.deadline,
            exit_code: Some(143),
            signal: None,
            stop_confirmed: true,
        })
        .handle(&run)
        .unwrap()
        {
            run.apply(&event);
        }
        assert_eq!(run.status, Status::TimedOut);
        assert_eq!(run.exit_code, Some(143));
        assert!(
            (Command::Observe {
                machine_id: request.machine_id,
                attempt_id: request.attempt_id,
                status: Status::Succeeded,
                started_at: None,
                at: request.deadline,
                exit_code: Some(0),
                signal: None,
                stop_confirmed: true
            })
            .handle(&run)
            .unwrap()
            .is_empty()
        );
    }
}
