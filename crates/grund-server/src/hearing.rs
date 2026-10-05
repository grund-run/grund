//! Since when this instance has been able to hear its machines.
//!
//! A machine is out of traffic 30 s after its last heartbeat, and its
//! stateless replicas are replaced after `reschedule_after` (grund-docs
//! design/apps.md §9.2). Both clocks used to run from the heartbeat alone, so
//! when the instance itself was away (stopped, restarting, or without
//! PostgreSQL to record heartbeats in), every machine looked silent the moment
//! it came back: the route table dropped them and the reconciler stopped
//! healthy replicas on every machine to start them again. The silence was the
//! instance's, not the machines' (apps.md §9.5: an instance outage is not an
//! app outage).
//!
//! So a machine's silence is counted from its last heartbeat or from when
//! this instance started hearing, whichever is later: the process start, and
//! the first database call that succeeds after one failed. A machine that is
//! really gone is then noticed up to 30 s (and replaced up to
//! `reschedule_after`) after the instance's return rather than at once, and a
//! spurious failed call delays noticing by the same at most. Each replica of
//! the instance keeps its own watermark; the others' heartbeats are in the
//! shared database either way.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use chrono::{DateTime, Utc};

/// The watermark, shared by everything in one process.
#[derive(Debug)]
pub struct Hearing {
    since_ms: AtomicI64,
    deaf: AtomicBool,
}

impl Hearing {
    /// Hearing from `now`: the process start.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            since_ms: AtomicI64::new(now.timestamp_millis()),
            deaf: AtomicBool::new(false),
        }
    }

    /// Since when the instance has been hearing its machines.
    pub fn since(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.since_ms.load(Ordering::Acquire)).unwrap_or_default()
    }

    /// A database call failed: heartbeats may not be recorded until one
    /// succeeds.
    pub fn failed(&self) {
        self.deaf.store(true, Ordering::Release);
    }

    /// A database call succeeded at `now`: after a failure, machines' silence
    /// is counted from here.
    pub fn succeeded(&self, now: DateTime<Utc>) {
        if self.deaf.swap(false, Ordering::AcqRel) {
            self.since_ms
                .fetch_max(now.timestamp_millis(), Ordering::AcqRel);
            tracing::info!(
                since = %now,
                "the database answers again; machines' silence is counted from now"
            );
        }
    }

    /// Records a database call's outcome, as [`Hearing::failed`] or
    /// [`Hearing::succeeded`].
    pub fn observe<T, E>(&self, result: &Result<T, E>) {
        match result {
            Ok(_) => self.succeeded(Utc::now()),
            Err(_) => self.failed(),
        }
    }

    /// When a machine last seen at `last_seen` counts as last seen: never
    /// earlier than [`Hearing::since`]. A machine never seen stays unseen.
    pub fn seen(&self, last_seen: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
        last_seen.map(|seen| seen.max(self.since()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    #[test]
    fn silence_from_before_the_instance_started_hearing_does_not_count() {
        let hearing = Hearing::new(at(100));
        assert_eq!(hearing.seen(Some(at(0))), Some(at(100)));
        assert_eq!(hearing.seen(Some(at(150))), Some(at(150)));
        assert_eq!(hearing.seen(None), None);
    }

    #[test]
    fn the_first_success_after_a_failure_moves_the_watermark_and_later_ones_do_not() {
        let hearing = Hearing::new(at(0));
        hearing.succeeded(at(50));
        assert_eq!(hearing.since(), at(0));
        hearing.failed();
        hearing.failed();
        hearing.succeeded(at(300));
        assert_eq!(hearing.since(), at(300));
        hearing.succeeded(at(400));
        assert_eq!(hearing.since(), at(300));
        assert_eq!(hearing.seen(Some(at(10))), Some(at(300)));
    }
}
