//! Keeps a database-bound worker running through a database outage.
//!
//! mire's projection runner and mire-sagas' worker return an error when
//! PostgreSQL drops their connections (a failover, a restart, a recreated
//! cluster). Returned to notmad, that error stops every component and the
//! process exits, so a database blip became a crash loop: the outage plus
//! the orchestrator's restart back-off. Liveness already promises that no
//! dependency outage is fixed by restarting grund (`health::live`); this is
//! the same promise for the workers. Each is built afresh and started again
//! after a back-off, while the HTTP server keeps answering and readiness
//! reports PostgreSQL as down.

use std::{
    future::Future,
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;

/// The first wait after a worker fails.
pub const FIRST_WAIT: Duration = Duration::from_secs(1);

/// The longest wait between starts, so a database that comes back is used
/// within this long.
pub const LONGEST_WAIT: Duration = Duration::from_secs(30);

/// A run at least this long counts as healthy: the next failure waits
/// [`FIRST_WAIT`] again rather than continuing the back-off.
pub const HEALTHY_RUN: Duration = Duration::from_secs(60);

/// How long to wait after the `failures`-th failure in a row (0 for the
/// first): doubling from [`FIRST_WAIT`], stretched by up to half again as
/// jitter (`unit` in [0, 1)), at most [`LONGEST_WAIT`].
pub fn wait_after(failures: u32, unit: f64) -> Duration {
    crate::acme::backoff(failures, FIRST_WAIT, None, unit).min(LONGEST_WAIT)
}

/// Runs the worker that `start` builds until `cancellation` fires. A worker
/// that fails is logged and started again after [`wait_after`]; one that
/// returns `Ok` without being cancelled has finished its work, and so does
/// this.
pub async fn until_cancelled<F, Fut>(
    name: &'static str,
    cancellation: CancellationToken,
    mut start: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let mut failures = 0u32;
    loop {
        let started = Instant::now();
        let error = match start().await {
            Ok(()) => return Ok(()),
            Err(error) if cancellation.is_cancelled() => return Err(error),
            Err(error) => error,
        };
        if started.elapsed() >= HEALTHY_RUN {
            failures = 0;
        }
        let wait = wait_after(failures, crate::acme::unit_random());
        failures = failures.saturating_add(1);
        tracing::warn!(
            worker = name,
            error = format!("{error:#}"),
            failures,
            wait_ms = wait.as_millis() as u64,
            "worker stopped with an error; starting it again"
        );
        tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            () = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    use super::*;

    #[test]
    fn the_wait_doubles_from_one_second_and_stops_at_thirty() {
        assert_eq!(wait_after(0, 0.0), FIRST_WAIT);
        assert_eq!(wait_after(1, 0.0), Duration::from_secs(2));
        assert_eq!(wait_after(3, 0.0), Duration::from_secs(8));
        assert_eq!(wait_after(0, 0.99), Duration::from_millis(1495));
        assert_eq!(wait_after(5, 0.0), LONGEST_WAIT);
        assert_eq!(wait_after(40, 0.99), LONGEST_WAIT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_worker_is_started_again_until_it_finishes() {
        let starts = Arc::new(AtomicU32::new(0));
        let counted = starts.clone();
        let result = until_cancelled("test", CancellationToken::new(), move || {
            let n = counted.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 3 {
                    anyhow::bail!("terminating connection due to administrator command")
                }
                Ok(())
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(starts.load(Ordering::SeqCst), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_during_the_wait_stops_without_another_start() {
        let starts = Arc::new(AtomicU32::new(0));
        let counted = starts.clone();
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        let run = tokio::spawn(until_cancelled("test", cancellation, move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { anyhow::bail!("the database is away") }
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        assert!(run.await.unwrap().is_ok());
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }
}
