//! In-process wake-ups for the long polls of the control link
//! (grund-docs design/apps.md §6.1): a machine's document changed, so its
//! WatchDesiredState answers now rather than at its next poll of the
//! database. A wake is a hint and carries nothing: every waiter reads the
//! database again, and also polls it, so a wake lost to another replica of
//! `grund serve` costs at most a second.

use std::{sync::Arc, time::Duration};

use tokio::sync::watch;

/// The most a waiter goes without reading the database again.
pub const POLL: Duration = Duration::from_secs(1);

/// Cheap to clone; every clone shares one counter.
#[derive(Clone)]
pub struct Wakes {
    documents: Arc<watch::Sender<u64>>,
    apps: Arc<tokio::sync::Notify>,
}

impl Default for Wakes {
    fn default() -> Self {
        Self {
            documents: Arc::new(watch::channel(0).0),
            apps: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

impl Wakes {
    /// Some machine's document changed: wake every waiter.
    pub fn documents_changed(&self) {
        self.documents.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Something an app's reconciler decides on changed (a release, a
    /// setting, a report): wake it. Wakes sent while it is busy collapse
    /// into one.
    pub fn apps_changed(&self) {
        self.apps.notify_one();
    }

    /// What the app reconciler waits on.
    pub fn apps(&self) -> Arc<tokio::sync::Notify> {
        self.apps.clone()
    }

    /// A receiver to wait on with [`Wakes::wait`], taken before reading the
    /// database so a change between the read and the wait is not missed.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.documents.subscribe()
    }

    /// Waits for the next wake, or [`POLL`], whichever is first.
    pub async fn wait(receiver: &mut watch::Receiver<u64>) {
        let _ = tokio::time::timeout(POLL, receiver.changed()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_wake_before_the_wait_is_not_missed() {
        let wakes = Wakes::default();
        let mut receiver = wakes.subscribe();
        wakes.documents_changed();
        let started = tokio::time::Instant::now();
        Wakes::wait(&mut receiver).await;
        assert!(started.elapsed() < POLL / 2);
    }
}
