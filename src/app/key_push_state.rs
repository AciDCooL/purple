//! Key-push state. Tracks the picker selection set, in-flight worker
//! handles and accumulated results between Screen transitions.
//!
//! Lives on `App` so the event loop can land per-host `KeyPushResult`
//! events into `results` regardless of which Screen is active (the user
//! may switch tabs while a push is running).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use ratatui::widgets::ListState;

use crate::key_push::KeyPushResult;
use std::collections::HashSet;

/// Push state owned by `App`. Empty between push runs.
#[derive(Default)]
pub struct KeyPushState {
    /// Aliases the user has selected in the picker. Modified by Space
    /// during `Screen::KeyPushPicker` and frozen into `committed` on Enter.
    pub selected: HashSet<String>,
    /// Snapshot of `selected` (in picker order) taken when the user
    /// presses Enter to open `Screen::ConfirmKeyPush`. Read by the
    /// confirm renderer and by `start_key_push`. Cleared on cancel or
    /// after the worker spawns. Keeps `Screen::ConfirmKeyPush` payload
    /// small.
    pub committed: Vec<String>,
    /// Cursor in the picker's host list. Indexes into the picker's
    /// visible host slice.
    pub list_state: ListState,
    /// Results accumulated as `AppEvent::KeyPushResult` lands. Drained
    /// when the run completes and the summary toast / sticky error is
    /// rendered.
    pub results: Vec<KeyPushResult>,
    /// Total hosts the current run is targeting. Used to know when the
    /// run is "done" so the summary can fire exactly once.
    pub expected_count: usize,
    /// Cancel flag observed by every worker thread. Set on push-cancel,
    /// new push run, or App drop.
    pub cancel: Option<Arc<AtomicBool>>,
    /// JoinHandle for the worker pool. Joined on App drop.
    pub worker: Option<std::thread::JoinHandle<()>>,
    /// Monotonic run identifier. Bumped at the start of every push so
    /// stale `KeyPushResult` events from a previously-cancelled run can
    /// be dropped instead of contaminating the next run's accumulator.
    pub run_id: u64,
}

impl KeyPushState {
    /// Drop the worker handle gracefully. Called from `App::drop` so a
    /// panicking unwind cannot leave the push thread running with a
    /// dangling sender.
    pub fn shutdown(&mut self) {
        if let Some(ref cancel) = self.cancel {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }

    /// Reset picker-only state without touching in-flight worker. Called
    /// before opening the picker for a new key so the previous run's
    /// selection set does not bleed in.
    pub fn reset_picker(&mut self) {
        self.selected.clear();
        self.list_state.select(Some(0));
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn default_is_empty() {
        let s = KeyPushState::default();
        assert!(s.selected.is_empty());
        assert_eq!(s.list_state.selected(), None);
        assert!(s.results.is_empty());
        assert_eq!(s.expected_count, 0);
        assert!(s.cancel.is_none());
        assert!(s.worker.is_none());
    }

    #[test]
    fn reset_picker_clears_selection_and_resets_cursor() {
        let mut s = KeyPushState::default();
        s.selected.insert("host-a".to_string());
        s.selected.insert("host-b".to_string());
        s.list_state.select(Some(5));
        s.reset_picker();
        assert!(s.selected.is_empty());
        assert_eq!(s.list_state.selected(), Some(0));
    }

    #[test]
    fn reset_picker_leaves_inflight_state_alone() {
        // shutdown is the path that touches worker/cancel; reset_picker
        // is the picker-open path and must not interfere with a run that
        // is still finalising.
        let mut s = KeyPushState::default();
        s.cancel = Some(Arc::new(AtomicBool::new(false)));
        s.expected_count = 5;
        s.results.push(crate::key_push::KeyPushResult {
            alias: "h".into(),
            outcome: crate::key_push::KeyPushOutcome::Appended,
        });
        s.reset_picker();
        assert!(s.cancel.is_some());
        assert_eq!(s.expected_count, 5);
        assert_eq!(s.results.len(), 1);
    }

    #[test]
    fn shutdown_sets_cancel_flag() {
        let mut s = KeyPushState::default();
        let flag = Arc::new(AtomicBool::new(false));
        s.cancel = Some(flag.clone());
        s.shutdown();
        assert!(flag.load(Ordering::Relaxed));
    }

    #[test]
    fn shutdown_joins_worker_and_takes_handle() {
        let mut s = KeyPushState::default();
        let flag = Arc::new(AtomicBool::new(false));
        let cancel = flag.clone();
        // A trivial worker that observes the cancel flag and exits.
        let handle = std::thread::spawn(move || {
            while !cancel.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        });
        s.cancel = Some(flag);
        s.worker = Some(handle);
        s.shutdown();
        assert!(s.worker.is_none(), "worker handle should be taken");
    }

    #[test]
    fn shutdown_is_idempotent_with_no_worker() {
        let mut s = KeyPushState::default();
        // Should not panic when called on an empty state.
        s.shutdown();
        s.shutdown();
    }
}
