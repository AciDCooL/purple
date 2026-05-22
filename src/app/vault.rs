use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// Vault SSH certificate and signing state.
pub struct VaultState {
    /// Cached vault certificate status per host alias.
    /// Tuple: (check timestamp, status, cert file mtime at check time).
    pub cert_cache: HashMap<
        String,
        (
            std::time::Instant,
            crate::vault_ssh::CertStatus,
            Option<std::time::SystemTime>,
        ),
    >,
    /// Aliases currently being checked for cert status (prevent duplicate checks).
    pub cert_checks_in_flight: HashSet<String>,
    /// Side-channel warning from cert-cache cleanup.
    pub cleanup_warning: Option<String>,
    /// Cancel flag for the V-key vault signing background thread.
    pub signing_cancel: Option<Arc<AtomicBool>>,
    /// JoinHandle for the V-key vault signing background thread.
    pub sign_thread: Option<std::thread::JoinHandle<()>>,
    /// Aliases currently being signed by the bulk V-key loop.
    pub sign_in_flight: Arc<Mutex<HashSet<String>>>,
    /// Deferred config write from VaultSignAllDone (guarded while forms are open).
    pub pending_config_write: bool,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            cert_cache: HashMap::new(),
            cert_checks_in_flight: HashSet::new(),
            cleanup_warning: None,
            signing_cancel: None,
            sign_thread: None,
            sign_in_flight: Arc::new(Mutex::new(HashSet::new())),
            pending_config_write: false,
        }
    }
}

impl VaultState {
    /// Reserve an alias against duplicate cert-status checks while a
    /// background thread runs. Paired with `record_cert_check` on the
    /// result event.
    pub(crate) fn mark_cert_check_started(&mut self, alias: String) {
        self.cert_checks_in_flight.insert(alias);
    }

    /// Land a finished cert-status check. Clears the in-flight reservation
    /// and writes the result to `cert_cache` in one step so the two fields
    /// cannot drift (a missed remove would dedupe the next lazy check
    /// forever; a missed insert would re-spawn it every tick).
    pub(crate) fn record_cert_check(
        &mut self,
        alias: String,
        status: crate::vault_ssh::CertStatus,
        mtime: Option<std::time::SystemTime>,
    ) {
        self.cert_checks_in_flight.remove(&alias);
        self.cert_cache
            .insert(alias, (std::time::Instant::now(), status, mtime));
    }

    /// Tear down a bulk-sign run that may still be running. Signals
    /// cancel to the worker, clears the cancel handle, and returns the
    /// thread for joining. Use at App::Drop and tui_loop teardown where
    /// the worker is asked to stop.
    pub(crate) fn cancel_signing_run(&mut self) -> Option<std::thread::JoinHandle<()>> {
        if let Some(ref cancel) = self.signing_cancel {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.signing_cancel = None;
        self.sign_thread.take()
    }

    /// Clean up after a bulk-sign worker exited or never started.
    /// Does NOT signal cancel: the worker is already gone, and the
    /// cancel handle in the field may belong to a newer user-started
    /// run that raced into existence during the dispatch window
    /// between worker exit and event processing. Use at the
    /// VaultSignAllDone handler and the spawn-failed path.
    pub(crate) fn finalize_signing_run(&mut self) -> Option<std::thread::JoinHandle<()>> {
        self.signing_cancel = None;
        self.sign_thread.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn mark_cert_check_started_inserts_alias() {
        let mut v = VaultState::default();
        v.mark_cert_check_started("web".to_string());
        assert!(v.cert_checks_in_flight.contains("web"));
    }

    #[test]
    fn mark_cert_check_started_is_idempotent() {
        // HashSet semantics; a second call must not panic and the set
        // still contains the alias exactly once.
        let mut v = VaultState::default();
        v.mark_cert_check_started("web".to_string());
        v.mark_cert_check_started("web".to_string());
        assert_eq!(v.cert_checks_in_flight.len(), 1);
        assert!(v.cert_checks_in_flight.contains("web"));
    }

    #[test]
    fn record_cert_check_clears_in_flight_and_writes_cache() {
        let mut v = VaultState::default();
        v.mark_cert_check_started("web".to_string());
        v.record_cert_check(
            "web".to_string(),
            crate::vault_ssh::CertStatus::Missing,
            None,
        );
        assert!(!v.cert_checks_in_flight.contains("web"));
        assert!(v.cert_cache.contains_key("web"));
        let (_, status, mtime) = v.cert_cache.get("web").unwrap();
        assert!(matches!(status, crate::vault_ssh::CertStatus::Missing));
        assert!(mtime.is_none());
    }

    #[test]
    fn record_cert_check_caches_even_without_prior_start() {
        // Defensive: if a result event somehow lands without a matching
        // start (e.g. spawned before App::new but result arrives after),
        // the cache must still be updated and the in-flight set
        // unaffected.
        let mut v = VaultState::default();
        v.record_cert_check(
            "web".to_string(),
            crate::vault_ssh::CertStatus::Invalid("nope".to_string()),
            None,
        );
        assert!(v.cert_cache.contains_key("web"));
        assert!(v.cert_checks_in_flight.is_empty());
    }

    #[test]
    fn cancel_signing_run_with_no_active_run_returns_none() {
        let mut v = VaultState::default();
        let handle = v.cancel_signing_run();
        assert!(handle.is_none());
        assert!(v.signing_cancel.is_none());
        assert!(v.sign_thread.is_none());
    }

    #[test]
    fn cancel_signing_run_signals_cancel_and_clears_handle() {
        // A real (short-lived) thread plus an Arc<AtomicBool> exercises
        // both halves: cancel_signing_run must set the flag to true (so
        // a long-running worker would exit) and detach the cancel handle.
        let mut v = VaultState::default();
        let cancel = Arc::new(AtomicBool::new(false));
        v.signing_cancel = Some(cancel.clone());
        v.sign_thread = Some(std::thread::spawn(|| {}));

        let handle = v
            .cancel_signing_run()
            .expect("returned thread handle for joining");
        let _ = handle.join();

        assert!(
            cancel.load(Ordering::Relaxed),
            "cancel must be signalled so a long-running worker exits"
        );
        assert!(v.signing_cancel.is_none());
        assert!(v.sign_thread.is_none());
    }

    #[test]
    fn finalize_signing_run_does_not_signal_cancel() {
        // After VaultSignAllDone arrives, the worker has already exited.
        // signing_cancel may belong to a *newer* user-started run that
        // raced in. finalize must NOT touch the cancel flag, only clear
        // the field and take the thread (which is the just-finished
        // worker's handle, ready for join).
        let mut v = VaultState::default();
        let cancel = Arc::new(AtomicBool::new(false));
        v.signing_cancel = Some(cancel.clone());
        v.sign_thread = Some(std::thread::spawn(|| {}));

        let handle = v
            .finalize_signing_run()
            .expect("returned thread handle for joining");
        let _ = handle.join();

        assert!(
            !cancel.load(Ordering::Relaxed),
            "finalize must not signal cancel: a racing newer run's Arc could be hit"
        );
        assert!(v.signing_cancel.is_none());
        assert!(v.sign_thread.is_none());
    }

    #[test]
    fn finalize_signing_run_with_cancel_but_no_thread_clears_cancel() {
        // Spawn-failure path: signing_cancel was set in `confirm.rs`
        // before the thread builder ran, the spawn failed, sign_thread
        // is still None. finalize_signing_run clears the orphaned cancel
        // without signalling (the spawned closure was dropped, no other
        // observer of the Arc exists).
        let mut v = VaultState::default();
        let cancel = Arc::new(AtomicBool::new(false));
        v.signing_cancel = Some(cancel.clone());

        let handle = v.finalize_signing_run();
        assert!(handle.is_none());
        assert!(v.signing_cancel.is_none());
        assert!(!cancel.load(Ordering::Relaxed));
    }
}
