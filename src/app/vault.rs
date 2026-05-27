use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// Vault SSH certificate and signing state.
pub struct VaultState {
    /// Cached vault certificate status per host alias.
    /// Tuple: (check timestamp, status, cert file mtime at check time).
    pub(in crate::app) cert_cache: HashMap<
        String,
        (
            std::time::Instant,
            crate::vault_ssh::CertStatus,
            Option<std::time::SystemTime>,
        ),
    >,
    /// Aliases currently being checked for cert status (prevent duplicate checks).
    pub(in crate::app) cert_checks_in_flight: HashSet<String>,
    /// When the cert file was last `stat()`-ed per alias. Lets the per-frame
    /// freshness probe throttle its syscall while still detecting external
    /// writes within the throttle window.
    pub(in crate::app) cert_stat_throttle: HashMap<String, std::time::Instant>,
    /// Side-channel warning from cert-cache cleanup.
    pub(in crate::app) cleanup_warning: Option<String>,
    /// Cancel flag for the V-key vault signing background thread.
    pub(in crate::app) signing_cancel: Option<Arc<AtomicBool>>,
    /// JoinHandle for the V-key vault signing background thread.
    pub(in crate::app) sign_thread: Option<std::thread::JoinHandle<()>>,
    /// Aliases currently being signed by the bulk V-key loop.
    pub(in crate::app) sign_in_flight: Arc<Mutex<HashSet<String>>>,
    /// Deferred config write from VaultSignAllDone (guarded while forms are open).
    pub(in crate::app) pending_config_write: bool,
    /// Payload of an open `Screen::ConfirmVaultSign` dialog. The Screen
    /// variant is data-less; the precomputed signable list lives here
    /// so the dialog transitions never clone the `VaultSignTarget` vec.
    pub(in crate::app) pending_sign: Option<Vec<crate::vault_ssh::VaultSignTarget>>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            cert_cache: HashMap::new(),
            cert_checks_in_flight: HashSet::new(),
            cert_stat_throttle: HashMap::new(),
            cleanup_warning: None,
            signing_cancel: None,
            sign_thread: None,
            sign_in_flight: Arc::new(Mutex::new(HashSet::new())),
            pending_config_write: false,
            pending_sign: None,
        }
    }
}

type CertCacheEntry = (
    std::time::Instant,
    crate::vault_ssh::CertStatus,
    Option<std::time::SystemTime>,
);

impl VaultState {
    pub fn cert_cache(&self) -> &HashMap<String, CertCacheEntry> {
        &self.cert_cache
    }

    pub fn cert_entry(&self, alias: &str) -> Option<&CertCacheEntry> {
        self.cert_cache.get(alias)
    }

    pub fn has_cert(&self, alias: &str) -> bool {
        self.cert_cache.contains_key(alias)
    }

    pub fn insert_cert(&mut self, alias: String, entry: CertCacheEntry) {
        self.cert_cache.insert(alias, entry);
    }

    pub fn remove_cert(&mut self, alias: &str) {
        self.cert_cache.remove(alias);
    }

    pub fn clear_cert_cache(&mut self) {
        self.cert_cache.clear();
    }

    pub fn is_cert_check_in_flight(&self, alias: &str) -> bool {
        self.cert_checks_in_flight.contains(alias)
    }

    pub fn take_cleanup_warning(&mut self) -> Option<String> {
        self.cleanup_warning.take()
    }

    pub fn signing_cancel(&self) -> Option<&Arc<AtomicBool>> {
        self.signing_cancel.as_ref()
    }

    pub fn is_signing(&self) -> bool {
        self.signing_cancel.is_some()
    }

    pub fn set_signing_cancel(&mut self, cancel: Arc<AtomicBool>) {
        self.signing_cancel = Some(cancel);
    }

    pub fn clear_signing_cancel(&mut self) {
        self.signing_cancel = None;
    }

    pub fn set_sign_thread(&mut self, handle: std::thread::JoinHandle<()>) {
        self.sign_thread = Some(handle);
    }

    pub fn sign_in_flight(&self) -> &Arc<Mutex<HashSet<String>>> {
        &self.sign_in_flight
    }

    pub fn pending_config_write(&self) -> bool {
        self.pending_config_write
    }

    pub fn set_pending_config_write(&mut self, value: bool) {
        self.pending_config_write = value;
    }

    /// Reserve an alias against duplicate cert-status checks while a
    /// background thread runs. Paired with `record_cert_check` on the
    /// result event.
    pub(crate) fn mark_cert_check_started(&mut self, alias: String) {
        self.cert_checks_in_flight.insert(alias);
    }

    /// Last time the per-frame freshness probe stat-ed this alias.
    pub(crate) fn last_cert_stat(&self, alias: &str) -> Option<std::time::Instant> {
        self.cert_stat_throttle.get(alias).copied()
    }

    /// Read the precomputed signable list for an open
    /// `Screen::ConfirmVaultSign` dialog. `None` when no dialog is
    /// open.
    pub fn pending_sign(&self) -> Option<&[crate::vault_ssh::VaultSignTarget]> {
        self.pending_sign.as_deref()
    }

    /// Install a fresh signable list. Caller transitions the screen.
    pub fn set_pending_sign(&mut self, signable: Vec<crate::vault_ssh::VaultSignTarget>) {
        self.pending_sign = Some(signable);
    }

    /// Drop the signable list, returning it for use by the confirm-yes
    /// handler.
    pub fn take_pending_sign(&mut self) -> Option<Vec<crate::vault_ssh::VaultSignTarget>> {
        self.pending_sign.take()
    }

    /// Record that the per-frame freshness probe just stat-ed this alias.
    pub(crate) fn note_cert_stat(&mut self, alias: String, when: std::time::Instant) {
        self.cert_stat_throttle.insert(alias, when);
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

    /// Drop cert-cache, in-flight check, and bulk-sign in-flight entries
    /// whose alias is no longer in `valid_aliases`. Called from
    /// `App::reload_hosts` after the new host list lands. Recovers from a
    /// poisoned `sign_in_flight` mutex by reading the inner set: a
    /// poisoned worker still owns live aliases that must not be wiped.
    pub fn prune_orphans(&mut self, valid_aliases: &HashSet<&str>) {
        let pre_cert = self.cert_cache.len();
        let pre_checks = self.cert_checks_in_flight.len();
        self.cert_cache
            .retain(|alias, _| valid_aliases.contains(alias.as_str()));
        self.cert_checks_in_flight
            .retain(|alias| valid_aliases.contains(alias.as_str()));
        self.cert_stat_throttle
            .retain(|alias, _| valid_aliases.contains(alias.as_str()));
        let dropped_cert = pre_cert.saturating_sub(self.cert_cache.len());
        if dropped_cert > 0 {
            log::debug!(
                "[purple] reload_hosts: dropped {dropped_cert} orphan cert_cache entrie(s)"
            );
        }
        let dropped_checks = pre_checks.saturating_sub(self.cert_checks_in_flight.len());
        if dropped_checks > 0 {
            log::debug!(
                "[purple] reload_hosts: dropped {dropped_checks} orphan cert_checks_in_flight alias(es)"
            );
        }

        let mut sign = match self.sign_in_flight.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let pre = sign.len();
        sign.retain(|alias| valid_aliases.contains(alias.as_str()));
        let dropped = pre.saturating_sub(sign.len());
        if dropped > 0 {
            log::debug!("[purple] reload_hosts: dropped {dropped} orphan sign_in_flight alias(es)");
        }

        // Open bulk-sign confirm payload: drop targets whose host was
        // removed. The next yes path then never tries to sign a cert
        // for a deleted alias. When every target is gone, drop the
        // whole list so the confirm handler can detect the empty state
        // and return to HostList.
        if let Some(list) = self.pending_sign.as_mut() {
            let pre = list.len();
            list.retain(|t| valid_aliases.contains(t.alias.as_str()));
            let dropped = pre.saturating_sub(list.len());
            if dropped > 0 {
                log::debug!(
                    "[purple] reload_hosts: dropped {dropped} orphan pending_sign target(s)"
                );
            }
            if list.is_empty() {
                self.pending_sign = None;
            }
        }
    }

    /// Move `cert_checks_in_flight` and `sign_in_flight` entries from
    /// `old` to `new`. `cert_cache` is excluded by design: a host
    /// rename invalidates the prior cert path, so the caller is
    /// expected to refresh the cache rather than migrate the entry.
    /// Recovers from a poisoned `sign_in_flight` mutex. No-op when
    /// `old == new`.
    pub fn migrate_alias(&mut self, old: &str, new: &str) {
        if old == new {
            return;
        }
        if self.cert_checks_in_flight.remove(old) {
            self.cert_checks_in_flight.insert(new.to_string());
        }
        if let Some(when) = self.cert_stat_throttle.remove(old) {
            self.cert_stat_throttle.insert(new.to_string(), when);
        }
        // Open bulk-sign confirm payload: rename any target that still
        // points at the old alias. Without this, the worker would sign
        // and write the cert under the stale path after the rename.
        if let Some(list) = self.pending_sign.as_mut() {
            for target in list.iter_mut() {
                if target.alias == old {
                    target.alias = new.to_string();
                }
            }
        }
        let mut sign = match self.sign_in_flight.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if sign.remove(old) {
            sign.insert(new.to_string());
        }
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

    #[test]
    fn prune_orphans_drops_unknown_aliases_across_cert_and_sign_state() {
        let mut v = VaultState::default();
        v.cert_cache.insert(
            "keep".to_string(),
            (
                std::time::Instant::now(),
                crate::vault_ssh::CertStatus::Missing,
                None,
            ),
        );
        v.cert_cache.insert(
            "drop".to_string(),
            (
                std::time::Instant::now(),
                crate::vault_ssh::CertStatus::Missing,
                None,
            ),
        );
        v.cert_checks_in_flight.insert("keep".to_string());
        v.cert_checks_in_flight.insert("drop".to_string());
        v.sign_in_flight.lock().unwrap().insert("keep".to_string());
        v.sign_in_flight.lock().unwrap().insert("drop".to_string());

        let valid: HashSet<&str> = ["keep"].into_iter().collect();
        v.prune_orphans(&valid);

        assert!(v.cert_cache.contains_key("keep"));
        assert!(!v.cert_cache.contains_key("drop"));
        assert!(v.cert_checks_in_flight.contains("keep"));
        assert!(!v.cert_checks_in_flight.contains("drop"));
        let sign = v.sign_in_flight.lock().unwrap();
        assert!(sign.contains("keep"));
        assert!(!sign.contains("drop"));
    }

    #[test]
    fn migrate_alias_moves_checks_and_sign_but_not_cert_cache() {
        let mut v = VaultState::default();
        v.cert_cache.insert(
            "old".to_string(),
            (
                std::time::Instant::now(),
                crate::vault_ssh::CertStatus::Missing,
                None,
            ),
        );
        v.cert_checks_in_flight.insert("old".to_string());
        v.sign_in_flight.lock().unwrap().insert("old".to_string());

        v.migrate_alias("old", "new");

        // cert_cache is intentionally left untouched: rename invalidates
        // the cert path so the caller refreshes rather than migrating.
        assert!(v.cert_cache.contains_key("old"));
        assert!(!v.cert_cache.contains_key("new"));

        assert!(!v.cert_checks_in_flight.contains("old"));
        assert!(v.cert_checks_in_flight.contains("new"));

        let sign = v.sign_in_flight.lock().unwrap();
        assert!(!sign.contains("old"));
        assert!(sign.contains("new"));
    }

    #[test]
    fn note_cert_stat_records_and_last_returns_it() {
        let mut v = VaultState::default();
        assert!(v.last_cert_stat("web").is_none());
        let when = std::time::Instant::now();
        v.note_cert_stat("web".to_string(), when);
        assert_eq!(v.last_cert_stat("web"), Some(when));
    }

    #[test]
    fn note_cert_stat_overwrites_prior_entry() {
        let mut v = VaultState::default();
        let earlier = std::time::Instant::now();
        v.note_cert_stat("web".to_string(), earlier);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let later = std::time::Instant::now();
        v.note_cert_stat("web".to_string(), later);
        assert_eq!(v.last_cert_stat("web"), Some(later));
    }

    #[test]
    fn prune_orphans_drops_stale_throttle_entries() {
        let mut v = VaultState::default();
        v.note_cert_stat("keep".to_string(), std::time::Instant::now());
        v.note_cert_stat("drop".to_string(), std::time::Instant::now());

        let valid: HashSet<&str> = ["keep"].into_iter().collect();
        v.prune_orphans(&valid);

        assert!(v.last_cert_stat("keep").is_some());
        assert!(v.last_cert_stat("drop").is_none());
    }

    #[test]
    fn migrate_alias_moves_throttle_entry() {
        let mut v = VaultState::default();
        let when = std::time::Instant::now();
        v.note_cert_stat("old".to_string(), when);

        v.migrate_alias("old", "new");

        assert!(v.last_cert_stat("old").is_none());
        assert_eq!(v.last_cert_stat("new"), Some(when));
    }
}
