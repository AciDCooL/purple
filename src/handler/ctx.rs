//! Shared handler-context infrastructure.
//!
//! Handlers operate on a narrow per-domain slice of `App` instead of taking
//! `&mut App`, so the compiler rejects any reach into unrelated state (vault,
//! containers, providers, ...). Whole-App operations that cannot run on a slice
//! (reload, sort, cross-cutting form helpers) are queued as deferred effects
//! and applied to the full `App` after the handler returns.
//!
//! The capability traits below let a slice opt in to only the helpers it needs
//! (a picker that just navigates implements `Nav`; a form that also writes and
//! reloads implements `Notify` and `Effectful` too) without forcing every
//! slice to carry a status center or an effect queue it never uses. Each helper
//! mirrors the equivalent `App` method exactly so a migrated handler keeps
//! identical behaviour.

use crate::app::{App, MessageClass, Screen, StatusCenter, StatusMessage};

/// A single deferred whole-App operation.
type Effect = Box<dyn FnOnce(&mut App)>;

/// A queue of whole-App effects collected during key handling and applied in
/// order once the handler's slice borrow has ended. Each effect is a closure
/// over `&mut App`, so a domain can defer any App operation (including its own)
/// without growing a shared enum.
#[derive(Default)]
pub(super) struct Effects {
    queue: Vec<Effect>,
}

impl Effects {
    /// Queue a whole-App operation to run after the handler returns.
    pub(super) fn defer(&mut self, effect: impl FnOnce(&mut App) + 'static) {
        self.queue.push(Box::new(effect));
    }

    /// Apply every queued effect to the full App, in push order.
    ///
    /// Deferred effects run AFTER all inline slice work, including inline
    /// `notify*` calls. So a handler that sets an inline success toast and then
    /// defers an op that can itself notify on failure (notably `reload_hosts`,
    /// which surfaces a vault-flush conflict via `notify_error`) will show the
    /// deferred error last. When both can occur in one path, order the toast
    /// with that in mind.
    pub(super) fn apply(mut self, app: &mut App) {
        for effect in std::mem::take(&mut self.queue) {
            effect(app);
        }
    }
}

/// Safety net: a handler that defers effects but returns before calling
/// `apply` would otherwise drop the queue silently. Surface that as an error
/// so the bug is caught instead of swallowed.
impl Drop for Effects {
    fn drop(&mut self) {
        if self.queue.is_empty() {
            return;
        }
        log::error!(
            "[purple] {} deferred effect(s) dropped unapplied: a handler returned after defer() without effects.apply()",
            self.queue.len()
        );
        // Debug/test builds fail loudly so a forgotten apply() is caught at its
        // source; release only logs. Skip while already unwinding to avoid a
        // double panic.
        #[cfg(debug_assertions)]
        if !std::thread::panicking() {
            panic!(
                "{} deferred effect(s) dropped unapplied without effects.apply()",
                self.queue.len()
            );
        }
    }
}

/// Screen navigation for a domain slice.
pub(super) trait Nav {
    fn screen_mut(&mut self) -> &mut Screen;

    /// Transition screen with the same debug log as `App::set_screen`.
    fn set_screen(&mut self, new: Screen) {
        let current = self.screen_mut();
        if *current != new {
            log::debug!(
                "screen: {} → {}",
                current.variant_name(),
                new.variant_name()
            );
        }
        *current = new;
    }
}

/// Toast / status notifications for a domain slice. Each method mirrors the
/// equivalent `App::notify*`.
pub(super) trait Notify {
    fn status_mut(&mut self) -> &mut StatusCenter;

    fn notify(&mut self, text: impl Into<String>) {
        self.status_mut().notify(text);
    }

    fn notify_error(&mut self, text: impl Into<String>) {
        self.status_mut().notify_error(text);
    }

    fn notify_warning(&mut self, text: impl Into<String>) {
        let msg = StatusMessage {
            text: text.into(),
            class: MessageClass::Warning,
            tick_count: 0,
            sticky: false,
            created_at: std::time::Instant::now(),
        };
        log::debug!("toast <- Warning: {}", msg.text);
        self.status_mut().push_toast(msg);
    }
}

/// Deferred whole-App effects for a domain slice.
pub(super) trait Effectful {
    fn effects_mut(&mut self) -> &mut Effects;

    /// Queue an arbitrary whole-App operation for after the handler returns.
    fn defer(&mut self, effect: impl FnOnce(&mut App) + 'static) {
        self.effects_mut().defer(effect);
    }

    /// Reload hosts from disk after the handler returns. Mirrors
    /// `App::reload_hosts`; deferred because it touches most of `App`.
    fn reload_hosts(&mut self) {
        self.effects_mut().defer(App::reload_hosts);
    }

    /// Re-sort the host display list after the handler returns.
    fn apply_sort(&mut self) {
        self.effects_mut().defer(App::apply_sort);
    }

    /// Refresh config/include mtimes after a write, after the handler returns.
    fn update_last_modified(&mut self) {
        self.effects_mut().defer(App::update_last_modified);
    }

    /// Record an SSH session against `alias` after the handler returns. The
    /// timestamp is captured now (handler time), not at apply time, so it
    /// matches the inline `App::record_key_use` it replaces exactly.
    fn record_key_use(&mut self, alias: impl Into<String>) {
        let alias = alias.into();
        let now = crate::key_activity::now_secs();
        self.effects_mut()
            .defer(move |app| app.record_key_use(&alias, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn test_app() -> App {
        let config = crate::ssh_config::model::SshConfigFile {
            elements: crate::ssh_config::model::SshConfigFile::parse_content(""),
            path: std::path::PathBuf::from("ctx_test_config"),
            crlf: false,
            bom: false,
        };
        App::new(config)
    }

    #[test]
    fn defer_then_apply_consumes_the_queue() {
        let mut effects = Effects::default();
        effects.defer(|_app| {});
        effects.defer(|_app| {});
        assert_eq!(effects.queue.len(), 2, "defer pushes onto the queue");
        effects.apply(&mut test_app());
    }

    #[test]
    fn apply_runs_every_effect_in_push_order() {
        let order = Rc::new(RefCell::new(Vec::new()));
        let mut effects = Effects::default();
        for i in 0..5 {
            let order = Rc::clone(&order);
            effects.defer(move |_app| order.borrow_mut().push(i));
        }
        effects.apply(&mut test_app());
        assert_eq!(*order.borrow(), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn apply_threads_the_real_app_into_each_effect() {
        let mut effects = Effects::default();
        effects.defer(|app| app.demo_mode = true);
        let mut app = test_app();
        assert!(!app.demo_mode);
        effects.apply(&mut app);
        assert!(
            app.demo_mode,
            "deferred effect must mutate the App passed to apply"
        );
    }

    #[test]
    fn apply_on_empty_queue_is_a_noop() {
        let effects = Effects::default();
        effects.apply(&mut test_app());
    }

    // The Drop safety-net panics in debug builds when a non-empty queue is
    // dropped without apply(); release only logs, so this test is debug-only.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "dropped unapplied")]
    fn dropping_unapplied_effects_panics_in_debug() {
        let mut effects = Effects::default();
        effects.defer(|_app| {});
    }
}
