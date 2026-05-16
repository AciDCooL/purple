//! Key handler for the global Keys-tab overview (top_page = Keys).
//!
//! The Keys tab is a master-detail view of every SSH public key found in
//! `~/.ssh/` plus an optional Vault SSH cert TTL strip above the list.
//! All actions in this tab are non-destructive in v1: navigation,
//! clipboard copy of the selected public key, key push, and Vault
//! signing. Key discovery is automatic: purple re-runs `discover_keys`
//! after key pushes and host-list changes, so there is no manual
//! `R`-style reload binding.

use std::sync::atomic::Ordering;

use crossterm::event::{KeyCode, KeyEvent};
use log::debug;

use crate::app::{App, Screen};

/// Dispatch a key event for the Keys overview tab. Routes to a dedicated
/// search sub-handler while a query is active so typing characters edits
/// the query instead of triggering the normal-mode shortcuts.
pub(super) fn handle_keys(app: &mut App, key: KeyEvent) {
    if app.search.query.is_some() {
        handle_search_keys(app, key);
        return;
    }
    match key.code {
        KeyCode::Tab => {
            app.cycle_top_page_next();
            app.search.query = None;
        }
        KeyCode::BackTab => {
            app.cycle_top_page_prev();
            app.search.query = None;
        }
        KeyCode::Char('j') | KeyCode::Down | KeyCode::Right => {
            app.select_next_key();
        }
        KeyCode::Char('k') | KeyCode::Up | KeyCode::Left => {
            app.select_prev_key();
        }
        KeyCode::PageDown => {
            crate::app::page_down(&mut app.keys.list_state, app.keys.list.len(), 10);
        }
        KeyCode::PageUp => {
            crate::app::page_up(&mut app.keys.list_state, app.keys.list.len(), 10);
        }
        KeyCode::Home | KeyCode::Char('g') if !app.keys.list.is_empty() => {
            app.keys.list_state.select(Some(0));
        }
        KeyCode::End | KeyCode::Char('G') if !app.keys.list.is_empty() => {
            app.keys.list_state.select(Some(app.keys.list.len() - 1));
        }
        // Enter and `c` both copy the selected pubkey. Enter is the
        // advertised primary in the footer; `c` is the muscle-memory
        // shortcut from picker overlays and the broader CLI ecosystem.
        KeyCode::Enter | KeyCode::Char('c') => {
            copy_selected_pubkey(app);
        }
        KeyCode::Char('p') => {
            open_push_picker(app);
        }
        // Bulk Vault SSH sign: same entry point the host list uses,
        // shared so the action stays consistent between tabs. Becomes a
        // no-op with a friendly notify when no host has a vault-ssh
        // role configured.
        KeyCode::Char('V') => {
            super::host_list::actions::initiate_bulk_vault_sign(app);
        }
        KeyCode::Char('/') => {
            // Enter search mode. We deliberately do not reuse
            // `App::start_search()` because that helper drives the
            // hosts-specific `filtered_indices` state machine; the Keys
            // tab filters at render time and only needs the query string.
            app.search.query = Some(String::new());
            // Reset selection so we always land on the first match.
            if !app.keys.list.is_empty() {
                app.keys.list_state.select(Some(0));
            }
            log::debug!("[purple] keys: opened search");
        }
        KeyCode::Char(':') => {
            log::debug!("jump: opened from keys overview");
            app.open_jump(crate::app::JumpMode::Keys);
        }
        KeyCode::Char('n') => {
            // Match host-list and tunnels: dismiss the upgrade toast and
            // open the What's New overlay so release notes are reachable
            // from any main tab.
            super::whats_new::dismiss_whats_new_toast(app);
            app.set_screen(Screen::WhatsNew(crate::app::WhatsNewState::default()));
        }
        KeyCode::Char('?') => {
            app.set_screen(Screen::Help {
                return_screen: Box::new(Screen::HostList),
            });
        }
        KeyCode::Char('q') => {
            app.running = false;
        }
        // Esc while a push is in flight cancels the run. Higher priority
        // than the q-hint toast because cancelling is the only Esc-shaped
        // affordance the user has during a long push.
        KeyCode::Esc if push_in_flight(app) => {
            cancel_push_if_running(app);
        }
        // Mirrors host-list / tunnels-overview policy: idle Esc never quits.
        // The first idle press surfaces a one-shot toast pointing to `q`;
        // the flag is shared across tabs so the hint shows at most once per
        // session. The sticky-toast guard skips the hint when a sticky toast
        // is active so an informational nudge cannot displace a sticky error.
        KeyCode::Esc
            if !app.esc_quit_hint_shown
                && !app.status_center.toast.as_ref().is_some_and(|t| t.sticky) =>
        {
            log::debug!("[purple] esc on idle keys overview, showing quit hint toast");
            app.notify(crate::messages::ESC_QUIT_HINT);
            app.esc_quit_hint_shown = true;
        }
        _ => {}
    }
}

/// True iff a push run is currently in flight (worker spawned, not yet
/// finalised). Used as the Esc-guard so cancel only fires when there is
/// something to cancel.
pub(super) fn push_in_flight(app: &App) -> bool {
    app.keys.push.expected_count > 0 && app.keys.push.cancel.is_some()
}

/// Cancel an in-flight push run. Sets the cancel flag (so the worker
/// short-circuits at its next iteration), bumps `run_id` so any tail
/// events from the cancelled worker are dropped on arrival, and emits a
/// toast naming the per-host progress at the moment of cancel.
///
/// The worker handle is intentionally NOT cleared here: the thread may
/// still be inside a `wait_with_output` for the in-flight ssh (bounded
/// by `ServerAliveInterval × CountMax = 30s`). `start_key_push` refuses
/// to launch a second worker until `worker.is_finished()`; `App::drop`
/// joins on exit.
fn cancel_push_if_running(app: &mut App) {
    let done = app.keys.push.results.len();
    let total = app.keys.push.expected_count;
    if let Some(ref cancel) = app.keys.push.cancel {
        cancel.store(true, Ordering::Relaxed);
    }
    log::debug!(
        "[purple] key_push: cancel requested, done={}/{}",
        done,
        total
    );
    app.keys.push.results.clear();
    app.keys.push.expected_count = 0;
    app.keys.push.cancel = None;
    app.keys.push.selected.clear();
    // Bump run_id so any KeyPushResult event still in flight from the
    // cancelled worker is dropped on arrival (run_id mismatch), instead
    // of getting silently dropped only because expected_count is zero.
    // Two layers of defence makes the invariant easier to reason about.
    app.keys.push.run_id = app.keys.push.run_id.wrapping_add(1);
    // Drop the progress toast through the status-center invariant so the
    // cancel message is unambiguously the latest status.
    app.status_center.clear_sticky_status();
    app.notify(crate::messages::key_push_cancelled(done, total));
}

/// Search-mode sub-handler. Typing edits the query, navigation keys move
/// through the filtered list, Esc cancels (clears query), Enter commits
/// (copies the highlighted match and clears the query). Tab/BackTab also
/// exit search-mode before cycling tabs.
fn handle_search_keys(app: &mut App, key: KeyEvent) {
    let filtered =
        crate::ssh_keys::filtered_key_indices(&app.keys.list, app.search.query.as_deref());
    let count = filtered.len();
    match key.code {
        KeyCode::Esc => {
            app.search.query = None;
            // Restore selection to first key so navigation feels stable
            // when the user re-opens the same view.
            if !app.keys.list.is_empty() {
                app.keys.list_state.select(Some(0));
            } else {
                app.keys.list_state.select(None);
            }
        }
        KeyCode::Enter => {
            // Copy the currently highlighted match, then exit search.
            copy_selected_pubkey(app);
            app.search.query = None;
        }
        KeyCode::Tab => {
            app.search.query = None;
            app.cycle_top_page_next();
        }
        KeyCode::BackTab => {
            app.search.query = None;
            app.cycle_top_page_prev();
        }
        KeyCode::Down | KeyCode::Right if count > 0 => {
            let cur = app.keys.list_state.selected().unwrap_or(0);
            app.keys.list_state.select(Some((cur + 1).min(count - 1)));
        }
        KeyCode::Up | KeyCode::Left if count > 0 => {
            let cur = app.keys.list_state.selected().unwrap_or(0);
            app.keys.list_state.select(Some(cur.saturating_sub(1)));
        }
        KeyCode::PageDown => {
            crate::app::page_down(&mut app.keys.list_state, count, 10);
        }
        KeyCode::PageUp => {
            crate::app::page_up(&mut app.keys.list_state, count, 10);
        }
        KeyCode::Backspace => {
            if let Some(q) = app.search.query.as_mut() {
                q.pop();
            }
            // Re-anchor selection to the first match after the query shrinks.
            let new_count =
                crate::ssh_keys::filtered_key_indices(&app.keys.list, app.search.query.as_deref())
                    .len();
            if new_count == 0 {
                app.keys.list_state.select(None);
            } else {
                app.keys.list_state.select(Some(0));
            }
        }
        KeyCode::Char(c) => {
            if let Some(q) = app.search.query.as_mut() {
                q.push(c);
            }
            let new_count =
                crate::ssh_keys::filtered_key_indices(&app.keys.list, app.search.query.as_deref())
                    .len();
            if new_count == 0 {
                app.keys.list_state.select(None);
            } else {
                app.keys.list_state.select(Some(0));
            }
        }
        _ => {}
    }
}

/// Read the selected key's public key file and push it to the clipboard.
/// Toasts on success and on every error path so the user always gets feedback.
///
/// When search is active, `key_list_state.selected()` is an index into the
/// filtered list, so we translate back through `filtered_key_indices`
/// before looking up the underlying `SshKeyInfo`.
fn copy_selected_pubkey(app: &mut App) {
    let Some(sel) = app.keys.list_state.selected() else {
        return;
    };
    let Some(idx) =
        crate::ssh_keys::resolve_selection(&app.keys.list, app.search.query.as_deref(), sel)
    else {
        return;
    };
    let Some(key_info) = app.keys.list.get(idx) else {
        return;
    };
    let pub_path = format!("{}.pub", key_info.display_path);
    let expanded = expand_tilde(&pub_path);
    let body = match std::fs::read_to_string(&expanded) {
        Ok(s) => s,
        Err(e) => {
            debug!(
                "[purple] keys: read pubkey failed path={} err={}",
                expanded, e
            );
            app.notify_error(crate::messages::keys_copy_read_failed(&key_info.name));
            return;
        }
    };
    match crate::clipboard::copy_to_clipboard(body.trim_end()) {
        Ok(()) => {
            debug!("[purple] keys: copied pubkey for {}", key_info.name);
            app.notify(crate::messages::keys_copy_success(&key_info.name));
        }
        Err(e) => {
            debug!("[purple] keys: clipboard copy failed: {}", e);
            app.notify_error(e);
        }
    }
}

/// Open the multi-host picker for the currently highlighted key. When
/// search is active, translate the filtered index to the underlying
/// `app.keys.list` index so the picker title and the eventual confirm dialog
/// name the right key.
fn open_push_picker(app: &mut App) {
    let Some(sel) = app.keys.list_state.selected() else {
        return;
    };
    let Some(key_index) =
        crate::ssh_keys::resolve_selection(&app.keys.list, app.search.query.as_deref(), sel)
    else {
        return;
    };
    if app.keys.list.get(key_index).is_none() {
        return;
    }
    // Fresh picker: drop any leftover selection from a prior run.
    app.keys.push.reset_picker();
    app.set_screen(Screen::KeyPushPicker { key_index });
    log::debug!("[purple] keys: opened push picker for index={}", key_index);
}

/// Expand a leading `~/` to the current home directory. Unchanged otherwise.
fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).display().to_string();
        }
    }
    p.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::ssh_config::model::SshConfigFile;
    use crate::ssh_keys::SshKeyInfo;
    use crossterm::event::KeyModifiers;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn expand_tilde_replaces_prefix() {
        let result = expand_tilde("~/.ssh/id_ed25519.pub");
        assert!(result.contains(".ssh/id_ed25519.pub"));
        assert!(!result.starts_with('~'));
    }

    #[test]
    fn expand_tilde_passthrough_for_absolute() {
        assert_eq!(expand_tilde("/tmp/id_ed25519.pub"), "/tmp/id_ed25519.pub");
    }

    #[test]
    fn expand_tilde_passthrough_for_relative() {
        assert_eq!(expand_tilde("keys/id_ed25519.pub"), "keys/id_ed25519.pub");
    }

    fn key(name: &str) -> SshKeyInfo {
        SshKeyInfo {
            name: name.to_string(),
            display_path: format!("~/.ssh/{}", name),
            key_type: "ED25519".into(),
            bits: "256".into(),
            fingerprint: String::new(),
            comment: String::new(),
            linked_hosts: vec![],
            bishop_art: String::new(),
            strength_score: 90,
            encrypted: true,
            agent_loaded: false,
            is_certificate: false,
            mtime_ts: None,
        }
    }

    fn make_app() -> App {
        let scratch = tempfile::tempdir().expect("tempdir").keep();
        crate::preferences::set_path_override(scratch.join("preferences"));
        crate::containers::set_path_override(scratch.join("container_cache.jsonl"));
        let config = SshConfigFile {
            elements: SshConfigFile::parse_content(""),
            path: scratch.join("test_config"),
            crlf: false,
            bom: false,
        };
        App::new(config)
    }

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn open_push_picker_under_search_translates_filtered_index() {
        let mut app = make_app();
        app.keys.list = vec![key("id_ed25519"), key("yubikey_work"), key("customer-x")];
        app.search.query = Some("yubi".to_string());
        // After applying the filter, position 0 in the visible list is
        // "yubikey_work" which is index 1 in app.keys.list.
        app.keys.list_state.select(Some(0));
        open_push_picker(&mut app);
        match app.screen {
            Screen::KeyPushPicker { key_index } => {
                assert_eq!(
                    key_index, 1,
                    "filtered idx 0 must map to app.keys.list idx 1"
                );
            }
            ref other => panic!("expected KeyPushPicker, got {:?}", other),
        }
    }

    #[test]
    fn open_push_picker_resets_picker_state() {
        let mut app = make_app();
        app.keys.list = vec![key("id_ed25519")];
        app.keys.list_state.select(Some(0));
        // Pre-existing stale selection from a previous picker run.
        app.keys.push.selected.insert("old-host".to_string());
        open_push_picker(&mut app);
        assert!(
            app.keys.push.selected.is_empty(),
            "selection must be reset on new picker open"
        );
    }

    #[test]
    fn push_in_flight_true_only_when_cancel_and_expected_set() {
        let mut app = make_app();
        assert!(!push_in_flight(&app));
        app.keys.push.expected_count = 3;
        assert!(
            !push_in_flight(&app),
            "expected_count alone is not in-flight"
        );
        app.keys.push.cancel = Some(Arc::new(AtomicBool::new(false)));
        assert!(push_in_flight(&app), "both fields set: in flight");
        app.keys.push.cancel = None;
        assert!(!push_in_flight(&app));
    }

    #[test]
    fn esc_cancels_in_flight_push_clears_state() {
        let mut app = make_app();
        // Seed an in-flight push.
        let flag = Arc::new(AtomicBool::new(false));
        app.keys.push.cancel = Some(flag.clone());
        app.keys.push.expected_count = 5;
        app.keys.push.results.push(crate::key_push::KeyPushResult {
            alias: "h1".into(),
            outcome: crate::key_push::KeyPushOutcome::Appended,
        });
        app.keys.push.selected.insert("h1".to_string());
        // Esc should observe push_in_flight and cancel.
        handle_keys(&mut app, k(KeyCode::Esc));
        assert!(flag.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(app.keys.push.expected_count, 0);
        assert!(app.keys.push.results.is_empty());
        assert!(app.keys.push.cancel.is_none());
        assert!(app.keys.push.selected.is_empty());
        // Cancel toast surfaced.
        assert!(app.status_center.toast.is_some());
    }

    // --- Arrow-key navigation (j/k aliases via Left/Right) ---

    #[test]
    fn right_arrow_advances_key_selection() {
        let mut app = make_app();
        app.keys.list = vec![key("a"), key("b"), key("c")];
        app.keys.list_state.select(Some(0));
        handle_keys(&mut app, k(KeyCode::Right));
        assert_eq!(app.keys.list_state.selected(), Some(1));
    }

    #[test]
    fn left_arrow_retreats_key_selection() {
        let mut app = make_app();
        app.keys.list = vec![key("a"), key("b"), key("c")];
        app.keys.list_state.select(Some(2));
        handle_keys(&mut app, k(KeyCode::Left));
        assert_eq!(app.keys.list_state.selected(), Some(1));
    }

    #[test]
    fn right_arrow_at_end_wraps_to_first() {
        // select_next_key wraps modulo, matching the j/k behaviour we
        // preserve via the alias.
        let mut app = make_app();
        app.keys.list = vec![key("a"), key("b")];
        app.keys.list_state.select(Some(1));
        handle_keys(&mut app, k(KeyCode::Right));
        assert_eq!(app.keys.list_state.selected(), Some(0));
    }

    #[test]
    fn left_arrow_at_start_wraps_to_last() {
        let mut app = make_app();
        app.keys.list = vec![key("a"), key("b")];
        app.keys.list_state.select(Some(0));
        handle_keys(&mut app, k(KeyCode::Left));
        assert_eq!(app.keys.list_state.selected(), Some(1));
    }

    // --- Dispatcher coverage: navigation and search (H12) ---

    #[test]
    fn slash_opens_search_and_resets_selection() {
        let mut app = make_app();
        app.keys.list = vec![key("a"), key("b"), key("c")];
        app.keys.list_state.select(Some(2));
        handle_keys(&mut app, k(KeyCode::Char('/')));
        assert_eq!(app.search.query.as_deref(), Some(""));
        assert_eq!(
            app.keys.list_state.selected(),
            Some(0),
            "search must land cursor on the first match"
        );
    }

    #[test]
    fn search_typing_appends_to_query() {
        let mut app = make_app();
        app.keys.list = vec![key("alpha"), key("bravo")];
        handle_keys(&mut app, k(KeyCode::Char('/')));
        handle_keys(&mut app, k(KeyCode::Char('a')));
        handle_keys(&mut app, k(KeyCode::Char('l')));
        assert_eq!(app.search.query.as_deref(), Some("al"));
    }

    #[test]
    fn search_esc_clears_query() {
        let mut app = make_app();
        app.keys.list = vec![key("alpha")];
        handle_keys(&mut app, k(KeyCode::Char('/')));
        handle_keys(&mut app, k(KeyCode::Char('a')));
        handle_keys(&mut app, k(KeyCode::Esc));
        assert!(app.search.query.is_none(), "Esc must close search");
    }

    #[test]
    fn search_backspace_on_empty_query_is_noop_and_keeps_search_open() {
        // Backspace on an empty query pop()s a no-op string but does NOT
        // close search mode. The user can keep typing to refine the query.
        // Esc is the explicit "close search" affordance.
        let mut app = make_app();
        app.keys.list = vec![key("alpha")];
        handle_keys(&mut app, k(KeyCode::Char('/')));
        handle_keys(&mut app, k(KeyCode::Backspace));
        assert_eq!(app.search.query.as_deref(), Some(""));
        // Cursor must remain on a valid match index when filtered list is non-empty.
        assert_eq!(app.keys.list_state.selected(), Some(0));
    }

    #[test]
    fn tab_cycles_to_next_top_page_and_closes_search() {
        let mut app = make_app();
        app.top_page = crate::app::TopPage::Keys;
        app.search.query = None;
        handle_keys(&mut app, k(KeyCode::Tab));
        assert!(!matches!(app.top_page, crate::app::TopPage::Keys));
    }

    #[test]
    fn tab_in_search_mode_exits_search_before_cycling() {
        let mut app = make_app();
        app.top_page = crate::app::TopPage::Keys;
        app.keys.list = vec![key("alpha")];
        handle_keys(&mut app, k(KeyCode::Char('/')));
        handle_keys(&mut app, k(KeyCode::Tab));
        assert!(app.search.query.is_none());
        assert!(!matches!(app.top_page, crate::app::TopPage::Keys));
    }

    #[test]
    fn q_quits_the_app() {
        let mut app = make_app();
        assert!(app.running);
        handle_keys(&mut app, k(KeyCode::Char('q')));
        assert!(!app.running);
    }

    #[test]
    fn copy_pubkey_on_empty_list_is_noop() {
        // Pressing Enter on an empty Keys tab must not panic. Earlier
        // versions indexed app.keys.list[0] in the copy path.
        let mut app = make_app();
        app.keys.list.clear();
        app.keys.list_state.select(None);
        handle_keys(&mut app, k(KeyCode::Enter));
        // The presence of any toast is fine; the invariant is "no panic".
    }

    #[test]
    fn n_opens_whats_new_overlay() {
        let mut app = make_app();
        app.keys.list = vec![key("a")];
        handle_keys(&mut app, k(KeyCode::Char('n')));
        assert!(matches!(app.screen, Screen::WhatsNew(_)));
    }
}
