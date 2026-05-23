//! Key handler for `Screen::KeyPushPicker`.
//!
//! Multi-select host picker reached from the Keys tab via `p`. Selection
//! is held in `app.keys.push.selected` (HashSet of aliases). Vault-ssh
//! hosts cannot be selected; Space and `a` skip them.

use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, Screen};
use crate::ssh_config::model::HostEntry;

/// Iterator over hosts that may appear in the picker. Vault-managed hosts
/// are included so the user can see they exist; the selection layer
/// (`toggle_at_cursor` / `toggle_select_all_eligible`) refuses to select
/// them. Picker policy lives in the handler layer, not the UI.
pub(crate) fn pickable_hosts(app: &App) -> impl Iterator<Item = &HostEntry> {
    app.hosts_state.list().iter()
}

/// True when a host is purple-Vault-managed: either a `# purple:vault-ssh`
/// role comment is set, or `CertificateFile` points into `~/.purple/certs/`.
/// Both flavours use signed certs rather than `authorized_keys` appends and
/// must not be picked.
pub(crate) fn is_vault_host(host: &HostEntry) -> bool {
    crate::vault_ssh::has_purple_vault_context(host)
}

pub(super) fn handle_key(app: &mut App, key: KeyEvent) {
    let key_index = match app.screen {
        Screen::KeyPushPicker { key_index } => key_index,
        _ => return,
    };
    let host_count = pickable_hosts(app).count();
    match key.code {
        KeyCode::Esc => {
            app.keys.push.selected.clear();
            app.set_screen(Screen::HostList);
        }
        KeyCode::Char('j') | KeyCode::Down => {
            if host_count == 0 {
                return;
            }
            let cur = app.keys.push.list_state.selected().unwrap_or(0);
            app.keys
                .push
                .list_state
                .select(Some((cur + 1).min(host_count - 1)));
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if host_count == 0 {
                return;
            }
            let cur = app.keys.push.list_state.selected().unwrap_or(0);
            app.keys.push.list_state.select(Some(cur.saturating_sub(1)));
        }
        KeyCode::PageDown => {
            crate::app::page_down(&mut app.keys.push.list_state, host_count, 10);
        }
        KeyCode::PageUp => {
            crate::app::page_up(&mut app.keys.push.list_state, host_count, 10);
        }
        KeyCode::Home | KeyCode::Char('g') if host_count > 0 => {
            app.keys.push.list_state.select(Some(0));
        }
        KeyCode::End | KeyCode::Char('G') if host_count > 0 => {
            app.keys.push.list_state.select(Some(host_count - 1));
        }
        KeyCode::Char(' ') => {
            toggle_at_cursor(app);
        }
        KeyCode::Char('a') | KeyCode::Char('A') => {
            toggle_select_all_eligible(app);
        }
        KeyCode::Enter => {
            commit_to_confirm(app, key_index);
        }
        _ => {}
    }
}

/// Flip the selection state of the alias at the cursor. Vault-ssh hosts
/// are skipped so the user cannot accidentally target a cert-managed
/// host with a static-key append.
fn toggle_at_cursor(app: &mut App) {
    let Some(idx) = app.keys.push.list_state.selected() else {
        return;
    };
    let host = match pickable_hosts(app).nth(idx) {
        Some(h) => h,
        None => return,
    };
    if is_vault_host(host) {
        app.notify(crate::messages::KEY_PUSH_VAULT_SKIP);
        return;
    }
    let alias = host.alias.clone();
    if app.keys.push.selected.contains(&alias) {
        app.keys.push.selected.remove(&alias);
    } else {
        app.keys.push.selected.insert(alias.clone());
    }
    log::debug!(
        "[purple] key_push picker: toggled {} (now {} selected)",
        alias,
        app.keys.push.selected.len()
    );
}

/// `a` toggle: if every eligible host is already selected, clear them;
/// otherwise select all eligible. Matches the host-list bulk-select rhythm.
fn toggle_select_all_eligible(app: &mut App) {
    let eligible: Vec<String> = pickable_hosts(app)
        .filter(|h| !is_vault_host(h))
        .map(|h| h.alias.clone())
        .collect();
    if eligible.is_empty() {
        return;
    }
    let all_already_selected = eligible.iter().all(|a| app.keys.push.selected.contains(a));
    if all_already_selected {
        for alias in &eligible {
            app.keys.push.selected.remove(alias);
        }
        log::debug!(
            "[purple] key_push picker: cleared all {} eligible selections",
            eligible.len()
        );
    } else {
        let n = eligible.len();
        for alias in eligible {
            app.keys.push.selected.insert(alias);
        }
        log::debug!(
            "[purple] key_push picker: selected all {} eligible hosts",
            n
        );
    }
}

/// Enter: freeze the selection into `app.keys.push.committed` and
/// transition. Empty selection notifies but stays on the picker so the
/// user gets feedback instead of a silent no-op.
fn commit_to_confirm(app: &mut App, key_index: usize) {
    if app.keys.push.selected.is_empty() {
        app.notify(crate::messages::KEY_PUSH_NONE_SELECTED);
        return;
    }
    // Preserve picker order (the user just saw the list in this order),
    // not HashSet iteration order, so the confirm dialog reads stably.
    let aliases: Vec<String> = pickable_hosts(app)
        .map(|h| h.alias.clone())
        .filter(|a| app.keys.push.selected.contains(a))
        .collect();
    app.keys.push.committed = aliases;
    app.set_screen(Screen::ConfirmKeyPush { key_index });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::ssh_config::model::SshConfigFile;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn make_app(content: &str) -> App {
        let scratch = tempfile::tempdir().expect("tempdir").keep();
        crate::preferences::set_path_override(scratch.join("preferences"));
        crate::containers::set_path_override(scratch.join("container_cache.jsonl"));
        let config = SshConfigFile {
            elements: SshConfigFile::parse_content(content),
            path: scratch.join("test_config"),
            crlf: false,
            bom: false,
        };
        let mut app = App::new(config);
        // Seed a minimal key so commit_to_confirm can identify it.
        app.keys.list = vec![crate::ssh_keys::SshKeyInfo {
            name: "id_ed25519".into(),
            display_path: "~/.ssh/id_ed25519".into(),
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
        }];
        app.screen = Screen::KeyPushPicker { key_index: 0 };
        app.keys.push.list_state.select(Some(0));
        app
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn space_toggles_selection_on_eligible_host() {
        let mut app = make_app("Host h1\n  HostName 1.1.1.1\nHost h2\n  HostName 2.2.2.2\n");
        handle_key(&mut app, k(KeyCode::Char(' ')));
        assert!(app.keys.push.selected.contains("h1"));
        handle_key(&mut app, k(KeyCode::Char(' ')));
        assert!(
            !app.keys.push.selected.contains("h1"),
            "second Space deselects"
        );
    }

    #[test]
    fn space_on_vault_host_does_not_select_and_notifies() {
        let mut app = make_app(
            "Host h1\n  HostName 1.1.1.1\n  # purple:vault-ssh ops/prod\nHost h2\n  HostName 2.2.2.2\n",
        );
        // Cursor on h1 (vault).
        app.keys.push.list_state.select(Some(0));
        handle_key(&mut app, k(KeyCode::Char(' ')));
        assert!(!app.keys.push.selected.contains("h1"));
        assert!(
            app.status_center.toast().is_some(),
            "vault skip should toast"
        );
    }

    #[test]
    fn space_on_purple_cert_file_host_is_treated_as_vault() {
        // Regression guard: a host without `# purple:vault-ssh` but with
        // `CertificateFile ~/.purple/certs/<alias>-cert.pub` is still
        // purple-Vault-managed and must not receive a static-key append.
        let mut app = make_app(
            "Host signed-prod\n  HostName 10.0.0.1\n  CertificateFile ~/.purple/certs/signed-prod-cert.pub\nHost plain\n  HostName 2.2.2.2\n",
        );
        app.keys.push.list_state.select(Some(0));
        handle_key(&mut app, k(KeyCode::Char(' ')));
        assert!(
            !app.keys.push.selected.contains("signed-prod"),
            "cert-file vault host must not be selectable"
        );
        assert!(app.status_center.toast().is_some());
    }

    #[test]
    fn a_skips_both_role_and_cert_file_vault_hosts() {
        let mut app = make_app(
            "Host plain\n  HostName 1.1.1.1\nHost role-vault\n  HostName 2.2.2.2\n  # purple:vault-ssh ops/prod\nHost cert-vault\n  HostName 3.3.3.3\n  CertificateFile ~/.purple/certs/cert-vault-cert.pub\nHost plain2\n  HostName 4.4.4.4\n",
        );
        handle_key(&mut app, k(KeyCode::Char('a')));
        assert!(app.keys.push.selected.contains("plain"));
        assert!(app.keys.push.selected.contains("plain2"));
        assert!(!app.keys.push.selected.contains("role-vault"));
        assert!(!app.keys.push.selected.contains("cert-vault"));
    }

    #[test]
    fn a_selects_all_eligible_skipping_vault() {
        let mut app = make_app(
            "Host h1\n  HostName 1.1.1.1\nHost h2\n  HostName 2.2.2.2\n  # purple:vault-ssh ops/prod\nHost h3\n  HostName 3.3.3.3\n",
        );
        handle_key(&mut app, k(KeyCode::Char('a')));
        assert!(app.keys.push.selected.contains("h1"));
        assert!(
            !app.keys.push.selected.contains("h2"),
            "vault host excluded"
        );
        assert!(app.keys.push.selected.contains("h3"));
    }

    #[test]
    fn a_again_clears_when_all_eligible_already_selected() {
        let mut app = make_app("Host h1\n  HostName 1.1.1.1\nHost h2\n  HostName 2.2.2.2\n");
        handle_key(&mut app, k(KeyCode::Char('a')));
        assert_eq!(app.keys.push.selected.len(), 2);
        handle_key(&mut app, k(KeyCode::Char('a')));
        assert!(app.keys.push.selected.is_empty());
    }

    #[test]
    fn enter_with_empty_selection_notifies_and_stays() {
        let mut app = make_app("Host h1\n  HostName 1.1.1.1\n");
        handle_key(&mut app, k(KeyCode::Enter));
        assert!(matches!(app.screen, Screen::KeyPushPicker { .. }));
        assert!(app.status_center.toast().is_some());
    }

    #[test]
    fn enter_with_selection_transitions_to_confirm() {
        let mut app = make_app("Host h1\n  HostName 1.1.1.1\nHost h2\n  HostName 2.2.2.2\n");
        app.keys.push.selected.insert("h1".to_string());
        app.keys.push.selected.insert("h2".to_string());
        handle_key(&mut app, k(KeyCode::Enter));
        match app.screen {
            Screen::ConfirmKeyPush { .. } => {
                assert_eq!(app.keys.push.committed.len(), 2);
            }
            ref other => panic!("expected ConfirmKeyPush, got {:?}", other),
        }
    }

    #[test]
    fn enter_commit_preserves_picker_order() {
        // HashSet iteration order is non-deterministic, but commit_to_confirm
        // walks the picker's host list and filters by selection so the
        // confirm dialog reads in the visual order the user just saw.
        let mut app = make_app(
            "Host alpha\n  HostName 1.1.1.1\nHost beta\n  HostName 2.2.2.2\nHost gamma\n  HostName 3.3.3.3\n",
        );
        app.keys.push.selected.insert("gamma".to_string());
        app.keys.push.selected.insert("alpha".to_string());
        handle_key(&mut app, k(KeyCode::Enter));
        assert_eq!(app.keys.push.committed, vec!["alpha", "gamma"]);
    }

    #[test]
    fn esc_clears_selection_and_returns_to_host_list() {
        let mut app = make_app("Host h1\n  HostName 1.1.1.1\n");
        app.keys.push.selected.insert("h1".to_string());
        handle_key(&mut app, k(KeyCode::Esc));
        assert!(app.keys.push.selected.is_empty());
        assert!(matches!(app.screen, Screen::HostList));
    }

    #[test]
    fn down_moves_cursor_within_bounds() {
        let mut app = make_app("Host h1\n  HostName 1.1.1.1\nHost h2\n  HostName 2.2.2.2\n");
        app.keys.push.list_state.select(Some(0));
        handle_key(&mut app, k(KeyCode::Down));
        assert_eq!(app.keys.push.list_state.selected(), Some(1));
        // Down at end stays at end.
        handle_key(&mut app, k(KeyCode::Down));
        assert_eq!(app.keys.push.list_state.selected(), Some(1));
    }

    #[test]
    fn up_moves_cursor_clamped_to_zero() {
        let mut app = make_app("Host h1\n  HostName 1.1.1.1\nHost h2\n  HostName 2.2.2.2\n");
        app.keys.push.list_state.select(Some(1));
        handle_key(&mut app, k(KeyCode::Up));
        assert_eq!(app.keys.push.list_state.selected(), Some(0));
        handle_key(&mut app, k(KeyCode::Up));
        assert_eq!(app.keys.push.list_state.selected(), Some(0));
    }
}
