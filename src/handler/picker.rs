use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::App;

pub(super) fn handle_password_picker(app: &mut App, key: KeyEvent) {
    // Ctrl+D sets selected source as global default
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('d') {
        if let Some(index) = app.ui.password_picker.list.selected() {
            if let Some(source) = crate::askpass::PASSWORD_SOURCES.get(index) {
                let is_none = source.label == "None";
                let value = if is_none { "" } else { source.value };
                match crate::preferences::save_askpass_default(value) {
                    Ok(()) => {
                        if is_none {
                            app.notify(crate::messages::GLOBAL_DEFAULT_CLEARED);
                        } else {
                            app.notify(crate::messages::global_default_set(source.label));
                        }
                    }
                    Err(e) => {
                        app.notify_error(crate::messages::save_default_failed(&e));
                    }
                }
            }
        }
        app.close_password_picker();
        return;
    }

    match key.code {
        KeyCode::Esc => {
            app.close_password_picker();
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.select_next_password_source();
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.select_prev_password_source();
        }
        KeyCode::Enter => {
            let mut needs_more_input = false;
            if let Some(index) = app.ui.password_picker.list.selected() {
                if let Some(source) = crate::askpass::PASSWORD_SOURCES.get(index) {
                    let is_none = source.label == "None";
                    let is_custom_cmd = source.label == "Custom command";
                    let is_prefix = source.value.ends_with(':') || source.value.ends_with("//");
                    if is_none {
                        app.forms.host.apply_password_source(String::new(), false);
                        app.notify(crate::messages::PASSWORD_SOURCE_CLEARED);
                    } else if is_custom_cmd {
                        app.forms.host.apply_password_source(String::new(), true);
                        app.notify(crate::messages::ASKPASS_CUSTOM_COMMAND_HINT);
                        needs_more_input = true;
                    } else if is_prefix {
                        app.forms
                            .host
                            .apply_password_source(source.value.to_string(), true);
                        app.notify(crate::messages::complete_path(source.label));
                        needs_more_input = true;
                    } else {
                        app.forms
                            .host
                            .apply_password_source(source.value.to_string(), false);
                        app.notify(crate::messages::password_source_set(source.label));
                    }
                }
            }
            app.close_password_picker();
            if !needs_more_input {
                try_auto_submit_after_picker(app);
            }
        }
        _ => {}
    }
}

/// Unified key picker handler for both host form and provider form.
pub(super) fn handle_key_picker_shared(app: &mut App, key: KeyEvent, for_provider: bool) {
    match key.code {
        KeyCode::Esc => {
            app.close_key_picker();
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.select_next_picker_key();
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.select_prev_picker_key();
        }
        KeyCode::Enter => {
            if let Some(index) = app.ui.key_picker.list.selected() {
                if let Some(key_info) = app.keys.list.get(index) {
                    if for_provider {
                        app.providers.form.identity_file = key_info.display_path.clone();
                        app.providers.form.sync_cursor_to_end();
                    } else {
                        app.forms.host.identity_file = key_info.display_path.clone();
                        app.forms.host.sync_cursor_to_end();
                    }
                    app.notify(crate::messages::key_selected(&key_info.name));
                }
            }
            app.close_key_picker();
            if !for_provider {
                try_auto_submit_after_picker(app);
            }
        }
        _ => {}
    }
}

/// ProxyJump picker handler for the host form.
pub(super) fn handle_proxyjump_picker(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.close_proxyjump_picker();
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.select_next_proxyjump();
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.select_prev_proxyjump();
        }
        KeyCode::Enter => {
            let candidates = app.proxyjump_candidates();
            if let Some(index) = app.ui.proxyjump_picker.list.selected() {
                if let Some(crate::app::ProxyJumpCandidate::Host { alias, .. }) =
                    candidates.get(index)
                {
                    app.forms.host.proxy_jump = alias.clone();
                    app.forms.host.sync_cursor_to_end();
                    app.notify(crate::messages::proxy_jump_set(alias));
                    app.close_proxyjump_picker();
                    try_auto_submit_after_picker(app);
                }
                // Separator selected: no-op, stay in picker.
            }
        }
        _ => {}
    }
}

pub(super) fn handle_vault_role_picker(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.close_vault_role_picker();
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.select_next_vault_role();
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.select_prev_vault_role();
        }
        KeyCode::Enter => {
            let candidates = app.vault_role_candidates();
            if let Some(index) = app.ui.vault_role_picker.list.selected() {
                if let Some(role) = candidates.get(index) {
                    app.forms.host.vault_ssh = role.clone();
                    app.forms.host.sync_cursor_to_end();
                    app.notify(crate::messages::vault_role_set(role));
                }
            }
            app.close_vault_role_picker();
        }
        _ => {}
    }
}

/// Auto-submit the host form after a picker selection if all required fields are filled.
pub(super) fn try_auto_submit_after_picker(app: &mut App) {
    if !app.forms.host.alias.is_empty() && !app.forms.host.hostname.is_empty() {
        super::host_form::submit_form(app);
    }
}
