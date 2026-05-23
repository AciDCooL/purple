use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, Screen};

pub(super) fn handle_tag_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            if let Some(input) = app.tags.input() {
                let tags: Vec<String> = input
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                if let Some(host) = app.selected_host() {
                    let alias = host.alias.clone();
                    let old_tags = host.tags.clone();
                    let _ = app
                        .hosts_state
                        .ssh_config_mut()
                        .set_host_tags(&alias, &tags);
                    if let Err(e) = app.hosts_state.ssh_config().write() {
                        // Restore old tags on write failure
                        let _ = app
                            .hosts_state
                            .ssh_config_mut()
                            .set_host_tags(&alias, &old_tags);
                        app.notify_error(crate::messages::failed_to_save(&e));
                    } else {
                        app.update_last_modified();
                        let count = tags.len();
                        app.reload_hosts();
                        app.select_host_by_alias(&alias);
                        app.notify(crate::messages::tagged_host(&alias, count));
                    }
                }
            }
            app.tags.close_tag_input();
        }
        KeyCode::Esc => {
            app.tags.close_tag_input();
        }
        KeyCode::Left => {
            app.tags.cursor_left();
        }
        KeyCode::Right => {
            app.tags.cursor_right();
        }
        KeyCode::Home => {
            app.tags.cursor_home();
        }
        KeyCode::End => {
            app.tags.cursor_end();
        }
        KeyCode::Char(c) => {
            app.tags.insert_char(c);
        }
        KeyCode::Backspace => {
            app.tags.backspace();
        }
        _ => {}
    }
}

pub(super) fn handle_key(app: &mut App, key: KeyEvent) {
    let index = match app.screen {
        Screen::HostDetail { index } => index,
        _ => return,
    };
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('i') => {
            app.set_screen(Screen::HostList);
        }
        KeyCode::Char('?') => {
            let old = std::mem::replace(&mut app.screen, Screen::HostList);
            app.set_screen(Screen::Help {
                return_screen: Box::new(old),
            });
        }
        KeyCode::Char('e') => {
            if let Some(host) = app.hosts_state.list().get(index).cloned() {
                let hint = super::host_form::stale_hint_for(&host);
                app.open_host_edit_form(host, hint);
            }
        }
        KeyCode::Char('T') => {
            if let Some(host) = app.hosts_state.list().get(index) {
                let stale_hint = super::host_form::stale_hint_for(host);
                let alias = host.alias.clone();
                if let Some(hint) = stale_hint {
                    app.notify_warning(crate::messages::stale_host(&hint));
                }
                app.refresh_tunnel_list(&alias);
                *app.ui.tunnel_list_state_mut() = ratatui::widgets::ListState::default();
                if !app.tunnels.list().is_empty() {
                    app.ui.tunnel_list_state_mut().select(Some(0));
                }
                app.set_screen(Screen::TunnelList { alias });
            }
        }
        KeyCode::Char('r') => {
            if let Some(host) = app.hosts_state.list().get(index) {
                let stale_hint = super::host_form::stale_hint_for(host);
                let alias = host.alias.clone();
                if let Some(hint) = stale_hint {
                    app.notify_warning(crate::messages::stale_host(&hint));
                }
                app.set_screen(Screen::SnippetPicker {
                    target_aliases: vec![alias],
                });
                *app.ui.snippet_picker_state_mut() = ratatui::widgets::ListState::default();
                let indices = app.filtered_snippet_indices();
                if !indices.is_empty() {
                    app.ui.snippet_picker_state_mut().select(Some(0));
                }
            }
        }
        _ => {}
    }
}
