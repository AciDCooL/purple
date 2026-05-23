use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Screen, ViewMode};
use crate::clipboard;
use crate::event::AppEvent;
use crate::preferences;
use crate::ssh_config::model::ConfigElement;

pub(crate) mod actions;

/// Build a provider hint clause for stale host messages, e.g. "Gone from DigitalOcean".
pub(super) fn stale_provider_hint(host: &crate::ssh_config::model::HostEntry) -> String {
    host.provider
        .as_ref()
        .map(|p| format!("Gone from {}", crate::providers::provider_display_name(p)))
        .unwrap_or_default()
}

fn serialize_host_block(elements: &[ConfigElement], alias: &str, crlf: bool) -> Option<String> {
    let line_ending = if crlf { "\r\n" } else { "\n" };
    for element in elements {
        match element {
            ConfigElement::HostBlock(block) if block.host_pattern == alias => {
                let mut output = block.raw_host_line.clone();
                for directive in &block.directives {
                    output.push_str(line_ending);
                    output.push_str(&directive.raw_line);
                }
                return Some(output);
            }
            ConfigElement::Include(include) => {
                for file in &include.resolved_files {
                    if let Some(result) = serialize_host_block(&file.elements, alias, crlf) {
                        return Some(result);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn handle_key(app: &mut App, key: KeyEvent, events_tx: &mpsc::Sender<AppEvent>) {
    match app.top_page {
        crate::app::TopPage::Tunnels => super::tunnels_overview::handle_key(app, key),
        crate::app::TopPage::Containers => {
            super::containers_overview::handle_key(app, key, events_tx);
        }
        crate::app::TopPage::Keys => super::keys_overview::handle_key(app, key),
        crate::app::TopPage::Hosts => {
            if app.search.query().is_some() {
                handle_search_key(app, key, events_tx);
            } else {
                handle_main_key(app, key, events_tx);
            }
        }
    }
    // Containers tab data load: lazy refresh on every key event in the
    // Containers tab. 30s TTL per resource; respects demo mode internally.
    if matches!(app.top_page, crate::app::TopPage::Containers)
        && matches!(app.screen, Screen::HostList)
    {
        super::containers_overview::ensure_inspect_for_selected(app, events_tx);
        super::containers_overview::ensure_logs_for_selected(app, events_tx);
        super::containers_overview::ensure_list_for_selected_host(app, events_tx);
        super::containers_overview::ensure_inspect_for_host_header(app, events_tx);
    }
}

pub(super) fn handle_main_key(app: &mut App, key: KeyEvent, events_tx: &mpsc::Sender<AppEvent>) {
    // Handle tag input mode
    if app.tags.input().is_some() {
        super::host_detail::handle_tag_input(app, key);
        return;
    }

    match key.code {
        KeyCode::Char('q') => {
            if let Some(cancel) = app.vault.signing_cancel() {
                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            app.running = false;
        }
        KeyCode::Esc => {
            if app.hosts_state.group_filter().is_some() {
                app.clear_group_filter();
            } else if !app.hosts_state.multi_select().is_empty() {
                app.hosts_state.clear_multi_select();
            } else if !app.ui.esc_quit_hint_shown
                && !app.status_center.toast().is_some_and(|t| t.sticky)
            {
                // Esc never quits the app. The first time a user presses Esc
                // on an idle host list we surface a one-shot toast pointing to
                // `q`, so accidental Esc presses discover the conventional
                // exit key. Skip the hint when a sticky toast is active so an
                // informational nudge cannot displace a sticky error the user
                // still needs to see; the flag stays unset so the hint will
                // surface on a later Esc once the sticky toast is dismissed.
                log::debug!("[purple] esc on idle host list, showing quit hint toast");
                app.notify(crate::messages::ESC_QUIT_HINT);
                app.ui.esc_quit_hint_shown = true;
            }
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.select_next_skipping_headers();
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.select_prev_skipping_headers();
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::Tab => {
            app.cycle_top_page_next();
            app.search.set_query(None);
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::BackTab => {
            app.cycle_top_page_prev();
            app.search.set_query(None);
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::PageDown => {
            app.page_down_host();
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::PageUp => {
            app.page_up_host();
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::Enter => {
            if app.is_pattern_selected() {
                return;
            }
            if let Some(host) = app.selected_host() {
                let alias = host.alias.clone();
                let askpass = host.askpass.clone();
                let stale_hint = super::host_form::stale_hint_for(host);
                if let Some(hint) = stale_hint {
                    app.notify_warning(crate::messages::stale_host(&hint));
                }
                if app.demo_mode {
                    app.notify_warning(crate::messages::DEMO_CONNECTION_DISABLED);
                    return;
                }
                app.ui.queue_connect(alias, askpass);
            }
        }
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let visible_indices: Vec<usize> = app
                .hosts_state
                .display_list()
                .iter()
                .filter_map(|item| match item {
                    crate::app::HostListItem::Host { index } => Some(*index),
                    _ => None,
                })
                .collect();
            let all_selected = !visible_indices.is_empty()
                && visible_indices
                    .iter()
                    .all(|idx| app.hosts_state.multi_select().contains(idx));
            if all_selected {
                app.hosts_state.clear_multi_select();
            } else {
                for idx in visible_indices {
                    app.hosts_state.multi_select_mut().insert(idx);
                }
            }
        }
        KeyCode::Char('a') => {
            app.open_host_add_form();
        }
        KeyCode::Char('A') => {
            app.open_host_pattern_add_form();
        }
        KeyCode::Char('e') => {
            if let Some(pattern) = app.selected_pattern().cloned() {
                if pattern.source_file.is_some() {
                    app.notify_error(crate::messages::included_file_edit(&pattern.pattern));
                    return;
                }
                app.open_host_pattern_edit_form(&pattern);
            } else if let Some(host) = app.selected_host().cloned() {
                let hint = super::host_form::stale_hint_for(&host);
                app.open_host_edit_form(host, hint);
            }
        }
        KeyCode::Char('d') => {
            if let Some(pattern) = app.selected_pattern() {
                if pattern.source_file.is_some() {
                    app.notify_error(crate::messages::included_file_delete(&pattern.pattern));
                    return;
                }
                let alias = pattern.pattern.clone();
                app.set_screen(Screen::ConfirmDelete { alias });
            } else if let Some(host) = app.selected_host() {
                if let Some(ref source) = host.source_file {
                    let alias = host.alias.clone();
                    let path = source.display();
                    app.notify_warning(crate::messages::included_host_lives_in(&alias, &path));
                    return;
                }
                let stale_hint = super::host_form::stale_hint_for(host);
                let alias = host.alias.clone();
                if let Some(hint) = stale_hint {
                    app.notify_warning(crate::messages::stale_host(&hint));
                }
                app.set_screen(Screen::ConfirmDelete { alias });
            }
        }
        KeyCode::Char('c') => actions::clone_selected(app),
        KeyCode::Char('y') => {
            if app.is_pattern_selected() {
                return;
            }
            if let Some(host) = app.selected_host() {
                let cmd = host.ssh_command(app.reload.config_path());
                let alias = host.alias.clone();
                match clipboard::copy_to_clipboard(&cmd) {
                    Ok(()) => {
                        app.notify(crate::messages::copied_ssh_command(&alias));
                    }
                    Err(e) => {
                        app.notify_error(e);
                    }
                }
            }
        }
        KeyCode::Char('x') => {
            if app.is_pattern_selected() {
                return;
            }
            if let Some(host) = app.selected_host() {
                let alias = host.alias.clone();
                if let Some(block) = serialize_host_block(
                    &app.hosts_state.ssh_config().elements,
                    &alias,
                    app.hosts_state.ssh_config().crlf,
                ) {
                    match clipboard::copy_to_clipboard(&block) {
                        Ok(()) => {
                            app.notify(crate::messages::copied_config_block(&alias));
                        }
                        Err(e) => {
                            app.notify_error(e);
                        }
                    }
                }
            }
        }
        KeyCode::Char('p') => {
            if app.is_pattern_selected() {
                return;
            }
            if !app.ping.status_is_empty() {
                log::debug!(
                    "[purple] p: clearing {} ping result(s) + timestamps",
                    app.ping.status_len()
                );
                app.ping.clear_results();
                app.clear_status();
            } else {
                super::ping::ping_selected_host(app, events_tx, true);
            }
        }
        KeyCode::Char('P') => {
            if !app.ping.status_is_empty() {
                log::debug!(
                    "[purple] P: clearing {} ping result(s) + timestamps",
                    app.ping.status_len()
                );
                app.ping.clear_results();
                app.clear_status();
            } else {
                let hosts_to_ping: Vec<(String, String, u16)> = app
                    .hosts_state
                    .list()
                    .iter()
                    .filter(|h| !h.hostname.is_empty() && h.proxy_jump.is_empty())
                    .map(|h| (h.alias.clone(), h.hostname.clone(), h.port))
                    .collect();
                // Mark ProxyJump hosts as Checking (their status will be
                // inherited from the bastion once it responds).
                for h in app.hosts_state.list() {
                    if !h.proxy_jump.is_empty() {
                        app.ping
                            .insert_status(h.alias.clone(), crate::app::PingStatus::Checking);
                    }
                }
                if !hosts_to_ping.is_empty() {
                    for (alias, _, _) in &hosts_to_ping {
                        app.ping
                            .insert_status(alias.clone(), crate::app::PingStatus::Checking);
                    }
                    app.notify_info(crate::messages::PINGING_ALL);
                    crate::ping::ping_all(&hosts_to_ping, events_tx.clone(), app.ping.generation());
                }
            }
        }
        KeyCode::Char('!') => {
            if app.ping.status_is_empty() {
                app.notify_warning(crate::messages::PING_FIRST);
            } else {
                app.ping.set_filter_down_only(!app.ping.filter_down_only());
                if app.ping.filter_down_only() {
                    // Activate search mode to trigger filtering
                    if app.search.query().is_none() {
                        app.search.set_query(Some(String::new()));
                    }
                    app.apply_filter();
                    let count = app.search.filtered_indices().len();
                    app.notify(crate::messages::showing_unreachable(count));
                } else {
                    // If search was only active for down-only, clear it
                    if app.search.query().is_some_and(|q| q.is_empty()) {
                        app.search.set_query(None);
                        app.search.clear_filtered_indices();
                        app.search.clear_filtered_pattern_indices();
                    } else {
                        app.apply_filter();
                    }
                    app.clear_status();
                }
            }
        }
        KeyCode::Char('/') => {
            app.start_search();
        }
        KeyCode::Char('K') => {
            app.scan_keys();
            app.set_screen(Screen::KeyList);
        }
        KeyCode::Char('t') => {
            // Context-sensitive: with a multi-host selection active, open
            // the bulk tag editor. Otherwise fall back to the single-host
            // tag input bar. `t` consistently means "edit tags" — only the
            // scope changes.
            if !app.hosts_state.multi_select().is_empty() {
                if !app.open_bulk_tag_editor() {
                    app.notify_warning(crate::messages::NO_HOSTS_TO_TAG);
                }
                return;
            }
            if app.is_pattern_selected() {
                return;
            }
            if let Some(host) = app.selected_host() {
                if let Some(ref source) = host.source_file {
                    let alias = host.alias.clone();
                    let path = source.display();
                    app.notify_error(crate::messages::included_host_tag_there(&alias, &path));
                    return;
                }
                let current_tags = host.tags.join(", ");
                app.tags.open_tag_input(current_tags);
            }
        }
        KeyCode::Char('s') => {
            app.hosts_state.advance_sort_mode();
            app.apply_sort();
            if let Err(e) = preferences::save_sort_mode(app.hosts_state.sort_mode()) {
                app.notify_error(crate::messages::sorted_by_save_failed(
                    app.hosts_state.sort_mode().label(),
                    &e,
                ));
            } else {
                app.notify(crate::messages::sorted_by(
                    app.hosts_state.sort_mode().label(),
                ));
            }
        }
        KeyCode::Char('g') => {
            use crate::app::GroupBy;
            match app.hosts_state.group_by() {
                GroupBy::None => {
                    app.hosts_state.set_group_by(GroupBy::Provider);
                    app.apply_sort();
                    if let Err(e) = preferences::save_group_by(app.hosts_state.group_by()) {
                        app.notify_error(crate::messages::grouped_by_save_failed(
                            &app.hosts_state.group_by().label(),
                            &e,
                        ));
                    } else {
                        app.notify(crate::messages::grouped_by(
                            &app.hosts_state.group_by().label(),
                        ));
                    }
                }
                GroupBy::Provider => {
                    let user_tags: Vec<String> = {
                        let mut seen = std::collections::HashSet::new();
                        let mut tags = Vec::new();
                        for host in app.hosts_state.list() {
                            for tag in &host.tags {
                                if seen.insert(tag.clone()) {
                                    tags.push(tag.clone());
                                }
                            }
                        }
                        tags.sort_by_cached_key(|a| a.to_lowercase());
                        tags
                    };
                    if user_tags.is_empty() {
                        app.hosts_state.set_group_by(GroupBy::None);
                        app.apply_sort();
                        if let Err(e) = preferences::save_group_by(app.hosts_state.group_by()) {
                            app.notify_error(crate::messages::ungrouped_save_failed(&e));
                        } else {
                            app.notify(crate::messages::UNGROUPED);
                        }
                    } else {
                        // Switch to tag mode directly. The nav bar shows all
                        // tags as tabs, no picker needed.
                        app.hosts_state.set_group_by(GroupBy::Tag(String::new()));
                        app.apply_sort();
                        if let Err(e) = preferences::save_group_by(app.hosts_state.group_by()) {
                            app.notify_error(crate::messages::grouped_by_tag_save_failed(&e));
                        } else {
                            app.notify(crate::messages::GROUPED_BY_TAG);
                        }
                    }
                }
                GroupBy::Tag(_) => {
                    app.hosts_state.set_group_by(GroupBy::None);
                    app.apply_sort();
                    if let Err(e) = preferences::save_group_by(app.hosts_state.group_by()) {
                        app.notify_error(crate::messages::ungrouped_save_failed(&e));
                    } else {
                        app.notify(crate::messages::UNGROUPED);
                    }
                }
            }
        }
        KeyCode::Char('i') => {
            if app.is_pattern_selected() {
                return;
            }
            if let Some(index) = app.selected_host_index() {
                app.set_screen(Screen::HostDetail { index });
            }
        }
        KeyCode::Char('v') => {
            app.hosts_state.toggle_view_mode();
            app.ui.detail_toggle_pending = true;
            app.ui.detail_scroll = 0;
            if let Err(e) = preferences::save_view_mode(app.hosts_state.view_mode()) {
                log::warn!("[config] Failed to persist view mode: {e}");
            }
        }
        KeyCode::Char(']') if app.hosts_state.view_mode() == ViewMode::Detailed => {
            app.ui.detail_scroll = app.ui.detail_scroll.saturating_add(1);
        }
        KeyCode::Char('[') if app.hosts_state.view_mode() == ViewMode::Detailed => {
            app.ui.detail_scroll = app.ui.detail_scroll.saturating_sub(1);
        }
        KeyCode::Char('u') => {
            // Bulk-tag undo takes priority: the most recent bulk-tag apply
            // can be reverted in one keystroke by restoring each host's
            // previous tag list. After a successful undo the snapshot is
            // cleared so the next `u` falls through to the deleted-host
            // stack as usual.
            if let Some(snapshot) = app.forms.bulk_tag_undo.take() {
                let config_backup = app.hosts_state.ssh_config().clone();
                for (alias, tags) in &snapshot {
                    let _ = app.hosts_state.ssh_config_mut().set_host_tags(alias, tags);
                }
                if let Err(e) = app.hosts_state.ssh_config().write() {
                    app.hosts_state.set_ssh_config(config_backup);
                    app.forms.bulk_tag_undo = Some(snapshot);
                    app.notify_error(crate::messages::failed_to_save(&e));
                } else {
                    let count = snapshot.len();
                    app.update_last_modified();
                    app.reload_hosts();
                    app.notify(crate::messages::restored_tags(count));
                }
            } else if let Some(deleted) = app.hosts_state.pop_undo() {
                let alias = match &deleted.element {
                    ConfigElement::HostBlock(block) => block.host_pattern.clone(),
                    _ => "host".to_string(),
                };
                app.hosts_state
                    .ssh_config_mut()
                    .insert_host_at(deleted.element, deleted.position);
                if let Err(e) = app.hosts_state.ssh_config().write() {
                    // Rollback: remove re-inserted host and restore undo buffer
                    if let Some((element, position)) = app
                        .hosts_state
                        .ssh_config_mut()
                        .delete_host_undoable(&alias)
                    {
                        app.hosts_state
                            .undo_stack_mut()
                            .push(crate::app::DeletedHost { element, position });
                    }
                    app.notify_error(crate::messages::failed_to_save(&e));
                } else {
                    app.update_last_modified();
                    app.reload_hosts();
                    // Restored host has no container_cache entry,
                    // queue an initial fetch for THIS alias only.
                    app.container_state.queue_fetch(alias.clone());
                    app.notify(crate::messages::host_restored(&alias));
                }
            } else {
                app.notify_warning(crate::messages::NOTHING_TO_UNDO);
            }
        }
        KeyCode::Char('#') => {
            app.open_tag_picker();
        }
        KeyCode::Char('m') => {
            let current = crate::ui::theme::current_theme().name;
            let builtins = crate::ui::theme::ThemeDef::builtins();
            let custom = crate::ui::theme::ThemeDef::load_custom();
            let idx = builtins
                .iter()
                .position(|t| t.name.eq_ignore_ascii_case(&current))
                .or_else(|| {
                    if custom.is_empty() {
                        None
                    } else {
                        custom
                            .iter()
                            .position(|t| t.name.eq_ignore_ascii_case(&current))
                            .map(|i| builtins.len() + 1 + i) // +1 for divider
                    }
                })
                .unwrap_or(0);
            app.ui.theme_picker.list.select(Some(idx));
            app.ui.theme_picker.builtins = builtins;
            app.ui.theme_picker.custom = custom;
            app.ui.theme_picker.saved_name =
                crate::preferences::load_theme().unwrap_or_else(|| "Purple".to_string());
            app.ui.theme_picker.original = Some(crate::ui::theme::current_theme());
            app.set_screen(Screen::ThemePicker);
        }
        KeyCode::Char('T') => {
            if app.is_pattern_selected() {
                return;
            }
            if let Some(host) = app.selected_host() {
                let stale_hint = super::host_form::stale_hint_for(host);
                let alias = host.alias.clone();
                if let Some(hint) = stale_hint {
                    app.notify_warning(crate::messages::stale_host(&hint));
                }
                app.refresh_tunnel_list(&alias);
                app.ui.tunnel_list_state = ratatui::widgets::ListState::default();
                if !app.tunnels.list().is_empty() {
                    app.ui.tunnel_list_state.select(Some(0));
                }
                app.set_screen(Screen::TunnelList { alias });
            }
        }
        KeyCode::Char('S') => {
            if !app.demo_mode {
                *app.providers.config_mut() = crate::providers::config::ProviderConfig::load();
            }
            app.ui.provider_list_state = ratatui::widgets::ListState::default();
            app.ui.provider_list_state.select(Some(0));
            app.set_screen(Screen::Providers);
        }
        KeyCode::Char('I') => {
            let count = crate::import::count_known_hosts_candidates();
            if count > 0 {
                app.set_screen(Screen::ConfirmImport { count });
            } else {
                app.notify_warning(crate::messages::NO_IMPORTABLE_HOSTS);
            }
        }
        KeyCode::Char('X') => {
            let stale = app.hosts_state.ssh_config().stale_hosts();
            if stale.is_empty() {
                app.notify_warning(crate::messages::NO_STALE_HOSTS);
            } else {
                let aliases: Vec<String> = stale.into_iter().map(|(a, _)| a).collect();
                app.set_screen(Screen::ConfirmPurgeStale {
                    aliases,
                    provider: None,
                });
            }
        }
        KeyCode::Char('V') => actions::initiate_bulk_vault_sign(app),
        // SPACE GUARD MUST PRECEDE the generic Char(c) arm below. Plain
        // Space and Ctrl+Space both toggle the multi-select set; without
        // this ordering the char arm would capture Space first.
        KeyCode::Char(' ') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if app.is_pattern_selected() {
                return;
            }
            if let Some(idx) = app.selected_host_index() {
                app.hosts_state.toggle_multi_select(idx);
            }
        }
        KeyCode::Char(' ') => {
            // Plain Space mirrors Ctrl+Space so users familiar with
            // ranger/k9s/mutt's muscle memory get the same mark toggle
            // without a modifier. Ctrl+Space still works.
            if app.is_pattern_selected() {
                return;
            }
            if let Some(idx) = app.selected_host_index() {
                app.hosts_state.toggle_multi_select(idx);
            }
        }
        KeyCode::Char('r') => {
            if app.is_pattern_selected() {
                return;
            }
            let (aliases, stale_hint): (Vec<String>, Option<String>) =
                if app.hosts_state.multi_select().is_empty() {
                    if let Some(host) = app.selected_host() {
                        let hint = super::host_form::stale_hint_for(host);
                        (vec![host.alias.clone()], hint)
                    } else {
                        (Vec::new(), None)
                    }
                } else {
                    let has_stale = app.hosts_state.multi_select().iter().any(|&idx| {
                        app.hosts_state
                            .list()
                            .get(idx)
                            .is_some_and(|h| h.stale.is_some())
                    });
                    (
                        app.hosts_state
                            .multi_select()
                            .iter()
                            .filter_map(|&idx| {
                                app.hosts_state.list().get(idx).map(|h| h.alias.clone())
                            })
                            .collect(),
                        if has_stale {
                            Some(" Selection includes stale hosts.".to_string())
                        } else {
                            None
                        },
                    )
                };
            if let Some(hint) = stale_hint {
                app.notify_warning(crate::messages::stale_host(&hint));
            }
            if aliases.is_empty() {
                app.notify_warning(crate::messages::NO_HOST_SELECTED);
            } else {
                super::snippet::open_snippet_picker(app, aliases);
            }
        }
        KeyCode::Char('R') => {
            if app.is_pattern_selected() {
                return;
            }
            let aliases: Vec<String> = app
                .hosts_state
                .display_list()
                .iter()
                .filter_map(|item| match item {
                    crate::app::HostListItem::Host { index } => {
                        Some(app.hosts_state.list()[*index].alias.clone())
                    }
                    _ => None,
                })
                .collect();
            if aliases.is_empty() {
                app.notify_warning(crate::messages::NO_HOSTS_TO_RUN);
            } else {
                super::snippet::open_snippet_picker(app, aliases);
            }
        }
        KeyCode::Char(':') => {
            log::debug!("jump: opened from host list");
            app.open_jump(crate::app::JumpMode::Hosts);
        }
        KeyCode::Char('F') => actions::open_file_browser(app, events_tx),
        KeyCode::Char('C') => actions::open_container_overlay(app, events_tx),
        KeyCode::Char('n') if app.search.query().is_none() => {
            log::debug!("[purple] opening whats-new overlay via n");
            super::whats_new::dismiss_whats_new_toast(app);
            app.set_screen(Screen::WhatsNew(crate::app::WhatsNewState::default()));
        }
        KeyCode::Char('?') => {
            let old = std::mem::replace(&mut app.screen, Screen::HostList);
            app.set_screen(Screen::Help {
                return_screen: Box::new(old),
            });
        }
        _ => {}
    }
}

pub(super) fn handle_search_key(app: &mut App, key: KeyEvent, events_tx: &mpsc::Sender<AppEvent>) {
    match key.code {
        KeyCode::Esc => {
            app.cancel_search();
        }
        KeyCode::Enter => {
            if let Some(host) = app.selected_host() {
                let alias = host.alias.clone();
                let askpass = host.askpass.clone();
                let stale_hint = super::host_form::stale_hint_for(host);
                app.cancel_search();
                if let Some(hint) = stale_hint {
                    app.notify_warning(crate::messages::stale_host(&hint));
                }
                if app.demo_mode {
                    app.notify_warning(crate::messages::DEMO_CONNECTION_DISABLED);
                    return;
                }
                app.ui.queue_connect(alias, askpass);
            }
        }
        KeyCode::Down | KeyCode::Tab => {
            app.select_next();
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::Up | KeyCode::BackTab => {
            app.select_prev();
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::PageDown => {
            app.page_down_host();
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::PageUp => {
            app.page_up_host();
            super::ping::refresh_selected_if_stale(app, events_tx);
        }
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if !app.ping.status_is_empty() {
                log::debug!(
                    "[purple] ctrl+p: clearing {} ping result(s) + timestamps",
                    app.ping.status_len()
                );
                let was_filtering = app.ping.filter_down_only();
                app.ping.clear_results();
                if was_filtering {
                    app.cancel_search();
                }
                app.clear_status();
            } else {
                super::ping::ping_selected_host(app, events_tx, false);
            }
        }
        KeyCode::Char(' ') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(idx) = app.selected_host_index() {
                app.hosts_state.toggle_multi_select(idx);
            }
        }
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let visible_indices: Vec<usize> = app.search.filtered_indices().to_vec();
            let all_selected = !visible_indices.is_empty()
                && visible_indices
                    .iter()
                    .all(|idx| app.hosts_state.multi_select().contains(idx));
            if all_selected {
                app.hosts_state.clear_multi_select();
            } else {
                for idx in visible_indices {
                    app.hosts_state.multi_select_mut().insert(idx);
                }
            }
        }
        KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(host) = app.selected_host().cloned() {
                let hint = super::host_form::stale_hint_for(&host);
                app.open_host_edit_form(host, hint);
            }
        }
        KeyCode::Char('!') if app.ping.filter_down_only() => {
            app.ping.set_filter_down_only(false);
            if app.search.query().is_some_and(|q| q.is_empty()) {
                app.cancel_search();
            } else {
                app.apply_filter();
            }
            app.clear_status();
        }
        KeyCode::Char(c) => {
            app.search.push_query_char(c);
            app.apply_filter();
        }
        KeyCode::Backspace => {
            app.search.pop_query_char();
            app.apply_filter();
        }
        _ => {}
    }
}
