//! Key handler for the global Tunnels-tab overview (top_page = Tunnels).
//!
//! Supports navigation, start/stop, and add/edit/delete. Adding from this
//! screen routes through the host picker first because the user has not yet
//! chosen which host the new tunnel belongs to.

use crossterm::event::{KeyCode, KeyEvent};
use log::{debug, info};

use crate::app::{App, Screen, TopPage};
use crate::tunnel::TunnelRule;

/// Resolve the tunnel row currently under the cursor. Walks the SAME
/// filtered + sorted sequence the UI renders so the cursor always points
/// at the row visually under it.
fn selected_row(app: &App) -> Option<(String, TunnelRule)> {
    let sel = app.ui.tunnels_overview_state.selected()?;
    crate::ui::tunnels_overview::visible_pairs(app)
        .into_iter()
        .nth(sel)
}

/// Total visible row count; used for cursor clamping.
fn row_count(app: &App) -> usize {
    crate::ui::tunnels_overview::visible_pairs(app).len()
}

fn select_next(app: &mut App) {
    let total = row_count(app);
    if total == 0 {
        app.ui.tunnels_overview_state.select(None);
        return;
    }
    let cur = app.ui.tunnels_overview_state.selected().unwrap_or(0);
    let next = if cur + 1 >= total { 0 } else { cur + 1 };
    app.ui.tunnels_overview_state.select(Some(next));
}

fn select_prev(app: &mut App) {
    let total = row_count(app);
    if total == 0 {
        app.ui.tunnels_overview_state.select(None);
        return;
    }
    let cur = app.ui.tunnels_overview_state.selected().unwrap_or(0);
    let prev = if cur == 0 { total - 1 } else { cur - 1 };
    app.ui.tunnels_overview_state.select(Some(prev));
}

fn toggle_tunnel(app: &mut App) {
    let Some((alias, rule)) = selected_row(app) else {
        return;
    };
    if app.tunnels.active.contains_key(&alias) {
        if let Some(mut tunnel) = app.tunnels.active.remove(&alias) {
            if let Err(e) = tunnel.child.kill() {
                debug!("[external] Failed to kill tunnel process for {alias}: {e}");
            }
            let _ = tunnel.child.wait();
            drop(tunnel);
            app.refresh_tunnel_bind_ports();
            reposition_cursor_on(app, &alias, &rule);
            app.notify(crate::messages::tunnel_stopped(&alias));
        }
        return;
    }
    if app.demo_mode {
        app.notify(crate::messages::DEMO_TUNNELS_DISABLED);
        return;
    }
    let askpass = app
        .hosts_state
        .list
        .iter()
        .find(|h| h.alias == alias)
        .and_then(|h| h.askpass.clone());
    let rules = app.hosts_state.ssh_config.find_tunnel_directives(&alias);
    if rules.is_empty() {
        return;
    }
    match crate::tunnel::start_tunnel(
        &alias,
        &app.reload.config_path,
        askpass.as_deref(),
        app.bw_session.as_deref(),
    ) {
        Ok(child) => {
            for rule in &rules {
                info!(
                    "Tunnel started: type={} local={} remote={}:{} alias={alias}",
                    rule.tunnel_type.label(),
                    rule.bind_port,
                    rule.remote_host,
                    rule.remote_port
                );
            }
            app.tunnels.ensure_lsof_poller();
            let parser_tx = app.tunnels.parser_tx.clone();
            let active = crate::tunnel::ActiveTunnel::spawn(child, &alias, parser_tx);
            app.tunnels.active.insert(alias.clone(), active);
            app.refresh_tunnel_bind_ports();
            // Tunnel start spawns a real ssh session, same as a shell
            // connect, so record it in connection history.
            app.history.record(&alias);
            app.apply_sort();
            reposition_cursor_on(app, &alias, &rule);
            app.notify(crate::messages::tunnel_started(&alias));
        }
        Err(e) => {
            app.notify_error(crate::messages::tunnel_start_failed(&e));
        }
    }
}

/// After an action that may reorder the visible row list (toggle tunnel
/// changes the MostRecent sort key), park the cursor on the same logical
/// row the user acted on. Falls back to clamping into range if the row
/// vanished (e.g. directive removed concurrently).
pub(super) fn reposition_cursor_on(app: &mut App, alias: &str, rule: &TunnelRule) {
    let pairs = crate::ui::tunnels_overview::visible_pairs(app);
    if pairs.is_empty() {
        app.ui.tunnels_overview_state.select(None);
        return;
    }
    let new_idx = pairs
        .iter()
        .position(|(a, r)| a == alias && r == rule)
        .unwrap_or(0)
        .min(pairs.len() - 1);
    app.ui.tunnels_overview_state.select(Some(new_idx));
}

/// True when the host under the cursor lives in an included config file
/// and is therefore read-only from purple's perspective.
fn selected_row_is_included(app: &App) -> bool {
    let Some((alias, _)) = selected_row(app) else {
        return false;
    };
    app.hosts_state
        .list
        .iter()
        .find(|h| h.alias == alias)
        .map(|h| h.source_file.is_some())
        .unwrap_or(false)
}

/// Confirm-and-remove the tunnel currently under the cursor. Mirrors the
/// per-host TunnelList delete path so behaviour is identical regardless of
/// which screen launched the deletion.
fn confirm_delete_selected(app: &mut App) {
    let Some(sel) = app.tunnels.pending_delete.take() else {
        return;
    };
    // Resolve the host + rule pair anew: the data is rebuilt every frame so
    // the index stored in `pending_delete` was captured against the same
    // ordering used by `selected_row()`.
    let Some((alias, rule)) = nth_row(app, sel) else {
        app.notify_warning(crate::messages::TUNNEL_NOT_FOUND);
        return;
    };
    let directive_key = rule.tunnel_type.directive_key().to_string();
    let directive_value = rule.to_directive_value();
    let config_backup = app.hosts_state.ssh_config.clone();
    if !app
        .hosts_state
        .ssh_config
        .remove_forward(&alias, &directive_key, &directive_value)
    {
        app.notify_warning(crate::messages::TUNNEL_NOT_FOUND);
        return;
    }
    if let Err(e) = app.hosts_state.ssh_config.write() {
        app.hosts_state.ssh_config = config_backup;
        app.notify_error(crate::messages::failed_to_save(&e));
        return;
    }
    app.update_last_modified();
    app.reload_hosts();
    // Clamp cursor: row count shrinks by 1, so the previous selection may
    // sit past the new end.
    let total = row_count(app);
    if total == 0 {
        app.ui.tunnels_overview_state.select(None);
    } else if sel >= total {
        app.ui.tunnels_overview_state.select(Some(total - 1));
    }
    app.notify(crate::messages::TUNNEL_REMOVED);
}

/// Resolve the (alias, rule) pair at `target` using the same filtered +
/// sorted sequence the UI renders. Cursor indices captured in
/// `pending_delete` are walked against this list on confirmation.
fn nth_row(app: &App, target: usize) -> Option<(String, TunnelRule)> {
    crate::ui::tunnels_overview::visible_pairs(app)
        .into_iter()
        .nth(target)
}

/// Handle a key event while the user is on the Tunnels tab. Caller is
/// responsible for confirming `app.top_page == TopPage::Tunnels`.
pub(super) fn handle_keys(app: &mut App, key: KeyEvent) {
    // Pending delete confirmation is exclusive: only y/n/Esc are handled,
    // every other key is ignored so a stray press cannot silently cancel.
    if app.tunnels.pending_delete.is_some() {
        match super::route_confirm_key(key) {
            super::ConfirmAction::Yes => confirm_delete_selected(app),
            super::ConfirmAction::No => {
                app.tunnels.pending_delete = None;
            }
            super::ConfirmAction::Ignored => {}
        }
        return;
    }

    // Search-mode intercept: while a query is being typed, navigation keys
    // are forwarded into the query buffer rather than moving the cursor.
    if app.search.query.is_some() {
        handle_search_keys(app, key);
        return;
    }

    match key.code {
        KeyCode::Char('j') | KeyCode::Down => select_next(app),
        KeyCode::Char('k') | KeyCode::Up => select_prev(app),
        KeyCode::PageDown => {
            for _ in 0..10 {
                select_next(app);
            }
        }
        KeyCode::PageUp => {
            for _ in 0..10 {
                select_prev(app);
            }
        }
        KeyCode::Char('g') if row_count(app) > 0 => {
            app.ui.tunnels_overview_state.select(Some(0));
        }
        KeyCode::Char('G') => {
            let total = row_count(app);
            if total > 0 {
                app.ui.tunnels_overview_state.select(Some(total - 1));
            }
        }
        KeyCode::Char('/') => {
            // Enter search mode. Stays on the Tunnels tab; filtering
            // happens at row-build time in ui::tunnels_overview.
            app.search.query = Some(String::new());
            app.ui.tunnels_overview_state.select(Some(0));
        }
        KeyCode::Char('s') => {
            // Capture the row under the cursor BEFORE cycling so we can
            // re-anchor on it after sort. Resetting to index 0 makes the
            // detail panel flap open/closed when the new row-0 happens to
            // have a different active state than the previously-selected
            // one.
            let pinned = selected_row(app);
            app.tunnels.sort_mode = app.tunnels.sort_mode.next();
            match pinned {
                Some((alias, rule)) => reposition_cursor_on(app, &alias, &rule),
                None => app.ui.tunnels_overview_state.select(Some(0)),
            }
            app.notify(crate::messages::sorted_by(app.tunnels.sort_mode.label()));
        }
        KeyCode::Char(':') => {
            log::debug!("palette: opened from tunnels overview");
            app.palette = Some(crate::app::CommandPaletteState::for_mode(
                crate::app::PaletteMode::Tunnels,
            ));
        }
        KeyCode::Tab | KeyCode::BackTab => {
            app.top_page = TopPage::Hosts;
            app.search.query = None;
        }
        KeyCode::Char('a') => {
            // Add: route through host picker — the user has not yet picked
            // which host the tunnel belongs to.
            let editable = super::tunnel_host_picker::editable_aliases(app);
            if editable.is_empty() {
                app.notify_warning(crate::messages::TUNNEL_NO_EDITABLE_HOSTS);
                return;
            }
            app.ui.tunnel_host_picker_state.select(Some(0));
            app.ui.tunnel_host_picker_query.clear();
            app.set_screen(Screen::TunnelHostPicker);
        }
        KeyCode::Char('e') => {
            let Some((alias, rule)) = selected_row(app) else {
                return;
            };
            if selected_row_is_included(app) {
                app.notify_warning(crate::messages::TUNNEL_INCLUDED_READ_ONLY);
                return;
            }
            // The TunnelForm uses an `editing: Option<usize>` index into
            // `app.tunnels.list` (the per-host tunnel list). Refresh that
            // list for the chosen host and resolve the matching index so
            // the form's edit/save path operates on the right rule.
            app.refresh_tunnel_list(&alias);
            let editing_idx = app.tunnels.list.iter().position(|r| r == &rule);
            let Some(idx) = editing_idx else {
                app.notify_warning(crate::messages::TUNNEL_NOT_FOUND);
                return;
            };
            app.tunnels.form = crate::app::TunnelForm::from_rule(&rule);
            app.set_screen(Screen::TunnelForm {
                alias,
                editing: Some(idx),
            });
            app.capture_form_mtime();
            app.capture_tunnel_form_baseline();
        }
        KeyCode::Char('d') => {
            let Some(sel) = app.ui.tunnels_overview_state.selected() else {
                return;
            };
            if selected_row_is_included(app) {
                app.notify_warning(crate::messages::TUNNEL_INCLUDED_READ_ONLY);
                return;
            }
            if sel < row_count(app) {
                app.tunnels.pending_delete = Some(sel);
            }
        }
        KeyCode::Enter => toggle_tunnel(app),
        KeyCode::Char('n') => {
            // Same as host-list: dismiss the upgrade toast and open the
            // What's New overlay so release notes / changelog are
            // reachable from either main tab.
            super::whats_new::dismiss_whats_new_toast(app);
            app.set_screen(Screen::WhatsNew(crate::app::WhatsNewState::default()));
        }
        KeyCode::Char('?') => {
            // Open the help overlay; pressing ? again or Esc returns here.
            app.set_screen(Screen::Help {
                return_screen: Box::new(Screen::HostList),
            });
        }
        KeyCode::Esc | KeyCode::Char('q') => {
            app.running = false;
        }
        _ => {}
    }
}

/// Sub-handler used while the search query is being edited. Mirrors
/// the host-list search rhythm: navigation keys move the cursor
/// through the filtered set without leaving input mode, and `Enter`
/// confirms by acting on the highlighted row (start/stop) instead of
/// just dismissing the input. That keeps the muscle memory consistent
/// across the two main tabs — type, navigate, act, all without
/// leaving the search bar.
fn handle_search_keys(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.search.query = None;
            app.ui.tunnels_overview_state.select(Some(0));
        }
        KeyCode::Enter => {
            // Act on the highlighted row and dismiss the input. Re-
            // pressing `/` re-opens with an empty query.
            app.search.query = None;
            toggle_tunnel(app);
        }
        KeyCode::Down | KeyCode::Tab => select_next(app),
        KeyCode::Up | KeyCode::BackTab => select_prev(app),
        KeyCode::PageDown => {
            for _ in 0..10 {
                select_next(app);
            }
        }
        KeyCode::PageUp => {
            for _ in 0..10 {
                select_prev(app);
            }
        }
        KeyCode::Backspace => {
            if let Some(q) = app.search.query.as_mut() {
                q.pop();
            }
            app.ui.tunnels_overview_state.select(Some(0));
        }
        KeyCode::Char(c) => {
            if let Some(q) = app.search.query.as_mut() {
                q.push(c);
            }
            app.ui.tunnels_overview_state.select(Some(0));
        }
        _ => {}
    }
}
