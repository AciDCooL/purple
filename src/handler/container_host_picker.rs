//! Host picker reached from the containers overview when adding a
//! host to the container cache (`a` keypress).
//!
//! Lists every host in the SSH config that does NOT already have a
//! cache entry. On Enter, fires one `docker ps` listing for the
//! chosen host and returns to the overview. Mirrors the tunnel host
//! picker's "type to filter" rhythm so muscle memory carries over.

use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Screen};
use crate::event::AppEvent;

/// Aliases of every host that has no cache entry yet, in display
/// order. The picker's `a`-flow is for *adding* — already-cached
/// hosts use `r`/`R` instead — so they are filtered out here.
pub(crate) fn uncached_aliases(app: &App) -> Vec<String> {
    app.hosts_state
        .list
        .iter()
        .filter(|h| !app.container_state.cache.contains_key(&h.alias))
        .map(|h| h.alias.clone())
        .collect()
}

/// Hosts that match the live query, paired with the matching hostname
/// for display. Same case-insensitive substring match the tunnel host
/// picker uses.
pub(crate) fn filtered_hosts(app: &App) -> Vec<(String, String)> {
    let query = app.ui.container_host_picker_query.to_lowercase();
    app.hosts_state
        .list
        .iter()
        .filter(|h| !app.container_state.cache.contains_key(&h.alias))
        .filter(|h| {
            if query.is_empty() {
                return true;
            }
            h.alias.to_lowercase().contains(&query) || h.hostname.to_lowercase().contains(&query)
        })
        .map(|h| (h.alias.clone(), h.hostname.clone()))
        .collect()
}

pub(super) fn handle_key(app: &mut App, key: KeyEvent, events_tx: &mpsc::Sender<AppEvent>) {
    let total = filtered_hosts(app).len();
    match key.code {
        KeyCode::Esc => close(app),
        KeyCode::Down if total > 0 => {
            let cur = app.ui.container_host_picker_state.selected().unwrap_or(0);
            let next = (cur + 1).min(total - 1);
            app.ui.container_host_picker_state.select(Some(next));
        }
        KeyCode::Up => {
            let cur = app.ui.container_host_picker_state.selected().unwrap_or(0);
            app.ui
                .container_host_picker_state
                .select(Some(cur.saturating_sub(1)));
        }
        KeyCode::Enter => {
            let Some(idx) = app.ui.container_host_picker_state.selected() else {
                return;
            };
            let Some((alias, _)) = filtered_hosts(app).into_iter().nth(idx) else {
                return;
            };
            close(app);
            spawn_initial_listing(app, alias, events_tx);
        }
        KeyCode::Backspace => {
            if app.ui.container_host_picker_query.is_empty() {
                close(app);
            } else {
                app.ui.container_host_picker_query.pop();
                reset_cursor_after_query_change(app);
            }
        }
        KeyCode::Char(c)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && app.ui.container_host_picker_query.len() < 64 =>
        {
            app.ui.container_host_picker_query.push(c);
            reset_cursor_after_query_change(app);
        }
        _ => {}
    }
}

fn close(app: &mut App) {
    app.ui.container_host_picker_state.select(None);
    app.ui.container_host_picker_query.clear();
    app.set_screen(Screen::HostList);
}

fn reset_cursor_after_query_change(app: &mut App) {
    let total = filtered_hosts(app).len();
    if total == 0 {
        app.ui.container_host_picker_state.select(None);
    } else {
        app.ui.container_host_picker_state.select(Some(0));
    }
}

/// Fire the first `docker ps` for `alias`. No cached runtime → the
/// listing command runs the sentinel-detection variant. Mirrors the
/// `C`-on-host-list flow exactly except for the surrounding flow
/// control (we are coming from the picker, not the host list).
fn spawn_initial_listing(app: &mut App, alias: String, events_tx: &mpsc::Sender<AppEvent>) {
    let askpass = app
        .hosts_state
        .list
        .iter()
        .find(|h| h.alias == alias)
        .and_then(|h| h.askpass.clone());
    let has_tunnel = app.tunnels.active.contains_key(&alias);
    log::debug!("[purple] container cache add: alias={}", alias);
    app.notify(crate::messages::container_refreshing(&alias));
    // Mark in-flight so the post-key auto-refresh does not spawn a
    // second `docker ps` for the same alias before this one returns.
    app.containers_overview
        .auto_list_in_flight
        .insert(alias.clone());
    let ctx = crate::ssh_context::OwnedSshContext {
        alias,
        config_path: app.reload.config_path.clone(),
        askpass,
        bw_session: app.bw_session.clone(),
        has_tunnel,
    };
    let tx = events_tx.clone();
    crate::containers::spawn_container_listing(ctx, None, move |a, result| {
        let _ = tx.send(AppEvent::ContainerListing { alias: a, result });
    });
}
