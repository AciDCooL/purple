use std::sync::mpsc;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, Screen};
use crate::event::AppEvent;

/// Build `ContainerSession` from cache, switch to `Screen::Containers`, and
/// (unless in demo mode) spawn the background SSH listing thread. Shared
/// by every entry point that opens the per-host containers overlay
/// (`C` on the host list, `Enter` on the containers overview tab) so the
/// state setup cannot drift between callers. Stale-host warnings stay at
/// the call site since they depend on cursor-resolved metadata the
/// caller already has in scope.
pub(super) fn open_overlay_for_host(
    app: &mut App,
    alias: String,
    askpass: Option<String>,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    let (cached_runtime, cached_containers) =
        if let Some(entry) = app.container_state.cache_entry(&alias) {
            (Some(entry.runtime), entry.containers.clone())
        } else {
            (None, Vec::new())
        };
    let mut list_state = ratatui::widgets::ListState::default();
    if !cached_containers.is_empty() {
        list_state.select(Some(0));
    }
    app.container_session = Some(crate::app::ContainerSession {
        alias: alias.clone(),
        askpass: askpass.clone(),
        runtime: cached_runtime,
        containers: cached_containers,
        list_state,
        loading: !app.demo_mode,
        error: None,
        action_in_progress: None,
        confirm_action: None,
    });
    app.set_screen(Screen::Containers {
        alias: alias.clone(),
    });
    if !app.demo_mode {
        let has_tunnel = app.tunnels.active_contains(&alias);
        // Mark in-flight so `ensure_list_for_selected_host` will not
        // double-spawn if the user Tabs to the Containers tab before
        // this listing returns.
        app.containers_overview
            .mark_auto_list_pending(alias.clone());
        let ctx = crate::ssh_context::OwnedSshContext {
            alias,
            config_path: app.reload.config_path().to_path_buf(),
            askpass,
            bw_session: app.bw_session.clone(),
            has_tunnel,
        };
        let tx = events_tx.clone();
        crate::containers::spawn_container_listing(ctx, cached_runtime, move |a, result| {
            let _ = tx.send(AppEvent::ContainerListing { alias: a, result });
        });
    }
}

pub(super) fn handle_key(
    app: &mut App,
    key: KeyEvent,
    events_tx: &mpsc::Sender<AppEvent>,
) -> Result<()> {
    // Handle pending container-action confirmation via the shared confirm
    // router. `?` (help) is the only key allowed to bypass the confirm gate;
    // every other key routes through route_confirm_key so a misplaced
    // keypress can never silently cancel or execute a destructive action.
    // `q` is intentionally not whitelisted here: in confirm-context it must
    // be Ignored, not treated as cancel.
    let confirm_pending = app
        .container_session
        .as_ref()
        .is_some_and(|s| s.confirm_action.is_some());
    if confirm_pending && key.code != KeyCode::Char('?') {
        match super::route_confirm_key(key) {
            super::ConfirmAction::Yes => {
                let taken = app
                    .container_session
                    .as_mut()
                    .and_then(|s| s.confirm_action.take());
                if let Some((action, _name, _id)) = taken {
                    container_action(app, events_tx, action);
                }
            }
            super::ConfirmAction::No => {
                if let Some(ref mut state) = app.container_session {
                    state.confirm_action = None;
                }
            }
            super::ConfirmAction::Ignored => {}
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            // No confirm pending (the early-return above handles that case):
            // close the overlay.
            app.container_session = None;
            app.set_screen(Screen::HostList);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if let Some(ref mut state) = app.container_session {
                let len = state.containers.len();
                if len > 0 {
                    let i = state.list_state.selected().unwrap_or(0);
                    state
                        .list_state
                        .select(Some(if i == 0 { len - 1 } else { i - 1 }));
                }
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if let Some(ref mut state) = app.container_session {
                let len = state.containers.len();
                if len > 0 {
                    let i = state.list_state.selected().unwrap_or(0);
                    state
                        .list_state
                        .select(Some(if i + 1 >= len { 0 } else { i + 1 }));
                }
            }
        }
        KeyCode::PageDown => {
            if let Some(ref mut state) = app.container_session {
                let len = state.containers.len();
                if len > 0 {
                    let i = state.list_state.selected().unwrap_or(0);
                    state.list_state.select(Some((i + 10).min(len - 1)));
                }
            }
        }
        KeyCode::PageUp => {
            if let Some(ref mut state) = app.container_session {
                let len = state.containers.len();
                if len > 0 {
                    let i = state.list_state.selected().unwrap_or(0);
                    state.list_state.select(Some(i.saturating_sub(10)));
                }
            }
        }
        KeyCode::Char('s') => {
            container_action(app, events_tx, crate::containers::ContainerAction::Start);
        }
        KeyCode::Char('x') => {
            // Stop requires confirmation
            if let Some(ref mut state) = app.container_session {
                if state.action_in_progress.is_some() || state.confirm_action.is_some() {
                    return Ok(());
                }
                if let Some(idx) = state.list_state.selected() {
                    if let Some(container) = state.containers.get(idx) {
                        state.confirm_action = Some((
                            crate::containers::ContainerAction::Stop,
                            container.names.clone(),
                            container.id.clone(),
                        ));
                    }
                }
            }
        }
        KeyCode::Char('r') => {
            // Restart requires confirmation
            if let Some(ref mut state) = app.container_session {
                if state.action_in_progress.is_some() || state.confirm_action.is_some() {
                    return Ok(());
                }
                if let Some(idx) = state.list_state.selected() {
                    if let Some(container) = state.containers.get(idx) {
                        state.confirm_action = Some((
                            crate::containers::ContainerAction::Restart,
                            container.names.clone(),
                            container.id.clone(),
                        ));
                    }
                }
            }
        }
        KeyCode::Char('R') => {
            // Refresh container list
            if app.demo_mode {
                app.notify_warning(crate::messages::DEMO_CONTAINER_REFRESH_DISABLED);
                return Ok(());
            }
            if let Some(ref mut state) = app.container_session {
                if state.action_in_progress.is_some() {
                    return Ok(());
                }
                state.loading = true;
                state.error = None;
                let alias = state.alias.clone();
                let cached_runtime = state.runtime;
                let ctx = crate::ssh_context::OwnedSshContext {
                    alias: alias.clone(),
                    config_path: app.reload.config_path().to_path_buf(),
                    askpass: state.askpass.clone(),
                    bw_session: app.bw_session.clone(),
                    has_tunnel: app.tunnels.active_contains(&alias),
                };
                let tx = events_tx.clone();
                crate::containers::spawn_container_listing(
                    ctx,
                    cached_runtime,
                    move |a, result| {
                        let _ = tx.send(AppEvent::ContainerListing { alias: a, result });
                    },
                );
            }
        }
        KeyCode::Char('?') => {
            let old = std::mem::replace(&mut app.screen, Screen::HostList);
            app.set_screen(Screen::Help {
                return_screen: Box::new(old),
            });
        }
        _ => {}
    }
    Ok(())
}

fn container_action(
    app: &mut App,
    events_tx: &mpsc::Sender<AppEvent>,
    action: crate::containers::ContainerAction,
) {
    let Some(ref mut state) = app.container_session else {
        return;
    };
    if state.action_in_progress.is_some() {
        return;
    }
    let Some(idx) = state.list_state.selected() else {
        return;
    };
    let Some(container) = state.containers.get(idx) else {
        return;
    };
    if crate::containers::validate_container_id(&container.id).is_err() {
        return;
    }
    if app.demo_mode {
        app.notify_warning(crate::messages::DEMO_CONTAINER_ACTIONS_DISABLED);
        return;
    }
    let Some(runtime) = state.runtime else {
        return;
    };
    let container_id = container.id.clone();
    let container_name = container.names.clone();
    state.action_in_progress = Some(format!("{} {}...", action.as_str(), container_name));
    let alias = state.alias.clone();
    let ctx = crate::ssh_context::OwnedSshContext {
        alias: alias.clone(),
        config_path: app.reload.config_path().to_path_buf(),
        askpass: state.askpass.clone(),
        bw_session: app.bw_session.clone(),
        has_tunnel: app.tunnels.active_contains(&alias),
    };
    let tx = events_tx.clone();
    crate::containers::spawn_container_action(
        ctx,
        runtime,
        action,
        container_id,
        move |a, act, result| {
            let _ = tx.send(AppEvent::ContainerActionComplete {
                alias: a,
                action: act,
                result,
            });
        },
    );
}
