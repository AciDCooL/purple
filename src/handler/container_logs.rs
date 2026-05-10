//! Key handler for the one-shot container logs overlay
//! (`Screen::ContainerLogs`). The overlay opens via `l` on the
//! containers tab and shows the last 200 lines of `<runtime> logs`
//! over a single SSH call. There is no live follow; refresh re-fires
//! the same call (`r`).

use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, ContainerLogsRequest, Screen};
use crate::event::AppEvent;

/// Number of trailing log lines requested per fetch. Sized to fit a
/// typical 50-row terminal twice over while keeping the SSH stream
/// bounded.
pub const DEFAULT_TAIL: usize = 200;

/// Scroll value that tail-anchors `body_len` lines in a `viewport_h`-row
/// area. Returns 0 when the body fits in the viewport so short logs
/// render flush-top without leaving blank rows below.
pub(crate) fn tail_scroll(body_len: usize, viewport_h: u16) -> u16 {
    body_len.saturating_sub(viewport_h as usize) as u16
}

pub(super) fn handle_keys(app: &mut App, key: KeyEvent, _events_tx: &mpsc::Sender<AppEvent>) {
    let Screen::ContainerLogs {
        body,
        scroll,
        alias,
        container_id,
        container_name,
        last_render_height,
        ..
    } = &mut app.screen
    else {
        return;
    };

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            log::debug!("[purple] container_logs: closed");
            app.set_screen(Screen::HostList);
        }
        KeyCode::Char('?') => {
            // Help dispatcher reads `app.top_page` to pick the
            // tab-specific help; the containers tab block already
            // documents `l logs`. Returning to HostList preserves
            // the tab the user was on.
            app.set_screen(Screen::Help {
                return_screen: Box::new(Screen::HostList),
            });
        }
        KeyCode::Char('j') | KeyCode::Down => {
            *scroll = scroll.saturating_add(1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            *scroll = scroll.saturating_sub(1);
        }
        KeyCode::PageDown => {
            *scroll = scroll.saturating_add(20);
        }
        KeyCode::PageUp => {
            *scroll = scroll.saturating_sub(20);
        }
        KeyCode::Char('g') => {
            *scroll = 0;
        }
        KeyCode::Char('G') => {
            // Tail-anchor: align the bottom of the body with the bottom
            // of the visible area so the most recent line sits at the
            // last visible row, with N preceding lines filling the gap.
            *scroll = tail_scroll(body.len(), *last_render_height);
        }
        KeyCode::Char('r') => {
            // Re-queue a fresh fetch with the same coordinates. Cleared
            // body + reset scroll so the loading indicator is visible
            // while the SSH call runs.
            let alias = alias.clone();
            let container_id = container_id.clone();
            let container_name = container_name.clone();
            requeue_logs_fetch(app, alias, container_id, container_name);
        }
        _ => {}
    }
}

fn requeue_logs_fetch(app: &mut App, alias: String, container_id: String, container_name: String) {
    let Some(entry) = app.container_cache.get(&alias) else {
        log::debug!(
            "[purple] container_logs: refresh aborted, no cache for alias={}",
            alias
        );
        return;
    };
    let runtime = entry.runtime;
    let askpass = app
        .hosts_state
        .list
        .iter()
        .find(|h| h.alias == alias)
        .and_then(|h| h.askpass.clone());

    if let Screen::ContainerLogs {
        body,
        scroll,
        error,
        fetched_at,
        ..
    } = &mut app.screen
    {
        body.clear();
        *scroll = 0;
        *error = None;
        *fetched_at = 0;
    }
    log::debug!(
        "[purple] container_logs: refresh queued alias={} id={}",
        alias,
        container_id
    );
    app.pending_container_logs = Some(ContainerLogsRequest {
        alias,
        askpass,
        runtime,
        container_id,
        container_name,
    });
}
