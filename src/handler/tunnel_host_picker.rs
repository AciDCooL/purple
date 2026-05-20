//! Host picker reached from the Tunnels overview when adding a new tunnel.
//!
//! Lists all editable hosts (hosts that live in the user's own SSH config,
//! not in an included file). Always-on filter input — every printable
//! keystroke appends to the query and the candidate set shrinks live, using
//! the same case-insensitive substring match the jump uses.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Screen};

/// Editable hosts visible in the picker, in display order.
///
/// Mirrors the filter applied in `handler::tunnel::handle_tunnel_list` for
/// add/edit/delete: hosts whose `source_file` is `Some(_)` originate from an
/// `Include` directive and cannot be mutated through purple.
pub(crate) fn editable_aliases(app: &App) -> Vec<String> {
    app.hosts_state
        .list
        .iter()
        .filter(|h| h.source_file.is_none())
        .map(|h| h.alias.clone())
        .collect()
}

/// Hosts that match the live query, paired with the matching hostname for
/// display. When the query is empty every editable host is returned.
///
/// Match rule mirrors `JumpState::filtered_commands`:
/// case-insensitive substring search. Same predictable semantics across
/// every "type to filter" overlay in the app.
pub(crate) fn filtered_hosts(app: &App) -> Vec<(String, String)> {
    let query = app.ui.tunnel_host_picker_query.to_lowercase();
    app.hosts_state
        .list
        .iter()
        .filter(|h| h.source_file.is_none())
        .filter(|h| {
            if query.is_empty() {
                return true;
            }
            h.alias.to_lowercase().contains(&query) || h.hostname.to_lowercase().contains(&query)
        })
        .map(|h| (h.alias.clone(), h.hostname.clone()))
        .collect()
}

pub(super) fn handle_key(app: &mut App, key: KeyEvent) {
    let total = filtered_hosts(app).len();
    match key.code {
        KeyCode::Esc => close(app),
        KeyCode::Down if total > 0 => {
            let cur = app.ui.tunnel_host_picker_state.selected().unwrap_or(0);
            let next = (cur + 1).min(total - 1);
            app.ui.tunnel_host_picker_state.select(Some(next));
        }
        KeyCode::Up => {
            let cur = app.ui.tunnel_host_picker_state.selected().unwrap_or(0);
            app.ui
                .tunnel_host_picker_state
                .select(Some(cur.saturating_sub(1)));
        }
        KeyCode::Enter => {
            let Some(idx) = app.ui.tunnel_host_picker_state.selected() else {
                return;
            };
            let Some((alias, _)) = filtered_hosts(app).into_iter().nth(idx) else {
                return;
            };
            app.ui.tunnel_host_picker_state.select(None);
            app.ui.tunnel_host_picker_query.clear();
            app.open_tunnel_add_form(alias);
        }
        KeyCode::Backspace => {
            // Mirror the jump: Backspace on an empty query
            // closes the overlay; otherwise it shortens the query.
            if app.ui.tunnel_host_picker_query.is_empty() {
                close(app);
            } else {
                app.ui.tunnel_host_picker_query.pop();
                reset_cursor_after_query_change(app);
            }
        }
        KeyCode::Char(c)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && app.ui.tunnel_host_picker_query.len() < 64 =>
        {
            // Cap the query length so a stuck key cannot grow the buffer
            // unbounded. Same 64-char cap the jump uses.
            app.ui.tunnel_host_picker_query.push(c);
            reset_cursor_after_query_change(app);
        }
        _ => {}
    }
}

fn close(app: &mut App) {
    app.ui.tunnel_host_picker_state.select(None);
    app.ui.tunnel_host_picker_query.clear();
    app.set_screen(Screen::HostList);
}

/// After the candidate set shrinks or grows, snap the cursor to row 0 (or
/// `None` when the set is empty) so the highlight always sits on a real row.
fn reset_cursor_after_query_change(app: &mut App) {
    let total = filtered_hosts(app).len();
    if total == 0 {
        app.ui.tunnel_host_picker_state.select(None);
    } else {
        app.ui.tunnel_host_picker_state.select(Some(0));
    }
}
