use crossterm::event::{KeyCode, KeyEvent};
use std::sync::mpsc;

use crate::app::{App, JumpActionTarget, JumpHit, JumpMode, Screen, TopPage};
use crate::event::AppEvent;

pub(super) fn handle_jump(app: &mut App, key: KeyEvent, events_tx: &mpsc::Sender<AppEvent>) {
    if app.jump.is_none() {
        return;
    }

    match key.code {
        KeyCode::Esc => {
            log::debug!("jump: closed via Esc");
            app.jump = None;
        }
        KeyCode::Down => {
            if let Some(p) = app.jump.as_mut() {
                let count = p.visible_hits().len();
                if count > 0 {
                    if !p.cursor_revealed {
                        // First Down on a fresh empty state: just reveal
                        // the cursor on row 0. Subsequent Downs increment.
                        p.cursor_revealed = true;
                        p.selected = 0;
                    } else {
                        p.selected = (p.selected + 1).min(count - 1);
                    }
                }
            }
        }
        KeyCode::Up => {
            if let Some(p) = app.jump.as_mut() {
                if !p.cursor_revealed {
                    p.cursor_revealed = true;
                    p.selected = 0;
                } else {
                    p.selected = p.selected.saturating_sub(1);
                }
            }
        }
        KeyCode::Tab => {
            if let Some(p) = app.jump.as_mut() {
                p.cursor_revealed = true;
                p.jump_next_section();
            }
        }
        KeyCode::Enter => {
            // Force a recompute so direct state-poking tests, and any path
            // that mutated query without running through Char(c), see the
            // up-to-date hits before we read selection.
            app.recompute_jump_hits();
            let chosen = app
                .jump
                .as_ref()
                .and_then(|p| p.visible_hits().get(p.selected).cloned());
            if let Some(hit) = chosen {
                log::debug!("jump: dispatching {:?} via Enter", hit.identity());
                app.record_jump_hit(&hit);
                let mode = app.jump.as_ref().map(|p| p.mode).unwrap_or(JumpMode::Hosts);
                app.jump = None;
                dispatch_hit(app, &hit, mode, events_tx);
            }
        }
        KeyCode::Backspace => {
            let close = app
                .jump
                .as_ref()
                .map(|p| p.query.is_empty())
                .unwrap_or(true);
            if close {
                log::debug!("jump: closed via Backspace on empty query");
                app.jump = None;
            } else if let Some(p) = app.jump.as_mut() {
                p.pop_query();
                if p.query.is_empty() {
                    // Backspaced back to empty — re-hide the selection
                    // cue so the user re-lands on the input field.
                    p.cursor_revealed = false;
                    p.selected = 0;
                }
                app.recompute_jump_hits();
            }
        }
        KeyCode::Char(c) => {
            if let Some(p) = app.jump.as_mut() {
                p.push_query(c);
                // Typing reveals the cursor — once a query exists the
                // selection IS meaningful again. Empty-query state
                // re-suppresses the cursor on next render.
                p.cursor_revealed = true;
            }
            app.recompute_jump_hits();
        }
        _ => {}
    }
}

/// Route an Enter on a jump hit to the right destination. For actions
/// this is the existing key-dispatch shim; for data sources it switches
/// tab/screen and selects the matched item. Default action runs after the
/// jump (connect host, toggle tunnel, run snippet, open container detail).
fn dispatch_hit(app: &mut App, hit: &JumpHit, _mode: JumpMode, events_tx: &mpsc::Sender<AppEvent>) {
    match hit {
        JumpHit::Action(action) => execute_action(app, action, events_tx),
        JumpHit::Host(h) => {
            app.top_page = TopPage::Hosts;
            app.screen = Screen::HostList;
            app.select_host_by_alias(&h.alias);
            // Default action on a host: trigger the connect flow exactly like
            // pressing Enter on the host list.
            super::host_list::handle_host_list(
                app,
                KeyEvent::new(KeyCode::Enter, crossterm::event::KeyModifiers::NONE),
                events_tx,
            );
        }
        JumpHit::Tunnel(t) => {
            app.top_page = TopPage::Tunnels;
            app.screen = Screen::HostList;
            app.select_host_by_alias(&t.alias);
            // The tunnels overview reads its highlight from
            // `tunnels_overview_state`, NOT the host list. Compute the
            // matching row in the overview's visible_pairs and set the
            // ListState there so the cursor lands on the actual tunnel
            // the user picked.
            let pairs = crate::ui::tunnels_overview::visible_pairs(app);
            if let Some(idx) = pairs
                .iter()
                .position(|(alias, rule)| alias == &t.alias && rule.bind_port == t.bind_port)
            {
                app.ui.tunnels_overview_state.select(Some(idx));
            }
        }
        JumpHit::Container(c) => {
            app.top_page = TopPage::Hosts;
            app.select_host_by_alias(&c.alias);
            app.screen = Screen::Containers {
                alias: c.alias.clone(),
            };
        }
        JumpHit::Snippet(_s) => {
            // The snippet picker requires at least one target host. If the
            // user opened the jump bar with no host selected, surface a
            // warning instead of opening an unusable picker.
            let target: Vec<String> = app
                .selected_host()
                .map(|h| h.alias.clone())
                .into_iter()
                .collect();
            if target.is_empty() {
                app.notify_warning(crate::messages::PALETTE_SNIPPET_NEEDS_HOST);
                return;
            }
            app.screen = Screen::SnippetPicker {
                target_aliases: target,
            };
        }
    }
}

/// Execute a jump action by routing it to the handler indicated by the
/// action's `target`. Switches `top_page` first so cross-tab actions
/// (e.g. picking `Tunnels: Add tunnel` from the Hosts tab) land the user
/// on the right page before the synthetic keypress fires.
fn execute_action(
    app: &mut App,
    action: &crate::app::JumpAction,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    use crossterm::event::KeyModifiers;
    let key = KeyEvent::new(KeyCode::Char(action.key), KeyModifiers::NONE);
    match action.target {
        JumpActionTarget::Hosts => {
            app.top_page = TopPage::Hosts;
            super::host_list::handle_host_list(app, key, events_tx);
        }
        JumpActionTarget::Tunnels => {
            app.top_page = TopPage::Tunnels;
            super::tunnels_overview::handle_keys(app, key);
        }
    }
}
