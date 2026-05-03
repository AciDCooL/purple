use crossterm::event::{KeyCode, KeyEvent};
use std::sync::mpsc;

use crate::app::{App, PaletteMode};
use crate::event::AppEvent;

pub(super) fn handle_command_palette(
    app: &mut App,
    key: KeyEvent,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    let palette = match app.palette.as_mut() {
        Some(p) => p,
        None => return,
    };

    match key.code {
        KeyCode::Esc => {
            log::debug!("palette: closed via Esc");
            app.palette = None;
        }
        KeyCode::Down => {
            let count = palette.filtered_commands().len();
            if count > 0 {
                palette.selected = (palette.selected + 1).min(count - 1);
            }
        }
        KeyCode::Up => {
            palette.selected = palette.selected.saturating_sub(1);
        }
        KeyCode::Enter => {
            let filtered = palette.filtered_commands();
            let clamped = palette.selected.min(filtered.len().saturating_sub(1));
            if let Some(cmd) = filtered.get(clamped) {
                let key_char = cmd.key;
                let mode = palette.mode;
                log::debug!(
                    "palette: executing '{}' ({}) via Enter (mode={:?})",
                    key_char,
                    cmd.label,
                    mode
                );
                app.palette = None;
                execute_command(app, key_char, mode, events_tx);
            }
        }
        KeyCode::Backspace => {
            if palette.query.is_empty() {
                log::debug!("palette: closed via Backspace on empty query");
                app.palette = None;
            } else {
                palette.pop_query();
            }
        }
        KeyCode::Char(c) => {
            palette.push_query(c);
        }
        _ => {}
    }
}

/// Execute a palette command by dispatching to the handler matching the
/// screen the palette was opened from.
fn execute_command(
    app: &mut App,
    key_char: char,
    mode: PaletteMode,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    use crossterm::event::KeyModifiers;
    let key = KeyEvent::new(KeyCode::Char(key_char), KeyModifiers::NONE);
    match mode {
        PaletteMode::Hosts => super::host_list::handle_host_list(app, key, events_tx),
        PaletteMode::Tunnels => super::tunnels_overview::handle_keys(app, key),
    }
}
