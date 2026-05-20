use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, BulkTagEditorState, Screen};

pub(super) fn handle_key(app: &mut App, key: KeyEvent) {
    // When the "new tag" input bar is active, route character input there
    // first so users can type tag names without triggering the row-level
    // keybindings (j/k/Space/Enter). Esc cancels the input without closing
    // the editor. The new-tag-input early-return runs BEFORE the discard
    // confirm so typing-mode Esc does not trigger the dirty check.
    if app.forms.bulk_tag_editor.new_tag_input.is_some() {
        handle_new_tag_input(app, key);
        return;
    }

    // Discard confirmation: when the user pressed Esc on a dirty editor, the
    // main handler armed the discard-confirm dialog and re-rendered with the
    // discard footer. Route the next keypress through the central confirm
    // router (uniform with form discard prompts elsewhere).
    if app.forms.is_discard_pending() {
        match super::route_confirm_key(key) {
            super::ConfirmAction::Yes => {
                app.forms.dismiss_discard_confirm();
                app.set_screen(Screen::HostList);
                app.forms.bulk_tag_editor = BulkTagEditorState::default();
            }
            super::ConfirmAction::No => {
                app.forms.dismiss_discard_confirm();
            }
            super::ConfirmAction::Ignored => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            // Stakes test: tag edits are non-trivial work (typing new tags,
            // deciding add/remove per row across N hosts). Warn before
            // discarding.
            if app.forms.bulk_tag_editor.is_dirty() {
                app.forms.request_discard_confirm();
            } else {
                app.set_screen(Screen::HostList);
                app.forms.bulk_tag_editor = BulkTagEditorState::default();
            }
        }
        KeyCode::Char('?') => {
            let old = std::mem::replace(&mut app.screen, Screen::HostList);
            app.set_screen(Screen::Help {
                return_screen: Box::new(old),
            });
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.bulk_tag_editor_next();
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.bulk_tag_editor_prev();
        }
        // SPACE GUARD MUST PRECEDE any generic Char(c) arm in this handler
        // so Space cycles the focused tag's tri-state rather than typing a
        // literal space into the new-tag input.
        KeyCode::Char(' ') => {
            app.bulk_tag_editor_cycle_current();
        }
        KeyCode::Char('+') => {
            app.forms.bulk_tag_editor.new_tag_input = Some(String::new());
            app.forms.bulk_tag_editor.new_tag_cursor = 0;
        }
        KeyCode::Enter => match app.bulk_tag_apply() {
            Ok(result) => {
                app.set_screen(Screen::HostList);
                app.forms.bulk_tag_editor = BulkTagEditorState::default();
                let msg = format_apply_status(&result);
                if !msg.is_empty() {
                    app.notify(msg);
                }
            }
            Err(err) => {
                app.notify_error(err);
            }
        },
        _ => {}
    }
}

/// Status string shown after a successful bulk apply. Empty when nothing
/// was pending (no-op) and no included-host warning applies, so the caller
/// can skip setting a status. Thin wrapper that funnels the formatting
/// through `crate::messages` to keep all user-facing copy in one place.
pub(crate) fn format_apply_status(result: &crate::app::BulkTagApplyResult) -> String {
    crate::messages::bulk_tag_apply_status(
        result.changed_hosts,
        result.added,
        result.removed,
        result.skipped_included,
    )
}

fn handle_new_tag_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            app.bulk_tag_editor_commit_new_tag();
        }
        KeyCode::Esc => {
            app.forms.bulk_tag_editor.new_tag_input = None;
            app.forms.bulk_tag_editor.new_tag_cursor = 0;
        }
        KeyCode::Left if app.forms.bulk_tag_editor.new_tag_cursor > 0 => {
            app.forms.bulk_tag_editor.new_tag_cursor -= 1;
        }
        KeyCode::Right => {
            if let Some(ref input) = app.forms.bulk_tag_editor.new_tag_input {
                if app.forms.bulk_tag_editor.new_tag_cursor < input.chars().count() {
                    app.forms.bulk_tag_editor.new_tag_cursor += 1;
                }
            }
        }
        KeyCode::Home => {
            app.forms.bulk_tag_editor.new_tag_cursor = 0;
        }
        KeyCode::End => {
            if let Some(ref input) = app.forms.bulk_tag_editor.new_tag_input {
                app.forms.bulk_tag_editor.new_tag_cursor = input.chars().count();
            }
        }
        KeyCode::Backspace if app.forms.bulk_tag_editor.new_tag_cursor > 0 => {
            if let Some(ref mut input) = app.forms.bulk_tag_editor.new_tag_input {
                let byte_pos =
                    crate::app::char_to_byte_pos(input, app.forms.bulk_tag_editor.new_tag_cursor);
                let prev = crate::app::char_to_byte_pos(
                    input,
                    app.forms.bulk_tag_editor.new_tag_cursor - 1,
                );
                input.drain(prev..byte_pos);
                app.forms.bulk_tag_editor.new_tag_cursor -= 1;
            }
        }
        KeyCode::Char(c) => {
            if let Some(ref mut input) = app.forms.bulk_tag_editor.new_tag_input {
                let byte_pos =
                    crate::app::char_to_byte_pos(input, app.forms.bulk_tag_editor.new_tag_cursor);
                input.insert(byte_pos, c);
                app.forms.bulk_tag_editor.new_tag_cursor += 1;
            }
        }
        _ => {}
    }
}
