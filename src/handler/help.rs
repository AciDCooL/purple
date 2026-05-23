use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, Screen};

pub(super) fn handle_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
            app.ui.help_scroll = 0;
            let return_screen = match std::mem::replace(&mut app.screen, Screen::HostList) {
                Screen::Help { return_screen } => *return_screen,
                _ => Screen::HostList,
            };
            app.set_screen(return_screen);
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.ui.help_scroll = app.ui.help_scroll.saturating_add(1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.ui.help_scroll = app.ui.help_scroll.saturating_sub(1);
        }
        KeyCode::PageDown => {
            app.ui.help_scroll = app.ui.help_scroll.saturating_add(10);
        }
        KeyCode::PageUp => {
            app.ui.help_scroll = app.ui.help_scroll.saturating_sub(10);
        }
        _ => {}
    }
}

pub(super) fn handle_key_list_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('K') => {
            app.set_screen(Screen::HostList);
        }
        KeyCode::Char('?') => {
            let old = std::mem::replace(&mut app.screen, Screen::HostList);
            app.set_screen(Screen::Help {
                return_screen: Box::new(old),
            });
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.select_next_key();
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.select_prev_key();
        }
        KeyCode::PageDown => {
            let len = app.keys.list().len();
            crate::app::page_down(app.keys.list_state_mut(), len, 10);
        }
        KeyCode::PageUp => {
            let len = app.keys.list().len();
            crate::app::page_up(app.keys.list_state_mut(), len, 10);
        }
        KeyCode::Enter => {
            if let Some(index) = app.keys.list_state().selected() {
                if index < app.keys.list().len() {
                    app.set_screen(Screen::KeyDetail { index });
                }
            }
        }
        _ => {}
    }
}

pub(super) fn handle_key_detail_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.set_screen(Screen::KeyList);
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
