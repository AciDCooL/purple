use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, Screen};

pub(super) fn handle_key(app: &mut App, key: KeyEvent) {
    let builtins = &app.ui.theme_picker.builtins;
    let custom = &app.ui.theme_picker.custom;
    let has_custom = !custom.is_empty();
    let divider_idx = if has_custom {
        Some(builtins.len())
    } else {
        None
    };
    let total = builtins.len() + if has_custom { 1 + custom.len() } else { 0 };

    if total == 0 {
        app.set_screen(Screen::HostList);
        return;
    }

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            // Restore the theme that was active when the picker opened
            if let Some(original) = app.ui.theme_picker.original.take() {
                crate::ui::theme::set_theme(original);
            }
            app.ui.theme_picker.reset();
            app.set_screen(Screen::HostList);
        }
        KeyCode::Char('?') => {
            let old = std::mem::replace(&mut app.screen, Screen::HostList);
            app.set_screen(Screen::Help {
                return_screen: Box::new(old),
            });
        }
        KeyCode::Char('j') | KeyCode::Down => {
            let current = app.ui.theme_picker.list.selected().unwrap_or(0);
            let mut next = current + 1;
            if next >= total {
                next = 0;
            }
            if divider_idx == Some(next) {
                next += 1;
                if next >= total {
                    next = 0;
                }
            }
            app.ui.theme_picker.list.select(Some(next));
            preview_theme_at_index(next, builtins, custom, divider_idx);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            let current = app.ui.theme_picker.list.selected().unwrap_or(0);
            let mut next = if current == 0 { total - 1 } else { current - 1 };
            if divider_idx == Some(next) {
                next = if next == 0 { total - 1 } else { next - 1 };
            }
            app.ui.theme_picker.list.select(Some(next));
            preview_theme_at_index(next, builtins, custom, divider_idx);
        }
        KeyCode::Enter => {
            if let Some(theme) = theme_at_index(
                app.ui.theme_picker.list.selected().unwrap_or(0),
                builtins,
                custom,
                divider_idx,
            ) {
                if !crate::demo_flag::is_demo() {
                    let _ = crate::preferences::save_theme(&theme.name);
                }
                crate::ui::theme::set_theme(theme);
            }
            app.ui.theme_picker.reset();
            app.ui.theme_picker.original = None;
            app.set_screen(Screen::HostList);
        }
        _ => {}
    }
}

fn preview_theme_at_index(
    idx: usize,
    builtins: &[crate::ui::theme::ThemeDef],
    custom: &[crate::ui::theme::ThemeDef],
    divider_idx: Option<usize>,
) {
    if let Some(theme) = theme_at_index(idx, builtins, custom, divider_idx) {
        crate::ui::theme::set_theme(theme);
    }
}

pub(super) fn theme_at_index(
    idx: usize,
    builtins: &[crate::ui::theme::ThemeDef],
    custom: &[crate::ui::theme::ThemeDef],
    divider_idx: Option<usize>,
) -> Option<crate::ui::theme::ThemeDef> {
    if idx < builtins.len() {
        return Some(builtins[idx].clone());
    }
    if let Some(div) = divider_idx {
        if idx == div {
            return None; // divider row
        }
        let custom_idx = idx - div - 1;
        return custom.get(custom_idx).cloned();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_config::model::SshConfigFile;
    use crate::ui::theme::ThemeDef;
    use crossterm::event::KeyModifiers;

    fn make_app_on_picker(builtins: Vec<ThemeDef>, custom: Vec<ThemeDef>) -> App {
        let scratch = tempfile::tempdir().expect("tempdir").keep();
        crate::preferences::set_path_override(scratch.join("preferences"));
        let config = SshConfigFile {
            elements: SshConfigFile::parse_content(""),
            path: scratch.join("test_config"),
            crlf: false,
            bom: false,
        };
        let mut app = App::new(config);
        app.screen = Screen::ThemePicker;
        app.ui.theme_picker.builtins = builtins;
        app.ui.theme_picker.custom = custom;
        app
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn dummy_theme(name: &str) -> ThemeDef {
        let mut t = crate::ui::theme::ThemeDef::purple_purple();
        t.name = name.to_string();
        t
    }

    #[test]
    fn empty_picker_returns_to_host_list_immediately() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app_on_picker(Vec::new(), Vec::new());
        handle_key(&mut app, k(KeyCode::Enter));
        assert!(matches!(app.screen, Screen::HostList));
    }

    #[test]
    fn esc_returns_to_host_list_and_clears_picker() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app_on_picker(vec![dummy_theme("a"), dummy_theme("b")], Vec::new());
        handle_key(&mut app, k(KeyCode::Esc));
        assert!(matches!(app.screen, Screen::HostList));
        assert!(app.ui.theme_picker.builtins.is_empty());
        assert!(app.ui.theme_picker.custom.is_empty());
    }

    #[test]
    fn enter_with_builtin_selection_sets_screen_and_clears_picker() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app_on_picker(vec![dummy_theme("a"), dummy_theme("b")], Vec::new());
        app.ui.theme_picker.list.select(Some(1));
        handle_key(&mut app, k(KeyCode::Enter));
        assert!(matches!(app.screen, Screen::HostList));
        assert!(app.ui.theme_picker.builtins.is_empty());
    }

    #[test]
    fn theme_at_index_returns_none_at_divider() {
        let builtins = vec![dummy_theme("a")];
        let custom = vec![dummy_theme("c1")];
        let divider_idx = Some(1);
        assert!(theme_at_index(1, &builtins, &custom, divider_idx).is_none());
    }

    #[test]
    fn theme_at_index_returns_custom_after_divider() {
        let builtins = vec![dummy_theme("a")];
        let custom = vec![dummy_theme("c1"), dummy_theme("c2")];
        let divider_idx = Some(1);
        let t = theme_at_index(2, &builtins, &custom, divider_idx).expect("custom theme");
        assert_eq!(t.name, "c1");
        let t = theme_at_index(3, &builtins, &custom, divider_idx).expect("custom theme");
        assert_eq!(t.name, "c2");
    }

    #[test]
    fn j_advances_selection_skipping_divider() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app_on_picker(vec![dummy_theme("a")], vec![dummy_theme("c1")]);
        app.ui.theme_picker.list.select(Some(0));
        handle_key(&mut app, k(KeyCode::Char('j')));
        assert_eq!(app.ui.theme_picker.list.selected(), Some(2));
    }
}
