use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, Screen};

pub(super) fn handle_key(app: &mut App, key: KeyEvent) {
    let Screen::Welcome {
        known_hosts_count, ..
    } = &app.screen
    else {
        return;
    };
    let known_hosts_count = *known_hosts_count;

    // Closing Welcome seeds last_seen_version so future launches do not re-trigger the upgraded flow.
    let version = env!("CARGO_PKG_VERSION");
    if let Err(e) = crate::preferences::save_last_seen_version(version) {
        log::warn!("[purple] failed to seed last_seen_version on welcome close: {e}");
    }
    if key.code == KeyCode::Char('?') {
        app.set_screen(Screen::Help {
            return_screen: Box::new(Screen::HostList),
        });
    } else if key.code == KeyCode::Char('I') && known_hosts_count > 0 {
        app.set_screen(Screen::HostList);
        super::confirm::execute_known_hosts_import(app);
    } else {
        app.set_screen(Screen::HostList);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_config::model::SshConfigFile;
    use crossterm::event::KeyModifiers;

    fn make_app_on_welcome(known_hosts_count: usize) -> App {
        let scratch = tempfile::tempdir().expect("tempdir").keep();
        crate::preferences::set_path_override(scratch.join("preferences"));
        let config = SshConfigFile {
            elements: SshConfigFile::parse_content(""),
            path: scratch.join("test_config"),
            crlf: false,
            bom: false,
        };
        let mut app = App::new(config);
        app.screen = Screen::Welcome {
            has_backup: false,
            host_count: 0,
            known_hosts_count,
        };
        app
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn question_key_opens_help() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app_on_welcome(0);
        handle_key(&mut app, k(KeyCode::Char('?')));
        assert!(matches!(app.screen, Screen::Help { .. }));
    }

    #[test]
    fn any_other_key_returns_to_host_list() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app_on_welcome(0);
        handle_key(&mut app, k(KeyCode::Esc));
        assert!(matches!(app.screen, Screen::HostList));
    }

    #[test]
    fn capital_i_with_zero_known_hosts_just_dismisses() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app_on_welcome(0);
        handle_key(&mut app, k(KeyCode::Char('I')));
        assert!(matches!(app.screen, Screen::HostList));
    }

    #[test]
    fn capital_i_with_known_hosts_triggers_import_path() {
        // ENV_LOCK serialises HOME/PATH env mutation across the test binary.
        let _path_guard = crate::vault_ssh::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let old_home = std::env::var("HOME").ok();
        let home = tempfile::tempdir().expect("tempdir").keep();
        // SAFETY: ENV_LOCK held above serializes env mutation in this test
        // binary; HOME is restored below before the lock drops.
        unsafe {
            std::env::set_var("HOME", &home);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut app = make_app_on_welcome(1);
            handle_key(&mut app, k(KeyCode::Char('I')));
            assert!(matches!(app.screen, Screen::HostList));
            assert!(
                app.status_center.toast().is_some() || app.status_center.status().is_some(),
                "I-key with known_hosts_count > 0 must attempt import and emit a status"
            );
        }));
        // SAFETY: ENV_LOCK still held; restore prior HOME before lock drops.
        unsafe {
            match old_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}
