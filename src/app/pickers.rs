//! Overlay picker lifecycle. Implements `impl App` continuation with
//! open/close domain actions for every `.open`-flag-based picker overlay
//! (password, key, proxyjump, vault_role, region). Screen-based pickers
//! (TagPicker, ThemePicker, SnippetPicker, etc.) live in `selection.rs`.

use ratatui::widgets::ListState;

use crate::app::App;

impl App {
    /// Close the password picker overlay.
    pub fn close_password_picker(&mut self) {
        log::debug!("[purple] close_password_picker");
        self.ui.password_picker.open = false;
    }

    /// Close the key picker overlay.
    pub fn close_key_picker(&mut self) {
        log::debug!("[purple] close_key_picker");
        self.ui.key_picker.open = false;
    }

    /// Close the ProxyJump picker overlay.
    pub fn close_proxyjump_picker(&mut self) {
        log::debug!("[purple] close_proxyjump_picker");
        self.ui.proxyjump_picker.open = false;
    }

    /// Close the Vault SSH role picker overlay.
    pub fn close_vault_role_picker(&mut self) {
        log::debug!("[purple] close_vault_role_picker");
        self.ui.vault_role_picker.open = false;
    }

    /// Close the provider region picker overlay.
    pub fn close_region_picker(&mut self) {
        log::debug!("[purple] close_region_picker");
        self.ui.region_picker.open = false;
    }

    /// Open the password picker overlay focused on the first source.
    pub fn open_password_picker(&mut self) {
        log::debug!("[purple] open_password_picker");
        self.ui.password_picker.open = true;
        self.ui.password_picker.list = ListState::default();
        self.ui.password_picker.list.select(Some(0));
    }

    /// Open the key picker overlay. Rescans `~/.ssh` first so the list
    /// reflects keys added since the form was opened, then selects the
    /// first key when at least one was discovered.
    pub fn open_key_picker(&mut self) {
        log::debug!("[purple] open_key_picker");
        self.scan_keys();
        self.ui.key_picker.open = true;
        self.ui.key_picker.list = ListState::default();
        if !self.keys.list.is_empty() {
            self.ui.key_picker.list.select(Some(0));
        }
    }

    /// Open the ProxyJump picker overlay. The opening cursor lands on the
    /// first host row rather than the first list entry, so separator/header
    /// rows above the host list do not steal initial focus.
    pub fn open_proxyjump_picker(&mut self) {
        log::debug!("[purple] open_proxyjump_picker");
        self.ui.proxyjump_picker.open = true;
        self.ui.proxyjump_picker.list = ListState::default();
        if let Some(idx) = self.proxyjump_first_host_index() {
            self.ui.proxyjump_picker.list.select(Some(idx));
        }
    }

    /// Open the Vault SSH role picker. The caller is responsible for
    /// guarding against an empty candidate list; this method assumes at
    /// least one role and selects the first.
    pub fn open_vault_role_picker(&mut self) {
        log::debug!("[purple] open_vault_role_picker");
        self.ui.vault_role_picker.open = true;
        self.ui.vault_role_picker.list = ListState::default();
        self.ui.vault_role_picker.list.select(Some(0));
    }

    /// Open the provider region picker overlay with the cursor on the
    /// first row. Region picker uses a `cursor: usize` rather than a
    /// ratatui `ListState` because its rows are a synthetic flat array.
    pub fn open_region_picker(&mut self) {
        log::debug!("[purple] open_region_picker");
        self.ui.region_picker.open = true;
        self.ui.region_picker.cursor = 0;
    }
}
