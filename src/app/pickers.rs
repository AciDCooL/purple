//! Overlay picker lifecycle. Implements `impl App` continuation with
//! open/close domain actions for every `.open`-flag-based picker overlay
//! (password, key, proxyjump, vault_role, region). Screen-based pickers
//! (TagPicker, ThemePicker, SnippetPicker, etc.) live in `selection.rs`.

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
}
