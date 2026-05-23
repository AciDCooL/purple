//! Consolidated Keys-tab state. Owns the discovered key list, the
//! cursor for the master pane, the persistent activity log, and the
//! in-flight push state.
//!
//! Mirrors the `TunnelState` / `ContainersOverviewState` pattern: one
//! sub-struct per top-level tab so the `App` god-struct stays flat and
//! every tab has a single field to consult, mutate, or snapshot.

use ratatui::widgets::ListState;

use super::KeyPushState;
use crate::key_activity::KeyActivityLog;
use crate::ssh_keys::SshKeyInfo;

#[derive(Default)]
pub struct KeysState {
    /// Discovered SSH key files under `~/.ssh/`. Populated by
    /// `ssh_keys::discover_keys` at startup, after host reloads, and
    /// after successful pushes. Empty until first discover completes.
    pub(in crate::app) list: Vec<SshKeyInfo>,
    /// Cursor in the Keys-tab master pane. `select()` index matches
    /// either `list` directly or `filtered_key_indices(list, query)`
    /// when a search query is active (translation happens at use sites).
    pub(in crate::app) list_state: ListState,
    /// Persistent per-alias activity log. Loaded once at startup,
    /// appended on every connect, flushed to `~/.purple/key_activity.json`.
    /// Drives the activity chart and last-touch hints in the Keys tab.
    pub(in crate::app) activity: KeyActivityLog,
    /// Push (ssh-copy-id equivalent) run state.
    pub(in crate::app) push: KeyPushState,
}

impl KeysState {
    pub fn list(&self) -> &Vec<SshKeyInfo> {
        &self.list
    }

    pub fn list_mut(&mut self) -> &mut Vec<SshKeyInfo> {
        &mut self.list
    }

    pub fn set_list(&mut self, list: Vec<SshKeyInfo>) {
        self.list = list;
    }

    pub fn list_state(&self) -> &ListState {
        &self.list_state
    }

    pub fn list_state_mut(&mut self) -> &mut ListState {
        &mut self.list_state
    }

    pub fn activity(&self) -> &KeyActivityLog {
        &self.activity
    }

    pub fn activity_mut(&mut self) -> &mut KeyActivityLog {
        &mut self.activity
    }

    pub fn set_activity(&mut self, activity: KeyActivityLog) {
        self.activity = activity;
    }

    pub fn push(&self) -> &KeyPushState {
        &self.push
    }

    pub fn push_mut(&mut self) -> &mut KeyPushState {
        &mut self.push
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> SshKeyInfo {
        SshKeyInfo {
            name: name.to_string(),
            display_path: format!("~/.ssh/{name}"),
            key_type: "ED25519".into(),
            bits: "256".into(),
            fingerprint: String::new(),
            comment: String::new(),
            linked_hosts: vec![],
            bishop_art: String::new(),
            strength_score: 90,
            encrypted: false,
            agent_loaded: false,
            is_certificate: false,
            mtime_ts: None,
        }
    }

    #[test]
    fn default_is_empty() {
        let s = KeysState::default();
        assert!(s.list().is_empty());
        assert!(s.list_state().selected().is_none());
    }

    #[test]
    fn set_list_replaces_contents() {
        let mut s = KeysState::default();
        s.set_list(vec![key("a")]);
        assert_eq!(s.list().len(), 1);
        s.set_list(vec![]);
        assert!(s.list().is_empty());
    }

    #[test]
    fn list_mut_allows_in_place_mutation() {
        let mut s = KeysState::default();
        s.list_mut().push(key("a"));
        assert_eq!(s.list().len(), 1);
    }

    #[test]
    fn list_state_mut_tracks_selection() {
        let mut s = KeysState::default();
        s.list_state_mut().select(Some(2));
        assert_eq!(s.list_state().selected(), Some(2));
    }
}
