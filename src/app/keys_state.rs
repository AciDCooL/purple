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
    pub list: Vec<SshKeyInfo>,
    /// Cursor in the Keys-tab master pane. `select()` index matches
    /// either `list` directly or `filtered_key_indices(list, query)`
    /// when a search query is active (translation happens at use sites).
    pub list_state: ListState,
    /// Persistent per-alias activity log. Loaded once at startup,
    /// appended on every connect, flushed to `~/.purple/key_activity.json`.
    /// Drives the activity chart and last-touch hints in the Keys tab.
    pub activity: KeyActivityLog,
    /// Push (ssh-copy-id equivalent) run state.
    pub push: KeyPushState,
}
