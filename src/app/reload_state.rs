//! Auto-reload mtime tracking and form conflict mtimes.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::ssh_config::model::SshConfigFile;

/// Auto-reload mtime tracking.
#[derive(Default)]
pub struct ReloadState {
    pub(in crate::app) config_path: PathBuf,
    pub(in crate::app) last_modified: Option<SystemTime>,
    pub(in crate::app) include_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
    pub(in crate::app) include_dir_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
    /// mtime of `~/.ssh/` itself. Changes when a key file is created,
    /// renamed or removed; combined with `key_file_mtimes` this gives a
    /// full add/remove/modify signal without needing a real watcher.
    pub(in crate::app) keys_dir_mtime: Option<SystemTime>,
    /// mtime per known `*.pub` (or private) key path. Touch-only edits
    /// (re-encrypt, passphrase change) move the file mtime without
    /// touching the parent directory, so we track both.
    pub(in crate::app) key_file_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
}

/// Form conflict detection mtimes.
#[derive(Default)]
pub struct ConflictState {
    pub form_mtime: Option<SystemTime>,
    pub form_include_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
    pub form_include_dir_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
    pub provider_form_mtime: Option<SystemTime>,
}

impl ConflictState {
    /// Clear all form mtime state (call on form cancel or successful submit).
    pub fn clear_form_mtimes(&mut self) {
        self.form_mtime = None;
        self.form_include_mtimes.clear();
        self.form_include_dir_mtimes.clear();
        self.provider_form_mtime = None;
    }
}

/// True if the main config or any tracked Include file/directory changed since
/// the form's mtimes were captured. Returns false when no form mtime is set.
pub(crate) fn config_changed(conflict: &ConflictState, config_path: &Path) -> bool {
    match conflict.form_mtime {
        Some(open_mtime) => {
            if get_mtime(config_path) != Some(open_mtime) {
                return true;
            }
            conflict
                .form_include_mtimes
                .iter()
                .any(|(path, old_mtime)| get_mtime(path) != *old_mtime)
                || conflict
                    .form_include_dir_mtimes
                    .iter()
                    .any(|(path, old_mtime)| get_mtime(path) != *old_mtime)
        }
        None => false,
    }
}

impl ReloadState {
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Build from a loaded config: captures initial mtimes for the main file
    /// and every Include'd file and directory.
    pub fn from_config(config: &SshConfigFile) -> Self {
        let config_path = config.path.clone();
        let last_modified = get_mtime(&config_path);
        let include_mtimes = snapshot_include_mtimes(config);
        let include_dir_mtimes = snapshot_include_dir_mtimes(config);
        Self {
            config_path,
            last_modified,
            include_mtimes,
            include_dir_mtimes,
            keys_dir_mtime: None,
            key_file_mtimes: Vec::new(),
        }
    }
}

/// Get the modification time of a file.
pub fn get_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Snapshot mtimes of all resolved Include files.
pub fn snapshot_include_mtimes(config: &SshConfigFile) -> Vec<(PathBuf, Option<SystemTime>)> {
    config
        .include_paths()
        .into_iter()
        .map(|p| {
            let mtime = get_mtime(&p);
            (p, mtime)
        })
        .collect()
}

/// Snapshot mtimes of parent directories of Include glob patterns.
pub fn snapshot_include_dir_mtimes(config: &SshConfigFile) -> Vec<(PathBuf, Option<SystemTime>)> {
    config
        .include_glob_dirs()
        .into_iter()
        .map(|p| {
            let mtime = get_mtime(&p);
            (p, mtime)
        })
        .collect()
}

/// Snapshot the mtime of every discovered key's public-key file. The
/// caller passes the live `discover_keys` result; we resolve each
/// `display_path` (with the leading `~` expanded) back to an absolute
/// path under `ssh_dir` so we can stat it cheaply on each tick.
pub fn snapshot_key_mtimes(
    ssh_dir: &Path,
    keys: &[crate::ssh_keys::SshKeyInfo],
) -> Vec<(PathBuf, Option<SystemTime>)> {
    keys.iter()
        .map(|k| {
            let pub_path = ssh_dir.join(format!("{}.pub", k.name));
            let mtime = get_mtime(&pub_path);
            (pub_path, mtime)
        })
        .collect()
}
