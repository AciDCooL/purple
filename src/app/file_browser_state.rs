use std::collections::HashMap;
use std::path::PathBuf;

/// Persistent per-host file-browser state: last-visited paths per alias.
#[derive(Debug, Default, Clone)]
pub struct FileBrowserState {
    pub(in crate::app) host_paths: HashMap<String, (PathBuf, String)>,
}

impl FileBrowserState {
    pub fn host_path(&self, alias: &str) -> Option<&(PathBuf, String)> {
        self.host_paths.get(alias)
    }

    pub fn contains_host(&self, alias: &str) -> bool {
        self.host_paths.contains_key(alias)
    }

    pub fn set_host_path(&mut self, alias: String, local: PathBuf, remote: String) {
        self.host_paths.insert(alias, (local, remote));
    }
}
