use std::collections::HashMap;
use std::path::PathBuf;

/// Persistent per-host file-browser state: last-visited paths per alias.
#[derive(Debug, Default, Clone)]
pub struct FileBrowserState {
    pub host_paths: HashMap<String, (PathBuf, String)>,
}
