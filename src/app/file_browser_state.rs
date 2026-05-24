use std::collections::{HashMap, HashSet};
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

    /// Drop `host_paths` entries whose alias is no longer in
    /// `valid_aliases`. Called from `App::reload_hosts` so a host rename
    /// or delete cannot leave the old alias behind as a leaked entry.
    pub fn prune_orphans(&mut self, valid_aliases: &HashSet<&str>) {
        let pre = self.host_paths.len();
        self.host_paths
            .retain(|alias, _| valid_aliases.contains(alias.as_str()));
        let dropped = pre.saturating_sub(self.host_paths.len());
        if dropped > 0 {
            log::debug!(
                "[purple] reload_hosts: dropped {dropped} orphan file_browser host_paths entrie(s)"
            );
        }
    }

    /// Move the `host_paths` entry from `old` to `new` on host rename.
    /// Called from `App::migrate_alias_keyed_caches` before
    /// `reload_hosts`, whose prune step would otherwise drop the
    /// entry under the old alias. No-op when `old == new`.
    pub fn migrate_alias(&mut self, old: &str, new: &str) {
        if old == new {
            return;
        }
        if let Some(v) = self.host_paths.remove(old) {
            self.host_paths.insert(new.to_string(), v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_orphans_drops_unknown_aliases() {
        let mut s = FileBrowserState::default();
        s.set_host_path(
            "keep".to_string(),
            PathBuf::from("/a/b"),
            "remote".to_string(),
        );
        s.set_host_path(
            "drop".to_string(),
            PathBuf::from("/x/y"),
            "remote".to_string(),
        );

        let valid: HashSet<&str> = ["keep"].into_iter().collect();
        s.prune_orphans(&valid);

        assert!(s.contains_host("keep"));
        assert!(!s.contains_host("drop"));
    }

    #[test]
    fn migrate_alias_moves_host_path() {
        let mut s = FileBrowserState::default();
        s.set_host_path(
            "old".to_string(),
            PathBuf::from("/local"),
            "/remote".to_string(),
        );

        s.migrate_alias("old", "new");

        assert!(!s.contains_host("old"));
        assert!(s.contains_host("new"));
        let (local, remote) = s.host_path("new").expect("new alias must hold path");
        assert_eq!(local, &PathBuf::from("/local"));
        assert_eq!(remote, "/remote");
    }
}
