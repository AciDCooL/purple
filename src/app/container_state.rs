//! Containers overlay state.

use crate::app::{ContainerActionRequest, ContainerExecRequest, ContainerLogsRequest};

/// Per-host overlay session state; only valid while the containers overlay is open.
///
/// No `Default` impl: construction always requires an alias and runtime
/// metadata, so a default-constructed value would be meaningless.
pub struct ContainerSession {
    pub alias: String,
    pub askpass: Option<String>,
    pub runtime: Option<crate::containers::ContainerRuntime>,
    pub containers: Vec<crate::containers::ContainerInfo>,
    pub list_state: ratatui::widgets::ListState,
    pub loading: bool,
    pub error: Option<String>,
    pub action_in_progress: Option<String>,
    /// Pending confirmation for stop/restart actions: (action, container_name, container_id).
    pub confirm_action: Option<(crate::containers::ContainerAction, String, String)>,
}

/// Always-present container-domain state: cache and cross-host pending operations.
/// Separate from `ContainerSession`, which is the per-host overlay session state.
#[derive(Debug, Default)]
pub struct ContainerState {
    pub pending_exec: Option<ContainerExecRequest>,
    pub pending_logs: Option<ContainerLogsRequest>,
    pub pending_actions: std::collections::VecDeque<ContainerActionRequest>,
    pub pending_fetch_aliases: Vec<String>,
    pub cache: std::collections::HashMap<String, crate::containers::ContainerCacheEntry>,
}

impl ContainerState {
    /// Queue a logs request for the main loop to drain. Replaces any
    /// previous pending logs request and logs the displaced alias so a
    /// dropped request is traceable.
    pub fn queue_logs(&mut self, req: ContainerLogsRequest) {
        if let Some(prev) = self.pending_logs.as_ref() {
            log::debug!(
                "[purple] queue_logs replaced pending request for alias={} id={}",
                prev.alias,
                prev.container_id,
            );
        }
        self.pending_logs = Some(req);
    }

    /// Queue an exec request for the main loop to drain. Same replace
    /// and log semantics as `queue_logs`.
    pub fn queue_exec(&mut self, req: ContainerExecRequest) {
        if let Some(prev) = self.pending_exec.as_ref() {
            log::debug!(
                "[purple] queue_exec replaced pending request for alias={} id={}",
                prev.alias,
                prev.container_id,
            );
        }
        self.pending_exec = Some(req);
    }

    /// Queue a non-interactive container action for the worker thread.
    /// Actions are FIFO via `VecDeque::push_back`; multiple actions
    /// against the same alias process in order.
    pub fn queue_action(&mut self, req: ContainerActionRequest) {
        self.pending_actions.push_back(req);
    }

    /// Enqueue an alias for the initial container-cache fetch. Drained by
    /// the main loop on the next tick via `drain_pending_fetches`.
    pub fn queue_fetch(&mut self, alias: String) {
        self.pending_fetch_aliases.push(alias);
    }

    /// Take the full fetch queue, leaving it empty.
    pub fn drain_pending_fetches(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_fetch_aliases)
    }

    /// Move a cache entry from `old` to `new` on host rename. Returns
    /// `true` when the cache changed so the caller can persist. No-op
    /// (returns `false`) when `old == new` or no entry exists under `old`.
    pub fn migrate_alias(&mut self, old: &str, new: &str) -> bool {
        if old == new {
            return false;
        }
        if let Some(v) = self.cache.remove(old) {
            debug_assert!(
                !self.cache.contains_key(new),
                "container_state.cache collision on rename {old} -> {new}"
            );
            self.cache.insert(new.to_string(), v);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::{ContainerCacheEntry, ContainerRuntime};

    fn make_logs_request(alias: &str) -> ContainerLogsRequest {
        ContainerLogsRequest {
            alias: alias.to_string(),
            askpass: None,
            runtime: ContainerRuntime::Docker,
            container_id: "abc123".to_string(),
            container_name: "nginx".to_string(),
        }
    }

    fn make_cache_entry() -> ContainerCacheEntry {
        ContainerCacheEntry {
            timestamp: 1700000000,
            runtime: ContainerRuntime::Docker,
            engine_version: Some("28.0.0".to_string()),
            containers: vec![],
        }
    }

    #[test]
    fn queue_logs_sets_pending() {
        let mut state = ContainerState::default();
        assert!(state.pending_logs.is_none());
        state.queue_logs(make_logs_request("host-a"));
        assert!(state.pending_logs.is_some());
        assert_eq!(state.pending_logs.as_ref().unwrap().alias, "host-a");
    }

    #[test]
    fn queue_logs_replaces_previous() {
        let mut state = ContainerState::default();
        state.queue_logs(make_logs_request("host-a"));
        state.queue_logs(make_logs_request("host-b"));
        assert_eq!(state.pending_logs.as_ref().unwrap().alias, "host-b");
    }

    #[test]
    fn queue_exec_sets_pending() {
        let mut state = ContainerState::default();
        assert!(state.pending_exec.is_none());
        state.queue_exec(ContainerExecRequest {
            alias: "host-a".to_string(),
            askpass: None,
            runtime: ContainerRuntime::Docker,
            container_id: "abc".to_string(),
            container_name: "nginx".to_string(),
            command: Some("echo hi".to_string()),
        });
        assert!(state.pending_exec.is_some());
        assert_eq!(state.pending_exec.as_ref().unwrap().alias, "host-a");
    }

    #[test]
    fn queue_fetch_pushes_alias() {
        let mut state = ContainerState::default();
        state.queue_fetch("host-a".to_string());
        state.queue_fetch("host-b".to_string());
        assert_eq!(state.pending_fetch_aliases, vec!["host-a", "host-b"]);
    }

    #[test]
    fn drain_pending_fetches_returns_and_clears() {
        let mut state = ContainerState::default();
        state.queue_fetch("host-a".to_string());
        state.queue_fetch("host-b".to_string());
        let drained = state.drain_pending_fetches();
        assert_eq!(drained, vec!["host-a", "host-b"]);
        assert!(state.pending_fetch_aliases.is_empty());
    }

    #[test]
    fn drain_pending_fetches_empty_when_no_aliases() {
        let mut state = ContainerState::default();
        let drained = state.drain_pending_fetches();
        assert!(drained.is_empty());
        assert!(state.pending_fetch_aliases.is_empty());
    }

    #[test]
    fn migrate_alias_renames_cache_entry() {
        let mut state = ContainerState::default();
        state.cache.insert("old".to_string(), make_cache_entry());
        assert!(state.migrate_alias("old", "new"));
        assert!(state.cache.contains_key("new"));
        assert!(!state.cache.contains_key("old"));
    }

    #[test]
    fn migrate_alias_returns_false_when_no_entry() {
        let mut state = ContainerState::default();
        assert!(!state.migrate_alias("missing", "new"));
        assert!(state.cache.is_empty());
    }

    #[test]
    fn migrate_alias_self_rename_is_noop() {
        let mut state = ContainerState::default();
        state.cache.insert("same".to_string(), make_cache_entry());
        assert!(!state.migrate_alias("same", "same"));
        assert!(state.cache.contains_key("same"));
    }

    #[test]
    fn queue_action_pushes_back_in_order() {
        let mut state = ContainerState::default();
        for id in ["a", "b", "c"] {
            state.queue_action(ContainerActionRequest {
                alias: "host".to_string(),
                askpass: None,
                runtime: ContainerRuntime::Docker,
                container_id: id.to_string(),
                container_name: id.to_string(),
                action: crate::containers::ContainerAction::Restart,
            });
        }
        assert_eq!(state.pending_actions.len(), 3);
        let ids: Vec<String> = state
            .pending_actions
            .iter()
            .map(|r| r.container_id.clone())
            .collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }
}
