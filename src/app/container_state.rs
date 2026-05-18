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
