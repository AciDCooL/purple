//! State for the global Containers tab (top_page = Containers).

use std::collections::{HashMap, HashSet, VecDeque};

use super::host_state::ViewMode;
use crate::containers::{ContainerInspect, ContainerRuntime};

/// One queued host in a `R` batch refresh: everything the listing
/// thread needs to spawn an SSH `docker ps` for that alias.
#[derive(Debug, Clone)]
pub struct RefreshQueueItem {
    pub alias: String,
    pub askpass: Option<String>,
    pub cached_runtime: Option<ContainerRuntime>,
    pub has_tunnel: bool,
}

/// State of a `R` batch refresh. None when no batch is active.
/// Drives a windowed concurrency: at most `MAX_PARALLEL` listings are
/// in flight at any time. Each `ContainerListing` event decrements
/// `in_flight` and pops the next queued item; the batch ends when
/// `queue` is empty and `in_flight` drops to zero.
#[derive(Debug, Default)]
pub struct RefreshBatch {
    pub queue: VecDeque<RefreshQueueItem>,
    pub in_flight: usize,
    /// Total host count when the batch started. used for the
    /// `Refreshing N/M` progress readout in the status footer.
    pub total: usize,
    /// Hosts whose listing has already returned (success or error).
    pub completed: usize,
    /// Aliases that the batch has spawned but not yet seen complete.
    /// Listings whose alias is NOT in this set are non-batch traffic
    /// (host-list `C`, action-complete refresh, `a`-add) and must not
    /// touch the counters. Without this guard the in-flight counter
    /// gets corrupted whenever a parallel non-batch fetch completes
    /// during a `R` run.
    pub in_flight_aliases: HashSet<String>,
}

/// Cap on parallel SSH connections during a `R` batch refresh. Picked
/// to keep load on the local SSH agent and remote sshd reasonable
/// while still amortising connection setup.
pub const REFRESH_MAX_PARALLEL: usize = 4;

/// Pending request to drop the user into a remote container shell. Set
/// by the handler when Enter is pressed on a running container; drained
/// by `handle_pending_container_exec` in the main loop, which suspends
/// the TUI, runs `ssh -t <alias> <runtime> exec -it <id> sh -c
/// 'bash || sh'`, then restores the TUI on exit.
///
/// `command` is the full remote command. `None` runs the default
/// shell (`sh -c 'bash || sh'`); `Some` runs the user-typed exec
/// prompt verbatim (validated upstream. must not contain newlines).
#[derive(Debug, Clone)]
pub struct ContainerExecRequest {
    pub alias: String,
    pub askpass: Option<String>,
    pub runtime: ContainerRuntime,
    pub container_id: String,
    /// Human-readable container name (for the log line and the toast
    /// the user sees when the session ends). Not used to build the
    /// command. the validated `container_id` is what addresses the
    /// container.
    pub container_name: String,
    /// User-supplied command. `None` falls back to the interactive
    /// shell (`sh -c 'bash || sh'`) used by the default Enter binding.
    /// `Some` is the verbatim payload from the `e` exec prompt.
    pub command: Option<String>,
}

/// Pending request to fetch container logs from a remote host. Drained
/// by the main loop into a background SSH thread; the result returns
/// via `AppEvent::ContainerLogsComplete` and lands on the
/// `Screen::ContainerLogs` overlay the user opened with `l`.
#[derive(Debug, Clone)]
pub struct ContainerLogsRequest {
    pub alias: String,
    pub askpass: Option<String>,
    pub runtime: ContainerRuntime,
    pub container_id: String,
    pub container_name: String,
}

/// Pending non-interactive container action (restart, stop). Same shape
/// as `ContainerExecRequest` but plus an action tag and minus the askpass
/// handling for an interactive shell. these run in a worker thread, not
/// the foreground TUI. Reuses `containers::ContainerAction` so the
/// command formatter (`container_action_command`) is shared.
#[derive(Debug, Clone)]
pub struct ContainerActionRequest {
    pub alias: String,
    pub askpass: Option<String>,
    pub runtime: ContainerRuntime,
    pub container_id: String,
    pub container_name: String,
    pub action: crate::containers::ContainerAction,
}

/// Sort order for the containers overview screen. Cycled with `s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainersSortMode {
    /// Alphabetical by host alias, then container name.
    #[default]
    AlphaHost,
    /// Alphabetical by container name, then host alias.
    AlphaContainer,
}

impl ContainersSortMode {
    pub fn next(self) -> Self {
        match self {
            ContainersSortMode::AlphaHost => ContainersSortMode::AlphaContainer,
            ContainersSortMode::AlphaContainer => ContainersSortMode::AlphaHost,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ContainersSortMode::AlphaHost => "A-Z host",
            ContainersSortMode::AlphaContainer => "A-Z container",
        }
    }

    pub fn to_key(self) -> &'static str {
        match self {
            ContainersSortMode::AlphaHost => "alpha_host",
            ContainersSortMode::AlphaContainer => "alpha_container",
        }
    }

    pub fn from_key(s: &str) -> Self {
        match s {
            "alpha_container" => ContainersSortMode::AlphaContainer,
            _ => ContainersSortMode::AlphaHost,
        }
    }
}

/// One cached `docker inspect` result, paired with the wall-clock seconds
/// at which it was fetched. The detail panel treats entries older than
/// `INSPECT_CACHE_TTL_SECS` as stale and re-fires the SSH call.
#[derive(Debug, Clone)]
pub struct InspectCacheEntry {
    pub timestamp: u64,
    pub result: Result<ContainerInspect, String>,
}

/// Detail-panel inspect cache and in-flight tracking. Keyed on the full
/// container ID rather than `(alias, container_id)` because `docker`
/// container IDs are globally unique 64-char hex strings. collisions
/// across hosts are practically impossible. Keeps the key shape simple.
#[derive(Debug, Default)]
pub struct InspectCache {
    pub entries: HashMap<String, InspectCacheEntry>,
    /// Container IDs with a pending background `inspect` thread. Prevents
    /// re-firing while a previous fetch is still in flight.
    pub in_flight: HashSet<String>,
}

/// One cached `docker logs --tail N` result. Same TTL semantics as
/// `InspectCacheEntry`: the LOGS card on the detail panel re-fires the
/// SSH call once the entry is older than `LOGS_CACHE_TTL_SECS`.
#[derive(Debug, Clone)]
pub struct LogsCacheEntry {
    pub timestamp: u64,
    pub result: Result<Vec<String>, String>,
}

/// Detail-panel logs cache and in-flight tracking. Mirrors `InspectCache`
/// so the LOGS card and the inspect cards refresh on the same rhythm.
#[derive(Debug, Default)]
pub struct LogsCache {
    pub entries: HashMap<String, LogsCacheEntry>,
    pub in_flight: HashSet<String>,
}

/// Cache TTL in seconds. Kept short so resource-y fields like
/// `RestartCount` and `Health.Status` do not lag too far behind reality
/// while still avoiding an SSH storm when the user scrolls a long list.
pub const INSPECT_CACHE_TTL_SECS: u64 = 30;

/// TTL for the per-container `docker logs --tail` cache feeding the
/// LOGS card. Same value as the inspect cache so a single user-driven
/// refresh re-fires both streams in lockstep.
pub const LOGS_CACHE_TTL_SECS: u64 = 30;

/// How many log lines the LOGS card requests via `--tail`. Sized for
/// the worst-case panel height we expect (a tall terminal can fit
/// dozens of lines inside the card); the renderer slices the trailing
/// `inner_capacity` rows so a short panel only paints what fits.
pub const LOGS_TAIL: usize = 50;

/// TTL for the per-host `docker ps` cache used by the auto-list-refresh
/// helper. When the user scrolls to a row whose host has a stale (or
/// missing) entry in `container_cache`, we re-fire the listing so the
/// running/exited counts and uptime in the visible row reflect reality.
/// Same value as the inspect TTL so the two refresh streams stay
/// loosely in lockstep.
pub const LIST_CACHE_TTL_SECS: u64 = 30;

#[derive(Debug)]
pub struct ContainersOverviewState {
    pub sort_mode: ContainersSortMode,
    pub inspect_cache: InspectCache,
    pub logs_cache: LogsCache,
    /// Currently-running `R` batch, if any. `None` when idle.
    pub refresh_batch: Option<RefreshBatch>,
    /// Aliases whose `docker ps` listing was kicked off by the
    /// scroll-driven auto-refresh helper and has not yet returned.
    /// Lets the helper skip a re-spawn while one is already pending.
    /// Cleared by `handle_container_listing` on arrival.
    pub auto_list_in_flight: HashSet<String>,
    /// Toggle for the per-row detail panel on the right. Mirrors the
    /// host-list `v` toggle. Default `Detailed` so the panel is visible
    /// whenever the terminal is wide enough.
    pub view_mode: ViewMode,
    /// Aliases whose container group is currently collapsed in the
    /// AlphaHost rendering. Persisted across sessions via preferences
    /// so a folded group stays folded after restart.
    pub collapsed_hosts: HashSet<String>,
}

impl Default for ContainersOverviewState {
    fn default() -> Self {
        Self {
            sort_mode: ContainersSortMode::default(),
            inspect_cache: InspectCache::default(),
            logs_cache: LogsCache::default(),
            refresh_batch: None,
            auto_list_in_flight: HashSet::new(),
            view_mode: ViewMode::Detailed,
            collapsed_hosts: HashSet::new(),
        }
    }
}

impl InspectCache {
    /// Returns `Some(entry)` only when the cache holds a *fresh* entry
    /// for `container_id` (`now - timestamp < TTL`). Stale entries
    /// behave like absent ones so the trigger code re-fetches.
    pub fn fresh(&self, container_id: &str, now: u64) -> Option<&InspectCacheEntry> {
        self.entries
            .get(container_id)
            .filter(|e| now.saturating_sub(e.timestamp) < INSPECT_CACHE_TTL_SECS)
    }
}

impl LogsCache {
    /// Same fresh-window contract as `InspectCache::fresh`, against
    /// `LOGS_CACHE_TTL_SECS`.
    pub fn fresh(&self, container_id: &str, now: u64) -> Option<&LogsCacheEntry> {
        self.entries
            .get(container_id)
            .filter(|e| now.saturating_sub(e.timestamp) < LOGS_CACHE_TTL_SECS)
    }
}
