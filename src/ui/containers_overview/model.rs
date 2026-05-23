use super::*;

/// One renderable row in the containers overview. Public so the
/// handler can resolve cursor-relative actions against the same
/// sequence the UI renders.
#[derive(Clone, Debug, PartialEq)]
pub struct ContainerRow {
    /// Full docker/podman container ID. Used by the handler to key the
    /// inspect cache and as the `<id>` argument to `docker inspect`.
    pub id: String,
    pub alias: String,
    pub name: String,
    pub image: String,
    pub state: String,
    /// Raw `Status` line from `docker ps` ("Up 5 minutes",
    /// "Exited (0) 2 days ago"). Rendered in the detail panel where the
    /// extra context fits.
    pub status: String,
    /// Raw `Ports` line from `docker ps`. Truncated in the row,
    /// rendered fully in the detail panel.
    pub ports: String,
    /// Compact uptime label parsed from the `docker ps` status line
    /// (`5w`, `12d`, `<1m`). `None` for any non-running state. the
    /// cell renders a dim `-` in that case.
    pub uptime: Option<String>,
    /// Unix-seconds timestamp of the host's last successful `docker ps`
    /// fetch. Identical for every row of the same host. Surfaces as
    /// the in-border staleness indicator, no longer per row.
    pub cache_timestamp: u64,
}

/// Strip the leading slash docker prepends to container names.
pub(crate) fn clean_name(raw: &str) -> String {
    raw.strip_prefix('/').unwrap_or(raw).to_string()
}

/// True when the container is actively running (uses the `state` field
/// docker/podman emit, not the human-readable `status` line). Thin
/// wrapper around the canonical `design::is_container_running` so this
/// file's tests can keep their short call sites while the design layer
/// owns the rule.
pub(crate) fn is_running(state: &str) -> bool {
    design::is_container_running(state)
}

/// Wall-clock seconds since Unix epoch. Demo mode uses the synthetic
/// clock so visual goldens stay deterministic.
pub(crate) fn current_unix_secs() -> u64 {
    if crate::demo_flag::is_demo() {
        crate::demo_flag::now_secs()
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// One row in the rendered list. `HostHeader` rows are visual
/// dividers (`── alias (N running) ──`) inserted in `AlphaHost` mode
/// only. `AlphaContainer` mode renders a flat container list with
/// no headers. Mirrors `HostListItem::GroupHeader` from the hosts
/// tab so the design conventions stay aligned across surfaces.
#[derive(Clone, Debug)]
pub enum ContainerListItem {
    HostHeader {
        alias: String,
        total: usize,
        running: usize,
    },
    Container(ContainerRow),
}

impl ContainerListItem {
    /// Production code branches on the variant via `match` directly;
    /// `is_header` is kept for test ergonomics (visual regression
    /// tests scan a list for a header by predicate). Marking it
    /// `#[allow(dead_code)]` keeps the no-warnings policy without
    /// hiding it behind `#[cfg(test)]` (which would also exclude it
    /// from doctests on the type).
    #[allow(dead_code)]
    pub(crate) fn is_header(&self) -> bool {
        matches!(self, ContainerListItem::HostHeader { .. })
    }
    pub(crate) fn as_container(&self) -> Option<&ContainerRow> {
        match self {
            ContainerListItem::Container(row) => Some(row),
            _ => None,
        }
    }
}

/// Build the rendered item list. In `AlphaHost` mode rows are
/// grouped by host with a `HostHeader` between groups; in
/// `AlphaContainer` mode the list is flat with no headers (the
/// container-name ordering would otherwise interleave hosts and the
/// headers would be meaningless).
///
/// Memoized: the result is cached in `ContainersOverviewState.view_cache`
/// keyed on a fingerprint of the inputs (sort_mode, search query,
/// collapsed_hosts, per-host listing signature). The 24 call sites
/// across handlers, jump and render hit this function multiple times
/// per key event; on cache hit we skip the collect/sort/intersperse
/// rebuild entirely. The cache stays correct without manual
/// invalidates because every input that influences the output is part
/// of the fingerprint.
pub(crate) fn visible_items(app: &App) -> Vec<ContainerListItem> {
    let fp = view_fingerprint(app);
    // Take the shared borrow, extract a clone if the fingerprint matches,
    // then DROP the borrow before any potential `borrow_mut()` path.
    // Holding a `Ref<_>` across the mutable refill would panic at runtime
    // because RefCell borrows are dynamically checked. Structuring as
    // extract-then-drop guarantees the panic class is unreachable.
    let cached = app
        .containers_overview
        .view_cache()
        .borrow()
        .as_ref()
        .filter(|(cached_fp, _)| *cached_fp == fp)
        .map(|(_, items)| items.clone());
    if let Some(items) = cached {
        return items;
    }
    let items = build_visible_items(app);
    *app.containers_overview.view_cache().borrow_mut() = Some((fp, items.clone()));
    items
}

pub(crate) fn build_visible_items(app: &App) -> Vec<ContainerListItem> {
    let mut rows = collect_rows(app);
    sort_rows(&mut rows, app.containers_overview.sort_mode());

    match app.containers_overview.sort_mode() {
        ContainersSortMode::AlphaHost => {
            intersperse_host_headers(rows, app.containers_overview.collapsed_hosts())
        }
        ContainersSortMode::AlphaContainer => {
            rows.into_iter().map(ContainerListItem::Container).collect()
        }
    }
}

/// Cheap content fingerprint over every input that influences
/// `visible_items`. Walks `container_cache` sorted by alias for a
/// stable hash regardless of HashMap iteration order. Reads only
/// (alias, timestamp, container_count) per host so cost is O(hosts)
/// rather than O(containers).
pub(crate) fn view_fingerprint(app: &App) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    (app.containers_overview.sort_mode() as u8).hash(&mut hasher);
    app.search.query().hash(&mut hasher);

    let mut collapsed: Vec<&String> = app.containers_overview.collapsed_hosts().iter().collect();
    collapsed.sort();
    collapsed.len().hash(&mut hasher);
    for c in collapsed {
        c.hash(&mut hasher);
    }

    let mut aliases: Vec<&String> = app.container_state.cache().keys().collect();
    aliases.sort();
    aliases.len().hash(&mut hasher);
    for alias in aliases {
        let Some(entry) = app.container_state.cache_entry(alias) else {
            continue;
        };
        alias.hash(&mut hasher);
        entry.timestamp.hash(&mut hasher);
        entry.containers.len().hash(&mut hasher);
    }

    hasher.finish()
}

/// Convenience: just the container rows, in render order, with
/// headers stripped out. Used by tests; production code resolves
/// cursor → row through `selected_container_row` in the handler so
/// header items cannot leak into action paths.
#[cfg(test)]
pub(crate) fn visible_rows(app: &App) -> Vec<ContainerRow> {
    visible_items(app)
        .into_iter()
        .filter_map(|item| match item {
            ContainerListItem::Container(row) => Some(row),
            _ => None,
        })
        .collect()
}

pub(crate) fn collect_rows(app: &App) -> Vec<ContainerRow> {
    let query = app
        .search
        .query()
        .map(|q| q.to_lowercase())
        .filter(|q| !q.is_empty());

    let mut rows: Vec<ContainerRow> = Vec::new();
    for (alias, entry) in app.container_state.cache() {
        for c in &entry.containers {
            let name = clean_name(&c.names);
            if let Some(ref q) = query {
                let alias_match = alias.to_lowercase().contains(q);
                let name_match = name.to_lowercase().contains(q);
                let image_match = c.image.to_lowercase().contains(q);
                if !alias_match && !name_match && !image_match {
                    continue;
                }
            }
            rows.push(ContainerRow {
                id: c.id.clone(),
                alias: alias.clone(),
                name,
                image: c.image.clone(),
                state: c.state.clone(),
                status: c.status.clone(),
                ports: c.ports.clone(),
                uptime: crate::containers::parse_uptime_from_status(&c.status),
                cache_timestamp: entry.timestamp,
            });
        }
    }
    rows
}

/// Walk a host-grouped row list and emit one `HostHeader` per
/// distinct host before its block of containers. Assumes the input is
/// already sorted by alias (then name) and that `collapsed_hosts`
/// holds the aliases the user has folded. Folded groups emit only the
/// header. their child container rows are suppressed so the user gets
/// a one-line summary instead of a long block they actively chose to
/// hide.
pub(crate) fn intersperse_host_headers(
    rows: Vec<ContainerRow>,
    collapsed_hosts: &std::collections::HashSet<String>,
) -> Vec<ContainerListItem> {
    // Pre-pass: tally counts per alias. The header needs running/total
    // even when the group is folded, so we cannot derive these from
    // the post-filter item list anymore.
    let mut totals: std::collections::HashMap<String, (usize, usize)> =
        std::collections::HashMap::new();
    for row in &rows {
        let entry = totals.entry(row.alias.clone()).or_insert((0, 0));
        entry.0 += 1;
        if is_running(&row.state) {
            entry.1 += 1;
        }
    }
    let mut items: Vec<ContainerListItem> = Vec::with_capacity(rows.len() + totals.len());
    let mut current_alias: Option<String> = None;
    for row in rows {
        if Some(&row.alias) != current_alias.as_ref() {
            let (total, running) = totals.get(&row.alias).copied().unwrap_or((0, 0));
            items.push(ContainerListItem::HostHeader {
                alias: row.alias.clone(),
                total,
                running,
            });
            current_alias = Some(row.alias.clone());
        }
        if !collapsed_hosts.contains(&row.alias) {
            items.push(ContainerListItem::Container(row));
        }
    }
    items
}

pub(crate) fn sort_rows(rows: &mut [ContainerRow], mode: ContainersSortMode) {
    // sort_by_cached_key amortises the lowercase allocations to N
    // instead of O(N log N): the closure runs once per element, the
    // returned key is reused across comparisons.
    match mode {
        ContainersSortMode::AlphaHost => {
            rows.sort_by_cached_key(|r| {
                (r.alias.to_ascii_lowercase(), r.name.to_ascii_lowercase())
            });
        }
        ContainersSortMode::AlphaContainer => {
            rows.sort_by_cached_key(|r| {
                (r.name.to_ascii_lowercase(), r.alias.to_ascii_lowercase())
            });
        }
    }
}

/// Total cached container count across every host (ignores the active
/// search filter). Used in the search-mode title to render `N/total`.
pub(crate) fn total_cached_count(app: &App) -> usize {
    app.container_state
        .cache()
        .values()
        .map(|e| e.containers.len())
        .sum()
}
