//! Containers-tab overview screen.
//!
//! Lists every cached container across every host purple has inspected,
//! grouped by host divider in `AlphaHost` mode and flat in
//! `AlphaContainer` mode. Renders an animated detail panel on the right
//! that swaps content based on the selected row: container-level fields
//! (cache + inspect tiers) for a Container row, per-host summary
//! (running/exited counts, runtime, last sync, fold state) for a
//! HostHeader row. Group dividers are first-class selection targets so
//! the user can fold groups with Space and dispatch bulk K/S actions
//! against every running container on the host.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph};
use unicode_width::UnicodeWidthStr;

use super::design;
use super::host_list;
use super::theme;
use crate::app::{App, ContainersSortMode, ViewMode};

const TOP_BAR_HEIGHT: u16 = 3;
const GAP: &str = "    ";
/// Column-width of `GAP`. Hand-paired with the literal so callers do
/// not pay a `UnicodeWidthStr::width()` call per row per frame.
const GAP_W: usize = 4;
const HIGHLIGHT_W: usize = 1;
const MARKER_W: usize = 1;
const STATUS_DOT_W: usize = 2;
const HOST_MIN: usize = 8;
const NAME_MIN: usize = 8;
const IMAGE_MIN: usize = 12;
/// Width of the UPTIME column. Holds compact labels produced by
/// `parse_uptime_from_status` (`5w`, `12d`, `<1m`, `3mo`) plus a
/// safety margin.
const UPTIME_W: usize = 8;

/// One renderable row in the containers overview. Public so the
/// handler can resolve cursor-relative actions against the same
/// sequence the UI renders.
#[derive(Clone)]
pub(crate) struct ContainerRow {
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
fn clean_name(raw: &str) -> String {
    raw.strip_prefix('/').unwrap_or(raw).to_string()
}

/// True when the container is actively running (uses the `state` field
/// docker/podman emit, not the human-readable `status` line).
fn is_running(state: &str) -> bool {
    state.eq_ignore_ascii_case("running")
}

/// Wall-clock seconds since Unix epoch. Demo mode uses the synthetic
/// clock so visual goldens stay deterministic.
fn current_unix_secs() -> u64 {
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
#[derive(Clone)]
pub(crate) enum ContainerListItem {
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
pub(crate) fn visible_items(app: &App) -> Vec<ContainerListItem> {
    let mut rows = collect_rows(app);
    sort_rows(&mut rows, app.containers_overview.sort_mode);

    match app.containers_overview.sort_mode {
        ContainersSortMode::AlphaHost => {
            intersperse_host_headers(rows, &app.containers_overview.collapsed_hosts)
        }
        ContainersSortMode::AlphaContainer => {
            rows.into_iter().map(ContainerListItem::Container).collect()
        }
    }
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

fn collect_rows(app: &App) -> Vec<ContainerRow> {
    let query = app
        .search
        .query
        .as_deref()
        .map(|q| q.to_lowercase())
        .filter(|q| !q.is_empty());

    let mut rows: Vec<ContainerRow> = Vec::new();
    for (alias, entry) in &app.container_cache {
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
fn intersperse_host_headers(
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

fn sort_rows(rows: &mut [ContainerRow], mode: ContainersSortMode) {
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
fn total_cached_count(app: &App) -> usize {
    app.container_cache
        .values()
        .map(|e| e.containers.len())
        .sum()
}

struct Columns {
    host: usize,
    name: usize,
    image: usize,
    /// Render the UPTIME column? `false` when the available width cannot
    /// fit it even with IMAGE shrunk to its minimum.
    show_uptime: bool,
    /// Render the HOST column? `false` in `AlphaHost` mode where the
    /// host alias already lives on the divider line above each
    /// group; suppressing the column reclaims ~16-30 cols for IMAGE
    /// and avoids the visual repetition the user flagged on review.
    show_host: bool,
}

/// `rows` only needs to be walked for `width()` of three string
/// fields per row; we accept anything that yields `&ContainerRow` so
/// callers can pass a `Vec<&ContainerRow>` (zero-copy from the items
/// list) instead of cloning every container per render tick.
fn compute_columns<'a, I>(rows: I, content_w: usize, show_host: bool) -> Columns
where
    I: IntoIterator<Item = &'a ContainerRow> + Clone,
{
    let host_content = rows
        .clone()
        .into_iter()
        .map(|r| r.alias.width())
        .max()
        .unwrap_or(0);
    let host = if show_host {
        host_content.max(HOST_MIN)
    } else {
        0
    };

    let name_content = rows
        .clone()
        .into_iter()
        .map(|r| r.name.width())
        .max()
        .unwrap_or(0);
    let name = name_content.max(NAME_MIN);

    let image_content = rows.into_iter().map(|r| r.image.width()).max().unwrap_or(0);
    let image_max = image_content.max(IMAGE_MIN);

    let host_segment = if show_host { host + GAP_W } else { 0 };
    let always_on_with_image =
        |image: usize| HIGHLIGHT_W + MARKER_W + STATUS_DOT_W + host_segment + name + GAP_W + image;

    // STATUS and HEALTH columns no longer exist — the per-row glyph
    // encodes both signals via colour and shape. PORTS was demoted to
    // detail-panel-only because it was empty for most rows.
    let with_uptime_min = always_on_with_image(IMAGE_MIN) + GAP_W + UPTIME_W;
    let show_uptime = content_w >= with_uptime_min;

    // Image shrink: if the row at image_max doesn't fit, eat into IMAGE
    // until it does (or hits IMAGE_MIN). UPTIME is already demoted
    // above so this is the last resort.
    let total_max =
        always_on_with_image(image_max) + if show_uptime { GAP_W + UPTIME_W } else { 0 };
    let image = if total_max > content_w {
        let excess = total_max - content_w;
        image_max.saturating_sub(excess).max(IMAGE_MIN)
    } else {
        image_max
    };

    Columns {
        host,
        name,
        image,
        show_uptime,
        show_host,
    }
}

/// Pad-or-truncate to exactly `w` columns. `compute_columns` already
/// sizes alias/name to the longest content so they always pad rather
/// than truncate, but a future caller (or a config reload mid-render)
/// could feed in a longer string; falling through to `super::truncate`
/// keeps the row from overflowing into the next column instead of
/// silently corrupting the layout.
fn pad_or_truncate(s: &str, w: usize) -> String {
    let cur = s.width();
    match cur.cmp(&w) {
        std::cmp::Ordering::Equal => s.to_string(),
        std::cmp::Ordering::Less => format!("{}{}", s, " ".repeat(w - cur)),
        std::cmp::Ordering::Greater => {
            let truncated = super::truncate(s, w);
            // `truncate` may produce slightly fewer cols than `w` when
            // it appends `…`; pad the remainder so columns line up.
            let tw = truncated.width();
            if tw < w {
                format!("{}{}", truncated, " ".repeat(w - tw))
            } else {
                truncated
            }
        }
    }
}

/// Index of the first visible item, header or container. Used when
/// snapping the cursor on first paint or after a sort flip. With
/// header rows now selectable the cursor is allowed to land on a
/// divider, so this is the right entry point for "first row".
pub(crate) fn first_visible_index(items: &[ContainerListItem]) -> Option<usize> {
    if items.is_empty() { None } else { Some(0) }
}

/// Resolve a (alias, container_id) pair to its index in the currently
/// rendered visible_items list. Returns `None` when the container is
/// not in the cache, its host group is folded, or it has been filtered
/// out by an active search query. Used by the jump dispatcher to land
/// the cursor on the picked container without leaving the tab.
pub(crate) fn position_of_container(app: &App, alias: &str, container_id: &str) -> Option<usize> {
    visible_items(app).iter().position(|item| match item {
        ContainerListItem::Container(row) => row.alias == alias && row.id == container_id,
        _ => false,
    })
}

/// Build the block title. Per-state breakdowns (running/exited) live on
/// the per-host group dividers (`(3 of 4 running)`); repeating them in
/// the top header was redundant noise. The header mirrors the host_list
/// pattern: bare visible count. The active tab in the top bar already
/// disambiguates scope (containers vs hosts vs tunnels), so labelling
/// the count here would be redundant.
fn build_stats_title(container_count: usize) -> Line<'static> {
    Line::from(vec![Span::styled(
        format!(" {} ", container_count),
        theme::bold(),
    )])
}

/// Render a `── alias (N running) ──────────` divider for one host
/// group. Mirrors `HostListItem::GroupHeader` styling: bold prefix,
/// muted dashes filling the row. Folded groups switch the suffix to
/// `(N hidden)` so the user sees that the children are suppressed,
/// not lost.
fn render_host_header_row<'a>(alias: &'a str, content_w: usize) -> ListItem<'a> {
    // Counts (running / total / hidden) used to live in the header but
    // duplicated information already visible: the per-row dots show
    // running vs not, and the host detail panel summarises the fleet.
    // Header now carries the alias only.
    let prefix = format!("── {} ", alias);
    // Subtract 1 for ratatui's highlight_symbol gutter (rendered to
    // the left of every list item). Same accounting as the host-list
    // group-header row.
    let available = content_w.saturating_sub(1);
    let fill_width = available.saturating_sub(prefix.width());
    ListItem::new(Line::from(vec![
        Span::styled(prefix, theme::bold()),
        Span::styled("─".repeat(fill_width), theme::muted()),
    ]))
}

fn render_header(frame: &mut Frame, area: Rect, cols: &Columns, sort_mode: ContainersSortMode) {
    let style = theme::bold();
    let gap = " ".repeat(GAP_W);

    let host_arrow = matches!(sort_mode, ContainersSortMode::AlphaHost);
    let name_arrow = matches!(sort_mode, ContainersSortMode::AlphaContainer);

    let host_label = if host_arrow { "HOST \u{25BE}" } else { "HOST" };
    let name_label = if name_arrow { "NAME \u{25BE}" } else { "NAME" };

    let leading_pad = " ".repeat(HIGHLIGHT_W + MARKER_W + STATUS_DOT_W);
    let mut spans = vec![Span::styled(leading_pad, style)];
    if cols.show_host {
        spans.push(Span::styled(
            format!("{:<width$}", host_label, width = cols.host),
            style,
        ));
        spans.push(Span::raw(gap.clone()));
    }
    spans.push(Span::styled(
        format!("{:<width$}", name_label, width = cols.name),
        style,
    ));
    spans.push(Span::raw(gap.clone()));
    spans.push(Span::styled(
        format!("{:<width$}", "IMAGE", width = cols.image),
        style,
    ));
    if cols.show_uptime {
        spans.push(Span::raw(gap));
        spans.push(Span::styled(
            format!("{:>width$}", "UPTIME", width = UPTIME_W),
            style,
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_row<'a>(
    row: &'a ContainerRow,
    cols: &Columns,
    health: Option<&str>,
    spinner_tick: u64,
) -> ListItem<'a> {
    let (state_glyph, state_style) = state_glyph(&row.state, health, &row.status, spinner_tick);
    let image = super::truncate(&row.image, cols.image);

    let mut spans: Vec<Span<'static>> = vec![
        Span::raw(" ".repeat(MARKER_W)),
        Span::styled(format!("{} ", state_glyph), state_style),
    ];
    if cols.show_host {
        spans.push(Span::styled(
            pad_or_truncate(&row.alias, cols.host),
            theme::bold(),
        ));
        spans.push(Span::raw(GAP));
    }
    spans.push(Span::styled(
        pad_or_truncate(&row.name, cols.name),
        theme::bold(),
    ));
    spans.push(Span::raw(GAP));
    spans.push(Span::styled(
        pad_or_truncate(&image, cols.image),
        theme::muted(),
    ));
    if cols.show_uptime {
        spans.push(Span::raw(GAP));
        match &row.uptime {
            Some(uptime) => spans.push(Span::styled(
                format!("{:>width$}", uptime, width = UPTIME_W),
                theme::muted(),
            )),
            None => spans.push(Span::styled(
                format!("{:>width$}", "-", width = UPTIME_W),
                theme::muted(),
            )),
        }
    }
    ListItem::new(Line::from(spans))
}

/// State glyph + style for a container row. Encodes both lifecycle state
/// and health into the leading dot so the row needs no STATUS or HEALTH
/// column. Running + healthy/no-healthcheck pulses green; running +
/// unhealthy goes red, running + starting goes yellow. Exited with a
/// non-zero code uses the error glyph in warning tier; `dead` uses the
/// error glyph in error tier; paused/restarting use the half-circle in
/// warning tier; everything else falls back to the muted hollow circle.
fn state_glyph(
    state: &str,
    health: Option<&str>,
    status: &str,
    spinner_tick: u64,
) -> (&'static str, ratatui::style::Style) {
    if is_running(state) {
        return match health {
            Some("unhealthy") => (design::ICON_ONLINE, theme::error()),
            Some("starting") => (design::ICON_ONLINE, theme::warning()),
            _ => (design::ICON_ONLINE, theme::online_dot_pulsing(spinner_tick)),
        };
    }
    match state {
        "dead" => (design::ICON_ERROR, theme::error()),
        "exited" => match parse_exit_code_from_status(status) {
            Some(code) if code != 0 => (design::ICON_ERROR, theme::warning()),
            _ => ("\u{25CB}", theme::muted()),
        },
        "paused" | "restarting" => ("\u{25D0}", theme::warning()),
        _ => ("\u{25CB}", theme::muted()),
    }
}

/// Detail panel width when the terminal is wide enough to render one.
/// Wider than the host-detail panel because container detail packs more
/// data per row (image, version, digest, command, mounts, log tail) and
/// the LOGS card needs room for a usable line of output.
const DETAIL_PANEL_WIDTH: u16 = 96;
/// Minimum animated detail-panel width before we stamp content into it.
/// Below this we still render an empty bordered placeholder so the list
/// area resizes smoothly without content briefly clipping the border.
/// Mirrors the host-list `DETAIL_RENDER_MIN` constant.
const DETAIL_RENDER_MIN: u16 = 8;
/// Below this total terminal width the detail panel is suppressed and
/// the list takes the full width. Threshold = panel width + the column
/// budget the list needs to render its columns at sensible minima with
/// some slack so HOST/IMAGE truncation does not bite at the threshold.
const DETAIL_MIN_TOTAL_WIDTH: u16 = 158;

pub fn render(frame: &mut Frame, app: &mut App, spinner_tick: u64, detail_progress: Option<f32>) {
    let area = frame.area();

    let search_active = app.search.query.is_some();
    let search_bar_h = if search_active { 1 } else { 0 };
    let [top_bar_area, body_area, search_bar_area, footer_area] = Layout::vertical([
        Constraint::Length(TOP_BAR_HEIGHT),
        Constraint::Min(0),
        Constraint::Length(search_bar_h),
        Constraint::Length(1),
    ])
    .areas(area);
    render_top_bar(frame, app, top_bar_area);

    let items = visible_items(app);
    let item_count = items.len();
    let row_count = items.iter().filter(|i| i.as_container().is_some()).count();
    let total_cached = if search_active {
        total_cached_count(app)
    } else {
        0
    };
    if search_active {
        render_search_bar(frame, app, search_bar_area, row_count, total_cached);
    }

    let sel = app.ui.containers_overview_state.selected();
    let new_sel = match sel {
        // Headers are now valid selection targets (the user can park on a
        // group divider to drive bulk actions or fold the group). Empty
        // lists or out-of-range indices still get snapped to the first
        // visible item, header or container, whichever comes first.
        Some(i) if i < item_count => Some(i),
        _ => first_visible_index(&items),
    };
    if new_sel != sel {
        app.ui.containers_overview_state.select(new_sel);
    }

    // Detail panel is gated by both the user's `v` toggle and the
    // terminal width threshold. Below the threshold the panel is
    // suppressed regardless of preference. Width animates between
    // 0 and DETAIL_PANEL_WIDTH using `detail_progress`, matching the
    // host-list cubic ease-out.
    let target_detail = app.containers_overview.view_mode == ViewMode::Detailed
        && body_area.width >= DETAIL_MIN_TOTAL_WIDTH;
    let detail_width = if body_area.width >= DETAIL_MIN_TOTAL_WIDTH {
        if let Some(progress) = detail_progress {
            (progress * DETAIL_PANEL_WIDTH as f32).round() as u16
        } else if target_detail {
            DETAIL_PANEL_WIDTH
        } else {
            0
        }
    } else {
        0
    };
    let (list_area, detail_area) = if detail_width > 0 {
        let [left, right] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(detail_width)])
                .areas(body_area);
        (left, Some(right))
    } else {
        (body_area, None)
    };

    let update_title = app.update.available.as_ref().map(|ver| {
        let label = host_list::build_update_label(
            ver,
            app.update.headline.as_deref(),
            app.update.hint,
            list_area.width,
        );
        Line::from(Span::styled(label, theme::update_badge()))
    });

    let url_label = Line::from(Span::styled(" getpurple.sh ", theme::muted()));
    let mut block = if search_active {
        let title = Line::from(vec![Span::styled(
            format!(" search: {}/{} ", row_count, total_cached),
            theme::bold(),
        )]);
        design::search_block_line(title).title_bottom(url_label.right_aligned())
    } else {
        // Top-border header is the bare visible-row count. Per-host
        // running/exited live on group-divider rows; the active top
        // tab already says "containers" so labelling the count here
        // would be redundant.
        let title = build_stats_title(row_count);
        design::main_block_line(title).title_bottom(url_label.right_aligned())
    };
    if let Some(update) = update_title.as_ref() {
        block = block.title_top(update.clone().right_aligned());
    }
    // Sync freshness no longer surfaces in the list-block title; it
    // moves to the LIFECYCLE card on the detail panel where it is
    // tied to a specific container's last refresh.
    let block_inner = block.inner(list_area);
    frame.render_widget(block, list_area);

    if items.is_empty() {
        design::render_empty(frame, block_inner, "No containers cached yet.");
        if let Some(detail) = detail_area {
            if detail.width >= DETAIL_RENDER_MIN {
                render_detail_empty(frame, detail);
            } else {
                let block = design::main_block_line(Line::default());
                frame.render_widget(block, detail);
            }
        }
        render_footer(frame, footer_area, app);
        return;
    }

    let inner = Rect {
        x: block_inner.x.saturating_add(1),
        y: block_inner.y,
        width: block_inner.width.saturating_sub(2),
        height: block_inner.height,
    };

    let [col_header_area, underline_area, list_inner_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(inner);

    let content_w = (inner.width as usize).saturating_sub(1);
    let containers_only: Vec<&ContainerRow> =
        items.iter().filter_map(|i| i.as_container()).collect();
    // HOST column lives on the divider in AlphaHost mode; flat
    // AlphaContainer mode shows it per-row so users keep cross-host
    // context when sorted by name.
    let show_host = matches!(
        app.containers_overview.sort_mode,
        ContainersSortMode::AlphaContainer
    );
    let cols = compute_columns(containers_only.iter().copied(), content_w, show_host);

    // In `AlphaHost` mode the host alias lives on the divider line,
    // so suppress the HOST column from the column header to match.
    render_header(
        frame,
        col_header_area,
        &cols,
        app.containers_overview.sort_mode,
    );
    frame.render_widget(
        Paragraph::new(Span::styled(
            "\u{2500}".repeat(underline_area.width as usize),
            theme::muted(),
        )),
        underline_area,
    );

    let list_items: Vec<ListItem> = items
        .iter()
        .map(|item| match item {
            ContainerListItem::Container(row) => {
                // Pull the cached health value out of the inspect cache
                // for this row. `None` when no inspect has landed yet
                // (HEALTH cell will show `-`); the auto-fetch trigger
                // populates it within a frame or two of selection.
                let health = app
                    .containers_overview
                    .inspect_cache
                    .entries
                    .get(&row.id)
                    .and_then(|e| e.result.as_ref().ok())
                    .and_then(|i| i.health.as_deref());
                render_row(row, &cols, health, spinner_tick)
            }
            ContainerListItem::HostHeader { alias, .. } => render_host_header_row(alias, content_w),
        })
        .collect();
    let list = List::new(list_items)
        .highlight_style(theme::selected_row())
        .highlight_symbol(design::HOST_HIGHLIGHT);

    let selected_item = app
        .ui
        .containers_overview_state
        .selected()
        .and_then(|i| items.get(i).cloned());

    frame.render_stateful_widget(list, list_inner_area, &mut app.ui.containers_overview_state);

    if let Some(detail) = detail_area {
        if detail.width >= DETAIL_RENDER_MIN {
            match &selected_item {
                Some(ContainerListItem::Container(row)) => {
                    render_detail(frame, app, detail, Some(row), spinner_tick);
                }
                Some(ContainerListItem::HostHeader {
                    alias,
                    total,
                    running,
                    ..
                }) => {
                    render_host_detail(frame, app, detail, alias, *total, *running);
                }
                None => {
                    render_detail(frame, app, detail, None, spinner_tick);
                }
            }
        } else {
            let block = design::main_block_line(Line::default());
            frame.render_widget(block, detail);
        }
    }

    render_footer(frame, footer_area, app);
}

fn render_top_bar(frame: &mut Frame, app: &App, area: Rect) {
    let block = design::main_block_line(Line::default());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let content_area = Rect::new(
        inner.x.saturating_add(1),
        inner.y,
        inner.width.saturating_sub(1),
        1,
    );
    let line = Line::from(host_list::top_bar_spans(app));
    frame.render_widget(Paragraph::new(line), content_area);
}

fn render_search_bar(frame: &mut Frame, app: &App, area: Rect, visible_count: usize, total: usize) {
    let query = app.search.query.as_deref().unwrap_or("");
    let match_info = if query.is_empty() {
        String::new()
    } else {
        format!(" ({} of {})", visible_count, total)
    };
    let line = Line::from(vec![
        Span::styled(" / ", theme::brand_badge()),
        Span::raw(" "),
        Span::raw(query.to_string()),
        Span::styled("_", theme::accent()),
        Span::styled(match_info, theme::muted()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

/// Render the detail panel for the selected container row. Cards are the
/// visual structure (no outer wrapper block). The top cards stack from
/// the top; the LOGS card stretches to fill the remaining height down
/// to the panel bottom so the panel always ends flush with the list.
fn render_detail(
    frame: &mut Frame,
    app: &App,
    area: Rect,
    selected: Option<&ContainerRow>,
    spinner_tick: u64,
) {
    let Some(row) = selected else {
        design::render_empty(frame, area, "No container selected.");
        return;
    };

    let inspect = app
        .containers_overview
        .inspect_cache
        .entries
        .get(&row.id)
        .map(|e| &e.result);
    let inspect_in_flight = app
        .containers_overview
        .inspect_cache
        .in_flight
        .contains(&row.id);
    let logs = app
        .containers_overview
        .logs_cache
        .entries
        .get(&row.id)
        .map(|e| &e.result);
    let logs_in_flight = app
        .containers_overview
        .logs_cache
        .in_flight
        .contains(&row.id);

    let box_width = area.width as usize;
    let top_lines = build_detail_lines(row, inspect, inspect_in_flight, spinner_tick, box_width);
    let top_height = top_lines.len() as u16;

    // Reserve LOGS_FLOOR rows at the bottom for the LOGS card so it
    // ALWAYS lands flush with the panel bottom, even when the top
    // cards would otherwise consume the whole panel. Above that
    // floor, LOGS gets whatever extra space the top cards leave so
    // a tall terminal fills with more log history.
    const LOGS_FLOOR: u16 = 7; // open + 5 visible + close
    let body_height = area.height;
    let (top_h, logs_h) = if body_height < 3 {
        (body_height, 0)
    } else if body_height < LOGS_FLOOR {
        // Tiny panel: give LOGS the minimum 3 rows, top gets the rest.
        let logs = 3.min(body_height);
        (body_height.saturating_sub(logs), logs)
    } else {
        // Cap top to body - LOGS_FLOOR. When the natural top height
        // exceeds that cap, snap down to the most recent card-close
        // boundary so we never clip mid-card and break the visual
        // structure. LOGS then gets the remainder.
        let top_max = body_height.saturating_sub(LOGS_FLOOR);
        let actual_top = if top_height > top_max {
            snap_top_to_card_boundary(&top_lines, top_max)
        } else {
            top_height
        };
        let actual_logs = body_height.saturating_sub(actual_top);
        (actual_top, actual_logs)
    };

    if top_h > 0 {
        let top_area = Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: top_h,
        };
        frame.render_widget(Paragraph::new(top_lines), top_area);
    }
    if logs_h >= 3 {
        let logs_area = Rect {
            x: area.x,
            y: area.y.saturating_add(top_h),
            width: area.width,
            height: logs_h,
        };
        let logs_lines = build_logs_card(logs, logs_in_flight, box_width, logs_h as usize);
        frame.render_widget(Paragraph::new(logs_lines), logs_area);
    }
}

/// LOGS card sized to `card_height`. Renders the trailing log lines
/// that fit in `inner_capacity`, padded with empty rows so the close
/// border lands at the panel bottom. Loading / error / empty render a
/// single status row in the same chrome.
fn build_logs_card(
    logs: Option<&Result<Vec<String>, String>>,
    in_flight: bool,
    box_width: usize,
    card_height: usize,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    if card_height < 3 {
        return lines;
    }
    design::section_open(&mut lines, "LOGS", box_width);
    let inner_capacity = card_height.saturating_sub(2);

    // Render the trailing `inner_capacity` lines so a tall terminal
    // fills with history while a short panel still shows the most
    // recent rows. Padding rows below the content keep the bottom
    // border at card_height - 1.
    let mut content_rows: Vec<String> = Vec::new();
    match logs {
        Some(Ok(entries)) => {
            if entries.is_empty() {
                content_rows.push("(no output)".to_string());
            } else {
                let take = inner_capacity.min(entries.len());
                let start = entries.len().saturating_sub(take);
                for line in &entries[start..] {
                    content_rows.push(line.clone());
                }
            }
        }
        Some(Err(e)) => {
            content_rows.push(format!("error: {}", e));
        }
        None if in_flight => {
            content_rows.push("loading…".to_string());
        }
        None => {
            content_rows.push("(no logs cached)".to_string());
        }
    }

    let max_value_width = box_width.saturating_sub(4);
    for raw in content_rows.iter().take(inner_capacity) {
        let trimmed = raw.replace('\t', "    ");
        let value = if trimmed.chars().count() > max_value_width {
            super::truncate(&trimmed, max_value_width)
        } else {
            trimmed
        };
        let style = if matches!(logs, Some(Err(_))) {
            theme::error()
        } else {
            theme::muted()
        };
        design::section_line(&mut lines, vec![Span::styled(value, style)], box_width);
    }

    // Pad with empty rows so the closing border lands at card bottom.
    let used_rows = content_rows.len().min(inner_capacity);
    let padding_rows = inner_capacity.saturating_sub(used_rows);
    for _ in 0..padding_rows {
        design::section_line(&mut lines, vec![Span::raw(" ")], box_width);
    }
    design::section_close(&mut lines, box_width);
    lines
}

/// Detail-panel content when the cursor is parked on a host-divider
/// row. Lists per-host scope (counts, runtime, last sync) plus a key
/// reminder so the user discovers the bulk-action affordances without
/// hunting through the help screen.
fn render_host_detail(
    frame: &mut Frame,
    app: &App,
    area: Rect,
    alias: &str,
    total: usize,
    running: usize,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let lines = build_host_detail_lines(app, alias, total, running, area.width, area.height);
    frame.render_widget(Paragraph::new(lines), area);
}

/// Card stack for the host-overview detail panel: STATUS, FLEET,
/// optional ATTENTION, ACTIONS, HOST. The HOST card is last and stretches
/// to the panel bottom via `design::stretch_last_card`.
fn build_host_detail_lines(
    app: &App,
    alias: &str,
    total: usize,
    running: usize,
    width: u16,
    height: u16,
) -> Vec<Line<'static>> {
    let box_width = width as usize;
    let max_value_width = box_width
        .saturating_sub(4)
        .saturating_sub(design::SECTION_LABEL_W as usize);
    let mut lines: Vec<Line<'static>> = Vec::new();

    let entry = app.container_cache.get(alias);
    let host = app.hosts_state.list.iter().find(|h| h.alias == alias);
    let collapsed = app.containers_overview.collapsed_hosts.contains(alias);
    let now = current_unix_secs();

    // STATUS card -----------------------------------------------------
    design::section_open(&mut lines, "STATUS", box_width);
    push_ping_field(&mut lines, app, alias, max_value_width, box_width);
    if let Some(e) = entry {
        let age_secs = now.saturating_sub(e.timestamp);
        let age_text = crate::messages::relative_age(std::time::Duration::from_secs(age_secs));
        let style = if age_secs > 300 {
            theme::warning()
        } else {
            theme::muted()
        };
        design::section_field_styled(
            &mut lines,
            "Sync age",
            &age_text,
            style,
            max_value_width,
            box_width,
        );
        let runtime_label = match e.runtime {
            crate::containers::ContainerRuntime::Docker => "Docker",
            crate::containers::ContainerRuntime::Podman => "Podman",
        };
        let runtime_value = match e.engine_version.as_deref() {
            Some(v) if !v.is_empty() => format!("{} {}", runtime_label, v),
            _ => runtime_label.to_string(),
        };
        design::section_field(
            &mut lines,
            "Runtime",
            &runtime_value,
            max_value_width,
            box_width,
        );
    }
    if let Some(hist) = app.history.entries.get(alias) {
        let ago = crate::history::ConnectionHistory::format_time_ago(hist.last_connected);
        if !ago.is_empty() {
            design::section_field(
                &mut lines,
                "Last SSH",
                &format!("{} ago", ago),
                max_value_width,
                box_width,
            );
        }
    }
    design::section_close(&mut lines, box_width);

    // FLEET card ------------------------------------------------------
    design::section_open(&mut lines, "FLEET", box_width);
    let exited = total.saturating_sub(running);
    let counts = entry
        .map(|e| count_states(&e.containers))
        .unwrap_or_default();
    let dead = counts.dead;
    let paused = counts.paused;
    let restarting = counts.restarting;
    push_state_dots(&mut lines, running, exited, dead, paused, box_width);
    design::section_field(
        &mut lines,
        "Total",
        &format!("{}", total),
        max_value_width,
        box_width,
    );
    if let Some(e) = entry {
        let exit_nonzero = e
            .containers
            .iter()
            .filter(|c| {
                parse_exit_code_from_status(&c.status)
                    .map(|code| code != 0)
                    .unwrap_or(false)
            })
            .count();
        if exit_nonzero > 0 {
            design::section_field_styled(
                &mut lines,
                "Exit ne 0",
                &exit_nonzero.to_string(),
                theme::warning(),
                max_value_width,
                box_width,
            );
        }
    }
    let tunnel_active = app.tunnels.active.contains_key(alias);
    if tunnel_active {
        design::section_field_styled(
            &mut lines,
            "Tunnels",
            "active",
            theme::online_dot(),
            max_value_width,
            box_width,
        );
    } else if let Some(h) = host {
        if h.tunnel_count > 0 {
            design::section_field(
                &mut lines,
                "Tunnels",
                &h.tunnel_count.to_string(),
                max_value_width,
                box_width,
            );
        }
    }
    if collapsed {
        design::section_field_styled(
            &mut lines,
            "Group",
            "folded",
            theme::warning(),
            max_value_width,
            box_width,
        );
    }
    design::section_close(&mut lines, box_width);

    // ATTENTION card (conditional) ------------------------------------
    let stale_listing = entry
        .map(|e| now.saturating_sub(e.timestamp) > 300)
        .unwrap_or(false);
    let inspect_signals = entry
        .map(|e| collect_inspect_signals(app, &e.containers))
        .unwrap_or_default();
    let attention_needed = dead > 0
        || restarting > 0
        || stale_listing
        || !inspect_signals.restart_loops.is_empty()
        || inspect_signals.oom_count > 0
        || entry
            .map(|e| {
                e.containers.iter().any(|c| {
                    parse_exit_code_from_status(&c.status)
                        .map(|code| code != 0)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
    if attention_needed {
        design::section_open(&mut lines, "ATTENTION", box_width);
        if dead > 0 {
            design::section_field_styled(
                &mut lines,
                "Dead",
                &format!("{}  K to restart all running", dead),
                theme::error(),
                max_value_width,
                box_width,
            );
        }
        if restarting > 0 {
            design::section_field_styled(
                &mut lines,
                "Restarting",
                &restarting.to_string(),
                theme::warning(),
                max_value_width,
                box_width,
            );
        }
        if let Some(e) = entry {
            let bad_exit = e
                .containers
                .iter()
                .filter(|c| {
                    parse_exit_code_from_status(&c.status)
                        .map(|code| code != 0)
                        .unwrap_or(false)
                })
                .count();
            if bad_exit > 0 {
                design::section_field_styled(
                    &mut lines,
                    "Exit ne 0",
                    &format!("{}  r to refresh", bad_exit),
                    theme::warning(),
                    max_value_width,
                    box_width,
                );
            }
        }
        for (name, count) in inspect_signals
            .restart_loops
            .iter()
            .take(ATTENTION_RESTART_LOOP_CAP)
        {
            let label = "Restart loop";
            let value = format!("{} ({})", name, count);
            design::section_field_styled(
                &mut lines,
                label,
                &value,
                theme::warning(),
                max_value_width,
                box_width,
            );
        }
        if inspect_signals.oom_count > 0 {
            design::section_field_styled(
                &mut lines,
                "OOM kills",
                &inspect_signals.oom_count.to_string(),
                theme::error(),
                max_value_width,
                box_width,
            );
        }
        if stale_listing {
            let ago = crate::messages::relative_age(std::time::Duration::from_secs(
                entry.map(|e| now.saturating_sub(e.timestamp)).unwrap_or(0),
            ));
            design::section_field_styled(
                &mut lines,
                "Stale",
                &format!("listing {}  r to refresh", ago),
                theme::warning(),
                max_value_width,
                box_width,
            );
        }
        design::section_close(&mut lines, box_width);
    }

    // ACTIONS card ----------------------------------------------------
    design::section_open(&mut lines, "ACTIONS", box_width);
    push_action_row(
        &mut lines,
        "K",
        "Restart running on host",
        running,
        running > 0,
        box_width,
    );
    push_action_row(
        &mut lines,
        "S",
        "Stop running on host",
        running,
        running > 0,
        box_width,
    );
    let refresh_qual = entry
        .map(|e| {
            let age = now.saturating_sub(e.timestamp);
            crate::messages::relative_age(std::time::Duration::from_secs(age))
        })
        .unwrap_or_else(|| "never synced".to_string());
    let r_qual = format!("last sync {}", refresh_qual);
    push_action_text_row(&mut lines, "r", "Refresh listing", &r_qual, true, box_width);
    let space_label = if collapsed {
        "Expand group"
    } else {
        "Collapse group"
    };
    push_action_text_row(&mut lines, "Space", space_label, "", true, box_width);
    design::section_close(&mut lines, box_width);

    // HOST card (last, stretches) -------------------------------------
    design::section_open(&mut lines, "HOST", box_width);
    if let Some(h) = host {
        let addr = if h.port != 22 {
            format!("{}:{}", h.hostname, h.port)
        } else {
            h.hostname.clone()
        };
        if !addr.is_empty() {
            design::section_field(&mut lines, "Address", &addr, max_value_width, box_width);
        }
        if !h.user.is_empty() {
            design::section_field(&mut lines, "User", &h.user, max_value_width, box_width);
        }
        if let Some(provider_name) = h.provider.as_deref() {
            let display = crate::providers::provider_display_name(provider_name);
            let region = h
                .provider_meta
                .iter()
                .find(|(k, _)| k == "region" || k == "zone" || k == "datacenter")
                .map(|(_, v)| v.clone());
            let value = match region {
                Some(r) if !r.is_empty() => format!("{} · {}", display, r),
                _ => display.to_string(),
            };
            design::section_field(&mut lines, "Provider", &value, max_value_width, box_width);
        }
        if !h.tags.is_empty() || !h.provider_tags.is_empty() {
            let combined: Vec<String> = h
                .provider_tags
                .iter()
                .chain(h.tags.iter())
                .cloned()
                .collect();
            let joined = combined.join(", ");
            design::section_field(&mut lines, "Tags", &joined, max_value_width, box_width);
        }
    } else {
        design::section_field(&mut lines, "Alias", alias, max_value_width, box_width);
    }
    design::section_close(&mut lines, box_width);

    design::stretch_last_card(&mut lines, height as usize, box_width);
    lines
}

/// FLEET state-dot row: one mixed-style line summarising counts.
fn push_state_dots(
    lines: &mut Vec<Line<'static>>,
    running: usize,
    exited: usize,
    dead: usize,
    paused: usize,
    box_width: usize,
) {
    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::styled(
        format!(
            "{:<width$}",
            "State",
            width = design::SECTION_LABEL_W as usize
        ),
        theme::muted(),
    ));
    spans.push(Span::styled("\u{25CF} ", theme::online_dot()));
    spans.push(Span::styled(
        format!("{} running  ", running),
        theme::bold(),
    ));
    spans.push(Span::styled("\u{25CB} ", theme::muted()));
    spans.push(Span::styled(format!("{} exited  ", exited), theme::bold()));
    if dead > 0 {
        spans.push(Span::styled("\u{2717} ", theme::error()));
        spans.push(Span::styled(format!("{} dead", dead), theme::error()));
    }
    if paused > 0 {
        if dead > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled("\u{25D0} ", theme::warning()));
        spans.push(Span::styled(format!("{} paused", paused), theme::warning()));
    }
    design::section_line(lines, spans, box_width);
}

fn push_ping_field(
    lines: &mut Vec<Line<'static>>,
    app: &App,
    alias: &str,
    _max_value_width: usize,
    box_width: usize,
) {
    let label_span = Span::styled(
        format!(
            "{:<width$}",
            "Ping",
            width = design::SECTION_LABEL_W as usize
        ),
        theme::muted(),
    );
    let value_spans: Vec<Span<'static>> = match app.ping.status.get(alias) {
        Some(crate::app::PingStatus::Reachable { rtt_ms }) => vec![
            Span::styled("\u{25CF} ", theme::online_dot()),
            Span::styled(host_list::format_rtt(*rtt_ms), theme::online_dot()),
        ],
        Some(crate::app::PingStatus::Slow { rtt_ms }) => vec![
            Span::styled("\u{25CB} ", theme::warning()),
            Span::styled(
                format!("slow {}", host_list::format_rtt(*rtt_ms)),
                theme::warning(),
            ),
        ],
        Some(crate::app::PingStatus::Unreachable) => vec![
            Span::styled("\u{2717} ", theme::error()),
            Span::styled("unreachable", theme::error()),
        ],
        Some(crate::app::PingStatus::Checking) => {
            vec![Span::styled("checking", theme::muted())]
        }
        Some(crate::app::PingStatus::Skipped) | None => {
            vec![Span::styled("--", theme::muted())]
        }
    };
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(1 + value_spans.len());
    spans.push(label_span);
    spans.extend(value_spans);
    design::section_line(lines, spans, box_width);
}

/// ACTIONS row with a count qualifier (e.g. "12 containers"). Disabled
/// rows render the key dimmed and the qualifier replaced with the muted
/// reason (`nothing running`).
fn push_action_row(
    lines: &mut Vec<Line<'static>>,
    key: &str,
    verb: &str,
    count: usize,
    enabled: bool,
    box_width: usize,
) {
    let qualifier = if !enabled {
        "nothing running".to_string()
    } else if count == 1 {
        "1 container".to_string()
    } else {
        format!("{} containers", count)
    };
    push_action_text_row(lines, key, verb, &qualifier, enabled, box_width);
}

fn push_action_text_row(
    lines: &mut Vec<Line<'static>>,
    key: &str,
    verb: &str,
    qualifier: &str,
    enabled: bool,
    box_width: usize,
) {
    let key_style = if enabled {
        theme::accent_bold()
    } else {
        theme::muted()
    };
    let verb_style = if enabled {
        theme::bold()
    } else {
        theme::muted()
    };
    // Key column is sized to fit the longest binding ("Space" = 5 chars
    // plus one trailing space). Keeping the verb column flush across
    // rows lets the eye scan the action verbs as a single column.
    let key_field = format!("{:<6}", key);
    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::styled(key_field, key_style));
    spans.push(Span::styled(verb.to_string(), verb_style));
    if !qualifier.is_empty() {
        spans.push(Span::styled(format!("  {}", qualifier), theme::muted()));
    }
    design::section_line(lines, spans, box_width);
}

#[derive(Default, Debug, PartialEq)]
struct StateCounts {
    running: usize,
    exited: usize,
    dead: usize,
    paused: usize,
    restarting: usize,
    created: usize,
}

fn count_states(containers: &[crate::containers::ContainerInfo]) -> StateCounts {
    let mut c = StateCounts::default();
    for ci in containers {
        match ci.state.as_str() {
            "running" => c.running += 1,
            "exited" => c.exited += 1,
            "dead" => c.dead += 1,
            "paused" => c.paused += 1,
            "restarting" => c.restarting += 1,
            "created" => c.created += 1,
            _ => {}
        }
    }
    c
}

/// Extract the integer in `Exited (N)` from a docker `Status` string. Returns
/// `None` when the prefix is absent or the captured slice is not a valid
/// integer. Used by the FLEET / ATTENTION cards to flag non-zero exits
/// without firing a per-container inspect.
fn parse_exit_code_from_status(status: &str) -> Option<i32> {
    let prefix = "Exited (";
    let start = status.find(prefix)?;
    let after = &status[start + prefix.len()..];
    let end = after.find(')')?;
    after[..end].parse().ok()
}

#[derive(Default, Debug)]
struct InspectSignals {
    restart_loops: Vec<(String, u32)>,
    oom_count: usize,
}

/// Restart-count threshold above which a container is flagged as a
/// restart loop in the host detail ATTENTION card. Five gives docker's
/// `on-failure:5` policy room to do its job before purple raises
/// the flag — only persistent loops past that policy show up here.
const RESTART_LOOP_THRESHOLD: u32 = 5;

/// Maximum restart-loop rows to render inside one ATTENTION card. More
/// than this and the eye starts to skim past; the rest are dropped
/// silently. Aligned with the truncation on the host detail render path.
const ATTENTION_RESTART_LOOP_CAP: usize = 3;

/// Best-effort aggregate over the inspect cache for containers on this
/// host. Iterates the cache by container ID; missing entries are simply
/// absent from the result.
fn collect_inspect_signals(
    app: &App,
    containers: &[crate::containers::ContainerInfo],
) -> InspectSignals {
    let mut out = InspectSignals::default();
    for c in containers {
        let Some(entry) = app.containers_overview.inspect_cache.entries.get(&c.id) else {
            continue;
        };
        let Ok(insp) = entry.result.as_ref() else {
            continue;
        };
        if insp.oom_killed {
            out.oom_count += 1;
        }
        if insp.restart_count > RESTART_LOOP_THRESHOLD {
            out.restart_loops
                .push((clean_name(&c.names), insp.restart_count));
        }
    }
    out
}

/// Detail-panel placeholder when there are no rows to select.
fn render_detail_empty(frame: &mut Frame, area: Rect) {
    design::render_empty(frame, area, "No containers cached yet.");
}

/// Compose the detail panel as a stack of section cards. Conditional cards
/// only materialise when they have content, mirroring host detail's
/// VAULT SSH / SNIPPETS pattern.
fn build_detail_lines(
    row: &ContainerRow,
    inspect: Option<&Result<crate::containers::ContainerInspect, String>>,
    in_flight: bool,
    spinner_tick: u64,
    box_width: usize,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let max_value_width = box_width
        .saturating_sub(4)
        .saturating_sub(design::SECTION_LABEL_W as usize);
    let running = is_running(&row.state);

    // Header card: container name in title border, "on alias" + state line.
    design::section_open(&mut lines, &row.name, box_width);
    design::section_line(
        &mut lines,
        vec![Span::styled(format!("on {}", row.alias), theme::muted())],
        box_width,
    );

    let (glyph, glyph_style) = if running {
        ("\u{25CF}", theme::online_dot_pulsing(spinner_tick))
    } else {
        ("\u{25CB}", theme::muted())
    };
    let state_text = if running {
        row.status.clone()
    } else if row.status.is_empty() {
        row.state.to_lowercase()
    } else {
        row.status.clone()
    };
    let state_style = if running {
        theme::online_dot_pulsing(spinner_tick)
    } else {
        theme::muted()
    };
    design::section_line(
        &mut lines,
        vec![
            Span::styled(format!("{} ", glyph), glyph_style),
            Span::styled(state_text, state_style),
        ],
        box_width,
    );
    design::section_close(&mut lines, box_width);

    let inspect_ok = inspect.and_then(|r| r.as_ref().ok());

    // ATTENTION card: only when something demands it. Bubbles up above the
    // happy-path lifecycle card so an exited / OOM row catches the eye
    // first.
    if let Some(insp) = inspect_ok {
        let attention = insp.oom_killed || (insp.exit_code != 0 && !running);
        if attention {
            design::section_open(&mut lines, "ATTENTION", box_width);
            if insp.exit_code != 0 {
                let meaning = crate::containers::exit_code_meaning(insp.exit_code);
                let value = match meaning {
                    Some(m) => format!("{}  {}", insp.exit_code, m),
                    None => insp.exit_code.to_string(),
                };
                // exit != 0 is "be aware" (warning), OOM is "act now" (error).
                design::section_field_styled(
                    &mut lines,
                    "Exit",
                    &value,
                    theme::warning(),
                    max_value_width,
                    box_width,
                );
            }
            if insp.oom_killed {
                design::section_field_styled(
                    &mut lines,
                    "OOM",
                    "killed",
                    theme::error(),
                    max_value_width,
                    box_width,
                );
            }
            design::section_close(&mut lines, box_width);
        }
    }

    // LIFECYCLE card: restart, timestamps, pid, stop signal.
    if let Some(insp) = inspect_ok {
        let has_lifecycle = insp.restart_policy.is_some()
            || insp.restart_count > 0
            || !insp.created_at.is_empty()
            || !insp.started_at.is_empty()
            || !insp.finished_at.is_empty()
            || insp.stop_signal.is_some()
            || insp.pid.is_some();
        if has_lifecycle {
            design::section_open(&mut lines, "LIFECYCLE", box_width);
            if let Some(p) = insp.restart_policy.as_deref() {
                design::section_field(&mut lines, "Restart", p, max_value_width, box_width);
            }
            // Restart count: only render when the field is meaningful (a
            // policy is set or we already saw restarts).
            let show_count = insp.restart_policy.is_some() || insp.restart_count > 0;
            if show_count {
                let style = if insp.restart_count > 0 {
                    theme::warning()
                } else {
                    theme::muted()
                };
                design::section_field_styled(
                    &mut lines,
                    "Restarts",
                    &insp.restart_count.to_string(),
                    style,
                    max_value_width,
                    box_width,
                );
            }
            if let Some(c) = format_iso_timestamp(&insp.created_at) {
                design::section_field(&mut lines, "Created", &c, max_value_width, box_width);
            }
            if let Some(s) = format_iso_timestamp(&insp.started_at) {
                design::section_field(&mut lines, "Started", &s, max_value_width, box_width);
            }
            if let Some(s) = format_iso_timestamp(&insp.finished_at) {
                design::section_field(&mut lines, "Stopped", &s, max_value_width, box_width);
            }
            // Stop signal: SIGTERM is the implicit docker default; only
            // surface when the image overrides it.
            if let Some(sig) = insp.stop_signal.as_deref() {
                if sig != "SIGTERM" {
                    let stop_text = match insp.stop_timeout {
                        Some(t) => format!("{} · {}s timeout", sig, t),
                        None => sig.to_string(),
                    };
                    design::section_field(
                        &mut lines,
                        "Stop sig",
                        &stop_text,
                        max_value_width,
                        box_width,
                    );
                }
            }
            if let Some(p) = insp.pid {
                design::section_field(
                    &mut lines,
                    "Pid",
                    &p.to_string(),
                    max_value_width,
                    box_width,
                );
            }
            // Synced: when the host's container listing was last refreshed.
            // Replaces the old list-header `synced Xm` badge so the staleness
            // signal is tied to a specific container instead of the whole tab.
            if row.cache_timestamp > 0 {
                let now = current_unix_secs();
                let age_secs = now.saturating_sub(row.cache_timestamp);
                let age_text =
                    crate::messages::relative_age(std::time::Duration::from_secs(age_secs));
                let style = if age_secs > 300 {
                    theme::warning()
                } else {
                    theme::muted()
                };
                design::section_field_styled(
                    &mut lines,
                    "Synced",
                    &age_text,
                    style,
                    max_value_width,
                    box_width,
                );
            }
            design::section_close(&mut lines, box_width);
        }
    } else if let Some(Err(e)) = inspect {
        design::section_open(&mut lines, "DETAILS", box_width);
        design::section_field_styled(
            &mut lines,
            "error",
            e,
            theme::error(),
            max_value_width,
            box_width,
        );
        design::section_close(&mut lines, box_width);
    } else if inspect.is_none() && in_flight {
        design::section_open(&mut lines, "DETAILS", box_width);
        design::section_field(
            &mut lines,
            "loading",
            "fetching inspect…",
            max_value_width,
            box_width,
        );
        design::section_close(&mut lines, box_width);
    }

    // APP card: image identity + run command. Always renders because Image
    // and ID come from the cached docker ps row, even when inspect is
    // absent.
    {
        design::section_open(&mut lines, "APP", box_width);
        design::section_field(&mut lines, "Image", &row.image, max_value_width, box_width);
        if let Some(insp) = inspect_ok {
            if let Some(v) = insp.image_version.as_deref() {
                let version_text = match insp.image_revision.as_deref() {
                    Some(r) => format!("{} · #{}", v, r),
                    None => v.to_string(),
                };
                design::section_field(
                    &mut lines,
                    "Version",
                    &version_text,
                    max_value_width,
                    box_width,
                );
            }
            if let Some(s) = insp.image_source.as_deref() {
                design::section_field(&mut lines, "Source", s, max_value_width, box_width);
            }
            if let Some(d) = insp.image_digest.as_deref() {
                design::section_field(
                    &mut lines,
                    "Digest",
                    &short_digest(d),
                    max_value_width,
                    box_width,
                );
            }
        }
        design::section_field(
            &mut lines,
            "ID",
            &short_id(&row.id),
            max_value_width,
            box_width,
        );
        if let Some(insp) = inspect_ok {
            // WorkDir: drop the implicit "/" so default-rooted images
            // stay quiet. Cmd / Entrypoint moved out to its own CMD
            // card below so long commands can wrap without a label
            // column eating their width.
            if let Some(w) = insp.working_dir.as_deref() {
                if w != "/" && !w.is_empty() {
                    design::section_field(&mut lines, "WorkDir", w, max_value_width, box_width);
                }
            }
        }
        design::section_close(&mut lines, box_width);
    }

    // CMD card: full-width, no label column. Cmd takes precedence
    // (it is what actually runs); Entrypoint surfaces only when Cmd
    // is absent. Wraps onto multiple lines so long pipelines stay
    // legible instead of getting truncated by a row-height budget.
    if let Some(insp) = inspect_ok {
        let cmd_text = insp
            .command
            .as_deref()
            .filter(|c| !c.is_empty())
            .map(|c| c.join(" "))
            .or_else(|| {
                insp.entrypoint
                    .as_deref()
                    .filter(|e| !e.is_empty())
                    .map(|e| e.join(" "))
            });
        if let Some(text) = cmd_text {
            design::section_open(&mut lines, "CMD", box_width);
            let wrap_width = box_width.saturating_sub(3);
            for chunk in wrap_to_lines(&text, wrap_width, 3) {
                design::section_line(
                    &mut lines,
                    vec![Span::styled(chunk, theme::muted())],
                    box_width,
                );
            }
            design::section_close(&mut lines, box_width);
        }
    }

    // HEALTH card: present when the image defines a healthcheck or the
    // runtime reports a status. Otherwise stay quiet so containers without
    // probes don't add a blank card.
    if let Some(insp) = inspect_ok {
        let render_health = insp.health.is_some()
            || insp.health_test.is_some()
            || insp.health_failing_streak.is_some();
        if render_health {
            design::section_open(&mut lines, "HEALTH", box_width);
            let (status_text, status_style) = match insp.health.as_deref() {
                Some("healthy") => ("healthy".to_string(), theme::online_dot()),
                Some("unhealthy") => ("unhealthy".to_string(), theme::error()),
                Some("starting") => ("starting".to_string(), theme::warning()),
                Some(other) => (other.to_string(), theme::muted()),
                None => ("not reporting".to_string(), theme::muted()),
            };
            design::section_field_styled(
                &mut lines,
                "Status",
                &status_text,
                status_style,
                max_value_width,
                box_width,
            );
            if let Some(test) = insp.health_test.as_deref() {
                let cmd_text = format_health_test(test);
                if !cmd_text.is_empty() {
                    design::section_field(
                        &mut lines,
                        "Check",
                        &cmd_text,
                        max_value_width,
                        box_width,
                    );
                }
            }
            if let Some(streak) = insp.health_failing_streak {
                let interval_suffix = insp
                    .health_interval_ns
                    .map(|n| format!(" · {} interval", format_duration_ns(n)))
                    .unwrap_or_default();
                let streak_text = format!("{} failing{}", streak, interval_suffix);
                let style = if streak > 0 {
                    theme::warning()
                } else {
                    theme::muted()
                };
                design::section_field_styled(
                    &mut lines,
                    "Streak",
                    &streak_text,
                    style,
                    max_value_width,
                    box_width,
                );
            }
            design::section_close(&mut lines, box_width);
        }
    }

    // SECURITY card: only when something deviates from default. Sits
    // high in the priority order so audit-relevant findings stay
    // visible even on tight panels where lower cards get clipped.
    if let Some(insp) = inspect_ok {
        let user_is_root = matches!(insp.user.as_deref(), Some("root") | Some("0") | Some("0:0"));
        let apparmor_deviates = matches!(
            insp.apparmor_profile.as_deref(),
            Some(p) if p != "docker-default" && p != "default" && !p.is_empty()
        );
        let seccomp_deviates = matches!(
            insp.seccomp_profile.as_deref(),
            Some(p) if p != "default" && !p.is_empty()
        );
        let render_security = insp.privileged
            || insp.readonly_rootfs
            || !insp.cap_add.is_empty()
            || !insp.cap_drop.is_empty()
            || apparmor_deviates
            || seccomp_deviates
            || user_is_root;
        if render_security {
            design::section_open(&mut lines, "SECURITY", box_width);
            if let Some(u) = insp.user.as_deref() {
                let user_style = if user_is_root {
                    theme::warning()
                } else {
                    theme::muted()
                };
                design::section_field_styled(
                    &mut lines,
                    "User",
                    u,
                    user_style,
                    max_value_width,
                    box_width,
                );
            }
            if insp.privileged {
                design::section_field_styled(
                    &mut lines,
                    "Privileged",
                    "yes",
                    theme::error(),
                    max_value_width,
                    box_width,
                );
            }
            if insp.readonly_rootfs {
                design::section_field(&mut lines, "RO rootfs", "yes", max_value_width, box_width);
            }
            if !insp.cap_add.is_empty() {
                design::section_field(
                    &mut lines,
                    "Caps +",
                    &insp.cap_add.join(", "),
                    max_value_width,
                    box_width,
                );
            }
            if !insp.cap_drop.is_empty() {
                design::section_field(
                    &mut lines,
                    "Caps -",
                    &insp.cap_drop.join(", "),
                    max_value_width,
                    box_width,
                );
            }
            if apparmor_deviates {
                if let Some(p) = insp.apparmor_profile.as_deref() {
                    design::section_field(&mut lines, "AppArmor", p, max_value_width, box_width);
                }
            }
            if seccomp_deviates {
                if let Some(p) = insp.seccomp_profile.as_deref() {
                    design::section_field(&mut lines, "Seccomp", p, max_value_width, box_width);
                }
            }
            design::section_close(&mut lines, box_width);
        }
    }

    // RESOURCES card: only when any limit is set or the log driver
    // deviates from json-file/journald (which our `l logs` action assumes).
    if let Some(insp) = inspect_ok {
        let non_standard_log = insp
            .log_driver
            .as_deref()
            .map(|d| d != "json-file" && d != "journald")
            .unwrap_or(false);
        let has_resources = insp.memory_limit.is_some()
            || insp.cpu_limit_nanos.is_some()
            || insp.pids_limit.is_some()
            || non_standard_log;
        if has_resources {
            design::section_open(&mut lines, "RESOURCES", box_width);
            if let Some(m) = insp.memory_limit {
                design::section_field(
                    &mut lines,
                    "Memory",
                    &format_memory_bytes(m),
                    max_value_width,
                    box_width,
                );
            }
            if let Some(c) = insp.cpu_limit_nanos {
                design::section_field(
                    &mut lines,
                    "CPU",
                    &format_cpu_nanos(c),
                    max_value_width,
                    box_width,
                );
            }
            if let Some(p) = insp.pids_limit {
                design::section_field(
                    &mut lines,
                    "PIDs",
                    &p.to_string(),
                    max_value_width,
                    box_width,
                );
            }
            if non_standard_log {
                if let Some(d) = insp.log_driver.as_deref() {
                    design::section_field(&mut lines, "Logs", d, max_value_width, box_width);
                }
            }
            design::section_close(&mut lines, box_width);
        }
    }

    // NETWORK card: ROUTE-style ladder. ○ host → ● network → ◉ container,
    // with port mappings as branches. Mirrors the host-detail ROUTE
    // pattern so the network stack reads as a path, not a field list.
    {
        let inspect_has_net = inspect_ok
            .map(|i| {
                i.network_mode.is_some()
                    || i.hostname
                        .as_deref()
                        .map(|s| !s.is_empty())
                        .unwrap_or(false)
                    || !i.networks.is_empty()
            })
            .unwrap_or(false);
        let has_ports = !row.ports.trim().is_empty();
        if inspect_has_net || has_ports {
            design::section_open(&mut lines, "NETWORK", box_width);
            let mode = inspect_ok
                .and_then(|i| i.network_mode.as_deref())
                .unwrap_or("");
            let hostname = inspect_ok.and_then(|i| i.hostname.as_deref()).unwrap_or("");
            let networks: &[crate::containers::NetworkInfo] =
                inspect_ok.map(|i| i.networks.as_slice()).unwrap_or(&[]);

            // Node 1: ○ host (always)
            design::section_line(
                &mut lines,
                vec![
                    Span::styled("  \u{25CB} ", theme::muted()),
                    Span::styled("host", theme::muted()),
                ],
                box_width,
            );

            // Node 2: ● network (only when not host/none mode and a
            // network is attached; matches docker semantics where host
            // mode shares the host namespace and none has no network).
            let show_net_node = mode != "host" && mode != "none" && !networks.is_empty();
            if show_net_node {
                design::section_line(
                    &mut lines,
                    vec![Span::styled("  \u{250A}", theme::muted())],
                    box_width,
                );
                for net in networks {
                    let net_label = if mode.is_empty() || mode == net.name {
                        net.name.clone()
                    } else {
                        format!("{} \u{00B7} {}", mode, net.name)
                    };
                    design::section_line(
                        &mut lines,
                        vec![
                            Span::styled("  \u{25CF} ", theme::muted()),
                            Span::styled(net_label, theme::bold()),
                        ],
                        box_width,
                    );
                    if !net.ip_address.is_empty() {
                        design::section_line(
                            &mut lines,
                            vec![
                                Span::styled("  \u{250A}  ", theme::muted()),
                                Span::styled(net.ip_address.clone(), theme::muted()),
                            ],
                            box_width,
                        );
                    }
                }
                design::section_line(
                    &mut lines,
                    vec![Span::styled("  \u{250A}", theme::muted())],
                    box_width,
                );
            } else if mode == "host" {
                design::section_line(
                    &mut lines,
                    vec![
                        Span::styled("  \u{250A}  ", theme::muted()),
                        Span::styled("host network".to_string(), theme::muted()),
                    ],
                    box_width,
                );
            } else if mode == "none" {
                design::section_line(
                    &mut lines,
                    vec![
                        Span::styled("  \u{250A}  ", theme::muted()),
                        Span::styled("network: none".to_string(), theme::warning()),
                    ],
                    box_width,
                );
            }

            // Node 3: ◉ container
            let container_id_short = short_id(&row.id);
            let container_label = if !hostname.is_empty() && hostname != container_id_short {
                format!("{}  ({})", row.name, hostname)
            } else if !container_id_short.is_empty() {
                format!("{}  ({})", row.name, container_id_short)
            } else {
                row.name.clone()
            };
            design::section_line(
                &mut lines,
                vec![
                    Span::styled("  \u{25C9} ", theme::accent()),
                    Span::styled(container_label, theme::bold()),
                ],
                box_width,
            );

            // Port branches: filter to public bindings, dedupe IPv4/IPv6.
            if has_ports {
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                for raw in row.ports.split(',').map(str::trim) {
                    if raw.is_empty() {
                        continue;
                    }
                    let is_public = raw.starts_with("0.0.0.0:") || raw.starts_with("[::]:");
                    let after_host = raw
                        .strip_prefix("0.0.0.0:")
                        .or_else(|| raw.strip_prefix("[::]:"))
                        .unwrap_or(raw);
                    let port_part = after_host.split("->").next().unwrap_or(after_host);
                    let port_part = port_part.split('/').next().unwrap_or(port_part);
                    let proto = after_host
                        .split('/')
                        .nth(1)
                        .map(|p| format!("/{}", p))
                        .unwrap_or_default();
                    let key = format!(":{}{}", port_part, proto);
                    if !seen.insert(key.clone()) {
                        continue;
                    }
                    let suffix = if is_public { "  pub" } else { "" };
                    design::section_line(
                        &mut lines,
                        vec![
                            Span::styled("      \u{2192} ", theme::muted()),
                            Span::styled(key, theme::muted()),
                            Span::styled(suffix.to_string(), theme::muted()),
                        ],
                        box_width,
                    );
                }
            }
            design::section_close(&mut lines, box_width);
        }
    }

    // MOUNTS card: aligned 2-column table. host-path → container-path
    // with a trailing rw/ro mode tag. Source and dest pad to the
    // longest content per column instead of a 50/50 split, so short
    // paths do not leave a wide gap before the arrow. The mode flag
    // stays right-flush via a flex spacer between dest and mode.
    // Falls back to a 50/50 truncated split when content cannot fit.
    if let Some(insp) = inspect_ok {
        if !insp.mounts.is_empty() {
            design::section_open(&mut lines, "MOUNTS", box_width);
            // section_line strips 3 cols for the left/right borders.
            let inner = box_width.saturating_sub(3);
            const ARROW: &str = " \u{2192} ";
            const ARROW_W: usize = 3;
            const MODE_W: usize = 2;
            const SEP_MIN: usize = 2;
            let source_max = insp
                .mounts
                .iter()
                .map(|m| m.source.width())
                .max()
                .unwrap_or(0);
            let dest_max = insp
                .mounts
                .iter()
                .map(|m| m.destination.width())
                .max()
                .unwrap_or(0);
            let needed = source_max + ARROW_W + dest_max + SEP_MIN + MODE_W;
            let (source_w, dest_w) = if needed <= inner {
                (source_max, dest_max)
            } else {
                let total_path = inner.saturating_sub(ARROW_W + SEP_MIN + MODE_W);
                let s = total_path / 2;
                (s, total_path.saturating_sub(s))
            };
            for m in &insp.mounts {
                let source = pad_or_truncate_path(&m.source, source_w);
                let dest = pad_or_truncate_path(&m.destination, dest_w);
                let mode = if m.read_only { "ro" } else { "rw" };
                let used = source_w + ARROW_W + dest_w + MODE_W;
                let spacer_w = inner.saturating_sub(used).max(SEP_MIN);
                design::section_line(
                    &mut lines,
                    vec![
                        Span::styled(source, theme::muted()),
                        Span::styled(ARROW, theme::muted()),
                        Span::styled(dest, theme::bold()),
                        Span::raw(" ".repeat(spacer_w)),
                        Span::styled(mode.to_string(), theme::muted()),
                    ],
                    box_width,
                );
            }
            design::section_close(&mut lines, box_width);
        }
    }

    // COMPOSE card: only for compose-managed containers. Mirrors the
    // PROXMOX VE / VAULT SSH cards on the host detail.
    if let Some(insp) = inspect_ok {
        if insp.compose_project.is_some() || insp.compose_service.is_some() {
            design::section_open(&mut lines, "COMPOSE", box_width);
            if let Some(p) = insp.compose_project.as_deref() {
                design::section_field(&mut lines, "Project", p, max_value_width, box_width);
            }
            if let Some(s) = insp.compose_service.as_deref() {
                design::section_field(&mut lines, "Service", s, max_value_width, box_width);
            }
            design::section_close(&mut lines, box_width);
        }
    }

    lines
}

/// Format `HostConfig.Memory` bytes as a panel value (`512 MB`, `1.5 GB`).
/// Sub-megabyte values render as raw bytes since they only happen on
/// pathological misconfigurations.
fn format_memory_bytes(bytes: u64) -> String {
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        let g = bytes as f64 / GB as f64;
        if g.fract().abs() < 0.05 {
            format!("{:.0} GB", g)
        } else {
            format!("{:.1} GB", g)
        }
    } else if bytes >= MB {
        let m = bytes as f64 / MB as f64;
        format!("{:.0} MB", m)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Format `NanoCpus` as a fractional core count (`1.5 cores`). Whole-core
/// values drop the trailing `.0`.
fn format_cpu_nanos(nanos: u64) -> String {
    let cores = nanos as f64 / 1_000_000_000.0;
    if cores.fract().abs() < 0.05 {
        format!("{:.0} cores", cores)
    } else {
        format!("{:.1} cores", cores)
    }
}

/// Format a nanosecond duration as the largest natural unit (`30s`, `5m`,
/// `2h`). Used for healthcheck intervals.
fn format_duration_ns(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else if secs > 0 {
        format!("{}s", secs)
    } else {
        format!("{}ms", ns / 1_000_000)
    }
}

/// Format a `Healthcheck.Test` array into a readable command. Docker
/// stores it as `["CMD", "curl", "-fs", url]` or `["CMD-SHELL", "..."]`.
/// `["NONE"]` means the image disabled the inherited healthcheck.
fn format_health_test(test: &[String]) -> String {
    if test.is_empty() {
        return String::new();
    }
    match test[0].as_str() {
        "CMD" | "CMD-SHELL" => test[1..].join(" "),
        "NONE" => "disabled".to_string(),
        _ => test.join(" "),
    }
}

/// Convert a docker/podman RFC3339 timestamp (`2026-05-09T08:00:00.123Z`)
/// into the compact "YYYY-MM-DD HH:MM:SS" form the detail panel renders.
/// Returns `None` for empty strings and the Go zero-time
/// `0001-01-01T00:00:00Z` that docker emits when a field is unset.
fn format_iso_timestamp(s: &str) -> Option<String> {
    if s.is_empty() || s.starts_with("0001-") {
        return None;
    }
    let main = s.split('.').next().unwrap_or(s);
    let main = main.trim_end_matches('Z');
    Some(main.replace('T', " "))
}

/// Truncate a path-like string to fit the 48-column detail panel,
/// preserving the right-hand segment (the leaf is usually more
/// informative than the prefix). Reuse for any panel value that may
/// exceed the column budget.
fn truncate_panel_value(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut = max.saturating_sub(2);
    let take_from_end = cut;
    let chars: Vec<char> = s.chars().collect();
    let start = chars.len().saturating_sub(take_from_end);
    let suffix: String = chars[start..].iter().collect();
    format!("…{}", suffix)
}

/// Snap a row count down to the latest card-close (`╰`) within `cap`
/// so the panel never clips a card mid-content.
fn snap_top_to_card_boundary(lines: &[Line<'static>], cap: u16) -> u16 {
    let cap_us = cap as usize;
    // Walk backwards looking for ╰ (close border) lines. Each one
    // sits at index `i`; including it means keeping `i + 1` rows.
    let mut best: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().take(cap_us) {
        let starts_with_close = line
            .spans
            .first()
            .map(|s| s.content.starts_with('\u{2570}'))
            .unwrap_or(false);
        if starts_with_close {
            best = Some(i + 1);
        }
    }
    best.map(|n| n as u16).unwrap_or(cap)
}

/// Hard-wrap on character boundary onto up to `max_lines` lines of
/// `width` cols; trailing `…` when the input still overflows.
fn wrap_to_lines(s: &str, width: usize, max_lines: usize) -> Vec<String> {
    if width == 0 || max_lines == 0 {
        return Vec::new();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut start = 0;
    while start < chars.len() && out.len() < max_lines {
        let remaining = chars.len() - start;
        let take = remaining.min(width);
        let is_last_slot = out.len() + 1 == max_lines;
        let overflows = is_last_slot && take < remaining;
        let end = start + take;
        let chunk: String = if overflows {
            // Reserve one column for the trailing `…`.
            let cut = end.saturating_sub(1);
            let mut s: String = chars[start..cut].iter().collect();
            s.push('\u{2026}');
            s
        } else {
            chars[start..end].iter().collect()
        };
        out.push(chunk);
        start = end;
    }
    out
}

/// Pad-or-truncate a path-like string to `w` columns, preserving the
/// leaf via left-truncation. Sibling of `pad_or_truncate` which
/// right-truncates; both produce exactly `w` cols of output.
fn pad_or_truncate_path(s: &str, w: usize) -> String {
    let cur = s.width();
    if cur == w {
        return s.to_string();
    }
    if cur < w {
        return format!("{}{}", s, " ".repeat(w - cur));
    }
    let truncated = truncate_panel_value(s, w);
    let tw = truncated.width();
    if tw < w {
        format!("{}{}", truncated, " ".repeat(w - tw))
    } else {
        truncated
    }
}

/// Compress a long sha256 image digest into `sha256:abcdef…1234` so
/// the 48-col panel has space for the row alignment without dropping
/// the prefix that identifies the algorithm.
fn short_digest(d: &str) -> String {
    if let Some(hex) = d.strip_prefix("sha256:") {
        if hex.len() > 12 {
            return format!("sha256:{}…{}", &hex[..6], &hex[hex.len() - 4..]);
        }
    }
    d.to_string()
}

/// Trim a 64-char container ID to the 12-char short form `docker ps`
/// shows. Leaves shorter IDs untouched so test fixtures stay readable.
fn short_id(id: &str) -> String {
    if id.len() <= 12 {
        id.to_string()
    } else {
        id[..12].to_string()
    }
}

fn render_footer(frame: &mut Frame, area: Rect, app: &mut App) {
    use crate::messages::footer as fl;
    // Mirror the host_list footer shape (Enter · / · # · v · :) with the
    // tag affordance swapped for `l logs`. K/S/e (restart, stop, exec),
    // s (sort) and r/R (refresh) stay as keybindings and are documented
    // in the help screen, but live outside the always-visible footer to
    // keep it readable on narrow terminals.
    let view_label = if app.containers_overview.view_mode == ViewMode::Detailed {
        " compact "
    } else {
        fl::ACTION_DETAIL
    };
    let spans = design::Footer::new()
        .primary("Enter", fl::ENTER_SHELL)
        .action("/", fl::ACTION_SEARCH)
        .action("l", fl::ACTION_LOGS)
        .action("v", view_label)
        .action(":", fl::ACTION_JUMP)
        .into_spans();
    super::render_footer_with_help(frame, area, spans, app);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::{ContainerCacheEntry, ContainerInfo, ContainerRuntime};
    use std::collections::HashMap;

    type RawContainer<'a> = (&'a str, &'a str, &'a str, &'a str);
    type RawCacheEntry<'a> = (&'a str, &'a [RawContainer<'a>]);

    fn cache_with(entries: &[RawCacheEntry<'_>]) -> HashMap<String, ContainerCacheEntry> {
        let mut map = HashMap::new();
        for (alias, items) in entries {
            let containers = items
                .iter()
                .map(|(id, name, image, state)| ContainerInfo {
                    id: id.to_string(),
                    names: name.to_string(),
                    image: image.to_string(),
                    state: state.to_string(),
                    status: "Up 5 minutes".to_string(),
                    ports: String::new(),
                })
                .collect();
            map.insert(
                alias.to_string(),
                ContainerCacheEntry {
                    timestamp: 0,
                    runtime: ContainerRuntime::Docker,
                    engine_version: None,
                    containers,
                },
            );
        }
        map
    }

    fn app_with_cache(cache: HashMap<String, ContainerCacheEntry>) -> App {
        let mut app = crate::demo::build_demo_app();
        app.container_cache = cache;
        app
    }

    #[test]
    fn alpha_host_sort_orders_by_host_then_name() {
        let cache = cache_with(&[
            ("zeus", &[("1", "alpha", "img", "running")]),
            (
                "apollo",
                &[
                    ("2", "zebra", "img", "running"),
                    ("3", "ant", "img", "exited"),
                ],
            ),
        ]);
        let app = app_with_cache(cache);
        let rows = visible_rows(&app);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].alias, "apollo");
        assert_eq!(rows[0].name, "ant");
        assert_eq!(rows[1].alias, "apollo");
        assert_eq!(rows[1].name, "zebra");
        assert_eq!(rows[2].alias, "zeus");
    }

    #[test]
    fn alpha_container_sort_orders_by_name_then_host() {
        let cache = cache_with(&[
            ("zeus", &[("1", "alpha", "img", "running")]),
            ("apollo", &[("2", "zebra", "img", "running")]),
        ]);
        let mut app = app_with_cache(cache);
        app.containers_overview.sort_mode = ContainersSortMode::AlphaContainer;
        let rows = visible_rows(&app);
        assert_eq!(rows[0].name, "alpha");
        assert_eq!(rows[1].name, "zebra");
    }

    #[test]
    fn search_filters_on_alias_name_or_image() {
        let cache = cache_with(&[
            ("zeus", &[("1", "alpha", "redis:7", "running")]),
            ("apollo", &[("2", "zebra", "postgres:16", "exited")]),
        ]);
        let mut app = app_with_cache(cache);
        app.search.query = Some("postgres".to_string());
        let rows = visible_rows(&app);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "zebra");

        app.search.query = Some("ZEUS".to_string());
        let rows = visible_rows(&app);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].alias, "zeus");
    }

    #[test]
    fn empty_search_query_returns_everything() {
        let cache = cache_with(&[("zeus", &[("1", "alpha", "img", "running")])]);
        let mut app = app_with_cache(cache);
        app.search.query = Some(String::new());
        let rows = visible_rows(&app);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn clean_name_strips_docker_leading_slash() {
        assert_eq!(clean_name("/web"), "web");
        assert_eq!(clean_name("web"), "web");
    }

    #[test]
    fn is_running_is_case_insensitive() {
        assert!(is_running("running"));
        assert!(is_running("Running"));
        assert!(!is_running("exited"));
        assert!(!is_running(""));
    }

    #[test]
    fn format_iso_timestamp_strips_t_and_fraction() {
        assert_eq!(
            format_iso_timestamp("2026-05-09T08:00:00Z"),
            Some("2026-05-09 08:00:00".to_string())
        );
        assert_eq!(
            format_iso_timestamp("2026-05-09T08:00:00.123456789Z"),
            Some("2026-05-09 08:00:00".to_string())
        );
    }

    #[test]
    fn format_iso_timestamp_rejects_empty_and_zero_time() {
        assert_eq!(format_iso_timestamp(""), None);
        // Go's zero time, emitted by docker for unset finished_at.
        assert_eq!(format_iso_timestamp("0001-01-01T00:00:00Z"), None);
    }

    #[test]
    fn pad_or_truncate_pads_short_strings() {
        assert_eq!(pad_or_truncate("hi", 5), "hi   ");
    }

    #[test]
    fn pad_or_truncate_truncates_long_strings() {
        // super::truncate uses `…` (1 column) so a 10-col input squeezed
        // to 5 cols becomes 4 chars + `…`.
        let out = pad_or_truncate("abcdefghij", 5);
        assert_eq!(out.chars().count(), 5);
        assert!(out.ends_with('…'));
    }

    fn col_row(name: &str, image: &str) -> ContainerRow {
        ContainerRow {
            id: format!("id-{}", name),
            alias: "h".to_string(),
            name: name.to_string(),
            image: image.to_string(),
            state: "running".to_string(),
            status: "Up 1m".to_string(),
            ports: String::new(),
            uptime: Some("1m".to_string()),
            cache_timestamp: 0,
        }
    }

    #[test]
    fn compute_columns_enables_uptime_when_wide_enough() {
        let rows = [col_row("svc", "img:1")];
        let cols = compute_columns(rows.iter(), 200, false);
        assert!(cols.show_uptime);
    }

    #[test]
    fn compute_columns_keeps_uptime_at_modest_width() {
        // PORTS is gone, so a width that previously demoted PORTS while
        // keeping UPTIME must still keep UPTIME.
        let rows = [col_row(
            "very-long-container-name-here",
            "registry.example.com/long/image:v1",
        )];
        let cols = compute_columns(rows.iter(), 75, false);
        assert!(cols.show_uptime, "UPTIME survives modest widths");
    }

    #[test]
    fn compute_columns_drops_uptime_at_extreme_width() {
        // Below the UPTIME-fit threshold even at IMAGE_MIN, the only
        // flex column disappears. With STATUS, HEALTH and PORTS
        // gone the threshold sits below 40 cols.
        let rows = [col_row("svc", "img")];
        let cols = compute_columns(rows.iter(), 35, false);
        assert!(!cols.show_uptime);
    }

    #[test]
    fn state_glyph_running_with_unhealthy_health_uses_error_tier() {
        let (glyph, _) = state_glyph("running", Some("unhealthy"), "Up 1m", 0);
        assert_eq!(glyph, design::ICON_ONLINE);
    }

    #[test]
    fn state_glyph_dead_state_uses_error_glyph() {
        let (glyph, _) = state_glyph("dead", None, "Dead", 0);
        assert_eq!(glyph, design::ICON_ERROR);
    }

    #[test]
    fn state_glyph_exited_with_nonzero_code_uses_error_glyph() {
        let (glyph, _) = state_glyph("exited", None, "Exited (137) 2h ago", 0);
        assert_eq!(glyph, design::ICON_ERROR);
    }

    #[test]
    fn state_glyph_exited_with_zero_code_uses_hollow_circle() {
        let (glyph, _) = state_glyph("exited", None, "Exited (0) 1m ago", 0);
        assert_eq!(glyph, "\u{25CB}");
    }

    #[test]
    fn state_glyph_paused_uses_half_circle() {
        let (glyph, _) = state_glyph("paused", None, "Paused", 0);
        assert_eq!(glyph, "\u{25D0}");
    }

    #[test]
    fn state_glyph_running_no_health_pulses_default_dot() {
        let (glyph, _) = state_glyph("running", None, "Up 5d", 0);
        assert_eq!(glyph, design::ICON_ONLINE);
    }

    #[test]
    fn build_detail_lines_running_container_has_no_exit_row() {
        let row = ContainerRow {
            id: "c1".to_string(),
            alias: "web".to_string(),
            name: "nginx".to_string(),
            image: "nginx:1.25".to_string(),
            state: "running".to_string(),
            status: "Up 3 hours".to_string(),
            ports: "0.0.0.0:80->80/tcp".to_string(),
            uptime: Some("3h".to_string()),
            cache_timestamp: 0,
        };
        let inspect = crate::containers::ContainerInspect {
            exit_code: 0,
            oom_killed: false,
            started_at: "2026-05-09T08:00:00Z".to_string(),
            finished_at: String::new(),
            health: Some("healthy".to_string()),
            restart_count: 0,
            command: Some(vec!["nginx".to_string(), "-g".to_string()]),
            entrypoint: None,
            env_count: 5,
            mount_count: 1,
            networks: vec![],
            image_digest: None,
            restart_policy: None,
            user: None,
            privileged: false,
            readonly_rootfs: false,
            apparmor_profile: None,
            seccomp_profile: None,
            cap_add: Vec::new(),
            cap_drop: Vec::new(),
            mounts: Vec::new(),
            compose_project: None,
            compose_service: None,
            ..Default::default()
        };
        let result = Ok(inspect);
        let lines = build_detail_lines(&row, Some(&result), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("nginx"));
        assert!(text.contains("on web"));
        assert!(text.contains("Up 3 hours"));
        // HEALTH card materialises because health is reported.
        assert!(text.contains("HEALTH"));
        assert!(text.contains("healthy"));
        assert!(text.contains("Started"));
        assert!(
            !text.contains("ATTENTION"),
            "running container must not raise ATTENTION card"
        );
        assert!(
            !text.contains("OOM"),
            "running container must not show OOM row"
        );
        assert!(
            !text.contains("Stopped"),
            "running container must not show Stopped row"
        );
    }

    #[test]
    fn build_detail_lines_oom_killed_shows_exit_and_oom() {
        let row = ContainerRow {
            id: "c2".to_string(),
            alias: "db".to_string(),
            name: "postgres".to_string(),
            image: "postgres:16".to_string(),
            state: "exited".to_string(),
            status: "Exited (137) 2 minutes ago".to_string(),
            ports: String::new(),
            uptime: None,
            cache_timestamp: 0,
        };
        let inspect = crate::containers::ContainerInspect {
            exit_code: 137,
            oom_killed: true,
            started_at: "2026-05-09T07:00:00Z".to_string(),
            finished_at: "2026-05-09T08:00:00Z".to_string(),
            health: None,
            restart_count: 3,
            command: None,
            entrypoint: Some(vec!["/docker-entrypoint.sh".to_string()]),
            env_count: 0,
            mount_count: 0,
            networks: vec![],
            image_digest: None,
            restart_policy: None,
            user: None,
            privileged: false,
            readonly_rootfs: false,
            apparmor_profile: None,
            seccomp_profile: None,
            cap_add: Vec::new(),
            cap_drop: Vec::new(),
            mounts: Vec::new(),
            compose_project: None,
            compose_service: None,
            ..Default::default()
        };
        let result = Ok(inspect);
        let lines = build_detail_lines(&row, Some(&result), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("Exit"));
        assert!(text.contains("137"));
        assert!(text.contains("OOM"));
        assert!(text.contains("killed"));
        assert!(text.contains("Restarts"));
        assert!(text.contains("Stopped"));
        // Cmd absent: entrypoint takes its place inside the dedicated
        // CMD card. No "Command" or "Entrypoint" labels appear because
        // the CMD card has no label column.
        assert!(text.contains("CMD"));
        assert!(text.contains("/docker-entrypoint.sh"));
        assert!(!text.contains("Command"));
    }

    #[test]
    fn build_detail_lines_no_inspect_shows_loading_when_in_flight() {
        let row = ContainerRow {
            id: "c3".to_string(),
            alias: "host".to_string(),
            name: "demo".to_string(),
            image: "img".to_string(),
            state: "running".to_string(),
            status: "Up 1m".to_string(),
            ports: String::new(),
            uptime: Some("1m".to_string()),
            cache_timestamp: 0,
        };
        let lines = build_detail_lines(&row, None, true, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("loading"));
    }

    #[test]
    fn build_detail_lines_renders_audit_fields_when_inspect_present() {
        let row = ContainerRow {
            id: "abcdef0123456789".to_string(),
            alias: "audit-host".to_string(),
            name: "auth-svc".to_string(),
            image: "auth:1.2.3".to_string(),
            state: "running".to_string(),
            status: "Up 5 weeks (healthy)".to_string(),
            ports: "0.0.0.0:443->443/tcp,127.0.0.1:9000->9000/tcp".to_string(),
            uptime: Some("5w".to_string()),
            cache_timestamp: 0,
        };
        let inspect = crate::containers::ContainerInspect {
            exit_code: 0,
            oom_killed: false,
            started_at: "2026-04-02T19:46:58Z".to_string(),
            finished_at: String::new(),
            health: Some("healthy".to_string()),
            restart_count: 0,
            command: Some(vec!["/auth".to_string()]),
            entrypoint: None,
            env_count: 12,
            mount_count: 2,
            networks: vec![],
            image_digest: Some(
                "sha256:a4f1e7c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7c91d"
                    .to_string(),
            ),
            restart_policy: Some("unless-stopped".to_string()),
            user: Some("root".to_string()),
            privileged: false,
            readonly_rootfs: false,
            apparmor_profile: Some("docker-default".to_string()),
            seccomp_profile: Some("default".to_string()),
            cap_add: Vec::new(),
            cap_drop: vec!["NET_RAW".to_string()],
            mounts: vec![
                crate::containers::MountInfo {
                    source: "/etc/letsencrypt".to_string(),
                    destination: "/etc/letsencrypt".to_string(),
                    read_only: false,
                },
                crate::containers::MountInfo {
                    source: "certs".to_string(),
                    destination: "/etc/nginx/certs".to_string(),
                    read_only: true,
                },
            ],
            compose_project: Some("auth-stack".to_string()),
            compose_service: Some("auth".to_string()),
            ..Default::default()
        };
        let result = Ok(inspect);
        let lines = build_detail_lines(&row, Some(&result), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        // LIFECYCLE card: restart policy on its own row, count on a
        // second row (renamed from the old combined "Restart  X · 0
        // restarts" string).
        assert!(text.contains("LIFECYCLE"));
        assert!(text.contains("Restart"), "expected Restart row");
        assert!(
            text.contains("unless-stopped"),
            "expected restart policy to render"
        );
        assert!(text.contains("Restarts"), "expected Restarts count row");
        // SECURITY card surfaces because user is root and cap-drop is
        // non-empty. Defaults (apparmor=docker-default, seccomp=default)
        // stay silenced.
        assert!(text.contains("SECURITY"));
        assert!(text.contains("User"));
        assert!(text.contains("root"));
        assert!(text.contains("Caps -"));
        assert!(text.contains("NET_RAW"));
        assert!(
            !text.contains("AppArmor"),
            "docker-default apparmor profile is noise; suppress"
        );
        assert!(
            !text.contains("Seccomp"),
            "default seccomp profile is noise; suppress"
        );
        // APP card: image + truncated digest.
        assert!(text.contains("APP"));
        assert!(text.contains("Digest"));
        assert!(text.contains("sha256:a4f1e7…c91d"));
        // NETWORK card (ladder): public ports surface as `:N  pub`
        // branches, loopback ports do not get the `pub` annotation.
        assert!(text.contains("NETWORK"));
        assert!(
            text.contains(":443"),
            "expected :443 branch in network ladder"
        );
        assert!(text.contains("pub"), "public binding must surface");
        assert!(
            !text.contains(":9000  pub"),
            "loopback ports must not be flagged pub"
        );
        // MOUNTS card (aligned table) shows source → dest with mode.
        assert!(text.contains("MOUNTS"));
        assert!(text.contains("rw"));
        assert!(text.contains("ro"));
        assert!(text.contains("/etc/nginx/certs"));
        // Layout regression: source must pad to the longest source-width
        // (16 cols for `/etc/letsencrypt`), NOT to a 50/50 split that
        // would leave a wide gap on the 5-char `certs` row before the
        // arrow. We isolate the MOUNTS rows by walking forward from the
        // MOUNTS header until the next section divider.
        let lines_strs: Vec<&str> = text.lines().collect();
        let mount_header_idx = lines_strs
            .iter()
            .position(|l| l.contains("MOUNTS"))
            .expect("MOUNTS header must be present");
        let mount_rows: Vec<&&str> = lines_strs[mount_header_idx + 1..]
            .iter()
            .take_while(|l| !l.starts_with("\u{2570}") && !l.contains("COMPOSE"))
            .filter(|l| l.contains(" \u{2192} "))
            .collect();
        assert_eq!(
            mount_rows.len(),
            2,
            "two mount rows must contain the arrow within the MOUNTS card"
        );
        // find() returns a byte offset; convert to character/column
        // count so the assertion is invariant to multi-byte border
        // glyphs like `│` (3 bytes / 1 column).
        let arrow_columns: Vec<usize> = mount_rows
            .iter()
            .map(|line| {
                let byte_pos = line.find(" \u{2192} ").unwrap_or(usize::MAX);
                line[..byte_pos].chars().count()
            })
            .collect();
        assert_eq!(
            arrow_columns[0], arrow_columns[1],
            "arrows must align across mount rows"
        );
        // The arrow should sit just past the longest source (16 cols)
        // plus the leading "│ " prefix (2 cols) = column 18, not at
        // column 21 where a 50/50 split (19-col source + 2-col prefix)
        // would push it.
        let expected_arrow_col = "│ /etc/letsencrypt".chars().count();
        assert_eq!(
            arrow_columns[0], expected_arrow_col,
            "arrow must hug the longest source, not float on a 50/50 split"
        );
        assert!(
            !text.contains("Env 12"),
            "Env count teaser dropped; full list not implemented"
        );
    }

    #[test]
    fn build_detail_lines_inspect_error_shows_error_message() {
        let row = ContainerRow {
            id: "c4".to_string(),
            alias: "host".to_string(),
            name: "demo".to_string(),
            image: "img".to_string(),
            state: "running".to_string(),
            status: "Up 1m".to_string(),
            ports: String::new(),
            uptime: Some("1m".to_string()),
            cache_timestamp: 0,
        };
        let err: Result<crate::containers::ContainerInspect, String> =
            Err("permission denied".to_string());
        let lines = build_detail_lines(&row, Some(&err), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("error"));
        assert!(text.contains("permission denied"));
    }

    fn make_row(name: &str, alias: &str, state: &str, status: &str) -> ContainerRow {
        ContainerRow {
            id: "abc123def456".to_string(),
            alias: alias.to_string(),
            name: name.to_string(),
            image: "img:latest".to_string(),
            state: state.to_string(),
            status: status.to_string(),
            ports: String::new(),
            uptime: None,
            cache_timestamp: 0,
        }
    }

    #[test]
    fn health_card_omitted_when_no_healthcheck() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let inspect = crate::containers::ContainerInspect {
            health: None,
            health_test: None,
            health_failing_streak: None,
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(inspect)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(
            !text.contains("HEALTH"),
            "HEALTH card must stay hidden when image has no healthcheck"
        );
    }

    #[test]
    fn health_card_renders_unhealthy_with_streak() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let inspect = crate::containers::ContainerInspect {
            health: Some("unhealthy".to_string()),
            health_test: Some(vec![
                "CMD".to_string(),
                "curl".to_string(),
                "-fs".to_string(),
            ]),
            health_interval_ns: Some(30_000_000_000),
            health_failing_streak: Some(4),
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(inspect)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("HEALTH"));
        assert!(text.contains("unhealthy"));
        assert!(text.contains("curl -fs"));
        assert!(text.contains("4 failing"));
        assert!(text.contains("30s interval"));
    }

    #[test]
    fn resources_card_omitted_when_no_limits() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let inspect = crate::containers::ContainerInspect {
            memory_limit: None,
            cpu_limit_nanos: None,
            pids_limit: None,
            log_driver: Some("json-file".to_string()),
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(inspect)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(
            !text.contains("RESOURCES"),
            "RESOURCES card must stay hidden when no limits and json-file logs"
        );
    }

    #[test]
    fn resources_card_renders_when_memory_set() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let inspect = crate::containers::ContainerInspect {
            memory_limit: Some(536870912),
            cpu_limit_nanos: Some(1_500_000_000),
            pids_limit: Some(200),
            log_driver: Some("json-file".to_string()),
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(inspect)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("RESOURCES"));
        assert!(text.contains("512 MB"));
        assert!(text.contains("1.5 cores"));
        assert!(text.contains("200"));
        assert!(
            !text.contains("Logs"),
            "default json-file log driver stays silent"
        );
    }

    #[test]
    fn resources_card_surfaces_non_standard_log_driver() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let inspect = crate::containers::ContainerInspect {
            log_driver: Some("syslog".to_string()),
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(inspect)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("RESOURCES"));
        assert!(text.contains("Logs"));
        assert!(text.contains("syslog"));
    }

    #[test]
    fn security_card_omitted_for_default_profile() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let inspect = crate::containers::ContainerInspect {
            user: Some("app".to_string()),
            privileged: false,
            readonly_rootfs: false,
            apparmor_profile: Some("docker-default".to_string()),
            seccomp_profile: Some("default".to_string()),
            cap_add: vec![],
            cap_drop: vec![],
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(inspect)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(
            !text.contains("SECURITY"),
            "SECURITY stays hidden for non-root + default profiles + no caps"
        );
    }

    #[test]
    fn security_card_renders_when_privileged() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let inspect = crate::containers::ContainerInspect {
            privileged: true,
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(inspect)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("SECURITY"));
        assert!(text.contains("Privileged"));
    }

    #[test]
    fn compose_card_only_when_compose_managed() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let bare = crate::containers::ContainerInspect::default();
        let lines = build_detail_lines(&row, Some(&Ok(bare)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(!text.contains("COMPOSE"));

        let managed = crate::containers::ContainerInspect {
            compose_project: Some("edge".to_string()),
            compose_service: Some("nginx".to_string()),
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(managed)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("COMPOSE"));
        assert!(text.contains("Project"));
        assert!(text.contains("edge"));
    }

    #[test]
    fn attention_card_only_for_failed_or_oom_containers() {
        let row = make_row("svc", "host", "exited", "Exited (137)");
        let oom = crate::containers::ContainerInspect {
            exit_code: 137,
            oom_killed: true,
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(oom)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("ATTENTION"));
        assert!(text.contains("OOM"));
        assert!(text.contains("137"));

        let healthy_row = make_row("svc", "host", "running", "Up 1m");
        let healthy = crate::containers::ContainerInspect::default();
        let lines = build_detail_lines(&healthy_row, Some(&Ok(healthy)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(!text.contains("ATTENTION"));
    }

    #[test]
    fn stop_signal_only_when_overrides_default() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let default_sig = crate::containers::ContainerInspect {
            restart_policy: Some("no".to_string()),
            stop_signal: Some("SIGTERM".to_string()),
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(default_sig)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(
            !text.contains("Stop sig"),
            "default SIGTERM stays silent in LIFECYCLE card"
        );

        let custom_sig = crate::containers::ContainerInspect {
            restart_policy: Some("no".to_string()),
            stop_signal: Some("SIGQUIT".to_string()),
            stop_timeout: Some(30),
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(custom_sig)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("Stop sig"));
        assert!(text.contains("SIGQUIT"));
        assert!(text.contains("30s timeout"));
    }

    #[test]
    fn format_memory_bytes_units() {
        assert_eq!(format_memory_bytes(512 * 1024 * 1024), "512 MB");
        assert_eq!(format_memory_bytes(1024 * 1024 * 1024), "1 GB");
        assert_eq!(format_memory_bytes(1536 * 1024 * 1024), "1.5 GB");
    }

    #[test]
    fn format_cpu_nanos_whole_and_fractional() {
        assert_eq!(format_cpu_nanos(1_000_000_000), "1 cores");
        assert_eq!(format_cpu_nanos(2_000_000_000), "2 cores");
        assert_eq!(format_cpu_nanos(1_500_000_000), "1.5 cores");
    }

    #[test]
    fn format_duration_ns_picks_natural_unit() {
        assert_eq!(format_duration_ns(30_000_000_000), "30s");
        assert_eq!(format_duration_ns(120_000_000_000), "2m");
        assert_eq!(format_duration_ns(7_200_000_000_000), "2h");
    }

    #[test]
    fn network_ladder_renders_mode_and_hostname() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let inspect = crate::containers::ContainerInspect {
            network_mode: Some("bridge".to_string()),
            hostname: Some("c1abc123".to_string()),
            networks: vec![crate::containers::NetworkInfo {
                name: "edge_default".to_string(),
                ip_address: "172.18.0.5".to_string(),
            }],
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(inspect)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("NETWORK"));
        // Top node: ○ host
        assert!(text.contains('\u{25CB}'), "○ host node missing");
        // Middle node: ● bridge · edge_default
        assert!(text.contains('\u{25CF}'), "● network node missing");
        assert!(text.contains("bridge"));
        assert!(text.contains("edge_default"));
        assert!(text.contains("172.18.0.5"));
        // Container node ◉ + container name + hostname
        assert!(text.contains('\u{25C9}'), "◉ container node missing");
        assert!(text.contains("svc"));
        assert!(text.contains("c1abc123"));
    }

    #[test]
    fn workdir_root_is_suppressed_app_keeps_other_paths() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let root = crate::containers::ContainerInspect {
            working_dir: Some("/".to_string()),
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(root)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(
            !text.contains("WorkDir"),
            "implicit / WorkDir stays silent in APP card"
        );

        let custom = crate::containers::ContainerInspect {
            working_dir: Some("/var/lib/postgres".to_string()),
            ..Default::default()
        };
        let lines = build_detail_lines(&row, Some(&Ok(custom)), false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("WorkDir"));
        assert!(text.contains("/var/lib/postgres"));
    }

    #[test]
    fn cache_only_render_omits_inspect_cards() {
        // No inspect data and not in flight: panel relies on `docker ps`
        // row data only. Header always renders, APP renders Image+ID,
        // NETWORK renders only when ports are cached. LIFECYCLE / HEALTH /
        // RESOURCES / MOUNTS / SECURITY / COMPOSE all stay hidden.
        let row = ContainerRow {
            id: "deadbeef0000".to_string(),
            alias: "host".to_string(),
            name: "svc".to_string(),
            image: "img:1".to_string(),
            state: "running".to_string(),
            status: "Up 1m".to_string(),
            ports: "0.0.0.0:80->80/tcp".to_string(),
            uptime: Some("1m".to_string()),
            cache_timestamp: 0,
        };
        let lines = build_detail_lines(&row, None, false, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        // Header survives.
        assert!(text.contains("svc"));
        assert!(text.contains("on host"));
        assert!(text.contains("Up 1m"));
        // APP card from cached row data only (no Version / Digest / Cmd).
        assert!(text.contains("APP"));
        assert!(text.contains("img:1"));
        assert!(text.contains("deadbeef0000"));
        // NETWORK card surfaces because ports are present in the cache
        // row. Ladder layout collapses the public binding to `:80  pub`.
        assert!(text.contains("NETWORK"));
        assert!(text.contains(":80"));
        assert!(text.contains("pub"));
        // Inspect-gated cards are hidden.
        assert!(!text.contains("LIFECYCLE"));
        assert!(!text.contains("HEALTH"));
        assert!(!text.contains("RESOURCES"));
        assert!(!text.contains("MOUNTS"));
        assert!(!text.contains("SECURITY"));
        assert!(!text.contains("COMPOSE"));
        assert!(!text.contains("ATTENTION"));
        assert!(!text.contains("DETAILS"));
    }

    #[test]
    fn details_card_shows_loading_when_inspect_in_flight() {
        let row = make_row("svc", "host", "running", "Up 1m");
        let lines = build_detail_lines(&row, None, true, 0, 48);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        assert!(text.contains("DETAILS"));
        assert!(text.contains("loading"));
        assert!(text.contains("fetching inspect"));
    }

    #[test]
    fn logs_card_omitted_when_height_below_three() {
        let logs: Vec<String> = vec!["a".to_string()];
        let lines = build_logs_card(Some(&Ok(logs)), false, 96, 2);
        assert!(lines.is_empty());
    }

    #[test]
    fn logs_card_renders_open_close_borders_when_height_three() {
        let lines = build_logs_card(None, false, 96, 3);
        assert_eq!(lines.len(), 3, "open + one inner + close");
        let first = lines[0].to_string();
        let last = lines[2].to_string();
        assert!(first.contains("LOGS"));
        assert!(first.starts_with('\u{256D}'));
        assert!(last.starts_with('\u{2570}'));
    }

    #[test]
    fn logs_card_fills_when_more_lines_than_capacity() {
        // 30 log lines, panel allows 12 inner rows: render the trailing
        // 12 (line18..line29). Lines older than the tail window are
        // dropped.
        let logs: Vec<String> = (0..30).map(|i| format!("line{}", i)).collect();
        let lines = build_logs_card(Some(&Ok(logs)), false, 96, 14);
        assert_eq!(lines.len(), 14);
        let body: Vec<String> = lines[1..13].iter().map(|l| l.to_string()).collect();
        for (i, expected) in (18..30).enumerate() {
            assert!(
                body[i].contains(&format!("line{}", expected)),
                "row {} expected line{} got {}",
                i,
                expected,
                body[i]
            );
        }
        assert!(!lines.iter().any(|l| l.to_string().contains("line17")));
        assert!(!lines.iter().any(|l| l.to_string().contains("line0 ")));
    }

    #[test]
    fn logs_card_pads_when_fewer_lines_than_capacity() {
        // Only 3 log lines but the card has 12 inner rows. All 3 render
        // and the bottom 9 rows are blank padding so the close border
        // lands at card_height - 1.
        let logs: Vec<String> = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let lines = build_logs_card(Some(&Ok(logs)), false, 96, 14);
        assert_eq!(lines.len(), 14);
        // First three inner rows carry the log content.
        let body_text = lines[1..13]
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("|");
        assert!(body_text.contains("a"));
        assert!(body_text.contains("b"));
        assert!(body_text.contains("c"));
        // Padding rows still wear the box sides so the card looks flush.
        for line in &lines[4..13] {
            let s = line.to_string();
            assert!(s.starts_with('\u{2502}'));
            assert!(s.ends_with('\u{2502}'));
        }
    }

    #[test]
    fn logs_card_loading_state_renders_status() {
        let lines = build_logs_card(None, true, 96, 8);
        let text = lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("LOGS"));
        assert!(text.contains("loading"));
    }

    #[test]
    fn logs_card_error_state_renders_message() {
        let err: Result<Vec<String>, String> = Err("permission denied".to_string());
        let lines = build_logs_card(Some(&err), false, 96, 8);
        let text = lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("error"));
        assert!(text.contains("permission denied"));
    }

    #[test]
    fn logs_card_empty_log_set_says_no_output() {
        let lines = build_logs_card(Some(&Ok(vec![])), false, 96, 8);
        let text = lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("(no output)"));
    }

    #[test]
    fn logs_card_truncates_overlong_lines() {
        let long_line = "x".repeat(300);
        let lines = build_logs_card(Some(&Ok(vec![long_line])), false, 48, 5);
        // Each rendered line must fit within box_width visually. We
        // assert the trailing ellipsis to confirm truncation happened.
        let body = lines[1].to_string();
        assert!(
            body.contains('…'),
            "expected ellipsis on truncated line, got: {}",
            body
        );
    }

    #[test]
    fn logs_card_height_exactly_matches_card_height() {
        for h in [3usize, 5, 8, 14, 30] {
            let logs: Vec<String> = vec!["one".to_string(), "two".to_string()];
            let lines = build_logs_card(Some(&Ok(logs)), false, 96, h);
            assert_eq!(
                lines.len(),
                h,
                "card_height={} must produce exactly {} lines",
                h,
                h
            );
        }
    }

    #[test]
    fn wrap_to_lines_returns_short_input_unchanged() {
        let out = wrap_to_lines("hello world", 30, 3);
        assert_eq!(out, vec!["hello world".to_string()]);
    }

    #[test]
    fn wrap_to_lines_splits_on_width() {
        // 12 chars, width 5, max 4 lines -> 5,5,2 (3 lines, no overflow)
        let out = wrap_to_lines("abcdefghijkl", 5, 4);
        assert_eq!(out, vec!["abcde", "fghij", "kl"]);
    }

    #[test]
    fn wrap_to_lines_truncates_with_ellipsis_when_overflow() {
        // 12 chars, width 4, max 2 lines: first line "abcd",
        // second line has 1 col reserved for `…` so chunk = "abc…"
        // (chars 4 through 6 then truncated).
        let out = wrap_to_lines("abcdefghijkl", 4, 2);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], "abcd");
        assert!(out[1].ends_with('\u{2026}'));
    }

    #[test]
    fn wrap_to_lines_zero_args_return_empty() {
        assert!(wrap_to_lines("anything", 0, 5).is_empty());
        assert!(wrap_to_lines("anything", 10, 0).is_empty());
    }

    #[test]
    fn pad_or_truncate_path_pads_short() {
        let out = pad_or_truncate_path("/etc", 10);
        assert_eq!(out, "/etc      ");
    }

    #[test]
    fn pad_or_truncate_path_truncates_left_to_preserve_leaf() {
        // Long path: leaf `/foo/bar` should remain visible, prefix
        // gets `…`-marked.
        let out = pad_or_truncate_path("/very/long/prefix/foo/bar", 12);
        assert_eq!(out.chars().count(), 12);
        assert!(out.starts_with('\u{2026}'));
        assert!(out.contains("foo/bar"));
    }

    #[test]
    fn pad_or_truncate_path_exact_width_returns_self() {
        let out = pad_or_truncate_path("abcdef", 6);
        assert_eq!(out, "abcdef");
    }

    #[test]
    fn snap_top_to_card_boundary_keeps_complete_cards() {
        // Build mock lines: open / content / close / open / content / close
        // = 6 lines representing two cards.
        let line = |c: char| Line::from(Span::raw(c.to_string()));
        let lines = vec![
            line('\u{256D}'), // ╭ open
            line(' '),
            line('\u{2570}'), // ╰ close
            line('\u{256D}'),
            line(' '),
            line('\u{2570}'),
        ];
        // cap = 6: both cards fit, snap returns 6.
        assert_eq!(snap_top_to_card_boundary(&lines, 6), 6);
        // cap = 5: only first card fits cleanly (3 lines).
        assert_eq!(snap_top_to_card_boundary(&lines, 5), 3);
        // cap = 3: still first card (boundary at 3).
        assert_eq!(snap_top_to_card_boundary(&lines, 3), 3);
        // cap = 2: no boundary fits, fall back to cap.
        assert_eq!(snap_top_to_card_boundary(&lines, 2), 2);
    }

    #[test]
    fn snap_top_to_card_boundary_no_close_lines_returns_cap() {
        let line = |c: char| Line::from(Span::raw(c.to_string()));
        let lines = vec![line('a'), line('b'), line('c')];
        assert_eq!(snap_top_to_card_boundary(&lines, 2), 2);
    }

    #[test]
    fn format_health_test_strips_cmd_prefix() {
        let test = vec![
            "CMD".to_string(),
            "curl".to_string(),
            "-fs".to_string(),
            "http://localhost".to_string(),
        ];
        assert_eq!(format_health_test(&test), "curl -fs http://localhost");

        let shell = vec!["CMD-SHELL".to_string(), "ps -ef | grep nginx".to_string()];
        assert_eq!(format_health_test(&shell), "ps -ef | grep nginx");

        let none = vec!["NONE".to_string()];
        assert_eq!(format_health_test(&none), "disabled");
    }

    // -- host detail helpers ---------------------------------------------

    #[test]
    fn count_states_buckets_each_kind() {
        let containers = vec![
            ContainerInfo {
                id: "1".into(),
                names: "a".into(),
                image: "img".into(),
                state: "running".into(),
                status: "Up".into(),
                ports: String::new(),
            },
            ContainerInfo {
                id: "2".into(),
                names: "b".into(),
                image: "img".into(),
                state: "running".into(),
                status: "Up".into(),
                ports: String::new(),
            },
            ContainerInfo {
                id: "3".into(),
                names: "c".into(),
                image: "img".into(),
                state: "exited".into(),
                status: "Exited (0) 1h ago".into(),
                ports: String::new(),
            },
            ContainerInfo {
                id: "4".into(),
                names: "d".into(),
                image: "img".into(),
                state: "dead".into(),
                status: "Dead".into(),
                ports: String::new(),
            },
            ContainerInfo {
                id: "5".into(),
                names: "e".into(),
                image: "img".into(),
                state: "paused".into(),
                status: "Paused".into(),
                ports: String::new(),
            },
            ContainerInfo {
                id: "6".into(),
                names: "f".into(),
                image: "img".into(),
                state: "restarting".into(),
                status: "Restarting".into(),
                ports: String::new(),
            },
        ];
        let c = count_states(&containers);
        assert_eq!(c.running, 2);
        assert_eq!(c.exited, 1);
        assert_eq!(c.dead, 1);
        assert_eq!(c.paused, 1);
        assert_eq!(c.restarting, 1);
        assert_eq!(c.created, 0);
    }

    #[test]
    fn exit_code_extracted_when_present() {
        assert_eq!(
            parse_exit_code_from_status("Exited (137) 2h ago"),
            Some(137)
        );
        assert_eq!(parse_exit_code_from_status("Exited (0) 1m ago"), Some(0));
    }

    #[test]
    fn exit_code_absent_when_status_does_not_match() {
        assert_eq!(parse_exit_code_from_status("Up 3 days"), None);
        assert_eq!(parse_exit_code_from_status("Exited"), None);
        assert_eq!(parse_exit_code_from_status("Exited (abc)"), None);
        assert_eq!(parse_exit_code_from_status(""), None);
    }

    fn host_detail_text(app: &App, alias: &str, total: usize, running: usize) -> String {
        let lines = build_host_detail_lines(app, alias, total, running, 80, 30);
        lines.iter().map(|l| l.to_string() + "\n").collect()
    }

    #[test]
    fn host_detail_renders_status_and_fleet_cards_for_healthy_host() {
        // Demo cache + inspect data is the easiest seed: every demo
        // host has a fleet, runtime label, and (most) carry an
        // engine_version on the cache entry.
        let app = crate::demo::build_demo_app();
        let alias = "aws-api-staging";
        let entry = app.container_cache.get(alias).expect("demo seeded");
        let total = entry.containers.len();
        let running = entry
            .containers
            .iter()
            .filter(|c| c.state == "running")
            .count();
        let text = host_detail_text(&app, alias, total, running);
        assert!(text.contains("STATUS"));
        assert!(text.contains("FLEET"));
        assert!(text.contains("ACTIONS"));
        assert!(text.contains("HOST"));
        assert!(text.contains("Docker 25.0.3"));
    }

    #[test]
    fn host_detail_attention_card_appears_for_dead_or_oom_or_restart_loop() {
        // bastion-ams in the demo carries a container with restart_count=14
        // (app-backend) so the inspect-aggregate ATTENTION row triggers.
        let app = crate::demo::build_demo_app();
        let entry = app.container_cache.get("bastion-ams").expect("seeded");
        let total = entry.containers.len();
        let running = entry
            .containers
            .iter()
            .filter(|c| c.state == "running")
            .count();
        let text = host_detail_text(&app, "bastion-ams", total, running);
        assert!(text.contains("ATTENTION"));
        assert!(text.contains("Restart loop"));
    }

    #[test]
    fn host_detail_runtime_falls_back_to_label_only_without_engine_version() {
        // gateway-vpn in the demo deliberately omits engine_version on
        // its cache line. The Runtime row must still render with just
        // "Docker" (no trailing version).
        let app = crate::demo::build_demo_app();
        let entry = app.container_cache.get("gateway-vpn").expect("seeded");
        let total = entry.containers.len();
        let running = entry
            .containers
            .iter()
            .filter(|c| c.state == "running")
            .count();
        let text = host_detail_text(&app, "gateway-vpn", total, running);
        assert!(text.contains("Runtime"));
        assert!(text.contains("Docker"));
        // No semver-shaped trailing fragment after Docker on this host.
        assert!(!text.contains("Docker 25.0"));
        assert!(!text.contains("Docker 24.0"));
    }

    #[test]
    fn host_detail_actions_disable_when_nothing_running() {
        let cache = cache_with(&[(
            "host-x",
            &[("1", "a", "img", "exited"), ("2", "b", "img", "exited")],
        )]);
        let app = app_with_cache(cache);
        let text = host_detail_text(&app, "host-x", 2, 0);
        assert!(text.contains("ACTIONS"));
        assert!(text.contains("nothing running"));
    }

    #[test]
    fn host_detail_last_card_stretches_to_panel_bottom() {
        let cache = cache_with(&[("host-y", &[("1", "n", "img", "running")])]);
        let app = app_with_cache(cache);
        let lines = build_host_detail_lines(&app, "host-y", 1, 1, 60, 40);
        // Panel height in lines is 40 — stretch_last_card must pad up
        // to that count so the bottom border lands flush.
        assert_eq!(lines.len(), 40);
        // The very last line is the closing border of the HOST card.
        let last = lines.last().expect("at least one line");
        let first_span = last.spans.first().expect("border line carries spans");
        assert!(first_span.content.starts_with(design::BOX_BL));
    }

    /// Build a cache entry whose `timestamp` is `age_secs` in the past so
    /// the "Stale" path in ATTENTION (>300s) is exercisable from tests.
    fn cache_with_age(alias: &str, age_secs: u64) -> HashMap<String, ContainerCacheEntry> {
        let mut map = HashMap::new();
        let now = current_unix_secs();
        map.insert(
            alias.to_string(),
            ContainerCacheEntry {
                timestamp: now.saturating_sub(age_secs),
                runtime: ContainerRuntime::Docker,
                engine_version: Some("25.0.3".to_string()),
                containers: vec![ContainerInfo {
                    id: "1".into(),
                    names: "n".into(),
                    image: "img".into(),
                    state: "running".into(),
                    status: "Up 1 hour".into(),
                    ports: String::new(),
                }],
            },
        );
        map
    }

    #[test]
    fn host_detail_attention_card_fires_for_stale_listing() {
        let cache = cache_with_age("host-stale", 700);
        let app = app_with_cache(cache);
        let text = host_detail_text(&app, "host-stale", 1, 1);
        assert!(text.contains("ATTENTION"));
        assert!(text.contains("Stale"));
        assert!(text.contains("r to refresh"));
    }

    #[test]
    fn host_detail_no_attention_card_when_listing_is_fresh_and_nothing_wrong() {
        let cache = cache_with_age("host-fresh", 30);
        let app = app_with_cache(cache);
        let text = host_detail_text(&app, "host-fresh", 1, 1);
        assert!(!text.contains("ATTENTION"));
    }

    // The "tunnels active" branch (`app.tunnels.active.contains_key`)
    // cannot be exercised cleanly from a unit test: `ActiveTunnel` owns
    // a `std::process::Child` for the live ssh tunnel and has no test
    // constructor. Coverage for that branch lives in the demo flow and
    // visual regression goldens. We do exercise the alternative branch
    // (configured tunnel directives without a live session) below.

    #[test]
    fn host_detail_fleet_shows_count_when_tunnel_count_is_set_but_inactive() {
        // Seed a fresh host with tunnel_count > 0 so the FLEET card
        // takes the count branch. We append a HostEntry directly because
        // the demo app's fixed host list does not contain "host-tc".
        let cache = cache_with(&[("host-tc", &[("1", "n", "img", "running")])]);
        let mut app = app_with_cache(cache);
        let host = crate::ssh_config::model::HostEntry {
            alias: "host-tc".to_string(),
            hostname: "10.0.0.1".to_string(),
            user: "deploy".to_string(),
            port: 22,
            tunnel_count: 3,
            ..Default::default()
        };
        app.hosts_state.list.push(host);
        let text = host_detail_text(&app, "host-tc", 1, 1);
        assert!(text.contains("Tunnels"));
        assert!(text.contains("3"));
    }

    #[test]
    fn host_detail_fleet_marks_group_folded_when_collapsed() {
        let cache = cache_with(&[("host-fold", &[("1", "n", "img", "running")])]);
        let mut app = app_with_cache(cache);
        app.containers_overview
            .collapsed_hosts
            .insert("host-fold".to_string());
        let text = host_detail_text(&app, "host-fold", 1, 1);
        assert!(text.contains("Group"));
        assert!(text.contains("folded"));
    }

    #[test]
    fn host_detail_actions_label_changes_when_group_collapsed() {
        let cache = cache_with(&[("host-ex", &[("1", "n", "img", "running")])]);
        let mut app = app_with_cache(cache);
        app.containers_overview
            .collapsed_hosts
            .insert("host-ex".to_string());
        let text = host_detail_text(&app, "host-ex", 1, 1);
        assert!(text.contains("Expand group"));
        assert!(!text.contains("Collapse group"));
    }

    #[test]
    fn host_detail_ping_renders_each_status_variant() {
        let cache = cache_with(&[("host-p", &[("1", "n", "img", "running")])]);
        let mut app = app_with_cache(cache);

        app.ping.status.insert(
            "host-p".into(),
            crate::app::PingStatus::Reachable { rtt_ms: 38 },
        );
        assert!(host_detail_text(&app, "host-p", 1, 1).contains("38ms"));

        app.ping.status.insert(
            "host-p".into(),
            crate::app::PingStatus::Slow { rtt_ms: 812 },
        );
        let slow = host_detail_text(&app, "host-p", 1, 1);
        assert!(slow.contains("slow"));
        assert!(slow.contains("812ms"));

        app.ping
            .status
            .insert("host-p".into(), crate::app::PingStatus::Unreachable);
        assert!(host_detail_text(&app, "host-p", 1, 1).contains("unreachable"));

        app.ping
            .status
            .insert("host-p".into(), crate::app::PingStatus::Checking);
        assert!(host_detail_text(&app, "host-p", 1, 1).contains("checking"));

        app.ping
            .status
            .insert("host-p".into(), crate::app::PingStatus::Skipped);
        assert!(host_detail_text(&app, "host-p", 1, 1).contains("--"));

        app.ping.status.remove("host-p");
        assert!(host_detail_text(&app, "host-p", 1, 1).contains("--"));
    }

    #[test]
    fn restart_loop_threshold_boundary_at_five_excludes_six_includes() {
        // Boundary: > 5, not >= 5. A container at exactly 5 must NOT
        // surface as a restart loop; one at 6 must.
        let app = crate::demo::build_demo_app();
        let make = |restart_count: u32| {
            let info = ContainerInfo {
                id: "boundary-id".into(),
                names: "svc".into(),
                image: "img".into(),
                state: "running".into(),
                status: "Up 1m".into(),
                ports: String::new(),
            };
            (info, restart_count)
        };
        let mut probe = app;
        probe.containers_overview.inspect_cache.entries.clear();
        let (info_at_5, _) = make(5);
        let (info_at_6, _) = make(6);
        // Insert two synthetic inspects keyed by the same id, swapping
        // the restart_count between probes. Easier than building a
        // ContainerInspect literal twice — assert via collect_inspect_signals.
        for rc in [5u32, 6u32] {
            let inspect = crate::containers::ContainerInspect {
                restart_count: rc,
                ..Default::default()
            };
            probe.containers_overview.inspect_cache.entries.insert(
                "boundary-id".into(),
                crate::app::InspectCacheEntry {
                    timestamp: 0,
                    result: Ok(inspect),
                },
            );
            let containers = if rc == 5 {
                vec![info_at_5.clone()]
            } else {
                vec![info_at_6.clone()]
            };
            let signals = collect_inspect_signals(&probe, &containers);
            if rc == 5 {
                assert!(
                    signals.restart_loops.is_empty(),
                    "restart_count == 5 must NOT trigger restart loop"
                );
            } else {
                assert_eq!(
                    signals.restart_loops.len(),
                    1,
                    "restart_count == 6 must trigger one restart loop"
                );
                assert_eq!(signals.restart_loops[0].1, 6);
            }
        }
    }

    #[test]
    fn host_detail_truncates_restart_loop_rows_at_attention_cap() {
        // Seed five containers each with restart_count above threshold.
        // The ATTENTION card must render at most ATTENTION_RESTART_LOOP_CAP
        // (= 3) restart-loop rows; the rest are dropped silently.
        let mut app = crate::demo::build_demo_app();
        app.containers_overview.inspect_cache.entries.clear();
        let mut containers: Vec<ContainerInfo> = Vec::new();
        for i in 0..5 {
            let id = format!("loopy-{}", i);
            let info = ContainerInfo {
                id: id.clone(),
                names: format!("svc-{}", i),
                image: "img".into(),
                state: "running".into(),
                status: "Up 1m".into(),
                ports: String::new(),
            };
            containers.push(info);
            let inspect = crate::containers::ContainerInspect {
                restart_count: 20,
                ..Default::default()
            };
            app.containers_overview.inspect_cache.entries.insert(
                id,
                crate::app::InspectCacheEntry {
                    timestamp: 0,
                    result: Ok(inspect),
                },
            );
        }
        // Override the demo cache so build_host_detail_lines reads the
        // synthetic containers under one alias.
        app.container_cache.insert(
            "loopy-host".into(),
            ContainerCacheEntry {
                timestamp: current_unix_secs(),
                runtime: ContainerRuntime::Docker,
                engine_version: None,
                containers,
            },
        );
        let text = host_detail_text(&app, "loopy-host", 5, 5);
        let count = text.matches("Restart loop").count();
        assert_eq!(
            count, ATTENTION_RESTART_LOOP_CAP,
            "ATTENTION must cap restart-loop rows at the documented limit"
        );
    }

    #[test]
    fn host_detail_action_qualifier_uses_count_with_correct_pluralisation() {
        // Singular vs plural matters for one-off operator readability.
        let cache_one = cache_with(&[("host-1", &[("1", "n", "img", "running")])]);
        let app_one = app_with_cache(cache_one);
        let text_one = host_detail_text(&app_one, "host-1", 1, 1);
        assert!(text_one.contains("1 container"));
        assert!(!text_one.contains("1 containers"));

        let cache_many = cache_with(&[(
            "host-2",
            &[("1", "a", "img", "running"), ("2", "b", "img", "running")],
        )]);
        let app_many = app_with_cache(cache_many);
        let text_many = host_detail_text(&app_many, "host-2", 2, 2);
        assert!(text_many.contains("2 containers"));
    }
}
