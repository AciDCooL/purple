//! Live detail panel — channel lifeline swimlane + client roster.
//!
//! The panel only renders when the selected tunnel is running (the
//! list partition logic in `tunnels_overview` skips it otherwise). The
//! block title carries the entire status line — `● active · N channels
//! · M clients · up T` — so the interior has zero chrome rows. Below
//! the title the swimlane shows one row per SSH channel observed in
//! the last 60 seconds, and below that the roster shows one row per
//! local client process. A single blank row separates the two.
//!
//! When the tunnel is active but has no channels and no clients yet,
//! the panel renders a minimal "waiting for first connection" hint
//! centred in the interior.
//!
//! Honesty rule: the swimlane and roster surface only events and
//! sockets we have observed.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_width::UnicodeWidthStr;

use super::design;
use super::theme;
use super::tunnels_format::{ClientActivity, RosterRow, build_roster, format_age, format_bps};
use crate::app::App;
use crate::tunnel::{TunnelRule, format_uptime};
use crate::tunnel_live::{
    ChannelEventKind, ChannelKind, ClientPeer, DisplayClient, TunnelLiveSnapshot,
};

/// Two-space indent matching the host-list rhythm.
const INDENT: &str = "  ";

/// Window the swimlane covers, in seconds. A short window trades
/// historical depth for visible motion: at 80 chart cells the bar
/// drifts ~4 cells/sec instead of ~1.3, so the half-cell quantum
/// drops from ~377 ms to ~125 ms (~10 fps perceived). Combined with
/// the hue-flow effect this brings the swimlane within the
/// "smooth-enough" range for terminal cell rendering.
const SWIMLANE_WINDOW_SECS: u64 = 20;

/// Floor on the number of channel-lane rows the swimlane keeps when
/// space gets tight. Below this threshold the lanes are not worth
/// rendering at all — better to give the rows to the roster.
const SWIMLANE_MIN_ROWS: usize = 2;

/// Floor on the number of client rows the roster keeps when space
/// gets tight. The detail panel always reserves at least this many
/// roster slots so a single bursty client never gets crowded out by
/// many idle channels.
const ROSTER_MIN_VISIBLE: usize = 3;

/// Body height threshold below which the dashboard is suppressed and
/// the list keeps the full vertical real estate.
pub(super) const DASHBOARD_MIN_BODY_HEIGHT: u16 = 8;

// ── Selection lookup ────────────────────────────────────────────────

struct SelectedRow {
    alias: String,
    rule: TunnelRule,
    started_at: Option<Instant>,
}

fn selected_row(app: &App) -> Option<SelectedRow> {
    let sel = app.ui.tunnels_overview_state().selected()?;
    let pairs = super::tunnels_overview::visible_pairs(
        &app.search,
        &app.hosts_state,
        &app.tunnels,
        &app.history,
    );
    let (alias, rule) = pairs.into_iter().nth(sel)?;
    let started_at = app.tunnels.active_get(&alias).map(|a| a.started_at);
    Some(SelectedRow {
        alias,
        rule,
        started_at,
    })
}

// ── Live data view ──────────────────────────────────────────────────

struct LiveView {
    is_active: bool,
    uptime_secs: u64,
    clients: Vec<DisplayClient>,
    last_exit: Option<(i32, String)>,
    /// Closed channel events in the last `SWIMLANE_WINDOW_SECS`. Age
    /// in fractional seconds so the swimlane bar drifts smoothly
    /// instead of stepping on whole-second boundaries.
    closed_events_smooth: Vec<(u32, ChannelKind, f64, f64)>,
    /// Currently-open channels at snapshot time. Each entry is
    /// `(channel_id, open_age_secs_f64, kind)`.
    currently_open: Vec<(u32, f64, ChannelKind)>,
}

impl LiveView {
    fn from_snapshot(snap: &TunnelLiveSnapshot) -> Self {
        let mut clients = snap.clients.clone();
        clients.sort_by_key(|c| c.age_secs);
        let closed_events_smooth: Vec<(u32, ChannelKind, f64, f64)> = snap
            .events
            .iter()
            .filter(|e| e.kind == ChannelEventKind::Close && e.age_secs <= SWIMLANE_WINDOW_SECS)
            .map(|e| {
                let close_age = e.age_secs as f64;
                let dur = e.duration_secs.unwrap_or(0) as f64;
                (e.channel_id, e.channel_kind, close_age, dur)
            })
            .collect();
        let currently_open: Vec<(u32, f64, ChannelKind)> = snap
            .currently_open
            .iter()
            .map(|(id, age, kind)| (*id, *age as f64, *kind))
            .collect();
        Self {
            is_active: snap.last_exit.is_none(),
            uptime_secs: snap.uptime_secs,
            clients,
            last_exit: snap.last_exit.clone(),
            closed_events_smooth,
            currently_open,
        }
    }

    fn from_runtime(app: &App, alias: &str, rule: &TunnelRule) -> Option<Self> {
        let tunnel = app.tunnels.active_get(alias)?;
        let now = Instant::now();
        let uptime_secs = now.saturating_duration_since(tunnel.started_at).as_secs();

        let mut clients: Vec<DisplayClient> = app
            .tunnels
            .clients()
            .get(&rule.bind_port)
            .map(|peers| {
                peers
                    .iter()
                    .map(|p: &ClientPeer| DisplayClient {
                        src: p.src.clone(),
                        process: p.process.clone(),
                        age_secs: now.saturating_duration_since(p.since).as_secs(),
                        pid: p.pid,
                        responsible_app: p.responsible_app.clone(),
                        current_rx_bps: p.current_rx_bps,
                        current_tx_bps: p.current_tx_bps,
                        viz_history: app
                            .tunnels
                            .peer_viz()
                            .get(&(rule.bind_port, p.src.clone()))
                            .copied()
                            .unwrap_or([0u64; crate::tunnel_live::PEER_VIZ_BUCKETS]),
                        throughput_ready: p.last_sample_at.is_some(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        clients.sort_by_key(|c| c.age_secs);

        let closed_events_smooth: Vec<(u32, ChannelKind, f64, f64)> = tunnel
            .live
            .events
            .iter()
            .filter_map(|e| {
                if e.kind != ChannelEventKind::Close {
                    return None;
                }
                let kind = e.channel_kind?;
                if !kind.is_user_visible() {
                    return None;
                }
                let close_age = now.saturating_duration_since(e.at).as_secs_f64();
                if close_age > SWIMLANE_WINDOW_SECS as f64 {
                    return None;
                }
                let dur = e
                    .opened_at
                    .map(|o| e.at.saturating_duration_since(o).as_secs_f64())
                    .unwrap_or(0.0);
                Some((e.channel_id, kind, close_age, dur))
            })
            .collect();

        let currently_open: Vec<(u32, f64, ChannelKind)> = tunnel
            .live
            .channel_open
            .iter()
            .filter(|(_, (_, kind))| kind.is_user_visible())
            .map(|(id, (open_at, kind))| {
                (
                    *id,
                    now.saturating_duration_since(*open_at).as_secs_f64(),
                    *kind,
                )
            })
            .collect();

        Some(Self {
            is_active: tunnel.live.last_exit.is_none(),
            uptime_secs,
            clients,
            last_exit: tunnel.live.last_exit.clone(),
            closed_events_smooth,
            currently_open,
        })
    }
}

// ── Swimlane lane construction ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
struct Lane {
    channel_id: u32,
    kind: ChannelKind,
    open_age_secs: f64,
    close_age_secs: Option<f64>,
}

impl Lane {
    fn is_open(&self) -> bool {
        self.close_age_secs.is_none()
    }
}

fn build_lanes(live: &LiveView) -> Vec<Lane> {
    let mut lanes: Vec<Lane> = Vec::new();
    for (id, age, kind) in &live.currently_open {
        lanes.push(Lane {
            channel_id: *id,
            kind: *kind,
            open_age_secs: *age,
            close_age_secs: None,
        });
    }
    for (id, kind, close_age, dur) in &live.closed_events_smooth {
        let open_age = close_age + dur;
        lanes.push(Lane {
            channel_id: *id,
            kind: *kind,
            open_age_secs: open_age,
            close_age_secs: Some(*close_age),
        });
    }
    lanes.sort_by(|a, b| match (a.is_open(), b.is_open()) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a
            .open_age_secs
            .partial_cmp(&b.open_age_secs)
            .unwrap_or(std::cmp::Ordering::Equal),
    });
    lanes
}

// ── Render ──────────────────────────────────────────────────────────

pub fn render(frame: &mut Frame, app: &mut App, area: Rect, spinner_tick: u64) {
    let row = match selected_row(app) {
        Some(r) => r,
        None => {
            // Defensive — partition_body should already have hidden us.
            let block = design::main_block_line(Line::default());
            frame.render_widget(block, area);
            return;
        }
    };

    let live: Option<LiveView> = if app.demo_mode {
        app.tunnels
            .demo_live_snapshots()
            .get(&row.alias)
            .map(LiveView::from_snapshot)
    } else {
        LiveView::from_runtime(app, &row.alias, &row.rule)
    };

    let lanes: Vec<Lane> = live.as_ref().map(build_lanes).unwrap_or_default();
    let roster: Vec<RosterRow> = live
        .as_ref()
        .map(|l| build_roster(&l.clients))
        .unwrap_or_default();

    let title = build_title(&row, live.as_ref(), &lanes, &roster, spinner_tick);
    let block = design::main_block_line(title);
    frame.render_widget(block, area);
    // Render into the body-area sub-rect so the sparkline and BPS column
    // never paint flush against the right border. design::body_area
    // applies the BODY_RIGHT_PAD breathing room every other surface uses.
    let inner = design::body_area(area);

    if inner.height == 0 {
        return;
    }

    let inner_w = inner.width as usize;

    // Empty state: tunnel is up but nothing has happened yet.
    if lanes.is_empty() && roster.is_empty() {
        render_waiting_hint(frame, inner, inner_w);
        return;
    }

    let inner_h = inner.height as usize;
    let alloc = allocate_sections(lanes.len(), roster.len(), inner_h);
    let mut y: u16 = 1; // top blank

    // Roster (clients/processes) renders FIRST so the operator's
    // primary scan target — "which app is using my tunnel" — sits at
    // the top of the panel. The channel swimlane follows below as
    // technical context. Channels can be many; processes (after
    // grouping) are usually few, and they are what the operator acts
    // on.
    let visible_roster = &roster[..alloc.roster_visible];
    let (identity_w, spark_w) = roster_layout(visible_roster, inner_w);
    let phase = sparkline_phase(app);
    for r in visible_roster {
        paint_at(
            frame,
            inner,
            y,
            roster_line(r, inner_w, identity_w, spark_w, phase),
        );
        y += 1;
    }
    if alloc.roster_truncated > 0 {
        paint_at(frame, inner, y, more_line(alloc.roster_truncated, inner_w));
        y += 1;
    }

    if alloc.roster_visible > 0 && alloc.lanes_visible > 0 {
        y += 1; // separator blank
    }

    let chart_w = chart_width(inner_w);
    for lane in lanes.iter().take(alloc.lanes_visible) {
        paint_at(frame, inner, y, swimlane_lane_line(lane, chart_w, inner_w));
        y += 1;
    }
    if alloc.lanes_truncated > 0 {
        paint_at(frame, inner, y, more_line(alloc.lanes_truncated, inner_w));
    }
}

/// Continuous animation phase in `[0, 1]` representing how far the
/// renderer has progressed through the gap between the two most recent
/// `push_peer_viz` rotations. Used by `sparkline_for` to drift the
/// wave leftward by one bucket per push interval, so when the data
/// array shifts the visual position lines up exactly. The interval is
/// derived from the actual delta between the last two pushes — that
/// auto-adapts to the platform's lsof poll cadence (~2s on Linux,
/// ~3-4s on macOS due to nettop overhead). Demo mode (visual goldens)
/// returns 0 so snapshots stay deterministic.
fn sparkline_phase(app: &App) -> f64 {
    if app.demo_mode {
        return 0.0;
    }
    let Some(last) = app.tunnels.peer_viz_last_push() else {
        return 0.0;
    };
    // Without a previous push we cannot estimate the interval. Falling
    // back to phase=0 keeps the wave anchored until the second push
    // gives us a real interval to drift across.
    let Some(prev) = app.tunnels.peer_viz_prev_push() else {
        return 0.0;
    };
    let interval_ms = last.saturating_duration_since(prev).as_millis() as f64;
    if interval_ms <= 0.0 {
        return 0.0;
    }
    let elapsed_ms = Instant::now().saturating_duration_since(last).as_millis() as f64;
    (elapsed_ms / interval_ms).clamp(0.0, 1.0)
}

/// Allocation result for one render pass: how many lane rows and
/// roster rows to actually paint, plus how many were truncated (used
/// for the `+N more` line).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SectionAlloc {
    lanes_visible: usize,
    lanes_truncated: usize,
    roster_visible: usize,
    roster_truncated: usize,
}

/// Distribute the panel's inner rows between the roster (clients) and
/// the swimlane (channels). Roster takes priority — apps using the
/// tunnel are the operator's primary scan target, lane detail is
/// secondary context. Each section reserves one row for `+N more`
/// when its content is truncated.
///
/// Inner row layout (roster on top, channels below):
/// ```text
///   1  top blank
///   R  roster rows + optional `+N more`
///   1  separator blank (only when both sections exist)
///   L  lane rows + optional `+N more`
///   1  bottom blank
/// ```
fn allocate_sections(lanes_total: usize, roster_total: usize, inner_h: usize) -> SectionAlloc {
    if inner_h == 0 || (lanes_total == 0 && roster_total == 0) {
        return SectionAlloc::default();
    }
    // Top + bottom blank are always reserved.
    let separator = if lanes_total > 0 && roster_total > 0 {
        1
    } else {
        0
    };
    let budget = inner_h.saturating_sub(2 + separator);

    if lanes_total + roster_total <= budget {
        return SectionAlloc {
            lanes_visible: lanes_total,
            lanes_truncated: 0,
            roster_visible: roster_total,
            roster_truncated: 0,
        };
    }

    // Roster takes priority. Cap at two thirds of budget so a runaway
    // bucket count cannot starve the lane chart entirely; the lane
    // floor still applies on top of that.
    let roster_cap = ((budget * 2) / 3).max(ROSTER_MIN_VISIBLE).min(budget);
    let (roster_visible, roster_truncated) = section_split(roster_total, roster_cap);
    let roster_used = roster_visible + (if roster_truncated > 0 { 1 } else { 0 });
    let lanes_budget = budget.saturating_sub(roster_used);
    let (lanes_visible, lanes_truncated) = if lanes_total == 0 {
        (0, 0)
    } else {
        section_split(lanes_total, lanes_budget.max(SWIMLANE_MIN_ROWS).min(budget))
    };

    SectionAlloc {
        lanes_visible,
        lanes_truncated,
        roster_visible,
        roster_truncated,
    }
}

/// Resolve how many rows of `total` to paint when only `budget` rows
/// are available, reserving one row for the `+N more` line when the
/// section overflows.
fn section_split(total: usize, budget: usize) -> (usize, usize) {
    if total == 0 || budget == 0 {
        return (0, 0);
    }
    if total <= budget {
        return (total, 0);
    }
    // Reserve one slot for the `+N more` row; if the budget cannot
    // afford even that, drop one row from the visible set so the
    // truncation marker still fits.
    let visible = budget.saturating_sub(1).max(1);
    let truncated = total - visible;
    (visible, truncated)
}

fn paint_at(frame: &mut Frame, inner: Rect, y_offset: u16, line: Line<'static>) {
    if y_offset >= inner.height {
        return;
    }
    let area = Rect::new(inner.x, inner.y + y_offset, inner.width, 1);
    frame.render_widget(Paragraph::new(line), area);
}

// ── Title ───────────────────────────────────────────────────────────

fn build_title(
    row: &SelectedRow,
    live: Option<&LiveView>,
    lanes: &[Lane],
    roster: &[RosterRow],
    spinner_tick: u64,
) -> Line<'static> {
    let active = live.is_some_and(|l| l.is_active);
    let failed = live.is_some_and(|l| l.last_exit.is_some());
    let uptime_secs = live
        .map(|l| l.uptime_secs)
        .or_else(|| {
            row.started_at
                .map(|s| Instant::now().saturating_duration_since(s).as_secs())
        })
        .unwrap_or(0);
    let uptime = format_uptime(std::time::Duration::from_secs(uptime_secs));

    // `online_dot_pulsing` matches the host-list rhythm for "live
    // right now" — `success()` is reserved for positive action
    // outcomes per the design-system rule.
    let (dot_glyph, dot_style, state_word, state_style): (&str, Style, &str, Style) = if failed {
        (
            design::ICON_ONLINE,
            theme::error(),
            "broken",
            theme::error(),
        )
    } else if active {
        (
            design::ICON_ONLINE,
            theme::online_dot_pulsing(spinner_tick),
            "active",
            theme::online_dot_pulsing(spinner_tick),
        )
    } else {
        (
            design::ICON_STOPPED,
            theme::muted(),
            "stopped",
            theme::muted(),
        )
    };

    // Channel and client counts dropped from the title — they
    // duplicate the rows below and the aggregates churn once per
    // sample without earning their pixels. The title now reads
    // `● active · up T`, which lets the eye land on uptime
    // immediately. Reserved for a future `· N errors` indicator.
    let _ = (lanes, roster);

    let mut spans: Vec<Span<'static>> = vec![
        Span::raw(" "),
        Span::styled(dot_glyph.to_string(), dot_style),
        Span::raw(" "),
        Span::styled(state_word.to_string(), state_style),
    ];
    if active {
        spans.push(Span::styled(" \u{00B7} ".to_string(), theme::muted()));
        spans.push(Span::styled(format!("up {}", uptime), theme::muted()));
    }
    if let Some((_, err)) = live.and_then(|l| l.last_exit.as_ref()) {
        spans.push(Span::styled(" \u{00B7} ".to_string(), theme::muted()));
        spans.push(Span::styled(err.clone(), theme::error()));
    }
    spans.push(Span::raw(" "));
    Line::from(spans)
}

// ── Empty interior (just-started) ──

fn render_waiting_hint(frame: &mut Frame, inner: Rect, inner_w: usize) {
    if inner.height == 0 {
        return;
    }
    let mid = inner.height / 2;
    let text = "waiting for first connection";
    let pad = inner_w.saturating_sub(text.width()) / 2;
    let line = Line::from(vec![
        Span::raw(" ".repeat(pad)),
        Span::styled(text.to_string(), theme::muted()),
    ]);
    paint_at(frame, inner, mid, line);
}

// ── Swimlane lane line ─────────────────────────────────────────────

fn swimlane_lane_line(lane: &Lane, chart_w: usize, inner_w: usize) -> Line<'static> {
    let id_cell = format!("ch#{}", lane.channel_id);
    let id_padded = pad_right(&id_cell, 6);
    let kind_cell = pad_right(channel_kind_short(lane.kind), 7);

    // Map an age (in fractional seconds) to a fractional column
    // position. Fractional positions give the half-cell rendering
    // below 2x the temporal resolution it would otherwise have, so
    // the bar drifts smoothly between cells instead of jumping a
    // whole cell every full second.
    let chart_w_f = chart_w as f64;
    let max_col = (chart_w_f - 1.0).max(0.0);
    let age_to_col = |age: f64| -> f64 {
        let clamped = age.clamp(0.0, SWIMLANE_WINDOW_SECS as f64);
        let frac = (SWIMLANE_WINDOW_SECS as f64 - clamped) / SWIMLANE_WINDOW_SECS as f64;
        (max_col * frac).clamp(0.0, max_col)
    };

    let open_pos = age_to_col(lane.open_age_secs);
    let close_pos = match lane.close_age_secs {
        Some(age) => age_to_col(age),
        None => max_col,
    };

    // Half-cell coverage rendering. Each cell covers [i, i+1). We
    // check whether its left half [i, i+0.5) and right half
    // [i+0.5, i+1) fall within [open_pos, close_pos]. Combinations
    // map to box-drawing line chars so the bar appears to move in
    // half-cell steps:
    //   left+right → `─`   left only → `╴`   right only → `╶`
    let mut chart: Vec<char> = vec![' '; chart_w];
    if chart_w > 0 && open_pos <= close_pos {
        for (i, cell) in chart.iter_mut().enumerate().take(chart_w) {
            let left_mid = i as f64 + 0.25;
            let right_mid = i as f64 + 0.75;
            let left_in = left_mid >= open_pos && left_mid <= close_pos;
            let right_in = right_mid >= open_pos && right_mid <= close_pos;
            *cell = match (left_in, right_in) {
                (true, true) => '\u{2500}',
                (true, false) => '\u{2574}',
                (false, true) => '\u{2576}',
                (false, false) => ' ',
            };
        }
        // Markers override the line chars at integer-cell positions.
        // The open marker stays at the cell left of `open_pos` so
        // the bar visually starts there. Falls back to `─` when the
        // channel opened before the window — there is no anchor to
        // mark.
        let open_int = open_pos.floor() as usize;
        if open_int < chart_w && lane.open_age_secs < SWIMLANE_WINDOW_SECS as f64 {
            chart[open_int] = '\u{251C}';
        }
        // The close/now marker sits at the integer cell at or after
        // `close_pos` so the arrow / bracket aligns with where the
        // half-cells ended.
        let close_int = close_pos.ceil() as usize;
        if close_int < chart_w {
            chart[close_int] = match lane.close_age_secs {
                None => '\u{25B8}',
                Some(_) => '\u{2524}',
            };
        }
    }
    let chart_str: String = chart.iter().collect();

    // Open lanes paint in `online_dot` green so they read as "live
    // right now" alongside the active-tunnel dot. `success()` is
    // reserved for positive action outcomes per the design-system
    // rule. The lane-flow hue-shift effect mutates this base style
    // each frame to give continuous motion.
    let line_style = if lane.is_open() {
        theme::online_dot()
    } else {
        theme::muted()
    };

    // Right-gutter label. Open lanes show how long they've been
    // running; this number naturally counts up because the channel
    // is still alive. Closed lanes show only the duration the
    // channel lived — that value is final once a channel closes.
    // The bar's position on the time axis already encodes "when"
    // the close happened, so a separate close-recency counter would
    // double-encode the same signal and read as if something were
    // still ticking after the channel ended.
    let right_label = match lane.close_age_secs {
        None => format_age(lane.open_age_secs.floor() as u64),
        Some(close) => {
            let dur = (lane.open_age_secs - close).max(0.0);
            format_age(dur.floor() as u64)
        }
    };
    let right_padded = pad_left(&right_label, 12);

    let mut spans: Vec<Span<'static>> = vec![
        Span::raw(INDENT),
        Span::styled(id_padded, theme::muted()),
        Span::raw(" "),
        Span::styled(kind_cell, theme::muted()),
        Span::styled(chart_str, line_style),
        Span::raw(" "),
        Span::styled(right_padded, theme::muted()),
    ];
    let used: usize = spans.iter().map(|s| s.content.width()).sum();
    if used < inner_w {
        spans.push(Span::raw(" ".repeat(inner_w - used)));
    }
    Line::from(spans)
}

// ── Client roster line ─────────────────────────────────────────────

/// Width of the connection cell (`:55487 · 1m 02s`). Pairs source
/// port and age in one muted cluster — the UI/UX rule that the
/// identity column should not double as a port-and-clock readout.
const CONNECTION_W: usize = 16;
/// Width of the PID cell (`[pid 4194304]` = 13 chars covers Linux's
/// max default `pid_max`). Always muted; suppressed for groups and
/// for known-browser helpers (their PID is a helper-process PID
/// which the operator cannot safely act on).
const PID_W: usize = 13;
/// Width of the live-throughput readout column, right-aligned.
const BPS_W: usize = 11;
/// Floor for the flex sparkline. Below this the chart is omitted so a
/// narrow terminal does not emit a stub that looks like a glitch.
const SPARK_MIN_W: usize = 8;
/// Maximum identity column width before it truncates with `…`. Keeps
/// the right-aligned bps anchored on absurdly long app+process pairs.
const IDENTITY_MAX_W: usize = 36;

/// Build the identity spans for one roster row. Returns the rendered
/// width (cells consumed) so the caller can pad to a column-wide
/// alignment across all rows.
fn identity_spans(row: &RosterRow) -> (Vec<Span<'static>>, usize) {
    use super::tunnels_format::helper_is_noise;

    // Identity highlights:
    //   - app prefix and the `→` separator are muted (context, not focus)
    //   - process / N-conn is the focal label, weighted by activity
    //   - groups always weight their count so a busy app stays scannable
    let process_style = if row.is_group || row.activity == ClientActivity::Active {
        theme::bold()
    } else if row.activity == ClientActivity::Idle {
        theme::muted()
    } else {
        Style::default()
    };

    // For single rows of helper-noise apps (browsers, Slack/Code/etc
    // Electron apps) the helper-process name is implementation noise.
    // Drop it and let the source-port column carry the per-connection
    // identity. Group rows still get the `→ N conn` count, so this
    // only fires for count==1 helpers.
    let hide_process = !row.is_group && !row.app.is_empty() && helper_is_noise(&row.app);

    if hide_process {
        let app_text = truncate(&row.app, IDENTITY_MAX_W);
        let width = app_text.width();
        let app_style = if row.activity == ClientActivity::Active {
            theme::bold()
        } else if row.activity == ClientActivity::Idle {
            theme::muted()
        } else {
            Style::default()
        };
        return (vec![Span::styled(app_text, app_style)], width);
    }

    let mut spans: Vec<Span<'static>> = Vec::with_capacity(3);
    let mut width = 0usize;

    if !row.app.is_empty() {
        let app_text = truncate(&row.app, IDENTITY_MAX_W);
        width += app_text.width();
        spans.push(Span::styled(app_text, theme::muted()));
        // `→` mirrors the host-list and tunnel-forward arrow rhythm
        // (`bind → remote`). Reads as "owns / responsible for".
        let arrow = " \u{2192} ".to_string();
        width += arrow.width();
        spans.push(Span::styled(arrow, theme::muted()));
    }
    let proc_budget = IDENTITY_MAX_W.saturating_sub(width);
    let proc_text = truncate(&row.process, proc_budget.max(1));
    width += proc_text.width();
    spans.push(Span::styled(proc_text, process_style));

    (spans, width)
}

/// Compose the connection cell: `:55487 · 18s` for single rows,
/// `oldest age` for collapsed groups (where no single port applies).
fn connection_text(row: &RosterRow) -> String {
    let age = format_age(row.age_secs);
    if row.is_group || row.src_port.is_empty() {
        age
    } else {
        format!("{} \u{00B7} {}", row.src_port, age)
    }
}

/// Compose the PID cell. Empty for groups and for known-browser
/// helpers (their PID is a helper-process PID and killing it does
/// not do what the operator expects). For everything else,
/// `[pid N]` muted so it stays useful for `lsof -p N` / `kill N`.
fn pid_text(row: &RosterRow) -> String {
    use super::tunnels_format::helper_is_noise;
    if row.is_group || row.pid == 0 {
        return String::new();
    }
    if !row.app.is_empty() && helper_is_noise(&row.app) {
        return String::new();
    }
    format!("[pid {}]", row.pid)
}

/// Render one roster row given the column-wide identity width and
/// flex sparkline width that the caller has computed for the whole
/// roster pass. Layout:
///
/// ```text
///   INDENT  IDENTITY  SP  CONNECTION  SP  PID  SP  SPARK(flex)  SP  BPS
/// ```
///
/// `CONNECTION` pairs `:port · age` in one muted cluster. `PID` is
/// `[pid N]` muted, suppressed for groups and known-browser helpers.
/// `phase` is the sparkline animation phase in `[0, 1]` — set this
/// to drift the wave continuously leftward by one bucket per
/// `push_peer_viz` rotation so the eye reads continuous motion
/// between lsof poll arrivals.
fn roster_line(
    row: &RosterRow,
    inner_w: usize,
    identity_w: usize,
    spark_w: usize,
    phase: f64,
) -> Line<'static> {
    let (mut id_spans, id_used) = identity_spans(row);
    if id_used < identity_w {
        id_spans.push(Span::raw(" ".repeat(identity_w - id_used)));
    }

    let connection_cell = pad_right(&connection_text(row), CONNECTION_W);
    let pid_cell = pad_right(&pid_text(row), PID_W);

    let combined_bps = row.current_rx_bps.saturating_add(row.current_tx_bps);
    let (spark_text, spark_style) = if spark_w == 0 {
        (String::new(), theme::muted())
    } else if row.throughput_ready {
        (
            sparkline_for(&row.viz_history, spark_w, phase),
            if combined_bps > 0 {
                theme::bold()
            } else {
                theme::muted()
            },
        )
    } else {
        (" ".repeat(spark_w), theme::muted())
    };
    let (bps_text, bps_style) = if row.throughput_ready {
        let bps = format_bps(combined_bps);
        (
            pad_left(&bps, BPS_W),
            if combined_bps > 0 {
                theme::accent_bold()
            } else {
                theme::muted()
            },
        )
    } else {
        (pad_left("\u{2014}", BPS_W), theme::muted())
    };

    let mut spans: Vec<Span<'static>> = vec![Span::raw(INDENT)];
    spans.extend(id_spans);
    spans.push(Span::raw("  "));
    spans.push(Span::styled(connection_cell, theme::muted()));
    spans.push(Span::raw("  "));
    spans.push(Span::styled(pid_cell, theme::muted()));
    spans.push(Span::raw("  "));
    spans.push(Span::styled(spark_text, spark_style));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(bps_text, bps_style));
    let used: usize = spans.iter().map(|s| s.content.width()).sum();
    if used < inner_w {
        spans.push(Span::raw(" ".repeat(inner_w - used)));
    }
    Line::from(spans)
}

/// Layout helper: compute the column-wide identity width and the
/// flex sparkline width for a roster pass. The identity column pads
/// to the longest visible identity across rows so vertical alignment
/// reads cleanly; the sparkline absorbs whatever inner width remains
/// after the fixed columns and `BPS_W` are accounted for. One trailing
/// cell is reserved on the right so the BPS readout breathes against
/// the rounded border, matching the trailing whitespace the channel
/// lane line gets from its right-aligned 12-cell label cell.
fn roster_layout(roster: &[RosterRow], inner_w: usize) -> (usize, usize) {
    let identity_w = roster
        .iter()
        .map(|r| identity_spans(r).1)
        .max()
        .unwrap_or(0)
        .min(IDENTITY_MAX_W);
    // INDENT(2) + identity + 2 + CONNECTION + 2 + PID + 2 + 1 + BPS + 1 (right margin).
    let fixed = INDENT.width() + identity_w + 2 + CONNECTION_W + 2 + PID_W + 2 + 1 + BPS_W + 1;
    let spark_w = if inner_w > fixed {
        let avail = inner_w - fixed;
        if avail >= SPARK_MIN_W { avail } else { 0 }
    } else {
        0
    };
    (identity_w, spark_w)
}

/// Render a throughput history as a Braille sparkline. Each cell holds
/// a 2-column × 4-row dot grid, so the visualisation has 2× the
/// horizontal resolution and 4× the vertical resolution of the
/// full-block sparkline it replaces. Adjacent buckets are linearly
/// interpolated so the wave reads as continuous instead of stair-
/// stepped.
///
/// `phase` is a continuous animation parameter in `[0, 1]` that
/// represents the fraction elapsed between the two most recent
/// `push_peer_viz` rotations. Adding it directly to the fractional
/// bucket index drifts the wave leftward by exactly one bucket per
/// push, so when the data array shifts left by one bucket on the
/// next rotation the visual position lines up without snapping. The
/// result is smooth motion at terminal frame rate while underlying
/// lsof samples land only every few seconds.
fn sparkline_for(history: &[u64], width: usize, phase: f64) -> String {
    if width == 0 {
        return String::new();
    }
    let n = history.len();
    if n == 0 {
        return " ".repeat(width);
    }
    // Scale relative to the 75th percentile of the window rather than
    // its absolute max. A single past peak (e.g., a connection-warmup
    // burst) used to drive `max` so high that the rest of the wave
    // collapsed into invisible level-1 dots; p75 is robust to one or
    // two outliers so steady-state traffic stays plainly visible.
    // Values above p75 still clip cleanly at level 4 thanks to the
    // `.min(4)` guard further down. Falls back to `max` when p75 is
    // zero (history mostly empty, e.g., the peer just appeared).
    let scale = percentile_75(history);
    if scale == 0 {
        return " ".repeat(width);
    }
    // Braille 8-dot pattern bit layout (Unicode U+2800 base):
    //   col0 (left)         col1 (right)
    //   row0 = 0x01         row0 = 0x08
    //   row1 = 0x02         row1 = 0x10
    //   row2 = 0x04         row2 = 0x20
    //   row3 = 0x40         row3 = 0x80   (bottom row)
    const COL0_BITS: [u8; 4] = [0x01, 0x02, 0x04, 0x40];
    const COL1_BITS: [u8; 4] = [0x08, 0x10, 0x20, 0x80];

    let total_subcols = width * 2;
    let phase = phase.clamp(0.0, 1.0);
    let mut out = String::with_capacity(width * 4);
    for cell in 0..width {
        let mut bits: u8 = 0;
        for sub in 0..2 {
            let subcol = cell * 2 + sub;
            // Map the sub-cell column to a fractional bucket index in
            // `[0, n)`, then add `phase` so the wave drifts leftward
            // by exactly one bucket between two pushes. Right-edge
            // overshoot is clamped to the latest sample so the wave
            // doesn't fade to zero on every render frame as `phase`
            // approaches 1 — that read as right-edge flicker. The
            // left edge stays at zero for negative pos because the
            // base never goes negative.
            let pos = (subcol as f64 + 0.5) * (n as f64) / (total_subcols.max(1) as f64) + phase;
            let lo = pos.floor() as i64;
            let frac = pos - pos.floor();
            let v_lo = if lo < 0 {
                0.0
            } else if lo as usize >= n {
                history[n - 1] as f64
            } else {
                history[lo as usize] as f64
            };
            let v_hi = if lo + 1 < 0 {
                0.0
            } else if (lo + 1) as usize >= n {
                history[n - 1] as f64
            } else {
                history[(lo + 1) as usize] as f64
            };
            let v = v_lo * (1.0 - frac) + v_hi * frac;

            // Quantise into 0..=4 dot rows for this sub-column.
            let level = ((v / scale as f64) * 4.0).round() as usize;
            let level = level.min(4);
            if level == 0 {
                continue;
            }

            let col_bits = if sub == 0 { &COL0_BITS } else { &COL1_BITS };
            // Fill bottom-up: level=1 lights only the bottom row,
            // level=4 lights all four rows.
            for row in 0..level {
                bits |= col_bits[3 - row];
            }
        }
        let ch = if bits == 0 {
            ' '
        } else {
            char::from_u32(0x2800 + bits as u32).unwrap_or(' ')
        };
        out.push(ch);
    }
    out
}

/// 75th-percentile of a small bucket history, falling back to the
/// max when the percentile resolves to zero (mostly-empty history).
/// Used as the sparkline scale so a single past peak does not drown
/// out steady-state traffic. `Vec` allocation is fine because the
/// caller passes a 12-element slice.
fn percentile_75(history: &[u64]) -> u64 {
    if history.is_empty() {
        return 0;
    }
    let mut sorted: Vec<u64> = history.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() as f64) * 0.75) as usize;
    let p75 = sorted[idx.min(sorted.len() - 1)];
    if p75 > 0 {
        p75
    } else {
        sorted[sorted.len() - 1]
    }
}

fn more_line(remaining: usize, inner_w: usize) -> Line<'static> {
    let text = format!("+{} more", remaining);
    let mut spans = vec![Span::raw(INDENT), Span::styled(text, theme::muted())];
    let used: usize = spans.iter().map(|s| s.content.width()).sum();
    if used < inner_w {
        spans.push(Span::raw(" ".repeat(inner_w - used)));
    }
    Line::from(spans)
}

// ── Helpers ─────────────────────────────────────────────────────────

fn chart_width(inner_w: usize) -> usize {
    // Layout: INDENT + id(6) + " " + kind(7) + chart + " " + right(12).
    let prefix = INDENT.width() + 6 + 1 + 7;
    let suffix = 1 + 12;
    inner_w.saturating_sub(prefix).saturating_sub(suffix)
}

fn channel_kind_short(kind: ChannelKind) -> &'static str {
    match kind {
        ChannelKind::Direct => "direct",
        ChannelKind::Forwarded => "fwd-in",
        ChannelKind::Dynamic => "socks",
        ChannelKind::Other => "other",
    }
}

fn pad_left(s: &str, w: usize) -> String {
    let cur = s.width();
    if cur >= w {
        s.to_string()
    } else {
        format!("{}{}", " ".repeat(w - cur), s)
    }
}

fn pad_right(s: &str, w: usize) -> String {
    let cur = s.width();
    if cur >= w {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(w - cur))
    }
}

fn truncate(s: &str, w: usize) -> String {
    let cur = s.width();
    if cur <= w {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in s.chars() {
        let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + cw + 1 > w {
            break;
        }
        out.push(ch);
        used += cw;
    }
    out.push('\u{2026}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_appends_ellipsis() {
        assert_eq!(truncate("psql", 10), "psql");
        assert_eq!(truncate("very-long-process-name", 10), "very-long\u{2026}");
    }

    #[test]
    fn channel_kind_short_strings() {
        assert_eq!(channel_kind_short(ChannelKind::Direct), "direct");
        assert_eq!(channel_kind_short(ChannelKind::Forwarded), "fwd-in");
        assert_eq!(channel_kind_short(ChannelKind::Dynamic), "socks");
        assert_eq!(channel_kind_short(ChannelKind::Other), "other");
    }

    #[test]
    fn percentile_75_ignores_single_outlier_peak() {
        // 11 buckets at 1 KB/s and one outlier peak at 100 KB/s.
        // p75 must land on a non-peak bucket so the wave scales to
        // typical traffic instead of collapsing under the peak.
        let mut h = [1_000u64; 12];
        h[3] = 100_000;
        let p = percentile_75(&h);
        assert_eq!(p, 1_000, "p75 must equal typical value, not the peak");
    }

    #[test]
    fn percentile_75_falls_back_to_max_when_percentile_is_zero() {
        // Mostly-empty history with a single non-zero sample at the
        // tail (e.g., peer just appeared). p75 of a zero-padded slice
        // is zero, so the fallback must promote the max so the dot
        // is still visible.
        let mut h = [0u64; 12];
        h[11] = 5_000;
        let p = percentile_75(&h);
        assert_eq!(p, 5_000);
    }

    #[test]
    fn percentile_75_returns_zero_for_all_zero_history() {
        let h = [0u64; 12];
        assert_eq!(percentile_75(&h), 0);
    }

    #[test]
    fn percentile_75_handles_empty_slice() {
        assert_eq!(percentile_75(&[]), 0);
    }

    #[test]
    fn build_lanes_open_first_then_closed() {
        let live = LiveView {
            is_active: true,
            uptime_secs: 100,
            clients: vec![],
            last_exit: None,
            closed_events_smooth: vec![(5, ChannelKind::Dynamic, 30.0, 10.0)],
            currently_open: vec![(7, 4.0, ChannelKind::Direct)],
        };
        let lanes = build_lanes(&live);
        assert_eq!(lanes.len(), 2);
        assert_eq!(lanes[0].channel_id, 7);
        assert!(lanes[0].is_open());
        assert_eq!(lanes[1].channel_id, 5);
        assert!(!lanes[1].is_open());
    }
}
