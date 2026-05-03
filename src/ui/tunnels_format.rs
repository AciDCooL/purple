//! Pure formatting and chart-math helpers used by the tunnels dashboard.
//!
//! Extracted out of `tunnels_detail.rs` so the renderer there stays
//! focused on layout and the helpers can be unit-tested without spinning
//! up a `TestBackend`. None of the functions in this module touch a
//! `Frame`, depend on a theme, or allocate styled spans — they take
//! plain inputs and return plain strings or simple tuples.
//!
//! Several helpers (`format_bind`, `forward_label`, etc.) are kept
//! around even though the heartbeat-dial dashboard no longer renders
//! them inline — they remain unit-tested and are reserved for variants
//! and detail-modal screens that may need them later.
#![allow(dead_code)]

use crate::tunnel::{TunnelRule, TunnelType};
use crate::tunnel_live::{DisplayClient, HISTORY_BUCKETS};

/// One-eighth fill block characters used by the rx/tx sparkline. Index 0
/// is a literal space so cells with zero traffic do not render any
/// glyph; indices 1..=8 escalate from `▁` to `█`.
pub(super) const SPARK_BLOCKS: [&str; 9] = [
    " ", "\u{2581}", "\u{2582}", "\u{2583}", "\u{2584}", "\u{2585}", "\u{2586}", "\u{2587}",
    "\u{2588}",
];

/// Soft floor for the sparkline scale. Below this byte/sec value a
/// one-off small burst draws a partial bar instead of saturating to a
/// full block; above it the chart auto-scales to the observed peak.
pub(super) const THROUGHPUT_SOFT_MAX_BPS: u64 = 64 * 1024;

/// Two-space indent inside every band, matching the host-list rhythm.
pub(super) const INDENT: &str = "  ";

/// Width of the live-value readout column on each rx/tx hero row, e.g.
/// `"14.4 KB/s "` — fixed so the chart, peak readout and arrow line up
/// vertically across the rx and tx rows.
/// Width of the live-value readout cell. Currently unused by the
/// renderer (the throughput row builds its own width inline) but the
/// helper `throughput_live_readout` still uses it, and tests assert
/// against this width directly.
#[allow(dead_code)]
pub(super) const LIVE_READOUT_W: usize = 11;
/// Width of the peak readout cell on each rx/tx hero row. Kept to feed
/// the still-tested `throughput_peak_readout` helper; the renderer no
/// longer consumes it now that peaks live in their own summary row.
#[allow(dead_code)]
pub(super) const PEAK_READOUT_W: usize = 14;

// ── Bytes-per-second formatting ─────────────────────────────────────

pub fn format_bps(bps: u64) -> String {
    if bps == 0 {
        "0 B/s".to_string()
    } else if bps < 1024 {
        format!("{} B/s", bps)
    } else if bps < 1024 * 1024 {
        format!("{:.1} KB/s", bps as f64 / 1024.0)
    } else if bps < 1024 * 1024 * 1024 {
        format!("{:.1} MB/s", bps as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB/s", bps as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// ── Tunnel rule formatters ──────────────────────────────────────────

pub(super) fn format_bind(rule: &TunnelRule) -> String {
    if rule.bind_address.is_empty() {
        rule.bind_port.to_string()
    } else if rule.bind_address.contains(':') {
        format!("[{}]:{}", rule.bind_address, rule.bind_port)
    } else {
        format!("{}:{}", rule.bind_address, rule.bind_port)
    }
}

pub(super) fn format_remote(rule: &TunnelRule) -> String {
    if rule.remote_host.contains(':') {
        format!("[{}]:{}", rule.remote_host, rule.remote_port)
    } else {
        format!("{}:{}", rule.remote_host, rule.remote_port)
    }
}

pub(super) fn forward_label(rule: &TunnelRule) -> String {
    let bind = format_bind(rule);
    match rule.tunnel_type {
        TunnelType::Local => format!("{} \u{2192} {}", bind, format_remote(rule)),
        TunnelType::Remote => format!("{} \u{2190} {}", bind, format_remote(rule)),
        TunnelType::Dynamic => format!("{}  [SOCKS proxy]", bind),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BindKind {
    Loopback,
    Exposed,
    Custom,
}

pub(super) fn bind_description(rule: &TunnelRule) -> (String, BindKind) {
    match (rule.tunnel_type, rule.bind_address.as_str()) {
        (TunnelType::Local | TunnelType::Dynamic, "")
        | (TunnelType::Local | TunnelType::Dynamic, "127.0.0.1")
        | (TunnelType::Local | TunnelType::Dynamic, "::1")
        | (TunnelType::Local | TunnelType::Dynamic, "localhost") => {
            ("127.0.0.1 (loopback)".to_string(), BindKind::Loopback)
        }
        (TunnelType::Remote, "") => ("loopback (server-side)".to_string(), BindKind::Loopback),
        (TunnelType::Remote, "127.0.0.1") | (TunnelType::Remote, "::1") => {
            ("127.0.0.1 (loopback)".to_string(), BindKind::Loopback)
        }
        (_, addr) if addr == "0.0.0.0" || addr == "*" || addr == "::" => {
            (format!("{}  ! exposed", addr), BindKind::Exposed)
        }
        (_, addr) => (addr.to_string(), BindKind::Custom),
    }
}

pub(super) fn use_commands(rule: &TunnelRule) -> Vec<String> {
    let bind = if rule.bind_address.is_empty() || rule.bind_address == "0.0.0.0" {
        "127.0.0.1".to_string()
    } else if rule.bind_address.contains(':') {
        format!("[{}]", rule.bind_address)
    } else {
        rule.bind_address.clone()
    };
    let port = rule.bind_port;
    match rule.tunnel_type {
        TunnelType::Local => match port {
            22 | 2222 => vec![format!("ssh -p {} user@{}", port, bind)],
            5432 => vec![
                format!("psql -h {} -p {} -U postgres", bind, port),
                format!("postgres://user:pass@{}:{}/db", bind, port),
            ],
            3306 => vec![
                format!("mysql -h {} -P {} -u root -p", bind, port),
                format!("mysql://user:pass@{}:{}/db", bind, port),
            ],
            6379 => vec![format!("redis-cli -h {} -p {}", bind, port)],
            27017 => vec![format!("mongosh --host {} --port {}", bind, port)],
            80 | 8080 | 3000 | 5000 | 8000 | 8888 | 9090 => {
                vec![format!("curl http://{}:{}", bind, port)]
            }
            443 | 8443 => vec![format!("curl https://{}:{}", bind, port)],
            _ => vec![format!("connect to {}:{}", bind, port)],
        },
        TunnelType::Remote => vec![
            format!("server-side: connect to localhost:{}", port),
            "(traffic flows back to your laptop)".to_string(),
        ],
        TunnelType::Dynamic => vec![
            format!("export ALL_PROXY=socks5://{}:{}", bind, port),
            format!("curl --socks5 {}:{} https://...", bind, port),
        ],
    }
}

// ── Sparkline math ──────────────────────────────────────────────────

/// Map a sample value to one of the 9 block-character levels (0..=8).
/// Linear scaling: a sample at half the observed peak draws at level 4.
/// Values above zero never collapse to level 0 so the chart never lies
/// about presence.
pub(super) fn level_for(value: f64, scale_max: f64) -> usize {
    if value <= 0.0 {
        return 0;
    }
    let ratio = (value / scale_max).clamp(0.0, 1.0);
    ((ratio * 8.0).round() as usize).clamp(1, 8)
}

/// Decay factor used by [`apply_decay`]. Each subsequent bucket retains
/// 92% of the previous decayed value, so a single peak fades from 100%
/// to roughly 10% over ~27 buckets ≈ 54 seconds at `BUCKET_SECS=2`.
/// Tuned so bursts leave a visible trail without polluting the chart
/// for too long after the actual traffic has stopped.
pub(super) const DECAY_FACTOR: f64 = 0.92;

/// Apply a forward-decay trail to a raw history. Bursts no longer
/// disappear instantly when the next sample is zero — they fade
/// gradually so the chart "breathes" even when traffic is sparse.
/// Raw peak data is preserved (decay only goes forward); existing
/// non-zero samples are never lowered, only zeros get filled in by
/// the decayed echo of the previous bucket.
pub(super) fn apply_decay(history: &[u64; HISTORY_BUCKETS]) -> [u64; HISTORY_BUCKETS] {
    let mut out = [0u64; HISTORY_BUCKETS];
    let mut prev = 0f64;
    for (i, &v) in history.iter().enumerate() {
        let decayed = prev * DECAY_FACTOR;
        let displayed = (v as f64).max(decayed);
        out[i] = displayed as u64;
        prev = displayed;
    }
    out
}

/// Compress a 150-bucket history to `width` output cells, taking the
/// peak across the buckets that map to each output cell. Used by the
/// mountain renderer below.
pub(super) fn compress_to_levels(
    buckets: &[u64; HISTORY_BUCKETS],
    width: usize,
    scale_max: f64,
    max_level: usize,
) -> Vec<usize> {
    let width = width.max(1);
    let mut compressed: Vec<u64> = vec![0u64; width];
    if width <= HISTORY_BUCKETS {
        for (i, &v) in buckets.iter().enumerate() {
            let cell = ((i * width) / HISTORY_BUCKETS).min(width - 1);
            compressed[cell] = compressed[cell].max(v);
        }
    } else {
        let last_bucket = (HISTORY_BUCKETS - 1) as f64;
        let last_cell = (width - 1).max(1) as f64;
        for (cell, slot) in compressed.iter_mut().enumerate() {
            let pos = (cell as f64) * last_bucket / last_cell;
            let lo = pos.floor() as usize;
            let hi = (lo + 1).min(HISTORY_BUCKETS - 1);
            let t = pos - lo as f64;
            let v = (buckets[lo] as f64) * (1.0 - t) + (buckets[hi] as f64) * t;
            *slot = v as u64;
        }
    }
    compressed
        .into_iter()
        .map(|v| {
            if v == 0 {
                0
            } else {
                let ratio = (v as f64 / scale_max).clamp(0.0, 1.0);
                ((ratio * max_level as f64).round() as usize).clamp(1, max_level)
            }
        })
        .collect()
}

/// Single-row block-character sparkline of `width` cells, from a 30-bucket
/// history. When the chart is wider than the bucket count, adjacent
/// buckets are linearly interpolated so a single non-zero bucket draws a
/// smooth peak. When narrower, mapped buckets coalesce by `max` so spikes
/// survive compression.
#[allow(dead_code)]
pub(super) fn block_sparkline(buckets: &[u64; HISTORY_BUCKETS], width: usize) -> String {
    let width = width.max(1);
    let observed_max = buckets.iter().copied().max().unwrap_or(0);
    if observed_max == 0 {
        return SPARK_BLOCKS[0].repeat(width);
    }
    let scale_max = observed_max.max(THROUGHPUT_SOFT_MAX_BPS) as f64;

    let mut levels: Vec<usize> = Vec::with_capacity(width);
    if width <= HISTORY_BUCKETS {
        let mut compressed: Vec<u64> = vec![0u64; width];
        for (i, &v) in buckets.iter().enumerate() {
            let cell = ((i * width) / HISTORY_BUCKETS).min(width - 1);
            compressed[cell] = compressed[cell].max(v);
        }
        for &v in &compressed {
            levels.push(level_for(v as f64, scale_max));
        }
    } else {
        let last_bucket = (HISTORY_BUCKETS - 1) as f64;
        let last_cell = (width - 1).max(1) as f64;
        for cell in 0..width {
            let pos = (cell as f64) * last_bucket / last_cell;
            let lo = pos.floor() as usize;
            let hi = (lo + 1).min(HISTORY_BUCKETS - 1);
            let t = pos - lo as f64;
            let v = (buckets[lo] as f64) * (1.0 - t) + (buckets[hi] as f64) * t;
            levels.push(level_for(v, scale_max));
        }
    }

    let mut out = String::with_capacity(width * 4);
    for level in levels {
        out.push_str(SPARK_BLOCKS[level]);
    }
    out
}

// ── Throughput readout text composition ─────────────────────────────

/// Compose the live-value cell on a rx/tx hero row: the ten-character
/// readout on the left of the sparkline. Returns `(text, is_bold)` so
/// the caller can apply the right theme style without re-deriving the
/// state. Four variants cover every render path:
///
/// - inactive: `"—"` left-padded to width, muted style
/// - active but no sample yet: `"sampling…"` left-padded, muted style
/// - active, ready, idle: `"0 B/s"` left-padded, muted style (not bold)
/// - active, ready, flowing: e.g. `"14.4 KB/s "`, bold style
#[allow(dead_code)]
pub(super) fn throughput_live_readout(active: bool, ready: bool, bps: u64) -> (String, bool) {
    if !active {
        return (format!("{:<width$}", "—", width = LIVE_READOUT_W), false);
    }
    if !ready {
        return (
            format!("{:<width$}", "sampling\u{2026}", width = LIVE_READOUT_W),
            false,
        );
    }
    let text = format!(
        "{:<width$}",
        format_bps(bps).trim().to_string(),
        width = LIVE_READOUT_W
    );
    (text, bps > 0)
}

/// Compose the peak-value cell on a rx/tx hero row: right-aligned
/// `"pk 175.7 KB/s"` when the sampler has produced data, blank padding
/// otherwise. Always returns exactly `PEAK_READOUT_W` characters wide.
/// Currently unused by the renderer (peaks moved to a dedicated summary
/// row), kept for tests and as the canonical formatter for the cell.
#[allow(dead_code)]
pub(super) fn throughput_peak_readout(active: bool, ready: bool, peak_bps: u64) -> String {
    if !active || !ready {
        return format!("{:>width$}", "", width = PEAK_READOUT_W);
    }
    format!(
        "{:>width$}",
        format!("pk {}", format_bps(peak_bps).trim()),
        width = PEAK_READOUT_W
    )
}

// ── Client display label ────────────────────────────────────────────

/// Decide what the CLIENTS row's primary and secondary labels read as.
/// `responsible_app` (macOS-only) wins when present and different from
/// the underlying process name. When they match we render only the
/// primary so the row does not say `"Safari · Safari"`. Returns
/// `(primary, secondary)` where an empty secondary signals "no detail".
pub(super) fn client_display_label(client: &DisplayClient) -> (String, String) {
    match client.responsible_app.as_deref() {
        Some(app) if !app.is_empty() && !app.eq_ignore_ascii_case(&client.process) => {
            (app.to_string(), client.process.clone())
        }
        _ => (client.process.clone(), String::new()),
    }
}

// ── Client roster helpers (volle roster) ────────────────────────────

/// Activity glyph rule: a client touched within the last 5 seconds is
/// "warm" and earns the trailing `*`. Older clients render without it.
pub(super) const CLIENT_ACTIVE_AGE_SECS: u64 = 5;
/// Past this age the client renders in `theme::muted()` so the eye
/// drifts to the busy ones first.
pub(super) const CLIENT_IDLE_AGE_SECS: u64 = 30;

/// Group threshold: at least this many sockets in one bucket before
/// the roster collapses them into a single summary row. Two sockets to
/// the same app already count as duplication worth collapsing — a lone
/// client always stays expanded.
pub(super) const GROUP_THRESHOLD: usize = 2;

/// Apps whose helper-process names are implementation noise. Browsers
/// and Electron-style apps fork tens of helper processes per
/// tab/window/extension whose names (`WebKit.Networking`,
/// `Isolated Web Co`, `Code Helper (Renderer)`, ...) tell the
/// operator nothing actionable. For these the roster shows just the
/// bucket name (`Safari`, `Slack`) and collapses count >= 2 into a
/// single summary line.
///
/// Apps NOT on this list — terminals (`Ghostty`, `iTerm2`,
/// `Alacritty`, `kitty`, `WezTerm`), database GUIs (`TablePlus`,
/// `Sequel Ace`), and IDE-spawned shells (`IntelliJ`, `Xcode`) —
/// have their helper kept visible because that helper IS the
/// command the user actually ran (`psql`, `ssh`, `kubectl`).
pub(super) const HELPER_NOISE_APPS: &[&str] = &[
    // Browsers
    "Safari",
    "Chrome",
    "Google Chrome",
    "Chromium",
    "Firefox",
    "Firefox Developer Edition",
    "Firefox Nightly",
    "Edge",
    "Microsoft Edge",
    "Brave",
    "Brave Browser",
    "Arc",
    "Vivaldi",
    "Opera",
    "Opera GX",
    "Tor Browser",
    "Zen",
    "Orion",
    // Chat / comms (Electron-style)
    "Slack",
    "Discord",
    "Discord Canary",
    "Discord PTB",
    "Element",
    "Signal",
    "Telegram",
    "Telegram Desktop",
    "WhatsApp",
    "Microsoft Teams",
    "Teams",
    "Zoom",
    "Beeper",
    // Productivity (Electron-style)
    "Notion",
    "Notion Calendar",
    "Linear",
    "Figma",
    "Obsidian",
    "Bitwarden",
    "1Password",
    "1Password 7",
    "Spotify",
    // IDE / API tools (Electron-style; the IDE itself, not the
    // shells it spawns — those route through the per-tool process
    // name and stay visible)
    "Code",
    "Visual Studio Code",
    "Code - Insiders",
    "Cursor",
    "Windsurf",
    "Postman",
    "Insomnia",
    "Bruno",
    // Media (Electron-style)
    "Plex",
    "Plex Media Server",
    // Mail (helper-heavy)
    "Mail",
    "Outlook",
    "Microsoft Outlook",
    "Spark",
    "Mimestream",
    // File sync helpers
    "Dropbox",
    "OneDrive",
    "Google Drive",
    // Remote access (helper noise)
    "AnyDesk",
    "TeamViewer",
    "RustDesk",
];

/// True when the app's helper-process name is implementation noise
/// and should be hidden from the roster identity column. Used for
/// both the "drop the `→ helper`" rendering rule and the collapse
/// threshold — buckets that match this predicate fold into a single
/// `{app} → N conn` row when count >= GROUP_THRESHOLD.
pub(super) fn helper_is_noise(app: &str) -> bool {
    HELPER_NOISE_APPS
        .iter()
        .any(|name| name.eq_ignore_ascii_case(app))
}

/// Drop clients silent for at least this long. They stay accounted for
/// in the live tunnel stats but no longer earn a roster row, so a
/// SOCKS tunnel does not accumulate ghost sockets indefinitely. The
/// 5-minute window matches the SSH `ServerAliveInterval` neighbourhood
/// most operators expect for "abandoned".
pub(super) const IDLE_ROLLOFF_SECS: u64 = 300;

/// Pick the bucket a client belongs to. Prefer the macOS responsible
/// app when present; otherwise fall back to the process name. Both
/// paths converge on the operator's mental model — one row per app
/// using the tunnel, regardless of how many helper PIDs or sockets it
/// spawned, regardless of whether the OS exposes responsible-app
/// information.
pub(super) fn bucket_for(client: &DisplayClient) -> String {
    match client.responsible_app.as_deref() {
        Some(app) if !app.trim().is_empty() => app.to_string(),
        _ => client.process.clone(),
    }
}

/// A client is rolled off when it has shown zero throughput for the
/// rolloff window AND its overall age has crossed it. Newer clients
/// with no traffic yet still appear (they may still be establishing).
pub(super) fn is_rolled_off(client: &DisplayClient) -> bool {
    let combined = client.current_rx_bps.saturating_add(client.current_tx_bps);
    combined == 0 && client.age_secs >= IDLE_ROLLOFF_SECS
}

/// Format a single age value as the four-character age cell used in the
/// roster: `"3s "`, `"42s "`, `"1m 02s"`, `"2h 14m"`. Always returns a
/// short, right-aligned string (no padding inside; the caller pads to a
/// fixed column width).
pub(super) fn format_age(age_secs: u64) -> String {
    if age_secs < 60 {
        format!("{}s", age_secs)
    } else if age_secs < 3600 {
        let m = age_secs / 60;
        let s = age_secs % 60;
        format!("{}m {:02}s", m, s)
    } else {
        let h = age_secs / 3600;
        let m = (age_secs % 3600) / 60;
        format!("{}h {:02}m", h, m)
    }
}

/// Activity classification used by both the glyph and the muted/normal
/// styling decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientActivity {
    Active,
    Recent,
    Idle,
}

pub(super) fn classify_activity(age_secs: u64) -> ClientActivity {
    if age_secs <= CLIENT_ACTIVE_AGE_SECS {
        ClientActivity::Active
    } else if age_secs <= CLIENT_IDLE_AGE_SECS {
        ClientActivity::Recent
    } else {
        ClientActivity::Idle
    }
}

/// Activity tier that prefers traffic over age — a 10-minute-old
/// socket pumping 100 KB/s is more "active" than a one-second curl
/// that has not transferred any bytes yet. Reserves the age-only
/// fallback for clients still in their warmup window.
pub(super) fn classify_activity_with_traffic(age_secs: u64, current_bps: u64) -> ClientActivity {
    if current_bps > 0 {
        return ClientActivity::Active;
    }
    classify_activity(age_secs)
}

/// One row in the client roster. The renderer turns this into a styled
/// `Line`. `app` may equal `process` (deduplicated upstream) or stand on
/// its own (e.g. `ghostty` + `psql`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RosterRow {
    pub app: String,
    pub process: String,
    pub src_port: String,
    pub pid: u32,
    pub age_secs: u64,
    pub activity: ClientActivity,
    /// True when this row collapses two or more sockets to a single
    /// summary line. Suppresses src/pid (no single value applies) and
    /// switches the identity column to `{bucket} → N conn`.
    pub is_group: bool,
    /// When `is_group` is true the count of collapsed connections.
    pub group_count: usize,
    /// Per-client throughput readouts. For groups this is the sum
    /// across collapsed connections so the summary row shows the
    /// app's aggregate footprint.
    pub current_rx_bps: u64,
    pub current_tx_bps: u64,
    /// Rolling combined rx+tx history. Summed across members for
    /// groups so a quiet member never hides a busy peer's burst.
    pub viz_history: [u64; crate::tunnel_live::PEER_VIZ_BUCKETS],
    /// True after the per-client sampler has produced at least one
    /// sample for this row (or any of its grouped clients).
    pub throughput_ready: bool,
}

/// Collapse the raw `DisplayClient` list into the roster rows the
/// renderer will paint. Bucket = `responsibleApp` when present, else
/// `process_name`. Buckets that name a helper-noise app (browsers,
/// Slack/Code-style Electron apps) collapse to one `{bucket} → N conn`
/// row when count >= `GROUP_THRESHOLD`. Other buckets — terminals
/// running real user commands like `psql`, `ssh`, `kubectl` — keep
/// every socket as its own row so the operator can see what was
/// running. Clients silent past `IDLE_ROLLOFF_SECS` drop out so the
/// panel does not accumulate ghost sockets.
pub(super) fn build_roster(clients: &[DisplayClient]) -> Vec<RosterRow> {
    use std::collections::BTreeMap;

    let mut bucket_order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<&DisplayClient>> = BTreeMap::new();
    for client in clients {
        if is_rolled_off(client) {
            continue;
        }
        let bucket = bucket_for(client);
        if !groups.contains_key(&bucket) {
            bucket_order.push(bucket.clone());
        }
        groups.entry(bucket).or_default().push(client);
    }

    let mut rows = Vec::new();
    for bucket in bucket_order {
        let members = groups.remove(&bucket).unwrap_or_default();
        if members.len() >= GROUP_THRESHOLD && helper_is_noise(&bucket) {
            // Oldest age signals "how long has this app been on the
            // tunnel" — the operator-relevant question when triaging a
            // stuck session. A youngest-age summary would lie about
            // sockets that have been silently idle for minutes.
            let oldest = members.iter().map(|c| c.age_secs).max().unwrap_or(0);
            let rx_sum: u64 = members.iter().map(|c| c.current_rx_bps).sum();
            let tx_sum: u64 = members.iter().map(|c| c.current_tx_bps).sum();
            let combined = rx_sum.saturating_add(tx_sum);
            let any_ready = members.iter().any(|c| c.throughput_ready);
            // Sum the viz history across members so a single bursty
            // peer keeps drawing colour while quieter members do not
            // wash it out. Cell-by-cell saturating add.
            let mut viz = [0u64; crate::tunnel_live::PEER_VIZ_BUCKETS];
            for m in &members {
                for (i, slot) in viz.iter_mut().enumerate() {
                    *slot = slot.saturating_add(m.viz_history[i]);
                }
            }
            rows.push(RosterRow {
                app: bucket.clone(),
                process: format!("{} conn", members.len()),
                src_port: String::new(),
                pid: 0,
                age_secs: oldest,
                activity: classify_activity_with_traffic(oldest, combined),
                is_group: true,
                group_count: members.len(),
                current_rx_bps: rx_sum,
                current_tx_bps: tx_sum,
                viz_history: viz,
                throughput_ready: any_ready,
            });
            continue;
        }
        for client in members {
            // Suppress the bucket prefix when it adds no info beyond
            // the process name (case-insensitive). `(sys)` no longer
            // exists as a synthetic bucket — Linux clients bucket on
            // their real process name instead.
            let app_label = if bucket.eq_ignore_ascii_case(&client.process) {
                String::new()
            } else {
                bucket.clone()
            };
            let combined = client.current_rx_bps.saturating_add(client.current_tx_bps);
            rows.push(RosterRow {
                app: app_label,
                process: client.process.clone(),
                src_port: src_port_only(&client.src),
                pid: client.pid,
                age_secs: client.age_secs,
                activity: classify_activity_with_traffic(client.age_secs, combined),
                is_group: false,
                group_count: 1,
                current_rx_bps: client.current_rx_bps,
                current_tx_bps: client.current_tx_bps,
                viz_history: client.viz_history,
                throughput_ready: client.throughput_ready,
            });
        }
    }
    rows
}

/// Reduce a `127.0.0.1:54321` source string to `:54321`. The IP part is
/// always loopback for local-bind tunnels and adds noise.
fn src_port_only(src: &str) -> String {
    match src.rsplit_once(':') {
        Some((_, port)) => format!(":{}", port),
        None => src.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_live::DisplayClient;

    fn rule(t: TunnelType, bind: &str, port: u16, host: &str, rport: u16) -> TunnelRule {
        TunnelRule {
            tunnel_type: t,
            bind_address: bind.to_string(),
            bind_port: port,
            remote_host: host.to_string(),
            remote_port: rport,
        }
    }

    fn empty_history() -> [u64; HISTORY_BUCKETS] {
        [0u64; HISTORY_BUCKETS]
    }

    fn client(process: &str, app: Option<&str>) -> DisplayClient {
        DisplayClient {
            src: "127.0.0.1:1".to_string(),
            process: process.to_string(),
            age_secs: 0,
            pid: 1,
            responsible_app: app.map(str::to_string),
            current_rx_bps: 0,
            current_tx_bps: 0,
            viz_history: [0u64; crate::tunnel_live::PEER_VIZ_BUCKETS],
            throughput_ready: false,
        }
    }

    // ── format_bps / format_bind / format_remote / forward_label / bind_description ──

    #[test]
    fn format_bps_thresholds() {
        assert_eq!(format_bps(0), "0 B/s");
        assert_eq!(format_bps(512), "512 B/s");
        assert_eq!(format_bps(2048), "2.0 KB/s");
        assert_eq!(format_bps(2 * 1024 * 1024), "2.0 MB/s");
        assert_eq!(format_bps(2 * 1024 * 1024 * 1024), "2.0 GB/s");
    }

    #[test]
    fn format_bind_empty_renders_port_only() {
        let r = rule(TunnelType::Local, "", 5432, "10.0.0.1", 5432);
        assert_eq!(format_bind(&r), "5432");
    }

    #[test]
    fn format_bind_ipv6_wrapped_in_brackets() {
        let r = rule(TunnelType::Local, "::1", 8080, "10.0.0.1", 8080);
        assert_eq!(format_bind(&r), "[::1]:8080");
    }

    #[test]
    fn format_remote_ipv6_wrapped_in_brackets() {
        let r = rule(TunnelType::Local, "", 5432, "fe80::1", 5432);
        assert_eq!(format_remote(&r), "[fe80::1]:5432");
    }

    #[test]
    fn forward_label_local_uses_arrow_right() {
        let r = rule(TunnelType::Local, "", 5432, "10.0.0.1", 5432);
        assert!(forward_label(&r).contains("\u{2192}"));
    }

    #[test]
    fn forward_label_remote_uses_arrow_left() {
        let r = rule(TunnelType::Remote, "", 9000, "10.0.0.1", 9000);
        assert!(forward_label(&r).contains("\u{2190}"));
    }

    #[test]
    fn forward_label_dynamic_mentions_socks() {
        let r = rule(TunnelType::Dynamic, "", 1080, "", 0);
        assert!(forward_label(&r).contains("SOCKS proxy"));
    }

    #[test]
    fn bind_description_loopback_for_local_default() {
        let r = rule(TunnelType::Local, "", 5432, "10.0.0.1", 5432);
        let (_, kind) = bind_description(&r);
        assert_eq!(kind, BindKind::Loopback);
    }

    #[test]
    fn bind_description_exposed_for_wildcard() {
        let r = rule(TunnelType::Local, "0.0.0.0", 8080, "10.0.0.1", 80);
        let (text, kind) = bind_description(&r);
        assert_eq!(kind, BindKind::Exposed);
        assert!(text.contains("exposed"));
    }

    #[test]
    fn use_commands_local_postgres_emits_psql() {
        let r = rule(TunnelType::Local, "", 5432, "10.0.0.1", 5432);
        let cmds = use_commands(&r);
        assert!(cmds.iter().any(|c| c.starts_with("psql")));
    }

    #[test]
    fn use_commands_dynamic_emits_socks_proxy_export() {
        let r = rule(TunnelType::Dynamic, "", 1080, "", 0);
        let cmds = use_commands(&r);
        assert!(cmds.iter().any(|c| c.contains("ALL_PROXY")));
    }

    // ── Sparkline math ──

    #[test]
    fn sparkline_zero_history_renders_blanks() {
        let s = block_sparkline(&empty_history(), 10);
        assert!(s.chars().all(|c| c == ' '));
    }

    #[test]
    fn sparkline_interpolates_when_stretched() {
        // Stretch path requires width > HISTORY_BUCKETS (now 150).
        let mut h = empty_history();
        h[75] = 1_000_000;
        let s = block_sparkline(&h, 200);
        let chars: Vec<char> = s.chars().collect();
        let full_block_count = chars.iter().filter(|&&c| c == '\u{2588}').count();
        assert!(full_block_count <= 2);
        assert!(
            chars
                .iter()
                .any(|&c| ('\u{2581}'..='\u{2587}').contains(&c))
        );
    }

    #[test]
    fn sparkline_half_peak_renders_mid_height() {
        // Compress path with width < HISTORY_BUCKETS. Place the peak
        // in the bucket that maps to cell 10 (peak), then a half-value
        // sample in the bucket that maps to cell 20.
        let mut h = empty_history();
        // With width=30 and HISTORY_BUCKETS=150, bucket i maps to cell
        // (i*30)/150 = i/5. So bucket 50 → cell 10, bucket 100 → cell 20.
        h[50] = 1_000_000;
        h[100] = 500_000;
        let s = block_sparkline(&h, 30);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars[20], '\u{2584}');
    }

    // ── Throughput readout text branches ──
    //
    // These four states are otherwise reachable only through visual
    // regression at full render; covering them here pins the textual
    // branch decisions independently of layout maths.

    #[test]
    fn throughput_live_readout_inactive_shows_dash() {
        let (text, bold) = throughput_live_readout(false, false, 0);
        assert!(text.starts_with('\u{2014}') || text.contains('\u{2014}'));
        assert!(!bold);
        assert_eq!(text.chars().count(), LIVE_READOUT_W);
    }

    #[test]
    fn throughput_live_readout_active_not_ready_shows_sampling() {
        let (text, bold) = throughput_live_readout(true, false, 0);
        assert!(text.contains("sampling"));
        assert!(!bold);
        assert_eq!(text.chars().count(), LIVE_READOUT_W);
    }

    #[test]
    fn throughput_live_readout_active_ready_zero_is_muted() {
        let (text, bold) = throughput_live_readout(true, true, 0);
        assert!(text.starts_with("0 B/s"));
        assert!(!bold, "zero traffic must render muted, not bold");
        assert_eq!(text.chars().count(), LIVE_READOUT_W);
    }

    #[test]
    fn throughput_live_readout_active_ready_nonzero_is_bold() {
        let (text, bold) = throughput_live_readout(true, true, 14_400);
        assert!(text.contains("14.1 KB/s") || text.contains("14.0 KB/s"));
        assert!(bold);
    }

    #[test]
    fn throughput_peak_readout_inactive_is_blank() {
        let text = throughput_peak_readout(false, false, 0);
        assert!(text.chars().all(|c| c == ' '));
        assert_eq!(text.chars().count(), PEAK_READOUT_W);
    }

    #[test]
    fn throughput_peak_readout_not_ready_is_blank() {
        let text = throughput_peak_readout(true, false, 999_999);
        assert!(text.chars().all(|c| c == ' '));
    }

    #[test]
    fn throughput_peak_readout_active_ready_shows_pk_prefix() {
        let text = throughput_peak_readout(true, true, 175_700);
        assert!(text.contains("pk"));
        assert_eq!(text.chars().count(), PEAK_READOUT_W);
    }

    // ── client_display_label ──

    #[test]
    fn client_display_label_no_responsible_app_uses_process() {
        let c = client("psql", None);
        let (primary, secondary) = client_display_label(&c);
        assert_eq!(primary, "psql");
        assert!(secondary.is_empty());
    }

    #[test]
    fn client_display_label_responsible_app_same_as_process_dedups() {
        let c = client("psql", Some("psql"));
        let (primary, secondary) = client_display_label(&c);
        assert_eq!(primary, "psql");
        assert!(
            secondary.is_empty(),
            "must not render Safari · Safari when app == process"
        );
    }

    #[test]
    fn client_display_label_responsible_app_differs_keeps_both() {
        let c = client("WebKit.Networking", Some("Safari"));
        let (primary, secondary) = client_display_label(&c);
        assert_eq!(primary, "Safari");
        assert_eq!(secondary, "WebKit.Networking");
    }

    #[test]
    fn client_display_label_empty_responsible_app_treated_as_none() {
        let c = client("psql", Some(""));
        let (primary, secondary) = client_display_label(&c);
        assert_eq!(primary, "psql");
        assert!(secondary.is_empty());
    }

    // ── Roster helpers ──

    fn client_with(
        process: &str,
        app: Option<&str>,
        age: u64,
        src: &str,
        pid: u32,
    ) -> DisplayClient {
        DisplayClient {
            src: src.to_string(),
            process: process.to_string(),
            age_secs: age,
            pid,
            responsible_app: app.map(str::to_string),
            current_rx_bps: 0,
            current_tx_bps: 0,
            viz_history: [0u64; crate::tunnel_live::PEER_VIZ_BUCKETS],
            throughput_ready: false,
        }
    }

    #[test]
    fn format_age_under_minute_uses_seconds() {
        assert_eq!(format_age(0), "0s");
        assert_eq!(format_age(42), "42s");
    }

    #[test]
    fn format_age_under_hour_uses_minutes_and_seconds() {
        assert_eq!(format_age(62), "1m 02s");
        assert_eq!(format_age(2 * 60 + 7), "2m 07s");
    }

    #[test]
    fn format_age_over_hour_uses_hours_and_minutes() {
        assert_eq!(format_age(3600 + 14 * 60), "1h 14m");
    }

    #[test]
    fn classify_activity_buckets() {
        assert_eq!(classify_activity(0), ClientActivity::Active);
        assert_eq!(classify_activity(5), ClientActivity::Active);
        assert_eq!(classify_activity(6), ClientActivity::Recent);
        assert_eq!(classify_activity(30), ClientActivity::Recent);
        assert_eq!(classify_activity(31), ClientActivity::Idle);
    }

    #[test]
    fn bucket_for_falls_back_to_process_when_no_app() {
        let c = client_with("curl", None, 0, "127.0.0.1:1", 1);
        assert_eq!(bucket_for(&c), "curl");
    }

    #[test]
    fn bucket_for_uses_responsible_app_when_present() {
        let c = client_with("psql", Some("Ghostty"), 0, "127.0.0.1:1", 1);
        assert_eq!(bucket_for(&c), "Ghostty");
    }

    /// Helper-noise apps (browsers, Electron) collapse at the group
    /// threshold; non-noise apps (terminals like Ghostty) keep every
    /// socket visible because each helper IS a real user command.
    #[test]
    fn build_roster_collapses_only_helper_noise_buckets() {
        let cs = vec![
            // Two Ghostty sockets — different user commands. Stays
            // expanded; the operator wants to see psql vs ssh.
            client_with("psql", Some("Ghostty"), 5, "127.0.0.1:54321", 8821),
            client_with("ssh", Some("Ghostty"), 12, "127.0.0.1:54398", 8835),
            // Three Safari helpers — collapse, helpers are noise.
            client_with(
                "WebKit.Networking",
                Some("Safari"),
                30,
                "127.0.0.1:54401",
                9101,
            ),
            client_with(
                "WebKit.Networking",
                Some("Safari"),
                60,
                "127.0.0.1:54402",
                9102,
            ),
            client_with(
                "WebKit.Networking",
                Some("Safari"),
                90,
                "127.0.0.1:54403",
                9103,
            ),
            // Lone curl — bucket "curl", count 1, stays single.
            client_with("curl", None, 3, "127.0.0.1:51209", 9412),
        ];
        let rows = build_roster(&cs);
        assert_eq!(rows.len(), 4);
        // Ghostty's psql — kept expanded.
        assert!(!rows[0].is_group);
        assert_eq!(rows[0].app, "Ghostty");
        assert_eq!(rows[0].process, "psql");
        // Ghostty's ssh — kept expanded.
        assert!(!rows[1].is_group);
        assert_eq!(rows[1].app, "Ghostty");
        assert_eq!(rows[1].process, "ssh");
        // Safari bucket collapsed, oldest age = 90.
        assert!(rows[2].is_group);
        assert_eq!(rows[2].app, "Safari");
        assert_eq!(rows[2].process, "3 conn");
        assert_eq!(rows[2].group_count, 3);
        assert_eq!(rows[2].age_secs, 90);
        // curl bucket — single, no collapse, no app prefix.
        assert!(!rows[3].is_group);
        assert_eq!(rows[3].app, "");
        assert_eq!(rows[3].process, "curl");
        assert_eq!(rows[3].src_port, ":51209");
    }

    /// Even with two members, a non-noise bucket like Ghostty keeps
    /// each socket on its own row — operators want to see what the
    /// terminal is actually running.
    #[test]
    fn build_roster_keeps_terminal_buckets_expanded() {
        let cs = vec![
            client_with("psql", Some("Ghostty"), 5, "127.0.0.1:54321", 8821),
            client_with("ssh", Some("Ghostty"), 12, "127.0.0.1:54398", 8835),
        ];
        let rows = build_roster(&cs);
        assert_eq!(rows.len(), 2);
        assert!(!rows[0].is_group);
        assert!(!rows[1].is_group);
    }

    /// Linux-style 19 firefox sockets all under bucket "firefox" (no
    /// responsibleApp) collapse into a single group row.
    #[test]
    fn build_roster_collapses_linux_firefox_without_responsible_app() {
        let cs: Vec<DisplayClient> = (0..19)
            .map(|i| client_with("firefox", None, 15, "127.0.0.1:50990", 68270 + i))
            .collect();
        let rows = build_roster(&cs);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].is_group);
        assert_eq!(rows[0].app, "firefox");
        assert_eq!(rows[0].process, "19 conn");
        assert_eq!(rows[0].group_count, 19);
    }

    /// A single client below the group threshold renders as a regular
    /// row even when its bucket comes from responsibleApp.
    #[test]
    fn build_roster_does_not_collapse_single_member_bucket() {
        let cs = vec![client_with(
            "WebKit.Networking",
            Some("Safari"),
            5,
            "127.0.0.1:1",
            1,
        )];
        let rows = build_roster(&cs);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].is_group);
        assert_eq!(rows[0].app, "Safari");
        assert_eq!(rows[0].process, "WebKit.Networking");
    }

    /// When a single client's bucket equals its process name, the
    /// duplicate prefix is suppressed so the row reads `psql` not
    /// `psql → psql`.
    #[test]
    fn build_roster_drops_app_label_when_equal_to_process() {
        let cs = vec![client_with("Ghostty", Some("Ghostty"), 0, "127.0.0.1:1", 1)];
        let rows = build_roster(&cs);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].app, "");
        assert_eq!(rows[0].process, "Ghostty");
    }

    /// Idle rolloff drops sockets that have been silent past the
    /// rolloff window, so a SOCKS tunnel does not accumulate ghost
    /// sockets indefinitely.
    #[test]
    fn build_roster_rolls_off_long_idle_clients() {
        let cs = vec![
            // Old + idle: rolled off.
            client_with("ghost", None, IDLE_ROLLOFF_SECS + 1, "127.0.0.1:1", 1),
            // Old but still has traffic: kept.
            {
                let mut c = client_with("psql", None, IDLE_ROLLOFF_SECS + 5, "127.0.0.1:2", 2);
                c.current_rx_bps = 100;
                c
            },
            // Young + idle: kept (still establishing).
            client_with("curl", None, 1, "127.0.0.1:3", 3),
        ];
        let rows = build_roster(&cs);
        let names: Vec<&str> = rows.iter().map(|r| r.process.as_str()).collect();
        assert!(!names.contains(&"ghost"));
        assert!(names.contains(&"psql"));
        assert!(names.contains(&"curl"));
    }
}
