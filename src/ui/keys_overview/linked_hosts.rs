//! Bottom panel of the Keys tab: the linked-hosts list for the active
//! key. Recently-connected hosts cluster at the top sorted by last-use;
//! never-connected hosts hang below a dim divider sorted alphabetically.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Padding, Paragraph};
use unicode_width::UnicodeWidthStr;

use crate::app::{App, PingStatus};
use crate::history::ConnectionHistory;
use crate::ssh_keys::SshKeyInfo;
use crate::ui::{self, design, theme};

use super::card_title;

/// Per-row data for the linked-hosts list. Reused for both the
/// recently-used cluster (top) and the never-connected divider section
/// (bottom).
struct LinkedHostRow<'a> {
    alias: &'a str,
    hostname: String,
    status: Option<PingStatus>,
    last_connected: u64,
}

pub(super) fn render_linked_hosts(frame: &mut Frame, app: &App, key: &SshKeyInfo, area: Rect) {
    let n = key.linked_hosts.len();
    let count_text = if n == 0 {
        "none".to_string()
    } else {
        n.to_string()
    };
    let block = design::main_block_line(card_title("LINKED HOSTS", Some(&count_text)))
        .padding(Padding::new(1, 1, 0, 0));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height == 0 || inner.width == 0 || n == 0 {
        return;
    }

    // Collect per-alias data (hostname, ping, history) so the list can
    // sort by last-connected and render an offline marker independent
    // of the bare key linkage.
    let mut rows: Vec<LinkedHostRow> = key
        .linked_hosts
        .iter()
        .map(|alias| {
            let hostname = app
                .hosts_state
                .list
                .iter()
                .find(|h| h.alias == *alias)
                .map(|h| h.hostname.clone())
                .unwrap_or_default();
            let status = app.ping.status.get(alias).cloned();
            let last_connected = app
                .history
                .entry(alias)
                .map(|e| e.last_connected)
                .unwrap_or(0);
            LinkedHostRow {
                alias,
                hostname,
                status,
                last_connected,
            }
        })
        .collect();

    let (mut connected, mut never): (Vec<_>, Vec<_>) =
        rows.drain(..).partition(|r| r.last_connected > 0);
    connected.sort_by_key(|r| std::cmp::Reverse(r.last_connected));
    never.sort_by_key(|r| r.alias.to_ascii_lowercase());

    // Column widths. Glyph (1) + space (1) + alias + 2-space gap +
    // hostname + 2-space gap + last-seen (right). The last-seen column
    // is fixed at 10 cols ("yesterday" fits, longer values truncate to
    // "10w ago"); the hostname column absorbs whatever remains.
    const LAST_SEEN_W: usize = 10;
    const GLYPH_COL: usize = 2;
    const GAP: usize = 2;

    let alias_w = key
        .linked_hosts
        .iter()
        .map(|a| UnicodeWidthStr::width(a.as_str()))
        .max()
        .unwrap_or(0)
        .clamp(8, 26);
    let fixed = GLYPH_COL + alias_w + GAP + GAP + LAST_SEEN_W;
    let hostname_w = (inner.width as usize).saturating_sub(fixed).max(8);

    let inner_h = inner.height as usize;
    let want_divider = !connected.is_empty() && !never.is_empty();
    // Reserve one row for the divider when both groups are populated.
    let capacity_for_rows = if want_divider {
        inner_h.saturating_sub(1)
    } else {
        inner_h
    };
    let total = connected.len() + never.len();
    let need_overflow = total > capacity_for_rows;
    let visible_cap = if need_overflow {
        capacity_for_rows.saturating_sub(1)
    } else {
        capacity_for_rows
    };

    let mut lines: Vec<Line> = Vec::with_capacity(inner_h);
    let mut shown = 0usize;
    for r in &connected {
        if shown >= visible_cap {
            break;
        }
        lines.push(render_host_row(r, alias_w, hostname_w, LAST_SEEN_W, false));
        shown += 1;
    }
    let connected_shown = shown;

    if want_divider && shown < visible_cap {
        lines.push(linked_hosts_divider(inner.width as usize));
    }

    for r in &never {
        if shown >= visible_cap {
            break;
        }
        lines.push(render_host_row(r, alias_w, hostname_w, LAST_SEEN_W, true));
        shown += 1;
    }

    let unseen = total.saturating_sub(connected_shown + never.len().min(shown - connected_shown));
    if need_overflow && unseen > 0 {
        lines.push(Line::from(Span::styled(
            format!("... {} more", unseen),
            theme::muted(),
        )));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

/// Build a single linked-host row: status glyph, alias (bold or muted
/// when never-connected), hostname (muted), and last-seen "Xh ago" /
/// unicode `\u{2014}` placeholder right-aligned in the fixed last-seen column.
fn render_host_row(
    row: &LinkedHostRow,
    alias_w: usize,
    hostname_w: usize,
    last_seen_w: usize,
    never_connected: bool,
) -> Line<'static> {
    use ratatui::style::Modifier;
    let (glyph, glyph_style) = match &row.status {
        Some(PingStatus::Reachable { .. }) => (design::ICON_ONLINE, theme::online_dot()),
        Some(PingStatus::Slow { .. }) => (design::ICON_SLOW, theme::warning()),
        Some(PingStatus::Unreachable) => (design::ICON_ERROR, theme::error()),
        Some(PingStatus::Checking) => (design::ICON_PENDING, theme::muted()),
        Some(PingStatus::Skipped) | None => (design::ICON_PENDING, theme::muted()),
    };

    let alias_style = if never_connected {
        theme::muted()
    } else {
        theme::bold()
    };
    let alias_padded = pad_to_width(row.alias, alias_w);
    let hostname_padded = pad_to_width(&row.hostname, hostname_w);

    let last_seen_text = if row.last_connected == 0 {
        "\u{2014}".to_string()
    } else {
        let ago = ConnectionHistory::format_time_ago(row.last_connected);
        if ago.is_empty() {
            "now".to_string()
        } else {
            format!("{} ago", ago)
        }
    };
    let last_seen_padded = format!("{:>width$}", last_seen_text, width = last_seen_w);
    let last_seen_style = if row.last_connected == 0 {
        theme::muted()
    } else {
        theme::muted().add_modifier(Modifier::DIM)
    };

    Line::from(vec![
        Span::styled(glyph.to_string(), glyph_style),
        Span::raw(" "),
        Span::styled(alias_padded, alias_style),
        Span::raw("  "),
        Span::styled(hostname_padded, theme::muted()),
        Span::raw("  "),
        Span::styled(last_seen_padded, last_seen_style),
    ])
}

/// Section divider rendered between the recently-connected cluster and
/// the never-connected stragglers. Muted dashes left and right of a
/// short label keep the visual rhythm aligned with the rounded card
/// border above and below.
fn linked_hosts_divider(width: usize) -> Line<'static> {
    let label = " never connected ";
    let total_dashes = width.saturating_sub(label.chars().count());
    let left = total_dashes / 2;
    let right = total_dashes.saturating_sub(left);
    Line::from(vec![
        Span::styled("\u{2500}".repeat(left), theme::muted()),
        Span::styled(label.to_string(), theme::muted()),
        Span::styled("\u{2500}".repeat(right), theme::muted()),
    ])
}

/// Pad or truncate `s` so it occupies exactly `width` display columns.
/// Uses `UnicodeWidthStr::width` so wide characters (CJK, emoji)
/// account for the cells they occupy on screen rather than the chars
/// they occupy in memory. Truncation delegates to `super::truncate`
/// which already appends a `…` ellipsis at the column-aware cut point.
fn pad_to_width(s: &str, width: usize) -> String {
    let display_w = UnicodeWidthStr::width(s);
    if display_w == width {
        return s.to_string();
    }
    if display_w < width {
        let pad = width - display_w;
        let mut out = String::with_capacity(s.len() + pad);
        out.push_str(s);
        for _ in 0..pad {
            out.push(' ');
        }
        return out;
    }
    ui::truncate(s, width)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_to_width_pads_short_strings() {
        assert_eq!(pad_to_width("abc", 6), "abc   ");
    }

    #[test]
    fn pad_to_width_truncates_with_ellipsis() {
        assert_eq!(pad_to_width("abcdefghij", 6), "abcde\u{2026}");
    }

    #[test]
    fn pad_to_width_returns_input_when_width_matches_exactly() {
        // Equal-width branch must not pad or truncate. Distinct from
        // the pad/truncate paths above so a future change to the
        // function can't collapse this branch silently.
        assert_eq!(pad_to_width("abc", 3), "abc");
    }
}
