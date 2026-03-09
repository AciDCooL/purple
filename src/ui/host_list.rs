use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, Paragraph};
use unicode_width::UnicodeWidthStr;

use super::theme;
use crate::app::{self, App, HostListItem, PingStatus, SortMode, ViewMode};
use crate::ssh_config::model::ConfigElement;

/// Minimum terminal width to show the detail panel in detailed view mode.
const DETAIL_MIN_WIDTH: u16 = 90;

/// Column layout computed from the visible host list.
struct Columns {
    alias: usize,
    tunnel: usize,
    password: usize,
    show_ping: bool,
    history: usize,
    content: usize,
}

impl Columns {
    fn fixed_width(&self) -> usize {
        let mut w = 0usize;
        let mut n = 0usize;
        if self.tunnel > 0 { w += self.tunnel; n += 1; }
        if self.password > 0 { w += self.password; n += 1; }
        if self.show_ping { w += 4; n += 1; }
        if self.history > 0 { w += self.history; n += 1; }
        if n > 0 { w + (n - 1) * 2 } else { 0 }
    }

    fn header_right(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.tunnel > 0 { parts.push(format!("{:<width$}", "TUNNEL", width = self.tunnel)); }
        if self.password > 0 { parts.push(format!("{:<width$}", "PASSWORD", width = self.password)); }
        if self.show_ping { parts.push("PING".to_string()); }
        if self.history > 0 { parts.push(format!("{:>width$}", "LAST", width = self.history)); }
        parts.join("  ")
    }
}

/// Short label for a password source suitable for column display.
fn password_label(source: &str) -> &'static str {
    if source == "keychain" {
        "keychain"
    } else if source.starts_with("op://") {
        "1password"
    } else if source.starts_with("bw:") {
        "bitwarden"
    } else if source.starts_with("pass:") {
        "pass"
    } else if source.starts_with("vault:") {
        "vault"
    } else {
        "custom"
    }
}

/// Build a short tunnel summary for a host, e.g. "L:5432" or "L:5432 +1".
fn tunnel_summary(elements: &[ConfigElement], alias: &str) -> String {
    let rules = collect_tunnel_labels(elements, alias);
    if rules.is_empty() {
        return String::new();
    }
    if rules.len() == 1 {
        rules[0].clone()
    } else {
        format!("{} +{}", rules[0], rules.len() - 1)
    }
}

fn collect_tunnel_labels(elements: &[ConfigElement], alias: &str) -> Vec<String> {
    for element in elements {
        match element {
            ConfigElement::HostBlock(block) if block.host_pattern == alias => {
                return block
                    .directives
                    .iter()
                    .filter(|d| !d.is_non_directive)
                    .filter_map(|d| {
                        let prefix = match d.key.to_lowercase().as_str() {
                            "localforward" => "L",
                            "remoteforward" => "R",
                            "dynamicforward" => "D",
                            _ => return None,
                        };
                        // Extract just the bind port (first token)
                        let port = d.value.split_whitespace().next().unwrap_or(&d.value);
                        Some(format!("{}:{}", prefix, port))
                    })
                    .collect();
            }
            ConfigElement::Include(include) => {
                for file in &include.resolved_files {
                    let result = collect_tunnel_labels(&file.elements, alias);
                    if !result.is_empty() {
                        return result;
                    }
                }
            }
            _ => {}
        }
    }
    Vec::new()
}

pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    let is_searching = app.search.query.is_some();
    let is_tagging = app.tag_input.is_some();

    // Layout: host list + optional input bar + footer/status
    let chunks = if is_searching || is_tagging {
        Layout::vertical([
            Constraint::Min(5),   // Host list (maximized)
            Constraint::Length(1), // Search/tag bar
            Constraint::Length(1), // Footer or status message
        ])
        .split(area)
    } else {
        Layout::vertical([
            Constraint::Min(5),   // Host list (maximized)
            Constraint::Length(1), // Footer or status message
        ])
        .split(area)
    };

    let content_area = chunks[0];
    let use_detail =
        app.view_mode == ViewMode::Detailed && content_area.width >= DETAIL_MIN_WIDTH;

    let (list_area, detail_area) = if use_detail {
        let detail_width = if content_area.width >= 140 { 48 } else { 40 };
        let [left, right] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Length(detail_width),
        ])
        .areas(content_area);
        (left, Some(right))
    } else {
        (content_area, None)
    };

    if is_searching {
        render_search_list(frame, app, list_area);
        render_search_bar(frame, app, chunks[1]);
        super::render_footer_with_status(frame, chunks[2], search_footer_spans(), app);
    } else if is_tagging {
        render_display_list(frame, app, list_area);
        render_tag_bar(frame, app, chunks[1]);
        super::render_footer_with_status(frame, chunks[2], tag_footer_spans(), app);
    } else {
        render_display_list(frame, app, list_area);
        super::render_footer_with_status(frame, chunks[1], footer_spans(use_detail, app.multi_select.len()), app);
    }

    if let Some(detail) = detail_area {
        super::detail_panel::render(frame, app, detail);
    }
}

fn render_display_list(frame: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    // Build multi-span title: brand badge + position counter
    let host_count = app.hosts.len();
    let title = if host_count == 0 {
        Line::from(Span::styled(" purple. ", theme::brand_badge()))
    } else {
        let pos = if let Some(sel) = app.ui.list_state.selected() {
            app.display_list.get(..=sel)
                .map(|slice| slice.iter().filter(|item| matches!(item, HostListItem::Host { .. })).count())
                .unwrap_or(0)
        } else {
            0
        };
        let mut spans = vec![
            Span::styled(" purple. ", theme::brand_badge()),
            Span::raw(format!(" {}/{} ", pos, host_count)),
        ];
        if app.sort_mode != SortMode::Original || app.group_by_provider {
            let mut label = String::new();
            if app.sort_mode != SortMode::Original {
                label.push_str(app.sort_mode.label());
            }
            if app.group_by_provider {
                if !label.is_empty() {
                    label.push_str(", ");
                }
                label.push_str("grouped");
            }
            spans.push(Span::raw(format!("({}) ", label)));
        }
        Line::from(spans)
    };

    let update_title = app.update_available.as_ref().map(|ver| {
        Line::from(Span::styled(
            format!(" v{} available — run '{}' ", ver, app.update_hint),
            theme::update_badge(),
        ))
    });

    if app.hosts.is_empty() {
        let mut block = Block::bordered()
            .border_type(BorderType::Rounded)
            .title(title)
            .border_style(theme::border());
        if let Some(update) = update_title {
            block = block.title_top(update.right_aligned());
        }
        let empty_msg =
            Paragraph::new("  It's quiet in here... Press 'a' to add a host or 'S' for cloud sync.")
                .style(theme::muted())
                .block(block);
        frame.render_widget(empty_msg, area);
        return;
    }

    // Build block and render border separately for column header
    let mut block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(theme::border());
    if let Some(update) = update_title {
        block = block.title_top(update.right_aligned());
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Pre-compute tunnel summaries
    let tunnel_summaries: std::collections::HashMap<String, String> = app.hosts.iter()
        .filter(|h| h.tunnel_count > 0)
        .map(|h| (h.alias.clone(), tunnel_summary(&app.config.elements, &h.alias)))
        .collect();

    // Compute column layout
    let cols = Columns {
        alias: app.hosts.iter().map(|h| h.alias.width()).max().unwrap_or(8).clamp(8, 20),
        tunnel: tunnel_summaries.values().map(|s| s.width()).max().unwrap_or(0),
        password: app.hosts.iter()
            .filter_map(|h| h.askpass.as_deref())
            .map(|s| password_label(s).width())
            .max()
            .unwrap_or(0),
        show_ping: !app.ping_status.is_empty(),
        history: app.hosts.iter()
            .filter_map(|h| app.history.entries.get(&h.alias))
            .map(|e| crate::history::ConnectionHistory::format_time_ago(e.last_connected))
            .filter(|s| !s.is_empty())
            .map(|s| s.width())
            .max()
            .unwrap_or(0),
        content: (inner.width as usize).saturating_sub(3),
    };

    // Column header + list body
    let [header_area, list_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(inner);

    render_header(frame, header_area, &cols);

    // Count hosts per group for group headers
    let group_counts: std::collections::HashMap<&str, usize> = {
        let mut counts = std::collections::HashMap::new();
        let mut current_group: Option<&str> = None;
        for item in &app.display_list {
            match item {
                HostListItem::GroupHeader(text) => {
                    current_group = Some(text.as_str());
                }
                HostListItem::Host { .. } => {
                    if let Some(group) = current_group {
                        *counts.entry(group).or_insert(0) += 1;
                    }
                }
            }
        }
        counts
    };

    let mut items: Vec<ListItem> = Vec::new();
    for item in &app.display_list {
        match item {
            HostListItem::GroupHeader(text) => {
                let upper = text.to_uppercase();
                let count = group_counts.get(text.as_str()).copied().unwrap_or(0);
                let label = format!("{} ({}) ", upper, count);
                let fill = cols.content.saturating_sub(label.width());
                let line = Line::from(vec![
                    Span::styled(label, theme::section_header()),
                    Span::styled("─".repeat(fill), theme::muted()),
                ]);
                items.push(ListItem::new(line));
            }
            HostListItem::Host { index } => {
                if let Some(host) = app.hosts.get(*index) {
                    let tunnel_active = app.active_tunnels.contains_key(&host.alias);
                    let list_item = build_host_item(
                        host,
                        &app.ping_status,
                        &app.history,
                        &tunnel_summaries,
                        tunnel_active,
                        None,
                        &cols,
                        app.multi_select.contains(index),
                    );
                    items.push(list_item);
                } else {
                    items.push(ListItem::new(Line::from(Span::raw(""))));
                }
            }
        }
    }

    let list = List::new(items)
        .highlight_style(theme::selected())
        .highlight_symbol(" ");

    frame.render_stateful_widget(list, list_area, &mut app.ui.list_state);

}

fn render_search_list(frame: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    let title = Line::from(vec![
        Span::styled(" purple. ", theme::brand_badge()),
        Span::raw(format!(
            " search: {}/{} ",
            app.search.filtered_indices.len(),
            app.hosts.len()
        )),
    ]);

    if app.search.filtered_indices.is_empty() {
        let empty_msg = Paragraph::new("  No matches. Try a different search.")
            .style(theme::muted())
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(title)
                    .border_style(theme::accent()),
            );
        frame.render_widget(empty_msg, area);
        return;
    }

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(theme::accent());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Pre-compute tunnel summaries for filtered hosts
    let tunnel_summaries: std::collections::HashMap<String, String> = app.search.filtered_indices.iter()
        .filter_map(|&i| app.hosts.get(i))
        .filter(|h| h.tunnel_count > 0)
        .map(|h| (h.alias.clone(), tunnel_summary(&app.config.elements, &h.alias)))
        .collect();

    let cols = Columns {
        alias: app.search.filtered_indices.iter()
            .filter_map(|&i| app.hosts.get(i))
            .map(|h| h.alias.width())
            .max()
            .unwrap_or(8)
            .clamp(8, 20),
        tunnel: tunnel_summaries.values().map(|s| s.width()).max().unwrap_or(0),
        password: app.search.filtered_indices.iter()
            .filter_map(|&i| app.hosts.get(i))
            .filter_map(|h| h.askpass.as_deref())
            .map(|s| password_label(s).width())
            .max()
            .unwrap_or(0),
        show_ping: !app.ping_status.is_empty(),
        history: app.search.filtered_indices.iter()
            .filter_map(|&i| app.hosts.get(i))
            .filter_map(|h| app.history.entries.get(&h.alias))
            .map(|e| crate::history::ConnectionHistory::format_time_ago(e.last_connected))
            .filter(|s| !s.is_empty())
            .map(|s| s.width())
            .max()
            .unwrap_or(0),
        content: (inner.width as usize).saturating_sub(3),
    };

    let [header_area, list_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(inner);

    render_header(frame, header_area, &cols);

    let query = app.search.query.as_deref();
    let mut items: Vec<ListItem> = Vec::new();
    for &idx in app.search.filtered_indices.iter() {
        if let Some(host) = app.hosts.get(idx) {
            let tunnel_active = app.active_tunnels.contains_key(&host.alias);
            let list_item = build_host_item(
                host,
                &app.ping_status,
                &app.history,
                &tunnel_summaries,
                tunnel_active,
                query,
                &cols,
                app.multi_select.contains(&idx),
            );
            items.push(list_item);
        }
    }

    let list = List::new(items)
        .highlight_style(theme::selected())
        .highlight_symbol(" ");

    frame.render_stateful_widget(list, list_area, &mut app.ui.list_state);

}

fn render_header(frame: &mut Frame, area: ratatui::layout::Rect, cols: &Columns) {
    let header_left = format!(" {:<width$}    HOST", "NAME", width = cols.alias);
    let header_right = cols.header_right();
    let header_right_len = header_right.width();
    let header_pad = cols.content
        .saturating_sub(header_left.width() + header_right_len);
    let mut spans = vec![
        Span::styled(format!(" {}", header_left), theme::muted()),
        Span::raw(" ".repeat(header_pad)),
    ];
    if !header_right.is_empty() {
        spans.push(Span::styled(header_right, theme::muted()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

#[allow(clippy::too_many_arguments)]
fn build_host_item<'a>(
    host: &'a crate::ssh_config::model::HostEntry,
    ping_status: &'a std::collections::HashMap<String, PingStatus>,
    history: &'a crate::history::ConnectionHistory,
    tunnel_summaries: &'a std::collections::HashMap<String, String>,
    tunnel_active: bool,
    query: Option<&str>,
    cols: &Columns,
    multi_selected: bool,
) -> ListItem<'a> {
    let q = query.unwrap_or("");

    // Determine which field matches for search highlighting
    let alias_matches = !q.is_empty() && app::contains_ci(&host.alias, q);
    let host_matches = !alias_matches && !q.is_empty() && app::contains_ci(&host.hostname, q);
    let user_matches =
        !alias_matches && !host_matches && !q.is_empty() && app::contains_ci(&host.user, q);

    // === LEFT: alias (fixed column) + user@hostname:port ===
    let alias_style = if alias_matches {
        theme::highlight_bold()
    } else {
        theme::bold()
    };
    let marker = if multi_selected { "\u{2713}" } else { " " };
    let alias_display = format!("{}{:<width$}    ", marker, host.alias, width = cols.alias);
    let mut left_len = alias_display.width();
    let mut left_spans = vec![Span::styled(alias_display, alias_style)];

    if !host.user.is_empty() {
        let user_style = if user_matches {
            theme::highlight_bold()
        } else {
            theme::muted()
        };
        let s = format!("{}@", host.user);
        left_len += s.width();
        left_spans.push(Span::styled(s, user_style));
    }

    let hostname_style = if host_matches {
        theme::highlight_bold()
    } else {
        Style::default()
    };
    left_len += host.hostname.width();
    left_spans.push(Span::styled(host.hostname.as_str(), hostname_style));

    if host.port != 22 {
        let s = format!(":{}", host.port);
        left_len += s.width();
        left_spans.push(Span::styled(s, theme::muted()));
    }

    // === TAGS ===
    let mut tag_spans: Vec<Span> = Vec::new();
    let mut tag_len: usize = 0;

    let tag_matches = !q.is_empty() && !alias_matches && !host_matches && !user_matches;
    for tag in &host.tags {
        let style = if tag_matches && app::contains_ci(tag, q) {
            theme::highlight_bold()
        } else {
            theme::muted()
        };
        let s = format!(" #{}", tag);
        tag_len += s.width();
        tag_spans.push(Span::styled(s, style));
    }

    if let Some(ref label) = host.provider {
        let style = if tag_matches && app::contains_ci(label, q) {
            theme::highlight_bold()
        } else {
            theme::muted()
        };
        let s = format!(" #{}", label);
        tag_len += s.width();
        tag_spans.push(Span::styled(s, style));
    }

    if let Some(ref source) = host.source_file {
        let file_name = source
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        if !file_name.is_empty() {
            let s = format!(" ({})", file_name);
            tag_len += s.width();
            tag_spans.push(Span::styled(s, theme::muted()));
        }
    }

    // === FIXED INDICATOR COLUMNS ===
    let mut ind_spans: Vec<Span> = Vec::new();
    let fixed_w = cols.fixed_width();
    let mut first_col = true;

    if cols.tunnel > 0 {
        if !first_col { ind_spans.push(Span::raw("  ")); }
        if let Some(summary) = tunnel_summaries.get(&host.alias) {
            let style = if tunnel_active { theme::bold() } else { theme::muted() };
            ind_spans.push(Span::styled(
                format!("{:<width$}", summary, width = cols.tunnel),
                style,
            ));
        } else {
            ind_spans.push(Span::raw(" ".repeat(cols.tunnel)));
        }
        first_col = false;
    }

    if cols.password > 0 {
        if !first_col { ind_spans.push(Span::raw("  ")); }
        if let Some(ref source) = host.askpass {
            ind_spans.push(Span::styled(
                format!("{:<width$}", password_label(source), width = cols.password),
                theme::muted(),
            ));
        } else {
            ind_spans.push(Span::raw(" ".repeat(cols.password)));
        }
        first_col = false;
    }

    if cols.show_ping {
        if !first_col { ind_spans.push(Span::raw("  ")); }
        if let Some(status) = ping_status.get(&host.alias) {
            let (indicator, style) = match status {
                PingStatus::Checking => ("..", theme::muted()),
                PingStatus::Reachable => ("ok", theme::success()),
                PingStatus::Unreachable => ("--", theme::error()),
                PingStatus::Skipped => ("??", theme::muted()),
            };
            ind_spans.push(Span::raw(" "));
            ind_spans.push(Span::styled(indicator, style));
            ind_spans.push(Span::raw(" "));
        } else {
            ind_spans.push(Span::raw("    "));
        }
        first_col = false;
    }

    if cols.history > 0 {
        if !first_col { ind_spans.push(Span::raw("  ")); }
        if let Some(entry) = history.entries.get(&host.alias) {
            let ago = crate::history::ConnectionHistory::format_time_ago(entry.last_connected);
            if !ago.is_empty() {
                ind_spans.push(Span::styled(
                    format!("{:>width$}", ago, width = cols.history),
                    theme::muted(),
                ));
            } else {
                ind_spans.push(Span::raw(" ".repeat(cols.history)));
            }
        } else {
            ind_spans.push(Span::raw(" ".repeat(cols.history)));
        }
    }

    // === COMBINE: left + padding + tags + gap + fixed indicators ===
    let gap = if fixed_w > 0 && tag_len > 0 { 2 } else { 0 };
    let right_len = tag_len + gap + fixed_w;
    let padding = cols.content.saturating_sub(left_len + right_len);
    let mut spans = left_spans;
    if padding > 0 {
        spans.push(Span::raw(" ".repeat(padding)));
    }
    spans.extend(tag_spans);
    if gap > 0 {
        spans.push(Span::raw("  "));
    }
    spans.extend(ind_spans);

    ListItem::new(Line::from(spans))
}

fn render_search_bar(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let query = app.search.query.as_deref().unwrap_or("");
    let match_info = if query.is_empty() {
        String::new()
    } else {
        let count = app.search.filtered_indices.len();
        match count {
            0 => " (no matches)".to_string(),
            1 => " (1 match)".to_string(),
            n => format!(" ({} matches)", n),
        }
    };
    let search_line = Line::from(vec![
        Span::styled(" / ", theme::accent_bold()),
        Span::raw(query),
        Span::styled("_", theme::accent()),
        Span::styled(match_info, theme::muted()),
    ]);
    frame.render_widget(Paragraph::new(search_line), area);
}

fn footer_spans(detail_active: bool, multi_count: usize) -> Vec<Span<'static>> {
    let view_label = if detail_active { " compact " } else { " detail " };
    let mut spans = vec![
        Span::styled(" Enter", theme::primary_action()),
        Span::styled(" connect ", theme::muted()),
        Span::styled("\u{2502} ", theme::muted()),
        Span::styled("/", theme::accent_bold()),
        Span::styled(" search ", theme::muted()),
        Span::styled("#", theme::accent_bold()),
        Span::styled(" tag ", theme::muted()),
        Span::styled("\u{2502} ", theme::muted()),
        Span::styled("a", theme::accent_bold()),
        Span::styled(" add ", theme::muted()),
        Span::styled("e", theme::accent_bold()),
        Span::styled(" edit ", theme::muted()),
        Span::styled("d", theme::accent_bold()),
        Span::styled(" del ", theme::muted()),
        Span::styled("\u{2502} ", theme::muted()),
        Span::styled("v", theme::accent_bold()),
        Span::styled(view_label, theme::muted()),
        Span::styled("?", theme::accent_bold()),
        Span::styled(" help", theme::muted()),
    ];
    if multi_count > 0 {
        spans.push(Span::styled("\u{2502} ", theme::muted()));
        spans.push(Span::styled(format!("{} selected", multi_count), theme::accent_bold()));
    }
    spans
}

fn search_footer_spans<'a>() -> Vec<Span<'a>> {
    vec![
        Span::styled(" Enter", theme::primary_action()),
        Span::styled(" connect ", theme::muted()),
        Span::styled("\u{2502} ", theme::muted()),
        Span::styled("Esc", theme::accent_bold()),
        Span::styled(" cancel", theme::muted()),
    ]
}

fn render_tag_bar(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let input = app.tag_input.as_deref().unwrap_or("");
    let tag_line = Line::from(vec![
        Span::styled(" tags: ", theme::accent_bold()),
        Span::raw(input),
        Span::styled("_", theme::accent()),
    ]);
    frame.render_widget(Paragraph::new(tag_line), area);
}

fn tag_footer_spans<'a>() -> Vec<Span<'a>> {
    vec![
        Span::styled(" Enter", theme::primary_action()),
        Span::styled(" save  ", theme::muted()),
        Span::styled("Esc", theme::accent_bold()),
        Span::styled(" cancel  ", theme::muted()),
        Span::styled("comma-separated", theme::muted()),
    ]
}
