use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::theme;
use crate::app::{App, ProviderFormField};
use crate::history::ConnectionHistory;
use crate::providers;

/// Render the provider management list screen.
pub fn render_provider_list(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    let title = Line::from(vec![
        Span::styled(" purple. ", theme::brand_badge()),
        Span::raw(" Providers "),
    ]);

    // Content width inside borders (2 for left+right border)
    let content_width = area.width.saturating_sub(2) as usize;

    let items: Vec<ListItem> = providers::PROVIDER_NAMES
        .iter()
        .map(|&name| {
            let display_name = crate::providers::provider_display_name(name);
            let configured = app.provider_config.section(name).is_some();
            let status = if configured {
                "[configured]"
            } else {
                "[not configured]"
            };
            let status_style = if configured {
                theme::success()
            } else {
                theme::muted()
            };
            let name_col = format!("  {:<18}", display_name);
            let mut used_width = name_col.width() + status.width();
            let mut spans = vec![
                Span::styled(name_col, theme::bold()),
                Span::styled(status, status_style),
            ];
            if configured {
                if let Some(section) = app.provider_config.section(name) {
                    let prefix_span = format!("     {}-*", section.alias_prefix);
                    used_width += prefix_span.width();
                    spans.push(Span::styled(prefix_span, theme::muted()));
                }
                let sync_text = if app.syncing_providers.contains_key(name) {
                    Some(("  syncing...".to_string(), theme::muted()))
                } else if let Some(record) = app.sync_history.get(name) {
                    let ago = ConnectionHistory::format_time_ago(record.timestamp);
                    let detail = if ago.is_empty() {
                        record.message.clone()
                    } else {
                        format!("{}, {}", record.message, ago)
                    };
                    let style = if record.is_error {
                        theme::error()
                    } else {
                        theme::muted()
                    };
                    let prefix = if record.is_error { "  ! " } else { "  " };
                    Some((format!("{}{}", prefix, detail), style))
                } else {
                    None
                };
                if let Some((text, style)) = sync_text {
                    let max = content_width.saturating_sub(used_width);
                    if let Some(truncated) = truncate_to_width(&text, max) {
                        spans.push(Span::styled(truncated, style));
                    }
                }
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let chunks = Layout::vertical([
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .split(area);

    let list = List::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(theme::border()),
        )
        .highlight_style(theme::selected())
        .highlight_symbol("  ");

    frame.render_stateful_widget(list, chunks[0], &mut app.ui.provider_list_state);

    // Footer
    if app.status.is_some() {
        super::render_status_bar(frame, chunks[1], app);
    } else {
        let footer = Line::from(vec![
            Span::styled(" Enter", theme::primary_action()),
            Span::styled(" configure  ", theme::muted()),
            Span::styled("s", theme::accent_bold()),
            Span::styled(" sync  ", theme::muted()),
            Span::styled("d", theme::accent_bold()),
            Span::styled(" remove  ", theme::muted()),
            Span::styled("Esc", theme::accent_bold()),
            Span::styled(" back", theme::muted()),
        ]);
        frame.render_widget(Paragraph::new(footer), chunks[1]);
    }
}

/// Render the provider configuration form.
pub fn render_provider_form(frame: &mut Frame, app: &mut App, provider_name: &str) {
    let area = frame.area();

    let display_name = crate::providers::provider_display_name(provider_name);
    let title = format!(" Configure {} ", display_name);

    let form_area = super::centered_rect(70, 80, area);
    frame.render_widget(Clear, form_area);

    let outer_block = Block::default()
        .title(Span::styled(title, theme::brand()))
        .borders(Borders::ALL)
        .border_style(theme::border());

    let inner = outer_block.inner(form_area);
    frame.render_widget(outer_block, form_area);

    let chunks = Layout::vertical([
        Constraint::Length(3), // Token
        Constraint::Length(3), // Alias Prefix
        Constraint::Length(3), // User
        Constraint::Length(3), // Identity File
        Constraint::Min(1),   // Spacer
        Constraint::Length(1), // Footer or status
    ])
    .split(inner);

    render_provider_field(frame, chunks[0], ProviderFormField::Token, &app.provider_form);
    render_provider_field(frame, chunks[1], ProviderFormField::AliasPrefix, &app.provider_form);
    render_provider_field(frame, chunks[2], ProviderFormField::User, &app.provider_form);
    render_provider_field(frame, chunks[3], ProviderFormField::IdentityFile, &app.provider_form);

    // Footer or status
    if app.status.is_some() {
        super::render_status_bar(frame, chunks[5], app);
    } else {
        let footer = Line::from(vec![
            Span::styled(" Enter", theme::primary_action()),
            Span::styled(" save  ", theme::muted()),
            Span::styled("Tab/S-Tab", theme::accent_bold()),
            Span::styled(" navigate  ", theme::muted()),
            Span::styled("Ctrl+K", theme::accent_bold()),
            Span::styled(" pick key  ", theme::muted()),
            Span::styled("Esc", theme::accent_bold()),
            Span::styled(" cancel", theme::muted()),
        ]);
        frame.render_widget(Paragraph::new(footer), chunks[5]);
    }

    // Key picker popup overlay
    if app.ui.show_key_picker {
        super::host_form::render_key_picker_overlay(frame, app);
    }
}

fn placeholder_for(field: ProviderFormField) -> &'static str {
    match field {
        ProviderFormField::Token => "your-api-token",
        ProviderFormField::AliasPrefix => "do",
        ProviderFormField::User => "root",
        ProviderFormField::IdentityFile => "~/.ssh/id_ed25519",
    }
}

fn render_provider_field(
    frame: &mut Frame,
    area: Rect,
    field: ProviderFormField,
    form: &crate::app::ProviderFormFields,
) {
    let is_focused = form.focused_field == field;

    let value = match field {
        ProviderFormField::Token => &form.token,
        ProviderFormField::AliasPrefix => &form.alias_prefix,
        ProviderFormField::User => &form.user,
        ProviderFormField::IdentityFile => &form.identity_file,
    };

    let (border_style, label_style) = if is_focused {
        (theme::border_focused(), theme::accent_bold())
    } else {
        (theme::border(), theme::muted())
    };

    let is_required = matches!(field, ProviderFormField::Token);
    let label = if is_required {
        format!(" {}* ", field.label())
    } else {
        format!(" {} ", field.label())
    };

    let block = Block::default()
        .title(Span::styled(label, label_style))
        .borders(Borders::ALL)
        .border_style(border_style);

    // Mask token except last 4 chars
    let display_value: String = if field == ProviderFormField::Token && !value.is_empty() && !is_focused {
        let char_count = value.chars().count();
        if char_count > 4 {
            let last4: String = value.chars().skip(char_count - 4).collect();
            format!("{}{}", "*".repeat(char_count - 4), last4)
        } else {
            value.clone()
        }
    } else {
        value.clone()
    };

    let display: Span = if value.is_empty() && !is_focused {
        Span::styled(placeholder_for(field), theme::muted())
    } else {
        Span::raw(display_value)
    };

    let paragraph = Paragraph::new(display).block(block);
    frame.render_widget(paragraph, area);

    if is_focused {
        let cursor_x = area
            .x
            .saturating_add(1)
            .saturating_add(value.width().min(u16::MAX as usize) as u16);
        let cursor_y = area.y + 1;
        if area.width > 1 && cursor_x < area.x.saturating_add(area.width).saturating_sub(1) {
            frame.set_cursor_position((cursor_x, cursor_y));
        }
    }
}

/// Truncate text to fit within `max_cols` display columns.
/// Returns None if no room (max_cols <= 1), the original text if it fits,
/// or truncated text with ellipsis appended.
fn truncate_to_width(text: &str, max_cols: usize) -> Option<String> {
    if max_cols <= 1 {
        return None;
    }
    if text.width() <= max_cols {
        return Some(text.to_string());
    }
    let target = max_cols - 1; // reserve 1 column for ellipsis
    let mut col = 0;
    let mut byte_end = 0;
    for ch in text.chars() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if col + w > target {
            break;
        }
        col += w;
        byte_end += ch.len_utf8();
    }
    Some(format!("{}…", &text[..byte_end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_fits() {
        assert_eq!(truncate_to_width("hello", 10), Some("hello".to_string()));
    }

    #[test]
    fn truncate_exact_fit() {
        assert_eq!(truncate_to_width("hello", 5), Some("hello".to_string()));
    }

    #[test]
    fn truncate_ascii() {
        assert_eq!(truncate_to_width("hello world", 8), Some("hello w…".to_string()));
    }

    #[test]
    fn truncate_no_room() {
        assert_eq!(truncate_to_width("hello", 1), None);
        assert_eq!(truncate_to_width("hello", 0), None);
    }

    #[test]
    fn truncate_wide_cjk() {
        // CJK chars are 2 columns wide each. "你好世界" = 8 columns.
        // With max 5: target = 4 columns, fits "你好" (4 cols) + "…"
        assert_eq!(truncate_to_width("你好世界", 5), Some("你好…".to_string()));
    }

    #[test]
    fn truncate_wide_cjk_odd_boundary() {
        // max 4: target = 3 columns, "你" = 2 cols fits, "好" = 2 cols won't
        assert_eq!(truncate_to_width("你好世界", 4), Some("你…".to_string()));
    }

    #[test]
    fn truncate_mixed_ascii_cjk() {
        // "ab你好" = 2 + 4 = 6 columns. max 5: target = 4, "ab你" fits (4 cols)
        assert_eq!(truncate_to_width("ab你好", 5), Some("ab你…".to_string()));
    }

    #[test]
    fn truncate_multibyte_emoji() {
        // "🚀🔥" = 2+2 = 4 columns (each emoji is 2 cols wide).
        // max 3: target = 2, "🚀" fits (2 cols)
        assert_eq!(truncate_to_width("🚀🔥", 3), Some("🚀…".to_string()));
    }
}
