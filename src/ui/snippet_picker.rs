use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, Paragraph};
use unicode_width::UnicodeWidthStr;

use super::theme;
use crate::app::{App, Screen};

pub fn render(frame: &mut Frame, app: &mut App) {
    let host_count = match &app.screen {
        Screen::SnippetPicker { target_aliases } => target_aliases.len(),
        Screen::SnippetForm { target_aliases, .. } => target_aliases.len(),
        Screen::SnippetParamForm { target_aliases, .. } => target_aliases.len(),
        _ => 1,
    };

    let searching = app.ui.snippet_search.is_some();

    let title = if host_count > 1 {
        Line::from(Span::styled(format!(" Snippets ({} hosts) ", host_count), theme::brand()))
    } else {
        Line::from(Span::styled(" Snippets ", theme::brand()))
    };

    let filtered = app.filtered_snippet_indices();
    let item_count = if searching {
        filtered.len().max(1)
    } else {
        app.snippet_store.snippets.len().max(1)
    };
    let search_row = if searching { 1u16 } else { 0 };
    let height = (item_count as u16 + 5 + search_row).min(frame.area().height.saturating_sub(4));
    let area = {
        let r = super::centered_rect(70, 80, frame.area());
        super::centered_rect_fixed(r.width, height, frame.area())
    };
    frame.render_widget(Clear, area);

    let border_style = if searching {
        theme::border_search()
    } else {
        theme::accent()
    };

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(border_style);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Layout: optional search bar + list + footer
    let constraints = if searching {
        vec![
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ]
    } else {
        vec![
            Constraint::Min(1),
            Constraint::Length(1),
        ]
    };
    let chunks = Layout::vertical(constraints).split(inner);

    // Search bar
    if searching {
        let query = app.ui.snippet_search.as_deref().unwrap_or("");
        let search_line = Line::from(vec![
            Span::styled(" / ", theme::brand_badge()),
            Span::styled(query, theme::bold()),
            Span::styled("_", theme::accent()),
        ]);
        frame.render_widget(Paragraph::new(search_line), chunks[0]);

        // Cursor position
        let cursor_x = chunks[0].x + 3 + query.width() as u16;
        if cursor_x < chunks[0].x + chunks[0].width {
            frame.set_cursor_position((cursor_x, chunks[0].y));
        }
    }

    let list_area = if searching { chunks[1] } else { chunks[0] };
    let footer_area = if searching { chunks[2] } else { chunks[1] };

    // Build snippet list (filtered when searching)
    let indices = if searching {
        filtered
    } else {
        (0..app.snippet_store.snippets.len()).collect()
    };

    if indices.is_empty() {
        let msg = if searching {
            "  No matches."
        } else {
            "  No snippets yet. Press 'a' to add one."
        };
        frame.render_widget(
            Paragraph::new(msg).style(theme::muted()),
            list_area,
        );
    } else {
        let items: Vec<ListItem> = indices
            .iter()
            .map(|&idx| {
                let snippet = &app.snippet_store.snippets[idx];
                let mut spans = vec![
                    Span::styled(format!(" {:<20}", super::truncate(&snippet.name, 20)), theme::bold()),
                    Span::styled(super::truncate(&snippet.command, 30), theme::muted()),
                ];
                if !snippet.description.is_empty() {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(
                        super::truncate(&snippet.description, 20),
                        theme::muted(),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        let list = List::new(items)
            .highlight_style(theme::selected_row())
            .highlight_symbol("  ");

        frame.render_stateful_widget(list, list_area, &mut app.ui.snippet_picker_state);
    }

    // Footer
    if searching {
        super::render_footer_with_status(frame, footer_area, vec![
            Span::styled(" Enter", theme::primary_action()),
            Span::styled(" select ", theme::muted()),
            Span::styled("\u{2502} ", theme::muted()),
            Span::styled("Esc", theme::accent_bold()),
            Span::styled(" cancel", theme::muted()),
        ], app);
    } else if app.pending_snippet_delete.is_some() {
        let name = app.pending_snippet_delete
            .and_then(|i| app.snippet_store.snippets.get(i))
            .map(|s| s.name.as_str())
            .unwrap_or("");
        super::render_footer_with_status(frame, footer_area, vec![
            Span::styled(format!(" Remove '{}'? ", super::truncate(name, 20)), theme::bold()),
            Span::styled("y", theme::accent_bold()),
            Span::styled(" yes ", theme::muted()),
            Span::styled("\u{2502} ", theme::muted()),
            Span::styled("Esc", theme::accent_bold()),
            Span::styled(" no", theme::muted()),
        ], app);
    } else {
        let mut spans: Vec<Span<'_>> = Vec::new();
        if !app.snippet_store.snippets.is_empty() {
            spans.push(Span::styled(" Enter", theme::primary_action()));
            spans.push(Span::styled(" run ", theme::muted()));
            spans.push(Span::styled("!", theme::accent_bold()));
            spans.push(Span::styled(" raw ", theme::muted()));
            spans.push(Span::styled("\u{2502} ", theme::muted()));
        }
        spans.push(Span::styled("a", theme::accent_bold()));
        spans.push(Span::styled(" add ", theme::muted()));
        if !app.snippet_store.snippets.is_empty() {
            spans.push(Span::styled("e", theme::accent_bold()));
            spans.push(Span::styled(" edit ", theme::muted()));
            spans.push(Span::styled("d", theme::accent_bold()));
            spans.push(Span::styled(" delete ", theme::muted()));
            spans.push(Span::styled("\u{2502} ", theme::muted()));
            spans.push(Span::styled("/", theme::accent_bold()));
            spans.push(Span::styled(" search ", theme::muted()));
        }
        spans.push(Span::styled("\u{2502} ", theme::muted()));
        spans.push(Span::styled("Esc", theme::accent_bold()));
        spans.push(Span::styled(" back", theme::muted()));
        super::render_footer_with_status(frame, footer_area, spans, app);
    }
}
