//! Host picker overlay reached from the containers overview when
//! adding a host to the container cache. Layout, input and footer
//! mirror the tunnel host picker so the two pickers feel identical.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, List, ListItem, Paragraph};
use unicode_width::UnicodeWidthStr;

use super::design;
use super::theme;
use crate::app::App;
use crate::handler::container_host_picker::{filtered_hosts, uncached_aliases};

const MAX_VISIBLE_ROWS: u16 = 16;

pub fn render(frame: &mut Frame, app: &mut App) {
    let total_uncached = uncached_aliases(app).len();
    let visible = filtered_hosts(app);
    let visible_count = visible.len() as u16;
    let query = app.ui.container_host_picker_query.clone();

    let list_height = visible_count.clamp(1, MAX_VISIBLE_ROWS);
    let total_height = 2 + 1 + 1 + list_height;

    let dynamic_width = 48u16.max(frame.area().width * 60 / 100);
    let overlay_width = dynamic_width.min(frame.area().width.saturating_sub(4));
    let height = total_height.min(frame.area().height.saturating_sub(3));
    let area = super::centered_rect_fixed(overlay_width, height, frame.area());

    frame.render_widget(Clear, area);

    let title = if query.is_empty() {
        format!("Add Container Host \u{203A} Select ({})", total_uncached)
    } else {
        format!(
            "Add Container Host \u{203A} Select ({} of {})",
            visible.len(),
            total_uncached
        )
    };
    let block = design::overlay_block(&title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .split(inner);

    render_input(frame, rows[0], &query);
    render_separator(frame, rows[1]);

    if visible.is_empty() {
        let msg = if total_uncached == 0 {
            crate::messages::CONTAINER_HOST_PICKER_NOTHING_TO_ADD
        } else {
            crate::messages::CONTAINER_HOST_PICKER_NO_MATCH
        };
        design::render_empty(frame, rows[2], msg);
    } else {
        let content_w = rows[2].width as usize;
        let items: Vec<ListItem> = visible
            .iter()
            .map(|(alias, hostname)| build_row(alias, hostname, content_w))
            .collect();

        let sel = app.ui.container_host_picker_state.selected();
        let new_sel = match sel {
            Some(i) if i < visible.len() => Some(i),
            _ => Some(0),
        };
        if new_sel != sel {
            app.ui.container_host_picker_state.select(new_sel);
        }

        let list = List::new(items).highlight_style(theme::selected_row());
        frame.render_stateful_widget(list, rows[2], &mut app.ui.container_host_picker_state);
    }

    let footer_area = design::render_overlay_footer(frame, area);
    use crate::messages::footer as fl;
    design::Footer::new()
        .primary("Enter", fl::ENTER_SELECT)
        .action("\u{2191}\u{2193}", fl::ARROWS_SELECT)
        .action("Esc", fl::ESC_CANCEL)
        .render_with_status(frame, footer_area, app);
}

fn render_input(frame: &mut Frame, area: ratatui::layout::Rect, query: &str) {
    let line = if query.is_empty() {
        Line::from(Span::styled("  type to filter hosts...", theme::muted()))
    } else {
        Line::from(vec![
            Span::styled("  /", theme::accent_bold()),
            Span::styled(query.to_string(), theme::brand()),
            Span::styled("\u{2588}", theme::accent_bold()),
        ])
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn render_separator(frame: &mut Frame, area: ratatui::layout::Rect) {
    let sep_width = (area.width as usize).saturating_sub(1);
    let sep = Line::from(Span::styled(
        format!(" {}", "\u{2500}".repeat(sep_width)),
        theme::muted(),
    ));
    frame.render_widget(Paragraph::new(sep), area);
}

fn build_row(alias: &str, hostname: &str, content_w: usize) -> ListItem<'static> {
    let leading = 2;
    let gap = 2;
    let alias_w = alias.width().min(content_w.saturating_sub(leading));
    let remaining = content_w
        .saturating_sub(leading)
        .saturating_sub(alias_w)
        .saturating_sub(gap);
    let hostname_truncated: String = hostname.chars().take(remaining).collect();
    ListItem::new(Line::from(vec![
        Span::raw("  "),
        Span::styled(alias.to_string(), theme::bold()),
        Span::raw("  "),
        Span::styled(hostname_truncated, theme::muted()),
    ]))
}
