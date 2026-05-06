//! Host picker overlay reached from the Tunnels overview when adding a new
//! tunnel. Layout, input affordance and footer mirror the jump bar
//! so users get the same "type to filter" experience everywhere in purple.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, List, ListItem, Paragraph};
use unicode_width::UnicodeWidthStr;

use super::design;
use super::theme;
use crate::app::App;
use crate::handler::tunnel_host_picker::{editable_aliases, filtered_hosts};

/// Cap on simultaneously visible rows. Mirrors the jump bar so both
/// overlays scroll at the same rate on tall terminals.
const MAX_VISIBLE_ROWS: u16 = 16;

pub fn render(frame: &mut Frame, app: &mut App) {
    let total_editable = editable_aliases(app).len();
    let visible = filtered_hosts(app);
    let visible_count = visible.len() as u16;
    let query = app.ui.tunnel_host_picker_query.clone();

    let list_height = visible_count.clamp(1, MAX_VISIBLE_ROWS);
    // border(2) + input(1) + separator(1) + list. Footer below the block.
    let total_height = 2 + 1 + 1 + list_height;

    // Width formula matches command_jump: max(48, 60% of terminal),
    // capped at terminal - 4.
    let dynamic_width = 48u16.max(frame.area().width * 60 / 100);
    let overlay_width = dynamic_width.min(frame.area().width.saturating_sub(4));
    let height = total_height.min(frame.area().height.saturating_sub(3));
    let area = super::centered_rect_fixed(overlay_width, height, frame.area());

    frame.render_widget(Clear, area);

    let title = if query.is_empty() {
        format!("Add Tunnel \u{203A} Select Host ({})", total_editable)
    } else {
        format!(
            "Add Tunnel \u{203A} Select Host ({} of {})",
            visible.len(),
            total_editable
        )
    };
    let block = design::overlay_block(&title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1), // input line
        Constraint::Length(1), // separator
        Constraint::Min(1),    // host list
    ])
    .split(inner);

    render_input(frame, rows[0], &query);
    render_separator(frame, rows[1]);

    if visible.is_empty() {
        let msg = if total_editable == 0 {
            crate::messages::TUNNEL_NO_EDITABLE_HOSTS
        } else {
            crate::messages::TUNNEL_HOST_PICKER_NO_MATCH
        };
        design::render_empty(frame, rows[2], msg);
    } else {
        let content_w = rows[2].width as usize;
        let items: Vec<ListItem> = visible
            .iter()
            .map(|(alias, hostname)| build_row(alias, hostname, content_w))
            .collect();

        let sel = app.ui.tunnel_host_picker_state.selected();
        let new_sel = match sel {
            Some(i) if i < visible.len() => Some(i),
            _ => Some(0),
        };
        if new_sel != sel {
            app.ui.tunnel_host_picker_state.select(new_sel);
        }

        let list = List::new(items).highlight_style(theme::selected_row());
        frame.render_stateful_widget(list, rows[2], &mut app.ui.tunnel_host_picker_state);
    }

    let footer_area = design::render_overlay_footer(frame, area);
    design::Footer::new()
        .action("Enter", " select ")
        .action("\u{2191}\u{2193}", " move ")
        .action("Esc", " cancel")
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

/// Single row: 2-space leading gutter, alias in bold, hostname dimmed.
/// Hostname is right-padded into the remaining space so columns align
/// vertically across rows of varying alias length.
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

#[cfg(test)]
mod tests {
    use ratatui::layout::Rect;

    use super::design;

    #[test]
    fn footer_sits_directly_below_block() {
        let area = Rect::new(0, 0, 60, 12);
        let footer = design::form_footer(area, area.height);
        assert_eq!(footer.height, 1);
        assert_eq!(footer.y, area.y + area.height);
    }
}
