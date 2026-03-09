use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};

use super::theme;
use crate::app::App;

pub fn render(frame: &mut Frame, app: &mut App) {
    let width: u16 = 48;
    let all_lines = help_text();
    let total_lines = all_lines.len() as u16;
    // 2 border + 1 footer + 1 scroll hint
    let max_body = frame.area().height.saturating_sub(5);
    let height = (total_lines + 4).min(frame.area().height.saturating_sub(2));
    let area = super::centered_rect_fixed(width, height, frame.area());

    frame.render_widget(Clear, area);

    let title = Span::styled(" Cheat Sheet ", theme::brand());
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(theme::accent());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(inner);

    // Clamp scroll offset
    let max_scroll = total_lines.saturating_sub(max_body);
    if app.ui.help_scroll > max_scroll {
        app.ui.help_scroll = max_scroll;
    }

    let para = Paragraph::new(all_lines).scroll((app.ui.help_scroll, 0));
    frame.render_widget(para, chunks[0]);

    let can_scroll = total_lines > max_body;
    let footer = if can_scroll {
        Line::from(vec![
            Span::styled(" j/k", theme::accent_bold()),
            Span::styled(" scroll ", theme::muted()),
            Span::styled("\u{2502} ", theme::muted()),
            Span::styled("Esc", theme::accent_bold()),
            Span::styled(" close", theme::muted()),
        ])
    } else {
        Line::from(vec![
            Span::styled(" Esc", theme::accent_bold()),
            Span::styled(" close", theme::muted()),
        ])
    };
    frame.render_widget(Paragraph::new(footer), chunks[1]);
}

fn help_text() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(" Navigate", theme::section_header())),
        help_line(" j/k        ", "up / down"),
        help_line(" PgDn/PgUp  ", "page down / up"),
        help_line(" /          ", "search hosts"),
        help_line(" #          ", "filter by tag"),
        help_line(" s          ", "cycle sort mode"),
        help_line(" g          ", "group by provider"),
        Line::from(""),
        Line::from(Span::styled(" Manage", theme::section_header())),
        help_line(" Enter      ", "connect to host"),
        help_line(" a          ", "add host"),
        help_line(" e          ", "edit host"),
        help_line(" d          ", "delete host"),
        help_line(" c          ", "clone host"),
        help_line(" t          ", "tag host (inline)"),
        help_line(" u          ", "undo delete"),
        Line::from(""),
        Line::from(Span::styled(" Tools", theme::section_header())),
        help_line(" i          ", "inspect all directives"),
        help_line(" v          ", "toggle detail panel"),
        help_line(" y          ", "copy ssh command"),
        help_line(" x          ", "copy config block"),
        help_line(" p / P      ", "ping host / ping all"),
        Line::from(""),
        Line::from(Span::styled(" Snippets", theme::section_header())),
        help_line(" Ctrl+Space ", "select / deselect host"),
        help_line(" r          ", "run snippet on host(s)"),
        help_line(" R          ", "run snippet on all visible"),
        Line::from(""),
        Line::from(Span::styled(" Overlays", theme::section_header())),
        help_line(" T          ", "tunnels for host"),
        help_line(" S          ", "cloud providers"),
        help_line(" K          ", "SSH keys"),
        Line::from(""),
        Line::from(Span::styled(" Forms", theme::section_header())),
        help_line(" Tab        ", "next field"),
        help_line(" Shift+Tab  ", "previous field"),
        help_line(" Enter      ", "save / open picker"),
        help_line(" Esc        ", "cancel"),
        Line::from(""),
        Line::from(Span::styled(" Search", theme::section_header())),
        help_line(" tag:name   ", "fuzzy tag filter"),
        help_line(" tag=name   ", "exact tag filter"),
        Line::from(""),
        help_line(" q / Esc    ", "quit / close"),
    ]
}

fn help_line<'a>(key: &'a str, desc: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(key, theme::accent_bold()),
        Span::raw(desc),
    ])
}
