use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};

use super::theme;
use crate::app::App;

pub fn render(frame: &mut Frame, _app: &App, alias: &str) {

    let area = super::centered_rect_fixed(48, 7, frame.area());

    // Clear background
    frame.render_widget(Clear, area);

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(Span::styled(" Confirm Delete ", theme::danger()))
        .border_style(theme::border_danger());

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  Delete \"{}\"?", alias),
            theme::bold(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("    y", theme::danger()),
            Span::styled(" yes   ", theme::muted()),
            Span::styled("Esc", theme::accent_bold()),
            Span::styled(" no", theme::muted()),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

pub fn render_host_key_reset(frame: &mut Frame, _app: &App, hostname: &str) {
    let display = super::truncate(hostname, 40);
    let area = super::centered_rect_fixed(52, 9, frame.area());

    frame.render_widget(Clear, area);

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(Span::styled(" Host Key Changed ", theme::danger()))
        .border_style(theme::border_danger());

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  Host key for {} changed.", display),
            theme::bold(),
        )),
        Line::from(Span::styled(
            "  This can happen after a server reinstall.",
            theme::muted(),
        )),
        Line::from(Span::styled(
            "  Remove old key and reconnect?",
            theme::muted(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("    y", theme::danger()),
            Span::styled(" yes   ", theme::muted()),
            Span::styled("Esc", theme::accent_bold()),
            Span::styled(" no", theme::muted()),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

pub fn render_welcome(frame: &mut Frame, _app: &App, has_backup: bool) {
    let height = if has_backup { 10 } else { 6 };
    let area = super::centered_rect_fixed(60, height, frame.area());

    frame.render_widget(Clear, area);

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(Span::styled(" Welcome ", theme::brand()))
        .border_style(theme::accent());

    let mut text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("Welcome to ", theme::bold()),
            Span::styled("purple", theme::border_search()),
            Span::styled(".", theme::bold()),
        ]).alignment(Alignment::Center),
    ];
    if has_backup {
        text.push(Line::from(""));
        text.push(
            Line::from(Span::styled(
                "Your original SSH config has been backed up",
                theme::muted(),
            )).alignment(Alignment::Center),
        );
        text.push(
            Line::from(Span::styled(
                "to ~/.purple/config.original",
                theme::muted(),
            )).alignment(Alignment::Center),
        );
    }
    text.push(Line::from(""));
    text.push(
        Line::from(vec![
            Span::styled("?", theme::accent_bold()),
            Span::styled(" cheat sheet   ", theme::muted()),
            Span::styled("Enter", theme::accent_bold()),
            Span::styled(" continue", theme::muted()),
        ]).alignment(Alignment::Center),
    );

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}
