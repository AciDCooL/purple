//! Full-screen logs overlay for `Screen::ContainerLogs`. Renders a
//! single block with a top title (`logs · alias · name · fetched
//! Xs ago`), the captured log lines as a scrollable Paragraph, and
//! a footer with the navigation keys. No styling is applied to the
//! log lines themselves: container output is opaque and any
//! syntax-highlighting heuristic risks dragging false positives in.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};

use super::design;
use super::theme;
use crate::app::{App, Screen};
use crate::messages::footer as fl;

pub fn render(frame: &mut Frame, app: &mut App) {
    let Screen::ContainerLogs {
        alias,
        container_name,
        body,
        fetched_at,
        error,
        scroll,
        ..
    } = &app.screen
    else {
        return;
    };

    let area = frame.area();
    frame.render_widget(Clear, area);

    let [body_area, footer_area] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area);

    let title_line = build_title(alias, container_name, *fetched_at, error.as_deref(), app);

    let block = design::overlay_block_line(title_line);
    let inner = block.inner(body_area);
    frame.render_widget(block, body_area);

    // Clamp scroll so it never leaves blank space below the body when
    // the body is longer than the viewport. With short bodies this is
    // a no-op (max_scroll = 0). The clamp guards against the
    // logs-arrival path running before the renderer has measured the
    // viewport (last_render_height = 0 yields scroll = body.len()).
    // Reuses the handler's `tail_scroll` so the two stay in lockstep.
    let max_scroll = crate::handler::container_logs::tail_scroll(body.len(), inner.height);
    let effective_scroll = (*scroll).min(max_scroll);
    render_body(frame, inner, body, error.as_deref(), effective_scroll);

    // Stash the rendered area height so the next logs-arrival or `G`
    // keypress can compute the tail-anchored scroll.
    if let Screen::ContainerLogs {
        last_render_height, ..
    } = &mut app.screen
    {
        *last_render_height = inner.height;
    }

    let footer_spans = design::Footer::new()
        .primary("Esc", fl::ACTION_BACK)
        .action("g", fl::ACTION_TOP)
        .action("G", fl::ACTION_BOTTOM)
        .action("j/k", fl::ACTION_SCROLL)
        .action("PgUp/PgDn", fl::ACTION_PAGE)
        .action("r", fl::ACTION_REFRESH)
        .into_spans();
    frame.render_widget(Paragraph::new(Line::from(footer_spans)), footer_area);
}

fn build_title(
    alias: &str,
    container_name: &str,
    fetched_at: u64,
    error: Option<&str>,
    app: &App,
) -> Line<'static> {
    let now = if app.demo_mode {
        crate::demo_flag::now_secs()
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };
    let mut spans = vec![
        Span::styled(" logs ", theme::bold()),
        Span::styled(format!("· {} ", container_name), theme::bold()),
        Span::styled(format!("· on {} ", alias), theme::muted()),
    ];
    if let Some(e) = error {
        spans.push(Span::styled(
            format!("· {} ", crate::messages::container_logs_failed(e)),
            theme::error(),
        ));
    } else if fetched_at == 0 {
        spans.push(Span::styled(
            format!("· {} ", crate::messages::CONTAINER_LOGS_LOADING),
            theme::muted(),
        ));
    } else {
        let age = now.saturating_sub(fetched_at);
        spans.push(Span::styled(
            format!("· {} ", crate::messages::container_logs_fetched(age)),
            theme::muted(),
        ));
    }
    Line::from(spans)
}

fn render_body(frame: &mut Frame, area: Rect, body: &[String], error: Option<&str>, scroll: u16) {
    if let Some(e) = error {
        // Error path: centred message in error style. Body is
        // empty because the SSH call failed before any output landed.
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("  fetch failed: {}", e),
                theme::error(),
            )),
        ];
        frame.render_widget(Paragraph::new(lines), area);
        return;
    }
    if body.is_empty() {
        // Loading path: spinner-less placeholder. The SSH call is
        // bounded and short; a static label avoids fighting the
        // crossterm tick cadence.
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("  {}", crate::messages::CONTAINER_LOGS_LOADING),
                theme::muted(),
            )),
        ];
        frame.render_widget(Paragraph::new(lines), area);
        return;
    }
    let lines: Vec<Line<'_>> = body.iter().map(|s| Line::from(s.as_str())).collect();
    let paragraph = Paragraph::new(lines).scroll((scroll, 0));
    frame.render_widget(paragraph, area);
}
