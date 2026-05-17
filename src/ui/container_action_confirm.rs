//! Confirm dialogs for the per-container destructive actions
//! (`Screen::ConfirmContainerRestart`, `Screen::ConfirmContainerStop`).
//! Both dialogs share a layout and only differ in the title block,
//! the body wording and the footer verb. One module, two thin
//! entry points.

use ratatui::Frame;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};

use super::design;
use super::theme;
use crate::app::{App, Screen};

/// Render the restart confirm dialog. Pulls `name`, `alias`,
/// `project`, and `uptime` from `Screen::ConfirmContainerRestart`.
/// No-op when the screen variant differs (defensive. main loop
/// guards against this but the renderer should be predictable).
pub fn render_restart(frame: &mut Frame, app: &mut App) {
    let Screen::ConfirmContainerRestart {
        alias,
        container_name,
        project,
        uptime,
        ..
    } = &app.screen
    else {
        return;
    };
    render_dialog(
        frame,
        " Restart container? ",
        container_name,
        alias,
        project.as_deref(),
        uptime.as_deref(),
        crate::messages::CONTAINER_RESTART_BODY,
        ("restart", "keep"),
    );
}

/// Render the stack-restart confirm dialog. Lists every running
/// member that will be cycled. Sized larger than the per-container
/// confirms so the member list fits without scrolling.
pub fn render_stack(frame: &mut Frame, app: &mut App) {
    let Screen::ConfirmStackRestart {
        alias,
        project,
        members,
    } = &app.screen
    else {
        return;
    };
    let identity = Line::from(vec![
        Span::raw("  "),
        Span::styled(project.clone(), theme::bold()),
        Span::raw("  "),
        Span::styled(format!("on  {}", alias), theme::muted()),
        Span::raw("  "),
        Span::styled(format!("· {} running", members.len()), theme::muted()),
    ]);
    render_bulk_dialog(
        frame,
        " Restart stack? ",
        identity,
        members,
        crate::messages::CONTAINER_STACK_RESTART_BODY,
        ("restart", "keep"),
    );
}

/// Render the bulk-restart-host confirm dialog. Lists every running
/// container on the host that will be cycled. Same layout as
/// `render_stack` so users on the divider see a familiar sheet.
pub fn render_host_restart_all(frame: &mut Frame, app: &mut App) {
    let Screen::ConfirmHostRestartAll { alias, members } = &app.screen else {
        return;
    };
    let identity = Line::from(vec![
        Span::raw("  "),
        Span::styled(alias.clone(), theme::bold()),
        Span::raw("  "),
        Span::styled(format!("· {} running", members.len()), theme::muted()),
    ]);
    render_bulk_dialog(
        frame,
        " Restart all containers on host? ",
        identity,
        members,
        crate::messages::CONTAINER_HOST_RESTART_ALL_BODY,
        ("restart", "keep"),
    );
}

/// Render the bulk-stop-host confirm dialog.
pub fn render_host_stop_all(frame: &mut Frame, app: &mut App) {
    let Screen::ConfirmHostStopAll { alias, members } = &app.screen else {
        return;
    };
    let identity = Line::from(vec![
        Span::raw("  "),
        Span::styled(alias.clone(), theme::bold()),
        Span::raw("  "),
        Span::styled(format!("· {} running", members.len()), theme::muted()),
    ]);
    render_bulk_dialog(
        frame,
        " Stop all containers on host? ",
        identity,
        members,
        crate::messages::CONTAINER_HOST_STOP_ALL_BODY,
        ("stop", "keep"),
    );
}

/// Shared layout for every bulk-action confirm dialog (stack-restart,
/// host-restart-all, host-stop-all). Caller supplies the title, the
/// identity line that introduces the scope (project-on-host vs host
/// alone), the member list to cycle, the body line and the footer
/// verbs. Body lines wrap so longer wording does not get clipped at
/// the dialog edge; the height budget reserves two extra rows for the
/// body so a one- or two-line wrap stays inside the box.
fn render_bulk_dialog(
    frame: &mut Frame,
    title: &str,
    identity: Line<'_>,
    members: &[crate::app::StackMember],
    body: &str,
    verbs: (&str, &str),
) {
    let height = (5 + members.len() as u16 + 5).min(22);
    let area = super::centered_rect_fixed(64, height, frame.area());
    frame.render_widget(Clear, area);
    let block = design::danger_block(title);

    let mut text: Vec<Line> = vec![Line::from(""), identity, Line::from("")];
    for m in members {
        let uptime = m.uptime.clone().unwrap_or_else(|| "-".to_string());
        text.push(Line::from(vec![
            Span::raw("   "),
            Span::raw(design::ICON_ONLINE),
            Span::raw(" "),
            Span::styled(m.container_name.clone(), theme::bold()),
            Span::raw("   "),
            Span::styled(uptime, theme::muted()),
        ]));
    }
    text.push(Line::from(""));
    text.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(body.to_string(), theme::muted()),
    ]));

    design::render_body_wrapped(frame, area, block, text);

    let footer_area = design::render_overlay_footer(frame, area);
    let footer = design::confirm_footer_destructive(verbs.0, verbs.1).to_line();
    frame.render_widget(Paragraph::new(footer), footer_area);
}

/// Render the stop confirm dialog. Same shape as `render_restart`.
pub fn render_stop(frame: &mut Frame, app: &mut App) {
    let Screen::ConfirmContainerStop {
        alias,
        container_name,
        project,
        uptime,
        ..
    } = &app.screen
    else {
        return;
    };
    render_dialog(
        frame,
        " Stop container? ",
        container_name,
        alias,
        project.as_deref(),
        uptime.as_deref(),
        crate::messages::CONTAINER_STOP_BODY,
        ("stop", "keep"),
    );
}

#[allow(clippy::too_many_arguments)]
fn render_dialog(
    frame: &mut Frame,
    title: &str,
    name: &str,
    alias: &str,
    project: Option<&str>,
    uptime: Option<&str>,
    body: &str,
    verbs: (&str, &str),
) {
    // Body lines describe the destructive mechanics in full sentences
    // and easily exceed the 60-col interior width. Reserve an extra
    // row so a wrapped body still fits inside the box. `Wrap` on the
    // Paragraph itself respects `Span::raw("  ")` indentation.
    let area = super::centered_rect_fixed(60, 10, frame.area());
    frame.render_widget(Clear, area);
    let block = design::danger_block(title);

    let identity_line = Line::from(vec![
        Span::raw("  "),
        Span::styled(name.to_string(), theme::bold()),
        Span::raw("  "),
        Span::styled(format!("on  {}", alias), theme::muted()),
    ]);

    let mut meta_parts: Vec<String> = Vec::new();
    if let Some(p) = project {
        meta_parts.push(p.to_string());
    }
    if let Some(u) = uptime {
        meta_parts.push(format!("Up {}", u));
    }
    let meta_line = if meta_parts.is_empty() {
        Line::from("")
    } else {
        Line::from(vec![
            Span::raw("  "),
            Span::styled(meta_parts.join("  ·  "), theme::muted()),
        ])
    };

    let body_line = Line::from(vec![Span::raw("  "), Span::styled(body, theme::muted())]);

    let text = vec![
        Line::from(""),
        identity_line,
        meta_line,
        Line::from(""),
        body_line,
    ];

    design::render_body_wrapped(frame, area, block, text);

    // Stakes test: destructive action, action verbs both sides.
    let footer_area = design::render_overlay_footer(frame, area);
    let footer = design::confirm_footer_destructive(verbs.0, verbs.1).to_line();
    frame.render_widget(Paragraph::new(footer), footer_area);
}
