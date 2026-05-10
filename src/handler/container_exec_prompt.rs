//! Key handler for the container exec prompt
//! (`Screen::ContainerExecPrompt`). Opens via `e` on the containers
//! tab; the user types a single-line command, Enter submits it
//! through the existing `pending_container_exec` flow with the typed
//! command in place of the default shell.

use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, ContainerExecRequest, Screen};

pub(super) fn handle_keys(app: &mut App, key: KeyEvent) {
    let Screen::ContainerExecPrompt {
        alias,
        container_id,
        container_name,
        query,
    } = &mut app.screen
    else {
        return;
    };

    match key.code {
        KeyCode::Esc => {
            log::debug!("[purple] container_exec_prompt: cancelled");
            app.set_screen(Screen::HostList);
        }
        KeyCode::Enter => {
            let cmd = query.trim().to_string();
            if cmd.is_empty() {
                // Empty submit is a no-op (no toast, no transition);
                // the user is asking for nothing.
                return;
            }
            // Reject control characters so a paste with embedded
            // newlines or escapes cannot smuggle a multi-line command
            // past the single-line prompt.
            if cmd.chars().any(|c| c.is_control()) {
                app.notify_error(crate::messages::CONTAINER_EXEC_INVALID_COMMAND.to_string());
                return;
            }
            let alias = alias.clone();
            let container_id = container_id.clone();
            let container_name = container_name.clone();
            queue_exec_with_command(app, alias, container_id, container_name, cmd);
        }
        KeyCode::Backspace => {
            query.pop();
        }
        // Cap the buffer at 512 chars so a held-down key cannot grow
        // without bound. 512 covers any realistic one-off command and
        // is well below shell ARG_MAX.
        KeyCode::Char(c) if query.chars().count() < 512 => {
            query.push(c);
        }
        _ => {}
    }
}

fn queue_exec_with_command(
    app: &mut App,
    alias: String,
    container_id: String,
    container_name: String,
    command: String,
) {
    let Some(entry) = app.container_cache.get(&alias) else {
        log::debug!(
            "[purple] container_exec_prompt: submit aborted, no cache for alias={}",
            alias
        );
        app.set_screen(Screen::HostList);
        return;
    };
    let runtime = entry.runtime;
    let askpass = app
        .hosts_state
        .list
        .iter()
        .find(|h| h.alias == alias)
        .and_then(|h| h.askpass.clone());

    log::info!(
        "[purple] container_exec_prompt: queue exec alias={} id={} cmd_len={}",
        alias,
        container_id,
        command.len()
    );
    app.pending_container_exec = Some(ContainerExecRequest {
        alias,
        askpass,
        runtime,
        container_id,
        container_name,
        command: Some(command),
    });
    app.set_screen(Screen::HostList);
}
