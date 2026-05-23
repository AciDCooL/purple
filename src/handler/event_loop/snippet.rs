//! Snippet run events. Accumulates per-host stdout/stderr/exit_code into
//! `app.snippets.output` and tracks completion progress for the snippet
//! output overlay.

use crate::app::{self, App};

/// Handle `AppEvent::SnippetHostDone`.
pub(crate) fn handle_snippet_host_done(
    app: &mut App,
    run_id: u64,
    alias: String,
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
) {
    if exit_code == Some(0) {
        app.history.record(&alias);
        app.record_key_use(&alias, crate::key_activity::now_secs());
        app.apply_sort();
    }
    if let Some(state) = app.snippets.output_mut() {
        if state.run_id == run_id {
            state.results.push(app::SnippetHostOutput {
                alias,
                stdout,
                stderr,
                exit_code,
            });
        }
    }
}

/// Handle `AppEvent::SnippetProgress`.
pub(crate) fn handle_snippet_progress(app: &mut App, run_id: u64, completed: usize, total: usize) {
    if let Some(state) = app.snippets.output_mut() {
        if state.run_id == run_id {
            state.completed = completed;
            state.total = total;
        }
    }
}

/// Handle `AppEvent::SnippetAllDone`.
pub(crate) fn handle_snippet_all_done(app: &mut App, run_id: u64) {
    if let Some(state) = app.snippets.output_mut() {
        if state.run_id == run_id {
            state.all_done = true;
        }
    }
}
