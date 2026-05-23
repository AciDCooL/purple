//! Key-push run accumulation. Each completed host pushes a `KeyPushResult`;
//! once `expected_count` has landed, `finalize_key_push` collapses them into
//! a single summary toast and refreshes the key list. Stale-run results
//! (after a cancel) are dropped before they touch the accumulator.

use crate::app::App;

/// Handle `AppEvent::KeyPushResult`. Accumulates per-host outcomes and
/// fires the run-completion summary exactly once.
///
/// Events whose `run_id` no longer matches the current run are dropped
/// before they touch the accumulator: this happens when a worker that
/// was cancelled mid-batch sends its tail event after a new run has
/// already started. Without the guard the stale event would either
/// pollute the new run's tallies or trip `finalize` one event sooner
/// than the new run actually finished.
pub(crate) fn handle_key_push_result(
    app: &mut App,
    run_id: u64,
    result: crate::key_push::KeyPushResult,
) {
    if run_id != app.keys.push.run_id {
        log::debug!(
            "[purple] key_push: dropping stale result for alias={} (event run_id={} current={})",
            result.alias,
            run_id,
            app.keys.push.run_id
        );
        return;
    }
    let expected = app.keys.push.expected_count;
    if expected == 0 {
        // No run is in flight (cancel just zeroed expected_count); drop.
        return;
    }
    app.keys.push.results.push(result);
    if app.keys.push.results.len() < expected {
        return;
    }
    finalize_key_push(app);
}

/// Compute the summary toast / sticky overlay from the accumulated
/// `KeyPushResult` entries and clear the run state. Pure-ish given the
/// app reference; called from `handle_key_push_result` once the expected
/// count is reached.
fn finalize_key_push(app: &mut App) {
    use crate::key_push::KeyPushOutcome;
    let mut appended = 0usize;
    let mut already = 0usize;
    let mut failed: Vec<(String, String)> = Vec::new();
    for r in &app.keys.push.results {
        match &r.outcome {
            KeyPushOutcome::Appended => appended += 1,
            KeyPushOutcome::AlreadyPresent => already += 1,
            KeyPushOutcome::Failed(msg) => failed.push((r.alias.clone(), msg.clone())),
        }
    }

    let total = app.keys.push.results.len();
    // Drop the "Pushing X to N hosts..." sticky progress before the
    // outcome toast lands; otherwise the footer would keep advertising
    // a push that already finished.
    app.status_center.clear_sticky_status();
    if failed.is_empty() {
        app.notify(crate::messages::key_push_success(appended, already));
    } else if failed.len() == total {
        app.notify_sticky_error(crate::messages::key_push_all_failed(total));
    } else {
        // Partial-failure: name up to five failed aliases inline so the
        // user can act on the outcome without grepping the log file. The
        // toast goes sticky because the headline number alone hides which
        // hosts need follow-up.
        let mut body = crate::messages::key_push_partial_failure(appended + already, failed.len());
        let preview: Vec<&str> = failed.iter().take(5).map(|(a, _)| a.as_str()).collect();
        if !preview.is_empty() {
            body.push_str(" Failed: ");
            body.push_str(&preview.join(", "));
            if failed.len() > preview.len() {
                use std::fmt::Write;
                let _ = write!(body, ", +{} more", failed.len() - preview.len());
            }
            body.push('.');
        }
        app.notify_sticky_error(body);
    }

    for (alias, msg) in &failed {
        // Remote failure is an external fault (the remote host's choice),
        // not a bug in purple. Tag it as such so log filters can split
        // [external] from [purple] like the rest of the codebase.
        log::warn!("[external] key_push: failed alias={} err={}", alias, msg);
    }

    // Refresh keys so linked_hosts picks up the newly-authorized aliases.
    // Honour the test override so suite runs never touch the real ~/.ssh.
    if appended > 0 {
        let ssh_dir = crate::ssh_keys::resolve_ssh_dir();
        if let Some(dir) = ssh_dir {
            app.keys.list = crate::ssh_keys::discover_keys(&dir, &app.hosts_state.list);
            // Clamp the key-list cursor in case discover_keys returned a
            // shorter list (a key removed between push start and finalize
            // would otherwise leave the cursor pointing past the end).
            if let Some(sel) = app.keys.list_state.selected() {
                if app.keys.list.is_empty() {
                    app.keys.list_state.select(None);
                } else if sel >= app.keys.list.len() {
                    app.keys.list_state.select(Some(app.keys.list.len() - 1));
                }
            }
        }
    }

    // Reset push state for the next run.
    app.keys.push.finish_run();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::key_push::{KeyPushOutcome, KeyPushResult};
    use crate::ssh_config::model::SshConfigFile;

    fn make_app() -> App {
        // Tempdir + preferences override so the in-test App does not touch
        // ~/.purple/ or ~/.ssh/. The SSH override scopes finalize_key_push's
        // `discover_keys` refresh at an empty synthetic dir so the
        // appended>0 path is exercisable in a clean HOME.
        let scratch = tempfile::tempdir().expect("tempdir").keep();
        crate::preferences::set_path_override(scratch.join("preferences"));
        crate::containers::set_path_override(scratch.join("container_cache.jsonl"));
        std::fs::create_dir_all(scratch.join("synthetic-ssh")).unwrap();
        crate::ssh_keys::set_ssh_dir_override(scratch.join("synthetic-ssh"));
        let config = SshConfigFile {
            elements: SshConfigFile::parse_content(""),
            path: scratch.join("test_config"),
            crlf: false,
            bom: false,
        };
        let mut app = App::new(config);
        // Tests assume a fresh run_id so they can fire results with run_id=1
        // without colliding with whatever default App::new set up.
        app.keys.push.run_id = 1;
        app
    }

    fn result(alias: &str, outcome: KeyPushOutcome) -> KeyPushResult {
        KeyPushResult {
            alias: alias.to_string(),
            outcome,
        }
    }

    #[test]
    fn handle_result_does_not_finalize_below_expected() {
        let mut app = make_app();
        app.keys.push.expected_count = 3;
        handle_key_push_result(&mut app, 1, result("h1", KeyPushOutcome::AlreadyPresent));
        assert_eq!(app.keys.push.results.len(), 1);
        assert_eq!(app.keys.push.expected_count, 3, "should not finalize early");
    }

    #[test]
    fn handle_result_skips_when_expected_zero() {
        // After a cancel the expected_count is zeroed; late-arriving
        // results from the worker must be dropped, not re-trigger the
        // finalize path.
        let mut app = make_app();
        app.keys.push.expected_count = 0;
        handle_key_push_result(&mut app, 1, result("h1", KeyPushOutcome::Appended));
        assert!(app.keys.push.results.is_empty());
    }

    #[test]
    fn handle_result_drops_stale_run_id() {
        // A worker that was cancelled mid-batch can still emit results
        // tagged with the old run_id. After the user starts a new push,
        // run_id has been bumped: the stale events must not contaminate
        // the new run's accumulator.
        let mut app = make_app();
        app.keys.push.expected_count = 2;
        app.keys.push.run_id = 7;
        handle_key_push_result(&mut app, 6, result("h-stale", KeyPushOutcome::Appended));
        assert!(
            app.keys.push.results.is_empty(),
            "stale-run event must not push into the new run's results"
        );
    }

    #[test]
    fn finalize_all_already_present_emits_success_toast() {
        let mut app = make_app();
        app.keys.push.expected_count = 2;
        app.keys
            .push
            .results
            .push(result("h1", KeyPushOutcome::AlreadyPresent));
        handle_key_push_result(&mut app, 1, result("h2", KeyPushOutcome::AlreadyPresent));
        // After finalize, accumulator state is cleared.
        assert_eq!(app.keys.push.expected_count, 0);
        assert!(app.keys.push.results.is_empty());
        assert!(app.keys.push.selected.is_empty());
        // Last status should be a non-sticky (toast) success.
        let toast = app.status_center.toast().expect("toast set");
        assert!(!toast.sticky, "fully-successful run is a plain toast");
    }

    #[test]
    fn finalize_all_failed_emits_sticky_error() {
        let mut app = make_app();
        app.keys.push.expected_count = 2;
        app.keys
            .push
            .results
            .push(result("h1", KeyPushOutcome::Failed("oops".into())));
        handle_key_push_result(
            &mut app,
            1,
            result("h2", KeyPushOutcome::Failed("also bad".into())),
        );
        assert_eq!(app.keys.push.expected_count, 0);
        let status = app.status_center.status().expect("sticky status");
        assert!(
            status.sticky && status.is_error(),
            "all-failed should be sticky-error"
        );
    }

    #[test]
    fn finalize_partial_failure_is_sticky_and_names_failed_hosts() {
        let mut app = make_app();
        app.keys.push.expected_count = 3;
        app.keys
            .push
            .results
            .push(result("h1", KeyPushOutcome::AlreadyPresent));
        app.keys
            .push
            .results
            .push(result("h2", KeyPushOutcome::Failed("bad".into())));
        handle_key_push_result(&mut app, 1, result("h3", KeyPushOutcome::AlreadyPresent));
        assert_eq!(app.keys.push.expected_count, 0);
        let status = app.status_center.status().expect("sticky status set");
        assert!(
            status.sticky && status.is_error(),
            "partial failure is sticky so the user sees which hosts failed"
        );
        assert!(
            status.text.contains("h2"),
            "failed alias must appear in body: {}",
            status.text
        );
    }

    #[test]
    fn finalize_appended_refreshes_keys_against_override_dir_not_real_home() {
        // Regression guard for the host-sensitive finalize branch. The
        // override directory exists but is empty, so the refresh yields
        // zero keys without touching the test runner's actual ~/.ssh.
        let mut app = make_app();
        app.keys.push.expected_count = 1;
        // Pre-seed a stale key entry to prove the refresh ran.
        app.keys.list.push(crate::ssh_keys::SshKeyInfo {
            name: "stale".into(),
            display_path: "~/.ssh/stale".into(),
            key_type: "ED25519".into(),
            bits: "256".into(),
            fingerprint: String::new(),
            comment: String::new(),
            linked_hosts: vec![],
            bishop_art: String::new(),
            strength_score: 90,
            encrypted: false,
            agent_loaded: false,
            is_certificate: false,
            mtime_ts: None,
        });
        handle_key_push_result(&mut app, 1, result("h", KeyPushOutcome::Appended));
        assert!(
            app.keys.list.is_empty(),
            "discover_keys against an empty override dir should return zero keys"
        );
        assert_eq!(app.keys.list_state.selected(), None);
    }
}
