use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{App, Screen};
use crate::event::AppEvent;

/// Result of routing a confirm-dialog key event.
///
/// Confirm dialogs accept exactly three classes of keys:
/// - `Yes`: y / Y
/// - `No`: n / N / Esc
/// - `Ignored`: anything else (must NOT change app state)
///
/// **Critical safety invariant**: a `_ =>` catch-all in a confirm handler
/// that transitions screen state is forbidden. A misplaced keypress must not
/// silently cancel a destructive operation. Use [`route_confirm_key`] in every
/// confirm handler to enforce the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    Yes,
    No,
    Ignored,
}

/// Single source of truth for confirm-dialog key routing.
pub fn route_confirm_key(key: KeyEvent) -> ConfirmAction {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => ConfirmAction::Yes,
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ConfirmAction::No,
        _ => ConfirmAction::Ignored,
    }
}

/// Run known_hosts import and set status. Used by both ConfirmImport and Welcome handlers.
pub(super) fn execute_known_hosts_import(app: &mut App) {
    let config_backup = app.hosts_state.ssh_config().clone();
    match crate::import::import_from_known_hosts(
        app.hosts_state.ssh_config_mut(),
        Some("known_hosts"),
    ) {
        Ok((imported, skipped, _, _)) => {
            if imported > 0 {
                if let Err(e) = app.hosts_state.ssh_config().write() {
                    app.hosts_state.set_ssh_config(config_backup);
                    app.notify_error(crate::messages::failed_to_save(&e));
                    return;
                }
                app.reload_hosts();
                app.notify(crate::messages::imported_hosts(imported, skipped));
            } else {
                app.notify(crate::messages::all_hosts_exist(skipped));
            }
            app.ui.known_hosts_count = 0;
        }
        Err(e) => {
            app.notify_error(e);
        }
    }
}

pub(super) fn handle_import_key(app: &mut App, key: KeyEvent) {
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            app.set_screen(Screen::HostList);
            execute_known_hosts_import(app);
        }
        ConfirmAction::No => {
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::Ignored => {}
    }
}

pub(super) fn handle_purge_stale_key(app: &mut App, key: KeyEvent) {
    let Screen::ConfirmPurgeStale { provider: p, .. } = &app.screen else {
        return;
    };
    let provider = p.clone();
    let return_screen = if provider.is_some() {
        Screen::Providers
    } else {
        Screen::HostList
    };
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            execute_purge_stale(app, provider.as_deref());
            app.screen = return_screen;
        }
        ConfirmAction::No => {
            app.screen = return_screen;
        }
        ConfirmAction::Ignored => {}
    }
}

fn execute_purge_stale(app: &mut App, provider: Option<&str>) {
    let stale = app.hosts_state.ssh_config().stale_hosts();
    if stale.is_empty() {
        return;
    }
    // Filter by provider if specified.
    let targets: Vec<(String, u64)> = if let Some(prov) = provider {
        stale
            .into_iter()
            .filter(|(alias, _)| {
                app.hosts_state
                    .ssh_config()
                    .host_entries()
                    .iter()
                    .any(|e| e.alias == *alias && e.provider.as_deref() == Some(prov))
            })
            .collect()
    } else {
        stale
    };
    if targets.is_empty() {
        return;
    }
    let config_backup = app.hosts_state.ssh_config().clone();
    let count = targets.len();
    for (alias, _) in &targets {
        app.hosts_state.ssh_config_mut().delete_host(alias);
    }
    if let Err(e) = app.hosts_state.ssh_config().write() {
        app.hosts_state.set_ssh_config(config_backup);
        app.notify_error(crate::messages::failed_to_save(&e));
        return;
    }
    // Kill active tunnels only after successful write (no rollback needed).
    for (alias, _) in &targets {
        if let Some(mut tunnel) = app.tunnels.active_remove(alias) {
            let _ = tunnel.child.kill();
            let _ = tunnel.child.wait();
        }
    }
    app.hosts_state.clear_undo();
    app.update_last_modified();
    app.reload_hosts();
    let msg = if let Some(prov) = provider {
        let display = crate::providers::provider_display_name(prov);
        format!(
            "Removed {} stale {} host{}.",
            count,
            display,
            if count == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "Removed {} stale host{}.",
            count,
            if count == 1 { "" } else { "s" }
        )
    };
    app.notify(msg);
}

pub(super) fn handle_delete_key(app: &mut App, key: KeyEvent) {
    let Screen::ConfirmDelete { alias } = &app.screen else {
        return;
    };
    let alias = alias.clone();
    // Use the central confirm-key router so the y/n/Esc contract is uniform
    // across all confirm dialogs.
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            let siblings = app.hosts_state.ssh_config().siblings_of(&alias);

            if !siblings.is_empty() {
                // Multi-alias block: strip only the selected token.
                // `delete_host_undoable` refuses this case (returning
                // None) because re-inserting the whole element via
                // `insert_host_at` cannot reverse a token strip. We
                // therefore skip the undo stack and surface the event
                // via a dedicated toast that names the surviving
                // siblings, so the user knows what did and did not
                // change on disk.
                app.hosts_state.ssh_config_mut().delete_host(&alias);
                if let Err(e) = app.hosts_state.ssh_config().write() {
                    // Disk write failed: reload from disk to discard
                    // the in-memory strip so view and storage match.
                    app.notify_error(crate::messages::failed_to_save(&e));
                    app.reload_hosts();
                } else {
                    if let Some(mut tunnel) = app.tunnels.active_remove(&alias) {
                        let _ = tunnel.child.kill();
                        let _ = tunnel.child.wait();
                    }
                    app.update_last_modified();
                    app.reload_hosts();
                    app.notify(crate::messages::siblings_stripped(&alias, siblings.len()));
                }
            } else if let Some((element, position)) = app
                .hosts_state
                .ssh_config_mut()
                .delete_host_undoable(&alias)
            {
                if let Err(e) = app.hosts_state.ssh_config().write() {
                    // Restore the element on write failure
                    app.hosts_state
                        .ssh_config_mut()
                        .insert_host_at(element, position);
                    app.notify_error(crate::messages::failed_to_save(&e));
                } else {
                    // Stop active tunnel for the deleted host
                    if let Some(mut tunnel) = app.tunnels.active_remove(&alias) {
                        let _ = tunnel.child.kill();
                        let _ = tunnel.child.wait();
                    }
                    // Clean up cert file if it exists. NotFound is the
                    // expected case for hosts that never had a cert. Other
                    // errors are surfaced via the status bar (never via
                    // eprintln, which would corrupt the ratatui screen).
                    let mut cert_cleanup_warning: Option<String> = None;
                    if !crate::demo_flag::is_demo() {
                        if let Ok(cert_path) = crate::vault_ssh::cert_path_for(&alias) {
                            match std::fs::remove_file(&cert_path) {
                                Ok(()) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                                Err(e) => {
                                    cert_cleanup_warning =
                                        Some(crate::messages::cert_cleanup_warning(
                                            &cert_path.display(),
                                            &e,
                                        ));
                                }
                            }
                        }
                    }
                    app.hosts_state
                        .undo_stack_mut()
                        .push(crate::app::DeletedHost { element, position });
                    if app.hosts_state.undo_stack().len() > 50 {
                        app.hosts_state.undo_stack_mut().remove(0);
                    }
                    app.update_last_modified();
                    app.reload_hosts();
                    if let Some(warning) = cert_cleanup_warning {
                        app.notify_error(warning);
                    } else {
                        app.notify(crate::messages::goodbye_host(&alias));
                    }
                }
            } else {
                app.notify_warning(crate::messages::host_not_found(&alias));
            }
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::No => {
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::Ignored => {}
    }
}

pub(super) fn handle_vault_sign_key(
    app: &mut App,
    key: KeyEvent,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    // Vault Sign is a destructive/material action: signing N certificates
    // hits Vault, may take time and is hard to reverse. Stray keys must NOT
    // cancel. use `route_confirm_key` so only y/Y/n/N/Esc are honored.
    // History: an earlier `_ => app.screen = Screen::HostList` catch-all
    // could be triggered by any keypress next to `y` (e.g. fat-fingered
    // `t` or `u`), silently aborting a bulk sign.
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            // Extract the precomputed signable list, then transition back to
            // the host list and kick off the background signing loop.
            let signable = if let Screen::ConfirmVaultSign { signable } = &app.screen {
                signable.clone()
            } else {
                return;
            };
            app.set_screen(Screen::HostList);
            start_vault_bulk_sign(app, signable, events_tx);
        }
        ConfirmAction::No => {
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::Ignored => {}
    }
}

/// Start the background vault bulk sign loop with fast-fail, progress, TOCTOU
/// coordination and cancellation. Stores the JoinHandle on App for clean exit.
fn start_vault_bulk_sign(
    app: &mut App,
    signable: Vec<crate::vault_ssh::VaultSignTarget>,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    let total = signable.len();
    if total == 0 {
        return;
    }
    app.notify_progress(crate::messages::vault_signing_progress(
        crate::animation::SPINNER_FRAMES[0],
        0,
        total,
        "",
    ));

    let cancel = Arc::new(AtomicBool::new(false));
    app.vault.set_signing_cancel(cancel.clone());

    let in_flight = app.vault.sign_in_flight().clone();
    let tx = events_tx.clone();
    let spawn_result = std::thread::Builder::new()
        .name("vault-bulk-sign".into())
        .spawn(move || {
            let mut signed = 0u32;
            let mut failed = 0u32;
            let mut skipped = 0u32;
            let mut consecutive_failures = 0usize;
            let mut first_error: Option<String> = None;
            let mut aborted_message: Option<String> = None;

            for (idx, target) in signable.iter().enumerate() {
                let crate::vault_ssh::VaultSignTarget {
                    alias,
                    role,
                    certificate_file: cert_file,
                    pubkey,
                    vault_addr,
                } = target;
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let done = idx + 1;

                // TOCTOU: skip host if another thread already has it in-flight.
                // Otherwise mark it in-flight for the duration of this iteration.
                {
                    // If the mutex is poisoned a worker thread panicked while holding
                    // the lock. Recover the inner value without clearing. clearing
                    // the whole set would make every in-flight alias simultaneously
                    // eligible for re-signing, risking duplicate cert writes.
                    let mut set = match in_flight.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    if !set.insert(alias.clone()) {
                        skipped += 1;
                        let _ = tx.send(AppEvent::VaultSignProgress {
                            alias: alias.clone(),
                            done,
                            total,
                        });
                        continue;
                    }
                }

                let _ = tx.send(AppEvent::VaultSignProgress {
                    alias: alias.clone(),
                    done,
                    total,
                });

                let cert_path = match crate::vault_ssh::resolve_cert_path(alias, cert_file) {
                    Ok(p) => p,
                    Err(e) => {
                        failed += 1;
                        consecutive_failures += 1;
                        let scrubbed = crate::vault_ssh::scrub_vault_stderr(&e.to_string());
                        if first_error.is_none() {
                            first_error = Some(scrubbed);
                        }
                        remove_in_flight(&in_flight, alias);
                        if consecutive_failures >= 3 {
                            aborted_message = Some(crate::messages::vault_signing_aborted(
                                failed,
                                first_error.as_deref(),
                            ));
                            break;
                        }
                        continue;
                    }
                };
                let status = crate::vault_ssh::check_cert_validity(&cert_path);
                if !crate::vault_ssh::needs_renewal(&status) {
                    skipped += 1;
                    consecutive_failures = 0;
                    remove_in_flight(&in_flight, alias);
                    continue;
                }

                let sign_result =
                    crate::vault_ssh::sign_certificate(role, pubkey, alias, vault_addr.as_deref());
                // Always clean up in_flight for this alias before handling the
                // result. Using a single cleanup point (rather than per-arm)
                // prevents orphaned aliases when new control flow is added.
                remove_in_flight(&in_flight, alias);
                match sign_result {
                    Ok(_) => {
                        let _ = tx.send(AppEvent::VaultSignResult {
                            alias: alias.clone(),
                            certificate_file: cert_file.clone(),
                            success: true,
                            message: String::new(),
                        });
                        signed += 1;
                        consecutive_failures = 0;
                    }
                    Err(e) => {
                        let raw = e.to_string();
                        let scrubbed = crate::vault_ssh::scrub_vault_stderr(&raw);
                        if first_error.is_none() {
                            first_error = Some(scrubbed.clone());
                        }
                        let _ = tx.send(AppEvent::VaultSignResult {
                            alias: alias.clone(),
                            certificate_file: cert_file.clone(),
                            success: false,
                            message: scrubbed,
                        });
                        failed += 1;
                        consecutive_failures += 1;
                        if consecutive_failures >= 3 {
                            aborted_message = Some(crate::messages::vault_signing_aborted(
                                failed,
                                first_error.as_deref(),
                            ));
                            break;
                        }
                    }
                }
            }

            let cancelled = cancel.load(Ordering::Relaxed);
            let _ = tx.send(AppEvent::VaultSignAllDone {
                signed,
                failed,
                skipped,
                cancelled,
                aborted_message,
                first_error,
            });
        });
    match spawn_result {
        Ok(handle) => {
            log::info!("[purple] vault sign thread: spawned");
            app.vault.set_sign_thread(handle);
        }
        Err(e) => {
            // Spawn failed (e.g. OS thread limit). Clear the cancel flag and
            // surface the error. otherwise the status bar is stuck at
            // "Signing 0/N" with no way for the user to recover.
            log::warn!("[purple] vault sign thread: spawn failed: {}", e);
            let _ = app.vault.finalize_signing_run();
            app.notify_error(crate::messages::vault_spawn_failed(&e));
        }
    }
}

pub(super) fn remove_in_flight(
    set: &std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    alias: &str,
) {
    // On mutex poison, recover the inner value and remove only the target alias.
    // Do NOT clear the entire set. other in-flight aliases are still owned by
    // live worker iterations and clearing them would allow duplicate signs.
    let mut guard = match set.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    guard.remove(alias);
}

pub(super) fn handle_host_key_reset_key(app: &mut App, key: KeyEvent) {
    let Screen::ConfirmHostKeyReset {
        alias,
        hostname,
        known_hosts_path,
        askpass,
    } = &app.screen
    else {
        return;
    };
    let alias = alias.clone();
    let hostname = hostname.clone();
    let known_hosts_path = known_hosts_path.clone();
    let askpass = askpass.clone();
    // Host key reset wipes the host's known_hosts entry. uniform y/n/Esc
    // contract via the central router so stray keys cannot trigger it.
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            let output = std::process::Command::new("ssh-keygen")
                .arg("-R")
                .arg(&hostname)
                .arg("-f")
                .arg(&known_hosts_path)
                .output();

            match output {
                Ok(result) if result.status.success() => {
                    app.notify(crate::messages::removed_host_key(&hostname));
                    if app.demo_mode {
                        app.notify_warning(crate::messages::DEMO_CONNECTION_DISABLED);
                    } else {
                        app.ui.queue_connect(alias, askpass);
                    }
                }
                Ok(result) => {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    app.notify_error(crate::messages::host_key_remove_failed(stderr.trim()));
                }
                Err(e) => {
                    app.notify_error(crate::messages::ssh_keygen_failed(&e));
                }
            }
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::No => {
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::Ignored => {}
    }
}

/// Confirm handler for `K` (kick = restart). On Yes, queues a
/// `ContainerActionKind::Restart` request; the main loop picks it
/// up, fires the SSH command, and emits a result event. On No or
/// Esc, the screen drops without side effects.
pub(super) fn handle_container_restart_key(app: &mut App, key: KeyEvent) {
    let Screen::ConfirmContainerRestart {
        alias,
        container_id,
        container_name,
        ..
    } = &app.screen
    else {
        return;
    };
    let alias = alias.clone();
    let container_id = container_id.clone();
    let container_name = container_name.clone();
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            queue_container_action(
                app,
                alias,
                container_id,
                container_name,
                crate::containers::ContainerAction::Restart,
            );
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::No => {
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::Ignored => {}
    }
}

/// Confirm handler for `S` (stop). Same shape as restart; the action
/// kind differs and so does the destructive wording in the dialog
/// body.
pub(super) fn handle_container_stop_key(app: &mut App, key: KeyEvent) {
    let Screen::ConfirmContainerStop {
        alias,
        container_id,
        container_name,
        ..
    } = &app.screen
    else {
        return;
    };
    let alias = alias.clone();
    let container_id = container_id.clone();
    let container_name = container_name.clone();
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            queue_container_action(
                app,
                alias,
                container_id,
                container_name,
                crate::containers::ContainerAction::Stop,
            );
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::No => {
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::Ignored => {}
    }
}

/// Confirm handler for `Ctrl-K` (stack kick). Iterates the stored
/// member list and queues a Restart for each through the same drain
/// mechanism that powers single-container restart. The drain
/// processes one request per tick, giving a sequential cadence.
pub(super) fn handle_stack_restart_key(app: &mut App, key: KeyEvent) {
    let Screen::ConfirmStackRestart { alias, members, .. } = &app.screen else {
        return;
    };
    let alias = alias.clone();
    let members = members.clone();
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            for m in members {
                queue_container_action(
                    app,
                    alias.clone(),
                    m.container_id,
                    m.container_name,
                    crate::containers::ContainerAction::Restart,
                );
            }
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::No => {
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::Ignored => {}
    }
}

/// Confirm handler for `K` on a host-divider row in the containers
/// overview. Iterates every running container of the host and queues
/// a Restart, regardless of compose project. Mirrors the stack-restart
/// drain. one request per tick keeps remote SSH sane.
pub(super) fn handle_host_restart_all_key(app: &mut App, key: KeyEvent) {
    let Screen::ConfirmHostRestartAll { alias, members } = &app.screen else {
        return;
    };
    let alias = alias.clone();
    let members = members.clone();
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            for m in members {
                queue_container_action(
                    app,
                    alias.clone(),
                    m.container_id,
                    m.container_name,
                    crate::containers::ContainerAction::Restart,
                );
            }
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::No => {
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::Ignored => {}
    }
}

/// Confirm handler for `S` on a host-divider row. Stops every running
/// container on the host. Same drain shape as host-restart.
pub(super) fn handle_host_stop_all_key(app: &mut App, key: KeyEvent) {
    let Screen::ConfirmHostStopAll { alias, members } = &app.screen else {
        return;
    };
    let alias = alias.clone();
    let members = members.clone();
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            for m in members {
                queue_container_action(
                    app,
                    alias.clone(),
                    m.container_id,
                    m.container_name,
                    crate::containers::ContainerAction::Stop,
                );
            }
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::No => {
            app.set_screen(Screen::HostList);
        }
        ConfirmAction::Ignored => {}
    }
}

fn queue_container_action(
    app: &mut App,
    alias: String,
    container_id: String,
    container_name: String,
    action: crate::containers::ContainerAction,
) {
    let Some(entry) = app.container_state.cache_entry(&alias) else {
        log::debug!(
            "[purple] container_action: queue aborted, no cache for alias={}",
            alias
        );
        return;
    };
    let runtime = entry.runtime;
    let askpass = app
        .hosts_state
        .list()
        .iter()
        .find(|h| h.alias == alias)
        .and_then(|h| h.askpass.clone());
    log::info!(
        "[purple] container_action queued: alias={} id={} action={:?}",
        alias,
        container_id,
        action
    );
    app.container_state
        .queue_action(crate::app::ContainerActionRequest {
            alias,
            askpass,
            runtime,
            container_id,
            container_name,
            action,
        });
}

/// Confirm for the `p` push action from the Keys tab. Stakes test:
/// pushing modifies remote `authorized_keys`, so the footer uses
/// action verbs (`push` / `keep`) and we only accept y/n/Esc.
pub(super) fn handle_key_push_key(
    app: &mut App,
    key: KeyEvent,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    match route_confirm_key(key) {
        ConfirmAction::Yes => {
            let key_index = match &app.screen {
                Screen::ConfirmKeyPush { key_index } => *key_index,
                _ => return,
            };
            let aliases = std::mem::take(&mut app.keys.push_mut().committed);
            app.set_screen(Screen::HostList);
            start_key_push(app, key_index, aliases, events_tx);
        }
        ConfirmAction::No => {
            // Return to the picker with the selection still intact so the
            // user can refine it.
            let key_index = match &app.screen {
                Screen::ConfirmKeyPush { key_index } => *key_index,
                _ => return,
            };
            app.keys.push_mut().committed.clear();
            app.set_screen(Screen::KeyPushPicker { key_index });
        }
        ConfirmAction::Ignored => {}
    }
}

/// Spawn the background push worker. Reads the pubkey from disk on the
/// main thread (cheap) so we surface an early error toast before
/// committing to the run. On read failure we abort and stay on
/// HostList. Refuses to start a second push while a first is still in
/// flight (`expected_count > 0`); the user must press Esc to cancel
/// before triggering another run.
fn start_key_push(
    app: &mut App,
    key_index: usize,
    aliases: Vec<String>,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    // Refuse second push while a previous run still has live state OR a
    // worker handle that has not been observed to finish. Belt-and-braces:
    // expected_count protects the in-flight branch, worker.is_finished()
    // protects the post-cancel branch where the worker is still draining
    // but its results no longer count toward any expected total.
    if app.keys.push().expected_count > 0
        || app
            .keys
            .push()
            .worker
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    {
        log::debug!(
            "[purple] key_push: rejected second push, run already in progress ({} of {})",
            app.keys.push().results.len(),
            app.keys.push().expected_count
        );
        app.notify_warning(crate::messages::KEY_PUSH_ALREADY_IN_PROGRESS);
        return;
    }
    if aliases.is_empty() {
        log::debug!("[purple] key_push: rejected, no aliases committed");
        app.notify_error(crate::messages::KEY_PUSH_NO_HOSTS_SELECTED);
        return;
    }
    let Some(key_info) = app.keys.list().get(key_index).cloned() else {
        return;
    };
    if key_info.is_certificate {
        app.notify_error(crate::messages::KEY_PUSH_CERT_NOT_PUSHABLE);
        return;
    }
    let pub_path = crate::key_push::pubkey_path_for(&key_info.display_path);
    let raw = match crate::key_push::read_pubkey_file(&pub_path) {
        Ok(s) => s,
        Err(crate::key_push::PubkeyValidationError::TooLarge(n)) => {
            log::warn!(
                "[purple] key_push: pubkey too large path={} bytes={}",
                pub_path.display(),
                n
            );
            app.notify_error(crate::messages::key_push_pubkey_too_large(
                &key_info.name,
                n,
            ));
            return;
        }
        Err(crate::key_push::PubkeyValidationError::NotARegularFile) => {
            log::warn!(
                "[purple] key_push: pubkey not a regular file path={}",
                pub_path.display()
            );
            app.notify_error(crate::messages::key_push_pubkey_not_regular(&key_info.name));
            return;
        }
        Err(_) => {
            // Other validation variants are unreachable here (read_pubkey_file
            // only returns TooLarge / NotARegularFile / IO collapsed into
            // NotARegularFile). Defensive fallthrough.
            app.notify_error(crate::messages::key_push_no_pubkey(&key_info.name));
            return;
        }
    };
    let pubkey = match crate::key_push::validate_pubkey(&raw) {
        Ok(s) => s,
        Err(err) => {
            let detail = match &err {
                crate::key_push::PubkeyValidationError::Empty => "file is empty",
                crate::key_push::PubkeyValidationError::MultiLine => {
                    "must be a single line; multi-line input is rejected"
                }
                crate::key_push::PubkeyValidationError::UnsupportedType(_) => {
                    "key algorithm not allowed for static push"
                }
                crate::key_push::PubkeyValidationError::MalformedBase64 => {
                    "base64 key body did not parse"
                }
                _ => "unexpected format",
            };
            log::warn!(
                "[purple] key_push: invalid pubkey path={} err={:?}",
                pub_path.display(),
                err
            );
            app.notify_error(crate::messages::key_push_invalid_pubkey(
                &key_info.name,
                detail,
            ));
            return;
        }
    };

    // Reset accumulators and start a new run.
    let (run_id, cancel) = app.keys.push_mut().start_run(aliases.len());

    app.notify_progress(crate::messages::key_push_in_progress(
        &key_info.name,
        aliases.len(),
    ));

    let config_path = app.hosts_state.ssh_config().path.clone();
    let tx = events_tx.clone();
    let pubkey_payload = pubkey;
    let handle = std::thread::Builder::new()
        .name("key-push".into())
        .spawn(move || {
            for alias in aliases {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let outcome =
                    crate::key_push::push_to_host(&pubkey_payload, &alias, &config_path, &cancel);
                let _ = tx.send(AppEvent::KeyPushResult {
                    run_id,
                    result: crate::key_push::KeyPushResult { alias, outcome },
                });
            }
        });
    match handle {
        Ok(h) => {
            app.keys.push_mut().worker = Some(h);
        }
        Err(e) => {
            log::error!("[purple] key_push: failed to spawn worker: {}", e);
            // Drop the progress toast through the status-center invariant
            // so the user does not see "Pushing..." stuck under the
            // failure message.
            app.status_center.clear_sticky_status();
            app.notify_error(crate::messages::key_push_thread_spawn_failed());
            app.keys.push_mut().clear_inflight_state();
        }
    }
}

#[cfg(test)]
mod key_push_confirm_tests {
    //! Coverage for the gate functions wrapping the push-worker spawn.
    //! Every test exercises a guard path (already-running, missing pubkey,
    //! certificate key, empty selection, return-to-picker) and asserts the
    //! observable state. The happy-spawn path is intentionally not unit
    //! tested here because it forks an ssh subprocess; that path is
    //! covered by the event-loop tests against the run-completion flow.
    use super::*;
    use crate::ssh_config::model::SshConfigFile;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn make_app() -> (App, std::path::PathBuf) {
        let scratch = tempfile::tempdir().expect("tempdir").keep();
        crate::preferences::set_path_override(scratch.join("preferences"));
        crate::containers::set_path_override(scratch.join("container_cache.jsonl"));
        let config = SshConfigFile {
            elements: SshConfigFile::parse_content("Host h1\n  HostName 1.1.1.1\n"),
            path: scratch.join("test_config"),
            crlf: false,
            bom: false,
        };
        let mut app = App::new(config);
        // Seed a non-cert key whose .pub file lives in the scratch dir so
        // `read_pubkey_file` succeeds via the override path.
        let pub_path = scratch.join("id_test.pub");
        std::fs::write(
            &pub_path,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBnSCk/2pwG7QHQHIvF2UxYZsMP1qJ4XbJjT7mxBSBb1 test@host\n",
        )
        .unwrap();
        app.keys.list_mut().push(crate::ssh_keys::SshKeyInfo {
            name: "id_test".into(),
            display_path: pub_path.with_extension("").to_string_lossy().into_owned(),
            key_type: "ED25519".into(),
            bits: "256".into(),
            fingerprint: String::new(),
            comment: "test@host".into(),
            linked_hosts: vec![],
            bishop_art: String::new(),
            strength_score: 95,
            encrypted: false,
            agent_loaded: false,
            is_certificate: false,
            mtime_ts: None,
        });
        (app, scratch)
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn n_returns_to_picker_with_key_index_preserved() {
        let (mut app, _scratch) = make_app();
        app.keys.push_mut().committed = vec!["h1".into()];
        app.screen = Screen::ConfirmKeyPush { key_index: 0 };
        let (tx, _rx) = mpsc::channel();
        handle_key_push_key(&mut app, k(KeyCode::Char('n')), &tx);
        match app.screen {
            Screen::KeyPushPicker { key_index } => assert_eq!(key_index, 0),
            ref other => panic!("expected KeyPushPicker, got {:?}", other),
        }
        assert!(
            app.keys.push().committed.is_empty(),
            "n should drop the frozen selection"
        );
    }

    #[test]
    fn esc_routes_through_route_confirm_key_and_returns_to_picker() {
        let (mut app, _scratch) = make_app();
        app.keys.push_mut().committed = vec!["h1".into()];
        app.screen = Screen::ConfirmKeyPush { key_index: 0 };
        let (tx, _rx) = mpsc::channel();
        handle_key_push_key(&mut app, k(KeyCode::Esc), &tx);
        assert!(matches!(app.screen, Screen::KeyPushPicker { .. }));
    }

    #[test]
    fn start_rejects_when_a_previous_run_is_still_in_flight() {
        let (mut app, _scratch) = make_app();
        app.keys.push_mut().expected_count = 2;
        app.keys
            .push_mut()
            .results
            .push(crate::key_push::KeyPushResult {
                alias: "h1".into(),
                outcome: crate::key_push::KeyPushOutcome::Appended,
            });
        let (tx, _rx) = mpsc::channel();
        start_key_push(&mut app, 0, vec!["h1".into()], &tx);
        assert_eq!(
            app.keys.push().expected_count,
            2,
            "guard must not reset in-flight state"
        );
        let toast = app.status_center.toast().expect("toast set");
        assert!(
            toast.text.contains("already running"),
            "expected 'already running' warning, got: {}",
            toast.text
        );
    }

    #[test]
    fn start_rejects_empty_aliases_and_does_not_spawn_worker() {
        let (mut app, _scratch) = make_app();
        let (tx, _rx) = mpsc::channel();
        start_key_push(&mut app, 0, Vec::new(), &tx);
        assert_eq!(app.keys.push().expected_count, 0);
        assert!(app.keys.push().worker.is_none());
        let toast = app.status_center.toast().expect("toast set");
        assert!(toast.is_error());
    }

    #[test]
    fn start_rejects_certificate_key() {
        let (mut app, _scratch) = make_app();
        app.keys.list_mut()[0].is_certificate = true;
        let (tx, _rx) = mpsc::channel();
        start_key_push(&mut app, 0, vec!["h1".into()], &tx);
        assert_eq!(app.keys.push().expected_count, 0);
        assert!(app.keys.push().worker.is_none());
        let toast = app.status_center.toast().expect("toast set");
        assert!(toast.is_error());
        assert!(toast.text.contains("Certificates"));
    }

    #[test]
    fn start_rejects_missing_pubkey_file() {
        let (mut app, _scratch) = make_app();
        app.keys.list_mut()[0].display_path = "/tmp/purple-this-file-does-not-exist".into();
        let (tx, _rx) = mpsc::channel();
        start_key_push(&mut app, 0, vec!["h1".into()], &tx);
        assert_eq!(app.keys.push().expected_count, 0);
        let toast = app.status_center.toast().expect("toast set");
        assert!(toast.is_error());
    }

    #[test]
    fn start_rejects_invalid_pubkey_content() {
        let (mut app, scratch) = make_app();
        // Multi-line pubkey: the canonical command-injection PoC. Must be
        // rejected without spawning the worker.
        let pub_path = scratch.join("id_bad.pub");
        std::fs::write(
            &pub_path,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBnSCk/2pwG7QHQHIvF2UxYZsMP1qJ4XbJjT7mxBSBb1 real\ncommand=\"evil\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBnSCk/2pwG7QHQHIvF2UxYZsMP1qJ4XbJjT7mxBSBb2 hack\n",
        )
        .unwrap();
        app.keys.list_mut()[0].display_path =
            pub_path.with_extension("").to_string_lossy().into_owned();
        app.keys.list_mut()[0].name = "id_bad".into();
        let (tx, _rx) = mpsc::channel();
        start_key_push(&mut app, 0, vec!["h1".into()], &tx);
        assert_eq!(app.keys.push().expected_count, 0);
        assert!(app.keys.push().worker.is_none());
        let toast = app.status_center.toast().expect("toast set");
        assert!(toast.is_error());
        assert!(toast.text.contains("validation"));
    }
}
