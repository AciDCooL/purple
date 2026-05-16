use std::sync::mpsc;
use std::time::Instant;

use crate::app::{self, App, Screen};
use crate::containers;
use crate::event::AppEvent;
use crate::file_browser;
use crate::providers;
use crate::ssh_config;
use crate::tui;
use crate::vault_ssh;

/// Handle `AppEvent::Tick` and `None` (timeout): spinner animation, ping TTL
/// expiry, config change detection and tunnel exit polling.
pub(crate) fn handle_tick(
    app: &mut App,
    anim: &mut crate::animation::AnimationState,
    vault_signing: bool,
    last_config_check: &mut Instant,
) {
    app.tick_status();
    app.tick_toast();
    let provider_syncing = !app.providers.syncing.is_empty();
    // Tick the spinner whenever something needs animation. Reachable hosts
    // drive the breathing online-dot pulse via `online_dot_pulsing(tick)`,
    // so they share the same monotonically-incrementing tick counter as
    // the spinner. saves a parallel tick driver. Active tunnels also
    // tick the spinner so the live chart wave has a continuous phase.
    let tunnels_animating =
        matches!(app.top_page, crate::app::TopPage::Tunnels) && !app.tunnels.active.is_empty();
    if anim.has_checking_hosts(app)
        || vault_signing
        || provider_syncing
        || anim.has_reachable_hosts(app)
        || tunnels_animating
    {
        anim.tick_spinner();
    }
    // Update the spinner character in the signing status text
    // so the spinner animates between VaultSignProgress events.
    if vault_signing {
        if let Some(ref mut status) = app.status_center.status {
            if status.sticky && !status.is_error() {
                let frame = crate::animation::SPINNER_FRAMES
                    [anim.spinner_tick as usize % crate::animation::SPINNER_FRAMES.len()];
                if let Some(updated) = crate::replace_spinner_frame(&status.text, frame) {
                    status.text = updated;
                }
            }
        }
    }
    // Animate the provider-sync footer: rotate the leading spinner frame on
    // each tick while a sync is in flight. The status is non-sticky (Info),
    // so we match by spinner-prefix instead of the sticky flag like
    // vault_signing does.
    if provider_syncing {
        if let Some(ref mut status) = app.status_center.status {
            let frame = crate::animation::SPINNER_FRAMES
                [anim.spinner_tick as usize % crate::animation::SPINNER_FRAMES.len()];
            if let Some(updated) = crate::replace_spinner_frame(&status.text, frame) {
                status.text = updated;
                // Refresh created_at so the Info-class footer message does not
                // expire by length-proportional timeout in the gap between
                // sync_complete events. The message stays alive as long as at
                // least one provider is still syncing.
                status.created_at = std::time::Instant::now();
            }
        }
    }
    // Throttle config file stat() to every 4 seconds
    if last_config_check.elapsed() >= std::time::Duration::from_secs(4) {
        app.check_config_changed();
        app.check_keys_changed();
        *last_config_check = Instant::now();
    }
    // Poll active tunnels for exit
    let exited = app.poll_tunnels();
    for (_alias, msg, is_error) in exited {
        if is_error {
            app.notify_background_error(msg);
        } else {
            app.notify_background(msg);
        }
    }
}

/// Handle `AppEvent::PingResult`.
pub(crate) fn handle_ping_result(
    app: &mut App,
    alias: String,
    rtt_ms: Option<u32>,
    generation: u64,
) {
    if generation == app.ping.generation {
        let status = app::classify_ping(rtt_ms, app.ping.slow_threshold_ms);
        let now = Instant::now();
        log::debug!(
            "ping-result: {} → {:?} (rtt={:?}ms, gen={})",
            alias,
            status,
            rtt_ms,
            generation
        );
        app.ping.status.insert(alias.clone(), status.clone());
        app.ping.last_checked.insert(alias.clone(), now);
        // Propagate bastion status to all ProxyJump dependents.
        app::propagate_ping_to_dependents(
            &app.hosts_state.list,
            &mut app.ping.status,
            &alias,
            &status,
        );
        let mut propagated = 0usize;
        for h in &app.hosts_state.list {
            if h.proxy_jump == alias {
                app.ping.last_checked.insert(h.alias.clone(), now);
                propagated += 1;
            }
        }
        if propagated > 0 {
            log::debug!(
                "ping-result: propagated bastion {} status+timestamp to {} dependent(s)",
                alias,
                propagated
            );
        }
        // Update live filter/sort as results arrive
        if app.ping.filter_down_only {
            app.apply_filter();
        }
        if app.hosts_state.sort_mode == app::SortMode::Status {
            app.apply_sort();
        }
        // Update "last checked" timestamp when all pings are done
        if !app.ping.status.is_empty()
            && app
                .ping
                .status
                .values()
                .all(|s| !matches!(s, app::PingStatus::Checking))
        {
            app.ping.checked_at = Some(Instant::now());
        }
    }
}

/// Handle `AppEvent::SyncProgress`.
pub(crate) fn handle_sync_progress(app: &mut App, provider: String, message: String) {
    // Only show per-provider progress while that provider is still syncing.
    // Late progress events (arriving after SyncComplete) are discarded.
    if app.providers.syncing.contains_key(&provider) && app.providers.sync_done.is_empty() {
        let name = providers::provider_display_name(&provider);
        // Prefix with SPINNER_FRAMES[0] so handle_tick keeps the spinner
        // animating while the granular progress message is on screen.
        let spinner = crate::animation::SPINNER_FRAMES[0];
        app.notify_background(crate::messages::provider_progress(spinner, name, &message));
    }
}

/// Handle `AppEvent::SyncComplete`. Returns the new `last_config_check` value.
pub(crate) fn handle_sync_complete(
    app: &mut App,
    provider: String,
    hosts: Vec<crate::providers::ProviderHost>,
    last_config_check: &mut Instant,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let display_name = providers::provider_display_name(&provider);
    let before_aliases = app.snapshot_alias_set();
    let (_msg, is_err, total, added, updated, stale) =
        app.apply_sync_result(&provider, hosts, false);
    if is_err {
        app.providers.sync_history.insert(
            provider.clone(),
            app::SyncRecord {
                timestamp: now,
                message: format!("{}: sync failed", display_name),
                is_error: true,
            },
        );
        app.providers.sync_had_errors = true;
    } else {
        let label = if total == 1 { "server" } else { "servers" };
        let message = format!(
            "{} {}{}",
            total,
            label,
            crate::format_sync_diff(added, updated, stale)
        );
        app.providers.sync_history.insert(
            provider.clone(),
            app::SyncRecord {
                timestamp: now,
                message,
                is_error: false,
            },
        );
        app.providers.batch_added += added;
        app.providers.batch_updated += updated;
        app.providers.batch_stale += stale;
    }
    app.providers.syncing.remove(&provider);
    app.providers.sync_done.push(display_name.to_string());
    crate::set_sync_summary(app);
    // Reset config check timer so auto-reload doesn't immediately
    // detect our own write as an "external" change
    *last_config_check = Instant::now();
    app.queue_new_aliases_since(&before_aliases);
}

/// Handle `AppEvent::SyncPartial`.
pub(crate) fn handle_sync_partial(
    app: &mut App,
    provider: String,
    hosts: Vec<crate::providers::ProviderHost>,
    failures: usize,
    total: usize,
    last_config_check: &mut Instant,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let display_name = providers::provider_display_name(provider.as_str());
    let before_aliases = app.snapshot_alias_set();
    let (msg, is_err, synced, added, updated, stale) =
        app.apply_sync_result(&provider, hosts, true);
    if is_err {
        app.providers.sync_history.insert(
            provider.clone(),
            app::SyncRecord {
                timestamp: now,
                message: msg,
                is_error: true,
            },
        );
    } else {
        let label = if synced == 1 { "server" } else { "servers" };
        app.providers.sync_history.insert(
            provider.clone(),
            app::SyncRecord {
                timestamp: now,
                message: format!(
                    "{} {}{} ({} of {} failed)",
                    synced,
                    label,
                    crate::format_sync_diff(added, updated, stale),
                    failures,
                    total
                ),
                is_error: true,
            },
        );
        // Partial successes still contributed real changes to the SSH config;
        // surface them in the batch aggregate so the footer reflects reality.
        app.providers.batch_added += added;
        app.providers.batch_updated += updated;
        app.providers.batch_stale += stale;
    }
    app.providers.sync_had_errors = true;
    app.providers.syncing.remove(&provider);
    app.providers.sync_done.push(display_name.to_string());
    crate::set_sync_summary(app);
    *last_config_check = Instant::now();
    app.queue_new_aliases_since(&before_aliases);
}

/// Handle `AppEvent::SyncError`.
pub(crate) fn handle_sync_error(
    app: &mut App,
    provider: String,
    message: String,
    last_config_check: &mut Instant,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let display_name = providers::provider_display_name(provider.as_str());
    app.providers.sync_history.insert(
        provider.clone(),
        app::SyncRecord {
            timestamp: now,
            message: message.clone(),
            is_error: true,
        },
    );
    app.providers.sync_had_errors = true;
    app.providers.syncing.remove(&provider);
    app.providers.sync_done.push(display_name.to_string());
    crate::set_sync_summary(app);
    *last_config_check = Instant::now();
}

/// Handle `AppEvent::UpdateAvailable`.
pub(crate) fn handle_update_available(app: &mut App, version: String, headline: Option<String>) {
    app.update.available = Some(version);
    app.update.headline = headline;
}

/// Handle `AppEvent::FileBrowserListing`.
pub(crate) fn handle_file_browser_listing(
    app: &mut App,
    alias: String,
    path: String,
    entries: Result<Vec<crate::file_browser::FileEntry>, String>,
    terminal: &mut tui::Tui,
) {
    let mut record_connection = false;
    if let Some(ref mut fb) = app.file_browser {
        if fb.alias == alias {
            fb.remote_loading = false;
            match entries {
                Ok(listing) => {
                    if !fb.connection_recorded {
                        fb.connection_recorded = true;
                        record_connection = true;
                    }
                    if fb.remote_path.is_empty() || fb.remote_path != path {
                        fb.remote_path = path;
                    }
                    fb.remote_entries = listing;
                    fb.remote_error = None;
                    fb.remote_list_state = ratatui::widgets::ListState::default();
                    fb.remote_list_state.select(Some(0));
                }
                Err(msg) => {
                    if fb.remote_path.is_empty() {
                        fb.remote_path = path;
                    }
                    fb.remote_error = Some(msg);
                    fb.remote_entries.clear();
                }
            }
        }
    }
    if record_connection {
        app.history.record(&alias);
        app.record_key_use(&alias, crate::key_activity::now_secs());
        app.apply_sort();
    }
    // Force full redraw: ssh may have written to /dev/tty
    terminal.force_redraw();
}

/// Handle `AppEvent::ScpComplete`.
pub(crate) fn handle_scp_complete(
    app: &mut App,
    alias: String,
    success: bool,
    message: String,
    events_tx: &mpsc::Sender<AppEvent>,
    terminal: &mut tui::Tui,
) {
    // Track whether we need to spawn a remote refresh (can't do it inside the fb borrow
    // because spawn_remote_listing needs values from app too)
    let mut refresh_remote: Option<(
        String,
        Option<String>,
        String,
        bool,
        file_browser::BrowserSort,
    )> = None;
    let matched = if let Some(ref mut fb) = app.file_browser {
        if fb.alias == alias {
            fb.transferring = None;
            if success {
                app.history.record(&alias);
                // Field-disjoint helper: fb already holds &mut app.file_browser,
                // so the `App::record_key_use` method would not borrow-check.
                crate::key_activity::record_and_flush(
                    &mut app.keys.activity,
                    &alias,
                    crate::key_activity::now_secs(),
                );
                // history_width depends on formatted timestamps; rebuild next render
                app.hosts_state.render_cache.invalidate();
                fb.local_selected.clear();
                fb.remote_selected.clear();
                match file_browser::list_local(&fb.local_path, fb.show_hidden, fb.sort) {
                    Ok(entries) => {
                        fb.local_entries = entries;
                        fb.local_error = None;
                    }
                    Err(e) => {
                        fb.local_entries = Vec::new();
                        fb.local_error = Some(e.to_string());
                    }
                }
                fb.local_list_state.select(Some(0));
                if !fb.remote_path.is_empty() {
                    fb.remote_loading = true;
                    fb.remote_entries.clear();
                    fb.remote_error = None;
                    fb.remote_list_state = ratatui::widgets::ListState::default();
                    refresh_remote = Some((
                        fb.alias.clone(),
                        fb.askpass.clone(),
                        fb.remote_path.clone(),
                        fb.show_hidden,
                        fb.sort,
                    ));
                }
            } else {
                fb.transfer_error = Some(message.clone());
            }
            true
        } else {
            false
        }
    } else {
        false
    };
    if matched && success {
        app.notify_background(crate::messages::TRANSFER_COMPLETE);
        // Rebuild display list so frecency sort and LAST column reflect the transfer
        app.apply_sort();
    }
    if let Some((fb_alias, askpass_fb, path, show_hidden, sort)) = refresh_remote {
        let has_tunnel = app.tunnels.active.contains_key(&fb_alias);
        let ctx = crate::ssh_context::OwnedSshContext {
            alias: fb_alias,
            config_path: app.reload.config_path.clone(),
            askpass: askpass_fb,
            bw_session: app.bw_session.clone(),
            has_tunnel,
        };
        let tx = events_tx.clone();
        file_browser::spawn_remote_listing(ctx, path, show_hidden, sort, move |a, p, e| {
            let _ = tx.send(AppEvent::FileBrowserListing {
                alias: a,
                path: p,
                entries: e,
            });
        });
    }
    crate::askpass::cleanup_marker(&alias);
    // Force full redraw: ssh may have written to /dev/tty
    terminal.force_redraw();
}

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
    if let Some(ref mut state) = app.snippets.output {
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
    if let Some(ref mut state) = app.snippets.output {
        if state.run_id == run_id {
            state.completed = completed;
            state.total = total;
        }
    }
}

/// Handle `AppEvent::SnippetAllDone`.
pub(crate) fn handle_snippet_all_done(app: &mut App, run_id: u64) {
    if let Some(ref mut state) = app.snippets.output {
        if state.run_id == run_id {
            state.all_done = true;
        }
    }
}

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
    app.keys.push.results.clear();
    app.keys.push.expected_count = 0;
    app.keys.push.selected.clear();
    app.keys.push.cancel = None;
    if let Some(handle) = app.keys.push.worker.take() {
        let _ = handle.join();
    }
}

/// Handle `AppEvent::ContainerListing`.
pub(crate) fn handle_container_listing(
    app: &mut App,
    alias: String,
    result: Result<containers::ContainerListing, containers::ContainerError>,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    // Race guard: a `docker ps` thread may return after the user
    // deleted the host (or `reload_hosts` pruned the cache via an
    // external config edit). Without this guard the cache would be
    // re-populated with an orphan and the next save would write it
    // back to disk. Drop the result silently in that case but still
    // tick the batch driver so an `R`-batch can complete cleanly.
    if !app.hosts_state.list.iter().any(|h| h.alias == alias) {
        log::debug!(
            "[purple] container_listing dropped: alias={} no longer in config",
            alias
        );
        crate::askpass::cleanup_marker(&alias);
        app.containers_overview.auto_list_in_flight.remove(&alias);
        drive_refresh_batch(app, &alias, events_tx);
        return;
    }
    // Always update cache, even if overlay is closed
    match &result {
        Ok(listing) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            app.container_cache.insert(
                alias.clone(),
                containers::ContainerCacheEntry {
                    timestamp: now,
                    runtime: listing.runtime,
                    engine_version: listing.engine_version.clone(),
                    containers: listing.containers.clone(),
                },
            );
            containers::save_container_cache(&app.container_cache);
            // Prefetch `docker inspect` for every container in this
            // listing so HEALTH and the inspect-sourced detail cards
            // populate without waiting for the user to scroll over
            // each row. Dedup via in_flight set + TTL.
            crate::handler::containers_overview::prefetch_inspect_for_listing(
                app,
                &alias,
                listing.runtime,
                &listing.containers,
                events_tx,
            );
        }
        Err(e) => {
            // Preserve runtime even on error
            if let Some(rt) = e.runtime {
                if let Some(entry) = app.container_cache.get_mut(&alias) {
                    entry.runtime = rt;
                }
            }
        }
    }
    // Update overlay state if open
    if let Some(ref mut state) = app.container_state {
        if state.alias == alias {
            match result {
                Ok(listing) => {
                    state.runtime = Some(listing.runtime);
                    state.containers = listing.containers;
                    state.loading = false;
                    state.error = None;
                    if let Some(sel) = state.list_state.selected() {
                        if sel >= state.containers.len() && !state.containers.is_empty() {
                            state.list_state.select(Some(0));
                        }
                    } else if !state.containers.is_empty() {
                        state.list_state.select(Some(0));
                    }
                }
                Err(e) => {
                    if let Some(rt) = e.runtime {
                        state.runtime = Some(rt);
                    }
                    state.loading = false;
                    state.error = Some(e.message);
                }
            }
        }
    }
    crate::askpass::cleanup_marker(&alias);
    app.containers_overview.auto_list_in_flight.remove(&alias);

    // Drive the `R` batch refresh: a listing whose alias is in the
    // batch's in_flight set decrements the counter and pops the next
    // queued host. Non-batch listings (parallel `C`, `a`-add,
    // action-complete refresh) drop through unchanged.
    drive_refresh_batch(app, &alias, events_tx);
}

/// Drive the `R` batch refresh on each `ContainerListing` arrival.
///
/// Only listings whose alias is in `batch.in_flight_aliases` mutate
/// the batch counters. Listings from concurrent non-batch triggers
/// (host-list `C`, action-complete refresh, `a`-add) drop through .
/// without that guard the counter would corrupt and the batch could
/// either complete prematurely or hang.
pub(crate) fn drive_refresh_batch(app: &mut App, alias: &str, events_tx: &mpsc::Sender<AppEvent>) {
    let Some(batch) = app.containers_overview.refresh_batch.as_mut() else {
        return;
    };
    if !batch.in_flight_aliases.remove(alias) {
        // Listing for an alias that is not part of this batch.
        log::debug!(
            "[purple] refresh_batch: alias={} not in batch in_flight, ignoring",
            alias
        );
        return;
    }
    batch.in_flight = batch.in_flight.saturating_sub(1);
    batch.completed += 1;

    let next = batch.queue.pop_front();
    let total = batch.total;
    let completed = batch.completed;
    let queue_remaining = batch.queue.len();

    let spawned = next.is_some();
    if let Some(item) = next {
        batch.in_flight += 1;
        batch.in_flight_aliases.insert(item.alias.clone());
        let config_path = app.reload.config_path.clone();
        let bw_session = app.bw_session.clone();
        let ctx = crate::ssh_context::OwnedSshContext {
            alias: item.alias,
            config_path,
            askpass: item.askpass,
            bw_session,
            has_tunnel: item.has_tunnel,
        };
        let tx = events_tx.clone();
        containers::spawn_container_listing(ctx, item.cached_runtime, move |a, r| {
            let _ = tx.send(AppEvent::ContainerListing {
                alias: a,
                result: r,
            });
        });
    }

    // Re-borrow after the mutable spawn block above so the final
    // counters are post-pop-and-respawn.
    let still_in_flight = app
        .containers_overview
        .refresh_batch
        .as_ref()
        .map(|b| b.in_flight)
        .unwrap_or(0);

    log::debug!(
        "[purple] refresh_batch: alias={} done={}/{} in_flight={} queue={} spawned_next={}",
        alias,
        completed,
        total,
        still_in_flight,
        queue_remaining,
        spawned
    );

    // Update progress / completion notification.
    if queue_remaining == 0 && still_in_flight == 0 {
        app.containers_overview.refresh_batch = None;
        // Clear the sticky progress footer set by notify_progress so the
        // success toast is the only thing the user sees after the batch.
        app.status_center.status = None;
        app.notify(crate::messages::container_refresh_complete(total));
    } else {
        app.notify_progress(crate::messages::container_refresh_progress(
            completed, total,
        ));
    }
}

/// Handle `AppEvent::ContainerInspectComplete`. Stores the result (Ok or
/// Err) in the per-overview cache keyed by container ID and clears the
/// in-flight marker. The result itself is held even on error so the
/// detail panel can render the message instead of spinning forever.
pub(crate) fn handle_container_inspect_complete(
    app: &mut App,
    alias: String,
    container_id: String,
    result: Result<containers::ContainerInspect, String>,
) {
    // Race guard mirrors handle_container_listing: drop the result
    // when the host (and therefore its containers) is gone.
    if !app.hosts_state.list.iter().any(|h| h.alias == alias) {
        log::debug!(
            "[purple] container_inspect_complete dropped: alias={} no longer in config",
            alias
        );
        app.containers_overview
            .inspect_cache
            .in_flight
            .remove(&container_id);
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    match &result {
        Ok(_) => log::debug!(
            "[purple] container_inspect_complete: alias={} id={} ok=true",
            alias,
            container_id,
        ),
        Err(msg) => log::warn!(
            "[external] container inspect failed: alias={} id={}: {}",
            alias,
            container_id,
            msg,
        ),
    }
    app.containers_overview.inspect_cache.entries.insert(
        container_id.clone(),
        crate::app::InspectCacheEntry {
            timestamp: now,
            result,
        },
    );
    app.containers_overview
        .inspect_cache
        .in_flight
        .remove(&container_id);
}

/// Handle `AppEvent::ContainerLogsTailComplete`. Stores the result in
/// the per-overview logs cache keyed by container ID and clears the
/// in-flight marker. The result is held even on error so the LOGS card
/// can render the message in place of spinning.
pub(crate) fn handle_container_logs_tail_complete(
    app: &mut App,
    alias: String,
    container_id: String,
    result: Result<Vec<String>, String>,
) {
    if !app.hosts_state.list.iter().any(|h| h.alias == alias) {
        log::debug!(
            "[purple] container_logs_tail_complete dropped: alias={} no longer in config",
            alias
        );
        app.containers_overview
            .logs_cache
            .in_flight
            .remove(&container_id);
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    match &result {
        Ok(_) => log::debug!(
            "[purple] container_logs_tail_complete: alias={} id={} ok=true",
            alias,
            container_id,
        ),
        Err(msg) => log::warn!(
            "[external] container logs tail failed: alias={} id={}: {}",
            alias,
            container_id,
            msg,
        ),
    }
    app.containers_overview.logs_cache.entries.insert(
        container_id.clone(),
        crate::app::LogsCacheEntry {
            timestamp: now,
            result,
        },
    );
    app.containers_overview
        .logs_cache
        .in_flight
        .remove(&container_id);
}

/// Handle `AppEvent::ContainerLogsComplete`. When the user is still
/// on the matching `Screen::ContainerLogs` overlay, populate the body
/// (or error). When the screen has changed (Esc, Tab away), drop the
/// payload silently. The user opted out before the SSH call returned.
pub(crate) fn handle_container_logs_complete(
    app: &mut App,
    alias: String,
    container_id: String,
    container_name: String,
    result: Result<Vec<String>, String>,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Screen::ContainerLogs {
        alias: scr_alias,
        container_id: scr_id,
        body,
        error,
        fetched_at,
        scroll,
        last_render_height,
        search,
        ..
    } = &mut app.screen
    {
        if scr_alias == &alias && scr_id == &container_id {
            match result {
                Ok(lines) => {
                    log::debug!(
                        "[purple] container_logs_complete: {} lines for alias={} id={}",
                        lines.len(),
                        alias,
                        container_id
                    );
                    *body = lines;
                    *error = None;
                    *fetched_at = now;
                    // Tail-anchor: align the bottom of the body with
                    // the bottom of the viewport so the latest line
                    // sits at the last visible row, with N preceding
                    // lines filling the gap. The renderer wrote
                    // `last_render_height` while painting the loading
                    // placeholder one frame earlier.
                    *scroll = crate::handler::container_logs::tail_scroll(
                        body.len(),
                        *last_render_height,
                    );
                    // Recompute search matches against the refreshed
                    // body so an active `/foo` survives the `r` cycle.
                    // Re-centre the viewport on the current match so
                    // the user lands back on a visible hit.
                    if let Some(s) = search.as_mut() {
                        crate::handler::container_logs::refresh_search(body, s);
                        log::debug!(
                            "[purple] container_logs: search refreshed query={:?} matches={}",
                            s.query,
                            s.matches.len()
                        );
                        crate::handler::container_logs::recenter_on_match(
                            body.len(),
                            *last_render_height,
                            s,
                            scroll,
                        );
                    }
                }
                Err(e) => {
                    log::warn!(
                        "[external] container_logs_complete: alias={} id={} error={}",
                        alias,
                        container_id,
                        e
                    );
                    body.clear();
                    *error = Some(e);
                    *fetched_at = now;
                    *scroll = 0;
                }
            }
            return;
        }
    }
    log::debug!(
        "[purple] container_logs_complete dropped (overlay closed): alias={} id={} name={}",
        alias,
        container_id,
        container_name
    );
}

/// Handle `AppEvent::ContainerActionComplete`.
pub(crate) fn handle_container_action_complete(
    app: &mut App,
    alias: String,
    action: containers::ContainerAction,
    result: Result<(), String>,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    // Check if overlay matches and extract refresh info before notify
    let should_refresh = if let Some(ref mut state) = app.container_state {
        if state.alias == alias {
            state.action_in_progress = None;
            match result {
                Ok(()) => {
                    state.loading = true;
                    Some((state.alias.clone(), state.askpass.clone(), state.runtime))
                }
                Err(e) => {
                    state.error = Some(e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    if let Some((refresh_alias, askpass, cached_runtime)) = should_refresh {
        app.notify(crate::messages::container_action_complete(action.as_str()));
        let has_tunnel = app.tunnels.active.contains_key(&refresh_alias);
        // Mark in-flight so the scroll-driven auto-refresh does not
        // double-spawn for the same alias while this post-action
        // listing is still pending.
        app.containers_overview
            .auto_list_in_flight
            .insert(refresh_alias.clone());
        let ctx = crate::ssh_context::OwnedSshContext {
            alias: refresh_alias,
            config_path: app.reload.config_path.clone(),
            askpass,
            bw_session: app.bw_session.clone(),
            has_tunnel,
        };
        let tx = events_tx.clone();
        containers::spawn_container_listing(ctx, cached_runtime, move |a, r| {
            let _ = tx.send(AppEvent::ContainerListing {
                alias: a,
                result: r,
            });
        });
    }
    crate::askpass::cleanup_marker(&alias);
}

/// Handle `AppEvent::VaultSignResult`.
pub(crate) fn handle_vault_sign_result(
    app: &mut App,
    alias: String,
    existing_cert_file: String,
    success: bool,
    message: String,
) {
    if success {
        // The CertificateFile snapshot is carried in the event so
        // we never re-look up the host (which would be O(n) and
        // racy under concurrent renames).
        let mut host_missing = false;
        if crate::should_write_certificate_file(&existing_cert_file) {
            if let Ok(cert_path) = vault_ssh::cert_path_for(&alias) {
                let updated = app
                    .hosts_state
                    .ssh_config
                    .set_host_certificate_file(&alias, &cert_path.to_string_lossy());
                if !updated {
                    host_missing = true;
                }
            }
        }
        app.refresh_cert_cache(&alias);
        if host_missing {
            app.notify_error(crate::messages::vault_cert_saved_host_gone(&alias));
        } else {
            app.notify(crate::messages::vault_signed(&alias));
        }
    } else {
        app.notify_error(crate::messages::vault_sign_failed(&alias, &message));
    }
}

/// Handle `AppEvent::VaultSignProgress`.
pub(crate) fn handle_vault_sign_progress(
    app: &mut App,
    alias: String,
    done: usize,
    total: usize,
    spinner_tick: u64,
) {
    // Truncate long aliases so the status line fits even on
    // narrow terminals; the full alias is recoverable from the
    // host list.
    const ALIAS_BUDGET: usize = 40;
    let display_alias: String = if alias.chars().count() > ALIAS_BUDGET {
        let cut: String = alias.chars().take(ALIAS_BUDGET - 1).collect();
        format!("{}\u{2026}", cut)
    } else {
        alias.clone()
    };
    let spinner = crate::animation::SPINNER_FRAMES
        [spinner_tick as usize % crate::animation::SPINNER_FRAMES.len()];
    app.notify_progress(crate::messages::vault_signing_progress(
        spinner,
        done,
        total,
        &display_alias,
    ));
}

/// Handle `AppEvent::VaultSignAllDone`. Returns `ControlFlow::Break(())` when
/// the caller should `continue` the event loop (skip the rest of the iteration),
/// or `ControlFlow::Continue(())` for normal processing.
pub(crate) fn handle_vault_sign_all_done(
    app: &mut App,
    signed: u32,
    failed: u32,
    skipped: u32,
    cancelled: bool,
    aborted_message: Option<String>,
    first_error: Option<String>,
) -> std::ops::ControlFlow<()> {
    app.vault.signing_cancel = None;
    // Join the background thread now that it has finished.
    if let Some(handle) = app.vault.sign_thread.take() {
        log::debug!("[purple] vault sign thread: joining");
        let _ = handle.join();
        log::info!(
            "[purple] vault sign thread: joined (signed={} failed={} skipped={} cancelled={})",
            signed,
            failed,
            skipped,
            cancelled
        );
    }
    if let Some(msg) = aborted_message {
        app.notify_sticky_error(msg);
        return std::ops::ControlFlow::Break(()); // caller should `continue`
    }
    if cancelled {
        let msg = crate::messages::vault_signing_cancelled_summary(
            signed,
            failed,
            first_error.as_deref(),
        );
        if failed > 0 {
            app.notify_sticky_error(msg);
        } else {
            app.notify_info(msg);
        }
        return std::ops::ControlFlow::Break(()); // caller should `continue`
    }
    let summary_msg =
        crate::format_vault_sign_summary(signed, failed, skipped, first_error.as_deref());
    if signed > 0 {
        if app.is_form_open() {
            // Defer config write to avoid mtime conflict with open forms
            app.pending_vault_config_write = true;
            if failed > 0 {
                app.notify_sticky_error(summary_msg);
            } else {
                app.notify_info(summary_msg);
            }
        } else if app.external_config_changed() {
            // The on-disk ssh config (or an include) was modified
            // by an external editor while the bulk-sign worker was
            // running. Writing now would overwrite those edits.
            let reapply: Vec<(String, String)> = app
                .hosts_state
                .ssh_config
                .host_entries()
                .into_iter()
                .filter_map(|h| {
                    if h.vault_ssh.is_some()
                        && crate::should_write_certificate_file(&h.certificate_file)
                    {
                        vault_ssh::cert_path_for(&h.alias)
                            .ok()
                            .map(|p| (h.alias.clone(), p.to_string_lossy().into_owned()))
                    } else {
                        None
                    }
                })
                .collect();
            match ssh_config::model::SshConfigFile::parse(&app.reload.config_path) {
                Ok(fresh) => {
                    app.hosts_state.ssh_config = fresh;
                    let mut reapplied = 0usize;
                    for (alias, cert_path) in &reapply {
                        let entry = app
                            .hosts_state
                            .ssh_config
                            .host_entries()
                            .into_iter()
                            .find(|h| &h.alias == alias);
                        if let Some(entry) = entry {
                            if crate::should_write_certificate_file(&entry.certificate_file)
                                && app
                                    .hosts_state
                                    .ssh_config
                                    .set_host_certificate_file(alias, cert_path)
                            {
                                reapplied += 1;
                            }
                        }
                    }
                    if reapplied > 0 {
                        if let Err(e) = app.hosts_state.ssh_config.write() {
                            app.notify_sticky_error(crate::messages::vault_config_reapply_failed(
                                signed as usize,
                                &e,
                            ));
                        } else {
                            app.update_last_modified();
                            app.reload_hosts();
                            if failed > 0 {
                                app.notify_sticky_error(
                                    crate::messages::vault_external_edits_merged(
                                        &summary_msg,
                                        reapplied,
                                    ),
                                );
                            } else {
                                app.notify_info(crate::messages::vault_external_edits_merged(
                                    &summary_msg,
                                    reapplied,
                                ));
                            }
                        }
                    } else {
                        app.reload_hosts();
                        app.notify_sticky_error(crate::messages::vault_external_edits_no_write(
                            &summary_msg,
                        ));
                    }
                }
                Err(e) => {
                    app.notify_sticky_error(crate::messages::vault_reparse_failed(
                        signed as usize,
                        &e,
                    ));
                }
            }
        } else if let Err(e) = app.hosts_state.ssh_config.write() {
            app.notify_sticky_error(crate::messages::vault_config_update_failed(
                signed as usize,
                &e,
            ));
        } else {
            app.update_last_modified();
            app.reload_hosts();
            if failed > 0 {
                app.notify_sticky_error(summary_msg);
            } else {
                app.notify_info(summary_msg);
            }
        }
    } else if failed > 0 {
        app.notify_sticky_error(summary_msg);
    } else {
        app.notify_info(summary_msg);
    }
    std::ops::ControlFlow::Continue(()) // normal flow
}

/// Handle `AppEvent::CertCheckResult`.
pub(crate) fn handle_cert_check_result(
    app: &mut App,
    alias: String,
    status: vault_ssh::CertStatus,
) {
    app.vault.cert_checks_in_flight.remove(&alias);
    let mtime = crate::tui_loop::current_cert_mtime(&alias, app);
    app.vault
        .cert_cache
        .insert(alias, (Instant::now(), status, mtime));
}

/// Handle `AppEvent::CertCheckError`.
pub(crate) fn handle_cert_check_error(app: &mut App, alias: String, message: String) {
    // Cache the error as Invalid so the lazy-check loop doesn't
    // re-spawn a background thread on every poll tick.
    app.vault.cert_checks_in_flight.remove(&alias);
    app.vault.cert_cache.insert(
        alias.clone(),
        (
            Instant::now(),
            vault_ssh::CertStatus::Invalid(message.clone()),
            None,
        ),
    );
    app.notify_background_error(crate::messages::vault_cert_check_failed(&alias, &message));
}

#[cfg(test)]
mod key_push_tests {
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
        let toast = app.status_center.toast.as_ref().expect("toast set");
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
        let status = app.status_center.status.as_ref().expect("sticky status");
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
        let status = app
            .status_center
            .status
            .as_ref()
            .expect("sticky status set");
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
