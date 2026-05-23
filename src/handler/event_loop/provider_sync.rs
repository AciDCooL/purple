//! Provider sync progress, completion, partial-failure and error events.
//! Maintains `app.providers.syncing`, `sync_history`, batch counters and
//! the footer summary set by `crate::set_sync_summary`.

use std::time::Instant;

use crate::app::{self, App};
use crate::providers;

/// Handle `AppEvent::SyncProgress`.
pub(crate) fn handle_sync_progress(app: &mut App, provider: String, message: String) {
    // Only show per-provider progress while that provider is still syncing.
    // Late progress events (arriving after SyncComplete) are discarded.
    if app.providers.syncing().contains_key(&provider) && app.providers.sync_done().is_empty() {
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
        app.providers.record_sync(
            provider.clone(),
            app::SyncRecord {
                timestamp: now,
                message: format!("{}: sync failed", display_name),
                is_error: true,
            },
        );
        app.providers.set_sync_had_errors(true);
    } else {
        let label = if total == 1 { "server" } else { "servers" };
        let message = format!(
            "{} {}{}",
            total,
            label,
            crate::format_sync_diff(added, updated, stale)
        );
        app.providers.record_sync(
            provider.clone(),
            app::SyncRecord {
                timestamp: now,
                message,
                is_error: false,
            },
        );
        app.providers.add_batch_diff(added, updated, stale);
    }
    app.providers.syncing_mut().remove(&provider);
    app.providers.push_sync_done(display_name.to_string());
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
        app.providers.record_sync(
            provider.clone(),
            app::SyncRecord {
                timestamp: now,
                message: msg,
                is_error: true,
            },
        );
    } else {
        let label = if synced == 1 { "server" } else { "servers" };
        app.providers.record_sync(
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
        app.providers.add_batch_diff(added, updated, stale);
    }
    app.providers.set_sync_had_errors(true);
    app.providers.syncing_mut().remove(&provider);
    app.providers.push_sync_done(display_name.to_string());
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
    app.providers.record_sync(
        provider.clone(),
        app::SyncRecord {
            timestamp: now,
            message: message.clone(),
            is_error: true,
        },
    );
    app.providers.set_sync_had_errors(true);
    app.providers.syncing_mut().remove(&provider);
    app.providers.push_sync_done(display_name.to_string());
    crate::set_sync_summary(app);
    *last_config_check = Instant::now();
}
