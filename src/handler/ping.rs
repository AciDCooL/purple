use std::sync::mpsc;

use crate::app::App;
use crate::event::AppEvent;
use crate::ping;

/// Re-ping the selected host in the background when its last result is older
/// than `STALE_REFRESH_AFTER` (or never recorded). No toast, just sets the
/// status to `Checking` and schedules a single-host TCP probe. Skips when
/// `auto_ping` is off so the user's "no network noise" intent is respected.
pub(crate) fn refresh_selected_if_stale(app: &mut App, events_tx: &mpsc::Sender<AppEvent>) {
    if !app.ping.auto_ping {
        return;
    }
    let Some(host) = app.selected_host() else {
        return;
    };
    let alias = host.alias.clone();
    if !app.ping.is_stale(&alias) {
        return;
    }
    let (ping_alias, hostname, port) = if !host.proxy_jump.is_empty() {
        let bastion_alias = host.proxy_jump.clone();
        match app
            .hosts_state
            .list
            .iter()
            .find(|h| h.alias == bastion_alias)
        {
            Some(b) if !b.hostname.is_empty() => (b.alias.clone(), b.hostname.clone(), b.port),
            _ => return,
        }
    } else if host.hostname.is_empty() {
        return;
    } else {
        (alias, host.hostname.clone(), host.port)
    };
    if matches!(
        app.ping.status.get(&ping_alias),
        Some(crate::app::PingStatus::Checking)
    ) {
        return;
    }
    log::debug!(
        "stale-refresh: marking {} Checking and probing {}:{}",
        ping_alias,
        hostname,
        port
    );
    app.ping
        .status
        .insert(ping_alias.clone(), crate::app::PingStatus::Checking);
    ping::ping_host(
        ping_alias,
        hostname,
        port,
        events_tx.clone(),
        app.ping.generation,
    );
}

/// Ping the currently selected host (shared by 'p' key and Ctrl+P in search mode).
pub(super) fn ping_selected_host(
    app: &mut App,
    events_tx: &mpsc::Sender<AppEvent>,
    show_hint: bool,
) {
    if let Some(host) = app.selected_host() {
        let alias = host.alias.clone();
        // For ProxyJump hosts, ping the bastion instead and propagate the
        // result to all dependents (handled in main.rs PingResult handler).
        let (ping_alias, hostname, port) = if !host.proxy_jump.is_empty() {
            let bastion_alias = host.proxy_jump.clone();
            if let Some(bastion) = app
                .hosts_state
                .list
                .iter()
                .find(|h| h.alias == bastion_alias)
            {
                app.ping
                    .status
                    .insert(alias.clone(), crate::app::PingStatus::Checking);
                (
                    bastion.alias.clone(),
                    bastion.hostname.clone(),
                    bastion.port,
                )
            } else {
                app.notify_warning(crate::messages::bastion_not_found(&bastion_alias));
                return;
            }
        } else {
            (alias.clone(), host.hostname.clone(), host.port)
        };
        app.ping
            .status
            .insert(ping_alias.clone(), crate::app::PingStatus::Checking);
        if show_hint && !app.ping.has_pinged {
            app.notify(crate::messages::pinging_host(&ping_alias, true));
            app.ping.has_pinged = true;
        } else {
            app.notify(crate::messages::pinging_host(&ping_alias, false));
        }
        ping::ping_host(
            ping_alias,
            hostname,
            port,
            events_tx.clone(),
            app.ping.generation,
        );
    }
}
