use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::ssh_config::model::HostEntry;

/// Re-ping a focused host whose last result is older than this.
pub const STALE_REFRESH_AFTER: Duration = Duration::from_secs(120);

/// Ping/health-check state for all hosts.
pub struct PingState {
    pub(in crate::app) status: HashMap<String, PingStatus>,
    pub(in crate::app) last_checked: HashMap<String, Instant>,
    pub(in crate::app) has_pinged: bool,
    pub(in crate::app) generation: u64,
    pub(in crate::app) slow_threshold_ms: u16,
    pub(in crate::app) auto_ping: bool,
    pub(in crate::app) filter_down_only: bool,
    pub(in crate::app) checked_at: Option<Instant>,
}

impl Default for PingState {
    fn default() -> Self {
        Self {
            status: HashMap::new(),
            last_checked: HashMap::new(),
            has_pinged: false,
            generation: 0,
            slow_threshold_ms: 500,
            auto_ping: false,
            filter_down_only: false,
            checked_at: None,
        }
    }
}

impl PingState {
    pub fn status_map(&self) -> &HashMap<String, PingStatus> {
        &self.status
    }

    pub fn status_map_mut(&mut self) -> &mut HashMap<String, PingStatus> {
        &mut self.status
    }

    pub fn status_of(&self, alias: &str) -> Option<&PingStatus> {
        self.status.get(alias)
    }

    pub fn status_contains(&self, alias: &str) -> bool {
        self.status.contains_key(alias)
    }

    pub fn status_len(&self) -> usize {
        self.status.len()
    }

    pub fn status_is_empty(&self) -> bool {
        self.status.is_empty()
    }

    pub fn insert_status(&mut self, alias: String, status: PingStatus) {
        self.status.insert(alias, status);
    }

    pub fn remove_status(&mut self, alias: &str) {
        self.status.remove(alias);
    }

    pub fn last_checked(&self) -> &HashMap<String, Instant> {
        &self.last_checked
    }

    pub fn last_checked_at(&self, alias: &str) -> Option<&Instant> {
        self.last_checked.get(alias)
    }

    pub fn record_check(&mut self, alias: String, at: Instant) {
        self.last_checked.insert(alias, at);
    }

    pub fn has_pinged(&self) -> bool {
        self.has_pinged
    }

    pub fn set_has_pinged(&mut self, value: bool) {
        self.has_pinged = value;
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn set_generation(&mut self, value: u64) {
        self.generation = value;
    }

    pub fn slow_threshold_ms(&self) -> u16 {
        self.slow_threshold_ms
    }

    pub fn set_slow_threshold_ms(&mut self, value: u16) {
        self.slow_threshold_ms = value;
    }

    pub fn auto_ping(&self) -> bool {
        self.auto_ping
    }

    pub fn set_auto_ping(&mut self, value: bool) {
        self.auto_ping = value;
    }

    pub fn filter_down_only(&self) -> bool {
        self.filter_down_only
    }

    pub fn set_filter_down_only(&mut self, value: bool) {
        self.filter_down_only = value;
    }

    pub fn checked_at(&self) -> Option<Instant> {
        self.checked_at
    }

    pub fn set_checked_at(&mut self, value: Option<Instant>) {
        self.checked_at = value;
    }

    /// Construct with slow threshold + auto-ping loaded from preferences.
    pub fn from_preferences(paths: Option<&crate::runtime::env::Paths>) -> Self {
        Self {
            slow_threshold_ms: crate::preferences::load_slow_threshold(paths),
            auto_ping: crate::preferences::load_auto_ping(paths),
            ..Self::default()
        }
    }

    /// Clear all ping results and reset the dynamic filter/timestamp state.
    /// Preserves config (slow_threshold_ms, auto_ping) and `has_pinged`.
    /// Bumps `generation` so in-flight ping responses can be discarded.
    pub fn clear_results(&mut self) {
        self.status.clear();
        self.last_checked.clear();
        self.filter_down_only = false;
        self.checked_at = None;
        self.generation += 1;
    }

    /// True when no ping result exists for `alias`, or the result is older
    /// than `STALE_REFRESH_AFTER`. Used to decide whether selecting a host
    /// should trigger a background refresh.
    pub fn is_stale(&self, alias: &str) -> bool {
        match self.last_checked.get(alias) {
            Some(t) => t.elapsed() >= STALE_REFRESH_AFTER,
            None => !self.status.contains_key(alias),
        }
    }

    /// Drop `status` and `last_checked` entries whose alias is no longer
    /// in `valid_aliases`. Called from `App::reload_hosts` after the new
    /// host list lands so stale ping entries cannot outlive their host.
    pub fn prune_orphans(&mut self, valid_aliases: &std::collections::HashSet<&str>) {
        let pre_status = self.status.len();
        let pre_checked = self.last_checked.len();
        self.status
            .retain(|alias, _| valid_aliases.contains(alias.as_str()));
        self.last_checked
            .retain(|alias, _| valid_aliases.contains(alias.as_str()));
        let dropped = pre_status.saturating_sub(self.status.len())
            + pre_checked.saturating_sub(self.last_checked.len());
        if dropped > 0 {
            log::debug!(
                "[purple] reload_hosts: pruned {} orphan ping entrie(s); {} aliases remain",
                dropped,
                valid_aliases.len()
            );
        }
    }

    /// Move `status` and `last_checked` entries from `old` to `new`.
    /// Called from `App::migrate_alias_keyed_caches` before
    /// `reload_hosts`, whose prune step would otherwise drop entries
    /// still under the old alias. No-op when `old == new`.
    pub fn migrate_alias(&mut self, old: &str, new: &str) {
        if old == new {
            return;
        }
        if let Some(v) = self.status.remove(old) {
            self.status.insert(new.to_string(), v);
        }
        if let Some(v) = self.last_checked.remove(old) {
            self.last_checked.insert(new.to_string(), v);
        }
    }
}

/// Ping status for a host.
#[derive(Debug, Clone, PartialEq)]
pub enum PingStatus {
    Checking,
    Reachable { rtt_ms: u32 },
    Slow { rtt_ms: u32 },
    Unreachable,
    Skipped,
}

/// Classify a ping result into a PingStatus based on RTT and threshold.
pub fn classify_ping(rtt_ms: Option<u32>, slow_threshold_ms: u16) -> PingStatus {
    match rtt_ms {
        Some(ms) if ms >= slow_threshold_ms as u32 => PingStatus::Slow { rtt_ms: ms },
        Some(ms) => PingStatus::Reachable { rtt_ms: ms },
        None => PingStatus::Unreachable,
    }
}

/// Propagate a ping result to all hosts that use the given alias as ProxyJump bastion.
pub fn propagate_ping_to_dependents(
    hosts: &[HostEntry],
    ping_status: &mut HashMap<String, PingStatus>,
    bastion_alias: &str,
    status: &PingStatus,
) {
    for h in hosts {
        if h.proxy_jump == bastion_alias {
            ping_status.insert(h.alias.clone(), status.clone());
        }
    }
}

/// Sort key for ping status: unreachable first, slow, reachable, unchecked last.
pub fn ping_sort_key(status: Option<&PingStatus>) -> u8 {
    match status {
        Some(PingStatus::Unreachable) => 0,
        Some(PingStatus::Slow { .. }) => 1,
        Some(PingStatus::Reachable { .. }) => 2,
        Some(PingStatus::Checking) => 3,
        Some(PingStatus::Skipped) | None => 4,
    }
}

/// Status glyph for dual encoding (color + shape).
/// ● online, ▲ slow, ✖ down. Checking uses animated spinner via tick.
pub fn status_glyph(status: Option<&PingStatus>, tick: u64) -> &'static str {
    match status {
        Some(PingStatus::Reachable { .. }) => "\u{25CF}", // ●
        Some(PingStatus::Slow { .. }) => "\u{25B2}",      // ▲
        Some(PingStatus::Unreachable) => "\u{2716}",      // ✖
        Some(PingStatus::Checking) => {
            crate::animation::SPINNER_FRAMES
                [(tick as usize) % crate::animation::SPINNER_FRAMES.len()]
        }
        Some(PingStatus::Skipped) => "",
        None => "\u{25CB}", // ○
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_stale_when_no_status_and_no_timestamp() {
        let state = PingState::default();
        assert!(state.is_stale("web1"));
    }

    #[test]
    fn is_fresh_when_just_checked() {
        let mut state = PingState::default();
        state
            .status
            .insert("web1".into(), PingStatus::Reachable { rtt_ms: 5 });
        state.last_checked.insert("web1".into(), Instant::now());
        assert!(!state.is_stale("web1"));
    }

    #[test]
    fn is_stale_after_refresh_window() {
        let mut state = PingState::default();
        state
            .status
            .insert("web1".into(), PingStatus::Reachable { rtt_ms: 5 });
        let past = Instant::now() - STALE_REFRESH_AFTER - Duration::from_secs(1);
        state.last_checked.insert("web1".into(), past);
        assert!(state.is_stale("web1"));
    }

    #[test]
    fn is_not_stale_when_status_present_without_timestamp() {
        // Demo seeds `status` but the timestamp branch handles the freshness
        // decision. Without a timestamp and with a status, we treat the host
        // as fresh so demo mode does not get a refresh storm.
        let mut state = PingState::default();
        state
            .status
            .insert("web1".into(), PingStatus::Reachable { rtt_ms: 5 });
        assert!(!state.is_stale("web1"));
    }

    #[test]
    fn clear_results_empties_status_and_last_checked_and_resets_filter() {
        let mut state = PingState::default();
        state
            .status
            .insert("web1".into(), PingStatus::Reachable { rtt_ms: 5 });
        state.last_checked.insert("web1".into(), Instant::now());
        state.filter_down_only = true;
        state.checked_at = Some(Instant::now());

        state.clear_results();

        assert!(state.status.is_empty());
        assert!(state.last_checked.is_empty());
        assert!(!state.filter_down_only);
        assert!(state.checked_at.is_none());
    }

    #[test]
    fn clear_results_increments_generation() {
        let mut state = PingState {
            generation: 7,
            ..Default::default()
        };
        state.clear_results();
        assert_eq!(state.generation, 8);
    }

    #[test]
    fn clear_results_preserves_config_and_has_pinged() {
        let mut state = PingState {
            slow_threshold_ms: 750,
            auto_ping: true,
            has_pinged: true,
            ..Default::default()
        };

        state.clear_results();

        assert_eq!(state.slow_threshold_ms, 750);
        assert!(state.auto_ping);
        assert!(state.has_pinged);
    }

    #[test]
    fn clear_results_is_idempotent_on_empty_state() {
        let mut state = PingState::default();
        state.clear_results();
        state.clear_results();
        assert!(state.status.is_empty());
        assert!(state.last_checked.is_empty());
        assert!(!state.filter_down_only);
        assert!(state.checked_at.is_none());
        assert_eq!(state.generation, 2);
    }

    #[test]
    fn prune_orphans_drops_only_unknown_aliases() {
        let mut s = PingState::default();
        s.status
            .insert("keep".to_string(), PingStatus::Reachable { rtt_ms: 12 });
        s.status.insert("drop".to_string(), PingStatus::Unreachable);
        s.last_checked.insert("keep".to_string(), Instant::now());
        s.last_checked.insert("drop".to_string(), Instant::now());

        let valid: std::collections::HashSet<&str> = ["keep"].into_iter().collect();
        s.prune_orphans(&valid);

        assert!(s.status.contains_key("keep"));
        assert!(!s.status.contains_key("drop"));
        assert!(s.last_checked.contains_key("keep"));
        assert!(!s.last_checked.contains_key("drop"));
    }

    #[test]
    fn migrate_alias_moves_status_and_last_checked() {
        let mut s = PingState::default();
        let now = Instant::now();
        s.status
            .insert("old".to_string(), PingStatus::Reachable { rtt_ms: 7 });
        s.last_checked.insert("old".to_string(), now);

        s.migrate_alias("old", "new");

        assert!(!s.status.contains_key("old"));
        assert!(!s.last_checked.contains_key("old"));
        assert!(matches!(
            s.status.get("new"),
            Some(PingStatus::Reachable { rtt_ms: 7 })
        ));
        assert_eq!(s.last_checked.get("new"), Some(&now));
    }
}
