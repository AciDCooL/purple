//! Group filter helpers. Implements `impl App` continuation for clearing the
//! active group filter.

use super::HostListItem;
use crate::app::App;

impl App {
    /// Clear group filter (Esc from filtered mode).
    pub fn clear_group_filter(&mut self) {
        if self.hosts_state.group_filter.is_none() {
            return;
        }
        self.hosts_state.group_filter = None;
        self.apply_sort();
        for (i, item) in self.hosts_state.display_list.iter().enumerate() {
            if matches!(item, HostListItem::Host { .. }) {
                self.ui.list_state.select(Some(i));
                break;
            }
        }
    }
}
