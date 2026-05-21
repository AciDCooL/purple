//! UI selection substate: list cursors, picker overlays, scroll offsets.

use ratatui::widgets::ListState;

use crate::ui::theme::ThemeDef;

/// A picker overlay: open flag plus its list cursor.
#[derive(Debug, Default)]
pub struct PickerState {
    pub open: bool,
    pub list: ListState,
}

#[allow(dead_code)]
impl PickerState {
    /// Open the picker with the cursor positioned at `index`.
    pub fn open_at(&mut self, index: usize) {
        self.open = true;
        self.list.select(Some(index));
    }

    /// Close the picker and reset the cursor.
    pub fn close(&mut self) {
        self.open = false;
        self.list.select(None);
    }
}

/// Theme picker carries extra catalogue + preview state beyond a simple list.
#[derive(Debug, Default)]
pub struct ThemePickerState {
    pub list: ListState,
    pub builtins: Vec<ThemeDef>,
    pub custom: Vec<ThemeDef>,
    pub saved_name: String,
    pub original: Option<ThemeDef>,
}

/// Region picker uses a cursor index rather than a ListState because region
/// rows are a synthetic flat array (provider × region pairs) rather than a
/// ratatui-managed list.
#[derive(Debug, Default)]
pub struct RegionPickerState {
    pub open: bool,
    pub cursor: usize,
}

#[derive(Debug, Default)]
pub struct UiSelection {
    pub list_state: ListState,
    pub key_picker: PickerState,
    pub password_picker: PickerState,
    pub proxyjump_picker: PickerState,
    pub vault_role_picker: PickerState,
    pub tag_picker_state: ListState,
    pub bulk_tag_editor_state: ListState,
    pub theme_picker: ThemePickerState,
    pub provider_list_state: ListState,
    pub tunnel_list_state: ListState,
    pub tunnels_overview_state: ListState,
    pub containers_overview_state: ListState,
    /// Cursor for the host picker reached from the tunnels overview when
    /// adding a new tunnel. Indexes into the editable-hosts slice built at
    /// render time (hosts from included files are excluded).
    pub tunnel_host_picker_state: ListState,
    /// Live fuzzy-search query for the tunnel host picker. Always-on input
    /// mode: every printable keystroke appends to the query and shrinks the
    /// candidate set. Empty string means "show all".
    pub tunnel_host_picker_query: String,
    /// Cursor + live query for the containers-tab `a` host picker.
    /// Mirrors the tunnel host picker pair; kept separate so the two
    /// pickers can be open back-to-back without state bleed.
    pub container_host_picker_state: ListState,
    pub container_host_picker_query: String,
    pub snippet_picker_state: ListState,
    pub snippet_search: Option<String>,
    pub region_picker: RegionPickerState,
    pub help_scroll: u16,
    pub detail_scroll: u16,
    /// Set by handler, consumed by AnimationState to trigger detail panel transition.
    pub detail_toggle_pending: bool,
    /// Tracks when the welcome screen was opened to auto-dismiss it.
    pub welcome_opened: Option<std::time::Instant>,
    /// Set once the first time Esc-on-empty-list hint is shown per process.
    pub esc_quit_hint_shown: bool,
    /// Welcome-screen heuristic: number of known hosts at last render.
    pub known_hosts_count: usize,
    /// Pending SSH dispatch queued by connect actions; consumed by the event loop.
    pub pending_connect: Option<(String, Option<String>)>,
}

impl UiSelection {
    /// Construct with all picker/list state defaulted and the host list
    /// selection pre-positioned at `initial` (the first selectable host or
    /// pattern in the display list).
    pub fn new_with_initial_selection(initial: Option<usize>) -> Self {
        let mut s = Self::default();
        if let Some(pos) = initial {
            s.list_state.select(Some(pos));
        }
        s
    }

    /// Queue an SSH connect for the event loop to pick up via the next
    /// `pending_connect.take()`. `askpass` carries the resolved per-host
    /// password source so the event loop can prepare a SSH_ASKPASS env
    /// before spawning the child.
    pub fn queue_connect(&mut self, alias: String, askpass: Option<String>) {
        self.pending_connect = Some((alias, askpass));
    }

    /// Enter snippet picker search mode with an empty query.
    pub fn open_snippet_search(&mut self) {
        self.snippet_search = Some(String::new());
    }

    /// Exit snippet picker search mode. Idempotent.
    pub fn close_snippet_search(&mut self) {
        self.snippet_search = None;
    }
}

impl ThemePickerState {
    /// Clear the catalogue lists and the saved-name input. Used by both
    /// picker-close paths. The `list` cursor and `original` are
    /// intentionally NOT touched here. The two callers handle `original`
    /// differently: the Esc/q path consumes it via `.take()` before
    /// calling reset (to restore the prior live theme); the Enter-save
    /// path leaves `original` intact through reset and clears it
    /// explicitly afterwards. Keeping `reset` orthogonal to `original`
    /// lets both flows share the same body.
    pub fn reset(&mut self) {
        self.builtins = Vec::new();
        self.custom = Vec::new();
        self.saved_name = String::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_connect_sets_pending_connect_to_some() {
        let mut s = UiSelection::default();
        s.queue_connect("web1".into(), Some("vault:foo".into()));
        assert_eq!(
            s.pending_connect,
            Some(("web1".to_string(), Some("vault:foo".to_string())))
        );
    }

    #[test]
    fn queue_connect_with_no_askpass_stores_none() {
        let mut s = UiSelection::default();
        s.queue_connect("web1".into(), None);
        assert_eq!(s.pending_connect, Some(("web1".to_string(), None)));
    }

    #[test]
    fn queue_connect_overwrites_existing_pending() {
        let mut s = UiSelection::default();
        s.queue_connect("first".into(), None);
        s.queue_connect("second".into(), Some("p".into()));
        assert_eq!(
            s.pending_connect,
            Some(("second".to_string(), Some("p".to_string())))
        );
    }

    #[test]
    fn open_snippet_search_sets_empty_query() {
        let mut s = UiSelection::default();
        s.open_snippet_search();
        assert_eq!(s.snippet_search.as_deref(), Some(""));
    }

    #[test]
    fn open_snippet_search_overwrites_existing_query_with_empty() {
        // The handler currently calls open only when search was inactive,
        // but the invariant should still hold: open is unconditional and
        // resets to an empty query. Pin the reset semantic so a future
        // caller cannot rely on a preserved query.
        let mut s = UiSelection {
            snippet_search: Some("old".to_string()),
            ..Default::default()
        };
        s.open_snippet_search();
        assert_eq!(s.snippet_search.as_deref(), Some(""));
    }

    #[test]
    fn close_snippet_search_clears_query() {
        let mut s = UiSelection {
            snippet_search: Some("query".to_string()),
            ..Default::default()
        };
        s.close_snippet_search();
        assert!(s.snippet_search.is_none());
    }

    #[test]
    fn close_snippet_search_is_idempotent() {
        let mut s = UiSelection::default();
        s.close_snippet_search();
        s.close_snippet_search();
        assert!(s.snippet_search.is_none());
    }

    #[test]
    fn theme_picker_reset_clears_lists_and_saved_name() {
        let mut t = ThemePickerState {
            builtins: vec![ThemeDef::purple_purple()],
            custom: vec![ThemeDef::purple_purple(), ThemeDef::purple_purple()],
            saved_name: "Solarized".to_string(),
            ..Default::default()
        };
        t.reset();
        assert!(t.builtins.is_empty());
        assert!(t.custom.is_empty());
        assert!(t.saved_name.is_empty());
    }

    #[test]
    fn theme_picker_reset_preserves_original_and_list_cursor() {
        let mut t = ThemePickerState {
            builtins: vec![ThemeDef::purple_purple()],
            original: Some(ThemeDef::purple_purple()),
            ..Default::default()
        };
        t.list.select(Some(2));
        t.reset();
        assert!(t.original.is_some(), "original must survive reset()");
        assert_eq!(t.list.selected(), Some(2));
    }
}
