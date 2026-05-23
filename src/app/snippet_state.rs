use crate::app::SnippetFormBaseline;
use crate::app::forms::{SnippetForm, SnippetOutputState, SnippetParamFormState};
use crate::snippet::{Snippet, SnippetStore};

/// Snippet-owned state grouped off the `App` god-struct. Holds the on-disk
/// snippet store, the edit form, the pending execution payload, the output
/// screen state, the param form, the terminal-submit flag, the dirty-check
/// baseline and the pending-delete index. Pure state container.
pub struct SnippetState {
    pub(in crate::app) store: SnippetStore,
    // Held at `pub(crate)` until the dedicated forms seal lands; the
    // SnippetForm has too many per-field mutations to wrap behind
    // methods in this commit.
    pub(crate) form: SnippetForm,
    pub(in crate::app) pending: Option<(Snippet, Vec<String>)>,
    // Held at `pub(crate)` because the output state is mutated through
    // multi-line patterns the forthcoming forms seal will route through
    // dedicated methods.
    pub(crate) output: Option<SnippetOutputState>,
    pub(crate) param_form: Option<SnippetParamFormState>,
    pub(in crate::app) pending_terminal: bool,
    pub(in crate::app) form_baseline: Option<SnippetFormBaseline>,
    // Held at `pub(crate)` so `if let Some(idx) = ...pending_delete`
    // multi-line patterns continue to compile.
    pub(crate) pending_delete: Option<usize>,
}

impl Default for SnippetState {
    fn default() -> Self {
        Self {
            store: SnippetStore::default(),
            form: SnippetForm::new(),
            pending: None,
            output: None,
            param_form: None,
            pending_terminal: false,
            form_baseline: None,
            pending_delete: None,
        }
    }
}

impl SnippetState {
    pub fn store(&self) -> &SnippetStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut SnippetStore {
        &mut self.store
    }

    pub fn pending(&self) -> Option<&(Snippet, Vec<String>)> {
        self.pending.as_ref()
    }

    pub fn take_pending(&mut self) -> Option<(Snippet, Vec<String>)> {
        self.pending.take()
    }

    pub fn set_pending(&mut self, value: Option<(Snippet, Vec<String>)>) {
        self.pending = value;
    }

    pub fn pending_terminal(&self) -> bool {
        self.pending_terminal
    }

    pub fn set_pending_terminal(&mut self, value: bool) {
        self.pending_terminal = value;
    }

    pub fn form_baseline(&self) -> Option<&SnippetFormBaseline> {
        self.form_baseline.as_ref()
    }

    pub fn set_form_baseline(&mut self, baseline: Option<SnippetFormBaseline>) {
        self.form_baseline = baseline;
    }

    /// Construct with snippet store loaded from disk.
    pub fn with_store_loaded() -> Self {
        Self {
            store: crate::snippet::SnippetStore::load(),
            ..Self::default()
        }
    }

    /// Open a delete confirmation for the snippet at `idx`. The renderer
    /// reads `pending_delete` to draw the confirm overlay.
    pub fn request_delete(&mut self, idx: usize) {
        self.pending_delete = Some(idx);
    }

    /// Dismiss a pending delete confirmation. Idempotent.
    pub fn cancel_delete(&mut self) {
        self.pending_delete = None;
    }

    /// Close the parameter substitution form. Clears the form state and
    /// the terminal-submit flag that decide whether the next Enter sends
    /// the resolved command to the foreground terminal or to background
    /// output capture. Idempotent.
    pub fn close_param_form(&mut self) {
        self.param_form = None;
        self.pending_terminal = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let s = SnippetState::default();
        assert!(s.pending.is_none());
        assert!(s.output.is_none());
        assert!(s.param_form.is_none());
        assert!(!s.pending_terminal);
        assert!(s.form_baseline.is_none());
        assert!(s.pending_delete.is_none());
    }

    #[test]
    fn request_delete_sets_pending_delete_to_some_idx() {
        let mut s = SnippetState::default();
        s.request_delete(3);
        assert_eq!(s.pending_delete, Some(3));
    }

    #[test]
    fn cancel_delete_clears_pending_delete() {
        let mut s = SnippetState {
            pending_delete: Some(2),
            ..Default::default()
        };
        s.cancel_delete();
        assert!(s.pending_delete.is_none());
    }

    #[test]
    fn request_delete_overwrites_existing_pending() {
        let mut s = SnippetState {
            pending_delete: Some(1),
            ..Default::default()
        };
        s.request_delete(7);
        assert_eq!(s.pending_delete, Some(7));
    }

    #[test]
    fn close_param_form_clears_param_form_and_pending_terminal() {
        let mut s = SnippetState {
            param_form: Some(SnippetParamFormState::new(&[])),
            pending_terminal: true,
            ..Default::default()
        };
        s.close_param_form();
        assert!(s.param_form.is_none());
        assert!(!s.pending_terminal);
    }

    #[test]
    fn close_param_form_preserves_pending_output_and_store() {
        use crate::snippet::Snippet;
        let mut s = SnippetState {
            param_form: Some(SnippetParamFormState::new(&[])),
            pending_terminal: true,
            pending: Some((
                Snippet {
                    name: "ls".into(),
                    command: "ls -la".into(),
                    description: String::new(),
                },
                vec!["host-a".into()],
            )),
            ..Default::default()
        };

        s.close_param_form();

        assert!(
            s.pending.is_some(),
            "pending stays for the consumer to read"
        );
        assert!(s.pending_delete.is_none());
    }

    #[test]
    fn close_param_form_is_idempotent_when_already_none() {
        let mut s = SnippetState::default();
        s.close_param_form();
        s.close_param_form();
        assert!(s.param_form.is_none());
        assert!(!s.pending_terminal);
    }
}
