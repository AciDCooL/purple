use crate::app::FormBaseline;
use crate::app::forms::HostForm;
use crate::app::tag_state::BulkTagEditorState;

/// Host-form and bulk-tag editor state grouped off the `App` god-struct.
/// Holds the add/edit host form, its dirty-check baseline, the bulk-tag
/// editor, the last-apply snapshot used by `u` to revert bulk-tag changes
/// and the pending-discard confirmation flag. Pure state container.
pub struct FormState {
    pub(crate) host: HostForm,
    pub(crate) host_baseline: Option<FormBaseline>,
    pub(crate) bulk_tag_editor: BulkTagEditorState,
    /// Snapshot of the last bulk tag apply, used by `u` to revert the
    /// operation even though `undo_stack` only holds deleted hosts. Holds
    /// `(alias, previous_tags)` pairs so restore is idempotent. Cleared
    /// after a successful undo or on the next mutation.
    pub(crate) bulk_tag_undo: Option<Vec<(String, Vec<String>)>>,
    /// When true, the Esc key shows a "Discard changes?" dialog instead of
    /// closing the open host form. Mutate via `request_discard_confirm`
    /// and `dismiss_discard_confirm`; read via `is_discard_pending`.
    discard_pending: bool,
}

impl FormState {
    /// Arm the "Discard changes?" Esc dialog. Called when Esc fires on a
    /// form that has unsaved edits relative to its baseline.
    pub fn request_discard_confirm(&mut self) {
        self.discard_pending = true;
    }

    /// Clear the pending discard flag. Called on dialog dismiss, on
    /// successful save, and on form close.
    pub fn dismiss_discard_confirm(&mut self) {
        self.discard_pending = false;
    }

    /// True when Esc should show the "Discard changes?" dialog instead of
    /// closing the form.
    pub fn is_discard_pending(&self) -> bool {
        self.discard_pending
    }
}

impl Default for FormState {
    fn default() -> Self {
        Self {
            host: HostForm::new(),
            host_baseline: None,
            bulk_tag_editor: BulkTagEditorState::default(),
            bulk_tag_undo: None,
            discard_pending: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let s = FormState::default();
        assert!(!s.is_discard_pending());
        assert!(s.bulk_tag_undo.is_none());
        assert!(s.host_baseline.is_none());
        assert!(s.bulk_tag_editor.rows.is_empty());
    }

    #[test]
    fn discard_confirm_lifecycle() {
        let mut s = FormState::default();
        assert!(!s.is_discard_pending());
        s.request_discard_confirm();
        assert!(s.is_discard_pending());
        s.dismiss_discard_confirm();
        assert!(!s.is_discard_pending());
    }
}
