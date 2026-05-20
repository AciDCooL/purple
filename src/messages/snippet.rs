//! Snippet store messages: validation, CRUD toasts, output overlay,
//! snippet runner errors.

// ── Form validation (SnippetForm + snippet store) ───────────────────

pub const SNIPPET_NAME_EMPTY: &str = "Snippet name cannot be empty.";
pub const SNIPPET_NAME_WHITESPACE: &str =
    "Snippet name cannot have leading or trailing whitespace.";
pub const SNIPPET_NAME_INVALID_CHARS: &str = "Snippet name cannot contain #, [ or ].";
pub const SNIPPET_NAME_CONTROL_CHARS: &str = "Snippet name cannot contain control characters.";
pub const SNIPPET_COMMAND_EMPTY: &str = "Command cannot be empty.";
pub const SNIPPET_COMMAND_CONTROL_CHARS: &str = "Command cannot contain control characters.";
pub const SNIPPET_DESCRIPTION_CONTROL_CHARS: &str = "Description contains control characters.";

// ── Snippets ────────────────────────────────────────────────────────

pub fn snippet_removed(name: &str) -> String {
    format!("Removed snippet '{}'.", name)
}

pub fn snippet_added(name: &str) -> String {
    format!("Added snippet '{}'.", name)
}

pub fn snippet_updated(name: &str) -> String {
    format!("Updated snippet '{}'.", name)
}

pub fn snippet_exists(name: &str) -> String {
    format!("'{}' already exists.", name)
}

pub const OUTPUT_COPIED: &str = "Output copied.";

pub fn copy_failed(e: &impl std::fmt::Display) -> String {
    format!("Copy failed: {}", e)
}

// ── Snippet runner errors ───────────────────────────────────────────

pub fn snippet_ssh_launch_failed(e: &impl std::fmt::Display) -> String {
    format!("Failed to launch ssh: {}", e)
}
