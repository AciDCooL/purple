//! Tunnel-related user-facing strings: tunnel list management, tunnel
//! form validation, tunnel lifecycle toasts.

// ── Form validation (TunnelForm) ────────────────────────────────────

pub const TUNNEL_BIND_PORT_INVALID: &str = "Bind port must be 1-65535.";
pub const TUNNEL_BIND_PORT_ZERO: &str = "Bind port can't be 0.";
pub const TUNNEL_REMOTE_HOST_EMPTY: &str = "Remote host can't be empty.";
pub const TUNNEL_REMOTE_HOST_SPACES: &str = "Remote host can't contain spaces.";
pub const TUNNEL_REMOTE_PORT_INVALID: &str = "Remote port must be 1-65535.";
pub const TUNNEL_REMOTE_PORT_ZERO: &str = "Remote port can't be 0.";

/// Short form of `field_control_chars` used by TunnelForm where the
/// toast is purely informational and does not need the guidance suffix.
pub fn field_control_chars_short(name: &str) -> String {
    format!("{} contains control characters.", name)
}

// ── Tunnels ─────────────────────────────────────────────────────────

pub const TUNNEL_REMOVED: &str = "Tunnel removed.";
pub const TUNNEL_SAVED: &str = "Tunnel saved.";
pub const TUNNEL_NOT_FOUND: &str = "Tunnel not found in config.";
pub const TUNNEL_INCLUDED_READ_ONLY: &str = "Included host. Tunnels are read-only.";
pub const TUNNEL_ORIGINAL_NOT_FOUND: &str = "Original tunnel not found in config.";
pub const TUNNEL_LIST_CHANGED: &str = "Tunnel list changed externally. Press Esc and re-open.";
pub const TUNNEL_DUPLICATE: &str = "Duplicate tunnel already configured.";
pub const TUNNEL_NO_EDITABLE_HOSTS: &str = "No editable hosts. Add a host first.";
pub const TUNNEL_HOST_PICKER_NO_MATCH: &str = "No matches.";

pub fn tunnel_stopped(alias: &str) -> String {
    format!("Tunnel for {} stopped.", alias)
}

pub fn tunnel_started(alias: &str) -> String {
    format!("Tunnel for {} started.", alias)
}

pub fn tunnel_start_failed(e: &impl std::fmt::Display) -> String {
    format!("Failed to start tunnel: {}", e)
}
