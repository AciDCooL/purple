//! Centralized user-facing messages.
//!
//! Every string the user can see (toasts, CLI output, error messages) lives
//! here. Handler, CLI and UI code reference these constants and functions
//! instead of inlining string literals. This makes copy consistent, auditable
//! and future-proof for i18n.

// ── General / shared ────────────────────────────────────────────────

pub const FAILED_TO_SAVE: &str = "Failed to save";
pub fn failed_to_save(e: &impl std::fmt::Display) -> String {
    format!("{}: {}", FAILED_TO_SAVE, e)
}

pub const CONFIG_CHANGED_EXTERNALLY: &str =
    "Config changed externally. Press Esc and re-open to pick up changes.";

// ── Demo mode ───────────────────────────────────────────────────────

pub const DEMO_CONNECTION_DISABLED: &str = "Demo mode. Connection disabled.";
pub const DEMO_SYNC_DISABLED: &str = "Demo mode. Sync disabled.";
pub const DEMO_TUNNELS_DISABLED: &str = "Demo mode. Tunnels disabled.";
pub const DEMO_VAULT_SIGNING_DISABLED: &str = "Demo mode. Vault SSH signing disabled.";
pub const DEMO_FILE_BROWSER_DISABLED: &str = "Demo mode. File browser disabled.";
pub const DEMO_CONTAINER_REFRESH_DISABLED: &str = "Demo mode. Container refresh disabled.";
pub const DEMO_CONTAINER_ACTIONS_DISABLED: &str = "Demo mode. Container actions disabled.";
pub const DEMO_EXECUTION_DISABLED: &str = "Demo mode. Execution disabled.";
pub const DEMO_PROVIDER_CHANGES_DISABLED: &str = "Demo mode. Provider config changes disabled.";

// ── Stale host ──────────────────────────────────────────────────────

/// Compose a "Stale host." warning with an optional hint clause.
/// Trims the hint, drops a trailing period to avoid doubling, and uses
/// a space separator so the result reads as one sentence. With an empty
/// hint the bare "Stale host." remains.
pub fn stale_host(hint: &str) -> String {
    let trimmed = hint.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        "Stale host.".to_string()
    } else {
        format!("Stale host. {}.", trimmed)
    }
}

// ── Host list ───────────────────────────────────────────────────────

pub fn copied_ssh_command(alias: &str) -> String {
    format!("Copied SSH command for {}.", alias)
}

pub fn copied_config_block(alias: &str) -> String {
    format!("Copied config block for {}.", alias)
}

pub fn showing_unreachable(count: usize) -> String {
    format!(
        "Showing {} unreachable host{}.",
        count,
        if count == 1 { "" } else { "s" }
    )
}

pub fn sorted_by(label: &str) -> String {
    format!("Sorted by {}.", label)
}

pub fn sorted_by_save_failed(label: &str, e: &impl std::fmt::Display) -> String {
    format!("Sorted by {}. (save failed: {})", label, e)
}

pub fn grouped_by(label: &str) -> String {
    format!("Grouped by {}.", label)
}

pub fn grouped_by_save_failed(label: &str, e: &impl std::fmt::Display) -> String {
    format!("Grouped by {}. (save failed: {})", label, e)
}

pub const UNGROUPED: &str = "Ungrouped.";

pub fn ungrouped_save_failed(e: &impl std::fmt::Display) -> String {
    format!("Ungrouped. (save failed: {})", e)
}

pub const GROUPED_BY_TAG: &str = "Grouped by tag.";

pub fn grouped_by_tag_save_failed(e: &impl std::fmt::Display) -> String {
    format!("Grouped by tag. (save failed: {})", e)
}

pub fn host_restored(alias: &str) -> String {
    format!("{} is back from the dead.", alias)
}

pub fn restored_tags(count: usize) -> String {
    format!(
        "Restored tags on {} host{}.",
        count,
        if count == 1 { "" } else { "s" }
    )
}

pub const NOTHING_TO_UNDO: &str = "Nothing to undo.";
pub const NO_IMPORTABLE_HOSTS: &str = "No importable hosts in known_hosts.";
pub const NO_STALE_HOSTS: &str = "No stale hosts.";
pub const NO_HOST_SELECTED: &str = "No host selected.";
pub const NO_HOSTS_TO_RUN: &str = "No hosts to run on.";
pub const NO_HOSTS_TO_TAG: &str = "No hosts to tag.";
pub const PING_FIRST: &str = "Ping first (p/P), then filter with !.";
pub const PINGING_ALL: &str = "Pinging all the things...";
pub const ESC_QUIT_HINT: &str = "Nothing to cancel. Press q to quit.";

pub fn included_file_edit(name: &str) -> String {
    format!("{} is in an included file. Edit it there.", name)
}

pub fn included_file_delete(name: &str) -> String {
    format!("{} is in an included file. Delete it there.", name)
}

pub fn included_file_clone(name: &str) -> String {
    format!("{} is in an included file. Clone it there.", name)
}

pub fn included_host_lives_in(alias: &str, path: &impl std::fmt::Display) -> String {
    format!("{} lives in {}. Edit it there.", alias, path)
}

pub fn included_host_clone_there(alias: &str, path: &impl std::fmt::Display) -> String {
    format!("{} lives in {}. Clone it there.", alias, path)
}

pub fn included_host_tag_there(alias: &str, path: &impl std::fmt::Display) -> String {
    format!("{} is included from {}. Tag it there.", alias, path)
}

pub const HOST_NOT_FOUND_IN_CONFIG: &str = "Host not found in config.";

// ── Host form ───────────────────────────────────────────────────────

pub const SMART_PARSED: &str = "Smart-parsed that for you. Check the fields.";
pub const LOOKS_LIKE_ADDRESS: &str = "Looks like an address. Suggested as Host.";

// ── Form validation (HostForm) ──────────────────────────────────────
//
// Surfaced via `notify_error(msg)` after `HostForm::validate()`. All
// strings live here so the central message audit (`check-messages.sh`)
// covers them and so the wording stays consistent with the rest of the
// TUI copy.

pub const HOST_ALIAS_EMPTY: &str = "Alias can't be empty. Every host needs a name!";
pub const HOST_PATTERN_EMPTY: &str = "Pattern can't be empty.";
pub const HOST_PATTERN_NEEDS_WILDCARD: &str =
    "Pattern needs a wildcard (*, ?, [) or multiple hosts.";
pub const HOST_ALIAS_WHITESPACE: &str = "Alias can't contain whitespace. Keep it simple.";
pub const HOST_ALIAS_HASH: &str =
    "Alias can't contain '#'. That's a comment character in SSH config.";
pub const HOST_ALIAS_PATTERN_CHARS: &str =
    "Alias can't contain pattern characters. That creates a match pattern, not a host.";
pub const HOST_HOSTNAME_EMPTY: &str = "Hostname can't be empty. Where should we connect to?";
pub const HOST_HOSTNAME_WHITESPACE: &str = "Hostname can't contain whitespace.";
pub const HOST_PORT_INVALID: &str = "That's not a port number. Ports are 1-65535, not poetry.";
pub const HOST_PORT_ZERO: &str = "Port 0? Bold choice, but no. Try 1-65535.";
pub const HOST_VAULT_ROLE_INVALID: &str = "Vault SSH role: only letters, digits, /, _ and - \
     are allowed (e.g. ssh-client-signer/sign/my-role).";
pub const HOST_VAULT_ADDR_INVALID: &str = "Vault SSH address: must be a non-empty URL \
     without spaces or control characters (e.g. http://127.0.0.1:8200).";

/// Long-form "{} contains control characters." used by `HostForm::validate`
/// where the toast doubles as guidance ("that's not going to work").
pub fn field_control_chars(name: &str) -> String {
    format!(
        "{} contains control characters. That's not going to work.",
        name
    )
}

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

// ── Form validation (SnippetForm + snippet store) ───────────────────

pub const SNIPPET_NAME_EMPTY: &str = "Snippet name cannot be empty.";
pub const SNIPPET_NAME_WHITESPACE: &str =
    "Snippet name cannot have leading or trailing whitespace.";
pub const SNIPPET_NAME_INVALID_CHARS: &str = "Snippet name cannot contain #, [ or ].";
pub const SNIPPET_NAME_CONTROL_CHARS: &str = "Snippet name cannot contain control characters.";
pub const SNIPPET_COMMAND_EMPTY: &str = "Command cannot be empty.";
pub const SNIPPET_COMMAND_CONTROL_CHARS: &str = "Command cannot contain control characters.";
pub const SNIPPET_DESCRIPTION_CONTROL_CHARS: &str = "Description contains control characters.";

// ── Host CRUD (add / edit) ──────────────────────────────────────────

pub fn pattern_already_exists(alias: &str) -> String {
    format!("Pattern '{}' already exists.", alias)
}

pub fn host_alias_already_exists(alias: &str) -> String {
    format!("'{}' already exists. Aliases must be unique.", alias)
}

pub const PATTERN_NO_LONGER_EXISTS: &str = "Pattern no longer exists.";
pub const HOST_NO_LONGER_EXISTS: &str = "Host no longer exists.";

pub fn cert_path_resolve_failed(e: &impl std::fmt::Display) -> String {
    format!("Failed to resolve cert path: {}", e)
}

/// Toast shown after a host is added through the TUI form. The CLI
/// `purple add` flow shares this string via `messages::cli::welcome`.
pub fn welcome_aboard(alias: &str) -> String {
    format!("Welcome aboard, {}!", alias)
}

// ── Bulk tag editor ─────────────────────────────────────────────────

pub const BULK_TAG_NO_HOSTS_SELECTED: &str = "No hosts selected.";

// ── Confirm delete ──────────────────────────────────────────────────

pub fn goodbye_host(alias: &str) -> String {
    format!("Goodbye, {}. We barely knew ye. (u to undo)", alias)
}

pub fn host_not_found(alias: &str) -> String {
    format!("Host '{}' not found.", alias)
}

/// Toast after stripping an alias token from a shared `Host` line. Undo is
/// not offered because re-inserting a whole block would not reverse a token
/// strip (sibling aliases and their directives stay in place).
pub fn siblings_stripped(alias: &str, sibling_count: usize) -> String {
    if sibling_count == 1 {
        format!(
            "Stripped {}. 1 sibling alias kept its shared config.",
            alias
        )
    } else {
        format!(
            "Stripped {}. {} sibling aliases kept their shared config.",
            alias, sibling_count
        )
    }
}

/// One-line note rendered inside the confirm-delete dialog when the target
/// alias shares its `Host` block with siblings. Explains that the other
/// tokens survive.
pub fn confirm_delete_siblings_note(siblings: &[String]) -> String {
    let shown: Vec<&str> = siblings.iter().take(3).map(String::as_str).collect();
    let tail = if siblings.len() > shown.len() {
        format!(" +{} more", siblings.len() - shown.len())
    } else {
        String::new()
    };
    format!("Siblings kept: {}{}", shown.join(", "), tail)
}

pub fn cert_cleanup_warning(path: &impl std::fmt::Display, e: &impl std::fmt::Display) -> String {
    format!("Warning: failed to clean up Vault SSH cert {}: {}", path, e)
}

// ── Clone ───────────────────────────────────────────────────────────

pub const CLONED_VAULT_CLEARED: &str = "Cloned. Vault SSH role cleared on copy.";

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

// ── Ping ────────────────────────────────────────────────────────────

pub fn pinging_host(alias: &str, show_hint: bool) -> String {
    if show_hint {
        format!("Pinging {}... (Shift+P pings all)", alias)
    } else {
        format!("Pinging {}...", alias)
    }
}

pub fn bastion_not_found(alias: &str) -> String {
    format!("Bastion {} not found in config.", alias)
}

// ── Providers ───────────────────────────────────────────────────────

pub fn provider_removed(display_name: &str) -> String {
    format!(
        "Removed {} configuration. Synced hosts remain in your SSH config.",
        display_name
    )
}

pub fn label_invalid(reason: &str) -> String {
    format!("Invalid name: {}", reason)
}

pub const LABEL_MUST_DIFFER: &str = "The two names must be different.";

pub const LABEL_MIGRATION_FIELD_CURRENT: &str = " Name for your current config ";
pub const LABEL_MIGRATION_FIELD_NEW: &str = " Name for the new config ";

pub fn confirm_remove_provider(display: &str) -> String {
    format!(" Remove {}? ", display)
}

pub fn confirm_remove_labeled_config(display: &str, label: &str) -> String {
    format!(" Remove {} ({})? ", display, label)
}

pub const EXPAND_TO_REMOVE_CONFIG: &str =
    "Expand the provider and pick a specific config to remove.";

pub fn provider_not_configured(display_name: &str) -> String {
    format!("{} is not configured. Nothing to remove.", display_name)
}

pub fn provider_configure_first(display_name: &str) -> String {
    format!("Configure {} first. Press Enter to set up.", display_name)
}

pub fn provider_saved_syncing(display_name: &str) -> String {
    format!("Saved {} configuration. Syncing...", display_name)
}

pub fn provider_saved(display_name: &str) -> String {
    format!("Saved {} configuration.", display_name)
}

pub fn no_stale_hosts_for(display_name: &str) -> String {
    format!("No stale hosts for {}.", display_name)
}

pub fn contains_control_chars(name: &str) -> String {
    format!("{} contains control characters.", name)
}

pub const TOKEN_FORMAT_AWS: &str = "Token format: AccessKeyId:SecretAccessKey";
pub const URL_REQUIRED_PROXMOX: &str = "URL is required for Proxmox VE.";
pub const PROJECT_REQUIRED_GCP: &str = "Project ID can't be empty. Set your GCP project ID.";
pub const COMPARTMENT_REQUIRED_OCI: &str =
    "Compartment can't be empty. Set your OCI compartment OCID.";
pub const REGIONS_REQUIRED_AWS: &str = "Select at least one AWS region.";
pub const ZONES_REQUIRED_SCALEWAY: &str = "Select at least one Scaleway zone.";
pub const SUBSCRIPTIONS_REQUIRED_AZURE: &str = "Enter at least one Azure subscription ID.";
pub const ALIAS_PREFIX_INVALID: &str =
    "Alias prefix can't contain spaces or pattern characters (*, ?, [, !).";
pub const USER_NO_WHITESPACE: &str = "User can't contain whitespace.";
pub const VAULT_ROLE_FORMAT: &str = "Vault SSH role must be in the form <mount>/sign/<role>.";

pub const PROVIDER_CONFIG_CHANGED_EXTERNALLY: &str =
    "Provider config changed externally. Press Esc and re-open to pick up changes.";
pub const PROVIDER_URL_REQUIRES_HTTPS: &str =
    "URL must start with https://. Toggle Verify TLS off for self-signed certificates.";
pub const PROVIDER_TOKEN_REQUIRED_GCP: &str =
    "Token can't be empty. Provide a service account JSON key file path or access token.";
pub const PROVIDER_TOKEN_REQUIRED_ORACLE: &str =
    "Token can't be empty. Provide the path to your OCI config file (e.g. ~/.oci/config).";

pub fn provider_token_required(display_name: &str) -> String {
    format!(
        "Token can't be empty. Grab one from your {} dashboard.",
        display_name
    )
}

pub fn azure_subscription_id_invalid(sub: &str) -> String {
    format!(
        "Invalid subscription ID '{}'. Expected UUID format \
         (e.g. 12345678-1234-1234-1234-123456789012).",
        sub
    )
}

// ── Vault SSH ───────────────────────────────────────────────────────

pub const VAULT_SIGNING_CANCELLED: &str = "Vault SSH signing cancelled.";

/// Sticky error shown when bulk signing hits 3 consecutive failures and
/// gives up. `failed` is the running failure count; `last_error` carries
/// the scrubbed Vault stderr so the user can act (run `vault login`,
/// fix the address, etc.).
pub fn vault_signing_aborted(failed: u32, last_error: Option<&str>) -> String {
    format!(
        "Vault SSH signing aborted after {} consecutive failures. Press V to retry. Last error: {}",
        failed,
        last_error.unwrap_or("unknown")
    )
}

/// Status line shown after a bulk Vault SSH sign run completes. Combines
/// signed/failed/skipped counters into one line, with the first error
/// inlined when there's room. Single-host sign runs show only the error
/// (no stats prefix) because the counter would just be noise.
/// Status string shown after a successful bulk tag apply. Returns an
/// empty string when nothing was changed and nothing was skipped, so the
/// caller can detect a no-op and skip setting a status.
pub fn bulk_tag_apply_status(
    changed_hosts: usize,
    added: usize,
    removed: usize,
    skipped_included: usize,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if changed_hosts > 0 {
        let host_word = if changed_hosts == 1 { "" } else { "s" };
        let mut head = format!("Updated {} host{}", changed_hosts, host_word);
        let mut delta = Vec::new();
        if added > 0 {
            delta.push(format!("+{}", added));
        }
        if removed > 0 {
            delta.push(format!("-{}", removed));
        }
        if !delta.is_empty() {
            head = format!("{} ({})", head, delta.join(" "));
        }
        parts.push(head);
    }
    if skipped_included > 0 {
        let file_word = if skipped_included == 1 { "" } else { "s" };
        parts.push(format!(
            "skipped {} in include file{}",
            skipped_included, file_word
        ));
    }
    parts.join(". ")
}

pub fn vault_sign_summary(
    signed: u32,
    failed: u32,
    skipped: u32,
    first_error: Option<&str>,
) -> String {
    let total = signed + failed + skipped;
    let cert_word = if total == 1 {
        "certificate"
    } else {
        "certificates"
    };
    if failed > 0 {
        if let Some(err) = first_error {
            if total == 1 {
                return err.to_string();
            }
            format!(
                "Signed {} of {} {}. {} failed: {}",
                signed, total, cert_word, failed, err
            )
        } else {
            format!(
                "Signed {} of {} {}. {} failed",
                signed, total, cert_word, failed
            )
        }
    } else if skipped > 0 && signed == 0 {
        format!(
            "All {} {} already valid. Nothing to sign.",
            total, cert_word
        )
    } else if skipped > 0 {
        format!(
            "Signed {} of {} {}. {} already valid.",
            signed, total, cert_word, skipped
        )
    } else {
        format!("Signed {} of {} {}.", signed, total, cert_word)
    }
}
pub const VAULT_NO_ROLE_CONFIGURED: &str = "No Vault SSH role configured. Set one in the host form \
     (Vault SSH role field) or on a provider for shared defaults.";
pub const VAULT_NO_HOSTS_WITH_ROLE: &str = "No hosts with a Vault SSH role configured.";
pub const VAULT_ALL_CERTS_VALID: &str = "All Vault SSH certificates are still valid.";
pub const VAULT_NO_ADDRESS: &str = "No Vault address set. Edit the host (e) or provider \
     and fill in the Vault SSH Address field.";

pub fn vault_error(msg: &str) -> String {
    format!("Vault SSH: {}", msg)
}

pub fn vault_signed(alias: &str) -> String {
    format!("Signed Vault SSH cert for {}", alias)
}

pub fn vault_sign_failed(alias: &str, message: &str) -> String {
    format!("Vault SSH: failed to sign {}: {}", alias, message)
}

pub fn vault_signing_progress(spinner: &str, done: usize, total: usize, alias: &str) -> String {
    format!(
        "{} Signing {}/{}: {} (V to cancel)",
        spinner, done, total, alias
    )
}

pub fn vault_cert_saved_host_gone(alias: &str) -> String {
    format!(
        "Vault SSH cert saved for {} but host no longer in config \
         (renamed or deleted). CertificateFile NOT written.",
        alias
    )
}

pub fn vault_spawn_failed(e: &impl std::fmt::Display) -> String {
    format!("Vault SSH: failed to spawn signing thread: {}", e)
}

pub fn vault_cert_check_failed(alias: &str, message: &str) -> String {
    format!("Cert check failed for {}: {}", alias, message)
}

pub fn vault_role_set(role: &str) -> String {
    format!("Vault SSH role set to {}.", role)
}

/// Toast shown after a successful pre-connect signing for a single host.
/// Distinct from `vault_signed` (used by bulk sign and form-submit) so the
/// connect path can mention that the cert was signed *as part of* connecting.
pub fn vault_signed_pre_connect(alias: &str) -> String {
    format!("Signed Vault SSH cert for {}.", alias)
}

/// Toast shown after a successful pre-connect signing covered multiple
/// chained hosts (target + ProxyJump hops). The `count` includes only hosts
/// that actually got a fresh cert; hosts whose cert was already valid are
/// excluded.
pub fn vault_signed_pre_connect_chain(target: &str, count: usize) -> String {
    if count <= 1 {
        format!("Signed Vault SSH cert for {}.", target)
    } else {
        format!("Signed Vault SSH certs for {} ({} hosts).", target, count)
    }
}

/// Toast shown when pre-connect signing failed for a host. Includes the
/// scrubbed Vault error so the user can act (run `vault login`, fix the
/// address, etc.). Distinct from `vault_sign_failed` so the wording can
/// reflect the connect context without breaking bulk-sign callers.
pub fn vault_sign_failed_pre_connect(alias: &str, message: &str) -> String {
    format!("Vault SSH signing failed for {}: {}", alias, message)
}

/// Toast shown when resolving the public key path for a Vault sign call
/// failed (missing pubkey, non-UTF8 path, etc.). Surfaced at the connect
/// step before any Vault round-trip happens.
pub fn vault_cert_pubkey_resolve_failed(e: &impl std::fmt::Display) -> String {
    format!("Vault SSH cert failed: {}", e)
}

/// Stderr warning emitted when a cert was signed but the matching host
/// block is no longer present (renamed or deleted between the connect
/// keypress and the signing call). The cert is still written to disk;
/// the user just has no `CertificateFile` directive pointing at it.
pub fn vault_cert_host_block_missing(alias: &str, cert_path: &std::path::Path) -> String {
    format!(
        "Warning: signed cert for {} but host block is no longer in ssh config; \
         CertificateFile not written (cert saved to {})",
        alias,
        cert_path.display()
    )
}

/// Stderr warning emitted when the cert was signed but writing the
/// updated SSH config back to disk failed.
pub fn vault_cert_config_write_failed(alias: &str, e: &impl std::fmt::Display) -> String {
    format!(
        "Warning: signed cert for {} but failed to update SSH config CertificateFile: {}",
        alias, e
    )
}

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

// ── Clipboard subprocess errors ─────────────────────────────────────
//
// Surfaced when `pbcopy`/`xclip`/`wl-copy` fails to spawn, write to its
// stdin, or be reaped. The cmd name is the binary the platform picked.

pub fn clipboard_run_failed(cmd: &str) -> String {
    format!("Failed to run {}.", cmd)
}

pub fn clipboard_write_failed(cmd: &str) -> String {
    format!("Failed to write to {}.", cmd)
}

pub fn clipboard_wait_failed(cmd: &str) -> String {
    format!("Failed to wait for {}.", cmd)
}

pub fn clipboard_exited_error(cmd: &str) -> String {
    format!("{} exited with error.", cmd)
}

// ── Import errors ───────────────────────────────────────────────────
//
// Bubble up to the CLI via `eprintln!("{}", e)` when the user runs
// `purple import` against a missing or unreadable file.

pub fn import_open_failed(path: &impl std::fmt::Display, e: &impl std::fmt::Display) -> String {
    format!("Can't open {}: {}", path, e)
}

pub fn import_known_hosts_open_failed(e: &impl std::fmt::Display) -> String {
    format!("Can't open known_hosts: {}", e)
}

pub const IMPORT_HOME_DIR_UNKNOWN: &str = "Could not determine home directory.";
pub const IMPORT_KNOWN_HOSTS_MISSING: &str = "~/.ssh/known_hosts not found.";

// ── Snippet runner errors ───────────────────────────────────────────

pub fn snippet_ssh_launch_failed(e: &impl std::fmt::Display) -> String {
    format!("Failed to launch ssh: {}", e)
}

// ── Vault SSH library errors ────────────────────────────────────────
//
// Reach the user via the anyhow chain that `ensure_vault_ssh_chain_if_needed`
// turns into a toast. `vault_create_dir_failed` and `vault_write_cert_failed`
// are with_context strings, so they appear after a colon in the error chain.

pub fn vault_create_dir_failed(path: &impl std::fmt::Display) -> String {
    format!("Failed to create {}", path)
}

pub fn vault_write_cert_failed(path: &impl std::fmt::Display) -> String {
    format!("Failed to write certificate to {}", path)
}

pub fn vault_ssh_keygen_run_failed(e: &impl std::fmt::Display) -> String {
    format!("Failed to run ssh-keygen: {}", e)
}

// ── Container library errors ────────────────────────────────────────
//
// Validation (`validate_container_id`) errors propagate via the
// `ContainerActionComplete` event and become toasts. The "no runtime"
// and "unknown sentinel" lines surface in the same path.

pub const CONTAINER_ID_EMPTY: &str = "Container ID must not be empty.";
pub const CONTAINER_RUNTIME_MISSING: &str = "No container runtime found. Install Docker or Podman.";

pub fn container_id_invalid_char(c: char) -> String {
    format!("Container ID contains invalid character: '{c}'")
}

pub fn container_unknown_sentinel(s: &str) -> String {
    format!("Unknown sentinel: {s}")
}

pub fn container_invalid_id(reason: &str) -> String {
    format!("Container exec blocked: {reason}")
}

/// Transient label shown on the file browser overlay while an scp transfer
/// is running. Singular form for a single source.
pub fn scp_copying_one(source: &str) -> String {
    format!("Copying {}...", source)
}

/// Transient label shown on the file browser overlay while an scp transfer
/// is running. Plural form when multiple files were selected at once.
pub fn scp_copying_many(count: usize) -> String {
    format!("Copying {} files...", count)
}

/// Toast shown when scp exited non-zero with no captured stderr to relay.
/// The exit code is the only signal we have left.
pub fn scp_failed_exit_code(code: i32) -> String {
    format!("Copy failed (exit code {}).", code)
}

/// Toast shown when the scp subprocess itself failed to spawn or wait
/// (e.g. binary missing, signal interrupted), distinct from a non-zero
/// exit which uses `scp_failed_exit_code`.
pub fn scp_spawn_failed(e: &impl std::fmt::Display) -> String {
    format!("scp failed: {}", e)
}

// ── Picker (password source, key, proxy) ────────────────────────────

pub const GLOBAL_DEFAULT_CLEARED: &str = "Global default cleared.";
pub const PASSWORD_SOURCE_CLEARED: &str = "Password source cleared.";
pub const ASKPASS_CUSTOM_COMMAND_HINT: &str =
    "Type your command. Use %a (alias) and %h (hostname) as placeholders.";

pub fn global_default_set(label: &str) -> String {
    format!("Global default set to {}.", label)
}

pub fn password_source_set(label: &str) -> String {
    format!("Password source set to {}.", label)
}

pub fn complete_path(label: &str) -> String {
    format!("Complete the {} path.", label)
}

pub fn key_selected(name: &str) -> String {
    format!("Locked and loaded with {}.", name)
}

// ── Keys tab ────────────────────────────────────────────────────────

/// Copy succeeded. Toast tells the user which key landed on the clipboard.
pub fn keys_copy_success(name: &str) -> String {
    format!("Copied {}.pub to clipboard.", name)
}

/// The .pub file could not be read from disk (deleted, permission denied).
pub fn keys_copy_read_failed(name: &str) -> String {
    format!("Could not read {}.pub from disk.", name)
}

/// Empty-state message for the keys tab when ~/.ssh/ has no public keys.
/// Kept short so it fits the narrow master pane on responsive collapse.
pub const KEYS_EMPTY_HINT: &str = "No SSH keys in ~/.ssh/. Run ssh-keygen.";

/// Empty-state message for the key-push picker when ~/.ssh/config has
/// no host entries to target.
pub const KEY_PUSH_NO_HOSTS: &str =
    "No hosts in ~/.ssh/config. Add a host first, then come back here.";

/// Header line for the Vault SSH strip when there is no Valid cached
/// cert. Tells the user how to populate the strip.
pub const VAULT_STRIP_EMPTY: &str =
    "  No active certs. Press V to sign all Vault SSH hosts at once.";

/// Inline tag appended to vault-ssh host rows in the push picker to
/// document why they cannot be selected.
pub const KEY_PUSH_VAULT_TAG: &str = "  (vault)";

/// Picker overlay title formats.
pub fn key_push_picker_title_eligible(key_label: &str, eligible: usize, total: usize) -> String {
    format!(
        "Push {} \u{203A} Select Hosts ({} eligible of {})",
        key_label, eligible, total
    )
}

pub fn key_push_picker_title_selected(
    key_label: &str,
    selected: usize,
    total: usize,
    eligible: usize,
) -> String {
    format!(
        "Push {} \u{203A} {} selected of {} ({} eligible)",
        key_label, selected, total, eligible
    )
}

/// Toast when the user presses `p` but no public key file is readable.
pub fn key_push_no_pubkey(name: &str) -> String {
    format!(
        "Cannot read {}.pub. The file is missing or unreadable.",
        name
    )
}

/// Toast when the user committed the picker with zero hosts selected.
pub const KEY_PUSH_NONE_SELECTED: &str = "Select at least one host with Space.";

/// Toast shown when the user tries to select a vault-ssh host. These
/// hosts are managed via signed certs (`V`), not static authorized_keys
/// appends.
pub const KEY_PUSH_VAULT_SKIP: &str =
    "Vault SSH host. Use V on the host list to sign a cert instead.";

/// Progress toast at the start of a push run.
pub fn key_push_in_progress(key_name: &str, host_count: usize) -> String {
    format!("Pushing {} to {} host(s)...", key_name, host_count)
}

/// Error toast when std::thread::spawn fails (essentially OOM / rlimit).
pub fn key_push_thread_spawn_failed() -> String {
    "Could not spawn push worker thread. Check resource limits.".to_string()
}

/// Warning toast when the user presses `p` while a push is still
/// running. Tells them how to recover.
pub const KEY_PUSH_ALREADY_IN_PROGRESS: &str =
    "A push is already running. Press Esc to cancel first.";

/// Error toast when the `.pub` file is not a regular file, is a symlink,
/// or could not be opened with `O_NOFOLLOW`. Stops the push before any
/// remote SSH call is made.
pub fn key_push_pubkey_not_regular(name: &str) -> String {
    format!("{}.pub is not a regular file. Symlinks are rejected.", name)
}

/// Error toast when the `.pub` file exceeds the 16 KiB cap. The most
/// common cause is a `.pub` symlink that resolved to a log file or a
/// truncated dump from an unrelated tool.
pub fn key_push_pubkey_too_large(name: &str, bytes: u64) -> String {
    format!(
        "{}.pub is {} bytes, larger than the 16 KiB push limit.",
        name, bytes
    )
}

/// Error toast when the `.pub` file does not parse as a single, valid
/// `authorized_keys` line. Catches multi-line content (which silently
/// installs multiple entries, including embedded `command=` clauses),
/// unsupported algorithms, and malformed base64 blobs.
pub fn key_push_invalid_pubkey(name: &str, detail: &str) -> String {
    format!("{}.pub failed validation: {}. Push aborted.", name, detail)
}

/// Error toast when the picker commits with zero eligible aliases. The
/// picker should always block this earlier, but the worker guard exists
/// as a defence-in-depth so the progress toast never sticks.
pub const KEY_PUSH_NO_HOSTS_SELECTED: &str =
    "Picker committed with no eligible hosts. Push aborted.";

/// Error toast when the user tries to push a certificate file. Pushing
/// a cert into authorized_keys bypasses its TTL and undermines the
/// signed-cert workflow.
pub const KEY_PUSH_CERT_NOT_PUSHABLE: &str =
    "Certificates cannot be pushed as static keys. Sign with V instead.";

/// Toast after the user pressed Esc to cancel an in-flight push run.
/// Names the per-host progress at the moment of cancel so the user
/// knows what may or may not have already been authorized.
pub fn key_push_cancelled(done: usize, total: usize) -> String {
    format!(
        "Push cancelled after {} of {} host(s). Re-run to finish the rest.",
        done, total,
    )
}

/// Body line shown inside the confirm dialog.
pub fn key_push_confirm_body(key_name: &str, host_count: usize) -> String {
    if host_count == 1 {
        format!("Push {} to 1 host?", key_name)
    } else {
        format!("Push {} to {} hosts?", key_name, host_count)
    }
}

/// Toast after a fully successful push run.
pub fn key_push_success(appended: usize, already: usize) -> String {
    if appended == 0 && already > 0 {
        format!("Key already present on {} host(s). Nothing to do.", already)
    } else if already == 0 {
        format!("Pushed to {} host(s).", appended)
    } else {
        format!(
            "Pushed to {} host(s). Already present on {}.",
            appended, already
        )
    }
}

/// Toast after a partial-failure push run. The detailed per-host errors
/// land in the sticky-error overlay rendered separately.
pub fn key_push_partial_failure(succeeded: usize, failed: usize) -> String {
    format!("Pushed to {} host(s). {} failed.", succeeded, failed)
}

/// Sticky-error overlay body when every host failed.
pub fn key_push_all_failed(count: usize) -> String {
    format!(
        "Push failed for all {} host(s). Check the host log for details.",
        count
    )
}

pub fn proxy_jump_set(alias: &str) -> String {
    format!("Jumping through {}.", alias)
}

pub fn save_default_failed(e: &impl std::fmt::Display) -> String {
    format!("Failed to save default: {}", e)
}

// ── Containers ──────────────────────────────────────────────────────

pub fn container_action_complete(action: &str) -> String {
    format!("Container {} complete.", action)
}

pub const HOST_KEY_UNKNOWN: &str = "Host key unknown. Connect first (Enter) to trust the host.";
pub const HOST_KEY_CHANGED: &str =
    "Host key changed. Possible tampering or server re-install. Clear with ssh-keygen -R.";

// User-friendly classifications of stderr from a remote `docker ps` /
// `podman ps`. The raw stderr is too technical and varies across
// distros; these phrasings give the user the actionable next step.
pub const CONTAINER_RUNTIME_NOT_FOUND: &str = "Docker or Podman not found on remote host.";
pub const CONTAINER_PERMISSION_DENIED: &str =
    "Permission denied. Is your user in the docker group?";
pub const CONTAINER_DAEMON_NOT_RUNNING: &str = "Container daemon is not running.";
pub const CONTAINER_CONNECTION_REFUSED: &str = "Connection refused.";
pub const CONTAINER_HOST_UNREACHABLE: &str = "Host unreachable.";

/// Generic fallback when none of the container error classifiers
/// matched. The exit code is the only signal we can show without
/// leaking unfiltered remote stderr.
pub fn container_command_failed(code: i32) -> String {
    format!("Command failed with code {}.", code)
}

/// `docker inspect` returned no JSON (empty array or empty stdout).
pub const CONTAINER_INSPECT_EMPTY: &str = "Inspect returned no data.";

/// `docker inspect` stdout was not valid JSON.
pub fn container_inspect_parse_failed(reason: &str) -> String {
    format!("Inspect parse failed: {}", reason)
}

// ── Container exec (Enter on containers overview) ──────────────────

/// User pressed Enter on a non-running container.
pub fn container_not_running(name: &str) -> String {
    format!("{} is not running. Cannot exec.", name)
}

/// Demo mode interactive guard.
pub const DEMO_CONTAINER_EXEC_DISABLED: &str = "Demo mode: container exec disabled.";

/// Tmux mode opened a new window for the exec session.
pub fn container_exec_opened_in_tmux(name: &str, alias: &str) -> String {
    format!("Opened {} on {} in tmux window.", name, alias)
}

/// Interactive shell exited cleanly.
pub fn container_exec_ended(name: &str) -> String {
    format!("Container shell ended: {}.", name)
}

/// Interactive shell failed with a parsed stderr reason.
pub fn container_exec_failed_with_reason(name: &str, reason: &str) -> String {
    format!("Container exec failed for {}: {}", name, reason)
}

/// Interactive shell exited non-zero with no stderr reason.
pub fn container_exec_exited_with_code(name: &str, code: i32) -> String {
    format!("Container exec for {} exited with code {}.", name, code)
}

/// `Command::new("ssh").spawn()` failed.
pub fn container_exec_spawn_failed(name: &str) -> String {
    format!("Failed to launch ssh for container {}.", name)
}

/// Exec prompt rejected the typed command (control chars, newline).
pub const CONTAINER_EXEC_INVALID_COMMAND: &str =
    "Command rejected: control characters not allowed.";

// ── Container logs (l) ─────────────────────────────────────────────

/// Title shown in the logs overlay border for "logs are loading".
pub const CONTAINER_LOGS_LOADING: &str = "fetching logs…";

/// Title for "logs are ready". Uses the short relative-time format
/// (12s, 5m, 2h) so the badge stays compact regardless of staleness.
pub fn container_logs_fetched(secs_ago: u64) -> String {
    format!(
        "fetched {} ago",
        crate::containers::format_uptime_short(secs_ago)
    )
}

/// Title for "logs fetch failed".
pub fn container_logs_failed(reason: &str) -> String {
    format!("logs fetch failed: {}", reason)
}

/// Search position badge for the logs overlay: `3 of 12` while the
/// user navigates `/foo` matches with n/N.
pub fn container_logs_search_position(current: usize, total: usize) -> String {
    format!("{} of {}", current, total)
}

/// Search badge when the query has no hits in the current body.
pub const CONTAINER_LOGS_SEARCH_NO_MATCHES: &str = "no matches";

// ── Container restart/stop (K / S) ─────────────────────────────────

/// Confirm body line that summarises a destructive action's mechanics.
pub const CONTAINER_RESTART_BODY: &str =
    "Sends SIGTERM, waits 10s, then SIGKILL. Live connections will drop.";
pub const CONTAINER_STOP_BODY: &str = "Sends SIGTERM, waits 10s, then SIGKILL. Container will not restart unless its policy reschedules it.";

// ── Container stack restart (Ctrl-K) ───────────────────────────────

pub fn container_stack_unknown(name: &str) -> String {
    format!("Stack unknown for {}: open the detail panel first.", name)
}

pub fn container_stack_no_running(project: &str) -> String {
    format!("Stack {} has no running members to restart.", project)
}

pub const CONTAINER_STACK_RESTART_BODY: &str = "Restart cycles every running member one by one. Exited members are not touched. Live connections will drop.";

// ── Container host-wide bulk actions (K / S on a divider) ──────────

/// Body line on the bulk-restart-host confirm dialog. Same mechanics
/// as a single restart but spelled out so the user knows it walks the
/// host one container at a time.
pub const CONTAINER_HOST_RESTART_ALL_BODY: &str = "Restart cycles every running container on the host one by one. Exited containers are not touched. Live connections will drop.";

/// Body line on the bulk-stop-host confirm dialog.
pub const CONTAINER_HOST_STOP_ALL_BODY: &str = "Stops every running container on the host one by one. Exited containers are not touched. Restart policies may reschedule them.";

/// Footer toast when the user presses a single-target action key (l, e)
/// while the cursor is parked on a host-divider row. Steers the user
/// back to a container row instead of silently no-op'ing. `action` is
/// lowercased for sentence-case readability ("logs needs..." reads
/// better than "Logs applies...").
pub fn container_action_needs_single(action: &str) -> String {
    format!(
        "{} need a single container. Place the cursor on a container row.",
        action.to_lowercase()
    )
}

/// Toast when bulk K/S on a divider finds no running containers.
pub fn container_host_no_running(alias: &str) -> String {
    format!("No running containers on {}.", alias)
}

// ── Container refresh (r / R / a) ──────────────────────────────────

/// `r` keypress: single-host refresh started.
pub fn container_refreshing(alias: &str) -> String {
    format!("Refreshing {}…", alias)
}

/// `R` keypress while a previous batch is still in flight.
pub const REFRESH_BATCH_ALREADY_RUNNING: &str = "Refresh already in progress.";

/// `R` keypress on an empty container cache.
pub const REFRESH_NOTHING_TO_REFRESH: &str = "No cached hosts to refresh. Press 'a' to add a host.";

/// Batch progress readout shown in the status footer.
pub fn container_refresh_progress(done: usize, total: usize) -> String {
    format!("Refreshing {}/{} hosts…", done, total)
}

/// Batch completed.
pub fn container_refresh_complete(total: usize) -> String {
    format!(
        "Refreshed {} host{}.",
        total,
        if total == 1 { "" } else { "s" }
    )
}

/// Host picker: no hosts match the live query.
pub const CONTAINER_HOST_PICKER_NO_MATCH: &str = "No hosts match.";

/// Host picker: every host already has a cache entry.
pub const CONTAINER_HOST_PICKER_NOTHING_TO_ADD: &str =
    "All hosts already cached. Use 'r' or 'R' to refresh.";

// ── Import ──────────────────────────────────────────────────────────

pub fn imported_hosts(imported: usize, skipped: usize) -> String {
    format!(
        "Imported {} host{}, skipped {} duplicate{}.",
        imported,
        if imported == 1 { "" } else { "s" },
        skipped,
        if skipped == 1 { "" } else { "s" }
    )
}

pub fn all_hosts_exist(skipped: usize) -> String {
    if skipped == 1 {
        "Host already exists.".to_string()
    } else {
        format!("All {} hosts already exist.", skipped)
    }
}

// ── SSH config repair ───────────────────────────────────────────────

pub fn config_repaired(groups: usize, orphaned: usize) -> String {
    format!(
        "Repaired SSH config ({} absorbed, {} orphaned group headers).",
        groups, orphaned
    )
}

pub fn no_exact_match(alias: &str) -> String {
    format!("No exact match for '{}'. Here's what we found.", alias)
}

pub fn group_pref_reset_failed(e: &impl std::fmt::Display) -> String {
    format!("Group preference reset. (save failed: {})", e)
}

// ── Connection ──────────────────────────────────────────────────────

pub fn opened_in_tmux(alias: &str) -> String {
    format!("Opened {} in new tmux window.", alias)
}

pub fn tmux_error(e: &impl std::fmt::Display) -> String {
    format!("tmux: {}", e)
}

pub fn connection_failed(alias: &str) -> String {
    format!("Connection to {} failed.", alias)
}

/// Stderr line printed when the ssh subprocess itself failed to spawn or
/// wait (e.g. binary missing, signal interrupted), distinct from a
/// non-zero exit code which the user sees via the toast.
pub fn connection_spawn_failed(e: &impl std::fmt::Display) -> String {
    format!("Connection failed: {}", e)
}

/// Toast shown when ssh exited non-zero with a captured stderr line we
/// can show. The reason is the trimmed last meaningful line of ssh stderr.
pub fn ssh_failed_with_reason(alias: &str, reason: &str) -> String {
    format!("SSH to {} failed. {}", alias, reason)
}

/// Toast shown when ssh exited non-zero with no captured stderr to relay.
/// The exit code is the only signal we have left.
pub fn ssh_exited_with_code(alias: &str, code: i32) -> String {
    format!("SSH to {} exited with code {}.", alias, code)
}

// ── Host key reset ──────────────────────────────────────────────────

pub fn host_key_remove_failed(stderr: &str) -> String {
    format!("Failed to remove host key: {}", stderr)
}

pub fn ssh_keygen_failed(e: &impl std::fmt::Display) -> String {
    format!("Failed to run ssh-keygen: {}", e)
}

// ── Transfer ────────────────────────────────────────────────────────

pub const TRANSFER_COMPLETE: &str = "Transfer complete.";

// ── Background / event loop ─────────────────────────────────────────

/// Per-provider sync progress line with a leading spinner frame so
/// `event_loop::handle_tick` animates the prefix while the message is
/// on screen. Format: `⠋ Proxmox VE: Resolving IPs (1/5)...`. Mirrors
/// the spinner contract used by `synced_progress` so the footer keeps
/// animating even when granular per-provider progress overrides the
/// batch summary mid-sync.
pub fn provider_progress(spinner: &str, name: &str, message: &str) -> String {
    format!("{} {}: {}", spinner, name, message)
}

// ── Relative age (detail panel "checked" suffix) ────────────────────

pub const AGE_JUST_NOW: &str = "just now";

/// Compact relative age: "just now", "12s ago", "3m ago", "2h ago",
/// "2d ago". Used in the detail panel so the reader can tell stale
/// data from fresh.
pub fn relative_age(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    if secs < 5 {
        AGE_JUST_NOW.to_string()
    } else if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

// ── Vault SSH bulk signing summaries (event_loop.rs) ────────────────

pub fn vault_config_reapply_failed(signed: usize, e: &impl std::fmt::Display) -> String {
    format!(
        "External edits detected; signed {} certs but failed to re-apply CertificateFile: {}",
        signed, e
    )
}

pub fn vault_external_edits_merged(summary: &str, reapplied: usize) -> String {
    format!(
        "{} External ssh config edits detected, merged {} CertificateFile directives.",
        summary, reapplied
    )
}

pub fn vault_external_edits_no_write(summary: &str) -> String {
    format!(
        "{} External ssh config edits detected; certs on disk, no CertificateFile written.",
        summary
    )
}

pub fn vault_reparse_failed(signed: usize, e: &impl std::fmt::Display) -> String {
    format!(
        "Signed {} certs but cannot re-parse ssh config after external edit: {}. \
         Certs are on disk under ~/.purple/certs/.",
        signed, e
    )
}

pub fn vault_config_update_failed(signed: usize, e: &impl std::fmt::Display) -> String {
    format!(
        "Signed {} certs but failed to update SSH config: {}",
        signed, e
    )
}

pub fn vault_config_write_after_sign(e: &impl std::fmt::Display) -> String {
    format!("Failed to update config after vault signing: {}", e)
}

pub fn vault_config_skipped_external_change() -> &'static str {
    "Config changed on disk since signing started. Cert files are saved; re-run vault sign to wire them up."
}

pub fn sync_skipped_external_change() -> &'static str {
    "Config changed on disk during sync. Re-run sync after reviewing your edits."
}

// ── File browser ────────────────────────────────────────────────────

// ── Confirm / host key ──────────────────────────────────────────────

pub fn removed_host_key(hostname: &str) -> String {
    format!("Removed host key for {}. Reconnecting...", hostname)
}

// ── Host detail (tags) ──────────────────────────────────────────────

pub fn tagged_host(alias: &str, count: usize) -> String {
    format!(
        "Tagged {} with {} label{}.",
        alias,
        count,
        if count == 1 { "" } else { "s" }
    )
}

// ── Config reload ───────────────────────────────────────────────────

pub fn config_reloaded(count: usize) -> String {
    format!("Config reloaded. {} hosts.", count)
}

// ── Sync background ─────────────────────────────────────────────────

/// In-progress sync line for the footer. Format:
/// `⠋ Syncing AWS, Hetzner · 1/3 (+12 ~3 -1)`.
/// Active provider names lead so the user immediately sees which provider
/// is currently in flight (especially relevant when one provider is slow).
/// `done/total` follows as a counter. The leading character is a braille
/// spinner frame rotated on every tick. The `(+a ~u -s)` suffix is omitted
/// when all counts are zero.
///
/// Callers MUST only invoke this when `active_names` is non-empty (i.e.
/// at least one provider is still in flight). The only call site is
/// `main::set_sync_summary`, which enters this branch via `still_syncing`,
/// itself gated on `!providers.syncing.is_empty()` — so `active_names`
/// (built from `syncing.keys()`) is guaranteed non-empty.
pub fn synced_progress(
    spinner: &str,
    active_names: &str,
    done: usize,
    total: usize,
    added: usize,
    updated: usize,
    stale: usize,
) -> String {
    debug_assert!(
        !active_names.is_empty(),
        "synced_progress must only be called while a provider is still in flight"
    );
    let diff = sync_diff_suffix(added, updated, stale);
    format!(
        "{} Syncing {} \u{00B7} {}/{}{}",
        spinner, active_names, done, total, diff
    )
}

/// Final sync summary for the footer once all providers in the batch have
/// completed. Format: `Synced 5/5 · AWS, DO, Vultr, Hetzner, Linode (+12 ~3 -1)`.
/// No spinner prefix, no auto-tick: the message expires by length-proportional
/// timeout once the batch is done.
pub fn synced_done(
    done: usize,
    total: usize,
    names: &str,
    added: usize,
    updated: usize,
    stale: usize,
) -> String {
    let diff = sync_diff_suffix(added, updated, stale);
    format!("Synced {}/{} \u{00B7} {}{}", done, total, names, diff)
}

fn sync_diff_suffix(added: usize, updated: usize, stale: usize) -> String {
    let parts: Vec<String> = [(added, '+'), (updated, '~'), (stale, '-')]
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, sign)| format!("{}{}", sign, n))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(" "))
    }
}

pub const SYNC_THREAD_SPAWN_FAILED: &str = "Failed to start sync thread.";

pub const SYNC_UNKNOWN_PROVIDER: &str = "Unknown provider.";

// ── Vault signing cancelled summary ─────────────────────────────────

pub fn vault_signing_cancelled_summary(
    signed: u32,
    failed: u32,
    first_error: Option<&str>,
) -> String {
    let mut msg = format!(
        "Vault SSH signing cancelled ({} signed, {} failed)",
        signed, failed
    );
    if let Some(err) = first_error {
        msg.push_str(": ");
        msg.push_str(err);
    }
    msg
}

// ── Region picker ───────────────────────────────────────────────────

pub fn regions_selected_count(count: usize, label: &str) -> String {
    let s = if count == 1 { "" } else { "s" };
    format!("{} {}{} selected.", count, label, s)
}

// ── Purge stale ─────────────────────────────────────────────────────

// ── Clipboard ───────────────────────────────────────────────────────

pub const NO_CLIPBOARD_TOOL: &str =
    "No clipboard tool found. Install pbcopy (macOS), wl-copy (Wayland), or xclip/xsel (X11).";

// ── MCP server ──────────────────────────────────────────────────────

pub const MCP_TOOL_DENIED_READ_ONLY: &str = "Tool denied. Server started with --read-only. Restart without --read-only to enable state-changing tools.";

/// Bare message body. Callers add the `[purple]` fault-domain prefix at
/// their `warn!` / `error!` site; the `eprintln!` startup diagnostic emits
/// this body directly without the tag.
pub fn mcp_audit_init_failed(path: &impl std::fmt::Display, e: &impl std::fmt::Display) -> String {
    format!(
        "Failed to initialise MCP audit log at {}: {}. Continuing without audit logging.",
        path, e
    )
}

/// Bare message body. Callers add `[purple]` at the log macro site.
pub fn mcp_audit_write_failed(e: &impl std::fmt::Display) -> String {
    format!("Failed to write MCP audit entry: {}", e)
}

/// Returned to the MCP client as `isError` content when the SSH config path
/// does not point to an existing file. Surfaces the bug class where a
/// missing-file silently yields an empty host list.
pub fn mcp_config_file_not_found(path: &impl std::fmt::Display) -> String {
    format!("SSH config file not found: {}", path)
}

/// Logged when `dirs::home_dir()` cannot resolve a home for the audit log
/// default. Auditing is silently disabled in this state, so the operator
/// needs an explicit cue.
pub const MCP_AUDIT_HOME_DIR_UNAVAILABLE: &str = "Could not determine home directory; MCP audit log disabled. Set --audit-log <PATH> explicitly to enable auditing.";

// ── Jump ─────────────────────────────────────────────────

/// Placeholder shown in the jump bar input when the query is empty.
pub const PALETTE_PLACEHOLDER: &str = "Find anything";
/// Empty-state copy when the current query has no matches.
pub const PALETTE_NO_RESULTS: &str = "No matches.";
/// Toast shown when the user dispatches a snippet from the jump bar while
/// no host is selected (the snippet picker needs at least one target).
pub const PALETTE_SNIPPET_NEEDS_HOST: &str =
    "Pick a host first, then run a snippet from the jump bar.";
/// Suffix appended to the truncated row list when the visible window is
/// smaller than the result list.
pub fn jump_more_rows(n: usize) -> String {
    format!("+{n} more (scroll down)")
}

// ── CLI messages ────────────────────────────────────────────────────

#[path = "messages/cli.rs"]
pub mod cli;
pub mod footer;

// ── Update messages ─────────────────────────────────────────────────

pub mod update {
    pub const WHATS_NEW_HINT: &str = "Press n inside purple to see what's new.";
    pub const DONE: &str = "done.";
    pub const CHECKSUM_OK: &str = "ok.";
    pub const SUDO_WARNING: &str =
        "Running via sudo. Consider fixing directory permissions instead.";

    /// Two-space-indented progress prefixes printed before each step.
    /// Trailing space is intentional so the success/fail glyph or
    /// `DONE` constant follows on the same line, matching the visual
    /// rhythm of the updater output.
    pub const STEP_CHECKING: &str = "  Checking for updates... ";
    pub const STEP_VERIFYING_CHECKSUM: &str = "  Verifying checksum... ";
    pub const STEP_INSTALLING: &str = "  Installing... ";

    pub fn already_on(current: &str) -> String {
        format!("already on v{} (latest).", current)
    }

    pub fn available(latest: &str, current: &str) -> String {
        format!("v{} available (current: v{}).", latest, current)
    }

    /// Two-space-indented progress prefix for the download step. Matches
    /// the trailing-space convention of the other STEP_* constants so
    /// the next print resumes on the same line.
    pub fn step_downloading(version: &str) -> String {
        format!("  Downloading v{}... ", version)
    }

    /// Indented sudo warning rendered before the download step. The
    /// caller passes a pre-bolded bang (`!`) so the line reads
    /// `  ! Running via sudo. ...` with the `!` emphasized.
    pub fn sudo_warning_line(bold_bang: &str) -> String {
        format!("  {} {}", bold_bang, SUDO_WARNING)
    }

    pub fn header(bold_name: &str) -> String {
        format!("\n  {} updater\n", bold_name)
    }

    pub fn binary_path(path: &std::path::Path) -> String {
        format!("  Binary: {}", path.display())
    }

    pub fn installed_at(bold_version: &str, path: &std::path::Path) -> String {
        format!("\n  {} installed at {}.", bold_version, path.display())
    }

    pub fn whats_new_hint_indented() -> String {
        format!("\n  {}", WHATS_NEW_HINT)
    }
}

// ── Askpass / password prompts ───────────────────────────────────────

pub mod askpass {
    pub const BW_NOT_FOUND: &str = "Bitwarden CLI (bw) not found. SSH will prompt for password.";
    pub const BW_NOT_LOGGED_IN: &str = "Bitwarden vault not logged in. Run 'bw login' first.";
    pub const EMPTY_PASSWORD: &str = "Empty password. SSH will prompt for password.";
    pub const PASSWORD_IN_KEYCHAIN: &str = "Password stored in keychain.";

    pub fn read_failed(e: &impl std::fmt::Display) -> String {
        format!("Failed to read password: {}", e)
    }

    pub fn unlock_failed_retry(e: &impl std::fmt::Display) -> String {
        format!("Unlock failed: {}. Try again.", e)
    }

    pub fn unlock_failed_prompt(e: &impl std::fmt::Display) -> String {
        format!("Unlock failed: {}. SSH will prompt for password.", e)
    }

    /// CLI prompt shown by the inline askpass path when the user has no
    /// stored credential yet. The trailing space is intentional — the
    /// reader echoes user input directly after.
    pub fn password_prompt(alias: &str) -> String {
        format!("Password for {}: ", alias)
    }

    /// CLI prompt shown when keychain storage is the sink. Reminds the
    /// user that the entry will be persisted, not just used once.
    pub fn keychain_password_prompt(alias: &str) -> String {
        format!("Password for {} (stored in keychain): ", alias)
    }

    /// Stderr line emitted when the keychain `add-generic-password` call
    /// failed. The user falls back to ssh's own prompt on the next try.
    pub fn keychain_store_failed(e: &impl std::fmt::Display) -> String {
        format!(
            "Failed to store in keychain: {}. SSH will prompt for password.",
            e
        )
    }

    pub const PROTON_NOT_FOUND: &str =
        "Proton Pass CLI (pass-cli) not found. SSH will prompt for password.";

    pub const PROTON_LOGIN_PROMPT: &str = "Proton Pass PAT: ";

    pub const PROTON_LOGIN_SUCCESS: &str = "Logged in to Proton Pass.";

    pub fn proton_login_failed_retry(e: &impl std::fmt::Display) -> String {
        format!("Proton Pass login failed: {}. Try again.", e)
    }

    pub fn proton_login_failed_prompt(e: &impl std::fmt::Display) -> String {
        format!(
            "Proton Pass login failed: {}. SSH will prompt for password.",
            e
        )
    }
}

// ── Logging ─────────────────────────────────────────────────────────

pub mod logging {
    pub fn init_failed(e: &impl std::fmt::Display) -> String {
        format!("[purple] Failed to initialize logger: {}", e)
    }

    pub const SSH_VERSION_FAILED: &str = "[purple] Failed to detect SSH version. Is ssh installed?";
}

// ── Form field hints / placeholders ─────────────────────────────────
//
// Dimmed placeholder text shown in empty form fields. Centralized here
// so every user-visible string lives in one place and is auditable.

pub mod hints {
    // ── Shared ──────────────────────────────────────────────────────
    // Picker hints mention "Space" because per the design system keyboard
    // invariants, Enter always submits a form; pickers open on Space.
    // Keep these strings in sync with scripts/check-keybindings.sh.
    pub const IDENTITY_FILE_PICK: &str = "Space to pick a key";
    pub const DEFAULT_SSH_USER: &str = "root";

    // ── Host form ───────────────────────────────────────────────────
    pub const HOST_ALIAS: &str = "e.g. prod or db-01";
    pub const HOST_ALIAS_PATTERN: &str = "10.0.0.* or *.example.com";
    pub const HOST_HOSTNAME: &str = "192.168.1.1 or example.com";
    pub const HOST_PORT: &str = "22";
    pub const HOST_PROXY_JUMP: &str = "Space to pick a host";
    pub const HOST_VAULT_SSH: &str = "e.g. ssh-client-signer/sign/my-role (auth via vault login)";
    pub const HOST_VAULT_SSH_PICKER: &str = "Space to pick a role or type one";
    pub const HOST_VAULT_ADDR: &str =
        "e.g. http://127.0.0.1:8200 (inherits from provider or env when empty)";
    pub const HOST_TAGS: &str = "e.g. prod, staging, us-east (comma-separated)";
    pub const HOST_ASKPASS_PICK: &str = "Space to pick a source";

    pub fn askpass_default(default: &str) -> String {
        format!("default: {}", default)
    }

    pub fn inherits_from(value: &str, provider: &str) -> String {
        format!("inherits {} from {}", value, provider)
    }

    // ── Tunnel form ─────────────────────────────────────────────────
    pub const TUNNEL_BIND_PORT: &str = "8080";
    pub const TUNNEL_REMOTE_HOST: &str = "localhost";
    pub const TUNNEL_REMOTE_PORT: &str = "80";

    // ── Snippet form ────────────────────────────────────────────────
    pub const SNIPPET_NAME: &str = "check-disk";
    pub const SNIPPET_COMMAND: &str = "df -h";
    pub const SNIPPET_OPTIONAL: &str = "(optional)";

    // ── Provider form ───────────────────────────────────────────────
    pub const PROVIDER_URL: &str = "https://pve.example.com:8006";
    pub const PROVIDER_TOKEN_DEFAULT: &str = "your-api-token";
    pub const PROVIDER_TOKEN_PROXMOX: &str = "user@pam!token=secret";
    pub const PROVIDER_TOKEN_AWS: &str = "AccessKeyId:Secret (or use Profile)";
    pub const PROVIDER_TOKEN_GCP: &str = "/path/to/service-account.json (or access token)";
    pub const PROVIDER_TOKEN_AZURE: &str = "/path/to/service-principal.json (or access token)";
    pub const PROVIDER_TOKEN_TAILSCALE: &str = "API key (leave empty for local CLI)";
    pub const PROVIDER_TOKEN_ORACLE: &str = "~/.oci/config";
    pub const PROVIDER_TOKEN_OVH: &str = "app_key:app_secret:consumer_key";
    pub const PROVIDER_PROFILE: &str = "Name from ~/.aws/credentials (or use Token)";
    pub const PROVIDER_PROJECT_DEFAULT: &str = "my-gcp-project-id";
    pub const PROVIDER_PROJECT_OVH: &str = "Public Cloud project ID";
    pub const PROVIDER_COMPARTMENT: &str = "ocid1.compartment.oc1..aaaa...";
    pub const PROVIDER_REGIONS_DEFAULT: &str = "Space to select regions";
    pub const PROVIDER_REGIONS_GCP: &str = "Space to select zones (empty = all)";
    pub const PROVIDER_REGIONS_SCALEWAY: &str = "Space to select zones";
    // Azure regions is a text input (not a picker), so no key is mentioned.
    pub const PROVIDER_REGIONS_AZURE: &str = "comma-separated subscription IDs";
    pub const PROVIDER_REGIONS_OVH: &str = "Space to select endpoint (default: EU)";
    pub const PROVIDER_USER_AWS: &str = "ec2-user";
    pub const PROVIDER_USER_GCP: &str = "ubuntu";
    pub const PROVIDER_USER_AZURE: &str = "azureuser";
    pub const PROVIDER_USER_ORACLE: &str = "opc";
    pub const PROVIDER_USER_OVH: &str = "ubuntu";
    pub const PROVIDER_VAULT_ROLE: &str =
        "e.g. ssh-client-signer/sign/my-role (vault login; inherited)";
    pub const PROVIDER_VAULT_ADDR: &str = "e.g. http://127.0.0.1:8200 (inherited by all hosts)";
    pub const PROVIDER_ALIAS_PREFIX_DEFAULT: &str = "prefix";
}

#[cfg(test)]
mod hints_tests {
    use super::hints;

    #[test]
    fn askpass_default_formats() {
        assert_eq!(hints::askpass_default("keychain"), "default: keychain");
    }

    #[test]
    fn askpass_default_formats_empty() {
        assert_eq!(hints::askpass_default(""), "default: ");
    }

    #[test]
    fn inherits_from_formats() {
        assert_eq!(
            hints::inherits_from("role/x", "aws"),
            "inherits role/x from aws"
        );
    }

    #[test]
    fn picker_hints_mention_space_not_enter() {
        // Per the keyboard invariants, pickers open on Space.
        // If these assertions fail, audit scripts/check-keybindings.sh too.
        for s in [
            hints::IDENTITY_FILE_PICK,
            hints::HOST_PROXY_JUMP,
            hints::HOST_VAULT_SSH_PICKER,
            hints::HOST_ASKPASS_PICK,
            hints::PROVIDER_REGIONS_DEFAULT,
            hints::PROVIDER_REGIONS_GCP,
            hints::PROVIDER_REGIONS_SCALEWAY,
            hints::PROVIDER_REGIONS_OVH,
        ] {
            assert!(
                s.starts_with("Space "),
                "picker hint must mention Space: {s}"
            );
            assert!(!s.contains("Enter "), "picker hint must not say Enter: {s}");
        }
    }
}

#[path = "messages/whats_new.rs"]
pub mod whats_new;

#[path = "messages/whats_new_toast.rs"]
pub mod whats_new_toast;

#[cfg(test)]
mod stale_host_tests {
    use super::stale_host;

    #[test]
    fn empty_hint_returns_bare_sentence() {
        assert_eq!(stale_host(""), "Stale host.");
    }

    #[test]
    fn empty_after_trim_returns_bare_sentence() {
        assert_eq!(stale_host("   "), "Stale host.");
    }

    #[test]
    fn provider_hint_is_appended_with_space_and_period() {
        assert_eq!(
            stale_host("Gone from DigitalOcean"),
            "Stale host. Gone from DigitalOcean."
        );
    }

    #[test]
    fn trailing_period_in_hint_is_not_doubled() {
        assert_eq!(
            stale_host("Gone from DigitalOcean."),
            "Stale host. Gone from DigitalOcean."
        );
    }

    #[test]
    fn leading_space_in_hint_is_trimmed() {
        assert_eq!(stale_host(" Gone from AWS"), "Stale host. Gone from AWS.");
    }
}

#[cfg(test)]
mod relative_age_tests {
    use super::relative_age;
    use std::time::Duration;

    #[test]
    fn relative_age_boundaries() {
        assert_eq!(relative_age(Duration::from_secs(0)), "just now");
        assert_eq!(relative_age(Duration::from_secs(4)), "just now");
        assert_eq!(relative_age(Duration::from_secs(5)), "5s ago");
        assert_eq!(relative_age(Duration::from_secs(59)), "59s ago");
        assert_eq!(relative_age(Duration::from_secs(60)), "1m ago");
        assert_eq!(relative_age(Duration::from_secs(3599)), "59m ago");
        assert_eq!(relative_age(Duration::from_secs(3600)), "1h ago");
        assert_eq!(relative_age(Duration::from_secs(86399)), "23h ago");
        assert_eq!(relative_age(Duration::from_secs(86400)), "1d ago");
        assert_eq!(relative_age(Duration::from_secs(86400 * 7)), "7d ago");
    }
}
