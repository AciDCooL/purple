//! AppEvent dispatch grouped by domain. Each submodule owns a coherent
//! slice of the channel surface (lifecycle, provider sync, file
//! transfer, snippet runs, key push, container ops, vault signing) and
//! exposes its handlers as `pub(crate)` so the main event loop in
//! `tui_loop.rs` and the per-domain integration tests can call
//! `event_loop::handle_X` directly via the glob re-exports below.

pub(crate) mod containers;
pub(crate) mod file_transfer;
pub(crate) mod key_push;
pub(crate) mod lifecycle;
pub(crate) mod provider_sync;
pub(crate) mod snippet;
pub(crate) mod vault;

pub(crate) use containers::{
    handle_container_action_complete, handle_container_inspect_complete, handle_container_listing,
    handle_container_logs_complete, handle_container_logs_tail_complete,
};
// drive_refresh_batch is an internal helper for handle_container_listing
// and is only reached from tests; re-export under cfg(test) so the bin
// build does not flag it as unused.
#[cfg(test)]
pub(crate) use containers::drive_refresh_batch;
pub(crate) use file_transfer::{handle_file_browser_listing, handle_scp_complete};
pub(crate) use key_push::handle_key_push_result;
pub(crate) use lifecycle::{handle_ping_result, handle_tick, handle_update_available};
pub(crate) use provider_sync::{
    handle_sync_complete, handle_sync_error, handle_sync_partial, handle_sync_progress,
};
pub(crate) use snippet::{
    handle_snippet_all_done, handle_snippet_host_done, handle_snippet_progress,
};
pub(crate) use vault::{
    handle_cert_check_error, handle_cert_check_result, handle_vault_sign_all_done,
    handle_vault_sign_progress, handle_vault_sign_result,
};
