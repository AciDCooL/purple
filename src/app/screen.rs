//! Screen enum: tags the currently-displayed overlay or view.

use std::path::PathBuf;

/// Top-level page selected via the top navigation bar.
///
/// Orthogonal to [`Screen`]. `Screen` tracks overlays and modal forms,
/// `TopPage` tracks which base view (hosts, tunnels, containers) renders
/// behind them. Tab/Shift+Tab cycles through the variants when no overlay
/// is active.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TopPage {
    #[default]
    Hosts,
    Tunnels,
    Containers,
}

impl TopPage {
    /// Cycle to the next page (Hosts -> Tunnels -> Containers -> Hosts).
    pub fn next(self) -> Self {
        match self {
            TopPage::Hosts => TopPage::Tunnels,
            TopPage::Tunnels => TopPage::Containers,
            TopPage::Containers => TopPage::Hosts,
        }
    }

    /// Cycle to the previous page (Hosts -> Containers -> Tunnels -> Hosts).
    pub fn prev(self) -> Self {
        match self {
            TopPage::Hosts => TopPage::Containers,
            TopPage::Tunnels => TopPage::Hosts,
            TopPage::Containers => TopPage::Tunnels,
        }
    }
}

/// State for the What's New overlay.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct WhatsNewState {
    pub scroll: u16,
}

/// One running compose-stack member surfaced in the stack-restart
/// confirm dialog. Carried so the confirm body can list every
/// container that will be cycled, identity-and-state-clear.
#[derive(Debug, Clone, PartialEq)]
pub struct StackMember {
    pub container_id: String,
    pub container_name: String,
    pub uptime: Option<String>,
}

/// Which screen is currently displayed.
#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    HostList,
    AddHost,
    EditHost {
        alias: String,
    },
    ConfirmDelete {
        alias: String,
    },
    Help {
        return_screen: Box<Screen>,
    },
    KeyList,
    KeyDetail {
        index: usize,
    },
    HostDetail {
        index: usize,
    },
    TagPicker,
    ThemePicker,
    Providers,
    ProviderForm {
        id: crate::providers::config::ProviderConfigId,
    },
    /// Step 1 of the lazy add-second-config flow: ask the user to pick a
    /// label for the existing (bare) config of `provider` before opening
    /// the new-config form. The chosen label lives on
    /// `app.providers.pending_label_migration` until step 2 saves both
    /// configs together.
    ProviderLabelMigration {
        provider: String,
    },
    TunnelList {
        alias: String,
    },
    TunnelForm {
        alias: String,
        editing: Option<usize>,
    },
    /// Host picker reached from the Tunnels overview when adding a new
    /// tunnel: the user must choose a host before the tunnel form opens.
    /// On confirm, transitions to `TunnelForm { alias, editing: None }`.
    TunnelHostPicker,
    SnippetPicker {
        target_aliases: Vec<String>,
    },
    SnippetForm {
        target_aliases: Vec<String>,
        editing: Option<usize>,
    },
    SnippetOutput {
        snippet_name: String,
        target_aliases: Vec<String>,
    },
    SnippetParamForm {
        snippet: crate::snippet::Snippet,
        target_aliases: Vec<String>,
    },
    ConfirmHostKeyReset {
        alias: String,
        hostname: String,
        known_hosts_path: String,
        askpass: Option<String>,
    },
    FileBrowser {
        alias: String,
    },
    Containers {
        alias: String,
    },
    /// Picker reached from the containers overview when adding a host
    /// to the cache (`a`). Lists hosts that have no cache entry yet;
    /// on Enter, spawns a `docker ps` listing for the chosen host and
    /// returns to the overview.
    ContainerHostPicker,
    /// One-shot logs viewer for a single container. `body` is empty
    /// while the SSH `docker logs --tail 200` call is in flight; once
    /// the result lands the lines populate it. `scroll` is line-based,
    /// `0` is the top. `last_render_height` is written by the renderer
    /// each frame so the logs-arrival path and `G` can compute the
    /// tail-anchored scroll without guessing the visible-area size.
    ContainerLogs {
        alias: String,
        container_id: String,
        container_name: String,
        body: Vec<String>,
        fetched_at: u64,
        error: Option<String>,
        scroll: u16,
        last_render_height: u16,
    },
    /// Confirm dialog for `K` (kick). restart a single running
    /// container. Reuses `route_confirm_key` so y/n/Esc are the only
    /// effective inputs; stake-test footer phrases the verb on both
    /// sides.
    ConfirmContainerRestart {
        alias: String,
        container_id: String,
        container_name: String,
        project: Option<String>,
        uptime: Option<String>,
    },
    /// Confirm dialog for `S` (stop). stop a single running container.
    /// Same key contract as ConfirmContainerRestart.
    ConfirmContainerStop {
        alias: String,
        container_id: String,
        container_name: String,
        project: Option<String>,
        uptime: Option<String>,
    },
    /// Single-line prompt for an arbitrary command to run inside the
    /// container via `docker exec -it`. Submit hits the existing
    /// `pending_container_exec` flow with the typed command in place
    /// of the default `bash || sh`.
    ContainerExecPrompt {
        alias: String,
        container_id: String,
        container_name: String,
        query: String,
    },
    /// Confirm dialog for `Ctrl-K` (stack kick). Restarts every running
    /// member of a compose stack on a single host, sequentially. The
    /// drain queue + 30s cache TTL pace the work; we accept the trivial
    /// per-tick interleaving.
    ConfirmStackRestart {
        alias: String,
        project: String,
        members: Vec<StackMember>,
    },
    /// Confirm dialog for `K` pressed on a host-divider row in the
    /// containers overview. Restarts every running container on the
    /// host, ignoring compose-project boundaries. Shares the bulk
    /// confirm shape with `ConfirmStackRestart`.
    ConfirmHostRestartAll {
        alias: String,
        members: Vec<StackMember>,
    },
    /// Confirm dialog for `S` pressed on a host-divider row. Stops
    /// every running container on the host, sequentially.
    ConfirmHostStopAll {
        alias: String,
        members: Vec<StackMember>,
    },
    ConfirmImport {
        count: usize,
    },
    ConfirmPurgeStale {
        aliases: Vec<String>,
        provider: Option<String>,
    },
    ConfirmVaultSign {
        /// Precomputed list of (alias, role, certificate_file, pubkey_path) for
        /// hosts that resolve to a vault SSH role. Computed when the user
        /// presses `V`. `certificate_file` is the host's existing
        /// `CertificateFile` directive (empty when unset) and is needed so the
        /// background worker checks renewal status against the actually
        /// configured cert path rather than purple's default.
        signable: Vec<(String, String, String, PathBuf, Option<String>)>,
    },
    Welcome {
        has_backup: bool,
        host_count: usize,
        known_hosts_count: usize,
    },
    /// Bulk tag editor: tri-state checkbox picker that edits tags across
    /// all hosts in `multi_select` in one go. Opened via `t` when a
    /// multi-host selection is active.
    BulkTagEditor,
    /// What's New overlay: shows recent changelog sections to the user
    /// after an upgrade. Opened via the upgrade toast or `n` key.
    WhatsNew(WhatsNewState),
}

impl Screen {
    /// Stable short variant name used in state-transition logs.
    /// Omits inner fields so log lines never leak host aliases, paths or
    /// tokens.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Screen::HostList => "HostList",
            Screen::AddHost => "AddHost",
            Screen::EditHost { .. } => "EditHost",
            Screen::ConfirmDelete { .. } => "ConfirmDelete",
            Screen::Help { .. } => "Help",
            Screen::KeyList => "KeyList",
            Screen::KeyDetail { .. } => "KeyDetail",
            Screen::HostDetail { .. } => "HostDetail",
            Screen::TagPicker => "TagPicker",
            Screen::ThemePicker => "ThemePicker",
            Screen::Providers => "Providers",
            Screen::ProviderForm { .. } => "ProviderForm",
            Screen::ProviderLabelMigration { .. } => "ProviderLabelMigration",
            Screen::TunnelList { .. } => "TunnelList",
            Screen::TunnelForm { .. } => "TunnelForm",
            Screen::TunnelHostPicker => "TunnelHostPicker",
            Screen::SnippetPicker { .. } => "SnippetPicker",
            Screen::SnippetForm { .. } => "SnippetForm",
            Screen::SnippetOutput { .. } => "SnippetOutput",
            Screen::SnippetParamForm { .. } => "SnippetParamForm",
            Screen::ConfirmHostKeyReset { .. } => "ConfirmHostKeyReset",
            Screen::FileBrowser { .. } => "FileBrowser",
            Screen::Containers { .. } => "Containers",
            Screen::ContainerHostPicker => "ContainerHostPicker",
            Screen::ContainerLogs { .. } => "ContainerLogs",
            Screen::ConfirmContainerRestart { .. } => "ConfirmContainerRestart",
            Screen::ConfirmContainerStop { .. } => "ConfirmContainerStop",
            Screen::ContainerExecPrompt { .. } => "ContainerExecPrompt",
            Screen::ConfirmStackRestart { .. } => "ConfirmStackRestart",
            Screen::ConfirmHostRestartAll { .. } => "ConfirmHostRestartAll",
            Screen::ConfirmHostStopAll { .. } => "ConfirmHostStopAll",
            Screen::ConfirmImport { .. } => "ConfirmImport",
            Screen::ConfirmPurgeStale { .. } => "ConfirmPurgeStale",
            Screen::ConfirmVaultSign { .. } => "ConfirmVaultSign",
            Screen::Welcome { .. } => "Welcome",
            Screen::BulkTagEditor => "BulkTagEditor",
            Screen::WhatsNew(_) => "WhatsNew",
        }
    }
}
