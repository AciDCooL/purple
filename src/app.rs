use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::SystemTime;

use ratatui::widgets::ListState;

use crate::history::ConnectionHistory;
use crate::providers::config::ProviderConfig;
use crate::ssh_config::model::{ConfigElement, HostEntry, SshConfigFile};
use crate::ssh_keys::{self, SshKeyInfo};

/// Case-insensitive substring check without allocation.
pub(crate) fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Case-insensitive equality check without allocation.
fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Which screen is currently displayed.
#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    HostList,
    AddHost,
    EditHost { alias: String },
    ConfirmDelete { alias: String },
    Help,
    KeyList,
    KeyDetail { index: usize },
    HostDetail { index: usize },
    TagPicker,
    Providers,
    ProviderForm { provider: String },
}

/// Which form field is focused.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FormField {
    Alias,
    Hostname,
    User,
    Port,
    IdentityFile,
    ProxyJump,
    Tags,
}

impl FormField {
    pub const ALL: [FormField; 7] = [
        FormField::Alias,
        FormField::Hostname,
        FormField::User,
        FormField::Port,
        FormField::IdentityFile,
        FormField::ProxyJump,
        FormField::Tags,
    ];

    pub fn next(self) -> Self {
        let idx = FormField::ALL.iter().position(|f| *f == self).unwrap_or(0);
        FormField::ALL[(idx + 1) % FormField::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let idx = FormField::ALL.iter().position(|f| *f == self).unwrap_or(0);
        FormField::ALL[(idx + FormField::ALL.len() - 1) % FormField::ALL.len()]
    }

    pub fn label(self) -> &'static str {
        match self {
            FormField::Alias => "Alias",
            FormField::Hostname => "Host / IP",
            FormField::User => "User",
            FormField::Port => "Port",
            FormField::IdentityFile => "Identity File",
            FormField::ProxyJump => "ProxyJump",
            FormField::Tags => "Tags",
        }
    }
}

/// Form state for adding/editing a host.
#[derive(Debug, Clone)]
pub struct HostForm {
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: String,
    pub identity_file: String,
    pub proxy_jump: String,
    pub tags: String,
    pub focused_field: FormField,
}

impl HostForm {
    pub fn new() -> Self {
        Self {
            alias: String::new(),
            hostname: String::new(),
            user: String::new(),
            port: "22".to_string(),
            identity_file: String::new(),
            proxy_jump: String::new(),
            tags: String::new(),
            focused_field: FormField::Alias,
        }
    }

    pub fn from_entry(entry: &HostEntry) -> Self {
        Self {
            alias: entry.alias.clone(),
            hostname: entry.hostname.clone(),
            user: entry.user.clone(),
            port: entry.port.to_string(),
            identity_file: entry.identity_file.clone(),
            proxy_jump: entry.proxy_jump.clone(),
            tags: entry.tags.join(", "),
            focused_field: FormField::Alias,
        }
    }

    /// Get a mutable reference to the currently focused field's value.
    pub fn focused_value_mut(&mut self) -> &mut String {
        match self.focused_field {
            FormField::Alias => &mut self.alias,
            FormField::Hostname => &mut self.hostname,
            FormField::User => &mut self.user,
            FormField::Port => &mut self.port,
            FormField::IdentityFile => &mut self.identity_file,
            FormField::ProxyJump => &mut self.proxy_jump,
            FormField::Tags => &mut self.tags,
        }
    }

    /// Validate the form. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.alias.trim().is_empty() {
            return Err("Alias can't be empty. Every host needs a name!".to_string());
        }
        if self.alias.contains(char::is_whitespace) {
            return Err("Alias can't contain whitespace. Keep it simple.".to_string());
        }
        if self.alias.contains('#') {
            return Err("Alias can't contain '#'. That's a comment character in SSH config.".to_string());
        }
        if crate::ssh_config::model::is_host_pattern(&self.alias) {
            return Err(
                "Alias can't contain pattern characters. That creates a match pattern, not a host."
                    .to_string(),
            );
        }
        // Reject control characters in all fields
        let fields = [
            (&self.alias, "Alias"),
            (&self.hostname, "Hostname"),
            (&self.user, "User"),
            (&self.port, "Port"),
            (&self.identity_file, "Identity File"),
            (&self.proxy_jump, "ProxyJump"),
            (&self.tags, "Tags"),
        ];
        for (value, name) in &fields {
            if value.chars().any(|c| c.is_control()) {
                return Err(format!("{} contains control characters. That's not going to work.", name));
            }
        }
        if self.hostname.trim().is_empty() {
            return Err("Hostname can't be empty. Where should we connect to?".to_string());
        }
        let port: u16 = self
            .port
            .parse()
            .map_err(|_| "That's not a port number. Ports are 1-65535, not poetry.".to_string())?;
        if port == 0 {
            return Err("Port 0? Bold choice, but no. Try 1-65535.".to_string());
        }
        Ok(())
    }

    /// Convert to a HostEntry.
    pub fn to_entry(&self) -> HostEntry {
        HostEntry {
            alias: self.alias.trim().to_string(),
            hostname: self.hostname.trim().to_string(),
            user: self.user.trim().to_string(),
            port: self.port.parse().unwrap_or(22),
            identity_file: self.identity_file.trim().to_string(),
            proxy_jump: self.proxy_jump.trim().to_string(),
            source_file: None,
            tags: self.tags.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
            provider: None,
        }
    }
}

/// Which provider form field is focused.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProviderFormField {
    Token,
    AliasPrefix,
    User,
    IdentityFile,
}

impl ProviderFormField {
    pub const ALL: [ProviderFormField; 4] = [
        ProviderFormField::Token,
        ProviderFormField::AliasPrefix,
        ProviderFormField::User,
        ProviderFormField::IdentityFile,
    ];

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let idx = Self::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    pub fn label(self) -> &'static str {
        match self {
            ProviderFormField::Token => "Token",
            ProviderFormField::AliasPrefix => "Alias Prefix",
            ProviderFormField::User => "User",
            ProviderFormField::IdentityFile => "Identity File",
        }
    }
}

/// Form state for configuring a provider.
#[derive(Debug, Clone)]
pub struct ProviderFormFields {
    pub token: String,
    pub alias_prefix: String,
    pub user: String,
    pub identity_file: String,
    pub focused_field: ProviderFormField,
}

impl ProviderFormFields {
    pub fn new() -> Self {
        Self {
            token: String::new(),
            alias_prefix: String::new(),
            user: "root".to_string(),
            identity_file: String::new(),
            focused_field: ProviderFormField::Token,
        }
    }

    pub fn focused_value_mut(&mut self) -> &mut String {
        match self.focused_field {
            ProviderFormField::Token => &mut self.token,
            ProviderFormField::AliasPrefix => &mut self.alias_prefix,
            ProviderFormField::User => &mut self.user,
            ProviderFormField::IdentityFile => &mut self.identity_file,
        }
    }
}

/// Status message displayed at the bottom.
#[derive(Debug, Clone)]
pub struct StatusMessage {
    pub text: String,
    pub is_error: bool,
    pub tick_count: u32,
}

/// An item in the display list (hosts + group headers).
#[derive(Debug, Clone)]
pub enum HostListItem {
    GroupHeader(String),
    Host { index: usize },
}

/// Ping status for a host.
#[derive(Debug, Clone, PartialEq)]
pub enum PingStatus {
    Checking,
    Reachable,
    Unreachable,
    Skipped,
}

/// Sort mode for the host list.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SortMode {
    Original,
    AlphaAlias,
    AlphaHostname,
    Frecency,
    MostRecent,
}

impl SortMode {
    pub fn next(self) -> Self {
        match self {
            SortMode::Original => SortMode::AlphaAlias,
            SortMode::AlphaAlias => SortMode::AlphaHostname,
            SortMode::AlphaHostname => SortMode::Frecency,
            SortMode::Frecency => SortMode::MostRecent,
            SortMode::MostRecent => SortMode::Original,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SortMode::Original => "config order",
            SortMode::AlphaAlias => "A-Z alias",
            SortMode::AlphaHostname => "A-Z hostname",
            SortMode::Frecency => "most used",
            SortMode::MostRecent => "most recent",
        }
    }

    pub fn to_key(self) -> &'static str {
        match self {
            SortMode::Original => "original",
            SortMode::AlphaAlias => "alpha_alias",
            SortMode::AlphaHostname => "alpha_hostname",
            SortMode::Frecency => "frecency",
            SortMode::MostRecent => "most_recent",
        }
    }

    pub fn from_key(s: &str) -> Self {
        match s {
            "original" => SortMode::Original,
            "alpha_alias" => SortMode::AlphaAlias,
            "alpha_hostname" => SortMode::AlphaHostname,
            "frecency" => SortMode::Frecency,
            "most_recent" => SortMode::MostRecent,
            _ => SortMode::AlphaAlias,
        }
    }
}

/// Stores a deleted host for undo.
#[derive(Debug, Clone)]
pub struct DeletedHost {
    pub element: ConfigElement,
    pub position: usize,
}

/// Ratatui ListState fields for all list views.
pub struct UiSelection {
    pub list_state: ListState,
    pub key_list_state: ListState,
    pub show_key_picker: bool,
    pub key_picker_state: ListState,
    pub tag_picker_state: ListState,
    pub provider_list_state: ListState,
}

/// Search mode state.
pub struct SearchState {
    pub query: Option<String>,
    pub filtered_indices: Vec<usize>,
    pub pre_search_selection: Option<usize>,
}

/// Auto-reload mtime tracking.
pub struct ReloadState {
    pub config_path: PathBuf,
    pub last_modified: Option<SystemTime>,
    pub include_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
    pub include_dir_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
}

/// Form conflict detection mtimes.
pub struct ConflictState {
    pub form_mtime: Option<SystemTime>,
    pub form_include_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
    pub form_include_dir_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
    pub provider_form_mtime: Option<SystemTime>,
}

/// Main application state.
pub struct App {
    // Core
    pub screen: Screen,
    pub running: bool,
    pub config: SshConfigFile,
    pub hosts: Vec<HostEntry>,
    pub display_list: Vec<HostListItem>,
    pub form: HostForm,
    pub status: Option<StatusMessage>,
    pub pending_connect: Option<String>,

    // Sub-structs
    pub ui: UiSelection,
    pub search: SearchState,
    pub reload: ReloadState,
    pub conflict: ConflictState,

    // Keys
    pub keys: Vec<SshKeyInfo>,

    // Tags
    pub tag_input: Option<String>,
    pub tag_list: Vec<String>,

    // History + preferences
    pub history: ConnectionHistory,
    pub sort_mode: SortMode,
    pub group_by_provider: bool,

    // Undo
    pub deleted_host: Option<DeletedHost>,

    // Providers
    pub provider_config: ProviderConfig,
    pub provider_form: ProviderFormFields,
    pub syncing_providers: HashMap<String, Arc<AtomicBool>>,

    // Hints
    pub ping_status: HashMap<String, PingStatus>,
    pub has_pinged: bool,
}

impl App {
    pub fn new(config: SshConfigFile) -> Self {
        let hosts = config.host_entries();
        let display_list = Self::build_display_list_from(&config, &hosts);
        let mut list_state = ListState::default();
        // Select first selectable item
        if let Some(pos) = display_list
            .iter()
            .position(|item| matches!(item, HostListItem::Host { .. }))
        {
            list_state.select(Some(pos));
        }

        let config_path = config.path.clone();
        let last_modified = Self::get_mtime(&config_path);
        let include_mtimes = Self::snapshot_include_mtimes(&config);
        let include_dir_mtimes = Self::snapshot_include_dir_mtimes(&config);

        Self {
            screen: Screen::HostList,
            running: true,
            config,
            hosts,
            display_list,
            form: HostForm::new(),
            status: None,
            pending_connect: None,
            ui: UiSelection {
                list_state,
                key_list_state: ListState::default(),
                show_key_picker: false,
                key_picker_state: ListState::default(),
                tag_picker_state: ListState::default(),
                provider_list_state: ListState::default(),
            },
            search: SearchState {
                query: None,
                filtered_indices: Vec::new(),
                pre_search_selection: None,
            },
            reload: ReloadState {
                config_path,
                last_modified,
                include_mtimes,
                include_dir_mtimes,
            },
            conflict: ConflictState {
                form_mtime: None,
                form_include_mtimes: Vec::new(),
                form_include_dir_mtimes: Vec::new(),
                provider_form_mtime: None,
            },
            keys: Vec::new(),
            tag_input: None,
            tag_list: Vec::new(),
            history: ConnectionHistory::load(),
            sort_mode: SortMode::Original,
            group_by_provider: false,
            deleted_host: None,
            provider_config: ProviderConfig::load(),
            provider_form: ProviderFormFields::new(),
            syncing_providers: HashMap::new(),
            ping_status: HashMap::new(),
            has_pinged: false,
        }
    }

    /// Build the display list with group headers from comments above host blocks.
    /// Comments are associated with the host block directly below them (no blank line between).
    /// Because the parser puts inter-block comments inside the preceding block's directives,
    /// we also extract trailing comments from each HostBlock.
    fn build_display_list_from(config: &SshConfigFile, hosts: &[HostEntry]) -> Vec<HostListItem> {
        let mut display_list = Vec::new();
        let mut host_index = 0;
        let mut pending_comment: Option<String> = None;

        for element in &config.elements {
            match element {
                ConfigElement::GlobalLine(line) => {
                    let trimmed = line.trim();
                    if trimmed.starts_with('#') {
                        let text = trimmed.trim_start_matches('#').trim();
                        let text = text.strip_prefix("purple:group ").unwrap_or(text);
                        if !text.is_empty() {
                            pending_comment = Some(text.to_string());
                        }
                    } else if trimmed.is_empty() {
                        // Blank line breaks the comment-to-host association
                        pending_comment = None;
                    } else {
                        pending_comment = None;
                    }
                }
                ConfigElement::HostBlock(block) => {
                    if crate::ssh_config::model::is_host_pattern(&block.host_pattern) {
                        pending_comment = None;
                        continue;
                    }

                    if host_index < hosts.len() {
                        if let Some(header) = pending_comment.take() {
                            display_list.push(HostListItem::GroupHeader(header));
                        }
                        display_list.push(HostListItem::Host { index: host_index });
                        host_index += 1;
                    }

                    // Extract trailing comments from this block for the next host
                    pending_comment = Self::extract_trailing_comment(&block.directives);
                }
                ConfigElement::Include(include) => {
                    pending_comment = None;
                    for file in &include.resolved_files {
                        Self::build_display_list_from_included(
                            &file.elements,
                            &file.path,
                            hosts,
                            &mut host_index,
                            &mut display_list,
                        );
                    }
                }
            }
        }

        display_list
    }

    /// Extract a trailing comment from a block's directives.
    /// If the last non-blank line in the directives is a comment, return it as
    /// a potential group header for the next host block.
    /// Strips `purple:group ` prefix so headers display as the provider name.
    fn extract_trailing_comment(directives: &[crate::ssh_config::model::Directive]) -> Option<String> {
        let d = directives.last()?;
        if !d.is_non_directive {
            return None;
        }
        let trimmed = d.raw_line.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.starts_with('#') {
            let text = trimmed.trim_start_matches('#').trim();
            // Skip purple metadata comments (purple:provider, purple:tags)
            // Only purple:group should produce a group header
            if text.starts_with("purple:") && !text.starts_with("purple:group ") {
                return None;
            }
            let text = text.strip_prefix("purple:group ").unwrap_or(text);
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
        None
    }

    fn build_display_list_from_included(
        elements: &[ConfigElement],
        file_path: &std::path::Path,
        hosts: &[HostEntry],
        host_index: &mut usize,
        display_list: &mut Vec<HostListItem>,
    ) {
        let mut pending_comment: Option<String> = None;
        let file_name = file_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        // Add file header for included files
        if !file_name.is_empty() {
            let has_hosts = elements.iter().any(|e| {
                matches!(e, ConfigElement::HostBlock(b)
                    if !crate::ssh_config::model::is_host_pattern(&b.host_pattern)
                )
            });
            if has_hosts {
                display_list.push(HostListItem::GroupHeader(file_name));
            }
        }

        for element in elements {
            match element {
                ConfigElement::GlobalLine(line) => {
                    let trimmed = line.trim();
                    if trimmed.starts_with('#') {
                        let text = trimmed.trim_start_matches('#').trim();
                        let text = text.strip_prefix("purple:group ").unwrap_or(text);
                        if !text.is_empty() {
                            pending_comment = Some(text.to_string());
                        }
                    } else {
                        pending_comment = None;
                    }
                }
                ConfigElement::HostBlock(block) => {
                    if crate::ssh_config::model::is_host_pattern(&block.host_pattern) {
                        pending_comment = None;
                        continue;
                    }

                    if *host_index < hosts.len() {
                        if let Some(header) = pending_comment.take() {
                            display_list.push(HostListItem::GroupHeader(header));
                        }
                        display_list.push(HostListItem::Host { index: *host_index });
                        *host_index += 1;
                    }

                    // Extract trailing comments from this block for the next host
                    pending_comment = Self::extract_trailing_comment(&block.directives);
                }
                ConfigElement::Include(include) => {
                    pending_comment = None;
                    for file in &include.resolved_files {
                        Self::build_display_list_from_included(
                            &file.elements,
                            &file.path,
                            hosts,
                            host_index,
                            display_list,
                        );
                    }
                }
            }
        }
    }

    /// Rebuild the display list based on the current sort mode and group_by_provider toggle.
    pub fn apply_sort(&mut self) {
        if self.sort_mode == SortMode::Original && !self.group_by_provider {
            self.display_list = Self::build_display_list_from(&self.config, &self.hosts);
        } else if self.sort_mode == SortMode::Original && self.group_by_provider {
            // Original order but grouped by provider: extract flat indices from config order
            let indices: Vec<usize> = (0..self.hosts.len()).collect();
            self.display_list = Self::group_indices_by_provider(&self.hosts, &indices);
        } else {
            let mut indices: Vec<usize> = (0..self.hosts.len()).collect();
            match self.sort_mode {
                SortMode::AlphaAlias => {
                    indices.sort_by_cached_key(|&i| self.hosts[i].alias.to_lowercase());
                }
                SortMode::AlphaHostname => {
                    indices.sort_by_cached_key(|&i| self.hosts[i].hostname.to_lowercase());
                }
                SortMode::Frecency => {
                    indices.sort_by(|a, b| {
                        let score_a = self.history.frecency_score(&self.hosts[*a].alias);
                        let score_b = self.history.frecency_score(&self.hosts[*b].alias);
                        score_b.total_cmp(&score_a)
                    });
                }
                SortMode::MostRecent => {
                    indices.sort_by(|a, b| {
                        let ts_a = self.history.last_connected(&self.hosts[*a].alias);
                        let ts_b = self.history.last_connected(&self.hosts[*b].alias);
                        ts_b.cmp(&ts_a)
                    });
                }
                _ => {}
            }
            if self.group_by_provider {
                self.display_list = Self::group_indices_by_provider(&self.hosts, &indices);
            } else {
                self.display_list = indices
                    .into_iter()
                    .map(|i| HostListItem::Host { index: i })
                    .collect();
            }
        }
        self.select_first_host();
    }

    /// Select the first host item in the display list.
    fn select_first_host(&mut self) {
        if let Some(pos) = self
            .display_list
            .iter()
            .position(|item| matches!(item, HostListItem::Host { .. }))
        {
            self.ui.list_state.select(Some(pos));
        }
    }

    /// Partition sorted indices by provider, inserting group headers.
    /// Hosts without provider appear first (no header), then named provider
    /// groups (in first-appearance order) with headers.
    fn group_indices_by_provider(hosts: &[HostEntry], sorted_indices: &[usize]) -> Vec<HostListItem> {
        let mut none_indices: Vec<usize> = Vec::new();
        let mut provider_groups: Vec<(&str, Vec<usize>)> = Vec::new();
        let mut provider_order: HashMap<&str, usize> = HashMap::new();

        for &idx in sorted_indices {
            match &hosts[idx].provider {
                None => none_indices.push(idx),
                Some(name) => {
                    if let Some(&group_idx) = provider_order.get(name.as_str()) {
                        provider_groups[group_idx].1.push(idx);
                    } else {
                        let group_idx = provider_groups.len();
                        provider_order.insert(name, group_idx);
                        provider_groups.push((name, vec![idx]));
                    }
                }
            }
        }

        let mut display_list = Vec::new();

        // Non-provider hosts first (no header)
        for idx in &none_indices {
            display_list.push(HostListItem::Host { index: *idx });
        }

        // Then provider groups with headers
        for (name, indices) in &provider_groups {
            let header = crate::providers::provider_display_name(name);
            display_list.push(HostListItem::GroupHeader(header.to_string()));
            for &idx in indices {
                display_list.push(HostListItem::Host { index: idx });
            }
        }
        display_list
    }

    /// Get the host index from the currently selected display list item.
    pub fn selected_host_index(&self) -> Option<usize> {
        if self.search.query.is_some() {
            // In search mode, list_state indexes into filtered_indices
            let sel = self.ui.list_state.selected()?;
            self.search.filtered_indices.get(sel).copied()
        } else {
            // In normal mode, list_state indexes into display_list
            let sel = self.ui.list_state.selected()?;
            match self.display_list.get(sel) {
                Some(HostListItem::Host { index }) => Some(*index),
                _ => None,
            }
        }
    }

    /// Get the currently selected host entry.
    pub fn selected_host(&self) -> Option<&HostEntry> {
        self.selected_host_index()
            .and_then(|i| self.hosts.get(i))
    }

    /// Move selection up, skipping group headers.
    pub fn select_prev(&mut self) {
        if self.search.query.is_some() {
            cycle_selection(&mut self.ui.list_state, self.search.filtered_indices.len(), false);
        } else {
            self.select_prev_in_display_list();
        }
    }

    /// Move selection down, skipping group headers.
    pub fn select_next(&mut self) {
        if self.search.query.is_some() {
            cycle_selection(&mut self.ui.list_state, self.search.filtered_indices.len(), true);
        } else {
            self.select_next_in_display_list();
        }
    }

    fn select_next_in_display_list(&mut self) {
        if self.display_list.is_empty() {
            return;
        }
        let len = self.display_list.len();
        let current = self.ui.list_state.selected().unwrap_or(0);
        // Find next Host item after current
        for offset in 1..=len {
            let idx = (current + offset) % len;
            if matches!(self.display_list[idx], HostListItem::Host { .. }) {
                self.ui.list_state.select(Some(idx));
                return;
            }
        }
    }

    fn select_prev_in_display_list(&mut self) {
        if self.display_list.is_empty() {
            return;
        }
        let len = self.display_list.len();
        let current = self.ui.list_state.selected().unwrap_or(0);
        // Find prev Host item before current
        for offset in 1..=len {
            let idx = (current + len - offset) % len;
            if matches!(self.display_list[idx], HostListItem::Host { .. }) {
                self.ui.list_state.select(Some(idx));
                return;
            }
        }
    }

    /// Reload hosts from config.
    pub fn reload_hosts(&mut self) {
        let had_search = self.search.query.take();

        self.hosts = self.config.host_entries();
        if self.sort_mode == SortMode::Original && !self.group_by_provider {
            self.display_list = Self::build_display_list_from(&self.config, &self.hosts);
        } else {
            self.apply_sort();
        }

        // Prune ping status for hosts that no longer exist
        let valid_aliases: std::collections::HashSet<&str> =
            self.hosts.iter().map(|h| h.alias.as_str()).collect();
        self.ping_status.retain(|alias, _| valid_aliases.contains(alias.as_str()));

        // Restore search if it was active, otherwise reset
        if let Some(query) = had_search {
            self.search.query = Some(query);
            self.apply_filter();
        } else {
            self.search.query = None;
            self.search.filtered_indices.clear();
            // Fix selection for display list mode
            if self.hosts.is_empty() {
                self.ui.list_state.select(None);
            } else if let Some(pos) = self
                .display_list
                .iter()
                .position(|item| matches!(item, HostListItem::Host { .. }))
            {
                let current = self.ui.list_state.selected().unwrap_or(0);
                if current >= self.display_list.len()
                    || !matches!(self.display_list.get(current), Some(HostListItem::Host { .. }))
                {
                    self.ui.list_state.select(Some(pos));
                }
            } else {
                self.ui.list_state.select(None);
            }
        }
    }

    // --- Search methods ---

    /// Enter search mode.
    pub fn start_search(&mut self) {
        self.search.pre_search_selection = self.ui.list_state.selected();
        self.search.query = Some(String::new());
        self.apply_filter();
    }

    /// Start search with an initial query (for positional arg).
    pub fn start_search_with(&mut self, query: &str) {
        self.search.pre_search_selection = self.ui.list_state.selected();
        self.search.query = Some(query.to_string());
        self.apply_filter();
    }

    /// Cancel search mode and restore normal view.
    pub fn cancel_search(&mut self) {
        self.search.query = None;
        self.search.filtered_indices.clear();
        // Restore pre-search position (bounds-checked)
        if let Some(pos) = self.search.pre_search_selection.take() {
            if pos < self.display_list.len() {
                self.ui.list_state.select(Some(pos));
            } else if let Some(first) = self
                .display_list
                .iter()
                .position(|item| matches!(item, HostListItem::Host { .. }))
            {
                self.ui.list_state.select(Some(first));
            }
        }
    }

    /// Apply the current search query to filter hosts.
    pub fn apply_filter(&mut self) {
        let query = match &self.search.query {
            Some(q) if !q.is_empty() => q.clone(),
            Some(_) => {
                self.search.filtered_indices = (0..self.hosts.len()).collect();
                if self.search.filtered_indices.is_empty() {
                    self.ui.list_state.select(None);
                } else {
                    self.ui.list_state.select(Some(0));
                }
                return;
            }
            None => return,
        };

        if let Some(tag_exact) = query.strip_prefix("tag=") {
            // Exact tag match (from tag picker), includes provider name
            self.search.filtered_indices = self
                .hosts
                .iter()
                .enumerate()
                .filter(|(_, host)| {
                    host.tags
                        .iter()
                        .any(|t| eq_ci(t, tag_exact))
                        || host.provider.as_ref().is_some_and(|p| eq_ci(p, tag_exact))
                })
                .map(|(i, _)| i)
                .collect();
        } else if let Some(tag_query) = query.strip_prefix("tag:") {
            // Fuzzy tag match (manual search), includes provider name
            self.search.filtered_indices = self
                .hosts
                .iter()
                .enumerate()
                .filter(|(_, host)| {
                    host.tags
                        .iter()
                        .any(|t| contains_ci(t, tag_query))
                        || host.provider.as_ref().is_some_and(|p| contains_ci(p, tag_query))
                })
                .map(|(i, _)| i)
                .collect();
        } else {
            self.search.filtered_indices = self
                .hosts
                .iter()
                .enumerate()
                .filter(|(_, host)| {
                    contains_ci(&host.alias, &query)
                        || contains_ci(&host.hostname, &query)
                        || contains_ci(&host.user, &query)
                        || host.tags.iter().any(|t| contains_ci(t, &query))
                        || host.provider.as_ref().is_some_and(|p| contains_ci(p, &query))
                })
                .map(|(i, _)| i)
                .collect();
        }

        // Reset selection
        if self.search.filtered_indices.is_empty() {
            self.ui.list_state.select(None);
        } else {
            self.ui.list_state.select(Some(0));
        }
    }

    /// Set a status message.
    pub fn set_status(&mut self, text: impl Into<String>, is_error: bool) {
        self.status = Some(StatusMessage {
            text: text.into(),
            is_error,
            tick_count: 0,
        });
    }

    /// Tick the status message timer. Errors show for 5s, success for 3s.
    pub fn tick_status(&mut self) {
        if let Some(ref mut status) = self.status {
            status.tick_count += 1;
            let timeout = if status.is_error { 20 } else { 12 };
            if status.tick_count > timeout {
                self.status = None;
            }
        }
    }

    /// Get the modification time of a file.
    fn get_mtime(path: &Path) -> Option<SystemTime> {
        std::fs::metadata(path).ok()?.modified().ok()
    }

    /// Check if config or any Include file has changed externally and reload if so.
    /// Skips reload when the user is in a form (AddHost/EditHost) to avoid
    /// overwriting in-memory config while the user is editing.
    pub fn check_config_changed(&mut self) {
        if matches!(
            self.screen,
            Screen::AddHost | Screen::EditHost { .. } | Screen::ProviderForm { .. }
        ) || self.tag_input.is_some()
        {
            return;
        }
        let current_mtime = Self::get_mtime(&self.reload.config_path);
        let changed = current_mtime != self.reload.last_modified
            || self.reload.include_mtimes.iter().any(|(path, old_mtime)| {
                Self::get_mtime(path) != *old_mtime
            })
            || self.reload.include_dir_mtimes.iter().any(|(path, old_mtime)| {
                Self::get_mtime(path) != *old_mtime
            });
        if changed {
            if let Ok(new_config) = SshConfigFile::parse(&self.reload.config_path) {
                self.config = new_config;
                // Invalidate undo state — config structure may have changed externally
                self.deleted_host = None;
                // Clear stale ping status — hosts may have changed
                self.ping_status.clear();
                self.reload_hosts();
                self.reload.last_modified = current_mtime;
                self.reload.include_mtimes = Self::snapshot_include_mtimes(&self.config);
                self.reload.include_dir_mtimes = Self::snapshot_include_dir_mtimes(&self.config);
                let count = self.hosts.len();
                self.set_status(format!("Config reloaded. {} hosts.", count), false);
            }
        }
    }

    /// Update the last_modified timestamp (call after writing config).
    pub fn update_last_modified(&mut self) {
        self.reload.last_modified = Self::get_mtime(&self.reload.config_path);
        self.reload.include_mtimes = Self::snapshot_include_mtimes(&self.config);
        self.reload.include_dir_mtimes = Self::snapshot_include_dir_mtimes(&self.config);
    }

    /// Clear form mtime state (call on form cancel or successful submit).
    pub fn clear_form_mtime(&mut self) {
        self.conflict.form_mtime = None;
        self.conflict.form_include_mtimes.clear();
        self.conflict.form_include_dir_mtimes.clear();
        self.conflict.provider_form_mtime = None;
    }

    /// Capture config and Include file mtimes when opening a host form.
    pub fn capture_form_mtime(&mut self) {
        self.conflict.form_mtime = Self::get_mtime(&self.reload.config_path);
        self.conflict.form_include_mtimes = Self::snapshot_include_mtimes(&self.config);
        self.conflict.form_include_dir_mtimes = Self::snapshot_include_dir_mtimes(&self.config);
    }

    /// Capture ~/.purple/providers mtime when opening a provider form.
    pub fn capture_provider_form_mtime(&mut self) {
        let path = dirs::home_dir()
            .map(|h| h.join(".purple/providers"));
        self.conflict.provider_form_mtime = path.as_ref().and_then(|p| Self::get_mtime(p));
    }

    /// Check if config or any Include file/directory has changed since the form was opened.
    pub fn config_changed_since_form_open(&self) -> bool {
        match self.conflict.form_mtime {
            Some(open_mtime) => {
                if Self::get_mtime(&self.reload.config_path) != Some(open_mtime) {
                    return true;
                }
                self.conflict.form_include_mtimes
                    .iter()
                    .any(|(path, old_mtime)| Self::get_mtime(path) != *old_mtime)
                    || self
                        .conflict.form_include_dir_mtimes
                        .iter()
                        .any(|(path, old_mtime)| Self::get_mtime(path) != *old_mtime)
            }
            None => false,
        }
    }

    /// Check if ~/.purple/providers has changed since the provider form was opened.
    pub fn provider_config_changed_since_form_open(&self) -> bool {
        let path = dirs::home_dir()
            .map(|h| h.join(".purple/providers"));
        let current_mtime = path.as_ref().and_then(|p| Self::get_mtime(p));
        self.conflict.provider_form_mtime != current_mtime
    }

    /// Snapshot mtimes of all resolved Include files.
    fn snapshot_include_mtimes(config: &SshConfigFile) -> Vec<(PathBuf, Option<SystemTime>)> {
        config
            .include_paths()
            .into_iter()
            .map(|p| {
                let mtime = Self::get_mtime(&p);
                (p, mtime)
            })
            .collect()
    }

    /// Snapshot mtimes of parent directories of Include glob patterns.
    fn snapshot_include_dir_mtimes(config: &SshConfigFile) -> Vec<(PathBuf, Option<SystemTime>)> {
        config
            .include_glob_dirs()
            .into_iter()
            .map(|p| {
                let mtime = Self::get_mtime(&p);
                (p, mtime)
            })
            .collect()
    }

    /// Scan SSH keys from ~/.ssh/ and cross-reference with hosts.
    pub fn scan_keys(&mut self) {
        if let Some(home) = dirs::home_dir() {
            let ssh_dir = home.join(".ssh");
            self.keys = ssh_keys::discover_keys(Path::new(&ssh_dir), &self.hosts);
            if !self.keys.is_empty() && self.ui.key_list_state.selected().is_none() {
                self.ui.key_list_state.select(Some(0));
            }
        }
    }

    /// Move key list selection up.
    pub fn select_prev_key(&mut self) {
        cycle_selection(&mut self.ui.key_list_state, self.keys.len(), false);
    }

    /// Move key list selection down.
    pub fn select_next_key(&mut self) {
        cycle_selection(&mut self.ui.key_list_state, self.keys.len(), true);
    }

    /// Move key picker selection up.
    pub fn select_prev_picker_key(&mut self) {
        cycle_selection(&mut self.ui.key_picker_state, self.keys.len(), false);
    }

    /// Move key picker selection down.
    pub fn select_next_picker_key(&mut self) {
        cycle_selection(&mut self.ui.key_picker_state, self.keys.len(), true);
    }

    /// Collect all unique tags from hosts, sorted alphabetically.
    pub fn collect_unique_tags(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut tags = Vec::new();
        for host in &self.hosts {
            for tag in &host.tags {
                if seen.insert(tag.as_str()) {
                    tags.push(tag.clone());
                }
            }
            if let Some(ref provider) = host.provider {
                if seen.insert(provider.as_str()) {
                    tags.push(provider.clone());
                }
            }
        }
        tags.sort_by_cached_key(|a| a.to_lowercase());
        tags
    }

    /// Open the tag picker overlay.
    pub fn open_tag_picker(&mut self) {
        self.tag_list = self.collect_unique_tags();
        self.ui.tag_picker_state = ListState::default();
        if !self.tag_list.is_empty() {
            self.ui.tag_picker_state.select(Some(0));
        }
        self.screen = Screen::TagPicker;
    }

    /// Move tag picker selection up.
    pub fn select_prev_tag(&mut self) {
        cycle_selection(&mut self.ui.tag_picker_state, self.tag_list.len(), false);
    }

    /// Move tag picker selection down.
    pub fn select_next_tag(&mut self) {
        cycle_selection(&mut self.ui.tag_picker_state, self.tag_list.len(), true);
    }

    /// Add a new host from the current form. Returns status message.
    pub fn add_host_from_form(&mut self) -> Result<String, String> {
        let entry = self.form.to_entry();
        let alias = entry.alias.clone();
        if self.config.has_host(&alias) {
            return Err(format!(
                "'{}' already exists. Aliases are like fingerprints — unique.",
                alias
            ));
        }
        let len_before = self.config.elements.len();
        self.config.add_host(&entry);
        if !entry.tags.is_empty() {
            self.config.set_host_tags(&alias, &entry.tags);
        }
        if let Err(e) = self.config.write() {
            self.config.elements.truncate(len_before);
            return Err(format!("Failed to save: {}", e));
        }
        self.update_last_modified();
        self.reload_hosts();
        self.select_host_by_alias(&alias);
        Ok(format!("Welcome aboard, {}!", alias))
    }

    /// Edit an existing host from the current form. Returns status message.
    pub fn edit_host_from_form(&mut self, old_alias: &str) -> Result<String, String> {
        let entry = self.form.to_entry();
        let alias = entry.alias.clone();
        if !self.config.has_host(old_alias) {
            return Err("Host no longer exists.".to_string());
        }
        if alias != old_alias && self.config.has_host(&alias) {
            return Err(format!(
                "'{}' already exists. Aliases are like fingerprints — unique.",
                alias
            ));
        }
        let old_entry = self
            .hosts
            .iter()
            .find(|h| h.alias == old_alias)
            .cloned()
            .unwrap_or_default();
        self.config.update_host(old_alias, &entry);
        self.config.set_host_tags(&entry.alias, &entry.tags);
        if let Err(e) = self.config.write() {
            self.config.update_host(&entry.alias, &old_entry);
            self.config.set_host_tags(&old_entry.alias, &old_entry.tags);
            return Err(format!("Failed to save: {}", e));
        }
        self.update_last_modified();
        self.reload_hosts();
        Ok(format!("{} got a makeover.", alias))
    }

    /// Select a host in the display list by alias.
    fn select_host_by_alias(&mut self, alias: &str) {
        for (i, item) in self.display_list.iter().enumerate() {
            if let HostListItem::Host { index } = item {
                if self.hosts.get(*index).is_some_and(|h| h.alias == *alias) {
                    self.ui.list_state.select(Some(i));
                    return;
                }
            }
        }
    }

    /// Apply sync results from a background provider fetch.
    /// Returns status message. Caller must remove from syncing_providers.
    pub fn apply_sync_result(
        &mut self,
        provider: &str,
        hosts: Vec<crate::providers::ProviderHost>,
    ) -> String {
        let section = match self.provider_config.section(provider).cloned() {
            Some(s) => s,
            None => return format!("! {} sync skipped: no config.", provider),
        };
        let provider_impl = match crate::providers::get_provider(provider) {
            Some(p) => p,
            None => return format!("! Unknown provider: {}.", provider),
        };
        let result = crate::providers::sync::sync_provider(
            &mut self.config,
            &*provider_impl,
            &hosts,
            &section,
            false,
            false,
        );
        if result.added > 0 || result.updated > 0 {
            if let Err(e) = self.config.write() {
                return format!("Sync failed to save: {}", e);
            }
            self.update_last_modified();
            self.reload_hosts();
        }
        let name = crate::providers::provider_display_name(provider);
        format!(
            "Synced {}: added {}, updated {}, unchanged {}.",
            name, result.added, result.updated, result.unchanged
        )
    }
}

/// Cycle list selection forward or backward with wraparound.
pub fn cycle_selection(state: &mut ListState, len: usize, forward: bool) {
    if len == 0 {
        return;
    }
    let i = match state.selected() {
        Some(i) => {
            if forward {
                if i >= len - 1 { 0 } else { i + 1 }
            } else if i == 0 {
                len - 1
            } else {
                i - 1
            }
        }
        None => 0,
    };
    state.select(Some(i));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_config::model::SshConfigFile;
    use std::path::PathBuf;

    fn make_app(content: &str) -> App {
        let config = SshConfigFile {
            elements: SshConfigFile::parse_content(content),
            path: PathBuf::from("/tmp/test_config"),
            crlf: false,
        };
        App::new(config)
    }

    #[test]
    fn test_apply_filter_matches_alias() {
        let mut app = make_app("Host alpha\n  HostName a.com\n\nHost beta\n  HostName b.com\n");
        app.start_search();
        app.search.query = Some("alp".to_string());
        app.apply_filter();
        assert_eq!(app.search.filtered_indices, vec![0]);
    }

    #[test]
    fn test_apply_filter_matches_hostname() {
        let mut app = make_app("Host alpha\n  HostName a.com\n\nHost beta\n  HostName b.com\n");
        app.start_search();
        app.search.query = Some("b.com".to_string());
        app.apply_filter();
        assert_eq!(app.search.filtered_indices, vec![1]);
    }

    #[test]
    fn test_apply_filter_empty_query() {
        let mut app = make_app("Host alpha\n  HostName a.com\n\nHost beta\n  HostName b.com\n");
        app.start_search();
        assert_eq!(app.search.filtered_indices, vec![0, 1]);
    }

    #[test]
    fn test_apply_filter_no_matches() {
        let mut app = make_app("Host alpha\n  HostName a.com\n");
        app.start_search();
        app.search.query = Some("zzz".to_string());
        app.apply_filter();
        assert!(app.search.filtered_indices.is_empty());
    }

    #[test]
    fn test_build_display_list_with_group_headers() {
        let content = "\
# Production
Host prod
  HostName prod.example.com

# Staging
Host staging
  HostName staging.example.com
";
        let app = make_app(content);
        assert_eq!(app.display_list.len(), 4);
        assert!(matches!(&app.display_list[0], HostListItem::GroupHeader(s) if s == "Production"));
        assert!(matches!(&app.display_list[1], HostListItem::Host { index: 0 }));
        assert!(matches!(&app.display_list[2], HostListItem::GroupHeader(s) if s == "Staging"));
        assert!(matches!(&app.display_list[3], HostListItem::Host { index: 1 }));
    }

    #[test]
    fn test_build_display_list_blank_line_breaks_group() {
        let content = "\
# This comment is separated by blank line

Host nogroup
  HostName nogroup.example.com
";
        let app = make_app(content);
        // Blank line between comment and host means no group header
        assert_eq!(app.display_list.len(), 1);
        assert!(matches!(&app.display_list[0], HostListItem::Host { index: 0 }));
    }

    #[test]
    fn test_navigation_skips_headers() {
        let content = "\
# Group
Host alpha
  HostName a.com

# Group 2
Host beta
  HostName b.com
";
        let mut app = make_app(content);
        // Should start on first Host (index 1 in display_list)
        assert_eq!(app.ui.list_state.selected(), Some(1));
        app.select_next();
        // Should skip header at index 2, land on Host at index 3
        assert_eq!(app.ui.list_state.selected(), Some(3));
        app.select_prev();
        assert_eq!(app.ui.list_state.selected(), Some(1));
    }

    #[test]
    fn test_group_by_provider_creates_headers() {
        let content = "\
Host do-web
  HostName 1.2.3.4
  # purple:provider digitalocean:123

Host do-db
  HostName 5.6.7.8
  # purple:provider digitalocean:456

Host vultr-app
  HostName 9.9.9.9
  # purple:provider vultr:789
";
        let mut app = make_app(content);
        app.group_by_provider = true;
        app.apply_sort();

        // Should have: DigitalOcean header, 2 hosts, Vultr header, 1 host
        assert_eq!(app.display_list.len(), 5);
        assert!(matches!(&app.display_list[0], HostListItem::GroupHeader(s) if s == "DigitalOcean"));
        assert!(matches!(&app.display_list[1], HostListItem::Host { .. }));
        assert!(matches!(&app.display_list[2], HostListItem::Host { .. }));
        assert!(matches!(&app.display_list[3], HostListItem::GroupHeader(s) if s == "Vultr"));
        assert!(matches!(&app.display_list[4], HostListItem::Host { .. }));
    }

    #[test]
    fn test_group_by_provider_no_header_for_none() {
        let content = "\
Host manual
  HostName 1.2.3.4

Host do-web
  HostName 5.6.7.8
  # purple:provider digitalocean:123
";
        let mut app = make_app(content);
        app.group_by_provider = true;
        app.apply_sort();

        // manual first (no header), then DigitalOcean header + do-web
        assert_eq!(app.display_list.len(), 3);
        // No header before the manual host
        assert!(matches!(&app.display_list[0], HostListItem::Host { .. }));
        assert!(matches!(&app.display_list[1], HostListItem::GroupHeader(s) if s == "DigitalOcean"));
        assert!(matches!(&app.display_list[2], HostListItem::Host { .. }));
    }

    #[test]
    fn test_group_by_provider_with_alpha_sort() {
        let content = "\
Host do-zeta
  HostName 1.2.3.4
  # purple:provider digitalocean:1

Host do-alpha
  HostName 5.6.7.8
  # purple:provider digitalocean:2
";
        let mut app = make_app(content);
        app.group_by_provider = true;
        app.sort_mode = SortMode::AlphaAlias;
        app.apply_sort();

        // DigitalOcean header + sorted hosts
        assert_eq!(app.display_list.len(), 3);
        assert!(matches!(&app.display_list[0], HostListItem::GroupHeader(s) if s == "DigitalOcean"));
        // First host should be do-alpha (alphabetical)
        if let HostListItem::Host { index } = &app.display_list[1] {
            assert_eq!(app.hosts[*index].alias, "do-alpha");
        } else {
            panic!("Expected Host item");
        }
    }

    #[test]
    fn test_config_changed_since_form_open_no_mtime() {
        let app = make_app("Host alpha\n  HostName a.com\n");
        // No mtime captured — should return false
        assert!(!app.config_changed_since_form_open());
    }

    #[test]
    fn test_config_changed_since_form_open_same_mtime() {
        let mut app = make_app("Host alpha\n  HostName a.com\n");
        // Config path is /tmp/test_config which doesn't exist, so mtime is None
        app.capture_form_mtime();
        // Immediately checking — mtime should be same (None == None)
        assert!(!app.config_changed_since_form_open());
    }

    #[test]
    fn test_config_changed_since_form_open_detects_change() {
        let mut app = make_app("Host alpha\n  HostName a.com\n");
        // Set form_mtime to a known past value (different from current None)
        app.conflict.form_mtime = Some(SystemTime::UNIX_EPOCH);
        // Config path doesn't exist (mtime is None), so it differs from UNIX_EPOCH
        assert!(app.config_changed_since_form_open());
    }

    #[test]
    fn test_group_by_provider_toggle_off_restores_flat() {
        let content = "\
Host do-web
  HostName 1.2.3.4
  # purple:provider digitalocean:123

Host vultr-app
  HostName 5.6.7.8
  # purple:provider vultr:456
";
        let mut app = make_app(content);
        app.sort_mode = SortMode::AlphaAlias;

        // Enable grouping
        app.group_by_provider = true;
        app.apply_sort();
        let grouped_len = app.display_list.len();
        assert!(grouped_len > 2); // Has headers

        // Disable grouping
        app.group_by_provider = false;
        app.apply_sort();
        // Should be flat: just hosts, no headers
        assert_eq!(app.display_list.len(), 2);
        assert!(app.display_list.iter().all(|item| matches!(item, HostListItem::Host { .. })));
    }

    // --- New validation tests from review findings ---

    #[test]
    fn test_validate_rejects_hash_in_alias() {
        let mut form = HostForm::new();
        form.alias = "my#host".to_string();
        form.hostname = "1.2.3.4".to_string();
        let result = form.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("#"));
    }

    #[test]
    fn test_validate_empty_alias() {
        let mut form = HostForm::new();
        form.alias = "".to_string();
        form.hostname = "1.2.3.4".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_validate_whitespace_alias() {
        let mut form = HostForm::new();
        form.alias = "my host".to_string();
        form.hostname = "1.2.3.4".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_validate_pattern_alias() {
        let mut form = HostForm::new();
        form.alias = "my*host".to_string();
        form.hostname = "1.2.3.4".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_validate_empty_hostname() {
        let mut form = HostForm::new();
        form.alias = "myhost".to_string();
        form.hostname = "".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_port() {
        let mut form = HostForm::new();
        form.alias = "myhost".to_string();
        form.hostname = "1.2.3.4".to_string();
        form.port = "abc".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_validate_port_zero() {
        let mut form = HostForm::new();
        form.alias = "myhost".to_string();
        form.hostname = "1.2.3.4".to_string();
        form.port = "0".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_validate_valid_form() {
        let mut form = HostForm::new();
        form.alias = "myhost".to_string();
        form.hostname = "1.2.3.4".to_string();
        form.port = "22".to_string();
        assert!(form.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_control_chars() {
        let mut form = HostForm::new();
        form.alias = "myhost".to_string();
        form.hostname = "1.2.3.4\x00".to_string();
        form.port = "22".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_to_entry_parses_tags() {
        let mut form = HostForm::new();
        form.alias = "myhost".to_string();
        form.hostname = "1.2.3.4".to_string();
        form.tags = "prod, staging, us-east".to_string();
        let entry = form.to_entry();
        assert_eq!(entry.tags, vec!["prod", "staging", "us-east"]);
    }

    #[test]
    fn test_sort_mode_round_trip() {
        for mode in [
            SortMode::Original,
            SortMode::AlphaAlias,
            SortMode::AlphaHostname,
            SortMode::Frecency,
            SortMode::MostRecent,
        ] {
            assert_eq!(SortMode::from_key(mode.to_key()), mode);
        }
    }
}
