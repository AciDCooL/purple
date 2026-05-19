use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, ProviderFormFields, Screen};
use crate::event::AppEvent;
use crate::providers;
use crate::providers::ProviderKind;

mod region;

// Test-only: region_picker_rows is pub(crate) in region.rs but only re-exported
// here for handler::tests which validates the OVH endpoint picker row count.
// Production code calls handle_region_picker directly; it never needs the raw rows.
#[cfg(test)]
pub(super) use region::region_picker_rows;
pub(crate) use region::zone_data_for;

pub(super) fn handle_provider_list_key(
    app: &mut App,
    key: KeyEvent,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    // Handle pending provider delete confirmation first.
    // `pending_delete_id` (Some) scopes the delete to one config; otherwise
    // `pending_delete` (legacy bare-name) deletes whatever single section
    // matches that provider name.
    if app.providers.pending_delete.is_some() && key.code != KeyCode::Char('?') {
        match super::route_confirm_key(key) {
            super::ConfirmAction::Yes => {
                let pending_id = app.providers.pending_delete_id.take();
                let Some(name) = app.providers.pending_delete.take() else {
                    return;
                };
                if let Some(id) = pending_id {
                    let Some(old_section) = app.providers.config.section_by_id(&id).cloned() else {
                        return;
                    };
                    app.providers.config.remove_section_by_id(&id);
                    if let Err(e) = app.providers.config.save() {
                        app.providers.config.set_section(old_section);
                        app.notify_error(crate::messages::failed_to_save(&e));
                    } else {
                        app.providers.sync_history.remove(&id.to_string());
                        crate::app::SyncRecord::save_all(&app.providers.sync_history);
                        // Drop the expand-state if this was the last config of
                        // its provider; otherwise a re-add would reopen expanded.
                        if app
                            .providers
                            .config
                            .sections_for_provider(&id.provider)
                            .is_empty()
                        {
                            app.providers.expanded_providers.remove(&id.provider);
                        }
                        let display_name = crate::providers::provider_display_name(&id.provider);
                        app.notify(crate::messages::provider_removed(display_name));
                    }
                } else if let Some(old_section) =
                    app.providers.config.section(name.as_str()).cloned()
                {
                    app.providers.config.remove_section(name.as_str());
                    if let Err(e) = app.providers.config.save() {
                        app.providers.config.set_section(old_section);
                        app.notify_error(crate::messages::failed_to_save(&e));
                    } else {
                        app.providers.sync_history.remove(name.as_str());
                        crate::app::SyncRecord::save_all(&app.providers.sync_history);
                        app.providers.expanded_providers.remove(&name);
                        let display_name = crate::providers::provider_display_name(name.as_str());
                        app.notify(crate::messages::provider_removed(display_name));
                    }
                }
            }
            super::ConfirmAction::No => {
                app.providers.pending_delete = None;
                app.providers.pending_delete_id = None;
            }
            super::ConfirmAction::Ignored => {}
        }
        return;
    }

    let rows = app.providers.provider_list_rows();
    let row_count = rows.len();
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            // Cancel all running syncs
            for cancel_flag in app.providers.syncing.values() {
                cancel_flag.store(true, Ordering::Relaxed);
            }
            app.set_screen(Screen::HostList);
        }
        KeyCode::Char('j') | KeyCode::Down => {
            crate::app::cycle_selection(&mut app.ui.provider_list_state, row_count, true);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            crate::app::cycle_selection(&mut app.ui.provider_list_state, row_count, false);
        }
        KeyCode::PageDown => {
            crate::app::page_down(&mut app.ui.provider_list_state, row_count, 10);
        }
        KeyCode::PageUp => {
            crate::app::page_up(&mut app.ui.provider_list_state, row_count, 10);
        }
        // SPACE GUARD MUST PRECEDE any generic Char(c) arm in this handler
        // so Space toggles expand/collapse on a multi-config header instead
        // of being consumed as a literal space.
        KeyCode::Char(' ') => {
            // Space toggles expand/collapse on a multi-config provider header.
            if let Some(idx) = app.ui.provider_list_state.selected() {
                if let Some(crate::app::ProviderRow::Header { name, config_count }) = rows.get(idx)
                {
                    if *config_count >= 2 {
                        let n = name.clone();
                        if app.providers.expanded_providers.contains(&n) {
                            app.providers.expanded_providers.remove(&n);
                            log::debug!("provider tree: collapsed '{}'", n);
                        } else {
                            log::debug!("provider tree: expanded '{}'", n);
                            app.providers.expanded_providers.insert(n);
                        }
                    }
                }
            }
        }
        KeyCode::Char('a') => {
            // Add another config for the selected provider. Triggers the
            // lazy-migration prompt when the provider already has one bare
            // config; for an already-labeled provider, opens the form
            // directly with an empty label.
            if let Some(idx) = app.ui.provider_list_state.selected() {
                let provider_name = rows.get(idx).map(|r| r.provider_name().to_string());
                if let Some(name) = provider_name {
                    open_add_config_flow(app, &name);
                }
            }
        }
        KeyCode::Enter => {
            if let Some(index) = app.ui.provider_list_state.selected() {
                let row = match rows.get(index) {
                    Some(r) => r.clone(),
                    None => return,
                };
                // Multi-config header: Enter toggles expand/collapse.
                if let crate::app::ProviderRow::Header { name, config_count } = &row {
                    if *config_count >= 2 {
                        if app.providers.expanded_providers.contains(name) {
                            app.providers.expanded_providers.remove(name);
                            log::debug!("provider tree: collapsed '{}'", name);
                        } else {
                            log::debug!("provider tree: expanded '{}'", name);
                            app.providers.expanded_providers.insert(name.clone());
                        }
                        return;
                    }
                }
                // Single-config header or leaf: open the edit form.
                let target_id = match &row {
                    crate::app::ProviderRow::Header { name, config_count } => {
                        if *config_count == 1 {
                            app.providers
                                .config
                                .sections_for_provider(name)
                                .first()
                                .map(|s| s.id.clone())
                                .unwrap_or_else(|| {
                                    crate::providers::config::ProviderConfigId::bare(name.clone())
                                })
                        } else {
                            crate::providers::config::ProviderConfigId::bare(name.clone())
                        }
                    }
                    crate::app::ProviderRow::Leaf { id } => id.clone(),
                };
                open_provider_form(app, target_id);
            }
        }
        KeyCode::Char('s') => {
            if app.demo_mode {
                app.notify_warning(crate::messages::DEMO_SYNC_DISABLED);
                return;
            }
            let row = match app
                .ui
                .provider_list_state
                .selected()
                .and_then(|i| rows.get(i))
            {
                Some(r) => r.clone(),
                None => return,
            };
            let sections_to_sync: Vec<providers::config::ProviderSection> = match &row {
                crate::app::ProviderRow::Header { name, .. } => app
                    .providers
                    .config
                    .sections_for_provider(name)
                    .into_iter()
                    .cloned()
                    .collect(),
                crate::app::ProviderRow::Leaf { id } => app
                    .providers
                    .config
                    .section_by_id(id)
                    .cloned()
                    .into_iter()
                    .collect(),
            };
            if sections_to_sync.is_empty() {
                let name = row.provider_name();
                let display_name = crate::providers::provider_display_name(name);
                app.notify_error(crate::messages::provider_configure_first(display_name));
                return;
            }
            for section in sections_to_sync {
                let key = section.id.to_string();
                if app.providers.syncing.contains_key(&key) {
                    continue;
                }
                app.providers.reset_batch_if_idle();
                let cancel = Arc::new(AtomicBool::new(false));
                app.providers.syncing.insert(key, cancel.clone());
                app.providers.batch_total = app
                    .providers
                    .batch_total
                    .max(app.providers.sync_done.len() + app.providers.syncing.len());
                super::sync::spawn_provider_sync(&section, events_tx.clone(), cancel);
            }
            crate::set_sync_summary(app);
        }
        KeyCode::Char('d') => {
            let row = match app
                .ui
                .provider_list_state
                .selected()
                .and_then(|i| rows.get(i))
            {
                Some(r) => r.clone(),
                None => return,
            };
            match &row {
                crate::app::ProviderRow::Leaf { id } => {
                    if app.providers.config.section_by_id(id).is_some() {
                        app.providers.pending_delete_id = Some(id.clone());
                        app.providers.pending_delete = Some(id.provider.clone());
                    }
                }
                crate::app::ProviderRow::Header { name, config_count } => {
                    if *config_count == 0 {
                        let display_name = crate::providers::provider_display_name(name);
                        app.notify(crate::messages::provider_not_configured(display_name));
                    } else if *config_count >= 2 {
                        // Refuse to mass-delete from the header. Force the
                        // user to expand and pick a specific config.
                        app.notify(crate::messages::EXPAND_TO_REMOVE_CONFIG.to_string());
                    } else {
                        // Single config: scope the confirm to that exact id.
                        if let Some(section) = app.providers.config.section(name) {
                            app.providers.pending_delete_id = Some(section.id.clone());
                            app.providers.pending_delete = Some(name.clone());
                        }
                    }
                }
            }
        }
        KeyCode::Char('?') => {
            let old = std::mem::replace(&mut app.screen, Screen::HostList);
            app.set_screen(Screen::Help {
                return_screen: Box::new(old),
            });
        }
        KeyCode::Char('X') => {
            // The list state indexes the FULL row list (headers + leaves),
            // not the bare-name list. Use the row to scope correctly:
            // - Header → all hosts of that provider (any label)
            // - Leaf   → only hosts of that labeled config
            let row = match app
                .ui
                .provider_list_state
                .selected()
                .and_then(|i| rows.get(i))
            {
                Some(r) => r.clone(),
                None => return,
            };
            let stale = app.hosts_state.ssh_config.stale_hosts();
            let entries = app.hosts_state.ssh_config.host_entries();
            let (display, scope_provider, provider_stale): (String, Option<String>, Vec<_>) =
                match &row {
                    crate::app::ProviderRow::Header { name, .. } => {
                        let display = crate::providers::provider_display_name(name).to_string();
                        let scope = name.clone();
                        let filtered: Vec<_> = stale
                            .iter()
                            .filter(|(alias, _)| {
                                entries.iter().any(|e| {
                                    e.alias == *alias
                                        && e.provider.as_deref() == Some(name.as_str())
                                })
                            })
                            .collect();
                        (display, Some(scope), filtered)
                    }
                    crate::app::ProviderRow::Leaf { id } => {
                        let display = format!(
                            "{} ({})",
                            crate::providers::provider_display_name(&id.provider),
                            id.label.as_deref().unwrap_or("")
                        );
                        let prov = id.provider.clone();
                        let label = id.label.clone();
                        let filtered: Vec<_> = stale
                            .iter()
                            .filter(|(alias, _)| {
                                entries.iter().any(|e| {
                                    e.alias == *alias
                                        && e.provider.as_deref() == Some(prov.as_str())
                                        && e.provider_label == label
                                })
                            })
                            .collect();
                        (display, Some(prov), filtered)
                    }
                };
            if provider_stale.is_empty() {
                app.notify_warning(crate::messages::no_stale_hosts_for(&display));
            } else {
                let aliases: Vec<String> =
                    provider_stale.into_iter().map(|(a, _)| a.clone()).collect();
                app.set_screen(Screen::ConfirmPurgeStale {
                    aliases,
                    provider: scope_provider,
                });
            }
        }
        _ => {}
    }
}

/// Pre-fill the provider form for the given config and switch to it.
/// If the id matches an existing section, the form starts in edit mode;
/// otherwise it starts blank with provider-appropriate defaults.
///
/// Label-entry mode (issue #51) activates when `id.label` is `Some("")` AND
/// no section exists at `id`. That state is reached only from the
/// `open_add_config_flow` "1+ labeled already" branch, where the user has not
/// yet chosen a label for the new config. The form prepends the `Label` field,
/// focuses it, and on submit writes the typed value into `form_id.label`
/// before persisting. Migration (label already chosen), bare add, and edits
/// all keep `label_entry` false so the label is sourced from the screen id.
fn open_provider_form(app: &mut App, id: crate::providers::config::ProviderConfigId) {
    let provider_impl = providers::get_provider(id.provider.as_str());
    let short_label = provider_impl
        .as_ref()
        .map(|p| p.short_label().to_string())
        .unwrap_or_else(|| id.provider.clone());
    let existing_section = app.providers.config.section_by_id(&id).cloned();
    let label_entry = existing_section.is_none() && id.label.as_deref() == Some("");
    let provider_first_field = crate::app::ProviderFormField::fields_for(id.provider.as_str())[0];
    let first_field = if label_entry {
        crate::app::ProviderFormField::Label
    } else {
        provider_first_field
    };

    app.providers.form = if let Some(section) = existing_section {
        let cursor_pos = match first_field {
            crate::app::ProviderFormField::Url => section.url.chars().count(),
            crate::app::ProviderFormField::Token => section.token.chars().count(),
            _ => 0,
        };
        ProviderFormFields {
            label: String::new(),
            label_entry: false,
            url: section.url.clone(),
            token: section.token.clone(),
            profile: section.profile.clone(),
            project: section.project.clone(),
            compartment: section.compartment.clone(),
            regions: section.regions.clone(),
            alias_prefix: section.alias_prefix.clone(),
            user: section.user.clone(),
            identity_file: section.identity_file.clone(),
            verify_tls: section.verify_tls,
            auto_sync: section.auto_sync,
            vault_role: section.vault_role.clone(),
            vault_addr: section.vault_addr.clone(),
            focused_field: first_field,
            cursor_pos,
            expanded: true,
        }
    } else {
        // New config: derive a sensible default alias_prefix. For a labeled
        // config with a known label, suggest `<short>-<label>` (e.g. `do-work`);
        // when the label is still empty (label-entry mode), fall back to the
        // bare short prefix so the field has a stable value the user can edit.
        let default_prefix = match id.label.as_deref() {
            Some("") | None => short_label.clone(),
            Some(l) => format!("{}-{}", short_label, l),
        };
        ProviderFormFields {
            label: String::new(),
            label_entry,
            url: String::new(),
            token: String::new(),
            profile: String::new(),
            project: String::new(),
            compartment: String::new(),
            regions: String::new(),
            alias_prefix: default_prefix,
            user: "root".to_string(),
            identity_file: String::new(),
            verify_tls: true,
            auto_sync: id.kind().is_none_or(ProviderKind::default_auto_sync),
            vault_role: String::new(),
            vault_addr: String::new(),
            focused_field: first_field,
            cursor_pos: 0,
            expanded: false,
        }
    };
    app.set_screen(Screen::ProviderForm { id });
    app.capture_provider_form_mtime();
    app.capture_provider_form_baseline();
}

/// Step 1 of the lazy add-second-config flow: pick labels for the existing
/// (bare) config AND the new one. On Enter, validate both and transition
/// to step 2 (the standard provider form). On Esc, drop pending state.
pub fn handle_label_migration_key(
    app: &mut App,
    key: KeyEvent,
    _events_tx: &mpsc::Sender<AppEvent>,
) {
    let provider = match &app.screen {
        Screen::ProviderLabelMigration { provider } => provider.clone(),
        _ => return,
    };
    match key.code {
        KeyCode::Esc => {
            app.providers.pending_label_migration = None;
            app.set_screen(Screen::Providers);
        }
        KeyCode::Tab | KeyCode::Down => {
            if let Some(p) = &mut app.providers.pending_label_migration {
                p.focused = match p.focused {
                    crate::app::LabelMigrationField::Existing => {
                        crate::app::LabelMigrationField::New
                    }
                    crate::app::LabelMigrationField::New => {
                        crate::app::LabelMigrationField::Existing
                    }
                };
                p.cursor_pos = p.focused_value().chars().count();
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Some(p) = &mut app.providers.pending_label_migration {
                p.focused = match p.focused {
                    crate::app::LabelMigrationField::Existing => {
                        crate::app::LabelMigrationField::New
                    }
                    crate::app::LabelMigrationField::New => {
                        crate::app::LabelMigrationField::Existing
                    }
                };
                p.cursor_pos = p.focused_value().chars().count();
            }
        }
        KeyCode::Left => {
            if let Some(p) = &mut app.providers.pending_label_migration {
                if p.cursor_pos > 0 {
                    p.cursor_pos -= 1;
                }
            }
        }
        KeyCode::Right => {
            if let Some(p) = &mut app.providers.pending_label_migration {
                let max = p.focused_value().chars().count();
                if p.cursor_pos < max {
                    p.cursor_pos += 1;
                }
            }
        }
        KeyCode::Home => {
            if let Some(p) = &mut app.providers.pending_label_migration {
                p.cursor_pos = 0;
            }
        }
        KeyCode::End => {
            if let Some(p) = &mut app.providers.pending_label_migration {
                p.cursor_pos = p.focused_value().chars().count();
            }
        }
        KeyCode::Backspace => {
            if let Some(p) = &mut app.providers.pending_label_migration {
                if p.cursor_pos > 0 {
                    let cursor_pos = p.cursor_pos;
                    let target = p.focused_value_mut();
                    let mut chars: Vec<char> = target.chars().collect();
                    chars.remove(cursor_pos - 1);
                    *target = chars.into_iter().collect();
                    p.cursor_pos -= 1;
                }
            }
        }
        KeyCode::Delete => {
            if let Some(p) = &mut app.providers.pending_label_migration {
                let len = p.focused_value().chars().count();
                if p.cursor_pos < len {
                    let cursor_pos = p.cursor_pos;
                    let target = p.focused_value_mut();
                    let mut chars: Vec<char> = target.chars().collect();
                    chars.remove(cursor_pos);
                    *target = chars.into_iter().collect();
                }
            }
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            let allowed = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
            if !allowed {
                return;
            }
            if let Some(p) = &mut app.providers.pending_label_migration {
                let cursor_pos = p.cursor_pos;
                let target = p.focused_value_mut();
                if target.len() < 32 {
                    let mut chars: Vec<char> = target.chars().collect();
                    chars.insert(cursor_pos, c);
                    *target = chars.into_iter().collect();
                    p.cursor_pos += 1;
                }
            }
        }
        KeyCode::Enter => {
            let (existing, new) = match app.providers.pending_label_migration.as_ref() {
                Some(p) => (p.existing_label.clone(), p.new_label.clone()),
                None => return,
            };
            if let Err(e) = crate::providers::config::validate_label(&existing) {
                app.notify_error(crate::messages::label_invalid(&e));
                return;
            }
            if let Err(e) = crate::providers::config::validate_label(&new) {
                app.notify_error(crate::messages::label_invalid(&e));
                return;
            }
            if existing == new {
                app.notify_error(crate::messages::LABEL_MUST_DIFFER.to_string());
                return;
            }
            // Move on to step 2: the standard provider form, pre-keyed to
            // the new labeled id. submit_provider_form will pick up
            // pending_label_migration to also rewrite the existing section.
            open_provider_form(
                app,
                crate::providers::config::ProviderConfigId::labeled(provider.clone(), new),
            );
        }
        _ => {}
    }
}

/// Begin the "add another config" flow for a provider.
/// - 0 existing configs: open the regular bare-config form (same as Enter).
/// - 1 existing bare config: prompt for a label for the existing one (Y step 1).
/// - 1+ existing labeled configs: open form for a new labeled config directly.
fn open_add_config_flow(app: &mut App, provider_name: &str) {
    let existing = app.providers.config.sections_for_provider(provider_name);
    match existing.len() {
        0 => {
            open_provider_form(
                app,
                crate::providers::config::ProviderConfigId::bare(provider_name),
            );
        }
        1 if existing[0].id.label.is_none() => {
            // Lazy migration: existing config is bare. Prompt for both
            // labels (existing + new) on one screen so step 2 is the
            // standard provider form without an extra label field.
            log::debug!("provider lazy migration: started for '{}'", provider_name);
            app.providers.pending_label_migration = Some(crate::app::PendingLabelMigration {
                provider: provider_name.to_string(),
                existing_label: "default".to_string(),
                new_label: String::new(),
                // Focus the FIRST field (current config). It's the surprise
                // — users didn't ask to rename their existing config —
                // so the cursor lands there to force engagement instead
                // of letting them blindly accept "default" by tabbing past.
                focused: crate::app::LabelMigrationField::Existing,
                cursor_pos: "default".chars().count(),
            });
            app.set_screen(Screen::ProviderLabelMigration {
                provider: provider_name.to_string(),
            });
        }
        _ => {
            // One or more labeled configs already exist: open the form with
            // an empty label so the user can fill it in.
            open_provider_form(
                app,
                crate::providers::config::ProviderConfigId {
                    provider: provider_name.to_string(),
                    label: Some(String::new()),
                },
            );
        }
    }
}

/// Show a non-blocking warning when leaving the Token field with an invalid format.
fn warn_aws_token_format(app: &mut App, provider_name: &str) {
    if provider_name.parse::<ProviderKind>().ok() != Some(ProviderKind::Aws) {
        return;
    }
    if app.providers.form.focused_field != crate::app::ProviderFormField::Token {
        return;
    }
    let token = app.providers.form.token.trim();
    if token.is_empty() {
        return;
    }
    if !token.contains(':') {
        app.notify_warning(crate::messages::TOKEN_FORMAT_AWS);
    }
}

pub(super) fn handle_provider_form_key(
    app: &mut App,
    key: KeyEvent,
    events_tx: &mpsc::Sender<AppEvent>,
) {
    // Dispatch to key picker if open
    if app.ui.key_picker.open {
        super::picker::handle_key_picker_shared(app, key, true);
        return;
    }

    // Dispatch to region picker if open
    if app.ui.region_picker.open {
        region::handle_region_picker(app, key);
        return;
    }

    let provider_name = match &app.screen {
        Screen::ProviderForm { id } => id.provider.clone(),
        _ => return,
    };
    // Progressive disclosure: hide `VaultAddr` when no role is set so Tab
    // navigation skips the hidden field. `visible_fields` is a filtered
    // snapshot of `fields_for(provider)` taken once per key press.
    let visible = app.providers.form.visible_fields(&provider_name);
    let fields: &[crate::app::ProviderFormField] = &visible;
    // Field-kind predicates live on `ProviderFormField` so the rule is
    // enforced in one place. Note: `is_picker` here matches the full set
    // (aws/scaleway/gcp/oracle/ovh) -- the previous local closure only
    // matched aws/scaleway/gcp which was a bug; oracle/ovh need the picker
    // too because their `Regions` Space-handler at the bottom of this match
    // expects to open the picker. `is_picker` on the type is the source of
    // truth.
    let is_toggle = |f: crate::app::ProviderFormField| f.is_toggle();
    let is_picker = |f: crate::app::ProviderFormField| f.is_picker(&provider_name);

    // Handle discard confirmation dialog via the shared confirm router.
    if app.forms.pending_discard_confirm {
        match super::route_confirm_key(key) {
            super::ConfirmAction::Yes => {
                app.forms.pending_discard_confirm = false;
                app.clear_form_mtime();
                app.providers.form_baseline = None;
                app.set_screen(Screen::Providers);
                app.flush_pending_vault_write();
            }
            super::ConfirmAction::No => {
                app.forms.pending_discard_confirm = false;
            }
            super::ConfirmAction::Ignored => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc => {
            if app.provider_form_is_dirty() {
                app.forms.pending_discard_confirm = true;
            } else {
                app.clear_form_mtime();
                app.providers.form_baseline = None;
                app.set_screen(Screen::Providers);
                app.flush_pending_vault_write();
            }
        }
        KeyCode::Tab | KeyCode::Down => {
            warn_aws_token_format(app, &provider_name);
            if !app.providers.form.expanded {
                // Use visible_fields so the dynamic Label (issue #51) joins the
                // navigation cycle alongside provider-static fields. Required
                // fields are always first in the per-provider arrays, and the
                // prepended Label is required when present, so the same prefix
                // slice rule holds.
                let all = &visible;
                let req_count = all
                    .iter()
                    .filter(|f| {
                        crate::app::ProviderFormField::is_required_field(**f, &provider_name)
                    })
                    .count();
                let required = &all[..req_count];
                if required.is_empty() {
                    // Fallback: no required fields, use full field list
                    app.providers.form.focused_field =
                        app.providers.form.focused_field.next(fields);
                } else {
                    let pos = required
                        .iter()
                        .position(|f| *f == app.providers.form.focused_field);
                    if let Some(idx) = pos {
                        if idx + 1 < required.len() {
                            app.providers.form.focused_field = required[idx + 1];
                        } else if req_count < all.len() {
                            // Last required field: expand and focus first optional
                            app.providers.form.expanded = true;
                            app.providers.form.focused_field = all[req_count];
                        } else {
                            // No optional fields, wrap
                            app.providers.form.focused_field = required[0];
                        }
                    } else {
                        app.providers.form.focused_field =
                            app.providers.form.focused_field.next(fields);
                    }
                }
            } else {
                app.providers.form.focused_field = app.providers.form.focused_field.next(fields);
            }
            app.providers.form.sync_cursor_to_end();
        }
        KeyCode::BackTab | KeyCode::Up => {
            warn_aws_token_format(app, &provider_name);
            if !app.providers.form.expanded {
                let all = &visible;
                let req_count = all
                    .iter()
                    .filter(|f| {
                        crate::app::ProviderFormField::is_required_field(**f, &provider_name)
                    })
                    .count();
                let required = &all[..req_count];
                if required.is_empty() {
                    // Fallback: no required fields, use full field list
                    app.providers.form.focused_field =
                        app.providers.form.focused_field.prev(fields);
                } else {
                    let pos = required
                        .iter()
                        .position(|f| *f == app.providers.form.focused_field);
                    if let Some(idx) = pos {
                        let prev_idx = if idx > 0 { idx - 1 } else { required.len() - 1 };
                        app.providers.form.focused_field = required[prev_idx];
                    } else {
                        // Focus is on a non-required field while collapsed; go to last required
                        app.providers.form.focused_field = required[required.len() - 1];
                    }
                }
            } else {
                app.providers.form.focused_field = app.providers.form.focused_field.prev(fields);
            }
            app.providers.form.sync_cursor_to_end();
        }
        KeyCode::Left if app.providers.form.cursor_pos > 0 => {
            app.providers.form.cursor_pos -= 1;
        }
        KeyCode::Right => {
            let len = app.providers.form.focused_value().chars().count();
            if app.providers.form.cursor_pos < len {
                app.providers.form.cursor_pos += 1;
            }
        }
        KeyCode::Home => {
            app.providers.form.cursor_pos = 0;
        }
        KeyCode::End => {
            app.providers.form.sync_cursor_to_end();
        }
        KeyCode::Enter => {
            // INVARIANT: Enter ALWAYS submits the form, regardless of focused
            // field. Pickers/toggles are reached via Space (see arms below).
            submit_provider_form(app, events_tx);
        }
        // SPACE GUARDS MUST PRECEDE the generic Char(c) arm.
        // Order: toggle first, picker second (no overlap, but explicit
        // ordering protects against future ProviderFormField additions).
        KeyCode::Char(' ')
            if app.providers.form.focused_field == crate::app::ProviderFormField::VerifyTls =>
        {
            app.providers.form.verify_tls = !app.providers.form.verify_tls;
        }
        KeyCode::Char(' ')
            if app.providers.form.focused_field == crate::app::ProviderFormField::AutoSync =>
        {
            app.providers.form.auto_sync = !app.providers.form.auto_sync;
        }
        // Empty-field gate: same rationale as host_form — once the user
        // has typed anything, Space inserts a literal space so custom
        // identity paths (e.g. `~/My Keys/id_rsa`) and free-form region
        // lists work. On an empty picker field, Space opens the picker.
        KeyCode::Char(' ')
            if is_picker(app.providers.form.focused_field)
                && app.providers.form.focused_value().is_empty() =>
        {
            let f = app.providers.form.focused_field;
            if f == crate::app::ProviderFormField::IdentityFile {
                app.scan_keys();
                app.ui.key_picker.open = true;
                app.ui.key_picker.list = ratatui::widgets::ListState::default();
                if !app.keys.list.is_empty() {
                    app.ui.key_picker.list.select(Some(0));
                }
            } else if f == crate::app::ProviderFormField::Regions {
                app.ui.region_picker.open = true;
                app.ui.region_picker.cursor = 0;
            }
        }
        KeyCode::Char(c) => {
            // Toggle fields (VerifyTls/AutoSync) have no text value to mutate;
            // every other field, including picker fields, accepts free-text
            // typing so users can supply custom paths or region values not
            // surfaced by the picker. Matches the host form's Char arm.
            let f = app.providers.form.focused_field;
            if is_toggle(f) {
                // Nothing to do.
            } else if f == crate::app::ProviderFormField::Label {
                // Label charset and length must mirror validate_label so a
                // value typed into this field always survives save-time
                // validation. Reject silently like the migration screen
                // (handler/provider.rs:502) does for the same constraints.
                let allowed = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
                if allowed && app.providers.form.label.len() < 32 {
                    app.providers.form.insert_char(c);
                }
            } else {
                app.providers.form.insert_char(c);
            }
        }
        KeyCode::Backspace => {
            let f = app.providers.form.focused_field;
            if !is_toggle(f) {
                app.providers.form.delete_char_before_cursor();
            }
        }
        _ => {}
    }
}

fn submit_provider_form(app: &mut App, events_tx: &mpsc::Sender<AppEvent>) {
    if app.demo_mode {
        app.notify_warning(crate::messages::DEMO_PROVIDER_CHANGES_DISABLED);
        app.set_screen(Screen::Providers);
        return;
    }
    let mut form_id = match &app.screen {
        Screen::ProviderForm { id } => id.clone(),
        _ => return,
    };
    let provider_name = form_id.provider.clone();
    let kind = provider_name.parse::<ProviderKind>().ok();

    // Label-entry mode (issue #51): seal the typed label into form_id before
    // any further validation or persistence. Without this the section would
    // serialize with the empty label still embedded in the screen id and the
    // save would fail downstream in validate_label. Reject early with a
    // pointed message so the user is not surprised by a "label is empty"
    // toast at the end of a long form.
    if app.providers.form.label_entry {
        let typed = app.providers.form.label.trim().to_string();
        if let Err(e) = providers::config::validate_label(&typed) {
            app.notify_error(crate::messages::label_invalid(&e));
            app.providers.form.focused_field = crate::app::ProviderFormField::Label;
            return;
        }
        // Reject collisions explicitly so the user understands why the save
        // would have been rejected by the dedup pass in validate().
        let candidate =
            providers::config::ProviderConfigId::labeled(provider_name.clone(), typed.clone());
        if app.providers.config.section_by_id(&candidate).is_some() {
            app.notify_error(crate::messages::label_already_in_use(&typed));
            app.providers.form.focused_field = crate::app::ProviderFormField::Label;
            return;
        }
        // The form opened with `alias_prefix = <short_label>` because we did
        // not know the label yet. Now that the user has typed one, suffix it
        // so the new section does not collide with a pre-existing bare-style
        // prefix on a sibling labeled config (validate() rejects duplicates).
        // Mirrors the migration helper at lines below that suffixes the
        // existing bare section's prefix when it equals the short label.
        let short = providers::get_provider(provider_name.as_str())
            .map(|p| p.short_label().to_string())
            .unwrap_or_else(|| provider_name.clone());
        if app.providers.form.alias_prefix.trim() == short {
            app.providers.form.alias_prefix = format!("{}-{}", short, typed);
        }
        form_id = candidate;
    }

    // Check for external provider config changes since form was opened
    if app.provider_config_changed_since_form_open() {
        app.notify_error(crate::messages::PROVIDER_CONFIG_CHANGED_EXTERNALLY);
        return;
    }

    // Reject control characters in all fields (prevents INI injection)
    let pf_fields = [
        (&app.providers.form.url, "URL"),
        (&app.providers.form.token, "Token"),
        (&app.providers.form.alias_prefix, "Alias Prefix"),
        (&app.providers.form.user, "User"),
        (&app.providers.form.identity_file, "Identity File"),
        (&app.providers.form.profile, "Profile"),
        (&app.providers.form.project, "Project ID"),
        (&app.providers.form.regions, "Regions"),
    ];
    for (value, name) in &pf_fields {
        if value.chars().any(|c| c.is_control()) {
            app.notify_warning(crate::messages::contains_control_chars(name));
            return;
        }
    }

    // Proxmox requires a URL
    if kind == Some(ProviderKind::Proxmox) {
        let url = app.providers.form.url.trim();
        if url.is_empty() {
            app.notify_warning(crate::messages::URL_REQUIRED_PROXMOX);
            return;
        }
        if !url.to_ascii_lowercase().starts_with("https://") {
            app.notify_error(crate::messages::PROVIDER_URL_REQUIRES_HTTPS);
            return;
        }
    }

    // AWS allows empty token when profile is set (credentials from ~/.aws/credentials)
    if app.providers.form.token.trim().is_empty()
        && kind != Some(ProviderKind::Tailscale)
        && (kind != Some(ProviderKind::Aws) || app.providers.form.profile.trim().is_empty())
    {
        let hint = if kind == Some(ProviderKind::Gcp) {
            crate::messages::PROVIDER_TOKEN_REQUIRED_GCP.to_string()
        } else if kind == Some(ProviderKind::Oracle) {
            crate::messages::PROVIDER_TOKEN_REQUIRED_ORACLE.to_string()
        } else {
            let display_name = crate::providers::provider_display_name(provider_name.as_str());
            crate::messages::provider_token_required(display_name)
        };
        app.notify_error(hint);
        return;
    }

    // GCP requires a project ID
    if kind == Some(ProviderKind::Gcp) && app.providers.form.project.trim().is_empty() {
        app.notify_warning(crate::messages::PROJECT_REQUIRED_GCP);
        return;
    }

    // Oracle requires a compartment OCID
    if kind == Some(ProviderKind::Oracle) && app.providers.form.compartment.trim().is_empty() {
        app.notify_warning(crate::messages::COMPARTMENT_REQUIRED_OCI);
        return;
    }

    // AWS/Scaleway require at least one region/zone
    if kind == Some(ProviderKind::Aws) && app.providers.form.regions.trim().is_empty() {
        app.notify_warning(crate::messages::REGIONS_REQUIRED_AWS);
        return;
    }
    if kind == Some(ProviderKind::Scaleway) && app.providers.form.regions.trim().is_empty() {
        app.notify_warning(crate::messages::ZONES_REQUIRED_SCALEWAY);
        return;
    }
    if kind == Some(ProviderKind::Azure) {
        let subs = app.providers.form.regions.trim();
        if subs.is_empty() {
            app.notify_warning(crate::messages::SUBSCRIPTIONS_REQUIRED_AZURE);
            return;
        }
        for sub in subs.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if !crate::providers::azure::is_valid_subscription_id(sub) {
                app.notify_error(crate::messages::azure_subscription_id_invalid(sub));
                return;
            }
        }
    }

    let token = app.providers.form.token.trim().to_string();
    let alias_prefix = app.providers.form.alias_prefix.trim().to_string();
    if crate::ssh_config::model::is_host_pattern(&alias_prefix) {
        app.notify_warning(crate::messages::ALIAS_PREFIX_INVALID);
        return;
    }

    let user = {
        let u = app.providers.form.user.trim();
        if u.is_empty() {
            "root".to_string()
        } else {
            u.to_string()
        }
    };
    if user.contains(char::is_whitespace) {
        app.notify_warning(crate::messages::USER_NO_WHITESPACE);
        return;
    }

    let vault_role_trimmed = app.providers.form.vault_role.trim();
    if !vault_role_trimmed.is_empty() && !crate::vault_ssh::is_valid_role(vault_role_trimmed) {
        app.notify_warning(crate::messages::VAULT_ROLE_FORMAT);
        return;
    }

    let section = providers::config::ProviderSection {
        id: form_id.clone(),
        token: token.clone(),
        alias_prefix,
        user,
        identity_file: app.providers.form.identity_file.trim().to_string(),
        url: app.providers.form.url.trim().to_string(),
        verify_tls: app.providers.form.verify_tls,
        auto_sync: app.providers.form.auto_sync,
        profile: app.providers.form.profile.trim().to_string(),
        regions: app.providers.form.regions.trim().to_string(),
        project: app.providers.form.project.trim().to_string(),
        compartment: app.providers.form.compartment.trim().to_string(),
        vault_role: app.providers.form.vault_role.trim().to_string(),
        vault_addr: app.providers.form.vault_addr.trim().to_string(),
    };

    // Snapshot for rollback. When migrating from bare to labeled, we have
    // an extra rename step on the existing section as well. Capture it.
    let old_section_by_id = app.providers.config.section_by_id(&form_id).cloned();
    let bare_id = providers::config::ProviderConfigId::bare(provider_name.clone());
    let old_bare_section = app.providers.config.section_by_id(&bare_id).cloned();

    let pending_migration = app.providers.pending_label_migration.clone();

    // Step 1: if a lazy migration is pending, rewrite the existing bare
    // section to its new labeled id BEFORE inserting the new section.
    if let Some(migration) = &pending_migration {
        if migration.provider == provider_name {
            if let Some(mut existing) = old_bare_section.clone() {
                let new_id = providers::config::ProviderConfigId::labeled(
                    migration.provider.clone(),
                    migration.existing_label.clone(),
                );
                existing.id = new_id.clone();
                // Default a sensible alias_prefix for the relabeled config
                // when the user hadn't set a custom one. Bare configs use
                // the provider short label as alias_prefix; once labeled,
                // we suffix the label so the two configs don't collide.
                let short = providers::get_provider(provider_name.as_str())
                    .map(|p| p.short_label().to_string())
                    .unwrap_or_else(|| provider_name.clone());
                if existing.alias_prefix == short {
                    existing.alias_prefix = format!("{}-{}", short, migration.existing_label);
                }
                app.providers.config.remove_section_by_id(&bare_id);
                app.providers.config.set_section(existing);
            }
        }
    }

    app.providers.config.set_section(section);
    if let Err(e) = app.providers.config.save() {
        log::warn!(
            "[config] Save failed for [{}]: {}; rolling back in-memory state",
            form_id,
            e
        );
        // Rollback: restore the previous section state for the form id
        // AND any migration-time relabel of the existing bare section.
        match old_section_by_id {
            Some(old) => app.providers.config.set_section(old),
            None => app.providers.config.remove_section_by_id(&form_id),
        }
        if let Some(old_bare) = old_bare_section {
            // Drop any new labeled section the migration may have inserted,
            // then restore the bare one.
            if let Some(migration) = &pending_migration {
                let migrated_id = providers::config::ProviderConfigId::labeled(
                    migration.provider.clone(),
                    migration.existing_label.clone(),
                );
                app.providers.config.remove_section_by_id(&migrated_id);
            }
            app.providers.config.set_section(old_bare);
        }
        // Drop pending migration state on failure too, so a retry doesn't
        // pick up half-applied input.
        app.providers.pending_label_migration = None;
        app.notify_error(crate::messages::failed_to_save(&e));
        return;
    }
    // Migration succeeded. Before clearing the pending state, also rewrite
    // any legacy 2-segment markers in ~/.ssh/config for this provider to
    // the new `existing_label`. Without this, the formerly-bare config's
    // hosts would be invisible to the labeled-default sync (different id),
    // get stale-marked or duplicated, and surface as data loss.
    if let Some(migration) = &pending_migration {
        let rewritten = app
            .hosts_state
            .ssh_config
            .rewrite_legacy_markers_to_label(&migration.provider, &migration.existing_label);
        if rewritten > 0 {
            log::debug!(
                "provider lazy migration: rewrote {} legacy marker(s) for '{}' to label '{}'",
                rewritten,
                migration.provider,
                migration.existing_label
            );
            if let Err(e) = app.hosts_state.ssh_config.write() {
                app.notify_error(crate::messages::failed_to_save(&e));
            }
        }
        log::debug!("provider lazy migration: completed for '{}'", provider_name);
    }
    app.providers.pending_label_migration = None;

    let display_name = crate::providers::provider_display_name(provider_name.as_str());

    // Look up by the EXACT id we just saved, not the bare provider name.
    // Otherwise a labeled save like `do:personal` would auto-sync `do:work`
    // (the first-found section for that provider).
    let sync_section = app.providers.config.section_by_id(&form_id).cloned();
    let sync_key = sync_section
        .as_ref()
        .map(|s| s.id.to_string())
        .unwrap_or_else(|| form_id.to_string());
    if !app.providers.syncing.contains_key(&sync_key) {
        if let Some(sync_section) = sync_section {
            app.providers.reset_batch_if_idle();
            let cancel = Arc::new(AtomicBool::new(false));
            app.providers.syncing.insert(sync_key, cancel.clone());
            app.providers.batch_total = app
                .providers
                .batch_total
                .max(app.providers.sync_done.len() + app.providers.syncing.len());
            app.notify(crate::messages::provider_saved_syncing(display_name));
            super::sync::spawn_provider_sync(&sync_section, events_tx.clone(), cancel);
            crate::set_sync_summary(app);
        }
    } else {
        app.notify(crate::messages::provider_saved(display_name));
    }
    app.clear_form_mtime();
    app.providers.form_baseline = None;
    app.set_screen(Screen::Providers);
    app.flush_pending_vault_write();
}

#[cfg(test)]
mod label_migration_tests {
    use super::*;
    use crate::app::LabelMigrationField;
    use crate::ssh_config::model::SshConfigFile;
    use crossterm::event::KeyModifiers;

    fn make_app() -> App {
        let scratch = tempfile::tempdir().expect("tempdir").keep();
        crate::preferences::set_path_override(scratch.join("preferences"));
        let config = SshConfigFile {
            elements: SshConfigFile::parse_content(""),
            path: scratch.join("test_config"),
            crlf: false,
            bom: false,
        };
        let mut app = App::new(config);
        app.screen = Screen::ProviderLabelMigration {
            provider: "aws".to_string(),
        };
        app.providers.pending_label_migration = Some(crate::app::PendingLabelMigration {
            provider: "aws".to_string(),
            existing_label: "default".to_string(),
            new_label: String::new(),
            focused: LabelMigrationField::New,
            cursor_pos: 0,
        });
        app
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn esc_returns_to_providers_and_clears_pending() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        let (tx, _rx) = mpsc::channel();
        handle_label_migration_key(&mut app, k(KeyCode::Esc), &tx);
        assert!(matches!(app.screen, Screen::Providers));
        assert!(app.providers.pending_label_migration.is_none());
    }

    #[test]
    fn tab_toggles_focused_field() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        let (tx, _rx) = mpsc::channel();
        handle_label_migration_key(&mut app, k(KeyCode::Tab), &tx);
        let p = app.providers.pending_label_migration.as_ref().unwrap();
        assert!(matches!(p.focused, LabelMigrationField::Existing));
    }
}

/// Regression tests for issue #51. The TUI add-another-config flow used to
/// open the provider form with `label: Some("")` and no input field for the
/// label itself, which left the section unsavable. The fixes:
/// 1. `open_provider_form` flips `label_entry` on for the `_ =>` add branch
///    so `visible_fields()` prepends a `Label` input.
/// 2. `submit_provider_form` seals the typed label into `form_id` before
///    persisting (and rejects empty / duplicate labels with explicit toasts).
/// 3. Char input on `Label` restricts to the `[a-z0-9-]` charset to mirror
///    `validate_label` so the user cannot type something save would reject.
#[cfg(test)]
mod labeled_add_tests {
    use super::*;
    use crate::providers::config::{ProviderConfigId, ProviderSection};
    use crate::ssh_config::model::SshConfigFile;
    use crossterm::event::KeyModifiers;

    fn make_app() -> App {
        let scratch = tempfile::tempdir().expect("tempdir").keep();
        crate::preferences::set_path_override(scratch.join("preferences"));
        let config = SshConfigFile {
            elements: SshConfigFile::parse_content(""),
            path: scratch.join("test_config"),
            crlf: false,
            bom: false,
        };
        let mut app = App::new(config);
        let providers_path = scratch.join("providers");
        app.providers.config = crate::providers::config::ProviderConfig {
            sections: Vec::new(),
            path_override: Some(providers_path),
        };
        app
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn proxmox_section(label: Option<&str>) -> ProviderSection {
        ProviderSection {
            id: match label {
                Some(l) => ProviderConfigId::labeled("proxmox", l),
                None => ProviderConfigId::bare("proxmox"),
            },
            token: "user@pam!t=secret".to_string(),
            alias_prefix: "pve".to_string(),
            user: "root".to_string(),
            identity_file: String::new(),
            url: "https://pve.example.com:8006".to_string(),
            verify_tls: false,
            auto_sync: false,
            profile: String::new(),
            regions: String::new(),
            project: String::new(),
            compartment: String::new(),
            vault_role: String::new(),
            vault_addr: String::new(),
        }
    }

    #[test]
    fn open_add_flow_with_existing_labeled_enters_label_mode() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        app.providers
            .config
            .set_section(proxmox_section(Some("server1")));
        open_add_config_flow(&mut app, "proxmox");
        assert!(matches!(app.screen, Screen::ProviderForm { ref id }
                if id.provider == "proxmox" && id.label.as_deref() == Some("")));
        assert!(app.providers.form.label_entry);
        assert_eq!(
            app.providers.form.focused_field,
            crate::app::ProviderFormField::Label
        );
        assert_eq!(app.providers.form.label, "");
    }

    #[test]
    fn open_add_flow_with_bare_only_goes_to_migration_not_label_mode() {
        // The migration screen handles label collection for the bare-to-labeled
        // transition. Label-entry on the form must stay off so the two flows
        // don't double-prompt for a name.
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        app.providers.config.set_section(proxmox_section(None));
        open_add_config_flow(&mut app, "proxmox");
        assert!(matches!(
            app.screen,
            Screen::ProviderLabelMigration { ref provider } if provider == "proxmox"
        ));
        // No ProviderFormFields::label_entry assertion here; the form is not
        // open at this point (migration screen is up).
    }

    #[test]
    fn open_add_flow_with_zero_existing_opens_bare_form() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        open_add_config_flow(&mut app, "proxmox");
        assert!(matches!(app.screen, Screen::ProviderForm { ref id }
                if id.provider == "proxmox" && id.label.is_none()));
        assert!(!app.providers.form.label_entry);
    }

    #[test]
    fn open_form_for_existing_labeled_does_not_enable_label_entry() {
        // Editing an already-named labeled config must not surface the label
        // input. Rename is out of scope here; the user changes other fields.
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        app.providers
            .config
            .set_section(proxmox_section(Some("server1")));
        open_provider_form(&mut app, ProviderConfigId::labeled("proxmox", "server1"));
        assert!(!app.providers.form.label_entry);
        assert_ne!(
            app.providers.form.focused_field,
            crate::app::ProviderFormField::Label
        );
    }

    #[test]
    fn visible_fields_prepends_label_when_label_entry_is_on() {
        let mut form = crate::app::ProviderFormFields::new();
        form.label_entry = true;
        let visible = form.visible_fields("proxmox");
        assert_eq!(visible.first(), Some(&crate::app::ProviderFormField::Label));
    }

    #[test]
    fn visible_fields_omits_label_when_label_entry_is_off() {
        let mut form = crate::app::ProviderFormFields::new();
        form.label_entry = false;
        let visible = form.visible_fields("proxmox");
        assert!(!visible.contains(&crate::app::ProviderFormField::Label));
    }

    #[test]
    fn char_input_on_label_field_rejects_illegal_chars() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        app.providers
            .config
            .set_section(proxmox_section(Some("server1")));
        open_add_config_flow(&mut app, "proxmox");
        let (tx, _rx) = mpsc::channel();
        // Allowed
        handle_provider_form_key(&mut app, k(KeyCode::Char('w')), &tx);
        handle_provider_form_key(&mut app, k(KeyCode::Char('o')), &tx);
        handle_provider_form_key(&mut app, k(KeyCode::Char('r')), &tx);
        handle_provider_form_key(&mut app, k(KeyCode::Char('k')), &tx);
        // Rejected: uppercase, space, special
        handle_provider_form_key(&mut app, k(KeyCode::Char('A')), &tx);
        handle_provider_form_key(&mut app, k(KeyCode::Char(' ')), &tx);
        handle_provider_form_key(&mut app, k(KeyCode::Char('@')), &tx);
        assert_eq!(app.providers.form.label, "work");
    }

    #[test]
    fn char_input_on_label_field_caps_at_32_chars() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        app.providers
            .config
            .set_section(proxmox_section(Some("server1")));
        open_add_config_flow(&mut app, "proxmox");
        let (tx, _rx) = mpsc::channel();
        for _ in 0..40 {
            handle_provider_form_key(&mut app, k(KeyCode::Char('a')), &tx);
        }
        assert_eq!(app.providers.form.label.len(), 32);
    }

    #[test]
    fn submit_with_empty_label_keeps_form_open_and_focuses_label() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        app.providers
            .config
            .set_section(proxmox_section(Some("server1")));
        open_add_config_flow(&mut app, "proxmox");
        let (tx, _rx) = mpsc::channel();
        // Enter without typing anything.
        handle_provider_form_key(&mut app, k(KeyCode::Enter), &tx);
        assert!(matches!(app.screen, Screen::ProviderForm { .. }));
        assert_eq!(
            app.providers.form.focused_field,
            crate::app::ProviderFormField::Label
        );
        // Original section still alone in the config.
        assert_eq!(
            app.providers.config.sections_for_provider("proxmox").len(),
            1
        );
    }

    #[test]
    fn submit_third_labeled_config_persists_with_typed_label() {
        // Issue #51 happy path: provider already has one labeled config. The
        // user presses `a`, fills in the new label, then the required Proxmox
        // fields, and presses Enter. The new section must land in the config
        // under the typed label (not under an empty-string label that
        // validate() would reject) and the form must close.
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        app.providers
            .config
            .set_section(proxmox_section(Some("server1")));
        open_add_config_flow(&mut app, "proxmox");
        let (tx, _rx) = mpsc::channel();
        for c in "server2".chars() {
            handle_provider_form_key(&mut app, k(KeyCode::Char(c)), &tx);
        }
        // Drive focus through the form rather than relying on Tab navigation
        // semantics so the test verifies persistence, not collapsed-mode key
        // routing (covered separately).
        app.providers.form.expanded = true;
        app.providers.form.focused_field = crate::app::ProviderFormField::Url;
        app.providers.form.sync_cursor_to_end();
        for c in "https://pve2.example.com:8006".chars() {
            handle_provider_form_key(&mut app, k(KeyCode::Char(c)), &tx);
        }
        app.providers.form.focused_field = crate::app::ProviderFormField::Token;
        app.providers.form.sync_cursor_to_end();
        for c in "user@pam!t=secret".chars() {
            handle_provider_form_key(&mut app, k(KeyCode::Char(c)), &tx);
        }
        handle_provider_form_key(&mut app, k(KeyCode::Enter), &tx);
        // Both labeled sections must coexist after submit.
        let names: Vec<String> = app
            .providers
            .config
            .sections_for_provider("proxmox")
            .iter()
            .map(|s| s.id.to_string())
            .collect();
        assert!(
            names.contains(&"proxmox:server1".to_string()),
            "got {names:?} (label={:?} url={:?} token_len={})",
            app.providers.form.label,
            app.providers.form.url,
            app.providers.form.token.len()
        );
        assert!(
            names.contains(&"proxmox:server2".to_string()),
            "got {names:?} (label={:?} url={:?} token_len={})",
            app.providers.form.label,
            app.providers.form.url,
            app.providers.form.token.len()
        );
    }

    #[test]
    fn delete_then_readd_same_label_persists_through_label_entry() {
        // Issue #51 workaround scenario: the user has two labeled configs,
        // deletes one, then tries to add it back. The previously-deleted
        // label must no longer count as a collision, the label-entry flow
        // must accept it, and the new section must land in the config under
        // the same id with full provider data.
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        app.providers.config.set_section(ProviderSection {
            alias_prefix: "pve-server1".to_string(),
            ..proxmox_section(Some("server1"))
        });
        app.providers.config.set_section(ProviderSection {
            alias_prefix: "pve-server2".to_string(),
            ..proxmox_section(Some("server2"))
        });
        assert_eq!(
            app.providers.config.sections_for_provider("proxmox").len(),
            2
        );

        // Delete server2 directly via the config API. The handler flow does
        // the same after the confirm step; routing it through the keystroke
        // sequence would not exercise additional code relevant here.
        app.providers
            .config
            .remove_section_by_id(&ProviderConfigId::labeled("proxmox", "server2"));
        assert_eq!(
            app.providers.config.sections_for_provider("proxmox").len(),
            1
        );

        // Press `a` and re-add `server2`. With one labeled config remaining,
        // the `_ =>` branch fires and label-entry mode opens.
        open_add_config_flow(&mut app, "proxmox");
        assert!(app.providers.form.label_entry);
        let (tx, _rx) = mpsc::channel();
        for c in "server2".chars() {
            handle_provider_form_key(&mut app, k(KeyCode::Char(c)), &tx);
        }
        app.providers.form.expanded = true;
        app.providers.form.focused_field = crate::app::ProviderFormField::Url;
        app.providers.form.sync_cursor_to_end();
        for c in "https://pve-readd.example.com:8006".chars() {
            handle_provider_form_key(&mut app, k(KeyCode::Char(c)), &tx);
        }
        app.providers.form.focused_field = crate::app::ProviderFormField::Token;
        app.providers.form.sync_cursor_to_end();
        for c in "user@pam!t=secret".chars() {
            handle_provider_form_key(&mut app, k(KeyCode::Char(c)), &tx);
        }
        handle_provider_form_key(&mut app, k(KeyCode::Enter), &tx);

        let names: Vec<String> = app
            .providers
            .config
            .sections_for_provider("proxmox")
            .iter()
            .map(|s| s.id.to_string())
            .collect();
        assert!(
            names.contains(&"proxmox:server1".to_string()),
            "got {names:?}"
        );
        assert!(
            names.contains(&"proxmox:server2".to_string()),
            "got {names:?}"
        );
        let readded = app
            .providers
            .config
            .section_by_id(&ProviderConfigId::labeled("proxmox", "server2"))
            .expect("readded section must be present");
        assert_eq!(readded.url, "https://pve-readd.example.com:8006");
    }

    #[test]
    fn submit_with_duplicate_label_keeps_form_open() {
        let _lock = crate::demo_flag::GLOBAL_TEST_LOCK.lock().unwrap();
        let mut app = make_app();
        app.providers
            .config
            .set_section(proxmox_section(Some("server1")));
        open_add_config_flow(&mut app, "proxmox");
        let (tx, _rx) = mpsc::channel();
        // Type the SAME label as the existing config.
        for c in "server1".chars() {
            handle_provider_form_key(&mut app, k(KeyCode::Char(c)), &tx);
        }
        // Tab to Token and type something so URL/Token validation doesn't
        // shadow the duplicate-label check.
        handle_provider_form_key(&mut app, k(KeyCode::Tab), &tx);
        for c in "fake-url-fake".chars() {
            handle_provider_form_key(&mut app, k(KeyCode::Char(c)), &tx);
        }
        handle_provider_form_key(&mut app, k(KeyCode::Enter), &tx);
        assert!(matches!(app.screen, Screen::ProviderForm { .. }));
        assert_eq!(
            app.providers.form.focused_field,
            crate::app::ProviderFormField::Label
        );
        // No duplicate inserted.
        assert_eq!(
            app.providers.config.sections_for_provider("proxmox").len(),
            1
        );
    }
}
