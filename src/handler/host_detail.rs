use crossterm::event::{KeyCode, KeyEvent};

use super::ctx::{Effectful, Effects, Nav, Notify};
use crate::app::{App, HostState, Screen, StatusCenter, TagState, TunnelState, UiSelection};
use crate::ssh_config::model::HostEntry;

/// The slice the tag-input bar touches: the tag input state (`tags`), the host
/// config (`hosts`, for the tag write) and the status center (for the
/// save-failed toast). The currently selected host is resolved in the thin
/// wrapper while it still holds `&App` (because `App::selected_host` reads
/// search, ui and hosts together), and the post-write reload/select/notify
/// sequence is a whole-App op deferred as one closure to keep its order.
struct TagInputCtx<'a> {
    tags: &'a mut TagState,
    hosts: &'a mut HostState,
    status: &'a mut StatusCenter,
    effects: Effects,
}

impl Notify for TagInputCtx<'_> {
    fn status_mut(&mut self) -> &mut StatusCenter {
        self.status
    }
}

impl Effectful for TagInputCtx<'_> {
    fn effects_mut(&mut self) -> &mut Effects {
        &mut self.effects
    }
}

pub(super) fn handle_tag_input(app: &mut App, key: KeyEvent) {
    // `selected_host` reads search + ui + hosts together, so resolve it here
    // while we still hold `&App`. It is a pure read with no side effect, so
    // resolving it before the mutable slice borrow preserves behaviour.
    let selected = app.selected_host().cloned();
    let effects = {
        let mut ctx = TagInputCtx {
            tags: &mut app.tags,
            hosts: &mut app.hosts_state,
            status: &mut app.status_center,
            effects: Effects::default(),
        };
        tag_input_key(&mut ctx, key, selected.as_ref());
        ctx.effects
    };
    effects.apply(app);
}

fn tag_input_key(ctx: &mut TagInputCtx, key: KeyEvent, selected: Option<&HostEntry>) {
    match key.code {
        KeyCode::Enter => {
            if let Some(input) = ctx.tags.input() {
                let tags: Vec<String> = input
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                if let Some(host) = selected {
                    let alias = host.alias.clone();
                    let old_tags = host.tags.clone();
                    let _ = ctx.hosts.ssh_config_mut().set_host_tags(&alias, &tags);
                    if let Err(e) = ctx.hosts.ssh_config().write() {
                        // Restore old tags on write failure
                        let _ = ctx.hosts.ssh_config_mut().set_host_tags(&alias, &old_tags);
                        ctx.notify_error(crate::messages::failed_to_save(&e));
                    } else {
                        let count = tags.len();
                        // update_last_modified, reload_hosts and
                        // select_host_by_alias touch most of App and must run
                        // in this order (select re-selects in the reloaded
                        // list), so the whole success sequence is deferred as
                        // one closure to preserve ordering.
                        ctx.defer(move |app| {
                            app.update_last_modified();
                            app.reload_hosts();
                            app.select_host_by_alias(&alias);
                            app.notify(crate::messages::tagged_host(&alias, count));
                        });
                    }
                }
            }
            ctx.tags.close_tag_input();
        }
        KeyCode::Esc => {
            ctx.tags.close_tag_input();
        }
        KeyCode::Left => {
            ctx.tags.cursor_left();
        }
        KeyCode::Right => {
            ctx.tags.cursor_right();
        }
        KeyCode::Home => {
            ctx.tags.cursor_home();
        }
        KeyCode::End => {
            ctx.tags.cursor_end();
        }
        KeyCode::Char(c) => {
            ctx.tags.insert_char(c);
        }
        KeyCode::Backspace => {
            ctx.tags.backspace();
        }
        _ => {}
    }
}

/// The slice the host-detail overlay touches: the host list (`hosts`,
/// read-only), the tunnel directives (`tunnels`, refreshed in place for the
/// `T` jump), the picker selection state (`ui`), the status center (stale-host
/// warnings) and the screen. The `e` key opens the host edit form, a whole-App
/// helper shared with several handlers, so it runs as a deferred effect.
struct HostDetailCtx<'a> {
    hosts: &'a HostState,
    tunnels: &'a mut TunnelState,
    ui: &'a mut UiSelection,
    status: &'a mut StatusCenter,
    screen: &'a mut Screen,
    effects: Effects,
}

impl Nav for HostDetailCtx<'_> {
    fn screen_mut(&mut self) -> &mut Screen {
        self.screen
    }
}

impl Notify for HostDetailCtx<'_> {
    fn status_mut(&mut self) -> &mut StatusCenter {
        self.status
    }
}

impl Effectful for HostDetailCtx<'_> {
    fn effects_mut(&mut self) -> &mut Effects {
        &mut self.effects
    }
}

pub(super) fn handle_key(app: &mut App, key: KeyEvent) {
    let index = match app.screen {
        Screen::HostDetail { index } => index,
        _ => return,
    };
    // `filtered_snippet_indices` reads ui.snippet_search + snippets together
    // and is a pure read; resolve it here so the slice need not borrow
    // snippets. The `r` arm only inspects whether the result is empty, which
    // is unaffected by the screen transition that precedes it.
    let snippet_indices = app.filtered_snippet_indices();
    let effects = {
        let mut ctx = HostDetailCtx {
            hosts: &app.hosts_state,
            tunnels: &mut app.tunnels,
            ui: &mut app.ui,
            status: &mut app.status_center,
            screen: &mut app.screen,
            effects: Effects::default(),
        };
        host_detail_key(&mut ctx, key, index, &snippet_indices);
        ctx.effects
    };
    effects.apply(app);
}

fn host_detail_key(
    ctx: &mut HostDetailCtx,
    key: KeyEvent,
    index: usize,
    snippet_indices: &[usize],
) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('i') => {
            ctx.set_screen(Screen::HostList);
        }
        KeyCode::Char('?') => {
            ctx.push_help_overlay();
        }
        KeyCode::Char('e') => {
            if let Some(host) = ctx.hosts.list().get(index).cloned() {
                let hint = super::host_form::stale_hint_for(&host);
                ctx.defer(move |app| {
                    app.open_host_edit_form(host, hint);
                });
            }
        }
        KeyCode::Char('T') => {
            if let Some(host) = ctx.hosts.list().get(index) {
                let stale_hint = super::host_form::stale_hint_for(host);
                let alias = host.alias.clone();
                if let Some(hint) = stale_hint {
                    ctx.notify_warning(crate::messages::stale_host(&hint));
                }
                // refresh_tunnel_list mirrors App's on the slice; the code
                // below reads tunnels.list(), so it must run here, not deferred.
                ctx.tunnels.load_directives(ctx.hosts.ssh_config(), &alias);
                *ctx.ui.tunnel_list_state_mut() = ratatui::widgets::ListState::default();
                if !ctx.tunnels.list().is_empty() {
                    ctx.ui.tunnel_list_state_mut().select(Some(0));
                }
                ctx.set_screen(Screen::TunnelList { alias });
            }
        }
        KeyCode::Char('r') => {
            if let Some(host) = ctx.hosts.list().get(index) {
                let stale_hint = super::host_form::stale_hint_for(host);
                let alias = host.alias.clone();
                if let Some(hint) = stale_hint {
                    ctx.notify_warning(crate::messages::stale_host(&hint));
                }
                let aliases = vec![alias];
                ctx.defer(move |app| app.snippets.set_flow_targets(aliases));
                ctx.set_screen(Screen::SnippetPicker);
                *ctx.ui.snippet_picker_state_mut() = ratatui::widgets::ListState::default();
                if !snippet_indices.is_empty() {
                    ctx.ui.snippet_picker_state_mut().select(Some(0));
                }
            }
        }
        _ => {}
    }
}
