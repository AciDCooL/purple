#!/usr/bin/env bash
# Design system enforcement checks.
# Run after cargo doc and before smoke_tui in the pre-commit sequence.

set -e

# 1. No manual Block construction outside design.rs/mod.rs.
if grep -rn 'Block::bordered()\|Block::new()\.borders(\|Block::default()\.borders(' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' | grep -v 'mod\.rs' \
    | grep -q .; then
    echo "ERROR: Manual Block construction found outside allowed files."
    echo "       Use design::overlay_block() / overlay_block_line() / plain_overlay_block() /"
    echo "       danger_block() / danger_block_line() / main_block() / main_block_line() /"
    echo "       search_block() / search_block_line()."
    grep -rn 'Block::bordered()\|Block::new()\.borders(\|Block::default()\.borders(' src/ui/ --include='*.rs' \
        | grep -v 'design\.rs' | grep -v 'mod\.rs'
    exit 1
fi

# 2. No direct footer builders (footer_action / footer_key_span) called from screens.
#    Inline `theme::footer_key()` styling inside content (e.g. welcome "Press ? for help"
#    or the host-list compound title's tag labels) is allowed — those are content spans,
#    not footer actions. Footer actions must flow through the `design::Footer` builder.
if grep -rn 'super::footer_action\|super::footer_key_span' src/ui/ \
    --include='*.rs' | grep -v 'design\.rs' | grep -v 'mod\.rs' \
    | grep -q .; then
    echo "ERROR: Manual footer construction found. Use design::Footer builder."
    grep -rn 'super::footer_action\|super::footer_key_span' src/ui/ \
        --include='*.rs' | grep -v 'design\.rs' | grep -v 'mod\.rs'
    exit 1
fi

# 3. No old notification API outside method definitions and delegations.
#
# Exclusions:
#  - `src/app/status_state.rs` is the defining module, so its own inline
#    `#[cfg(test)] mod tests` may call its deprecated `set_*` methods to
#    verify their behaviour. The deprecation is already signalled by the
#    `#[deprecated]` attribute on the definition site.
#  - `src/app.rs` dispatches through `status_center.set_*` shims; the
#    regex is anchored to that file so the exception cannot leak.
if grep -rn 'set_status\|set_background_status\|set_sticky_status\|set_info_status' \
    src/ --include='*.rs' \
    | grep -v 'tests\.rs' | grep -v 'test_' | grep -v '#\[deprecated' \
    | grep -v 'pub fn ' | grep -v 'pub use ' \
    | grep -v 'self\.set_' | grep -Ev '^src/app\.rs:[0-9]+:.*status_center\.set_' \
    | grep -v '^src/app/status_state\.rs:' \
    | grep -v '// ' | grep -v '/// ' \
    | grep -q .; then
    echo "ERROR: Old notification API used. Use app.notify/notify_error/etc."
    grep -rn 'set_status\|set_background_status\|set_sticky_status\|set_info_status' \
        src/ --include='*.rs' \
        | grep -v 'tests\.rs' | grep -v 'test_' | grep -v '#\[deprecated' \
        | grep -v 'pub fn ' | grep -v 'pub use ' \
        | grep -v 'self\.set_' | grep -Ev '^src/app\.rs:[0-9]+:.*status_center\.set_' \
        | grep -v '^src/app/status_state\.rs:' \
        | grep -v '// ' | grep -v '/// '
    exit 1
fi

# 4. No direct centered_rect calls from screen files.
if grep -rn 'centered_rect(' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' | grep -v 'mod\.rs' | grep -q .; then
    echo "ERROR: Direct centered_rect() call found. Use design::overlay_area()."
    grep -rn 'centered_rect(' src/ui/ --include='*.rs' \
        | grep -v 'design\.rs' | grep -v 'mod\.rs'
    exit 1
fi

# 5. No hardcoded highlight_symbol outside design.rs/mod.rs
if grep -rn 'highlight_symbol("' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' | grep -v 'mod\.rs' | grep -q .; then
    echo "ERROR: Hardcoded highlight_symbol found. Use design::LIST_HIGHLIGHT or design::HOST_HIGHLIGHT."
    grep -rn 'highlight_symbol("' src/ui/ --include='*.rs' \
        | grep -v 'design\.rs' | grep -v 'mod\.rs'
    exit 1
fi

# 6. No local padded() closures in screen files (use design::padded_usize).
if grep -rEn 'w \+ w / 10' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' | grep -v 'mod\.rs' | grep -q .; then
    echo "ERROR: Local padded() closure found. Use design::padded_usize()."
    grep -rEn 'w \+ w / 10' src/ui/ --include='*.rs' \
        | grep -v 'design\.rs' | grep -v 'mod\.rs'
    exit 1
fi

# 7. No local render_divider wrappers in screen files (call super::render_divider directly).
if grep -rEn '^fn render_divider\(' src/ui/ --include='*.rs' \
    | grep -v 'mod\.rs' | grep -q .; then
    echo "ERROR: Local render_divider() wrapper found. Call super::render_divider() directly."
    grep -rEn '^fn render_divider\(' src/ui/ --include='*.rs' \
        | grep -v 'mod\.rs'
    exit 1
fi

# 8. No inline picker/toggle glyphs outside design.rs (use design::PICKER_ARROW / TOGGLE_HINT).
if grep -rEn '"\\u\{25B8\}"|"\\u\{2423\}"' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' | grep -q .; then
    echo "ERROR: Inline glyph found. Use design::PICKER_ARROW or design::TOGGLE_HINT."
    grep -rEn '"\\u\{25B8\}"|"\\u\{2423\}"' src/ui/ --include='*.rs' \
        | grep -v 'design\.rs'
    exit 1
fi

# 9. Golden file count matches expected screen count.
GOLDEN_COUNT=$(ls tests/visual_golden/*.golden 2>/dev/null | wc -l | tr -d ' ')
EXPECTED_GOLDEN=40
if [ "$GOLDEN_COUNT" != "$EXPECTED_GOLDEN" ]; then
    echo "ERROR: Expected $EXPECTED_GOLDEN golden files, found $GOLDEN_COUNT."
    echo "If you added a new Screen variant, add a visual regression test and update EXPECTED_GOLDEN."
    exit 1
fi

# 10. No content_and_footer / content_spacer_footer usage (use design::form_footer).
# These helpers were removed when all overlay footers unified to render below the block border.
if grep -rEn 'content_and_footer\(|content_spacer_footer\(' src/ui/ --include='*.rs' | grep -q .; then
    echo "ERROR: content_and_footer / content_spacer_footer were removed. Use design::form_footer for footer placement."
    grep -rEn 'content_and_footer\(|content_spacer_footer\(' src/ui/ --include='*.rs'
    exit 1
fi

# 11. No render_picker_overlay_wide usage (removed in favour of single uniform picker).
# All pickers must call render_picker_overlay so they share the same width range and
# height ceiling (design::PICKER_MIN_W..=PICKER_MAX_W and design::PICKER_MAX_H).
if grep -rEn 'render_picker_overlay_wide' src/ui/ --include='*.rs' | grep -q .; then
    echo "ERROR: render_picker_overlay_wide was removed. All pickers must use render_picker_overlay."
    grep -rEn 'render_picker_overlay_wide' src/ui/ --include='*.rs'
    exit 1
fi

# 12. Picker overlays must use picker_overlay_width(frame), not raw PICKER_MIN_W or
# overlay_area(70, ...) for width. This keeps every picker the same visual size.
if grep -rEn 'centered_rect_fixed\(design::PICKER_MIN_W,' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs\|mod\.rs' | grep -q .; then
    echo "ERROR: Picker uses raw PICKER_MIN_W for width. Use super::picker_overlay_width(frame)."
    grep -rEn 'centered_rect_fixed\(design::PICKER_MIN_W,' src/ui/ --include='*.rs' \
        | grep -v 'design\.rs\|mod\.rs'
    exit 1
fi

# 13. No internal footer rendering to Layout chunks in overlay screens.
# Overlays must render footers via design::render_overlay_footer / form_footer,
# not via Layout::vertical footer rows. host_list.rs is the main screen (not an
# overlay) and is the only allowed exception.
if grep -rEn 'render_footer_with_status\(frame, (chunks|rows|inner_chunks)\[|render_with_status\(frame, (chunks|rows|inner_chunks)\[' \
    src/ui/ --include='*.rs' | grep -v 'host_list\.rs' | grep -v 'test' | grep -q .; then
    echo "ERROR: Footer rendered to Layout chunk instead of design::render_overlay_footer."
    grep -rEn 'render_footer_with_status\(frame, (chunks|rows|inner_chunks)\[|render_with_status\(frame, (chunks|rows|inner_chunks)\[' \
        src/ui/ --include='*.rs' | grep -v 'host_list\.rs' | grep -v 'test'
    exit 1
fi

# 14. theme::success() may not be used to colour live-state glyphs.
#
# Design system rule: `online_dot()` / `online_dot_pulsing()`
# encode "host or tunnel is live right now". `success()` encodes a
# positive action outcome (a check-mark, a toast, "saved successfully").
# Mixing them produces multiple shades of green for the same semantic
# tier and breaks the cross-screen rhythm.
#
# Files allowed to call `theme::success()` for action-outcome surfaces:
# - snippet_output.rs        — exit-code zero badge (one-shot outcome)
# - provider_list.rs         — sync-completion check icon (one-shot outcome)
# - bulk_tag_editor.rs       — tag-diff arrows (action outcome: "this tag was added")
# - detail_panel.rs          — vault-cert `Signed` state (one-shot outcome). Mixed file:
#                              live-state callers MUST use `online_dot()` (see lines
#                              above where `running` and `online` were migrated).
#                              When adding new green spans here, choose deliberately.
if grep -rEn 'theme::success\(\)' src/ui/ --include='*.rs' \
    | grep -v 'snippet_output\.rs' \
    | grep -v 'provider_list\.rs' \
    | grep -v 'bulk_tag_editor\.rs' \
    | grep -v 'detail_panel\.rs' \
    | grep -v 'design\.rs' \
    | grep -v 'mod\.rs' \
    | grep -v 'theme.*tests' \
    | grep -q .; then
    echo "ERROR: theme::success() used for what looks like a live-state indicator."
    echo "       Use theme::online_dot() or theme::online_dot_pulsing(spinner_tick)"
    echo "       for live-now signals. Reserve success() for action-outcome content"
    echo "       (toast banners, completion icons). Add an exception above if your"
    echo "       file is a new toast/outcome surface."
    grep -rEn 'theme::success\(\)' src/ui/ --include='*.rs' \
        | grep -v 'snippet_output\.rs' \
        | grep -v 'provider_list\.rs' \
        | grep -v 'bulk_tag_editor\.rs' \
        | grep -v 'detail_panel\.rs' \
        | grep -v 'design\.rs' \
        | grep -v 'mod\.rs' \
        | grep -v 'theme.*tests'
    exit 1
fi

# 15. Footer chip ordering — primary action first, exit (Esc/Ctrl+C) last.
#
# Canonical order purple already uses in 11+ overlays:
#   .primary("Enter", ...)        // first
#   .action(...)                  // navigation / mode / feature keys
#   .action("Esc"|"Ctrl+C", ...)  // last (exit)
#
# Two violations are flagged:
#  (a) `.action(...)` followed by `.primary(...)` — primary must come BEFORE
#      any action chip on the same builder.
#  (b) `.action("Esc"|"Ctrl+C", ...)` followed by another `.action(...)` —
#      exit chip must be the LAST action.
#
# We scan a sliding two-line window per file. Files exempt: design.rs (the
# builder definition), tests files.
python3 - <<'PY' || exit 1
import re, sys, os

ROOT = "src/ui"
violations = []

PRIMARY_RE = re.compile(r'\.primary\(\s*"([^"]+)"')
ACTION_RE  = re.compile(r'\.action\(\s*"([^"]+)"')
EXIT_KEY   = {"Esc", "Ctrl+C"}

for dirpath, _, files in os.walk(ROOT):
    for fn in files:
        if not fn.endswith(".rs"):
            continue
        if fn in ("design.rs",) or "test" in fn:
            continue
        path = os.path.join(dirpath, fn)
        with open(path) as f:
            text = f.read()

        # Split into Footer-builder chains. Each chain runs from `Footer::new()`
        # to the next non-chained statement. We capture the chain as a single
        # logical line so order can be checked.
        for m in re.finditer(
            r'Footer::new\(\)((?:\s*\.\w+\([^)]*\))+)', text, re.DOTALL
        ):
            chain = m.group(1)
            # Find positions of primary / action / exit-action calls.
            calls = []
            for cm in re.finditer(r'\.(primary|action)\(\s*"([^"]*)"', chain):
                calls.append((cm.group(1), cm.group(2)))

            seen_action = False
            for kind, label in calls:
                if kind == "action":
                    seen_action = True
                if kind == "primary" and seen_action:
                    violations.append(
                        f"{path}: primary action chip appears AFTER an .action(...). "
                        f"Move .primary({label!r}, ...) before any .action(...)."
                    )

            # Exit chip (Esc / Ctrl+C) must be last action.
            for i, (kind, label) in enumerate(calls):
                if kind == "action" and label in EXIT_KEY:
                    if i != len(calls) - 1:
                        tail = ", ".join(f"{k}({l!r})" for k, l in calls[i+1:])
                        violations.append(
                            f"{path}: exit chip .action({label!r}, ...) is not last. "
                            f"Trailing chips: {tail}."
                        )

if violations:
    print("ERROR: footer chip ordering violation(s):")
    for v in violations:
        print("  " + v)
    print()
    print("  Canonical order: primary first, secondary actions middle, exit (Esc/Ctrl+C) last.")
    sys.exit(1)
PY

# 16. Footer exit-label drift — Esc/Ctrl+C must use one of close/back/cancel.
#
# Convention:
#   close  — read-only viewers (snippet output, key detail, jump bar)
#   back   — list overlays in a navigation stack (key list, containers,
#            tag picker, provider list)
#   cancel — forms with unsaved input (host form, snippet form, etc.)
#
# Other verbs are allowed only when the screen has its own non-generic
# semantics (multi-select uses `clear` to convey "drop selection"; that
# is recorded in the allowlist below).
EXIT_VERB_ALLOWLIST="clear|done"
BAD_EXIT=$(grep -rEn '\.action\(\s*"(Esc|Ctrl\+C)"\s*,\s*"\s*[a-z]+' src/ui/ --include='*.rs' \
    | grep -vE '\.action\(\s*"(Esc|Ctrl\+C)"\s*,\s*"\s*(close|back|cancel|'"$EXIT_VERB_ALLOWLIST"')\s*"' \
    | grep -v 'design\.rs' || true)
if [ -n "$BAD_EXIT" ]; then
    echo "ERROR: footer exit-label uses an unrecognised verb."
    echo "       Use 'close' (viewer), 'back' (list overlay), or 'cancel' (form)."
    echo "       Allowlist for screen-specific verbs: $EXIT_VERB_ALLOWLIST"
    echo "$BAD_EXIT"
    exit 1
fi

echo "Design system checks: OK"
