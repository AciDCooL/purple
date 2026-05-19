#!/usr/bin/env bash
# Design system enforcement checks.
# Run after cargo doc and before smoke_tui in the pre-commit sequence.

set -euo pipefail

# 1. No manual Block construction outside design.rs/mod.rs.
#    Catches the chain whether `.borders(` lands on the same line or wraps
#    after rustfmt splits the call. Earlier single-line grep missed
#    `Block::default()` followed by `.borders(...)` on the next line
#    (verified false-negative in jump.rs:121 before the 3.15.0 sweep).
BLOCK_HITS=$(grep -rnE 'Block::(default|new|bordered)\s*\(\s*\)' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' | grep -v 'mod\.rs' | grep -v '_tests\.rs' \
    || true)
if [ -n "$BLOCK_HITS" ]; then
    echo "ERROR: Manual Block construction found outside allowed files."
    echo "       Use design::overlay_block() / overlay_block_line() / plain_overlay_block() /"
    echo "       danger_block() / danger_block_line() / main_block() / main_block_line() /"
    echo "       search_block() / search_block_line() / search_overlay_block_line()."
    echo "$BLOCK_HITS"
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

# 8. No inline icon / status / glyph codepoints outside design.rs.
#    Mirrors the full ICON_* / ROUTE_BRANCH / HOST_HIGHLIGHT / TREE_*
#    constant set exported by design.rs. Earlier release shipped 9
#    inline `\u{25CF}` / `\u{25CB}` / `\u{2716}` literals across 8 files
#    because this check only blocked `\u{25B8}` and `\u{2423}`. Keep
#    this regex in lockstep with the constants in design.rs.
INLINE_ICON_HITS=$(grep -rEn '"\\u\{(25B8|2423|25CF|25CB|25D0|25C9|25BE|2716|2713|26A0|258C|250A|25B2|00B7)\}"' \
    src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' | grep -v '_tests\.rs' \
    | grep -v 'activity_chart\.rs' \
    || true)
if [ -n "$INLINE_ICON_HITS" ]; then
    echo "ERROR: Inline icon / status / chrome glyph codepoint found."
    echo "       Use design::ICON_ONLINE / ICON_STOPPED / ICON_PAUSED / ICON_ERROR /"
    echo "       ICON_SUCCESS / ICON_WARNING / ICON_SLOW / ICON_PENDING / ICON_TARGET /"
    echo "       ROUTE_BRANCH / TREE_BRANCH / TREE_EXPANDED / TREE_COLLAPSED /"
    echo "       HOST_HIGHLIGHT / PICKER_ARROW / TOGGLE_HINT."
    echo "$INLINE_ICON_HITS"
    exit 1
fi

# 8a. List rows render flush against LIST_HIGHLIGHT / HOST_HIGHLIGHT.
#     The first column of every row in a `List` widget is rendered straight
#     after the highlight_symbol. Rows that prepend extra whitespace via
#     `format!("   <name>", ...)` create a wider-than-elsewhere padded column
#     that drifts away from sibling overlays (see 2026-05-08 image #6 review).
#     Rule: no `format!("   ` (3+ leading spaces) inside src/ui except for
#     the explicit whitelist below — tree-glyph leaf indentation in
#     provider_list, and confirm-dialog body lines in file_browser.
LIST_PADDING_HITS=$(grep -rnE 'format!\("   ' src/ui/ --include='*.rs' \
    | grep -v '_tests\.rs' \
    | grep -v 'src/ui/provider_list\.rs:.*TREE_BRANCH' \
    | grep -v 'src/ui/file_browser\.rs:.*dest_path' \
    | grep -v 'src/ui/file_browser\.rs:.*more' \
    || true)
if [ -n "$LIST_PADDING_HITS" ]; then
    echo "ERROR: List-row content with 3+ leading spaces detected."
    echo "       Rows render directly after LIST_HIGHLIGHT / HOST_HIGHLIGHT;"
    echo "       extra spaces produce wider padding than other overlays."
    echo "       If this is a tree-aligned leaf row or confirm-dialog body,"
    echo "       extend the allowlist in scripts/check-design-system.sh."
    echo "$LIST_PADDING_HITS"
    exit 1
fi

# 8b. Footer key labels must come from messages::footer (single source of truth).
#     Detect: `.primary("...", " <word> ")` and `.action("...", " <word> ")` with
#     a string-literal label. The regex anchors on `, "` followed by content
#     ending in `")`. Allows passing in a variable (no quote on second arg).
#     Exempt: design.rs (the helpers themselves), the `messages/footer.rs` file,
#     and width-padding "compact"/" detail " labels in host_list which are
#     dynamic by view-state.
INLINE_FOOTER_HITS=$(grep -rnE '\.(primary|action)\("[^"]+",\s*"[^"]+"\)' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' \
    | grep -v 'messages' \
    | grep -v '_tests\.rs' \
    || true)
if [ -n "$INLINE_FOOTER_HITS" ]; then
    echo "ERROR: Inline footer label literal found. Use crate::messages::footer constants."
    echo "       Defined in src/messages/footer.rs."
    echo "$INLINE_FOOTER_HITS"
    exit 1
fi

# 9. Golden file count matches expected screen count.
GOLDEN_COUNT=$(ls tests/visual_golden/*.golden 2>/dev/null | wc -l | tr -d ' ')
EXPECTED_GOLDEN=82
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

# 17. theme::footer_key() may only appear in approved files.
#
# Design system rule: footer_key() renders the inverted keycap style.
# Legitimate uses are footer action chips (built via design::Footer) and
# content-level keycap hints (welcome screen, confirm-dialog Enter/?/I
# hints, host-list tag-mode `tag:` / `tag=` labels). Applying footer_key()
# to regular prose creates a keycap look-alike that the user mistakes for
# a pressable hint.
#
# Files allowed to call `theme::footer_key()`:
# - design.rs              the Footer builder uses it for action chips
# - mod.rs                 legacy helpers + jump bar footer
# - theme.rs               function definition
# - host_list.rs           content-level "tag:" / "tag=" mode hints
# - confirm_dialog.rs      content-level Enter / ? / I keycap hints
if grep -rEn 'theme::footer_key\(\)' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' \
    | grep -v 'mod\.rs' \
    | grep -v 'theme\.rs' \
    | grep -v 'host_list\.rs' \
    | grep -v 'confirm_dialog\.rs' \
    | grep -v '_tests\.rs' \
    | grep -q .; then
    echo "ERROR: theme::footer_key() used outside the approved files."
    echo "       Keycap styling is reserved for footer action chips and"
    echo "       documented content-level hints. Move action chips through"
    echo "       design::Footer; for new keycap-looking content, extend the"
    echo "       allowlist in scripts/check-design-system.sh check 17."
    grep -rEn 'theme::footer_key\(\)' src/ui/ --include='*.rs' \
        | grep -v 'design\.rs' \
        | grep -v 'mod\.rs' \
        | grep -v 'theme\.rs' \
        | grep -v 'host_list\.rs' \
        | grep -v 'confirm_dialog\.rs' \
        | grep -v '_tests\.rs'
    exit 1
fi

# 18. confirm_footer_destructive verbs must be action verbs on both sides.
#
# Stakes test for destructive confirm dialogs: render action verbs on both
# yes and no chips so the user understands what each choice does without
# re-reading the prompt. Generic placeholders (yes/no/y/n/ok) break that
# contract: the no-side reads like "abandon" instead of like the action
# that will happen on the system if the user picks it.
#
# Canonical pairs: (delete,keep), (sign,skip), (purge,keep), (reset,keep),
# (import,skip), (restart,keep), (stop,keep), (copy,skip), (discard,keep).
python3 - <<'PY' || exit 1
import re, sys, os

ROOT = "src/ui"
BANNED = {"yes", "no", "y", "n", "ok", "cancel"}
violations = []

for dirpath, _, files in os.walk(ROOT):
    for fn in files:
        if not fn.endswith(".rs"):
            continue
        if "test" in fn or fn == "design.rs":
            continue
        path = os.path.join(dirpath, fn)
        with open(path) as f:
            text = f.read()
        for m in re.finditer(
            r'confirm_footer_destructive\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)',
            text,
        ):
            yes_verb, no_verb = m.group(1), m.group(2)
            offenders = [v for v in (yes_verb, no_verb) if v in BANNED]
            if offenders:
                violations.append(
                    f"{path}: confirm_footer_destructive({yes_verb!r}, {no_verb!r}) "
                    f"uses generic verb(s) {offenders}. Pick action verbs both sides."
                )

if violations:
    print("ERROR: confirm-footer verb pair violation(s):")
    for v in violations:
        print("  " + v)
    print()
    print("  Stakes test: destructive confirms render action verbs both")
    print("  sides (e.g. 'delete'/'keep', 'sign'/'skip'). Generic verbs")
    print("  like 'yes'/'no'/'cancel' break that contract.")
    sys.exit(1)
PY

# 19. Every public design.rs symbol must appear in docs/design-system-reference.md.
#
# Catches drift between the primitive library and its lookup-table reference.
# A primitive that callers can find by grep but cannot find by reading the
# reference doc is invisible to new contributors and to design reviews.
#
# The reference doc lives under `docs/` which is gitignored. The check is
# therefore a local-only gate: when the file is absent (e.g. CI runners or
# fresh clones), it skips with a notice instead of failing.
if [ -f docs/design-system-reference.md ]; then
    python3 - <<'PY' || exit 1
import re, sys

with open("src/ui/design.rs") as f:
    src = f.read()
with open("docs/design-system-reference.md") as f:
    doc = f.read()

names = re.findall(r"^pub (?:fn|const|struct|enum) (\w+)", src, re.M)
# Exempt a small set of internal-feeling primitives. Add justification.
exempt = {
    "Footer",            # builder type; documented under "Footer builder"
    "FieldKind",         # enum used by form_save_footer; documented under that helper
    "FormFooterMode",    # enum used by form_save_footer; documented under that helper
    "BOX_TL", "BOX_TR", "BOX_BL", "BOX_BR", "BOX_H", "BOX_V",  # internal section-card glyphs
}
missing = [n for n in names if n not in doc and n not in exempt]
if missing:
    print("ERROR: public design.rs symbols missing from docs/design-system-reference.md:")
    for n in missing:
        print("  " + n)
    print()
    print("  Document each in the reference doc, or add to the exempt set in check 19")
    print("  with a one-line justification.")
    sys.exit(1)
PY
else
    echo "Check 19 skipped: docs/design-system-reference.md not present (local-only doc)."
fi

# 20. Every Screen variant must have a visual_<snake_case_name> test.
#
# Rule: adding a new `Screen` variant requires adding a `visual_<name>`
# test and bumping `EXPECTED_GOLDEN`. Catches the trap where the count
# check (9) passes only because both the test AND the golden file are
# missing.
python3 - <<'PY' || exit 1
import re, sys

with open("src/app/screen.rs") as f:
    screen_src = f.read()
with open("src/visual_regression_tests.rs") as f:
    tests_src = f.read()

# Locate the `pub enum Screen { ... }` block by brace balancing — the body
# contains nested `{ }` (e.g. `EditHost { alias: String }`), so a regex
# anchored on the closing brace would never match.
start = screen_src.find("pub enum Screen")
if start < 0:
    print("WARN: could not locate `pub enum Screen`; skipping check 20")
    sys.exit(0)
open_brace = screen_src.find("{", start)
depth = 0
end = -1
for i in range(open_brace, len(screen_src)):
    if screen_src[i] == "{":
        depth += 1
    elif screen_src[i] == "}":
        depth -= 1
        if depth == 0:
            end = i
            break
if end < 0:
    print("WARN: could not balance braces in `pub enum Screen`; skipping check 20")
    sys.exit(0)

body = screen_src[open_brace + 1 : end]
variants = set()
for line in body.splitlines():
    line = line.strip()
    if not line or line.startswith("//"):
        continue
    vm = re.match(r"(\w+)\s*[\{\(,]", line)
    if vm:
        variants.add(vm.group(1))

# A variant is considered covered when `Screen::<Variant>` appears somewhere
# in the visual regression test source.
missing = sorted(v for v in variants if f"Screen::{v}" not in tests_src)
if missing:
    print("ERROR: Screen variants without a visual_ regression test:")
    for v in missing:
        print("  Screen::" + v)
    print()
    print("  Add `visual_<snake_case_name>` in src/visual_regression_tests.rs,")
    print("  run scripts/update-golden.sh, and bump EXPECTED_GOLDEN in this script.")
    sys.exit(1)
PY

# 21. No non-Rounded BorderType in screen code.
#
# Design system mandates BorderType::Rounded everywhere. Any other
# variant must be an explicit, documented exception.
BORDER_HITS=$(grep -rEn 'BorderType::(Plain|Thick|Double|QuadrantInside|QuadrantOutside)' \
    src/ui/ --include='*.rs' \
    | grep -v '_tests\.rs' \
    || true)
if [ -n "$BORDER_HITS" ]; then
    echo "ERROR: Non-Rounded BorderType found. Use BorderType::Rounded everywhere."
    echo "$BORDER_HITS"
    exit 1
fi

# 22. No orphan .actual files in tests/visual_golden/.
#
# `update-golden.sh` writes one .actual per test run. Stale .actual files
# from removed tests accumulate silently and pollute `git diff`. Every
# .actual file must have a matching .golden.
ORPHAN_ACTUAL=$(find tests/visual_golden -name '*.actual' -type f 2>/dev/null \
    | while read -r f; do
        golden="${f%.actual}.golden"
        if [ ! -f "$golden" ]; then
            echo "$f"
        fi
      done \
    || true)
if [ -n "$ORPHAN_ACTUAL" ]; then
    echo "ERROR: orphan .actual files in tests/visual_golden/ (no matching .golden):"
    echo "$ORPHAN_ACTUAL"
    echo
    echo "  Delete them: find tests/visual_golden -name '*.actual' -type f \\"
    echo "    | while read f; do [ -f \"\${f%.actual}.golden\" ] || rm -f \"\$f\"; done"
    exit 1
fi

# 24. Destructive `pending_delete` / `pending_*_confirm` branches must
#     render as centred popups (design::render_destructive_popup), not
#     as footer prompts under the parent overlay. Footer prompts re-
#     introduced the inconsistency that this design-system rule exists
#     to prevent — destructive confirms have one rendering shape, and
#     the shape is a centred danger-block popup with action verbs.
DESTRUCTIVE_FOOTER_HITS=$(grep -rEn 'pending_delete\.is_some\(\)|pending_discard_confirm' \
    src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' \
    | grep -v '_tests\.rs' \
    | grep -v 'render_destructive_popup' \
    || true)
# For each file that has a pending_delete render branch, verify the
# branch uses render_destructive_popup. The heuristic: any file where
# `pending_delete.is_some()` appears must ALSO contain a call to
# `render_destructive_popup` within the same render path.
if [ -n "$DESTRUCTIVE_FOOTER_HITS" ]; then
    DESTRUCTIVE_FAIL=0
    for f in $(echo "$DESTRUCTIVE_FOOTER_HITS" | cut -d: -f1 | sort -u); do
        # Discard-changes confirms (form abandonment) use the dedicated
        # `render_discard_prompt` footer helper by design; they sit on
        # a different stakes tier than delete/remove confirms and are
        # exempt. Delete-style confirms must use the popup.
        if grep -q 'render_destructive_popup\|render_discard_prompt' "$f" 2>/dev/null; then
            continue
        fi
        echo "ERROR: $f branches on pending_delete/pending_*_confirm without design::render_destructive_popup"
        DESTRUCTIVE_FAIL=1
    done
    if [ "$DESTRUCTIVE_FAIL" -eq 1 ]; then
        echo "       Destructive confirms render as centred popups, not as"
        echo "       footer prompts. Use design::render_destructive_popup with"
        echo "       messages::CONFIRM_*_TITLE / _QUESTION / _DETAIL constants."
        echo "       (Form discard confirms via design::render_discard_prompt are"
        echo "       a separate, intentionally lighter stakes tier and exempt.)"
        exit 1
    fi
fi

# 23. Paragraph body content must reserve right-margin breathing room.
#
# `Paragraph::new(text).block(block)` rendered to a full block area (or
# `block.inner(area)`) writes the last glyph flush against the right `│`
# whenever the longest line fills the inner width. Same with Wrap.
# Render bodies via `design::render_body` / `render_body_wrapped` (which
# inset by `design::BODY_RIGHT_PAD`), or compute `design::body_area(area)`
# manually.
PARAGRAPH_BODY_HITS=$(grep -rEn '\.block\(\s*block\s*\)' src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' \
    | grep -v '_tests\.rs' \
    || true)
# Filter to the bare pattern `Paragraph::new(...).block(block)`; with no
# `.wrap(`, no `body_area(`, no `render_body`, and not assigned to a name
# that is later inset. Heuristic: flag the line if there is no `body_area`
# OR `render_body` OR `.wrap(` within ±3 lines of the match.
python3 - <<'PY' || exit 1
import re, sys, os, pathlib

ROOT = pathlib.Path("src/ui")
violations = []
PAT = re.compile(r"\.block\(\s*block\s*\)")

for path in sorted(ROOT.rglob("*.rs")):
    name = path.name
    if name in ("design.rs",) or "test" in name:
        continue
    text = path.read_text()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not PAT.search(line):
            continue
        window = "\n".join(lines[max(0, i - 3) : min(len(lines), i + 4)])
        if "body_area" in window or "render_body" in window or ".wrap(" in window:
            continue
        # Single-line content (e.g. a one-line title that's already padded by
        # `format!` is fine. Only flag when the surrounding context indicates
        # multi-line body text. Heuristic: the variable backing the Paragraph
        # is named `text` and the same window contains `vec!` building lines.
        if "Paragraph::new(text)" not in line:
            continue
        violations.append(f"{path}:{i+1}: Paragraph::new(text).block(block) without wrap or body_area")

if violations:
    print("ERROR: paragraph body content without right-margin breathing room:")
    for v in violations:
        print("  " + v)
    print()
    print("  Use design::render_body_wrapped(frame, area, block, lines) for prose,")
    print("  design::render_body(frame, area, block, lines) for pre-sized rows,")
    print("  or render to design::body_area(area) manually for custom layouts.")
    sys.exit(1)
PY

echo "Design system checks: OK"
