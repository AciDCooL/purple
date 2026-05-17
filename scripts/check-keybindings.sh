#!/usr/bin/env bash
# Keyboard interaction enforcement.
#
# Codifies the four keyboard interaction invariants as commit-time checks
# so future contributions cannot regress them:
#
#   1. Enter ALWAYS submits a form (never opens pickers).
#   2. Space activates the focused field (picker/toggle/literal).
#   3. Confirm dialogs accept y/n/Esc only — no `_ =>` catch-all that
#      transitions screen state.
#   4. Confirm footer labels follow the stakes test (action verbs for
#      destructive confirms).
#
# This script enforces invariant 1 (Enter must not open pickers in form
# handlers), the route_confirm_key adoption hint, and the destructive
# confirm-footer helper for new confirms. Invariant 4's specific verb
# choices are a content decision left to humans.

set -euo pipefail
FAIL=0

# Tempdir for intermediate awk output. The trap removes it on every exit
# path so a kill or unexpected failure leaves no leftovers in /tmp.
TMPDIR_KB=$(mktemp -d)
trap 'rm -rf "$TMPDIR_KB"' EXIT

# 1. Form handlers must NOT dispatch Enter to picker opens.
#    The handler must call submit_*() unconditionally on Enter; pickers
#    are activated via Space (Char(' ')). Scan every handler under
#    src/handler/ (except picker.rs itself which legitimately uses Enter
#    to choose an item) for the pattern `KeyCode::Enter` followed within
#    a 6-line window by `Screen::*Picker*` set via `set_screen` or
#    `app.screen =`. Earlier check grepped for five hard-coded function
#    names that no longer exist; it was permanently green.
python3 - <<'PY' > "$TMPDIR_KB/enter_hits" 2>/dev/null || true
import os, re

ROOT = "src/handler"
violations = []
enter_re = re.compile(r"KeyCode::Enter\b")
picker_set_re = re.compile(r"(set_screen|app\.screen\s*=)\s*[^;]*Screen::\w*[Pp]icker")

for dirpath, _, files in os.walk(ROOT):
    for fn in files:
        if not fn.endswith(".rs"):
            continue
        if fn in ("picker.rs", "mod.rs"):
            continue
        if "_tests" in fn or fn.endswith("_test.rs"):
            continue
        path = os.path.join(dirpath, fn)
        with open(path) as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if not enter_re.search(line):
                continue
            for j in range(i + 1, min(i + 7, len(lines))):
                if picker_set_re.search(lines[j]):
                    violations.append(
                        f"{path}:{i+1}: KeyCode::Enter dispatches to a picker screen "
                        f"(transition near line {j+1})"
                    )
                    break

for v in violations:
    print(v)
PY
if [ -s "$TMPDIR_KB/enter_hits" ]; then
    echo "ERROR: Enter dispatches to picker open in a form handler."
    echo "       Enter must always submit; pickers open on Space."
    echo "       Invariant 1: Enter always submits a form, never opens a picker."
    cat "$TMPDIR_KB/enter_hits"
    FAIL=1
fi

# 1b. SPACE GUARD marker must precede Char(' ') in any handler that also
#     matches Char(c). Without the guard the generic Char(c) arm shadows
#     the space arm and the field-action (toggle/picker open) becomes
#     unreachable. The marker is a comment, not a static analysis tool,
#     but its presence is mandatory and trivial to enforce.
SPACE_GUARD_FAIL=0
while IFS= read -r f; do
    [ -z "$f" ] && continue
    # tests.rs is a test harness; ordering rules apply to handler files only.
    case "$f" in
        *tests.rs|*_tests.rs|*test_*.rs) continue ;;
    esac
    if grep -q "KeyCode::Char(c)" "$f" 2>/dev/null \
       && ! grep -q "SPACE GUARD MUST PRECEDE" "$f" 2>/dev/null; then
        echo "ERROR: $f has both Char(' ') and Char(c) arms but no SPACE GUARD MUST PRECEDE comment."
        SPACE_GUARD_FAIL=1
    fi
done < <(grep -rln "KeyCode::Char(' ')" src/handler/ --include='*.rs' || true)
if [ "$SPACE_GUARD_FAIL" -eq 1 ]; then
    echo "       Invariant 2: Space activates the focused field."
    echo "       Add a SPACE GUARD MUST PRECEDE comment immediately above the"
    echo "       Char(' ') arm so future contributors don't reorder it under"
    echo "       the generic Char(c) catch-all."
    FAIL=1
fi

# 1c. Inline pending_delete / pending_discard_confirm blocks must route
#     through handler::route_confirm_key. Even when today's `_ => {}` is
#     benign, the next refactor that adds a state mutation inside that arm
#     becomes a silent regression of the y/n/Esc contract.
INLINE_CONFIRM_FAIL=0
while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -q 'route_confirm_key' "$f" 2>/dev/null; then
        echo "ERROR: $f handles pending_delete / pending_discard_confirm without route_confirm_key."
        INLINE_CONFIRM_FAIL=1
    fi
done < <(grep -rln 'pending_delete\.is_some\|pending_discard_confirm' src/handler/ --include='*.rs' || true)
if [ "$INLINE_CONFIRM_FAIL" -eq 1 ]; then
    echo "       Invariant 3: confirm dialogs accept y/n/Esc only."
    echo "       Migrate the inline match block to:"
    echo "         match super::route_confirm_key(key) {"
    echo "             super::ConfirmAction::Yes => { /* ... */ }"
    echo "             super::ConfirmAction::No => { /* ... */ }"
    echo "             super::ConfirmAction::Ignored => {}"
    echo "         }"
    FAIL=1
fi

# 2. Confirm handlers must use route_confirm_key (or have no `_ =>` arm
#    that transitions state). Detection heuristic: any handler function
#    that matches Char('y') / Char('Y') AND Char('n') in close proximity
#    is a confirm handler. We scan for `_ =>` lines with `app.screen` or
#    `app.pending_*` mutations within ~4 lines after a Char('y') match.
#
#    Conservative implementation: flag any file under src/handler/ that has
#    BOTH `KeyCode::Char('y')` AND `_ =>` AND `app.screen =` within a
#    20-line window, except confirm.rs (which now uses route_confirm_key).
CONFIRM_FILES=$(grep -rln "KeyCode::Char('y')" src/handler/ --include='*.rs' || true)
for file in $CONFIRM_FILES; do
    # Find each Char('y') line; check the 20 lines that follow for both
    # `_ =>` and a state transition. False positives are acceptable here
    # because the fix is to switch to route_confirm_key.
    awk '
        /KeyCode::Char\(.y.\)/ { window = 20; saw_catch = 0; saw_state = 0 }
        window > 0 {
            if (/^[[:space:]]*_ =>/) saw_catch = 1
            if (saw_catch && /app\.screen[[:space:]]*=/) saw_state = 1
            if (saw_state) {
                print FILENAME ":" NR ": catch-all `_ =>` transitions screen state in confirm handler"
                window = 0
                saw_catch = 0
                saw_state = 0
            }
            window--
        }
    ' "$file" > "$TMPDIR_KB/state_hits"
    if [ -s "$TMPDIR_KB/state_hits" ]; then
        echo "ERROR: Confirm handler has a \`_ =>\` arm that transitions state."
        echo "       Use handler::route_confirm_key(key) and match"
        echo "       ConfirmAction::{Yes, No, Ignored} explicitly. Stray keys"
        echo "       must not silently cancel destructive operations."
        echo "       Invariant 3: confirm dialogs accept y/n/Esc only."
        cat "$TMPDIR_KB/state_hits"
        FAIL=1
    fi
done

# 3. Confirm handlers with both Char('y') AND Char('Y') (the canonical
#    case-insensitive y/Y pattern) must also handle Char('n'). This avoids
#    false positives on lowercase-only `y` shortcuts (e.g. host list yank).
#    Confirm dialogs always handle both cases of the affirmative key.
for file in $CONFIRM_FILES; do
    # Skip files that route through the helper (they handle n via the helper)
    if grep -q 'route_confirm_key' "$file"; then
        continue
    fi
    # Only flag when both lower- and upper-case y are present (confirm pattern).
    if ! grep -q "KeyCode::Char('Y')" "$file"; then
        continue
    fi
    if ! grep -q "KeyCode::Char('n')" "$file"; then
        echo "ERROR: $file matches Char('y')|Char('Y') but not Char('n')."
        echo "       Confirm dialogs must accept n/N as cancel (uniform with"
        echo "       Esc). Either add an explicit Char('n') | Char('N') arm,"
        echo "       or migrate to handler::route_confirm_key(key)."
        echo "       Invariant 3: confirm dialogs accept y/n/Esc only."
        FAIL=1
    fi
done

# 4. New confirm-style footers should use the design helpers, not raw
#    Footer::new().action("y", ...). The helpers encode the stakes test.
#    Existing bare Footer usage in tests and overlays that genuinely need
#    custom labels is allowed via an opt-out comment.
RAW_CONFIRM=$(grep -rn '\.action("y", " yes "\|\.action("y", " confirm "' \
    src/ui/ --include='*.rs' \
    | grep -v 'design\.rs' \
    | grep -v 'test' \
    || true)
if [ -n "$RAW_CONFIRM" ]; then
    echo "ERROR: Raw y/yes or y/confirm footer construction outside design.rs."
    echo "       Use design::confirm_footer_destructive(yes_verb, no_verb) for"
    echo "       destructive confirms (delete, sign, purge)."
    echo "       Invariant 4: confirm footer labels follow the stakes test."
    echo "$RAW_CONFIRM"
    FAIL=1
fi

if [ $FAIL -eq 0 ]; then
    echo "Keyboard interaction checks: OK"
fi

exit $FAIL
