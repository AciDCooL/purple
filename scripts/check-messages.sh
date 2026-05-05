#!/usr/bin/env bash
# Message centralization enforcement.
# Ensures all user-facing strings go through src/messages.rs.
# Run as part of the pre-commit checks.
#
# Scans the entire src/ tree (excluding the messages/ directory itself
# and _tests.rs / tests.rs files). Inline `#[cfg(test)] mod ... {}`
# blocks are stripped from each file before grepping so test fixtures
# can use literal notify strings without tripping the gate.

set -e

FAIL=0

# Build a temporary copy of src/ with #[cfg(test)] mod {...} blocks removed.
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

while IFS= read -r src_file; do
    rel="${src_file#src/}"
    dest="$WORK_DIR/$rel"
    mkdir -p "$(dirname "$dest")"
    awk '
    BEGIN { in_test_attr=0; in_test=0; depth=0 }
    {
        if (in_test) {
            for (i=1; i<=length($0); i++) {
                c=substr($0,i,1)
                if (c=="{") depth++
                else if (c=="}") {
                    depth--
                    if (depth==0) { in_test=0; next }
                }
            }
            next
        }
        if ($0 ~ /^[[:space:]]*#\[cfg\(test\)\]/) {
            in_test_attr=1
            next
        }
        if (in_test_attr && $0 ~ /^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+[a-zA-Z_]+/) {
            in_test_attr=0
            in_test=1
            depth=0
            for (i=1; i<=length($0); i++) {
                c=substr($0,i,1)
                if (c=="{") depth++
                else if (c=="}") depth--
            }
            if (depth==0) { in_test=0 }
            next
        }
        if (in_test_attr) { in_test_attr=0 }
        print
    }
    ' "$src_file" > "$dest"
done < <(find src/ -name '*.rs' ! -name '*_tests.rs' ! -name 'tests.rs' -not -path 'src/messages/*')

SCAN_ROOT="$WORK_DIR"

# 1. No hardcoded string literals in notify calls.
for pattern in \
    '\.notify("[A-Z]' \
    '\.notify_error("[A-Z]' \
    '\.notify_warning("[A-Z]' \
    '\.notify_info("[A-Z]' \
    '\.notify_background("[A-Z]' \
    '\.notify_progress("[A-Z]' \
    '\.notify_sticky_error("[A-Z]' \
    '\.notify_background_error("[A-Z]'; do
    HITS=$(grep -rn "$pattern" "$SCAN_ROOT" --include='*.rs' || true)
    if [ -n "$HITS" ]; then
        echo "ERROR: Hardcoded string in notify call. Use crate::messages::*"
        echo "$HITS" | sed "s|$SCAN_ROOT|src|g"
        FAIL=1
    fi
done

# 2. No format! inside notify calls.
for pattern in \
    '\.notify(format!' \
    '\.notify_error(format!' \
    '\.notify_warning(format!' \
    '\.notify_info(format!' \
    '\.notify_background(format!' \
    '\.notify_progress(format!' \
    '\.notify_sticky_error(format!' \
    '\.notify_background_error(format!'; do
    HITS=$(grep -rn "$pattern" "$SCAN_ROOT" --include='*.rs' || true)
    if [ -n "$HITS" ]; then
        echo "ERROR: format! inside notify call. Move to crate::messages::*"
        echo "$HITS" | sed "s|$SCAN_ROOT|src|g"
        FAIL=1
    fi
done

# 3. No .to_string() on string literals passed to notify.
HITS=$(grep -rn '\.notify.*".*"\.to_string()' "$SCAN_ROOT" --include='*.rs' || true)
if [ -n "$HITS" ]; then
    echo "ERROR: Inline .to_string() in notify call. Use crate::messages::*"
    echo "$HITS" | sed "s|$SCAN_ROOT|src|g"
    FAIL=1
fi

# 4. No hardcoded literals in eprintln!/println!/print! anywhere a user can
# see them. The message-centralization rule scopes to "handler, CLI or UI
# code" — in practice every print macro outside test/log paths lands on
# the user's terminal, so we scan the same SCAN_ROOT used above. Library
# modules (vault_ssh, providers, import) use `log::*` macros and
# `anyhow::bail!` instead of print macros, so they don't trip these
# patterns.
#
# Patterns are deliberately conservative: we only flag literals that
# start with characters typical of user prose — capital letter, single
# quote (`'X' already exists`), bang (`! N lines could not be parsed`),
# or square bracket. Format strings starting with `{`, whitespace or
# numbers (table layout, indented data, numeric prefixes) pass through.
#
# Multi-line `eprintln!(\n  "Foo")` constructs slip through because grep
# is line-oriented. After running rustfmt every previously-multi-line
# call collapses to one line; new violations introduced and fmt'd would
# be caught on the next precommit run. We accept the gap rather than
# pull in pcregrep.
# Patterns are deliberately conservative: we only flag literals that
# start with characters typical of user prose:
#   "[A-Z]   — capital letter at start ("Failed to ...")
#   "'       — quoted-name errors ("'X' already exists")
#   "!       — bang-prefixed warnings ("! N lines ...")
#   "\[[A-Z] — log-style bracket prefix ("[External] ..."). The
#             trailing [A-Z] excludes placeholder prefixes like
#             `[{}] {}` used to label per-host output.
#   "\\n[A-Z] — leading-newline literal ("\nFoo: ...")
#
# Macro-name disambiguation: `println!` is a substring of `eprintln!`,
# so a naive `println!` pattern would double-match and spam the same
# finding under two headings. We anchor `println!` with `(^|[^a-z])`
# so it does not match when preceded by `e`. `print!` is unambiguous
# because `println!` has `l` where `print!` has `!`. PCRE `-P` is not
# available on BSD grep (macOS), so we use POSIX ERE (`-E`) throughout.
declare -a MACRO_PATTERNS=(
    'eprintln![[:space:]]*[(]'
    '(^|[^a-z])println![[:space:]]*[(]'
    '(^|[^a-z])print![[:space:]]*[(]'
)
declare -a MACRO_LABELS=('eprintln!' 'println!' 'print!')

for i in "${!MACRO_PATTERNS[@]}"; do
    macro_pat="${MACRO_PATTERNS[$i]}"
    label="${MACRO_LABELS[$i]}"
    for start in '"[A-Z]' "\"'" '"!' '"\[[A-Z]' '"\\n[A-Z]'; do
        pattern="${macro_pat}${start}"
        HITS=$(grep -rEn "$pattern" "$SCAN_ROOT" --include='*.rs' || true)
        if [ -n "$HITS" ]; then
            echo "ERROR: Hardcoded user-facing literal in $label. Use crate::messages::*"
            echo "$HITS" | sed "s|$SCAN_ROOT|src|g"
            FAIL=1
        fi
    done
done

# 5. No format! built strictly to be passed to a print macro.
# Catches `eprintln!("{}", format!("Foo..."))` style indirection that
# slips past pattern (4). Lines where format!("[A-Z]...") sits inside
# any print macro on the same line get flagged.
for i in "${!MACRO_PATTERNS[@]}"; do
    macro_pat="${MACRO_PATTERNS[$i]}"
    label="${MACRO_LABELS[$i]}"
    pattern="${macro_pat}.*format![(]\"[A-Z]"
    HITS=$(grep -rEn "$pattern" "$SCAN_ROOT" --include='*.rs' || true)
    if [ -n "$HITS" ]; then
        echo "ERROR: format! with hardcoded literal inside $label. Use crate::messages::*"
        echo "$HITS" | sed "s|$SCAN_ROOT|src|g"
        FAIL=1
    fi
done

if [ $FAIL -eq 0 ]; then
    echo "Message centralization checks: OK"
fi

exit $FAIL
