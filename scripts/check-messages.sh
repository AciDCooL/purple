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

if [ $FAIL -eq 0 ]; then
    echo "Message centralization checks: OK"
fi

exit $FAIL
