#!/usr/bin/env bash
# Gate: verify the three upstream AUR PKGBUILD templates stay in lockstep
# on the fields that must not drift between them.
#
# The release pipeline used to rely on a manual "before tagging, eyeball
# purple-git" step. That step was forgotten more than once. This gate
# replaces it: any commit that desyncs the templates fails before push.
#
# Shared across all three (purple, purple-bin, purple-git): pkgdesc,
# arch, url, license, depends.
# Shared between the two source builds (purple + purple-git): options,
# and the bodies of prepare()/build()/package() (with the leading `cd`
# line normalized away, because the source archive and the git clone
# land in differently named directories by design).
# purple-bin diverges by design on options, prepare/build (it ships a
# prebuilt binary) and package (installs the binary directly).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG_PURPLE="$REPO_ROOT/packaging/aur/purple/PKGBUILD"
PKG_BIN="$REPO_ROOT/packaging/aur/purple-bin/PKGBUILD"
PKG_GIT="$REPO_ROOT/packaging/aur/purple-git/PKGBUILD"

for f in "$PKG_PURPLE" "$PKG_BIN" "$PKG_GIT"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: missing PKGBUILD: $f"
        exit 1
    fi
done

field() {
    grep -E "^$2=" "$1" | head -1
}

# Function body extractor: everything between `name() {` and the matching
# closing brace at column 0. Strips the leading `cd "..."` line because the
# tarball and git-clone paths differ by construction.
fn_body() {
    awk -v fn="$2" '
        $0 ~ "^"fn"\\(\\) \\{" { in_fn = 1; next }
        in_fn && /^\}/         { exit }
        in_fn && $1 != "cd"    { print }
    ' "$1"
}

fail=0

check_field_shared() {
    local field_name="$1"; shift
    local files=("$@")
    local first="" first_file=""
    for f in "${files[@]}"; do
        local v
        v="$(field "$f" "$field_name")"
        if [ -z "$first_file" ]; then
            first="$v"; first_file="$f"
            continue
        fi
        if [ "$v" != "$first" ]; then
            echo "ERROR: AUR PKGBUILD drift on field '$field_name':"
            echo "  $first_file:"
            echo "    $first"
            echo "  $f:"
            echo "    $v"
            fail=1
        fi
    done
}

check_fn_shared() {
    local fn_name="$1"; shift
    local files=("$@")
    local first="" first_file=""
    for f in "${files[@]}"; do
        local body
        body="$(fn_body "$f" "$fn_name")"
        if [ -z "$first_file" ]; then
            first="$body"; first_file="$f"
            continue
        fi
        if [ "$body" != "$first" ]; then
            echo "ERROR: AUR PKGBUILD drift on '$fn_name()' body (cd lines ignored):"
            echo "  --- $first_file"
            printf '%s\n' "$first"
            echo "  --- $f"
            printf '%s\n' "$body"
            fail=1
        fi
    done
}

# Fields shared by all three.
for fld in pkgdesc arch url license depends; do
    check_field_shared "$fld" "$PKG_PURPLE" "$PKG_BIN" "$PKG_GIT"
done

# Fields and function bodies shared by the two source builds.
check_field_shared options "$PKG_PURPLE" "$PKG_GIT"
for fn in prepare build package; do
    check_fn_shared "$fn" "$PKG_PURPLE" "$PKG_GIT"
done

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "Templates live at packaging/aur/<pkgname>/PKGBUILD."
    echo "Sync the drift, re-run, then commit."
    exit 1
fi
