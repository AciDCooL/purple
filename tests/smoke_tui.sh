#!/bin/bash
# TUI smoke test: launches purple --demo in tmux, navigates through all
# major screens via keystrokes, and verifies no crash at each step.
#
# Requires: tmux, a built purple binary (release or debug).
# Run: ./tests/smoke_tui.sh [path-to-binary]
#
# Exit code 0 = all screens survived, 1 = crash detected.

set -e
cd "$(dirname "$0")/.."

BINARY="${1:-./target/release/purple}"
if [ ! -x "$BINARY" ]; then
    BINARY="./target/debug/purple"
fi
if [ ! -x "$BINARY" ]; then
    printf "No purple binary found. Run cargo build first.\n"
    exit 1
fi

if ! command -v tmux >/dev/null 2>&1; then
    printf "tmux not found. Install it to run the TUI smoke test.\n"
    exit 1
fi

SESSION="purple_smoke_$$"
FAIL=0
STEP=0

cleanup() {
    tmux kill-session -t "$SESSION" 2>/dev/null || true
}
trap cleanup EXIT

step() {
    STEP=$((STEP + 1))
    printf "  [%02d] %s" "$STEP" "$1"
}

ok() { printf " ✓\n"; }

fail() {
    printf " ✗ %s\n" "$1"
    FAIL=1
}

send() {
    tmux send-keys -t "$SESSION" -l "$@" 2>/dev/null
    sleep 0.3
}

send_key() {
    tmux send-keys -t "$SESSION" "$@" 2>/dev/null
    sleep 0.3
}

alive() {
    # Verify the tmux session AND that purple's TUI is still on the
    # alternate screen. Without the second check, pressing Esc on the
    # bare host list (which sets app.running = false) leaves the shell
    # alive in tmux while purple has exited — every subsequent step
    # then "passes" the bare session check but is sending keys to the
    # shell prompt. Look for the title bar that only appears in the
    # TUI: `╭` ... `purple` ... `tunnels`.
    tmux has-session -t "$SESSION" 2>/dev/null || return 1
    local out
    out=$(tmux capture-pane -t "$SESSION" -p 2>/dev/null || true)
    echo "$out" | grep -qF "tunnels" || return 1
    return 0
}

capture() {
    tmux capture-pane -t "$SESSION" -p 2>/dev/null || echo ""
}

# Liveness + content check in one. Used for screens where rendering blank
# (no panel, empty body, missing title) would not crash but also would
# not show the user anything useful. Prefer over the bare `alive` check
# whenever the screen has a stable title or label string.
#
# `pattern` is grep -F text (literal). Pick the most stable substring
# that appears only on this screen — usually the title between the
# rounded ╭ ╮ borders, e.g. " Help ", " Commands ", " Add New Host ".
expect_screen() {
    local pattern="$1"
    if ! alive; then
        fail "crash"
        exit 1
    fi
    OUTPUT=$(capture)
    if echo "$OUTPUT" | grep -qF "$pattern"; then
        ok
    else
        fail "screen missing '$pattern'"
        if [ "${SMOKE_DEBUG:-0}" = "1" ]; then
            printf '\n--- captured pane (last 8 lines) ---\n%s\n---\n' \
                "$(echo "$OUTPUT" | tail -8)"
        fi
    fi
}

# Start purple in demo mode.
# `-c "$(pwd)"` pins the new session to the script's cwd; without it
# tmux can pick up a stale `default-path` from a previously-running
# tmux server, which makes `./target/debug/purple` resolve to nothing
# and the binary exits silently before any capture can see it. The
# downstream effect is that every step then fails with "screen missing"
# even though the keystrokes are correct.
tmux new-session -d -s "$SESSION" -x 120 -y 40 -c "$(pwd)"
sleep 0.3
tmux send-keys -t "$SESSION" "$BINARY --demo" Enter
sleep 3

printf "=== Purple TUI Smoke Test ===\n\n"

# 1. Host list
step "Host list renders"
if alive; then
    OUTPUT=$(capture)
    # Check for the title bar which shows host count (e.g. "purple -- 22")
    if echo "$OUTPUT" | grep -q "purple"; then ok; else fail "TUI not visible"; fi
else
    fail "crashed on startup"; exit 1
fi

# 2. Navigate down
step "Navigate down (j j j)"
send "j"; send "j"; send "j"
if alive; then ok; else fail "crash"; exit 1; fi

# 3. Navigate up
step "Navigate up (k k)"
send "k"; send "k"
if alive; then ok; else fail "crash"; exit 1; fi

# 4. Search
step "Search (/ prod Esc)"
send "/"; sleep 0.2; send "prod"; sleep 0.4
if alive; then ok; else fail "crash"; exit 1; fi
send_key Escape; sleep 0.3

# 5. Connect attempt in demo mode (Enter triggers a "connection disabled"
#    toast, doesn't open a separate screen). The follow-up Esc that lived
#    here previously hit the bare host list and SET app.running = false,
#    silently killing the TUI — every later step then sent keys to the
#    shell prompt. The new alive() check would have caught that, but we
#    drop the Esc anyway so the toast auto-dismisses on its own and the
#    test stays on a known-good screen.
step "Connect attempt in demo mode (Enter)"
send_key Enter; sleep 0.5
expect_screen "Demo mode. Connection disabled."

# 6. Help screen
step "Help screen (?, Esc)"
send "?"; sleep 0.5
expect_screen " Help "
send_key Escape; sleep 0.3

# 7. Command palette
# Trigger key is `:` (the footer hint reads `:  cmds`). Ctrl-p clears
# ping results, not the palette — using it here used to silently leave
# the test on the host list and the Esc that followed killed the TUI.
step "Command palette (:, Esc)"
send ":"; sleep 0.5
expect_screen " Commands "
send_key Escape; sleep 0.3

# 8. Theme picker
# `t` opens the tag picker, not the theme picker. Theme is `m`. Easy
# regression to make when copying-and-renaming a step; the new
# expect_screen call catches it instead of letting the next Esc kill
# the TUI.
step "Theme picker (m, navigate, Esc)"
send "m"; sleep 0.4
send "j"; send "j"; send "j"; sleep 0.2
expect_screen " Theme "
send_key Escape; sleep 0.3

# 9. Provider list
step "Provider list (S, Esc)"
send "S"; sleep 0.4
expect_screen " Providers "
send_key Escape; sleep 0.3

# 10. Snippet picker
# `x` copies the selected host's config block. Snippet picker on the
# selected host is `r` (run snippet). Capital `R` runs across all
# displayed hosts; either opens the same picker.
step "Snippet picker (r, Esc)"
send "r"; sleep 0.4
expect_screen " Snippets "
send_key Escape; sleep 0.3

# 11. Tunnel list
step "Tunnel list (T, Esc)"
send "T"; sleep 0.4
expect_screen " Tunnels for "
send_key Escape; sleep 0.3

# 12. Add host form
step "Add host form (a, Esc)"
send "a"; sleep 0.4
expect_screen " Add New Host "
send_key Escape; sleep 0.3

# 13. Edit host form
step "Edit host form (e, Esc)"
send "e"; sleep 0.4
expect_screen " Edit: "
send_key Escape; sleep 0.3

# 14. Container screen
# Lowercase `c` clones the selected host. Containers overlay is `C`.
step "Container screen (C, Esc)"
send "C"; sleep 0.4
expect_screen " Containers for "
send_key Escape; sleep 0.3

# 15. File browser
# Lowercase `f` is unbound. File browser is `F`. In demo mode the
# overlay refuses to open and surfaces a "Demo mode. File browser
# disabled." toast instead — assert THAT, since asserting the title
# would require a non-demo binary with a real ssh target.
step "File browser disabled in demo (F)"
send "F"; sleep 0.4
expect_screen "Demo mode. File browser disabled."

# 16. Sort cycling
step "Sort modes (s s s)"
send "s"; sleep 0.2; send "s"; sleep 0.2; send "s"; sleep 0.2
if alive; then ok; else fail "crash"; fi

# 17. Group cycling
step "Group by (g g)"
send "g"; sleep 0.2; send "g"; sleep 0.2
if alive; then ok; else fail "crash"; fi

# 18. View mode
step "View mode toggle (v v)"
send "v"; sleep 0.2; send "v"; sleep 0.2
if alive; then ok; else fail "crash"; fi

# 19. Ping
step "Ping all (p)"
send "p"; sleep 1.5
if alive; then ok; else fail "crash"; fi

# 20. Filter down
step "Filter down hosts (! !)"
send "!"; sleep 0.3; send "!"; sleep 0.3
if alive; then ok; else fail "crash"; fi

# 21. Top/bottom navigation
step "Top/bottom (G, gg)"
send "G"; sleep 0.2; send "g"; send "g"; sleep 0.2
if alive; then ok; else fail "crash"; fi

# 22. What's new overlay
step "What's new overlay (n, j, Esc)"
send "n"; sleep 0.3
send "j"; sleep 0.2
expect_screen " What's new "
send_key Escape; sleep 0.3

# 23. Clean exit
step "Clean exit (q)"
send "q"; sleep 1
if alive; then
    # Check if purple exited and shell prompt returned
    OUTPUT=$(capture)
    if echo "$OUTPUT" | grep -q '\$\|%\|❯'; then
        ok
    else
        fail "did not exit cleanly"
    fi
else
    ok
fi

printf "\n=== Results: %d steps ===" "$STEP"
if [ "$FAIL" -eq 0 ]; then
    printf " ALL PASSED ✓\n"
else
    printf " FAILURES ✗\n"
fi

exit $FAIL
