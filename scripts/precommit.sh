#!/usr/bin/env bash
# Single source of truth for the pre-commit gates. Run before every
# commit. Strict mode so the first non-zero exit aborts the run.
#
# Use `cargo +stable` everywhere so rustfmt and clippy versions match
# what CI runs (`dtolnay/rust-toolchain@master` resolves to latest
# stable). Whatever the local default toolchain happens to be drifts
# from CI silently.
#
# Pass `--with-docker` to add a Linux validation gate that runs the
# same toolchain CI uses inside `rust:latest`. Catches regressions in
# `#[cfg(target_os = "linux")]` paths invisible on macOS.
#
# Pass `--with-nix` to add a `nix flake check` gate that validates the
# flake builds the package and `cargo fmt` passes inside the Nix
# sandbox. Requires `nix` on PATH with flakes enabled.

set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; RESET='\033[0m'
gate_num=0
WITH_DOCKER=false
WITH_NIX=false
for arg in "$@"; do
    case "$arg" in
        --with-docker) WITH_DOCKER=true ;;
        --with-nix)    WITH_NIX=true ;;
    esac
done

step() {
    gate_num=$((gate_num + 1))
    echo -e "${CYAN}[$gate_num] $*${RESET}"
}

pass() {
    echo -e "${GREEN}    ✓ pass${RESET}"
}

# Verify cargo +stable is available; otherwise we are running against
# a non-stable default which will drift from CI.
if ! cargo +stable --version >/dev/null 2>&1; then
    echo -e "${RED}cargo +stable is not installed. Install with: rustup install stable${RESET}"
    exit 1
fi

step "cargo +stable fmt --check"
cargo +stable fmt --check
pass

step "cargo +stable clippy --all-targets -- -D warnings"
cargo +stable clippy --all-targets -- -D warnings
pass

step "cargo build"
cargo build
pass

step "cargo test (release-grade race flush: 3 runs)"
for i in 1 2 3; do
    echo "    run $i ..."
    cargo test --quiet
done
pass

step "cargo deny check"
cargo deny check
pass

step "rustup run 1.86 cargo check --locked (MSRV)"
rustup run 1.86 cargo check --locked
pass

step 'RUSTDOCFLAGS="-D warnings" cargo doc --no-deps'
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
pass

step "sh scripts/site/check-sync.sh"
sh scripts/site/check-sync.sh
pass

step "./tests/smoke_tui.sh"
./tests/smoke_tui.sh
pass

step "./scripts/check-design-system.sh"
./scripts/check-design-system.sh
pass

step "./scripts/check-messages.sh"
./scripts/check-messages.sh
pass

step "./scripts/check-keybindings.sh"
./scripts/check-keybindings.sh
pass

step "./scripts/check-conventions.sh"
./scripts/check-conventions.sh
pass

step "./scripts/check-aur-pkgbuild-drift.sh"
./scripts/check-aur-pkgbuild-drift.sh
pass

step "./scripts/check-alias-caches.sh"
./scripts/check-alias-caches.sh
pass

step "cargo test --lib visual_regression"
cargo test --lib visual_regression
pass

if [[ "$WITH_DOCKER" == "true" ]]; then
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}Docker daemon not running. Skip --with-docker or start Docker.${RESET}"
        exit 1
    fi
    step "docker rust:latest cargo clippy --locked --all-targets -- -D warnings (Linux, CI-matching toolchain)"
    docker run --rm -v "$(pwd)":/work -w /work rust:latest \
        bash -c "cargo clippy --locked --all-targets -- -D warnings"
    pass

    step "docker rust:latest cargo test (Linux, CI-matching toolchain)"
    docker run --rm -v "$(pwd)":/work -w /work rust:latest \
        bash -c "cargo test --quiet"
    pass
fi

if [[ "$WITH_NIX" == "true" ]]; then
    if ! command -v nix >/dev/null 2>&1; then
        echo -e "${RED}nix is not installed. Install via https://nixos.org/download or skip --with-nix.${RESET}"
        exit 1
    fi
    step "nix flake check (validates flake builds purple-ssh and cargo fmt passes)"
    nix flake check
    pass
fi

echo ""
echo -e "${GREEN}All $gate_num pre-commit gates passed.${RESET}"
