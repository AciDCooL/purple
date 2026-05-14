//! Opt-in smoke test against a real `pass-cli` binary on PATH.
//!
//! These tests are `#[ignore]` by default because they require `pass-cli` to
//! be installed on the test machine. Run manually with:
//!
//! ```sh
//! cargo test --test proton_live_smoke -- --ignored
//! ```
//!
//! Purpose: catch the day Proton ships a `pass-cli` update that breaks the
//! command shape purple depends on. No Proton account is required because
//! every assertion stays before the login boundary (`--version`, `--help`,
//! `info` without a session, `view` against a fake URI).
//!
//! Custom binary path: set `PASSCLI_BIN=/path/to/pass-cli` to point at a
//! specific binary instead of relying on `which pass-cli`.

#![cfg(unix)]

use std::process::Command;

fn passcli_path() -> Option<String> {
    if let Ok(p) = std::env::var("PASSCLI_BIN") {
        return Some(p);
    }
    let which = Command::new("which").arg("pass-cli").output().ok()?;
    if !which.status.success() {
        return None;
    }
    let path = String::from_utf8(which.stdout).ok()?.trim().to_string();
    if path.is_empty() { None } else { Some(path) }
}

fn require_passcli() -> String {
    passcli_path().unwrap_or_else(|| {
        panic!(
            "pass-cli not found on PATH and PASSCLI_BIN not set. \
             Install pass-cli (https://protonpass.github.io/pass-cli/get-started/installation/) \
             or set PASSCLI_BIN to a binary path."
        )
    })
}

#[test]
#[ignore = "requires pass-cli on PATH or PASSCLI_BIN"]
fn live_pass_cli_responds_to_version() {
    // The mere existence of `--version` output proves the binary is the
    // Proton Pass CLI we think it is. A renamed binary or unrelated `pass-cli`
    // npm package would not match this pattern.
    let bin = require_passcli();
    let output = Command::new(&bin)
        .arg("--version")
        .output()
        .expect("pass-cli --version invocation failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}").to_lowercase();
    assert!(
        combined.contains("pass-cli") || combined.contains("proton"),
        "pass-cli --version output does not mention pass-cli or Proton. \
         Got: stdout={stdout:?} stderr={stderr:?}"
    );
}

#[test]
#[ignore = "requires pass-cli on PATH or PASSCLI_BIN"]
fn live_pass_cli_documents_item_view_and_login_and_test_subcommands() {
    // purple depends on three subcommands. A future breaking rename of any of
    // them would surface here. `--help` is paginated by clap in pass-cli 2.x,
    // so we ask each subcommand individually with `--help` to avoid relying
    // on the truncated top-level listing.
    let bin = require_passcli();
    for subcmd in &[&["item", "view"][..], &["login"][..], &["test"][..]] {
        let mut args: Vec<&str> = subcmd.to_vec();
        args.push("--help");
        let output = Command::new(&bin)
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("pass-cli {subcmd:?} --help failed: {e}"));
        assert!(
            output.status.success(),
            "pass-cli {subcmd:?} --help exited non-zero. stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "requires pass-cli on PATH or PASSCLI_BIN"]
fn live_pass_cli_test_without_login_exits_nonzero() {
    // purple's `proton_status` calls `pass-cli test` and treats any non-zero
    // exit as `NotAuthenticated`. Confirms the contract against the real
    // binary: with no login session, `test` exits non-zero. (Unlike `info`,
    // which in pass-cli 2.x exits zero even without a session and only logs
    // the error to stderr.)
    let bin = require_passcli();
    let home = tempfile::Builder::new()
        .prefix("purple_live_smoke_home_")
        .tempdir()
        .unwrap();
    // env_clear() so an active D-Bus session, keyring agent or stray Proton
    // env var on the developer's machine cannot leak a real session into the
    // sandboxed run. Re-add only the bits pass-cli needs to find its sandbox.
    let output = Command::new(&bin)
        .arg("test")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .output()
        .expect("pass-cli test invocation failed");
    assert!(
        !output.status.success(),
        "pass-cli test without a login session must exit non-zero. \
         Got status={:?} stdout={:?} stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[ignore = "requires pass-cli on PATH or PASSCLI_BIN"]
fn live_pass_cli_login_help_documents_pat_flag() {
    // purple supplies the PAT via the `PROTON_PASS_PERSONAL_ACCESS_TOKEN` env
    // var so the secret never appears in argv. The same env var is read by
    // `pass-cli login` when `--pat` is not supplied. Verify the flag is still
    // documented; the env var is also implicitly verified (you cannot login
    // without one of these two routes).
    let bin = require_passcli();
    let output = Command::new(&bin)
        .args(["login", "--help"])
        .output()
        .expect("pass-cli login --help invocation failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("--pat") || combined.contains("personal access token"),
        "pass-cli login --help no longer documents a Personal Access Token flow. \
         purple's headless login depends on this. Full output:\n{combined}"
    );
}

#[test]
#[ignore = "requires pass-cli on PATH or PASSCLI_BIN"]
fn live_pass_cli_item_view_help_documents_name_based_flags() {
    // purple maps `proton:Vault/Item/field` to `pass-cli item view
    // --vault-name V --item-title I --field F`. The three name-based flags
    // are the contract; if any is renamed (e.g. `--vault` -> `--vault-id`)
    // we want to catch it here, not at user-connect time.
    let bin = require_passcli();
    let output = Command::new(&bin)
        .args(["item", "view", "--help"])
        .output()
        .expect("pass-cli item view --help invocation failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    for flag in &["--vault-name", "--item-title", "--field"] {
        assert!(
            combined.contains(flag),
            "pass-cli item view --help is missing required flag `{flag}`. \
             Full output:\n{combined}"
        );
    }
}
