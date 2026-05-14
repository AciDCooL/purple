//! Log-output assertions for the Proton Pass askpass flow.
//!
//! Spawns purple in askpass mode with `PURPLE_LOG=debug` and a sandboxed HOME,
//! then inspects `~/.purple/purple.log` for the expected log statements. This
//! is the troubleshooting safety net: a future regression that deletes a
//! `debug!`/`warn!` call (or renames the message) will be caught here.
//!
//! Complements the snapshot intent of test review item 6: instead of a full
//! file snapshot (fragile across timestamps and platform paths), this asserts
//! the presence and relative ordering of the specific log lines that the spec
//! requires.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn purple_bin() -> &'static str {
    env!("CARGO_BIN_EXE_purple")
}

fn write_executable(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

struct Fixture {
    home: tempfile::TempDir,
    shim_dir: tempfile::TempDir,
    config_path: std::path::PathBuf,
    _config_dir: tempfile::TempDir,
}

fn setup(askpass_value: &str, shim_body: &str) -> Fixture {
    let home = tempfile::Builder::new()
        .prefix("purple_log_e2e_home_")
        .tempdir()
        .unwrap();
    let shim_dir = tempfile::Builder::new()
        .prefix("purple_log_e2e_shim_")
        .tempdir()
        .unwrap();
    let config_dir = tempfile::Builder::new()
        .prefix("purple_log_e2e_cfg_")
        .tempdir()
        .unwrap();
    write_executable(&shim_dir.path().join("pass-cli"), shim_body);
    let config_path = config_dir.path().join("config");
    std::fs::write(
        &config_path,
        format!(
            "Host test-host\n    HostName test.example.com\n    # purple:askpass {askpass_value}\n",
        ),
    )
    .unwrap();
    Fixture {
        home,
        shim_dir,
        config_path,
        _config_dir: config_dir,
    }
}

fn run(fixture: &Fixture, prompt: &str) -> std::process::Output {
    let path = format!(
        "{}:{}",
        fixture.shim_dir.path().display(),
        std::env::var("PATH").unwrap_or_default(),
    );
    Command::new(purple_bin())
        .env_clear()
        .env("PURPLE_ASKPASS_MODE", "1")
        .env("PURPLE_LOG", "debug")
        .env("PURPLE_HOST_ALIAS", "test-host")
        .env("PURPLE_CONFIG_PATH", &fixture.config_path)
        .env("HOME", fixture.home.path())
        .env("PATH", path)
        .arg(prompt)
        .output()
        .expect("failed to spawn purple binary")
}

fn read_log(fixture: &Fixture) -> String {
    let path = fixture.home.path().join(".purple").join("purple.log");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read purple.log at {}: {e}", path.display()))
}

/// Verify the log contains the given substrings in order (not necessarily
/// adjacent). Panics with a helpful diff on failure.
fn assert_log_order(log: &str, expected: &[&str]) {
    let mut cursor = 0usize;
    for needle in expected {
        match log[cursor..].find(needle) {
            Some(idx) => cursor += idx + needle.len(),
            None => panic!(
                "log missing expected line (or out of order): {needle:?}\n--- log contents ---\n{log}\n---"
            ),
        }
    }
}

#[test]
fn log_success_path_emits_all_expected_statements() {
    let shim_body = "#!/bin/sh\nprintf 'super-secret-value'\nexit 0\n";
    let fixture = setup("proton:Personal/web-server-1/password", shim_body);
    let output = run(&fixture, "test-host's password:");
    assert!(
        output.status.success(),
        "askpass should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let log = read_log(&fixture);
    assert_log_order(
        &log,
        &[
            "Askpass invoked for alias=test-host source=proton:Personal/web-server-1/password",
            "Proton Pass lookup succeeded",
            "Askpass retrieved password for test-host via proton:Personal/web-server-1/password",
        ],
    );
}

#[test]
fn log_failure_path_emits_warn_with_external_prefix() {
    // pass-cli exits non-zero. The spec mandates a `warn!` with the
    // `[external]` fault-domain prefix so support tickets can grep for the
    // failure quickly. Fault domains: `[external]` for remote/tool errors,
    // `[config]` for local config issues, `[purple]` for internal errors.
    let shim_body = "#!/bin/sh\nprintf 'no such item\\n' >&2\nexit 1\n";
    let fixture = setup("proton:Missing/Item/p", shim_body);
    let output = run(&fixture, "test-host's password:");
    assert!(!output.status.success(), "askpass should bail");
    let log = read_log(&fixture);
    // Assert on the stable prefix only. The trailing stderr text comes from
    // pass-cli itself and could change with any upstream release; only the
    // fault-domain prefix is purple's own contract.
    assert_log_order(
        &log,
        &[
            "Askpass invoked for alias=test-host source=proton:Missing/Item/p",
            "[external] Proton Pass lookup failed:",
            "[external] Password retrieval failed via proton:Missing/Item/p",
        ],
    );
}

#[test]
fn log_empty_secret_path_warns_external_before_bail() {
    // Invariant 8 path: empty stdout from pass-cli must produce a warn with
    // `[external]` prefix and refuse to emit an empty password.
    let shim_body = "#!/bin/sh\nexit 0\n";
    let fixture = setup("proton:Empty/Item/p", shim_body);
    let output = run(&fixture, "test-host's password:");
    assert!(!output.status.success());
    let log = read_log(&fixture);
    assert_log_order(
        &log,
        &[
            "Askpass invoked for alias=test-host source=proton:Empty/Item/p",
            "[external] Proton Pass returned empty secret",
        ],
    );
}

#[test]
fn log_not_installed_path_uses_config_fault_domain() {
    // pass-cli not on PATH. The askpass subprocess must emit an `error!` with
    // the `[config]` prefix because a missing binary is a local configuration
    // issue, not an external service problem.
    let home = tempfile::Builder::new()
        .prefix("purple_log_e2e_nopath_")
        .tempdir()
        .unwrap();
    let shim_dir = tempfile::Builder::new()
        .prefix("purple_log_e2e_nopath_shim_")
        .tempdir()
        .unwrap();
    // Do NOT write any pass-cli into shim_dir. PATH points there only so the
    // shim_dir tempdir survives the call.
    let config_dir = tempfile::Builder::new()
        .prefix("purple_log_e2e_nopath_cfg_")
        .tempdir()
        .unwrap();
    let config_path = config_dir.path().join("config");
    std::fs::write(
        &config_path,
        "Host test-host\n    HostName test.example.com\n    # purple:askpass proton:X/Y/p\n",
    )
    .unwrap();
    let output = Command::new(purple_bin())
        .env_clear()
        .env("PURPLE_ASKPASS_MODE", "1")
        .env("PURPLE_LOG", "debug")
        .env("PURPLE_HOST_ALIAS", "test-host")
        .env("PURPLE_CONFIG_PATH", &config_path)
        .env("HOME", home.path())
        .env("PATH", shim_dir.path())
        .arg("test-host's password:")
        .output()
        .expect("failed to spawn purple");
    assert!(!output.status.success(), "askpass must exit non-zero");

    let log_path = home.path().join(".purple").join("purple.log");
    let log = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|e| panic!("missing purple.log at {}: {e}", log_path.display()));
    assert!(
        log.contains("[config] Password manager binary not found: pass-cli"),
        "missing [config] error for missing pass-cli; log:\n{log}"
    );
}
