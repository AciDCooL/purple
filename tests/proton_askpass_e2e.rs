//! End-to-end test for the askpass subprocess path with a Proton Pass source.
//!
//! Spawns the real purple binary in askpass mode (`PURPLE_ASKPASS_MODE=1`) with
//! a temp SSH config, a temp HOME, and a PATH that contains a shell-script
//! `pass-cli` shim. Asserts that the secret printed by the shim ends up on
//! purple's stdout, exactly as SSH would consume it.
//!
//! Complements the unit tests in `src/askpass_tests.rs` by exercising the full
//! `askpass::handle()` flow including SSH config parsing, alias resolution,
//! prompt parsing, marker file handling and the `proton:` dispatcher arm.

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

struct E2eFixture {
    home: tempfile::TempDir,
    shim_dir: tempfile::TempDir,
    config_path: std::path::PathBuf,
    _config_dir: tempfile::TempDir,
}

fn setup_fixture(askpass_value: &str, shim_body: &str) -> E2eFixture {
    let home = tempfile::Builder::new()
        .prefix("purple_e2e_home_")
        .tempdir()
        .unwrap();
    let shim_dir = tempfile::Builder::new()
        .prefix("purple_e2e_shim_")
        .tempdir()
        .unwrap();
    let config_dir = tempfile::Builder::new()
        .prefix("purple_e2e_cfg_")
        .tempdir()
        .unwrap();
    let config_path = config_dir.path().join("config");

    write_executable(&shim_dir.path().join("pass-cli"), shim_body);

    let config = format!(
        "Host test-host\n    HostName test.example.com\n    # purple:askpass {askpass_value}\n",
    );
    std::fs::write(&config_path, config).unwrap();

    E2eFixture {
        home,
        shim_dir,
        config_path,
        _config_dir: config_dir,
    }
}

fn run_askpass(fixture: &E2eFixture, prompt: &str) -> std::process::Output {
    let path = format!(
        "{}:{}",
        fixture.shim_dir.path().display(),
        std::env::var("PATH").unwrap_or_default(),
    );
    Command::new(purple_bin())
        .env_clear()
        .env("PURPLE_ASKPASS_MODE", "1")
        .env("PURPLE_HOST_ALIAS", "test-host")
        .env("PURPLE_CONFIG_PATH", &fixture.config_path)
        .env("HOME", fixture.home.path())
        .env("PATH", path)
        .arg(prompt)
        .output()
        .expect("failed to spawn purple binary")
}

#[test]
fn e2e_proton_askpass_returns_secret_on_stdout() {
    // The shim prints a deterministic secret on stdout and records its argv to
    // a file so we can also assert purple invoked `pass-cli item view` with
    // the expected name-based flags. Both assertions run in one test to keep
    // the spawn cost low.
    let argv_log_path = tempfile::Builder::new()
        .prefix("purple_e2e_argv_")
        .tempdir()
        .unwrap();
    let argv_log = argv_log_path.path().join("argv.log");
    let shim_body = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{argv}\"\nprintf 'super-secret-value'\nexit 0\n",
        argv = argv_log.display(),
    );

    let fixture = setup_fixture("proton:Personal/web-server-1/password", &shim_body);
    let output = run_askpass(&fixture, "test-host's password:");

    assert!(
        output.status.success(),
        "purple askpass exited non-zero. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "super-secret-value",
        "purple askpass stdout (full): {:?}",
        String::from_utf8_lossy(&output.stdout)
    );

    let argv = std::fs::read_to_string(&argv_log).expect("shim did not record argv");
    let argv_lines: Vec<&str> = argv
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        argv_lines,
        vec![
            "item",
            "view",
            "--vault-name",
            "Personal",
            "--item-title",
            "web-server-1",
            "--field",
            "password",
        ],
        "purple invoked pass-cli with wrong argv: {argv:?}"
    );
}

#[test]
fn e2e_proton_askpass_returns_failure_when_pass_cli_fails() {
    // pass-cli exits non-zero (e.g. expired session, missing item).
    // purple's askpass must exit non-zero so SSH falls back to interactive.
    let shim_body = "#!/bin/sh\nprintf 'no such item\\n' >&2\nexit 1\n";
    let fixture = setup_fixture("proton:Personal/missing/p", shim_body);
    let output = run_askpass(&fixture, "test-host's password:");
    assert!(
        !output.status.success(),
        "purple askpass should exit non-zero when pass-cli fails. stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn e2e_proton_askpass_refuses_empty_secret() {
    // pass-cli exits 0 but prints nothing. Invariant 8: we must NOT relay an
    // empty password to SSH (would attempt empty-password auth).
    let shim_body = "#!/bin/sh\nexit 0\n";
    let fixture = setup_fixture("proton:Empty/Item/p", shim_body);
    let output = run_askpass(&fixture, "test-host's password:");
    assert!(
        !output.status.success(),
        "purple askpass should exit non-zero on empty secret. stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).trim().is_empty(),
        "purple must not print anything on stdout when bailing on empty secret"
    );
}

#[test]
fn e2e_proton_askpass_skips_passphrase_prompt() {
    // Passphrase prompts (for SSH key decryption) must be skipped by purple so
    // SSH falls back to interactive input. The shim would fail loudly if
    // invoked; we assert purple never invokes it.
    let argv_log_path = tempfile::Builder::new()
        .prefix("purple_e2e_passphrase_")
        .tempdir()
        .unwrap();
    let invoked_marker = argv_log_path.path().join("invoked");
    let shim_body = format!(
        "#!/bin/sh\nprintf 'invoked' > \"{marker}\"\nprintf 'should-not-be-used'\nexit 0\n",
        marker = invoked_marker.display(),
    );

    let fixture = setup_fixture("proton:Personal/web/p", &shim_body);
    let output = run_askpass(
        &fixture,
        "Enter passphrase for key '/home/user/.ssh/id_ed25519': ",
    );

    assert!(
        !output.status.success(),
        "passphrase prompts must exit non-zero so SSH falls back to interactive"
    );
    assert!(
        !invoked_marker.exists(),
        "pass-cli must NOT be invoked for passphrase prompts"
    );
}
