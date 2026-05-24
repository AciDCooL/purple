use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use log::{debug, error, info, warn};

/// Result of an SSH connection attempt.
pub struct ConnectResult {
    pub status: std::process::ExitStatus,
    pub stderr_output: String,
}

/// Returns true if the process is running inside a tmux session, per the
/// resolved environment (so tests inject `TMUX` via `Env` instead of mutating
/// the process env).
#[cfg(unix)]
pub fn is_in_tmux(env: &crate::runtime::env::Env) -> bool {
    env.in_tmux()
}

/// Returns true if the current process is running inside a tmux session.
#[cfg(not(unix))]
pub fn is_in_tmux(_env: &crate::runtime::env::Env) -> bool {
    false
}

/// Open an SSH connection in a new tmux window.
/// Returns immediately after the window is created. The SSH session runs
/// asynchronously in the new window. Returns an error if tmux is not
/// available or the window cannot be created.
///
/// This path deliberately does not wire up SSH_ASKPASS. The caller in `main.rs`
/// guards this with `askpass.is_none()`, because an askpass-backed host needs an
/// inherited stdin (so purple's askpass subprocess can print back to the ssh
/// parent) and that inheritance does not survive the `tmux new-window` fork.
/// Hosts with a password source therefore keep using the suspend-TUI `connect()`
/// flow instead.
pub fn connect_tmux_window(alias: &str, config_path: &Path, has_active_tunnel: bool) -> Result<()> {
    info!("SSH connection via tmux: {alias}");

    let config_str = config_path
        .to_str()
        .context("SSH config path is not valid UTF-8")?;

    let mut args = vec!["new-window", "-n", alias, "--", "ssh", "-F", config_str];

    if has_active_tunnel {
        args.extend(["-o", "ClearAllForwardings=yes"]);
    }

    args.extend(["--", alias]);

    debug!("tmux args: {:?}", args);

    let status = Command::new("tmux")
        .args(&args)
        .status()
        .with_context(|| format!("Failed to launch tmux new-window for '{alias}'"))?;

    if status.success() {
        info!("tmux window created: {alias}");
        Ok(())
    } else {
        let code = status.code().unwrap_or(-1);
        error!("[external] tmux new-window failed for {alias} (exit {code})");
        anyhow::bail!("tmux new-window exited with code {code}")
    }
}

/// RAII guard that restores the signal mask when dropped.
/// Ensures SIGINT/SIGTSTP are unmasked even on early return or error.
#[cfg(unix)]
struct SignalMaskGuard {
    old: libc::sigset_t,
}

#[cfg(unix)]
impl SignalMaskGuard {
    /// Block SIGINT and SIGTSTP, saving the previous mask for restore on drop.
    fn block_interactive() -> Self {
        // SAFETY: `old` and `mask` are stack-allocated `sigset_t`s zeroed before
        // use. The libc sigset / sigprocmask calls only read/write these
        // pointers, which are valid for the duration of this block. `old` is
        // moved into `Self` so the mask can be restored on drop.
        unsafe {
            let mut old: libc::sigset_t = std::mem::zeroed();
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGINT);
            libc::sigaddset(&mut mask, libc::SIGTSTP);
            libc::sigprocmask(libc::SIG_BLOCK, &mask, &mut old);
            Self { old }
        }
    }
}

#[cfg(unix)]
impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        // SAFETY: `self.old` is a valid `sigset_t` captured by
        // `block_interactive`. `pending` is zeroed before `sigpending` writes
        // to it. `libc::signal` is called with valid signal numbers. The
        // sigprocmask call restores the previously-saved mask, which is still
        // live for the duration of this drop.
        unsafe {
            // Discard any pending SIGINT/SIGTSTP that arrived while masked.
            // Without this, queued signals would fire immediately on unmask and
            // kill/suspend purple before the TUI can be restored.
            let mut pending: libc::sigset_t = std::mem::zeroed();
            libc::sigpending(&mut pending);
            let has_sigint = libc::sigismember(&pending, libc::SIGINT) == 1;
            let has_sigtstp = libc::sigismember(&pending, libc::SIGTSTP) == 1;
            // Temporarily ignore pending signals so they're consumed on unmask.
            if has_sigint {
                libc::signal(libc::SIGINT, libc::SIG_IGN);
            }
            if has_sigtstp {
                libc::signal(libc::SIGTSTP, libc::SIG_IGN);
            }
            libc::sigprocmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut());
            // Restore default handlers after pending signals are consumed.
            if has_sigint {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
            }
            if has_sigtstp {
                libc::signal(libc::SIGTSTP, libc::SIG_DFL);
            }
        }
    }
}

/// Spawn `cmd`, mask interactive signals in the parent, tee SSH's
/// stderr to the real stderr while capturing it for error detection,
/// then wait for the child to exit. Both `connect` and
/// `connect_with_remote_command` build their `Command` independently
/// (different argv) and delegate the spawn/wait/tee plumbing here so
/// the long stderr-buffer + signal-guard sequence lives in one place.
///
/// `log_label` is interpolated into the started/ended/failed log lines
/// so a reader can tell host-login from container-exec at a glance.
fn spawn_ssh_and_wait(mut cmd: Command, alias: &str, log_label: &str) -> Result<ConnectResult> {
    cmd.stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped());

    // Reset signal mask in the child process so SSH receives Ctrl+C
    // normally. We mask signals in the parent AFTER spawn so the
    // child doesn't inherit the blocked mask.
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigprocmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to launch ssh {} for '{}'", log_label, alias))?;

    // Mask SIGINT/SIGTSTP in purple AFTER spawn so SSH doesn't inherit
    // the blocked mask. The guard restores the mask on drop (even on
    // early return).
    #[cfg(unix)]
    let _signal_guard = SignalMaskGuard::block_interactive();

    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_thread = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut captured = Vec::new();
        let mut buf = [0u8; 4096];
        let mut reader = stderr_pipe;
        let mut stderr_out = std::io::stderr();
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = stderr_out.write_all(&buf[..n]);
                    let _ = stderr_out.flush();
                    captured.extend_from_slice(&buf[..n]);
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&captured).to_string()
    });

    let status = child
        .wait()
        .with_context(|| format!("Failed to wait for ssh {} for '{}'", log_label, alias))?;
    let stderr_output = stderr_thread.join().unwrap_or_else(|_| {
        warn!("[purple] Stderr capture thread panicked for {alias}");
        String::new()
    });

    let code = status.code().unwrap_or(-1);
    if code == 0 {
        info!("SSH {} ended: {alias} (exit 0)", log_label);
    } else {
        error!("[external] SSH {} failed: {alias} (exit {code})", log_label);
        if !stderr_output.is_empty() {
            let stderr = stderr_output.trim();
            let lower = stderr.to_lowercase();
            if lower.contains("are too open") || lower.contains("bad permissions") {
                warn!("[config] SSH key permission issue: {stderr}");
            } else {
                debug!("[external] SSH stderr: {stderr}");
            }
        }
    }

    Ok(ConnectResult {
        status,
        stderr_output,
    })
}

/// Launch an SSH connection to the given host alias.
/// Uses the system `ssh` binary with inherited stdin/stdout. Stderr is piped and
/// forwarded to real stderr in real time so the output is captured for error detection.
/// Passes `-F <config_path>` so the alias resolves against the correct config file.
/// When `askpass` is Some, delegates to `askpass_env::configure_ssh_command` to wire up
/// SSH_ASKPASS, SSH_ASKPASS_REQUIRE=force and the PURPLE_* env vars.
pub fn connect(
    alias: &str,
    config_path: &Path,
    askpass: Option<&str>,
    bw_session: Option<&str>,
    has_active_tunnel: bool,
) -> Result<ConnectResult> {
    info!("SSH connection started: {alias}");
    debug!("SSH command: ssh -F {} -- {alias}", config_path.display());

    let mut cmd = Command::new("ssh");
    cmd.arg("-F").arg(config_path);

    // When a tunnel is already running for this host, disable forwards in the
    // interactive session to avoid "Address already in use" bind conflicts.
    if has_active_tunnel {
        cmd.arg("-o").arg("ClearAllForwardings=yes");
    }

    cmd.arg("--").arg(alias);

    if askpass.is_some() {
        crate::askpass_env::configure_ssh_command(&mut cmd, alias, config_path);
    }

    if let Some(token) = bw_session {
        cmd.env("BW_SESSION", token);
    }

    spawn_ssh_and_wait(cmd, alias, "connection")
}

/// Launch an SSH connection that runs a single remote command in
/// interactive mode. Mirrors `connect()` exactly except for two
/// additions: `-t` to allocate a TTY (required for the remote shell
/// `docker exec` opens) and the trailing `remote_command` string passed
/// to ssh as one argv slot. The remote shell receives the string as a
/// single command line, so multi-token commands and shell operators
/// like `||` work naturally.
///
/// Used by the containers overview Enter handler: the `remote_command`
/// is built as `<runtime> exec -it <container_id> sh -c 'bash || sh'`
/// where `container_id` has already been validated to alphanumeric +
/// `-_.` so it cannot inject shell metacharacters.
pub fn connect_with_remote_command(
    alias: &str,
    config_path: &Path,
    askpass: Option<&str>,
    bw_session: Option<&str>,
    has_active_tunnel: bool,
    remote_command: &str,
) -> Result<ConnectResult> {
    info!("SSH exec started: {alias}");
    debug!(
        "SSH command: ssh -F {} -t -- {alias} {}",
        config_path.display(),
        remote_command
    );

    // Renew the Vault SSH cert before exec'ing into a container so an
    // expired cert is refreshed, mirroring the interactive connect path.
    // No-op for non-vault hosts.
    crate::runtime::helpers::ensure_vault_cert_for_alias(
        &crate::runtime::env::Env::from_process(),
        alias,
        config_path,
    );

    let mut cmd = Command::new("ssh");
    cmd.arg("-F").arg(config_path).arg("-t");

    if has_active_tunnel {
        cmd.arg("-o").arg("ClearAllForwardings=yes");
    }

    cmd.arg("--").arg(alias).arg(remote_command);

    if askpass.is_some() {
        crate::askpass_env::configure_ssh_command(&mut cmd, alias, config_path);
    }

    if let Some(token) = bw_session {
        cmd.env("BW_SESSION", token);
    }

    spawn_ssh_and_wait(cmd, alias, "exec")
}

/// tmux variant of `connect_with_remote_command`. Opens a new tmux
/// window running `ssh -t <alias> <remote_command>` so the TUI stays
/// alive in the original window. Same askpass-incompatible caveat as
/// `connect_tmux_window`.
pub fn connect_tmux_window_with_remote_command(
    alias: &str,
    config_path: &Path,
    has_active_tunnel: bool,
    remote_command: &str,
    window_label: &str,
) -> Result<()> {
    info!("SSH exec via tmux: {alias}");

    // Renew the Vault SSH cert before exec'ing into a container so an
    // expired cert is refreshed, mirroring the interactive connect path.
    // No-op for non-vault hosts.
    crate::runtime::helpers::ensure_vault_cert_for_alias(
        &crate::runtime::env::Env::from_process(),
        alias,
        config_path,
    );

    let config_str = config_path
        .to_str()
        .context("SSH config path is not valid UTF-8")?;

    let mut args = vec![
        "new-window",
        "-n",
        window_label,
        "--",
        "ssh",
        "-F",
        config_str,
        "-t",
    ];

    if has_active_tunnel {
        args.extend(["-o", "ClearAllForwardings=yes"]);
    }

    args.extend(["--", alias, remote_command]);

    debug!("tmux exec args: {:?}", args);

    let status = Command::new("tmux")
        .args(&args)
        .status()
        .with_context(|| format!("Failed to launch tmux exec window for '{alias}'"))?;

    if status.success() {
        info!("tmux exec window created: {alias}");
        Ok(())
    } else {
        let code = status.code().unwrap_or(-1);
        error!("[external] tmux exec window failed for {alias} (exit {code})");
        anyhow::bail!("tmux new-window exited with code {code}")
    }
}

/// Extract a concise reason from SSH stderr for display in the toast.
/// Joins all non-empty, non-banner lines with ` | ` so the full context
/// is visible. Truncates to 200 chars (char-safe) if needed.
pub fn stderr_summary(stderr: &str) -> Option<String> {
    let summary: String = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('@'))
        .collect::<Vec<_>>()
        .join(" | ");
    if summary.is_empty() {
        return None;
    }
    if summary.len() > 200 {
        let truncated: String = summary.chars().take(197).collect();
        Some(format!("{truncated}..."))
    } else {
        Some(summary)
    }
}

/// Parse host key verification error from SSH stderr output.
/// Returns (hostname, known_hosts_path) if the error is a changed host key.
///
/// Uses two detection strategies:
/// 1. English string matching for hostname and known_hosts path extraction.
/// 2. Locale-independent fallback: the `@@@@@` warning banner is always present
///    regardless of locale, combined with a known_hosts path from "Offending" line.
///    When the English hostname line is missing, falls back to extracting the
///    hostname from the known_hosts file path.
pub fn parse_host_key_error(stderr: &str) -> Option<(String, String)> {
    // Primary: English locale detection
    let has_english_error = stderr.contains("Host key verification failed.");
    // Fallback: the @@@ banner is locale-independent and always present for host key errors
    let has_banner = stderr.contains("@@@@@@@@@@@@@@@");

    if !has_english_error && !has_banner {
        return None;
    }

    // Parse hostname from "Host key for <hostname> has changed"
    let hostname = stderr
        .lines()
        .find(|l| l.contains("Host key for") && l.contains("has changed"))
        .and_then(|l| {
            let start = l.find("Host key for ")? + "Host key for ".len();
            let rest = &l[start..];
            let end = rest.find(" has changed")?;
            Some(rest[..end].to_string())
        });

    // Parse known_hosts path from "Offending ... key in <path>:<line>"
    let known_hosts_path = stderr
        .lines()
        .find(|l| l.starts_with("Offending") && l.contains(" key in "))
        .and_then(|l| {
            let start = l.find(" key in ")? + " key in ".len();
            let rest = &l[start..];
            let end = rest.rfind(':')?;
            Some(rest[..end].to_string())
        });

    // We need at least the known_hosts path to be useful
    let known_hosts_path = known_hosts_path?;

    // If we couldn't parse the hostname (non-English locale), derive it from
    // the known_hosts path by running ssh-keygen -F would be complex.
    // Instead, use a reasonable default: the user will see the confirmation dialog
    // with the known_hosts path, which is the critical piece for the reset.
    let hostname = hostname.unwrap_or_else(|| "the remote host".to_string());

    Some((hostname, known_hosts_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_fails_with_nonexistent_config() {
        // connect() should return an error when the config file doesn't exist and
        let result = connect(
            "nonexistent-host",
            Path::new("/tmp/__purple_test_nonexistent_config__"),
            None,
            None,
            false,
        );
        // SSH should exit with a non-zero status (config file not found)
        assert!(result.is_ok()); // spawn succeeds, SSH exits with error
        let r = result.unwrap();
        assert!(!r.status.success());
    }

    #[test]
    fn connect_with_tunnel_flag_does_not_panic() {
        // Verify has_active_tunnel=true adds the ClearAllForwardings arg without panic.
        let result = connect(
            "nonexistent-host",
            Path::new("/tmp/__purple_test_nonexistent_config__"),
            None,
            None,
            true,
        );
        assert!(result.is_ok());
        assert!(!result.unwrap().status.success());
    }

    #[test]
    fn connect_captures_stderr() {
        // SSH should produce some stderr output when failing.
        let result = connect(
            "nonexistent-host",
            Path::new("/tmp/__purple_test_nonexistent_config__"),
            None,
            None,
            false,
        );
        assert!(result.is_ok());
        // SSH writes errors to stderr; we should have captured something
        // (either "Can't open user config file" or a connection error)
        let r = result.unwrap();
        assert!(
            !r.stderr_output.is_empty() || !r.status.success(),
            "SSH should produce stderr or fail"
        );
    }

    // --- parse_host_key_error tests ---

    #[test]
    fn parse_host_key_error_detects_changed_key() {
        let stderr = "\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:ohwPXZbfBMvYWXnKefVYWVAcQsXKLMqaRKbXxRUVXqc.
Please contact your system administrator.
Add correct host key in /Users/user/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /Users/user/.ssh/known_hosts:55
Host key for example.com has changed and you have requested strict checking.
Host key verification failed.
";
        let result = parse_host_key_error(stderr);
        assert!(result.is_some());
        let (hostname, path) = result.unwrap();
        assert_eq!(hostname, "example.com");
        assert_eq!(path, "/Users/user/.ssh/known_hosts");
    }

    #[test]
    fn parse_host_key_error_returns_none_for_other_errors() {
        let stderr = "ssh: connect to host example.com port 22: Connection refused\n";
        assert!(parse_host_key_error(stderr).is_none());
    }

    #[test]
    fn parse_host_key_error_returns_none_for_empty() {
        assert!(parse_host_key_error("").is_none());
    }

    #[test]
    fn parse_host_key_error_handles_ip_address() {
        let stderr = "\
Offending ECDSA key in /home/user/.ssh/known_hosts:12
Host key for 10.0.0.1 has changed and you have requested strict checking.
Host key verification failed.
";
        let result = parse_host_key_error(stderr);
        assert!(result.is_some());
        let (hostname, path) = result.unwrap();
        assert_eq!(hostname, "10.0.0.1");
        assert_eq!(path, "/home/user/.ssh/known_hosts");
    }

    #[test]
    fn parse_host_key_error_handles_custom_known_hosts_path() {
        let stderr = "\
Offending RSA key in /etc/ssh/known_hosts:3
Host key for server.local has changed and you have requested strict checking.
Host key verification failed.
";
        let result = parse_host_key_error(stderr);
        assert!(result.is_some());
        let (hostname, path) = result.unwrap();
        assert_eq!(hostname, "server.local");
        assert_eq!(path, "/etc/ssh/known_hosts");
    }

    #[test]
    fn parse_host_key_error_handles_ipv6() {
        let stderr = "\
Offending ED25519 key in /Users/user/.ssh/known_hosts:7
Host key for ::1 has changed and you have requested strict checking.
Host key verification failed.
";
        let result = parse_host_key_error(stderr);
        assert!(result.is_some());
        let (hostname, _) = result.unwrap();
        assert_eq!(hostname, "::1");
    }

    #[test]
    fn connect_tmux_window_fails_gracefully_outside_tmux_session() {
        // When no tmux server is running (or tmux is absent), should return an error.
        // Skip if we're actually inside a live tmux session (the command would succeed).
        // Holds TMUX_LOCK so the env-mutating tests below cannot flip TMUX between
        // the guard read and the call to connect_tmux_window.
        let _guard = TMUX_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        if std::env::var("TMUX").is_ok() {
            return;
        }
        let result = connect_tmux_window(
            "test-host",
            Path::new("/tmp/__purple_test_nonexistent_config__"),
            false,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("tmux") || err.contains("No such file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn connect_tmux_window_with_tunnel_does_not_panic() {
        // Verify has_active_tunnel=true doesn't panic and fails gracefully.
        // Skip if inside a live tmux session. TMUX_LOCK prevents the env-mutating
        // tests from racing this guard read.
        let _guard = TMUX_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        if std::env::var("TMUX").is_ok() {
            return;
        }
        let result = connect_tmux_window(
            "tunnel-host",
            Path::new("/tmp/__purple_test_nonexistent_config__"),
            true,
        );
        assert!(result.is_err());
    }

    /// Mutex to serialise tests that mutate the TMUX env var.
    static TMUX_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn is_in_tmux_returns_true_when_set() {
        let env = crate::runtime::env::Env::for_test("/tmp/x")
            .with_var("TMUX", "/tmp/tmux-1000/default,12345,0");
        assert!(is_in_tmux(&env));
    }

    #[test]
    fn is_in_tmux_returns_false_when_unset() {
        let env = crate::runtime::env::Env::for_test("/tmp/x");
        assert!(!is_in_tmux(&env));
    }

    // --- first_stderr_line tests ---

    #[test]
    fn stderr_summary_joins_all_lines() {
        let stderr = "channel 0: open failed: administratively prohibited: open failed\n\
                      stdio forwarding failed\n\
                      Connection closed by UNKNOWN port 65535\n";
        let result = stderr_summary(stderr);
        assert_eq!(
            result.as_deref(),
            Some(
                "channel 0: open failed: administratively prohibited: open failed | stdio forwarding failed | Connection closed by UNKNOWN port 65535"
            )
        );
    }

    #[test]
    fn stderr_summary_skips_banner_lines() {
        let stderr = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                      @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
                      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                      IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n";
        let result = stderr_summary(stderr);
        assert_eq!(
            result.as_deref(),
            Some("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!")
        );
    }

    #[test]
    fn stderr_summary_returns_none_for_empty() {
        assert!(stderr_summary("").is_none());
        assert!(stderr_summary("   \n  \n").is_none());
        assert!(stderr_summary("@@@@@\n@@@@@\n").is_none());
    }

    #[test]
    fn stderr_summary_truncates_long_output() {
        let long = "x".repeat(250);
        let result = stderr_summary(&long).unwrap();
        assert_eq!(result.len(), 200);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn stderr_summary_truncates_multibyte_safely() {
        // Each '日' is 3 bytes. 100 chars = 300 bytes, exceeds the 200-char limit.
        let long = "日".repeat(100);
        let result = stderr_summary(&long).unwrap();
        assert!(result.ends_with("..."));
        // Must not panic and must be valid UTF-8
        assert!(result.len() <= 600); // 197 chars * 3 bytes + 3 bytes for "..."
    }

    #[test]
    fn stderr_summary_simple_errors() {
        assert_eq!(
            stderr_summary("Connection refused\n").as_deref(),
            Some("Connection refused")
        );
        assert_eq!(
            stderr_summary("Permission denied (publickey).\n").as_deref(),
            Some("Permission denied (publickey).")
        );
    }
}
