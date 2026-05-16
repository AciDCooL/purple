use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global flag checked by all disk-write functions.
static DEMO_MODE: AtomicBool = AtomicBool::new(false);

/// Frozen "now" timestamp in seconds since the Unix epoch. Demo data and
/// `history::ConnectionHistory::format_time_ago` both read this when demo
/// mode is active so relative time strings ("<1m", "1h") stay stable across
/// long-running renders. Without freezing, a render that crosses a minute
/// boundary after build time would flip a host's last-connected from "<1m"
/// to "1m", flaking the visual regression tests.
///
/// `dead_code` allow: this module is compiled into both the binary crate
/// (where it is consumed by `demo` and `history`) and the library crate
/// (where there are no consumers).
#[allow(dead_code)]
static DEMO_NOW_SECS: OnceLock<u64> = OnceLock::new();

/// Returns true if demo mode is active (no disk writes).
pub fn is_demo() -> bool {
    DEMO_MODE.load(Ordering::Relaxed)
}

/// Enable demo mode. Called once at startup by `demo::build_demo_app()`.
pub fn enable() {
    DEMO_MODE.store(true, Ordering::Relaxed);
}

/// Disable demo mode. Used by tests to reset global state.
#[cfg(test)]
pub fn disable() {
    DEMO_MODE.store(false, Ordering::Relaxed);
}

/// Cross-crate test mutex serialising any test that mutates global
/// process state: the demo flag, `set_var`, the working directory, etc.
/// Lives in the library so both the binary's `preferences::tests` and the
/// library's `key_activity::tests` can acquire the same lock and never run
/// concurrently. `preferences::GLOBAL_TEST_IO_LOCK` is a `pub use` alias
/// for back-compat with existing call sites.
///
/// `dead_code` allow: only `#[cfg(test)]` paths read this static, and the
/// release binary's lint pass does not see those paths.
#[allow(dead_code)]
pub static GLOBAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Frozen reference timestamp for demo mode. Initialised lazily on first
/// call from real wall-clock time, then cached for the rest of the process.
/// Demo data builders and `format_time_ago` both call this when demo mode is
/// active so the relative-time arithmetic uses one consistent reference.
#[allow(dead_code)]
pub(crate) fn now_secs() -> u64 {
    *DEMO_NOW_SECS.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    })
}
