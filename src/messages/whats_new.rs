// ── What's New overlay strings ──────────────────────────────────────

pub const TITLE: &str = "What's new";
/// Special: what's_new combines `esc`, `q` and `n` (mark seen). Other
/// labels and the `j/k` / `g/G` keys come from `messages::footer`.
pub const FOOTER_CLOSE_KEYS: &str = "esc/q/n";
pub const KIND_FEAT: &str = "+ feat  ";
pub const KIND_CHANGE: &str = "~ change";
pub const KIND_FIX: &str = "! fix   ";
pub const EMPTY: &str = "no release notes available.";

pub fn subtitle(from: Option<&str>, to: &str) -> String {
    match from {
        Some(f) if f != to => format!("upgraded from {} to {}", f, to),
        Some(_) => format!("you're on purple {}", to),
        None => format!("welcome to purple {}", to),
    }
}

pub fn update_available(version: &str) -> String {
    format!(
        "purple {} is available. run purple update to upgrade.",
        version
    )
}
