use std::io;
use std::path::PathBuf;

use crate::app::SortMode;
use crate::fs_util;

fn path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".purple/preferences"))
}

/// Load a value for a given key from ~/.purple/preferences.
fn load_value(key: &str) -> Option<String> {
    let path = path()?;
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Save a key=value pair to ~/.purple/preferences. Preserves unknown keys and comments.
fn save_value(key: &str, value: &str) -> io::Result<()> {
    let path = match path() {
        Some(p) => p,
        None => return Ok(()),
    };

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    let mut found = false;

    for line in existing.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('#')
            && !trimmed.is_empty()
            && trimmed
                .split_once('=')
                .is_some_and(|(k, _)| k.trim() == key)
        {
            lines.push(format!("{}={}", key, value));
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }

    if !found {
        lines.push(format!("{}={}", key, value));
    }

    let content = lines.join("\n") + "\n";

    fs_util::atomic_write(&path, content.as_bytes())
}

/// Load sort mode from ~/.purple/preferences. Returns AlphaAlias if missing or invalid.
pub fn load_sort_mode() -> SortMode {
    load_value("sort_mode")
        .map(|v| SortMode::from_key(&v))
        .unwrap_or(SortMode::AlphaAlias)
}

/// Save sort mode to ~/.purple/preferences.
pub fn save_sort_mode(mode: SortMode) -> io::Result<()> {
    save_value("sort_mode", mode.to_key())
}

/// Load group_by_provider from ~/.purple/preferences. Returns true if missing or invalid.
pub fn load_group_by_provider() -> bool {
    load_value("group_by_provider")
        .map(|v| v != "false")
        .unwrap_or(true)
}

/// Save group_by_provider to ~/.purple/preferences.
pub fn save_group_by_provider(enabled: bool) -> io::Result<()> {
    save_value("group_by_provider", &enabled.to_string())
}
