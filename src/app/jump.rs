//! Unified jump bar types.
//!
//! Sources hosts, tunnels, containers, snippets and actions in one ranked
//! list. Sections render in a fixed order. Empty sections are omitted.

use std::path::PathBuf;

use crate::fs_util::atomic_write;

/// What kind of thing a jump hit represents. Drives the type-marker glyph
/// rendered in the left column and the section grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Host,
    Tunnel,
    Container,
    Snippet,
    Action,
}

impl SourceKind {
    pub fn section_label(self) -> &'static str {
        match self {
            Self::Host => "HOSTS",
            Self::Tunnel => "TUNNELS",
            Self::Container => "CONTAINERS",
            Self::Snippet => "SNIPPETS",
            Self::Action => "ACTIONS",
        }
    }

    /// Fixed render order. Empty sections are skipped at render time but the
    /// order itself never changes — keeps muscle memory stable.
    pub fn render_order() -> [Self; 5] {
        [
            Self::Host,
            Self::Tunnel,
            Self::Container,
            Self::Snippet,
            Self::Action,
        ]
    }
}

/// One row in the unified jump bar. Each variant carries enough state for the
/// dispatch step to navigate the user to the matched item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JumpHit {
    Action(JumpAction),
    Host(HostHit),
    Tunnel(TunnelHit),
    Container(ContainerHit),
    Snippet(SnippetHit),
}

impl JumpHit {
    pub fn kind(&self) -> SourceKind {
        match self {
            Self::Action(_) => SourceKind::Action,
            Self::Host(_) => SourceKind::Host,
            Self::Tunnel(_) => SourceKind::Tunnel,
            Self::Container(_) => SourceKind::Container,
            Self::Snippet(_) => SourceKind::Snippet,
        }
    }

    /// All searchable strings, including aliases. Score = max over haystacks.
    /// Returns borrowed slices so the scoring loop is allocation-free per
    /// hit. The single exception is the action hotkey which needs a tiny
    /// owned buffer; we render it via `key_str` which is a `String` field
    /// on `JumpAction`.
    pub fn haystacks(&self) -> Vec<&str> {
        match self {
            Self::Action(a) => {
                let mut v = Vec::with_capacity(2 + a.aliases.len());
                v.push(a.label);
                v.push(a.key_str);
                for alias in a.aliases {
                    v.push(*alias);
                }
                v
            }
            Self::Host(h) => {
                let mut v = Vec::with_capacity(7 + h.tags.len());
                v.push(h.alias.as_str());
                v.push(h.hostname.as_str());
                if let Some(p) = &h.provider {
                    v.push(p.as_str());
                }
                for t in &h.tags {
                    v.push(t.as_str());
                }
                if !h.user.is_empty() {
                    v.push(h.user.as_str());
                }
                if !h.identity_file.is_empty() {
                    v.push(h.identity_file.as_str());
                }
                if !h.proxy_jump.is_empty() {
                    v.push(h.proxy_jump.as_str());
                }
                if let Some(role) = &h.vault_ssh {
                    v.push(role.as_str());
                }
                v
            }
            Self::Tunnel(t) => vec![t.alias.as_str(), t.destination.as_str(), &t.bind_port_str],
            Self::Container(c) => vec![
                c.container_name.as_str(),
                c.alias.as_str(),
                c.container_id.as_str(),
            ],
            Self::Snippet(s) => vec![s.name.as_str(), s.command_preview.as_str()],
        }
    }

    /// Stable identity used for MRU dedup.
    pub fn identity(&self) -> RecentRef {
        match self {
            Self::Action(a) => RecentRef::new(SourceKind::Action, a.key.to_string()),
            Self::Host(h) => RecentRef::new(SourceKind::Host, h.alias.clone()),
            Self::Tunnel(t) => {
                RecentRef::new(SourceKind::Tunnel, format!("{}:{}", t.alias, t.bind_port))
            }
            Self::Container(c) => RecentRef::new(
                SourceKind::Container,
                format!("{}/{}", c.alias, c.container_name),
            ),
            Self::Snippet(s) => RecentRef::new(SourceKind::Snippet, s.name.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JumpAction {
    pub key: char,
    /// Same letter as `key` but as a `&'static str` so it can be used as a
    /// haystack without allocating per scoring call. Stored once in the
    /// static action table; verified by debug assertion in tests.
    pub key_str: &'static str,
    pub label: &'static str,
    pub aliases: &'static [&'static str],
    /// Which top-page handler executes this action. The dispatch path
    /// switches `app.top_page` to this target before synthesising the
    /// hotkey keypress, so `Tunnels: Add tunnel` works from the Hosts
    /// tab and vice versa.
    pub target: JumpActionTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpActionTarget {
    Hosts,
    Tunnels,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHit {
    pub alias: String,
    pub hostname: String,
    pub tags: Vec<String>,
    pub provider: Option<String>,
    pub user: String,
    pub identity_file: String,
    pub proxy_jump: String,
    pub vault_ssh: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelHit {
    pub alias: String,
    pub bind_port: u16,
    /// Pre-rendered port number, kept around so `haystacks()` can return
    /// borrowed slices instead of allocating a fresh `format!` per
    /// keystroke.
    pub bind_port_str: String,
    pub destination: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHit {
    pub alias: String,
    pub container_name: String,
    pub container_id: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetHit {
    pub name: String,
    pub command_preview: String,
}

/// Stable reference to a hit, used for the on-disk MRU log and for
/// dispatching jumps.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RecentRef {
    pub kind: SourceKind,
    pub key: String,
}

impl RecentRef {
    pub fn new(kind: SourceKind, key: String) -> Self {
        Self { kind, key }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecentEntry {
    #[serde(flatten)]
    pub target: RecentRef,
    pub last_used_unix: i64,
}

/// On-disk schema for `~/.purple/recents.json`. Versioned so future shape
/// changes can rev without dropping user state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecentsFile {
    pub version: u32,
    pub entries: Vec<RecentEntry>,
}

impl Default for RecentsFile {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

const RECENTS_VERSION: u32 = 1;
const RECENTS_CAP: usize = 50;

/// Resolve the recents file path. Honors `purple_recents_path_override`
/// for tests; otherwise lives at `~/.purple/recents.json`.
pub fn recents_path() -> Option<PathBuf> {
    if let Some(p) = recents_path_override() {
        return Some(p);
    }
    let home = dirs::home_dir()?;
    Some(home.join(".purple").join("recents.json"))
}

// Test-only override pattern. **Thread-local** so parallel `cargo test`
// threads do not see each other's overrides. The previous `Mutex` shape
// caused contamination: any test that triggered a record dispatch on
// thread A would observe an override set by an unrelated test on thread B
// and write into B's tempdir, breaking B's roundtrip assertions.
#[cfg(test)]
pub mod test_path {
    use std::cell::RefCell;
    use std::path::PathBuf;

    thread_local! {
        static OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    pub fn set(path: PathBuf) {
        OVERRIDE.with(|cell| *cell.borrow_mut() = Some(path));
    }

    pub fn clear() {
        OVERRIDE.with(|cell| *cell.borrow_mut() = None);
    }

    pub fn get() -> Option<PathBuf> {
        OVERRIDE.with(|cell| cell.borrow().clone())
    }
}

#[cfg(test)]
fn recents_path_override() -> Option<PathBuf> {
    test_path::get()
}

#[cfg(not(test))]
fn recents_path_override() -> Option<PathBuf> {
    None
}

pub fn load_recents() -> RecentsFile {
    #[cfg(test)]
    {
        // Test builds only read recents when a tempdir override is set. See
        // the matching guard in `save_recents` for the rationale.
        if test_path::get().is_none() {
            return RecentsFile::default();
        }
    }
    let Some(path) = recents_path() else {
        return RecentsFile::default();
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return RecentsFile::default(),
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save_recents(file: &RecentsFile) -> std::io::Result<()> {
    // In test builds, only persist when a test has explicitly set a
    // tempdir override. This keeps tests that exercise the dispatch path
    // (which calls `record_jump_hit`) from contaminating either the
    // user's real `~/.purple/recents.json` or other tests' tempdirs via
    // the shared override slot.
    #[cfg(test)]
    {
        if test_path::get().is_none() {
            return Ok(());
        }
    }
    let Some(path) = recents_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(file).map_err(std::io::Error::other)?;
    atomic_write(&path, &bytes)
}

/// Insert or move-to-front a recent ref. Caps the list at `RECENTS_CAP`.
pub fn touch_recent(file: &mut RecentsFile, target: RecentRef) {
    file.version = RECENTS_VERSION;
    file.entries.retain(|e| e.target != target);
    let now = current_unix_ts();
    file.entries.insert(
        0,
        RecentEntry {
            target,
            last_used_unix: now,
        },
    );
    if file.entries.len() > RECENTS_CAP {
        file.entries.truncate(RECENTS_CAP);
    }
}

fn current_unix_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;

    pub(crate) static PATH_LOCK: Mutex<()> = Mutex::new(());

    fn with_temp<F: FnOnce(&std::path::Path)>(f: F) {
        let _g = PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recents.json");
        test_path::set(path.clone());
        f(&path);
        test_path::clear();
    }

    #[test]
    fn section_labels_are_uppercase() {
        for k in SourceKind::render_order() {
            let label = k.section_label();
            assert_eq!(label, label.to_uppercase(), "{:?} not uppercase", k);
        }
    }

    #[test]
    fn render_order_starts_with_hosts() {
        assert_eq!(SourceKind::render_order()[0], SourceKind::Host);
        assert_eq!(SourceKind::render_order()[4], SourceKind::Action);
    }

    #[test]
    fn touch_moves_existing_to_front_and_caps() {
        let mut f = RecentsFile::default();
        for i in 0..(RECENTS_CAP + 5) {
            touch_recent(&mut f, RecentRef::new(SourceKind::Host, format!("h{i}")));
        }
        assert_eq!(f.entries.len(), RECENTS_CAP);
        // Re-touching an existing ref moves it to the front.
        let target = RecentRef::new(SourceKind::Host, format!("h{}", RECENTS_CAP + 2));
        touch_recent(&mut f, target.clone());
        assert_eq!(f.entries[0].target, target);
        assert_eq!(f.entries.len(), RECENTS_CAP);
    }

    #[test]
    fn save_then_load_roundtrip() {
        with_temp(|_path| {
            let mut f = RecentsFile::default();
            touch_recent(&mut f, RecentRef::new(SourceKind::Action, "F".into()));
            touch_recent(&mut f, RecentRef::new(SourceKind::Host, "web-01".into()));
            save_recents(&f).expect("save");
            let loaded = load_recents();
            assert_eq!(loaded.version, RECENTS_VERSION);
            assert_eq!(loaded.entries.len(), 2);
            assert_eq!(loaded.entries[0].target.key, "web-01");
            assert_eq!(loaded.entries[1].target.key, "F");
        });
    }

    #[test]
    fn missing_file_loads_empty() {
        with_temp(|_path| {
            let loaded = load_recents();
            assert!(loaded.entries.is_empty());
        });
    }

    #[test]
    fn corrupt_file_loads_empty() {
        with_temp(|path| {
            std::fs::write(path, b"not json").unwrap();
            let loaded = load_recents();
            assert!(loaded.entries.is_empty());
        });
    }
}
