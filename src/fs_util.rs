use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use log::{debug, error};

/// Advisory file lock using a `.lock` file.
/// The lock is released when the `FileLock` is dropped.
pub struct FileLock {
    lock_path: PathBuf,
    #[cfg(unix)]
    _file: fs::File,
}

impl FileLock {
    /// Acquire an advisory lock for the given path.
    /// Creates a `.purple_lock` file alongside the target and holds an `flock` on it.
    /// Blocks until the lock is acquired (or returns an error on failure).
    pub fn acquire(path: &Path) -> io::Result<Self> {
        let mut lock_name = path.file_name().unwrap_or_default().to_os_string();
        lock_name.push(".purple_lock");
        let lock_path = path.with_file_name(lock_name);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&lock_path)?;

            // SAFETY: flock() is safe to call on any valid file descriptor.
            // The fd comes from a File we just opened and own. LOCK_EX
            // requests an exclusive advisory lock, blocking until acquired.
            let ret =
                unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(FileLock {
                lock_path,
                _file: file,
            })
        }

        #[cfg(not(unix))]
        {
            // On non-Unix, use a simple lock file (best-effort)
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
                .or_else(|_| {
                    // If it already exists, wait briefly and retry
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    fs::remove_file(&lock_path).ok();
                    fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&lock_path)
                })?;
            Ok(FileLock {
                lock_path,
                _file: file,
            })
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // On Unix, flock is released when the file descriptor is closed (automatic).
        // The lockfile itself is intentionally left on disk: unlinking it here
        // creates a race where a second process opens a fresh inode at the
        // same path and obtains an independent flock, so both processes
        // think they hold the lock. Leaving the file (1 byte at chmod 600)
        // matches the standard advisory-lock pattern.
        // The `lock_path` field is kept for diagnostics (Debug, logging).
        let _ = &self.lock_path;
    }
}

/// Atomic write: write content to a PID-suffixed temp file with chmod 600, then rename.
/// Uses O_EXCL (create_new) to prevent symlink attacks on the temp file path.
/// Cleans up the temp file on failure.
pub fn atomic_write(path: &Path, content: &[u8]) -> io::Result<()> {
    debug!("Atomic write: {}", path.display());
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".purple_tmp.{}", std::process::id()));
    let tmp_path = path.with_file_name(tmp_name);

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // Try O_EXCL first. If a stale tmp file exists from a crashed run, remove
        // it and retry once. This avoids a TOCTOU gap from removing before creating.
        let open = || {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
        };
        let mut file = match open() {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&tmp_path);
                open().map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("Failed to create temp file {}: {}", tmp_path.display(), e),
                    )
                })?
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("Failed to create temp file {}: {}", tmp_path.display(), e),
                ));
            }
        };
        if let Err(e) = file.write_all(content) {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        if let Err(e) = file.sync_all() {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(e) = fs::write(&tmp_path, content) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        // sync_all via reopen since fs::write doesn't return a File handle
        match fs::File::open(&tmp_path) {
            Ok(f) => {
                if let Err(e) = f.sync_all() {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(e);
                }
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
        }
    }

    let result = fs::rename(&tmp_path, path);
    if let Err(ref err) = result {
        let _ = fs::remove_file(&tmp_path);
        error!("[purple] Atomic write failed: {}: {err}", path.display());
        return result;
    }

    // Durable rename: the temp file's data was synced before rename, but the
    // directory entry change produced by `rename` lives in the page cache
    // until the parent directory itself is synced. Without this, a crash
    // within seconds of save can leave the directory pointing at the old
    // inode (= silently dropped edit). Best-effort: log but don't fail the
    // write if the parent sync itself fails — the rename already succeeded.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::File::open(parent).and_then(|d| d.sync_all()) {
            debug!(
                "[purple] parent dir sync after rename failed (rename succeeded): {}: {err}",
                parent.display()
            );
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_lock_does_not_remove_lockfile_on_drop() {
        // Regression for the lockfile-unlink race: a second process can open
        // a new inode at the same path between fd-close and remove_file,
        // and then both processes hold flock on independent inodes.
        // Leaving the lockfile in place after drop prevents this entirely.
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("config");
        let lockfile = dir.path().join("config.purple_lock");

        {
            let _lock = FileLock::acquire(&target).expect("acquire");
            assert!(lockfile.exists(), "lockfile must be created on acquire");
        }
        assert!(
            lockfile.exists(),
            "lockfile must remain after drop (not unlinked)"
        );
    }

    #[test]
    fn atomic_write_creates_file_with_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("file");
        atomic_write(&target, b"hello\n").expect("write");
        let content = std::fs::read_to_string(&target).expect("read");
        assert_eq!(content, "hello\n");
    }

    #[test]
    fn atomic_write_replaces_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("file");
        std::fs::write(&target, b"old").expect("write old");
        atomic_write(&target, b"new").expect("write new");
        let content = std::fs::read_to_string(&target).expect("read");
        assert_eq!(content, "new");
    }

    #[test]
    fn atomic_write_leaves_no_temp_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("file");
        atomic_write(&target, b"content").expect("write");
        let stem = target.file_name().unwrap().to_string_lossy().to_string();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with(&format!("{}.purple_tmp.", stem))
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp file leaked after successful write: {:?}",
            leftovers.iter().map(|e| e.path()).collect::<Vec<_>>()
        );
    }
}
