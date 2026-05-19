use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind};

/// Application events.
pub enum AppEvent {
    Key(KeyEvent),
    Tick,
    PingResult {
        alias: String,
        rtt_ms: Option<u32>,
        generation: u64,
    },
    SyncComplete {
        provider: String,
        hosts: Vec<crate::providers::ProviderHost>,
    },
    SyncPartial {
        provider: String,
        hosts: Vec<crate::providers::ProviderHost>,
        failures: usize,
        total: usize,
    },
    SyncError {
        provider: String,
        message: String,
    },
    SyncProgress {
        provider: String,
        message: String,
    },
    UpdateAvailable {
        version: String,
        headline: Option<String>,
    },
    FileBrowserListing {
        alias: String,
        path: String,
        entries: Result<Vec<crate::file_browser::FileEntry>, String>,
    },
    ScpComplete {
        alias: String,
        success: bool,
        message: String,
    },
    SnippetHostDone {
        run_id: u64,
        alias: String,
        stdout: String,
        stderr: String,
        exit_code: Option<i32>,
    },
    SnippetAllDone {
        run_id: u64,
    },
    SnippetProgress {
        run_id: u64,
        completed: usize,
        total: usize,
    },
    /// Result of one host in a key-push run. Aggregated in
    /// `app.keys.push.results` by the main loop; the summary toast / sticky
    /// error overlay fires once `results.len() == expected_count`.
    ///
    /// `run_id` matches `app.keys.push.run_id` at the moment the worker
    /// was spawned. Results whose `run_id` no longer matches the current
    /// run are stale (a previous cancelled run's tail event) and dropped
    /// before they touch the accumulator.
    KeyPushResult {
        run_id: u64,
        result: crate::key_push::KeyPushResult,
    },
    ContainerListing {
        alias: String,
        result: Result<crate::containers::ContainerListing, crate::containers::ContainerError>,
    },
    ContainerActionComplete {
        alias: String,
        action: crate::containers::ContainerAction,
        result: Result<(), String>,
    },
    /// Result of a `docker inspect` (or `podman inspect`) call fired by
    /// the containers overview detail panel. Cached per (alias,
    /// container_id) once received so repeat fetches inside the TTL
    /// window are skipped.
    ContainerInspectComplete {
        alias: String,
        container_id: String,
        // Boxed because `ContainerInspect` carries the full audit
        // payload (caps, mounts, compose labels). Inlining it grows the
        // `AppEvent` enum past clippy's `large_enum_variant` budget,
        // bloating every queue slot for events that do not carry it.
        result: Box<Result<crate::containers::ContainerInspect, String>>,
    },
    /// Result of `<runtime> logs --tail 200` over SSH for a container
    /// the user opened with `l`. Populates `Screen::ContainerLogs.body`
    /// (or `.error`) when received.
    ContainerLogsComplete {
        alias: String,
        container_id: String,
        container_name: String,
        result: Result<Vec<String>, String>,
    },
    /// Result of a short `<runtime> logs --tail N` fetch fired by the
    /// containers-overview detail panel to populate the LOGS card.
    /// Distinct from `ContainerLogsComplete` so the dedicated logs
    /// viewer (`l`) and the detail-panel card stay on separate caches.
    ContainerLogsTailComplete {
        alias: String,
        container_id: String,
        result: Box<Result<Vec<String>, String>>,
    },
    VaultSignResult {
        alias: String,
        /// Snapshot of the host's `CertificateFile` directive at signing time.
        /// Carried in the event so the main loop never has to re-look up the
        /// host (which would be O(n) and racy under concurrent renames). Empty
        /// when the host has no `CertificateFile` set; `should_write_certificate_file`
        /// uses this directly to decide whether to write a default directive.
        certificate_file: String,
        success: bool,
        message: String,
    },
    VaultSignProgress {
        alias: String,
        done: usize,
        total: usize,
    },
    VaultSignAllDone {
        signed: u32,
        failed: u32,
        skipped: u32,
        cancelled: bool,
        aborted_message: Option<String>,
        first_error: Option<String>,
    },
    CertCheckResult {
        alias: String,
        status: crate::vault_ssh::CertStatus,
    },
    CertCheckError {
        alias: String,
        message: String,
    },
    PollError,
}

impl AppEvent {
    /// True for variants produced by background workers (sync, ping,
    /// container ops, Vault, etc.). False for variants produced by the
    /// crossterm poll thread (`Key`, `Tick`, `PollError`). Exhaustive
    /// match forces a deliberate choice when adding a new variant.
    fn is_background_result(&self) -> bool {
        match self {
            AppEvent::Key(_) | AppEvent::Tick | AppEvent::PollError => false,
            AppEvent::PingResult { .. }
            | AppEvent::SyncComplete { .. }
            | AppEvent::SyncPartial { .. }
            | AppEvent::SyncError { .. }
            | AppEvent::SyncProgress { .. }
            | AppEvent::UpdateAvailable { .. }
            | AppEvent::FileBrowserListing { .. }
            | AppEvent::ScpComplete { .. }
            | AppEvent::SnippetHostDone { .. }
            | AppEvent::SnippetAllDone { .. }
            | AppEvent::SnippetProgress { .. }
            | AppEvent::KeyPushResult { .. }
            | AppEvent::ContainerListing { .. }
            | AppEvent::ContainerActionComplete { .. }
            | AppEvent::ContainerInspectComplete { .. }
            | AppEvent::ContainerLogsComplete { .. }
            | AppEvent::ContainerLogsTailComplete { .. }
            | AppEvent::VaultSignResult { .. }
            | AppEvent::VaultSignProgress { .. }
            | AppEvent::VaultSignAllDone { .. }
            | AppEvent::CertCheckResult { .. }
            | AppEvent::CertCheckError { .. } => true,
        }
    }
}

/// Polls crossterm events in a background thread.
pub struct EventHandler {
    tx: mpsc::Sender<AppEvent>,
    rx: mpsc::Receiver<AppEvent>,
    paused: Arc<AtomicBool>,
    // Keep the thread handle alive
    _handle: thread::JoinHandle<()>,
}

impl EventHandler {
    pub fn new(tick_rate_ms: u64) -> Self {
        let (tx, rx) = mpsc::channel();
        let tick_rate = Duration::from_millis(tick_rate_ms);
        let event_tx = tx.clone();
        let paused = Arc::new(AtomicBool::new(false));
        let paused_flag = paused.clone();

        let handle = thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                // When paused, sleep instead of polling stdin
                if paused_flag.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }

                // Cap poll timeout at 50ms so we notice pause flag quickly
                let remaining = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or(Duration::ZERO);
                let timeout = remaining.min(Duration::from_millis(50));

                match event::poll(timeout) {
                    Ok(true) => {
                        if let Ok(evt) = event::read() {
                            match evt {
                                CrosstermEvent::Key(key)
                                    if key.kind == KeyEventKind::Press
                                        && event_tx.send(AppEvent::Key(key)).is_err() =>
                                {
                                    return;
                                }
                                // Trigger immediate redraw on terminal resize.
                                CrosstermEvent::Resize(..)
                                    if event_tx.send(AppEvent::Tick).is_err() =>
                                {
                                    return;
                                }
                                _ => {}
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(e) => {
                        // Poll error (e.g. stdin closed). Notify main loop and exit.
                        log::error!("[external] crossterm poll failed: {e}");
                        let _ = event_tx.send(AppEvent::PollError);
                        return;
                    }
                }

                if last_tick.elapsed() >= tick_rate {
                    if event_tx.send(AppEvent::Tick).is_err() {
                        return;
                    }
                    last_tick = Instant::now();
                }
            }
        });

        Self {
            tx,
            rx,
            paused,
            _handle: handle,
        }
    }

    /// Get the next event (blocks until available).
    pub fn next(&self) -> Result<AppEvent> {
        Ok(self.rx.recv()?)
    }

    /// Try to get the next event with a timeout.
    pub fn next_timeout(&self, timeout: Duration) -> Result<Option<AppEvent>> {
        match self.rx.recv_timeout(timeout) {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(anyhow::anyhow!("event channel disconnected"))
            }
        }
    }

    /// Get a clone of the sender for sending events from other threads.
    pub fn sender(&self) -> mpsc::Sender<AppEvent> {
        self.tx.clone()
    }

    /// Pause event polling (call before spawning SSH).
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Release);
    }

    /// Resume event polling (call after SSH exits).
    pub fn resume(&self) {
        let mut preserved = Vec::new();
        while let Ok(event) = self.rx.try_recv() {
            if event.is_background_result() {
                preserved.push(event);
            }
        }
        for event in preserved {
            let _ = self.tx.send(event);
        }
        self.paused.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn poll_thread_events_are_not_background_results() {
        let k = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        assert!(!AppEvent::Key(k).is_background_result());
        assert!(!AppEvent::Tick.is_background_result());
        assert!(!AppEvent::PollError.is_background_result());
    }

    #[test]
    fn worker_events_are_background_results() {
        assert!(
            AppEvent::PingResult {
                alias: "h".into(),
                rtt_ms: None,
                generation: 0,
            }
            .is_background_result()
        );
        assert!(
            AppEvent::SyncComplete {
                provider: "p".into(),
                hosts: vec![],
            }
            .is_background_result()
        );
        assert!(
            AppEvent::SyncPartial {
                provider: "p".into(),
                hosts: vec![],
                failures: 0,
                total: 0,
            }
            .is_background_result()
        );
        assert!(
            AppEvent::SyncError {
                provider: "p".into(),
                message: "x".into(),
            }
            .is_background_result()
        );
        assert!(
            AppEvent::SyncProgress {
                provider: "p".into(),
                message: "x".into(),
            }
            .is_background_result()
        );
        assert!(
            AppEvent::UpdateAvailable {
                version: "1.0.0".into(),
                headline: None,
            }
            .is_background_result()
        );
        assert!(
            AppEvent::FileBrowserListing {
                alias: "h".into(),
                path: "/".into(),
                entries: Ok(vec![]),
            }
            .is_background_result()
        );
        assert!(
            AppEvent::ScpComplete {
                alias: "h".into(),
                success: true,
                message: String::new(),
            }
            .is_background_result()
        );
        assert!(
            AppEvent::SnippetHostDone {
                run_id: 0,
                alias: "h".into(),
                stdout: String::new(),
                stderr: String::new(),
                exit_code: Some(0),
            }
            .is_background_result()
        );
        assert!(AppEvent::SnippetAllDone { run_id: 0 }.is_background_result());
        assert!(
            AppEvent::SnippetProgress {
                run_id: 0,
                completed: 0,
                total: 0,
            }
            .is_background_result()
        );
        assert!(
            AppEvent::VaultSignProgress {
                alias: "h".into(),
                done: 0,
                total: 0,
            }
            .is_background_result()
        );
        assert!(
            AppEvent::VaultSignAllDone {
                signed: 0,
                failed: 0,
                skipped: 0,
                cancelled: false,
                aborted_message: None,
                first_error: None,
            }
            .is_background_result()
        );
        assert!(
            AppEvent::CertCheckError {
                alias: "h".into(),
                message: "x".into(),
            }
            .is_background_result()
        );
    }

    /// End-to-end: pause, drop a mix of events into the channel, resume,
    /// and verify the drain rule. `Key`, `Tick`, `PollError` must be gone
    /// and the background results must reappear on the receiving end.
    /// Filters out any `Tick`/`Key` that the poll thread could in theory
    /// inject between `EventHandler::new()` and `pause()` (small race
    /// window) so the assertion stays deterministic in CI.
    #[test]
    fn resume_drains_input_and_keeps_background_results() {
        let handler = EventHandler::new(60_000);
        handler.pause();

        let k = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        handler.tx.send(AppEvent::Key(k)).unwrap();
        handler.tx.send(AppEvent::Tick).unwrap();
        handler.tx.send(AppEvent::PollError).unwrap();
        handler
            .tx
            .send(AppEvent::SyncProgress {
                provider: "p".into(),
                message: "x".into(),
            })
            .unwrap();
        handler
            .tx
            .send(AppEvent::PingResult {
                alias: "h".into(),
                rtt_ms: Some(12),
                generation: 1,
            })
            .unwrap();

        handler.resume();

        let mut received = Vec::new();
        while let Ok(Some(ev)) = handler.next_timeout(Duration::from_millis(50)) {
            received.push(ev);
        }
        let background: Vec<_> = received
            .into_iter()
            .filter(AppEvent::is_background_result)
            .collect();

        assert_eq!(
            background.len(),
            2,
            "exactly two background events survive resume()"
        );
        assert!(matches!(background[0], AppEvent::SyncProgress { .. }));
        assert!(matches!(background[1], AppEvent::PingResult { .. }));
    }
}
