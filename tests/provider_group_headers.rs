//! Verifies provider group-header handling across every registered provider.
//!
//! The sync engine WRITES a `# purple:group <DisplayName>` header using
//! `providers::provider_display_name`. The startup cleanup
//! (`remove_all_orphaned_group_headers`) and the per-delete cleanup
//! (`remove_orphaned_group_header`) MATCH headers using their own display-name
//! mapping. If the two mappings disagree for a provider, the header for an
//! active provider is wrongly deleted on startup (and a stale header is never
//! cleaned on delete). These tests drive the real functions for all 16
//! providers so any divergence is caught, not assumed.

use std::path::PathBuf;

use purple_ssh::providers::{PROVIDER_NAMES, provider_display_name};
use purple_ssh::ssh_config::model::{ConfigElement, SshConfigFile};

fn parse(content: &str) -> SshConfigFile {
    SshConfigFile {
        elements: SshConfigFile::parse_content(content),
        path: PathBuf::from("/tmp/test_config"),
        crlf: false,
        bom: false,
    }
}

fn header_present(config: &SshConfigFile, display: &str) -> bool {
    let needle = format!("# purple:group {display}");
    config
        .elements
        .iter()
        .any(|e| matches!(e, ConfigElement::GlobalLine(l) if l.trim() == needle))
}

/// For an ACTIVE provider host, the group header sync wrote must survive the
/// startup cleanup. A provider listed in the failure message has a divergent
/// cleanup mapping that deletes its header even though it has live hosts.
#[test]
fn every_provider_group_header_survives_startup_cleanup_with_active_host() {
    let mut broken = Vec::new();
    for &name in PROVIDER_NAMES {
        let display = provider_display_name(name);
        let cfg = format!(
            "# purple:group {display}\n\nHost test-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:123\n"
        );
        let mut config = parse(&cfg);
        let removed = config.remove_all_orphaned_group_headers();
        if !header_present(&config, display) {
            broken.push(format!("{name} -> '{display}' (removed={removed})"));
        }
    }
    assert!(
        broken.is_empty(),
        "{} of {} providers lose their group header on startup despite active hosts: {:#?}",
        broken.len(),
        PROVIDER_NAMES.len(),
        broken
    );
}

/// When the last host of a provider is gone, its now-orphaned group header must
/// be removed by the startup cleanup. A provider in the failure message has a
/// divergent mapping that leaves a stale header behind forever.
#[test]
fn every_provider_orphan_header_removed_when_no_hosts() {
    let mut broken = Vec::new();
    for &name in PROVIDER_NAMES {
        let display = provider_display_name(name);
        // Header present, but NO host of that provider anywhere.
        let cfg = format!("# purple:group {display}\n\nHost unrelated\n  HostName 9.9.9.9\n");
        let mut config = parse(&cfg);
        config.remove_all_orphaned_group_headers();
        if header_present(&config, display) {
            broken.push(format!("{name} -> '{display}'"));
        }
    }
    assert!(
        broken.is_empty(),
        "{} of {} providers leave a stale orphan group header behind: {:#?}",
        broken.len(),
        PROVIDER_NAMES.len(),
        broken
    );
}
