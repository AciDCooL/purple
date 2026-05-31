//! Exhaustive per-provider scenario matrix for `# purple:group` handling.
//!
//! For every provider in the registry, this drives the real config-layer
//! functions through every scenario that can happen to a provider group and
//! records PASS/FAIL into a matrix written to /tmp/provider_matrix.txt. The
//! file is written before the assertion so the full matrix is always available,
//! even on failure. The test then asserts the whole matrix is green.

use std::path::PathBuf;

use purple_ssh::providers::{PROVIDER_NAMES, provider_display_name};
use purple_ssh::ssh_config::model::{ConfigElement, SshConfigFile};

fn parse(content: &str) -> SshConfigFile {
    SshConfigFile {
        elements: SshConfigFile::parse_content(content),
        path: PathBuf::from("/tmp/matrix_config"),
        crlf: false,
        bom: false,
    }
}

fn header_idx(c: &SshConfigFile, display: &str) -> Option<usize> {
    let needle = format!("# purple:group {display}");
    c.elements
        .iter()
        .position(|e| matches!(e, ConfigElement::GlobalLine(l) if l.trim() == needle))
}

fn header_present(c: &SshConfigFile, display: &str) -> bool {
    header_idx(c, display).is_some()
}

fn host_idx(c: &SshConfigFile, alias: &str) -> Option<usize> {
    c.elements
        .iter()
        .position(|e| matches!(e, ConfigElement::HostBlock(b) if b.host_pattern == alias))
}

/// A different provider name to build a neighbouring group with.
fn other_provider(name: &str) -> &'static str {
    if name == "tailscale" {
        "digitalocean"
    } else {
        "tailscale"
    }
}

const SCENARIOS: &[&str] = &[
    "registry_display",         // S0: display name resolves
    "active_header_survives",   // S1: orphan-cleanup keeps header w/ active host
    "orphan_header_removed",    // S2: orphan-cleanup drops stale header
    "detect_bare_marker",       // S3: provider:server_id recognised
    "detect_labeled_marker",    // S4: provider:label:server_id recognised
    "detect_colon_server_id",   // S5: provider:qemu:300 (colon in id) recognised
    "raw_colon_server_id",      // S6: find_hosts_by_provider_raw on colon id
    "insert_anchor_in_group",   // S7: new host anchors inside its group
    "delete_last_drops_header", // S8: deleting last host removes orphan header
    "roundtrip_header",         // S9: parse->serialize keeps header + marker
    "repair_absorbed_header",   // S10: absorbed group comment relocated
    "no_dup_header_on_reparse", // S11: re-parse/serialize keeps exactly one header
];

struct Cell {
    pass: bool,
    note: String,
}

fn run_scenario(name: &str, display: &str, scenario: &str) -> Cell {
    let ok = |b: bool| Cell {
        pass: b,
        note: String::new(),
    };
    let okn = |b: bool, n: &str| Cell {
        pass: b,
        note: n.to_string(),
    };
    match scenario {
        "registry_display" => okn(!display.is_empty(), display),
        "active_header_survives" => {
            let cfg = format!(
                "# purple:group {display}\n\nHost act-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:123\n"
            );
            let mut c = parse(&cfg);
            let removed = c.remove_all_orphaned_group_headers();
            okn(header_present(&c, display), &format!("removed={removed}"))
        }
        "orphan_header_removed" => {
            let cfg = format!("# purple:group {display}\n\nHost unrelated\n  HostName 9.9.9.9\n");
            let mut c = parse(&cfg);
            c.remove_all_orphaned_group_headers();
            ok(!header_present(&c, display))
        }
        "detect_bare_marker" => {
            let cfg =
                format!("Host b-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:123\n");
            let c = parse(&cfg);
            ok(c.find_hosts_by_provider(name).len() == 1)
        }
        "detect_labeled_marker" => {
            let cfg =
                format!("Host l-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:work:123\n");
            let c = parse(&cfg);
            ok(c.find_hosts_by_provider(name).len() == 1)
        }
        "detect_colon_server_id" => {
            let cfg =
                format!("Host c-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:qemu:300\n");
            let c = parse(&cfg);
            ok(c.find_hosts_by_provider(name).len() == 1)
        }
        "raw_colon_server_id" => {
            let cfg =
                format!("Host r-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:qemu:300\n");
            let c = parse(&cfg);
            ok(c.find_hosts_by_provider_raw(name).len() == 1)
        }
        "insert_anchor_in_group" => {
            let other = other_provider(name);
            let other_d = provider_display_name(other);
            let cfg = format!(
                "# purple:group {display}\n\nHost p1-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:1\n\n# purple:group {other_d}\n\nHost o1\n  HostName 2.2.2.2\n  # purple:provider {other}:2\n"
            );
            let c = parse(&cfg);
            let pos = c.find_provider_insert_position(name);
            let other_header = header_idx(&c, other_d);
            match (pos, other_header) {
                (Some(p), Some(oh)) => okn(p <= oh, &format!("pos={p} other_header={oh}")),
                (p, oh) => okn(false, &format!("pos={p:?} other_header={oh:?}")),
            }
        }
        "delete_last_drops_header" => {
            let cfg = format!(
                "# purple:group {display}\n\nHost only-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:123\n"
            );
            let mut c = parse(&cfg);
            c.delete_host(&format!("only-{name}"));
            okn(
                !header_present(&c, display) && host_idx(&c, &format!("only-{name}")).is_none(),
                "after delete",
            )
        }
        "roundtrip_header" => {
            let cfg = format!(
                "# purple:group {display}\n\nHost rt-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:123\n"
            );
            let c = parse(&cfg);
            let s = c.serialize();
            ok(s.contains(&format!("# purple:group {display}"))
                && s.contains(&format!("# purple:provider {name}:123")))
        }
        "repair_absorbed_header" => {
            // Indented group comment is absorbed into the block's directives by
            // the parser; repair must relocate it to a top-level GlobalLine.
            let cfg = format!(
                "Host ab-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:123\n  # purple:group {display}\n"
            );
            let mut c = parse(&cfg);
            c.repair_absorbed_group_comments();
            ok(header_present(&c, display))
        }
        "no_dup_header_on_reparse" => {
            let cfg = format!(
                "# purple:group {display}\n\nHost nd-{name}\n  HostName 1.1.1.1\n  # purple:provider {name}:123\n"
            );
            let c = parse(&cfg);
            let s1 = c.serialize();
            let c2 = parse(&s1);
            let count = c2
                .elements
                .iter()
                .filter(|e| matches!(e, ConfigElement::GlobalLine(l) if l.trim_start().starts_with("# purple:group ")))
                .count();
            okn(count == 1, &format!("header_count={count}"))
        }
        _ => okn(false, "unknown scenario"),
    }
}

#[test]
fn provider_scenario_matrix_all_green() {
    let mut rows: Vec<(String, Vec<Cell>)> = Vec::new();
    for &name in PROVIDER_NAMES {
        let display = provider_display_name(name).to_string();
        let cells: Vec<Cell> = SCENARIOS
            .iter()
            .map(|s| run_scenario(name, &display, s))
            .collect();
        rows.push((name.to_string(), cells));
    }

    let mut out = String::new();
    out.push_str("PER-PROVIDER SCENARIO MATRIX\n");
    out.push_str(&format!(
        "{} providers x {} scenarios\n\n",
        rows.len(),
        SCENARIOS.len()
    ));
    out.push_str("Scenario legend:\n");
    for (i, s) in SCENARIOS.iter().enumerate() {
        out.push_str(&format!("  S{i:<2} {s}\n"));
    }
    out.push('\n');
    out.push_str(&format!("{:<14}", "provider"));
    for i in 0..SCENARIOS.len() {
        out.push_str(&format!(" S{i:<2}"));
    }
    out.push_str("  result\n");
    let mut total_fail = 0;
    let mut fail_detail = String::new();
    for (name, cells) in &rows {
        out.push_str(&format!("{name:<14}"));
        let mut row_fail = 0;
        for (i, c) in cells.iter().enumerate() {
            out.push_str(&format!(" {:<3}", if c.pass { "ok" } else { "XX" }));
            if !c.pass {
                row_fail += 1;
                total_fail += 1;
                fail_detail.push_str(&format!("  {name} / S{i} {} : {}\n", SCENARIOS[i], c.note));
            }
        }
        out.push_str(&format!(
            "  {}\n",
            if row_fail == 0 { "ALL PASS" } else { "FAIL" }
        ));
    }
    out.push_str(&format!("\nTOTAL FAILURES: {total_fail}\n"));
    if total_fail > 0 {
        out.push_str("\nFAILURE DETAIL:\n");
        out.push_str(&fail_detail);
    }
    std::fs::write("/tmp/provider_matrix.txt", &out).unwrap();

    assert_eq!(
        total_fail, 0,
        "{total_fail} provider/scenario cells failed; see /tmp/provider_matrix.txt\n{out}"
    );
}
