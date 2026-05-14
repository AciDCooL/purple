use std::path::PathBuf;

use crate::app::{App, GroupBy, PingStatus, SortMode, SyncRecord, ViewMode};
use crate::containers;
use crate::history::ConnectionHistory;
use crate::providers::config::ProviderConfig;
use crate::snippet::SnippetStore;
use crate::ssh_config::model::SshConfigFile;
use crate::ssh_keys::SshKeyInfo;

const DEMO_SSH_CONFIG: &str = "\
# Infrastructure

Host bastion-ams
  HostName 140.82.121.3
  User ops
  DynamicForward 1080
  LocalForward 8443 internal.corp:443
  IdentityFile ~/.ssh/id_ed25519
  # purple:tags production,vpn
  # purple:askpass keychain

Host db-primary
  HostName 10.30.1.5
  User postgres
  Port 5433
  ProxyJump bastion-ams
  LocalForward 5432 localhost:5432
  LocalForward 9090 localhost:9090
  # purple:tags production,database
  # purple:askpass op://vault/prod-db

Host db-proton
  HostName db1.example.com
  User dba
  ProxyJump bastion-ams
  # purple:tags production,database
  # purple:askpass proton:Production/db-server/password

Host monitoring
  HostName 10.30.2.10
  User admin
  ProxyJump bastion-ams
  LocalForward 3000 localhost:3000
  # purple:tags production,monitoring

Host gateway-vpn
  HostName 185.199.108.5
  User openvpn
  # purple:tags infra,vpn
  # purple:vault-ssh ssh-client-signer/sign/infra

Host podman-edge
  HostName 10.20.30.40
  User core
  # purple:tags edge,podman
  # purple:meta os=Fedora CoreOS 41,runtime=podman 5.8

# AWS EC2

Host aws-api-prod
  HostName 52.47.100.23
  User ec2-user
  ProxyJump bastion-ams
  IdentityFile ~/.ssh/id_ed25519
  # purple:tags production,api
  # purple:provider aws:i-0a1b2c3d4e5f60001
  # purple:meta region=us-east-1,instance=t3.medium,os=Amazon Linux 2023,status=running
  # purple:vault-ssh ssh-client-signer/sign/admin

Host aws-api-staging
  HostName 52.47.100.24
  User ec2-user
  # purple:tags staging,api
  # purple:provider aws:i-0a1b2c3d4e5f60002
  # purple:meta region=us-east-1,instance=t3.small,os=Amazon Linux 2023,status=running

Host aws-worker-eu
  HostName 3.120.55.17
  User ec2-user
  # purple:tags production,worker
  # purple:provider aws:i-0a1b2c3d4e5f60003
  # purple:meta region=eu-central-1,instance=c6i.large,os=Ubuntu 22.04,status=running

Host aws-batch-us
  HostName 52.47.100.25
  User ec2-user
  # purple:tags production,batch
  # purple:provider aws:i-0a1b2c3d4e5f60004
  # purple:meta region=us-east-1,instance=c6i.xlarge,os=Amazon Linux 2023,status=running

Host aws-ml-eu
  HostName 3.120.55.18
  User ec2-user
  # purple:tags ml
  # purple:provider aws:i-0a1b2c3d4e5f60005
  # purple:meta region=eu-central-1,instance=g5.xlarge,os=Ubuntu 22.04,status=running

Host aws-cache-eu
  HostName 3.120.55.19
  User ec2-user
  # purple:tags cache
  # purple:provider aws:i-0a1b2c3d4e5f60006
  # purple:meta region=eu-central-1,instance=r6i.large,os=Amazon Linux 2023,status=stopped
  # purple:stale 1743800000

# DigitalOcean

Host do-work-web-ams
  HostName 104.248.38.91
  User deploy
  # purple:tags production,web
  # purple:provider digitalocean:work:382010
  # purple:meta region=ams3,size=s-2vcpu-4gb,image=Ubuntu 22.04,status=active

Host do-work-staging-ams
  HostName 104.248.38.92
  User deploy
  LocalForward 5432 localhost:5432
  # purple:tags staging,web
  # purple:provider digitalocean:work:382011
  # purple:meta region=ams3,size=s-2vcpu-4gb,image=Ubuntu 22.04,status=active

Host do-work-worker-ams
  HostName 104.248.38.93
  User deploy
  # purple:tags worker
  # purple:provider digitalocean:work:382012
  # purple:meta region=ams3,size=s-1vcpu-2gb,image=Ubuntu 22.04,status=active

Host do-work-ci-runner
  HostName 104.248.38.94
  User gitlab
  ProxyJump bastion-ams
  # purple:tags ci
  # purple:provider digitalocean:work:382013
  # purple:meta region=ams3,size=s-4vcpu-8gb,image=Ubuntu 22.04,status=active

Host do-personal-blog
  HostName 167.99.42.10
  User root
  # purple:tags personal,web
  # purple:provider digitalocean:personal:482001
  # purple:meta region=ams3,size=s-1vcpu-1gb,image=Ubuntu 22.04,status=active

Host do-personal-mail
  HostName 167.99.42.11
  User root
  # purple:tags personal,mail
  # purple:provider digitalocean:personal:482002
  # purple:meta region=fra1,size=s-1vcpu-2gb,image=Ubuntu 22.04,status=active

# Proxmox VE

Host pve-web-01
  HostName 192.168.1.20
  User root
  # purple:tags web,internal
  # purple:provider proxmox:100
  # purple:meta node=pve1,type=qemu,specs=4c/8GiB,os=Debian 12,status=running

Host pve-web-02
  HostName 192.168.1.21
  User root
  # purple:tags web,internal
  # purple:provider proxmox:101
  # purple:meta node=pve1,type=qemu,specs=4c/8GiB,os=Debian 12,status=running

Host pve-db-01
  HostName 192.168.1.30
  User postgres
  LocalForward 5432 localhost:5432
  # purple:tags database,internal
  # purple:provider proxmox:102
  # purple:meta node=pve1,type=qemu,specs=8c/32GiB,os=Debian 12,status=running

Host pve-db-02
  HostName 192.168.1.31
  User postgres
  # purple:tags database,internal
  # purple:provider proxmox:103
  # purple:meta node=pve2,type=qemu,specs=8c/32GiB,os=Debian 12,status=running

Host pve-redis
  HostName 192.168.1.40
  User redis
  LocalForward 6379 localhost:6379
  # purple:tags cache,internal
  # purple:provider proxmox:104
  # purple:meta node=pve1,type=lxc,specs=2c/4GiB,os=Debian 12,status=running

Host pve-mail
  HostName 192.168.1.50
  User mail
  # purple:tags mail,internal
  # purple:provider proxmox:105
  # purple:meta node=pve2,type=lxc,specs=2c/4GiB,os=Debian 12,status=running

Host pve-monitor
  HostName 192.168.1.60
  User admin
  LocalForward 3000 localhost:3000
  LocalForward 9090 localhost:9090
  # purple:tags monitoring,internal
  # purple:provider proxmox:106
  # purple:meta node=pve2,type=qemu,specs=4c/8GiB,os=Ubuntu 22.04,status=running

Host pve-backup
  HostName 192.168.1.70
  User backup
  # purple:tags backup,internal
  # purple:provider proxmox:107
  # purple:meta node=pve2,type=lxc,specs=2c/8GiB,os=Debian 12,status=stopped
  # purple:stale 1743800000
";

const DEMO_SNIPPETS: &str = "\
[uptime]
command=uptime
description=Server uptime and load

[disk-usage]
command=df -h /
description=Root disk usage

[docker-ps]
command=docker ps --format 'table {{.Names}}\\t{{.Status}}'
description=Running containers

[tail-logs]
command=tail -n 50 /var/log/syslog
description=Last 50 syslog lines

[restart-nginx]
command=sudo systemctl restart nginx
description=Restart nginx service
";

const DEMO_PROVIDERS: &str = "\
[aws]
token=
alias_prefix=aws
user=ec2-user
profile=production
regions=us-east-1,eu-central-1
auto_sync=true
vault_role=ssh-client-signer/sign/engineer

[digitalocean:work]
token=dop_v1_demo_work
alias_prefix=do-work
user=deploy
auto_sync=true

[digitalocean:personal]
token=dop_v1_demo_personal
alias_prefix=do-personal
user=root
auto_sync=false

[proxmox]
url=https://192.168.1.10:8006
token=root@pam!demo=xxx
alias_prefix=pve
user=root
vault_role=ssh-client-signer/sign/ops
vault_addr=http://localhost:8200
auto_sync=true
";

/// Generate demo history with timestamps relative to now.
/// Each entry: (alias, total_connections, spread_days).
const DEMO_HISTORY_SPEC: &[(&str, u32, u64)] = &[
    ("bastion-ams", 247, 300),
    ("db-primary", 142, 250),
    ("monitoring", 121, 280),
    ("gateway-vpn", 31, 300),
    ("podman-edge", 18, 60),
    ("aws-api-prod", 180, 300),
    ("aws-api-staging", 90, 200),
    ("aws-worker-eu", 65, 180),
    ("aws-batch-us", 160, 300),
    ("aws-ml-eu", 25, 80),
    ("aws-cache-eu", 8, 40),
    ("do-web-ams", 130, 250),
    ("do-staging-ams", 76, 180),
    ("do-worker-ams", 50, 150),
    ("do-ci-runner", 95, 200),
    ("pve-web-01", 110, 280),
    ("pve-web-02", 85, 250),
    ("pve-db-01", 70, 200),
    ("pve-db-02", 35, 120),
    ("pve-redis", 40, 100),
    ("pve-mail", 18, 90),
    ("pve-monitor", 60, 200),
    ("pve-backup", 6, 120),
];

fn build_demo_history() -> ConnectionHistory {
    use std::collections::HashMap;

    // Use the frozen demo clock so visual goldens are stable across slow CI
    // runs that might otherwise straddle a minute boundary between build and
    // render time.
    let now = crate::demo_flag::now_secs();
    let day: u64 = 86400;
    let hour: u64 = 3600;

    let mut entries = HashMap::new();
    // Generate timestamps with realistic variation: bursts of activity
    // mixed with quiet periods, creating interesting sparkline shapes.
    // Uses a simple LCG (linear congruential generator) for determinism.
    // last_connected is set to now minus a small offset based on spec order,
    // so hosts with higher count (earlier in spec) sort first in frecency.
    for (spec_idx, &(alias, count, spread_days)) in DEMO_HISTORY_SPEC.iter().enumerate() {
        let mut timestamps = Vec::with_capacity(count as usize);
        // Seed from alias for per-host variation
        let mut rng: u64 = alias.bytes().fold(0u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(u64::from(b))
        });
        for i in 0..count {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Base spread with jitter: clustered in recent weeks, sparse further back
            let base_days = (u64::from(i + 1) * spread_days) / u64::from(count + 1);
            let jitter_days = (rng >> 33) % (spread_days / 8 + 1);
            let days_ago = base_days.saturating_add(jitter_days).min(spread_days);
            // Working hours with variation
            let work_hour = 7 + (rng >> 40) % 13; // 7..19
            let minute = (rng >> 48) % 60;
            let ts = now.saturating_sub(days_ago * day) + work_hour * hour + minute * 60;
            let ts = ts.min(now);
            timestamps.push(ts);
        }
        timestamps.sort_unstable();
        timestamps.reverse();
        timestamps.dedup();
        // Override last_connected based on spec order so sort-by-recent is deterministic.
        // First entry in DEMO_HISTORY_SPEC = most recently connected.
        let last_connected = now - (spec_idx as u64) * hour;
        if let Some(first) = timestamps.first_mut() {
            *first = last_connected;
        }
        entries.insert(
            alias.to_string(),
            crate::history::HistoryEntry {
                alias: alias.to_string(),
                last_connected,
                count,
                timestamps,
            },
        );
    }
    ConnectionHistory::from_entries(entries)
}

fn build_demo_sync_history() -> String {
    let now = crate::demo_flag::now_secs();
    // All synced just now (within last few seconds)
    format!(
        "aws\t{now}\t0\tSynced 6 hosts (2 regions)\n\
         digitalocean\t{now}\t0\tSynced 4 hosts\n\
         proxmox\t{now}\t0\tSynced 8 VMs",
    )
}

fn build_demo_container_cache() -> String {
    let now = crate::demo_flag::now_secs();
    let ts1 = now - 1200;
    let ts2 = now - 900;
    let ts3 = now - 600;
    let ts4 = now - 1500;
    let ts5 = now - 1000;
    let ts6 = now - 800;
    let ts7 = now - 1100;
    let ts8 = now - 700;
    // The `podman-edge` row is the only podman host in the demo. Key
    // shape differences vs the docker fleet above:
    //   - runtime: "Podman", engine_version 5.x
    //   - Status is empty (podman emits no "Up Xd" / "Exited (N)" text)
    //   - Image uses the docker.io/library/ registry-prefixed form
    //   - One stopped container with non-zero exit driven by the
    //     inspect cache (not the Status string) so the state glyph
    //     warning path exercises the podman fallback in render_row.
    format!(
        r#"{{"alias":"bastion-ams","timestamp":{},"runtime":"Docker","engine_version":"25.0.3","containers":[{{"ID":"f1a2b3c4d5e6","Names":"nginx-proxy","Image":"nginx:1.25-alpine","State":"running","Status":"Up 12 days","Ports":"0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp"}},{{"ID":"a2b3c4d5e6f7","Names":"app-backend","Image":"myapp:v2.14.1","State":"running","Status":"Up 12 days","Ports":"127.0.0.1:8080->8080/tcp"}},{{"ID":"b3c4d5e6f7a8","Names":"redis","Image":"redis:7-alpine","State":"running","Status":"Up 12 days","Ports":"127.0.0.1:6379->6379/tcp"}},{{"ID":"c4d5e6f7a8b9","Names":"postgres","Image":"postgres:16-alpine","State":"running","Status":"Up 12 days","Ports":"127.0.0.1:5432->5432/tcp"}},{{"ID":"d5e6f7a8b9c0","Names":"prometheus","Image":"prom/prometheus:v2.48","State":"running","Status":"Up 5 days","Ports":"127.0.0.1:9090->9090/tcp"}},{{"ID":"e6f7a8b9c0d1","Names":"grafana","Image":"grafana/grafana:10.2","State":"running","Status":"Up 5 days","Ports":"127.0.0.1:3000->3000/tcp"}},{{"ID":"f7a8b9c0d1e2","Names":"certbot","Image":"certbot/certbot:v2.7","State":"exited","Status":"Exited (0) 2 days ago","Ports":""}}]}}
{{"alias":"db-primary","timestamp":{},"runtime":"Docker","engine_version":"24.0.7","containers":[{{"ID":"a8b9c0d1e2f3","Names":"postgres-primary","Image":"postgres:16-alpine","State":"running","Status":"Up 30 days","Ports":"127.0.0.1:5432->5432/tcp"}},{{"ID":"b9c0d1e2f3a4","Names":"pgbouncer","Image":"pgbouncer:1.21","State":"running","Status":"Up 30 days","Ports":"127.0.0.1:6432->6432/tcp"}},{{"ID":"c0d1e2f3a4b5","Names":"pg-exporter","Image":"prometheuscommunity/postgres-exporter:0.15","State":"running","Status":"Up 30 days","Ports":"127.0.0.1:9187->9187/tcp"}}]}}
{{"alias":"do-web-ams","timestamp":{},"runtime":"Docker","engine_version":"25.0.3","containers":[{{"ID":"d1e2f3a4b5c6","Names":"nginx","Image":"nginx:1.25","State":"running","Status":"Up 8 days","Ports":"0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp"}},{{"ID":"e2f3a4b5c6d7","Names":"app","Image":"myapp:3.2.1","State":"running","Status":"Up 8 days","Ports":"8080/tcp"}},{{"ID":"f3a4b5c6d7e8","Names":"worker","Image":"myapp:3.2.1","State":"running","Status":"Up 8 days","Ports":""}},{{"ID":"a4b5c6d7e8f9","Names":"redis","Image":"redis:7-alpine","State":"running","Status":"Up 8 days","Ports":"6379/tcp"}},{{"ID":"b5c6d7e8f9a0","Names":"sidekiq","Image":"myapp:3.2.1","State":"exited","Status":"Exited (1) 3 hours ago","Ports":""}}]}}
{{"alias":"pve-web-01","timestamp":{},"runtime":"Docker","engine_version":"25.0.3","containers":[{{"ID":"c6d7e8f9a0b1","Names":"nginx","Image":"nginx:1.25","State":"running","Status":"Up 20 days","Ports":"0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp"}},{{"ID":"d7e8f9a0b1c2","Names":"webapp","Image":"internal/webapp:1.8.3","State":"running","Status":"Up 20 days","Ports":"127.0.0.1:3000->3000/tcp"}},{{"ID":"e8f9a0b1c2d3","Names":"celery","Image":"internal/webapp:1.8.3","State":"running","Status":"Up 20 days","Ports":""}}]}}
{{"alias":"aws-api-staging","timestamp":{},"runtime":"Docker","engine_version":"25.0.3","containers":[{{"ID":"f9a0b1c2d3e4","Names":"api","Image":"myteam/api:v4.1.0-rc2","State":"running","Status":"Up 2 days","Ports":"0.0.0.0:8080->8080/tcp"}},{{"ID":"a0b1c2d3e4f5","Names":"nginx","Image":"nginx:1.25-alpine","State":"running","Status":"Up 2 days","Ports":"0.0.0.0:443->443/tcp"}},{{"ID":"b1c2d3e4f5a6","Names":"datadog-agent","Image":"datadog/agent:7","State":"running","Status":"Up 2 days","Ports":""}},{{"ID":"c2d3e4f5a6b7","Names":"redis","Image":"redis:7-alpine","State":"running","Status":"Up 2 days","Ports":"127.0.0.1:6379->6379/tcp"}}]}}
{{"alias":"aws-batch-us","timestamp":{},"runtime":"Docker","engine_version":"25.0.3","containers":[{{"ID":"d3e4f5a6b7c8","Names":"scheduler","Image":"myteam/batch:2.9.0","State":"running","Status":"Up 14 days","Ports":"127.0.0.1:8080->8080/tcp"}},{{"ID":"e4f5a6b7c8d9","Names":"worker-1","Image":"myteam/batch:2.9.0","State":"running","Status":"Up 14 days","Ports":""}},{{"ID":"f5a6b7c8d9e0","Names":"worker-2","Image":"myteam/batch:2.9.0","State":"running","Status":"Up 14 days","Ports":""}},{{"ID":"a6b7c8d9e0f1","Names":"rabbitmq","Image":"rabbitmq:3.13-management","State":"running","Status":"Up 14 days","Ports":"127.0.0.1:5672->5672/tcp, 127.0.0.1:15672->15672/tcp"}},{{"ID":"b7c8d9e0f1a2","Names":"flower","Image":"mher/flower:2.0","State":"running","Status":"Up 14 days","Ports":"127.0.0.1:5555->5555/tcp"}}]}}
{{"alias":"gateway-vpn","timestamp":{},"runtime":"Docker","containers":[{{"ID":"c8d9e0f1a2b3","Names":"wireguard","Image":"linuxserver/wireguard:1.0","State":"running","Status":"Up 45 days","Ports":"0.0.0.0:51820->51820/udp"}},{{"ID":"d9e0f1a2b3c4","Names":"pihole","Image":"pihole/pihole:2024.07","State":"running","Status":"Up 45 days","Ports":"0.0.0.0:53->53/tcp, 0.0.0.0:53->53/udp, 127.0.0.1:8080->80/tcp"}},{{"ID":"e0f1a2b3c4d5","Names":"unbound","Image":"mvance/unbound:1.20","State":"running","Status":"Up 45 days","Ports":"127.0.0.1:5335->5335/tcp"}}]}}
{{"alias":"podman-edge","timestamp":{},"runtime":"Podman","engine_version":"5.8.2","containers":[{{"ID":"a1b2c3d4e5f6","Names":"caddy","Image":"docker.io/library/caddy:2.8-alpine","State":"running","Status":"","Ports":"443->443/tcp"}},{{"ID":"b2c3d4e5f6a7","Names":"podman-api","Image":"docker.io/library/python:3.13-slim","State":"running","Status":"","Ports":"127.0.0.1:8000->8000/tcp"}},{{"ID":"c3d4e5f6a7b8","Names":"valkey","Image":"docker.io/valkey/valkey:8-alpine","State":"running","Status":"","Ports":"127.0.0.1:6379->6379/tcp"}},{{"ID":"d4e5f6a7b8c9","Names":"loki","Image":"docker.io/grafana/loki:3.2","State":"exited","Status":"","Ports":""}}]}}"#,
        ts1, ts2, ts3, ts4, ts5, ts6, ts7, ts8,
    )
}

/// Pre-populate the inspect-detail cache with deterministic synthetic
/// data for every container in the demo cache. Real builds fire SSH
/// `docker inspect` calls; the demo skips that path so the panel
/// renders fully without any network activity.
///
/// The seed varies digest, mounts, compose-project, user and privs by
/// container name so the demo renders a plausibly heterogeneous fleet
/// (db containers get `/var/lib/postgresql/data`, nginx gets
/// `/etc/letsencrypt`, datadog-agent gets `/var/run/docker.sock`).
/// Earlier versions seeded a single uniform record per container which
/// made the stack-restart demo group every container on a host into
/// one fictional project.
fn seed_demo_inspect_cache(app: &mut App) {
    use crate::app::{InspectCacheEntry, LogsCacheEntry};
    use crate::containers::{ContainerInspect, NetworkInfo};

    let now = crate::demo_flag::now_secs();
    let aliases: Vec<(String, Vec<crate::containers::ContainerInfo>)> = app
        .container_cache
        .iter()
        .map(|(a, e)| (a.clone(), e.containers.clone()))
        .collect();
    for (alias, containers) in aliases {
        for c in containers {
            let running = c.state.eq_ignore_ascii_case("running");
            let profile = container_demo_profile(&c.names);
            let optional_str = |s: &'static str| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            };
            // Synthetic deterministic PID derived from the container id so
            // the panel shows different numbers per row.
            let synthetic_pid =
                c.id.bytes()
                    .fold(2000u32, |acc, b| acc.wrapping_add(b as u32 * 7));
            // The demo deliberately surfaces a restart loop on
            // `app-backend` (bastion-ams) and an OOM kill on `sidekiq`
            // (do-web-ams) so the host detail panel's ATTENTION card
            // demonstrates inspect-aggregate signals.
            let demo_oom_killed = c.names == "sidekiq";
            let demo_restart_count = match c.names.as_str() {
                "app-backend" => 14u32,
                _ if running => 0,
                _ => 2,
            };
            // The `loki` container on the podman-edge host is exited
            // with code 137 (SIGKILL / OOM) so the state-glyph fallback
            // path warns even though podman emits an empty Status.
            let demo_exit_code = match c.names.as_str() {
                _ if running => 0,
                "loki" => 137,
                _ => 1,
            };
            let inspect = ContainerInspect {
                exit_code: demo_exit_code,
                oom_killed: demo_oom_killed,
                // Deterministic timestamps so the visual regression
                // golden does not drift with wall-clock. Running
                // containers carry a Started; exited carry both.
                started_at: "2026-04-27T08:00:00Z".to_string(),
                finished_at: if running {
                    String::new()
                } else {
                    "2026-05-07T16:42:00Z".to_string()
                },
                created_at: "2026-04-27T07:59:55Z".to_string(),
                health: if running && profile.has_healthcheck {
                    Some("healthy".to_string())
                } else {
                    None
                },
                restart_count: demo_restart_count,
                command: Some(vec!["/usr/local/bin/entrypoint".to_string()]),
                entrypoint: None,
                env_count: profile.env_count,
                mount_count: profile.mounts.len(),
                // Synthetic network name. The compose-network convention
                // follows `<project>_default`, so reuse the per-container
                // project name to keep the panel coherent.
                networks: vec![NetworkInfo {
                    name: format!(
                        "{}_default",
                        profile
                            .compose_project
                            .as_deref()
                            .unwrap_or(&alias)
                            .replace(['-', '.'], "_")
                    ),
                    ip_address: "172.18.0.5".to_string(),
                }],
                image_digest: Some(synthetic_digest(&c.id)),
                restart_policy: if running {
                    Some("unless-stopped".to_string())
                } else {
                    Some("on-failure".to_string())
                },
                user: Some(profile.user.to_string()),
                privileged: profile.privileged,
                readonly_rootfs: false,
                apparmor_profile: Some("docker-default".to_string()),
                seccomp_profile: Some("default".to_string()),
                cap_add: profile.cap_add.iter().map(|s| s.to_string()).collect(),
                cap_drop: profile.cap_drop.iter().map(|s| s.to_string()).collect(),
                mounts: profile.mounts,
                compose_project: profile.compose_project.clone(),
                compose_service: Some(c.names.clone()),
                pid: if running { Some(synthetic_pid) } else { None },
                stop_signal: None,
                stop_timeout: None,
                image_version: optional_str(profile.image_version),
                image_revision: optional_str(profile.image_revision),
                image_source: optional_str(profile.image_source),
                working_dir: optional_str(profile.working_dir),
                hostname: Some(c.id[..12.min(c.id.len())].to_string()),
                memory_limit: profile.memory_mb.map(|mb| mb * 1024 * 1024),
                cpu_limit_nanos: profile.cpu_cores.map(|c| (c * 1e9) as u64),
                pids_limit: profile.pids_limit,
                log_driver: Some("json-file".to_string()),
                network_mode: Some("bridge".to_string()),
                health_test: if profile.has_healthcheck {
                    Some(vec![
                        "CMD-SHELL".to_string(),
                        "curl -fs http://localhost/healthz || exit 1".to_string(),
                    ])
                } else {
                    None
                },
                health_interval_ns: if profile.has_healthcheck {
                    Some(30_000_000_000)
                } else {
                    None
                },
                health_failing_streak: if profile.has_healthcheck {
                    Some(0)
                } else {
                    None
                },
            };
            app.containers_overview.inspect_cache.entries.insert(
                c.id.clone(),
                InspectCacheEntry {
                    timestamp: now,
                    result: Ok(inspect),
                },
            );
            let log_lines = container_demo_logs(&c.names, running);
            app.containers_overview.logs_cache.entries.insert(
                c.id.clone(),
                LogsCacheEntry {
                    timestamp: now,
                    result: Ok(log_lines),
                },
            );
        }
    }
}

/// Synthetic recent log lines per container profile. Returned in
/// chronological order (oldest first) so the LOGS card's tail-render
/// shows the most recent line at the bottom. Lines are deterministic
/// per service name so visual goldens stay stable.
///
/// Long enough (~15 lines) that a tall LOGS card has content to fill
/// instead of empty padding when the panel grows.
fn container_demo_logs(name: &str, running: bool) -> Vec<String> {
    let stem = name
        .rsplit_once('-')
        .filter(|(_, n)| n.chars().all(|c| c.is_ascii_digit()))
        .map(|(s, _)| s)
        .unwrap_or(name);
    if !running {
        return vec![
            "[2026-05-07 16:41:50] INFO shutdown signal received".to_string(),
            "[2026-05-07 16:41:51] INFO draining 4 active connections".to_string(),
            "[2026-05-07 16:41:55] INFO connection 7f3a closed".to_string(),
            "[2026-05-07 16:41:55] INFO connection 8b1c closed".to_string(),
            "[2026-05-07 16:41:56] INFO connection a4d2 closed".to_string(),
            "[2026-05-07 16:41:56] INFO connection b2e8 closed".to_string(),
            "[2026-05-07 16:41:58] INFO shutting down workers".to_string(),
            "[2026-05-07 16:41:59] INFO worker 1 stopped".to_string(),
            "[2026-05-07 16:41:59] INFO worker 2 stopped".to_string(),
            "[2026-05-07 16:42:00] INFO graceful shutdown complete".to_string(),
            "[2026-05-07 16:42:00] INFO process exited code=1".to_string(),
        ];
    }
    match stem {
        "nginx" | "nginx-proxy" => vec![
            r#"172.18.0.5 - - [27/Apr/2026:07:58:12 +0000] "GET /healthz HTTP/1.1" 200 2"#
                .to_string(),
            r#"172.18.0.5 - - [27/Apr/2026:07:58:42 +0000] "GET /healthz HTTP/1.1" 200 2"#
                .to_string(),
            r#"203.0.113.42 - - [27/Apr/2026:07:59:01 +0000] "GET / HTTP/1.1" 200 4218"#
                .to_string(),
            r#"203.0.113.42 - - [27/Apr/2026:07:59:01 +0000] "GET /assets/main.css HTTP/1.1" 200 8421"#
                .to_string(),
            r#"203.0.113.42 - - [27/Apr/2026:07:59:01 +0000] "GET /assets/main.js HTTP/1.1" 200 124816"#
                .to_string(),
            r#"172.18.0.5 - - [27/Apr/2026:07:59:12 +0000] "GET /healthz HTTP/1.1" 200 2"#
                .to_string(),
            r#"198.51.100.7 - - [27/Apr/2026:07:59:43 +0000] "POST /api/v1/login HTTP/1.1" 200 187"#
                .to_string(),
            r#"198.51.100.7 - - [27/Apr/2026:07:59:44 +0000] "GET /api/v1/users HTTP/1.1" 200 2147"#
                .to_string(),
            r#"172.18.0.5 - - [27/Apr/2026:07:59:42 +0000] "GET /healthz HTTP/1.1" 200 2"#
                .to_string(),
            r#"198.51.100.7 - - [27/Apr/2026:08:00:14 +0000] "GET /api/v1/orders HTTP/1.1" 200 8124"#
                .to_string(),
            r#"172.18.0.5 - - [27/Apr/2026:08:01:12 +0000] "GET /healthz HTTP/1.1" 200 2"#
                .to_string(),
            r#"172.18.0.5 - - [27/Apr/2026:08:01:43 +0000] "GET /api/v1/users HTTP/1.1" 200 2147"#
                .to_string(),
            r#"172.18.0.5 - - [27/Apr/2026:08:02:02 +0000] "POST /api/v1/login HTTP/1.1" 200 187"#
                .to_string(),
            r#"172.18.0.5 - - [27/Apr/2026:08:02:14 +0000] "GET /assets/main.js HTTP/1.1" 304 0"#
                .to_string(),
            r#"172.18.0.5 - - [27/Apr/2026:08:02:31 +0000] "GET /healthz HTTP/1.1" 200 2"#
                .to_string(),
        ],
        "certbot" => vec![
            "Cert not yet due for renewal".to_string(),
            "The following certificates are not due for renewal yet:".to_string(),
            "  /etc/letsencrypt/live/example.com/fullchain.pem expires on 2026-07-19".to_string(),
            "No renewals were attempted.".to_string(),
            "Sleeping until next scheduled run".to_string(),
        ],
        "app-backend" | "app" | "webapp" | "api" => vec![
            "[INFO] worker booted, listening on 0.0.0.0:8080".to_string(),
            "[INFO] connected to postgres at db-primary:5432".to_string(),
            "[INFO] connected to redis at cache:6379".to_string(),
            "[INFO] migrations complete (schema v42)".to_string(),
            r#"[INFO] request_id=4f30 method=GET path=/healthz status=200 duration=1ms"#
                .to_string(),
            r#"[INFO] request_id=4f31 method=GET path=/api/users/42 status=200 duration=12ms"#
                .to_string(),
            r#"[INFO] request_id=4f32 method=GET path=/api/orders status=200 duration=38ms"#
                .to_string(),
            r#"[WARN] request_id=4f33 method=GET path=/api/orders/9999 status=404 duration=4ms"#
                .to_string(),
            r#"[INFO] request_id=4f34 method=POST path=/api/login status=200 duration=22ms"#
                .to_string(),
            r#"[INFO] request_id=4f35 method=GET path=/api/dashboard status=200 duration=64ms"#
                .to_string(),
            r#"[INFO] request_id=4f36 method=GET path=/api/healthz status=200 duration=1ms"#
                .to_string(),
            r#"[INFO] request_id=4f3a method=GET path=/healthz status=200 duration=2ms"#
                .to_string(),
            r#"[INFO] request_id=4f3b method=POST path=/api/users status=201 duration=18ms"#
                .to_string(),
            r#"[INFO] request_id=4f3c method=GET path=/api/orders status=200 duration=42ms"#
                .to_string(),
            r#"[INFO] request_id=4f3d method=GET path=/api/healthz status=200 duration=1ms"#
                .to_string(),
        ],
        "worker" | "celery" | "sidekiq" | "scheduler" | "flower" => vec![
            r#"task=email.send id=8b2c queue=default state=running"#.to_string(),
            r#"task=email.send id=8b2c queue=default state=success duration=312ms"#.to_string(),
            r#"task=billing.charge id=4a91 queue=default state=running"#.to_string(),
            r#"task=billing.charge id=4a91 queue=default state=success duration=518ms"#.to_string(),
            r#"task=metrics.flush id=ff10 queue=metrics state=success duration=4ms"#.to_string(),
        ],
        "redis" => vec![
            "1:M 27 Apr 2026 08:00:01.123 * Ready to accept connections".to_string(),
            "1:M 27 Apr 2026 08:01:14.881 * 1 changes in 3600 seconds. Saving...".to_string(),
            "1:M 27 Apr 2026 08:01:14.882 * Background saving started by pid 39".to_string(),
            "39:C 27 Apr 2026 08:01:14.911 * DB saved on disk".to_string(),
            "1:M 27 Apr 2026 08:01:14.982 * Background saving terminated with success".to_string(),
        ],
        "postgres" | "postgres-primary" => vec![
            "2026-04-27 08:00:14.121 UTC [1] LOG:  starting PostgreSQL 16.4".to_string(),
            "2026-04-27 08:00:14.245 UTC [1] LOG:  listening on IPv4 address \"0.0.0.0\""
                .to_string(),
            "2026-04-27 08:00:14.512 UTC [42] LOG:  database system is ready to accept connections"
                .to_string(),
            "2026-04-27 08:01:00.114 UTC [89] LOG:  checkpoint starting: time".to_string(),
            "2026-04-27 08:01:01.882 UTC [89] LOG:  checkpoint complete: wrote 12 buffers".to_string(),
        ],
        "pgbouncer" => vec![
            "2026-04-27 08:00:00.001 UTC [1] LOG kernel file descriptor limit: 1048576".to_string(),
            "2026-04-27 08:00:00.018 UTC [1] LOG listening on 0.0.0.0:6432".to_string(),
            "2026-04-27 08:01:14.219 UTC [1] LOG C-0xc12: db=app login attempt: user=app db=app"
                .to_string(),
            "2026-04-27 08:01:14.221 UTC [1] LOG C-0xc12: db=app closing because: client close request"
                .to_string(),
            "2026-04-27 08:02:00.001 UTC [1] LOG stats: 12 xacts/s, 24 queries/s, in 14kB out 38kB"
                .to_string(),
        ],
        "prometheus" => vec![
            r#"ts=2026-04-27T08:00:14Z level=info caller=main.go:451 msg="Starting Prometheus""#
                .to_string(),
            r#"ts=2026-04-27T08:00:14Z level=info caller=web.go:526 msg="Start listening for connections" address=0.0.0.0:9090"#
                .to_string(),
            r#"ts=2026-04-27T08:01:00Z level=info caller=head.go:651 msg="Replaying on-disk memory mappable chunks if any""#
                .to_string(),
            r#"ts=2026-04-27T08:01:00Z level=info caller=main.go:1136 msg="Server is ready to receive web requests""#
                .to_string(),
            r#"ts=2026-04-27T08:02:00Z level=info caller=compact.go:518 msg="write block" duration=42ms"#
                .to_string(),
        ],
        "grafana" => vec![
            r#"logger=server t=2026-04-27T08:00:14Z level=info msg="Starting Grafana" version=11.3.0"#
                .to_string(),
            r#"logger=migrator t=2026-04-27T08:00:14Z level=info msg="migrations completed""#
                .to_string(),
            r#"logger=http.server t=2026-04-27T08:00:15Z level=info msg="HTTP Server Listen" address=0.0.0.0:3000"#
                .to_string(),
            r#"logger=context t=2026-04-27T08:01:14Z level=info msg="Request completed" method=GET path=/api/health status=200"#
                .to_string(),
            r#"logger=context t=2026-04-27T08:02:14Z level=info msg="Request completed" method=GET path=/api/health status=200"#
                .to_string(),
        ],
        "rabbitmq" => vec![
            "2026-04-27 08:00:00.001 [info] <0.42.0> Server startup complete".to_string(),
            "2026-04-27 08:00:00.018 [info] <0.42.0> Listening on 0.0.0.0:5672 amqp".to_string(),
            "2026-04-27 08:01:14.882 [info] <0.91.0> connection accepted from 172.18.0.5:54321"
                .to_string(),
            "2026-04-27 08:01:14.901 [info] <0.91.0> connection accepted: user=app vhost=/"
                .to_string(),
            "2026-04-27 08:02:00.001 [info] <0.91.0> consumer handed off to channel 1".to_string(),
        ],
        "datadog-agent" => vec![
            r#"2026-04-27 08:00:00 UTC | CORE | INFO | running on platform: linux"#.to_string(),
            r#"2026-04-27 08:00:01 UTC | CORE | INFO | hostname configured to ip-10-30-0-6"#
                .to_string(),
            r#"2026-04-27 08:01:00 UTC | CORE | INFO | Sent series. payload_size=12834 bytes"#
                .to_string(),
            r#"2026-04-27 08:01:30 UTC | CORE | INFO | Sent metadata payload"#.to_string(),
            r#"2026-04-27 08:02:00 UTC | CORE | INFO | Sent series. payload_size=11240 bytes"#
                .to_string(),
        ],
        "wireguard" => vec![
            "[#] iptables-restore -n".to_string(),
            "[#] wg setconf wg0 /dev/fd/63".to_string(),
            "[#] ip -4 address add 10.13.13.1/24 dev wg0".to_string(),
            "[#] ip link set mtu 1420 up dev wg0".to_string(),
            "Successfully connected to WireGuard interface wg0".to_string(),
        ],
        "pihole" | "unbound" => vec![
            "Apr 27 08:00:01 dnsmasq[1]: started, version 2.90".to_string(),
            "Apr 27 08:00:01 dnsmasq[1]: read /etc/hosts - 6 addresses".to_string(),
            "Apr 27 08:01:14 dnsmasq[1]: query[A] api.example.com from 192.168.1.42".to_string(),
            "Apr 27 08:01:14 dnsmasq[1]: forwarded api.example.com to 1.1.1.1".to_string(),
            "Apr 27 08:01:14 dnsmasq[1]: reply api.example.com is 203.0.113.42".to_string(),
        ],
        "pg-exporter" => vec![
            r#"ts=2026-04-27T08:00:00Z caller=main.go:155 level=info msg="Starting postgres_exporter""#
                .to_string(),
            r#"ts=2026-04-27T08:00:01Z caller=server.go:33 level=info msg="Listening on" address=0.0.0.0:9187"#
                .to_string(),
            r#"ts=2026-04-27T08:01:00Z caller=postgres_exporter.go:1672 level=info msg="Established new database connection""#
                .to_string(),
            r#"ts=2026-04-27T08:01:30Z caller=postgres_exporter.go:1789 level=info msg="Scrape complete" duration=42ms"#
                .to_string(),
            r#"ts=2026-04-27T08:02:00Z caller=postgres_exporter.go:1789 level=info msg="Scrape complete" duration=38ms"#
                .to_string(),
        ],
        _ => vec![
            "service started".to_string(),
            "ready to accept work".to_string(),
            "tick: heartbeat ok".to_string(),
            "tick: heartbeat ok".to_string(),
            "tick: heartbeat ok".to_string(),
        ],
    }
}

/// Per-container demo profile. Bound to the container's name so a
/// nginx instance always renders with `/etc/letsencrypt`, postgres
/// with `/var/lib/postgresql/data` and so on. Stack-grouping uses
/// `compose_project`; containers that share a project on the same
/// host get cycled together by the stack-restart confirm.
struct ContainerDemoProfile {
    compose_project: Option<String>,
    user: &'static str,
    privileged: bool,
    cap_add: &'static [&'static str],
    cap_drop: &'static [&'static str],
    mounts: Vec<crate::containers::MountInfo>,
    env_count: usize,
    image_version: &'static str,
    image_revision: &'static str,
    image_source: &'static str,
    working_dir: &'static str,
    memory_mb: Option<u64>,
    cpu_cores: Option<f64>,
    pids_limit: Option<i64>,
    has_healthcheck: bool,
}

fn container_demo_profile(name: &str) -> ContainerDemoProfile {
    use crate::containers::MountInfo;
    let bind = |source: &str, dest: &str, read_only: bool| MountInfo {
        source: source.to_string(),
        destination: dest.to_string(),
        read_only,
    };
    let volume = |volume_name: &str, dest: &str, read_only: bool| MountInfo {
        source: volume_name.to_string(),
        destination: dest.to_string(),
        read_only,
    };

    // Match on the container's compose-service name (the `Names` field
    // on `docker ps` JSON), trimming any compose-style numeric suffix
    // so `worker-1` and `worker-2` share a profile.
    let stem = name
        .rsplit_once('-')
        .filter(|(_, n)| n.chars().all(|c| c.is_ascii_digit()))
        .map(|(s, _)| s)
        .unwrap_or(name);

    match stem {
        "nginx" | "nginx-proxy" => ContainerDemoProfile {
            compose_project: Some("edge".into()),
            user: "root",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![
                bind("/etc/letsencrypt", "/etc/letsencrypt", false),
                volume("certs", "/etc/nginx/certs", true),
            ],
            env_count: 8,
            image_version: "1.27.3",
            image_revision: "a4f9b22",
            image_source: "github.com/nginxinc/docker-nginx",
            working_dir: "/",
            memory_mb: Some(256),
            cpu_cores: Some(1.0),
            pids_limit: Some(100),
            has_healthcheck: true,
        },
        "certbot" => ContainerDemoProfile {
            compose_project: Some("edge".into()),
            user: "root",
            privileged: false,
            cap_add: &[],
            cap_drop: &[],
            mounts: vec![bind("/etc/letsencrypt", "/etc/letsencrypt", false)],
            env_count: 4,
            image_version: "2.11.0",
            image_revision: "5b3f9e1",
            image_source: "github.com/certbot/certbot",
            working_dir: "/etc/letsencrypt",
            memory_mb: None,
            cpu_cores: None,
            pids_limit: None,
            has_healthcheck: false,
        },
        "app-backend" | "app" | "webapp" | "api" => ContainerDemoProfile {
            compose_project: Some("app".into()),
            user: "app",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![
                bind("/srv/app/data", "/app/data", false),
                bind("/srv/app/config", "/app/config", true),
            ],
            env_count: 16,
            image_version: "3.2.1",
            image_revision: "8c2a15d",
            image_source: "github.com/acme/app",
            working_dir: "/app",
            memory_mb: Some(512),
            cpu_cores: Some(2.0),
            pids_limit: Some(200),
            has_healthcheck: true,
        },
        "worker" | "celery" | "sidekiq" => ContainerDemoProfile {
            compose_project: Some("app".into()),
            user: "app",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![bind("/srv/app/data", "/app/data", false)],
            env_count: 14,
            image_version: "3.2.1",
            image_revision: "8c2a15d",
            image_source: "github.com/acme/app",
            working_dir: "/app",
            memory_mb: Some(256),
            cpu_cores: Some(1.0),
            pids_limit: Some(100),
            has_healthcheck: false,
        },
        "redis" => ContainerDemoProfile {
            compose_project: Some("cache".into()),
            user: "redis",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![volume("redis_data", "/data", false)],
            env_count: 4,
            image_version: "7.4.1",
            image_revision: "f9e2b07",
            image_source: "github.com/redis/docker",
            working_dir: "/data",
            memory_mb: Some(256),
            cpu_cores: Some(0.5),
            pids_limit: Some(100),
            has_healthcheck: true,
        },
        "postgres" | "postgres-primary" => ContainerDemoProfile {
            compose_project: Some("db".into()),
            user: "postgres",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![volume("postgres_data", "/var/lib/postgresql/data", false)],
            env_count: 9,
            image_version: "16.4",
            image_revision: "2d8e7a3",
            image_source: "github.com/docker-library/postgres",
            working_dir: "/var/lib/postgresql",
            memory_mb: Some(1024),
            cpu_cores: Some(2.0),
            pids_limit: Some(200),
            has_healthcheck: true,
        },
        "pgbouncer" => ContainerDemoProfile {
            compose_project: Some("db".into()),
            user: "postgres",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![bind("/etc/pgbouncer", "/etc/pgbouncer", true)],
            env_count: 6,
            image_version: "1.23.1",
            image_revision: "",
            image_source: "github.com/edoburu/docker-pgbouncer",
            working_dir: "/",
            memory_mb: Some(128),
            cpu_cores: Some(0.5),
            pids_limit: Some(50),
            has_healthcheck: false,
        },
        "pg-exporter" => ContainerDemoProfile {
            compose_project: Some("monitoring".into()),
            user: "nobody",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW", "SETUID", "SETGID"],
            mounts: vec![],
            env_count: 3,
            image_version: "0.15.0",
            image_revision: "4a3b8c1",
            image_source: "github.com/prometheus-community/postgres_exporter",
            working_dir: "/",
            memory_mb: None,
            cpu_cores: None,
            pids_limit: None,
            has_healthcheck: false,
        },
        "prometheus" => ContainerDemoProfile {
            compose_project: Some("monitoring".into()),
            user: "nobody",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW", "SETUID", "SETGID"],
            mounts: vec![
                volume("prometheus_data", "/prometheus", false),
                bind("/srv/prometheus", "/etc/prometheus", true),
            ],
            env_count: 5,
            image_version: "2.55.0",
            image_revision: "7e9d3a2",
            image_source: "github.com/prometheus/prometheus",
            working_dir: "/prometheus",
            memory_mb: Some(512),
            cpu_cores: Some(1.0),
            pids_limit: Some(100),
            has_healthcheck: true,
        },
        "grafana" => ContainerDemoProfile {
            compose_project: Some("monitoring".into()),
            user: "grafana",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![
                volume("grafana_data", "/var/lib/grafana", false),
                bind("/srv/grafana", "/etc/grafana", true),
            ],
            env_count: 11,
            image_version: "11.3.0",
            image_revision: "9c1f8e4",
            image_source: "github.com/grafana/grafana",
            working_dir: "/usr/share/grafana",
            memory_mb: Some(512),
            cpu_cores: Some(1.0),
            pids_limit: Some(100),
            has_healthcheck: true,
        },
        "rabbitmq" => ContainerDemoProfile {
            compose_project: Some("batch".into()),
            user: "rabbitmq",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![volume("rabbitmq_data", "/var/lib/rabbitmq", false)],
            env_count: 7,
            image_version: "4.0.4",
            image_revision: "3b6a9d2",
            image_source: "github.com/docker-library/rabbitmq",
            working_dir: "/",
            memory_mb: Some(1024),
            cpu_cores: Some(1.5),
            pids_limit: Some(200),
            has_healthcheck: true,
        },
        "scheduler" | "flower" | "worker-1" | "worker-2" => ContainerDemoProfile {
            compose_project: Some("batch".into()),
            user: "celery",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![bind("/srv/batch", "/app", true)],
            env_count: 12,
            image_version: "5.4.0",
            image_revision: "8c2a15d",
            image_source: "github.com/celery/celery",
            working_dir: "/app",
            memory_mb: Some(256),
            cpu_cores: Some(1.0),
            pids_limit: Some(100),
            has_healthcheck: false,
        },
        "datadog-agent" => ContainerDemoProfile {
            // Agents run as host-network siblings, not as a compose
            // service. Surfacing no project suppresses the stack
            // restart confirm for the agent (Ctrl-K is refused with
            // a toast), which matches real fleet behaviour.
            compose_project: None,
            user: "root",
            privileged: false,
            cap_add: &["SYS_PTRACE"],
            cap_drop: &[],
            mounts: vec![bind("/var/run/docker.sock", "/var/run/docker.sock", true)],
            env_count: 18,
            image_version: "7.58.0",
            image_revision: "b4f1e3c",
            image_source: "github.com/DataDog/datadog-agent",
            working_dir: "/",
            memory_mb: Some(512),
            cpu_cores: Some(0.5),
            pids_limit: Some(100),
            has_healthcheck: true,
        },
        "wireguard" => ContainerDemoProfile {
            compose_project: Some("vpn".into()),
            user: "root",
            privileged: false,
            cap_add: &["NET_ADMIN", "SYS_MODULE"],
            cap_drop: &[],
            mounts: vec![bind("/srv/wireguard", "/config", false)],
            env_count: 5,
            image_version: "1.0.20210914",
            image_revision: "",
            image_source: "github.com/linuxserver/docker-wireguard",
            working_dir: "/",
            memory_mb: None,
            cpu_cores: None,
            pids_limit: None,
            has_healthcheck: false,
        },
        "pihole" | "unbound" => ContainerDemoProfile {
            compose_project: Some("vpn".into()),
            user: "root",
            privileged: false,
            cap_add: &["NET_ADMIN"],
            cap_drop: &[],
            mounts: vec![bind("/srv/dns", "/etc/pihole", false)],
            env_count: 7,
            image_version: "2024.07.0",
            image_revision: "",
            image_source: "github.com/pi-hole/docker-pi-hole",
            working_dir: "/",
            memory_mb: Some(256),
            cpu_cores: Some(0.5),
            pids_limit: None,
            has_healthcheck: true,
        },
        _ => ContainerDemoProfile {
            compose_project: None,
            user: "root",
            privileged: false,
            cap_add: &[],
            cap_drop: &["NET_RAW"],
            mounts: vec![bind("/srv/data", "/data", false)],
            env_count: 6,
            image_version: "",
            image_revision: "",
            image_source: "",
            working_dir: "/",
            memory_mb: None,
            cpu_cores: None,
            pids_limit: None,
            has_healthcheck: false,
        },
    }
}

/// Deterministic synthetic sha256 digest for a container id. Real
/// `docker inspect` returns the actual content-addressable hash; the
/// demo fakes one so the panel renders a digest line that varies per
/// container instead of repeating a single hardcoded constant.
fn synthetic_digest(container_id: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in container_id.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    let half = format!("{:016x}", hash);
    format!("sha256:{}{}", half, half.chars().rev().collect::<String>())
}

pub fn build_demo_app() -> App {
    crate::demo_flag::enable();

    let config = SshConfigFile::from_content(DEMO_SSH_CONFIG, PathBuf::from("/demo/ssh/config"));
    let mut app = App::new(config);
    app.demo_mode = true;

    // History (timestamps relative to now for sparkline visibility)
    app.history = build_demo_history();

    // Provider config — replace disk-loaded config with demo-only providers
    app.providers.config = ProviderConfig::parse(DEMO_PROVIDERS);

    // Sync history (timestamps relative to now)
    app.providers.sync_history = SyncRecord::load_from_content(&build_demo_sync_history());

    // Snippets
    app.snippets.store = SnippetStore::parse(DEMO_SNIPPETS);

    // Container cache (timestamps relative to now)
    app.container_cache = containers::parse_container_cache_content(&build_demo_container_cache());
    seed_demo_inspect_cache(&mut app);
    // One pre-folded host group so a fresh `--demo` boot already
    // showcases the divider's `(N hidden)` summary without the user
    // hunting for the Space binding. Picked `aws-batch-us` because it
    // is mid-list (not the first group) and homogeneous (all running),
    // so the folded summary reads cleanly.
    app.containers_overview
        .collapsed_hosts
        .insert("aws-batch-us".to_string());

    // Ping status (deterministic)
    let reachable = |ms| PingStatus::Reachable { rtt_ms: ms };
    // Ungrouped hosts
    app.ping.status.insert("bastion-ams".into(), reachable(7));
    app.ping.status.insert("gateway-vpn".into(), reachable(11));
    app.ping.status.insert("podman-edge".into(), reachable(28));
    // ProxyJump hosts (normally skipped by pinger, forced reachable for demo)
    app.ping.status.insert("db-primary".into(), reachable(5));
    app.ping.status.insert("monitoring".into(), reachable(8));
    // AWS
    app.ping.status.insert("aws-api-prod".into(), reachable(89));
    app.ping
        .status
        .insert("aws-api-staging".into(), reachable(92));
    app.ping
        .status
        .insert("aws-worker-eu".into(), reachable(23));
    app.ping.status.insert("aws-batch-us".into(), reachable(18));
    app.ping.status.insert("aws-ml-eu".into(), reachable(25));
    app.ping
        .status
        .insert("aws-cache-eu".into(), PingStatus::Unreachable);
    // DigitalOcean
    app.ping.status.insert("do-web-ams".into(), reachable(12));
    app.ping
        .status
        .insert("do-staging-ams".into(), reachable(14));
    app.ping
        .status
        .insert("do-worker-ams".into(), reachable(15));
    app.ping.status.insert("do-ci-runner".into(), reachable(42));
    // Proxmox
    app.ping.status.insert("pve-web-01".into(), reachable(3));
    app.ping.status.insert("pve-web-02".into(), reachable(3));
    app.ping.status.insert("pve-db-01".into(), reachable(2));
    app.ping.status.insert("pve-db-02".into(), reachable(2));
    app.ping.status.insert("pve-redis".into(), reachable(2));
    app.ping.status.insert("pve-mail".into(), reachable(3));
    app.ping.status.insert("pve-monitor".into(), reachable(3));
    app.ping
        .status
        .insert("pve-backup".into(), PingStatus::Unreachable);

    app.ping.has_pinged = true;
    let now = std::time::Instant::now();
    app.ping.checked_at = Some(now);
    for alias in app.ping.status.keys().cloned().collect::<Vec<_>>() {
        app.ping.last_checked.insert(alias, now);
    }

    // Vault SSH cert status (deterministic demo data)
    {
        use crate::vault_ssh::CertStatus;
        let now = std::time::Instant::now();
        // aws-api-prod: valid cert, 6h remaining out of 8h total
        app.vault.cert_cache.insert(
            "aws-api-prod".into(),
            (
                now,
                CertStatus::Valid {
                    expires_at: 0,
                    remaining_secs: 21600,
                    total_secs: 28800,
                },
                None,
            ),
        );
        // aws-worker-eu: valid cert, 45m remaining out of 8h (warning tier)
        app.vault.cert_cache.insert(
            "aws-worker-eu".into(),
            (
                now,
                CertStatus::Valid {
                    expires_at: 0,
                    remaining_secs: 2700,
                    total_secs: 28800,
                },
                None,
            ),
        );
        // aws-batch-us: valid cert, 4h remaining out of 8h
        app.vault.cert_cache.insert(
            "aws-batch-us".into(),
            (
                now,
                CertStatus::Valid {
                    expires_at: 0,
                    remaining_secs: 14400,
                    total_secs: 28800,
                },
                None,
            ),
        );
        // gateway-vpn: valid cert, 7h remaining out of 8h
        app.vault.cert_cache.insert(
            "gateway-vpn".into(),
            (
                now,
                CertStatus::Valid {
                    expires_at: 0,
                    remaining_secs: 25200,
                    total_secs: 28800,
                },
                None,
            ),
        );
        // pve-web-01: valid cert, 3h remaining out of 8h
        app.vault.cert_cache.insert(
            "pve-web-01".into(),
            (
                now,
                CertStatus::Valid {
                    expires_at: 0,
                    remaining_secs: 10800,
                    total_secs: 28800,
                },
                None,
            ),
        );
        // Others left as Missing (Not signed) for variety
    }

    // SSH keys (fake metadata)
    app.keys = vec![
        SshKeyInfo {
            name: "id_ed25519".into(),
            display_path: "~/.ssh/id_ed25519".into(),
            key_type: "ED25519".into(),
            bits: "256".into(),
            fingerprint: "SHA256:dGVzdGRlbW9rZXlmb3JwdXJwbGVzc2g".into(),
            comment: "ops@bastion".into(),
            linked_hosts: vec![
                "bastion-ams".into(),
                "aws-api-prod".into(),
                "aws-api-staging".into(),
            ],
        },
        SshKeyInfo {
            name: "id_rsa".into(),
            display_path: "~/.ssh/id_rsa".into(),
            key_type: "RSA".into(),
            bits: "4096".into(),
            fingerprint: "SHA256:cnNhdGVzdGtleWZvcnB1cnBsZXNzaGRl".into(),
            comment: "deploy@legacy".into(),
            linked_hosts: vec![],
        },
    ];

    // Preferences
    app.hosts_state.view_mode = ViewMode::Compact;
    app.hosts_state.sort_mode = SortMode::MostRecent;
    app.hosts_state.group_by = GroupBy::None;
    app.ping.auto_ping = true;

    // Rebuild display list with sort/group applied
    app.apply_sort();
    app.select_first_host();

    app
}

/// Seed deterministic tunnel-live snapshots for `--demo` and visual
/// regression tests. The detail panel reads these instead of the
/// runtime mpsc state when `App.demo_mode == true`, so the LIVE,
/// CLIENTS and EVENTS cards render byte-stably across runs.
///
/// Currently seeds one host (`bastion-ams`) with a representative
/// active state: a fresh open, two clients, a small history bump.
pub fn seed_tunnel_live_snapshots(app: &mut App) {
    use crate::tunnel_live::{
        ChannelEventKind, ChannelKind, DisplayClient, DisplayEvent, HISTORY_BUCKETS,
        PEER_VIZ_BUCKETS, TunnelLiveSnapshot,
    };

    // Receive-heavy profile: a Postgres replication-like read pattern
    // with bursty tx (queries) and sustained rx (rows). Numbers are
    // bytes-per-second; the renderer scales them for the sparkline.
    let mut rx_history = [0u64; HISTORY_BUCKETS];
    let mut tx_history = [0u64; HISTORY_BUCKETS];
    // Spread the bursts across recent history (right side of the
    // 150-bucket window) so the rendered mountain shows the activity
    // approaching "now" — three peaks at increasing intensity, with
    // quiet gaps between them so decay trails are visible.
    for (i, slot) in rx_history.iter_mut().enumerate() {
        *slot = match i {
            70..=79 => 96_000,
            80..=84 => 256_000,
            85..=89 => 64_000,
            105..=114 => 384_000,
            115..=119 => 192_000,
            135..=139 => 512_000,
            140..=144 => 768_000,
            145..=149 => 384_000,
            _ => 0,
        };
    }
    for (i, slot) in tx_history.iter_mut().enumerate() {
        *slot = match i {
            70..=79 => 6_000,
            80..=84 => 16_000,
            85..=89 => 4_000,
            105..=114 => 24_000,
            115..=119 => 12_000,
            135..=139 => 32_000,
            140..=144 => 48_000,
            145..=149 => 24_000,
            _ => 0,
        };
    }
    let snapshot = TunnelLiveSnapshot {
        uptime_secs: 12 * 60 + 47,
        active_channels: 2,
        peak_concurrent: 7,
        total_opens: 23,
        idle_secs: 4,
        rx_history,
        tx_history,
        current_rx_bps: 768_000,
        current_tx_bps: 48_000,
        peak_rx_bps: 768_000,
        peak_tx_bps: 48_000,
        throughput_ready: true,
        clients: {
            // Synthesize realistic 12-cell histories per client. Cells
            // are ~2s each, so the window covers the last ~24 seconds.
            let psql_history = [
                12_000u64, 16_000, 32_000, 96_000, 128_000, 256_000, 384_000, 512_000, 384_000,
                256_000, 384_000, 512_000,
            ];
            let ssh_history = [
                4_000u64, 8_000, 8_000, 12_000, 8_000, 12_000, 16_000, 12_000, 8_000, 12_000,
                16_000, 24_000,
            ];
            let safari_history = [
                0u64, 0, 4_000, 8_000, 16_000, 24_000, 16_000, 8_000, 4_000, 8_000, 12_000, 32_000,
            ];
            let curl_history = [0u64, 0, 0, 0, 0, 0, 0, 0, 0, 8_000, 96_000, 220_000];
            vec![
                DisplayClient {
                    src: "127.0.0.1:54321".into(),
                    process: "psql".into(),
                    age_secs: 4,
                    pid: 8123,
                    responsible_app: Some("Ghostty".into()),
                    current_rx_bps: 480_000,
                    current_tx_bps: 32_000,
                    viz_history: psql_history,
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:54398".into(),
                    process: "ssh".into(),
                    age_secs: 12,
                    pid: 8200,
                    responsible_app: Some("Ghostty".into()),
                    current_rx_bps: 20_000,
                    current_tx_bps: 4_000,
                    viz_history: ssh_history,
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:54390".into(),
                    process: "WebKit.Networking".into(),
                    age_secs: 38,
                    pid: 8456,
                    responsible_app: Some("Safari".into()),
                    current_rx_bps: 28_000,
                    current_tx_bps: 4_000,
                    viz_history: safari_history,
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:54392".into(),
                    process: "WebKit.Networking".into(),
                    age_secs: 62,
                    pid: 8457,
                    responsible_app: Some("Safari".into()),
                    current_rx_bps: 0,
                    current_tx_bps: 0,
                    viz_history: [0u64; PEER_VIZ_BUCKETS],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:51209".into(),
                    process: "curl".into(),
                    age_secs: 3,
                    pid: 9412,
                    responsible_app: None,
                    current_rx_bps: 220_000,
                    current_tx_bps: 0,
                    viz_history: curl_history,
                    throughput_ready: true,
                },
            ]
        },
        events: vec![
            DisplayEvent {
                age_secs: 4,
                channel_id: 25,
                kind: ChannelEventKind::Open,
                channel_kind: ChannelKind::Dynamic,
                duration_secs: None,
                count: 1,
            },
            DisplayEvent {
                age_secs: 18,
                channel_id: 24,
                kind: ChannelEventKind::Close,
                channel_kind: ChannelKind::Dynamic,
                duration_secs: Some(8),
                count: 1,
            },
            DisplayEvent {
                age_secs: 38,
                channel_id: 23,
                kind: ChannelEventKind::Open,
                channel_kind: ChannelKind::Dynamic,
                duration_secs: None,
                count: 1,
            },
            DisplayEvent {
                age_secs: 47,
                channel_id: 22,
                kind: ChannelEventKind::Close,
                channel_kind: ChannelKind::Dynamic,
                duration_secs: Some(13),
                count: 1,
            },
            DisplayEvent {
                age_secs: 55,
                channel_id: 21,
                kind: ChannelEventKind::Close,
                channel_kind: ChannelKind::Direct,
                duration_secs: Some(40),
                count: 1,
            },
        ],
        // Three channels still open at snapshot time. Combined with the
        // closed events above, the swimlane shows 5 lanes total in the
        // 60-second window: ch#21, ch#22, ch#23, ch#24, ch#25 plus one
        // long-running direct channel (ch#20) that started before the
        // window.
        currently_open: vec![
            (20, 95, ChannelKind::Direct),
            (23, 38, ChannelKind::Dynamic),
            (25, 4, ChannelKind::Dynamic),
        ],
        conflict: None,
        last_exit: None,
    };
    app.tunnels
        .demo_live_snapshots
        .insert("bastion-ams".to_string(), snapshot);

    // db-primary: sustained OLTP workload through a Postgres tunnel.
    // Four concurrent client processes, four open channels, ~47 minutes
    // of uptime — the canonical "this tunnel has been carrying real
    // production traffic for a while" snapshot. Profile contrasts with
    // bastion-ams (which is a fresher, burstier replication-style host).
    app.tunnels.demo_live_snapshots.insert(
        "db-primary".to_string(),
        TunnelLiveSnapshot {
            uptime_secs: 47 * 60 + 12,
            active_channels: 4,
            peak_concurrent: 5,
            total_opens: 38,
            idle_secs: 1,
            rx_history: [0u64; HISTORY_BUCKETS],
            tx_history: [0u64; HISTORY_BUCKETS],
            current_rx_bps: 320_000,
            current_tx_bps: 24_000,
            peak_rx_bps: 540_000,
            peak_tx_bps: 64_000,
            throughput_ready: true,
            clients: vec![
                DisplayClient {
                    src: "127.0.0.1:48201".into(),
                    process: "psql".into(),
                    age_secs: 12,
                    pid: 4421,
                    responsible_app: Some("Ghostty".into()),
                    current_rx_bps: 168_000,
                    current_tx_bps: 12_000,
                    viz_history: [
                        96_000u64, 128_000, 144_000, 160_000, 152_000, 176_000, 168_000, 184_000,
                        160_000, 144_000, 168_000, 168_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:48312".into(),
                    process: "psql".into(),
                    age_secs: 89,
                    pid: 4488,
                    responsible_app: Some("Ghostty".into()),
                    current_rx_bps: 88_000,
                    current_tx_bps: 8_000,
                    viz_history: [
                        72_000u64, 80_000, 96_000, 104_000, 88_000, 96_000, 88_000, 96_000,
                        104_000, 88_000, 80_000, 88_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:48450".into(),
                    process: "pg_dump".into(),
                    age_secs: 142,
                    pid: 4612,
                    responsible_app: None,
                    current_rx_bps: 56_000,
                    current_tx_bps: 2_000,
                    viz_history: [
                        24_000u64, 32_000, 48_000, 64_000, 72_000, 88_000, 96_000, 80_000, 64_000,
                        56_000, 48_000, 56_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:48601".into(),
                    process: "prometheus".into(),
                    age_secs: 305,
                    pid: 4701,
                    responsible_app: None,
                    current_rx_bps: 8_000,
                    current_tx_bps: 2_000,
                    viz_history: [
                        4_000u64, 8_000, 8_000, 8_000, 4_000, 8_000, 8_000, 8_000, 8_000, 8_000,
                        8_000, 8_000,
                    ],
                    throughput_ready: true,
                },
            ],
            events: vec![
                DisplayEvent {
                    age_secs: 12,
                    channel_id: 18,
                    kind: ChannelEventKind::Open,
                    channel_kind: ChannelKind::Direct,
                    duration_secs: None,
                    count: 1,
                },
                DisplayEvent {
                    age_secs: 32,
                    channel_id: 17,
                    kind: ChannelEventKind::Close,
                    channel_kind: ChannelKind::Direct,
                    duration_secs: Some(45),
                    count: 1,
                },
            ],
            currently_open: vec![
                (15, 305, ChannelKind::Direct),
                (16, 142, ChannelKind::Direct),
                (18, 12, ChannelKind::Direct),
                (19, 89, ChannelKind::Direct),
            ],
            conflict: None,
            last_exit: None,
        },
    );

    // pve-redis: bursty cache access from a few short-lived clients.
    // Just-started tunnel (8m), one of the clients still in the
    // "sampling…" warmup window so the renderer exercises the
    // not-yet-throughput-ready branch alongside live ones.
    app.tunnels.demo_live_snapshots.insert(
        "pve-redis".to_string(),
        TunnelLiveSnapshot {
            uptime_secs: 8 * 60 + 33,
            active_channels: 3,
            peak_concurrent: 4,
            total_opens: 14,
            idle_secs: 0,
            rx_history: [0u64; HISTORY_BUCKETS],
            tx_history: [0u64; HISTORY_BUCKETS],
            current_rx_bps: 88_000,
            current_tx_bps: 56_000,
            peak_rx_bps: 256_000,
            peak_tx_bps: 192_000,
            throughput_ready: true,
            clients: vec![
                DisplayClient {
                    src: "127.0.0.1:55102".into(),
                    process: "redis-cli".into(),
                    age_secs: 6,
                    pid: 7821,
                    responsible_app: Some("Ghostty".into()),
                    current_rx_bps: 72_000,
                    current_tx_bps: 48_000,
                    viz_history: [
                        4_000u64, 8_000, 32_000, 96_000, 4_000, 8_000, 64_000, 128_000, 16_000,
                        4_000, 96_000, 120_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:55245".into(),
                    process: "node".into(),
                    age_secs: 24,
                    pid: 7905,
                    responsible_app: None,
                    current_rx_bps: 16_000,
                    current_tx_bps: 8_000,
                    viz_history: [
                        8_000u64, 12_000, 16_000, 24_000, 16_000, 12_000, 16_000, 24_000, 16_000,
                        12_000, 20_000, 24_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:55401".into(),
                    process: "python3".into(),
                    age_secs: 2,
                    pid: 8002,
                    responsible_app: None,
                    current_rx_bps: 0,
                    current_tx_bps: 0,
                    viz_history: [0u64; PEER_VIZ_BUCKETS],
                    throughput_ready: false,
                },
            ],
            events: vec![
                DisplayEvent {
                    age_secs: 2,
                    channel_id: 12,
                    kind: ChannelEventKind::Open,
                    channel_kind: ChannelKind::Direct,
                    duration_secs: None,
                    count: 1,
                },
                DisplayEvent {
                    age_secs: 6,
                    channel_id: 11,
                    kind: ChannelEventKind::Open,
                    channel_kind: ChannelKind::Direct,
                    duration_secs: None,
                    count: 1,
                },
                DisplayEvent {
                    age_secs: 18,
                    channel_id: 9,
                    kind: ChannelEventKind::Close,
                    channel_kind: ChannelKind::Direct,
                    duration_secs: Some(34),
                    count: 1,
                },
            ],
            currently_open: vec![
                (10, 24, ChannelKind::Direct),
                (11, 6, ChannelKind::Direct),
                (12, 2, ChannelKind::Direct),
            ],
            conflict: None,
            last_exit: None,
        },
    );

    // monitoring: a long-running, mostly-idle tunnel. Single grafana
    // dashboard tab keeping a steady ~5 KB/s of websocket chatter. The
    // detail panel exercises the "active but quiet" rendering — bps
    // values muted, single open channel, hours of uptime.
    app.tunnels.demo_live_snapshots.insert(
        "monitoring".to_string(),
        TunnelLiveSnapshot {
            uptime_secs: 2 * 3600 + 14 * 60 + 8,
            active_channels: 1,
            peak_concurrent: 2,
            total_opens: 11,
            idle_secs: 38,
            rx_history: [0u64; HISTORY_BUCKETS],
            tx_history: [0u64; HISTORY_BUCKETS],
            current_rx_bps: 4_800,
            current_tx_bps: 1_200,
            peak_rx_bps: 96_000,
            peak_tx_bps: 24_000,
            throughput_ready: true,
            clients: vec![DisplayClient {
                src: "127.0.0.1:39112".into(),
                process: "Chrome".into(),
                age_secs: 8 * 60 + 12,
                pid: 612,
                responsible_app: Some("Google Chrome".into()),
                current_rx_bps: 4_800,
                current_tx_bps: 1_200,
                viz_history: [
                    3_200u64, 4_800, 4_800, 5_600, 4_800, 4_800, 6_400, 4_800, 4_800, 5_600, 4_800,
                    4_800,
                ],
                throughput_ready: true,
            }],
            events: vec![DisplayEvent {
                age_secs: 8 * 60 + 12,
                channel_id: 7,
                kind: ChannelEventKind::Open,
                channel_kind: ChannelKind::Direct,
                duration_secs: None,
                count: 1,
            }],
            currently_open: vec![(7, (8 * 60 + 12) as u64, ChannelKind::Direct)],
            conflict: None,
            last_exit: None,
        },
    );

    // do-staging-ams: just-opened staging Postgres tunnel. CI just pushed
    // a migration, so the panel exercises the "fresh tunnel + active
    // psql session" combination. Lower throughput than db-primary, fewer
    // clients, no decay trail yet (uptime < 1 channel rotation).
    app.tunnels.demo_live_snapshots.insert(
        "do-staging-ams".to_string(),
        TunnelLiveSnapshot {
            uptime_secs: 5 * 60 + 22,
            active_channels: 2,
            peak_concurrent: 2,
            total_opens: 4,
            idle_secs: 1,
            rx_history: [0u64; HISTORY_BUCKETS],
            tx_history: [0u64; HISTORY_BUCKETS],
            current_rx_bps: 96_000,
            current_tx_bps: 12_000,
            peak_rx_bps: 256_000,
            peak_tx_bps: 32_000,
            throughput_ready: true,
            clients: vec![
                DisplayClient {
                    src: "127.0.0.1:62013".into(),
                    process: "psql".into(),
                    age_secs: 18,
                    pid: 11_204,
                    responsible_app: Some("Ghostty".into()),
                    current_rx_bps: 80_000,
                    current_tx_bps: 10_000,
                    viz_history: [
                        16_000u64, 32_000, 64_000, 128_000, 96_000, 64_000, 96_000, 128_000,
                        80_000, 64_000, 96_000, 80_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:62041".into(),
                    process: "node".into(),
                    age_secs: 92,
                    pid: 11_310,
                    responsible_app: None,
                    current_rx_bps: 16_000,
                    current_tx_bps: 2_000,
                    viz_history: [
                        8_000u64, 12_000, 16_000, 16_000, 12_000, 16_000, 20_000, 16_000, 16_000,
                        12_000, 16_000, 16_000,
                    ],
                    throughput_ready: true,
                },
            ],
            events: vec![
                DisplayEvent {
                    age_secs: 18,
                    channel_id: 4,
                    kind: ChannelEventKind::Open,
                    channel_kind: ChannelKind::Direct,
                    duration_secs: None,
                    count: 1,
                },
                DisplayEvent {
                    age_secs: 92,
                    channel_id: 3,
                    kind: ChannelEventKind::Open,
                    channel_kind: ChannelKind::Direct,
                    duration_secs: None,
                    count: 1,
                },
            ],
            currently_open: vec![(3, 92, ChannelKind::Direct), (4, 18, ChannelKind::Direct)],
            conflict: None,
            last_exit: None,
        },
    );

    // pve-db-01: self-hosted Postgres on Proxmox. Mid-traffic profile —
    // an Elixir/BEAM application server holds a persistent pool while a
    // human is poking around in DataGrip. Showcases mixed long-lived
    // (BEAM) and short-lived (DataGrip) channel patterns.
    app.tunnels.demo_live_snapshots.insert(
        "pve-db-01".to_string(),
        TunnelLiveSnapshot {
            uptime_secs: 22 * 60 + 4,
            active_channels: 3,
            peak_concurrent: 4,
            total_opens: 19,
            idle_secs: 0,
            rx_history: [0u64; HISTORY_BUCKETS],
            tx_history: [0u64; HISTORY_BUCKETS],
            current_rx_bps: 248_000,
            current_tx_bps: 18_000,
            peak_rx_bps: 412_000,
            peak_tx_bps: 36_000,
            throughput_ready: true,
            clients: vec![
                DisplayClient {
                    src: "127.0.0.1:51012".into(),
                    process: "beam.smp".into(),
                    age_secs: 21 * 60 + 48,
                    pid: 5_013,
                    responsible_app: None,
                    current_rx_bps: 168_000,
                    current_tx_bps: 12_000,
                    viz_history: [
                        140_000u64, 152_000, 168_000, 144_000, 160_000, 172_000, 168_000, 156_000,
                        168_000, 160_000, 168_000, 168_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:51208".into(),
                    process: "datagrip".into(),
                    age_secs: 14,
                    pid: 5_904,
                    responsible_app: Some("DataGrip".into()),
                    current_rx_bps: 64_000,
                    current_tx_bps: 4_000,
                    viz_history: [
                        4_000u64, 8_000, 16_000, 96_000, 128_000, 64_000, 32_000, 48_000, 96_000,
                        64_000, 48_000, 64_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:51310".into(),
                    process: "psql".into(),
                    age_secs: 47,
                    pid: 6_001,
                    responsible_app: Some("Ghostty".into()),
                    current_rx_bps: 16_000,
                    current_tx_bps: 2_000,
                    viz_history: [
                        8_000u64, 12_000, 16_000, 16_000, 12_000, 16_000, 16_000, 12_000, 16_000,
                        16_000, 12_000, 16_000,
                    ],
                    throughput_ready: true,
                },
            ],
            events: vec![
                DisplayEvent {
                    age_secs: 14,
                    channel_id: 31,
                    kind: ChannelEventKind::Open,
                    channel_kind: ChannelKind::Direct,
                    duration_secs: None,
                    count: 1,
                },
                DisplayEvent {
                    age_secs: 28,
                    channel_id: 30,
                    kind: ChannelEventKind::Close,
                    channel_kind: ChannelKind::Direct,
                    duration_secs: Some(74),
                    count: 1,
                },
            ],
            currently_open: vec![
                (29, 21 * 60 + 48, ChannelKind::Direct),
                (31, 14, ChannelKind::Direct),
                (32, 47, ChannelKind::Direct),
            ],
            conflict: None,
            last_exit: None,
        },
    );

    // pve-monitor: Grafana + Prometheus combo. Two browser dashboards
    // pulling websocket updates plus a remote Prometheus scraper hitting
    // the federation endpoint every 15s. Demonstrates a forward used by
    // multiple humans simultaneously, with periodic spikes when panels
    // refresh. Both directives (3000, 9090) share this one snapshot.
    app.tunnels.demo_live_snapshots.insert(
        "pve-monitor".to_string(),
        TunnelLiveSnapshot {
            uptime_secs: 18 * 60 + 41,
            active_channels: 3,
            peak_concurrent: 3,
            total_opens: 24,
            idle_secs: 2,
            rx_history: [0u64; HISTORY_BUCKETS],
            tx_history: [0u64; HISTORY_BUCKETS],
            current_rx_bps: 56_000,
            current_tx_bps: 8_000,
            peak_rx_bps: 192_000,
            peak_tx_bps: 24_000,
            throughput_ready: true,
            clients: vec![
                DisplayClient {
                    src: "127.0.0.1:43210".into(),
                    process: "Chrome".into(),
                    age_secs: 12 * 60 + 4,
                    pid: 3_311,
                    responsible_app: Some("Google Chrome".into()),
                    current_rx_bps: 32_000,
                    current_tx_bps: 4_000,
                    viz_history: [
                        12_000u64, 16_000, 96_000, 32_000, 16_000, 24_000, 128_000, 32_000, 16_000,
                        24_000, 96_000, 32_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:43298".into(),
                    process: "Chrome".into(),
                    age_secs: 4 * 60 + 18,
                    pid: 3_312,
                    responsible_app: Some("Google Chrome".into()),
                    current_rx_bps: 16_000,
                    current_tx_bps: 2_000,
                    viz_history: [
                        8_000u64, 12_000, 64_000, 16_000, 12_000, 16_000, 96_000, 16_000, 12_000,
                        16_000, 64_000, 16_000,
                    ],
                    throughput_ready: true,
                },
                DisplayClient {
                    src: "127.0.0.1:43501".into(),
                    process: "prometheus".into(),
                    age_secs: 18 * 60 + 11,
                    pid: 3_888,
                    responsible_app: None,
                    current_rx_bps: 8_000,
                    current_tx_bps: 2_000,
                    viz_history: [
                        4_000u64, 4_000, 24_000, 4_000, 4_000, 4_000, 24_000, 4_000, 4_000, 4_000,
                        24_000, 4_000,
                    ],
                    throughput_ready: true,
                },
            ],
            events: vec![DisplayEvent {
                age_secs: 4 * 60 + 18,
                channel_id: 22,
                kind: ChannelEventKind::Open,
                channel_kind: ChannelKind::Direct,
                duration_secs: None,
                count: 1,
            }],
            currently_open: vec![
                (20, 18 * 60 + 11, ChannelKind::Direct),
                (21, 12 * 60 + 4, ChannelKind::Direct),
                (22, 4 * 60 + 18, ChannelKind::Direct),
            ],
            conflict: None,
            last_exit: None,
        },
    );
}

/// Seed the upgrade toast so `--demo` always demonstrates the what's new flow.
/// Kept out of `build_demo_app` so visual regression tests get a stable baseline.
pub fn seed_whats_new_toast(app: &mut App) {
    let version = env!("CARGO_PKG_VERSION");
    app.status_center.toast = Some(crate::app::StatusMessage {
        text: crate::messages::whats_new_toast::upgraded(version),
        class: crate::app::MessageClass::Success,
        tick_count: 0,
        sticky: true,
        created_at: std::time::Instant::now(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    /// Serialise all demo tests so the global `DEMO_MODE` AtomicBool never
    /// leaks into a concurrent test that exercises disk-write paths.
    static DEMO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that holds the serialisation lock and resets the global demo
    /// flag on drop (including panics). The MutexGuard is held (not read) to
    /// keep the lock alive for the duration of the test.
    struct DemoGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Drop for DemoGuard {
        fn drop(&mut self) {
            crate::demo_flag::disable();
        }
    }

    /// Build demo app with serialisation lock + RAII guard to reset global flag.
    fn demo_app() -> (App, DemoGuard) {
        let lock = DEMO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let app = build_demo_app();
        (app, DemoGuard(lock))
    }

    #[test]
    fn demo_app_has_expected_hosts() {
        let (app, _guard) = demo_app();
        // 22 original + 2 do-personal + 1 podman-edge + 1 db-proton = 26
        assert_eq!(app.hosts_state.list.len(), 26);
    }

    #[test]
    fn demo_app_has_providers() {
        let (app, _guard) = demo_app();
        // aws + digitalocean:work + digitalocean:personal + proxmox = 4
        assert_eq!(app.providers.config.configured_providers().len(), 4);
    }

    #[test]
    fn demo_app_has_history() {
        let (app, _guard) = demo_app();
        assert_eq!(app.history.entries.len(), 23);
    }

    #[test]
    fn demo_app_has_snippets() {
        let (app, _guard) = demo_app();
        assert_eq!(app.snippets.store.snippets.len(), 5);
    }

    #[test]
    fn demo_app_has_containers() {
        let (app, _guard) = demo_app();
        assert_eq!(app.container_cache.len(), 8);
        assert!(app.container_cache.contains_key("bastion-ams"));
        assert!(app.container_cache.contains_key("db-primary"));
        assert!(app.container_cache.contains_key("do-web-ams"));
        assert!(app.container_cache.contains_key("pve-web-01"));
        assert!(app.container_cache.contains_key("aws-api-staging"));
        assert!(app.container_cache.contains_key("aws-batch-us"));
        assert!(app.container_cache.contains_key("gateway-vpn"));
        assert!(app.container_cache.contains_key("podman-edge"));
        assert_eq!(
            app.container_cache["podman-edge"].runtime,
            crate::containers::ContainerRuntime::Podman
        );
    }

    #[test]
    fn demo_app_has_ping_status() {
        let (app, _guard) = demo_app();
        assert!(app.ping.has_pinged);
        assert!(app.ping.checked_at.is_some());
        assert_eq!(
            app.ping.status.get("bastion-ams"),
            Some(&PingStatus::Reachable { rtt_ms: 7 })
        );
        assert_eq!(
            app.ping.status.get("aws-cache-eu"),
            Some(&PingStatus::Unreachable)
        );
        assert_eq!(
            app.ping.status.get("pve-backup"),
            Some(&PingStatus::Unreachable)
        );
        assert_eq!(
            app.ping.status.get("monitoring"),
            Some(&PingStatus::Reachable { rtt_ms: 8 })
        );
    }

    #[test]
    fn demo_app_has_keys() {
        let (app, _guard) = demo_app();
        assert_eq!(app.keys.len(), 2);
    }

    #[test]
    fn demo_app_has_sync_history() {
        let (app, _guard) = demo_app();
        assert_eq!(app.providers.sync_history.len(), 3);
    }

    #[test]
    fn demo_mode_flag_is_set() {
        let (app, _guard) = demo_app();
        assert!(app.demo_mode);
    }

    #[test]
    fn demo_app_has_vault_ssh_config() {
        let (app, _guard) = demo_app();
        // Two providers have vault_role (inheritance for their hosts).
        let aws = app.providers.config.section("aws").expect("aws section");
        assert!(
            !aws.vault_role.is_empty(),
            "aws provider should have vault_role set"
        );
        let pve = app
            .providers
            .config
            .section("proxmox")
            .expect("proxmox section");
        assert!(
            !pve.vault_role.is_empty(),
            "proxmox provider should have vault_role set"
        );
        assert!(
            !pve.vault_addr.is_empty(),
            "proxmox provider should have vault_addr set"
        );
        // At least one host has a per-host vault_ssh override.
        let override_host = app
            .hosts_state
            .list
            .iter()
            .find(|h| h.vault_ssh.as_deref().is_some_and(|s| !s.is_empty()));
        assert!(
            override_host.is_some(),
            "demo should have a host with a vault_ssh override"
        );
    }

    #[test]
    fn demo_app_has_stale_hosts() {
        let (app, _guard) = demo_app();
        let cache = app
            .hosts_state
            .list
            .iter()
            .find(|h| h.alias == "aws-cache-eu");
        assert!(cache.is_some());
        assert!(cache.unwrap().stale.is_some());
        let backup = app
            .hosts_state
            .list
            .iter()
            .find(|h| h.alias == "pve-backup");
        assert!(backup.is_some());
        assert!(backup.unwrap().stale.is_some());
    }

    #[test]
    fn demo_sorted_provider_names() {
        let (app, _guard) = demo_app();
        let names = app.sorted_provider_names();
        // First 3 should be our configured providers (with sync history)
        let configured: Vec<&str> = names.iter().take(3).map(|s| s.as_str()).collect();
        assert!(
            configured.contains(&"aws"),
            "aws missing from top 3: {:?}",
            configured
        );
        assert!(
            configured.contains(&"digitalocean"),
            "digitalocean missing from top 3: {:?}",
            configured
        );
        assert!(
            configured.contains(&"proxmox"),
            "proxmox missing from top 3: {:?}",
            configured
        );
        // No other provider should have a checkmark (be configured)
        for name in &names[3..] {
            assert!(
                app.providers.config.section(name).is_none(),
                "unexpected configured provider: {}",
                name
            );
        }
    }

    #[test]
    fn demo_app_has_correct_preferences() {
        let (app, _guard) = demo_app();
        assert_eq!(app.hosts_state.view_mode, ViewMode::Compact);
        assert_eq!(app.hosts_state.sort_mode, SortMode::MostRecent);
        assert_eq!(app.hosts_state.group_by, GroupBy::None);
        assert!(app.ping.auto_ping);
        assert!(!app.hosts_state.display_list.is_empty());
    }
}
