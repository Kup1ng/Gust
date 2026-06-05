//! Linux NAT runtime: preflight checks, rule installation, layered cleanup,
//! and counter-based status reporting.

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use crate::config::Config;
use crate::netopt::split_host_port;
use crate::runtime::Shutdown;
use crate::signals;

use super::nftables::{self, NatRule};
use super::status;

const IPV4_FWD: &str = "/proc/sys/net/ipv4/ip_forward";

/// Run NAT mode to completion.
pub async fn run(cfg: Config) -> ExitCode {
    // 1. Preflight: nft present and we can program netfilter.
    if let Err(e) = nftables::ensure_available() {
        tracing::error!("{e}");
        return ExitCode::from(1);
    }
    if !has_net_admin() {
        tracing::error!(
            "NAT mode needs root or CAP_NET_ADMIN. Run as root, or grant the unit \
             AmbientCapabilities=CAP_NET_ADMIN."
        );
        return ExitCode::from(1);
    }

    // 2. Resolve destinations into concrete DNAT rules.
    let rules = match build_rules(&cfg).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(2);
        }
    };

    // 3. Ensure ip_forward (fail fast unless --set-ip-forward).
    let restore_fwd = match ensure_ip_forward(cfg.set_ip_forward) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(1);
        }
    };

    // 4. Startup pre-clean — wipe any stale table from a crashed prior run.
    nftables::delete_table("ip");
    nftables::delete_table("ip6");

    // 5. Install atomically.
    let ruleset = nftables::build_ruleset(&rules);
    tracing::debug!("installing nftables ruleset:\n{ruleset}");
    if let Err(e) = nftables::apply(&ruleset) {
        tracing::error!(error = %e, "failed to install NAT rules");
        if let Some(prev) = restore_fwd {
            let _ = write_ip_forward(prev);
        }
        return ExitCode::from(1);
    }

    // Arm the cleanup guard immediately after apply succeeds. Its Drop is the
    // backstop; the explicit cleanup on shutdown is the primary path.
    let mut state = NatState {
        armed: true,
        restore_fwd,
    };

    tracing::info!(rules = rules.len(), "NAT rules installed");
    for r in &rules {
        tracing::info!(
            "  {} dport {} -> {}:{}",
            proto_name(r),
            r.dport,
            r.dest_ip,
            r.dest_port
        );
    }

    // 6. Signals + heartbeat (status from kernel counters, not userspace conns).
    let shutdown = Shutdown::new();
    signals::install(shutdown.clone(), dump_status);
    spawn_heartbeat(cfg.heartbeat, shutdown.clone());

    tracing::info!("NAT mode active; press Ctrl-C to stop");
    shutdown.cancelled().await;

    tracing::info!("shutting down; removing NAT rules");
    state.cleanup();
    ExitCode::SUCCESS
}

fn proto_name(r: &NatRule) -> &'static str {
    r.proto.as_str()
}

async fn build_rules(cfg: &Config) -> Result<Vec<NatRule>, String> {
    let mut rules = Vec::with_capacity(cfg.listeners.len());
    for l in &cfg.listeners {
        if l.targets.len() != 1 {
            return Err(format!(
                "NAT mode requires exactly one destination per -L; `{}` has {} \
                 (round-robin DNAT is not supported in NAT mode)",
                l.name,
                l.targets.len()
            ));
        }
        let (host, port) = split_host_port(&l.targets[0]).map_err(|e| e.to_string())?;
        let ip = resolve_ip(&host)
            .await
            .map_err(|e| format!("NAT target `{host}` could not be resolved to an IP: {e}"))?;
        let comment = format!("gust:{}:{}->{}:{}", l.proto.as_str(), l.port, ip, port);
        rules.push(NatRule {
            proto: l.proto,
            dport: l.port,
            dest_ip: ip,
            dest_port: port,
            comment,
        });
    }
    Ok(rules)
}

/// Resolve a host to a single IP, preferring IPv4 (DNAT targets must be literal).
async fn resolve_ip(host: &str) -> std::io::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let mut fallback: Option<IpAddr> = None;
    for sa in tokio::net::lookup_host((host, 0)).await? {
        match sa.ip() {
            v4 @ IpAddr::V4(_) => return Ok(v4),
            v6 => fallback = Some(v6),
        }
    }
    fallback.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address found"))
}

/// Returns `Some(previous_value)` if we changed `ip_forward` and must restore it.
fn ensure_ip_forward(set: bool) -> Result<Option<bool>, String> {
    let cur = read_ip_forward().map_err(|e| format!("cannot read {IPV4_FWD}: {e}"))?;
    if cur {
        return Ok(None);
    }
    if !set {
        return Err(
            "net.ipv4.ip_forward is 0, but NAT forwarding to a remote backend needs it set to 1.\n  \
             Persistent fix:  echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-gust.conf && sudo sysctl --system\n  \
             Or pass --set-ip-forward to have gust set it for this run (restored on exit)."
                .to_string(),
        );
    }
    write_ip_forward(true).map_err(|e| format!("cannot set {IPV4_FWD}=1: {e}"))?;
    tracing::info!("set net.ipv4.ip_forward=1 (will restore to 0 on graceful exit)");
    Ok(Some(false))
}

fn read_ip_forward() -> std::io::Result<bool> {
    Ok(std::fs::read_to_string(IPV4_FWD)?.trim() == "1")
}

fn write_ip_forward(v: bool) -> std::io::Result<()> {
    std::fs::write(IPV4_FWD, if v { "1\n" } else { "0\n" })
}

/// True if we hold CAP_NET_ADMIN (root, or the effective-capabilities bit).
fn has_net_admin() -> bool {
    // Safety: geteuid is always safe.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    const CAP_NET_ADMIN: u32 = 12;
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:") {
                if let Ok(bits) = u64::from_str_radix(hex.trim(), 16) {
                    return (bits >> CAP_NET_ADMIN) & 1 == 1;
                }
            }
        }
    }
    false
}

fn dump_status() {
    match nftables::list_json() {
        Some(json) => {
            let stats = status::parse_counters(&json);
            tracing::info!("--- NAT status ({} tunnels) ---", stats.len());
            for s in &stats {
                tracing::info!("{} packets={} bytes={}", s.comment, s.packets, s.bytes);
            }
        }
        None => tracing::warn!("NAT status unavailable (table missing or nft error)"),
    }
}

fn spawn_heartbeat(interval: Duration, shutdown: Shutdown) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
            if shutdown.is_triggered() {
                break;
            }
            match nftables::list_json() {
                Some(json) => {
                    let stats = status::parse_counters(&json);
                    let packets: u64 = stats.iter().map(|s| s.packets).sum();
                    let bytes: u64 = stats.iter().map(|s| s.bytes).sum();
                    tracing::info!(
                        "heartbeat(nat): tunnels={} packets={packets} bytes={bytes}",
                        stats.len()
                    );
                }
                None => tracing::warn!("heartbeat(nat): table missing"),
            }
        }
    });
}

/// Cleanup guard. `cleanup` is idempotent and runs both on the explicit
/// shutdown path and via `Drop` (the backstop for early returns / unwind).
struct NatState {
    armed: bool,
    restore_fwd: Option<bool>,
}

impl NatState {
    fn cleanup(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        nftables::delete_table("ip");
        nftables::delete_table("ip6");
        if let Some(prev) = self.restore_fwd.take() {
            match write_ip_forward(prev) {
                Ok(()) => tracing::info!(value = prev as u8, "restored net.ipv4.ip_forward"),
                Err(e) => tracing::warn!(error = %e, "failed to restore ip_forward"),
            }
        }
    }
}

impl Drop for NatState {
    fn drop(&mut self) {
        self.cleanup();
    }
}
