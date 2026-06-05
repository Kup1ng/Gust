//! nftables ruleset generation and the thin `nft` shell-out layer.
//!
//! We own a dedicated table (`table <family> gust`) so the entire ruleset can be
//! installed and removed atomically without touching any other tooling's rules.
//! All rules go in via a single `nft -f -` (one kernel netlink transaction).

use std::io::{self, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};

use crate::config::Protocol;

/// The dedicated table name we create and delete in both families.
pub const TABLE: &str = "gust";

/// One DNAT rule: `<proto> dport <dport>` is rewritten to `<dest>`.
#[derive(Debug, Clone)]
pub struct NatRule {
    pub proto: Protocol,
    pub dport: u16,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub comment: String,
}

/// Outcome of an `nft` invocation.
pub struct NftOutcome {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

fn run_nft(args: &[&str], input: Option<&str>) -> io::Result<NftOutcome> {
    let mut cmd = Command::new("nft");
    cmd.args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to run `nft` (is the nftables package installed?): {e}"),
        )
    })?;

    if let Some(inp) = input {
        // Take and drop stdin after writing so the child sees EOF.
        child
            .stdin
            .take()
            .expect("stdin piped")
            .write_all(inp.as_bytes())?;
    }

    let out = child.wait_with_output()?;
    Ok(NftOutcome {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Verify the `nft` binary is usable.
pub fn ensure_available() -> io::Result<()> {
    let out = run_nft(&["--version"], None)?;
    if out.success {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "`nft --version` failed: {}",
            out.stderr.trim()
        )))
    }
}

/// Build the full ruleset text for the given rules, emitting an `ip` and/or
/// `ip6` table depending on which address families appear.
pub fn build_ruleset(rules: &[NatRule]) -> String {
    let v4: Vec<&NatRule> = rules.iter().filter(|r| r.dest_ip.is_ipv4()).collect();
    let v6: Vec<&NatRule> = rules.iter().filter(|r| r.dest_ip.is_ipv6()).collect();

    let mut s = String::new();
    if !v4.is_empty() {
        s.push_str(&build_table("ip", &v4));
    }
    if !v6.is_empty() {
        s.push_str(&build_table("ip6", &v6));
    }
    s
}

fn build_table(family: &str, rules: &[&NatRule]) -> String {
    let mut s = String::new();
    s.push_str(&format!("table {family} {TABLE} {{\n"));
    s.push_str("    chain prerouting {\n");
    s.push_str("        type nat hook prerouting priority dstnat; policy accept;\n");
    for r in rules {
        s.push_str(&format!(
            "        {} dport {} counter comment \"{}\" dnat to {}\n",
            proto_str(r.proto),
            r.dport,
            r.comment,
            format_dest(r.dest_ip, r.dest_port),
        ));
    }
    s.push_str("    }\n");
    s.push_str("    chain postrouting {\n");
    s.push_str("        type nat hook postrouting priority srcnat; policy accept;\n");
    // Masquerade ONLY connections we DNAT'd, so return traffic from the remote
    // backend routes back through this host. fully-random reduces source-port
    // insertion races under high connection counts.
    s.push_str("        ct status dnat counter masquerade fully-random\n");
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

fn proto_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn format_dest(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Apply a ruleset atomically via `nft -f -`.
pub fn apply(ruleset: &str) -> io::Result<()> {
    let out = run_nft(&["-f", "-"], Some(ruleset))?;
    if out.success {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "nft apply failed: {}",
            out.stderr.trim()
        )))
    }
}

/// Delete our table in one family. Never errors on "not found" — this is the
/// idempotent cleanup primitive used on startup and shutdown.
pub fn delete_table(family: &str) {
    match run_nft(&["delete", "table", family, TABLE], None) {
        Ok(out) if out.success => {
            tracing::debug!(family, "deleted nftables table");
        }
        Ok(out) => {
            let e = out.stderr.to_lowercase();
            if e.contains("no such file") || e.contains("does not exist") {
                tracing::debug!(family, "nftables table already absent");
            } else {
                tracing::warn!(family, error = %out.stderr.trim(), "nft delete table returned an error");
            }
        }
        Err(e) => {
            tracing::warn!(family, error = %e, "could not run nft to delete table");
        }
    }
}

/// Fetch the `ip gust` table as JSON for counter reporting. Returns the JSON
/// string, or `None` if the table is absent / nft is unavailable.
pub fn list_json() -> Option<String> {
    match run_nft(&["-j", "list", "table", "ip", TABLE], None) {
        Ok(out) if out.success => Some(out.stdout),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn rule(port: u16, ip: [u8; 4], dport: u16) -> NatRule {
        let ip = IpAddr::V4(Ipv4Addr::from(ip));
        NatRule {
            proto: Protocol::Tcp,
            dport: port,
            dest_ip: ip,
            dest_port: dport,
            comment: format!("gust:tcp:{port}->{ip}:{dport}"),
        }
    }

    #[test]
    fn ruleset_contains_dnat_and_masquerade() {
        let rules = vec![rule(8080, [1, 2, 3, 4], 443)];
        let s = build_ruleset(&rules);
        assert!(s.contains("table ip gust"));
        assert!(s.contains("type nat hook prerouting priority dstnat"));
        assert!(s.contains(
            "tcp dport 8080 counter comment \"gust:tcp:8080->1.2.3.4:443\" dnat to 1.2.3.4:443"
        ));
        assert!(s.contains("ct status dnat counter masquerade fully-random"));
        assert!(!s.contains("table ip6 gust"));
    }

    #[test]
    fn ruleset_emits_ip6_when_needed() {
        let mut rules = vec![rule(8080, [1, 2, 3, 4], 443)];
        rules.push(NatRule {
            proto: Protocol::Udp,
            dport: 5353,
            dest_ip: "2001:db8::1".parse().unwrap(),
            dest_port: 53,
            comment: "gust:udp:5353->[2001:db8::1]:53".to_string(),
        });
        let s = build_ruleset(&rules);
        assert!(s.contains("table ip gust"));
        assert!(s.contains("table ip6 gust"));
        assert!(s.contains("udp dport 5353 counter comment \"gust:udp:5353->[2001:db8::1]:53\" dnat to [2001:db8::1]:53"));
    }
}
