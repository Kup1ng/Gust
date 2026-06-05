//! The validated runtime configuration, built from parsed CLI flags.
//!
//! This module performs all *pure* cross-rule validation (no syscalls), so it is
//! fully unit-testable. Environment checks that require the OS (nft present,
//! `ip_forward`, capabilities) are done at startup in `main`/`nat`.

use std::time::Duration;

use crate::cli::RawArgs;
use crate::netopt::SockOpts;
use crate::node::parse_node;

/// Forwarding transport for a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// One `-L` rule.
#[derive(Debug, Clone)]
pub struct ListenerSpec {
    pub proto: Protocol,
    /// Normalized bind address (e.g. `0.0.0.0:8080`), resolvable by the socket layer.
    pub bind: String,
    pub port: u16,
    /// Destination(s); round-robined when more than one. Resolved at dial time.
    pub targets: Vec<String>,
    /// Whether `?nodelay` was requested (TCP_NODELAY is on by default regardless).
    pub nodelay: bool,
    /// Stable display name used in logs and stats, e.g. `tcp://:8080`.
    pub name: String,
}

/// One `-F` SOCKS5 hop.
#[derive(Debug, Clone)]
pub struct ChainHop {
    pub addr: String,
    pub user: Option<String>,
    pub pass: Option<String>,
}

/// Whether listeners run in userspace or are programmed as in-kernel DNAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Userspace,
    Nat,
}

/// The fully validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub listeners: Vec<ListenerSpec>,
    /// SOCKS5 chain; empty means a direct dial.
    pub chain: Vec<ChainHop>,
    pub mode: Mode,
    /// `SO_MARK` for outbound sockets, if `-M` was given.
    pub mark: Option<u32>,
    pub set_ip_forward: bool,
    /// Relay buffer size per direction, in bytes.
    pub buf_size: usize,
    pub heartbeat: Duration,
    pub debug: bool,
    /// Tokio worker thread count. `None` = one per available CPU (affinity-aware).
    pub worker_threads: Option<usize>,
    /// Socket tuning for accepted and dialed TCP sockets.
    pub sock: SockOpts,
}

const MIN_BUF_KB: usize = 1;
const MAX_BUF_KB: usize = 1024;

/// Build and validate a [`Config`] from parsed flags. All errors are
/// operator-facing strings.
pub fn build_config(raw: RawArgs) -> Result<Config, String> {
    if raw.listens.is_empty() {
        return Err(
            "no listeners: at least one -L is required (e.g. -L=tcp://:8080/1.2.3.4:9090)"
                .to_string(),
        );
    }

    // --- Listeners ---
    let mut listeners = Vec::with_capacity(raw.listens.len());
    for ls in &raw.listens {
        let node = parse_node(ls)?;
        let proto = match node.scheme.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => {
                return Err(format!(
                    "-L `{ls}`: unsupported scheme `{other}` (only tcp:// and udp:// are supported)"
                ))
            }
        };
        let bind = node
            .bind_string()
            .ok_or_else(|| format!("-L `{ls}`: missing listen port"))?;
        let port = node.port.expect("bind_string implies a port");
        let targets = node.targets();
        if targets.is_empty() {
            return Err(format!(
                "-L `{ls}`: forwarding requires a destination, e.g. {}://:{port}/HOST:PORT",
                proto.as_str()
            ));
        }
        for t in &targets {
            validate_hostport(t).map_err(|e| format!("-L `{ls}` target `{t}`: {e}"))?;
        }
        let nodelay = node
            .query
            .get("nodelay")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(false);
        let name = match node.host.is_empty() {
            true => format!("{}://:{}", proto.as_str(), port),
            false => format!("{}://{}:{}", proto.as_str(), node.host, port),
        };
        listeners.push(ListenerSpec {
            proto,
            bind,
            port,
            targets,
            nodelay,
            name,
        });
    }

    // --- Chain hops ---
    let mut chain = Vec::with_capacity(raw.forwards.len());
    for fwd in &raw.forwards {
        let node = parse_node(fwd)?;
        if node.scheme != "socks5" {
            return Err(format!(
                "-F `{fwd}`: only socks5:// hops are supported (got `{}://`)",
                node.scheme
            ));
        }
        let addr = node
            .authority()
            .ok_or_else(|| format!("-F `{fwd}`: missing host:port"))?;
        validate_hostport(&addr).map_err(|e| format!("-F `{fwd}`: {e}"))?;
        chain.push(ChainHop {
            addr,
            user: node.user.clone(),
            pass: node.pass.clone(),
        });
    }

    let mode = if raw.nat { Mode::Nat } else { Mode::Userspace };

    // --- Cross-rule validation ---
    if mode == Mode::Nat && !chain.is_empty() {
        return Err(
            "--nat cannot be combined with -F: kernel DNAT cannot speak SOCKS5. \
             Use a separate process for SOCKS5-chained listeners."
                .to_string(),
        );
    }
    if !chain.is_empty() {
        if let Some(l) = listeners.iter().find(|l| l.proto == Protocol::Udp) {
            return Err(format!(
                "UDP forwarding does not support SOCKS5 chaining (-F): listener `{}` is udp://. \
                 Remove -F or drop the udp:// listener.",
                l.name
            ));
        }
    }
    // Duplicate / overlapping bind (same protocol + bind address).
    for i in 0..listeners.len() {
        for j in (i + 1)..listeners.len() {
            if listeners[i].proto == listeners[j].proto && listeners[i].bind == listeners[j].bind {
                return Err(format!(
                    "duplicate listener: {} and {} both bind {} on {}",
                    listeners[i].name,
                    listeners[j].name,
                    listeners[i].bind,
                    listeners[i].proto.as_str()
                ));
            }
        }
    }

    // --- Scalars ---
    let buf_kb = raw.buf_size_kb.unwrap_or(32);
    if !(MIN_BUF_KB..=MAX_BUF_KB).contains(&buf_kb) {
        return Err(format!(
            "--buf-size-kb must be between {MIN_BUF_KB} and {MAX_BUF_KB} (got {buf_kb})"
        ));
    }
    let mark = match raw.mark {
        Some(m) if m < 0 => return Err(format!("-M mark must be non-negative (got {m})")),
        Some(m) => Some(m as u32),
        None => None,
    };
    let heartbeat = Duration::from_secs(raw.heartbeat_secs.unwrap_or(60));

    if let Some(w) = raw.worker_threads {
        if w == 0 {
            return Err("--worker-threads must be >= 1".to_string());
        }
    }
    let sock = SockOpts {
        nodelay: raw.nodelay.unwrap_or(true),
        rcvbuf: raw.so_rcvbuf,
        sndbuf: raw.so_sndbuf,
    };

    Ok(Config {
        listeners,
        chain,
        mode,
        mark,
        set_ip_forward: raw.set_ip_forward,
        buf_size: buf_kb * 1024,
        heartbeat,
        debug: raw.debug,
        worker_threads: raw.worker_threads,
        sock,
    })
}

/// Validate that `s` looks like `host:port` with a non-empty host and a valid
/// port. Supports bracketed IPv6. Does not resolve DNS.
fn validate_hostport(s: &str) -> Result<(), String> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']').ok_or("unterminated IPv6 bracket")?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = after
            .strip_prefix(':')
            .ok_or("missing :port after IPv6 literal")?;
        (host, port)
    } else {
        let c = s.rfind(':').ok_or("missing :port")?;
        (&s[..c], &s[c + 1..])
    };
    if host.is_empty() {
        return Err("missing host".to_string());
    }
    port.parse::<u16>()
        .map_err(|_| format!("invalid port `{port}`"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> RawArgs {
        RawArgs::default()
    }

    #[test]
    fn basic_tcp_userspace() {
        let mut r = raw();
        r.listens = vec!["tcp://:8080/1.2.3.4:9090".into()];
        let c = build_config(r).unwrap();
        assert_eq!(c.mode, Mode::Userspace);
        assert_eq!(c.listeners.len(), 1);
        assert_eq!(c.listeners[0].bind, "0.0.0.0:8080");
        assert_eq!(c.listeners[0].targets, vec!["1.2.3.4:9090".to_string()]);
        assert_eq!(c.buf_size, 32 * 1024);
    }

    #[test]
    fn nat_with_forward_rejected() {
        let mut r = raw();
        r.listens = vec!["tcp://:8080/1.2.3.4:9090".into()];
        r.forwards = vec!["socks5://u:p@h:1080".into()];
        r.nat = true;
        let e = build_config(r).unwrap_err();
        assert!(e.contains("--nat cannot be combined with -F"), "{e}");
    }

    #[test]
    fn udp_with_forward_rejected() {
        let mut r = raw();
        r.listens = vec!["udp://:5300/8.8.8.8:53".into()];
        r.forwards = vec!["socks5://h:1080".into()];
        let e = build_config(r).unwrap_err();
        assert!(e.contains("UDP forwarding does not support SOCKS5"), "{e}");
    }

    #[test]
    fn missing_target_rejected() {
        let mut r = raw();
        r.listens = vec!["tcp://:8080".into()];
        let e = build_config(r).unwrap_err();
        assert!(e.contains("requires a destination"), "{e}");
    }

    #[test]
    fn duplicate_bind_rejected() {
        let mut r = raw();
        r.listens = vec![
            "tcp://:8080/1.2.3.4:9090".into(),
            "tcp://0.0.0.0:8080/5.6.7.8:9090".into(),
        ];
        let e = build_config(r).unwrap_err();
        assert!(e.contains("duplicate listener"), "{e}");
    }

    #[test]
    fn tcp_and_udp_same_port_ok() {
        let mut r = raw();
        r.listens = vec![
            "tcp://:8080/1.2.3.4:9090".into(),
            "udp://:8080/1.2.3.4:9090".into(),
        ];
        let c = build_config(r).unwrap();
        assert_eq!(c.listeners.len(), 2);
    }

    #[test]
    fn bad_forward_scheme_rejected() {
        let mut r = raw();
        r.listens = vec!["tcp://:8080/1.2.3.4:9090".into()];
        r.forwards = vec!["http://h:8080".into()];
        let e = build_config(r).unwrap_err();
        assert!(e.contains("only socks5"), "{e}");
    }

    #[test]
    fn nat_mode_set() {
        let mut r = raw();
        r.listens = vec!["tcp://:8080/1.2.3.4:9090".into()];
        r.nat = true;
        let c = build_config(r).unwrap();
        assert_eq!(c.mode, Mode::Nat);
    }

    #[test]
    fn buf_size_bounds() {
        let mut r = raw();
        r.listens = vec!["tcp://:8080/1.2.3.4:9090".into()];
        r.buf_size_kb = Some(0);
        assert!(build_config(r).is_err());
    }

    #[test]
    fn chain_hops_parsed() {
        let mut r = raw();
        r.listens = vec!["tcp://:8080/1.2.3.4:9090".into()];
        r.forwards = vec!["socks5://u:p@h1:1080".into(), "socks5://h2:1080".into()];
        let c = build_config(r).unwrap();
        assert_eq!(c.chain.len(), 2);
        assert_eq!(c.chain[0].user.as_deref(), Some("u"));
        assert!(c.chain[1].user.is_none());
    }
}
