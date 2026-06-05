//! Parsing of GOST-style node strings.
//!
//! A node string follows the form `scheme://[user:pass@]host:port[/target][?query]`,
//! mirroring how GOST v2 parses `-L` and `-F` values. The forward target for a
//! `-L` listener lives in the URL *path* (e.g. `tcp://:8080/1.2.3.4:9090` → target
//! `1.2.3.4:9090`). This is a hand-written parser rather than a generic URL crate
//! so the awkward empty-host case (`:8080`) and Go's "split userinfo at the last
//! `@`" rule are matched exactly.

use std::collections::HashMap;

/// A parsed node string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub scheme: String,
    pub user: Option<String>,
    pub pass: Option<String>,
    /// Host portion of the authority. May be empty (`:8080` → ""), meaning
    /// "all interfaces" for a bind address.
    pub host: String,
    pub port: Option<u16>,
    /// The path portion, trimmed of surrounding slashes. For forwarders this is
    /// the destination, optionally a comma-separated list. May be empty.
    pub target: String,
    pub query: HashMap<String, String>,
}

impl Node {
    /// `host:port` authority string (e.g. a SOCKS5 hop address). Empty host is
    /// preserved as-is (callers that need a bind address use [`Node::bind_string`]).
    pub fn authority(&self) -> Option<String> {
        self.port.map(|p| format!("{}:{}", self.host, p))
    }

    /// Bindable address string: an empty host becomes `0.0.0.0`.
    pub fn bind_string(&self) -> Option<String> {
        let p = self.port?;
        if self.host.is_empty() {
            Some(format!("0.0.0.0:{p}"))
        } else {
            Some(format!("{}:{}", self.host, p))
        }
    }

    /// Comma-separated targets, split and trimmed. Empty entries are dropped.
    pub fn targets(&self) -> Vec<String> {
        self.target
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }
}

/// Parse a node string. Returns a human-readable error suitable for printing to
/// the operator.
pub fn parse_node(s: &str) -> Result<Node, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty node string".to_string());
    }

    let scheme_idx = s.find("://").ok_or_else(|| {
        format!("node `{s}` is missing a scheme (expected e.g. tcp://, udp://, socks5://)")
    })?;
    let scheme = s[..scheme_idx].to_ascii_lowercase();
    if scheme.is_empty() {
        return Err(format!("node `{s}` has an empty scheme"));
    }
    let rest = &s[scheme_idx + 3..];

    // Authority ends at the first '/' or '?', whichever comes first.
    let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let remainder = &rest[auth_end..];

    // Split remainder into path and query.
    let (path, query_str) = match remainder.chars().next() {
        Some('?') => ("", &remainder[1..]),
        Some('/') => match remainder.find('?') {
            Some(q) => (&remainder[1..q], &remainder[q + 1..]),
            None => (&remainder[1..], ""),
        },
        _ => ("", ""),
    };
    let target = path.trim_matches('/').to_string();

    // Authority: userinfo is everything before the LAST '@' (Go semantics).
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    let (user, pass) = match userinfo {
        Some(ui) => match ui.find(':') {
            Some(c) => (Some(decode(&ui[..c])), Some(decode(&ui[c + 1..]))),
            None => (Some(decode(ui)), None),
        },
        None => (None, None),
    };

    let (host, port) = parse_host_port(hostport).map_err(|e| format!("node `{s}`: {e}"))?;

    let mut query = HashMap::new();
    for pair in query_str.split('&').filter(|p| !p.is_empty()) {
        match pair.find('=') {
            Some(eq) => {
                query.insert(pair[..eq].to_string(), pair[eq + 1..].to_string());
            }
            None => {
                query.insert(pair.to_string(), String::new());
            }
        }
    }

    Ok(Node {
        scheme,
        user,
        pass,
        host,
        port,
        target,
        query,
    })
}

/// Split a `host:port`, supporting bracketed IPv6 (`[::1]:8080`) and the
/// empty-host form (`:8080`). A missing port yields `None`.
fn parse_host_port(hp: &str) -> Result<(String, Option<u16>), String> {
    if hp.is_empty() {
        return Ok((String::new(), None));
    }
    if let Some(stripped) = hp.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let close = stripped
            .find(']')
            .ok_or_else(|| "unterminated IPv6 bracket".to_string())?;
        let host = stripped[..close].to_string();
        let after = &stripped[close + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(parse_port(p)?)
        } else if after.is_empty() {
            None
        } else {
            return Err(format!(
                "unexpected characters after IPv6 literal: `{after}`"
            ));
        };
        return Ok((host, port));
    }
    match hp.rfind(':') {
        Some(c) => {
            let host = hp[..c].to_string();
            let port = parse_port(&hp[c + 1..])?;
            Ok((host, Some(port)))
        }
        None => Ok((hp.to_string(), None)),
    }
}

fn parse_port(p: &str) -> Result<u16, String> {
    p.parse::<u16>().map_err(|_| format!("invalid port `{p}`"))
}

/// Minimal percent-decoding for userinfo (passwords frequently contain encoded
/// characters). Invalid escapes are passed through unchanged.
fn decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_forward_basic() {
        let n = parse_node("tcp://:8080/1.2.3.4:9090").unwrap();
        assert_eq!(n.scheme, "tcp");
        assert_eq!(n.host, "");
        assert_eq!(n.port, Some(8080));
        assert_eq!(n.bind_string().unwrap(), "0.0.0.0:8080");
        assert_eq!(n.target, "1.2.3.4:9090");
        assert_eq!(n.targets(), vec!["1.2.3.4:9090".to_string()]);
        assert!(n.user.is_none());
    }

    #[test]
    fn udp_forward_basic() {
        let n = parse_node("udp://:5300/8.8.8.8:53").unwrap();
        assert_eq!(n.scheme, "udp");
        assert_eq!(n.port, Some(5300));
        assert_eq!(n.target, "8.8.8.8:53");
    }

    #[test]
    fn socks5_with_auth() {
        let n = parse_node("socks5://user:pass@host.example:1080").unwrap();
        assert_eq!(n.scheme, "socks5");
        assert_eq!(n.user.as_deref(), Some("user"));
        assert_eq!(n.pass.as_deref(), Some("pass"));
        assert_eq!(n.host, "host.example");
        assert_eq!(n.port, Some(1080));
        assert_eq!(n.authority().unwrap(), "host.example:1080");
        assert!(n.target.is_empty());
    }

    #[test]
    fn socks5_no_auth() {
        let n = parse_node("socks5://10.0.0.1:1080").unwrap();
        assert!(n.user.is_none());
        assert!(n.pass.is_none());
        assert_eq!(n.authority().unwrap(), "10.0.0.1:1080");
    }

    #[test]
    fn explicit_bind_host() {
        let n = parse_node("tcp://127.0.0.1:8080/1.2.3.4:9090").unwrap();
        assert_eq!(n.host, "127.0.0.1");
        assert_eq!(n.bind_string().unwrap(), "127.0.0.1:8080");
    }

    #[test]
    fn multi_target_round_robin() {
        let n = parse_node("tcp://:8080/1.2.3.4:9090,2.3.4.5:9090").unwrap();
        assert_eq!(
            n.targets(),
            vec!["1.2.3.4:9090".to_string(), "2.3.4.5:9090".to_string()]
        );
    }

    #[test]
    fn ipv6_bind_and_target() {
        let n = parse_node("tcp://[::]:8080/[2001:db8::1]:443").unwrap();
        assert_eq!(n.host, "::");
        assert_eq!(n.port, Some(8080));
        assert_eq!(n.bind_string().unwrap(), ":::8080");
        assert_eq!(n.target, "[2001:db8::1]:443");
    }

    #[test]
    fn query_params() {
        let n = parse_node("tcp://:8080/1.2.3.4:9090?nodelay=true&foo").unwrap();
        assert_eq!(n.query.get("nodelay").map(String::as_str), Some("true"));
        assert_eq!(n.query.get("foo").map(String::as_str), Some(""));
    }

    #[test]
    fn password_with_at_sign_uses_last_at() {
        // user is `u`, password `p@ss` — split at the LAST '@'.
        let n = parse_node("socks5://u:p@ss@host:1080").unwrap();
        assert_eq!(n.user.as_deref(), Some("u"));
        assert_eq!(n.pass.as_deref(), Some("p@ss"));
        assert_eq!(n.host, "host");
        assert_eq!(n.port, Some(1080));
    }

    #[test]
    fn missing_scheme_errors() {
        assert!(parse_node(":8080/1.2.3.4:9090").is_err());
    }

    #[test]
    fn bad_port_errors() {
        assert!(parse_node("tcp://:99999/1.2.3.4:9090").is_err());
    }
}
