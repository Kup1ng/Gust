//! Socket option helpers: keep-alive / nodelay / buffer tuning and a
//! timeout-aware, mark-aware TCP dialer built on `socket2`.

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::net::TcpStream;

use crate::constants::KEEPALIVE;

/// Per-socket tuning applied to accepted and dialed TCP sockets. Exposed as CLI
/// knobs so single-stream throughput behavior can be measured against GOST.
#[derive(Debug, Clone, Copy)]
pub struct SockOpts {
    /// Set TCP_NODELAY (disable Nagle). GOST leaves this off by default.
    pub nodelay: bool,
    /// Explicit SO_RCVBUF in bytes. `None` keeps kernel autotuning (recommended).
    pub rcvbuf: Option<usize>,
    /// Explicit SO_SNDBUF in bytes. `None` keeps kernel autotuning (recommended).
    pub sndbuf: Option<usize>,
}

impl Default for SockOpts {
    fn default() -> Self {
        Self {
            nodelay: true,
            rcvbuf: None,
            sndbuf: None,
        }
    }
}

fn keepalive() -> TcpKeepalive {
    let k = TcpKeepalive::new().with_time(KEEPALIVE);
    // Tighten probe interval/count on Linux so a genuinely dead peer is reaped
    // faster than the distro default. These setters aren't available on all
    // platforms, so the dev-host (Windows) build keeps just the idle time. Live
    // peers answer probes and are never affected.
    #[cfg(target_os = "linux")]
    let k = k
        .with_interval(crate::constants::KEEPALIVE_INTERVAL)
        .with_retries(crate::constants::KEEPALIVE_RETRIES);
    k
}

/// Apply keep-alive + tuning to an accepted stream.
pub fn tune_accepted(stream: &TcpStream, opts: SockOpts) -> io::Result<()> {
    if opts.nodelay {
        stream.set_nodelay(true)?;
    }
    let sref = SockRef::from(stream);
    sref.set_tcp_keepalive(&keepalive())?;
    if let Some(n) = opts.rcvbuf {
        sref.set_recv_buffer_size(n)?;
    }
    if let Some(n) = opts.sndbuf {
        sref.set_send_buffer_size(n)?;
    }
    Ok(())
}

/// Connect to `addr` within `timeout`. Skips DNS (and the `spawn_blocking`
/// getaddrinfo it implies) when `addr` is already an `IP:port` literal — the
/// common forwarding case, important when many processes share one core.
pub async fn dial_tcp(
    addr: &str,
    timeout: Duration,
    mark: Option<u32>,
    opts: SockOpts,
) -> io::Result<TcpStream> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return dial_one(sa, timeout, mark, opts).await;
    }
    let mut last_err: Option<io::Error> = None;
    for sa in tokio::net::lookup_host(addr).await? {
        match dial_one(sa, timeout, mark, opts).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other(format!("could not resolve `{addr}`"))))
}

async fn dial_one(
    sa: SocketAddr,
    timeout: Duration,
    mark: Option<u32>,
    opts: SockOpts,
) -> io::Result<TcpStream> {
    let sock = Socket::new(Domain::for_address(sa), Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    sock.set_tcp_keepalive(&keepalive())?;
    if opts.nodelay {
        sock.set_nodelay(true)?;
    }
    // Buffer sizes are set BEFORE connect so window-scale negotiation sees them.
    if let Some(n) = opts.rcvbuf {
        sock.set_recv_buffer_size(n)?;
    }
    if let Some(n) = opts.sndbuf {
        sock.set_send_buffer_size(n)?;
    }
    #[cfg(target_os = "linux")]
    if let Some(m) = mark {
        sock.set_mark(m)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = mark;

    match sock.connect(&sa.into()) {
        Ok(()) => {}
        Err(e) if is_in_progress(&e) => {}
        Err(e) => return Err(e),
    }

    let std_stream: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_stream)?;

    tokio::time::timeout(timeout, stream.writable())
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "connect timed out"))??;

    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    Ok(stream)
}

fn is_in_progress(e: &io::Error) -> bool {
    if e.kind() == ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::EINPROGRESS) {
        return true;
    }
    false
}

/// Split a `host:port` string into its parts, stripping IPv6 brackets from the
/// host. Used to build SOCKS5 address fields.
pub fn split_host_port(s: &str) -> io::Result<(String, u16)> {
    let bad = || io::Error::new(ErrorKind::InvalidInput, format!("invalid host:port `{s}`"));
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(bad)?;
        let host = &rest[..close];
        let port = rest[close + 1..].strip_prefix(':').ok_or_else(bad)?;
        (host.to_string(), port)
    } else {
        let c = s.rfind(':').ok_or_else(bad)?;
        (s[..c].to_string(), &s[c + 1..])
    };
    let port: u16 = port.parse().map_err(|_| bad())?;
    if host.is_empty() {
        return Err(bad());
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::split_host_port;

    #[test]
    fn split_ipv4() {
        assert_eq!(
            split_host_port("1.2.3.4:9090").unwrap(),
            ("1.2.3.4".into(), 9090)
        );
    }

    #[test]
    fn split_ipv6_brackets() {
        assert_eq!(
            split_host_port("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".into(), 443)
        );
    }

    #[test]
    fn split_hostname() {
        assert_eq!(
            split_host_port("example.com:1080").unwrap(),
            ("example.com".into(), 1080)
        );
    }

    #[test]
    fn split_bad() {
        assert!(split_host_port("noport").is_err());
    }
}
