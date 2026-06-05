//! Tunables ported from GOST v2.11.5 defaults, plus supervisor backoff values.

use std::time::Duration;

/// TCP keep-alive idle time (GOST `KeepAliveTime`). Set on accepted and dialed
/// sockets so dead mobile clients are reaped and don't leak fds.
pub const KEEPALIVE: Duration = Duration::from_secs(180);

/// Keep-alive probe interval after the idle time elapses (Linux). With
/// [`KEEPALIVE_RETRIES`] this reaps a genuinely dead peer in ~180s + 4×25s ≈ 4.7
/// min instead of the distro default (~14 min). Live peers answer probes and are
/// never affected.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

/// Number of unanswered keep-alive probes before the connection is dropped (Linux).
pub const KEEPALIVE_RETRIES: u32 = 4;

/// Timeout for establishing an outbound TCP connection (GOST `DialTimeout`).
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for a single SOCKS5 hop negotiation (GOST `HandshakeTimeout`).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Idle lifetime of a userspace UDP NAT session (GOST `defaultTTL`).
pub const UDP_TTL: Duration = Duration::from_secs(60);

/// Per-datagram UDP receive buffer. GOST uses 8 KiB; we use 64 KiB to never
/// silently truncate a large datagram.
pub const UDP_BUF: usize = 64 * 1024;

/// Per-session UDP receive queue depth (GOST `defaultQueueSize`).
pub const UDP_QUEUE: usize = 128;

/// Supervisor restart backoff: starts here, doubles up to [`BACKOFF_MAX`].
pub const BACKOFF_INITIAL: Duration = Duration::from_millis(100);
pub const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// A listener that ran at least this long before failing is considered healthy,
/// so its backoff resets to [`BACKOFF_INITIAL`].
pub const BACKOFF_HEALTHY: Duration = Duration::from_secs(10);
