//! Userspace UDP forwarding with per-client NAT sessions.
//!
//! Mirrors GOST's `udpListener` + `udpServerConn`: datagrams from a client are
//! keyed by source address into a session that owns a dedicated outbound socket
//! connected to the target. A reverse task copies replies back to the client.
//! Sessions are reaped after [`UDP_TTL`] of inactivity in either direction.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::config::ListenerSpec;
use crate::constants::{UDP_BUF, UDP_TTL};
use crate::runtime::{Context, Shutdown};
use crate::stats::ListenerStats;

/// Monotonic milliseconds since the first call, for lock-free idle tracking.
fn mono_ms() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u64
}

struct Session {
    out: Arc<UdpSocket>,
    last_activity: Arc<AtomicU64>,
}

type SessionMap = Arc<Mutex<HashMap<SocketAddr, Session>>>;

/// Bind the UDP socket and run the receive loop until shutdown.
pub async fn serve(
    spec: Arc<ListenerSpec>,
    stats: Arc<ListenerStats>,
    ctx: Arc<Context>,
    shutdown: Shutdown,
) -> io::Result<()> {
    let sock = UdpSocket::bind(&spec.bind)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("bind {} failed: {e}", spec.bind)))?;
    let listener = Arc::new(sock);
    tracing::info!(listener = %spec.name, bind = %spec.bind, targets = %spec.targets.join(","), "udp listening");

    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let mut rr: usize = 0;
    let mut buf = vec![0u8; UDP_BUF];

    loop {
        let (n, peer) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!(listener = %spec.name, "udp listener stopping");
                return Ok(());
            }
            res = listener.recv_from(&mut buf) => match res {
                Ok(v) => v,
                Err(e) => {
                    stats.inc_error();
                    tracing::warn!(listener = %spec.name, error = %e, "udp recv error");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            },
        };

        // Fast path: existing session.
        if let Some((out, last)) = lookup(&sessions, &peer) {
            last.store(mono_ms(), Ordering::Relaxed);
            if let Err(e) = out.send(&buf[..n]).await {
                tracing::debug!(listener = %spec.name, peer = %peer, error = %e, "udp forward send failed");
            }
            continue;
        }

        // New session.
        let target = pick_target(&spec.targets, &mut rr);
        match new_session(&target, ctx.mark).await {
            Ok(out) => {
                let last = Arc::new(AtomicU64::new(mono_ms()));
                let session = Session {
                    out: out.clone(),
                    last_activity: last.clone(),
                };
                sessions.lock().unwrap().insert(peer, session);
                let guard = stats.on_accept();
                spawn_reverse(
                    spec.clone(),
                    sessions.clone(),
                    listener.clone(),
                    out.clone(),
                    peer,
                    last.clone(),
                    guard,
                );
                // Forward the first datagram that created the session.
                last.store(mono_ms(), Ordering::Relaxed);
                if let Err(e) = out.send(&buf[..n]).await {
                    tracing::debug!(listener = %spec.name, peer = %peer, error = %e, "udp first send failed");
                }
                tracing::debug!(listener = %spec.name, peer = %peer, target = %target, "udp session opened");
            }
            Err(e) => {
                stats.inc_error();
                tracing::debug!(listener = %spec.name, peer = %peer, target = %target, error = %e, "udp session open failed");
            }
        }
    }
}

fn lookup(sessions: &SessionMap, peer: &SocketAddr) -> Option<(Arc<UdpSocket>, Arc<AtomicU64>)> {
    let map = sessions.lock().unwrap();
    map.get(peer)
        .map(|s| (s.out.clone(), s.last_activity.clone()))
}

/// Create an outbound UDP socket connected to `target`. Skips DNS (and its
/// `spawn_blocking`) when `target` is already an `IP:port` literal.
async fn new_session(target: &str, mark: Option<u32>) -> io::Result<Arc<UdpSocket>> {
    if let Ok(sa) = target.parse::<SocketAddr>() {
        return Ok(Arc::new(bind_connected(sa, mark)?));
    }
    let mut last_err: Option<io::Error> = None;
    for sa in tokio::net::lookup_host(target).await? {
        match bind_connected(sa, mark) {
            Ok(out) => return Ok(Arc::new(out)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("no target address")))
}

fn bind_connected(sa: SocketAddr, mark: Option<u32>) -> io::Result<UdpSocket> {
    let domain = Domain::for_address(sa);
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    if let Some(m) = mark {
        sock.set_mark(m)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = mark;
    let bind_any: SocketAddr = if sa.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    sock.bind(&bind_any.into())?;
    sock.connect(&sa.into())?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

#[allow(clippy::too_many_arguments)]
fn spawn_reverse(
    spec: Arc<ListenerSpec>,
    sessions: SessionMap,
    listener: Arc<UdpSocket>,
    out: Arc<UdpSocket>,
    peer: SocketAddr,
    last: Arc<AtomicU64>,
    guard: crate::stats::ActiveGuard,
) {
    tokio::spawn(async move {
        let _guard = guard; // dropped (active--) when the session ends
        let mut buf = vec![0u8; UDP_BUF];
        let ttl_ms = UDP_TTL.as_millis() as u64;
        loop {
            tokio::select! {
                res = out.recv(&mut buf) => {
                    match res {
                        Ok(n) => {
                            last.store(mono_ms(), Ordering::Relaxed);
                            if let Err(e) = listener.send_to(&buf[..n], peer).await {
                                tracing::debug!(listener = %spec.name, peer = %peer, error = %e, "udp reverse send failed");
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(listener = %spec.name, peer = %peer, error = %e, "udp reverse recv failed");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(UDP_TTL) => {
                    if mono_ms().saturating_sub(last.load(Ordering::Relaxed)) >= ttl_ms {
                        break;
                    }
                }
            }
        }
        sessions.lock().unwrap().remove(&peer);
        tracing::debug!(listener = %spec.name, peer = %peer, "udp session closed");
    });
}

fn pick_target(targets: &[String], rr: &mut usize) -> String {
    if targets.len() == 1 {
        targets[0].clone()
    } else {
        let i = *rr % targets.len();
        *rr = rr.wrapping_add(1);
        targets[i].clone()
    }
}
