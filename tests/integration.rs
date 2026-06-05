//! End-to-end tests that drive the real serve loops through a loopback backend.

use std::sync::Arc;
use std::time::Duration;

use gust::config::{ListenerSpec, Protocol};
use gust::netopt::SockOpts;
use gust::runtime::{Context, Dialer, Shutdown};
use gust::stats::ListenerStats;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Grab an ephemeral port by binding then releasing it. Small TOCTOU window,
/// acceptable for tests.
fn free_tcp_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

async fn connect_retry(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("listener never came up on port {port}");
}

fn ctx() -> Arc<Context> {
    Arc::new(Context {
        buf_size: 32 * 1024,
        dialer: Dialer::new(vec![], None, SockOpts::default()),
        mark: None,
        sock: SockOpts::default(),
    })
}

#[tokio::test]
async fn tcp_forward_roundtrip() {
    // Echo backend.
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = backend.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let port = free_tcp_port();
    let spec = Arc::new(ListenerSpec {
        proto: Protocol::Tcp,
        bind: format!("127.0.0.1:{port}"),
        port,
        targets: vec![backend_addr.to_string()],
        nodelay: false,
        name: format!("tcp://127.0.0.1:{port}"),
    });
    let stats = ListenerStats::new(spec.name.clone(), "tcp");
    let shutdown = Shutdown::new();
    let serve = tokio::spawn(gust::forward::tcp::serve(
        spec.clone(),
        stats.clone(),
        ctx(),
        shutdown.clone(),
    ));

    let mut client = connect_retry(port).await;
    client.write_all(b"hello gust").await.unwrap();
    let mut buf = [0u8; 10];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello gust");

    // Larger transfer to exercise the relay buffer across multiple reads.
    let big = vec![0xABu8; 256 * 1024];
    client.write_all(&big).await.unwrap();
    let mut got = vec![0u8; big.len()];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(got, big);

    assert!(stats.accepted() >= 1);

    shutdown.trigger();
    let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
}

#[tokio::test]
async fn udp_forward_roundtrip() {
    // Echo backend: reply with the same datagram.
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = backend.recv_from(&mut b).await {
            let _ = backend.send_to(&b[..n], from).await;
        }
    });

    let port = free_udp_port();
    let spec = Arc::new(ListenerSpec {
        proto: Protocol::Udp,
        bind: format!("127.0.0.1:{port}"),
        port,
        targets: vec![backend_addr.to_string()],
        nodelay: false,
        name: format!("udp://127.0.0.1:{port}"),
    });
    let stats = ListenerStats::new(spec.name.clone(), "udp");
    let shutdown = Shutdown::new();
    let serve = tokio::spawn(gust::forward::udp::serve(
        spec.clone(),
        stats.clone(),
        ctx(),
        shutdown.clone(),
    ));

    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(("127.0.0.1", port)).await.unwrap();
    client.send(b"ping").await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no udp reply")
        .unwrap();
    assert_eq!(&buf[..n], b"ping");

    // Second datagram reuses the same session.
    client.send(b"pong").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no udp reply 2")
        .unwrap();
    assert_eq!(&buf[..n], b"pong");
    assert_eq!(stats.accepted(), 1, "exactly one session expected");

    shutdown.trigger();
    let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
}
