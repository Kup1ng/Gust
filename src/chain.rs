//! Dialing a destination through a chain of SOCKS5 hops.
//!
//! Mirrors GOST's `Chain.getConn`: connect to hop 1, then SOCKS5-CONNECT to
//! hop 2 *through* hop 1, and so on, finally CONNECT to the real destination
//! through the last hop. The returned stream relays application bytes end-to-end.

use std::io;

use tokio::net::TcpStream;

use crate::config::ChainHop;
use crate::constants::{DIAL_TIMEOUT, HANDSHAKE_TIMEOUT};
use crate::netopt::{dial_tcp, split_host_port};
use crate::socks5;

/// Dial `target` (`host:port`) through `hops`. `hops` must be non-empty.
pub async fn dial(hops: &[ChainHop], target: &str, mark: Option<u32>) -> io::Result<TcpStream> {
    debug_assert!(!hops.is_empty());

    // TCP-connect to the first hop directly.
    let mut stream = dial_tcp(&hops[0].addr, DIAL_TIMEOUT, mark).await?;

    // For each hop, negotiate over the current stream and CONNECT to the next
    // address in the chain (the following hop, or the final target).
    for i in 0..hops.len() {
        let (host, port) = if i + 1 < hops.len() {
            split_host_port(&hops[i + 1].addr)?
        } else {
            split_host_port(target)?
        };
        let hop = &hops[i];
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            socks5::connect(
                &mut stream,
                &host,
                port,
                hop.user.as_deref(),
                hop.pass.as_deref(),
            ),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("SOCKS5 handshake to {} timed out", hop.addr),
            )
        })??;
    }

    Ok(stream)
}
