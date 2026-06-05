//! The userspace bidirectional relay.
//!
//! Mirrors GOST's `transport`: two concurrent copy loops, returning the instant
//! the FIRST direction finishes (EOF or error), after which BOTH streams are
//! dropped (closed). This is deliberately different from tokio's
//! `copy_bidirectional`, which waits for *both* directions to shut down. Under
//! proxy load a peer often sends FIN on one side while leaving the other half
//! open; waiting for both then pins the connection's buffers and fds until TCP
//! keepalive reaps it (~minutes), so half-finished connections accumulate and
//! RSS climbs. Closing on first-finish (like GOST) keeps the live-connection
//! set — and thus memory — bounded.
//!
//! A fixed buffer per direction is held for the connection lifetime: no pool and
//! no per-chunk timers on the data path.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

// Note: on EOF we return immediately rather than awaiting `shutdown()` on the
// opposite writer. The caller drops both `TcpStream`s, which closes both fds
// (sending FIN/RST) without blocking — matching GOST's `defer Close()`. Awaiting
// shutdown could pend if the peer stopped draining, reintroducing a hang.

/// Relay bytes between two TCP streams until one direction finishes, then return
/// (the caller drops both streams, closing them). `buf_size` is the buffer per
/// direction, in bytes.
pub async fn transport(a: &mut TcpStream, b: &mut TcpStream, buf_size: usize) -> io::Result<()> {
    let (ar, aw) = a.split();
    let (br, bw) = b.split();

    // First direction to complete wins; the other copy future is cancelled when
    // this returns and both streams are dropped by the caller.
    tokio::select! {
        r = copy_one(ar, bw, buf_size) => r.map(|_| ()),
        r = copy_one(br, aw, buf_size) => r.map(|_| ()),
    }
}

/// One-direction copy: read up to `buf_size`, write it all, repeat until EOF or
/// error. Mirrors GOST's `io.CopyBuffer` with a fixed buffer.
async fn copy_one<R, W>(mut r: R, mut w: W, buf_size: usize) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buf_size];
    let mut total: u64 = 0;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}
