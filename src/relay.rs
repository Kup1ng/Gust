//! The userspace bidirectional relay.
//!
//! Mirrors GOST's `transport` (two `io.CopyBuffer` goroutines) using tokio's
//! `copy_bidirectional_with_sizes` with a fixed buffer per direction held for
//! the connection lifetime. No buffer pool and no per-chunk timers on the data
//! path — the two things that wrecked the prior attempt under load.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

/// Relay bytes between two streams until one side closes. Returns
/// `(client→backend, backend→client)` byte counts. `buf_size` is the buffer per
/// direction, in bytes.
pub async fn transport<A, B>(a: &mut A, b: &mut B, buf_size: usize) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional_with_sizes(a, b, buf_size, buf_size).await
}
