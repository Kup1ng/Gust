//! Per-listener supervisor.
//!
//! Each `-L` runs under its own supervisor: it (re)starts the listener's serve
//! loop, applies exponential backoff on failure, and isolates panics so one
//! listener can never take down its siblings or the process. A bind failure on
//! one port simply backs off and retries; the others keep running.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use tokio::time::sleep;

use crate::constants::{BACKOFF_HEALTHY, BACKOFF_INITIAL, BACKOFF_MAX};
use crate::runtime::Shutdown;
use crate::stats::ListenerStats;

/// Supervise a listener. `serve` is called to (re)build and run the accept loop;
/// it should return `Ok(())` only when asked to stop (shutdown). Any `Err` or
/// panic triggers a backed-off restart. Returns when shutdown is observed.
pub async fn supervise<F, Fut>(stats: Arc<ListenerStats>, shutdown: Shutdown, mut serve: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let mut backoff = BACKOFF_INITIAL;

    loop {
        if shutdown.is_triggered() {
            return;
        }

        let started = Instant::now();
        // Run the serve loop in its own task so a panic is captured here rather
        // than unwinding past the supervisor.
        let mut handle = tokio::spawn(serve());
        let outcome = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                handle.abort();
                return;
            }
            joined = &mut handle => joined,
        };

        match outcome {
            Ok(Ok(())) => {
                // Clean stop (only happens on shutdown).
                return;
            }
            Ok(Err(e)) => {
                stats.set_last_error(e.to_string());
                tracing::warn!(listener = %stats.name, error = %e, "listener failed; will restart");
            }
            Err(join_err) if join_err.is_panic() => {
                stats.set_last_error("panic".to_string());
                tracing::error!(
                    listener = %stats.name,
                    "listener panicked; restarting (siblings unaffected)"
                );
            }
            Err(_) => {
                // Cancelled/aborted — treat as shutdown.
                return;
            }
        }

        if shutdown.is_triggered() {
            return;
        }

        // Reset backoff if the listener had been healthy for a while.
        if started.elapsed() >= BACKOFF_HEALTHY {
            backoff = BACKOFF_INITIAL;
        }
        stats.inc_restart();
        tracing::info!(listener = %stats.name, backoff_ms = backoff.as_millis() as u64, "backing off before restart");

        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}
