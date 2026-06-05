//! Signal wiring: SIGINT/SIGTERM trigger graceful shutdown; SIGUSR1 dumps status.
//!
//! On non-Unix hosts (used only for local development builds) we fall back to
//! Ctrl-C for shutdown; SIGUSR1 has no analogue and is ignored.

use crate::runtime::Shutdown;

/// Install signal handlers. `dump` is invoked on each SIGUSR1.
#[cfg(unix)]
pub fn install<F>(shutdown: Shutdown, dump: F)
where
    F: Fn() + Send + 'static,
{
    use tokio::signal::unix::{signal, SignalKind};

    // SIGINT + SIGTERM -> graceful shutdown.
    let sd = shutdown.clone();
    tokio::spawn(async move {
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGINT handler");
                return;
            }
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler");
                return;
            }
        };
        let which = tokio::select! {
            _ = sigint.recv() => "SIGINT",
            _ = sigterm.recv() => "SIGTERM",
        };
        tracing::info!(signal = which, "shutdown requested");
        sd.trigger();
    });

    // SIGUSR1 -> status dump.
    tokio::spawn(async move {
        let mut sigusr1 = match signal(SignalKind::user_defined1()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGUSR1 handler");
                return;
            }
        };
        while sigusr1.recv().await.is_some() {
            dump();
        }
    });
}

#[cfg(not(unix))]
pub fn install<F>(shutdown: Shutdown, _dump: F)
where
    F: Fn() + Send + 'static,
{
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("Ctrl-C received");
            shutdown.trigger();
        }
    });
}
