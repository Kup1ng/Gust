//! Non-blocking logging setup.
//!
//! All log records go through a dedicated background writer thread
//! (`tracing-appender`), so the data path never blocks on log I/O. The returned
//! guard must be kept alive for the lifetime of the process.

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Initialize the global logger. Honors `RUST_LOG`; otherwise defaults to
/// `info` (or `debug` when `-D/--debug` is set).
pub fn init(debug: bool) -> WorkerGuard {
    let default = if debug { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));

    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .with_target(false)
        .init();

    guard
}
