//! Application orchestration: build the runtime context, launch a supervised
//! task per listener, wire signals and the heartbeat, and wait for shutdown.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Config, ListenerSpec, Mode, Protocol};
use crate::forward;
use crate::runtime::{Context, Dialer, Shutdown};
use crate::stats::{ListenerStats, Registry};
use crate::supervisor::supervise;
use crate::{logging, signals};

/// Run Gust to completion. Returns the process exit code.
pub async fn run(cfg: Config) -> ExitCode {
    let _log_guard = logging::init(cfg.debug);
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        mode = ?cfg.mode,
        listeners = cfg.listeners.len(),
        chain_hops = cfg.chain.len(),
        buf_kib = cfg.buf_size / 1024,
        "gust starting"
    );

    match cfg.mode {
        Mode::Userspace => run_userspace(cfg).await,
        Mode::Nat => crate::nat::run(cfg).await,
    }
}

async fn run_userspace(cfg: Config) -> ExitCode {
    let shutdown = Shutdown::new();
    let ctx = Arc::new(Context {
        buf_size: cfg.buf_size,
        dialer: Dialer::new(cfg.chain.clone(), cfg.mark),
        mark: cfg.mark,
    });

    let mut registry = Registry::default();
    let mut handles = Vec::new();

    for spec in cfg.listeners {
        let spec = Arc::new(spec);
        let stats = ListenerStats::new(spec.name.clone(), spec.proto.as_str());
        registry.listeners.push(stats.clone());
        handles.push(spawn_listener(spec, stats, ctx.clone(), shutdown.clone()));
    }

    signals::install(shutdown.clone(), {
        let reg = registry.clone();
        move || reg.dump()
    });

    spawn_heartbeat(registry.clone(), cfg.heartbeat, shutdown.clone());

    tracing::info!("all listeners launched; press Ctrl-C to stop");
    shutdown.cancelled().await;
    tracing::info!("shutting down");

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        for h in handles {
            let _ = h.await;
        }
    })
    .await;

    ExitCode::SUCCESS
}

/// Spawn the supervised serve loop for one listener.
pub fn spawn_listener(
    spec: Arc<ListenerSpec>,
    stats: Arc<ListenerStats>,
    ctx: Arc<Context>,
    shutdown: Shutdown,
) -> tokio::task::JoinHandle<()> {
    match spec.proto {
        Protocol::Tcp => tokio::spawn(supervise(stats.clone(), shutdown.clone(), move || {
            forward::tcp::serve(spec.clone(), stats.clone(), ctx.clone(), shutdown.clone())
        })),
        Protocol::Udp => tokio::spawn(supervise(stats.clone(), shutdown.clone(), move || {
            forward::udp::serve(spec.clone(), stats.clone(), ctx.clone(), shutdown.clone())
        })),
    }
}

fn spawn_heartbeat(registry: Registry, interval: Duration, shutdown: Shutdown) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
            if shutdown.is_triggered() {
                break;
            }
            tracing::info!("{}", registry.heartbeat_line());
        }
    });
}
