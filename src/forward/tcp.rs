//! Userspace TCP forwarding: accept, dial (direct or via the SOCKS5 chain),
//! and relay. Mirrors GOST's `tcpDirectForwardHandler`.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use crate::config::ListenerSpec;
use crate::netopt::tune_accepted;
use crate::relay::transport;
use crate::runtime::{Context, Shutdown};
use crate::stats::ListenerStats;

/// Bind and run the accept loop until shutdown. Returns `Err` on bind failure
/// (the supervisor will back off and retry).
pub async fn serve(
    spec: Arc<ListenerSpec>,
    stats: Arc<ListenerStats>,
    ctx: Arc<Context>,
    shutdown: Shutdown,
) -> io::Result<()> {
    let listener = TcpListener::bind(&spec.bind)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("bind {} failed: {e}", spec.bind)))?;
    tracing::info!(listener = %spec.name, bind = %spec.bind, targets = %spec.targets.join(","), "tcp listening");

    let rr = AtomicUsize::new(0);

    loop {
        let accepted = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!(listener = %spec.name, "tcp listener stopping");
                return Ok(());
            }
            res = listener.accept() => res,
        };

        let (client, peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                // Transient accept errors (e.g. EMFILE under fd pressure) must
                // not kill the listener. Log, pause briefly, keep serving.
                stats.inc_error();
                tracing::warn!(listener = %spec.name, error = %e, "accept error");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };

        let target = pick_target(&spec.targets, &rr).to_string();
        let stats_c = stats.clone();
        let ctx_c = ctx.clone();
        let spec_c = spec.clone();

        tokio::spawn(async move {
            let _guard = stats_c.on_accept();
            if let Err(e) = handle_conn(client, &spec_c, &ctx_c, &target).await {
                stats_c.inc_error();
                tracing::debug!(
                    listener = %spec_c.name,
                    peer = %peer,
                    target = %target,
                    error = %e,
                    "tcp connection closed with error"
                );
            }
        });
    }
}

async fn handle_conn(
    mut client: TcpStream,
    spec: &ListenerSpec,
    ctx: &Context,
    target: &str,
) -> io::Result<()> {
    tune_accepted(&client, ctx.sock)?;
    let mut backend = ctx
        .dialer
        .connect(target)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("dial {target} failed: {e}")))?;
    tracing::debug!(listener = %spec.name, target = %target, "tcp relay established");
    transport(&mut client, &mut backend, ctx.buf_size).await?;
    Ok(())
}

fn pick_target<'a>(targets: &'a [String], rr: &AtomicUsize) -> &'a str {
    if targets.len() == 1 {
        &targets[0]
    } else {
        let i = rr.fetch_add(1, Ordering::Relaxed) % targets.len();
        &targets[i]
    }
}
