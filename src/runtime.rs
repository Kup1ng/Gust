//! Shared runtime types: the cooperative shutdown signal, the outbound dialer,
//! and the per-connection context handed to listeners.

use std::io;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::config::ChainHop;
use crate::constants::DIAL_TIMEOUT;
use crate::{chain, netopt};

/// A cheaply-clonable shutdown broadcast. Backed by a `watch` channel so late
/// subscribers always observe the final state (no lost-wakeup races).
#[derive(Clone)]
pub struct Shutdown {
    tx: Arc<watch::Sender<bool>>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self { tx: Arc::new(tx) }
    }

    /// Signal all listeners to stop.
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }

    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }

    /// Resolve once shutdown has been triggered (returns immediately if already).
    pub async fn cancelled(&self) {
        let mut rx = self.tx.subscribe();
        if *rx.borrow() {
            return;
        }
        // Wait for the value to flip to `true`.
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
    }
}

/// Outbound dialer: direct when the chain is empty, otherwise through SOCKS5 hops.
pub struct Dialer {
    chain: Vec<ChainHop>,
    mark: Option<u32>,
}

impl Dialer {
    pub fn new(chain: Vec<ChainHop>, mark: Option<u32>) -> Self {
        Self { chain, mark }
    }

    pub async fn connect(&self, target: &str) -> io::Result<TcpStream> {
        if self.chain.is_empty() {
            netopt::dial_tcp(target, DIAL_TIMEOUT, self.mark).await
        } else {
            chain::dial(&self.chain, target, self.mark).await
        }
    }
}

/// Immutable context shared by all connection tasks of all listeners.
pub struct Context {
    pub buf_size: usize,
    pub dialer: Dialer,
    /// `SO_MARK` for outbound sockets (UDP sessions; TCP dials carry it via the
    /// dialer). `None` unless `-M` was given.
    pub mark: Option<u32>,
}
