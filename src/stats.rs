//! Per-listener counters, the SIGUSR1 dump, and the periodic heartbeat.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

/// Live counters for one userspace listener. Updated with relaxed atomics off
/// the hot path's critical sections.
#[derive(Debug)]
pub struct ListenerStats {
    pub name: String,
    pub proto: &'static str,
    accepted: AtomicU64,
    active: AtomicU64,
    restarts: AtomicU64,
    errors: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl ListenerStats {
    pub fn new(name: impl Into<String>, proto: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            proto,
            accepted: AtomicU64::new(0),
            active: AtomicU64::new(0),
            restarts: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_error: Mutex::new(None),
        })
    }

    /// Record an accepted connection and return a guard that decrements the
    /// active gauge on drop — including on panic unwind.
    pub fn on_accept(self: &Arc<Self>) -> ActiveGuard {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(self.clone())
    }

    pub fn inc_restart(&self) {
        self.restarts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_last_error(&self, e: impl Into<String>) {
        if let Ok(mut g) = self.last_error.lock() {
            *g = Some(e.into());
        }
    }

    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }
    pub fn restarts(&self) -> u64 {
        self.restarts.load(Ordering::Relaxed)
    }
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// One-line summary for SIGUSR1 / heartbeat.
    pub fn summary(&self) -> String {
        let last = self
            .last_error
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .map(|e| format!(", last_error=\"{e}\""))
            .unwrap_or_default();
        format!(
            "{} accepted={} active={} restarts={} errors={}{}",
            self.name,
            self.accepted(),
            self.active(),
            self.restarts(),
            self.errors(),
            last,
        )
    }
}

/// RAII guard that decrements the active-connection gauge on drop.
pub struct ActiveGuard(Arc<ListenerStats>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Registry of all listener stats, shared by the supervisor, the heartbeat, and
/// the SIGUSR1 handler.
#[derive(Clone, Default)]
pub struct Registry {
    pub listeners: Vec<Arc<ListenerStats>>,
}

impl Registry {
    pub fn dump(&self) {
        tracing::info!("--- status dump ({} listeners) ---", self.listeners.len());
        let mut total_active = 0u64;
        let mut total_accepted = 0u64;
        for s in &self.listeners {
            total_active += s.active();
            total_accepted += s.accepted();
            tracing::info!("{}", s.summary());
        }
        tracing::info!("totals: accepted={total_accepted} active={total_active}");
    }

    pub fn heartbeat_line(&self) -> String {
        let active: u64 = self.listeners.iter().map(|s| s.active()).sum();
        let accepted: u64 = self.listeners.iter().map(|s| s.accepted()).sum();
        let restarts: u64 = self.listeners.iter().map(|s| s.restarts()).sum();
        format!(
            "heartbeat: listeners={} accepted={accepted} active={active} restarts={restarts}",
            self.listeners.len()
        )
    }
}
