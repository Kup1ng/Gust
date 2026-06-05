//! Opt-in in-kernel NAT mode.
//!
//! When `--nat` is set, Gust programs nftables DNAT rules so traffic is
//! forwarded entirely in-kernel (no userspace relay, ~0 per-connection memory).
//! This module owns rule installation, layered cleanup, and counter-based
//! status reporting. The runtime implementation is Linux-only; other platforms
//! get a stub so the crate still builds for local development.

pub mod nftables;
pub mod status;

use std::process::ExitCode;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::run;

/// Stub for non-Linux dev hosts. NAT requires the Linux netfilter stack.
#[cfg(not(target_os = "linux"))]
pub async fn run(_cfg: crate::config::Config) -> ExitCode {
    tracing::error!("--nat mode is only supported on Linux");
    ExitCode::from(1)
}

/// `gust --nat-cleanup`: remove our nftables table(s) and exit. Cross-platform
/// so the flag at least reports a clear error where `nft` is unavailable.
pub fn cleanup_main() -> ExitCode {
    if let Err(e) = nftables::ensure_available() {
        eprintln!("gust: {e}");
        return ExitCode::from(1);
    }
    nftables::delete_table("ip");
    nftables::delete_table("ip6");
    println!(
        "gust: removed nftables table `{}` (ip, ip6) if it was present",
        nftables::TABLE
    );
    ExitCode::SUCCESS
}
