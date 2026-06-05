//! Gust — a focused, GOST-v2-compatible TCP/UDP port forwarder.
//!
//! Thin binary wrapper: argument parsing, runtime bootstrap, and dispatch into
//! the `gust` library. See `README.md` for usage.

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::process::ExitCode;

use gust::cli::{self, ParseOutcome};
use gust::config;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let raw = match cli::parse_args(&args) {
        Ok(ParseOutcome::Run(raw)) => raw,
        Ok(ParseOutcome::Help) => {
            print!("{}", cli::help_text());
            return ExitCode::SUCCESS;
        }
        Ok(ParseOutcome::Version) => {
            println!("gust {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("gust: {e}");
            eprintln!("try `gust --help`");
            return ExitCode::from(2);
        }
    };

    if raw.nat_cleanup {
        return gust::nat::cleanup_main();
    }

    let cfg = match config::build_config(raw) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gust: {e}");
            return ExitCode::from(2);
        }
    };

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(n) = cfg.worker_threads {
        // Explicit cap so several processes pinned to one core don't each spawn
        // one worker per machine CPU. Also bound the blocking pool accordingly.
        builder.worker_threads(n);
        builder.max_blocking_threads((n * 2).max(2));
    }
    let rt = match builder.build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("gust: failed to start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    rt.block_on(gust::app::run(cfg))
}
