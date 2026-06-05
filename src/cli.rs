//! A small argv scanner that mimics Go's `flag` package closely enough that
//! existing GOST `-L`/`-F` command lines (and the systemd unit invoking them)
//! run against Gust unchanged.
//!
//! Accepted forms per flag: `-X value`, `-X=value`, `--X value`, `--X=value`.
//! Repeated `-L`/`-F` append. Booleans accept a bare form (`--nat`) or
//! `--nat=true/false`. A lone `--` terminates flag parsing.

/// Raw, unvalidated flag values. Turned into a [`crate::config::Config`] by
/// [`crate::config::build_config`].
#[derive(Debug, Default, Clone)]
pub struct RawArgs {
    pub listens: Vec<String>,
    pub forwards: Vec<String>,
    pub mark: Option<i64>,
    pub nat: bool,
    pub set_ip_forward: bool,
    pub nat_cleanup: bool,
    pub buf_size_kb: Option<usize>,
    pub heartbeat_secs: Option<u64>,
    pub debug: bool,
    pub help: bool,
    pub version: bool,
}

/// Outcome of scanning argv.
pub enum ParseOutcome {
    Run(RawArgs),
    Help,
    Version,
}

/// Scan `args` (excluding argv[0]).
pub fn parse_args(args: &[String]) -> Result<ParseOutcome, String> {
    let mut raw = RawArgs::default();
    let mut i = 0;
    let mut no_more_flags = false;

    while i < args.len() {
        let arg = &args[i];
        i += 1;

        if no_more_flags || !arg.starts_with('-') || arg == "-" {
            return Err(format!("unexpected positional argument: `{arg}`"));
        }
        if arg == "--" {
            no_more_flags = true;
            continue;
        }

        // Normalize: strip one or two leading dashes, split inline `=value`.
        let body = arg.trim_start_matches('-');
        let (name, inline) = match body.find('=') {
            Some(eq) => (&body[..eq], Some(body[eq + 1..].to_string())),
            None => (body, None),
        };

        // Helper to fetch a value either from `=value` or the next token.
        let mut take_value = |inline: Option<String>| -> Result<String, String> {
            if let Some(v) = inline {
                return Ok(v);
            }
            if i < args.len() {
                let v = args[i].clone();
                i += 1;
                Ok(v)
            } else {
                Err(format!("flag `-{name}` requires a value"))
            }
        };

        match name {
            "L" => raw.listens.push(take_value(inline)?),
            "F" => raw.forwards.push(take_value(inline)?),
            "M" => {
                let v = take_value(inline)?;
                raw.mark = Some(
                    v.parse::<i64>()
                        .map_err(|_| format!("-M expects an integer (got `{v}`)"))?,
                );
            }
            "buf-size-kb" => {
                let v = take_value(inline)?;
                raw.buf_size_kb = Some(
                    v.parse::<usize>()
                        .map_err(|_| format!("--buf-size-kb expects an integer (got `{v}`)"))?,
                );
            }
            "heartbeat-secs" => {
                let v = take_value(inline)?;
                raw.heartbeat_secs = Some(
                    v.parse::<u64>()
                        .map_err(|_| format!("--heartbeat-secs expects an integer (got `{v}`)"))?,
                );
            }
            "nat" => raw.nat = parse_bool(name, inline)?,
            "set-ip-forward" => raw.set_ip_forward = parse_bool(name, inline)?,
            "nat-cleanup" => raw.nat_cleanup = parse_bool(name, inline)?,
            "D" | "debug" => raw.debug = parse_bool(name, inline)?,
            "h" | "help" => return Ok(ParseOutcome::Help),
            "V" | "version" => return Ok(ParseOutcome::Version),
            other => return Err(format!("unknown flag: `-{other}`")),
        }
    }

    if raw.help {
        return Ok(ParseOutcome::Help);
    }
    if raw.version {
        return Ok(ParseOutcome::Version);
    }
    Ok(ParseOutcome::Run(raw))
}

/// Booleans: a bare flag is `true`; `=true`/`=false` (and `1`/`0`) are honored.
fn parse_bool(name: &str, inline: Option<String>) -> Result<bool, String> {
    match inline {
        None => Ok(true),
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(format!("--{name} expects a boolean (got `{v}`)")),
        },
    }
}

/// The `--help` text, modeled on GOST's flag layout for the supported subset.
pub fn help_text() -> String {
    format!(
        "gust {ver} — a focused TCP/UDP port forwarder with SOCKS5 chaining\n\
         \n\
         USAGE:\n\
         \x20 gust -L=PROTO://[BIND]/DEST [-L=...] [-F=socks5://user:pass@host:port ...] [--nat]\n\
         \n\
         FORWARDING:\n\
         \x20 -L=tcp://:PORT/HOST:PORT     forward a TCP port (repeatable)\n\
         \x20 -L=udp://:PORT/HOST:PORT     forward a UDP port (repeatable)\n\
         \x20 -F=socks5://u:p@host:port    chain through a SOCKS5 hop (repeatable, TCP only)\n\
         \n\
         MODE:\n\
         \x20 --nat                        program in-kernel DNAT instead of userspace relay\n\
         \x20                              (every -L becomes kernel NAT; incompatible with -F)\n\
         \x20 --set-ip-forward             set net.ipv4.ip_forward=1 at start, restore on exit\n\
         \x20 --nat-cleanup               remove Gust's nftables table and exit\n\
         \n\
         TUNING:\n\
         \x20 --buf-size-kb=N              relay buffer per direction in KiB (default 32)\n\
         \x20 --heartbeat-secs=N           heartbeat log interval (default 60)\n\
         \x20 -M=N                         SO_MARK for outbound sockets\n\
         \n\
         MISC:\n\
         \x20 -D, --debug                  verbose logging\n\
         \x20 -h, --help                   show this help\n\
         \x20 -V, --version                show version\n",
        ver = env!("CARGO_PKG_VERSION"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> RawArgs {
        let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        match parse_args(&v).unwrap() {
            ParseOutcome::Run(r) => r,
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn eq_form() {
        let r = run(&["-L=tcp://:8080/1.2.3.4:9090"]);
        assert_eq!(r.listens, vec!["tcp://:8080/1.2.3.4:9090".to_string()]);
    }

    #[test]
    fn space_form() {
        let r = run(&["-L", "tcp://:8080/1.2.3.4:9090"]);
        assert_eq!(r.listens.len(), 1);
    }

    #[test]
    fn double_dash_form() {
        let r = run(&["--nat", "--L=tcp://:8080/1.2.3.4:9090"]);
        assert!(r.nat);
        assert_eq!(r.listens.len(), 1);
    }

    #[test]
    fn repeated_listens_and_forwards() {
        let r = run(&[
            "-L=tcp://:8080/1.2.3.4:9090",
            "-L=udp://:5300/8.8.8.8:53",
            "-F=socks5://u:p@h1:1080",
            "-F=socks5://h2:1080",
        ]);
        assert_eq!(r.listens.len(), 2);
        assert_eq!(r.forwards.len(), 2);
    }

    #[test]
    fn value_with_equals_in_query() {
        // Only the first '=' splits name/value; query '=' is preserved.
        let r = run(&["-L=tcp://:8080/1.2.3.4:9090?nodelay=true"]);
        assert_eq!(r.listens[0], "tcp://:8080/1.2.3.4:9090?nodelay=true");
    }

    #[test]
    fn mark_and_buf() {
        let r = run(&["-L=tcp://:8080/1.2.3.4:9090", "-M=100", "--buf-size-kb=16"]);
        assert_eq!(r.mark, Some(100));
        assert_eq!(r.buf_size_kb, Some(16));
    }

    #[test]
    fn bool_explicit_false() {
        let r = run(&["-L=tcp://:8080/1.2.3.4:9090", "--nat=false"]);
        assert!(!r.nat);
    }

    #[test]
    fn unknown_flag_errors() {
        let v = vec!["--bogus".to_string()];
        assert!(parse_args(&v).is_err());
    }

    #[test]
    fn missing_value_errors() {
        let v = vec!["-L".to_string()];
        assert!(parse_args(&v).is_err());
    }

    #[test]
    fn help_short_circuits() {
        let v = vec!["-h".to_string()];
        assert!(matches!(parse_args(&v).unwrap(), ParseOutcome::Help));
    }
}
