# Gust

A lightweight, high-performance TCP/UDP port forwarder with SOCKS5 chaining — a
focused subset of [GOST v2](https://github.com/ginuerzh/gost), used the same way,
plus an opt-in in-kernel NAT mode. Single static binary, no glibc/OpenSSL, no
runtime dependencies (except `nft` when you use `--nat`).

## What it does

- **TCP forwarding** — `-L=tcp://:PORT/DEST_IP:DEST_PORT`
- **UDP forwarding** — `-L=udp://:PORT/DEST_IP:DEST_PORT` (per-client session NAT)
- **SOCKS5 chaining** — `-F=socks5://user:pass@host:port` (username/password auth,
  multiple hops, TCP only)
- **Many listeners** in one process, each supervised independently
- **In-kernel NAT mode** — `--nat` programs nftables DNAT so traffic is forwarded
  entirely in-kernel (iptables-level throughput, ~0 per-connection memory)

The `-L`/`-F` syntax matches GOST v2, so existing commands and systemd units work
unchanged.

### Not in scope

TLS/WS/WSS/gRPC/h2 transports, obfuscation, GOST-v3 relay, DNS, TUN/TAP,
transparent proxy, UDP-over-SOCKS5, and any L7 proxy protocol (run those on the
destination, e.g. with Xray).

## Usage

```sh
# Forward a TCP port to a backend
gust -L=tcp://:8080/1.2.3.4:9090

# Multiple listeners in one process
gust -L=tcp://:8080/1.2.3.4:9090 -L=udp://:5300/8.8.8.8:53

# TCP through a SOCKS5 chain (two hops, with auth)
gust -F=socks5://user:pass@hop1:1080 -F=socks5://hop2:1080 \
     -L=tcp://:8080/example.com:443

# In-kernel NAT (no userspace relay; every -L becomes kernel DNAT)
sudo gust --nat -L=tcp://:8080/1.2.3.4:443 -L=udp://:5300/1.2.3.4:53

# Remove leftover NAT rules manually
sudo gust --nat-cleanup
```

### Flags

| Flag                 | Meaning                                                       |
| -------------------- | ------------------------------------------------------------ |
| `-L=PROTO://[BIND]/DEST` | listener (repeatable); `PROTO` is `tcp` or `udp`         |
| `-F=socks5://u:p@host:port` | SOCKS5 chain hop (repeatable, TCP only)               |
| `--nat`              | program in-kernel DNAT instead of userspace relay (global)   |
| `--set-ip-forward`   | set `net.ipv4.ip_forward=1` at start, restore on exit        |
| `--nat-cleanup`      | remove Gust's nftables table and exit                        |
| `--buf-size-kb=N`    | relay buffer per direction in KiB (default 32)               |
| `--worker-threads=N` | tokio worker threads (default: one per CPU, affinity-aware)  |
| `--nodelay=BOOL`     | TCP_NODELAY on accepted+dialed sockets (default true)        |
| `--so-rcvbuf=BYTES`  | force `SO_RCVBUF` (disables autotuning; default: auto)       |
| `--so-sndbuf=BYTES`  | force `SO_SNDBUF` (disables autotuning; default: auto)       |
| `--heartbeat-secs=N` | heartbeat log interval (default 60)                          |
| `-M=N`               | `SO_MARK` for outbound sockets                               |
| `-D, --debug`        | verbose logging                                              |

### Running several instances on one CPU core

tokio sizes its worker pool from the process's CPU affinity, but to be safe when
pinning multiple `gust` processes to the **same** core (e.g. with `taskset`),
pass `--worker-threads=1` to each so they don't each spawn one worker per machine
CPU and oversubscribe the core. Nothing else in Gust spawns a fixed large thread
pool: one background logging thread per process, no per-connection threads (tasks
only), and the blocking pool is lazy and capped to `2×worker-threads`. IP-literal
targets skip DNS entirely (no `getaddrinfo` blocking threads).

`SIGUSR1` dumps per-tunnel status (userspace: accepted/active/restarts; NAT:
packets/bytes from nftables counters). `SIGINT`/`SIGTERM` shut down gracefully
and remove any NAT rules.

## Modes

**Userspace (default).** Data passes through Gust via `copy_bidirectional` with a
fixed per-connection buffer, so it can do SOCKS5 chaining. This is the default for
every `-L` unless you pass `--nat`. The absence of `-F` does **not** enable NAT.

**NAT (`--nat`, opt-in).** Gust installs nftables DNAT rules and the kernel
forwards packets without them ever entering userspace. Requirements and rules:

- Needs root or `CAP_NET_ADMIN`, the `nft` binary, and `net.ipv4.ip_forward=1`.
- Incompatible with `-F` (kernel DNAT can't speak SOCKS5) — rejected at startup.
- Global: every `-L` becomes kernel DNAT. To mix userspace and NAT, run two units.
- Rules live in a dedicated `table ip gust` (and `ip6` if needed) and are removed
  on shutdown. A startup pre-clean and the `ExecStopPost` in `deploy/gust.service`
  guarantee no orphan rules even after a hard crash.

See [`docs/tuning.md`](docs/tuning.md) for the capacity math (how many connections
fit in 2 GB, the ephemeral-port ceiling, and why hundreds of thousands of
connections must run in NAT mode) and `deploy/` for the systemd unit and sysctl.

## Install

Download `gust-amd64` or `gust-arm64` from the
[releases](https://github.com/Kup1ng/Gust/releases), then:

```sh
sudo install -m 0755 gust-amd64 /usr/local/bin/gust
```

Both are fully static musl binaries (`x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`).

## Build from source

```sh
cargo build --release                      # native
cross build --release --target x86_64-unknown-linux-musl   # static musl
```

## License

[MIT](LICENSE).
