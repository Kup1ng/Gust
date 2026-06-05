# Gust capacity & OS tuning

Target box: **2 vCPU, 2 GB RAM, ~2 Gbit/s aggregate**, many listeners.

## Two independent limits

Throughput and connection *count* are separate constraints:

- **Throughput** is bounded by the link and CPU. At 2 Gbit/s, only a small number
  of connections move data at once — a 4K stream is ~20 Mbit/s, so ~100 active
  streams saturate 2 Gbit/s. Both modes handle 2 Gbit/s comfortably on 2 cores
  (NAT in-kernel; userspace ≈ 250 MB/s through 32 KiB buffers is a modest syscall
  rate on a 2-worker runtime).
- **Connection count** is bounded by per-connection *state memory*. This is where
  the mode you choose matters.

## Userspace mode memory

Per relayed TCP connection: `2 × relay_buffer` (one per direction, held for the
connection lifetime) + ~4 KiB task/heap + **kernel socket buffers for two
sockets** (accepted + dialed). The kernel buffers — not the relay buffers — are
the real wall, and TCP autotuning will blow the budget unless capped (see the
`tcp_rmem`/`tcp_wmem` values in `deploy/99-gust.conf`).

| relay buf / dir | userspace / conn | ~idle conns in 1.5 GiB |
| --------------- | ---------------- | ---------------------- |
| 8 KiB           | ~20 KiB          | ~30k–43k               |
| 16 KiB          | ~36 KiB          | ~23k–30k               |
| 32 KiB (default)| ~68 KiB          | ~15k–18k               |

Tune with `--buf-size-kb` (per direction). **Hundreds of thousands of live
userspace-relayed connections do not fit in 2 GB** — 300k × 64 KiB of relay
buffers alone is ~19 GiB. Userspace mode tops out around 15k–18k connections at
the default 32 KiB buffer.

## NAT mode memory

In `--nat` mode packets never enter userspace, so per-connection userspace memory
is ≈ 0. The only cost is the kernel conntrack entry (~320 B each):

- 300k tracked connections ≈ **~100 MiB**
- `nf_conntrack_max = 524288` worst case ≈ **~160 MiB**

This is how hundreds of thousands of connections fit in 2 GB — they must run in
NAT mode (which is also why NAT can't do SOCKS5: there is no userspace relay to
speak the protocol).

## Ephemeral-port honesty

In **userspace** mode Gust is the client to a single `DEST:port`, so concurrent
outbound flows are bounded by the `(src_ip, src_port, dst_ip, dst_port)` tuple —
about **64k per (source IP → backend)**.

**NAT mode does not escape this.** Because we masquerade for the remote backend's
return path, conntrack enforces the same ~64k-per-(Gust IP, backend) ceiling.
NAT's advantage is *memory per connection*, not the port limit. To exceed ~64k
concurrent flows you must spread across multiple backends and/or multiple source
IPs. Mitigations: widen `ip_local_port_range`, set `tcp_tw_reuse=1`, use multiple
backends, and (already enabled) `masquerade fully-random` to reduce source-port
insertion races.

## Applying the tuning

```sh
sudo cp deploy/99-gust.conf /etc/sysctl.d/99-gust.conf
sudo sysctl --system

# NAT mode only:
sudo cp deploy/nf_conntrack.conf /etc/modprobe.d/nf_conntrack.conf
# reboot or: sudo modprobe -r nf_conntrack && sudo modprobe nf_conntrack
```

`LimitNOFILE=1048576` is set in `deploy/gust.service` (userspace uses 2 fds per
connection). On a 2 GB box, RAM is the binding constraint long before fds.
