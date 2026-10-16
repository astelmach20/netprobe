# netprobe

Finds where your network is slow, and when. macOS only; one Python file, standard library only, no root needed.

```
$ ./netprobe.py check

Connection
  en0  Wi-Fi 802.11ax, channel 69 (6GHz, 160MHz), -54 dBm, SNR 37 dB, link 1152 Mbps
  path   this Mac → router 192.168.1.1 → ISP edge 203.0.113.1 → internet 1.1.1.1
  DNS    1.0.0.1, 1.1.1.1

Measuring (~61s): idle, then saturating download, upload, both
  idle      done
  download  done  ↓ 233 Mbps
  upload    done  ↑ 23 Mbps
  both      done  ↓ 227 Mbps  ↑ 22 Mbps

Latency by segment (ms: median / 95th percentile, loss)
                            idle              download          upload            both
  Router (Wi-Fi/LAN)        3.6 / 5.1         4.7 / 7.1         4.1 / 6.7         4.6 / 6.5
  ISP network               14 / 17           41 / 46           218 / 236         245 / 273
  Internet (1.1.1.1)        14 / 19           40 / 52           219 / 240         235 / 272
  zoom.us (tcp)             17 / 25           48 / 67           219 / 238         246 / 272

Findings
  ✗ Upload: +205 ms under load (grade D)
    Bufferbloat: the delay builds between your router and the ISP's network (your modem's queue
    or the access line). Fix: smart queue management (fq_codel/CAKE, "SQM", "Smart Queues") on a
    router you control, shaped to about 90% of measured speed (upload ~21 Mbps).
  ! Real apps feel it: connecting to zoom.us took 246 ms during both load vs 17 ms unloaded
  ✓ Strong Wi-Fi signal (-54 dBm, SNR 37 dB)
  ✓ Router hop clean (3.6 ms, 0.9 ms jitter)
  ✓ Download: +27 ms under load (grade A)
```

The Wi-Fi hop stays at 4 ms while the first ISP router jumps to 218 ms under upload, so the problem is the gateway's upload queue, not Wi-Fi or the ISP.

Speed tests give you one snapshot against one server. netprobe also covers what they leave out:

| Gap in typical testers | What netprobe does |
|---|---|
| Can't say *where* the delay is | Probes each segment separately: this Mac → router (Wi-Fi/LAN) → first ISP router → internet. Delay or loss is blamed on the segment where it starts. |
| One-off snapshot | `monitor` samples every second into SQLite; `report` shows a timeline, an hour-of-day pattern and a list of incidents |
| No loss or jitter | Loss %, p50/p95/p99 and jitter for every segment |
| Unrealistic load | Idle, then saturating download, upload and both at once (RRUL-style), with latency measured throughout |
| Only tests its own server | Times DNS, TCP, TLS and first byte to the sites you actually use, and TCP connect times to them under load |
| Assumes "idle" is idle | Detects when something else was already using the line and measures against best-case latency instead |

## Usage

```bash
./netprobe.py check            # ~60 s diagnosis (uses roughly 1 GB of data)
./netprobe.py check --quick    # shorter phases
./netprobe.py check --no-load  # latency/loss only, no data use
./netprobe.py monitor          # sample continuously (Ctrl-C to stop)
./netprobe.py report --since 24h
./netprobe.py agent install    # run monitor in the background, also after login
./netprobe.py agent status
./netprobe.py agent uninstall
```

Destinations default to google.com, github.com, apple.com and zoom.us. Override in `~/.netprobe/config.json`:

```json
{"destinations": ["github.com", "slack.com", "meet.google.com"]}
```

Data lives in `~/.netprobe/` (database `netprobe.db`, kept 30 days).

## How it works

- **Router and internet:** ICMP echo over an unprivileged datagram socket. The internet anchor is 1.1.1.1.
- **ISP router:** many ISP routers ignore pings sent to them but answer traceroute probes. netprobe finds the first ISP hop with an ICMP traceroute (skipping your gateway's own WAN address) and times its TTL-exceeded replies. These routers rate-limit such replies, so loss reported at that hop is ignored when assigning blame.
- **Destinations:** timed TCP handshakes to port 443, because many hosts drop ICMP.
- **Load:** parallel HTTPS streams to Apple's networkQuality servers (`mensura.cdn-apple.com`), the same servers `networkQuality` uses.
- **Blame:** when latency or loss rises at the internet anchor, the segment that accounts for at least half of the rise gets the blame. A rise at the ISP hop but not at the router means the gateway's queue or the access line (bufferbloat). A rise only past the ISP hop means ISP or upstream congestion.

## License

MIT. See [LICENSE](LICENSE).
