# netprobe

Finds where your network is slow, and when. Runs on macOS and Linux; one Python file, standard library only, no root needed.

```bash
pipx install git+https://github.com/astelmach20/netprobe
netprobe check
```

```
$ netprobe check

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
| Can't say *where* the delay is | Probes each segment separately: this computer → router (Wi-Fi/LAN) → first ISP router → internet. Delay or loss is blamed on the segment where it starts. |
| One-off snapshot | `monitor` samples every second into SQLite; `report` shows a timeline, an hour-of-day pattern and a list of incidents |
| No loss or jitter | Loss %, p50/p95/p99 and jitter for every segment |
| Unrealistic load | Idle, then saturating download, upload and both at once (RRUL-style), with latency measured throughout |
| Only tests its own server | Times DNS, TCP, TLS and first byte to the sites you actually use, and TCP connect times to them under load |
| Assumes "idle" is idle | Detects when something else was already using the line and measures against best-case latency instead |

## Install

Needs Python 3.10 or newer.

```bash
pipx install git+https://github.com/astelmach20/netprobe
```

`pipx upgrade netprobe` updates it. Without pipx, `pip install --user git+https://github.com/astelmach20/netprobe` also works, or download [`netprobe.py`](netprobe.py) and run it directly (`python3 netprobe.py check`); it has no dependencies.

## Usage

```bash
netprobe check            # ~60 s diagnosis (uses roughly 1 GB of data)
netprobe check --quick    # shorter phases
netprobe check --no-load  # latency/loss only, no data use
netprobe monitor          # sample continuously (Ctrl-C to stop)
netprobe report --since 24h
netprobe agent install    # run monitor in the background, also after login
netprobe agent status
netprobe agent uninstall
```

The agent runs a copy of netprobe from `~/.netprobe/`, so run `netprobe agent install` again after upgrading.

Destinations default to google.com, github.com, apple.com and zoom.us. Override in `~/.netprobe/config.json`:

```json
{"destinations": ["github.com", "slack.com", "meet.google.com"]}
```

Data lives in `~/.netprobe/` (database `netprobe.db`, kept 30 days).

## Linux

Works the same as on macOS, with these differences:

- **ICMP permission:** netprobe pings without root through Linux "ping sockets", which the kernel allows only for groups listed in `net.ipv4.ping_group_range`. Most current distributions (Fedora, Ubuntu, Debian, Arch, anything on systemd 243+) already allow every group. If yours doesn't, netprobe exits with the exact fix:
  ```bash
  sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'
  echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/60-netprobe.conf
  ```
- **Route and DNS:** default route from `ip route` (or `/proc/net/route`), DNS servers from `/etc/resolv.conf`, or from `resolvectl` when systemd-resolved's local stub is in use.
- **Wi-Fi:** signal, channel and link rate come from `iw` (install the `iw` package if you want them). `iw` doesn't report the noise floor, so there's no SNR and the signal rating uses dBm alone. Without `iw`, Wi-Fi details are skipped.
- **Real-destination timings** (DNS/TCP/TLS/first byte) use `curl`; without it those rows show as failed and everything else still works.
- **Agent:** `netprobe agent install` writes a systemd user unit, `~/.config/systemd/user/netprobe.service`. It runs while you are logged in; to keep it running after you log out, run `loginctl enable-linger $USER`.

## How it works

- **Router and internet:** ICMP echo over an unprivileged datagram socket. The internet anchor is 1.1.1.1.
- **ISP router:** many ISP routers ignore pings sent to them but answer traceroute probes. netprobe finds the first ISP hop with an ICMP traceroute (skipping your gateway's own WAN address) and times its TTL-exceeded replies. On Linux it walks the TTLs itself over the same ping socket and reads the TTL-exceeded replies from the socket's error queue, since Linux `traceroute -I` needs root. These routers rate-limit such replies, so loss reported at that hop is ignored when assigning blame.
- **Destinations:** timed TCP handshakes to port 443, because many hosts drop ICMP.
- **Load:** parallel HTTPS streams to Apple's networkQuality servers (`mensura.cdn-apple.com`), the same servers `networkQuality` uses.
- **Blame:** when latency or loss rises at the internet anchor, the segment that accounts for at least half of the rise gets the blame. A rise at the ISP hop but not at the router means the gateway's queue or the access line (bufferbloat). A rise only past the ISP hop means ISP or upstream congestion.

## License

MIT. See [LICENSE](LICENSE).
