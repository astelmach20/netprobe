#!/usr/bin/env python3
"""netprobe: find out where your network is slow, and when.

Commands:
  check     one-shot diagnosis: latency, jitter and loss per path segment,
            idle and under download/upload/bidirectional load
  monitor   sample the path continuously into a local database
  report    summarize what monitor recorded: timeline, incidents, who to blame
  agent     install or remove a launchd agent that runs monitor in the background

The path is split into segments so problems can be located:
  this Mac -> router (Wi-Fi/LAN) -> ISP edge (first hop past the router) -> internet
"""

import argparse
import http.client
import json
import math
import os
import plistlib
import random
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

DATA_DIR = os.path.expanduser('~/.netprobe')
DB_PATH = os.path.join(DATA_DIR, 'netprobe.db')
CONFIG_PATH = os.path.join(DATA_DIR, 'config.json')
AGENT_LABEL = 'com.netprobe.monitor'
AGENT_PLIST = os.path.expanduser(f'~/Library/LaunchAgents/{AGENT_LABEL}.plist')

# Apple's networkQuality servers: built for saturation tests, no per-request cap
LOAD_HOST = 'mensura.cdn-apple.com'
DOWNLOAD_PATH = '/api/v1/gm/large'
UPLOAD_PATH = '/api/v1/gm/slurp'
UPLOAD_REQUEST_BYTES = 100_000_000
INTERNET_ANCHOR = '1.1.1.1'
DEFAULT_DESTINATIONS = ['google.com', 'github.com', 'apple.com', 'zoom.us']
PROBE_TIMEOUT = 2.0
RETENTION_DAYS = 30

SEGMENT_LABELS = {'gateway': 'Router (Wi-Fi/LAN)', 'isp': 'ISP network', 'internet': f'Internet ({INTERNET_ANCHOR})'}
PHASES = [('idle', ()), ('download', ('down',)), ('upload', ('up',)), ('both', ('down', 'up'))]


# ---------------------------------------------------------------- output

COLOR = sys.stdout.isatty() and not os.environ.get('NO_COLOR')


def style(text, code):
    return f'\033[{code}m{text}\033[0m' if COLOR else str(text)


def bold(t): return style(t, '1')
def dim(t): return style(t, '2')
def red(t): return style(t, '31')
def green(t): return style(t, '32')
def yellow(t): return style(t, '33')


def fmt_ms(ms):
    if ms is None:
        return '—'
    return f'{ms:.1f}' if ms < 10 else f'{ms:.0f}'


def pad(text, width):
    """Left-justify text that may contain ANSI codes."""
    visible = len(re.sub(r'\033\[[0-9;]*m', '', text))
    return text + ' ' * max(0, width - visible)


def live(line):
    if sys.stdout.isatty():
        sys.stdout.write('\r\033[K' + line)
        sys.stdout.flush()


# ---------------------------------------------------------------- stats

@dataclass
class Stats:
    sent: int
    lost: int
    min: float | None = None
    p50: float | None = None
    p95: float | None = None
    p99: float | None = None
    max: float | None = None
    jitter: float | None = None

    @property
    def loss_pct(self):
        return 100.0 * self.lost / self.sent if self.sent else 0.0


def percentile(sorted_vals, q):
    return sorted_vals[min(len(sorted_vals) - 1, round(q * (len(sorted_vals) - 1)))]


def summarize(rtts):
    """rtts: chronological list of RTTs in ms, None for a lost probe."""
    got = [r for r in rtts if r is not None]
    stats = Stats(sent=len(rtts), lost=len(rtts) - len(got))
    if got:
        s = sorted(got)
        stats.min, stats.max = s[0], s[-1]
        stats.p50, stats.p95, stats.p99 = percentile(s, 0.5), percentile(s, 0.95), percentile(s, 0.99)
        # RFC 3550-style jitter: mean change between consecutive replies
        stats.jitter = sum(abs(b - a) for a, b in zip(got, got[1:])) / (len(got) - 1) if len(got) > 1 else 0.0
    return stats


def baseline(stats, name, phases):
    """Unloaded latency for a target. Normally the idle median, but if the line
    was already busy during the idle phase, fall back to the best RTT seen."""
    idle = stats.get((name, 'idle'))
    floors = [s.min for p in phases if (s := stats.get((name, p))) and s.min is not None]
    if not floors:
        return None
    floor = min(floors)
    return min(idle.p50, floor + 10) if idle and idle.p50 is not None else floor + 10


def grade(added_ms):
    for limit, letter in ((5, 'A+'), (30, 'A'), (60, 'B'), (200, 'C'), (400, 'D')):
        if added_ms < limit:
            return letter
    return 'F'


# ---------------------------------------------------------------- environment

def run(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ''


def default_route():
    out = run(['route', '-n', 'get', 'default'])
    gw = re.search(r'gateway:\s*(\S+)', out)
    iface = re.search(r'interface:\s*(\S+)', out)
    return (gw.group(1) if gw else None), (iface.group(1) if iface else None)


def public_ip():
    out = run(['curl', '-s', '--max-time', '5', f'https://{INTERNET_ANCHOR}/cdn-cgi/trace'], timeout=10)
    m = re.search(r'^ip=(\S+)', out, re.M)
    return m.group(1) if m else None


def find_isp_hop(gateway):
    """First ISP router that answers traceroute: (ip, hop number).

    Skips the gateway's own WAN address (it shows up as a hop on many ISP
    gateways) and private home-router ranges (double NAT)."""
    skip = {gateway, INTERNET_ANCHOR, public_ip()}
    # ICMP traceroute, so the hop count matches the path our ICMP probes take
    out = run(['traceroute', '-I', '-n', '-m', '10', '-q', '1', '-w', '1', INTERNET_ANCHOR], timeout=30)
    for line in out.splitlines():
        m = re.match(r'\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)', line)
        if not m or m.group(2) in skip:
            continue
        if re.match(r'192\.168\.|172\.(1[6-9]|2\d|3[01])\.', m.group(2)):
            continue
        return m.group(2), int(m.group(1))
    return None, None


def dns_servers():
    servers = []
    for m in re.finditer(r'nameserver\[\d+\]\s*:\s*(\S+)', run(['scutil', '--dns'])):
        if m.group(1) not in servers:
            servers.append(m.group(1))
    return servers


def wifi_info():
    out = run(['system_profiler', 'SPAirPortDataType', '-json'], timeout=30)
    try:
        interfaces = json.loads(out)['SPAirPortDataType'][0]['spairport_airport_interfaces']
    except (ValueError, KeyError, IndexError):
        return None
    for iface in interfaces:
        cur = iface.get('spairport_current_network_information')
        if not cur:
            continue
        m = re.match(r'(-?\d+) dBm / (-?\d+) dBm', cur.get('spairport_signal_noise', ''))
        return {
            'interface': iface.get('_name'),
            'phy': cur.get('spairport_network_phymode'),
            'channel': cur.get('spairport_network_channel'),
            'rate': cur.get('spairport_network_rate'),
            'rssi': int(m.group(1)) if m else None,
            'noise': int(m.group(2)) if m else None,
        }
    return None


def resolve(host):
    try:
        return socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except OSError:
        return None


def curl_timings(host):
    """DNS, TCP, TLS and first-byte times for a real HTTPS request, in ms."""
    out = run(['curl', '-s', '-o', '/dev/null', '--max-time', '10', '-w', '%{json}', f'https://{host}/'], timeout=15)
    try:
        d = json.loads(out)
    except ValueError:
        return None
    if not d.get('http_code'):
        return None
    ms = lambda k: d[k] * 1000
    return {
        'dns': ms('time_namelookup'),
        'tcp': ms('time_connect') - ms('time_namelookup'),
        'tls': ms('time_appconnect') - ms('time_connect'),
        'ttfb': ms('time_starttransfer') - ms('time_appconnect'),
        'total': ms('time_starttransfer'),
    }


def load_config():
    cfg = {'destinations': DEFAULT_DESTINATIONS}
    try:
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        pass
    except ValueError as e:
        print(yellow(f'Ignoring {CONFIG_PATH}: {e}'), file=sys.stderr)
    return cfg


# ---------------------------------------------------------------- probing

@dataclass
class Target:
    name: str       # 'gateway', 'isp', 'internet', or a destination hostname
    host: str       # IPv4 address expected to answer
    kind: str       # 'icmp' or 'tcp'
    interval: float
    port: int = 443
    ttl: int | None = None  # set: send toward INTERNET_ANCHOR and time the hop's TTL-exceeded reply
    next_at: float = 0.0


def path_targets(gateway, isp, isp_hop, interval):
    targets = []
    if gateway:
        targets.append(Target('gateway', gateway, 'icmp', interval))
    if isp:
        # ISP routers often drop pings addressed to them but still answer
        # traceroute-style probes, so reach the hop by TTL instead. They also
        # rate-limit those replies, so probe gently and never trust its loss.
        targets.append(Target('isp', isp, 'icmp', max(interval, 1.0), ttl=isp_hop))
    targets.append(Target('internet', INTERNET_ANCHOR, 'icmp', interval))
    return targets


def ip_header_len(data):
    return (data[0] & 0x0F) * 4 if data and data[0] >> 4 == 4 else 0


def icmp_checksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack(f'!{len(data) // 2}H', data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class Prober:
    """Pings each target on its own interval: ICMP echo over an unprivileged
    datagram socket, or a timed TCP handshake for hosts that drop ICMP."""

    def __init__(self, targets, on_sample):
        self.targets = targets
        self.on_sample = on_sample  # (wall_ts, target_name, rtt_ms | None)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._pending = {}  # seq -> (name, ip, sent_monotonic, sent_wall)
        self._ident = os.getpid() & 0xFFFF
        self._seq = random.randrange(0x10000)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        self._sock.settimeout(0.2)
        self._tcp_pool = ThreadPoolExecutor(max_workers=8)
        self._threads = [threading.Thread(target=self._send_loop, daemon=True),
                         threading.Thread(target=self._recv_loop, daemon=True)]

    def start(self):
        for t in self._threads:
            t.start()

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self._tcp_pool.shutdown(wait=False, cancel_futures=True)
        self._sock.close()

    def set_targets(self, targets):
        with self._lock:
            self.targets = targets

    def _send_loop(self):
        while not self._stop.is_set():
            now = time.monotonic()
            with self._lock:
                targets = list(self.targets)
            for t in targets:
                if now >= t.next_at:
                    t.next_at = max(t.next_at + t.interval, now)
                    if t.kind == 'icmp':
                        self._send_icmp(t)
                    else:
                        self._tcp_pool.submit(self._tcp_probe, t)
            self._expire(now)
            self._stop.wait(0.01)

    def _send_icmp(self, t):
        with self._lock:
            self._seq = seq = (self._seq + 1) & 0xFFFF
            self._pending[seq] = (t.name, t.host, time.monotonic(), time.time())
        payload = b'netprobe' + bytes(24)
        header = struct.pack('!BBHHH', 8, 0, 0, self._ident, seq)
        packet = struct.pack('!BBHHH', 8, 0, icmp_checksum(header + payload), self._ident, seq) + payload
        try:
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, t.ttl or 64)
            self._sock.sendto(packet, (INTERNET_ANCHOR if t.ttl else t.host, 0))
        except OSError:  # no route, interface down: count as lost
            with self._lock:
                entry = self._pending.pop(seq, None)
            if entry:
                self.on_sample(entry[3], entry[0], None)

    def _recv_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                time.sleep(0.1)
                continue
            now = time.monotonic()
            # macOS hands datagram ICMP sockets the IP header too
            offset = ip_header_len(data)
            if len(data) < offset + 8:
                continue
            kind, _, _, ident, seq = struct.unpack('!BBHHH', data[offset:offset + 8])
            ttl_reply = kind == 11
            if ttl_reply:  # TTL exceeded: our original echo header is quoted after the inner IP header
                inner = offset + 8
                inner += ip_header_len(data[inner:])
                if len(data) < inner + 8:
                    continue
                kind, _, _, ident, seq = struct.unpack('!BBHHH', data[inner:inner + 8])
                kind = 0 if kind == 8 else kind
            if kind != 0 or ident != self._ident:
                continue
            with self._lock:
                entry = self._pending.get(seq)
                # ISP hops are often load-balanced pairs, so any router at that TTL counts
                if not entry or (not ttl_reply and entry[1] != addr[0]):
                    continue
                del self._pending[seq]
            self.on_sample(entry[3], entry[0], (now - entry[2]) * 1000)

    def _expire(self, now):
        with self._lock:
            expired = [(seq, e) for seq, e in self._pending.items() if now - e[2] > PROBE_TIMEOUT]
            for seq, _ in expired:
                del self._pending[seq]
        for _, e in expired:
            self.on_sample(e[3], e[0], None)

    def _tcp_probe(self, t):
        wall, start = time.time(), time.monotonic()
        try:
            with socket.create_connection((t.host, t.port), timeout=PROBE_TIMEOUT):
                rtt = (time.monotonic() - start) * 1000
        except OSError:
            rtt = None
        if not self._stop.is_set():
            self.on_sample(wall, t.name, rtt)


class Collector:
    def __init__(self):
        self._lock = threading.Lock()
        self.samples = []  # (wall_ts, name, rtt)

    def add(self, ts, name, rtt):
        with self._lock:
            self.samples.append((ts, name, rtt))

    def window(self, name, t0, t1):
        with self._lock:
            return [r for ts, n, r in sorted(self.samples) if n == name and t0 <= ts < t1]

    def latest(self, name):
        with self._lock:
            for _, n, r in reversed(self.samples):
                if n == name and r is not None:
                    return r
        return None


# ---------------------------------------------------------------- load generation

class Load:
    """Saturates one direction with parallel HTTPS streams to Cloudflare."""

    def __init__(self, direction, streams=4):
        self.direction = direction
        self.streams = streams
        self.bytes = 0
        self.errors = 0
        self.last_error = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._conns = set()
        self._threads = []

    def start(self):
        for _ in range(self.streams):
            t = threading.Thread(target=self._run, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop.set()
        with self._lock:
            conns = list(self._conns)
        for conn in conns:
            self._abort(conn)
        for t in self._threads:
            t.join(timeout=3)

    @staticmethod
    def _abort(conn):
        # RST instead of FIN so data queued in the send buffer is dropped,
        # not drained into the next measurement phase
        sock = conn.sock
        if sock:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            except OSError:
                pass
        conn.close()

    def _add(self, n):
        with self._lock:
            self.bytes += n

    def _run(self):
        while not self._stop.is_set():
            conn = http.client.HTTPSConnection(LOAD_HOST, timeout=5)
            with self._lock:
                self._conns.add(conn)
            try:
                if self.direction == 'down':
                    self._download(conn)
                else:
                    self._upload(conn)
            except (OSError, http.client.HTTPException, AttributeError) as e:
                if not self._stop.is_set():
                    self.errors += 1
                    self.last_error = str(e) or type(e).__name__
                    self._stop.wait(0.5)
            finally:
                with self._lock:
                    self._conns.discard(conn)
                self._abort(conn)

    def _download(self, conn):
        buf = memoryview(bytearray(256 * 1024))
        while not self._stop.is_set():  # back-to-back requests on one kept-alive connection
            conn.request('GET', DOWNLOAD_PATH)
            resp = conn.getresponse()
            if resp.status != 200:
                raise http.client.HTTPException(f'HTTP {resp.status}')
            while not self._stop.is_set() and (n := resp.readinto(buf)):
                self._add(n)

    def _upload(self, conn):
        chunk = bytes(64 * 1024)
        while not self._stop.is_set():
            conn.putrequest('POST', UPLOAD_PATH)
            conn.putheader('Content-Type', 'application/octet-stream')
            conn.putheader('Content-Length', str(UPLOAD_REQUEST_BYTES))
            conn.endheaders()
            sent = 0
            while not self._stop.is_set() and sent < UPLOAD_REQUEST_BYTES:
                n = min(len(chunk), UPLOAD_REQUEST_BYTES - sent)
                conn.send(chunk[:n])
                sent += n
                self._add(n)
            if sent < UPLOAD_REQUEST_BYTES:
                return
            resp = conn.getresponse()
            resp.read()
            if resp.status != 200:
                raise http.client.HTTPException(f'HTTP {resp.status}')


# ---------------------------------------------------------------- check

def run_phase(name, directions, duration, collector):
    """Runs one phase; returns the (t0, t1) sample window and Mbps per direction."""
    loads = [Load(d) for d in directions]
    for load in loads:
        load.start()
    start = time.time()
    warm = start + (min(3.0, duration / 3) if loads else 0)  # let TCP ramp up and queues fill
    marks, last, rates = {}, {l.direction: (start, 0) for l in loads}, {}
    try:
        while (now := time.time()) < start + duration:
            for l in loads:
                b, (t0, b0) = l.bytes, last[l.direction]
                if now - t0 >= 1:
                    rates[l.direction] = (b - b0) * 8 / (now - t0) / 1e6
                    last[l.direction] = (now, b)
                if now >= warm and l.direction not in marks:
                    marks[l.direction] = (now, b)
            rate_text = '  '.join(f'{"↓" if d == "down" else "↑"} {r:5.0f} Mbps' for d, r in rates.items())
            live(f'  {name:<9} {int(now - start):>3}/{duration}s  latency {fmt_ms(collector.latest("internet")):>5} ms  {rate_text}')
            time.sleep(0.25)
        end = time.time()
        mbps = {l.direction: (l.bytes - marks[l.direction][1]) * 8 / (end - marks[l.direction][0]) / 1e6
                for l in loads if l.direction in marks and end > marks[l.direction][0]}
    finally:
        for load in loads:
            load.stop()
    live('')
    for l in loads:
        if l.bytes == 0:
            print(yellow(f'  {name}: {l.direction}load to {LOAD_HOST} failed ({l.last_error or "no data"})'))
    if loads:
        time.sleep(2)  # let queues drain before the next phase
    return (warm, end), mbps


def print_connection(iface, wifi, gateway, isp, dns):
    print(bold('\nConnection'))
    if wifi:
        snr = wifi['rssi'] - wifi['noise'] if wifi['rssi'] is not None and wifi['noise'] is not None else None
        signal = f'{wifi["rssi"]} dBm, SNR {snr} dB' if snr is not None else 'signal unknown'
        print(f'  {iface}  Wi-Fi {wifi["phy"]}, channel {wifi["channel"]}, {signal}, link {wifi["rate"]} Mbps')
    else:
        print(f'  {iface}  wired or non-Wi-Fi interface')
    hops = [f'router {gateway}', f'ISP edge {isp}' if isp else dim('ISP edge not found'), f'internet {INTERNET_ANCHOR}']
    print(f'  path   this Mac → {" → ".join(hops)}')
    print(f'  DNS    {", ".join(dns) or "unknown"}')


def print_app_timings(rows):
    print(bold('\nReal destinations (idle, ms)'))
    print(dim(f'  {"host":<16}{"DNS":>7}{"TCP":>7}{"TLS":>7}{"server":>8}{"total":>8}'))
    for host, t in rows:
        if t is None:
            print(f'  {host:<16}{red("failed"):>7}')
            continue
        print(f'  {host:<16}{fmt_ms(t["dns"]):>7}{fmt_ms(t["tcp"]):>7}{fmt_ms(t["tls"]):>7}'
              f'{fmt_ms(t["ttfb"]):>8}{fmt_ms(t["total"]):>8}')


def print_latency_table(targets, phases, stats):
    print(bold('\nLatency by segment (ms: median / 95th percentile, loss)'))
    width = 26
    print(dim('  ' + ' ' * width + ''.join(f'{p:<18}' for p in phases)))
    for t in targets:
        label = SEGMENT_LABELS.get(t.name, f'{t.name} (tcp)')
        base = baseline(stats, t.name, phases)
        cells = []
        for p in phases:
            s = stats[(t.name, p)]
            if s.p50 is None:
                cells.append(pad(red('no replies'), 18))
                continue
            text = f'{fmt_ms(s.p50)} / {fmt_ms(s.p95)}'
            added = s.p50 - base
            text = red(text) if added >= 200 else yellow(text) if added >= 30 else text
            if s.loss_pct >= 1:
                # ISP routers throttle replies to probes, so their "loss" isn't real loss
                text += ' ' + (dim(f'{s.loss_pct:.0f}%*') if t.name == 'isp' else red(f'{s.loss_pct:.0f}%'))
            cells.append(pad(text, 18))
        print(f'  {label:<{width}}' + ''.join(cells))
    if any(stats[('isp', p)].loss_pct >= 1 for p in phases if ('isp', p) in stats):
        print(dim('  * ISP routers rate-limit replies to probes; loss shown there is not real packet loss'))


LOCATIONS = {
    'local': 'between this Mac and the router (Wi-Fi or the router itself)',
    'access': "between your router and the ISP's network (your modem's queue or the access line)",
    'upstream': "past your router (your modem's queue, the access line or the ISP; no ISP hop answered to narrow it down)",
    'beyond': "past the first ISP router (congestion in the ISP's network or further upstream)",
}


def locate(seg_rise, net_rise, have_isp):
    """Which segment owns most of a rise in latency or loss seen at the far end."""
    if seg_rise.get('gateway', 0) >= 0.5 * net_rise:
        return 'local'
    if not have_isp:
        return 'upstream'
    if seg_rise.get('isp', 0) >= 0.5 * net_rise:
        return 'access'
    return 'beyond'


def diagnose(stats, phases, wifi, throughput, dest_names, have_isp):
    findings = []  # (level, title, detail)
    get = lambda name, phase: stats.get((name, phase))
    idle_net, idle_gw = get('internet', 'idle'), get('gateway', 'idle')
    idle_isp = get('isp', 'idle') if have_isp else None

    if wifi and wifi['rssi'] is not None and wifi['noise'] is not None:
        rssi, snr = wifi['rssi'], wifi['rssi'] - wifi['noise']
        if rssi < -70 or snr < 20:
            findings.append(('bad', f'Weak Wi-Fi signal ({rssi} dBm, SNR {snr} dB)',
                             'Expect retries, jitter and lower speed. Move closer to the router, remove obstructions, or use Ethernet.'))
        elif rssi < -65 or snr < 25:
            findings.append(('warn', f'Fair Wi-Fi signal ({rssi} dBm, SNR {snr} dB)',
                             'Usable, but a few metres or a wall away from trouble.'))
        else:
            findings.append(('ok', f'Strong Wi-Fi signal ({rssi} dBm, SNR {snr} dB)', None))

    if idle_gw and idle_gw.p50 is not None:
        if idle_gw.p50 > 10 or idle_gw.jitter > 5 or idle_gw.loss_pct >= 1:
            findings.append(('warn', 'Slow or jittery hop to the router',
                             f'{fmt_ms(idle_gw.p50)} ms median, {fmt_ms(idle_gw.jitter)} ms jitter, {idle_gw.loss_pct:.0f}% loss to the router; '
                             'a clean link is 1-4 ms. Usually Wi-Fi interference or a busy router. Ethernet removes it.'))
        else:
            findings.append(('ok', f'Router hop clean ({fmt_ms(idle_gw.p50)} ms, {fmt_ms(idle_gw.jitter)} ms jitter)', None))

    bases = {n: baseline(stats, n, phases) for n in ('gateway', 'isp', 'internet', *dest_names)}
    have_isp = have_isp and bases['isp'] is not None  # a silent hop can't locate anything

    def rises(phase):
        return {n: s.p50 - bases[n] for n in ('gateway', 'isp')
                if (s := get(n, phase)) and s.p50 is not None and bases.get(n) is not None}

    if idle_net and idle_net.p50 is not None:
        if idle_net.loss_pct >= 1:
            # only the router's loss is trustworthy; ISP routers throttle probe replies
            rise = {'gateway': idle_gw.loss_pct} if idle_gw and idle_gw.p50 is not None else {}
            where = 'local' if locate(rise, idle_net.loss_pct, True) == 'local' else 'upstream'
            findings.append(('bad', f'{idle_net.loss_pct:.1f}% packet loss at idle', f'The loss starts {LOCATIONS[where]}.'))
        busy = idle_net.p50 - bases['internet']
        if busy >= 30:
            where = locate(rises('idle'), busy, have_isp)
            findings.append(('bad' if busy >= 100 else 'warn',
                             f'Line was already busy before the test (+{fmt_ms(busy)} ms at "idle")',
                             'Another app or device was using the connection, so everyday latency is worse than the '
                             f'load results below suggest. The delay builds {LOCATIONS[where]}. '
                             'Check for cloud backups, photo sync, game downloads or a busy roommate.'))
        if idle_isp and idle_isp.p50 is not None and bases.get('gateway') is not None:
            access = bases['isp'] - bases['gateway']
            if access > 30:
                findings.append(('warn', f'Slow access line (+{fmt_ms(access)} ms from router to ISP)',
                                 'Typical cable/fiber is under 15 ms; DSL, fixed wireless or satellite are slower.'))

    labels = {'download': 'Download', 'upload': 'Upload', 'both': 'Download + upload'}
    for phase in (p for p in phases if p != 'idle'):
        net = get('internet', phase)
        if not net or net.p50 is None or bases['internet'] is None:
            findings.append(('bad', f'{labels[phase]}: internet stopped answering under load', None))
            continue
        added = max(0.0, net.p50 - bases['internet'])
        letter = grade(added)
        if added < 30:
            findings.append(('ok', f'{labels[phase]}: +{fmt_ms(added)} ms under load (grade {letter})', None))
            continue
        where = locate(rises(phase), added, have_isp)
        level = 'bad' if added >= 200 else 'warn'
        title = f'{labels[phase]}: +{fmt_ms(added)} ms under load (grade {letter})'
        speeds = throughput.get(phase, {})
        shaped = ', '.join(f'{"download" if d == "down" else "upload"} ~{v * 0.9:.0f} Mbps' for d, v in speeds.items())
        sqm = ('Fix: smart queue management (fq_codel/CAKE, "SQM", "Smart Queues") on a router you control, '
               f'shaped to about 90% of measured speed ({shaped}).')
        if where == 'local':
            detail = (f'The delay builds {LOCATIONS[where]}: Wi-Fi airtime contention or the router struggling '
                      'at this speed. Try Ethernet to confirm.')
        elif where == 'access':
            detail = f'Bufferbloat: the delay builds {LOCATIONS[where]}. {sqm}'
        elif where == 'upstream':
            detail = f'The delay builds {LOCATIONS[where]}. A jump this size under your own load is usually bufferbloat. {sqm}'
        else:
            detail = (f'The delay builds {LOCATIONS[where]}. Re-test at a different time; '
                      'if it persists, raise it with your ISP.')
        findings.append((level, title, detail))

    worst = None
    for name in dest_names:
        base = bases.get(name)
        if base is None:
            continue
        for phase in phases[1:]:
            s = get(name, phase)
            if s and s.p50 is not None and (worst is None or s.p50 - base > worst[0]):
                worst = (s.p50 - base, name, phase, base, s.p50)
    if worst and worst[0] >= 30:
        _, name, phase, before, after = worst
        findings.append(('warn', f'Real apps feel it: connecting to {name} took {fmt_ms(after)} ms during {phase} load '
                                 f'vs {fmt_ms(before)} ms unloaded', None))
    return findings


def print_findings(findings):
    print(bold('\nFindings'))
    marks = {'ok': green('✓'), 'warn': yellow('!'), 'bad': red('✗')}
    order = {'bad': 0, 'warn': 1, 'ok': 2}
    for level, title, detail in sorted(findings, key=lambda f: order[f[0]]):
        print(f'  {marks[level]} {title}')
        if detail:
            print(dim(f'    {detail}'))


def cmd_check(args):
    cfg = load_config()
    idle_s, load_s = (5, 8) if args.quick else (args.idle, args.load)
    gateway, iface = default_route()
    if not gateway:
        sys.exit('netprobe: no default route; you appear to be offline.')

    print(bold('netprobe check'))
    live(dim('  Discovering path…'))
    wifi = wifi_info()
    if wifi and wifi['interface'] != iface:
        wifi = None
    isp, isp_hop = find_isp_hop(gateway)
    dests = [(h, ip) for h in cfg['destinations'] if (ip := resolve(h))]
    live(dim('  Timing real requests…'))
    app = [(h, curl_timings(h)) for h, _ in dests]
    live('')
    print_connection(iface, wifi, gateway, isp, dns_servers())
    print_app_timings(app)

    targets = path_targets(gateway, isp, isp_hop, interval=0.2) + [Target(h, ip, 'tcp', 1.0) for h, ip in dests]
    phases = PHASES[:1] if args.no_load else PHASES
    total = idle_s + (0 if args.no_load else 3 * (load_s + 2))
    print(bold(f'\nMeasuring (~{total}s){"" if args.no_load else ": idle, then saturating download, upload, both"}'))

    collector = Collector()
    prober = Prober(targets, collector.add)
    windows, throughput = {}, {}
    prober.start()
    try:
        for name, directions in phases:
            windows[name], throughput[name] = run_phase(name, directions, idle_s if name == 'idle' else load_s, collector)
            rate = '  '.join(f'{"↓" if d == "down" else "↑"} {v:.0f} Mbps' for d, v in throughput[name].items())
            print(f'  {name:<9} done  {rate}')
    except KeyboardInterrupt:
        print('\nInterrupted.')
        return 130
    finally:
        prober.stop()

    phase_names = [p for p, _ in phases]
    stats = {(t.name, p): summarize(collector.window(t.name, *windows[p])) for t in targets for p in phase_names}
    print_latency_table(targets, phase_names, stats)
    if not args.no_load:
        down = throughput.get('download', {}).get('down')
        up = throughput.get('upload', {}).get('up')
        print(bold('\nThroughput  ') + f'↓ {down or 0:.0f} Mbps   ↑ {up or 0:.0f} Mbps')
    print_findings(diagnose(stats, phase_names, wifi, throughput, [h for h, _ in dests], bool(isp)))
    return 0


# ---------------------------------------------------------------- monitor

def open_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS samples (ts REAL NOT NULL, target TEXT NOT NULL, rtt REAL);
        CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);
        CREATE TABLE IF NOT EXISTS wifi (ts REAL NOT NULL, rssi INTEGER, noise INTEGER, rate INTEGER, channel TEXT);
        CREATE TABLE IF NOT EXISTS events (ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT);
    ''')
    return db


def cmd_monitor(args):
    sys.stdout.reconfigure(line_buffering=True)  # status lines reach logs promptly
    cfg = load_config()
    db = open_db()
    cutoff = time.time() - RETENTION_DAYS * 86400
    for table in ('samples', 'wifi', 'events'):
        db.execute(f'DELETE FROM {table} WHERE ts < ?', (cutoff,))
    db.commit()

    lock, buffer, recent = threading.Lock(), [], []

    def on_sample(ts, name, rtt):
        with lock:
            buffer.append((ts, name, rtt))
            recent.append((ts, name, rtt))

    def build_targets(gateway):
        isp, isp_hop = find_isp_hop(gateway) if gateway else (None, None)
        dests = [Target(h, ip, 'tcp', args.interval * 10) for h in cfg['destinations'] if (ip := resolve(h))]
        return path_targets(gateway, isp, isp_hop, args.interval) + dests, isp

    gateway, _ = default_route()
    targets, isp = build_targets(gateway)
    db.execute('INSERT INTO events VALUES (?, ?, ?)', (time.time(), 'start', f'gateway={gateway} isp={isp}'))
    db.commit()
    if not args.quiet:
        print(bold('netprobe monitor') + dim(f'  router {gateway}, ISP edge {isp}, writing to {DB_PATH}  (Ctrl-C to stop)'))

    def on_term(signum, frame):  # launchd stops agents with SIGTERM
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, signal.default_int_handler)  # background shells start us with SIGINT ignored

    prober = Prober(targets, on_sample)
    prober.start()
    next_flush = next_route = next_status = time.time()
    next_wifi = time.time() + 5
    try:
        while True:
            time.sleep(1)
            now = time.time()
            if now >= next_flush:
                with lock:
                    rows, buffer[:] = list(buffer), []
                db.executemany('INSERT INTO samples VALUES (?, ?, ?)', rows)
                db.commit()
                next_flush = now + 5
            if now >= next_route:
                new_gateway, _ = default_route()
                if new_gateway != gateway:
                    gateway = new_gateway
                    targets, isp = build_targets(gateway)
                    prober.set_targets(targets)
                    db.execute('INSERT INTO events VALUES (?, ?, ?)', (now, 'route', f'gateway={gateway} isp={isp}'))
                    if not args.quiet:
                        print(yellow(f'{time.strftime("%H:%M:%S")}  network changed: router {gateway}, ISP edge {isp}'))
                next_route = now + 30
            if now >= next_wifi:
                w = wifi_info()
                if w:
                    db.execute('INSERT INTO wifi VALUES (?, ?, ?, ?, ?)', (now, w['rssi'], w['noise'], w['rate'], w['channel']))
                next_wifi = now + 120
            if not args.quiet and now >= next_status:
                with lock:
                    recent[:] = [s for s in recent if s[0] >= now - 10]
                    window = list(recent)
                parts = []
                for name in ('gateway', 'isp', 'internet'):
                    s = summarize([r for _, n, r in sorted(window) if n == name])
                    if s.sent:
                        text = f'{name} {fmt_ms(s.p50)} ms' + (f' {s.loss_pct:.0f}% loss' if s.lost else '')
                        parts.append(red(text) if s.loss_pct >= 10 else text)
                print(f'{time.strftime("%H:%M:%S")}  ' + '   '.join(parts))
                next_status = now + 10
    except KeyboardInterrupt:
        pass
    finally:
        prober.stop()
        with lock:
            db.executemany('INSERT INTO samples VALUES (?, ?, ?)', buffer)
        db.commit()
        db.close()
    return 0


# ---------------------------------------------------------------- report

SPARKS = '▁▂▃▄▅▆▇█'
BUCKET_SIZES = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]
INCIDENT_WINDOW = 10


def parse_duration(text):
    m = re.fullmatch(r'(\d+)([mhd])', text)
    if not m:
        raise argparse.ArgumentTypeError('use a number followed by m, h or d, e.g. 30m, 24h, 7d')
    return int(m.group(1)) * {'m': 60, 'h': 3600, 'd': 86400}[m.group(2)]


def sparkline(values, lo, hi):
    out = []
    for v in values:
        if v is None:
            out.append(' ')
        elif hi <= lo:
            out.append(SPARKS[0])
        else:
            # log scale: 20 ms vs 40 ms matters as much as 500 ms vs 1000 ms
            f =(math.log(max(v, lo)) - math.log(lo)) / (math.log(hi) - math.log(lo))
            out.append(SPARKS[min(len(SPARKS) - 1, int(f * len(SPARKS)))])
    return ''.join(out)


def loss_marks(pcts):
    out = []
    for p in pcts:
        if p is None:
            out.append(' ')
        elif p == 0:
            out.append(dim('·'))
        elif p < 5:
            out.append(yellow('▪'))
        else:
            out.append(red('█'))
    return ''.join(out)


def find_incidents(series, t_from, t_to):
    """series: target -> [(ts, rtt)]. Flags 10 s windows at the internet anchor."""
    net = series.get('internet', [])
    if not net:
        return []
    baselines = {}
    for name, rows in series.items():
        got = sorted(r for _, r in rows if r is not None)
        baselines[name] = percentile(got, 0.25) if got else None
    base = baselines['internet']
    if base is None:
        return []
    lag_threshold = base + max(50, 2 * base)

    def bucket(rows):
        out = {}
        for ts, r in rows:
            out.setdefault(int((ts - t_from) // INCIDENT_WINDOW), []).append(r)
        return out

    def classify(s):
        if s.loss_pct >= 80:
            return 'outage'
        if s.p50 is not None and s.p50 > lag_threshold:
            return 'lag'  # bufferbloat usually brings a little loss along; latency is the story
        if s.loss_pct >= 10:
            return 'loss'
        return None

    windows = {name: bucket(rows) for name, rows in series.items()}
    incidents = []
    for idx in sorted(windows['internet']):
        s = summarize(windows['internet'][idx])
        if s.sent < 3 or not classify(s):
            continue
        if incidents and idx - incidents[-1]['end'] <= 1:
            incidents[-1]['end'] = idx
        else:
            incidents.append({'start': idx, 'end': idx})

    have_isp = baselines.get('isp') is not None
    for inc in incidents:
        span = range(inc['start'], inc['end'] + 1)
        seg = {name: summarize([r for i in span for r in w.get(i, [])]) for name, w in windows.items()}
        net_s = seg['internet']
        inc['kind'] = classify(net_s) or 'lag'  # a merged run can dilute below thresholds; keep it as lag
        if inc['kind'] == 'lag':
            net_rise = net_s.p50 - base
            rise = {n: seg[n].p50 - baselines[n] for n in ('gateway', 'isp')
                    if n in seg and seg[n].p50 is not None and baselines.get(n) is not None}
            inc['blame'] = locate(rise, net_rise, have_isp)
        else:
            # only the router's loss is trustworthy; ISP routers throttle probe replies
            gw = seg.get('gateway')
            rise = {'gateway': gw.loss_pct} if gw and gw.sent and baselines.get('gateway') is not None else {}
            inc['blame'] = 'local' if locate(rise, net_s.loss_pct, True) == 'local' else 'upstream'
        inc['t0'] = t_from + inc['start'] * INCIDENT_WINDOW
        inc['t1'] = t_from + (inc['end'] + 1) * INCIDENT_WINDOW
        inc['stats'] = net_s
    return incidents


def cmd_report(args):
    if not os.path.exists(DB_PATH):
        sys.exit('netprobe: no data yet. Run `netprobe monitor` or `netprobe agent install` first.')
    db = sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True)
    t_to = time.time()
    t_from = t_to - args.since_seconds
    series = {}
    for ts, target, rtt in db.execute('SELECT ts, target, rtt FROM samples WHERE ts >= ? ORDER BY ts', (t_from,)):
        series.setdefault(target, []).append((ts, rtt))
    if not series:
        sys.exit(f'netprobe: no samples in the last {args.since}. Is monitor running? (`netprobe agent status`)')
    first = min(rows[0][0] for rows in series.values())
    last = max(rows[-1][0] for rows in series.values())
    t_from = first
    span = max(last - first, 60)
    fmt_time = (lambda t: time.strftime('%a %H:%M', time.localtime(t))) if span > 86400 else \
               (lambda t: time.strftime('%H:%M', time.localtime(t)))

    print(bold('netprobe report') + dim(f'  {time.strftime("%b %d %H:%M", time.localtime(first))} → '
                                        f'{time.strftime("%b %d %H:%M", time.localtime(last))}  ({span / 3600:.1f} h)'))

    order = ['gateway', 'isp', 'internet'] + sorted(n for n in series if n not in SEGMENT_LABELS)
    names = [n for n in order if n in series]
    print(bold('\nOverall (ms)'))
    print(dim(f'  {"":<26}{"samples":>9}{"loss":>8}{"median":>8}{"p95":>7}{"p99":>7}{"jitter":>8}'))
    for name in names:
        s = summarize([r for _, r in series[name]])
        loss = f'{s.loss_pct:.2f}%'
        loss = red(f'{loss:>8}') if s.loss_pct >= 1 else f'{loss:>8}'
        print(f'  {SEGMENT_LABELS.get(name, name + " (tcp)"):<26}{s.sent:>9}{loss}'
              f'{fmt_ms(s.p50):>8}{fmt_ms(s.p95):>7}{fmt_ms(s.p99):>7}{fmt_ms(s.jitter):>8}')

    size = next((b for b in BUCKET_SIZES if span / b <= 60), BUCKET_SIZES[-1])
    n_buckets = int(span // size) + 1
    print(bold(f'\nTimeline') + dim(f'  one column = {size // 60} min · bars = 95th-percentile latency (log scale) · '
                                     f'loss: · none ▪ <5% █ ≥5%'))
    p95s = {}
    for name in names:
        buckets = [[] for _ in range(n_buckets)]
        for ts, r in series[name]:
            buckets[min(n_buckets - 1, int((ts - first) // size))].append(r)
        stats = [summarize(b) if b else None for b in buckets]
        p95s[name] = ([s.p95 if s else None for s in stats], [s.loss_pct if s else None for s in stats])
    path_names = [n for n in names if n in SEGMENT_LABELS]
    vals = [v for n in path_names for v in p95s[n][0] if v is not None]
    lo, hi = (max(1.0, min(vals)), max(vals)) if vals else (1.0, 1.0)
    for name in path_names:
        lat, loss = p95s[name]
        label = SEGMENT_LABELS[name]
        print(f'  {label:<26}{sparkline(lat, lo, hi)}')
        print(f'  {"":<26}{loss_marks(loss)}')
    print(dim(f'  {"":<26}{fmt_time(first)}{" " * max(1, n_buckets - 2 * len(fmt_time(first)))}{fmt_time(last)}'))
    print(dim(f'  {"":<26}scale {fmt_ms(lo)}–{fmt_ms(hi)} ms'))

    incidents = find_incidents({n: series[n] for n in path_names}, first, last)
    blame_text = {'local': 'Wi-Fi / router', 'access': 'modem queue / access line',
                  'upstream': 'past the router', 'beyond': 'ISP network or beyond'}
    print(bold(f'\nIncidents ({len(incidents)})'))
    if not incidents:
        print(green('  ✓ none: no outages, loss bursts or lag spikes'))
    else:
        events = list(db.execute('SELECT ts, kind, detail FROM events WHERE ts >= ? AND kind = "route"', (first,)))
        wifi_rows = list(db.execute('SELECT ts, rssi FROM wifi WHERE ts >= ?', (first,)))
        counts = {}
        for inc in incidents:
            counts[inc['blame']] = counts.get(inc['blame'], 0) + 1
        print(dim('  where: ' + ', '.join(f'{blame_text[b]} {c}' for b, c in sorted(counts.items(), key=lambda x: -x[1]))))
        shown = incidents[-args.limit:]
        if len(shown) < len(incidents):
            print(dim(f'  (showing the latest {len(shown)})'))
        for inc in shown:
            s, dur = inc['stats'], inc['t1'] - inc['t0']
            kind = {'outage': red('outage'), 'loss': red('loss  '), 'lag': yellow('lag   ')}[inc['kind']]
            detail = f'{fmt_ms(s.p50)} ms' + (f', {s.loss_pct:.0f}% loss' if s.lost else '')
            notes = []
            if any(inc['t0'] - 30 <= ts <= inc['t1'] for ts, _, _ in events):
                notes.append('network changed')
            rssi = [r for ts, r in wifi_rows if inc['t0'] - 120 <= ts <= inc['t1'] + 120 and r is not None]
            if rssi and min(rssi) < -70:
                notes.append(f'weak Wi-Fi {min(rssi)} dBm')
            print(f'  {time.strftime("%b %d %H:%M:%S", time.localtime(inc["t0"]))}  {kind}  {int(dur):>4}s  '
                  f'{detail:<16} → {blame_text[inc["blame"]]}' + (dim(f'  ({", ".join(notes)})') if notes else ''))

    if span >= 12 * 3600 and 'internet' in series:
        hours = [[] for _ in range(24)]
        for ts, r in series['internet']:
            hours[time.localtime(ts).tm_hour].append(r)
        stats = [summarize(h) if h else None for h in hours]
        p95 = [s.p95 if s else None for s in stats]
        got = [v for v in p95 if v is not None]
        print(bold('\nBy hour of day') + dim('  internet 95th-percentile latency, 00 → 23'))
        print(f'  {sparkline(p95, max(1.0, min(got)), max(got))}')
        print(dim('  0     6     12    18   23'))
        worst = max(range(24), key=lambda h: p95[h] or 0)
        print(f'  worst hour {worst:02d}:00 ({fmt_ms(p95[worst])} ms p95)')

    wifi_rows = [r for (r,) in db.execute('SELECT rssi FROM wifi WHERE ts >= ? AND rssi IS NOT NULL', (first,))]
    if wifi_rows:
        s = sorted(wifi_rows)
        print(bold('\nWi-Fi signal') + f'  median {percentile(s, 0.5)} dBm, worst {s[0]} dBm  ({len(s)} readings)')
    return 0


# ---------------------------------------------------------------- agent

def cmd_agent(args):
    domain = f'gui/{os.getuid()}'
    if args.action == 'install':
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(AGENT_PLIST), exist_ok=True)
        log = os.path.join(DATA_DIR, 'agent.log')
        plist = {
            'Label': AGENT_LABEL,
            'ProgramArguments': [sys.executable, os.path.abspath(__file__), 'monitor', '--quiet'],
            'RunAtLoad': True,
            'KeepAlive': True,
            'ProcessType': 'Background',
            'StandardOutPath': log,
            'StandardErrorPath': log,
        }
        subprocess.run(['launchctl', 'bootout', f'{domain}/{AGENT_LABEL}'], capture_output=True)
        with open(AGENT_PLIST, 'wb') as f:
            plistlib.dump(plist, f)
        r = subprocess.run(['launchctl', 'bootstrap', domain, AGENT_PLIST], capture_output=True, text=True)
        if r.returncode:
            sys.exit(f'netprobe: launchctl bootstrap failed: {r.stderr.strip()}')
        print(f'Installed {AGENT_PLIST}; monitor runs in the background and at login. Logs: {log}')
    elif args.action == 'uninstall':
        subprocess.run(['launchctl', 'bootout', f'{domain}/{AGENT_LABEL}'], capture_output=True)
        if os.path.exists(AGENT_PLIST):
            os.remove(AGENT_PLIST)
        print(f'Removed the agent. Recorded data stays in {DB_PATH}.')
    else:
        r = subprocess.run(['launchctl', 'print', f'{domain}/{AGENT_LABEL}'], capture_output=True, text=True)
        if r.returncode:
            print('Agent not running.')
        else:
            state = re.search(r'state = (\S+)', r.stdout)
            print(f'Agent {state.group(1) if state else "loaded"}.')
    return 0


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(prog='netprobe', description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('check', help='one-shot diagnosis, idle and under load')
    p.add_argument('--quick', action='store_true', help='shorter phases (~40 s total)')
    p.add_argument('--no-load', action='store_true', help='skip the load phases (no data used)')
    p.add_argument('--idle', type=int, default=10, help='idle phase seconds (default 10)')
    p.add_argument('--load', type=int, default=15, help='seconds per load phase (default 15)')
    p.set_defaults(func=cmd_check)

    p = sub.add_parser('monitor', help='sample continuously into ~/.netprobe/netprobe.db')
    p.add_argument('--interval', type=float, default=1.0, help='seconds between pings per segment (default 1)')
    p.add_argument('--quiet', action='store_true', help='no status lines')
    p.set_defaults(func=cmd_monitor)

    p = sub.add_parser('report', help='summarize recorded data')
    p.add_argument('--since', default='24h', help='e.g. 30m, 24h, 7d (default 24h)')
    p.add_argument('--limit', type=int, default=20, help='max incidents to list (default 20)')
    p.set_defaults(func=cmd_report)

    p = sub.add_parser('agent', help='run monitor in the background via launchd')
    p.add_argument('action', choices=['install', 'uninstall', 'status'])
    p.set_defaults(func=cmd_agent)

    args = parser.parse_args()
    if args.command == 'report':
        try:
            args.since_seconds = parse_duration(args.since)
        except argparse.ArgumentTypeError as e:
            parser.error(f'--since: {e}')
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
