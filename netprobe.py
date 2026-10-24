#!/usr/bin/env python3
"""netprobe: find out where your network is slow, and when.

Commands:
  check     one-shot diagnosis: latency, jitter and loss per path segment,
            idle and under download/upload/bidirectional load
  monitor   sample the path continuously into a local database
  report    summarize what monitor recorded: timeline, incidents, who to blame
  agent     install or remove a background agent that runs monitor
            (launchd on macOS, systemd --user on Linux, Task Scheduler on Windows)

The path is split into segments so problems can be located:
  this computer -> router (Wi-Fi/LAN) -> ISP edge (first hop past the router) -> internet
"""

import argparse
import ctypes
import functools
import http.client
import ipaddress
import json
import math
import os
import plistlib
import random
import re
import select
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

DATA_DIR = os.path.join(os.path.expanduser('~'), '.netprobe')
DB_PATH = os.path.join(DATA_DIR, 'netprobe.db')
CONFIG_PATH = os.path.join(DATA_DIR, 'config.json')
AGENT_LABEL = 'com.netprobe.monitor'
AGENT_PLIST = os.path.expanduser(f'~/Library/LaunchAgents/{AGENT_LABEL}.plist')
AGENT_UNIT = 'netprobe.service'
AGENT_UNIT_PATH = os.path.expanduser(f'~/.config/systemd/user/{AGENT_UNIT}')
AGENT_TASK = 'netprobe'

__version__ = '0.4.0'
IS_LINUX = sys.platform.startswith('linux')
IS_WINDOWS = sys.platform == 'win32'
THIS_HOST = 'this Mac' if sys.platform == 'darwin' else 'this computer'

# Apple's networkQuality servers: built for saturation tests, no per-request cap
LOAD_HOST = 'mensura.cdn-apple.com'
DOWNLOAD_PATH = '/api/v1/gm/large'
UPLOAD_PATH = '/api/v1/gm/slurp'
UPLOAD_REQUEST_BYTES = 100_000_000
# Streams per direction: start small, add a step at a time while throughput still rises
LOAD_STREAMS, LOAD_STREAMS_MAX = 4, 16
RAMP_STEP_S, RAMP_MAX_S = 2.0, 8.0
INTERNET_ANCHOR = '1.1.1.1'
INTERNET_ANCHOR6 = '2606:4700:4700::1111'
DEFAULT_DESTINATIONS = ['google.com', 'github.com', 'apple.com', 'zoom.us']
PROBE_TIMEOUT = 2.0
RETENTION_DAYS = 30

SEGMENT_LABELS = {'gateway': 'Router (Wi-Fi/LAN)', 'isp': 'ISP network', 'internet': f'Internet ({INTERNET_ANCHOR})',
                  'internet6': 'Internet (IPv6)'}
PHASES = [('idle', ()), ('download', ('down',)), ('upload', ('up',)), ('both', ('down', 'up'))]


# ---------------------------------------------------------------- output

def enable_ansi():
    """Escape codes work on a macOS/Linux terminal as is; Windows consoles need
    virtual terminal processing switched on (Windows 10 1511 and later)."""
    if not (sys.stdout and sys.stdout.isatty()):  # None under pythonw
        return False
    if not IS_WINDOWS:
        return True
    kernel32 = ctypes.WinDLL('kernel32')
    handle, mode = kernel32.GetStdHandle(-11), ctypes.c_uint32()  # STD_OUTPUT_HANDLE
    return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                and kernel32.SetConsoleMode(handle, mode.value | 0x4))  # ENABLE_VIRTUAL_TERMINAL_PROCESSING


ANSI = enable_ansi()
COLOR = ANSI and not os.environ.get('NO_COLOR')


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
    if ANSI:
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
    if IS_LINUX:
        return linux_default_route()
    if IS_WINDOWS:
        return windows_default_route()
    out = run(['route', '-n', 'get', 'default'])
    gw = re.search(r'gateway:\s*(\S+)', out)
    iface = re.search(r'interface:\s*(\S+)', out)
    return (gw.group(1) if gw else None), (iface.group(1) if iface else None)


def linux_default_route():
    # `ip` lists routes for the same prefix in metric order, so the first default wins
    m = re.search(r'^default(?: via (\S+))? dev (\S+)', run(['ip', '-4', 'route', 'show', 'default']), re.M)
    if m:
        return m.group(1), m.group(2)
    # no iproute2 (minimal containers): read the kernel table directly
    best = None
    try:
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                iface, dest, gw, flags, _, _, metric = line.split()[:7]
                if dest == '00000000' and int(flags, 16) & 0x2 and (best is None or int(metric) < best[0]):
                    best = (int(metric), socket.inet_ntoa(struct.pack('<I', int(gw, 16))), iface)
    except (OSError, ValueError):
        pass
    return (best[1], best[2]) if best else (None, None)


def local_address():
    """This computer's IPv4 address on the default route."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((INTERNET_ANCHOR, 53))  # picks a route and source address; sends nothing
            return s.getsockname()[0]
    except OSError:
        return None


def public_ip():
    url = f'https://{INTERNET_ANCHOR}/cdn-cgi/trace'
    if shutil.which('curl'):
        out = run(['curl', '-s', '--max-time', '5', url], timeout=10)
    else:  # minimal Linux installs
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                out = resp.read().decode()
        except (OSError, ValueError):
            out = ''
    m = re.search(r'^ip=(\S+)', out, re.M)
    return m.group(1) if m else None


def find_isp_hop(gateway):
    """First ISP router that answers traceroute: (ip, hop number).

    Skips the gateway's own WAN address (it shows up as a hop on many ISP
    gateways) and private RFC 1918 hops, which are usually a second home router
    (double NAT). Some ISPs number their first router in 10/8 too; skipping it
    only moves the boundary one ISP hop out, while taking a home router for the
    ISP would blame the access line's queue on the ISP. CGNAT space (100.64/10)
    is the ISP's and is kept."""
    skip = {gateway, INTERNET_ANCHOR, public_ip()}
    for hop, ip in trace_hops(INTERNET_ANCHOR):
        if ip in skip or re.match(r'10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.', ip):
            continue
        return ip, hop
    return None, None


def trace_hops(dest, max_hops=10):
    """[(hop number, router ip)] along the ICMP path to dest."""
    if IS_LINUX:
        # Linux traceroute needs root for ICMP mode (and often isn't installed),
        # so walk the TTLs over our own unprivileged ping socket
        return linux_icmp_trace(dest, max_hops)
    if IS_WINDOWS:
        return windows_icmp_trace(dest, max_hops)
    # ICMP traceroute, so the hop count matches the path our ICMP probes take
    out = run(['traceroute', '-I', '-n', '-m', str(max_hops), '-q', '1', '-w', '1', dest], timeout=30)
    return [(int(m.group(1)), m.group(2)) for line in out.splitlines()
            if (m := re.match(r'\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)', line))]


def linux_icmp_trace(dest, max_hops, timeout=2.0):
    sock = icmp_socket()
    hops, reached = {}, None
    try:
        for ttl in range(1, max_hops + 1):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            try:
                icmp_send(sock, echo_packet(0, ttl), dest)
            except OSError:
                return []
        deadline = time.monotonic() + timeout
        while reached is None and (left := deadline - time.monotonic()) > 0:
            select.select([sock], [], [], left)
            for seq, _, src, ttl_exceeded in linux_icmp_read(sock):
                if ttl_exceeded:
                    hops[seq] = src
                elif src == dest:
                    reached = seq
    finally:
        sock.close()
    return sorted((h, ip) for h, ip in hops.items() if reached is None or h < reached)


def dns_servers(iface=None):
    """iface is the default-route interface (used on Windows)."""
    if IS_LINUX:
        return linux_dns_servers()
    if IS_WINDOWS:
        return windows_dns_servers(iface)
    servers = []
    for m in re.finditer(r'nameserver\[\d+\]\s*:\s*(\S+)', run(['scutil', '--dns'])):
        if m.group(1) not in servers:
            servers.append(m.group(1))
    return servers


def linux_dns_servers():
    def nameservers(path):
        try:
            with open(path) as f:
                return re.findall(r'^\s*nameserver\s+(\S+)', f.read(), re.M)
        except OSError:
            return []

    servers = nameservers('/etc/resolv.conf')
    if servers and all(s.startswith('127.') for s in servers):
        # systemd-resolved stub (127.0.0.53): ask it for the real upstream servers
        upstream = []
        for line in run(['resolvectl', 'dns']).splitlines():
            upstream += [s.split('#')[0] for s in line.partition(':')[2].split()]  # 1.1.1.1#cloudflare-dns.com
        servers = upstream or nameservers('/run/systemd/resolve/resolv.conf') or servers
    return list(dict.fromkeys(servers))


def wifi_info(iface=None):
    """Current Wi-Fi link, or None. iface is the default-route interface (used on Linux and Windows)."""
    if IS_LINUX:
        return linux_wifi_info(iface)
    if IS_WINDOWS:
        return windows_wifi_info(iface)
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


def linux_wifi_info(iface):
    if not iface or not shutil.which('iw'):
        return None
    out = run(['iw', 'dev', iface, 'link'])
    if not out.startswith('Connected'):
        return None
    sig = re.search(r'signal:\s*(-?\d+)', out)
    freq = re.search(r'freq:\s*(\d+)', out)
    tx = re.search(r'tx bitrate:\s*([\d.]+) MBit/s(.*)', out)
    flags = tx.group(2) if tx else ''
    phy = next((name for tag, name in (('EHT', '802.11be'), ('HE-', '802.11ax'), ('VHT', '802.11ac'), ('MCS', '802.11n'))
                if tag in flags), None)
    channel = None
    if freq:
        f = int(freq.group(1))
        band, ch = ('2.4GHz', 14 if f == 2484 else (f - 2407) // 5) if f < 3000 else \
                   ('5GHz', (f - 5000) // 5) if f < 5925 else ('6GHz', (f - 5950) // 5)
        width = re.search(r'(\d+)MHz', flags)
        channel = f'{ch} ({band}, {width.group(1) if width else 20}MHz)'
    return {
        'interface': iface,
        'phy': phy or 'legacy',
        'channel': channel,
        'rate': round(float(tx.group(1))) if tx else None,
        'rssi': int(sig.group(1)) if sig else None,
        'noise': None,  # iw doesn't report the noise floor
    }


def ipv6_available():
    """True with a global IPv6 route and an unprivileged ICMPv6 socket."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect((INTERNET_ANCHOR6, 53))  # picks a route and source address; sends nothing
            if s.getsockname()[0].lower().startswith('fe80'):
                return False
        if not IS_WINDOWS:  # Windows probes through its ICMP API, which needs no socket
            socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6).close()
    except OSError:
        return False
    return True


def resolve(host):
    try:
        return socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except OSError:
        return None


def curl_timings(host):
    """DNS, TCP, TLS and first-byte times for a real HTTPS request, in ms."""
    out = run(['curl', '-s', '-o', os.devnull, '--max-time', '10', '-w', '%{json}', f'https://{host}/'], timeout=15)
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


# ---------------------------------------------------------------- Windows
#
# Windows has no unprivileged ICMP sockets (raw sockets need admin), but its ICMP
# API (what ping and tracert use) sends echoes with any TTL and reports the router
# that answered, with no special rights. Each call blocks until the reply or the
# timeout, so the prober runs them on a thread pool.

IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT = 0, 11013
TCP_MAXRT = 5
ECHO_PAYLOAD = b'netprobe' + bytes(24)


class IpOptionInformation(ctypes.Structure):
    _fields_ = [('Ttl', ctypes.c_ubyte), ('Tos', ctypes.c_ubyte), ('Flags', ctypes.c_ubyte),
                ('OptionsSize', ctypes.c_ubyte), ('OptionsData', ctypes.c_void_p)]


class IcmpEchoReply(ctypes.Structure):
    _fields_ = [('Address', ctypes.c_uint32), ('Status', ctypes.c_uint32), ('RoundTripTime', ctypes.c_uint32),
                ('DataSize', ctypes.c_uint16), ('Reserved', ctypes.c_uint16), ('Data', ctypes.c_void_p),
                ('Options', IpOptionInformation)]


class Ipv6AddressEx(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('sin6_port', ctypes.c_uint16), ('sin6_flowinfo', ctypes.c_uint32),
                ('sin6_addr', ctypes.c_ubyte * 16), ('sin6_scope_id', ctypes.c_uint32)]


class Icmpv6EchoReply(ctypes.Structure):
    _fields_ = [('Address', Ipv6AddressEx), ('Status', ctypes.c_uint32), ('RoundTripTime', ctypes.c_uint32)]


class SockaddrIn6(ctypes.Structure):
    _fields_ = [('sin6_family', ctypes.c_uint16), ('sin6_port', ctypes.c_uint16), ('sin6_flowinfo', ctypes.c_uint32),
                ('sin6_addr', ctypes.c_ubyte * 16), ('sin6_scope_id', ctypes.c_uint32)]


class MibIpForwardRow(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        'dest', 'mask', 'policy', 'next_hop', 'if_index', 'type', 'proto', 'age', 'next_hop_as',
        'metric1', 'metric2', 'metric3', 'metric4', 'metric5')]


@functools.cache
def iphlpapi():
    from ctypes import wintypes as w
    lib = ctypes.WinDLL('iphlpapi')
    lib.IcmpCreateFile.restype = lib.Icmp6CreateFile.restype = w.HANDLE
    lib.IcmpCloseHandle.argtypes = [w.HANDLE]
    lib.IcmpSendEcho.argtypes = [w.HANDLE, ctypes.c_uint32, ctypes.c_void_p, w.WORD,
                                 ctypes.POINTER(IpOptionInformation), ctypes.c_void_p, w.DWORD, w.DWORD]
    lib.Icmp6SendEcho2.argtypes = [w.HANDLE, w.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.POINTER(SockaddrIn6), ctypes.POINTER(SockaddrIn6), ctypes.c_void_p, w.WORD,
                                   ctypes.POINTER(IpOptionInformation), ctypes.c_void_p, w.DWORD, w.DWORD]
    lib.IcmpSendEcho.restype = lib.Icmp6SendEcho2.restype = w.DWORD
    lib.GetBestRoute.argtypes = [w.DWORD, w.DWORD, ctypes.POINTER(MibIpForwardRow)]
    lib.ConvertInterfaceIndexToLuid.argtypes = [w.ULONG, ctypes.POINTER(ctypes.c_uint64)]
    lib.ConvertInterfaceLuidToAlias.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_wchar_p, ctypes.c_size_t]
    return lib


def windows_ping(host, ttl=None, timeout=PROBE_TIMEOUT):
    """One echo through the Windows ICMP API: (rtt ms, kind, router ip), where kind is
    'reply' (host answered), 'ttl' (a router at that TTL answered) or None (lost)."""
    lib = iphlpapi()
    v6 = ':' in host
    handle = lib.Icmp6CreateFile() if v6 else lib.IcmpCreateFile()
    if handle in (None, ctypes.c_void_p(-1).value):
        return None, None, None
    reply_type = Icmpv6EchoReply if v6 else IcmpEchoReply
    buf = ctypes.create_string_buffer(ctypes.sizeof(reply_type) + len(ECHO_PAYLOAD) + 64)
    opts = IpOptionInformation(Ttl=ttl or 64)
    try:
        # time it ourselves: the API's RoundTripTime is in whole milliseconds
        start = time.perf_counter()
        if v6:
            src, dst = SockaddrIn6(sin6_family=socket.AF_INET6), SockaddrIn6(sin6_family=socket.AF_INET6)
            dst.sin6_addr[:] = socket.inet_pton(socket.AF_INET6, host)
            lib.Icmp6SendEcho2(handle, None, None, None, ctypes.byref(src), ctypes.byref(dst), ECHO_PAYLOAD,
                               len(ECHO_PAYLOAD), ctypes.byref(opts), buf, len(buf), int(timeout * 1000))
        else:
            dest = struct.unpack('<I', socket.inet_aton(host))[0]  # IPAddr: network byte order in memory
            lib.IcmpSendEcho(handle, dest, ECHO_PAYLOAD, len(ECHO_PAYLOAD), ctypes.byref(opts), buf, len(buf),
                             int(timeout * 1000))
        rtt = (time.perf_counter() - start) * 1000
    finally:
        lib.IcmpCloseHandle(handle)
    reply = reply_type.from_buffer(buf)
    kind = {IP_SUCCESS: 'reply', IP_TTL_EXPIRED_TRANSIT: 'ttl'}.get(reply.Status)
    if not kind:
        return None, None, None
    router = socket.inet_ntop(socket.AF_INET6, bytes(reply.Address.sin6_addr)) if v6 else \
             socket.inet_ntoa(struct.pack('<I', reply.Address))
    return rtt, kind, router


def windows_default_route():
    """(gateway, interface alias) of the route Windows would use to reach the internet."""
    lib = iphlpapi()
    row = MibIpForwardRow()
    if lib.GetBestRoute(struct.unpack('<I', socket.inet_aton(INTERNET_ANCHOR))[0], 0, ctypes.byref(row)):
        return None, None
    gateway = socket.inet_ntoa(struct.pack('<I', row.next_hop))
    luid, alias = ctypes.c_uint64(), ctypes.create_unicode_buffer(257)
    iface = None
    if not lib.ConvertInterfaceIndexToLuid(row.if_index, ctypes.byref(luid)) and \
            not lib.ConvertInterfaceLuidToAlias(ctypes.byref(luid), alias, len(alias)):
        iface = alias.value
    return (None if gateway == '0.0.0.0' else gateway), iface  # 0.0.0.0: on-link, e.g. a VPN or PPP link


def windows_icmp_trace(dest, max_hops):
    # one probe per TTL, all at once, so the trace takes a single timeout
    with ThreadPoolExecutor(max_workers=max_hops) as pool:
        replies = list(pool.map(lambda ttl: windows_ping(dest, ttl, timeout=1.0), range(1, max_hops + 1)))
    hops = []
    for hop, (_, kind, router) in enumerate(replies, 1):
        if kind == 'reply':
            break
        if kind == 'ttl':
            hops.append((hop, router))
    return hops


def windows_dns_servers(iface):
    if not iface:
        return []
    servers = []
    for family in ('ipv4', 'ipv6'):
        for token in run(['netsh', 'interface', family, 'show', 'dnsservers', iface]).split():
            try:
                ip = ipaddress.ip_address(token.split('%')[0])
            except ValueError:
                continue
            if not (ip.version == 6 and ip.is_site_local):  # fec0:0:0:ffff::1-3: Windows' "none configured" placeholders
                servers.append(str(ip))
    return list(dict.fromkeys(servers))


def windows_wifi_info(iface):
    for block in re.split(r'\n\s*\n', run(['netsh', 'wlan', 'show', 'interfaces'])):
        f = {k.strip().lower(): v.strip() for k, v in re.findall(r'^\s*([^:\n]+?)\s+:\s(.*)$', block, re.M)}
        if f.get('name') != iface or f.get('state', '').lower() != 'connected':
            continue
        rssi = f.get('rssi')
        if rssi is None and (pct := re.match(r'(\d+)%', f.get('signal', ''))):
            rssi = int(pct.group(1)) // 2 - 100  # Windows maps -100..-50 dBm onto 0..100%
        channel = f.get('channel')
        if channel and channel.isdigit():
            band = f.get('band', '').replace(' ', '') or ('2.4GHz' if int(channel) <= 14 else '5GHz')
            channel = f'{channel} ({band})'
        rate = f.get('transmit rate (mbps)', '')
        return {
            'interface': iface,
            'phy': f.get('radio type'),
            'channel': channel,
            'rate': round(float(rate)) if re.fullmatch(r'[\d.]+', rate) else None,
            'rssi': int(rssi) if rssi is not None else None,
            'noise': None,  # netsh doesn't report the noise floor
        }
    return None


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


def path_targets(gateway, isp, isp_hop, interval, ipv6=False):
    targets = []
    if gateway:
        targets.append(Target('gateway', gateway, 'icmp', interval))
    if isp:
        # ISP routers often drop pings addressed to them but still answer
        # traceroute-style probes, so reach the hop by TTL instead. They also
        # rate-limit those replies, so probe gently and never trust its loss.
        targets.append(Target('isp', isp, 'icmp', max(interval, 1.0), ttl=isp_hop))
    targets.append(Target('internet', INTERNET_ANCHOR, 'icmp', interval))
    if ipv6:
        targets.append(Target('internet6', INTERNET_ANCHOR6, 'icmp', interval))
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


def echo_packet(ident, seq, v6=False):
    payload = b'netprobe' + bytes(24)
    if v6:  # the kernel fills in the ICMPv6 checksum, which covers an IPv6 pseudo-header
        return struct.pack('!BBHHH', 128, 0, 0, ident, seq) + payload
    header = struct.pack('!BBHHH', 8, 0, 0, ident, seq)
    return struct.pack('!BBHHH', 8, 0, icmp_checksum(header + payload), ident, seq) + payload


IP_RECVERR = getattr(socket, 'IP_RECVERR', 11)
MSG_ERRQUEUE = getattr(socket, 'MSG_ERRQUEUE', 0x2000)


def icmp_socket():
    """Unprivileged ICMP echo socket. On Linux it is non-blocking and reports
    ICMP errors (TTL exceeded) through its error queue; see linux_icmp_read."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError as e:
        sys.exit(icmp_help(e))
    if IS_LINUX:
        sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
        sock.setblocking(False)
    return sock


def check_icmp():
    """Exit with the fix now if ICMP probing is not allowed, rather than after path discovery."""
    if IS_WINDOWS:
        iphlpapi()  # the ICMP API needs no special rights
    else:
        icmp_socket().close()


def icmp6_socket():
    """Unprivileged ICMPv6 echo socket, or None. IPv6 sockets never deliver the IP
    header, and Linux rewrites the echo ident here just as for IPv4."""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
    except OSError:
        return None
    sock.setblocking(False)
    return sock


def icmp_send(sock, packet, host):
    for attempt in range(3):
        try:
            return sock.sendto(packet, (host, 0))
        except OSError:
            # Linux hands an earlier probe's ICMP error (e.g. TTL exceeded) to the next
            # send and drops that packet; the error itself is still on the error queue
            if not IS_LINUX or attempt == 2:
                raise


def icmp_help(err):
    msg = f'netprobe: cannot open an unprivileged ICMP socket ({err.strerror or err}).'
    if not IS_LINUX:
        return msg
    try:
        with open('/proc/sys/net/ipv4/ping_group_range') as f:
            current = ' '.join(f.read().split())
    except OSError:
        current = 'unknown'
    groups = ', '.join(str(g) for g in sorted({os.getgid(), *os.getgroups()}))
    return (f'{msg}\n'
            f'Linux allows ping sockets only for groups in net.ipv4.ping_group_range (now "{current}"; '
            f'your groups: {groups}).\n'
            "Allow all groups (most distributions already default to this):\n"
            "  sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'\n"
            'Keep it across reboots:\n'
            "  echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/60-netprobe.conf")


def linux_icmp_read(sock):
    """Drain a Linux ping socket: [(seq, ident, source ip, ttl_exceeded)].

    Linux differs from macOS here: replies come without the IP header, the
    kernel rewrites the echo ident to the socket's local port (and only delivers
    replies carrying it), and TTL-exceeded errors arrive on the error queue with
    the router's address in the ancillary data rather than as normal packets."""
    out = []
    while True:
        try:
            data, anc, _, _ = sock.recvmsg(512, 512, MSG_ERRQUEUE)
        except OSError:  # queue empty
            break
        for level, kind, cdata in anc:
            # struct sock_extended_err, then the offending router's sockaddr_in
            if level != socket.IPPROTO_IP or kind != IP_RECVERR or len(cdata) < 24 or len(data) < 8:
                continue
            _, origin, icmp_type = struct.unpack_from('=IBB', cdata)
            if origin == 2 and icmp_type == 11:  # SO_EE_ORIGIN_ICMP, time exceeded
                _, _, _, ident, seq = struct.unpack('!BBHHH', data[:8])  # our echo, as quoted by the router
                out.append((seq, ident, socket.inet_ntoa(cdata[20:24]), True))
    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:  # nothing left, or a pending socket error (already drained above)
            break
        offset = ip_header_len(data)
        if len(data) >= offset + 8:
            kind, _, _, ident, seq = struct.unpack('!BBHHH', data[offset:offset + 8])
            if kind == 0:
                out.append((seq, ident, addr[0], False))
    return out


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
        self._tcp_pool = ThreadPoolExecutor(max_workers=8)
        self._threads = [threading.Thread(target=self._send_loop, daemon=True)]
        if IS_WINDOWS:
            # each probe blocks until its reply or timeout: room for every target's in-flight probes
            self._sock = self._sock6 = None
            self._icmp_pool = ThreadPoolExecutor(max_workers=64)
            return
        self._sock = icmp_socket()
        if not IS_LINUX:
            self._sock.settimeout(0.2)
        self._sock6 = icmp6_socket()
        self._threads.append(threading.Thread(target=self._recv_loop, daemon=True))
        if self._sock6:
            self._threads.append(threading.Thread(target=self._recv_loop6, daemon=True))

    def start(self):
        for t in self._threads:
            t.start()

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self._tcp_pool.shutdown(wait=False, cancel_futures=True)
        if IS_WINDOWS:
            self._icmp_pool.shutdown(wait=False, cancel_futures=True)
            return
        self._sock.close()
        if self._sock6:
            self._sock6.close()

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
        if IS_WINDOWS:
            self._icmp_pool.submit(self._windows_probe, t)
            return
        with self._lock:
            self._seq = seq = (self._seq + 1) & 0xFFFF
            self._pending[seq] = (t.name, t.host, time.monotonic(), time.time())
        try:
            if ':' in t.host:
                if not self._sock6:
                    raise OSError('no ICMPv6 socket')
                self._sock6.sendto(echo_packet(self._ident, seq, v6=True), (t.host, 0))
            else:
                self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, t.ttl or 64)
                icmp_send(self._sock, echo_packet(self._ident, seq), INTERNET_ANCHOR if t.ttl else t.host)
        except OSError:  # no route, interface down: count as lost
            with self._lock:
                entry = self._pending.pop(seq, None)
            if entry:
                self.on_sample(entry[3], entry[0], None)

    def _recv_loop(self):
        if IS_LINUX:
            return self._recv_loop_linux()
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
            self._match(seq, addr[0], ttl_reply, now)

    def _recv_loop_linux(self):
        while not self._stop.is_set():
            try:
                select.select([self._sock], [], [], 0.2)
            except (OSError, ValueError):  # socket closed by stop()
                return
            now = time.monotonic()
            # the kernel already filtered on ident (it rewrote ours to the socket's port)
            for seq, _, src, ttl_reply in linux_icmp_read(self._sock):
                self._match(seq, src, ttl_reply, now)

    def _recv_loop6(self):
        while not self._stop.is_set():
            try:
                select.select([self._sock6], [], [], 0.2)
            except (OSError, ValueError):  # socket closed by stop()
                return
            now = time.monotonic()
            while True:
                try:
                    data, addr = self._sock6.recvfrom(2048)
                except OSError:  # nothing left, a reported ICMP error, or closed
                    break
                if len(data) < 8:
                    continue
                kind, _, _, ident, seq = struct.unpack('!BBHHH', data[:8])
                # macOS hands every ICMPv6 socket every reply; Linux filters on its rewritten ident
                if kind == 129 and (IS_LINUX or ident == self._ident):
                    self._match(seq, addr[0].split('%')[0], False, now)

    def _match(self, seq, src, ttl_reply, now):
        with self._lock:
            entry = self._pending.get(seq)
            # ISP hops are often load-balanced pairs, so any router at that TTL counts
            if not entry or (not ttl_reply and entry[1] != src):
                return
            del self._pending[seq]
        self.on_sample(entry[3], entry[0], (now - entry[2]) * 1000)

    def _expire(self, now):
        with self._lock:
            expired = [(seq, e) for seq, e in self._pending.items() if now - e[2] > PROBE_TIMEOUT]
            for seq, _ in expired:
                del self._pending[seq]
        for _, e in expired:
            self.on_sample(e[3], e[0], None)

    def _windows_probe(self, t):
        wall = time.time()
        try:
            rtt, kind, _ = windows_ping(INTERNET_ANCHOR if t.ttl else t.host, t.ttl)
        except OSError:  # unparsable address, API failure: count as lost
            rtt = kind = None
        # ISP hops are often load-balanced pairs, so any router at that TTL counts
        if not self._stop.is_set():
            self.on_sample(wall, t.name, rtt if kind == ('ttl' if t.ttl else 'reply') else None)

    def _tcp_probe(self, t):
        # perf_counter: before Python 3.13, monotonic() on Windows ticks only every ~16 ms
        wall, start = time.time(), time.perf_counter()
        try:
            if IS_WINDOWS:
                # a socket timeout waits in Winsock's select(), which wakes on ~16 ms timer
                # ticks and would round every handshake up; connect blocking instead and let
                # TCP_MAXRT (seconds of retransmission) enforce the timeout
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.IPPROTO_TCP, TCP_MAXRT, math.ceil(PROBE_TIMEOUT))
                    s.connect((t.host, t.port))
                    rtt = (time.perf_counter() - start) * 1000
            else:
                with socket.create_connection((t.host, t.port), timeout=PROBE_TIMEOUT):
                    rtt = (time.perf_counter() - start) * 1000
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
    """Saturates one direction with parallel HTTPS streams to Apple's networkQuality servers."""

    def __init__(self, direction):
        self.direction = direction
        self.bytes = 0
        self.errors = 0
        self.last_error = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._conns = set()
        self._threads = []

    @property
    def streams(self):
        return len(self._threads)

    def start(self):
        self.add_streams(LOAD_STREAMS)

    def add_streams(self, n):
        for _ in range(n):
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
                # struct linger: two ints, but two u_shorts in Winsock
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('HH' if IS_WINDOWS else 'ii', 1, 0))
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
    """Runs one phase; returns the (t0, t1) sample window and Mbps per direction.

    A load phase first adds streams until throughput stops rising, since a few
    streams can't fill a fast line and an unfilled line hides bufferbloat. It
    then lets the queues fill and measures for the rest of `duration`."""
    loads = [Load(d) for d in directions]
    for load in loads:
        load.start()
    start = time.time()
    measure = duration - min(3.0, duration / 3) if loads else duration
    warm = end = None  # set once the ramp settles
    if not loads:
        warm, end = start, start + duration
    ramp = {l.direction: (start, 0, 0.0) for l in loads}  # step start, bytes then, best Mbps so far
    ramping = set(ramp)
    marks, last, rates = {}, {l.direction: (start, 0) for l in loads}, {}
    try:
        while (now := time.time()) < (end or math.inf):
            for l in loads:
                b, (t0, b0) = l.bytes, last[l.direction]
                if now - t0 >= 1:
                    rates[l.direction] = (b - b0) * 8 / (now - t0) / 1e6
                    last[l.direction] = (now, b)
                if l.direction in ramping and now - ramp[l.direction][0] >= RAMP_STEP_S:
                    t0, b0, best = ramp[l.direction]
                    rate = (b - b0) * 8 / (now - t0) / 1e6
                    if rate > best * 1.1 and l.streams < LOAD_STREAMS_MAX and now < start + RAMP_MAX_S:
                        l.add_streams(LOAD_STREAMS)
                        ramp[l.direction] = (now, b, rate)
                    else:
                        ramping.discard(l.direction)
                if warm and now >= warm and l.direction not in marks:
                    marks[l.direction] = (now, b)
            if warm is None and (not ramping or now >= start + RAMP_MAX_S):
                warm = now + 1  # let queues fill at the final stream count
                end = warm + measure
            rate_text = '  '.join(f'{"↓" if d == "down" else "↑"} {r:5.0f} Mbps' for d, r in rates.items())
            streams = ' '.join(str(l.streams) for l in loads)
            when = f'{max(0, int(end - now)):>3}s left' if end else ' ramping'
            live(f'  {name:<9} {when}  latency {fmt_ms(collector.latest("internet")):>5} ms  {rate_text}'
                 + (dim(f'  ({streams} streams)') if loads else ''))
            time.sleep(0.25)
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


def print_connection(iface, wifi, gateway, isp, dns, ipv6):
    print(bold('\nConnection'))
    if wifi:
        snr = wifi['rssi'] - wifi['noise'] if wifi['rssi'] is not None and wifi['noise'] is not None else None
        signal = f'{wifi["rssi"]} dBm, SNR {snr} dB' if snr is not None else \
                 f'{wifi["rssi"]} dBm' if wifi['rssi'] is not None else 'signal unknown'
        print(f'  {iface}  Wi-Fi {wifi["phy"]}, channel {wifi["channel"]}, {signal}, link {wifi["rate"]} Mbps')
    else:
        print(f'  {iface}  wired or non-Wi-Fi interface')
    hops = [f'router {gateway}', f'ISP edge {isp}' if isp else dim('ISP edge not found'), f'internet {INTERNET_ANCHOR}']
    print(f'  path   {THIS_HOST} → {" → ".join(hops)}')
    print(f'  DNS    {", ".join(dns) or "unknown"}')
    print(f'  IPv6   {f"yes, probing {INTERNET_ANCHOR6}" if ipv6 else dim("no global IPv6 route")}')


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
    'local': f'between {THIS_HOST} and the router (Wi-Fi or the router itself)',
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

    if wifi and wifi['rssi'] is not None:
        # Linux (iw) reports no noise floor, so judge on signal strength alone there
        rssi = wifi['rssi']
        snr = rssi - wifi['noise'] if wifi['noise'] is not None else math.inf
        reading = f'{rssi} dBm, SNR {snr} dB' if wifi['noise'] is not None else f'{rssi} dBm'
        if rssi < -70 or snr < 20:
            findings.append(('bad', f'Weak Wi-Fi signal ({reading})',
                             'Expect retries, jitter and lower speed. Move closer to the router, remove obstructions, or use Ethernet.'))
        elif rssi < -65 or snr < 25:
            findings.append(('warn', f'Fair Wi-Fi signal ({reading})',
                             'Usable, but a few metres or a wall away from trouble.'))
        else:
            findings.append(('ok', f'Strong Wi-Fi signal ({reading})', None))

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

    idle_v6 = get('internet6', 'idle')
    if idle_v6 and idle_net and idle_net.p50 is not None:
        if idle_v6.p50 is None:
            findings.append(('bad', 'IPv6 is not answering',
                             'There is an IPv6 route but no replies over it. Apps try IPv6 first and fall back '
                             'to IPv4 after a delay, so connections start slowly. Check the router\'s IPv6 settings '
                             'or turn IPv6 off on it.'))
        elif idle_v6.loss_pct >= 1:
            findings.append(('warn', f'{idle_v6.loss_pct:.1f}% IPv6 packet loss at idle (IPv4: {idle_net.loss_pct:.1f}%)',
                             'Most apps prefer IPv6, so they get the lossy path.'))
        elif (slower := idle_v6.p50 - idle_net.p50) > 20:
            findings.append(('warn', f'IPv6 is {fmt_ms(slower)} ms slower than IPv4',
                             'Most apps prefer IPv6, so they get the slower path. Usually a poor ISP IPv6 route '
                             'or a tunnel; worth raising with your ISP.'))
        else:
            findings.append(('ok', f'IPv6 working ({fmt_ms(idle_v6.p50)} ms vs {fmt_ms(idle_net.p50)} ms over IPv4)', None))

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
    check_icmp()

    print(bold('netprobe check'))
    live(dim('  Discovering path…'))
    wifi = wifi_info(iface)
    if wifi and wifi['interface'] != iface:
        wifi = None
    isp, isp_hop = find_isp_hop(gateway)
    dests = [(h, ip) for h in cfg['destinations'] if (ip := resolve(h))]
    live(dim('  Timing real requests…'))
    app = [(h, curl_timings(h)) for h, _ in dests]
    live('')
    ipv6 = ipv6_available()
    print_connection(iface, wifi, gateway, isp, dns_servers(iface), ipv6)
    print_app_timings(app)

    targets = path_targets(gateway, isp, isp_hop, 0.2, ipv6) + [Target(h, ip, 'tcp', 1.0) for h, ip in dests]
    phases = PHASES[:1] if args.no_load else PHASES
    total = f'{idle_s}' if args.no_load else f'{idle_s + 3 * (load_s + 2)}–{idle_s + 3 * (load_s + int(RAMP_MAX_S))}'
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


def prune(db):
    cutoff = time.time() - RETENTION_DAYS * 86400
    for table in ('samples', 'wifi', 'events'):
        db.execute(f'DELETE FROM {table} WHERE ts < ?', (cutoff,))
    db.commit()


def cmd_monitor(args):
    if args.log:  # the Windows agent runs under pythonw, which has no stdout or stderr
        sys.stdout = sys.stderr = open(args.log, 'a', encoding='utf-8')
    sys.stdout.reconfigure(line_buffering=True)  # status lines reach logs promptly
    cfg = load_config()
    db = open_db()
    prune(db)

    lock, buffer, recent, wifi_rows = threading.Lock(), [], [], []

    def on_sample(ts, name, rtt):
        with lock:
            buffer.append((ts, name, rtt))
            recent.append((ts, name, rtt))

    def build_path(gateway):
        isp, isp_hop = find_isp_hop(gateway) if gateway else (None, None)
        return path_targets(gateway, isp, isp_hop, args.interval, ipv6_available()), isp

    def build_dests():
        return [Target(h, ip, 'tcp', args.interval * 10) for h in cfg['destinations'] if (ip := resolve(h))]

    gateway, iface = default_route()
    check_icmp()
    # Many networks share a router address like 192.168.1.1, so a change of network
    # also shows as a new local address or public address. (The router's MAC would be
    # better, but macOS hides the ARP table from apps without Local Network access.)
    address, public = local_address(), public_ip()
    path, isp = build_path(gateway)
    dests = build_dests()
    db.execute('INSERT INTO events VALUES (?, ?, ?)', (time.time(), 'start', f'gateway={gateway} isp={isp}'))
    db.commit()
    if not args.quiet:
        print(bold('netprobe monitor') + dim(f'  router {gateway}, ISP edge {isp}, writing to {DB_PATH}  (Ctrl-C to stop)'))

    def on_term(signum, frame):  # launchd and systemd stop agents with SIGTERM (Task Scheduler just ends the process)
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, signal.default_int_handler)  # background shells start us with SIGINT ignored

    # system_profiler takes seconds, so sample Wi-Fi off the loop that flushes samples
    wifi_iface, wifi_stop = [iface], threading.Event()

    def sample_wifi():
        delay = 5
        while not wifi_stop.wait(delay):
            w = wifi_info(wifi_iface[0])
            if w:
                with lock:
                    wifi_rows.append((time.time(), w['rssi'], w['noise'], w['rate'], w['channel']))
            delay = 120
    threading.Thread(target=sample_wifi, daemon=True).start()

    def flush():
        with lock:
            rows, buffer[:] = list(buffer), []
            wifi, wifi_rows[:] = list(wifi_rows), []
        db.executemany('INSERT INTO samples VALUES (?, ?, ?)', rows)
        db.executemany('INSERT INTO wifi VALUES (?, ?, ?, ?, ?)', wifi)
        db.commit()

    prober = Prober(path + dests, on_sample)
    prober.start()
    next_flush = next_route = next_status = time.time()
    next_public = time.time() + 120
    next_prune = time.time() + 3600
    next_resolve = time.time() + 600
    try:
        while True:
            time.sleep(1)
            now = time.time()
            if now >= next_flush:
                flush()
                next_flush = now + 5
            if now >= next_route:
                new_gateway, new_iface = default_route()
                new_address = local_address()
                changed = (new_gateway, new_iface, new_address) != (gateway, iface, address)
                if not changed and now >= next_public:
                    # a failed lookup (None) is not a change
                    new_public = public_ip()
                    changed = bool(public and new_public and new_public != public)
                    public = new_public or public
                    next_public = now + 120
                if changed:
                    gateway, iface, address = new_gateway, new_iface, new_address
                    wifi_iface[0] = iface
                    path, isp = build_path(gateway)
                    dests = build_dests()
                    prober.set_targets(path + dests)
                    public, next_public = public_ip(), now + 120
                    next_resolve = now + 600
                    db.execute('INSERT INTO events VALUES (?, ?, ?)', (now, 'route', f'gateway={gateway} isp={isp}'))
                    if not args.quiet:
                        print(yellow(f'{time.strftime("%H:%M:%S")}  network changed: router {gateway}, ISP edge {isp}'))
                next_route = now + 30
            if now >= next_resolve:
                # CDN addresses rotate; keep probing the ones apps would connect to now
                new_dests = build_dests()
                if [(t.name, t.host) for t in new_dests] != [(t.name, t.host) for t in dests]:
                    dests = new_dests
                    prober.set_targets(path + dests)
                next_resolve = now + 600
            if now >= next_prune:
                prune(db)
                next_prune = now + 3600
            if not args.quiet and now >= next_status:
                with lock:
                    recent[:] = [s for s in recent if s[0] >= now - 10]
                    window = list(recent)
                parts = []
                for name in ('gateway', 'isp', 'internet', 'internet6'):
                    s = summarize([r for _, n, r in sorted(window) if n == name])
                    if s.sent:
                        text = f'{name} {fmt_ms(s.p50)} ms' + (f' {s.loss_pct:.0f}% loss' if s.lost else '')
                        parts.append(red(text) if s.loss_pct >= 10 else text)
                print(f'{time.strftime("%H:%M:%S")}  ' + '   '.join(parts))
                next_status = now + 10
    except KeyboardInterrupt:
        pass
    finally:
        wifi_stop.set()
        prober.stop()
        flush()
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
    print(bold('\nTimeline') + dim(f'  one column = {size // 60} min · bars = 95th-percentile latency (log scale) · '
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
        events = list(db.execute("SELECT ts, kind, detail FROM events WHERE ts >= ? AND kind = 'route'", (first,)))
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

def install_script():
    """Copy netprobe into ~/.netprobe for the agent to run; returns (python, script, log)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    # Run a copy from ~/.netprobe: macOS privacy controls block background jobs from
    # reading ~/Desktop or ~/Documents, where the checkout often lives, and the
    # agent keeps working if a pipx install or checkout moves
    script = os.path.join(DATA_DIR, 'netprobe.py')
    shutil.copy2(os.path.abspath(__file__), script)
    return agent_python(), script, os.path.join(DATA_DIR, 'agent.log')


def agent_python():
    """Prefer the PATH python3, a stable symlink (sys.executable can point into a
    versioned directory that disappears on the next Homebrew upgrade), but only if
    it is new enough: on macOS it is often Apple's /usr/bin/python3, which is 3.9.
    On Windows, use pythonw from the same install so the agent opens no console window
    (and skip PATH: python3 there is often the Microsoft Store installer stub)."""
    if IS_WINDOWS:
        pythonw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
        return pythonw if os.path.exists(pythonw) else sys.executable
    path = shutil.which('python3')
    if path:
        try:
            if not subprocess.run([path, '-c', 'import sys; sys.exit(sys.version_info < (3, 10))'],
                                  capture_output=True, timeout=10).returncode:
                return path
        except (OSError, subprocess.TimeoutExpired):
            pass
    return sys.executable


def cmd_agent(args):
    if IS_LINUX:
        return linux_agent(args)
    if IS_WINDOWS:
        return windows_agent(args)
    domain = f'gui/{os.getuid()}'
    if args.action == 'install':
        os.makedirs(os.path.dirname(AGENT_PLIST), exist_ok=True)
        python, script, log = install_script()
        plist = {
            'Label': AGENT_LABEL,
            'ProgramArguments': [python, script, 'monitor', '--quiet'],
            'RunAtLoad': True,
            'KeepAlive': True,
            'ProcessType': 'Background',
            'StandardOutPath': log,
            'StandardErrorPath': log,
        }
        subprocess.run(['launchctl', 'bootout', f'{domain}/{AGENT_LABEL}'], capture_output=True)
        # bootout returns before the old monitor has exited (it flushes to the database
        # on SIGTERM); bootstrapping before then fails with "5: Input/output error"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not subprocess.run(
                ['launchctl', 'print', f'{domain}/{AGENT_LABEL}'], capture_output=True).returncode:
            time.sleep(0.25)
        with open(AGENT_PLIST, 'wb') as f:
            plistlib.dump(plist, f)
        for attempt in range(5):
            r = subprocess.run(['launchctl', 'bootstrap', domain, AGENT_PLIST], capture_output=True, text=True)
            if not r.returncode:
                break
            time.sleep(1)
        if r.returncode:
            sys.exit(f'netprobe: launchctl bootstrap failed: {r.stderr.strip()}')
        print(f'Installed {AGENT_PLIST}; monitor runs in the background and at login. Logs: {log}')
        print(dim(f'The agent runs a copy at {script}; re-run `agent install` after updating netprobe.'))
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


def linux_agent(args):
    if not shutil.which('systemctl'):
        sys.exit('netprobe: the agent needs systemd (systemctl not found). Run `netprobe monitor` under '
                 'your own supervisor instead.')

    def systemctl(*cmd):
        return subprocess.run(['systemctl', '--user', *cmd], capture_output=True, text=True)

    if args.action == 'install':
        python, script, log = install_script()
        quote = lambda s: '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
        unit = (
            '[Unit]\n'
            'Description=netprobe network monitor\n'
            'Wants=network-online.target\n'
            'After=network-online.target\n\n'
            '[Service]\n'
            f'ExecStart={quote(python)} {quote(script)} monitor --quiet\n'
            'Restart=always\n'
            'RestartSec=10\n'
            f'StandardOutput=append:{log}\n'
            f'StandardError=append:{log}\n\n'
            '[Install]\n'
            'WantedBy=default.target\n'
        )
        os.makedirs(os.path.dirname(AGENT_UNIT_PATH), exist_ok=True)
        with open(AGENT_UNIT_PATH, 'w') as f:
            f.write(unit)
        for cmd in (['daemon-reload'], ['enable', AGENT_UNIT], ['restart', AGENT_UNIT]):
            r = systemctl(*cmd)
            if r.returncode:
                sys.exit(f'netprobe: systemctl --user {" ".join(cmd)} failed: {r.stderr.strip()}')
        print(f'Installed {AGENT_UNIT_PATH}; monitor runs in the background and at login. Logs: {log}')
        print(dim(f'The agent runs a copy at {script}; re-run `agent install` after updating netprobe.'))
        print(dim(f'To keep it running while you are logged out: loginctl enable-linger {os.environ.get("USER", "$USER")}'))
    elif args.action == 'uninstall':
        systemctl('disable', '--now', AGENT_UNIT)
        if os.path.exists(AGENT_UNIT_PATH):
            os.remove(AGENT_UNIT_PATH)
        systemctl('daemon-reload')
        print(f'Removed the agent. Recorded data stays in {DB_PATH}.')
    else:
        state = systemctl('is-active', AGENT_UNIT).stdout.strip()
        print(f'Agent {state}.' if state == 'active' else 'Agent not running.')
    return 0


def windows_agent(args):
    def schtasks(*cmd):
        return subprocess.run(['schtasks', *cmd], capture_output=True, text=True)

    if args.action == 'install':
        python, script, log = install_script()
        user = f'{os.environ.get("USERDOMAIN", "")}\\{os.environ.get("USERNAME", "")}'.lstrip('\\')
        esc = lambda s: s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        # a task XML rather than schtasks flags: only XML can turn off the 72-hour run limit
        # and the battery rules, and restart the monitor if it dies
        task = (
            '<?xml version="1.0" encoding="UTF-16"?>\n'
            '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
            '  <RegistrationInfo><Description>netprobe network monitor</Description></RegistrationInfo>\n'
            f'  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{esc(user)}</UserId></LogonTrigger></Triggers>\n'
            '  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType>'
            '<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n'
            '  <Settings>\n'
            '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n'
            '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n'
            '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n'
            '    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n'
            '    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>\n'
            '  </Settings>\n'
            '  <Actions Context="Author"><Exec>\n'
            f'    <Command>{esc(python)}</Command>\n'
            f'    <Arguments>{esc(subprocess.list2cmdline([script, "monitor", "--quiet", "--log", log]))}</Arguments>\n'
            '  </Exec></Actions>\n'
            '</Task>\n'
        )
        xml_path = os.path.join(DATA_DIR, 'agent-task.xml')
        with open(xml_path, 'w', encoding='utf-16') as f:
            f.write(task)
        schtasks('/End', '/TN', AGENT_TASK)
        for cmd in (['/Create', '/TN', AGENT_TASK, '/XML', xml_path, '/F'], ['/Run', '/TN', AGENT_TASK]):
            r = schtasks(*cmd)
            if r.returncode:
                sys.exit(f'netprobe: schtasks {cmd[0]} failed: {(r.stderr or r.stdout).strip()}')
        print(f'Installed the "{AGENT_TASK}" scheduled task; monitor runs in the background and at logon. Logs: {log}')
        print(dim(f'The agent runs a copy at {script}; re-run `agent install` after updating netprobe.'))
    elif args.action == 'uninstall':
        schtasks('/End', '/TN', AGENT_TASK)
        schtasks('/Delete', '/TN', AGENT_TASK, '/F')
        print(f'Removed the agent. Recorded data stays in {DB_PATH}.')
    else:
        r = schtasks('/Query', '/TN', AGENT_TASK, '/FO', 'CSV', '/NH')
        if r.returncode:
            print('Agent not installed.')
        else:
            state = r.stdout.strip().split('","')[-1].strip('"')  # "\netprobe","N/A","Running"
            print(f'Agent {state.lower()}.' if state else 'Agent installed.')
    return 0


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(prog='netprobe', description=__doc__.split('\n')[0])
    parser.add_argument('--version', action='version', version=f'netprobe {__version__}')
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
    p.add_argument('--log', help=argparse.SUPPRESS)  # used by the Windows agent
    p.set_defaults(func=cmd_monitor)

    p = sub.add_parser('report', help='summarize recorded data')
    p.add_argument('--since', default='24h', help='e.g. 30m, 24h, 7d (default 24h)')
    p.add_argument('--limit', type=int, default=20, help='max incidents to list (default 20)')
    p.set_defaults(func=cmd_report)

    p = sub.add_parser('agent', help='run monitor in the background '
                                     '(launchd on macOS, systemd --user on Linux, Task Scheduler on Windows)')
    p.add_argument('action', choices=['install', 'uninstall', 'status'])
    p.set_defaults(func=cmd_agent)

    if IS_WINDOWS:
        # a console takes any character, but output redirected to a file or pipe would
        # use the ANSI code page, which has no ✓, ↓ or ▁
        for stream in (sys.stdout, sys.stderr):
            if stream and not stream.isatty():
                stream.reconfigure(encoding='utf-8')
    args = parser.parse_args()
    if args.command != 'report' and sys.platform != 'darwin' and not IS_LINUX and not IS_WINDOWS:
        sys.exit(f'netprobe: {args.command} supports macOS, Linux and Windows only (this is {sys.platform}).')
    if args.command == 'report':
        try:
            args.since_seconds = parse_duration(args.since)
        except argparse.ArgumentTypeError as e:
            parser.error(f'--since: {e}')
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
