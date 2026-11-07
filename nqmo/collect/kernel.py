"""C2 + C6: kernel counters from /proc and /sys (file reads only, no exec).

All parsers take text so tests run off-Linux; read_* helpers take a root so a
fixture tree can stand in for /.
"""
import os

SNMP_WANTED = {
    "Ip": ("FragCreates", "FragFails", "FragOKs", "ReasmReqds", "ReasmFails",
           "ReasmTimeout", "ReasmOKs"),
    "Icmp": ("OutDestUnreachs", "InDestUnreachs"),
    "Udp": ("RcvbufErrors", "SndbufErrors", "InErrors"),
    "Tcp": ("RetransSegs", "OutSegs"),
    "TcpExt": ("TCPMTUPFail", "TCPMTUPSuccess"),
}
# eth0 NIC-side drops. rx_dropped is deliberately NOT here: in
# __netif_receive_skb_core it counts frames with no protocol handler (LLDP,
# unknown ethertypes), not queue loss. Measured on myserver: rx_dropped=533353
# with rx_missed/fifo/over all 0.
NIC_DROP_STATS = ("rx_missed_errors", "rx_fifo_errors", "rx_over_errors")
WG_STATS = ("rx_frame_errors", "tx_errors", "tx_dropped")


def parse_snmp(text):
    """Parse /proc/net/snmp or /proc/net/netstat → {"Ip.FragCreates": int}."""
    out = {}
    lines = [l.split() for l in text.splitlines() if l.strip()]
    for hdr, vals in zip(lines[0::2], lines[1::2]):
        if not hdr or not vals or hdr[0] != vals[0]:
            continue
        proto = hdr[0].rstrip(":")
        for name, v in zip(hdr[1:], vals[1:]):
            try:
                out["%s.%s" % (proto, name)] = int(v)
            except ValueError:
                pass
    return out


def pick_snmp(counters):
    out = {}
    for proto, names in SNMP_WANTED.items():
        for n in names:
            k = "%s.%s" % (proto, n)
            if k in counters:
                out[k] = counters[k]
    return out


def parse_softnet(text):
    """/proc/net/softnet_stat → (dropped_total, squeeze_total). Hex columns."""
    dropped = squeeze = 0
    for line in text.splitlines():
        cols = line.split()
        if len(cols) >= 3:
            dropped += int(cols[1], 16)
            squeeze += int(cols[2], 16)
    return dropped, squeeze


def parse_proc_stat_cpu(text):
    """First 'cpu' line → dict of jiffies (user..steal)."""
    for line in text.splitlines():
        if line.startswith("cpu "):
            f = [int(x) for x in line.split()[1:]]
            names = ("user", "nice", "system", "idle", "iowait", "irq",
                     "softirq", "steal")
            return dict(zip(names, f + [0] * (len(names) - len(f))))
    raise ValueError("no cpu line")


def cpu_pct(prev, cur):
    """(total_busy_pct, softirq_pct) between two parse_proc_stat_cpu() dicts."""
    tp = sum(prev.values())
    tc = sum(cur.values())
    dt = tc - tp
    if dt <= 0:
        return None, None
    idle = (cur["idle"] + cur["iowait"]) - (prev["idle"] + prev["iowait"])
    soft = cur["softirq"] - prev["softirq"]
    return round(100.0 * (dt - idle) / dt, 2), round(100.0 * soft / dt, 2)


def parse_self_stat(text):
    """/proc/self/stat → utime+stime in clock ticks."""
    rest = text[text.rindex(")") + 2:].split()
    return int(rest[11]) + int(rest[12])


def parse_vmrss_mb(text):
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024.0
    return None


def _read(root, rel):
    with open(os.path.join(root, rel.lstrip("/")), "r") as f:
        return f.read()


def read_iface_stats(root, iface, names):
    out = {}
    base = os.path.join(root, "sys/class/net", iface, "statistics")
    for n in names:
        try:
            with open(os.path.join(base, n)) as f:
                out[n] = int(f.read().strip())
        except (OSError, ValueError):
            out[n] = None
    return out


def read_mtu(root, iface):
    try:
        with open(os.path.join(root, "sys/class/net", iface, "mtu")) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def read_frag_mem_pct(root):
    """IPv4 reassembly memory as % of net.ipv4.ipfrag_high_thresh.

    At ≥100% the kernel creates no new reassembly queue: every new fragment
    from every peer is dropped (counted in ReasmFails, not ReasmTimeout) —
    AFTER the capture taps, so the capture still sees those fragments
    complete (lab, 28 Oct: one peer whose tail fragments never arrive filled
    4 MiB and silenced another peer's fragmented upload). None if unreadable."""
    try:
        mem = None
        for line in _read(root, "proc/net/sockstat").splitlines():
            if line.startswith("FRAG:"):
                parts = line.split()
                mem = int(parts[parts.index("memory") + 1])
        hi = int(_read(root, "proc/sys/net/ipv4/ipfrag_high_thresh"))
        if mem is None or hi <= 0:
            return None
        return round(100.0 * mem / hi, 2)
    except (OSError, ValueError, IndexError):
        return None


def read_reasm_drops(root):
    """Cumulative IPv4 fragments dropped without ever being queued:
    Ip.ReasmFails − Ip.ReasmTimeout (ip_expire bumps both, so a tail lost on
    the path is excluded; a full reassembly memory is not). None if unreadable."""
    try:
        c = parse_snmp(_read(root, "proc/net/snmp"))
        return c["Ip.ReasmFails"] - c["Ip.ReasmTimeout"]
    except (OSError, KeyError):
        return None


def read_conntrack_pct(root):
    try:
        c = int(_read(root, "proc/sys/net/netfilter/nf_conntrack_count"))
        m = int(_read(root, "proc/sys/net/netfilter/nf_conntrack_max"))
        return round(100.0 * c / m, 2) if m > 0 else None
    except (OSError, ValueError):
        return None


class KernelSampler:
    """Holds previous raw readings and returns per-interval deltas.

    A counter that goes backwards (module reload, interface recreate) yields
    None for that interval rather than a negative or wrapped value.
    """

    def __init__(self, root="/", wan="eth0", user="wg1udp"):
        self.root = root
        self.wan = wan
        self.user = user
        self.prev = None
        self.prev_cpu = None
        self.prev_self = None

    def read_raw(self):
        raw = {}
        raw.update(pick_snmp(parse_snmp(_read(self.root, "proc/net/snmp"))))
        raw.update(pick_snmp(parse_snmp(_read(self.root, "proc/net/netstat"))))
        d, s = parse_softnet(_read(self.root, "proc/net/softnet_stat"))
        raw["softnet.dropped"] = d
        raw["softnet.squeeze"] = s
        nic = read_iface_stats(self.root, self.wan, NIC_DROP_STATS)
        raw["nic.missed_fifo"] = (None if any(v is None for v in nic.values())
                                  else sum(nic.values()))
        for k, v in read_iface_stats(self.root, self.user, WG_STATS).items():
            raw["wg1." + k] = v
        return raw

    def sample(self):
        """Return (deltas | None on first call, gauges)."""
        raw = self.read_raw()
        cpu = parse_proc_stat_cpu(_read(self.root, "proc/stat"))
        gauges = {"conntrack_pct": read_conntrack_pct(self.root),
                  "frag_mem_pct": read_frag_mem_pct(self.root),
                  "cpu_total_pct": None, "cpu_softirq_pct": None}
        if self.prev_cpu is not None:
            gauges["cpu_total_pct"], gauges["cpu_softirq_pct"] = cpu_pct(self.prev_cpu, cpu)
        self.prev_cpu = cpu
        deltas = None
        if self.prev is not None:
            deltas = {}
            for k, v in raw.items():
                p = self.prev.get(k)
                deltas[k] = (None if v is None or p is None or v < p else v - p)
        self.prev = raw
        return deltas, gauges


class SelfMonitor:
    """CPU% and RSS of the nqmo process itself (for budgets / backpressure)."""

    def __init__(self, root="/", hz=None, clock=None):
        import time as _t
        self.root = root
        self.hz = hz or (os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100)
        self.clock = clock or _t.monotonic
        self.prev = None

    def sample(self):
        ticks = parse_self_stat(_read(self.root, "proc/self/stat"))
        rss = parse_vmrss_mb(_read(self.root, "proc/self/status"))
        now = self.clock()
        pct = None
        if self.prev is not None:
            dt = now - self.prev[0]
            if dt > 0:
                pct = round(100.0 * (ticks - self.prev[1]) / self.hz / dt, 2)
        self.prev = (now, ticks)
        return pct, rss
