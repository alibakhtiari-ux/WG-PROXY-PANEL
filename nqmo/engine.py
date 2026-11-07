"""Wires collectors, aggregator, store, export and ctl into one process.

Threads and ownership (review round 2, B1/M4/M8):
  main      scheduler, aggregator, store, ctl request handling — the ONLY
            thread that touches the aggregator or the SQLite connection
  nqmo-cap  S1 S2 S3 S5 on one select loop; each socket reopens itself with
            backoff after an error (e.g. wg1udp recreated); every lost frame
            or socket error becomes a timestamped gap event
  nqmo-ring S4 via TPACKET_V3, reduced *in this thread* (S4Reducer) to
            per-minute summaries; only summaries cross to main
  nqmo-tc   `tc -s -j show` once a minute, off the main loop
  nqmo-ctl  socket front-end; hands requests to main via a queue

Minute M is flushed at M+60+FLUSH_DELAY, after the ring thread has reported
it (or, at worst, 10 s later with a S4:NO_SUMMARY taint). The watchdog
tracks the main loop only: a capture failure degrades data quality, it never
restart-loops the service.
"""
import collections
import faulthandler
import json
import os
import queue
import select
import signal
import sqlite3
import sys
import threading
import time

from . import asn as asnmod
from . import config as cfgmod
from . import export, store as storemod
from .analysis import Analysis
from .aggregate import FLUSH_DELAY, Aggregator, S4Reducer, key_fp, minute_of
from .collect import kernel, meta as metamod, tcstats, wgparse
from .ctl import Handler, Server, serve_pending
from .runner import NotAllowed, run_ro
from .sched import Scheduler, sd_notify

THREAD_STALE_S = 30.0
RING_WAIT_MAX = 10.0
# §29.161: a main-loop step that outlives this dumps every thread's Python
# stack to stderr (the journal) BEFORE systemd's WatchdogSec=90 SIGABRT, so the
# next stall names its own line; and any single phase slower than SLOW_PHASE_S
# is reported as an engine error with its name.
STALL_DUMP_S = 60.0
SLOW_PHASE_S = 10.0
LOOP_PHASES = ("ctl", "probes", "drain", "taints", "tasks", "flush")
REOPEN_BACKOFF = (5, 15, 30, 60)


def load_secret(path):
    """32 random bytes, created once. A wrong-length file is an error, not a
    reason to silently re-key every ip_hmac."""
    try:
        with open(path, "rb") as f:
            s = f.read()
        if len(s) != 32:
            raise RuntimeError("%s: expected 32 bytes, found %d — refusing to re-key"
                               % (path, len(s)))
        return s
    except FileNotFoundError:
        pass
    s = os.urandom(32)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(s)
    os.replace(path + ".tmp", path)
    return s


class EventBus:
    """Bounded, drop-oldest event deque."""

    def __init__(self, maxlen):
        self.q = collections.deque(maxlen=maxlen)
        self.maxlen = maxlen
        self.dropped = 0
        self.lock = threading.Lock()

    def put(self, ev):
        with self.lock:
            if len(self.q) >= self.maxlen:
                self.dropped += 1
            self.q.append(ev)

    def drain(self, limit=200000):
        out = []
        with self.lock:
            while self.q and len(out) < limit:
                out.append(self.q.popleft())
            dropped, self.dropped = self.dropped, 0
        return out, dropped


class _Worker(threading.Thread):
    # How long a heartbeat stays fresh. Must outlast the longest sleep in run():
    # a shorter value reports every idle worker as stalled.
    STALE_S = THREAD_STALE_S

    def __init__(self, name):
        super().__init__(name=name, daemon=True)
        self.stop = threading.Event()
        self.heartbeat = time.monotonic()
        self.error = ""

    def healthy(self):
        return (self.is_alive() and not self.error
                and time.monotonic() - self.heartbeat <= self.STALE_S)


class LowRateCapture(_Worker):
    """S1 S2 S3 S5. Receive-only; sockets reopen themselves with backoff."""

    def __init__(self, cfg, bus):
        super().__init__("nqmo-cap")
        self.cfg = cfg
        self.bus = bus

    def _open(self, name):
        from .collect import capture
        role, proto, prog = capture.STREAMS[name]
        ifname = self.cfg["capture"]["wan_iface" if role == "wan" else "user_iface"]
        return capture.open_tap(ifname, proto, prog)

    def run(self):
        from .collect import bpf, capture
        try:
            capture.check_port(self.cfg["capture"]["listen_port"])
        except capture.CaptureError as e:
            self.error = str(e)
            return
        socks, retry = {}, {n: (0.0, 0) for n in capture.STREAMS}
        try:
            while not self.stop.is_set():
                now_m = time.monotonic()
                self.heartbeat = now_m
                for name, (at, n) in list(retry.items()):
                    if now_m >= at:
                        try:
                            socks[name] = self._open(name)
                            del retry[name]
                        except OSError as e:
                            self.error = "%s: %s" % (name, e)
                            retry[name] = (now_m + REOPEN_BACKOFF[min(n, 3)], n + 1)
                if not retry:
                    self.error = ""
                by_fd = {s.fileno(): n for n, s in socks.items()}
                ready = select.select(list(by_fd), [], [], 1.0)[0] if by_fd else \
                    (self.stop.wait(1.0) and [])
                for fd in ready or []:
                    name = by_fd[fd]
                    s = socks[name]
                    snap = bpf.PROGRAMS[capture.STREAMS[name][2]]["snaplen"]
                    try:
                        ts, pkttype, data = capture.recv_one(s, snap)
                    except OSError as e:      # ENETDOWN, ifindex gone, …
                        self.bus.put(("gap", time.time(), "SOCK_ERR:" + name))
                        self.error = "%s: %s" % (name, e)
                        s.close()
                        del socks[name]
                        retry[name] = (time.monotonic() + REOPEN_BACKOFF[0], 1)
                        continue
                    if ts is None:
                        self.bus.put(("gap", time.time(), "NO_KERNEL_TS:" + name))
                        continue
                    self.bus.put((name, ts, pkttype, data))
                # after every select (≤1 s apart when idle); a drop is tainted at
                # ts and ts−1.5. A batched loop was measured in the lab (28 Oct,
                # simultaneous A/B on the same packets): no difference in drops
                for name, s in socks.items():
                    try:
                        _pk, drops = capture.read_stats(s)
                    except OSError:
                        continue
                    if drops:
                        self.bus.put(("gap", time.time(), "KERNEL_DROP:" + name))
        except Exception as e:
            self.error = "%s: %s" % (type(e).__name__, e)
        finally:
            for s in socks.values():
                s.close()


class RingCapture(_Worker):
    """S4 via TPACKET_V3, reduced in-thread. Emits ("S4SUM", minute, …) for
    every closed minute and ("S4DONE", minute) once it has reported it."""

    def __init__(self, cfg, bus, wan_mtu):
        super().__init__("nqmo-ring")
        self.cfg = cfg
        self.bus = bus
        self.sampling = threading.Event()
        self.reducer = S4Reducer(wan_mtu)

    def _report(self, now):
        upto = minute_of(now - 60 - 1.0)
        for m, summ, taints in self.reducer.harvest(upto):
            self.bus.put(("S4SUM", m, summ, taints))
        self.bus.put(("S4DONE", upto))

    def run(self):
        from .collect import capture, ring
        c = self.cfg["capture"]
        try:
            capture.check_port(c["listen_port"])
        except capture.CaptureError as e:
            self.error = str(e)
            return
        r, n_fail, next_try = None, 0, 0.0
        skipping = False
        try:
            while not self.stop.is_set():
                self.heartbeat = time.monotonic()
                now = time.time()
                if r is None:
                    if time.monotonic() >= next_try:
                        try:
                            r = ring.Ring(c["wan_iface"], c["ring_block_kb"], c["ring_blocks"])
                            self.error = ""
                            self.reducer.gap(now, "RING_OPEN")
                        except OSError as e:
                            self.error = "ring: %s" % e
                            next_try = time.monotonic() + REOPEN_BACKOFF[min(n_fail, 3)]
                            n_fail += 1
                    if r is None:
                        self.reducer.taint(now, "S4:DOWN")
                        self._report(now)
                        self.stop.wait(1.0)
                        continue
                parse = not (self.sampling.is_set() and (now % 60) >= 5)
                if not parse and not skipping:
                    self.reducer.gap(now, "SAMPLED")
                skipping = not parse
                try:
                    for kind, item in r.poll(1.0, parse=parse):
                        if kind == "gap":
                            self.reducer.gap(time.time(), "KERNEL_DROP")
                        else:
                            ts, _tp_len, frame = item
                            self.reducer.frame(ts, frame)
                except OSError as e:
                    self.error = "ring: %s" % e
                    self.reducer.gap(time.time(), "RING_ERR")
                    r.close()
                    r = None
                    continue
                now = time.time()
                self.reducer.expire(now)
                self._report(now)
        except Exception as e:
            self.error = "%s: %s" % (type(e).__name__, e)
        finally:
            if r is not None:
                r.close()


class TcCollector:
    """Per-IP drop/overlimit deltas from the panel's htb, if installed."""

    def __init__(self, user_iface):
        self.dev = user_iface
        self.ifb = ("ib_" + user_iface)[:15]
        self.prev = {}

    def _json(self, what, dev):
        # the allowlist refuses an interface that does not exist (no ifb on
        # this host, wg1udp being recreated): that is "no data", and must not
        # abort the minute's route checks that run after this (lab, 28 Oct)
        try:
            rc, out, _err = run_ro(["tc", "-s", "-j", what, "show", "dev", dev])
        except NotAllowed:
            return None
        return out if rc == 0 else None

    def sample(self):
        q = self._json("qdisc", self.dev)
        if not q or '"htb"' not in q:
            self.prev = {}
            return {}
        res = {}
        for dev, direction in ((self.dev, "dst"), (self.ifb, "src")):
            cls = self._json("class", dev)
            flt = self._json("filter", dev)
            if cls is None or flt is None:
                continue
            for ip, st in tcstats.per_ip(tcstats.parse_classes(cls),
                                         tcstats.parse_filters(flt, direction)).items():
                key = (dev, ip)
                cur = (st.get("drops") or 0, st.get("overlimits") or 0)
                p = self.prev.get(key)
                self.prev[key] = cur
                if p is None or cur[0] < p[0] or cur[1] < p[1]:
                    continue
                d = res.setdefault(ip, [0, 0])
                d[0] += cur[0] - p[0]
                d[1] += cur[1] - p[1]
        return res


def route_status(meta, wan, runner=run_ro, limit=64):
    """{endpoint_ip: reply route leaves via the WAN?} using the kernel's own
    decision (`ip route get <ep> from <local> [mark <fwmark>]`)."""
    out = {}
    if meta is None:
        return out
    for ip in sorted(meta.endpoint_ips)[:limit]:
        argv = ["ip", "-j", "route", "get", ip]
        if meta.wg1udp_local_ip:
            argv += ["from", meta.wg1udp_local_ip]
        if meta.wg1udp_fwmark:
            argv += ["mark", "0x%x" % meta.wg1udp_fwmark]
        try:
            rc, txt, err = runner(argv, timeout=5)
        except NotAllowed:
            continue                        # never reached with validated meta; no data
        if rc != 0:
            # a prohibit / unreachable / blackhole route makes `ip route get`
            # itself fail — that IS a routing anomaly, not missing data
            e = (err or "").lower()
            if any(k in e for k in ("permission denied", "unreachable", "no route",
                                    "invalid argument", "prohibit")):
                out[ip] = False
            continue
        try:
            routes = json.loads(txt)
        except ValueError:
            continue
        if isinstance(routes, list) and routes and isinstance(routes[0], dict):
            r = routes[0]
            if r.get("type") in ("blackhole", "prohibit", "unreachable"):
                out[ip] = False
            elif r.get("dev"):
                out[ip] = (r["dev"] == wan)
    return out


class NetThread(_Worker):
    """Once a minute, off the main loop: tc stats and reply-route checks."""
    INTERVAL_S = 60.0
    STALE_S = INTERVAL_S + THREAD_STALE_S   # a round may run this long before it counts as stuck

    def __init__(self, cfg, bus, meta_getter):
        super().__init__("nqmo-net")
        self.tc = TcCollector(cfg["capture"]["user_iface"])
        self.wan = cfg["capture"]["wan_iface"]
        self.bus = bus
        self.meta_getter = meta_getter     # Meta objects are immutable: safe to read

    def run(self):
        while not self.stop.is_set():
            self.heartbeat = time.monotonic()
            try:
                res = self.tc.sample()
                if res:
                    self.bus.put(("TC", time.time(), None, res))
                routes = route_status(self.meta_getter(), self.wan)
                if routes:
                    self.bus.put(("ROUTE", time.time(), None, routes))
                self.error = ""
            except Exception as e:
                self.error = "%s: %s" % (type(e).__name__, e)
            self.stop.wait(self.INTERVAL_S)


class Engine:
    def __init__(self, cfg, cfg_path=None, root="/", clock=time.time):
        os.umask(0o077)                    # -wal/-shm/state tmp files inherit this
        self.cfg = cfg
        self.cfg_path = cfg_path
        self.root = root
        self.clock = clock
        p = cfg["paths"]
        self.store = storemod.Store(p["db"], now=clock)
        self.secret = load_secret(p["secret"])
        self.errors = []
        self.asn = None
        try:
            self.asn = asnmod.load_dir(p["asn_dir"])   # absent ⇒ PREFIX_ONLY grouping
        except (OSError, asnmod.AsnError) as e:
            self._err("asn", e)
        self.agg = Aggregator(self.secret, cfg["limits"]["pending_hs_max"],
                              cfg["limits"]["frag_table_max"], asn=self.asn)
        self.analysis = Analysis(self.store, cfg, clock=clock,
                                 iface_mtu=lambda dev: kernel.read_mtu(root, dev),
                                 reasm_drops=lambda: kernel.read_reasm_drops(root),
                                 progress=self._heartbeat)
        self.bus = EventBus(cfg["limits"]["queue_max"])      # low-rate + tc
        self.bus_s4 = EventBus(4096)                           # summaries only
        self.kern = kernel.KernelSampler(root, cfg["capture"]["wan_iface"],
                                         cfg["capture"]["user_iface"])
        self.selfmon = kernel.SelfMonitor(root)
        self.meta_error = "not read yet"
        self.workers = []
        self.ring = None
        self.ctl = None
        self.ctl_q = queue.Queue(maxsize=16)
        self.stop = threading.Event()
        self.sched = Scheduler()
        now = clock()
        self.next_flush = minute_of(now)
        self.agg.taint(now, "STARTUP")                       # first minute is partial
        self.ring_done = None
        self.tc_pending = {}
        self.loop_ms = {}             # phase → max ms since the last minute flush (§29.161)
        self.last_loop_ms = {}
        self.last_glob = collections.Counter()
        self.last_global = {}
        self.last_kernel_at = None
        self.handler = Handler(self.get_mode, self.set_mode, self.ack, self.probe)
        self.mode = self._resolve_mode()

    # ---- mode ----------------------------------------------------------------
    def _resolve_mode(self):
        cfg_mode = self.cfg["mode"]
        if self.store.read_only:
            return cfg_mode
        seen = self.store.get_meta("mode_cfg_seen")
        override = self.store.get_meta("mode_override")
        if seen != cfg_mode:                  # operator edited the file: it wins
            with self.store.transaction() as s:
                s.set_meta("mode_cfg_seen", cfg_mode)
                s.set_meta("mode_override", cfg_mode)
            return cfg_mode
        return override if override in cfgmod.MODES else cfg_mode

    def get_mode(self):
        return self.mode

    def set_mode(self, to, actor):
        old = self.mode
        with self.store.transaction() as s:
            s.set_meta("mode_override", to)
            s.config_event("MODE", "nqmo", old, "%s by %s" % (to, actor))
        self.mode = to

    def probe(self, peer_name, actor):
        r = self.analysis.request_probe(peer_name, actor, self.mode, lambda: self.agg.meta)
        if r.get("ok"):
            with self.store.transaction() as s:
                s.config_event("PROBE", peer_name, None, "requested by %s" % actor)
        return r

    def ack(self, diag_id, actor):
        with self.store.transaction() as s:
            cur = s.conn.execute(
                "UPDATE diagnosis SET ack_by=?, ack_ts=? WHERE id=? AND state='OPEN' "
                "AND ack_by IS NULL", (actor, self.clock(), diag_id))
            return cur.rowcount == 1

    # ---- helpers ---------------------------------------------------------------
    def _err(self, where, e):
        self.errors.append({"ts": round(self.clock(), 1), "where": where,
                            "error": ("%s: %s" % (type(e).__name__, e))[:200]})
        del self.errors[:-50]

    def capture_enabled(self):
        return bool(self.cfg["capture"]["enabled"])

    # ---- tasks -------------------------------------------------------------------
    def task_meta(self):
        try:
            m = metamod.read(self.cfg["paths"]["meta"], self.clock())
        except metamod.MetaError as e:
            self.meta_error = str(e)[:300]
            return
        self.meta_error = ""
        self.agg.set_meta(m)

    def drain(self):
        now = self.clock()
        events, dropped = self.bus.drain()
        if dropped:
            self.agg.user_drops += dropped
            self.agg.taint(now, "LOWRATE_QUEUE_DROP")
            self.agg.taint(now - 1.5, "LOWRATE_QUEUE_DROP")
        for ev in events:
            kind = ev[0]
            if kind == "gap":
                _k, ts, reason = ev
                self.agg.taint(ts, reason)
                self.agg.taint(ts - 1.5, reason)       # stats are read ~1 s late
                continue
            if kind == "TC":
                self.tc_pending[minute_of(ev[1])] = ev[3]
                continue
            if kind == "ROUTE":
                self.agg.set_routes(ev[1], ev[3])
                continue
            _k, ts, pkttype, data = ev
            if kind == "S1":
                m = wgparse.parse_wg(data)
                if m is not None:
                    self.agg.on_s1(ts, pkttype == 4, m)
            elif kind == "S2":
                f = wgparse.parse_first_frag(data)
                if f is not None:
                    self.agg.on_s2(ts, f)
            elif kind == "S3":
                f = wgparse.parse_tail_frag(data)
                if f is not None:
                    self.agg.on_s3(ts, f)
            elif kind == "S5":
                r = wgparse.parse_syn(data)
                if r is not None:
                    self.agg.on_s5(ts, r[0], r[1])
        s4, dropped4 = self.bus_s4.drain()
        if dropped4:
            self.agg.taint(now, "S4:SUMMARY_DROP")
        for ev in s4:
            if ev[0] == "S4SUM":
                self.agg.on_s4_summary(ev[1], ev[2], ev[3])
            elif ev[0] == "S4DONE":
                self.ring_done = ev[1]
        self.agg.expire(now)

    def _health_taints(self, now):
        if not self.capture_enabled():
            return
        for w in self.workers:
            if isinstance(w, (LowRateCapture, RingCapture)) and not w.healthy():
                self.agg.taint(now, "C3:DOWN:" + w.name)

    def maybe_flush(self):
        now = self.clock()
        while now >= self.next_flush + 60 + FLUSH_DELAY:
            m = self.next_flush
            ring_alive = self.ring is not None and self.ring.is_alive()
            extra = set()
            if not self.capture_enabled():
                extra.add("C3:DISABLED")
            elif ring_alive and (self.ring_done is None or self.ring_done < m):
                if now < m + 60 + RING_WAIT_MAX:
                    return                      # wait for the ring's summary
                extra.add("S4:NO_SUMMARY")
            latest = now < m + 120 + FLUSH_DELAY   # the most recent closed minute
            self._flush_minute(m, now, extra, latest)
            self._heartbeat()                      # a backlog of minutes is progress too
            self.next_flush = m + 60
            if (m + 60) % 300 == 0:                 # a 5-minute window just closed
                try:
                    self.analysis.run_window(m + 60 - 300, self.agg.meta, self.mode)
                except Exception as e:              # analysis must never stop collection
                    self._err("analysis", e)

    def _kernel_row(self, m, latest):
        g = {"ts": m, "quality": "GOOD"}
        if not latest:
            g["quality"] = "INVALID"            # backlog minute: no per-minute counters
            return g
        try:
            deltas, gauges = self.kern.sample()
            span_ok = (self.last_kernel_at is not None
                       and self.clock() - self.last_kernel_at <= 90)
            self.last_kernel_at = self.clock()
            if deltas is None or not span_ok:
                g["quality"] = "INVALID"
            else:
                g.update({
                    "frag_creates": deltas.get("Ip.FragCreates"),
                    "frag_fails": deltas.get("Ip.FragFails"),
                    "reasm_reqds": deltas.get("Ip.ReasmReqds"),
                    "reasm_fails": deltas.get("Ip.ReasmFails"),
                    "reasm_timeout": deltas.get("Ip.ReasmTimeout"),
                    "icmp_out_unreach": deltas.get("Icmp.OutDestUnreachs"),
                    "icmp_in_unreach": deltas.get("Icmp.InDestUnreachs"),
                    "udp_rcvbuf_err": deltas.get("Udp.RcvbufErrors"),
                    "udp_sndbuf_err": deltas.get("Udp.SndbufErrors"),
                    "wg1_rx_frame_err": deltas.get("wg1.rx_frame_errors"),
                    "wg1_tx_err": deltas.get("wg1.tx_errors"),
                    "wg1_tx_dropped": deltas.get("wg1.tx_dropped"),
                    "eth0_rx_missed_fifo": deltas.get("nic.missed_fifo"),
                    "softnet_dropped": deltas.get("softnet.dropped"),
                    "softnet_squeeze": deltas.get("softnet.squeeze"),
                })
            g.update(gauges)
        except (OSError, ValueError) as e:
            # a failed read must not make the next delta span two minutes
            self.kern.prev = None
            self.kern.prev_cpu = None
            self.last_kernel_at = None
            g["quality"] = "INVALID"
            self._err("kernel", e)
        try:
            g["nqmo_cpu_pct"], g["nqmo_rss_mb"] = self.selfmon.sample()
        except (OSError, ValueError) as e:
            self._err("selfmon", e)
        if self.ring is not None:
            cpu = g.get("nqmo_cpu_pct")
            lim = self.cfg["capture"]["s4_cpu_pct_max"]
            if cpu is not None and cpu > lim:
                self.ring.sampling.set()
            elif cpu is not None and cpu < lim * 0.6:
                self.ring.sampling.clear()
        return g

    def _flush_minute(self, m, now, extra, latest):
        g = self._kernel_row(m, latest)
        meta = self.agg.meta
        if meta is not None:
            g["egress_json"] = json.dumps(meta.egress, sort_keys=True)
        health = self.sched.health(reset=True)
        tc = self.tc_pending.pop(m, None)
        for k in [k for k in self.tc_pending if k < m]:
            del self.tc_pending[k]
        try:
            with self.store.transaction() as s:
                _rows, glob = self.agg.flush(m, s, now=now,
                                             meta_stale_s=self.cfg["limits"]["meta_stale_s"],
                                             extra_why=extra)
                g["hs_cookie_out"] = glob.get("hs_cookie_out", 0)
                g["c3_user_drops"] = self.agg.user_drops
                self.agg.user_drops = 0
                if tc and meta is not None:
                    self._apply_tc(s, m, tc, meta)
                s.put_global_minute(g)
                for name, h in health.items():
                    s.put_collector_health(m, name, h["runs"], h["failures"],
                                           h["max_ms"], h["last_error"])
                for w in self.workers:
                    s.put_collector_health(m, w.name, 1, int(not w.healthy()), None,
                                           w.error or None)
                loop_ms, self.loop_ms = self.loop_ms, {}
                self.last_loop_ms = loop_ms
                for ph in LOOP_PHASES:
                    if ph in loop_ms:
                        s.put_collector_health(m, "loop:" + ph, 1, 0, loop_ms[ph], None)
            self.last_glob = glob
        except (storemod.StoreError, sqlite3.Error) as e:
            self._err("store", e)
        self.last_global = g

    def _apply_tc(self, s, m, tc, meta):
        for ip, (drops, over) in tc.items():
            pub = meta.by_tunnel_ip.get(ip)
            if pub is None:
                continue
            p = meta.peers[pub]
            pid = s.peer_id(p["iface"], p["name"], key_fp(pub))
            s.conn.execute("UPDATE peer_minute SET tc_drops=?, tc_overlimits=? "
                           "WHERE peer_id=? AND ts=?", (drops, over, pid, int(m)))

    def task_export(self):
        now = self.clock()
        meta = self.agg.meta
        threads = {w.name: {"alive": w.is_alive(), "healthy": w.healthy(),
                            "error": w.error} for w in self.workers}
        coverage = {
            "capture_enabled": self.capture_enabled(),
            "threads": threads,
            "meta_age_s": None if meta is None else round(meta.age(now), 1),
            "meta_error": self.meta_error,
            "peers_total": 0 if meta is None else len(meta.peers),
            "peers_handshake_180s": 0 if meta is None else sum(
                1 for p in meta.peers.values()
                if p["latest_handshake"] and now - p["latest_handshake"] < 180),
            "ambiguous_endpoints": 0 if meta is None else len(meta.ambiguous_endpoints),
            "unmodelled_endpoints": 0 if meta is None else meta.unmodelled_endpoints,
            "last_minute_unmapped": {k: v for k, v in self.last_glob.items()
                                     if k.startswith("unmapped")},
            "asn": None,
            # the engine's own cost (§29.153): the last minute's CPU and RSS, and
            # whether S4 is in sampling rotation because CPU crossed the cap —
            # the one state that silently degrades data quality
            "loop_ms": dict(self.last_loop_ms),
            "engine": {"cpu_pct": self.last_global.get("nqmo_cpu_pct"),
                       "rss_mb": self.last_global.get("nqmo_rss_mb"),
                       "cpu_pct_max": self.cfg["capture"]["s4_cpu_pct_max"],
                       "sampling": self.ring is not None and self.ring.sampling.is_set()},
        }
        cap = [w for w in self.workers if isinstance(w, (LowRateCapture, RingCapture))]
        collectors = {"C1_meta": not self.meta_error and meta is not None
                      and meta.age(now) <= self.cfg["limits"]["meta_stale_s"],
                      "C2_kernel": self.last_global.get("quality") == "GOOD",
                      "C3_capture": (None if not self.capture_enabled()
                                     else bool(cap) and all(w.healthy() for w in cap))}
        store_info = {"size_mb": round(self.store.size_mb(), 2),
                      "read_only": self.store.read_only,
                      "recreated": self.store.recreated}
        try:
            names = self.analysis.diag.peer_names()
            ana = self.analysis.snapshot(names)
        except Exception as e:
            self._err("snapshot", e)
            ana = {}
        coverage["asn"] = (None if self.asn is None else
                           {"sha": self.asn.sha, "ranges": self.asn.size,
                            "stale": self.asn.stale(now)})
        st = export.build_state(now, self.mode, collectors, coverage, self.errors, store_info,
                                analysis=ana)
        try:
            export.write_atomic(self.cfg["paths"]["state"], st)
        except OSError as e:
            self._err("export", e)

    def task_prune(self):
        try:
            self.store.prune(self.cfg["retention_days"])
        except (storemod.StoreError, sqlite3.Error) as e:
            self._err("prune", e)
        if self.store.size_mb() > self.cfg["limits"]["max_db_mb"]:
            self._err("store", RuntimeError("DB_SIZE_CAP exceeded"))

    def task_supervise(self):
        """Restart workers that died of an unexpected bug (sockets already
        self-heal inside their threads)."""
        for i, w in enumerate(self.workers):
            if not w.is_alive() and not w.stop.is_set():
                nw = self._make_worker(w)
                if nw is not None:
                    self.workers[i] = nw
                    nw.start()
                    if isinstance(nw, RingCapture):
                        self.ring = nw
        if self.ctl is not None and not self.ctl.is_alive():
            self._start_ctl()

    def _make_worker(self, old):
        if isinstance(old, LowRateCapture):
            return LowRateCapture(self.cfg, self.bus)
        if isinstance(old, RingCapture):
            return RingCapture(self.cfg, self.bus_s4,
                               kernel.read_mtu(self.root, self.cfg["capture"]["wan_iface"]))
        if isinstance(old, NetThread):
            return NetThread(self.cfg, self.bus, lambda: self.agg.meta)
        return None

    # ---- lifecycle -------------------------------------------------------------
    def _start_ctl(self):
        self.ctl = Server(self.cfg["paths"]["ctl"], self.ctl_q)
        self.ctl.start()

    def start(self):
        iv = self.cfg["intervals"]
        self.sched.add("meta", iv["meta_s"], 1.0, self.task_meta)
        self.sched.add("export", iv["export_s"], 2.0, self.task_export)
        self.sched.add("prune", iv["prune_s"], 30.0, self.task_prune,
                       start_at=time.monotonic() + 60)
        self.sched.add("supervise", 60.0, 1.0, self.task_supervise,
                       start_at=time.monotonic() + 60)
        self.workers.append(NetThread(self.cfg, self.bus, lambda: self.agg.meta))
        if self.capture_enabled():
            if not sys.platform.startswith("linux"):
                self._err("capture", RuntimeError("capture needs Linux"))
            else:
                self.ring = RingCapture(self.cfg, self.bus_s4,
                                        kernel.read_mtu(self.root, self.cfg["capture"]["wan_iface"]))
                self.workers += [LowRateCapture(self.cfg, self.bus), self.ring]
        for w in self.workers:
            w.start()
        self._start_ctl()

    def step(self):
        """One main-loop iteration (also used by tests). Each phase is timed:
        the per-minute maximum goes to collector_health as loop:<phase> (and to
        state.json coverage.loop_ms) and a phase over SLOW_PHASE_S is an error."""
        self._phase("ctl", lambda: serve_pending(self.ctl_q, self.handler))

        def probes():
            try:
                self.analysis.collect_probes()
            except Exception as e:
                self._err("probe", e)
        self._phase("probes", probes)
        self._phase("drain", self.drain)
        self._phase("taints", lambda: self._health_taints(self.clock()))
        self._phase("tasks", self.sched.run_due)
        self._phase("flush", self.maybe_flush)

    def _heartbeat(self):
        """Watchdog heartbeat from inside a long phase (§29.161): the loop is
        progressing, so a slow window analysis must not count as a hang."""
        sd_notify("WATCHDOG=1")

    def _phase(self, name, fn):
        t0 = time.monotonic()
        try:
            fn()
        finally:
            dt = time.monotonic() - t0
            if dt > self.loop_ms.get(name, 0.0) / 1000.0:
                self.loop_ms[name] = round(dt * 1000.0, 1)
            if dt > SLOW_PHASE_S:
                self._err("loop:" + name, RuntimeError("phase took %.1f s" % dt))

    def shutdown(self):
        for w in self.workers:
            w.stop.set()
        if self.ctl is not None:
            self.ctl.stop.set()
        for w in self.workers:
            w.join(timeout=3)
        if self.ctl is not None:
            self.ctl.join(timeout=3)          # lets it remove its socket file
        try:
            self.drain()
        finally:
            self.store.close()

    def reload(self):
        """SIGHUP: only mode, retention and active_probes change live; every
        other key needs a restart and is reported, not half-applied."""
        try:
            new = cfgmod.load(self.cfg_path) if self.cfg_path else self.cfg
        except cfgmod.ConfigError as e:
            self._err("reload", e)          # keep the previous config
            return False
        for k in ("retention_days", "active_probes"):
            self.cfg[k] = new[k]
        changed = [k for k in ("capture", "paths", "intervals", "limits")
                   if new[k] != self.cfg[k]]
        if changed:
            self._err("reload", RuntimeError("restart required for: " + ", ".join(changed)))
        if new["mode"] != self.cfg["mode"]:
            self.cfg["mode"] = new["mode"]
            self.mode = self._resolve_mode()
        return True

    def run_forever(self):
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        hup = threading.Event()
        signal.signal(signal.SIGHUP, lambda *_: hup.set())
        self.start()
        sd_notify("READY=1")
        # the watchdog kill (SIGABRT) and a step over STALL_DUMP_S both write
        # every thread's stack to stderr → journal (§29.161)
        try:
            faulthandler.enable(all_threads=True)
            faulthandler.register(signal.SIGABRT, all_threads=True, chain=True)
        except (RuntimeError, AttributeError, ValueError):
            pass
        while not self.stop.is_set():
            if hup.is_set():
                hup.clear()
                self.reload()
            faulthandler.dump_traceback_later(STALL_DUMP_S, repeat=False)
            try:
                self.step()
            finally:
                faulthandler.cancel_dump_traceback_later()
            sd_notify("WATCHDOG=1")             # main loop progressed
            self.stop.wait(0.5)
        sd_notify("STOPPING=1")
        self.shutdown()
