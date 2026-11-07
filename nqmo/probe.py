"""Manual active probe (design 04 §7). Off unless EVERY gate holds:
  1. mode == RECOMMENDATIONS_ENABLED        (checked by the engine)
  2. config active_probes == true           (checked by the engine)
  3. an explicit request for ONE peer, from the panel over ctl.sock (RBAC +
     audit are the panel's side)
  4. the peer handshook < 120 s ago; it stops if that goes > 180 s
  5. a 56-byte pre-test is answered, otherwise CLIENT_NO_ICMP and nothing is
     claimed
Budget: ≤40 packets and ≤60 KB per run, one run at a time server-wide,
one per peer per hour (the last two enforced by the engine).

What it measures: the inner ICMP packet carries DF (-M do), the outer
WireGuard packet does not (server df=0) — so fragmentation on the way still
"succeeds". A stable size threshold therefore means "packets above this size
are dropped somewhere on the round trip" (fragment-dropping path or a DF
client's black hole). The threshold is quantized to 16 B by WireGuard padding.
A local error (EMSGSIZE, permission) is PROBE_ERROR, never a "no reply".
Likewise a reply the SERVER dropped is not a path answer: a full IPv4
reassembly memory drops every new fragment, so a fragmented reply never
arrives and the boundary looks exactly like a path limit (lab, 28 Oct: a
healthy peer failed at 1316 only while another peer's fragments filled the
memory). Any such drop during the run makes the threshold INCONCLUSIVE.
"""
import re
import threading

from .runner import run_ro

PRETEST = 56
LOW = 1232
MAX_PACKETS = 40
MAX_BYTES = 60000
HS_START_MAX = 120
# Abort only when the session is truly gone: WireGuard rejects a keypair after
# REJECT_AFTER_TIME = 180 s. (60 s contradicted the 120 s start gate: a run
# started at 61–120 s aborted before its first packet — review round 4.)
HS_ABORT = 180
CONFIRM = 3

_SUMMARY = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")
_LOCAL_ERR = ("too long", "message too long", "sendmsg", "not permitted",
              "operation not permitted", "cannot assign", "unknown iface",
              "network is unreachable", "socket")


class ProbeError(RuntimeError):
    pass


def parse_ping(rc, out, err):
    """→ (sent, received) or raise ProbeError on a local failure."""
    e = (err or "").lower()
    m = _SUMMARY.search(out or "")
    # iputils: rc 0 = replies, 1 = no reply, anything else = local failure
    if rc not in (0, 1) or m is None or any(k in e for k in _LOCAL_ERR):
        raise ProbeError((err or out or "rc=%s" % rc).strip()[:160])
    return int(m.group(1)), int(m.group(2))


def grid(lo, hi):
    """Sizes S in [lo, hi] whose inner length S+28 is a 16-byte multiple
    (what WireGuard actually puts on the wire), plus both ends."""
    out = {lo, hi}
    s = lo + ((-(lo + 28)) % 16)
    while s <= hi:
        out.add(s)
        s += 16
    return sorted(out)


class ProbeRun(threading.Thread):
    """One run for one peer. Results go to `results` (a queue.Queue)."""

    def __init__(self, run_id, peer_pub, tunnel_ip, t_config, iface_mtu, iface,
                 hs_age, results, runner=run_ro, reasm_drops=None):
        super().__init__(name="nqmo-probe", daemon=True)
        # callable → cumulative ReasmFails−ReasmTimeout, or None if unreadable
        self.reasm_drops = reasm_drops or (lambda: None)
        self.run_id = run_id
        self.peer_pub = peer_pub
        self.tunnel_ip = tunnel_ip
        self.t_config = t_config
        self.iface_mtu = iface_mtu
        self.iface = iface
        self.hs_age = hs_age              # callable → seconds since handshake
        self.results = results
        self.runner = runner
        self.sent = 0
        self.bytes = 0
        self.log = []

    def _ping(self, size, count=2):
        if self.sent + count > MAX_PACKETS or self.bytes + (size + 28) * count > MAX_BYTES:
            raise ProbeError("BUDGET")
        age = self.hs_age()
        if age is None or age > HS_ABORT:
            raise ProbeError("STALE_HS")
        rc, out, err = self.runner(["ping", "-4", "-n", "-q", "-M", "do", "-s", str(size),
                                    "-c", str(count), "-W", "1", "-I", self.iface,
                                    self.tunnel_ip], timeout=count + 3, allow_probe=True)
        sent, rcv = parse_ping(rc, out, err)
        self.sent += sent
        self.bytes += (size + 28) * sent
        self.log.append([size, sent, rcv])
        return rcv > 0

    def execute(self):
        upper = min(self.t_config, self.iface_mtu) - 28
        if upper < LOW:
            return {"verdict": "UNDETERMINED", "reason": "RANGE_EMPTY"}
        if not self._ping(PRETEST):
            return {"verdict": "CLIENT_NO_ICMP"}
        if not self._ping(LOW):
            return {"verdict": "INCONCLUSIVE", "reason": "SMALL_PACKETS_LOST"}
        if self._ping(upper):
            return {"verdict": "FULL_PATH_OK", "s_max": upper}
        g = grid(LOW, upper)
        lo, hi = 0, len(g) - 1                    # g[lo] ok, g[hi] failed
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if self._ping(g[mid]):
                lo = mid
            else:
                hi = mid
        ok = sum(self._ping(g[lo], 1) for _ in range(CONFIRM))
        bad = sum(not self._ping(g[hi], 1) for _ in range(CONFIRM))
        if ok >= 2 and bad == CONFIRM:
            return {"verdict": "THRESHOLD", "s_star": g[lo], "s_fail": g[hi]}
        return {"verdict": "INCONCLUSIVE", "reason": "UNSTABLE_BOUNDARY",
                "s_ok": g[lo], "s_fail": g[hi]}

    def run(self):
        d0 = self.reasm_drops()
        res: dict
        try:
            res = self.execute()
        except ProbeError as e:
            reason = str(e)
            res = {"verdict": "PROBE_ERROR" if reason not in ("BUDGET", "STALE_HS")
                   else "ABORTED", "reason": reason}
        except Exception as e:                    # never kill silently
            res = {"verdict": "PROBE_ERROR", "reason": "%s: %s" % (type(e).__name__, e)}
        d1 = self.reasm_drops()
        drops = (d1 - d0) if (d0 is not None and d1 is not None) else None
        res["server_reasm_drops"] = drops
        if res.get("verdict") == "THRESHOLD" and drops:
            res = {"verdict": "INCONCLUSIVE", "reason": "SERVER_REASM_DROPS",
                   "s_ok": res["s_star"], "s_fail": res["s_fail"],
                   "server_reasm_drops": drops}
        # identity travels with the result, never looked up later from whatever
        # run is current (review round 4, F8)
        res.update({"run_id": self.run_id, "peer": self.peer_pub, "t_config": self.t_config,
                    "peer_id": getattr(self, "peer_id", None),
                    "requested_by": getattr(self, "requested_by", "?"),
                    "packets_sent": self.sent, "bytes_sent": self.bytes, "log": self.log})
        self.results.put(res)
