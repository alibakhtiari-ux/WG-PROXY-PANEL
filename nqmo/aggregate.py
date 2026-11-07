"""Turns capture events + meta snapshots into per-peer minute rows.

Exactness rules (design 02 §C3; review rounds 1 and 2):
  * Every event is bucketed by its *kernel* timestamp, never by when it was
    drained. Minute M is flushed only after M has closed + FLUSH_DELAY, so a
    late drain cannot move an event into the wrong row.
  * RTT: a sample exists only for an index-exact pair (Response↔first data of
    that keypair with counter 0, or Initiation↔Response). Unpaired → MISSED.
  * Loss (S4Reducer, owned by the ring thread): replay-window accounting with
    WireGuard's own window (COUNTER_WINDOW_SIZE = 8192 − 64; a counter exactly
    W behind the highest is still accepted, as in counter_validate). A counter
    is judged when it leaves the window — received or lost — so there is no
    boundary error. A capture gap first folds what was already judged, then
    discards the open windows: loss is never invented across a gap.
  * Attribution: data is mapped by receiver index (learned from the server's
    own outgoing Response/Initiation) before falling back to endpoint, so two
    peers that share an ip:port behind CGNAT are never mixed. An ambiguous
    endpoint maps to nobody.
"""
import hashlib
import hmac
import ipaddress
from collections import Counter

from .collect import wgparse

COUNTER_WINDOW = 8192 - 64          # WireGuard COUNTER_WINDOW_SIZE
BITMAP = COUNTER_WINDOW + 1         # holds (h−W, h] inclusive of h−W
MAX_COUNTER_JUMP = 1 << 20
PENDING_HS_TTL = 5.0
FRAG_TTL = 30.0
ORPHAN_TAIL_TTL = 2.0
KEYPAIR_IDLE = 240.0                # > REJECT_AFTER_TIME (180 s) + slack
REKEY_FINALIZE_AFTER = 10.0         # finish an old keypair this long after its successor
INDEX_TTL = 600.0
FLUSH_DELAY = 2.5


def minute_of(ts):
    return int(ts // 60) * 60


def key_fp(pub):
    return hashlib.sha256(pub.encode("ascii")).hexdigest()[:16]


def prefix24(ip):
    return str(ipaddress.IPv4Network(ip + "/24", strict=False))


def ip_hmac(secret, ip, port):
    return hmac.new(secret, ("%s:%d" % (ip, port)).encode(), hashlib.sha256).hexdigest()[:20]


# ============================================================ loss accounting
class KeypairTrack:
    """Loss accounting for one (endpoint, receiver_index) stream."""
    __slots__ = ("first", "highest", "bits", "ok", "lost", "dup", "late",
                 "reorder", "last_ts")

    def __init__(self, c, ts):
        self.first = c
        self.highest = c
        self.bits = bytearray(BITMAP)
        self.bits[c % BITMAP] = 1
        self.ok = self.lost = self.dup = self.late = self.reorder = 0
        self.last_ts = ts

    def add(self, c, ts):
        """Returns False if the stream must be discarded (implausible jump)."""
        self.last_ts = ts
        h = self.highest
        if c > h:
            if c - h > MAX_COUNTER_JUMP:
                return False
            if c - h >= BITMAP:
                self.finalize()
                self.bits = bytearray(BITMAP)
                self.lost += max(0, c - BITMAP - h)
            else:
                lo = max(h - BITMAP + 1, self.first)
                for x in range(lo, c - BITMAP + 1):
                    s = x % BITMAP
                    if self.bits[s]:
                        self.ok += 1
                    else:
                        self.lost += 1
                    self.bits[s] = 0
            self.bits[c % BITMAP] = 1
            self.highest = c
        elif h - c >= BITMAP or c < self.first:
            self.late += 1
        else:
            s = c % BITMAP
            if self.bits[s]:
                self.dup += 1
            else:
                self.bits[s] = 1
                self.reorder += 1
        return True

    def finalize(self):
        """Judge everything still inside the window (keypair ended)."""
        lo = max(self.highest - BITMAP + 1, self.first)
        for x in range(lo, self.highest + 1):
            if self.bits[x % BITMAP]:
                self.ok += 1
            else:
                self.lost += 1
        self.bits = bytearray(0)

    def take(self):
        out = (self.ok, self.lost, self.dup, self.late, self.reorder)
        self.ok = self.lost = self.dup = self.late = self.reorder = 0
        return out


def _new_s4():
    return {"ok": 0, "lost": 0, "dup": 0, "late": 0, "reorder": 0, "pkts": 0,
            "df": 0, "unfrag": 0, "lens": Counter(), "runs": 0}


class S4Reducer:
    """Ring-thread-local reduction of S4 frames into per-minute summaries.

    Keys are (src_ip, src_port, receiver); the main thread maps them to peers.
    """

    def __init__(self, wan_mtu=None):
        self.wan_mtu = wan_mtu
        self.tracks = {}
        self.buckets = {}            # minute → {key: s4 stats}
        self.taints = {}             # minute → set(tokens)
        self.successor = {}          # (ip, port) → (receiver, ts) newest keypair

    def _b(self, ts, key):
        m = self.buckets.setdefault(minute_of(ts), {})
        s = m.get(key)
        if s is None:
            s = m[key] = _new_s4()
        return s

    def taint(self, ts, token):
        self.taints.setdefault(minute_of(ts), set()).add(token)

    def _fold(self, key, tr, ts):
        ok, lost, dup, late, reorder = tr.take()
        if ok or lost or dup or late or reorder:
            s = self._b(ts, key)
            s["ok"] += ok
            s["lost"] += lost
            s["dup"] += dup
            s["late"] += late
            s["reorder"] += reorder

    def frame(self, ts, data):
        m = wgparse.parse_wg(data)
        if m is None or m["type"] != wgparse.WG_DATA:
            return
        ip = m["ip"]
        key = (ip["src"], m["sport"], m["receiver"])
        s = self._b(ts, key)
        s["pkts"] += 1
        if ip["df"]:
            s["df"] += 1
        if self.wan_mtu and ip["tot_len"] > self.wan_mtu:
            self.taint(ts, "S4:INVALID_GRO")
        if not ip["mf"]:
            s["unfrag"] += 1
            s["lens"][ip["tot_len"]] += 1
        tr = self.tracks.get(key)
        if tr is None:
            self.tracks[key] = KeypairTrack(m["counter"], ts)
            s["runs"] += 1
            ep = key[:2]
            prev = self.successor.get(ep)
            if prev is None or prev[0] != key[2]:
                self.successor[ep] = (key[2], ts)
            return
        if not tr.add(m["counter"], ts):
            self._fold(key, tr, ts)
            del self.tracks[key]
            self.taint(ts, "S4_COUNTER_JUMP")
            return
        self._fold(key, tr, ts)

    def gap(self, ts, reason):
        """Frames were lost: keep what was judged, discard every open window,
        and taint the minutes the loss may span (stats are read ≤1.5 s late)."""
        for key, tr in self.tracks.items():
            self._fold(key, tr, ts)
        self.tracks.clear()
        self.taint(ts, "S4:GAP:" + reason)
        self.taint(ts - 1.5, "S4:GAP:" + reason)

    def expire(self, now):
        for key in list(self.tracks):
            tr = self.tracks[key]
            succ = self.successor.get(key[:2])
            rekeyed = (succ is not None and succ[0] != key[2]
                       and now - succ[1] > REKEY_FINALIZE_AFTER)
            if rekeyed or now - tr.last_ts > KEYPAIR_IDLE:
                tr.finalize()
                self._fold(key, tr, now)
                del self.tracks[key]

    def harvest(self, upto_minute):
        """Pop every closed minute ≤ upto_minute → [(minute, {key: s}, taints)]."""
        out = []
        for m in sorted(k for k in set(self.buckets) | set(self.taints) if k <= upto_minute):
            out.append((m, self.buckets.pop(m, {}), self.taints.pop(m, set())))
        return out


# ============================================================ fragments
class _Frag:
    __slots__ = ("ts", "pub", "F", "O", "cov", "end")

    def __init__(self, ts, pub, F, O):
        self.ts = ts
        self.pub = pub
        self.F = F
        self.O = O
        self.cov = [(0, F - 20)]
        self.end = None

    def add(self, off, ln, mf):
        self.cov.append((off, off + ln))
        if not mf:
            self.end = off + ln

    def complete(self):
        if self.end is None:
            return False
        pos = 0
        for a, b in sorted(self.cov):
            if a > pos:
                return False
            pos = max(pos, b)
        return pos >= self.end


def _new_acc():
    return {
        "hs_init_in": 0, "hs_resp_out": 0, "hs_init_out": 0, "hs_resp_in": 0,
        "hs_cookie_out": 0, "rtt": [], "rtt_missed": 0,
        "frag_first": 0, "frag_incomplete": 0, "frag_F": [], "frag_O": 0,
        "s4_ok": 0, "s4_lost": 0, "s4_dup": 0, "s4_late": 0, "s4_reorder": 0,
        "s4_runs": 0, "s4_pkts": 0, "lens": Counter(), "df": 0, "unfrag": 0,
        "mss": Counter(), "syn": 0, "why": set(),
        "c1_rx": None, "c1_tx": None, "c1_interval": None,
        "ep_changed": 0, "ep_port_only": 0,
    }


# ============================================================ aggregator
class Aggregator:
    """Main-thread only."""

    def __init__(self, secret, pending_max=4096, frag_max=10000, asn=None):
        self.secret = secret
        self.asn = asn             # optional nqmo.asn.AsnDb
        self.routes = {}           # endpoint ip → (ok: bool, ts)
        self.pending_max = pending_max
        self.frag_max = frag_max
        self.meta = None
        self.pending = {}          # raw sender index → (ts, pub, kind)
        self.index_pub = {}        # server-side index → (pub, ts)  (S4 attribution)
        self.frags = {}            # (src, dst, id) → _Frag
        self.orphans = {}          # (src, dst, id) → [(ts, off, len, mf)]
        self.minutes = {}          # minute → {pub: acc}
        self.mwhy = {}             # minute → set(tokens)
        self.mglobal = {}          # minute → Counter (unmapped, cookie_out, ...)
        self.user_drops = 0
        self.flushed_upto = None   # newest minute already written

    # ---- buckets -------------------------------------------------------------
    def _bucket(self, ts):
        """Minute bucket for ts. An event whose minute was already flushed —
        a fragment found incomplete at its 30 s TTL, an RTT pair completing
        after FLUSH_DELAY, a drop read ~1 s late — lands in the first open
        minute instead of a bucket nobody will ever flush (review round 3)."""
        m = minute_of(ts)
        if self.flushed_upto is not None and m <= self.flushed_upto:
            m = self.flushed_upto + 60
        return m

    def _acc(self, pub, ts):
        m = self.minutes.setdefault(self._bucket(ts), {})
        a = m.get(pub)
        if a is None:
            a = m[pub] = _new_acc()
        return a

    def _g(self, ts):
        return self.mglobal.setdefault(self._bucket(ts), Counter())

    def taint(self, ts, token):
        self.mwhy.setdefault(self._bucket(ts), set()).add(token)

    # ---- meta (C1) ---------------------------------------------------------------
    def set_meta(self, meta):
        """Accept a newer meta; C1 deltas and endpoint changes are taken
        between *consecutive metas* and land in the minute the newer one was
        generated — each meta contributes exactly once."""
        prev = self.meta
        if prev is not None and meta.generated_at <= prev.generated_at:
            return False
        self.meta = meta
        if prev is None:
            return True
        ts = meta.generated_at
        interval = meta.generated_at - prev.generated_at
        for pub, p in meta.peers.items():
            pp = prev.peers.get(pub)
            if pp is None:
                continue
            a = self._acc(pub, ts)
            drx = p["rx_bytes"] - pp["rx_bytes"]
            dtx = p["tx_bytes"] - pp["tx_bytes"]
            if drx >= 0 and dtx >= 0:            # negative ⇒ counter reset: no data
                a["c1_rx"] = (a["c1_rx"] or 0) + drx
                a["c1_tx"] = (a["c1_tx"] or 0) + dtx
                a["c1_interval"] = (a["c1_interval"] or 0) + interval
            ep, oep = p["endpoint"], pp["endpoint"]
            if ep and oep and ep != oep:
                if ep[0] == oep[0]:
                    a["ep_port_only"] += 1
                else:
                    a["ep_changed"] += 1
        return True

    def set_routes(self, ts, status):
        """status: {endpoint_ip: True if the reply route leaves via the WAN}."""
        for ip, ok in status.items():
            self.routes[ip] = (bool(ok), ts)

    def _ctx(self, store, ip, port, t_config, rate):
        """endpoint_ctx row + baseline context key (network | MTU | rate | iface MTU)."""
        asn = name = country = None
        sha = ""
        if self.asn is not None:
            hit = self.asn.lookup(ip)
            sha = self.asn.sha
            if hit:
                asn, name, country = hit
        p24 = prefix24(ip)
        cid = store.endpoint_ctx(ip_hmac(self.secret, ip, port), p24, asn=asn,
                                 asn_name=name, country=country, asn_db_sha=sha)
        net = ("AS%d" % asn) if asn else p24
        mtu = self.meta.wg1udp_mtu if self.meta is not None else None
        return cid, "%s|%s|%s|%s" % (net, t_config, rate or 0, mtu)

    def _pub_ep(self, ip, port):
        if self.meta is None:
            return None
        return self.meta.by_endpoint.get((ip, port))

    # ---- S1: handshakes + first data of a keypair ----------------------------
    def on_s1(self, ts, outgoing, m):
        ip = m["ip"]
        t = m["type"]
        if t == wgparse.WG_COOKIE and outgoing:
            self._g(ts)["hs_cookie_out"] += 1        # global even if unmapped
        if outgoing:
            pub = self._pub_ep(ip["dst"], m["dport"])
        else:
            pub = self._pub_ep(ip["src"], m["sport"])
        if pub is None and t == wgparse.WG_DATA and not outgoing:
            ent = self.index_pub.get(m["receiver"])
            pub = ent[0] if ent else None
        if pub is None:
            self._g(ts)["unmapped_s1"] += 1
            return
        a = self._acc(pub, ts)
        if t == wgparse.WG_INIT:
            if outgoing:
                a["hs_init_out"] += 1
                self._pend(m["sender"], ts, pub, "init")
                self.index_pub[m["sender"]] = (pub, ts)
            else:
                a["hs_init_in"] += 1
        elif t == wgparse.WG_RESP:
            if outgoing:
                a["hs_resp_out"] += 1
                self._pend(m["sender"], ts, pub, "resp")
                self.index_pub[m["sender"]] = (pub, ts)
            else:
                a["hs_resp_in"] += 1
                self._pair(m["receiver"], ts, pub, "init")
        elif t == wgparse.WG_COOKIE:
            if outgoing:
                a["hs_cookie_out"] += 1
        elif t == wgparse.WG_DATA and not outgoing and m.get("counter") == 0:
            self._pair(m["receiver"], ts, pub, "resp")

    def _pend(self, idx, ts, pub, kind):
        if len(self.pending) >= self.pending_max:
            oldest = min(self.pending, key=lambda k: self.pending[k][0])
            t0, p, _k = self.pending.pop(oldest)
            self._acc(p, t0)["rtt_missed"] += 1
            self.user_drops += 1
        self.pending[idx] = (ts, pub, kind)

    def _pair(self, idx, ts, pub, kind):
        p = self.pending.get(idx)
        if p is None or p[2] != kind or p[1] != pub:
            return
        del self.pending[idx]
        dt = ts - p[0]
        a = self._acc(pub, p[0])                 # the sample belongs to its start
        if 0.0 <= dt <= PENDING_HS_TTL:
            a["rtt"].append(dt * 1000.0)
        else:
            a["rtt_missed"] += 1

    # ---- S2/S3: fragments ----------------------------------------------------
    def on_s2(self, ts, f):
        pub = self._pub_ep(f["src"], f["sport"])
        if pub is None:
            self._g(ts)["unmapped_s2"] += 1
            return
        key = (f["src"], f["dst"], f["id"])
        a = self._acc(pub, ts)
        if key in self.frags:              # id reuse inside TTL: ambiguous, both dropped
            self.frags.pop(key)
            a["why"].add("FRAG_ID_REUSE")
            a["frag_first"] += 1
            return
        if len(self.frags) >= self.frag_max:
            self.user_drops += 1
            self.taint(ts, "FRAG_TABLE_FULL")
            return
        fr = _Frag(ts, pub, f["F"], f["O"])
        for _t, off, ln, mf in self.orphans.pop(key, []):
            fr.add(off, ln, mf)
        self.frags[key] = fr
        a["frag_first"] += 1
        a["frag_F"].append(f["F"])
        a["frag_O"] = max(a["frag_O"], f["O"])
        if fr.complete():
            del self.frags[key]

    def on_s3(self, ts, f):
        key = (f["src"], f["dst"], f["id"])
        fr = self.frags.get(key)
        if fr is None:
            if self.meta is not None and f["src"] not in self.meta.endpoint_ips:
                return                     # not from any peer: never stored
            if len(self.orphans) >= self.frag_max:
                self.taint(ts, "FRAG_TABLE_FULL")
                return
            self.orphans.setdefault(key, []).append((ts, f["off"], f["len"], f["mf"]))
            return
        fr.add(f["off"], f["len"], f["mf"])
        if fr.complete():
            del self.frags[key]

    # ---- S4: summaries from the ring thread ------------------------------------
    def on_s4_summary(self, minute, summaries, taints):
        for tok in taints:
            self.taint(minute, tok)
        for (ip, port, recv), s in summaries.items():
            ent = self.index_pub.get(recv)
            pub = ent[0] if ent else self._pub_ep(ip, port)
            if pub is None:
                self._g(minute)["unmapped_s4"] += s["pkts"]
                continue
            if ent:
                self.index_pub[recv] = (pub, max(ent[1], minute))
            a = self._acc(pub, minute)
            for k in ("ok", "lost", "dup", "late", "reorder", "runs", "pkts"):
                a["s4_" + k] += s[k]
            a["df"] += s["df"]
            a["unfrag"] += s["unfrag"]
            a["lens"].update(s["lens"])

    # ---- S5: SYN MSS -----------------------------------------------------------
    def on_s5(self, ts, src, mss):
        if self.meta is None:
            return
        pub = self.meta.by_tunnel_ip.get(src)
        if pub is None:
            self._g(ts)["unmapped_s5"] += 1
            return
        a = self._acc(pub, ts)
        a["syn"] += 1
        if mss is not None:
            a["mss"][mss] += 1

    # ---- housekeeping (called every drain) -------------------------------------
    def expire(self, now):
        for idx in [k for k, v in self.pending.items() if now - v[0] > PENDING_HS_TTL]:
            t0, pub, _k = self.pending.pop(idx)
            self._acc(pub, t0)["rtt_missed"] += 1
        for key in [k for k, v in self.frags.items() if now - v.ts > FRAG_TTL]:
            fr = self.frags.pop(key)
            self._acc(fr.pub, fr.ts)["frag_incomplete"] += 1
        for key in [k for k, v in self.orphans.items() if now - v[0][0] > ORPHAN_TAIL_TTL]:
            del self.orphans[key]
        for idx in [k for k, v in self.index_pub.items() if now - v[1] > INDEX_TTL]:
            del self.index_pub[idx]

    # ---- minute rows -----------------------------------------------------------
    def flush(self, minute_ts, store, now, meta_stale_s=180, extra_why=()):
        """Write the rows of one closed minute. Returns (rows, global Counter)."""
        minute_ts = minute_of(minute_ts)
        if self.flushed_upto is None or minute_ts > self.flushed_upto:
            self.flushed_upto = minute_ts
        accs = self.minutes.pop(minute_ts, {})
        why_all = self.mwhy.pop(minute_ts, set()) | set(extra_why)
        glob = self.mglobal.pop(minute_ts, Counter())
        meta = self.meta
        if meta is None:
            return 0, glob
        stale = meta.age(minute_ts + 60) > meta_stale_s
        rows = 0
        for pub, p in meta.peers.items():
            a = accs.get(pub)
            recent_hs = p["latest_handshake"] and (minute_ts + 60 - p["latest_handshake"]) < 180
            if a is None and not recent_hs:
                continue                    # idle peer: no row this minute
            a = a or _new_acc()
            why = set(a["why"]) | why_all
            if stale:
                why.add("C1:STALE")
            pid = store.peer_id(p["iface"], p["name"], key_fp(pub))
            row = {"peer_id": pid, "ts": minute_ts,
                   "rx_bytes": a["c1_rx"], "tx_bytes": a["c1_tx"],
                   "c1_interval_s": (round(a["c1_interval"], 1)
                                     if a["c1_interval"] is not None else None),
                   "ep_changed": a["ep_changed"], "ep_port_only_changed": a["ep_port_only"]}
            if p["latest_handshake"] > 0:
                row["hs_age_max"] = int(max(0, minute_ts + 60 - p["latest_handshake"]))
            t_cfg = meta.effective_mtu(pub)
            row["t_config"] = t_cfg
            if p["endpoint"]:
                ip, port = p["endpoint"]
                row["ep_ctx"], row["ctx_key"] = self._ctx(store, ip, port, t_cfg,
                                                          p["rate_mbit"])
                r = self.routes.get(ip)
                if r is not None and minute_ts - 120 <= r[1] <= minute_ts + 120:
                    row["route_ok"] = int(r[0])
            for k in ("hs_init_in", "hs_resp_out", "hs_init_out", "hs_resp_in",
                      "hs_cookie_out", "rtt_missed", "frag_first", "frag_incomplete",
                      "s4_runs", "s4_pkts"):
                row[k] = a[k]
            if a["rtt"]:
                r = sorted(a["rtt"])
                row["rtt_ms_min"] = round(r[0], 3)
                row["rtt_ms_med"] = round(r[len(r) // 2], 3)
                row["rtt_samples"] = ",".join("%.1f" % x for x in r[:30])
            row["rtt_n"] = len(a["rtt"])
            if a["frag_F"]:
                row["frag_first_len_min"] = min(a["frag_F"])
                row["frag_first_len_max"] = max(a["frag_F"])
                row["frag_orig_len"] = a["frag_O"]
            row["s4_expected"] = a["s4_ok"] + a["s4_lost"]
            row["s4_received"] = a["s4_ok"]
            row["s4_dup"] = a["s4_dup"]
            row["s4_late"] = a["s4_late"]
            row["s4_reorder"] = a["s4_reorder"]
            if a["unfrag"]:
                lmax = max(a["lens"])
                row["l_max_unfrag"] = lmax
                top = sum(n for ln, n in a["lens"].items() if ln >= lmax - 15)
                row["l_ceiling_share"] = round(top / a["unfrag"], 4)
            if a["s4_pkts"]:
                row["df_ratio"] = round(a["df"] / a["s4_pkts"], 4)
            if a["mss"]:
                mode = a["mss"].most_common(1)[0][0]
                row["mss_mode"] = mode
                row["mss_exceeds"] = int(t_cfg is not None and mode + 40 > t_cfg)
            row["syn_n"] = a["syn"]
            row["rate_limit_mbit"] = p["rate_mbit"]
            row["quality"] = "INVALID" if stale else ("DEGRADED" if why else "GOOD")
            row["quality_why"] = ";".join(sorted(why))
            store.put_peer_minute(row)
            rows += 1
        return rows, glob

    def open_minutes(self):
        return sorted(set(self.minutes) | set(self.mwhy) | set(self.mglobal))
