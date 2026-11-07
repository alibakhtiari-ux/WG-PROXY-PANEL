"""Diagnosis cycle: windows → rules → confidence → hysteresis → diagnosis rows
→ notify_outbox. Main-thread only (it owns the store).

Ordering is exclusion-first (04 §2): server and egress before per-peer, so a
slow egress or the panel's own shaping is never reported as an MTU problem.

Mode handling (01 §4):
  OBSERVATION_ONLY         diagnoses are computed and stored with mode=SHADOW;
                           nothing is notified
  DIAGNOSTICS_ENABLED      stored as LIVE; HIGH/MEDIUM opens are notified
  RECOMMENDATIONS_ENABLED  as above + recommendations (recommend.py)
CONFIG_ADVISORY findings are CALCULATED, shown in the UI, never notified.
"""
import json
import time

from . import confidence as conf
from . import features as feat
from . import rules, stats

WINDOW = 300
RTT_WINDOW = 900
BASELINE_DAYS = 14
BASELINE_MIN_MINUTES = 120
ACTIVE_BYTES_MIN = 200000           # WireGuard message bytes per minute
BASELINE_TTL = 3600
BASELINE_GUARD = 3600              # excluded hour before the judged window
NOTIFY_COOLDOWN = 6 * 3600
NOTIFY_RATE_PER_HOUR = 6
NOTIFY_LEVELS = ("HIGH", "MEDIUM")


def _rows(conn, sql, args):
    cur = conn.execute(sql, args)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def span(cls):
    """The window a class is judged on. The stored window_start must be the
    start of THAT window: congestion is judged every 15 min but was stored
    with the last 5-minute slot, so its 15-minute median sat on a 5-minute
    span (lab, 29 Oct)."""
    return RTT_WINDOW if cls == "NETWORK_CONGESTION" else WINDOW


class Diagnoser:
    def __init__(self, store, clock=time.time):
        self.store = store
        self.clock = clock
        self._base = {}             # (peer_id, ctx_key) → (computed_at, baseline)

    # ---- data access ---------------------------------------------------------
    def peer_rows(self, ws, we):
        out = {}
        for r in _rows(self.store.conn,
                       "SELECT * FROM peer_minute WHERE ts >= ? AND ts < ?", (ws, we)):
            out.setdefault(r["peer_id"], []).append(r)
        return out

    def global_rows(self, ws, we):
        rows = _rows(self.store.conn,
                     "SELECT * FROM global_minute WHERE ts >= ? AND ts < ?", (ws, we))
        for r in rows:
            try:
                r["egress"] = json.loads(r["egress_json"]) if r.get("egress_json") else None
            except ValueError:
                r["egress"] = None
        return rows

    def peer_names(self):
        return {r[0]: (r[1], r[2]) for r in
                self.store.conn.execute("SELECT peer_id, iface, name FROM peer")}

    def baseline(self, peer_id, ctx_key, before):
        """Robust baseline over active GOOD minutes of the same context.
        Returns None when fewer than BASELINE_MIN_MINUTES exist (NO_BASELINE):
        a baseline is never borrowed from other peers or invented."""
        if ctx_key is None:
            return None
        now = self.clock()
        key = (peer_id, ctx_key)
        hit = self._base.get(key)
        # staggered expiry: the 24 recomputations spread over the hour instead
        # of all landing on one main-loop tick (review round 4, F10)
        ttl = BASELINE_TTL + (peer_id % 12) * WINDOW
        # "not yet" (None) is re-asked every window: cached for the full TTL it
        # kept a peer NO_BASELINE up to ~2 h after its data sufficed (lab, 28 Oct)
        if hit and now - hit[0] < (ttl if hit[1] is not None else WINDOW):
            return hit[1]
        for k in [k for k, v in self._base.items() if now - v[0] > 2 * BASELINE_TTL + 12 * WINDOW]:
            del self._base[k]
        # the hour before the judged window is excluded, so an ongoing episode
        # cannot raise its own baseline (contamination)
        rows = _rows(self.store.conn,
                     "SELECT rx_bytes, tx_bytes, s4_pkts, s4_expected, s4_received, "
                     "rtt_samples, c1_interval_s, quality, quality_why FROM peer_minute "
                     "WHERE peer_id=? AND ctx_key=? AND ts>=? AND ts<?",
                     (peer_id, ctx_key, before - BASELINE_DAYS * 86400, before - BASELINE_GUARD))
        active = [r for r in rows
                  if (r.get("rx_bytes") or 0) + (r.get("tx_bytes") or 0) >= ACTIVE_BYTES_MIN
                  or (r.get("s4_pkts") or 0) >= 1000]
        base = None
        if len(active) >= BASELINE_MIN_MINUTES:
            rtts, exp, lost, ups = [], 0, 0, []
            for r in active:
                if feat.stream_ok(r, "S1") and r.get("rtt_samples"):
                    rtts += [float(x) for x in r["rtt_samples"].split(",") if x]
                if feat.stream_ok(r, "S4") and (r.get("s4_expected") or 0) > 0:
                    exp += r["s4_expected"]
                    lost += r["s4_expected"] - (r.get("s4_received") or 0)
                if r.get("rx_bytes") and r.get("c1_interval_s"):
                    ups.append(r["rx_bytes"] * 8 / r["c1_interval_s"] / 1e6)
            med = stats.median(rtts) if len(rtts) >= 20 else None
            base = {"minutes": len(active), "rtt_med": med,
                    "rtt_mad": stats.mad(rtts, med) if med is not None else None,
                    "rtt_n": len(rtts),
                    "loss_rate": (lost / exp) if exp >= 10000 else None,
                    # 95th percentile, not the single busiest minute: a steady
                    # uploader must not have every loss capped as "saturation"
                    "max_up_mbit": sorted(ups)[int(0.95 * (len(ups) - 1))] if ups else None}
        self._base[key] = (self.clock(), base)
        return base

    # ---- the cycle -------------------------------------------------------------
    def evaluate(self, ws, meta_fresh):
        """Pure-ish: compute every Outcome for the window starting at ws."""
        we = ws + WINDOW
        g = feat.global_features(self.global_rows(ws, we))
        out = {"global": [], "peers": {}}
        res = rules.server_resource(g)
        flood = rules.handshake_flood(g)
        eg = rules.egress(g, meta_fresh)
        out["global"] = [res, flood] + eg
        server_bad = res.positive is True or flood.positive is True
        egress_bad = any(o.positive is True for o in eg)
        egress_unknown = (not meta_fresh) or not eg
        rtt_window = (we % RTT_WINDOW) == 0
        rtt_rows = self.peer_rows(we - RTT_WINDOW, we) if rtt_window else {}
        hour_rows = self.peer_rows(we - 3600, we)
        for pid, rows in self.peer_rows(ws, we).items():
            f = feat.peer_features(rows)
            base = self.baseline(pid, f["ctx_key"], ws)
            o = []
            shaping = rules.traffic_shaping(f)
            o.append(shaping)
            o.append(rules.handshake_failure(f))
            o.append(rules.nat_or_firewall(f))
            o.append(rules.routing_anomaly(f))
            hour_ip = sum((r.get("ep_changed") or 0) for r in hour_rows.get(pid, []))
            o.append(rules.udp_instability(f, hour_ip))
            mtu = rules.mtu_problem(f["frag_first"], f["F_min"], f["F_max"], f["l_max"],
                                    f["t_config"], f["quality"]["S2"], f["quality"]["S4"])
            per_dgram = (-(-(f["O_max"] - 20) // (f["F_min"] - 20))
                         if f["O_max"] and f["F_min"] and f["F_min"] > 20 else 2)
            bh_a = rules.blackhole_frag(f["frag_first"], f["frag_incomplete"],
                                        f["s4_loss_point"], f["quality"]["S2"], per_dgram)
            bh_b = rules.blackhole_df(f["df_ratio"], f["frag_first"], f["l_max"],
                                      f["ceiling_share"], f["t_device"], f["loss_lb"] or 0,
                                      f["loss_n"], f["quality"]["S4"])
            bh = bh_a if bh_a.positive else (bh_b if bh_b.positive is not None else bh_a)
            loss = rules.packet_loss(f, base, server_bad, bh_b.positive is True,
                                     bh_a.positive is True)
            o += [loss, mtu, bh]
            if rtt_window:
                rf = feat.peer_features(rtt_rows.get(pid, []))
                o.append(rules.congestion(rf["rtt_samples"], rf["quality"]["S1"], base))
            explained = any(x.positive for x in o)
            o.append(rules.unknown_degradation(f, base, explained))
            # R-MTU-2 and C5: server/egress/shaping causes cap the MTU classes
            for x in o:
                if x.cls in ("SUSPECTED_MTU_PROBLEM", "SUSPECTED_PMTU_BLACKHOLE",
                             "UNKNOWN_DEGRADATION") and x.positive:
                    if server_bad or egress_bad or shaping.positive:
                        x.cap = conf.cap_level(x.cap or "HIGH", "LOW")
                        x.counter.append("server, egress or shaping cause active (R-MTU-2)")
                    elif egress_unknown:
                        x.cap = conf.cap_level(x.cap or "HIGH", "LOW")
            for x in o:
                x.subject = str(pid)
            out["peers"][pid] = {"features": f, "outcomes": o, "baseline": base}
        return out

    def apply(self, ws, result, mode, now=None):
        """Persist states/diagnoses/outbox for the evaluated window."""
        now = self.clock() if now is None else now
        live = mode != "OBSERVATION_ONLY"
        store_mode = "LIVE" if live else "SHADOW"
        names = self.peer_names()
        allo = list(result["global"])
        for pid, pr in result["peers"].items():
            allo += pr["outcomes"]
        seen = set()
        for o in allo:
            seen.add((o.scope, o.subject, o.cls))
            self._apply_one(o, ws, store_mode, live, names, now)
        # An OPEN diagnosis whose subject produced no outcome this window (peer
        # went idle, tunnel left the meta) still ages: it gets an n/a entry so
        # STALE_AFTER can close it instead of it staying open forever.
        for scope, subject, cls in self.store.conn.execute(
                "SELECT scope, subject, class FROM rule_state WHERE open_id IS NOT NULL "
                "AND last_window < ?", (ws,)).fetchall():
            if (scope, subject, cls) in seen:
                continue
            if cls == "NETWORK_CONGESTION" and (ws + WINDOW) % RTT_WINDOW:
                continue                              # evaluated on 15-min windows only
            self._apply_one(rules.Outcome(cls, None, quality="INVALID", scope=scope,
                                          subject=subject), ws, store_mode, live, names, now)

    def _apply_one(self, o, ws, store_mode, live, names, now):
        c = self.store.conn
        row = c.execute("SELECT history, open_id, last_window, notified_level, notified_ts "
                        "FROM rule_state WHERE scope=? AND subject=? AND class=?",
                        (o.scope, o.subject, o.cls)).fetchone()
        if row:
            hist, open_id, last_w, n_level, n_ts = (json.loads(row[0]), row[1], row[2],
                                                    row[3], row[4])
            if last_w >= ws:
                return                               # window already applied
        else:
            hist, open_id, n_level, n_ts = [], None, None, None
        if o.positive is None and not row:
            return                                   # nothing ever seen: keep no state
        step = span(o.cls)
        if row:
            # windows with no outcome at all are n/a, so "consecutive" means
            # adjacent in time, not adjacent in the list (review round 3)
            missing = min(max(0, (ws - last_w) // step - 1), conf.STALE_AFTER)
            hist += [{"w": ws - step * (missing - i), "p": None, "s": None, "q": "INVALID",
                      "c": False, "cap": None} for i in range(missing)]
        hist = (hist + [conf.summarize(o, ws)])[-conf.HISTORY_MAX:]
        lv = conf.level(hist, rules.PARAMS["frag_min_total_high"]
                        if o.cls == "SUSPECTED_MTU_PROBLEM" else None)
        tr = conf.transition(hist, open_id is not None)
        ev_json = json.dumps(o.evidence, ensure_ascii=False)
        ce_json = json.dumps(o.counter, ensure_ascii=False)
        alt_json = json.dumps(rules.ALT.get(o.cls, []), ensure_ascii=False)
        if tr == "OPEN":
            cur = c.execute(
                "INSERT INTO diagnosis(ts,scope,subject,class,confidence,window_start,"
                "window_end,evidence_json,counter_evidence_json,alternatives_json,"
                "data_quality,baseline_ref,mode,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'OPEN')",
                (now, o.scope, o.subject, o.cls, lv, ws + WINDOW - step, ws + WINDOW,
                 ev_json, ce_json, alt_json, o.quality, None, store_mode))
            open_id = cur.lastrowid
            if live:
                n_level, n_ts = self._notify_open(o, lv, names, now, n_level, n_ts)
        elif open_id is not None and tr in ("CLEAR", "STALE"):
            c.execute("UPDATE diagnosis SET state='CLEARED', cleared_ts=? WHERE id=?",
                      (now, open_id))
            if n_level:                 # announced ⇒ always closed, whatever the mode now
                self._outbox(now, "INFO", self._key(o), "nqmo.alert.cleared",
                             self._params(o, n_level, names, stale=(tr == "STALE")))
            open_id, n_level = None, None
        elif open_id is not None:
            if o.positive:
                c.execute("UPDATE diagnosis SET confidence=?, window_end=?, evidence_json=?,"
                          " counter_evidence_json=?, data_quality=? WHERE id=?",
                          (lv, ws + WINDOW, ev_json, ce_json, o.quality, open_id))
            if live:
                # a diagnosis opened in SHADOW (or at LOW) becomes live on its first
                # notifiable level; MEDIUM → HIGH sends exactly one escalation
                c.execute("UPDATE diagnosis SET mode='LIVE' WHERE id=? AND mode='SHADOW'",
                          (open_id,))
                if n_level is None and lv in NOTIFY_LEVELS:
                    n_level, n_ts = self._notify_open(o, lv, names, now, None, None)
                elif lv == "HIGH" and n_level == "MEDIUM":
                    # a suppressed escalation must keep the episode "announced"
                    # (otherwise it never gets its cleared message and is
                    # re-announced as new after the cooldown — review round 4)
                    n_level, n_ts = self._notify_open(o, lv, names, now, n_level, n_ts,
                                                      text_key="nqmo.alert.escalated")
        c.execute("INSERT OR REPLACE INTO rule_state(scope,subject,class,history,open_id,"
                  "last_window,notified_level,notified_ts) VALUES(?,?,?,?,?,?,?,?)",
                  (o.scope, o.subject, o.cls, json.dumps(hist), open_id, ws, n_level, n_ts))

    # ---- notifications ---------------------------------------------------------
    @staticmethod
    def _key(o):
        return "nqmo:%s:%s:%s" % (o.scope, o.subject, o.cls)

    @staticmethod
    def _params(o, lv, names, stale=False):
        p = {"class": o.cls, "confidence": lv, "scope": o.scope, "stale": stale,
             "automatic_change": "DISABLED"}
        if o.scope == "PEER":
            n = names.get(int(o.subject))
            p["peer"] = n[1] if n else o.subject
            p["iface"] = n[0] if n else None
        else:
            p["subject"] = o.subject
        p["evidence"] = [{"metric": e["metric"], "value": e["value"]} for e in o.evidence[:3]]
        return p

    def _notify_open(self, o, lv, names, now, n_level, n_ts, text_key="nqmo.alert.open"):
        if lv not in NOTIFY_LEVELS:
            return n_level, n_ts
        c = self.store.conn
        last = c.execute("SELECT MAX(ts) FROM notify_outbox WHERE key=? AND text_key=?",
                         (self._key(o), text_key)).fetchone()[0]
        if last is not None and now - last < NOTIFY_COOLDOWN:
            # suppressed: not announced (so no "cleared" later either), but it
            # goes to the digest instead of vanishing (05 §5.4)
            dig = c.execute("SELECT 1 FROM notify_outbox WHERE key=? AND severity='DIGEST' "
                            "AND ts > ?", (self._key(o), now - NOTIFY_COOLDOWN)).fetchone()
            if not dig:
                self._outbox(now, "DIGEST", self._key(o), text_key, self._params(o, lv, names))
            return n_level, n_ts
        hour = c.execute("SELECT COUNT(*) FROM notify_outbox WHERE ts > ? AND "
                         "severity IN ('HIGH', 'MEDIUM')", (now - 3600,)).fetchone()[0]
        if hour >= NOTIFY_RATE_PER_HOUR:
            self._outbox_more(now)
            return n_level, n_ts                    # retried next window, delivered later
        self._outbox(now, "HIGH" if lv == "HIGH" else "MEDIUM", self._key(o), text_key,
                     self._params(o, lv, names))
        return lv, now

    def _outbox(self, now, severity, key, text_key, params):
        self.store.conn.execute(
            "INSERT INTO notify_outbox(ts,severity,key,text_key,params_json) VALUES(?,?,?,?,?)",
            (now, severity, key, text_key, json.dumps(params, ensure_ascii=False)))

    def _outbox_more(self, now):
        """Over the hourly cap: at most one aggregate 'more' message per hour."""
        c = self.store.conn
        got = c.execute("SELECT COUNT(*) FROM notify_outbox WHERE ts > ? AND key='nqmo:more'",
                        (now - 3600,)).fetchone()[0]
        if not got:
            self._outbox(now, "INFO", "nqmo:more", "nqmo.alert.more", {})

    # ---- advisories (CALCULATED, never notified) --------------------------------
    def advisories(self, meta, iface_mtu, result):
        """Server-tunnel MTU audit + per-peer config findings → list of dicts."""
        out = []
        if meta is not None:
            for name, e in sorted(meta.egress.items()):
                if e.get("mtu") is None or not e.get("endpoint_dev"):
                    continue
                devs = [d for d in str(e["endpoint_dev"]).split(",") if d]
                dmtus = []
                for d in devs:
                    m = (meta.egress.get(d) or {}).get("mtu") or iface_mtu(d)
                    if m:
                        dmtus.append(m)
                if not dmtus:
                    continue
                if e.get("kind") == "awg":
                    if e.get("awg_s4") is None:
                        out.append({"scope": "SERVER_TUNNEL", "subject": name,
                                    "finding": "UNDETERMINED", "why": "awg S4 unknown"})
                        continue
                    ovh = 60 + e["awg_s4"]
                else:
                    ovh = 60
                need = e["mtu"] + ovh
                if need > min(dmtus):
                    out.append({"scope": "SERVER_TUNNEL", "subject": name,
                                "finding": "NESTED_MTU_MISMATCH", "tunnel_mtu": e["mtu"],
                                "carrier": devs, "carrier_mtu": min(dmtus), "outer": need,
                                "suggested_mtu": min(dmtus) - ovh, "status": "ESTIMATED",
                                "note": "packets are delivered fragmented (DF=0); impact "
                                        "on fixed MSS 1200 and upstream chain not measured"})
        for pid, pr in result["peers"].items():
            f = pr["features"]
            if f["O_max"] and f["t_config"] and f["O_max"] - 60 != f["t_config"]:
                out.append({"scope": "PEER", "subject": str(pid), "finding": "CONFIG_MISMATCH",
                            "observed_client_mtu": f["O_max"] - 60, "config_mtu": f["t_config"]})
            if f["mss_exceeds"]:
                out.append({"scope": "PEER", "subject": str(pid),
                            "finding": "MSS_EXCEEDS_TUNNEL_MTU", "mss": f["mss_mode"],
                            "config_mtu": f["t_config"],
                            "suggested_server_mss": (f["t_config"] - 40) if f["t_config"] else None,
                            "status": "CANDIDATE_FOR_TESTING"})
        return out

    def shadow_stats(self, now):
        """Promotion criterion support (01 §4): data days + SHADOW HIGH per peer."""
        c = self.store.conn
        first = c.execute("SELECT MIN(ts) FROM peer_minute").fetchone()[0]
        rows = c.execute("SELECT subject, COUNT(*) FROM diagnosis WHERE mode='SHADOW' AND "
                         "confidence='HIGH' AND ts > ? GROUP BY subject",
                         (now - 7 * 86400,)).fetchall()
        return {"data_days": round((now - first) / 86400, 2) if first else 0,
                "shadow_high_by_peer_7d": {s: n for s, n in rows}}
