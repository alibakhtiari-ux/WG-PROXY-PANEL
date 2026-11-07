"""Analysis orchestration (PHASE 3): runs once per closed 5-minute window on
the main thread, inside one store transaction.

  diagnose → advisories → correlation → recommendations (+ follow-up loop)

and owns the manual probe's gates and results. Everything it publishes goes
through snapshot(), which export.py places in state.json.
"""
import json
import queue
import time

from . import confidence as conf
from . import diagnose as dg
from . import features as feat
from . import recommend as rec
from . import rules, stats
from .aggregate import key_fp
from .correlate import correlate
from .probe import HS_START_MAX, ProbeRun

PROBE_PER_PEER_S = 3600
PROBE_MAX_AGE_S = 24 * 3600
OUTBOX_EXPORT = 100

# Per-peer quality summary (design 05 §5.5) — the numbers the rules themselves
# judge, each with its sample size, and nothing where the rule would abstain:
#   rtt   median of S1 handshake-pair round trips (eth0, server↔client, incl.
#         client processing) over the trailing 15-minute RTT window, only from
#         S1-clean minutes and only with ≥ rtt_min_samples samples.
#   loss  UPSTREAM only (client→server, S4 counter gaps + incomplete-fragment
#         share, as features.peer_features computes it) for the closed 5-minute
#         window, only when S4 is not INVALID and ≥ loss_n_min counters were judged.
#   mtu   status of the first CLIENT_IFACE_MTU recommendation (recommend.py).
#   quality  worst confidence of this peer's OPEN LIVE diagnoses; OK only when a
#         measurement stream was usable; None in OBSERVATION_ONLY (shadow
#         diagnoses are not shown, so "OK" there would be an unfounded claim).
PEER_QUALITY = ("INSUFFICIENT", "OK", "LOW", "MEDIUM", "HIGH")
MTU_STATUSES = ("UNDETERMINED", "CANDIDATE_FOR_TESTING", "ESTIMATED", "VERIFIED")
_JUDGED_STREAMS = ("S1", "S2", "S4")
# Per-peer history (§29.153): the trailing HISTORY_HOURS hourly buckets ending
# at the closed window, each judged exactly like the summary (S1-clean minutes
# for RTT with ≥ rtt_min_samples samples, S4-clean minutes for loss with
# ≥ loss_n_min judged counters), None where the rule would abstain. The
# peer_hour table is not used: nothing writes it yet, and a bucket computed
# from the same minutes the rules read cannot disagree with the rules.
HISTORY_HOURS = 24
WHY_MAX = 8                       # distinct quality_why tokens exported per peer


def peer_summary(ws, f, rf, recs, live_levels, mode, why=()):
    """f: features of the closed window; rf: features of the trailing RTT
    window (or None); recs: recommend() output; live_levels: confidences of
    this peer's OPEN LIVE diagnoses; why: quality_why tokens of the window's
    minutes. Pure: no store access."""
    p = rules.PARAMS
    out = {"window": ws, "rtt_ms_med": None, "rtt_ms_min": None, "rtt_n": 0,
           "loss_n": 0, "loss_k": None, "loss_point": None, "loss_lb": None,
           "loss_ub": None, "mtu_status": None, "quality": None,
           # why a stream was DEGRADED/INVALID: the window quality of each
           # judged stream and the distinct tokens behind it (features._BAD)
           "streams": {s: f["quality"][s] for s in _JUDGED_STREAMS},
           "why": sorted(set(why))[:WHY_MAX]}
    smp = rf["rtt_samples"] if rf and rf["quality"]["S1"] != "INVALID" else []
    out["rtt_n"] = len(smp)
    if len(smp) >= p["rtt_min_samples"]:
        out["rtt_ms_med"] = round(stats.median(smp), 1)
        out["rtt_ms_min"] = round(min(smp), 1)
    if f["quality"]["S4"] != "INVALID" and f["loss_n"]:
        out["loss_n"] = f["loss_n"]
        if f["loss_n"] >= p["loss_n_min"]:
            out["loss_k"] = f["loss_k"]
            out["loss_point"] = round(f["loss_k"] / f["loss_n"], 6)
            out["loss_lb"], out["loss_ub"] = (round(f["loss_lb"], 6), round(f["loss_ub"], 6))
    first = next((r for r in recs if r.get("target") == "CLIENT_IFACE_MTU"), None)
    if first and first.get("status") in MTU_STATUSES:
        out["mtu_status"] = first["status"]
    if mode != "OBSERVATION_ONLY":
        lv = [x for x in live_levels if x in conf.LEVELS[1:]]
        if lv:
            out["quality"] = max(lv, key=conf.LEVELS.index)
        elif live_levels:                 # open but unranked: never reported as OK
            out["quality"] = "INSUFFICIENT"
        elif any(f["quality"][s] != "INVALID" for s in _JUDGED_STREAMS):
            out["quality"] = "OK"
        else:
            out["quality"] = "INSUFFICIENT"
    return out


class Analysis:
    def __init__(self, store, cfg, clock=time.time, iface_mtu=None, probe_cls=ProbeRun,
                 reasm_drops=None, progress=None):
        # progress(): called between the stages of run_window (§29.161). The
        # engine passes its watchdog heartbeat: on myserver the window analysis
        # takes 1.4 s of CPU but 13 s of wall time on the main thread (Nice=10
        # under two busy amneziawg-go processes, CPUQuota), and on a bad minute
        # more than WatchdogSec — a loop that is progressing must say so.
        self.progress = progress or (lambda: None)
        self.store = store
        self.cfg = cfg
        self.clock = clock
        self.iface_mtu = iface_mtu or (lambda dev: None)
        self.diag = dg.Diagnoser(store, clock)
        self.probe_cls = probe_cls
        self.reasm_drops = reasm_drops      # → ReasmFails−ReasmTimeout, for the probe
        self.probe_results = queue.Queue()
        self.probe_running = None
        self.prev_corr = set()
        self.last = {"window": None, "advisories": [], "correlations": [],
                     "groups_eligible": 0, "recommendations": {}, "peers": {}}

    # ---- per window -----------------------------------------------------------
    def run_window(self, ws, meta, mode):
        now = self.clock()
        fresh = meta is not None and meta.age(now) <= self.cfg["limits"]["meta_stale_s"]
        result = self.diag.evaluate(ws, fresh)
        self.progress()
        with self.store.transaction():
            self.diag.apply(ws, result, mode, now)
            server_bad = any(o.positive for o in result["global"]
                             if o.cls == "SERVER_RESOURCE_BOTTLENECK")
            egress_bad = sorted(o.subject for o in result["global"]
                                if o.cls == "EGRESS_TUNNEL_DEGRADATION" and o.positive)
            events, eligible = correlate(result, server_bad, egress_bad)
            keys = {(e["group_type"], e["group_key"]) for e in events}
            for e in events:
                if (e["group_type"], e["group_key"]) in self.prev_corr:
                    continue                      # one row per episode, not per window
                self.store.conn.execute(
                    "INSERT INTO correlation_event(ts,group_type,group_key,active_peers,"
                    "affected_peers,confidence,suspected_cause,mtu_related_evidence,"
                    "requires_investigation,evidence_json,state) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (now, e["group_type"], e["group_key"], e["active_peers"],
                     e["affected_peers"], e["confidence"], e["suspected_cause"],
                     int(e["mtu_related_evidence"]), int(e["requires_investigation"]),
                     json.dumps({"window": ws}), "OPEN" if mode != "OBSERVATION_ONLY"
                     else "SHADOW"))
            self.progress()
            recs = self._recommendations(ws, result, mode, now)
            self.progress()
            peers = self._peer_summaries(ws, result, recs, mode)
        self.progress()
        self.prev_corr = keys
        self.last = {"window": ws, "correlations": events, "groups_eligible": eligible,
                     "advisories": self.diag.advisories(meta, self.iface_mtu, result),
                     "recommendations": recs, "peers": peers}
        return result

    def _peer_summaries(self, ws, result, recs, mode):
        """{pid: peer_summary} for the peers evaluated in this window, after
        apply(): the LIVE levels are the ones this window just produced."""
        we = ws + dg.WINDOW
        rtt_rows = self.diag.peer_rows(we - dg.RTT_WINDOW, we)
        win_rows = self.diag.peer_rows(ws, we)
        hist = self._history(we, result["peers"])
        c = self.store.conn
        out = {}
        for pid, pr in result["peers"].items():
            levels = [r[0] for r in c.execute(
                "SELECT confidence FROM diagnosis WHERE scope='PEER' AND subject=? "
                "AND state='OPEN' AND mode='LIVE'", (str(pid),))]
            rows = rtt_rows.get(pid)
            rf = feat.peer_features(rows) if rows else None
            why = set()
            for r in win_rows.get(pid, []):
                why |= feat.tokens(r)
            out[pid] = peer_summary(ws, pr["features"], rf, recs.get(pid, []), levels, mode,
                                    why)
            out[pid]["history"] = hist.get(pid)
        return out

    @staticmethod
    def _clean_sql(stream):
        """SQL predicate equal to features.stream_ok(row, stream): the row is not
        INVALID and carries none of the stream's bad tokens (S4 also rejects any
        'S4:' token). Built from features._BAD so the two cannot drift; the
        equality is pinned by test_history_sql_filter_equals_stream_ok."""
        parts = ["quality != 'INVALID'"]
        if stream == "S4":
            parts.append("instr(quality_why, 'S4:') = 0")
        for tok in feat._BAD[stream]:
            assert "'" not in tok
            parts.append("instr(';' || quality_why || ';', ';%s;') = 0" % tok)
        return " AND ".join(parts)

    def _history(self, we, pids):
        """{pid: {"end": we, "rtt_ms": [...], "loss": [...]}} over the trailing
        HISTORY_HOURS hours, one bucket per hour, oldest first. Same gates as
        peer_summary; a bucket without enough clean data is None.

        §29.160: aggregated in SQL. The first version loaded every 24-hour row
        as a 45-column dict (50 694 rows on myserver: +91 MB and 3 s of CPU every
        five minutes), which raised the engine's RSS to its MemoryHigh and, under
        the CPU quota, starved the watchdog twice. Now the loss sums are grouped
        per (peer, hour) in SQLite and only the rtt_samples strings of S1-clean
        minutes are fetched (0.24 s, a few hundred KB on the same data)."""
        p = rules.PARAMS
        span = HISTORY_HOURS * 3600
        t0 = we - span
        c = self.store.conn
        want = set(pids)
        rtt = {pid: [[] for _ in range(HISTORY_HOURS)] for pid in want}
        exp = {pid: [0] * HISTORY_HOURS for pid in want}
        rec = {pid: [0] * HISTORY_HOURS for pid in want}
        for pid, h, e, k in c.execute(
                "SELECT peer_id, (ts - ?) / 3600, COALESCE(SUM(s4_expected), 0), "
                "COALESCE(SUM(s4_received), 0) FROM peer_minute WHERE ts >= ? AND ts < ? AND "
                + self._clean_sql("S4") + " GROUP BY 1, 2", (t0, t0, we)):
            if pid in want and 0 <= h < HISTORY_HOURS:
                exp[pid][h] += e
                rec[pid][h] += k
        for pid, h, samples in c.execute(
                "SELECT peer_id, (ts - ?) / 3600, rtt_samples FROM peer_minute WHERE ts >= ? "
                "AND ts < ? AND rtt_samples IS NOT NULL AND rtt_samples != '' AND "
                + self._clean_sql("S1"), (t0, t0, we)):
            if pid in want and 0 <= h < HISTORY_HOURS:
                rtt[pid][h] += [float(x) for x in samples.split(",") if x]
        out = {}
        for pid in pids:
            out[pid] = {
                "end": we,
                "rtt_ms": [round(stats.median(s), 1) if len(s) >= p["rtt_min_samples"]
                           else None for s in rtt[pid]],
                "loss": [round(max(0, e - k) / e, 6) if e >= p["loss_n_min"] else None
                         for e, k in zip(exp[pid], rec[pid])]}
        return out

    def _diag_levels(self, pid):
        rows = self.store.conn.execute(
            "SELECT class, confidence FROM diagnosis WHERE scope='PEER' AND subject=? "
            "AND state='OPEN'", (str(pid),)).fetchall()
        return {c: (True, lv) for c, lv in rows}

    def _lookback_rows(self, ws):
        """Rows of the LOOKBACK_WINDOWS windows ending at ws, for every peer, loaded
        once per run_window (§29.161: _windows used to run this 30-minute query once
        per peer — 36 times, 0.8 s of the window's 1.4 s)."""
        return self.diag.peer_rows(ws - (rec.LOOKBACK_WINDOWS - 1) * dg.WINDOW, ws + dg.WINDOW)

    def _windows(self, pid, ws, n=rec.LOOKBACK_WINDOWS, since=None, rows=None):
        start = ws - (n - 1) * dg.WINDOW
        if since is not None:
            start = max(start, int(since // dg.WINDOW) * dg.WINDOW)
        if rows is None or n != rec.LOOKBACK_WINDOWS or since is not None:
            rows = self.diag.peer_rows(start, ws + dg.WINDOW)
        mine = [r for r in rows.get(pid, []) if r["ts"] >= start]
        by_w = {}
        for r in mine:
            by_w.setdefault(int(r["ts"] // dg.WINDOW) * dg.WINDOW, []).append(r)
        return rec.windows_features([by_w[w] for w in sorted(by_w)])

    def _latest_probe(self, pid):
        row = self.store.conn.execute(
            "SELECT results_json, ts FROM probe_run WHERE peer_id=? ORDER BY ts DESC LIMIT 1",
            (pid,)).fetchone()
        if not row or self.clock() - row[1] > PROBE_MAX_AGE_S:
            return None
        try:
            return json.loads(row[0])
        except ValueError:
            return None

    def _recommendations(self, ws, result, mode, now):
        out = {}
        c = self.store.conn
        lookback = self._lookback_rows(ws) if result["peers"] else {}
        for pid, pr in result["peers"].items():
            f = pr["features"]
            t = f["t_config"]
            prev = c.execute("SELECT t_config FROM peer_minute WHERE peer_id=? AND ts<? AND "
                             "t_config IS NOT NULL ORDER BY ts DESC LIMIT 1",
                             (pid, ws)).fetchone()
            prev_t = prev[0] if prev else None       # from the DB: survives restarts
            if prev_t is not None and t is not None and t != prev_t:
                last = c.execute("SELECT id FROM recommendation WHERE peer_id=? AND "
                                 "suggested_value IS NOT NULL ORDER BY ts DESC LIMIT 1",
                                 (pid,)).fetchone()
                if last:
                    c.execute("INSERT OR REPLACE INTO rec_followup(peer_id,rec_id,t_old,t_new,"
                              "changed_at,active_minutes,verdict) VALUES(?,?,?,?,?,0,NULL)",
                              (pid, last[0], prev_t, t, now))
                c.execute("INSERT INTO config_event(ts,kind,subject,old,new) VALUES(?,?,?,?,?)",
                          (now, "CLIENT_MTU", str(pid), prev_t, t))
            items = rec.recommend(self._windows(pid, ws, rows=lookback), self._diag_levels(pid), t, mode,
                                  self._latest_probe(pid))
            fu = c.execute("SELECT rec_id, t_new, changed_at, verdict FROM rec_followup "
                           "WHERE peer_id=?", (pid,)).fetchone()
            if fu and fu[3] is None and t == fu[1]:
                v = rec.followup_verdict(self._windows(pid, ws, n=288, since=fu[2]), fu[1],
                                         now - fu[2])
                if v:
                    c.execute("UPDATE rec_followup SET verdict=? WHERE peer_id=?", (v, pid))
                    fu = (fu[0], fu[1], fu[2], v)
            if fu and fu[3] == "CONFIRMED" and t == fu[1]:
                up = [x for x in items if x["target"] == "CLIENT_IFACE_MTU"
                      and x["direction_scope"] == "UPSTREAM"]
                if any(x["suggested_value"] for x in up):
                    # fresh evidence contradicts the confirmation: it no longer holds
                    c.execute("UPDATE rec_followup SET verdict='SUPERSEDED' WHERE peer_id=?",
                              (pid,))
                else:
                    items = [x for x in items if x not in up]
                    items.insert(0, {"target": "CLIENT_IFACE_MTU", "current_value": t,
                                     "current_source": "CONFIG", "suggested_value": None,
                                     "status": "VERIFIED", "direction_scope": "UPSTREAM",
                                     "rationale": ["follow-up confirmed after the change to %d: "
                                                   "full-size packets unfragmented, no "
                                                   "fragments, no DF ceiling" % t],
                                     "limitations": ["downstream direction not verified"]})
            for it in items:
                self._store_rec(pid, f, it, now)
            out[pid] = items
        return out

    def _store_rec(self, pid, f, it, now):
        c = self.store.conn
        last = c.execute("SELECT id, status, suggested_value, direction_scope FROM "
                         "recommendation WHERE peer_id=? AND target=? AND direction_scope=? "
                         "AND superseded_by IS NULL ORDER BY ts DESC LIMIT 1",
                         (pid, it["target"], it["direction_scope"])).fetchone()
        same = last and (last[1], last[2], last[3]) == (it["status"], it["suggested_value"],
                                                         it["direction_scope"])
        if same:
            return
        cur = c.execute(
            "INSERT INTO recommendation(ts,peer_id,iface,target,current_value,current_source,"
            "suggested_value,status,direction_scope,rationale_json,limitations_json,"
            "diagnosis_ids,superseded_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (now, pid, None, it["target"], it["current_value"], it["current_source"],
             it["suggested_value"], it["status"], it["direction_scope"],
             json.dumps(it["rationale"], ensure_ascii=False),
             json.dumps(it["limitations"], ensure_ascii=False), "[]"))
        if last:
            c.execute("UPDATE recommendation SET superseded_by=? WHERE id=?",
                      (cur.lastrowid, last[0]))

    # ---- probe gates (04 §7) -----------------------------------------------------
    def request_probe(self, peer_name, actor, mode, meta_getter):
        now = self.clock()
        meta = meta_getter()
        if mode != "RECOMMENDATIONS_ENABLED":
            return {"ok": False, "refused": "MODE_GATE"}
        if not self.cfg["active_probes"]:
            return {"ok": False, "refused": "FLAG_GATE"}
        if self.probe_running is not None and self.probe_running.is_alive():
            return {"ok": False, "refused": "BUSY"}
        if meta is None or meta.age(now) > self.cfg["limits"]["meta_stale_s"]:
            return {"ok": False, "refused": "META_STALE"}
        hits = [(pub, p) for pub, p in meta.peers.items() if p["name"] == peer_name]
        if len(hits) != 1:
            return {"ok": False, "refused": "NO_SUCH_PEER"}
        pub, p = hits[0]
        if not p["enabled"] or not p["tunnel_ip"]:
            return {"ok": False, "refused": "PEER_NOT_PROBEABLE"}
        if not p["latest_handshake"] or now - p["latest_handshake"] > HS_START_MAX:
            return {"ok": False, "refused": "STALE_HS"}
        pid = self.store.peer_id(p["iface"], p["name"], key_fp(pub))
        last = self.store.conn.execute("SELECT MAX(ts) FROM probe_run WHERE peer_id=?",
                                       (pid,)).fetchone()[0]
        if last is not None and now - last < PROBE_PER_PEER_S:
            return {"ok": False, "refused": "RATE"}
        t_cfg = meta.effective_mtu(pub)

        def hs_age():
            """Seconds since this peer's latest handshake, from the newest meta
            (Meta objects are immutable; reading the reference is thread-safe)."""
            m = meta_getter()
            q = m.peers.get(pub) if m is not None else None
            if not q or not q["latest_handshake"]:
                return None
            return self.clock() - q["latest_handshake"]

        run_id = int(now * 1000)
        self.probe_running = self.probe_cls(run_id, pub, p["tunnel_ip"], t_cfg,
                                            meta.wg1udp_mtu, self.cfg["capture"]["user_iface"],
                                            hs_age, self.probe_results,
                                            reasm_drops=self.reasm_drops)
        self.probe_running.requested_by = actor
        self.probe_running.peer_id = pid
        self.probe_running.start()
        return {"ok": True, "run_id": run_id}

    def collect_probes(self):
        while True:
            try:
                res = self.probe_results.get_nowait()
            except queue.Empty:
                return
            pid = res.get("peer_id")
            actor = res.get("requested_by", "?")
            with self.store.transaction():
                self.store.conn.execute(
                    "INSERT INTO probe_run(ts,peer_id,requested_by,sizes_json,results_json,"
                    "packets_sent,bytes_sent,verdict,aborted_reason) VALUES(?,?,?,?,?,?,?,?,?)",
                    (self.clock(), pid if pid is not None else -1, actor,
                     json.dumps([x[0] for x in res.get("log", [])]),
                     json.dumps({k: res.get(k) for k in ("verdict", "s_star", "s_fail",
                                                         "s_ok", "s_max", "t_config",
                                                         "reason", "server_reasm_drops")}),
                     res.get("packets_sent", 0), res.get("bytes_sent", 0),
                     res.get("verdict"), res.get("reason")))

    # ---- export -----------------------------------------------------------------
    def snapshot(self, names):
        c = self.store.conn
        diags = []
        for r in c.execute("SELECT id, ts, scope, subject, class, confidence, window_end, "
                           "evidence_json, counter_evidence_json, alternatives_json, "
                           "data_quality, mode, ack_by FROM diagnosis WHERE state='OPEN' "
                           "AND mode='LIVE' "                # shadow stays out of the UI (01 §4)
                           "ORDER BY ts DESC LIMIT 500"):
            d = {"id": r[0], "since": r[1], "scope": r[2], "class": r[4],
                 "confidence": r[5], "last_window_end": r[6],
                 "evidence": json.loads(r[7]), "counter_evidence": json.loads(r[8]),
                 "alternatives": json.loads(r[9]), "data_quality": r[10],
                 "mode": r[11], "acked_by": r[12]}
            if r[2] == "PEER":
                n = names.get(int(r[3]))
                d["peer"], d["iface"] = (n[1], n[0]) if n else (r[3], None)
            else:
                d["subject"] = r[3]
            diags.append(d)
        outbox = [{"id": r[0], "ts": r[1], "severity": r[2], "key": r[3], "text_key": r[4],
                   "params": json.loads(r[5])}
                  for r in c.execute("SELECT id, ts, severity, key, text_key, params_json "
                                     "FROM notify_outbox ORDER BY id DESC LIMIT ?",
                                     (OUTBOX_EXPORT,))]
        outbox.reverse()
        recs = {}
        for pid, items in self.last["recommendations"].items():
            n = names.get(pid)
            recs["%s/%s" % (n[0], n[1]) if n else str(pid)] = items   # iface/name: unique
        adv = []
        for a in self.last["advisories"]:
            a = dict(a)
            if a["scope"] == "PEER":
                n = names.get(int(a["subject"]))
                a["peer"] = n[1] if n else a["subject"]
                del a["subject"]
            adv.append(a)
        probe = None
        if self.probe_running is not None:
            probe = {"running": self.probe_running.is_alive(),
                     "run_id": self.probe_running.run_id}
        # one label per (iface, name): a name with two peer_ids in one window
        # (key rotated mid-window) is ambiguous and is left out, never merged
        by_label = {}
        for pid, s in self.last.get("peers", {}).items():
            n = names.get(pid)
            if n:
                by_label.setdefault((n[0], n[1]), []).append(s)
        peers = [dict(v[0], iface=k[0], name=k[1])
                 for k, v in sorted(by_label.items()) if len(v) == 1]
        return {"diagnoses": diags, "notify_outbox": outbox, "recommendations": recs,
                "peers": peers,
                "advisories": adv, "correlations": self.last["correlations"],
                "groups_eligible": self.last["groups_eligible"],
                "last_window": self.last["window"], "probe": probe,
                "promotion": self.diag.shadow_stats(self.clock())}
