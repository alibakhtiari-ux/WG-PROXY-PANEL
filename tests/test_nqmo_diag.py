"""WG-NQMO PHASE 3 tests: diagnosis, confidence, recommendations, correlation,
advisories, probe, ASN.

Family guards:
  NqmoWilsonTests                 a true 0.3% loss essentially never fires the 1% rule (exact binomial)
  NqmoMtuNotFromThroughputTests   R-MTU-1: MTU rules take no rate/throughput input
  NqmoNoFabricationTests          missing/partial data ⇒ UNDETERMINED, never a number
  NqmoNoFilteringClaimTests       R-FILTER-1: no text names filtering as the cause
  NqmoProbeGateTests              ping only via probe.py, only behind every gate
"""
import ast
import inspect
import json
import math
import os
import queue
import random
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from nqmo import asn, confidence as conf, config, correlate, features, probe  # noqa: E402
from nqmo import recommend as rec, rules, runner, stats, store as storemod  # noqa: E402
from nqmo.analysis import HISTORY_HOURS, WHY_MAX, Analysis  # noqa: E402

PKG = os.path.join(ROOT, "nqmo")
T0 = 1000200                     # a multiple of 300 (window-aligned)
CTX = "198.51.100.0/24|1392|0|1392"

# Host-independent runner checks: runner._iface consults SYS_NET when it exists.
# Every test sees the same fake sysfs, so a result never depends on whether the
# host has /sys (macOS) or happens to lack wg1udp (a plain Linux box) — the
# OrbStack lab found four tests that passed on the Mac only by accident.
FAKE_IFACES = ("eth0", "wg1udp", "ib_wg1udp")
_SAVED_SYS_NET = None


def setUpModule():
    global _SAVED_SYS_NET
    d = tempfile.mkdtemp(prefix="nqmo-sysnet-")
    for name in FAKE_IFACES:
        os.mkdir(os.path.join(d, name))
    _SAVED_SYS_NET, runner.SYS_NET = runner.SYS_NET, d


def tearDownModule():
    d = runner.SYS_NET
    runner.SYS_NET = _SAVED_SYS_NET
    shutil.rmtree(d, ignore_errors=True)



def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def mrow(pid, ts, **kw):
    r = {"peer_id": pid, "ts": ts, "quality": "GOOD", "quality_why": "",
         "t_config": 1392, "ctx_key": CTX, "rx_bytes": 2000000, "tx_bytes": 3000000,
         "c1_interval_s": 60.0, "ep_changed": 0, "ep_port_only_changed": 0,
         "hs_age_max": 30, "hs_init_in": 0, "hs_resp_out": 0, "hs_init_out": 0,
         "hs_resp_in": 0, "hs_cookie_out": 0, "rtt_n": 0, "rtt_missed": 0,
         "frag_first": 0, "frag_incomplete": 0, "s4_runs": 1, "s4_pkts": 5000,
         "s4_expected": 5000, "s4_received": 5000, "s4_dup": 0, "s4_late": 0,
         "s4_reorder": 0, "l_max_unfrag": 1392 + 60, "l_ceiling_share": 0.4,
         "df_ratio": 0.0, "syn_n": 0}
    r.update(kw)
    return r


def window_rows(pid, ws, **kw):
    return [mrow(pid, ws + 60 * i, **kw) for i in range(5)]


def feats(**kw):
    return features.peer_features(window_rows(1, T0, **kw))


# ------------------------------------------------------------------ statistics
class NqmoWilsonTests(unittest.TestCase):
    def test_known_values(self):
        lo, hi = stats.wilson(0, 100)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.0370, places=3)
        lo, hi = stats.wilson(50, 100)
        self.assertAlmostEqual(lo, 0.4038, places=3)
        self.assertAlmostEqual(hi, 0.5962, places=3)

    def test_small_samples_cannot_cross_threshold(self):
        # 2 lost in 200 (point estimate 1%) must not reach a 1% lower bound
        self.assertLess(stats.wilson(2, 200)[0], 0.01)

    def test_true_low_loss_essentially_never_fires(self):
        """Exact: P(Wilson LB ≥ 1% | n=1000, p=0.3%) — review round 1, finding 12."""
        n, p = 1000, 0.003
        k_min = next(k for k in range(n + 1) if stats.wilson(k, n)[0] >= 0.01)
        tail = sum(math.comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(k_min, n + 1))
        self.assertLess(tail, 1e-4, (k_min, tail))
        # and HIGH needs three such windows: probability ≈ tail³
        self.assertLess(tail ** 3, 1e-12)

    def test_median_mad(self):
        self.assertEqual(stats.median([3, 1, 2]), 2)
        self.assertEqual(stats.median([1, 2, 3, 4]), 2.5)
        self.assertEqual(stats.mad([1, 2, 3, 4, 100]), 1)


# ------------------------------------------------------------------ features
class NqmoFeatureValidityTests(unittest.TestCase):
    def test_tainted_stream_is_excluded_per_stream(self):
        rows = window_rows(1, T0, s4_expected=5000, s4_received=4000)
        for r in rows[:3]:
            r["quality_why"] = "S4:GAP:KERNEL_DROP"
            r["quality"] = "DEGRADED"
        f = features.peer_features(rows)
        self.assertEqual(f["quality"]["S4"], "INVALID")          # only 2 clean minutes
        self.assertEqual(f["quality"]["S2"], "GOOD")              # other streams unaffected

    def test_startup_and_disabled_invalidate_capture(self):
        rows = window_rows(1, T0, quality_why="C3:DISABLED", quality="DEGRADED")
        f = features.peer_features(rows)
        for s in ("S1", "S2", "S4", "S5"):
            self.assertEqual(f["quality"][s], "INVALID", s)
        self.assertEqual(f["quality"]["C1"], "GOOD")

    def test_loss_folds_incomplete_fragments(self):
        # 20 incomplete of 25 000 arrived data packets (share 0.0008) applied
        # to the 5 000 judged counters; the denominator is NOT inflated — the
        # incomplete datagrams' first fragments are already inside s4_expected
        f = feats(s4_expected=1000, s4_received=1000, frag_first=10, frag_incomplete=4)
        self.assertEqual((f["loss_k"], f["loss_n"]), (4, 5000))
        self.assertEqual(f["s4_loss_point"], 0.0)


# ------------------------------------------------------------------ rules
class NqmoRuleTests(unittest.TestCase):
    def test_loss_rule_uses_lower_bound(self):
        self.assertFalse(rules.packet_loss(feats(s4_expected=300, s4_received=297),
                                           None, False, False).positive is True)
        self.assertTrue(rules.packet_loss(feats(s4_expected=5000, s4_received=4850),
                                          None, False, False).positive)

    def test_loss_routed_to_df_blackhole(self):
        o = rules.packet_loss(feats(s4_received=4800), None, False, True)
        self.assertFalse(o.positive)

    def test_client_saturation_caps_loss(self):
        base = {"max_up_mbit": 0.27, "loss_rate": None, "rtt_med": None}
        o = rules.packet_loss(feats(s4_received=4800), base, False, False)
        self.assertTrue(o.positive)
        self.assertEqual(o.cap, "LOW")

    def test_mtu_problem_stable_fragments(self):
        o = rules.mtu_problem(10, 1420, 1424, None, 1392, "GOOD", "GOOD")
        self.assertTrue(o.positive)
        self.assertFalse(rules.mtu_problem(10, 1300, 1420, None, 1392, "GOOD", "GOOD").positive)
        self.assertIsNone(rules.mtu_problem(10, 1420, 1424, None, 1392, "INVALID", "GOOD").positive)
        multi = rules.mtu_problem(10, 1420, 1424, 1452, 1392, "GOOD", "GOOD")
        self.assertEqual(multi.cap, "LOW")

    def test_df_blackhole_ceiling(self):
        o = rules.blackhole_df(0.99, 0, 1380, 0.5, 1392, 0.02, 5000, "GOOD")
        self.assertTrue(o.positive)
        self.assertEqual(o.cap, "MEDIUM")
        self.assertFalse(rules.blackhole_df(0.99, 0, 1452, 0.5, 1392, 0.02, 5000, "GOOD").positive)
        self.assertFalse(rules.blackhole_df(0.1, 0, 1380, 0.5, 1392, 0.02, 5000, "GOOD").positive)

    def test_nat_signature(self):
        f = feats(rx_bytes=0, tx_bytes=740, hs_init_out=2, hs_resp_in=0)
        self.assertTrue(rules.nat_or_firewall(f).positive)
        f = feats(rx_bytes=100, tx_bytes=740, hs_init_out=2)
        self.assertFalse(rules.nat_or_firewall(f).positive)

    def test_nat_is_not_an_offline_client(self):
        """§29.157 — family: the NAT signature (rx frozen, server Initiations, no
        Response) is also exactly what an absent device looks like. Only a session
        that was alive within nat_offline_s is a NAT/firewall symptom; beyond that
        the rule says why it abstains, and the boundary is inclusive."""
        lim = rules.PARAMS["nat_offline_s"]
        sig = dict(rx_bytes=0, tx_bytes=740, hs_init_out=2, hs_resp_in=0)
        for age, want in ((0, True), (lim - 1, True), (lim, False), (4 * 86400, False)):
            o = rules.nat_or_firewall(feats(hs_age_max=age, **sig))
            self.assertEqual(o.positive, want, age)
            if not want:
                self.assertTrue(any("offline" in c for c in o.counter), o.counter)
                self.assertEqual(o.evidence, [])
        # a window where the handshake age is unknown (None) is treated as 0
        self.assertTrue(rules.nat_or_firewall(feats(hs_age_max=None, **sig)).positive)
        # and the offline guard never turns a non-signature into a diagnosis
        self.assertFalse(rules.nat_or_firewall(feats(rx_bytes=100, hs_age_max=lim * 2,
                                                     **{k: v for k, v in sig.items()
                                                        if k != "rx_bytes"})).positive)

    def test_handshake_failure(self):
        self.assertTrue(rules.handshake_failure(feats(hs_init_in=1, hs_resp_out=0)).positive)
        self.assertFalse(rules.handshake_failure(feats(hs_init_in=1, hs_resp_out=1)).positive)

    def test_congestion_needs_baseline_and_samples(self):
        self.assertIsNone(rules.congestion([100.0] * 10, "GOOD", None).positive)
        base = {"rtt_med": 40.0, "rtt_mad": 5.0, "rtt_n": 500}
        self.assertIsNone(rules.congestion([200.0] * 4, "GOOD", base).positive)
        self.assertTrue(rules.congestion([200.0] * 6, "GOOD", base).positive)
        self.assertFalse(rules.congestion([60.0] * 6, "GOOD", base).positive)

    def test_shaping(self):
        self.assertTrue(rules.traffic_shaping(feats(rate_limit_mbit=1, tc_drops=3)).positive)
        self.assertFalse(rules.traffic_shaping(feats()).positive)


class NqmoMtuNotFromThroughputTests(unittest.TestCase):
    """R-MTU-1 — no MTU rule can see a rate, byte count or throughput."""
    FORBIDDEN = ("rx", "tx", "rate", "mbit", "throughput", "bytes", "c1_interval")

    def test_signatures(self):
        for fn in (rules.mtu_problem, rules.blackhole_frag, rules.blackhole_df):
            for name in inspect.signature(fn).parameters:
                self.assertFalse(any(w in name for w in self.FORBIDDEN), (fn.__name__, name))

    def test_bodies_read_no_rate_feature(self):
        tree = ast.parse(read(os.path.join(PKG, "rules.py")))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in (
                    "mtu_problem", "blackhole_frag", "blackhole_df"):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                        self.assertNotIn(sub.value, ("rx", "tx", "rate_limit_mbit",
                                                     "c1_interval"), node.name)

    def test_slow_peer_alone_never_suspects_mtu(self):
        f = feats(rx_bytes=1000, tx_bytes=1000)          # very slow, nothing else
        for o in (rules.mtu_problem(f["frag_first"], f["F_min"], f["F_max"], f["l_max"],
                                    f["t_config"], "GOOD", "GOOD"),
                  rules.blackhole_frag(f["frag_first"], f["frag_incomplete"], 0, "GOOD")):
            self.assertNotEqual(o.positive, True)


class NqmoNoFilteringClaimTests(unittest.TestCase):
    def test_no_filtering_claims_anywhere(self):
        """Every string a user can see (not docstrings/comments) is checked."""
        for fn in ("rules.py", "diagnose.py", "correlate.py", "recommend.py", "analysis.py"):
            tree = ast.parse(read(os.path.join(PKG, fn)))
            docs = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)):
                    d = ast.get_docstring(node, clean=False)
                    if d:
                        docs.add(d)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                        and node.value not in docs:
                    low = node.value.lower()
                    for bad in ("filtering", "filtered by", "censor", "isp changed",
                                "isp blocked"):
                        self.assertNotIn(bad, low, (fn, node.value[:80]))


# ------------------------------------------------------------------ confidence
def H(p, s="DIRECT", q="GOOD", c=False, cap=None):
    return {"w": 0, "p": p, "s": s, "q": q, "c": c, "cap": cap}


class NqmoConfidenceTests(unittest.TestCase):
    def test_table(self):
        self.assertEqual(conf.level([H(True)] * 3), "HIGH")
        self.assertEqual(conf.level([H(True)] * 2), "MEDIUM")
        self.assertEqual(conf.level([H(True)]), "LOW")
        self.assertEqual(conf.level([H(True, q="DEGRADED")] * 3), "MEDIUM")
        self.assertEqual(conf.level([H(True, s="INDIRECT")] * 3), "MEDIUM")
        self.assertEqual(conf.level([H(True, c=True)] * 3), "LOW")        # 04 §3: counter ⇒ LOW
        self.assertEqual(conf.level([H(True, cap="LOW")] * 3), "LOW")
        self.assertEqual(conf.level([H(False)] * 5), "INSUFFICIENT_EVIDENCE")
        self.assertEqual(conf.level([H(None)] * 5), "INSUFFICIENT_EVIDENCE")

    def test_hysteresis(self):
        self.assertIsNone(conf.transition([H(True)], False))
        self.assertEqual(conf.transition([H(True)] * 2, False), "OPEN")
        self.assertIsNone(conf.transition([H(True), H(False), H(False)], True))
        self.assertEqual(conf.transition([H(False)] * 3, True), "CLEAR")
        self.assertIsNone(conf.transition([H(None)] * 3, True))       # n/a is not "healthy"
        self.assertEqual(conf.transition([H(None)] * conf.STALE_AFTER, True), "STALE")


# ------------------------------------------------------------------ recommendations
def W(**kw):
    return [feats(**kw) for _ in range(6)]


class NqmoRecommendTests(unittest.TestCase):
    MODE = "RECOMMENDATIONS_ENABLED"

    def test_verified_upstream_only(self):
        r = rec.recommend(W(), {}, 1392, self.MODE)[0]
        self.assertEqual((r["status"], r["suggested_value"], r["direction_scope"]),
                         ("VERIFIED", None, "UPSTREAM"))
        self.assertIn("downstream direction not verified", r["limitations"])

    def test_fragment_estimate_is_F_minus_60(self):
        fs = W(frag_first=5, frag_first_len_min=1420, frag_first_len_max=1420,
               l_max_unfrag=1400)
        r = rec.recommend(fs, {"SUSPECTED_MTU_PROBLEM": (True, "HIGH")}, 1392, self.MODE)
        self.assertEqual((r[0]["status"], r[0]["suggested_value"]), ("ESTIMATED", 1360))
        self.assertEqual(r[-1]["target"], "SERVER_PEER_TCP_MSS")
        self.assertEqual(r[-1]["suggested_value"], 1320)
        r = rec.recommend(fs, {"SUSPECTED_MTU_PROBLEM": (True, "MEDIUM")}, 1392, self.MODE)
        self.assertEqual(r[0]["status"], "CANDIDATE_FOR_TESTING")

    def test_below_1280_capped(self):
        fs = W(frag_first=5, frag_first_len_min=1300, frag_first_len_max=1300)
        r = rec.recommend(fs, {"SUSPECTED_MTU_PROBLEM": (True, "HIGH")}, 1392, self.MODE)[0]
        self.assertEqual((r["status"], r["suggested_value"]), ("CANDIDATE_FOR_TESTING", 1240))
        self.assertTrue(any("1280" in x for x in r["limitations"]))

    def test_df_ceiling_candidate(self):
        fs = W(df_ratio=0.99, l_max_unfrag=1380, s4_received=4800)   # 11(b) evidence: loss
        r = rec.recommend(fs, {"SUSPECTED_PMTU_BLACKHOLE": (True, "MEDIUM")}, 1392, self.MODE)
        self.assertEqual((r[0]["status"], r[0]["suggested_value"]),
                         ("CANDIDATE_FOR_TESTING", 1320))

    def test_probe_threshold_roundtrip(self):
        r = rec.recommend(W(l_max_unfrag=1300), {}, 1392, self.MODE,
                          probe={"verdict": "THRESHOLD", "s_star": 1316, "t_config": 1392,
                                 "server_reasm_drops": 0})
        r = [x for x in r if x["direction_scope"] == "ROUNDTRIP"][0]
        self.assertEqual((r["status"], r["suggested_value"]), ("ESTIMATED", 1344))

    def test_mode_gate(self):
        r = rec.recommend(W(), {}, 1392, "DIAGNOSTICS_ENABLED")[0]
        self.assertEqual((r["status"], r["rationale"]), ("UNDETERMINED", ["DISABLED_BY_MODE"]))

    def test_followup(self):
        ok = W(l_max_unfrag=1360 + 60)
        self.assertEqual(rec.followup_verdict(ok[:3], 1360, 600), "CONFIRMED")
        bad = W(frag_first=3, frag_first_len_min=1400, frag_first_len_max=1400)
        self.assertEqual(rec.followup_verdict(bad[:2], 1360, 600), "NOT_CONFIRMED")
        self.assertIsNone(rec.followup_verdict(bad[:1], 1360, 600))      # one window: draining
        self.assertEqual(rec.followup_verdict([], 1360, 25 * 3600), "INCONCLUSIVE")


class NqmoNoFabricationTests(unittest.TestCase):
    def test_partial_data_is_undetermined(self):
        cases = [
            [],
            W(quality_why="C3:DISABLED", quality="DEGRADED"),
            W(l_max_unfrag=None, s4_pkts=0),
            W()[:2],
        ]
        for fs in cases:
            r = rec.recommend(fs, {}, 1392, "RECOMMENDATIONS_ENABLED")[0]
            self.assertEqual(r["status"], "UNDETERMINED")
            self.assertIsNone(r["suggested_value"])
        self.assertEqual(rec.recommend(W(), {}, None, "RECOMMENDATIONS_ENABLED")[0]["status"],
                         "UNDETERMINED")

    def test_random_features_never_raise_or_exceed_config(self):
        rnd = random.Random(5)
        for _ in range(300):
            kw = {"frag_first": rnd.choice([0, 0, 3, 9]),
                  "frag_first_len_min": rnd.randint(1200, 1500),
                  "frag_first_len_max": rnd.randint(1200, 1500),
                  "l_max_unfrag": rnd.choice([None, rnd.randint(500, 1500)]),
                  "df_ratio": rnd.random(), "quality_why": rnd.choice(["", "S4:GAP:X"]),
                  "quality": rnd.choice(["GOOD", "DEGRADED"])}
            fs = [feats(**kw) for _ in range(rnd.randint(0, 6))]
            diag = {c: (True, rnd.choice(conf.LEVELS)) for c in
                    rnd.sample(["SUSPECTED_MTU_PROBLEM", "SUSPECTED_PMTU_BLACKHOLE",
                                "PACKET_LOSS"], rnd.randint(0, 3))}
            for r in rec.recommend(fs, diag, 1392, "RECOMMENDATIONS_ENABLED"):
                self.assertIn(r["status"], ("VERIFIED", "ESTIMATED", "CANDIDATE_FOR_TESTING",
                                            "UNDETERMINED"))
                if r["suggested_value"] is not None and r["target"] == "CLIENT_IFACE_MTU":
                    self.assertLess(r["suggested_value"], 1392)
                if r["status"] == "UNDETERMINED":
                    self.assertIsNone(r["suggested_value"])


# ------------------------------------------------------------------ correlation
class FakeOutcome:
    def __init__(self, cls, positive=True):
        self.cls, self.positive, self.strength, self.cap = cls, positive, "DIRECT", None


def peers_result(specs):
    out = {"peers": {}}
    for i, (net, degraded, F) in enumerate(specs):
        f = feats(ctx_key="%s|1392|0|1392" % net,
                  frag_first_len_min=F, frag_first_len_max=F, frag_first=4 if F else 0)
        o = [FakeOutcome("PACKET_LOSS", degraded)]
        out["peers"][i] = {"features": f, "outcomes": o}
    return out


class NqmoCorrelationTests(unittest.TestCase):
    def test_group_event_needs_three_and_half(self):
        res = peers_result([("198.51.100.0/24", True, None)] * 3)
        ev, eligible = correlate.correlate(res, False, [])
        kinds = {(e["group_type"], e["suspected_cause"]) for e in ev}
        self.assertIn(("PREFIX24", "UNKNOWN"), kinds)
        self.assertEqual(eligible, 2)                    # /24 and its /16
        res = peers_result([("198.51.100.0/24", True, None)] * 2 +
                           [("198.51.100.0/24", False, None)] * 2)
        ev, _ = correlate.correlate(res, False, [])
        self.assertFalse([e for e in ev if e["group_type"] == "PREFIX24"])

    def test_server_cause_named_and_mtu_evidence(self):
        res = peers_result([("AS64500", True, 1420), ("AS64500", True, 1424),
                            ("AS64500", True, None)])
        ev, _ = correlate.correlate(res, True, [])
        g = [e for e in ev if e["group_type"] == "ASN"][0]
        self.assertEqual(g["suspected_cause"], "SERVER")
        self.assertTrue(g["mtu_related_evidence"])
        self.assertEqual(g["confidence"], "LOW")


# ------------------------------------------------------------------ end-to-end
class Meta:
    """Minimal stand-in for collect.meta.Meta used by analysis."""

    def __init__(self, now, egress=None, peers=None):
        self.generated_at = now
        self.egress = egress or {}
        self.peers = peers or {}
        self.wg1udp_mtu = 1392

    def age(self, now):
        return now - self.generated_at

    def effective_mtu(self, pub):
        return self.peers[pub]["c_mtu"] or 1392


class NqmoAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.store = storemod.Store(os.path.join(self.d, "n.db"))
        self.cfg = config.validate({})
        self.t = [T0]
        self.an = Analysis(self.store, self.cfg, clock=lambda: self.t[0],
                           iface_mtu=lambda dev: {"awg1": 1420}.get(dev))
        self.pid = self.store.peer_id("wg1udp", "alice", "fp")

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.d)

    EGRESS_OK = json.dumps({"awg1": {"kind": "awg", "mtu": 1420, "endpoint_dev": "eth0",
                                     "awg_s4": 0, "health": "healthy", "svc_ok": True,
                                     "mtr_loss": 0.0}})

    def feed(self, ws, egress_json=EGRESS_OK, **kw):
        for r in window_rows(self.pid, ws, **kw):
            self.store.put_peer_minute(r)
        self.store.put_global_minute({"ts": ws, "quality": "GOOD", "egress_json": egress_json})

    def run_windows(self, n, mode, start=0, **kw):
        for i in range(start, start + n):
            ws = T0 + 300 * i
            self.feed(ws, **kw)
            self.t[0] = ws + 310
            self.an.run_window(ws, Meta(self.t[0]), mode)

    def outbox(self):
        return self.store.conn.execute("SELECT severity, text_key FROM notify_outbox").fetchall()

    def test_loss_opens_notifies_once_and_clears(self):
        lossy = dict(s4_expected=5000, s4_received=4800)
        self.run_windows(4, "DIAGNOSTICS_ENABLED", **lossy)
        st = self.store.conn.execute(
            "SELECT class, confidence, state FROM diagnosis WHERE class='PACKET_LOSS'").fetchall()
        self.assertEqual(st, [("PACKET_LOSS", "HIGH", "OPEN")])
        self.assertEqual([x for x in self.outbox() if x[1] == "nqmo.alert.open"],
                         [("MEDIUM", "nqmo.alert.open")])
        self.assertEqual([x for x in self.outbox() if x[1] == "nqmo.alert.escalated"],
                         [("HIGH", "nqmo.alert.escalated")])
        self.run_windows(3, "DIAGNOSTICS_ENABLED", start=4)       # healthy now
        st = self.store.conn.execute(
            "SELECT state FROM diagnosis WHERE class='PACKET_LOSS'").fetchone()
        self.assertEqual(st, ("CLEARED",))
        self.assertIn(("INFO", "nqmo.alert.cleared"), self.outbox())

    def test_shadow_mode_never_notifies(self):
        self.run_windows(4, "OBSERVATION_ONLY", s4_expected=5000, s4_received=4800)
        self.assertEqual(self.outbox(), [])
        mode = self.store.conn.execute("SELECT mode FROM diagnosis").fetchone()
        self.assertEqual(mode, ("SHADOW",))

    def test_shaping_caps_mtu_at_low(self):
        self.run_windows(4, "DIAGNOSTICS_ENABLED", frag_first=5, frag_first_len_min=1420,
                         frag_first_len_max=1420, l_max_unfrag=1400, rate_limit_mbit=1,
                         tc_drops=9)
        lv = self.store.conn.execute(
            "SELECT confidence FROM diagnosis WHERE class='SUSPECTED_MTU_PROBLEM'").fetchone()
        self.assertEqual(lv, ("LOW",))
        self.assertFalse([x for x in self.outbox()
                          if "SUSPECTED_MTU" in x[1]])                 # LOW never pages

    def test_healthy_peer_verified_and_silent(self):
        self.run_windows(4, "RECOMMENDATIONS_ENABLED")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM diagnosis").fetchone(),
                         (0,))
        recs = self.an.last["recommendations"][self.pid]
        self.assertEqual(recs[0]["status"], "VERIFIED")
        self.assertEqual(self.outbox(), [])

    def test_followup_after_operator_change(self):
        frag = dict(frag_first=5, frag_first_len_min=1420, frag_first_len_max=1420,
                    l_max_unfrag=1400)
        self.run_windows(4, "RECOMMENDATIONS_ENABLED", **frag)
        r = self.store.conn.execute("SELECT status, suggested_value FROM recommendation "
                                    "WHERE target='CLIENT_IFACE_MTU' AND superseded_by IS NULL"
                                    ).fetchone()
        self.assertEqual(r, ("ESTIMATED", 1360))
        self.run_windows(4, "RECOMMENDATIONS_ENABLED", start=4, t_config=1360,
                         l_max_unfrag=1420, ctx_key="198.51.100.0/24|1360|0|1392")
        fu = self.store.conn.execute("SELECT verdict FROM rec_followup").fetchone()
        self.assertEqual(fu, ("CONFIRMED",))
        verified = [x for x in self.an.last["recommendations"][self.pid]
                    if x["status"] == "VERIFIED"]
        self.assertTrue(verified)

    def test_nested_tunnel_advisory_is_never_notified(self):
        eg = {"wg21": {"kind": "wg", "mtu": 1400, "endpoint_dev": "awg1", "awg_s4": None},
              "awg1": {"kind": "awg", "mtu": 1420, "endpoint_dev": "eth0", "awg_s4": 0}}
        for i in range(3):
            ws = T0 + 300 * i
            self.feed(ws)
            self.t[0] = ws + 310
            self.an.run_window(ws, Meta(self.t[0], egress=eg), "DIAGNOSTICS_ENABLED")
        adv = [a for a in self.an.last["advisories"] if a["subject"] == "wg21"][0]
        self.assertEqual((adv["finding"], adv["suggested_mtu"], adv["outer"]),
                         ("NESTED_MTU_MISMATCH", 1360, 1460))
        self.assertFalse([x for x in self.outbox() if "wg21" in str(x)])

    def test_insufficient_data_opens_nothing(self):
        self.run_windows(4, "DIAGNOSTICS_ENABLED", quality_why="C3:DISABLED",
                         quality="DEGRADED", s4_received=1000)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) FROM diagnosis").fetchone(), (0,))

    def test_rate_cap_aggregates(self):
        for i in range(10):
            self.an.diag._outbox(T0, "HIGH", "k%d" % i, "nqmo.alert.open", {})
        self.an.diag._outbox_more(T0)
        self.an.diag._outbox_more(T0 + 10)
        self.assertEqual(len([x for x in self.outbox() if x[1] == "nqmo.alert.more"]), 1)

    def test_snapshot_has_no_raw_ips_or_keys(self):
        self.run_windows(3, "DIAGNOSTICS_ENABLED", s4_expected=5000, s4_received=4800)
        snap = json.dumps(self.an.snapshot(self.an.diag.peer_names()))
        self.assertNotIn("198.51.100.7", snap)
        self.assertIn("alice", snap)


class NqmoPeerSummaryTests(unittest.TestCase):
    """state.json → peers (05 §5.5). Family guard: every number is one the rules
    themselves would judge, from the same filtered minutes, with its sample
    size — and absent wherever the rule would abstain. Never an invented value."""

    setUp = NqmoAnalysisTests.setUp
    tearDown = NqmoAnalysisTests.tearDown
    feed = NqmoAnalysisTests.feed
    run_windows = NqmoAnalysisTests.run_windows
    EGRESS_OK = NqmoAnalysisTests.EGRESS_OK

    def reset(self):
        self.tearDown()
        self.setUp()

    def peer(self, name="alice"):
        snap = self.an.snapshot(self.an.diag.peer_names())
        hit = [p for p in snap["peers"] if p["name"] == name]
        self.assertLessEqual(len(hit), 1)
        return hit[0] if hit else None

    def test_rtt_needs_enough_clean_samples_over_the_rtt_window(self):
        self.run_windows(3, "DIAGNOSTICS_ENABLED", rtt_samples="40.0")      # 15 samples
        p = self.peer()
        self.assertEqual((p["rtt_n"], p["rtt_ms_med"], p["rtt_ms_min"]), (15, 40.0, 40.0))
        # 4 samples across the window: reported as a count, never as a median
        self.reset()
        self.feed(T0, rtt_samples="")
        rows = window_rows(self.pid, T0 + 300, rtt_samples="")
        rows[0]["rtt_samples"] = "10.0,20.0,30.0,40.0"
        for r in rows:
            self.store.put_peer_minute(r)
        self.store.put_global_minute({"ts": T0 + 300, "quality": "GOOD"})
        self.t[0] = T0 + 610
        self.an.run_window(T0 + 300, Meta(self.t[0]), "DIAGNOSTICS_ENABLED")
        p = self.peer()
        self.assertEqual((p["rtt_n"], p["rtt_ms_med"], p["rtt_ms_min"]), (4, None, None))

    def test_rtt_excludes_minutes_whose_s1_stream_was_dirty(self):
        self.run_windows(3, "DIAGNOSTICS_ENABLED", rtt_samples="900.0",
                         quality_why="KERNEL_DROP:S1")
        p = self.peer()
        self.assertEqual((p["rtt_n"], p["rtt_ms_med"]), (0, None))

    def test_rtt_median_and_min_are_the_rules_own(self):
        vals = [12.0, 15.0, 11.0, 90.0, 14.0]
        self.run_windows(3, "DIAGNOSTICS_ENABLED",
                         rtt_samples=",".join("%.1f" % v for v in vals))
        p = self.peer()
        allv = vals * 15
        self.assertEqual(p["rtt_n"], len(allv))
        self.assertEqual(p["rtt_ms_med"], round(stats.median(allv), 1))
        self.assertEqual(p["rtt_ms_min"], 11.0)

    def test_loss_is_upstream_wilson_and_gated_by_the_rules_minimum(self):
        self.run_windows(1, "DIAGNOSTICS_ENABLED", s4_expected=5000, s4_received=4800)
        p = self.peer()
        n, k = 25000, 1000
        self.assertEqual((p["loss_n"], p["loss_k"]), (n, k))
        self.assertEqual(p["loss_point"], round(k / n, 6))
        lb, ub = stats.wilson(k, n)
        self.assertEqual((p["loss_lb"], p["loss_ub"]), (round(lb, 6), round(ub, 6)))
        # below loss_n_min the rule abstains, and so does the export
        self.reset()
        m = rules.PARAMS["loss_n_min"] // 5 - 1
        self.run_windows(1, "DIAGNOSTICS_ENABLED", s4_expected=m, s4_received=m - 3)
        p = self.peer()
        self.assertEqual(p["loss_n"], 5 * m)
        self.assertEqual((p["loss_k"], p["loss_point"], p["loss_lb"], p["loss_ub"]),
                         (None, None, None, None))

    def test_loss_absent_when_s4_is_invalid(self):
        self.run_windows(1, "DIAGNOSTICS_ENABLED", s4_expected=5000, s4_received=4000,
                         quality_why="S4_COUNTER_JUMP")
        p = self.peer()
        self.assertEqual((p["loss_n"], p["loss_point"]), (0, None))

    def test_mtu_status_is_the_recommenders_first_client_item(self):
        self.run_windows(4, "RECOMMENDATIONS_ENABLED")
        self.assertEqual(self.peer()["mtu_status"], "VERIFIED")
        self.reset()
        self.run_windows(4, "DIAGNOSTICS_ENABLED")
        self.assertEqual(self.peer()["mtu_status"], "UNDETERMINED")
        self.reset()
        frag = dict(frag_first=5, frag_first_len_min=1420, frag_first_len_max=1420,
                    l_max_unfrag=1400)
        self.run_windows(4, "RECOMMENDATIONS_ENABLED", **frag)
        self.assertEqual(self.peer()["mtu_status"], "ESTIMATED")

    def test_streams_and_why_tell_why_a_number_is_missing(self):
        """§29.153: the summary says which judged stream was clean and which
        quality_why tokens dirtied the window, so a missing RTT or loss is
        explainable in the UI. Tokens are distinct, sorted and capped."""
        self.run_windows(1, "DIAGNOSTICS_ENABLED", rtt_samples="40.0",
                         quality_why="KERNEL_DROP:S1;LOWRATE_QUEUE_DROP")
        p = self.peer()
        self.assertEqual(p["streams"], {"S1": "INVALID", "S2": "INVALID", "S4": "GOOD"})
        self.assertEqual(p["why"], ["KERNEL_DROP:S1", "LOWRATE_QUEUE_DROP"])
        self.reset()
        self.run_windows(1, "DIAGNOSTICS_ENABLED", rtt_samples="40.0")
        p = self.peer()
        self.assertEqual(p["streams"], {"S1": "GOOD", "S2": "GOOD", "S4": "GOOD"})
        self.assertEqual(p["why"], [])
        self.reset()
        self.run_windows(1, "DIAGNOSTICS_ENABLED",
                         quality_why=";".join("T%02d" % i for i in range(20)))
        self.assertEqual(len(self.peer()["why"]), WHY_MAX)

    def test_run_window_reports_progress_between_its_stages(self):
        """§29.161: the engine's watchdog heartbeat rides on this hook; a window
        that progresses (evaluate → apply/correlate → recommend → summarize) must
        call it at least once per stage, and never before evaluate has run."""
        calls = []
        self.an.progress = lambda: calls.append(len(self.store.conn.execute(
            "SELECT 1 FROM diagnosis").fetchall()))
        self.run_windows(1, "DIAGNOSTICS_ENABLED", s4_expected=5000, s4_received=4800)
        self.assertGreaterEqual(len(calls), 4, calls)

    def test_recommendation_lookback_is_loaded_once_per_window_not_per_peer(self):
        """§29.161: _windows ran its 30-minute query once per peer (36 × on myserver,
        0.8 of the window's 1.4 s). Family guard: the number of peer_rows calls in a
        window does not grow with the number of peers."""
        def count_rows(n_peers):
            self.reset()
            pids = [self.store.peer_id("wg1udp", "p%d" % i, "fp%d" % i) for i in range(n_peers)]
            for i in range(6):
                ws = T0 + 300 * i
                for pid in pids:
                    for r in window_rows(pid, ws, rtt_samples="40.0"):
                        self.store.put_peer_minute(r)
                self.store.put_global_minute({"ts": ws, "quality": "GOOD",
                                              "egress_json": self.EGRESS_OK})
            calls = []
            real = self.an.diag.peer_rows
            self.an.diag.peer_rows = lambda a, b: (calls.append((a, b)), real(a, b))[1]
            self.t[0] = T0 + 300 * 5 + 310
            self.an.run_window(T0 + 300 * 5, Meta(self.t[0]), "RECOMMENDATIONS_ENABLED")
            self.an.diag.peer_rows = real
            return len(calls)
        one, many = count_rows(1), count_rows(5)
        self.assertEqual(one, many, "peer_rows calls grew with the peer count: %d → %d" % (one, many))
        self.assertLessEqual(many, 8)

    def test_history_sql_filter_equals_stream_ok_and_loads_no_rows(self):
        """§29.160 — family guard for the SQL rewrite of _history: for every token
        the engine can write (features._BAD, an 'S4:' gap, a foreign token, none)
        and every row quality, the SQL predicate selects exactly the minutes
        features.stream_ok accepts; and _history never calls peer_rows (the 24-hour
        row load that cost 91 MB and 3 s every five minutes on myserver)."""
        import itertools
        toks = sorted({t for v in features._BAD.values() for t in v}) + \
            ["S4:GAP:KERNEL_DROP", "FOO", ""]
        combos = [";".join(c) for n in (1, 2) for c in itertools.combinations(toks, n)] + [""]
        rows = []
        ts = T0
        for why in combos:
            for q in ("GOOD", "DEGRADED", "INVALID"):
                rows.append(mrow(self.pid, ts, quality=q, quality_why=why, rtt_samples="1.0",
                                 rtt_n=1))
                ts += 60
        for r in rows:
            self.store.put_peer_minute(r)
        c = self.store.conn
        for stream in ("S1", "S4"):
            want = {r["ts"] for r in rows if features.stream_ok(r, stream)}
            got = {t for (t,) in c.execute("SELECT ts FROM peer_minute WHERE " +
                                           Analysis._clean_sql(stream))}
            self.assertEqual(got, want, stream)
            self.assertTrue(want and want != {r["ts"] for r in rows}, stream)
        self.an.diag.peer_rows = lambda *a, **k: self.fail("_history must not load rows")
        h = self.an._history(ts, [self.pid])
        self.assertEqual(set(h[self.pid]), {"end", "rtt_ms", "loss"})

    def test_history_is_hourly_judged_like_the_summary(self):
        """§29.153: 24 hourly buckets ending at the closed window, oldest first.
        RTT only from S1-clean minutes with enough samples, loss only from
        S4-clean minutes with enough counters, None elsewhere — never a number
        the rules would not have judged."""
        lossy = dict(s4_expected=5000, s4_received=4800)
        # three windows two hours earlier (dirty S1), then three windows now
        self.run_windows(3, "DIAGNOSTICS_ENABLED", start=-24, rtt_samples="900.0",
                         quality_why="KERNEL_DROP:S1", **lossy)
        self.run_windows(3, "DIAGNOSTICS_ENABLED", rtt_samples="40.0", **lossy)
        h = self.peer()["history"]
        we = T0 + 900
        self.assertEqual(h["end"], we)
        self.assertEqual((len(h["rtt_ms"]), len(h["loss"])), (HISTORY_HOURS, HISTORY_HOURS))
        now_i = HISTORY_HOURS - 1
        old_i = int((T0 - 7200 - (we - HISTORY_HOURS * 3600)) // 3600)
        self.assertEqual(h["rtt_ms"][now_i], 40.0)
        self.assertEqual(h["loss"][now_i], 0.04)
        self.assertIsNone(h["rtt_ms"][old_i], "dirty S1 minutes give no RTT")
        self.assertEqual(h["loss"][old_i], 0.04, "S4 was clean there")
        for i in range(HISTORY_HOURS):
            if i not in (now_i, old_i):
                self.assertEqual((h["rtt_ms"][i], h["loss"][i]), (None, None), i)
        # below the rules' minimums the bucket abstains
        self.reset()
        m = rules.PARAMS["loss_n_min"] // 5 - 1
        rows = window_rows(self.pid, T0, s4_expected=m, s4_received=m - 1, rtt_samples="")
        rows[0]["rtt_samples"] = "10.0,20.0,30.0,40.0"
        for r in rows:
            self.store.put_peer_minute(r)
        self.store.put_global_minute({"ts": T0, "quality": "GOOD", "egress_json": self.EGRESS_OK})
        self.t[0] = T0 + 310
        self.an.run_window(T0, Meta(self.t[0]), "DIAGNOSTICS_ENABLED")
        h = self.peer()["history"]
        self.assertEqual((h["rtt_ms"][-1], h["loss"][-1]), (None, None))
        # and the snapshot carries it per label, JSON-clean
        snap = json.dumps(self.an.snapshot(self.an.diag.peer_names()))
        self.assertIn('"history"', snap)

    def test_quality_follows_open_live_diagnoses_only(self):
        lossy = dict(s4_expected=5000, s4_received=4800)
        self.run_windows(4, "OBSERVATION_ONLY", **lossy)
        self.assertIsNone(self.peer()["quality"])          # shadow is never "OK"
        self.reset()
        self.run_windows(4, "DIAGNOSTICS_ENABLED", **lossy)
        self.assertEqual(self.peer()["quality"], "HIGH")
        self.reset()
        self.run_windows(2, "DIAGNOSTICS_ENABLED")
        self.assertEqual(self.peer()["quality"], "OK")
        self.reset()
        self.run_windows(2, "DIAGNOSTICS_ENABLED", quality="INVALID")
        self.assertEqual(self.peer()["quality"], "INSUFFICIENT")

    def test_quality_is_always_the_worst_diagnosis_the_ui_lists(self):
        """Across mode switches (a SHADOW diagnosis is promoted to LIVE by the
        first live window, and clears only after CLEAR_AFTER) the per-peer
        quality never disagrees with the diagnoses snapshot() shows."""
        lossy = dict(s4_expected=5000, s4_received=4800)
        plan = [("OBSERVATION_ONLY", lossy)] * 4 + [("DIAGNOSTICS_ENABLED", {})] * 4 \
            + [("DIAGNOSTICS_ENABLED", lossy)] * 3 + [("OBSERVATION_ONLY", {})] * 2
        for i, (mode, kw) in enumerate(plan):
            self.run_windows(1, mode, start=i, **kw)
            snap = self.an.snapshot(self.an.diag.peer_names())
            mine = [d["confidence"] for d in snap["diagnoses"] if d.get("peer") == "alice"]
            q = self.peer()["quality"]
            with self.subTest(i=i, mode=mode):
                if mode == "OBSERVATION_ONLY":
                    self.assertIsNone(q)
                elif mine:
                    self.assertEqual(q, max(mine, key=conf.LEVELS.index))
                else:
                    self.assertEqual(q, "OK")

    def test_too_few_clean_minutes_withhold_numbers_that_do_exist(self):
        """Two clean minutes out of fifteen: the samples are there, but the
        stream is INVALID (features.MIN_VALID) — so the rule abstains, and the
        export must too, even though a median could be computed."""
        from nqmo.analysis import peer_summary
        rows = [mrow(1, T0 + 60 * i, quality_why="KERNEL_DROP:S1;S4_COUNTER_JUMP",
                     rtt_samples="40.0,41.0,42.0,43.0,44.0") for i in range(15)]
        for r in rows[:2]:
            r["quality_why"] = ""
        f = features.peer_features(rows)
        self.assertEqual((f["quality"]["S1"], f["quality"]["S4"]), ("INVALID", "INVALID"))
        self.assertEqual(len(f["rtt_samples"]), 10)
        self.assertGreaterEqual(f["loss_n"], rules.PARAMS["loss_n_min"])
        s = peer_summary(T0, f, f, [], [], "DIAGNOSTICS_ENABLED")
        self.assertEqual((s["rtt_n"], s["rtt_ms_med"], s["loss_n"], s["loss_point"]),
                         (0, None, 0, None))

    def test_open_but_unranked_is_never_ok(self):
        f = feats()
        for lv in (["INSUFFICIENT_EVIDENCE"], ["bogus"]):
            s = __import__("nqmo.analysis", fromlist=["x"]).peer_summary(
                T0, f, None, [], lv, "DIAGNOSTICS_ENABLED")
            self.assertEqual(s["quality"], "INSUFFICIENT", lv)

    def test_ambiguous_label_and_idle_peers_are_left_out(self):
        self.run_windows(1, "DIAGNOSTICS_ENABLED")
        twin = self.store.peer_id("wg1udp", "alice", "fp2")       # same name, new key
        for r in window_rows(twin, T0 + 300):
            self.store.put_peer_minute(r)
        self.feed(T0 + 300)
        self.t[0] = T0 + 610
        self.an.run_window(T0 + 300, Meta(self.t[0]), "DIAGNOSTICS_ENABLED")
        self.assertIsNone(self.peer())
        # a window in which alice sent nothing: she leaves the list, no stale row
        self.store.put_global_minute({"ts": T0 + 600, "quality": "GOOD"})
        self.t[0] = T0 + 910
        self.an.run_window(T0 + 600, Meta(self.t[0]), "DIAGNOSTICS_ENABLED")
        self.assertEqual(self.an.snapshot(self.an.diag.peer_names())["peers"], [])

    def test_state_file_carries_the_summaries(self):
        from nqmo import export
        self.run_windows(1, "DIAGNOSTICS_ENABLED")
        st = export.build_state(self.t[0], "DIAGNOSTICS_ENABLED", {}, {}, [], {},
                                analysis=self.an.snapshot(self.an.diag.peer_names()))
        self.assertEqual([(p["iface"], p["name"], p["window"]) for p in st["peers"]],
                         [("wg1udp", "alice", T0)])
        self.assertEqual(export.build_state(0, "OBSERVATION_ONLY", {}, {}, [], {})["peers"], [])

    def test_no_number_without_its_gate_over_a_grid(self):
        from nqmo.analysis import peer_summary
        rnd = random.Random(55)
        for i in range(400):
            kw = {"s4_expected": rnd.choice([0, 10, 199, 200, 201, 5000]),
                  "rtt_samples": ",".join("%.1f" % rnd.uniform(1, 500)
                                          for _ in range(rnd.choice([0, 1, 4, 5, 9]))),
                  "quality_why": rnd.choice(["", "KERNEL_DROP:S1", "S4_COUNTER_JUMP",
                                             "C3:DISABLED"]),
                  "quality": rnd.choice(["GOOD", "GOOD", "INVALID"])}
            kw["s4_received"] = max(0, kw["s4_expected"] - rnd.choice([0, 1, 30]))
            rows = window_rows(1, T0, **kw)
            f = features.peer_features(rows)
            rf = features.peer_features(rows) if i % 2 else None
            s = peer_summary(T0, f, rf, [{"target": "CLIENT_IFACE_MTU",
                                          "status": rnd.choice(rec_statuses())}],
                             [], rnd.choice(config.MODES))
            with self.subTest(i=i, kw=kw):
                if s["rtt_ms_med"] is not None:
                    self.assertGreaterEqual(s["rtt_n"], rules.PARAMS["rtt_min_samples"])
                    self.assertNotEqual(rf["quality"]["S1"], "INVALID")
                if s["loss_point"] is not None:
                    self.assertGreaterEqual(s["loss_n"], rules.PARAMS["loss_n_min"])
                    self.assertNotEqual(f["quality"]["S4"], "INVALID")
                    self.assertLessEqual(s["loss_lb"], s["loss_point"])
                    self.assertLessEqual(s["loss_point"], s["loss_ub"])
                if s["quality"] == "OK":
                    self.assertTrue(any(f["quality"][x] != "INVALID"
                                        for x in ("S1", "S2", "S4")))
                json.dumps(s, allow_nan=False)


def rec_statuses():
    from nqmo.analysis import MTU_STATUSES
    return list(MTU_STATUSES) + ["bogus"]


# ------------------------------------------------------------------ probe
def fake_runner(limit, local_error=False, icmp=True):
    """Simulated path: inner packets > limit are dropped; returns ping-like output."""
    def run(argv, timeout=10, allow_probe=False):
        assert allow_probe, "probe must pass allow_probe"
        runner.match(argv, allow_probe=True)
        size, count = int(argv[argv.index("-s") + 1]), int(argv[argv.index("-c") + 1])
        if local_error and size + 28 > 1392:
            return 2, "", "ping: local error: message too long, mtu=1392"
        rcv = count if (icmp and size + 28 <= limit) else 0
        return (0 if rcv else 1,
                "%d packets transmitted, %d received, x%% packet loss" % (count, rcv), "")
    return run


class NqmoProbeTests(unittest.TestCase):
    def mk(self, runner_fn, t_config=1392):
        q = queue.Queue()
        p = probe.ProbeRun(1, "pub", "10.66.0.5", t_config, 1392, "wg1udp",
                           lambda: 10, q, runner=runner_fn)
        p.run()
        return q.get_nowait()

    def test_threshold(self):
        r = self.mk(fake_runner(1340))
        self.assertEqual(r["verdict"], "THRESHOLD")
        self.assertLessEqual(r["s_star"] + 28, 1340)
        self.assertGreater(r["s_fail"] + 28, 1340)
        self.assertLessEqual(r["packets_sent"], probe.MAX_PACKETS)
        self.assertLessEqual(r["bytes_sent"], probe.MAX_BYTES)

    def test_full_path_and_no_icmp(self):
        self.assertEqual(self.mk(fake_runner(1500))["verdict"], "FULL_PATH_OK")
        self.assertEqual(self.mk(fake_runner(1500, icmp=False))["verdict"], "CLIENT_NO_ICMP")

    def test_local_error_is_not_a_threshold(self):
        r = self.mk(fake_runner(1500, local_error=True), t_config=1420)   # upper > iface
        self.assertNotEqual(r["verdict"], "THRESHOLD")
        r = self.mk(fake_runner(1500), t_config=1250)
        self.assertEqual(r["reason"], "RANGE_EMPTY")

    def test_parse_ping_local_errors(self):
        with self.assertRaises(probe.ProbeError):
            probe.parse_ping(2, "", "ping: sendmsg: Message too long")
        with self.assertRaises(probe.ProbeError):
            probe.parse_ping(1, "", "ping: socket: Operation not permitted")
        self.assertEqual(probe.parse_ping(1, "2 packets transmitted, 0 received", ""), (2, 0))


class NqmoProbeGateTests(unittest.TestCase):
    def test_only_probe_module_passes_allow_probe(self):
        for dp, dn, fn in os.walk(PKG):
            dn[:] = [d for d in dn if d != "__pycache__"]
            for f in fn:
                if not f.endswith(".py") or f in ("probe.py", "runner.py"):
                    continue
                tree = ast.parse(read(os.path.join(dp, f)))
                for node in ast.walk(tree):
                    if isinstance(node, ast.keyword) and node.arg == "allow_probe":
                        self.fail("%s passes allow_probe" % f)

    def test_ping_refused_without_flag(self):
        argv = ["ping", "-4", "-n", "-q", "-M", "do", "-s", "1300", "-c", "1", "-W", "1",
                "-I", "wg1udp", "10.66.0.5"]
        with self.assertRaises(runner.NotAllowed):
            runner.match(argv)
        runner.match(argv, allow_probe=True)

    def test_request_gates(self):
        d = tempfile.mkdtemp()
        try:
            st = storemod.Store(os.path.join(d, "n.db"))
            now = [T0]
            peers = {"pub": {"name": "alice", "enabled": True, "tunnel_ip": "10.66.0.5",
                             "latest_handshake": T0 - 10, "iface": "wg1udp", "c_mtu": None}}

            class Fake:
                def __init__(self, *a, **k):
                    self.run_id = a[0]

                def start(self):
                    pass

                def is_alive(self):
                    return True

            cfg = config.validate({"mode": "RECOMMENDATIONS_ENABLED", "active_probes": True})
            an = Analysis(st, cfg, clock=lambda: now[0], probe_cls=Fake)
            m = Meta(T0, peers=peers)
            get = lambda: m                                   # noqa: E731
            self.assertEqual(an.request_probe("alice", "a", "DIAGNOSTICS_ENABLED", get)["refused"],
                             "MODE_GATE")
            self.assertEqual(an.request_probe("bob", "a", "RECOMMENDATIONS_ENABLED", get)["refused"],
                             "NO_SUCH_PEER")
            self.assertTrue(an.request_probe("alice", "a", "RECOMMENDATIONS_ENABLED", get)["ok"])
            self.assertEqual(an.request_probe("alice", "a", "RECOMMENDATIONS_ENABLED", get)["refused"],
                             "BUSY")
            an.probe_running = None
            st.conn.execute("INSERT INTO probe_run(ts,peer_id,requested_by,sizes_json,"
                            "results_json,packets_sent,bytes_sent,verdict) VALUES(?,?,?,?,?,?,?,?)",
                            (T0, st.peer_id("wg1udp", "alice",
                                            __import__("nqmo.aggregate", fromlist=["x"]).key_fp("pub")),
                             "a", "[]", "{}", 0, 0, "X"))
            self.assertEqual(an.request_probe("alice", "a", "RECOMMENDATIONS_ENABLED", get)["refused"],
                             "RATE")
            cfg2 = config.validate({"mode": "RECOMMENDATIONS_ENABLED"})
            an2 = Analysis(st, cfg2, clock=lambda: now[0], probe_cls=Fake)
            self.assertEqual(an2.request_probe("alice", "a", "RECOMMENDATIONS_ENABLED", get)["refused"],
                             "FLAG_GATE")
            peers["pub"]["latest_handshake"] = T0 - 500
            an3 = Analysis(st, cfg, clock=lambda: now[0] + 7200, probe_cls=Fake)
            m.generated_at = T0 + 7200
            self.assertEqual(an3.request_probe("alice", "a", "RECOMMENDATIONS_ENABLED", get)["refused"],
                             "STALE_HS")
            st.close()
        finally:
            shutil.rmtree(d)


# ------------------------------------------------------------------ ASN
class NqmoAsnTests(unittest.TestCase):
    def test_load_and_lookup(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "ip2asn-v4.tsv")
            with open(p, "w") as f:
                f.write("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
                        "5.0.0.0\t5.0.255.255\t0\tNone\tNot routed\n"
                        "10.0.0.0\t10.255.255.255\t65000\tZZ\tPRIVATE-IN-FILE\n"
                        "100.0.0.0\t100.0.0.255\t64500\tIR\tEXAMPLE\n")
            db = asn.load_dir(d)
            self.assertEqual(db.lookup("1.0.0.7"), (13335, "CLOUDFLARENET", "US"))
            self.assertIsNone(db.lookup("5.0.1.1"))           # not routed
            self.assertIsNone(db.lookup("10.1.2.3"))          # private never gets an ASN
            self.assertIsNone(db.lookup("9.9.9.9"))           # gap
            self.assertEqual(db.size, 4)
            with open(p, "w") as f:
                f.write("2.0.0.0\t2.0.0.255\t1\tUS\tA\n1.0.0.0\t1.0.0.255\t2\tUS\tB\n")
            with self.assertRaises(asn.AsnError):
                asn.load(p)
        finally:
            shutil.rmtree(d)

    def test_absent_dir_means_prefix_only(self):
        self.assertIsNone(asn.load_dir("/nonexistent/nqmo-asn"))


if __name__ == "__main__":
    unittest.main()


class NqmoEgressUnknownTests(unittest.TestCase):
    """C5 UNKNOWN (no egress data) caps the MTU classes at LOW — a slow
    egress must never be mistaken for an MTU problem."""

    def test_no_egress_data_caps_mtu(self):
        d = tempfile.mkdtemp()
        try:
            st = storemod.Store(os.path.join(d, "n.db"))
            t = [T0]
            an = Analysis(st, config.validate({}), clock=lambda: t[0])
            pid = st.peer_id("wg1udp", "alice", "fp")
            for i in range(4):
                ws = T0 + 300 * i
                for r in window_rows(pid, ws, frag_first=5, frag_first_len_min=1420,
                                     frag_first_len_max=1420, l_max_unfrag=1400):
                    st.put_peer_minute(r)
                st.put_global_minute({"ts": ws, "quality": "GOOD"})     # no egress_json
                t[0] = ws + 310
                an.run_window(ws, Meta(t[0]), "DIAGNOSTICS_ENABLED")
            lv = st.conn.execute("SELECT confidence FROM diagnosis WHERE "
                                 "class='SUSPECTED_MTU_PROBLEM'").fetchone()
            self.assertEqual(lv, ("LOW",))
            st.close()
        finally:
            shutil.rmtree(d)


class NqmoEngineAnalysisTests(unittest.TestCase):
    def test_window_boundary_runs_analysis_and_exports(self):
        from nqmo import engine
        d = tempfile.mkdtemp()
        try:
            cfg = config.validate({"paths": {k: os.path.join(d, k)
                                             for k in config.DEFAULTS["paths"]}})
            t = [T0 + 10.0]
            e = engine.Engine(cfg, clock=lambda: t[0])
            t[0] = T0 + 300 + 3.0                     # minutes T0..T0+240 closed
            e.step()
            e.task_export()
            with open(cfg["paths"]["state"], encoding="utf-8") as f:
                st = json.load(f)
            for k in ("diagnoses", "notify_outbox", "recommendations", "advisories",
                      "correlations", "promotion"):
                self.assertIn(k, st)
            self.assertEqual(st["last_window"], T0)
            # /proc is absent off-Linux (kernel/selfmon errors are expected there);
            # the analysis path itself must be error-free
            self.assertEqual([x for x in e.errors
                              if x["where"] in ("analysis", "snapshot", "store", "export")], [])
            e.store.close()
        finally:
            shutil.rmtree(d)


class NqmoReviewRound3Tests(unittest.TestCase):
    """Regression guards for the six bugs reproduced in review round 3."""

    def test_late_events_land_in_an_open_minute(self):
        from tests.test_nqmo import FakeStore, agg_with_meta
        a = agg_with_meta()
        a.on_s2(40.0, {"src": "198.51.100.7", "dst": "203.0.113.1", "id": 6, "F": 1420,
                       "O": 1472, "sport": 51000, "payload": 1400})
        a.expire(62.5)
        a.flush(0, FakeStore(), now=62.5, meta_stale_s=10 ** 9)      # minute 0 written
        a.expire(75.0)                                                 # TTL hits after flush
        self.assertNotIn(0, a.minutes)                                 # nothing orphaned
        fs = FakeStore()
        a.flush(60, fs, now=125, meta_stale_s=10 ** 9)
        self.assertEqual(fs.rows[0]["frag_incomplete"], 1)             # counted, not lost
        a.taint(10.0, "LATE")
        self.assertNotIn(0, a.mwhy)

    def _an(self):
        t = NqmoAnalysisTests()
        t.setUp()
        self.addCleanup(t.tearDown)
        return t

    def test_cooldown_suppressed_episode_gets_no_cleared_message(self):
        t = self._an()
        lossy = dict(s4_expected=5000, s4_received=4800)
        M = "DIAGNOSTICS_ENABLED"
        t.run_windows(3, M, **lossy)
        t.run_windows(3, M, start=3)
        t.run_windows(3, M, start=6, **lossy)          # reopens inside the 6 h cooldown
        t.run_windows(3, M, start=9)
        cleared = [x for x in t.outbox() if x[1] == "nqmo.alert.cleared"]
        self.assertEqual(len(cleared), 1)               # only the announced episode

    def test_non_adjacent_windows_do_not_open(self):
        t = self._an()
        lossy = dict(s4_expected=5000, s4_received=4800)
        t.run_windows(1, "DIAGNOSTICS_ENABLED", **lossy)
        t.run_windows(1, "DIAGNOSTICS_ENABLED", start=200, **lossy)
        self.assertEqual(t.store.conn.execute("SELECT COUNT(*) FROM diagnosis").fetchone(), (0,))

    def test_idle_peer_diagnosis_goes_stale(self):
        t = self._an()
        t.run_windows(3, "DIAGNOSTICS_ENABLED", s4_expected=5000, s4_received=4800)
        for i in range(3, 3 + conf.STALE_AFTER + 1):
            ws = T0 + 300 * i
            t.store.put_global_minute({"ts": ws, "quality": "GOOD", "egress_json": t.EGRESS_OK})
            t.t[0] = ws + 310
            t.an.run_window(ws, Meta(t.t[0]), "DIAGNOSTICS_ENABLED")
        self.assertEqual(t.store.conn.execute(
            "SELECT state FROM diagnosis WHERE class='PACKET_LOSS'").fetchone(), ("CLEARED",))

    def test_quiet_window_or_stray_fragment_never_sets_the_number(self):
        fs = [feats(l_max_unfrag=1380, df_ratio=1.0, s4_received=4800) for _ in range(5)] + \
             [feats(l_max_unfrag=180, df_ratio=1.0)]
        r = rec.recommend(fs, {"SUSPECTED_PMTU_BLACKHOLE": (True, "MEDIUM")}, 1392,
                          "RECOMMENDATIONS_ENABLED")[0]
        self.assertEqual(r["suggested_value"], 1320)                 # not 120
        fs = [feats()] * 5 + [feats(frag_first=1, frag_first_len_min=600,
                                    frag_first_len_max=600)]
        r = rec.recommend(fs, {"SUSPECTED_MTU_PROBLEM": (True, "LOW")}, 1392,
                          "RECOMMENDATIONS_ENABLED")[0]
        self.assertIsNone(r["suggested_value"])                       # not 540

    def test_one_minute_window_is_never_good(self):
        f = features.peer_features([mrow(1, T0)])
        self.assertTrue(all(q == "DEGRADED" for q in f["quality"].values()), f["quality"])


class NqmoReviewRound4Tests(unittest.TestCase):
    """Regression guards for the review-round-4 reproducers (r1…r8)."""
    LOSSY = dict(s4_expected=5000, s4_received=4800)
    M = "DIAGNOSTICS_ENABLED"
    R = "RECOMMENDATIONS_ENABLED"

    def _an(self):
        t = NqmoAnalysisTests()
        t.setUp()
        self.addCleanup(t.tearDown)
        return t

    @staticmethod
    def q(t, sql, *a):
        return t.store.conn.execute(sql, a).fetchall()

    def test_r1_suppressed_escalation_keeps_episode_announced(self):
        t = self._an()
        t.run_windows(2, self.M, **self.LOSSY)
        for i in range(6):                                   # fill the hourly cap
            t.an.diag._outbox(t.t[0], "MEDIUM", "nqmo:PEER:o%d:X" % i, "nqmo.alert.open", {})
        t.run_windows(2, self.M, start=2, **self.LOSSY)
        t.run_windows(3, self.M, start=4)
        mine = self.q(t, "SELECT severity, text_key FROM notify_outbox WHERE key LIKE '%PACKET_LOSS'")
        self.assertIn(("INFO", "nqmo.alert.cleared"), mine)
        self.assertEqual(len([m for m in mine if m[1] == "nqmo.alert.open"]), 1)

    def test_r2_sparse_healthy_peer_clears(self):
        t = self._an()
        t.run_windows(3, self.M, **self.LOSSY)
        for i in range(3, 15):
            if i % 2:
                t.run_windows(1, self.M, start=i)
            else:
                t.run_windows(1, self.M, start=i, s4_expected=150, s4_received=150,
                              s4_pkts=150, rx_bytes=10000, tx_bytes=10000)
        self.assertEqual(self.q(t, "SELECT state FROM diagnosis WHERE class='PACKET_LOSS'"),
                         [("CLEARED",)])

    def test_r3_recommendations_are_not_reinserted_every_window(self):
        t = self._an()
        t.store.conn.execute(
            "INSERT INTO probe_run(ts,peer_id,requested_by,sizes_json,results_json,"
            "packets_sent,bytes_sent,verdict,aborted_reason) VALUES(?,?,?,?,?,?,?,?,?)",
            (T0 - 10, t.pid, "op", "[]", json.dumps({"verdict": "THRESHOLD", "s_star": 1308,
                                                     "t_config": 1392}), 20, 20000,
             "THRESHOLD", None))
        t.run_windows(4, self.R)
        n4 = self.q(t, "SELECT COUNT(*) FROM recommendation")[0][0]
        t.run_windows(20, self.R, start=4)
        self.assertLessEqual(self.q(t, "SELECT COUNT(*) FROM recommendation")[0][0] - n4, 1)

    def test_r4_followup_verified_persists(self):
        t = self._an()
        frag = dict(frag_first=5, frag_first_len_min=1420, frag_first_len_max=1420,
                    l_max_unfrag=1400)
        t.run_windows(4, self.R, **frag)
        new = dict(t_config=1360, l_max_unfrag=1420, ctx_key="198.51.100.0/24|1360|0|1392")
        t.run_windows(8, self.R, start=4, **new)
        ver = self.q(t, "SELECT superseded_by FROM recommendation WHERE status='VERIFIED' "
                        "AND target='CLIENT_IFACE_MTU' ORDER BY id DESC LIMIT 1")
        self.assertEqual(ver, [(None,)])
        live = [x["status"] for x in t.an.last["recommendations"][t.pid]
                if x["target"] == "CLIENT_IFACE_MTU" and x["direction_scope"] == "UPSTREAM"]
        self.assertEqual(live, ["VERIFIED"])

    def test_r5_counter_evidence_is_not_paged(self):
        t = self._an()
        for i in range(4):
            ws = T0 + 300 * i
            for r in window_rows(t.pid, ws, **self.LOSSY):
                t.store.put_peer_minute(r)
            t.store.put_global_minute({"ts": ws, "quality": "GOOD", "egress_json": t.EGRESS_OK,
                                       "softnet_dropped": 50})
            t.t[0] = ws + 310
            t.an.run_window(ws, Meta(t.t[0]), self.M)
        self.assertEqual(self.q(t, "SELECT * FROM notify_outbox WHERE key LIKE '%PACKET_LOSS'"), [])

    def test_r6_class10_needs_twenty_fragments_for_high(self):
        t = self._an()
        for i in range(3):
            ws = T0 + 300 * i
            for j, r in enumerate(window_rows(t.pid, ws, l_max_unfrag=1400)):
                if j < 4:
                    r.update(frag_first=1, frag_first_len_min=1380, frag_first_len_max=1380)
                t.store.put_peer_minute(r)
            t.store.put_global_minute({"ts": ws, "quality": "GOOD", "egress_json": t.EGRESS_OK})
            t.t[0] = ws + 310
            t.an.run_window(ws, Meta(t.t[0]), self.R)
        d = self.q(t, "SELECT confidence FROM diagnosis WHERE class='SUSPECTED_MTU_PROBLEM'")
        self.assertNotIn(("HIGH",), d)
        est = [x for x in t.an.last["recommendations"][t.pid] if x["status"] == "ESTIMATED"]
        self.assertEqual(est, [])

    def test_r8_probe_start_and_abort_gates_agree(self):
        res = queue.Queue()
        p = probe.ProbeRun(1, "pub", "10.0.0.2", 1392, 1392, "wg1udp", lambda: 90.0, res,
                           runner=lambda *a, **k: (0, "2 packets transmitted, 2 received", ""))
        p.run()
        self.assertNotEqual(res.get_nowait()["verdict"], "ABORTED")

    def test_probe_result_carries_its_own_identity(self):
        res = queue.Queue()
        p = probe.ProbeRun(7, "pub", "10.0.0.2", 1392, 1392, "wg1udp", lambda: 10.0, res,
                           runner=lambda *a, **k: (0, "2 packets transmitted, 2 received", ""))
        p.peer_id, p.requested_by = 42, "admin"
        p.run()
        r = res.get_nowait()
        self.assertEqual((r["peer_id"], r["requested_by"]), (42, "admin"))

    def test_shadow_diagnoses_stay_out_of_the_ui(self):
        t = self._an()
        t.run_windows(3, "OBSERVATION_ONLY", **self.LOSSY)
        self.assertEqual(t.an.snapshot(t.an.diag.peer_names())["diagnoses"], [])

    def test_route_prohibit_is_an_anomaly(self):
        from nqmo import engine

        class M:
            endpoint_ips = {"198.51.100.7", "198.51.100.8"}
            wg1udp_local_ip = None
            wg1udp_fwmark = None

        def fake(argv, timeout=5):
            if argv[4] == "198.51.100.7":
                return 2, "", "RTNETLINK answers: Permission denied"
            return 0, '[{"dst":"198.51.100.8","dev":"eth0"}]', ""
        self.assertEqual(engine.route_status(M, "eth0", runner=fake),
                         {"198.51.100.7": False, "198.51.100.8": True})


class NqmoLabRoundTests(unittest.TestCase):
    """Findings of the OrbStack Linux lab (28 Oct 2026)."""

    @staticmethod
    def gmin(**kw):
        r = {"ts": T0, "quality": "GOOD", "softnet_dropped": 0, "eth0_rx_missed_fifo": 0,
             "udp_rcvbuf_err": 0, "hs_cookie_out": 0, "frag_creates": 0,
             "reasm_fails": 0, "reasm_timeout": 0, "conntrack_pct": 0, "frag_mem_pct": 0}
        r.update(kw)
        return r

    def test_reassembly_saturation_is_a_server_cause(self):
        # lab: ReasmFails 5639 / ReasmTimeout 3247 per minute, FRAG memory at 100%
        g = features.global_features([self.gmin(ts=T0 + 60 * i, reasm_fails=5639,
                                                reasm_timeout=3247, frag_mem_pct=100.05)
                                      for i in range(5)])
        o = rules.server_resource(g)
        self.assertIs(o.positive, True)
        self.assertEqual({e["metric"] for e in o.evidence},
                         {"reasm_drops_without_queue", "reassembly_memory_pct"})
        self.assertEqual(g["reasm_drops"], 5 * (5639 - 3247))

    def test_reassembly_timeouts_alone_are_a_path_not_the_server(self):
        # family: fragments that never complete because a PEER's path drops
        # tails time out (ReasmFails == ReasmTimeout) — class 11a, not class 1
        g = features.global_features([self.gmin(ts=T0 + 60 * i, reasm_fails=3000,
                                                reasm_timeout=3000, frag_mem_pct=40.0)
                                      for i in range(5)])
        self.assertIs(rules.server_resource(g).positive, False)

    def test_each_reassembly_signal_alone_is_enough(self):
        drops = features.global_features([self.gmin(reasm_fails=12, reasm_timeout=1)])
        mem = features.global_features([self.gmin(frag_mem_pct=95.0)])
        quiet = features.global_features([self.gmin(reasm_fails=9, reasm_timeout=0,
                                                    frag_mem_pct=89.9)])
        self.assertIs(rules.server_resource(drops).positive, True)
        self.assertIs(rules.server_resource(mem).positive, True)
        self.assertIs(rules.server_resource(quiet).positive, False)

    def test_minutes_without_both_counters_never_invent_drops(self):
        g = features.global_features([self.gmin(reasm_fails=500, reasm_timeout=None)])
        self.assertEqual(g["reasm_drops"], 0)

    # c3 in the lab, minute by minute: counters judged in batches (11.5k / 0),
    # ~5 770 data packets and ~5 640 never-completing first fragments a minute
    C3 = [dict(s4_expected=e, s4_received=e, s4_pkts=5770, frag_first=5650,
               frag_incomplete=5640, frag_first_len_min=1396, frag_first_len_max=1396,
               frag_orig_len=1452, l_max_unfrag=188) for e in (11500, 0, 11500, 0, 11500)]

    def c3_feats(self):
        return features.peer_features([mrow(3, T0 + 60 * i, **kw)
                                       for i, kw in enumerate(self.C3)])

    def test_effective_loss_of_a_fragment_blackhole_is_near_total(self):
        # truth: every large datagram was lost (≈98% of data packets); the old
        # formula (k = lost + inc, n = expected + inc) reported 45%
        f = self.c3_feats()
        self.assertGreater(f["loss_k"] / f["loss_n"], 0.97)
        self.assertLessEqual(f["loss_k"], f["loss_n"])
        self.assertEqual(f["s4_loss_point"], 0.0)

    def test_effective_loss_is_stable_across_judging_batches(self):
        # family: the same traffic judged in 2 or 3 batches per window must
        # give the same rate (mixing clocks made it swing)
        a = self.c3_feats()
        rows = [mrow(3, T0 + 60 * i, **kw) for i, kw in
                enumerate(self.C3[1:] + [dict(self.C3[1])])]          # 11.5k × 2
        b = features.peer_features(rows)
        self.assertAlmostEqual(a["loss_k"] / a["loss_n"], b["loss_k"] / b["loss_n"], places=2)

    def test_incomplete_fragments_are_not_their_own_counter_evidence(self):
        f = self.c3_feats()
        o = rules.blackhole_frag(f["frag_first"], f["frag_incomplete"], f["s4_loss_point"],
                                 f["quality"]["S2"], 2)
        self.assertIs(o.positive, True)
        self.assertEqual(o.counter, [])

    def test_counter_loss_that_can_explain_the_ratio_is_still_counter_evidence(self):
        # 40% independent loss leaves a 2-fragment datagram incomplete 40% of
        # the time: a 60% ratio is within twice that
        o = rules.blackhole_frag(100, 60, 0.40, "GOOD", 2)
        self.assertEqual(len(o.counter), 1)
        # …but 6% loss cannot explain a 99.8% ratio
        self.assertEqual(rules.blackhole_frag(100, 99, 0.06, "GOOD", 2).counter, [])
        # more fragments per datagram ⇒ more of them can be hit
        self.assertEqual(len(rules.blackhole_frag(100, 70, 0.20, "GOOD", 5).counter), 1)

    # ---- the manual probe and server-side reassembly drops (lab, 28 Oct) ------
    # c2 (healthy path) failed at 1316 only while c3's fragments filled the
    # server's reassembly memory; the probe called that a path boundary.
    def _probe(self, limit, drops_seq):
        q = queue.Queue()
        it = iter(drops_seq)
        p = probe.ProbeRun(1, "pub", "10.66.0.12", 1392, 1392, "wg1udp", lambda: 10, q,
                           runner=fake_runner(limit), reasm_drops=lambda: next(it))
        p.run()
        return q.get_nowait()

    def test_server_reasm_drops_void_a_probe_threshold(self):
        r = self._probe(1340, [1000, 1001])
        self.assertEqual((r["verdict"], r["reason"]), ("INCONCLUSIVE", "SERVER_REASM_DROPS"))
        self.assertEqual(r["server_reasm_drops"], 1)

    def test_a_clean_run_keeps_its_threshold(self):
        r = self._probe(1340, [1000, 1000])
        self.assertEqual((r["verdict"], r["server_reasm_drops"]), ("THRESHOLD", 0))

    def test_drops_never_change_a_full_path_verdict(self):
        # every size was answered: whatever the server dropped, it was not these
        self.assertEqual(self._probe(1500, [0, 50])["verdict"], "FULL_PATH_OK")

    def test_unreadable_counters_are_recorded_not_invented(self):
        for seq in ([None, None], [None, 5], [5, None]):
            r = self._probe(1340, seq)
            self.assertEqual(r["verdict"], "THRESHOLD")
            self.assertIsNone(r["server_reasm_drops"])

    def test_unmeasured_probe_is_never_estimated(self):
        for drops in (None, "missing"):
            pr = {"verdict": "THRESHOLD", "s_star": 1300, "t_config": 1392}
            if drops != "missing":
                pr["server_reasm_drops"] = drops
            r = rec.recommend(W(l_max_unfrag=1300), {}, 1392, "RECOMMENDATIONS_ENABLED",
                              probe=pr)
            r = [x for x in r if x["direction_scope"] == "ROUNDTRIP"][0]
            self.assertEqual(r["status"], "CANDIDATE_FOR_TESTING")
            self.assertTrue(any("not measured" in x for x in r["limitations"]))

    def test_inconclusive_probe_never_recommends(self):
        pr = {"verdict": "INCONCLUSIVE", "reason": "SERVER_REASM_DROPS", "s_ok": 1300,
              "s_fail": 1316, "t_config": 1392, "server_reasm_drops": 3}
        r = rec.recommend(W(l_max_unfrag=1300), {}, 1392, "RECOMMENDATIONS_ENABLED", probe=pr)
        self.assertEqual([x for x in r if x["direction_scope"] == "ROUNDTRIP"], [])

    def test_reasm_drops_reader_excludes_timeouts(self):
        from nqmo.collect import kernel
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "proc/net"))
            with open(os.path.join(d, "proc/net/snmp"), "w") as f:
                f.write("Ip: Forwarding ReasmTimeout ReasmReqds ReasmOKs ReasmFails\n"
                        "Ip: 1 40553 158000000 79000000 41383\n")
            self.assertEqual(kernel.read_reasm_drops(d), 830)
            os.remove(os.path.join(d, "proc/net/snmp"))
            self.assertIsNone(kernel.read_reasm_drops(d))
        finally:
            shutil.rmtree(d)

    def test_engine_wires_the_reasm_reader_into_the_probe(self):
        src = read(os.path.join(PKG, "engine.py"))
        self.assertIn("reasm_drops=lambda: kernel.read_reasm_drops(root)", src)
        an = read(os.path.join(PKG, "analysis.py"))
        self.assertIn("reasm_drops=self.reasm_drops", an)
        self.assertIn('"server_reasm_drops"', an)       # persisted in probe_run

    # ---- baseline cold start (lab, 28 Oct) -----------------------------------
    # "not yet" was cached for the full 60–115 min TTL, so c5 would have stayed
    # NO_BASELINE ~85 min after its data sufficed.
    def _baseline_store(self, minutes, now):
        from nqmo import diagnose as dgm
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        st = storemod.Store(os.path.join(d, "n.db"))
        self.addCleanup(st.close)
        pid = st.peer_id("wg1udp", "c5", "fp5")
        t = [now]
        dg_ = dgm.Diagnoser(st, lambda: t[0])

        def add(first, n):
            for i in range(first, first + n):
                st.put_peer_minute(mrow(pid, now - dgm.BASELINE_GUARD - 60 * (i + 1),
                                        rtt_samples="40.0,42.0,44.0"))
        add(0, minutes)
        return dgm, dg_, pid, t, add

    def test_not_yet_baseline_is_asked_again_next_window(self):
        dgm, dg_, pid, t, add = self._baseline_store(100, T0 + 86400)
        self.assertIsNone(dg_.baseline(pid, CTX, t[0]))
        add(100, 30)                                         # now 130 ≥ 120
        t[0] += dgm.WINDOW
        b = dg_.baseline(pid, CTX, t[0])
        self.assertIsNotNone(b, "a 'not yet' must not outlive one window")
        self.assertGreaterEqual(b["minutes"], dgm.BASELINE_MIN_MINUTES)

    def test_a_real_baseline_still_keeps_its_ttl(self):
        dgm, dg_, pid, t, add = self._baseline_store(130, T0 + 86400)
        b1 = dg_.baseline(pid, CTX, t[0])
        add(130, 50)
        t[0] += dgm.WINDOW
        self.assertEqual(dg_.baseline(pid, CTX, t[0])["minutes"], b1["minutes"])   # cached
        t[0] += dgm.BASELINE_TTL + 12 * dgm.WINDOW
        self.assertGreater(dg_.baseline(pid, CTX, t[0])["minutes"], b1["minutes"])

    # ---- a diagnosis spans the window it was judged on (lab, 29 Oct) -----------
    # congestion is judged on 15-minute windows but was stored with the last
    # 5-minute slot: its 15-minute median sat on an 11:10–11:15 span.
    def test_stored_window_is_the_judged_window_for_every_class(self):
        from nqmo import diagnose as dgm
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        st = storemod.Store(os.path.join(d, "n.db"))
        self.addCleanup(st.close)
        dg_ = dgm.Diagnoser(st, lambda: 0)
        ws0 = 900 * 2000 - dgm.WINDOW          # (ws + WINDOW) % RTT_WINDOW == 0
        for cls in sorted(rules.ALT):
            step = dgm.span(cls)
            last = None
            for i in range(conf.OPEN_AFTER):
                last = ws0 + step * i
                o = rules.Outcome(cls, True, rules.DIRECT, [], subject="p-" + cls)
                dg_._apply_one(o, last, "SHADOW", False, {}, last + dgm.WINDOW)
            row = st.conn.execute("SELECT window_start, window_end FROM diagnosis "
                                  "WHERE class=?", (cls,)).fetchone()
            self.assertIsNotNone(row, cls)
            self.assertEqual(row[1], last + dgm.WINDOW, cls)
            self.assertEqual(row[1] - row[0], step, cls)
        self.assertEqual(dgm.span("NETWORK_CONGESTION"), dgm.RTT_WINDOW)

    # ---- one engine per database (lab, 28 Oct) ---------------------------------
    def test_second_engine_on_the_same_db_is_refused(self):
        from nqmo import __main__ as m
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "nqmo.db.lock")
        first = m.single_instance(path)
        self.assertIsNotNone(first)
        self.assertIsNone(m.single_instance(path))         # same DB: refused
        self.assertIsNotNone(m.single_instance(path + "2"))  # another DB: fine
        os.close(first)                                    # holder gone ⇒ lock free
        again = m.single_instance(path)
        self.assertIsNotNone(again)
        os.close(again)

    def test_run_takes_the_lock_before_building_the_engine(self):
        src = read(os.path.join(PKG, "__main__.py"))
        body = src[src.index("def main("):src.index("def single_instance(")]
        self.assertLess(body.index("single_instance("), body.index("Engine(cfg"))
        self.assertIn('cfg["paths"]["db"]', body[:body.index("Engine(cfg")])

    def test_one_cause_one_diagnosis_for_fragment_blackholes(self):
        # family (round 4 F5, now for 11a): the incomplete fragments raise
        # SUSPECTED_PMTU_BLACKHOLE, not also PACKET_LOSS
        f = self.c3_feats()
        self.assertIs(rules.packet_loss(f, None, False, False, True).positive, False)
        self.assertIs(rules.packet_loss(f, None, False, False, False).positive, True)
        # a peer with BOTH a blackhole and real counter loss keeps class 8
        rows = [mrow(3, T0 + 60 * i, **dict(kw, s4_received=int(kw["s4_expected"] * 0.95)))
                for i, kw in enumerate(self.C3)]
        g = features.peer_features(rows)
        self.assertIs(rules.packet_loss(g, None, False, False, True).positive, True)

    def test_frag_mem_gauge_parses_sockstat(self):
        from nqmo.collect import kernel
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "proc/net"))
            os.makedirs(os.path.join(d, "proc/sys/net/ipv4"))
            with open(os.path.join(d, "proc/net/sockstat"), "w") as f:
                f.write("sockets: used 5\nUDP: inuse 3 mem 1\nFRAG: inuse 1676 memory 4196704\n")
            with open(os.path.join(d, "proc/sys/net/ipv4/ipfrag_high_thresh"), "w") as f:
                f.write("4194304\n")
            self.assertEqual(kernel.read_frag_mem_pct(d), 100.06)
            os.remove(os.path.join(d, "proc/sys/net/ipv4/ipfrag_high_thresh"))
            self.assertIsNone(kernel.read_frag_mem_pct(d))
        finally:
            shutil.rmtree(d)

    def test_missing_interface_is_refused_where_sysfs_exists(self):
        # the existence check is part of the allowlist on the server
        with self.assertRaises(runner.NotAllowed):
            runner.match(["tc", "-s", "-j", "qdisc", "show", "dev", "nosuchif0"])
        runner.match(["tc", "-s", "-j", "qdisc", "show", "dev", "wg1udp"])

    def test_missing_interface_never_aborts_collection(self):
        # family: every engine caller of the allowlist treats NotAllowed as
        # "no data" — htb on wg1udp without its ifb must still return the
        # upload-side stats, and the minute's route checks must still run
        from nqmo import engine
        saved = engine.run_ro
        htb = '[{"kind":"htb","handle":"1:"}]'

        def fake(argv, timeout=10):
            runner.match(argv)                    # raises for the missing ifb
            return 0, (htb if argv[3] == "qdisc" else "[]"), ""
        try:
            engine.run_ro = fake
            tc = engine.TcCollector("wg1udp")
            tc.ifb = "nosuchifb0"
            self.assertEqual(tc.sample(), {})
        finally:
            engine.run_ro = saved

        class M:
            endpoint_ips = {"198.51.100.7"}
            wg1udp_local_ip = None
            wg1udp_fwmark = None

        def refusing(argv, timeout=5):
            raise runner.NotAllowed("x")
        self.assertEqual(engine.route_status(M, "eth0", runner=refusing), {})

    def test_every_run_ro_call_in_engine_is_guarded(self):
        # structural guard: a new direct call must not escape NotAllowed
        src = read(os.path.join(PKG, "engine.py"))
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) in ("run_ro", "runner"):
                guarded = any(isinstance(t, ast.Try) and any(
                    getattr(h.type, "id", None) == "NotAllowed" for h in t.handlers)
                    and node in list(ast.walk(t)) for t in ast.walk(tree))
                self.assertTrue(guarded, "unguarded allowlist call at line %d" % node.lineno)
