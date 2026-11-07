"""WG-NQMO PHASE 4 — the panel side of the contract, tested against the engine.

The engine (nqmo/) rejects a whole meta document over one bad field, so the
panel's export is checked here with the engine's own parser, never with a copy
of its rules. Private for the same reason as tests/test_nqmo*.py: without the
nqmo package these tests cannot import.
"""
import ast
import base64
import grp
import json
import os
import random
import re
import shutil
import stat
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

import nqmo  # noqa: E402
from nqmo import analysis as nanalysis  # noqa: E402
from nqmo import config as nconfig  # noqa: E402
from nqmo import diagnose as ndiag  # noqa: E402
from nqmo import export as nexport  # noqa: E402
from nqmo import rules  # noqa: E402
from nqmo.collect import meta as nmeta  # noqa: E402
from tests import test_wg_panel as twp  # noqa: E402  (a module: its TestCases are not re-collected)

RNG = random.Random(4)


def pubkey():
    return base64.b64encode(bytes(RNG.getrandbits(8) for _ in range(32))).decode()


K_OK, K_OFF, K_V6, K_IDLE, K_DUP = (pubkey() for _ in range(5))
PSK, PRIV = pubkey(), pubkey()
LONG = "n" * 65
CONF = """[Interface]
PrivateKey = {priv}
Address = 192.168.188.1/32
ListenPort = 53953
MTU=1392

#!!!alice
[Peer]
PublicKey = {ok}
PresharedKey = {psk}
AllowedIPs = 192.168.188.20/32,149.154.166.110
#!!!bob
#[Peer]
#PublicKey = {off}
#AllowedIPs = 192.168.188.21/32
#!!!carol
[Peer]
PublicKey = {v6}
AllowedIPs = 10.0.0.0/24
#!!!dave
[Peer]
PublicKey = {idle}
AllowedIPs = 192.168.188.23/32
#!!!fixture
[Peer]
PublicKey = PUB_USER02_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=
AllowedIPs = 192.168.188.24/32
#!!!{long}
[Peer]
PublicKey = {k1}
AllowedIPs = 192.168.188.25/32
#!!!{b64name}
[Peer]
PublicKey = {k2}
AllowedIPs = 192.168.188.26/32
#!!!twin
[Peer]
PublicKey = {ok}
AllowedIPs = 192.168.188.27/32
""".format(priv=PRIV, ok=K_OK, psk=PSK, off=K_OFF, v6=K_V6, idle=K_IDLE, long=LONG,
           k1=pubkey(), b64name=pubkey(), k2=pubkey())
NOW = 1_800_000_000.0


def live(pub, hs, rx, tx, ep, iface="wgtest", psk="", rate=0.0):
    return {"iface": iface, "public_key": pub, "handshake": hs, "rx": rx, "tx": tx,
            "rx_rate": rate, "tx_rate": rate, "endpoint": ep, "keepalive": "off", "psk": psk}


def panel_source():
    with open(twp.PANEL, encoding="utf-8") as f:
        return f.read()


class _Panel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nqmo-panel-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        m = self.m = twp.load_module(self.tmp)
        with open(os.path.join(self.tmp, "wgtest.conf"), "w", encoding="utf-8") as f:
            f.write(CONF)
        m.CONFIG["nqmo"] = {"enabled": True, "user_iface": "wgtest"}
        m.CONFIG["client_mtu"] = 1392
        peers = [live(K_OK, int(NOW) - 20, 5000, 9000, "198.51.100.7:51000", psk=PSK),
                 live(K_V6, int(NOW) - 30, 1, 2, "[2001:db8::1]:4500"),
                 live(K_IDLE, 0, 0, 0, "(none)"),
                 live(pubkey(), int(NOW) - 5, 10, 10, "203.0.113.9:51820", iface="awg1", rate=50.0),
                 live(pubkey(), int(NOW) - 5, 10, 10, "203.0.113.10:2408", iface="wgwarp"),
                 live(pubkey(), int(NOW) - 900, 0, 10, "203.0.113.11:51820", iface="wg22")]
        m.SAMPLER = types.SimpleNamespace(
            meta_cache={("wgtest", "alice"): {"c_mtu": 1280, "rate_mbit": 20},
                        ("wgtest", "dave"): {"c_mtu": "", "rate_mbit": "abc"}},
            month_usage={}, life_usage={}, refresh_meta=lambda: None,
            snapshot=lambda: {"ts": NOW, "peers": peers,
                              "ifaces": {i: {} for i in ("wgtest", "awg1", "wgwarp", "wg22")}},
            iface_history=lambda _iface: [])
        def tun(**kw):
            return dict({"systemd": "active", "endpoint": "", "enabled": True,
                         "kind": "wireguard", "userspace": False, "loop_dev": None,
                         "loop": False, "chain": False}, **kw)
        m.TUNNELS = types.SimpleNamespace(get=lambda: {
            "awg1": tun(kind="amneziawg"), "wgwarp": tun(chain=True), "wg22": tun(),
            "wg21": tun(systemd="inactive"),                    # enabled but down ⇒ "off"
            "wgold": tun(enabled=False, systemd="inactive")})   # deliberately off ⇒ omitted
        m._nqmo_sys_mtu = lambda iface: {"wgtest": 1392, "awg1": 1420}.get(iface)
        m.iface_meta_all = lambda: {"eth0": {"addresses": [twp.WAN_IP], "mtu": 1500, "up": True}}
        m.NQMO_META_PATH = os.path.join(self.tmp, "run", "wg-panel", "nqmo-meta.json")
        m.NQMO_GROUP = grp.getgrgid(os.getgid()).gr_name

    def doc(self):
        d = self.m.build_nqmo_meta(NOW)
        self.assertIsNotNone(d)
        return d


class NqmoMetaContractTests(_Panel):
    def test_engine_parser_accepts_the_panel_document(self):
        d = self.doc()
        m = nmeta.parse(json.dumps(d), read_at=NOW + 1)      # raises on any violation
        self.assertEqual(m.peers[K_OK]["name"], "alice")
        self.assertEqual(m.by_endpoint[("198.51.100.7", 51000)], K_OK)
        self.assertEqual(m.effective_mtu(K_OK), 1280)
        self.assertEqual(m.unmodelled_endpoints, 1)           # carol's IPv6 endpoint
        self.assertEqual(m.wg1udp_local_ip, twp.WAN_IP)
        self.assertIsNone(m.wg1udp_fwmark)

    def test_one_bad_peer_never_costs_the_whole_document(self):
        # family: every peer the engine would refuse (bad key, >64-char name,
        # key-shaped name, duplicate key) is dropped alone, not the document
        names = {p["name"] for p in self.doc()["peers"].values()}
        self.assertEqual(names, {"alice", "bob", "carol", "dave"})

    def test_peer_fields_follow_the_panel_not_a_guess(self):
        p = self.doc()["peers"]
        self.assertEqual(p[K_OK]["tunnel_ip"], "192.168.188.20")   # the /32, not the route
        self.assertIsNone(p[K_V6]["tunnel_ip"])                   # no /32 ⇒ unknown
        self.assertFalse(p[K_OFF]["enabled"])
        self.assertEqual((p[K_OFF]["latest_handshake"], p[K_OFF]["rx_bytes"]), (0, 0))
        self.assertIsNone(p[K_IDLE]["endpoint"])                  # "(none)"
        self.assertEqual((p[K_IDLE]["c_mtu"], p[K_IDLE]["rate_mbit"]), (None, None))
        self.assertEqual((p[K_OK]["c_mtu"], p[K_OK]["rate_mbit"]), (1280, 20))

    def test_no_secret_from_the_config_or_the_dump_reaches_the_file(self):
        text = json.dumps(self.doc())
        for secret in (PSK, PRIV):
            self.assertNotIn(secret, text)
        self.assertNotRegex(text.lower(), r"psk|preshared|private|secret|token")

    def test_egress_carries_the_panels_own_health(self):
        e = self.doc()["egress"]
        self.assertEqual({k: v["health"] for k, v in e.items()},
                         {"awg1": "healthy", "wgwarp": "chain", "wg22": "noreturn",
                          "wg21": "off"})
        self.assertNotIn("wgold", e)
        self.assertEqual(e["awg1"]["mtu"], 1420)
        self.assertIsNone(e["awg1"]["rx_delta"])                  # first export
        self.assertEqual(e["awg1"]["hs_age"], 5)
        self.assertTrue(all(v["svc_ok"] is None and v["mtr_loss"] is None for v in e.values()))

    def test_rx_delta_is_bytes_since_the_previous_export(self):
        self.doc()
        self.assertEqual(self.doc()["egress"]["awg1"]["rx_delta"], 0)

    def test_missing_user_iface_mtu_writes_no_document(self):
        self.m._nqmo_sys_mtu = lambda iface: None
        self.assertIsNone(self.m.build_nqmo_meta(NOW))


class NqmoHealthVocabularyTests(unittest.TestCase):
    """Family guard: every health value the panel can produce is classified by
    the engine on purpose. "chain" (healthy WARP chain) was read as a fault."""

    EXPECT = {"healthy": False, "idle": False, "chain": False,
              "loop": True, "off": True, "dead": True, "noreturn": True}

    def test_engine_judges_every_panel_health_value(self):
        src = panel_source()
        fn = next(n for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.FunctionDef) and n.name == "tunnel_health")
        produced = {n.value.value for n in ast.walk(fn)
                    if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)}
        self.assertEqual(produced, set(self.EXPECT),
                         "tunnel_health changed: classify the new value in rules.egress")
        for h, bad in self.EXPECT.items():
            o = rules.egress({"egress": {"t": {"health": h}}}, True)[0]
            self.assertEqual(o.positive, bad, h)


class NqmoMetaWriteTests(_Panel):
    def test_flag_off_reads_and_writes_nothing(self):
        for cfg in (None, {}, {"enabled": "true"}, {"enabled": 1}, {"enabled": False}):
            self.m.CONFIG["nqmo"] = cfg
            self.m.build_nqmo_meta = lambda now=None: self.fail("built with the flag off")
            self.assertFalse(self.m.nqmo_export_meta(NOW))
        self.assertFalse(os.path.exists(os.path.dirname(self.m.NQMO_META_PATH)))

    def test_written_atomically_with_group_read_only(self):
        self.assertTrue(self.m.nqmo_export_meta(NOW))
        path = self.m.NQMO_META_PATH
        st, dst = os.stat(path), os.stat(os.path.dirname(path))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(dst.st_mode), 0o750)
        self.assertEqual(st.st_gid, os.getgid())
        self.assertEqual(os.listdir(os.path.dirname(path)), ["nqmo-meta.json"])   # no tmp left
        nmeta.read(path, read_at=NOW + 1)

    def test_no_engine_group_means_no_file(self):
        self.m.NQMO_GROUP = "wg-nqmo-absent-%d" % os.getpid()
        self.assertFalse(self.m.nqmo_export_meta(NOW))
        self.assertFalse(os.path.exists(self.m.NQMO_META_PATH))

    def test_export_runs_outside_the_alert_switch_in_its_own_try(self):
        src = panel_source()
        run = src[src.index("class AlertMonitor"):]
        run = run[run.index("    def run(self):"):run.index("    def _digest_mark")]
        self.assertLess(run.index("nqmo_export_meta()"), run.index("self._check_tunnels()"))
        self.assertLess(run.index("nqmo_export_meta()"), run.index('alert_cfg()["enabled"]'))
        self.assertLess(run.index("nqmo_export_meta()"), run.index("except Exception"))
        self.assertLess(run.index("except Exception"), run.index("self._check_tunnels()"))


class NqmoStateReadTests(unittest.TestCase):
    """P2: the panel reads what the engine's own writer produces, and every way
    the file can be absent or hostile ends in a fixed `why`, never an exception.
    The writer is the unprivileged wg-nqmo user, so the content is untrusted."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nqmo-state-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        m = self.m = twp.load_module(self.tmp)
        m.CONFIG["nqmo"] = {"enabled": True}
        self.default_path = m.NQMO_STATE_PATH
        m.NQMO_STATE_PATH = self.path = os.path.join(self.tmp, "state.json")
        self.seen = set()

    def engine_write(self, now=NOW, **over):
        st = nexport.build_state(now, "OBSERVATION_ONLY", {"C1_meta": True}, {}, [], {},
                                 analysis={"notify_outbox": [
                                     {"id": 3, "ts": now, "severity": "HIGH", "key": "k",
                                      "text_key": "nqmo.x", "params": {}}]})
        st.update(over)
        nexport.write_atomic(self.path, st)

    def read(self, now=NOW + 5):
        self.m._nqmo_state_cache["ts"] = None              # each case reads afresh
        s = self.m.nqmo_state(now)
        if not s["available"]:
            self.assertIn(s["why"], self.m.NQMO_STATE_WHY)
            self.seen.add(s["why"])
        return s

    def clear(self):
        if os.path.isdir(self.path) and not os.path.islink(self.path):
            os.rmdir(self.path)
        elif os.path.lexists(self.path):
            os.unlink(self.path)

    def raw(self, data):
        with open(self.path, "wb") as f:
            f.write(data)

    def test_constants_follow_the_engine(self):
        # the panel may not import nqmo (it ships alone), so the copies are pinned here
        self.assertEqual(self.default_path, nconfig.DEFAULTS["paths"]["state"])
        self.assertEqual(self.m.NQMO_META_PATH, nconfig.DEFAULTS["paths"]["meta"])
        self.assertEqual(self.m.NQMO_STATE_SCHEMA, nqmo.STATE_SCHEMA)
        self.assertEqual(self.m.NQMO_MODES, nconfig.MODES)
        self.assertGreaterEqual(self.m.NQMO_STATE_STALE, 2 * nconfig.DEFAULTS["intervals"]["export_s"])
        self.assertLessEqual(3 * self.m.NQMO_META_EVERY, nconfig.DEFAULTS["limits"]["meta_stale_s"])
        # §29.153: the history, stream and why shapes the panel validates against
        self.assertEqual(self.m.NQMO_HISTORY_HOURS, nanalysis.HISTORY_HOURS)
        self.assertEqual(self.m.NQMO_WHY_MAX, nanalysis.WHY_MAX)
        self.assertEqual(self.m.NQMO_STREAMS, nanalysis._JUDGED_STREAMS)
        from nqmo import correlate as ncorr, features as nfeat
        with open(ncorr.__file__, encoding="utf-8") as f:
            causes = set(re.findall(r'"(SERVER|EGRESS|UNKNOWN)', f.read()))
        self.assertEqual(set(self.m.NQMO_CORR_CAUSES), causes)
        for toks in nfeat._BAD.values():                  # every engine token passes the shape
            for t in toks:
                self.assertRegex(t, self.m._NQMO_WHY_RE)

    def test_engine_written_state_is_read(self):
        self.engine_write()
        s = self.read()
        self.assertTrue(s["available"])
        self.assertEqual((s["mode"], s["age_s"]), ("OBSERVATION_ONLY", 5.0))
        self.assertEqual(s["notify_outbox"][0]["id"], 3)

    def test_every_failure_is_a_fixed_why_never_an_exception(self):
        # family: absent, hostile file types, size, encoding, nesting, shape, schema,
        # field types, age and clock; plus an unexpected bug inside the reader
        cases = []
        cases.append(("missing", lambda: None))
        cases.append(("unreadable", lambda: os.symlink(os.path.join(self.tmp, "x.json"),
                                                       self.path)))
        cases.append(("unreadable", lambda: os.mkdir(self.path)))
        cases.append(("unreadable", lambda: os.mkfifo(self.path)))
        cases.append(("too_large", lambda: self.raw(b" " * (self.m.NQMO_STATE_MAX_BYTES + 1))))
        cases.append(("corrupt", lambda: self.raw(b"{not json")))
        cases.append(("corrupt", lambda: self.raw(b"\xff\xfe{}")))
        cases.append(("corrupt", lambda: self.raw(b"[" * 200000)))
        cases.append(("corrupt", lambda: self.raw(b"[1, 2]")))
        cases.append(("schema", lambda: self.engine_write(schema=2)))
        cases.append(("schema", lambda: self.engine_write(schema=True)))
        cases.append(("schema", lambda: self.engine_write(schema=None)))
        cases.append(("corrupt", lambda: self.engine_write(generated_at="1")))
        cases.append(("corrupt", lambda: self.engine_write(generated_at=True)))
        cases.append(("corrupt", lambda: self.raw(json.dumps(
            {"schema": 1, "generated_at": float("nan"), "mode": "OBSERVATION_ONLY"}).encode())))
        cases.append(("corrupt", lambda: self.engine_write(mode="ROOT")))
        cases.append(("stale", lambda: self.engine_write(now=NOW - 176)))
        cases.append(("clock", lambda: self.engine_write(now=NOW + 70)))
        for why, make in cases:
            with self.subTest(why=why):
                self.clear()
                make()
                s = self.read()
                self.assertFalse(s["available"])
                self.assertEqual(s["why"], why)
        if os.geteuid() != 0:                              # root reads 0000 files
            self.engine_write()
            os.chmod(self.path, 0)
            self.assertEqual(self.read()["why"], "unreadable")
        def boom():
            raise RuntimeError("bug")
        self.m._nqmo_load_state = boom
        self.assertEqual(self.read()["why"], "error")
        self.m.CONFIG["nqmo"] = {"enabled": "true"}
        self.assertEqual(self.read()["why"], "disabled")   # and boom() was never reached
        self.assertEqual(self.seen, set(self.m.NQMO_STATE_WHY),
                         "a why in NQMO_STATE_WHY that no case produces, or the reverse")

    def test_cached_for_ttl_then_reread_and_clock_jumps_reread(self):
        self.engine_write()
        self.assertTrue(self.read()["available"])
        os.unlink(self.path)
        ttl = self.m.NQMO_STATE_TTL
        self.assertTrue(self.m.nqmo_state(NOW + 5 + ttl - 1)["available"])   # cached
        self.assertEqual(self.m.nqmo_state(NOW + 5 + ttl)["why"], "missing")
        self.engine_write()
        self.assertTrue(self.m.nqmo_state(NOW + 1)["available"])             # clock went back

    def test_caller_mutation_never_poisons_the_cache(self):
        self.engine_write()
        s = self.read()
        s["mode"] = "RECOMMENDATIONS_ENABLED"
        s.pop("notify_outbox")
        again = self.m.nqmo_state(NOW + 6)
        self.assertEqual(again["mode"], "OBSERVATION_ONLY")
        self.assertIn("notify_outbox", again)



class NqmoNotifyTests(unittest.TestCase):
    """P3: notify_outbox → ALERTS.event("nqmo", …). The engine owns dedup, cooldown
    and rate; the panel owns only "which ids are new" — and that cursor has two
    invalid-baseline states (first run, engine database rebuilt) that must neither
    replay the whole box nor go silent forever."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nqmo-notify-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        m = self.m = twp.load_module(self.tmp)
        m.CONFIG["nqmo"] = {"enabled": True}
        m.CONFIG["alerts"] = {"enabled": True}
        m.NQMO_NOTIFIED_STATE = self.last_path = os.path.join(self.tmp, "nqmo-notified.last")
        self.sent = []
        m.ALERTS.emit = lambda t, html=False: self.sent.append(t)
        self.box = []
        self.avail = True
        m.nqmo_state = lambda now=None: ({"available": True, "notify_outbox": self.box}
                                         if self.avail else {"available": False, "why": "stale"})
        self.mon = m.AlertMonitor()

    def ev(self, eid, ts=NOW, severity="HIGH", text_key="nqmo.alert.open", params=None):
        return {"id": eid, "ts": ts, "severity": severity, "key": "nqmo:PEER:7:X",
                "text_key": text_key,
                "params": {"class": "PACKET_LOSS", "scope": "PEER", "peer": "alice",
                           "iface": "wgtest", "confidence": "HIGH", "evidence": []}
                if params is None else params}

    def check(self, now=NOW + 5, fresh_monitor=False):
        if fresh_monitor:                                  # a panel restart
            self.mon = self.m.AlertMonitor()
        self.mon._check_nqmo(now)

    def last_on_disk(self):
        with open(self.last_path, encoding="utf-8") as f:
            return int(f.read())

    # ---- the contract with the engine ------------------------------------------------
    def test_every_key_and_severity_the_engine_emits_is_handled(self):
        with open(ndiag.__file__, encoding="utf-8") as f:
            src = f.read()
        keys = set(re.findall(r'"(nqmo\.alert\.\w+)"', src))
        self.assertEqual(keys, set(self.m.NQMO_NOTIFY_KEYS))
        sev = set(re.findall(r'_outbox\(now, "([A-Z]+)"', src)) | set(ndiag.NOTIFY_LEVELS)
        self.assertEqual(sev - set(self.m.NQMO_NOTIFY_SEVERITIES), {"DIGEST"})
        self.assertNotIn("LOW", self.m.NQMO_NOTIFY_SEVERITIES)
        self.assertEqual(self.m.NQMO_NOTIFY_BURST, ndiag.NOTIFY_RATE_PER_HOUR)

    def test_engine_params_render_in_every_language(self):
        # the real engine builder, both scopes, every text key, every language
        evs = [rules.ev("loss", 0.0712345, "S1", "client", "up"), rules.ev("rtt", 81, "S1", "c", "up")]
        names = {7: ("wgtest", "alice")}
        outs = [rules.Outcome("PACKET_LOSS", True, evidence=evs, scope="PEER", subject="7"),
                rules.Outcome("EGRESS_TUNNEL_DEGRADATION", True, evidence=evs,
                              scope="EGRESS", subject="awg1")]
        cases = [(k, sv, st) for k in self.m.NQMO_NOTIFY_KEYS
                 for sv in ("HIGH", "MEDIUM", "INFO") for st in (False, True)]
        for lang in self.m.LANGS:
            self.m.alert_lang = lambda lang=lang: lang
            for o in outs:
                for key, sv, stale in cases:
                    with self.subTest(lang=lang, scope=o.scope, key=key, sev=sv, stale=stale):
                        p = ndiag.Diagnoser._params(o, "HIGH", names, stale=stale)
                        txt = self.m.nqmo_alert_text(self.ev(1, severity=sv, text_key=key,
                                                             params=json.loads(json.dumps(p))))
                        self.assertIsInstance(txt, str)
                        self.assertNotRegex(txt, r"\{\w*\}|nqmo\.alert|alert\.nqmo")
                        if key != "nqmo.alert.more":
                            self.assertIn(o.cls, txt)
                            self.assertIn("alice (wgtest)" if o.scope == "PEER" else "awg1", txt)
                        if key == "nqmo.alert.cleared":     # "no data" is not "recovered"
                            self.assertTrue(txt.startswith("⚪" if stale else "✅"))
                        if key in ("nqmo.alert.open", "nqmo.alert.escalated"):
                            self.assertIn("loss = 0.07123", txt)

    # ---- the cursor ------------------------------------------------------------------
    def test_first_run_sends_only_fresh_events_then_only_new_ids(self):
        stale = NOW + 5 - self.m.NQMO_STATE_STALE - 1
        self.box[:] = [self.ev(1, ts=stale), self.ev(2, ts=stale), self.ev(3)]
        self.check()
        self.assertEqual(len(self.sent), 1)                # not the 100-event history
        self.assertEqual(self.last_on_disk(), 3)
        self.check()
        self.assertEqual(len(self.sent), 1)                # nothing new ⇒ nothing sent
        self.box.append(self.ev(4, ts=stale))              # resumed: age no longer matters
        self.check(fresh_monitor=True)                     # and the cursor survived restart
        self.assertEqual((len(self.sent), self.last_on_disk()), (2, 4))

    def test_engine_database_rebuilt_is_detected_not_silent(self):
        with open(self.last_path, "w") as f:
            f.write("500\n")
        self.box[:] = [self.ev(1, ts=NOW - 3600), self.ev(2)]
        self.check()
        self.assertEqual((len(self.sent), self.last_on_disk()), (1, 2))

    def test_bad_cursor_file_is_a_first_run(self):
        for bad in ("", "abc", "-4", "1e9", "\x00"):
            with self.subTest(content=bad):
                with open(self.last_path, "w") as f:
                    f.write(bad)
                self.sent.clear()
                self.box[:] = [self.ev(1, ts=NOW - 3600), self.ev(2)]
                self.check(fresh_monitor=True)
                self.assertEqual((len(self.sent), self.last_on_disk()), (1, 2))

    def test_burst_cap_carries_the_rest_to_the_next_cycle(self):
        self.box[:] = [self.ev(i) for i in range(1, 15)]
        cap = self.m.NQMO_NOTIFY_BURST
        self.check()
        self.assertEqual((len(self.sent), self.last_on_disk()), (cap, cap))
        self.check()
        self.check()
        self.assertEqual((len(self.sent), self.last_on_disk()), (14, 14))

    def test_unsendable_entries_advance_the_cursor_without_a_message(self):
        # family: everything the panel must not send still moves the cursor,
        # otherwise one such entry would be re-evaluated (and block the burst) forever
        # (the one sendable entry comes first, so only advancing past the rest reaches 9;
        # a known cursor keeps the first-run age filter, which also advances, out of it)
        with open(self.last_path, "w") as f:
            f.write("0\n")
        self.box[:] = [self.ev(1), self.ev(2, severity="DIGEST"), self.ev(3, severity="LOW"),
                       self.ev(4, severity="CRITICAL"), self.ev(5, text_key="nqmo.alert.root"),
                       self.ev(6, text_key=None), self.ev(7, params="x"),
                       dict(self.ev(8), params=None), {"id": 9, "ts": NOW}]
        self.check()
        self.assertEqual((len(self.sent), self.last_on_disk()), (1, 9))

    def test_malformed_ids_are_ignored_and_duplicates_send_once(self):
        self.box[:] = [self.ev(True), self.ev("5"), self.ev(5.0), self.ev(None), self.ev(0),
                       self.ev(-3), "x", None, 7, self.ev(2), self.ev(2), self.ev(3)]
        self.check()
        self.assertEqual((len(self.sent), self.last_on_disk()), (2, 3))
        for box in (None, "x", {}, 5, [], [None]):
            with self.subTest(box=box):
                self.box = box
                self.check()                              # never raises, never moves
                self.assertEqual(self.last_on_disk(), 3)

    def test_alerts_off_moves_the_cursor_so_turning_on_replays_nothing(self):
        self.m.CONFIG["alerts"] = {"enabled": False}
        self.box[:] = [self.ev(1), self.ev(2)]
        self.check()
        self.assertEqual((self.sent, self.last_on_disk()), ([], 2))
        self.m.CONFIG["alerts"] = {"enabled": True, "events": {"nqmo": False}}
        self.box.append(self.ev(3))
        self.check()
        self.assertEqual((self.sent, self.last_on_disk()), ([], 3))
        self.m.CONFIG["alerts"] = {"enabled": True}
        self.check()
        self.assertEqual(self.sent, [])

    def test_engine_unavailable_never_touches_the_cursor(self):
        self.avail = False
        self.box[:] = [self.ev(1)]
        self.check()
        self.assertEqual(self.sent, [])
        self.assertFalse(os.path.exists(self.last_path))

    def test_the_monitor_loop_calls_it_outside_the_alerts_enabled_gate(self):
        tree = ast.parse(panel_source())
        run = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)
                   and n.name == "AlertMonitor")
        run = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "run")
        gated = {id(c) for n in ast.walk(run) if isinstance(n, ast.If)
                 and "enabled" in ast.unparse(n.test) for c in ast.walk(n)}
        calls = [n for n in ast.walk(run) if isinstance(n, ast.Call)
                 and ast.unparse(n.func) == "self._check_nqmo"]
        self.assertEqual(len(calls), 1)
        self.assertNotIn(id(calls[0]), gated)

    # ---- hostile content -------------------------------------------------------------
    def test_hostile_strings_are_cleaned_and_capped(self):
        nasty = "a‮b\x1b[31m\nc⁦" + "x" * 500
        p = {"class": nasty, "scope": "PEER", "peer": nasty, "iface": nasty,
             "confidence": {"x": 1}, "evidence": [{"metric": nasty, "value": float("inf")},
                                                  "x", None, {"metric": 1, "value": True}]}
        txt = self.m.nqmo_alert_text(self.ev(1, params=p))
        self.assertNotRegex(txt, "[\x00-\x09\x0b-\x1f‪-‮⁦-⁩]")
        self.assertNotIn("x" * (self.m._NQMO_TXT_MAX + 1), txt)
        self.assertIn("= ?", txt)

    def test_random_documents_never_raise(self):
        rnd = random.Random(1729)
        atoms = [None, True, 0, -1, 2 ** 70, 1.5, float("nan"), "", "PEER", "‮", [], {}]
        def junk(d=0):
            r = rnd.random()
            if d > 3 or r < 0.5:
                return rnd.choice(atoms)
            if r < 0.75:
                return [junk(d + 1) for _ in range(rnd.randrange(4))]
            keys = ["id", "ts", "severity", "text_key", "params", "class", "scope", "peer",
                    "iface", "subject", "stale", "evidence", "metric", "value", "confidence"]
            return {rnd.choice(keys): junk(d + 1) for _ in range(rnd.randrange(6))}
        for i in range(400):
            e = junk() if i % 2 else dict(self.ev(i + 1, severity=rnd.choice(["HIGH", "INFO"]),
                                                  text_key=rnd.choice(self.m.NQMO_NOTIFY_KEYS)),
                                          params=junk())
            with self.subTest(i=i):
                if isinstance(e, dict):
                    r = self.m.nqmo_alert_text(e)
                    self.assertTrue(r is None or isinstance(r, str))
                self.box[:] = [e]
                self.check()


class NqmoMetricsTests(unittest.TestCase):
    """P4: wg_nqmo_* in /metrics. Every label comes from a closed vocabulary pinned
    to the engine's source, the flag off changes nothing byte for byte, and a
    hostile state file can neither raise, inject a label, nor grow the series."""

    LABEL = r'\w+="(?:[^"\\]|\\.)*"'

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nqmo-metrics-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        m = self.m = twp.load_module(self.tmp)
        m.CONFIG["nqmo"] = {"enabled": True}
        m.NQMO_STATE_PATH = self.path = os.path.join(self.tmp, "state.json")
        m.build_stats = lambda: {"users": [], "tunnels": [], "interfaces": [],
                                 "sys": {"cur": {}, "extra": {}}}
        m.health_report = lambda: {"threads": {}, "uptime": 7}
        m.META.svc_probe_all = lambda: {}
        self.known = set()

    def users(self, *labels):
        self.known = set(labels)
        self.m.build_stats = lambda: {
            "users": [{"iface": i, "name": n, "enabled": True, "online": True, "handshake": 0,
                       "rx": 0, "tx": 0, "rx_rate": 0.0, "tx_rate": 0.0, "month_rx": 0,
                       "month_tx": 0, "life_rx": 0, "life_tx": 0, "live": True}
                      for i, n in labels],
            "tunnels": [], "interfaces": [], "sys": {"cur": {}, "extra": {}}}

    def full_state(self, now=NOW):
        diags = [{"id": i, "class": c, "scope": "PEER", "peer": "alice", "iface": "wgtest"}
                 for i, c in enumerate(["PACKET_LOSS", "PACKET_LOSS", "HANDSHAKE_FLOOD"])]
        st = nexport.build_state(
            now, "DIAGNOSTICS_ENABLED",
            {"C1_meta": True, "C2_kernel": False, "C3_capture": None},
            {"peers_total": 24, "peers_handshake_180s": 17},
            [{"ts": now, "where": "store", "error": "x"}] * 3,
            {"size_mb": 1.5, "read_only": False, "recreated": False},
            analysis={"diagnoses": diags})
        return dict(st, available=True, age_s=4.0)

    def series(self, st):
        """{(name, frozenset(labels)): value} via the real build_metrics formatter."""
        self.m.nqmo_state = lambda now=None: st
        out = self.m.build_metrics()
        got = {}
        for line in out.splitlines():
            if not line.startswith("wg_nqmo"):
                continue
            mt = re.fullmatch(r"(wg_nqmo_\w+)\{(%s(?:,%s)*)?\} (\S+)" % (self.LABEL, self.LABEL),
                              line)
            self.assertIsNotNone(mt, line)
            float(mt.group(3))                                  # never nan/inf/True
            self.assertNotIn(mt.group(3).lower(), ("nan", "inf", "-inf", "true", "false"))
            lbl = frozenset(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', mt.group(2) or ""))
            self.assertNotIn((mt.group(1), lbl), got, "duplicate series")
            got[(mt.group(1), lbl)] = mt.group(3)
        return got

    def closed(self, got):
        vocab = {"mode": set(self.m.NQMO_MODES), "collector": set(self.m.NQMO_COLLECTORS),
                 "class": set(self.m.NQMO_CLASSES), "why": set(self.m.NQMO_STATE_WHY),
                 "iface": {k[0] for k in self.known}, "name": {k[1] for k in self.known}}
        for (_name, lbl) in got:
            for k, v in lbl:
                self.assertIn(v, vocab[k], (k, v))

    # ---- the closed vocabularies are the engine's ----------------------------------

    def test_label_vocabularies_follow_the_engine_source(self):
        with open(rules.__file__, encoding="utf-8") as f:
            src = f.read()
        classes = set(re.findall(r'(?:Outcome|_na)\("([A-Z_]+)"', src))
        self.assertEqual(set(self.m.NQMO_CLASSES), classes)
        with open(os.path.join(os.path.dirname(nqmo.__file__), "engine.py"),
                  encoding="utf-8") as f:
            eng = f.read()
        self.assertEqual(set(self.m.NQMO_COLLECTORS), set(re.findall(r'"(C\d_\w+)":', eng)))

    # ---- the flag off is invisible ------------------------------------------------

    def test_flag_off_is_byte_identical_and_reads_nothing(self):
        m = self.m
        m.CONFIG["nqmo"] = {"enabled": False}
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.full_state(), f)
        reads = []
        real = m._nqmo_load_state
        m._nqmo_load_state = lambda: reads.append(1) or real()
        off = m.build_metrics()
        m.nqmo_metric_rows = lambda st, known=(): []
        self.assertEqual(off, m.build_metrics())
        self.assertNotIn("wg_nqmo", off)
        self.assertEqual(reads, [])

    # ---- what a valid state exports ----------------------------------------------

    def test_engine_written_state_exports_the_expected_series(self):
        st = self.full_state()
        got = self.series(st)
        self.closed(got)
        want = {("wg_nqmo_up", ()): "1", ("wg_nqmo_state_age_seconds", ()): "4.0",
                ("wg_nqmo_peers", ()): "24", ("wg_nqmo_active_peers", ()): "17",
                ("wg_nqmo_recent_errors", ()): "3", ("wg_nqmo_store_read_only", ()): "0",
                ("wg_nqmo_store_bytes", ()): str(int(1.5 * 1024 * 1024)),
                ("wg_nqmo_collector_ok", (("collector", "C1_meta"),)): "1",
                ("wg_nqmo_collector_ok", (("collector", "C2_kernel"),)): "0",
                ("wg_nqmo_mode", (("mode", "DIAGNOSTICS_ENABLED"),)): "1",
                ("wg_nqmo_mode", (("mode", "OBSERVATION_ONLY"),)): "0",
                ("wg_nqmo_diagnoses_open", (("class", "PACKET_LOSS"),)): "2",
                ("wg_nqmo_diagnoses_open", (("class", "HANDSHAKE_FLOOD"),)): "1",
                ("wg_nqmo_diagnoses_open", (("class", "UDP_INSTABILITY"),)): "0"}
        for (name, lbl), v in want.items():
            self.assertEqual(got.get((name, frozenset(lbl))), v, (name, lbl))
        # capture off (None) is absent, not "0": off is not unhealthy
        self.assertNotIn(("wg_nqmo_collector_ok", frozenset({("collector", "C3_capture")})), got)
        # one row per class and per mode, always — a constant cardinality
        self.assertEqual(sum(1 for n, _ in got if n == "wg_nqmo_diagnoses_open"),
                         len(self.m.NQMO_CLASSES))
        self.assertEqual(sum(1 for n, _ in got if n == "wg_nqmo_mode"), len(self.m.NQMO_MODES))
        self.assertNotIn("alice", self.m.build_metrics().split("wg_nqmo", 1)[1])

    def test_every_unavailable_reason_is_up_zero_and_nothing_else(self):
        for why in self.m.NQMO_STATE_WHY:
            if why == "disabled":
                continue
            with self.subTest(why=why):
                got = self.series({"available": False, "why": why, "age_s": 999})
                self.assertEqual(got, {("wg_nqmo_up", frozenset()): "0",
                                       ("wg_nqmo_unavailable", frozenset({("why", why)})): "1"})
        got = self.series({"available": False, "why": 'x"}\nwg_nqmo_up 1'})
        self.assertEqual(got[("wg_nqmo_unavailable", frozenset({("why", "error")}))], "1")

    def test_the_real_reader_feeds_the_scrape_without_a_subprocess(self):
        m = self.m
        st = self.full_state(now=1_000.0)
        for k in ("available", "age_s"):
            del st[k]
        nexport.write_atomic(self.path, st)
        def boom(*a, **k):
            raise AssertionError("subprocess at scrape time")
        for name in ("run", "Popen", "check_output", "call"):
            setattr(m.subprocess, name, boom)
        m._nqmo_state_cache["ts"] = None
        rows = m.nqmo_metric_rows(m.nqmo_state(1_004.0))
        self.assertEqual(rows[0][3], [({}, 1)])

    # ---- hostile state ------------------------------------------------------------

    def test_hostile_values_never_become_labels_or_bad_numbers(self):
        st = self.full_state()
        st["mode"] = 'x"} 1\nwg_nqmo_up'
        st["collectors"] = {"C1_meta": 1, "C2_kernel": "true", "C9_evil": True,
                            'C3_capture"}': True}
        st["diagnoses"] = [{"class": "EVIL"}, {"class": ["PACKET_LOSS"]}, "PACKET_LOSS",
                           {"class": "PACKET_LOSS"}, None]
        st["coverage"] = {"peers_total": float("nan"), "peers_handshake_180s": True}
        st["store"] = {"size_mb": float("inf"), "read_only": 0}
        st["age_s"] = float("-inf")
        st["errors"] = "many"
        got = self.series(st)
        self.closed(got)
        self.assertNotIn(("wg_nqmo_collector_ok", frozenset({("collector", "C1_meta")})), got)
        self.assertEqual(got[("wg_nqmo_diagnoses_open", frozenset({("class", "PACKET_LOSS")}))],
                         "1")
        for name in ("wg_nqmo_peers", "wg_nqmo_active_peers", "wg_nqmo_store_bytes",
                     "wg_nqmo_store_read_only", "wg_nqmo_state_age_seconds",
                     "wg_nqmo_recent_errors"):
            self.assertNotIn((name, frozenset()), got, name)
        self.assertTrue(all(v == "0" for (n, _), v in got.items() if n == "wg_nqmo_mode"))

    # ---- per-peer series ------------------------------------------------------------

    def peer(self, name="alice", iface="wgtest", **kw):
        p = {"iface": iface, "name": name, "window": NOW - 400, "quality": "LOW",
             "mtu_status": "VERIFIED", "rtt_n": 15, "rtt_ms_med": 42.0, "rtt_ms_min": 30.5,
             "loss_n": 25000, "loss_k": 1000, "loss_point": 0.04, "loss_lb": 0.0376,
             "loss_ub": 0.0425}
        p.update(kw)
        return p

    def peer_state(self, *peers):
        return dict(self.full_state(), peers=list(peers))

    def test_peer_gates_follow_the_engine(self):
        self.assertEqual(self.m.NQMO_RTT_MIN_SAMPLES, rules.PARAMS["rtt_min_samples"])
        self.assertEqual(self.m.NQMO_LOSS_N_MIN, rules.PARAMS["loss_n_min"])
        self.assertEqual(set(self.m.NQMO_PEER_QUALITY), set(nanalysis.PEER_QUALITY))
        self.assertEqual(set(self.m.NQMO_MTU_STATUS), set(nanalysis.MTU_STATUSES))
        self.assertEqual(self.m.NQMO_WINDOW, ndiag.WINDOW)
        # analysis runs 60 s after a window closes; the next export can be one interval later
        self.assertGreaterEqual(self.m.NQMO_PEER_MAX_AGE,
                                ndiag.WINDOW + 60 + 2 * nconfig.DEFAULTS["intervals"]["export_s"])
        self.assertLess(self.m.NQMO_PEER_MAX_AGE, 3 * ndiag.WINDOW)

    def test_engine_analysis_end_to_end_reaches_the_scrape(self):
        from nqmo import store as nstore
        from tests import test_nqmo_diag as td
        db = nstore.Store(os.path.join(self.tmp, "n.db"))
        self.addCleanup(db.close)
        an = nanalysis.Analysis(db, nconfig.validate({}), clock=lambda: t[0])
        pid = db.peer_id("wgtest", "alice", "fp")
        t = [td.T0]
        for i in range(4):
            ws = td.T0 + 300 * i
            for r in td.window_rows(pid, ws, rtt_samples="40.0", s4_expected=5000,
                                    s4_received=4800):
                db.put_peer_minute(r)
            db.put_global_minute({"ts": ws, "quality": "GOOD",
                                  "egress_json": td.NqmoAnalysisTests.EGRESS_OK})
            t[0] = ws + 310
            an.run_window(ws, td.Meta(t[0]), "RECOMMENDATIONS_ENABLED")
        st = nexport.build_state(t[0], "RECOMMENDATIONS_ENABLED", {}, {}, [], {},
                                 analysis=an.snapshot(an.diag.peer_names()))
        nexport.write_atomic(self.path, st)
        self.users(("wgtest", "alice"))
        real = self.m.nqmo_state
        self.m._nqmo_state_cache["ts"] = None
        doc = real(t[0] + 5)
        self.assertTrue(doc["available"], doc)
        got = self.series(doc)
        self.closed(got)
        A = frozenset({("iface", "wgtest"), ("name", "alice")})
        lb, ub = nanalysis.stats.wilson(1000, 25000)
        self.assertEqual(got[("wg_nqmo_peer_rtt_seconds", A)], "0.04")
        self.assertEqual(got[("wg_nqmo_peer_rtt_samples", A)], "15")
        self.assertEqual(got[("wg_nqmo_peer_upstream_loss_ratio", A)], "0.04")
        self.assertEqual(got[("wg_nqmo_peer_upstream_loss_lower_ratio", A)], str(round(lb, 6)))
        self.assertEqual(got[("wg_nqmo_peer_upstream_loss_upper_ratio", A)], str(round(ub, 6)))
        self.assertEqual(got[("wg_nqmo_peer_upstream_loss_judged_packets", A)], "25000")
        self.assertEqual(got[("wg_nqmo_peer_quality_state", A)], "3")          # PACKET_LOSS HIGH
        self.assertEqual(got[("wg_nqmo_peer_mtu_status", A)], "0")             # loss blocks VERIFIED

    def test_each_peer_gate_withholds_only_its_own_number(self):
        self.users(("wgtest", "alice"))
        A = frozenset({("iface", "wgtest"), ("name", "alice")})
        cases = {
            "rtt few": (dict(rtt_n=4), {"wg_nqmo_peer_rtt_seconds", "wg_nqmo_peer_rtt_min_seconds"}),
            "rtt min>med": (dict(rtt_ms_min=50.0), {"wg_nqmo_peer_rtt_seconds",
                                                    "wg_nqmo_peer_rtt_min_seconds"}),
            "rtt nan": (dict(rtt_ms_med=float("nan")), {"wg_nqmo_peer_rtt_seconds",
                                                        "wg_nqmo_peer_rtt_min_seconds"}),
            "rtt n bool": (dict(rtt_n=True), {"wg_nqmo_peer_rtt_seconds",
                                              "wg_nqmo_peer_rtt_min_seconds",
                                              "wg_nqmo_peer_rtt_samples"}),
            "loss few": (dict(loss_n=999), {"wg_nqmo_peer_upstream_loss_ratio",
                                            "wg_nqmo_peer_upstream_loss_lower_ratio",
                                            "wg_nqmo_peer_upstream_loss_upper_ratio"}),
            "loss lb>pt": (dict(loss_lb=0.05), {"wg_nqmo_peer_upstream_loss_ratio",
                                                "wg_nqmo_peer_upstream_loss_lower_ratio",
                                                "wg_nqmo_peer_upstream_loss_upper_ratio"}),
            "loss >1": (dict(loss_point=1.5, loss_ub=2.0),
                        {"wg_nqmo_peer_upstream_loss_ratio",
                         "wg_nqmo_peer_upstream_loss_lower_ratio",
                         "wg_nqmo_peer_upstream_loss_upper_ratio"}),
            "quality none": (dict(quality=None), {"wg_nqmo_peer_quality_state"}),
            "quality bogus": (dict(quality="GREAT"), {"wg_nqmo_peer_quality_state"}),
            "mtu bogus": (dict(mtu_status="PATH_MTU"), {"wg_nqmo_peer_mtu_status"}),
        }
        full = {n for (n, lbl) in self.series(self.peer_state(self.peer())) if lbl == A}
        self.assertEqual(len(full), 9)
        for why, (over, gone) in cases.items():
            with self.subTest(why):
                have = {n for (n, lbl) in self.series(self.peer_state(self.peer(**over)))
                        if lbl == A}
                self.assertEqual(full - have, gone)

    def test_unknown_duplicate_and_stale_peers_are_left_out(self):
        self.users(("wgtest", "alice"), ("wgtest", "bob"), ("wgtest", "carol"))
        st = self.peer_state(self.peer(), self.peer("mallory"),           # not a panel peer
                             self.peer("bob"), self.peer("bob"),          # ambiguous label
                             self.peer("carol", window=NOW - 300 - 721),  # stale window
                             self.peer("alice", iface="awg1"),             # wrong iface
                             'x', None)
        names = {dict(lbl).get("name") for (n, lbl) in self.series(st)
                 if n.startswith("wg_nqmo_peer_")}
        self.assertEqual(names, {"alice"})
        self.users()
        self.assertFalse([n for n, _ in self.series(st) if n.startswith("wg_nqmo_peer_")])

    def test_random_states_never_raise_and_stay_bounded(self):
        rnd = random.Random(31337)
        atoms = [None, True, False, 0, -3, 2 ** 70, 1.5, float("nan"), float("inf"), "",
                 "PACKET_LOSS", "C1_meta", "OBSERVATION_ONLY", '"\n', [], {}, "wgtest",
                 "alice", "HIGH", "VERIFIED", 0.02, 1000, NOW - 400]
        keys = ["mode", "collectors", "diagnoses", "coverage", "errors", "store", "age_s",
                "class", "C1_meta", "C2_kernel", "peers_total", "peers_handshake_180s",
                "size_mb", "read_only", "available", "why", "peers", "iface", "name",
                "window", "quality", "mtu_status", "rtt_n", "rtt_ms_med", "rtt_ms_min",
                "loss_n", "loss_point", "loss_lb", "loss_ub", "generated_at"]
        def junk(d=0):
            r = rnd.random()
            if d > 3 or r < 0.45:
                return rnd.choice(atoms)
            if r < 0.7:
                return [junk(d + 1) for _ in range(rnd.randrange(5))]
            return {rnd.choice(keys): junk(d + 1) for _ in range(rnd.randrange(7))}
        bound = (1 + 1 + len(self.m.NQMO_MODES) + len(self.m.NQMO_COLLECTORS)
                 + len(self.m.NQMO_CLASSES) + 2 + 1 + 2 + 9)
        self.users(("wgtest", "alice"))
        for i in range(300):
            if i % 3 == 1:
                st = self.peer_state(*[dict(self.peer(), **{rnd.choice(keys): junk()
                                                            for _ in range(rnd.randrange(3))})
                                       for _ in range(rnd.randrange(4))])
            else:
                st = junk() if i % 3 == 0 else dict(self.full_state(), **{
                    rnd.choice(keys): junk() for _ in range(rnd.randrange(1, 5))})
            if not isinstance(st, dict):
                st = {"available": st}
            with self.subTest(i=i):
                got = self.series(st)
                self.closed(got)
                self.assertLessEqual(len(got), bound)


class _CtlEngine:
    """The engine's own ctl.Server + serve_pending on a real AF_UNIX socket,
    with the engine's Handler and fake callbacks — the contract is tested
    against the code the engine runs, not against a copy of its schema."""

    def __init__(self, path, mode="OBSERVATION_ONLY", probe=None):
        import queue
        import threading
        from nqmo import ctl
        self.mode, self.calls = mode, []
        self.handler = ctl.Handler(lambda: self.mode, self._set, self._ack,
                                   probe or (lambda peer, actor: self._log(
                                       "probe", peer, actor) or {"ok": True, "run_id": 7}))
        self.ops = []                    # every request that reached the engine
        real = self.handler.handle
        self.handler.handle = lambda req: (self.ops.append(
            (req.get("op"), req.get("to")) if isinstance(req, dict) else None), real(req))[1]
        self.q = queue.Queue(maxsize=8)
        # SO_PEERCRED is Linux-only; the engine's own tests inject uid_fn too
        self.srv = ctl.Server(path, self.q, allowed_uid=0, uid_fn=lambda c: self.uid)
        self.uid = 0
        self.stop = threading.Event()
        self.srv.start()
        self.loop = threading.Thread(target=self._serve, daemon=True)
        self.loop.start()
        for _ in range(200):
            if os.path.exists(path):
                break
            self.stop.wait(0.01)

    def _log(self, *a):
        self.calls.append(a)

    def _set(self, to, actor):
        self._log("mode.set", to, actor)
        self.mode = to

    def _ack(self, did, actor):
        self._log("ack", did, actor)
        return did == 5

    def _serve(self):
        from nqmo import ctl
        while not self.stop.is_set():
            ctl.serve_pending(self.q, self.handler)
            self.stop.wait(0.005)

    def close(self):
        self.stop.set()
        self.srv.stop.set()
        self.srv.join(3)
        self.loop.join(3)


def _fake_ctl(path, reply, delay=0.0):
    """A hostile/broken engine: answers every connection with `reply` bytes."""
    import socket as _s
    import threading
    srv = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
    srv.bind(path)
    srv.listen(2)
    stop = threading.Event()

    def run():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                continue
            with c:
                try:
                    c.recv(65536)
                    stop.wait(delay)
                    c.sendall(reply)
                except OSError:
                    pass
        srv.close()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return lambda: (stop.set(), t.join(3))


class NqmoApiTests(unittest.TestCase):
    """P5 (six /api/nqmo/* routes) and P6 (the nqmo permission group).

    Family guards: every route's permission is the one the design names and
    the RBAC gate really applies it; a view-only role never sees prefix, ASN
    or full evidence; every command is audited whether accepted or refused;
    the ctl.sock reply is untrusted (any engine refusal code is known, any
    other becomes UNKNOWN, any broken reply is BAD_REPLY, never an exception);
    and no value from state.json reaches the browser without being cleaned."""

    PERMS = {"/api/nqmo/status": "nqmo.view", "/api/nqmo/peer": "nqmo.view",
             "/api/nqmo/events": "nqmo.view", "/api/nqmo/ack": "nqmo.ack",
             "/api/nqmo/probe": "nqmo.probe", "/api/nqmo/mode": "nqmo.manage"}
    KNOWN = {("wgtest", "alice"), ("wgtest", "bob"), ("wg2", "bob")}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nqmo-api-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        m = self.m = twp.load_module(self.tmp)
        m.CONFIG["nqmo"] = {"enabled": True}
        m.CONFIG["roles"] = {"nview": {"perms": ["nqmo.view"]},
                             "ndetail": {"perms": ["nqmo.detail"]},
                             "nops": {"perms": ["nqmo.ack", "nqmo.probe", "nqmo.manage"]}}
        m.CONFIG["users"] = [
            {"username": u, "salt": "a" * 32, "hash": "h", "role": r, "totp": "",
             "stoken": "s" + u}
            for u, r in (("admin", "admin"), ("viewer", "viewer"), ("nview", "nview"),
                         ("ndetail", "ndetail"), ("nops", "nops"))]
        # AF_UNIX paths are capped (~104 bytes on macOS): a short dir of our own
        self.sockdir = tempfile.mkdtemp(prefix="nq", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.sockdir, True)
        m.NQMO_CTL_PATH = os.path.join(self.sockdir, "c.sock")
        m.nqmo_panel_peers = lambda: set(self.KNOWN)
        self.state = self.full_state()
        m.nqmo_state = lambda now=None: self.state
        self.audits, self.logs = [], []
        m.audit = lambda *a, **k: self.audits.append(a)
        real_log = m.log_action
        m.log_action = lambda msg: (self.logs.append(msg), real_log(msg))

    def E(self, key):
        """The panel answers errors in the viewer's language (here: en)."""
        return self.m.t(key, "en")

    def engine(self, **kw):
        e = _CtlEngine(self.m.NQMO_CTL_PATH, **kw)
        self.addCleanup(e.close)
        return e

    def full_state(self):
        diags = [
            {"id": 11, "class": "PACKET_LOSS", "scope": "PEER", "peer": "alice",
             "iface": "wgtest", "confidence": "HIGH", "since": NOW - 900,
             "evidence": [{"metric": "upstream_loss_wilson_lb", "value": 0.03,
                           "source": "AF_PACKET S4", "point": "eth0", "direction": "in"},
                          {"metric": "group", "value": "198.51.100.0/24"}],
             "counter_evidence": ["x"], "alternatives": ["y"], "data_quality": "GOOD"},
            {"id": 12, "class": "PACKET_LOSS", "scope": "PEER", "peer": "mallory",
             "iface": "wgtest", "confidence": "HIGH", "evidence": []},
            {"id": 13, "class": "EGRESS_TUNNEL_DEGRADATION", "scope": "EGRESS",
             "subject": "awg1", "confidence": "MEDIUM", "evidence": []}]
        box = [{"id": i, "ts": NOW - 100 + i, "severity": "HIGH", "key": "k",
                "text_key": "nqmo.alert.open",
                "params": {"class": "PACKET_LOSS", "scope": "PEER", "peer": p,
                           "iface": "wgtest", "confidence": "HIGH",
                           "evidence": [{"metric": "m", "value": "198.51.100.0/24"}]}}
               for i, p in ((1, "alice"), (2, "mallory"), (3, "bob"), (4, "alice"))]
        return {"available": True, "mode": "DIAGNOSTICS_ENABLED", "age_s": 4.0,
                "generated_at": NOW, "collectors": {"C1_meta": True, "C3_capture": None},
                "coverage": {"peers_total": 3, "peers_handshake_180s": 2},
                "store": {"size_mb": 1.5, "read_only": False}, "diagnoses": diags,
                "notify_outbox": box,
                "peers": [{"iface": "wgtest", "name": "alice", "window": NOW - 400,
                           "quality": "HIGH", "mtu_status": "UNDETERMINED", "rtt_n": 15,
                           "rtt_ms_med": 40.0, "rtt_ms_min": 31.0, "loss_n": 25000,
                           "loss_k": 750, "loss_point": 0.03, "loss_lb": 0.028,
                           "loss_ub": 0.032}],
                "recommendations": {"wgtest/alice": [{"target": "CLIENT_IFACE_MTU",
                                                      "status": "UNDETERMINED",
                                                      "limitations": ["l"], "junk": 1}]},
                "advisories": [{"scope": "PEER", "peer": "alice", "finding": "CONFIG_MISMATCH"},
                               {"scope": "PEER", "peer": "bob", "finding": "CONFIG_MISMATCH"},
                               {"scope": "SERVER_TUNNEL", "subject": "wg21",
                                "finding": "NESTED_MTU_MISMATCH"}],
                "correlations": [{"group_type": "PREFIX24", "group_key": "198.51.100.0/24"}],
                "groups_eligible": 2}

    def post(self, path, body=None, user="admin"):
        h = twp.make_fake_handler(self.m, path=path, method="POST", body=body or {},
                                  headers={"Cookie": "wgl=en"},
                                  session={"u": user, "r": user})
        h.do_POST()
        code = dict(h.sent).get("__code__")
        raw = b"".join(h.body)
        return code, (json.loads(raw) if raw else None)

    # ---- P6: the permission group --------------------------------------------------

    def test_each_route_requires_the_designed_permission_and_the_gate_applies_it(self):
        m = self.m
        self.assertEqual({k: m.Handler.required_perm(k) for k in self.PERMS}, self.PERMS)
        grp_ = [g for g in m.PERM_CATALOG if g[0] == "nqmo"]
        self.assertEqual(len(grp_), 1)
        self.assertEqual({k for k, _ in grp_[0][2]},
                         {"nqmo.view", "nqmo.detail", "nqmo.ack", "nqmo.probe", "nqmo.manage"})
        for p in ("nqmo.detail", "nqmo.ack", "nqmo.probe", "nqmo.manage"):
            self.assertIn("nqmo.view", m.normalize_perms([p]), p)
        self.assertFalse({p for p in m.VIEWER_PERMS if p.startswith("nqmo.")})
        self.assertFalse({p for p in m.ESCALATION_PERMS if p.startswith("nqmo.")})
        self.engine()
        holders = {"admin": set(self.PERMS.values()), "viewer": set(),
                   "nview": {"nqmo.view"}, "ndetail": {"nqmo.view", "nqmo.detail"},
                   "nops": set(self.PERMS.values())}
        for user, perms in holders.items():
            for path, need in self.PERMS.items():
                with self.subTest(user=user, path=path):
                    code, _ = self.post(path, {"name": "alice", "id": 5}, user=user)
                    self.assertEqual(code, 200 if need in perms else 403)
        h = twp.make_fake_handler(m, path="/api/nqmo/status", method="POST", body={},
                                  headers={"Cookie": "wgl=en"}, session=None)
        h.do_POST()
        self.assertEqual(dict(h.sent).get("__code__"), 401)

    def test_flag_off_answers_disabled_and_touches_nothing(self):
        self.m.CONFIG["nqmo"] = {"enabled": False}
        self.m.nqmo_state = lambda now=None: self.fail("state read with the flag off")
        self.m.nqmo_ctl = lambda req: self.fail("ctl used with the flag off")
        for path in self.PERMS:
            with self.subTest(path=path):
                self.assertEqual(self.post(path, {"to": "DIAGNOSTICS_ENABLED", "id": 5,
                                                  "name": "alice"}),
                                 (200, {"ok": False, "error": self.E("api.err.nqmo.disabled"),
                                        "disabled": True}))
        self.assertEqual(self.audits, [])

    def test_stats_tells_the_page_about_the_flag_only_when_it_is_on(self):
        """me.nqmo is the page's only source for the flag. Off: the key is absent, so
        /api/stats is byte-identical to the panel before WG-NQMO (05 §5.1)."""
        self.m.build_stats = lambda: {}
        for flag, want in (({"enabled": True}, True), ({"enabled": False}, None),
                           ({"enabled": "true"}, None), ({}, None), (None, None)):
            with self.subTest(flag=flag):
                if flag is None:
                    self.m.CONFIG.pop("nqmo", None)
                else:
                    self.m.CONFIG["nqmo"] = flag
                for user in ("admin", "viewer"):
                    h = twp.make_fake_handler(self.m, path="/api/stats", method="GET",
                                              headers={"Cookie": "wgl=en"},
                                              session={"u": user, "r": user})
                    h.do_GET()                       # the page reads it with GET
                    self.assertEqual(dict(h.sent).get("__code__"), 200)
                    doc = json.loads(b"".join(h.body))
                    me = doc["me"]
                    self.assertEqual(me.get("nqmo"), want)
                    base = {"username", "role", "totp", "perms", "need_totp", "protected"}
                    self.assertEqual(set(me), base | ({"nqmo"} if want else set()))

    # ---- P5: reads -------------------------------------------------------------------

    def test_view_role_never_sees_prefix_asn_or_full_evidence(self):
        blob_view = json.dumps([self.post(p, {"name": "alice"}, user="nview")[1]
                                for p in ("/api/nqmo/status", "/api/nqmo/peer",
                                          "/api/nqmo/events")])
        blob_detail = json.dumps([self.post(p, {"name": "alice"}, user="ndetail")[1]
                                  for p in ("/api/nqmo/status", "/api/nqmo/peer",
                                            "/api/nqmo/events")])
        for leak in ("198.51.100.0/24", "PREFIX24", "counter_evidence", "AF_PACKET",
                     "correlations"):
            self.assertNotIn(leak, blob_view, leak)
            self.assertIn(leak, blob_detail, leak)
        self.assertIn("upstream_loss_wilson_lb", blob_view)     # the number itself stays

    def test_status_is_whitelisted_and_scoped_to_panel_peers(self):
        _, r = self.post("/api/nqmo/status", user="nview")
        st = r["nqmo"]
        self.assertEqual((st["available"], st["mode"], st["detail"]),
                         (True, "DIAGNOSTICS_ENABLED", False))
        self.assertEqual(st["collectors"], {"C1_meta": True, "C3_capture": None})
        self.assertEqual([d["id"] for d in st["global"]], [13])
        self.assertEqual([(p["iface"], p["name"]) for p in st["peers"]], [("wgtest", "alice")])
        a = st["peers"][0]
        self.assertEqual((a["open"], a["top_class"], a["top_confidence"], a["rtt_ms_med"],
                          a["loss_point"], a["quality"]),
                         (1, "PACKET_LOSS", "HIGH", 40.0, 0.03, "HIGH"))
        self.assertNotIn("mallory", json.dumps(r))
        self.assertEqual([x["finding"] for x in st["advisories"]], ["NESTED_MTU_MISMATCH"])
        self.state = {"available": False, "why": 'evil"\n'}
        self.assertEqual(self.post("/api/nqmo/status")[1]["nqmo"],
                         {"available": False, "why": "error"})

    def test_history_streams_why_engine_cost_and_correlation_counts(self):
        """§29.153: per-peer hourly history, stream quality and why-tokens ride on
        the summary (status rows and the peer document); the engine's own cost and
        a prefix-free correlation count reach every viewer. Each is validated as a
        whole: a series of the wrong length or with a bad value is dropped entirely."""
        m = self.m
        H = m.NQMO_HISTORY_HOURS
        st = self.full_state()
        peer = st["peers"][0]
        peer["history"] = {"end": NOW - 100, "rtt_ms": [None] * (H - 1) + [41.5],
                           "loss": [0.0] * (H - 2) + [None, 0.04]}
        peer["streams"] = {"S1": "GOOD", "S2": "INVALID", "S4": "DEGRADED", "S9": "GOOD"}
        peer["why"] = ["KERNEL_DROP:S1", "KERNEL_DROP:S1", "‮evil", "a b", "C3:DISABLED"]
        st["coverage"]["engine"] = {"cpu_pct": 9.5, "rss_mb": 20.2, "cpu_pct_max": 15.0,
                                    "sampling": True}
        st["correlations"] = [{"group_type": "PREFIX24", "group_key": "198.51.100.0/24",
                               "active_peers": 6, "affected_peers": 4,
                               "suspected_cause": "EGRESS:awg1,awg3"},
                              {"group_type": "ASN", "group_key": "AS64500", "active_peers": 5,
                               "affected_peers": 3, "suspected_cause": "UNKNOWN"}, "junk"]
        self.state = st
        view = self.post("/api/nqmo/status", user="nview")[1]["nqmo"]
        row = view["peers"][0]
        self.assertEqual(row["history"], {"end": NOW - 100,
                                          "rtt_ms": [None] * (H - 1) + [41.5],
                                          "loss": [0.0] * (H - 2) + [None, 0.04]})
        self.assertEqual(row["streams"], {"S1": "GOOD", "S2": "INVALID", "S4": "DEGRADED"})
        self.assertEqual(row["why"], ["C3:DISABLED", "KERNEL_DROP:S1"])
        self.assertEqual(view["coverage"]["engine"], {"cpu_pct": 9.5, "rss_mb": 20.2,
                                                      "cpu_pct_max": 15.0, "sampling": True})
        self.assertEqual(view["correlation_summary"],
                         {"groups": 2, "active_peers": 11, "affected_peers": 7,
                          "causes": ["EGRESS", "UNKNOWN"]})
        self.assertNotIn("198.51.100", json.dumps(view))     # the count never carries a key
        self.assertNotIn("correlations", view)
        p = self.post("/api/nqmo/peer", {"iface": "wgtest", "name": "alice"},
                      user="nview")[1]["peer"]
        self.assertEqual(p["summary"]["history"], row["history"])
        self.assertEqual(p["summary"]["why"], row["why"])
        # a series with the wrong length, a bad value or a missing end goes as a whole
        for bad in ({"end": NOW, "rtt_ms": [1.0] * (H - 1), "loss": [None] * H},
                    {"end": NOW, "rtt_ms": [None] * H, "loss": [None] * (H - 1) + [1.5]},
                    {"end": NOW, "rtt_ms": [None] * (H - 1) + [-1], "loss": [None] * H},
                    {"end": NOW, "rtt_ms": [None] * (H - 1) + ["7"], "loss": [None] * H},
                    {"rtt_ms": [None] * H, "loss": [None] * H}, [1, 2], "x"):
            peer["history"] = bad
            self.state = st
            view = self.post("/api/nqmo/status", user="nview")[1]["nqmo"]
            self.assertIsNone(view["peers"][0]["history"], bad)
        # an older engine: empty shapes, nothing raises; junk engine cost is bounded
        st = self.full_state()
        self.state = st
        view = self.post("/api/nqmo/status", user="nview")[1]["nqmo"]
        self.assertEqual((view["peers"][0]["history"], view["peers"][0]["why"],
                          view["peers"][0]["streams"], view["coverage"]["engine"]),
                         (None, [], {"S1": None, "S2": None, "S4": None}, None))
        st["coverage"]["engine"] = {"cpu_pct": 250, "rss_mb": -3, "cpu_pct_max": "x",
                                    "sampling": "yes"}
        st["correlations"] = "x"
        self.state = st
        view = self.post("/api/nqmo/status", user="nview")[1]["nqmo"]
        self.assertEqual(view["coverage"]["engine"], {"cpu_pct": None, "rss_mb": None,
                                                      "cpu_pct_max": None, "sampling": None})
        self.assertIsNone(view["correlation_summary"])
        # /metrics: the engine cost as three series, absent when unknown
        rows = lambda cov: {r[0]: r[3][0][1] for r in m.nqmo_metric_rows(dict(st, coverage=cov))
                            if r[0].startswith("wg_nqmo_engine_")}
        self.assertEqual(rows({"engine": {"cpu_pct": 9.5, "rss_mb": 1.0, "cpu_pct_max": 15.0,
                                          "sampling": False}}),
                         {"wg_nqmo_engine_cpu_percent": 9.5,
                          "wg_nqmo_engine_rss_bytes": 1024 * 1024,
                          "wg_nqmo_engine_sampling": 0})
        self.assertEqual(rows({}), {})

    def test_status_carries_the_engine_health_the_page_used_to_drop(self):
        """Family guard for the §29.149 fields: everything engine.task_export and
        analysis.snapshot already write (promotion, errors, probe, last_window, the
        coverage details, store.recreated) reaches the page — cleaned, bounded, and
        with the error text behind nqmo.detail — and a document without them, or
        with junk in them, yields None/empty, never an exception or a raw string."""
        m = self.m
        st = self.full_state()
        st["promotion"] = {"data_days": 3.456, "shadow_high_by_peer_7d": {"4": 2, "9": 1, "x": "n"}}
        st["errors"] = [{"ts": NOW - 50 - i, "where": "store",
                         "error": "sqlite3.OperationalError: /var/lib/wg-nqmo/x.db locked"}
                        for i in range(15)] + [{"where": "‮evil\x1b", "ts": NOW},
                                               {"ts": NOW}, "junk"]
        st["probe"] = {"running": True, "run_id": 7}
        st["last_window"] = NOW - 400
        st["coverage"].update({"meta_age_s": 12.3, "meta_error": "", "ambiguous_endpoints": 2,
                               "unmodelled_endpoints": True, "capture_enabled": True,
                               "asn": {"sha": "abc", "ranges": 5, "stale": True},
                               "threads": {"nqmo-cap": {"alive": True, "healthy": True},
                                           "nqmo-ring": {"alive": True, "healthy": False},
                                           "‮bad": {"healthy": True}, "nqmo-x": "junk",
                                           "nqmo-y": {"healthy": "yes"}}})
        st["store"]["recreated"] = True
        self.state = st
        view = self.post("/api/nqmo/status", user="nview")[1]["nqmo"]
        self.assertEqual(view["promotion"], {"data_days": 3.46, "shadow_high_7d": 3,
                                             "days_required": m.NQMO_PROMOTION_DAYS})
        self.assertEqual(len(view["errors"]), m.NQMO_STATUS_ERRORS)
        self.assertEqual(view["errors"][-1], {"ts": NOW, "where": "evil"})    # bidi stripped
        self.assertTrue(all("error" not in e for e in view["errors"]))          # text: detail only
        self.assertEqual(view["probe"], {"running": True, "run_id": 7})
        self.assertEqual(view["last_window"], NOW - 400)
        cov = view["coverage"]
        self.assertEqual((cov["meta_age_s"], cov["meta_error"], cov["ambiguous_endpoints"],
                          cov["unmodelled_endpoints"], cov["asn_stale"], cov["capture_enabled"]),
                         (12.3, False, 2, None, True, True))
        self.assertEqual(cov["threads"], {"nqmo-cap": True, "nqmo-ring": False, "bad": True})
        self.assertEqual(view["store"]["recreated"], True)
        detail = self.post("/api/nqmo/status", user="ndetail")[1]["nqmo"]
        self.assertIn("locked", detail["errors"][0]["error"])
        self.assertNotIn("locked", json.dumps(view))
        # meta_error is a string with content ⇒ True; a missing probe ⇒ None
        st["coverage"]["meta_error"] = "could not read /run/wg-panel/nqmo-meta.json"
        del st["probe"]
        self.state = st
        view = self.post("/api/nqmo/status", user="nview")[1]["nqmo"]
        self.assertEqual((view["coverage"]["meta_error"], view["probe"]), (True, None))
        self.assertNotIn("nqmo-meta.json", json.dumps(view))
        # the bare document of an older engine: every new field is empty, nothing raises
        self.state = self.full_state()
        view = self.post("/api/nqmo/status", user="nview")[1]["nqmo"]
        self.assertEqual((view["promotion"], view["errors"], view["probe"], view["last_window"],
                          view["coverage"]["threads"], view["coverage"]["meta_age_s"],
                          view["store"]["recreated"]), (None, [], None, None, {}, None, None))
        # junk in each new field
        st = self.full_state()
        st.update(promotion="x", errors={"a": 1}, probe=[1], last_window="soon")
        st["coverage"]["threads"] = [1, 2]
        self.state = st
        view = self.post("/api/nqmo/status", user="nview")[1]["nqmo"]
        self.assertEqual((view["promotion"], view["errors"], view["probe"], view["last_window"],
                          view["coverage"]["threads"]), (None, [], None, None, {}))
        # a running probe with no id, and a promotion with only the days
        st["probe"], st["promotion"] = {"running": False, "run_id": -3}, {"data_days": -2}
        self.state = st
        view = self.post("/api/nqmo/status", user="nview")[1]["nqmo"]
        self.assertEqual(view["probe"], {"running": False, "run_id": None})
        self.assertEqual(view["promotion"], {"data_days": 0.0, "shadow_high_7d": None,
                                             "days_required": m.NQMO_PROMOTION_DAYS})

    def test_peer_lookup_is_exact_and_ambiguity_is_refused(self):
        _, r = self.post("/api/nqmo/peer", {"name": "alice"})
        p = r["peer"]
        self.assertEqual([d["id"] for d in p["diagnoses"]], [11])
        self.assertEqual(p["summary"]["rtt_n"], 15)
        self.assertEqual(p["recommendations"][0]["status"], "UNDETERMINED")
        self.assertNotIn("junk", p["recommendations"][0])
        self.assertEqual([a["finding"] for a in p["advisories"]], ["CONFIG_MISMATCH"])
        for body in ({"name": "bob"}, {"name": "mallory"}, {"name": ""}, {"name": 7},
                     {"name": "x" * 65}, {}, {"name": "alice", "iface": "wg2"}):
            with self.subTest(body=body):
                self.assertEqual(self.post("/api/nqmo/peer", body)[1]["error"],
                                 self.E("api.err.nqmo.no_peer"))
        # bob exists on two ifaces: by iface it resolves, but a name-only
        # advisory cannot be attributed and is withheld
        p = self.post("/api/nqmo/peer", {"name": "bob", "iface": "wg2"})[1]["peer"]
        self.assertEqual(p["advisories"], [])

    def test_events_page_in_order_without_unknown_peers(self):
        _, r = self.post("/api/nqmo/events")
        self.assertEqual([(e["id"], e.get("peer")) for e in r["events"]],
                         [(1, "alice"), (3, "bob"), (4, "alice")])
        self.assertEqual([e["id"] for e in self.post("/api/nqmo/events",
                                                     {"since": 1, "limit": 1})[1]["events"]],
                         [3])
        for body in ({"since": -1}, {"since": "1"}, {"since": True}, {"limit": 0},
                     {"limit": 201}, {"limit": 2.0}):
            with self.subTest(body=body):
                self.assertEqual(self.post("/api/nqmo/events", body)[1]["error"],
                                 self.E("api.err.nqmo.bad_page"))

    def test_hostile_state_never_raises_and_every_string_is_clean(self):
        rnd = random.Random(808)
        atoms = [None, True, 0, -1, 2 ** 70, 1.5, float("nan"), float("inf"), "",
                 "PACKET_LOSS", "PEER", "alice", "wgtest", "HIGH", "nqmo.alert.open",
                 "a‮b\x1b[31m" + "z" * 300, [], {}]
        keys = ["available", "why", "mode", "diagnoses", "notify_outbox", "peers",
                "recommendations", "advisories", "correlations", "collectors", "coverage",
                "store", "id", "class", "scope", "peer", "iface", "subject", "confidence",
                "evidence", "metric", "value", "params", "text_key", "window", "rtt_n",
                "quality", "loss_point", "generated_at", "wgtest/alice",
                "promotion", "data_days", "shadow_high_by_peer_7d", "errors", "where",
                "error", "probe", "running", "run_id", "last_window", "threads", "healthy",
                "meta_error", "meta_age_s", "asn", "stale", "recreated"]

        def junk(d=0):
            r = rnd.random()
            if d > 4 or r < 0.4:
                return rnd.choice(atoms)
            if r < 0.65:
                return [junk(d + 1) for _ in range(rnd.randrange(5))]
            return {rnd.choice(keys): junk(d + 1) for _ in range(rnd.randrange(7))}
        bad = re.compile("[\x00-\x09\x0b-\x1f‪-‮⁦-⁩]")
        for i in range(300):
            st = dict(self.full_state(), **{rnd.choice(keys): junk()
                                           for _ in range(rnd.randrange(1, 6))})
            if i % 4 == 0:
                st = junk() if isinstance(junk(), dict) else {"available": True}
            self.state = st if isinstance(st, dict) else {}
            for path, body in (("/api/nqmo/status", {}), ("/api/nqmo/peer", {"name": "alice"}),
                               ("/api/nqmo/events", {})):
                for user in ("nview", "ndetail"):
                    with self.subTest(i=i, path=path, user=user):
                        code, r = self.post(path, body, user=user)
                        self.assertEqual(code, 200)
                        out = json.dumps(r, allow_nan=False, ensure_ascii=False)
                        self.assertIsNone(bad.search(out), out[:200])
                        for s in re.findall(r'"((?:[^"\\]|\\.)*)"', out):
                            self.assertLessEqual(len(s), 210)

    # ---- P5: commands over ctl.sock --------------------------------------------------

    def test_refusal_vocabulary_covers_every_code_the_engine_can_send(self):
        codes = set()
        for f in ("ctl.py", "analysis.py", "engine.py"):
            with open(os.path.join(os.path.dirname(nqmo.__file__), f), encoding="utf-8") as fh:
                codes |= set(re.findall(r'"refused":\s*"([A-Z_]+)"', fh.read()))
            with open(os.path.join(os.path.dirname(nqmo.__file__), f), encoding="utf-8") as fh:
                codes |= set(re.findall(r'^\s+return "([A-Z_]+)"$', fh.read(), re.M))
        self.assertGreaterEqual(len(codes), 20)
        self.assertLessEqual(codes, set(self.m.NQMO_REFUSALS), codes - set(self.m.NQMO_REFUSALS))
        self.assertEqual(self.m.NQMO_CTL_PATH.endswith("c.sock"), True)
        from nqmo import ctl
        self.assertGreater(self.m.NQMO_CTL_TIMEOUT, ctl.Server.REPLY_TIMEOUT)
        self.assertEqual(self.m.NQMO_CTL_MAX, ctl.MAX_REQ)
        self.assertEqual(twp.load_module(self.tmp).NQMO_CTL_PATH,
                         nconfig.DEFAULTS["paths"]["ctl"])
        self.assertEqual(tuple(self.m.NQMO_LEVELS), tuple(__import__(
            "nqmo.confidence", fromlist=["x"]).LEVELS))

    def test_ack_through_the_real_engine_socket_is_audited_either_way(self):
        e = self.engine()
        self.assertEqual(self.post("/api/nqmo/ack", {"id": 5})[1], {"ok": True})
        self.assertEqual(self.post("/api/nqmo/ack", {"id": 6})[1],
                         {"ok": False, "error": self.E("api.err.nqmo.refused"),
                          "refused": "NO_SUCH_OPEN_DIAGNOSIS"})
        self.assertEqual(e.calls, [("ack", 5, "admin"), ("ack", 6, "admin")])
        self.assertEqual([(a[0], a[1], a[2], a[3], a[6]) for a in self.audits],
                         [("admin", "settings", "nqmo.ack", "5", True),
                          ("admin", "settings", "nqmo.ack", "6", False)])
        self.assertIn("NO_SUCH_OPEN_DIAGNOSIS", self.audits[1][4])
        self.assertEqual(len([x for x in self.logs if x.startswith("nqmo ack")]), 2)
        n_calls = len(e.calls)
        e.uid = 1000                                    # the panel is not root
        self.assertEqual(self.post("/api/nqmo/ack", {"id": 5})[1]["refused"], "NO_REPLY")
        e.uid = 0
        for bad in (0, -1, True, "5", 5.0, None, 2 ** 53):
            with self.subTest(id=bad):
                self.assertEqual(self.post("/api/nqmo/ack", {"id": bad})[1]["error"],
                                 self.E("api.err.nqmo.bad_id"))
        self.assertEqual(len(e.calls), n_calls)

    def test_mode_moves_one_step_and_both_sides_refuse_a_jump(self):
        e = self.engine(mode="OBSERVATION_ONLY")
        self.assertEqual(self.post("/api/nqmo/mode")[1],
                         {"ok": True, "mode": "OBSERVATION_ONLY"})
        self.assertEqual(self.post("/api/nqmo/mode", {"to": "RECOMMENDATIONS_ENABLED"})[1],
                         {"ok": False, "error": self.E("api.err.nqmo.refused"),
                          "refused": "NOT_ADJACENT"})
        self.assertEqual(e.calls, [])
        # the panel refused first: no mode.set ever reached the engine
        self.assertNotIn(("mode.set", "RECOMMENDATIONS_ENABLED"), e.ops)
        self.assertEqual(self.post("/api/nqmo/mode", {"to": "DIAGNOSTICS_ENABLED"})[1],
                         {"ok": True, "mode": "DIAGNOSTICS_ENABLED"})
        self.assertEqual(e.calls, [("mode.set", "DIAGNOSTICS_ENABLED", "admin")])
        # and the engine refuses a jump on its own (defence in depth)
        self.assertEqual(self.m.nqmo_ctl({"v": 1, "op": "mode.set", "to": "OBSERVATION_ONLY",
                                          "actor": "x"})["ok"], True)
        self.assertEqual(self.m.nqmo_ctl({"v": 1, "op": "mode.set",
                                          "to": "RECOMMENDATIONS_ENABLED", "actor": "x"}),
                         {"ok": False, "refused": "NOT_ADJACENT"})
        for bad in ("observation_only", "", 3, ["OBSERVATION_ONLY"]):
            with self.subTest(to=bad):
                self.assertEqual(self.post("/api/nqmo/mode", {"to": bad})[1]["error"],
                                 self.E("api.err.nqmo.bad_mode"))
        acts = [(a[2], a[3], a[6]) for a in self.audits]
        self.assertEqual(acts, [("nqmo.mode", "RECOMMENDATIONS_ENABLED", False),
                                ("nqmo.mode", "DIAGNOSTICS_ENABLED", True)])

    def test_probe_resolves_the_panel_peer_and_never_sends_an_ambiguous_name(self):
        refusals = iter([{"ok": False, "refused": "MODE_GATE"}])
        e = self.engine(probe=lambda peer, actor: next(refusals, {"ok": True, "run_id": 9}))
        self.assertEqual(self.post("/api/nqmo/probe", {"name": "alice"})[1],
                         {"ok": False, "error": self.E("api.err.nqmo.refused"), "refused": "MODE_GATE"})
        self.assertEqual(self.post("/api/nqmo/probe", {"name": "alice"})[1],
                         {"ok": True, "run_id": 9})
        self.assertEqual(self.post("/api/nqmo/probe", {"name": "bob", "iface": "wg2"})[1],
                         {"ok": False, "error": self.E("api.err.nqmo.refused"),
                          "refused": "AMBIGUOUS_PEER"})
        self.assertEqual(self.post("/api/nqmo/probe", {"name": "mallory"})[1]["error"],
                         self.E("api.err.nqmo.no_peer"))
        self.assertEqual([(a[2], a[3], a[6]) for a in self.audits],
                         [("nqmo.probe", "wgtest/alice", False),
                          ("nqmo.probe", "wgtest/alice", True),
                          ("nqmo.probe", "wg2/bob", False)])
        self.assertEqual(e.calls, [])          # the fake probe callback logs nothing itself

    def test_a_broken_or_hostile_engine_reply_is_never_trusted(self):
        m = self.m
        req = {"v": 1, "op": "mode.get"}
        self.assertEqual(m.nqmo_ctl(req), {"ok": False, "refused": "UNREACHABLE"})
        cases = [(b"not json\n", "BAD_REPLY"), (b"[1,2]\n", "BAD_REPLY"),
                 (b'{"ok": 1}\n', "BAD_REPLY"), (b"", "NO_REPLY"),
                 (b'{"ok": false, "refused": "PWNED"}\n', "UNKNOWN"),
                 (b'{"ok": false, "refused": ["MODE_GATE"]}\n', "UNKNOWN"),
                 (b"{" * 100000 + b"\n", "BAD_REPLY"),
                 (b'{"ok": false}' + b" " * 70000 + b"\n", "BAD_REPLY")]
        for raw, want in cases:
            with self.subTest(raw=raw[:30]):
                stop = _fake_ctl(m.NQMO_CTL_PATH, raw)
                try:
                    self.assertEqual(m.nqmo_ctl(req), {"ok": False, "refused": want})
                finally:
                    stop()
                    os.unlink(m.NQMO_CTL_PATH)
        stop = _fake_ctl(m.NQMO_CTL_PATH, b'{"ok": true, "mode": "ROOT", "run_id": "7", '
                                           b'"evil": "<script>"}\n')
        try:
            self.assertEqual(m.nqmo_ctl(req), {"ok": True})
        finally:
            stop()
            os.unlink(m.NQMO_CTL_PATH)
        m.NQMO_CTL_TIMEOUT = 0.3
        stop = _fake_ctl(m.NQMO_CTL_PATH, b'{"ok": true}\n', delay=1.0)
        try:
            self.assertEqual(m.nqmo_ctl(req), {"ok": False, "refused": "TIMEOUT"})
        finally:
            stop()



# ---- P7–P8: the «connection quality» UI ---------------------------------------------

PAGE = os.path.join(HERE, "..", "wgpanel", "web", "page.html")
RENDER = os.path.join(HERE, "js", "nqmo-render.mjs")


def _engine_src(*names):
    out = ""
    for f in names:
        with open(os.path.join(os.path.dirname(nqmo.__file__), f), encoding="utf-8") as fh:
            out += fh.read()
    return out


class NqmoUiVocabTests(unittest.TestCase):
    """P8: every engine word the UI translates has exactly one key per vocabulary code.

    Family guard: a key family `ui.nqmo.<f>.*` must equal the server's closed
    vocabulary (or, where the panel does not filter, the codes the engine source
    can write). A code added on either side without its key turns red here, not
    as raw Latin in the browser; a key without a code is dead weight. And the UI
    may use no family this test does not guard."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nqmo-ui-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.m = twp.load_module(self.tmp)
        with open(PAGE, encoding="utf-8") as fh:
            self.page = fh.read()

    def families(self):
        m = self.m
        diag_src, rec_src = _engine_src("diagnose.py"), _engine_src("recommend.py", "analysis.py")
        return {
            "cls": set(m.NQMO_CLASSES), "lv": set(m.NQMO_LEVELS), "q": set(m.NQMO_PEER_QUALITY),
            "mtu": set(m.NQMO_MTU_STATUS), "md": set(m.NQMO_MODES), "why": set(m.NQMO_STATE_WHY),
            "ref": set(m.NQMO_REFUSALS), "scope": set(m.NQMO_SCOPES),
            "dq": set(m.NQMO_DATA_QUALITY),
            "cause": set(m.NQMO_CORR_CAUSES),
            "act": set(m.NQMO_CLASSES),              # §29.154: one action hint per class
            "ev": {k.rsplit(".", 1)[1] for k in m.NQMO_NOTIFY_KEYS} | {"stale"},
            "find": set(re.findall(r'"finding":\s*"([A-Z_]+)"', diag_src)),
            "tgt": set(re.findall(r'"target":\s*"([A-Z_]+)"', rec_src)),
        }

    def test_each_key_family_equals_its_vocabulary(self):
        fams = self.families()
        self.assertGreaterEqual(len(fams["find"]), 4)
        self.assertGreaterEqual(len(fams["tgt"]), 2)
        for f, vocab in fams.items():
            with self.subTest(family=f):
                pre = "ui.nqmo.%s." % f
                keys = {k[len(pre):] for k in self.m.I18N if k.startswith(pre)}
                self.assertEqual(keys, vocab, "%s: missing %s, extra %s"
                                 % (f, sorted(vocab - keys), sorted(keys - vocab)))

    def test_engine_statuses_shown_with_the_mtu_family_are_all_translated(self):
        # recommendation and advisory statuses are rendered with ui.nqmo.mtu.*
        src = _engine_src("diagnose.py", "recommend.py", "analysis.py")
        statuses = set(re.findall(r'"status":\s*"([A-Z_]+)"', src))
        self.assertGreaterEqual(len(statuses), 3)
        self.assertLessEqual(statuses, set(self.m.NQMO_MTU_STATUS))

    def test_the_ui_uses_only_guarded_families(self):
        used = set(re.findall(r"(?:_tk|nqmoChip)\('ui\.nqmo\.([a-z]+)\.'", self.page))
        self.assertEqual(used, set(self.families()))
        # no other way of building a ui.nqmo key at run time
        self.assertEqual(re.findall(r"_t\(\s*'ui\.nqmo\.[\w.]*'\s*\+", self.page), [])

    def test_js_mode_ladder_is_the_server_ladder(self):
        mo = re.search(r"^const NQMO_MODES = \[([^\]]*)\];", self.page, re.M)
        self.assertIsNotNone(mo)
        self.assertEqual(tuple(re.findall(r"'([A-Z_]+)'", mo.group(1))), self.m.NQMO_MODES)

    def test_every_nqmo_surface_is_gated_by_the_server_flag(self):
        """Family guard: with nqmo.enabled off the page shows no trace of WG-NQMO.

        The design (05 §5.1) promises byte-identical behaviour with the flag off, and the
        public tree ships these hooks without the engine. So every place that shows
        WG-NQMO asks nqmoSeen() (flag and permission) or hides its 'nqmo' entry when
        myNqmo is false. can('nqmo.view') alone appears nowhere else."""
        page = self.page
        self.assertIn("function nqmoSeen(){ return myNqmo && can('nqmo.view'); }", page)
        self.assertEqual(page.count("can('nqmo.view')"), 1)
        role = page[page.index("function applyRole("):]
        role = role[:role.index("\n}\n")]
        self.assertIn("myNqmo = me.nqmo === true;", role)
        self.assertIn("const nqv = nqmoSeen();", role)
        for i in ("nqmo-admin", "nqmo-admin2"):
            self.assertIn("el('%s').classList.toggle('hidden', !nqv);" % i, role)
            self.assertRegex(page, r'id="%s" class="[^"]*\bhidden\b' % i)   # hidden until applyRole
        edit = page[page.index("function showEditModal("):]
        edit = edit[:edit.index("\n}\n")]
        self.assertIn("(nqmoSeen() ? '<div id=\"e-nqmo\"></div>' : '')", edit)
        self.assertIn("if(nqmoSeen()) nqmoFillPeer('e-nqmo', iface, name, true);", edit)
        for fn in ("loadNqmo", "nqmoSchedule"):
            body = page[page.index("function %s(" % fn):][:200]
            self.assertIn("if(!nqmoSeen()) return;", body, fn)
        # every 'nqmo' entry of a server list (perm group, alert kind) is hidden by class
        # with the flag off; never filtered out, so saving keeps the stored value
        hits = re.findall(r"(\w+(?:\.\w+)?) === 'nqmo'( && !myNqmo \? ' hidden' : '')?", page)
        self.assertEqual(sorted(h[0] for h in hits), ["e.key", "g.group"])
        self.assertTrue(all(h[1] for h in hits), hits)
        self.assertNotRegex(page, r"\.filter\([^)]*nqmo")
        # the server lists those entries are drawn from
        self.assertIn("nqmo", self.m.ALERT_EVENT_KEYS)
        self.assertIn("nqmo", {g for g, _, _ in self.m.PERM_CATALOG})
        # forced-TOTP mode hides every admin section, this one included
        totp = page[page.index("function forceTotpSetup("):][:600]
        self.assertIn("#nqmo-admin2", totp)

    def test_each_command_function_checks_its_own_permission(self):
        for fn, perm in (("nqmoAck", "nqmo.ack"), ("nqmoAckAll", "nqmo.ack"),
                         ("nqmoProbe", "nqmo.probe"), ("nqmoSetMode", "nqmo.manage")):
            body = self.page[self.page.index("async function %s(" % fn):][:400]
            with self.subTest(fn=fn):
                self.assertIn("can('%s')" % perm, body.split("\n", 3)[1] + body.split("\n", 3)[2])

    def test_disabled_flag_has_a_stable_code_the_ui_reads(self):
        self.assertIn("r.disabled", self.page)
        self.assertIn('"error": "api.err.nqmo.disabled", "disabled": True', panel_source())


@unittest.skipUnless(shutil.which("node"), "node is not installed")
@unittest.skipUnless(os.path.exists(RENDER), "tests/js/ is not in the public tree "
                     "(its helpers need a maintainer-only inline-JS extractor)")
class NqmoUiRenderTests(unittest.TestCase):
    """P7 end to end: real /api/nqmo/* answers, rendered by page.html's own functions.

    The documents come from the real HTTP handler (RBAC, cleaning, translation),
    then tests/js/nqmo-render.mjs renders them with the functions it slices out
    of page.html and the real catalog. So a field renamed on one side, a key
    missing in one language, a leak past the view/detail boundary or a value
    that becomes markup is caught where the user would see it."""

    KNOWN = NqmoApiTests.KNOWN
    setUp = NqmoApiTests.setUp
    full_state = NqmoApiTests.full_state
    post = NqmoApiTests.post
    PERMS_OF = {"admin": ["nqmo.view", "nqmo.detail", "nqmo.ack", "nqmo.probe", "nqmo.manage"],
                "ndetail": ["nqmo.view", "nqmo.detail"], "nview": ["nqmo.view"]}

    def docs(self, user):
        out = {}
        for key, path, body in (("status", "/api/nqmo/status", {}),
                                ("peer", "/api/nqmo/peer", {"iface": "wgtest", "name": "alice"}),
                                ("events", "/api/nqmo/events", {})):
            code, r = self.post(path, body, user=user)
            self.assertEqual(code, 200)
            out[key] = r.get({"status": "nqmo"}.get(key, key)) if r.get("ok") else None
        return out

    def render(self, jobs):
        import subprocess
        p = subprocess.run(["node", RENDER], input=json.dumps(jobs).encode(),
                           capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr.decode()[-2000:])
        return json.loads(p.stdout)

    def job(self, user, lang="fa", **extra):
        return dict(self.docs(user), lang=lang, perms=self.PERMS_OF[user], **extra)

    @staticmethod
    def text(r):
        return "".join(v or "" for v in r.values())

    def test_real_documents_render_in_four_languages_with_their_numbers(self):
        out = self.render([self.job("admin", lang) for lang in ("fa", "en", "ru", "zh")])
        for lang, r in zip(("fa", "en", "ru", "zh"), out):
            with self.subTest(lang=lang):
                html = self.text(r)
                self.assertNotIn("ui.nqmo.", html)
                self.assertNotIn("⟦", html)
                self.assertIn(self.m.t("ui.nqmo.cls.PACKET_LOSS", lang), html)
                self.assertIn(self.m.t("ui.nqmo.md.DIAGNOSTICS_ENABLED", lang), html)
                self.assertIn(self.m.t("ui.nqmo.find.NESTED_MTU_MISMATCH", lang), html)
                self.assertIn("40 ms", r["rows"])            # rtt_ms_med from peers
                self.assertIn("3.00%", r["rows"])            # loss_point 0.03
                self.assertIn("showNqmoPeer(0)", r["rows"])
                self.assertIn("C1_meta", r["status"])
                if lang != "fa":
                    self.assertEqual(re.findall(r"[؀-ۿ]{3,}", html), [])

    def test_view_role_render_carries_no_prefix_or_asn(self):
        view, detail = self.render([self.job("nview"), self.job("ndetail")])
        self.assertNotIn("198.51.100", self.text(view))
        self.assertIn("198.51.100", self.text(detail))       # correlations, full evidence
        self.assertNotIn("mallory", self.text(view) + self.text(detail))

    def test_command_buttons_follow_the_viewers_permissions(self):
        view, admin = self.render([self.job("nview"), self.job("admin")])
        for fn in ("nqmoAck(", "nqmoProbe(", "nqmoSetMode("):
            self.assertNotIn(fn, self.text(view))
            self.assertIn(fn, self.text(admin))
        self.assertIn("nqmoAck(11)", admin["peer"])
        self.assertEqual(sorted(set(re.findall(r"nqmoSetMode\('([A-Z_]+)'\)", admin["status"]))),
                         ["OBSERVATION_ONLY", "RECOMMENDATIONS_ENABLED"])

    def test_hostile_state_renders_inert(self):
        evil = '<img src=x onerror=alert(1)>"\'‮'
        st = self.full_state()
        st["diagnoses"][0]["acked_by"] = evil
        st["diagnoses"][0]["evidence"].append({"metric": evil, "value": evil, evil: evil})
        st["diagnoses"][2]["subject"] = evil
        st["advisories"].append({"scope": "SERVER_TUNNEL", "subject": evil, "finding": evil,
                                 "status": evil, evil: [evil, 1]})
        st["correlations"] = [{evil: evil}]
        st["recommendations"]["wgtest/alice"][0].update(rationale=[evil], current_source=evil,
                                                        target=evil, suggested_value=evil)
        self.state = st
        jobs = [self.job(u, lang) for u in ("admin", "ndetail", "nview") for lang in ("fa", "en")]
        # and 150 random states (the API's own fuzz atoms), batched into one node run
        rnd = random.Random(1101)
        atoms = [None, True, 0, -1, 2 ** 60, 1.5, "", evil, "PACKET_LOSS", "HIGH", [], {}]
        keys = ["available", "why", "mode", "diagnoses", "peers", "advisories", "correlations",
                "collectors", "coverage", "store", "subject", "evidence", "acked_by",
                "recommendations", "notify_outbox"]
        for i in range(150):
            st2 = self.full_state()
            for _ in range(rnd.randrange(1, 5)):
                st2[rnd.choice(keys)] = rnd.choice(atoms + [[{rnd.choice(keys): rnd.choice(atoms)}]])
            self.state = st2
            jobs.append(self.job(rnd.choice(["admin", "nview"]), rnd.choice(["fa", "en"])))
        on = re.compile(r"^onclick=\"(nqmoAck\(\d+\)|nqmoSetMode\('[A-Z_]+'\)|nqmoProbe\(\)|"
                        r"showNqmoPeer\(\d+\);return false)\"$")
        for i, r in enumerate(self.render(jobs)):
            html = self.text(r)
            with self.subTest(job=i):
                self.assertNotRegex(html, r"<(img|script)", html[:300])
                self.assertNotIn("‮", html)                 # cleaned by the server
                for b in re.findall(r'onclick="[^"]*"', html):
                    self.assertRegex(b, on)


if __name__ == "__main__":
    unittest.main()
