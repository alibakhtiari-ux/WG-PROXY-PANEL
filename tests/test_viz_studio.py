# -*- coding: utf-8 -*-
"""گاردهای «نقشه و گزارش»: مدل‌های SvgStudio (wgpanel/viz.py)، کارپوشه‌ی Excel
(wgpanel/report.py + wgpanel/xlsx.py)، چسبِ مرورگر (web/studio.js) و endpointها.

هر کلاس یک **خانواده** را می‌گیرد، نه یک نمونه:
  - امضای ترافیک: هر کد با ورودیِ نمونه‌اش، و NAT فقط با هندشیکِ کهنه؛
  - چیدمانِ نقشه: هیچ دو گره روی هم نیستند، هر یال دو سرِ موجود دارد و هر گره کشو دارد؛
  - کاتالوگ: هر کلیدی که سه مدل و کارپوشه در هر چهار زبان می‌سازند وجود دارد و
    هیچ «{جای‌گیر}» ِ پرنشده‌ای در خروجی نمی‌ماند؛
  - xlsx: همه‌ی XMLها خوش‌ساخت، اولویتِ قالبِ شرطی عددی و یکتا (یک بار
    «%1%» اکسلِ مک را بی‌صدا از بازکردن انداخت)، متنِ «=…» ِ کاربر فرمول نمی‌شود؛
  - RBAC: چهار endpoint نگاشت دارند و کتاب فقط برگه‌های مجازِ همان کاربر را دارد.
"""
import importlib.util
import io
import json
import os
import re
import unittest
import zipfile
from xml.etree import ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG = os.path.join(ROOT, "wgpanel")
WEB = os.path.join(PKG, "web")
LANGS = ("fa", "en", "ru", "zh")
NOW = 1_800_000_000.0
MINIFIED = "minified at publish time"     # نشانه‌ی publish/make-public.sh (گامِ ۴ت)


def _web(name):
    """متنِ یک فایلِ web/؛ در کپیِ عمومی که minify شده، گاردهای متن‌خوان skip می‌گیرند
    (همان گاردها در مخزنِ خصوصی روی سورسِ خوانا اجرا می‌شوند)."""
    with open(os.path.join(WEB, name), encoding="utf-8") as f:
        txt = f.read()
    if MINIFIED in txt[:200]:
        raise unittest.SkipTest("%s در انتشار minify شده" % name)
    return txt

PERSIAN = re.compile(r"[؀-ۿ]")


def _load(name):
    spec = importlib.util.spec_from_file_location("wgpanel_t_" + name, os.path.join(PKG, name + ".py"))
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


V = _load("viz")
XL = _load("xlsx")
R = _load("report")
with open(os.path.join(PKG, "i18n", "catalog.json"), encoding="utf-8") as _f:
    CAT = json.load(_f)


class _Tr:
    """t() ِ کاتالوگ با ضبطِ کلیدهای گم‌شده و جای‌گیرهای پرنشده."""

    def __init__(self, lang):
        self.i = LANGS.index(lang)
        self.missing, self.unfilled = set(), set()

    def __call__(self, k, **kw):
        row = CAT.get(k)
        if row is None:
            self.missing.add(k)
            return k
        s = row[self.i] if self.i < len(row) and row[self.i] != "" else row[0]
        try:
            s = s.format(**kw)
        except (KeyError, IndexError, ValueError):
            self.unfilled.add(k)
        return s


def _tun(i, dev, h="healthy", rx=5000, tx=800, active=True, hs=20):
    return {"iface": i, "active": active, "enabled": True, "kind": "wireguard",
            "endpoint": "203.0.113.%d:51820" % (len(i) * 7), "loop_dev": dev, "handshake": NOW - hs,
            "rx": 10 ** 8, "tx": 10 ** 7, "rx_rate": rx, "tx_rate": tx, "health": h, "keepalive": "25",
            "hist": [{"rx_rate": rx, "tx_rate": tx}] * 10}


def egress_facts():
    return {
        "wan": "eth0",
        "users": {"total": 15, "online": 7, "disabled": 2},
        "ingress": [{"iface": "wgin", "peers": 12, "online": 6, "rx_rate": 1e5, "tx_rate": 2e6,
                     "subnet": "10.8.0.0/24", "ks": True},
                    {"iface": "eth1", "peers": 0, "online": 1, "rx_rate": 0, "tx_rate": 0,
                     "subnet": "192.0.2.0/24", "ks": True}],
        "ks": {"rules": 8, "ifaces": ["wgin", "eth1"]},
        "tunnels": [_tun("mom1", "eth0"), _tun("mom2", "eth0"), _tun("sub1", "mom1"),
                    _tun("sub2", "mom2", "dead", 0, 30, hs=900), _tun("chain0", "sub1", "chain"),
                    _tun("pool1", "mom1"), _tun("pool2", "mom2"), _tun("spare", "eth0", "off", active=False),
                    dict(_tun("unused", "eth0", "off", active=False), enabled=False)],
        "ecmp": {"enabled": True, "groups": [{"name": "grp", "tunnels": ["sub1", "sub2"],
                                              "member": {"sub1": "in", "sub2": "out"}, "probe": "198.51.100.1"}]},
        "default": [{"probe": "1.0.0.1", "dev": "mom1"}, {"probe": "149.112.112.112", "dev": "mom2"}],
        "sni": {"enabled": True, "active": True, "healthy": True, "hb_age": 3, "tproxy": True,
                "unit_active": True, "quic_active": True},
        "ai": {"main": "pool1", "pool": [{"dev": "pool1", "up": True, "burned": False},
                                         {"dev": "pool2", "up": True, "burned": True}]},
        "warp": {"iface": "chain0", "up": True, "handshake": NOW - 30, "egress": "sub1",
                 "guard_alive": True, "healthy": True}}


def trace_facts(user, decisions=None, can_tun=True):
    F = egress_facts()
    return {"user": user, "ip": "10.8.0.11", "ingress": {"iface": "wgin", "ks": True},
            "hist": user.get("hist") or [], "wan": "eth0", "can_tun": can_tun,
            "decisions": decisions if decisions is not None else [
                {"kind": "default", "probe": "1.0.0.1", "dev": "mom1"},
                {"kind": "ecmp", "probe": "198.51.100.1", "dev": "sub2", "group": "grp"},
                {"kind": "ai", "probe": "SNI · 443", "dev": "pool1"}],
            "tunnels": {t["iface"]: t for t in F["tunnels"]} if can_tun else {}}


def _user(**kw):
    u = {"name": "phone-1", "iface": "wgin", "enabled": True, "handshake": NOW - 600,
         "endpoint": "198.51.100.7:4000", "allowed_ips": "10.8.0.11/32", "rx": 1e6, "tx": 2e7,
         "rx_rate": 0, "tx_rate": 30, "month_rx": 1e9, "month_tx": 1e10,
         "hist": [{"rx_rate": 0, "tx_rate": 30}] * 12}
    u.update(kw)
    return u


def timeline_facts():
    t0 = NOW - 86400
    ev = [{"ts": NOW - 7200, "src": "audit", "subject": "sub2", "action": "tun.monitor.down",
           "detail": "", "sev": "bad", "actor": "sys:monitor"},
          {"ts": NOW - 3600, "src": "audit", "subject": "sub2", "action": "tun.monitor.up",
           "detail": "", "sev": "ok", "actor": "sys:monitor"},
          {"ts": NOW - 5000, "src": "nqmo", "subject": "", "action": "open", "title": "LOSS",
           "detail": "", "sev": "warn"},
          {"ts": NOW - 4000, "src": "warp", "subject": "", "action": "rotate", "detail": "ep", "sev": "info"},
          {"ts": NOW - 3000, "src": "guard", "subject": "mom1", "action": "guard.heal", "title": "heal",
           "detail": "roam heal applied", "sev": "warn", "actor": "tunnel-guard"},
          {"ts": NOW - 2900, "src": "guard", "subject": "", "action": "guard.pin", "title": "pin",
           "detail": "pin", "sev": "info", "actor": "tunnel-guard"}]
    return {"t0": t0, "t1": NOW, "events": ev, "tunnels": [
        {"iface": "mom1", "health": "healthy", "hours": [{"t": t0 + k * 3600, "bytes": 10 ** 8 * (k % 3)}
                                                         for k in range(24)]},
        {"iface": "sub2", "health": "dead", "hours": []}]}


def all_models(lang):
    tr = _Tr(lang)
    cx = V.Ctx(tr, fa=lang == "fa", rtl=lang == "fa", now=NOW)
    out = [V.egress_model(egress_facts(), cx), V.timeline_model(timeline_facts(), cx)]
    users = [_user(),                                                   # NAT
             _user(enabled=False), _user(auto_disabled="quota", enabled=False),
             _user(handshake=0), _user(hist=[], tx_rate=0),             # never / offline
             _user(handshake=NOW - 20, hist=[{"rx_rate": 900, "tx_rate": 90}] * 12)]
    for u in users:
        out.append(V.trace_model(trace_facts(u), cx))
        out.append(V.trace_model(trace_facts(u, can_tun=False), cx))
    out.append(V.trace_model(trace_facts(_user(handshake=NOW - 20), decisions=[]), cx))
    ok_dec = [{"kind": "default", "probe": "1.0.0.1", "dev": "mom1"}]
    out.append(V.trace_model(trace_facts(_user(handshake=NOW - 20, hist=[{"rx_rate": 900, "tx_rate": 90}] * 9),
                                         decisions=ok_dec), cx))
    return out, tr


class SignatureFamily(unittest.TestCase):
    def sig(self, kind, age, rx, tx, **kw):
        return V.signature(kind, age, rx, tx, **kw)[0]

    def test_every_code_has_its_canonical_input(self):
        tiny, heavy = [30] * 12, [50_000] * 12
        self.assertEqual(self.sig("peer", None, [], []), "never")
        self.assertEqual(self.sig("peer", 10, [0] * 12, [0] * 12, enabled=False), "disabled")
        self.assertEqual(self.sig("peer", 10, [900] * 12, tiny), "ok")
        self.assertEqual(self.sig("peer", 10, [0] * 12, tiny), "idle")
        self.assertEqual(self.sig("peer", 900, [0] * 12, tiny), "nat_expired")
        self.assertEqual(self.sig("peer", 900, [0] * 12, [0] * 12), "offline")
        self.assertEqual(self.sig("peer", 10, [0] * 12, heavy), "loop")
        self.assertEqual(self.sig("tunnel", 900, [0] * 12, tiny), "dead_ep")
        self.assertEqual(self.sig("tunnel", 10, [0] * 12, tiny, rx_total=148), "no_forward")
        self.assertEqual(self.sig("tunnel", 10, [800] * 12, tiny), "ok")

    def test_nat_needs_a_stale_handshake(self):
        """«tx ِ ریز بی rx» با هندشیکِ تازه همان پیرِ بیکارِ سالم است، نه NAT."""
        for age in (0, 30, V.ONLINE_AGE - 1):
            self.assertNotEqual(self.sig("peer", age, [0] * 12, [30] * 12), "nat_expired", age)

    def test_series_rates_accepts_every_sampler_shape(self):
        for h in ([[1, 2]] * 3, [(0, 1, 2)] * 3, [{"rx_rate": 1, "tx_rate": 2}] * 3):
            self.assertEqual(V.series_rates(h), ([1] * 3, [2] * 3))

    def test_verdict_family(self):
        """نخستین حلقه‌ی شکسته برنده است — ترتیبِ نگاه‌کردنِ عیب‌یابی."""
        dec = trace_facts(_user())["decisions"]
        u, off = _user(), _user(enabled=False)
        cases = [("auto", dict(off, auto_disabled="quota"), "ok", "sub2", True, dec),
                 ("disabled", off, "never", None, True, dec),
                 ("never", u, "never", "sub2", True, dec),
                 ("nat", u, "nat_expired", "sub2", True, dec),
                 ("offline", u, "offline", None, True, dec),
                 ("egress", u, "ok", "sub2", True, dec),
                 ("egress0", u, "ok", "sub2", False, dec),
                 ("noroute", u, "ok", None, True, []),
                 ("ok", u, "idle", None, True, dec)]
        for want, user, code, bad, can_tun, d in cases:
            self.assertEqual(V.trace_verdict(user, code, bad, can_tun, d), want, want)


class GuardLogFamily(unittest.TestCase):
    """هر خطِ لاگِ tunnel-guard یا رویدادِ خطِ زمانی است یا صریحاً نویز — خطِ تازه‌ای که
    به اسکریپت اضافه شود بی‌تصمیم از gantt جا نمی‌افتد."""
    NOISE = re.compile(r"صرف‌نظر|بودجه‌ی زمانی|آزمونِ نودِ|دور ریخته شد|می‌رود \(تونل‌درتونل\)")
    WANT = {"heal: تعویضِ listen-port ناموفق": "fail", "node heal: 9 -> 9 — داده رد شد": "heal",
            "هیچ‌کدام از 9 نامزد داده رد نکرد": "fail", "nested heal applied": "heal",
            "roam heal applied": "heal", "port-blackhole heal": "heal", "heal verified": "verified",
            "STATE up->down": "down", "STATE down->up": "up", "[route] پینِ": "pin"}

    def lines(self):
        p = os.path.join(ROOT, "deploy", "tunnel-guard.sh")
        if not os.path.exists(p):
            raise unittest.SkipTest("tunnel-guard.sh در این کپی نیست")
        with open(p, encoding="utf-8") as f:
            raw = [m.group(1) for m in (re.match(r'\s*log "(\[.*)"', x) for x in f) if m]
        sub = lambda m: "awg1" if m.group(0) in ("$ifc", "$IFACE") else "9"   # noqa: E731
        return [re.sub(r"\$\{[^}]*\}|\$[A-Za-z_]+", sub, x) for x in raw]

    def test_every_guard_line_is_classified_or_noise(self):
        lines = self.lines()
        self.assertGreater(len(lines), 20)
        for msg in lines:
            g = V.guard_event(msg)
            if g is None:
                self.assertRegex(msg, self.NOISE, "خطِ لاگِ بی‌تصمیم: " + msg)
            else:
                self.assertIsNone(self.NOISE.search(msg), "نویز رویداد شد: " + msg)
                self.assertIn(g[1], V.GUARD_KINDS)
        for frag, kind in self.WANT.items():
            hit = [V.guard_event(m) for m in lines if frag in m]
            self.assertTrue(hit, frag)
            self.assertEqual({h[1] for h in hit if h}, {kind}, frag)

    def test_guard_state_feeds_down_intervals(self):
        ev = [{"ts": NOW - 900, "subject": "mom1", "action": "guard.down"},
              {"ts": NOW - 300, "subject": "mom1", "action": "guard.up"}]
        self.assertEqual(V.down_intervals(ev, "mom1", NOW - 3600, NOW), [[NOW - 900, NOW - 300]])
        self.assertIsNone(V.guard_event("alert delivered via awg1"))     # بی‌پیشوندِ [iface]
        self.assertEqual(V.guard_event("[route] پینِ 1.2.3.4/32 via 9 dev eth0")[0], "")


class EgressLayout(unittest.TestCase):
    def setUp(self):
        self.X = V.egress_model(egress_facts(), V.Ctx(_Tr("fa"), fa=True, rtl=True, now=NOW))
        self.D = self.X["diagrams"][0]

    def test_no_two_nodes_share_a_cell(self):
        cells = {}
        for n in self.D["nodes"]:
            for c in range(n["c"], n["c"] + n.get("w", 1)):
                for r in range(n["r"], n["r"] + n.get("h", 1)):
                    self.assertNotIn((c, r), cells, "%s روی %s" % (n["id"], cells.get((c, r))))
                    cells[(c, r)] = n["id"]

    def test_edges_join_existing_nodes_and_every_node_has_a_drawer(self):
        ids = {n["id"] for n in self.D["nodes"]}
        for e in self.D["edges"]:
            self.assertIn(e["from"], ids)
            self.assertIn(e["to"], ids)
        for n in self.D["nodes"]:
            self.assertIn(n["id"], self.X["details"], n["id"])

    def test_nested_tunnel_sits_nearer_the_decision_than_its_carrier(self):
        col = {n["id"]: n["c"] for n in self.D["nodes"]}
        self.assertLess(col["t:sub1"], col["t:mom1"])
        self.assertLess(col["t:chain0"], col["t:sub1"])

    def test_pool_is_one_node_and_unused_off_tunnels_are_listed_not_drawn(self):
        ids = {n["id"] for n in self.D["nodes"]}
        self.assertIn("ai", ids)
        self.assertNotIn("t:pool2", ids)
        self.assertNotIn("t:unused", ids)
        self.assertIn("unused", self.X["details"]["route"]["html"])

    def test_ltr_mirrors_the_direction(self):
        X = V.egress_model(egress_facts(), V.Ctx(_Tr("en"), fa=False, rtl=False, now=NOW))
        self.assertEqual(X["diagrams"][0]["dir"], "ltr")
        self.assertEqual(self.D["dir"], "rtl")


class LabelMeaning(unittest.TestCase):
    """برچسبِ کشو باید با جنسِ مقدارش بخواند: «کلِ ترافیک» روی شمارِ کاربران نشسته بود
    (گرهِ Users: «Total traffic: 15»). هر ردیفِ k.total در هر مدل و هر زبان جفتِ بایتی است."""

    def test_total_traffic_rows_hold_a_byte_pair(self):
        for lang in LANGS:
            label = CAT["viz.k.total"][LANGS.index(lang)]
            models, _tr = all_models(lang)
            for m in models:
                for nid, d in (m.get("details") or {}).items():
                    for k, v in re.findall(r"<dt>(.*?)</dt><dd>(.*?)</dd>", d.get("html") or ""):
                        if k == label:
                            self.assertIn("↓", v, "%s · %s: %r" % (lang, nid, v))


class CatalogCoverage(unittest.TestCase):
    """هر کلیدی که مدل‌ها و کارپوشه در هر زبان می‌سازند باید باشد و پر شود."""

    def test_models_in_every_language(self):
        for lang in LANGS:
            models, tr = all_models(lang)
            self.assertEqual(tr.missing, set(), lang)
            self.assertEqual(tr.unfilled, set(), lang)
            blob = json.dumps(models, ensure_ascii=False)
            self.assertNotRegex(blob, r'"viz\.[a-z]', lang)
            if lang != "fa":
                self.assertIsNone(PERSIAN.search(blob.replace("ِ", "")), lang)

    def test_every_code_family_has_keys(self):
        fam = ["viz.h.%s" % h for h in R.HEALTH_CODES] + ["viz.hd.%s" % h for h in R.HEALTH_CODES]
        fam += ["viz.sig.%s" % s for s in R.SIG_CODES + ("down",)]
        fam += ["viz.sig.%s.t" % s for s in R.SIG_CODES + ("down",)]
        for v in ("auto", "disabled", "never", "nat", "offline", "egress", "egress0", "noroute", "ok"):
            fam += ["viz.v." + v, "viz.v.%s.t" % v]
        fam += ["viz.tone." + t for t in V.TONE_HEX]
        fam += ["viz.src." + s for s in V.EVENT_SRCS] + ["viz.d.src." + s for s in V.EVENT_SRCS]
        fam += ["viz.gd." + k for k in V.GUARD_KINDS]
        fam += ["xl.sev." + s for s in ("info", "ok", "warn", "bad")]
        for k in fam:
            self.assertIn(k, CAT, k)

    def test_workbook_in_every_language(self):
        for lang in LANGS:
            tr = _Tr(lang)
            cx = V.Ctx(tr, fa=lang == "fa", rtl=lang == "fa", now=NOW)
            R.build(report_facts_fixture(), cx, XL, V)
            self.assertEqual(tr.missing, set(), lang)

    def test_browser_keys_exist(self):
        js = _web("studio.js")
        for k in set(re.findall(r"_t\(['\"](ui\.[a-z0-9_.]+)['\"]", js)) - {"ui.ss."}:
            self.assertIn(k, CAT, k)
        ss = _web("svgstudio.js")
        m = re.search(r"var L0 = \{(.*?)\n\};", ss, re.S)
        self.assertIsNotNone(m)
        l0 = m.group(1) if m else ""
        for k in re.findall(r"(?:^|[{,]\s*)([A-Za-z0-9]+):\s*\"", l0, re.M):
            self.assertIn("ui.ss." + k, CAT, k)

    def test_page_markup_keys_exist(self):
        with open(os.path.join(WEB, "page.html"), encoding="utf-8") as f:
            page = f.read()
        for k in ("ui.viz.title", "ui.viz.badge", "ui.viz.tv"):
            self.assertIn(k, page)
            self.assertIn(k, CAT)


class EngineStaysGeneric(unittest.TestCase):
    """موتور عمومی است: متنِ رابطش فقط در L0، و هیچ شناسه‌ی این استقرار در فایل‌های تازه."""

    def test_engine_has_no_persian_outside_its_string_table(self):
        ss = _web("svgstudio.js")
        code = re.sub(r"var L0 = \{.*?\n\};", "", ss, flags=re.S)
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
        code = "\n".join(ln.split("//", 1)[0] for ln in code.splitlines())
        # تنها ارقامِ فارسی (برای faNum) مجازند
        self.assertIsNone(re.search(r"[؀-ۯۺ-ۿ]", code.replace("۰۱۲۳۴۵۶۷۸۹", "")))

    def test_glue_has_no_hardcoded_persian(self):
        js = _web("studio.js")
        code = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
        code = "\n".join(ln.split("//", 1)[0] for ln in code.splitlines())
        self.assertIsNone(PERSIAN.search(code))

    def test_no_private_identifier_in_new_files(self):
        p = os.path.join(ROOT, "publish", "private-identifiers.txt")
        if not os.path.isfile(p):
            self.skipTest("فهرستِ شناسه‌های خصوصی در این درخت نیست")
        with open(p, encoding="utf-8") as f:
            pats = [re.compile(ln.strip()) for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
        files = [os.path.join(PKG, n) for n in ("viz.py", "report.py", "xlsx.py")] + \
                [os.path.join(WEB, n) for n in ("svgstudio.js", "svgstudio.css", "studio.js")]
        for fn in files:
            with open(fn, encoding="utf-8") as f:
                txt = f.read()
            for pat in pats:
                self.assertIsNone(pat.search(txt), "%s در %s" % (pat.pattern, os.path.basename(fn)))


def report_facts_fixture(perms=("wg.view", "tun.view", "audit.view", "sys.view")):
    users = []
    for k in range(14):
        users.append({"name": "user-%02d" % k, "iface": "wgin", "public_key": "pk%d" % k, "enabled": k != 3,
                      "online": k % 2 == 0, "handshake": NOW - 60 * k * k,
                      "endpoint": "198.51.100.%d:40%02d" % (k + 2, k), "allowed_ips": "10.8.0.%d/32" % (k + 2),
                      "month_rx": 1e9 * k, "month_tx": 2e8 * k, "life_rx": 5e10, "life_tx": 1e10,
                      "quota_gb": 10 if k % 3 == 0 else None, "expires": "2027-01-%02d" % (k + 1) if k % 4 == 0 else "",
                      "auto_disabled": "quota" if k == 3 else "", "rate_mbit": "20" if k == 5 else "",
                      "note": "=cmd|' /C calc'!A0" if k == 6 else "note",
                      "hist": [[0, 30]] * 30 if k == 4 else [[1000, 200]] * 30})
    F = egress_facts()
    return {"now": NOW, "host": "panel-host", "build": "abcdef123456", "days": 30, "mask": True,
            "perms": set(perms), "users": users,
            "range_bytes": {("wgin", "pk%d" % k): 3e9 * k for k in range(14)},
            "daily": [{"day": "2026-10-%02d" % d, "bytes": 1e10 * (d % 5 + 1), "active": d % 9} for d in range(1, 31)],
            "tunnels": F["tunnels"], "egress": F,
            "events": timeline_facts()["events"],
            "audit": [{"ts": NOW - 600 * k, "actor": "admin", "category": "peer", "action": "peer.add",
                       "target": "u%d" % k, "detail": "", "ip": "192.0.2.%d" % k, "ok": k % 5 != 0} for k in range(40)],
            "speed": [{"ts": NOW - 3600 * k, "iface": "mom1", "ping_ms": 40 + k, "down_bps": 5e7, "up_bps": 2e7,
                       "jitter_ms": 3, "loss_pct": 0, "ok": True, "error": ""} for k in range(12)],
            "sys": {m: [{"t": "2026-10-%02d" % d, "v": 10 + d} for d in range(1, 31)] for m in ("cpu", "ram", "disk")}}


def build_book(perms=("wg.view", "tun.view", "audit.view", "sys.view"), lang="fa"):
    cx = V.Ctx(_Tr(lang), fa=lang == "fa", rtl=lang == "fa", now=NOW)
    return zipfile.ZipFile(io.BytesIO(R.build(report_facts_fixture(perms), cx, XL, V)))


class WorkbookStructure(unittest.TestCase):
    def setUp(self):
        self.z = build_book()

    def test_every_part_is_well_formed_xml(self):
        for n in self.z.namelist():
            if n.endswith((".xml", ".rels")):
                ET.fromstring(self.z.read(n))

    def test_conditional_format_priorities_are_numeric_and_unique(self):
        for n in self.z.namelist():
            if not n.startswith("xl/worksheets/sheet"):
                continue
            x = self.z.read(n).decode("utf-8")
            pr = re.findall(r'priority="([^"]*)"', x)
            for p in pr:
                self.assertRegex(p, r"^[1-9][0-9]*$", n)
            self.assertEqual(len(pr), len(set(pr)), n)
            self.assertNotIn("@@", x, n)

    def test_no_excel_table_parts(self):
        self.assertFalse([n for n in self.z.namelist() if n.startswith("xl/tables/")])

    def test_user_text_is_never_a_formula(self):
        ss = self.z.read("xl/sharedStrings.xml").decode("utf-8")
        self.assertIn("=cmd|", ss)
        for n in self.z.namelist():
            if n.startswith("xl/worksheets/sheet"):
                self.assertNotIn("cmd|", self.z.read(n).decode("utf-8"), n)

    def test_endpoints_are_masked(self):
        ss = self.z.read("xl/sharedStrings.xml").decode("utf-8")
        self.assertNotIn("198.51.100.7:4005", ss)
        self.assertIn("198.51.100.•", ss)

    def test_sheet_names_are_valid(self):
        wb = self.z.read("xl/workbook.xml").decode("utf-8")
        names = re.findall(r'<sheet name="([^"]+)"', wb)
        self.assertEqual(len(names), len(set(names)))
        for nm in names:
            self.assertLessEqual(len(nm), 31)
            self.assertIsNone(re.search(r"[\[\]:*?/\\]", nm))

    def test_sheets_follow_permissions(self):
        full = len([n for n in self.z.namelist() if n.startswith("xl/worksheets/sheet")])
        viewer = build_book(("wg.view",))
        n = len([x for x in viewer.namelist() if x.startswith("xl/worksheets/sheet")])
        self.assertLess(n, full)
        names = re.findall(r'<sheet name="([^"]+)"', viewer.read("xl/workbook.xml").decode("utf-8"))
        for forbidden in ("xl.s.tunnels", "xl.s.audit", "xl.s.egress", "xl.s.sys"):
            self.assertNotIn(CAT[forbidden][0], names)


class MaskEndpoint(unittest.TestCase):
    def test_family(self):
        m = R.mask_endpoint
        self.assertEqual(m("198.51.100.7:4000"), "198.51.100.•")
        self.assertEqual(m("[2001:db8:1:2:3:4:5:6]:51820"), "2001:0db8:0001:0002:•")
        self.assertEqual(m(""), "")
        self.assertEqual(m("(none)"), "")
        self.assertEqual(m("not-an-ip:1"), "•")


class PanelWiring(unittest.TestCase):
    """گره‌خوردنِ سه سو: endpoint ↔ PERM_MAP، دارایی ↔ مسیر، اسلایدِ TV ↔ سه‌بعدیِ آخر."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(PKG, "app.py"), encoding="utf-8") as f:
            cls.app = f.read()
        with open(os.path.join(WEB, "page.html"), encoding="utf-8") as f:
            cls.page = f.read()

    def test_endpoints_are_mapped_to_read_permissions(self):
        for path, perm in (("/api/viz/egress", "tun.view"), ("/api/viz/timeline", "tun.view"),
                           ("/api/viz/trace", "wg.view"), ("/api/report.xlsx", "wg.view")):
            self.assertIn('"%s": "%s"' % (path, perm), self.app)
            self.assertIn('path == "%s"' % path, self.app)

    def test_assets_are_served_and_included(self):
        for a in ("/svgstudio.js", "/svgstudio.css", "/studio.js"):
            self.assertIn('"%s"' % a, self.app)
            self.assertIn('"%s"' % a, self.page)
        self.assertTrue(os.path.isfile(os.path.join(WEB, "vendor", "svg-pan-zoom-3.6.1.min.js")))
        self.assertIn('SVGPANZOOM_VER = "3.6.1"', self.app)
        with open(os.path.join(WEB, "svgstudio.js"), encoding="utf-8") as f:
            self.assertIn("svg-pan-zoom-3.6.1.min.js", f.read())

    def test_3d_slide_stays_last_and_viz_slide_is_wired(self):
        self.assertIn("TV_SLIDE_3D = TV_SLIDES.length - 1", self.page)
        self.assertIn("_t('ui.viz.tv'), _t('ui.js.initPal.5')", self.page)
        self.assertIsNone(re.search(r"_tv\.slide [!=]== 4\b", self.page))
        self.assertIn("vizTvShow(body)", self.page)
        self.assertIn("vizAfterRole();", self.page)


if __name__ == "__main__":
    unittest.main()
