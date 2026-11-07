"""خروجیِ Excel از رباتِ تلگرام (/excel): سه نوع گزارش در هر بازه.

  ۱. همه‌ی کاربرانِ وایرگارد ۲. یک کاربرِ مشخص (وایرگارد یا پروکسی) ۳. کلِ سرور.
بازه: ۱/۳/۷ روز، ۱ ماه، یا دلخواه (تعدادِ روز، یا از تاریخ تا تاریخ به شمسی/میلادی).

خانواده‌هایی که اینجا پاسبانی می‌شوند:
  - هر بخشِ فایل فقط با مجوزِ دیدنِ همان بخش؛ فایلِ «همه‌ی کاربران» فقط برگه‌های وایرگارد؛
  - IP ِ کاربر و مبدأ همیشه پوشانده، رمزِ پروکسی هرگز در فایل؛
  - تبدیلِ شمسی ↔ میلادی برای هر روز در دو جهت یکی است، و کپیِ الگوریتم در report.py
    با نسخه‌ی پنل یکی می‌ماند؛
  - هر ورودیِ نامعتبر یا خارج از نگهداریِ داده هرگز کارپوشه نمی‌سازد؛
  - دکمه‌ی کاربر بی‌حالت است: پس از ری‌استارت هم همان کاربر را پیدا می‌کند.
"""
import io
import os
import re
import shutil
import sys
import tempfile
import time
import types
import unittest
import zipfile
from datetime import date, datetime, timedelta
from xml.dom import minidom

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from tests import test_wg_panel as twp  # noqa: E402


class _SyncThread:
    """نخِ پس‌زمینه را همان‌جا اجرا می‌کند تا تست قطعی باشد."""
    def __init__(self, target=None, daemon=None, **_):
        self.target = target

    def start(self):
        self.target()


def _stats(now):
    return {"sections": [{"iface": "wgtest"}], "tunnels": [], "users": [
        {"name": "alice", "iface": "wgtest", "public_key": "pkA", "enabled": True, "online": True,
         "handshake": now - 30, "endpoint": "198.51.100.7:4000", "allowed_ips": "10.8.0.2/32",
         "month_rx": 5e9, "month_tx": 1e9, "life_rx": 9e10, "life_tx": 1e10, "quota_gb": 20,
         "expires": "", "rate_mbit": "", "note": ""},
        {"name": "alicia", "iface": "wg2", "public_key": "pkB", "enabled": False, "online": False,
         "handshake": 0, "endpoint": "", "allowed_ips": "10.9.0.2/32"}]}


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bot-excel-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        m = self.m = twp.load_module(self.tmp)
        m.CONFIG["roles"] = {"wgonly": {"perms": ["wg.view"]}, "pxonly": {"perms": ["proxy.view"]},
                             "tunonly": {"perms": ["tun.view"]}}
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "1", "role": "admin"}, {"id": "3", "role": "wgonly"}, {"id": "6", "role": "pxonly"},
            {"id": "5", "role": "tunonly"}, {"id": "4", "role": "wgonly", "lang": "en"}]}
        real = m.threading
        m.threading = types.SimpleNamespace(Thread=_SyncThread, Lock=real.Lock)
        self.addCleanup(setattr, m, "threading", real)
        self.now = time.time()
        m.build_stats = lambda: _stats(self.now)
        self.today = datetime.now().date()

    def T(self, key, lang="fa", **kw):
        return self.m.t(key, lang, **kw)


class BotExcelTests(_Base):
    def setUp(self):
        super().setUp()
        m = self.m
        con = m.MetaDB._connect()
        with con:
            con.execute("INSERT INTO proxy_user(username, pass_hash, pass_plain, enabled, protocol) "
                        "VALUES('pxu','HASHSECRET','PLAINSECRET',1,'both')")
        con.close()
        self.calls, self.ucalls = [], []

        def fake_report(perms, days, mask, lang, span=None):
            self.calls.append((set(perms), span, mask, lang))
            return b"PK-fake", "x.xlsx"

        def fake_user(kind, ident, span, perms, mask, lang):
            self.ucalls.append((kind, ident, span, mask))
            return b"PK-user", "u.xlsx"
        m.report_xlsx = fake_report
        m.user_report_xlsx = fake_user
        self.bot = m.TelegramBot()
        self.sent, self.docs = [], []
        self.bot.send = lambda chat, text, keyboard=None: self.sent.append((chat, text, keyboard))
        self.bot._send_fresh = lambda chat, text, keyboard=None: self.sent.append((chat, text, keyboard))
        self.bot.answer_cb = lambda *a, **k: None
        self.bot.send_doc = lambda chat, fn, data, caption="", ctype="text/plain": (
            self.docs.append((chat, fn, data, caption, ctype)) or (True, {}))

    def cmd(self, frm, text):
        self.sent.clear()
        self.bot._dispatch_inner({"message": {"from": {"id": int(frm)},
                                              "chat": {"id": int(frm), "type": "private"},
                                              "text": text}})
        return self.sent

    def cb(self, frm, data):
        self.sent.clear()
        self.bot._dispatch_inner({"callback_query": {
            "id": "q", "from": {"id": int(frm)}, "data": data,
            "message": {"message_id": 9, "chat": {"id": int(frm), "type": "private"}}}})
        return self.sent

    @staticmethod
    def datas(kb):
        return [b["callback_data"] for row in kb or [] for b in row]

    def span(self, n):
        return (self.today - timedelta(days=n - 1), self.today)

    # ---- صفحه‌ی اول و گزینشگرِ بازه ----------------------------------------------
    def test_home_offers_the_three_kinds(self):
        (_, text, kb), = self.cmd(3, "/excel")
        self.assertIn(self.T("bot.xl.kind"), text)
        self.assertEqual(self.datas(kb), ["xl:r:a", "xl:u", "xl:r:s", "menu:"])
        self.assertTrue(text.split("\n")[-1].startswith("‏"))     # راست‌چین

    def test_proxy_only_user_gets_only_the_single_user_report(self):
        (_, _t, kb), = self.cmd(6, "/excel")
        self.assertEqual(self.datas(kb), ["xl:u", "menu:"])
        self.cb(6, "xl:d:a:7")
        self.cb(6, "xl:d:s:7")
        self.assertEqual(self.calls, [])

    def test_range_picker_carries_its_target(self):
        for k in ("a", "s"):
            (_, _text, kb), = self.cb(3, "xl:r:" + k)
            self.assertEqual(self.datas(kb), ["xl:d:%s:1" % k, "xl:d:%s:3" % k, "xl:d:%s:7" % k,
                                              "xl:d:%s:30" % k, "xl:c:" + k, "xl:page", "menu:"])
        labels = [b["text"] for row in kb for b in row]
        self.assertEqual(labels[:4], [self.T("bot.xl.days", p0="۱"), self.T("bot.xl.days", p0="۳"),
                                      self.T("bot.xl.days", p0="۷"), self.T("bot.xl.month")])

    def test_english_user_gets_latin_digits(self):
        (_, _t, kb), = self.cb(4, "xl:r:a")
        self.assertEqual(kb[0][0]["text"], self.T("bot.xl.days", lang="en", p0="1"))

    # ---- ساخت ------------------------------------------------------------------
    def test_every_preset_builds_its_own_span(self):
        for d in self.bot.XL_PRESETS:
            self.calls.clear(); self.docs.clear()
            self.cb(3, "xl:d:a:%d" % d)
            self.assertEqual(self.calls, [({"wg.view"}, self.span(d), True, "fa")])
            (_, fn, _data, caption, ctype), = self.docs
            self.assertRegex(fn, r"^wg-users-\d{8}_\d{8}\.xlsx$")
            self.assertEqual(ctype, self.bot.XL_CTYPE)
            self.assertIn(self.T("bot.xl.all"), caption)

    def test_all_users_file_is_cut_to_wireguard_even_for_admin(self):
        self.cb(1, "xl:d:a:7")
        self.assertEqual(self.calls[0][0], {"wg.view"})
        self.assertTrue(self.calls[0][2])                 # پوشانده

    def test_server_file_gets_exactly_the_viewable_sections(self):
        self.cb(1, "xl:d:s:7")
        self.assertEqual(self.calls[0][0], set(self.bot.XL_SERVER_PERMS))
        self.calls.clear()
        self.cb(3, "xl:d:s:7")
        self.assertEqual(self.calls[0][0], {"wg.view"})

    def test_find_then_pick_then_build_a_wireguard_user(self):
        (_, text, kb), = self.cmd(1, "/excel ali")
        self.assertIn(self.T("bot.xl.find_pick", p0="۲"), text)
        tok = self.bot._xl_token("wg", ("wgtest", "alice"))
        self.assertEqual(kb[0][0]["callback_data"], "xl:r:" + tok)         # نامِ کوتاه‌تر اول
        for d in self.datas(kb):
            self.assertLessEqual(len(d.encode("utf-8")), 64)
        (_, text, _kb), = self.cb(1, "xl:r:" + tok)
        self.assertIn("alice (wgtest)", text)
        self.cb(1, "xl:d:%s:7" % tok)
        self.assertEqual(self.ucalls, [("wg", ("wgtest", "alice"), self.span(7), True)])
        self.assertTrue(self.docs)

    def test_find_by_conversation_and_proxy_users(self):
        self.cb(6, "xl:u")
        self.assertEqual(self.bot.convo[6], {"flow": "xl_find"})
        (_, _t, kb), = self.cmd(6, "PX")
        tok = self.bot._xl_token("px", "pxu")
        self.assertEqual(self.datas(kb)[0], "xl:r:" + tok)
        self.assertNotIn(self.bot._xl_token("wg", ("wgtest", "alice")), " ".join(self.datas(kb)))
        self.cb(6, "xl:d:%s:30" % tok)
        self.assertEqual(self.ucalls, [("px", "pxu", self.span(30), True)])

    def test_user_token_needs_the_permission_of_its_kind(self):
        wtok = self.bot._xl_token("wg", ("wgtest", "alice"))
        ptok = self.bot._xl_token("px", "pxu")
        (_, text, _kb), = self.cb(6, "xl:d:%s:7" % wtok)          # پروکسی‌بین ⇐ وایرگارد
        self.assertIn(self.T("bot.xl.stale"), text)
        (_, text, _kb), = self.cb(3, "xl:d:%s:7" % ptok)          # وایرگاردبین ⇐ پروکسی
        self.assertIn(self.T("bot.xl.stale"), text)
        self.assertEqual(self.ucalls, [])

    def test_token_is_stateless_and_survives_a_restart(self):
        tok = self.bot._xl_token("wg", ("wgtest", "alice"))
        fresh = self.m.TelegramBot()
        self.assertEqual(fresh._xl_token("wg", ("wgtest", "alice")), tok)
        self.assertEqual(fresh._xl_resolve(tok, {"wg.view"}), ("wg", ("wgtest", "alice")))
        self.assertIsNone(fresh._xl_resolve("w0000000000", {"wg.view"}))
        self.assertNotEqual(tok, self.bot._xl_token("wg", ("wg2", "alice")))

    def test_user_pages_link_to_their_own_report(self):
        self.cb(1, "wg:show:wgtest|alice")
        self.assertIn("xl:r:" + self.bot._xl_token("wg", ("wgtest", "alice")), self.datas(self.sent[-1][2]))
        self.cb(1, "px:show:pxu")
        self.assertIn("xl:r:" + self.bot._xl_token("px", "pxu"), self.datas(self.sent[-1][2]))

    def test_custom_days_and_date_ranges(self):
        g = self.m._greg_to_jalali
        a = self.today - timedelta(days=20)
        b = self.today - timedelta(days=6)
        ja = "%04d/%02d/%02d" % g(a.year, a.month, a.day)
        jb = "%04d/%02d/%02d" % g(b.year, b.month, b.day)
        cases = [("۱۴", self.span(14)), ("45", self.span(45)),
                 ("%s تا %s" % (ja, jb), (a, b)),
                 (("%s تا %s" % (jb, ja)).translate(str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")), (a, b)),
                 ("%s %s" % (a.isoformat(), b.isoformat()), (a, b)),
                 (b.isoformat(), (b, b))]
        for raw, want in cases:
            self.calls.clear()
            self.cb(3, "xl:c:s")
            self.assertEqual(self.bot.convo[3], {"flow": "xl_days", "k": "s"})
            self.cmd(3, raw)
            self.assertNotIn(3, self.bot.convo)
            self.assertEqual([c[1] for c in self.calls], [want], raw)

    def test_bad_input_never_builds_and_says_why(self):
        lo, hi = self.m.REPORT_DAYS
        old = self.today - timedelta(days=hi + 5)
        cases = {str(lo - 1): "bot.xl.bad", str(hi + 1): "bot.xl.bad", "abc": "bot.xl.bad",
                 "7.5": "bot.xl.bad", "-3": "bot.xl.bad", "2026-02-30": "bot.xl.bad_date",
                 "1405/12/30": "bot.xl.bad_date", "1405/07/31": "bot.xl.bad_date",
                 (self.today + timedelta(days=1)).isoformat(): "bot.xl.future",
                 "%s %s" % (old.isoformat(), self.today.isoformat()): "bot.xl.too_long",
                 "%s %s" % (old.isoformat(), (old + timedelta(days=3)).isoformat()): "bot.xl.too_old",
                 "2026-10-01 2026-10-02 2026-10-03": "bot.xl.bad"}
        for raw, key in cases.items():
            self.calls.clear()
            self.cb(3, "xl:c:a")
            (_, text, kb), = self.cmd(3, raw)
            self.assertEqual(self.calls, [], raw)
            self.assertIn(self.T(key, p0="۱", p1="۱۸۳"), text, raw)
            self.assertIn("xl:c:a", self.datas(kb))

    def test_command_with_days_builds_all_users_directly(self):
        self.cmd(3, "/excel ۱۰")
        self.assertEqual([c[1] for c in self.calls], [self.span(10)])

    def test_concurrent_build_is_refused_not_queued(self):
        self.bot._xl_lock.acquire()
        try:
            (_, text, _kb), = self.cb(3, "xl:d:a:7")
        finally:
            self.bot._xl_lock.release()
        self.assertEqual(self.calls, [])
        self.assertIn(self.T("bot.xl.busy"), text)
        self.cb(3, "xl:d:a:7")
        self.cb(3, "xl:d:a:3")
        self.assertEqual(len(self.calls), 2)

    def test_failure_releases_the_lock_and_says_so(self):
        def boom(*a, **k):
            raise RuntimeError("x")
        self.m.report_xlsx = boom
        out = self.cb(3, "xl:d:a:7")
        self.assertIn(self.T("bot.xl.fail"), out[-1][1])
        self.assertTrue(self.bot._xl_lock.acquire(blocking=False))
        self.bot._xl_lock.release()

    def test_build_is_audited_as_the_bot_user_with_its_target(self):
        seen = []
        self.m.audit = lambda *a, **k: seen.append(a)
        self.cb(3, "xl:d:a:7")
        tok = self.bot._xl_token("wg", ("wgtest", "alice"))
        self.cb(3, "xl:d:%s:7" % tok)
        self.assertEqual([s[:4] for s in seen], [("bot:3", "settings", "report.xlsx", "*"),
                                                 ("bot:3", "settings", "report.xlsx", "alice @ wgtest")])

    # ---- مجوز ------------------------------------------------------------------
    def test_without_wg_or_proxy_view_there_is_no_button_command_or_callback(self):
        (_, _t, kb), = self.cmd(5, "/menu")
        self.assertNotIn("xl:page", self.datas(kb))
        (_, text, _kb), = self.cmd(5, "/excel 7")
        self.assertIn(self.T("bot.backup_page.1"), text)
        self.cb(5, "xl:d:a:7")
        self.assertEqual(self.calls, [])
        for frm in (3, 6):
            (_, _t, kb), = self.cmd(frm, "/menu")
            self.assertIn("xl:page", self.datas(kb))

    def test_setcommands_lists_excel(self):
        got = []
        self.m.alert_cfg = lambda: {"bot_token": "t", "iface": "", "lang": "fa"}
        self.m.tg_api = lambda tok, method, p, **k: got.append(p) or (True, {})
        self.m.bot_setcommands()
        self.assertTrue(got)
        for p in got:
            self.assertIn("excel", [c["command"] for c in p["commands"]])


class SpanParserTests(_Base):
    def test_jalali_round_trip_for_every_day(self):
        # خانواده: هر روزِ ۲۰۲۰ تا ۲۰۳۲ در دو جهت برمی‌گردد؛ وارون با خودِ تابعِ پنل سنجیده می‌شود
        g2j, j2g = self.m._greg_to_jalali, self.m._jalali_to_greg
        d = date(2020, 1, 1)
        while d <= date(2032, 12, 31):
            self.assertEqual(j2g(*g2j(d.year, d.month, d.day)), d, d)
            d += timedelta(days=1)

    def test_impossible_jalali_dates_are_rejected(self):
        j2g = self.m._jalali_to_greg
        for y, mo, d in ((1405, 7, 31), (1405, 13, 1), (1405, 0, 1), (1405, 1, 32), (1405, 12, 30)):
            self.assertIsNone(j2g(y, mo, d), (y, mo, d))
        self.assertIsNotNone(j2g(1403, 12, 30))            # ۱۴۰۳ کبیسه است

    def test_report_module_jalali_copy_matches_the_panel(self):
        R = self.m._pkg_module("report")
        d = date(2024, 1, 1)
        while d <= date(2030, 12, 31):
            self.assertEqual(R._g2j(d.year, d.month, d.day), self.m._greg_to_jalali(d.year, d.month, d.day))
            d += timedelta(days=1)

    def test_report_targets_match_the_catalog(self):
        R = self.m._pkg_module("report")
        cat = {k.rsplit(".", 1)[1] for k in self.m.I18N if k.startswith("ui.nqmo.tgt.")}
        self.assertEqual(set(R._NQ_TARGETS), cat)


class WorkbookTests(_Base):
    """کارپوشه‌های واقعی روی پایگاهِ موقت با داده‌ی ساختگی."""
    SECRETS = (b"HASHSECRET", b"PLAINSECRET", b"198.51.100.7", b"203.0.113.9")

    def setUp(self):
        super().setUp()
        m = self.m
        now = datetime.now()
        con = m.MetaDB._connect()
        with con:
            for k in range(40):
                d = (now - timedelta(days=k)).strftime("%Y-%m-%d")
                con.execute("INSERT INTO usage_day VALUES(?,?,?,?,?)", (d, "wgtest", "pkA", 10 ** 8 * (k % 5), 10 ** 7 * k))
                con.execute("INSERT INTO proxy_usage_day VALUES(?,?,?)", (d, "pxu", 5 * 10 ** 6 * k))
            for k in range(30 * 24):
                hh = (now - timedelta(hours=k)).strftime("%Y-%m-%d %H")
                con.execute("INSERT INTO usage_hour VALUES(?,?,?,?,?)", (hh, "wgtest", "pkA", 10 ** 6 * (k % 7), 10 ** 5))
                con.execute("INSERT INTO proxy_usage_hour VALUES(?,?,?)", (hh, "pxu", 10 ** 5 * (k % 3)))
            con.execute("INSERT INTO proxy_user(username, pass_hash, pass_plain, quota_gb, expires, enabled, protocol, created) "
                        "VALUES('pxu','HASHSECRET','PLAINSECRET',10,'2099-12-01',1,'both',?)", (time.time() - 86400 * 50,))
            con.execute("INSERT INTO proxy_client VALUES('pxu','203.0.113.9',?,?,40,123456789)",
                        (time.time() - 86400 * 9, time.time() - 3600))
            con.execute("INSERT INTO proxy_dest VALUES('pxu','example.com',?,?,50,45,5,9999999)",
                        (time.time() - 86400 * 9, time.time() - 600))
            con.execute("INSERT INTO proxy_dest VALUES('pxu','old.example',?,?,5,5,0,10)",
                        (time.time() - 86400 * 90, time.time() - 86400 * 80))
            for cat, tgt in (("peer", "alice @ wgtest"), ("peer", "alicia @ wg2"), ("panel-user", "pxu")):
                con.execute("INSERT INTO audit(ts,actor,category,action,target,detail,ip,ok) VALUES(?,?,?,?,?,?,?,1)",
                            (time.time() - 3600, "admin", cat, "px.edit" if cat == "panel-user" else "peer.quota.bot",
                             tgt, "", "192.0.2.1"))
            con.execute("INSERT INTO share VALUES('h1','wgtest','alice',?,1,2,?,'admin',0)",
                        (time.time() + 86400, time.time() - 7200))
        con.close()
        self.ALL = {"wg.view", "proxy.view", "audit.view", "tun.view", "sys.view"}

    def book(self, data):
        z = zipfile.ZipFile(io.BytesIO(data))
        names = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        flat = b"".join(z.read(n) for n in z.namelist())
        for s in self.SECRETS:
            self.assertNotIn(s, flat)
        for n in z.namelist():
            if n.endswith(".xml") or n.endswith(".rels"):
                minidom.parseString(z.read(n))            # هر بخش XML ِ خوش‌ساخت
        return z, names, flat

    def S(self, k, lang="fa"):
        return self.T("xl.s." + k, lang)

    def test_wireguard_user_book(self):
        span = (self.today - timedelta(days=6), self.today)
        f = self.m.user_report_facts("wg", ("wgtest", "alice"), span, self.ALL, True, "fa")
        self.assertEqual([r[0] for r in f["daily"]], [(span[0] + timedelta(days=i)).isoformat() for i in range(7)])
        k = 6                                              # نخستین روزِ بازه = ۶ روز پیش
        self.assertEqual(f["daily"][0][1:], (10 ** 8 * (k % 5), 10 ** 7 * k))
        self.assertEqual(len(f["hourly"]), 6 * 24 + datetime.now().hour + 1)
        self.assertFalse(f["hourly_cut"])
        self.assertEqual([r["target"] for r in f["audit"]], ["alice @ wgtest"])
        data, fn = self.m.user_report_xlsx("wg", ("wgtest", "alice"), span, self.ALL, True, "fa")
        self.assertRegex(fn, r"^wg-alice-\d{8}_\d{8}\.xlsx$")
        _z, names, flat = self.book(data)
        self.assertEqual(names[:3], [self.S(x) for x in ("home", "daily", "hourly")])
        self.assertIn(self.S("shares"), names)
        self.assertIn(self.S("audit"), names)
        self.assertIn(b"198.51.100.", flat)               # پوشانده، نه حذف

    def test_audit_needs_audit_view_and_nqmo_needs_its_flag(self):
        span = (self.today - timedelta(days=2), self.today)
        f = self.m.user_report_facts("wg", ("wgtest", "alice"), span, {"wg.view"}, True, "fa")
        self.assertNotIn("audit", f)
        self.assertNotIn("nqmo", f)
        data, _ = self.m.user_report_xlsx("wg", ("wgtest", "alice"), span, {"wg.view"}, True, "fa")
        _z, names, _f = self.book(data)
        self.assertNotIn(self.S("audit"), names)

    def test_quality_sheet_when_engine_is_on(self):
        m = self.m
        m.CONFIG["nqmo"] = {"enabled": True}
        m.nqmo_panel_peers = lambda: {("wgtest", "alice")}
        m.nqmo_state = lambda now=None: {
            "available": True, "mode": "OBSERVATION_ONLY", "age_s": 3.0, "generated_at": self.now - 30,
            "coverage": {"peers_total": 1, "peers_handshake_180s": 1}, "diagnoses": [],
            "peers": [{"iface": "wgtest", "name": "alice", "window": self.now - 300, "quality": None,
                       "rtt_n": 7, "rtt_ms_med": 4.5, "rtt_ms_min": 4.0, "loss_n": 16587,
                       "loss_point": 0.0, "loss_lb": 0.0, "loss_ub": 0.0002}],
            "recommendations": {"wgtest/alice": [{"target": "CLIENT_IFACE_MTU", "status": "UNDETERMINED",
                                                  "current_value": 1392, "current_source": "CONFIG",
                                                  "suggested_value": None}]}}
        span = (self.today - timedelta(days=2), self.today)
        perms = self.ALL | {"nqmo.view"}
        data, _ = m.user_report_xlsx("wg", ("wgtest", "alice"), span, perms, True, "fa")
        _z, names, flat = self.book(data)
        self.assertIn(self.S("nqmo"), names)
        self.assertIn(self.T("xl.nq.obs").encode("utf-8"), flat)
        self.assertIn(self.T("ui.nqmo.src.CONFIG").encode("utf-8"), flat)
        data, _ = m.report_xlsx(perms, 7, True, "fa")
        _z, names, _f = self.book(data)
        self.assertIn(self.S("nqmo"), names)

    def test_every_sheet_has_a_back_link_and_a_full_width_note(self):
        """خانواده‌ی «برگه با widths ِ تک‌ستونی»: بی پیوندِ بازگشت و یادداشتِ شکسته در یک ستونِ باریک.

        Excel ِ مک (۷ نوامبر): برگه‌های «پروکسی» و «کیفیتِ ارتباط» ِ گزارشِ سرور با widths=[18]
        ساخته می‌شدند ⇒ ردیفِ ۱ پیوندِ بازگشت نداشت و یادداشتِ ردیفِ ۲ در ۱۸ نویسه چهار خط می‌شکست.
        """
        m = self.m
        m.CONFIG["nqmo"] = {"enabled": True}
        m.nqmo_panel_peers = lambda: {("wgtest", "alice")}
        m.nqmo_state = lambda now=None: {"available": True, "mode": "OBSERVATION_ONLY", "age_s": 3.0,
                                         "generated_at": self.now - 30, "coverage": {}, "diagnoses": [],
                                         "peers": [], "recommendations": {}}
        perms = self.ALL | {"nqmo.view"}
        span = (self.today - timedelta(days=6), self.today)
        books = [m.report_xlsx(perms, 7, True, "fa")[0],
                 m.user_report_xlsx("wg", ("wgtest", "alice"), span, perms, True, "fa")[0],
                 m.user_report_xlsx("px", "pxu", span, perms, True, "fa")[0]]
        for data in books:
            z, names, _f = self.book(data)
            home = names[0]
            for i, nm in enumerate(names[1:], 2):
                x = z.read("xl/worksheets/sheet%d.xml" % i).decode("utf-8")
                links = re.findall(r'<hyperlink ref="([A-Z]+)1" location="([^"]+)"', x)
                self.assertTrue(any(home in loc for _c, loc in links), "%s: پیوندِ بازگشت ندارد" % nm)
                merges = re.findall(r'<mergeCell ref="A2:([A-Z]+)2"/>', x)
                if merges:                                 # یادداشت دست‌کم تا ستونِ پیوندِ بازگشت
                    self.assertGreaterEqual(len(merges[0]), 1)
                    self.assertGreater(merges[0], "B", "%s: یادداشت در یک ستون شکسته" % nm)

    def test_proxy_user_book(self):
        span = (self.today - timedelta(days=9), self.today)
        f = self.m.user_report_facts("px", "pxu", span, self.ALL, True, "fa")
        self.assertNotIn("pass_hash", f["user"])
        self.assertNotIn("pass_plain", f["user"])
        self.assertEqual([x["host"] for x in f["dests"]], ["example.com"])   # old.example خارج از بازه
        self.assertEqual(sum(r[1] for r in f["daily"]), 5 * 10 ** 6 * sum(range(10)))
        self.assertEqual([r["target"] for r in f["audit"]], ["pxu"])
        data, fn = self.m.user_report_xlsx("px", "pxu", span, self.ALL, True, "fa")
        self.assertEqual(fn, "px-pxu-%s_%s.xlsx" % (span[0].strftime("%Y%m%d"), span[1].strftime("%Y%m%d")))
        _z, names, flat = self.book(data)
        self.assertEqual(names, [self.S(x) for x in ("home", "daily", "hourly", "clients", "dests", "audit")])
        self.assertIn(b"203.0.113.", flat)

    def test_user_report_respects_kind_permission_and_missing_users(self):
        span = (self.today, self.today)
        self.assertIsNone(self.m.user_report_xlsx("wg", ("wgtest", "alice"), span, {"proxy.view"}, True, "fa"))
        self.assertIsNone(self.m.user_report_xlsx("px", "pxu", span, {"wg.view"}, True, "fa"))
        self.assertIsNone(self.m.user_report_xlsx("wg", ("wgtest", "nobody"), span, self.ALL, True, "fa"))
        self.assertIsNone(self.m.user_report_xlsx("px", "nobody", span, self.ALL, True, "fa"))

    def test_old_span_marks_hourly_as_cut(self):
        span = (self.today - timedelta(days=40), self.today - timedelta(days=30))
        f = self.m.user_report_facts("wg", ("wgtest", "alice"), span, self.ALL, True, "en")
        self.assertTrue(f["hourly_cut"])
        self.assertEqual(f["hourly"], [])
        data, _ = self.m.user_report_xlsx("wg", ("wgtest", "alice"), span, self.ALL, True, "en")
        _z, _n, flat = self.book(data)
        self.assertIn(b"Hourly data is kept for 21 days only", flat)

    def test_server_book_with_a_past_span(self):
        span = (self.today - timedelta(days=20), self.today - timedelta(days=3))
        f = self.m.report_facts(self.ALL, None, True, "fa", span)
        self.assertEqual(f["days"], 18)
        self.assertFalse(f["recent"])
        days = [d["day"] for d in f["daily"]]
        self.assertEqual((days[0], days[-1]), (span[0].isoformat(), span[1].isoformat()))
        self.assertEqual([u["range_bytes"] for u in f["proxy_users"]], [5 * 10 ** 6 * sum(range(3, 21))])
        self.assertNotIn("pass_hash", f["proxy_users"][0])
        data, _ = self.m.report_xlsx(self.ALL, None, True, "fa", span)
        _z, names, flat = self.book(data)
        for k in ("users", "daily", "proxy", "proxy_daily", "audit"):
            self.assertIn(self.S(k), names)
        a, b = f["span_text"]
        want = self.T("xl.k.range.span", a=a, b=b, d="۱۸").translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789"))
        self.assertIn(want.encode("utf-8"), flat)

    def test_wireguard_only_book_has_no_other_sections(self):
        data, _ = self.m.report_xlsx({"wg.view"}, 7, True, "fa")
        _z, names, flat = self.book(data)
        self.assertLessEqual(set(names), {self.S(k) for k in ("home", "users", "daily", "gloss")})
        self.assertIn(b"alice", flat)


if __name__ == "__main__":
    unittest.main()
