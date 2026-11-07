"""WG-NQMO P9 — فرمانِ /quality ِ رباتِ تلگرام (فقط خواندنی).

چرا فایلِ جدا: ربات همان اسنادِ /api/nqmo/status و /api/nqmo/peer را نشان می‌دهد
و برچسب‌هایش همان ui.nqmo.* ِ پنل است؛ این تست‌ها هم صفحه‌ها را می‌سنجند و هم
خانواده‌ها را:
  - هر مقدارِ واژگانِ موتور (کلاس، اطمینان، کیفیت، MTU، حالت، علتِ نبودن) برچسب دارد،
    وگرنه ربات نامِ خامِ کلید را چاپ می‌کند؛
  - دکمه‌ی منو و مسیرِ callback با یک مجوز گیت می‌شوند (bot-ops §۱)؛
  - بدونِ nqmo.detail هیچ prefix، ASN یا شاهدِ خامی به ربات نمی‌رسد؛
  - نامِ دستگاه هرگز بی‌escape به HTML ِ تلگرام نمی‌رود.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from tests import test_wg_panel as twp  # noqa: E402  (ماژول: TestCaseهایش دوباره جمع نمی‌شوند)


def _src():
    with open(os.path.join(HERE, "..", "wgpanel", "app.py"), encoding="utf-8") as f:
        return f.read()


class BotQualityTests(unittest.TestCase):
    KNOWN = {("wgtest", "alice"), ("wgtest", "bob"), ("wg2", "bob"), ("wgtest", "carol")}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bot-quality-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        m = self.m = twp.load_module(self.tmp)
        m.CONFIG["nqmo"] = {"enabled": True}
        m.CONFIG["roles"] = {"nview": {"perms": ["nqmo.view"]},
                             "wgonly": {"perms": ["wg.view"]}}
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "1", "role": "admin"}, {"id": "2", "role": "nview"},
            {"id": "3", "role": "wgonly"}, {"id": "4", "role": "nview", "lang": "en"}]}
        self.now = time.time()
        self.state = self.full_state()
        m.nqmo_state = lambda now=None: self.state
        m.nqmo_panel_peers = lambda: set(self.KNOWN)
        self.bot = m.TelegramBot()
        self.sent = []
        self.bot.send = lambda chat, text, keyboard=None: self.sent.append((chat, text, keyboard))
        self.bot.answer_cb = lambda *a, **k: None

    def full_state(self):
        now = self.now
        return {
            "available": True, "mode": "DIAGNOSTICS_ENABLED", "age_s": 4.0,
            "generated_at": now - 30,
            "coverage": {"peers_total": 4, "peers_handshake_180s": 3},
            "diagnoses": [
                {"id": 11, "class": "PACKET_LOSS", "scope": "PEER", "peer": "alice",
                 "iface": "wgtest", "confidence": "HIGH",
                 "evidence": [{"metric": "group", "value": "198.51.100.0/24"},
                              {"metric": "asn", "value": "AS64500"}]},
                {"id": 12, "class": "PACKET_LOSS", "scope": "PEER", "peer": "mallory",
                 "iface": "wgtest", "confidence": "HIGH", "evidence": []},
                {"id": 13, "class": "EGRESS_TUNNEL_DEGRADATION", "scope": "EGRESS",
                 "subject": "awg1", "confidence": "MEDIUM", "evidence": []}],
            "peers": [
                {"iface": "wgtest", "name": "alice", "window": now - 400, "quality": "HIGH",
                 "mtu_status": "UNDETERMINED", "rtt_n": 15, "rtt_ms_med": 40.0,
                 "rtt_ms_min": 31.0, "loss_n": 25000, "loss_point": 0.03,
                 "loss_lb": 0.028, "loss_ub": 0.032},
                {"iface": "wgtest", "name": "carol", "window": now - 400, "quality": "OK",
                 "mtu_status": "ESTIMATED", "rtt_n": 2, "loss_n": 10},
                {"iface": "wgtest", "name": "mallory", "window": now - 400, "quality": "HIGH"}],
            "recommendations": {"wgtest/alice": [
                {"target": "CLIENT_IFACE_MTU", "status": "ESTIMATED", "current_value": 1420,
                 "current_source": "config", "suggested_value": 1380}]},
        }

    def cmd(self, frm, text, chat=None):
        self.sent.clear()
        self.bot._dispatch_inner({"message": {"from": {"id": int(frm)},
                                              "chat": {"id": chat or int(frm), "type": "private"},
                                              "text": text}})
        return self.sent

    def cb(self, frm, data):
        self.sent.clear()
        self.bot._dispatch_inner({"callback_query": {
            "id": "q", "from": {"id": int(frm)}, "data": data,
            "message": {"message_id": 9, "chat": {"id": int(frm), "type": "private"}}}})
        return self.sent

    def T(self, key, lang="fa", **kw):
        return self.m.t(key, lang, **kw)

    # ---- صفحه‌ی خلاصه ----------------------------------------------------------
    def test_overview_lists_known_peers_worst_first(self):
        (_, text, kb), = self.cmd(1, "/quality")
        self.assertIn(self.T("ui.nqmo.title"), text)
        self.assertIn(self.T("ui.nqmo.md.DIAGNOSTICS_ENABLED"), text)
        self.assertIn(self.T("ui.nqmo.coverage.v", p0="۳", p1="۴"), text)
        # تشخیصِ سراسری با برچسبِ پنل و موضوعش
        self.assertIn(self.T("ui.nqmo.cls.EGRESS_TUNNEL_DEGRADATION"), text)
        self.assertIn("awg1", text)
        data = [b["callback_data"] for row in kb for b in row]
        self.assertEqual(data[:2], ["nq:p:wgtest|alice", "nq:p:wgtest|carol"])
        self.assertNotIn("mallory", " ".join(data))      # پیری که پنل نمی‌شناسد
        self.assertEqual(data[-1], "menu:")
        self.assertIn("۱", kb[0][0]["text"])              # شمارِ تشخیصِ باز، رقمِ فارسی

    def test_overview_says_why_when_engine_output_is_unavailable(self):
        self.state = {"available": False, "why": "stale"}
        (_, text, kb), = self.cmd(1, "/quality")
        self.assertIn(self.T("ui.nqmo.why.stale"), text)
        self.assertEqual(kb, [[{"text": self.T("bot.menu"), "callback_data": "menu:"}]])

    def _pages(self):
        """همه‌ی صفحه‌ها را با دکمه‌ی «بعدی» پیمایش می‌کند ⇒ [(متن، کیبورد)]."""
        out = [self.cmd(1, "/quality")[0][1:]]
        while True:
            nxt = [b["callback_data"] for row in out[-1][1] for b in row
                   if b["text"] == self.T("bot.paged.2")]
            if not nxt:
                return out
            out.append(self.cb(1, nxt[0])[-1][1:])

    def test_every_known_peer_is_reachable_through_the_pages(self):
        # خانواده: هیچ دستگاهی پشتِ سقفِ صفحه گم نمی‌شود (abnavid ِ ۷ نوامبر ردیفِ ۲۶ بود)
        n = self.bot.NQMO_PAGE_MAX * 2 + 3
        self.KNOWN = {("wgtest", "u%02d" % i) for i in range(n)}
        self.state["peers"] = [{"iface": "wgtest", "name": "u%02d" % i,
                                "window": self.now - 400, "quality": "OK"} for i in range(n)]
        pages = self._pages()
        self.assertEqual(len(pages), 3)
        seen = [b["callback_data"] for _, kb in pages for row in kb for b in row
                if b["callback_data"].startswith("nq:p:")]
        self.assertEqual(sorted(seen), sorted("nq:p:wgtest|u%02d" % i for i in range(n)))
        for _, kb in pages:
            self.assertLessEqual(len([r for r in kb if r[0]["callback_data"].startswith("nq:p:")]),
                                 self.bot.NQMO_PAGE_MAX)
            self.assertEqual(kb[-1], [{"text": self.T("bot.menu"), "callback_data": "menu:"}])
        self.assertIn("۳", " ".join(b["text"] for b in pages[0][1][-2]))   # «۱/۳» با ارقامِ فارسی

    def test_peers_with_data_come_before_silent_ones_when_quality_is_unknown(self):
        # همان حالتِ واقعیِ myserver: کیفیت برای همه None، فقط بعضی RTT دارند
        n = self.bot.NQMO_PAGE_MAX + 6
        self.KNOWN = {("wgtest", "a%02d" % i) for i in range(n)} | {("wgtest", "zz-active")}
        self.state["peers"] = [{"iface": "wgtest", "name": "a%02d" % i, "window": self.now - 400,
                                "quality": None} for i in range(n)] + [
            {"iface": "wgtest", "name": "zz-active", "window": self.now - 400, "quality": None,
             "rtt_n": 7, "loss_n": 623, "rtt_ms_med": 12.4}]
        (_, text, kb), = self.cmd(1, "/quality")
        self.assertEqual(kb[0][0]["callback_data"], "nq:p:wgtest|zz-active")
        self.assertIn("۱۲٫۴ ms", kb[0][0]["text"])        # بدونِ کیفیت، RTT نشان داده می‌شود

    # ---- صفحه‌ی دستگاه ---------------------------------------------------------
    def test_peer_page_by_command_shows_summary_diagnoses_and_recommendations(self):
        (_, text, kb), = self.cmd(2, "/quality alice")
        self.assertIn(self.T("ui.nqmo.q.HIGH"), text)
        self.assertIn(self.T("ui.nqmo.rtt.v", p0="۴۰", p1="۳۱", p2="۱۵"), text)
        self.assertIn(self.T("ui.nqmo.loss.v", p0="۳٫۰۰", p1="۲٫۸۰", p2="۳٫۲۰", p3="۲۵۰۰۰"), text)
        self.assertIn(self.T("ui.nqmo.mtu.UNDETERMINED"), text)
        self.assertIn(self.T("ui.nqmo.cls.PACKET_LOSS"), text)
        self.assertIn(self.T("ui.nqmo.lv.HIGH"), text)
        self.assertIn(self.T("ui.nqmo.tgt.CLIENT_IFACE_MTU"), text)
        self.assertIn(self.T("ui.nqmo.rec.v", p0="۱۴۲۰", p1="config", p2="۱۳۸۰"), text)
        self.assertEqual(kb[0][0]["callback_data"], "nq:page")

    def test_peer_page_without_enough_samples_says_so(self):
        (_, text, _), = self.cmd(2, "/quality carol")
        self.assertIn(self.T("ui.nqmo.rtt.few", p0="۲"), text)
        self.assertIn(self.T("ui.nqmo.loss.few", p0="۱۰"), text)

    def test_peer_without_fresh_data_gets_the_panel_sentence(self):
        self.KNOWN = self.KNOWN | {("wgtest", "dave")}
        (_, text, _), = self.cmd(2, "/quality dave")
        self.assertIn(self.T("ui.nqmo.nosummary"), text)

    def test_ambiguous_or_unknown_name_is_refused_and_callback_disambiguates(self):
        for name in ("bob", "mallory", "nobody"):
            (_, text, _), = self.cmd(2, "/quality " + name)
            self.assertIn(self.T("bot.nqmo.no_peer"), text, name)
            self.assertNotIn(self.T("ui.nqmo.th.quality"), text, name)
        (_, text, _), = self.cb(2, "nq:p:wg2|bob")
        self.assertIn("bob (wg2)", text)
        self.assertNotIn(self.T("bot.nqmo.no_peer"), text)

    def test_name_is_case_sensitive_and_command_is_not(self):
        (_, text, _), = self.cmd(2, "/QUALITY alice")
        self.assertIn(self.T("ui.nqmo.q.HIGH"), text)
        (_, text, _), = self.cmd(2, "/quality Alice")
        self.assertIn(self.T("bot.nqmo.no_peer"), text)

    def test_english_user_gets_latin_digits(self):
        (_, text, _), = self.cmd(4, "/quality alice")
        self.assertIn(self.T("ui.nqmo.rtt.v", "en", p0="40", p1="31", p2="15"), text)
        self.assertNotRegex(text, "[۰-۹]")

    # ---- امنیت و حریمِ خصوصی ---------------------------------------------------
    def test_no_detail_reaches_the_bot_even_for_admin(self):
        for frm in (1, 2):
            text = self.cmd(frm, "/quality alice")[0][1] + self.cmd(frm, "/quality")[0][1]
            self.assertNotIn("198.51.100", text)
            self.assertNotIn("AS64500", text)

    def test_device_name_is_escaped(self):
        self.KNOWN = {("wgtest", "a<b>&c")}
        self.state["peers"] = [{"iface": "wgtest", "name": "a<b>&c",
                                "window": self.now - 400, "quality": "OK"}]
        for text in (self.cmd(1, "/quality")[0][1], self.cmd(1, "/quality a<b>&c")[0][1]):
            self.assertNotIn("a<b>", text)
        self.assertIn("a&lt;b&gt;&amp;c", text)

    def test_without_nqmo_view_there_is_no_button_command_or_callback(self):
        (_, text, kb), = self.cmd(3, "/quality alice")
        self.assertEqual(text, self.T("bot.backup_page.1"))
        self.assertNotIn(self.T("ui.nqmo.q.HIGH"), text)
        self.assertEqual(self.cb(3, "nq:p:wgtest|alice"), [])          # مسیرِ callback بسته
        (_, _, kb), = self.cmd(3, "/menu")
        self.assertNotIn("nq:page", [b["callback_data"] for row in kb for b in row])
        (_, _, kb), = self.cmd(2, "/menu")
        self.assertIn("nq:page", [b["callback_data"] for row in kb for b in row])

    def test_flag_off_hides_the_button_and_the_command_says_disabled(self):
        self.m.CONFIG["nqmo"] = {"enabled": False}
        self.m.nqmo_state = lambda now=None: self.fail("state read with the flag off")
        (_, _, kb), = self.cmd(1, "/menu")
        self.assertNotIn("nq:page", [b["callback_data"] for row in kb for b in row])
        (_, text, _), = self.cmd(1, "/quality")
        self.assertIn(self.T("ui.nqmo.why.disabled"), text)

    def test_command_menu_lists_quality_only_with_the_flag(self):
        m = self.m
        m.CONFIG["alerts"] = dict(m.CONFIG.get("alerts") or {}, bot_token="t")
        calls = []
        m.tg_api = lambda tok, method, p=None, **k: (calls.append((method, p)), (True, {}))[1]
        for on in (False, True):
            m.CONFIG["nqmo"] = {"enabled": on}
            calls.clear()
            m.bot_setcommands()
            names = {c["command"] for _, p in calls if p and "commands" in p
                     for c in (json.loads(p["commands"]) if isinstance(p["commands"], str)
                               else p["commands"])}
            self.assertEqual("quality" in names, on, on)

    # ---- خانواده‌ها --------------------------------------------------------------
    def test_observation_mode_peer_page_explains_instead_of_dash(self):
        # همان صفحه‌ی ABAB ِ ۷ نوامبر: کیفیت None، RTT ِ ۴٫۵، توصیه‌ی بی‌پیشنهاد با منبعِ CONFIG
        self.state["mode"] = "OBSERVATION_ONLY"
        self.state["peers"][0].update(quality=None, rtt_ms_med=4.5, rtt_ms_min=4.0, rtt_n=7)
        self.state["recommendations"] = {"wgtest/alice": [
            {"target": "CLIENT_IFACE_MTU", "status": "UNDETERMINED", "current_value": 1392,
             "current_source": "CONFIG", "suggested_value": None}]}
        (_, text, _kb), = self.cmd(1, "/quality alice")
        self.assertIn(self.T("bot.nqmo.q_obs"), text)
        self.assertIn(self.T("ui.nqmo.rtt.v", p0="۴٫۵", p1="۴٫۰", p2="۷"), text)
        self.assertIn(self.T("bot.nqmo.rec.cur", p0="۱۳۹۲", p1=self.T("ui.nqmo.src.CONFIG"),
                             p2=self.T("ui.nqmo.mtu.UNDETERMINED")), text)
        self.assertNotIn("CONFIG", text)
        self.assertNotIn(self.T("ui.nqmo.rec.nosug"), text)

    def test_graded_mode_never_shows_the_observation_note(self):
        self.state["peers"][0]["quality"] = None
        (_, text, _kb), = self.cmd(1, "/quality alice")
        self.assertNotIn(self.T("bot.nqmo.q_obs"), text)

    def test_every_engine_vocabulary_value_has_a_label_in_every_language(self):
        """کلیدِ ناشناخته خودِ کلید را برمی‌گرداند؛ پس مقدارِ تازه‌ای در واژگانِ موتور بی‌برچسب
        در ربات به شکلِ «ui.nqmo.cls.X» دیده می‌شد. همه‌ی پیشوندهای پویای این صفحه‌ها."""
        m = self.m
        fams = {"ui.nqmo.cls.": m.NQMO_CLASSES, "ui.nqmo.lv.": m.NQMO_LEVELS,
                "ui.nqmo.q.": m.NQMO_PEER_QUALITY, "ui.nqmo.mtu.": m.NQMO_MTU_STATUS,
                "ui.nqmo.md.": m.NQMO_MODES, "ui.nqmo.why.": m.NQMO_STATE_WHY,
                "ui.nqmo.scope.": m.NQMO_SCOPES, "ui.nqmo.src.": m.NQMO_REC_SOURCES}
        for pre, vocab in fams.items():
            for v in vocab:
                row = m.I18N.get(pre + v)
                self.assertIsNotNone(row, pre + v)
                self.assertEqual(len(row), len(m.LANGS), pre + v)
                self.assertTrue(all(row), pre + v)
        src = _src()
        body = src[src.index("    # ---- WG-NQMO: کیفیتِ ارتباط (P9)"):src.index("    def _find(self, chat, q, p):")]
        used = set(re.findall(r"'((?:ui\.nqmo|bot\.nqmo|bot)\.[\w.]+?)'", body))
        dyn = {k for k in used if k.endswith(".")}
        self.assertLessEqual(dyn, set(fams) | {"ui.nqmo.tgt."}, "پیشوندِ پویای تازه بدونِ گارد")
        for k in used - dyn:
            self.assertIn(k, m.I18N, k)
            self.assertTrue(all(m.I18N[k]), k)

    def test_main_menu_areas_all_have_a_route(self):
        """دکمه‌ای که در _main_menu هست ولی _on_action مسیرش را ندارد، دیده می‌شود و کار
        نمی‌کند (bot-ops §۱) — برای همه‌ی دکمه‌های منو، نه فقط nq."""
        src = _src()
        menu = src[src.index("    def _main_menu(self, chat, frm):"):src.index("    def _on_action(")]
        act = src[src.index("    def _on_action("):src.index("    def _back_row(self):")]
        areas = set(re.findall(r'"callback_data": "(\w+):', menu))
        self.assertIn("nq", areas)
        routed = set(re.findall(r'area == "(\w+)"', act))
        self.assertLessEqual(areas, routed)


if __name__ == "__main__":
    unittest.main()
