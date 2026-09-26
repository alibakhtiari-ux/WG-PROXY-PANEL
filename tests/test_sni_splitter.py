# -*- coding: utf-8 -*-
"""تست‌های آفلاینِ پارسرِ SNI و طبقه‌بندِ warp-sni-splitter.

هیچ سوکت/دستوری اجرا نمی‌شود — فقط منطقِ خالص. با ساختِ بایت‌های واقعیِ
ClientHello (شاملِ اکستنشنِ SNI) صحتِ پارس و رفتارِ لبه‌ها را تأیید می‌کند.
"""
import asyncio
import json
import os
import socket
import struct
import sys
import tempfile
import time
import unittest
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "deploy"))
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "warp_sni_splitter",
    os.path.join(os.path.dirname(__file__), "..", "deploy",
                 "warp-sni-splitter.py"))
wss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wss)

_qspec = importlib.util.spec_from_file_location(
    "quic_sni",
    os.path.join(os.path.dirname(__file__), "..", "deploy", "quic_sni.py"))
q = importlib.util.module_from_spec(_qspec)
_qspec.loader.exec_module(q)


def build_client_hello(sni=None, extra_exts=b"", trailing_ok=True):
    """یک ClientHelloِ حداقلی ولی معتبر می‌سازد. اگر sni داده شود اکستنشنِ
    server_name را می‌گذارد."""
    exts = b""
    if sni is not None:
        host = sni.encode("ascii")
        server_name = bytes([0]) + len(host).to_bytes(2, "big") + host
        snl = len(server_name).to_bytes(2, "big") + server_name
        exts += (0x0000).to_bytes(2, "big") + len(snl).to_bytes(2, "big") + snl
    exts += extra_exts
    body = b""
    body += b"\x03\x03"                       # client_version TLS1.2
    body += b"\x00" * 32                      # random
    body += b"\x00"                           # session_id length 0
    body += (2).to_bytes(2, "big") + b"\x13\x01"   # 1 cipher suite
    body += b"\x01\x00"                        # compression: 1 method, null
    body += len(exts).to_bytes(2, "big") + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body   # handshake ClientHello
    rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    return rec


class TestSNIParser(unittest.TestCase):
    def test_basic_sni(self):
        buf = build_client_hello("gemini.google.com")
        self.assertEqual(wss.parse_client_hello_sni(buf),
                         ("ok", "gemini.google.com"))

    def test_sni_uppercase_normalized(self):
        buf = build_client_hello("Gemini.Google.COM")
        self.assertEqual(wss.parse_client_hello_sni(buf),
                         ("ok", "gemini.google.com"))

    def test_no_sni_extension(self):
        buf = build_client_hello(sni=None)
        self.assertEqual(wss.parse_client_hello_sni(buf), ("ok", None))

    def test_sni_after_other_extension(self):
        # یک اکستنشنِ دلخواه (supported_versions) قبل از SNI
        pre = (0x002b).to_bytes(2, "big") + (3).to_bytes(2, "big") \
            + b"\x02\x03\x04"
        buf = build_client_hello("www.youtube.com")
        # بازسازی با اکستنشنِ اضافه *قبل* از SNI: ساده‌تر است که extra بعد
        # بیاید؛ ترتیب نباید مهم باشد چون حلقه روی همه می‌گردد.
        buf2 = build_client_hello("www.youtube.com", extra_exts=pre)
        self.assertEqual(wss.parse_client_hello_sni(buf2),
                         ("ok", "www.youtube.com"))

    def test_need_more_truncated_record(self):
        buf = build_client_hello("gemini.google.com")
        # نصفِ رکورد
        self.assertEqual(wss.parse_client_hello_sni(buf[:20]),
                         ("need_more", None))

    def test_need_more_empty(self):
        self.assertEqual(wss.parse_client_hello_sni(b""), ("need_more", None))
        self.assertEqual(wss.parse_client_hello_sni(b"\x16\x03"),
                         ("need_more", None))

    def test_bad_not_tls(self):
        self.assertEqual(wss.parse_client_hello_sni(b"GET / HTTP/1.1\r\n"),
                         ("bad", None))

    def test_bad_not_client_hello(self):
        # رکوردِ handshake ولی نوعِ ServerHello (0x02)
        hs = b"\x02" + (4).to_bytes(3, "big") + b"\x00\x00\x00\x00"
        rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
        self.assertEqual(wss.parse_client_hello_sni(rec), ("bad", None))

    def test_incremental_reassembly(self):
        # بایت‌به‌بایت اضافه‌کردن باید در نهایت به ok برسد و قبلش need_more
        buf = build_client_hello("aistudio.google.com")
        got_need_more = False
        for i in range(1, len(buf)):
            st, _ = wss.parse_client_hello_sni(buf[:i])
            if st == "need_more":
                got_need_more = True
            elif st == "ok":
                pass
        self.assertTrue(got_need_more)
        self.assertEqual(wss.parse_client_hello_sni(buf),
                         ("ok", "aistudio.google.com"))

    def test_malformed_name_len_overflow(self):
        # SNI با name_len دروغینِ بزرگ‌تر از داده → bad، نه crash
        host = b"x.com"
        server_name = bytes([0]) + (999).to_bytes(2, "big") + host
        snl = len(server_name).to_bytes(2, "big") + server_name
        exts = (0x0000).to_bytes(2, "big") + len(snl).to_bytes(2, "big") + snl
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00" \
            + (2).to_bytes(2, "big") + b"\x13\x01" + b"\x01\x00" \
            + len(exts).to_bytes(2, "big") + exts
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
        self.assertEqual(wss.parse_client_hello_sni(rec), ("bad", None))


class TestClassify(unittest.TestCase):
    AI = ["gemini.google.com", "aistudio.google.com",
          "generativelanguage.googleapis.com", "notebooklm.google",
          "notebooklm.google.com", "robinfrontend-pa.googleapis.com",
          "signaler-pa.googleapis.com"]

    def test_exact_ai(self):
        self.assertTrue(wss.classify("gemini.google.com", self.AI))

    def test_android_gemini_app_backend(self):
        """اپِ اندرویدِ Gemini هرگز به gemini.google.com وصل نمی‌شود؛ بک‌اندش
        robinfrontend-pa است (Robin = نامِ داخلیِ پروژه). نبودنِ این دامنه در
        فهرست یعنی اپ اصلاً باز نمی‌شود — رگرسیونِ زندهٔ 2026-07-20."""
        self.assertTrue(wss.classify("robinfrontend-pa.googleapis.com",
                                     self.AI))

    def test_subdomain_ai(self):
        self.assertTrue(wss.classify("foo.gemini.google.com", self.AI))

    def test_collateral_google_search(self):
        self.assertFalse(wss.classify("www.google.com", self.AI))

    def test_collateral_youtube(self):
        self.assertFalse(wss.classify("www.youtube.com", self.AI))

    def test_collateral_play_api(self):
        self.assertFalse(wss.classify("play.googleapis.com", self.AI))

    def test_collateral_other_pa_backends(self):
        """همسایه‌های `-pa.googleapis.com` که در همان /24ها نشسته‌اند باید
        مستقیم بمانند — یعنی افزودنِ robinfrontend نباید به کلِ خانوادهٔ
        `-pa` سرریز کند (هر دو در شکارِ زندهٔ 2026-07-20 دیده شدند)."""
        self.assertFalse(wss.classify("firebaselogging-pa.googleapis.com",
                                      self.AI))
        self.assertFalse(wss.classify("photosdata-pa.googleapis.com",
                                      self.AI))

    def test_no_sni_defaults_ai(self):
        # fail-safe: بدونِ SNI → AI/WARP (رفتارِ امنِ امروز)
        self.assertTrue(wss.classify(None, self.AI))
        self.assertTrue(wss.classify("", self.AI))

    def test_not_fooled_by_suffix_substring(self):
        # «notgemini.google.com.evil.com» نباید AI حساب شود
        self.assertFalse(wss.classify("evilgemini.google.com.attacker.io",
                                      self.AI))

    def test_trailing_dot(self):
        self.assertTrue(wss.classify("gemini.google.com.", self.AI))


class TestGeoMark(unittest.TestCase):
    """رفعِ جغرافیا (0x79 → wg22): خانواده‌ی یوتیوب باید مارکِ GEO بگیرد، AI
    اولویت دارد، و بقیه مستقیم بمانند. گاردِ خانوادگیِ باگِ ۱۰ اوت ۲۰۲۶ —
    یوتیوب‌موزیکِ کاربر چون تونلِ مادر «روسیه» دیده می‌شد باز نمی‌شد."""
    AI = ["gemini.google.com", "generativelanguage.googleapis.com"]
    GEO = ["youtube.com", "youtubei.googleapis.com",
           "googlevideo.com", "ytimg.com"]

    def _mark(self, sni):
        """همان منطقِ تصمیمِ درون هندلر (TCP و QUIC یکسان‌اند)."""
        is_ai = wss.classify(sni, self.AI)
        is_geo = (not is_ai) and wss.classify(sni, self.GEO)
        return (wss.MARK_AI if is_ai
                else (wss.MARK_GEO if is_geo else wss.MARK_DIRECT))

    def test_whole_youtube_family_goes_geo(self):
        # کلِ خانواده — نه فقط نمونه‌ای که شکایت از آن بود
        for host in ("music.youtube.com", "www.youtube.com", "youtube.com",
                     "m.youtube.com", "s.youtube.com",
                     "youtubei.googleapis.com",
                     "rr1---sn-4g5e6nsz.googlevideo.com",
                     "i.ytimg.com", "s.ytimg.com"):
            self.assertEqual(self._mark(host), wss.MARK_GEO,
                             "باید GEO باشد: %s" % host)

    def test_ai_wins_over_geo(self):
        # اگر دامنه‌ای در هر دو فهرست بود، AI (WARP) مقدم است
        gemini_and_geo = self.GEO + ["gemini.google.com"]
        is_ai = wss.classify("gemini.google.com", self.AI)
        is_geo = (not is_ai) and wss.classify("gemini.google.com",
                                              gemini_and_geo)
        self.assertTrue(is_ai)
        self.assertFalse(is_geo)

    def test_no_sni_stays_warp_not_geo(self):
        # بی‌SNI ⇒ AI/WARP (fail-safe)، نه geo — geo نباید fail-safe را بدزدد
        self.assertEqual(self._mark(None), wss.MARK_AI)
        self.assertEqual(self._mark(""), wss.MARK_AI)

    def test_collateral_stays_direct(self):
        # گوگلِ غیرِیوتیوب و غیرِAI باید مستقیم بماند (نه geo، نه WARP)
        for host in ("www.google.com", "play.googleapis.com",
                     "mail.google.com"):
            self.assertEqual(self._mark(host), wss.MARK_DIRECT,
                             "باید DIRECT باشد: %s" % host)

    def test_geo_marks_are_distinct(self):
        # سه مارک نباید با هم برابر باشند وگرنه تفکیک بی‌معنی است
        self.assertEqual(len({wss.MARK_AI, wss.MARK_DIRECT, wss.MARK_GEO}), 3)


class TestLoadSuffixes(unittest.TestCase):
    def test_parses_domains_skips_ips(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                         delete=False) as f:
            f.write("# comment\n")
            f.write("gemini.google.com\n")
            f.write("1.2.3.0/24\n")          # رنج — باید رد شود
            f.write("8.8.8.8\n")             # IP — باید رد شود
            f.write("  aistudio.google.com  \n")
            f.write("\n")
            path = f.name
        try:
            got = wss.load_ai_suffixes(path)
            self.assertEqual(sorted(got),
                             ["aistudio.google.com", "gemini.google.com"])
        finally:
            os.unlink(path)


class TestLoopGuard(unittest.TestCase):
    """محافظِ حلقه: اتصالی که با TPROXY منحرف نشده مقصدِ اصلی ندارد و
    getsockname() خودِ این ماشین را برمی‌گرداند؛ وصل‌شدن به آن یعنی بازگشتِ
    نامتناهی. در عمل ۳ اتصالِ اسکنر ~۱۴۵۰ اتصالِ داخلی ساخت."""

    def setUp(self):
        self._saved = wss.LOCAL_ADDRS
        wss.LOCAL_ADDRS = {"203.0.113.68", "10.9.161.37", "127.0.0.1"}

    def tearDown(self):
        wss.LOCAL_ADDRS = self._saved

    def test_own_listen_port_is_loop(self):
        # اسکنِ مستقیمِ پورتِ splitter از اینترنت
        self.assertTrue(wss.is_loop_target(("203.0.113.68", wss.LISTEN_PORT)))

    def test_own_address_other_port_is_loop(self):
        self.assertTrue(wss.is_loop_target(("10.9.161.37", 443)))

    def test_loopback_is_loop(self):
        self.assertTrue(wss.is_loop_target(("127.0.0.1", 443)))

    def test_missing_dst_is_loop(self):
        self.assertTrue(wss.is_loop_target(None))

    def test_real_tproxy_target_passes(self):
        # مقصدِ واقعیِ منحرف‌شده باید عبور کند
        self.assertFalse(wss.is_loop_target(("142.251.152.2", 443)))
        self.assertFalse(wss.is_loop_target(("172.217.113.20", 443)))

    def test_refresh_local_addrs_includes_loopback(self):
        self.assertIn("127.0.0.1", wss.refresh_local_addrs())


class TestEchDetect(unittest.TestCase):
    """تشخیصِ اکستنشنِ Encrypted Client Hello (0xfe0d) — هشدارِ زودهنگامِ کوری."""

    ECH_EXT = ((0xfe0d).to_bytes(2, "big") + (4).to_bytes(2, "big")
               + b"\x00\x01\x02\x03")

    def test_ech_extension_detected(self):
        buf = build_client_hello("gemini.google.com", extra_exts=self.ECH_EXT)
        self.assertTrue(wss.ech_present(buf))
        # پارسِ SNI نباید با حضورِ ECH خراب شود (SNIِ بیرونی خوانده می‌شود)
        self.assertEqual(wss.parse_client_hello_sni(buf),
                         ("ok", "gemini.google.com"))

    def test_plain_hello_no_ech(self):
        self.assertFalse(wss.ech_present(build_client_hello("a.example.com")))
        self.assertFalse(wss.ech_present(build_client_hello(None)))

    def test_garbage_and_truncated_safe(self):
        self.assertFalse(wss.ech_present(b""))
        self.assertFalse(wss.ech_present(b"\x00\x01\x02"))
        self.assertFalse(wss.ech_present(b"GET / HTTP/1.1\r\n"))
        buf = build_client_hello("x.example.com", extra_exts=self.ECH_EXT)
        self.assertFalse(wss.ech_present(buf[:20]))   # رکوردِ ناقص

    def test_stats_have_blindness_keys(self):
        sp = wss.Splitter(None)
        for k in ("nosni_bytes", "ech_conns", "ech_bytes",
                  "quic_nosni_bytes"):
            self.assertIn(k, sp.stats)


class TestSniCounters(unittest.TestCase):
    """شمارنده‌های per-SNI (کشفِ دامنه): ثبت، کران، compaction و top."""

    def test_note_and_accumulate(self):
        st = {}
        wss.sni_note(st, "Gemini.Google.com.", 100, 1, True)
        wss.sni_note(st, "gemini.google.com", 50, 1, True)
        self.assertEqual(list(st.keys()), ["gemini.google.com"])
        self.assertEqual(st["gemini.google.com"][0], 150)   # bytes
        self.assertEqual(st["gemini.google.com"][1], 2)     # conns
        self.assertEqual(st["gemini.google.com"][2], 1)     # is_ai

    def test_no_sni_aggregates_under_empty_key(self):
        st = {}
        wss.sni_note(st, None, 10, 1, True)
        wss.sni_note(st, "", 20, 1, True)
        self.assertEqual(st[""][0], 30)
        self.assertEqual(st[""][1], 2)

    def test_reclassify_follows_targets_change(self):
        # با تغییرِ فهرستِ مقصدها، طبقه‌بندیِ ردیفِ موجود باید به‌روز شود
        st = {}
        wss.sni_note(st, "x.example.com", 10, 1, False)
        self.assertEqual(st["x.example.com"][2], 0)
        wss.sni_note(st, "x.example.com", 10, 1, True)
        self.assertEqual(st["x.example.com"][2], 1)

    def test_bounded_when_full(self):
        st = {}
        for i in range(wss.SNI_MAX):
            wss.sni_note(st, "h%d.example.com" % i, 1, 1, False)
        wss.sni_note(st, "overflow.example.com", 1, 1, False)
        self.assertEqual(len(st), wss.SNI_MAX)
        self.assertNotIn("overflow.example.com", st)

    def test_compact_drops_idle_then_keeps_both_axes(self):
        st = {}
        now = 1_000_000
        # یک ردیفِ کهنه (بی‌ترافیک بیش از یک روز) — باید بیفتد
        st["stale.example.com"] = [9999, 1, 0, now - wss.SNI_IDLE - 10]
        # بایت صعودی و شمارِ اتصال نزولی: دو محور عمداً معکوسِ هم، تا معلوم
        # شود نگه‌داشتن روی هر دو انجام می‌شود نه فقط یکی
        for i in range(wss.SNI_MAX):
            st["h%d.example.com" % i] = [i + 1, wss.SNI_MAX - i, 0, now]
        wss.sni_compact(st, now=now)
        self.assertNotIn("stale.example.com", st)
        # سقف همان سه‌چهارمِ قبلی است
        self.assertLessEqual(len(st), wss.SNI_MAX * 3 // 4)
        self.assertIn("h%d.example.com" % (wss.SNI_MAX - 1), st)   # سرِ محورِ حجم
        self.assertIn("h0.example.com", st)                        # سرِ محورِ اتصال
        # میانه در هیچ‌کدام از دو سرِ طیف نیست → می‌افتد
        self.assertNotIn("h%d.example.com" % (wss.SNI_MAX // 2), st)

    def test_compact_keeps_blocked_domain(self):
        """دامنه‌ی ۴۰۳ چند صد بایت جابه‌جا می‌کند ولی ده‌ها بار تلاشِ دوباره
        دارد. با ملاکِ صرفاً حجمی اول قربانی می‌شد و کشفِ خودکار هرگز
        نمی‌دیدش — همان چیزی که notebook.google.com را پنهان کرده بود."""
        st = {}
        now = 1_000_000
        for i in range(wss.SNI_MAX):
            st["fat%d.example.com" % i] = [10_000_000 + i, 1, 0, now]
        st["blocked.google.com"] = [400, 900, 0, now]
        wss.sni_compact(st, now=now)
        self.assertIn("blocked.google.com", st)

    def test_compact_keeps_fresh_small_table(self):
        st = {"a.example.com": [5, 1, 1, int(wss.time.time())]}
        wss.sni_compact(st)
        self.assertIn("a.example.com", st)

    def test_top_sorted_by_bytes(self):
        st = {}
        wss.sni_note(st, "small.example.com", 10, 1, False)
        wss.sni_note(st, "big.example.com", 1000, 1, True)
        wss.sni_note(st, "mid.example.com", 100, 1, False)
        top = wss.sni_top(st, n=2)
        self.assertEqual([r[0] for r in top],
                         ["big.example.com", "mid.example.com"])
        self.assertEqual(top[0][1:], [1000, 1, 1])   # bytes, conns, is_ai

    def test_top_conns_ranks_independently_of_bytes(self):
        """دو فهرست باید دو ترتیبِ متفاوت بدهند، وگرنه فهرستِ دوم بی‌فایده است."""
        st = {}
        wss.sni_note(st, "fat.example.com", 1_000_000, 2, False)
        wss.sni_note(st, "blocked.google.com", 400, 90, False)
        self.assertEqual([r[0] for r in wss.sni_top(st, n=1)],
                         ["fat.example.com"])
        self.assertEqual([r[0] for r in wss.sni_top_conns(st, n=1)],
                         ["blocked.google.com"])
        # ساختارِ ردیف در هر دو یکسان است (autodetect هر دو را یک‌جور می‌خوانَد)
        self.assertEqual(wss.sni_top_conns(st, n=1)[0], ["blocked.google.com",
                                                         400, 90, 0])

    def test_src_note_and_split_columns(self):
        st = {}
        wss.src_note(st, "192.168.188.20", 100, 1, True)
        wss.src_note(st, "192.168.188.20", 40, 1, False)
        e = st["192.168.188.20"]
        self.assertEqual(e[0], 100)   # ai_bytes
        self.assertEqual(e[1], 40)    # direct_bytes
        self.assertEqual(e[2], 1)     # ai_conns
        self.assertEqual(e[3], 1)     # direct_conns
        # مبدأِ خالی نباید ردیف بسازد
        wss.src_note(st, "", 10, 1, True)
        self.assertEqual(len(st), 1)

    def test_src_bounded_and_compact(self):
        st = {}
        now = 2_000_000
        for i in range(wss.SRC_MAX):
            st["10.0.%d.%d" % (i // 256, i % 256)] = [i + 1, 0, 1, 0, now]
        wss.src_note(st, "192.168.188.99", 5, 1, True)   # جدول پر → رد
        self.assertEqual(len(st), wss.SRC_MAX)
        self.assertNotIn("192.168.188.99", st)
        st["stale"] = [1, 1, 1, 1, now - wss.SRC_IDLE - 5]
        wss.src_compact(st, now=now)
        self.assertNotIn("stale", st)
        self.assertEqual(len(st), wss.SRC_MAX * 3 // 4)

    def test_src_top_sorted_by_ai_bytes(self):
        st = {}
        wss.src_note(st, "u-light", 10, 1, True)
        wss.src_note(st, "u-heavy", 900, 1, True)
        wss.src_note(st, "u-collateral", 50, 1, False)   # فقط کولترال
        top = wss.src_top(st, n=3)
        self.assertEqual(top[0][0], "u-heavy")
        self.assertEqual(top[0][1], 900)
        # مرتب‌سازی بر پایه‌ی AI است، نه جمعِ کل
        self.assertEqual([r[0] for r in top][:2], ["u-heavy", "u-light"])

    def test_quic_classify_returns_sni_tuple(self):
        # قراردادِ جدیدِ _classify_initial سه‌تایی است (is_ai، tag، sni)
        qs = wss.QuicSplitter.__new__(wss.QuicSplitter)
        qs.get_suffixes = lambda: ["gemini.google.com"]
        saved = wss.quic_sni
        try:
            wss.quic_sni = None
            self.assertEqual(qs._classify_initial(b"x"), (True, "no_sni", None))

            class _FakeQuic:
                @staticmethod
                def sni_from_initial(data, parser):
                    return "ok", "gemini.google.com"
            wss.quic_sni = _FakeQuic
            self.assertEqual(qs._classify_initial(b"x"),
                             (True, "ok", "gemini.google.com"))
        finally:
            wss.quic_sni = saved


class PipeLifetimeTests(unittest.TestCase):
    """سقفِ عمرِ جریانِ TCP در pipe() — رگرسیونِ نشتِ fd (۲۰۲۶-۰۷-۲۱).

    بدونِ سقف، جریانی که یک سرش بی‌خداحافظی غیب می‌شد برای همیشه در
    sock_recv می‌ماند (هر جریان دو سوکت) تا در پیکِ شبانه fd تمام شد؛
    این‌جا با ثابت‌های کوچک‌شده ثابت می‌کنیم جریانِ مرده ظرفِ مهلت بسته
    می‌شود و جریانِ فعال نه بسته می‌شود نه داده‌ای گم می‌کند."""

    def setUp(self):
        self._saved = (wss.PIPE_POLL, wss.IDLE_TIMEOUT,
                       wss.HALF_CLOSE_GRACE, wss.SEND_TIMEOUT)
        wss.PIPE_POLL = 0.05
        wss.IDLE_TIMEOUT = 0.2
        wss.HALF_CLOSE_GRACE = 0.1
        wss.SEND_TIMEOUT = 0.5
        self.loop = asyncio.new_event_loop()
        self.socks = []

    def tearDown(self):
        (wss.PIPE_POLL, wss.IDLE_TIMEOUT,
         wss.HALF_CLOSE_GRACE, wss.SEND_TIMEOUT) = self._saved
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        self.loop.close()

    def _pair(self):
        a, b = socket.socketpair()
        a.setblocking(False)
        b.setblocking(False)
        self.socks += [a, b]
        return a, b

    def test_half_closed_flow_reaped(self):
        """جهتِ ساکتی که همتایش EOF دیده ظرفِ grace بسته می‌شود — همان
        جفت‌های CLOSE-WAIT/FIN-WAIT-2ِ حادثه."""
        src, _peer = self._pair()
        dst, _peer2 = self._pair()
        flow = wss._FlowState()
        flow.eof = True                     # جهتِ مقابل EOF دیده است
        sp = wss.Splitter(self.loop)
        t0 = time.monotonic()
        self.loop.run_until_complete(
            asyncio.wait_for(sp.pipe(src, dst, None, flow), 5))
        self.assertLess(time.monotonic() - t0, 2)

    def test_fully_idle_flow_reaped(self):
        """جریانِ دوطرفه‌بازِ بی‌ترافیک بعد از IDLE_TIMEOUT بسته می‌شود."""
        src, _peer = self._pair()
        dst, _peer2 = self._pair()
        sp = wss.Splitter(self.loop)
        self.loop.run_until_complete(
            asyncio.wait_for(sp.pipe(src, dst, None, wss._FlowState()), 5))

    def test_active_flow_survives_and_passes_data(self):
        """فعالیت flow.last را تازه می‌کند: عمرِ جریان از IDLE_TIMEOUT
        می‌گذرد ولی بسته نمی‌شود؛ داده و شمارنده هم سالم‌اند.

        حاشیه: فاصله‌ی نوشتن 0.35s در برابرِ سقفِ 2s ⇒ ~1.65s تحمل، و
        جمعِ 2.8s همچنان از IDLE_TIMEOUT بیشتر است (شرطِ معنادار بودنِ
        تست). ۱۵ اوت ۲۰۲۶ با سقفِ 1s یک بار در باتری قرمز شد — ۳۰ بایت
        به‌جای ۴۰ — و در ۱۵ اجرای منزوی، ۸ اجرای زیرِ بارِ CPU و یک
        اجرای کاملِ سوییت بازتولید نشد. حاشیه گشادتر شد چون تنها راهِ
        رسیدن به مضربِ کاملِ ۱۰ بایتِ کم، شکستنِ لوله بینِ دو نوشتن است.

        ⚠️ SEND_TIMEOUT و HALF_CLOSE_GRACE عمداً روی مقدارِ setUp
        (0.5 و 0.1) می‌مانند — این تست فقط IDLE_TIMEOUT را می‌سنجد. اگر
        روزی امضای شکست عوض شد، اول همان دو را نگاه کن.
        """
        wss.IDLE_TIMEOUT = 2.0
        cl_out, cl_in = self._pair()
        up_out, up_in = self._pair()
        flow = wss._FlowState()
        cnt = [0]
        sp = wss.Splitter(self.loop)

        async def scenario():
            task = self.loop.create_task(sp.pipe(cl_in, up_out, cnt, flow))
            for _ in range(8):              # جمعاً ~2.8s > IDLE_TIMEOUT=2
                await self.loop.sock_sendall(cl_out, b"x" * 10)
                await asyncio.sleep(0.35)
            cl_out.close()                  # EOF → پایانِ تمیز
            await asyncio.wait_for(task, 5)
            got = b""
            while True:
                try:
                    chunk = await asyncio.wait_for(
                        self.loop.sock_recv(up_in, 4096), 1)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                got += chunk
            return got

        got = self.loop.run_until_complete(scenario())
        # هر سه با هم assert می‌شوند، نه پشتِ‌سرِ هم. علتش یک شکستِ واقعیِ
        # ۱۵ اوت ۲۰۲۶ است: assertEqual(got, …) اول می‌شکست و دو سنجه‌ی
        # بعدی هرگز اجرا نمی‌شدند — در حالی که **امضای علت در همان‌ها
        # بود**. شکستنِ لوله از IDLE_TIMEOUT ⇒ eof=False و cnt کم؛ ولی
        # گم‌شدنِ داده در خواندنِ تست ⇒ eof=True و cnt کامل. با ترتیبِ
        # قبلی این دو از هم تفکیک‌پذیر نبودند.
        self.assertEqual(
            (len(got), cnt[0], flow.eof), (80, 80, True),
            "(بایتِ خوانده‌شده، شمارنده، eof) — اگر eof=False و شمارنده "
            "کم بود، لوله از IDLE_TIMEOUT شکسته؛ اگر eof=True و شمارنده "
            "۸۰ بود، داده در حلقه‌ی خواندنِ خودِ تست گم شده.")
        self.assertEqual(got, b"x" * 80)


class QuicIdleTTLTests(unittest.TestCase):
    """TTLِ جدولِ جریانِ QUIC — تنظیم‌پذیری و کفایتِ پیش‌فرض.

    چرا این تست وجود دارد: SNI فقط در پکتِ Initial است و پکت‌های بعدیِ همان
    اتصال short-header‌اند (ذاتاً بی‌SNI). تصمیمِ درست تنها از راهِ جدولِ
    جریان به آن‌ها می‌رسد، پس اگر TTL کوتاه‌تر از سکوتِ معمولِ یک اتصالِ
    زنده باشد، جریان جارو می‌شود و پکتِ بعدی fail-open به WARP می‌رود —
    هم مصرفِ بی‌مورد، هم تعویضِ آی‌پیِ مبدأ وسطِ اتصالِ زنده.
    """

    def _reload(self, value):
        """ماژول را با WSS_QUIC_IDLEِ دلخواه دوباره بار می‌کند.

        importِ ماژول سروری راه نمی‌اندازد (همه زیرِ __main__)، پس این امن
        است. مقدارِ None یعنی «متغیر اصلاً ست نشده».
        """
        old = os.environ.get("WSS_QUIC_IDLE")
        if value is None:
            os.environ.pop("WSS_QUIC_IDLE", None)
        else:
            os.environ["WSS_QUIC_IDLE"] = value
        try:
            spec = importlib.util.spec_from_file_location(
                "wss_reload",
                os.path.join(os.path.dirname(__file__), "..", "deploy",
                             "warp-sni-splitter.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        finally:
            if old is None:
                os.environ.pop("WSS_QUIC_IDLE", None)
            else:
                os.environ["WSS_QUIC_IDLE"] = old

    def test_default_is_long_enough_for_idle_connections(self):
        # باید بلندتر از سکوتِ متعارفِ یک اتصالِ زنده باشد (بافرِ ویدیو،
        # تبِ پس‌زمینه). ۶۰ ثانیه کم بود: ۹۹٪ اتصالاتِ QUICِ رفته به WARP
        # از همان جاروی زودهنگام می‌آمد، نه از تشخیصِ واقعیِ AI.
        mod = self._reload(None)
        self.assertGreaterEqual(mod.QUIC_IDLE, 180.0)
        self.assertEqual(mod.QUIC_IDLE, 300.0)

    def test_env_override(self):
        mod = self._reload("45")
        self.assertEqual(mod.QUIC_IDLE, 45.0)

    def test_empty_env_falls_back_to_default(self):
        """رشته‌ی خالی نباید ValueError بدهد (یونیت با متغیرِ خالی)."""
        mod = self._reload("")
        self.assertEqual(mod.QUIC_IDLE, 300.0)

    def test_sweep_threshold_uses_the_ttl(self):
        """جریانِ ساکت‌تر از TTL جارو می‌شود و تازه‌تر از آن می‌ماند."""
        mod = self._reload("300")
        now = time.monotonic()
        fresh = now - 100      # ۱۰۰s سکوت: با TTLِ ۳۰۰ باید بماند
        stale = now - 400      # ۴۰۰s سکوت: باید جارو شود
        self.assertLessEqual(now - fresh, mod.QUIC_IDLE)
        self.assertGreater(now - stale, mod.QUIC_IDLE)


# ============================================================================
# فیکسچرِ QUIC: ساختِ بستهٔ Initialِ **واقعی و رمزنگاری‌شده**
# ============================================================================
# چرا این‌قدر زحمت و نه یک نگاشتِ مصنوعیِ {offset: bytes}: ارزشِ رفع در
# استخراجِ سرتاسری است. نگاشتِ دستی فقط منطقِ ادغام را می‌سنجد و اگر
# رمزگشایی/هدرِ پکتِ دوم بشکند هیچ تستی نمی‌فهمد.
#
# ماژول عمداً فقط **رمزگشایی** دارد (کارِ splitter خواندن است نه نوشتن)، پس
# قرینه‌ی رمزگذاریِ GCM این‌جا و فقط برای فیکسچر نوشته شده — دقیقاً با همان
# کنوانسیون‌های aes128_gcm_decrypt.
def _gcm_encrypt(key, iv, plaintext, aad):
    aes = q.AES128(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"          # IVِ ۱۲بایتی
    out = bytearray()
    ctr = int.from_bytes(j0, "big")
    for i in range(0, len(plaintext), 16):
        ctr = (ctr & ~0xffffffff) | ((ctr + 1) & 0xffffffff)
        ks = aes.encrypt_block(ctr.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(plaintext[i:i + 16], ks))
    ct = bytes(out)
    lens = struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
    ghash_in = (aad + b"\x00" * ((-len(aad)) % 16)
                + ct + b"\x00" * ((-len(ct)) % 16) + lens)
    s_val = q._ghash(h, ghash_in)
    tag = (s_val ^ int.from_bytes(aes.encrypt_block(j0), "big")
           ).to_bytes(16, "big")
    return ct, tag


def _venc(v):
    """کدگذاریِ varint ِ QUIC (قرینه‌ی _varint ِ ماژول)."""
    if v < 64:
        return bytes([v])
    if v < 16384:
        return (0x4000 | v).to_bytes(2, "big")
    if v < 1073741824:
        return (0x80000000 | v).to_bytes(4, "big")
    return (0xc000000000000000 | v).to_bytes(8, "big")


def crypto_frame(offset, data):
    return b"\x06" + _venc(offset) + _venc(len(data)) + data


def build_initial(dcid, pn, frames):
    """یک دیتاگرامِ QUIC Initialِ کاملِ محافظت‌شده (نسخه‌ی ۱، پیلودِ دلخواه)."""
    pn_len = 4
    first = 0xC0 | (pn_len - 1)            # long header + Initial + pn_len
    key, iv, hp = q.initial_secrets(dcid)
    pn_bytes = pn.to_bytes(pn_len, "big")
    length = pn_len + len(frames) + 16     # pn + ciphertext + tag
    hdr = (bytes([first]) + (1).to_bytes(4, "big")
           + bytes([len(dcid)]) + dcid
           + b"\x00"                       # SCIDِ خالی
           + _venc(0)                      # tokenِ خالی
           + _venc(length) + pn_bytes)
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    ct, tag = _gcm_encrypt(key, nonce, frames, hdr)
    body = ct + tag
    # header protection: نمونه از offsetِ pn_offset+4 — با pn_lenِ ۴ یعنی
    # دقیقاً ۱۶ بایتِ اولِ ciphertext
    mask = q.AES128(hp).encrypt_block(body[:16])
    prot_first = first ^ (mask[0] & 0x0f)
    prot_pn = bytes(pn_bytes[i] ^ mask[1 + i] for i in range(pn_len))
    return (bytes([prot_first]) + hdr[1:len(hdr) - pn_len] + prot_pn + body)


def _pad_ext(n):
    """اکستنشنِ حجیم — جای key_shareِ پساکوانتومیِ X25519MLKEM768."""
    return (0x0015).to_bytes(2, "big") + n.to_bytes(2, "big") + b"\x00" * n


def _sni_ext(host):
    h = host.encode("ascii")
    sn = b"\x00" + len(h).to_bytes(2, "big") + h
    snl = len(sn).to_bytes(2, "big") + sn
    return (0x0000).to_bytes(2, "big") + len(snl).to_bytes(2, "big") + snl


def big_hello(host, sni_first=False, pad=1400):
    """ClientHelloِ بزرگ‌تر از یک پکتِ Initial (بدونِ هدرِ رکوردِ TLS).

    sni_first=False یعنی SNI **بعد** از اکستنشنِ حجیم می‌آید، پس در پکتِ
    دوم می‌افتد — همان نیمه‌ای که امروز بی‌نام می‌ماند. کروم ترتیبِ
    اکستنشن‌ها را می‌چیند، پس هر دو حالت در طبیعت رخ می‌دهد.
    """
    exts = (_sni_ext(host) + _pad_ext(pad) if sni_first
            else _pad_ext(pad) + _sni_ext(host))
    return build_client_hello(sni=None, extra_exts=exts)[5:]


class MultiPacketHelloTests(unittest.TestCase):
    """ClientHelloِ پخش‌شده در چند پکتِ Initial (پلنِ ۰۵۰).

    بازآرایی فقط داخلِ **یک** دیتاگرام بود. با X25519MLKEM768 که در کروم و
    فایرفاکسِ امروز پیش‌فرض است ClientHello از ~۱۲۰۰ بایت رد می‌شود و در دو
    پکت می‌آید — پس جریان بی‌نام می‌ماند، fail-open به WARP می‌رفت، و در
    جدولِ کشفِ دامنه زیرِ «بدونِ SNI» ثبت می‌شد.
    """
    DCID = bytes.fromhex("8394c8f03e515708")
    HOST = "late.example.com"
    SPLIT = 1100

    def setUp(self):
        hello = big_hello(self.HOST)
        self.assertGreater(len(hello), 1200, "فیکسچر باید چندپکتی باشد")
        self.pkt1 = build_initial(self.DCID, 0,
                                  crypto_frame(0, hello[:self.SPLIT]))
        self.pkt2 = build_initial(self.DCID, 1,
                                  crypto_frame(self.SPLIT,
                                               hello[self.SPLIT:]))
        self.qs = wss.QuicSplitter.__new__(wss.QuicSplitter)
        self.qs.stats = wss.Splitter(None).stats
        self.qs.sni_stats = {}
        self.qs.src_stats = {}
        self.qs.get_suffixes = lambda: ["gemini.google.com"]

    def flow(self):
        return wss._QuicFlow(None, ("1.2.3.4", 443), ("192.168.1.9", 5000))

    # ---- سلامتِ خودِ فیکسچر ----
    def test_the_fixture_decrypts(self):
        self.assertIsNotNone(q.decrypt_initial(self.pkt1))
        self.assertIsNotNone(q.decrypt_initial(self.pkt2))
        self.assertEqual(list(q.crypto_from_datagram(self.pkt2)),
                         [self.SPLIT])

    # ---- هسته‌ی رفع ----
    def test_one_packet_alone_is_not_mistaken_for_a_complete_hello(self):
        """پکتِ اول به‌تنهایی «ناقص» است، نه «بدونِ SNI».

        رکوردِ TLSِ جعلی با طولِ بایت‌های موجود ساخته می‌شود، پس از دیدِ
        پارسر خودسازگار است و ClientHelloِ بریده را «کاملِ بدونِ SNI»
        می‌دید — همان جایی که نام برای همیشه گم می‌شد.
        """
        self.assertEqual(q.sni_from_initial(self.pkt1,
                                            wss.parse_client_hello_sni),
                         ("need_more", None))

    def test_sni_from_a_hello_split_across_two_initials(self):
        fl = self.flow()
        self.qs._begin_hello(fl, self.pkt1)
        self.assertIsNotNone(fl.pend, "پکتِ اول باید بافر شود")
        self.assertIsNone(fl.sni)
        self.qs._continue_hello(fl, self.pkt2)
        self.assertEqual(fl.sni, self.HOST)
        self.assertIsNone(fl.pend, "بعد از حل، بافر باید آزاد شود")
        self.assertEqual(self.qs.stats["quic_hello_multi"], 1)
        self.assertEqual(self.qs.stats["quic_hello_giveup"], 0)
        # و جدولِ کشفِ دامنه نام را دیده — نه کلیدِ ''
        self.assertIn(self.HOST, self.qs.sni_stats)
        self.assertNotIn("", self.qs.sni_stats)

    def test_out_of_order_initials_still_yield_the_sni(self):
        """UDP ترتیب تضمین نمی‌کند — پکتِ دوم می‌تواند اول برسد."""
        fl = self.flow()
        self.qs._begin_hello(fl, self.pkt2)
        self.assertIsNotNone(fl.pend)
        self.qs._continue_hello(fl, self.pkt1)
        self.assertEqual(fl.sni, self.HOST)

    def test_a_single_packet_hello_still_works(self):
        """رگرسیون: حالتِ رایجِ تک‌پکتی نباید عوض شود."""
        hello = build_client_hello(sni="gemini.google.com")[5:]
        pkt = build_initial(self.DCID, 0, crypto_frame(0, hello))
        self.assertEqual(
            self.qs._classify_initial(pkt),
            (True, "ok", "gemini.google.com"))

    def test_an_sni_in_the_first_packet_is_still_found_immediately(self):
        """نیمه‌ای که امروز درست کار می‌کند باید دست‌نخورده بماند.

        کروم ترتیبِ اکستنشن‌ها را می‌چیند، پس تقریباً نیمی از
        ClientHelloهای دوپکتی SNI را در پکتِ اول دارند و همین حالا درست
        مسیریابی می‌شوند. «کامل‌گراییِ» بی‌دقت همان نیمه را هم به fail-open
        می‌فرستاد — یعنی رفع، مسیریابی را بدتر می‌کرد.
        """
        hello = big_hello("early.example.com", sni_first=True)
        pkt = build_initial(self.DCID, 0, crypto_frame(0, hello[:self.SPLIT]))
        self.assertEqual(self.qs._classify_initial(pkt),
                         (False, "ok", "early.example.com"))

    # ---- تصمیم و فوروارد نباید عوض شده باشند ----
    def test_a_stale_quic_sni_module_disables_accumulation_not_the_path(self):
        """اختلافِ نسخه‌ی دو فایلِ همراه نباید حلقه‌ی داده را بشکند.

        `quic_sni.py` تا امروز در `ansible/sync-files.sh` نبود، پس ماژولِ
        کهنه در برابرِ splitterِ تازه فرضی نیست. با ماژولِ کهنه رفتار باید
        دقیقاً همان پیشِ این تغییر شود، نه AttributeError وسطِ حلقه.
        """
        saved = wss.QUIC_REASSEMBLY
        try:
            wss.QUIC_REASSEMBLY = False
            self.assertEqual(self.qs._classify_initial(self.pkt1),
                             (True, "bad", None))
        finally:
            wss.QUIC_REASSEMBLY = saved

    def test_a_pending_flow_keeps_todays_fail_open_decision(self):
        """این پلن «فرصتِ دومِ تصمیم» اضافه می‌کند، نه تغییرِ مسیر."""
        is_ai, tag, sni = self.qs._classify_initial(self.pkt1)
        self.assertEqual((is_ai, tag, sni), (True, "need_more", None))

    def test_a_late_name_that_would_have_gone_direct_is_counted(self):
        """سهمِ عددیِ همین باگ در ترافیکِ WARP — مبنای تصمیمِ بعدی."""
        fl = self.flow()
        self.qs._begin_hello(fl, self.pkt1)
        self.qs._continue_hello(fl, self.pkt2)
        self.assertEqual(self.qs.stats["quic_hello_misrouted"], 1)
        self.assertTrue(fl.is_ai is None or fl.is_ai,
                        "مسیر نباید عوض شده باشد")

    # ---- کران‌ها: ورودی UDPِ احراز هویت‌نشده است ----
    def test_a_flow_that_never_completes_is_bounded(self):
        fl = self.flow()
        self.qs._begin_hello(fl, self.pkt1)
        for _ in range(wss.QUIC_HELLO_PKTS + 2):
            if fl.pend is None:
                break
            self.qs._continue_hello(fl, self.pkt1)     # همان offset، بی‌پیشرفت
        self.assertIsNone(fl.pend, "بافر باید رها شده باشد")
        self.assertEqual(self.qs.stats["quic_hello_giveup"], 1)

    def test_sparse_offsets_cannot_grow_the_buffer(self):
        """آفستِ پراکنده‌ی بزرگ نباید بافر را باد کند.

        کران روی **مجموعِ بایتِ بافرشده** است نه بزرگ‌ترین offset — با
        کرانِ آفست‌محور، جریانِ ۰/۱M/۲M از کنارش رد می‌شد.
        """
        fl = self.flow()
        fl.pend = {}
        chunk = b"\x00" * 4096
        for k in range(64):
            if fl.pend is None:
                break
            self.qs._feed_hello(fl, {1_000_000 * (k + 1): chunk})
        self.assertIsNone(fl.pend)
        self.assertLessEqual(fl.pend_bytes, wss.QUIC_HELLO_MAX)
        self.assertEqual(self.qs.stats["quic_hello_giveup"], 1)

    def test_frame_count_is_bounded_too(self):
        """frameِ خردِ فراوان نباید نگاشت را باد کند."""
        fl = self.flow()
        fl.pend = {}
        self.qs._feed_hello(fl, {n: b"\x01" for n in
                                 range(1, wss.QUIC_HELLO_FRAMES + 50)})
        self.assertIsNone(fl.pend)
        self.assertEqual(self.qs.stats["quic_hello_giveup"], 1)

    # ---- رها کردن باید دقیقاً حسابداریِ امروز را بدهد ----
    def test_giving_up_falls_back_to_todays_no_sni_accounting(self):
        fl = self.flow()
        fl.is_ai = True
        self.qs._begin_hello(fl, self.pkt1)
        self.qs._giveup_hello(fl)
        self.assertTrue(fl.nosni)
        self.assertEqual(self.qs.stats["quic_no_sni"], 1)
        self.assertEqual(self.qs.sni_stats[""][1], 1)   # اتصال گم نشده
        self.assertEqual(self.qs.src_stats["192.168.1.9"][2], 1)

    def test_a_non_initial_datagram_ends_the_wait(self):
        """پکتِ short-header یعنی handshake رد شده — نام دیگر نمی‌آید."""
        fl = self.flow()
        self.qs._begin_hello(fl, self.pkt1)
        self.qs._continue_hello(fl, b"\x40" + b"\x00" * 40)
        self.assertIsNone(fl.pend)
        self.assertEqual(self.qs.stats["quic_hello_giveup"], 1)

    def test_a_dead_flow_flushes_its_pending_hello(self):
        """جریانی که پیش از کامل‌شدن جارو شود نباید شمارشش گم شود."""
        fl = self.flow()
        fl.up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(fl.up.close)
        self.qs.sel = type("S", (), {"unregister": lambda *a: None})()
        self.qs.up_index = {}
        self.qs.flows = {}
        self.qs.reply_socks = {}
        self.qs._begin_hello(fl, self.pkt1)
        self.qs._close_flow(fl)
        self.assertEqual(self.qs.stats["quic_hello_giveup"], 1)
        self.assertEqual(self.qs.stats["quic_no_sni"], 1)


class FdHeadroomTests(unittest.TestCase):
    """سنجه‌ی فضای fd در _beat باید QUIC را هم بشمارد (پلنِ ۰۵۱).

    _beat لچ‌دار است: بعد از اولین EMFILE ضربان **قطع می‌ماند** تا فضای
    واقعی برگردد. در حادثه‌ی ۲۰۲۶-۰۷-۲۱ سنجه‌ی شانسی باعث شد گارد TPROXY
    را برگرداند، پروسه دوباره اشباع شود، و سیستم هر ~۴۵ ثانیه flap کند.
    شمردنِ فقط TCP همان کم‌برآوردی است که لچ را زودتر از موعد باز می‌کند.
    """

    def setUp(self):
        self._orig = wss.STATS_FILE
        wss.STATS_FILE = os.path.join(tempfile.gettempdir(),
                                      "wss-nonexistent-baseline.stats")
        self.sp = wss.Splitter(None)
        self.sp._hb_block = True
        self._hb = wss.HEARTBEAT_FILE
        wss.HEARTBEAT_FILE = os.path.join(tempfile.mkdtemp(), "hb")

    def tearDown(self):
        wss.STATS_FILE = self._orig
        wss.HEARTBEAT_FILE = self._hb

    class _rlimit:
        """RLIMIT_NOFILEِ نرمِ ساختگی — بدونِ دست‌زدن به سقفِ واقعیِ پروسه."""
        def __init__(self, soft):
            self.soft = soft

        def __enter__(self):
            self._orig = wss.resource.getrlimit
            wss.resource.getrlimit = lambda _w: (self.soft, self.soft)

        def __exit__(self, *a):
            wss.resource.getrlimit = self._orig

    def test_headroom_check_counts_quic_flows(self):
        """با QUICِ اشباع، لچ نباید باز شود — حتی اگر TCP خلوت باشد."""
        self.sp.stats["active"] = 10
        self.sp.stats["quic_flows"] = 400      # به‌تنهایی از سقف رد می‌شود
        self.sp.stats["quic_fds"] = 400
        with self._rlimit(512):
            self.sp._beat()
        self.assertTrue(self.sp._hb_block)

    def test_reply_sockets_of_a_draining_process_are_counted(self):
        """سوکتِ پاسخ تا جاروی بعدی بعد از آخرین جریانش زنده می‌ماند.

        در آن پنجره quic_flows صفر است ولی صدها fd هنوز باز — شمارشِ
        صرفاً جریان‌محور همان‌جا کم می‌آورد و لچ را باز می‌کند.
        """
        self.sp.stats["active"] = 1
        self.sp.stats["quic_flows"] = 0
        self.sp.stats["quic_fds"] = 480
        with self._rlimit(512):
            self.sp._beat()
        self.assertTrue(self.sp._hb_block)

    def test_latch_releases_when_both_counts_are_low(self):
        self.sp.stats["active"] = 1
        self.sp.stats["quic_flows"] = 1
        self.sp.stats["quic_fds"] = 2
        with self._rlimit(1024):
            self.sp._beat()
        self.assertFalse(self.sp._hb_block)

    def test_missing_quic_keys_do_not_raise(self):
        """QUIC خاموش ⇒ نبودِ کلید نباید KeyError بدهد."""
        self.sp.stats.pop("quic_flows", None)
        self.sp.stats.pop("quic_fds", None)
        self.sp.stats["active"] = 1
        with self._rlimit(1024):
            self.sp._beat()
        self.assertFalse(self.sp._hb_block)

    def test_the_coefficient_is_an_upper_bound_not_a_guess(self):
        """ضریب باید دستِ‌کم سوکتِ خروجی + سوکتِ پاسخ را بپوشاند."""
        self.assertGreaterEqual(wss.QUIC_FD_PER_FLOW, 2)

    def test_tcp_only_saturation_still_blocks(self):
        """رگرسیون: رفتارِ اصلیِ TCP نباید عوض شده باشد."""
        self.sp.stats["active"] = 300
        self.sp.stats["quic_flows"] = 0
        self.sp.stats["quic_fds"] = 0
        with self._rlimit(512):
            self.sp._beat()
        self.assertTrue(self.sp._hb_block)

    def test_the_latch_itself_is_unchanged(self):
        """گاردِ رفعِ حادثه در برابرِ دقیقاً همین‌جور ویرایش‌ها.

        خطوطِ کامنت پیش از تطبیق حذف می‌شوند: این مخزن دو بار گاردی
        فرستاده که کامنتِ توصیفِ تله را می‌گرفته، نه خودِ کد را.
        """
        with open(os.path.join(os.path.dirname(__file__), "..", "deploy",
                               "warp-sni-splitter.py"),
                  encoding="utf-8") as f:
            src = f.read()
        body = "\n".join(l for l in src.splitlines()
                         if not l.lstrip().startswith("#"))
        for needle in ("self._hb_block = True",
                       "os.unlink(HEARTBEAT_FILE)",
                       "errno.EMFILE"):
            self.assertIn(needle, body, "لچِ حادثه‌ی ۲۰۲۶-۰۷-۲۱ دست خورده")

    def test_quic_fds_tracks_flows_and_reply_sockets(self):
        """عددِ منتشرشده باید هر دو مؤلفه را بشمارد، نه فقط جریان‌ها."""
        qs = wss.QuicSplitter.__new__(wss.QuicSplitter)
        qs.stats = {}
        qs.flows = {("c", i): None for i in range(5)}
        qs.reply_socks = {("d", i): None for i in range(3)}
        qs._note_fds()
        self.assertEqual(qs.stats["quic_flows"], 5)
        self.assertEqual(qs.stats["quic_fds"], 8)


class StatsBaselineTests(unittest.TestCase):
    """بازگردانیِ مبنای شمارنده‌ها بینِ اجراها (پلنِ ۰۴۹).

    فایلِ آمار نوشته می‌شد ولی هرگز خوانده نمی‌شد، پس هر ری‌استارت — ارتقا،
    ری‌لود، OOM، کرش — انباشتِ جدولِ کشفِ دامنه را پاک می‌کرد و اپراتور
    هیچ سیگنالی جز «کوچک بودنِ عددها» نداشت.
    """

    FULL = {
        "started": 1000, "counting_since": 500,
        "ai_conns": 11, "direct_conns": 22, "ai_bytes": 333,
        "direct_bytes": 444, "no_sni": 5, "parse_bad": 6, "errors": 7,
        "loop_blocked": 8, "nosni_bytes": 99, "ech_conns": 1,
        "ech_bytes": 2, "quic_ai_conns": 3, "quic_direct_conns": 4,
        "quic_ai_bytes": 5, "quic_direct_bytes": 6, "quic_no_sni": 7,
        "quic_bad": 8, "quic_nosni_bytes": 9, "quic_replies": 10,
        "quic_rsfail": 11, "quic_rerr": 12,
        # سنجه‌های لحظه‌ای — نباید برگردند
        "active": 9999, "quic_flows": 777, "quic_enabled": True,
        # کلیدِ نسخه‌ی قدیمی‌تر که دیگر وجود ندارد — merge ِ کور برش می‌داشت
        "legacy_gone": 4242,
    }

    def setUp(self):
        self._orig = wss.STATS_FILE
        fd, self.path = tempfile.mkstemp(suffix=".stats")
        os.close(fd)
        wss.STATS_FILE = self.path

    def tearDown(self):
        wss.STATS_FILE = self._orig
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def write(self, payload, raw=None):
        mode = "wb" if raw is not None else "w"
        with open(self.path, mode) as f:
            f.write(raw if raw is not None else json.dumps(payload))

    # ---- هسته‌ی رفع ----
    def test_counters_survive_a_restart(self):
        self.write(self.FULL)
        sp = wss.Splitter(None)
        self.assertEqual(sp.stats["ai_bytes"], 333)
        self.assertEqual(sp.stats["quic_replies"], 10)
        self.assertEqual(sp.stats["errors"], 7)
        self.assertTrue(sp.stats["resumed"])

    def test_live_gauges_are_not_restored(self):
        """active و quic_flows نباید بازگردانده شوند.

        وضعِ لحظه‌ای‌اند: مقدارِ کهنه محاسبه‌ی فضای fd در _beat را مسموم
        می‌کند و همان flapِ حادثه‌ی ۲۰۲۶-۰۷-۲۱ را — این‌بار وارونه، یعنی
        ضربانِ همیشه-قطع روی پروسه‌ی بی‌کار — برمی‌گرداند.
        """
        self.write(self.FULL)
        base, _sni, _src = wss._load_stats()
        self.assertNotIn("active", base)
        self.assertNotIn("quic_flows", base)
        sp = wss.Splitter(None)
        self.assertEqual(sp.stats["active"], 0)
        self.assertEqual(sp.stats["quic_flows"], 0)
        self.assertFalse(sp.stats["quic_enabled"])

    def test_keys_outside_the_allow_list_are_dropped(self):
        """merge ِ کور کلیدِ نسخه‌ی قدیمی را هم برمی‌گرداند — نباید."""
        self.write(self.FULL)
        sp = wss.Splitter(None)
        self.assertNotIn("legacy_gone", sp.stats)

    def test_counting_since_survives_but_started_does_not(self):
        self.write(self.FULL)
        sp = wss.Splitter(None)
        self.assertEqual(sp.stats["counting_since"], 500)
        self.assertGreater(sp.stats["started"], 1000)

    def test_counting_since_falls_back_to_started_on_first_run(self):
        """اولین اجرا بعد از این تغییر: فایل counting_since ندارد."""
        payload = dict(self.FULL)
        del payload["counting_since"]
        self.write(payload)
        sp = wss.Splitter(None)
        self.assertEqual(sp.stats["counting_since"], sp.stats["started"])

    def test_a_corrupt_stats_file_does_not_stop_the_splitter(self):
        """فایلِ خراب ⇒ صفر، نه استثنا. این پروسه روی مسیرِ داده است."""
        for junk in (b"", b"{", b"null", b"[]", b'"x"', b"\xff\xfe\x00",
                     b'{"ai_bytes": "x"}', b'{"top_sni": "notalist"}',
                     b'{"top_sni": [["a"], 5, null]}',
                     b'{"top_src": [[1, 2, 3, 4, 5]]}'):
            with self.subTest(junk=junk):
                self.write(None, raw=junk)
                sp = wss.Splitter(None)          # نباید استثنا بدهد
                self.assertEqual(sp.stats["ai_bytes"], 0)

    def test_a_missing_stats_file_is_a_cold_start(self):
        os.unlink(self.path)
        sp = wss.Splitter(None)
        self.assertFalse(sp.stats["resumed"])
        self.assertEqual(sp.stats["counting_since"], sp.stats["started"])

    def test_a_boolean_is_not_counted_as_one(self):
        """bool زیرمجموعه‌ی int است — True نباید به شمارنده‌ی ۱ ترجمه شود."""
        self.write({"ai_conns": True, "direct_conns": 5})
        base, _s, _r = wss._load_stats()
        self.assertNotIn("ai_conns", base)
        self.assertEqual(base["direct_conns"], 5)

    # ---- جدول‌های کشفِ دامنه ----
    def test_sni_and_src_tables_use_the_real_snapshot_keys(self):
        """کلیدهای واقعیِ snapshot، نه حدس: top_sni/top_sni_conns/top_src."""
        self.write({
            "top_sni": [["a.google.com", 900, 3, 0]],
            "top_sni_conns": [["blocked.google.com", 400, 800, 0],
                              ["a.google.com", 900, 3, 0]],
            "top_src": [["192.168.1.9", 100, 200, 3, 4]],
        })
        sp = wss.Splitter(None)
        self.assertEqual(sorted(sp.sni_stats), ["a.google.com",
                                                "blocked.google.com"])
        self.assertEqual(sp.sni_stats["a.google.com"][:3], [900, 3, 0])
        self.assertEqual(sp.src_stats["192.168.1.9"][:4], [100, 200, 3, 4])
        # همان ردیف در دو فهرست ⇒ یک ردیف، نه دو
        self.assertEqual(len(sp.sni_stats), 2)

    def test_restored_rows_keep_accumulating(self):
        """ردیفِ بازگردانده‌شده باید مبنای sni_note باشد، نه دور ریخته شود."""
        self.write({"top_sni": [["a.google.com", 900, 3, 0]]})
        sp = wss.Splitter(None)
        wss.sni_note(sp.sni_stats, "a.google.com", 100, 1, False)
        self.assertEqual(sp.sni_stats["a.google.com"][0], 1000)
        self.assertEqual(sp.sni_stats["a.google.com"][1], 4)

    def test_restored_rows_expire_like_live_ones(self):
        """snapshot ستونِ زمان ندارد؛ بی‌مهرِ زمانی ردیف ابدی می‌شد.

        مهر از mtimeِ فایل می‌آید، پس جدولِ یک‌هفته‌ای در همان compaction
        اولِ اجرای تازه می‌افتد.
        """
        self.write({"top_sni": [["old.google.com", 5, 1, 0]],
                    "top_src": [["192.168.1.9", 1, 2, 3, 4]]})
        week = time.time() - 7 * 86400
        os.utime(self.path, (week, week))
        sp = wss.Splitter(None)
        self.assertIn("old.google.com", sp.sni_stats)     # بار شد
        wss.sni_compact(sp.sni_stats)
        wss.src_compact(sp.src_stats)
        self.assertEqual(sp.sni_stats, {})                # و کهنه افتاد
        self.assertEqual(sp.src_stats, {})

    def test_a_future_mtime_cannot_make_rows_immortal(self):
        """انحرافِ ساعت به جلو نباید ردیف را از انقضا معاف کند."""
        self.write({"top_sni": [["x.google.com", 5, 1, 0]]})
        ahead = time.time() + 10 * 86400
        os.utime(self.path, (ahead, ahead))
        sp = wss.Splitter(None)
        self.assertLessEqual(sp.sni_stats["x.google.com"][3],
                             int(time.time()) + 1)

    # ---- گاردِ خانوادگی ----
    def test_every_stat_key_is_classified(self):
        """هر کلیدِ stats باید یا تجمعی باشد یا لحظه‌ای — بی‌طبقه نه.

        گاردِ خودِ خانواده‌ی باگ، نه یک نمونه: شمارنده‌ی تجمعیِ تازه‌ای که
        به _RESUMABLE اضافه نشود بی‌صدا با هر ری‌استارت صفر می‌ماند و هیچ
        تستِ رفتاری‌ای این را نمی‌بیند.
        """
        sp = wss.Splitter(None)
        classified = set(wss._RESUMABLE) | set(wss._LIVE_GAUGES)
        self.assertEqual(set(sp.stats) - classified, set(),
                         "کلیدِ بی‌طبقه: به _RESUMABLE یا _LIVE_GAUGES اضافه کن")
        self.assertEqual(classified - set(sp.stats), set(),
                         "نامِ مرده در فهرست‌ها — کلید از stats حذف شده است")
        self.assertEqual(set(wss._RESUMABLE) & set(wss._LIVE_GAUGES), set())


class _FakeSock:
    """سوکتِ ساختگی که مارک و بایت‌های فرستاده‌شده را ثبت می‌کند.

    روی مک `socket.SO_MARK` وجود ندارد (کد به ۳۶ برمی‌گردد) و
    `setsockopt` واقعی خطا می‌دهد، پس مسیرِ بازساختِ سوکت با سوکتِ واقعی
    اصلاً آزمودنی نیست. اینجا فقط چیزی که اهمیت دارد ثبت می‌شود: مارک،
    ترتیبِ ارسال، و اینکه بسته شد یا نه (نشتِ fd).
    """
    _next_fd = 900
    live = []

    def __init__(self, *_a, **_k):
        _FakeSock._next_fd += 1
        self._fd = _FakeSock._next_fd
        self.mark = None
        self.sent = []
        self.closed = False
        self.connected = None
        _FakeSock.live.append(self)

    def setsockopt(self, _lvl, _opt, val):
        self.mark = val

    def setblocking(self, _b):
        pass

    def connect(self, addr):
        self.connected = addr

    def send(self, data):
        if self.closed:
            raise OSError("send on closed socket")
        self.sent.append(data)
        return len(data)

    def fileno(self):
        return self._fd

    def close(self):
        self.closed = True


class _FakeSel:
    def __init__(self):
        self.registered = {}

    def register(self, sock, _ev, data):
        self.registered[sock.fileno()] = data

    def unregister(self, sock):
        self.registered.pop(sock.fileno(), None)


class QuicHoldTests(unittest.TestCase):
    """نگه‌داشتنِ دیتاگرام تا روشن‌شدنِ نام (پلنِ ۰۶۶).

    چرا این تست‌ها سنگین‌ترند از بقیه: این تنها تغییرِ این مجموعه است که
    **پیش از تصمیم چیزی نمی‌فرستد**. اگر مسیرِ تخلیه هر جا نشت کند، دادهٔ
    کاربر بی‌صدا دور ریخته می‌شود — نه خطایی، نه لاگی. پس هر مسیرِ خروج
    (حل، تسلیم، مهلت، مرگِ جریان، شکستِ بازساخت) جدا آزموده می‌شود.
    """

    HOST_AI = "gemini.google.com"
    HOST_OTHER = "example.invalid"
    SPLIT = 900

    def setUp(self):
        _FakeSock.live = []
        self._real_socket = wss.socket.socket
        wss.socket.socket = _FakeSock
        self.addCleanup(setattr, wss.socket, "socket", self._real_socket)
        self.qs = wss.QuicSplitter.__new__(wss.QuicSplitter)
        self.qs.stats = wss.Splitter(None).stats
        self.qs.sni_stats = {}
        self.qs.src_stats = {}
        self.qs.flows = {}
        self.qs.up_index = {}
        self.qs.reply_socks = {}
        self.qs.sel = _FakeSel()
        self.qs.get_suffixes = lambda: [self.HOST_AI]
        self.qs.get_geo_suffixes = lambda: []

    def _flow(self, is_ai=True, mark=None):
        up = _FakeSock()
        up.mark = wss.MARK_AI if mark is None else mark
        fl = wss._QuicFlow(up, ("1.2.3.4", 443), ("192.168.1.9", 5000))
        fl.is_ai = is_ai
        fl.mark = up.mark
        self.qs.flows[(fl.client, fl.orig_dst)] = fl
        self.qs.up_index[up.fileno()] = fl
        self.qs.sel.register(up, None, ("up", fl))
        return fl

    def _pkts(self, host):
        hello = big_hello(host)
        self.assertGreater(len(hello), 1200, "فیکسچر باید چندپکتی باشد")
        return (build_initial(b"\x11" * 8, 0, crypto_frame(0, hello[:self.SPLIT])),
                build_initial(b"\x11" * 8, 1,
                              crypto_frame(self.SPLIT, hello[self.SPLIT:])))

    # ---- هسته ----

    def test_the_first_datagram_is_not_forwarded_before_the_name_resolves(self):
        p1, _p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.assertIsNotNone(fl.held, "صف باید باز شده باشد")
        self.assertTrue(self.qs._hold_datagram(fl, p1))
        self.assertEqual(fl.up.sent, [], "هیچ بایتی نباید رفته باشد")

    def test_resolving_to_a_non_ai_name_swaps_the_mark_and_flushes_in_order(self):
        p1, p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        old = fl.up
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.qs._continue_hello(fl, p2)
        self.assertEqual(fl.sni, self.HOST_OTHER)
        self.assertEqual(
            (fl.is_ai, fl.mark, fl.up.mark, fl.up.sent, old.closed, fl.held),
            (False, wss.MARK_DIRECT, wss.MARK_DIRECT, [p1], True, None),
            "(is_ai، مارکِ جریان، مارکِ سوکت، فرستاده‌ها، سوکتِ قدیم بسته، صف)")
        self.assertEqual(self.qs.stats["quic_hold_swap"], 1)
        self.assertEqual(self.qs.stats["quic_hello_misrouted"], 1)

    def test_resolving_to_an_ai_name_keeps_the_socket(self):
        p1, p2 = self._pkts(self.HOST_AI)
        fl = self._flow()
        old = fl.up
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.qs._continue_hello(fl, p2)
        self.assertEqual((fl.is_ai, fl.up is old, old.closed, fl.up.sent),
                         (True, True, False, [p1]))
        self.assertEqual(self.qs.stats["quic_hold_swap"], 0)
        self.assertEqual(self.qs.stats["quic_hello_misrouted"], 0)

    def test_a_geo_domain_does_not_fall_through_to_direct(self):
        """رفعِ یک بدمسیری نباید بدمسیریِ تازه بسازد."""
        self.qs.get_geo_suffixes = lambda: [self.HOST_OTHER]
        p1, p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.qs._continue_hello(fl, p2)
        self.assertEqual(fl.up.mark, wss.MARK_GEO)

    # ---- مسیرهای خروجِ دیگر ----

    def test_giving_up_flushes_the_queue_to_geo(self):
        """تسلیم: صف تخلیه می‌شود و مقصد **geo** است، نه استخرِ AI.

        تا ۲۰ سپتامبر ۲۰۲۶ اینجا MARK_AI انتظار می‌رفت («رفتارِ پیش از
        ۰۶۶»). آن قرارداد عوض شد چون مقصدِ ابهام خودش باگ بود: چهار
        خروجی از شش خروجیِ استخر یوتیوب‌موزیک را رد می‌کردند در حالی که
        برای AI سالم بودند، پس جریانِ بی‌نام روی استخر نشستن یعنی ۶۷٪
        کاربران «در حال اتصال». آنچه اینجا **نباید** عوض شده باشد و
        همچنان سنجیده می‌شود: صف واقعاً تخلیه شود و نگه‌داری بسته شود.
        """
        p1, _p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.qs._giveup_hello(fl)
        self.assertEqual((fl.up.sent, fl.held), ([p1], None),
                         "صف باید تخلیه و نگه‌داری بسته شود")
        self.assertEqual(fl.up.mark, wss.MARK_GEO)
        self.assertTrue(fl.blind)

    def test_giving_up_honours_the_kill_switch(self):
        """با WSS_QUIC_BLIND_GEO=0 همان fail-openِ تاریخی برمی‌گردد."""
        self.addCleanup(setattr, wss, "QUIC_BLIND_GEO", wss.QUIC_BLIND_GEO)
        wss.QUIC_BLIND_GEO = False
        p1, _p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.qs._giveup_hello(fl)
        self.assertEqual((fl.up.sent, fl.up.mark, fl.held),
                         ([p1], wss.MARK_AI, None))

    def test_a_flow_held_past_the_deadline_is_flushed(self):
        p1, _p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        fl.held_since -= (wss.QUIC_HOLD_MS / 1000.0) + 1
        self.qs._flush_expired_holds(time.monotonic())
        self.assertEqual((fl.up.sent, fl.held, self.qs.stats["quic_hold_timeout"]),
                         ([p1], None, 1))

    def test_closing_a_flow_drops_held_data_without_charging_bytes(self):
        p1, _p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        before = self.qs.stats["quic_ai_bytes"]
        self.qs._close_flow(fl)
        self.assertEqual(
            (self.qs.stats["quic_ai_bytes"], self.qs.stats["quic_hold_dropped"]),
            (before, 1),
            "بایتی که نرفته نباید حساب شود — نسبتِ پلنِ ۰۶۶ به آن تکیه دارد")

    def test_a_failed_socket_swap_leaves_nothing_registered(self):
        """نشتِ ثبتِ selector یعنی نشتِ fd — همان چیزی که _beat برایش هست."""
        p1, p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        old_fd = fl.up.fileno()

        def boom(*_a, **_k):
            raise OSError("no fd")
        wss.socket.socket = boom
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.qs._continue_hello(fl, p2)
        self.assertNotIn(old_fd, self.qs.up_index)
        self.assertNotIn(old_fd, self.qs.sel.registered)
        self.assertNotIn((fl.client, fl.orig_dst), self.qs.flows)
        self.assertEqual(self.qs.stats["errors"], 1)

    # ---- کران‌ها و حسابداری ----

    def test_the_queue_is_bounded_by_packet_count(self):
        """دقیقاً QUIC_HELLO_PKTS تا جا می‌گیرد؛ بعدی تخلیه‌ی fail-open است."""
        p1, _p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        for i in range(wss.QUIC_HELLO_PKTS):
            self.assertTrue(self.qs._hold_datagram(fl, b"x" * 10),
                            "دیتاگرامِ %d باید هنوز جا بگیرد" % i)
        self.assertEqual(len(fl.held), wss.QUIC_HELLO_PKTS)
        # یکی بیشتر ⇒ کران رد می‌شود ⇒ صف تخلیه و این دیتاگرام عادی می‌رود
        self.assertFalse(self.qs._hold_datagram(fl, b"x" * 10))
        self.assertIsNone(fl.held, "ردِ کران باید صف را تخلیه کرده باشد")
        self.assertEqual(len(fl.up.sent), wss.QUIC_HELLO_PKTS)

    def test_the_queue_is_bounded_by_bytes(self):
        p1, _p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.assertFalse(self.qs._hold_datagram(fl, b"x" * (wss.QUIC_HELLO_MAX + 1)))
        self.assertIsNone(fl.held)

    def test_bytes_are_charged_once_and_against_the_final_mark(self):
        p1, p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.qs._continue_hello(fl, p2)
        self.assertEqual(
            (self.qs.stats["quic_ai_bytes"], self.qs.stats["quic_direct_bytes"]),
            (0, len(p1)),
            "بایتِ نگه‌داشته باید یک‌بار و به ستونِ مقصدِ نهایی بخورد")

    def test_the_connection_is_counted_exactly_once(self):
        p1, p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.qs._continue_hello(fl, p2)
        self.qs._close_flow(fl)          # نباید دوباره بشمارد
        self.assertEqual((self.qs.stats["quic_ai_conns"],
                          self.qs.stats["quic_direct_conns"]), (0, 1))

    def test_a_flow_that_dies_while_still_holding_is_still_counted_once(self):
        """جریانی که هرگز حل نشد نباید از شمارشِ اتصال بیفتد.

        جهشِ هدفمند نشان داد `_count_conn` در `_close_flow` را می‌شود
        برداشت بی‌آنکه تستی قرمز شود — چون آن مسیر همیشه از
        `_giveup_hello` رد می‌شد. این تست همان شکاف را می‌بندد و ثابت
        می‌کند شمارش از هر دو در می‌آید، نه دو بار.
        """
        p1, _p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.assertFalse(fl.counted, "هنوز نباید شمرده شده باشد")
        self.qs._close_flow(fl)
        self.assertTrue(fl.counted)
        self.assertEqual((self.qs.stats["quic_ai_conns"],
                          self.qs.stats["quic_direct_conns"]), (1, 0),
                         "fail-open ⇒ به ستونِ AI، و دقیقاً یک بار")

    def test_the_hold_cost_is_measured_not_argued(self):
        p1, p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        self.qs._continue_hello(fl, p2)
        self.assertGreater(self.qs.stats["quic_hold_us_total"], 0)

    # ---- کلید خاموشی ----

    def test_the_kill_switch_reproduces_the_previous_path(self):
        """WSS_QUIC_HOLD=0 ⇒ هیچ صفی باز نمی‌شود و هیچ سوکتی عوض نمی‌شود."""
        p1, p2 = self._pkts(self.HOST_OTHER)
        orig = wss.QUIC_HOLD
        wss.QUIC_HOLD = False
        self.addCleanup(setattr, wss, "QUIC_HOLD", orig)
        fl = self._flow()
        old = fl.up
        self.qs._begin_hello(fl, p1)
        self.assertIsNone(fl.held, "با کلیدِ خاموش نباید صفی باز شود")
        self.qs._continue_hello(fl, p2)
        self.assertEqual((fl.is_ai, fl.up is old, self.qs.stats["quic_hold_swap"]),
                         (True, True, 0),
                         "با کلیدِ خاموش، مسیر باید دقیقاً پیش از ۰۶۶ بماند")
        self.assertEqual(self.qs.stats["quic_hello_misrouted"], 1,
                         "ولی شمارشِ تشخیص باید سرِ جایش بماند")

    def test_the_select_deadline_is_milliseconds_not_the_ten_second_sweep(self):
        """گامِ ۵ ِ پلن اشتباه بود: _sweep هر ۱۰ ثانیه می‌دود.

        بدونِ مهلتِ پویا، «۲۵۰ میلی‌ثانیه» عملاً تا ۱۰ ثانیه می‌شد.
        """
        p1, _p2 = self._pkts(self.HOST_OTHER)
        fl = self._flow()
        self.qs._begin_hello(fl, p1)
        self.qs._hold_datagram(fl, p1)
        d = self.qs._hold_deadline(time.monotonic())
        self.assertIsNotNone(d)
        self.assertLessEqual(d, wss.QUIC_HOLD_MS / 1000.0)

    def test_no_deadline_when_nothing_is_held(self):
        self._flow()
        self.assertIsNone(self.qs._hold_deadline(time.monotonic()))


if __name__ == "__main__":
    unittest.main()


class AiMarkPoolTests(unittest.TestCase):
    """گاردِ خانوادگیِ پخشِ بارِ per-user روی چند خروجی (۱۵ اوت ۲۰۲۶).

    خانواده‌ی باگی که این‌ها می‌گیرند: «هشِ انتخابِ خروجی به چیزی جز
    آدرسِ کاربر وابسته شود». هر شکلی از آن — هشِ per-flow، هشِ رندمِ
    per-process، یا از دست رفتنِ چسبندگی هنگامِ تصحیحِ تصمیم — یعنی
    اتصال‌های یک کاربر از IPهای مختلف بیرون می‌روند و گوگل آن را
    جابه‌جاییِ هویت وسطِ نشست می‌بیند؛ همان چیزی که wg22 را به صفحه‌ی
    abuse رساند.
    """

    def setUp(self):
        self._saved = wss.MARK_AI_POOL

    def tearDown(self):
        wss.MARK_AI_POOL = self._saved

    def test_empty_pool_keeps_legacy_single_mark(self):
        """استخرِ خالی ⇒ دقیقاً رفتارِ پیشین. راهِ برگشت باید همیشه باز باشد."""
        wss.MARK_AI_POOL = []
        for ip in ("192.168.69.1", "192.168.188.37", "10.0.0.1", ""):
            self.assertEqual(wss.ai_mark_for(ip), wss.MARK_AI)

    def test_same_client_always_same_mark(self):
        """چسبندگی: یک کاربر همیشه یک خروجی — قلبِ کلِ طراحی."""
        wss.MARK_AI_POOL = [0x81, 0x82, 0x83, 0x84, 0x85, 0x86]
        for ip in ("192.168.69.7", "192.168.188.37", "192.168.70.201"):
            marks = {wss.ai_mark_for(ip) for _ in range(50)}
            self.assertEqual(len(marks), 1, "مارکِ %s پایدار نماند" % ip)

    def test_mark_is_deterministic_across_processes(self):
        """crc32 و نه hash(): مقدار باید بینِ اجراها ثابت بماند.

        اگر کسی به hash() برگردد این تست سبز می‌ماند ولی رفتار در
        ری‌استارت عوض می‌شود، پس مقدارِ crc32 صریحاً سنجیده می‌شود.
        """
        wss.MARK_AI_POOL = [0x81, 0x82, 0x83]
        expect = 0x81 + (zlib.crc32(b"192.168.69.7") % 3)
        self.assertEqual(wss.ai_mark_for("192.168.69.7"), expect)

    def test_pool_actually_spreads_users(self):
        """پخش: ۲۵۴ کاربر نباید همه روی یک خروجی بیفتند."""
        wss.MARK_AI_POOL = [0x81, 0x82, 0x83, 0x84, 0x85, 0x86]
        seen = {}
        for i in range(1, 255):
            m = wss.ai_mark_for("192.168.69.%d" % i)
            seen[m] = seen.get(m, 0) + 1
        self.assertEqual(len(seen), 6, "همه‌ی شش خروجی باید کاربر بگیرند")
        # هیچ خروجی نباید بیش از دو برابرِ سهمِ منصفانه بگیرد
        self.assertLess(max(seen.values()), (254 // 6) * 2)

    def test_broken_env_falls_back_to_single_mark(self):
        """ورودیِ خرابِ env ⇒ فهرستِ خالی ⇒ رفتارِ سالمِ تک‌مارک.

        fail-safe عمدی: env بد نباید ترافیک را بی‌مارک رها کند.
        """
        for bad in ("zz", "0x81,zz", "0x81,,0x82,nope", "-1", "0"):
            self.assertEqual(wss._parse_mark_pool(bad), [],
                             "ورودیِ %r باید رد شود" % bad)
        self.assertEqual(wss._parse_mark_pool("0x81, 0x82"), [0x81, 0x82])

    def test_ai_by_mark_aggregates_per_tunnel(self):
        """تجمیعِ آمار به تفکیکِ خروجی — پایه‌ی تشخیصِ انحراف."""
        wss.MARK_AI_POOL = [0x81, 0x82]
        store = {}
        for i in range(1, 41):
            # [ai_bytes, direct_bytes, ai_conns, direct_conns, last_seen]
            store["192.168.69.%d" % i] = [1000, 0, 10, 0, int(time.time())]
        rows = wss.ai_by_mark(store)
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(r[1] for r in rows), 40 * 1000)
        self.assertEqual(sum(r[2] for r in rows), 40 * 10)
        self.assertEqual(sum(r[3] for r in rows), 40)

    def test_ai_by_mark_exposes_a_degraded_tunnel(self):
        """سناریوی واقعی: یک خروجی سوخته ⇒ بایت‌به‌اتصالش باید پرت باشد.

        این همان چیزی است که هیچ سنجه‌ی مطلقی نمی‌دید — کدِ HTTP و
        اندازه‌ی صفحه از IPِ سالم و بلاک‌شده یکسان بود.
        """
        wss.MARK_AI_POOL = [0x81, 0x82]
        store = {}
        for i in range(1, 41):
            ip = "192.168.69.%d" % i
            sick = wss.ai_mark_for(ip) == 0x81
            # خروجیِ سوخته: همان تعداد اتصال، ولی بایتِ ناچیز
            store[ip] = [200 if sick else 5000, 0, 10, 0, int(time.time())]
        per_conn = {r[0]: r[1] / max(1, r[2]) for r in wss.ai_by_mark(store)}
        self.assertLess(per_conn["0x81"] * 5, per_conn["0x82"])


class BlindQuicGoesToGeoTests(unittest.TestCase):
    """گاردِ خانوادگی — «جریانی که نامش قطعی نشد کجا می‌رود؟» (۲۰ سپتامبر ۲۰۲۶).

    خانواده‌ی باگ: fail-openِ ابهام به **استخرِ AI**. استخر برای کارِ
    خودش سالم بود ولی چهار خروجی از شش‌تایش یوتیوب‌موزیک را رد می‌کرد
    (۲۰۰ ِ ۱٬۶۶۶ بایتی با MUSIC_UNAVAILABLE)، و نگاشتِ قطعیِ crc32 یعنی
    ۶۷٪ کاربران همیشه روی همان‌ها می‌نشستند.

    این تست‌ها **مقصدِ ابهام** را قفل می‌کنند، نه یک نمونه را: هر مسیری
    که به جریانِ بی‌نام ختم شود باید geo بدهد، و هیچ جریانِ نام‌داری
    نباید رفتارش عوض شده باشد.
    """

    HOST_AI = "gemini.google.com"
    HOST_GEO = "youtube.com"

    def setUp(self):
        self.qs = wss.QuicSplitter.__new__(wss.QuicSplitter)
        self.qs.stats = wss.Splitter(None).stats
        self.qs.sni_stats = {}
        self.qs.src_stats = {}
        self.qs.get_suffixes = lambda: [self.HOST_AI]
        self.qs.get_geo_suffixes = lambda: [self.HOST_GEO]
        self._pool = wss.MARK_AI_POOL
        self._flag = wss.QUIC_BLIND_GEO
        wss.MARK_AI_POOL = [0x81, 0x82, 0x83, 0x84, 0x85, 0x86]
        wss.QUIC_BLIND_GEO = True
        self.addCleanup(setattr, wss, "MARK_AI_POOL", self._pool)
        self.addCleanup(setattr, wss, "QUIC_BLIND_GEO", self._flag)

    def _flow(self, is_ai=True, sni=None, blind=False,
              client="192.168.69.7"):
        fl = wss._QuicFlow(None, ("1.2.3.4", 443), (client, 5000))
        fl.is_ai = is_ai
        fl.sni = sni
        fl.blind = blind
        return fl

    # ---- هسته‌ی رفع ----
    def test_blind_flow_goes_to_geo_not_the_pool(self):
        fl = self._flow(is_ai=True, sni=None, blind=True)
        self.assertEqual(self.qs._mark_for(fl), wss.MARK_GEO)

    def test_no_blind_flow_lands_on_any_pool_mark(self):
        """قفلِ اصلیِ خانواده: هیچ کاربری، با هیچ آدرسی، نباید بی‌نام روی
        استخر بنشیند — نه فقط آن آدرسی که در گزارش آمده بود."""
        pool = set(wss.MARK_AI_POOL)
        for i in range(1, 120):
            fl = self._flow(is_ai=True, sni=None, blind=True,
                            client="192.168.69.%d" % i)
            m = self.qs._mark_for(fl)
            self.assertNotIn(m, pool,
                             "کاربرِ %d بی‌نام روی استخر نشست" % i)
            self.assertEqual(m, wss.MARK_GEO)

    # ---- رگرسیون: جریان‌های نام‌دار دست‌نخورده ----
    def test_named_ai_flow_still_uses_its_sticky_pool_mark(self):
        fl = self._flow(is_ai=True, sni=self.HOST_AI, blind=False)
        self.assertEqual(self.qs._mark_for(fl),
                         wss.ai_mark_for("192.168.69.7"))

    def test_named_ai_flows_still_spread_across_the_pool(self):
        """چسبندگیِ per-user نباید قربانیِ این رفع شده باشد."""
        marks = {self.qs._mark_for(
            self._flow(is_ai=True, sni=self.HOST_AI,
                       client="192.168.69.%d" % i)) for i in range(1, 60)}
        self.assertGreater(len(marks), 1)
        self.assertTrue(marks <= set(wss.MARK_AI_POOL))

    def test_named_geo_flow_unchanged(self):
        fl = self._flow(is_ai=False, sni="music." + self.HOST_GEO)
        self.assertEqual(self.qs._mark_for(fl), wss.MARK_GEO)

    def test_named_ordinary_flow_still_direct(self):
        fl = self._flow(is_ai=False, sni="example.com")
        self.assertEqual(self.qs._mark_for(fl), wss.MARK_DIRECT)

    # ---- دو مسیری که به «بی‌نام» ختم می‌شوند ----
    def test_giveup_marks_the_flow_blind(self):
        """نگه‌داری شکست خورد ⇒ blind ⇒ مقصدش geo."""
        fl = self._flow(is_ai=True, sni=None, blind=False)
        fl.held = []
        self.qs._blind_hello(fl, "quic_no_sni")
        self.assertTrue(fl.blind)
        self.assertEqual(self.qs._mark_for(fl), wss.MARK_GEO)

    def test_a_name_that_arrives_late_clears_blind(self):
        """نامِ دیررس نباید جریان را برای همیشه در geo حبس کند."""
        fl = self._flow(is_ai=True, sni=None, blind=True)
        fl.sni = self.HOST_AI
        fl.blind = False                      # همان کاری که _promote می‌کند
        self.assertEqual(self.qs._mark_for(fl),
                         wss.ai_mark_for("192.168.69.7"))

    # ---- کلیدِ خاموشی ----
    def test_kill_switch_restores_the_old_fail_open(self):
        wss.QUIC_BLIND_GEO = False
        fl = self._flow(is_ai=True, sni=None, blind=True)
        self.assertEqual(self.qs._mark_for(fl),
                         wss.ai_mark_for("192.168.69.7"))

    # ---- خودِ قرارداد ----
    def test_geo_and_pool_marks_are_distinct(self):
        """اگر MARK_GEO با یکی از مارک‌های استخر یکی شود، همه‌ی تست‌های
        بالا بی‌صدا بی‌معنا می‌شوند."""
        self.assertNotIn(wss.MARK_GEO, set(wss.MARK_AI_POOL))
        self.assertNotEqual(wss.MARK_GEO, wss.MARK_DIRECT)
