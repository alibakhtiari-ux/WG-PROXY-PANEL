# -*- coding: utf-8 -*-
"""تست‌های حالتِ دمو (demo/).

دمو باید دو قول را نگه دارد: هیچ برنامه‌ی واقعیِ سیستم را اجرا نکند و
هیچ چیزی بیرون از پوشه‌ی خودش ننویسد. هر دو این‌جا با خودِ سورسِ پنل
سنجیده می‌شوند، پس افزودنِ یک ابزارِ تازه به پنل بدونِ نسخه‌ی ساختگی‌اش
این تست را می‌شکند.
"""
import ast
import os
import shutil
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "demo"))
import fake_tools  # noqa: E402
import run as demo  # noqa: E402

# awg عمداً ساختگی ندارد: نبودنش یعنی «AmneziaWG نصب نیست» و پنل همان مسیر
# را می‌رود.
NOT_FAKED = {"awg"}


def _programs_the_panel_runs():
    """نامِ برنامه‌هایی که wg_panel.py اجرا یا جست‌وجو می‌کند."""
    with open(os.path.join(ROOT, "wg_panel.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(
            fn, "id", None)
        if not node.args:
            continue
        arg = node.args[0]
        if name == "which" and isinstance(arg, ast.Constant):
            found.add(arg.value)
        elif name in ("run", "_tc", "Popen", "check_output") and \
                isinstance(arg, (ast.List, ast.Tuple)) and arg.elts and \
                isinstance(arg.elts[0], ast.Constant) and \
                isinstance(arg.elts[0].value, str):
            found.add(arg.elts[0].value)
    return found


class DemoToolsTests(unittest.TestCase):

    def test_every_program_the_panel_runs_has_a_fake(self):
        progs = _programs_the_panel_runs()
        self.assertIn("wg", progs, "الگوی جست‌وجو دیگر با سورس نمی‌خواند")
        missing = sorted(progs - set(demo.TOOLS) - NOT_FAKED)
        self.assertEqual(missing, [],
                         "دمو این‌ها را از سیستمِ واقعی اجرا می‌کرد: %s"
                         % missing)

    def test_live_counters_only_grow(self):
        p = {"rate": 5e5, "base": 10 ** 9, "up": 0.2, "t0": 1000.0}
        prev = (0, 0)
        for t in range(1000, 5000, 7):
            rx, tx, _ = fake_tools._counter("peer", p, float(t))
            self.assertGreaterEqual(rx, prev[0])
            self.assertGreaterEqual(tx, prev[1])
            prev = (rx, tx)

    def test_unknown_tools_fail_quietly(self):
        for tool in ("curl", "iptables", "rclone", "speedtest"):
            with self.subTest(tool=tool):
                self.assertEqual(fake_tools.main(["x", tool, "-v"]), 1)


class DemoSandboxTests(unittest.TestCase):

    def test_paths_already_inside_a_var_state_dir_are_not_remapped(self):
        # macOS: پوشه‌ی موقت زیرِ ‎/var/folders است؛ CONFIG_PATH ِ کپی که از
        # قبل داخلِ پوشه‌ی دموست نباید دوباره زیرِ root برود.
        import types
        state = "/var/folders/xx/T/wg-panel-demo"
        m = types.SimpleNamespace(
            CONFIG_PATH=state + "/panel/config.json",
            SQUID_PASSWD="/etc/squid/passwd",
            SOME_VAR="/var/lib/wg-panel/x")
        demo.sandbox(m, state)
        self.assertEqual(m.CONFIG_PATH, state + "/panel/config.json")
        self.assertEqual(m.SQUID_PASSWD, state + "/root/etc/squid/passwd")
        self.assertEqual(m.SOME_VAR, state + "/root/var/lib/wg-panel/x")


class DemoSeedTests(unittest.TestCase):
    """دمو را واقعاً می‌سازد (بدونِ بالا آوردنِ سرور)."""

    @classmethod
    def setUpClass(cls):
        cls.saved_env = dict(os.environ)
        cls.saved_mod = sys.modules.get("wg_panel")
        cls.tmp = tempfile.mkdtemp(prefix="wgpanel-demo-test-")
        # cleanup حتی اگر prepare شکست بخورد اجرا می‌شود (tearDownClass نه)؛
        # وگرنه PATH ِ ابزارهای ساختگی به تست‌های بعدی نشت می‌کند.
        cls.addClassCleanup(cls._restore)
        cls.state = os.path.join(cls.tmp, "demo")
        cls.m = demo.prepare(cls.state, reset=True)

    @classmethod
    def _restore(cls):
        os.environ.clear()
        os.environ.update(cls.saved_env)
        if cls.saved_mod is None:
            sys.modules.pop("wg_panel", None)
        else:
            sys.modules["wg_panel"] = cls.saved_mod
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_system_path_points_inside_the_demo_folder(self):
        root = os.path.realpath(self.state)
        for name, val in vars(self.m).items():
            if isinstance(val, str) and val.startswith("/") and \
                    ("/etc/" in val or "/var/" in val or "/opt/" in val):
                with self.subTest(name=name):
                    self.assertTrue(os.path.realpath(val).startswith(root),
                                    "%s = %s" % (name, val))
        self.assertTrue(os.path.realpath(self.m.DB_PATH).startswith(root))

    def test_seeded_clients_and_history(self):
        blocks = self.m.parse_user_blocks("wg0")
        self.assertEqual(len(blocks), len(demo.CLIENTS))
        self.assertEqual(sum(1 for b in blocks if not b["enabled"]), 1)
        con = self.m.META._connect()
        try:
            days = con.execute(
                "SELECT COUNT(DISTINCT day) FROM usage_day").fetchone()[0]
            audits = con.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        finally:
            con.close()
        self.assertGreater(days, 150)
        self.assertGreaterEqual(audits, 10)

    def test_the_newest_speed_test_is_recent(self):
        # زمان‌بندِ خودکار با «آخرین» تست تصمیم می‌گیرد؛ اگر کهنه باشد
        # دمو speedtest (ساختگی) را صدا می‌زند و ردیفِ شکست ثبت می‌کند.
        last = self.m.META.speedtest_recent(1)[0]["ts"]
        self.assertLess(time.time() - last, 3600)

    def test_fake_wg_reports_the_seeded_peers(self):
        rc, out, _ = self.m.run(["wg", "show", "all", "dump"])
        self.assertEqual(rc, 0)
        peers = [l for l in out.splitlines()
                 if l.startswith("wg0\t") and len(l.split("\t")) == 9]
        # یک کاربرِ غیرفعال در wg ِ زنده نیست
        self.assertEqual(len(peers), len(demo.CLIENTS) - 1)

    def test_only_documentation_addresses_are_used(self):
        import ipaddress
        doc = [ipaddress.ip_network(n) for n in
               ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
        rc, out, _ = self.m.run(["wg", "show", "all", "dump"])
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 9 and parts[3] != "(none)":
                ip = ipaddress.ip_address(parts[3].rsplit(":", 1)[0])
                with self.subTest(endpoint=parts[3]):
                    self.assertTrue(any(ip in n for n in doc))


if __name__ == "__main__":
    unittest.main()
