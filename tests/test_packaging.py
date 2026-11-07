# -*- coding: utf-8 -*-
"""تست‌های بسته‌بندیِ wg_panel.pyz (پلنِ ۰۶۸): بیلدِ قطعی، --check، لانچر، BASE_DIR.

هیچ‌چیز از wgpanel/app.py در خودِ مخزن import نمی‌شود (import ِ آن traffic.db
می‌سازد)؛ هرجا لازم بود روی کپی در پوشه‌ی موقت یا در subprocess اجرا می‌شود.
"""
import contextlib
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG = os.path.join(ROOT, "wgpanel")
LAUNCHER = os.path.join(ROOT, "wg_panel.py")
EPOCH = (1980, 1, 1, 0, 0, 0)


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_pyz", os.path.join(ROOT, "tools", "build_pyz.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


B = _load_builder()


def _run(args, **kw):
    kw.setdefault("timeout", 120)
    return subprocess.run(args, capture_output=True, text=True, **kw)


def _copy_pkg(dst):
    shutil.copytree(PKG, os.path.join(dst, "wgpanel"),
                    ignore=shutil.ignore_patterns("__pycache__"))


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-pkg-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _install(self):
        """لانچر + آرشیو کنارِ هم در پوشه‌ی موقت؛ مسیرِ pyz را برمی‌گرداند."""
        shutil.copy(LAUNCHER, self.tmp)
        pyz = os.path.join(self.tmp, "wg_panel.pyz")
        with contextlib.redirect_stdout(io.StringIO()):
            B.main(["--out", pyz, "--allow-untracked"])
        return pyz

    def test_build_is_deterministic(self):
        self.assertEqual(B.build_bytes(PKG), B.build_bytes(PKG))

    def test_id_matches_written_file(self):
        out = os.path.join(self.tmp, "x.pyz")
        with contextlib.redirect_stdout(io.StringIO()):
            B.main(["--out", out, "--allow-untracked"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            B.main(["--id", "--allow-untracked"])
        with open(out, "rb") as f:
            want = hashlib.sha256(f.read()).hexdigest()[:12]
        self.assertEqual(buf.getvalue().strip(), want)

    def test_members_are_exactly_the_package(self):
        with zipfile.ZipFile(io.BytesIO(B.build_bytes(PKG))) as z:
            infos = z.infolist()
        names = [i.filename for i in infos]
        self.assertIn("__main__.py", names)
        for n in names:
            self.assertTrue(n == "__main__.py" or n.startswith("wgpanel/"), n)
            self.assertNotIn("__pycache__", n)
            self.assertFalse(n.endswith(".pyc"), n)
        for i in infos:
            self.assertEqual(i.date_time, EPOCH, i.filename)

    def test_check_passes_on_a_fresh_build(self):
        pyz = os.path.join(self.tmp, "wg_panel.pyz")
        with contextlib.redirect_stdout(io.StringIO()):
            B.main(["--out", pyz, "--allow-untracked"])
        r = _run([sys.executable, pyz, "--check"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("CHECK_OK"), r.stdout)

    def test_check_fails_on_a_syntax_error(self):
        _copy_pkg(self.tmp)
        with open(os.path.join(self.tmp, "wgpanel", "app.py"), "a",
                  encoding="utf-8") as f:
            f.write("\ndef (:\n")
        pyz = os.path.join(self.tmp, "bad.pyz")
        r = _run([sys.executable, os.path.join(ROOT, "tools", "build_pyz.py"),
                  "--src", os.path.join(self.tmp, "wgpanel"), "--out", pyz,
                  "--allow-untracked"])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = _run([sys.executable, pyz, "--check"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not compile", r.stderr)

    def test_launcher_runs_the_archive(self):
        self._install()
        r = _run([sys.executable, os.path.join(self.tmp, "wg_panel.py"),
                  "--check"], cwd=self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("CHECK_OK"), r.stdout)

    def test_launcher_without_archive_fails_loudly(self):
        shutil.copy(LAUNCHER, self.tmp)
        r = _run([sys.executable, os.path.join(self.tmp, "wg_panel.py"),
                  "--check"], cwd=self.tmp)
        self.assertEqual(r.returncode, 2)
        self.assertIn("wg_panel.pyz", r.stderr)

    def test_base_dir_is_the_archive_directory(self):
        pyz = self._install()
        code = ("import sys; sys.path.insert(0, %r); import wgpanel.app as a; "
                "print(a.BASE_DIR); print(a.ARCHIVE); print(a.BUILD_ID)" % pyz)
        r = _run([sys.executable, "-c", code], cwd=self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertEqual(os.path.realpath(lines[0]), os.path.realpath(self.tmp))
        self.assertEqual(os.path.realpath(lines[1]), os.path.realpath(pyz))
        with open(pyz, "rb") as f:
            self.assertEqual(lines[2], hashlib.sha256(f.read()).hexdigest()[:12])

    def test_launcher_import_exposes_what_backup_scripts_use(self):
        self._install()
        code = (
            "import importlib.util as u\n"
            "s = u.spec_from_file_location('wgp', %r)\n"
            "m = u.module_from_spec(s); s.loader.exec_module(m)\n"
            "assert callable(m.load_config)\n"
            "assert callable(m.alert_cfg)\n"
            "assert hasattr(m.ALERTS, 'send_now')\n"
            "print('OK')\n" % os.path.join(self.tmp, "wg_panel.py"))
        r = _run([sys.executable, "-c", code], cwd=self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK", r.stdout)

    @unittest.skipIf(shutil.which("git") is None, "git نیست")
    def test_untracked_files_are_refused_inside_git(self):
        subprocess.run(["git", "init", "-q", self.tmp], check=True,
                       capture_output=True, timeout=60)
        _copy_pkg(self.tmp)
        subprocess.run(["git", "-C", self.tmp, "add", "wgpanel"], check=True,
                       capture_output=True, timeout=60)
        with open(os.path.join(self.tmp, "wgpanel", "app.py.orig"), "w") as f:
            f.write("stray\n")
        tool = os.path.join(ROOT, "tools", "build_pyz.py")
        src = os.path.join(self.tmp, "wgpanel")
        r = _run([sys.executable, tool, "--src", src, "--id"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("untracked", r.stderr)
        r = _run([sys.executable, tool, "--src", src, "--id",
                  "--allow-untracked"])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_source_tree_base_dir_is_repo_root(self):
        _copy_pkg(self.tmp)
        code = (
            "import importlib.util as u\n"
            "s = u.spec_from_file_location('x', %r)\n"
            "m = u.module_from_spec(s); s.loader.exec_module(m)\n"
            "print(m.BASE_DIR); print(m.ARCHIVE)\n"
            % os.path.join(self.tmp, "wgpanel", "app.py"))
        r = _run([sys.executable, "-c", code], cwd=self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertEqual(os.path.realpath(lines[0]), os.path.realpath(self.tmp))
        self.assertEqual(lines[1], "None")


    DATA_FILES = (
        "wgpanel/i18n/catalog.json", "wgpanel/web/page.html",
        "wgpanel/web/share.html", "wgpanel/web/tv3d.mjs",
        "wgpanel/web/fonts/vazirmatn-400.woff2",
        "wgpanel/web/fonts/vazirmatn-700.woff2",
        "wgpanel/web/svgstudio.js", "wgpanel/web/svgstudio.css", "wgpanel/web/studio.js",
        "wgpanel/web/vendor/svg-pan-zoom-3.6.1.min.js",
        "wgpanel/viz.py", "wgpanel/report.py", "wgpanel/xlsx.py")

    def test_archive_carries_the_package_data(self):
        with zipfile.ZipFile(io.BytesIO(B.build_bytes(PKG))) as z:
            names = set(z.namelist())
        for n in self.DATA_FILES:
            self.assertIn(n, names)

    def test_check_rejects_a_duplicate_catalog_key(self):
        _copy_pkg(self.tmp)
        cat = os.path.join(self.tmp, "wgpanel", "i18n", "catalog.json")
        with open(cat, encoding="utf-8") as f:
            lines = f.read().split("\n")
        self.assertTrue(lines[1].endswith(","), lines[1])
        lines.insert(2, lines[1])  # همان ردیف دوباره ⇒ کلیدِ تکراری
        with open(cat, "w", encoding="utf-8", newline="") as f:
            f.write("\n".join(lines))
        pyz = os.path.join(self.tmp, "dup.pyz")
        r = _run([sys.executable, os.path.join(ROOT, "tools", "build_pyz.py"),
                  "--src", os.path.join(self.tmp, "wgpanel"), "--out", pyz,
                  "--allow-untracked"])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = _run([sys.executable, pyz, "--check"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("duplicate key", r.stderr)

    def test_archive_serves_the_same_bytes_as_the_source_tree(self):
        """مسیرِ zip (zipimporter) و مسیرِ فایل (SourceFileLoader) باید بایتِ یکسان بدهند."""
        pyz = self._install()
        src_copy = os.path.join(self.tmp, "srccopy")
        os.makedirs(src_copy)
        _copy_pkg(src_copy)
        probe = (
            "import hashlib, json\n"
            "h = lambda s: hashlib.sha256(s.encode('utf-8')).hexdigest()\n"
            "print(json.dumps({'PAGE_HTML': h(a.PAGE_HTML), 'SHARE_HTML': h(a.SHARE_HTML),\n"
            "                  'TV3D_JS': h(a.TV3D_JS),\n"
            "                  'I18N': h(json.dumps({k: list(v) for k, v in a.I18N.items()},\n"
            "                                        ensure_ascii=False, sort_keys=True))},\n"
            "                 sort_keys=True))\n")
        zip_code = ("import sys; sys.path.insert(0, %r); import wgpanel.app as a\n"
                    % pyz) + probe
        file_code = (
            "import importlib.util as u\n"
            "s = u.spec_from_file_location('x', %r)\n"
            "a = u.module_from_spec(s); s.loader.exec_module(a)\n"
            % os.path.join(src_copy, "wgpanel", "app.py")) + probe
        r1 = _run([sys.executable, "-c", zip_code], cwd=self.tmp)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        r2 = _run([sys.executable, "-c", file_code], cwd=src_copy)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(r1.stdout, r2.stdout)
        self.assertIn("PAGE_HTML", r1.stdout)


if __name__ == "__main__":
    unittest.main()
