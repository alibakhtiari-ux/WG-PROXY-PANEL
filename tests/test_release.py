# -*- coding: utf-8 -*-
"""گاردِ release: CHANGELOG.md و استخراجِ یادداشتِ نسخه.

workflow ِ release یادداشت را از CHANGELOG می‌سازد و بدونِ بخشِ همان نسخه
شکست می‌خورد. این تست‌ها خرابیِ قالبِ CHANGELOG را پیش از push ِ tag
می‌گیرند — وقتی هنوز چیزی منتشر نشده.
"""
import importlib.util
import io
import os
import re
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "release_notes", os.path.join(ROOT, ".github", "release_notes.py"))
notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notes)


def _changelog_path():
    """The public changelog: in the private tree CHANGELOG.md is a different
    document, so publish/CHANGELOG.public.md wins when it exists."""
    pub = os.path.join(ROOT, "publish", "CHANGELOG.public.md")
    return pub if os.path.exists(pub) else os.path.join(ROOT, "CHANGELOG.md")


def _changelog():
    with open(_changelog_path(), encoding="utf-8") as f:
        return f.read()


class ChangelogTests(unittest.TestCase):

    def test_every_version_has_a_non_empty_section(self):
        text = _changelog()
        versions = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", text, re.M)
        self.assertTrue(versions, "هیچ نسخه‌ای در CHANGELOG نیست")
        for v in versions:
            with self.subTest(version=v):
                body = notes.section(text, v)
                self.assertTrue(body, "بخشِ خالی")
                self.assertNotRegex(body, r"(?m)^\[[^\]]+\]: ",
                                    "ارجاعِ لینک واردِ یادداشت شد")

    def test_versions_are_newest_first_and_linked(self):
        text = _changelog()
        versions = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", text, re.M)
        as_tuples = [tuple(map(int, v.split("."))) for v in versions]
        self.assertEqual(as_tuples, sorted(as_tuples, reverse=True))
        for v in versions:
            with self.subTest(version=v):
                self.assertRegex(text, r"(?m)^\[%s\]: https://"
                                 % re.escape(v))

    def test_notes_carry_the_build_id(self):
        v = re.search(r"^## \[(\d+\.\d+\.\d+)\]", _changelog(), re.M).group(1)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(notes.main(["x", "v" + v], _changelog_path()), 0)
        import subprocess
        bid = subprocess.run(
            ["python3", os.path.join(ROOT, "tools", "build_pyz.py"), "--id",
             "--allow-untracked"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout.strip()
        self.assertIn("`%s`" % bid, out.getvalue())

    def test_notes_carry_the_engine_build_id_and_both_checksum_lists(self):
        """از 1.4.0 ریلیز موتور را هم دارد؛ یادداشت شناسه‌اش را از سورس می‌سازد
        (همان قاعده‌ی پنل) و هر دو فهرستِ هش را نام می‌برد."""
        import subprocess
        v = re.search(r"^## \[(\d+\.\d+\.\d+)\]", _changelog(), re.M).group(1)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(notes.main(["x", "v" + v], _changelog_path()), 0)
        eid = subprocess.run(
            ["python3", os.path.join(ROOT, "tools", "build_nqmo_pyz.py"), "--id",
             "--allow-untracked"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout.strip()
        self.assertEqual(notes.engine_build_id(), eid)
        text = out.getvalue()
        self.assertIn("Engine build id: `%s`" % eid, text)
        self.assertIn("`sha256sum -c SHA256SUMS`", text)
        self.assertIn("`sha256sum -c SHA256SUMS.nqmo`", text)

    def test_build_id_ignores_a_stale_dist_archive(self):
        """شناسه همیشه از سورس ساخته می‌شود، نه از dist/wg_panel.pyz ِ موجود:
        dist ِ محلیِ کهنه پیش از این شناسه‌ی قدیمی چاپ می‌کرد و همین تست را
        بعد از هر تغییرِ سورس قرمز می‌کرد."""
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="wgrel-")
        try:
            shutil.copytree(os.path.join(ROOT, "wgpanel"),
                            os.path.join(tmp, "wgpanel"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            os.makedirs(os.path.join(tmp, "tools"))
            shutil.copy(os.path.join(ROOT, "tools", "build_pyz.py"),
                        os.path.join(tmp, "tools"))
            os.makedirs(os.path.join(tmp, "dist"))
            with open(os.path.join(tmp, "dist", "wg_panel.pyz"), "wb") as f:
                f.write(b"stale archive from an older build")
            saved = notes.ROOT
            notes.ROOT = tmp
            try:
                got = notes.panel_build_id()
            finally:
                notes.ROOT = saved
            self.assertNotEqual(got, notes.build_id(
                os.path.join(tmp, "dist", "wg_panel.pyz")))
            spec2 = importlib.util.spec_from_file_location(
                "build_pyz_t", os.path.join(tmp, "tools", "build_pyz.py"))
            bp = importlib.util.module_from_spec(spec2)
            spec2.loader.exec_module(bp)
            self.assertEqual(got, bp.build_id(bp.build_bytes(
                os.path.join(tmp, "wgpanel"))))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_an_undocumented_version_is_refused(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(notes.main(["x", "v99.0.0"]), 1)
            self.assertEqual(notes.main(["x", "latest"]), 2)


if __name__ == "__main__":
    unittest.main()
