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


def _changelog():
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
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
            self.assertEqual(notes.main(["x", "v" + v]), 0)
        bid = notes.build_id(os.path.join(ROOT, "wg_panel.py"))
        self.assertIn("`%s`" % bid, out.getvalue())

    def test_an_undocumented_version_is_refused(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(notes.main(["x", "v99.0.0"]), 1)
            self.assertEqual(notes.main(["x", "latest"]), 2)


if __name__ == "__main__":
    unittest.main()
