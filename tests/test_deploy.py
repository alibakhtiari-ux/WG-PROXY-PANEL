# -*- coding: utf-8 -*-
"""گاردهای فایل‌های نصب: یونیتِ systemd، اسّت‌های ریلیز و مرحله‌ی نصبِ README.

این‌ها را هیچ تستِ واحدی نمی‌بیند؛ CI فقط `bash -n` می‌زند. دو خرابیِ واقعی
که این فایل می‌گیرد:

- `ProtectSystem=full` بدونِ `/etc/squid` در ReadWritePaths → نوشتنِ
  passwd/squid.conf با EROFS شکست می‌خورد و فقط در actions.log دیده می‌شود.
- ریلیز/نصب بدونِ qr.js و three.js → QR، صفحه‌ی اشتراک و نمای سه‌بعدیِ TV
  با ۴۰۴ می‌شکنند، چون پنل آن‌ها را از کنارِ خودش سرو می‌کند.
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


# فایل‌هایی که wg_panel.py از BASE_DIR سرو می‌کند (و در نبودشان ۴۰۴ می‌دهد)
SERVED_FILES = ("qr.js", "three.module.min.js.gz", "three.core.min.js.gz")
READMES = ("README.md", "README.fa.md", "README.ru.md", "README.zh-CN.md")


class SystemdUnitTests(unittest.TestCase):

    def _rw_paths(self):
        unit = _read("wg-panel.service")
        m = re.search(r"(?m)^ReadWritePaths=(.*)$", unit)
        self.assertIsNotNone(m, "ReadWritePaths در یونیت نیست")
        # پیشوندِ «-» (نادیده‌گرفتنِ مسیرِ ناموجود) جزءِ مسیر نیست
        return [p.lstrip("-") for p in m.group(1).split()]

    def _panel_write_dirs(self):
        src = _read("wg_panel.py")
        dirs = set()
        for const in ("WG_DIR", "SQUID_CONF", "SQUID_PASSWD"):
            m = re.search(r'(?m)^%s = "([^"]+)"' % const, src)
            self.assertIsNotNone(m, const)
            path = m.group(1)
            dirs.add(path if const == "WG_DIR" else os.path.dirname(path))
        dirs.add("/opt/wg-panel")   # BASE_DIR ِ نصبِ systemd (config/db/clients)
        return dirs

    def test_every_directory_the_panel_writes_is_writable_under_protectsystem(self):
        unit = _read("wg-panel.service")
        self.assertIn("ProtectSystem=full", unit)
        rw = self._rw_paths()
        for d in sorted(self._panel_write_dirs()):
            with self.subTest(dir=d):
                self.assertTrue(
                    any(d == p or d.startswith(p.rstrip("/") + "/") for p in rw),
                    "%s در ReadWritePaths نیست: %s" % (d, rw))

    def test_squid_dir_is_optional_so_a_host_without_squid_still_boots(self):
        unit = _read("wg-panel.service")
        self.assertRegex(unit, r"(?m)^ReadWritePaths=.*\s-/etc/squid(\s|$)")


class ReleaseAssetTests(unittest.TestCase):

    def test_panel_serves_exactly_the_files_this_test_knows(self):
        """اگر فایلِ تازه‌ای از BASE_DIR سرو شود، این تست باید عوض شود — و با
        آن ریلیز و README."""
        src = _read("wg_panel.py")
        served = set(re.findall(
            r'os\.path\.join\(BASE_DIR,\s*"([^"]+\.(?:js|gz))"\)', src))
        # three.* از یک نگاشتِ نام می‌آید، نه join ِ مستقیم
        served |= set(re.findall(r'"(three\.[a-z.]+\.min\.js\.gz)"', src))
        self.assertEqual(served, set(SERVED_FILES))
        for fn in SERVED_FILES:
            self.assertTrue(os.path.exists(os.path.join(ROOT, fn)), fn)

    def test_release_workflow_ships_every_served_file_with_a_checksum(self):
        wf = _read(".github", "workflows", "release.yml")
        m = re.search(r'ASSETS="([^"]+)"', wf)
        self.assertIsNotNone(m, "ASSETS در release.yml نیست")
        assets = m.group(1).split()
        for fn in ("wg_panel.py", "wg-panel.service") + SERVED_FILES:
            with self.subTest(file=fn):
                self.assertIn(fn, assets)
        self.assertIn("cp $ASSETS dist/", wf)
        self.assertIn("sha256sum $ASSETS > SHA256SUMS", wf)

    def test_readme_install_steps_download_and_install_every_served_file(self):
        for name in READMES:
            text = _read(name)
            with self.subTest(readme=name):
                for fn in SERVED_FILES:
                    self.assertIn('-O "$base/%s"' % fn, text)
                    self.assertRegex(
                        text, r"(?m)^sudo install .*-t /opt/wg-panel .*%s"
                        % re.escape(fn))
                # همه‌ی فایل‌های دانلودشده باید در SHA256SUMS باشند، وگرنه
                # `sha256sum -c` ِ خطِ بعد رد می‌شود
                self.assertIn('-O "$base/SHA256SUMS"', text)


if __name__ == "__main__":
    unittest.main()
