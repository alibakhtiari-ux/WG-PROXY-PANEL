# -*- coding: utf-8 -*-
"""گاردهای فایل‌های نصب: یونیتِ systemd، اسّت‌های ریلیز و مرحله‌ی نصبِ README.

این‌ها را هیچ تستِ واحدی نمی‌بیند؛ CI فقط `bash -n` می‌زند. دو خرابیِ واقعی
که این فایل می‌گیرد:

- `ProtectSystem=full` بدونِ `/etc/squid` در ReadWritePaths → نوشتنِ
  passwd/squid.conf با EROFS شکست می‌خورد و فقط در actions.log دیده می‌شود.
- ریلیز/نصب بدونِ qr.js و three.js → QR، صفحه‌ی اشتراک و نمای سه‌بعدیِ TV
  با ۴۰۴ می‌شکنند، چون پنل آن‌ها را از کنارِ خودش سرو می‌کند.
"""
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
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


    def test_unit_loads_ifb_outside_the_sandbox(self):
        """ProtectKernelModules=yes جلوی modprobe ِ خودِ پنل را می‌گیرد، پس
        محدودیتِ آپلود (ifb) بی‌صدا اعمال نمی‌شد. یونیت باید ifb را با «+»
        (بیرونِ sandbox) و «-» (کرنلِ بدونِ ifb مانعِ شروع نشود) لود کند."""
        unit = _read("wg-panel.service")
        self.assertIn("ProtectKernelModules=yes", unit)
        m = re.search(r"(?m)^ExecStartPre=([-+@:!]*)\S*modprobe\b.*\bifb$",
                      unit)
        self.assertIsNotNone(m, "ExecStartPre ِ modprobe ifb در یونیت نیست")
        self.assertIn("+", m.group(1))
        self.assertIn("-", m.group(1))

    def test_docker_installers_load_ifb_on_the_host(self):
        # کانتینر ماژول لود نمی‌کند؛ میزبان باید ifb را هم مثلِ wireguard
        # لود و ماندگار کند، وگرنه محدودیتِ آپلود در Docker هم اعمال نمی‌شود.
        for path in (("docker", "host-setup.sh"),
                     ("docker", "airgap", "install.sh")):
            with self.subTest(script="/".join(path)):
                sh = _read(*path)
                self.assertIn("modprobe ifb", sh)
                self.assertIn("/etc/modules-load.d/ifb.conf", sh)


class VerifyBackupTests(unittest.TestCase):
    """deploy/wg-panel-verify-backup.sh با یک rclone ِ جعلی که از پوشه‌ی محلی
    سرو می‌کند. مسیرهای ثابتِ /etc و /var به پوشه‌ی موقت برگردانده می‌شوند."""

    FAKE_RCLONE = r'''#!/usr/bin/env python3
import os, sys
root = os.environ["FAKE_S4"]
args = [a for a in sys.argv[1:] if a != "--config"]
cmd, target = args[0], args[-1]
path = os.path.join(root, target.split(":", 1)[1])
if cmd == "lsf":
    if not os.path.isdir(path):
        sys.exit(0)
    print("\n".join(sorted(os.listdir(path))))
elif cmd == "cat":
    try:
        sys.stdout.buffer.write(open(path, "rb").read())
    except OSError:
        sys.exit(3)
'''

    def setUp(self):
        if not shutil.which("bash"):
            self.skipTest("bash نیست")
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        d = self.tmp
        self.s4 = os.path.join(d, "s4")
        self.state = os.path.join(d, "state.json")
        self.env = os.path.join(d, "s4.env")
        with open(self.env, "w") as f:
            f.write("REMOTE=mega\nBUCKET=bk\n")
        bindir = os.path.join(d, "bin")
        os.makedirs(bindir)
        rc = os.path.join(bindir, "rclone")
        with open(rc, "w") as f:
            f.write(self.FAKE_RCLONE)
        os.chmod(rc, 0o755)
        self.path = bindir + os.pathsep + os.environ.get("PATH", "")
        src = _read("deploy", "wg-panel-verify-backup.sh")
        for old, new in (("/etc/wg-panel-s4.env", self.env),
                         ("/etc/wg-panel-rclone.conf", os.path.join(d, "rc")),
                         ("/root/.config/rclone/rclone.conf",
                          os.path.join(d, "rc")),
                         ("/var/backups/backup-state.json", self.state),
                         ("/var/backups/", os.path.join(d, "local") + "/"),
                         ("/opt/wg-panel/wg_panel.py",
                          os.path.join(d, "none.py"))):
            self.assertIn(old, src)
            src = src.replace(old, new)
        self.script = os.path.join(d, "verify.sh")
        with open(self.script, "w", encoding="utf-8") as f:
            f.write(src)

    def _put(self, prefix, name, members):
        """آرشیوِ tar.gz با اعضای داده‌شده + sidecar ِ sha256 روی «MEGA»."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for member, data in members.items():
                info = tarfile.TarInfo(member)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        blob = buf.getvalue()
        d = os.path.join(self.s4, "bk", prefix)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "wb") as f:
            f.write(blob)
        with open(os.path.join(d, name + ".sha256"), "w") as f:
            f.write(hashlib.sha256(blob).hexdigest() + "  " + name + "\n")

    def _panel_backup(self):
        db = os.path.join(self.tmp, "traffic.db")
        con = sqlite3.connect(db)
        con.execute("create table t (x)")
        con.commit()
        con.close()
        with open(db, "rb") as f:
            dbdata = f.read()
        self._put("wg-panel", "wg-panel-20260926-043000.tar.gz",
                  {"wg-panel/config.json": b"{}",
                   "wg-panel/traffic.db": dbdata})

    def _state(self, **keys):
        with open(self.state, "w") as f:
            json.dump({k: {"uploaded": time.time()} for k in keys}, f)

    def _run(self):
        return subprocess.run(
            ["bash", self.script], capture_output=True, text=True,
            env=dict(os.environ, PATH=self.path, FAKE_S4=self.s4), timeout=60)

    def test_panel_only_install_passes_without_a_full_host_chain(self):
        # نصبی که فقط بکاپِ پنل دارد (همه‌ی نصب‌ها جز استقرارِ نگه‌دارنده)
        self._panel_backup()
        self._state(panel=1)
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("سرور:", r.stdout + r.stderr)

    def test_full_chain_in_state_is_still_checked(self):
        # زنجیره‌ای که زمانی آپلود کرده و حالا بکاپی ندارد باید گزارش شود
        self._panel_backup()
        self._state(panel=1, full=1)
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("سرور: هیچ بکاپی روی MEGA نیست", r.stderr)

    def test_full_chain_present_and_healthy_passes(self):
        self._panel_backup()
        self._put("host-full", "host-backup-20260926.tar.gz",
                  {"etc/letsencrypt/README": b"x"})
        self._state(panel=1, full=1)
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("پنل + سرور", r.stdout)


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

    def test_readme_downloads_every_asset_listed_in_sha256sums(self):
        """`sha256sum -c SHA256SUMS` برای هر فایلِ فهرست‌شده‌ای که دانلود نشده
        «No such file» می‌دهد و با کدِ غیرصفر بیرون می‌آید — حتی وقتی بقیه
        سالم‌اند. پس دستورِ curl ِ README باید همه‌ی ASSETS را بگیرد."""
        wf = _read(".github", "workflows", "release.yml")
        assets = re.search(r'ASSETS="([^"]+)"', wf).group(1).split()
        for name in READMES:
            text = _read(name)
            for fn in assets:
                with self.subTest(readme=name, file=fn):
                    self.assertRegex(
                        text, r'(?:-fLO|-O) "\$base/%s"' % re.escape(fn))


if __name__ == "__main__":
    unittest.main()
