#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""گاردهای نصاب‌های airgap و deploy/setup-deps.sh.

هیچ نصابی هرگز **اجرا** نمی‌شود — نه در باتری، نه اینجا. کلِ پوششِ قبلی
`bash -n` بود، که نحو را می‌گیرد و منطق را نه. به همین دلیل چند باگ سال‌ها
زنده ماندند: گیتِ نسخه‌ای که دقیقاً حداقلِ مستندشده را رد می‌کرد، و
راستی‌آزماییِ یکپارچگی‌ای که با حذفِ یک فایل دور می‌خورد.

پس این فایل دو نوع گارد دارد:

- **ساختاری** — روی متنِ اسکریپت، همیشه با حذفِ خطوطِ کامنت. این مخزن دو بار
  گاردی داشته که به‌جای کد، کامنتِ توضیح‌دهنده‌ی همان دام را می‌گرفت.
- **رفتاری** — تابع را از اسکریپت بیرون می‌کشد، با استابِ ag_* در یک ریشه‌ی
  ساختگی اجرا می‌کند، و کدِ خروج را می‌سنجد. هیچ مسیرِ واقعیِ سیستم لمس
  نمی‌شود.
"""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# استابِ کمکی‌های نصاب — خروجی به stdout می‌رود تا تست بتواند بخواندش
AG_STUBS = """#!/bin/bash
set -Eeuo pipefail
ag_step(){ echo "STEP: $*"; }
ag_ok(){ echo "OK: $*"; }
ag_warn(){ echo "WARN: $*"; }
ag_err(){ echo "ERR: $*"; }
ag_log_raw(){ echo "LOG: $*"; }
"""


class _NeedsDir(unittest.TestCase):
    """کلاسی که بیرونِ wg_panel.py را می‌سنجد و در شاخه‌ی public نیست.

    شاخه‌ی `public` مشتق است و فقط زیرمجموعه‌ای از مخزن را می‌برد —
    `airgap/` و `publish/` آنجا وجود ندارند. همان الگوی AnsibleSyncTests
    و QrAssetTests: کلاس آنجا skip می‌شود، اینجا هرگز.
    """

    NEEDS = ()

    @classmethod
    def setUpClass(cls):
        for d in cls.NEEDS:
            if not (ROOT / d).exists():
                raise unittest.SkipTest("%s نیست — مخزنِ عمومی" % d)


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _nocomments(src):
    """خطوطِ کامنت را می‌اندازد — گارد باید کد را بگیرد، نه توضیحش را."""
    return "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))


def _extract_fn(src, name):
    """بدنه‌ی یک تابعِ شل را از سورس بیرون می‌کشد (تا `\\n}` ستونِ صفر)."""
    m = re.search(r"%s\(\)\s*\{.*?\n\}" % re.escape(name), src, re.S)
    return m.group(0) if m else None


class PythonVersionGateTests(_NeedsDir):
    """verify.sh روی پایتونِ دقیقاً ۳.۱۰ FAIL می‌داد — با پیامی که خودش
    می‌گفت «۳.۱۰+ لازم است». ۳.۱۰ پایتونِ سیستمیِ اوبونتو ۲۲.۰۴ است."""

    NEEDS = ("airgap",)
    REL = "airgap/single-server/installer/verify.sh"

    def test_python_version_gate_accepts_the_documented_minimum(self):
        """گیتِ نسخه‌ی پایتون باید دقیقاً حداقلِ مستندشده را بپذیرد.

        الگوی قبلی `printf '%s\\n3.10\\n' "$pv" | sort -V -C` بود؛ sort -C
        ورودیِ غیرنزولی را می‌پذیرد، یعنی pv<=3.10 آزموده می‌شد. ضمناً
        pv="?" (وقتی مفسر اجرا نمی‌شد) بی‌صدا PASS می‌گرفت، چون '?' از
        '3' بزرگ‌تر است و دنباله نزولی می‌شد.
        """
        body = _nocomments(_read(self.REL))
        self.assertNotIn("sort -V -C", body,
                         "verify.sh هنوز نسخه را با sort -V -C می‌سنجد")
        self.assertIn("version_info>=(3,10)", body.replace(" ", ""),
                      "گیتِ نسخه به خودِ پایتون سپرده نشده")

    def test_version_predicate_is_correct_at_the_boundary(self):
        """خودِ محمولِ جایگزین را روی مرز بسنج، نه فقط وجودش را.

        تاپلِ ساختگی می‌دهد تا مرز مستقل از پایتونِ میزبان اثبات شود.
        """
        for ver, want in (((3, 9), False), ((3, 10), True), ((3, 11), True),
                          ((4, 0), True), ((2, 7), False)):
            with self.subTest(ver=ver):
                r = subprocess.run(
                    ["python3", "-c",
                     "import sys;v=%r;sys.exit(0 if v>=(3,10) else 1)" % (ver,)],
                    capture_output=True)
                self.assertEqual(r.returncode == 0, want)

    def test_the_sibling_kernel_gate_is_left_alone(self):
        """preflight.sh همان اصطلاح را با ترتیبِ معکوس دارد و **درست** است.

        `printf '5.6\\n%s\\n' "$kver" | sort -V -C` یعنی 5.6 <= kver، پس
        برابری روی سمتِ **خواسته‌شده** می‌افتد و کرنلِ دقیقاً ۵.۶ قبول
        می‌شود — همان چیزی که کامنتش می‌گوید. تنها پرسشِ مهم درباره‌ی این
        اصطلاح این است که ثابت کدام سمتِ مقایسه نشسته.
        """
        body = _nocomments(_read("airgap/single-server/installer/preflight.sh"))
        self.assertIn("printf '5.6\\n%s\\n'", body,
                      "گاردِ کرنلِ preflight.sh عوض شده — عمداً؟")

    def test_no_unreviewed_sort_v_version_gate_remains(self):
        """گاردِ خانوادگی: هر `sort -V -C` تازه باید آگاهانه بازبینی شود."""
        hits = []
        for base in ("airgap/generic/installer", "airgap/single-server/installer",
                     "deploy", "online"):
            d = ROOT / base
            if not d.is_dir():
                continue
            for p in d.rglob("*"):
                if p.is_file() and "sort -V" in _nocomments(
                        p.read_text(encoding="utf-8", errors="ignore")):
                    hits.append(str(p.relative_to(ROOT)))
        self.assertEqual(
            sorted(hits), ["airgap/single-server/installer/preflight.sh"],
            "sort -V ِ بازبینی‌نشده: ثابت کدام سمتِ مقایسه است و برابری "
            "کجا می‌افتد؟ %s" % sorted(hits))


class NetworkArtifactTests(_NeedsDir):
    """rclone همان پروسه‌ای است که /etc/wg-panel-rclone.conf و بکاپِ کاملِ
    سرور را دست می‌گیرد — و شبانه از تایمر اجرا می‌شود."""

    NEEDS = ("deploy/setup-deps.sh",)
    REL = "deploy/setup-deps.sh"

    def test_no_network_download_is_installed_without_a_checksum(self):
        """هیچ آرتیفکتی که از شبکه می‌آید نباید بدونِ بررسیِ checksum نصب شود.

        setup-deps.sh زیپِ rclone را می‌گرفت و مستقیم با install -m755 در
        /usr/local/bin می‌نشاند — بدونِ sha256، بدونِ امضا، با نسخه‌ای که
        خودش از همان میزبان می‌آمد.
        """
        src = _read(self.REL)
        body = _nocomments(src)
        if "curl" in body and "install -m" in body:
            self.assertRegex(body, r"sha256sum\s+-c",
                             "دانلود هست ولی بررسیِ sha256sum نیست")
        self.assertNotIn("version.txt", body,
                         "نسخه‌ی rclone هنوز از شبکه خوانده می‌شود (پین نیست)")

    def test_pinned_hash_is_real_and_not_a_placeholder(self):
        """هشِ placeholder نباید به کامیت برسد — هشِ غلط این رفع را به
        قطعیِ زمانِ نصب تبدیل می‌کند، که از وضعِ موجود بدتر است."""
        src = _read(self.REL)
        m = re.search(r'RCLONE_SHA256="([0-9a-f]{64})"', src)
        self.assertIsNotNone(m, "ثابتِ RCLONE_SHA256 با هشِ ۶۴ رقمی پیدا نشد")
        assert m is not None
        self.assertNotEqual(m.group(1), "0" * 64, "هشِ placeholder جا مانده")
        self.assertRegex(_nocomments(src), r'RCLONE_VER="v[0-9]+\.[0-9]+\.[0-9]+"',
                         "نسخه پین نشده")

    def test_extraction_uses_a_fresh_temp_dir(self):
        """`cd /tmp` با نامِ ثابت یعنی پوشه‌ی از پیش کاشته‌شده یا اجرای
        موازی می‌تواند تعیین کند چه چیزی به‌عنوانِ root نصب شود."""
        body = _nocomments(_read(self.REL))
        self.assertIn("mktemp -d", body, "استخراج در پوشه‌ی موقتِ تازه نیست")


class TransientAptSourceTests(_NeedsDir):
    """`deb [trusted=yes] file://…` در حینِ نصب امن است چون _ag_apt با
    -o Dir::Etc::sourcelist محدودش می‌کند. بعد از خروجِ نصاب هیچ چیزی
    محدودش نمی‌کند."""

    NEEDS = ("airgap",)
    VARIANTS = ("generic", "single-server")

    def test_no_permanent_trusted_apt_source_is_installed(self):
        """منبعِ apt ِ trusted=yes نباید در sources.list.d ماندگار شود.

        هر apt-get ِ بعدیِ اپراتور یک منبعِ file:// بدونِ بررسیِ امضا
        می‌دید؛ و اگر پوشه‌ی بسته پاک شده بود، apt-get update با خطای
        منبعِ گم‌شده می‌شکست.
        """
        for v in self.VARIANTS:
            body = _nocomments(_read("airgap/%s/installer/install.sh" % v))
            with self.subTest(variant=v):
                self.assertNotRegex(
                    body, r'AG_OFFLINE_LIST=.*/etc/apt/sources\.list\.d/',
                    "منبعِ موقت هنوز در sources.list.d نوشته می‌شود")
                self.assertRegex(body, r"trap\s+_ag_drop_offline_source\s+EXIT",
                                 "پاک‌سازیِ منبعِ موقت روی EXIT ثبت نشده")

    def test_every_apt_get_goes_through_the_confined_wrapper(self):
        """تنها راهی که این تغییر می‌تواند بشکند: فراخوانیِ apt-get ای که
        `-o Dir::Etc::sourcelist` نمی‌گیرد و حالا منبع را نمی‌بیند."""
        for v in self.VARIANTS:
            src = _read("airgap/%s/installer/install.sh" % v)
            wrapper = _extract_fn(src, "_ag_apt") or ""
            outside = [l.strip() for l in _nocomments(src).splitlines()
                       if "apt-get" in l and l.strip() not in wrapper]
            with self.subTest(variant=v):
                self.assertEqual(outside, [],
                                 "apt-get بیرونِ _ag_apt: %s" % outside)

    def test_legacy_path_is_still_cleaned_up(self):
        """نصبِ تازه روی هاستی که با نسخه‌ی قدیمی نصب شده باید جامانده‌ی
        `/etc/apt/sources.list.d/wg-panel-offline.list` را هم ببرد."""
        for v in self.VARIANTS:
            body = _nocomments(_read("airgap/%s/installer/install.sh" % v))
            with self.subTest(variant=v):
                self.assertIn("/etc/apt/sources.list.d/wg-panel-offline.list",
                              body, "مسیرِ قدیمی پاک‌سازی نمی‌شود")

    def test_the_ansible_writer_is_cleaned_up_too(self):
        """نقشِ ansible همان فایل را جدا می‌نویسد. ماژولِ apt ِ ansible
        `-o Dir::Etc::*` نمی‌گیرد و نقشِ wg-panel هم بعدش apt می‌زند، پس
        فایل باید تا پایانِ play بماند — ولی نه بیشتر."""
        for v in self.VARIANTS:
            site = _read("airgap/%s/ansible/playbooks/site.yml" % v)
            with self.subTest(variant=v):
                self.assertIn("post_tasks", site,
                              "پاک‌سازیِ پایانِ play در site.yml نیست")
                self.assertRegex(
                    site,
                    r"path:\s*/etc/apt/sources\.list\.d/wg-panel-offline\.list"
                    r"\s*\n\s*state:\s*absent",
                    "تسکِ برداشتنِ منبعِ موقت پیدا نشد")


class UninstallRestoresTests(_NeedsDir):
    """نقشِ نصب همه‌ی منابعِ apt را کنار می‌گذارد و خودش این کار را
    «برگشت‌پذیر» می‌نامد."""

    NEEDS = ("airgap",)
    VARIANTS = ("generic", "single-server")
    MARKS = ("disabled-by-wg-panel", "sources.list.wg-panel-disabled")

    @staticmethod
    def _undo_text(variant):
        """متنِ همه‌ی فایل‌هایی که مسیرِ حذف را می‌سازند."""
        parts, names = [], []
        for p in (ROOT / "airgap" / variant).rglob("*"):
            if p.is_file() and ("uninstall" in p.name
                                or "uninstall" in str(p.parent)):
                parts.append(p.read_text(encoding="utf-8", errors="ignore"))
                names.append(str(p.relative_to(ROOT)))
        return "".join(parts), names

    def test_uninstall_restores_what_install_disabled(self):
        """هر چیزی که نصب کنار می‌گذارد باید در حذف برگردد.

        گارد به‌صورتِ **رابطه** نوشته شده — «هرچه نقش کنار می‌گذارد، مسیرِ
        حذف باید نامش را بداند» — تا با افزودنِ موردِ سومی هم کار کند.
        """
        for v in self.VARIANTS:
            role = _read("airgap/%s/ansible/roles/offline_repository"
                         "/tasks/main.yml" % v)
            undo, names = self._undo_text(v)
            # گلاب واقعاً به مسیرهای حذف رسیده باشد، وگرنه تست بی‌معنا سبز است
            self.assertTrue(names, "%s: هیچ فایلِ حذفی پیدا نشد" % v)
            for mark in self.MARKS:
                if mark in role:
                    with self.subTest(variant=v, mark=mark):
                        self.assertIn(
                            mark, undo,
                            "%s: نصب %s را کنار می‌گذارد ولی مسیرِ حذف "
                            "(%s) هرگز برنمی‌گرداند" % (v, mark, names))

    def test_restore_never_overwrites_an_operator_created_source(self):
        """رفتاری: منبعی که اپراتور بعد از نصب ساخته باید **زنده بماند**.

        بازگرداندنِ بی‌قید بی‌صدا نابودش می‌کند. رد کردن چیزی برای اقدام
        باقی می‌گذارد؛ رونویسی هیچ.
        """
        src = _read("airgap/single-server/installer/uninstall.sh")
        fn = _extract_fn(src, "_ag_restore_apt_sources")
        self.assertIsNotNone(fn, "تابعِ بازگردانی پیدا نشد")
        assert fn is not None
        # مسیرهای مطلق به ریشه‌ی ساختگی می‌روند — هیچ چیزِ واقعی لمس نمی‌شود
        probe = AG_STUBS + fn.replace("/etc/apt/", '${FAKE}/etc/apt/') \
            + "\n_ag_restore_apt_sources\n"
        tmp = tempfile.mkdtemp(prefix="wg-restore-")
        try:
            sh = os.path.join(tmp, "probe.sh")
            with open(sh, "w", encoding="utf-8") as f:
                f.write(probe)
            fake = os.path.join(tmp, "root")
            d = os.path.join(fake, "etc/apt/sources.list.d/disabled-by-wg-panel")
            os.makedirs(d)
            for n in ("ubuntu.sources", "docker.list"):
                with open(os.path.join(d, n), "w", encoding="utf-8") as f:
                    f.write("stashed\n")
            live = os.path.join(fake, "etc/apt/sources.list.d/docker.list")
            with open(live, "w", encoding="utf-8") as f:
                f.write("OPERATOR\n")          # هم‌نامِ تازه — نباید نابود شود
            with open(os.path.join(fake, "etc/apt/sources.list.wg-panel-disabled"),
                      "w", encoding="utf-8") as f:
                f.write("classic\n")

            env = dict(os.environ, FAKE=fake)
            r = subprocess.run(["bash", sh], capture_output=True, text=True,
                               env=env, timeout=30)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

            with open(live, encoding="utf-8") as f:
                self.assertEqual(f.read(), "OPERATOR\n",
                                 "منبعِ ساخته‌ی اپراتور رونویسی شد")
            self.assertIn("رد شد", r.stdout, "هشدارِ رد شدن چاپ نشد")
            self.assertTrue(
                os.path.isfile(os.path.join(
                    fake, "etc/apt/sources.list.d/ubuntu.sources")),
                "منبعِ بدونِ برخورد بازگردانده نشد")
            self.assertTrue(
                os.path.isfile(os.path.join(fake, "etc/apt/sources.list")),
                "sources.list ِ کلاسیک بازگردانده نشد")
            # چیزی رد شده ⇒ پوشه نباید حذف شود؛ هشدار خودش خروجی است
            self.assertTrue(os.path.isdir(d),
                            "پوشه‌ی disabled با وجودِ موردِ ردشده حذف شد")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_restore_is_quiet_on_an_empty_or_absent_directory(self):
        """پوشه‌ی خالی نباید خطای کاذب بدهد (glob بسط نمی‌یابد و $f
        رشته‌ی الگو می‌ماند)."""
        src = _read("airgap/single-server/installer/uninstall.sh")
        fn = _extract_fn(src, "_ag_restore_apt_sources")
        assert fn is not None
        probe = AG_STUBS + fn.replace("/etc/apt/", '${FAKE}/etc/apt/') \
            + "\n_ag_restore_apt_sources\n"
        tmp = tempfile.mkdtemp(prefix="wg-restore-empty-")
        try:
            sh = os.path.join(tmp, "probe.sh")
            with open(sh, "w", encoding="utf-8") as f:
                f.write(probe)
            for case, make in (("خالی", True), ("نبودِ پوشه", False)):
                fake = os.path.join(tmp, case)
                os.makedirs(os.path.join(fake, "etc/apt/sources.list.d"))
                if make:
                    os.makedirs(os.path.join(
                        fake, "etc/apt/sources.list.d/disabled-by-wg-panel"))
                r = subprocess.run(["bash", sh], capture_output=True, text=True,
                                   env=dict(os.environ, FAKE=fake), timeout=30)
                with self.subTest(case=case):
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertNotIn("ناموفق", r.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class IntegrityFailClosedTests(_NeedsDir):
    """`_ag_verify_integrity` تنها دفاعِ نصابِ airgap در برابرِ بسته‌ی
    دست‌کاری‌شده است."""

    NEEDS = ("airgap",)
    VARIANTS = ("generic", "single-server")

    def test_integrity_check_fails_closed(self):
        """راستی‌آزماییِ یکپارچگی نباید با نبودِ مانیفست موفق اعلام شود.

        پیش از این، نبودِ checksums.sha256 یعنی ag_warn و return 0 — پس
        مهاجمی که بسته را دست‌کاری می‌کند لازم نبود هش را جعل کند، فقط
        مانیفست را حذف می‌کرد و کلِ بررسی با یک هشدارِ زرد ناپدید می‌شد.
        """
        for v in self.VARIANTS:
            fn = _extract_fn(_read("airgap/%s/installer/install.sh" % v),
                             "_ag_verify_integrity")
            self.assertIsNotNone(fn, "%s: _ag_verify_integrity پیدا نشد" % v)
            assert fn is not None
            body = _nocomments(fn)
            miss = body[body.index("! -f"):]
            with self.subTest(variant=v):
                self.assertIn("return 1", miss,
                              "شاخه‌ی نبودِ مانیفست هنوز موفق برمی‌گردد")
                if "return 0" in miss:
                    self.assertIn("AG_ALLOW_UNVERIFIED", miss,
                                  "return 0 بدونِ فلگِ صریحِ عبور")
                # فلگ نباید شاخه‌ی عدمِ تطابق را هم بپوشاند: نبودِ مانیفست
                # مشکلِ ساخت است، ناهم‌خوانی دست‌کاری. این تنها راهِ واقع‌بینانه‌ی
                # خنثی‌شدنِ این رفع است.
                mismatch = body[body.index("sha256sum -c"):]
                self.assertNotIn("AG_ALLOW_UNVERIFIED", mismatch,
                                 "فلگِ عبور نباید عدمِ تطابقِ هش را هم رد کند")

    def test_integrity_check_behaviour_on_three_bundles(self):
        """رفتاری: مانیفستِ درست ⇒ ۰ · ناهم‌خوان ⇒ ۱ · نبودن ⇒ ۱.
        و فلگ فقط سومی را نجات می‌دهد."""
        if not shutil.which("sha256sum"):
            raise unittest.SkipTest("sha256sum روی این میزبان نیست")
        fn = _extract_fn(
            _read("airgap/single-server/installer/install.sh"),
            "_ag_verify_integrity")
        assert fn is not None
        probe = (AG_STUBS
                 + 'ag_manifest_dir(){ printf "%s" "$BUNDLE"; }\n'
                 + 'ag_offline_dir(){ printf "%s" "$BUNDLE"; }\n'
                 + fn + "\n_ag_verify_integrity\n")
        tmp = tempfile.mkdtemp(prefix="wg-integ-")
        try:
            sh = os.path.join(tmp, "probe.sh")
            with open(sh, "w", encoding="utf-8") as f:
                f.write(probe)
            for case in ("good", "bad", "missing"):
                d = os.path.join(tmp, case)
                os.makedirs(d)
                with open(os.path.join(d, "file.txt"), "w", encoding="utf-8") as f:
                    f.write("payload\n")
                if case != "missing":
                    with open(os.path.join(d, "checksums.sha256"), "w",
                              encoding="utf-8") as f:
                        f.write(subprocess.run(
                            ["sha256sum", "file.txt"], cwd=d,
                            capture_output=True, text=True).stdout)
                if case == "bad":       # مانیفست هست، محتوا عوض شده
                    with open(os.path.join(d, "file.txt"), "w",
                              encoding="utf-8") as f:
                        f.write("tampered\n")

            def run(case, allow=False):
                env = dict(os.environ, BUNDLE=os.path.join(tmp, case))
                if allow:
                    env["AG_ALLOW_UNVERIFIED"] = "1"
                return subprocess.run(["bash", sh], capture_output=True,
                                      text=True, env=env, timeout=30).returncode

            self.assertEqual(run("good"), 0, "بسته‌ی سالم رد شد")
            self.assertEqual(run("bad"), 1, "بسته‌ی دست‌کاری‌شده پذیرفته شد")
            self.assertEqual(run("missing"), 1,
                             "نبودِ مانیفست هنوز موفق برمی‌گردد")
            self.assertEqual(run("missing", allow=True), 0,
                             "فلگِ عبور روی نبودِ مانیفست کار نمی‌کند")
            self.assertEqual(run("bad", allow=True), 1,
                             "فلگِ عبور دست‌کاری را هم رد کرد — نباید")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ContainerBootstrapTests(_NeedsDir):
    """اسکریپت‌های docker هرگز اجرا نمی‌شوند — کلِ پوششِ قبلی `bash -n`
    بود. به همین دلیل یک تزریقِ نحواً معتبر زنده ماند."""

    NEEDS = ("docker",)

    def test_no_env_value_is_interpolated_into_python_source(self):
        """مقدارِ .env نباید داخلِ سورسِ پایتون درج شود.

        مقداری با یک آپاستروف رشته را می‌بندد و بقیه‌اش به‌عنوانِ کد
        اجرا می‌شود — با root، در بوت‌استرپِ اولِ کانتینر. اثباتِ عملی:
        مقداری مثلِ ``10.0.0.0/24'); print('X'); ipaddress.ip_network('``
        با الگوی قبلی X را چاپ می‌کرد و ۰ برمی‌گشت.

        الگوی امن در همان فایل بود: heredoc با دلیمیترِ کوت‌شده و
        مقدارها از os.environ — یعنی «یک فایل، دو الگو، یکی غلط».
        """
        for p in sorted((ROOT / "docker").rglob("*.sh")):
            body = _nocomments(p.read_text(encoding="utf-8"))
            with self.subTest(f=str(p.relative_to(ROOT))):
                # heredoc ِ بدونِ کوت که به python داده می‌شود
                self.assertNotRegex(
                    body, r"python3?\s+-\s*<<[A-Z]",
                    "heredoc ِ پایتون بدونِ کوت — شل داخلش را بسط می‌دهد")
                # python3 -c با متغیرِ شل داخلِ رشته
                self.assertNotRegex(
                    body, "python3?\\s+-c\\s+\"[^\"]*\\$",
                    "متغیرِ شل داخلِ سورسِ پایتون درج می‌شود")

    def test_env_files_are_created_with_restrictive_permissions(self):
        """هر جا .env ساخته یا نوشته می‌شود باید مود محدود بگیرد.

        .env توکنِ ربات را نگه می‌دارد — همان رباتی که پیر می‌سازد و
        ورودِ پنل را تأیید می‌کند. `cp` ِ ساده مود را از umask می‌گیرد
        و روی هاستِ چندکاربره خواندنی می‌ماند.
        """
        checked = 0
        for p in sorted((ROOT / "docker").rglob("*.sh")):
            # 🪤 docker/airgap/dist/ خروجیِ ساختِ بسته است (gitignore شده) و
            # کپیِ کهنه‌ی همین فایل‌ها را دارد؛ اسکنش یعنی گاردی که با هر
            # بیلدِ قدیمی قرمز می‌شود.
            if "dist" in p.parts:
                continue
            body = _nocomments(p.read_text(encoding="utf-8"))
            # 🪤 خطِ پیام (say/echo/printf) دستور نیست — host-setup.sh در
            # راهنمای پایانی‌اش `cp .env.example .env` را **می‌نویسد**.
            body_cmds = "\n".join(
                l for l in body.splitlines()
                if not re.match(r"\s*(say|echo|printf)\b", l))
            creates = re.findall(
                r"^[^\n]*(?:cp|sed -i|>>?)[^\n]*\.env\b(?!\.example)",
                body_cmds, re.M)
            if not creates:
                continue
            checked += 1
            with self.subTest(f=str(p.relative_to(ROOT))):
                self.assertRegex(
                    body, r"umask 0?77",
                    "%s فایلِ .env می‌سازد ولی umask نمی‌گذارد" % p.name)
                self.assertRegex(
                    body, r"chmod 0?600[^\n]*\.env",
                    "%s مودِ .env را صریح نمی‌کند" % p.name)
        # گاردی که صفر فایل را سنجیده تا ابد سبز می‌ماند و شبیهِ پوشش است
        self.assertGreater(checked, 0, "هیچ فایلی .env نمی‌سازد — الگو غلط است")

    def test_an_existing_env_is_tightened_too(self):
        """نیمه‌ای که استقرارهای **موجود** را نجات می‌دهد.

        گاردِ `[ ! -f ]` یعنی مسیرِ ساخت برای کسی که با نصابِ قدیمی
        .env ساخته اصلاً اجرا نمی‌شود؛ سفت‌کردن باید بی‌قید هم باشد.
        """
        body = _nocomments(
            (ROOT / "docker/airgap/install.sh").read_text(encoding="utf-8"))
        self.assertRegex(
            body, r'\[ -f "\$\{SELF_DIR\}/\.env" \]\s*&&\s*chmod 600',
            "سفت‌کردنِ بی‌قیدِ .env ِ موجود نیست")


class ArchivePermissionTests(_NeedsDir):
    """هر آرشیوی از /opt/wg-panel یک آرتیفکتِ رازدار است."""

    NEEDS = ("airgap",)

    def test_installer_archives_are_not_world_readable(self):
        """آرشیوی که کلِ /opt/wg-panel را دارد نباید خواندنی برای همه باشد.

        شاملِ config.json است: secret ِ نشست، توکنِ ربات، هشِ رمزها.
        بدونِ umask، tar با مودِ پیش‌فرض می‌سازد و آرشیو **پس از حذفِ
        پنل هم** در /var/backups می‌ماند. الگوی درست از قبل در
        wg-panel-backup.sh هست (chmod 600).
        """
        checked = 0
        for p in sorted((ROOT / "airgap").rglob("installer/*.sh")):
            body = _nocomments(p.read_text(encoding="utf-8"))
            if not re.search(r"tar\s+[^\n]*-c?zf", body):
                continue
            checked += 1
            with self.subTest(f=str(p.relative_to(ROOT))):
                self.assertRegex(body, r"umask 0?77",
                                 "%s آرشیو می‌سازد بدونِ umask" % p.name)
                self.assertRegex(body, r"chmod 600",
                                 "%s مودِ آرشیو را صریح نمی‌کند" % p.name)
        self.assertGreater(checked, 0, "هیچ نصابی آرشیو نمی‌سازد — الگو غلط است")

    def test_a_failed_archive_is_not_left_behind(self):
        """tar ِ شکست‌خورده آرشیوِ ناقص جا می‌گذاشت و نصب ادامه می‌داد.

        آرشیوِ ناقصی که شبیهِ بکاپ است از نبودنش بدتر است — اپراتور
        فکر می‌کند بکاپ دارد.
        """
        for rel in ("airgap/single-server/installer/uninstall.sh",
                    "airgap/single-server/installer/install.sh"):
            body = _nocomments((ROOT / rel).read_text(encoding="utf-8"))
            with self.subTest(f=rel):
                self.assertRegex(body, r"rm -f \"\$\{b(kp|dir)\}",
                                 "%s آرشیوِ ناقص را پاک نمی‌کند" % rel)

    def test_the_shared_system_backup_dir_is_not_tightened(self):
        """‏/var/backups روی دبیان ۰۷۵۵ است و بسته‌های دیگر در آن
        می‌نویسند؛ عوض‌کردنِ مودش عارضه‌ی جانبیِ یک رفعِ wg-panel روی
        نرم‌افزارِ دیگر است. زیرپوشه‌ی اختصاصی راهِ درست است.
        """
        for rel in ("airgap/single-server/installer/uninstall.sh",
                    "airgap/generic/ansible/playbooks/uninstall.yml"):
            body = _nocomments((ROOT / rel).read_text(encoding="utf-8"))
            with self.subTest(f=rel):
                self.assertNotRegex(
                    body, r"chmod 0?7[05]0 /var/backups\s*$",
                    "مودِ /var/backups ِ مشترک عوض شده")
                self.assertIn("/var/backups/wg-panel", body,
                              "زیرپوشه‌ی اختصاصی استفاده نشده")


class InstallerSyntaxTests(_NeedsDir):
    """`bash -n` کلِ پوششِ اجرایی این اسکریپت‌هاست — دستِ‌کم باید سبز باشد."""

    NEEDS = ("airgap", "publish")

    def test_all_installer_scripts_parse(self):
        rels = ["deploy/setup-deps.sh", "publish/make-public.sh"]
        for v in ("generic", "single-server"):
            d = ROOT / "airgap" / v / "installer"
            rels += [str(p.relative_to(ROOT))
                     for p in sorted(d.rglob("*.sh"))]
        for rel in rels:
            with self.subTest(f=rel):
                r = subprocess.run(["bash", "-n", str(ROOT / rel)],
                                   capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 0, "%s: %s" % (rel, r.stderr))

    def test_edited_playbooks_are_valid_yaml(self):
        try:
            import yaml
        except ImportError:
            raise unittest.SkipTest("PyYAML نیست")
        rels = ["airgap/generic/ansible/playbooks/site.yml",
                "airgap/single-server/ansible/playbooks/site.yml",
                "airgap/generic/ansible/playbooks/uninstall.yml"]
        for rel in rels:
            with self.subTest(f=rel):
                with open(ROOT / rel, encoding="utf-8") as f:
                    self.assertIsNotNone(yaml.safe_load(f))


class DockerInstallSurfaceTests(_NeedsDir):
    """خروجیِ زمانِ اجرای مسیرِ Docker باید برای غیرفارسی‌زبان خواندنی باشد.

    پلن ۰۵۶ و مرزِ عمدی‌اش: **خروجیِ زمانِ اجرا و کامنتِ `.env` برای کاربر
    است (ترجمه شود)، کامنتِ کد برای نگهدارنده است (فارسی بماند).** کاربرِ
    گیرکرده هنوز پنل را نمی‌بیند؛ تنها چیزی که دارد همین خروجی است — و
    Docker اولین راهی است که یک غریبه از گیت‌هاب امتحان می‌کند.
    """
    NEEDS = ("docker",)

    #: کاراکترهای عربی/فارسی
    FA = re.compile(r"[؀-ۿ]")
    #: یک کلمه‌ی لاتینِ واقعی — نه نامِ متغیر یا مسیر
    EN = re.compile(r"[A-Za-z]{4,}")

    def _code_lines(self, rel):
        """بدنه بدونِ خطوطِ کامنت.

        این مخزن دو بار گاردی فرستاده که کامنتِ توصیفِ تله را می‌گرفته نه
        خودِ کد را. اینجا دوچندان مهم است: فایل پر از کامنتِ فارسی است که
        **باید** فارسی بماند.
        """
        body = (ROOT / rel).read_text(encoding="utf-8")
        return [l for l in body.splitlines() if not l.lstrip().startswith("#")]

    def test_bootstrap_die_messages_are_not_persian_only(self):
        """پیامِ `die` همان چیزی است که کاربرِ گیرکرده می‌خواند."""
        bad = []
        for line in self._code_lines("docker/entrypoint.sh"):
            for mo in re.finditer(r'\bdie\s+"([^"]+)"', line):
                s = mo.group(1)
                if self.FA.search(s) and not self.EN.search(s):
                    bad.append(s[:60])
        self.assertEqual(bad, [], "پیامِ die ِ فقط‌فارسی: %s" % bad)

    def test_host_setup_and_entrypoint_output_is_not_persian_only(self):
        """هر پیامی که اسکریپت چاپ می‌کند، نه فقط پیام‌های مرگ."""
        bad = []
        for rel in ("docker/entrypoint.sh", "docker/host-setup.sh",
                    "docker/systemctl-shim.sh"):
            for line in self._code_lines(rel):
                for mo in re.finditer(r'\b(?:say|echo|printf)\s+"([^"]+)"',
                                      line):
                    s = mo.group(1)
                    if self.FA.search(s) and not self.EN.search(s):
                        bad.append("%s: %s" % (rel, s[:50]))
        self.assertEqual(bad, [], "خروجیِ فقط‌فارسی: %s" % bad)

    def test_env_example_comments_are_bilingual(self):
        """`.env` را کاربر خط‌به‌خط هنگامِ پیکربندی می‌خواند."""
        body = (ROOT / "docker" / ".env.example").read_text(encoding="utf-8")
        self.assertRegex(body, r"[A-Za-z]{4,}", "هیچ انگلیسی‌ای ندارد")
        self.assertTrue(self.FA.search(body), "فارسی حذف شده — دوزبانه بماند")

    def test_env_example_variable_names_are_untouched(self):
        """ترجمه نباید نام یا مقدارِ متغیری را عوض کند.

        نامِ عوض‌شده هر `.env` موجودی را بی‌صدا می‌شکند، و این فایل تنها
        منبعِ نخستین بوت‌استرپ است.
        """
        body = (ROOT / "docker" / ".env.example").read_text(encoding="utf-8")
        names = re.findall(r"^([A-Z][A-Z0-9_]*)=", body, re.M)
        self.assertIn("WG_SERVER_HOST", names)
        self.assertIn("WG_PANEL_ALLOW_IPS", names)
        self.assertEqual(len(names), len(set(names)), "نامِ تکراری")

    def test_code_comments_stay_persian(self):
        """مرزِ مقابل: ترجمه نباید به کامنتِ کد سرایت کند.

        کامنتِ کد برای نگهدارنده است و زبانِ مخزن فارسی است. اگر این گارد
        نبود، «ترجمهٔ بعدی» به‌راحتی کلِ فایل را می‌برد.
        """
        for rel in ("docker/entrypoint.sh", "docker/host-setup.sh"):
            body = (ROOT / rel).read_text(encoding="utf-8")
            comments = [l for l in body.splitlines()
                        if l.lstrip().startswith("#")]
            fa = sum(1 for l in comments if self.FA.search(l))
            with self.subTest(f=rel):
                self.assertGreater(fa, 5,
                                   "کامنت‌های فارسیِ %s ناپدید شده‌اند" % rel)

    def test_the_docker_guide_exists_in_both_languages(self):
        for name in ("README.md", "README.fa.md"):
            with self.subTest(f=name):
                self.assertTrue((ROOT / "docker" / name).exists(),
                                "docker/%s نیست" % name)
        en = (ROOT / "docker" / "README.md").read_text(encoding="utf-8")
        self.assertIn("README.fa.md", en, "نسخه‌ی انگلیسی به فارسی لینک ندارد")

    def test_links_to_the_docker_guide_still_resolve(self):
        """تغییرِ نامِ فایل نباید لینکِ جایی را بشکند.

        `README.fa.md` سابقه‌ی عملیاتی است و در درختِ عمومی نیست، پس
        نبودنش خرابی نیست — ولی اگر **هست**، لینکش باید کار کند.
        """
        checked = 0
        for src in ("README.md", "README.fa.md"):
            if not (ROOT / src).exists():
                continue
            checked += 1
            body = (ROOT / src).read_text(encoding="utf-8")
            for target in re.findall(r"\((docker/README[^)]*)\)", body):
                with self.subTest(src=src, target=target):
                    self.assertTrue((ROOT / target).exists(),
                                    "لینکِ شکسته در %s → %s" % (src, target))
        self.assertGreater(checked, 0, "هیچ READMEای برای بررسی نبود")


class InstallerDivergenceTests(_NeedsDir):
    """سه نصاب فورکِ هم‌اند — واگراییِ تازه نباید بی‌صدا بماند (پلنِ ۰۶۴).

    همین ممیزی **یک باگ را در سه حالتِ متفاوت** پیدا کرد: گیتِ نسخه‌ی
    پایتون فقط در یکی غلط بود، بازگردانیِ منابعِ apt فقط در یکی بود، و
    fail-open ِ یکپارچگی در هر دو airgap. امضای فورک همین است: رفع در یک
    کپی می‌نشیند و بقیه دور می‌شوند.

    **این گارد ادغام را طلب نمی‌کند.** اندازه‌گیریِ ۱۴ اوت ۲۰۲۶ نشان داد
    واگراییِ کلِ فایل‌ها ۸۸٪ تا ۷۳۶٪ است — سه برنامه‌ی متفاوت، نه سه کپیِ
    یک برنامه؛ توصیه‌ی `plans/064-design.md` «ادغام نشود» است. کاری که
    این‌جا می‌شود ارزان و مستقل از آن تصمیم است: **وضعِ امروز پین می‌شود**،
    پس هر ویرایشی در هر کپی قرمز می‌کند و نویسنده مجبور می‌شود به دو کپیِ
    دیگر هم نگاه کند — همان لحظه‌ی «رفع در یک کپی نشست» که شکستِ واقعی است.
    """
    NEEDS = ("online", "airgap")

    VARIANTS = ("online", "airgap/generic", "airgap/single-server")

    #: امضای بدنه‌ی توابعِ مشترکِ `installer/lib/common.sh`، به ترتیبِ
    #: VARIANTS. سنجشِ ۱۴ اوت ۲۰۲۶: ۱۸ تابعِ مشترک · online و generic در
    #: ۱۷تا یکسان (تنها اختلاف `ag_require_root`) · هر سه در ۹تا یکسان.
    #: **به‌روزکردنِ این جدول عمدی و دستی است**: وقتی قرمز شد، اول دو کپیِ
    #: دیگر را ببین، بعد پین را عوض کن.
    SHARED = {
        "ag_ansible_dir": ("c1ab1e419531", "c1ab1e419531",
                           "c1ab1e419531"),
        "ag_confirm": ("0f6bbcc9f60d", "0f6bbcc9f60d",
                       "f9489a19b9ab"),
        "ag_detect_os": ("f8378a17d1cf", "f8378a17d1cf",
                         "28e914c6899e"),
        "ag_dim": ("649a5770b379", "649a5770b379",
                   "649a5770b379"),
        "ag_enable_errtrap": ("e358a2c0148c", "e358a2c0148c",
                              "0bbe6aad4b8a"),
        "ag_err": ("46ae7c79dcb3", "46ae7c79dcb3",
                   "46ae7c79dcb3"),
        "ag_free_disk_mb": ("8c39d43f7038", "8c39d43f7038",
                            "09b7055c0cf7"),
        "ag_have": ("1cc3725cb9b5", "1cc3725cb9b5",
                    "1cc3725cb9b5"),
        "ag_info": ("b41ac17647fd", "b41ac17647fd",
                    "b41ac17647fd"),
        "ag_log_init": ("9c96377f2c2a", "9c96377f2c2a",
                        "233faacec4cc"),
        "ag_log_raw": ("aabbd79fb896", "aabbd79fb896",
                       "aabbd79fb896"),
        "ag_ok": ("6cfe64f52662", "6cfe64f52662",
                  "6cfe64f52662"),
        "ag_on_err": ("02135913e162", "02135913e162",
                      "a2a8a3d8624c"),
        "ag_require_root": ("0b7f7f6a7709", "d85c14fb9305",
                            "517eb6998647"),
        "ag_run": ("aa1358a134c0", "aa1358a134c0",
                   "a8c832f3f533"),
        "ag_step": ("08e4159c9d26", "08e4159c9d26",
                    "08e4159c9d26"),
        "ag_total_ram_mb": ("c95d9fe1867c", "c95d9fe1867c",
                            "7d2ff68af18a"),
        "ag_warn": ("b00adf13f730", "b00adf13f730",
                    "b00adf13f730"),
    }

    @staticmethod
    def _bodies(root, variant):
        """{نامِ تابع: هشِ بدنه} از common.sh ِ یک نسخه.

        هر دو شکل را می‌گیرد: یک‌خطیِ `f() { … }` و چندخطی تا `}` ِ ستونِ
        صفر. الگوی صرفاً چندخطی بی‌صدا ۶ از ۱۸ را می‌گرفت — و گاردی که کم
        بگیرد بدتر از نبودنش است.
        """
        import hashlib
        p = root / variant / "installer" / "lib" / "common.sh"
        if not p.exists():
            return {}
        src = p.read_text(encoding="utf-8").splitlines()
        out, i = {}, 0
        while i < len(src):
            m = re.match(r"^([a-z_][a-z0-9_]*)\(\)\s*\{(.*)$", src[i])
            if m:
                name, rest = m.group(1), m.group(2).rstrip()
                if rest.endswith("}"):
                    body = rest[:-1].strip()
                else:
                    j = i + 1
                    while j < len(src) and src[j] != "}":
                        j += 1
                    body = "\n".join(src[i + 1:j])
                    i = j
                out[name] = hashlib.sha256(body.encode()).hexdigest()[:12]
            i += 1
        return out

    def test_the_extractor_still_sees_every_shared_helper(self):
        """گاردِ خودِ گارد: اگر استخراج بشکند، بقیه بی‌صدا خالی می‌شوند."""
        for v in self.VARIANTS:
            with self.subTest(variant=v):
                self.assertGreaterEqual(len(self._bodies(ROOT, v)), 18,
                                        "استخراجِ %s کم گرفت" % v)

    def test_shared_helpers_have_not_drifted(self):
        got = {v: self._bodies(ROOT, v) for v in self.VARIANTS}
        moved = []
        for fn, want in self.SHARED.items():
            for v, w in zip(self.VARIANTS, want):
                have = got[v].get(fn)
                if have is None:
                    moved.append("%s حذف شد از %s" % (fn, v))
                elif have != w:
                    moved.append("%s در %s عوض شد (%s→%s)" % (fn, v, w, have))
        self.assertEqual(moved, [],
                         "واگراییِ تازه در نصاب‌ها — **اول دو کپیِ دیگر را "
                         "ببین**، بعد پین را به‌روز کن: %s" % moved)

    def test_no_shared_helper_vanished_from_a_variant(self):
        """تابعی که از یک نسخه حذف شود، همان دریفتِ کلاسیک است."""
        sets = [set(self._bodies(ROOT, v)) for v in self.VARIANTS]
        common = set.intersection(*sets) if sets else set()
        self.assertGreaterEqual(len(common), len(self.SHARED),
                                "مجموعه‌ی توابعِ مشترک کوچک شد")


if __name__ == "__main__":
    unittest.main()
