#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""گاردِ بسته‌ی آفلاینِ Docker ‏(docker/airgap/) — بدونِ نیاز به خودِ docker.

خانواده‌ی خطاها:
  ۱) واگراییِ transform از compose کانونی (composeِ خرابِ بی‌صدا داخلِ بسته)
  ۲) نشتِ مستندات/اسکیل/سورسِ myserver به داخلِ بسته‌ای که «تحویل‌دادنی» است
  ۳) شکستنِ نحوِ bash اسکریپت‌های بیلد/نصب/verify
  ۴) حذفِ تصادفیِ گاردهای حیاتیِ نصاب (checksum، ایزوله‌سازیِ apt، معماری)
"""
import importlib.util
import os
import re
import subprocess
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AIRGAP = os.path.join(REPO, "docker", "airgap")


def _read(*parts):
    with open(os.path.join(*parts), "r", encoding="utf-8") as f:
        return f.read()


def _load_transform():
    spec = importlib.util.spec_from_file_location(
        "transform_compose", os.path.join(AIRGAP, "transform-compose.py"))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TransformComposeTests(unittest.TestCase):
    """اجرای واقعیِ transform روی compose کانونی — واگرایی پیش از بیلد بمیرد."""

    def setUp(self):
        self.mod = _load_transform()
        self.src = _read(REPO, "docker", "docker-compose.yml")

    def test_transform_on_canonical_compose(self):
        out = self.mod.transform(self.src, "wg-panel:0123456789ab")
        self.assertIsNone(re.search(r"^\s*build\s*:", out, re.M),
                          "بعد از تبدیل نباید build: بماند")
        self.assertIn("image: wg-panel:0123456789ab", out)
        self.assertNotIn("wg-panel:local", out)
        self.assertNotIn("--build", out,
                         "بنر/متنِ بسته نباید به build اشاره کند")
        # هیچ خطِ دیگری نباید گم شود: ports/volumes/environment/healthcheck
        for needle in ("ports:", "volumes:", "environment:", "healthcheck:",
                       "cap_add:", "/dev/net/tun", "init: true",
                       "restart: unless-stopped", "networks:"):
            self.assertIn(needle, out, "خطِ %s در تبدیل گم شد" % needle)
        # شمارشِ خطوطِ غیرکامنت: فقط ۳ خطِ build و ۰ خطِ دیگر کم شده باشد
        strip = lambda t: [l for l in t.splitlines()
                           if l.strip() and not l.strip().startswith("#")]
        self.assertEqual(len(strip(self.src)) - len(strip(out)), 3,
                         "غیر از ۳ خطِ بلوکِ build نباید چیزی حذف شود")

    def test_transform_rejects_bad_tag(self):
        for bad in ("wg-panel:local", "wg-panel:v1", "evil:0123456789ab"):
            with self.assertRaises(SystemExit, msg=bad):
                self.mod.transform(self.src, bad)

    def test_transform_dies_on_unexpected_structure(self):
        with self.assertRaises(SystemExit):
            self.mod.transform("name: x\nservices: {}\n", "wg-panel:0123456789ab")


class AirgapBundleTests(unittest.TestCase):
    def test_scripts_bash_syntax(self):
        for fn in ("build-offline-bundle.sh", "install.sh",
                   "verify-checksums.sh"):
            path = os.path.join(AIRGAP, fn)
            self.assertTrue(os.path.isfile(path), "%s نیست" % fn)
            p = subprocess.run(["bash", "-n", path],
                               capture_output=True, text=True, timeout=20)
            self.assertEqual(p.returncode, 0,
                             "نحوِ bash در %s: %s" % (fn, p.stderr))

    def test_whitelist_sources_exist_and_clean(self):
        entries = []
        for line in _read(AIRGAP, "bundle-files.txt").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            src, _, dest = line.partition("|")
            self.assertTrue(src and dest, "خطِ بدقواره در bundle-files.txt: %r" % line)
            self.assertTrue(os.path.isfile(os.path.join(REPO, src)),
                            "منبعِ فهرستِ سفید نیست: %s" % src)
            entries.append((src, dest))
        dests = {d for _, d in entries}
        for must in ("install.sh", "verify-checksums.sh",
                     "README-OFFLINE.md", ".env.example"):
            self.assertIn(must, dests, "%s در فهرستِ سفید نیست" % must)
        # سدِ نشت: هیچ سند/اسکیل/سورسِ پنل واردِ بسته نشود
        for src, _ in entries:
            self.assertIsNone(
                re.search(r"\.html$|^\.claude/|CLAUDE\.md|^wg_panel\.py$|"
                          r"^myserver-|^scripts/|^online/|^airgap/", src),
                "منبعِ ممنوع در فهرستِ سفید: %s" % src)

    def test_build_script_guards(self):
        b = _read(AIRGAP, "build-offline-bundle.sh")
        self.assertIn("bundle-files.txt", b, "بیلد باید از فهرستِ سفید بخواند")
        self.assertIn("unittest", b, "گیتِ تست از بیلد حذف شده")
        self.assertIn("tests.test_docker_airgap", b,
                      "گیتِ تست باید خودِ تست‌های airgap را هم بزند")
        self.assertIn("*.html", b, "گاردِ نشتِ find از بیلد حذف شده")
        self.assertIn("transform-compose.py", b)
        self.assertIn("--platform", b, "بیلدِ ایمیج باید معماریِ هدف را صریح بدهد")
        self.assertIn("{{.Architecture}}", b,
                      "سنجشِ معماریِ واقعیِ ایمیجِ ساخته‌شده حذف شده")

    def test_install_script_guards(self):
        i = _read(AIRGAP, "install.sh")
        self.assertLess(i.find("verify-checksums.sh"), i.find("docker load"),
                        "نصاب باید پیش از استفاده از بسته، checksum را بسنجد")
        self.assertIn("Dir::Etc::sourcelist", i,
                      "ایزوله‌سازیِ apt حذف شده — روی میزبانِ آفلاین apt-get update "
                      "با منابعِ اینترنتی می‌شکند")
        self.assertIn("trusted=yes", i)
        self.assertIn("dpkg --print-architecture", i,
                      "سنجشِ سازگاریِ معماریِ بسته با میزبان حذف شده")
        self.assertIn("modules-load.d", i, "ماندگارسازیِ ماژولِ wireguard حذف شده")

    def test_gitignore_covers_dist(self):
        self.assertIn("docker/airgap/dist/", _read(REPO, ".gitignore"),
                      "خروجیِ بیلد (dist/) نباید واردِ گیت شود")

    def test_offline_readme_is_standalone(self):
        r = _read(AIRGAP, "README-OFFLINE.md")
        self.assertIn("install.sh", r)
        for forbidden in ("myserver", ".claude", "CLAUDE.md", "ansible/"):
            self.assertNotIn(forbidden, r,
                             "README آفلاین باید خودکفا باشد و به مخزن/سرورِ "
                             "myserver اشاره نکند: %r" % forbidden)


class BuildContextTests(unittest.TestCase):
    """گاردِ contextِ بیلد — نقطهٔ کورِ گاردهای بالا.

    گاردهای دیگرِ این فایل «فهرستِ سفیدِ بسته» و «README آفلاین» را می‌پایند.
    هیچ‌کدام به contextِ بیلد نگاه نمی‌کرد، در حالی که
    docker-compose.yml با `context: ..` کلِ مخزن را به daemon می‌فرستد.
    تا ۱۳ اوت ۲۰۲۶ هیچ .dockerignore وجود نداشت: ۱٫۲GB شاملِ .git ‏(۷۹MB)،
    ‏.claude، و خودِ docker/airgap/dist ‏(۷۷۷MB، بازگشتی).

    ایمیج آن را نگه نمی‌داشت چون همهٔ COPYها باریک‌اند — ولی این تضمینِ
    ساختاری نبود، فقط بخت بود. یک `COPY . .` کافی بود تا کلِ لایهٔ عملیاتی
    داخلِ ایمیجِ «تحویل‌دادنی» برود.
    """

    def _copy_sources(self):
        """مسیرهای منبعِ هر COPY/ADD در Dockerfile (مقصد کنار گذاشته می‌شود)."""
        text = _read(REPO, "docker", "Dockerfile")
        text = re.sub(r"\\\n", " ", text)          # ادامه‌ی خط
        out = []
        for line in text.split("\n"):
            m = re.match(r"\s*(?:COPY|ADD)\s+(.*)", line, re.I)
            if not m:
                continue
            parts = [p for p in m.group(1).split() if not p.startswith("--")]
            out.extend(parts[:-1])                 # آخری مقصد است
        return out

    def _ignore_patterns(self):
        return [ln.strip() for ln in _read(REPO, ".dockerignore").split("\n")
                if ln.strip() and not ln.strip().startswith("#")]

    def test_dockerignore_exists_and_blocks_operational_layer(self):
        pats = set(p.rstrip("/") for p in self._ignore_patterns())
        for must in (".git", ".claude", "CLAUDE.md", "CHANGELOG.md",
                     "README.fa.md", "*.html", "scripts", "config.json",
                     "docker/airgap/dist", "docker/.env", "docker/secrets"):
            self.assertIn(must.rstrip("/"), pats,
                          "‏.dockerignore لایهٔ عملیاتی را نمی‌بندد: %s" % must)

    def test_dockerfile_has_no_broad_copy(self):
        """`COPY . .` همهٔ گاردهای دیگر را دور می‌زند."""
        for src in self._copy_sources():
            self.assertNotIn(src, (".", "./", "*", "./*"),
                             "COPYِ فراخ در Dockerfile: %r — بارِ ایمیج باید "
                             "فایل‌به‌فایل و صریح باشد" % src)

    def test_dockerignore_keeps_every_copy_source(self):
        """جهتِ خطرناکِ دیگر: بستنِ بیش‌ازحد ⇒ بیلد می‌شکند.

        سنجش عمداً محافظه‌کار است — فقط الگوهای دقیق و پوشه‌های والد.
        """
        pats = [p.rstrip("/") for p in self._ignore_patterns()
                if "*" not in p and not p.startswith("!")]
        for src in self._copy_sources():
            src = src.lstrip("./")
            for pat in pats:
                self.assertFalse(
                    src == pat or src.startswith(pat + "/"),
                    "‏.dockerignore منبعِ COPY را حذف می‌کند: %s ⟸ %s"
                    % (src, pat))

    def test_image_payload_carries_no_deployment_hostname(self):
        """آنچه *داخلِ ایمیج* می‌رود هم نباید نامِ یک استقرارِ خاص را ببرد.

        این دقیقاً همان چیزی است که از کنارِ گاردهای قبلی رد شد: فهرستِ
        سفید `wg_panel.py` را از *بسته* منع می‌کند، ولی همان فایل قانوناً
        داخلِ *ایمیج* کپی می‌شود و کسی محتوایش را نمی‌سنجید. ایمیجِ ساختهٔ
        ۱۱ اوت ۲۰۲۶ نامِ میزبانِ سرور را در صفحهٔ ورودِ خودش داشت.

        🪤 الگو عمداً از فایلِ بیرونی می‌آید، نه literal ِ همین‌جا. نسخهٔ
        نخست الگو را داخلِ خودش داشت و ژنراتورِ شاخهٔ public همین فایل را
        به‌عنوان نشت علامت زد — گاردِ «نباید X باشد» خودش X را ثبت می‌کند.
        در مخزنِ عمومی آن فایل وجود ندارد و سنجه skip می‌شود، که درست است:
        آنجا چیزی برای نشت نیست.
        """
        ident = os.path.join(REPO, "publish", "private-identifiers.txt")
        if not os.path.isfile(ident):
            self.skipTest("فهرستِ شناسه‌های خصوصی نیست — مخزنِ عمومی")
        with open(ident, encoding="utf-8") as fh:
            pats = [ln.strip() for ln in fh
                    if ln.strip() and not ln.strip().startswith("#")]
        self.assertTrue(pats, "فهرستِ شناسه‌ها خالی است")
        HOST = re.compile("|".join(pats))
        for src in self._copy_sources():
            path = os.path.join(REPO, src)
            if not os.path.isfile(path) or src.endswith(".gz"):
                continue
            with open(path, encoding="utf-8", errors="ignore") as fh:
                body = fh.read()
            hit = HOST.search(body)
            self.assertIsNone(
                hit, "نامِ میزبانِ استقرار در بارِ ایمیج: %s ⟸ %r"
                     % (src, hit.group(0) if hit else ""))


class ImagePayloadExtraTests(unittest.TestCase):
    """دو سنجه‌ی افزوده روی بارِ ایمیج — بدونِ تکرارِ کارِ گاردِ موجود.

    نامِ میزبان/شناسه‌های خصوصی را از قبل
    `BuildContextTests.test_image_payload_carries_no_deployment_hostname`
    می‌سنجد و الگوهایش را از `publish/private-identifiers.txt` می‌گیرد.
    نسخه‌ی نخستِ همین کلاس آن کار را **دوباره** کرد و الگوها را literal
    نوشت — و ژنراتورِ شاخه‌ی public همین فایل را نشت علامت زد، دقیقاً
    همان چیزی که داک‌استرینگِ آن تست از پیش هشدار داده بود. اینجا فقط
    چیزی می‌ماند که آن گارد پوشش نمی‌دهد.
    """

    def _copy_sources(self):
        out = []
        for line in _read(REPO, "docker", "Dockerfile").split("\n"):
            m = re.match(r"\s*(?:COPY|ADD)\s+(.*)", line, re.I)
            if not m:
                continue
            parts = [p for p in m.group(1).split() if not p.startswith("--")]
            out.extend(parts[:-1])
        return out

    def test_no_private_key_material_is_copied_into_the_image(self):
        """ایمیج توزیع‌شدنی است؛ کلیدِ خصوصی در آن یعنی کلیدِ مشترکِ همه.

        بسته‌ی ssl-cert (وابستگیِ squid) هنگامِ بیلد جفتِ snakeoil را
        می‌سازد و در لایه می‌پزد — Dockerfile حذفش می‌کند. این سنجه
        سمتِ COPY را می‌پاید تا کسی کلیدی را از مخزن داخل نبرد.
        """
        for src in self._copy_sources():
            self.assertFalse(
                src.endswith((".key", ".pem", "_rsa", "_ed25519")),
                "مادّه‌ی کلیدِ خصوصی در COPY: %s" % src)
        dockerfile = _read(REPO, "docker", "Dockerfile")
        self.assertIn("ssl-cert-snakeoil.key", dockerfile,
                      "حذفِ کلیدِ snakeoil از Dockerfile برداشته شده — "
                      "ایمیج دوباره کلیدِ خصوصیِ مشترک حمل می‌کند.")

    def test_the_compose_defaults_do_not_use_this_deployments_subnet(self):
        """پیش‌فرضِ ساب‌نت بارِ ایمیج نیست ولی همان‌جا دیده می‌شود.

        رنجِ RFC1918 راز نیست (فیکسچرهای منتشرشده هم دارندش)، پس در
        فهرستِ شناسه‌های خصوصی جا ندارد — ولی نصبِ تازه نباید پیش‌فرضِ
        یک استقرارِ دیگر را بگیرد.
        """
        for rel in ("docker/docker-compose.yml", "docker/.env.example",
                    "docker/entrypoint.sh"):
            body = _read(REPO, *rel.split("/"))
            self.assertNotRegex(
                body, r"192\.168\.(?:188|69|64)\.\d+",
                "‏%s پیش‌فرضِ ساب‌نتِ یک استقرارِ دیگر را دارد." % rel)


if __name__ == "__main__":
    unittest.main()
