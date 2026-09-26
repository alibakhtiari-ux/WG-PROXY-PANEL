#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""گاردِ بسته‌ی docker/ — نصبِ compose روی اوبونتوی دیگر.

خانواده‌ی خطاهایی که می‌گیرد (بدونِ نیاز به خودِ docker):
  ۱) کهنگی/گم‌شدنِ منابع: هر مسیری که Dockerfile کپی می‌کند باید در مخزن
     موجود باشد (بسته‌ی docker عمداً «کپیِ دوم» ندارد؛ context = ریشه).
  ۲) شکستنِ نحوِ bash در اسکریپت‌های docker/ (باتریِ run-local فقط
     deploy/ansible/scripts/.claude را bash -n می‌کند، نه docker/ را).
  ۳) واگراییِ مستندات از کد: هر متغیرِ ${...} در compose باید در .env.example
     مستند باشد و برعکس.
  ۴) واگراییِ بوت‌استرپِ entrypoint از قالبِ کانونیِ config.json.j2 نقشِ
     ansible (کلیدِ جاافتاده = پنلی که با KeyError یا رفتارِ ناقص بالا می‌آید).
  ۵) مصرفِ systemctl تازه در wg_panel.py بدونِ به‌روزرسانیِ شیم — تعدادِ
     call-siteها قفل شده است.
"""
import os
import re
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKER = os.path.join(REPO, "docker")


def _read(*parts):
    with open(os.path.join(*parts), "r", encoding="utf-8") as f:
        return f.read()


class DockerBundleTests(unittest.TestCase):
    # ---------- ۱) منابعِ COPY ----------
    def test_dockerfile_copy_sources_exist(self):
        """هر مسیرِ مبدأ در دستورهای COPY باید در مخزن موجود باشد."""
        text = _read(DOCKER, "Dockerfile")
        # COPY چندخطی (با \) را یکپارچه کن، بعد مبدأها = همه به‌جز آخری
        text = re.sub(r"\\\s*\n", " ", text)
        srcs = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("COPY "):
                continue
            parts = line.split()[1:]
            self.assertGreaterEqual(len(parts), 2, "COPY ناقص: %s" % line)
            srcs.extend(parts[:-1])
        self.assertTrue(srcs, "هیچ COPYای در Dockerfile پیدا نشد")
        missing = [s for s in srcs if not os.path.exists(os.path.join(REPO, s))]
        self.assertEqual(missing, [],
                         "منبعِ COPY در مخزن نیست (context باید ریشه باشد): %s"
                         % ", ".join(missing))

    def test_dockerfile_uses_repo_root_context(self):
        """compose باید context را ریشه‌ی مخزن بگذارد، نه docker/ را."""
        yml = _read(DOCKER, "docker-compose.yml")
        self.assertIn("context: ..", yml)
        self.assertIn("dockerfile: docker/Dockerfile", yml)

    # ---------- ۲) نحوِ bash ----------
    def test_docker_scripts_bash_syntax(self):
        for fn in ("entrypoint.sh", "systemctl-shim.sh", "journalctl-shim.sh",
                   "healthcheck.sh", "host-setup.sh"):
            path = os.path.join(DOCKER, fn)
            self.assertTrue(os.path.isfile(path), "%s نیست" % fn)
            p = subprocess.run(["bash", "-n", path],
                               capture_output=True, text=True, timeout=20)
            self.assertEqual(p.returncode, 0,
                             "نحوِ bash در docker/%s: %s" % (fn, p.stderr))

    # ---------- ۳) هم‌گامیِ compose و .env.example ----------
    def test_env_example_documents_compose_vars(self):
        yml = _read(DOCKER, "docker-compose.yml")
        env = _read(DOCKER, ".env.example")
        compose_vars = set(re.findall(r"\$\{([A-Z0-9_]+)(?::-[^}]*)?\}", yml))
        documented = set(re.findall(r"^([A-Z0-9_]+)=", env, re.M))
        undocumented = compose_vars - documented
        self.assertEqual(undocumented, set(),
                         "متغیرِ compose بدونِ سند در .env.example: %s"
                         % ", ".join(sorted(undocumented)))
        unused = documented - compose_vars
        self.assertEqual(unused, set(),
                         "متغیرِ .env.example که compose مصرف نمی‌کند: %s"
                         % ", ".join(sorted(unused)))

    def test_entrypoint_env_vars_are_passed_by_compose(self):
        """هر WG_*ای که entrypoint می‌خواند باید در compose پاس شده باشد."""
        ep = _read(DOCKER, "entrypoint.sh")
        yml = _read(DOCKER, "docker-compose.yml")
        used = set(re.findall(r'\bWG_[A-Z0-9_]+', ep))
        passed = set(re.findall(r'^\s+(WG_[A-Z0-9_]+):', yml, re.M))
        missing = used - passed
        self.assertEqual(missing, set(),
                         "entrypoint این متغیرها را می‌خواند ولی compose پاسشان "
                         "نمی‌دهد: %s" % ", ".join(sorted(missing)))

    # ---------- ۴) هم‌گامی با config.json.j2 نقش ----------
    def test_entrypoint_config_covers_role_template_keys(self):
        # نقشِ ansible در شاخه‌ی public نیست (بسته‌های نصب هنوز عمومی‌سازی
        # نشده‌اند) — آنجا مرجعی برای مقایسه وجود ندارد، پس skip.
        tpl = os.path.join(REPO, "ansible", "roles", "wg-panel", "templates",
                           "config.json.j2")
        if not os.path.isfile(tpl):
            self.skipTest("نقشِ ansible نیست — مخزنِ عمومی")
        j2 = _read(REPO, "ansible", "roles", "wg-panel", "templates",
                   "config.json.j2")
        ep = _read(DOCKER, "entrypoint.sh")
        j2_keys = set(re.findall(r'^\s*"([a-z_]+)":', j2, re.M))
        ep_keys = set(re.findall(r'"([a-z_]+)":', ep))
        ep_keys |= set(re.findall(r'cfg\["([a-z_]+)"\]', ep))
        missing = j2_keys - ep_keys
        self.assertEqual(missing, set(),
                         "کلیدِ config.json.j2 که بوت‌استرپِ docker نمی‌سازد "
                         "(واگرایی از نقشِ کانونی): %s" % ", ".join(sorted(missing)))

    # ---------- ۵) قفلِ call-siteهای systemctl ----------
    def test_panel_systemctl_call_sites_locked_to_shim(self):
        src = _read(REPO, "wg_panel.py")
        n = len(re.findall(r'"systemctl"', src))
        self.assertEqual(
            n, 10,
            "تعدادِ call-siteهای systemctl در wg_panel.py عوض شده (%d≠10). "
            "اول docker/systemctl-shim.sh را با مصرفِ تازه هم‌گام کن، بعد این "
            "عدد را به‌روز کن (قاعده‌ی گاردِ خانوادگی)." % n)

    def test_shim_covers_known_verbs(self):
        shim = _read(DOCKER, "systemctl-shim.sh")
        for verb in ("is-active", "is-enabled", "start", "stop", "restart",
                     "show", "daemon-reload"):
            self.assertIn(verb, shim, "شیم فعلِ %s را ندارد" % verb)

    # ---------- ۶) قراردادِ «show» — ستون‌های صفحه‌ی بکاپ ----------
    def test_shim_show_reports_the_props_the_panel_reads(self):
        """پنل غیبتِ property را «هرگز اجرا نشده/ناموفق» تفسیر می‌کند، پس
        خروجیِ خالیِ show یک بکاپِ موفق را قرمز نشان می‌داد. هر propertyای که
        wg_panel.py از یونیت‌های بکاپ می‌خواند باید در شیم تولید شود."""
        shim = _read(DOCKER, "systemctl-shim.sh")
        for prop in ("ExecMainExitTimestamp", "ExecMainStatus", "Result",
                     "NextElapseUSecRealtime"):
            self.assertIn(prop, shim,
                          "شیم «%s» را برنمی‌گرداند ⇒ صفحه‌ی بکاپ همان را "
                          "«اجرا نشده/ناموفق» نشان می‌دهد" % prop)
        # قالبِ زمان باید همان چیزی باشد که _sysd_ts پارس می‌کند، وگرنه
        # ستون خالی می‌مانَد بدونِ هیچ خطایی.
        self.assertIn("%a %Y-%m-%d %H:%M:%S %z", shim,
                      "قالبِ زمانِ شیم با _sysd_ts در wg_panel.py نمی‌خواند")
        self.assertIn("%a %Y-%m-%d %H:%M:%S %z", _read(REPO, "wg_panel.py"),
                      "قالبِ _sysd_ts در پنل عوض شده — شیم را هم‌گام کن")

    def test_shim_state_dir_is_on_a_persisted_volume(self):
        """stateِ یونیت‌ها اگر در /var/log بنشیند، هر بازآفرینیِ کانتینر
        «آخرین بکاپ» را پاک می‌کند. باید زیرِ مسیری باشد که compose mount
        می‌کند."""
        yml = _read(DOCKER, "docker-compose.yml")
        for fn in ("systemctl-shim.sh", "wg-panel-cron.py"):
            text = _read(DOCKER, fn)
            self.assertIn("/opt/wg-panel/units", text,
                          "%s باید state را زیرِ /opt/wg-panel/units بگذارد" % fn)
        self.assertIn(":/opt/wg-panel", yml,
                      "/opt/wg-panel باید والیوم باشد وگرنه state ماندگار نیست")

    # ---------- ۷) گاردِ خانوادگی: تایمرِ نقش بدونِ جانشین در کانتینر ----------
    # تایمرهایی که آگاهانه در نسخه‌ی Docker نیستند — با دلیل، تا «فراموش شد»
    # از «تصمیم گرفته شد» قابلِ تفکیک باشد. هر تایمرِ *تازه‌ای* در نقش که در
    # این فهرست و در زمان‌بند نباشد، این تست را قرمز می‌کند.
    TIMERS_INTENTIONALLY_ABSENT = {
        "ecmp-guard": "توپولوژیِ ECMP دو تونلِ مادرِ myserver است، نه نصبِ تک‌سروری",
        "endpoint-route-check": "قاعده‌ی مسیرِ endpoint مخصوصِ زنجیره‌ی تونلِ myserver",
        "tunnel-guard": "نگهبانِ تونلِ مادر awg1 — در نصبِ تک‌تونلی موضوعی ندارد",
        "warp-autodetect": "زنجیره‌ی WARP در ایمیج نیست",
        "warp-gemini": "زنجیره‌ی WARP در ایمیج نیست",
        "myserver-full-backup": "بکاپِ یک میزبانِ کامل؛ کانتینر چنین میزبانی نیست",
        "wg-panel-verify-backup": (
            "راستی‌آزمای موجود فقط MEGA-محور است و قاعده‌ی «هیچ بکاپی روی سرور "
            "نماند» را اعمال می‌کند — عکسِ طرحِ این نصب که بکاپ را در والیوم "
            "نگه می‌دارد؛ اجرایش هر هفته دو هشدارِ کاذب می‌داد"),
    }

    def test_every_role_timer_is_scheduled_or_explicitly_excluded(self):
        """خانواده‌ی خطا: یونیتی که روی نصبِ systemd با تایمر اجرا می‌شود و در
        کانتینر هیچ‌چیز آن را نمی‌زند ⇒ قابلیتی که بی‌هیچ خطایی هرگز اجرا
        نمی‌شود. (بکاپِ خودکار دقیقاً همین بود.)"""
        files_dir = os.path.join(REPO, "ansible", "roles", "wg-panel", "files")
        if not os.path.isdir(files_dir):
            self.skipTest("نقشِ ansible نیست — مخزنِ عمومی")
        timers = sorted(fn[:-len(".timer")] for fn in os.listdir(files_dir)
                        if fn.endswith(".timer"))
        self.assertTrue(timers, "هیچ تایمری در نقش پیدا نشد — مسیر عوض شده؟")
        cron = _read(DOCKER, "wg-panel-cron.py")
        unscheduled = [t for t in timers
                       if t not in cron
                       and t not in self.TIMERS_INTENTIONALLY_ABSENT]
        self.assertEqual(
            unscheduled, [],
            "این تایمر(ها) در نقش هست ولی در کانتینر نه زمان‌بندی شده‌اند و نه "
            "در TIMERS_INTENTIONALLY_ABSENT با دلیل مستثنا: %s"
            % ", ".join(unscheduled))

    def test_scheduler_is_actually_started_by_the_entrypoint(self):
        """اسکریپتِ زمان‌بند اگر اجرا نشود، دقیقاً همان‌قدر بی‌اثر است که
        نبودنش — و سبزیِ تست‌های دیگر پنهانش می‌کند."""
        ep = _read(DOCKER, "entrypoint.sh")
        self.assertRegex(ep, r"wg-panel-cron\s*&",
                         "entrypoint زمان‌بند را در پس‌زمینه اجرا نمی‌کند")
        self.assertLess(ep.index("wg-panel-cron"), ep.index("exec python3"),
                        "زمان‌بند باید پیش از exec ِ پنل آغاز شود، وگرنه "
                        "هرگز اجرا نمی‌شود")
        dockerfile = _read(DOCKER, "Dockerfile")
        self.assertIn("docker/wg-panel-cron.py", dockerfile,
                      "زمان‌بند در ایمیج کپی نشده است")

    def test_scheduler_python_syntax(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run(
                ["python3", "-c",
                 "import py_compile,sys; py_compile.compile(sys.argv[1], "
                 "cfile=sys.argv[2], doraise=True)",
                 os.path.join(DOCKER, "wg-panel-cron.py"),
                 os.path.join(tmp, "cron.pyc")],
                capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0,
                         "نحوِ پایتونِ wg-panel-cron.py: %s" % p.stderr)

    # ---------- سلامتِ ترکیبِ compose ----------
    def test_compose_hardening_and_persistence(self):
        yml = _read(DOCKER, "docker-compose.yml")
        for needle, why in (
            ("NET_ADMIN", "بدونِ NET_ADMIN هیچ wg/iptables ای کار نمی‌کند"),
            ("/dev/net/tun", "بدونِ tun هیچ تونلِ userspace ای بالا نمی‌آید"),
            ("net.ipv4.ip_forward=1", "بدونِ فوروارد، کلاینت اینترنت ندارد"),
            ("init: true", "بدونِ init، پروسه‌های دیمن‌شده زامبی می‌شوند"),
            ("restart: unless-stopped", "بدونِ restart، کرشِ پنل = قطعی"),
            ("./data/panel:/opt/wg-panel", "داده‌ی پنل باید ماندگار باشد"),
            ("./data/wireguard:/etc/wireguard", "کلیدها باید ماندگار باشند"),
            ("healthcheck", "بدونِ healthcheck خرابی بی‌صداست"),
        ):
            self.assertIn(needle, yml, "%s — «%s» در compose نیست" % (why, needle))
        self.assertIsNone(re.search(r"^\s*privileged\s*:", yml, re.M),
                          "privileged ممنوع — حداقلِ لازم NET_ADMIN است")

    def test_gitignore_covers_docker_secrets(self):
        gi = _read(REPO, ".gitignore")
        for entry in ("docker/.env", "docker/data/", "docker/secrets/"):
            self.assertIn(entry, gi,
                          "%s باید در .gitignore باشد (راز/داده، نه سورس)" % entry)


if __name__ == "__main__":
    unittest.main()
