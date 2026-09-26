# -*- coding: utf-8 -*-
"""گاردِ خانوادگیِ تشخیصِ خروجیِ سوخته (۱۵ اوت ۲۰۲۶).

خانواده‌ی باگی که این‌ها می‌گیرند: «سنجه‌ای که یا هرگز آتش نمی‌گیرد یا
بی‌جا آتش می‌گیرد». هر دو سرِ طیف خطرناک‌اند — سنجه‌ی همیشه‌سبز اعتمادِ
کاذب می‌دهد (همان چهار سنجه‌ی مستقیمی که آزموده شد و همه یکسان جواب
دادند)، و سنجه‌ی پرنویز همان الگوی ecmp-guard است که ۱۳ بار در یک روز
بی‌جا آتش گرفت.
"""
import importlib.util
import json
import os
import tempfile
import unittest

_PATH = os.path.join(os.path.dirname(__file__), "..", "deploy",
                     "wgpl-egress-health.py")
# توپولوژی‌محور است و مثلِ warp-gemini/ecmp-guard در درختِ عمومی نیست
# (publish/filelist.txt). بدونِ این گارد، انتشارِ عمومی قرمز می‌شود.
if not os.path.exists(_PATH):
    raise unittest.SkipTest("wgpl-egress-health.py در این درخت نیست — مخزنِ عمومی")

_spec = importlib.util.spec_from_file_location("wgpl_egress_health", _PATH)
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)


def _rows(spec):
    """spec: {mark: (bytes, conns)} → قالبِ ai_by_mark"""
    return [[m, b, c, 10] for m, (b, c) in spec.items()]


class EgressHealthTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        h.STATS = os.path.join(self.dir, "stats.json")
        h.STATE = os.path.join(self.dir, "state.json")
        h.LOG = os.path.join(self.dir, "actions.log")
        h.MIN_CONNS = 40
        h.RATIO = 0.30
        h.STREAK = 3
        h.PROBE_ON = False                      # مرحله‌ی ۲ جداگانه تست می‌شود
        h.YTM_ON = False                        # مرحله‌ی ۳ هم همین‌طور
        h.BURNED = os.path.join(self.dir, "burned.list")
        h.YTM_LIST = os.path.join(self.dir, "ytm.list")

    def _write_stats(self, spec):
        with open(h.STATS, "w", encoding="utf-8") as f:
            json.dump({"ai_by_mark": _rows(spec)}, f)

    def _run(self):
        return h.main()

    def test_first_run_never_alerts(self):
        """اجرای نخست مبنا ندارد ⇒ هیچ قضاوتی. جلوگیری از هشدارِ راه‌اندازی."""
        self._write_stats({"0x81": (100, 100), "0x82": (5000, 100),
                           "0x83": (5000, 100)})
        self.assertEqual(self._run(), 0)

    def test_missing_or_empty_stats_is_silent(self):
        """splitterِ قدیمی یا استخرِ خاموش ⇒ سکوت، نه خطا."""
        self.assertEqual(self._run(), 0)          # فایل اصلاً نیست
        with open(h.STATS, "w", encoding="utf-8") as f:
            json.dump({"ai_by_mark": []}, f)
        self.assertEqual(self._run(), 0)

    def test_healthy_fleet_never_alerts(self):
        """همه‌ی خروجی‌ها مشابه ⇒ هیچ هشداری، هرچند بار تکرار شود."""
        base = {"0x81": (0, 0), "0x82": (0, 0), "0x83": (0, 0)}
        self._write_stats(base)
        self._run()
        for step in range(1, 8):
            self._write_stats({m: (5000 * step, 100 * step) for m in base})
            self.assertEqual(self._run(), 0)

    def test_degraded_tunnel_alerts_only_after_streak(self):
        """خروجیِ سوخته باید گرفته شود — ولی نه با یک پنجره‌ی تنها."""
        self._write_stats({"0x81": (0, 0), "0x82": (0, 0), "0x83": (0, 0)})
        self._run()
        codes = []
        for step in range(1, 5):
            self._write_stats({
                "0x81": (200 * step, 100 * step),     # سوخته: بایتِ ناچیز
                "0x82": (5000 * step, 100 * step),
                "0x83": (5000 * step, 100 * step)})
            codes.append(self._run())
        self.assertEqual(codes[:2], [0, 0], "نباید زودتر از streak آتش بگیرد")
        self.assertEqual(codes[2], 2, "بعد از سه پنجره باید هشدار بدهد")

    def test_recovery_resets_streak(self):
        """بازگشتِ سلامت باید streak را صفر کند، وگرنه هشدار می‌چسبد."""
        self._write_stats({"0x81": (0, 0), "0x82": (0, 0), "0x83": (0, 0)})
        self._run()
        b = {"0x81": 0, "0x82": 0, "0x83": 0}
        c = dict(b)
        for _ in range(2):                        # دو پنجره‌ی بد
            b["0x81"] += 200; b["0x82"] += 5000; b["0x83"] += 5000
            for m in c: c[m] += 100
            self._write_stats({m: (b[m], c[m]) for m in b})
            self._run()
        for _ in range(3):                        # سه پنجره‌ی سالم
            for m in b: b[m] += 5000
            for m in c: c[m] += 100
            self._write_stats({m: (b[m], c[m]) for m in b})
            self.assertEqual(self._run(), 0)

    def test_low_sample_is_not_judged(self):
        """زیرِ کفِ نمونه هیچ قضاوتی — خروجیِ کم‌مصرف نباید متهم شود."""
        self._write_stats({"0x81": (0, 0), "0x82": (0, 0), "0x83": (0, 0)})
        self._run()
        for step in range(1, 6):
            self._write_stats({
                "0x81": (10 * step, 5 * step),        # فقط ۵ اتصال در پنجره
                "0x82": (5000 * step, 5 * step),
                "0x83": (5000 * step, 5 * step)})
            self.assertEqual(self._run(), 0)

    def test_splitter_restart_does_not_fake_an_alert(self):
        """شمارنده‌ی عقب‌رفته = ری‌استارت، نه خرابی.

        بدونِ این، هر ری‌استارتِ splitter یک دلتای منفیِ عظیم می‌سازد و
        نگهبان بی‌جا آتش می‌گیرد — همان تله‌ای که گیج‌های زنده‌ی ۰۴۹ را
        یک بار به اشتباه انداخت.
        """
        self._write_stats({"0x81": (50000, 1000), "0x82": (50000, 1000),
                           "0x83": (50000, 1000)})
        self._run()
        self._write_stats({"0x81": (100, 50), "0x82": (5000, 50),
                           "0x83": (5000, 50)})
        self.assertEqual(self._run(), 0)
        with open(h.STATE, encoding="utf-8") as f:
            state = json.load(f)
        self.assertEqual(state["streaks"], {}, "مبنا باید از نو ساخته شود")

    def test_two_peers_is_not_enough_to_judge(self):
        """با دو خروجی «میانه‌ی همتایان» یعنی مقایسه با یک نفر ⇒ قضاوت نکن."""
        self._write_stats({"0x81": (0, 0), "0x82": (0, 0)})
        self._run()
        for step in range(1, 6):
            self._write_stats({"0x81": (100 * step, 100 * step),
                               "0x82": (9000 * step, 100 * step)})
            self.assertEqual(self._run(), 0)



class ProbeStageTests(unittest.TestCase):
    """گاردِ خانوادگیِ خانواده‌ی دوم (۱۱ سپتامبر ۲۰۲۶): «خروجی‌ای که هندشیک و
    لینکش سالم است ولی گوگل آن را با ۴۰۳ رد می‌کند یا داده از آن نمی‌گذرد،
    و هیچ نگهبانی نمی‌بیندش». wgpl5 (۴۰۳ ِ صریح) و wgpl6 (بلک‌هول با هندشیکِ
    تازه) هر دو «سالم» شمرده می‌شدند و یک‌سومِ کاربران بی‌AI مانده بودند.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        h.STATS = os.path.join(self.dir, "stats.json")   # نیست ⇒ مرحله‌ی ۱ ساکت
        h.STATE = os.path.join(self.dir, "state.json")
        h.LOG = os.path.join(self.dir, "actions.log")
        h.BURNED = os.path.join(self.dir, "burned.list")
        h.YTM_LIST = os.path.join(self.dir, "ytm.list")
        h.NOTIFY = os.path.join(self.dir, "no-such-notify")
        h.PROBE_ON = True
        h.YTM_ON = False                        # این کلاس مرحله‌ی ۲ را می‌سنجد
        h.TUNNELS = ["wgpl", "wgpl5", "wgpl6"]
        h.BAD_STREAK = 3
        h.GOOD_STREAK = 4
        h.link_exists = lambda dev: True
        self.http = {"wgpl": "302", "wgpl5": "302", "wgpl6": "302"}
        self.icmp = {"wgpl": True, "wgpl5": True, "wgpl6": True}
        h.probe_http = lambda dev: self.http[dev]
        h.probe_icmp = lambda dev: self.icmp[dev]

    def _burned(self):
        return h.read_burned()

    def test_healthy_fleet_writes_empty_list_and_never_burns(self):
        """استخرِ سالم: فایل ساخته می‌شود (تا failover مطمئن باشد نگهبان زنده
        است) ولی خالی می‌ماند، هر چند بار تکرار شود."""
        for _ in range(10):
            self.assertEqual(h.main(), 0)
            self.assertTrue(os.path.exists(h.BURNED))
            self.assertEqual(self._burned(), [])

    def test_hard_403_burns_only_after_streak(self):
        """۴۰۳ ِ صریح: نه با یک پروب (نویز)، ولی قطعاً پس از BAD_STREAK."""
        self.http["wgpl5"] = "403"
        codes = [h.main() for _ in range(3)]
        self.assertEqual(codes[:2], [0, 0], "نباید زودتر از streak بسوزاند")
        self.assertEqual(codes[2], 2, "پروبِ سوم باید یافته گزارش کند")
        self.assertEqual(self._burned(), ["wgpl5"])
        # چهارمین اجرا: همچنان سوخته ولی «تغییری نیست» ⇒ ۰، بدونِ هشدارِ تکراری
        self.assertEqual(h.main(), 0)
        self.assertEqual(self._burned(), ["wgpl5"])

    def test_blackhole_needs_both_http_and_icmp_to_fail(self):
        """000 به‌تنهایی حکم نیست (گوگل کند؟)؛ 000 + ping ِ شکست‌خورده = بلک‌هول."""
        self.http["wgpl6"] = "000"
        for _ in range(5):                        # ping سالم ⇒ بی‌حکم
            h.main()
        self.assertEqual(self._burned(), [])
        self.icmp["wgpl6"] = False
        for _ in range(3):
            h.main()
        self.assertEqual(self._burned(), ["wgpl6"])

    def test_neutral_code_does_not_touch_streaks(self):
        """کدِ ناآشنا (۵۰۳) نه streak ِ بد را می‌شکند نه سالم می‌سازد —
        وگرنه یک ۵۰۳ ِ گذرا شمارشِ ۴۰۳ را صفر می‌کرد و سوختگی هرگز تأیید نمی‌شد."""
        self.http["wgpl5"] = "403"
        h.main(); h.main()
        self.http["wgpl5"] = "503"
        h.main()
        self.http["wgpl5"] = "403"
        h.main()
        self.assertEqual(self._burned(), ["wgpl5"], "دو ۴۰۳ + ۵۰۳ + ۴۰۳ = سه بد")

    def test_recovery_has_hysteresis(self):
        """بازگشت به استخر فقط پس از GOOD_STREAK پروبِ سالمِ پیاپی — یک ۳۰۲ ِ
        گذرا نباید کاربران را برگرداند و بعد دوباره ببرد (نوسان)."""
        self.http["wgpl5"] = "403"
        for _ in range(3):
            h.main()
        self.assertEqual(self._burned(), ["wgpl5"])
        self.http["wgpl5"] = "302"
        for _ in range(3):                        # سه سالم — کمتر از ۴
            self.assertEqual(h.main(), 0)
            self.assertEqual(self._burned(), ["wgpl5"])
        self.http["wgpl5"] = "403"                # یک بدِ میانی ⇒ شمارش از نو
        h.main()
        self.http["wgpl5"] = "302"
        for _ in range(3):
            h.main()
        self.assertEqual(self._burned(), ["wgpl5"], "شمارشِ سالم باید از نو شروع شده باشد")
        self.assertEqual(h.main(), 2)             # چهارمین سالمِ پیاپی ⇒ بازگشت
        self.assertEqual(self._burned(), [])

    def test_manual_entry_is_honored_until_proven_good(self):
        """ورودیِ دستیِ اپراتور می‌ماند تا وقتی پروب سلامت را ثابت کند؛ نامی
        که اصلاً پروب نمی‌شود (بیرونِ TUNNELS) دست‌نخورده می‌ماند."""
        with open(h.BURNED, "w", encoding="utf-8") as f:
            f.write("# دستی\nwgpl5\nwgpl9\n")
        self.http["wgpl5"] = "403"
        for _ in range(5):
            h.main()
        self.assertEqual(self._burned(), ["wgpl5", "wgpl9"])
        self.http["wgpl5"] = "302"
        for _ in range(4):
            h.main()
        self.assertEqual(self._burned(), ["wgpl9"])

    def test_probe_disabled_keeps_file_untouched(self):
        """WGPL_PROBE=0: فهرست نه ساخته می‌شود نه تغییر می‌کند."""
        h.PROBE_ON = False
        self.http["wgpl5"] = "403"
        for _ in range(5):
            self.assertEqual(h.main(), 0)
        self.assertFalse(os.path.exists(h.BURNED))

    def test_missing_link_is_skipped_not_burned(self):
        """اینترفیسِ غایب (wg-quick پایین) کارِ failover است، نه سوختگی."""
        h.link_exists = lambda dev: dev != "wgpl6"
        self.http["wgpl6"] = "000"
        self.icmp["wgpl6"] = False
        for _ in range(5):
            h.main()
        self.assertEqual(self._burned(), [])

    def test_stage_one_state_survives_probe_stage(self):
        """دو مرحله یک فایلِ state دارند؛ مرحله‌ی ۲ نباید snap/streaks ِ مرحله‌ی
        ۱ را پاک کند (وگرنه مرحله‌ی ۱ هر بار «اجرای نخست» می‌شود و لال می‌ماند)."""
        with open(h.STATS, "w", encoding="utf-8") as f:
            json.dump({"ai_by_mark": _rows({"0x81": (100, 100), "0x82": (100, 100),
                                            "0x83": (100, 100)})}, f)
        h.main()
        with open(h.STATE, encoding="utf-8") as f:
            st = json.load(f)
        self.assertEqual(set(st["snap"]), {"0x81", "0x82", "0x83"})
        self.assertIn("probe", st)
        self.assertEqual(st["burned"], [])


class FailoverHonorsBurnedListTests(unittest.TestCase):
    """مصرف‌کننده‌ی فهرست: healthy() ِ wgpl-failover.sh باید تونلِ فهرست‌شده را
    ناسالم بشمارد حتی با لینک و هندشیکِ کاملاً تازه — وگرنه فهرست بی‌اثر است."""

    _SH = os.path.join(os.path.dirname(__file__), "..", "deploy", "wgpl-failover.sh")

    def setUp(self):
        if not os.path.exists(self._SH):
            raise unittest.SkipTest("wgpl-failover.sh در این درخت نیست")
        self.dir = tempfile.mkdtemp()
        bin_ = os.path.join(self.dir, "bin")
        os.mkdir(bin_)
        # wg/ip ِ ساختگی: لینک هست، هندشیک همین حالا
        for name, body in (("wg", '#!/bin/sh\nprintf "k\\t%s\\n" "$(date +%s)"\n'),
                           ("ip", "#!/bin/sh\nexit 0\n")):
            fp = os.path.join(bin_, name)
            with open(fp, "w") as f:
                f.write(body)
            os.chmod(fp, 0o755)
        self.env = dict(os.environ, PATH=bin_ + os.pathsep + os.environ.get("PATH", ""),
                        WGPL_FAILOVER_LIB="1",
                        WGPL_BURNED=os.path.join(self.dir, "burned.list"))

    def _healthy(self, dev):
        import subprocess
        r = subprocess.run(["bash", "-c", 'source "$0" && healthy "$1" && echo yes || echo no',
                            self._SH, dev], env=self.env, capture_output=True, text=True,
                           timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_fresh_handshake_is_healthy_without_list(self):
        self.assertEqual(self._healthy("wgpl5"), "yes")

    def test_listed_tunnel_is_unhealthy_despite_fresh_handshake(self):
        with open(self.env["WGPL_BURNED"], "w") as f:
            f.write("wgpl5\n")
        self.assertEqual(self._healthy("wgpl5"), "no")
        self.assertEqual(self._healthy("wgpl"), "yes", "فقط نامِ دقیق، نه پیشوند")

    def test_lib_mode_executes_nothing(self):
        """source با LIB=1 نباید ensure_infra/point_table را بزند (iptables ندارد)."""
        import subprocess
        r = subprocess.run(["bash", "-c", 'source "$0"; echo lib-ok', self._SH],
                           env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(r.stdout.strip(), "lib-ok", r.stderr)


class YouTubeMusicStageTests(unittest.TestCase):
    """گاردِ خانوادگیِ مرحله‌ی ۳ (۲۰ سپتامبر ۲۰۲۶).

    خانواده‌ی باگ: «خروجی برای یک سرویس سالم است و برای سرویسِ دیگر
    سوخته، و نگهبانی که فقط اولی را می‌سنجد همیشه‌سبز می‌ماند». چهار
    خروجی از شش‌تا aistudio=302 می‌دادند و همان‌ها یوتیوب‌موزیک را رد
    می‌کردند؛ مرحله‌ی ۲ هیچ‌کدام را نمی‌دید.

    قیدِ دومی که اینجا قفل می‌شود و به‌اندازه‌ی خودِ تشخیص مهم است:
    این مرحله **هرگز** نباید تونلی را از استخرِ AI بیرون بیندازد.
    """

    BIG = "x" * 30000

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        h.STATS = os.path.join(self.dir, "stats.json")   # نیست ⇒ مرحله‌ی ۱ ساکت
        h.STATE = os.path.join(self.dir, "state.json")
        h.LOG = os.path.join(self.dir, "actions.log")
        h.BURNED = os.path.join(self.dir, "burned.list")
        h.YTM_LIST = os.path.join(self.dir, "ytm.list")
        h.NOTIFY = os.path.join(self.dir, "no-such-notify")
        h.PROBE_ON = False                  # مرحله‌ی ۲ اینجا بی‌ربط است
        h.YTM_ON = True
        h.TUNNELS = ["wgpl", "wgpl5", "wgpl6"]
        h.BAD_STREAK = 3
        h.GOOD_STREAK = 4
        h.link_exists = lambda dev: True
        self.body = {d: self.BIG for d in h.TUNNELS}
        self.real_probe = h.probe_ytmusic          # برای تست‌هایی که خودش را می‌سنجند
        self.addCleanup(setattr, h, "probe_ytmusic", self.real_probe)
        h.probe_ytmusic = lambda dev: self._verdict(self.body[dev])

    def _verdict(self, body):
        """خودِ قاعده‌ی محصول، نه بازنویسی‌اش در تست."""
        return h.ytm_verdict(body)

    def _bad(self):
        return h.read_list(h.YTM_LIST)

    # ---- خودِ سنجه ----
    def test_http_200_is_not_evidence_of_health(self):
        """قلبِ خانواده: پاسخِ ردشده هم ۲۰۰ است. سنجه باید بدنه باشد."""
        short_200 = '{"iconType":"%s"}' % h.YTM_MARKER
        self.assertEqual(self._verdict(short_200)[0], "bad")
        self.assertEqual(self._verdict(self.BIG)[0], "good")

    def test_a_short_body_without_the_marker_is_no_verdict(self):
        """اگر گوگل نشانگر را عوض کند، نباید بی‌جا آتش بگیریم."""
        self.assertEqual(self._verdict("{}")[0], "none")

    def test_size_floor_sits_in_the_real_gap(self):
        """۸KB باید بینِ پاسخِ ردشده (~۱٫۷KB) و سالم (~۳۰KB) بنشیند."""
        self.assertGreater(h.YTM_MIN_BYTES, 2000)
        self.assertLess(h.YTM_MIN_BYTES, 25000)

    # ---- هیسترزیس ----
    def test_rejection_reported_only_after_streak(self):
        self.body["wgpl5"] = '{"iconType":"%s"}' % h.YTM_MARKER
        codes = [h.main() for _ in range(3)]
        self.assertEqual(codes[:2], [0, 0], "نباید زودتر از streak خبر دهد")
        self.assertEqual(codes[2], 2)
        self.assertEqual(self._bad(), ["wgpl5"])
        self.assertEqual(h.main(), 0, "تکرار نباید هشدارِ دوباره بسازد")

    def test_recovery_needs_the_good_streak(self):
        self.body["wgpl5"] = '{"iconType":"%s"}' % h.YTM_MARKER
        for _ in range(3):
            h.main()
        self.assertEqual(self._bad(), ["wgpl5"])
        self.body["wgpl5"] = self.BIG
        for _ in range(h.GOOD_STREAK - 1):
            h.main()
            self.assertEqual(self._bad(), ["wgpl5"], "زود برنگردد")
        h.main()
        self.assertEqual(self._bad(), [])

    def test_healthy_fleet_writes_an_empty_list(self):
        for _ in range(5):
            self.assertEqual(h.main(), 0)
        self.assertTrue(os.path.exists(h.YTM_LIST))
        self.assertEqual(self._bad(), [])

    # ---- قیدِ «اقدام نکن» ----
    def test_stage_three_never_touches_the_ai_pool_list(self):
        """مهم‌ترین قید: خروجیِ ردکننده‌ی یوتیوب‌موزیک برای AI سالم است،
        پس نباید از استخر بیرون برود. اگر این تست بشکند، رفع تبدیل شده
        به خرابیِ بدتر از درد."""
        for d in h.TUNNELS:
            self.body[d] = '{"iconType":"%s"}' % h.YTM_MARKER
        for _ in range(10):
            h.main()
        self.assertEqual(self._bad(), h.TUNNELS, "هر سه باید گزارش شوند")
        self.assertEqual(h.read_burned(), [],
                         "مرحله‌ی ۳ نباید تونلی را از استخرِ AI بیرون کند")

    def test_the_two_lists_are_different_files(self):
        """اگر مسیرها یکی شوند، گزارشِ بی‌ضرر تبدیل به کنارگذاشتنِ تونل
        می‌شود — بی‌آنکه هیچ تستِ دیگری بفهمد."""
        self.assertNotEqual(h.YTM_LIST, h.BURNED)

    # ---- گاردِ تله‌ی اندازه‌گیری ----
    def test_the_probe_is_mark_based_not_interface_based(self):
        """تله‌ای که اجرای زنده لو داد (۲۲ سپتامبر ۲۰۲۶).

        نسخه‌ی اول با <curl --interface dev> می‌سنجید. هر شش تونل آدرسِ
        یکسانِ 10.2.0.2/32 دارند و کاربر با **مارک** مسیریابی می‌شود، پس
        آن سنجه چیزی را می‌دید که هیچ کاربری تجربه نمی‌کند — و دقیقاً
        همان دو تونلی را سالم نشان می‌داد که کاربرانشان «در حال اتصال»
        می‌دیدند (wgpl5: SO_MARK=BAD ولی --interface=good ۲۰۱KB).

        این تست قرارداد را قفل می‌کند، نه پیاده‌سازی را: هر تونل باید
        مارکِ یکتای خودش را بگیرد.
        """
        marks = [h.mark_for(d) for d in h.TUNNELS]
        self.assertNotIn(None, marks, "هر تونل باید مارک داشته باشد")
        self.assertEqual(len(set(marks)), len(marks), "مارک‌ها باید یکتا باشند")

    def test_an_unknown_tunnel_yields_no_verdict(self):
        """تونلی که در نگاشت نیست نباید بی‌جا «بد» شمرده شود."""
        self.assertIsNone(h.mark_for("wgpl-does-not-exist"))
        # تابعِ واقعی، نه mock — باید پیش از هر سوکتی برگردد
        self.assertEqual(self.real_probe("wgpl-does-not-exist"), ("none", "no-mark"))

    def test_marks_line_up_with_the_tunnel_order(self):
        """اگر ترتیبِ TUNNELS و YTM_MARKS از هم بیفتند، هر تونل مارکِ
        همسایه‌اش را می‌گیرد و نگهبان بی‌صدا تونلِ اشتباه را متهم می‌کند."""
        self.assertGreaterEqual(len(h.YTM_MARKS), len(h.TUNNELS))
        for i, dev in enumerate(h.TUNNELS):
            self.assertEqual(h.mark_for(dev), h.YTM_MARKS[i])

    # ---- کلیدِ خاموشی ----
    def test_kill_switch_silences_the_stage(self):
        h.YTM_ON = False
        for d in h.TUNNELS:
            self.body[d] = '{"iconType":"%s"}' % h.YTM_MARKER
        for _ in range(6):
            self.assertEqual(h.main(), 0)
        self.assertEqual(self._bad(), [])


if __name__ == "__main__":
    unittest.main()
