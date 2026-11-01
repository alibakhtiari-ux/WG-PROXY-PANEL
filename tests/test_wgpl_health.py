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
        # حاملِ endpoint: پیش‌فرض همه از awg3 ِ سالم — رفتارِ پیش از ۲۸ سپتامبر
        self.carrier = {"wgpl": "awg3", "wgpl5": "awg3", "wgpl6": "awg3"}
        self.carrier_up = {"awg1": True, "awg3": True}
        self.carrier_pings = []
        h.endpoint_carrier = lambda dev: self.carrier.get(dev)

        def _ping(c):
            self.carrier_pings.append(c)
            return self.carrier_up[c]
        h.carrier_ping = _ping

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


class TransportOutageIsNotBurnTests(unittest.TestCase):
    """گاردِ خانوادگیِ ۲۸ سپتامبر ۲۰۲۶ (ردیفِ بازِ ۴۳): «قطعیِ حاملِ endpoint
    به‌عنوانِ سوختگیِ خودِ تونل ثبت می‌شود». نودِ ارائه‌دهنده‌ی تونلِ مادر مرد، هر شش تونلِ Proton
    000 + دروازه‌ی بی‌پاسخ دادند، چهار تونلِ سالم سوختند و AI سه ساعت و ۴۶
    دقیقه روی WARP ماند. خانواده: هر حکمِ «بد» که علتش خارج از خودِ تونل است.
    """

    setUp = ProbeStageTests.setUp
    _burned = ProbeStageTests._burned

    def _blackhole_all(self):
        for d in self.http:
            self.http[d] = "000"
            self.icmp[d] = False

    def test_mother_outage_burns_nothing_however_long(self):
        """همان صحنه‌ی ۲۸ سپتامبر: حامل مرده، هر تونل 000 + ICMP ِ ناموفق —
        ده اجرا (۵۰ دقیقه) و هیچ سوختگی."""
        self._blackhole_all()
        self.carrier_up["awg3"] = False
        for _ in range(10):
            self.assertEqual(h.main(), 0)
        self.assertEqual(self._burned(), [])

    def test_hold_does_not_build_a_bad_streak(self):
        """بی‌حکم یعنی streak دست‌نخورده: پس از برگشتِ حامل، سه پروبِ واقعیِ
        بد لازم است، نه یکی (وگرنه شمارشِ دورانِ قطعی پنهانی جمع می‌شد)."""
        self._blackhole_all()
        self.carrier_up["awg3"] = False
        for _ in range(5):
            h.main()
        self.carrier_up["awg3"] = True             # حامل برگشت، تونل هنوز مرده
        h.main(); h.main()
        self.assertEqual(self._burned(), [], "دو بدِ واقعی هنوز کمتر از سه است")
        h.main()
        self.assertEqual(set(self._burned()), {"wgpl", "wgpl5", "wgpl6"})

    def test_hold_does_not_break_an_existing_bad_streak(self):
        """همان قاعده‌ی کدِ خنثی: بد، بد، (قطعیِ حامل)، بد ⇒ سوخته."""
        self.icmp["wgpl6"] = False
        self.http["wgpl6"] = "000"
        h.main(); h.main()
        self.carrier_up["awg3"] = False
        h.main()
        self.carrier_up["awg3"] = True
        h.main()
        self.assertEqual(self._burned(), ["wgpl6"])

    def test_only_tunnels_on_the_dead_carrier_are_held(self):
        """سنجه به‌ازای تونل است، نه «همه با هم»: تونلی که حاملش سالم است و
        بلک‌هول شده باید بسوزد (همان wgpl6 ِ ۱۱ سپتامبر)."""
        self._blackhole_all()
        self.carrier.update({"wgpl": "awg1", "wgpl5": "awg1", "wgpl6": "awg3"})
        self.carrier_up["awg1"] = False
        for _ in range(3):
            h.main()
        self.assertEqual(self._burned(), ["wgpl6"])

    def test_explicit_403_is_judged_even_if_carrier_looks_dead(self):
        """۴۰۳ پاسخِ صریحِ گوگل است — مسیر کار کرده؛ حامل ربطی ندارد."""
        self.http["wgpl5"] = "403"
        self.carrier_up["awg3"] = False
        for _ in range(3):
            h.main()
        self.assertEqual(self._burned(), ["wgpl5"])

    def test_unknown_or_direct_carrier_keeps_old_behavior(self):
        """حاملِ نامعلوم یا eth0 ⇒ «نمی‌دانم» ⇒ همان حکمِ بلک‌هول."""
        for carrier in (None, "eth0"):
            self.setUp()
            self._blackhole_all()
            self.carrier = {d: carrier for d in self.http}
            for _ in range(3):
                h.main()
            self.assertEqual(set(self._burned()), {"wgpl", "wgpl5", "wgpl6"},
                             "حامل=%r" % carrier)

    def test_carrier_is_pinged_once_per_run(self):
        """سه تونل روی یک حامل ⇒ یک پینگ در هر اجرا، نه سه (هر پینگِ ناموفق
        تا ۴ ثانیه طول می‌کشد و یونیت oneshot است)."""
        self._blackhole_all()
        self.carrier_up["awg3"] = False
        h.main()
        self.assertEqual(self.carrier_pings, ["awg3"])
        h.main()
        self.assertEqual(self.carrier_pings, ["awg3", "awg3"], "حافظه فقط برای یک اجرا")

    def test_healthy_carrier_is_not_even_consulted_on_success(self):
        """تونلِ سالم هیچ هزینه‌ی تازه‌ای ندارد."""
        h.main()
        self.assertEqual(self.carrier_pings, [])

    def test_hold_is_logged_once_per_run_and_not_notified(self):
        self._blackhole_all()
        self.carrier_up["awg3"] = False
        h.main()
        with open(h.LOG, encoding="utf-8") as f:
            lines = [l for l in f if "بی‌حکم ماند" in l]
        self.assertEqual(len(lines), 1)
        self.assertIn("awg3", lines[0])

    def test_route_dev_parses_real_ip_route_get_output(self):
        self.assertEqual(h.route_dev(
            "198.51.100.7 dev awg3 src 10.24.0.172 uid 0 \n    cache \n"), "awg3")
        self.assertEqual(h.route_dev(
            "198.51.100.8 via 203.0.113.1 dev eth0 src 203.0.113.2 uid 0"), "eth0")
        self.assertIsNone(h.route_dev(""))
        self.assertIsNone(h.route_dev("RTNETLINK answers: Network is unreachable"))


class PoolAlignmentTests(unittest.TestCase):
    """گاردِ خانوادگیِ «اندازه‌ی استخر در هفت جا تکرار شده» (۲۸ سپتامبر ۲۰۲۶،
    شش ⇐ ده). ناهم‌خوانی‌ها ساکت‌اند: مارکی در splitter بدونِ ip rule ⇒ نشت به
    main؛ مارکِ یوتیوب‌موزیکِ جابه‌جا ⇒ هر تونل همسایه‌اش را می‌سنجد؛ شمارشِ
    کیل‌سوییچِ کهنه در audit ⇒ قرمزِ کاذب یا سبزِ کاذب."""

    ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

    def _read(self, *parts):
        p = os.path.join(self.ROOT, *parts)
        if not os.path.exists(p):
            raise unittest.SkipTest("%s در این درخت نیست" % "/".join(parts))
        with open(p, encoding="utf-8") as f:
            return f.read()

    def _bash_array(self, src, name):
        import re
        m = re.search(r"^%s=\(([^)]*)\)" % name, src, re.M)
        self.assertIsNotNone(m, "آرایه‌ی %s پیدا نشد" % name)
        return m.group(1).split()

    def _failover(self):
        s = self._read("deploy", "wgpl-failover.sh")
        return {k: self._bash_array(s, k) for k in
                ("TUNNELS", "POOL_MARKS", "POOL_TABLES", "POOL_RULE_PRI", "POOL_KS_PRI")}

    def test_failover_arrays_are_index_aligned_and_disjoint(self):
        f = self._failover()
        n = len(f["TUNNELS"])
        for k, v in f.items():
            self.assertEqual(len(v), n, "%s طولش %d است نه %d" % (k, len(v), n))
            self.assertEqual(len(set(v)), n, "%s تکراری دارد" % k)
        ks = [int(x) for x in f["POOL_KS_PRI"]]
        pairs = {p for k in ks for p in (k, k + 1)}
        self.assertEqual(len(pairs), 2 * n, "جفت‌های suppress+prohibit روی هم افتاده‌اند")
        self.assertTrue(all(32708 <= p for p in pairs), "با کیل‌سوییچِ اصلیِ ۳۲۷۰۰–۳۲۷۰۷ برخورد")
        pri = [int(x) for x in f["POOL_RULE_PRI"]]
        self.assertFalse({9, 11} & set(pri), "اولویتِ 0x77 (۹) یا 0x79 (۱۱) گرفته شده")

    def test_splitter_pool_equals_failover_marks(self):
        import re
        conf = self._read("deploy", "warp-sni-splitter-pool.conf")
        m = re.search(r"WSS_AI_MARK_POOL=([0-9a-fx,]+)", conf)
        self.assertEqual(m.group(1).split(","), self._failover()["POOL_MARKS"],
                         "مارکی در splitter بدونِ ip rule ⇒ نشت به main")

    def test_panel_tables_equal_failover_tables(self):
        import re
        src = self._read("wgpanel/app.py")
        m = re.search(r"^AI_POOL_TABLES = \(([^)]*)\)", src, re.M | re.S)
        tables = re.findall(r'"(\d+)"', m.group(1))
        self.assertEqual(tables, self._failover()["POOL_TABLES"])

    def test_egress_health_defaults_equal_failover(self):
        # از سورس، نه از h.TUNNELS: setUp ِ کلاس‌های دیگر آن را عوض می‌کند.
        f = self._failover()
        src = self._read("deploy", "wgpl-egress-health.py")
        import re
        tun = re.search(r'or "(wgpl[^"]*)"\)\.split\(\)', src).group(1).split()
        ytm = re.search(r'or "(8[^"]*)"\)\.split\(\)', src).group(1).split()
        self.assertEqual(tun, f["TUNNELS"])
        self.assertEqual(["0x" + x for x in ytm], f["POOL_MARKS"],
                         "مارکِ یوتیوب‌موزیکِ هم‌اندیس نیست ⇒ هر تونل همسایه‌اش را می‌سنجد")

    def test_manual_exclude_dropin_is_index_aligned(self):
        import re
        f = self._failover()
        conf = self._read("deploy", "wgpl-egress-health-manual-exclude.conf")
        tun = re.search(r'WGPL_TUNNELS="([^"]*)"', conf).group(1).split()
        ytm = re.search(r'WGPL_YTM_MARKS="([^"]*)"', conf).group(1).split()
        self.assertEqual(len(tun), len(ytm))
        for t, m in zip(tun, ytm):
            self.assertIn(t, f["TUNNELS"])
            self.assertEqual("0x" + m, f["POOL_MARKS"][f["TUNNELS"].index(t)],
                             "%s در drop-in مارکِ %s گرفته، نه مارکِ خودش" % (t, m))

    def test_boot_audit_counts_and_units_follow_pool(self):
        f = self._failover()
        a = self._read(".claude", "skills", "boot-path-audit", "audit.sh")
        n = len(f["TUNNELS"])
        self.assertIn('"$pool" -eq %d' % (2 * n), a, "شمارشِ کیل‌سوییچِ استخر کهنه است")
        for t in f["TUNNELS"]:
            self.assertRegex(a, r"wg-quick@%s(\s|\")" % t, "یونیتِ %s در audit نیست" % t)


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


class TableOwnershipTests(unittest.TestCase):
    """گاردِ خانوادگیِ «دو نویسنده برای یک جدولِ مسیریابی» (۲۸ سپتامبر ۲۰۲۶، §۲۹٫۱۲۵).

    warp-gemini-sync.sh هر ۱۵ دقیقه مسیرِ پیش‌فرضِ جدولِ ۲۳۰ را به
    WARP_EGRESS_IFACE می‌برد و wgpl-failover.sh ≤۱۵ث بعد به نخستین تونلِ
    سالم برمی‌گرداند. دو بار رخ داد: ۱۵ اوت با wgwarp (§۲۹٫۱۰۱) و ۲۸ سپتامبر
    با wgpl ِ سوخته (۴۴۳ جابه‌جایی — ترافیکِ AI روی خروجیِ ۴۰۳). رفعِ اول نامِ
    اینترفیس را عوض کرد و خانواده زنده ماند؛ این‌جا خودِ «نویسنده‌ی دوم» قفل
    می‌شود: هر جدولی که مالِ wgpl-failover است، هر نویسنده‌ی دیگری فقط از
    داخلِ تابعی می‌نویسد که پیش از نوشتن مالکیت را می‌پرسد."""

    ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    _SYNC = os.path.join(ROOT, "deploy", "warp-gemini-sync.sh")
    _FAILOVER = os.path.join(ROOT, "deploy", "wgpl-failover.sh")
    # مسیرِ پیش‌فرضِ اصلی — نه پشتیبانِ metric، نه blackhole/local
    _WRITE = __import__("re").compile(
        r"\bip\s+route\s+(?:replace|add|change)\s+default\s+dev\s+\S+"
        r"(?![^\n]*\bmetric\b)[^\n]*\btable\s+(\S+)")

    def setUp(self):
        for p in (self._SYNC, self._FAILOVER):
            if not os.path.exists(p):
                raise unittest.SkipTest("%s در این درخت نیست" % os.path.basename(p))

    @staticmethod
    def _code(path):
        with open(path, encoding="utf-8") as f:
            return [l for l in f.read().splitlines()]

    def _failover_tables(self):
        import re
        src = "\n".join(self._code(self._FAILOVER))
        main = re.search(r"^MAIN_TABLE=(\d+)", src, re.M).group(1)
        pool = re.search(r"^POOL_TABLES=\(([^)]*)\)", src, re.M).group(1).split()
        return {main, *pool}

    def _resolve(self, lines, tok):
        import re
        tok = tok.strip('"').strip("'")
        if tok.isdigit():
            return tok
        m = re.fullmatch(r"\$\{?(\w+)\}?", tok)
        self.assertIsNotNone(m, "جدولِ «%s» قابلِ حل نیست" % tok)
        for l in lines:
            a = re.match(r"^%s=(\d+)\b" % m.group(1), l)
            if a:
                return a.group(1)
        self.fail("متغیرِ جدولِ $%s مقدارِ عددیِ ثابت ندارد — نویسنده‌ی پنهان؟" % m.group(1))

    def _enclosing_function(self, lines, idx):
        import re
        for j in range(idx, -1, -1):
            m = re.match(r"^(\w+)\(\)\s*\{", lines[j])
            if m:
                end = next(k for k in range(j + 1, len(lines)) if lines[k] == "}")
                return (m.group(1), j) if end > idx else (None, None)
        return None, None

    def test_failover_owned_tables_have_no_unguarded_second_writer(self):
        import glob
        owned = self._failover_tables()
        scripts = sorted(set(glob.glob(os.path.join(self.ROOT, "deploy", "**", "*.sh"),
                                       recursive=True)) - {self._FAILOVER})
        self.assertIn(self._SYNC, scripts)
        seen = 0
        for path in scripts:
            lines = self._code(path)
            for i, l in enumerate(lines):
                if l.lstrip().startswith("#"):
                    continue
                m = self._WRITE.search(l)
                if not m or self._resolve(lines, m.group(1)) not in owned:
                    continue
                seen += 1
                where = "%s:%d" % (os.path.relpath(path, self.ROOT), i + 1)
                fn, start = self._enclosing_function(lines, i)
                self.assertIsNotNone(fn, "%s جدولِ نگهبان را بیرون از هر تابعی می‌نویسد" % where)
                body = "\n".join(lines[start:i])
                self.assertIn("table_owned_elsewhere", body,
                              "%s (در %s) پیش از نوشتن مالکیت را نمی‌پرسد" % (where, fn))
        self.assertGreaterEqual(seen, 1, "نوشتنِ جدولِ ۲۳۰ در sync.sh پیدا نشد — regex کهنه است")

    def test_sync_table_is_the_failover_main_table(self):
        import re
        sync = "\n".join(self._code(self._SYNC))
        fo = "\n".join(self._code(self._FAILOVER))
        self.assertEqual(re.search(r"^TABLE=(\d+)", sync, re.M).group(1),
                         re.search(r"^MAIN_TABLE=(\d+)", fo, re.M).group(1))

    def test_owner_unit_exists_in_repo(self):
        import re
        sync = "\n".join(self._code(self._SYNC))
        unit = re.search(r"TABLE_OWNER=\$\{WARP_TABLE_OWNER:-([^}]+)\}", sync).group(1)
        self.assertTrue(os.path.exists(os.path.join(self.ROOT, "deploy", unit)),
                        "مالکِ %s در deploy/ نیست ⇒ is-active همیشه false و واگذاری مرده" % unit)
        svc = os.path.join(self.ROOT, "deploy", unit.replace(".timer", ".service"))
        with open(svc, encoding="utf-8") as f:
            self.assertIn("wgpl-failover.sh", f.read())

    def test_panel_never_writes_ai_tables(self):
        """پنل فقط می‌خوانَد (_default_dev_of_table)؛ نویسنده‌ی سوم نسازد."""
        import re
        src = self._code(os.path.join(self.ROOT, "wgpanel", "app.py"))
        for i, l in enumerate(src, 1):
            if re.search(r'"route",\s*"(replace|add|change)",\s*"default"', l):
                self.assertNotRegex(l, r"WARP_TABLE|AI_POOL_TABLES|\"2(3\d|4\d|50)\"",
                                    "wg_panel.py:%d جدولِ نگهبان را می‌نویسد" % i)

    # ---- رفتاری: set_warp_table با ip/systemctl ِ ساختگی --------------
    def _run(self, owner_active, table):
        import subprocess
        d = tempfile.mkdtemp()
        bin_ = os.path.join(d, "bin")
        os.mkdir(bin_)
        for name, body in (
                ("ip", '#!/bin/sh\nif [ "$1 $2 $3" = "route show table" ]; then\n'
                       '  cat "$FAKE_TABLE" 2>/dev/null; exit 0; fi\n'
                       'echo "$*" >>"$FAKE_LOG"\n'),
                ("systemctl", '#!/bin/sh\nexit "$FAKE_OWNER_RC"\n')):
            fp = os.path.join(bin_, name)
            with open(fp, "w") as f:
                f.write(body)
            os.chmod(fp, 0o755)
        tbl, log = os.path.join(d, "table"), os.path.join(d, "log")
        with open(tbl, "w") as f:
            f.write(table)
        env = dict(os.environ, PATH=bin_ + os.pathsep + os.environ.get("PATH", ""),
                   WARP_SYNC_LIB="1", WARP_EGRESS_IFACE="wgpl",
                   FAKE_TABLE=tbl, FAKE_LOG=log,
                   FAKE_OWNER_RC="0" if owner_active else "3")
        r = subprocess.run(["bash", "-c", 'source "$0" && set_warp_table', self._SYNC],
                           env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)
        writes = open(log).read().splitlines() if os.path.exists(log) else []
        return writes

    LIVE = "default dev wgpl2 scope link \ndefault dev wgwarp scope link metric 100 \n"

    def test_owner_active_and_table_set_is_left_alone(self):
        """دقیقاً وضعِ ۲۸ سپتامبر: نگهبان wgpl2 گذاشته، sync نباید wgpl ِ سوخته بنویسد."""
        self.assertEqual(self._run(True, self.LIVE), [])

    def test_owner_active_but_table_empty_is_bootstrapped(self):
        """بوت یا پس از teardown: جدولِ خالی بلک‌هول است، پس مقدارِ اولیه لازم است."""
        self.assertEqual(self._run(True, ""), ["route replace default dev wgpl table 230"])

    def test_backup_route_alone_does_not_count_as_owned(self):
        """پشتیبانِ metric 100 مسیرِ اصلی نیست — همان قاعده‌ی awk ِ point_table."""
        self.assertEqual(self._run(True, "default dev wgwarp scope link metric 100 \n"),
                         ["route replace default dev wgpl table 230"])

    def test_without_owner_sync_keeps_old_behavior(self):
        """نصب‌های بدونِ استخر (ansible/airgap): sync تنها مالک است، مثلِ قبل."""
        self.assertEqual(self._run(False, self.LIVE),
                         ["route replace default dev wgpl table 230"])

    def test_lib_mode_executes_nothing(self):
        import subprocess
        d = tempfile.mkdtemp()
        r = subprocess.run(["bash", "-c", 'source "$0"; echo lib-ok', self._SYNC],
                           env=dict(os.environ, WARP_SYNC_LIB="1",
                                    PATH=d + os.pathsep + os.environ.get("PATH", "")),
                           capture_output=True, text=True, timeout=20)
        self.assertEqual(r.stdout.strip(), "lib-ok", r.stderr)

    def test_standby_check_reads_warp_not_egress(self):
        """IFACE=wgpl نباید کلیدِ wgpl را با کلیدِ استندبایِ WARP مقایسه کند."""
        code = [l for l in self._code(self._SYNC) if not l.lstrip().startswith("#")]
        line = next(l for l in code if "public-key" in l and "wg show" in l)
        self.assertIn("$WARP_IF", line)
        self.assertNotIn("$IFACE", line)


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
