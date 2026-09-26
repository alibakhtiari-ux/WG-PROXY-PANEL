#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""زمان‌بندِ درون‌کانتینری — جانشینِ تایمرهای systemd که کانتینر ندارد.

## چرا این فایل وجود دارد

نصبِ systemd ِ پنل بکاپ را با تایمر می‌گیرد (`wg-panel-backup.timer` هر شب
۰۴:۳۰، `wg-panel-s4-upload.timer` ساعتِ ۰۴:۵۵). خودِ `wg_panel.py` هیچ
زمان‌بندیِ بکاپی ندارد — فقط وضعیتِ آن یونیت‌ها را *می‌خواند* و با فشارِ دکمه
*راه* می‌اندازد. پس داخلِ کانتینر که systemd نیست، بکاپ به‌سادگی **هرگز
خودکار اجرا نمی‌شد**: نصبی با صفر بکاپِ خودکار، بدونِ هیچ خطایی — همان
الگوی «عقب‌رفتنِ بی‌صدا» که فقط با نگاهِ چشمی به صفحه‌ی بکاپ دیده می‌شد.

## قرارداد

هر jobی از راهِ **همان** `systemctl start <unit>` (شیم) اجرا می‌شود که دکمه‌ی
«پشتیبان‌گیریِ دستی» پنل استفاده می‌کند — یک مسیر، نه منطقِ بکاپِ دوم. در
نتیجه state ای که شیم ثبت می‌کند برای هر دو مسیر یکی است و صفحه‌ی بکاپِ پنل
همان‌قدر راست می‌گوید که روی نصبِ systemd.

`NextElapseUSecRealtime` را همین‌جا می‌نویسیم چون معادلِ `.timer` ما همین
حلقه است؛ ستونِ «اجرای بعدی» پنل از این خوانده می‌شود.

فقط کتابخانه‌ی استاندارد (روی سرور نه Docker-in-Docker هست نه pip).
"""
import json
import os
import subprocess
import sys
import time

STATE_DIR = "/opt/wg-panel/units"          # روی والیوم ⇒ بازآفرینیِ کانتینر آن را نمی‌برد
S4_ENV = "/etc/wg-panel-s4.env"
S4_CONF = "/etc/wg-panel-rclone.conf"

DAY = 86400
# مهلتِ «از دست رفته»: ۲۴ ساعت + ۲ ساعت ارفاق، تا ری‌استارتِ کوتاه پس از یک
# اجرای موفق دوباره اجرا نشود.
STALE_AFTER = DAY + 2 * 3600
FIRST_RUN_DELAY = 600                       # نخستین بوتِ یک نصبِ تازه: ۱۰ دقیقه
CATCHUP_DELAY = 120                         # جبرانِ اجرای از دست رفته پس از بالا آمدن
TICK = 30


def say(msg):
    """به stdout ِ کانتینر ⇒ در `docker compose logs` دیده می‌شود."""
    sys.stdout.write("[wg-panel-cron] %s\n" % msg)
    sys.stdout.flush()


def parse_hhmm(raw, default):
    """'04:30' → (4, 30). مقدارِ نامعتبر به پیش‌فرض برمی‌گردد با هشدارِ روشن،
    چون یک تایپو در .env نباید کلِ بکاپِ خودکار را خاموش کند."""
    txt = (raw or "").strip()
    if txt:
        parts = txt.split(":")
        if len(parts) == 2:
            try:
                hh, mm = int(parts[0]), int(parts[1])
            except ValueError:
                hh = mm = -1
            if 0 <= hh <= 23 and 0 <= mm <= 59:
                return hh, mm
        say("⚠️ زمانِ نامعتبر %r — پیش‌فرضِ %s استفاده شد · invalid time, using default"
            % (txt, default))
    hh, mm = default.split(":")
    return int(hh), int(mm)


def env_true(name, default=True):
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def next_daily(hh, mm, now=None):
    """نخستین epoch ِ پس از now که ساعتِ محلی‌اش hh:mm است.

    محاسبه با mktime روی تقویمِ محلی انجام می‌شود، نه با جمعِ ۸۶۴۰۰ ثانیه —
    وگرنه در تغییرِ ساعتِ تابستانی یک روز جابه‌جا می‌شد."""
    now = time.time() if now is None else now
    lt = time.localtime(now)
    cand = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hh, mm, 0,
                        0, 0, -1))
    if cand <= now:
        tomorrow = time.localtime(now + DAY)
        cand = time.mktime((tomorrow.tm_year, tomorrow.tm_mon,
                            tomorrow.tm_mday, hh, mm, 0, 0, 0, -1))
    return cand


def _state_path(unit_with_suffix):
    return os.path.join(STATE_DIR, unit_with_suffix + ".json")


def read_last_run(unit):
    """epoch ِ آخرین اجرای ثبت‌شده (موفق یا ناموفق) یا None.

    نویسنده‌ی این فایل شیمِ systemctl است، پس اجرای دستیِ کاربر هم پنجره را
    جلو می‌برد — دقیقاً مثلِ systemd که تایمر را از آخرین فعال‌شدنِ یونیت
    می‌شمارد."""
    try:
        with open(_state_path(unit + ".service"), "r", encoding="utf-8") as f:
            return float(json.load(f).get("ts") or 0) or None
    except (OSError, ValueError, TypeError):
        return None


def write_next(unit, when):
    """`NextElapseUSecRealtime` معادل — ستونِ «اجرای بعدی» در پنل.
    when=None یعنی زمان‌بندی خاموش است ⇒ فایل برداشته می‌شود تا پنل ستون را
    خالی نشان بدهد، نه زمانی که هرگز نمی‌رسد."""
    path = _state_path(unit + ".timer")
    if when is None:
        try:
            os.unlink(path)
        except OSError:
            pass
        return
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"next": when}, f)
        os.replace(tmp, path)
    except OSError as e:
        say("⚠️ نوشتنِ زمانِ بعدیِ %s نشد: %s" % (unit, e))


def s4_configured():
    """آپلودِ ابری فقط وقتی رازها mount شده‌اند معنا دارد.

    اگر پیکربندی نشده باشد job را **اجرا نمی‌کنیم** (نه اینکه اجرا کنیم و
    شکست بخورد): وگرنه صفحه‌ی بکاپ هر شب یک قرمزِ کاذب می‌گرفت، در حالی که
    «آپلودِ ابری ندارم» یک انتخابِ درست است نه یک خرابی."""
    return os.access(S4_ENV, os.R_OK) and os.access(S4_CONF, os.R_OK)


class Job:
    def __init__(self, unit, hh, mm, precondition=None):
        self.unit = unit
        self.hh, self.mm = hh, mm
        self.precondition = precondition
        self.next = None
        self._published = "unset"      # آخرین مقداری که در فایلِ .timer نوشتیم

    def ready(self):
        return self.precondition() if self.precondition else True

    def publish(self, when):
        """«اجرای بعدی» را فقط وقتی عوض شده بنویس (هر ۳۰ ثانیه نوشتن بی‌معنی
        است). when=None ⇒ ستون خالی می‌مانَد."""
        if self._published != when:
            write_next(self.unit, when)
            self._published = when

    def schedule_initial(self, now):
        """معادلِ Persistent=true، با یک انحرافِ عمدی.

        systemd با Persistent=true یونیتی که هرگز اجرا نشده را در نخستین
        فعال‌سازی *همان لحظه* می‌زند. اینجا به‌جای «همان لحظه»، ۱۰ دقیقه
        بعد: نخستین بوتِ یک نصبِ تازه لحظه‌ای است که اپراتور تازه دارد
        پیکربندی می‌کند و بکاپِ هم‌زمان با آن هم گیج‌کننده است هم بی‌ارزش.
        ولی صفر بکاپ تا ۲۴ ساعت هم پذیرفتنی نیست، پس یک تورِ ایمنی می‌گذاریم."""
        last = read_last_run(self.unit)
        if last is None:
            self.next = now + FIRST_RUN_DELAY
            say("%s: نصبِ تازه — نخستین اجرا %d دقیقه بعد، سپس هر شب %02d:%02d"
                % (self.unit, FIRST_RUN_DELAY // 60, self.hh, self.mm))
        elif now - last > STALE_AFTER:
            self.next = now + CATCHUP_DELAY
            say("%s: آخرین اجرا %.1f ساعت پیش بود (از دست رفته) — جبران %d ثانیه بعد"
                % (self.unit, (now - last) / 3600.0, CATCHUP_DELAY))
        else:
            self.next = next_daily(self.hh, self.mm, now)
        # 🪤 اگر پیش‌شرط برقرار نیست، زمانِ بعدی **منتشر نمی‌شود**. وگرنه
        # صفحه‌ی بکاپ برای آپلودِ ابریِ پیکربندی‌نشده «اجرای بعدی: ۰۴:۵۵»
        # نشان می‌داد و آن ساعت هیچ اتفاقی نمی‌افتاد — همان جنسِ دروغی که
        # این تغییر برای رفعش آمده، فقط از سرِ دیگر.
        self.publish(self.next if self.ready() else None)

    def run(self):
        started = time.time()
        try:
            p = subprocess.run(["systemctl", "start", self.unit],
                               capture_output=True, text=True, timeout=3600)
            rc, err = p.returncode, (p.stderr or "").strip()
        except subprocess.TimeoutExpired:
            rc, err = 1, "مهلتِ اجرا تمام شد (۱ ساعت)"
        except OSError as e:
            rc, err = 1, str(e)
        took = time.time() - started
        if rc == 0:
            say("%s: موفق (%.0f ثانیه)" % (self.unit, took))
        else:
            # فقط لاگ — یک شبِ ناموفق نباید زمان‌بند را بکشد؛ خودِ شیم
            # Result=exit-code را ثبت کرده و پنل قرمز نشان می‌دهد.
            say("⚠️ %s: ناموفق (کد %d، %.0f ثانیه) %s"
                % (self.unit, rc, took, err.splitlines()[-1] if err else ""))


def main():
    if not env_true("WG_BACKUP_ENABLED", True):
        say("WG_BACKUP_ENABLED=false — زمان‌بند خاموش است (بکاپِ دستی از پنل "
            "همچنان کار می‌کند) · scheduler disabled")
        for unit in ("wg-panel-backup", "wg-panel-s4-upload"):
            write_next(unit, None)
        return 0

    try:
        os.makedirs(STATE_DIR, mode=0o750, exist_ok=True)
    except OSError as e:
        say("❌ ساختِ %s نشد: %s — زمان‌بند بی‌state کار نمی‌کند" % (STATE_DIR, e))
        return 1

    b_hh, b_mm = parse_hhmm(os.environ.get("WG_BACKUP_AT"), "04:30")
    u_hh, u_mm = parse_hhmm(os.environ.get("WG_S4_UPLOAD_AT"), "04:55")

    jobs = [Job("wg-panel-backup", b_hh, b_mm),
            Job("wg-panel-s4-upload", u_hh, u_mm, precondition=s4_configured)]

    now = time.time()
    for job in jobs:
        job.schedule_initial(now)
    if not s4_configured():
        say("آپلودِ ابری پیکربندی نشده (رازهای MEGA mount نشده‌اند) — از قلم "
            "می‌افتد، که برای نصبِ بدونِ ابر درست است · cloud upload not configured")
    say("زمان‌بند فعال: بکاپ %02d:%02d · آپلود %02d:%02d (منطقه‌ی زمانی %s)"
        % (b_hh, b_mm, u_hh, u_mm, os.environ.get("TZ") or "UTC"))

    while True:
        time.sleep(TICK)
        now = time.time()
        for job in jobs:
            # پیش‌شرط هر دور سنجیده می‌شود، نه یک‌بار در آغاز: اگر اپراتور
            # رازهای ابری را بعداً mount کند، زمان‌بند بی‌ری‌استارت می‌بیندش.
            if not job.ready():
                job.publish(None)
                continue
            if job.next is None:
                job.next = next_daily(job.hh, job.mm, now)
            job.publish(job.next)
            if now < job.next:
                continue
            job.run()
            # زمانِ بعدی از تقویم محاسبه می‌شود نه از «الان + ۲۴ساعت»، تا
            # اجرای طولانی (بکاپِ کند) ساعتِ شبِ بعد را جابه‌جا نکند.
            job.next = next_daily(job.hh, job.mm)
            job.publish(job.next)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
