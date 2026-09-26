#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""warp-sni-splitter — جراحیِ کولترالِ WARP بر پایهٔ SNI.

انگیزه (اثباتِ زنده): /24های GFEِ گوگل اشتراکی‌اند — همان بلوک‌هایی که
gemini دارد، یوتیوب/سرچ/APIهای اندروید هم دارند؛ پس مسیریابیِ IPمحور
نمی‌تواند AI را از کولترال جدا کند. اندازه‌گیریِ ۱۵دقیقه‌ای نشان داد ~۸۲٪
بایتی که از WARP می‌رود کولترال است. این دیمن تنها راهِ دقیق را پیاده می‌کند:
تفکیک بر اساسِ SNI.

معماری (سطحِ خطای محدود):
  * فقط ترافیکِ  src 192.168/16 + dst ai_warp + tcp/443  با TPROXY به این
    دیمن منحرف می‌شود (قاعده در mangle PREROUTING). بقیهٔ اینترنت اصلاً
    وارد نمی‌شود.
  * دیمن ClientHello را می‌خواند، فقط SNI را درمی‌آورد و تصمیم می‌گیرد:
      - هاست در فهرستِ AI (warp-targets.conf) → SO_MARK 0x77 → جدولِ WARP.
      - بقیه (کولترال)                        → SO_MARK 0x78 → مسیرِ مستقیم.
    (مقصدِ واقعیِ هر مارک با ip rule/route بیرونِ این فایل تعریف می‌شود؛
     این دیمن فقط مارک می‌زند و هیچ نامِ اینترفیسی نمی‌شناسد.)
  * fail-safe: هر ابهامی (بدونِ SNI، غیر-TLS، خطای پارس) → AI/WARP، یعنی
    رفتارِ امنِ امروز حفظ می‌شود.
  * fail-open در سطحِ سیستم: اگر این دیمن بمیرد، WarpGuardِ پنل قاعدهٔ
    TPROXY را برمی‌دارد و ترافیک به مارکِ blanketِ 0x77 (کلِ /24 → WARP)
    برمی‌گردد — یعنی بدترین حالتِ خرابیِ دیمن = وضعیتِ فعلی، نه قطعی.

پایتونِ خالصِ stdlib (asyncio + سوکتِ خام) — بدونِ هیچ وابستگی، هم‌ذاتِ
خودِ پنل. importِ این فایل سروری راه نمی‌اندازد (همه زیرِ __main__)، تا
تست‌های آفلاینِ پارسرِ SNI بتوانند مستقیم import کنند.
"""

import asyncio
import errno
import importlib.util
import json
import os
import re
import resource
import selectors
import socket
import struct
import sys
import threading
import time
import zlib

# ---- ثابت‌ها (قابلِ override با env برای تست) --------------------------------
LISTEN_HOST = os.environ.get("WSS_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("WSS_PORT", "8445"))
MARK_AI = int(os.environ.get("WSS_MARK_AI", "0x77"), 16)       # → جدولِ WARP
MARK_DIRECT = int(os.environ.get("WSS_MARK_DIRECT", "0x78"), 16)  # → مستقیم
# رفعِ جغرافیا: دامنه‌هایی که از تونلِ مادر «روسیه» دیده می‌شوند (یوتیوب‌موزیک
# در روسیه بلاک است) ولی باید از خروجی‌ای با کشورِ سالم بروند. مارکِ جدا از
# WARP تا کولترالِ سنگین (googlevideo) تونلِ مشترکِ WARP را اشغال نکند —
# مسیرش (ip rule/route) بیرونِ این فایل تعریف می‌شود. فهرستش جداست
# تا در ai_warp (ورود به splitter) باشد ولی به‌عنوان AI طبقه‌بندی نشود.
MARK_GEO = int(os.environ.get("WSS_MARK_GEO", "0x79"), 16)     # → جدولِ geo

# استخرِ مارکِ AI — پخشِ بارِ کاربران روی چند خروجی، با چسبندگیِ per-user.
# قالب: "0x81,0x82,0x83". خالی (پیش‌فرض) ⇒ دقیقاً رفتارِ تک‌مارکِ پیشین،
# یعنی راهِ برگشت همیشه یک env است نه یک استقرار.
_AI_POOL_RAW = (os.environ.get("WSS_AI_MARK_POOL", "") or "").strip()


def _parse_mark_pool(raw):
    """رشته‌ی env را به فهرستِ مارک تبدیل می‌کند. ورودیِ خراب ⇒ فهرستِ خالی.

    fail-safe عمدی است: اگر کسی env را بد بنویسد، سیستم به رفتارِ
    تک‌مارکِ سالم برمی‌گردد و ترافیک بی‌مارک رها نمی‌شود.
    """
    out = []
    for part in raw.replace(" ", "").split(","):
        if not part:
            continue
        try:
            val = int(part, 16)
        except ValueError:
            return []
        if val <= 0 or val > 0xFFFFFFFF:
            return []
        out.append(val)
    return out


MARK_AI_POOL = _parse_mark_pool(_AI_POOL_RAW)


def ai_mark_for(client_ip):
    """مارکِ AI ِ این کاربر.

    هش روی **آدرسِ کاربر** است، نه روی جریان. تفاوتش حیاتی است: با هشِ
    per-flow (کاری که ECMP ِ کرنل می‌کند) اتصال‌های هم‌زمانِ یک کاربر از
    IP های مختلف بیرون می‌روند و گوگل آن را جابه‌جاییِ هویت وسطِ نشست
    می‌بیند — همان چیزی که wg22 را به صفحه‌ی abuse رساند. با هشِ per-user
    بار پخش می‌شود ولی هویتِ هر کاربر پایدار می‌ماند.

    crc32 انتخاب شد نه hash() چون hash() ِ پایتون per-process رندم است و
    بعد از هر ری‌استارت نگاشت عوض می‌شد.
    """
    if not MARK_AI_POOL or not client_ip:
        return MARK_AI
    idx = zlib.crc32(client_ip.encode("utf-8", "replace")) % len(MARK_AI_POOL)
    return MARK_AI_POOL[idx]
TARGETS_FILE = os.environ.get("WSS_TARGETS", "/opt/wg-panel/warp-targets.conf")
GEO_TARGETS_FILE = os.environ.get("WSS_GEO_TARGETS", "/opt/wg-panel/geo-targets.conf")
HEARTBEAT_FILE = os.environ.get("WSS_HEARTBEAT", "/opt/wg-panel/warp-sni.active")
STATS_FILE = os.environ.get("WSS_STATS", "/opt/wg-panel/warp-sni.stats")
# QUIC/UDP splitter (اختیاری). اگر WSS_QUIC_PORT ست شود، یک نخِ جدا UDPِ 443ِ
# منحرف‌شده با TPROXY را می‌گیرد، SNI را از QUIC Initial (رمزگشاییِ AES-GCM)
# می‌خواند و مثلِ TCP تفکیک می‌کند. پیش‌فرض خاموش (پورت خالی).
QUIC_PORT = int(os.environ.get("WSS_QUIC_PORT", "0") or "0")
# انقضای جریانِ UDPِ بی‌ترافیک (QUIC خودش FIN ندارد، پس سنجه‌ی ما زمان است).
#
# چرا ۳۰۰ و نه ۶۰: SNI فقط در پکتِ **Initial** (long-header) است؛ پکت‌های
# بعدیِ همان اتصال short-header‌اند و ذاتاً SNI ندارند. تصمیمِ درست فقط از
# طریقِ همین جدولِ جریان به آن‌ها می‌رسد. با TTLِ ۶۰ ثانیه‌ای، یک اتصالِ زنده
# که کمی ساکت بماند (بافرِ ویدیو، تبِ پس‌زمینه) جریانش جارو می‌شد و پکتِ
# بعدی‌اش به‌عنوانِ «جریانِ جدیدِ بی‌SNI» دیده می‌شد → fail-open به WARP.
# اندازه‌گیریِ زنده: ۹۹٪ از اتصالاتِ QUICِ رفته به WARP از همین مسیر بود، نه
# از تشخیصِ واقعیِ AI (۳۱۸MB از ۴۲۷MB مصرفِ WARP).
#
# این فقط «حافظه‌ی تصمیم» را طولانی می‌کند و خودِ منطقِ تصمیم را عوض نمی‌کند:
# ترافیکِ AI در هر دو حالت به WARP می‌رود (چه از SNI شناخته شود چه از
# fail-open)، پس سرویس‌های فهرستِ SNI از این تغییر آسیب نمی‌بینند؛ تنها
# ترافیکِ غیر-AI است که به مسیرِ درستِ خودش (مستقیم) برمی‌گردد. سودِ جانبی:
# آی‌پیِ مبدأ وسطِ یک اتصالِ زنده عوض نمی‌شود (مهاجرتِ ناخواسته‌ی QUIC).
QUIC_IDLE = float(os.environ.get("WSS_QUIC_IDLE", "300") or "300")

# سقف‌های انباشتِ ClientHelloِ چندپکتی (رجوع به QuicSplitter._feed_hello).
# ورودی **UDPِ احراز هویت‌نشده** است: فرستنده می‌تواند تا ابد CRYPTO با
# offsetِ دلخواه بفرستد، پس بافرِ بی‌کران یعنی سطحِ حمله‌ی حافظه. کران روی
# **مجموعِ بایتِ بافرشده** است نه بزرگ‌ترین offset — وگرنه آفستِ پراکنده
# (۰، ۱M، ۲M …) که هیچ‌وقت از صفر پیوسته نمی‌شود از کنارش رد می‌شد.
QUIC_HELLO_MAX = 64 * 1024   # سقفِ بایتِ بافرشده‌ی هر جریان
QUIC_HELLO_PKTS = 8          # بیش از این دیتاگرام یعنی چیزی درست نیست
QUIC_HELLO_FRAMES = 512      # سقفِ ردیفِ نگاشت (frameِ خردِ فراوان)

# هزینه‌ی توصیف‌گرِ هر جریانِ QUIC — **از کد شمرده شده، نه حدس‌زده**:
#   ۱ سوکتِ خروجیِ اختصاصی (_QuicFlow.up — ساخته در _new_flow، بسته در
#     _close_flow؛ دقیقاً یکی به‌ازای هر جریان)
# + حداکثر ۱ سوکتِ پاسخ    (reply_socks — **مشترک به‌ازای هر مقصد**، نه هر
#     جریان؛ بدترین حالت یعنی هر جریان مقصدِ یکتای خودش را داشته باشد)
# سوکتِ گوش‌دهنده و epollِ selector ثابت‌اند و در حاشیه‌ی +۶۴ جا می‌شوند.
# جهتِ خطا عمداً «بیش‌برآورد» است: بیش‌برآورد یعنی ضربان کمی بیشتر بسته
# می‌ماند (محافظه‌کارانه)، کم‌برآورد یعنی برگشتِ flapِ ۲۰۲۶-۰۷-۲۱.
QUIC_FD_PER_FLOW = 2

# ---- نگه‌داشتنِ دیتاگرام تا روشن‌شدنِ نام (پلنِ ۰۶۶) ----
# کلیدِ خاموشی **پیش از** خودِ قابلیت ساخته شد و این عمدی است: با
# WSS_QUIC_HOLD=0 هیچ دیتاگرامی صف نمی‌شود و مسیر بایت‌به‌بایت همان پیش از
# این تغییر است، پس رفعِ اضطراری یک ویرایشِ env در یونیت + ری‌استارت است،
# نه رول‌بکِ کد زیرِ فشار.
QUIC_HOLD = (os.environ.get("WSS_QUIC_HOLD", "1") or "1").strip().lower() \
    not in ("0", "no", "off", "false")
# سقفِ زمانِ نگه‌داری. عمداً **کمتر** از نخستین PTOِ کلاینت (~۲۰۰–۵۰۰ms):
# اگر بیشتر باشد کلاینت خودش Initial را بازارسال می‌کند و نگه‌داری هم
# تأخیر می‌سازد هم کار را دوباره. سقفِ بایت و پکت از همان کران‌های
# بازآرایی می‌آید (QUIC_HELLO_MAX/PKTS) تا دو مفهومِ موازی ساخته نشود.
QUIC_HOLD_MS = float(os.environ.get("WSS_QUIC_HOLD_MS", "250") or "250")

# ---- جریانِ QUIC که نامش هرگز قطعی نشد ⇒ geo، نه استخرِ AI ----
# fail-openِ تاریخی «ابهام ⇒ AI/WARP» بود. سنجشِ ۲۰ سپتامبر ۲۰۲۶ نشان داد
# چهار خروجی از شش خروجیِ استخرِ AI یوتیوب‌موزیک را رد می‌کنند (پاسخِ ۲۰۰ ِ
# ۱٬۶۶۶ بایتی با "iconType":"MUSIC_UNAVAILABLE" در برابرِ ۳۰KBِ سالم) در
# حالی که برای خودِ AI سالم‌اند — پس «سوخته» شمردنشان و کنارگذاشتنشان غلط
# است؛ مقصدِ کورها باید عوض شود، نه استخر.
#
# چرا geo مقصدِ امنی برای کورهاست: از مسیرِ geo هر دو خانواده جواب می‌دهند
# (aistudio 302 · gemini 200 · ai.google.dev 200 · notebooklm 301 — دقیقاً
# همان کدهای استخرِ AI)، در حالی که عکسش برقرار نیست. پس این تغییر یک
# خانواده را درست می‌کند بی‌آنکه دیگری را بشکند.
#
# بار: جریانِ بی‌نام ~۰٫۱٪ بایتِ کل است (۹٫۲GB در ۳۶ روز ≈ ۲۵۵MB/روز در
# برابرِ ۲۳۲GB مستقیم)، پس wg22 چیزی حس نمی‌کند.
#
# کلیدِ خاموشی جداست تا رول‌بک یک ویرایشِ env + ری‌استارت باشد، نه رول‌بکِ کد.
QUIC_BLIND_GEO = (os.environ.get("WSS_QUIC_BLIND_GEO", "1") or "1") \
    .strip().lower() not in ("0", "no", "off", "false")

# ماژولِ رمزگشاییِ QUIC (فایلِ کنارِ همین اسکریپت). با مسیرِ مطلق import می‌شود
# تا مستقل از cwd باشد؛ اگر نبود، QUIC خاموش می‌ماند (TCP دست‌نخورده).
quic_sni = None
try:
    _qp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quic_sni.py")
    _spec = importlib.util.spec_from_file_location("quic_sni", _qp)
    quic_sni = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(quic_sni)
except Exception:
    quic_sni = None

# آیا ماژولِ کنارِ ما بازآراییِ چندپکتی را دارد؟ دو فایلِ **جدا** مستقر
# می‌شوند و می‌توانند از هم عقب بمانند (تا امروز `quic_sni.py` حتی در
# `ansible/sync-files.sh` نبود). با ماژولِ کهنه انباشت خاموش می‌ماند و
# رفتار دقیقاً همان پیش از این تغییر می‌شود — نه AttributeError وسطِ حلقه‌ی
# داده، نه فرستادنِ کلِ QUIC به WARP.
QUIC_REASSEMBLY = quic_sni is not None and all(
    hasattr(quic_sni, _n) for _n in ("crypto_from_datagram",
                                     "sni_from_crypto"))

# ثابت‌های cmsg برای TPROXYِ UDP (به‌دست‌آوردنِ مقصدِ اصلیِ هر دیتاگرام)
IP_ORIGDSTADDR = 20        # = IP_RECVORIGDSTADDR
IP_TRANSPARENT_OPT = getattr(socket, "IP_TRANSPARENT", 19)

# محافظِ حلقه: سوکتِ گوش‌دهنده IP_TRANSPARENT است و روی 0.0.0.0 می‌نشیند، پس
# اتصالِ مستقیم به این پورت (اسکنرِ اینترنتی یا هر کلاینتِ محلی) هم پذیرفته
# می‌شود. در آن حالت getsockname() مقصدِ اصلی نیست بلکه «خودِ این ماشین:8445»
# است و دیمن به خودش وصل می‌شود → بازگشتِ نامتناهی و انفجارِ اتصال. هر اتصالی
# که مقصدش پورتِ خودِ ما یا یک آدرسِ محلی باشد بی‌درنگ بسته می‌شود.
LOCAL_ADDRS = set()
HELLO_MAX = 16 * 1024      # سقفِ بافرِ ClientHello (رکوردِ TLS ≤ 16KiB)
HELLO_TIMEOUT = 5.0        # ثانیه برای رسیدنِ ClientHello
CONNECT_TIMEOUT = 10.0
# سقف‌های عمرِ جریانِ TCP — ضدِ نشتِ fd (حادثه‌ی ۲۰۲۶-۰۷-۲۱). IDLE_TIMEOUT
# از روزِ اول تعریف شده بود ولی در pipe() اِعمال نمی‌شد: جریانی که یک سرش
# بی‌خداحافظی غیب می‌شد (موبایلِ پشتِ NAT، سرورِ ساکت) برای همیشه در
# sock_recv می‌ماند — هر جریان دو سوکت — تا در پیکِ شبانه fdِ پروسه تمام شد
# (۹۷۱ سوکتِ CLOSE-WAIT/FIN-WAIT-2 در برابرِ ۱۴ اتصالِ زنده) و اولین قربانیِ
# EMFILE خودِ heartbeat بود → flapِ سلامت و رگبارِ هشدار.
IDLE_TIMEOUT = 300.0       # بی‌ترافیکیِ کاملِ جریانِ دوطرفه‌باز → بستن
HALF_CLOSE_GRACE = 90.0    # یک طرف EOF داده؛ سکوتِ طرفِ دیگر بیش از این → بستن
SEND_TIMEOUT = 120.0       # sendallِ گیرکرده (گیرنده‌ی مرده، پنجره‌ی صفر) → بستن
PIPE_POLL = 30.0           # دانه‌بندیِ بیدارشدن برای سنجشِ بیکاری
BUF = 65536

# IP_TRANSPARENT در برخی نسخه‌های پایتون در ماژولِ socket نیست
IP_TRANSPARENT = getattr(socket, "IP_TRANSPARENT", 19)
SO_MARK = getattr(socket, "SO_MARK", 36)
SOL_IP = getattr(socket, "SOL_IP", 0)

# شمارنده‌های per-SNI (کشفِ دامنه از دلِ ترافیک): کران‌دار تا حافظه نترکد.
SNI_MAX = 512              # سقفِ تعدادِ SNIهای نگه‌داشته‌شده
SNI_TOP = 60               # چندتای برتر (حجمی) که واردِ فایلِ آمار می‌شود
SNI_TOP_CONNS = 60         # برترین‌ها بر پایه‌ی شمارِ اتصال (رجوع به sni_top_conns)
SNI_IDLE = 86400           # SNIِ یک روز بی‌ترافیک از جدول می‌افتد


# ============================================================================
# شمارنده‌ی per-SNI — کشفِ دامنه (منطقِ خالص، مستقلاً تست‌شونده)
# ============================================================================
# انگیزه: splitter تنها جای سیستم است که SNIِ واقعیِ ترافیکِ /24های منحرف‌شده
# را می‌بیند. بدونِ این جدول، پیدا کردنِ بک‌اندِ گم‌شده‌ی یک اپ (درسِ
# robinfrontend-pa: اپِ اندرویدِ Gemini هفته‌ها می‌شکست) یک تحقیقِ کامل
# می‌خواست؛ با آن، دامنه‌ی «کولترال»ی که باید AI باشد خودش را نشان می‌دهد.
# ساختارِ هر ردیف: sni -> [bytes, conns, is_ai(0/1)، last_ts]
def sni_note(store, sni, nbytes, conns, is_ai):
    """ثبتِ ترافیکِ یک SNI. کلیدِ '' یعنی «بدونِ SNI» (تجمیعی).

    اگر جدول پر است ردیفِ تازه نمی‌سازد (compaction بعدی جا باز می‌کند) —
    قطره‌ای گم می‌شود ولی حافظه هرگز بی‌کران رشد نمی‌کند."""
    key = (sni or "").lower().rstrip(".")
    e = store.get(key)
    if e is None:
        if len(store) >= SNI_MAX:
            return
        store[key] = [nbytes, conns, 1 if is_ai else 0, int(time.time())]
    else:
        e[0] += nbytes
        e[1] += conns
        e[2] = 1 if is_ai else 0     # طبقه‌بندیِ فعلی (با تغییرِ مقصدها عوض می‌شود)
        e[3] = int(time.time())


def sni_compact(store, now=None):
    """کهنه‌ها (بی‌ترافیک > یک روز) حذف؛ اگر هنوز پر است، جا باز می‌شود.

    نگه‌داشتن روی **دو** محور است نه یکی: نیمی از سهمیه به پرحجم‌ترین‌ها و
    نیمی به پراتصال‌ترین‌ها. اگر فقط حجم ملاک بود، دامنه‌ای که کاملاً بلاک
    است — چند صد بایت با ده‌ها تلاشِ دوباره — همیشه اول قربانی می‌شد و
    کشفِ خودکار هرگز نمی‌دیدش. سقفِ نهایی همان سه‌چهارمِ قبلی است."""
    now = int(now if now is not None else time.time())
    for k in [k for k, e in store.items() if now - e[3] > SNI_IDLE]:
        del store[k]
    if len(store) >= SNI_MAX:
        half = SNI_MAX * 3 // 8
        keep = dict(sorted(store.items(), key=lambda kv: kv[1][0],
                           reverse=True)[:half])
        keep.update(sorted(store.items(), key=lambda kv: kv[1][1],
                           reverse=True)[:half])
        store.clear()
        store.update(keep)


def sni_top(store, n=SNI_TOP):
    """برترین SNIها بر پایه‌ی حجم → [[sni, bytes, conns, is_ai], …]"""
    rows = sorted(store.items(), key=lambda kv: kv[1][0], reverse=True)[:n]
    return [[k, e[0], e[1], e[2]] for k, e in rows]


def ai_by_mark(store):
    """آمارِ AI به تفکیکِ مارکِ خروجی → [[mark, bytes, conns, srcs], …].

    پایه‌ی «تشخیصِ انحراف از همتایان» است: وقتی گوگل یک IP خروجی را برای
    سرویس رد می‌کند، کاربرانِ همان خروجی پاسخِ کوتاه می‌گیرند و زود قطع
    می‌کنند، پس بایت‌به‌ازای‌اتصالشان نسبت به بقیه می‌افتد. هیچ سنجه‌ی
    مطلقی برای این وجود ندارد (کدِ HTTP و اندازه‌ی صفحه و پاسخِ API از
    IP سالم و بلاک‌شده یکسان‌اند — ۱۵ اوت ۲۰۲۶ آزموده شد)، ولی وقتی
    کاربران روی چند خروجی پخش‌اند، بقیه گروهِ مرجع می‌شوند.

    از src_stats ساخته می‌شود نه از شمارنده‌ی جدا: نگاشتِ کاربر→مارک
    قطعی است (crc32)، پس همان داده کافی است و ساختارِ تازه‌ای که باید
    کران‌دار و پاک‌سازی شود اضافه نمی‌کنیم.
    """
    agg = {}
    for src, e in store.items():
        row = agg.setdefault(ai_mark_for(src), [0, 0, 0])
        row[0] += e[0]      # ai_bytes
        row[1] += e[2]      # ai_conns
        row[2] += 1         # تعدادِ کاربرانِ این خروجی
    return [[hex(m), v[0], v[1], v[2]] for m, v in sorted(agg.items())]


def sni_top_conns(store, n=SNI_TOP_CONNS):
    """برترین SNIها بر پایه‌ی **شمارِ اتصال** — همان ساختارِ sni_top.

    دامنه‌ای که ۴۰۳ می‌خورد تقریباً بایتی جابه‌جا نمی‌کند، پس در رتبه‌بندیِ
    حجمی هرگز بالا نمی‌آید؛ ولی مرورگر مدام دوباره تلاش می‌کند و شمارِ
    اتصالش بالاست. بدونِ این فهرست، کشفِ خودکار نسبت به دقیقاً همان خرابی‌ای
    که برای یافتنش ساخته شده کور می‌ماند (موردِ notebook.google.com)."""
    rows = sorted(store.items(), key=lambda kv: kv[1][1], reverse=True)[:n]
    return [[k, e[0], e[1], e[2]] for k, e in rows]


# ============================================================================
# شمارنده‌ی per-src — مصرفِ AI به تفکیکِ کاربر (منطقِ خالص، تست‌شونده)
# ============================================================================
# splitter مبدأِ واقعیِ هر اتصالِ منحرف‌شده را می‌بیند (فقط 192.168/16 وارد
# می‌شود). با نگه‌داشتنِ کران‌دارش، پنل می‌تواند نشان دهد چه کسی چقدر AI
# مصرف می‌کند — برای ظرفیت‌سنجیِ WARP و پیدا کردنِ مصرفِ غیرعادی.
# ساختارِ هر ردیف: src -> [ai_bytes, direct_bytes, ai_conns, direct_conns, last_ts]
SRC_MAX = 1024             # سقفِ تعدادِ مبدأها (کاربران عملاً چند صدتا هستند)
SRC_TOP = 30               # چندتای برتر که واردِ فایلِ آمار می‌شود
SRC_IDLE = 3 * 86400       # مبدأِ ۳ روز بی‌ترافیک از جدول می‌افتد


def src_note(store, src, nbytes, conns, is_ai):
    """ثبتِ ترافیکِ یک مبدأ. جدولِ پر ردیفِ تازه نمی‌سازد (کران‌داری)."""
    if not src:
        return
    e = store.get(src)
    if e is None:
        if len(store) >= SRC_MAX:
            return
        e = store[src] = [0, 0, 0, 0, 0]
    if is_ai:
        e[0] += nbytes
        e[2] += conns
    else:
        e[1] += nbytes
        e[3] += conns
    e[4] = int(time.time())


def src_compact(store, now=None):
    """کهنه‌ها حذف؛ اگر هنوز پر است فقط پرمصرف‌ترین‌ها (سه‌چهارمِ سقف) بمانند."""
    now = int(now if now is not None else time.time())
    for k in [k for k, e in store.items() if now - e[4] > SRC_IDLE]:
        del store[k]
    if len(store) >= SRC_MAX:
        keep = sorted(store.items(), key=lambda kv: kv[1][0] + kv[1][1],
                      reverse=True)[:SRC_MAX * 3 // 4]
        store.clear()
        store.update(keep)


def src_top(store, n=SRC_TOP):
    """برترین مبدأها بر پایه‌ی بایتِ AI (موضوعِ جدول «مصرفِ AI» است) →
    [[src, ai_bytes, direct_bytes, ai_conns, direct_conns], …]"""
    rows = sorted(store.items(), key=lambda kv: kv[1][0], reverse=True)[:n]
    return [[k, e[0], e[1], e[2], e[3]] for k, e in rows]


# ============================================================================
# پارسرِ SNI — منطقِ حساس، مستقلاً تست‌شونده
# ============================================================================
# وضعیت‌ها: ("ok", sni|None) پارس کامل شد (sni ممکن است None باشد = بدونِ SNI)
#           ("need_more", None) بایتِ بیشتری لازم است
#           ("bad", None) غیر-TLS/غیر-ClientHello — بی‌خیال شو (پیش‌فرض AI)

_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


def parse_client_hello_sni(buf):
    """SNI را از یک بافرِ خامِ TLS ClientHello درمی‌آورد.

    فقط با کتابخانهٔ استاندارد؛ در برابرِ بافرِ ناقص/مخدوش امن است.
    """
    try:
        n = len(buf)
        if n < 5:
            return ("need_more", None)
        # رکوردِ TLS: type(1) version(2) length(2)
        if buf[0] != 0x16:            # 0x16 = handshake
            return ("bad", None)
        rec_len = (buf[3] << 8) | buf[4]
        if rec_len == 0 or rec_len > HELLO_MAX:
            return ("bad", None)
        if n < 5 + rec_len:
            return ("need_more", None)
        hs = buf[5:5 + rec_len]
        m = len(hs)
        if m < 4 or hs[0] != 0x01:    # 0x01 = ClientHello
            return ("bad", None)
        # handshake header: type(1) length(3)
        p = 4
        p += 2                        # client_version
        p += 32                       # random
        if p + 1 > m:
            return ("bad", None)
        sid_len = hs[p]; p += 1 + sid_len
        if p + 2 > m:
            return ("bad", None)
        cs_len = (hs[p] << 8) | hs[p + 1]; p += 2 + cs_len
        if p + 1 > m:
            return ("bad", None)
        comp_len = hs[p]; p += 1 + comp_len
        if p + 2 > m:
            # بدونِ اکستنشن‌ها (TLS 1.0 خیلی قدیمی) → SNI ندارد
            return ("ok", None)
        ext_total = (hs[p] << 8) | hs[p + 1]; p += 2
        end = min(p + ext_total, m)
        while p + 4 <= end:
            etype = (hs[p] << 8) | hs[p + 1]
            elen = (hs[p + 2] << 8) | hs[p + 3]
            p += 4
            if etype == 0x0000:       # server_name
                q = p
                if q + 2 > m:
                    return ("bad", None)
                # list_len := hs[q:q+2] (نادیده)
                q += 2
                if q + 3 > m:
                    return ("bad", None)
                name_type = hs[q]; q += 1
                name_len = (hs[q] << 8) | hs[q + 1]; q += 2
                if name_type != 0 or q + name_len > m:
                    return ("bad", None)
                try:
                    host = bytes(hs[q:q + name_len]).decode("ascii").lower()
                except UnicodeDecodeError:
                    return ("bad", None)
                if not _HOST_RE.match(host):
                    return ("bad", None)
                return ("ok", host.rstrip("."))
            p += elen
        return ("ok", None)           # پارس کامل ولی بدونِ SNI
    except Exception:
        return ("bad", None)


# ============================================================================
# طبقه‌بندی: AI (→WARP) یا direct
# ============================================================================
def ech_present(buf):
    """آیا ClientHello اکستنشنِ Encrypted Client Hello (0xfe0d) دارد؟

    هشدارِ زودهنگام: با ECH، نامِ واقعی رمز می‌شود و SNIِ بیرونی یک نامِ
    عمومی/پوششی است — یعنی طبقه‌بندیِ SNIمحور کور می‌شود و ممکن است ترافیکِ
    AI به‌اشتباه «کولترال/مستقیم» برود. این تابع فقط تشخیص می‌دهد (تصمیمی
    نمی‌گیرد) تا پنل روندش را ببیند و قبل از شکایتِ کاربران هشدار بدهد.
    ساختارِ پیمایش همان parse_client_hello_sni است؛ در برابرِ بافرِ ناقص امن."""
    try:
        if len(buf) < 5 or buf[0] != 0x16:
            return False
        rec_len = (buf[3] << 8) | buf[4]
        if rec_len == 0 or len(buf) < 5 + rec_len:
            return False
        hs = buf[5:5 + rec_len]
        m = len(hs)
        if m < 4 or hs[0] != 0x01:
            return False
        p = 4 + 2 + 32                     # header + version + random
        if p + 1 > m:
            return False
        p += 1 + hs[p]                     # session_id
        if p + 2 > m:
            return False
        p += 2 + ((hs[p] << 8) | hs[p + 1])   # cipher_suites
        if p + 1 > m:
            return False
        p += 1 + hs[p]                     # compression
        if p + 2 > m:
            return False
        ext_total = (hs[p] << 8) | hs[p + 1]
        p += 2
        end = min(p + ext_total, m)
        while p + 4 <= end:
            etype = (hs[p] << 8) | hs[p + 1]
            elen = (hs[p + 2] << 8) | hs[p + 3]
            p += 4
            if etype == 0xfe0d:            # encrypted_client_hello (draft-13+)
                return True
            p += elen
        return False
    except Exception:
        return False


def classify(sni, ai_suffixes):
    """True یعنی AI (باید از WARP برود).

    fail-safe: بدونِ SNI/نامشخص → AI/WARP (رفتارِ امنِ امروز)."""
    if not sni:
        return True
    s = sni.lower().rstrip(".")
    for suf in ai_suffixes:
        if s == suf or s.endswith("." + suf):
            return True
    return False


def refresh_local_addrs():
    """آدرس‌های IPv4ِ محلی را از /proc/net/route و getifaddrs-وارِ ioctl-فری
    درمی‌آورد. اگر نشد، مجموعه خالی می‌ماند و فقط محافظِ پورت کار می‌کند."""
    addrs = set()
    try:
        import fcntl
        import struct
        import array
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            buf_size = 8192
            names = array.array("B", b"\0" * buf_size)
            outbytes = struct.unpack("iL", fcntl.ioctl(
                s.fileno(), 0x8912,  # SIOCGIFCONF
                struct.pack("iL", buf_size, names.buffer_info()[0])))[0]
            data = names.tobytes()[:outbytes]
            for i in range(0, len(data), 40):  # sizeof(struct ifreq) روی x86_64
                addrs.add(socket.inet_ntoa(data[i + 20:i + 24]))
        finally:
            s.close()
    except Exception:
        pass
    addrs.add("127.0.0.1")
    return addrs


def is_loop_target(orig_dst):
    """آیا این «مقصدِ اصلی» در واقع خودِ ما است؟ (اتصالِ غیر-TPROXY)"""
    if not orig_dst:
        return True
    host, port = orig_dst[0], orig_dst[1]
    if port == LISTEN_PORT:
        return True
    return host in LOCAL_ADDRS


def load_ai_suffixes(path):
    """دامنه‌های AI را از warp-targets.conf می‌خواند (فقط خطوطِ دامنه؛
    IP/رنج‌ها اینجا بی‌ربط‌اند چون تفکیک بر پایهٔ SNI است)."""
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                # IP یا رنج را رد کن — فقط دامنه معیارِ SNI است
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", line):
                    continue
                if "." in line and _HOST_RE.match(line):
                    out.append(line.lower().rstrip("."))
    except OSError:
        pass
    return out


# ============================================================================
# بازگردانیِ شمارنده‌ها بینِ اجراها — STATS_FILE فقط نوشته می‌شد
# ============================================================================
# فایلِ آمار هر ۳ ثانیه نوشته می‌شد ولی **هرگز خوانده نمی‌شد**: هر ری‌استارت
# — ارتقا، ری‌لود، OOM، کرش — همه‌ی شمارنده‌ها را صفر می‌کرد. جدولِ کشفِ
# دامنه دقیقاً روی همین انباشت ساخته شده (دامنه‌ای که باید AI باشد و
# «کولترال» دیده می‌شود فقط در طولِ زمان خودش را نشان می‌دهد — درسِ
# robinfrontend-pa و notebook.google.com)، پس ری‌استارت تحلیل را پاک می‌کرد
# بدونِ اینکه چیزی به اپراتور بگوید.
#
# ⚠️ **شمارنده‌ی تجمعیِ تازه به self.stats اضافه کردی ⇒ نامش را به _RESUMABLE
# هم اضافه کن**، وگرنه بی‌صدا با هر ری‌استارت صفر می‌شود. سنجه‌ی لحظه‌ای
# ⇒ _LIVE_GAUGES. تستِ StatsBaselineTests.test_every_stat_key_is_classified
# اجازه نمی‌دهد کلیدی در هیچ‌کدام نباشد.
_LIVE_GAUGES = (
    "started",        # زمانِ آغازِ **همین** پروسه
    "resumed",        # آیا این اجرا مبنای قبلی را برداشت؟
    "active",         # جریان‌های TCPِ زنده
    "quic_flows",     # جریان‌های QUICِ زنده
    "quic_fds",       # توصیف‌گرهای زنده‌ی QUIC (بازگردانی = ضربانِ ابدی-قطع)
    "quic_enabled",   # وضعِ همین اجرا
)

# شمارنده‌های تجمعی — صریح و نه merge ِ کور. یک merge ِ کور هم `active` را
# برمی‌گرداند (سنجه‌ی لحظه‌ای: مقدارِ کهنه محاسبه‌ی فضای fd در _beat را مسموم
# می‌کند) و هم کلیدهای نسخه‌های قدیمی‌تر را که دیگر وجود ندارند.
_RESUMABLE = (
    "counting_since",   # آغازِ انباشت (≠ آغازِ پروسه) — رجوع به __init__
    # TCP
    "ai_conns", "direct_conns", "ai_bytes", "direct_bytes",
    "no_sni", "parse_bad", "errors", "loop_blocked",
    "nosni_bytes", "ech_conns", "ech_bytes",
    # QUIC
    "quic_ai_conns", "quic_direct_conns", "quic_ai_bytes",
    "quic_direct_bytes", "quic_no_sni", "quic_bad", "quic_nosni_bytes",
    "quic_replies", "quic_rsfail", "quic_rerr",
    "quic_hello_multi", "quic_hello_giveup", "quic_hello_misrouted",
    "quic_hold_swap", "quic_hold_timeout", "quic_hold_dropped",
    "quic_hold_us_total",
)


def _load_stats(path=None):
    """(شمارنده‌ها، sni_stats، src_stats)ِ اجرای قبلی. خطا ⇒ خالی، نه استثنا.

    **فیل‌سافتِ مطلق.** این پروسه روی مسیرِ داده است؛ ناخوانا بودنِ یک فایلِ
    متریک هرگز نباید مانعِ بالا آمدنش شود — قطعیِ خودزده بدتر از شمارنده‌ی
    صفر است.

    جدولِ per-SNI/per-src از نمای **خلاصه‌ی** فایل بازسازی می‌شود (top_sni،
    top_sni_conns، top_src)، چون snapshot فقط همین‌ها را دارد: دنباله‌ی
    جدول (تا SNI_MAX ردیف) در فایل نیست و برنمی‌گردد. دو فهرستِ SNI با هم
    ادغام می‌شوند چون هرکدام روی یک محور (حجم/اتصال) بریده شده‌اند.
    """
    path = STATS_FILE if path is None else path
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
            mtime = os.fstat(f.fileno()).st_mtime
    except (OSError, ValueError):
        return {}, {}, {}
    if not isinstance(d, dict):
        return {}, {}, {}
    base = {}
    for k in _RESUMABLE:
        v = d.get(k)
        # bool زیرمجموعه‌ی int است — صریح ردش کن تا True به ۱ ترجمه نشود
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            continue
        base[k] = int(v)
    # مهرِ زمانیِ ردیف‌های بازگردانده‌شده = آخرین نوشتنِ فایل. خودِ snapshot
    # ستونِ زمان ندارد (sni_top/src_top دورش می‌ریزند) در حالی که انقضای این
    # دو جدول **زمان‌محور** است (SNI_IDLE/SRC_IDLE) — بی‌مهر، ردیفِ
    # بازگردانده‌شده هرگز نمی‌افتاد. mtime کرانِ بالای «آخرین دیده‌شدن» است:
    # ردیفی که پیش از کرش هم کهنه بود حداکثر یک دوره‌ی IDLE بیشتر می‌ماند،
    # نه ابدی. min با now جلوی mtimeِ آینده (انحرافِ ساعت) را می‌گیرد.
    ts = min(int(mtime), int(time.time()))
    sni = {}
    for key in ("top_sni", "top_sni_conns"):     # دو نمای همان یک جدول
        rows = d.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not (isinstance(row, list) and len(row) >= 4):
                continue
            name = row[0]
            if not isinstance(name, str) or name in sni:
                continue          # کلیدِ '' معتبر است (تجمیعِ بدونِ SNI)
            try:
                sni[name] = [int(row[1]), int(row[2]),
                             1 if row[3] else 0, ts]
            except (TypeError, ValueError):
                sni.pop(name, None)
    src = {}
    rows = d.get("top_src")
    if isinstance(rows, list):
        for row in rows:
            if not (isinstance(row, list) and len(row) >= 5):
                continue
            name = row[0]
            if not isinstance(name, str) or not name or name in src:
                continue
            try:
                src[name] = [int(row[1]), int(row[2]), int(row[3]),
                             int(row[4]), ts]
            except (TypeError, ValueError):
                src.pop(name, None)
    return base, sni, src


# ============================================================================
# دیتاپلینِ آسنکرون
# ============================================================================
class _FlowState:
    """وضعِ مشترکِ دو جهتِ یک جریانِ TCP — برای سقفِ عمر (ضدِ نشتِ fd).

    بینِ دو pipe مشترک است تا جریانی که فقط یک سمتش حرف می‌زند (دانلودِ
    یک‌طرفه) «بیکار» شمرده نشود؛ بیکاری یعنی سکوتِ هر دو جهت."""
    __slots__ = ("last", "eof")

    def __init__(self):
        self.last = time.monotonic()   # آخرین حرکتِ داده در هرکدام از دو جهت
        self.eof = False               # یک جهت EOF دیده (جریانِ نیمه‌بسته)


class Splitter:
    def __init__(self, loop):
        self.loop = loop
        self.ai_suffixes = []
        self._suf_mtime = 0
        self._suf_path = TARGETS_FILE
        # دامنه‌های «رفعِ جغرافیا» → مارکِ MARK_GEO (فهرستِ مستقل از AI)
        self.geo_suffixes = []
        self._geo_mtime = 0
        self._geo_path = GEO_TARGETS_FILE
        # آمار (برای کارتِ WARP در پنل)
        self.stats = {
            "started": int(time.time()),
            "ai_conns": 0, "direct_conns": 0,
            "ai_bytes": 0, "direct_bytes": 0,
            "no_sni": 0, "parse_bad": 0, "errors": 0,
            "active": 0, "loop_blocked": 0,
            # کوریِ طبقه‌بندی (هشدارِ زودهنگامِ ECH): بایتِ جریان‌های بی‌SNI
            # و جریان‌هایی که اکستنشنِ ECH دارند (SNIِ بیرونی = نامِ پوششی)
            "nosni_bytes": 0, "ech_conns": 0, "ech_bytes": 0,
            # QUIC/UDP (فقط اگر روشن باشد پُر می‌شود)
            "quic_ai_conns": 0, "quic_direct_conns": 0,
            "quic_ai_bytes": 0, "quic_direct_bytes": 0,
            "quic_no_sni": 0, "quic_bad": 0, "quic_flows": 0,
            # توصیف‌گرهای زنده‌ی QUIC (سوکتِ خروجی + سوکت‌های پاسخ) — سنجه‌ی
            # فضای fd در _beat به این نیاز دارد، چون هر دو در همان پروسه‌اند.
            "quic_fds": 0,
            "quic_nosni_bytes": 0,
            # ClientHelloِ چندپکتی: multi = کامل شد و نام درآمد ·
            # giveup = از کران رد شد یا جریان پیش از کامل‌شدن مرد ·
            # misrouted = نامِ کامل «غیر-AI» بود ولی جریان از قبل به WARP
            # سپرده شده بود ⇒ سهمِ عددیِ همین باگ در ترافیکِ WARP.
            "quic_hello_multi": 0, "quic_hello_giveup": 0,
            "quic_hello_misrouted": 0,
            # نگه‌داری (پلنِ ۰۶۶): swap = مارک واقعاً عوض شد ·
            # timeout = نام نیامد و مهلت تمام شد · dropped = دیتاگرامِ
            # صف‌شده‌ای که با مرگِ جریان هرگز نرفت (بایتش هم حساب نشد) ·
            # us_total = مجموعِ زمانِ نگه‌داری، تا هزینه سنجیده شود نه بحث.
            "quic_hold_swap": 0, "quic_hold_timeout": 0,
            "quic_hold_dropped": 0, "quic_hold_us_total": 0,
            "quic_enabled": False,
            # سلامتِ مسیرِ بازگشت (source-spoofing): replies باید بالا برود؛
            # rsfail>0 یعنی bindِ سوکتِ پاسخ شکست خورده (مثلاً کمبودِ
            # CAP_NET_BIND_SERVICE) → پاسخِ QUIC به کاربر نمی‌رسد.
            "quic_replies": 0, "quic_rsfail": 0, "quic_rerr": 0,
        }
        # مبنای اجرای قبلی (رجوع به _load_stats). سه فیلد، سه معنیِ متفاوت —
        # و همین سه‌تایی است که «از استارت» را صادق نگه می‌دارد بدونِ اینکه
        # نرخ‌ها با مجموعِ بازگردانده‌شده جور در نیایند:
        #   started        = این پروسه کِی بالا آمد (معنایش عوض نشده)
        #   counting_since = انباشتِ شمارنده‌ها از کِی شروع شده (بقا دارد)
        #   resumed        = این اجرا مبنای قبلی را برداشت یا از صفر شروع کرد
        _base, _sni, _src = _load_stats()
        self.stats.update(_base)
        self.stats["counting_since"] = int(
            _base.get("counting_since") or self.stats["started"])
        self.stats["resumed"] = bool(_base)
        # جدولِ per-SNI (کشفِ دامنه) — بینِ نخِ TCP (asyncio) و نخِ QUIC
        # مشترک است؛ مثل خودِ stats، عملیاتِ دیکشنری زیرِ GIL برای شمارنده
        # کافی است (دقتِ مطلق لازم نیست، دید لازم است).
        self.sni_stats = _sni
        # جدولِ per-src (مصرفِ AI به تفکیکِ کاربر) — همان الگوی اشتراک
        self.src_stats = _src
        # لچِ ضربان (رجوع به _beat): بعد از EMFILE قطع می‌ماند تا فضای واقعی
        self._hb_block = False
        self.reload_suffixes(force=True)

    # ---- بارگذاریِ فهرستِ AI با تشخیصِ تغییر ----
    def reload_suffixes(self, force=False):
        try:
            mt = os.path.getmtime(self._suf_path)
        except OSError:
            mt = 0
        if force or mt != self._suf_mtime:
            self.ai_suffixes = load_ai_suffixes(self._suf_path)
            self._suf_mtime = mt
        # فهرستِ رفعِ جغرافیا — همان قالب و همان بارگذار، فایلِ جدا
        try:
            gmt = os.path.getmtime(self._geo_path)
        except OSError:
            gmt = 0
        if force or gmt != self._geo_mtime:
            self.geo_suffixes = load_ai_suffixes(self._geo_path)
            self._geo_mtime = gmt

    # ---- خواندنِ ClientHello تا حدِ کافی برای SNI ----
    async def read_client_hello(self, sock):
        buf = bytearray()
        deadline = self.loop.time() + HELLO_TIMEOUT
        while True:
            timeout = deadline - self.loop.time()
            if timeout <= 0:
                return buf, ("bad", None)
            try:
                chunk = await asyncio.wait_for(
                    self.loop.sock_recv(sock, BUF), timeout)
            except (asyncio.TimeoutError, OSError):
                return buf, ("bad", None)
            if not chunk:
                return buf, ("bad", None)
            buf += chunk
            status, sni = parse_client_hello_sni(buf)
            if status != "need_more":
                return buf, (status, sni)
            if len(buf) >= HELLO_MAX:
                return buf, ("bad", None)

    # ---- سوکتِ خروجی با مارکِ درست ----
    def make_upstream(self, mark):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
        s.setblocking(False)
        return s

    # ---- رله‌ی یک‌طرفه ----
    async def pipe(self, src, dst, counter=None, flow=None):
        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        self.loop.sock_recv(src, BUF), PIPE_POLL)
                except asyncio.TimeoutError:
                    if flow is None:
                        continue
                    limit = HALF_CLOSE_GRACE if flow.eof else IDLE_TIMEOUT
                    if time.monotonic() - flow.last > limit:
                        break
                    continue
                if not data:
                    if flow is not None:
                        flow.eof = True
                        flow.last = time.monotonic()
                    break
                if flow is not None:
                    flow.last = time.monotonic()
                await asyncio.wait_for(
                    self.loop.sock_sendall(dst, data), SEND_TIMEOUT)
                if counter is not None:
                    counter[0] += len(data)
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    # ---- مدیریتِ یک اتصال ----
    async def handle(self, client):
        self.stats["active"] += 1
        upstream = None
        try:
            try:
                orig_dst = client.getsockname()   # با TPROXY = مقصدِ اصلی
            except OSError:
                return
            # اتصالی که با TPROXY منحرف نشده (مثلاً اسکنِ مستقیمِ پورتِ 8445)
            # مقصدِ اصلی ندارد؛ وصل‌شدن به آن یعنی وصل‌شدن به خودمان.
            if is_loop_target(orig_dst):
                self.stats["loop_blocked"] += 1
                return
            try:
                peer_ip = client.getpeername()[0]   # IPِ واقعیِ کاربر (TPROXY)
            except OSError:
                peer_ip = ""
            client.setblocking(False)
            hello, (status, sni) = await self.read_client_hello(client)
            is_ai = classify(sni, self.ai_suffixes)
            # geo فقط وقتی AI نبود و SNI هست (بی‌SNI ⇒ AI/WARP، دست‌نخورده)
            is_geo = (not is_ai) and classify(sni, self.geo_suffixes)
            no_sni_flow = (status == "ok" and sni is None)
            ech_flow = (status == "ok" and ech_present(hello))
            if no_sni_flow:
                self.stats["no_sni"] += 1
            elif status == "bad":
                self.stats["parse_bad"] += 1
            if ech_flow:
                self.stats["ech_conns"] += 1
            mark = ai_mark_for(peer_ip) if is_ai \
                else (MARK_GEO if is_geo else MARK_DIRECT)
            upstream = self.make_upstream(mark)
            try:
                await asyncio.wait_for(
                    self.loop.sock_connect(upstream, orig_dst),
                    CONNECT_TIMEOUT)
            except (asyncio.TimeoutError, OSError):
                self.stats["errors"] += 1
                return
            # بایت‌های ClientHelloِ بافرشده را اول بفرست
            if hello:
                try:
                    await self.loop.sock_sendall(upstream, bytes(hello))
                except OSError:
                    self.stats["errors"] += 1
                    return
            if is_ai:
                self.stats["ai_conns"] += 1
                cU = [0]; cD = [0]
            else:
                self.stats["direct_conns"] += 1
                cU = [0]; cD = [0]
            flow = _FlowState()
            await asyncio.gather(
                self.pipe(client, upstream, cU, flow),
                self.pipe(upstream, client, cD, flow),
                return_exceptions=True,
            )
            total = cU[0] + cD[0] + len(hello)
            if is_ai:
                self.stats["ai_bytes"] += total
            else:
                self.stats["direct_bytes"] += total
            if no_sni_flow:
                self.stats["nosni_bytes"] += total
            if ech_flow:
                self.stats["ech_bytes"] += total
            sni_note(self.sni_stats, sni, total, 1, is_ai)
            src_note(self.src_stats, peer_ip, total, 1, is_ai)
        except Exception:
            self.stats["errors"] += 1
        finally:
            self.stats["active"] -= 1
            for s in (client, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    # ---- نگهبان: heartbeat + آمار + بارگذاریِ مجددِ فهرست ----
    def _beat(self):
        """ضربانِ سلامت — صادق و لچ‌دار در برابرِ اشباعِ fd.

        دیمنی که fd ندارد accept هم نمی‌تواند بکند؛ پس در EMFILE «ناسالم»
        دیده‌شدنش درست است (fail-openِ warp-guard کاربران را نجات می‌دهد).
        چیزی که در حادثه‌ی ۲۰۲۶-۰۷-۲۱ غلط بود flap بود: با بسته‌شدنِ
        اتفاقیِ یکی‌دو جریان، openِ ضربان لحظه‌ای موفق می‌شد → گارد TPROXY
        را برمی‌گرداند → دوباره اشباع → هر ~۴۵ ثانیه قطع/وصل و رگبارِ
        هشدارِ تلگرام. این‌جا بعد از اولین EMFILE ضربان *قطع می‌ماند* تا
        وقتی شمارِ جریان‌های باز نشان دهد فضای واقعی برگشته، نه شانسی.
        """
        if self._hb_block:
            try:
                soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            except (OSError, ValueError):
                soft = 1024
            # جریان‌های QUIC هم fd می‌گیرند و در همان پروسه و همان
            # RLIMIT_NOFILE‌اند. پیش از این فقط TCP شمرده می‌شد، پس این
            # سنجه کم‌برآورد می‌کرد و ضربان زودتر از موعد از لچ درمی‌آمد —
            # یعنی دقیقاً همان flapی که این لچ برای پایان‌دادنش نوشته شده.
            #
            # دو برآورد، محافظه‌کارانه‌ترش برنده: quic_fds شمارشِ **دقیقِ**
            # زنده است (up + reply_socks)، ولی در حالتِ عادی
            # quic_flows*QUIC_FD_PER_FLOW بزرگ‌تر است چون سوکتِ پاسخ بینِ
            # جریان‌های هم‌مقصد مشترک می‌شود. عکسش هم ممکن است: سوکتِ پاسخ
            # تا جاروی بعدی (≤۱۰ث) پس از آخرین جریانش زنده می‌ماند، پس در
            # لحظه‌ی تخلیه شمارشِ جریان‌محور کم می‌آورد. max هر دو سوراخ را
            # می‌بندد.
            quic = max(self.stats.get("quic_fds", 0),
                       self.stats.get("quic_flows", 0) * QUIC_FD_PER_FLOW)
            if self.stats["active"] * 2 + quic + 64 >= soft:
                return
            self._hb_block = False
            # این خط در ژورنال تنها ردِ فارنزیکِ «چرا لچ باز شد» است.
            sys.stderr.write("heartbeat resumed: fd headroom back "
                             "(active=%d quic_flows=%d quic_fds=%d)\n"
                             % (self.stats["active"],
                                self.stats.get("quic_flows", 0), quic))
        tmp = HEARTBEAT_FILE + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("%d\n" % int(time.time()))
            os.replace(tmp, HEARTBEAT_FILE)
        except OSError as e:
            if e.errno in (errno.EMFILE, errno.ENFILE):
                self._hb_block = True
                sys.stderr.write("heartbeat blocked: fd exhausted (%r, "
                                 "active=%d)\n" % (e, self.stats["active"]))
                # سیگنال را قطعی کن: unlink فایل fd نمی‌خواهد؛ نبودِ فایل
                # برای warp-guard یعنی «ناسالم» بدونِ ابهامِ کهنگی.
                try:
                    os.unlink(HEARTBEAT_FILE)
                except OSError:
                    pass
            else:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    async def housekeeping(self):
        n = 0
        while True:
            # ضربان پیش از هر کارِ دیگر: خطای بقیه‌ی کارها (مثلاً EMFILE در
            # بارگذاریِ فهرست) نباید مانعِ منطقِ صادقانه‌ی ضربان شود.
            self._beat()
            try:
                self.reload_suffixes()
                n += 1
                if n % 20 == 0:      # هر ~۶۰ث: آدرس‌های محلی ممکن است عوض شوند
                    global LOCAL_ADDRS
                    LOCAL_ADDRS = refresh_local_addrs()
                sni_compact(self.sni_stats)
                src_compact(self.src_stats)
                snap = dict(self.stats)
                snap["ai_suffixes"] = len(self.ai_suffixes)
                snap["geo_suffixes"] = len(self.geo_suffixes)
                snap["top_sni"] = sni_top(self.sni_stats)
                snap["top_sni_conns"] = sni_top_conns(self.sni_stats)
                snap["top_src"] = src_top(self.src_stats)
                snap["ai_by_mark"] = ai_by_mark(self.src_stats)
                _atomic_write(STATS_FILE, json.dumps(snap))
            except Exception:
                pass
            await asyncio.sleep(3)

    # ---- حلقهٔ accept ----
    async def serve(self, listen_sock):
        while True:
            try:
                client, _addr = await self.loop.sock_accept(listen_sock)
            except OSError:
                await asyncio.sleep(0.05)
                continue
            self.loop.create_task(self.handle(client))


class _QuicFlow:
    __slots__ = ("up", "orig_dst", "client", "last", "is_ai", "decided",
                 "sni", "nosni", "blind", "pend", "pend_bytes", "pend_pkts",
                 "mark", "counted", "held", "held_bytes", "held_since")

    def __init__(self, up, orig_dst, client):
        self.up = up               # سوکتِ UDPِ خروجی (SO_MARK، connect به مقصد)
        self.orig_dst = orig_dst   # (ip, 443)
        self.client = client       # (ip, port)ِ کاربر
        self.last = time.monotonic()
        self.is_ai = None
        self.decided = False
        self.sni = None            # برای شمارنده‌ی per-SNI (کشفِ دامنه)
        self.nosni = False         # جریانِ بی‌SNI (سهمِ کوریِ طبقه‌بندی)
        # «نامش قطعی نشد» — جدا از nosni که فقط حسابداریِ بایت است و
        # `bad` را نمی‌گیرد. مقصدِ این‌ها QUIC_BLIND_GEO تعیین می‌کند.
        self.blind = False
        # انباشتِ CRYPTOِ ClientHelloِ چندپکتی. None = «چیزی در جریان نیست»
        # (حالتِ رایج). حالتِ جریان اینجاست نه در quic_sni: آن ماژول عمداً
        # بی‌حالت و بی‌وابستگی است و ممکن است اصلاً نصب نباشد.
        self.pend = None           # {offset: bytes} یا None
        self.pend_bytes = 0
        self.pend_pkts = 0
        # ---- نگه‌داری تا روشن‌شدنِ نام (پلنِ ۰۶۶) ----
        # این پنج تا یک عمرِ مشترک دارند و با هم پاک می‌شوند.
        self.mark = None           # مارکی که سوکتِ فعلی با آن ساخته شد
        self.counted = False       # شمارشِ اتصال انجام شده؟ (یک‌بار، نه بیشتر)
        self.held = None           # None = نگه‌داری فعال نیست · [] = در حالِ صف
        self.held_bytes = 0
        self.held_since = 0.0      # time.monotonic() ِ نخستین دیتاگرامِ صف


class QuicSplitter(threading.Thread):
    """تفکیکِ QUIC (UDP/443) بر پایهٔ SNI — نخِ مستقل با selectors.

    برخلافِ TCP، اینجا SNI در همان **اولین دیتاگرام** (QUIC Initial) است، پس
    نیازی به «صبر تا بعد از handshake» نیست. رمزگشاییِ Initial با کلیدهایی که
    فقط از Connection ID مشتق می‌شوند (عمومی، RFC 9001) انجام و SNI خوانده
    می‌شود. سپس مثلِ TCP: AI → SO_MARK 0x77 (WARP)، بقیه → 0x78 (مستقیم).

    مسیرِ بازگشت (transparent): پاسخِ سرور باید با مبدأِ «مقصدِ اصلی:۴۴۳» به
    کاربر برسد، پس یک سوکتِ IP_TRANSPARENT که به همان (ip,443) bind شده به‌ازای
    هر مقصد نگه می‌داریم و پاسخ‌ها را از آن sendto می‌کنیم.

    fail-open در سطحِ سیستم: اگر این نخ/دیمن بمیرد، sync/گارد قاعدهٔ NFQUEUE…
    نه — برای QUIC، قاعدهٔ TPROXY حذف و قاعدهٔ REJECTِ قدیمی برمی‌گردد →
    مرورگر به TCP برمی‌گردد (رفتارِ امنِ امروز). این‌جا فقط دیتاپلین است.
    """

    def __init__(self, port, stats, get_suffixes, sni_stats=None,
                 src_stats=None, get_geo_suffixes=None):
        super().__init__(daemon=True)
        self.port = port
        self.stats = stats
        self.get_suffixes = get_suffixes      # callable → فهرستِ AI (زنده)
        self.get_geo_suffixes = get_geo_suffixes or (lambda: [])  # → فهرستِ geo
        self.sni_stats = sni_stats if sni_stats is not None else {}
        self.src_stats = src_stats if src_stats is not None else {}
        self.sel = selectors.DefaultSelector()
        self.flows = {}                       # (client, orig_dst) -> _QuicFlow
        self.up_index = {}                    # fileno(up) -> flow
        self.reply_socks = {}                 # orig_dst -> transparent sender
        self._last_sweep = time.monotonic()

    def _note_fds(self):
        """شمارِ جریان‌ها و **توصیف‌گرهای زنده‌ی** QUIC را منتشر می‌کند.

        _beat به این عدد نیاز دارد: هر دو مؤلفه در همان پروسه و همان
        RLIMIT_NOFILE‌اند، پس شمردنِ فقط TCP در سنجه‌ی فضای fd کم‌برآورد
        می‌کرد. سوکتِ پاسخ **به‌ازای هر مقصد** است نه هر جریان، پس ضریبِ
        ثابت (QUIC_FD_PER_FLOW) کرانِ بالاست و این عدد مقدارِ دقیق.
        """
        self.stats["quic_flows"] = len(self.flows)
        self.stats["quic_fds"] = len(self.flows) + len(self.reply_socks)

    # ---- سوکتِ ارسالِ پاسخ با مبدأِ جعلیِ (مقصد:۴۴۳) ----
    def _reply_sock(self, orig_dst):
        s = self.reply_socks.get(orig_dst)
        if s is not None:
            return s
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(SOL_IP, IP_TRANSPARENT_OPT, 1)
            s.bind(orig_dst)                  # bind به آدرسِ غیرمحلی (transparent)
            s.setblocking(False)
        except OSError:
            return None
        self.reply_socks[orig_dst] = s
        self._note_fds()
        return s

    def _make_listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(SOL_IP, IP_TRANSPARENT_OPT, 1)
        # برای گرفتنِ مقصدِ اصلیِ هر دیتاگرامِ منحرف‌شده با TPROXY
        s.setsockopt(SOL_IP, IP_ORIGDSTADDR, 1)
        s.bind((LISTEN_HOST, self.port))
        s.setblocking(False)
        return s

    @staticmethod
    def _parse_origdst(ancdata):
        for lvl, typ, data in ancdata:
            if lvl == SOL_IP and typ == IP_ORIGDSTADDR and len(data) >= 8:
                port = struct.unpack_from("!H", data, 2)[0]
                ip = socket.inet_ntoa(data[4:8])
                return (ip, port)
        return None

    def _classify_initial(self, data):
        """(is_ai, tag, sni) — tag برای شمارنده. fail-safe: ابهام → AI/WARP."""
        if quic_sni is None:
            return True, "no_sni", None
        try:
            st, sni = quic_sni.sni_from_initial(data, parse_client_hello_sni)
        except Exception:
            return True, "bad", None
        if st == "ok" and sni:
            return classify(sni, self.get_suffixes()), "ok", sni
        if st == "ok":
            return True, "no_sni", None    # بدونِ SNI → AI (رفتارِ امنِ امروز)
        if st == "need_more" and QUIC_REASSEMBLY:
            # ClientHello هنوز کامل نشده (چندپکتی). تصمیمِ همین لحظه فرق
            # نمی‌کند — fail-open به WARP، دقیقاً مثل قبل — ولی این حالت
            # دیگر با «پارس نشد» یکی گرفته نمی‌شود تا دیتاگرامِ بعدی فرصتِ
            # کامل‌کردنش را داشته باشد.
            return True, "need_more", None
        return True, "bad", None           # پارس نشد → AI

    def _new_flow(self, data, client, orig_dst):
        is_ai, tag, sni = self._classify_initial(data)
        if tag == "no_sni":
            self.stats["quic_no_sni"] += 1
        elif tag == "bad":
            self.stats["quic_bad"] += 1
        # geo فقط با SNIِ واقعی و وقتی AI نیست. جریانِ بی‌نام (no_sni/bad)
        # is_ai=True می‌گیرد ولی مقصدش دیگر استخرِ AI نیست — رجوع به
        # QUIC_BLIND_GEO. `need_more` اینجا blind **نیست**: هنوز فرصتِ
        # روشن‌شدنِ نام را دارد و نگه‌داری همان را می‌سنجد.
        blind = tag in ("no_sni", "bad")
        is_geo = (not is_ai) and bool(sni) and classify(sni, self.get_geo_suffixes())
        if is_ai and blind and QUIC_BLIND_GEO:
            mark = MARK_GEO
        elif is_ai:
            mark = ai_mark_for(client[0])
        else:
            mark = MARK_GEO if is_geo else MARK_DIRECT
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
            up.setblocking(False)
            up.connect(orig_dst)
        except OSError:
            self.stats["errors"] += 1
            return None
        fl = _QuicFlow(up, orig_dst, client)
        fl.is_ai = is_ai
        fl.decided = True
        fl.mark = mark
        fl.sni = sni
        fl.nosni = (tag == "no_sni")
        fl.blind = blind
        self.flows[(client, orig_dst)] = fl
        self.up_index[up.fileno()] = fl
        self.sel.register(up, selectors.EVENT_READ, ("up", fl))
        self._note_fds()
        # شمارشِ اتصال وقتی نگه‌داری فعال است تا **پس از** روشن‌شدنِ نام عقب
        # می‌افتد. بدونِ این، جریانی که fail-open به AI شمرده شده و بعد
        # مستقیم می‌رود، quic_ai_conns را برای همیشه بالا نگه می‌دارد — و
        # همان نسبتی که پلنِ ۰۶۶ روی آن بنا شده دروغ می‌شود.
        if not (tag == "need_more" and self._holding(fl)):
            self._count_conn(fl)
        if tag == "need_more":
            # ClientHelloِ چندپکتی. **مسیر و فوروارد عوض نمی‌شوند** — همان
            # fail-openِ امروز به WARP — ولی شمارشِ اتصال و ثبتِ per-SNI تا
            # روشن‌شدنِ نام عقب می‌افتد تا زیرِ کلیدِ «بی‌SNI» ثبت نشود و
            # جدولِ کشفِ دامنه دروغ نگوید.
            self._begin_hello(fl, data)
        else:
            sni_note(self.sni_stats, sni, 0, 1, is_ai)
            src_note(self.src_stats, client[0], 0, 1, is_ai)
        return fl

    # ---- نگه‌داری تا روشن‌شدنِ نام (پلنِ ۰۶۶) ----
    # چرا اصلاً: تا پیش از این، مارک هنگامِ ساختِ سوکت پخته می‌شد و پکتِ اول
    # فوراً می‌رفت، پس وقتی نام چند میلی‌ثانیه بعد روشن می‌شد دیگر کاری از
    # دست برنمی‌آمد. سنجشِ ۱۵ اوت ۲۰۲۶: ۳۰۲ از ۳۵۰ جریانِ سپرده‌شده به WARP
    # (~۸۶٪) اصلاً AI نبودند.
    #
    # چرا «نگه‌داری» و نه دو راهِ دیگر:
    #   • عوض‌کردنِ SO_MARK روی سوکتِ connect‌شده آدرسِ مبدأ را نگه می‌دارد
    #     (connect آن را bind کرده و setsockopt دوباره bind نمی‌کند) ⇒ بسته
    #     با مبدأِ مسیرِ قبلی از اینترفیسِ جدید بیرون می‌رود ⇒ rp_filter.
    #   • بازساختِ سوکت **پس از** رفتنِ پکتِ اول یعنی connection migration،
    #     که RFC 9000 §9 پیش از تأییدِ handshake ممنوعش کرده.
    # پس تنها راهِ سازگار این است که هیچ چیز از میزبان خارج نشود تا نام
    # روشن شود — سرور از همان پکتِ اول یک چهارتاییِ ثابت می‌بیند.

    def _holding(self, fl):
        """آیا برای این جریان نگه‌داری معنا دارد؟

        `fl.up is None` در فیکسچرهای تست رخ می‌دهد (جریانِ بی‌سوکت). آنجا
        چیزی برای «نفرستادن» وجود ندارد، پس نگه‌داری هم آغاز نمی‌شود و
        مسیرِ پیش از ۰۶۶ دست‌نخورده می‌ماند.
        """
        return QUIC_HOLD and fl.up is not None

    def _count_conn(self, fl):
        """شمارشِ اتصال — دقیقاً یک بار در عمرِ هر جریان."""
        if fl.counted:
            return
        fl.counted = True
        if fl.is_ai:
            self.stats["quic_ai_conns"] += 1
        else:
            self.stats["quic_direct_conns"] += 1

    def _account_out(self, fl, n):
        """حسابداریِ بایتِ خروجی — از دو جا صدا زده می‌شود (ارسالِ مستقیم و
        تخلیه‌ی صف)، پس اینجا یکجا شده تا از هم جدا نیفتند."""
        if fl.is_ai:
            self.stats["quic_ai_bytes"] += n
        else:
            self.stats["quic_direct_bytes"] += n
        if fl.nosni:
            self.stats["quic_nosni_bytes"] += n
        sni_note(self.sni_stats, fl.sni, n, 0, fl.is_ai)
        src_note(self.src_stats, fl.client[0], n, 0, fl.is_ai)

    def _hold_datagram(self, fl, data):
        """دیتاگرام را به صف می‌برد. کران که رد شد ⇒ تخلیه‌ی fail-open.

        بایت **اینجا** حساب نمی‌شود: تا مارکِ نهایی معلوم نشود معلوم نیست
        به کدام ستون بخورد. حساب در _flush_held انجام می‌شود.
        """
        if fl.held_since == 0.0:
            fl.held_since = time.monotonic()
        if (len(fl.held) >= QUIC_HELLO_PKTS
                or fl.held_bytes + len(data) > QUIC_HELLO_MAX):
            self._giveup_hello(fl)      # خودش تخلیه می‌کند
            return False                # این دیتاگرام صف نشد ⇒ عادی بفرست
        fl.held.append(data)
        fl.held_bytes += len(data)
        return True

    def _mark_for(self, fl):
        """مارکِ درست بر پایه‌ی نامِ **کامل**؛ همان منطقِ _new_flow.

        گیتِ geo هم باید دوباره حساب شود، وگرنه دامنه‌ی geo از AI به
        DIRECT می‌افتد — یعنی رفعِ یک بدمسیری با ساختنِ یکی دیگر.
        """
        if fl.is_ai:
            # نام قطعی نشد ⇒ انتخابِ استخر کور بود؛ به geo برو (QUIC_BLIND_GEO).
            # این پیش از چسبندگیِ per-user می‌آید چون چسبندگی برای حفظِ
            # **هویتِ** کاربر روی یک خروجیِ AI است، و جریانِ بی‌نام اصلاً
            # قرار نیست روی خروجیِ AI بنشیند.
            if fl.blind and QUIC_BLIND_GEO:
                return MARK_GEO
            # همان کاربر ⇒ همان مارک. تصحیحِ تصمیم نباید خروجیِ کاربر را
            # جابه‌جا کند، وگرنه هدفِ چسبندگیِ per-user نقض می‌شود.
            return ai_mark_for(fl.client[0])
        if fl.sni and classify(fl.sni, self.get_geo_suffixes()):
            return MARK_GEO
        return MARK_DIRECT

    def _reopen_up(self, fl, mark):
        """سوکتِ خروجی را با مارکِ تازه بازمی‌سازد. False = جریان بسته شد.

        نشتِ fd اینجا همان چیزی است که حادثه‌ی ۲۰۲۱-۰۷ را ساخت، پس هر
        مسیرِ خطا باید ثبتِ selector و up_index را هم پاک کند نه فقط سوکت را.
        """
        old = fl.up
        try:
            self.sel.unregister(old)
        except (KeyError, ValueError):
            pass
        self.up_index.pop(old.fileno(), None)
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
            up.setblocking(False)
            up.connect(fl.orig_dst)
        except OSError:
            self.stats["errors"] += 1
            try:
                old.close()
            except OSError:
                pass
            self.flows.pop((fl.client, fl.orig_dst), None)
            self._note_fds()
            return False
        try:
            old.close()
        except OSError:
            pass
        fl.up = up
        fl.mark = mark
        self.up_index[up.fileno()] = fl
        self.sel.register(up, selectors.EVENT_READ, ("up", fl))
        self._note_fds()
        self.stats["quic_hold_swap"] += 1
        return True

    def _flush_held(self, fl):
        """صف را با مارکِ نهایی می‌فرستد و نگه‌داری را می‌بندد."""
        if fl.held is None:
            return
        queued, fl.held = fl.held, None
        if fl.held_since:
            self.stats["quic_hold_us_total"] += int(
                (time.monotonic() - fl.held_since) * 1e6)
        fl.held_bytes = 0
        fl.held_since = 0.0
        if not queued:
            return
        want = self._mark_for(fl)
        if want != fl.mark and not self._reopen_up(fl, want):
            return                      # جریان بسته شد؛ صف عمداً دور ریخته شد
        for d in queued:
            try:
                fl.up.send(d)
            except OSError:
                self._close_flow(fl)
                return
            self._account_out(fl, len(d))

    def _flush_expired_holds(self, now):
        """جریانی که نامش نیامد نباید بیش از QUIC_HOLD_MS منتظر بماند.

        گیت روی `self.flows` است نه `stats["quic_flows"]`: دومی یک گیجِ
        **منتشرشده** است که _note_fds به‌روزش می‌کند، و اگر کهنه یا صفر
        بماند مهلت‌ها هرگز منقضی نمی‌شوند — همان خانواده‌ی «سنجه را با
        منبعِ حقیقت اشتباه گرفتن» که پلنِ ۰۴۹ درباره‌اش بود. تستِ
        test_a_flow_held_past_the_deadline_is_flushed این را گرفت.
        """
        if not self.flows:
            return
        lim = QUIC_HOLD_MS / 1000.0
        for fl in list(self.flows.values()):
            if fl.held is not None and fl.held_since and now - fl.held_since > lim:
                self.stats["quic_hold_timeout"] += 1
                self._giveup_hello(fl)

    def _hold_deadline(self, now):
        """نزدیک‌ترین مهلتِ نگه‌داری، برای تنظیمِ timeoutِ select.

        بدونِ این، مهلت را _sweep می‌سنجید که هر ۱۰ ثانیه می‌دود و
        select هم timeout=5 دارد — یعنی «۲۵۰ میلی‌ثانیه» عملاً تا ۱۰
        ثانیه می‌شد. این تصحیحِ خودِ پلن است (گامِ ۵).
        """
        best = None
        for fl in self.flows.values():
            if fl.held is not None and fl.held_since:
                d = fl.held_since + QUIC_HOLD_MS / 1000.0 - now
                if best is None or d < best:
                    best = d
        return best

    # ---- ClientHelloِ پخش‌شده در چند پکتِ Initial ----
    # با X25519MLKEM768 (پیش‌فرضِ کروم و فایرفاکسِ امروز) ClientHello از سقفِ
    # ~۱۲۰۰ بایتیِ پیلودِ Initial رد می‌شود و در دو پکت می‌آید. quic_sni فقط
    # داخلِ **یک** دیتاگرام بازآرایی می‌کرد، پس اگر SNI در پکتِ دوم می‌افتاد
    # جریان بی‌نام می‌ماند و بی‌سروصدا fail-open به WARP می‌رفت — و در
    # جدولِ کشفِ دامنه هم زیرِ «بدونِ SNI» ثبت می‌شد، یعنی همان دامنه‌ای که
    # این جدول برای پیدا کردنش ساخته شده نامرئی می‌ماند.
    def _begin_hello(self, fl, data):
        crypto = quic_sni.crypto_from_datagram(data) if quic_sni else None
        fl.pend = {}
        # صف **پیش از** تلاشِ حل باز می‌شود: اگر همین‌جا حل شود،
        # _flush_held صفِ خالی را می‌بندد و دیتاگرام عادی می‌رود.
        if self._holding(fl):
            fl.held = []
        if not crypto:
            self._giveup_hello(fl)
            return
        self._feed_hello(fl, crypto)

    def _continue_hello(self, fl, data):
        crypto = quic_sni.crypto_from_datagram(data) if quic_sni else None
        if crypto is None:
            # دیتاگرامِ غیر-Initial یا با کلیدِ دیگر (DCIDِ عوض‌شده/Retry):
            # دستِ handshake رد شده و نامِ کامل دیگر نمی‌آید.
            self._giveup_hello(fl)
            return
        self._feed_hello(fl, crypto)

    def _feed_hello(self, fl, crypto):
        """نگاشتِ تازه را ادغام و تلاشِ حل می‌کند — با هر سه کران."""
        if quic_sni is None:               # ماژول نصب نیست ⇒ QUIC خاموش
            self._giveup_hello(fl)
            return
        fl.pend_pkts += 1
        for off, chunk in crypto.items():
            if off in fl.pend:
                continue
            if (len(fl.pend) >= QUIC_HELLO_FRAMES
                    or fl.pend_bytes + len(chunk) > QUIC_HELLO_MAX):
                self._giveup_hello(fl)
                return
            fl.pend[off] = chunk
            fl.pend_bytes += len(chunk)
        st, sni = quic_sni.sni_from_crypto(fl.pend, parse_client_hello_sni)
        if st == "need_more":
            if fl.pend_pkts >= QUIC_HELLO_PKTS:
                self._giveup_hello(fl)
            return
        self._resolve_hello(fl, st, sni)

    def _resolve_hello(self, fl, st, sni):
        fl.pend = None
        fl.pend_bytes = 0
        if not (st == "ok" and sni):
            self._blind_hello(fl, "quic_bad" if st == "bad" else "quic_no_sni")
            return
        fl.sni = sni
        fl.blind = False           # نام روشن شد ⇒ تصمیم دیگر کور نیست
        self.stats["quic_hello_multi"] += 1
        # آیا تصمیمِ fail-open با نامِ کامل فرق می‌کرد؟ این عدد سهمِ همین
        # باگ در ترافیکِ WARP را می‌سنجد. **پیش از** به‌روزکردنِ is_ai
        # خوانده می‌شود تا معنایش عوض نشود: «چند جریان با تصمیمِ کور به
        # WARP می‌رفتند» — حتی وقتی نگه‌داری جلویش را گرفته باشد.
        really_ai = classify(sni, self.get_suffixes())
        if not really_ai:
            self.stats["quic_hello_misrouted"] += 1
        if fl.held is not None:
            # نگه‌داری فعال است ⇒ هنوز چیزی نرفته ⇒ تصمیم را **اصلاح** کن.
            fl.is_ai = bool(really_ai)
        self._count_conn(fl)
        sni_note(self.sni_stats, sni, 0, 1, fl.is_ai)
        src_note(self.src_stats, fl.client[0], 0, 1, fl.is_ai)
        self._flush_held(fl)

    def _giveup_hello(self, fl):
        self.stats["quic_hello_giveup"] += 1
        self._blind_hello(fl, "quic_no_sni")

    def _blind_hello(self, fl, stat):
        """نام قطعی نشد — دقیقاً همان حسابداریِ امروزِ جریانِ بی‌SNI.

        صف با مارکِ fail-openِ فعلی تخلیه می‌شود، یعنی رفتارِ پیش از ۰۶۶؛
        نگه‌داری فقط تأخیر انداخته، تصمیم را عوض نکرده.
        """
        fl.pend = None
        fl.pend_bytes = 0
        fl.nosni = (stat == "quic_no_sni")
        fl.blind = True            # نام هرگز قطعی نشد ⇒ مقصدش را _mark_for تعیین می‌کند
        self.stats[stat] += 1
        self._count_conn(fl)
        sni_note(self.sni_stats, None, 0, 1, fl.is_ai)
        src_note(self.src_stats, fl.client[0], 0, 1, fl.is_ai)
        self._flush_held(fl)

    def _close_flow(self, fl):
        # صف **پیش از** _giveup_hello دور ریخته می‌شود، وگرنه آن تابع
        # تخلیه‌اش می‌کند. جریانی که بسته می‌شود معمولاً به این دلیل بسته
        # می‌شود که سوکتش خراب است؛ فرستادن در آن نه ممکن است نه مفید.
        # و بایتش حساب نمی‌شود: چیزی که نرفته نباید در quic_ai_bytes
        # بنشیند، وگرنه نسبتی که پلنِ ۰۶۶ روی آن بنا شده بی‌اعتبار می‌شود.
        if fl.held:
            self.stats["quic_hold_dropped"] += len(fl.held)
        fl.held = None
        fl.held_bytes = 0
        fl.held_since = 0.0
        if fl.pend is not None:
            # جریان پیش از کامل‌شدنِ ClientHello مرد — مثل امروز «بی‌SNI»
            # حساب شود تا شمارشِ اتصال گم نشود. همین مسیر شمارشِ اتصال را
            # هم تضمین می‌کند (_blind_hello → _count_conn)، پس فراخوانِ
            # دومِ _count_conn اینجا **مرده بود**: جهشِ هدفمند نشان داد
            # برداشتنش هیچ تستی را قرمز نمی‌کند. نامتغیر «هر جریان دقیقاً
            # یک بار شمرده می‌شود» را test_a_flow_that_dies_while_still_
            # holding_is_still_counted_once نگه می‌دارد، نه این خط.
            self._giveup_hello(fl)
        try:
            self.sel.unregister(fl.up)
        except (KeyError, ValueError):
            pass
        self.up_index.pop(fl.up.fileno(), None)
        try:
            fl.up.close()
        except OSError:
            pass
        self.flows.pop((fl.client, fl.orig_dst), None)
        self._note_fds()

    def _sweep(self):
        now = time.monotonic()
        if now - self._last_sweep < 10:
            return
        self._last_sweep = now
        for key, fl in list(self.flows.items()):
            if now - fl.last > QUIC_IDLE:
                self._close_flow(fl)
        # سوکت‌های پاسخِ بدونِ جریانِ فعال را هم ببند (نشتی)
        active_dsts = {fl.orig_dst for fl in self.flows.values()}
        for dst, s in list(self.reply_socks.items()):
            if dst not in active_dsts:
                try:
                    s.close()
                except OSError:
                    pass
                del self.reply_socks[dst]
                self._note_fds()

    def _on_listen(self, lsock):
        # چند دیتاگرام را در یک رویداد بخوان
        for _ in range(64):
            try:
                data, ancdata, _flags, client = lsock.recvmsg(
                    65535, socket.CMSG_SPACE(28))
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            if not data:
                continue
            orig_dst = self._parse_origdst(ancdata)
            if orig_dst is None or orig_dst[1] == self.port:
                continue                      # محافظِ حلقه
            key = (client, orig_dst)
            fl = self.flows.get(key)
            if fl is None:
                fl = self._new_flow(data, client, orig_dst)
                if fl is None:
                    continue
            elif fl.pend is not None:
                # ClientHelloِ چندپکتی: این دیتاگرام ممکن است نام را کامل
                # کند. **از پلنِ ۰۶۶ به بعد فوروارد هم می‌تواند عوض شود** —
                # تا وقتی fl.held صف است هیچ بایتی از میزبان خارج نشده، پس
                # _resolve_hello اجازه دارد مارک را اصلاح و سوکت را بازسازد.
                # با WSS_QUIC_HOLD=0 صفی باز نمی‌شود و رفتار همان قبل است.
                self._continue_hello(fl, data)
            fl.last = time.monotonic()
            # صفِ باز یعنی «هنوز تصمیم قطعی نیست» — این دیتاگرام هم منتظر
            # می‌ماند. _hold_datagram با ردِ کران خودش تخلیه می‌کند و False
            # می‌دهد تا همین دیتاگرام مسیرِ عادی را برود.
            if fl.held is not None and self._hold_datagram(fl, data):
                continue
            try:
                fl.up.send(data)
            except OSError:
                self._close_flow(fl)
                continue
            self._account_out(fl, len(data))

    def _on_upstream(self, fl):
        rs = self._reply_sock(fl.orig_dst)
        if rs is None:
            self.stats["quic_rsfail"] += 1
        for _ in range(64):
            try:
                data = fl.up.recv(65535)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                self._close_flow(fl)
                return
            if not data:
                break
            fl.last = time.monotonic()
            if rs is not None:
                try:
                    rs.sendto(data, fl.client)
                    self.stats["quic_replies"] += 1
                except OSError:
                    self.stats["quic_rerr"] += 1

    def run(self):
        try:
            lsock = self._make_listen()
        except OSError as e:
            sys.stderr.write("QUIC bind failed: %r\n" % e)
            return
        self.sel.register(lsock, selectors.EVENT_READ, ("listen", None))
        self.stats["quic_enabled"] = True
        sys.stderr.write("QUIC splitter روی UDP %s:%d\n"
                         % (LISTEN_HOST, self.port))
        while True:
            try:
                # timeoutِ پویا: مهلتِ نگه‌داری در مقیاسِ میلی‌ثانیه است،
                # پس نمی‌شود آن را به _sweep سپرد که هر ۱۰ ثانیه می‌دود.
                # (این تصحیحِ گامِ ۵ ِ خودِ پلنِ ۰۶۶ است — آنجا نوشته شده
                # بود «در همان sweep»، که مهلت را تا ۱۰ ثانیه می‌کشاند.)
                wait = 5.0
                if QUIC_HOLD:
                    d = self._hold_deadline(time.monotonic())
                    if d is not None:
                        wait = max(0.001, min(wait, d))
                events = self.sel.select(timeout=wait)
                for key, _mask in events:
                    kind, obj = key.data
                    if kind == "listen":
                        self._on_listen(key.fileobj)
                    else:
                        self._on_upstream(obj)
                if QUIC_HOLD:
                    self._flush_expired_holds(time.monotonic())
                self._sweep()
            except Exception:
                self.stats["errors"] += 1
                time.sleep(0.05)


def _atomic_write(path, data):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def make_listen_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # IP_TRANSPARENT لازم است تا سوکت بتواند اتصالاتِ منحرف‌شده با TPROXY
    # (که مقصدشان این ماشین نیست) را بپذیرد و پاسخ را با مبدأِ مقصدِ اصلی
    # بفرستد.
    s.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(256)
    s.setblocking(False)
    return s


def main():
    global LOCAL_ADDRS
    LOCAL_ADDRS = refresh_local_addrs()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        listen_sock = make_listen_socket()
    except OSError as e:
        sys.stderr.write("bind failed: %r\n" % e)
        sys.exit(1)
    sp = Splitter(loop)
    sys.stderr.write(
        "warp-sni-splitter روی %s:%d — %d دامنهٔ AI بارگذاری شد\n"
        % (LISTEN_HOST, LISTEN_PORT, len(sp.ai_suffixes)))
    # نخِ QUIC (اختیاری) — فقط اگر پورت ست شده و ماژولِ رمزگشایی بارگذاری شد
    if QUIC_PORT and quic_sni is not None:
        qs = QuicSplitter(QUIC_PORT, sp.stats,
                          lambda: sp.ai_suffixes, sp.sni_stats, sp.src_stats,
                          get_geo_suffixes=lambda: sp.geo_suffixes)
        qs.start()
    elif QUIC_PORT and quic_sni is None:
        sys.stderr.write("QUIC خواسته شد ولی quic_sni.py بارگذاری نشد — خاموش\n")
    loop.create_task(sp.housekeeping())
    loop.create_task(sp.serve(listen_sock))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            os.unlink(HEARTBEAT_FILE)
        except OSError:
            pass


if __name__ == "__main__":
    main()
