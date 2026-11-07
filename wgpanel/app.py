#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wg-panel — پنل مانیتورینگ و مدیریت WireGuard (چهارزبانه: fa/en/ru/zh)
تک‌فایل، فقط کتابخانه استاندارد پایتون. اجرا به‌صورت root (سرویس systemd).

قابلیت‌ها:
  - مانیتور لحظه‌ای ترافیک هر peer و هر اینترفیس (نمونه‌برداری هر ۲ ثانیه)
  - فعال/غیرفعال‌کردن کاربرهای wg1udp (کامنت/آن‌کامنت بلوک‌های #!!!name + wg set)
  - افزودن/حذف کاربر (تولید کلید، تخصیص IP، تولید کانفیگ کلاینت)
  - روشن/خاموش‌کردن تونل‌های خروجی wgN از طریق systemd wg-quick@
  - بکاپ خودکار قبل از هر تغییر فایل کانفیگ در /etc/wireguard/backups/
"""

import base64
import concurrent.futures
import contextlib
import hashlib
import ssl
import stat
import hmac
import binascii
import grp
import gzip
import ipaddress
import json
import math
import os
import queue
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import zlib
from collections import deque
from datetime import datetime, timedelta
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


# -------------------------------------------------------- بوت و مسیرهای پایه


def _locate():
    """(BASE_DIR, ARCHIVE) — پوشه‌ی داده و (اگر از zipapp اجرا می‌شویم) مسیرِ خودِ wg_panel.pyz.

    کد در wgpanel/app.py است؛ داده (config.json، traffic.db، clients/، qr.js، three.*)
    همیشه کنارِ **ظرفِ** پکیج می‌ماند، دقیقاً همان‌جا که wg_panel.py ِ تک‌فایل بود:
      · درختِ سورس:  <repo>/wgpanel/app.py            ⇒ BASE_DIR = <repo>
      · zipapp:      /opt/wg-panel/wg_panel.pyz/wgpanel/app.py ⇒ BASE_DIR = /opt/wg-panel
    ظرف در حالتِ zipapp یک **فایل** است (خودِ .pyz)، نه پوشه — همین تمایز.
    """
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    container = os.path.dirname(pkg_dir)
    if os.path.isfile(container):
        return os.path.dirname(container), container
    return container, None


BASE_DIR, ARCHIVE = _locate()


def _pkg_bytes(rel):
    """بایت‌های یک فایلِ دادهٔ داخلِ پکیجِ wgpanel — هم از درختِ سورس هم از داخلِ wg_panel.pyz.

    از __loader__.get_data استفاده می‌شود، نه importlib.resources (هارنسِ تست app.py
    را با نامِ سطح‌بالا و __package__ ِ خالی بار می‌کند) و نه BASE_DIR (تست‌ها آن را به
    پوشهٔ موقت می‌برند و روی سرور /opt/wg-panel است، نه پکیج).
    """
    here = os.path.dirname(os.path.abspath(__file__))
    return __loader__.get_data(os.path.join(here, *rel.split("/")))


def _pkg_text(rel):
    return _pkg_bytes(rel).decode("utf-8")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
ACTION_LOG = os.path.join(BASE_DIR, "actions.log")
CLIENTS_DIR = os.path.join(BASE_DIR, "clients")  # کانفیگ کلاینت‌های ساخته‌شده (فقط root)
DB_PATH = os.path.join(BASE_DIR, "traffic.db")   # حسابداری ترافیک + متادیتای کاربرها
NETDEV_KEY = "__netdev__"   # pubkey مجازی برای شمارنده‌های /proc/net/dev هر اینترفیس
IFACE_AGG_KEY = "__iface__"  # حالت تجمیع همه‌ی peer های یک اینترفیس در /api/usage
WG_DIR = "/etc/wireguard"
AWG_DIR = "/etc/amnezia/amneziawg"   # کانفیگ‌های AmneziaWG (userspace)
BACKUP_DIR = os.path.join(WG_DIR, "backups")
SESSION_TTL = 12 * 3600  # 12 ساعت


def _build_id():
    """۱۲ هگزِ اولِ SHA-256 — همان «build id» ِ یادداشتِ ریلیز و نسخه‌ی چاپ‌شده در docker.
    از روی آرشیو: sha256(wg_panel.pyz) — همان مقدارِ `tools/build_pyz.py --id`؛
    از روی درختِ سورس: شناسه‌ی توسعه (sha ِ app.py)."""
    try:
        with open(ARCHIVE or os.path.abspath(__file__), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:12]
    except OSError:
        return "unknown"


BUILD_ID = _build_id()
SAMPLE_INTERVAL = 2.0
HISTORY_LEN = 90  # ~۳ دقیقه با نمونه‌برداری ۲ ثانیه‌ای

# ═══════════════════════════════════════════════════════════════════════════
# i18n — چهار زبانه (فارسی · English · Русский · 中文)
# ───────────────────────────────────────────────────────────────────────────
# قرارداد: کاتالوگ یک dict است که هر کلید را به یک تاپلِ چهارتایی می‌نگارد،
# دقیقاً به ترتیبِ LANGS. جای خالیِ تاپل (نبودنِ خانه) ⇒ افتادن به فارسی.
#
# ⚠️ رشتهٔ خالی "" یعنی **عمداً هیچ** — نه «هنوز ترجمه نشده». چند کلید حرفِ
# دستوریِ فارسی‌اند («ها»ی جمع، «را»ی مفعولی) که در en/ru/zh معادل ندارند و
# ترجمهٔ درستشان نبودنشان است؛ اگر خالی به فارسی می‌افتاد، وسطِ جملهٔ انگلیسی
# یک واژهٔ فارسی ظاهر می‌شد.
#
#     "ui.users.title": ("کاربران وایرگارد", "WireGuard users",
#                        "Пользователи WireGuard", "WireGuard 用户"),
#
# جای‌گیرها به سبکِ str.format نوشته می‌شوند — {name} — تا هم پایتون و هم
# فرمت‌کنندهٔ کوچکِ سمتِ مرورگر یک نحو داشته باشند. ترتیبِ جای‌گیرها در هر
# زبان می‌تواند فرق کند؛ به همین دلیل جای‌گیرِ نام‌دار است نه موضعی.
#
# فضای نام کلیدها:
#     ui.*     رابطِ پنل (نشانه‌گذاری + JS)   → به مرورگر تزریق می‌شود
#     api.*    پاسخ و خطاهای HTTP            → سمتِ سرور
#     alert.*  هشدارهای تلگرامِ نگهبانِ سامانه → سمتِ سرور
#     bot.*    رباتِ تلگرام                   → سمتِ سرور، زبانِ هر چت جدا
#
# کاتالوگ عمداً درونِ همین فایل است: کلِ زنجیرهٔ استقرار (ansible، سه بستهٔ
# نصب، airgap، drift-check) روی «تک‌فایل بودنِ wg_panel.py» بنا شده و افزودنِ
# فایلِ دادهٔ جدا هر شش نقطه را می‌شکند.
# ═══════════════════════════════════════════════════════════════════════════


# ----------------------------------------------------- زبان‌ها و انتخابِ زبان


LANGS = ("fa", "en", "ru", "zh")
DEFAULT_LANG = "fa"
_LANG_IDX = {code: i for i, code in enumerate(LANGS)}

# برچسبِ هر زبان به خطِ خودش — همیشه، در هر زبانِ رابط
LANG_LABEL = {"fa": "فارسی", "en": "English", "ru": "Русский", "zh": "中文"}
# جهتِ نوشتار؛ تنها فارسی راست‌چین است
LANG_DIR = {"fa": "rtl", "en": "ltr", "ru": "ltr", "zh": "ltr"}
# مقدارِ صفتِ lang در <html> (برای zh نوعِ ساده‌شده اعلام می‌شود)
LANG_HTML = {"fa": "fa", "en": "en", "ru": "ru", "zh": "zh-Hans"}
# فقط فارسی ارقامِ بومی دارد؛ بقیه ارقامِ لاتین می‌گیرند
LANG_FA_DIGITS = frozenset(("fa",))


def norm_lang(code):
    """کدِ زبانِ ورودی را به یکی از LANGS می‌نگارد؛ ناشناخته ⇒ None.

    زیرگونه‌ها تا زبانِ پایه کوتاه می‌شوند: fa-IR⇒fa، zh-CN/zh-TW/zh-Hans⇒zh.
    """
    if not code:
        return None
    base = str(code).strip().lower().replace("_", "-").split("-")[0]
    return base if base in _LANG_IDX else None


def lang_from_accept(header):
    """زبان را از سرآیندِ Accept-Language برمی‌گزیند (با احترام به q)."""
    best, best_q = None, -1.0
    for part in (header or "").split(","):
        part = part.strip()
        if not part:
            continue
        code, _, params = part.partition(";")
        q = 1.0
        params = params.strip()
        if params.startswith("q="):
            try:
                q = float(params[2:])
            except ValueError:
                q = 0.0
        code = norm_lang(code)
        if code and q > best_q:
            best, best_q = code, q
    return best


def t(key, lang=None, **kw):
    """متنِ محلی‌سازی‌شدهٔ key در زبانِ lang.

    کلیدِ ناشناخته خودِ کلید را برمی‌گرداند (نه رشتهٔ خالی) تا هم در رابط
    دیده شود و هم آزمونِ نگهبان بتواند بگیردش. ترجمهٔ خالی به فارسی می‌افتد.
    """
    row = I18N.get(key)
    if row is None:
        return key
    idx = _LANG_IDX.get(lang or DEFAULT_LANG, 0)
    # فقط «خانهٔ نبوده» به فارسی می‌افتد؛ "" یعنی عمداً هیچ (بالا را ببین)
    s = row[idx] if idx < len(row) else row[0]
    if kw:
        try:
            s = s.format(**kw)
        except (KeyError, IndexError, ValueError):
            pass  # جای‌گیرِ ناجور نباید صفحه را بشکند
    return s


def ui_catalog(lang):
    """زیرمجموعهٔ ui.* برای تزریق به مرورگر — فقط زبانِ فعال."""
    idx = _LANG_IDX.get(lang or DEFAULT_LANG, 0)
    out = {}
    for key, row in I18N.items():
        if key.startswith("ui."):
            out[key] = row[idx] if idx < len(row) else row[0]
    return out


# ---------------------------------------------------- رندرِ صفحه و توکنِ ترجمه



# ── رندرِ صفحهٔ پنل ─────────────────────────────────────────────────────────
# نشانه‌گذاریِ PAGE_HTML به‌جای متنِ فارسی، نشانهٔ ⟦کلید⟧ دارد و سرور آن را در
# زمانِ سرو با ترجمهٔ زبانِ فعال جایگزین می‌کند. دو دلیلِ انتخابِ این روش
# به‌جای data-i18n ِ سمتِ مرورگر:
#   ۱. هیچ پرشِ متنِ ترجمه‌نشده‌ای (FOUC) دیده نمی‌شود؛
#   ۲. رشته‌های JS از راهِ window.__T می‌آیند نه جایگزینیِ متنی، پس نقلِ‌قول و
#      بک‌اسلشِ ترجمه هرگز نمی‌تواند نحوِ اسکریپت را بشکند.
# نشانهٔ جامانده به‌شکلِ ⟦ui.foo⟧ در صفحه دیده می‌شود — خرابیِ پرسروصدا، که
# آزمونِ نگهبان هم همان را می‌گیرد.
_TOKEN_RE = re.compile(r"⟦([A-Za-z0-9_.]+)⟧")
# نشانهٔ «خام»: ترجمه بدونِ گریزِ HTML درج می‌شود. فقط برای جمله‌هایی که خودشان
# مارکاپِ درون‌خطی دارند (<b>، <span class="mono">) و شکستنشان به چند کلید
# جملهٔ بی‌معنی می‌سازد که مترجم نمی‌تواند درست بچیند. مقدارش هرگز از ورودیِ
# کاربر نمی‌آید — فقط از کاتالوگِ خودِ مخزن.
_TOKEN_RAW_RE = re.compile(r"⟪([A-Za-z0-9_.]+)⟫")
_PAGE_CACHE = {}


def _esc_html(s):
    """گریزِ HTML برای متنِ ترجمه — هم در متنِ گره و هم داخلِ صفتِ نقل‌قولی."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&#39;"))


def render_page(lang):
    """PAGE_HTML را برای زبانِ خواسته‌شده می‌سازد و کش می‌کند.

    (PAGE_HTML پایین‌تر در همین فایل تعریف شده؛ چون فقط هنگامِ فراخوانی خوانده
    می‌شود، ترتیبِ تعریف اهمیتی ندارد.)
    """
    lang = lang if lang in _LANG_IDX else DEFAULT_LANG
    cached = _PAGE_CACHE.get(lang)
    if cached is not None:
        return cached
    html = _TOKEN_RE.sub(lambda m: _esc_html(t(m.group(1), lang)), PAGE_HTML)
    html = _TOKEN_RAW_RE.sub(lambda m: t(m.group(1), lang), html)
    html = html.replace("__LANG__", LANG_HTML[lang])
    html = html.replace("__DIR__", LANG_DIR[lang])
    # آخرین گام: تزریقِ کاتالوگ. عمداً بعد از جایگزینیِ نشانه‌هاست تا متنِ
    # ترجمه هرگز خودش دوباره به‌عنوانِ نشانه یا نشانوندِ __LANG__ خوانده نشود.
    boot = "window.__LANG=%s;window.__DIR=%s;window.__T=%s;" % (
        json.dumps(lang), json.dumps(LANG_DIR[lang]),
        json.dumps(ui_catalog(lang), ensure_ascii=False).replace("</", "<\\/"))
    html = html.replace("__I18N_BOOTSTRAP__", boot)
    _PAGE_CACHE[lang] = html
    return html


# ----------------------------------------------- کاتالوگِ ترجمه (fa/en/ru/zh)



# کاتالوگِ ترجمه‌ها در wgpanel/i18n/catalog.json است: یک کلید در هر خط، مقدارش
# فهرستِ چهارتایی [fa, en, ru, zh] به ترتیبِ LANGS (برای افزودنِ زبان، LANGS و
# همهٔ ردیف‌ها با هم رشد کنند). رشتهٔ خالیِ "" یعنی «عمداً هیچ» و جانشین
# (fallback) نیست؛ کلیدِ ناموجود در t() به خودِ کلید برمی‌گردد (رفتارِ بی‌تغییر).
# کلیدِ تکراری و ردیفِ بدشکل همان لحظهٔ import و در --check ِ بیلد شکست می‌خورند.
# فضای نام‌ها: ui.* (رابط) · api.* (خطای API) · alert.* (هشدار) · bot.* (ربات)؛
# قواعدِ جای‌گیرها ({p0} …) و گریزِ HTML همان‌اند که بودند.
def _load_catalog():
    """کاتالوگِ ترجمه از i18n/catalog.json — هر کلید ⇒ تاپلِ چهارتایی به ترتیبِ LANGS.

    کلیدِ تکراری یا ردیفِ بدشکل همان لحظهٔ import شکست می‌خورد (و --check ِ بیلد هم
    همین را می‌سنجد)؛ پیش از این دیکشنریِ پایتونی تکراری را بی‌صدا می‌بلعید.
    """
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError("i18n/catalog.json: کلیدِ تکراری %r" % k)
            out[k] = v
        return out
    raw = json.loads(_pkg_text("i18n/catalog.json"), object_pairs_hook=pairs)
    cat = {}
    for k, v in raw.items():
        if (not isinstance(v, list) or len(v) != len(LANGS)
                or not all(isinstance(x, str) for x in v)):
            raise ValueError("i18n/catalog.json: ردیفِ بدشکل %r" % k)
        cat[k] = tuple(v)
    return cat


I18N = _load_catalog()


# -------------------------------------------------------- پیکربندی و لاگِ کنش


CONFIG = {}


def load_config():
    global CONFIG
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        CONFIG = json.load(f)


_USERNAME_RE = re.compile(r"[A-Za-z0-9_.\-]{1,32}\Z")


def _user_problems(u, c):
    """مشکلاتِ یک رکوردِ کاربر → (خطاها، هشدارها). خطا یعنی کاربر قابلِ
    استفاده نیست (قرنطینه)، نه اینکه پنل نباید بالا بیاید."""
    if not isinstance(u, dict):
        return ["must be an object"], []
    err, warn = [], []
    name = u.get("username")
    if not isinstance(name, str) or not _USERNAME_RE.match(name):
        err.append("invalid \"username\" %r" % (name,))
    role = u.get("role")
    if not isinstance(role, str) or not role:
        err.append("missing \"role\"")
    elif role not in BUILTIN_ROLES and role not in (c.get("roles") or {}):
        warn.append("role %r is not defined (user has no permissions)" % role)
    salt = u.get("salt", "")
    if salt:
        try:
            bytes.fromhex(salt)
        except (ValueError, TypeError):
            err.append("\"salt\" is not hex")
    h = u.get("hash", "")
    if h and not isinstance(h, str):
        err.append("\"hash\" must be a string")
    if bool(salt) != bool(h):
        warn.append("one of salt/hash is empty — first login sets "
                    "a new password")
    exp = u.get("expires", "")
    if exp and not (isinstance(exp, str)
                    and re.fullmatch(r"\d{4}-\d{2}-\d{2}", exp)):
        err.append("\"expires\" must be YYYY-MM-DD")
    if u.get("allow_ips") is not None and not isinstance(u["allow_ips"], list):
        err.append("\"allow_ips\" must be a list")
    return err, warn


def invalid_users(c):
    """[(index, username_or_None, [errors])] برای رکوردهای کاربرِ خراب.
    تکراری‌ها هم اینجا هستند: اولی می‌ماند، بعدی‌ها خراب‌اند (find_user
    هم همیشه اولی را برمی‌گرداند)."""
    out, seen = [], set()
    users = c.get("users") if isinstance(c, dict) else None
    if not isinstance(users, list):
        return out
    for i, u in enumerate(users):
        err, _w = _user_problems(u, c)
        name = u.get("username") if isinstance(u, dict) else None
        if not err and name in seen:
            err = ["duplicate username %r" % name]
        if err:
            out.append((i, name if isinstance(name, str) else None, err))
        elif isinstance(name, str):
            seen.add(name)
    return out


def validate_config(c):
    """بررسیِ شکلِ config.json → (fatal, warnings) — دو لیستِ پیام.

    بدونِ این، یک salt ِ غیرهگز یا رکوردِ کاربرِ بی‌نام تا وسطِ یک درخواست
    پنهان می‌ماند و آن‌جا به KeyError/ValueError می‌رسید — ۵۰۰ ِ بی‌توضیح.
    این در راه‌اندازی صدا زده می‌شود: fatal یعنی پنل نباید بالا بیاید.

    خرابیِ **یک کاربر** fatal نیست: پیش از این یک salt ِ غلط یا تاریخِ
    انقضای بدشکل در رکوردِ یک اپراتورِ فرعی کلِ پنل را از کار می‌انداخت —
    اعمالِ سهمیه و انقضا، شیپر، ربات، هشدارها — آن هم معمولاً بعد از یک
    ویرایشِ دستی و ری‌استارتِ شبانه. حالا آن رکورد هشدار می‌گیرد و
    quarantine_invalid_users کنارش می‌گذارد؛ فقط همان کاربر نمی‌تواند
    وارد شود. خرابیِ ساختاری (users ِ غیرِ لیست، پورت، TLS، شبکه‌ها) هنوز
    fatal است.
    """
    fatal, warn = [], []
    if not isinstance(c, dict):
        return ["config.json must be a JSON object"], []
    users = c.get("users")
    if users is not None and not isinstance(users, list):
        fatal.append("\"users\" must be a list")
        users = []
    for i, u in enumerate(users or []):
        _e, w = _user_problems(u, c)
        warn += ["users[%d]: %s" % (i, x) for x in w]
    for i, _name, errs in invalid_users(c):
        warn.append("users[%d] is ignored until fixed: %s"
                    % (i, "; ".join(errs)))
    for key in ("allow_ips", "trusted_proxies"):
        for e in (c.get(key) or []):
            try:
                ipaddress.ip_network(str(e), strict=False)
            except ValueError:
                fatal.append("\"%s\": invalid network %r" % (key, e))
    port = c.get("port", 8787)
    if not isinstance(port, int) or not (1 <= port <= 65535):
        fatal.append("\"port\" must be an integer between 1 and 65535")
    cert, key = c.get("tls_cert"), c.get("tls_key")
    if bool(cert) != bool(key):
        fatal.append("tls_cert and tls_key must be set together")
    for k, v in (("tls_cert", cert), ("tls_key", key)):
        if v and not os.path.isfile(str(v)):
            fatal.append("\"%s\": file not found: %s" % (k, v))
    sec = c.get("secret")
    if sec is not None and (not isinstance(sec, str) or len(sec) < 32):
        warn.append("\"secret\" is short; it will be regenerated on migration")
    if users == []:
        warn.append("no users defined — nobody can log in")
    elif users and len(invalid_users(c)) == len(users):
        warn.append("no valid users — nobody can log in until config.json "
                    "is fixed")
    return fatal, warn


# رکوردهای کاربرِ خراب که در راه‌اندازی از CONFIG["users"] کنار رفته‌اند.
# در حافظه نیستند تا هیچ مسیری (ورود، فهرست، RBAC) به آن‌ها نرسد، ولی
# save_config عیناً به فایل برشان می‌گرداند: ویرایشِ بعدیِ پنل نباید
# رکوردی را که اپراتور می‌خواهد درست کند پاک کند.
_QUARANTINED_USERS = []


def quarantine_invalid_users():
    """رکوردهای خرابِ CONFIG["users"] را به _QUARANTINED_USERS می‌برد."""
    bad = invalid_users(CONFIG)
    if not bad:
        return []
    idx = {i for i, _n, _e in bad}
    users = CONFIG["users"]
    _QUARANTINED_USERS[:] = [users[i] for i in sorted(idx)]
    CONFIG["users"] = [u for i, u in enumerate(users) if i not in idx]
    return bad


# ضربانِ نخ‌های پس‌زمینه: هر حلقه در ابتدای هر دور خود را ثبت می‌کند و
# /api/health سنِ آخرین ضربان را با سقفِ موردانتظار می‌سنجد. پیش از این مرگِ
# یک نخ (استثنای بیرونِ try، یا هنگِ یک فراخوانی) فقط در لاگ دیده می‌شد.
_HEARTBEAT = {}
_HEARTBEAT_LOCK = threading.Lock()
_STARTED_AT = time.time()
# سقفِ سنِ قابلِ‌قبول (ثانیه) به ازای هر نخ؛ ~۳ برابرِ دوره‌ی معمول
HEARTBEAT_MAX_AGE = {
    "sampler": 30, "sysmon": 60, "confwatch": 60, "tunnels": 60,
    "proxylog": 120, "alertmon": 180, "ecmpguard": 300, "warpguard": 300,
    "warptraffic": 300, "svcdiag": 3 * 3600, "bot": 180,
}


# نامِ ضربانِ نخِ جاری، تا کارهای طولانیِ داخلِ یک دور هم بتوانند «هنوز
# زنده‌ام» بگویند (_heartbeat_progress).
_HB_TLS = threading.local()


def _heartbeat(name):
    _HB_TLS.name = name
    with _HEARTBEAT_LOCK:
        _HEARTBEAT[name] = time.time()


def _heartbeat_progress():
    """ضربانِ میانِ‌دور برای نخی که _heartbeat زده است؛ در بقیه‌ی نخ‌ها no-op.

    سقفِ HEARTBEAT_MAX_AGE برای «یک دورِ عادی» تنظیم شده، نه یک دورِ
    **خرابی**. ربات در یک دور getUpdates را با timeout ِ ۴۵ ثانیه روی همه‌ی
    مسیرهای نامزد (مستقیم + هر تونلِ فعال) امتحان می‌کند؛ وقتی تلگرام
    فیلتر است، با سه تونل همین یک دور از ۱۸۰ ثانیه می‌گذشت و /api/health و
    متریکِ panel_thread_alive نخِ سالمِ ربات را «مرده» گزارش می‌کردند —
    دقیقاً همان وقتی که اپراتور دنبالِ علتِ واقعی است. alertmon هم با
    سنجش‌های subprocess‌ای (هر کدام تا ۲۰ ثانیه) در دورِ خرابی به همین سقف
    می‌رسید. به‌جای بزرگ‌کردنِ سقف (که مرگِ واقعی را دیرتر نشان می‌دهد)،
    هر تلاشِ شبکه/subprocess پیشرفت را ثبت می‌کند؛ سقف حالا فقط باید از
    **یک** فراخوانی بلندتر باشد.
    """
    name = getattr(_HB_TLS, "name", None)
    if name:
        with _HEARTBEAT_LOCK:
            _HEARTBEAT[name] = time.time()


def health_report():
    """وضعیتِ زنده‌بودنِ نخ‌ها → {"ok", "uptime", "threads": {name: {...}}}.
    نخی که هنوز هیچ ضربانی نداده (تازه راه‌افتاده) در «مهلتِ گرم‌شدن»
    (۹۰ ثانیه از استارت) سالم شمرده می‌شود."""
    now = time.time()
    with _HEARTBEAT_LOCK:
        beats = dict(_HEARTBEAT)
    warming = now - _STARTED_AT < 90
    threads, ok = {}, True
    for name, limit in HEARTBEAT_MAX_AGE.items():
        last = beats.get(name)
        if last is None:
            good = warming
            age = None
        else:
            age = round(now - last, 1)
            good = age <= limit
        ok = ok and good
        threads[name] = {"ok": good, "age": age, "max_age": limit}
    return {"ok": ok, "uptime": round(now - _STARTED_AT),
            "threads": threads}


def log_action(msg):
    line = "%s  %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        # چرخش ساده: بالای ۱MB → یک نسخه‌ی قبلی نگه می‌داریم
        if os.path.exists(ACTION_LOG) and os.path.getsize(ACTION_LOG) > 1_000_000:
            os.replace(ACTION_LOG, ACTION_LOG + ".1")
        with open(ACTION_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def aerr(key, **params):
    """خطای پارامتردارِ API — کلید و پارامتر، نه متنِ آمادهٔ یک‌زبانه.

    خروجی همان قالبِ adet() است و در گلوگاهِ `Handler._json` باز و ترجمه
    می‌شود؛ پس هیچ تابعِ اعتبارسنجی‌ای لازم نیست زبان را بداند.
    """
    return json.dumps({"k": key, "p": params}, ensure_ascii=False,
                      separators=(",", ":"))


def api_text(v, lang):
    """کلیدِ api.* (ساده یا خروجیِ aerr) را به متنِ زبانِ lang می‌برد.

    هرچه کلید نباشد دست‌نخورده برمی‌گردد، پس پیامِ خامِ سیستم (خروجیِ wg،
    متنِ خطای OS) از این مسیر سالم رد می‌شود. پارامتری که خودش کلید است
    («چرا»ی یک خطای بیرونی‌تر) هم ترجمه می‌شود. گلوگاهِ مشترکِ Handler._msg،
    ربات (BotThread.M) و هشدارها.
    """
    if not isinstance(v, str) or not v:
        return v
    if v.startswith("api.") and v in I18N:
        return t(v, lang)
    if v.startswith('{"k":"api.'):
        try:
            o = json.loads(v)
            p = {k: api_text(x, lang) for k, x in (o.get("p") or {}).items()}
            return t(o["k"], lang, **p)
        except (ValueError, KeyError, TypeError, AttributeError):
            return v
    return v


def audit_detail_text(d, lang):
    """پارامترهای api.* ِ جزئیاتِ ممیزی را پیش از رفتن به مرورگر ترجمه می‌کند.

    کاتالوگِ مرورگر فقط ui.* دارد، پس «ناموفق: {why}» با why=کلیدِ api.*
    خودِ کلید را نشان می‌داد. قالبِ adet دست نمی‌خورد تا مرورگر همچنان
    رندرش کند؛ فقط مقدارِ پارامترها متن می‌شوند.
    """
    if not isinstance(d, str) or not d.startswith('{"k":"ui.'):
        return api_text(d, lang)
    try:
        o = json.loads(d)
        o["p"] = {k: api_text(x, lang) for k, x in (o.get("p") or {}).items()}
    except (ValueError, TypeError, AttributeError):
        return d
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"))


def adet(key, **params):
    """جزئیاتِ ممیزی به‌شکلِ «کلید + پارامتر»، نه متنِ آمادهٔ یک‌زبانه.

    خروجی یک JSON ِ فشرده است که در همان ستونِ detail می‌نشیند؛ مرورگر
    هنگامِ نمایش آن را باز می‌کند و به زبانِ کاربر رندر می‌کند. رکوردهای
    پیش از چهارزبانه‌شدن متنِ آزادند و JSON نمی‌شوند، پس رندرکننده آن‌ها را
    عیناً نشان می‌دهد — بدونِ نیاز به هیچ مهاجرتِ دیتابیسی.
    """
    return json.dumps({"k": key, "p": params}, ensure_ascii=False,
                      separators=(",", ":"))


# ------------------------------------------------------------- ممیزی (audit)



# کنشگرهای «سیستمی» هم کد می‌گیرند، چون متنشان در ستونِ «توسط» دیده می‌شود.
# نامِ کاربرِ واقعی و «bot:<id>» دست‌نخورده می‌مانند.
ACTOR_GUARD = "sys:guard"        # نگهبانِ مسیر
ACTOR_POLICY = "sys:policy"      # اعمالِ سیاستِ سهمیه/انقضا
ACTOR_MONITOR = "sys:monitor"    # پایشِ تونل
ACTOR_MANUAL = "sys:manual"      # ویرایشِ دستیِ فایلِ کانفیگ
ACTOR_RESTORE = "sys:restore"    # اعمالِ زنده‌ی کانفیگِ بازیابی‌شده از بکاپ
ACTOR_SPEEDTEST = "sys:speedtest"


def audit(actor, category, action, target="", detail="", ip="", ok=True):
    """ثبت رویداد در تاریخچه‌ی ساخت‌یافته (نگهداری ۶ ماه) + لاگ متنی.

    ⚠️ `action` باید **کدِ پایدارِ لاتین** باشد (نمونه: "peer.add")، نه متنِ
    نمایشی؛ مرورگر آن را با کلیدِ ui.audit.act.<کد> ترجمه می‌کند. `detail`
    یا خروجیِ adet() است یا متنِ خامِ داده‌ای (نامِ فایل، پیامِ خطای سیستم).
    """
    try:
        META.add_audit(actor, category, action, target, detail, ip, ok)
    except Exception as e:
        log_action("audit db error: %r" % e)


# -------------------------------------------------- پارسِ ورودی و اجرای فرمان



def parse_quota_expires(quota_raw, expires_raw):
    """اعتبارسنجی مشترک سهمیه (GB) و تاریخ انقضا (میلادی YYYY-MM-DD).

    خروجی: (quota|None, expires|None, error|None). تبدیل شمسی→میلادی
    سمت مرورگر انجام می‌شود؛ سرور همیشه تاریخ میلادی می‌گیرد.
    """
    quota = None
    if quota_raw not in (None, ""):
        try:
            quota = float(quota_raw)
        except (TypeError, ValueError):
            return None, None, "api.err.quota.num"
        # inf/nan از float() رد می‌شوند و از «<= 0» هم: inf در DB می‌نشست و
        # json.dumps آن را به Infinity ِ خام می‌برد که JSON.parse ِ مرورگر رد
        # می‌کند — کلِ /api/stats برای همه‌ی تب‌ها می‌شکست؛ nan سهمیه را
        # بی‌صدا غیرفعال می‌کرد.
        if not math.isfinite(quota):
            return None, None, "api.err.quota.num"
        if quota <= 0:
            quota = None
    expires = str(expires_raw or "").strip()
    if expires:
        try:
            datetime.strptime(expires, "%Y-%m-%d")
        except ValueError:
            return None, None, "api.err.date"
    else:
        expires = None
    return quota, expires, None


def parse_rate_mbit(raw):
    """محدودیت سرعت (Mbit/s). خروجی: (rate|None, error). خالی/۰ = نامحدود."""
    if raw in (None, ""):
        return None, None
    try:
        rate = float(raw)
    except (TypeError, ValueError):
        return None, "api.err.rate.num"
    if not math.isfinite(rate):          # int(inf) → OverflowError
        return None, "api.err.rate.num"
    rate = int(rate)
    if rate <= 0:
        return None, None
    if rate > 10000:
        return None, "api.err.rate.max"
    return rate, None


def parse_client_overrides(body):
    """اعتبارسنجی override های کلاینت. خروجی: (dict, error).
    dict شامل c_dns/c_mtu/c_keepalive/c_allowed (None اگر خالی = پیش‌فرض)."""
    out = {"c_dns": None, "c_mtu": None, "c_keepalive": None, "c_allowed": None}
    dns = str(body.get("c_dns", "") or "").strip()
    if dns:
        for part in dns.split(","):
            part = part.strip()
            try:
                ipaddress.ip_address(part)
            except ValueError:
                return None, aerr("api.err.dns", v=part)
        out["c_dns"] = ", ".join(p.strip() for p in dns.split(","))
    mtu = body.get("c_mtu")
    if mtu not in (None, ""):
        try:
            mtu = int(mtu)
        except (TypeError, ValueError):
            return None, "api.err.mtu.num"
        if not (1280 <= mtu <= 1500):
            return None, "api.err.mtu.range"
        out["c_mtu"] = mtu
    ka = body.get("c_keepalive")
    if ka not in (None, ""):
        try:
            ka = int(ka)
        except (TypeError, ValueError):
            return None, "api.err.keepalive.num"
        if not (0 <= ka <= 600):
            return None, "api.err.keepalive.range"
        out["c_keepalive"] = ka
    allowed = str(body.get("c_allowed", "") or "").strip()
    if allowed:
        parts = [p.strip() for p in allowed.split(",") if p.strip()]
        for pt in parts:
            try:
                ipaddress.ip_network(pt, strict=False)
            except ValueError:
                return None, aerr("api.err.allowedips", v=pt)
        out["c_allowed"] = ", ".join(parts)
    return out, None


def _parse_total_action(body):
    """اعتبارسنجی سقف حجم کل + اکشن. خروجی: (dict{total_gb,enforce_action}, error)."""
    total = None
    raw = body.get("total_gb")
    if raw not in (None, ""):
        try:
            total = float(raw)
        except (TypeError, ValueError):
            return None, "api.err.total.num"
        if not math.isfinite(total):
            return None, "api.err.total.num"
        if total <= 0:
            total = None
    action = str(body.get("enforce_action", "disable") or "disable")
    if action not in ("disable", "delete"):
        action = "disable"
    return {"total_gb": total, "enforce_action": action}, None


def wg_pubkey(priv, timeout=10):
    """کلیدِ عمومی را از کلیدِ خصوصی حساب می‌کند — (ok, pub).

    از run() نمی‌گذرد چون آن تابع `input=` ندارد و این فرمان کلید را از
    stdin می‌گیرد. سه فراخوانیِ یکسانِ پراکنده بودند و **هیچ‌کدام
    timeout نداشتند**: فرزندِ گیرکرده نخ را برای همیشه می‌گرفت.

    ۱۰ ثانیه دست‌ودل‌بازانه است — این یک محاسبه‌ی curve25519 روی ۳۲ بایت
    است و در عمل میکروثانیه طول می‌کشد؛ مهلت فقط وقتی می‌سوزد که خودِ
    باینری گم یا قفل شده باشد.

    هر سه فراخوان **پیش از** هر نوشتنِ کانفیگ صدا زده می‌شوند، پس
    برگشتِ زودهنگام کانفیگِ نیمه‌نوشته جا نمی‌گذارد.
    """
    try:
        p = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        log_action("timeout: wg pubkey (%ss)" % timeout)
        return False, ""
    except OSError as e:
        log_action("wg pubkey failed: %r" % e)
        return False, ""
    if p.returncode != 0:
        return False, ""
    return True, p.stdout.strip()


def run(cmd, timeout=20):
    """اجرای دستور؛ خروجی (rc, stdout, stderr)."""
    _heartbeat_progress()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except OSError as e:
        return -1, "", str(e)


# ---------------------------------------------------------------- احراز هویت

# تعدادِ تکرارِ PBKDF2-SHA256 برای هش‌های **تازه**. رکوردِ هر کاربر تعدادِ
# تکرارِ خودش را در "pbkdf2_iters" نگه می‌دارد (نبودنش = ۲۰۰٬۰۰۰ ِ قدیمی)،
# پس این عدد بدونِ باطل‌شدنِ رمزها بالا می‌رود و ورودِ موفقِ بعدی هش را
# بی‌صدا به تعدادِ جدید می‌رساند (rehash_user_password).
PBKDF2_ITERS = 600_000
_PBKDF2_LEGACY_ITERS = 200_000


def hash_password(password, salt_hex, iters=PBKDF2_ITERS):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), int(iters)
    ).hex()


def user_pbkdf2_iters(user):
    try:
        return int(user.get("pbkdf2_iters") or _PBKDF2_LEGACY_ITERS)
    except (TypeError, ValueError):
        return _PBKDF2_LEGACY_ITERS


# salt ثابت فقط برای هم‌سطح‌کردن زمانِ پاسخ در ورودِ کاربر ناموجود
# (جلوگیری از شمارش نام کاربری با تحلیل زمان‌بندی)
_DUMMY_SALT = secrets.token_hex(16)


# قفلِ نوشتنِ config.json. برخلافِ _conf_lock که فایل‌های wg را می‌پاید،
# این یکی هیچ مالکی نداشت: ۲۵ نقطه‌ی فراخوانی از نخ‌های HTTP و از نخِ ربات
# هم‌زمان می‌نویسند و همه یک مسیرِ tmp ِ ثابت را با O_TRUNC باز می‌کردند،
# پس فایلِ rename‌شده می‌توانست JSON ِ درهم باشد و load_config در استارتِ
# بعدی می‌افتاد — و گاردِ ضدِ بازنویسیِ زیر هم بازیابی را دستی می‌کرد.
#
# RLock و نه Lock: فراخواننده‌ای که روزی قفل را نگه دارد و دوباره
# save_config صدا بزند با Lock ِ ساده قفل می‌شد. هزینه‌اش اینجا صفر است.
#
# 🪤 ترتیبِ قفل: تنها نقطه‌ای که هر دو را می‌گیرد خط ~۱۶۴۰۴ است
# (_conf_lock → این یکی). save_config خودش هرگز _conf_lock نمی‌گیرد، پس
# ترتیب تک‌جهته و بدونِ inversion است. اگر روزی جایی داخلِ این قفل
# _conf_lock بخواهد، همان‌جا deadlock می‌شود.
_config_write_lock = threading.RLock()


def save_config():
    # محافظِ ضدِ بازنویسیِ فاجعه‌بار: اگر CONFIG بارگذاری‌نشده/ناقص باشد
    # (مثلاً import ماژول بدونِ load_config)، نوشتنِ آن config.json را با
    # نسخه‌ی خالی جایگزین می‌کند و tls/secret/users را نابود می‌کند. اگر
    # کاربرِ admin وجود ندارد یعنی CONFIG معتبر نیست → از نوشتن خودداری کن.
    #
    # عمداً بیرونِ قفل: گرفتنِ قفل برای اینکه بلافاصله raise کنیم بی‌فایده
    # است و قصد را هم مبهم می‌کند.
    if not (CONFIG.get("users") or _QUARANTINED_USERS):
        log_action("save_config REFUSED: CONFIG بدون users (بارگذاری‌نشده؟)")
        raise RuntimeError("refusing to save an unpopulated CONFIG")
    with _config_write_lock:
        # نامِ یکتا به‌جای CONFIG_PATH + ".tmp": دو نویسنده‌ی هم‌زمان همان
        # یک مسیر را با O_TRUNC می‌گرفتند و در آفست‌های مستقل می‌نوشتند.
        d = os.path.dirname(CONFIG_PATH) or "."
        fd, tmp = tempfile.mkstemp(prefix=".config.", suffix=".tmp", dir=d)
        try:
            os.fchmod(fd, 0o600)   # mkstemp معمولاً ۰۶۰۰ می‌دهد؛ صریح می‌کنیمش
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                out = CONFIG
                if _QUARANTINED_USERS:
                    out = dict(CONFIG, users=list(CONFIG.get("users") or [])
                               + _QUARANTINED_USERS)
                json.dump(out, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())   # بدونِ این، قطعِ برق فایلِ صفرطول می‌گذارد
            os.replace(tmp, CONFIG_PATH)
            tmp = None
        finally:
            if tmp is not None:      # json.dump شکست خورد ⇒ آشغال نگذار
                try:
                    os.unlink(tmp)
                except OSError:
                    pass


@contextlib.contextmanager
def config_txn():
    """خواندن-تغییر-نوشتنِ CONFIG به‌صورتِ **اتمیک**.

    `save_config` خودِ *نوشتن* را سریال می‌کند، پس `config.json` دیگر پاره
    نمی‌شود. آنچه می‌ماند **lost update** است: ده‌ها نقطه CONFIG را
    می‌خوانند، زیردرختی را عوض می‌کنند و ذخیره می‌کنند. دو نخ — یک
    هندلرِ HTTP و نخِ ربات، یا دو هندلر — درهم می‌شوند و دومی تغییرِ اولی
    را بازمی‌نویسد. فایل سالم می‌ماند و تغییر **بی‌صدا** ناپدید می‌شود:
    نه خطایی، نه خطِ لاگی، و درخواستِ خودِ کاربر هم موفق برگشته بوده.

    قفل همان RLock ِ save_config است، پس ورودِ دوباره امن است و
    save_config می‌تواند از داخلِ تراکنش صدا زده شود.

    ⚠️ **با استثنا ذخیره نمی‌کند.** اگر بدنه‌ی تراکنش بیفتد، تغییرِ
    نیمه‌کاره نباید ماندگار شود — و قفل هم آزاد می‌شود (وگرنه کلِ پنل
    روی نوشتنِ بعدی هنگ می‌کرد). این تصمیم است، نه اتفاق: کسی که بعداً
    `yield` را در `try/finally` بپیچد، نیمه‌نوشتن را برمی‌گرداند.

    ⚠️ **کارِ کند را داخلش نگذار.** subprocess، شبکه یا ممیزیِ کند داخلِ
    این قفل همه‌ی نویسنده‌های دیگر را پشتِ خودش نگه می‌دارد.
    """
    with _config_write_lock:
        yield CONFIG
        save_config()


# ------------------------------------------------- گاردِ ECMP (تنظیماتِ پایه)
# سراسری‌ها در ریشه‌ی ecmp_guard، و هر «مجموعه‌مسیر» یک گروه در groups:
#   {"name","routes_file","tunnels":[...],"weight","table","enabled"}
ECMP_GUARD_DEFAULTS = {
    "enabled": False,
    "dead_after": 150,          # ثانیه؛ باید > ۱۲۰ باشد (دورهٔ هندشیکِ WG)
    "confirm": 2,               # چرخه‌های متوالیِ «مرده» تا حذفِ nexthop
    "script": "/usr/local/sbin/awg-ecmp-from-file.sh",
}
ECMP_GROUP_DEFAULTS = {"name": "", "routes_file": "", "tunnels": [],
                       "weight": 5, "table": "main", "enabled": True}
IFACE_RE = re.compile(r"(wg|awg)[0-9a-zA-Z]+\Z")
RT_TABLE_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}\Z")


def migrate_ecmp_guard(c):
    """شکلِ تکـ‌مجموعه‌ایِ قدیمی (routes_file/tunnels در ریشه) → groups[].

    برمی‌گرداند: آیا چیزی تغییر کرد (تا save_config صدا زده شود)."""
    changed = False
    for k, v in ECMP_GUARD_DEFAULTS.items():
        if k not in c:
            c[k] = v
            changed = True
    if "groups" not in c:
        legacy = {}
        for k in ("routes_file", "tunnels", "weight", "table"):
            if k in c:
                legacy[k] = c.pop(k)
                changed = True
        c["groups"] = []
        if legacy.get("routes_file"):
            g = dict(ECMP_GROUP_DEFAULTS, **legacy)
            g["name"] = "گوگل"      # تنها گروهِ موجود تا امروز
            g["enabled"] = True
            c["groups"] = [g]
        changed = True
    return changed


def ecmp_groups(c):
    """گروه‌های معتبر و فعالِ گارد (نامعتبرها بی‌صدا کنار گذاشته می‌شوند)."""
    out = []
    for g in (c.get("groups") or []):
        g = dict(ECMP_GROUP_DEFAULTS, **(g or {}))
        if not g.get("enabled") or not g.get("routes_file"):
            continue
        g["tunnels"] = [t for t in (g.get("tunnels") or [])
                        if isinstance(t, str) and IFACE_RE.match(t)]
        if not g["tunnels"]:
            continue
        if not RT_TABLE_RE.match(str(g.get("table") or "main")):
            g["table"] = "main"
        try:
            g["weight"] = max(1, min(255, int(g.get("weight", 5))))
        except (ValueError, TypeError):
            g["weight"] = 5
        out.append(g)
    return out


def migrate_config():
    """رمز تک‌کاربره‌ی قدیمی → کاربر admin؛ تولید توکن metrics در نبودش."""
    changed = False
    if "users" not in CONFIG:
        # pop و نه get: کلیدهای سطحِ بالا پس از مهاجرت نسخه‌ی **دومی** از
        # اعتبارنامه‌ی ادمین‌اند که هرگز به‌روز نمی‌شود — تغییرِ رمز فقط
        # users[0] را عوض می‌کند، پس password_hash ِ جامانده هشِ رمزی است
        # که اپراتور فکر می‌کند بازنشسته شده. الگوی درست چند ده خط بالاتر
        # در مهاجرتِ ECMP از قبل c.pop است.
        _salt = CONFIG.pop("salt", "") or secrets.token_hex(16)
        _hash = CONFIG.pop("password_hash", "")
        CONFIG["users"] = [{
            "username": "admin",
            "salt": _salt,
            "hash": _hash,
            "role": "admin",
            "totp": "",
            "stoken": secrets.token_hex(8),
        }]
        changed = True
    else:
        # و این نیمه همان چیزی است که واقعاً کار می‌کند: کانفیگی که با
        # نسخه‌ی قبلی مهاجرت کرده جفتِ کهنه را هنوز دارد و شاخه‌ی بالا
        # برایش **هرگز** اجرا نمی‌شود — یعنی وضعِ همه‌ی استقرارهای موجود.
        # config.json در هر آرشیوِ بکاپ می‌رود، پس نیم‌عمرِ این هش بلند است.
        for _k in ("salt", "password_hash"):
            if _k in CONFIG:
                CONFIG.pop(_k, None)
                changed = True
    # توکن سشن هر کاربر: با تغییر/ریست رمز می‌چرخد تا سشن‌های قدیمی باطل شوند
    for u in CONFIG.get("users", []):
        if not u.get("stoken"):
            u["stoken"] = secrets.token_hex(8)
            changed = True
    # کلیدِ HMAC ِ کوکیِ نشست. فقط قالبِ ansible و entrypoint ِ داکر
    # می‌ساختندش، پس کانفیگی که از راهِ دیگری سرِ هم شود — مسیرِ دستیِ
    # systemd که README مستندش می‌کند، ویرایشِ دستی، بازیابیِ ناقص —
    # پنلی می‌داد که بالا می‌آید، صفحه‌ی ورود می‌دهد، رمزِ بوت‌استرپ را
    # می‌پذیرد، و بعد سرِ صدورِ کوکی KeyError می‌خورد. آن رمزِ یک‌بارمصرف
    # هم تا آن لحظه مصرف شده است.
    #
    # `not CONFIG.get("secret")` و نه `not in`: مقدارِ خالی از نبودنش
    # بدتر است — HMAC محاسبه می‌شود، پس کوکی زیرِ کلیدِ معلوم جعل‌پذیر
    # می‌شود و هیچ‌جا خطایی نمی‌دهد.
    if not CONFIG.get("secret"):
        CONFIG["secret"] = secrets.token_hex(24)   # ۴۸ هگز، مثلِ قالبِ نقش
        changed = True
    if "metrics_token" not in CONFIG:
        CONFIG["metrics_token"] = secrets.token_urlsafe(24)
        changed = True
    if "allow_ips" not in CONFIG:
        CONFIG["allow_ips"] = []
        changed = True
    # RBAC: نقش‌های سفارشی {name: {"perms": [...], "require_totp": bool}}
    if "roles" not in CONFIG:
        CONFIG["roles"] = {}
        changed = True
    # رباتِ تلگرام: {"enabled": bool, "users": [{"id","role","name"}]}
    if "bot" not in CONFIG:
        CONFIG["bot"] = {"enabled": False, "users": []}
        changed = True
    # تأییدِ ورودِ پنل با تلگرام (۲مرحله‌ای)
    if "login_2fa" not in CONFIG:
        CONFIG["login_2fa"] = {"enabled": False}
        changed = True
    # ترمیمِ ECMP در بازهٔ گذار (opt-in، پیش‌فرض خاموش)
    if "ecmp_guard" not in CONFIG:
        CONFIG["ecmp_guard"] = dict(ECMP_GUARD_DEFAULTS, groups=[])
        changed = True
    elif migrate_ecmp_guard(CONFIG["ecmp_guard"]):
        changed = True
    if changed:
        # مسیرِ بوت و تک‌نخی است، ولی همان مرز را می‌گیرد تا هیچ نقطه‌ای
        # بیرونِ قرارداد نماند. RLock ورودِ دوباره را امن می‌کند.
        with _config_write_lock:
            save_config()


def find_user(username):
    for u in CONFIG.get("users", []):
        if u["username"] == username:
            return u
    return None


def is_protected_admin(username):
    """حسابِ اصلیِ ادمین (اولین کاربرِ config) مصون است: هیچ‌کس (حتی ادمینِ دیگر)
    نمی‌تواند حذفش کند یا رمزش را از مدیریتِ کاربران ریست کند. فقط خودِ این
    حساب می‌تواند رمز/TOTP خود را از «تغییر رمز»/«ورود دومرحله‌ای» عوض کند."""
    users = CONFIG.get("users", [])
    return bool(users) and username == users[0]["username"]


# ------------------------------------------------------------- RBAC (نقش‌ها)
# کاتالوگ مجوزها: (گروه، برچسبِ گروه، [(کلید، برچسب)]). کلیدها پایدارند و در
# config.json ذخیره می‌شوند؛ برچسب‌ها فقط برای UI ماتریسِ نقش است.
PERM_CATALOG = (
    ("wg", "کاربران وایرگارد", (
        ("wg.view", "دیدن و نمودار"), ("wg.add", "افزودن"),
        ("wg.edit", "ویرایش و فعال/غیرفعال"), ("wg.del", "حذف"),
        ("wg.conf", "کانفیگ / QR / لینک اشتراک"))),
    ("proxy", "کاربران پروکسی", (
        ("proxy.view", "دیدن، نمودار و لاگ"), ("proxy.add", "افزودن"),
        ("proxy.edit", "ویرایش"), ("proxy.del", "حذف"),
        ("proxy.conf", "کانفیگ / QR (شاملِ رمز)"))),
    ("tun", "تونل‌های خروجی", (
        ("tun.view", "دیدن"), ("tun.toggle", "روشن/خاموش"))),
    ("net", "اینترفیس‌های شبکه", (("net.view", "دیدن"),)),
    ("sys", "وضعیت سرور (گیج‌ها)", (("sys.view", "دیدن"),)),
    ("svc", "تشخیص مسیر سرویس‌ها", (
        ("svc.view", "دیدن و تست"), ("svc.edit", "افزودن/ویرایش/حذف"))),
    ("audit", "تاریخچه و لاگ", (("audit.view", "دیدن"),)),
    ("nqmo", "کیفیتِ ارتباط (WG-NQMO)", (
        ("nqmo.view", "دیدنِ کیفیت و تشخیص‌ها"),
        ("nqmo.detail", "جزئیات: prefix، ASN و شواهدِ کامل"),
        ("nqmo.ack", "تأییدِ دیده‌شدنِ تشخیص"),
        ("nqmo.probe", "اجرای probe ِ دستیِ MTU"),
        ("nqmo.manage", "تغییرِ حالتِ موتور"))),
    ("mgmt", "مدیریت پنل", (
        ("users.manage", "کاربران پنل و نقش‌ها (هم‌ارزِ ادمینِ کامل)"),
        ("alerts.manage", "تنظیماتِ هشدارِ تلگرام"),
        ("bot.manage", "کاربرانِ رباتِ تلگرام"),
        ("ecmp.manage", "گاردِ ECMP (ترمیمِ مسیرِ تونل‌های مرده)"),
        ("warp.manage", "مقصدهای مسیریابیِ WARP (افزودن/حذفِ سایت و IP)"),
        ("settings.ips", "محدودیت IP سراسری"),
        ("backup.get", "دانلود بکاپ"),
        ("backup.restore", "بازیابی بکاپ"))),
)
ALL_PERMS = frozenset(p for _, _, items in PERM_CATALOG for p, _ in items)
# نقشِ داخلیِ viewer = رفتارِ قبلی: فقط مشاهده‌ی بخش‌های عمومی
VIEWER_PERMS = frozenset(("wg.view", "tun.view", "net.view", "sys.view"))
BUILTIN_ROLES = ("admin", "viewer")
# مجوزِ عملی بدونِ «دیدنِ» همان بخش بی‌معنی است؛ خودکار اضافه می‌شود
_PERM_IMPLIES = {
    "wg.add": "wg.view", "wg.edit": "wg.view", "wg.del": "wg.view",
    "wg.conf": "wg.view",
    "proxy.add": "proxy.view", "proxy.edit": "proxy.view",
    "proxy.del": "proxy.view", "proxy.conf": "proxy.view",
    "tun.toggle": "tun.view", "svc.edit": "svc.view",
    "nqmo.detail": "nqmo.view", "nqmo.ack": "nqmo.view", "nqmo.probe": "nqmo.view",
    "nqmo.manage": "nqmo.view",
}


def normalize_perms(perms):
    """فقط کلیدهای معتبر + مجوزهای viewِ ضمنی."""
    s = {p for p in perms if p in ALL_PERMS}
    for p in list(s):
        imp = _PERM_IMPLIES.get(p)
        if imp:
            s.add(imp)
    return s


def role_perms(role):
    if role == "owner":       # مالکِ ربات — دسترسیِ کامل مثلِ admin
        return set(ALL_PERMS)
    if role == "admin":
        return set(ALL_PERMS)
    if role == "viewer":
        return set(VIEWER_PERMS)
    r = (CONFIG.get("roles") or {}).get(role)
    if not r:
        return set()  # نقشِ حذف‌شده/ناشناخته → هیچ دسترسی (پیش‌فرضِ امن)
    return normalize_perms(r.get("perms", []))


def user_perms(user):
    return role_perms(user.get("role", "")) if user else set()


# مجوزهایی که دارنده‌شان می‌تواند **مجوزهای بیشتری به دست آورد** — پس
# اعطای نقشی که یکی از این‌ها را دارد خودش ارتقای دسترسی است:
#   users.manage   — فهرست و نقشِ کاربرانِ پنل را عوض می‌کند (سند هم
#                    آن را «معادلِ admin به‌طراحی» ثبت کرده)
#   bot.manage     — توکنِ ربات و چتِ تأییدِ ورود را کنترل می‌کند، یعنی
#                    سطحِ دومِ احراز هویت
#   backup.restore — می‌تواند پنل را به وضعیتِ قبلی برگرداند، از جمله
#                    جدولِ کاربرانِ قبلی
ESCALATION_PERMS = frozenset(("users.manage", "bot.manage", "backup.restore"))


def role_is_privileged(role):
    """آیا اعطای این نقش، ارتقای دسترسی است؟

    🪤 قابلیت‌محور و نه نام‌محور. «admin» فقط یک **نامِ** نقش است و جدولِ
    نقش‌ها پیکربندی‌پذیر: `/api/roles/save` هر مجوزی از ALL_PERMS را
    می‌پذیرد، پس نقشی به نامِ «superuser» با `users.manage` یک عملیاتِ
    پشتیبانی‌شده است، نه فرض. آن نقش از کنارِ هر مقایسه‌ی نامی رد می‌شود
    — بی‌صدا، بدونِ خطا و بدونِ لاگ.
    """
    return bool(ESCALATION_PERMS & role_perms(role))


def role_require_totp(role):
    r = (CONFIG.get("roles") or {}).get(role)
    return bool(r and r.get("require_totp"))


def user_needs_totp(user):
    """نقشِ کاربر TOTP را الزامی کرده ولی هنوز فعالش نکرده است."""
    return bool(user and role_require_totp(user.get("role", ""))
                and not user.get("totp"))


def user_expired(user):
    exp = (user.get("expires") or "").strip()
    if not exp:
        return False
    try:
        end = datetime.strptime(exp, "%Y-%m-%d").replace(
            hour=23, minute=59, second=59)
    except ValueError:
        return False
    return end < datetime.now()


def user_is_active(user):
    return bool(user) and user.get("active", True) and not user_expired(user)


def user_ip_ok(user, ip):
    """محدودیتِ IP اختصاصیِ هر کاربرِ پنل (خالی = همه‌جا).
    127.0.0.1 همیشه مجاز است تا دسترسیِ اضطراری از خودِ سرور بسته نشود."""
    allow = user.get("allow_ips") or []
    if not allow:
        return True
    if ip in ("127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allow:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def parse_panel_allow_ips(text):
    """رشته‌ی IP/CIDRهای جداشده با کاما/فاصله → (list, error)."""
    items = [x for x in re.split(r"[,\s]+", str(text or "").strip()) if x]
    out = []
    for it in items:
        try:
            ipaddress.ip_network(it, strict=False)
        except ValueError:
            return None, aerr("api.err.addr", v=it)
        out.append(it)
    return out, None


def count_active_admins(exclude_username=None):
    """تعدادِ ادمین‌های کاملِ فعال و غیرمنقضی (برای گاردِ آخرین ادمین)."""
    return sum(1 for u in CONFIG.get("users", [])
               if u["role"] == "admin" and user_is_active(u)
               and u["username"] != exclude_username)


def check_user_password(user, password):
    try:
        got = hash_password(password, user["salt"], user_pbkdf2_iters(user))
    except (ValueError, TypeError):      # salt ِ غیرهگز در config ِ دست‌کاری‌شده
        return False
    return hmac.compare_digest(str(user.get("hash", "")), got)


def rehash_user_password(user, password):
    """بعد از ورودِ موفق: اگر هش با تکرارِ کمتر از PBKDF2_ITERS ساخته شده،
    با همان رمز و تکرارِ جدید بازنویسی می‌شود. True اگر عوض شد."""
    if user_pbkdf2_iters(user) >= PBKDF2_ITERS:
        return False
    with config_txn():
        user["salt"] = secrets.token_hex(16)
        user["hash"] = hash_password(password, user["salt"])
        user["pbkdf2_iters"] = PBKDF2_ITERS
    return True


def set_user_password(user, new):
    if len(new) < 8:
        return False, "api.err.pw.short"
    with config_txn():
        user["salt"] = secrets.token_hex(16)
        user["hash"] = hash_password(new, user["salt"])
        user["pbkdf2_iters"] = PBKDF2_ITERS
        user["stoken"] = secrets.token_hex(8)  # ابطال همه‌ی سشن‌های قبلی
    return True, "api.ok.pw.changed"


# ---- TOTP (RFC 6238، SHA1، گام ۳۰ ثانیه، ۶ رقم)

def totp_code(secret_b32, t=None):
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((time.time() if t is None else t) // 30)
    h = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    o = h[19] & 15
    return str((int.from_bytes(h[o:o + 4], "big") & 0x7FFFFFFF)
               % 1_000_000).zfill(6)


# کدهای بازیابیِ TOTP: ۸ کدِ یک‌بارمصرفِ ۱۰ حرفی که هنگامِ فعال‌کردنِ TOTP
# ساخته می‌شوند؛ فقط هشِ SHA-256 ِ هر کد در رکوردِ کاربر می‌ماند. بدونِ آن،
# گم‌شدنِ اپِ authenticator ِ ادمینِ اصلی یعنی ویرایشِ دستیِ config.json.
TOTP_RECOVERY_COUNT = 8
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def _recovery_hash(code):
    return hashlib.sha256(code.encode()).hexdigest()


def totp_recovery_codes(user):
    """کدهای تازه می‌سازد و هشِ آن‌ها را روی کاربر می‌گذارد → لیستِ متنِ کدها."""
    codes = ["".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
             for _ in range(TOTP_RECOVERY_COUNT)]
    codes = ["%s-%s" % (c[:5], c[5:]) for c in codes]
    user["totp_recovery"] = [_recovery_hash(c) for c in codes]
    return codes


def totp_recovery_consume(user, code):
    """اگر code یکی از کدهای بازیابیِ مصرف‌نشده باشد، آن را حذف می‌کند و
    True برمی‌گرداند (باید داخلِ config_txn صدا زده شود)."""
    code = str(code or "").strip().lower().replace(" ", "")
    # کدها «xxxxx-xxxxx» صادر می‌شوند، ولی کاربر از روی کاغذ خط‌تیره را
    # جا می‌اندازد یا خطِ تیره‌ی دیگری (– ‑) تایپ/چسباند می‌کند. شکلِ
    # کانونی: فقط حروف و ارقام، و اگر ۱۰ تاست، خط‌تیره وسط.
    bare = re.sub(r"[^0-9a-z]", "", code)
    if len(bare) == 10:
        code = "%s-%s" % (bare[:5], bare[5:])
    if not code:
        return False
    h = _recovery_hash(code)
    left = user.get("totp_recovery") or []
    for stored in left:
        if hmac.compare_digest(stored, h):
            user["totp_recovery"] = [x for x in left if x != stored]
            return True
    return False


def totp_verify(secret_b32, code):
    code = code.strip()
    # فقط ارقام ASCII؛ \d ارقام فارسی/یونیکد را هم می‌گیرد و بعد
    # compare_digest روی رشته‌ی غیر-ASCII خطا (کرش) می‌دهد
    if not re.fullmatch(r"[0-9]{6}", code):
        return False
    now = time.time()
    return any(hmac.compare_digest(totp_code(secret_b32, now + d * 30), code)
               for d in (-1, 0, 1))


# TOTP یک‌بارمصرف. totp_verify پنجره‌ی d ∈ (-1, 0, 1) × ۳۰ ثانیه را
# می‌پذیرد، یعنی یک کدِ ۶رقمی در بازه‌ای تا ۹۰ ثانیه معتبر است — پس هرکس
# یک بار ببیندش (شانه‌نگاه، اسکرین‌شات، لاگِ کیبورد) تا پایانِ همان بازه
# می‌تواند تکرارش کند. عاملِ دوم باید یک‌بارمصرف باشد وگرنه عاملِ دوم نیست.
#
# TTL دقیقاً کلِ بازه‌ی پذیرش است: کمتر، تکرار را باز می‌گذارد؛ بیشتر،
# کدِ مشروعِ بعدی را رد می‌کند.
_TOTP_WINDOW = 90
_totp_used = {}
_totp_used_lock = threading.Lock()


def totp_consume(username, code):
    """کدِ TOTP فقط یک بار. True یعنی تازه بود و مصرف شد."""
    now = time.time()
    with _totp_used_lock:
        # هرسِ درجا، بی‌تایمر — همان شکلی که سه محدودکننده‌ی دیگرِ این
        # فایل دارند. چهار سیاستِ تخلیه برای چهار ساختار یعنی یکی‌شان
        # بالاخره نشت می‌کند.
        for k in [k for k, exp in _totp_used.items() if exp <= now]:
            _totp_used.pop(k, None)
        key = (str(username), str(code))
        if key in _totp_used:
            return False
        _totp_used[key] = now + _TOTP_WINDOW
        return True


# محدودیتِ per-account در کنارِ per-IP، نه به‌جایش. per-IP تنها، دو
# مسئله دارد: مهاجمی که تلاش‌ها را روی چند آدرس پخش کند بی‌نهایت شانس
# روی یک حساب دارد، و — حالتِ رایج‌ترِ واقعی — یک NAT ِ مشترک یعنی
# تایپِ اشتباهِ یک کاربر همه‌ی پشتِ آن آدرس را می‌بندد.
#
# ۱۰ در ۳۰۰ ثانیه، عمداً شل‌تر از ۵ در ۶۰ ثانیه‌ی per-IP: کاربرِ مشروع
# ممکن است از چند دستگاه تلاش کند. و **خودبه‌خود باز می‌شود** — قفلی که
# دخالتِ ادمین بخواهد، خودش سلاحِ انکارِ سرویس علیهِ نامِ کاربریِ معلوم است.
_LOGIN_USER_MAX = 10
_LOGIN_USER_WINDOW = 300
_login_attempts_user = {}
_login_user_lock = threading.Lock()


def login_user_allowed(username):
    now = time.time()
    u = str(username)
    with _login_user_lock:
        a = [t for t in _login_attempts_user.get(u, [])
             if now - t < _LOGIN_USER_WINDOW]
        if len(a) >= _LOGIN_USER_MAX:
            _login_attempts_user[u] = a
            return False
        a.append(now)                         # رزروِ اتمیک (رجوع به login_allowed)
        _login_attempts_user[u] = a
        _login_pending_user[u] = _login_pending_user.get(u, 0) + 1
        return True


def login_user_succeeded(username):
    u = str(username)
    with _login_user_lock:
        if _login_pending_user.get(u, 0) > 0:
            _login_pending_user[u] -= 1
            a = _login_attempts_user.get(u)
            if a:
                a.pop()
            if not _login_pending_user[u]:
                _login_pending_user.pop(u, None)


def login_user_failed(username):
    now = time.time()
    u = str(username)
    with _login_user_lock:
        if _login_pending_user.get(u, 0) > 0:
            _login_pending_user[u] -= 1
            if not _login_pending_user[u]:
                _login_pending_user.pop(u, None)
            _login_attempts_user.setdefault(u, [])
        else:
            _login_attempts_user.setdefault(u, []).append(now)
        if len(_login_attempts_user) > 4096:      # همان ثابت‌های بقیه
            for k in [k for k, v in _login_attempts_user.items()
                      if not v or now - v[-1] > 3600]:
                _login_attempts_user.pop(k, None)
                _login_pending_user.pop(k, None)   # رجوع به login_failed


def make_session_cookie(user):
    payload = json.dumps({"exp": int(time.time()) + SESSION_TTL,
                          "u": user["username"], "r": user["role"],
                          "s": user.get("stoken", ""),
                          "n": secrets.token_hex(8)}).encode()
    b = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    sig = hmac.new(CONFIG["secret"].encode(), b.encode(), hashlib.sha256).hexdigest()
    return b + "." + sig


# مهلتِ بی‌کاریِ نشست: CONFIG["session_idle_min"] (دقیقه؛ ۰/نبود = خاموش).
# کوکی بی‌حالت است، پس آخرین فعالیتِ هر نشست (کلید = nonce ِ کوکی) در حافظه
# نگه داشته می‌شود؛ بعد از ری‌استارت نشست‌ها «تازه» شمرده می‌شوند (کرانِ
# مطلقِ SESSION_TTL همچنان در خودِ کوکی است).
_session_seen = {}
_session_seen_lock = threading.Lock()


def session_idle_limit():
    try:
        return max(0, int(CONFIG.get("session_idle_min") or 0)) * 60
    except (TypeError, ValueError):
        return 0


def _session_touch(nonce, now):
    """True اگر نشست هنوز فعال است (و آخرین فعالیت به‌روز شد)."""
    limit = session_idle_limit()
    if not limit or not nonce:
        return True
    with _session_seen_lock:
        last = _session_seen.get(nonce)
        if last is not None and now - last > limit:
            _session_seen.pop(nonce, None)
            return False
        _session_seen[nonce] = now
        if len(_session_seen) > 4096:
            for k in [k for k, v in _session_seen.items() if now - v > limit]:
                _session_seen.pop(k, None)
    return True


def verify_session_cookie(value):
    """None اگر نامعتبر؛ وگرنه dict سشن {u, r, exp} با نقشِ به‌روزِ کاربر.

    نقش از رکورد فعلی کاربر گرفته می‌شود نه از خود کوکی، و توکن سشن (s)
    باید با stoken فعلی کاربر بخواند تا با تغییر/ریست رمز باطل شود.
    """
    try:
        b, sig = value.split(".", 1)
        good = hmac.new(CONFIG["secret"].encode(), b.encode(),
                        hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, sig):
            return None
        pad = "=" * (-len(b) % 4)
        payload = json.loads(base64.urlsafe_b64decode(b + pad))
        if payload.get("exp", 0) <= time.time():
            return None
        user = find_user(payload.get("u", ""))
        if not user:
            return None
        # حسابِ غیرفعال/منقضی: سشنِ موجود هم بلافاصله بی‌اعتبار می‌شود
        if not user_is_active(user):
            return None
        if not hmac.compare_digest(str(payload.get("s", "")),
                                   str(user.get("stoken", ""))):
            return None
        if not _session_touch(payload.get("n", ""), time.time()):
            return None
        payload["r"] = user["role"]  # نقشِ به‌روز، نه نقشِ منجمد در کوکی
        return payload
    except Exception:
        return None


# ---- محدودیت IP (پنل فقط از این آدرس‌ها؛ خالی = همه؛ 127.0.0.1 همیشه مجاز)

def trusted_proxies():
    """شبکه‌های reverse proxy ِ مورداعتماد از config (لیستِ IP/CIDR)."""
    out = []
    for e in (CONFIG.get("trusted_proxies") or []):
        try:
            out.append(ipaddress.ip_network(str(e).strip(), strict=False))
        except ValueError:
            continue
    return out


def _ip_in_nets(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


# نشانیِ «کلاینتِ نامعلوم»: وقتی درخواست از proxy ِ معتمد آمده ولی هدرها
# خراب یا متناقض‌اند. عمداً نه loopback است (که allowlist و تأییدِ تلگرام
# را دور می‌زند) و نه نشانیِ کسی دیگر؛ سطلِ rate-limit ِ مشترکِ جاعل‌هاست.
UNKNOWN_CLIENT_IP = "0.0.0.0"


def _forwarded_hop(h):
    """یک hop ِ هدر → IP ِ خالص، یا None اگر IP نباشد."""
    h = h.strip()
    if h.startswith("[") and "]" in h:              # [v6] یا [v6]:port
        h = h[1:h.index("]")]
    elif h.count(":") == 1 and "." in h:            # a.b.c.d:port
        h = h.split(":")[0]
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        return None


def client_ip_from(peer_ip, headers):
    """IP ِ واقعیِ کلاینت با توجه به proxyهای مورداعتماد (رجوع به _client_ip).

    سه راهِ جعل که بسته شده‌اند:

    * هدرِ خراب یا زنجیره‌ی «فقط-معتمد» قبلاً به peer برمی‌گشت؛ پشتِ proxy
      ِ همان میزبان peer یعنی 127.0.0.1 — همان نشانی‌ای که allowlist و تأییدِ
      تلگرام را دور می‌زند. حالا خراب → UNKNOWN_CLIENT_IP، و loopback ِ
      آمده از هدر هرگز کلاینت شمرده نمی‌شود.
    * proxy‌ای که فقط X-Real-IP می‌گذارد، X-Forwarded-For ِ کلاینت را دست‌نخورده
      رد می‌کند؛ proxy‌ای که فقط XFF می‌گذارد، X-Real-IP را. اگر هر دو باشند
      و X-Real-IP نامعتمد باشد، باید با نتیجه‌ی XFF یکی باشند (nginx ِ
      رایج هر دو را از $remote_addr می‌سازد)؛ ناهمخوانی یعنی یکی جعلی است.
    * HAProxy و برخی دیگر XFF را سطرِ **جدا** اضافه می‌کنند؛ headers.get
      فقط سطرِ اول — سطرِ مهاجم — را می‌دید. همه‌ی سطرها به ترتیب الحاق
      می‌شوند.

    بدونِ هیچ هدری peer برمی‌گردد: دسترسیِ اضطراریِ SSH port-forward
    مستقیم به پورتِ پنل همین است، و proxy ِ درست‌پیکربندی‌شده همیشه
    هدر می‌گذارد، پس مهاجم نمی‌تواند به این حالت برسد.
    """
    nets = trusted_proxies()
    if not nets or not _ip_in_nets(peer_ip, nets):
        return peer_ip
    get_all = getattr(headers, "get_all", None)
    lines = (get_all("X-Forwarded-For") or []) if get_all \
        else [headers.get("X-Forwarded-For") or ""]
    hops = [h.strip() for line in lines for h in str(line).split(",")
            if h.strip()]
    real_raw = (headers.get("X-Real-IP") or "").strip()
    if not hops and not real_raw:
        return peer_ip
    real = None
    if real_raw:
        real = _forwarded_hop(real_raw)
        if real is None:
            return UNKNOWN_CLIENT_IP
    if hops:
        client = None
        # از راست: proxyهای معتمد را کنار بزن؛ اولین آدرسِ نامعتمد کلاینت است
        for h in reversed(hops):
            ip = _forwarded_hop(h)
            if ip is None:
                return UNKNOWN_CLIENT_IP
            client = ip
            if not _ip_in_nets(ip, nets):
                break
        # همه معتمد → چپ‌ترین (همان client ِ آخرِ حلقه)
        if real is not None and not _ip_in_nets(real, nets) \
                and real != client:
            return UNKNOWN_CLIENT_IP
    else:
        client = real
    try:
        if ipaddress.ip_address(client).is_loopback:
            return UNKNOWN_CLIENT_IP
    except ValueError:
        return UNKNOWN_CLIENT_IP
    return client


def request_is_https(peer_ip, headers):
    """آیا مرورگر پنل را با https می‌بیند؟

    با tls_cert ِ خودِ پنل، بله. پشتِ reverse proxy ای که TLS را خاتمه
    می‌دهد، پنل http سرو می‌کند و قبلاً لینکِ اشتراک را http:// می‌ساخت
    (مرورگر روی سایتِ https به http می‌افتاد یا اصلاً باز نمی‌کرد) و کوکیِ
    سشن را بدونِ Secure می‌داد. X-Forwarded-Proto فقط از proxy ِ **معتمد**
    خوانده می‌شود — همان قاعده‌ی client_ip_from؛ از کلاینتِ مستقیم، جعل است.
    اولین مقدار (proxy ِ لبه) ملاک است.
    """
    if CONFIG.get("tls_cert"):
        return True
    nets = trusted_proxies()
    if not nets or not _ip_in_nets(peer_ip, nets):
        return False
    proto = (headers.get("X-Forwarded-Proto") or "").split(",")[0]
    return proto.strip().lower() == "https"


def ip_allowed(ip):
    allow = CONFIG.get("allow_ips") or []
    if not allow:
        return True
    if ip in ("127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allow:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


# محدودیت تلاش ورود: حداکثر ۵ تلاش ناموفق در ۶۰ ثانیه به ازای هر IP
_login_attempts = {}
# IP → آستانه‌ای که هشدارش با آن رفت. **مقدار، نه فقط عضویت**: اگر تنها
# «هشدار رفت» را نگه داریم، ادمینی که وسطِ حمله آستانه را پایین می‌آورد
# هرگز هشدارِ تازه نمی‌گیرد — همان حالتی که این تغییر قرار بود درستش کند.
# همراهِ _login_attempts هرس می‌شود؛ جدا نگه‌داشتنش یعنی رشدِ بی‌پایان و
# IPای که یک بار حمله کرده دیگر هرگز هشدار نمی‌گیرد.
_login_alerted = {}
_login_lock = threading.Lock()
_totp_pending = {}  # username -> (secret, مهلت) در انتظار تأیید
_TOTP_PENDING_TTL = 600


# جای‌های رزروشده: تلاش‌هایی که login_allowed پذیرفته ولی هنوز نتیجه‌شان
# معلوم نیست. 🪤 پیش از این سنجش و ثبت از هم جدا بودند (check-then-act):
# N درخواستِ هم‌زمان همه از «< 5» رد می‌شدند، ~۱۵۰ms PBKDF2 می‌گرفتند و
# بعد ثبت می‌شدند — یعنی سقفِ ۵ تلاش با موازی‌سازی دور می‌خورد. حالا جا
# در همان لحظه‌ی سنجش گرفته می‌شود؛ شکست همان جا را نگه می‌دارد و موفقیت
# پس می‌دهد.
_login_pending = {}          # ip → تعدادِ رزروهای بازِ
_login_pending_user = {}     # username → همان


def login_allowed(ip):
    now = time.time()
    with _login_lock:
        attempts = [t for t in _login_attempts.get(ip, []) if now - t < 60]
        if len(attempts) >= 5:
            _login_attempts[ip] = attempts
            return False
        attempts.append(now)                  # رزروِ اتمیک
        _login_attempts[ip] = attempts
        _login_pending[ip] = _login_pending.get(ip, 0) + 1
        return True


def login_succeeded(ip):
    """ورودِ موفق: رزروِ login_allowed پس داده می‌شود (موفقیت تلاشِ ناموفق نیست)."""
    with _login_lock:
        if _login_pending.get(ip, 0) > 0:
            _login_pending[ip] -= 1
            a = _login_attempts.get(ip)
            if a:
                a.pop()
            if not _login_pending[ip]:
                _login_pending.pop(ip, None)


def login_failed(ip):
    now = time.time()
    with _login_lock:
        if _login_pending.get(ip, 0) > 0:
            # رزروِ همین تلاش از قبل در فهرست است؛ فقط «باز» نیست دیگر
            _login_pending[ip] -= 1
            if not _login_pending[ip]:
                _login_pending.pop(ip, None)
            _login_attempts.setdefault(ip, [])
        else:
            _login_attempts.setdefault(ip, []).append(now)
        # نشتِ حافظه: IPهایی که مدتی خطا نداشته‌اند را دور بریز
        if len(_login_attempts) > 4096:
            for k in [k for k, v in _login_attempts.items()
                      if not v or now - v[-1] > 3600]:
                _login_attempts.pop(k, None)
                _login_alerted.pop(k, None)   # حالتِ هشدار هم با آن برود
                # رزروِ بازِ یک ساعت پیش هرگز بسته نمی‌شود (درخواستی که وسطِ
                # ورود به ۵۰۰ خورد). بی این، کلیدش نشت می‌کرد و — بدتر —
                # اولین شکستِ بعدیِ همان IP فقط این رزروِ کهنه را می‌بست و
                # هیچ تلاشی ثبت نمی‌کرد: یک شانسِ مجانی.
                _login_pending.pop(k, None)
        recent10 = sum(1 for t in _login_attempts[ip] if now - t < 600)
        alerted_at = _login_alerted.get(ip)
    # هشدارِ حمله‌ی جستجوی رمز: N خطای اخیر از یک IP (لبه‌ای، هر ۱۰ دقیقه یک‌بار)
    #
    # `>=` به‌همراهِ یادداشتِ آستانه‌ای که هشدار با آن رفت، نه `== thr`:
    # با برابریِ دقیق، هر مسیری که شمارش را از آستانه **بپراند** هشدار را
    # کاملاً از بین می‌برد. واقعی‌ترینش این است که ادمین وسطِ حمله آستانه
    # را پایین بیاورد — شمارش از قبل ۱۲ است و آستانه ۵ می‌شود، پس تا
    # خالی‌شدنِ پنجره‌ی ۶۰۰ ثانیه هرگز برابر نمی‌شوند. دقیقاً همان لحظه‌ای
    # که اپراتور بیشترین نیاز را به سیگنال دارد. انقضای پنجره هم می‌تواند
    # شمارش را جابه‌جا کند و از آستانه بپراند.
    #
    # سه خاصیتِ لازم، و چرا نشانه‌ی بولی هر سه را نمی‌دهد:
    #   ۱. آستانه‌ی ثابت + خطاهای بیشتر ⇒ اسپم نشود.  (بولی می‌دهد)
    #   ۲. شمارش زیرِ آستانه برگردد ⇒ حمله‌ی بعدی دوباره هشدار بگیرد.
    #      (بولی می‌دهد)
    #   ۳. **آستانه پایین بیاید ⇒ هشدارِ تازه بیاید.** بولی این را
    #      نمی‌دهد؛ «هشدار رفته» می‌ماند و وضعیتِ تازه بی‌صدا می‌شود.
    # پس مقدارِ ذخیره‌شده خودِ آستانه است. آستانه فقط با دستِ انسان عوض
    # می‌شود، پس این نمی‌تواند منبعِ اسپم باشد.
    #
    # پاک‌شدن با ورودِ **موفق** عمداً نیست: مهاجمی که یک رمز را درست حدس
    # بزند نباید بتواند هشدار را ریست کند.
    try:
        thr = alert_cfg()["login_fails"]
        if recent10 >= thr and alerted_at != thr:
            with _login_lock:
                _login_alerted[ip] = thr
            ALERTS.event("login",
                         A('alert.login_failed.1', p0=recent10, p1=ip, p2=_host_label()))
        elif recent10 < thr and alerted_at is not None:
            with _login_lock:
                _login_alerted.pop(ip, None)
    except Exception:
        pass


# محدودیت درخواست به لینک اشتراک: حداکثر ۲۰ در ۶۰ ثانیه به ازای هر IP
_share_hits = {}
_share_lock = threading.Lock()


def share_rate_ok(ip):
    now = time.time()
    with _share_lock:
        hits = [t for t in _share_hits.get(ip, []) if now - t < 60]
        hits.append(now)
        _share_hits[ip] = hits
        # نشتِ حافظه: کلیدهای IP هرگز حذف نمی‌شدند — فقط مهرهای زمانیِ
        # داخلشان هرس می‌شد. ‏/s/ بدونِ احراز هویت است، پس هر آدرسی که یک
        # بار درخواست بدهد یک ورودیِ دائمی می‌سازد. همان الگو و همان دو
        # ثابتِ login_failed، که این سوییپ را از قبل دارد؛ دو محدودکننده
        # با آستانه‌های متفاوت در یک فایل خودش دامِ نگه‌داری است.
        #
        # سوییپ داخلِ قفل است و نمی‌تواند ورودیِ تازه‌افزوده را ببرد
        # (‏v[-1] همین now است).
        if len(_share_hits) > 4096:
            for k in [k for k, v in _share_hits.items()
                      if not v or now - v[-1] > 3600]:
                _share_hits.pop(k, None)
        return len(hits) <= 20


# ------------------------------------------------- پارس کانفیگ کاربرها (wg1udp)

PEER_KEYS = ("[Peer]", "PublicKey", "AllowedIPs", "Endpoint",
             "PersistentKeepalive", "PresharedKey")
LABEL_RE = re.compile(r"^#!!!(\S+)\s*$")


def _is_peer_line(line):
    """خطی که (شاید با یک # اول) یکی از کلیدهای بلوک peer باشد."""
    s = line.strip()
    if s.startswith("#"):
        s = s[1:].strip()
    for k in PEER_KEYS:
        if s.startswith(k):
            return True
    return False


def conf_path(iface):
    # basename مانع هرگونه پیمایش مسیر (../ یا /) در نام اینترفیس می‌شود
    return os.path.join(WG_DIR, os.path.basename(str(iface)) + ".conf")


def _conf_is_server_type(path):
    """اینترفیس «سمت کاربر»: ListenPort دارد و هیچ peer ای Endpoint ندارد."""
    has_listen = False
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("ListenPort"):
                    has_listen = True
                elif s.startswith("Endpoint"):
                    return False
    except OSError:
        return False
    return has_listen


_server_ifaces_cache = {"ts": 0.0, "val": []}


def server_ifaces():
    """لیست اینترفیس‌های سمت کاربر؛ از config یا تشخیص خودکار (کش ۶۰ ثانیه)."""
    explicit = CONFIG.get("server_ifaces")
    if explicit:
        return list(explicit)
    now = time.time()
    if now - _server_ifaces_cache["ts"] < 60:
        return list(_server_ifaces_cache["val"])
    found = []
    for iface in list_all_wg_confs():
        if _conf_is_server_type(conf_path(iface)):
            found.append(iface)
    _server_ifaces_cache["ts"] = now
    _server_ifaces_cache["val"] = found
    return list(found)


def iface_listen_port(iface):
    try:
        with open(conf_path(iface), "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("ListenPort"):
                    return s.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def iface_addresses(iface):
    """همه‌ی آدرس‌های [Interface] Address (v4 و v6) به‌صورت ip_interface."""
    out = []
    try:
        with open(conf_path(iface), "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("[Peer]") or s.startswith("#!!!"):
                    break
                if s.startswith("Address") and "=" in s:
                    for part in s.split("=", 1)[1].split(","):
                        part = part.strip()
                        if not part:
                            continue
                        try:
                            out.append(ipaddress.ip_interface(part))
                        except ValueError:
                            continue
    except OSError:
        pass
    return out


def iface_subnet(iface):
    """رنجِ IPv4 ِ کاربرهای اینترفیس (رشته‌ی CIDR ِ نرمال‌شده).

    اولویت: CONFIG["user_subnets"]؛ وگرنه از خطِ Address با **پیشوندِ واقعی**
    (‎/22 دیگر /24 خوانده نمی‌شود). Address ِ سرور معمولاً /32 یا بی‌پیشوند
    است؛ آن‌جا مثلِ قبل /24 فرض می‌شود.
    """
    subnets = CONFIG.get("user_subnets", {})
    if iface in subnets:
        try:
            return str(ipaddress.ip_network(str(subnets[iface]), strict=False))
        except ValueError:
            return None
    for a in iface_addresses(iface):
        if a.version != 4:
            continue
        pl = a.network.prefixlen
        if pl >= 31:
            return str(ipaddress.ip_network(str(a.ip) + "/24", strict=False))
        return str(a.network)
    return None


_awg_checked = {"has": None}


def awg_available():
    if _awg_checked["has"] is None:
        _awg_checked["has"] = bool(shutil.which("awg"))
    return _awg_checked["has"]


def live_interfaces():
    """اینترفیس‌های زنده‌ی WireGuard + AmneziaWG."""
    out_all = []
    rc, out, _ = run(["wg", "show", "interfaces"], timeout=10)
    if rc == 0:
        out_all += out.split()
    if awg_available():
        rc, out, _ = run(["awg", "show", "interfaces"], timeout=10)
        if rc == 0:
            out_all += out.split()
    return out_all


def read_proc_net_dev():
    """شمارنده‌ی کل هر اینترفیس شبکه از /proc/net/dev.

    خروجی: {iface: (rx_bytes, tx_bytes)} برای همه‌ی اینترفیس‌ها.
    """
    out = {}
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    for line in lines[2:]:  # دو خط اول سرستون است
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        cols = rest.split()
        if len(cols) < 16:
            continue
        try:
            out[name] = (int(cols[0]), int(cols[8]))  # rx_bytes, tx_bytes
        except ValueError:
            continue
    return out


# ------------------------------------------- متریک‌های سیستم (CPU/RAM/DISK/پنل)

_CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
try:
    _NCPU = os.cpu_count() or 1
except Exception:
    _NCPU = 1


def _read_cpu_times():
    """(total_jiffies, idle_jiffies) از خط aggregate در /proc/stat."""
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline()
    except OSError:
        return None
    parts = line.split()
    if not parts or parts[0] != "cpu":
        return None
    try:
        vals = [int(x) for x in parts[1:]]
    except ValueError:
        return None
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
    return sum(vals), idle


def _read_self_cpu_jiffies():
    """utime+stime پروسه‌ی پنل (jiffies) از /proc/self/stat."""
    try:
        with open("/proc/self/stat", "r", encoding="utf-8") as f:
            data = f.read()
    except OSError:
        return None
    # فیلد comm ممکن است پرانتز/فاصله داشته باشد؛ از بعد از آخرین ')' می‌خوانیم.
    rp = data.rfind(")")
    if rp < 0:
        return None
    fields = data[rp + 2:].split()
    # پس از comm: field[0]=state ... utime=field[11], stime=field[12] (۰-اندیس)
    try:
        return int(fields[11]) + int(fields[12])
    except (IndexError, ValueError):
        return None


def read_mem_pct():
    """(used_pct, total_kb, avail_kb) رم سرور از /proc/meminfo."""
    total = avail = None
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1])
                if total is not None and avail is not None:
                    break
    except (OSError, ValueError):
        return None
    if not total:
        return None
    used_pct = max(0.0, min(100.0, (total - (avail or 0)) * 100.0 / total))
    return used_pct, total, (avail or 0)


def read_disk_pct(path="/"):
    """(used_pct, total_bytes, used_bytes) ریشه‌ی فایل‌سیستم."""
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    if not total:
        return None
    used = total - (st.f_bfree * st.f_frsize)
    used_pct = max(0.0, min(100.0, used * 100.0 / total))
    return used_pct, total, used


def read_self_rss_mb():
    """RSS پروسه‌ی پنل بر حسب مگابایت از /proc/self/status."""
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0  # kB -> MB
    except (OSError, ValueError):
        return None
    return None


_iface_meta_cache = {"ts": 0.0, "val": {}}


def iface_meta_all():
    """متادیتای همه‌ی اینترفیس‌ها (آدرس‌ها، MTU، وضعیت) با کش ۳۰ ثانیه."""
    now = time.time()
    if now - _iface_meta_cache["ts"] < 30 and _iface_meta_cache["val"]:
        return _iface_meta_cache["val"]
    meta = {}
    rc, out, _ = run(["ip", "-j", "addr", "show"], timeout=10)
    if rc == 0:
        try:
            for it in json.loads(out):
                addrs = [a.get("local", "") for a in it.get("addr_info", [])
                         if a.get("family") == "inet"]
                meta[it["ifname"]] = {
                    "addresses": addrs,
                    "mtu": it.get("mtu", 0),
                    "up": it.get("operstate") in ("UP", "UNKNOWN"),
                }
        except (ValueError, KeyError):
            pass
    _iface_meta_cache["ts"] = now
    _iface_meta_cache["val"] = meta
    return meta


def classify_iface(name, addrs):
    """نوع و «کدِ نقشِ» اینترفیس را تعیین می‌کند.

    ⚠️ مقدارِ دوم عمداً یک **کدِ پایدارِ لاتین** است، نه متنِ نمایشی. پیش از
    چهارزبانه‌شدن اینجا برچسبِ فارسی برمی‌گشت و همان رشته هم در API می‌رفت، هم
    برچسبِ متریکِ Prometheus می‌شد و هم سه جا (دو جای پایتون و یک جای JS) با
    literal ِ فارسی مقایسه می‌شد — یعنی ترجمه‌اش منطق را بی‌صدا می‌شکست.
    متنِ خواندنی از روی همین کد و با کلیدِ ui.role.* ساخته می‌شود.
    """
    if name == "lo":
        return "loopback", "loopback"
    if name in server_ifaces():
        return "wireguard", "wg_users"
    if name.startswith("awg"):
        return "amneziawg", "awg_egress"
    if name.startswith("wg"):
        return "wireguard", "wg_egress"
    private = False
    public = False
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_private:
            private = True
        else:
            public = True
    if name.startswith(("eth", "en", "eno", "ens")):
        # داشتن هر آدرس private یعنی سمت داخلی (حتی اگر IP عمومی هم داشته باشد)
        if private:
            return "ethernet", "lan"
        if public:
            return "ethernet", "wan"
        return "ethernet", "nic"
    if addrs and "@" not in name:
        return "other", "lan_other" if private else "other"
    return "other", "p2p"


_BLOCKS_CACHE = {}          # path -> ((mtime_ns, size), blocks)
_BLOCKS_CACHE_LOCK = threading.Lock()


def parse_user_blocks(iface, lines=None):
    """بلوک‌های #!!!name را از کانفیگ اینترفیس استخراج می‌کند.

    خروجی: لیست dict با name, start, end (بازه‌ی خطوط شامل label)،
    enabled, public_key, allowed_ips, psk, keepalive.

    وقتی lines داده نشود، نتیجه به کلیدِ (mtime_ns, size) ِ فایل کش می‌شود:
    build_stats هر ۲ ثانیه برای هر تب و هر scrape ِ Prometheus همه‌ی
    کانفیگ‌ها را از نو می‌خواند و پارس می‌کرد. هر نوشتنِ پنل mtime را عوض
    می‌کند، پس کش خودبه‌خود باطل می‌شود. کپیِ کم‌عمقِ dictها برمی‌گردد تا
    فراخوان‌ها کش را جهش ندهند.
    """
    key = None
    if lines is None:
        path = conf_path(iface)
        st = os.stat(path)
        key = (st.st_mtime_ns, st.st_size)
        with _BLOCKS_CACHE_LOCK:
            hit = _BLOCKS_CACHE.get(path)
        if hit is not None and hit[0] == key:
            return [dict(b) for b in hit[1]]
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    blocks = _parse_user_blocks(lines)
    if key is not None:
        with _BLOCKS_CACHE_LOCK:
            _BLOCKS_CACHE[path] = (key, [dict(b) for b in blocks])
    return blocks


def _parse_user_blocks(lines):
    blocks = []
    i = 0
    while i < len(lines):
        m = LABEL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        start = i
        j = i + 1
        last_content = i
        while j < len(lines):
            if LABEL_RE.match(lines[j]):
                break
            s = lines[j].strip()
            if s == "" :
                j += 1
                continue
            if _is_peer_line(lines[j]):
                last_content = j
                j += 1
                continue
            break  # خطی که مال بلوک نیست ([Interface] و ...)
        end = last_content
        block_lines = lines[start:end + 1]
        enabled = any(l.strip().startswith("[Peer]") for l in block_lines)
        pub, allowed, psk, keepalive = "", "", "", 0
        for l in block_lines:
            s = l.strip().lstrip("#").strip()
            val = s.split("=", 1)[1].strip() if "=" in s else ""
            if s.startswith("PublicKey"):
                pub = val
            elif s.startswith("AllowedIPs"):
                allowed = val
            elif s.lower().startswith("presharedkey"):
                psk = val
            elif s.lower().startswith("persistentkeepalive"):
                try:
                    keepalive = int(val)
                except ValueError:
                    keepalive = 0
        # psk و keepalive هم خوانده می‌شوند تا اعمالِ زنده (wg set) بعد از
        # remove ِ کاملِ peer بتواند همان چیزی را برگرداند که فایل می‌گوید،
        # نه فقط allowed-ips.
        blocks.append({"name": name, "start": start, "end": end,
                       "enabled": enabled, "public_key": pub,
                       "allowed_ips": allowed, "psk": psk,
                       "keepalive": keepalive})
        i = end + 1
    return blocks


_conf_lock = threading.Lock()


def backup_conf(path, keep=50):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    base = os.path.basename(path)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S.%f")
    dst = os.path.join(BACKUP_DIR, base + "." + ts)
    shutil.copy2(path, dst)
    # فقط جدیدترین‌ها نگه داشته شوند (نام‌ها بر اساس timestamp مرتب می‌شوند)
    try:
        files = sorted(f for f in os.listdir(BACKUP_DIR)
                       if f.startswith(base + "."))
        for f in files[:-keep]:
            os.remove(os.path.join(BACKUP_DIR, f))
    except OSError:
        pass
    return dst


def write_conf_atomic(path, lines):
    tmp = path + ".tmp-wgpanel"
    # مود **پیش از** نوشتن خوانده و در همان os.open داده می‌شود. پیش از
    # این فایلِ موقت با umask ِ پیش‌فرض (معمولاً ۰۶۴۴) ساخته می‌شد،
    # کلیدهای خصوصیِ WireGuard داخلش نوشته می‌شد، و تازه بعدش chmod
    # می‌خورد — یک پنجره‌ی کوتاه با محتوای کامل و مودِ باز.
    # حفظِ مودِ فایلِ موجود عمدی است و دست‌نخورده ماند؛ فقط جای خواندنش
    # عوض شد. فایلِ تازه (نبودِ مقصد) ۰۶۰۰ می‌گیرد نه umask.
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        mode = 0o600
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
        f.flush()
        os.fsync(f.fileno())     # بدونِ این، قطعِ برق = wgX.conf ِ خالی
    os.chmod(tmp, mode)      # os.open را umask می‌تراشد؛ این قطعی‌اش می‌کند
    os.rename(tmp, path)
    _fsync_dir(os.path.dirname(path) or ".")


def _fsync_dir(d):
    """rename را روی دیسک قطعی می‌کند (fsync ِ دایرکتوری)؛ خطا نادیده."""
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _valid_iface(iface):
    return bool(re.fullmatch(r"wg[0-9a-zA-Z]+", iface)) and \
        os.path.exists(conf_path(iface))


def _wg_set_peer(iface, pub, allowed=None, psk=None, keepalive=None):
    """یک peer را زنده با **یک** فراخوانیِ `wg set` هم‌شکلِ فایل می‌کند.

    psk: None = دست نزن، "" = حذف، رشته = ست. wg کلید را از فایل می‌خواند و
    «حذف» را فقط از فایلِ **صفر بایتی** می‌فهمد — یک `\\n` تنها «Invalid
    length key» است. خروجی: (ok, پیامِ خطا).

    allowed و keepalive هم همین قرارداد را دارند: None = دست نزن، و مقدارِ
    «خالی» (رشته‌ی "" / عددِ 0) یعنی **پاک کن**. پیش از این هر دو با
    `if allowed:` / `if keepalive:` فیلتر می‌شدند، پس حذفِ PersistentKeepalive
    یا خالی‌کردنِ AllowedIPs در فایل هیچ‌وقت به کرنل نمی‌رسید و مقدارِ کهنه
    تا ری‌استارتِ wg-quick زنده می‌ماند.
    """
    args = ["wg", "set", iface, "peer", pub]
    tmp = None
    try:
        if psk is not None:
            fd, tmp = tempfile.mkstemp(prefix="wgpsk-")
            os.write(fd, (psk + "\n").encode() if psk else b"")
            os.close(fd)
            os.chmod(tmp, 0o600)
            args += ["preshared-key", tmp]
        if allowed is not None:
            args += ["allowed-ips", allowed.replace(" ", "")]
        if keepalive is not None:
            args += ["persistent-keepalive", str(int(keepalive or 0))]
        rc, out, err = run(args)
        return rc == 0, (err or out)
    finally:
        if tmp:
            try:
                os.remove(tmp)
            except OSError:
                pass


def _peer_live_state(iface, lines=None):
    """{public_key: (allowed_ips, psk, keepalive)} برای بلوک‌های **فعال**.

    همان چیزی که کرنل باید داشته باشد؛ مبنای مقایسه‌ی ناظرِ فایل و
    بازیابیِ بکاپ. فایلِ ناموجود = هیچ peer ای.
    """
    try:
        blocks = parse_user_blocks(iface, lines)
    except OSError:
        return {}
    return {b["public_key"]: (b["allowed_ips"].replace(" ", ""),
                              b["psk"], b["keepalive"])
            for b in blocks if b["enabled"] and b["public_key"]}


def apply_conf_delta(iface, old, new, actor=ACTOR_MANUAL):
    """تفاوتِ دو وضعیتِ فایل (خروجیِ _peer_live_state) را با wg set روی
    اینترفیسِ زنده اعمال می‌کند. peerهایی که فقط در runtime هستند دست
    نمی‌خورند. خروجی: تعدادِ تغییرهای اعمال‌شده."""
    if iface not in live_interfaces():
        return 0
    n = 0
    for pub, (allowed, psk, keep) in new.items():
        if old.get(pub) == (allowed, psk, keep):
            continue
        prev = old.get(pub)
        # PSK فقط وقتی فرستاده می‌شود که تازه/تغییرکرده باشد — «"" = حذف»
        # وقتی قبلاً PSK داشت و حالا ندارد.
        psk_arg = None
        if prev is None or prev[1] != psk:
            psk_arg = psk
        ok, err = _wg_set_peer(iface, pub, allowed, psk=psk_arg, keepalive=keep)
        n += 1
        log_action("autosync %s: peer %s… set %s (%s)"
                   % (iface, pub[:8], allowed, "ok" if ok else err.strip()))
        audit(actor, "peer", "peer.sync.auto",
              "%s @ %s" % (pub[:12] + "…", iface),
              adet("ui.audit.det.peeradded" if prev is None
                   else "ui.audit.det.peerchanged", ips=allowed), ok=ok)
    for pub in old:
        if pub in new:
            continue
        rc, _, err = run(["wg", "set", iface, "peer", pub, "remove"])
        ok = rc == 0
        n += 1
        log_action("autosync %s: peer %s… removed (%s)"
                   % (iface, pub[:8], "ok" if ok else err.strip()))
        audit(actor, "peer", "peer.sync.auto",
              "%s @ %s" % (pub[:12] + "…", iface),
              adet("ui.audit.det.peerremoved"), ok=ok)
    return n


def set_peer_enabled(iface, name, enable):
    """کامنت/آن‌کامنت بلوک peer در فایل + اعمال زنده با wg set."""
    if not _valid_iface(iface):
        return False, "api.err.iface"
    with _conf_lock:
        path = conf_path(iface)
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        blocks = parse_user_blocks(iface, lines)
        blk = next((b for b in blocks if b["name"] == name), None)
        if blk is None:
            return False, aerr("api.err.peer.notinconf", v=name)
        if blk["enabled"] == bool(enable):
            return True, "api.ok.nochange"
        backup_conf(path)
        for idx in range(blk["start"] + 1, blk["end"] + 1):
            line = lines[idx]
            if not _is_peer_line(line):
                continue
            stripped = line.lstrip()
            if enable:
                if stripped.startswith("#"):
                    # فقط یک # اول را بردار
                    pos = line.index("#")
                    lines[idx] = line[:pos] + line[pos + 1:]
            else:
                if not stripped.startswith("#"):
                    lines[idx] = "#" + line
        write_conf_atomic(path, lines)

    if enable:
        META.clear_auto_disabled(iface, name)

    # اعمال زنده (فقط اگر اینترفیس بالا باشد؛ در غیر این صورت با wg-quick up اعمال می‌شود)
    live = iface in live_interfaces()
    ok, err = True, ""
    if live:
        if enable:
            # 🪤 غیرفعال‌کردن peer را **کامل** از کرنل برمی‌دارد (PSK و
            # keepalive هم می‌روند). پیش از این فعال‌کردن فقط allowed-ips
            # را ست می‌کرد؛ کاربرِ PSK‌دار — پیش‌فرضِ همه‌ی کاربران — تا
            # ری‌استارتِ wg-quick هندشیک نمی‌کرد. حالا همان چیزی که فایل
            # می‌گوید یک‌جا اعمال می‌شود.
            ok, err = _wg_set_peer(iface, blk["public_key"],
                                   blk["allowed_ips"],
                                   psk=(blk["psk"] or None),
                                   keepalive=blk["keepalive"])
        else:
            rc, out, err = run(["wg", "set", iface, "peer",
                                blk["public_key"], "remove"])
            ok, err = rc == 0, (err or out)
    if not ok:
        # بدونِ resync: ناظر هنوز حالتِ قبلیِ فایل را دارد، پس در دورِ بعد
        # همین دلتا را دوباره با wg set امتحان می‌کند. resync ِ پیش از این
        # بازگشت، حالتِ «اعمال‌نشده» را «اعمال‌شده» ثبت می‌کرد و کرنل تا
        # ری‌استارت با فایل ناهمخوان می‌ماند — همان الگوی rotate.
        return False, aerr("api.err.apply.edited", v=err)
    WATCHER.resync()
    log_action("peer %s@%s -> %s" % (name, iface,
                                     "enabled" if enable else "disabled"))
    return True, ("api.ok.done" if live else "api.ok.saved.offline")


# اولین ۹ میزبانِ رنج رزرو می‌مانند (سازگار با رفتارِ قبلی: تخصیص از .10)
_FREE_IP_FIRST_OFFSET = 10


def next_free_ip(iface, blocks):
    subnet = iface_subnet(iface)
    if not subnet:
        return None
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    used = set()
    for b in blocks:
        for part in b["allowed_ips"].split(","):
            part = part.strip().split("/")[0]
            try:
                ip = ipaddress.ip_address(part)
                if ip.version == 4 and ip in net:
                    used.add(ip)
            except ValueError:
                pass
    # آدرس‌های خودِ سرور (هرچه در Address هست، نه فقط .1) رزروند
    for a in iface_addresses(iface):
        if a.version == 4:
            used.add(a.ip)
    base = int(net.network_address)
    for host in net.hosts():
        if int(host) - base < _FREE_IP_FIRST_OFFSET:
            continue
        if host not in used:
            return str(host)
    return None


def server_public_key(iface):
    rc, server_pub, _ = run(["wg", "show", iface, "public-key"])
    server_pub = server_pub.strip()
    if rc == 0 and server_pub:
        return server_pub
    # اینترفیس خاموش است؛ کلید عمومی را از کلید خصوصی فایل حساب کن
    try:
        with open(conf_path(iface), "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("PrivateKey"):
                    sp = s.split("=", 1)[1].strip()
                    ok, pub = wg_pubkey(sp)
                    return pub if ok else ""
    except OSError:
        pass
    return ""


def _endpoint_host(ep):
    """میزبانِ یک endpointِ host:port — با IPv6 ِ [::1]:51820 و ::1 ِ خام."""
    ep = (ep or "").strip()
    if not ep:
        return ""
    if ep.startswith("["):
        return ep[1:ep.find("]")] if "]" in ep else ep.strip("[]")
    if ep.count(":") > 1:            # IPv6 ِ بدونِ براکت و بدونِ پورت
        return ep
    return ep.split(":")[0]


def make_client_conf(priv, ip, iface, psk=None, overrides=None, name=None):
    """متن کانفیگ استاندارد کلاینت. overrides: dict با کلیدهای اختیاری
    c_dns, c_mtu, c_keepalive, c_allowed (اگر خالی/None باشند پیش‌فرض سراسری).

    name (اختیاری): برای درجِ کامنتِ نام در ابتدای کانفیگ — بعضی کلاینت‌ها آن را
    به‌عنوان نامِ تونل می‌خوانند و برای خوانایی هم مفید است.
    """
    o = overrides or {}
    server_pub = server_public_key(iface)
    host = CONFIG.get("server_host") or \
        _endpoint_host(CONFIG.get("server_endpoint", ""))
    port = iface_listen_port(iface)
    # میزبانِ IPv6 در Endpoint باید داخلِ [] باشد
    try:
        if ipaddress.ip_address(host).version == 6:
            host = "[%s]" % host
    except ValueError:
        pass
    dns = (o.get("c_dns") or CONFIG.get("client_dns", "1.1.1.1, 8.8.8.8"))
    mtu = (o.get("c_mtu") or CONFIG.get("client_mtu", 1420))
    keep = o.get("c_keepalive")
    keep = keep if keep else 25
    # پیش‌فرض شاملِ ::/0 است تا ترافیکِ IPv6 هم واردِ تونل شود. سرور v6
    # ندارد پس v6 داخلِ تونل دراپ می‌شود و کلاینت (Happy Eyeballs) به v4
    # برمی‌گردد → از مسیرِ WARP می‌رود. بدونِ ::/0، v6ِ نیتیوِ کلاینت از کنارِ
    # تونل مستقیم می‌رفت و مسیریابیِ WARP (مثلاً برای gemini) را دور می‌زد.
    # اگر کاربر AllowedIPsِ سفارشی (split-tunnel) دارد، همان محترم شمرده می‌شود.
    allowed = (o.get("c_allowed")
               or CONFIG.get("client_allowed", "0.0.0.0/0, ::/0"))
    lines = []
    if name:
        # نامِ تونل به‌صورت کامنت (کلاینت‌های سازگار آن را می‌خوانند؛ اپِ رسمی
        # هنگام import فایل از نامِ فایل استفاده می‌کند).
        lines.append("# Name = %s" % name)
    lines += [
        "[Interface]",
        "PrivateKey = %s" % priv,
        "Address = %s/32" % ip,
        "DNS = %s" % dns,
        "MTU = %s" % mtu,
        "",
        "[Peer]",
        "PublicKey = %s" % server_pub,
    ]
    if psk:
        lines.append("PresharedKey = %s" % psk)
    lines += [
        "Endpoint = %s:%s" % (host, port),
        "AllowedIPs = %s" % allowed,
        "PersistentKeepalive = %s" % keep,
    ]
    return "\n".join(lines)


def gen_psk():
    rc, out, _ = run(["wg", "genpsk"])
    return out.strip() if rc == 0 else ""


def apply_preshared_key(iface, pub, psk):
    """اعمال زنده‌ی PSK با فایل موقت 0600 (wg set از فایل می‌خواند، نه آرگومان).
    psk خالی = حذف (فایلِ صفر بایتی — رجوع به _wg_set_peer)."""
    if iface not in live_interfaces():
        return True, ""
    return _wg_set_peer(iface, pub, psk=(psk or ""))


PSK_RE = re.compile(r"^#?\s*PresharedKey\s*=", re.IGNORECASE)


def block_psk(iface, name):
    """مقدار PresharedKey از بلوک کاربر (فعال یا کامنت‌شده)، یا ''."""
    try:
        with open(conf_path(iface), "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return ""
    blocks = parse_user_blocks(iface, lines)
    blk = next((b for b in blocks if b["name"] == name), None)
    if not blk:
        return ""
    for idx in range(blk["start"], blk["end"] + 1):
        s = lines[idx].strip().lstrip("#").strip()
        if s.lower().startswith("presharedkey") and "=" in s:
            return s.split("=", 1)[1].strip()
    return ""


def peer_overrides(iface, name):
    """dict override های کلاینت از متادیتا (فقط کلیدهای c_*)."""
    meta = SAMPLER.meta_cache.get((iface, name)) if SAMPLER else None
    if meta is None:
        meta = META.meta_all().get((iface, name), {})
    return {k: meta.get(k) for k in ("c_dns", "c_mtu", "c_keepalive", "c_allowed")}


def saved_conf_privkey(iface, name):
    """PrivateKey از کانفیگ ذخیره‌شده‌ی کلاینت (برای بازتولید)، یا None."""
    conf = load_client_conf(iface, name)
    if not conf:
        return None
    for line in conf.splitlines():
        s = line.strip()
        if s.startswith("PrivateKey"):
            return s.split("=", 1)[1].strip()
    return None


def peer_ip(iface, name):
    try:
        with open(conf_path(iface), "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return ""
    blocks = parse_user_blocks(iface, lines)
    blk = next((b for b in blocks if b["name"] == name), None)
    if not blk:
        return ""
    return blk["allowed_ips"].split(",")[0].strip().split("/")[0]


def regen_client_conf(iface, name):
    """کانفیگ کلاینت ذخیره‌شده را با override ها و PSK فعلی بازتولید می‌کند.
    فقط برای کاربرهایی که کلید خصوصی‌شان ذخیره است. خروجی: متن یا None."""
    priv = saved_conf_privkey(iface, name)
    if not priv:
        return None
    ip = peer_ip(iface, name)
    conf = make_client_conf(priv, ip, iface, psk=block_psk(iface, name),
                            overrides=peer_overrides(iface, name), name=name)
    save_client_conf(iface, name, conf)
    return conf


def add_peer(iface, name, use_psk=True, overrides=None, backup=True):
    if not _valid_iface(iface):
        return None, "api.err.iface"
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,32}", name):
        return None, "api.err.name"
    with _conf_lock:
        path = conf_path(iface)
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        blocks = parse_user_blocks(iface, lines)
        if any(b["name"] == name for b in blocks):
            return None, aerr("api.err.peer.exists", v=name)
        ip = next_free_ip(iface, blocks)
        if not ip:
            return None, "api.err.nofreeip"

        rc, priv, err = run(["wg", "genkey"])
        if rc != 0:
            return None, aerr("api.err.keygen", v=err)
        priv = priv.strip()
        ok, pub = wg_pubkey(priv)
        if not ok:
            return None, "api.err.pubkey"
        psk = gen_psk() if use_psk else ""

        if backup:       # bulk_add_peers یک بکاپ برای کلِ دسته می‌گیرد
            backup_conf(path)
        # keepalive سمتِ سرور هم نوشته می‌شود، نه فقط در کانفیگِ کلاینت: اگر
        # کلاینت (اپِ خوابیده، بهینه‌سازیِ باتری، کانفیگِ قدیمی) keepalive
        # نفرستد، نگاشتِ NATِ اپراتور منقضی می‌شود و تونل یک‌طرفه می‌میرد —
        # سرور به endpointِ کهنه هندشیک می‌فرستد و جوابی نمی‌گیرد. با این
        # خط، سرور هم نگاشت را گرم نگه می‌دارد. همان مقدارِ کانفیگِ کلاینت.
        keep = (overrides or {}).get("c_keepalive") or 25
        block = ["", "#!!!%s" % name,
                 "[Peer]",
                 "PublicKey = %s" % pub]
        if psk:
            block.append("PresharedKey = %s" % psk)
        block.append("AllowedIPs = %s/32" % ip)
        block.append("PersistentKeepalive = %s" % keep)
        lines += block
        write_conf_atomic(path, lines)

    if iface in live_interfaces():
        ok, err = _wg_set_peer(iface, pub, "%s/32" % ip, psk=psk or None,
                               keepalive=keep)
        if not ok:
            # بدونِ resync: ناظر پیرِ تازه‌ی فایل را در تیکِ بعدی اعمال می‌کند
            return None, aerr("api.err.apply.written", v=err)
    WATCHER.resync()

    client_conf = make_client_conf(priv, ip, iface, psk=psk,
                                   overrides=overrides, name=name)
    save_client_conf(iface, name, client_conf)
    log_action("peer %s@%s added (ip %s, psk=%s)"
               % (name, iface, ip, "yes" if psk else "no"))
    return {"name": name, "iface": iface, "ip": ip,
            "client_conf": client_conf}, None


def _client_conf_path(iface, name):
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,32}", name):
        return None
    if not re.fullmatch(r"wg[0-9a-zA-Z]+", iface):
        return None
    return os.path.join(CLIENTS_DIR, iface, name + ".conf")


def save_client_conf(iface, name, conf_text):
    """کانفیگ کلاینت را برای کپی/QR بعدی نگه می‌دارد (فقط خواندنی برای root)."""
    path = _client_conf_path(iface, name)
    if path is None:
        return
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        os.chmod(CLIENTS_DIR, 0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(conf_text + "\n")
    except OSError as e:
        log_action("client conf save error for %s@%s: %r" % (name, iface, e))


def load_client_conf(iface, name):
    path = _client_conf_path(iface, name)
    if path is None or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def has_client_conf(iface, name):
    path = _client_conf_path(iface, name)
    return bool(path) and os.path.exists(path)


def delete_peer(iface, name):
    if not _valid_iface(iface):
        return False, "api.err.iface"
    with _conf_lock:
        path = conf_path(iface)
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        blocks = parse_user_blocks(iface, lines)
        blk = next((b for b in blocks if b["name"] == name), None)
        if blk is None:
            return False, aerr("api.err.peer.notfound", v=name)
        backup_conf(path)
        del lines[blk["start"]:blk["end"] + 1]
        # خط خالی اضافه‌ی جامانده را پاک کن
        if blk["start"] < len(lines) and lines[blk["start"]].strip() == "" \
                and blk["start"] > 0 and lines[blk["start"] - 1].strip() == "":
            del lines[blk["start"]]
        write_conf_atomic(path, lines)
    if blk["enabled"] and blk["public_key"] and iface in live_interfaces():
        # کدِ خروج بررسی می‌شود: اگر حذف از اینترفیسِ زنده شکست بخورد،
        # پیر از کانفیگ رفته ولی هنوز وصل است — یعنی کاربرِ «حذف‌شده» تا
        # ری‌استارتِ بعدی ترافیک می‌فرستد. الگوی درست در autosync
        # (~۱۱۰۲۳) از قبل همین است.
        rc, _, err = run(["wg", "set", iface, "peer",
                          blk["public_key"], "remove"])
        if rc != 0:
            log_action("delete_peer %s@%s: حذف از اینترفیسِ زنده شکست خورد: %s"
                       % (name, iface, (err or "").strip()))
        else:
            WATCHER.resync()
    else:
        WATCHER.resync()
    # شکستِ حذفِ زنده ⇒ بدونِ resync، تا ناظر همان حذف را دوباره بزند.
    cpath = _client_conf_path(iface, name)
    if cpath and os.path.exists(cpath):
        try:
            os.remove(cpath)
        except OSError:
            pass
    META.delete(iface, name)
    log_action("peer %s@%s deleted" % (name, iface))
    return True, "api.ok.deleted"


def rotate_peer_key(iface, name):
    """چرخش کلید: کلید جدید می‌سازد، PublicKey بلوک را عوض می‌کند و
    کانفیگ کامل کلاینت را برمی‌گرداند (برای کاربرهای قدیمی که QR ندارند)."""
    if not _valid_iface(iface):
        return None, "api.err.iface"
    rc, priv, err = run(["wg", "genkey"])
    if rc != 0:
        return None, aerr("api.err.keygen", v=err)
    priv = priv.strip()
    ok, new_pub = wg_pubkey(priv)
    if not ok:
        return None, "api.err.pubkey"

    with _conf_lock:
        path = conf_path(iface)
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        blocks = parse_user_blocks(iface, lines)
        blk = next((b for b in blocks if b["name"] == name), None)
        if blk is None:
            return None, aerr("api.err.peer.notfound", v=name)
        if not blk["public_key"]:
            return None, "api.err.nopub"
        backup_conf(path)
        changed = False
        for idx in range(blk["start"] + 1, blk["end"] + 1):
            line = lines[idx]
            s = line.strip()
            commented = s.startswith("#")
            core = s.lstrip("#").strip()
            if core.startswith("PublicKey"):
                indent = line[:len(line) - len(line.lstrip())]
                prefix = "#" if commented else ""
                lines[idx] = "%s%sPublicKey = %s" % (indent, prefix, new_pub)
                changed = True
        if not changed:
            return None, "api.err.nopubline"
        write_conf_atomic(path, lines)

    old_pub = blk["public_key"]
    psk = block_psk(iface, name)
    if iface in live_interfaces():
        if blk["enabled"]:
            # 🪤 اینجا تیزترین موردِ این خانواده است: اگر حذفِ کلیدِ قدیم
            # بی‌صدا شکست بخورد، کلیدِ تازه اضافه می‌شود و **هر دو** زنده
            # می‌مانند — یعنی کلیدی که قرار بود باطل شود هنوز کار می‌کند.
            # چرخشِ کلید بی‌اثر شده و پنل «موفق» گزارش می‌دهد.
            rc, out, err = run(["wg", "set", iface, "peer", old_pub, "remove"])
            if rc != 0:
                return None, aerr("api.err.apply.changed", v=(err or out))
            # allowed-ips + PSK + keepalive در یک فراخوانی؛ پیش از این PSK
            # جدا و بی‌بررسیِ rc اعمال می‌شد و keepalive اصلاً نه.
            ok, err = _wg_set_peer(iface, new_pub, blk["allowed_ips"],
                                   psk=(psk or None),
                                   keepalive=blk["keepalive"])
            if not ok:
                return None, aerr("api.err.apply.changed", v=err)
    WATCHER.resync()

    ip = blk["allowed_ips"].split(",")[0].strip().split("/")[0]
    client_conf = make_client_conf(priv, ip, iface, psk=psk,
                                   overrides=peer_overrides(iface, name),
                                   name=name)
    save_client_conf(iface, name, client_conf)
    log_action("peer %s@%s key rotated" % (name, iface))
    return {"name": name, "iface": iface, "ip": ip,
            "client_conf": client_conf}, None


def set_peer_psk(iface, name, enable):
    """افزودن یا حذف Preshared Key برای کاربر موجود (فایل + اعمال زنده + بازتولید کانفیگ)."""
    if not _valid_iface(iface):
        return False, "api.err.iface"
    with _conf_lock:
        path = conf_path(iface)
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        blocks = parse_user_blocks(iface, lines)
        blk = next((b for b in blocks if b["name"] == name), None)
        if blk is None:
            return False, aerr("api.err.peer.notfound", v=name)
        if not blk["public_key"]:
            return False, "api.err.nopub"
        has = any(PSK_RE.match(lines[i].strip())
                  for i in range(blk["start"], blk["end"] + 1))
        if enable and has:
            regen_client_conf(iface, name)
            return True, "api.ok.psk.had"
        if not enable and not has:
            return True, "api.ok.psk.none"
        # پیشوند کامنت را از خط PublicKey تشخیص بده
        pub_idx = next((i for i in range(blk["start"], blk["end"] + 1)
                        if lines[i].strip().lstrip("#").strip()
                        .startswith("PublicKey")), None)
        prefix = "#" if (pub_idx is not None and
                         lines[pub_idx].lstrip().startswith("#")) else ""
        backup_conf(path)
        psk = ""
        if enable:
            psk = gen_psk()
            if not psk:
                return False, "api.err.psk"
            lines.insert(pub_idx + 1, "%sPresharedKey = %s" % (prefix, psk))
        else:
            lines = [ln for i, ln in enumerate(lines)
                     if not (blk["start"] <= i <= blk["end"]
                             and PSK_RE.match(ln.strip()))]
        write_conf_atomic(path, lines)

    aok, aerr_msg = True, ""
    if iface in live_interfaces() and blk["enabled"]:
        aok, aerr_msg = apply_preshared_key(iface, blk["public_key"], psk)  # psk="" ⇒ حذف
    if aok:
        # شکست → بدونِ resync تا ناظر دوباره اعمالش کند (مثلِ set_peer_enabled)
        WATCHER.resync()
    regen_client_conf(iface, name)
    log_action("peer %s@%s psk %s (%s)"
               % (name, iface, "on" if enable else "off",
                  "ok" if aok else aerr_msg.strip()))
    if not aok:
        # فایل و کانفیگِ کلاینت عوض شده‌اند ولی کرنل نه؛ اپراتور باید بداند،
        # وگرنه «انجام شد» می‌بیند و کلاینت تا ری‌استارت وصل نمی‌شود.
        return False, aerr("api.err.apply.changed", v=aerr_msg)
    return True, "api.ok.done"


def allowed_ips_conflict(parts, blocks, exclude=None):
    """اولین (شبکه، نامِ peer) که با یکی از parts هم‌پوشانی دارد، یا None.
    فقط بینِ peerهای همین فایل؛ رنج‌های خارج از تونل (0.0.0.0/0 و…) در
    AllowedIPs ِ سرور معمولاً نیستند، ولی اگر باشند همان قاعده صادق است."""
    nets = []
    for pt in parts:
        try:
            nets.append(ipaddress.ip_network(pt, strict=False))
        except ValueError:
            continue
    for b in blocks:
        if b["name"] == exclude:
            continue
        for other in b["allowed_ips"].split(","):
            other = other.strip()
            if not other:
                continue
            try:
                on = ipaddress.ip_network(other, strict=False)
            except ValueError:
                continue
            for n in nets:
                if n.version == on.version and n.overlaps(on):
                    return str(on), b["name"]
    return None


def update_peer_ips(iface, name, allowed_ips):
    """ویرایش AllowedIPs بلوک (فایل + اعمال زنده)."""
    if not _valid_iface(iface):
        return False, "api.err.iface"
    parts = [p.strip() for p in allowed_ips.split(",") if p.strip()]
    if not parts:
        return False, "api.err.needip"
    for pt in parts:
        try:
            ipaddress.ip_network(pt, strict=False)
        except ValueError:
            return False, aerr("api.err.value", v=pt)
    new_val = ",".join(parts)

    with _conf_lock:
        path = conf_path(iface)
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        blocks = parse_user_blocks(iface, lines)
        blk = next((b for b in blocks if b["name"] == name), None)
        if blk is None:
            return False, aerr("api.err.peer.notfound", v=name)
        # هم‌پوشانی با peerهای دیگر: WireGuard (cryptokey routing) یک /32 را
        # بی‌صدا از peer ِ A به B منتقل می‌کند و در بوتِ بعدی «آخرین بلوک
        # برنده است» — ادمین ناخواسته IP ِ یک کاربر را می‌دزدد.
        clash = allowed_ips_conflict(parts, blocks, exclude=name)
        if clash:
            return False, aerr("api.err.ipinuse", v=clash[0], name=clash[1])
        backup_conf(path)
        changed = False
        for idx in range(blk["start"] + 1, blk["end"] + 1):
            line = lines[idx]
            s = line.strip()
            commented = s.startswith("#")
            core = s.lstrip("#").strip()
            if core.startswith("AllowedIPs"):
                indent = line[:len(line) - len(line.lstrip())]
                prefix = "#" if commented else ""
                lines[idx] = "%s%sAllowedIPs = %s" % (indent, prefix, new_val)
                changed = True
        if not changed:
            return False, "api.err.noallowedips"
        write_conf_atomic(path, lines)

    if blk["enabled"] and iface in live_interfaces():
        ok, err = _wg_set_peer(iface, blk["public_key"], new_val)
        if not ok:
            return False, aerr("api.err.apply.changed", v=err)
    WATCHER.resync()
    log_action("peer %s@%s allowed-ips -> %s" % (name, iface, new_val))
    return True, "api.ok.done"


# ---------------------------------------------------- ساخت دسته‌ای کاربر

def bulk_add_peers(iface, prefix, start, count, use_psk=True, overrides=None,
                   meta_fields=None):
    """ساخت count کاربر با نام prefix + شماره. خروجی: (created_list, error)."""
    if not _valid_iface(iface):
        return None, "api.err.iface"
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,24}", prefix):
        return None, "api.err.prefix"
    try:
        start = int(start)
        count = int(count)
    except (TypeError, ValueError):
        return None, "api.err.startcount.num"
    if not (1 <= count <= 50):
        return None, "api.err.count"
    if start < 0 or start > 100000:
        return None, "api.err.start.bad"
    created, errors = [], []
    # یک بکاپ برای کلِ دسته: پیش از این ۵۰ افزودن ۵۰ بکاپ می‌گرفت و کلِ
    # چرخه‌ی ۵۰تاییِ backups/ ِ آن اینترفیس را می‌شست.
    try:
        backup_conf(conf_path(iface))
    except OSError:
        pass
    for i in range(start, start + count):
        nm = "%s%d" % (prefix, i)
        res, err = add_peer(iface, nm, use_psk=use_psk, overrides=overrides,
                            backup=False)
        if err:
            errors.append(aerr("api.err.bulk.item", name=nm, why=err))
            continue
        if meta_fields:
            META.meta_update(iface, nm, meta_fields)
        created.append(nm)
    if SAMPLER:
        SAMPLER.refresh_meta()
    log_action("bulk add %s x%d on %s -> %d ساخته, %d خطا"
               % (prefix, count, iface, len(created), len(errors)))
    return {"created": created, "errors": errors}, None


# ------------------------------------------------- ابزار ping/traceroute

def _peer_target_ip(iface, name):
    """IP قابل‌پینگِ کاربر: اولین AllowedIP که داخل رنج اینترفیس است.
    جلوگیری از SSRF — فقط IP متعلق به همین peer در subnet سرور مجاز است."""
    subnet = iface_subnet(iface)
    if not subnet:
        return None
    net = ipaddress.ip_network(subnet, strict=False)
    try:
        with open(conf_path(iface), "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    blocks = parse_user_blocks(iface, lines)
    blk = next((b for b in blocks if b["name"] == name), None)
    if not blk:
        return None
    for part in blk["allowed_ips"].split(","):
        ips = part.strip().split("/")[0]
        try:
            addr = ipaddress.ip_address(ips)
            if addr in net:
                return str(addr)
        except ValueError:
            continue
    return None


def peer_ping(iface, name):
    ip = _peer_target_ip(iface, name)
    if not ip:
        return False, "api.err.noip"
    rc, out, err = run(["ping", "-c", "4", "-W", "1", "-n", ip], timeout=12)
    return True, (out or err)[:4000]


def peer_trace(iface, name):
    ip = _peer_target_ip(iface, name)
    if not ip:
        return False, "api.err.noip"
    if shutil.which("traceroute"):
        cmd = ["traceroute", "-n", "-w", "1", "-q", "1", "-m", "15", ip]
    else:
        cmd = ["tracepath", "-n", ip]
    rc, out, err = run(cmd, timeout=30)
    return True, (out or err)[:6000]


# ------------------------------------------------------ بکاپ / بازیابی

# نکته امنیتی: config.json (هش رمزها، secret سشن، توکن metrics) عمداً در
# بکاپ نیست تا رازهای پنل در فایل دانلودی نشت نکند. بکاپ فقط شامل کانفیگ‌های
# WireGuard + کانفیگ کلاینت‌ها + دیتابیس حسابداری/تاریخچه است.
_BACKUP_WG_RE = re.compile(r"^wg[0-9a-zA-Z]+\.conf$")
_BACKUP_CLIENT_RE = re.compile(r"^clients/wg[0-9a-zA-Z]+/[A-Za-z0-9_.\-]{1,32}\.conf$")


def backup_archive_bytes():
    """tar.gz از کانفیگ‌های WireGuard + clients + traffic.db در حافظه."""
    import io
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for iface in list_all_wg_confs():
            p = conf_path(iface)
            if os.path.exists(p):
                tar.add(p, arcname=iface + ".conf")
        if os.path.isdir(CLIENTS_DIR):
            for root, _dirs, files in os.walk(CLIENTS_DIR):
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = "clients/" + os.path.relpath(full, CLIENTS_DIR)
                    tar.add(full, arcname=rel)
        if os.path.exists(DB_PATH):
            _tar_add_db_snapshot(tar, "traffic.db")
        readme = ("wg-panel backup\nشامل: کانفیگ‌های WireGuard، کانفیگ "
                  "کلاینت‌ها، و دیتابیس حسابداری/تاریخچه.\nشامل نیست: "
                  "config.json (حساب‌های پنل و رازها).\n").encode()
        info = tarfile.TarInfo("README.txt")
        info.size = len(readme)
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(readme))
    return buf.getvalue()


def _write_pre_restore_snapshot():
    """اسنپ‌شاتِ وضعیتِ فعلی پیش از هر بازیابی → (ok، خطا)."""
    try:
        os.makedirs(os.path.join(BASE_DIR, "restore-backups"), exist_ok=True)
        snap = os.path.join(BASE_DIR, "restore-backups",
                            "pre-restore-%s.tar.gz"
                            % datetime.now().strftime("%Y%m%d-%H%M%S"))
        with open(snap, "wb") as f:
            f.write(backup_archive_bytes())
        return True, ""
    except OSError as e:
        return False, aerr("api.err.bkstate", v=e)


def _db_sidecars_clear():
    """سایدکارهای WAL را بردار — فقط پیش از جایگزینیِ فایلِ اصلی.

    🪤 اگر traffic.db ِ تازه کنارِ traffic.db-wal ِ **کهنه**ی سیستمِ در
    حالِ اجرا بنشیند، SQLite می‌تواند WAL ِ قدیمی را روی فایلِ تازه
    اعمال کند — یعنی خرابی، نه فقط از دست رفتنِ داده. تا ۱۳ اوت ۲۰۲۶
    هیچ‌جای این فایل سایدکارها را لمس نمی‌کرد (هارنسِ تست می‌کرد، مسیرِ
    بازیابی نه).

    MetaDB._connect برای هر متد اتصالِ کوتاه‌عمر می‌سازد، پس هیچ اتصالِ
    دیرپایی روی این فایل‌ها باز نیست.
    """
    for suffix in ("-wal", "-shm"):
        try:
            os.unlink(DB_PATH + suffix)
        except OSError:
            pass


def _tar_add_db_snapshot(tar, arcname):
    """اسنپ‌شاتِ سازگارِ دیتابیس را به آرشیو اضافه می‌کند.

    🪤 traffic.db در حالتِ WAL است: تراکنش‌های اخیر در traffic.db-wal
    می‌مانند نه در فایلِ اصلی. ‏tar.add(DB_PATH) بی‌صدا همان‌ها را جا
    می‌گذاشت — آرشیو سالم باز می‌شد و فقط داده کمتر داشت، که یعنی هیچ
    نشانه‌ای از خرابی نبود.

    اندازه‌گیریِ ۱۳ اوت ۲۰۲۶ روی فیکسچر: بعد از ۱۰۰۰ درج و commit،
    فایلِ اصلی ۴۰۹۶ بایت بود و WAL ‏۲۸٬۸۷۲ — کپیِ فایل‌سیستمی حتی
    **جدول را هم نداشت** («no such table»)، نه اینکه ردیف کم داشته باشد.

    Connection.backup اسنپ‌شاتِ سازگار می‌گیرد و WAL را هم شامل می‌شود.
    جایگزینِ ساده‌ترش — wal_checkpoint(TRUNCATE) و بعد tar.add — دیتابیسِ
    **زنده** را به‌عنوانِ عارضه‌ی گرفتنِ بکاپ تغییر می‌دهد؛ بکاپ نباید
    موضوعش را دست بزند.
    """
    tmpd = tempfile.mkdtemp(prefix="wgdbsnap-")
    try:
        snap = os.path.join(tmpd, "traffic.db")
        src = sqlite3.connect(DB_PATH, timeout=10)
        try:
            dst = sqlite3.connect(snap)
            try:
                with dst:
                    src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
        tar.add(snap, arcname=arcname)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def _validate_restore_content(dest, data):
    """اعتبارِ محتوای یک فایلِ بازیابی → پیامِ خطا یا ''.

    کانفیگِ WireGuard باید [Interface] و PrivateKey داشته باشد و بلوک‌هایش
    پارس شود؛ traffic.db باید از PRAGMA integrity_check سربلند بیرون بیاید.
    بدونِ این، یک آرشیوِ خراب فایلِ سالمِ فعلی را جایگزین می‌کرد.
    """
    if dest == DB_PATH:
        if not data.startswith(b"SQLite format 3\x00"):
            return "not an SQLite database"
        fd, tmp = tempfile.mkstemp(prefix="restore-check-", suffix=".db")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            con = sqlite3.connect(tmp)
            try:
                res = con.execute("PRAGMA integrity_check").fetchone()
                names = {r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                con.close()
            if not res or res[0] != "ok":
                return "integrity_check failed: %s" % (res[0] if res else "?")
            if "peer_meta" not in names or "usage_day" not in names:
                return "not a wg-panel traffic.db (tables missing)"
        except sqlite3.Error as e:
            return "sqlite: %s" % e
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return ""
    if os.path.dirname(dest) == WG_DIR and dest.endswith(".conf"):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return "not UTF-8 text"
        lines = text.splitlines()
        if not any(l.strip() == "[Interface]" for l in lines):
            return "no [Interface] section"
        if not any(l.strip().startswith("PrivateKey") for l in lines):
            return "no PrivateKey"
        try:
            parse_user_blocks("", lines)
        except Exception as e:
            return "unparseable peers: %r" % e
    return ""


def _unlabeled_active_peers(lines):
    """تعدادِ [Peer] ِ فعالی که داخلِ هیچ بلوکِ #!!!name نیست."""
    blocks = _parse_user_blocks(lines)
    return sum(1 for i, l in enumerate(lines)
               if l.strip() == "[Peer]"
               and not any(b["start"] <= i <= b["end"] for b in blocks))


def _restore_live_problem(planned_data):
    """خطای aerr اگر بازیابی نتواند روی اینترفیسِ زنده درست اعمال شود، وگرنه ''.

    اعمالِ زنده (apply_conf_delta) فقط بلوک‌های برچسب‌دار را می‌شناسد. کانفیگی
    با [Peer] ِ بی‌برچسب روی اینترفیسِ بالا یعنی: همه‌ی کاربرانِ برچسب‌دارِ
    فعلی از کرنل برداشته می‌شوند و peerهای بی‌برچسبِ فایل اضافه نمی‌شوند —
    تا ری‌استارتِ wg-quick، فایل و کرنل دو چیزِ کاملاً متفاوت‌اند. روی
    اینترفیسِ پایین مشکلی نیست: wg-quick up کلِ فایل را می‌خواند.
    هم dry-run و هم مسیرِ واقعی همین را صدا می‌زنند تا پیش‌نمایش چیزی را
    تأیید نکند که بازیابی بعد رد می‌کند.
    """
    live = set(live_interfaces())
    for dest, data in planned_data:
        if not (os.path.dirname(dest) == WG_DIR and dest.endswith(".conf")):
            continue
        iface = os.path.basename(dest)[:-5]
        if iface not in live:
            continue
        n = _unlabeled_active_peers(
            data.decode("utf-8", "replace").splitlines())
        if n:
            return aerr("api.err.bk.unlabeled", v=iface, n=n)
    return ""


def _restore_plan(planned_data):
    """پیش‌نمایشِ بازیابی: به ازای هر اینترفیس، peerهایی که اضافه/حذف/تغییر
    می‌شوند (نام‌ها؛ کلید = PublicKey) + فهرستِ فایل‌ها."""
    plan = {"files": [], "ifaces": {}}
    for dest, data in planned_data:
        plan["files"].append(os.path.relpath(dest, BASE_DIR)
                             if dest.startswith(BASE_DIR) else dest)
        if not (os.path.dirname(dest) == WG_DIR and dest.endswith(".conf")):
            continue
        iface = os.path.basename(dest)[:-5]
        try:
            cur = {b["public_key"]: b for b in parse_user_blocks(iface)
                   if b["public_key"]}
        except OSError:
            cur = {}
        try:
            new = {b["public_key"]: b for b in
                   parse_user_blocks("", data.decode("utf-8", "replace").splitlines())
                   if b["public_key"]}
        except Exception:
            new = {}
        added = sorted(new[k]["name"] for k in new if k not in cur)
        removed = sorted(cur[k]["name"] for k in cur if k not in new)
        # همان چهار چیزی که مسیرِ واقعی (_peer_live_state → apply_conf_delta)
        # مقایسه و اعمال می‌کند؛ keepalive پیش از این جا افتاده بود و
        # پیش‌نمایش «بدونِ تغییر» می‌گفت در حالی که بازیابی wg set می‌زد.
        def sig(b):
            return (b["enabled"], b["allowed_ips"].replace(" ", ""),
                    b["psk"], b["keepalive"])
        changed = sorted(new[k]["name"] for k in new
                         if k in cur and sig(new[k]) != sig(cur[k]))
        plan["ifaces"][iface] = {"add": added, "remove": removed,
                                 "change": changed,
                                 "peers_now": len(cur), "peers_after": len(new),
                                 "live": iface in live_interfaces()}
    return plan


def restore_from_tar(raw, dry_run=False):
    """بازیابی از بایت‌های tar.gz با اعتبارسنجی سخت‌گیرانه‌ی هر عضو.
    قبل از بازیابی، بکاپ وضعیت فعلی گرفته می‌شود. خروجی: (ok, پیام).
    dry_run=True: هیچ چیزی نوشته نمی‌شود؛ خروجی (True, plan) — رجوع به
    _restore_plan."""
    import io
    if len(raw) > 50 * 1024 * 1024:
        return False, "api.err.bk.big"
    try:
        tar = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    except (tarfile.TarError, OSError):
        return False, "api.err.bk.bad"

    planned = []  # (member, dest_path)
    with tar:
        members = tar.getmembers()
        for mem in members:
            nm = mem.name
            # فقط فایل عادی؛ بدون symlink/دایرکتوری/دستگاه
            if not mem.isfile():
                if mem.isdir():
                    continue
                return False, aerr("api.err.bk.member", v=nm)
            if nm.startswith("/") or ".." in nm.split("/") or "\\" in nm:
                return False, aerr("api.err.bk.path", v=nm)
            if mem.size > 20 * 1024 * 1024:
                return False, aerr("api.err.bk.bigfile", v=nm)
            if nm == "README.txt":
                continue
            if _BACKUP_WG_RE.match(nm):
                dest = os.path.join(WG_DIR, nm)
            elif _BACKUP_CLIENT_RE.match(nm):
                dest = os.path.join(BASE_DIR, nm)
            elif nm == "traffic.db":
                dest = DB_PATH
            else:
                return False, aerr("api.err.bk.skipped", v=nm)
            planned.append((mem, dest))
        if not planned:
            return False, "api.err.bk.empty"

        # محتوا پیش از هر نوشتنی خوانده و اعتبارسنجی می‌شود
        planned_data = []
        for mem, dest in planned:
            src = tar.extractfile(mem)
            if src is None:
                continue
            data = src.read()
            why = _validate_restore_content(dest, data)
            if why:
                return False, aerr("api.err.bk.invalid", v=mem.name, why=why)
            planned_data.append((dest, data))
        why = _restore_live_problem(planned_data)
        if why:
            return False, why
        if dry_run:
            return True, _restore_plan(planned_data)

        # بکاپ وضعیت فعلی (قابل بازگشت)
        ok, snap_err = _write_pre_restore_snapshot()
        if not ok:
            return False, snap_err

        restored, synced = _restore_write_planned(planned_data)

    if SAMPLER:
        SAMPLER.refresh_meta()
    log_action("restore: %d file(s) restored, %d live peer change(s)"
               % (restored, synced))
    return True, aerr("api.ok.restore", n=restored)


def _restore_write_planned(planned_data):
    """فایل‌های برنامه‌ریزی‌شده‌ی بازیابی [(dest, bytes)] را می‌نویسد و
    کانفیگ‌های WireGuard را روی اینترفیس‌های زنده اعمال می‌کند.
    خروجی: (restored, synced).

    🪤 پیش از این فقط WATCHER.resync() صدا می‌شد، که فایلِ تازه را «قبلاً
    اعمال‌شده» ثبت می‌کند و هیچ wg set نمی‌زند: peerهای حذف‌شده در بکاپ وصل
    می‌ماندند، peerهای برگشته کار نمی‌کردند و ناظر هم دیگر هرگز آن‌ها را
    همگام نمی‌کرد. حالا وضعیتِ قبل/بعدِ هر کانفیگ مقایسه و تفاوت اعمال
    می‌شود — همان مسیرِ ویرایشِ دستی. کلِ نوشتن زیرِ _conf_lock است تا یک
    add_peer هم‌زمان نسخه‌ی کهنه‌اش را روی فایلِ بازیابی‌شده ننویسد.
    """
    wg_ifaces = {}
    for dest, _data in planned_data:
        if os.path.dirname(dest) == WG_DIR and dest.endswith(".conf"):
            wg_ifaces[dest] = os.path.basename(dest)[:-5]
    restored = 0
    with _conf_lock:
        before = {ifc: _peer_live_state(ifc) for ifc in wg_ifaces.values()}
        for dest, data in planned_data:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            tmp = dest + ".restore-tmp"
            # مود در خودِ os.open — محتوا کانفیگِ WireGuard و traffic.db
            # است و پیش از این بینِ ساخت و chmod با umask نوشته می‌شد.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.chmod(tmp, 0o600)
            if dest == DB_PATH:
                _db_sidecars_clear()      # پیش از جایگزینی، نه بعدش
            os.replace(tmp, dest)
            restored += 1
        after = {ifc: _peer_live_state(ifc) for ifc in wg_ifaces.values()}
    synced = 0
    for ifc in wg_ifaces.values():
        try:
            synced += apply_conf_delta(ifc, before.get(ifc, {}),
                                       after.get(ifc, {}),
                                       actor=ACTOR_RESTORE)
        except Exception as e:      # اعمالِ زنده نباید خودِ بازیابی را بشکند
            log_action("restore: live apply failed on %s: %r" % (ifc, e))
    WATCHER.resync()
    return restored, synced


# ---- بازیابیِ انتخابی از آرشیوِ شبانه (فرمتِ wg-panel-backup.sh روی MEGA)
CLOUD_RESTORE_COMPONENTS = (
    ("wireguard", "کانفیگ‌های WireGuard"),
    ("clients", "کانفیگ کلاینت‌ها"),
    ("db", "دیتابیس حسابداری/تاریخچه"),
)
CLOUD_COMPONENT_KEYS = frozenset(k for k, _ in CLOUD_RESTORE_COMPONENTS)


def restore_from_nightly_tar(raw, components, ok_key="api.ok.restore.parts"):
    """بازیابیِ اجزای انتخابی از آرشیوِ شبانه (ساختارِ wireguard/ و wg-panel/).

    تفاوتِ عمدی با restore_from_tar: آرشیوِ شبانه فایل‌هایی دارد که **هرگز**
    از این مسیر بازیابی نمی‌شوند — config.json (رمزها/رازها؛ بازیابی‌اش یعنی
    برگشتِ رمزهای چرخانده‌شده یا قفل‌شدن) و wg_panel.py (کد؛ بازیابی‌اش یعنی
    downgrade از یک آرشیو راهِ دور). این‌ها skip می‌شوند، نه error — چون
    حضورشان در آرشیو طبیعی است. خروجی: (ok، پیام).

    ok_key کلیدِ پیامِ موفقیت است (جای‌گیرهای {n} و {skipped})؛ فراخوان
    نتیجهٔ sha256 را از همین راه در پیام می‌گذارد، نه با الحاقِ متن."""
    import io
    components = [c for c in components if c in CLOUD_COMPONENT_KEYS]
    if not components:
        return False, "api.err.nocomp"
    if len(raw) > 200 * 1024 * 1024:
        return False, "api.err.arch.big"
    try:
        tar = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    except (tarfile.TarError, OSError):
        return False, "api.err.arch.bad"
    planned, skipped = [], 0
    with tar:
        for mem in tar.getmembers():
            nm = mem.name
            if nm.startswith("./"):          # tar -C … czf … .  ⇒  پیشوندِ ./
                nm = nm[2:]
            if not nm or mem.isdir():
                continue
            if not mem.isfile():             # symlink/device → قاطعانه رد
                return False, aerr("api.err.arch.member", v=mem.name)
            if nm.startswith("/") or ".." in nm.split("/") or "\\" in nm:
                return False, aerr("api.err.arch.path", v=mem.name)
            wg = re.fullmatch(r"wireguard/(wg[0-9a-zA-Z]+\.conf)", nm)
            cl = re.fullmatch(
                r"wg-panel/(clients/wg[0-9a-zA-Z]+/[A-Za-z0-9_.\-]{1,32}"
                r"\.conf)", nm)
            if wg and "wireguard" in components:
                dest, cap = os.path.join(WG_DIR, wg.group(1)), 20
            elif cl and "clients" in components:
                dest, cap = os.path.join(BASE_DIR, cl.group(1)), 20
            elif nm == "wg-panel/traffic.db" and "db" in components:
                dest, cap = DB_PATH, 200
            else:
                skipped += 1                 # config.json، wg_panel.py، squid و…
                continue
            if mem.size > cap * 1024 * 1024:
                return False, aerr("api.err.arch.bigfile", v=nm)
            planned.append((mem, dest))
        if not planned:
            return False, "api.err.nothingsel"
        planned_data = []
        for mem, dest in planned:
            src = tar.extractfile(mem)
            if src is None:
                continue
            data = src.read()
            why = _validate_restore_content(dest, data)
            if why:
                return False, aerr("api.err.bk.invalid", v=mem.name, why=why)
            planned_data.append((dest, data))
        why = _restore_live_problem(planned_data)
        if why:
            return False, why
        ok, snap_err = _write_pre_restore_snapshot()
        if not ok:
            return False, snap_err
        restored, synced = _restore_write_planned(planned_data)
    if SAMPLER:
        SAMPLER.refresh_meta()
    log_action("cloud restore: %d restored, %d skipped, %d live peer "
               "change(s) (%s)"
               % (restored, skipped, synced, ",".join(components)))
    return True, aerr(ok_key, n=restored, skipped=skipped)


# ------------------------------------------------------ لینک اشتراک امن

def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_share(iface, name, minutes, single, creator):
    """لینک اشتراک می‌سازد. خروجی: (token, error). توکن فقط همین یک بار برمی‌گردد."""
    if not _valid_iface(iface):
        return None, "api.err.iface"
    if load_client_conf(iface, name) is None:
        return None, "api.err.peer.no_saved_conf"
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        return None, "api.err.min.num"
    if not (1 <= minutes <= 1440):
        return None, "api.err.min.range"
    token = secrets.token_urlsafe(32)
    META.share_add(_hash_token(token), iface, name,
                   time.time() + minutes * 60, bool(single), creator)
    log_action("share created for %s@%s (%dm, single=%s) by %s"
               % (name, iface, minutes, single, creator))
    return token, None


def resolve_share(token):
    """توکن را به کانفیگ کلاینت تبدیل می‌کند (با مصرف اگر single). خروجی: (dict|None)."""
    if not token or len(token) > 128:
        return None
    th = _hash_token(token)
    # مطالبه‌ی اتمیک: بررسی و افزایش در یک دستور، پس دیتابیس برنده را
    # تعیین می‌کند نه ترتیبِ اتفاقیِ دو نخ.
    rec = META.share_claim(th, time.time())
    if rec is None:
        return None
    # عارضه‌ی عمدی: لینکی که کانفیگش گم شده حالا مصرفش را می‌سوزاند.
    # جهتِ امنش همین است — بدیلش توکنی است که می‌شود دوباره امتحانش کرد،
    # یعنی همان خاصیتی که داریم برمی‌داریم.
    conf = load_client_conf(rec["iface"], rec["name"])
    if conf is None:
        return None
    log_action("share viewed for %s@%s" % (rec["name"], rec["iface"]))
    return {"name": rec["name"], "iface": rec["iface"], "client_conf": conf,
            "ip": peer_ip(rec["iface"], rec["name"]),
            "link_expires": rec.get("expires") or 0}


# ------------------------------------------------------------- تونل‌های خروجی

def list_all_wg_confs():
    """نام همه‌ی اینترفیس‌هایی که فایل wg*.conf دارند."""
    out = []
    try:
        names = os.listdir(WG_DIR)
    except OSError:
        return out
    for fn in sorted(names):
        m = re.fullmatch(r"(wg[0-9a-zA-Z]+)\.conf", fn)
        if not m:
            continue
        out.append(m.group(1))
    return out


def list_awg_confs():
    """کانفیگ‌های AmneziaWG در AWG_DIR — بدون نسخه‌های failed/self/bak."""
    try:
        names = os.listdir(AWG_DIR)
    except OSError:
        return []
    out = []
    for fn in sorted(names):
        m = re.fullmatch(r"(awg[0-9a-zA-Z]+)\.conf", fn)
        if m:
            out.append(m.group(1))
    return out


def list_tunnel_confs():
    """اینترفیس‌های تونل خروجی = WireGuard (به‌جز سمت کاربر) + AmneziaWG."""
    srv = set(server_ifaces())
    wg = [i for i in list_all_wg_confs() if i not in srv]
    return wg + list_awg_confs()


def _tunnel_is_awg(iface):
    return bool(re.fullmatch(r"awg[0-9a-zA-Z]+", iface))


def tunnel_unit(iface):
    """نامِ یونیتِ systemd متناسب با نوعِ تونل (awg-quick برای AmneziaWG)."""
    return ("awg-quick@%s" if _tunnel_is_awg(iface) else "wg-quick@%s") % iface


def _tunnel_conf_path(iface):
    return os.path.join(AWG_DIR if _tunnel_is_awg(iface) else WG_DIR,
                        iface + ".conf")


def read_tunnel_endpoint(iface):
    try:
        with open(_tunnel_conf_path(iface), "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("Endpoint"):
                    return s.split("=", 1)[1].split("#")[0].strip()
    except OSError:
        pass
    return ""


def systemd_state(iface):
    rc, out, _ = run(["systemctl", "is-active", tunnel_unit(iface)], timeout=10)
    return out.strip() or "unknown"


SYSTEMD_WANTS_DIR = "/etc/systemd/system/multi-user.target.wants"


def tunnel_enabled(iface):
    """آیا تونل برای بوت enable است؟ (بررسیِ سریعِ symlink، بدونِ subprocess)."""
    link = os.path.join(SYSTEMD_WANTS_DIR, "%s.service" % tunnel_unit(iface))
    return os.path.islink(link) or os.path.exists(link)


def tunnel_health(t):
    """سلامتِ صادقانهٔ تونل از ترکیبِ سیگنال‌ها (نه فقط systemd).

    خروجی یکی از: loop | off | dead | noreturn | chain | idle | healthy
      loop     = حلقهٔ مسیریابی (بحرانی — endpoint از داخلِ تونل مسیر می‌خورد)
      off      = خاموش (اینترفیس بالا نیست)
      dead     = بالا ولی بدونِ هندشیک (endpointِ مرده)
      noreturn = هندشیکِ تازه ولی ۰ بایت دریافت (ارسال هست، برگشت نیست)
      chain    = زنده و سالم، و endpoint عمداً از تونلِ دیگری می‌رود (WARP)
      idle     = زنده و سالم ولی الان ترافیکی رد نمی‌شود
      healthy  = زنده، هندشیکِ تازه، دریافتِ داده

    chain بعد از خرابی‌ها سنجیده می‌شود تا «عمدی» بودنِ زنجیره، مرده/بی‌بازگشت
    بودنِ واقعیِ همان تونل را پنهان نکند.
    """
    if t.get("loop"):
        return "loop"
    if not t.get("active"):
        return "off"
    hs = t.get("handshake") or 0
    fresh = hs and (time.time() - hs) < 180
    if not fresh:
        return "dead"
    if (t.get("rx") or 0) == 0:
        return "noreturn"
    if t.get("chain"):
        return "chain"
    if (t.get("rx_rate") or 0) + (t.get("tx_rate") or 0) < 1:
        return "idle"
    return "healthy"


_LOOP_RE = re.compile(r"\bdev\s+(\S+)")


def endpoint_route_check(endpoint):
    """تشخیصِ حلقهٔ مسیریابی: آیا مسیرِ رسیدن به endpointِ تونل از داخلِ یک
    تونلِ دیگر می‌رود (به‌جای اینترفیسِ فیزیکی)؟ خروجی: (dev|None, loop?).

    endpoint می‌تواند 'IP:port' یا فقط IP باشد. اگر IP نداشته باشد → (None, False).
    """
    if not endpoint:
        return None, False
    host = endpoint.rsplit(":", 1)[0].strip("[]")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None, False   # هاست‌نیم؛ بدونِ resolve قضاوت نمی‌کنیم
    rc, out, _ = run(["ip", "route", "get", host], timeout=5)
    if rc != 0:
        return None, False
    m = _LOOP_RE.search(out)
    dev = m.group(1) if m else None
    loop = bool(dev and re.fullmatch(r"(wg|awg)[0-9a-zA-Z]+", dev))
    return dev, loop


def intentional_chain(iface, dev):
    """آیا مسیرخوردنِ endpointِ این تونل از تونلِ «dev» عمدی است؟

    فقط زنجیرهٔ WARP: endpointِ wgwarp عمداً از تونلِ egressِ WarpGuard پین
    شده، چون eth0 اصلاً به WARP نمی‌رسد و awg1 دیتای بزرگِ TLS را بلک‌هول
    می‌کند. این حلقه نیست؛ همان چیزی است که کارتِ «مسیریابیِ WARP» با نامِ
    «زنجیره‌ی خروج» سالم نشان می‌دهد — بی این استثنا دو بخشِ پنل دربارهٔ یک
    واقعیت حرفِ متضاد می‌زدند.

    مرجعِ عمدی‌بودن، خطِ egress= در warp-guard.state است نه یک نامِ ثابت:
    اگر گارد به تونلِ دیگری سوییچ کند همان تونل عمدی می‌شود، و هر devِ
    دیگری (یا هر تونلِ دیگری جز wgwarp) همچنان حلقهٔ واقعیِ بحرانی است.
    """
    if not dev:
        return False
    if iface == WARP_IFACE:
        return dev == (warp_guard_state().get("egress") or "")
    # §29.157 — تونلِ فرعی روی تونلِ مادر. قاعده‌ی معماری (CLAUDE.md، «دام‌های
    # شبکه»): «تونلِ مادر از eth0، تونلِ فرعی از awg». یعنی endpointِ wg21/wg22 و
    # استخرِ wgpl* عمداً از awg1/awg3 می‌رود؛ از ۲۸ اکتبر تا ۴ نوامبر این دوازده
    # تونل در کارتِ تونل‌ها، رباتِ تلگرام و متای WG-NQMO «loop» (بحرانی) خورده
    # بودند و موتور ۱۲ تشخیصِ کاذبِ افتِ خروجی باز کرده بود.
    # شرطِ عمدی‌بودن سه تایی و تنگ است تا حلقه‌ی واقعی پنهان نشود:
    #   ۱) خودِ iface تونلِ WireGuard ِ ساده باشد (مادر هرگز استثنا نمی‌گیرد:
    #      awg3 از داخلِ awg1 همان تونل‌درتونلِ §۲۹٫۱۳۰ است و باید loop بماند)؛
    #   ۲) dev تونلِ AmneziaWG (مادر) باشد؛
    #   ۳) endpointِ خودِ dev از اینترفیسِ فیزیکی برود (loop=False)، وگرنه
    #      زنجیره روی زنجیره است و باز حلقه‌ی واقعی.
    if _tunnel_is_awg(iface) or not _tunnel_is_awg(dev):
        return False
    mother_ep = read_tunnel_endpoint(dev)
    if not mother_ep:
        return False
    _mdev, mother_loop = endpoint_route_check(mother_ep)
    return not mother_loop


def endpoint_route_state(iface, ep):
    """(dev, loop, chain) — حلقهٔ واقعی از زنجیرهٔ عمدی جدا می‌شود."""
    dev, loop = endpoint_route_check(ep)
    chain = bool(loop and intentional_chain(iface, dev))
    return dev, (loop and not chain), chain


def toggle_tunnel(iface, up):
    if not re.fullmatch(r"(wg|awg)[0-9a-zA-Z]+", iface):
        return False, "api.err.ifacename"
    unit = tunnel_unit(iface)
    action = "start" if up else "stop"
    rc, out, err = run(["systemctl", action, unit], timeout=60)
    if rc != 0:
        # جزئیات خطا از ژورنال
        _, jout, _ = run(["journalctl", "-u", unit,
                          "-n", "8", "--no-pager", "-o", "cat"], timeout=10)
        # متنِ خامِ systemd/ژورنال — پیامِ سیستم است و ترجمه نمی‌شود
        return False, ((err or out or "systemctl %s: rc=%d" % (action, rc))
                       + "\n" + jout)
    log_action("tunnel %s -> %s" % (iface, action))
    TUNNELS.update_one(iface)
    return True, "api.ok.done"


def ensure_user_routes():
    """نگهبان مسیر: peer هایی که بعد از بالاآمدن اینترفیس با wg set اضافه
    می‌شوند (برخلاف wg-quick) مسیر kernel نمی‌گیرند؛ در نتیجه ترافیک
    برگشتی به کلاینت از مسیر پیش‌فرض بیرون می‌رود و tx صفر می‌ماند.
    یک مسیر subnet روی هر اینترفیس کاربرِ بالا، همه را پوشش می‌دهد
    (مسیرهای /32 موجود چون دقیق‌ترند همچنان اولویت دارند)."""
    live = live_interfaces()
    for iface in server_ifaces():
        if iface not in live:
            continue
        subnet = iface_subnet(iface)
        if not subnet:
            continue
        rc, out, _ = run(["ip", "route", "show", subnet, "dev", iface],
                         timeout=10)
        if rc == 0 and not out.strip():
            rc2, _, err = run(["ip", "route", "replace", subnet,
                               "dev", iface], timeout=10)
            ok = rc2 == 0
            log_action("route guard: %s dev %s (%s)"
                       % (subnet, iface, "ok" if ok else err.strip()))
            audit("sys:guard", "iface", "iface.route.add",
                  iface, adet("ui.audit.det.routerestored", net=subnet), ok=ok)


# ------------------------------------------- محدودیت سرعتِ کاربر (traffic shaping)
#
# با `tc htb` روی اینترفیسِ کاربر: دانلود (server→client) روی egressِ خودِ
# اینترفیس با u32 match dst=IP، و آپلود (client→server) با redirectِ ingress به
# یک دستگاهِ ifb و شکل‌دهیِ egress آن با match src=IP. کاملاً **opt-in**: تا وقتی
# هیچ کاربری محدود نشده، اصلاً به tc دست نمی‌زنیم (اینترفیس دست‌نخورده می‌مانَد).
# کلاسِ پیش‌فرض روی line-rate است تا کاربرانِ بدونِ محدودیت هیچ اثری نبینند.

SHAPER_LINE_MBIT = 1000          # کلاسِ پیش‌فرض (عملاً نامحدود)
_DEFAULT_CLASSID = "4095"        # minor کلاسِ پیش‌فرض (بزرگ‌تر از هر octet)


def _tc(args, ok_fail=False):
    """اجرای یک دستور tc/ip؛ خطاها لاگ می‌شوند (مگر ok_fail)."""
    rc, out, err = run(args, timeout=10)
    if rc != 0 and not ok_fail:
        log_action("shaper cmd fail: %s -> %s" % (" ".join(args), err.strip()))
    return rc == 0


class TrafficShaper:
    """محدودیت سرعتِ per-user با tc htb (خوددرمان، مقاوم به ری‌استارت wg-quick)."""

    def __init__(self):
        self.sig = {}   # iface -> امضای آخرین وضعیت اعمال‌شده
        # kick() از UI و TunnelCache هر ۱۰ ثانیه هر دو reconcile می‌زنند؛
        # بدونِ قفل دو ساختِ tc درهم می‌رفتند.
        self._lock = threading.Lock()

    def _ifb(self, iface):
        # نامِ دستگاه ifb (سقف ۱۵ کاراکتر برای نامِ اینترفیس)
        return ("ib_" + iface)[:15]

    def _desired(self):
        """{iface: {ip: mbit}} برای کاربرانِ دارای محدودیتِ سرعت."""
        out = {}
        try:
            meta = META.meta_all()
        except Exception:
            return out
        for (iface, name), m in meta.items():
            rate = m.get("rate_mbit")
            if not rate:
                continue
            try:
                rate = int(rate)
            except (TypeError, ValueError):
                continue
            if rate <= 0:
                continue
            ip = peer_ip(iface, name)
            if not ip:
                continue
            try:
                if ipaddress.ip_address(ip).version != 4:
                    continue        # فیلترهای u32 ِ پایین فقط IPv4 هستند
            except ValueError:
                continue
            out.setdefault(iface, {})[ip] = rate
        return out

    @staticmethod
    def _classids(limits):
        """[(ip, mbit, classid)] با minor ِ یکتا به ازای هر IP.

        🪤 پیش از این minor از آخرین بایتِ IP ساخته می‌شد: با user_subnets
        بزرگ‌تر از /24، دو کاربرِ 10.0.0.5 و 10.0.1.5 یک classid می‌گرفتند،
        `tc class add` ِ دوم «File exists» می‌داد و فیلترش به کلاسِ کاربرِ
        اول می‌رفت (هر دو یک نرخ). شماره‌گذاریِ ترتیبی از ۱، با پرش از
        minor ِ کلاسِ پیش‌فرض.
        """
        out, minor = [], 0
        for ip in sorted(limits, key=lambda a: int(ipaddress.ip_address(a))):
            minor += 1
            if "%x" % minor == _DEFAULT_CLASSID.lower():
                minor += 1
            out.append((ip, limits[ip], "1:%x" % minor))
        return out

    def _root_installed(self, dev):
        rc, out, _ = run(["tc", "qdisc", "show", "dev", dev], timeout=10)
        return rc == 0 and "htb" in out and "1:" in out

    def _teardown(self, iface):
        ifb = self._ifb(iface)
        _tc(["tc", "qdisc", "del", "dev", iface, "root"], ok_fail=True)
        _tc(["tc", "qdisc", "del", "dev", iface, "ingress"], ok_fail=True)
        _tc(["tc", "qdisc", "del", "dev", ifb, "root"], ok_fail=True)
        _tc(["ip", "link", "set", ifb, "down"], ok_fail=True)
        _tc(["ip", "link", "del", ifb], ok_fail=True)

    def _build(self, iface, limits):
        """کلِ tc اینترفیس را از نو می‌سازد (فقط وقتی وضعیت عوض شده)."""
        ifb = self._ifb(iface)
        line = "%dmbit" % SHAPER_LINE_MBIT
        # --- دانلود: egress روی خودِ اینترفیس ---
        _tc(["tc", "qdisc", "del", "dev", iface, "root"], ok_fail=True)
        _tc(["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:",
             "htb", "default", _DEFAULT_CLASSID, "r2q", "1000"])
        _tc(["tc", "class", "add", "dev", iface, "parent", "1:",
             "classid", "1:" + _DEFAULT_CLASSID, "htb", "rate", line, "ceil", line])
        classes = self._classids(limits)
        for ip, mbit, cid in classes:
            r = "%dmbit" % mbit
            _tc(["tc", "class", "add", "dev", iface, "parent", "1:",
                 "classid", cid, "htb", "rate", r, "ceil", r])
            _tc(["tc", "filter", "add", "dev", iface, "protocol", "ip",
                 "parent", "1:", "prio", "1", "u32", "match", "ip", "dst",
                 ip + "/32", "flowid", cid])
        # --- آپلود: ingress اینترفیس → ifb، شکل‌دهی روی ifb ---
        # بدونِ ماژولِ ifb، «ip link add … type ifb» بی‌صدا شکست می‌خورد و
        # محدودیتِ آپلود هیچ‌وقت اعمال نمی‌شد؛ modprobe ِ صریح + لاگ.
        _tc(["modprobe", "ifb"], ok_fail=True)
        rc_ifb, _o, err_ifb = run(["ip", "link", "add", ifb, "type", "ifb"])
        if rc_ifb != 0 and "exists" not in (err_ifb or "").lower():
            log_action("shaper: ifb device %s unavailable (%s) — upload "
                       "limits on %s are NOT enforced" % (ifb, err_ifb.strip(),
                                                          iface))
        _tc(["ip", "link", "set", ifb, "up"])
        _tc(["tc", "qdisc", "del", "dev", ifb, "root"], ok_fail=True)
        _tc(["tc", "qdisc", "add", "dev", ifb, "root", "handle", "1:",
             "htb", "default", _DEFAULT_CLASSID, "r2q", "1000"])
        _tc(["tc", "class", "add", "dev", ifb, "parent", "1:",
             "classid", "1:" + _DEFAULT_CLASSID, "htb", "rate", line, "ceil", line])
        _tc(["tc", "qdisc", "del", "dev", iface, "ingress"], ok_fail=True)
        _tc(["tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"])
        _tc(["tc", "filter", "add", "dev", iface, "parent", "ffff:",
             "protocol", "ip", "u32", "match", "u32", "0", "0",
             "action", "mirred", "egress", "redirect", "dev", ifb])
        for ip, mbit, cid in classes:
            r = "%dmbit" % mbit
            _tc(["tc", "class", "add", "dev", ifb, "parent", "1:",
                 "classid", cid, "htb", "rate", r, "ceil", r])
            _tc(["tc", "filter", "add", "dev", ifb, "protocol", "ip",
                 "parent", "1:", "prio", "1", "u32", "match", "ip", "src",
                 ip + "/32", "flowid", cid])

    def reconcile(self):
        """وضعیت tc را با متادیتا هماهنگ می‌کند (خوددرمان هر ۱۰ ثانیه)."""
        with self._lock:
            self._reconcile()

    def _reconcile(self):
        desired = self._desired()
        live = live_interfaces()
        for iface in server_ifaces():
            if iface not in live:
                continue
            limits = desired.get(iface, {})
            sig = "|".join("%s=%d" % (ip, limits[ip]) for ip in sorted(limits))
            changed = (sig != self.sig.get(iface))
            missing = bool(limits) and not self._root_installed(iface)
            if not changed and not missing:
                continue
            try:
                if limits:
                    self._build(iface, limits)
                    log_action("shaper: %s → %d کاربرِ محدود" % (iface, len(limits)))
                elif self.sig.get(iface):   # قبلاً محدودیت بود، حالا نیست
                    self._teardown(iface)
                    log_action("shaper: %s → محدودیت‌ها برداشته شد" % iface)
                self.sig[iface] = sig
            except Exception as e:
                log_action("shaper reconcile error (%s): %r" % (iface, e))

    def kick(self):
        """اعمالِ فوری (بعد از ویرایش سرعت از UI)، در نخِ جدا تا UI بلاک نشود."""
        threading.Thread(target=self.reconcile, daemon=True).start()


SHAPER = TrafficShaper()


# ------------------------------------------- پروکسی HTTP/HTTPS (Squid) — فاز ۲
#
# پنل «مدیر/حسابدارِ» Squid است: از DB فایل‌های squid.conf و passwd را می‌سازد،
# با `squid -k reconfigure` نرم اعمال می‌کند، لاگ را برای حسابداریِ حجم پارس
# می‌کند، سرعت را با delay_pools محدود می‌کند و سهمیه را اعمال می‌کند.
# کاملاً **opt-in**: تا وقتی هیچ کاربرِ پروکسی نباشد، squid خاموش می‌ماند.
# هیچ ربطی به WireGuard/tcِ wg/مسیریابی ندارد (سرویس و پورتِ جدا).

SQUID_CONF = "/etc/squid/squid.conf"
SQUID_PASSWD = "/etc/squid/passwd"
SQUID_LOG = "/var/log/squid/access.log"
PROXY_PORT = 18080

_PROXY_USER_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,32}$")
# خطِ لاگِ فرمتِ wgp: %tl %>a "%un" %rm %ru %>Hs out=%<st in=%>st ...
# گروه‌ها: ۱=IP مبدأ، ۲=نام کاربر، ۳=متد، ۴=مقصد(url)، ۵=کدِ وضعیت،
# ۶=out، ۷=in. برای حسابداریِ بایت، نسبت‌دهیِ IP، و تاریخچه‌ی مقصدها.
_PROXY_LINE_RE = re.compile(
    r'(\S+)\s+"([^"]*)"\s+(\S+)\s+(\S+)\s+(\S+)\s+out=(\d+)\s+in=(\d+)')


def _proxy_dest_host(method, url):
    """هاستِ مقصد را از خطِ لاگ درمی‌آورد. CONNECT: host:port؛ GET: از URL.
    خطوطِ خطا (error:...) یا نامعتبر → None."""
    if not url or url == "-" or url.startswith("error:"):
        return None
    if method == "CONNECT":
        return url.rsplit(":", 1)[0]  # host:port → host
    m = re.match(r'(?:[a-zA-Z]+://)?([^/:]+)', url)
    return m.group(1) if m else None


def valid_proxy_user(name):
    return bool(_PROXY_USER_RE.match(name or ""))


def parse_allow_src(raw):
    """لیستِ IP/CIDR (v4/v6) از رشته‌ی جداشده با کاما/فاصله/خط.
    خروجی: (list, error). خالی = بدونِ محدودیتِ مبدأ."""
    if not raw:
        return [], None
    parts = re.split(r"[\s,]+", str(raw).strip())
    out = []
    for p in parts:
        if not p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            return None, aerr("api.err.addrrange", v=p[:40])
        out.append(str(net))
        if len(out) > 32:
            return None, "api.err.maxip"
    return out, None


def proxy_noauth_src_conflict(srcs, exclude=None):
    """آیا IP/رنجِ داده‌شده با کاربرِ بدونِ‌رمزِ دیگری هم‌پوشانی دارد؟
    (چون هویتِ کاربرِ بدونِ‌رمز = IP مبدأ است، هم‌پوشانی نسبت‌دهی را مبهم می‌کند.)
    خروجی: نامِ کاربرِ متداخل یا None."""
    try:
        want = [ipaddress.ip_network(s, strict=False) for s in srcs]
    except ValueError:
        return None
    for u in META.proxy_users():
        if not u.get("noauth") or u["username"] == exclude:
            continue
        other, _e = parse_allow_src(u.get("allow_src"))
        for o in (other or []):
            try:
                onet = ipaddress.ip_network(o, strict=False)
            except ValueError:
                continue
            if any(w.overlaps(onet) for w in want):
                return u["username"]
    return None


def proxy_hash(pw):
    """هشِ apr1 (سازگار با basic_ncsa_auth). رمز از stdin تا در ps دیده نشود."""
    try:
        r = subprocess.run(["openssl", "passwd", "-apr1", "-stdin"],
                           input=str(pw) + "\n", capture_output=True,
                           text=True, timeout=10)
        h = (r.stdout or "").strip()
        return h if h.startswith("$apr1$") else None
    except Exception as e:
        log_action("proxy_hash error: %r" % e)
        return None


def _write_root_file(path, text, mode=0o644, owner=None):
    """نوشتنِ اتمیک (tmp+rename) با مالک/دسترسیِ مشخص.

    فایلِ موقت نامِ یکتا دارد (mkstemp)، نه path+".tmp" ِ ثابت: دو نویسنده‌ی
    هم‌زمان با O_TRUNC روی یک نام، فایلِ نیمه‌ی هم را منتشر می‌کردند.
    mkstemp با 0600 می‌سازد و chmod ِ بعدی مود را قطعی می‌کند — یکی از
    فراخوان‌ها SQUID_PASSWD است که نباید حتی یک لحظه بازتر باشد.
    """
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".",
                               suffix=".tmp", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        if owner:
            try:
                shutil.chown(tmp, user=owner, group=owner)
            except (LookupError, PermissionError, OSError):
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _proxy_id_acl(u):
    """نامِ ACL هویتِ کاربر برای delay/proto: بدونِ‌رمز = src-محور، وگرنه auth-محور."""
    return ("noauth_%s" if u.get("noauth") else "u_%s") % u["username"]


def proxy_squid_conf(users):
    """متنِ squid.conf. users: [{"username","rate_kbit","allow_src":[...],
    "protocol","noauth"}].
    - کاربرِ عادی: با proxy_auth (نام/رمز)؛ اختیاری محدودیتِ IP مبدأ.
    - کاربرِ بدونِ‌رمز (noauth): بدونِ نام/رمز، فقط بر اساسِ IP مبدأ (allow_src
      اجباری — در reconcile تضمین شده)؛ قبل از لایه‌ی auth اجازه می‌گیرد.
    - rate_kbit → delay_pool (چه auth چه noauth)."""
    auth_users = [u for u in users if not u.get("noauth")]
    noauth_users = [u for u in users if u.get("noauth")]
    rate_users = [u for u in users if u.get("rate_kbit")]
    # محدودیتِ IP فقط برای کاربرانِ auth معنی دارد (noauth ذاتاً IP-محور است)
    src_auth = [u for u in auth_users if u.get("allow_src")]
    proto_users = [u for u in users if u.get("protocol") in ("http", "https")]
    L = [
        "# ساخته‌شده توسط wg-panel — دستی ویرایش نکنید",
        # نامِ سرور را از کانفیگ بگیر، نه سخت‌کد: این مقدار در صفحه‌ی خطای
        # Squid و هدرِ Via به کاربرِ نهایی نشان داده می‌شود، پس نامِ سخت‌کدِ
        # یک استقرار روی هر نصبِ دیگری هم ظاهر می‌شد.
        "visible_hostname %s-proxy" % re.sub(r"[^A-Za-z0-9.-]", "-",
                                             _host_label() or "wg-panel"),
        "http_port %d" % PROXY_PORT,
        "auth_param basic program /usr/lib/squid/basic_ncsa_auth %s" % SQUID_PASSWD,
        "auth_param basic realm proxy",
        "auth_param basic children 5",
        "auth_param basic credentialsttl 2 hours",
        "acl authenticated proxy_auth REQUIRED",
        "acl to_internal dst 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 "
        "192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 ::1 fc00::/7 fe80::/10",
        "acl SSL_ports port 443",
        "acl Safe_ports port 80 443",
        "acl CONNECT method CONNECT",
    ]
    # acl هویتِ کاربرانِ auth (برای delay/src/protocol) — بدونِ تکرار
    for u in {x["username"]: x for x in
              rate_users + src_auth + proto_users if not x.get("noauth")}.values():
        L.append("acl u_%s proxy_auth %s" % (u["username"], u["username"]))
    for u in src_auth:
        L.append("acl src_%s src %s"
                 % (u["username"], " ".join(u["allow_src"])))
    # acl هویتِ کاربرانِ noauth: خودِ IP مبدأ
    for u in noauth_users:
        L.append("acl noauth_%s src %s"
                 % (u["username"], " ".join(u["allow_src"])))
    L += [
        "http_access deny to_internal",
        "http_access deny CONNECT !SSL_ports",
        "http_access deny !Safe_ports",
    ]
    # محدودیتِ IP مبدأ کاربرانِ auth (قبل از allow؛ از IP غیرمجاز رد می‌شود)
    for u in src_auth:
        L.append("http_access deny u_%s !src_%s"
                 % (u["username"], u["username"]))
    # محدودیتِ پروتکل per-user: http = بدونِ CONNECT، https = فقط CONNECT
    for u in proto_users:
        idacl = _proxy_id_acl(u)
        if u["protocol"] == "http":
            L.append("http_access deny %s CONNECT" % idacl)
        elif u["protocol"] == "https":
            L.append("http_access deny %s !CONNECT" % idacl)
    # کاربرانِ بدونِ‌رمز: قبل از لایه‌ی auth، فقط از IP مجازشان اجازه بگیرند
    for u in noauth_users:
        L.append("http_access allow noauth_%s" % u["username"])
    L += [
        "http_access allow authenticated",
        "http_access deny all",
    ]
    if rate_users:
        L.append("delay_pools %d" % len(rate_users))
        for i, u in enumerate(rate_users, start=1):
            bps = max(1, int(u["rate_kbit"]) * 125)   # kbit/s → bytes/s
            L.append("delay_class %d 1" % i)
            L.append("delay_parameters %d %d/%d" % (i, bps, bps))
            L.append("delay_access %d allow %s" % (i, _proxy_id_acl(u)))
            L.append("delay_access %d deny all" % i)
    L += [
        'logformat wgp %tl %>a "%un" %rm %ru %>Hs out=%<st in=%>st %<tt "%{User-Agent}>h"',
        "access_log %s wgp" % SQUID_LOG,
        "cache deny all",
        "via off",
        "forwarded_for delete",
        "dns_nameservers 127.0.0.1",
        "shutdown_lifetime 3 seconds",
        "",
    ]
    return "\n".join(L)


class ProxyManager:
    """opt-in: از DB، passwd/squid.conf می‌سازد و squid را استارت/reconfigure/stop
    می‌کند؛ سهمیه و انقضا را اعمال می‌کند (کاربرِ ردشده از passwd حذف می‌شود)."""

    def __init__(self):
        self.sig = None
        # kick() و TunnelCache هم‌زمان: دو نویسنده روی passwd/squid.conf
        # فایلِ نیمه/خالی منتشر می‌کردند.
        self._lock = threading.Lock()

    def _active(self):
        rc, out, _ = run(["systemctl", "is-active", "squid"], timeout=10)
        return out.strip() == "active"

    def _apply(self, running_wanted):
        if running_wanted:
            if self._active():
                run(["squid", "-k", "reconfigure"], timeout=15)
            else:
                run(["systemctl", "start", "squid"], timeout=20)
        else:
            if self._active():
                run(["systemctl", "stop", "squid"], timeout=20)

    def reconcile(self):
        with self._lock:
            self._reconcile()

    def _reconcile(self):
        users = META.proxy_users()
        if not users:
            if self.sig != "":
                self._apply(False)
                self.sig = ""
            return
        month = datetime.now().strftime("%Y-%m")
        today = datetime.now().strftime("%Y-%m-%d")
        totals = META.proxy_month_totals(month)
        GB = 1024 ** 3
        allowed = []   # dictهای کاربرِ مجاز به auth
        for u in users:
            name = u["username"]
            # ⚠️ کدِ پایدارِ لاتین، نه متنِ نمایشی — این مقدار در ستونِ
            #    auto_disabled ذخیره و بعداً با == مقایسه می‌شود. متنِ خواندنی
            #    از کلیدِ ui.disabled.* ساخته می‌شود. (مقدارِ فارسیِ به‌جامانده
            #    از نسخه‌های پیشین در همین چرخه با کد جایگزین می‌شود.)
            reason = ""
            if not valid_proxy_user(name):
                reason = "invalid"
            elif not u["enabled"]:
                reason = "disabled"
            elif u["expires"] and today >= u["expires"]:
                reason = "expired"
            elif u["quota_gb"] and totals.get(name, 0) >= u["quota_gb"] * GB:
                reason = "quota"
            noauth = bool(u.get("noauth"))
            srcs, _e = parse_allow_src(u.get("allow_src"))
            # ★ گاردِ امنیتی: کاربرِ بدونِ‌رمز حتماً باید IP مجاز داشته باشد،
            #   وگرنه پروکسیِ بازِ عمومی می‌شود. بدونِ IP → غیرفعال.
            if not reason and noauth and not srcs:
                reason = "no_src_ip"
            if (u["auto_disabled"] or "") != reason:
                try:
                    META.proxy_set_auto_disabled(name, reason)
                except Exception:
                    pass
                # هشدارِ لبه‌ای: تازه به سهمیه/انقضا خورد
                if reason in ("quota", "expired"):
                    ALERTS.event("quota" if reason == "quota" else "expiry",
                                 A('alert.reconcile.6', p0=name, p1=reason))
            # هشدارِ نزدیک‌شدن به سقفِ سهمیه (۹۰٪ پیش‌فرض) — یک‌بار per-user
            if not reason and u["quota_gb"]:
                used = totals.get(name, 0)
                pct = used / (u["quota_gb"] * GB) * 100 if u["quota_gb"] else 0
                thr = alert_cfg()["quota_pct"]
                ALERTS.edge("pxquota:" + name, pct >= thr,
                            A('alert.reconcile.1', p0=name, p1=round(pct), p2=used / GB, p3=u['quota_gb']),
                            category="quota")
            if not reason and (u["pass_hash"] or noauth):
                proto = u.get("protocol") or "both"
                if proto not in ("http", "https", "both"):
                    proto = "both"
                allowed.append({"username": name,
                                "pass_hash": u["pass_hash"] or "",
                                "rate_kbit": u["rate_kbit"],
                                "allow_src": srcs or [], "protocol": proto,
                                "noauth": noauth})
        sig = "|".join(
            "%s:%s:%d:%s:%s:%d" % (u["username"], u["pass_hash"][:12],
                                   u["rate_kbit"], ",".join(u["allow_src"]),
                                   u["protocol"], 1 if u["noauth"] else 0)
            for u in sorted(allowed, key=lambda x: x["username"]))
        want_running = bool(allowed)
        if sig == self.sig and self._active() == want_running:
            return
        try:
            # فقط کاربرانِ دارای رمز در passwd می‌آیند (noauth بدونِ رمز است)
            passwd = "".join(
                "%s:%s\n" % (u["username"], u["pass_hash"])
                for u in allowed if u["pass_hash"])
            _write_root_file(SQUID_PASSWD, passwd, 0o640, owner="proxy")
            _write_root_file(SQUID_CONF, proxy_squid_conf(allowed), 0o644)
            self._apply(want_running)
            log_action("proxy: %d کاربرِ فعال (squid %s)"
                       % (len(allowed), "روشن" if want_running else "خاموش"))
            self.sig = sig
        except Exception as e:
            log_action("proxy reconcile error: %r" % e)

    def kick(self):
        threading.Thread(target=self.reconcile, daemon=True).start()


PROXY = ProxyManager()


class ProxyLogParser(threading.Thread):
    """دنباله‌ی access.log را می‌خواند و حجمِ per-user را در DB جمع می‌زند
    (مقاوم به چرخشِ لاگ). بارِ ناچیز؛ اگر squid خاموش باشد لاگ رشد نمی‌کند."""

    INTERVAL = 10

    def __init__(self):
        super().__init__(daemon=True)
        self.pos = 0
        self.inode = None
        self.pending = {}
        self.pending_clients = {}   # (user, ip) -> [bytes, hits]
        self.pending_dests = {}     # (user, host) -> [bytes, hits, ok, fail]
        self.noauth_nets = []   # [(ip_network, username)] برای نسبت‌دهیِ IP-محور

    def _refresh_noauth_map(self):
        """نگاشتِ IP/رنجِ کاربرانِ بدونِ‌رمز → نامشان (برای خطوطِ لاگِ بی‌نام)."""
        nets = []
        try:
            for u in META.proxy_users():
                if not u.get("noauth"):
                    continue
                srcs, _e = parse_allow_src(u.get("allow_src"))
                for s in (srcs or []):
                    try:
                        nets.append((ipaddress.ip_network(s, strict=False),
                                     u["username"]))
                    except ValueError:
                        pass
        except Exception:
            return
        self.noauth_nets = nets

    def _noauth_owner(self, ip_str):
        if not self.noauth_nets:
            return None
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        for net, name in self.noauth_nets:
            if ip in net:
                return name
        return None

    def _collect(self):
        try:
            f = open(SQUID_LOG, "r", encoding="utf-8", errors="replace")
        except OSError:
            return
        self._refresh_noauth_map()
        try:
            st = os.fstat(f.fileno())
            if self.inode is None:
                # بارِ اول: از انتهای فایل شروع کن (لاگ‌های قدیمی دوباره شمرده نشوند)
                self.inode, self.pos = st.st_ino, st.st_size
                return
            if st.st_ino != self.inode or st.st_size < self.pos:
                self.inode, self.pos = st.st_ino, 0   # چرخشِ لاگ
            f.seek(self.pos)
            for line in f:
                m = _PROXY_LINE_RE.search(line)
                if not m:
                    continue
                srcip, user = m.group(1), m.group(2)
                if not user or user == "-":
                    # خطِ بی‌نام: اگر از IP یک کاربرِ بدونِ‌رمز است، به او نسبت بده
                    user = self._noauth_owner(srcip)
                    if not user:
                        continue
                method, url, code = m.group(3), m.group(4), m.group(5)
                b = int(m.group(6)) + int(m.group(7))
                if b:
                    self.pending[user] = self.pending.get(user, 0) + b
                # تاریخچه‌ی IP کلاینت (هر خطِ نسبت‌داده‌شده = یک اتصال)
                if srcip and srcip != "-":
                    c = self.pending_clients.setdefault((user, srcip), [0, 0])
                    c[0] += b
                    c[1] += 1
                # تاریخچه‌ی مقصد (host): hits/ok/fail/bytes per (user, host)
                host = _proxy_dest_host(method, url)
                if host:
                    d = self.pending_dests.setdefault((user, host), [0, 0, 0, 0])
                    d[0] += b          # bytes
                    d[1] += 1          # hits
                    if code.isdigit():
                        c3 = int(code)
                        if 200 <= c3 < 400:
                            d[2] += 1  # ok
                        elif c3 >= 400 and c3 != 407:
                            d[3] += 1  # fail (407 = چالشِ auth، خطا نیست)
            self.pos = f.tell()
        finally:
            f.close()

    def _flush(self):
        ts = time.time()
        if self.pending_clients:
            crows = [(u, ip, bh[0], bh[1], ts)
                     for (u, ip), bh in self.pending_clients.items()]
            self.pending_clients = {}
            try:
                META.proxy_add_clients(crows)
            except Exception as e:
                log_action("proxy client flush error: %r" % e)
        if self.pending_dests:
            drows = [(u, h, v[0], v[1], v[2], v[3], ts)
                     for (u, h), v in self.pending_dests.items()]
            self.pending_dests = {}
            try:
                META.proxy_add_dests(drows)
            except Exception as e:
                log_action("proxy dest flush error: %r" % e)
        if not self.pending:
            return
        now = datetime.now()
        hour, day = now.strftime("%Y-%m-%d %H"), now.strftime("%Y-%m-%d")
        rows = [(hour, day, u, b) for u, b in self.pending.items() if b]
        self.pending = {}
        META.proxy_add_usage(rows)

    def run(self):
        while True:
            _heartbeat("proxylog")
            time.sleep(self.INTERVAL)
            try:
                self._collect()
                self._flush()
            except Exception as e:
                log_action("proxy log parse error: %r" % e)


PROXYLOG = ProxyLogParser()


def proxy_recent_log(n=200):
    """آخرین n خطِ access.log را به رکوردهای ساختاریافته تبدیل می‌کند (برای UI)."""
    try:
        n = max(1, min(int(n), 1000))
    except (TypeError, ValueError, OverflowError):
        n = 200
    try:
        with open(SQUID_LOG, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            chunk = min(size, 256 * 1024)
            f.seek(size - chunk)
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    lines = [l for l in data.splitlines() if l.strip()][-n:]
    out = []
    # فرمت wgp: <زمان> <IP> "<user>" <متد> <url> <کد> out=.. in=.. <مدت> "<ua>"
    rx = re.compile(
        r'^(?P<ts>\S+ \S+) (?P<ip>\S+) "(?P<user>[^"]*)" (?P<method>\S+) '
        r'(?P<url>\S+) (?P<code>\S+) out=(?P<out>\d+) in=(?P<in>\d+) '
        r'(?P<dur>\S+) "(?P<ua>[^"]*)"')
    for line in reversed(lines):   # جدیدترین اول
        m = rx.match(line)
        if not m:
            continue
        d = m.groupdict()
        user, by_ip = d["user"], False
        if not user or user == "-":
            owner = PROXYLOG._noauth_owner(d["ip"])
            if owner:
                user, by_ip = owner, True   # کاربرِ بدونِ‌رمز، شناسایی با IP
        out.append({
            "ts": d["ts"], "ip": d["ip"], "user": user, "by_ip": by_ip,
            "method": d["method"], "url": d["url"][:200], "code": d["code"],
            "bytes": int(d["out"]) + int(d["in"]),
            "dur_ms": (int(d["dur"]) if d["dur"].isdigit() else None)})
    return out


class TunnelCache(threading.Thread):
    """وضعیت systemd و Endpoint تونل‌ها را هر ۱۰ ثانیه در پس‌زمینه تازه می‌کند.

    بدون این کش، هر درخواستِ /api/stats به ازای هر تونل یک پروسه‌ی
    systemctl اجرا می‌کرد (۴۲ پروسه در هر ۲ ثانیه به ازای هر تب باز).
    همین چرخه نگهبان مسیر رنج کاربرها را هم اجرا می‌کند.
    """

    INTERVAL = 10

    def __init__(self):
        super().__init__(daemon=True)
        self.lock = threading.Lock()
        self.data = {}  # iface -> {"systemd": ..., "endpoint": ...}

    def refresh(self):
        data = {}
        live = set(live_interfaces())
        for iface in list_tunnel_confs():
            ep = read_tunnel_endpoint(iface)
            info = {"systemd": systemd_state(iface),
                    "endpoint": ep,
                    "enabled": tunnel_enabled(iface),
                    "kind": "amneziawg" if _tunnel_is_awg(iface) else "wireguard",
                    "userspace": _tunnel_is_awg(iface),
                    "loop_dev": None, "loop": False, "chain": False}
            # آشکارسازِ حلقهٔ مسیریابی فقط برای تونل‌های زنده (ارزان می‌ماند)
            if iface in live:
                (info["loop_dev"], info["loop"],
                 info["chain"]) = endpoint_route_state(iface, ep)
            data[iface] = info
        with self.lock:
            self.data = data
        try:
            ensure_user_routes()
        except Exception as e:
            log_action("route guard error: %r" % e)
        try:
            SHAPER.reconcile()      # محدودیت سرعت (خوددرمان، opt-in)
        except Exception as e:
            log_action("shaper error: %r" % e)
        try:
            PROXY.reconcile()       # پروکسی Squid (opt-in: بدونِ کاربر، خاموش)
        except Exception as e:
            log_action("proxy error: %r" % e)

    def update_one(self, iface):
        ep = read_tunnel_endpoint(iface)
        info = {"systemd": systemd_state(iface), "endpoint": ep,
                "enabled": tunnel_enabled(iface),
                "kind": "amneziawg" if _tunnel_is_awg(iface) else "wireguard",
                "userspace": _tunnel_is_awg(iface),
                "loop_dev": None, "loop": False, "chain": False}
        if iface in set(live_interfaces()):
            (info["loop_dev"], info["loop"],
             info["chain"]) = endpoint_route_state(iface, ep)
        with self.lock:
            self.data[iface] = info

    def get(self):
        with self.lock:
            return dict(self.data)

    def run(self):
        while True:
            _heartbeat("tunnels")
            time.sleep(self.INTERVAL)
            try:
                self.refresh()
            except Exception as e:
                log_action("tunnelcache error: %r" % e)


TUNNELS = TunnelCache()


# ------------------------------------------- ناظر تغییرات دستی فایل کانفیگ

class ConfWatcher(threading.Thread):
    """تغییرات دستی کانفیگ اینترفیس‌های سمت کاربر (خارج از پنل) را تشخیص
    می‌دهد و بدون ری‌استارت اینترفیس، فقط دلتای قدیم→جدید را با wg set
    اعمال می‌کند.

    - هر ۵ ثانیه mtime فایل‌ها چک می‌شود.
    - بعد از تغییر، یک دور ۵ ثانیه‌ای صبر می‌کند تا فایل پایدار بماند
      (ویرایش نیمه‌کاره اعمال نشود).
    - peer هایی که فقط در runtime اضافه شده‌اند (با wg set دستی) دست
      نمی‌خورند؛ فقط تفاوت دو نسخه‌ی فایل اعمال می‌شود.
    """

    def __init__(self):
        super().__init__(daemon=True)
        self.lock = threading.Lock()
        self.mtimes = {}    # iface -> mtime
        self.pendings = {}  # iface -> mtime در انتظار پایداری
        self.states = {}    # iface -> {public_key: allowed_ips} بلوک‌های فعال

    @staticmethod
    def _snapshot(iface):
        # {pub: (allowed, psk, keepalive)} — تغییرِ PSK یا keepalive در
        # فایل هم باید اعمال شود، نه فقط AllowedIPs.
        return _peer_live_state(iface)

    def resync(self):
        """بعد از هر نوشتنِ خود پنل صدا زده می‌شود تا همان تغییر دوباره اعمال نشود."""
        with self.lock:
            for iface in server_ifaces():
                try:
                    self.mtimes[iface] = os.stat(conf_path(iface)).st_mtime
                    self.states[iface] = self._snapshot(iface)
                    self.pendings.pop(iface, None)
                except OSError:
                    pass

    def run(self):
        self.resync()
        while True:
            _heartbeat("confwatch")
            time.sleep(5)
            for iface in server_ifaces():
                try:
                    self._tick(iface)
                except Exception as e:
                    log_action("confwatch error (%s): %r" % (iface, e))

    def _tick(self, iface):
        try:
            m = os.stat(conf_path(iface)).st_mtime
        except OSError:
            return
        with self.lock:
            if iface not in self.mtimes:
                self.mtimes[iface] = m
                self.states[iface] = self._snapshot(iface)
                return
            if m == self.mtimes[iface]:
                self.pendings.pop(iface, None)
                return
            if self.pendings.get(iface) != m:
                self.pendings[iface] = m  # تازه عوض شده؛ یک دور صبر کن
                return
            old = self.states[iface]
            new = self._snapshot(iface)
            self.mtimes[iface] = m
            self.pendings.pop(iface, None)
            self.states[iface] = new
        # اینترفیسِ خاموش: فایل با wg-quick up اعمال خواهد شد (apply_conf_delta
        # خودش بررسی می‌کند). همان تابعی که بازیابیِ بکاپ استفاده می‌کند.
        apply_conf_delta(iface, old, new, actor=ACTOR_MANUAL)


WATCHER = ConfWatcher()


# ------------------------------------ دیتابیس: حسابداری ترافیک + متادیتا

class MetaDB:
    """SQLite (WAL) برای مصرف ساعتی/روزانه‌ی هر peer و متادیتای کاربرها.

    اتصال‌ها کوتاه‌عمرند (هر عملیات یک اتصال) تا بین نخ‌ها امن باشد.
    """

    def __init__(self):
        con = self._connect()
        with con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS usage_hour("
                "hour TEXT, iface TEXT, pubkey TEXT,"
                "rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,"
                "PRIMARY KEY(hour, iface, pubkey))")
            con.execute(
                "CREATE TABLE IF NOT EXISTS usage_day("
                "day TEXT, iface TEXT, pubkey TEXT,"
                "rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,"
                "PRIMARY KEY(day, iface, pubkey))")
            con.execute(
                "CREATE TABLE IF NOT EXISTS peer_meta("
                "iface TEXT, name TEXT,"
                "note TEXT NOT NULL DEFAULT '', quota_gb REAL, expires TEXT,"
                "auto_disabled TEXT NOT NULL DEFAULT '',"
                "PRIMARY KEY(iface, name))")
            con.execute(
                "CREATE TABLE IF NOT EXISTS audit("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
                "actor TEXT NOT NULL DEFAULT '', category TEXT NOT NULL,"
                "action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',"
                "detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',"
                "ok INTEGER NOT NULL DEFAULT 1)")
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts)")
            # لینک‌های اشتراک امن (توکن به‌صورت هش ذخیره می‌شود؛ خودِ توکن هرگز)
            con.execute(
                "CREATE TABLE IF NOT EXISTS share("
                "token_hash TEXT PRIMARY KEY, iface TEXT NOT NULL,"
                "name TEXT NOT NULL, expires REAL NOT NULL,"
                "single INTEGER NOT NULL DEFAULT 1, views INTEGER NOT NULL "
                "DEFAULT 0, created REAL NOT NULL, creator TEXT NOT NULL "
                "DEFAULT '', revoked INTEGER NOT NULL DEFAULT 0)")
            # ستون‌های افزوده‌ی peer_meta (مهاجرت امن روی دیتابیس موجود)
            for coldef in ("c_dns TEXT", "c_mtu INTEGER", "c_keepalive INTEGER",
                           "c_allowed TEXT", "total_gb REAL",
                           "enforce_action TEXT", "rate_mbit INTEGER"):
                try:
                    con.execute("ALTER TABLE peer_meta ADD COLUMN " + coldef)
                except sqlite3.OperationalError:
                    pass  # ستون از قبل هست
            # --- تشخیص مسیر سرویس‌ها (فقط اطلاعاتی؛ هیچ تغییری در مسیریابی)
            # فهرست IPهای resolve‌شده‌ی هر سرویس (موجودیِ مقصد).
            con.execute(
                "CREATE TABLE IF NOT EXISTS svc_resolved("
                "service TEXT NOT NULL, ip TEXT NOT NULL,"
                "first_seen REAL NOT NULL, last_seen REAL NOT NULL,"
                "PRIMARY KEY(service, ip))")
            # آخرین نتیجه‌ی پروبِ هر (سرویس، اینترفیسِ خروجی).
            con.execute(
                "CREATE TABLE IF NOT EXISTS svc_probe("
                "service TEXT NOT NULL, iface TEXT NOT NULL,"
                "ok INTEGER NOT NULL DEFAULT 0, latency_ms REAL,"
                "http_code INTEGER, verdict TEXT NOT NULL DEFAULT '',"
                "detail TEXT NOT NULL DEFAULT '', ts REAL NOT NULL,"
                "PRIMARY KEY(service, iface))")
            # --- متریک‌های سیستم (گیج‌ها): میانگینِ ساعتی/روزانه (sum/cnt).
            con.execute(
                "CREATE TABLE IF NOT EXISTS metric_hour("
                "hour TEXT NOT NULL, metric TEXT NOT NULL,"
                "sum REAL NOT NULL DEFAULT 0, cnt INTEGER NOT NULL DEFAULT 0,"
                "PRIMARY KEY(hour, metric))")
            con.execute(
                "CREATE TABLE IF NOT EXISTS metric_day("
                "day TEXT NOT NULL, metric TEXT NOT NULL,"
                "sum REAL NOT NULL DEFAULT 0, cnt INTEGER NOT NULL DEFAULT 0,"
                "PRIMARY KEY(day, metric))")
            # --- نسبتِ بلندمدتِ AI/کولترالِ جراحیِ SNI (بایت در هر ساعت/روز).
            #     از دلتای شمارنده‌های splitter پُر می‌شود؛ برای نمودارِ روند.
            con.execute(
                "CREATE TABLE IF NOT EXISTS warp_split_hour("
                "hour TEXT PRIMARY KEY, ai INTEGER NOT NULL DEFAULT 0,"
                "direct INTEGER NOT NULL DEFAULT 0,"
                "qai INTEGER NOT NULL DEFAULT 0, qdirect INTEGER NOT NULL DEFAULT 0)")
            con.execute(
                "CREATE TABLE IF NOT EXISTS warp_split_day("
                "day TEXT PRIMARY KEY, ai INTEGER NOT NULL DEFAULT 0,"
                "direct INTEGER NOT NULL DEFAULT 0,"
                "qai INTEGER NOT NULL DEFAULT 0, qdirect INTEGER NOT NULL DEFAULT 0)")
            # ستون‌های کوریِ طبقه‌بندی (هشدارِ زودهنگامِ ECH) — مهاجرتِ امن
            # روی دیتابیسِ موجود، همان الگوی peer_meta.
            for tbl in ("warp_split_hour", "warp_split_day"):
                for coldef in ("nosni INTEGER NOT NULL DEFAULT 0",
                               "ech INTEGER NOT NULL DEFAULT 0"):
                    try:
                        con.execute("ALTER TABLE %s ADD COLUMN %s"
                                    % (tbl, coldef))
                    except sqlite3.OperationalError:
                        pass  # ستون از قبل هست
            # --- خطِ زمانیِ رویدادهای WARP: افزودن/حذفِ مقصد، سوییچِ egress،
            #     چرخشِ endpoint، دوره‌های fail-open، تغییرِ کشورِ خروج — همه‌ی
            #     رویدادهایی که تا حالا در actions.log و هشدارها پراکنده بودند،
            #     یک‌جا و در خودِ کارت. کران‌دار (trim در warp_event).
            con.execute(
                "CREATE TABLE IF NOT EXISTS warp_event("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
                "kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',"
                "actor TEXT NOT NULL DEFAULT '')")
            con.execute("CREATE INDEX IF NOT EXISTS idx_warp_event_ts "
                        "ON warp_event(ts)")
            # --- کیفیتِ مسیر: TTFBِ WARP در برابر مسیرِ عادی (میلی‌ثانیه).
            #     برای دیدنِ «تونلِ سالم ولی کند» که probeِ دودویی نمی‌دید.
            con.execute(
                "CREATE TABLE IF NOT EXISTS warp_latency("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
                "warp_ms REAL, direct_ms REAL)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_warp_latency_ts "
                        "ON warp_latency(ts)")
            # --- تاریخچه‌ی نمودار مسیر (mtr): هر اجرا با آمار سطحِ مسیر + hops JSON
            #     برای مقایسه‌ی قبل/بعد. نگهداری ۶ ماه (در prune).
            con.execute(
                "CREATE TABLE IF NOT EXISTS mtr_run("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
                "service TEXT NOT NULL, iface TEXT NOT NULL, target TEXT,"
                "rtt REAL, jitter REAL, loss REAL, mos REAL,"
                "reached INTEGER NOT NULL DEFAULT 0, hop_count INTEGER,"
                "hops TEXT)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_mtr_run "
                        "ON mtr_run(service, iface, ts)")
            # --- کاربران پروکسی (Squid) و حسابداریِ حجمِ per-user ---
            con.execute(
                "CREATE TABLE IF NOT EXISTS proxy_user("
                "username TEXT PRIMARY KEY, pass_hash TEXT NOT NULL DEFAULT '',"
                "rate_kbit INTEGER NOT NULL DEFAULT 0,"
                "quota_gb REAL NOT NULL DEFAULT 0,"
                "expires TEXT NOT NULL DEFAULT '',"
                "enabled INTEGER NOT NULL DEFAULT 1,"
                "auto_disabled TEXT NOT NULL DEFAULT '',"
                "note TEXT NOT NULL DEFAULT '', created REAL NOT NULL DEFAULT 0,"
                "allow_src TEXT NOT NULL DEFAULT '',"
                "pass_plain TEXT NOT NULL DEFAULT '',"
                "protocol TEXT NOT NULL DEFAULT 'both',"
                "noauth INTEGER NOT NULL DEFAULT 0)")
            for _coldef in ("allow_src TEXT NOT NULL DEFAULT ''",
                            "pass_plain TEXT NOT NULL DEFAULT ''",
                            "protocol TEXT NOT NULL DEFAULT 'both'",
                            "noauth INTEGER NOT NULL DEFAULT 0"):
                try:   # مهاجرت DBهای قدیمی
                    con.execute("ALTER TABLE proxy_user ADD COLUMN " + _coldef)
                except sqlite3.OperationalError:
                    pass  # ستون از قبل هست
            con.execute(
                "CREATE TABLE IF NOT EXISTS proxy_usage_hour("
                "hour TEXT NOT NULL, username TEXT NOT NULL,"
                "bytes INTEGER NOT NULL DEFAULT 0,"
                "PRIMARY KEY(hour, username))")
            con.execute(
                "CREATE TABLE IF NOT EXISTS proxy_usage_day("
                "day TEXT NOT NULL, username TEXT NOT NULL,"
                "bytes INTEGER NOT NULL DEFAULT 0,"
                "PRIMARY KEY(day, username))")
            # تاریخچه‌ی IP کلاینت‌های هر کاربرِ پروکسی (نگهداری ۶ ماه).
            con.execute(
                "CREATE TABLE IF NOT EXISTS proxy_client("
                "username TEXT NOT NULL, ip TEXT NOT NULL,"
                "first_seen REAL NOT NULL, last_seen REAL NOT NULL,"
                "hits INTEGER NOT NULL DEFAULT 0,"
                "bytes INTEGER NOT NULL DEFAULT 0,"
                "PRIMARY KEY(username, ip))")
            # تاریخچه‌ی مقصدهای (host) هر کاربرِ پروکسی (نگهداری ۶ ماه).
            con.execute(
                "CREATE TABLE IF NOT EXISTS proxy_dest("
                "username TEXT NOT NULL, host TEXT NOT NULL,"
                "first_seen REAL NOT NULL, last_seen REAL NOT NULL,"
                "hits INTEGER NOT NULL DEFAULT 0,"
                "ok INTEGER NOT NULL DEFAULT 0,"
                "fail INTEGER NOT NULL DEFAULT 0,"
                "bytes INTEGER NOT NULL DEFAULT 0,"
                "PRIMARY KEY(username, host))")
            # نتایجِ تستِ سرعت (دستی + خودکار؛ نگهداری ۶ ماه)
            con.execute(
                "CREATE TABLE IF NOT EXISTS speedtest("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ts REAL NOT NULL, iface TEXT NOT NULL,"
                "server_id INTEGER, ping_ms REAL,"
                "down_bps REAL, up_bps REAL,"
                "ok INTEGER NOT NULL DEFAULT 0,"
                "error TEXT NOT NULL DEFAULT '')")
            for coldef in ("jitter_ms REAL", "loss_pct REAL", "url TEXT"):
                try:
                    con.execute("ALTER TABLE speedtest ADD COLUMN " + coldef)
                except sqlite3.OperationalError:
                    pass  # ستون از قبل هست
        con.close()
        try:
            os.chmod(DB_PATH, 0o600)
        except OSError:
            pass

    META_COLS = ("note", "quota_gb", "expires", "c_dns", "c_mtu",
                 "c_keepalive", "c_allowed", "total_gb", "enforce_action",
                 "rate_mbit")

    @staticmethod
    def _connect():
        con = sqlite3.connect(DB_PATH, timeout=10)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        return con

    # ---- حسابداری
    def add_usage(self, rows):
        """rows: [(hour, day, iface, pubkey, rx_delta, tx_delta), ...]"""
        if not rows:
            return
        con = self._connect()
        with con:
            for hour, day, iface, pub, rx, tx in rows:
                con.execute(
                    "INSERT INTO usage_hour(hour,iface,pubkey,rx,tx) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(hour,iface,pubkey) DO "
                    "UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx",
                    (hour, iface, pub, rx, tx))
                con.execute(
                    "INSERT INTO usage_day(day,iface,pubkey,rx,tx) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(day,iface,pubkey) DO "
                    "UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx",
                    (day, iface, pub, rx, tx))
        con.close()

    def month_totals(self, month_prefix):
        """{(iface, pubkey): (rx, tx)} برای ماه جاری (پیشوند YYYY-MM)."""
        con = self._connect()
        cur = con.execute(
            "SELECT iface, pubkey, SUM(rx), SUM(tx) FROM usage_day "
            "WHERE day LIKE ? GROUP BY iface, pubkey", (month_prefix + "%",))
        out = {(i, p): (rx or 0, tx or 0) for i, p, rx, tx in cur.fetchall()}
        con.close()
        return out

    def usage_matrix(self, iface, mode):
        """برای نمای انباشته: {buckets:[...], data:{pubkey:{bucket: total}}}."""
        if mode == "24h":
            table, col, span, fmt = "usage_hour", "hour", 24 * 3600, "%Y-%m-%d %H"
        elif mode == "7d":
            table, col, span, fmt = "usage_day", "day", 7 * 86400, "%Y-%m-%d"
        elif mode == "6m":
            table, col, span, fmt = "usage_day", "day", 183 * 86400, "%Y-%m-%d"
        else:
            table, col, span, fmt = "usage_day", "day", 30 * 86400, "%Y-%m-%d"
        key = datetime.fromtimestamp(
            datetime.now().timestamp() - span).strftime(fmt)
        con = self._connect()
        cur = con.execute(
            "SELECT %s, pubkey, SUM(rx)+SUM(tx) FROM %s WHERE iface=? AND "
            "pubkey NOT IN (?, ?) AND %s>=? GROUP BY %s, pubkey ORDER BY %s"
            % (col, table, col, col, col),
            (iface, NETDEV_KEY, IFACE_AGG_KEY, key))
        buckets, data = [], {}
        seen = set()
        for t, pub, total in cur.fetchall():
            if t not in seen:
                seen.add(t); buckets.append(t)
            data.setdefault(pub, {})[t] = total or 0
        con.close()
        return {"buckets": buckets, "data": data}

    def lifetime_totals(self):
        """{(iface, pubkey): (rx, tx)} مجموع کل ثبت‌شده از ابتدای حسابداری."""
        con = self._connect()
        cur = con.execute(
            "SELECT iface, pubkey, SUM(rx), SUM(tx) FROM usage_day "
            "GROUP BY iface, pubkey")
        out = {(i, p): (rx or 0, tx or 0) for i, p, rx, tx in cur.fetchall()}
        con.close()
        return out

    # ---- تستِ سرعت
    def speedtest_add(self, r):
        con = self._connect()
        with con:
            con.execute(
                "INSERT INTO speedtest(ts,iface,server_id,ping_ms,down_bps,"
                "up_bps,ok,error,jitter_ms,loss_pct,url) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (r["ts"], r["iface"], r["server_id"], r["ping_ms"],
                 r["down_bps"], r["up_bps"], 1 if r["ok"] else 0,
                 r.get("error") or "", r.get("jitter_ms"),
                 r.get("loss_pct"), r.get("url") or ""))
        con.close()

    def speedtest_recent(self, limit=400):
        con = self._connect()
        cur = con.execute(
            "SELECT ts,iface,server_id,ping_ms,down_bps,up_bps,ok,error,"
            "jitter_ms,loss_pct,url FROM speedtest ORDER BY id DESC LIMIT ?",
            (min(int(limit), 2000),))
        rows = [{"ts": ts, "iface": i, "server_id": sid, "ping_ms": pg,
                 "down_bps": dn, "up_bps": up, "ok": bool(ok), "error": er,
                 "jitter_ms": jt, "loss_pct": lp, "url": u or ""}
                for ts, i, sid, pg, dn, up, ok, er, jt, lp, u
                in cur.fetchall()]
        con.close()
        return rows

    def speedtest_avg(self, iface, days=7, before_ts=None):
        """میانگینِ دانلود/آپلودِ تست‌های موفقِ یک اینترفیس در بازه.
        خروجی: (avg_down, avg_up, count). before_ts برای حذفِ تستِ جاری."""
        con = self._connect()
        q = ("SELECT AVG(down_bps), AVG(up_bps), COUNT(*) FROM speedtest "
             "WHERE iface=? AND ok=1 AND ts>=?")
        params = [iface, time.time() - days * 86400]
        if before_ts is not None:
            q += " AND ts<?"
            params.append(before_ts)
        dn, up, n = con.execute(q, params).fetchone()
        con.close()
        return (dn or 0.0, up or 0.0, n or 0)

    # ---- لینک‌های اشتراک امن
    def share_add(self, token_hash, iface, name, expires, single, creator):
        con = self._connect()
        with con:
            con.execute(
                "INSERT OR REPLACE INTO share(token_hash,iface,name,expires,"
                "single,views,created,creator,revoked) VALUES(?,?,?,?,?,0,?,?,0)",
                (token_hash, iface, name, expires, 1 if single else 0,
                 time.time(), creator))
        con.close()

    def share_get(self, token_hash):
        con = self._connect()
        cur = con.execute(
            "SELECT iface,name,expires,single,views,revoked FROM share "
            "WHERE token_hash=?", (token_hash,))
        row = cur.fetchone()
        con.close()
        if not row:
            return None
        return {"iface": row[0], "name": row[1], "expires": row[2],
                "single": row[3], "views": row[4], "revoked": row[5]}

    def share_mark_viewed(self, token_hash):
        con = self._connect()
        with con:
            con.execute("UPDATE share SET views=views+1 WHERE token_hash=?",
                        (token_hash,))
        con.close()

    def share_claim(self, token_hash, now):
        """یک بازدید را «مطالبه» می‌کند و می‌گوید موفق بود یا نه.

        شرطِ یک‌بارمصرف داخلِ خودِ UPDATE است، نه در پایتون: پیش از این
        خواندن و افزایش دو رفت‌وبرگشتِ جدا بودند و /s/ را سرورِ چندنخی
        سرو می‌کند، پس دو درخواستِ هم‌زمان — پیش‌واکشیِ مرورگر، پیش‌نمایشِ
        لینک در مسنجر — هر دو views==0 می‌دیدند و هر دو کلیدِ خصوصی را
        نشان می‌دادند. «یک‌بارمصرف» همان چیزی است که به اپراتور می‌گوید
        اگر گیرنده توانست باز کند، کسِ دیگری ندیده.

        هر چهار شرط باید در WHERE بمانند؛ برداشتنِ هرکدام آن بررسی را به
        پایتون برمی‌گرداند و همان مسابقه را برای آن شرط باز می‌کند.

        برمی‌گرداند: dict ِ رکورد اگر مطالبه موفق بود، وگرنه None.
        """
        con = self._connect()
        try:
            with con:
                cur = con.execute(
                    "UPDATE share SET views=views+1 "
                    "WHERE token_hash=? AND revoked=0 AND expires>? "
                    "AND (single=0 OR views=0)",
                    (token_hash, now))
                if cur.rowcount != 1:
                    return None
                row = con.execute(
                    "SELECT iface,name,expires,single,views,revoked "
                    "FROM share WHERE token_hash=?", (token_hash,)).fetchone()
        finally:
            con.close()
        if not row:
            return None
        return {"iface": row[0], "name": row[1], "expires": row[2],
                "single": row[3], "views": row[4], "revoked": row[5]}

    def share_revoke(self, iface, name):
        con = self._connect()
        with con:
            con.execute("UPDATE share SET revoked=1 WHERE iface=? AND name=?",
                        (iface, name))
        con.close()

    def share_active_for(self, iface, name):
        """آیا لینک فعال (منقضی‌نشده، لغونشده، مصرف‌نشده) برای این کاربر هست؟"""
        con = self._connect()
        cur = con.execute(
            "SELECT COUNT(*) FROM share WHERE iface=? AND name=? AND revoked=0 "
            "AND expires>? AND (single=0 OR views=0)",
            (iface, name, time.time()))
        n = cur.fetchone()[0]
        con.close()
        return n > 0

    def share_active_set(self):
        """مجموعه‌ی (iface,name) هایی که لینک فعال دارند — یک کوئری."""
        con = self._connect()
        cur = con.execute(
            "SELECT DISTINCT iface, name FROM share WHERE revoked=0 AND "
            "expires>? AND (single=0 OR views=0)", (time.time(),))
        s = {(i, n) for i, n in cur.fetchall()}
        con.close()
        return s

    def share_prune(self):
        con = self._connect()
        with con:
            con.execute("DELETE FROM share WHERE expires < ?",
                        (time.time() - 86400,))
        con.close()

    # ---- تشخیص مسیر سرویس‌ها (اطلاعاتی)
    def svc_resolved_upsert(self, service, ips):
        """IPهای resolve‌شده‌ی یک سرویس را ثبت/به‌روز می‌کند (last_seen)."""
        if not ips:
            return
        now = time.time()
        con = self._connect()
        with con:
            for ip in ips:
                con.execute(
                    "INSERT INTO svc_resolved(service,ip,first_seen,last_seen) "
                    "VALUES(?,?,?,?) ON CONFLICT(service,ip) DO UPDATE SET "
                    "last_seen=excluded.last_seen", (service, ip, now, now))
        con.close()

    def svc_resolved_summary(self):
        """{service: {"count": n, "last": ts}} برای شمارش IPهای تازه (۷ روز)."""
        cut = time.time() - 7 * 86400
        con = self._connect()
        cur = con.execute(
            "SELECT service, COUNT(*), MAX(last_seen) FROM svc_resolved "
            "WHERE last_seen >= ? GROUP BY service", (cut,))
        out = {s: {"count": c, "last": m} for s, c, m in cur.fetchall()}
        con.close()
        return out

    def svc_resolved_ips(self, service, limit=64):
        cut = time.time() - 7 * 86400
        con = self._connect()
        cur = con.execute(
            "SELECT ip FROM svc_resolved WHERE service=? AND last_seen >= ? "
            "ORDER BY ip LIMIT ?", (service, cut, limit))
        out = [r[0] for r in cur.fetchall()]
        con.close()
        return out

    def svc_resolved_list(self, service, limit=256):
        """همه‌ی IPهای ثبت‌شده‌ی سرویس برای مدیریت (ویرایش/حذف)، جدیدترین اول."""
        con = self._connect()
        cur = con.execute(
            "SELECT ip, first_seen, last_seen FROM svc_resolved WHERE service=? "
            "ORDER BY last_seen DESC LIMIT ?", (service, limit))
        out = [{"ip": ip, "first_seen": fs, "last_seen": ls}
               for ip, fs, ls in cur.fetchall()]
        con.close()
        return out

    def svc_probe_upsert(self, service, iface, ok, latency_ms, http_code,
                         verdict, detail):
        con = self._connect()
        with con:
            con.execute(
                "INSERT INTO svc_probe(service,iface,ok,latency_ms,http_code,"
                "verdict,detail,ts) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(service,iface) DO UPDATE SET ok=excluded.ok,"
                "latency_ms=excluded.latency_ms,http_code=excluded.http_code,"
                "verdict=excluded.verdict,detail=excluded.detail,ts=excluded.ts",
                (service, iface, 1 if ok else 0, latency_ms, http_code,
                 verdict, detail, time.time()))
        con.close()

    def svc_probe_all(self):
        """{(service, iface): row-dict} از آخرین نتایج پروب."""
        con = self._connect()
        cur = con.execute(
            "SELECT service,iface,ok,latency_ms,http_code,verdict,detail,ts "
            "FROM svc_probe")
        out = {}
        for s, i, ok, lat, code, verdict, detail, ts in cur.fetchall():
            out[(s, i)] = {"ok": bool(ok), "latency_ms": lat,
                           "http_code": code, "verdict": verdict,
                           "detail": detail, "ts": ts}
        con.close()
        return out

    def svc_prune(self):
        """IPهای قدیمی (بیش از ۳۰ روز دیده‌نشده) و نتایج پروبِ سرویس‌های حذف‌شده."""
        con = self._connect()
        with con:
            con.execute("DELETE FROM svc_resolved WHERE last_seen < ?",
                        (time.time() - 30 * 86400,))
        con.close()

    def svc_purge_service(self, service):
        """همه‌ی داده‌های یک سرویس (IPها + نتایج پروب + مسیر) را پاک می‌کند."""
        con = self._connect()
        with con:
            con.execute("DELETE FROM svc_resolved WHERE service=?", (service,))
            con.execute("DELETE FROM svc_probe WHERE service=?", (service,))
            con.execute("DELETE FROM mtr_run WHERE service=?", (service,))
        con.close()

    # ---- تاریخچه‌ی نمودار مسیر (mtr) برای مقایسه‌ی قبل/بعد و روند ۶ ماه
    def mtr_add(self, service, iface, target, rtt, jitter, loss, mos,
                reached, hop_count, hops_json):
        con = self._connect()
        with con:
            cur = con.execute(
                "INSERT INTO mtr_run(ts,service,iface,target,rtt,jitter,loss,"
                "mos,reached,hop_count,hops) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), service, iface, target, rtt, jitter, loss, mos,
                 1 if reached else 0, hop_count, hops_json))
            rid = cur.lastrowid
        con.close()
        return rid

    def mtr_prev(self, service, iface, before_id):
        """آخرین اجرای پیش از before_id (برای مقایسه‌ی «قبل»)."""
        con = self._connect()
        cur = con.execute(
            "SELECT ts,target,rtt,jitter,loss,mos,reached,hop_count,hops "
            "FROM mtr_run WHERE service=? AND iface=? AND id<? "
            "ORDER BY id DESC LIMIT 1", (service, iface, before_id))
        row = cur.fetchone()
        con.close()
        if not row:
            return None
        return {"ts": row[0], "target": row[1], "rtt": row[2], "jitter": row[3],
                "loss": row[4], "mos": row[5], "reached": bool(row[6]),
                "hop_count": row[7], "hops": row[8]}

    def mtr_history(self, service, iface, days=183, limit=500):
        """سریِ زمانیِ آمارِ مسیر (برای روند/۶ ماه)، قدیمی→جدید."""
        cut = time.time() - days * 86400
        con = self._connect()
        cur = con.execute(
            "SELECT ts,rtt,jitter,loss,mos,reached FROM mtr_run "
            "WHERE service=? AND iface=? AND ts>=? ORDER BY ts LIMIT ?",
            (service, iface, cut, limit))
        out = [{"ts": t, "rtt": rtt, "jitter": j, "loss": l, "mos": mo,
                "reached": bool(r)} for t, rtt, j, l, mo, r in cur.fetchall()]
        con.close()
        return out

    def svc_resolved_delete(self, service, ip):
        """حذفِ یک IP از موجودیِ سرویس (اطلاعاتی؛ هیچ اثری بر مسیریابی ندارد)."""
        con = self._connect()
        with con:
            cur = con.execute(
                "DELETE FROM svc_resolved WHERE service=? AND ip=?",
                (service, ip))
            n = cur.rowcount
        con.close()
        return n

    def svc_resolved_rename(self, service, old_ip, new_ip):
        """ویرایشِ یک IP در موجودیِ سرویس (حذفِ قدیم، درجِ جدید با حفظِ زمان‌ها)."""
        con = self._connect()
        with con:
            row = con.execute(
                "SELECT first_seen,last_seen FROM svc_resolved "
                "WHERE service=? AND ip=?", (service, old_ip)).fetchone()
            if not row:
                con.close()
                return False
            con.execute("DELETE FROM svc_resolved WHERE service=? AND ip=?",
                        (service, old_ip))
            con.execute(
                "INSERT INTO svc_resolved(service,ip,first_seen,last_seen) "
                "VALUES(?,?,?,?) ON CONFLICT(service,ip) DO UPDATE SET "
                "last_seen=excluded.last_seen",
                (service, new_ip, row[0], row[1]))
        con.close()
        return True

    # ---- متریک‌های سیستم (گیج‌ها)
    def add_metrics(self, rows):
        """rows: [(hour, day, metric, sum, cnt), ...] — انباشتِ میانگین."""
        if not rows:
            return
        con = self._connect()
        with con:
            for hour, day, metric, s, c in rows:
                con.execute(
                    "INSERT INTO metric_hour(hour,metric,sum,cnt) "
                    "VALUES(?,?,?,?) ON CONFLICT(hour,metric) DO UPDATE SET "
                    "sum=sum+excluded.sum, cnt=cnt+excluded.cnt",
                    (hour, metric, s, c))
                con.execute(
                    "INSERT INTO metric_day(day,metric,sum,cnt) "
                    "VALUES(?,?,?,?) ON CONFLICT(day,metric) DO UPDATE SET "
                    "sum=sum+excluded.sum, cnt=cnt+excluded.cnt",
                    (day, metric, s, c))
        con.close()

    def metric_series(self, metric, mode):
        """میانگینِ هر بازه: mode = 24h (ساعتی)، 7d/30d/6m (روزانه).
        خروجی: [{"t": bucket, "v": avg}, ...] مرتب."""
        if mode == "24h":
            table, col, span, fmt = "metric_hour", "hour", 24 * 3600, "%Y-%m-%d %H"
        elif mode == "7d":
            table, col, span, fmt = "metric_day", "day", 7 * 86400, "%Y-%m-%d"
        elif mode == "6m":
            table, col, span, fmt = "metric_day", "day", 183 * 86400, "%Y-%m-%d"
        else:
            table, col, span, fmt = "metric_day", "day", 30 * 86400, "%Y-%m-%d"
        key = datetime.fromtimestamp(
            datetime.now().timestamp() - span).strftime(fmt)
        con = self._connect()
        cur = con.execute(
            "SELECT %s, sum, cnt FROM %s WHERE metric=? AND %s>=? ORDER BY %s"
            % (col, table, col, col),
            (metric, key))
        rows = [{"t": t, "v": (s / c if c else 0)} for t, s, c in cur.fetchall()]
        con.close()
        return rows

    # ---- کاربران پروکسی (Squid)
    PROXY_COLS = ("pass_hash", "rate_kbit", "quota_gb", "expires",
                  "enabled", "auto_disabled", "note", "allow_src",
                  "pass_plain", "protocol", "noauth")

    def proxy_users(self):
        con = self._connect()
        cur = con.execute(
            "SELECT username,pass_hash,rate_kbit,quota_gb,expires,enabled,"
            "auto_disabled,note,created,allow_src,pass_plain,protocol,noauth "
            "FROM proxy_user ORDER BY username")
        cols = ["username", "pass_hash", "rate_kbit", "quota_gb", "expires",
                "enabled", "auto_disabled", "note", "created", "allow_src",
                "pass_plain", "protocol", "noauth"]
        out = [dict(zip(cols, r)) for r in cur.fetchall()]
        con.close()
        return out

    def proxy_user_get(self, username):
        for u in self.proxy_users():
            if u["username"] == username:
                return u
        return None

    def proxy_user_upsert(self, username, fields):
        """درج/به‌روزِ فقط ستون‌های داده‌شده (created فقط بار اول)."""
        fields = {k: v for k, v in fields.items() if k in self.PROXY_COLS}
        con = self._connect()
        with con:
            exists = con.execute("SELECT 1 FROM proxy_user WHERE username=?",
                                 (username,)).fetchone()
            if not exists:
                con.execute("INSERT INTO proxy_user(username,created) VALUES(?,?)",
                            (username, time.time()))
            if fields:
                cols = list(fields.keys())
                con.execute(
                    "UPDATE proxy_user SET %s WHERE username=?"
                    % ", ".join("%s=?" % c for c in cols),
                    [fields[c] for c in cols] + [username])
        con.close()

    def proxy_user_delete(self, username):
        con = self._connect()
        with con:
            con.execute("DELETE FROM proxy_user WHERE username=?", (username,))
        con.close()

    def proxy_set_auto_disabled(self, username, reason):
        con = self._connect()
        with con:
            con.execute("UPDATE proxy_user SET auto_disabled=? WHERE username=?",
                        (reason, username))
        con.close()

    def proxy_add_usage(self, rows):
        """rows: [(hour, day, username, bytes), ...] — انباشتِ حجم."""
        if not rows:
            return
        con = self._connect()
        with con:
            for hour, day, user, b in rows:
                con.execute(
                    "INSERT INTO proxy_usage_hour(hour,username,bytes) "
                    "VALUES(?,?,?) ON CONFLICT(hour,username) DO UPDATE SET "
                    "bytes=bytes+excluded.bytes", (hour, user, b))
                con.execute(
                    "INSERT INTO proxy_usage_day(day,username,bytes) "
                    "VALUES(?,?,?) ON CONFLICT(day,username) DO UPDATE SET "
                    "bytes=bytes+excluded.bytes", (day, user, b))
        con.close()

    def proxy_add_clients(self, rows):
        """rows: [(username, ip, bytes, hits, ts), ...] — تاریخچه‌ی IP کلاینت.
        first_seen بارِ اول ثبت، last_seen/hits/bytes انباشته می‌شوند."""
        if not rows:
            return
        con = self._connect()
        with con:
            for user, ip, b, hits, ts in rows:
                con.execute(
                    "INSERT INTO proxy_client(username,ip,first_seen,last_seen,"
                    "hits,bytes) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(username,ip) DO UPDATE SET "
                    "last_seen=excluded.last_seen, hits=hits+excluded.hits, "
                    "bytes=bytes+excluded.bytes",
                    (user, ip, ts, ts, hits, b))
        con.close()

    def proxy_clients(self, username, limit=500):
        """تاریخچه‌ی IP کلاینت‌های یک کاربرِ پروکسی، جدیدترین اتصال اول."""
        con = self._connect()
        cur = con.execute(
            "SELECT ip, first_seen, last_seen, hits, bytes FROM proxy_client "
            "WHERE username=? ORDER BY last_seen DESC LIMIT ?",
            (username, limit))
        out = [{"ip": ip, "first_seen": fs, "last_seen": ls,
                "hits": h, "bytes": b}
               for ip, fs, ls, h, b in cur.fetchall()]
        con.close()
        return out

    def proxy_add_dests(self, rows):
        """rows: [(username, host, bytes, hits, ok, fail, ts), ...]."""
        if not rows:
            return
        con = self._connect()
        with con:
            for user, host, b, hits, ok, fail, ts in rows:
                con.execute(
                    "INSERT INTO proxy_dest(username,host,first_seen,last_seen,"
                    "hits,ok,fail,bytes) VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(username,host) DO UPDATE SET "
                    "last_seen=excluded.last_seen, hits=hits+excluded.hits, "
                    "ok=ok+excluded.ok, fail=fail+excluded.fail, "
                    "bytes=bytes+excluded.bytes",
                    (user, host, ts, ts, hits, ok, fail, b))
        con.close()

    def proxy_dests(self, username, limit=500):
        """تاریخچه‌ی مقصدهای یک کاربرِ پروکسی، جدیدترین اول."""
        con = self._connect()
        cur = con.execute(
            "SELECT host, first_seen, last_seen, hits, ok, fail, bytes "
            "FROM proxy_dest WHERE username=? ORDER BY last_seen DESC LIMIT ?",
            (username, limit))
        out = [{"host": h, "first_seen": fs, "last_seen": ls, "hits": hits,
                "ok": ok, "fail": fail, "bytes": b}
               for h, fs, ls, hits, ok, fail, b in cur.fetchall()]
        con.close()
        return out

    def proxy_month_totals(self, month_prefix):
        """{username: bytes} برای ماه جاری (پیشوند YYYY-MM)."""
        con = self._connect()
        cur = con.execute(
            "SELECT username, SUM(bytes) FROM proxy_usage_day "
            "WHERE day LIKE ? GROUP BY username", (month_prefix + "%",))
        out = {u: (b or 0) for u, b in cur.fetchall()}
        con.close()
        return out

    def proxy_usage_series(self, username, mode):
        """سری زمانیِ حجمِ یک کاربرِ پروکسی (برای گراف). rx=bytes, tx=0."""
        if mode == "24h":
            table, col, span, fmt = "proxy_usage_hour", "hour", 24*3600, "%Y-%m-%d %H"
        elif mode == "7d":
            table, col, span, fmt = "proxy_usage_day", "day", 7*86400, "%Y-%m-%d"
        elif mode == "6m":
            table, col, span, fmt = "proxy_usage_day", "day", 183*86400, "%Y-%m-%d"
        else:
            table, col, span, fmt = "proxy_usage_day", "day", 30*86400, "%Y-%m-%d"
        key = datetime.fromtimestamp(
            datetime.now().timestamp() - span).strftime(fmt)
        con = self._connect()
        cur = con.execute(
            "SELECT %s, bytes FROM %s WHERE username=? AND %s>=? ORDER BY %s"
            % (col, table, col, col), (username, key))
        rows = [{"t": t, "bytes": b or 0} for t, b in cur.fetchall()]
        con.close()
        return rows

    def usage_series(self, iface, pubkey, mode, gran=None):
        """سری زمانی مصرف. mode: ‏24h (ساعتی)، 7d/30d/6m (روزانه).

        gran="hour" برای 7d/30d باکتِ ساعتی می‌دهد (نقشه‌ی حرارتیِ
        ساعت×روزِهفته — جدولِ ساعتی ~۲۱ روز نگه داشته می‌شود).
        pubkey ویژه: IFACE_AGG_KEY = جمع همه‌ی peer های اینترفیس (برای
        تونل‌ها)؛ NETDEV_KEY = شمارنده‌های /proc/net/dev خود اینترفیس.
        """
        if gran == "hour" and mode in ("7d", "30d"):
            table, col, fmt = "usage_hour", "hour", "%Y-%m-%d %H"
            span = (7 if mode == "7d" else 30) * 86400
        elif mode == "24h":
            table, col, span, fmt = "usage_hour", "hour", 24 * 3600, "%Y-%m-%d %H"
        elif mode == "7d":
            table, col, span, fmt = "usage_day", "day", 7 * 86400, "%Y-%m-%d"
        elif mode == "6m":
            table, col, span, fmt = "usage_day", "day", 183 * 86400, "%Y-%m-%d"
        else:
            table, col, span, fmt = "usage_day", "day", 30 * 86400, "%Y-%m-%d"
        key = datetime.fromtimestamp(
            datetime.now().timestamp() - span).strftime(fmt)
        con = self._connect()
        if pubkey == IFACE_AGG_KEY:
            cur = con.execute(
                "SELECT %s, SUM(rx), SUM(tx) FROM %s WHERE iface=? AND "
                "pubkey != ? AND %s>=? GROUP BY %s ORDER BY %s"
                % (col, table, col, col, col),
                (iface, NETDEV_KEY, key))
        else:
            cur = con.execute(
                "SELECT %s, rx, tx FROM %s WHERE iface=? AND pubkey=? AND "
                "%s>=? ORDER BY %s" % (col, table, col, col),
                (iface, pubkey, key))
        rows = [{"t": t, "rx": rx or 0, "tx": tx or 0}
                for t, rx, tx in cur.fetchall()]
        con.close()
        return rows

    def usage_prev_total(self, iface, pubkey, mode):
        """مجموعِ rx/tx بازه‌ی هم‌طولِ «قبل» (برای چیپِ ▲/▼ نسبت به بازه‌ی
        قبل). 24h از جدولِ ساعتی، بقیه از روزانه — همان منطقِ usage_series."""
        if mode == "24h":
            table, col, span, fmt = "usage_hour", "hour", 24 * 3600, "%Y-%m-%d %H"
        elif mode == "7d":
            table, col, span, fmt = "usage_day", "day", 7 * 86400, "%Y-%m-%d"
        elif mode == "6m":
            table, col, span, fmt = "usage_day", "day", 183 * 86400, "%Y-%m-%d"
        else:
            table, col, span, fmt = "usage_day", "day", 30 * 86400, "%Y-%m-%d"
        now = datetime.now().timestamp()
        k0 = datetime.fromtimestamp(now - 2 * span).strftime(fmt)
        k1 = datetime.fromtimestamp(now - span).strftime(fmt)
        con = self._connect()
        if pubkey == IFACE_AGG_KEY:
            cur = con.execute(
                "SELECT SUM(rx), SUM(tx) FROM %s WHERE iface=? AND pubkey != ? "
                "AND %s>=? AND %s<?" % (table, col, col),
                (iface, NETDEV_KEY, k0, k1))
        else:
            cur = con.execute(
                "SELECT SUM(rx), SUM(tx) FROM %s WHERE iface=? AND pubkey=? "
                "AND %s>=? AND %s<?" % (table, col, col),
                (iface, pubkey, k0, k1))
        row = cur.fetchone()
        con.close()
        return {"rx": (row and row[0]) or 0, "tx": (row and row[1]) or 0}

    def graph_events(self, iface, name, since_ts, include_warp=False):
        """رویدادهای مرتبط با یک موجودیتِ گراف (کاربر/تونل/اینترفیس) از
        auditِ موجود + رویدادهای WARP — برای نشانگرهای روی محورِ زمان.

        name خالی = خودِ اینترفیس/تونل (category های tunnel/iface)؛
        name پر = کاربرِ وایرگارد (category=peer با target «name @ iface»).
        خروجی: [{ts, src, action, detail, actor, sev}] — src: audit|warp؛
        action کدِ پایدار است (peer.disable، tun.monitor.down، rotate) و
        مرورگر آن را ترجمه می‌کند. sev: bad|ok|info برای رنگِ فلگ.
        """
        def sev_of(action):
            a = str(action)
            parts = set(re.split(r"[._]", a))
            if parts & {"del", "disable", "down", "degrade", "standby",
                        "failopen"} or a == "iface.loop.found":
                return "bad"
            if parts & {"add", "enable", "up", "fix", "restore"}:
                return "ok"
            # ردیف‌های پیش از چهارزبانه‌شدن متنِ فارسی دارند، نه کد
            if any(w in a for w in ("قطع", "غیرفعال", "حذف", "حلقه")):
                return "bad"
            if any(w in a for w in ("وصل", "فعال", "افزودن", "رفع")):
                return "ok"
            return "info"
        con = self._connect()
        out = []
        if name:
            cur = con.execute(
                "SELECT ts, action, detail, actor FROM audit WHERE "
                "category='peer' AND target=? AND ts>=? ORDER BY ts LIMIT 300",
                ("%s @ %s" % (name, iface), since_ts))
        else:
            cur = con.execute(
                "SELECT ts, action, detail, actor FROM audit WHERE "
                "category IN ('tunnel','iface') AND target=? AND ts>=? "
                "ORDER BY ts LIMIT 300", (iface, since_ts))
        for ts, action, detail, actor in cur.fetchall():
            out.append({"ts": ts, "src": "audit", "action": action,
                        "detail": detail or "", "actor": actor or "",
                        "sev": sev_of(action)})
        if include_warp:
            cur = con.execute(
                "SELECT ts, kind, detail FROM warp_event WHERE ts>=? "
                "ORDER BY ts LIMIT 200", (since_ts,))
            for ts, kind, detail in cur.fetchall():
                out.append({"ts": ts, "src": "warp", "action": kind or "",
                            "detail": detail or "", "actor": "",
                            "sev": sev_of(kind) if kind else "info"})
        con.close()
        out.sort(key=lambda e: e["ts"])
        return out[-300:]

    def prune(self):
        con = self._connect()
        with con:
            h = datetime.fromtimestamp(
                time.time() - 21 * 86400).strftime("%Y-%m-%d %H")
            d = datetime.fromtimestamp(
                time.time() - 400 * 86400).strftime("%Y-%m-%d")
            con.execute("DELETE FROM usage_hour WHERE hour < ?", (h,))
            con.execute("DELETE FROM usage_day WHERE day < ?", (d,))
            # متریک‌های سیستم: ساعتی ~۲۱ روز، روزانه ~۴۰۰ روز (>۶ ماه)
            con.execute("DELETE FROM metric_hour WHERE hour < ?", (h,))
            con.execute("DELETE FROM metric_day WHERE day < ?", (d,))
            # نسبتِ AI/کولترالِ جراحیِ SNI: ساعتی ~۲۱ روز، روزانه ~۴۰۰ روز
            con.execute("DELETE FROM warp_split_hour WHERE hour < ?", (h,))
            con.execute("DELETE FROM warp_split_day WHERE day < ?", (d,))
            # خطِ زمانیِ رویدادهای WARP: نگهداری ۶ ماه (کران‌داری هم در نوشتن)
            con.execute("DELETE FROM warp_event WHERE ts < ?",
                        (time.time() - 183 * 86400,))
            # کیفیتِ مسیر (TTFB): نگهداری ~۳۰ روز (نمونه‌ی هر ۱۰ دقیقه)
            con.execute("DELETE FROM warp_latency WHERE ts < ?",
                        (time.time() - 30 * 86400,))
            # حسابداریِ حجمِ پروکسی: ساعتی ~۲۱ روز، روزانه ~۴۰۰ روز (>۶ ماه)
            con.execute("DELETE FROM proxy_usage_hour WHERE hour < ?", (h,))
            con.execute("DELETE FROM proxy_usage_day WHERE day < ?", (d,))
            # تاریخچه‌ی IP کلاینت‌ها و مقصدها: نگهداری ۶ ماه (بر اساسِ آخرین اتصال)
            con.execute("DELETE FROM proxy_client WHERE last_seen < ?",
                        (time.time() - 183 * 86400,))
            con.execute("DELETE FROM proxy_dest WHERE last_seen < ?",
                        (time.time() - 183 * 86400,))
            # تاریخچه‌ی تغییرات: نگهداری ۶ ماه (۱۸۳ روز)
            con.execute("DELETE FROM audit WHERE ts < ?",
                        (time.time() - 183 * 86400,))
            # نتایجِ تستِ سرعت: نگهداری ۶ ماه
            con.execute("DELETE FROM speedtest WHERE ts < ?",
                        (time.time() - 183 * 86400,))
            # موجودیِ IP سرویس‌ها: نگهداری ۳۰ روز
            con.execute("DELETE FROM svc_resolved WHERE last_seen < ?",
                        (time.time() - 30 * 86400,))
            # تاریخچه‌ی نمودار مسیر (mtr): نگهداری ۶ ماه (۱۸۳ روز)؛ از قدیمی‌ترین
            con.execute("DELETE FROM mtr_run WHERE ts < ?",
                        (time.time() - 183 * 86400,))
        # WAL بعد از هرسِ روزانه فشرده شود؛ وگرنه فایلِ -wal تا ری‌استارت
        # رشد می‌کند (خارج از تراکنش، چون checkpoint داخلِ آن بی‌اثر است).
        #
        # 🪤 این دو DELETE ِ بالا قبلاً اینجا، زیرِ `pass` ِ همین except
        # بودند: تورفتگی‌شان آن‌ها را جزوِ شاخه‌ی خطا کرده بود و هرگز اجرا
        # نمی‌شدند — svc_resolved و mtr_run بی‌کران رشد می‌کردند.
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        con.close()

    # ---- تاریخچه‌ی تغییرات (audit)
    def add_audit(self, actor, category, action, target, detail, ip, ok):
        con = self._connect()
        with con:
            con.execute(
                "INSERT INTO audit(ts,actor,category,action,target,detail,ip,ok)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (time.time(), actor, category, action, target,
                 detail, ip, 1 if ok else 0))
        con.close()

    def audit_list(self, category=None, actor=None, q=None, since_days=None,
                   limit=500):
        where, params = [], []
        if category and category != "all":
            where.append("category=?"); params.append(category)
        if actor:
            where.append("actor=?"); params.append(actor)
        if since_days:
            where.append("ts>=?"); params.append(time.time() - since_days * 86400)
        if q:
            # % و _ ِ خودِ کاربر باید حرفی باشند، نه wildcard
            esc = (str(q).replace("\\", "\\\\").replace("%", "\\%")
                   .replace("_", "\\_"))
            where.append("(target LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' "
                         "OR actor LIKE ? ESCAPE '\\')")
            like = "%" + esc + "%"; params += [like, like, like]
        sql = "SELECT ts,actor,category,action,target,detail,ip,ok FROM audit"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(min(int(limit), 2000))
        con = self._connect()
        cur = con.execute(sql, params)
        rows = [{"ts": ts, "actor": actor, "category": cat, "action": act,
                 "target": tgt, "detail": det, "ip": ip, "ok": bool(ok)}
                for ts, actor, cat, act, tgt, det, ip, ok in cur.fetchall()]
        con.close()
        return rows

    def audit_actors(self):
        con = self._connect()
        cur = con.execute("SELECT DISTINCT actor FROM audit "
                          "WHERE actor != '' ORDER BY actor")
        out = [r[0] for r in cur.fetchall()]
        con.close()
        return out

    # ---- متادیتای کاربرها
    def meta_all(self):
        cols = ["note", "quota_gb", "expires", "auto_disabled", "c_dns",
                "c_mtu", "c_keepalive", "c_allowed", "total_gb",
                "enforce_action", "rate_mbit"]
        con = self._connect()
        cur = con.execute(
            "SELECT iface, name, %s FROM peer_meta" % ", ".join(cols))
        out = {}
        for row in cur.fetchall():
            iface, name = row[0], row[1]
            out[(iface, name)] = dict(zip(cols, row[2:]))
        con.close()
        return out

    def meta_update(self, iface, name, fields):
        """upsert فقط ستون‌های داده‌شده (بقیه دست‌نخورده)."""
        fields = {k: v for k, v in fields.items() if k in self.META_COLS}
        if not fields:
            return
        cols = list(fields.keys())
        con = self._connect()
        with con:
            placeholders = ",".join("?" for _ in cols)
            setclause = ", ".join("%s=excluded.%s" % (c, c) for c in cols)
            con.execute(
                "INSERT INTO peer_meta(iface,name,%s) VALUES(?,?,%s) "
                "ON CONFLICT(iface,name) DO UPDATE SET %s"
                % (",".join(cols), placeholders, setclause),
                [iface, name] + [fields[c] for c in cols])
        con.close()

    def meta_set(self, iface, name, note, quota_gb, expires):
        self.meta_update(iface, name, {"note": note, "quota_gb": quota_gb,
                                       "expires": expires})

    def set_auto_disabled(self, iface, name, reason):
        con = self._connect()
        with con:
            con.execute(
                "INSERT INTO peer_meta(iface,name,auto_disabled) "
                "VALUES(?,?,?) ON CONFLICT(iface,name) DO UPDATE SET "
                "auto_disabled=excluded.auto_disabled", (iface, name, reason))
        con.close()

    def clear_auto_disabled(self, iface, name):
        con = self._connect()
        with con:
            con.execute(
                "UPDATE peer_meta SET auto_disabled='' WHERE iface=? AND name=?",
                (iface, name))
        con.close()

    def delete(self, iface, name):
        con = self._connect()
        with con:
            con.execute("DELETE FROM peer_meta WHERE iface=? AND name=?",
                        (iface, name))
        con.close()


META = MetaDB()


# --------------------------------------------------------- نمونه‌بردار ترافیک

class Sampler(threading.Thread):
    """هر ۲ ثانیه `wg show all dump` را می‌خواند و نرخ لحظه‌ای را حساب می‌کند."""

    FLUSH_INTERVAL = 60
    PRUNE_INTERVAL = 3600
    RING10_LEN = 360        # تبِ «۱ ساعت»: ۳۶۰ نقطه‌ی ~۱۰ثانیه‌ای در حافظه

    def __init__(self):
        super().__init__(daemon=True)
        self.lock = threading.Lock()
        self.prev = {}          # (iface, pub) -> (ts, rx, tx)
        self.rates = {}         # (iface, pub) -> (rx_rate, tx_rate)
        self.history = {}       # (iface, pub) -> deque[(ts, rx_rate, tx_rate)]
        self.iface_hist = {}    # iface -> deque (مجموع نرخ peer های wg)
        self.latest = {"ifaces": {}, "peers": []}
        self.net_prev = {}      # iface -> (ts, rx_bytes, tx_bytes)  از /proc/net/dev
        self.net_hist = {}      # iface -> deque[(ts, rx_rate, tx_rate)]
        self.net_latest = {}    # iface -> {rx_total, tx_total, rx_rate, tx_rate}
        self.pending = {}       # (iface, pub) -> [rx_delta, tx_delta] برای DB
        # رینگِ میان‌دانه برای پر کردنِ شکافِ «زنده (۳دقیقه) ← ساعتی»:
        # دلتاها در پنجره‌های ~۱۰ثانیه‌ای تجمیع و به‌صورت نرخِ میانگین ذخیره
        # می‌شوند — کلیدها: (iface,pub) peer، ('agg',iface) تونل، ('net',iface).
        self.ring10 = {}        # key -> deque[(ts, rx_rate, tx_rate)]
        self.acc10 = {}         # key -> [t0, rx_bytes, tx_bytes]
        self.last_flush = time.time()
        self.last_prune = time.time()
        self.month_usage = {}   # (iface, pub) -> (rx, tx) ماه جاری
        self.life_usage = {}    # (iface, pub) -> (rx, tx) کل از ابتدای حسابداری
        self.meta_cache = {}    # (iface, name) -> متادیتا

    def _ring10_add(self, key, now, drx, dtx):
        a = self.acc10.get(key)
        if a is None:
            # پنجره با صفر باز می‌شود — دلتای بازکننده به بازه‌ی «پیش از
            # شروعِ پنجره» تعلق دارد و شمردنش نرخ را بیش‌برآورد می‌کرد
            self.acc10[key] = [now, 0, 0]
            return
        a[1] += drx
        a[2] += dtx
        dt = now - a[0]
        if dt >= 10:
            r = self.ring10.setdefault(key, deque(maxlen=self.RING10_LEN))
            r.append((now, a[1] / dt, a[2] / dt))
            self.acc10[key] = [now, 0, 0]

    def ring10_series(self, iface, pubkey):
        """سری تبِ ۱ساعت: [{t: epoch_ms, rx, tx}] — rx/tx نرخِ بایت‌برثانیه."""
        if pubkey == NETDEV_KEY:
            key = ("net", iface)
        elif pubkey == IFACE_AGG_KEY:
            key = ("agg", iface)
        else:
            key = (iface, pubkey)
        r = self.ring10.get(key)
        if not r:
            return []
        return [{"t": int(ts * 1000), "rx": round(rx, 1), "tx": round(tx, 1)}
                for ts, rx, tx in list(r)]

    def refresh_meta(self):
        """کش متادیتا/مصرف ماه/کل را فوری تازه می‌کند (بعد از ویرایش از UI)."""
        try:
            self.month_usage = META.month_totals(
                datetime.now().strftime("%Y-%m"))
            self.life_usage = META.lifetime_totals()
            self.meta_cache = META.meta_all()
        except Exception as e:
            log_action("meta refresh error: %r" % e)

    def run(self):
        self.refresh_meta()
        while True:
            _heartbeat("sampler")
            try:
                self.sample()
            except Exception as e:
                log_action("sampler error: %r" % e)
            try:
                if time.time() - self.last_flush >= self.FLUSH_INTERVAL:
                    self._flush()
            except Exception as e:
                log_action("flush error: %r" % e)
            time.sleep(SAMPLE_INTERVAL)

    def _flush(self):
        """دلتاهای انباشته را در DB می‌نویسد، کش‌ها را تازه و سهمیه/انقضا را اجرا می‌کند."""
        self.last_flush = time.time()
        now = datetime.now()
        hour, day = now.strftime("%Y-%m-%d %H"), now.strftime("%Y-%m-%d")
        pending, self.pending = self.pending, {}
        rows = [(hour, day, iface, pub, int(d[0]), int(d[1]))
                for (iface, pub), d in pending.items() if d[0] or d[1]]
        META.add_usage(rows)
        self.refresh_meta()
        if time.time() - self.last_prune >= self.PRUNE_INTERVAL:
            self.last_prune = time.time()
            META.prune()
            n = self._evict_gone_peers()
            if n:
                log_action("sampler: %d ورودیِ حالتِ پیرِ حذف‌شده آزاد شد" % n)
        self._enforce(day)

    def _known_peer_keys(self):
        """اتحادِ پیرهای زنده و پیکربندی‌شده — مرجعِ «هنوز وجود دارد».

        فقط snapshot کافی **نیست**: پیرِ پیکربندی‌شده‌ی خاموش هم باید
        بماند، چون تاریخچه‌اش دقیقاً همان چیزی است که اپراتور برای
        فهمیدنِ «کِی قطع شد» نگاه می‌کند.

        مجموعه‌ی خالی برمی‌گردد اگر خواندنِ کانفیگ‌ها شکست بخورد — و
        فراخواننده آن را «خطا» می‌فهمد، نه «همه حذف شدند».
        """
        keys = set()
        for p in (self.latest.get("peers") or []):
            if p.get("iface") and p.get("public_key"):
                keys.add((p["iface"], p["public_key"]))
        try:
            for srv in server_ifaces():
                for b in parse_user_blocks(srv):
                    if b.get("public_key"):
                        keys.add((srv, b["public_key"]))
        except Exception as e:
            log_action("evict: conf read error: %r" % e)
            return set()
        return keys

    def _evict_gone_peers(self):
        """حالتِ درون‌حافظه‌ایِ پیرهایی که دیگر وجود ندارند را آزاد کن.

        META.prune() فقط دیتابیس را هرس می‌کند؛ دیکشنری‌های خودِ Sampler
        هرگز جارو نمی‌شدند. سرویس ماه‌ها بالا می‌ماند، پس روی استقراری
        که پیر جابه‌جا می‌کند نشت یک‌طرفه و دائمی است — history و ring10
        گران‌ترین‌شان‌اند.

        🪤 سه شکلِ کلید در کار است و اشتباه‌گرفتنشان یعنی یا چیزی جارو
        نمی‌شود یا تجمیعِ اینترفیس پاک می‌شود:
          (iface, pub)  → prev/rates/history/pending
          (iface, name) → meta_cache  ← اینجا **جارو نمی‌شود**
          (iface, pub) یا ('agg', iface) یا ('net', iface) → ring10/acc10

        meta_cache و month_usage و life_usage عمداً بیرون‌اند: هر تیک
        refresh_meta آن‌ها را **بازمی‌سازد** (نه به‌روزرسانی)، پس
        خودترمیم‌اند. دیکشنری‌های per-interface هم بیرون‌اند: اینترفیس‌ها
        کم و دیرپا هستند و جاروشان ریسک می‌افزاید بی‌آنکه چیزی بدهد.
        """
        alive = self._known_peer_keys()
        if not alive:
            # هیچ پیری پیدا نشد ⇒ احتمالاً خطای خواندن، نه حذفِ همه.
            # بدونِ این گارد، یک OSError ِ گذرا کلِ تاریخچه را می‌برد.
            return 0
        gone = 0
        with self.lock:
            for d in (self.prev, self.rates, self.history, self.pending):
                for k in [k for k in d if k not in alive]:
                    d.pop(k, None)
                    gone += 1
            for d in (self.ring10, self.acc10):
                for k in [k for k in d
                          if k[0] not in ("agg", "net") and k not in alive]:
                    d.pop(k, None)
                    gone += 1
        return gone

    def _enforce(self, today):
        """اعمال سیاست: انقضا، سهمیه‌ی ماهانه، و سقف حجم کل — با اکشن
        قابل‌انتخاب (غیرفعال‌سازی یا حذف). حذف فقط با انتخاب صریح ادمین."""
        GB = 1024 ** 3
        for iface in server_ifaces():
            try:
                blocks = parse_user_blocks(iface)
            except OSError:
                continue
            for b in blocks:
                if not b["enabled"]:
                    continue
                meta = self.meta_cache.get((iface, b["name"]))
                if not meta:
                    continue
                # کدِ پایدارِ لاتین — در ستونِ auto_disabled ذخیره و با ==
                # مقایسه می‌شود؛ متنِ خواندنی از کلیدِ ui.disabled.* می‌آید.
                # 🪤 سه شرطِ مستقل، نه زنجیره‌ی elif. پیش از این
                # total_gb پشتِ elif ِ quota_gb بود، پس پیری که هر دو را
                # داشت هرگز سقفِ حجمِ کل را نمی‌خورد: شاخه‌ی quota_gb
                # درست بود (کلید وجود داشت)، elif ِ بعدی اصلاً ارزیابی
                # نمی‌شد، و سقفِ کل بی‌صدا بی‌اثر می‌ماند — دقیقاً همان
                # ترکیبی که ادمین برای «ماهانه X، ولی در مجموع بیش از Y نه»
                # می‌سازد. ترتیبِ اولویت حفظ شده: انقضا > ماهانه > کل.
                reason = ""
                if meta.get("expires") and today >= meta["expires"]:
                    reason = "expired"
                if not reason and meta.get("quota_gb"):
                    rx, tx = self.month_usage.get(
                        (iface, b["public_key"]), (0, 0))
                    if rx + tx >= meta["quota_gb"] * GB:
                        reason = "quota"
                if not reason and meta.get("total_gb"):
                    rx, tx = self.life_usage.get(
                        (iface, b["public_key"]), (0, 0))
                    if rx + tx >= meta["total_gb"] * GB:
                        reason = "total_cap"
                if not reason:
                    continue
                action = meta.get("enforce_action") or "disable"
                # کلیدِ کاتالوگ، نه متنِ فارسی: مرورگر پارامترِ why را هنگامِ
                # نمایش به زبانِ کاربر ترجمه می‌کند (auditDetail).
                det = "ui.audit.reason." + reason
                ALERTS.event("quota" if reason != "expired" else "expiry",
                             A('alert.enforce.1', p0=b['name'], p1=iface, p2=reason, p3=A('alert.lit.1') if action == 'delete' else A('alert.lit.2')))
                if action == "delete":
                    ok, msg = delete_peer(iface, b["name"])
                    log_action("enforce: %s@%s DELETED (%s) -> %s"
                               % (b["name"], iface, reason,
                                  "ok" if ok else msg))
                    audit("sys:policy", "peer", "peer.del.auto",
                          "%s @ %s" % (b["name"], iface),
                          adet("ui.audit.det.autodel", why=det), ok=ok)
                else:
                    ok, msg = set_peer_enabled(iface, b["name"], False)
                    META.set_auto_disabled(iface, b["name"], reason)
                    log_action("enforce: %s@%s disabled (%s) -> %s"
                               % (b["name"], iface, reason,
                                  "ok" if ok else msg))
                    audit("sys:policy", "peer", "peer.disable.auto",
                          "%s @ %s" % (b["name"], iface),
                          adet("ui.audit.det.autodisable", why=det), ok=ok)
        self.refresh_meta()

    def sample(self):
        now = time.time()
        self._sample_netdev(now)      # همه‌ی اینترفیس‌ها از /proc/net/dev
        dumps = []
        rc, out, err = run(["wg", "show", "all", "dump"], timeout=10)
        if rc == 0:
            dumps.append(out)
        if awg_available():
            rc, out, err = run(["awg", "show", "all", "dump"], timeout=10)
            if rc == 0:
                dumps.append(out)
        if not dumps:
            return
        ifaces = {}
        peers = []
        iface_rate = {}
        agg10 = {}   # iface -> [drx, dtx] این tick برای رینگِ ۱ساعته‌ی تونل
        for out in dumps:
          for line in out.splitlines():
            parts = line.split("\t")
            # خط peer همیشه ۹ فیلد است (هم wg هم awg)؛ خط interface
            # برای wg پنج فیلد و برای awg بیشتر است — عمومی می‌خوانیم.
            if len(parts) != 9:
                if len(parts) >= 5 and parts[3].isdigit():
                    iface, pub, listen = parts[0], parts[2], parts[3]
                    ifaces[iface] = {"listen_port": listen, "public_key": pub}
                continue
            if True:
                (iface, pub, _psk, endpoint, allowed,
                 hs, rx, tx, keepalive) = parts
                try:
                    rx, tx, hs = int(rx), int(tx), int(hs)
                except ValueError:
                    continue
                key = (iface, pub)
                rx_rate = tx_rate = 0.0
                if key in self.prev:
                    pts, prx, ptx = self.prev[key]
                    dt = now - pts
                    if dt > 0 and rx >= prx and tx >= ptx:
                        rx_rate = (rx - prx) / dt
                        tx_rate = (tx - ptx) / dt
                        # رینگِ ۱ساعته: دلتای صفر هم نقطه می‌سازد تا سکوت
                        # به‌جای گپ، خطِ صفرِ صادق باشد
                        self._ring10_add(key, now, rx - prx, tx - ptx)
                        ag = agg10.setdefault(iface, [0, 0])
                        ag[0] += rx - prx
                        ag[1] += tx - ptx
                        if rx > prx or tx > ptx:
                            pend = self.pending.setdefault(key, [0, 0])
                            pend[0] += rx - prx
                            pend[1] += tx - ptx
                self.prev[key] = (now, rx, tx)
                self.rates[key] = (rx_rate, tx_rate)
                h = self.history.setdefault(key, deque(maxlen=HISTORY_LEN))
                h.append((now, rx_rate, tx_rate))
                ir = iface_rate.setdefault(iface, [0.0, 0.0])
                ir[0] += rx_rate
                ir[1] += tx_rate
                peers.append({
                    "iface": iface, "public_key": pub, "endpoint": endpoint,
                    "allowed_ips": allowed, "handshake": hs,
                    "rx": rx, "tx": tx,
                    "rx_rate": rx_rate, "tx_rate": tx_rate,
                    "keepalive": keepalive,
                })
        for iface, (rr, tr) in iface_rate.items():
            h = self.iface_hist.setdefault(iface, deque(maxlen=HISTORY_LEN))
            h.append((now, rr, tr))
        for iface, (drx, dtx) in agg10.items():
            self._ring10_add(("agg", iface), now, drx, dtx)
        with self.lock:
            self.latest = {"ifaces": ifaces, "peers": peers, "ts": now}

    def _sample_netdev(self, now):
        """نرخ و مجموع کل هر اینترفیس شبکه از /proc/net/dev."""
        counters = read_proc_net_dev()
        latest = {}
        for iface, (rx, tx) in counters.items():
            rx_rate = tx_rate = 0.0
            if iface in self.net_prev:
                pts, prx, ptx = self.net_prev[iface]
                dt = now - pts
                if dt > 0 and rx >= prx and tx >= ptx:
                    rx_rate = (rx - prx) / dt
                    tx_rate = (tx - ptx) / dt
                    self._ring10_add(("net", iface), now,
                                     rx - prx, tx - ptx)
                    # حسابداری تاریخی اینترفیس‌ها (برای گراف ۲۴س/۷روز/۳۰روز)
                    if iface != "lo" and (rx > prx or tx > ptx):
                        pend = self.pending.setdefault(
                            (iface, NETDEV_KEY), [0, 0])
                        pend[0] += rx - prx
                        pend[1] += tx - ptx
            self.net_prev[iface] = (now, rx, tx)
            latest[iface] = {"rx_total": rx, "tx_total": tx,
                             "rx_rate": rx_rate, "tx_rate": tx_rate}
            h = self.net_hist.setdefault(iface, deque(maxlen=HISTORY_LEN))
            h.append((now, rx_rate, tx_rate))
        with self.lock:
            self.net_latest = latest

    def netdev_snapshot(self):
        with self.lock:
            return dict(self.net_latest)

    @staticmethod
    def _rate_series(h):
        """کپیِ اتمیک از dequeی مشترک بگیر، سپس به سریِ نرخ تبدیل کن.

        نخِ نمونه‌بردار هم‌زمان (بیرونِ `self.lock`) به این dequeها append
        می‌کند؛ پیمایشِ مستقیمِ همان deque گاهی درست وسطِ list-comprehension با
        یک append برخورد می‌کرد و `RuntimeError: deque mutated during
        iteration` می‌داد — یعنی آن /api/stats با ۵۰۰ می‌افتاد. `list(h)` در
        CPython اتمیک است (حلقهٔ ساختِ لیست در C است و بینِ گام‌های iterator
        هیچ‌جا GIL آزاد نمی‌شود، پس append نمی‌تواند لابه‌لای آن تزریق شود)، پس
        یک snapshotِ امن می‌دهد که round را روی کپی می‌زنیم نه روی dequeی زنده.
        """
        if not h:
            return []
        return [[round(r, 1), round(t, 1)] for (_, r, t) in list(h)]

    def net_history(self, iface):
        return self._rate_series(self.net_hist.get(iface))

    def snapshot(self):
        with self.lock:
            latest = dict(self.latest)
        return latest

    def peer_history(self, iface, pub):
        return self._rate_series(self.history.get((iface, pub)))

    def iface_history(self, iface):
        return self._rate_series(self.iface_hist.get(iface))


SAMPLER = Sampler()


# ------------------------------------------- ناظر متریک‌های سیستم (گیج‌ها)

# کلیدهای متریک و برچسب/واحد/بیشینه‌ی هر گیج.
SYS_METRICS = ("cpu", "ram", "disk", "pcpu", "pram")


class SysMon(threading.Thread):
    """هر چند ثانیه CPU/RAM/DISK سرور و CPU/RAM خودِ پنل را می‌سنجد.

    - مقادیر لحظه‌ای برای گیج‌ها (snapshot).
    - رینگِ زنده در حافظه برای نمودارِ «زنده».
    - میانگینِ ساعتی/روزانه در SQLite برای نمودارِ ۲۴س/۷روز/۳۰روز/۶ماه
      (نگهداری ۶ ماه؛ مثل حسابداری ترافیک).
    """

    INTERVAL = 3.0
    FLUSH_INTERVAL = 60
    LIVE_LEN = 1200         # ~۱ ساعت با نمونه‌ی ۳ ثانیه‌ای (تبِ ۱س گیج‌ها)
    LIVE_TAIL = 200         # نمای «زنده»‌ی قبلی: فقط ~۱۰ دقیقه‌ی آخر

    def __init__(self):
        super().__init__(daemon=True)
        self.lock = threading.Lock()
        self.cur = {}                       # metric -> value لحظه‌ای
        self.extra = {}                     # اطلاعات کمکی (کل رم/دیسک و ...)
        self.live = {m: deque(maxlen=self.LIVE_LEN) for m in SYS_METRICS}
        self.prev_cpu = None                # (total, idle)
        self.prev_self = None               # (self_jiffies, total_jiffies)
        self.pending = {m: [0.0, 0] for m in SYS_METRICS}  # metric -> [sum, cnt]
        self.last_flush = time.time()

    def sample(self):
        now = time.time()
        vals = {}
        # --- CPU سرور (دلتای /proc/stat)
        cpu = _read_cpu_times()
        if cpu and self.prev_cpu:
            dt_total = cpu[0] - self.prev_cpu[0]
            dt_idle = cpu[1] - self.prev_cpu[1]
            if dt_total > 0:
                vals["cpu"] = max(0.0, min(100.0,
                                  (dt_total - dt_idle) * 100.0 / dt_total))
        # --- CPU پنل (دلتای self نسبت به کلِ ظرفیت)
        selfj = _read_self_cpu_jiffies()
        if selfj is not None and cpu:
            if self.prev_self:
                d_self = selfj - self.prev_self[0]
                d_total = cpu[0] - self.prev_self[1]
                if d_total > 0:
                    vals["pcpu"] = max(0.0, min(100.0,
                                       d_self * 100.0 / d_total))
            self.prev_self = (selfj, cpu[0])
        if cpu:
            self.prev_cpu = cpu
        # --- RAM سرور
        mem = read_mem_pct()
        if mem:
            vals["ram"] = mem[0]
            self.extra["ram_total_mb"] = mem[1] / 1024.0
            self.extra["ram_used_mb"] = (mem[1] - mem[2]) / 1024.0
        # --- DISK سرور
        disk = read_disk_pct("/")
        if disk:
            vals["disk"] = disk[0]
            self.extra["disk_total_gb"] = disk[1] / (1024.0 ** 3)
            self.extra["disk_used_gb"] = disk[2] / (1024.0 ** 3)
        # --- RAM پنل (مگابایت)
        rss = read_self_rss_mb()
        if rss is not None:
            vals["pram"] = rss
        # ثبت
        with self.lock:
            for m, v in vals.items():
                self.cur[m] = v
                self.live[m].append((now, v))
                pend = self.pending[m]
                pend[0] += v
                pend[1] += 1

    def _flush(self):
        self.last_flush = time.time()
        now = datetime.now()
        hour, day = now.strftime("%Y-%m-%d %H"), now.strftime("%Y-%m-%d")
        with self.lock:
            pending, self.pending = self.pending, {m: [0.0, 0] for m in SYS_METRICS}
        rows = [(hour, day, m, s, c) for m, (s, c) in pending.items() if c]
        try:
            META.add_metrics(rows)
        except Exception as e:
            log_action("metric flush error: %r" % e)

    def snapshot(self):
        """{metric: value} لحظه‌ای + extra (بیشینه/واحدِ نمایش)."""
        with self.lock:
            cur = dict(self.cur)
            extra = dict(self.extra)
        # بیشینه‌ی گیجِ RAM پنل: پویا (سقفِ رُندشده‌ی بالای مقدار فعلی).
        pram = cur.get("pram", 0)
        pram_max = 128
        for cap in (128, 256, 512, 1024, 2048, 4096):
            if pram <= cap * 0.85:
                pram_max = cap
                break
        else:
            pram_max = 8192
        extra["pram_max_mb"] = pram_max
        return {"cur": cur, "extra": extra}

    def live_series(self, metric, tail=None):
        """سری زنده؛ tail=N فقط N نمونه‌ی آخر (نمای «زنده» ~۱۰ دقیقه)."""
        with self.lock:
            h = self.live.get(metric)
            if not h:
                return []
            rows = list(h)
        if tail:
            rows = rows[-tail:]
        return [[round(t, 0), round(v, 2)] for (t, v) in rows]

    def run(self):
        while True:
            _heartbeat("sysmon")
            try:
                self.sample()
            except Exception as e:
                log_action("sysmon error: %r" % e)
            try:
                if time.time() - self.last_flush >= self.FLUSH_INTERVAL:
                    self._flush()
            except Exception as e:
                log_action("sysmon flush error: %r" % e)
            time.sleep(self.INTERVAL)


SYSMON = SysMon()


# ============================================================================
# هشدارِ تلگرام — نگهبانِ سامانه (تونل/کاربر/منابع/امنیت)
# ============================================================================
# تلگرام مستقیم از سرور فیلتر است؛ فرستنده در صورت لزوم سوکت را با
# SO_BINDTODEVICE به یک تونلِ خروجی (wg21/wg22 …) می‌بندد تا از مسیرِ دورزنِ
# تحریم خارج شود. پنل با root اجرا می‌شود پس این binding مجاز است.

_SO_BINDTODEVICE = 25  # ثابتِ لینوکس (در بعضی نسخه‌های پایتون در socket نیست)

ALERT_EVENTS = (
    ("tunnel", "قطع/وصلِ تونل‌های خروجی"),
    ("ecmp", "ترمیمِ خودکارِ مسیرِ ECMP (حذف/بازگرداندنِ تونلِ مرده)"),
    ("warp", "مسیریابیِ WARP (قطعِ تونل، ناهمخوانیِ خروج، افتِ حساب)"),
    ("quota", "رسیدن به سقفِ سهمیه (وایرگارد/پروکسی)"),
    ("expiry", "نزدیک‌شدنِ انقضای حساب‌ها"),
    ("resource", "بالا ماندنِ CPU/RAM/DISK سرور"),
    ("swap", "مصرفِ Swap (خطرِ کمبودِ حافظه)"),
    ("login", "تلاش‌های ناموفقِ مکررِ ورود"),
    ("backup", "شکستِ آپلودِ بکاپِ شبانه (MEGA S4)"),
    ("speedtest", "افتِ سرعتِ اینترنت (تستِ دوره‌ای)"),
    ("startup", "راه‌اندازی/ری‌استارتِ پنل"),
    ("nqmo", "تشخیص‌های موتورِ کیفیتِ شبکه (WG-NQMO)"),
)
ALERT_EVENT_KEYS = frozenset(k for k, _ in ALERT_EVENTS)

ALERT_DEFAULTS = {
    "enabled": False,
    "bot_token": "",
    "chat_id": "",
    "iface": "",              # "" = خودکار (اول مستقیم، بعد تونل‌ها)
    "events": {k: True for k, _ in ALERT_EVENTS},
    "cpu_pct": 90,
    "ram_pct": 90,
    "disk_pct": 90,
    "sustain_min": 5,         # چند دقیقه بالای آستانه بماند تا هشدار
    "quota_pct": 90,
    "expiry_days": 3,
    "login_fails": 10,        # در پنجره‌ی ۱۰ دقیقه‌ای
    "digest_enabled": False,  # خلاصه‌ی روزانه/هفتگی
    "digest_time": "09:00",   # ساعتِ ارسال (HH:MM)
    "digest_weekly": False,   # True=هفتگی (شنبه‌ها)، False=روزانه
}


def alert_cfg():
    c = dict(ALERT_DEFAULTS)
    c.update(CONFIG.get("alerts") or {})
    ev = dict(ALERT_DEFAULTS["events"])
    ev.update((c.get("events") or {}))
    c["events"] = {k: bool(ev.get(k, True)) for k in ALERT_EVENT_KEYS}
    return c


_FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")


def _greg_to_jalali(gy, gm, gd):
    """تبدیلِ میلادی به هجریِ شمسی (الگوریتمِ jdf، بدونِ کتابخانه)."""
    g_dm = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    if gy > 1600:
        jy = 979
        gy -= 1600
    else:
        jy = 0
        gy -= 621
    gy2 = gy + 1 if gm > 2 else gy
    days = (365 * gy + (gy2 + 3) // 4 - (gy2 + 99) // 100
            + (gy2 + 399) // 400 - 80 + gd + g_dm[gm - 1])
    jy += 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm = 1 + days // 31
        jd = 1 + days % 31
    else:
        jm = 7 + (days - 186) // 30
        jd = 1 + (days - 186) % 30
    return jy, jm, jd


def _fa_num(s):
    """ارقامِ لاتین → فارسی؛ نقطه‌ی اعشار → ممیزِ فارسی (فقط برای اعداد)."""
    return str(s).translate(_FA_DIGITS).replace(".", "٫")


_EN_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩٫", "01234567890123456789.")


def _fa_digits_en(s):
    """ارقامِ فارسی/عربی و ممیزِ فارسی → لاتین (برای ورودی‌های عددیِ ربات)."""
    return str(s).translate(_EN_DIGITS)


BACKUP_STATE_PATH = "/var/backups/backup-state.json"

# نامِ گروهِ «بکاپِ کاملِ سرور» (پوشه‌ی آرشیو + یونیتِ systemd + پیشوندِ MEGA).
# ⚠️ پیش‌فرض عمداً **خنثی** است. این رشته داخلِ ایمیجِ Docker می‌رود و آن
# ایمیج قرار است روی سرورهای دیگر نصب شود — نامِ این استقرار نباید در آن
# باشد. همان دامی که §۲۹٫۷۴/۷۵ برای نامِ میزبان بست، اینجا از راهِ نامِ
# بکاپ باز مانده بود — و چون خودِ **کامنت** هم داخلِ ایمیج می‌رود، اینجا
# هیچ نامِ استقراری نوشته نمی‌شود. استقرارِ عملیاتی مقدارش را با
# `Environment=WG_FULL_BACKUP_NAME=<نام>` در یونیتِ پنل می‌دهد؛ بدونِ آن
# پنل دنبالِ wg-panel-full-backup می‌گردد و ردیفِ بکاپِ کامل خالی می‌ماند
# (نه خطا). مقدارِ واقعی در deploy/ و سندِ تغییرات ثبت است، نه اینجا.
FULL_BACKUP_NAME = os.environ.get("WG_FULL_BACKUP_NAME") or "wg-panel-full"
FULL_BACKUP_DIR = "/var/backups/" + FULL_BACKUP_NAME
FULL_BACKUP_UNIT = FULL_BACKUP_NAME + "-backup"


def _backup_state():
    """stateِ آخرین آپلودِ تأییدشده‌ی بکاپ‌ها (نوشته‌ی اسکریپت‌های بکاپ)."""
    try:
        with open(BACKUP_STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _backup_status():
    """[(برچسب, سنِ خوانا, مشکل‌دار؟), ...] — سیاستِ جدید: بکاپ فقط روی MEGA
    می‌ماند؛ ملاک، stateِ آخرین آپلودِ «تأییدشده با sha256» است. اگر state
    نبود (سازگاری با گذشته) به فایلِ محلی برمی‌گردد."""
    st = _backup_state()
    out = []
    for key, path in (("panel", "/var/backups/wg-panel/latest.tar.gz"),
                      ("full", FULL_BACKUP_DIR + "/latest.tar.gz")):
        label = A("alert.bk." + key)
        e = st.get(key) or {}
        if e.get("verified") and e.get("uploaded"):
            age = time.time() - float(e["uploaded"])
            out.append((label, _ago_srv(float(e["uploaded"])) + " (MEGA)",
                        age >= 36 * 3600))
            continue
        try:
            age = time.time() - os.path.getmtime(path)
            out.append((label, _ago_srv(time.time() - age), age >= 36 * 3600))
        except OSError:
            out.append((label, A("alert.bk.none"), True))
    return out


def _unit_props(unit, props):
    """چند property از systemctl show — خروجی: dict (خالی اگر خطا)."""
    rc, out, _e = run(["systemctl", "show", unit, "-p", ",".join(props)],
                      timeout=10)
    d = {}
    if rc == 0:
        for line in out.splitlines():
            k, _, v = line.partition("=")
            d[k] = v.strip()
    return d


def _sysd_ts(v):
    """زمانِ systemd ('Sun 2026-07-19 04:56:47 +0330') → epoch یا None."""
    v = (v or "").strip()
    if not v or v in ("n/a", "0"):
        return None
    for fmt in ("%a %Y-%m-%d %H:%M:%S %z", "%a %Y-%m-%d %H:%M:%S %Z"):
        try:
            return datetime.strptime(v, fmt).timestamp()
        except ValueError:
            continue
    return None


_MONO_RE = re.compile(r"(?:(\d+)h)?\s*(?:(\d+)min)?\s*(?:([\d.]+)s)?")


def _monotonic_to_epoch(v):
    """زمانِ مونوتونیکِ systemd ('7h 45min 56.07s' یا میکروثانیه) → epoch.

    تایمرهای OnBootSec/OnUnitActiveSec مبنای بوت دارند نه ساعتِ دیواری، پس
    NextElapseUSecRealtime خالی می‌مانَد. با uptime به زمانِ واقعی تبدیل می‌شود."""
    v = (v or "").strip()
    if not v or v in ("n/a", "0", "infinity"):
        return None
    secs = None
    if v.isdigit():                      # میکروثانیه‌ی خام
        secs = int(v) / 1e6
    else:
        m = _MONO_RE.match(v)
        if m and any(m.groups()):
            secs = (int(m.group(1) or 0) * 3600 + int(m.group(2) or 0) * 60
                    + float(m.group(3) or 0))
    if secs is None:
        return None
    try:
        with open("/proc/uptime") as f:
            up = float(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None
    return time.time() + (secs - up)


_SHA_CACHE = {}   # path -> ((mtime, size), hexdigest) — تا بکاپِ بزرگ هر بار هش نشود


def _file_sha256_cached(path):
    """SHA256 فایل با کش بر اساسِ (mtime, size)؛ خطا/نبودن → رشته‌ی خالی."""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    key = (st.st_mtime, st.st_size)
    ent = _SHA_CACHE.get(path)
    if ent and ent[0] == key:
        return ent[1]
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    dig = h.hexdigest()
    _SHA_CACHE[path] = (key, dig)
    return dig


_S4_CACHE = {}   # prefix -> {"ts", "data"}


def _s4_target(which="panel"):
    """(target، conf، keep، error) از env — مشترکِ وضعیت/فهرست/بازیابی."""
    env = {}
    try:
        with open("/etc/wg-panel-s4.env", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#") and "=" in ln:
                    k, _, v = ln.partition("=")
                    env[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return "", "", 30, "api.err.s4.noenv"
    remote, bucket = env.get("REMOTE", ""), env.get("BUCKET", "")
    if which == "full":
        prefix, keep = env.get("FULL_PREFIX", FULL_BACKUP_NAME), 14
    else:
        prefix, keep = env.get("PREFIX", "wg-panel"), 30
    if not (remote and bucket):
        return "", "", keep, "api.err.s4.nobucket"
    # سرویسِ پنل ProtectHome=yes دارد و /root را نمی‌بیند؛ configِ
    # rclone در /etc نگه‌داری می‌شود (اگر نبود، مسیرِ سنتیِ root).
    conf = "/etc/wg-panel-rclone.conf"
    if not os.path.exists(conf):
        conf = "/root/.config/rclone/rclone.conf"
    return "%s:%s/%s" % (remote, bucket, prefix), conf, keep, ""


def _s4_remote_status(force=False, which="panel"):
    """وضعیتِ باکتِ MEGA S4 با rclone lsjson؛ کشِ ۱۰ دقیقه‌ای به‌ازای هر
    prefix. which: "panel" → PREFIX (wg-panel)، "full" → FULL_PREFIX."""
    now = time.time()
    ent = _S4_CACHE.get(which)
    if not force and ent and ent["data"] and now - ent["ts"] < 600:
        return ent["data"]
    target, conf, keep, terr = _s4_target(which)
    data = {"ok": False, "error": terr, "target": "", "keep": keep}
    if target:
        data["target"] = target
        rc, out, err = run(["rclone", "--config", conf, "lsjson",
                            data["target"]], timeout=30)
        if rc == 0:
            try:
                objs = [o for o in json.loads(out or "[]")
                        if not o.get("IsDir")
                        and not o.get("Name", "").endswith(".sha256")]
                objs.sort(key=lambda o: o.get("ModTime", ""), reverse=True)
                data.update(
                    ok=True, count=len(objs),
                    total_bytes=sum(o.get("Size", 0) for o in objs),
                    latest=(objs[0].get("Name", "") if objs else ""),
                    latest_bytes=(objs[0].get("Size", 0) if objs else 0),
                    latest_mod=(objs[0].get("ModTime", "") if objs else ""))
            except ValueError:
                data["error"] = "api.err.s4.badjson"
        else:
            data["error"] = ((err or out or "").strip()
                             or "api.err.s4.rclone")[:160]
    elif not data["error"]:
        data["error"] = "api.err.s4.nobucket"
    _S4_CACHE[which] = {"ts": now, "data": data}
    return data


# ---- بازیابیِ ابری: فهرستِ نسخه‌های پنل روی MEGA + دانلود و بازیابی
_S4_VER_CACHE = {"ts": 0.0, "data": None}
_CLOUD_OBJ_RE = re.compile(r"wg-panel-\d{8}-\d{6}\.tar\.gz\Z")
CLOUD_RESTORE = {"running": False, "by": "", "started": 0.0}


def s4_panel_versions(force=False):
    """فهرستِ کاملِ نسخه‌های بکاپِ پنل روی MEGA (با نشانِ داشتنِ sha256)."""
    now = time.time()
    if not force and _S4_VER_CACHE["data"] and \
            now - _S4_VER_CACHE["ts"] < 600:
        return _S4_VER_CACHE["data"]
    target, conf, _keep, terr = _s4_target("panel")
    data = {"ok": False, "error": terr, "target": target, "versions": []}
    if target:
        rc, out, err = run(["rclone", "--config", conf, "lsjson", target],
                           timeout=30)
        if rc == 0:
            try:
                objs = json.loads(out or "[]")
                names = {o.get("Name", "") for o in objs}
                vers = []
                for o in objs:
                    nm = o.get("Name", "")
                    if o.get("IsDir") or not _CLOUD_OBJ_RE.fullmatch(nm):
                        continue
                    vers.append({"name": nm, "size": o.get("Size", 0),
                                 "mod": o.get("ModTime", ""),
                                 "has_sha": (nm + ".sha256") in names})
                vers.sort(key=lambda v: v["name"], reverse=True)
                data.update(ok=True, versions=vers)
            except ValueError:
                data["error"] = "api.err.s4.badjson"
        else:
            data["error"] = ((err or out or "").strip()
                             or "api.err.s4.rclone")[:160]
    _S4_VER_CACHE.update(ts=now, data=data)
    return data


def cloud_restore_panel(obj, components, by):
    """دانلودِ یک نسخه از MEGA، راستی‌آزماییِ sha256 (اگر sidecar باشد) و
    بازیابیِ اجزای انتخابی → (ok، پیام). همیشه fail-closed."""
    if not _CLOUD_OBJ_RE.fullmatch(obj or ""):
        return False, "api.err.vername"
    with _manual_backup_lock:
        if MANUAL_BACKUP["running"]:
            return False, "api.err.bk.busy"
        if CLOUD_RESTORE["running"]:
            return False, "api.err.restore.busy"
        CLOUD_RESTORE.update(running=True, by=by, started=time.time())
    tmpd = tempfile.mkdtemp(prefix="wgp-restore-")
    try:
        target, conf, _keep, terr = _s4_target("panel")
        if not target:
            return False, terr
        local = os.path.join(tmpd, obj)
        rc, _, err = run(["rclone", "--config", conf, "copyto",
                          "%s/%s" % (target, obj), local], timeout=300)
        if rc != 0 or not os.path.isfile(local):
            return False, aerr("api.err.mega.dl", v=(err or "rc=%s" % rc)[:150])
        if os.path.getsize(local) > 200 * 1024 * 1024:
            return False, "api.err.arch.big"
        with open(local, "rb") as f:
            raw = f.read()
        # sidecar: اگر هست باید عیناً بخواند؛ اگر نیست فقط هشدار می‌دهیم
        rc, out, _ = run(["rclone", "--config", conf, "cat",
                          "%s/%s.sha256" % (target, obj)], timeout=60)
        remote_sha = (out or "").strip().split()[0] if rc == 0 and out else ""
        if remote_sha:
            local_sha = hashlib.sha256(raw).hexdigest()
            if local_sha != remote_sha:
                return False, aerr("api.err.mega.sha", got=local_sha[:12],
                                   want=remote_sha[:12])
            ok_key = "api.ok.restore.parts.sha"
        else:
            ok_key = "api.ok.restore.parts.nosha"
        return restore_from_nightly_tar(raw, components, ok_key)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
        with _manual_backup_lock:
            CLOUD_RESTORE.update(running=False)


def backup_full_status():
    """وضعیتِ کاملِ پشتیبان‌گیری برای پنل — سیاست: بکاپ فقط روی MEGA می‌ماند.
    stateِ آخرین آپلودِ تأییدشده + فهرستِ ریموتِ هر دو prefix + یونیت‌های
    systemd؛ فایلِ محلی فقط به‌عنوانِ «باقی‌مانده‌ی موقت» گزارش می‌شود."""
    bstate = _backup_state()
    archives = []
    for label, key, path in (
            ("پنل", "panel", "/var/backups/wg-panel/latest.tar.gz"),
            ("سرور (کامل)", "full",
             FULL_BACKUP_DIR + "/latest.tar.gz")):
        a = {"label": label, "path": path, "exists": False, "size": 0,
             "mtime": None, "stale": True, "kept": 0, "dir_bytes": 0,
             "remote": bstate.get(key) or {}}
        try:
            st = os.stat(path)
            a.update(exists=True, size=st.st_size, mtime=st.st_mtime,
                     stale=(time.time() - st.st_mtime) >= 36 * 3600,
                     sha256=_file_sha256_cached(path))
        except OSError:
            pass
        try:
            d = os.path.dirname(path)
            fs = [f for f in os.listdir(d) if f.endswith(".tar.gz")]
            a["kept"] = len(fs)
            a["dir_bytes"] = sum(os.path.getsize(os.path.join(d, f))
                                 for f in fs)
        except OSError:
            pass
        archives.append(a)
    units = []
    for label, unit in (("بکاپِ محلیِ پنل", "wg-panel-backup"),
                        ("بکاپِ کاملِ سرور", FULL_BACKUP_UNIT),
                        ("آپلود به MEGA S4", "wg-panel-s4-upload"),
                        ("راستی‌آزماییِ بکاپ", "wg-panel-verify-backup")):
        sp = _unit_props(unit + ".service",
                         ("ExecMainExitTimestamp", "ExecMainStatus",
                          "Result"))
        tp = _unit_props(unit + ".timer", ("NextElapseUSecRealtime",))
        units.append({
            "label": label, "unit": unit,
            "last": _sysd_ts(sp.get("ExecMainExitTimestamp")),
            "ok": sp.get("Result") == "success"
                  and sp.get("ExecMainStatus", "0") in ("0", ""),
            "result": sp.get("Result", ""),
            "next": _sysd_ts(tp.get("NextElapseUSecRealtime"))})
    return {"archives": archives, "units": units,
            # نامِ یونیتِ بکاپِ کامل به کلاینت داده می‌شود تا JS مجبور نباشد
            # سخت‌کدش کند — وگرنه نامِ این استقرار در PAGE_HTML و در نتیجه
            # داخلِ ایمیجِ Docker می‌ماند.
            "full_unit": FULL_BACKUP_UNIT,
            "s4": _s4_remote_status(),
            "s4_full": _s4_remote_status(which="full")}


# ---- پشتیبان‌گیریِ دستی (اجرای همان jobهای شبانه به درخواستِ کاربر)
# سرویس‌ها Type=oneshot اند، پس systemctl start تا پایانِ اجرا بلاک می‌شود و
# کدِ خروج همان نتیجهٔ jobِ واقعی است — هیچ منطقِ بکاپِ دوم/موازی نمی‌سازیم.
MANUAL_BACKUP_JOBS = {
    # which -> (برچسب، [(برچسبِ مرحله، یونیت، timeout)])
    "panel": ("بکاپِ پنل", [
        ("ساختِ آرشیوِ پنل", "wg-panel-backup.service", 600),
        ("آپلود به MEGA S4", "wg-panel-s4-upload.service", 1800)]),
    # بکاپِ کامل خودش آپلود می‌کند (اسکریپتِ <FULL_BACKUP_NAME>-backup.sh)
    "full": ("بکاپِ کاملِ سرور", [
        ("ساخت و آپلودِ بکاپِ کامل (~۸۰۰MB)",
         FULL_BACKUP_UNIT + ".service", 3600)]),
}
MANUAL_BACKUP = {"running": False, "which": "", "label": "", "step": "",
                 "started": 0.0, "by": "", "finished": 0.0, "result": "",
                 "error": ""}
_manual_backup_lock = threading.Lock()


def start_manual_backup(which, by):
    """شروعِ پشتیبان‌گیریِ دستی در نخِ پس‌زمینه → (ok، خطا)."""
    job = MANUAL_BACKUP_JOBS.get(which)
    if not job:
        return False, "api.err.bktype"
    label, steps = job
    with _manual_backup_lock:
        if MANUAL_BACKUP["running"]:
            return False, aerr("api.err.bk.busy.v", v=MANUAL_BACKUP["label"])
        if CLOUD_RESTORE["running"]:
            return False, "api.err.restore.cloud.busy"
        MANUAL_BACKUP.update(running=True, which=which, label=label,
                             step=steps[0][0], started=time.time(), by=by,
                             finished=0.0, result="", error="")

    def _worker():
        err = ""
        try:
            for step_label, unit, tmo in steps:
                with _manual_backup_lock:
                    MANUAL_BACKUP["step"] = step_label
                rc, _, e = run(["systemctl", "start", unit], timeout=tmo)
                if rc != 0:
                    err = "%s: %s" % (step_label, (e or "rc=%s" % rc)[:150])
                    break
        except Exception as ex:
            err = repr(ex)[:150]
        # لاگ/هشدار پیش از برداشتنِ قفلِ running — تا «تمام شد» یعنی واقعاً
        # همه‌چیز (شاملِ هشدار) انجام شده و اجرایِ بعدی هم زودتر شروع نشود
        log_action("manual backup %s by %s -> %s"
                   % (which, by, err or "ok"))
        audit(by, "settings", "bk.manual", label,
              err or adet("ui.audit.det.done"), "", not err)
        if err:
            ALERTS.event("backup",
                         A('alert.worker.1', p0=label, p1=err))
        with _manual_backup_lock:
            MANUAL_BACKUP.update(running=False, finished=time.time(),
                                 result="err" if err else "ok", error=err,
                                 step="")

    threading.Thread(target=_worker, daemon=True).start()
    return True, ""


def manual_backup_state():
    with _manual_backup_lock:
        return dict(MANUAL_BACKUP)


class SpeedTester:
    """تستِ سرعتِ Ookla (speedtest -s <id>) روی همه‌ی اینترفیس‌های آدرس‌دار.
    فقط به درخواستِ کاربر اجرا می‌شود (هیچ زمان‌بندی‌ای ندارد)؛ اجراها
    ترتیبی‌اند و نتایج (موفق/ناموفق) در جدولِ speedtest می‌مانند (۶ ماه).
    HOME=/tmp چون سرویسِ پنل ProtectHome دارد و ookla به HOME می‌نویسد."""

    def __init__(self):
        self.lock = threading.Lock()
        self.state = {"running": False, "cancel": False, "current": "",
                      "done": 0, "total": 0, "started": 0.0, "by": ""}

    @staticmethod
    def server_id():
        try:
            return int(CONFIG.get("speedtest_server") or 3744)
        except (TypeError, ValueError):
            return 3744

    @staticmethod
    def ifaces():
        """اینترفیس‌های هدفِ تست. اگر config کلیدِ speedtest_ifaces (لیست)
        داشته باشد فقط همان‌ها (طبقِ خواستِ کاربر: فقط awg1)؛ وگرنه همه‌ی
        اینترفیس‌های دارای آدرس به‌جز lo. اینترفیسِ خواسته‌شده حتی اگر
        موجود نباشد هم تست می‌شود تا خطایش ثبت و دیده شود."""
        allowed = [str(x) for x in (CONFIG.get("speedtest_ifaces") or []) if x]
        rc, out, _e = run(["ip", "-br", "addr", "show"], timeout=10)
        names = []
        if rc == 0:
            for ln in out.splitlines():
                parts = ln.split()
                if len(parts) >= 3 and parts[0] != "lo":
                    names.append(parts[0].split("@")[0])
        if allowed:
            return [i for i in allowed if i in names] or allowed
        return names

    def start(self, actor=""):
        with self.lock:
            if self.state["running"]:
                return False
            self.state.update(running=True, cancel=False, current="",
                              done=0, total=0, started=time.time(),
                              by=actor)
        threading.Thread(target=self._worker, daemon=True).start()
        return True

    def cancel(self):
        self.state["cancel"] = True

    AUTO_EVERY = 12 * 3600   # دو بار در شبانه‌روز
    BACKUP_HOURS = (3, 4, 5)   # پنجره‌ی بکاپ/آپلودِ MEGA — تست بی‌معنا می‌شود

    @classmethod
    def in_backup_window(cls, hour=None):
        """ساعت‌های بکاپِ شبانه (۰۳ تا ۰۶) — اجرای خودکار عقب می‌افتد تا
        آپلود/دانلودِ ۳۰۰MB بکاپ نتیجه‌ی تست را خراب نکند."""
        h = datetime.now().hour if hour is None else hour
        return h in cls.BACKUP_HOURS

    def auto_due(self):
        """آیا موعدِ اجرای خودکار رسیده؟ (۱۲ ساعت از آخرین تستِ ثبت‌شده —
        اجرای دستی هم پنجره را جلو می‌برد تا بیش از دو بار در روز نشود؛
        داخلِ پنجره‌ی بکاپِ شبانه هرگز.)"""
        if self.state["running"] or self.in_backup_window():
            return False
        rows = META.speedtest_recent(1)
        last = rows[0]["ts"] if rows else 0
        return time.time() - last >= self.AUTO_EVERY

    def scheduler(self):
        """حلقه‌ی اجرای خودکار: هر ۵ دقیقه چک، هر ۱۲ ساعت یک اجرا."""
        while True:
            try:
                if self.auto_due():
                    audit("sys:speedtest", "settings", "sp.run.auto",
                          ",".join(self.ifaces()),
                          adet("ui.audit.det.every12h",
                               id=self.server_id()), "", True)
                    self.start(actor=ACTOR_SPEEDTEST)
            except Exception as e:
                log_action("speedtest scheduler error: %r" % e)
            time.sleep(300)

    DROP_RATIO = 0.5   # هشدار اگر از ۵۰٪ میانگینِ ۷روزه کمتر شود
    DROP_MIN_SAMPLES = 3   # حداقل نمونه‌ی قبلی تا نویز هشدارِ کاذب نسازد

    @classmethod
    def drop_alert_text(cls, row):
        """اگر نتیجه‌ی موفقِ جدید نسبت به میانگینِ ۷روزه‌ی همان اینترفیس
        افتِ شدید داشته باشد، متنِ هشدارِ فارسی برمی‌گرداند وگرنه None."""
        if not row.get("ok"):
            return None
        avg_dn, avg_up, n = META.speedtest_avg(row["iface"], days=7,
                                               before_ts=row["ts"])
        if n < cls.DROP_MIN_SAMPLES:
            return None
        drops = []
        for key, new, avg in (("alert.speed.dir.down", row.get("down_bps"), avg_dn),
                              ("alert.speed.dir.up", row.get("up_bps"), avg_up)):
            if avg and new is not None and new < avg * cls.DROP_RATIO:
                drops.append(A('alert.speed.drop.part',
                               p0=A(key),
                               p1=_fa_num("%.0f" % (new / 1e6)),
                               p2=_fa_num("%.0f" % (avg / 1e6)),
                               p3=_fa_num("%.0f" % (100 - new / avg * 100))))
            # توجه: مقایسه فقط با تست‌های موفقِ قبلی است (avg بدونِ ردیفِ جاری)
        if not drops:
            return None
        return A('alert.speed.drop', p0=row["iface"], p1="، ".join(drops))

    # ۱۷ اکتبر ۲۰۲۶: سرورِ ookla ‏(۳۷۴۴) تستِ دوم و سومِ یک رشته‌ی پشت‌سرهم را
    # با «Cannot read:» رد می‌کرد — هر اینترفیسی که اول بود سالم درمی‌آمد
    # (دستی: awg4 ✓ ⇐ awg3 ✗؛ awg3 ✓ ⇐ awg1 ✗). پس فاصله بینِ اینترفیس‌ها و
    # یک تلاشِ دوباره برای همین خطا؛ هر دو انتظار با «لغو» قطع می‌شوند.
    GAP_SECONDS = 30
    RETRY_DELAY = 60
    RETRY_ERRORS = ("Cannot read",)

    def _wait(self, seconds):
        """انتظارِ لغوپذیر؛ True یعنی لغو شد."""
        end = time.time() + seconds
        while time.time() < end:
            if self.state["cancel"]:
                return True
            time.sleep(min(1.0, max(0.0, end - time.time())))
        return bool(self.state["cancel"])

    def _one_with_retry(self, iface, sid):
        row = self._one(iface, sid)
        if row.get("ok") or not any(e in (row.get("error") or "")
                                    for e in self.RETRY_ERRORS):
            return row
        log_action("speedtest %s: %s — retry in %ds"
                   % (iface, row.get("error"), self.RETRY_DELAY))
        if self._wait(self.RETRY_DELAY):
            return row
        return self._one(iface, sid)

    def _worker(self):
        try:
            ifs = self.ifaces()
            self.state["total"] = len(ifs)
            sid = self.server_id()
            for n, iface in enumerate(ifs):
                if self.state["cancel"]:
                    break
                if n and self._wait(self.GAP_SECONDS):
                    break
                self.state["current"] = iface
                try:
                    row = self._one_with_retry(iface, sid)
                    warn = self.drop_alert_text(row)
                    META.speedtest_add(row)
                    if warn:
                        ALERTS.event("speedtest", warn)
                except Exception as e:
                    log_action("speedtest save error (%s): %r" % (iface, e))
                self.state["done"] = n + 1
        except Exception as e:
            log_action("speedtest worker error: %r" % e)
        finally:
            self.state["running"] = False
            self.state["current"] = ""

    @staticmethod
    def _parse_result(stdout):
        """آخرین خطِ jsonِ type=result از خروجیِ ookla، وگرنه None."""
        data = None
        for ln in (stdout or "").splitlines():
            ln = ln.strip()
            if not ln.startswith("{"):
                continue
            try:
                d = json.loads(ln)
            except ValueError:
                continue
            if d.get("type") == "result":
                data = d
        return data

    @classmethod
    def _one(cls, iface, sid):
        row = {"ts": time.time(), "iface": iface, "server_id": sid,
               "ping_ms": None, "down_bps": None, "up_bps": None,
               "ok": 0, "error": ""}
        env = dict(os.environ, HOME="/tmp")
        try:
            p = subprocess.run(
                ["speedtest", "-s", str(sid), "-I", iface, "-f", "json",
                 "--accept-license", "--accept-gdpr"],
                capture_output=True, text=True, timeout=150, env=env)
        except subprocess.TimeoutExpired:
            row["error"] = "مهلتِ تست تمام شد"
            return row
        except OSError as e:
            row["error"] = "speedtest اجرا نشد: %s" % e
            return row
        data = cls._parse_result(p.stdout)
        if data:
            # bandwidth در خروجیِ ookla بایت‌برثانیه است → bit/s
            row.update(
                ok=1,
                ping_ms=(data.get("ping") or {}).get("latency"),
                jitter_ms=(data.get("ping") or {}).get("jitter"),
                loss_pct=data.get("packetLoss"),
                url=(data.get("result") or {}).get("url") or "",
                down_bps=((data.get("download") or {}).get("bandwidth")
                          or 0) * 8,
                up_bps=((data.get("upload") or {}).get("bandwidth")
                        or 0) * 8)
        else:
            tail = [l for l in ((p.stderr or "") + "\n"
                                + (p.stdout or "")).splitlines() if l.strip()]
            row["error"] = (tail[-1] if tail else "بدونِ خروجی")[:160]
        return row


SPEEDTEST = SpeedTester()


def build_digest_text():
    """خلاصه‌ی وضعیت (دایجستِ روزانه/هفتگی و /digest). راست‌چین با RLM،
    ارقامِ فارسی، بخش‌بندیِ روشن، بدونِ ایموجی."""
    R = "‏"                        # RLM — راست‌چینِ قطعیِ هر خط
    c = alert_cfg()
    s = build_stats()
    users = s.get("users", [])
    online = sum(1 for u in users if u.get("online"))
    meta = META.meta_all()
    px = META.proxy_users()
    month = META.proxy_month_totals(datetime.now().strftime("%Y-%m"))
    px_active = sum(1 for u in px if u.get("enabled")
                    and not u.get("auto_disabled"))
    soon = datetime.now() + timedelta(days=c["expiry_days"])
    exp_hits = []       # (نوع, نام, تاریخ)
    for u in users:
        e = (meta.get((u["iface"], u["name"]), {}).get("expires") or "").strip()
        if e:
            try:
                if datetime.now() <= datetime.strptime(e, "%Y-%m-%d") <= soon:
                    exp_hits.append((A("alert.kind.wg"), u["name"], e))
            except ValueError:
                pass
    for u in px:
        e = (u.get("expires") or "").strip()
        if e:
            try:
                if datetime.now() <= datetime.strptime(e, "%Y-%m-%d") <= soon:
                    exp_hits.append((A("alert.kind.px"), u["username"], e))
            except ValueError:
                pass
    cur = SYSMON.snapshot().get("cur", {})
    lang = alert_lang()
    fa = lang in LANG_FA_DIGITS
    # RLM فقط برای زبانِ راست‌به‌چپ؛ در en/ru/zh خطوط چپ‌چین می‌مانند
    R = R if LANG_DIR.get(lang) == "rtl" else ""

    def n(x):
        return _fa_num(x) if fa else str(x)

    def pct(k):
        v = cur.get(k)
        return (n("%.0f" % v) + ("٪" if fa else "%")) \
            if isinstance(v, (int, float)) else "—"

    def kv(label, value):        # «برچسب: مقدارِ پررنگ»
        return R + "%s <b>%s</b>" % (label, value)

    def head(t_):
        return R + "<b>%s</b>" % t_

    now = datetime.now()
    jy, jm, jd = _greg_to_jalali(now.year, now.month, now.day)
    L = [head(A("alert.digest.title")),
         "<code>%s</code>" % esc_html(_host_label())]
    if fa:
        L.append(R + A("alert.digest.jalali",
                       p0=n("%04d/%02d/%02d" % (jy, jm, jd)),
                       p1=n(now.strftime("%H:%M"))))
    L += [R + A("alert.digest.greg", p0=n(now.strftime("%Y-%m-%d")),
                p1=n(now.strftime("%H:%M"))),
          "",
          head(A("alert.kind.wg")),
          kv(A("alert.digest.users"), n(len(users))),
          kv(A("alert.digest.online"), n(online)),
          "",
          head(A("alert.kind.px")),
          kv(A("alert.digest.users"), n(len(px))),
          kv(A("alert.digest.active"), n(px_active)),
          kv(A("alert.digest.monthuse"), n(fmt_bytes_srv(sum(month.values())))),
          "",
          head(A("alert.digest.server")),
          kv(A("alert.digest.cpu"), pct("cpu")),
          kv(A("alert.digest.ram"), pct("ram")),
          kv(A("alert.digest.disk"), pct("disk")),
          "",
          head(A("alert.digest.backup"))]
    for label, ago, stale in _backup_status():
        L.append(kv(label + ":", n(ago) + (("  (%s)" % A("alert.digest.stale"))
                                           if stale else "")))
    # آخرین تستِ سرعتِ موفقِ هر اینترفیسِ هدف (بخشِ تست سرعتِ پنل)
    sp_seen = set()
    for r in META.speedtest_recent(60):
        if not r["ok"] or r["iface"] in sp_seen:
            continue
        sp_seen.add(r["iface"])
        if r["iface"] in SPEEDTEST.ifaces():
            L.append(kv(A("alert.digest.speed", p0=r["iface"]),
                        n("↓%.0f / ↑%.0f Mbit/s"
                          % (r["down_bps"] / 1e6, r["up_bps"] / 1e6))
                        + " · " + _ago_srv(r["ts"])))
    L.append("")
    if exp_hits:
        L.append(head(A("alert.digest.expiring", p0=n(c["expiry_days"]))))
        for kind, name, date in exp_hits[:12]:
            L.append(R + "%s · <code>%s</code> · <code>%s</code>"
                     % (kind, esc_html(name), n(date)))
        if len(exp_hits) > 12:
            L.append(R + A("alert.digest.more", p0=n(len(exp_hits) - 12)))
    else:
        L.append(kv(A("alert.digest.expiring0"), A("alert.digest.nobody")))
    return "\n".join(L)


def _decode_chunked(body):
    out = bytearray()
    i = 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(body[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if n == 0:
            break
        out += body[j + 2:j + 2 + n]
        i = j + 2 + n + 2
    return bytes(out)


def _https_raw_over_iface(host, port, request_bytes, iface, timeout):
    """درخواستِ خامِ HTTPS با bind اختیاری به اینترفیس (دور زدنِ فیلتر از تونل).
    برمی‌گرداند (status_code, body_bytes) یا استثنا پرتاب می‌کند."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if iface:
            raw.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE,
                           (iface + "\0").encode())
        raw.settimeout(timeout)
        raw.connect((host, port))
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.sendall(request_bytes)
        chunks = []
        while True:
            b = sock.recv(8192)
            if not b:
                break
            chunks.append(b)
        sock.close()
        data = b"".join(chunks)
        head, _, body = data.partition(b"\r\n\r\n")
        status = 0
        first = head.split(b"\r\n", 1)[0].split(b" ")
        if len(first) >= 2 and first[1].isdigit():
            status = int(first[1])
        if b"transfer-encoding: chunked" in head.lower():
            body = _decode_chunked(body)
        return status, body
    finally:
        try:
            raw.close()
        except OSError:
            pass


# ---- لایه‌ی مشترکِ Telegram Bot API (GET/POST-JSON/multipart، از تونل) ----
TG_HOST = "api.telegram.org"


# آخرین مسیری که به تلگرام رسید، اول امتحان می‌شود: روی سروری که مسیرِ
# مستقیم بلک‌هول است، بدونِ این هر پیام timeout ِ کاملِ مسیرِ مستقیم را
# می‌خورد (۲۰–۴۵ ثانیه) و بعد به تونل می‌رفت.
_TG_LAST_OK = {"iface": None}


def tg_iface_candidates(explicit=""):
    """مسیرهای خروجِ نامزد: اگر explicit داده شده اول آن، وگرنه اول مسیرِ
    آخرین موفقیت، بعد مستقیم، بعد تونل‌های خروجیِ فعال (wg2x معمولاً
    ECMPِ دورزنِ فیلتر)."""
    if explicit:
        return [explicit, ""]
    tuns = [i for i in list_tunnel_confs() if systemd_state(i) == "active"]
    tuns.sort(key=lambda x: (not x.startswith("wg2"), x))
    order = [""] + tuns
    last = _TG_LAST_OK["iface"]
    if last is not None and last in order:
        order.remove(last)
        order.insert(0, last)
    return order


TG_MAX_MESSAGE = 4096


_TG_TAG_RE = re.compile(r"<(/?)([a-zA-Z][\w-]*)[^>]*>")


def _tg_safe_cut(line, limit, html):
    """جای برشِ خطِ بلند در ≤ limit — در HTML نه وسطِ تگ یا &entity;."""
    if not html:
        return limit
    cut = limit
    lt, gt = line.rfind("<", 0, cut), line.rfind(">", 0, cut)
    if lt > gt:                                  # وسطِ یک تگ
        cut = lt
    amp, semi = line.rfind("&", 0, cut), line.rfind(";", 0, cut)
    if amp > semi and cut - amp <= 10:           # وسطِ &amp; و…
        cut = amp
    # تگِ بازِ چسبیده به انتها → تکه‌ای با <b></b> ِ خالی؛ به تکه‌ی بعد برود
    while cut > 0:
        mt = re.search(r"<[a-zA-Z][^<>]*>$", line[:cut])
        if not mt:
            break
        cut = mt.start()
    return cut if cut > 0 else limit


def tg_chunks(text, limit=TG_MAX_MESSAGE - 96, html=False):
    """متنِ بلند را در مرزِ خط به تکه‌های ≤ limit می‌شکند (تلگرام ۴۰۹۶ حرف
    می‌پذیرد و بلندتر را بی‌صدا رد می‌کند).

    html=True (parse_mode=HTML): هر تکه باید به‌تنهایی HTML ِ معتبر باشد.
    برشِ کور وسطِ <pre>…</pre> (کانفیگِ وایرگارد، ممیزیِ نشت، فهرستِ
    تونل‌ها) تکه‌ای با تگِ باز می‌ساخت؛ تلگرام «can't parse entities»
    می‌داد و **کلِ** آن تکه — و در ربات همه‌ی تکه‌های بعدی — نمی‌رسید. حالا
    تگ‌های باز در پایانِ هر تکه بسته و در آغازِ تکه‌ی بعد با همان صفت‌ها
    دوباره باز می‌شوند، و خطِ غول‌پیکر وسطِ تگ یا &entity; بریده نمی‌شود.
    سقفِ تلگرام روی متنِ **پس از** پارسِ تگ‌هاست، پس تگ‌های افزوده از
    بودجه کم نمی‌کنند.
    """
    text = text or ""
    if len(text) <= limit:
        return [text]
    out, cur = [], ""
    for line in text.split("\n"):
        while len(line) > limit:                 # خطِ تکیِ خیلی بلند
            if cur:
                out.append(cur)
                cur = ""
            cut = _tg_safe_cut(line, limit, html)
            out.append(line[:cut])
            line = line[cut:]
        cand = line if not cur else cur + "\n" + line
        if len(cand) > limit:
            out.append(cur)
            cur = line
        else:
            cur = cand
    if cur:
        out.append(cur)
    if not html:
        return out
    balanced, stack = [], []                     # stack: [(name, opening)]
    for part in out:
        head = "".join(o for _n, o in stack)
        for mt in _TG_TAG_RE.finditer(part):
            name = mt.group(2).lower()
            if not mt.group(1):
                stack.append((name, mt.group(0)))
            else:
                for i in range(len(stack) - 1, -1, -1):
                    if stack[i][0] == name:
                        del stack[i:]
                        break
        tail = "".join("</%s>" % n for n, _o in reversed(stack))
        balanced.append(head + part + tail)
    return balanced


def tg_api(token, method, params=None, photo=None, iface="", timeout=20,
           _field="photo", _ctype="image/png"):
    """فراخوانیِ متدِ Bot API. photo=(filename, bytes) → multipart (فیلدِ _field).
    برمی‌گرداند (ok:bool, result_or_error). روی همه‌ی مسیرهای نامزد تلاش می‌کند."""
    if not token:
        return False, "api.err.notoken"
    params = params or {}
    if photo is not None:
        boundary = "----wgp%s" % secrets.token_hex(8)
        parts = bytearray()
        for k, v in params.items():
            parts += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                      % (boundary, k, v)).encode("utf-8")
        fname, fbytes = photo
        parts += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
                  "filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"
                  % (boundary, _field, fname, _ctype)).encode("utf-8")
        parts += fbytes + b"\r\n"
        parts += ("--%s--\r\n" % boundary).encode("utf-8")
        req = ("POST /bot%s/%s HTTP/1.1\r\nHost: %s\r\n"
               "Content-Type: multipart/form-data; boundary=%s\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n"
               % (token, method, TG_HOST, boundary, len(parts))).encode() + bytes(parts)
    else:
        payload = json.dumps(params).encode("utf-8")
        req = ("POST /bot%s/%s HTTP/1.1\r\nHost: %s\r\n"
               "Content-Type: application/json\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n"
               % (token, method, TG_HOST, len(payload))).encode() + payload
    last = "no attempt"
    for ifc in tg_iface_candidates(iface):
        _heartbeat_progress()           # هر مسیر تا timeout طول می‌کشد
        try:
            st, data = _https_raw_over_iface(TG_HOST, 443, req, ifc, timeout)
            try:
                obj = json.loads(data.decode("utf-8", "replace"))
            except ValueError:
                last = "invalid response (HTTP %s)" % st
                continue
            if obj.get("ok"):
                if not iface:
                    _TG_LAST_OK["iface"] = ifc
                return True, obj.get("result")
            last = obj.get("description", "HTTP %s" % st)
            if st == 429:
                # محدودیتِ نرخ: retry_after را رعایت کن و همان مسیر را یک بار
                # دیگر بزن؛ تعویضِ مسیر فقط نرخ را بدتر می‌کند.
                wait = (obj.get("parameters") or {}).get("retry_after", 1)
                try:
                    wait = min(max(int(wait), 1), 30)
                except (TypeError, ValueError):
                    wait = 1
                time.sleep(wait)
                _heartbeat_progress()
                st, data = _https_raw_over_iface(TG_HOST, 443, req, ifc, timeout)
                try:
                    obj = json.loads(data.decode("utf-8", "replace"))
                except ValueError:
                    obj = {}
                if obj.get("ok"):
                    return True, obj.get("result")
                return False, obj.get("description", last)
            # خطای توکن/درخواست/دسترسی (بات بلاک/کیک شده، getUpdates ِ
            # تکراری): تعویضِ مسیر بی‌فایده است
            if st in (400, 401, 403, 404, 409):
                return False, last
        except Exception as e:
            last = "%s%s" % (type(e).__name__, " via %s" % ifc if ifc else "")
            continue
    return False, last


def _rtl_lines(lines):
    """چند خطِ فارسی را به یک پیامِ راست‌چینِ تلگرام تبدیل می‌کند.

    هر خط با RLM (‏) شروع می‌شود تا وجودِ کلمه‌های لاتین (WARP، AI، …)
    جهتِ خط را چپ‌چین نکند. خطِ خالی جداکنندهٔ پاراگراف است و RLM نمی‌گیرد.
    """
    return "\n".join(("‏" + ln) if ln else "" for ln in lines)


class AlertManager:
    """صفِ ارسالِ هشدار + وضعیتِ ضدِتکرار. ارسال در نخِ جدا با retry."""

    API_HOST = "api.telegram.org"

    def __init__(self):
        self.q = queue.Queue(maxsize=200)
        self.state = {}          # کلیدِ رویداد -> وضعیتِ آخر (برای لبه‌یابی)
        self.seen = {}           # کلیدِ رویداد -> آخرین بارِ سنجش (هرس)
        self.lock = threading.Lock()
        self._started = False

    def start(self):
        if self._started:
            return
        self._started = True
        self.load_state()
        threading.Thread(target=self._run, daemon=True).start()

    # وضعیتِ لبه‌ها روی دیسک: بدونِ آن، هر ری‌استارت حافظه را خالی می‌کرد و
    # تونلی که از قبل قطع بود «اولین مشاهده» می‌شد — بی‌صدا — و گذرِ
    # بعدی‌اش هم به‌جای «وصل شد» هیچ می‌گفت.
    def load_state(self):
        try:
            with open(ALERT_EDGES_STATE, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if isinstance(data, dict):
            now = time.time()
            with self.lock:
                for k, v in data.items():
                    if isinstance(k, str) and isinstance(v, bool):
                        self.state.setdefault(k, v)
                        self.seen.setdefault(k, now)   # مهلتِ کامل پس از بوت

    # کلیدی که این مدت سنجیده نشده (تونل/کاربرِ پروکسی/دامنه‌ی حذف‌شده)
    # هرس می‌شود. کلیدها «pxquota:<user>»، «tun:<iface>»، «warp:stale:<dom>»
    # و… از داده‌ی کاربر می‌آیند و پیش از این alert-edges.json را بی‌کران
    # رشد می‌دادند. کلیدِ زنده هر ~۳۰ ثانیه سنجیده می‌شود؛ هفت روز یعنی حتی
    # پنلی که هفته‌ها خاموش بوده چیزی را زودتر از موعد فراموش نمی‌کند (seen
    # پس از بارگذاری از نو شروع می‌شود). بدترین پیامدِ هرسِ اشتباه: اولین
    # مشاهده‌ی بعدی بی‌صداست.
    EDGE_TTL = 7 * 86400

    def save_state(self):
        cutoff = time.time() - self.EDGE_TTL
        with self.lock:
            for k in [k for k, t in self.seen.items() if t < cutoff]:
                self.seen.pop(k, None)
                self.state.pop(k, None)
            data = {k: v for k, v in self.state.items() if isinstance(v, bool)}
        try:
            tmp = ALERT_EDGES_STATE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, ALERT_EDGES_STATE)
        except OSError:
            pass

    def send_now(self, text, iface_override=None, html=False):
        """ارسالِ همگام (برای دکمه‌ی تست). (ok, detail) برمی‌گرداند."""
        c = alert_cfg()
        if not (c["bot_token"] and c["chat_id"]):
            return False, "api.err.tg.unset"
        ifc = c["iface"] if iface_override is None else (iface_override or "")
        for part in tg_chunks(text, html=html):
            p = {"chat_id": c["chat_id"], "text": part,
                 "disable_web_page_preview": True}
            if html:
                p["parse_mode"] = "HTML"
            ok, res = tg_api(c["bot_token"], "sendMessage", p, iface=ifc)
            if not ok:
                return False, aerr("api.err.tg.send", v=res)
        return True, "api.ok.sent"

    def emit(self, text, html=False):
        """صف‌کردنِ هشدار (غیرِمسدودکننده). html=True برای پیام‌های قالب‌دار."""
        if not alert_cfg()["enabled"]:
            return
        try:
            self.q.put_nowait((text, html))
        except queue.Full:
            log_action("alert queue full; dropped")

    def event(self, key, text):
        """هشدارِ یک رویداد، فقط اگر آن دسته روشن باشد."""
        c = alert_cfg()
        if c["enabled"] and c["events"].get(key, True):
            self.emit(text)

    # لبه‌یاب: فقط وقتی وضعیت عوض شد emit کن (ضدِ اسپم)
    def edge(self, key, now_state, text_on_change, category=None):
        """لبه‌یاب. category (اختیاری) = کلیدِ ALERT_EVENTS؛ اگر آن دسته در
        تنظیمات خاموش باشد وضعیت ثبت می‌شود ولی پیامی نمی‌رود. پیش از این
        edge مستقیم emit می‌زد و کلیدهای events.tunnel/events.swap بی‌اثر
        بودند."""
        with self.lock:
            prev = self.state.get(key)
            self.state[key] = now_state
            self.seen[key] = time.time()
        if prev != now_state:
            self.save_state()
        if prev is not None and prev != now_state:
            if category is None:
                self.emit(text_on_change)
            else:
                self.event(category, text_on_change)
        return prev

    def _run(self):
        while True:
            item = self.q.get()
            # سازگاری: هم تاپلِ (text, html) هم رشته‌ی خام را بپذیر
            text, html = item if isinstance(item, tuple) else (item, False)
            for attempt in range(3):
                ok, _ = self.send_now(text, html=html)
                if ok:
                    break
                time.sleep(5 * (attempt + 1))
            else:
                log_action("alert send failed after retries")
            time.sleep(1)  # احترام به محدودیتِ نرخِ تلگرام


ALERTS = AlertManager()


# --------------------------------------- WG-NQMO: خروجیِ meta (PHASE 4، P1)
# موتورِ پایشِ کیفیت (پروسه‌ی جدا، بدونِ CAP_NET_ADMIN) هرچه `wg show` می‌داند
# را فقط از این فایل می‌گیرد. قرارداد: nqmo/collect/meta.py — فیلدها دقیقاً
# همان‌اند و موتور هر سندی را که فیلدِ ناشناخته یا چیزی شبیهِ کلید داشته باشد
# **کامل** رد می‌کند. پس اینجا فقط فیلدهای فهرست‌شده کپی می‌شوند، هرگز psk یا
# کلیدِ خصوصی، و چیزی که پنل با اطمینان ندارد null می‌ماند، نه حدس.
NQMO_META_PATH = "/run/wg-panel/nqmo-meta.json"
NQMO_GROUP = "wg-nqmo"           # بدونِ این گروه (موتور نصب نیست) هیچ فایلی نوشته نمی‌شود
NQMO_META_EVERY = 60
NQMO_LOCAL_IP_EVERY = 600        # آدرسِ WAN به‌ندرت عوض می‌شود: `ip addr` هر ۱۰ دقیقه
_NQMO_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
_NQMO_B64_RE = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=?(?![A-Za-z0-9+/=])")
_NQMO_NAME_RE = re.compile(r"^[^\x00-\x1f]{1,64}$")
_nqmo_state: dict = {"prev_rx": {}, "local_ip": None, "local_ip_ts": 0.0, "last_err": ""}


def nqmo_enabled():
    """پرچمِ config.json → nqmo.enabled؛ پیش‌فرض خاموش."""
    c = CONFIG.get("nqmo")
    return isinstance(c, dict) and c.get("enabled") is True


def _nqmo_int(v, lo, hi):
    """عددِ صحیح در بازه، وگرنه None (موتور مقدارِ بیرون از بازه را رد می‌کند)."""
    if isinstance(v, bool) or v in (None, ""):
        return None
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def _nqmo_tunnel_ip(allowed):
    """نخستین IPv4 ِ ‎/32 در AllowedIPs ِ پیر، یا None."""
    for part in str(allowed or "").split(","):
        net = part.strip()
        if not net.endswith("/32"):
            continue
        try:
            return str(ipaddress.IPv4Address(net[:-3]))
        except ValueError:
            continue
    return None


def _nqmo_sys_mtu(iface):
    try:
        with open("/sys/class/net/%s/mtu" % os.path.basename(iface)) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _nqmo_fwmark(iface):
    """FwMark از کانفیگ (wg-quick جز این fwmark ای روی اینترفیسِ سرور نمی‌گذارد)."""
    try:
        with open(conf_path(iface), encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.lower().startswith("fwmark") and "=" in s:
                    v = s.split("=", 1)[1].split("#")[0].strip()
                    return None if v.lower() in ("off", "0", "") else int(v, 0)
    except (OSError, ValueError):
        pass
    return None


def _nqmo_local_ip(now):
    """آدرسِ IPv4 ِ تنها اینترفیسِ WAN، برای مدل‌کردنِ مسیرِ پاسخ در موتور.
    بیش از یک WAN یا هیچ ⇒ None (حدس نمی‌زنیم)."""
    st = _nqmo_state
    if now - st["local_ip_ts"] < NQMO_LOCAL_IP_EVERY:
        return st["local_ip"]
    st["local_ip_ts"] = now
    wan = []
    try:
        for name, m in iface_meta_all().items():
            addrs = m.get("addresses", [])
            if addrs and classify_iface(name, addrs)[1] == "wan":
                wan.append(addrs[0])
    except Exception:
        wan = []
    st["local_ip"] = wan[0] if len(wan) == 1 else None
    return st["local_ip"]


def _nqmo_ecmp_member(iface):
    """عضوِ فعالِ گروهِ ECMP؟ گارد خاموش یا تونل بیرون از گروه‌ها ⇒ None."""
    try:
        if not ECMPGUARD.enabled():
            return None
        states = [v for (_g, i), v in list(ECMPGUARD.membership.items()) if i == iface]
    except Exception:
        return None
    return ("in" in states) if states else None


def build_nqmo_meta(now=None):
    """سندِ meta، یا None وقتی چیزی که موتور الزامی می‌داند در دست نیست."""
    now = time.time() if now is None else now
    ncfg = CONFIG.get("nqmo")
    if not isinstance(ncfg, dict):
        ncfg = {}
    user_iface = ncfg.get("user_iface") or "wg1udp"
    client_mtu = _nqmo_int(CONFIG.get("client_mtu", 1420), 576, 9000)
    wg_mtu = _nqmo_sys_mtu(user_iface)
    if client_mtu is None or wg_mtu is None:
        return None
    snap = SAMPLER.snapshot()
    live_ifaces = snap.get("ifaces", {})
    live_peers = {(p["iface"], p["public_key"]): p for p in snap.get("peers", [])}
    srv_list = server_ifaces()
    peers = {}
    for srv in srv_list:
        try:
            blocks = parse_user_blocks(srv)
        except OSError:
            continue
        for b in blocks:
            pub, name = b["public_key"], b["name"]
            # یک کلید یا نامِ نامعتبر کلِ سند را در موتور رد می‌کند ⇒ همان پیر کنار می‌رود
            if (not _NQMO_KEY_RE.match(pub) or pub in peers
                    or not _NQMO_NAME_RE.match(name) or _NQMO_B64_RE.search(name)):
                continue
            lp = live_peers.get((srv, pub)) or {}
            meta = SAMPLER.meta_cache.get((srv, name), {})
            ep = lp.get("endpoint") or None
            peers[pub] = {
                "iface": srv, "name": name, "enabled": bool(b["enabled"]),
                "tunnel_ip": _nqmo_tunnel_ip(b["allowed_ips"]),
                "c_mtu": _nqmo_int(meta.get("c_mtu"), 576, 9000),
                "rate_mbit": _nqmo_int(meta.get("rate_mbit"), 0, 100000),
                "endpoint": None if ep == "(none)" else ep,
                "latest_handshake": _nqmo_int(lp.get("handshake"), 0, 1 << 40) or 0,
                "rx_bytes": _nqmo_int(lp.get("rx"), 0, 1 << 62) or 0,
                "tx_bytes": _nqmo_int(lp.get("tx"), 0, 1 << 62) or 0,
            }
    egress = {}
    prev_rx = _nqmo_state["prev_rx"]
    for iface, info in sorted(TUNNELS.get().items()):
        if iface in srv_list:
            continue
        t = tunnel_row(iface, info, live_ifaces, live_peers, with_hist=False)
        if not (t["enabled"] or t["active"]):
            continue                 # تونلِ عمداً خاموش «خرابی» نیست
        rx = int(t["rx"] or 0)
        old = prev_rx.get(iface)
        prev_rx[iface] = rx
        egress[iface] = {
            "kind": t["kind"], "mtu": _nqmo_sys_mtu(iface), "endpoint_dev": None,
            "awg_s4": None,
            "hs_age": int(max(0, now - t["handshake"])) if t["handshake"] else None,
            "rx_delta": (rx - old) if old is not None and rx >= old else None,
            "health": t["health"],
            # این سه منبعِ تک‌مقداری برای هر تونل ندارند (SvcDiag به‌ازای سرویس
            # است و یک سرویسِ مسدود یعنی خرابیِ تونل نیست) ⇒ گزارش نمی‌شوند.
            "svc_ok": None, "svc_latency_ms": None, "mtr_loss": None, "mtr_rtt": None,
            "warp_ms": None,
            "ecmp_member": _nqmo_ecmp_member(iface), "ts": round(now, 3),
        }
    return {"schema": 1, "generated_at": round(now, 3), "client_mtu": client_mtu,
            "wg1udp": {"mtu": wg_mtu, "fwmark": _nqmo_fwmark(user_iface),
                       "local_ip": _nqmo_local_ip(now)},
            "peers": peers, "egress": egress}


def _nqmo_write_meta(doc):
    """نوشتنِ اتمیک با مودِ ‎0640 و گروهِ wg-nqmo (پوشه ‎0750). گروه نیست ⇒ False."""
    try:
        gid = grp.getgrnam(NQMO_GROUP).gr_gid
    except KeyError:
        return False
    d = os.path.dirname(NQMO_META_PATH)
    os.makedirs(d, mode=0o750, exist_ok=True)
    os.chown(d, -1, gid)
    os.chmod(d, 0o750)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".nqmo-meta.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))
        os.chown(tmp, -1, gid)
        os.chmod(tmp, 0o640)
        os.replace(tmp, NQMO_META_PATH)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return True


def nqmo_export_meta(now=None):
    """یک دورِ خروجی؛ پرچم خاموش ⇒ هیچ کاری (نه خواندن، نه نوشتن)."""
    if not nqmo_enabled():
        return False
    doc = build_nqmo_meta(now)
    return _nqmo_write_meta(doc) if doc is not None else False


# --------------------------------------- WG-NQMO: خواندنِ state.json (PHASE 4، P2)
# تنها چیزی که پنل از موتور می‌خوانَد. موتور هر ۶۰ ثانیه آن را اتمیک می‌نویسد
# (nqmo/export.py). نویسنده کاربرِ بی‌امتیازِ wg-nqmo است و پنل root، پس محتوا
# داده‌ی نامطمئن است: فقط فایلِ معمولی، بدونِ دنبال‌کردنِ symlink، با سقفِ اندازه.
# هر شکستی {"available": False, "why": …} است و هرگز استثنا به بالا نمی‌رود.
# ثابت‌ها با موتور هم‌گام‌اند (تستِ NqmoStateReadTests)؛ پنل nqmo را import نمی‌کند.
NQMO_STATE_PATH = "/var/lib/wg-nqmo/state.json"
NQMO_STATE_SCHEMA = 1
NQMO_STATE_TTL = 10              # کشِ خواندن: /metrics و API ها هر بار دیسک را نمی‌زنند
NQMO_STATE_STALE = 180           # سه دورِ خروجیِ موتور
NQMO_STATE_SKEW = 60             # generated_at بیش از این در آینده ⇒ ساعتِ ناهم‌گام
NQMO_STATE_MAX_BYTES = 8 << 20
NQMO_MODES = ("OBSERVATION_ONLY", "DIAGNOSTICS_ENABLED", "RECOMMENDATIONS_ENABLED")
# واژگانِ بسته‌ی why: رابط (P7) برای هرکدام کلیدِ ترجمه دارد
NQMO_STATE_WHY = ("disabled", "missing", "unreadable", "too_large", "corrupt", "schema",
                  "stale", "clock", "error")
_nqmo_state_lock = threading.Lock()
_nqmo_state_cache: dict = {"ts": None, "doc": None, "why": "missing"}


def _nqmo_load_state():
    """(سند, None) یا (None, why). why فقط از واژگانِ ثابتِ زیر است."""
    try:
        fd = os.open(NQMO_STATE_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unreadable"            # از جمله symlink (ELOOP) و نبودِ دسترسی
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "unreadable"        # FIFO نخِ پنل را برای همیشه نگه می‌داشت
        with os.fdopen(fd, "rb") as f:
            fd = None
            raw = f.read(NQMO_STATE_MAX_BYTES + 1)
    except OSError:
        return None, "unreadable"
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) > NQMO_STATE_MAX_BYTES:
        return None, "too_large"
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):     # UnicodeDecodeError زیرکلاسِ ValueError است
        return None, "corrupt"
    if not isinstance(doc, dict):
        return None, "corrupt"
    sc = doc.get("schema")
    if isinstance(sc, bool) or sc != NQMO_STATE_SCHEMA:
        return None, "schema"
    ga = doc.get("generated_at")
    if (isinstance(ga, bool) or not isinstance(ga, (int, float)) or not math.isfinite(ga)
            or doc.get("mode") not in NQMO_MODES):
        return None, "corrupt"
    return doc, None


def nqmo_state(now=None):
    """وضعیتِ موتور برای /metrics، API و هشدار. موفق: کپیِ سطحیِ سند به‌علاوه‌ی
    available=True و age_s. شکست: {"available": False, "why": …}. هرگز raise نمی‌کند."""
    try:
        if not nqmo_enabled():
            return {"available": False, "why": "disabled"}
        now = time.time() if now is None else now
        with _nqmo_state_lock:
            c = _nqmo_state_cache
            if c["ts"] is None or not 0 <= now - c["ts"] < NQMO_STATE_TTL:
                c["doc"], c["why"] = _nqmo_load_state()
                c["ts"] = now
            doc, why = c["doc"], c["why"]
        if doc is None:
            return {"available": False, "why": why}
        age = now - doc["generated_at"]
        if age > NQMO_STATE_STALE:
            return {"available": False, "why": "stale", "age_s": round(age, 1)}
        if age < -NQMO_STATE_SKEW:
            return {"available": False, "why": "clock", "age_s": round(age, 1)}
        return dict(doc, available=True, age_s=round(max(age, 0.0), 1))
    except Exception:
        return {"available": False, "why": "error"}


# ------------------------------------------- WG-NQMO (P4): سری‌های wg_nqmo_* در /metrics
# فقط از nqmo_state() ِ کش‌شده؛ هیچ subprocess ای در زمانِ scrape. هر برچسب از یک
# واژگانِ بسته است (کاردینالیتیِ ثابت، و رشته‌ی موتور هرگز برچسب نمی‌شود). سندِ ۰۵
# سری‌های per-peer (RTT، loss، MTU) هم طرح کرده بود، ولی state.json امروز آن‌ها را
# ندارد؛ عددِ ساختگی صادر نمی‌شود. پرچمِ خاموش ⇒ هیچ سطری (خروجی بایت‌به‌بایت همان).
NQMO_CLASSES = ("EGRESS_TUNNEL_DEGRADATION", "HANDSHAKE_FAILURE", "HANDSHAKE_FLOOD",
                "NAT_OR_FIREWALL_ISSUE", "NETWORK_CONGESTION", "PACKET_LOSS",
                "ROUTING_ANOMALY", "SERVER_RESOURCE_BOTTLENECK", "SUSPECTED_MTU_PROBLEM",
                "SUSPECTED_PMTU_BLACKHOLE", "TRAFFIC_SHAPING_EFFECT", "UDP_INSTABILITY",
                "UNKNOWN_DEGRADATION")
NQMO_COLLECTORS = ("C1_meta", "C2_kernel", "C3_capture")
# سری‌های هر پیر (state.json → peers، nqmo/analysis.peer_summary). دروازه‌های موتور
# این‌جا دوباره سنجیده می‌شوند: عددی که موتور نباید می‌داد، پنل هم صادر نمی‌کند.
NQMO_PEER_QUALITY = {"INSUFFICIENT": -1, "OK": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
NQMO_MTU_STATUS = {"UNDETERMINED": 0, "CANDIDATE_FOR_TESTING": 1, "ESTIMATED": 2,
                   "VERIFIED": 3}
NQMO_RTT_MIN_SAMPLES = 5         # rules.PARAMS["rtt_min_samples"]
NQMO_LOSS_N_MIN = 1000           # rules.PARAMS["loss_n_min"]
NQMO_WINDOW = 300
NQMO_PEER_MAX_AGE = 720          # پایانِ پنجره تا generated_at: دو پنجره + فاصله‌ی اجرا
# معیارِ ارتقا از «فقط مشاهده» (سندِ ۰۱ §۴): دستِ‌کم این‌قدر روز داده و صفر تشخیصِ
# سایه‌ایِ HIGH در هفت روزِ اخیر. موتور promotion را می‌نویسد؛ تصمیم با اپراتور است.
NQMO_PROMOTION_DAYS = 7
# §29.153 — با analysis.py هم‌گام (NqmoStateReadTests.test_constants_follow_the_engine)
NQMO_HISTORY_HOURS = 24          # analysis.HISTORY_HOURS
NQMO_WHY_MAX = 8                 # analysis.WHY_MAX
NQMO_STREAMS = ("S1", "S2", "S4")    # analysis._JUDGED_STREAMS
_NQMO_WHY_RE = re.compile(r"^[A-Za-z0-9_:-]{1,40}$")   # توکنِ quality_why (features._BAD)
NQMO_CORR_CAUSES = ("SERVER", "EGRESS", "UNKNOWN")   # correlate.py: suspected_cause
NQMO_STATUS_ERRORS = 10          # خطاهای اخیرِ موتور که به رابط می‌رسد (موتور ۲۰ تا می‌نویسد)
NQMO_STATUS_THREADS = 8          # سقفِ نخ‌هایی که در «پوشش» نشان داده می‌شوند


def _nqmo_num(v):
    """عددِ متناهیِ غیرِ bool، وگرنه None."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return v if math.isfinite(v) else None


def _nqmo_fresh_peers(st, known):
    """{(iface, name): خلاصه} از state → peers. فقط برچسبی که پنل خودش می‌شناسد
    (بدونِ تزریق و با کاردینالیتیِ محدود)؛ برچسبِ تکراری و پنجره‌ی کهنه کنار
    می‌روند. منبعِ واحد برای /metrics و API."""
    ga = _nqmo_num(st.get("generated_at"))
    peers = st.get("peers")
    if ga is None or not isinstance(peers, list) or not known:
        return {}
    seen, dup = {}, set()
    for p in peers:
        if not isinstance(p, dict):
            continue
        lab = (p.get("iface"), p.get("name"))
        if lab not in known:
            continue
        if lab in seen:
            dup.add(lab)
        seen[lab] = p
    out = {}
    for lab in set(seen) - dup:
        w = _nqmo_num(seen[lab].get("window"))
        if w is not None and -60 <= ga - (w + NQMO_WINDOW) <= NQMO_PEER_MAX_AGE:
            out[lab] = seen[lab]
    return out


def _nqmo_peer_rows(st, known):
    """سری‌های هر پیر (هم‌نام با wg_peer_*)."""
    fresh = _nqmo_fresh_peers(st, known)
    cols = {k: [] for k in ("q", "rtt", "rmin", "rn", "loss", "llo", "lhi", "ln", "mtu")}
    for lab in sorted(fresh):
        p = fresh[lab]
        L = {"iface": lab[0], "name": lab[1]}
        q = p.get("quality")
        if isinstance(q, str) and q in NQMO_PEER_QUALITY:
            cols["q"].append((L, NQMO_PEER_QUALITY[q]))
        mt = p.get("mtu_status")
        if isinstance(mt, str) and mt in NQMO_MTU_STATUS:
            cols["mtu"].append((L, NQMO_MTU_STATUS[mt]))
        rn = p.get("rtt_n")
        if type(rn) is int and rn >= 0:
            cols["rn"].append((L, rn))
            med, mn = _nqmo_num(p.get("rtt_ms_med")), _nqmo_num(p.get("rtt_ms_min"))
            if (rn >= NQMO_RTT_MIN_SAMPLES and med is not None and mn is not None
                    and 0 <= mn <= med):
                cols["rtt"].append((L, round(med / 1000, 4)))
                cols["rmin"].append((L, round(mn / 1000, 4)))
        ln = p.get("loss_n")
        if type(ln) is int and ln >= 0:
            cols["ln"].append((L, ln))
            pt, lo, hi = (_nqmo_num(p.get(k)) for k in ("loss_point", "loss_lb", "loss_ub"))
            if (ln >= NQMO_LOSS_N_MIN and None not in (pt, lo, hi)
                    and 0 <= lo <= pt <= hi <= 1):
                cols["loss"].append((L, pt))
                cols["llo"].append((L, lo))
                cols["lhi"].append((L, hi))
    spec = (("q", "wg_nqmo_peer_quality_state",
             "Worst open live diagnosis (-1 insufficient, 0 ok, 1 low, 2 medium, 3 high)"),
            ("rtt", "wg_nqmo_peer_rtt_seconds",
             "Median handshake round trip, last 15 min (only with >=5 samples)"),
            ("rmin", "wg_nqmo_peer_rtt_min_seconds", "Minimum handshake round trip, last 15 min"),
            ("rn", "wg_nqmo_peer_rtt_samples", "Handshake round-trip samples, last 15 min"),
            ("loss", "wg_nqmo_peer_upstream_loss_ratio",
             "Client-to-server loss, last 5 min (only with >=1000 judged packets)"),
            ("llo", "wg_nqmo_peer_upstream_loss_lower_ratio", "Wilson 95% lower bound"),
            ("lhi", "wg_nqmo_peer_upstream_loss_upper_ratio", "Wilson 95% upper bound"),
            ("ln", "wg_nqmo_peer_upstream_loss_judged_packets",
             "Data packets judged for loss, last 5 min"),
            ("mtu", "wg_nqmo_peer_mtu_status",
             "Client MTU status (0 undetermined, 1 candidate, 2 estimated, 3 verified)"))
    return [(name, help_, "gauge", cols[k]) for k, name, help_ in spec if cols[k]]


def nqmo_metric_rows(st, known=frozenset()):
    """[(name, help, type, rows)] برای build_metrics. known: {(iface, name)} ِ
    پیرهای خودِ پنل. هرگز raise نمی‌کند."""
    if st.get("why") == "disabled":
        return []
    out: list = [("wg_nqmo_up", "WG-NQMO state is fresh and valid (1/0)", "gauge",
            [({}, int(st.get("available") is True))])]
    if st.get("available") is not True:
        why = st.get("why") if st.get("why") in NQMO_STATE_WHY else "error"
        out.append(("wg_nqmo_unavailable", "Why the WG-NQMO state is not usable", "gauge",
                    [({"why": why}, 1)]))
        return out
    try:
        age = _nqmo_num(st.get("age_s"))
        if age is not None:
            out.append(("wg_nqmo_state_age_seconds", "Age of the engine state file",
                        "gauge", [({}, age)]))
        out.append(("wg_nqmo_mode", "Engine mode (1 = current)", "gauge",
                    [({"mode": md}, int(st.get("mode") == md)) for md in NQMO_MODES]))
        col = st.get("collectors") if isinstance(st.get("collectors"), dict) else {}
        out.append(("wg_nqmo_collector_ok", "Engine collector healthy (1/0; absent = off)",
                    "gauge", [({"collector": c}, int(col[c])) for c in NQMO_COLLECTORS
                              if type(col.get(c)) is bool]))
        diags = st.get("diagnoses") if isinstance(st.get("diagnoses"), list) else []
        cnt = dict.fromkeys(NQMO_CLASSES, 0)
        for d in diags:
            c = d.get("class") if isinstance(d, dict) else None
            if isinstance(c, str) and c in cnt:
                cnt[c] += 1
        out.append(("wg_nqmo_diagnoses_open", "Open live diagnoses by class", "gauge",
                    [({"class": c}, n) for c, n in cnt.items()]))
        cov = st.get("coverage") if isinstance(st.get("coverage"), dict) else {}
        for key, name, help_ in (("peers_total", "wg_nqmo_peers", "Peers the engine knows"),
                                 ("peers_handshake_180s", "wg_nqmo_active_peers",
                                  "Peers with a handshake in the last 180s")):
            v = _nqmo_num(cov.get(key))
            if v is not None:
                out.append((name, help_, "gauge", [({}, v)]))
        errs = st.get("errors")
        if isinstance(errs, list):
            out.append(("wg_nqmo_recent_errors", "Engine errors kept in the state (last 20)",
                        "gauge", [({}, len(errs))]))
        eng = _nqmo_status_engine(cov)
        if eng is not None:
            if eng["cpu_pct"] is not None:
                out.append(("wg_nqmo_engine_cpu_percent", "Engine CPU over the last minute",
                            "gauge", [({}, eng["cpu_pct"])]))
            if eng["rss_mb"] is not None:
                out.append(("wg_nqmo_engine_rss_bytes", "Engine resident memory", "gauge",
                            [({}, int(eng["rss_mb"] * 1024 * 1024))]))
            if eng["sampling"] is not None:
                out.append(("wg_nqmo_engine_sampling", "Header capture in sampling rotation "
                            "because CPU crossed the cap (1/0)", "gauge",
                            [({}, int(eng["sampling"]))]))
        sto = st.get("store") if isinstance(st.get("store"), dict) else {}
        mb = _nqmo_num(sto.get("size_mb"))
        if mb is not None:
            out.append(("wg_nqmo_store_bytes", "Engine database size", "gauge",
                        [({}, int(mb * 1024 * 1024))]))
        if type(sto.get("read_only")) is bool:
            out.append(("wg_nqmo_store_read_only", "Engine database is read-only (1/0)",
                        "gauge", [({}, int(sto["read_only"]))]))
        out += _nqmo_peer_rows(st, known)
    except Exception:
        pass
    return out


# ------------------------------------------- WG-NQMO (P5): API و ctl.sock
# خواندن فقط از nqmo_state() (سندِ نامطمئن ⇒ فیلدها با فهرستِ سفید و پاک‌شده)؛
# فرمان (ack، probe، mode) فقط از ctl.sock ِ خودِ موتور، که uid ِ ۰ را می‌پذیرد و
# همه‌ی گیت‌ها را خودش دوباره می‌سنجد. prefix و ASN فقط در correlation ها و
# شواهدِ کامل‌اند ⇒ فقط با nqmo.detail.
NQMO_CTL_PATH = "/run/wg-nqmo/ctl.sock"
NQMO_CTL_TIMEOUT = 7.0           # موتور خودش پس از ۵ ثانیه TIMEOUT برمی‌گرداند
NQMO_CTL_MAX = 64 * 1024
# واژگانِ بسته‌ی refused: کدهای موتور (ctl.py، analysis.request_probe) و چهار کدِ پنل
NQMO_REFUSALS = (
    "BAD_VERSION", "UNKNOWN_OP", "BAD_FIELDS", "BAD_ACTOR", "BAD_MODE", "BAD_ID",
    "BAD_PEER", "NOT_ADJACENT", "NO_SUCH_OPEN_DIAGNOSIS", "NOT_AVAILABLE", "BUSY",
    "TIMEOUT", "TOO_LARGE", "BAD_JSON", "INTERNAL", "MODE_GATE", "FLAG_GATE",
    "META_STALE", "NO_SUCH_PEER", "PEER_NOT_PROBEABLE", "STALE_HS", "RATE",
    "UNREACHABLE", "NO_REPLY", "BAD_REPLY", "AMBIGUOUS_PEER", "UNKNOWN")
NQMO_LEVELS = ("INSUFFICIENT_EVIDENCE", "LOW", "MEDIUM", "HIGH")
NQMO_SCOPES = ("PEER", "GLOBAL", "EGRESS")
NQMO_DATA_QUALITY = ("GOOD", "DEGRADED", "INVALID")
NQMO_EVENTS_MAX = 200
_NQMO_KEY_OK = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_NQMO_REC_KEYS = ("target", "current_value", "current_source", "suggested_value", "status",
                  "direction_scope", "rationale", "limitations")


def _nqmo_clean(v, depth=0):
    """کپیِ JSON ِ امن از داده‌ی نامطمئن: رشته بی‌کاراکترِ کنترلی/bidi و ≤۲۰۰،
    عددِ متناهی، کلیدِ لاتینِ کوتاه، عمق ≤۴ و طولِ ≤۵۰."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v if -(1 << 53) <= v <= 1 << 53 else None
    if isinstance(v, float):
        return v if math.isfinite(v) else None
    if isinstance(v, str):
        return _NQMO_TXT_BAD.sub("", v)[:200]
    if depth >= 4:
        return None
    if isinstance(v, list):
        return [_nqmo_clean(x, depth + 1) for x in v[:50]]
    if isinstance(v, dict):
        return {k: _nqmo_clean(x, depth + 1) for k, x in list(v.items())[:40]
                if isinstance(k, str) and _NQMO_KEY_OK.match(k)}
    return None


def _nqmo_pick(v, vocab):
    return v if isinstance(v, str) and v in vocab else None


def _nqmo_label(v):
    """نامِ پیر/اینترفیس/موضوع از سند: رشته‌ی پاک‌شده و کوتاه، وگرنه None."""
    return _nqmo_clean(v)[:64] if isinstance(v, str) else None


def nqmo_panel_peers():
    """{(iface, name)} ِ پیرهای خودِ پنل — همان مجموعه‌ای که P1 به موتور می‌دهد."""
    out = set()
    for srv in server_ifaces():
        try:
            for b in parse_user_blocks(srv):
                out.add((srv, b["name"]))
        except OSError:
            continue
    return out


def nqmo_pick_peer(known, name, iface=None):
    """(iface, name) یا None. بدونِ iface، نام باید در پنل یکتا باشد."""
    if not isinstance(name, str) or not 0 < len(name) <= 64:
        return None
    hits = [lab for lab in known if lab[1] == name
            and (iface is None or lab[0] == iface)]
    return hits[0] if len(hits) == 1 else None


def _nqmo_evidence(ev, detail):
    if not isinstance(ev, list):
        return []
    if detail:
        return [_nqmo_clean(e) for e in ev[:20] if isinstance(e, dict)]
    out = []
    for e in ev[:20]:
        if not isinstance(e, dict) or not isinstance(e.get("metric"), str):
            continue
        val = e.get("value")
        if isinstance(val, list):
            val = [x for x in val[:4] if _nqmo_num(x) is not None]
        elif _nqmo_num(val) is None:
            continue                       # فقط عدد؛ رشته‌ی شاهد ممکن است prefix باشد
        out.append({"metric": _nqmo_label(e["metric"]), "value": val})
    return out


def _nqmo_diag(d, detail):
    """یک تشخیصِ باز برای API، یا None."""
    if not isinstance(d, dict):
        return None
    cls, scope = _nqmo_pick(d.get("class"), NQMO_CLASSES), _nqmo_pick(d.get("scope"), NQMO_SCOPES)
    did = d.get("id")
    if cls is None or scope is None or type(did) is not int or did <= 0:
        return None
    out = {"id": did, "class": cls, "scope": scope,
           "confidence": _nqmo_pick(d.get("confidence"), NQMO_LEVELS),
           "since": _nqmo_num(d.get("since")),
           "last_window_end": _nqmo_num(d.get("last_window_end")),
           "data_quality": _nqmo_pick(d.get("data_quality"), NQMO_DATA_QUALITY),
           "acked_by": _nqmo_label(d.get("acked_by")),
           "evidence": _nqmo_evidence(d.get("evidence"), detail)}
    if scope == "PEER":
        out["peer"], out["iface"] = _nqmo_label(d.get("peer")), _nqmo_label(d.get("iface"))
    else:
        out["subject"] = _nqmo_label(d.get("subject"))
    if detail:
        out["counter_evidence"] = _nqmo_clean(d.get("counter_evidence"))
        out["alternatives"] = _nqmo_clean(d.get("alternatives"))
    return out


def _nqmo_diags(st, detail):
    ds = st.get("diagnoses")
    return [x for x in (_nqmo_diag(d, detail) for d in (ds if isinstance(ds, list) else []))
            if x is not None]


def _nqmo_series(v, n, lo, hi):
    """آرایه‌ی تاریخچه: دقیقاً n خانه، هر خانه عددِ متناهی در [lo, hi] یا None.
    طولِ غلط یا نوعِ غلط ⇒ None (کلِ سری کنار می‌رود، نه نصفش)."""
    if not isinstance(v, list) or len(v) != n:
        return None
    out = []
    for x in v:
        if x is None:
            out.append(None)
            continue
        x = _nqmo_num(x)
        if x is None or not lo <= x <= hi:
            return None
        out.append(x)
    return out


def _nqmo_history(h):
    """peers[].history ِ موتور (analysis._history): دو سریِ ساعتیِ هم‌طول یا None."""
    if not isinstance(h, dict):
        return None
    rtt = _nqmo_series(h.get("rtt_ms"), NQMO_HISTORY_HOURS, 0, 60000)
    loss = _nqmo_series(h.get("loss"), NQMO_HISTORY_HOURS, 0, 1)
    end = _nqmo_num(h.get("end"))
    if rtt is None or loss is None or end is None:
        return None
    return {"end": end, "rtt_ms": rtt, "loss": loss}


def _nqmo_summary(p):
    out = {}
    for k in ("rtt_n", "loss_n"):
        out[k] = p.get(k) if type(p.get(k)) is int and p.get(k) >= 0 else 0
    for k in ("window", "rtt_ms_med", "rtt_ms_min", "loss_point", "loss_lb", "loss_ub"):
        out[k] = _nqmo_num(p.get(k))
    if out["rtt_n"] < NQMO_RTT_MIN_SAMPLES:
        out["rtt_ms_med"] = out["rtt_ms_min"] = None
    lo, pt, hi = out["loss_lb"], out["loss_point"], out["loss_ub"]
    if (out["loss_n"] < NQMO_LOSS_N_MIN or None in (lo, pt, hi)
            or not 0 <= lo <= pt <= hi <= 1):       # type: ignore[operator]
        out["loss_point"] = out["loss_lb"] = out["loss_ub"] = None
    out["quality"] = _nqmo_pick(p.get("quality"), NQMO_PEER_QUALITY)
    out["mtu_status"] = _nqmo_pick(p.get("mtu_status"), NQMO_MTU_STATUS)
    # §29.153: چرا عددی غایب است (کیفیتِ هر جریانِ داوری‌شده و توکن‌های quality_why)
    # و تاریخچه‌ی ساعتی. توکن از واژگانِ بازِ موتور است ⇒ فقط شکلِ لاتینِ کوتاه.
    st = p.get("streams") if isinstance(p.get("streams"), dict) else {}
    out["streams"] = {s: _nqmo_pick(st.get(s), NQMO_DATA_QUALITY) for s in NQMO_STREAMS}
    why = p.get("why") if isinstance(p.get("why"), list) else []
    out["why"] = sorted({w for w in why[:NQMO_WHY_MAX]
                         if isinstance(w, str) and _NQMO_WHY_RE.match(w)})
    out["history"] = _nqmo_history(p.get("history"))
    return out


def _nqmo_bool(v):
    return v if type(v) is bool else None


def _nqmo_count(v):
    """شمارِ صحیحِ نامنفی، وگرنه None (bool و float عمداً رد می‌شوند)."""
    return v if type(v) is int and 0 <= v <= 1 << 53 else None


def _nqmo_status_threads(cov):
    """{نام: سالم؟} از coverage.threads ِ موتور — فقط نامِ پاک و مقدارِ bool،
    با سقفِ NQMO_STATUS_THREADS (هر نخ یک چیپ در رابط است)."""
    th = cov.get("threads")
    out = {}
    if not isinstance(th, dict):
        return out
    for name, info in list(th.items())[:NQMO_STATUS_THREADS]:
        lab = _nqmo_label(name)
        if not lab or not isinstance(info, dict):
            continue
        ok = _nqmo_bool(info.get("healthy"))
        if ok is not None:
            out[lab] = ok
    return out


def _nqmo_status_errors(st, detail):
    """خطاهای اخیرِ موتور (engine._err): زمان و محلِ هرکدام برای همه؛ متنِ خطا
    (می‌تواند مسیرِ فایل یا جزئیاتِ درونی داشته باشد) فقط با nqmo.detail."""
    errs = st.get("errors")
    out = []
    if not isinstance(errs, list):
        return out
    for e in reversed(errs[-50:]):           # تازه‌ترین‌ها؛ ورودیِ خراب جای یکی را نمی‌گیرد
        if len(out) >= NQMO_STATUS_ERRORS:
            break
        if not isinstance(e, dict):
            continue
        row = {"ts": _nqmo_num(e.get("ts")), "where": _nqmo_label(e.get("where"))}
        if row["where"] is None:
            continue
        if detail:
            row["error"] = _nqmo_label(e.get("error")) or ""
        out.append(row)
    out.reverse()                            # صعودی مثلِ خودِ موتور
    return out


def _nqmo_status_promotion(st):
    """آمادگیِ ارتقا از analysis.shadow_stats: روزهای داده و شمارِ تشخیص‌های
    سایه‌ایِ HIGH در هفت روزِ اخیر (جمعِ همه‌ی پیرها، بدونِ نامِ پیر)."""
    pr = st.get("promotion")
    if not isinstance(pr, dict):
        return None
    days = _nqmo_num(pr.get("data_days"))
    by = pr.get("shadow_high_by_peer_7d")
    high = None
    if isinstance(by, dict):
        counts = [_nqmo_count(v) for v in by.values()]
        high = sum(c for c in counts if c is not None) if counts else 0
    if days is None and high is None:
        return None
    return {"data_days": None if days is None else round(max(days, 0.0), 2),
            "shadow_high_7d": high, "days_required": NQMO_PROMOTION_DAYS}


def _nqmo_status_engine(cov):
    """هزینه‌ی خودِ موتور (engine.task_export → coverage.engine)."""
    e = cov.get("engine")
    if not isinstance(e, dict):
        return None
    out = {"cpu_pct": _nqmo_num(e.get("cpu_pct")), "rss_mb": _nqmo_num(e.get("rss_mb")),
           "cpu_pct_max": _nqmo_num(e.get("cpu_pct_max")),
           "sampling": _nqmo_bool(e.get("sampling"))}
    for k in ("cpu_pct", "cpu_pct_max"):
        if out[k] is not None and not 0 <= out[k] <= 100:
            out[k] = None
    if out["rss_mb"] is not None and out["rss_mb"] < 0:
        out["rss_mb"] = None
    return out


def _nqmo_corr_summary(st):
    """شمارشِ همبستگی‌ها بدونِ prefix و ASN (برای همه، نه فقط nqmo.detail):
    شمارِ گروه، دستگاه‌های فعال و متأثر، و علتِ مظنون از واژگانِ بسته."""
    corr = st.get("correlations")
    if not isinstance(corr, list):
        return None
    groups = active = affected = 0
    causes = set()
    for c in corr[:50]:
        if not isinstance(c, dict):
            continue
        groups += 1
        active += _nqmo_count(c.get("active_peers")) or 0
        affected += _nqmo_count(c.get("affected_peers")) or 0
        cause = c.get("suspected_cause")
        if isinstance(cause, str):
            cause = cause.split(":", 1)[0]            # «EGRESS:awg1,awg3» ⇒ EGRESS
            if cause in NQMO_CORR_CAUSES:
                causes.add(cause)
    return {"groups": groups, "active_peers": active, "affected_peers": affected,
            "causes": sorted(causes)}


def nqmo_status_doc(st, detail, known):
    """/api/nqmo/status"""
    if st.get("available") is not True:
        why = st.get("why") if st.get("why") in NQMO_STATE_WHY else "error"
        return {"available": False, "why": why}
    col = st.get("collectors") if isinstance(st.get("collectors"), dict) else {}
    cov = st.get("coverage") if isinstance(st.get("coverage"), dict) else {}
    sto = st.get("store") if isinstance(st.get("store"), dict) else {}
    asn = cov.get("asn") if isinstance(cov.get("asn"), dict) else {}
    probe = st.get("probe") if isinstance(st.get("probe"), dict) else None
    diags = _nqmo_diags(st, detail)
    fresh = _nqmo_fresh_peers(st, known)
    peers = []
    for lab in sorted(known):
        mine = [d for d in diags if d["scope"] == "PEER"
                and (d.get("iface"), d.get("peer")) == lab]
        row = {"iface": lab[0], "name": lab[1], "open": len(mine),
               "top_class": None, "top_confidence": None}
        if mine:
            top = max(mine, key=lambda d: NQMO_LEVELS.index(d["confidence"])
                      if d["confidence"] else -1)
            row["top_class"], row["top_confidence"] = top["class"], top["confidence"]
        if lab in fresh:
            row.update(_nqmo_summary(fresh[lab]))
        if lab in fresh or mine:
            peers.append(row)
    adv = st.get("advisories") if isinstance(st.get("advisories"), list) else []
    out = {"available": True, "mode": _nqmo_pick(st.get("mode"), NQMO_MODES),
           "age_s": _nqmo_num(st.get("age_s")),
           "generated_at": _nqmo_num(st.get("generated_at")),
           # غایب ≠ خاموش: فقط کلیدی که موتور نوشته (None یعنی capture خاموش)
           "collectors": {c: col[c] for c in NQMO_COLLECTORS
                          if c in col and (col[c] is None or type(col[c]) is bool)},
           "coverage": {"peers_total": _nqmo_num(cov.get("peers_total")),
                        "peers_active": _nqmo_num(cov.get("peers_handshake_180s")),
                        "capture_enabled": _nqmo_bool(cov.get("capture_enabled")),
                        # جزئیاتِ پوشش (engine.task_export): چرا C1 قرمز است، چند
                        # endpoint مبهم یا بی‌مدل مانده، کدام نخ ناسالم است
                        "meta_age_s": _nqmo_num(cov.get("meta_age_s")),
                        # متنِ خطا مسیرِ فایل دارد؛ به رابط فقط «هست/نیست» می‌رسد
                        "meta_error": (bool(cov.get("meta_error"))
                                       if isinstance(cov.get("meta_error"), str) else None),
                        "ambiguous_endpoints": _nqmo_count(cov.get("ambiguous_endpoints")),
                        "unmodelled_endpoints": _nqmo_count(cov.get("unmodelled_endpoints")),
                        "threads": _nqmo_status_threads(cov),
                        "asn_stale": _nqmo_bool(asn.get("stale")),
                        "engine": _nqmo_status_engine(cov)},
           "correlation_summary": _nqmo_corr_summary(st),
           "store": {"size_mb": _nqmo_num(sto.get("size_mb")),
                     "read_only": _nqmo_bool(sto.get("read_only")),
                     "recreated": _nqmo_bool(sto.get("recreated"))},
           # پنجره‌ی تحلیلِ بسته‌شده (آغازش)؛ generated_at زمانِ نوشتنِ state است
           "last_window": _nqmo_num(st.get("last_window")),
           "probe": None if probe is None else {
               "running": _nqmo_bool(probe.get("running")) is True,
               "run_id": probe["run_id"] if type(probe.get("run_id")) is int
               and probe["run_id"] > 0 else None},
           "promotion": _nqmo_status_promotion(st),
           "errors": _nqmo_status_errors(st, detail),
           "global": [d for d in diags if d["scope"] != "PEER"],
           "advisories": [_nqmo_clean(a) for a in adv[:50]
                          if isinstance(a, dict) and a.get("scope") == "SERVER_TUNNEL"],
           "peers": peers, "detail": bool(detail)}
    if detail:
        out["correlations"] = _nqmo_clean(st.get("correlations"))
        out["groups_eligible"] = _nqmo_num(st.get("groups_eligible"))
    return out


def nqmo_peer_doc(st, lab, detail, known):
    """/api/nqmo/peer — یک پیرِ شناخته‌شده‌ی پنل."""
    out = {"iface": lab[0], "name": lab[1]}
    if st.get("available") is not True:
        why = st.get("why") if st.get("why") in NQMO_STATE_WHY else "error"
        out.update(available=False, why=why)
        return out
    fresh = _nqmo_fresh_peers(st, known)
    out["available"] = True
    out["summary"] = _nqmo_summary(fresh[lab]) if lab in fresh else None
    out["diagnoses"] = [d for d in _nqmo_diags(st, detail) if d["scope"] == "PEER"
                        and (d.get("iface"), d.get("peer")) == lab]
    recs = st.get("recommendations") if isinstance(st.get("recommendations"), dict) else {}
    items = recs.get("%s/%s" % lab)
    out["recommendations"] = [{k: _nqmo_clean(r.get(k)) for k in _NQMO_REC_KEYS}
                              for r in (items if isinstance(items, list) else [])[:10]
                              if isinstance(r, dict)]
    # advisory فقط نامِ پیر را دارد، نه iface ⇒ فقط وقتی نام در پنل یکتاست
    unique = sum(1 for k in known if k[1] == lab[1]) == 1
    adv = st.get("advisories") if isinstance(st.get("advisories"), list) else []
    out["advisories"] = [_nqmo_clean(a) for a in adv[:50] if unique and isinstance(a, dict)
                         and a.get("scope") == "PEER" and a.get("peer") == lab[1]]
    return out


def nqmo_events(st, since, limit, detail, known):
    """/api/nqmo/events — تاریخچه از notify_outbox (باز، تشدید، بسته)، صعودی از since."""
    if st.get("available") is not True:
        return []
    box = st.get("notify_outbox")
    out = []
    for e in sorted((e for e in (box if isinstance(box, list) else [])
                     if isinstance(e, dict) and type(e.get("id")) is int and e["id"] > since),
                    key=lambda e: e["id"]):
        kind = _nqmo_pick(e.get("text_key"), NQMO_NOTIFY_KEYS)
        p = e.get("params") if isinstance(e.get("params"), dict) else {}
        if kind is None:
            continue
        row = {"id": e["id"], "ts": _nqmo_num(e.get("ts")), "kind": kind.rsplit(".", 1)[1],
               "severity": _nqmo_pick(e.get("severity"), NQMO_NOTIFY_SEVERITIES + ("DIGEST",)),
               "class": _nqmo_pick(p.get("class"), NQMO_CLASSES),
               "confidence": _nqmo_pick(p.get("confidence"), NQMO_LEVELS),
               "scope": _nqmo_pick(p.get("scope"), NQMO_SCOPES),
               "stale": p.get("stale") is True}
        if row["scope"] == "PEER":
            lab = (p.get("iface"), p.get("peer"))
            if lab not in known:
                continue
            row["iface"], row["peer"] = lab
        elif row["scope"] is not None:
            row["subject"] = _nqmo_label(p.get("subject"))
        if detail:
            row["evidence"] = _nqmo_evidence(p.get("evidence"), True)
        out.append(row)
        if len(out) >= limit:
            break
    return out


def nqmo_ctl(req):
    """یک درخواست به ctl.sock ِ موتور. پاسخ همیشه dict ِ پاک‌شده است:
    {"ok": True, ...} یا {"ok": False, "refused": <کد از NQMO_REFUSALS>}."""
    s = None
    data = b""
    connected = False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(NQMO_CTL_TIMEOUT)
        s.connect(NQMO_CTL_PATH)
        connected = True
        s.sendall(json.dumps(req, separators=(",", ":")).encode() + b"\n")
        while b"\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > NQMO_CTL_MAX:
                return {"ok": False, "refused": "BAD_REPLY"}
    except socket.timeout:
        return {"ok": False, "refused": "TIMEOUT"}
    except OSError:
        # پس از connect، بستنِ بی‌پاسخِ موتور روی لینوکس ریست است (ECONNRESET/EPIPE،
        # چون درخواستِ ما خوانده‌نشده مانده) و روی مک EOF؛ هر دو یعنی NO_REPLY ِ پایین
        if not connected:
            return {"ok": False, "refused": "UNREACHABLE"}
        data = b""
    finally:
        if s is not None:
            s.close()
    if not data:
        # موتور اتصالِ uid ِ غیرِ ۰ را بی‌پاسخ می‌بندد (SO_PEERCRED): «پنل root نیست»
        # با «پاسخِ خراب» یکی نیست
        return {"ok": False, "refused": "NO_REPLY"}
    try:
        r = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
    except (ValueError, RecursionError):
        return {"ok": False, "refused": "BAD_REPLY"}
    if not isinstance(r, dict) or type(r.get("ok")) is not bool:
        return {"ok": False, "refused": "BAD_REPLY"}
    if not r["ok"]:
        code = r.get("refused")
        return {"ok": False, "refused": code if code in NQMO_REFUSALS else "UNKNOWN"}
    out = {"ok": True}
    if r.get("mode") in NQMO_MODES:
        out["mode"] = r["mode"]
    if type(r.get("run_id")) is int:
        out["run_id"] = r["run_id"]
    return out


# ------------------------------------------- WG-NQMO (P3): صندوقِ رویدادها → تلگرام
# dedup، cooldown، سقفِ نرخ و ACK کارِ موتور است (nqmo/diagnose.py)؛ پنل فقط
# شناسه‌های تازه‌تر از آخرین ارسال را می‌فرستد. شناسه AUTOINCREMENT ِ sqlite است.
# متن از کاتالوگِ خودِ پنل ساخته می‌شود: text_key ِ موتور فقط از فهرستِ بسته
# انتخاب می‌کند و هیچ رشته‌ای از سند مستقیم به پیام نمی‌رود مگر پاک‌شده و کوتاه.
NQMO_NOTIFIED_STATE = "/opt/wg-panel/nqmo-notified.last"
NQMO_NOTIFY_BURST = 6            # سقفِ پیام در هر چرخه (هم‌اندازه‌ی سقفِ ساعتیِ موتور)
NQMO_NOTIFY_SEVERITIES = ("HIGH", "MEDIUM", "INFO")   # DIGEST و LOW هرگز پیام نمی‌شوند
NQMO_NOTIFY_KEYS = ("nqmo.alert.open", "nqmo.alert.escalated", "nqmo.alert.cleared",
                    "nqmo.alert.more")
_NQMO_TXT_MAX = 64
_NQMO_TXT_BAD = re.compile(r"[\x00-\x1f\x7f‎‏‪-‮⁦-⁩]")


def _nqmo_txt(v):
    """مقدارِ نامطمئنِ سند ⇒ رشته‌ی کوتاهِ بی‌کاراکترِ کنترلی. ناشناخته ⇒ «?»."""
    if isinstance(v, bool) or v is None:
        return "?"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return ("%.4g" % v) if math.isfinite(v) else "?"
    if not isinstance(v, str):
        return "?"
    v = _NQMO_TXT_BAD.sub("", v).strip()
    return (v[:_NQMO_TXT_MAX] + "…") if len(v) > _NQMO_TXT_MAX else (v or "?")


def nqmo_alert_text(ev):
    """یک ورودیِ notify_outbox ⇒ متنِ پیام، یا None اگر نباید فرستاده شود."""
    sev, key = ev.get("severity"), ev.get("text_key")
    if sev not in NQMO_NOTIFY_SEVERITIES or key not in NQMO_NOTIFY_KEYS:
        return None
    if key == "nqmo.alert.more":
        return A('alert.nqmo.more')
    p = ev.get("params")
    if not isinstance(p, dict):
        return None
    cls = _nqmo_txt(p.get("class"))
    if p.get("scope") == "PEER":
        who = _nqmo_txt(p.get("peer"))
        if isinstance(p.get("iface"), str):
            who += " (%s)" % _nqmo_txt(p["iface"])
    else:
        who = "%s %s" % (_nqmo_txt(p.get("scope")), _nqmo_txt(p.get("subject")))
    if key == "nqmo.alert.cleared":
        if p.get("stale") is True:
            return A('alert.nqmo.stale', p0=cls, p1=who)
        return A('alert.nqmo.cleared', p0=cls, p1=who)
    evs = p.get("evidence")
    lines = []
    for e in (evs if isinstance(evs, list) else [])[:3]:
        if isinstance(e, dict):
            lines.append("• %s = %s" % (_nqmo_txt(e.get("metric")), _nqmo_txt(e.get("value"))))
    icon = "🔴" if sev == "HIGH" else "🟠"
    if key == "nqmo.alert.escalated":
        return A('alert.nqmo.escalated', p0=icon, p1=cls, p2=who, p3="\n".join(lines))
    return A('alert.nqmo.open', p0=icon, p1=cls, p2=who, p3=_nqmo_txt(p.get("confidence")),
             p4="\n".join(lines))


def _host_label():
    """نامِ نمایشیِ سرور در ربات/هشدار/دایجست.
    اولویت: server_label (نامِ دلخواه، مثل MYVPN) → server_host → hostname."""
    return (CONFIG.get("server_label") or CONFIG.get("server_host")
            or socket.gethostname())


class AlertMonitor(threading.Thread):
    """هر ~۳۰ ثانیه شرایطِ هشدار را می‌سنجد و از راهِ ALERTS emit می‌کند.
    از داده‌ی نخ‌های موجود (TUNNELS/SYSMON/SAMPLER/META) استفاده می‌کند تا
    بارِ اضافه نسازد."""

    INTERVAL = 30
    # سنجش‌های گران (چند subprocess/DNS) هر چند دقیقه، نه هر ۳۰ ثانیه
    SLOW_EVERY = {"warp:split": 300, "warp:ech": 900, "net:leak": 300,
                  "nqmo:meta": NQMO_META_EVERY}

    def __init__(self):
        super().__init__(daemon=True)
        self._sustain = {}       # منبع -> شمارشِ نمونه‌های پیاپیِ بالای آستانه
        self._slow_last = {}     # کلیدِ سنجشِ گران -> آخرین اجرا

    def _due(self, key):
        """True اگر سنجشِ گرانِ key موعدش رسیده (و همان‌جا ثبت می‌شود)."""
        now = time.time()
        if now - self._slow_last.get(key, 0) < self.SLOW_EVERY.get(key, 0):
            return False
        self._slow_last[key] = now
        return True

    def run(self):
        # مهلتِ کوتاه تا نخ‌های داده اولین نمونه‌ها را بگیرند
        time.sleep(20)
        while True:
            _heartbeat("alertmon")
            # WG-NQMO (P1): بیرون از شرطِ هشدارها و در try ِ خودش، تا نه خاموش‌بودنِ
            # هشدارها جلویش را بگیرد و نه خطای یک سنجشِ دیگر
            try:
                if self._due("nqmo:meta"):
                    nqmo_export_meta()
                _nqmo_state["last_err"] = ""
            except Exception as e:
                msg = "nqmo meta error: %r" % e
                if msg != _nqmo_state["last_err"]:    # یک خط برای هر خطای تازه، نه هر دقیقه
                    log_action(msg)
                _nqmo_state["last_err"] = msg
            try:
                # P3: بیرون از شرطِ enabled تا شناسه هنگامِ خاموشیِ هشدارها هم جلو برود
                # و روشن‌کردنشان صفِ کهنه را یک‌جا نفرستد (ALERTS.event خودش گیت دارد)
                self._check_nqmo()
            except Exception as e:
                log_action("nqmo notify error: %r" % e)
            try:
                # پایشِ تونل‌ها مستقل از روشن‌بودنِ هشدارهاست تا گذرِ
                # قطع/وصل همیشه در audit ثبت شود (نشانگرهای روی گراف)؛
                # خودِ ارسالِ پیام داخل ALERTS پشتِ enabled می‌ماند.
                self._check_tunnels()
                # گزارشِ تصویری mode مستقلِ خودش را دارد (پشتِ enabled نیست)
                self._check_report()
                if alert_cfg()["enabled"]:
                    self._check_resources()
                    self._check_swap()
                    self._check_expiry()
                    self._check_warp()
                    self._check_digest()
            except Exception as e:
                log_action("alert monitor error: %r" % e)
            time.sleep(self.INTERVAL)

    def _digest_mark(self, today):
        """ثبتِ «برای امروز تمام شد» — هم در حافظه هم روی دیسک.
        بدونِ فایل، بعد از هر restartِ پنل (مثلاً هنگامِ استقرار) حافظه
        خالی می‌شد و اگر ساعت از digest_time گذشته بود، خلاصه *دوباره*
        ارسال می‌شد — کاربر بعد از هر استقرار یک «خلاصهٔ وضعیت» اضافه
        می‌گرفت (همان کلاسِ باگِ حافظه‌ی در-RAMِ گاردِ ECMP)."""
        self._digest_last = today
        try:
            tmp = DIGEST_STATE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(today + "\n")
            os.replace(tmp, DIGEST_STATE)
        except OSError:
            pass

    def _check_digest(self):
        """خلاصه‌ی روزانه/هفتگی در ساعتِ مقرر، یک‌بار در هر دوره."""
        c = alert_cfg()
        if not c["digest_enabled"]:
            return
        nowdt = datetime.now()
        today = nowdt.strftime("%Y-%m-%d")
        last = getattr(self, "_digest_last", "")
        if not last:
            # بعد از restart از فایل بخوان تا دایجستِ امروز تکرار نشود
            try:
                with open(DIGEST_STATE, encoding="utf-8") as f:
                    last = f.read().strip()
            except OSError:
                pass
            self._digest_last = last
        if last == today:
            return
        try:
            hh, mm = (int(x) for x in str(c["digest_time"]).split(":")[:2])
        except (ValueError, TypeError):
            hh, mm = 9, 0
        if (nowdt.hour, nowdt.minute) < (hh, mm):
            return
        # هفتگی: فقط شنبه‌ها (weekday()==5)
        if c["digest_weekly"] and nowdt.weekday() != 5:
            self._digest_mark(today)    # امروز رد شد؛ دوباره امتحان نکن
            return
        # ساختنِ متن می‌تواند شکست بخورد (فایلِ وضعیتِ بکاپِ خراب و…)؛ روز
        # فقط بعد از **صف‌شدنِ** پیام ثبت می‌شود، وگرنه دایجستِ آن روز گم
        # می‌شد. بینِ تلاش‌های ناموفق ۱۰ دقیقه فاصله تا لاگ رگبار نشود.
        if getattr(self, "_digest_retry_at", 0) > time.time():
            return
        try:
            text = build_digest_text()
        except Exception as e:
            log_action("digest error: %r" % e)
            self._digest_retry_at = time.time() + 600
            return
        self._digest_mark(today)
        ALERTS.emit(text, html=True)

    def _report_mark(self, today):
        self._report_last = today
        try:
            tmp = REPORT_STATE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(today + "\n")
            os.replace(tmp, REPORT_STATE)
        except OSError:
            pass

    def _check_report(self):
        """گزارشِ تصویریِ روزانه/هفتگی در ساعتِ مقرر — یک‌بار در هر روزِ
        واجد؛ ضدِتکرار روی دیسک (همان الگوی digest ضدِ ارسالِ دوباره بعد
        از restart)."""
        rc = report_cfg()
        if rc["mode"] == "off":
            return
        c = alert_cfg()
        if not (c["bot_token"] and c["chat_id"]):
            return
        nowdt = datetime.now()
        today = nowdt.strftime("%Y-%m-%d")
        last = getattr(self, "_report_last", "")
        if not last:
            try:
                with open(REPORT_STATE, encoding="utf-8") as f:
                    last = f.read().strip()
            except OSError:
                pass
            self._report_last = last
        if last == today:
            return
        try:
            hh, mm = (int(x) for x in str(rc["time"]).split(":")[:2])
        except (TypeError, ValueError):
            hh, mm = 10, 0
        if (nowdt.hour, nowdt.minute) < (hh, mm):
            return
        if rc["mode"] == "weekly" and nowdt.weekday() != rc["dow"]:
            self._report_mark(today)    # امروز روزِ گزارش نیست
            return
        self._report_mark(today)
        threading.Thread(target=send_periodic_report, daemon=True).start()

    def _check_tunnels(self):
        for iface, info in TUNNELS.get().items():
            st = info.get("systemd", "")
            good = st in ("active", "activating")
            # از کاتالوگ، نه رشته‌ی درجا: این دو تا سال‌ها از گاردِ AST
            # رد می‌شدند چون به متغیر نسبت داده می‌شدند نه اینکه داخلِ
            # خودِ فراخوانی بنشینند.
            msg = (A('alert.tunnel.up', p0=iface) if good
                   else A('alert.tunnel.down', p0=iface, p1=st))
            prev = ALERTS.edge("tun:" + iface, good, msg, category="tunnel")
            if prev is not None and prev != good:
                # ثبتِ گذر برای نشانگرِ رویداد/باندِ قطعی روی گراف تونل
                audit("sys:monitor", "tunnel",
                      "tun.monitor.up" if good else "tun.monitor.down", iface,
                      adet("ui.audit.det.svchealth", state=(st or "?")),
                      ok=good)
            # هشدارِ حلقهٔ مسیریابی (بحرانی): endpoint از داخلِ تونل مسیر می‌خورد
            prev_l = ALERTS.edge(
                "tunloop:" + iface, not info.get("loop"),
                A('alert.check_tunnels.1', p0=iface)
                if not info.get("loop") else
                A('alert.check_tunnels.2', p0=iface, p1=info.get('loop_dev') or '?'),
                category="tunnel")
            if prev_l is not None and prev_l != (not info.get("loop")):
                audit("sys:monitor", "tunnel",
                      "iface.loop.fix" if not info.get("loop")
                      else "iface.loop.found",
                      iface,
                      "" if not info.get("loop")
                      else adet("ui.audit.det.loopvia",
                                dev=(info.get("loop_dev") or "?")),
                      ok=not info.get("loop"))

    def _check_warp(self):
        """سلامتِ مسیریابیِ WARP — فقط اگر نصب/فعال باشد. سه خرابیِ خاموش
        که کاربر بی‌آنکه بداند AI را می‌شکنند:
          - تونلِ wgwarp قطع/بی‌هندشیک شود
          - endpoint از تونلِ ساده به awg1 برگردد (TLS بلک‌هول می‌شود)
          - حساب از unlimited بیفتد
        همه لبه‌یاب: فقط هنگامِ تغییرِ وضعیت خبر می‌دهد."""
        if not alert_cfg()["events"].get("warp", True):
            return
        w = warp_status()
        if not w.get("installed"):
            return
        ifc = w.get("iface") or {}
        # ۱) سلامتِ تونل: بالا + هندشیکِ تازه (< ۱۸۰ث، مثل بقیهٔ تونل‌ها)
        age = ifc.get("handshake_age")
        alive = bool(ifc.get("up")) and age is not None and age < 180
        ALERTS.edge("warp:tunnel", alive,
                    A('alert.check_warp.1')
                    if alive else
                    A('alert.check_warp.2'))
        # ۲) خروج باید از تونلِ موردانتظار (wg22) باشد نه awg1 — وگرنه TLS
        #    بلک‌هول می‌شود ولی تونل «سالم» به‌نظر می‌رسد
        eg_ok = (not w.get("egress_actual")) or (not w.get("egress_want")) \
            or w.get("egress_actual") == w.get("egress_want")
        ALERTS.edge("warp:egress", eg_ok,
                    A('alert.check_warp.3')
                    if eg_ok else
                    A('alert.check_warp.4', p0=w.get('egress_actual'), p1=w.get('egress_want'), p2=w.get('egress_want')))
        # ۳) نوعِ حساب — افت از unlimited (لبه‌یاب فقط وقتی قبلاً unlimited بود)
        acct = (w.get("account") or "").lower()
        if acct:
            ALERTS.edge("warp:account", acct == "unlimited",
                        A('alert.check_warp.7')
                        if acct == "unlimited" else
                        A('alert.check_warp.8', p0=acct))
        # ۴) تازگیِ sync — تایمر هر ۱۵ دقیقه است؛ مهرِ کهنه‌تر از ۴۵ دقیقه
        #    (۳ دورِ پیاپیِ ناموفق) یعنی sync در حلقه‌ی خرابیِ خاموش است —
        #    دقیقاً کلاسِ باگِ کش که هفته‌ها می‌توانست دیده نشود.
        age_s = warp_sync_age()
        fresh = age_s is not None and age_s < 2700
        ALERTS.edge("warp:sync", fresh,
                    A('alert.check_warp.5')
                    if fresh else
                    A('alert.check_warp.6'))
        # ۵) کهنگیِ per-domain — سیاستِ fail-open: sync بلوک‌های کهنه را
        #    دیگر حذف نمی‌کند (حذفِ ۲۴ساعته‌ی قبلی = قطعیِ کاربر)؛ به‌جایش
        #    اینجا برای هر دامنه‌ای که >۲۴ ساعت resolve نشده هشدار می‌دهیم.
        nowt = time.time()
        for dh in (w.get("domain_health") or []):
            dom = dh.get("domain") or ""
            if not dom:
                continue
            last = dh.get("last")
            dok = last is not None and (nowt - last) < 86400
            ALERTS.edge("warp:stale:" + dom, dok,
                        A('alert.check_warp.9', p0=dom)
                        if dok else
                        A('alert.check_warp.10', p0=dom))
        # ۶) probe دوره‌ایِ سطحِ اپلیکیشن (هر ۱۰ دقیقه، فقط وقتی تونل
        #    سالم است — وگرنه هشدارِ تونل کافی است و probe فقط نویز
        #    و curlِ بیهوده اضافه می‌کرد)
        if alive and nowt - _WARP_PROBE["ts"] >= WARP_PROBE_INTERVAL:
            p = warp_probe_run()
            with _WARP_PROBE_LOCK:
                prev_loc = (_WARP_PROBE.get("trace") or {}).get("loc", "")
                _WARP_PROBE.update(p)
            tr = p["trace"]
            net_ok = bool(tr.get("warp"))
            ALERTS.edge("warp:probe-net", net_ok,
                        A('alert.check_warp.11')
                        if net_ok else
                        A('alert.check_warp.12'))
            if net_ok:
                code = p["gemini"]
                gok = code in ("200", "301", "302")
                # از کاتالوگ: این دو داخلِ IfExp پاس می‌شدند، پس حتی
                # فهرست‌کردنِ آرگومان‌های سطحِ اولِ فراخوانی هم پیداشان
                # نمی‌کرد — گاردِ درون‌تابعیِ گسترده گرفتشان.
                if code in ("403", "429"):
                    gmsg = A('alert.warp.gemini.throttled', p0=code)
                else:
                    gmsg = A('alert.warp.gemini.unreachable',
                             p0=(code or A('alert.warp.gemini.noresp')))
                ALERTS.edge("warp:probe-gemini", gok,
                            A('alert.check_warp.15')
                            if gok else gmsg)
                loc = tr.get("loc", "")
                if prev_loc and loc and loc != prev_loc:
                    warp_event("country", "%s → %s" % (prev_loc, loc), "probe")
                    ALERTS.event("warp",
                                 A('alert.check_warp.18', p0=prev_loc, p1=loc))
                # کیفیتِ مسیر: TTFBِ WARP در برابر عادی — «سالم ولی کند»
                wms, dms = p.get("warp_ttfb"), p.get("direct_ttfb")
                warp_latency_record(wms, dms)
                if wms is not None:
                    slow = (wms >= WARP_SLOW_MS and
                            (dms is None or wms >= dms * WARP_SLOW_RATIO))
                    ALERTS.edge("warp:slow", not slow,
                                A('alert.check_warp.19', p0=wms)
                                if not slow else
                                A('alert.check_warp.20', p0=wms, p1='%dms' % dms if dms else A('alert.lit.3')))
        # ۷) کوریِ طبقه‌بندیِ SNI — فقط با splitterِ روشن. fail-safe جریانِ
        #    بی‌SNI را به WARP می‌فرستد (سرویس نمی‌شکند) ولی مصرفِ WARP خاموش
        #    بالا می‌رود. ⚠️ ECH عمداً در این نسبت نیست: شمارنده‌اش GREASEِ
        #    کروم را هم می‌گیرد و با آن ۶۷٪ خوانده می‌شد در حالی که کوریِ
        #    واقعی ۲۴٫۶٪ بود ⇒ هشدار به سیگنالِ دروغ شلیک می‌کرد (§۲۹٫۴۷).
        #    خطرِ واقعیِ ECH را بندِ ۸ می‌پاید، نه این.
        if warp_sni_enabled() and self._due("warp:split"):
            try:
                ser = warp_split_series("24h")
                pts = (ser.get("points") or [])[-6:]     # ~۶ ساعتِ اخیر
                tot = sum(p["ai"] + p["direct"] for p in pts)
                blind = sum(p.get("blind") or 0 for p in pts)
                if tot >= WARP_BLIND_MIN_BYTES:
                    share = 100.0 * blind / tot
                    bok = share < WARP_BLIND_ALERT_PCT
                    ALERTS.edge("warp:blind", bok,
                                A('alert.check_warp.21', p0=share)
                                if bok else
                                A('alert.check_warp.22', p0=share, p1=WARP_BLIND_ALERT_PCT))
            except Exception:
                pass

        # ۸) تله‌ی ECHِ واقعی — تنها لحظه‌ای که طبقه‌بندیِ SNI واقعاً می‌شکند.
        #    بدونِ ECHConfig، ECH ناممکن است؛ پس به‌جای شمردنِ اکستنشن (که
        #    GREASE را هم می‌گیرد) مستقیم می‌پرسیم آیا مقصدی ECHConfig منتشر
        #    کرده. اگر روزی بله، ترافیکِ همان دامنه بی‌صدا «کولترال» طبقه‌بندی
        #    و مستقیم فرستاده می‌شود — و چون کشفِ خودکار هم کور می‌شود، خرابی
        #    خودش را پنهان می‌کند. کش ساعتی است، پس این حلقه DNS را نمی‌کوبد.
        if warp_sni_enabled() and self._due("warp:ech"):
            try:
                hits = warp_ech_publishers(warp_targets_read())
                ALERTS.edge("warp:echconfig", not hits,
                            A('alert.check_warp.16')
                            if not hits else
                            A('alert.check_warp.17', p0=_fa_num(len(hits)), p1=', '.join(hits[:5])))
            except Exception:
                pass

        # ۹) ممیزیِ نشتِ DNS/IPv6 — لبه‌ای، پس فقط هنگامِ **تغییرِ وضعیت**
        #    پیام می‌رود، نه هر چرخه. حالتِ پایدارِ «warn» (قاعده‌ی همه‌گیرِ
        #    DNS نیست ولی همه‌چیز از تونل می‌رود) نباید هر بار رگبار بسازد؛
        #    آنچه ارزشِ خبر دارد گذر به `bad` است — یعنی لحظه‌ای که ترافیک
        #    واقعاً بیرونِ تونل می‌رود. متنِ کامل در پنل و زیرصفحه‌ی ربات است.
        if not self._due("net:leak"):
            return
        try:
            _lk = dns_leak_audit()
            _bad = [f["text"] for f in _lk["findings"] if f["level"] == "bad"]
            ALERTS.edge("net:leak", not _bad,
                        A('alert.check_warp.13')
                        if not _bad else
                        A('alert.check_warp.14', p0=_fa_num(len(_bad)), p1='\n• '.join(_bad[:4])))
        except Exception:
            pass

    def _check_resources(self):
        c = alert_cfg()
        # snapshot() = {"cur": {metric: value}, "extra": {...}} — پیش از این
        # snap.get("cpu") روی همین پوشش خوانده می‌شد و همیشه None بود، پس
        # هشدارِ CPU/RAM/DISK هرگز ارسال نمی‌شد.
        snap = (SYSMON.snapshot() or {}).get("cur") or {}
        need = max(1, int(c["sustain_min"] * 60 / self.INTERVAL))
        for m, lbl, thr in (("cpu", "CPU", c["cpu_pct"]),
                            ("ram", "RAM", c["ram_pct"]),
                            ("disk", "DISK", c["disk_pct"])):
            v = snap.get(m)
            if v is None:
                continue
            over = v >= thr
            cnt = self._sustain.get(m, 0)
            cnt = cnt + 1 if over else 0
            self._sustain[m] = cnt
            fired_key = "res:" + m
            with ALERTS.lock:
                already = ALERTS.state.get(fired_key, False)
            if over and cnt >= need and not already:
                with ALERTS.lock:
                    ALERTS.state[fired_key] = True
                ALERTS.event("resource",
                    A('alert.check_resources.1', p0=lbl, p1=round(v), p2=thr, p3=c['sustain_min'], p4=_host_label()))
            elif not over and already:
                with ALERTS.lock:
                    ALERTS.state[fired_key] = False
                ALERTS.event("resource",
                    A('alert.check_resources.2', p0=lbl, p1=round(v), p2=_host_label()))

    def _check_swap(self):
        try:
            used = 0
            with open("/proc/meminfo") as f:
                mi = {}
                for line in f:
                    k, _, rest = line.partition(":")
                    mi[k] = rest.strip()
            total = int(mi.get("SwapTotal", "0 kB").split()[0])
            free = int(mi.get("SwapFree", "0 kB").split()[0])
            used = total - free
        except (OSError, ValueError, IndexError):
            return
        # هشدار وقتی بیش از ۲۵۶MB سواپ مصرف شده (فشارِ واقعیِ حافظه)
        heavy = used > 256 * 1024
        ALERTS.edge("swap", heavy,
                    (A('alert.check_swap.1', p0=used // 1024, p1=_host_label())) if heavy else
                    (A('alert.check_swap.2', p0=_host_label())),
                    category="swap")

    def _expiry_mark(self, today):
        self._last_expiry_day = today
        try:
            tmp = EXPIRY_STATE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(today + "\n")
            os.replace(tmp, EXPIRY_STATE)
        except OSError:
            pass

    def _expiry_last_day(self):
        d = getattr(self, "_last_expiry_day", None)
        if d is None:
            try:
                with open(EXPIRY_STATE, encoding="utf-8") as f:
                    d = f.read().strip()
            except OSError:
                d = ""
            self._last_expiry_day = d
        return d

    def expiring_accounts(self, days=None):
        """[(kind, name, expires)] حساب‌هایی که تا `days` روزِ دیگر منقضی
        می‌شوند — وایرگارد (متادیتا) و پروکسی؛ همان منطقِ دایجست."""
        if days is None:
            days = alert_cfg()["expiry_days"]
        now = datetime.now()
        soon = now + timedelta(days=days)
        hits = []
        try:
            for (iface, name), m in META.meta_all().items():
                e = (m.get("expires") or "").strip()
                if not e:
                    continue
                try:
                    if now <= datetime.strptime(e, "%Y-%m-%d") <= soon:
                        hits.append(("wg", "%s@%s" % (name, iface), e))
                except ValueError:
                    pass
        except Exception as ex:
            log_action("expiry check (wg) error: %r" % ex)
        for u in META.proxy_users():
            e = (u.get("expires") or "").strip()
            if not e:
                continue
            try:
                if now <= datetime.strptime(e, "%Y-%m-%d") <= soon:
                    hits.append(("px", u["username"], e))
            except ValueError:
                pass
        hits.sort(key=lambda h: (h[2], 0 if h[0] == "wg" else 1, h[1]))
        return hits

    def _check_expiry(self):
        """یک‌بار در هر روزِ تقویمی (ماندگار روی دیسک، مثلِ دایجست).

        🪤 پیش از این: گاردِ ۶ ساعته در حافظه (هر ری‌استارت دوباره می‌فرستاد،
        هر حساب ~۴ بار در روز) و فقط کاربرانِ پروکسی — حساب‌های وایرگارد که
        README قولِ گزارششان را می‌دهد اصلاً دیده نمی‌شدند."""
        c = alert_cfg()
        if not (c["enabled"] and c["events"].get("expiry", True)):
            return
        today = datetime.now().strftime("%Y-%m-%d")
        if self._expiry_last_day() == today:
            return
        hits = self.expiring_accounts(c["expiry_days"])
        # روزِ امروز ثبت می‌شود حتی بدونِ hit، تا هر ۳۰ ثانیه دوباره DB را نگردیم
        self._expiry_mark(today)
        if not hits:
            return
        lines = ["%s/%s (%s)" % (A("alert.kind.wg") if k == "wg"
                                 else A("alert.kind.px"), n, e)
                 for k, n, e in hits[:20]]
        if len(hits) > 20:
            lines.append("… +%d" % (len(hits) - 20))
        ALERTS.event("expiry", A('alert.check_expiry.1', p0=c['expiry_days'],
                                 p1='\n'.join(lines)))

    def _nqmo_last(self):
        """آخرین شناسه‌ی فرستاده، یا None (اولین اجرا / فایلِ خراب)."""
        if not hasattr(self, "_nqmo_last_id"):
            self._nqmo_last_id = None
            try:
                with open(NQMO_NOTIFIED_STATE, encoding="utf-8") as f:
                    v = int(f.read().strip())
                self._nqmo_last_id = v if v >= 0 else None
            except (OSError, ValueError):
                pass
        return self._nqmo_last_id

    def _nqmo_mark(self, last):
        self._nqmo_last_id = last
        try:
            tmp = NQMO_NOTIFIED_STATE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("%d\n" % last)
            os.replace(tmp, NQMO_NOTIFIED_STATE)
        except OSError:
            pass

    def _check_nqmo(self, now=None):
        """رویدادهای تازه‌ی notify_outbox ⇒ ALERTS.event("nqmo", …).

        🪤 دو حالتِ «شناسه‌ی پایه نامعتبر»: اولین اجرا (فایل نیست) و بازسازیِ
        دیتابیسِ موتور (بزرگ‌ترین شناسه از آخرینِ ما کوچک‌تر شد). در هر دو فقط
        رویدادِ تازه (عمرِ کمتر از NQMO_STATE_STALE) فرستاده می‌شود: بدونِ این،
        اولی تاریخچه‌ی ۱۰۰ رویدادیِ صندوق را یک‌جا می‌فرستاد و دومی تا ابد
        ساکت می‌ماند. بازسازی‌ای که پیش از دیده‌شدن از آخرین شناسه‌ی ما بگذرد
        از روی شناسه تشخیص‌پذیر نیست."""
        doc = nqmo_state(now)
        if not doc.get("available"):
            return
        now = time.time() if now is None else now
        box = doc.get("notify_outbox")
        items = sorted((e["id"], e) for e in (box if isinstance(box, list) else [])
                       if isinstance(e, dict) and type(e.get("id")) is int and e["id"] > 0)
        if not items:
            return
        last = self._nqmo_last()
        fresh_only = last is None or items[-1][0] < last
        base = 0 if fresh_only else last
        new_last, sent = (last if not fresh_only else 0), 0
        for eid, ev in items:
            if eid <= base or eid == new_last:
                continue                       # شناسه‌ی تکراری در سندِ خراب
            if fresh_only:
                ts = ev.get("ts")
                if (isinstance(ts, bool) or not isinstance(ts, (int, float))
                        or not math.isfinite(ts) or now - ts > NQMO_STATE_STALE):
                    new_last = eid
                    continue
            if sent >= NQMO_NOTIFY_BURST:
                break                          # بقیه در چرخه‌ی بعد
            text = nqmo_alert_text(ev)
            if text:
                ALERTS.event("nqmo", text)
                sent += 1
            new_last = eid
        if new_last != last:
            self._nqmo_mark(new_last)


ALERTMON = AlertMonitor()


def tunnel_handshake_age(iface):
    """سنِ تازه‌ترین هندشیکِ یک اینترفیسِ تونل (ثانیه)، از دادهٔ SAMPLER.
    None اگر هیچ هندشیکی نباشد."""
    best = 0
    for p in SAMPLER.snapshot().get("peers", []):
        if p.get("iface") == iface and (p.get("handshake") or 0) > best:
            best = p["handshake"]
    if not best:
        return None
    return max(0.0, time.time() - best)


def tunnel_rx_rate(iface):
    """نرخِ لحظه‌ایِ دریافتِ یک تونل (بایت/ثانیه) از SAMPLER — جمعِ peerها.

    اگر SAMPLER هنوز آماده نباشد ۰ برمی‌گردد و استثنا پرتاب نمی‌کند: این
    تابع روی مسیرِ سنجشِ سلامتِ گاردهاست و یک استثنا کلِ چرخه‌ی گارد را
    می‌سوزاند (حلقه فقط لاگ می‌کند و رد می‌شود) — یعنی گارد بی‌صدا از کار
    می‌افتد. «نامعلوم» را مثلِ «ساکت» می‌گیریم تا سنجشِ قطعی‌ترِ بعدی
    (probeِ لایه‌ی داده) تصمیم را بگیرد.
    """
    r = 0.0
    try:
        peers = SAMPLER.snapshot().get("peers", [])
    except Exception:
        return 0.0
    for p in peers:
        if p.get("iface") == iface:
            r += p.get("rx_rate") or 0.0
    return r


# مقصدِ probeِ لایه‌ی داده: باید IPِ همیشه‌دردسترسِ بیرونی باشد که از داخلِ
# هر تونلِ سالمی پاسخ دهد. عمداً یک ثابتِ ماژول است نه تنظیمِ کاربر، چون
# اشتباه‌تنظیم‌کردنش گاردها را کور می‌کند.
DATA_PLANE_PROBE_TARGET = "1.1.1.1"


def tunnel_data_plane_ok(iface, target=DATA_PLANE_PROBE_TARGET, timeout=2):
    """آیا داده واقعاً از این تونل عبور می‌کند؟ (نه صرفاً هندشیک)

    «تونلِ زامبی» حالتی است که اینترفیس بالاست و هندشیک هم تازه است، ولی
    سمتِ مقابل دیگر ترافیک را به اینترنت forward نمی‌کند. چون هندشیک سالم
    است، هر گاردی که فقط سنِ هندشیک را می‌سنجد آن را «زنده» می‌بیند و
    failover نمی‌کند — و ترافیک بی‌صدا بلک‌هول می‌شود.

    یک ping از خودِ اینترفیس تنها سیگنالی است که مستقیماً همان چیزی را
    می‌سنجد که اهمیت دارد: عبورِ واقعیِ بسته. گران‌تر از خواندنِ شمارنده
    است، پس باید فقط وقتی صدا زده شود که سیگنالِ ارزان (rx) ساکت است.
    """
    rc, _out, _err = run(["ping", "-c", "1", "-W", str(int(timeout)),
                          "-I", iface, target], timeout=timeout + 3)
    return rc == 0


# ------------------------------------------- وضعیتِ WARP (مسیریابیِ انتخابی)
# همه‌چیز **زنده** از خودِ سیستم خوانده می‌شود (ipset، اسکریپتِ sync، iptables،
# systemd) — هیچ فهرستی در پنل تکرار نمی‌شود، پس با کم/زیادشدنِ دامنه یا IP
# خودکار به‌روز می‌شود و هرگز کهنه نمی‌ماند.
WARP_IFACE = "wgwarp"
WARP_IPSET = "ai_warp"
# مسیرها باید از داخلِ sandboxِ سرویسِ پنل قابلِ‌دسترس باشند:
# ProtectHome=yes یعنی /root اصلاً دیده نمی‌شود، و ProtectSystem=full یعنی
# /etc فقط‌خواندنی است. پس اسکریپت در /usr/local/sbin (خواندن+اجرا) و فایلِ
# مقصدها در /opt/wg-panel (تنها مسیرِ نوشتنیِ پنل) قرار دارد.
WARP_SYNC = "/usr/local/sbin/warp-gemini-sync.sh"
WARP_TABLE = "230"
WARP_MARK = "0x77"
WARP_UNIT = "warp-gemini.service"
WARP_TIMER = "warp-gemini.timer"
WARP_ACCOUNT_FILE = "/opt/wg-panel/warp-account"   # نوشته‌ی sync.sh
WARP_LAST_SYNC = "/opt/wg-panel/warp-last-sync"    # مهرِ آخرین اجرای موفقِ sync
# نتیجه‌ی آخرین اجرای warp-autodetect (تایمرِ ۶ساعته). این سرویس بیرون از پنل
# است و ممکن است اصلاً نصب نباشد، پس نبودِ فایل حالتِ عادی است نه خطا.
WARP_AUTODETECT_STATE = "/opt/wg-panel/warp-autodetect.state"
DIGEST_STATE = "/opt/wg-panel/alert-digest.last"   # تاریخِ آخرین دایجستِ ارسالی
EXPIRY_STATE = "/opt/wg-panel/alert-expiry.last"   # روزِ آخرین هشدارِ نزدیکِ انقضا
ALERT_EDGES_STATE = "/opt/wg-panel/alert-edges.json"  # وضعیتِ لبه‌ها (ماندگار بینِ ری‌استارت‌ها)
REPORT_STATE = "/opt/wg-panel/alert-report.last"   # تاریخِ آخرین گزارشِ تصویری


def report_cfg():
    """تنظیماتِ گزارشِ دوره‌ایِ تصویری (CONFIG["report"]).
    dow با شماره‌گذاریِ weekday پایتون (دوشنبه=0 … جمعه=4، شنبه=5)."""
    c = {"mode": "off", "time": "10:00", "dow": 4}
    c.update(CONFIG.get("report") or {})
    if c.get("mode") not in ("off", "daily", "weekly"):
        c["mode"] = "off"
    try:
        c["dow"] = int(c.get("dow", 4)) % 7
    except (TypeError, ValueError):
        c["dow"] = 4
    return c


def build_report_photos():
    """[(png, caption)] گزارشِ تصویری: WAN ۷روز، top-۵ کاربر، روندِ سرعت.
    هر بخش مستقل است؛ خطای یکی بقیه را حذف نمی‌کند."""
    photos = []
    label = _host_label()
    lang = alert_lang()
    fa = lang in LANG_FA_DIGITS

    def n(x):
        return _fa_num(x) if fa else str(x)

    def caption(lines):
        # RLM فقط برای زبانِ راست‌به‌چپ؛ در en/ru/zh خطوط چپ‌چین می‌مانند
        return (_rtl_lines(lines) if LANG_DIR.get(lang) == "rtl"
                else "\n".join(lines))
    try:
        st = build_stats()
        wan = next((i for i in st["interfaces"]
                    if i["role"] == "wan"), None)
        if wan:
            rows = META.usage_series(wan["iface"], NETDEV_KEY, "7d")
            if rows:
                vals = [(r["rx"] or 0) + (r["tx"] or 0) for r in rows]
                xl = [(0.0, rows[0]["t"][5:]), (1.0, rows[-1]["t"][5:])]
                png = render_chart_png(
                    [(vals, (88, 166, 255), "TOTAL/DAY")], x_labels=xl,
                    title="WAN %s - 7D" % wan["iface"].upper(), bars=True)
                photos.append((png, caption([
                    A("alert.report.title", p0=label),
                    A("alert.report.wan", p0=wan["iface"]),
                    A("alert.report.total", p0=fmt_bytes_srv(sum(vals)))])))
    except Exception as e:
        log_action("report wan error: %r" % e)
    try:
        agg = {}
        for srv in server_ifaces():
            mx = META.usage_matrix(srv, "7d")
            try:
                names = {b["public_key"]: b["name"]
                         for b in parse_user_blocks(srv)}
            except OSError:
                names = {}
            for pub, byb in mx["data"].items():
                nm = names.get(pub, pub[:8])
                agg[nm] = agg.get(nm, 0) + sum(byb.values())
        top = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:5]
        if top:
            def ascii_name(nm):
                return ("".join(ch for ch in nm if ord(ch) < 128)
                        or "user")[:10]
            vals = [v for _, v in top]
            xl = [((i + 0.5) / len(top), ascii_name(nm))
                  for i, (nm, _) in enumerate(top)]
            png = render_chart_png(
                [(vals, (63, 185, 80), "7D TOTAL")], x_labels=xl,
                title="TOP USERS - 7D", bars=True)
            cap = [A("alert.report.top")]
            for i, (nm, v) in enumerate(top):
                cap.append("%s) %s — %s"
                           % (n(i + 1), nm, fmt_bytes_srv(v)))
            photos.append((png, caption(cap)))
    except Exception as e:
        log_action("report top error: %r" % e)
    try:
        cut = time.time() - 7 * 86400
        rows = [r for r in META.speedtest_recent(1200)
                if r["ok"] and r["ts"] >= cut][::-1]
        if len(rows) >= 2:
            dn = [r["down_bps"] / 1e6 for r in rows]
            up = [r["up_bps"] / 1e6 for r in rows]

            def lbl(ts):
                return datetime.fromtimestamp(ts).strftime("%m-%d")
            xl = [(0.0, lbl(rows[0]["ts"])), (1.0, lbl(rows[-1]["ts"]))]
            png = render_chart_png(
                [(dn, (63, 185, 80), "DOWN"), (up, (88, 166, 255), "UP")],
                x_labels=xl, y_fmt=_fmt_mbps_ascii,
                title="SPEEDTEST - 7D")
            photos.append((png, caption([
                A("alert.report.speed", p0=n(len(rows))),
                A("alert.report.avg",
                  p0=n("%.0f" % (sum(dn) / len(dn))),
                  p1=n("%.0f" % (sum(up) / len(up))))])))
    except Exception as e:
        log_action("report speed error: %r" % e)
    return photos


def send_periodic_report():
    """ساخت و ارسالِ گزارشِ تصویری به چتِ هشدارها. (ok, msg)"""
    c = alert_cfg()
    if not (c["bot_token"] and c["chat_id"]):
        return False, "api.err.tg.unset"
    photos = build_report_photos()
    if not photos:
        return False, "api.err.noreport"
    okall = True
    for png, cap in photos:
        ok, _res = tg_api(c["bot_token"], "sendPhoto",
                          {"chat_id": c["chat_id"], "caption": cap},
                          photo=("report.png", png), iface=c["iface"])
        okall = okall and ok
        time.sleep(1)   # احترام به نرخِ تلگرام
    return okall, "api.ok.sent" if okall else "alert.report.partial"
WARP_EP_IP = "162.159.192.1"                       # endpointِ ثابتِ wgwarp
WARP_GUARD_STATE = "/opt/wg-panel/warp-guard.state"  # egress/rule برای sync.sh
WARP_GUARD_HEARTBEAT = "/opt/wg-panel/warp-guard.active"  # تازه = گارد زنده
WARP_GUARD_DEFAULTS = {"enabled": True, "primary": "wg22",
                       "backup": "wg21", "degrade_after": 5,
                       "rotate": True, "rotate_after": 3}
# استخرِ endpointهای WARP (همه anycast کلادفلر با همان کلیدِ عمومیِ سراسری؛
# پورتِ 2408). primary اول است؛ چرخش وقتی هندشیک نمی‌آید، قبل از degradation.
WARP_EP_POOL = ["162.159.192.1", "162.159.192.2", "188.114.96.1",
                "188.114.97.1", "188.114.98.1", "188.114.99.1"]
# کلیدِ خصوصیِ حسابِ استندبای (wgcfِ جدا) — اگر باشد، پس از شکستِ کلِ
# استخر (سناریوی «کلید/حساب مسدود شده») گارد به آن سوییچ می‌کند.
WARP_STANDBY_KEY = "/opt/wg-panel/warp-standby.key"
# جراحیِ کولترال بر پایهٔ SNI (splitter). marker = روشن؛ heartbeat/stats را
# خودِ دیمن می‌نویسد. WarpGuard مستقلاً fail-open را اعمال می‌کند: اگر دیمن
# ناسالم شد قاعدهٔ TPROXY را برمی‌دارد تا ترافیک به blanketِ 0x77 (کلِ /24 →
# WARP = رفتارِ امروز) برگردد — بدترین حالتِ خرابیِ دیمن = وضعیتِ فعلی نه قطعی.
WARP_SNI_MARK_FILE = "/opt/wg-panel/warp-sni-split"     # وجود = روشن
WARP_SNI_HEARTBEAT = "/opt/wg-panel/warp-sni.active"
WARP_SNI_STATS = "/opt/wg-panel/warp-sni.stats"
WARP_SNI_UNIT = "warp-sni-splitter.service"
WARP_SNI_PORT = "8445"
WARP_SNI_DIRECT_MARK = "0x78"     # کولترال → مستقیم
WARP_SNI_DIVERT_MARK = "0x100"    # مارکِ TPROXY
WARP_SNI_TABLE = "100"
# تفکیکِ QUIC (UDP/443) — مستقل از TCP. روشن + سالم → UDP TPROXY؛ وگرنه
# fail-open به REJECT (مرورگر→TCP→splitterِ TCP = رفتارِ امنِ امروز).
WARP_SNI_QUIC_MARK_FILE = "/opt/wg-panel/warp-sni-quic"   # وجود = روشن
WARP_SNI_QUIC_PORT = "8446"
# آستانه‌ی هشدارِ «کوریِ طبقه‌بندی» (ECH/بی‌SNI): اگر در ~۶ ساعتِ اخیر سهمِ
# بایتیِ جریان‌های بی‌SNI/ECHدار از این درصد گذشت (با حداقلِ حجم برای
# معناداری)، تفکیکِ SNI دارد بی‌اثر می‌شود — هشدارِ زودهنگام قبل از شکایت.
WARP_BLIND_ALERT_PCT = 25
WARP_BLIND_MIN_BYTES = 200 * 1024 * 1024
# تله‌ی ECH از همان BINDِ کاربران می‌پرسد، نه systemd-resolved — چون سؤال این
# است که «کلاینتِ کاربر چه ECHConfigی می‌گیرد»، و پاسخِ resolverِ دیگر می‌تواند
# فرق کند (همان درسی که در پوششِ ناقصِ /24ها گرفته شد).
WARP_ECH_RESOLVER = "2.2.2.2"
_WARP_CACHE = {"ts": 0.0, "data": None}


WARP_TARGETS = "/opt/wg-panel/warp-targets.conf"
# پهن‌ترین رنجِ مجاز. /12 ≈ یک میلیون آی‌پی — جلوی فاجعه‌هایی مثل 0.0.0.0/0
# یا 34.0.0.0/8 (کلِ Google Cloud) را می‌گیرد که کلِ ترافیک را به تونل می‌برد.
WARP_MIN_PREFIX = 12

# خطِ زمانیِ رویدادهای WARP — کران و برچسب‌های فارسیِ نوعِ رویداد
WARP_EVENT_MAX = 300           # سقفِ ردیف‌ها (trim در هر نوشتن)
_WARP_EVENT_LOCK = threading.Lock()
WARP_EVENT_LABELS = {
    "target_add": "افزودنِ مقصد", "target_del": "حذفِ مقصد",
    "preset_on": "روشن‌کردنِ سرویس", "preset_off": "خاموش‌کردنِ سرویس",
    "egress": "سوییچِ تونلِ خروج", "rotate": "چرخشِ endpoint",
    "standby": "سوییچ به کلیدِ استندبای", "degrade": "حالتِ اضطراری (fail-open)",
    "restore": "بازگشتِ سالم", "failopen_sni": "fail-openِ فیلترِ SNI",
    "country": "تغییرِ کشورِ خروج", "quic": "تنظیمِ QUIC",
}


def warp_event(kind, detail="", actor=""):
    """ثبتِ یک رویدادِ WARP در خطِ زمانی (کران‌دار، ضدِخرابی).

    از هر نخی امن است (پنل، WarpGuard، AlertMonitor): اتصالِ مستقلِ SQLite +
    قفلِ سبکِ ماژول برای بازه‌ی trim. خطا هرگز به فراخواننده نمی‌زند —
    رویدادِ گم‌شده نباید هیچ مسیرِ حیاتی‌ای را بشکند."""
    try:
        with _WARP_EVENT_LOCK:
            con = sqlite3.connect(DB_PATH, timeout=10)
            try:
                con.execute(
                    "INSERT INTO warp_event(ts,kind,detail,actor) "
                    "VALUES(?,?,?,?)",
                    (time.time(), str(kind), str(detail)[:400],
                     str(actor)[:64]))
                # trim: فقط اگر از سقف گذشت، کهنه‌ترین‌ها را بینداز
                con.execute(
                    "DELETE FROM warp_event WHERE id NOT IN "
                    "(SELECT id FROM warp_event ORDER BY id DESC LIMIT ?)",
                    (WARP_EVENT_MAX,))
                con.commit()
            finally:
                con.close()
    except sqlite3.Error:
        pass


def warp_events_read(limit=40):
    """آخرین رویدادهای WARP (جدید به قدیم) → لیستِ dict."""
    out = []
    try:
        con = sqlite3.connect(DB_PATH, timeout=10)
        try:
            cur = con.execute(
                "SELECT ts,kind,detail,actor FROM warp_event "
                "ORDER BY id DESC LIMIT ?", (int(limit),))
            for ts, kind, detail, actor in cur.fetchall():
                out.append({"ts": ts, "kind": kind,
                            "label": WARP_EVENT_LABELS.get(kind, kind),
                            "detail": detail, "actor": actor})
        finally:
            con.close()
    except sqlite3.Error:
        pass
    return out


# آستانه‌ی هشدارِ کندیِ مسیرِ WARP: تونل «سالم» ولی TTFB هم به‌طورِ مطلق بالا
# و هم چند برابرِ مسیرِ عادی → «زجرآور». هر دو شرط لازم است تا نوسانِ عادیِ
# شبکه هشدارِ کاذب ندهد.
WARP_SLOW_MS = 4000            # آستانه‌ی مطلقِ TTFB (میلی‌ثانیه)
WARP_SLOW_RATIO = 3.0          # نسبت به مسیرِ عادی


def warp_latency_record(warp_ms, direct_ms):
    """ثبتِ یک نمونه‌ی TTFB (کران‌دار، ضدِخرابی). None مجاز است (شکستِ سنجش)."""
    try:
        con = sqlite3.connect(DB_PATH, timeout=10)
        try:
            con.execute("INSERT INTO warp_latency(ts,warp_ms,direct_ms) "
                        "VALUES(?,?,?)", (time.time(), warp_ms, direct_ms))
            con.commit()
        finally:
            con.close()
    except sqlite3.Error:
        pass


def warp_latency_series(span=86400, limit=300):
    """سریِ زمانیِ TTFBِ WARP/عادی برای نمودار → dict."""
    since = time.time() - span
    pts = []
    try:
        con = sqlite3.connect(DB_PATH, timeout=10)
        try:
            cur = con.execute(
                "SELECT ts,warp_ms,direct_ms FROM warp_latency WHERE ts>=? "
                "ORDER BY ts DESC LIMIT ?", (since, int(limit)))
            for ts, w, d in cur.fetchall():
                pts.append({"ts": ts, "warp": w, "direct": d})
        finally:
            con.close()
    except sqlite3.Error:
        pass
    pts.reverse()          # قدیم به جدید برای نمودار
    wv = [p["warp"] for p in pts if p["warp"] is not None]
    dv = [p["direct"] for p in pts if p["direct"] is not None]
    return {"points": pts,
            "warp_avg": round(sum(wv) / len(wv)) if wv else None,
            "direct_avg": round(sum(dv) / len(dv)) if dv else None,
            "slow_ms": WARP_SLOW_MS, "slow_ratio": WARP_SLOW_RATIO}


def _ping_rtt(ip, count=2, timeout=4):
    """میانگینِ RTT (میلی‌ثانیه) با ping؛ None اگر نرسید. خروجیِ لینوکس/مک هر
    دو خطِ «min/avg/max» دارند — همان را می‌خوانیم."""
    rc, out, _ = run(["ping", "-c", str(count), "-W", str(timeout), ip],
                     timeout=timeout * count + 4)
    if rc != 0:
        return None
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", out or "")
    if not m:
        return None
    try:
        return round(float(m.group(1)), 1)
    except ValueError:
        return None


def warp_rank_endpoints():
    """استخرِ endpointهای WARP را با RTT رتبه‌بندی می‌کند (فقط سنجش، بدونِ
    تغییرِ پیکربندی — چرخشِ واقعی دستِ WarpGuard است) → لیستِ مرتب‌شده.

    endpointِ فعلی هم علامت می‌خورد تا معلوم شود جای بهتری هست یا نه."""
    cur_ep = ""
    try:
        with open(WARP_GUARD_STATE, encoding="utf-8") as f:
            for ln in f:
                if ln.startswith("endpoint="):
                    cur_ep = ln.split("=", 1)[1].strip()
    except OSError:
        pass
    # موازی: پیش از این ۶ ping ِ پشت‌سرهم (هر یک تا ~۱۲ ثانیه) در نخِ HTTP
    # بود؛ حالا همه با هم و هر یک با یک بسته
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(WARP_EP_POOL)) as ex:
        rtts = list(ex.map(lambda ip: _ping_rtt(ip, count=1), WARP_EP_POOL))
    rows = [{"ip": ip, "rtt": rtt, "current": ip == cur_ep}
            for ip, rtt in zip(WARP_EP_POOL, rtts)]
    # مرتب: ابتدا آن‌هایی که RTT دارند (کمترین اول)، سپس نرسیده‌ها
    rows.sort(key=lambda r: (r["rtt"] is None, r["rtt"] if r["rtt"]
                             is not None else 1e9))
    best = next((r["ip"] for r in rows if r["rtt"] is not None), "")
    return {"endpoints": rows, "current": cur_ep, "best": best}

# کاتالوگِ آماده‌ی سرویس‌های هوش‌مصنوعی — هر پریست مجموعه‌ی دامنه‌های بک‌اندِ
# یک سرویس است که با یک سوییچ به warp-targets.conf اضافه/حذف می‌شود. درسِ
# robinfrontend-pa: افزودنِ یک سرویس یعنی دانستنِ *همه‌ی* دامنه‌هایش، نه فقط
# دامنه‌ی اصلی؛ این کاتالوگ آن دانش را یک‌جا نگه می‌دارد.
#
# نکته‌ها:
#  - فقط دامنه (نه IP/رنج): تفکیک بر پایهٔ SNI است و sync خودش resolve می‌کند.
#  - این ثابتِ کد است (منبعِ مورداعتماد)، ولی مسیرِ نوشتن باز هم تک‌تک را با
#    warp_validate_target اعتبارسنجی می‌کند (دفاع در عمق).
#  - دامنه‌های «اشتراکی/پرخطر» (مثلِ x.com که با توییتر مشترک است) عمداً کنار
#    گذاشته شده‌اند تا کولترالِ سنگین نسازند؛ به‌جایش دامنه‌ی اختصاصیِ سرویس.
WARP_AI_PRESETS = [
    {"id": "openai", "label": "ChatGPT / OpenAI",
     "domains": ["chatgpt.com", "chat.openai.com", "openai.com",
                 "api.openai.com", "auth.openai.com", "auth0.openai.com",
                 "cdn.openai.com", "oaistatic.com", "oaiusercontent.com",
                 "sora.com", "sora.chatgpt.com"]},
    {"id": "anthropic", "label": "Claude / Anthropic",
     "domains": ["claude.ai", "anthropic.com", "api.anthropic.com",
                 "console.anthropic.com", "cdn.anthropic.com",
                 "claudeusercontent.com"]},
    {"id": "gemini", "label": "Gemini / Google AI",
     "domains": ["gemini.google.com", "aistudio.google.com",
                 "generativelanguage.googleapis.com", "notebooklm.google",
                 "notebooklm.google.com", "robinfrontend-pa.googleapis.com",
                 "signaler-pa.googleapis.com"]},
    {"id": "copilot", "label": "Microsoft / GitHub Copilot",
     "domains": ["copilot.microsoft.com", "githubcopilot.com",
                 "api.githubcopilot.com", "copilot-proxy.githubusercontent.com"]},
    {"id": "perplexity", "label": "Perplexity",
     "domains": ["perplexity.ai", "www.perplexity.ai", "pplx.ai",
                 "api.perplexity.ai"]},
    {"id": "grok", "label": "Grok / xAI",
     "domains": ["grok.com", "x.ai", "api.x.ai", "grok.x.ai"]},
    {"id": "mistral", "label": "Mistral / Le Chat",
     "domains": ["chat.mistral.ai", "mistral.ai", "api.mistral.ai"]},
    {"id": "deepseek", "label": "DeepSeek",
     "domains": ["chat.deepseek.com", "deepseek.com", "api.deepseek.com"]},
    {"id": "midjourney", "label": "Midjourney",
     "domains": ["midjourney.com", "www.midjourney.com", "cdn.midjourney.com"]},
]


def warp_presets_status():
    """وضعیتِ هر پریست نسبت به مقصدهای فعلی → لیستِ dict.

    state: "on" (همه‌ی دامنه‌ها حاضرند)، "off" (هیچ‌کدام)، "partial" (بخشی).
    منبعِ حقیقت خودِ targets.conf است، پس با هر تغییرِ دستی هم درست می‌ماند."""
    cur = set(warp_targets_read())
    out = []
    for p in WARP_AI_PRESETS:
        doms = p["domains"]
        present = [d for d in doms if d in cur]
        n = len(present)
        state = "on" if n == len(doms) else ("off" if n == 0 else "partial")
        out.append({"id": p["id"], "label": p["label"],
                    "total": len(doms), "present": n,
                    "state": state, "domains": doms})
    return out


def warp_preset_apply(pid, enable, by):
    """افزودن/حذفِ کلِ دامنه‌های یک پریست → (ok, پیام, applied).

    enable=True دامنه‌های غایب را اضافه می‌کند؛ False دامنه‌های حاضر را حذف.
    نوشتن با همان warp_targets_write (اعتبارسنجی + بکاپ + اتمیک)."""
    preset = next((p for p in WARP_AI_PRESETS if p["id"] == pid), None)
    if preset is None:
        return False, "api.err.preset", False
    cur = warp_targets_read()
    doms = preset["domains"]
    if enable:
        add = [d for d in doms if d not in cur]
        if not add:
            return True, "api.ok.warp.preset.all", False
        new = cur + add
    else:
        dset = set(doms)
        new = [t for t in cur if t not in dset]
        if len(new) == len(cur):
            return True, "api.ok.warp.preset.none", False
        if not new:
            return False, "api.err.warp.preset.empties", False
    ok, werr = warp_targets_write(new, by)
    if not ok:
        return False, werr, False
    aok, msg = warp_apply()
    return True, msg, aok
_WARP_DOMAIN_RE = re.compile(
    r"\A(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")


# هم‌اندیس با POOL_TABLES ِ deploy/wgpl-failover.sh (گارد: PoolAlignmentTests).
AI_POOL_TABLES = ("241", "242", "243", "244", "245", "246",
                  "247", "248", "249", "250")
# فهرستِ خروجی‌های سوخته — نوشته‌ی wgpl-egress-health.py، خوانده‌ی
# wgpl-failover.sh (۱۱ سپتامبر ۲۰۲۶، §۲۹٫۱۰۵). پنل فقط می‌خوانَد: تونلی که
# لینک و هندشیکش سالم است ولی گوگل خروجی‌اش را ۴۰۳ می‌دهد، بدونِ این
# «سالم» نمایش داده می‌شد — همان همیشه‌سبزِ گمراه‌کننده.
AI_POOL_BURNED_FILE = "/opt/wg-panel/wgpl-burned.list"


def _pool_burned():
    try:
        with open(AI_POOL_BURNED_FILE, encoding="utf-8") as f:
            return {ln.strip() for ln in f
                    if ln.strip() and not ln.lstrip().startswith("#")}
    except OSError:
        return set()


def _default_dev_of_table(table):
    """اینترفیسِ مسیرِ پیش‌فرضِ یک جدول (پشتیبانِ metric-دار نادیده گرفته می‌شود)."""
    rc, out, _ = run(["ip", "route", "show", "table", str(table)], timeout=5)
    for ln in (out or "").splitlines():
        if ln.startswith("default") and "metric" not in ln:
            m = re.search(r"\bdev\s+(\S+)", ln)
            if m:
                return m.group(1)
    return ""


def ai_egress_diag():
    """خروجیِ **واقعیِ** ترافیکِ AI — عمداً جدا از WARP_IFACE.

    چرا جدا: WARP_IFACE مالِ WarpGuard است و گارد endpointِ آن اینترفیس را
    می‌چرخاند (`_rotate_endpoint`). اگر آن ثابت را به تونلِ خروجیِ تازه
    ببریم، گارد endpointِ آن تونل را با endpointهای Cloudflare جایگزین
    می‌کند و می‌شکندش. پس این تابع فقط **می‌خوانَد** که مسیر واقعاً کجا
    می‌رود، بی‌آنکه ثابتِ گارد را لمس کند.

    ۱۵ اوت ۲۰۲۶ (§۲۹٫۱۰۲): گوگل آدرس‌های WARP را برای سرویسِ Gemini رد
    می‌کند، پس خروجی به استخری از تونل‌ها منتقل شد و پنل بدونِ این تابع
    همچنان wgwarp را گزارش می‌کرد — سبز، ولی گمراه‌کننده.
    """
    d = {"main": _default_dev_of_table(WARP_TABLE), "pool": [], "spread": False}
    live = live_interfaces()
    burned = _pool_burned()
    now = int(time.time())
    for t in AI_POOL_TABLES:
        dev = _default_dev_of_table(t)
        if not dev:
            continue
        row = {"table": t, "dev": dev, "up": dev in live, "age": None,
               "rx": 0, "tx": 0, "burned": dev in burned}
        rc, out, _ = run(["wg", "show", dev, "dump"], timeout=5)
        if rc == 0:
            for ln in (out or "").splitlines()[1:]:
                f = ln.split("\t")
                if len(f) >= 7:
                    try:
                        hs = int(f[4])
                        row["age"] = (now - hs) if hs else None
                        row["rx"], row["tx"] = int(f[5]), int(f[6])
                    except (ValueError, IndexError):
                        pass
                    break
        d["pool"].append(row)
    # «پخش» یعنی بیش از یک خروجیِ متمایز — با یک تونل، استخر بی‌معناست.
    d["spread"] = len({r["dev"] for r in d["pool"]}) > 1
    d["burned"] = sorted(burned)
    return d


def warp_protected_ips():
    """فضایی که هرگز نباید به WARP برود (وگرنه سرور/کاربران می‌شکنند).

    - endpointِ خودِ وارپ: اگر داخلِ ست بیفتد، بسته‌های رمزشدهٔ WARP دوباره
      به wgwarp مسیر می‌خورند → **حلقهٔ بی‌نهایت** و قطعِ کامل.
    - resolverِ کاربران (BIND): رفتنش به تونل یعنی مرگِ DNS همه.
    - **کلِ سابنت‌های متصلِ سرور** (نه فقط آدرسِ دقیق): مثلاً روی eth0 آدرسِ
      .68 است ولی .69 هم آدرسِ سرورِ VPNِ کاربران است؛ اگر فقط آدرسِ دقیق
      را محافظت کنیم، رنجِ همسایه از دروازه رد می‌شود و VPN را می‌شکند.
      (این شکاف در تستِ زنده گرفته شد.)
    """
    nets = set()
    _d, _s, cfg = warp_sync_config()
    for key in ("warp_ep", "resolver"):
        v = cfg.get(key)
        if v:
            try:
                nets.add(ipaddress.ip_network(v + "/32", strict=False))
            except ValueError:
                pass
    # 🪤 کلِ استخرِ endpointها، نه فقط endpointِ فعلیِ sync.sh: WarpGuard
    # endpoint را در WARP_EP_POOL می‌چرخاند؛ هدفی مثل 188.114.96.0/24 با
    # endpointِ امروز تداخل نداشت و پذیرفته می‌شد، و بعد از چرخش بسته‌های
    # رمزشده‌ی WARP خودشان به wgwarp می‌رفتند (همان حلقه‌ی بالا).
    for ep in list(WARP_EP_POOL) + [WARP_EP_IP]:
        try:
            nets.add(ipaddress.ip_network(ep + "/32"))
        except ValueError:
            pass
    rc, out, _ = run(["wg", "show", WARP_IFACE, "endpoints"], timeout=5)
    if rc == 0:
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+):\d+", out or ""):
            try:
                nets.add(ipaddress.ip_network(m.group(1) + "/32"))
            except ValueError:
                pass
    rc, out, _ = run(["ip", "-4", "-o", "addr", "show"], timeout=5)
    if rc == 0:
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", out or ""):
            try:
                nets.add(ipaddress.ip_network(m.group(1), strict=False))
            except ValueError:
                pass
    return nets


def warp_validate_target(raw, protected=None):
    """اعتبارسنجیِ سخت‌گیرانهٔ یک مقصد → (نوع، مقدارِ نرمال‌شده، خطا).

    نوع: "domain" یا "net". هر چیزِ دیگری قاطعانه رد می‌شود — این تنها
    دروازهٔ ورودِ داده به فایلی است که اسکریپتِ rootی می‌خواندش."""
    s = (raw or "").strip().lower()
    if not s:
        return "", "", "api.err.warp.t.empty"
    if len(s) > 253:
        return "", "", "api.err.warp.t.long"
    if any(c.isspace() for c in s) or any(c in s for c in "\\;|&$`'\"<>(){}[]*?!"):
        return "", "", "api.err.warp.t.chars"
    protected = protected if protected is not None else warp_protected_ips()
    # --- IP یا رنج
    if re.fullmatch(r"[0-9./]+", s):
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return "", "", "api.err.warp.t.ipfmt"
        if net.version != 4:
            return "", "", "api.err.warp.t.v4only"
        if net.prefixlen < WARP_MIN_PREFIX:
            return "", "", aerr("api.err.warp.t.wide", max=WARP_MIN_PREFIX)
        if (net.is_private or net.is_loopback or net.is_link_local
                or net.is_multicast or net.is_reserved
                or net.network_address.packed[0] == 0):
            return "", "", "api.err.warp.t.private"
        for pn in protected:
            if net.overlaps(pn):
                return "", "", aerr("api.err.warp.t.overlap", net=str(pn))
        return "net", str(net), ""
    # --- دامنه
    if not _WARP_DOMAIN_RE.match(s):
        return "", "", "api.err.warp.t.domain"
    return "domain", s, ""


def warp_targets_read():
    """مقصدهای فعلی از فایلِ داده (به‌ترتیبِ فایل، بدونِ کامنت)."""
    out = []
    try:
        with open(WARP_TARGETS, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(line)
    except OSError:
        pass
    return out


def warp_autodetect_state():
    """نتیجه‌ی آخرین اجرای warp-autodetect، یا {} اگر در دسترس نباشد.

    آن سرویس بیرون از پنل زندگی می‌کند (تایمرِ ۶ساعته) و مقصد به
    `warp-targets.conf` **اضافه می‌کند**. پس پنل/ربات باید بتواند نشان دهد
    آخرین بار کِی اجرا شده و چه چیزی افزوده — وگرنه فهرست بی‌آنکه کاربر
    بداند تغییر می‌کند.

    نبودِ فایل حالتِ عادی است (سرویس نصب نشده یا هنوز اجرا نشده)، نه خطا؛
    پس {} برمی‌گردد و صدازننده فقط بخش را نشان نمی‌دهد. کلیدها:
    ts (زمان)، checked (چند تست شد)، added (چه افزوده شد)،
    blocked (چه چیزی ۴۰۳ گرفت)، dry_run.
    """
    try:
        with open(WARP_AUTODETECT_STATE, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


# چهار نویسنده (API، ربات، presetها، autodetect ِ بیرونی) read→modify→write
# می‌کنند. قفل هم نوشتن را یکی می‌کند هم — وقتی فراخوان دورِ read+write
# بگیرد (RLock) — گم‌شدنِ تغییرِ هم‌زمان را.
_WARP_TARGETS_LOCK = threading.RLock()


def warp_targets_write(entries, by):
    """نوشتنِ اتمیکِ فایلِ مقصدها با بکاپ → (ok، خطا).

    همهٔ ورودی‌ها دوباره اعتبارسنجی می‌شوند (حتی اگر قبلاً شده باشند)."""
    with _WARP_TARGETS_LOCK:
        return _warp_targets_write_locked(entries, by)


def _warp_targets_write_locked(entries, by):
    protected = warp_protected_ips()
    clean, seen = [], set()
    for e in entries:
        kind, val, err = warp_validate_target(e, protected)
        if err:
            return False, aerr("api.err.warp.t.entry", entry=e, why=err)
        if val not in seen:
            seen.add(val)
            clean.append((kind, val))
    if not clean:
        return False, "api.err.listempty"
    body = ["# مقصدهای مسیریابیِ WARP — از پنل مدیریت می‌شود.",
            "# هر خط یکی از: دامنه (example.com) یا IP (1.2.3.4) یا رنج (1.2.3.0/24)",
            "# آخرین تغییر: %s توسط %s"
            % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), by), ""]
    body += [v for _k, v in clean]
    tmp = None
    try:
        if os.path.exists(WARP_TARGETS):
            shutil.copy2(WARP_TARGETS, WARP_TARGETS + ".bak")
        # نامِ یکتا، نه .tmp ِ ثابت (رجوع به _write_root_file)
        fd, tmp = tempfile.mkstemp(prefix="warp-targets.", suffix=".tmp",
                                   dir=os.path.dirname(WARP_TARGETS) or ".")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(body) + "\n")
            f.flush()
            os.fsync(f.fileno())          # اسکریپتِ root ِ sync آن را می‌خواند
        os.chmod(tmp, 0o600)
        os.replace(tmp, WARP_TARGETS)
    except OSError as e:
        if tmp:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return False, aerr("api.err.write", v=e)
    return True, ""


def warp_probe_target(raw):
    """یک مقصد را از مسیرِ WARP و مسیرِ عادی probe می‌کند تا معلوم شود
    مسیریابی کار می‌کند و exit-IPِ WARP چیست → (ok، dict).

    برای دامنه، خودِ hostname را می‌زند (SNI درست). برای IP، همان IP.
    از مسیرِ WARP: اگر مقصد در ai_warp باشد mark می‌خورد؛ ما مستقیماً با
    curl --interface نمی‌رویم چون مسیر با mark تعیین می‌شود — به‌جایش IP را
    موقتاً برای این probe به یک ست جدا اضافه نمی‌کنیم؛ فقط اگر مقصد از قبل
    در ai_warp است، خروجی از WARP خواهد بود."""
    kind, val, err = warp_validate_target(raw)
    if err:
        return False, err
    host = val.split("/")[0] if kind == "net" else val
    # exit-IP از مسیرِ عادی
    rc, out, _ = run(["curl", "-s", "--max-time", "8",
                      "https://ifconfig.me/ip"], timeout=12)
    normal_ip = (out or "").strip()[:45]
    # آیا این مقصد الان در ai_warp هست (یعنی از WARP می‌رود)؟
    in_set = False
    if kind == "net":
        rc, _o, _e = run(["ipset", "test", WARP_IPSET, host], timeout=5)
        in_set = rc == 0
    else:
        # دامنه: یک IP را resolve کن و ست را چک کن
        rc, out, _ = run(["dig", "+short", "@2.2.2.2", host, "A"], timeout=8)
        ips = [l for l in (out or "").splitlines()
               if re.fullmatch(r"[0-9.]+", l.strip())]
        for ip in ips[:1]:
            rc2, _o, _e = run(["ipset", "test", WARP_IPSET, ip.strip()],
                              timeout=5)
            if rc2 == 0:
                in_set = True
    # تستِ دسترسی به خودِ مقصد
    tgt = "https://%s/" % host
    rc, out, _ = run(["curl", "-s", "--max-time", "12", "-o", "/dev/null",
                      "-w", "%{http_code}", tgt], timeout=16)
    code = (out or "").strip()
    return True, {"host": host, "http_code": code or "000",
                  "reachable": code not in ("", "000"),
                  "via_warp": in_set, "normal_exit_ip": normal_ip}


def warp_apply():
    """اجرای sync.sh برای اعمالِ تغییر → (ok، پیام)."""
    if not os.path.isfile(WARP_SYNC):
        return False, "api.err.nosync"
    rc, out, err = run([WARP_SYNC], timeout=120)
    _WARP_CACHE.update(ts=0, data=None)        # کش باطل شود
    if rc != 0:
        # متنِ خامِ sync.sh — پیامِ سیستم است و ترجمه نمی‌شود
        return False, (err or out or "sync.sh: rc=%d" % rc).strip()[:200]
    return True, (out or "").strip()[:200]


def warp_sync_config():
    """DOMAINS و STATIC_NETS و کلیدهای اصلی را از خودِ sync.sh می‌خواند
    (منبعِ حقیقتِ پیکربندی).

    نکته: کامنت‌ها **پیش از** تحلیل حذف می‌شوند، چون خودشان ممکن است پرانتز
    داشته باشند (مثلاً «# لندینگ (216.239.32.x)») و مرزِ آرایه را زودتر
    ببندند — همین باگ در تستِ زنده گرفته شد و یک دامنه گم می‌شد."""
    doms, stat, extra = [], [], {}
    arrays = {"DOMAINS": doms, "STATIC_NETS": stat}
    keys = ("EGRESS", "WARP_EP", "USERS", "RESOLVER")
    try:
        with open(WARP_SYNC, encoding="utf-8") as f:
            raw_lines = f.read().splitlines()
    except OSError:
        return doms, stat, extra
    cur = None
    for raw in raw_lines:
        line = raw.split("#", 1)[0].strip()        # کامنت اول حذف شود
        if not line:
            continue
        if cur is None:
            m = re.match(r"([A-Z_]+)=\((.*)$", line)
            if m and m.group(1) in arrays:
                cur, line = arrays[m.group(1)], m.group(2)
            else:
                m2 = re.match(r"([A-Z_]+)=(\S+)$", line)
                if m2 and m2.group(1) in keys:
                    extra[m2.group(1).lower()] = m2.group(2).strip('"\'')
                continue
        closed = ")" in line
        if closed:
            line = line.split(")", 1)[0]
        for tok in line.split():
            tok = tok.strip().strip('"\'')
            if tok:
                cur.append(tok)
        if closed:
            cur = None
    return doms, stat, extra


def _warp_account_type():
    """نوعِ حسابِ WARP (unlimited/free) از فایلی که sync.sh می‌نویسد.

    چرا فایل و نه فراخوانیِ مستقیمِ wgcf: پنل ProtectHome=yes دارد و نه /root
    را می‌بیند نه wgcf-account.toml را؛ پس sync.sh (root، بدونِ sandbox) نوعِ
    حساب را در /opt/wg-panel/warp-account می‌نویسد و ما فقط می‌خوانیم."""
    try:
        with open(WARP_ACCOUNT_FILE, encoding="utf-8") as f:
            return f.read().strip()[:20]
    except OSError:
        return ""


def warp_sync_age():
    """سن (ثانیه) از آخرین اجرای *موفقِ* sync.sh؛ None اگر مهر وجود ندارد.

    sync.sh در پایانِ اجرای کاملاً موفق epoch را در WARP_LAST_SYNC می‌نویسد.
    درسِ باگِ کش (ورودیِ ۹۸): sync می‌توانست هفته‌ها هر ۱۵ دقیقه با rc≠0
    بمیرد و هیچ هشداری نیاید — این مهر آن حفره‌ی پایشی را می‌بندد."""
    try:
        with open(WARP_LAST_SYNC, encoding="utf-8") as f:
            ts = int(f.read().strip() or "0")
    except (OSError, ValueError):
        return None
    if ts <= 0:
        return None
    return max(0, int(time.time() - ts))


# probe دوره‌ایِ سطحِ اپلیکیشن — هندشیکِ سالم ≠ gemini باز. اگر گوگل
# خروجیِ WARP را ببندد (403/429) یا کشورِ خروجی عوض شود، تونل «سالم»
# به‌نظر می‌رسد ولی سرویس خراب است — همان الگوی «خطرناک‌ترین حالت».
_WARP_PROBE = {"ts": 0, "trace": {}, "gemini": ""}
_WARP_PROBE_LOCK = threading.Lock()
WARP_PROBE_INTERVAL = 600      # هر ۱۰ دقیقه (فراخوانیِ شبکه است)
# میزبانِ نماینده برای سنجشِ TTFB (کیفیتِ مسیر). همان دامنه‌ی probe تا
# سنجش با واقعیتِ سرویس بخواند.
WARP_TTFB_HOST = "https://gemini.google.com/"


def _curl_ttfb(url, iface=None, timeout=16):
    """TTFB (میلی‌ثانیه) یک URL؛ None اگر شکست. iface=None → مسیرِ عادی."""
    cmd = ["curl", "-s", "-o", "/dev/null", "-w",
           "%{time_starttransfer} %{http_code}", "--max-time", "12"]
    if iface:
        cmd += ["--interface", iface]
    cmd.append(url)
    rc, out, _ = run(cmd, timeout=timeout)
    if rc != 0 or not out:
        return None, ""
    parts = (out or "").strip().split()
    if len(parts) < 2:
        return None, ""
    try:
        ms = round(float(parts[0]) * 1000)
    except ValueError:
        return None, ""
    return ms, parts[1][:3]


def warp_probe_run():
    """probe از خودِ تونل (curl --interface wgwarp) → dict.

    تفاوت با warp_probe_target: آن یکی «مسیرِ policy» (mark→rule→table) را
    می‌سنجد؛ این یکی «datapathِ خودِ تونل» را — عمداً، تا خرابیِ لایه‌ی
    اپلیکیشن (بلاکِ گوگل/کشور) از خرابیِ مسیریابی تفکیک شود.
    cdn-cgi/trace در یک درخواست سه چیز می‌دهد: عبورِ واقعیِ ترافیک،
    نوعِ حساب (warp=plus)، و کشور/coloی خروج.

    از فازِ کیفیتِ مسیر: TTFB را هم از مسیرِ WARP و هم مسیرِ عادی می‌گیرد تا
    «تونلِ سالم ولی زجرآور» (هندشیک دارد، کد ۲۰۰ می‌دهد، ولی کند است) دیده
    شود — چیزی که probeِ دودوییِ قبلی نمی‌دید."""
    out = {"ts": int(time.time()), "trace": {}, "gemini": "",
           "warp_ttfb": None, "direct_ttfb": None}
    rc, txt, _ = run(["curl", "-s", "--max-time", "10", "--interface",
                      WARP_IFACE,
                      "https://www.cloudflare.com/cdn-cgi/trace"],
                     timeout=15)
    if rc == 0 and txt:
        for ln in txt.splitlines():
            k, _sep, v = ln.partition("=")
            if k in ("warp", "loc", "colo", "ip"):
                out["trace"][k] = v.strip()[:40]
    # TTFBِ WARP (کد هم از همین می‌آید — یک درخواستِ کمتر)
    wms, wcode = _curl_ttfb(WARP_TTFB_HOST, iface=WARP_IFACE)
    if wcode:
        out["gemini"] = wcode
    out["warp_ttfb"] = wms
    # TTFBِ مسیرِ عادی (بدونِ interface) — مبنای مقایسه
    dms, _dc = _curl_ttfb(WARP_TTFB_HOST, iface=None)
    out["direct_ttfb"] = dms
    return out


# ----------------------------------------------- حسابداریِ per-block از ipset
# حسابداریِ ترافیکِ per-block از شمارنده‌های ipset (فازِ ۳)
# هدف: کمّی‌کردنِ «کولترال» — /24های GFE اشتراکی‌اند و یوتیوب/سرچ هم با
# gemini از همان رنج‌ها می‌روند؛ بدونِ عدد نمی‌شود درباره‌ی SNI-split تصمیم
# گرفت. شمارنده‌های کرنل با هر swapِ sync صفر می‌شوند (tmpِ تازه)؛ این نخ
# هر ۳۰ ثانیه delta می‌گیرد و با تشخیصِ ریست تجمیع می‌کند. باختِ داده فقط
# «از آخرین نمونه تا swap» است (حداکثر ~۳۰ث در هر ۱۵ دقیقه — برای سنجش
# کافی، برای صورتحساب نه؛ و ادعای ما همان سنجش است).
_WARP_TRAFFIC = {"since": 0, "nets": {}}
_WARP_TRAFFIC_LOCK = threading.Lock()


def _parse_ipset_counters(text):
    """خروجیِ `ipset list` → {net: (packets, bytes)} — فقط خطوطِ عضوها."""
    out = {}
    for ln in (text or "").splitlines():
        m = re.match(r"^([0-9.]+/\d+|[0-9.]+)\s+packets\s+(\d+)\s+"
                     r"bytes\s+(\d+)", ln.strip())
        if m:
            out[m.group(1)] = (int(m.group(2)), int(m.group(3)))
    return out


def _warp_traffic_merge(nets, sample):
    """تجمیعِ deltaی یک نمونه در stateی تجمعی (in-place).

    ریست (swapِ sync یا بازساختِ ست) = شمارنده‌ی جدید < قبلی → کلِ مقدارِ
    جدید delta حساب می‌شود. عضوِ غایب حفظ می‌شود (تجمعش نمی‌پرد) و
    last_*اش صفر، تا بازگشتِ بعدی درست شمرده شود."""
    seen = set()
    for net, (p, b) in sample.items():
        st = nets.setdefault(net, {"bytes": 0, "pkts": 0,
                                   "last_b": 0, "last_p": 0})
        db = b - st["last_b"]
        dp = p - st["last_p"]
        if db < 0:
            db = b
        if dp < 0:
            dp = p
        st["bytes"] += db
        st["pkts"] += dp
        st["last_b"], st["last_p"] = b, p
        seen.add(net)
    for net, st in nets.items():
        if net not in seen:
            st["last_b"] = st["last_p"] = 0
    return nets


def _warp_net_domains():
    """نگاشتِ net→[domains] از فایل‌های کش (برای برچسبِ جدولِ ترافیک)."""
    out = {}
    try:
        names = os.listdir(WARP_CACHE_DIR)
    except OSError:
        return out
    for name in names:
        if "/" in name or ".." in name:
            continue
        try:
            with open(os.path.join(WARP_CACHE_DIR, name),
                      encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        for ln in lines[1:]:
            ln = ln.strip()
            if ln:
                out.setdefault(ln, []).append(name)
    return out


def warp_traffic_snapshot(limit=20):
    """براساسِ stateی تجمعی: top-N بر حسبِ بایت + جمعِ کل + نگاشتِ دامنه."""
    with _WARP_TRAFFIC_LOCK:
        since = _WARP_TRAFFIC["since"]
        items = [(net, st["bytes"], st["pkts"])
                 for net, st in _WARP_TRAFFIC["nets"].items()]
    dom_map = _warp_net_domains()
    items.sort(key=lambda x: -x[1])
    return {"since": since,
            "total_bytes": sum(b for _n, b, _p in items),
            "top": [{"net": n, "bytes": b, "pkts": p,
                     "domains": sorted(dom_map.get(n, []))}
                    for n, b, p in items[:limit]]}


# استخرِ VPN (openconnect) — همان رنجی که در sync.sh با POOL مستند است؛
# IPهایش نامِ peer ندارند و در جدولِ per-user برچسبِ عمومی می‌گیرند.
# ⚠️ پیش‌فرض **None** است، نه رنجِ این استقرار: این ثابت داخلِ ایمیجِ Docker
# می‌رود و ایمیج به سرورهای دیگر می‌رسد. نصبِ تازه استخرِ AnyConnect ندارد،
# پس نبودنِ برچسب رفتارِ درست است. استقرارِ عملیاتی رنجِ خودش را با
# `Environment=WG_VPN_POOL=…` می‌دهد — و عمداً اینجا نوشته نمی‌شود.
_pool = os.environ.get("WG_VPN_POOL", "").strip()
try:
    WARP_POOL_NET = ipaddress.ip_network(_pool) if _pool else None
except ValueError:
    WARP_POOL_NET = None
_WARP_SRC_NAMES = {"ts": 0.0, "map": {}}


def warp_src_names():
    """نگاشتِ IPِ کاربر → «iface/نام» از کانفیگ‌های وایرگارد (کشِ ۶۰ث).

    برای جدولِ «مصرفِ AI به تفکیکِ کاربر»: IPِ peerِ وایرگارد نامِ خودش را
    می‌گیرد؛ IPِ استخر (که peer ندارد) برچسبِ «استخر VPN» می‌گیرد؛ بقیه خام
    می‌مانند. خواندنِ کانفیگ‌ها ارزان است ولی نه در حدِ هر ۳۰ ثانیه — کش."""
    now = time.time()
    if now - _WARP_SRC_NAMES["ts"] < 60:
        return _WARP_SRC_NAMES["map"]
    mp = {}
    for ifc in list_all_wg_confs():
        try:
            for b in parse_user_blocks(ifc):
                for part in (b.get("allowed_ips") or "").split(","):
                    ip = part.strip().split("/")[0]
                    if ip and ":" not in ip:
                        mp[ip] = "%s/%s" % (ifc, b["name"])
        except OSError:
            continue
    _WARP_SRC_NAMES.update(ts=now, map=mp)
    return mp


# برچسبِ مبدأِ استخر خودِ کلیدِ کاتالوگ است؛ مرورگر و ربات ترجمه‌اش می‌کنند
WARP_POOL_LABEL = "ui.warp.src.pool"


def warp_src_label(ip, names=None):
    """برچسبِ نمایشیِ یک مبدأ: نامِ peer، یا WARP_POOL_LABEL، یا خالی (=خام)."""
    names = names if names is not None else warp_src_names()
    if ip in names:
        return names[ip]
    try:
        if WARP_POOL_NET is not None and ipaddress.ip_address(ip) in WARP_POOL_NET:
            return WARP_POOL_LABEL
    except ValueError:
        pass
    return ""


def warp_sni_status():
    """وضعیتِ زنده‌ی جراحیِ SNI (splitter): روشن؟ سالم؟ TPROXY حاضر؟ + آمار.

    همه‌چیز زنده خوانده می‌شود: marker، heartbeat، systemd، قاعدهٔ iptables،
    و فایلِ stats که خودِ دیمن می‌نویسد. هیچ حالتی در پنل کش نمی‌شود."""
    st = {"enabled": warp_sni_enabled(), "healthy": False,
          "active": False, "tproxy": False, "unit_active": False,
          "stats": None, "hb_age": None,
          "quic_enabled": warp_sni_quic_enabled(),
          "quic_active": False, "quic_tproxy": False,
          "blind_alert_pct": WARP_BLIND_ALERT_PCT}
    if not st["enabled"] and not st["quic_enabled"]:
        return st
    st["healthy"] = warp_sni_healthy()
    st["tproxy"] = warp_sni_tproxy_present()
    rc, out, _ = run(["systemctl", "is-active", WARP_SNI_UNIT], timeout=5)
    st["unit_active"] = (out or "").strip() == "active"
    # فعال = روشن و سالم و قاعده حاضر (تفکیک واقعاً در جریان است)
    st["active"] = bool(st["healthy"] and st["tproxy"])
    if st["quic_enabled"]:
        st["quic_tproxy"] = warp_sni_quic_tproxy_present()
        st["quic_active"] = bool(st["healthy"] and st["quic_tproxy"])
    try:
        with open(WARP_SNI_HEARTBEAT, encoding="utf-8") as f:
            hb = int((f.readline() or "0").strip() or "0")
        st["hb_age"] = max(0, int(time.time() - hb))
    except (OSError, ValueError):
        pass
    try:
        with open(WARP_SNI_STATS, encoding="utf-8") as f:
            st["stats"] = json.load(f)
    except (OSError, ValueError):
        pass
    # برچسبِ مبدأها برای جدولِ per-user (فقط IPهای حاضر در top_src)
    try:
        tsrc = (st["stats"] or {}).get("top_src") or []
        names = warp_src_names()
        st["src_labels"] = {r[0]: warp_src_label(r[0], names)
                            for r in tsrc if r and r[0]}
    except Exception:
        st["src_labels"] = {}
    return st


# آخرین مقادیرِ شمارنده‌های splitter (برای محاسبهٔ دلتا؛ ریست/restart را
# تشخیص می‌دهد: اگر مقدارِ جدید < قبلی، خودِ مقدارِ جدید = دلتا).
_SPLIT_PREV = {"ai": None, "direct": None, "qai": None, "qdirect": None,
               "nosni": None, "ech": None, "started": None}


def _warp_split_sample(con):
    """دلتای بایتِ AI/کولترال (+ کوریِ ECH/بی‌SNI) را در سطلِ جاری می‌ریزد."""
    try:
        with open(WARP_SNI_STATS, encoding="utf-8") as f:
            s = json.load(f)
    except (OSError, ValueError):
        return
    started = s.get("started")
    cur = {"ai": int(s.get("ai_bytes", 0)),
           "direct": int(s.get("direct_bytes", 0)),
           "qai": int(s.get("quic_ai_bytes", 0)),
           "qdirect": int(s.get("quic_direct_bytes", 0)),
           # کوریِ طبقه‌بندی: TCP+QUIC بی‌SNI و جریان‌های ECHدار
           "nosni": int(s.get("nosni_bytes", 0))
           + int(s.get("quic_nosni_bytes", 0)),
           "ech": int(s.get("ech_bytes", 0))}
    reset = (_SPLIT_PREV["started"] != started)   # دیمن restart شده
    deltas = {}
    for k in ("ai", "direct", "qai", "qdirect", "nosni", "ech"):
        prev = _SPLIT_PREV[k]
        if reset or prev is None or cur[k] < prev:
            deltas[k] = cur[k] if reset or prev is None else cur[k]
        else:
            deltas[k] = cur[k] - prev
        _SPLIT_PREV[k] = cur[k]
    _SPLIT_PREV["started"] = started
    if not any(deltas.values()):
        return
    hour = time.strftime("%Y-%m-%d %H", time.localtime())
    day = time.strftime("%Y-%m-%d", time.localtime())
    for tbl, key, val in (("warp_split_hour", "hour", hour),
                          ("warp_split_day", "day", day)):
        con.execute(
            "INSERT INTO %s(%s,ai,direct,qai,qdirect,nosni,ech) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(%s) DO UPDATE SET "
            "ai=ai+?, direct=direct+?, qai=qai+?, qdirect=qdirect+?, "
            "nosni=nosni+?, ech=ech+?" % (tbl, key, key),
            (val, deltas["ai"], deltas["direct"], deltas["qai"],
             deltas["qdirect"], deltas["nosni"], deltas["ech"],
             deltas["ai"], deltas["direct"], deltas["qai"],
             deltas["qdirect"], deltas["nosni"], deltas["ech"]))
    con.commit()


def warp_split_series(rng="24h"):
    """سریِ زمانیِ نسبتِ AI/کولترال (بایت) برای نمودار. rng: 24h/7d/30d."""
    now = time.time()
    if rng == "24h":
        table, col, fmt, span, step = ("warp_split_hour", "hour",
                                       "%Y-%m-%d %H", 24 * 3600, 3600)
    elif rng == "7d":
        table, col, fmt, span, step = ("warp_split_hour", "hour",
                                       "%Y-%m-%d %H", 7 * 86400, 3600)
    else:  # 30d
        table, col, fmt, span, step = ("warp_split_day", "day",
                                       "%Y-%m-%d", 30 * 86400, 86400)
    since = time.strftime(fmt, time.localtime(now - span))
    out = []
    try:
        con = sqlite3.connect(DB_PATH, timeout=10)
        try:
            cur = con.execute(
                "SELECT %s,ai,direct,qai,qdirect,nosni,ech FROM %s "
                "WHERE %s>=? ORDER BY %s" % (col, table, col, col), (since,))
            for t, ai, direct, qai, qdirect, nosni, ech in cur.fetchall():
                a = (ai or 0) + (qai or 0)
                d = (direct or 0) + (qdirect or 0)
                # «کور» یعنی نامی برای تصمیم‌گیری نداشتیم — یعنی فقط بی‌SNI.
                # ECH عمداً بیرون است: اکستنشنِ 0xfe0d که splitter می‌شمارد
                # با GREASEِ کروم یکی است و از هم تفکیک‌پذیر نیست، و ECHِ
                # واقعی بدونِ ECHConfig ناممکن است. اندازه‌گیریِ ۴ اوت ۲۰۲۶:
                # هیچ‌کدام از ۳۰ مقصد و هیچ‌کدام از کولترال‌های پرحجم ECHConfig
                # منتشر نمی‌کردند، و از ۲۶۱٬۹۵۴ اتصالِ «ECHدار» فقط ۳۷ تا SNI
                # نداشتند ⇒ همه GREASE بود و نامِ واقعی آشکار.
                # با احتسابِ ECH این نسبت ۶۷٪ خوانده می‌شد و آستانه‌ی ۲۵٪ را
                # می‌شکست؛ بدونش ۲۴٫۶٪ است. یعنی هشدار به سیگنالِ دروغ شلیک
                # می‌کرد. ⇒ ردیفِ ۳۲ سند و §۲۹٫۴۷.
                out.append({"t": t, "ai": a, "direct": d,
                            "tcp_ai": ai or 0, "tcp_direct": direct or 0,
                            "quic_ai": qai or 0, "quic_direct": qdirect or 0,
                            "blind": (nosni or 0), "ech": (ech or 0)})
        finally:
            con.close()
    except sqlite3.Error:
        pass
    tot_ai = sum(r["ai"] for r in out)
    tot_d = sum(r["direct"] for r in out)
    tot_blind = sum(r["blind"] for r in out)
    tot_ech = sum(r["ech"] for r in out)
    tot = tot_ai + tot_d
    return {"points": out, "range": rng,
            "total_ai": tot_ai, "total_direct": tot_d,
            "total_blind": tot_blind, "total_ech": tot_ech,
            "collateral_pct": round(100 * tot_d / tot) if tot else 0,
            "blind_pct": round(100 * tot_blind / tot) if tot else 0,
            "ech_pct": round(100 * tot_ech / tot) if tot else 0}


class WarpTraffic(threading.Thread):
    """نمونه‌بردارِ ۳۰ثانیه‌ایِ شمارنده‌های ipset (سبک: یک ipset list) +
    دلتای شمارنده‌های splitter برای نمودارِ نسبتِ بلندمدت."""

    INTERVAL = 30

    def __init__(self):
        super().__init__(daemon=True)

    def sample(self):
        if not os.path.isfile(WARP_SYNC):      # WARP نصب نیست
            return
        rc, out, _ = run(["ipset", "list", WARP_IPSET], timeout=8)
        if rc != 0:
            return
        cur = _parse_ipset_counters(out)
        with _WARP_TRAFFIC_LOCK:
            if not _WARP_TRAFFIC["since"]:
                _WARP_TRAFFIC["since"] = int(time.time())
            _warp_traffic_merge(_WARP_TRAFFIC["nets"], cur)

    def run(self):
        time.sleep(20)
        while True:
            _heartbeat("warptraffic")
            try:
                self.sample()
            except Exception as e:
                log_action("warp-traffic error: %r" % e)
            # نمونه‌ی دلتای splitter → جدولِ نسبت (اگر جراحیِ SNI روشن باشد)
            try:
                if warp_sni_enabled() or warp_sni_quic_enabled():
                    con = sqlite3.connect(DB_PATH, timeout=10)
                    try:
                        _warp_split_sample(con)
                    finally:
                        con.close()
            except Exception as e:
                log_action("warp-split sample error: %r" % e)
            time.sleep(self.INTERVAL)


WARPTRAFFIC = WarpTraffic()


def warp_status(force=False):
    """وضعیتِ کاملِ مسیریابیِ WARP برای پنل (کشِ ۱۰ثانیه‌ای)."""
    now = time.time()
    if not force and _WARP_CACHE["data"] and now - _WARP_CACHE["ts"] < 10:
        return _WARP_CACHE["data"]
    _d, _s, cfg = warp_sync_config()
    # مقصدها از targets.conf می‌آیند (منبعِ حقیقت، مدیریت‌شده از پنل) —
    # نه از آرایه‌های sync.sh که حالا داینامیک‌اند.
    targets = warp_targets_read()
    doms = [t for t in targets if not re.fullmatch(r"[0-9./]+", t)]
    static = [t for t in targets if re.fullmatch(r"[0-9./]+", t)]
    d = {"installed": os.path.isfile(WARP_SYNC),
         "domains": doms, "static_nets": static,
         "egress_want": cfg.get("egress", ""), "endpoint": cfg.get("warp_ep", ""),
         "users_src": cfg.get("users", ""), "resolver": cfg.get("resolver", ""),
         "iface": {"name": WARP_IFACE, "up": False}, "nets": [],
         "rules": {}, "service": {}, "account": ""}

    # --- اینترفیس: بالا/پایین + هندشیک + ترافیک (از wg dump، ارزان)
    up = WARP_IFACE in live_interfaces()
    d["iface"]["up"] = up
    if up:
        rc, out, _ = run(["wg", "show", WARP_IFACE, "dump"], timeout=5)
        if rc == 0:
            lines = [l for l in (out or "").splitlines() if l.strip()]
            for ln in lines[1:]:                  # خطِ اول = خودِ اینترفیس
                f = ln.split("\t")
                if len(f) >= 8:
                    hs = int(f[4] or 0)
                    d["iface"].update(
                        endpoint=f[2], handshake=hs,
                        handshake_age=(int(now - hs) if hs else None),
                        rx=int(f[5] or 0), tx=int(f[6] or 0))
                    break
        try:
            with open("/sys/class/net/%s/mtu" % WARP_IFACE) as f:
                d["iface"]["mtu"] = int(f.read().strip())
        except (OSError, ValueError):
            pass
        d["iface"]["rx_rate"] = tunnel_rx_rate(WARP_IFACE)
        d["account"] = _warp_account_type()

    # --- مقصدهای فعال (ipset زنده — با هر تغییرِ دامنه/IP خودش عوض می‌شود)
    rc, out, _ = run(["ipset", "list", "-o", "save", WARP_IPSET], timeout=8)
    if rc == 0:
        d["nets"] = sorted(l.split()[2] for l in (out or "").splitlines()
                           if l.startswith("add "))

    # --- سلامتِ قواعد (هرکدام نبود یعنی مسیر ناقص است)
    rc, mg, _ = run(["iptables", "-t", "mangle", "-S"], timeout=8)
    mg = mg or ""
    rc2, nt, _ = run(["iptables", "-t", "nat", "-S", "POSTROUTING"], timeout=8)
    nt = nt or ""
    # فقط قواعدِ MARK — از فازِ ۱ قواعدِ RETURNِ پورتِ ۵۳ هم ipset را
    # ارجاع می‌دهند و *قبل از* MARK نشسته‌اند؛ بدونِ این قید، اولین خطِ
    # PREROUTING همان RETURNِ بدونِ `-s` بود → «مبدأ ؟» در کارت (رگرسیونی
    # که کاربر دید) و mark_forward/mark_local حتی بدونِ MARK هم True می‌شد.
    mark_pre = [l for l in mg.splitlines()
                if "PREROUTING" in l and WARP_IPSET in l and "-j MARK" in l]
    d["rules"] = {
        "mark_forward": bool(mark_pre),
        "forward_src": (mark_pre[0].split("-s ")[1].split()[0]
                        if mark_pre and "-s " in mark_pre[0] else ""),
        "mark_local": any("OUTPUT" in l and WARP_IPSET in l
                          and "-j MARK" in l
                          for l in mg.splitlines()),
        "masquerade": ("-o %s -j MASQUERADE" % WARP_IFACE) in nt,
        "mss": next((l.split("--set-mss ")[1].split()[0]
                     for l in mg.splitlines()
                     if WARP_IFACE in l and "--set-mss" in l), ""),
    }
    rc, out, _ = run(["ip", "rule", "show"], timeout=5)
    d["rules"]["ip_rule"] = any(WARP_MARK in l and WARP_TABLE in l
                                for l in (out or "").splitlines())
    rc, out, _ = run(["ip", "route", "show", "table", WARP_TABLE], timeout=5)
    d["rules"]["table"] = WARP_IFACE in (out or "")
    d["ai_egress"] = ai_egress_diag()

    # --- مسیرِ خروجِ واقعیِ endpoint (باید تونلِ WGِ ساده باشد، نه awg1)
    if d["endpoint"]:
        rc, out, _ = run(["ip", "route", "get", d["endpoint"]], timeout=5)
        m = re.search(r"\bdev\s+(\S+)", out or "")
        d["egress_actual"] = m.group(1) if m else ""

    # --- سرویس و تایمرِ به‌روزرسانی
    for key, unit in (("service", WARP_UNIT), ("timer", WARP_TIMER)):
        rc, out, _ = run(["systemctl", "is-active", unit], timeout=5)
        act = (out or "").strip() == "active"
        rc, out, _ = run(["systemctl", "is-enabled", unit], timeout=5)
        d["service"][key] = {"active": act,
                             "enabled": (out or "").strip() == "enabled"}
    # تایمر مبنای مونوتونیک دارد (OnBootSec/OnUnitActiveSec)، پس
    # NextElapseUSecRealtime خالی است و باید از مونوتونیک تبدیل شود.
    tp = _unit_props(WARP_TIMER, ("NextElapseUSecRealtime",
                                  "NextElapseUSecMonotonic"))
    nxt = _sysd_ts(tp.get("NextElapseUSecRealtime"))
    if nxt is None:
        nxt = _monotonic_to_epoch(tp.get("NextElapseUSecMonotonic"))
    d["service"]["next_refresh"] = nxt
    sp = _unit_props("warp-gemini-refresh.service", ("ExecMainExitTimestamp",))
    d["service"]["last_refresh"] = _sysd_ts(sp.get("ExecMainExitTimestamp"))
    # آخرین اجرای *موفق* (مهرِ sync.sh) — last_refresh فقط «آخرین اجرا» است
    # و rc را نمی‌گوید؛ این یکی فقط با موفقیتِ کامل جلو می‌رود.
    _age = warp_sync_age()
    d["service"]["last_sync_ok"] = (int(now - _age) if _age is not None
                                    else None)

    # --- سلامتِ per-domain از فایل‌های کش (که sync.sh می‌نویسد)
    d["domain_health"] = warp_domain_health(doms)

    # --- QUIC: آیا drop روشن است؟ (نبودِ فایلِ off = روشن)
    d["quic_block"] = not os.path.exists(WARP_QUIC_OFF)

    # --- WarpGuard: زنده؟ حالت؟
    d["guard"] = warp_guard_state()

    # --- آخرین probeِ سطحِ اپلیکیشن (خودِ probe را AlertMonitor می‌زند؛
    #     اینجا فقط نتیجه‌ی ذخیره‌شده خوانده می‌شود تا status سریع بماند)
    with _WARP_PROBE_LOCK:
        d["probe"] = dict(_WARP_PROBE["trace"] or {})
        d["probe"]["ts"] = _WARP_PROBE["ts"]
        d["probe"]["gemini"] = _WARP_PROBE["gemini"]
        d["probe"]["warp_ttfb"] = _WARP_PROBE.get("warp_ttfb")
        d["probe"]["direct_ttfb"] = _WARP_PROBE.get("direct_ttfb")

    # --- ترافیکِ تجمعیِ per-block (نخِ WarpTraffic؛ برای سنجشِ کولترال)
    d["traffic"] = warp_traffic_snapshot()

    # --- جراحیِ SNI (splitter): وضعیت + آمارِ AI/کولترال
    d["sni"] = warp_sni_status()

    # --- کشفِ خودکار: این سرویس فهرستِ مقصدها را **خودش** عوض می‌کند، پس
    # شفافیتش لازم است. تا ۴ اوت ۲۰۲۶ فقط ربات نشانش می‌داد و پنل کور بود؛
    # یعنی اپراتوری که با مرورگر کار می‌کرد نمی‌دید فهرست چرا عوض شده.
    d["autodetect"] = warp_autodetect_state()

    # --- سلامتِ کلی: همه‌ی اجزا سرِ جا؟
    r = d["rules"]
    d["healthy"] = bool(d["iface"]["up"] and d["nets"] and r.get("mark_forward")
                        and r.get("mark_local") and r.get("masquerade")
                        and r.get("ip_rule") and r.get("table")
                        and d["service"]["service"]["active"])
    _WARP_CACHE.update(ts=now, data=d)
    return d


# داده‌ی شخصیِ داخلِ warp_status که نباید به هر بیننده‌ای برسد:
#   top_sni / top_sni_conns → نامِ سایت‌هایی که کاربران می‌روند
#   top_src                 → IP و مصرفِ AI به تفکیکِ کاربر
#   src_labels              → نگاشتِ IP به نامِ کاربر/تونل
WARP_PRIVATE_STATS = ("top_sni", "top_sni_conns", "top_src")


def warp_status_redacted(w, perms):
    """نسخه‌ی امنِ warp_status برای بیننده‌ای که warp.manage ندارد.

    روتِ /api/warp/status عمداً با tun.view باز است (نقشِ viewer هم داردش)
    تا سلامتِ مسیر دیده شود؛ ولی رابط جدول‌های SNI و مصرفِ per-user را پشتِ
    warp.manage پنهان می‌کند. بدونِ این تابع آن پنهان‌سازی فقط سمتِ کلاینت
    بود و با یک درخواستِ خام دور می‌خورد.

    **کپیِ کم‌عمق واجب است** — warp_status کشِ ۱۰ثانیه‌ای دارد و همان شیء را
    برمی‌گرداند، پس حذفِ درجا کش را برای مدیران هم می‌شکست.
    """
    if not isinstance(w, dict) or "warp.manage" in (perms or ()):
        return w

    def _strip(d):
        d = dict(d)
        d["src_labels"] = {}
        st = d.get("stats")
        if isinstance(st, dict):
            st = dict(st)
            for k in WARP_PRIVATE_STATS:
                st.pop(k, None)
            d["stats"] = st
        return d

    out = _strip(w)
    # کشفِ خودکار هم نامِ دامنه‌هایی است که کاربران رفته‌اند (همان طبقه‌ی
    # top_sni)، پس همان گیت را می‌گیرد. ربات هم کلِ بخشِ WARP را پشتِ
    # warp.manage گذاشته؛ بدونِ این خط، پنل همان نشت را از نو باز می‌کرد.
    out["autodetect"] = {}
    # 🪤 داده‌ی واقعی زیرِ d["sni"] است (warp_sni_status)، نه سطحِ بالا؛
    # رابط هم از w.sni.stats.top_sni می‌خواند. پیش از این فقط سطحِ بالا
    # پاک می‌شد — که هیچ‌وقت این کلیدها را نداشت — و top_sni/top_src و
    # نگاشتِ IP→کاربر برای هر دارنده‌ی tun.view (نقشِ viewer) می‌رفت.
    if isinstance(out.get("sni"), dict):
        out["sni"] = _strip(out["sni"])
    return out


WARP_CACHE_DIR = "/opt/wg-panel/warp-cache"
WARP_QUIC_OFF = "/opt/wg-panel/warp-quic-off"


# تله‌ی ECH — کشِ ساعتی تا حلقه‌ی هشدار DNS را نکوبد.
_ECH_PROBE = {"ts": 0.0, "hits": []}
ECH_PROBE_TTL = 3600


def warp_ech_publishers(domains, force=False):
    """کدام مقصد رکوردِ HTTPS با پارامترِ `ech=` منتشر می‌کند؟

    **چرا این سنجه و نه شمردنِ اکستنشن:** اکستنشنِ 0xfe0d که splitter
    می‌شمارد با GREASEِ کروم یکی است و تفکیک‌پذیر نیست، پس عددش معنای
    «کوری» نمی‌دهد (اندازه‌گیریِ ۴ اوت ۲۰۲۶: ۴۳GB «ECHدار» ولی صفر دامنه‌ی
    منتشرکننده ⇒ همه‌اش GREASE بود). ECHِ واقعی بدونِ ECHConfig **ناممکن**
    است، پس تنها لحظه‌ای که طبقه‌بندیِ SNI واقعاً می‌شکند همان لحظه‌ای است
    که یکی از مقصدها ECHConfig منتشر کند — و این تابع دقیقاً آن را می‌بیند.

    آن روز خطرناک‌تر از یک خرابیِ معمولی است: با ECHِ واقعی، کشفِ خودکار هم
    کور می‌شود (دامنه هرگز به‌عنوان کاندید ظاهر نمی‌شود)، یعنی خرابی خودش را
    پنهان می‌کند — همان الگوی notebook.google.com ولی در مقیاسِ بزرگ‌تر.

    شکستِ DNS «بدونِ ECH» گزارش می‌شود، نه هشدار: مثبتِ کاذب اینجا یعنی
    هشدارِ بی‌جهت درباره‌ی چیزی که کاربر نمی‌تواند رفعش کند.
    """
    now = time.time()
    if not force and _ECH_PROBE["ts"] and now - _ECH_PROBE["ts"] < ECH_PROBE_TTL:
        return list(_ECH_PROBE["hits"])
    hits = []
    for d in domains:
        if re.fullmatch(r"[0-9./]+", d) or "/" in d:   # پیشوندِ IP، نه دامنه
            continue
        rc, out, _ = run(["dig", "+short", "@%s" % WARP_ECH_RESOLVER,
                          d, "HTTPS"], timeout=8)
        if rc == 0 and "ech=" in (out or "").lower():
            hits.append(d)
    _ECH_PROBE.update(ts=now, hits=list(hits))
    return hits


def warp_domain_health(domains):
    """سلامتِ per-domain از فایل‌های کش: آخرین resolve، تعداد بلوک، کهنه؟"""
    out = []
    now = time.time()
    for d in domains:
        # نامِ دامنه اعتبارسنجی‌شده است؛ ولی برای احتیاط از basename جلوگیری
        if "/" in d or ".." in d:
            continue
        info = {"domain": d, "last": None, "nets": 0, "stale": True}
        try:
            with open(os.path.join(WARP_CACHE_DIR, d), encoding="utf-8") as f:
                lines = f.read().splitlines()
            if lines and lines[0].strip().isdigit():
                info["last"] = int(lines[0].strip())
                info["nets"] = sum(1 for l in lines[1:] if l.strip())
                info["stale"] = (now - info["last"]) > 3600
        except OSError:
            pass
        out.append(info)
    return out


# ============================================================================
# ممیزیِ نشتِ DNS/IPv6 — کاملاً خواندنی، هیچ چیزی را تغییر نمی‌دهد
# ============================================================================
# پس‌زمینه (ممیزیِ ۴ اوت ۲۰۲۶، ردیفِ بازِ ۱۶): «نشتِ DNS» در این سرور یک
# سؤالِ ساده‌ی بله/خیر نیست، چون دو چیزِ متفاوت با هم اشتباه می‌شوند:
#
#   ۱) آیا کوئری به BIND می‌رسد؟  (DNAT شفاف — فقط برای resolverهای فهرست‌شده)
#   ۲) آیا کوئری از تونل می‌رود؟  (مسیر — تعیین‌کننده‌ی «ISP می‌بیند یا نه»)
#
# اندازه‌گیریِ آن روز نشان داد resolverِ فهرست‌نشده BIND را دور می‌زند **ولی
# همچنان از تونل می‌رود** — یعنی افتِ یکپارچگی است، نه نشتِ حریمِ خصوصی.
# این تفکیک تنها چیزی است که این ممیزی را از یک چراغِ سبز/قرمزِ گمراه‌کننده
# جدا می‌کند، پس هر دو محور جدا گزارش می‌شوند.
DNS_LEAK_PROBES = ("8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
                   "94.140.14.14", "45.90.28.0", "77.88.8.8")
DNS_TRANSPARENT_SET = "COMMON_DNS"


# ------------------------------------------------------ تشخیصِ مسیر و نشتِ DNS

def _route_dev(dst, src="", iif=""):
    """اینترفیسِ خروجیِ یک مقصد، اختیاراً از دیدِ یک مبدأ/ورودیِ مشخص.

    `ip route get` تنها راهِ درستِ سنجشِ مسیر است؛ `ping -I` فقط آدرسِ مبدأ را
    عوض می‌کند و مسیر را اثبات نمی‌کند (قاعده‌ی مؤکدِ CLAUDE.md)."""
    cmd = ["ip", "route", "get", dst]
    if src:
        cmd += ["from", src]
    if iif:
        cmd += ["iif", iif]
    rc, out, _ = run(cmd, timeout=5)
    if rc != 0:
        return ""
    m = re.search(r"\bdev\s+(\S+)", out or "")
    return m.group(1) if m else ""


def _wan_iface():
    """اینترفیسِ مسیرِ پیش‌فرض (خروجِ مستقیم). مبنای «تونل است یا نه»."""
    rc, out, _ = run(["ip", "route", "show", "default"], timeout=5)
    if rc != 0:
        return ""
    m = re.search(r"\bdev\s+(\S+)", (out or "").splitlines()[0] if out else "")
    return m.group(1) if m else ""


def _sample_user_ip(subnet):
    """یک آدرسِ نمونه داخلِ سابنتِ کاربران، برای `ip route get … from`.

    `.1` معمولاً خودِ سرور است، پس `.11` گرفته می‌شود تا مسیر از دیدِ یک
    کاربرِ واقعی سنجیده شود نه از دیدِ خودِ گیت‌وی."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = net.network_address + 11
        return str(hosts) if hosts in net else str(net.network_address + 2)
    except (ValueError, TypeError):
        return ""


def user_ingress_ifaces():
    """اینترفیس‌هایی که ترافیکِ کاربر از آن‌ها وارد می‌شود.

    منبع عمداً **خودِ قواعدِ کیل‌سوییچ** است (`iif X prohibit`)، نه
    `CONFIG["user_subnets"]`: آن کلید روی این سرور خالی است و هر منطقی که
    به آن تکیه کند بی‌صدا به دیدِ *سرور* می‌افتد — که مسیرِ متفاوتی دارد،
    چون قواعدِ کیل‌سوییچ فقط روی مسیرِ کاربر اثر می‌گذارند. این تفاوت دقیقاً
    همان چیزی است که یک ممیزیِ نشت باید ببیند (کشف‌شده ۴ اوت ۲۰۲۶)."""
    rc, out, _ = run(["ip", "rule", "show"], timeout=5)
    if rc != 0:
        return []
    seen, res = set(), []
    for m in re.finditer(r"iif (\S+) prohibit", out or ""):
        ifc = m.group(1)
        if ifc not in seen:
            seen.add(ifc)
            res.append(ifc)
    return res


def iface_connected_subnet(ifc):
    """سابنتِ متصل به یک اینترفیس، از جدولِ مسیر.

    آدرسِ خودِ اینترفیس کافی نیست: `wg1udp` آدرسِ `/32` دارد و پیشوندِ
    واقعیِ کاربران (`/24`) فقط به‌صورتِ مسیرِ متصل روی همان دستگاه دیده
    می‌شود."""
    rc, out, _ = run(["ip", "route", "show", "dev", ifc], timeout=5)
    if rc != 0:
        return ""
    for ln in (out or "").splitlines():
        pre = ln.split()[0] if ln.split() else ""
        if "/" in pre and not pre.startswith("default"):
            try:
                ipaddress.ip_network(pre, strict=False)
                return pre
            except ValueError:
                continue
    return ""


def dns_leak_audit():
    """ممیزیِ نشتِ DNS و IPv6 — فقط می‌خوانَد، هیچ تغییری نمی‌دهد.

    خروجی عمداً «یافته‌محور» است نه صرفاً داده‌محور: هر یافته سطح
    (`ok`/`warn`/`bad`) و متنِ خودش را دارد، تا رابط و ربات یک روایت را
    نشان دهند و تفسیرِ موازی نسازند.
    """
    wan = _wan_iface()
    tunneled = lambda dev: bool(dev) and dev != wan and not dev.startswith("eth")
    out = {"wan": wan, "resolver": {}, "transparent": {}, "probes": [],
           "ipv6": {}, "findings": [], "verdict": "ok"}

    # ---- ۱) خودِ resolver ----------------------------------------------
    cfg = {}
    try:
        _d, _s, cfg = warp_sync_config()
    except Exception:
        cfg = {}
    rip = (cfg.get("resolver") or "").strip() or WARP_ECH_RESOLVER
    rc, sso, _ = run(["ss", "-ulnH", "sport", "=", ":53"], timeout=5)
    listening = bool(rc == 0 and rip and rip in (sso or ""))
    regress = _route_dev("1.1.1.1", src=rip) if rip else ""
    out["resolver"] = {"ip": rip, "listening": listening, "egress": regress,
                       "tunneled": tunneled(regress)}

    # ---- ۲) DNATِ شفاف: کدام کوئری‌ها اجباراً به BIND می‌روند ------------
    rc, nat, _ = run(["iptables", "-t", "nat", "-S", "PREROUTING"], timeout=8)
    lines = [l for l in (nat or "").splitlines() if "--dport 53" in l]
    forced = [l for l in lines if "--match-set" in l and "DNAT" in l]
    catchall = [l for l in lines if "--match-set" not in l and "DNAT" in l]
    ifaces = sorted({m.group(1) for l in forced
                     for m in [re.search(r"-i (\S+)", l)] if m})
    members = 0
    rc2, ips, _ = run(["ipset", "list", DNS_TRANSPARENT_SET], timeout=8)
    if rc2 == 0:
        m = re.search(r"Number of entries:\s*(\d+)", ips or "")
        members = int(m.group(1)) if m else 0
    out["transparent"] = {"set": DNS_TRANSPARENT_SET, "members": members,
                          "ifaces": ifaces, "rules": len(forced),
                          "catchall": bool(catchall)}

    # ---- ۳) پروبِ هر resolver: اجباری؟ و از کجا می‌رود؟ ------------------
    ingress = user_ingress_ifaces()
    src_iface, src_ip = "", ""
    for ifc in ingress:
        ip = _sample_user_ip(iface_connected_subnet(ifc))
        if ip:
            src_iface, src_ip = ifc, ip
            break
    for d in DNS_LEAK_PROBES:
        rc3, _o, _e = run(["ipset", "test", DNS_TRANSPARENT_SET, d], timeout=5)
        dev = _route_dev(d, src=src_ip, iif=src_iface) if src_ip else _route_dev(d)
        out["probes"].append({"ip": d, "forced": rc3 == 0, "egress": dev,
                              "tunneled": tunneled(dev)})
    out["probe_src"] = {"iface": src_iface, "ip": src_ip}

    # ---- ۴) IPv6 -------------------------------------------------------
    sysctl = lambda k: (run(["sysctl", "-n", k], timeout=5)[1] or "").strip()
    rc4, r6, _ = run(["ip", "-6", "route", "show", "default"], timeout=5)
    globals6 = []
    for ifc in ingress:
        rc5, a6, _ = run(["ip", "-6", "addr", "show", ifc], timeout=5)
        for m in re.finditer(r"inet6 (\S+)", a6 or ""):
            if not m.group(1).lower().startswith("fe80"):
                globals6.append("%s:%s" % (ifc, m.group(1)))
    out["ipv6"] = {
        "disabled": sysctl("net.ipv6.conf.all.disable_ipv6") == "1",
        "forwarding": sysctl("net.ipv6.conf.all.forwarding") == "1",
        "default_route": bool(rc4 == 0 and (r6 or "").strip()),
        "global_addrs": globals6}

    # ---- ۵) یافته‌ها ----------------------------------------------------
    add = lambda lvl, txt: out["findings"].append({"level": lvl, "text": txt})
    r = out["resolver"]
    if not r["ip"]:
        add("bad", "آدرسِ resolverِ کاربران پیدا نشد")
    elif not r["listening"]:
        add("bad", "BIND روی %s:۵۳ گوش نمی‌دهد — DNSِ کاربران قطع است" % r["ip"])
    elif not r["tunneled"]:
        add("bad", "کوئریِ خودِ BIND از «%s» می‌رود، نه از تونل — "
                   "ISP مقصدها را می‌بیند" % (r["egress"] or "؟"))
    else:
        add("ok", "BIND روی %s گوش می‌دهد و کوئری‌هایش از «%s» می‌رود"
                  % (r["ip"], r["egress"]))

    t = out["transparent"]
    if not t["rules"]:
        add("bad", "هیچ قاعده‌ی DNATِ شفافی نیست — کوئری‌ها به BIND هدایت نمی‌شوند")
    else:
        add("ok", "DNATِ شفاف روی %s فعال است (%s resolverِ فهرست‌شده)"
                  % ("، ".join(t["ifaces"]) or "؟", _fa_num(t["members"])))
    if not t["catchall"]:
        bypass = [p for p in out["probes"] if not p["forced"]]
        leaked = [p for p in bypass if not p["tunneled"]]
        if leaked:
            add("bad", "resolverِ فهرست‌نشده هم BIND را دور می‌زند و هم از "
                       "تونل نمی‌رود ⇒ نشتِ واقعی: %s"
                       % "، ".join(p["ip"] for p in leaked))
        elif bypass:
            add("warn", "قاعده‌ی همه‌گیر نیست: resolverِ فهرست‌نشده BIND را دور "
                        "می‌زند (افتِ یکپارچگی) ولی همچنان از تونل می‌رود، پس "
                        "ISP آن را نمی‌بیند")
        else:
            add("ok", "همه‌ی resolverهای آزموده‌شده اجباراً به BIND می‌روند")

    v = out["ipv6"]
    if v["global_addrs"]:
        add("bad", "آدرسِ IPv6ِ سراسری روی اینترفیسِ کاربر: %s"
                   % "، ".join(v["global_addrs"]))
    elif v["default_route"]:
        add("bad", "مسیرِ پیش‌فرضِ IPv6 وجود دارد — ترافیک می‌تواند تونل را دور بزند")
    elif v["disabled"]:
        add("ok", "IPv6 در کرنل خاموش است و آدرسِ سراسری/مسیرِ پیش‌فرضی نیست")
    else:
        add("warn", "IPv6 خاموش نیست، ولی مسیرِ پیش‌فرض و آدرسِ سراسری ندارد — "
                    "فعلاً راهِ خروجی نیست")

    lv = [f["level"] for f in out["findings"]]
    out["verdict"] = "bad" if "bad" in lv else ("warn" if "warn" in lv else "ok")
    return out


# ------------------------------------------------------- گاردهای ECMP و WARP

def warp_guard_state():
    """وضعیتِ WarpGuard از heartbeat/state (بدونِ دسترسی به نخِ گارد)."""
    g = {"alive": False, "egress": "", "rule": "on", "enabled":
         bool((CONFIG.get("warp_guard") or WARP_GUARD_DEFAULTS).get(
             "enabled", True))}
    try:
        with open(WARP_GUARD_HEARTBEAT, encoding="utf-8") as f:
            hb = int((f.read().strip() or "0"))
        g["alive"] = (time.time() - hb) < 60
    except (OSError, ValueError):
        pass
    try:
        with open(WARP_GUARD_STATE, encoding="utf-8") as f:
            for ln in f:
                k, _, v = ln.strip().partition("=")
                if k == "egress":
                    g["egress"] = v
                elif k == "rule":
                    g["rule"] = v
    except OSError:
        pass
    return g


def ecmp_tunnel_state(iface, dead_after):
    """وضعیتِ سلامتِ یک تونلِ ECMP برای guard:
      down    = اینترفیس بالا نیست (PreDown مسیرها را برداشته)
      healthy = بالا و (هندشیکِ تازه یا در حالِ دریافتِ داده)
      dead    = بالا ولی هندشیک کهنه و هیچ دریافتی (بازهٔ گذارِ خطرناک)

    نکتهٔ کلیدی: WireGuard هر ~۱۲۰ ثانیه یک‌بار هندشیک می‌کند، پس «سنِ
    هندشیک» به‌تنهایی سیگنالِ مطمئنی نیست (dead_after باید > ۱۲۰ باشد).
    حرکتِ rx سیگنالِ قطعیِ زنده‌بودن است: تونلی که داده می‌گیرد، زنده است.

    ترتیبِ سنجش عمدی است. اگر اول سنِ هندشیک بررسی شود، «تونلِ زامبی»
    (هندشیکِ تازه ولی سمتِ مقابل دیگر forward نمی‌کند) در همان شرطِ اول
    healthy برمی‌گردد و بررسیِ rx هرگز اجرا نمی‌شود — تونل مرده در ECMP
    می‌مانَد و نیمی از ترافیک بی‌صدا بلک‌هول می‌شود. پس اول سیگنالِ ارزان
    و قطعی (rx) می‌آید؛ و وقتی rx ساکت است — که هم برای تونلِ بیکارِ سالم
    و هم برای زامبی صادق است — با یک probeِ فعال این دو را جدا می‌کنیم:
    بیکارِ سالم به ping پاسخ می‌دهد، زامبی نه.
    """
    if iface not in live_interfaces():
        return "down"
    if tunnel_rx_rate(iface) > 0:      # در حالِ دریافت = قطعاً زنده
        return "healthy"
    age = tunnel_handshake_age(iface)
    if age is not None and age < dead_after:
        # هندشیکِ تازه ولی rx ساکت: بیکارِ سالم یا زامبی؟ probe جدا می‌کند.
        return "healthy" if tunnel_data_plane_ok(iface) else "dead"
    return "dead"


class EcmpGuard(threading.Thread):
    """ترمیمِ ECMP در بازهٔ گذار (opt-in با config['ecmp_guard']).

    مشکل: وقتی یک تونلِ ECMP اینترفیسش بالا می‌ماند ولی تونل می‌میرد
    (بدونِ هندشیک)، nexthopِ آن در مسیرهای آن مجموعه می‌مانَد و نیمی از
    ترافیک بلک‌هول می‌شود — چون PreDown فقط با پایین‌آمدنِ اینترفیس اجرا
    می‌شود.

    راه‌حل: به‌محضِ تشخیصِ «بالا ولی مرده»، همان اسکریپتِ
    awg-ecmp-from-file.sh را با action=down صدا می‌زنیم تا nexthopِ تونلِ
    مرده از مسیرها حذف شود؛ ترافیک به تونلِ سالمِ دیگر (یا در نبودش، به
    مسیرِ پیش‌فرضِ awg1) می‌افتد. با بازگشتِ هندشیک، action=up دوباره اضافه
    می‌کند. edge-triggered: اسکریپت فقط هنگامِ تغییرِ وضعیت اجرا می‌شود.

    **چندگروهی:** هر «مجموعه‌مسیر» (گوگل، و هر مجموعهٔ دیگری که بسازید) یک
    گروه با routes_file/tunnels/weight/table خودش است. سلامتِ یک تونل یک‌بار
    سنجیده می‌شود، ولی عضویتِ nexthop برای هر گروه جداگانه دنبال می‌شود —
    چون یک تونل می‌تواند در چند مجموعه‌مسیر شرکت کند.
    """

    INTERVAL = 12

    def __init__(self):
        super().__init__(daemon=True)
        self.membership = {}   # (گروه، iface) -> "in" | "out"
        self.dead_streak = {}  # iface -> تعدادِ چرخه‌های متوالیِ «مرده»

    def cfg(self):
        return CONFIG.get("ecmp_guard") or {}

    def enabled(self):
        c = self.cfg()
        return bool(c.get("enabled")) and bool(ecmp_groups(c))

    def _sampler_ready(self):
        """تا وقتی SAMPLER دادهٔ تازهٔ peer نگرفته، قضاوت نکن (ضدِ گذارِ استارتاپ)."""
        snap = SAMPLER.snapshot()
        return bool(snap.get("peers")) and \
            (time.time() - snap.get("ts", 0)) < 15

    def reconcile(self):
        if not self.enabled() or not self._sampler_ready():
            return
        c = self.cfg()
        script = c.get("script", ECMP_GUARD_DEFAULTS["script"])
        dead_after = float(c.get("dead_after", 150))
        confirm = max(1, int(c.get("confirm", 2)))   # چرخه‌های تأییدِ مرگ
        groups = ecmp_groups(c)
        # سلامتِ هر تونل یک‌بار (نه یک‌بار به‌ازای هر گروه) سنجیده می‌شود
        states = {t: ecmp_tunnel_state(t, dead_after)
                  for g in groups for t in g["tunnels"]}
        for t, state in states.items():
            if state == "dead":
                self.dead_streak[t] = self.dead_streak.get(t, 0) + 1
            else:                            # healthy یا down
                self.dead_streak[t] = 0
        for g in groups:
            for t in g["tunnels"]:
                self._apply(g, t, states[t], script, confirm)

    def _apply(self, g, t, state, script, confirm):
        """عضویتِ nexthopِ یک تونل در یک گروه را با وضعیتِ سلامتش هماهنگ کن."""
        key = (g["name"], t)
        prev = self.membership.get(key)
        if state == "down":
            self.membership[key] = "out"     # PreDown مسیرها را برداشته
            return
        # هیسترزیس: حذف فقط پس از تأییدِ چند چرخهٔ متوالیِ مرگ؛
        # افزودنِ دوباره (بازگشت) فوری است.
        desired = "out" if self.dead_streak.get(t, 0) >= confirm else "in"
        if prev == desired:
            return
        action = "up" if desired == "in" else "down"
        rc, out, err = run([script, action, g["routes_file"], t,
                            str(g["weight"]), g["table"]], timeout=90)
        ok = rc == 0
        if ok:
            self.membership[key] = desired
        label = g["name"] or g["routes_file"]
        log_action("ecmp-guard[%s]: %s %s (%s، streak=%d) -> %s"
                   % (label, t, action, state, self.dead_streak.get(t, 0),
                      "ok" if ok else (err or "err")[:120]))
        if action == "down" and ok:
            ALERTS.event("ecmp",
                         A('alert.apply.1', p0=t, p1=label))
        elif action == "up" and ok and prev is not None:
            # فقط بازگشتِ *واقعی* (out → in) خبر دارد. prev=None یعنی
            # همگام‌سازیِ استارتاپ: بعد از هر restartِ پنل، membershipِ
            # حافظه‌ای خالی است و تونلِ همیشه-سالم دوباره «up» می‌شود —
            # کاربر بعد از هر استقرار پیامِ گمراه‌کننده‌ی «دوباره سالم شد»
            # می‌گرفت، درحالی‌که هیچ رخدادی نبود (فقط log کافی است).
            ALERTS.event("ecmp",
                         A('alert.apply.2', p0=t, p1=label))

    def run(self):
        while True:
            _heartbeat("ecmpguard")
            time.sleep(self.INTERVAL)
            try:
                self.reconcile()
            except Exception as e:
                log_action("ecmp-guard error: %r" % e)


ECMPGUARD = EcmpGuard()


def warp_iface_up(iface):
    """اینترفیس وجود دارد و بالاست؟ (ارزان، برای انتخابِ egress)."""
    return iface in live_interfaces()


def warp_egress_actual(ep=None):
    """endpointِ وارپ الان از کدام dev می‌رود (خالی اگر نامعلوم).

    ep = endpointِ زنده‌ی wgwarp. بدونِ آن به ثابتِ WARP_EP_IP می‌افتد که
    فقط fallbackِ «endpoint ناخوانا» است — endpoint روی anycast روم می‌کند
    (autodetect/چرخش) و سنجشِ ثابتِ کهنه یعنی سنجیدنِ مسیری که ترافیک از
    آن نمی‌رود."""
    rc, out, _ = run(["ip", "route", "get", ep or WARP_EP_IP], timeout=5)
    m = re.search(r"\bdev\s+(\S+)", out or "") if rc == 0 else None
    return m.group(1) if m else ""


def warp_rule_present():
    rc, out, _ = run(["ip", "rule", "show"], timeout=5)
    return any(WARP_MARK in l and WARP_TABLE in l
               for l in (out or "").splitlines())


# ---- جراحیِ SNI: سلامت و مدیریتِ قاعدهٔ TPROXY (برای fail-open) --------------
def warp_sni_enabled():
    """آیا جراحیِ SNI روشن است؟ (وجودِ فایلِ marker)"""
    return os.path.isfile(WARP_SNI_MARK_FILE)


def warp_sni_healthy():
    """splitter سالم است؟ heartbeatِ تازه (< ۱۲ث؛ heartbeat هر ۳ث = ۴ ضربه
    تحمل). نبودِ فایل = ناسالم. کوتاه‌تر = fail-open سریع‌تر روی مرگِ دیمن؛
    مرگِ گذرا را systemd با RestartSec=2 پیش از رسیدن به این آستانه می‌پوشاند."""
    try:
        with open(WARP_SNI_HEARTBEAT, "r", encoding="utf-8") as f:
            hb = int((f.readline() or "0").strip() or "0")
    except (OSError, ValueError):
        return False
    return 0 < (time.time() - hb) < 12


_SNI_TPROXY_ARGS = [
    "-s", "192.168.0.0/16", "-p", "tcp", "--dport", "443",
    "-m", "set", "--match-set", WARP_IPSET, "dst",
    "-j", "TPROXY", "--on-port", WARP_SNI_PORT,
    "--tproxy-mark", WARP_SNI_DIVERT_MARK + "/" + WARP_SNI_DIVERT_MARK]


def warp_sni_tproxy_present():
    rc, _o, _e = run(["iptables", "-t", "mangle", "-C", "PREROUTING"]
                     + _SNI_TPROXY_ARGS, timeout=5)
    return rc == 0


def warp_sni_set_tproxy(want):
    """قاعدهٔ TPROXY را به وضعیتِ دلخواه می‌رساند (idempotent). True=حاضر
    باشد (splitter سالم)، False=نباشد (fail-open به blanket WARP)."""
    present = warp_sni_tproxy_present()
    if want and not present:
        run(["iptables", "-t", "mangle", "-I", "PREROUTING", "1"]
            + _SNI_TPROXY_ARGS, timeout=5)
        return True
    if not want and present:
        # حذفِ همهٔ نسخه‌ها
        for _ in range(8):
            rc, _o, _e = run(["iptables", "-t", "mangle", "-D", "PREROUTING"]
                             + _SNI_TPROXY_ARGS, timeout=5)
            if rc != 0:
                break
        return True
    return False


# ---- QUIC (UDP/443): TPROXY ↔ REJECT با fail-open ---------------------------
def warp_sni_quic_enabled():
    return os.path.isfile(WARP_SNI_QUIC_MARK_FILE)


_SNI_QUIC_TPROXY_ARGS = [
    "-s", "192.168.0.0/16", "-p", "udp", "--dport", "443",
    "-m", "set", "--match-set", WARP_IPSET, "dst",
    "-j", "TPROXY", "--on-port", WARP_SNI_QUIC_PORT,
    "--tproxy-mark", WARP_SNI_DIVERT_MARK + "/" + WARP_SNI_DIVERT_MARK]
_QUIC_REJECT_FWD = [
    "-s", "192.168.0.0/16", "-p", "udp", "--dport", "443",
    "-m", "set", "--match-set", WARP_IPSET, "dst",
    "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]
_QUIC_REJECT_OUT = [
    "-p", "udp", "--dport", "443",
    "-m", "set", "--match-set", WARP_IPSET, "dst",
    "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]


def warp_sni_quic_tproxy_present():
    rc, _o, _e = run(["iptables", "-t", "mangle", "-C", "PREROUTING"]
                     + _SNI_QUIC_TPROXY_ARGS, timeout=5)
    return rc == 0


def _rule(op, table, chain, args):
    cmd = ["iptables"]
    if table:
        cmd += ["-t", table]
    return run(cmd + [op, chain] + args, timeout=5)


def warp_sni_set_quic(want):
    """QUIC را به وضعیتِ دلخواه می‌رساند (idempotent، mutually-exclusive):
      want=True  (سالم): UDP TPROXY حاضر، REJECT غایب (تفکیکِ QUIC فعال).
      want=False (fail-open): UDP TPROXY غایب، REJECT حاضر (مرورگر→TCP).
    خروجی: True اگر چیزی عوض شد."""
    changed = False
    present = warp_sni_quic_tproxy_present()
    rej = _rule("-C", None, "FORWARD", _QUIC_REJECT_FWD)[0] == 0
    if want:
        if not present:
            _rule("-I", "mangle", "PREROUTING", ["1"] + _SNI_QUIC_TPROXY_ARGS)
            changed = True
        if rej:
            for _ in range(8):
                if _rule("-D", None, "FORWARD", _QUIC_REJECT_FWD)[0] != 0:
                    break
            for _ in range(8):
                if _rule("-D", None, "OUTPUT", _QUIC_REJECT_OUT)[0] != 0:
                    break
            changed = True
    else:
        if present:
            for _ in range(8):
                if run(["iptables", "-t", "mangle", "-D", "PREROUTING"]
                       + _SNI_QUIC_TPROXY_ARGS, timeout=5)[0] != 0:
                    break
            changed = True
        if not rej and not os.path.isfile(WARP_QUIC_OFF):
            _rule("-A", None, "FORWARD", _QUIC_REJECT_FWD)
            _rule("-A", None, "OUTPUT", _QUIC_REJECT_OUT)
            changed = True
    return changed


class FlapGate:
    """ضدِ رگبار برای هشدارِ لبه‌ایِ قطع/وصلِ یک موضوع (مثلاً سلامتِ splitter).

    حادثه‌ی ۲۰۲۶-۰۷-۲۱: اشباعِ fdِ دیمنِ SNI سلامتش را هر ~۴۵ ثانیه قطع/وصل
    کرد و چون هر گذر یک ALERTS.event بود، ربات در ~۲.۵ ساعت ~۳۶۰ پیامِ
    تکراری فرستاد. گذرِ منفرد ارزشمند است و باید فوری برسد؛ ولی وقتی گذرها
    پشتِ‌سرِهم شدند (flap)، پیامِ درست «ناپایدار شده» است — یک‌بار — و بعد
    سکوت تا آرامش، و در پایان یک جمع‌بندی.

    قرارداد: هر گذرِ واقعیِ وضعیت flip() صدا بزند؛ خروجی:
      "send"  → پیامِ عادیِ همان گذر فرستاده شود (وضعِ عادی)
      "storm" → به‌جای آن، اعلانِ یک‌باره‌ی «ناپایدار شد» فرستاده شود
      None    → در دلِ طوفانیم؛ هیچ پیامی نه
    و هر چرخه‌ی پایش poll() صدا زده شود: اگر طوفان با QUIET ثانیه‌ی بی‌گذر
    تمام شده باشد، شمارِ گذرهای ساکت‌شده را برمی‌گرداند (برای جمع‌بندی)،
    وگرنه None. زمانِ تزریقی (پارامترِ now) فقط برای تست است.
    """

    WINDOW = 600.0    # پنجره‌ی لغزانِ شمارشِ گذرها
    STORM_AT = 3      # این تعداد گذر در پنجره = طوفان
    QUIET = 600.0     # این‌قدر بی‌گذر = پایانِ طوفان

    def __init__(self):
        self.flips = []      # زمانِ گذرهای اخیر (داخلِ WINDOW)
        self.storm = False
        self.muted = 0       # گذرهای ساکت‌شده در طوفانِ جاری

    def flip(self, now=None):
        now = time.time() if now is None else now
        self.flips = [t for t in self.flips if now - t < self.WINDOW]
        self.flips.append(now)
        if self.storm:
            self.muted += 1
            return None
        if len(self.flips) >= self.STORM_AT:
            self.storm = True
            self.muted = 0
            return "storm"
        return "send"

    def poll(self, now=None):
        now = time.time() if now is None else now
        if self.storm and now - self.flips[-1] >= self.QUIET:
            muted = self.muted
            self.storm = False
            self.flips = []
            self.muted = 0
            return muted
        return None


# --------------------------------------------------------------- نگهبانِ WARP



class WarpGuard(threading.Thread):
    """تاب‌آوریِ مسیریابیِ WARP (opt-in، پیش‌فرض روشن). دو کار:

    ۱) **failoverِ egress:** endpointِ وارپ باید از یک تونلِ WireGuardِ ساده
       برود (primary=wg22؛ اگر مرد، backup=wg21). اگر wg22 بمیرد، مسیرِ
       /32ِ endpoint حذف می‌شود و به awg1 می‌افتد که دیتای WARP را می‌شکند؛
       این‌جا فوری به تونلِ سالم می‌بندیم.

    ۲) **graceful degradation:** اگر خودِ wgwarp چند چرخهٔ متوالی مرده بماند
       (endpoint در دسترس نیست)، `ip rule` را برمی‌داریم تا ترافیکِ AI به‌جای
       **بلک‌هول** (هنگِ ۳۰ثانیه‌ای) به مسیرِ عادی برگردد (بلاک ولی سریع)؛
       با بازگشتِ wgwarp دوباره برقرار می‌شود.

    هماهنگی با sync.sh: گارد هر چرخه یک heartbeat می‌نویسد و egress/ruleِ
    انتخابی‌اش را در فایلِ state می‌گذارد؛ sync.sh اگر heartbeat تازه بود به
    گارد واگذار می‌کند، وگرنه خودش مدیریت می‌کند (پنل خاموش = fallback).
    """

    INTERVAL = 12

    def __init__(self):
        super().__init__(daemon=True)
        self.dead_streak = 0
        self.degraded = False        # آیا ما ip rule را برداشته‌ایم؟
        self.ep_idx = 0              # جای فعلی در استخرِ endpoint
        self.rot_count = 0           # چند چرخش در این قطعی (برای استندبای)
        self.rotated_alerted = False # فقط اولین چرخشِ هر قطعی هشدار بدهد
        self.current_ep = ""         # endpointِ فعال (برای state/sync)
        self.sni_ok = None           # آخرین سلامتِ splitter (برای هشدارِ لبه)
        self.quic_ok = None          # آخرین سلامتِ تفکیکِ QUIC (هشدارِ لبه)
        self.sni_gate = FlapGate()   # ضدِ رگبارِ پیامِ قطع/وصلِ splitter
        self.quic_gate = FlapGate()  # ضدِ رگبارِ پیامِ قطع/وصلِ تفکیکِ QUIC

    def cfg(self):
        c = dict(WARP_GUARD_DEFAULTS)
        c.update(CONFIG.get("warp_guard") or {})
        return c

    def _peer_pub(self):
        rc, out, _ = run(["wg", "show", WARP_IFACE, "peers"], timeout=5)
        return (out or "").strip().splitlines()[0].strip() \
            if rc == 0 and (out or "").strip() else ""

    def _read_current_ep(self):
        """endpointِ فعالِ واقعی از خودِ اینترفیس (بعد از restartِ پنل هم
        درست است — stateِ حافظه‌ای نیست)."""
        rc, out, _ = run(["wg", "show", WARP_IFACE, "endpoints"], timeout=5)
        if rc == 0 and out:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+):\d+", out)
            if m:
                return m.group(1)
        return ""

    def _on_standby(self):
        """آیا اینترفیس *همین حالا* روی کلیدِ استندبای است؟

        عمداً از کرنل خوانده می‌شود نه از حافظه — مثلِ `_read_current_ep`.
        با فلگِ حافظه‌ای، راهِ بازگشتی که خودِ متنِ هشدار می‌دهد
        (`systemctl restart wg-quick@wgwarp`) کلیدِ اصلی را برمی‌گرداند ولی
        فلگ روشن می‌ماند، پس شرطِ زیر در قطعیِ بعدی سوییچ را مسدود می‌کند و
        تورِ استندبای تا ری‌استارتِ بعدیِ پنل **بی‌صدا خلع‌سلاح** می‌شود.
        مقایسه هیچ کلیدی را واردِ argv نمی‌کند (`wg show` نامِ فیلد می‌گیرد،
        نه مقدار) و خروجی جایی لاگ نمی‌شود."""
        try:
            with open(WARP_STANDBY_KEY, encoding="utf-8") as f:
                sb = f.read().strip()
        except OSError:
            return False
        if not sb:
            return False
        rc, cur, _e = run(["wg", "show", WARP_IFACE, "private-key"],
                          timeout=5)
        return rc == 0 and cur.strip() == sb

    def _rotate_endpoint(self, egress):
        """endpointِ بعدیِ استخر را امتحان کن. ترتیبِ حیاتی: اول pinِ مسیر
        به تونلِ ساده، بعد سوییچ — endpointهای جایگزین به‌طورِ پیش‌فرض از
        awg1 مسیر می‌گیرند (تأییدشده با ip route get) که دیتای WARP را
        می‌شکند؛ سوییچِ بدونِ pin یعنی هندشیکِ مرده‌ی تضمینی."""
        pub = self._peer_pub()
        if not pub:
            return
        self.ep_idx = (self.ep_idx + 1) % len(WARP_EP_POOL)
        ep = WARP_EP_POOL[self.ep_idx]
        if egress:
            run(["ip", "route", "replace", ep + "/32", "dev", egress],
                timeout=10)
        rc, _o, err = run(["wg", "set", WARP_IFACE, "peer", pub,
                           "endpoint", ep + ":2408"], timeout=10)
        if rc != 0:
            log_action("warp-guard: چرخشِ endpoint به %s شکست: %s"
                       % (ep, (err or "?")[:80]))
            return
        self.rot_count += 1
        self.current_ep = ep
        log_action("warp-guard: endpoint → %s (چرخشِ %d، streak=%d)"
                   % (ep, self.rot_count, self.dead_streak))
        warp_event("rotate", A('alert.rotate_endpoint.1', p0=ep, p1=self.rot_count), "WarpGuard")
        if not self.rotated_alerted:
            self.rotated_alerted = True
            ALERTS.event("warp",
                         A('alert.rotate_endpoint.2', p0=ep))
        # استندبای: یک دورِ کامل چرخیدیم و هنوز مرده — شاید کلید/حساب
        # مسدود شده؛ اگر کلیدِ استندبای هست، سوییچ کن (یک‌بار در هر قطعی).
        if (self.rot_count > len(WARP_EP_POOL)
                and os.path.isfile(WARP_STANDBY_KEY)
                and not self._on_standby()):
            rc, _o, err = run(["wg", "set", WARP_IFACE, "private-key",
                               WARP_STANDBY_KEY], timeout=10)
            if rc == 0:
                log_action("warp-guard: سوییچ به کلیدِ استندبای")
                warp_event("standby", A('alert.rotate_endpoint.3'),
                           "WarpGuard")
                ALERTS.event("warp",
                             A('alert.rotate_endpoint.4'))
                try:
                    with open(WARP_ACCOUNT_FILE, "w",
                              encoding="utf-8") as f:
                        f.write("standby\n")
                except OSError:
                    pass

    def _write_state(self, egress, rule_on):
        try:
            tmp = WARP_GUARD_STATE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("egress=%s\nrule=%s\nendpoint=%s\n"
                        % (egress, "on" if rule_on else "off",
                           self.current_ep))
            os.replace(tmp, WARP_GUARD_STATE)
        except OSError:
            pass

    def _heartbeat(self):
        try:
            with open(WARP_GUARD_HEARTBEAT, "w", encoding="utf-8") as f:
                f.write("%d\n" % int(time.time()))
        except OSError:
            pass

    def reconcile(self):
        c = self.cfg()
        if not c.get("enabled"):
            return
        # فقط وقتی مسیریابیِ WARP روی این سرور نصب است دخالت کن (نبودِ
        # sync.sh = نصب نیست → نه heartbeat، نه دستکاریِ route/rule).
        # نسخه‌ی قبلیِ این گیت کدِ مرده بود: شرطش همیشه-False بود (خودِ
        # WARP_IFACE به لیستِ live_interfaces append می‌شد) و بدنه‌اش هم
        # `pass` بود نه `return`. نکته: پایین‌بودنِ *موقتِ* wgwarp دلیلِ
        # خروج نیست — دقیقاً همان‌جاست که degradation باید کار کند؛ پس فقط
        # وجودِ sync.sh (= نصب‌بودن) شرط است.
        if not os.path.isfile(WARP_SYNC):
            return
        self._heartbeat()
        primary, backup = c.get("primary", "wg22"), c.get("backup", "wg21")

        # ---- ۱) failoverِ egress — روی endpointِ *زنده*
        # endpoint روی anycast روم می‌کند (autodetect/چرخش/ری‌استارت)؛ پین
        # و سنجش باید همان را دنبال کنند. نسخه‌ی قبلی ثابتِ WARP_EP_IP را
        # می‌سنجید/پین می‌کرد، پس بعدِ روم، endpointِ واقعی از catch-allِ
        # awg1 می‌رفت (دیتای WARP شکسته؛ اندازه‌گیری: gemini ۱ از ۵ در
        # برابرِ ۵ از ۵ از wg21) در حالی که state ادعای egress سالم داشت
        # و sync.sh هم به همان state واگذار کرده بود — نیتِ اعلام‌شده ولی
        # اعمال‌نشده.
        ep_live = self._read_current_ep()
        if ep_live:
            self.current_ep = ep_live
        ep_pin = self.current_ep or WARP_EP_IP
        want = primary if warp_iface_up(primary) else \
            (backup if warp_iface_up(backup) else "")
        egress_for_state = want or primary
        if want:
            actual = warp_egress_actual(ep_pin)
            if actual != want:
                rc, _o, err = run(["ip", "route", "replace",
                                   ep_pin + "/32", "dev", want],
                                  timeout=10)
                if rc == 0:
                    log_action("warp-guard: egress %s → %s (بود: %s)"
                               % (ep_pin, want, actual or "?"))
                    warp_event("egress", A('alert.reconcile.7', p0=ep_pin, p1=want, p2=actual or '?'), "WarpGuard")
                    ALERTS.event("warp",
                                 A('alert.reconcile.8', p0=ep_pin, p1=want, p2=actual or '?'))

        # ---- ۲) graceful degradation بر پایهٔ سلامتِ wgwarp
        alive = WARP_IFACE in live_interfaces()
        age = tunnel_handshake_age(WARP_IFACE)
        healthy = alive and age is not None and age < 180
        # هندشیکِ تازه تضمینِ عبورِ داده نیست: اگر تونلِ egress زامبی شود
        # (هندشیکِ سالم ولی بی‌عبورِ ترافیک) هندشیکِ wgwarp هم می‌تواند
        # مدتی تازه بماند در حالی که هیچ داده‌ای رد نمی‌شود. وقتی rx ساکت
        # است با probeِ فعال تأیید می‌کنیم تا چرخشِ endpoint و degradation
        # واقعاً فعال شوند به‌جای اینکه گارد تونلِ مرده را سالم ببیند.
        if healthy and tunnel_rx_rate(WARP_IFACE) <= 0:
            healthy = tunnel_data_plane_ok(WARP_IFACE)
        if healthy:
            self.dead_streak = 0
            self.rot_count = 0
            self.rotated_alerted = False
            if self.degraded:
                # بازگرداندنِ قاعده (اگر خودمان برداشته بودیم)
                if not warp_rule_present():
                    run(["ip", "rule", "add", "fwmark", WARP_MARK,
                         "table", WARP_TABLE, "priority", "9"], timeout=5)
                self.degraded = False
                log_action("warp-guard: wgwarp سالم شد؛ مسیریابیِ AI بازگشت")
                warp_event("restore", A('alert.reconcile.2'),
                           "WarpGuard")
                ALERTS.event("warp",
                             A('alert.reconcile.3'))
        else:
            self.dead_streak += 1
            # چرخشِ endpoint (استخر): از rotate_after به بعد، هر ۲ چرخه
            # (~۲۴ث) یک endpointِ تازه — تا هندشیک (تلاشِ ~۵ثانیه‌ای)
            # فرصتِ برقراری داشته باشد. degradation مستقل و سرِ جایش است؛
            # چرخش هم بعد از degradation ادامه دارد تا مسیرِ بازگشت باز
            # بماند (سالم‌شدن → rule برمی‌گردد).
            rotate_after = max(2, int(c.get("rotate_after", 3)))
            if c.get("rotate", True) and alive and \
                    self.dead_streak >= rotate_after and \
                    (self.dead_streak - rotate_after) % 2 == 0:
                self._rotate_endpoint(egress_for_state)
            degrade_after = max(2, int(c.get("degrade_after", 5)))
            if self.dead_streak >= degrade_after and not self.degraded:
                # حذفِ قاعده → ترافیکِ AI به مسیرِ عادی (سریع‌شکست نه بلک‌هول)
                while warp_rule_present():
                    rc, _o, _e = run(["ip", "rule", "del", "fwmark",
                                      WARP_MARK, "table", WARP_TABLE,
                                      "priority", "9"], timeout=5)
                    if rc != 0:
                        break
                self.degraded = True
                log_action("warp-guard: wgwarp مرده (streak=%d) → قاعده "
                           "برداشته شد؛ AI به مسیرِ عادی افتاد"
                           % self.dead_streak)
                warp_event("degrade", A('alert.reconcile.4', p0=self.dead_streak), "WarpGuard")
                ALERTS.event("warp",
                             A('alert.reconcile.5'))

        self._write_state(egress_for_state, not self.degraded)

        # ---- ۳) fail-open جراحیِ SNI ----
        # اگر جراحیِ SNI روشن است، قاعدهٔ TPROXY را با سلامتِ splitter هماهنگ
        # کن: سالم → قاعده حاضر (تفکیک فعال)؛ ناسالم → قاعده برداشته شود تا
        # ترافیک به blanketِ 0x77 (کلِ /24 → WARP) بیفتد = رفتارِ امروز. این
        # مستقل و سریع‌تر از تایمرِ ۱۵دقیقه‌ایِ sync است (چرخهٔ ۱۲ث).
        try:
            if warp_sni_enabled():
                ok = warp_sni_healthy()
                changed = warp_sni_set_tproxy(ok)
                if self.sni_ok is not None and ok != self.sni_ok:
                    # لاگ/audit همیشه؛ فقط پیامِ تلگرام پشتِ ضدِ رگبار است
                    verdict = self.sni_gate.flip()
                    if ok:
                        log_action("warp-guard: splitterِ SNI سالم شد؛ TPROXY "
                                   "بازگشت (تفکیکِ AI/کولترال فعال)")
                        if verdict == "send":
                            ALERTS.event("warp", _rtl_lines([
                                A('alert.reconcile.17'),
                                "",
                                A('alert.reconcile.18'),
                            ]))
                    else:
                        log_action("warp-guard: splitterِ SNI ناسالم → TPROXY "
                                   "برداشته شد (fail-open به WARPِ کامل)")
                        warp_event("failopen_sni", A('alert.reconcile.12'), "WarpGuard")
                        if verdict == "send":
                            ALERTS.event("warp", _rtl_lines([
                                A('alert.reconcile.19'),
                                "",
                                A('alert.reconcile.20'),
                                "",
                                A('alert.reconcile.21'),
                                "",
                                A('alert.reconcile.22'),
                            ]))
                    if verdict == "storm":
                        ALERTS.event("warp", _rtl_lines([
                            A('alert.reconcile.13'),
                            "",
                            A('alert.reconcile.14'),
                            "",
                            A('alert.reconcile.15'),
                        ]))
                elif changed and self.sni_ok is None and not ok:
                    log_action("warp-guard: splitterِ SNI ناسالم در استارتاپ؛ "
                               "TPROXY نصب نشد (fail-open)")
                self.sni_ok = ok
                muted = self.sni_gate.poll()
                if muted is not None:
                    ALERTS.event("warp", _rtl_lines([
                        A('alert.reconcile.9', p0=A('alert.lit.4') if self.sni_ok else A('alert.lit.5')),
                        "",
                        A('alert.reconcile.10', p0=_fa_num(muted + self.sni_gate.STORM_AT)),
                    ]))
            else:
                self.sni_ok = None
        except Exception as e:
            log_action("warp-guard SNI error: %r" % e)

        # ---- ۴) fail-open تفکیکِ QUIC ----
        # اگر تفکیکِ QUIC روشن است، UDP TPROXY را با سلامتِ splitter هماهنگ کن:
        # سالم → UDP TPROXY (REJECT برداشته)؛ ناسالم → REJECT (مرورگر به TCP =
        # رفتارِ امنِ امروز). فقط وقتی هم QUIC-marker هم SNI-marker باشند (دیمنِ
        # مشترک؛ QUIC بدونِ TCP-split بی‌معناست چون مسیرِ fallback همان است).
        try:
            if warp_sni_quic_enabled() and warp_sni_enabled():
                okq = warp_sni_healthy()
                warp_sni_set_quic(okq)
                if self.quic_ok is not None and okq != self.quic_ok:
                    verdict = self.quic_gate.flip()
                    if okq:
                        log_action("warp-guard: تفکیکِ QUIC سالم شد؛ UDP TPROXY "
                                   "بازگشت")
                        if verdict == "send":
                            ALERTS.event("warp", A('alert.reconcile.23'))
                    else:
                        log_action("warp-guard: splitter ناسالم → QUIC به "
                                   "REJECT برگشت (مرورگر به TCP، fail-open)")
                        if verdict == "send":
                            ALERTS.event("warp",
                                         A('alert.reconcile.24'))
                    if verdict == "storm":
                        ALERTS.event("warp",
                                     A('alert.reconcile.16'))
                self.quic_ok = okq
                muted = self.quic_gate.poll()
                if muted is not None:
                    ALERTS.event("warp",
                                 A('alert.reconcile.11', p0=A('alert.lit.6') if self.quic_ok else A('alert.lit.2'), p1=_fa_num(muted + self.quic_gate.STORM_AT)))
            else:
                self.quic_ok = None
        except Exception as e:
            log_action("warp-guard QUIC error: %r" % e)

    def run(self):
        time.sleep(15)
        while True:
            _heartbeat("warpguard")
            try:
                self.reconcile()
            except Exception as e:
                log_action("warp-guard error: %r" % e)
            time.sleep(self.INTERVAL)


WARPGUARD = WarpGuard()


# ============================================================================
# رندرِ PNG با پایتونِ خالص (بدونِ کتابخانه) — برای نمودار و QR در ربات
# ============================================================================

def _png_encode(width, height, rgb):
    """rgb: bytearray به طولِ width*height*3 → بایت‌های PNG."""
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)  # filter type 0 (None) در ابتدای هر ردیف
        raw += rgb[y * stride:(y + 1) * stride]
    comp = zlib.compress(bytes(raw), 9)

    def chunk(tag, data):
        c = tag + data
        return (struct.pack(">I", len(data)) + c
                + struct.pack(">I", binascii.crc32(c) & 0xffffffff))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", comp) + chunk(b"IEND", b""))


# --------------------------------------------------- رندرِ PNG با پایتونِ خالص



class _Canvas:
    """بومِ RGB ساده با چند ابزارِ ترسیم (بدونِ آنتی‌آلیاس)."""
    def __init__(self, w, h, bg):
        self.w, self.h = w, h
        self.buf = bytearray(bg * (w * h))

    def px(self, x, y, c):
        if 0 <= x < self.w and 0 <= y < self.h:
            i = (y * self.w + x) * 3
            self.buf[i:i + 3] = c

    def rect(self, x0, y0, x1, y1, c):
        x0, x1 = max(0, int(x0)), min(self.w, int(x1))
        y0, y1 = max(0, int(y0)), min(self.h, int(y1))
        row = bytes(c) * max(0, x1 - x0)
        for y in range(y0, y1):
            i = (y * self.w + x0) * 3
            self.buf[i:i + len(row)] = row

    def hline(self, x0, x1, y, c):
        self.rect(x0, y, x1, y + 1, c)

    def line(self, x0, y0, x1, y1, c, thick=2):
        # بروزنهام ساده با ضخامت
        dx, dy = abs(x1 - x0), abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx - dy
        x, y = int(x0), int(y0)
        t = thick // 2
        while True:
            self.rect(x - t, y - t, x + thick - t, y + thick - t, c)
            if x == int(x1) and y == int(y1):
                break
            e2 = 2 * err
            if e2 > -dy:
                err -= dy
                x += sx
            if e2 < dx:
                err += dx
                y += sy

    def png(self):
        return _png_encode(self.w, self.h, self.buf)


# فونتِ بیت‌مپِ ۵×۷ برای برچسب‌های نمودار (فقط لاتین/رقم؛ متنِ فارسی در کپشن).
# همه‌ی ASCIIِ چاپی به‌جز حروفِ کوچک را پوشش می‌دهد (_draw_text متن را upper
# می‌کند)، چون نامِ کاربر هم روی محورِ X می‌آید و نویسه‌ی بی‌گلیف جای خالی می‌شود.
_FONT5x7 = {
    "0": (0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E),
    "1": (0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E),
    "2": (0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F),
    "3": (0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E),
    "4": (0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02),
    "5": (0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E),
    "6": (0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E),
    "7": (0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08),
    "8": (0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E),
    "9": (0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C),
    "A": (0x0E, 0x11, 0x11, 0x11, 0x1F, 0x11, 0x11),
    "B": (0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E),
    "C": (0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E),
    "D": (0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E),
    "E": (0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F),
    "F": (0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10),
    "G": (0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F),
    "H": (0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11),
    "I": (0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E),
    "J": (0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0C),
    "K": (0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11),
    "L": (0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F),
    "M": (0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11),
    "N": (0x11, 0x11, 0x19, 0x15, 0x13, 0x11, 0x11),
    "O": (0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E),
    "P": (0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10),
    "Q": (0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D),
    "R": (0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11),
    "S": (0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E),
    "T": (0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04),
    "U": (0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E),
    "V": (0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04),
    "W": (0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11),
    "X": (0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11),
    "Y": (0x11, 0x11, 0x11, 0x0A, 0x04, 0x04, 0x04),
    "Z": (0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F),
    ".": (0, 0, 0, 0, 0, 0x06, 0x06),
    ",": (0, 0, 0, 0, 0x0C, 0x04, 0x08),
    ":": (0, 0x06, 0x06, 0, 0x06, 0x06, 0),
    ";": (0, 0x0C, 0x0C, 0, 0x0C, 0x04, 0x08),
    "/": (0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10),
    "\\": (0x10, 0x08, 0x08, 0x04, 0x02, 0x02, 0x01),
    "-": (0, 0, 0, 0x1F, 0, 0, 0),
    "_": (0, 0, 0, 0, 0, 0, 0x1F),
    "+": (0, 0x04, 0x04, 0x1F, 0x04, 0x04, 0),
    "=": (0, 0, 0x1F, 0, 0x1F, 0, 0),
    "*": (0, 0x04, 0x15, 0x0E, 0x15, 0x04, 0),
    "%": (0x18, 0x19, 0x02, 0x04, 0x08, 0x13, 0x03),
    "#": (0x0A, 0x0A, 0x1F, 0x0A, 0x1F, 0x0A, 0x0A),
    "$": (0x04, 0x0F, 0x14, 0x0E, 0x05, 0x1E, 0x04),
    "&": (0x0C, 0x12, 0x14, 0x08, 0x15, 0x12, 0x0D),
    "@": (0x0E, 0x11, 0x01, 0x0D, 0x15, 0x15, 0x0E),
    "!": (0x04, 0x04, 0x04, 0x04, 0x04, 0, 0x04),
    "?": (0x0E, 0x11, 0x01, 0x02, 0x04, 0, 0x04),
    "'": (0x0C, 0x04, 0x08, 0, 0, 0, 0),
    '"': (0x0A, 0x0A, 0x0A, 0, 0, 0, 0),
    "`": (0x08, 0x04, 0x02, 0, 0, 0, 0),
    "^": (0x04, 0x0A, 0x11, 0, 0, 0, 0),
    "~": (0, 0, 0x08, 0x15, 0x02, 0, 0),
    "|": (0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04),
    "(": (0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02),
    ")": (0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08),
    "[": (0x0E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0E),
    "]": (0x0E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0E),
    "{": (0x02, 0x04, 0x04, 0x08, 0x04, 0x04, 0x02),
    "}": (0x08, 0x04, 0x04, 0x02, 0x04, 0x04, 0x08),
    "<": (0x02, 0x04, 0x08, 0x10, 0x08, 0x04, 0x02),
    ">": (0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08),
    " ": (0, 0, 0, 0, 0, 0, 0),
}


def _draw_text(cv, x, y, s, color, scale=2):
    """رشته‌ی لاتین را با فونتِ ۵×۷ روی بومِ cv می‌کشد. عرضِ کلی را برمی‌گرداند."""
    col = bytes(color)
    cx = x
    for ch in str(s).upper():
        g = _FONT5x7.get(ch)
        if g is None:
            cx += 6 * scale
            continue
        for ry in range(7):
            bits = g[ry]
            for rx in range(5):
                if bits & (1 << (4 - rx)):
                    cv.rect(cx + rx * scale, y + ry * scale,
                            cx + rx * scale + scale, y + ry * scale + scale, col)
        cx += 6 * scale
    return cx - x


def _text_w(s, scale=2):
    return len(str(s)) * 6 * scale


def _fmt_bytes_ascii(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return ("%.0f %s" if (n >= 100 or u == "B") else "%.1f %s") % (n, u)
        n /= 1024
    return "%.1f TB" % n


def _fmt_mbps_ascii(v):
    """مقدارِ Mbit/s برای محورِ Y (نمودارِ تستِ سرعت)؛ از ۱۰۰۰ به بالا Gbit/s."""
    v = float(v or 0)
    if v >= 1000:
        return "%.1f Gbit/s" % (v / 1000)
    return ("%.0f Mbit/s" if (v >= 10 or v == 0) else "%.1f Mbit/s") % v


def _chart_y_labels(series, y_fmt=None):
    """پنج برچسبِ محورِ Y از بالا به پایین (بیشینه → صفر) با فرمت‌گرِ y_fmt."""
    allv = [v for vals, _, _ in series for v in (vals or [])]
    mx = (max(allv) if allv else 0.0) or 1.0
    fmt = y_fmt or _fmt_bytes_ascii
    return mx, [fmt(mx * (4 - k) / 4) for k in range(5)]


def render_chart_png(series, x_labels=None, title="", bars=False, y_fmt=None):
    """نمودارِ کامل با محور/راهنما/برچسب. PNG برمی‌گرداند.
    series: [(values, (r,g,b), name_ascii), ...] یک یا دو سری.
    x_labels: [(frac0..1, text_ascii), ...].
    title: عنوانِ لاتینِ اختیاری (بالا). bars=True → میله‌ای (برای حجمِ روزانه).
    y_fmt: تابعِ مقدار → برچسبِ ascii برای محورِ Y؛ پیش‌فرض بایت
    (_fmt_bytes_ascii). برای سرعت _fmt_mbps_ascii بدهید."""
    W, H = 900, 400
    mx, ylabels = _chart_y_labels(series, y_fmt)
    # حاشیه‌ی چپ به اندازه‌ی پهن‌ترین برچسبِ Y تا متن روی نمودار نیفتد
    PADL = max(78, max(_text_w(s, 2) for s in ylabels) + 14)
    PADR, PADT, PADB = 22, 46, 34
    bg = bytes((13, 17, 23))
    grid = bytes((38, 45, 56))
    axis = bytes((90, 100, 115))
    cv = _Canvas(W, H, bg)
    x0, x1 = PADL, W - PADR
    y0, y1 = PADT, H - PADB
    # شبکه‌ی افقی + برچسبِ مقدار در هر خط
    for k, lbl in enumerate(ylabels):
        gy = y0 + (y1 - y0) * k // 4
        cv.hline(x0, x1, gy, grid)
        _draw_text(cv, 4, gy - 5, lbl, axis, scale=2)
    cv.rect(x0, y0, x0 + 1, y1, axis)          # محورِ Y
    cv.hline(x0, x1, y1, axis)                 # محورِ X
    plotw = x1 - x0
    nser = len(series)
    for sidx, (vals, color, _name) in enumerate(series):
        vals = [max(0.0, float(v)) for v in (vals or [])]
        n = len(vals)
        if not n:
            continue
        col = bytes(color)
        fill = bytes(tuple(int(c * 0.30 + 13 * 0.70) for c in color))
        if bars:
            # میله‌های گروهی: هر بازه به nser زیرمیله‌ی کنارِ هم تقسیم می‌شود
            slot = plotw / n
            gap = 2
            subw = max(2, (slot - gap) / max(1, nser))
            for i, v in enumerate(vals):
                base = x0 + slot * i + gap / 2 + subw * sidx
                cy = y1 - int((y1 - y0) * (v / mx))
                cv.rect(int(base), cy, int(base + subw), y1, col)
        else:
            prev = None
            for i, v in enumerate(vals):
                cx = (x0 + plotw * i // max(1, n - 1)) if n > 1 else x0 + plotw // 2
                cy = y1 - int((y1 - y0) * (v / mx))
                cv.rect(cx, cy, cx + 1, y1, fill)
                if prev is not None:
                    cv.line(prev[0], prev[1], cx, cy, col, thick=3)
                prev = (cx, cy)
    # برچسب‌های محورِ X
    for frac, text in (x_labels or []):
        tx = x0 + int(plotw * max(0.0, min(1.0, frac)))
        w = _text_w(text, 2)
        tx = max(x0, min(x1 - w, tx - w // 2))
        _draw_text(cv, tx, y1 + 8, text, axis, scale=2)
    # عنوان (بالا-چپ) + راهنمای رنگی (بالا-راست)
    if title:
        _draw_text(cv, PADL, 14, title, bytes((200, 210, 220)), scale=3)
    lx = x1
    for vals, color, name in reversed(series):
        if not name:
            continue
        w = _text_w(name, 2)
        lx -= w + 26
        cv.rect(lx, 20, lx + 16, 30, bytes(color))
        _draw_text(cv, lx + 22, 18, name, bytes((200, 210, 220)), scale=2)
    return cv.png()


def render_qr_png(text, scale=8, margin=4):
    """QR به‌صورتِ PNG با qrencode (کتابخانه‌ی اثبات‌شده). اگر qrencode نصب
    نباشد یا خطا دهد → None (ربات آن‌وقت QR را رد می‌کند، متن/سند سرِ جا)."""
    try:
        p = subprocess.run(
            ["qrencode", "-o", "-", "-t", "PNG",
             "-s", str(scale), "-m", str(margin)],
            input=text.encode("utf-8"), capture_output=True, timeout=10)
        if p.returncode == 0 and p.stdout[:8] == b"\x89PNG\r\n\x1a\n":
            return p.stdout
    except Exception:
        pass
    return None


# ---- فرمت‌بندیِ سمتِ سرور (برای متنِ ربات)
def esc_html(s):
    """escapeِ حداقلی برای parse_mode=HTMLِ تلگرام."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def fmt_bytes_srv(n, lang=None):
    """حجمِ خوانا (نمایشیِ ربات/دایجست)؛ ارقامِ فارسی فقط برای زبانِ فارسی
    (پیش‌فرض: زبانِ مالکِ ربات)."""
    n = float(n or 0)
    fa = (lang or alert_lang()) in LANG_FA_DIGITS
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            s = ("%.0f %s" if (n >= 100 or u == "B") else "%.1f %s") % (n, u)
            return _fa_num(s) if fa else s
        n /= 1024
    s = "%.1f TB" % n
    return _fa_num(s) if fa else s


def _ago_srv(ts, lang=None):
    """«n ثانیه/دقیقه/ساعت/روز پیش» به زبانِ lang (پیش‌فرض: زبانِ مالکِ ربات)."""
    if not ts:
        return "—"
    d = int(time.time() - ts)
    if d < 0:
        return "—"
    lang = lang or alert_lang()
    if d < 60:
        s = t("alert.ago.s", lang, n=d)
    elif d < 3600:
        s = t("alert.ago.m", lang, n=d // 60)
    elif d < 86400:
        s = t("alert.ago.h", lang, n=d // 3600)
    else:
        s = t("alert.ago.d", lang, n=d // 86400)
    return _fa_num(s) if lang in LANG_FA_DIGITS else s


# ============================================================================
# ربات تلگرام — انجامِ کارهای پنل از داخلِ تلگرام (long-poll از تونل)
# ============================================================================
BOT_DEFAULTS = {"enabled": False, "users": [],   # users: [{id, role, name}]
                "add_ifaces": []}   # اینترفیس‌های مجازِ ساخت از ربات؛ خالی = همه


# --------------------------------------------------------------- رباتِ تلگرام



def bot_cfg():
    c = dict(BOT_DEFAULTS)
    c.update(CONFIG.get("bot") or {})
    c["users"] = list(c.get("users") or [])
    return c


def alert_lang():
    """زبانِ هشدارهای تلگرام = زبانِ **مالکِ ربات**.

    هشدار به یک چتِ گروهی می‌رود که ممکن است چند مدیر با زبان‌های مختلف در
    آن باشند، پس «زبانِ گیرنده» تعریف‌شده نیست. انتخابِ کاربر (۱۲ اوت
    ۲۰۲۶): زبانِ مالکِ ربات — تنها حسابی که همیشه دقیقاً یکی است و از پنل
    هم تغییرناپذیر است. اگر مالکی تعریف نشده باشد، فارسی.
    """
    for u in bot_cfg()["users"]:
        if u.get("role") == "owner":
            return norm_lang(u.get("lang")) or DEFAULT_LANG
    return DEFAULT_LANG


def A(key, **params):
    """متنِ هشدار به زبانِ مالکِ ربات."""
    return t(key, alert_lang(), **params)


def bot_lang(tg_id):
    """زبانِ کاربرِ ربات — از رکوردِ خودش در config.

    زبان per-chat است چون یک ربات هم‌زمان به چند مدیر با زبان‌های مختلف
    پاسخ می‌دهد؛ زبانِ سراسری اینجا معنا ندارد. رکوردهای قدیمی فیلدِ lang
    ندارند و به فارسی می‌افتند.
    """
    tid = str(tg_id)
    for u in bot_cfg()["users"]:
        if str(u.get("id")) == tid:
            return norm_lang(u.get("lang")) or DEFAULT_LANG
    return DEFAULT_LANG


def bot_set_lang(tg_id, lang):
    """زبانِ کاربرِ ربات را می‌نویسد (روی همان رکوردِ users در config)."""
    lang = norm_lang(lang)
    if not lang:
        return False
    tid = str(tg_id)
    with _conf_lock:
        cfg = CONFIG.setdefault("bot", {})
        users = cfg.get("users") or []
        for u in users:
            if str(u.get("id")) == tid:
                u["lang"] = lang
                with config_txn() as c2:
                    c2.setdefault("bot", {})["users"] = users
                return True
    return False


def bot_owner_violation(new_users):
    """مالکِ ربات (role=owner) از پنل تغییرناپذیر است. فهرستِ پیشنهادیِ
    کاربرانِ ربات را می‌سنجد؛ اگر ردیفِ ownerِ فعلی حذف/تغییرِ نقش/تغییرِ نام
    شده یا ownerِ تازه اضافه شده باشد، پیامِ خطا برمی‌گرداند، وگرنه None."""
    cur = {str(u.get("id")): (u.get("name") or "")[:40]
           for u in bot_cfg()["users"] if u.get("role") == "owner"}
    new = {str(u.get("id")): (u.get("name") or "")[:40]
           for u in new_users if u.get("role") == "owner"}
    dup_bad = any(str(u.get("id")) in cur and u.get("role") != "owner"
                  for u in new_users)
    if new != cur or dup_bad:
        return "api.err.bot.owner_locked"
    return None


def bot_admin_grant_violation(new_users, privileged):
    """اعطای نقشِ «admin» به کاربرِ ربات فقط از دستِ ادمینِ کاملِ پنل.

    نقشِ admin همه‌ی مجوزها را دارد؛ پس اگر دارنده‌ی صرفِ bot.manage بتواند
    آیدیِ خودش (یا هرکسِ دیگر) را admin کند، یک **ارتقای دسترسی** است:
    از یک مجوزِ باریک به کنترلِ کاملِ ربات می‌رسد. ردیف‌های adminِ از قبل
    موجود که دست‌نخورده مانده‌اند مجازند تا ذخیره‌ی تغییرهای دیگر نشکند.
    خروجی: پیامِ خطا، یا None اگر ایرادی نبود."""
    if privileged:
        return None
    cur = {str(u.get("id")): u.get("role") for u in bot_cfg()["users"]}
    for u in new_users:
        # قابلیت‌محور: نقشِ سفارشی‌ای که users.manage دارد همان قدرت را
        # می‌دهد که «admin»، فقط نامش فرق می‌کند.
        new_role = u.get("role")
        old_role = cur.get(str(u.get("id")))
        if role_is_privileged(new_role) and not role_is_privileged(old_role):
            return "api.err.bot.admin_grant"
    return None


def bot_user_role(tg_id):
    """نقشِ RBACِ نگاشت‌شده به این آیدیِ تلگرام، یا None اگر مجاز نباشد."""
    tid = str(tg_id)
    for u in bot_cfg()["users"]:
        if str(u.get("id")) == tid:
            return u.get("role", "viewer")
    return None


def bot_perms(tg_id):
    role = bot_user_role(tg_id)
    if role is None:
        return None
    return role_perms(role)


class TelegramBot(threading.Thread):
    """long-poll getUpdates از تونل؛ منوی inline؛ اجرای کارها با رعایتِ RBAC.
    فقط «ساخت + مشاهده» (بدونِ حذف/ویرایشِ مخرب)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.offset = 0
        self.convo = {}   # tg_id -> وضعیتِ گفت‌وگوی چندمرحله‌ای
        self._edit = None  # (chat, message_id) هنگام پردازشِ callback؛ تک‌نخی
        self._chat_type = None  # نوعِ چتِ درخواستِ جاری (private/group/…)
        # زبانِ کاربرِ همین به‌روزرسانی. مثلِ _edit روی نمونه می‌نشیند چون
        # حلقهٔ long-poll تک‌نخی است؛ این کار زبان را از عبور دادن به ده‌ها
        # امضای متد بی‌نیاز می‌کند. در آغازِ هر update ست و در پایان پاک
        # می‌شود، پس هیچ پیامی زبانِ کاربرِ قبلی را به ارث نمی‌برد.
        self._lang = DEFAULT_LANG

    def T(self, key, **params):
        """متنِ محلی‌شده به زبانِ کاربرِ همین به‌روزرسانی."""
        return t(key, self._lang, **params)

    def M(self, v):
        """پیامِ برگشتیِ توابعِ مشترک با وب (کلیدِ api.* یا aerr) به زبانِ همین
        چت، HTML-امن. متنِ خامِ سیستم دست‌نخورده (فقط escape) رد می‌شود."""
        return esc_html(str(api_text(v, self._lang) or ""))

    # ---- ابزارِ ارسال
    def _token(self):
        return alert_cfg()["bot_token"]

    def send(self, chat, text, keyboard=None):
        p = {"chat_id": chat, "text": text, "parse_mode": "HTML",
             "disable_web_page_preview": True}
        if keyboard is not None:
            p["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
        # ناوبریِ در جا: اگر پاسخ به یک دکمه است و خودش دکمه دارد (صفحه‌ی
        # ناوبری، نه صرفاً یک تخلیه‌ی متن)، همان پیام را ویرایش کن.
        edit = self._edit
        if edit and keyboard is not None and str(edit[0]) == str(chat):
            self._edit = None
            ok, res = tg_api(self._token(), "editMessageText",
                             dict(p, message_id=edit[1]),
                             iface=alert_cfg()["iface"])
            if ok:
                return ok, res
            # «محتوا تغییر نکرد» = صفحه از قبل درست است؛ پیامِ تکراری نفرست
            if isinstance(res, str) and "not modified" in res.lower():
                return True, None
            # سایرِ خطاها (پیامِ قدیمی و…) → ارسالِ پیامِ جدید
        parts = tg_chunks(text, html=True)     # send همیشه parse_mode=HTML است
        if len(parts) == 1:
            return tg_api(self._token(), "sendMessage", p, iface=alert_cfg()["iface"])
        # پیامِ بلند (فهرستِ تونل‌ها، کانفیگ با AllowedIPs ِ طولانی، ممیزیِ
        # نشت): تلگرام >۴۰۹۶ را رد می‌کند و کاربر هیچ نمی‌دید. تکه‌تکه؛
        # کیبورد با تکه‌ی آخر.
        ok, res = True, None
        for i, part in enumerate(parts):
            q = dict(p, text=part)
            if i < len(parts) - 1:
                q.pop("reply_markup", None)
            ok, res = tg_api(self._token(), "sendMessage", q,
                             iface=alert_cfg()["iface"])
            if not ok:
                break
        return ok, res

    # --- کمکی‌های UX: کپی و جهت‌دهی ---------------------------------------
    # تلگرام فونت/justify را کنترل نمی‌کند؛ ولی: (۱) <code>/<pre> با لمس کپی
    # می‌شوند، (۲) دکمه‌ی copy_text (Bot API 7.11+) کپیِ دقیق می‌دهد، (۳) با
    # علائمِ جهتِ یونیکد خطوطِ فارسی راست‌چین و لینک‌ها/لاتین چپ‌چین می‌شوند.
    RLM = "‏"   # علامتِ راست‌به‌چپ (ابتدای خطِ فارسی)
    LRM = "‎"   # علامتِ چپ‌به‌راست (دورِ لینک/لاتین)

    @staticmethod
    def _copy_btn(label, text):
        # copy_text.text حداکثر ۲۵۶ کاراکتر؛ بلندتر → None (از <pre> لمسی)
        if not text or len(text) > 256:
            return None
        return {"text": label, "copy_text": {"text": text}}

    def _rtl(self, s):
        """خطِ فارسی: با RLM شروع تا راست‌چین قطعی شود."""
        return self.RLM + s

    def _code_line(self, latin):
        """مقدارِ لاتین/لینک در خطِ جدا، چپ‌چین و لمس‌برای‌کپی."""
        return self.LRM + "<code>" + esc_html(latin) + "</code>"

    def _kv(self, label, value, latin=False):
        """جفتِ برچسب/مقدار. latin=True → مقدار در خطِ جدا، چپ‌چین و کپی‌شدنی."""
        if latin:
            return self._rtl(label) + "\n" + self._code_line(str(value))
        return self._rtl("%s <b>%s</b>" % (label, value))

    def _head(self, t):
        """سرتیترِ بخش (پررنگ، راست‌چین) — مثلِ دایجست."""
        return self._rtl("<b>%s</b>" % t)

    def _titlebar(self, t):
        """سربرگِ استانداردِ صفحه: عنوانِ پررنگ + نامِ سرور در خطِ بعد."""
        return self._head(t) + "\n<code>%s</code>" % esc_html(_host_label())

    def _pct(self, v):
        return (_fa_num("%.0f" % v) + self.T('bot.pct.1')) if isinstance(v, (int, float)) else "—"

    def _fa_date(self, ymd):
        """'YYYY-MM-DD' → 'شمسی (میلادی)' با ارقامِ فارسی. خالی → ''."""
        ymd = (ymd or "").strip()
        if not ymd:
            return ""
        try:
            y, mo, d = (int(x) for x in ymd.split("-"))
            jy, jm, jd = _greg_to_jalali(y, mo, d)
            return _fa_num("%04d/%02d/%02d (%s)" % (jy, jm, jd, ymd))
        except (ValueError, TypeError):
            return _fa_num(ymd)

    def send_photo(self, chat, png, caption=""):
        return tg_api(self._token(), "sendPhoto",
                      {"chat_id": chat, "caption": caption, "parse_mode": "HTML"},
                      photo=("chart.png", png), iface=alert_cfg()["iface"])

    def send_doc(self, chat, filename, content, caption=""):
        return tg_api(self._token(), "sendDocument",
                      {"chat_id": chat, "caption": caption, "parse_mode": "HTML"},
                      photo=(filename, content.encode("utf-8")
                             if isinstance(content, str) else content),
                      iface=alert_cfg()["iface"],
                      _field="document", _ctype="text/plain")

    def answer_cb(self, cb_id, text=""):
        tg_api(self._token(), "answerCallbackQuery",
               {"callback_query_id": cb_id, "text": text}, iface=alert_cfg()["iface"])

    # ---- حلقه‌ی اصلی
    def run(self):
        time.sleep(8)
        while True:
            _heartbeat("bot")
            try:
                if not (bot_cfg()["enabled"] and self._token()):
                    time.sleep(10)
                    continue
                ok, res = tg_api(self._token(), "getUpdates",
                                 {"offset": self.offset, "timeout": 30,
                                  "allowed_updates": ["message", "callback_query"]},
                                 iface=alert_cfg()["iface"], timeout=45)
                if not ok or not isinstance(res, list):
                    time.sleep(5)
                    continue
                for upd in res:
                    self.offset = max(self.offset, upd.get("update_id", 0) + 1)
                    try:
                        self._dispatch(upd)
                    except Exception as e:
                        log_action("bot dispatch error: %r" % e)
            except Exception as e:
                log_action("bot loop error: %r" % e)
                time.sleep(5)

    # ---- تأییدِ ورودِ پنل (۲مرحله‌ای)
    def _on_login_approval(self, frm, cb):
        """تأیید/ردِ ورود — فقط از همان چتی که درخواست به آن رفته است.

        بندِ امنیتی: مقصدِ هر توکن هنگامِ ارسال ذخیره می‌شود و اینجا بررسی
        می‌شود که پیامِ دکمه در همان چت باشد. وگرنه با per-user chat، هر
        ادمینِ ربات می‌توانست ورودِ حسابِ دیگری را تأیید کند."""
        c = alert_cfg()
        chat = cb.get("message", {}).get("chat", {}).get("id")
        parts = cb.get("data", "").split(":")
        approved = len(parts) > 1 and parts[1] == "ok"
        token = parts[2] if len(parts) > 2 else ""
        dest = login_approval_dest(token)
        if not dest:
            self.answer_cb(cb.get("id", ""), self.T('bot.on_login_approval.1'))
            return
        # همان چت + (خودِ صاحبِ چتِ خصوصی یا ادمینِ رباتِ حاضر در آن چت)
        authorized = (str(chat) == dest
                      and (str(frm) == dest or bot_user_role(frm) == "admin"))
        self.answer_cb(cb.get("id", ""),
                       "" if authorized else self.T('bot.on_login_approval.2'))
        if not authorized:
            log_action("login 2fa: unauthorized approval attempt by %s "
                       "(chat=%s, dest=%s)" % (frm, chat, dest))
            return
        resolve_login_approval(token, approved)
        mid = cb.get("message", {}).get("message_id")
        if chat and mid:
            tg_api(c["bot_token"], "editMessageText",
                   {"chat_id": chat, "message_id": mid, "parse_mode": "HTML",
                    "text": self.T('bot.on_login_approval.3', p0='' if approved else '', p1=self.T('bot.lit.2') if approved else self.T('bot.lit.3'))},
                   iface=c["iface"])

    # ---- مسیریابیِ آپدیت
    def _dispatch(self, upd):
        try:
            self._dispatch_inner(upd)
        finally:
            self._lang = DEFAULT_LANG   # نشتِ زبان به به‌روزرسانیِ بعدی ممنوع

    def _dispatch_inner(self, upd):
        if "callback_query" in upd:
            cb = upd["callback_query"]
            frm = cb.get("from", {}).get("id")
            self._lang = bot_lang(frm)
            chat = cb.get("message", {}).get("chat", {}).get("id")
            self._chat_type = cb.get("message", {}).get("chat", {}).get("type")
            data = cb.get("data", "")
            if data.startswith("lg:"):     # تأییدِ ورودِ پنل (۲مرحله‌ای)
                self._on_login_approval(frm, cb)
                return
            self.answer_cb(cb.get("id", ""))
            if bot_perms(frm) is None:
                return
            # ناوبریِ در جا: اولین پاسخ همان پیامِ دکمه را ویرایش می‌کند
            self._edit = (chat, cb.get("message", {}).get("message_id"))
            try:
                self._on_action(frm, chat, data)
            finally:
                self._edit = None
            return
        msg = upd.get("message")
        if not msg:
            return
        frm = msg.get("from", {}).get("id")
        chat = msg.get("chat", {}).get("id")
        self._chat_type = msg.get("chat", {}).get("type")
        self._lang = bot_lang(frm)
        text = (msg.get("text") or "").strip()
        perms = bot_perms(frm)
        if perms is None:
            if not self._private():
                return      # در گروه‌های غریبه ساکت بمان (نه اسپم، نه افشای شناسه)
            self.send(chat, self._rtl(self.T('bot.dispatch_inner.6')) + "\n" + self._rtl(self.T('bot.dispatch_inner.5')) + "\n" + self._code_line(str(frm)) + "\n"
                            + self._rtl(self.T('bot.dispatch_inner.4')))
            return
        cmd = text.lower().split("@")[0].split()[0] if text else ""
        if cmd in ("/lang", "/language"):
            self._lang_menu(chat)
            return
        if cmd in ("/cancel", self.T('bot.dispatch_inner.1')):
            self.convo.pop(frm, None)
            self.send(chat, self.T('bot.dispatch_inner.2'))
            self._main_menu(chat, frm)
            return
        # اگر وسطِ یک گفت‌وگو هستیم (ورودیِ متنی)
        if frm in self.convo and text and not text.startswith("/"):
            self._convo_step(frm, chat, text)
            return
        if cmd in ("/start", "/menu", self.T('bot.dispatch_inner.3'), "start"):
            self.convo.pop(frm, None)
            self._main_menu(chat, frm)
        elif cmd in ("/wgusers", "/users"):
            self._wg_action(frm, chat, "list", "", perms)
        elif cmd == "/pxusers":
            self._px_action(frm, chat, "list", "", perms)
        elif cmd == "/addwg":
            if "wg.add" in perms:
                self._start_wg_add(frm, chat)
            else:
                self.send(chat, self.T('bot.backup_page.1'))
        elif cmd == "/addpx":
            if "proxy.add" in perms:
                self._start_px_add(frm, chat)
            else:
                self.send(chat, self.T('bot.backup_page.1'))
        elif cmd == "/live":
            self._live_list(chat, perms)
        elif cmd in ("/listexp", "/listusers"):
            self._wg_list_sorted(chat, perms, "exp")
        elif cmd == "/listquota":
            self._wg_list_sorted(chat, perms, "quota")
        elif cmd == "/find":
            self.convo[frm] = {"flow": "find"}
            self.send(chat, self._rtl(self.T('bot.on_action.1')))
        elif cmd == "/digest":
            try:
                self.send(chat, build_digest_text())
            except Exception:
                self.send(chat, self.T('bot.on_action.2'))
        elif cmd == "/botusers":
            if "bot.manage" in perms:
                self._bu_action(frm, chat, "list", "")
            else:
                self.send(chat, self.T('bot.backup_page.1'))
        elif cmd == "/botwatch":
            self._bot_watch(frm, chat, 0)
        elif cmd == "/speed":
            self._speed_page(frm, chat, perms)
        elif cmd == "/backup":
            self._backup_page(chat, perms)
        elif cmd == "/ecmp":
            if "ecmp.manage" in perms:
                self._ecmp_page(chat, frm)
            else:
                self.send(chat, self.T('bot.backup_page.1'))
        elif cmd == "/warp":
            if "warp.manage" in perms:
                self._warp_page(chat, frm)
            else:
                self.send(chat, self.T('bot.backup_page.1'))
        else:
            self._main_menu(chat, frm)

    # ---- منوی اصلی بر اساسِ مجوزها
    def _main_menu(self, chat, frm):
        p = bot_perms(frm) or set()
        rows = []
        if "wg.view" in p:
            rows.append([{"text": self.T('bot.main_menu.6'), "callback_data": "wg:list"}])
        if "proxy.view" in p:
            rows.append([{"text": self.T('bot.main_menu.7'), "callback_data": "px:list"}])
        if "tun.view" in p:
            rows.append([{"text": self.T('bot.tun_list.2'), "callback_data": "tun:list"}])
        if "sys.view" in p:
            rows.append([{"text": self.T('bot.main_menu.8'), "callback_data": "sys:status"}])
        if "net.view" in p:
            rows.append([{"text": self.T('bot.main_menu.9'),
                          "callback_data": "lk:page"}])
        if "ecmp.manage" in p:
            rows.append([{"text": self.T('bot.main_menu.10'), "callback_data": "ec:page"}])
        if "warp.manage" in p:
            rows.append([{"text": self.T('bot.main_menu.11'), "callback_data": "wp:page"}])
        if "wg.add" in p:
            rows.append([{"text": self.T('bot.main_menu.12'),
                          "callback_data": "wg:add"}])
        if "proxy.add" in p:
            rows.append([{"text": self.T('bot.main_menu.13'),
                          "callback_data": "px:add"}])
        rows.append([{"text": self.T('bot.main_menu.1'), "callback_data": "menu:find"},
                     {"text": self.T('bot.main_menu.2'), "callback_data": "menu:digest"}])
        if "bot.manage" in p:
            rows.append([{"text": self.T('bot.bu_add_user.4'),
                          "callback_data": "bu:list"}])
        role = bot_user_role(frm)
        txt = "\n".join([
            self._titlebar(self.T('bot.main_menu.3')),
            self._kv(self.T('bot.main_menu.4'), self._bu_role_label(role)), "",
            self._rtl(self.T('bot.main_menu.5'))])
        self.send(chat, txt, rows or None)

    # ---- اکشن‌های دکمه‌ای
    def _on_action(self, frm, chat, data):
        p = bot_perms(frm) or set()
        parts = data.split(":")
        area = parts[0]
        act = parts[1] if len(parts) > 1 else ""
        arg = ":".join(parts[2:]) if len(parts) > 2 else ""
        if area == "lang":
            self._set_lang(frm, chat, act)
            return
        if area == "menu":
            self.convo.pop(frm, None)
            if act == "find":
                self.convo[frm] = {"flow": "find"}
                self.send(chat, self._rtl(self.T('bot.on_action.1')))
            elif act == "digest":
                try:
                    self.send(chat, build_digest_text(), [self._back_row()])
                except Exception:
                    self.send(chat, self.T('bot.on_action.2'))
            else:
                self._main_menu(chat, frm)
        elif area == "ok":            # پاسخِ تأیید (بله/خیر)
            self._on_confirm(frm, chat, act == "yes")
        elif area == "wg" and "wg.view" in p:
            self._wg_action(frm, chat, act, arg, p)
        elif area == "px" and "proxy.view" in p:
            self._px_action(frm, chat, act, arg, p)
        elif area == "tun" and "tun.view" in p:
            self._tun_list(chat)
        elif area == "sys" and "sys.view" in p:
            self._sys_status(chat)
        elif area == "ec" and "ecmp.manage" in p:
            self._ecmp_action(frm, chat, act)
        elif area == "lk" and "net.view" in p:
            self._leak_audit(chat)
        elif area == "wp" and "warp.manage" in p:
            self._warp_action(frm, chat, act, arg)
        elif area == "bu" and "bot.manage" in p:
            self._bu_action(frm, chat, act, arg)
        elif area == "bw":            # پایشِ کاربرانِ ربات (فقط مالک؛ چکِ داخلی)
            self._bot_watch(frm, chat, int(act) if act.isdigit() else 0)
        elif area == "spd" and "sys.view" in p:
            self._speed_action(frm, chat, act, p)

    # ---- الگوی تأیید Yes/No
    def _ask_confirm(self, frm, chat, st, prompt):
        self.convo[frm] = st
        self.send(chat, self._rtl(prompt), [[
            {"text": self.T('bot.leak_audit.15'), "callback_data": "ok:yes"},
            {"text": self.T('bot.leak_audit.21'), "callback_data": "ok:no"}]])

    def _on_confirm(self, frm, chat, yes):
        st = self.convo.pop(frm, None)
        if not st or st.get("flow") != "confirm":
            return
        if not yes:
            self.send(chat, self.T('bot.on_confirm.1'), [self._back_row()])
            return
        self._apply(frm, chat, st)

    def _back_row(self):
        return [{"text": self.T("bot.menu"), "callback_data": "menu:"}]

    # ---- زبان (per-chat) -------------------------------------------------
    def _lang_menu(self, chat):
        """گزینشگرِ زبان. نامِ هر زبان به خطِ خودش می‌ماند، پس ترجمه ندارد."""
        rows = [[{"text": ("✅ " if code == self._lang else "") + LANG_LABEL[code],
                  "callback_data": "lang:%s" % code}] for code in LANGS]
        self.send(chat, self._rtl(self.T("bot.lang.pick")), rows)

    def _set_lang(self, frm, chat, code):
        if not bot_set_lang(frm, code):
            return
        self._lang = norm_lang(code) or DEFAULT_LANG
        # منوی دستورها هم به زبانِ تازه (و اگر مالک بود، منوی پیش‌فرض هم)
        threading.Thread(target=bot_setcommands, daemon=True).start()
        self.send(chat, self._rtl(self.T("bot.lang.done",
                                         name=LANG_LABEL[self._lang])))
        self._main_menu(chat, frm)

    PAGE = 8   # آیتم در هر صفحه‌ی لیست

    def _paged(self, items, page, make_btn, nav_prefix):
        """برشِ صفحه + دکمه‌های ناوبری. برمی‌گرداند (rows, page, pages)."""
        total = len(items)
        pages = max(1, (total + self.PAGE - 1) // self.PAGE)
        page = max(0, min(page, pages - 1))
        rows = [make_btn(it) for it in
                items[page * self.PAGE:(page + 1) * self.PAGE]]
        if pages > 1:
            nav = []
            if page > 0:
                nav.append({"text": self.T('bot.paged.1'),
                            "callback_data": "%s:%d" % (nav_prefix, page - 1)})
            nav.append({"text": "%d/%d" % (page + 1, pages),
                        "callback_data": "x"})
            if page < pages - 1:
                nav.append({"text": self.T('bot.paged.2'),
                            "callback_data": "%s:%d" % (nav_prefix, page + 1)})
            rows.append(nav)
        rows.append(self._back_row())
        return rows, page, pages

    # ---- وایرگارد
    def _wg_action(self, frm, chat, act, arg, p):
        if act == "list":
            s = build_stats()
            users = s.get("users", [])
            if not users:
                self.send(chat, self.T('bot.wg_action.1'), [self._back_row()])
                return
            page = int(arg) if arg.isdigit() else 0
            def mk(u):
                tag = self.T('bot.mk.1') if u.get("online") else ""
                return [{"text": "%s (%s)%s" % (u["name"], u["iface"], tag),
                         "callback_data": "wg:show:%s|%s" % (u["iface"], u["name"])}]
            rows, page, pages = self._paged(users, page, mk, "wg:list")
            self.send(chat, self._rtl(self.T('bot.wg_action.2', p0=_fa_num(len(users)), p1=_fa_num(page + 1), p2=_fa_num(pages))), rows)
        elif act == "show":
            iface, _, name = arg.partition("|")
            self._wg_show(chat, iface, name, p)
        elif act == "graph":
            parts2 = arg.split("|")
            iface = parts2[0] if parts2 else ""
            name = parts2[1] if len(parts2) > 1 else ""
            mode = parts2[2] if len(parts2) > 2 else "7d"
            self._wg_graph(chat, iface, name, mode)
        elif act == "conf" and "wg.conf" in p:
            self._wg_conf(chat, iface_name=arg)
        elif act == "add" and "wg.add" in p:
            self._start_wg_add(frm, chat)
        elif act == "addw" and "wg.add" in p:
            self._wg_add_cb(frm, chat, arg, p)
        elif act in ("ren", "quo", "rat") and "wg.edit" in p:
            iface, _, name = arg.partition("|")
            prompts = {"ren": self.T('bot.wg_action.3'),
                       "quo": self.T('bot.wg_action.4'),
                       "rat": self.T('bot.wg_action.5')}
            self.convo[frm] = {"flow": "input", "kind": "wg", "act": act,
                               "iface": iface, "name": name}
            self.send(chat, self._rtl("<b>%s</b> · <code>%s</code>"
                      % (esc_html(name), esc_html(iface))) + "\n"
                      + self._rtl(prompts[act]))
        elif act == "tog" and "wg.edit" in p:
            iface, _, name = arg.partition("|")
            u = self._wg_find(iface, name)
            newv = not (u and u.get("enabled"))
            self._ask_confirm(frm, chat,
                {"flow": "confirm", "kind": "wg", "act": "tog",
                 "iface": iface, "name": name, "val": newv},
                self.T('bot.wg_action.6', p0=self.T('bot.px_show.1') if newv else self.T('bot.px_show.2'), p1=name))
        elif act == "key" and "wg.edit" in p:
            iface, _, name = arg.partition("|")
            self._ask_confirm(frm, chat,
                {"flow": "confirm", "kind": "wg", "act": "key",
                 "iface": iface, "name": name},
                self.T('bot.wg_action.7', p0=name))
        elif act == "del" and "wg.del" in p:
            iface, _, name = arg.partition("|")
            self._ask_confirm(frm, chat,
                {"flow": "confirm", "kind": "wg", "act": "del",
                 "iface": iface, "name": name},
                self.T('bot.wg_action.8', p0=name, p1=iface))

    def _wg_find(self, iface, name):
        for u in build_stats().get("users", []):
            if u["iface"] == iface and u["name"] == name:
                return u
        return None

    def _wg_show(self, chat, iface, name, p):
        u = self._wg_find(iface, name)
        if not u:
            self.send(chat, self.T('bot.wg_show.2'), [self._back_row()])
            return
        meta = META.meta_all().get((iface, name), {})
        quota = meta.get("quota_gb")
        exp = meta.get("expires")
        status = (self.T('bot.wg_show.1') if u.get("online")
                  else (self.T('bot.px_show.1') if u.get("enabled") else self.T('bot.px_show.2')))
        txt = "\n".join([
            self._rtl("<b>%s</b> · <code>%s</code>"
                      % (esc_html(name), esc_html(iface))), "",
            self._kv(self.T('bot.ecmp_page.2'), status),
            self._kv("IP:", u.get("ip", "—"), latin=True),
            self._kv(self.T('bot.wg_show.3'), "↓%s ↑%s" % (
                fmt_bytes_srv(u.get("rx", 0)), fmt_bytes_srv(u.get("tx", 0)))),
            self._kv(self.T('bot.wg_show.4'), (_fa_num("%s GB" % quota)) if quota
                     else self.T('bot.wg_add_create.12')),
            self._kv(self.T('bot.wg_show.5'), self._fa_date(exp) if exp else self.T('bot.wg_add_create.14')),
            self._kv(self.T('bot.wg_show.6'), _ago_srv(u.get("handshake", 0)))])
        a = "%s|%s" % (iface, name)
        rows = [[{"text": self.T('bot.speed_page.3'), "callback_data": "wg:graph:" + a}]]
        if "wg.conf" in p:
            rows.append([{"text": self.T('bot.wg_show.7'), "callback_data": "wg:conf:" + a}])
        if "wg.edit" in p:
            rows.append([
                {"text": self.T('bot.wg_show.8'), "callback_data": "wg:ren:" + a},
                {"text": self.T('bot.wg_show.9'), "callback_data": "wg:quo:" + a},
                {"text": self.T('bot.wg_show.10'), "callback_data": "wg:rat:" + a}])
            rows.append([
                {"text": self.T('bot.px_show.2') if u.get("enabled") else self.T('bot.px_show.1'),
                 "callback_data": "wg:tog:" + a},
                {"text": self.T('bot.wg_show.11'), "callback_data": "wg:key:" + a}])
        if "wg.del" in p:
            rows.append([{"text": self.T('bot.wg_show.12'), "callback_data": "wg:del:" + a}])
        rows.append(self._back_row())
        self.send(chat, txt, rows)

    # عنصرِ دوم کلیدِ i18n است نه متن؛ ترجمه سرِ مصرف انجام می‌شود، چون
    # بدنهٔ کلاس در زمانِ import اجرا می‌شود و آنجا هنوز زبانی وجود ندارد.
    RANGES = [("24h", "bot.range.24h", "24H"), ("7d", "bot.range.7d", "7D"),
              ("30d", "bot.range.30d", "30D"), ("6m", "bot.range.6m", "6M")]

    def _range_row(self, prefix, arg, cur):
        """نوارِ دکمه‌های انتخابِ بازه؛ بازه‌ی فعلی با نشان."""
        row = []
        for rid, fa_key, _ in self.RANGES:
            mark = "• " if rid == cur else ""
            row.append({"text": mark + self.T(fa_key),
                        "callback_data": "%s:%s|%s" % (prefix, arg, rid)})
        return row

    def _xlabels(self, rows, mode):
        """برچسب‌های زمانِ ابتدا/میانه/انتها از کلیدِ ردیف‌ها (ascii)."""
        if not rows:
            return []
        def short(t):
            t = str(t)
            if mode == "24h":                 # "YYYY-MM-DD HH" → "HH:00"
                return (t.split(" ")[-1] + ":00") if " " in t else t
            p = t.split("-")                  # "YYYY-MM-DD" → "MM-DD"
            return "-".join(p[1:]) if len(p) == 3 else t
        idx = [0, len(rows) // 2, len(rows) - 1]
        return [(i / max(1, len(rows) - 1), short(rows[i]["t"]))
                for i in sorted(set(idx))]

    def _wg_graph(self, chat, iface, name, mode="7d"):
        self._edit = None            # عکس ادیت‌شدنی نیست؛ پیام‌های تازه بفرست
        u = self._wg_find(iface, name)
        pub = (u or {}).get("public_key", "")
        rows = META.usage_series(iface, pub, mode) if pub else []
        rx = [r["rx"] for r in rows]
        tx = [r["tx"] for r in rows]
        png = render_chart_png(
            [(rx, (63, 185, 80), "RX"), (tx, (88, 166, 255), "TX")],
            x_labels=self._xlabels(rows, mode),
            title=[x[2] for x in self.RANGES if x[0] == mode][0], bars=True)
        fa = self.T([x[1] for x in self.RANGES if x[0] == mode][0])
        trx, ttx = sum(rx), sum(tx)
        cap = "\n".join([
            self._rtl(self.T('bot.wg_graph.2', p0=esc_html(name), p1=fa)),
            self._kv(self.T('bot.wg_graph.3'), fmt_bytes_srv(trx)),
            self._kv(self.T('bot.wg_graph.4'), fmt_bytes_srv(ttx)),
            self._kv(self.T('bot.wg_graph.5'), fmt_bytes_srv(trx + ttx)),
            self._kv(self.T('bot.wg_graph.6'), fmt_bytes_srv(max(rx + tx) if (rx or tx) else 0))])
        a = "%s|%s" % (iface, name)
        self.send_photo(chat, png, cap)
        self.send(chat, self._rtl(self.T('bot.wg_graph.1')),
                  [self._range_row("wg:graph", a, mode),
                   [{"text": self.T('bot.px_dests.1'), "callback_data": "wg:show:" + a}]])

    def _wg_conf(self, chat, iface_name):
        iface, _, name = iface_name.partition("|")
        path = _client_conf_path(iface, name)
        if not path or not os.path.exists(path):
            self.send(chat, self.T('bot.wg_conf.1'),
                      [self._back_row()])
            return
        with open(path, encoding="utf-8") as f:
            conf = f.read()
        self._send_wg_conf(chat, name, conf)

    def _private(self):
        """True اگر درخواستِ جاری از چتِ خصوصی (یا نامعلوم) آمده باشد."""
        return self._chat_type in (None, "private")

    def _refuse_in_group(self, chat):
        """رازها (کلیدِ خصوصی، PSK، رمزِ پروکسی) فقط در چتِ خصوصی؛ در گروه هر
        عضوِ دیگری هم می‌بیند. True یعنی رد شد و پیام رفت."""
        if self._private():
            return False
        self.send(chat, self._rtl(self.T('bot.private_only')), [self._back_row()])
        return True

    def _send_wg_conf(self, chat, name, conf):
        """کانفیگِ وایرگارد: (۱) QR برای اسکنِ مستقیم در اپِ موبایل،
        (۲) فایلِ .conf قابلِ Import، (۳) بلوکِ <pre> لمس‌برای‌کپی."""
        if self._refuse_in_group(chat):
            return
        endpoint = ""
        for ln in conf.splitlines():
            if ln.strip().lower().startswith("endpoint"):
                endpoint = ln.split("=", 1)[1].strip()
        qr = render_qr_png(conf)
        if qr:
            self.send_photo(chat, qr, self._rtl(
                self.T('bot.send_wg_conf.4', p0=esc_html(name))))
        self.send_doc(chat, "%s.conf" % name, conf,
                      self._rtl(self.T('bot.send_wg_conf.3')))
        head = self._rtl(self.T('bot.send_wg_conf.1', p0=esc_html(name)))
        self.send(chat, head + "\n" + self.LRM + "<pre>" + esc_html(conf)
                  + "</pre>")
        rows = []
        b = self._copy_btn(self.T('bot.send_wg_conf.2'), endpoint)
        if b:
            rows.append([b])
        if rows:
            self.send(chat, self._rtl("Endpoint:") + "\n"
                      + self._code_line(endpoint), rows + [self._back_row()])

    # ---- پروکسی
    def _px_action(self, frm, chat, act, arg, p):
        if act == "dst":
            uname, _, pg = arg.partition("|")
            self._px_dests(chat, uname, int(pg) if pg.isdigit() else 0)
            return
        if act == "list":
            users = META.proxy_users()
            if not users:
                self.send(chat, self.T('bot.px_action.1'), [self._back_row()])
                return
            page = int(arg) if arg.isdigit() else 0
            def mk(u):
                return [{"text": "%s%s" % (u["username"],
                         self.T('bot.mk.2') if u.get("noauth") else ""),
                         "callback_data": "px:show:%s" % u["username"]}]
            rows, page, pages = self._paged(users, page, mk, "px:list")
            self.send(chat, self._rtl(self.T('bot.px_action.2', p0=_fa_num(len(users)), p1=_fa_num(page + 1), p2=_fa_num(pages))), rows)
        elif act == "show":
            self._px_show(chat, arg, p)
        elif act == "graph":
            uname, _, mode = arg.partition("|")
            self._px_graph(chat, uname, mode or "30d")
        elif act == "conf" and "proxy.conf" in p:
            self._px_conf(chat, arg)
        elif act == "add" and "proxy.add" in p:
            self._start_px_add(frm, chat)
        elif act == "addw" and "proxy.add" in p:
            self._px_add_cb(frm, chat, arg, p)
        elif act in ("ren", "quo", "rat") and "proxy.edit" in p:
            prompts = {"ren": self.T('bot.px_action.3'),
                       "quo": self.T('bot.wg_action.4'),
                       "rat": self.T('bot.wg_action.5')}
            self.convo[frm] = {"flow": "input", "kind": "px", "act": act,
                               "name": arg}
            self.send(chat, self._rtl("<b>%s</b>" % esc_html(arg)) + "\n"
                      + self._rtl(prompts[act]))
        elif act == "tog" and "proxy.edit" in p:
            u = META.proxy_user_get(arg)
            newv = 0 if (u and u.get("enabled")) else 1
            self._ask_confirm(frm, chat,
                {"flow": "confirm", "kind": "px", "act": "tog",
                 "name": arg, "val": newv},
                self.T('bot.px_action.4', p0=self.T('bot.px_show.1') if newv else self.T('bot.px_show.2'), p1=arg))
        elif act == "pwd" and "proxy.edit" in p:
            self._ask_confirm(frm, chat,
                {"flow": "confirm", "kind": "px", "act": "pwd", "name": arg},
                self.T('bot.px_action.5', p0=arg))
        elif act == "del" and "proxy.del" in p:
            self._ask_confirm(frm, chat,
                {"flow": "confirm", "kind": "px", "act": "del", "name": arg},
                self.T('bot.px_action.6', p0=arg))

    def _px_show(self, chat, username, p):
        u = META.proxy_user_get(username)
        if not u:
            self.send(chat, self.T('bot.wg_show.2'), [self._back_row()])
            return
        month = META.proxy_month_totals(
            datetime.now().strftime("%Y-%m")).get(username, 0)
        st = self.T('bot.px_show.1') if u.get("enabled") else self.T('bot.px_show.2')
        if u.get("auto_disabled"):
            st = self.T('bot.px_show.3', p0=u['auto_disabled'])
        proto = {"http": self.T('bot.px_show.5'), "https": self.T('bot.px_show.6')}.get(
            u.get("protocol", "both"), self.T('bot.px_show.4'))
        txt = "\n".join([
            self._rtl("<b>%s</b>" % esc_html(username)), "",
            self._kv(self.T('bot.ecmp_page.2'), st),
            self._kv(self.T('bot.px_show.7'), self.T('bot.px_show.12') if u.get("noauth") else self.T('bot.px_add_create.3')),
            self._kv(self.T('bot.px_show.8'), proto),
            self._kv(self.T('bot.px_show.9'), _fa_num("%.1f Mbit/s" % (u["rate_kbit"] / 1000))
                     if u.get("rate_kbit") else self.T('bot.wg_add_create.12')),
            self._kv(self.T('bot.wg_show.4'), _fa_num("%s GB" % u["quota_gb"])
                     if u.get("quota_gb") else self.T('bot.wg_add_create.12')),
            self._kv(self.T('bot.wg_show.5'), self._fa_date(u.get("expires"))
                     if u.get("expires") else self.T('bot.wg_add_create.14')),
            self._kv(self.T('bot.px_show.10'), fmt_bytes_srv(month))])
        rows = [[{"text": self.T('bot.speed_page.3'), "callback_data": "px:graph:%s" % username},
                 {"text": self.T('bot.px_show.11'), "callback_data": "px:dst:%s" % username}]]
        if "proxy.conf" in p:
            rows.append([{"text": self.T('bot.wg_show.7'), "callback_data": "px:conf:%s" % username}])
        if "proxy.edit" in p:
            rows.append([
                {"text": self.T('bot.wg_show.8'), "callback_data": "px:ren:%s" % username},
                {"text": self.T('bot.wg_show.9'), "callback_data": "px:quo:%s" % username},
                {"text": self.T('bot.wg_show.10'), "callback_data": "px:rat:%s" % username}])
            row2 = [{"text": self.T('bot.px_show.2') if u.get("enabled") else self.T('bot.px_show.1'),
                     "callback_data": "px:tog:%s" % username}]
            if not u.get("noauth"):
                row2.append({"text": self.T('bot.px_show.13'),
                             "callback_data": "px:pwd:%s" % username})
            rows.append(row2)
        if "proxy.del" in p:
            rows.append([{"text": self.T('bot.wg_show.12'), "callback_data": "px:del:%s" % username}])
        rows.append(self._back_row())
        self.send(chat, txt, rows)

    def _px_dests(self, chat, username, page=0):
        """مقصدهای کاربرِ پروکسی — معادلِ مودالِ وب: سلامت، شمارِ درخواست/
        موفق/خطا، حجم، و تازگیِ آخرین اتصال؛ جدیدترین اول با صفحه‌بندی."""
        rows = META.proxy_dests(username, limit=500)
        back = [{"text": self.T('bot.px_dests.1'),
                 "callback_data": "px:show:" + username}]
        if not rows:
            self.send(chat, self._rtl(self.T('bot.px_dests.6', p0=esc_html(username))), [back])
            return
        per = 6
        pages = max(1, (len(rows) + per - 1) // per)
        page = max(0, min(page, pages - 1))
        L = [self._titlebar(self.T('bot.px_dests.2')),
             self._code_line(username),
             self._rtl(self.T('bot.px_dests.3', p0=_fa_num(len(rows)), p1=_fa_num(page + 1), p2=_fa_num(pages))),
             self._rtl(self.T('bot.px_dests.4')),
             ""]
        for r in rows[page * per:(page + 1) * per]:
            health = (self.T('bot.warp_page.1') if not r["fail"] else
                      self.T('bot.px_dests.5', p0=_fa_num(r['fail'])))
            L.append(self._rtl("<code>%s</code> — <b>%s</b> · %s"
                               % (esc_html(r["host"]), health,
                                  _ago_srv(r["last_seen"]))))
            L.append(self._rtl(self.T('bot.px_dests.7', p0=_fa_num(r['hits']), p1=_fa_num(r['ok']), p2=fmt_bytes_srv(r['bytes'] or 0))))
            L.append("")
        nav = []
        if page + 1 < pages:
            nav.append({"text": self.T('bot.px_dests.8'),
                        "callback_data": "px:dst:%s|%d" % (username, page + 1)})
        if page > 0:
            nav.append({"text": self.T('bot.px_dests.9'),
                        "callback_data": "px:dst:%s|%d" % (username, page - 1)})
        kb = ([nav] if nav else []) + [back, self._back_row()]
        self.send(chat, "\n".join(L).rstrip(), kb)

    def _px_graph(self, chat, username, mode="30d"):
        self._edit = None
        rows = []
        try:
            rows = META.proxy_usage_series(username, mode) or []
        except Exception:
            pass
        series = [r["bytes"] for r in rows]
        png = render_chart_png(
            [(series, (88, 166, 255), "")],
            x_labels=self._xlabels(rows, mode),
            title=[x[2] for x in self.RANGES if x[0] == mode][0], bars=True)
        fa = self.T([x[1] for x in self.RANGES if x[0] == mode][0])
        avg = (sum(series) / len(series)) if series else 0
        cap = "\n".join([
            self._rtl(self.T('bot.px_graph.1', p0=esc_html(username), p1=fa)),
            self._kv(self.T('bot.wg_graph.5'), fmt_bytes_srv(sum(series))),
            self._kv(self.T('bot.px_graph.2'), fmt_bytes_srv(avg)),
            self._kv(self.T('bot.px_graph.3'), fmt_bytes_srv(max(series) if series else 0))])
        self.send_photo(chat, png, cap)
        self.send(chat, self._rtl(self.T('bot.wg_graph.1')),
                  [self._range_row("px:graph", username, mode),
                   [{"text": self.T('bot.px_dests.1'),
                     "callback_data": "px:show:" + username}]])

    def _px_conf(self, chat, username):
        if self._refuse_in_group(chat):
            return
        u = META.proxy_user_get(username)
        if not u:
            self.send(chat, self.T('bot.wg_show.2'), [self._back_row()])
            return
        host = CONFIG.get("server_host") or ""
        pw = u.get("pass_plain", "")
        if u.get("noauth"):
            url = "http://%s:%d" % (host, PROXY_PORT)
        else:
            url = "http://%s:%s@%s:%d" % (username, pw, host, PROXY_PORT)
        # هر مقدار در خطِ جدا، لاتین/چپ‌چین و لمس‌برای‌کپی؛ برچسب‌ها راست‌چین
        lines = [self._rtl(self.T('bot.px_conf.2', p0=esc_html(username))), "",
                 self._rtl(self.T('bot.px_conf.3')),
                 self._code_line(url), "",
                 self._rtl(self.T('bot.px_conf.4')), self._code_line(host),
                 self._rtl(self.T('bot.px_conf.5')), self._code_line(str(PROXY_PORT))]
        if not u.get("noauth"):
            lines += [self._rtl(self.T('bot.px_conf.6')), self._code_line(username),
                      self._rtl(self.T('bot.px_conf.7')), self._code_line(pw)]
        rows = []
        b = self._copy_btn(self.T('bot.px_conf.1'), url)
        if b:
            rows.append([b])
        rows.append(self._back_row())
        self.send(chat, "\n".join(lines), rows)
        qr = render_qr_png(url)
        if qr:
            self.send_photo(chat, qr, self._rtl(
                self.T('bot.px_conf.8', p0=esc_html(username))))

    # ---- تونل‌ها و سرور
    _TUN_ST = {"active": "bot.tunst.active",
               "activating": "bot.tunst.activating",
               "failed": "bot.tunst.failed", "inactive": "bot.tunst.inactive",
               "deactivating": "bot.tunst.deactivating"}
    # همان شش حالتِ «سلامتِ صادقانه»ی جدولِ پنل (tunnel_health) — بدترین اول
    _HEALTH_RANK = ("loop", "dead", "noreturn", "off", "idle", "chain",
                    "healthy")
    # بدونِ ایموجی — قرارِ کامیت ۴۵: پیام‌های ربات ایموجی ندارند
    # off = واژگانِ tunnel_health؛ down = واژگانِ ecmp_tunnel_state
    _HEALTH_LBL = {"healthy": "bot.health.healthy", "idle": "bot.health.idle",
                   "noreturn": "bot.health.noreturn", "dead": "bot.health.dead",
                   "loop": "bot.health.loop", "chain": "bot.health.chain",
                   "off": "bot.health.off", "down": "bot.health.off"}

    def _tun_list(self, chat):
        tunnels = build_stats().get("tunnels", [])
        if not tunnels:
            self.send(chat, self.T('bot.tun_list.1'), [self._back_row()])
            return
        rank = {h: i for i, h in enumerate(self._HEALTH_RANK)}
        tunnels = sorted(tunnels, key=lambda t: (rank.get(t.get("health"), 9),
                                                 t.get("iface", "")))
        bad = sum(1 for t in tunnels
                  if t.get("health") in ("loop", "dead", "noreturn"))
        alive = sum(1 for t in tunnels
                    if t.get("health") in ("healthy", "idle", "chain"))
        L = [self._titlebar(self.T('bot.tun_list.2')), "",
             self._kv(self.T('bot.tun_list.3'), _fa_num(alive)),
             self._kv(self.T('bot.tun_list.4'), _fa_num(bad)), ""]
        for t in tunnels[:60]:
            tags = [self.T(self._HEALTH_LBL.get(t.get("health"), ""))
                    if self._HEALTH_LBL.get(t.get("health"))
                    else t.get("health", "?")]
            if t.get("kind") == "amneziawg":
                tags.append("AWG")
            tags.append(self.T('bot.tun_list.5') if t.get("enabled") else self.T('bot.tun_list.6'))
            rate = (t.get("rx_rate") or 0) + (t.get("tx_rate") or 0)
            if rate >= 1024:
                tags.append("%s KB/s" % _fa_num(int(rate / 1024)))
            L.append(self._rtl("<code>%s</code> — %s"
                     % (esc_html(t["iface"]), " · ".join(tags))))
        self.send(chat, "\n".join(L), [self._back_row()])

    def _sys_status(self, chat):
        snap = SYSMON.snapshot()
        cur = snap.get("cur", snap) if isinstance(snap, dict) else {}
        txt = "\n".join([
            self._titlebar(self.T('bot.sys_status.1')), "",
            self._kv(self.T('bot.sys_status.2'), self._pct(cur.get("cpu"))),
            self._kv(self.T('bot.sys_status.3'), self._pct(cur.get("ram"))),
            self._kv(self.T('bot.sys_status.4'), self._pct(cur.get("disk")))])
        self.send(chat, txt, [self._back_row()])

    # ---- گاردِ ECMP (معادلِ مودالِ وب؛ گیتِ ecmp.manage در _on_action)
    # مشاهده برای هر دارنده‌ی ecmp.manage؛ **تغییر فقط برای مالکِ ربات** —
    # چون یک تنظیمِ سراسریِ مسیریابیِ سرور است، نه ترجیحِ شخصیِ هر کاربر.
    _ECMP_MEM = {"in": "bot.ecmp.in", "out": "bot.ecmp.out"}

    def _ecmp_action(self, frm, chat, act):
        if act == "toggle":
            if bot_user_role(frm) != "owner":
                self.send(chat, self._rtl(self.T('bot.apply_ecmp.2')), [self._back_row()])
                return
            c = dict(ECMP_GUARD_DEFAULTS)
            c.update(CONFIG.get("ecmp_guard") or {})
            to_on = not c.get("enabled")
            if to_on and not ecmp_groups(c):
                self.send(chat, self._rtl(self.T('bot.ecmp_action.2')),
                          [self._back_row()])
                return
            self._ask_confirm(frm, chat,
                              {"flow": "confirm", "kind": "ec",
                               "act": "toggle", "to_on": to_on},
                              self.T('bot.ecmp_action.1', p0=self.T('bot.lit.1') if to_on else self.T('bot.ecmp_page.9')))
            return
        self._ecmp_page(chat, frm)

    def _ecmp_page(self, chat, frm=None):
        c = dict(ECMP_GUARD_DEFAULTS)
        c.update(CONFIG.get("ecmp_guard") or {})
        on = bool(c.get("enabled"))
        da = float(c.get("dead_after", 150))
        L = [self._titlebar(self.T('bot.ecmp_page.1')), "",
             self._kv(self.T('bot.ecmp_page.2'), self.T('bot.px_show.1') if on else self.T('bot.ecmp_page.9')),
             self._kv(self.T('bot.ecmp_page.3'), self.T('bot.ecmp_page.4', p0=_fa_num(int(da)))),
             self._kv(self.T('bot.ecmp_page.5'),
                      self.T('bot.ecmp_page.6', p0=_fa_num(int(c.get('confirm', 2)))))]
        groups = c.get("groups") or []
        if not groups:
            L += ["", self._rtl(self.T('bot.ecmp_page.10'))]
        for g in groups:
            gname = str(g.get("name") or g.get("routes_file", "?"))
            gtag = "" if g.get("enabled", True) else self.T('bot.ecmp_page.7')
            L += ["", self._head(self.T('bot.ecmp_page.11', p0=esc_html(gname), p1=gtag))]
            for t in (g.get("tunnels") or []):
                if not (isinstance(t, str) and IFACE_RE.match(t)):
                    continue
                st = ecmp_tunnel_state(t, da)
                parts = [self.T(self._HEALTH_LBL[st])
                         if st in self._HEALTH_LBL else st]
                mem = ECMPGUARD.membership.get((g.get("name", ""), t))
                if on and mem:
                    parts.append(self.T(self._ECMP_MEM[mem])
                                 if mem in self._ECMP_MEM else mem)
                L.append(self._rtl("<code>%s</code> — %s"
                         % (esc_html(t), " · ".join(parts))))
        row1 = [{"text": self.T('bot.ecmp_page.8'), "callback_data": "ec:page"}]
        if bot_user_role(frm) == "owner":     # دکمه‌ی تغییر فقط برای مالک
            row1.insert(0, {"text": self.T('bot.ecmp_page.13') if on
                            else self.T('bot.ecmp_page.14'),
                            "callback_data": "ec:toggle"})
        else:
            L += ["", self._rtl(self.T('bot.ecmp_page.12'))]
        self.send(chat, "\n".join(L), [row1, self._back_row()])

    def _apply_ecmp(self, frm, chat, st):
        # دفاعِ دوم: مالک‌بودن در لحظه‌ی اجرا هم چک می‌شود (ممکن است بینِ
        # پرسش و تأیید، نقشِ کاربر عوض شده باشد)
        if bot_user_role(frm) != "owner":
            self.send(chat, self._rtl(self.T('bot.apply_ecmp.2')), [self._back_row()])
            return
        c = dict(ECMP_GUARD_DEFAULTS)
        c.update(CONFIG.get("ecmp_guard") or {})
        to_on = bool(st.get("to_on"))
        # همان گاردِ API: روشن‌کردن بدونِ گروهِ فعال بی‌معنی است (شرایط
        # ممکن است بینِ پرسش و تأیید عوض شده باشد — دوباره چک کن)
        if to_on and not ecmp_groups(c):
            self.send(chat, self._rtl(self.T('bot.apply_ecmp.3')), [self._back_row()])
            return
        with config_txn() as cfg:
            c["enabled"] = to_on
            cfg["ecmp_guard"] = c
        # مثلِ /api/ecmp/save: وضعیتِ عضویت از نو ساخته شود
        ECMPGUARD.membership.clear()
        ECMPGUARD.dead_streak.clear()
        audit("bot:%s" % frm, "settings", "ecmp.settings.bot", "",
              adet("ui.audit.det.turnedon") if to_on else adet("ui.audit.det.turnedoff"), "", True)
        log_action("ecmp guard %s by bot:%s"
                   % ("enabled" if to_on else "disabled", frm))
        self.send(chat, self._rtl(self.T('bot.apply_ecmp.1', p0=self.T('bot.lit.1') if to_on else self.T('bot.ecmp_page.9'))),
                  [[{"text": self.T('bot.ecmp_page.1'), "callback_data": "ec:page"}],
                   self._back_row()])

    # ---- مسیریابیِ WARP (وضعیت + افزودن/حذفِ مقصد — فقط مالک برای تغییر)
    def _warp_action(self, frm, chat, act, arg):
        if act == "events":
            self._warp_events(chat)
            return
        if act == "quality":
            self._warp_quality(chat)
            return
        if act == "rank":
            self._warp_rank(chat)
            return
        if act == "ai":
            self._warp_ai_usage(chat)
            return
        if act == "auto":
            self._warp_autodetect(chat)
            return
        if act == "add":
            if bot_user_role(frm) != "owner":
                self.send(chat, self._rtl(self.T('bot.warp_action.3')), [self._back_row()])
                return
            self.convo[frm] = {"flow": "warp_add"}
            self.send(chat, self._rtl(self.T('bot.warp_action.1')))
            return
        if act == "del":
            if bot_user_role(frm) != "owner":
                self.send(chat, self._rtl(self.T('bot.warp_action.4')), [self._back_row()])
                return
            cur = warp_targets_read()
            if arg in cur and len(cur) > 1:
                ok, werr = warp_targets_write([t for t in cur if t != arg],
                                              "bot:%s" % frm)
                if ok:
                    warp_apply()
                    log_action("warp target removed: %s by bot:%s"
                               % (arg, frm))
                    self.send(chat, self._rtl(self.T('bot.warp_action.5', p0=esc_html(arg))),
                              [[{"text": self.T('bot.warp_page.3'),
                                 "callback_data": "wp:page"}]])
                    return
            self.send(chat, self._rtl(self.T('bot.warp_action.2')), [self._back_row()])
            return
        self._warp_page(chat, frm)

    def _warp_page(self, chat, frm=None):
        w = warp_status(force=True)
        if not w.get("installed"):
            self.send(chat, self._rtl(self.T('bot.warp_page.11')),
                      [self._back_row()])
            return
        ifc = w.get("iface") or {}
        g = w.get("guard") or {}
        hs = ifc.get("handshake_age")
        health = self.T('bot.warp_page.1') if w.get("healthy") else self.T('bot.warp_page.2')
        L = [self._titlebar(self.T('bot.warp_page.3')), "",
             self._kv(self.T('bot.warp_page.4'), health),
             self._kv(self.T('bot.warp_page.5'), w.get("account") or "?"),
             self._kv(self.T('bot.warp_page.6'), self.T('bot.warp_page.12') if ifc.get("up") else self.T('bot.warp_page.13')),
             self._kv(self.T('bot.warp_page.7'), (self.T('bot.warp_page.14', p0=_fa_num(int(hs))))
                      if hs is not None else "—"),
             self._kv(self.T('bot.warp_page.8'), "%s ← %s"
                      % (esc_html(w.get("egress_actual") or "?"),
                         "Cloudflare"))]
        # خروجیِ واقعیِ AI — از iface ِ گارد جداست (رجوع به ai_egress_diag).
        # بدونِ این خط، ربات همچنان wgwarp را گزارش می‌کرد در حالی که
        # ترافیک از جای دیگری می‌رفت.
        ae = w.get("ai_egress") or {}
        if ae.get("main"):
            pool = ae.get("pool") or []
            if pool:
                okn = sum(1 for x in pool if x.get("up") and not x.get("burned"))
                txt = self.T('bot.warp_page.26',
                             p0=esc_html(ae["main"]),
                             p1=_fa_num(len(pool)), p2=_fa_num(okn))
                if ae.get("burned"):
                    txt += " · " + self.T('bot.warp_page.27',
                                          p0=esc_html(", ".join(ae["burned"])))
            else:
                txt = esc_html(ae["main"])
            L.append(self._kv(self.T('bot.warp_page.25'), txt))
        if g.get("enabled"):
            gs = (self.T('bot.warp_page.9') if g.get("rule") == "off"
                  else (self.T('bot.warp_page.1') if g.get("alive") else self.T('bot.warp_page.15')))
            L.append(self._kv(self.T('bot.warp_page.16'), gs))
        # کشفِ خودکار فهرست را بی‌اطلاعِ کاربر تغییر می‌دهد، پس وضعیتش باید
        # همین‌جا دیده شود نه فقط در زیرصفحه.
        ad = warp_autodetect_state()
        if ad.get("ts"):
            n_add = len(ad.get("added") or [])
            L.append(self._kv(self.T('bot.warp_page.17'), self.T('bot.warp_page.18', p0=_ago_srv(ad.get('ts')), p1=_fa_num(n_add))))
        L += ["", self._head(self.T('bot.warp_page.10'))]
        for t in warp_targets_read()[:30]:
            L.append(self._rtl("<code>%s</code>" % esc_html(t)))
        rows = [
            [{"text": self.T('bot.warp_page.19'), "callback_data": "wp:quality"},
             {"text": self.T('bot.warp_page.20'), "callback_data": "wp:events"}],
            [{"text": self.T('bot.warp_page.21'), "callback_data": "wp:rank"},
             {"text": self.T('bot.warp_page.22'), "callback_data": "wp:ai"}],
            [{"text": self.T('bot.ecmp_page.8'), "callback_data": "wp:page"}],
        ]
        if ad.get("ts"):
            rows.insert(2, [{"text": self.T('bot.warp_page.23'),
                             "callback_data": "wp:auto"}])
        if bot_user_role(frm) == "owner":
            rows.insert(0, [{"text": self.T('bot.warp_page.24'), "callback_data": "wp:add"}])
        rows.append(self._back_row())
        self.send(chat, "\n".join(L), rows)

    # ---- زیرصفحه‌های WARP (parity با پنل: رویداد، کیفیتِ مسیر، رتبه، AI)
    # رنگِ نوعِ رویداد در پنل → آیکنِ متنی در ربات. سبز=بازگشت/روشن،
    # قرمز=اضطراری/استندبای/fail-open، کهربایی=تغییرِ مسیر/کشور/QUIC.
    _WARP_EVENT_ICON = {
        "restore": "🟢", "preset_on": "🟢",
        "degrade": "🔴", "standby": "🔴", "failopen_sni": "🔴",
        "egress": "🟡", "rotate": "🟡", "country": "🟡", "quic": "🟡",
        "target_add": "➕", "target_del": "➖", "preset_off": "⚪",
    }
    _SPARK = "▁▂▃▄▅▆▇█"

    def _send_fresh(self, chat, text, keyboard=None):
        """ارسالِ پیامِ تازه بدونِ منطقِ ویرایش — امن برای نخِ پس‌زمینه.
        self._edit تک‌نخیِ حلقه‌ی poll است و نباید از نخِ دیگر لمس شود."""
        p = {"chat_id": chat, "text": text, "parse_mode": "HTML",
             "disable_web_page_preview": True}
        if keyboard is not None:
            p["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
        return tg_api(self._token(), "sendMessage", p,
                      iface=alert_cfg()["iface"])

    @classmethod
    def _spark(cls, vals):
        """نمودارِ خطیِ فشرده با کاراکترهای بلوکی (بدونِ PNG — چون محورِ
        render_chart_png بایت‌محور است و برای ms مناسب نیست)."""
        vals = [float(v) for v in vals if v is not None]
        if not vals:
            return ""
        lo, hi = min(vals), max(vals)
        rng = (hi - lo) or 1.0
        return "".join(cls._SPARK[min(len(cls._SPARK) - 1,
                                      int((v - lo) / rng * (len(cls._SPARK) - 1)))]
                       for v in vals)

    def _warp_backrows(self, refresh):
        return [[{"text": self.T('bot.ecmp_page.8'), "callback_data": refresh}],
                [{"text": self.T('bot.warp_page.3'), "callback_data": "wp:page"}]]

    def _warp_events(self, chat):
        """خطِ زمانیِ رویدادهای WARP (warp_events_read) — جدید به قدیم."""
        evs = warp_events_read(20)
        L = [self._titlebar(self.T('bot.warp_events.1')), ""]
        if not evs:
            L.append(self._rtl(self.T('bot.warp_events.2')))
        else:
            for e in evs:
                icon = self._WARP_EVENT_ICON.get(e.get("kind"), "•")
                lk = "ui.warpev.%s" % e.get("kind")
                lbl = self.T(lk) if lk in I18N else (e.get("label") or "")
                L.append(self._rtl("%s <b>%s</b> · %s"
                                   % (icon, esc_html(lbl),
                                      _ago_srv(e.get("ts")))))
                det = (e.get("detail") or "").strip()
                who = (e.get("actor") or "").strip()
                sub = []
                if det:
                    sub.append(esc_html(det))
                if who:
                    sub.append(self.T('bot.warp_events.3', p0=esc_html(who)))
                if sub:
                    L.append(self._rtl("<i>%s</i>" % " · ".join(sub)))
        self.send(chat, "\n".join(L), self._warp_backrows("wp:events"))

    def _warp_quality(self, chat):
        """کیفیتِ مسیر: میانگینِ TTFBِ WARP/عادی + حکمِ سالم/کند + روند."""
        ser = warp_latency_series()
        pts = ser.get("points") or []
        wa, da = ser.get("warp_avg"), ser.get("direct_avg")
        L = [self._titlebar(self.T('bot.warp_quality.1')), ""]
        if wa is None:
            L.append(self._rtl(self.T('bot.warp_quality.2')))
        else:
            L.append(self._kv(self.T('bot.warp_quality.3'), _fa_num("%d ms" % wa)))
            L.append(self._kv(self.T('bot.warp_quality.4'),
                              _fa_num("%d ms" % da) if da is not None else "—"))
            slow = (wa >= ser.get("slow_ms", 0) and da is not None and da > 0
                    and wa >= da * ser.get("slow_ratio", 1e9))
            L.append(self._kv(self.T('bot.ecmp_page.2'), self.T('bot.warp_quality.6') if slow else self.T('bot.warp_page.1')))
            L.append(self._kv(self.T('bot.warp_quality.5'), _fa_num(
                self.T('bot.warp_quality.7', p0=ser.get('slow_ms', 0), p1=ser.get('slow_ratio', 0)))))
            wv = [p.get("warp") for p in pts if p.get("warp") is not None]
            if len(wv) >= 2:
                L += ["", self._rtl(self.T('bot.warp_quality.8', p0=_fa_num(len(wv)))),
                      self.LRM + "<code>" + self._spark(wv) + "</code>"]
        self.send(chat, "\n".join(L), self._warp_backrows("wp:quality"))

    def _warp_autodetect(self, chat):
        """نتیجه‌ی آخرین اجرای کشفِ خودکارِ دامنه‌های بلاک‌شده.

        این سرویس فهرستِ مقصدها را **خودش** تغییر می‌دهد، پس شفافیتش مهم
        است: کاربر باید ببیند چه چیزی و چرا افزوده شده. «۴۰۳ از ایران +
        غیر۴۰۳ از WARP» تنها الگویی است که افزودن را توجیه می‌کند.
        """
        ad = warp_autodetect_state()
        L = [self._titlebar(self.T('bot.warp_autodetect.1')), ""]
        if not ad.get("ts"):
            L.append(self._rtl(self.T('bot.warp_autodetect.6')))
            self.send(chat, "\n".join(L), self._warp_backrows("wp:auto"))
            return
        added = ad.get("added") or []
        blocked = ad.get("blocked") or []
        L += [self._kv(self.T('bot.warp_autodetect.2'), _ago_srv(ad.get("ts"))),
              self._kv(self.T('bot.warp_autodetect.3'), self.T('bot.warp_autodetect.4', p0=_fa_num(int(ad.get('checked') or 0)))),
              self._kv(self.T('bot.warp_autodetect.5'), _fa_num(len(added)))]
        if ad.get("dry_run"):
            L.append(self._kv(self.T('bot.warp_autodetect.7'), self.T('bot.warp_autodetect.8')))
        if added:
            L += ["", self._head(self.T('bot.warp_autodetect.9'))]
            for d in added[:15]:
                L.append(self._rtl("<code>%s</code>" % esc_html(str(d))))
        # موارد بلاک‌شده‌ای که هنوز افزوده نشده‌اند (سقفِ هر اجرا) — همان‌ها
        # هستند که اجرای بعدی می‌گیرد؛ دیدنشان یعنی کاربر غافلگیر نمی‌شود.
        rest = [b for b in blocked
                if isinstance(b, dict) and b.get("sni") not in added]
        if rest:
            L += ["", self._head(self.T('bot.warp_autodetect.10'))]
            # شمارِ تلاش کنارِ حجم می‌آید چون امضای دامنه‌ی بلاک‌شده «بایتِ
            # ناچیز + تلاشِ زیاد» است؛ بدونِ این ستون، ردیف بی‌اهمیت به نظر
            # می‌رسد و همان چیزی است که notebook.google.com را پنهان کرد.
            for b in rest[:10]:
                L.append(self._rtl(self.T('bot.warp_autodetect.12', p0=esc_html(str(b.get('sni') or '?')), p1=_fa_num(str(b.get('iran') or '?')), p2=_fa_num(str(b.get('warp') or '?')), p3=_fa_num(str(b.get('conns') or 0)), p4=fmt_bytes_srv(int(b.get('bytes') or 0)))))
        if not added and not rest:
            # جمله‌ی قبلی «همه‌ی دامنه‌های پرترافیک پوشش دارند» بود — که در
            # روزِ خرابیِ NotebookLM هم‌زمان درست و گمراه‌کننده بود: معیارِ
            # کاندیدشدن دیگر «پرترافیک» نیست.
            L += ["", self._rtl(self.T('bot.warp_autodetect.11'))]
        self.send(chat, "\n".join(L), self._warp_backrows("wp:auto"))

    def _leak_audit(self, chat):
        """گزارشِ ممیزیِ نشتِ DNS/IPv6 — parity با بخشِ همین‌نامِ پنل.

        چرا این گزارش دو محورِ جدا دارد و یک چراغِ سبز/قرمز نیست: کوئریِ
        DNS می‌تواند BIND را دور بزند ولی همچنان از تونل برود. اولی افتِ
        یکپارچگی است، دومی نشتِ واقعی — و قاطی‌کردنشان یا هشدارِ بی‌جا
        می‌سازد یا نشتِ واقعی را پشتِ «همه‌چیز سبز» پنهان می‌کند.
        """
        a = dns_leak_audit()
        icon = {"ok": "🟢", "warn": "🟡", "bad": "🔴"}
        L = [self._titlebar(self.T('bot.leak_audit.1')), "",
             self._kv(self.T('bot.leak_audit.2'), "%s %s" % (
                 icon.get(a["verdict"], "⚪"),
                 {"ok": self.T('bot.leak_audit.29'), "warn": self.T('bot.leak_audit.30'),
                  "bad": self.T('bot.leak_audit.31')}.get(a["verdict"], self.T('bot.leak_audit.25'))))]

        r = a.get("resolver") or {}
        L += ["", self._head(self.T('bot.leak_audit.3')),
              self._kv(self.T('bot.leak_audit.4'), "<code>%s</code>" % esc_html(r.get("ip") or self.T('bot.leak_audit.25'))),
              self._kv(self.T('bot.leak_audit.5'), self.T('bot.leak_audit.15') if r.get("listening") else self.T('bot.leak_audit.16')),
              self._kv(self.T('bot.leak_audit.6'), "<code>%s</code> %s" % (
                  esc_html(r.get("egress") or self.T('bot.leak_audit.25')),
                  self.T('bot.leak_audit.26') if r.get("tunneled") else self.T('bot.leak_audit.27')))]

        t = a.get("transparent") or {}
        L += ["", self._head(self.T('bot.leak_audit.7')),
              self._kv(self.T('bot.leak_audit.8'), esc_html(self.T('bot.leak_audit.28').join(t.get("ifaces") or [])) or "—"),
              self._kv(self.T('bot.leak_audit.9'), _fa_num(t.get("members") or 0)),
              self._kv(self.T('bot.leak_audit.10'),
                       self.T('bot.leak_audit.17') if t.get("catchall") else self.T('bot.leak_audit.18'))]

        src = a.get("probe_src") or {}
        if a.get("probes"):
            L += ["", self._head(self.T('bot.leak_audit.19', p0=esc_html(src.get('iface') or self.T('bot.leak_audit.25'))))]
            for pr in a["probes"]:
                L.append(self._rtl(
                    self.T('bot.leak_audit.24', p0=esc_html(pr['ip']), p1=self.T('bot.lit.4') if pr['forced'] else self.T('bot.lit.5'), p2=esc_html(pr['egress'] or self.T('bot.leak_audit.25')), p3='✅' if pr['tunneled'] else self.T('bot.lit.6'))))

        v = a.get("ipv6") or {}
        L += ["", self._head("IPv6"),
              self._kv(self.T('bot.leak_audit.11'), self.T('bot.leak_audit.20') if v.get("disabled") else self.T('bot.leak_audit.21')),
              self._kv(self.T('bot.leak_audit.12'),
                       self.T('bot.leak_audit.22') if v.get("default_route") else self.T('bot.leak_audit.23')),
              self._kv(self.T('bot.leak_audit.13'),
                       esc_html(self.T('bot.leak_audit.28').join(v.get("global_addrs") or []))
                       or self.T('bot.leak_audit.23'))]

        L += ["", self._head(self.T('bot.leak_audit.14'))]
        for f in a.get("findings") or []:
            L.append(self._rtl("%s %s" % (icon.get(f["level"], "⚪"),
                                          esc_html(f["text"]))))
        self.send(chat, "\n".join(L),
                  [[{"text": self.T('bot.ecmp_page.8'), "callback_data": "lk:page"}],
                   [self._back_row()[0]]])

    def _warp_ai_usage(self, chat):
        """مصرفِ AI به تفکیکِ کاربر (top_src از splitter). فقط warp.manage —
        که ورودیِ کلِ بخشِ WARP همان را می‌طلبد، پس گیتِ اضافه لازم نیست.

        عمداً به‌جای warp_sni_status() مستقیم فایلِ stats را می‌خوانیم: آن تابع
        برای این جدول سه فراخوانیِ بلاک‌کننده‌ی نامربوط اجرا می‌کند (systemctl
        is-active با timeoutِ ۵ث + دو بررسیِ iptables) که نخِ تک‌poll را بی‌جهت
        معطل می‌کند. این جدول فقط به top_src و برچسبِ مبدأ نیاز دارد، و آن‌ها
        صرفاً از خواندنِ یک فایل + کشِ نامِ peer می‌آیند."""
        tsrc, labels = [], {}
        if warp_sni_enabled() or warp_sni_quic_enabled():
            try:
                with open(WARP_SNI_STATS, encoding="utf-8") as f:
                    stats = json.load(f)
                tsrc = (stats or {}).get("top_src") or []
                names = warp_src_names()
                labels = {r[0]: warp_src_label(r[0], names)
                          for r in tsrc if r and r[0]}
            except (OSError, ValueError):
                pass
        L = [self._titlebar(self.T('bot.warp_ai_usage.1')), ""]
        if not tsrc:
            L.append(self._rtl(self.T('bot.warp_ai_usage.2')))
        else:
            L.append(self._rtl(self.T('bot.warp_ai_usage.3', p0=_fa_num(len(tsrc)))))
            L.append("")
            for r in tsrc[:15]:
                ip = r[0] if r else ""
                aB = r[1] if len(r) > 1 else 0
                dB = r[2] if len(r) > 2 else 0
                aC = r[3] if len(r) > 3 else 0
                dC = r[4] if len(r) > 4 else 0
                lbl = labels.get(ip) or ""
                if lbl == WARP_POOL_LABEL:
                    lbl = self.T(lbl)
                who = ("%s " % esc_html(lbl)) if lbl else ""
                L.append(self._rtl("%s<code>%s</code>" % (who, esc_html(ip))))
                L.append(self._rtl(self.T('bot.warp_ai_usage.4', p0=fmt_bytes_srv(aB), p1=fmt_bytes_srv(dB), p2=_fa_num(aC), p3=_fa_num(dC))))
        self.send(chat, "\n".join(L), self._warp_backrows("wp:ai"))

    def _warp_rank(self, chat):
        """رتبه‌بندیِ endpointها با ping. سنجش کند و بلاک‌کننده است، پس در نخِ
        پس‌زمینه اجرا می‌شود تا حلقه‌ی poll معطل نماند؛ نتیجه با _send_fresh
        (بدونِ لمسِ self._edit) فرستاده می‌شود."""
        self.send(chat, self._rtl(self.T('bot.warp_rank.1')),
                  [[{"text": self.T('bot.warp_page.3'), "callback_data": "wp:page"}]])

        def work():
            try:
                r = warp_rank_endpoints()
            except Exception:
                self._send_fresh(chat, self._rtl(self.T('bot.work.6')))
                return
            eps = r.get("endpoints") or []
            best = r.get("best") or ""
            cur = r.get("current") or ""
            L = [self._titlebar(self.T('bot.work.1')), ""]
            for e in eps:
                ip = e.get("ip", "")
                rtt = e.get("rtt")
                marks = []
                if e.get("current"):
                    marks.append(self.T('bot.work.3'))
                if ip and ip == best:
                    marks.append(self.T('bot.work.4'))
                tag = (" — " + self.T('bot.leak_audit.28').join(marks)) if marks else ""
                val = _fa_num("%s ms" % rtt) if rtt is not None else self.T('bot.work.2')
                L.append(self._rtl("<code>%s</code> · <b>%s</b>%s"
                                   % (esc_html(ip), val, tag)))
            if cur and best and cur != best:
                L += ["", self._rtl(self.T('bot.work.5'))]
            self._send_fresh(chat, "\n".join(L),
                             [[{"text": self.T('bot.work.7'),
                                "callback_data": "wp:rank"}],
                              [{"text": self.T('bot.warp_page.3'),
                                "callback_data": "wp:page"}]])

        threading.Thread(target=work, daemon=True).start()

    # ---- گفت‌وگوی ساختِ کاربرِ وایرگارد (ویزاردِ کامل مثلِ مودالِ وب)
    @staticmethod
    def _wg_add_ifaces():
        """اینترفیس‌های قابلِ انتخاب در ویزاردِ ساخت — محدودشده به
        bot.add_ifaces در config (خالی = همه‌ی اینترفیس‌های سمتِ کاربر)."""
        allowed = bot_cfg().get("add_ifaces") or []
        ifs = server_ifaces()
        return [i for i in ifs if i in allowed] if allowed else ifs

    def _start_wg_add(self, frm, chat):
        # خروجیِ ویزارد کانفیگ با کلیدِ خصوصی است. بدونِ این گارد peer در
        # گروه ساخته می‌شد و بعد _send_wg_conf تحویلش را رد می‌کرد: کاربری
        # بی‌کانفیگ، و نام/سهمیه‌اش جلوی همه.
        if self._refuse_in_group(chat):
            return
        ifs = self._wg_add_ifaces()
        if not ifs:
            self.send(chat, self.T('bot.start_wg_add.1'), [self._back_row()])
            return
        st = {"flow": "wg_add", "step": "iface", "iface": "", "name": "",
              "psk": True, "quota": None, "total": None, "rate": None,
              "expires": None}
        self.convo[frm] = st
        if len(ifs) == 1:               # تنها گزینه — مرحله‌ی انتخاب لازم نیست
            st["iface"], st["step"] = ifs[0], "name"
        self._wg_add_prompt(frm, chat)

    _WGADD_CANCEL_CB = "wg:addw:cancel"

    def _wgadd_cancel(self):
        """ردیفِ «انصراف»ِ ویزاردِ وایرگارد — متد، چون متنش زبان‌دار شد."""
        return [{"text": self.T("bot.cancel"),
                 "callback_data": self._WGADD_CANCEL_CB}]

    def _wg_add_prompt(self, frm, chat):
        """پرسشِ مرحله‌ی جاریِ ویزاردِ ساخت (متن + دکمه‌های همان مرحله)."""
        st = self.convo.get(frm) or {}
        step = st.get("step")
        head = self._head(self.T('bot.wg_add_prompt.1'))
        if step == "iface":
            rows = [[{"text": "%s (%s)" % (i, iface_subnet(i) or "?"),
                      "callback_data": "wg:addw:if|" + i}]
                    for i in self._wg_add_ifaces()[:20]]
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.wg_add_prompt.2')),
                      rows + [self._wgadd_cancel()])
        elif step == "name":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.wg_add_prompt.3')),
                      [self._wgadd_cancel()])
        elif step == "psk":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.wg_add_prompt.4')),
                      [[{"text": self.T('bot.wg_add_prompt.5'),
                         "callback_data": "wg:addw:psk|1"},
                        {"text": self.T('bot.px_show.2'), "callback_data": "wg:addw:psk|0"}],
                       self._wgadd_cancel()])
        elif step == "quota":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.wg_add_prompt.6')),
                      [[{"text": self.T('bot.wg_add_create.12'), "callback_data": "wg:addw:quota|-"}],
                       self._wgadd_cancel()])
        elif step == "total":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.wg_add_prompt.7')),
                      [[{"text": self.T('bot.wg_add_create.13'), "callback_data": "wg:addw:total|-"}],
                       self._wgadd_cancel()])
        elif step == "rate":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.px_add_prompt.8')),
                      [[{"text": self.T('bot.wg_add_create.12'), "callback_data": "wg:addw:rate|-"}],
                       self._wgadd_cancel()])
        elif step == "exp":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.wg_add_prompt.8')),
                      [[{"text": self.T('bot.wg_add_prompt.10'),
                         "callback_data": "wg:addw:exp|-"}],
                       self._wgadd_cancel()])
        elif step == "confirm":
            L = [self._head(self.T('bot.wg_add_prompt.9')), "",
                 self._kv(self.T('bot.warp_page.6'), "<code>%s</code>" % esc_html(st["iface"])),
                 self._kv(self.T('bot.bu_show.4'), "<code>%s</code>" % esc_html(st["name"])),
                 self._kv("Preshared Key:", self.T('bot.px_show.1') if st["psk"] else self.T('bot.px_show.2')),
                 self._kv(self.T('bot.wg_add_create.8'), _fa_num("%g GB" % st["quota"])
                          if st["quota"] else self.T('bot.wg_add_create.12')),
                 self._kv(self.T('bot.wg_add_create.9'), _fa_num("%g GB" % st["total"])
                          if st["total"] else self.T('bot.wg_add_create.13')),
                 self._kv(self.T('bot.wg_add_create.10'), _fa_num("%d Mbit/s" % st["rate"])
                          if st["rate"] else self.T('bot.wg_add_create.12')),
                 self._kv(self.T('bot.wg_add_create.11'), self._fa_date(st["expires"])
                          if st["expires"] else self.T('bot.wg_add_create.14'))]
            self.send(chat, "\n".join(L),
                      [[{"text": self.T('bot.wg_add_prompt.11'), "callback_data": "wg:addw:go"}],
                       self._wgadd_cancel()])

    _WGADD_ORDER = ("iface", "name", "psk", "quota", "total", "rate", "exp",
                    "confirm")

    def _wg_add_next(self, frm, chat, st):
        st["step"] = self._WGADD_ORDER[self._WGADD_ORDER.index(st["step"]) + 1]
        self._wg_add_prompt(frm, chat)

    def _wg_add_cb(self, frm, chat, arg, p):
        """دکمه‌های ویزاردِ ساخت: wg:addw:<field>|<val> یا go/cancel."""
        if self._refuse_in_group(chat):
            return
        st = self.convo.get(frm)
        if not st or st.get("flow") != "wg_add":
            self.send(chat, self._rtl(self.T('bot.wg_add_cb.1')), [self._back_row()])
            return
        if arg == "cancel":
            self.convo.pop(frm, None)
            self.send(chat, self.T('bot.on_confirm.1'), [self._back_row()])
            return
        if arg == "go":
            if st["step"] != "confirm":
                self._wg_add_prompt(frm, chat)
                return
            self.convo.pop(frm, None)
            self._wg_add_create(frm, chat, st)
            return
        field, _, val = arg.partition("|")
        expect = {"if": "iface", "psk": "psk", "quota": "quota",
                  "total": "total", "rate": "rate", "exp": "exp"}.get(field)
        if expect != st["step"]:        # دکمه‌ی کهنه از مرحله‌ی دیگر
            self._wg_add_prompt(frm, chat)
            return
        if field == "if":
            if val not in self._wg_add_ifaces():
                self.send(chat, self.T('bot.wg_add_cb.2'), [self._back_row()])
                return
            st["iface"] = val
        elif field == "psk":
            st["psk"] = (val == "1")
        # quota/total/rate/exp با دکمه یعنی «نامحدود/دائمی» → None (پیش‌فرض)
        self._wg_add_next(frm, chat, st)

    def _wg_add_text(self, frm, chat, st, text, p):
        """ورودیِ متنیِ مراحلِ ویزاردِ ساخت (نام/اعداد/تاریخ)."""
        step = st["step"]
        if step in ("iface", "psk", "confirm"):    # این مراحل فقط دکمه‌ای‌اند
            self._wg_add_prompt(frm, chat)
            return
        text = _fa_digits_en(text.strip())
        if step == "name":
            if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,32}", text):
                self.send(chat, self._rtl(self.T('bot.wg_add_text.1')),
                          [self._wgadd_cancel()])
                return
            if self._wg_find(st["iface"], text):
                self.send(chat, self._rtl(self.T('bot.wg_add_text.2', p0=esc_html(st['iface']))), [self._wgadd_cancel()])
                return
            st["name"] = text
        elif step in ("quota", "total"):
            try:
                gb = float(text)
            except ValueError:
                self.send(chat, self._rtl(self.T('bot.wg_add_text.3')), [self._wgadd_cancel()])
                return
            st[step] = gb if gb > 0 else None
        elif step == "rate":
            rate, rerr = parse_rate_mbit(text)
            if rerr:
                self.send(chat, self._rtl(rerr + self.T('bot.wg_add_text.4')),
                          [self._wgadd_cancel()])
                return
            st["rate"] = rate
        elif step == "exp":
            val = self._parse_expiry_input(text, {})
            if not val:
                self.send(chat, self._rtl(self.T('bot.wg_add_text.5')), [self._wgadd_cancel()])
                return
            st["expires"] = val
        self._wg_add_next(frm, chat, st)

    def _wg_add_create(self, frm, chat, st):
        """ساختِ نهایی: peer + متادیتا (سهمیه/سقف/سرعت/انقضا) — مثلِ مسیرِ وب."""
        iface, name = st["iface"], st["name"]
        res, err = add_peer(iface, name, use_psk=st["psk"])
        if err:
            audit("bot:%s" % frm, "peer", "peer.add.bot",
                  "%s @ %s" % (name, iface), adet("ui.audit.det.failed", why=err), "", False)
            self.send(chat, self.M(err), [self._back_row()])
            return
        mf = {}
        if st["quota"]:
            mf["quota_gb"] = st["quota"]
        if st["expires"]:
            mf["expires"] = st["expires"]
        if st["total"]:
            mf["total_gb"] = st["total"]
            mf["enforce_action"] = "disable"
        if st["rate"]:
            mf["rate_mbit"] = st["rate"]
        if mf:
            META.meta_update(iface, name, mf)
            SAMPLER.refresh_meta()
        if st["rate"]:
            SHAPER.kick()               # اعمالِ فوریِ محدودیتِ سرعت
        det = self.T('bot.wg_add_create.1', p0=res['ip'], p1=self.T('bot.leak_audit.15') if st['psk'] else self.T('bot.leak_audit.21'))
        if st["quota"]:
            det += self.T('bot.wg_add_create.2', p0=st['quota'])
        if st["total"]:
            det += self.T('bot.wg_add_create.3', p0=st['total'])
        if st["rate"]:
            det += self.T('bot.wg_add_create.4', p0=st['rate'])
        if st["expires"]:
            det += self.T('bot.wg_add_create.5', p0=st['expires'])
        audit("bot:%s" % frm, "peer", "peer.add.bot",
              "%s @ %s" % (name, iface), det, "", True)
        ALERTS.event("startup", self.T('bot.wg_add_create.6', p0=name, p1=res['ip']))
        L = [self._rtl(self.T('bot.wg_add_create.7', p0=esc_html(name))),
             "", self._rtl("IP:"), self._code_line(res["ip"]),
             self._kv(self.T('bot.wg_add_create.8'), _fa_num("%g GB" % st["quota"])
                      if st["quota"] else self.T('bot.wg_add_create.12')),
             self._kv(self.T('bot.wg_add_create.9'), _fa_num("%g GB" % st["total"])
                      if st["total"] else self.T('bot.wg_add_create.13')),
             self._kv(self.T('bot.wg_add_create.10'), _fa_num("%d Mbit/s" % st["rate"])
                      if st["rate"] else self.T('bot.wg_add_create.12')),
             self._kv(self.T('bot.wg_add_create.11'), self._fa_date(st["expires"])
                      if st["expires"] else self.T('bot.wg_add_create.14'))]
        self.send(chat, "\n".join(L))
        self._send_wg_conf(chat, name, res["client_conf"])

    # ---- گفت‌وگوی ساختِ کاربرِ پروکسی (ویزاردِ کامل مثلِ مودالِ وب)
    def _start_px_add(self, frm, chat):
        # رمزِ پروکسی هم در مرحله‌ی تأیید و هم در پیامِ نهایی چاپ می‌شود.
        if self._refuse_in_group(chat):
            return
        self.convo[frm] = {"flow": "px_add", "step": "name", "name": "",
                           "noauth": False, "pw": "", "rate": None,
                           "quota": None, "proto": "both", "src": [],
                           "expires": None}
        self._px_add_prompt(frm, chat)

    _PXADD_CANCEL_CB = "px:addw:cancel"

    def _pxadd_cancel(self):
        """ردیفِ «انصراف» — متد است نه ثابتِ کلاسی، چون متنش زبان‌دار شد."""
        return [{"text": self.T("bot.cancel"),
                 "callback_data": self._PXADD_CANCEL_CB}]
    _PXADD_ORDER = ("name", "auth", "pass", "rate", "quota", "proto", "src",
                    "exp", "confirm")
    _PROTO_FA = {"both": "bot.proto.both", "http": "bot.proto.http",
                 "https": "bot.proto.https"}

    def _px_add_prompt(self, frm, chat):
        """پرسشِ مرحله‌ی جاریِ ویزاردِ ساختِ پروکسی."""
        st = self.convo.get(frm) or {}
        step = st.get("step")
        head = self._head(self.T('bot.px_add_prompt.1'))
        if step == "name":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.px_add_prompt.2')),
                      [self._pxadd_cancel()])
        elif step == "auth":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.px_add_prompt.3')),
                      [[{"text": self.T('bot.px_add_prompt.4'),
                         "callback_data": "px:addw:auth|0"},
                        {"text": self.T('bot.px_add_prompt.5'),
                         "callback_data": "px:addw:auth|1"}],
                       self._pxadd_cancel()])
        elif step == "pass":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.px_add_prompt.6')),
                      [[{"text": self.T('bot.px_add_prompt.7'),
                         "callback_data": "px:addw:pass|-"}],
                       self._pxadd_cancel()])
        elif step == "rate":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.px_add_prompt.8')),
                      [[{"text": self.T('bot.wg_add_create.12'), "callback_data": "px:addw:rate|-"}],
                       self._pxadd_cancel()])
        elif step == "quota":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.px_add_prompt.9')),
                      [[{"text": self.T('bot.wg_add_create.12'), "callback_data": "px:addw:quota|-"}],
                       self._pxadd_cancel()])
        elif step == "proto":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.px_add_prompt.12')),
                      [[{"text": self.T('bot.px_add_prompt.13'),
                         "callback_data": "px:addw:proto|both"}],
                       [{"text": self.T('bot.px_show.5'), "callback_data": "px:addw:proto|http"},
                        {"text": self.T('bot.px_show.6'), "callback_data": "px:addw:proto|https"}],
                       self._pxadd_cancel()])
        elif step == "src":
            rows = []
            if not st.get("noauth"):
                rows.append([{"text": self.T('bot.px_add_prompt.14'),
                              "callback_data": "px:addw:src|-"}])
            note = (self.T('bot.px_add_prompt.10')
                    if st.get("noauth") else self.T('bot.px_add_prompt.11'))
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.px_add_prompt.15') + note),
                      rows + [self._pxadd_cancel()])
        elif step == "exp":
            self.send(chat, head + "\n"
                      + self._rtl(self.T('bot.wg_add_prompt.8')),
                      [[{"text": self.T('bot.wg_add_prompt.10'),
                         "callback_data": "px:addw:exp|-"}],
                       self._pxadd_cancel()])
        elif step == "confirm":
            L = [self._head(self.T('bot.px_add_prompt.16')), "",
                 self._kv(self.T('bot.px_add_prompt.17'), "<code>%s</code>"
                          % esc_html(st["name"])),
                 self._kv(self.T('bot.px_add_prompt.18'), self.T('bot.px_add_prompt.5')
                          if st["noauth"] else self.T('bot.px_add_prompt.20')),
                 self._kv(self.T('bot.px_conf.7'), "—" if st["noauth"] else
                          ("<code>%s</code>" % esc_html(st["pw"])
                           if st["pw"] else self.T('bot.px_add_prompt.7'))),
                 self._kv(self.T('bot.wg_add_create.10'), _fa_num("%d Mbit/s" % st["rate"])
                          if st["rate"] else self.T('bot.wg_add_create.12')),
                 self._kv(self.T('bot.wg_add_create.8'), _fa_num("%g GB" % st["quota"])
                          if st["quota"] else self.T('bot.wg_add_create.12')),
                 self._kv(self.T('bot.px_add_create.10'), self.T(self._PROTO_FA[st["proto"]])),
                 self._kv(self.T('bot.px_add_prompt.19'), self.T('bot.px_add_prompt.21') if not st["src"] else ""),
                 ]
            if st["src"]:
                L[-1] = self._rtl(self.T('bot.px_add_prompt.19'))
                L.append(self._code_line(", ".join(st["src"])))
            L.append(self._kv(self.T('bot.wg_add_create.11'), self._fa_date(st["expires"])
                              if st["expires"] else self.T('bot.wg_add_create.14')))
            self.send(chat, "\n".join(L),
                      [[{"text": self.T('bot.wg_add_prompt.11'), "callback_data": "px:addw:go"}],
                       self._pxadd_cancel()])

    def _px_add_next(self, frm, chat, st):
        nxt = self._PXADD_ORDER[self._PXADD_ORDER.index(st["step"]) + 1]
        if nxt == "pass" and st["noauth"]:      # بدونِ‌رمز → مرحله‌ی رمز ندارد
            nxt = "rate"
        st["step"] = nxt
        self._px_add_prompt(frm, chat)

    def _px_add_cb(self, frm, chat, arg, p):
        """دکمه‌های ویزاردِ ساختِ پروکسی: px:addw:<field>|<val> یا go/cancel."""
        if self._refuse_in_group(chat):
            return
        st = self.convo.get(frm)
        if not st or st.get("flow") != "px_add":
            self.send(chat, self._rtl(self.T('bot.px_add_cb.1')), [self._back_row()])
            return
        if arg == "cancel":
            self.convo.pop(frm, None)
            self.send(chat, self.T('bot.on_confirm.1'), [self._back_row()])
            return
        if arg == "go":
            if st["step"] != "confirm":
                self._px_add_prompt(frm, chat)
                return
            self.convo.pop(frm, None)
            self._px_add_create(frm, chat, st)
            return
        field, _, val = arg.partition("|")
        expect = {"auth": "auth", "pass": "pass", "rate": "rate",
                  "quota": "quota", "proto": "proto", "src": "src",
                  "exp": "exp"}.get(field)
        if expect != st["step"]:                # دکمه‌ی کهنه از مرحله‌ی دیگر
            self._px_add_prompt(frm, chat)
            return
        if field == "auth":
            st["noauth"] = (val == "1")
        elif field == "proto":
            st["proto"] = val if val in ("both", "http", "https") else "both"
        elif field == "src" and st["noauth"]:   # بدونِ‌رمز نمی‌تواند رد کند
            self._px_add_prompt(frm, chat)
            return
        # pass/rate/quota/src/exp با دکمه یعنی خودکار/نامحدود/دائمی → پیش‌فرض
        self._px_add_next(frm, chat, st)

    def _px_add_text(self, frm, chat, st, text, p):
        """ورودیِ متنیِ مراحلِ ویزاردِ ساختِ پروکسی."""
        step = st["step"]
        if step in ("auth", "proto", "confirm"):    # فقط دکمه‌ای
            self._px_add_prompt(frm, chat)
            return
        raw = text.strip()
        text = _fa_digits_en(raw)
        if step == "name":
            if not valid_proxy_user(text):
                self.send(chat, self._rtl(self.T('bot.px_add_text.1')),
                          [self._pxadd_cancel()])
                return
            if META.proxy_user_get(text):
                self.send(chat, self._rtl(self.T('bot.px_add_text.2')), [self._pxadd_cancel()])
                return
            st["name"] = text
        elif step == "pass":
            if len(raw) < 4:
                self.send(chat, self._rtl(self.T('bot.px_add_text.3')), [self._pxadd_cancel()])
                return
            st["pw"] = raw
        elif step == "rate":
            rate, rerr = parse_rate_mbit(text)
            if rerr:
                self.send(chat, self._rtl(rerr + self.T('bot.wg_add_text.4')),
                          [self._pxadd_cancel()])
                return
            st["rate"] = rate
        elif step == "quota":
            try:
                gb = float(text)
            except ValueError:
                self.send(chat, self._rtl(self.T('bot.wg_add_text.3')), [self._pxadd_cancel()])
                return
            st["quota"] = gb if gb > 0 else None
        elif step == "src":
            srcs, serr = parse_allow_src(text)
            if serr:
                self.send(chat, self._rtl(serr + self.T('bot.wg_add_text.4')),
                          [self._pxadd_cancel()])
                return
            if st["noauth"]:
                if not srcs:
                    self.send(chat, self._rtl(self.T('bot.px_add_text.4')),
                              [self._pxadd_cancel()])
                    return
                clash = proxy_noauth_src_conflict(srcs)
                if clash:
                    self.send(chat, self._rtl(self.T('bot.px_add_text.5', p0=esc_html(clash))), [self._pxadd_cancel()])
                    return
            st["src"] = srcs
        elif step == "exp":
            val = self._parse_expiry_input(text, {})
            if not val:
                self.send(chat, self._rtl(self.T('bot.wg_add_text.5')), [self._pxadd_cancel()])
                return
            st["expires"] = val
        self._px_add_next(frm, chat, st)

    def _px_add_create(self, frm, chat, st):
        """ساختِ نهاییِ کاربرِ پروکسی — همان اعتبارسنجی‌ها و اعمالِ مسیرِ وب."""
        username = st["name"]
        if META.proxy_user_get(username):       # دفاعِ دوم (شاید همزمان ساخته شد)
            self.send(chat, self._rtl(self.T('bot.px_add_create.11')),
                      [self._back_row()])
            return
        if st["noauth"]:
            if not st["src"]:
                self.send(chat, self._rtl(self.T('bot.px_add_create.15')), [self._back_row()])
                return
            clash = proxy_noauth_src_conflict(st["src"])
            if clash:
                self.send(chat, self._rtl(self.T('bot.px_add_create.16', p0=esc_html(clash))), [self._back_row()])
                return
            pw, ph = "", ""
        else:
            pw = st["pw"] or secrets.token_urlsafe(9)
            ph = proxy_hash(pw)
            if not ph:
                self.send(chat, self.T('bot.px_add_create.12'), [self._back_row()])
                return
        rate_kbit = (st["rate"] or 0) * 1000
        META.proxy_user_upsert(username, {
            "pass_hash": ph, "rate_kbit": rate_kbit,
            "quota_gb": st["quota"] or 0, "expires": st["expires"] or "",
            "enabled": 1, "note": self.T('bot.px_add_create.8'),
            "allow_src": ",".join(st["src"]), "pass_plain": pw,
            "protocol": st["proto"], "noauth": 1 if st["noauth"] else 0})
        PROXY.kick()
        det = self.T('bot.px_add_create.2') if st["noauth"] else self.T('bot.px_add_create.3')
        det += self.T('bot.px_add_create.1', p0=st['proto'])
        if st["rate"]:
            det += self.T('bot.px_add_create.4', p0=st['rate'])
        if st["quota"]:
            det += self.T('bot.px_add_create.5', p0=st['quota'])
        if st["src"]:
            det += self.T('bot.px_add_create.6', p0=','.join(st['src']))
        if st["expires"]:
            det += self.T('bot.px_add_create.7', p0=st['expires'])
        audit("bot:%s" % frm, "panel-user", "px.add.bot",
              username, det, "", True)
        host = CONFIG.get("server_host") or ""
        L = [self._rtl(self.T('bot.px_add_create.9', p0=esc_html(username))), "",
             self._kv(self.T('bot.px_add_create.10'), self.T(self._PROTO_FA[st["proto"]])),
             self._kv(self.T('bot.wg_add_create.10'), _fa_num("%d Mbit/s" % st["rate"])
                      if st["rate"] else self.T('bot.wg_add_create.12')),
             self._kv(self.T('bot.wg_add_create.8'), _fa_num("%g GB" % st["quota"])
                      if st["quota"] else self.T('bot.wg_add_create.12')),
             self._kv(self.T('bot.wg_add_create.11'), self._fa_date(st["expires"])
                      if st["expires"] else self.T('bot.wg_add_create.14'))]
        rows = []
        if st["noauth"]:
            L += ["", self._rtl(self.T('bot.px_add_create.13')),
                  self._code_line(", ".join(st["src"])), "",
                  self._rtl(self.T('bot.px_conf.4')), self._code_line(host),
                  self._rtl(self.T('bot.px_conf.5')), self._code_line(str(PROXY_PORT))]
        else:
            url = "http://%s:%s@%s:%d" % (username, pw, host, PROXY_PORT)
            L += ["", self._rtl(self.T('bot.px_add_create.14')),
                  self._code_line(url), "",
                  self._rtl(self.T('bot.px_conf.4')), self._code_line(host),
                  self._rtl(self.T('bot.px_conf.5')), self._code_line(str(PROXY_PORT)),
                  self._rtl(self.T('bot.px_conf.6')), self._code_line(username),
                  self._rtl(self.T('bot.px_conf.7')), self._code_line(pw)]
            if st["src"]:
                L += [self._rtl(self.T('bot.px_add_create.17')),
                      self._code_line(", ".join(st["src"]))]
            b = self._copy_btn(self.T('bot.px_conf.1'), url)
            if b:
                rows.append([b])
        rows.append(self._back_row())
        self.send(chat, "\n".join(L), rows)
        if not st["noauth"]:
            qr = render_qr_png("http://%s:%s@%s:%d"
                               % (username, pw, host, PROXY_PORT))
            if qr:
                self.send_photo(chat, qr, self._rtl(self.T('bot.px_add_create.18')))

    def _convo_step(self, frm, chat, text):
        st = self.convo.get(frm)
        if not st:
            return
        p = bot_perms(frm) or set()
        # گفت‌وگو با frm کلید خورده نه با چت: ویزاردی که در خصوصی باز است،
        # پیامِ بعدیِ همان کاربر در **گروه** را ورودیِ خودش می‌گرفت — رمزِ
        # پروکسی از گروه، و پاسخِ مرحله (با رمز) به گروه. متنِ گروهی ورودیِ
        # ویزارد نیست؛ بی‌صدا، تا گفت‌وگوی معمولیِ گروه پر از خطا نشود.
        if st["flow"] in ("wg_add", "px_add") and not self._private():
            return
        if st["flow"] == "wg_add":
            if "wg.add" not in p:
                self.convo.pop(frm, None)
                return
            self._wg_add_text(frm, chat, st, text, p)
        elif st["flow"] == "px_add":
            if "proxy.add" not in p:
                self.convo.pop(frm, None)
                return
            self._px_add_text(frm, chat, st, text, p)
        elif st["flow"] == "warp_add":
            self.convo.pop(frm, None)
            if "warp.manage" not in p or bot_user_role(frm) != "owner":
                return
            kind, val, err = warp_validate_target(text.strip())
            if err:
                self.send(chat, self._rtl(self.T('bot.convo_step.3') + self.M(err)),
                          [[{"text": self.T('bot.warp_page.3'),
                             "callback_data": "wp:page"}]])
                return
            cur = warp_targets_read()
            if val in cur:
                self.send(chat, self._rtl(self.T('bot.convo_step.2')),
                          [[{"text": self.T('bot.warp_page.3'),
                             "callback_data": "wp:page"}]])
                return
            ok, werr = warp_targets_write(cur + [val], "bot:%s" % frm)
            if not ok:
                self.send(chat, self._rtl(self.T('bot.convo_step.4') + self.M(werr)), [self._back_row()])
                return
            aok, msg = warp_apply()
            log_action("warp target added: %s by bot:%s" % (val, frm))
            self.send(chat, self._rtl(self.T('bot.convo_step.1', p0=esc_html(val), p1='' if aok else self.T('bot.lit.9'))),
                      [[{"text": self.T('bot.warp_page.3'), "callback_data": "wp:page"}]])
        elif st["flow"] == "find":
            self.convo.pop(frm, None)
            self._find(chat, text.strip(), p)
        elif st["flow"] == "input":
            self._input_step(frm, chat, st, text.strip(), p)
        elif st["flow"] == "bu_add":
            self.convo.pop(frm, None)
            if "bot.manage" not in p:
                return
            uid = _fa_digits_en(text.strip())
            if not re.fullmatch(r"-?[0-9]{1,20}", uid):
                self.send(chat, self._rtl(self.T('bot.convo_step.5')),
                          [[{"text": self.T('bot.bu_add_user.4'), "callback_data": "bu:list"}]])
                return
            if any(str(u.get("id")) == uid for u in bot_cfg()["users"]):
                self.send(chat, self._rtl(self.T('bot.convo_step.6')),
                          [[{"text": self.T('bot.convo_step.9'), "callback_data": "bu:show:" + uid}],
                           [{"text": self.T('bot.bu_add_user.4'), "callback_data": "bu:list"}]])
                return
            # انتخابِ نقش برای آیدیِ جدید
            rows = [[{"text": self._bu_role_label(r),
                      "callback_data": "bu:arole:%s|%s" % (uid, r)}]
                    for r in self._bu_roles(frm)]
            rows.append([{"text": self.T('bot.dispatch_inner.1'), "callback_data": "bu:list"}])
            self.send(chat, "\n".join([
                self._rtl(self.T('bot.convo_step.7')), self._code_line(uid), "",
                self._rtl(self.T('bot.convo_step.8'))]), rows)

    # ---- ورودیِ مقدار برای تمدید/سهمیه/سرعت → تأیید
    def _input_step(self, frm, chat, st, text, p):
        # ارقامِ فارسی/عربی → لاتین. 🪤 \d ِ regex ارقامِ فارسی را هم می‌گیرد،
        # پس «۲۰۲۶-۱۰-۰۱» بی‌تبدیل ذخیره می‌شد؛ اعمالِ انقضا مقایسه‌ی رشته‌ای
        # با تاریخِ لاتین است و کاربر هرگز منقضی نمی‌شد.
        text = _fa_digits_en(text.strip())
        act = st["act"]
        if act == "ren":
            if st["kind"] == "wg":
                st["_curexp"] = META.meta_all().get(
                    (st["iface"], st["name"]), {}).get("expires")
            else:
                cu = META.proxy_user_get(st["name"])
                st["_curexp"] = cu.get("expires") if cu else None
            val = self._parse_expiry_input(text, st)
            if not val:
                self.send(chat, self.T('bot.input_step.4'))
                return
            st["val"] = val
            summary = self.T('bot.input_step.1', p0=self._fa_date(val))
        elif act == "quo":
            try:
                gb = max(0.0, float(text.replace(self.T('bot.input_step.7'), ".")))
            except ValueError:
                self.send(chat, self.T('bot.input_step.5'))
                return
            st["val"] = gb
            summary = self.T('bot.input_step.2', p0=_fa_num('%g GB' % gb) if gb else self.T('bot.wg_add_create.12'))
        else:  # rat
            try:
                mb = max(0, int(float(text)))
            except ValueError:
                self.send(chat, self.T('bot.input_step.6'))
                return
            st["val"] = mb
            summary = self.T('bot.input_step.3', p0=_fa_num('%d Mbit/s' % mb) if mb else self.T('bot.wg_add_create.12'))
        st["flow"] = "confirm"
        self._ask_confirm(frm, chat, st, summary)

    def _parse_expiry_input(self, text, st):
        text = _fa_digits_en(text.strip())
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text):
            try:
                datetime.strptime(text, "%Y-%m-%d")
            except ValueError:
                return None
            return text
        if re.fullmatch(r"[0-9]{1,4}", text):
            base = datetime.now()
            cur = st.get("_curexp")
            if cur:
                try:
                    d = datetime.strptime(cur, "%Y-%m-%d")
                    if d > base:
                        base = d
                except ValueError:
                    pass
            return (base + timedelta(days=int(text))).strftime("%Y-%m-%d")
        return None

    # ---- اجرای عملِ تأییدشده
    def _apply(self, frm, chat, st):
        p = bot_perms(frm) or set()
        kind, act = st["kind"], st["act"]
        need = ("bot.manage" if kind == "bu" else
                "ecmp.manage" if kind == "ec" else
                "wg.del" if (kind == "wg" and act == "del") else
                "proxy.del" if (kind == "px" and act == "del") else
                "wg.edit" if kind == "wg" else "proxy.edit")
        if need not in p:
            self.send(chat, self.T('bot.apply.1'), [self._back_row()])
            return
        try:
            if kind == "wg":
                self._apply_wg(frm, chat, st)
            elif kind == "bu":
                self._apply_bu(frm, chat, st)
            elif kind == "ec":
                self._apply_ecmp(frm, chat, st)
            else:
                self._apply_px(frm, chat, st)
        except Exception as e:
            log_action("bot apply error: %r" % e)
            self.send(chat, self.T('bot.apply.2'), [self._back_row()])

    def _apply_bu(self, frm, chat, st):
        uid = str(st.get("uid", ""))
        if uid == str(frm):     # گاردِ ضدخودقفلی (دفاعِ دوم)
            self.send(chat, self.T('bot.apply_bu.1'), [self._back_row()])
            return
        tgt = next((x for x in bot_cfg()["users"]
                    if str(x.get("id")) == uid), None)
        if tgt and tgt.get("role") == "owner":  # مالک حذف‌ناشدنی (دفاعِ دوم)
            self.send(chat, self.T('bot.apply_bu.2'), [self._back_row()])
            return
        with config_txn() as cfg:
            users = [u for u in bot_cfg()["users"] if str(u.get("id")) != uid]
            cfg["bot"] = dict(bot_cfg(), users=users)
        audit("bot:%s" % frm, "settings", "bot.user.del", uid,
              "", "", True)
        log_action("bot user %s removed by bot:%s" % (uid, frm))
        self.send(chat, self._rtl(self.T('bot.apply_bu.3', p0=esc_html(uid))),
                  [[{"text": self.T('bot.bu_add_user.4'), "callback_data": "bu:list"}]])

    def _apply_wg(self, frm, chat, st):
        iface, name, act = st["iface"], st["name"], st["act"]
        tag = "%s @ %s" % (name, iface)
        if act == "del":
            ok, msg = delete_peer(iface, name)
            audit("bot:%s" % frm, "peer", "peer.del.bot", tag, "", "", ok)
            self.send(chat, (self.T('bot.apply_wg.1', p0=name)) if ok
                      else self.M(msg), [self._back_row()])
        elif act == "tog":
            ok, msg = set_peer_enabled(iface, name, st["val"])
            audit("bot:%s" % frm, "peer",
                  "peer.enable.bot" if st["val"] else "peer.disable.bot",
                  tag, "", "", ok)
            self.send(chat, (self.T('bot.apply_wg.2', p0=self.T('bot.px_show.1') if st['val'] else self.T('bot.px_show.2'), p1=name)) if ok
                      else self.M(msg), [self._back_row()])
        elif act == "key":
            res, err = rotate_peer_key(iface, name)
            if err:
                self.send(chat, self.M(err), [self._back_row()])
                return
            audit("bot:%s" % frm, "peer", "peer.key.rotate.bot", tag, "", "", True)
            conf = res.get("client_conf", "")
            self.send(chat, self.T('bot.apply_wg.3', p0=name))
            if conf:
                self.send_doc(chat, "%s.conf" % name, conf,
                              self.T('bot.apply_wg.4'))
        elif act == "ren":
            META.meta_update(iface, name, {"expires": st["val"]})
            SAMPLER.refresh_meta()
            audit("bot:%s" % frm, "peer", "peer.renew.bot", tag,
                  adet("ui.audit.det.expiry", v=st["val"]), "", True)
            self.send(chat, self.T('bot.apply_wg.5', p0=name, p1=self._fa_date(st['val'])),
                      [self._back_row()])
        elif act == "quo":
            META.meta_update(iface, name, {"quota_gb": st["val"] or None})
            SAMPLER.refresh_meta()
            audit("bot:%s" % frm, "peer", "peer.quota.bot", tag,
                  adet("ui.audit.det.quota", v=st["val"]), "", True)
            self.send(chat, self.T('bot.apply_wg.6', p0=name, p1=_fa_num('%g GB' % st['val']) if st['val'] else self.T('bot.wg_add_create.12')),
                [self._back_row()])
        elif act == "rat":
            META.meta_update(iface, name, {"rate_mbit": st["val"] or None})
            SAMPLER.refresh_meta()
            SHAPER.kick()
            audit("bot:%s" % frm, "peer", "peer.rate.bot", tag,
                  adet("ui.audit.det.rate", v=st["val"]), "", True)
            self.send(chat, self.T('bot.apply_wg.7', p0=name, p1=_fa_num('%d Mbit/s' % st['val']) if st['val'] else self.T('bot.wg_add_create.12')),
                [self._back_row()])

    def _apply_px(self, frm, chat, st):
        name, act = st["name"], st["act"]
        if act == "del":
            META.proxy_user_delete(name)
            PROXY.kick()
            audit("bot:%s" % frm, "panel-user", "px.del.bot", name,
                  "", "", True)
            self.send(chat, self.T('bot.apply_px.1', p0=name), [self._back_row()])
        elif act == "tog":
            META.proxy_user_upsert(name, {"enabled": st["val"]})
            PROXY.kick()
            audit("bot:%s" % frm, "panel-user",
                  "px.enable.bot" if st["val"]
                  else "px.disable.bot", name, "", "", True)
            self.send(chat, self.T('bot.apply_px.2', p0=self.T('bot.px_show.1') if st['val'] else self.T('bot.px_show.2'), p1=name),
                      [self._back_row()])
        elif act == "pwd":
            if self._refuse_in_group(chat):
                return
            pw = secrets.token_urlsafe(9)
            META.proxy_user_upsert(name, {"pass_hash": proxy_hash(pw),
                                          "pass_plain": pw})
            PROXY.kick()
            audit("bot:%s" % frm, "panel-user", "px.pw.bot",
                  name, "", "", True)
            host = CONFIG.get("server_host") or ""
            self.send(chat, self.T('bot.apply_px.3', p0=name, p1=pw, p2=name, p3=pw, p4=host, p5=PROXY_PORT),
                      [self._back_row()])
        elif act == "ren":
            META.proxy_user_upsert(name, {"expires": st["val"]})
            PROXY.kick()
            audit("bot:%s" % frm, "panel-user", "px.renew.bot", name,
                  adet("ui.audit.det.expiry", v=st["val"]), "", True)
            self.send(chat, self.T('bot.apply_px.4', p0=name, p1=self._fa_date(st['val'])),
                      [self._back_row()])
        elif act == "quo":
            META.proxy_user_upsert(name, {"quota_gb": st["val"]})
            PROXY.kick()
            audit("bot:%s" % frm, "panel-user", "px.quota.bot",
                  name, adet("ui.audit.det.quota", v=st["val"]), "", True)
            self.send(chat, self.T('bot.apply_px.5', p0=name, p1=_fa_num('%g GB' % st['val']) if st['val'] else self.T('bot.wg_add_create.12')),
                [self._back_row()])
        elif act == "rat":
            META.proxy_user_upsert(name, {"rate_kbit": int(st["val"] * 1000)})
            PROXY.kick()
            audit("bot:%s" % frm, "panel-user", "px.rate.bot",
                  name, adet("ui.audit.det.rate", v=st["val"]), "", True)
            self.send(chat, self.T('bot.apply_px.6', p0=name, p1=_fa_num('%d Mbit/s' % st['val']) if st['val'] else self.T('bot.wg_add_create.12')),
                [self._back_row()])

    # ---- مدیریتِ کاربرانِ خودِ ربات (فقط نقشِ دارای bot.manage)
    def _bu_role_label(self, role):
        return {"owner": self.T('bot.bu_role_label.1'), "admin": self.T('bot.bu_role_label.2'),
                "viewer": self.T('bot.bu_role_label.3')}.get(role, role)

    def _bu_roles(self, frm=None):
        """نقش‌های قابلِ‌تخصیص: داخلی + سفارشی (owner هرگز تخصیص‌دادنی نیست).

        با دادنِ frm، نقشِ «admin» فقط برای مالک/مدیرِ ربات در فهرست می‌آید؛
        وگرنه دارنده‌ی صرفِ bot.manage می‌توانست خودش (یا هرکسِ دیگر) را مدیر
        کند و به همه‌ی مجوزها برسد — یک ارتقای دسترسی. چون اعتبارسنجیِ
        افزودن/تغییرِ نقش هم از همین فهرست می‌خوانَد، این یک‌جا هم دکمه‌ها را
        فیلتر می‌کند و هم اجرا را می‌بندد."""
        roles = list(BUILTIN_ROLES) + sorted(
            r for r in (CONFIG.get("roles") or {}) if r != "owner")
        if frm is not None and bot_user_role(frm) not in ("owner", "admin"):
            # 🪤 قاعده **زیرمجموعه‌بودن** است، نه مقایسه‌ی نام: کسی فقط
            # نقشی را می‌تواند بدهد که مجوزهایش زیرمجموعه‌ی مجوزهای خودش
            # باشد. پیش از این فقط `r != "admin"` بود، پس نقشِ سفارشیِ
            # ممتاز — «superuser» با users.manage، که /api/roles/save
            # ساختنش را می‌پذیرد — در فهرست می‌ماند و دارنده‌ی صرفِ
            # bot.manage با آن به همان جایی می‌رسید که نامِ «admin» را
            # بسته بودند.
            #
            # زیرمجموعه و نه «هیچ نقشِ ممتازی»: اعطای نقشی که خودت
            # داری **افقی** است نه ارتقا. سخت‌گیریِ بیش‌ازحد، جریانِ
            # مشروعِ «مدیرِ ربات همتای خودش را اضافه می‌کند» را می‌شکست.
            mine = bot_perms(frm) or set()
            roles = [r for r in roles if role_perms(r) <= mine]
        return roles

    def _bu_action(self, frm, chat, act, arg):
        if act in ("list", ""):
            users = bot_cfg()["users"]
            rows = []
            for u in users:
                uid = str(u.get("id"))
                nm = u.get("name") or ""
                label = "%s — %s%s" % (
                    uid, self._bu_role_label(u.get("role", "viewer")),
                    (" · " + nm) if nm else "")
                rows.append([{"text": label, "callback_data": "bu:show:" + uid}])
            rows.append([{"text": self.T('bot.bu_action.1'), "callback_data": "bu:add"}])
            rows.append(self._back_row())
            self.send(chat, "\n".join([
                self._rtl(self.T('bot.bu_action.2', p0=_fa_num(len(users)))),
                self._rtl(self.T('bot.bu_action.3'))]), rows)
        elif act == "add":
            self.convo[frm] = {"flow": "bu_add"}
            self.send(chat, "\n".join([
                self._rtl(self.T('bot.bu_action.4')),
                self._rtl(self.T('bot.bu_action.5')),
                self._rtl(self.T('bot.bu_action.6'))]),
                [[{"text": self.T('bot.dispatch_inner.1'), "callback_data": "bu:list"}]])
        elif act == "show":
            self._bu_show(frm, chat, arg)
        elif act == "role":
            uid, _, role = arg.partition("|")
            self._bu_set_role(frm, chat, uid, role)
        elif act == "arole":
            uid, _, role = arg.partition("|")
            self._bu_add_user(frm, chat, uid, role)
        elif act == "del":
            self._bu_confirm_del(frm, chat, arg)

    def _bu_add_user(self, frm, chat, uid, role):
        back = [[{"text": self.T('bot.bu_add_user.4'), "callback_data": "bu:list"}]]
        # پیامِ روشن به‌جای «ورودیِ نامعتبر» وقتی علتِ رد، نبودنِ اختیارِ
        # اعطای نقشِ مدیر است (ضدِ ارتقای دسترسی).
        if role == "admin" and role not in self._bu_roles(frm):
            self.send(chat, self._rtl(self.T('bot.bu_add_user.5')), back)
            return
        uid = _fa_digits_en(str(uid))
        if not re.fullmatch(r"-?[0-9]{1,20}", uid) \
                or role not in self._bu_roles(frm):
            self.send(chat, self.T('bot.bu_add_user.1'), back)
            return
        with config_txn() as cfg:
            users = list(bot_cfg()["users"])
            if any(str(u.get("id")) == str(uid) for u in users):
                dup = True
            else:
                dup = False
                users.append({"id": str(uid), "role": role, "name": ""})
                cfg["bot"] = dict(bot_cfg(), users=users)
        if dup:
            # پاسخِ شبکه **بیرونِ** قفل: ارسال به تلگرام کندِ بالقوه است و
            # نباید بقیه‌ی نویسنده‌های CONFIG را پشتِ خودش نگه دارد.
            self.send(chat, self.T('bot.bu_add_user.2'), back)
            return
        audit("bot:%s" % frm, "settings", "bot.user.add",
              str(uid), adet("ui.audit.det.role", role=role), "", True)
        log_action("bot user %s added (%s) by bot:%s" % (uid, role, frm))
        self.send(chat, self._rtl(self.T('bot.bu_add_user.3', p0=esc_html(str(uid)), p1=self._bu_role_label(role))))
        self._bu_show(frm, chat, str(uid))

    def _bu_show(self, frm, chat, uid):
        u = next((x for x in bot_cfg()["users"] if str(x.get("id")) == uid), None)
        if not u:
            self.send(chat, self.T('bot.wg_show.2'), [[{"text": self.T('bot.bu_add_user.4'),
                                            "callback_data": "bu:list"}]])
            return
        is_self = str(uid) == str(frm)
        is_owner = u.get("role") == "owner"
        lines = [self._rtl(self.T('bot.bu_show.1')),
                 self._rtl(self.T('bot.bu_show.2')), self._code_line(uid)]
        if u.get("name"):
            lines.append(self._kv(self.T('bot.bu_show.4'), esc_html(u["name"])))
        lines.append(self._kv(self.T('bot.bu_show.3'),
                              self._bu_role_label(u.get("role", "viewer"))))
        if is_owner:
            lines.append("")
            lines.append(self._rtl(self.T('bot.bu_show.5')))
        elif is_self:
            lines.append("")
            lines.append(self._rtl(self.T('bot.bu_show.7')))
        rows = []
        if not is_self and not is_owner:
            cur = u.get("role", "viewer")
            for r in self._bu_roles(frm):
                suf = self.T('bot.bu_show.6') if r == cur else ""
                rows.append([{"text": self.T('bot.bu_show.9', p0=self._bu_role_label(r), p1=suf),
                              "callback_data": "bu:role:%s|%s" % (uid, r)}])
            rows.append([{"text": self.T('bot.bu_show.8'),
                          "callback_data": "bu:del:" + uid}])
        rows.append([{"text": self.T('bot.bu_add_user.4'), "callback_data": "bu:list"}])
        self.send(chat, "\n".join(lines), rows)

    def _bu_set_role(self, frm, chat, uid, role):
        back = [[{"text": self.T('bot.bu_add_user.4'), "callback_data": "bu:list"}]]
        # ضدِ ارتقای دسترسی: ارتقا به «مدیر» فقط از دستِ مالک/مدیرِ ربات.
        if role == "admin" and role not in self._bu_roles(frm):
            self.send(chat, self._rtl(self.T('bot.bu_set_role.4')), back)
            return
        if role not in self._bu_roles(frm):
            self.send(chat, self.T('bot.bu_set_role.1'), back)
            return
        if str(uid) == str(frm):
            self.send(chat, self.T('bot.bu_set_role.2'),
                      [[{"text": self.T('bot.bu_add_user.4'), "callback_data": "bu:list"}]])
            return
        users = list(bot_cfg()["users"])
        found = False
        for u in users:
            if str(u.get("id")) == str(uid):
                if u.get("role") == "owner":    # مالک از ربات تغییرناپذیر است
                    self.send(chat, self.T('bot.bu_set_role.5'),
                              [[{"text": self.T('bot.bu_add_user.4'),
                                 "callback_data": "bu:list"}]])
                    return
                u["role"], found = role, True
        if not found:
            self.send(chat, self.T('bot.wg_show.2'), [self._back_row()])
            return
        with config_txn() as cfg:
            cfg["bot"] = dict(bot_cfg(), users=users)
        audit("bot:%s" % frm, "settings", "bot.user.role",
              str(uid), adet("ui.audit.det.newrole", role=role), "", True)
        log_action("bot user %s role->%s by bot:%s" % (uid, role, frm))
        self.send(chat, self._rtl(self.T('bot.bu_set_role.3', p0=esc_html(uid), p1=self._bu_role_label(role))))
        self._bu_show(frm, chat, uid)

    # ---- پایشِ کاربرانِ ربات (فقط مالک)
    BW_PAGE = 6   # رویداد در هر صفحه

    def _bot_watch(self, frm, chat, page=0):
        """ریزِ همه‌ی کارهای ثبت‌شده‌ی (audit) کاربران — از ربات (شاملِ خودِ
        مالک) و از پنلِ وب — تا ۶ ماه، جدیدترین اول، فقط برای مالک.
        رویدادهای خودکارِ «سیستم …» (همگام‌سازی/سیاست‌ها) نمی‌آیند."""
        if bot_user_role(frm) != "owner":
            self.send(chat, self.T('bot.bot_watch.1'),
                      [self._back_row()])
            return
        names = {str(u.get("id")): (u.get("name") or "")
                 for u in bot_cfg()["users"]}
        rows = []
        for r in META.audit_list(limit=2000):   # سقفِ کوئری = کلِ ۶ ماه
            actor = str(r.get("actor") or "")
            if actor.startswith(self.T('bot.bot_watch.2')):
                continue                    # کارهای خودکارِ سیستم، نه کاربران
            rows.append((actor, r))
        total = len(rows)
        pages = max(1, (total + self.BW_PAGE - 1) // self.BW_PAGE)
        page = max(0, min(page, pages - 1))
        L = [self._titlebar(self.T('bot.bot_watch.3')),
             self._rtl(self.T('bot.bot_watch.4', p0=_fa_num(total), p1=_fa_num(page + 1), p2=_fa_num(pages))),
             ""]
        chunk = rows[page * self.BW_PAGE:(page + 1) * self.BW_PAGE]
        if not chunk:
            L.append(self._rtl(self.T('bot.bot_watch.8')))
        for actor, r in chunk:
            if actor.startswith("bot:"):
                aid = actor[4:]
                role = bot_user_role(aid)
                who = self._bu_role_label(role) if role else self.T('bot.bot_watch.9')
                nm = names.get(aid) or ""
                src = self.T('bot.bot_watch.5', p0=who, p1=' · ' + esc_html(nm) if nm else '')
                shown = aid
            else:
                src = self.T('bot.bot_watch.6')
                shown = actor or "?"
            L.append(self._rtl("<code>%s</code> (%s) · %s" % (
                esc_html(shown), src, _ago_srv(r["ts"]))))
            line = "<b>%s</b>" % esc_html(r["action"])
            if r.get("target"):
                line += " — <code>%s</code>" % esc_html(str(r["target"]))
            if not r.get("ok"):
                line += self.T('bot.bot_watch.7')
            L.append(self._rtl(line))
            if r.get("detail"):
                L.append(self._rtl(esc_html(str(r["detail"]))))
            L.append("")
        nav = []
        if page + 1 < pages:
            nav.append({"text": self.T('bot.px_dests.8'), "callback_data": "bw:%d" % (page + 1)})
        if page > 0:
            nav.append({"text": self.T('bot.px_dests.9'), "callback_data": "bw:%d" % (page - 1)})
        kb = ([nav] if nav else []) + [self._back_row()]
        self.send(chat, "\n".join(L).rstrip(), kb)

    def _bu_confirm_del(self, frm, chat, uid):
        if str(uid) == str(frm):
            self.send(chat, self.T('bot.bu_confirm_del.2'),
                      [[{"text": self.T('bot.bu_add_user.4'), "callback_data": "bu:list"}]])
            return
        tgt = next((x for x in bot_cfg()["users"]
                    if str(x.get("id")) == str(uid)), None)
        if tgt and tgt.get("role") == "owner":
            self.send(chat, self.T('bot.bu_confirm_del.3'),
                      [[{"text": self.T('bot.bu_add_user.4'), "callback_data": "bu:list"}]])
            return
        self._ask_confirm(frm, chat,
            {"flow": "confirm", "kind": "bu", "act": "del", "uid": str(uid)},
            self.T('bot.bu_confirm_del.1', p0=esc_html(uid)))

    # ---- وضعیتِ پشتیبان‌گیری (از ربات — عمداً بدونِ فراخوانیِ شبکه:
    #      state + systemd محلی؛ شمارشِ MEGA فقط اگر کشِ پنل گرم باشد،
    #      تا حلقه‌ی تک‌نخیِ ربات هرگز پشتِ rclone گیر نکند.)
    def _backup_page(self, chat, p):
        if "audit.view" not in p:
            self.send(chat, self.T('bot.backup_page.1'), [self._back_row()])
            return
        st = _backup_state()
        L = [self._titlebar(self.T('bot.backup_page.2')), ""]
        kb = []
        for label, key in ((self.T('bot.backup_page.3'), "panel"),
                           (self.T('bot.backup_page.4'), "full")):
            e = st.get(key) or {}
            L.append(self._head(label))
            if e.get("verified") and e.get("uploaded"):
                up = float(e["uploaded"])
                fresh = (time.time() - up) < 36 * 3600
                d = datetime.fromtimestamp(up)
                L.append(self._kv(self.T('bot.ecmp_page.2'), self.T('bot.backup_page.20')
                                  if fresh else self.T('bot.backup_page.21')))
                L.append(self._kv(self.T('bot.backup_page.14'), "%s · %s %s" % (
                    _ago_srv(up), self._fa_date(d.strftime("%Y-%m-%d")),
                    _fa_num(d.strftime("%H:%M")))))
                L.append(self._kv(self.T('bot.backup_page.15'), fmt_bytes_srv(e.get("size") or 0)))
                L.append(self._rtl(self.T('bot.backup_page.16')))
                L.append(self._code_line(e.get("object") or ""))
                sha = e.get("sha256") or ""
                if sha:
                    L.append(self._rtl("sha256:"))
                    L.append(self._code_line(sha))
                    b = self._copy_btn(
                        self.T('bot.backup_page.17', p0=self.T('bot.lit.7') if key == 'panel' else self.T('bot.lit.8')), sha)
                    if b:
                        kb.append([b])
            else:
                L.append(self._kv(self.T('bot.ecmp_page.2'), self.T('bot.backup_page.18')))
            ent = _S4_CACHE.get(key)   # فقط کشِ گرم؛ شبکه ممنوع
            d4 = (ent or {}).get("data") or {}
            if d4.get("ok"):
                L.append(self._kv(self.T('bot.backup_page.19'), "%s · %s" % (
                    _fa_num(d4.get("count") or 0),
                    fmt_bytes_srv(d4.get("total_bytes") or 0))))
            L.append("")
        L.append(self._head(self.T('bot.backup_page.5')))
        for label, unit in ((self.T('bot.backup_page.6'), "wg-panel-backup"),
                            (self.T('bot.backup_page.4'), FULL_BACKUP_UNIT),
                            (self.T('bot.backup_page.7'), "wg-panel-s4-upload"),
                            (self.T('bot.backup_page.8'), "wg-panel-verify-backup")):
            sp = _unit_props(unit + ".service",
                             ("ExecMainExitTimestamp", "Result"))
            tp = _unit_props(unit + ".timer", ("NextElapseUSecRealtime",))
            last = _sysd_ts(sp.get("ExecMainExitTimestamp"))
            nxt = _sysd_ts(tp.get("NextElapseUSecRealtime"))
            res = sp.get("Result", "")
            stat = self.T('bot.backup_page.9') if res == "success" else (res or "—")
            L.append(self._kv("%s:" % label, self.T('bot.backup_page.11', p0=stat, p1=_ago_srv(last) if last else '—', p2=_fa_num(datetime.fromtimestamp(nxt).strftime('%m-%d %H:%M')) if nxt else '—')))
        left = 0
        for dpath in ("/var/backups/wg-panel", FULL_BACKUP_DIR):
            try:
                left += sum(1 for f in os.listdir(dpath)
                            if f.endswith(".tar.gz"))
            except OSError:
                pass
        L.append("")
        L.append(self._kv(self.T('bot.backup_page.10'),
                          self.T('bot.backup_page.12') if left == 0
                          else self.T('bot.backup_page.13', p0=_fa_num(left))))
        kb.append(self._back_row())
        self.send(chat, "\n".join(L).rstrip(), kb)

    # ---- تستِ سرعت (از ربات)
    def _speed_page(self, frm, chat, p):
        if "sys.view" not in p:
            self.send(chat, self.T('bot.speed_page.1'), [self._back_row()])
            return
        st = SPEEDTEST.state
        L = [self._titlebar(self.T('bot.speed_page.2')), ""]
        if st["running"]:
            L += [self._rtl(self.T('bot.speed_page.4', p0=esc_html(st['current'] or '…'), p1=_fa_num(st['done']), p2=_fa_num(st['total']))),
                  ""]
        seen = set()
        for r in META.speedtest_recent(60):
            if not r["ok"] or r["iface"] in seen:
                continue
            seen.add(r["iface"])
            L.append(self._rtl("<code>%s</code> — %s"
                               % (esc_html(r["iface"]), _ago_srv(r["ts"]))))
            L.append(self._kv(self.T('bot.speed_page.5'), _fa_num(
                "%.0f / %.0f Mbit/s" % (r["down_bps"] / 1e6,
                                        r["up_bps"] / 1e6))))
            L.append(self._kv(self.T('bot.speed_page.6'), _fa_num("%.0f ms" % r["ping_ms"])
                              if r["ping_ms"] is not None else "—"))
            L.append("")
        if not seen:
            L.append(self._rtl(self.T('bot.speed_page.7')))
        row1 = [{"text": self.T('bot.speed_page.3'), "callback_data": "spd:graph"}]
        if "svc.edit" in p and not st["running"]:
            row1.append({"text": self.T('bot.speed_page.8'), "callback_data": "spd:run"})
        self.send(chat, "\n".join(L).rstrip(), [row1, self._back_row()])

    def _speed_action(self, frm, chat, act, p):
        if act == "run":
            if "svc.edit" not in p:
                self.send(chat, self.T('bot.speed_action.2'),
                          [self._back_row()])
                return
            ok = SPEEDTEST.start(actor="bot:%s" % frm)
            audit("bot:%s" % frm, "settings", self.T('bot.speed_action.1'),
                  ",".join(SPEEDTEST.ifaces()), "", "", ok)
            self.send(chat, self.T('bot.speed_action.3') if ok
                      else self.T('bot.speed_action.4'),
                      [[{"text": self.T('bot.speed_action.5'), "callback_data": "spd:page"}],
                       self._back_row()])
        elif act == "graph":
            self._speed_graph(chat)
        else:
            self._speed_page(frm, chat, p)

    def _speed_graph(self, chat):
        targets = SPEEDTEST.ifaces()
        iface = targets[0] if targets else ""
        rows = [r for r in META.speedtest_recent(1200)
                if r["iface"] == iface and r["ok"]][::-1]
        if len(rows) < 2:
            self.send(chat, self.T('bot.speed_graph.1'),
                      [self._back_row()])
            return
        dn = [r["down_bps"] / 1e6 for r in rows]
        up = [r["up_bps"] / 1e6 for r in rows]
        lbl = lambda ts: datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")
        xl = [(0.0, lbl(rows[0]["ts"])), (1.0, lbl(rows[-1]["ts"]))]
        if len(rows) > 2:
            xl.insert(1, (0.5, lbl(rows[len(rows) // 2]["ts"])))
        png = render_chart_png(
            [(dn, (63, 185, 80), "DOWN"), (up, (88, 166, 255), "UP")],
            x_labels=xl, y_fmt=_fmt_mbps_ascii,
            title=iface.upper())
        cap = "\n".join([
            self._rtl(self.T('bot.speed_graph.2', p0=esc_html(iface), p1=_fa_num(len(rows)))),
            self._kv(self.T('bot.speed_graph.3'), _fa_num("%.0f / %.0f Mbit/s"
                                       % (dn[-1], up[-1]))),
            self._kv(self.T('bot.speed_graph.4'), _fa_num("%.0f / %.0f Mbit/s"
                                         % (sum(dn) / len(dn),
                                            sum(up) / len(up)))),
            self._kv(self.T('bot.speed_graph.5'), _fa_num("%.0f / %.0f Mbit/s"
                                        % (max(dn), max(up))))])
        self.send_photo(chat, png, cap)

    # ---- نماهای گزارش
    def _wg_list_sorted(self, chat, p, mode):
        if "wg.view" not in p:
            self.send(chat, self.T('bot.speed_page.1'), [self._back_row()])
            return
        users = build_stats().get("users", [])
        meta = META.meta_all()
        rows = []
        for u in users:
            m = meta.get((u["iface"], u["name"]), {})
            u["_exp"] = m.get("expires") or ""
            u["_use"] = u.get("rx", 0) + u.get("tx", 0)
        if mode == "quota":
            users.sort(key=lambda x: -x["_use"])
            title = self.T('bot.wg_list_sorted.1')
            label = lambda u: fmt_bytes_srv(u["_use"])
        else:
            users.sort(key=lambda x: (x["_exp"] == "", x["_exp"]))
            title = self.T('bot.wg_list_sorted.2')
            label = lambda u: (_fa_num(u["_exp"]) if u["_exp"] else self.T('bot.wg_add_create.14'))
        for u in users[:50]:
            rows.append([{"text": "%s — %s" % (u["name"], label(u)),
                          "callback_data": "wg:show:%s|%s" % (u["iface"], u["name"])}])
        rows.append(self._back_row())
        self.send(chat, self._rtl(self.T('bot.wg_list_sorted.3', p0=title, p1=_fa_num(len(users)))), rows)

    def _live_list(self, chat, p):
        if "wg.view" not in p:
            self.send(chat, self.T('bot.speed_page.1'), [self._back_row()])
            return
        users = [u for u in build_stats().get("users", []) if u.get("online")]
        if not users:
            self.send(chat, self.T('bot.live_list.1'), [self._back_row()])
            return
        users.sort(key=lambda x: -(x.get("rx", 0) + x.get("tx", 0)))
        rows = [[{"text": "%s (%s) — ↓%s ↑%s" % (
            u["name"], u["iface"], fmt_bytes_srv(u.get("rx", 0)),
            fmt_bytes_srv(u.get("tx", 0))),
            "callback_data": "wg:show:%s|%s" % (u["iface"], u["name"])}]
            for u in users[:50]]
        rows.append(self._back_row())
        self.send(chat, self._rtl(self.T('bot.live_list.2', p0=_fa_num(len(users)))), rows)

    def _find(self, chat, q, p):
        q = q.lower()
        rows = []
        if "wg.view" in p:
            for u in build_stats().get("users", []):
                if q in u["name"].lower():
                    rows.append([{"text": "%s (%s)" % (u["name"], u["iface"]),
                                  "callback_data": "wg:show:%s|%s" % (u["iface"], u["name"])}])
        if "proxy.view" in p:
            for u in META.proxy_users():
                if q in u["username"].lower():
                    rows.append([{"text": "%s" % u["username"],
                                  "callback_data": "px:show:%s" % u["username"]}])
        if not rows:
            self.send(chat, self._rtl(self.T('bot.find.2', p0=esc_html(q))),
                      [self._back_row()])
            return
        n = len(rows)
        rows = rows[:40] + [self._back_row()]
        self.send(chat, self._rtl(self.T('bot.find.1', p0=esc_html(q), p1=_fa_num(n))), rows)


# ---- تأیید ورودِ پنل با تپِ تلگرام (2FA) ----
_login_approvals = {}
_login_appr_lock = threading.Lock()


def login2fa_enabled():
    c = alert_cfg()
    return bool((CONFIG.get("login_2fa") or {}).get("enabled")
                and c["bot_token"] and c["chat_id"])


def parse_login_chat(raw):
    """اعتبارسنجیِ «چتِ تأییدِ ورود»ِ یک کاربرِ پنل → (chat_id، خطا).

    خالی مجاز است (یعنی «به چتِ اصلیِ هشدارها برود»). فقط شناسهٔ **مثبت**
    پذیرفته می‌شود: شناسهٔ منفی یعنی گروه/کانال، و تأییدِ ورودِ شخصی در
    گروه یعنی «هرکسی در آن گروه می‌تواند ورودِ این حساب را تأیید کند» —
    که هدفِ ۲مرحله‌ای را از بین می‌برد."""
    s = str(raw or "").strip()
    if not s:
        return "", None
    # [0-9] نه \d — چون \d در پایتون ارقامِ فارسی/عربی («۱۲۳») را هم می‌پذیرد
    # و آن‌وقت شناسه‌ای ذخیره می‌شد که تلگرام هرگز نمی‌شناسد.
    if not re.fullmatch(r"[0-9]{1,20}", s):
        return "", "api.err.login_chat.format"
    return s, None


def verify_login_chat(chat_id, username):
    """پیشاپیش مطمئن شو ربات می‌تواند به این چت پیام بدهد → (ok، خطا).

    بدونِ این بررسی، یک شناسهٔ اشتباه یعنی **قفل‌شدنِ کاملِ آن کاربر** (چون
    نرسیدنِ پیام = ردِ ورود)."""
    c = alert_cfg()
    if not c["bot_token"]:
        return False, "api.err.login_chat.no_token"
    ok, res = tg_api(c["bot_token"], "sendMessage",
                     {"chat_id": chat_id, "parse_mode": "HTML",
                      "text": "<b>تأییدِ ورودِ پنل</b>\nاز این پس درخواستِ "
                              "تأییدِ ورودِ حسابِ <b>%s</b> به همین چت "
                              "می‌آید." % esc_html(username)},
                     iface=c["iface"])
    if ok:
        return True, ""
    return False, aerr("api.err.login_chat.send", v=str(res)[:120])


def user_login_chat(u):
    """چتِ مقصدِ تأییدِ ورودِ این کاربر: چتِ شخصیِ خودش، وگرنه چتِ اصلیِ
    هشدارها (رفتارِ قبلی، تا هیچ کاربری بدونِ مقصد نمانَد)."""
    own = str((u or {}).get("tg_chat") or "").strip()
    return own or str(alert_cfg()["chat_id"] or "").strip()


def login_approval_dest(token):
    """چتی که درخواستِ تأیید واقعاً به آن فرستاده شد (بندِ امنیتیِ callback)."""
    with _login_appr_lock:
        rec = _login_approvals.get(token)
        return str(rec.get("chat", "")) if rec else ""


def resolve_login_approval(token, approved):
    with _login_appr_lock:
        if token in _login_approvals:
            _login_approvals[token]["state"] = \
                "approved" if approved else "rejected"


def request_login_approval(user, ip):
    """پیامِ تأیید را به چتِ خودِ کاربر — یا **در نبودش به چتِ مشترکِ
    هشدارها** — می‌فرستد و تا ~۹۰ ثانیه منتظرِ تپ می‌ماند.

    ⚠️ مقصد `own or fallback` است، نه فقط `own`. کاربری که `tg_chat`
    ندارد روی چتِ مشترک می‌افتد و آنجا **هر ادمینِ رباتِ حاضر در آن چت**
    می‌تواند تأییدش کند — یعنی عاملِ دوم برای او «تأییدِ یک ادمین» است نه
    «تأییدِ خودِ کاربر». این عمدی است و تصمیمِ ثبت‌شده‌ی مالک
    (plans/043، معوق ۱۳ اوت ۲۰۲۶): بستنِ این بازگشت هر کاربرِ بدونِ چتِ
    خصوصی را در استقرار قفل می‌کند. اگر روزی بسته شد، این داک‌استرینگ و
    `LoginApprovalDocstringTests` هر دو باید عوض شوند.

    True = تأیید شد. اگر هیچ مقصدی نباشد یا نتوان پیام فرستاد → False
    (پیش‌فرضِ امن؛ ورود از 127.0.0.1 این مسیر را دور می‌زند تا قفل‌شدنِ
    اضطراری رخ ندهد)."""
    c = alert_cfg()
    username = user["username"] if isinstance(user, dict) else str(user)
    own = str((user or {}).get("tg_chat") or "").strip() \
        if isinstance(user, dict) else ""
    fallback = str(c["chat_id"] or "").strip()
    dest = own or fallback
    if not dest:
        log_action("login 2fa: no destination chat for user=%s" % username)
        return False
    token = secrets.token_urlsafe(10)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _login_appr_lock:
        # هرسِ درخواست‌های رهاشده (نشتِ حافظه)
        for k in [k for k, v in _login_approvals.items()
                  if time.time() - v["ts"] > 300]:
            _login_approvals.pop(k, None)
        _login_approvals[token] = {"state": "pending", "ts": time.time(),
                                   "chat": dest, "user": username}
    kb = {"inline_keyboard": [[
        {"text": "تأیید", "callback_data": "lg:ok:" + token},
        {"text": "رد", "callback_data": "lg:no:" + token}]]}
    text = ("<b>تلاشِ ورود به پنل</b>\nکاربر: <b>%s</b>\n"
            "IP: <code>%s</code>\nزمان: %s\n\nخودتان هستید؟"
            % (esc_html(username), ip, now))
    ok, _ = tg_api(c["bot_token"], "sendMessage",
                   {"chat_id": dest, "parse_mode": "HTML", "text": text,
                    "reply_markup": json.dumps(kb)}, iface=c["iface"])
    if not ok and own and fallback and fallback != own:
        # چتِ شخصیِ کاربر از دسترس خارج شده (ربات بلاک شده و…) — به‌جای
        # قفل‌شدنِ حساب، به چتِ اصلی برگرد ولی صریح بگو چه شد.
        log_action("login 2fa: chat %s unreachable for user=%s → fallback"
                   % (own, username))
        with _login_appr_lock:
            if token in _login_approvals:
                _login_approvals[token]["chat"] = fallback
        ok, _ = tg_api(c["bot_token"], "sendMessage",
                       {"chat_id": fallback, "parse_mode": "HTML",
                        "text": text + "\n\n<i>چتِ شخصیِ این کاربر در دسترس "
                                       "نبود؛ این درخواست به چتِ اصلی آمد.</i>",
                        "reply_markup": json.dumps(kb)}, iface=c["iface"])
    if not ok:
        with _login_appr_lock:
            _login_approvals.pop(token, None)
        return False
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(1)
        with _login_appr_lock:
            state = _login_approvals.get(token, {}).get("state")
        if state in ("approved", "rejected"):
            with _login_appr_lock:
                _login_approvals.pop(token, None)
            return state == "approved"
    with _login_appr_lock:
        _login_approvals.pop(token, None)
    return False


def bot_setcommands():
    """منوی دستورِ ربات را در تلگرام ثبت می‌کند (دکمه‌ی Menu)، به زبانِ هر کاربر.

    دو لایه؛ تلگرام خاص‌ترین را نشان می‌دهد:
      ۱. پیش‌فرض (همه‌ی چت‌ها): زبانِ مالک، همان زبانِ هشدارها؛
      ۲. scope=chat برای هر کاربرِ مجاز: زبانی که با /lang برگزیده، تا منو
         همان زبانِ پاسخ‌های ربات باشد. مالک(ها) در انتها «پایش کاربران
         بات» را هم می‌گیرند — بقیه این دستور را اصلاً نمی‌بینند.
    پیش‌تر توضیح‌ها ثابت و فارسی بودند، در هر زبانی که کاربر انتخاب کرده بود.
    """
    tok = alert_cfg()["bot_token"]
    if not (tok and bot_cfg()["enabled"]):
        return
    cmds = [("start", "bot.cmd.start"), ("menu", "bot.cmd.menu"),
            ("addwg", "bot.cmd.addwg"),
            ("addpx", "bot.cmd.addpx"),
            ("wgusers", "bot.cmd.wgusers"), ("pxusers", "bot.cmd.pxusers"),
            ("live", "bot.cmd.live"), ("find", "bot.cmd.find"),
            ("listexp", "bot.cmd.listexp"),
            ("listquota", "bot.cmd.listquota"),
            ("digest", "bot.cmd.digest"), ("speed", "bot.cmd.speed"),
            ("backup", "bot.cmd.backup"),
            ("ecmp", "bot.cmd.ecmp"),
            ("warp", "bot.cmd.warp"),
            ("botusers", "bot.cmd.botusers"),
            ("cancel", "bot.cmd.cancel")]
    own = cmds + [("botwatch", "bot.cmd.botwatch")]
    ifc = alert_cfg()["iface"]

    def put(items, lang, scope=None):
        p = {"commands": [{"command": c, "description": t(k, lang)}
                          for c, k in items]}
        if scope:
            p["scope"] = scope
        tg_api(tok, "setMyCommands", p, iface=ifc)

    put(cmds, alert_lang())
    for u in bot_cfg()["users"]:
        try:
            cid = int(str(u.get("id")))
        except (TypeError, ValueError):
            continue
        put(own if u.get("role") == "owner" else cmds, bot_lang(cid),
            {"type": "chat", "chat_id": cid})


BOT = TelegramBot()


# ============================================================================
# تشخیص مسیر سرویس‌ها (فاز ۰ و ۱) — فقط اطلاعاتی
# ---------------------------------------- تشخیصِ سرویس‌های محدودشده (SvcDiag)
# هدف: بفهمیم سرویس‌هایی که در ایران محدودند (یوتیوب، یوتیوب‌موزیک، x.com،
# تلگرام، Tidal) از دلِ خروجی(های) فعلی چه وضعیتی دارند و مقصدشان کدام IPهاست.
#
# ★ این ماژول هیچ‌چیزی در سیستم تغییر نمی‌دهد: نه ip route، نه ip rule، نه
#   iptables/nftables، نه ipset. فقط (۱) دامنه‌ها را resolve می‌کند (DNS) و
#   (۲) با curl که به اینترفیسِ خروجی bind شده یک درخواستِ سبک می‌زند و
#   نتیجه (کد HTTP/تأخیر/حکم) را در دیتابیس ثبت می‌کند. خروجی‌ها همان
#   مسیری‌اند که کاربر همین حالا از آن بیرون می‌رود؛ چیز تازه‌ای مسیردهی
#   نمی‌شود. بارِ آن هم ناچیز است (چند درخواست کوچک هر چند دقیقه).
# ============================================================================

# سرویس‌های هدف: کلید → (برچسب فارسی، دامنه‌ها برای resolve، URL پروب).
# probe_url های generate_204 سبک‌اند (۲۰۴ بدون بدنه). دامنه‌ها فقط برای
# جمع‌آوریِ موجودیِ IP مقصد resolve می‌شوند.
SVC_DEFAULTS = {
    "youtube":  {"label": "یوتیوب",
                 "domains": ["www.youtube.com", "youtube.com",
                             "youtubei.googleapis.com"],
                 "probe": "https://www.youtube.com/generate_204"},
    "ytmusic":  {"label": "یوتیوب موزیک",
                 "domains": ["music.youtube.com"],
                 "probe": "https://music.youtube.com/generate_204"},
    "x":        {"label": "x.com (توییتر)",
                 "domains": ["x.com", "api.x.com", "twitter.com",
                             "abs.twimg.com"],
                 "probe": "https://x.com/robots.txt"},
    "telegram": {"label": "تلگرام",
                 "domains": ["telegram.org", "core.telegram.org",
                             "web.telegram.org"],
                 "probe": "https://telegram.org/"},
    "tidal":    {"label": "Tidal",
                 "domains": ["tidal.com", "listen.tidal.com", "api.tidal.com"],
                 "probe": "https://listen.tidal.com/"},
}

# regex نامِ اینترفیس مجاز برای پاس‌دادن به curl (جلوگیری از تزریق).
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,20}$")
_UA_PROBE = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$")


def svc_services():
    """تعریف سرویس‌ها: پیش‌فرض‌های allow-list + سرویس‌های سفارشیِ ادمین.

    پیش‌فرض‌ها فقط از SVC_DEFAULTS. سرویس‌های سفارشی در CONFIG["svc_custom"]
    ذخیره می‌شوند و هنگام افزودن سخت اعتبارسنجی می‌شوند (دامنه‌ی عمومی؛ ضدِ SSRF)؛
    probe همیشه https://<دامنه>/ است (URL دلخواه پذیرفته نمی‌شود).
    """
    enabled = CONFIG.get("svc_services")
    if enabled is None or not isinstance(enabled, list):
        out = dict(SVC_DEFAULTS)           # کلید تنظیم نشده → همه‌ی پیش‌فرض‌ها
    else:
        # لیستِ صریح (حتی خالی) رعایت می‌شود تا حذفِ سرویس ماندگار باشد.
        out = {k: SVC_DEFAULTS[k] for k in enabled if k in SVC_DEFAULTS}
    custom = CONFIG.get("svc_custom")
    if isinstance(custom, dict):
        for k, v in custom.items():
            if (isinstance(v, dict) and v.get("domains")
                    and v.get("probe")):
                out[k] = {"label": v.get("label") or k,
                          "domains": list(v["domains"]),
                          "probe": v["probe"], "custom": True}
    return out


# حرف/عدد (هر زبانی)، فاصله، نقطه، خطِ تیره، پرانتز — بدونِ کوتیشن، < > & و
# کاراکترِ کنترلی؛ اولین نویسه حرف یا عدد.
_SVC_LABEL_RE = re.compile(r"[^\W_][\w .\-()]{0,39}")


def svc_add_custom(domain, label):
    """افزودنِ سرویسِ سفارشی از یک دامنه (ضدِ SSRF). خروجی: (key, error)."""
    domain = (domain or "").strip().lower()
    # اگر کاربر URL چسبانده، فقط hostname را جدا کن
    if "//" in domain:
        domain = domain.split("//", 1)[1]
    domain = domain.split("/")[0].split("?")[0].split(":")[0].strip().strip(".")
    if not _DOMAIN_RE.match(domain):
        return None, "api.err.svc.domain_bad"
    # برچسب در رابط داخلِ HTML و آرگومانِ handler می‌رود؛ سمتِ سرور هم
    # محدود می‌شود تا یک svc.edit نتواند متنِ دلخواه به همه‌ی ادمین‌ها برساند
    # (دفاعِ دوم؛ اولی escape ِ درستِ سمتِ کلاینت است).
    label = (label or "").strip()
    if label and not _SVC_LABEL_RE.fullmatch(label):
        return None, "api.err.svc.label_bad"
    try:
        ipaddress.ip_address(domain)
        return None, "api.err.svc.ip_not_domain"
    except ValueError:
        pass
    # resolve و بررسیِ اینکه فقط به IP عمومی اشاره می‌کند (ضدِ SSRF)
    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except Exception:
        return None, "api.err.svc.unresolved"
    ips = {i[4][0] for i in infos}
    if not ips:
        return None, "api.err.svc.noaddr"
    for ip in ips:
        if not _is_global_ip(ip):
            return None, "api.err.svc.nonpublic"
    key = "c_" + re.sub(r"[^a-z0-9]+", "_", domain).strip("_")
    if key in svc_services():
        return None, "api.err.svc.exists"
    custom = CONFIG.get("svc_custom")
    if not isinstance(custom, dict):
        custom = {}
    if len(custom) >= 30:
        return None, "api.err.svc.max"
    with config_txn() as cfg:
        custom[key] = {"label": (label or domain).strip()[:40] or domain,
                       "domains": [domain], "probe": "https://%s/" % domain}
        cfg["svc_custom"] = custom
    return key, None


def _valid_public_iface(iface):
    """نام اینترفیس باید امن باشد و واقعاً وجود داشته باشد."""
    if not _IFACE_RE.match(iface or ""):
        return False
    try:
        return iface in iface_meta_all()
    except Exception:
        return False


def svc_probe_ifaces():
    """اینترفیس‌های خروجیِ کاندید برای پروب.

    پیش‌فرض: فقط خروجیِ فعلیِ کاربر (تشخیص خودکار) — یعنی همان مسیری که
    کاربران الان از آن بیرون می‌روند، تا هیچ رفتار تازه‌ای اضافه نشود.
    admin می‌تواند با svc_probe_ifaces در config اینترفیس‌های دیگر را اضافه
    کند (برای مقایسه در فازهای بعد).
    """
    conf = CONFIG.get("svc_probe_ifaces")
    if isinstance(conf, list) and conf:
        out = [i for i in conf if _valid_public_iface(i)]
        if out:
            return out
    ex = detect_user_exit()
    return [ex] if ex else []


_exit_cache = {"ts": 0.0, "val": None}


def detect_user_exit():
    """اینترفیسی که ترافیکِ فورواردیِ کاربر از آن بیرون می‌رود (کش ۶۰ ثانیه).

    فقط خواندنی: با `ip route get` مسیرِ یک مقصد نمونه را از IP یک کاربر
    شبیه‌سازی می‌کند و دستگاه خروجی را می‌خواند. چیزی تغییر نمی‌کند.
    """
    now = time.time()
    if now - _exit_cache["ts"] < 60 and _exit_cache["val"] is not None:
        return _exit_cache["val"]
    dev = None
    ifaces = server_ifaces()
    for sif in ifaces:
        subnet = iface_subnet(sif)
        if not subnet:
            continue
        try:
            hosts = list(ipaddress.ip_network(subnet).hosts())
        except ValueError:
            continue
        # آدرسِ خودِ سرور (معمولاً .1) را رد کن: kernel به `ip route get
        # from <آدرسِ محلی>` خطای «Invalid argument» می‌دهد. یک IP کاربر
        # (آدرسی که محلی نیست) را به‌عنوان مبدأ شبیه‌سازی انتخاب می‌کنیم.
        try:
            local = set(iface_meta_all().get(sif, {}).get("addresses", []))
        except Exception:
            local = set()
        src = next((str(h) for h in hosts if str(h) not in local), None)
        if not src:
            continue
        rc, out, _ = run(["ip", "route", "get", "142.250.185.110",
                          "from", src, "iif", sif], timeout=6)
        if rc == 0 and " dev " in out:
            try:
                dev = out.split(" dev ", 1)[1].split()[0]
            except IndexError:
                dev = None
            if dev:
                break
    _exit_cache["ts"] = now
    _exit_cache["val"] = dev
    return dev


def svc_resolve_one(service):
    """دامنه‌های یک سرویس را resolve و مجموعه IPv4ها را برمی‌گرداند."""
    svc = svc_services().get(service)
    if not svc:
        return set()
    ips = set()
    for dom in svc["domains"]:
        try:
            infos = socket.getaddrinfo(dom, 443, socket.AF_INET,
                                       socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            continue
        for info in infos:
            ips.add(info[4][0])
    return ips


def _verdict(rc, code):
    """حکم فارسی از کد خروجی curl و کد HTTP."""
    if rc == 0 and code and 200 <= code < 400:
        return "ok", "دسترس‌پذیر"
    if code == 451:
        return "geoblock", "مسدود قانونی/جغرافیایی (۴۵۱)"
    if code in (403, 429):
        return "blocked", "پاسخِ مسدودسازی (%d)" % code
    if code and code >= 500:
        return "server", "خطای سمت سرویس (%d)" % code
    if rc == 28:
        return "timeout", "وقفه‌ی زمانی (بدون پاسخ)"
    if rc == 6 or rc == 7:
        return "unreach", "عدم اتصال/DNS"
    if rc == 35 or rc == 60:
        return "tls", "خطای TLS"
    if code:
        return "other", "کد HTTP %d" % code
    return "unreach", "ناموفق (curl rc=%s)" % rc


def svc_probe_one(service, iface):
    """یک پروبِ سبک به سرویس از دلِ اینترفیسِ داده‌شده (curl، bind به دستگاه).

    خروجی: dict نتیجه. هیچ تغییری در مسیریابی/فایروال نمی‌دهد.
    """
    svc = svc_services().get(service)
    if not svc:
        return None
    # detail فقط متنِ خامِ curl است؛ nocurl/badiface خودِ کدِ verdict اند و
    # مرورگر برچسبِ ترجمه‌شده‌شان را از SVC_VERDICT می‌گیرد
    if not shutil.which("curl"):
        return {"ok": False, "latency_ms": None, "http_code": None,
                "verdict": "nocurl", "detail": ""}
    if not _valid_public_iface(iface):
        return {"ok": False, "latency_ms": None, "http_code": None,
                "verdict": "badiface", "detail": ""}
    cmd = ["curl", "-4", "-sS", "-o", "/dev/null", "--interface", iface,
           "--max-time", "8", "-A", _UA_PROBE,
           "-w", "%{http_code} %{time_total}", svc["probe"]]
    rc, out, err = run(cmd, timeout=12)
    code, latency = None, None
    parts = (out or "").split()
    if len(parts) >= 2:
        try:
            code = int(parts[0])
            latency = round(float(parts[1]) * 1000.0, 1)
        except ValueError:
            pass
    if code == 0:
        code = None
    verdict, _label = _verdict(rc, code)
    return {"ok": verdict == "ok", "latency_ms": latency, "http_code": code,
            "verdict": verdict,
            "detail": (err or "").strip()[:200] if verdict != "ok" else ""}


def _is_global_ip(ip):
    """فقط IPهای واقعاً عمومی برای mtr/سرویسِ سفارشی مجازند (ضدِ SSRF).

    هر دو سنجه لازم‌اند و هیچ‌کدام جای دیگری را نمی‌گیرد:

    - فهرستِ صفت‌ها به‌تنهایی CGNAT ِ RFC 6598 (100.64.0.0/10) را رد نمی‌کند،
      چون در پایتون نه is_private است نه is_reserved. روی یک گیتوی VPN همان
      فضایی است که همسایه‌های اپراتور در آن‌اند.
    - is_global به‌تنهایی multicast و پیشوندِ NAT64 (64:ff9b::/96) را مجاز
      می‌کند، چون در رجیستریِ special-purpose ِ IANA نیستند. is_global سنجه‌ی
      «قابلِ مسیریابی در اینترنت» است، نه فیلترِ امنیتی؛ 64:ff9b::7f00:1 روی
      هاستی که گیتویِ NAT64 دارد به 127.0.0.1 می‌رسد.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not a.is_global:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or
                a.is_multicast or a.is_reserved or a.is_unspecified)


def _is_valid_ip(ip):
    """فقط اعتبارِ قالبِ IPv4/IPv6 (برای ویرایش/حذفِ موجودیِ سرویس — اطلاعاتی)."""
    try:
        ipaddress.ip_address(str(ip).strip())
        return True
    except ValueError:
        return False


def svc_mtr_target(service):
    """یک IP مقصدِ عمومی برای سرویس: از svc_resolved، وگرنه resolve لحظه‌ای."""
    for ip in META.svc_resolved_ips(service, limit=32):
        if _is_global_ip(ip):
            return ip
    for ip in svc_resolve_one(service):
        if _is_global_ip(ip):
            return ip
    return None


def _parse_traceroute(text, queries):
    """خروجی `traceroute -n -q Q` را به hopها تبدیل می‌کند (آمار سبکِ mtr-وار).

    هر خط: شماره‌ی هاپ، سپس IP(ها) و مقادیرِ «lat ms»؛ «*» = بسته‌ی گمشده؛
    توکن‌های `!H`/`!N`/`!X`… = علامتِ رسیدن/خطای ICMP (نگه می‌داریم).
    اگر یک هاپ چند IP بدهد (چند مسیر)، پرتکرارترین را host می‌گیریم و بقیه را
    در alt نگه می‌داریم.
    """
    hops = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("traceroute to"):
            continue
        toks = line.split()
        if not toks or not toks[0].isdigit():
            continue
        hop = int(toks[0])
        rest = toks[1:]
        hosts, lats, losses, notes, i = [], [], 0, [], 0
        while i < len(rest):
            t = rest[i]
            if t == "*":
                losses += 1
                i += 1
                continue
            if i + 1 < len(rest) and rest[i + 1] == "ms":
                try:
                    lats.append(float(t))
                except ValueError:
                    pass
                i += 2
                continue
            if t.startswith("!"):        # علامتِ traceroute (مثلِ !H, !N, !X)
                notes.append(t)
                i += 1
                continue
            hosts.append(t)              # یک IP (حالت -n)
            i += 1
        host = "???"
        alt = 0
        if hosts:
            uniq = {}
            for hh in hosts:
                uniq[hh] = uniq.get(hh, 0) + 1
            host = max(uniq, key=uniq.get)
            alt = len(uniq) - 1
        snt = max(queries, losses + len(lats))
        avg = round(sum(lats) / len(lats), 1) if lats else 0.0
        mean = (sum(lats) / len(lats)) if lats else 0.0
        jitter = (round((sum((x - mean) ** 2 for x in lats) / len(lats)) ** 0.5, 1)
                  if len(lats) > 1 else 0.0)
        hops.append({
            "hop": hop,
            "host": host,
            "alt": alt,                  # تعداد IPهای دیگرِ همان هاپ
            "loss": round(losses * 100.0 / snt, 1) if snt else 0.0,
            "snt": snt,
            "avg": avg,
            "best": round(min(lats), 1) if lats else 0.0,
            "wrst": round(max(lats), 1) if lats else 0.0,
            "jitter": jitter,            # انحرافِ معیارِ تأخیر (لرزش)
            "notes": "".join(notes),
        })
    return hops


# --- Reverse-DNS (PTR) با کش و مهلتِ سخت (برای خوانا‌شدنِ مسیر) ---
_ptr_cache = {}


def _ptr_lookup(ip):
    if ip in _ptr_cache:
        return _ptr_cache[ip]
    name = ""
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = ""
    _ptr_cache[ip] = name
    return name


def _enrich_ptr(hops, deadline=3.0):
    """PTR هر هاپ را (با کش) پر می‌کند؛ با مهلتِ کلی تا UI معطل نماند.

    لوکاپ‌های کندِ باقی‌مانده در پس‌زمینه کش را پر می‌کنند (بدونِ block).
    """
    ips = list({h["host"] for h in hops
                if h.get("host") and h["host"] != "???"
                and h["host"] not in _ptr_cache})
    if ips:
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        futs = [ex.submit(_ptr_lookup, ip) for ip in ips]
        concurrent.futures.wait(futs, timeout=deadline)
        ex.shutdown(wait=False)          # روی استراگلرها block نکن
    for h in hops:
        h["ptr"] = _ptr_cache.get(h.get("host"), "")


def _mos_score(rtt_ms, jitter_ms, loss_pct):
    """کیفیتِ تخمینیِ مسیر (۱ تا ۴.۵) با مدلِ ساده‌شده‌ی E-model.

    RTT گردِ رفت‌وبرگشت است؛ تأخیرِ یک‌طرفه ~ rtt/2 گرفته می‌شود.
    """
    latency = rtt_ms / 2.0
    eff = latency + jitter_ms * 2.0 + 10.0
    r = (93.2 - eff / 40.0) if eff < 160 else (93.2 - (eff - 120) / 10.0)
    r -= 2.5 * loss_pct
    r = max(0.0, min(100.0, r))
    mos = 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
    return round(max(1.0, min(4.5, mos)), 2)


def _path_summary(hops, target):
    """آمارِ سطحِ مسیر (end-to-end): rtt/jitter/loss/mos از هاپِ مقصد.

    هاپِ نماینده: هاپِ برابرِ target، وگرنه آخرین هاپِ پاسخ‌ده.
    """
    resp = [h for h in hops
            if h.get("host") and h["host"] != "???" and h.get("avg", 0) > 0]
    end = next((h for h in resp if h["host"] == target), None)
    if end is None and resp:
        end = resp[-1]
    if not end:
        return {"rtt": 0.0, "jitter": 0.0, "loss": 100.0, "mos": 1.0}
    rtt = float(end["avg"])
    jitter = float(end.get("jitter", 0.0))
    loss = float(end.get("loss", 0.0))
    return {"rtt": round(rtt, 1), "jitter": round(jitter, 1),
            "loss": round(loss, 1), "mos": _mos_score(rtt, jitter, loss)}


def svc_mtr(service, iface, cycles=None, store=True):
    """نمودار مسیر به یک IP مقصدِ سرویس از دلِ اینترفیسِ خروجی.

    ابزار: `traceroute -i <iface>` (بسته به دستگاهِ خروجی bind می‌شود تا
    مسیرِ واقعیِ همان تونل را بپیماید — mtr روی اینترفیس‌های tun پاسخ‌ها را
    دریافت نمی‌کند). چند کوئری در هر هاپ برای محاسبه‌ی میانگین/افت.

    فقط اطلاعاتی و SSRF-safe: مقصد از IPهای resolve‌شده‌ی همان سرویس (عمومی)
    و اینترفیس اعتبارسنجی‌شده است.
    """
    if service not in svc_services():
        return {"ok": False, "error": "api.err.svc.invalid"}
    if not _valid_public_iface(iface):
        return {"ok": False, "error": "api.err.svc.iface_invalid"}
    if not shutil.which("traceroute"):
        return {"ok": False, "error": "api.err.svc.no_traceroute"}
    ip = svc_mtr_target(service)
    if not ip:
        return {"ok": False, "error": "api.err.svc.no_public_ip"}
    try:
        q = int(cycles if cycles is not None else CONFIG.get("svc_trace_q", 3))
    except (TypeError, ValueError):
        q = 3
    q = max(1, min(q, 5))
    rc, out, err = run(["traceroute", "-n", "-i", iface, "-q", str(q),
                        "-w", "1", "-m", "20", ip], timeout=q * 22 + 10)
    hops = _parse_traceroute(out, q)
    if not hops:
        return {"ok": False, "error": (err or "api.err.svc.mtr_silent").strip()[:200],
                "target": ip, "iface": iface}
    _enrich_ptr(hops)
    # آیا مسیر به مقصد رسید؟ (آخرین هاپِ پاسخ‌ده == IP مقصد)
    responded = [h for h in hops if h["host"] and h["host"] != "???"]
    reached = bool(responded and responded[-1]["host"] == ip)
    dst_ptr = _ptr_cache.get(ip, "")
    summ = _path_summary(hops, ip)      # rtt/jitter/loss/mos سطحِ مسیر
    res = {"ok": True, "service": service, "iface": iface, "target": ip,
           "dst_ptr": dst_ptr, "reached": reached, "hop_count": len(hops),
           "cycles": q, "tool": "traceroute", "hops": hops,
           "rtt": summ["rtt"], "jitter": summ["jitter"],
           "loss": summ["loss"], "mos": summ["mos"]}
    if store:
        try:
            rid = META.mtr_add(service, iface, ip, summ["rtt"], summ["jitter"],
                               summ["loss"], summ["mos"], reached, len(hops),
                               json.dumps(hops))
            res["run_id"] = rid
            prev = META.mtr_prev(service, iface, rid)   # اجرای «قبل»
            if prev:
                res["prev"] = {"ts": prev["ts"], "rtt": prev["rtt"],
                               "jitter": prev["jitter"], "loss": prev["loss"],
                               "mos": prev["mos"], "reached": prev["reached"]}
        except Exception as e:
            log_action("mtr store error: %r" % e)
    return res


class SvcDiag(threading.Thread):
    """نخِ پس‌زمینه: هر چند دقیقه دامنه‌ها را resolve و سرویس‌ها را از
    خروجی(های) فعلی پروب می‌کند و نتیجه را در DB ثبت می‌کند.

    کاملاً اطلاعاتی؛ هیچ تغییری در سیستم اعمال نمی‌شود.
    """

    def __init__(self):
        super().__init__(daemon=True)
        self._wake = threading.Event()
        self.last_run = 0.0
        self.running = False
        self.last_mtr = {}      # (service, iface) -> ts آخرین ثبتِ مسیر

    def interval(self):
        try:
            v = int(CONFIG.get("svc_interval", 300))
        except (TypeError, ValueError):
            v = 300
        return max(60, v)

    def mtr_interval(self):
        """بازه‌ی جمع‌آوریِ خودکارِ نمودار مسیر (پیش‌فرض ۱ ساعت؛ ۰ = خاموش)."""
        try:
            return int(CONFIG.get("svc_mtr_interval", 3600))
        except (TypeError, ValueError):
            return 3600

    def kick(self):
        """اجرای فوری (از دکمه‌ی پنل)."""
        self._wake.set()

    def cycle(self):
        if not CONFIG.get("svc_enabled", True):
            return
        self.running = True
        try:
            services = svc_services()
            ifaces = svc_probe_ifaces()
            for key in services:
                try:
                    ips = svc_resolve_one(key)
                    META.svc_resolved_upsert(key, ips)
                except Exception as e:
                    log_action("svc resolve error (%s): %r" % (key, e))
                for iface in ifaces:
                    try:
                        res = svc_probe_one(key, iface)
                        if res:
                            META.svc_probe_upsert(
                                key, iface, res["ok"], res["latency_ms"],
                                res["http_code"], res["verdict"],
                                res["detail"])
                    except Exception as e:
                        log_action("svc probe error (%s@%s): %r"
                                   % (key, iface, e))
                    # جمع‌آوریِ خودکارِ نمودار مسیر (هر ~۱ ساعت) برای تاریخچه‌ی ۶ ماه
                    self._maybe_mtr(key, iface)
        finally:
            self.running = False
            self.last_run = time.time()

    def _maybe_mtr(self, key, iface):
        gap = self.mtr_interval()
        if gap <= 0:
            return
        now = time.time()
        if now - self.last_mtr.get((key, iface), 0) < gap:
            return
        self.last_mtr[(key, iface)] = now      # قبل از اجرا، تا تکرار نشود
        try:
            svc_mtr(key, iface, store=True)    # نتیجه در mtr_run ذخیره می‌شود
        except Exception as e:
            log_action("svc auto-mtr error (%s@%s): %r" % (key, iface, e))

    def run(self):
        # کمی صبر تا بقیه‌ی سرویس بالا بیاید، بعد یک دور اولیه.
        self._wake.wait(15)
        while True:
            _heartbeat("svcdiag")
            try:
                self.cycle()
            except Exception as e:
                log_action("svcdiag error: %r" % e)
            self._wake.clear()
            self._wake.wait(self.interval())


SVCDIAG = SvcDiag()


def build_svc_status():
    """داده‌ی صفحه‌ی «تشخیص مسیر سرویس‌ها» برای رابط کاربری."""
    services = svc_services()
    ifaces = svc_probe_ifaces()
    summary = META.svc_resolved_summary()
    probes = META.svc_probe_all()
    rows = []
    for key, svc in services.items():
        cells = {}
        for iface in ifaces:
            p = probes.get((key, iface))
            cells[iface] = p  # ممکن است None باشد (هنوز پروب نشده)
        rows.append({
            "key": key,
            "label": svc["label"],
            "custom": bool(svc.get("custom")),
            "probe_url": svc["probe"],
            "domains": svc["domains"],
            "ip_count": summary.get(key, {}).get("count", 0),
            "ip_last": summary.get(key, {}).get("last"),
            "cells": cells,
        })
    return {
        "enabled": bool(CONFIG.get("svc_enabled", True)),
        "interval": SVCDIAG.interval(),
        "ifaces": ifaces,
        "exit": detect_user_exit(),
        "running": SVCDIAG.running,
        "last_run": SVCDIAG.last_run,
        "has_curl": bool(shutil.which("curl")),
        "has_traceroute": bool(shutil.which("traceroute")),
        "services": rows,
    }


# ------------------------------------------------------------------ API آمار

def tunnel_row(iface, info, live_ifaces, live_peers, with_hist=True):
    """ردیفِ یک تونلِ خروجی همان‌طور که رابط می‌بیند، با سلامتش.

    منبعِ واحد برای build_stats و خروجیِ meta ِ WG-NQMO: سلامتی که موتور
    می‌گیرد همان است که پنل نشان می‌دهد."""
    active = iface in live_ifaces
    t = {
        "iface": iface,
        "active": active,
        "systemd": info["systemd"],
        "endpoint": info["endpoint"],
        "enabled": info.get("enabled", False),
        "kind": info.get("kind", "wireguard"),
        "userspace": info.get("userspace", False),
        "loop": info.get("loop", False),
        "loop_dev": info.get("loop_dev"),
        "chain": info.get("chain", False),
        "handshake": 0, "rx": 0, "tx": 0, "rx_rate": 0, "tx_rate": 0,
        "keepalive": "", "hist": [],
    }
    if active:
        for (ifc, pub), p in live_peers.items():
            if ifc == iface:
                t["handshake"] = p["handshake"]
                t["rx"] += p["rx"]
                t["tx"] += p["tx"]
                t["rx_rate"] += p["rx_rate"]
                t["tx_rate"] += p["tx_rate"]
                if p.get("keepalive") and p["keepalive"] != "off":
                    t["keepalive"] = p["keepalive"]
                if p["endpoint"] and p["endpoint"] != "(none)":
                    t["endpoint"] = p["endpoint"]
        if with_hist:
            t["hist"] = SAMPLER.iface_history(iface)
    t["health"] = tunnel_health(t)
    return t


def build_stats():
    snap = SAMPLER.snapshot()
    live_ifaces = snap.get("ifaces", {})
    live_peers = {(p["iface"], p["public_key"]): p for p in snap.get("peers", [])}
    srv_list = server_ifaces()

    # --- کاربرها (همه‌ی اینترفیس‌های سمت کاربر)
    users = []
    sections = []
    active_shares = META.share_active_set()  # یک کوئری برای همه (نه هر peer)
    for srv in srv_list:
        try:
            with open(conf_path(srv), "r", encoding="utf-8") as f:
                srv_lines = f.read().splitlines()
            blocks = parse_user_blocks(srv, srv_lines)
        except OSError as e:
            log_action("conf read error (%s): %r" % (srv, e))
            continue
        sections.append({
            "iface": srv,
            "active": srv in live_ifaces,
            "listen_port": live_ifaces.get(srv, {}).get("listen_port")
            or iface_listen_port(srv),
            "subnet": iface_subnet(srv) or "",
            "count": len(blocks),
        })
        for b in blocks:
            lp = live_peers.get((srv, b["public_key"]))
            mrx, mtx = SAMPLER.month_usage.get((srv, b["public_key"]), (0, 0))
            lrx, ltx = SAMPLER.life_usage.get((srv, b["public_key"]), (0, 0))
            meta = SAMPLER.meta_cache.get((srv, b["name"]), {})
            users.append({
                "iface": srv,
                "name": b["name"],
                "has_conf": has_client_conf(srv, b["name"]),
                "enabled": b["enabled"],
                "allowed_ips": b["allowed_ips"],
                "public_key": b["public_key"],
                "live": lp is not None,     # در snapshotِ زنده هست؟
                "online": bool(lp and lp["handshake"] and
                               time.time() - lp["handshake"] < 180),
                "handshake": lp["handshake"] if lp else 0,
                "endpoint": lp["endpoint"] if lp else "",
                "rx": lp["rx"] if lp else 0,
                "tx": lp["tx"] if lp else 0,
                "rx_rate": lp["rx_rate"] if lp else 0,
                "tx_rate": lp["tx_rate"] if lp else 0,
                "hist": SAMPLER.peer_history(srv, b["public_key"]) if lp else [],
                "month_rx": mrx,
                "month_tx": mtx,
                "life_rx": lrx,
                "life_tx": ltx,
                "note": meta.get("note", ""),
                "quota_gb": meta.get("quota_gb"),
                "expires": meta.get("expires") or "",
                "auto_disabled": meta.get("auto_disabled", ""),
                "total_gb": meta.get("total_gb"),
                "enforce_action": meta.get("enforce_action") or "disable",
                "rate_mbit": meta.get("rate_mbit") or "",
                "c_dns": meta.get("c_dns") or "",
                "c_mtu": meta.get("c_mtu") or "",
                "c_keepalive": (meta.get("c_keepalive")
                                if meta.get("c_keepalive") is not None else ""),
                "c_allowed": meta.get("c_allowed") or "",
                "has_psk": any(PSK_RE.match(srv_lines[i].strip())
                               for i in range(b["start"], b["end"] + 1)),
                "share_active": (srv, b["name"]) in active_shares,
            })

    # --- تونل‌ها (وضعیت systemd/Endpoint از کش پس‌زمینه)
    tunnels = []
    tcache = TUNNELS.get()
    for iface in sorted(tcache):
        if iface in srv_list:
            continue
        tunnels.append(tunnel_row(iface, tcache[iface], live_ifaces, live_peers))

    # --- همه‌ی اینترفیس‌های شبکه (از /proc/net/dev) با مجموع کل rx/tx
    netdev = SAMPLER.netdev_snapshot()
    imeta = iface_meta_all()
    wg_by_iface = {}  # iface -> {handshake, endpoint, peers} برای غنی‌سازی
    for (ifc, pub), p in live_peers.items():
        agg = wg_by_iface.setdefault(ifc, {"handshake": 0, "endpoint": "",
                                           "peers": 0})
        agg["peers"] += 1
        if p["handshake"] > agg["handshake"]:
            agg["handshake"] = p["handshake"]
        if p["endpoint"] and p["endpoint"] != "(none)":
            agg["endpoint"] = p["endpoint"]

    interfaces = []
    for iface in sorted(netdev):
        nd = netdev[iface]
        m = imeta.get(iface, {})
        addrs = m.get("addresses", [])
        kind, role = classify_iface(iface, addrs)
        wgi = wg_by_iface.get(iface)
        interfaces.append({
            "iface": iface,
            "kind": kind,
            "role": role,
            "addresses": addrs,
            "mtu": m.get("mtu", 0),
            "up": m.get("up", False),
            "rx_total": nd["rx_total"],
            "tx_total": nd["tx_total"],
            "rx_rate": nd["rx_rate"],
            "tx_rate": nd["tx_rate"],
            "hist": SAMPLER.net_history(iface),
            "handshake": wgi["handshake"] if wgi else 0,
            "endpoint": wgi["endpoint"] if wgi else "",
            "peers": wgi["peers"] if wgi else None,
        })

    # مجموع کل عبوری از اینترفیس‌های WAN (اینترنت خروجی/ورودی سرور)
    wan = [i for i in interfaces if i["role"] == "wan"]
    net_totals = {
        "rx_rate": sum(i["rx_rate"] for i in wan),
        "tx_rate": sum(i["tx_rate"] for i in wan),
        "rx_total": sum(i["rx_total"] for i in wan),
        "tx_total": sum(i["tx_total"] for i in wan),
    }

    srv_info = {
        "rx_rate": sum(u["rx_rate"] for u in users),
        "tx_rate": sum(u["tx_rate"] for u in users),
    }

    return {
        "ts": time.time(),
        "server": srv_info,
        "net_totals": net_totals,
        "sections": sections,
        "users": users,
        "tunnels": tunnels,
        "interfaces": interfaces,
        "sys": SYSMON.snapshot(),
    }


# ------------------------------------------- نمودارهای زنده (SvgStudio) و گزارشِ Excel
#
# مرزِ مسئولیت: این‌جا فقط **واقعیت** جمع می‌شود (همان منابعی که پنل و نگهبان‌ها
# می‌خوانند — هیچ منطقِ موازی). ساختنِ مدلِ نمودار در wgpanel/viz.py و کتابِ Excel
# در wgpanel/report.py است؛ هر دو تابعِ خالص‌اند و بی سرور آزموده می‌شوند. موتورِ
# مرورگر (web/svgstudio.js) هیچ دانشی از شبکه ندارد.

# مقصدهای سنجشِ مسیرِ پیش‌فرض از دیدِ کاربر: یکی در نیمه‌ی پایینِ IPv4 و یکی در نیمه‌ی
# بالا — مسیرِ catch-all می‌تواند فضای نشانی را بینِ دو تونل نصف کند و یک مقصد فقط
# یک نیمه را نشان می‌دهد. `ip route get` بسته‌ای نمی‌فرستد؛ فقط جدول را می‌پرسد.
# با CONFIG["viz"]["probes"] قابلِ بازنویسی است.
VIZ_DEFAULT_PROBES = ("1.0.0.1", "149.112.112.112")
VIZ_FACTS_TTL = 5.0
_VIZ_CACHE = {"ts": 0.0, "data": None}
_VIZ_LOCK = threading.Lock()


def _pkg_module(name):
    """ماژولِ خواهرِ داخلِ پکیج (viz، report، xlsx) — از همان راهِ _pkg_bytes.

    import ِ نسبی کار نمی‌کند: هارنسِ تست app.py را با نامِ سطح‌بالا و __package__ ِ
    خالی بار می‌کند، و روی سرور کد داخلِ wg_panel.pyz است. پس متنِ ماژول از
    __loader__ خوانده و یک بار در sys.modules نشانده می‌شود."""
    import sys as _sys
    import types as _types
    key = "wgpanel." + name
    mod = _sys.modules.get(key)
    if mod is None:
        mod = _types.ModuleType(key)
        mod.__file__ = os.path.join(os.path.dirname(os.path.abspath(__file__)), name + ".py")
        _sys.modules[key] = mod
        try:
            exec(compile(_pkg_text(name + ".py"), mod.__file__, "exec"), mod.__dict__)
        except Exception:
            _sys.modules.pop(key, None)
            raise
    return mod


def viz_ctx(lang):
    """زمینه‌ی ترجمه/ارقام/جهت برای سازنده‌های مدل."""
    lang = lang if lang in _LANG_IDX else DEFAULT_LANG
    V = _pkg_module("viz")
    return V.Ctx(lambda k, **kw: t(k, lang, **kw), fa=lang in LANG_FA_DIGITS,
                 rtl=LANG_DIR[lang] == "rtl")


def _t_or(key, fallback, lang):
    return t(key, lang) if key in I18N else fallback


def _viz_probes():
    p = (CONFIG.get("viz") or {}).get("probes")
    out = []
    for x in (p if isinstance(p, list) else VIZ_DEFAULT_PROBES):
        try:
            out.append(str(ipaddress.IPv4Address(str(x))))
        except ValueError:
            continue
    return out[:6] or list(VIZ_DEFAULT_PROBES)


def _routes_file_probe(path):
    """نخستین پیشوندِ معتبرِ یک routes_file ِ ECMP ⇒ یک نشانیِ درونِ آن (برای ip route get)."""
    try:
        with open(path, encoding="utf-8") as f:
            for ln in f:
                tok = ln.split("#", 1)[0].strip().split()
                if not tok:
                    continue
                try:
                    net = ipaddress.ip_network(tok[0], strict=False)
                except ValueError:
                    continue
                if net.version == 4:
                    return str(net.network_address + (1 if net.num_addresses > 2 else 0))
    except OSError:
        pass
    return ""


def _ks_rule_count():
    rc, out, _ = run(["ip", "rule", "show"], timeout=5)
    return sum(1 for ln in (out or "").splitlines() if " prohibit" in ln) if rc == 0 else 0


def _user_vantage(ingress):
    """(iif, src) ِ یک کاربرِ نمونه برای `ip route get … from … iif …`."""
    for g in ingress:
        ip = _sample_user_ip(g.get("subnet") or "")
        if ip:
            return g["iface"], ip
    return "", ""


def viz_egress_facts(stats=None):
    """واقعیت‌های نقشه‌ی مسیرِ خروج (قالب در viz.egress_model). کشِ چندثانیه‌ای:
    اسلایدِ TV و نقشه هر چند ثانیه می‌پرسند و هر سنجشِ مسیر یک پروسه‌ی ip است."""
    with _VIZ_LOCK:
        if _VIZ_CACHE["data"] is not None and time.time() - _VIZ_CACHE["ts"] < VIZ_FACTS_TTL and stats is None:
            return _VIZ_CACHE["data"]
    s = stats or build_stats()
    f = {"wan": "", "ingress": [], "users": {}, "ks": {}, "tunnels": s.get("tunnels") or [],
         "ecmp": {}, "default": [], "sni": None, "ai": None, "warp": None}
    users = s.get("users") or []
    f["users"] = {"total": len(users), "online": sum(1 for u in users if u.get("online")),
                  "disabled": sum(1 for u in users if not u.get("enabled"))}
    try:
        f["wan"] = _wan_iface()
        ks_if = user_ingress_ifaces()
        f["ks"] = {"rules": _ks_rule_count(), "ifaces": ks_if}
        rates = {i["iface"]: i for i in s.get("interfaces") or []}
        seen = set()
        for sec in s.get("sections") or []:
            i = sec["iface"]
            seen.add(i)
            f["ingress"].append({
                "iface": i, "peers": sec.get("count", 0),
                "online": sum(1 for u in users if u["iface"] == i and u.get("online")),
                "rx_rate": (rates.get(i) or {}).get("rx_rate", 0), "tx_rate": (rates.get(i) or {}).get("tx_rate", 0),
                "subnet": sec.get("subnet") or iface_connected_subnet(i), "ks": i in ks_if})
        for i in ks_if:                       # ورودیِ غیرِ WireGuard (مثلاً لایه‌ی AnyConnect)
            if i in seen:
                continue
            f["ingress"].append({"iface": i, "peers": 0, "online": 0,
                                 "rx_rate": (rates.get(i) or {}).get("rx_rate", 0),
                                 "tx_rate": (rates.get(i) or {}).get("tx_rate", 0),
                                 "subnet": iface_connected_subnet(i), "ks": True})
        iif, src = _user_vantage(f["ingress"])
        for p in _viz_probes():
            dev = _route_dev(p, src=src, iif=iif) if src else _route_dev(p)
            f["default"].append({"probe": p, "dev": dev})
    except Exception as e:
        log_action("viz egress facts: %r" % e)
    try:
        c = CONFIG.get("ecmp_guard") or {}
        groups = []
        for g in ecmp_groups(c):
            groups.append({"name": g.get("name") or os.path.basename(g["routes_file"]),
                           "tunnels": list(g["tunnels"]),
                           "member": {x: ECMPGUARD.membership.get((g.get("name"), x)) for x in g["tunnels"]},
                           "probe": _routes_file_probe(g["routes_file"])})
        f["ecmp"] = {"enabled": bool(c.get("enabled")), "groups": groups}
    except Exception as e:
        log_action("viz ecmp facts: %r" % e)
    try:
        if os.path.isfile(WARP_SYNC):
            w = warp_status()
            f["sni"] = dict(w.get("sni") or {})
            f["ai"] = w.get("ai_egress") or ai_egress_diag()
            g = w.get("guard") or {}
            f["warp"] = {"iface": WARP_IFACE, "up": bool((w.get("iface") or {}).get("up")),
                         "handshake": (w.get("iface") or {}).get("handshake") or 0,
                         "egress": g.get("egress") or "", "guard_alive": bool(g.get("alive")),
                         "healthy": bool(w.get("healthy"))}
    except Exception as e:
        log_action("viz warp facts: %r" % e)
    if stats is None:
        with _VIZ_LOCK:
            _VIZ_CACHE.update(ts=time.time(), data=f)
    return f


def viz_trace_facts(iface, name, can_tun):
    """واقعیت‌های ردیابیِ یک کاربر؛ None ⇒ چنین کاربری نیست."""
    s = build_stats()
    u = next((x for x in s.get("users") or [] if x["iface"] == iface and x["name"] == name), None)
    if u is None:
        return None
    ip = ""
    for a in str(u.get("allowed_ips") or "").split(","):
        a = a.strip()
        try:
            n = ipaddress.ip_network(a, strict=False)
        except ValueError:
            continue
        if n.version == 4:
            ip = str(n.network_address)
            break
    hist = []
    try:
        hist = SAMPLER.peer_history(iface, u["public_key"])
    except Exception:
        hist = []
    ks_if = user_ingress_ifaces()
    dec = []
    if ip:
        for p in _viz_probes():
            dec.append({"kind": "default", "probe": p, "dev": _route_dev(p, src=ip, iif=iface)})
        try:
            for g in ecmp_groups(CONFIG.get("ecmp_guard") or {}):
                pr = _routes_file_probe(g["routes_file"])
                if pr:
                    dec.append({"kind": "ecmp", "probe": pr, "dev": _route_dev(pr, src=ip, iif=iface),
                                "group": g.get("name") or ""})
        except Exception as e:
            log_action("viz trace ecmp: %r" % e)
        try:
            if os.path.isfile(WARP_SYNC) and (warp_sni_status() or {}).get("enabled"):
                main = _default_dev_of_table(WARP_TABLE)
                if main:
                    dec.append({"kind": "ai", "probe": "SNI · 443", "dev": main})
        except Exception as e:
            log_action("viz trace ai: %r" % e)
    return {"user": u, "ip": ip, "hist": hist, "wan": _wan_iface(),
            "ingress": {"iface": iface, "ks": iface in ks_if, "subnet": iface_subnet(iface) or ""},
            "decisions": dec, "can_tun": bool(can_tun),
            "tunnels": {x["iface"]: x for x in (s.get("tunnels") or [])} if can_tun else {}}


def _hour_ts(h):
    try:
        return datetime.strptime(h, "%Y-%m-%d %H").timestamp()
    except (TypeError, ValueError):
        return None


def viz_timeline_facts(hours, perms, lang):
    """رویدادهای بازه (پیش‌فرض ۲۴ ساعت) و مصرفِ ساعتیِ هر تونل.

    منبع‌ها به مجوزِ همان بخش در رابط گره خورده‌اند: رویدادِ تونل/اینترفیس و WARP با
    tun.view (همان /api/warp/events)، NQMO با nqmo.view، بقیه‌ی ممیزی با audit.view."""
    t1 = time.time()
    t0 = t1 - hours * 3600
    s = build_stats()
    tun = []
    for x in s.get("tunnels") or []:
        hrs = []
        if hours <= 24 * 21:
            for r in META.usage_series(x["iface"], IFACE_AGG_KEY, "24h" if hours <= 24 else "7d", gran="hour"
                                       if hours > 24 else None):
                ts = _hour_ts(r["t"])
                if ts is not None and ts + 3600 > t0:
                    hrs.append({"t": ts, "bytes": (r.get("rx") or 0) + (r.get("tx") or 0)})
        tun.append({"iface": x["iface"], "health": x.get("health"), "hours": hrs})
    return {"t0": t0, "t1": t1, "tunnels": tun, "events": viz_events(t0, perms, lang)}


def viz_events(t0, perms, lang):
    """رویدادهای پس از t0 از چهار منبع (ممیزیِ تونل، tunnel-guard، WARP، NQMO؛ و ممیزیِ دیگر با audit.view)، به یک شکل (خط‌زمان و برگه‌ی «رویدادها»ی Excel)."""
    days = max(1, int(math.ceil((time.time() - t0) / 86400.0)))
    ev = []
    sev_of = {"ok": "ok", "bad": "bad"}
    for cat in ("tunnel", "iface"):
        for r in META.audit_list(category=cat, since_days=days, limit=600):
            if r["ts"] < t0:
                continue
            a = r.get("action") or ""
            bad = any(w in a for w in ("down", "found", "fail", "degrade"))
            ev.append({"ts": r["ts"], "src": "audit", "subject": r.get("target") or "", "action": a,
                       "title": _t_or("ui.audit.act." + a, a, lang), "actor": r.get("actor") or "",
                       "detail": audit_detail_text(r.get("detail"), lang),
                       "sev": "bad" if bad else ("ok" if any(w in a for w in ("up", "fix")) else "info")})
    try:
        ev += guard_events(t0, lang)
    except Exception as e:
        log_action("viz guard events: %r" % e)
    try:
        for r in warp_events_read(limit=300):
            if r["ts"] < t0:
                continue
            k = r.get("kind") or ""
            ev.append({"ts": r["ts"], "src": "warp", "subject": "", "action": k,
                       "title": _t_or("ui.warpev." + k, k, lang), "actor": r.get("actor") or "",
                       "detail": r.get("detail") or "", "sev": "warn" if k in ("egress", "rotate") else "info"})
    except Exception as e:
        log_action("viz warp events: %r" % e)
    if "nqmo.view" in perms and nqmo_enabled():
        try:
            for r in nqmo_events(nqmo_state(), 0, NQMO_EVENTS_MAX, False, nqmo_panel_peers()):
                ts = r.get("ts") or 0
                if not ts or ts < t0:
                    continue
                cls = r.get("class") or ""
                subj = r.get("peer") or r.get("subject") or ""
                ev.append({"ts": ts, "src": "nqmo", "subject": "", "action": r.get("kind") or "",
                           "title": "%s · %s" % (_t_or("ui.nqmo.cls." + cls, cls, lang), r.get("kind") or ""),
                           "actor": subj, "detail": "%s %s" % (r.get("severity") or "", r.get("confidence") or ""),
                           "sev": "ok" if r.get("kind") == "close" else ("bad" if r.get("severity") == "CRITICAL" else "warn")})
        except Exception as e:
            log_action("viz nqmo events: %r" % e)
    if "audit.view" in perms:
        for r in META.audit_list(since_days=days, limit=400):
            if r["ts"] < t0 or r.get("category") in ("tunnel", "iface", "peer", "auth"):
                continue
            a = r.get("action") or ""
            ev.append({"ts": r["ts"], "src": "audit", "subject": "", "action": a,
                       "title": _t_or("ui.audit.act." + a, a, lang), "actor": r.get("actor") or "",
                       "detail": "%s %s" % (r.get("target") or "", audit_detail_text(r.get("detail"), lang)),
                       "sev": sev_of.get("ok" if r.get("ok") else "bad", "info")})
    return ev


GUARD_EVENTS_MAX = 400


def guard_events(t0, lang):
    """کنش‌ها و تغییرِ وضعیتِ tunnel-guard از ژورنال (تنها جایی که ثبت می‌شوند جز تلگرام).
    روی مک/دمو journalctl نیست ⇒ فهرستِ خالی."""
    V = _pkg_module("viz")
    rc, out, _ = run(["journalctl", "-t", "tunnel-guard", "--since", "@%d" % int(t0),
                      "-o", "json", "--no-pager", "-n", "5000"], timeout=10)
    if rc != 0:
        return []
    ev = []
    for line in out.splitlines():
        try:
            r = json.loads(line)
            ts = int(r["__REALTIME_TIMESTAMP"]) / 1e6
            msg = r.get("MESSAGE")
            if isinstance(msg, list):          # journald پیامِ غیر-UTF-8 را آرایه‌ی بایت می‌دهد
                msg = bytes(msg).decode("utf-8", "replace")
        except (ValueError, KeyError, TypeError):
            continue
        g = V.guard_event(msg)
        if g is None or ts < t0:
            continue
        subj, kind, sev, text = g
        ev.append({"ts": ts, "src": "guard", "subject": subj, "action": "guard." + kind,
                   "title": t("viz.gd." + kind, lang), "actor": "tunnel-guard",
                   "detail": text, "sev": sev})          # متنِ خامِ لاگ — پیامِ سیستم است و ترجمه نمی‌شود
    return ev[-GUARD_EVENTS_MAX:]


# ── کارپوشه‌ی Excel ─────────────────────────────────────────────────────
REPORT_DAYS = (1, 183)      # بازه‌ی مجاز؛ جدولِ روزانه ۶ ماه نگه داشته می‌شود


def _report_usage(days, ifaces):
    """(range_bytes, daily) ِ کاربرانِ اینترفیس‌های ifaces در days روزِ اخیر (امروز هم).

    فقط پیرهای کاربر: شمارنده‌ی خودِ اینترفیس و جمعِ تجمیعی کنار گذاشته می‌شوند،
    و تونل‌ها (که پیرهایشان هم در usage_day اند) با فیلترِ اینترفیس بیرون می‌مانند."""
    ifaces = sorted(set(ifaces))
    if not ifaces:
        return {}, []
    since = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    q = ",".join("?" * len(ifaces))
    base = ("FROM usage_day WHERE day>=? AND pubkey NOT IN (?, ?) AND iface IN (%s)" % q)
    args = [since, NETDEV_KEY, IFACE_AGG_KEY] + ifaces
    con = MetaDB._connect()
    try:
        rng = {(i, p): (rx or 0) + (tx or 0) for i, p, rx, tx in con.execute(
            "SELECT iface, pubkey, SUM(rx), SUM(tx) " + base + " GROUP BY iface, pubkey", args)}
        daily = [{"day": d, "bytes": b or 0, "active": n} for d, b, n in con.execute(
            "SELECT day, SUM(rx) + SUM(tx), COUNT(DISTINCT iface || '/' || pubkey) " + base +
            " AND rx + tx > 0 GROUP BY day ORDER BY day", args)]
    finally:
        con.close()
    return rng, daily


def _report_metric(metric, days):
    """میانگینِ روزانه‌ی یک متریکِ سامانه در days روزِ اخیر."""
    mode = "7d" if days <= 7 else ("30d" if days <= 30 else "6m")
    since = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    return [r for r in META.metric_series(metric, mode) if str(r.get("t")) >= since]


def report_facts(perms, days, mask, lang):
    """واقعیت‌های کارپوشه (قالب در report.build). هر بخش فقط با مجوزِ همان بخش در رابط
    جمع می‌شود — کتاب چیزی را نشان نمی‌دهد که همان کاربر در پنل نمی‌بیند."""
    perms = set(perms)
    now = time.time()
    s = build_stats()
    f = {"now": now, "host": _host_label(), "build": BUILD_ID or "", "days": days,
         "mask": bool(mask), "perms": perms}
    if "wg.view" in perms:
        users = []
        for u in s.get("users") or []:
            u = dict(u)
            try:
                u["hist"] = SAMPLER.peer_history(u["iface"], u["public_key"])[-60:]
            except Exception:
                u["hist"] = []
            users.append(u)
        f["users"] = users
        try:
            f["range_bytes"], f["daily"] = _report_usage(
                days, [x["iface"] for x in s.get("sections") or []])
        except Exception as e:
            log_action("report usage: %r" % e)
    if "tun.view" in perms:
        f["tunnels"] = s.get("tunnels") or []
        f["egress"] = viz_egress_facts()
        try:
            f["events"] = viz_events(now - days * 86400, perms, lang)
        except Exception as e:
            log_action("report events: %r" % e)
    if "audit.view" in perms:
        rows = []
        for r in META.audit_list(since_days=days, limit=2000):
            a = r.get("action") or ""
            rows.append(dict(r, action_text=_t_or("ui.audit.act." + a, a, lang),
                             detail=audit_detail_text(r.get("detail"), lang)))
        f["audit"] = rows
    if "sys.view" in perms:
        f["speed"] = [r for r in META.speedtest_recent(2000) if (r.get("ts") or 0) >= now - days * 86400]
        f["sys"] = {m: _report_metric(m, days) for m in ("cpu", "ram", "disk")}
    return f


def report_xlsx(perms, days, mask, lang):
    """بایت‌های کارپوشه + نامِ فایل."""
    V, R, X = _pkg_module("viz"), _pkg_module("report"), _pkg_module("xlsx")
    data = R.build(report_facts(perms, days, mask, lang), viz_ctx(lang), X, V)
    return data, "wg-report-%s.xlsx" % datetime.now().strftime("%Y%m%d-%H%M")


def viz_model(kind, lang, **kw):
    """مدلِ کاوشگرِ SvgStudio برای یکی از سه نما (همه‌ی هوش همین‌جا و در viz.py)."""
    V, cx = _pkg_module("viz"), viz_ctx(lang)
    if kind == "egress":
        return V.egress_model(viz_egress_facts(), cx)
    if kind == "trace":
        f = viz_trace_facts(kw["iface"], kw["name"], kw.get("can_tun"))
        return None if f is None else V.trace_model(f, cx)
    return V.timeline_model(viz_timeline_facts(kw["hours"], kw["perms"], lang), cx)


# ------------------------------------------------------------- Prometheus

def build_metrics():
    """متریک‌ها به فرمت Prometheus — فقط از کش‌ها و فایل‌های کوچک محلی."""
    s = build_stats()
    now = time.time()
    L = []

    def lv(v):
        # escape ِ مقدارِ برچسب طبقِ فرمتِ exposition: \ " و newline
        return (str(v).replace("\\", "\\\\").replace('"', '\\"')
                .replace("\n", "\\n"))

    def m(name, help_, mtype, rows):
        L.append("# HELP %s %s" % (name, help_))
        L.append("# TYPE %s %s" % (name, mtype))
        for labels, val in rows:
            lbl = ",".join('%s="%s"' % (k, lv(v)) for k, v in labels.items())
            L.append("%s{%s} %s" % (name, lbl, val))

    users = s["users"]
    # شمارنده‌های *_total فقط برای peerهایی که در snapshotِ زنده هستند:
    # صفرِ موقتِ یک peer ِ غایب برای Prometheus «reset» است و rate() آن را
    # دوباره می‌شمارد.
    live_users = [u for u in users if u.get("live", True)]
    m("wg_peer_enabled", "Peer enabled in config (1/0)", "gauge",
      [({"iface": u["iface"], "name": u["name"]}, int(u["enabled"]))
       for u in users])
    m("wg_peer_online", "Handshake fresher than 180s (1/0)", "gauge",
      [({"iface": u["iface"], "name": u["name"]}, int(u["online"]))
       for u in users])
    m("wg_peer_handshake_age_seconds", "Seconds since last handshake (-1 never)",
      "gauge",
      [({"iface": u["iface"], "name": u["name"]},
        int(now - u["handshake"]) if u["handshake"] else -1) for u in users])
    m("wg_peer_receive_bytes_total", "Interface counter since iface start",
      "counter",
      [({"iface": u["iface"], "name": u["name"]}, u["rx"]) for u in live_users])
    m("wg_peer_transmit_bytes_total", "Interface counter since iface start",
      "counter",
      [({"iface": u["iface"], "name": u["name"]}, u["tx"]) for u in live_users])
    m("wg_peer_receive_rate_bytes", "Current receive rate B/s", "gauge",
      [({"iface": u["iface"], "name": u["name"]}, round(u["rx_rate"], 1))
       for u in users])
    m("wg_peer_transmit_rate_bytes", "Current transmit rate B/s", "gauge",
      [({"iface": u["iface"], "name": u["name"]}, round(u["tx_rate"], 1))
       for u in users])
    m("wg_peer_month_usage_bytes", "Accounted usage this month", "gauge",
      [({"iface": u["iface"], "name": u["name"], "dir": d},
        u["month_rx"] if d == "rx" else u["month_tx"])
       for u in users for d in ("rx", "tx")])
    GB = 1024 ** 3
    m("wg_peer_lifetime_usage_bytes", "Accounted usage since the peer was created",
      "counter",
      [({"iface": u["iface"], "name": u["name"], "dir": d},
        u["life_rx"] if d == "rx" else u["life_tx"])
       for u in users for d in ("rx", "tx")])
    m("wg_peer_quota_bytes", "Monthly quota in bytes (0 = unlimited)", "gauge",
      [({"iface": u["iface"], "name": u["name"]},
        int(float(u["quota_gb"]) * GB) if u.get("quota_gb") else 0)
       for u in users])
    m("wg_peer_total_cap_bytes", "Lifetime cap in bytes (0 = none)", "gauge",
      [({"iface": u["iface"], "name": u["name"]},
        int(float(u["total_gb"]) * GB) if u.get("total_gb") else 0)
       for u in users])
    m("wg_peer_speed_limit_bits_per_second", "Speed limit (0 = unlimited)",
      "gauge",
      [({"iface": u["iface"], "name": u["name"]},
        int(u["rate_mbit"]) * 1_000_000 if u.get("rate_mbit") else 0)
       for u in users])

    def _exp_ts(d):
        try:
            return int(datetime.strptime(d, "%Y-%m-%d").timestamp())
        except (ValueError, TypeError):
            return -1
    m("wg_peer_expires_timestamp_seconds",
      "Expiry date as Unix time (-1 = never)", "gauge",
      [({"iface": u["iface"], "name": u["name"]},
        _exp_ts(u["expires"]) if u.get("expires") else -1) for u in users])
    m("wg_peer_auto_disabled", "Disabled by policy (1/0)", "gauge",
      [({"iface": u["iface"], "name": u["name"],
         "reason": u.get("auto_disabled") or "none"},
        int(bool(u.get("auto_disabled")))) for u in users])

    tns = s["tunnels"]
    m("wg_tunnel_active", "Tunnel interface is up (1/0)", "gauge",
      [({"iface": t["iface"]}, int(t["active"])) for t in tns])
    m("wg_tunnel_handshake_age_seconds", "Seconds since last handshake (-1 never)",
      "gauge",
      [({"iface": t["iface"]},
        int(now - t["handshake"]) if t["handshake"] else -1) for t in tns])
    m("wg_tunnel_receive_rate_bytes", "Current receive rate B/s", "gauge",
      [({"iface": t["iface"]}, round(t["rx_rate"], 1)) for t in tns])
    m("wg_tunnel_transmit_rate_bytes", "Current transmit rate B/s", "gauge",
      [({"iface": t["iface"]}, round(t["tx_rate"], 1)) for t in tns])
    m("wg_tunnel_receive_bytes_total", "Interface counter since iface start",
      "counter", [({"iface": t["iface"]}, t["rx"]) for t in tns])
    m("wg_tunnel_transmit_bytes_total", "Interface counter since iface start",
      "counter", [({"iface": t["iface"]}, t["tx"]) for t in tns])

    ifs = s["interfaces"]
    m("net_interface_receive_bytes_total", "Total received bytes (/proc/net/dev)",
      "counter", [({"iface": i["iface"], "role": i["role"]}, i["rx_total"])
                  for i in ifs])
    m("net_interface_transmit_bytes_total",
      "Total transmitted bytes (/proc/net/dev)", "counter",
      [({"iface": i["iface"], "role": i["role"]}, i["tx_total"]) for i in ifs])
    m("net_interface_receive_rate_bytes", "Current receive rate B/s", "gauge",
      [({"iface": i["iface"]}, round(i["rx_rate"], 1)) for i in ifs])
    m("net_interface_transmit_rate_bytes", "Current transmit rate B/s", "gauge",
      [({"iface": i["iface"]}, round(i["tx_rate"], 1)) for i in ifs])
    m("net_interface_up", "Interface is up (1/0)", "gauge",
      [({"iface": i["iface"]}, int(i["up"])) for i in ifs])

    sysc = ((s.get("sys") or {}).get("cur") or {})
    m("panel_sys_usage_percent", "Host CPU/RAM/disk usage percent", "gauge",
      [({"resource": k}, round(float(sysc[k]), 1))
       for k in ("cpu", "ram", "disk") if isinstance(sysc.get(k), (int, float))])
    try:
        probes = META.svc_probe_all()
    except Exception:
        probes = {}
    m("svc_probe_ok", "Last probe of a restricted service succeeded (1/0)",
      "gauge",
      [({"service": svc, "iface": ifc}, int(bool(r.get("ok"))))
       for (svc, ifc), r in sorted(probes.items())])
    m("svc_probe_latency_seconds", "Last probe latency", "gauge",
      [({"service": svc, "iface": ifc}, round(float(r["latency_ms"]) / 1000, 3))
       for (svc, ifc), r in sorted(probes.items())
       if isinstance(r.get("latency_ms"), (int, float))])
    hb = health_report()
    m("panel_thread_alive", "Background thread heartbeat within its limit (1/0)",
      "gauge", [({"thread": n}, int(t["ok"])) for n, t in sorted(hb["threads"].items())])
    L.append("# HELP wg_panel_uptime_seconds Seconds since the panel started")
    L.append("# TYPE wg_panel_uptime_seconds gauge")
    L.append("wg_panel_uptime_seconds %d" % hb["uptime"])
    for name, help_, mtype, rows in nqmo_metric_rows(
            nqmo_state(now), {(u["iface"], u["name"]) for u in users}):
        m(name, help_, mtype, rows)
    m("wg_panel_build_info", "Build id (first 12 hex of sha256 of wg_panel.pyz)",
      "gauge", [({"version": BUILD_ID}, 1)])
    L.append("# HELP wg_panel_up Panel is serving")
    L.append("# TYPE wg_panel_up gauge")
    L.append("wg_panel_up 1")
    return "\n".join(L) + "\n"


# ------------------------------------------------------- صفحه‌ی اشتراک

# کلیدهایی که JSِ خودِ صفحه‌ی اشتراک در زمانِ اجرا می‌سازد. مثلِ پنلِ اصلی از
# راهِ یک شیءِ JSON تزریق می‌شوند، نه جایگزینیِ متنی — تا نقلِ‌قول یا بک‌اسلشِ
# ترجمه نتواند نحوِ اسکریپت را بشکند.
_SHARE_JS_KEYS = ("ui.share.month", "ui.share.quota", "ui.share.budget",
                  "ui.share.budgetabove", "ui.share.linkuntil",
                  "ui.share.acctexp", "ui.share.copied")
_SHARE_CACHE = {}


def share_page_tmpl(lang):
    """قالبِ صفحه‌ی اشتراک برای یک زبان — یک بار ساخته و کش می‌شود.

    ترتیبِ گام‌ها عمدی است و مثلِ render_page: اول نشانه‌های ترجمه، آخر
    __PAYLOAD__ (در render_share_page). داده‌ی کاربر — نامِ دستگاه و خودِ
    کانفیگ — هرگز نباید دوباره به‌عنوانِ نشانه‌ی ⟦…⟧ خوانده شود.
    """
    page = _SHARE_CACHE.get(lang)
    if page is not None:
        return page
    page = _TOKEN_RE.sub(lambda m: _esc_html(t(m.group(1), lang)), SHARE_HTML)
    page = page.replace("__LANG__", LANG_HTML[lang])
    page = page.replace("__DIR__", LANG_DIR[lang])
    # گزینشگرِ زبان: گیرنده‌ی لینک کاربرِ پنل نیست و هیچ راهِ دیگری برای
    # عوض‌کردنِ زبان ندارد. نامِ هر زبان به خطِ خودش می‌ماند.
    nav = " · ".join(
        ("<b>%s</b>" % _esc_html(LANG_LABEL[c])) if c == lang
        else '<a href="?lang=%s">%s</a>' % (c, _esc_html(LANG_LABEL[c]))
        for c in LANGS)
    page = page.replace("__LANGNAV__", nav)
    boot = "var _T=%s,_FA=%s;" % (
        json.dumps({k: t(k, lang) for k in _SHARE_JS_KEYS},
                   ensure_ascii=False).replace("</", "<\\/"),
        "true" if lang == "fa" else "false")
    page = page.replace("__SHARE_BOOTSTRAP__", boot)
    _SHARE_CACHE[lang] = page
    return page


def render_share_page(res, usage=None, lang=None):
    """صفحه‌ی مستقل اشتراک کانفیگ (بدون احراز هویت). داده با json.dumps
    امن تزریق می‌شود و qr.js از همان مسیر پنل بارگذاری می‌شود.
    usage: مصرفِ همان peer برای نمایش به کاربرِ نهایی (اختیاری).
    lang: زبانِ مذاکره‌شده‌ی همان درخواست (?lang= ← کوکیِ wgl ←
    Accept-Language) — این صفحه سشن ندارد، پس زبانش فقط از مرورگر می‌آید."""
    payload = json.dumps({"name": res["name"], "ip": res["ip"],
                          "conf": res["client_conf"],
                          "link_expires": int(res.get("link_expires") or 0),
                          "expires": res.get("expires") or "",
                          "usage": usage or None}, ensure_ascii=False)
    # سخت‌گیری: جلوگیری از شکستن تگ <script> حتی اگر داده‌ای غیرمنتظره باشد
    payload = (payload.replace("<", "\\u003c").replace(">", "\\u003e")
               .replace("&", "\\u0026"))
    lang = lang if lang in _LANG_IDX else DEFAULT_LANG
    return share_page_tmpl(lang).replace("__PAYLOAD__", payload)


def _with_fonts(html):
    """data-URI ِ فونتِ Vazirmatn را برمی‌گرداند — همان بایت‌هایی که پیش‌تر درونِ رشته بود."""
    for w in ("400", "700"):
        b64 = base64.b64encode(_pkg_bytes("web/fonts/vazirmatn-%s.woff2" % w)).decode("ascii")
        html = html.replace("__FONT_VAZIRMATN_%s__" % w, b64)
    return html


# منبع: wgpanel/web/share.html
SHARE_HTML = _with_fonts(_pkg_text("web/share.html"))


# ------------------------------------------------------------------- HTML/JS

# منبع: wgpanel/web/page.html. هیچ f-string ای در کار نیست و همه‌ی داده‌ها از /api
# می‌آیند؛ تنها جایگزینیِ زمانِ بارگذاری، نشانه‌های فونت (__FONT_VAZIRMATN_*__) است.
PAGE_HTML = _with_fonts(_pkg_text("web/page.html"))

# نسخه‌ی vendorشده‌ی three.js — دو فایل gzip کنار پنل: three.module.min.js.gz و
# three.core.min.js.gz (importِ نسبیِ core از داخل module). URL نسخه‌دار است تا
# کش immutable امن باشد؛ با ارتقا باید این ثابت و TV3D_THREE_URL در PAGE_HTML
# با هم عوض شوند (تستِ test_tv3d همگامی را قفل می‌کند).
# ⚠️ با تعویضِ فایل‌های vendorشده **این را هم عوض کن** — تستی هر سه گوشه را
# به هم گره زده (این ثابت · URL ِ داخلِ PAGE_HTML · خودِ بایت‌ها).
# چرا مهم است: روتِ vendor این URL ِ نسخه‌دار را با کشِ `immutable` سرو
# می‌کند، پس ثابتِ کهنه یعنی مرورگر بایت‌های تازه را زیرِ نسخه‌ی قدیمی
# **برای همیشه** نگه می‌دارد. شکل هم دو جور است: انتشارِ three.js «r180»
# است و این‌جا شکلِ npm ِ «0.180.0» — نگاشت عمدی است.
THREE_VER = "0.180.0"

# ------------------------------------------------------------------ tv3d.mjs
# ماژول صحنه‌ی سه‌بعدی نمای TV. جدا از PAGE_HTML سرو می‌شود تا فقط هنگام ورود
# به اسلاید «شبکه (سه‌بعدی)» بارگیری شود و صفحه‌ی اصلی سنگین نشود.
#
# طراحی (نتیجه‌ی تحلیل three.js برای این پنل):
#   - داده‌ی جغرافیایی جعل نمی‌شود: سرور در مرکز، هر اینترفیس WG یک حلقه‌ی
#     مداری، هر کاربر گره‌ای روی حلقه‌ی اینترفیس خودش، تونل‌ها بیرونی‌ترین حلقه.
#   - جریان ذرات = نرخ لحظه‌ای (RX از سرور به گره، TX برعکس)؛ تراکم/سرعت با
#     لگاریتم نرخ فشرده می‌شود تا اختلاف چند مرتبه‌ای خوانا بماند.
#   - متن فارسی در WebGL رندر نمی‌شود (شکل‌دهی حروف/نیم‌فاصله) — برچسب‌ها DOM.
#   - render فقط وقتی اسلاید فعال و تب دیده می‌شود؛ dispose کامل هنگام خروج
#     (forceContextLoss تا GPU همان لحظه آزاد شود، نه با GC).
#   - prefers-reduced-motion: بدون چرخش خودکار و با ذرات کم/آهسته.
# منبع: wgpanel/web/tv3d.mjs
TV3D_JS = _pkg_text("web/tv3d.mjs")

# ------------------------------------------------------- SvgStudio (نقشه و گزارش)
# موتورِ عمومیِ نمودار (svgstudio.js/css)، چسبِ صفحه (studio.js) و svg-pan-zoom ِ
# vendorشده. سه فایلِ اول URL ِ بی‌نسخه دارند ⇒ همان no-store ِ پیش‌فرض (با هر استقرار
# عوض می‌شوند)؛ vendor نسخه‌دار است ⇒ کشِ immutable. هیچ‌کدام CDN نمی‌خواهد (air-gap).
SVGPANZOOM_VER = "3.6.1"
STUDIO_ASSETS = {
    "/svgstudio.js": ("web/svgstudio.js", "text/javascript; charset=utf-8", False),
    "/svgstudio.css": ("web/svgstudio.css", "text/css; charset=utf-8", False),
    "/studio.js": ("web/studio.js", "text/javascript; charset=utf-8", False),
    "/vendor/svg-pan-zoom-%s.min.js" % SVGPANZOOM_VER:
        ("web/vendor/svg-pan-zoom-%s.min.js" % SVGPANZOOM_VER, "text/javascript; charset=utf-8", True),
}
STUDIO_BYTES = {k: _pkg_bytes(v[0]) for k, v in STUDIO_ASSETS.items()}


# ------------------------------------------------------------------ HTTP سرور

def _json_finite(obj):
    """کپیِ obj با جای‌گذاریِ float ِ غیرمتناهی → None (برای json.dumps)."""
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {k: _json_finite(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_finite(v) for v in obj]
    return obj


class Handler(BaseHTTPRequestHandler):
    server_version = "wg-panel"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # ساکت؛ لاگ اقدامات جدا نوشته می‌شود

    # --- کمکی‌ها
    # فشرده‌سازیِ پاسخ. مصرفِ اصلی /api/stats است که هر ۲ ثانیه برای هر
    # تبِ باز فرستاده می‌شود. سطحِ ۱ عمدی است نه ۶: این مسیر داغ است و
    # بازدهِ سطوحِ بالاتر ناچیز.
    _GZIP_MIN = 1024          # زیرِ این، سربارِ هدر از صرفه‌جویی بیشتر است
    _GZIP_TYPES = ("application/json", "text/html", "text/plain",
                   "text/css", "application/javascript", "text/javascript")

    def _send(self, code, body, ctype="application/json; charset=utf-8",
              extra_headers=None):
        data = body if isinstance(body, bytes) else body.encode()
        # فشرده‌سازی فقط وقتی هر چهار شرط برقرار باشد. شرطِ چهارم —
        # نبودِ Content-Encoding در extra_headers — همان چیزی است که
        # جلوی دوباره‌فشرده‌شدنِ فایل‌های .gz ِ vendor و /api/backup را
        # می‌گیرد؛ چشم از رویش می‌پرد.
        # پیش از send_response است تا Content-Length ِ پایین‌تر خودبه‌خود
        # طولِ فشرده را ببیند.
        self._responded = True
        enc = None
        if (len(data) >= self._GZIP_MIN
                and ctype.split(";")[0].strip() in self._GZIP_TYPES
                and not (extra_headers and "Content-Encoding" in extra_headers)
                and "gzip" in (self.headers.get("Accept-Encoding") or "")):
            data = gzip.compress(data, compresslevel=1)
            enc = "gzip"
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if enc:
            self.send_header("Content-Encoding", enc)
            # بدونِ Vary، واسطه‌ای می‌تواند بدنه‌ی فشرده را به کلاینتی
            # بدهد که نخواسته — به‌ویژه چون فایل‌های vendor کشِ بلند دارند.
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(data)))
        # اگر هندلر تصمیم گرفته اتصال را ببندد (بدنه‌ی بیش‌ازحد بزرگ که
        # تخلیه‌اش نمی‌ارزد)، HTTP/1.1 می‌خواهد که اعلام شود — وگرنه
        # کلاینت اتصال را قابلِ استفاده می‌پندارد و درخواستِ بعدی‌اش
        # روی سوکتِ بسته می‌رود.
        if self.close_connection:
            self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        # پیش‌فرض no-store؛ فایل‌های استاتیک نسخه‌دار (vendor) override می‌کنند
        if not (extra_headers and "Cache-Control" in extra_headers):
            self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if CONFIG.get("tls_cert"):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        if ctype.startswith("text/html"):
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                # وزیرمتن به‌صورتِ data: داخلِ CSS جاسازی شده؛ بدونِ font-src
                # مرورگر به default-src 'self' می‌افتد و فونت را رد می‌کند.
                "font-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _msg(self, v, lang):
        """کلیدِ api.* (ساده یا خروجیِ aerr) را به متنِ زبانِ درخواست می‌برد.

        هرچه کلید نباشد دست‌نخورده برمی‌گردد، پس پیامِ خامِ سیستم (خروجیِ
        wg، متنِ خطای OS) و رشته‌های دادهٔ معمولی از این مسیر سالم رد می‌شوند.
        """
        return api_text(v, lang)

    def _json(self, obj, code=200, extra_headers=None):
        # فقط دو خانهٔ پیام‌رسان ترجمه می‌شوند، نه کلِ payload — /api/stats هر
        # ۲ ثانیه صدا زده می‌شود و پیمایشِ بازگشتیِ آن هزینهٔ بی‌دلیل است.
        if isinstance(obj, dict) and ("error" in obj or "message" in obj):
            lang = self._lang()
            obj = dict(obj)
            for k in ("error", "message"):
                if k in obj:
                    obj[k] = self._msg(obj[k], lang)
        try:
            data = json.dumps(obj, ensure_ascii=False, allow_nan=False)
        except ValueError:
            # NaN/Infinity در JSON معتبر نیست و JSON.parse ِ مرورگر رد می‌کند.
            # پارسرها ورودی را می‌گیرند؛ این تورِ آخر است تا یک مقدارِ
            # محاسباتی همه‌ی پاسخ را نشکند.
            log_action("json: non-finite number replaced with null")
            data = json.dumps(_json_finite(obj), ensure_ascii=False)
        self._send(code, data, extra_headers=extra_headers)

    def _query_lang(self):
        """زبانِ صریحاً خواسته‌شده در ?lang= — یا None اگر نبود/نامعتبر بود."""
        for part in (urlparse(self.path).query or "").split("&"):
            if part.startswith("lang="):
                return norm_lang(part[5:])
        return None

    def _lang(self):
        """زبانِ این درخواست.

        ترتیبِ اولویت: ?lang= صریح ← کوکیِ wgl ← Accept-Language ← پیش‌فرض.
        عمداً به سشن گره نخورده تا صفحهٔ ورود و صفحهٔ اشتراک — که هیچ‌کدام
        کاربرِ واردشده ندارند — هم زبانِ درست بگیرند.
        """
        want = self._query_lang()
        if want:
            return want
        c = SimpleCookie(self.headers.get("Cookie", ""))
        if "wgl" in c:
            code = norm_lang(c["wgl"].value)
            if code:
                return code
        return (lang_from_accept(self.headers.get("Accept-Language", ""))
                or DEFAULT_LANG)

    def _lang_cookie_header(self, lang):
        return ("wgl=%s; Path=/; Max-Age=31536000; SameSite=Strict" % lang)

    def _session(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        if "wgs" not in c:
            return None
        sess = verify_session_cookie(c["wgs"].value)
        if sess is None:
            return None
        # محدودیتِ IP اختصاصیِ کاربر، روی همه‌ی درخواست‌ها (نه فقط ورود)
        user = find_user(sess["u"])
        if user is None or not user_ip_ok(user, self._client_ip()):
            return None
        return sess

    def _authed(self):
        return self._session() is not None

    def _is_admin(self):
        # نقش از verify_session_cookie همیشه رکورد فعلیِ کاربر است
        s = self._session()
        return bool(s) and s.get("r") == "admin"
        # (verify_session_cookie مقدار r را از user["role"] فعلی می‌گذارد)

    def _can(self, perm):
        """RBAC: کاربرِ سشنِ فعلی مجوزِ perm را دارد؟ (نقش زنده خوانده می‌شود؛
        کاربری که TOTPِ الزامی را هنوز فعال نکرده هیچ مجوزی ندارد.)"""
        s = self._session()
        if not s:
            return False
        u = find_user(s["u"])
        if u is None or user_needs_totp(u):
            return False
        return perm in user_perms(u)

    def _deny_ip(self):
        """True اگر IP مجاز نباشد (پاسخ 403 هم می‌فرستد)."""
        if ip_allowed(self._client_ip()):
            return False
        self._json({"ok": False, "error": "api.err.auth.ip_denied"}, 403)
        return True

    # سقفِ تخلیه: بدنه‌ی کمی بزرگ‌تر از حد را می‌خوانیم و دور می‌ریزیم تا
    # اتصال قابلِ استفاده بماند؛ بدنه‌ی خیلی بزرگ ارزشِ خواندن ندارد و
    # اتصال بسته می‌شود. ۱MB انتخابی است: به‌اندازه‌ی جذبِ کلاینتی که کمی
    # از سقفِ ۶۴KB ِ JSON رد شده، و کوچک‌تر از آنکه تخلیه گران شود.
    DRAIN_MAX = 1024 * 1024

    # نگهبانِ «بدنه بیش‌ازحد بزرگ» — شیءِ یکتا، نه None و نه False.
    # ‏None از قبل معنیِ «JSON خراب» را دارد و تنها فراخواننده صریحاً
    # `is None` می‌سنجد؛ برگرداندنِ False آنجا به «بدنه‌ی خالیِ معتبر»
    # خوانده می‌شد — بدتر از خودِ باگ.
    BODY_TOO_LARGE = object()

    def _drain_body(self, n):
        """بدنه را تا سقف بخوان و دور بریز. True یعنی اتصال سالم ماند.

        تکه‌تکه (۶۴KB) خوانده می‌شود تا کلاینتِ خصمانه نتواند سرور را به
        تخصیصِ یک‌جای حافظه وادار کند.
        """
        if n <= 0:
            return True
        if n > self.DRAIN_MAX:
            return False
        left = n
        try:
            while left > 0:
                chunk = self.rfile.read(min(65536, left))
                if not chunk:
                    return False          # کلاینت زودتر بست
                left -= len(chunk)
        except OSError:
            return False
        return True

    def _body_json(self):
        """بدنه‌ی JSON. None یعنی نامعتبر، BODY_TOO_LARGE یعنی بیش‌ازحد بزرگ.

        🪤 پیش از این بدنه‌ی بزرگ **خوانده نمی‌شد**: بایت‌های نخوانده در
        بافرِ سوکت می‌ماندند و چون protocol_version روی HTTP/1.1 است،
        اتصال keep-alive می‌ماند و خواندنِ بعدی — که منتظرِ خطِ درخواست
        است — همان بایت‌ها را می‌خورد. نتیجه: اتصالِ ناهم‌گام، پاسخِ
        بی‌معنا یا هنگ، و کاربری که می‌گوید «پنل الکی از کار افتاد».
        """
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        if n < 0:
            # rfile.read(-1) یعنی «تا EOF»: نخِ درخواست تا وقتی کلاینت اتصال
            # را باز نگه دارد گیر می‌ماند — یک هدر، یک نخِ قفل‌شده. طولِ
            # منفی بدنه‌ای ندارد که بشود تخلیه کرد؛ اتصال بسته می‌شود.
            self.close_connection = True
            return None
        if n > 65536:
            if not self._drain_body(n):
                self.close_connection = True
            return self.BODY_TOO_LARGE
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, OSError):
            return None
        # هر مسیر body.get(...) می‌زند؛ آرایه/رشته/عدد به‌جای شیء تا این‌جا
        # AttributeError می‌داد و اتصال بی‌پاسخ بسته می‌شد (حتی در /api/login
        # بدونِ احراز هویت).
        return body if isinstance(body, dict) else None

    def _client_ip(self):
        """IP ِ کلاینت — با پشتیبانی از reverse proxy ِ **مورداعتماد**.

        بدونِ CONFIG["trusted_proxies"] همان peer ِ سوکت است. اگر peer در
        فهرست باشد، آخرین hop ِ نامعتمدِ X-Forwarded-For (یا X-Real-IP)
        گرفته می‌شود؛ وگرنه پشتِ nginx/caddy همه 127.0.0.1 می‌شدند:
        allowlist و rate-limit یک سطلِ مشترک، تأییدِ تلگرام دور می‌خورد و
        fail2ban هیچ‌کس را نمی‌بست. هدر از کلاینتِ مستقیم هرگز خوانده
        نمی‌شود (جعل).
        """
        return client_ip_from(self.client_address[0], self.headers)

    def _is_https(self):
        return request_is_https(self.client_address[0], self.headers)

    def _pw_confirm(self, user, pw):
        """تأییدِ رمزِ کاربرِ واردشده، زیرِ همان بودجه‌ی per-account ِ ورود.

        True/False، یا None اگر بودجه تمام است (فراخوان ۴۲۹ می‌دهد).
        /api/totp/setup، /api/totp/disable، /api/password و رمزِ تأییدِ هر
        دو مسیرِ بازیابی رمز را بی‌هیچ سقفی می‌سنجیدند:
        کسی با کوکیِ دزدیده یا مرورگرِ رهاشده می‌توانست رمز را بی‌نهایت حدس
        بزند — دقیقاً چیزی که محدودیتِ ورود جلویش را گرفته بود. بودجه با
        ورود مشترک است: حدس از هر در از همان سهم کم می‌کند.
        """
        u = user["username"]
        if not login_user_allowed(u):
            return None
        ok = check_user_password(user, pw)
        (login_user_succeeded if ok else login_user_failed)(u)
        return ok

    def _session_cookie_header(self, user):
        cookie = make_session_cookie(user)
        secure = "; Secure" if self._is_https() else ""
        return ("wgs=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d%s"
                % (cookie, SESSION_TTL, secure))

    def _audit(self, category, action, target, detail, ok=True, actor=None):
        s = self._session()
        who = actor or (s["u"] if s else "?")
        audit(who, category, action, target, detail, self._client_ip(), ok)

    def _guarded(self, fn):
        """هر استثنای ناگرفته‌ی یک مسیر → ۵۰۰ ِ JSON + لاگ، نه اتصالِ بی‌پاسخ.

        BaseHTTPRequestHandler استثنا را به process_request_thread می‌رساند
        که فقط traceback به stderr می‌نویسد؛ کلاینت هیچ پاسخی نمی‌گرفت و
        اپراتور «پنل الکی از کار افتاد» می‌دید. قطعِ اتصال از سمتِ کلاینت
        (BrokenPipe/Reset) خطای ما نیست و بی‌صدا رد می‌شود.
        """
        self._responded = False
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            self.close_connection = True
        except Exception as e:
            log_action("unhandled %s %s: %s: %s"
                       % (self.command, urlparse(self.path).path,
                          type(e).__name__, str(e)[:200]))
            # بدنه‌ی نخوانده ممکن است در سوکت مانده باشد؛ اتصال قابلِ
            # اعتماد نیست.
            self.close_connection = True
            if not self._responded:
                try:
                    self._json({"ok": False, "error": "api.err.internal"},
                               500)
                except OSError:
                    pass

    def do_GET(self):
        self._guarded(self._do_get)

    def do_POST(self):
        self._guarded(self._do_post)

    # --- GET
    def _do_get(self):
        path = urlparse(self.path).path
        # لینک اشتراک: بدون احراز هویت و بدون allowlist (برای کاربر راه دور)
        # ولی محدودیت نرخ، توکن هش‌شده، انقضای کوتاه و ۴۰۴ عمومی دارد.
        if path.startswith("/s/"):
            ip = self._client_ip()
            if not share_rate_ok(ip):
                self._send(429, t("ui.share.ratelimit", self._lang()),
                           "text/plain; charset=utf-8")
                return
            token = path[3:]
            res = resolve_share(token)
            lang = self._lang()
            if res is None:
                self._send(404, _esc_html(t("ui.share.invalid", lang)),
                           "text/html; charset=utf-8")
                return
            # مصرفِ همان peer برای بخشِ «مصرف اینترنت شما» — خطا نباید
            # خودِ صفحه‌ی کانفیگ را بشکند
            usage = None
            try:
                blk = next((b for b in parse_user_blocks(res["iface"])
                            if b["name"] == res["name"]), None)
                pub = blk["public_key"] if blk else ""
                if pub:
                    mrx, mtx = SAMPLER.month_usage.get(
                        (res["iface"], pub), (0, 0))
                    meta = SAMPLER.meta_cache.get(
                        (res["iface"], res["name"]), {}) or {}
                    usage = {"rows": META.usage_series(
                                 res["iface"], pub, "30d"),
                             "month": mrx + mtx,
                             "quota_gb": meta.get("quota_gb") or 0}
                    res["expires"] = meta.get("expires") or ""
            except Exception as e:
                log_action("share usage error: %r" % e)
            self._send(200, render_share_page(res, usage, lang),
                       "text/html; charset=utf-8",
                       extra_headers={"Referrer-Policy": "no-referrer",
                                      "X-Robots-Tag": "noindex"})
            return
        if path == "/api/health":
            # سلامتِ نخ‌ها: با توکنِ metrics (برای مانیتورینگِ بیرونی، مثلِ
            # healthcheck ِ docker) یا نشستِ دارای sys.view. ۵۰۳ اگر نخی مرده.
            if self._deny_ip():
                return
            auth = self.headers.get("Authorization", "")
            token = CONFIG.get("metrics_token", "")
            if not (token and hmac.compare_digest(auth, "Bearer " + token)):
                if self._perm_denied(path):
                    return
            rep_ = health_report()
            # ok همان healthy است: ۵۰۳ با ok:true به کلاینت‌هایی که فقط
            # بدنه را می‌خوانند (قاعده‌ی بقیه‌ی API) «سالم» می‌گفت.
            self._json(dict(rep_, healthy=rep_["ok"]),
                       200 if rep_["ok"] else 503)
            return
        if path == "/metrics":
            # توکن جدا برای Prometheus (بدون کوکی)؛ 127.0.0.1 مثل بقیه allowlist
            if self._deny_ip():
                return
            auth = self.headers.get("Authorization", "")
            token = CONFIG.get("metrics_token", "")
            if not (token and hmac.compare_digest(auth, "Bearer " + token)):
                self._json({"ok": False, "error": "unauthorized"}, 401)
                return
            self._send(200, build_metrics(),
                       "text/plain; version=0.0.4; charset=utf-8")
            return
        if self._deny_ip():
            return
        if path == "/":
            lang = self._lang()
            # فقط وقتی زبان صریحاً با ?lang= خواسته شده کوکی ست می‌شود؛
            # تشخیصِ خودکار از Accept-Language انتخابِ کاربر نیست و نباید
            # به‌جای او تثبیت شود.
            hdrs = ({"Set-Cookie": self._lang_cookie_header(lang)}
                    if self._query_lang() else None)
            self._send(200, render_page(lang), "text/html; charset=utf-8",
                       hdrs)
        elif path == "/qr.js":
            try:
                with open(os.path.join(BASE_DIR, "qr.js"), "rb") as f:
                    self._send(200, f.read(),
                               "application/javascript; charset=utf-8")
            except OSError:
                self._json({"ok": False, "error": "not found"}, 404)
        elif path.startswith("/vendor/three-"):
            # three.js vendorشده (pinned؛ بدون CDN — سازگار با air-gap). فقط
            # نسخه‌ی gzip روی دیسک است تا حجم مخزن/بکاپ کم بماند. URL نسخه‌دار
            # است پس کشِ immutable امن است و importِ نسبیِ three.core از داخلِ
            # three.module هم خودکار به همین مسیرِ نسخه‌دار می‌رود.
            base = "/vendor/three-%s/" % THREE_VER
            fn = {base + "three.module.min.js": "three.module.min.js.gz",
                  base + "three.core.min.js": "three.core.min.js.gz"}.get(path)
            gz = None
            if fn:
                try:
                    with open(os.path.join(BASE_DIR, fn), "rb") as f:
                        gz = f.read()
                except OSError:
                    gz = None
            if gz is None:
                self._json({"ok": False, "error": "not found"}, 404)
                return
            hdrs = {"Cache-Control": "public, max-age=31536000, immutable",
                    "Vary": "Accept-Encoding"}
            if "gzip" in (self.headers.get("Accept-Encoding") or ""):
                hdrs["Content-Encoding"] = "gzip"
                self._send(200, gz, "text/javascript; charset=utf-8",
                           extra_headers=hdrs)
            else:
                # کلاینت بدون gzip (نادر) — در حافظه باز می‌شود (wbits=31: فقط gzip)
                self._send(200, zlib.decompress(gz, 31),
                           "text/javascript; charset=utf-8",
                           extra_headers=hdrs)
        elif path in STUDIO_ASSETS:
            _rel, ctype, immutable = STUDIO_ASSETS[path]
            self._send(200, STUDIO_BYTES[path], ctype, extra_headers=(
                {"Cache-Control": "public, max-age=31536000, immutable"} if immutable else None))
        elif path == "/tv3d.mjs":
            # ماژول صحنه‌ی سه‌بعدی نمای TV — جدا از PAGE_HTML تا فقط با ورود
            # به اسلاید «شبکه (سه‌بعدی)» بارگیری شود، نه در هر بازشدن صفحه
            self._send(200, TV3D_JS, "text/javascript; charset=utf-8")
        elif path == "/api/stats":
            sess = self._session()
            if sess is None:
                self._json({"ok": False, "error": "unauthorized"}, 401)
                return
            u = find_user(sess["u"])
            need2fa = user_needs_totp(u)
            perms = set() if need2fa else user_perms(u)
            me = {"username": sess["u"], "role": sess.get("r", "viewer"),
                  "totp": bool(u and u.get("totp")),
                  "perms": sorted(perms), "need_totp": need2fa,
                  "protected": is_protected_admin(sess["u"])}
            # WG-NQMO: فقط با پرچمِ روشن — با پرچمِ خاموش پاسخ بایت‌به‌بایت همان قبلی است
            # و رابط هیچ نشانی از آن نمی‌سازد (سندِ ۰۵ ِ طرح، §۵٫۱)
            if nqmo_enabled():
                me["nqmo"] = True
            d = build_stats()
            d["me"] = me
            # RBAC: هر بخشی که کاربر مجوزِ دیدنش را ندارد از پاسخ حذف می‌شود
            if "wg.view" not in perms:
                d["users"], d["sections"] = [], []
                d["server"] = {"rx_rate": 0, "tx_rate": 0}
            if "tun.view" not in perms:
                d["tunnels"] = []
            if "net.view" not in perms:
                d["interfaces"] = []
                d["net_totals"] = {"rx_rate": 0, "tx_rate": 0,
                                   "rx_total": 0, "tx_total": 0}
            if "sys.view" not in perms:
                d["sys"] = None
            if "settings.ips" in perms:
                d["allow_ips"] = CONFIG.get("allow_ips", [])
            self._json(d)
        elif path == "/api/log":
            if self._perm_denied(path):
                return
            lines = []
            try:
                with open(ACTION_LOG, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()[-300:]
            except OSError:
                pass
            self._json({"ok": True, "lines": lines})
        elif path == "/api/audit":
            if self._perm_denied(path):
                return
            qs = urlparse(self.path).query
            from urllib.parse import parse_qs
            p = parse_qs(qs)
            cat = (p.get("category") or ["all"])[0]
            actor = (p.get("actor") or [""])[0] or None
            q = (p.get("q") or [""])[0] or None
            days = (p.get("days") or [""])[0]
            since = int(days) if days.isdigit() else None
            rows = META.audit_list(category=cat, actor=actor, q=q,
                                   since_days=since, limit=800)
            lang = self._lang()
            for r in rows:
                r["detail"] = audit_detail_text(r.get("detail"), lang)
            self._json({"ok": True, "rows": rows,
                        "actors": META.audit_actors()})
        elif path == "/api/svc/status":
            if self._perm_denied(path):
                return
            self._json({"ok": True, "status": build_svc_status()})
        elif path == "/api/backup/status":
            if self._perm_denied(path):
                return
            st = backup_full_status()
            # خطای S4 داخلِ یک dict ِ تو در تو است و _json فقط error ِ سطحِ
            # بالا را ترجمه می‌کند. کپی، چون همین dict در _S4_CACHE می‌ماند.
            lang = self._lang()
            s4 = {k: dict(st[k], error=self._msg(st[k].get("error"), lang))
                  for k in ("s4", "s4_full")}
            self._json({"ok": True, "archives": st["archives"],
                        "units": st["units"], "s4": s4["s4"],
                        "s4_full": s4["s4_full"],
                        "manual": manual_backup_state()})
        elif path == "/api/speedtest/status":
            if self._perm_denied(path):
                return
            self._json({"ok": True, "state": dict(SPEEDTEST.state),
                        "server_id": SpeedTester.server_id(),
                        "ifaces": SpeedTester.ifaces(),
                        "cfg_ifaces": list(CONFIG.get("speedtest_ifaces")
                                           or []),
                        "rows": META.speedtest_recent(1200)})
        elif path in ("/api/viz/egress", "/api/viz/trace", "/api/viz/timeline"):
            if self._perm_denied(path):
                return
            from urllib.parse import parse_qs
            p = parse_qs(urlparse(self.path).query)
            lang = self._lang()
            perms = user_perms(find_user(self._session()["u"]))
            if path == "/api/viz/egress":
                X = viz_model("egress", lang)
            elif path == "/api/viz/trace":
                iface = (p.get("iface") or [""])[0]
                name = (p.get("name") or [""])[0]
                X = viz_model("trace", lang, iface=iface, name=name, can_tun="tun.view" in perms)
                if X is None:
                    self._json({"ok": False, "error": aerr("api.err.peer.notfound", v=name)}, 404)
                    return
            elif path == "/api/viz/timeline":
                h = (p.get("hours") or ["24"])[0]
                hours = max(1, min(168, int(h))) if h.isdigit() else 24
                X = viz_model("timeline", lang, hours=hours, perms=perms)
            self._json(X)
        elif path == "/api/report.xlsx":
            if self._perm_denied(path):
                return
            from urllib.parse import parse_qs
            p = parse_qs(urlparse(self.path).query)
            d = (p.get("days") or ["30"])[0]
            days = max(REPORT_DAYS[0], min(REPORT_DAYS[1], int(d))) if d.isdigit() else 30
            # پوشاندنِ endpoint پیش‌فرض است؛ فقط mask=0 ِ صریح بازش می‌کند
            mask = (p.get("mask") or ["1"])[0] != "0"
            perms = user_perms(find_user(self._session()["u"]))
            data, fn = report_xlsx(perms, days, mask, self._lang())
            self._send(200, data,
                       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                       extra_headers={"Content-Disposition": 'attachment; filename="%s"' % fn})
            self._audit("settings", "report.xlsx", "*",
                        adet("ui.audit.det.report.mask" if mask else "ui.audit.det.report", d=days))
        elif path == "/api/backup":
            if self._perm_denied(path):
                return
            data = backup_archive_bytes()
            fn = "wg-panel-backup-%s.tar.gz" % datetime.now().strftime("%Y%m%d-%H%M%S")
            self._send(200, data, "application/gzip", extra_headers={
                "Content-Disposition": 'attachment; filename="%s"' % fn})
            self._audit("settings", "bk.download", "*",
                        adet("ui.audit.det.bkdownload"))
        else:
            self._json({"ok": False, "error": "not found"}, 404)

    # RBAC: نگاشتِ هر endpoint به مجوزِ لازم. مسیرهای «سلف‌سرویس» (حسابِ خودِ
    # کاربر) مجوز نمی‌خواهند. هر مسیرِ /api/ که در هیچ‌کدام نباشد به‌صورتِ
    # پیش‌فرض فقط برای نقشِ admin مجاز است (دفاعِ عمقی برای endpointهای آینده).
    PERM_MAP = {
        # وایرگارد
        "/api/peer/add": "wg.add", "/api/peer/bulk": "wg.add",
        "/api/peer/toggle": "wg.edit", "/api/peer/psk": "wg.edit",
        "/api/peer/rotate": "wg.edit", "/api/peer/ips": "wg.edit",
        "/api/peer/meta": "wg.edit", "/api/peer/delete": "wg.del",
        "/api/peer/conf": "wg.conf", "/api/peer/share": "wg.conf",
        "/api/usage": "wg.view", "/api/usage_matrix": "wg.view",
        "/api/graph/events": "wg.view",
        # تونل‌ها / سرور
        "/api/tunnel/toggle": "tun.toggle",
        "/api/warp/status": "tun.view",
        "/api/net/leak-audit": "net.view",
        "/api/warp/targets": "warp.manage",
        "/api/warp/presets": "warp.manage",
        "/api/warp/preset/toggle": "warp.manage",
        "/api/warp/events": "tun.view",
        "/api/viz/egress": "tun.view", "/api/viz/timeline": "tun.view",
        "/api/viz/trace": "wg.view", "/api/report.xlsx": "wg.view",
        "/api/warp/latency": "tun.view",
        "/api/warp/endpoints/rank": "warp.manage",
        "/api/warp/target/add": "warp.manage",
        "/api/warp/target/del": "warp.manage",
        "/api/warp/test": "warp.manage",
        "/api/warp/quic": "warp.manage",
        "/api/warp/split-series": "tun.view",
        "/api/sys/series": "sys.view", "/api/health": "sys.view",
        # سرویس‌ها
        "/api/svc/status": "svc.view", "/api/svc/probe": "svc.view",
        "/api/svc/mtr": "svc.view", "/api/svc/mtr/history": "svc.view",
        "/api/svc/iplist": "svc.view",
        "/api/svc/add": "svc.edit", "/api/svc/delete": "svc.edit",
        "/api/svc/ip/delete": "svc.edit", "/api/svc/ip/edit": "svc.edit",
        # پروکسی
        "/api/proxy/list": "proxy.view", "/api/proxy/series": "proxy.view",
        "/api/proxy/log": "proxy.view", "/api/proxy/clients": "proxy.view",
        "/api/proxy/dests": "proxy.view",
        "/api/proxy/add": "proxy.add", "/api/proxy/edit": "proxy.edit",
        "/api/proxy/delete": "proxy.del", "/api/proxy/config": "proxy.conf",
        # ممیزی / مدیریت
        "/api/log": "audit.view", "/api/audit": "audit.view",
        "/api/backup/status": "audit.view",
        "/api/speedtest/status": "sys.view",
        "/api/speedtest/run": "svc.edit",
        "/api/speedtest/cancel": "svc.edit",
        "/api/speedtest/config": "svc.edit",
        "/api/backup": "backup.get", "/api/restore": "backup.restore",
        "/api/backup/run": "backup.get",
        "/api/backup/versions": "backup.restore",
        "/api/backup/cloud-restore": "backup.restore",
        "/api/settings/allowlist": "settings.ips",
        "/api/alerts/get": "alerts.manage", "/api/alerts/save": "alerts.manage",
        "/api/report/config": "alerts.manage", "/api/report/test": "alerts.manage",
        "/api/alerts/test": "alerts.manage",
        "/api/bot/get": "bot.manage", "/api/bot/save": "bot.manage",
        "/api/ecmp/get": "ecmp.manage", "/api/ecmp/save": "ecmp.manage",
        # WG-NQMO (P5) — خواندن با nqmo.view؛ هر فرمان مجوزِ جدای خودش
        "/api/nqmo/status": "nqmo.view", "/api/nqmo/peer": "nqmo.view",
        "/api/nqmo/events": "nqmo.view", "/api/nqmo/ack": "nqmo.ack",
        "/api/nqmo/probe": "nqmo.probe", "/api/nqmo/mode": "nqmo.manage",
    }
    # مسیرهای حسابِ خودِ کاربر — برای هر کاربرِ واردشده آزادند
    SELF_PATHS = ("/api/login", "/api/logout", "/api/stats", "/api/password",
                  "/api/totp/setup", "/api/totp/confirm", "/api/totp/disable")
    # وقتی TOTPِ الزامیِ نقش هنوز فعال نشده، فقط این‌ها مجازند
    TOTP_SETUP_PATHS = ("/api/login", "/api/logout", "/api/stats",
                        "/api/totp/setup", "/api/totp/confirm")

    @classmethod
    def required_perm(cls, path):
        """مجوزِ لازمِ مسیر؛ None یعنی یا سلف‌سرویس است یا نگاشت ندارد."""
        if path in cls.PERM_MAP:
            return cls.PERM_MAP[path]
        if path.startswith("/api/users/") or path.startswith("/api/roles/"):
            return "users.manage"
        return None

    def _perm_denied(self, path):
        """گیتِ مرکزیِ RBAC؛ True یعنی پاسخِ خطا فرستاده شد."""
        sess = self._session()
        if sess is None:
            self._json({"ok": False, "error": "unauthorized"}, 401)
            return True
        user = find_user(sess["u"])
        if user_needs_totp(user) and path not in self.TOTP_SETUP_PATHS:
            self._json({"ok": False,
                        "error": "api.err.auth.totp_required_role"},
                       403)
            return True
        need = self.required_perm(path)
        if need is None:
            if path in self.SELF_PATHS or not path.startswith("/api/"):
                return False
            # endpoint بدونِ نگاشت: فقط admin (سازگاری عقب‌رو + پیش‌فرضِ امن)
            if sess.get("r") != "admin":
                self._json({"ok": False,
                            "error": "api.err.auth.admin_only"}, 403)
                return True
            return False
        if need not in user_perms(user):
            self._json({"ok": False,
                        "error": "api.err.auth.role_denied"}, 403)
            return True
        return False

    # --- POST

    def _post_proxy(self, path, body):
        """گروهِ `/api/proxy/*` — True یعنی همین‌جا رسیدگی شد.

        گروهِ دومِ استخراج (پلنِ ۰۶۳). از svc حساس‌تر است — اعتبارنامه‌ی
        پروکسی می‌سازد و حذف می‌کند — و **هفت مجوزِ متفاوت** دارد
        (proxy.view/add/edit/del/conf). هیچ‌کدام در این جابه‌جایی عوض
        نشدند و `PostProxyGroupTests` هر نه مسیر را پین می‌کند.

        گیتِ مجوز پیش از این فراخوانی اجرا شده؛ این‌جا فقط بدنه‌هاست.
        """
        if path == "/api/proxy/list":
            month = datetime.now().strftime("%Y-%m")
            totals = META.proxy_month_totals(month)
            users = []
            for u in META.proxy_users():
                users.append({
                    "username": u["username"], "enabled": bool(u["enabled"]),
                    "auto_disabled": u["auto_disabled"],
                    "rate_kbit": u["rate_kbit"], "quota_gb": u["quota_gb"],
                    "expires": u["expires"], "note": u["note"],
                    "allow_src": u.get("allow_src", ""),
                    "protocol": u.get("protocol", "both"),
                    "noauth": bool(u.get("noauth")),
                    "has_pass": bool(u.get("pass_plain")),
                    "month_bytes": totals.get(u["username"], 0)})
            host = CONFIG.get("server_host") or \
                CONFIG.get("server_endpoint", "").split(":")[0]
            self._json({"ok": True, "users": users,
                        "info": {"host": host, "port": PROXY_PORT,
                                 "active": PROXY._active()}})
        elif path == "/api/proxy/add":
            username = str(body.get("username", "")).strip()
            if not valid_proxy_user(username):
                self._json({"ok": False, "error": "api.err.proxy.name_format"})
                return True
            if META.proxy_user_get(username):
                self._json({"ok": False, "error": "api.err.user.exists"})
                return True
            noauth = bool(body.get("noauth"))
            srcs, serr = parse_allow_src(body.get("allow_src"))
            if serr:
                self._json({"ok": False, "error": serr})
                return True
            # کاربرِ بدونِ‌رمز: IP مبدأ اجباری + بدونِ تداخل با کاربرِ بدونِ‌رمزِ دیگر
            if noauth:
                if not srcs:
                    self._json({"ok": False, "error": "api.err.proxy.nopw_needs_ip_open"})
                    return True
                clash = proxy_noauth_src_conflict(srcs)
                if clash:
                    self._json({"ok": False, "error": aerr("api.err.proxy.ip_clash", user=clash)})
                    return True
                pw, ph = "", ""
            else:
                pw = str(body.get("password", "")).strip()
                if not pw:
                    pw = secrets.token_urlsafe(9)
                elif len(pw) < 4:
                    self._json({"ok": False, "error": "api.err.proxy.pw_short4"})
                    return True
                ph = proxy_hash(pw)
                if not ph:
                    self._json({"ok": False, "error": "api.err.proxy.hash_failed"})
                    return True
            quota, expires, err = parse_quota_expires(
                body.get("quota_gb"), body.get("expires"))
            if err:
                self._json({"ok": False, "error": err})
                return True
            try:
                rate = int(body.get("rate_kbit") or 0)
            except (TypeError, ValueError):
                rate = 0
            rate = max(0, min(rate, 10_000_000))
            proto = str(body.get("protocol", "both"))
            if proto not in ("http", "https", "both"):
                proto = "both"
            META.proxy_user_upsert(username, {
                "pass_hash": ph, "rate_kbit": rate,
                "quota_gb": quota or 0, "expires": expires or "",
                "enabled": 1, "note": str(body.get("note", ""))[:120],
                "allow_src": ",".join(srcs), "pass_plain": pw,
                "protocol": proto, "noauth": 1 if noauth else 0})
            PROXY.kick()
            self._audit("panel-user", "px.add", username,
                        adet("ui.audit.det.pxadd",
                             auth=("noauth" if noauth else "pw"),
                             rate=rate, quota=(quota or "∞")))
            self._json({"ok": True, "username": username,
                        "password": ("" if noauth else pw), "noauth": noauth,
                        "allow_src": ",".join(srcs), "protocol": proto,
                        "host": (CONFIG.get("server_host") or ""),
                        "port": PROXY_PORT})
        elif path == "/api/proxy/edit":
            username = str(body.get("username", "")).strip()
            u = META.proxy_user_get(username)
            if not u:
                self._json({"ok": False, "error": "api.err.user.notfound"})
                return True
            fields = {}
            quota, expires, err = parse_quota_expires(
                body.get("quota_gb"), body.get("expires"))
            if err:
                self._json({"ok": False, "error": err})
                return True
            fields["quota_gb"] = quota or 0
            fields["expires"] = expires or ""
            srcs, serr = parse_allow_src(body.get("allow_src"))
            if serr:
                self._json({"ok": False, "error": serr})
                return True
            fields["allow_src"] = ",".join(srcs)
            proto = str(body.get("protocol", "both"))
            if proto not in ("http", "https", "both"):
                proto = "both"
            fields["protocol"] = proto
            try:
                fields["rate_kbit"] = max(0, min(
                    int(body.get("rate_kbit") or 0), 10_000_000))
            except (TypeError, ValueError):
                fields["rate_kbit"] = 0
            if "enabled" in body:
                fields["enabled"] = 1 if body.get("enabled") else 0
            # حالتِ بدونِ‌رمز (اگر در بدنه آمده، قابلِ تغییر است)
            noauth = bool(body.get("noauth")) if "noauth" in body \
                else bool(u.get("noauth"))
            newpw = str(body.get("password", "")).strip()
            resp = {"ok": True}
            if noauth:
                if not srcs:
                    self._json({"ok": False, "error": "api.err.proxy.nopw_needs_ip"})
                    return True
                clash = proxy_noauth_src_conflict(srcs, exclude=username)
                if clash:
                    self._json({"ok": False, "error": aerr("api.err.proxy.ip_clash", user=clash)})
                    return True
                fields["noauth"] = 1
                fields["pass_hash"] = ""   # بدونِ‌رمز: رمزی نگه نمی‌داریم
                fields["pass_plain"] = ""
            else:
                fields["noauth"] = 0
                if newpw:
                    if len(newpw) < 4:
                        self._json({"ok": False, "error": "api.err.proxy.pw_short4"})
                        return True
                    ph = proxy_hash(newpw)
                    if not ph:
                        self._json({"ok": False, "error": "api.err.proxy.hash_failed"})
                        return True
                    fields["pass_hash"] = ph
                    fields["pass_plain"] = newpw
                    resp["password"] = newpw
                elif not u.get("pass_hash"):
                    # از بدونِ‌رمز به بارمز تغییر می‌کند ولی رمزی نداده
                    self._json({"ok": False, "error": "api.err.proxy.pw_required"})
                    return True
            META.proxy_user_upsert(username, fields)
            PROXY.kick()
            self._audit("panel-user", "px.edit", username,
                        adet("ui.audit.det.pxedit", rate=fields["rate_kbit"], quota=(quota or "∞")))
            self._json(resp)
        elif path == "/api/proxy/delete":
            username = str(body.get("username", "")).strip()
            if not META.proxy_user_get(username):
                self._json({"ok": False, "error": "api.err.user.notfound"})
                return True
            META.proxy_user_delete(username)
            PROXY.kick()
            self._audit("panel-user", "px.del", username, "")
            self._json({"ok": True})
        elif path == "/api/proxy/series":
            username = str(body.get("username", ""))
            mode = str(body.get("range", "24h"))
            if mode not in ("24h", "7d", "30d", "6m"):
                mode = "24h"
            self._json({"ok": True, "mode": mode, "username": username,
                        "rows": META.proxy_usage_series(username, mode)})
        elif path == "/api/proxy/log":
            self._json({"ok": True, "lines": proxy_recent_log(
                body.get("n", 200))})
        elif path == "/api/proxy/config":
            # کانفیگ/QR یک کاربر (شاملِ رمزِ خام؛ فقط admin — این مسیر gated است).
            u = META.proxy_user_get(str(body.get("username", "")))
            if not u:
                self._json({"ok": False, "error": "api.err.user.notfound"})
                return True
            host = CONFIG.get("server_host") or \
                CONFIG.get("server_endpoint", "").split(":")[0]
            self._json({"ok": True, "username": u["username"],
                        "password": u.get("pass_plain", ""),
                        "noauth": bool(u.get("noauth")),
                        "allow_src": u.get("allow_src", ""),
                        "host": host, "port": PROXY_PORT,
                        "protocol": u.get("protocol", "both")})
        elif path == "/api/proxy/clients":
            # تاریخچه‌ی IP کلاینت‌های یک کاربرِ پروکسی (نگهداری ۶ ماه).
            username = str(body.get("username", ""))
            if not META.proxy_user_get(username):
                self._json({"ok": False, "error": "api.err.user.notfound"})
            else:
                self._json({"ok": True, "username": username,
                            "clients": META.proxy_clients(username)})
        elif path == "/api/proxy/dests":
            # تاریخچه‌ی مقصدهای یک کاربرِ پروکسی (host + سلامت، نگهداری ۶ ماه).
            username = str(body.get("username", ""))
            if not META.proxy_user_get(username):
                self._json({"ok": False, "error": "api.err.user.notfound"})
            else:
                self._json({"ok": True, "username": username,
                            "dests": META.proxy_dests(username)})
        else:
            return False
        return True


    def _post_svc(self, path, body):
        """گروهِ `/api/svc/*` — True یعنی این مسیر همین‌جا رسیدگی شد.

        استخراجِ گروهی (پلنِ ۰۶۳، گامِ ۲) و نه جدولِ کاملِ مسیر:
        `do_POST` ‏۱٬۶۳۵ خط و ۷۶ شاخه بود و ویرایشش مکرر — ولی جدولِ
        کامل هر شاخه را جابه‌جا می‌کند و یک مجوزِ بدرونویسی‌شده هیچ
        نشانه‌ای در زمانِ کامپایل ندارد. این شکل بیشترِ سود را با کسری
        از ریسک می‌دهد، و مهم‌تر: **معناشناسیِ مسیرِ نگاشت‌نشده را نگه
        می‌دارد** — بازگشتِ False یعنی زنجیره ادامه پیدا کند و در نهایت
        همان ۴۰۴ ِ قبلی بیفتد، نه ۴۰۴ ِ زودهنگام.

        گیتِ مجوز و همه‌ی گام‌های پیش‌گیت **پیش از** این فراخوانی اجرا
        شده‌اند؛ این‌جا فقط بدنه‌ی شاخه‌هاست.
        """
        if path == "/api/svc/probe":
            # اجرای فوریِ یک دور تشخیص (فقط اطلاعاتی؛ بدون تغییر مسیر).
            if SVCDIAG.running:
                self._json({"ok": True, "already": True})
            else:
                threading.Thread(target=SVCDIAG.cycle, daemon=True).start()
                self._audit("settings", "svc.probe", "*",
                            adet("ui.audit.det.svcprobe"))
                self._json({"ok": True, "started": True})
        elif path == "/api/svc/mtr":
            # نمودار مسیر (mtr) یک سرویس از دلِ خروجی — فقط اطلاعاتی, SSRF-safe.
            service = str(body.get("service", ""))
            iface = str(body.get("iface", "")) or (detect_user_exit() or "")
            res = svc_mtr(service, iface)
            self._json(res)
        elif path == "/api/svc/mtr/history":
            # روندِ ۶ماهه‌ی کیفیتِ مسیر (rtt/jitter/loss/mos) برای نمودار/مقایسه.
            service = str(body.get("service", ""))
            iface = str(body.get("iface", "")) or (detect_user_exit() or "")
            if service not in svc_services():
                self._json({"ok": False, "error": "api.err.svc.invalid"}, 400)
            else:
                self._json({"ok": True, "service": service, "iface": iface,
                            "runs": META.mtr_history(service, iface)})
        elif path == "/api/svc/add":
            # افزودنِ سرویسِ سفارشی از یک دامنه (ضدِ SSRF؛ فقط دامنه‌ی عمومی).
            domain = str(body.get("domain", ""))
            label = str(body.get("label", ""))
            key, err = svc_add_custom(domain, label)
            if err:
                self._json({"ok": False, "error": err}, 400)
            else:
                SVCDIAG.kick()   # یک دورِ فوری تا سرویسِ تازه سریع داده بگیرد
                self._audit("settings", "svc.add", key,
                            adet("ui.audit.det.customdomain", domain=domain))
                self._json({"ok": True, "key": key})
        elif path == "/api/svc/delete":
            # حذفِ یک سرویس از پایش (ماندگار در config) + پاک‌سازیِ داده‌هایش.
            service = str(body.get("service", ""))
            if service not in svc_services():
                self._json({"ok": False, "error": "api.err.svc.invalid"}, 400)
            else:
                custom = CONFIG.get("svc_custom")
                with config_txn() as cfg:
                    if isinstance(custom, dict) and service in custom:
                        del custom[service]           # سرویسِ سفارشی
                        cfg["svc_custom"] = custom
                    else:
                        cfg["svc_services"] = [     # سرویسِ پیش‌فرض
                            k for k in svc_services()
                            if k != service and k in SVC_DEFAULTS]
                META.svc_purge_service(service)
                self._audit("settings", "svc.del", service,
                            adet("ui.audit.det.svcremoved"))
                self._json({"ok": True})
        elif path == "/api/svc/iplist":
            # فهرست IPهای یک سرویس برای مدیریت (ویرایش/حذف).
            service = str(body.get("service", ""))
            if service not in svc_services():
                self._json({"ok": False, "error": "api.err.svc.invalid"}, 400)
            else:
                self._json({"ok": True, "service": service,
                            "ips": META.svc_resolved_list(service)})
        elif path == "/api/svc/ip/delete":
            # حذفِ یک IP از موجودیِ سرویس (اطلاعاتی؛ بدون اثر بر مسیریابی).
            service = str(body.get("service", ""))
            ip = str(body.get("ip", ""))
            if service not in svc_services():
                self._json({"ok": False, "error": "api.err.svc.invalid"}, 400)
            elif not _is_valid_ip(ip):
                self._json({"ok": False, "error": "api.err.svc.ip_invalid"}, 400)
            else:
                n = META.svc_resolved_delete(service, ip)
                self._audit("settings", "svc.ip.del", service,
                            adet("ui.audit.det.ipremoved", ip=ip, svc=service), n > 0)
                self._json({"ok": n > 0,
                            "error": None if n else "api.err.svc.ip_notfound"})
        elif path == "/api/svc/ip/edit":
            # ویرایشِ یک IP در موجودیِ سرویس (اطلاعاتی).
            service = str(body.get("service", ""))
            old_ip = str(body.get("old", ""))
            new_ip = str(body.get("new", ""))
            if service not in svc_services():
                self._json({"ok": False, "error": "api.err.svc.invalid"}, 400)
            elif not (_is_valid_ip(old_ip) and _is_valid_ip(new_ip)):
                self._json({"ok": False, "error": "api.err.svc.ip_invalid"}, 400)
            else:
                ok = META.svc_resolved_rename(service, old_ip, new_ip)
                self._audit("settings", "svc.ip.edit", service,
                            adet("ui.audit.det.ipedited", old=old_ip, new=new_ip, svc=service), ok)
                self._json({"ok": ok,
                            "error": None if ok else "api.err.svc.old_ip_notfound"})
        else:
            return False
        return True


    def _post_nqmo(self, path, body):
        """گروهِ `/api/nqmo/*` (WG-NQMO، P5) — True یعنی همین‌جا رسیدگی شد.

        سه خواندن از state ِ کش‌شده و سه فرمان از ctl.sock. گیتِ مجوز پیش از
        این اجرا شده؛ nqmo.detail فقط محتوا را گسترده‌تر می‌کند. هر فرمان
        audit و log_action دارد، رد شده یا پذیرفته.
        """
        if path not in ("/api/nqmo/status", "/api/nqmo/peer", "/api/nqmo/events",
                        "/api/nqmo/ack", "/api/nqmo/probe", "/api/nqmo/mode"):
            return False
        sess = self._session()
        if sess is None:
            self._json({"ok": False, "error": "unauthorized"}, 401)
            return True
        if not nqmo_enabled():
            # disabled: کدِ پایدار برای رابط (پیام ترجمه می‌شود، پس قابلِ مقایسه نیست)
            self._json({"ok": False, "error": "api.err.nqmo.disabled", "disabled": True})
            return True
        detail = "nqmo.detail" in user_perms(find_user(sess["u"]))
        who = sess["u"]
        if path == "/api/nqmo/status":
            self._json({"ok": True, "nqmo": nqmo_status_doc(nqmo_state(), detail,
                                                             nqmo_panel_peers())})
        elif path == "/api/nqmo/peer":
            known = nqmo_panel_peers()
            lab = nqmo_pick_peer(known, body.get("name"), body.get("iface"))
            if lab is None:
                self._json({"ok": False, "error": "api.err.nqmo.no_peer"})
            else:
                self._json({"ok": True, "peer": nqmo_peer_doc(nqmo_state(), lab, detail,
                                                              known)})
        elif path == "/api/nqmo/events":
            since, limit = body.get("since", 0), body.get("limit", NQMO_EVENTS_MAX)
            if (type(since) is not int or since < 0 or type(limit) is not int
                    or not 0 < limit <= NQMO_EVENTS_MAX):
                self._json({"ok": False, "error": "api.err.nqmo.bad_page"})
                return True
            self._json({"ok": True, "events": nqmo_events(nqmo_state(), since, limit,
                                                          detail, nqmo_panel_peers())})
        elif path == "/api/nqmo/ack":
            did = body.get("id")
            if type(did) is not int or not 0 < did < 1 << 53:
                self._json({"ok": False, "error": "api.err.nqmo.bad_id"})
                return True
            r = nqmo_ctl({"v": 1, "op": "ack", "id": did, "actor": who})
            self._nqmo_done(r, "nqmo.ack", str(did), "ack #%d" % did)
        elif path == "/api/nqmo/probe":
            name = body.get("name")
            known = nqmo_panel_peers()
            lab = nqmo_pick_peer(known, name, body.get("iface"))
            if lab is None:
                self._json({"ok": False, "error": "api.err.nqmo.no_peer"})
                return True
            # موتور پیر را فقط با نام پیدا می‌کند ⇒ نامِ تکراری در پنل هرگز فرستاده نمی‌شود
            if sum(1 for k in known if k[1] == lab[1]) != 1:
                r = {"ok": False, "refused": "AMBIGUOUS_PEER"}
            else:
                r = nqmo_ctl({"v": 1, "op": "probe", "peer": lab[1], "actor": who})
            self._nqmo_done(r, "nqmo.probe", "%s/%s" % lab, "probe %s/%s" % lab)
        elif path == "/api/nqmo/mode":
            to = body.get("to")
            if to is None:
                r = nqmo_ctl({"v": 1, "op": "mode.get"})
                self._json(r if r["ok"] else {"ok": False, "error": "api.err.nqmo.refused",
                                              "refused": r["refused"]})
                return True
            if to not in NQMO_MODES:
                self._json({"ok": False, "error": "api.err.nqmo.bad_mode"})
                return True
            cur = nqmo_ctl({"v": 1, "op": "mode.get"})
            if not cur["ok"] or "mode" not in cur:
                r = cur if not cur["ok"] else {"ok": False, "refused": "BAD_REPLY"}
            elif abs(NQMO_MODES.index(cur["mode"]) - NQMO_MODES.index(to)) != 1:
                r = {"ok": False, "refused": "NOT_ADJACENT"}    # موتور هم همین را می‌سنجد
            else:
                r = nqmo_ctl({"v": 1, "op": "mode.set", "to": to, "actor": who})
            self._nqmo_done(r, "nqmo.mode", to, "mode -> %s" % to)
        else:
            return False
        return True

    def _nqmo_done(self, r, action, target, what):
        """پاسخ و ثبتِ یکسانِ هر فرمانِ nqmo: audit + log_action، پذیرفته یا رد."""
        sess = self._session()
        code = None if r["ok"] else r["refused"]
        log_action("nqmo %s by %s: %s" % (what, sess["u"] if sess else "?",
                                           "ok" if r["ok"] else "refused " + code))
        self._audit("settings", action, target,
                    "" if r["ok"] else adet("ui.audit.det.nqmorefused", code=code),
                    ok=r["ok"])
        self._json(r if r["ok"] else {"ok": False, "error": "api.err.nqmo.refused",
                                      "refused": code})

    def _post_warp(self, path, body):
        """گروهِ `/api/warp/*` — True یعنی همین‌جا رسیدگی شد.

        گروهِ سومِ استخراج (پلنِ ۰۶۳): بیشترین شاخه (۱۲) با کوچک‌ترین
        بدنه‌ها. **دو سطحِ مجوز** دارد و مرزشان معنادار است — خواندنِ
        وضعیت `tun.view` ولی هر تغییری `warp.manage`، چون این‌ها مسیرِ
        دادهٔ زنده را عوض می‌کنند. `PostWarpGroupTests` همان مرز را پین
        می‌کند.
        """
        # sess در do_POST یک متغیرِ محلی است و با استخراجِ این گروه جا ماند؛
        # بدونِ این خط هر شاخه‌ای که sess می‌خواند NameError می‌داد — از جمله
        # وضعیتِ WARP، که بخشِ WARP را برای همیشه روی «در حال بارگذاری» نگه
        # می‌داشت. do_POST پیش از رسیدن به این‌جا نشست را تأیید کرده است.
        sess = self._session()
        if sess is None:
            # فقط در مسابقه با حذف/غیرفعال‌شدنِ کاربر وسطِ درخواست
            self._json({"ok": False, "error": "unauthorized"}, 401)
            return True
        if path == "/api/warp/status":
            # روت با tun.view باز است؛ داده‌ی شخصی جدا گیت می‌شود
            # (رجوع به warp_status_redacted).
            self._json({"ok": True, "warp": warp_status_redacted(
                warp_status(force=bool(body.get("force"))),
                user_perms(find_user(sess["u"])))})
        elif path == "/api/warp/split-series":
            self._json({"ok": True,
                        "series": warp_split_series(str(body.get("range", "24h")))})
        elif path == "/api/warp/targets":
            self._json({"ok": True, "targets": warp_targets_read(),
                        "min_prefix": WARP_MIN_PREFIX})
        elif path == "/api/warp/presets":
            self._json({"ok": True, "presets": warp_presets_status()})
        elif path == "/api/warp/events":
            self._json({"ok": True, "events": warp_events_read(40)})
        elif path == "/api/warp/latency":
            self._json({"ok": True, "latency": warp_latency_series()})
        elif path == "/api/warp/endpoints/rank":
            # سنجشِ زنده (ping به کلِ استخر) — چند ثانیه طول می‌کشد
            self._json({"ok": True, "rank": warp_rank_endpoints()})
        elif path == "/api/warp/preset/toggle":
            pid = str(body.get("id", ""))
            enable = bool(body.get("enable"))
            ok, msg, aok = warp_preset_apply(pid, enable, sess["u"])
            if not ok:
                self._json({"ok": False, "error": msg})
                return True
            log_action("warp preset %s=%s by %s (apply=%s)"
                       % (pid, enable, sess["u"], "ok" if aok else msg))
            warp_event("preset_on" if enable else "preset_off", pid, sess["u"])
            self._audit("settings",
                        "warp.preset.on" if enable else "warp.preset.off",
                        pid, msg if aok else adet("ui.audit.det.applyfail", msg=msg),
                        ok=aok)
            self._json({"ok": True, "applied": aok, "message": msg,
                        "presets": warp_presets_status(),
                        "targets": warp_targets_read()})
        elif path == "/api/warp/target/add":
            raw = str(body.get("target", ""))
            kind, val, err = warp_validate_target(raw)
            if err:
                self._json({"ok": False, "error": err})
                return True
            with _WARP_TARGETS_LOCK:       # read+write یک‌جا، نه گم‌شدنِ تغییرِ هم‌زمان
                cur = warp_targets_read()
                if val in cur:
                    self._json({"ok": False, "error": "api.err.warp.target_exists"})
                    return True
                ok, werr = warp_targets_write(cur + [val], sess["u"])
            if not ok:
                self._json({"ok": False, "error": werr})
                return True
            aok, msg = warp_apply()
            log_action("warp target added: %s by %s (apply=%s)"
                       % (val, sess["u"], "ok" if aok else msg))
            warp_event("target_add", val, sess["u"])
            self._audit("settings", "warp.target.add", val,
                        msg if aok else adet("ui.audit.det.applyfail", msg=msg), ok=aok)
            self._json({"ok": True, "value": val, "kind": kind,
                        "applied": aok, "message": msg,
                        "targets": warp_targets_read()})
        elif path == "/api/warp/target/del":
            val = str(body.get("target", "")).strip().lower()
            with _WARP_TARGETS_LOCK:
                cur = warp_targets_read()
                if val not in cur:
                    self._json({"ok": False, "error": "api.err.warp.target_missing"})
                    return True
                rest = [t for t in cur if t != val]
                if not rest:
                    self._json({"ok": False, "error": "api.err.warp.target_last"})
                    return True
                ok, werr = warp_targets_write(rest, sess["u"])
            if not ok:
                self._json({"ok": False, "error": werr})
                return True
            aok, msg = warp_apply()
            log_action("warp target removed: %s by %s (apply=%s)"
                       % (val, sess["u"], "ok" if aok else msg))
            warp_event("target_del", val, sess["u"])
            self._audit("settings", "warp.target.del", val,
                        msg if aok else adet("ui.audit.det.applyfail", msg=msg), ok=aok)
            self._json({"ok": True, "applied": aok, "message": msg,
                        "targets": warp_targets_read()})
        elif path == "/api/warp/test":
            # probe یک دامنه/IP از مسیرِ WARP و مقایسه با مسیرِ عادی
            raw = str(body.get("target", ""))
            ok, res = warp_probe_target(raw)
            self._json({"ok": ok, "error": None if ok else res,
                        "result": res if ok else None})
        elif path == "/api/warp/quic":
            want = bool(body.get("block"))
            try:
                if want:
                    if os.path.exists(WARP_QUIC_OFF):
                        os.remove(WARP_QUIC_OFF)
                else:
                    open(WARP_QUIC_OFF, "w").close()
            except OSError as e:
                self._json({"ok": False, "error": aerr("api.err.warp.quic_io", detail=repr(e))})
                return True
            aok, msg = warp_apply()
            log_action("warp QUIC block=%s by %s (apply=%s)"
                       % (want, sess["u"], "ok" if aok else msg))
            warp_event("quic", adet("ui.audit.det.blocked") if want else adet("ui.audit.det.unblocked"), sess["u"])
            self._audit("settings", "warp.quic", "",
                        adet("ui.audit.det.blocked") if want else adet("ui.audit.det.unblocked"))
            self._json({"ok": aok, "error": None if aok else msg,
                        "block": not os.path.exists(WARP_QUIC_OFF)})
        else:
            return False
        return True

    def _do_post(self):
        path = urlparse(self.path).path
        if self._deny_ip():
            return
        # دفاع دوم در برابر CSRF (اولی SameSite=Strict است)
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc != self.headers.get("Host", ""):
            self._json({"ok": False, "error": "bad origin"}, 403)
            return

        # بازیابی بکاپ: بدنه‌ی خام (تا ۵۰MB) + تأیید رمز؛ جدا از JSON
        if path == "/api/restore":
            sess = self._session()
            if self._perm_denied(path):
                return
            # بازیابی فقط برای حسابِ اصلیِ admin (هم‌ارزِ «مالک» در ربات) —
            # حتی ادمین‌های دیگر هم نه؛ چون بازیابی می‌تواند peer/کانفیگ‌ها را
            # به گذشته برگرداند و ردِ خرابکاری را پاک کند.
            if not is_protected_admin(sess["u"]):
                self._audit("settings", "bk.restore", "",
                            adet("ui.audit.det.adminonly"), ok=False)
                self._json({"ok": False, "error": "api.err.restore.owner_only"},
                           403)
                return
            me = find_user(sess["u"])
            pw = self.headers.get("X-Confirm-Password", "")
            pw_ok = self._pw_confirm(me, pw) if me else False
            if not pw_ok:
                # بدنه (تا ۵۰MB) خوانده نشده؛ اتصال باید بسته شود وگرنه
                # بایت‌هایش درخواستِ بعدیِ همین اتصال را ناهم‌گام می‌کنند.
                self.close_connection = True
                if pw_ok is None:
                    self._json({"ok": False, "error": "api.err.auth.rate"},
                               429)
                    return
                self._audit("settings", "bk.restore", "*",
                            adet("ui.audit.det.badconfirmpw"), ok=False)
                self._json({"ok": False, "error": "api.err.auth.totp_bad"}, 403)
                return
            try:
                n = int(self.headers.get("Content-Length", 0))
            except ValueError:
                n = 0
            if n <= 0 or n > 50 * 1024 * 1024:
                # ۵۰MB برای تخلیه زیادی است — اتصال بسته می‌شود. بدونِ
                # این، بایت‌های نخوانده درخواستِ بعدیِ همان اتصال را
                # ناهم‌گام می‌کردند و اپراتور آن را به «بازیابیِ
                # نیمه‌انجام‌شده» نسبت می‌داد. close_connection **پیش از**
                # _json ست می‌شود تا هدرِ Connection: close با پاسخ برود.
                self.close_connection = True
                self._json({"ok": False, "error": "api.err.bk.big"}, 413)
                return
            raw = self.rfile.read(n)
            if self.headers.get("X-Dry-Run") == "1":
                # پیش‌نمایش: هیچ‌چیز نوشته نمی‌شود، فقط طرحِ تغییرات
                ok, res = restore_from_tar(raw, dry_run=True)
                self._json({"ok": ok, "error": None if ok else res,
                            "plan": res if ok else None})
                return
            ok, msg = restore_from_tar(raw)
            self._audit("settings", "bk.restore", "*", msg, ok=ok)
            self._json({"ok": ok, "error": None if ok else msg,
                        "message": msg if ok else None})
            return

        body = self._body_json()
        if body is self.BODY_TOO_LARGE:
            # ۴۱۳ جدا از ۴۰۰: کاربر باید بداند مشکل «بزرگ است» بوده نه
            # «JSON خراب» — پیش از این هر دو یک پاسخِ عمومی می‌گرفتند.
            self._json({"ok": False, "error": "api.err.body.big"}, 413)
            return
        if body is None:
            self._json({"ok": False, "error": "bad request"}, 400)
            return

        if path == "/api/login":
            ip = self._client_ip()
            if not login_allowed(ip):
                self._json({"ok": False,
                            "error": "api.err.auth.rate"}, 429)
                return
            _uname = str(body.get("username", "admin")).strip()
            # پس از معلوم‌شدنِ نام و **پیش از** مقایسه‌ی رمز: حسابِ بسته
            # نباید هیچ کارِ هشینگی خرج کند. per-IP جدا و دست‌نخورده
            # می‌ماند؛ این مکملش است نه جایگزینش.
            if not login_user_allowed(_uname):
                self._json({"ok": False, "error": "api.err.auth.rate"}, 429)
                return
            user = find_user(_uname)
            pw = str(body.get("password", ""))
            if user and not user.get("hash"):
                # هشِ خالی (راه‌اندازیِ اول / بازیابی): اولین رمزِ واردشده به‌عنوان
                # رمزِ جدید ثبت می‌شود و کاربر وارد می‌گردد. پس از این، هش دیگر
                # خالی نیست و این مسیر بسته می‌شود.
                if not pw:
                    self._json({"ok": False,
                                "error": "api.err.auth.set_first_pw"},
                               401)
                    return
                with config_txn():
                    user["salt"] = secrets.token_hex(16)
                    user["hash"] = hash_password(pw, user["salt"])
                    user["pbkdf2_iters"] = PBKDF2_ITERS
                    user["stoken"] = secrets.token_hex(8)
                log_action("initial password SET user=%s from %s"
                           % (user["username"], ip))
                audit(user["username"], "auth", "auth.pw.initial", "",
                      adet("ui.audit.det.pwbootstrap"), ip, True)
                pw_ok = True
            else:
                # زمان‌بندی ثابت: کاربر ناموجود هم یک هش ساختگی اجرا می‌کند
                pw_ok = check_user_password(user, pw) if user \
                    else bool(hash_password(pw, _DUMMY_SALT)) and False
            if user and pw_ok:
                # RBAC: وضعیتِ حساب فقط بعد از رمزِ درست بررسی/افشا می‌شود
                if not user.get("active", True):
                    login_failed(ip)
                    audit(user["username"], "auth", "auth.login.fail", "",
                          adet("ui.audit.det.accdisabled"), ip, False)
                    self._json({"ok": False,
                                "error": "api.err.auth.acct_disabled"}, 403)
                    return
                if user_expired(user):
                    login_failed(ip)
                    audit(user["username"], "auth", "auth.login.fail", "",
                          adet("ui.audit.det.accexpired"), ip, False)
                    self._json({"ok": False,
                                "error": "api.err.auth.acct_expired"}, 403)
                    return
                if not user_ip_ok(user, ip):
                    login_failed(ip)
                    audit(user["username"], "auth", "auth.login.fail", "",
                          adet("ui.audit.det.badip"), ip, False)
                    self._json({"ok": False,
                                "error": "api.err.auth.ip_denied_user"}, 403)
                    return
                if user.get("totp"):
                    code = str(body.get("totp", "")).strip()
                    if not code:
                        # رمز درست بود؛ این مرحله‌ی طبیعیِ ورودِ دومرحله‌ای است،
                        # نه تلاشِ ناموفق — جا پس داده می‌شود.
                        login_succeeded(ip)
                        login_user_succeeded(user["username"])
                        self._json({"ok": False, "totp_required": True,
                                    "error": "api.err.auth.totp_needed"})
                        return
                    # totp_consume بعد از verify: کد باید هم درست باشد
                    # هم **تازه**. بدونش، کدِ دیده‌شده تا ۹۰ ثانیه
                    # دوباره کار می‌کند و عاملِ دوم عاملِ دوم نیست.
                    #
                    # نتیجه یک بار حساب و نگه داشته می‌شود. شاخه‌ی ردِ پایین
                    # قبلاً دوباره فقط totp_verify را می‌پرسید؛ کدِ تکراری
                    # verify را پاس می‌کند و consume را نه، پس از هر دو
                    # شاخه رد می‌شد و ورود **موفق** بود — یعنی همان replay
                    # که consume برای بستنش آمده بود.
                    totp_ok = (totp_verify(user["totp"], code)
                               and totp_consume(user["username"], code))
                    used_recovery = False
                    if not totp_ok:
                        # کدِ بازیابیِ یک‌بارمصرف به‌جای TOTP
                        with config_txn():
                            used_recovery = totp_recovery_consume(user, code)
                    if used_recovery:
                        left = len(user.get("totp_recovery") or [])
                        log_action("login with TOTP recovery code user=%s "
                                   "from %s (%d left)"
                                   % (user["username"], ip, left))
                        audit(user["username"], "auth", "auth.totp.recovery",
                              "", adet("ui.audit.det.recoveryleft", n=left),
                              ip, True)
                        ALERTS.event("login", A('alert.totp.recovery',
                                                p0=user["username"], p1=ip,
                                                p2=left))
                    elif not totp_ok:
                        login_failed(ip)
                        login_user_failed(user["username"])
                        log_action("login FAILED (totp) user=%s from %s"
                                   % (user["username"], ip))
                        self._json({"ok": False, "totp_required": True,
                                    "error": "api.err.auth.totp_bad"}, 401)
                        return
                # تأییدِ ورود با تلگرام (۲مرحله‌ای)؛ 127.0.0.1 برای دسترسیِ
                # اضطراری (SSH port-forward) این مرحله را دور می‌زند.
                if login2fa_enabled() and ip not in ("127.0.0.1", "::1"):
                    if not request_login_approval(user, ip):
                        log_action("login DENIED (tg 2fa) user=%s from %s"
                                   % (user["username"], ip))
                        audit(user["username"], "auth",
                              "auth.login.denied", "",
                              adet("ui.audit.det.tgdenied"), ip, False)
                        self._json({"ok": False,
                                    "error": "api.err.auth.tg_not_confirmed"},
                                   403)
                        return
                login_succeeded(ip)
                login_user_succeeded(user["username"])
                if pw and rehash_user_password(user, pw):
                    log_action("password hash upgraded user=%s"
                               % user["username"])
                with config_txn():
                    user["last_login"] = int(time.time())
                    user["last_ip"] = ip
                self._json({"ok": True}, extra_headers={
                    "Set-Cookie": self._session_cookie_header(user)})
                log_action("login ok user=%s from %s" % (user["username"], ip))
                audit(user["username"], "auth", "auth.login.ok", "",
                      adet("ui.audit.det.role", role=user["role"]), ip, True)
            else:
                login_failed(ip)
                # فقط شکستِ **اعتبارنامه** به شمارنده‌ی per-account می‌رود.
                # سه ردِ بالاتر (حسابِ غیرفعال/منقضی/IP) بعد از رمزِ درست
                # رخ می‌دهند و سیگنالِ جست‌وجوی رمز نیستند. نامِ ارسالی
                # شمرده می‌شود نه نامِ موجود — هدفِ مهاجم همان است.
                login_user_failed(_uname)
                uname = str(body.get("username", ""))[:32]
                log_action("login FAILED user=%r from %s" % (uname, ip))
                audit(uname or "?", "auth", "auth.login.fail", "",
                      adet("ui.audit.det.badcreds"), ip, False)
                self._json({"ok": False,
                            "error": "api.err.auth.bad_creds"}, 401)
            return

        sess = self._session()
        if sess is None:
            self._json({"ok": False, "error": "unauthorized"}, 401)
            return
        me = find_user(sess["u"])
        if self._perm_denied(path):
            return

        if path == "/api/password":
            # همان بودجه‌ی per-account ِ ورود (رجوع به _pw_confirm)
            pw_ok = self._pw_confirm(me, str(body.get("current", ""))) \
                if me else False
            if pw_ok is None:
                self._json({"ok": False, "error": "api.err.auth.rate"}, 429)
                return
            if not pw_ok:
                log_action("password change FAILED user=%s from %s"
                           % (sess["u"], self._client_ip()))
                self._json({"ok": False, "error": "api.err.auth.cur_pw_bad"})
                return
            ok, msg = set_user_password(me, str(body.get("new", "")))
            if ok:
                log_action("password changed user=%s" % sess["u"])
                self._audit("auth", "auth.pw.change", sess["u"],
                            adet("ui.audit.det.selfpw"))
                # stoken چرخید و کوکی فعلی باطل شد؛ کوکی تازه صادر می‌کنیم
                self._json({"ok": ok, "error": None}, extra_headers={
                    "Set-Cookie": self._session_cookie_header(me)})
            else:
                self._json({"ok": ok, "error": msg})
        elif path == "/api/users/list":
            self._json({"ok": True, "users": [
                {"username": u["username"], "role": u["role"],
                 "role_missing": u["role"] not in BUILTIN_ROLES
                 and u["role"] not in (CONFIG.get("roles") or {}),
                 "totp": bool(u.get("totp")),
                 "need_totp": user_needs_totp(u),
                 "active": u.get("active", True),
                 "expired": user_expired(u),
                 "expires": u.get("expires", ""),
                 "allow_ips": u.get("allow_ips") or [],
                 "tg_chat": u.get("tg_chat", ""),
                 "last_login": u.get("last_login", 0),
                 "last_ip": u.get("last_ip", ""),
                 "protected": is_protected_admin(u["username"]),
                 "me": u["username"] == sess["u"]}
                for u in CONFIG["users"]]})
        elif path == "/api/users/add":
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            role = str(body.get("role", "viewer"))
            if not re.fullmatch(r"[A-Za-z0-9_.\-]{2,32}", username):
                self._json({"ok": False, "error": "api.err.user.name_format"})
                return
            if find_user(username):
                self._json({"ok": False, "error": "api.err.user.exists"})
                return
            if len(password) < 8:
                self._json({"ok": False, "error": "api.err.user.pw_short8"})
                return
            if role not in BUILTIN_ROLES and \
                    role not in (CONFIG.get("roles") or {}):
                self._json({"ok": False, "error": "api.err.user.role_missing"})
                return
            expires = str(body.get("expires", "")).strip()
            if expires and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires):
                self._json({"ok": False, "error": "api.err.user.expiry_format"})
                return
            allow, err = parse_panel_allow_ips(body.get("allow_ips", ""))
            if err:
                self._json({"ok": False, "error": err})
                return
            tg_chat, err = parse_login_chat(body.get("tg_chat", ""))
            if err:
                self._json({"ok": False, "error": err})
                return
            if tg_chat:
                ok, err = verify_login_chat(tg_chat, username)
                if not ok:
                    self._json({"ok": False, "error": err})
                    return
            salt = secrets.token_hex(16)
            with config_txn() as cfg:
                cfg["users"].append({
                    "username": username, "salt": salt,
                    "hash": hash_password(password, salt),
                    "pbkdf2_iters": PBKDF2_ITERS,
                    "role": role, "totp": "", "stoken": secrets.token_hex(8),
                    "active": bool(body.get("active", True)),
                    "expires": expires, "allow_ips": allow,
                    "tg_chat": tg_chat})
            log_action("user %s (%s) added by %s" % (username, role, sess["u"]))
            self._audit("panel-user", "pu.add", username,
                        adet("ui.audit.det.puadd", role=role,
                             exp=(expires or "-"),
                             ips=(",".join(allow) or "-")))
            self._json({"ok": True})
        elif path == "/api/users/edit":
            username = str(body.get("username", ""))
            target = find_user(username)
            if not target:
                self._json({"ok": False, "error": "api.err.user.notfound"})
                return
            if is_protected_admin(username):
                self._json({"ok": False, "error": "api.err.user.admin_no_edit"})
                return
            role = str(body.get("role", target["role"]))
            if role not in BUILTIN_ROLES and \
                    role not in (CONFIG.get("roles") or {}):
                self._json({"ok": False, "error": "api.err.user.role_missing"})
                return
            active = bool(body.get("active", target.get("active", True)))
            expires = str(body.get("expires",
                                   target.get("expires", ""))).strip()
            if expires and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires):
                self._json({"ok": False, "error": "api.err.user.expiry_format"})
                return
            allow, err = parse_panel_allow_ips(
                body.get("allow_ips",
                         ",".join(target.get("allow_ips") or [])))
            if err:
                self._json({"ok": False, "error": err})
                return
            tg_chat, err = parse_login_chat(
                body.get("tg_chat", target.get("tg_chat", "")))
            if err:
                self._json({"ok": False, "error": err})
                return
            # فقط وقتی عوض شده تست کن (تا هر ذخیره یک پیامِ تلگرام نشود)
            if tg_chat and tg_chat != target.get("tg_chat", ""):
                ok, err = verify_login_chat(tg_chat, username)
                if not ok:
                    self._json({"ok": False, "error": err})
                    return
            # خود-قفلی: کاربر نمی‌تواند نقش/وضعیتِ خودش را تغییر دهد
            if username == sess["u"] and (role != target["role"]
                                          or not active):
                self._json({"ok": False, "error": "api.err.user.self_role"})
                return
            # گاردِ آخرین ادمین: نباید بدونِ ادمینِ کاملِ فعال بمانیم
            was_admin = target["role"] == "admin" and user_is_active(target)
            probe = dict(target, role=role, active=active, expires=expires)
            if was_admin and not (probe["role"] == "admin"
                                  and user_is_active(probe)) \
                    and count_active_admins(exclude_username=username) < 1:
                self._json({"ok": False, "error": "api.err.user.last_admin"})
                return
            changes = []          # برای log_action (انگلیسی، فنی)
            ch = {"role": "—", "active": "—", "exp": "—", "ips": "—",
                  "chat": "—", "pw": "0"}   # برای ممیزی (کلیدِ کاتالوگ)
            if role != target["role"]:
                changes.append("role %s->%s" % (target["role"], role))
                ch["role"] = "%s→%s" % (target["role"], role)
            if active != target.get("active", True):
                changes.append("active" if active else "disabled")
                ch["active"] = "1" if active else "0"
                # غیرفعال‌شدن: سشن‌های فعلی فوراً باطل شوند
                if not active:
                    target["stoken"] = secrets.token_hex(8)
            if expires != target.get("expires", ""):
                changes.append("expires %s" % (expires or "removed"))
                ch["exp"] = expires or "∅"
            if allow != (target.get("allow_ips") or []):
                changes.append("allow_ips %s" % (",".join(allow) or "all"))
                ch["ips"] = ",".join(allow) or "*"
            if tg_chat != target.get("tg_chat", ""):
                changes.append("tg_chat %s" % (tg_chat or "default"))
                ch["chat"] = tg_chat or "∅"
            # رمز **پیش از** بقیه‌ی جهش‌ها اعمال می‌شود، چون تنها چیزی است
            # که می‌تواند شکست بخورد. پیش از این، جهش‌ها اول انجام می‌شدند و
            # شکستِ رمز با `return` بی‌ذخیره برمی‌گشت — یعنی CONFIG ِ حافظه
            # جهش‌یافته می‌ماند و فایل نه، تا اولین ذخیره‌ی هر نویسنده‌ی
            # دیگری. پاسخِ کاربر عوض نشده؛ فقط آن حالتِ نیمه‌کاره حذف شده.
            new_pw = str(body.get("password", ""))
            if new_pw:
                ok, msg = set_user_password(target, new_pw)   # خودش تراکنش دارد
                if not ok:
                    self._json({"ok": False, "error": msg})
                    return
                changes.append("password changed")
                ch["pw"] = "1"
            with config_txn():
                target["role"], target["active"] = role, active
                target["expires"], target["allow_ips"] = expires, allow
                target["tg_chat"] = tg_chat
            log_action("user %s edited by %s (%s)"
                       % (username, sess["u"], "; ".join(changes) or "-"))
            self._audit("panel-user", "pu.edit", username,
                        adet("ui.audit.det.puedit", **ch) if changes
                        else adet("ui.audit.det.nochange"))
            self._json({"ok": True})
        elif path == "/api/users/delete":
            username = str(body.get("username", ""))
            target = find_user(username)
            if not target:
                self._json({"ok": False, "error": "api.err.user.notfound"})
                return
            if is_protected_admin(username):
                self._json({"ok": False,
                            "error": "api.err.user.admin_no_delete"})
                return
            if username == sess["u"]:
                self._json({"ok": False, "error": "api.err.user.self_delete"})
                return
            if target["role"] == "admin" \
                    and count_active_admins(exclude_username=username) < 1:
                self._json({"ok": False,
                            "error": "api.err.user.last_admin_delete"})
                return
            with config_txn() as cfg:
                cfg["users"].remove(target)
            log_action("user %s deleted by %s" % (username, sess["u"]))
            self._audit("panel-user", "pu.del", username,
                        adet("ui.audit.det.prevrole", role=target["role"]))
            self._json({"ok": True})
        elif path == "/api/users/reset":
            uname = str(body.get("username", ""))
            target = find_user(uname)
            if not target:
                self._json({"ok": False, "error": "api.err.user.notfound"})
                return
            if is_protected_admin(uname) and uname != sess["u"]:
                self._json({"ok": False, "error": "api.err.user.admin_pw_self"})
                return
            ok, msg = set_user_password(target, str(body.get("password", "")))
            if ok:
                with config_txn():
                    target["totp"] = ""
                    target.pop("totp_recovery", None)
                log_action("user %s password reset by %s"
                           % (target["username"], sess["u"]))
                self._audit("panel-user", "pu.pw.reset",
                            target["username"],
                            adet("ui.audit.det.pwreset"))
            self._json({"ok": ok, "error": None if ok else msg})
        elif path == "/api/roles/list":
            counts = {}
            for u in CONFIG["users"]:
                counts[u["role"]] = counts.get(u["role"], 0) + 1
            roles = [
                {"name": "admin", "builtin": True, "require_totp": False,
                 "perms": sorted(ALL_PERMS), "users": counts.get("admin", 0)},
                {"name": "viewer", "builtin": True, "require_totp": False,
                 "perms": sorted(VIEWER_PERMS),
                 "users": counts.get("viewer", 0)},
            ] + [
                {"name": name, "builtin": False,
                 "require_totp": bool(r.get("require_totp")),
                 "perms": sorted(normalize_perms(r.get("perms", []))),
                 "users": counts.get(name, 0)}
                for name, r in sorted((CONFIG.get("roles") or {}).items())]
            catalog = [{"group": g, "label": lbl,
                        "perms": [{"key": k, "label": pl} for k, pl in items]}
                       for g, lbl, items in PERM_CATALOG]
            self._json({"ok": True, "roles": roles, "catalog": catalog})
        elif path == "/api/roles/save":
            name = str(body.get("name", "")).strip()
            orig = str(body.get("orig", "")).strip()
            if not (2 <= len(name) <= 32) or re.search(r"[\x00-\x1f]", name):
                self._json({"ok": False,
                            "error": "api.err.role.name_len"})
                return
            if name in BUILTIN_ROLES or orig in BUILTIN_ROLES:
                self._json({"ok": False,
                            "error": "api.err.role.builtin_locked"})
                return
            if name == "owner" or orig == "owner":
                # رزرو: وگرنه نقشِ سفارشیِ هم‌نام، owner را قابلِ‌تخصیص می‌کرد
                self._json({"ok": False,
                            "error": "api.err.role.owner_reserved"})
                return
            roles = CONFIG.setdefault("roles", {})
            if orig and orig not in roles:
                self._json({"ok": False, "error": "api.err.role.notfound"})
                return
            if name != orig and name in roles:
                self._json({"ok": False, "error": "api.err.role.name_taken"})
                return
            perms = body.get("perms", [])
            if not isinstance(perms, list) \
                    or not all(isinstance(p, str) for p in perms):
                self._json({"ok": False, "error": "bad request"}, 400)
                return
            bad = [p for p in perms if p not in ALL_PERMS]
            if bad:
                self._json({"ok": False,
                            "error": aerr("api.err.role.unknown_perm",
                                          perm=bad[0])})
                return
            entry = {"perms": sorted(normalize_perms(perms)),
                     "require_totp": bool(body.get("require_totp"))}
            if orig:
                roles.pop(orig, None)
                if name != orig:  # تغییرِ نام: کاربرانِ آن نقش هم منتقل شوند
                    for u in CONFIG["users"]:
                        if u["role"] == orig:
                            u["role"] = name
            with config_txn() as cfg:
                cfg["roles"] = roles
                roles[name] = entry
            log_action("role %r saved by %s (perms=%d, totp=%s)"
                       % (name, sess["u"], len(entry["perms"]),
                          entry["require_totp"]))
            self._audit("panel-user", "role.edit" if orig else "role.add", name,
                        adet("ui.audit.det.roleperms",
                             perms=(", ".join(entry["perms"]) or "-"),
                             totp=("1" if entry["require_totp"] else "0"),
                             was=(orig if orig and orig != name else "-")))
            self._json({"ok": True})
        elif path == "/api/roles/delete":
            name = str(body.get("name", ""))
            if name in BUILTIN_ROLES:
                self._json({"ok": False, "error": "api.err.role.builtin_no_delete"})
                return
            roles = CONFIG.setdefault("roles", {})
            if name not in roles:
                self._json({"ok": False, "error": "api.err.role.notfound"})
                return
            holders = [u["username"] for u in CONFIG["users"]
                       if u["role"] == name]
            if holders:
                self._json({"ok": False, "error": aerr("api.err.role.in_use", count=len(holders),
                                          who=", ".join(holders[:5]))})
                return
            with config_txn() as cfg:
                cfg["roles"] = roles
                del roles[name]
            log_action("role %r deleted by %s" % (name, sess["u"]))
            self._audit("panel-user", "role.del", name, "")
            self._json({"ok": True})
        elif path == "/api/totp/setup":
            # 🪤 تعویضِ عاملِ دوم با یک کوکیِ سرقتی/مرورگرِ رهاشده: وقتی TOTP
            # از قبل فعال است، شروعِ ثبتِ تازه رمزِ فعلی می‌خواهد — همان
            # قاعده‌ای که /api/totp/disable از اول داشت.
            if me and me.get("totp"):
                pw_ok = self._pw_confirm(me, str(body.get("password", "")))
                if pw_ok is None:
                    self._json({"ok": False, "error": "api.err.auth.rate"}, 429)
                    return
                if not pw_ok:
                    self._json({"ok": False, "error": "api.err.auth.pw_bad"},
                               403)
                    return
            secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
            _totp_pending[sess["u"]] = (secret, time.time() + _TOTP_PENDING_TTL)
            uri = ("otpauth://totp/wg-panel:%s?secret=%s&issuer=wg-panel"
                   % (sess["u"], secret))
            self._json({"ok": True, "secret": secret, "uri": uri})
        elif path == "/api/totp/confirm":
            if not me:
                self._json({"ok": False, "error": "unauthorized"}, 401)
                return
            pend = _totp_pending.get(sess["u"])
            if pend and pend[1] < time.time():         # مهلتِ ۱۰ دقیقه گذشت
                _totp_pending.pop(sess["u"], None)
                pend = None
            if not pend:
                self._json({"ok": False, "error": "api.err.totp.setup_first"})
                return
            secret = pend[0]
            _code = str(body.get("code", ""))
            if not (totp_verify(secret, _code)
                    and totp_consume(sess["u"], _code)):     # ← همان دلیلِ ورود
                self._json({"ok": False, "error": "api.err.totp.code_bad"})
                return
            had = bool(me.get("totp"))
            with config_txn():
                me["totp"] = secret
                recovery = totp_recovery_codes(me)
                # عاملِ دوم عوض شد: نشست‌های دیگر (از جمله سشنِ احتمالیِ
                # مهاجم) باطل شوند؛ کوکیِ تازه برای همین مرورگر می‌رود.
                me["stoken"] = secrets.token_hex(8)
            _totp_pending.pop(sess["u"], None)
            log_action("totp %s for %s" % ("replaced" if had else "enabled",
                                           sess["u"]))
            self._audit("auth", "auth.totp.on", sess["u"], "")
            # کدها فقط همین یک بار برمی‌گردند؛ روی دیسک فقط هش هست.
            self._json({"ok": True, "recovery_codes": recovery},
                       extra_headers={
                           "Set-Cookie": self._session_cookie_header(me)})
        elif path == "/api/totp/disable":
            pw_ok = self._pw_confirm(me, str(body.get("password", ""))) \
                if me else False
            if pw_ok is None:
                self._json({"ok": False, "error": "api.err.auth.rate"}, 429)
                return
            if not pw_ok:
                self._json({"ok": False, "error": "api.err.auth.pw_bad"})
                return
            with config_txn():
                me["totp"] = ""
                me.pop("totp_recovery", None)
            log_action("totp disabled for %s" % sess["u"])
            self._audit("auth", "auth.totp.off", sess["u"], "")
            self._json({"ok": True})
        elif path == "/api/settings/allowlist":
            raw = str(body.get("allow_ips", ""))
            entries = [e.strip() for e in re.split(r"[,\n\s]+", raw) if e.strip()]
            for e in entries:
                try:
                    ipaddress.ip_network(e, strict=False)
                except ValueError:
                    self._json({"ok": False, "error": aerr("api.err.allow.value_bad", value=e)})
                    return
            ip = self._client_ip()
            if entries and ip not in ("127.0.0.1", "::1"):
                addr = ipaddress.ip_address(ip)
                if not any(addr in ipaddress.ip_network(e, strict=False)
                           for e in entries):
                    self._json({"ok": False, "error": aerr("api.err.allow.self_excluded", ip=ip)})
                    return
            old = CONFIG.get("allow_ips") or []
            with config_txn() as cfg:
                cfg["allow_ips"] = entries
            log_action("allowlist set to %s by %s" % (entries or "ALL", sess["u"]))
            self._audit("settings", "allow.ip", "",
                        adet("ui.audit.det.fromto",
                             old=(", ".join(old) or "*"),
                             new=(", ".join(entries) or "*")))
            self._json({"ok": True, "allow_ips": entries})
        elif path == "/api/report/config":
            if body.get("set"):
                mode = str(body.get("mode", "off"))
                if mode not in ("off", "daily", "weekly"):
                    mode = "off"
                tstr = str(body.get("time", "10:00"))[:5]
                try:
                    hh, mm = (int(x) for x in tstr.split(":")[:2])
                    tstr = "%02d:%02d" % (hh % 24, mm % 60)
                except (TypeError, ValueError):
                    tstr = "10:00"
                try:
                    dow = int(body.get("dow", 4)) % 7
                except (TypeError, ValueError):
                    dow = 4
                with config_txn() as cfg:
                    cfg["report"] = {"mode": mode, "time": tstr, "dow": dow}
                self._audit("settings", "alert.report", "telegram",
                        adet("ui.audit.det.reportcfg", mode=mode, time=tstr, day=dow))
            self._json({"ok": True, "report": report_cfg()})
        elif path == "/api/report/test":
            def _rpt():
                ok, msg = send_periodic_report()
                log_action("report test: %s (%s)" % (ok, msg))
            threading.Thread(target=_rpt, daemon=True).start()
            self._audit("settings", "alert.report", "telegram",
                        adet("ui.audit.det.testsend"))
            self._json({"ok": True,
                        "message": "api.ok.report.queued"})
        elif path == "/api/alerts/get":
            c = alert_cfg()
            tuns = [i for i in list_tunnel_confs()
                    if systemd_state(i) == "active"]
            self._json({"ok": True, "cfg": {
                "enabled": c["enabled"],
                "has_token": bool(c["bot_token"]),
                "chat_id": c["chat_id"], "iface": c["iface"],
                "events": c["events"], "cpu_pct": c["cpu_pct"],
                "ram_pct": c["ram_pct"], "disk_pct": c["disk_pct"],
                "sustain_min": c["sustain_min"], "quota_pct": c["quota_pct"],
                "expiry_days": c["expiry_days"], "login_fails": c["login_fails"],
                "digest_enabled": c["digest_enabled"],
                "digest_time": c["digest_time"],
                "digest_weekly": c["digest_weekly"],
                "login_2fa": bool((CONFIG.get("login_2fa") or {}).get("enabled"))},
                "event_list": [{"key": k, "label": l} for k, l in ALERT_EVENTS],
                "tunnels": tuns})
        elif path == "/api/alerts/save":
            cur = dict(ALERT_DEFAULTS)
            cur.update(CONFIG.get("alerts") or {})
            tok = str(body.get("bot_token", "")).strip()
            if tok:  # خالی = دست‌نخورده (توکن هیچ‌وقت به کلاینت نرفته)
                cur["bot_token"] = tok
            cur["enabled"] = bool(body.get("enabled"))
            cur["chat_id"] = str(body.get("chat_id", "")).strip()
            cur["iface"] = str(body.get("iface", "")).strip()
            ev = body.get("events") or {}
            if not isinstance(ev, dict):
                self._json({"ok": False, "error": "bad request"}, 400)
                return
            cur["events"] = {k: bool(ev.get(k, True)) for k in ALERT_EVENT_KEYS}
            for k, lo, hi in (("cpu_pct", 1, 100), ("ram_pct", 1, 100),
                              ("disk_pct", 1, 100), ("sustain_min", 1, 120),
                              ("quota_pct", 1, 100), ("expiry_days", 1, 60),
                              ("login_fails", 3, 100)):
                try:
                    cur[k] = max(lo, min(hi, int(body.get(k, cur[k]))))
                except (ValueError, TypeError):
                    pass
            cur["digest_enabled"] = bool(body.get("digest_enabled"))
            cur["digest_weekly"] = bool(body.get("digest_weekly"))
            dt = str(body.get("digest_time", cur["digest_time"])).strip()
            if re.fullmatch(r"\d{1,2}:\d{2}", dt):
                cur["digest_time"] = dt
            if cur["enabled"] and not (cur["bot_token"] and cur["chat_id"]):
                self._json({"ok": False, "error": "api.err.alert.need_token_chat"})
                return
            # تپِ تأیید را نخِ long-pollِ ربات پردازش می‌کند؛ با رباتِ خاموش
            # هیچ ورودی تأیید نمی‌شود و همه (جز 127.0.0.1) قفل می‌شوند.
            if body.get("login_2fa") and not bot_cfg()["enabled"]:
                self._json({"ok": False, "error": "api.err.alert.need_bot_for_2fa"})
                return
            with config_txn() as cfg:
                cfg["alerts"] = cur
                cfg["login_2fa"] = {"enabled": bool(body.get("login_2fa"))}
            log_action("alerts config saved by %s (enabled=%s, login2fa=%s)"
                       % (sess["u"], cur["enabled"],
                          CONFIG["login_2fa"]["enabled"]))
            self._audit("settings", "alert.settings", "",
                        adet("ui.audit.det.enabled") if cur["enabled"]
                        else adet("ui.audit.det.disabled"))
            self._json({"ok": True})
        elif path == "/api/alerts/test":
            ifc = body.get("iface")
            # send_now تا ۱۳ اوت ۲۰۲۶ اصلاً در فهرستِ نام‌های گاردِ AST
            # نبود، پس این رشته کاملاً بیرونِ دیدِ آن ماند.
            ok, detail = ALERTS.send_now(
                A('alert.test.message', p0=_host_label()),
                iface_override=(ifc if ifc else None))
            self._audit("settings", "alert.test", "", detail, ok=ok)
            self._json({"ok": ok, "error": None if ok else detail,
                        "detail": self._msg(detail, self._lang())})
        elif path == "/api/ecmp/get":
            c = dict(ECMP_GUARD_DEFAULTS)
            c.update(CONFIG.get("ecmp_guard") or {})
            live = live_interfaces()
            da = float(c.get("dead_after", 150))
            # وضعیتِ زندهٔ هر تونلِ نام‌برده‌شده در گروه‌ها (برای نمایش در UI)
            named = [t for g in (c.get("groups") or [])
                     for t in (g.get("tunnels") or []) if isinstance(t, str)]
            states = {t: ecmp_tunnel_state(t, da)
                      for t in dict.fromkeys(named) if IFACE_RE.match(t)}
            member = {"%s|%s" % (gn, t): v
                      for (gn, t), v in ECMPGUARD.membership.items()}
            self._json({"ok": True,
                        "cfg": {k: c.get(k) for k in
                                ("enabled", "dead_after", "confirm",
                                 "script", "groups")},
                        "candidates": sorted(t for t in list_tunnel_confs()
                                             if IFACE_RE.match(t)),
                        "live": live, "states": states,
                        "membership": member,
                        "running": ECMPGUARD.enabled()})
        elif path == "/api/ecmp/save":
            cur = dict(ECMP_GUARD_DEFAULTS)
            cur.update(CONFIG.get("ecmp_guard") or {})
            cur["enabled"] = bool(body.get("enabled"))
            for k, lo, hi in (("dead_after", 130, 600), ("confirm", 1, 20)):
                try:
                    cur[k] = max(lo, min(hi, int(body.get(k, cur[k]))))
                except (ValueError, TypeError):
                    pass
            groups, seen = [], set()
            raw_groups = body.get("groups") or []
            if not isinstance(raw_groups, list) \
                    or not all(isinstance(g, dict) for g in raw_groups):
                self._json({"ok": False, "error": "bad request"}, 400)
                return
            for raw in raw_groups:
                g = dict(ECMP_GROUP_DEFAULTS, **raw)
                name = str(g.get("name", "")).strip()[:40]
                rf = str(g.get("routes_file", "")).strip()
                if not name or not rf:
                    self._json({"ok": False, "error": "api.err.ecmp.group_fields"})
                    return
                if name in seen:
                    self._json({"ok": False,
                                "error": aerr("api.err.ecmp.group_dup", name=name)})
                    return
                seen.add(name)
                # مسیرِ فایل مستقیم به اسکریپت می‌رود: مطلق و موجود باشد
                if not rf.startswith("/") or not os.path.isfile(rf):
                    self._json({"ok": False, "error": aerr("api.err.ecmp.routes_missing", path=rf)})
                    return
                tuns = [str(t).strip() for t in (g.get("tunnels") or [])
                        if str(t).strip()]
                for t in tuns:
                    if not IFACE_RE.match(t):
                        self._json({"ok": False,
                                    "error": aerr("api.err.ecmp.iface_bad", name=t)})
                        return
                if not tuns:
                    self._json({"ok": False, "error": aerr("api.err.ecmp.group_empty", name=name)})
                    return
                tbl = str(g.get("table") or "main").strip()
                if not RT_TABLE_RE.match(tbl):
                    self._json({"ok": False,
                                "error": aerr("api.err.ecmp.table_bad", name=tbl)})
                    return
                try:
                    w = max(1, min(255, int(g.get("weight", 5))))
                except (ValueError, TypeError):
                    w = 5
                groups.append({"name": name, "routes_file": rf,
                               "tunnels": tuns, "weight": w, "table": tbl,
                               "enabled": bool(g.get("enabled", True))})
            if cur["enabled"] and not any(g["enabled"] for g in groups):
                self._json({"ok": False, "error": "api.err.ecmp.need_group"})
                return
            if not os.path.isfile(cur["script"]):
                self._json({"ok": False, "error": aerr("api.err.ecmp.script_missing",
                                          path=cur["script"])})
                return
            with config_txn() as cfg:
                cur["groups"] = groups
                cfg["ecmp_guard"] = cur
            # گروه‌ها/تونل‌ها عوض شده‌اند: حافظهٔ عضویت باید از نو ساخته شود
            ECMPGUARD.membership.clear()
            ECMPGUARD.dead_streak.clear()
            log_action("ecmp guard config saved by %s (enabled=%s, groups=%s)"
                       % (sess["u"], cur["enabled"],
                          ",".join(g["name"] for g in groups)))
            self._audit("settings", "ecmp.settings", "",
                        adet("ui.audit.det.ecmpcfg",
                             on=("1" if cur["enabled"] else "0"),
                             n=len(groups)))
            self._json({"ok": True})
        elif path == "/api/backup/run":
            which = str(body.get("which", "panel"))
            ok, err = start_manual_backup(which, sess["u"])
            if ok:
                self._audit("settings", "bk.manual.start",
                            MANUAL_BACKUP_JOBS[which][0], "")
            self._json({"ok": ok, "error": err or None,
                        "manual": manual_backup_state()})
        elif path == "/api/net/leak-audit":
            # کاملاً خواندنی؛ چند `ip route get` و `ipset test` می‌زند،
            # پس on-demand است نه بخشی از پولِ وضعیت.
            self._json({"ok": True, "audit": dns_leak_audit()})
        elif self._post_warp(path, body):
            pass          # گروهِ WARP — رجوع به _post_warp
        elif self._post_nqmo(path, body):
            pass          # گروهِ WG-NQMO — رجوع به _post_nqmo
        elif path == "/api/backup/versions":
            if not is_protected_admin(sess["u"]):
                self._json({"ok": False, "error": "api.err.restore.owner_only"},
                           403)
                return
            v = s4_panel_versions(force=bool(body.get("force")))
            self._json({"ok": v["ok"], "error": v.get("error") or None,
                        "versions": v.get("versions", []),
                        "target": v.get("target", ""),
                        "components": [{"key": k, "label": l}
                                       for k, l in CLOUD_RESTORE_COMPONENTS]})
        elif path == "/api/backup/cloud-restore":
            if not is_protected_admin(sess["u"]):
                self._audit("settings", "bk.restore.cloud", "",
                            adet("ui.audit.det.adminonly"), ok=False)
                self._json({"ok": False, "error": "api.err.restore.owner_only"},
                           403)
                return
            me = find_user(sess["u"])
            pw = str(body.get("password", ""))
            pw_ok = self._pw_confirm(me, pw) if me else False
            if pw_ok is None:
                self._json({"ok": False, "error": "api.err.auth.rate"}, 429)
                return
            if not pw_ok:
                self._audit("settings", "bk.restore.cloud", "",
                            adet("ui.audit.det.badconfirmpw"), ok=False)
                self._json({"ok": False, "error": "api.err.auth.totp_bad"}, 403)
                return
            comps = [str(c) for c in (body.get("components") or [])]
            obj = str(body.get("object", ""))
            ok, msg = cloud_restore_panel(obj, comps, sess["u"])
            self._audit("settings", "bk.restore.cloud", obj,
                        adet("ui.audit.det.cloudparts", msg=msg,
                             parts=(",".join(comps) or "-")), ok=ok)
            # بازیابی رخدادِ مهمی است — موفق یا ناموفق، خبرش برود
            ALERTS.event("backup",
                         A('alert.do_POST.1', p0=obj, p1=sess['u'], p2=A('alert.lit.7') if ok else A('alert.lit.8') + api_text(msg, alert_lang())))
            self._json({"ok": ok, "error": None if ok else msg,
                        "message": msg if ok else None})
        elif path == "/api/bot/get":
            c = bot_cfg()
            # owner در فهرستِ قابلِ‌تخصیص نمی‌آید (ردیفِ مالک در UI قفل است)
            roles = ["admin", "viewer"] \
                + sorted(r for r in (CONFIG.get("roles") or {}) if r != "owner")
            self._json({"ok": True,
                        "enabled": c["enabled"], "users": c["users"],
                        "roles": roles,
                        "alerts_ready": bool(alert_cfg()["bot_token"])})
        elif path == "/api/bot/save":
            users = []
            raw_users = body.get("users") or []
            if not isinstance(raw_users, list) \
                    or not all(isinstance(u, dict) for u in raw_users):
                self._json({"ok": False, "error": "bad request"}, 400)
                return
            for u in raw_users:
                tid = str(u.get("id", "")).strip()
                role = str(u.get("role", "viewer"))
                if not re.fullmatch(r"-?[0-9]{1,20}", tid):   # \d = ارقامِ فارسی هم
                    self._json({"ok": False,
                                "error": aerr("api.err.bot.id_digits", id=tid)})
                    return
                if role != "owner" and role not in BUILTIN_ROLES and \
                        role not in (CONFIG.get("roles") or {}):
                    self._json({"ok": False, "error": aerr("api.err.bot.role_bad", role=role)})
                    return
                row = {"id": tid, "role": role,
                       "name": str(u.get("name", ""))[:40]}
                # زبانی که کاربر با /lang برگزیده در فرمِ پنل نیست؛ بدونِ این
                # هر ذخیره آن را پاک می‌کرد و ربات، منو و (برای مالک) هشدارها
                # بی‌صدا به فارسی برمی‌گشتند.
                prev = next((x for x in bot_cfg()["users"]
                             if str(x.get("id")) == tid), {})
                if norm_lang(prev.get("lang")):
                    row["lang"] = prev["lang"]
                users.append(row)
            oerr = bot_owner_violation(users)
            if oerr:
                self._json({"ok": False, "error": oerr})
                return
            # ضدِ ارتقای دسترسی: دارنده‌ی صرفِ bot.manage نتواند کسی (از جمله
            # خودش) را مدیرِ ربات کند — نقشِ admin همه‌ی مجوزها را دارد.
            # ⚠️ نامِ «aerr» این‌جا ممنوع است: انتساب به آن در do_POST نام را
            # محلیِ کلِ تابع می‌کرد و همهٔ فراخوان‌های aerr(...) ِ این متد
            # UnboundLocalError می‌دادند.
            gerr = bot_admin_grant_violation(users, sess.get("r") == "admin")
            if gerr:
                self._audit("settings", "bot.settings", "",
                            adet("ui.audit.det.escalation"),
                            ok=False)
                self._json({"ok": False, "error": gerr}, 403)
                return
            # طرفِ دومِ همان گارد: خاموش‌کردنِ ربات وقتی تأییدِ ورود روشن است
            # یعنی هیچ تپی پردازش نمی‌شود → قفل‌شدنِ ورودِ همه.
            if not body.get("enabled") \
                    and (CONFIG.get("login_2fa") or {}).get("enabled"):
                self._json({"ok": False, "error": "api.err.bot.disable_2fa_first"})
                return
            # dict(bot_cfg(), …) و نه ساختنِ دیکشنری از صفر: کلیدهایی که
            # این هندلر مدیریتشان نمی‌کند — مثلِ add_ifaces که فقط با
            # ویرایشِ دستیِ config ست می‌شود و UI ندارد — نباید با هر
            # ذخیره پاک شوند. اپراتوری که آن را ست کرده عمداً سطحِ نوشتنِ
            # ربات را باریک کرده؛ پاک‌شدنش بی‌صدا به «همه‌ی اینترفیس‌ها»
            # برمی‌گشت. همان الگویی که هندلرهای کاربرِ ربات از قبل دارند.
            with config_txn() as cfg:
                cfg["bot"] = dict(bot_cfg(),
                                  enabled=bool(body.get("enabled")),
                                  users=users)
            threading.Thread(target=bot_setcommands, daemon=True).start()
            log_action("bot config saved by %s (enabled=%s, users=%d)"
                       % (sess["u"], CONFIG["bot"]["enabled"], len(users)))
            self._audit("settings", "bot.settings", "",
                        adet("ui.audit.det.botcfg", n=len(users),
                             on=("1" if CONFIG["bot"]["enabled"] else "0")))
            self._json({"ok": True})
        elif path == "/api/speedtest/run":
            started = SPEEDTEST.start(actor=(sess or {}).get("u", "?"))
            if started:
                self._audit("settings", "sp.run", "*",
                        adet("ui.audit.det.server", id=SpeedTester.server_id()))
            self._json({"ok": started,
                        "error": None if started else "api.err.speed.running"})
        elif path == "/api/speedtest/cancel":
            SPEEDTEST.cancel()
            self._audit("settings", "sp.cancel", "", "")
            self._json({"ok": True})
        elif path == "/api/speedtest/config":
            try:
                sid = int(body.get("server_id") or 3744)
            except (TypeError, ValueError):
                self._json({"ok": False,
                            "error": "api.err.speed.server_num"})
                return
            if not (1 <= sid <= 99999999):
                self._json({"ok": False, "error": "api.err.speed.server_bad"})
                return
            raw = body.get("ifaces")
            ifs = []
            for x in (raw if isinstance(raw, list)
                      else str(raw or "").replace("،", ",").split(",")):
                x = str(x).strip()
                if not x:
                    continue
                if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,15}", x):
                    self._json({"ok": False,
                                "error": aerr("api.err.speed.iface_bad", name=x[:20])})
                    return
                ifs.append(x)
            with config_txn() as cfg:
                cfg["speedtest_server"] = sid
                cfg["speedtest_ifaces"] = ifs
            self._audit("settings", "sp.settings",
                        ",".join(ifs) or "*",
                        adet("ui.audit.det.server", id=sid))
            self._json({"ok": True, "server_id": sid, "ifaces": ifs})
        elif path == "/api/logout":
            # 🪤 نشست کوکیِ امضاشده‌ی بدونِ حالتِ سمتِ سرور است، پس
            # پاک‌کردنِ کوکی فقط نسخه‌ی همین مرورگر را می‌برد: کوکیِ
            # کپی‌شده (ماشینِ مشترک، sync ِ مرورگر، لاگِ پروکسی) تا
            # انقضا معتبر می‌ماند، در حالی که کاربر فکر می‌کند خارج شده.
            #
            # دستگیره‌ی ابطال از قبل هست و لازم نیست ساخته شود: کوکی
            # `stoken` را حمل می‌کند و verify_session_cookie آن را با
            # مقدارِ فعلیِ کاربر می‌سنجد (همان سازوکاری که تغییرِ رمز
            # استفاده می‌کند). چرخاندنش همه‌ی نشست‌های آن کاربر را
            # می‌بندد — که برای پنلی که کلیدهای VPN را مدیریت می‌کند
            # پیش‌فرضِ درستی است.
            sess = self._session()
            u = find_user(sess["u"]) if sess else None
            if u is not None:
                with config_txn():
                    u["stoken"] = secrets.token_hex(8)
                self._audit("auth", "auth.logout", "", "", ok=True)
            # کوکیِ پاک‌کننده باید همان صفت‌های کوکیِ واقعی را داشته باشد؛
            # بعضی مرورگرها بدونِ تطابقِ صفت‌ها اصلاً بازنویسی‌اش نمی‌کنند.
            secure = "; Secure" if self._is_https() else ""
            self._json({"ok": True}, extra_headers={
                "Set-Cookie": "wgs=; HttpOnly; SameSite=Strict; Path=/; "
                              "Max-Age=0" + secure})
        elif path == "/api/peer/toggle":
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", ""))
            enable = bool(body.get("enable"))
            ok, msg = set_peer_enabled(iface, name, enable)
            self._audit("peer", "peer.enable" if enable else "peer.disable",
                        "%s @ %s" % (name, iface),
                        (adet("ui.audit.det.peeron") if enable
                     else adet("ui.audit.det.peeroff")) if ok
                    else adet("ui.audit.det.failed", why=msg), ok)
            self._json({"ok": ok, "error": None if ok else msg,
                        "message": msg if ok else None})
        elif path == "/api/peer/add":
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", "")).strip()
            quota, expires, qerr = parse_quota_expires(
                body.get("quota_gb"), body.get("expires"))
            if qerr:
                self._json({"ok": False, "error": qerr})
                return
            ov, operr = parse_client_overrides(body)
            if operr:
                self._json({"ok": False, "error": operr})
                return
            total, terr = _parse_total_action(body)
            if terr:
                self._json({"ok": False, "error": terr})
                return
            rate, rerr = parse_rate_mbit(body.get("rate_mbit"))
            if rerr:
                self._json({"ok": False, "error": rerr})
                return
            use_psk = body.get("use_psk", True) is not False
            result, err = add_peer(iface, name, use_psk=use_psk, overrides=ov)
            if err:
                self._audit("peer", "peer.add", "%s @ %s" % (name, iface),
                            adet("ui.audit.det.failed", why=err), False)
                self._json({"ok": False, "error": err})
            else:
                mf = {k: v for k, v in ov.items() if v is not None}
                if quota is not None:
                    mf["quota_gb"] = quota
                if expires is not None:
                    mf["expires"] = expires
                if total["total_gb"] is not None:
                    mf["total_gb"] = total["total_gb"]
                    mf["enforce_action"] = total["enforce_action"]
                if rate is not None:
                    mf["rate_mbit"] = rate
                if mf:
                    META.meta_update(iface, name, mf)
                    SAMPLER.refresh_meta()
                if rate is not None:
                    SHAPER.kick()   # اعمالِ فوریِ محدودیت سرعت
                result["quota_gb"] = quota
                result["expires"] = expires or ""
                det = adet("ui.audit.det.peeradd", ip=result["ip"],
                           psk=("1" if use_psk else "0"),
                           quota=(quota if quota is not None else "—"),
                           total=(total["total_gb"]
                                  if total["total_gb"] is not None else "—"),
                           rate=(rate if rate is not None else "—"),
                           exp=(expires or "—"))
                self._audit("peer", "peer.add", "%s @ %s" % (name, iface), det)
                self._json({"ok": True, "result": result})
        elif path == "/api/peer/bulk":
            iface = str(body.get("iface", "wg1udp"))
            prefix = str(body.get("prefix", "")).strip()
            ov, operr = parse_client_overrides(body)
            if operr:
                self._json({"ok": False, "error": operr})
                return
            quota, expires, qerr = parse_quota_expires(
                body.get("quota_gb"), body.get("expires"))
            if qerr:
                self._json({"ok": False, "error": qerr})
                return
            total, terr = _parse_total_action(body)
            if terr:
                self._json({"ok": False, "error": terr})
                return
            mf = {k: v for k, v in ov.items() if v is not None}
            if quota is not None:
                mf["quota_gb"] = quota
            if expires is not None:
                mf["expires"] = expires
            if total["total_gb"] is not None:
                mf["total_gb"] = total["total_gb"]
                mf["enforce_action"] = total["enforce_action"]
            res, err = bulk_add_peers(
                iface, prefix, body.get("start", 1), body.get("count", 1),
                use_psk=body.get("use_psk", True) is not False,
                overrides=ov, meta_fields=mf or None)
            if err:
                self._json({"ok": False, "error": err})
            else:
                self._audit("peer", "peer.bulk", "%s* @ %s" % (prefix, iface),
                            adet("ui.audit.det.bulkmade", n=len(res["created"])),
                            not res["errors"])
                lang = self._lang()
                res["errors"] = [self._msg(e, lang) for e in res["errors"]]
                self._json({"ok": True, "result": res})
        elif path == "/api/peer/psk":
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", ""))
            enable = bool(body.get("enable"))
            ok, msg = set_peer_psk(iface, name, enable)
            self._audit("peer", "peer.psk" if enable else "peer.psk.off",
                        "%s @ %s" % (name, iface), msg, ok)
            self._json({"ok": ok, "error": None if ok else msg})
        elif path in ("/api/peer/ping", "/api/peer/trace"):
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", ""))
            if path.endswith("ping"):
                ok, out = peer_ping(iface, name)
            else:
                ok, out = peer_trace(iface, name)
            self._json({"ok": ok, "output": out if ok else None,
                        "error": None if ok else out})
        elif path == "/api/peer/share":
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", ""))
            if body.get("revoke"):
                META.share_revoke(iface, name)
                self._audit("peer", "peer.share.revoke", "%s @ %s" % (name, iface),
                            adet("ui.audit.det.linksrevoked"))
                self._json({"ok": True})
            else:
                token, err = create_share(
                    iface, name, body.get("minutes", 30),
                    body.get("single", True), self._session()["u"])
                if err:
                    self._json({"ok": False, "error": err})
                else:
                    host = self.headers.get("Host", "")
                    # همان schemeی که مرورگر می‌بیند؛ لینکِ https برای پنلِ
                    # بدونِ TLS (docker با WG_TLS_ENABLED=false) کار نمی‌کرد و
                    # لینکِ http پشتِ proxy ِ TLS‌دار هم (request_is_https).
                    scheme = "https" if self._is_https() else "http"
                    url = "%s://%s/s/%s" % (scheme, host, token)
                    self._audit("peer", "peer.share.new",
                                "%s @ %s" % (name, iface),
                                adet("ui.audit.det.linkmade",
                                     min=body.get("minutes", 30)))
                    self._json({"ok": True, "url": url})
        elif path == "/api/peer/conf":
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", ""))
            conf = load_client_conf(iface, name)
            if conf is None:
                self._json({"ok": False, "error": "api.err.peer.no_saved_conf"})
            else:
                blocks = parse_user_blocks(iface)
                blk = next((b for b in blocks if b["name"] == name), None)
                ip = blk["allowed_ips"].split("/")[0] if blk else ""
                self._json({"ok": True, "result":
                            {"name": name, "iface": iface, "ip": ip,
                             "client_conf": conf}})
        elif path == "/api/peer/delete":
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", ""))
            ok, msg = delete_peer(iface, name)
            if ok:
                SHAPER.kick()   # کلاسِ سرعتِ کاربرِ حذف‌شده را پاک کن
            self._audit("peer", "peer.del", "%s @ %s" % (name, iface),
                        adet("ui.audit.det.peerdeleted") if ok
                        else adet("ui.audit.det.failed", why=msg), ok)
            self._json({"ok": ok, "error": None if ok else msg})
        elif path == "/api/peer/rotate":
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", ""))
            result, err = rotate_peer_key(iface, name)
            self._audit("peer", "peer.key.rotate", "%s @ %s" % (name, iface),
                        adet("ui.audit.det.keyrotated")
                        if not err else adet("ui.audit.det.failed", why=err), not err)
            if err:
                self._json({"ok": False, "error": err})
            else:
                self._json({"ok": True, "result": result})
        elif path == "/api/peer/ips":
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", ""))
            new_ips = str(body.get("allowed_ips", ""))
            old_ips = ""
            try:
                blk = next((b for b in parse_user_blocks(iface)
                            if b["name"] == name), None)
                old_ips = blk["allowed_ips"] if blk else ""
            except OSError:
                pass
            ok, msg = update_peer_ips(iface, name, new_ips)
            self._audit("peer", "peer.allowedips", "%s @ %s" % (name, iface),
                        adet("ui.audit.det.fromto", old=old_ips, new=new_ips)
                        if ok else adet("ui.audit.det.failed", why=msg), ok)
            self._json({"ok": ok, "error": None if ok else msg})
        elif path == "/api/peer/meta":
            iface = str(body.get("iface", "wg1udp"))
            name = str(body.get("name", ""))
            note = str(body.get("note", ""))[:200]
            quota, expires, qerr = parse_quota_expires(
                body.get("quota_gb"), body.get("expires"))
            if qerr:
                self._json({"ok": False, "error": qerr})
                return
            ov, operr = parse_client_overrides(body)
            if operr:
                self._json({"ok": False, "error": operr})
                return
            total, terr = _parse_total_action(body)
            if terr:
                self._json({"ok": False, "error": terr})
                return
            rate, rerr = parse_rate_mbit(body.get("rate_mbit"))
            if rerr:
                self._json({"ok": False, "error": rerr})
                return
            fields = {"note": note, "quota_gb": quota, "expires": expires,
                      "total_gb": total["total_gb"],
                      "enforce_action": total["enforce_action"],
                      "rate_mbit": rate}
            fields.update(ov)
            META.meta_update(iface, name, fields)
            SAMPLER.refresh_meta()
            SHAPER.kick()   # اعمال/برداشتنِ فوریِ محدودیت سرعت
            regen_client_conf(iface, name)  # override ها را روی کانفیگ اعمال کن
            log_action("meta %s@%s note=%r quota=%s total=%s expires=%s rate=%s"
                       % (name, iface, note, quota, total["total_gb"], expires, rate))
            self._audit("peer", "peer.edit", "%s @ %s" % (name, iface),
                        adet("ui.audit.det.peeredit",
                             quota=(quota or "∞"),
                             total=("%s (%s)" % (total["total_gb"],
                                                 total["enforce_action"])
                                    if total["total_gb"] else "—"),
                             rate=(rate or "∞"), exp=(expires or "—"),
                             mtu=(ov.get("c_mtu") or "—"),
                             dns=(ov.get("c_dns") or "—"),
                             allowed=(ov.get("c_allowed") or "—"),
                             note=(note or "—")))
            self._json({"ok": True})
        elif path == "/api/usage":
            iface = str(body.get("iface", "wg1udp"))
            pubkey = str(body.get("pubkey", ""))
            mode = str(body.get("range", "30d"))
            if mode not in ("1h", "24h", "7d", "30d", "6m"):
                mode = "30d"
            if mode == "1h":
                # تبِ ۱ساعت: نرخ‌های ~۱۰ثانیه‌ای از رینگِ حافظه (نه DB)
                self._json({"ok": True, "mode": mode,
                            "rows": SAMPLER.ring10_series(iface, pubkey)})
                return
            gran = "hour" if str(body.get("gran", "")) == "hour" else None
            rows = META.usage_series(iface, pubkey, mode, gran=gran)
            out = {"ok": True, "mode": mode, "rows": rows}
            if body.get("cmp"):
                out["prev"] = META.usage_prev_total(iface, pubkey, mode)
            self._json(out)
        elif path == "/api/graph/events":
            # رویدادهای audit/WARP یک موجودیت برای نشانگرهای روی گراف
            iface = str(body.get("iface", ""))
            name = str(body.get("name", ""))
            mode = str(body.get("range", "30d"))
            days = {"24h": 1, "7d": 7, "30d": 30, "6m": 183}.get(mode, 30)
            evs = META.graph_events(
                iface, name, time.time() - days * 86400,
                include_warp=("warp" in iface.lower()))
            self._json({"ok": True, "events": evs})
        elif path == "/api/usage_matrix":
            iface = str(body.get("iface", "wg1udp"))
            mode = str(body.get("range", "30d"))
            if mode not in ("24h", "7d", "30d", "6m"):
                mode = "30d"
            mx = META.usage_matrix(iface, mode)
            # نگاشت pubkey → نام کاربر
            name_by_pub = {}
            try:
                for b in parse_user_blocks(iface):
                    if b["public_key"]:
                        name_by_pub[b["public_key"]] = b["name"]
            except OSError:
                pass
            series = []
            for pub, byb in mx["data"].items():
                total = sum(byb.values())
                series.append({
                    "name": name_by_pub.get(pub, pub[:8] + "…"),
                    "values": [byb.get(t, 0) for t in mx["buckets"]],
                    "total": total})
            series.sort(key=lambda s: s["total"], reverse=True)
            self._json({"ok": True, "mode": mode,
                        "buckets": mx["buckets"], "series": series})
        elif path == "/api/tunnel/toggle":
            iface = str(body.get("iface", ""))
            up = bool(body.get("up"))
            ok, msg = toggle_tunnel(iface, up)
            self._audit("tunnel", "tun.up" if up else "tun.down", iface,
                        adet("ui.audit.det.tuntoggle",
                             on=("1" if up else "0")), ok)
            self._json({"ok": ok, "error": None if ok else msg})
        elif self._post_svc(path, body):
            pass          # گروهِ svc — رجوع به _post_svc
        elif path == "/api/sys/series":
            # سری زمانیِ یک متریکِ سیستم (زنده یا میانگینِ ذخیره‌شده).
            metric = str(body.get("metric", ""))
            mode = str(body.get("range", "live"))
            if metric not in SYS_METRICS:
                self._json({"ok": False, "error": "api.err.svc.metric_invalid"}, 400)
            elif mode == "live":
                self._json({"ok": True, "mode": "live", "metric": metric,
                            "live": SYSMON.live_series(
                                metric, tail=SYSMON.LIVE_TAIL)})
            elif mode == "1h":
                # کلِ رینگِ ۱ساعته با t بر حسبِ epoch-ms (برای محورِ زمانِ واقعی)
                rows = [{"t": int(t * 1000), "v": v}
                        for t, v in SYSMON.live_series(metric)]
                self._json({"ok": True, "mode": mode, "metric": metric,
                            "rows": rows})
            else:
                if mode not in ("24h", "7d", "30d", "6m"):
                    mode = "30d"
                self._json({"ok": True, "mode": mode, "metric": metric,
                            "rows": META.metric_series(metric, mode)})
        elif self._post_proxy(path, body):
            pass          # گروهِ پروکسی — رجوع به _post_proxy
        else:
            self._json({"ok": False, "error": "not found"}, 404)


# ----------------------------------------------------- سرورِ TLS و راه‌اندازی



class TLSThreadingHTTPServer(ThreadingHTTPServer):
    """سرورِ HTTPS با هندشیکِ TLS در نخِ هر اتصال، نه در حلقه‌ی accept.

    چرا: الگوی قبلی (wrap کردنِ سوکتِ listen) هندشیک را داخلِ accept()‏ ِ
    تک‌نخیِ serve_forever می‌بُرد؛ نتیجه این‌که یک کلاینتِ ساکت — مثل
    اسکنرهای اینترنتی که فقط TCP باز می‌کنند و ClientHello نمی‌فرستند —
    کلِ پنل را برای همه فریز می‌کرد و مرورگر «سایت باز نمی‌شود / خیلی
    دیر باز می‌شود» می‌دید. تاییدِ عملی روی همین سرور: یک اتصالِ خامِ
    ۹ثانیه‌ای، هندشیکِ کلاینتِ سالمِ بعدی را ۸.۱ ثانیه معطل کرد.
    """

    # صفِ pendingِ پیش‌فرضِ socketserver فقط ۵ است؛ هنگامِ فریزِ بالا
    # SYNهای اضافه دور ریخته می‌شدند و مرورگر از ریشه «اتصال برقرار نشد»
    # می‌گرفت. ۶۴ برای رگبارِ چند تب + اسکنرها کافی است.
    request_queue_size = 64

    tls_context = None        # main()‏ فقط در حالتِ HTTPS ست می‌کند
    handshake_timeout = 15.0  # کلاینتِ ساکت حداکثر همین‌قدر «یک نخ» را می‌گیرد
    session_timeout = 300.0   # گاردِ slowloris بعدِ هندشیک؛ برای لینکِ کُند سخاوتمندانه

    def get_request(self):
        # فقط acceptِ خامِ TCP — هیچ I/O ِ وابسته به کلاینت این‌جا نیست
        sock, addr = self.socket.accept()
        if self.tls_context is not None:
            sock.settimeout(self.handshake_timeout)
        return sock, addr

    def finish_request(self, request, client_address):
        # ThreadingMixIn این متد را در نخِ اختصاصیِ اتصال صدا می‌زند؛ پس
        # هندشیکِ کُند/ناتمام فقط همین نخ را مشغول می‌کند، نه کلِ پنل را.
        if self.tls_context is None:
            # گاردِ slowloris در حالتِ HTTP ِ ساده هم لازم است. پیش از این
            # **هر دو** settimeout پشتِ شرطِ TLS بودند، پس کلاینتی که وصل
            # می‌شد و هیچ بایتی نمی‌فرستاد یک نخ را برای همیشه می‌گرفت.
            # حالتِ ساده پیش‌فرضِ بسته‌های docker و airgap است — یعنی
            # دقیقاً همان‌جا که این کلاس هیچ محافظتی نمی‌داد.
            #
            # get_request عمداً دست‌نخورده ماند: بدونِ TLS هیچ I/O ِ
            # پیش‌از‌درخواستی نیست و خطِ درخواست را BaseHTTPRequestHandler
            # داخلِ همین finish_request می‌خواند، که حالا پوشش دارد.
            request.settimeout(self.session_timeout)
            return super().finish_request(request, client_address)
        try:
            tls_sock = self.tls_context.wrap_socket(request, server_side=True)
        except Exception:
            # هندشیکِ ناتمام/خراب (اسکنر، probe ِ فیلترینگ، timeout)؛
            # traceback ِ این‌ها فقط لاگ را پر می‌کند — بی‌صدا ببند.
            try:
                request.close()
            except OSError:
                pass
            return
        tls_sock.settimeout(self.session_timeout)
        try:
            super().finish_request(tls_sock, client_address)
        finally:
            # wrap_socket فایل‌دسکریپتور را از سوکتِ خام detach می‌کند؛
            # shutdown_request ِ socketserver سوکتِ خامِ بی‌fd را می‌بندد،
            # پس بدونِ این finally سوکتِ TLS (و fd ِ واقعی) نشت می‌کرد.
            try:
                tls_sock.close()
            except OSError:
                pass


def main():
    load_config()
    fatal, warn = validate_config(CONFIG)
    for w in warn:
        log_action("config warning: %s" % w)
    if fatal:
        for f in fatal:
            log_action("config error: %s" % f)
        raise SystemExit("config.json is invalid:\n  - " + "\n  - ".join(fatal))
    for i, name, errs in quarantine_invalid_users():
        log_action("config: user %s (users[%d]) disabled until fixed: %s"
                   % (name or "?", i, "; ".join(errs)))
    migrate_config()
    if CONFIG.get("trusted_proxies"):
        log_action("trusted proxies: %s (client IP from X-Forwarded-For)"
                   % ", ".join(str(x) for x in CONFIG["trusted_proxies"]))
    SAMPLER.start()
    TUNNELS.refresh()  # یک بار همگام، تا اولین درخواست‌ها لیست کامل ببینند
    TUNNELS.start()
    WATCHER.start()
    SVCDIAG.start()  # تشخیص مسیر سرویس‌ها (اطلاعاتی)
    SYSMON.start()   # متریک‌های سیستم برای گیج‌ها
    PROXYLOG.start() # حسابداریِ حجمِ پروکسی از access.log
    ALERTS.start()   # صفِ ارسالِ هشدارِ تلگرام
    ALERTMON.start() # نگهبانِ شرایطِ هشدار
    ECMPGUARD.start()# ترمیمِ ECMP در بازهٔ گذار (opt-in)
    WARPGUARD.start()# تاب‌آوریِ WARP: failover + graceful degradation
    WARPTRAFFIC.start()  # حسابداریِ per-blockِ WARP از شمارنده‌های ipset
    BOT.start()      # رباتِ تلگرام (long-poll از تونل)
    threading.Thread(target=bot_setcommands, daemon=True).start()
    threading.Thread(target=SPEEDTEST.scheduler, daemon=True).start()
    if alert_cfg()["enabled"] and alert_cfg()["events"].get("startup", True):
        ALERTS.emit(A('alert.startup', p0=_host_label(),
                      p1=datetime.now().strftime("%Y-%m-%d %H:%M")))
    port = int(CONFIG.get("port", 8787))
    srv = TLSThreadingHTTPServer(("0.0.0.0", port), Handler)
    scheme = "http"
    cert, key = CONFIG.get("tls_cert"), CONFIG.get("tls_key")
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        # هندشیک این‌جا انجام نمی‌شود؛ TLSThreadingHTTPServer آن را در نخِ
        # هر اتصال (finish_request) انجام می‌دهد تا accept آزاد بماند.
        srv.tls_context = ctx
        scheme = "https"
    log_action("panel started on port %d (%s)" % (port, scheme))
    srv.serve_forever()


if __name__ == "__main__":
    main()
