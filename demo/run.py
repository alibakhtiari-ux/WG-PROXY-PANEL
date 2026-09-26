# -*- coding: utf-8 -*-
"""حالتِ دمو: پنل را با داده‌ی کاملاً ساختگی و بدونِ سرورِ واقعی اجرا می‌کند.

    python3 demo/run.py                  # http://127.0.0.1:8787 — admin / demo
    python3 demo/run.py --port 8799 --reset

چه می‌کند:
  • یک کپی از wg_panel.py را از یک پوشه‌ی موقت بارگذاری می‌کند (پیش‌فرض
    ‎$TMPDIR/wg-panel-demo) و هر مسیرِ ثابتِ ‎/etc و ‎/var و ‎/opt ِ آن را به
    داخلِ همان پوشه می‌برد؛
  • جلوی هر برنامه‌ای که پنل صدا می‌زند (wg، ip، systemctl، tc، iptables،
    curl، rclone …) نسخه‌ی ساختگیِ demo/fake_tools.py را می‌گذارد؛
  • فقط روی 127.0.0.1 گوش می‌دهد؛
  • بارِ اول ۱۵ کاربر، یک تونلِ خروجی، ۶ ماه تاریخچه‌ی ترافیک، گیج‌ها، تستِ
    سرعت و تاریخچه‌ی تغییرات می‌سازد.

همه‌ی نام‌ها ساختگی‌اند، کلیدها تازه ساخته می‌شوند، دامنه vpn.example.com
است و آدرس‌ها از بازه‌های مستندسازیِ RFC 5737. هیچ root ای لازم نیست و
هیچ چیزی بیرون از پوشه‌ی دمو نوشته نمی‌شود.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import random
import secrets
import shutil
import sys
import tempfile
import time
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import fake_tools  # noqa: E402

PASSWORD = "demo"
ASSETS = ("wg_panel.py", "qr.js", "three.core.min.js.gz",
          "three.module.min.js.gz", "three.LICENSE.txt")
# هر برنامه‌ای که پنل اجرا می‌کند؛ نبودنِ یکی یعنی دمو ابزارِ واقعیِ سیستم را
# صدا می‌زد. tests/test_demo.py این فهرست را با خودِ سورس می‌سنجد.
TOOLS = ("wg", "ip", "tc", "systemctl", "journalctl", "iptables", "ipset",
         "curl", "dig", "ping", "traceroute", "mtr", "rclone", "speedtest",
         "squid", "ss", "sysctl", "openssl", "qrencode")
SYSTEM_PREFIXES = ("/etc/", "/var/", "/opt/", "/usr/", "/run/", "/root/")

CLIENTS = [
    # نام، یادداشت، سهمیه‌ی ماهانه GB، سقفِ کل GB، انقضا (روز)، سرعت Mbit/s
    ("alice-phone", "Family plan", 50, None, 92, 20),
    ("alice-laptop", "", 50, None, 92, None),
    ("bob-desktop", "Design team", 200, None, None, 50),
    ("carol-ipad", "", 30, None, 2, None),
    ("dave-android", "", 20, None, None, 10),
    ("erin-macbook", "", None, 500, 180, None),
    ("frank-router", "Branch office", None, None, None, 100),
    ("grace-pixel", "", None, None, None, None),
    ("heidi-iphone", "", 40, None, 30, None),
    ("ivan-work", "", None, None, -3, None),
    ("judy-tablet", "", None, None, None, None),
    ("mallory-test", "", None, None, None, None),
    ("office-nas", "Backups only", None, None, None, 25),
    ("oscar-tv", "", None, None, None, None),
    ("peggy-laptop", "", None, None, None, None),
]
OFFLINE = {"ivan-work", "judy-tablet", "mallory-test", "oscar-tv"}


def build(state_dir):
    """پوشه‌ی دمو را از نو می‌سازد: کپیِ پنل، کانفیگ‌ها و ابزارهای ساختگی."""
    if os.path.isdir(state_dir):
        shutil.rmtree(state_dir)
    panel = os.path.join(state_dir, "panel")
    os.makedirs(panel)
    for name in ASSETS:
        shutil.copy2(os.path.join(ROOT, name), panel)
    wg_dir = os.path.join(state_dir, "root", "etc", "wireguard")
    os.makedirs(wg_dir)
    with open(os.path.join(wg_dir, "wg0.conf"), "w", encoding="utf-8") as f:
        f.write("[Interface]\nAddress = 10.8.0.1/24\nListenPort = 51820\n"
                "PrivateKey = %s\n" % _key())
    # یک تونلِ خروجی (کلاینت‌-نوع: Endpoint دارد) تا بخشِ تونل‌ها خالی نباشد
    with open(os.path.join(wg_dir, "wg1.conf"), "w", encoding="utf-8") as f:
        f.write("[Interface]\nAddress = 10.99.0.2/32\nPrivateKey = %s\n\n"
                "[Peer]\nPublicKey = %s\nEndpoint = 198.51.100.200:51820\n"
                "AllowedIPs = 0.0.0.0/0\n" % (_key(), _key()))
    salt = secrets.token_hex(16)
    cfg = {"port": 8787,
           "users": [{"username": "admin", "salt": salt, "role": "admin",
                      "hash": _hash(PASSWORD, salt)}],
           "server_host": "vpn.example.com",
           "client_dns": "1.1.1.1, 8.8.8.8", "client_mtu": 1420,
           "server_ifaces": ["wg0"],
           # پروبِ سرویس‌ها DNS و HTTPS ِ واقعی می‌زند — در دمو خاموش
           "svc_enabled": False}
    with open(os.path.join(panel, "config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    bin_dir = os.path.join(state_dir, "bin")
    os.makedirs(bin_dir)
    tool = os.path.join(HERE, "fake_tools.py")
    for name in TOOLS:
        path = os.path.join(bin_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write('#!/bin/sh\nexec "%s" "%s" "%s" "$@"\n'
                    % (sys.executable, tool, name))
        os.chmod(path, 0o755)


def _key():
    import base64
    return base64.b64encode(os.urandom(32)).decode()


def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(),
                               bytes.fromhex(salt), 200_000).hex()


def environ(state_dir):
    """متغیرهای محیطی که ابزارهای ساختگی و پنل باید ببینند."""
    os.environ["PATH"] = os.path.join(state_dir, "bin") + os.pathsep + \
        os.environ.get("PATH", "")
    os.environ["DEMO_WG_DIR"] = os.path.join(state_dir, "root", "etc",
                                             "wireguard")
    os.environ["DEMO_STATE"] = os.path.join(state_dir, "peers.json")
    fake_tools.WG_DIR = os.environ["DEMO_WG_DIR"]
    fake_tools.STATE = os.environ["DEMO_STATE"]


def load(state_dir):
    """کپیِ پنل را بارگذاری و قرنطینه می‌کند؛ ماژول را برمی‌گرداند."""
    environ(state_dir)
    path = os.path.join(state_dir, "panel", "wg_panel.py")
    spec = importlib.util.spec_from_file_location("wg_panel", path)
    m = importlib.util.module_from_spec(spec)
    sys.modules["wg_panel"] = m
    spec.loader.exec_module(m)
    sandbox(m, state_dir)
    patch(m)
    m.load_config()
    m.migrate_config()
    return m


def sandbox(m, state_dir):
    """هر مسیرِ ثابتِ سیستمی را به داخلِ پوشه‌ی دمو می‌برد."""
    root = os.path.join(state_dir, "root")
    # مسیرهایی که از BASE_DIR ِ خودِ کپی می‌آیند از قبل داخلِ پوشه‌ی دمو‌اند؛
    # در macOS پوشه‌ی موقت زیرِ ‎/var/folders است و بدونِ این استثنا دوباره
    # به root برده می‌شدند. realpath برای ‎/var → ‎/private/var.
    local = tuple({os.path.join(d, "") for d in
                   (os.path.abspath(state_dir), os.path.realpath(state_dir))})
    for name, val in list(vars(m).items()):
        if isinstance(val, str) and val.startswith(SYSTEM_PREFIXES) and \
                not val.startswith(local):
            setattr(m, name, root + val)


def patch(m):
    """دو وصله‌ی نمایشی که روی سرورِ واقعی لازم نیستند.

    eth0 ِ ساختگی آدرسِ مستندسازی دارد و پایتون آن را «خصوصی» می‌داند، پس
    پنل آن را WAN حساب نمی‌کرد و کارت‌های WAN صفر می‌ماندند. شمارنده‌هایش هم
    از ‎/proc/net/dev ِ واقعی نمی‌آید، پس ساختگی ساخته می‌شود.
    """
    classify = m.classify_iface

    def classify_iface(name, addrs):
        return ("ethernet", "wan") if name == "eth0" else classify(name, addrs)
    m.classify_iface = classify_iface

    wan = {"rate": 2.6e6, "base": 9 * 10 ** 12, "up": 0.35,
           "t0": time.time() - 3 * 86400}
    lo = {"rate": 2e3, "base": 10 ** 8, "up": 1.0, "t0": wan["t0"]}

    def read_proc_net_dev():
        # همه ساختگی: اینترفیس‌های واقعیِ ماشینِ اجراکننده (docker0 …) نباید
        # در دمو و اسکرین‌شات‌ها دیده شوند.
        now = time.time()
        out = {"lo": fake_tools._counter("lo", lo, now)[:2],
               "eth0": fake_tools._counter("eth0", wan, now)[:2]}
        out.update(fake_tools.iface_totals(now))
        return out
    m.read_proc_net_dev = read_proc_net_dev

    # فقط روی لوکال‌هاست — دمو هرگز نباید از بیرون دیده شود
    server = m.TLSThreadingHTTPServer

    class LocalOnly(server):
        def __init__(self, addr, handler):
            super().__init__(("127.0.0.1", addr[1]), handler)
    m.TLSThreadingHTTPServer = LocalOnly


def seed(m, state_dir):
    """داده‌ی ساختگی: کاربران، ترافیکِ زنده، ۶ ماه تاریخچه، گیج‌ها، رویدادها."""
    rnd = random.Random(7)
    now = time.time()
    for c in CLIENTS:
        rec, err = m.add_peer("wg0", c[0])
        if err:
            raise SystemExit("demo: add_peer %s: %s" % (c[0], err))
    blocks = {b["name"]: b for b in m.parse_user_blocks("wg0")}
    live = {}
    for i, c in enumerate(CLIENTS):
        name = c[0]
        ep = "%s:%d" % (("198.51.100.%d" if i % 2 else "203.0.113.%d")
                        % (20 + 3 * i), rnd.randint(20000, 64000))
        p = {"base": rnd.randint(2, 60) * 10 ** 9, "t0": now - 3 * 86400,
             "up": round(rnd.uniform(0.06, 0.25), 2), "ep": ep}
        if name in OFFLINE:
            p.update(rate=0, hs=int(now - rnd.choice((900, 5 * 3600,
                                                      2 * 86400, 9 * 86400))))
        else:
            p["rate"] = rnd.choice((40e3, 90e3, 180e3, 650e3, 1.4e6, 2.8e6))
        live[blocks[name]["public_key"]] = p
    # تونلِ خروجی
    with open(os.path.join(fake_tools.WG_DIR, "wg1.conf"),
              encoding="utf-8") as f:
        tunnel = f.read().splitlines()
    for line in tunnel:
        if line.startswith("PublicKey"):
            live[line.split("=", 1)[1].strip()] = {
                "rate": 3.1e6, "base": 4 * 10 ** 12, "up": 0.3,
                "t0": now - 3 * 86400, "ep": "198.51.100.200:51820"}
    with open(fake_tools.STATE, "w", encoding="utf-8") as f:
        json.dump(live, f)

    m.set_peer_enabled("wg0", "mallory-test", False)
    today = datetime.now()
    for name, note, quota, total, exp_days, rate in CLIENTS:
        fields = {}
        if note:
            fields["note"] = note
        if quota:
            fields["quota_gb"] = quota
        if total:
            fields["total_gb"] = total
        if exp_days is not None:
            fields["expires"] = (today + timedelta(days=exp_days)).strftime(
                "%Y-%m-%d")
        if rate:
            fields["rate_mbit"] = rate
        if fields:
            m.META.meta_update("wg0", name, fields)

    # ۶ ماه تاریخچه‌ی ساعتی/روزانه با الگوی شبانه‌روزی و آخرِ هفته
    start = today.replace(minute=0, second=0, microsecond=0) - \
        timedelta(days=185)
    rows = []
    for i, c in enumerate(CLIENTS):
        name, pub = c[0], blocks[c[0]]["public_key"]
        scale = rnd.choice((0.2, 0.5, 1, 2, 4)) * 40e6
        peak_h = rnd.choice((10, 13, 20, 21, 22))
        up = live[pub]["up"]
        t = start + timedelta(days=0 if i < 3 else rnd.randint(0, 120))
        while t <= today:
            daily = 0.15 + math.exp(-((t.hour - peak_h) ** 2) / 18) + \
                0.6 * math.exp(-((t.hour - 12) ** 2) / 10)
            week = 1.25 if t.weekday() in (4, 5) else 1.0
            trend = 0.7 + 0.3 * math.sin((t - start).days / 30.0 + i)
            rx = int(scale * daily * week * trend * rnd.uniform(0.5, 1.5))
            if name in OFFLINE and t > today - timedelta(days=3):
                rx = 0
            if rx and rnd.random() > 0.03:
                rows.append((t.strftime("%Y-%m-%d %H"),
                             t.strftime("%Y-%m-%d"), "wg0", pub, rx,
                             int(rx * up * rnd.uniform(0.7, 1.3))))
            t += timedelta(hours=1)
    m.META.add_usage(rows)

    metrics, t = [], start
    while t <= today:
        load_ = 0.5 + 0.5 * math.sin((t.hour - 8) / 24 * 2 * math.pi)
        for metric, base, amp in (("cpu", 8, 25), ("ram", 38, 12),
                                  ("disk", 41, 1), ("pcpu", 1, 2),
                                  ("pram", 2, 0.5)):
            v = max(0.0, base + amp * load_ + rnd.uniform(-3, 3))
            metrics.append((t.strftime("%Y-%m-%d %H"), t.strftime("%Y-%m-%d"),
                            metric, v * 30, 30))
        t += timedelta(hours=1)
    m.META.add_metrics(metrics)

    # تستِ سرعت: هر ۱۲ ساعت در ۳۰ روز؛ آخرین تست تازه است، پس زمان‌بندِ
    # خودکار (که speedtest ِ واقعی لازم دارد) در دمو اجرا نمی‌شود. از قدیم
    # به جدید درج می‌شود، چون پنل «آخرین» را با بزرگ‌ترین id می‌شناسد.
    for k in range(59, -1, -1):
        ts = now - k * 12 * 3600 - 600
        m.META.speedtest_add({
            "ts": ts, "iface": "eth0", "server_id": 1000, "ok": True,
            "ping_ms": rnd.uniform(18, 34), "jitter_ms": rnd.uniform(1, 6),
            "loss_pct": 0.0, "down_bps": rnd.uniform(380, 520) * 1e6,
            "up_bps": rnd.uniform(160, 240) * 1e6, "url": ""})

    det = m.adet
    events = [
        (140, "admin", "auth", "auth.login.ok", "", ""),
        (120, "admin", "peer", "peer.add", "heidi-iphone @ wg0", ""),
        (100, "admin", "peer", "peer.edit", "dave-android @ wg0", ""),
        (90, "admin", "peer", "peer.disable", "mallory-test @ wg0", ""),
        (70, "sys:policy", "peer", "peer.disable.auto", "ivan-work @ wg0",
         det("ui.audit.det.autodisable", why="ui.audit.reason.expired")),
        (60, "sys:policy", "peer", "peer.disable.auto", "dave-android @ wg0",
         det("ui.audit.det.autodisable", why="ui.audit.reason.quota")),
        (50, "sys:monitor", "tunnel", "tun.monitor.down", "wg1", "handshake"),
        (47, "sys:monitor", "tunnel", "tun.monitor.up", "wg1", "handshake"),
        (30, "admin", "peer", "peer.share.new", "bob-desktop @ wg0", ""),
        (10, "admin", "settings", "bk.download", "*", ""),
    ]
    for hours, actor, cat, action, target, detail in events:
        m.META.add_audit(actor, cat, action, target, detail,
                         "192.0.2.%d" % (10 + hours % 50), True)
    # رویدادِ پیشین را به عقب ببر (add_audit زمانِ حال را می‌گذارد)
    con = m.META._connect()
    with con:
        for hours, _a, _c, action, target, _d in events:
            con.execute("UPDATE audit SET ts=? WHERE action=? AND target=?",
                        (now - hours * 3600, action, target))
    con.close()


def prepare(state_dir, reset=False):
    """پوشه‌ی دمو را آماده می‌کند و ماژولِ قرنطینه‌شده را برمی‌گرداند."""
    fresh = reset or not os.path.exists(
        os.path.join(state_dir, "panel", "config.json"))
    if fresh:
        build(state_dir)
    m = load(state_dir)
    if fresh:
        seed(m, state_dir)
    return m


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=os.path.join(tempfile.gettempdir(),
                                                  "wg-panel-demo"))
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--reset", action="store_true",
                    help="throw the demo data away and seed it again")
    a = ap.parse_args()
    m = prepare(os.path.abspath(a.dir), a.reset)
    m.CONFIG["port"] = a.port
    print("demo: http://127.0.0.1:%d  —  admin / %s  (data in %s)"
          % (a.port, PASSWORD, a.dir), flush=True)
    # main() خودش load_config را دوباره صدا می‌زند؛ پورت را در فایل هم بنویس
    with open(m.CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(m.CONFIG, f, indent=2)
    m.main()


if __name__ == "__main__":
    main()
