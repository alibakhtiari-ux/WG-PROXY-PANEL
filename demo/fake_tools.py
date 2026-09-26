# -*- coding: utf-8 -*-
"""ابزارهای ساختگیِ سیستم برای حالتِ دمو — wg، ip، systemctl و خاموش‌ها.

run.py برای هر برنامه‌ای که پنل صدا می‌زند یک پوشاننده‌ی کوچک در bin/ ِ دمو
می‌سازد که این فایل را با نامِ همان برنامه اجرا می‌کند:

    python3 fake_tools.py wg show all dump

هیچ‌کدام به شبکه، فایروال یا کرنل دست نمی‌زنند. wg داده‌ی زنده را از
کانفیگ‌های پوشه‌ی دمو و فایلِ وضعیتِ seed.py می‌سازد؛ شمارنده‌ها تابعی از
زمان‌اند تا نمودارهای «زنده» حرکت کنند. بقیه‌ی ابزارها (curl، iptables،
rclone، speedtest …) بی‌صدا شکست می‌خورند و پنل همان مسیرِ خطایی را می‌رود
که روی سرورِ بی‌آن ابزار می‌رفت.
"""
import base64
import glob
import hashlib
import json
import math
import os
import sys
import time

WG_DIR = os.environ.get("DEMO_WG_DIR", "")
STATE = os.environ.get("DEMO_STATE", "")

# آدرسِ «عمومیِ» ساختگیِ سرور — از بازه‌ی مستندسازیِ RFC 5737
SERVER_IP = "203.0.113.10"


def _pub_of(priv):
    return base64.b64encode(
        hashlib.sha256(priv.strip().encode()).digest()).decode()


def _state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _confs():
    out = {}
    for p in sorted(glob.glob(os.path.join(WG_DIR, "wg*.conf"))):
        with open(p, encoding="utf-8") as f:
            out[os.path.basename(p)[:-5]] = f.read().splitlines()
    return out


def _counter(pub, p, now):
    """(rx, tx, handshake) ِ یک peer در لحظه‌ی now — پیوسته و صعودی."""
    h = int(hashlib.md5(pub.encode()).hexdigest()[:8], 16)
    rate = p.get("rate", 0)
    t0 = p.get("t0", now)
    # نرخِ نوسانی حولِ rate، با دوره‌ی جدا برای هر peer تا نمودارها هم‌شکل
    # نباشند؛ مشتق rate·(1+sin) است، پس شمارنده هرگز کم نمی‌شود.
    phase = (h % 628) / 100.0
    w = 12 + h % 29
    moved = rate * ((now - t0) + w * (math.cos(phase) - math.cos((now - t0) / w + phase)))
    rx = int(p.get("base", 10 ** 9) + max(moved, 0))
    tx = int(rx * p.get("up", 0.12))
    hs = int(now - (h % 90) - 5) if rate > 0 else int(p.get("hs", 0))
    return rx, tx, hs


def iface_totals(now):
    """{iface: (rx, tx)} — مجموعِ شمارنده‌های peerهای هر اینترفیس."""
    st, out = _state(), {}
    for iface, ls in _confs().items():
        rx = tx = 0
        for line in ls:
            s = line.strip()
            if s.startswith("PublicKey"):
                pub = s.split("=", 1)[1].strip()
                r, t, _ = _counter(pub, st.get(pub, {}), now)
                rx, tx = rx + r, tx + t
        out[iface] = (rx, tx)
    return out


def wg(args):
    if args[:1] in (["genkey"], ["genpsk"]):
        print(base64.b64encode(os.urandom(32)).decode())
        return 0
    if args[:1] == ["pubkey"]:
        print(_pub_of(sys.stdin.read()))
        return 0
    if args[:1] in (["set"], ["syncconf"], ["addconf"], ["setconf"]):
        return 0
    confs = _confs()
    if args[:2] == ["show", "interfaces"]:
        print(" ".join(confs))
        return 0
    if len(args) == 3 and args[0] == "show" and args[2] == "public-key":
        for line in confs.get(args[1], []):
            if line.strip().startswith("PrivateKey"):
                print(_pub_of(line.split("=", 1)[1]))
                return 0
        return 1
    if args[:1] != ["show"]:
        return 0
    st, now, lines = _state(), time.time(), []
    for iface, ls in confs.items():
        priv = listen = ""
        for line in ls:
            s = line.strip()
            if s.startswith("PrivateKey"):
                priv = s.split("=", 1)[1].strip()
            elif s.startswith("ListenPort"):
                listen = s.split("=", 1)[1].strip()
        lines.append("\t".join([iface, priv, _pub_of(priv), listen or "0",
                                "off"]))
        cur = None
        for line in ls + ["[Peer]"]:
            s = line.strip()
            if s == "[Peer]":
                if cur and cur.get("pub"):
                    p = st.get(cur["pub"], {})
                    rx, tx, hs = _counter(cur["pub"], p, now)
                    lines.append("\t".join([
                        iface, cur["pub"], cur.get("psk", "(none)"),
                        cur.get("ep") or p.get("ep", "(none)"),
                        cur.get("allowed", ""), str(hs), str(rx), str(tx),
                        "25"]))
                cur = {}
                continue
            if cur is None or s.startswith("#"):
                continue      # بلوکِ غیرفعال (کامنت‌شده) در wg ِ زنده نیست
            key, _, val = s.partition("=")
            key, val = key.strip(), val.strip()
            if key == "PublicKey":
                cur["pub"] = val
            elif key == "PresharedKey":
                cur["psk"] = val
            elif key == "AllowedIPs":
                cur["allowed"] = val
            elif key == "Endpoint":
                cur["ep"] = val
            elif s.startswith("["):
                cur = None
    print("\n".join(lines))
    return 0


def ip(args):
    if args[:1] == ["-j"]:
        addrs = [("lo", "127.0.0.1", 8, "UNKNOWN", 65536),
                 ("eth0", SERVER_IP, 24, "UP", 1500)]
        for iface, ls in _confs().items():
            for line in ls:
                if line.strip().startswith("Address"):
                    a = line.split("=", 1)[1].strip().split(",")[0]
                    addr, _, plen = a.partition("/")
                    addrs.append((iface, addr, int(plen or 32), "UNKNOWN",
                                  1420))
        print(json.dumps([{"ifindex": i + 1, "ifname": n, "mtu": mtu,
                           "operstate": op,
                           "addr_info": [{"family": "inet", "local": a,
                                          "prefixlen": pl}]}
                          for i, (n, a, pl, op, mtu) in enumerate(addrs)]))
        return 0
    if args[:2] == ["route", "get"] and len(args) > 2:
        print("%s via 203.0.113.1 dev eth0 src %s uid 0" % (args[2], SERVER_IP))
        return 0
    if args[:2] == ["route", "show"] and "default" in args:
        print("default via 203.0.113.1 dev eth0 proto static")
        return 0
    return 0


def systemctl(args):
    verb = args[0] if args else ""
    if verb == "is-active":
        print("active")
        return 0
    if verb == "is-enabled":
        print("enabled")
        return 0
    if verb == "show":
        print("ActiveState=active\nSubState=running\nResult=success\n"
              "ExecMainStatus=0")
        return 0
    return 0


def main(argv):
    tool, args = os.path.basename(argv[1]), argv[2:]
    if tool == "wg":
        return wg(args)
    if tool == "ip":
        return ip(args)
    if tool == "systemctl":
        return systemctl(args)
    if tool == "tc":
        return 0
    # هر ابزارِ دیگر (curl، dig، ping، iptables، ipset، rclone، speedtest …):
    # شکستِ بی‌صدا، تا دمو هیچ درخواستِ شبکه یا تغییرِ فایروالی نفرستد.
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
