# -*- coding: utf-8 -*-
"""مدل‌های نمودارِ تعاملی (SvgStudio) از داده‌ی زنده‌ی پنل — تابعِ خالص روی «واقعیت‌ها».

مرزِ مسئولیت (عمدی): موتورِ مرورگر (web/svgstudio.js) هیچ دانشی از شبکه ندارد و فقط
گره/یال/گام را رسم می‌کند. **همه‌ی هوش این‌جاست**: نقشِ هر تونل (مادر یا فرعی) از مسیرِ
endpointِ خودش، تصمیمِ مسیر از `ip route get` ِ گردآوری‌شده، عضویتِ ECMP از گارد، امضای
خرابی از شمارنده‌های rx/tx. هیچ نامِ اینترفیس یا IP ای این‌جا ثابت نیست — همه از
واقعیت‌هایی می‌آیند که app.py جمع می‌کند (`viz_*_facts`)، پس روی هر استقراری درست است.

ورودیِ هر سازنده یک dict ِ واقعیت است (قالبش در docstring همان تابع) و یک `Ctx` (ترجمه،
ارقام، جهت، اکنون). خروجی «کاوشگر» ِ SvgStudio است:
    {id, title, root, diagrams:[{id, kind, ...}], details:{key:{title, html, tags, related}}, legend:[...]}
details[k].html همین‌جا escape می‌شود — نامِ کاربر و یادداشت ورودیِ ادمین است و کشو
آن را با innerHTML می‌نشاند.
"""
import html as _html
import re
import time
from datetime import datetime

FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")

# سلامتِ تونل (tunnel_health) ⇒ لحنِ گره
HEALTH_TONE = {"healthy": "ok", "chain": "ok", "idle": "ok", "loop": "deny",
               "dead": "deny", "noreturn": "deny", "off": "muted"}
HEALTH_BAD = frozenset(("loop", "dead", "noreturn", "off"))
#: سنِ هندشیکی که WireGuard «زنده» می‌شمارد (همان آستانه‌ی build_stats)
ONLINE_AGE = 180
#: آستانه‌های امضا (بایت بر ثانیه). keepalive ِ ۲۵ثانیه‌ای + تلاشِ هندشیک ≈ ۱۴۸ بایت در ۵ ثانیه
#: (~۳۰ B/s)؛ هر چیزِ زیرِ ۲۰۰ B/s «tx ِ ریز» است، بالای ۲۰ KB/s «tx ِ سنگین».
TX_TINY = 200
TX_HEAVY = 20_000


def esc(s):
    return _html.escape("" if s is None else str(s), quote=True)


class Ctx:
    """زمینه‌ی رندر: ترجمه، ارقامِ فارسی، جهت و «اکنون»."""

    def __init__(self, T, fa=True, rtl=True, now=None):
        self.T = T
        self.fa = bool(fa)
        self.rtl = bool(rtl)
        self.now = float(now if now is not None else time.time())

    def t(self, key, **kw):
        return self.T(key, **kw)

    def n(self, x):
        """عدد ⇒ متن با ارقامِ زبان (فقط برای کمیت‌ها؛ شناسه‌ها هرگز از این‌جا رد نمی‌شوند)."""
        if isinstance(x, float):
            s = ("%.1f" % x).rstrip("0").rstrip(".") if abs(x) < 100 else "%d" % round(x)
        else:
            s = str(x)
        return s.translate(FA_DIGITS) if self.fa else s

    def bytes(self, b):
        b = float(b or 0)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(b) < 1024 or unit == "TB":
                return "%s %s" % (self.n(round(b, 1) if unit != "B" else int(b)), unit)
            b /= 1024.0
        return ""

    def rate(self, bps):
        return self.bytes(bps) + "/s"

    def ago(self, ts):
        if not ts:
            return self.t("viz.ago.never")
        d = max(0, int(self.now - float(ts)))
        if d < 90:
            return self.t("viz.ago.s", n=self.n(d))
        if d < 5400:
            return self.t("viz.ago.m", n=self.n(d // 60))
        if d < 172800:
            return self.t("viz.ago.h", n=self.n(d // 3600))
        return self.t("viz.ago.d", n=self.n(d // 86400))

    def clock(self, ts, with_date=False):
        dt = datetime.fromtimestamp(float(ts))
        s = dt.strftime("%m-%d %H:%M" if with_date else "%H:%M")
        return s.translate(FA_DIGITS) if self.fa else s


def kv(rows):
    """[(برچسب، مقدارِ HTML ِ امن)] ⇒ dl ِ کشو. مقدار باید از قبل escape شده باشد."""
    return '<dl class="dgp-kv">%s</dl>' % "".join(
        "<dt>%s</dt><dd>%s</dd>" % (esc(k), v) for k, v in rows if v not in (None, ""))


def mono(s):
    return '<span class="mono">%s</span>' % esc(s) if s else ""


def lvl(cls, text):
    return '<span class="%s">%s</span>' % (cls, esc(text))


def html_text(h):
    """HTML ِ کشو ⇒ متنِ سطری برای خانه‌ی Excel («برچسب: مقدار»، سرتیترِ هر بخش با «■»)."""
    import re
    t = str(h or "")
    t = re.sub(r"(?i)<h4[^>]*>", "\n■ ", t)
    t = re.sub(r"(?i)</h4>|</p>|<br\s*/?>|</dd>|</li>", "\n", t)
    t = re.sub(r"(?i)</dt>", ": ", t)
    t = re.sub(r"(?i)<li[^>]*>", "• ", t)
    t = re.sub(r"<[^>]+>", "", t)
    t = _html.unescape(t)
    return re.sub(r"\n\s*\n+", "\n", re.sub(r"[ \t]+", " ", t)).strip()


# ── امضای خرابی ───────────────────────────────────────────────────────────
def signature(kind, hs_age, rx_rates, tx_rates, enabled=True, rx_total=None):
    """امضای عددیِ وضعیتِ یک پیر/تونل از سری‌های نرخ (B/s، تازه‌ترین در انتها).

    kind = "peer" (کاربر؛ سرور طرفِ پاسخ‌دهنده است) | "tunnel" (سرور کلاینتِ فراهم‌کننده است).
    خروجی: (کد، سطح). کدها همان امضاهای مستندِ عیب‌یابی‌اند و هرکدام درمانِ جدا دارند —
    اشتباه‌گرفتنشان یعنی گشتنِ سمتِ اشتباه:
      nat_expired  rx یخ‌زده، tx ِ ریزِ پیوسته ⇒ نگاشتِ NAT ِ اپراتورِ کلاینت منقضی شده (سمتِ سرور سالم)
      loop         tx ِ سنگین، rx ≈ ۰ ⇒ حلقه‌ی مسیریابی: بسته‌ها به خودِ تونل برمی‌گردند
      dead_ep      rx یخ‌زده، tx ِ ریز، هندشیکِ کهنه (تونل) ⇒ endpoint ِ مرده
      no_forward   هندشیکِ تازه ولی rx ِ کلِ تونل فقط اندازه‌ی پاسخِ هندشیک ⇒ سرور کلید را می‌شناسد ولی forward نمی‌کند
      never        هرگز هندشیک نشده
      offline      هندشیکِ کهنه، بی ترافیک ⇒ کلاینت خاموش/بیرون (عادی)
      idle         هندشیکِ تازه، ترافیکِ ناچیز
      ok           هندشیکِ تازه و دریافتِ داده
      disabled     پیر غیرفعال است
    """
    if not enabled:
        return "disabled", "muted"
    rx = [max(0.0, float(v or 0)) for v in (rx_rates or [])]
    tx = [max(0.0, float(v or 0)) for v in (tx_rates or [])]
    rx_on = any(v > 0 for v in rx)
    tx_mean = (sum(tx) / len(tx)) if tx else 0.0
    tx_steady = bool(tx) and sum(1 for v in tx if v > 0) >= max(2, len(tx) // 4)   # نمونه‌ی ۲ثانیه‌ای، تپشِ ۵ثانیه‌ای
    if hs_age is None:
        return "never", ("bad" if kind == "tunnel" else "muted")
    fresh = hs_age < ONLINE_AGE
    if tx and not rx_on and tx_mean >= TX_HEAVY:
        return "loop", "bad"
    if kind == "tunnel":
        if fresh and rx_total is not None and 0 < rx_total <= 512 and not rx_on:
            return "no_forward", "bad"
        if not fresh:
            return "dead_ep", "bad"
        if not rx_on and tx_steady:
            return "no_forward", "bad"
        return ("ok", "ok") if rx_on else ("idle", "ok")
    # peer
    if not fresh:
        if not rx_on and tx_steady and tx_mean < TX_TINY:
            return "nat_expired", "warn"
        return "offline", "muted"
    # با هندشیکِ تازه «tx ِ ریز بی rx» همان پیرِ بیکارِ سالم است — امضای NAT فقط وقتی معنا دارد
    # که هندشیک کهنه شده (کلاینت دیگر جواب نمی‌دهد) و سرور هنوز می‌فرستد.
    return ("ok", "ok") if rx_on else ("idle", "ok")


def series_rates(hist):
    """تاریخچه‌ی SAMPLER ⇒ (rx[], tx[]) نرخ‌ها: [rx, tx]، (t, rx, tx) یا dict با rx_rate/tx_rate."""
    rx, tx = [], []
    for h in hist or []:
        if isinstance(h, dict):
            rx.append(h.get("rx_rate", h.get("rx", 0)))
            tx.append(h.get("tx_rate", h.get("tx", 0)))
        elif isinstance(h, (list, tuple)) and len(h) >= 3:          # (t, rx, tx)
            rx.append(h[1])
            tx.append(h[2])
        elif isinstance(h, (list, tuple)) and len(h) == 2:          # [rx, tx] ِ SAMPLER._rate_series
            rx.append(h[0])
            tx.append(h[1])
    return rx, tx


def sig_html(cx, code, level, rx=None, tx=None):
    """متنِ کشو برای یک امضا: عنوان، توضیح و شاهدِ عددی."""
    ev = []
    if rx is not None and tx is not None and (rx or tx):
        ev.append(cx.t("viz.sig.ev", n=cx.n(len(rx)),
                       rx=cx.rate(sum(rx) / max(1, len(rx))), tx=cx.rate(sum(tx) / max(1, len(tx)))))
    return ('<h4>%s</h4><p class="dgp-desc %s">%s</p>%s'
            % (esc(cx.t("viz.sig.h")), level, esc(cx.t("viz.sig.%s" % code)),
               "".join('<p class="dgp-desc note">%s</p>' % esc(e) for e in ev)))


# ── نقشه‌ی مسیرِ خروج (flow) ─────────────────────────────────────────────
def _carrier(t, tun_names):
    dev = t.get("loop_dev") or ""
    return dev if dev in tun_names and dev != t["iface"] else ""


def tunnel_roles(tunnels):
    """{iface: (carrier, depth)} — نقش از مسیرِ endpoint ِ خودِ تونل: endpoint از تونلِ دیگر ⇒ فرعی
    روی آن حامل؛ وگرنه مادر (depth=0). حلقه‌ی حامل‌ها (هرگز نباید باشد) با سقفِ عمق شکسته می‌شود."""
    names = {t["iface"] for t in tunnels}
    car = {t["iface"]: _carrier(t, names) for t in tunnels}
    out = {}
    for i in car:
        d, cur, seen = 0, i, {i}
        while car.get(cur) and car[cur] not in seen and d < 8:
            cur = car[cur]
            seen.add(cur)
            d += 1
        out[i] = (car[i], d)
    return out


def egress_model(f, cx):
    """نقشه‌ی زنده‌ی مسیرِ خروج.

    f = {"wan": str, "ingress": [{iface, peers, online, rx_rate, tx_rate, subnet, ks}],
         "users": {"total", "online", "disabled"},
         "ks": {"rules": int, "ifaces": [..]},
         "tunnels": [tunnel_row …],                      # iface, active, enabled, kind, endpoint,
                                                        # loop_dev, chain, handshake, rx/tx(_rate), health, hist?
         "ecmp": {"enabled": bool, "groups": [{"name", "tunnels": [..], "member": {iface: "in"|"out"|None}, "probe"}]},
         "default": [{"probe", "dev"}],                  # ip route get از دیدِ کاربر (catch-all)
         "sni": {enabled, active, healthy, hb_age, tproxy, unit_active, quic_active} | None,
         "ai": {"main": dev, "pool": [{dev, up, age, burned}]} | None,
         "warp": {"iface", "up", "handshake", "egress", "guard_alive", "healthy"} | None}
    """
    T = cx.t
    wan = f.get("wan") or "wan"
    ecmp = f.get("ecmp") or {}
    groups = ecmp.get("groups") or []
    default = [d for d in (f.get("default") or []) if d.get("dev")]
    ai = f.get("ai") or {}
    sni = f.get("sni") or None
    warp = f.get("warp") or None
    ingress = f.get("ingress") or []
    tunnels_all = list(f.get("tunnels") or [])
    by = {t["iface"]: t for t in tunnels_all}
    pool_devs = {p["dev"] for p in ((ai or {}).get("pool") or []) if p.get("dev")}
    used = {d["dev"] for d in default} | {x for g in groups for x in g.get("tunnels") or []}
    if ai and ai.get("main") and ai["main"] not in pool_devs:
        used.add(ai["main"])
    if warp and warp.get("iface"):
        used.add(warp["iface"])
    roles = tunnel_roles(tunnels_all)
    # حاملِ هر تونلِ استفاده‌شده (و حاملِ اعضای استخرِ AI) هم دیده می‌شود
    for i in list(used) + sorted(pool_devs):
        c = roles.get(i, ("", 0))[0]
        while c and c not in used:
            used.add(c)
            c = roles.get(c, ("", 0))[0]
    # تونلِ نمایش‌داده‌شده: استفاده‌شده، یا روشن/فعال. اعضای استخرِ AI یک‌به‌یک رسم نمی‌شوند
    # (ده تونلِ هم‌ارز نقشه را بی‌خوانا می‌کرد) — در گره‌ی «استخر» و کشویش فهرست می‌شوند.
    shown = [t for t in tunnels_all
             if (t["iface"] in used or t.get("active") or t.get("enabled"))
             and (t["iface"] not in pool_devs or t["iface"] in used)]
    hidden = [t["iface"] for t in tunnels_all if t not in shown and t["iface"] not in pool_devs]
    names = {t["iface"] for t in shown}
    roles_all, roles = roles, tunnel_roles(shown)     # عمق فقط روی آنچه رسم می‌شود (حاملِ پنهان ⇒ مادر)
    D = max([roles[t["iface"]][1] for t in shown] + [0])

    # ردیف‌ها: DFS از هر مادر — پیش‌فرض‌ها اول، بعد اعضای ECMP، بعد بقیه؛ هر تونل ردیفِ یکتا
    prio = {}
    for k, d in enumerate(default):
        prio.setdefault(d["dev"], k)
    for g in groups:
        for x in g.get("tunnels") or []:
            prio.setdefault(x, 100 + len(prio))
    kids = {}
    for t in shown:
        kids.setdefault(roles[t["iface"]][0] if roles[t["iface"]][0] in names else "", []).append(t["iface"])
    order = []

    def walk(i):
        order.append(i)
        for k in sorted(kids.get(i, []), key=lambda x: (x == (warp or {}).get("iface"), prio.get(x, 999), x)):
            walk(k)
    for m in sorted(kids.get("", []), key=lambda x: (prio.get(x, 999), x)):
        walk(m)
    row_of = {i: k for k, i in enumerate(order)}
    has_ai = bool(ai and (ai.get("pool") or ai.get("main")) and sni and sni.get("enabled"))
    # ردیف‌های بدنه: یکی برای هر تونل (هر یالِ افقی از «تصمیم» به تونلِ خودش هیچ گره‌ای را قطع نمی‌کند).
    # ردیفِ «پایه» (B) زیرِ بدنه: جراحیِ SNI کنارِ استخرِ AI (یالِ افقیِ مستقیم) و کیل‌سوییچ زیرِ ورودی‌ها.
    R = max(len(order), len(ingress), 2)
    B = R
    ai_row = B if has_ai else None
    C_USERS, C_IN, C_ROUTE = 0, 1, 2
    col_t = lambda i: 3 + (D - roles[i][1])          # noqa: E731 — عمیق‌ترین فرعی نزدیکِ تصمیم
    C_WAN, C_NET = 4 + D, 5 + D
    extra = 1 if (sni and sni.get("enabled")) or (f.get("ks") or {}).get("rules") or has_ai else 0
    nodes, edges, det = [], [], {}
    T_ = lambda k, **kw: T("viz." + k, **kw)          # noqa: E731

    # ── کاربران و ورودی‌ها
    u = f.get("users") or {}
    nodes.append({"id": "users", "c": C_USERS, "r": 0, "h": R, "label": T_("n.users"), "tone": "user", "shape": "pill",
                  "sub": [T_("n.users.sub", on=cx.n(u.get("online", 0)), all=cx.n(u.get("total", 0)))]})
    det["users"] = {"title": T_("n.users"), "html": kv([
        (T_("k.users"), esc(cx.n(u.get("total", 0)))), (T_("k.online"), esc(cx.n(u.get("online", 0)))),
        (T_("k.disabled"), esc(cx.n(u.get("disabled", 0))))]) +
        '<p class="dgp-desc note">%s</p>' % esc(T_("d.users"))}
    r0 = max(0, (R - len(ingress)) // 2)
    for k, g in enumerate(ingress):
        nid = "in:" + g["iface"]
        ks_on = bool(g.get("ks"))
        nodes.append({"id": nid, "c": C_IN, "r": r0 + k, "label": g["iface"], "tone": "user",
                      "sub": [T_("n.in.sub", on=cx.n(g.get("online", 0)), all=cx.n(g.get("peers", 0))),
                              "↓%s ↑%s" % (cx.rate(g.get("rx_rate")), cx.rate(g.get("tx_rate")))]})
        edges.append({"id": "e:" + nid, "from": "users", "to": nid, "tone": "user"})
        edges.append({"from": nid, "to": "route", "tone": "core"})
        det[nid] = {"title": g["iface"], "tags": [T_("tag.ingress")], "html": kv([
            (T_("k.peers"), esc(cx.n(g.get("peers", 0)))), (T_("k.online"), esc(cx.n(g.get("online", 0)))),
            (T_("k.subnet"), mono(g.get("subnet"))),
            (T_("k.rate"), esc("↓%s ↑%s" % (cx.rate(g.get("rx_rate")), cx.rate(g.get("tx_rate"))))),
            (T_("k.ks"), lvl("ok" if ks_on else "bad", T_("ks.on" if ks_on else "ks.off")))]),
            "related": ["route"] + (["ks"] if (f.get("ks") or {}).get("rules") else [])}

    # ── تصمیمِ مسیر
    nodes.append({"id": "route", "c": C_ROUTE, "r": 0, "h": R,
                  "label": T_("n.route"), "tone": "core", "sub": [T_("n.route.sub")]})
    rrows = []
    for d in default:
        rrows.append((T_("k.default"), "%s ⇒ %s" % (mono(d.get("probe")), mono(d["dev"]))))
    for g in groups:
        ins = [x for x in g.get("tunnels") or [] if (g.get("member") or {}).get(x) != "out"]
        rrows.append((T_("k.ecmp", g=g.get("name") or "ECMP"),
                      "%s%s" % (mono(" + ".join(ins) or "—"),
                                (" ⇐ " + mono(g["probe"])) if g.get("probe") else "")))
    if sni and sni.get("enabled"):
        rrows.append((T_("k.sni"), esc(T_("d.route.sni"))))
    rrows.append((T_("k.direct"), esc(T_("d.route.direct", wan=wan))))
    det["route"] = {"title": T_("n.route"), "html": kv(rrows) + '<h4>%s</h4><p class="dgp-desc">%s</p>' % (
        esc(T_("h.order")), esc(T_("d.route.order"))) + (
        '<p class="dgp-desc note">%s</p>' % esc(T_("d.route.hidden", list="، ".join(hidden) if cx.rtl else ", ".join(hidden)))
        if hidden else "")}

    # ── تونل‌ها
    member_of = {}
    for g in groups:
        for x in g.get("tunnels") or []:
            member_of.setdefault(x, []).append((g.get("name") or "ECMP", (g.get("member") or {}).get(x)))
    defaults_of = {}
    for d in default:
        defaults_of.setdefault(d["dev"], []).append(d.get("probe"))
    for i in order:
        t = by[i]
        h = t.get("health") or ("off" if not t.get("active") else "healthy")
        car = roles[i][0]
        tone = HEALTH_TONE.get(h, "muted")
        sub = [T_("h." + h)]
        if t.get("active"):
            sub.append("↓%s ↑%s" % (cx.rate(t.get("rx_rate")), cx.rate(t.get("tx_rate"))))
        nodes.append({"id": "t:" + i, "c": col_t(i), "r": row_of[i], "label": i, "tone": tone,
                      "shape": "dashed" if not t.get("enabled") and not t.get("active") else None, "sub": sub})
        hs = t.get("handshake") or 0
        rx, tx = series_rates(t.get("hist"))
        code, level = signature("tunnel", (cx.now - hs) if hs else None, rx[-60:], tx[-60:], True, t.get("rx"))
        if not t.get("active"):
            code, level = "down", "muted"
        rows = [(T_("k.kind"), esc(t.get("kind") or "")),
                (T_("k.role"), esc(T_("role.sub", c=car) if car and car in names else T_("role.mother", wan=t.get("loop_dev") or wan))),
                (T_("k.endpoint"), mono(t.get("endpoint"))),
                (T_("k.epdev"), mono(t.get("loop_dev"))),
                (T_("k.health"), lvl({"ok": "ok", "deny": "bad"}.get(tone, "warn"), T_("h." + h))),
                (T_("k.hs"), esc(cx.ago(hs)) if t.get("active") else ""),
                (T_("k.rate"), esc("↓%s ↑%s" % (cx.rate(t.get("rx_rate")), cx.rate(t.get("tx_rate"))))),
                (T_("k.total"), esc("↓%s ↑%s" % (cx.bytes(t.get("rx")), cx.bytes(t.get("tx"))))),
                (T_("k.keepalive"), mono(t.get("keepalive")))]
        for gname, mem in member_of.get(i, []):
            rows.append((T_("k.ecmp", g=gname), lvl("bad" if mem == "out" else "ok",
                                                    T_("ecmp.out" if mem == "out" else ("ecmp.in" if mem == "in" else "ecmp.unk")))))
        if i in defaults_of:
            rows.append((T_("k.default"), mono(", ".join(p for p in defaults_of[i] if p))))
        if warp and warp.get("iface") == i:
            rows.append((T_("k.guard"), lvl("ok" if warp.get("guard_alive") else "bad",
                                            T_("guard.alive" if warp.get("guard_alive") else "guard.dead"))))
        if warp and warp.get("egress") == i:
            rows.append((T_("k.warp_egress"), esc(T_("d.warp_egress"))))
        html = kv(rows) + '<p class="dgp-desc note">%s</p>' % esc(T_("hd." + h)) + sig_html(cx, code, level, rx[-60:], tx[-60:])
        rel = (["t:" + car] if car in names else ["wan"]) + ["t:" + k for k in kids.get(i, [])]
        det["t:" + i] = {"title": i, "tags": [T_("tag.tunnel"), T_("role.tag.sub" if car in names else "role.tag.mother")],
                         "html": html, "related": rel}
        # یال‌ها
        if car and car in names:
            edges.append({"from": "t:" + i, "to": "t:" + car, "tone": "muted" if not t.get("active") else "edge",
                          "label": T_("e.carrier"), "lpos": .5})
        else:
            edges.append({"from": "t:" + i, "to": "wan", "tone": "edge" if t.get("active") else "muted",
                          "dash": not t.get("active")})
    for d in default:
        if d["dev"] in names:
            eid = "e:def:" + d["dev"]
            if any(e.get("id") == eid for e in edges):
                continue
            edges.append({"id": eid, "from": "route", "to": "t:" + d["dev"], "tone": "core", "label": T_("e.default")})
            det[eid] = {"title": T_("e.default") + " ⇒ " + d["dev"], "html": kv(
                [(T_("k.probe"), mono(", ".join(x.get("probe") or "" for x in default if x["dev"] == d["dev"]))),
                 (T_("k.dev"), mono(d["dev"]))]) + '<p class="dgp-desc">%s</p>' % esc(T_("d.default"))}
    for g in groups:
        gname = g.get("name") or "ECMP"
        for x in g.get("tunnels") or []:
            if x not in names:
                continue
            mem = (g.get("member") or {}).get(x)
            eid = "e:ecmp:%s:%s" % (gname, x)
            edges.append({"id": eid, "from": "route", "to": "t:" + x, "tone": "deny" if mem == "out" else "app",
                          "dash": mem == "out", "label": gname})
            det[eid] = {"title": "%s ⇒ %s" % (gname, x), "html": kv([
                (T_("k.member"), lvl("bad" if mem == "out" else "ok", T_("ecmp.out" if mem == "out" else ("ecmp.in" if mem == "in" else "ecmp.unk")))),
                (T_("k.guard"), esc(T_("on" if ecmp.get("enabled") else "off"))),
                (T_("k.probe"), mono(g.get("probe")))]) + '<p class="dgp-desc">%s</p>' % esc(T_("d.ecmp"))}

    # ── جراحیِ SNI و استخرِ AI
    if sni and sni.get("enabled"):
        hb = sni.get("hb_age")
        s_ok = bool(sni.get("active")) and hb is not None and hb < 12
        nodes.append({"id": "sni", "c": C_ROUTE, "r": B, "label": T_("n.sni"), "tone": "iam" if s_ok else "deny",
                      "sub": [T_("n.sni.hb", s=cx.n(hb)) if hb is not None else T_("n.sni.nohb")]})
        edges.append({"from": "route", "to": "sni", "tone": "iam", "label": T_("e.sni")})
        det["sni"] = {"title": T_("n.sni"), "html": kv([
            (T_("k.state"), lvl("ok" if s_ok else "bad", T_("ok" if s_ok else "bad"))),
            (T_("k.hb"), esc(T_("n.sni.hb", s=cx.n(hb))) if hb is not None else esc(T_("n.sni.nohb"))),
            (T_("k.tproxy"), esc(T_("on" if sni.get("tproxy") else "off"))),
            (T_("k.unit"), esc(T_("on" if sni.get("unit_active") else "off"))),
            (T_("k.quic"), esc(T_("on" if sni.get("quic_active") else "off")))]) +
            '<p class="dgp-desc">%s</p>' % esc(T_("d.sni"))}
        target = None
        if has_ai and ai.get("pool"):
            pool = ai["pool"]
            up = sum(1 for p in pool if p.get("up") and not p.get("burned"))
            nodes.append({"id": "ai", "c": 3, "r": ai_row, "w": max(1, D + 1), "label": T_("n.ai"),
                          "tone": "iam" if up else "deny", "sub": [T_("n.ai.sub", up=cx.n(up), all=cx.n(len(pool)))]})
            target = "ai"
            det["ai"] = {"title": T_("n.ai"), "html": kv([(T_("k.main"), mono(ai.get("main")))]) +
                         '<h4>%s</h4><ul>%s</ul>' % (esc(T_("h.pool")), "".join(
                             "<li>%s — %s%s</li>" % (mono(p.get("dev")),
                                                    lvl("ok" if p.get("up") else "bad", T_("on" if p.get("up") else "off")),
                                                    (" · " + lvl("bad", T_("burned"))) if p.get("burned") else "")
                             for p in pool)) + '<p class="dgp-desc">%s</p>' % esc(T_("d.ai"))}
            # حاملِ اعضای استخر در کشو می‌آید نه یال: یالِ عمودی از ردیفِ پایه تا حامل از روی همه‌ی تونل‌ها رد می‌شد
            cars = sorted({roles_all.get(p["dev"], ("", 0))[0] for p in pool} - {""})
            if cars:
                det["ai"]["html"] += kv([(T_("k.carriers"), mono(", ".join(cars)))])
                det["ai"]["related"] = ["t:" + c_ for c_ in cars if c_ in names]
        elif ai and ai.get("main") in names:
            target = "t:" + ai["main"]
        if target:
            edges.append({"from": "sni", "to": target, "tone": "iam", "label": T_("e.ai")})
    # ── کیل‌سوییچ
    ks = f.get("ks") or {}
    if ks.get("rules"):
        nodes.append({"id": "ks", "c": C_IN, "r": B, "label": T_("n.ks"), "tone": "deny", "shape": "dashed",
                      "sub": [T_("n.ks.sub", n=cx.n(ks["rules"]))]})
        if ingress:
            edges.append({"from": "in:" + ingress[-1]["iface"], "to": "ks", "tone": "deny", "dash": True, "label": T_("e.ks")})
        det["ks"] = {"title": T_("n.ks"), "html": kv([
            (T_("k.rules"), esc(cx.n(ks["rules"]))), (T_("k.ifaces"), mono(", ".join(ks.get("ifaces") or [])))]) +
            '<p class="dgp-desc">%s</p>' % esc(T_("d.ks"))}
    # ── WAN و اینترنت
    nodes.append({"id": "wan", "c": C_WAN, "r": 0, "h": R, "label": wan, "tone": "ext",
                  "sub": [T_("n.wan.sub")]})
    nodes.append({"id": "net", "c": C_NET, "r": 0, "h": R, "label": T_("n.net"),
                  "tone": "ext", "shape": "pill"})
    edges.append({"from": "wan", "to": "net", "tone": "ext"})
    det["wan"] = {"title": wan, "html": '<p class="dgp-desc">%s</p>' % esc(T_("d.wan"))}
    det["net"] = {"title": T_("n.net"), "html": '<p class="dgp-desc">%s</p>' % esc(T_("d.net"))}
    # مستقیم: از زیرِ تونل‌ها (فاصله‌ی بینِ ردیف‌ها) تا WAN — از روی هیچ گره‌ای رد نمی‌شود
    gy = B + 0.07                                     # شکافِ بالای ردیفِ پایه
    edges.append({"id": "e:direct", "from": "route", "to": "wan", "tone": "muted", "dash": True,
                  "label": T_("e.direct"), "route": "via", "via": [[C_ROUTE + .5, gy], [C_WAN + .5, gy]]})
    det["e:direct"] = {"title": T_("e.direct"), "html": '<p class="dgp-desc">%s</p>' % esc(T_("d.route.direct", wan=wan))}

    rows_total = R + extra
    return {
        "id": "egress", "title": T_("t.egress"), "root": "egress",
        "diagrams": [{"id": "egress", "kind": "flow", "title": T_("t.egress"), "dir": "rtl" if cx.rtl else "ltr",
                      "grid": {"cols": C_NET + 1, "rows": rows_total, "cw": 196, "rh": 104, "gx": 14},
                      "zones": [{"c": 3, "r": 0, "w": D + 1, "h": max(1, len(order)),
                                 "label": T_("z.tunnels"), "tone": "muted"}] if order else [],
                      "nodes": [{k: v for k, v in n.items() if v is not None} for n in nodes], "edges": edges}],
        "details": det,
        "legend": [{"tone": "ok", "label": T_("lg.ok")}, {"tone": "deny", "label": T_("lg.bad")},
                   {"tone": "muted", "label": T_("lg.off")}, {"tone": "core", "label": T_("lg.route")},
                   {"tone": "app", "label": T_("lg.ecmp")}, {"tone": "iam", "label": T_("lg.ai")},
                   {"tone": "user", "label": T_("lg.user")}, {"tone": "ext", "label": T_("lg.ext")}],
        "summary": egress_summary(f, order, by),
    }


def egress_summary(f, order, by):
    """خلاصه‌ی عددی برای اسلایدِ TV و کارتِ Excel (بی متن)."""
    bad = [i for i in order if (by[i].get("health") or "") in HEALTH_BAD and by[i].get("enabled")]
    groups = (f.get("ecmp") or {}).get("groups") or []
    out = sum(1 for g in groups for x in g.get("tunnels") or [] if (g.get("member") or {}).get(x) == "out")
    tot = sum(len(g.get("tunnels") or []) for g in groups)
    sni = f.get("sni") or {}
    return {"tunnels": len(order), "bad": bad, "ecmp_out": out, "ecmp_total": tot,
            "sni": None if not sni.get("enabled") else bool(sni.get("active"))}


# ── ردیابیِ کاربر (seq) ────────────────────────────────────────────────────
def trace_model(f, cx):
    """«چرا این کاربر قطع است؟» — نردبانِ شواهد از دستگاه تا اینترنت.

    f = {"user": ردیفِ build_stats, "ip": str, "ingress": {iface, ks, subnet},
         "hist": [نمونه‌های peer_history], "decisions": [{kind: default|ecmp|ai, probe, dev, group?}],
         "tunnels": {iface: tunnel_row} (فقط با tun.view؛ وگرنه {}), "wan": str, "can_tun": bool}
    """
    T_ = lambda k, **kw: cx.t("viz." + k, **kw)        # noqa: E731
    u = f.get("user") or {}
    name = u.get("name") or "?"
    ing = (f.get("ingress") or {}).get("iface") or u.get("iface") or "?"
    hs = u.get("handshake") or 0
    hs_age = (cx.now - hs) if hs else None
    rx, tx = series_rates(f.get("hist"))
    code, level = signature("peer", hs_age, rx[-60:], tx[-60:], bool(u.get("enabled", True)))
    tuns = f.get("tunnels") or {}
    can_tun = bool(f.get("can_tun"))
    decisions = [d for d in (f.get("decisions") or []) if d.get("dev")]
    names = set(tuns)
    roles = tunnel_roles(list(tuns.values())) if tuns else {}
    actors = [{"id": "dev", "label": name, "sub": T_("a.dev"), "tone": "user"},
              {"id": "in", "label": ing, "sub": T_("a.in"), "tone": "user"},
              {"id": "rt", "label": T_("n.route"), "sub": mono_plain(f.get("ip")), "tone": "core"}]
    seen = []
    chain = {}
    for d in decisions:
        dev = d["dev"] if can_tun else "egress"
        cur = dev
        while cur and cur not in seen:
            seen.append(cur)
            nxt = roles.get(cur, ("", 0))[0] if can_tun else ""
            chain[cur] = nxt if nxt in names else ""
            cur = chain[cur]
    for x in seen:
        t = tuns.get(x) or {}
        h = t.get("health") or "healthy"
        actors.append({"id": "t:" + x, "label": x if can_tun else T_("a.egress"),
                       "sub": T_("h." + h) if can_tun else "", "tone": HEALTH_TONE.get(h, "core") if can_tun else "core"})
    actors.append({"id": "net", "label": T_("n.net"), "tone": "ext"})
    steps, det, n = [], {}, 0

    def step(**s):
        nonlocal n
        n += 1
        s["n"] = n
        steps.append(s)
        return s
    # ۱) هندشیک
    hs_ok = hs_age is not None and hs_age < ONLINE_AGE
    step(id="s:hs", type="msg", **{"from": "dev", "to": "in"}, label=T_("s.hs", ago=cx.ago(hs)),
         tone="ok" if hs_ok else ("warn" if hs_age is not None else "deny"))
    det["s:hs"] = {"title": T_("s.hs.t"), "html": kv([
        (T_("k.hs"), esc(cx.ago(hs))), (T_("k.endpoint"), mono(u.get("endpoint"))),
        (T_("k.allowed"), mono(u.get("allowed_ips"))), (T_("k.enabled"), lvl("ok" if u.get("enabled", True) else "bad",
                                                                              T_("on" if u.get("enabled", True) else "off"))),
        (T_("k.auto"), esc(u.get("auto_disabled") or ""))]) + '<p class="dgp-desc note">%s</p>' % esc(T_("d.hs"))}
    # ۲) امضای شمارنده‌ها
    step(id="s:sig", type="self", **{"from": "in", "to": "in"}, label=T_("sig.%s.t" % code),
         tone={"ok": "ok", "warn": "warn", "bad": "deny"}.get(level, "muted"))
    det["s:sig"] = {"title": T_("s.sig.t"), "html": kv([
        (T_("k.rate"), esc("↓%s ↑%s" % (cx.rate(u.get("rx_rate")), cx.rate(u.get("tx_rate"))))),
        (T_("k.total"), esc("↓%s ↑%s" % (cx.bytes(u.get("rx")), cx.bytes(u.get("tx"))))),
        (T_("k.month"), esc(cx.bytes((u.get("month_rx") or 0) + (u.get("month_tx") or 0))))]) +
        sig_html(cx, code, level, rx[-60:], tx[-60:])}
    # ۳) تصمیمِ مسیر
    step(id="s:rt", type="msg", **{"from": "in", "to": "rt"},
         label=T_("s.rt", ip=f.get("ip") or "?"), tone="core")
    ks = bool((f.get("ingress") or {}).get("ks"))
    det["s:rt"] = {"title": T_("s.rt.t"), "html": kv(
        [(T_("k.%s" % ("default" if d.get("kind") == "default" else ("ai_path" if d.get("kind") == "ai" else "ecmp")),
             g=d.get("group") or "ECMP"),
          "%s ⇒ %s" % (mono(d.get("probe")), mono(d["dev"] if can_tun else T_("a.egress")))) for d in decisions] +
        [(T_("k.ks"), lvl("ok" if ks else "bad", T_("ks.on" if ks else "ks.off")))]) +
        '<p class="dgp-desc note">%s</p>' % esc(T_("d.rt"))}
    # ۴) هر تصمیم ⇒ تونل، و زنجیره تا اینترنت
    bad_dev = None
    for k, d in enumerate(decisions):
        dev = d["dev"] if can_tun else "egress"
        t = tuns.get(dev) or {}
        h = t.get("health") or "healthy"
        sid = "s:d:%d" % k
        lab = "%s ⇒ %s" % (d.get("probe"), dev if can_tun else T_("a.egress"))
        step(id=sid, type="msg", **{"from": "rt", "to": "t:" + dev}, label=lab,
             tone="deny" if h in HEALTH_BAD else ("app" if d.get("kind") == "ecmp" else ("iam" if d.get("kind") == "ai" else "core")))
        det[sid] = {"title": lab, "html": kv([
            (T_("k.kind"), esc(T_("dk." + (d.get("kind") or "default")))), (T_("k.group"), esc(d.get("group") or "")),
            (T_("k.health"), lvl("bad" if h in HEALTH_BAD else "ok", T_("h." + h)) if can_tun else ""),
            (T_("k.hs"), esc(cx.ago(t.get("handshake"))) if can_tun and t else "")]) +
            ('<p class="dgp-desc note">%s</p>' % esc(T_("hd." + h)) if can_tun else "")}
        if h in HEALTH_BAD and bad_dev is None:
            bad_dev = dev
    done = set()
    for x in seen:
        nxt = chain.get(x) or ""
        if (x, nxt) in done:
            continue
        done.add((x, nxt))
        t = tuns.get(x) or {}
        h = t.get("health") or "healthy"
        sid = "s:c:" + x
        if nxt:
            step(id=sid, type="msg", **{"from": "t:" + x, "to": "t:" + nxt}, label=T_("s.carrier"),
                 tone="deny" if (tuns.get(nxt) or {}).get("health") in HEALTH_BAD else "edge")
        else:
            step(id=sid, type="msg", **{"from": "t:" + x, "to": "net"},
                 label=T_("s.out", wan=(t.get("loop_dev") or f.get("wan") or "")) if can_tun else T_("s.out0"),
                 tone="deny" if h in HEALTH_BAD else "ext")
        det[sid] = {"title": x if can_tun else T_("a.egress"), "html": kv([
            (T_("k.endpoint"), mono(t.get("endpoint")) if can_tun else ""),
            (T_("k.epdev"), mono(t.get("loop_dev")) if can_tun else ""),
            (T_("k.health"), lvl("bad" if h in HEALTH_BAD else "ok", T_("h." + h)) if can_tun else "")])}
        if h in HEALTH_BAD and bad_dev is None:
            bad_dev = x
    # ۵) کیل‌سوییچ وقتی خروجی مرده
    if bad_dev and ks:
        step(id="s:ks", type="note", over=["in", "rt"], label=T_("s.ks"), tone="note")
        det["s:ks"] = {"title": T_("n.ks"), "html": '<p class="dgp-desc">%s</p>' % esc(T_("d.ks"))}
    # ۶) حکم
    verdict = trace_verdict(u, code, bad_dev, can_tun, decisions)
    step(id="s:v", type="note", over=[a["id"] for a in actors], label=T_("v.%s.t" % verdict), tone="note")
    det["s:v"] = {"title": T_("v.h"), "html": '<p class="dgp-desc">%s</p>' % esc(
        T_("v.%s" % verdict, dev=bad_dev or "", name=name, reason=u.get("auto_disabled") or ""))}
    return {"id": "trace", "title": T_("t.trace", name=name), "root": "trace",
            "diagrams": [{"id": "trace", "kind": "seq", "title": T_("t.trace", name=name), "dir": "rtl" if cx.rtl else "ltr",
                          "actors": actors, "steps": steps, "colw": 200}],
            "details": det, "verdict": verdict, "signature": code,
            "legend": [{"tone": "ok", "label": T_("lg.ok")}, {"tone": "warn", "label": T_("lg.warn")},
                       {"tone": "deny", "label": T_("lg.bad")}, {"tone": "note", "label": T_("lg.note")}]}


def mono_plain(s):
    return str(s or "")


def trace_verdict(u, code, bad_dev, can_tun, decisions):
    """نخستین حلقه‌ی شکسته‌ی زنجیره — به همان ترتیبی که عیب‌یابی باید نگاه کند."""
    if not u.get("enabled", True):
        return "auto" if u.get("auto_disabled") else "disabled"
    if code == "never":
        return "never"
    if code == "nat_expired":
        return "nat"
    if code == "offline":
        return "offline"
    if bad_dev:
        return "egress" if can_tun else "egress0"
    if not decisions:
        return "noroute"
    return "ok"


# ── خطِ زمانیِ رویدادها (gantt) ───────────────────────────────────────────
SEV_MARK = {"bad": "leave-bad", "ok": "join", "info": "pre", "warn": "alarm"}
EVENT_SRCS = ("guard", "nqmo", "warp", "audit")      # ترتیبِ نوارهای منبع در gantt

# خطوطِ syslog ِ tunnel-guard (`logger -t tunnel-guard`) ⇒ رویداد. فقط تغییرِ وضعیت و کنش؛
# «صرف‌نظر»، «آزمونِ نود» و گزارشِ تحویلِ تلگرام هر چرخه تکرار می‌شوند و نویزند. ترتیب مهم است:
# «heal» پیش از «fail»، چون خطِ موفقِ نودِ تازه دنباله‌ی «(N نامزدِ ناموفق پیش از آن)» دارد؛
# الگوهای «heal» هیچ خطِ شکستی را نمی‌گیرند (شکست‌ها «applied» یا «— داده رد شد» ندارند).
GUARD_RULES = (
    ("down", "bad", re.compile(r"STATE up->down")),
    ("up", "ok", re.compile(r"STATE down->up")),
    ("verified", "ok", re.compile(r"heal verified")),
    ("heal", "warn", re.compile(r"heal applied|heal: listen-port \S+ -> |node heal: \S+ -> \S+ — داده رد شد")),
    ("fail", "bad", re.compile(r"⚠️|ناموفق|FAILED|داده رد نکرد")),
    ("pin", "info", re.compile(r"^پینِ \S+/32")),
)
GUARD_KINDS = tuple(k for k, _, _ in GUARD_RULES)
_GUARD_SUBJ = re.compile(r"^\[([A-Za-z0-9_.-]+)\]\s*")


def guard_event(msg):
    """یک خطِ لاگِ tunnel-guard ⇒ (iface، نوع، سطح، متنِ بی‌پیشوند) یا None اگر نویز است.
    نوعِ down/up همان «پایین/بالا» ِ خودِ نگهبان است و در down_intervals با رویدادِ پایشِ پنل
    یکی می‌شود — دو ناظرِ مستقل بر یک مسیر."""
    m = _GUARD_SUBJ.match(msg or "")
    if not m:
        return None
    subj, rest = m.group(1), msg[m.end():]
    for kind, sev, rx in GUARD_RULES:
        if rx.search(rest):
            return ("" if subj == "route" else subj), kind, sev, rest
    return None


def down_intervals(events, iface, t0, t1):
    """بازه‌های «پایین» ِ یک تونل از رویدادهای tun.monitor.down/up، iface.loop.found/fix و guard.down/up.
    اگر نخستین رویدادِ بازه «up» باشد، تونل از ابتدای بازه پایین بوده است."""
    evs = sorted((e for e in events if e.get("subject") == iface and e.get("action") in
                  ("tun.monitor.down", "tun.monitor.up", "iface.loop.found", "iface.loop.fix", "guard.down", "guard.up")),
                 key=lambda e: e["ts"])
    out, start = [], None
    for k, e in enumerate(evs):
        down = e["action"] in ("tun.monitor.down", "iface.loop.found", "guard.down")
        if down and start is None:
            start = max(t0, e["ts"])
        elif not down:
            if start is None and k == 0:
                start = t0
            if start is not None:
                out.append([start, min(t1, e["ts"])])
                start = None
    if start is not None:
        out.append([start, t1])
    return out


def timeline_model(f, cx):
    """رویدادهای NQMO، نگهبانِ تونل و ممیزی روی محورِ ۲۴ساعته؛ هر تونل یک نوار به رنگِ کیفیت.

    f = {"t0", "t1", "tunnels": [{iface, health, hours: [{t, bytes}]}],
         "events": [{ts, src: guard|audit|warp|nqmo, subject, action, detail, sev, actor, title?}]}
    """
    T_ = lambda k, **kw: cx.t("viz." + k, **kw)        # noqa: E731
    t0, t1 = float(f["t0"]), float(f["t1"])
    events = sorted(f.get("events") or [], key=lambda e: e["ts"])
    span = t1 - t0
    step_h = 3600 * (3 if span <= 2 * 86400 else 24)
    first = int(t0 // step_h + 1) * step_h
    ticks = [{"t": x, "label": cx.clock(x, with_date=span > 2 * 86400)} for x in range(int(first), int(t1) + 1, int(step_h))]
    lanes, det, steps = [], {}, []
    by_subj = {}
    for e in events:
        by_subj.setdefault(e.get("subject") or "", []).append(e)
    used = set()
    for t in f.get("tunnels") or []:
        i = t["iface"]
        bars = []
        hours = sorted(t.get("hours") or [], key=lambda h: h["t"])
        for h in hours:
            a, b = max(t0, h["t"]), min(t1, h["t"] + 3600)
            if b <= a:
                continue
            bars.append({"a": a, "b": b, "cls": "p", "tip": "%s · %s" % (cx.clock(a), cx.bytes(h.get("bytes")))})
            if (h.get("bytes") or 0) > 0:
                bars.append({"a": a, "b": b, "cls": "t", "tip": "%s · %s" % (cx.clock(a), cx.bytes(h.get("bytes")))})
        if not hours:
            bars.append({"a": t0, "b": t1, "cls": "p-unk", "tip": T_("tl.nodata")})
        for k, (a, b) in enumerate(down_intervals(events, i, t0, t1)):
            key = "down:%s:%d" % (i, k)
            bars.append({"a": a, "b": b, "cls": "q-bad", "key": key,
                         "tip": T_("tl.down", a=cx.clock(a), b=cx.clock(b))})
            det[key] = {"title": T_("tl.down.t", i=i), "html": kv([
                (T_("k.from"), esc(cx.clock(a, True))), (T_("k.to"), esc(cx.clock(b, True))),
                (T_("k.dur"), esc(T_("tl.min", n=cx.n(int((b - a) // 60)))))])}
        marks = []
        for e in by_subj.get(i, []):
            used.add(id(e))
            marks.append(_mark(e, cx, det, steps, i))
        h = t.get("health") or "healthy"
        lanes.append({"id": "lane:" + i, "label": i, "sub": T_("h." + h),
                      "tone": "deny" if h in HEALTH_BAD else None, "bars": bars, "marks": marks})
        det["lane:" + i] = {"title": i, "html": kv([
            (T_("k.health"), lvl("bad" if h in HEALTH_BAD else "ok", T_("h." + h))),
            (T_("k.events"), esc(cx.n(len(by_subj.get(i, [])))))]) + '<p class="dgp-desc note">%s</p>' % esc(T_("d.lane"))}
    for src in EVENT_SRCS:
        rest = [e for e in events if id(e) not in used and e.get("src") == src]
        if not rest:
            continue
        lid = "lane:" + src
        lanes.append({"id": lid, "label": T_("src." + src), "sub": T_("tl.n", n=cx.n(len(rest))),
                      "bars": [], "marks": [_mark(e, cx, det, steps, lid) for e in rest]})
        det[lid] = {"title": T_("src." + src), "html": '<p class="dgp-desc">%s</p>' % esc(T_("d.src." + src))}
    steps.sort(key=lambda s: s["t"])
    for k, s in enumerate(steps, 1):
        s["n"] = k
    return {"id": "timeline", "title": T_("t.timeline"), "root": "timeline",
            "diagrams": [{"id": "timeline", "kind": "gantt", "title": T_("t.timeline"), "t0": t0, "t1": t1, "colw": 170,
                          "ticks": ticks, "bands": [], "lanes": lanes, "steps": steps}],
            "details": det,
            "legend": [{"tone": "muted", "label": T_("lg.idle")}, {"tone": "ok", "label": T_("lg.traffic")},
                       {"tone": "deny", "label": T_("lg.down")}, {"tone": "warn", "label": T_("lg.event")}]}


def _mark(e, cx, det, steps, lane):
    T_ = lambda k, **kw: cx.t("viz." + k, **kw)        # noqa: E731
    key = "ev:%s:%d:%s" % (e.get("src"), int(e["ts"] * 1000), abs(hash((e.get("action"), e.get("subject")))) % 10000)
    title = e.get("title") or e.get("action") or ""
    tip = "%s · %s" % (cx.clock(e["ts"]), title)
    det[key] = {"title": title, "tags": [T_("src." + (e.get("src") or "audit"))], "html": kv([
        (T_("k.when"), esc(cx.clock(e["ts"], True))), (T_("k.subject"), mono(e.get("subject"))),
        (T_("k.action"), mono(e.get("action"))), (T_("k.actor"), esc(e.get("actor") or "")),
        (T_("k.detail"), esc(e.get("detail") or ""))])}
    lid = lane if lane.startswith("lane:") else "lane:" + lane
    steps.append({"id": key, "t": e["ts"], "label": tip, "lane": lid, "ty": {"bad": "leave", "ok": "join"}.get(e.get("sev"), "x")})
    return {"t": e["ts"], "cls": SEV_MARK.get(e.get("sev"), "pre"), "key": key, "tip": tip}


# ── خروجیِ بومیِ Excel: همان مدلِ flow روی بومِ DrawingML ──────────────────
TONE_HEX = {  # (پرکردن، خط، متن) — همان خانواده‌ی رنگ‌های روشنِ SvgStudio (کتاب همیشه روشن چاپ می‌شود)
    "user": ("EFF6FF", "3B82F6", "1E3A8A"), "edge": ("F1F5F9", "64748B", "0F172A"), "core": ("EEF2FF", "6366F1", "312E81"),
    "ext": ("FFF7ED", "EA580C", "7C2D12"), "app": ("ECFDF5", "10B981", "064E3B"), "iam": ("FAF5FF", "9333EA", "581C87"),
    "deny": ("FEF2F2", "DC2626", "7F1D1D"), "ok": ("F0FDF4", "16A34A", "14532D"), "warn": ("FFFBEB", "D97706", "78350F"),
    "note": ("FEFCE8", "CA8A04", "713F12"), "muted": ("F8FAFC", "94A3B8", "334155")}


def flow_to_canvas(X, xl, scale=0.5, link_sheet=None, link_rows=None):
    """نمودارِ flow ِ کاوشگر ⇒ xlsx.Canvas (مختصاتِ دیداری؛ آینه‌کردن کارِ Book است).

    link_rows = {node_id: ردیف} ⇒ کلیک روی گره به ردیفِ جدولِ همان برگه می‌رود (پیوندِ درون‌کتابی)."""
    d = X["diagrams"][0]
    g = d["grid"]
    cw, rh, gx = g["cw"] * scale, g["rh"] * scale, g.get("gx", 14) * scale
    W = g["cols"] * cw
    cv = xl.Canvas(W + 8)
    rtl = d.get("dir", "rtl") == "rtl"

    def box(n):
        c, w = n["c"], n.get("w", 1)
        x = (W - (c + w) * cw) if rtl else c * cw
        return (x + gx, n["r"] * rh + 26 * scale, w * cw - 2 * gx, n.get("h", 1) * rh - 36 * scale)
    R = {n["id"]: box(n) for n in d["nodes"]}
    for z in d.get("zones") or []:
        x = (W - (z["c"] + z["w"]) * cw) if rtl else z["c"] * cw
        f_, l_, t_ = TONE_HEX.get(z.get("tone"), TONE_HEX["muted"])
        cv.shape("zone", x + 2, z["r"] * rh + 2, z["w"] * cw - 4, z["h"] * rh - 4, fill=f_, line=l_, geom="roundRect",
                 dash=True, txbody=xl.body([xl.para(z["label"], 8, True, t_, "r" if rtl else "l")], anchor="t"))
    for e in d["edges"]:
        if e["from"] not in R or e["to"] not in R:
            continue
        ax, ay, aw, ah = R[e["from"]]
        bx, by, bw, bh = R[e["to"]]
        col = TONE_HEX.get(e.get("tone"), TONE_HEX["core"])[1]
        # ساده و خوانا: یالِ افقی بینِ لبه‌های نزدیک، در وسطِ هم‌پوشانیِ عمودی (یا مرکزها)
        oy0, oy1 = max(ay, by), min(ay + ah, by + bh)
        y1 = y2 = (oy0 + oy1) / 2 if oy1 - oy0 > 4 else None
        if y1 is None:
            y1, y2 = ay + ah / 2, by + bh / 2
        x1 = ax if bx < ax else ax + aw
        x2 = bx + bw if bx < ax else bx
        if abs(x2 - x1) < 2 and abs(y2 - y1) > 2:                # هم‌ستون ⇒ عمودی
            x1 = x2 = ax + aw / 2
            y1, y2 = (ay + ah, by) if by > ay else (ay, by + bh)
        cv.line(e.get("id") or "edge", x1, y1, x2, y2, col, lw=1.0, dash=bool(e.get("dash")))
    det = X.get("details") or {}
    for n in d["nodes"]:
        x, y, w, h = R[n["id"]]
        f_, l_, t_ = TONE_HEX.get(n.get("tone"), TONE_HEX["core"])
        paras = [xl.para(n["label"], 8.5, True, t_)] + [xl.para(s, 7, False, "334155") for s in (n.get("sub") or [])[:2]]
        link = None
        if link_sheet and link_rows and n["id"] in link_rows:
            link = "#%s!A%d" % (xl.quote_sheet(link_sheet), link_rows[n["id"]])
        cv.shape(n["id"], x, y, w, h, fill=f_, line=l_, geom="roundRect", dash=n.get("shape") == "dashed",
                 txbody=xl.body(paras), link=link, tip=(det.get(n["id"]) or {}).get("title") or n["label"])
    return cv, g["rows"] * rh + 10
