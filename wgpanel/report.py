# -*- coding: utf-8 -*-
"""کتابِ Excel ِ گزارشِ پنل — تابعِ خالص روی «واقعیت‌ها» (گردآوری در app.py: report_facts).

هر برگه فقط وقتی ساخته می‌شود که خواننده مجوزِ دیدنِ همان بخش را در رابط دارد (همان
گیتِ /api/*)؛ گزارش راهِ دورزدنِ RBAC نیست. نشانیِ IP ِ کلاینت‌ها به‌طورِ پیش‌فرض
پوشانده می‌شود (داده‌ی شخصی است و فایل از پنل بیرون می‌رود).

ماژول هیچ‌چیز import نمی‌کند جز stdlib: نویسنده (xlsx) و مدل‌ساز (viz) را فراخواننده
می‌دهد — app.py آن‌ها را با _pkg_module بار می‌کند (هارنسِ تست import ِ نسبی ندارد).
"""
import ipaddress
import math
from datetime import datetime

HEALTH_BAD = ("loop", "dead", "noreturn", "off")
SIG_CODES = ("ok", "idle", "offline", "nat_expired", "never", "loop", "dead_ep", "no_forward", "disabled")
HEALTH_CODES = ("healthy", "chain", "idle", "noreturn", "dead", "loop", "off")
GB = 1024.0 ** 3


def mask_endpoint(ep):
    """«IP:port» ِ کلاینت ⇒ نشانیِ پوشانده (هشت بیتِ آخرِ IPv4 / ۶۴ بیتِ آخرِ IPv6؛ پورت حذف)."""
    s = str(ep or "").strip()
    if not s or s == "(none)":
        return ""
    host = s
    if s.startswith("["):
        host = s[1:].split("]", 1)[0]
    elif s.count(":") == 1:
        host = s.rsplit(":", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "•"
    if ip.version == 4:
        return ".".join(str(ip).split(".")[:3] + ["•"])
    return ":".join(ip.exploded.split(":")[:4]) + ":•"


def _dt(ts):
    try:
        return datetime.fromtimestamp(float(ts)) if ts else None
    except (TypeError, ValueError, OSError):
        return None


def _date(s):
    try:
        return datetime.strptime(str(s)[:10], "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def _gb(b):
    return round((b or 0) / GB, 3) if b is not None else None


def build(f, cx, xl, V):
    """f = report_facts (پایین)؛ cx = viz.Ctx؛ xl = ماژولِ xlsx؛ V = ماژولِ viz ⇒ بایت‌های xlsx.

    f = {"now", "host", "build", "days", "mask", "perms": set,
         "users": [ردیفِ build_stats], "range_bytes": {(iface, pubkey): بایت}, "daily": [{day, bytes, active}],
         "tunnels": [tunnel_row], "egress": واقعیت‌های viz.egress_model,
         "events": [رویدادِ viz.timeline], "audit": [ردیفِ audit_list], "speed": [ردیفِ speedtest],
         "sys": {"cpu": [{t, v}], "ram": [...], "disk": [...]}, "sysnow": {...}}
    """
    T = lambda k, **kw: cx.t("xl." + k, **kw)          # noqa: E731
    TV = lambda k, **kw: cx.t("viz." + k, **kw)        # noqa: E731
    perms = set(f.get("perms") or ())
    home = T("s.home")
    b = xl.Book(T("title"), home, rtl=cx.rtl, words={
        "yes": T("yes"), "no": T("no"), "unknown": T("unknown"), "back": T("back"),
        "trimmed": T("trimmed"), "trimmed_empty": T("trimmed_empty")}, num=cx.n)
    b.props = {"title": T("title"), "subject": T("subject"), "creator": "wg-panel",
               "keywords": "wireguard, report", "category": T("subject")}
    b.classification = T("class")
    now = _dt(f.get("now")) or datetime.now()
    days = int(f.get("days") or 30)
    mask = bool(f.get("mask", True))
    toc = []                      # (نامِ برگه، شرح)
    findings = []                 # (سطح، متن)

    W = [18, 14, 14, 14, 14, 14, 14, 14]
    dash = b.sheet(home, T("title"), T("home.note", d=cx.n(days)), widths=W, tab=xl.GREEN, title_rows="1:1")

    users = f.get("users") or [] if "wg.view" in perms else []
    tunnels = f.get("tunnels") or [] if "tun.view" in perms else []

    # ── کاربران
    if "wg.view" in perms:
        rng = f.get("range_bytes") or {}
        nm = T("s.users")
        ws = b.sheet(nm, T("users.t"), T("users.note", d=cx.n(days)), widths=[22, 10, 12, 8, 19, 18, 18, 11, 11, 11, 10, 10, 12, 9, 9, 30, 22],
                     tab=xl.BLUE, title_rows="3:3")
        cols = [(T("c.name"), "txt", 22), (T("c.iface"), "txt", 10), (T("c.status"), "txt", 12), (T("c.online"), "txt", 8),
                (T("c.hs"), "dt", 19), (T("c.endpoint"), "txt", 18), (T("c.allowed"), "txt", 18),
                (T("c.month_gb"), "gb", 11), (T("c.range_gb", d=cx.n(days)), "gb", 11), (T("c.life_gb"), "gb", 11),
                (T("c.quota_gb"), "gb", 10), (T("c.quota_pct"), "pct", 10), (T("c.expires"), "date", 12),
                (T("c.days_left"), "int", 9), (T("c.rate"), "num1", 9), (T("c.note"), "txt", 30), (T("c.sig"), "txt", 22)]
        rows = []
        for u in sorted(users, key=lambda u: (u["iface"], u["name"].lower())):
            mtot = (u.get("month_rx") or 0) + (u.get("month_tx") or 0)
            q = u.get("quota_gb")
            try:
                q = float(q) if q not in (None, "") else None
            except (TypeError, ValueError):
                q = None
            pct = round(100.0 * mtot / (q * GB), 1) if q else None
            exp = _date(u.get("expires"))
            left = (exp - now.date()).days if exp else None
            st = T("st.auto", r=u.get("auto_disabled")) if u.get("auto_disabled") else T("st.on" if u.get("enabled") else "st.off")
            hs = u.get("handshake") or 0
            rx, tx = V.series_rates(u.get("hist"))
            code, _lv = V.signature("peer", (cx.now - hs) if hs else None, rx[-60:], tx[-60:], bool(u.get("enabled")))
            if code == "nat_expired":
                findings.append(("warn", T("f.nat", n=u["name"])))
            if pct is not None and pct >= 90:
                findings.append(("bad" if pct >= 100 else "warn", T("f.quota", n=u["name"], p=cx.n(pct))))
            if left is not None and 0 <= left <= 7 and u.get("enabled"):
                findings.append(("warn", T("f.expiry", n=u["name"], d=cx.n(left))))
            try:
                rate = float(u.get("rate_mbit")) if u.get("rate_mbit") not in (None, "") else None
            except (TypeError, ValueError):
                rate = None
            rows.append((u["name"], u["iface"], st, bool(u.get("online")), _dt(hs),
                         mask_endpoint(u.get("endpoint")) if mask else (u.get("endpoint") or ""),
                         u.get("allowed_ips") or "", _gb(mtot), _gb(rng.get((u["iface"], u.get("public_key"))) or 0),
                         _gb((u.get("life_rx") or 0) + (u.get("life_tx") or 0)), q, pct, exp, left, rate,
                         u.get("note") or "", TV("sig.%s.t" % code)))
        first, last = b.table(ws, 3, cols, rows, empty=T("empty"), bars=(7,),
                              cf=[(11, "greaterThanOrEqual", ["100"], xl.BAD, xl.BADTX),
                                  (11, "between", ["75", "99.999"], xl.WARN, xl.WARNTX),
                                  (13, "lessThan", ["0"], xl.BAD, xl.BADTX),
                                  (13, "between", ["0", "7"], xl.WARN, xl.WARNTX)],
                              total=[T("total"), None, None, None, None, None, None, "sum", "sum", "sum"],
                              ltr_cols=(5, 6))
        toc.append((nm, T("users.toc", n=cx.n(len(rows)))))

        # ── مصرفِ روزانه
        nm2 = T("s.daily")
        ws2 = b.sheet(nm2, T("daily.t", d=cx.n(days)), T("daily.note"), widths=[14, 14, 14, 4, 24, 12, 14, 12], tab=xl.TEAL,
                      note_max_width=44)
        daily = [(_date(d["day"]), _gb(d.get("bytes")), d.get("active")) for d in f.get("daily") or []]
        r0 = 3
        f2, l2 = b.table(ws2, r0, [(T("c.day"), "date", 14), (T("c.total_gb"), "gb", 14), (T("c.active"), "int", 14)],
                         daily, empty=T("empty"), bars=(1,), total=[T("total"), "sum", None], freeze=False, filt=False)
        top = sorted(((u["name"], u["iface"], rng.get((u["iface"], u.get("public_key"))) or 0) for u in users),
                     key=lambda x: -x[2])[:25]
        allb = sum(x[2] for x in top) or 0
        b.put(ws2, r0 - 1, 5, T("top.t"), "txt", "sec", border=False)
        # جدولِ دوم کنارِ اولی: ستون‌ها از E (۵) — table همیشه از ستونِ A می‌نویسد، پس دستی
        heads = [T("c.name"), T("c.iface"), T("c.range_gb", d=cx.n(days)), T("c.share")]
        for j, h in enumerate(heads):
            b.put(ws2, r0, 5 + j, h, "txt", "hdr", "hdr", "hdr")
        for k, (n, i, x) in enumerate(top):
            fill = "band" if k % 2 else None
            b.put(ws2, r0 + 1 + k, 5, n, "txt", fill=fill)
            b.put(ws2, r0 + 1 + k, 6, i, "txt", fill=fill)
            b.put(ws2, r0 + 1 + k, 7, _gb(x), "gb", fill=fill)
            b.put(ws2, r0 + 1 + k, 8, round(100.0 * x / allb, 1) if allb else None, "pct", fill=fill)
        if daily:
            b.chart(ws2, max(l2 + 3, r0 + len(top) + 3), 1, "bar", T("daily.chart"), ws2, [2], f2, l2, cat_col=1,
                    colors=[xl.GREEN], width_cm=26, height_cm=8, y_title="GB")
            b.chart(dash, 40, 1, "line", T("daily.chart"), ws2, [2], f2, l2, cat_col=1, colors=[xl.BLUE],
                    width_cm=24, height_cm=7, y_title="GB")
        toc.append((nm2, T("daily.toc")))

    # ── تونل‌ها
    if "tun.view" in perms:
        nm = T("s.tunnels")
        ws = b.sheet(nm, T("tun.t"), T("tun.note"), widths=[11, 11, 14, 11, 22, 11, 14, 19, 11, 11, 11, 11, 22, 26],
                     tab=xl.PURPLE, title_rows="3:3")
        eg = f.get("egress") or {}
        roles = V.tunnel_roles(tunnels)
        mem = {}
        for g in (eg.get("ecmp") or {}).get("groups") or []:
            for x in g.get("tunnels") or []:
                m = (g.get("member") or {}).get(x)
                mem.setdefault(x, []).append("%s:%s" % (g.get("name") or "ECMP", T("mem.out") if m == "out" else T("mem.in")))
        rows = []
        for tt in tunnels:
            h = tt.get("health") or "off"
            car = roles.get(tt["iface"], ("", 0))[0]
            hs = tt.get("handshake") or 0
            rx, tx = V.series_rates(tt.get("hist"))
            code, _lv = V.signature("tunnel", (cx.now - hs) if hs else None, rx[-60:], tx[-60:], True, tt.get("rx"))
            if not tt.get("active"):
                code = None
            if h in HEALTH_BAD and tt.get("enabled"):
                findings.append(("bad", T("f.tunnel", i=tt["iface"], h=TV("h." + h))))
            rows.append((tt["iface"], tt.get("kind") or "", TV("role.tag.sub") if car else TV("role.tag.mother"), car or "",
                         tt.get("endpoint") or "", tt.get("loop_dev") or "", TV("h." + h), _dt(hs) if tt.get("active") else None,
                         round((tt.get("rx_rate") or 0) / 1024.0, 1), round((tt.get("tx_rate") or 0) / 1024.0, 1),
                         _gb(tt.get("rx")), _gb(tt.get("tx")), "، ".join(mem.get(tt["iface"], [])) if cx.rtl else ", ".join(mem.get(tt["iface"], [])),
                         TV("sig.%s.t" % code) if code else ""))
        b.table(ws, 3, [(T("c.iface"), "txt", 11), (T("c.kind"), "txt", 11), (T("c.role"), "txt", 14), (T("c.carrier"), "txt", 11),
                        (T("c.endpoint"), "txt", 22), (T("c.epdev"), "txt", 11), (T("c.health"), "txt", 14), (T("c.hs"), "dt", 19),
                        (T("c.rx_kbs"), "num1", 11), (T("c.tx_kbs"), "num1", 11), (T("c.rx_gb"), "gb", 11), (T("c.tx_gb"), "gb", 11),
                        (T("c.ecmp"), "txt", 22), (T("c.sig"), "txt", 26)],
                rows, empty=T("empty"), bars=(8,),
                cf=[(6, "equal", ['"%s"' % TV("h." + h).replace('"', '""')], xl.BAD, xl.BADTX) for h in HEALTH_BAD],
                ltr_cols=(4,))
        toc.append((nm, T("tun.toc", n=cx.n(len(rows)))))

        # ── نقشه‌ی مسیر: همان مدلِ flow ِ پنل، بومی (DrawingML) + جدولِ گره‌ها
        nm = T("s.egress")
        X = V.egress_model(eg, cx)
        g = X["diagrams"][0]["grid"]
        scale = 0.5
        cols_n = max(8, int(math.ceil(g["cols"] * g["cw"] * scale / 60.0)) + 1)
        ws = b.sheet(nm, T("egress.t"), T("egress.note"), widths=[10] * cols_n, tab=xl.GREEN)
        ws.right_margin = 1.0
        y0 = 24 + 30 + 8                               # زیرِ عنوان و یادداشت
        dets = X.get("details") or {}
        nodes = X["diagrams"][0]["nodes"]
        cv_h = g["rows"] * g["rh"] * scale + 10
        # ردیفِ جدول = نخستین ردیفی که بالایش زیرِ بوم است
        top, r = 0.0, 1
        hts = {1: ws.row_h.get(1, 15), 2: ws.row_h.get(2, 15)}
        while top < y0 + cv_h + 10:
            top += hts.get(r, ws.row_h.get(r, 15))
            r += 1
        tr = r + 1
        link_rows = {n["id"]: tr + 1 + k for k, n in enumerate(nodes)}
        cv, _h = V.flow_to_canvas(X, xl, scale=scale, link_sheet=nm, link_rows=link_rows)
        for k, it in enumerate(cv.items):              # جابه‌جاییِ عمودیِ کلِ بوم به زیرِ عنوان
            x, w, yy, hh, xml, fh, fv = it
            cv.items[k] = (x, w, yy + y0, hh, xml, fh, fv)
        ws.canvas = cv
        b.put(ws, tr - 1, 1, T("egress.table"), "txt", "sec", border=False)
        b.merge(ws, tr - 1, 1, tr - 1, min(cols_n, 8))
        trows = []
        for n in nodes:
            d = dets.get(n["id"]) or {}
            trows.append((n["label"], TV("tone." + (n.get("tone") or "core")), " · ".join(n.get("sub") or []),
                          V.html_text(d.get("html") or "")))
        ws.widths = [16, 14, 26, 60] + [10] * max(0, cols_n - 4)
        b.table(ws, tr, [(T("c.node"), "txt", 16), (T("c.state"), "txt", 14), (T("c.summary"), "txt", 26),
                         (T("c.details"), "txt", 60)], trows, empty=T("empty"), freeze=False, filt=False)
        # پهنای ستون‌ها بعد از ساختنِ بوم عوض شد: بی‌اثر است — لنگرِ هر شکل در Book._drawing از پهنای
        # واقعیِ ستون‌ها حساب می‌شود و آینه‌کردن فقط به پهنای خودِ بوم (cv.width) وابسته است.
        toc.append((nm, T("egress.toc")))

        # ── رویدادها
        nm = T("s.events")
        ws = b.sheet(nm, T("ev.t", d=cx.n(days)), T("ev.note"), widths=[19, 10, 14, 26, 14, 50, 10], tab=xl.WARNTX, title_rows="3:3")
        ev = sorted(f.get("events") or [], key=lambda e: -e["ts"])
        b.table(ws, 3, [(T("c.when"), "dt", 19), (T("c.src"), "txt", 10), (T("c.subject"), "txt", 14), (T("c.event"), "txt", 26),
                        (T("c.actor"), "txt", 14), (T("c.detail"), "txt", 50), (T("c.sev"), "txt", 10)],
                [(_dt(e["ts"]), TV("src." + (e.get("src") or "audit")), e.get("subject") or "", e.get("title") or e.get("action") or "",
                  e.get("actor") or "", e.get("detail") or "", T("sev." + (e.get("sev") or "info"))) for e in ev],
                empty=T("empty"), cf=[(6, "equal", ['"%s"' % T("sev.bad")], xl.BAD, xl.BADTX),
                                      (6, "equal", ['"%s"' % T("sev.warn")], xl.WARN, xl.WARNTX)])
        toc.append((nm, T("ev.toc", n=cx.n(len(ev)))))

    # ── ممیزی
    if "audit.view" in perms:
        nm = T("s.audit")
        ws = b.sheet(nm, T("audit.t", d=cx.n(days)), T("audit.note"), widths=[19, 14, 11, 24, 22, 44, 15, 8], tab=xl.MUTE, title_rows="3:3")
        rows = [(_dt(r["ts"]), r.get("actor") or "", r.get("category") or "", r.get("action_text") or r.get("action") or "",
                 r.get("target") or "", r.get("detail") or "", r.get("ip") or "", bool(r.get("ok")))
                for r in f.get("audit") or []]
        b.table(ws, 3, [(T("c.when"), "dt", 19), (T("c.actor"), "txt", 14), (T("c.cat"), "txt", 11), (T("c.event"), "txt", 24),
                        (T("c.target"), "txt", 22), (T("c.detail"), "txt", 44), (T("c.ip"), "txt", 15), (T("c.ok"), "txt", 8)],
                rows, empty=T("empty"), cf=[(7, "equal", ['"%s"' % T("no")], xl.BAD, xl.BADTX)], ltr_cols=(6,))
        toc.append((nm, T("audit.toc", n=cx.n(len(rows)))))

    # ── تستِ سرعت و سامانه
    if "sys.view" in perms:
        nm = T("s.speed")
        ws = b.sheet(nm, T("speed.t"), T("speed.note"), widths=[19, 11, 10, 11, 11, 10, 10, 8, 30], tab=xl.TEAL, title_rows="3:3")
        rows = [(_dt(r.get("ts")), r.get("iface") or "", r.get("ping_ms"),
                 round(r["down_bps"] / 1e6, 1) if r.get("down_bps") else None,
                 round(r["up_bps"] / 1e6, 1) if r.get("up_bps") else None,
                 r.get("jitter_ms"), r.get("loss_pct"), bool(r.get("ok")), r.get("error") or "")
                for r in sorted(f.get("speed") or [], key=lambda r: r.get("ts") or 0)]
        sf, sl = b.table(ws, 3, [(T("c.when"), "dt", 19), (T("c.iface"), "txt", 11), (T("c.ping"), "num1", 10),
                                 (T("c.down"), "mbps", 11), (T("c.up"), "mbps", 11), (T("c.jitter"), "num1", 10),
                                 (T("c.loss"), "num1", 10), (T("c.ok"), "txt", 8), (T("c.error"), "txt", 30)],
                         rows, empty=T("empty"), bars=(3,))
        if rows:
            b.chart(ws, sl + 3, 1, "line", T("speed.chart"), ws, [4, 5], sf, sl, cat_col=1,
                    colors=[xl.GREEN, xl.BLUE], width_cm=26, height_cm=8, y_title="Mbps", dashed=(1,))
        toc.append((nm, T("speed.toc", n=cx.n(len(rows)))))

        nm = T("s.sys")
        ws = b.sheet(nm, T("sys.t", d=cx.n(days)), T("sys.note"), widths=[14, 11, 11, 11], tab=xl.MUTE)
        sy = f.get("sys") or {}
        keys = sorted({p["t"] for k in ("cpu", "ram", "disk") for p in sy.get(k) or []})
        val = {k: {p["t"]: round(p["v"], 1) for p in sy.get(k) or []} for k in ("cpu", "ram", "disk")}
        rows = [(_date(t_) or t_, val["cpu"].get(t_), val["ram"].get(t_), val["disk"].get(t_)) for t_ in keys]
        yf, yl = b.table(ws, 3, [(T("c.day"), "date", 14), ("CPU %", "num1", 11), ("RAM %", "num1", 11), (T("c.disk"), "num1", 11)],
                         rows, empty=T("empty"), scales=[(1, "E6F4EA", "FEF3C7", "FDE8E8")], freeze=False)
        if rows:
            b.chart(ws, yl + 3, 1, "line", T("sys.chart"), ws, [2, 3, 4], yf, yl, cat_col=1,
                    colors=[xl.BADTX, xl.BLUE, xl.MUTE], width_cm=24, height_cm=8, y_min=0, y_max=100)
        toc.append((nm, T("sys.toc")))

    # ── واژه‌نامه
    nm = T("s.gloss")
    ws = b.sheet(nm, T("gloss.t"), "", widths=[24, 80], tab=xl.MUTE)
    rows = [(TV("h." + h), TV("hd." + h)) for h in HEALTH_CODES] + \
           [(TV("sig.%s.t" % s), TV("sig." + s)) for s in SIG_CODES]
    b.table(ws, 3, [(T("c.term"), "txt", 24), (T("c.meaning"), "txt", 80)], rows, filt=False, freeze=False)
    toc.append((nm, T("gloss.toc")))

    # ── داشبورد (آخر ساخته می‌شود چون یافته‌ها و فهرست از برگه‌ها می‌آیند)
    r = 3
    r = b.kv(dash, r, [(T("k.host"), f.get("host") or "", "txt"), (T("k.build"), f.get("build") or "", "txt"),
                       (T("k.generated"), now, "dt"), (T("k.range"), T("k.range.v", d=cx.n(days)), "txt"),
                       (T("k.mask"), T("yes") if mask else T("no"), "txt")])
    r += 1
    cards = []
    if users:
        on = sum(1 for u in users if u.get("online"))
        off = sum(1 for u in users if not u.get("enabled"))
        mtot = sum((u.get("month_rx") or 0) + (u.get("month_tx") or 0) for u in users)
        cards += [(T("card.users"), len(users), "int", T("card.users.sub", n=cx.n(off)), None),
                  (T("card.online"), on, "int", "", "ok" if on else None),
                  (T("card.month"), _gb(mtot), "gb", "GB", None)]
    if "tun.view" in perms:
        bad = [x for x in tunnels if (x.get("health") or "") in HEALTH_BAD and x.get("enabled")]
        cards.append((T("card.tunnels"), len(tunnels) - len(bad), "int", T("card.tunnels.sub", n=cx.n(len(tunnels))),
                      "bad" if bad else "ok"))
        sm = V.egress_model(f.get("egress") or {}, cx).get("summary") or {}
        if sm.get("ecmp_total"):
            cards.append((T("card.ecmp"), sm["ecmp_total"] - sm["ecmp_out"], "int",
                          T("card.ecmp.sub", n=cx.n(sm["ecmp_total"])), "warn" if sm["ecmp_out"] else "ok"))
        if sm.get("sni") is not None:
            cards.append((T("card.sni"), T("on") if sm["sni"] else T("off"), "txt", "", "ok" if sm["sni"] else "bad"))
    if cards:
        r = b.section(dash, r, T("h.kpi"))
        r = b.cards(dash, r, cards, per_row=4, span=2)
    r = b.section(dash, r + 1, T("h.findings"))
    lvl_order = {"bad": 0, "warn": 1, "ok": 2}
    if findings:
        for lv, txt in sorted(findings, key=lambda x: lvl_order.get(x[0], 3))[:40]:
            b.put(dash, r, 1, T("sev." + lv), "txt", {"bad": "badtx", "warn": "warntx"}.get(lv, "oktx"),
                  {"bad": "bad", "warn": "warn"}.get(lv, "ok"), "c")
            b.put(dash, r, 2, txt, "txt", align="wrap")
            b.merge(dash, r, 2, r, 8)
            r += 1
    else:
        r = b.para(dash, r, T("f.none"))
    r = b.section(dash, r + 1, T("h.toc"))
    for nm_, desc in toc:
        b.link(dash, r, 1, nm_, nm_, border=True)
        b.put(dash, r, 2, desc, "txt")
        b.merge(dash, r, 2, r, 8)
        r += 1
    # نمودارِ روزانه روی داشبورد زیرِ فهرست (اگر ساخته شده): ردیفش را به پایینِ محتوا ببر
    for k, ch in enumerate(dash.charts):
        dash.charts[k] = (r + 2,) + ch[1:]
    return b.save()
