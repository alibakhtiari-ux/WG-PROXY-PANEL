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


def range_words(f, cx, T):
    """سه متنی که بازه را می‌گویند: «N روزِ اخیر» وقتی بازه به امروز می‌رسد، وگرنه «از a تا b»."""
    days = int(f.get("days") or 30)
    if f.get("recent", True) or not f.get("span_text"):
        return {"home": T("home.note", d=cx.n(days)), "users": T("users.note", d=cx.n(days)),
                "kv": T("k.range.v", d=cx.n(days))}
    a, b = f["span_text"]
    return {"home": T("home.note.span", a=a, b=b, d=cx.n(days)),
            "users": T("users.note.span", a=a, b=b, d=cx.n(days)),
            "kv": T("k.range.span", a=a, b=b, d=cx.n(days))}


def _num(v):
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _px_status(u, T):
    if u.get("auto_disabled"):
        return T("st.auto", r=u.get("auto_disabled"))
    return T("st.on" if u.get("enabled") else "st.off")


def _nq_quality(m, mode, cx):
    """برچسبِ کیفیت؛ در حالتِ فقط‌مشاهده موتور عمداً رتبه نمی‌دهد و «—» گمراه‌کننده است."""
    q = (m or {}).get("quality")
    if q:
        return cx.t("ui.nqmo.q." + q)
    return cx.t("xl.nq.obs") if mode == "OBSERVATION_ONLY" else "—"


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
    rw = range_words(f, cx, T)
    dash = b.sheet(home, T("title"), rw["home"], widths=W, tab=xl.GREEN, title_rows="1:1")

    users = f.get("users") or [] if "wg.view" in perms else []
    tunnels = f.get("tunnels") or [] if "tun.view" in perms else []

    # ── کاربران
    if "wg.view" in perms:
        rng = f.get("range_bytes") or {}
        nm = T("s.users")
        ws = b.sheet(nm, T("users.t"), rw["users"], widths=[22, 10, 12, 8, 19, 18, 18, 11, 11, 11, 10, 10, 12, 9, 9, 30, 22],
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

    # ── کاربرانِ پروکسی
    if "proxy.view" in perms and f.get("proxy_users") is not None:
        nm = T("s.proxy")
        ws = b.sheet(nm, T("px.t"), T("px.note", d=cx.n(days)), widths=[18, 12, 12, 16, 9, 10, 11, 11, 10, 12, 9, 22, 10, 19, 19, 30], tab=xl.PURPLE, title_rows="3:3")
        rows = []
        for u in f.get("proxy_users") or []:
            q = _num(u.get("quota_gb"))
            mb = u.get("month_bytes") or 0
            pct = round(100.0 * mb / (q * GB), 1) if q else None
            exp = _date(u.get("expires"))
            left = (exp - now.date()).days if exp else None
            if pct is not None and pct >= 90:
                findings.append(("bad" if pct >= 100 else "warn", T("f.quota", n=u["username"], p=cx.n(pct))))
            if left is not None and 0 <= left <= 7 and u.get("enabled"):
                findings.append(("warn", T("f.expiry", n=u["username"], d=cx.n(left))))
            rate = _num(u.get("rate_kbit"))
            rows.append((u["username"], _px_status(u, T), T("px.proto." + (u.get("protocol") or "both")),
                         T("px.auth.src" if u.get("noauth") else "px.auth.pw"),
                         round(rate / 1000.0, 1) if rate else None, q or None, _gb(mb), _gb(u.get("range_bytes")),
                         pct, exp, left, u.get("allow_src") or "", u.get("clients") or 0,
                         _dt(u.get("last_seen")), _dt(u.get("created")), u.get("note") or ""))
        b.table(ws, 3, [(T("c.username"), "txt", 18), (T("c.status"), "txt", 12), (T("c.proto"), "txt", 12),
                        (T("c.auth"), "txt", 16), (T("c.rate"), "num1", 9), (T("c.quota_gb"), "gb", 10),
                        (T("c.month_gb"), "gb", 11), (T("c.range_gb", d=cx.n(days)), "gb", 11),
                        (T("c.quota_pct"), "pct", 10), (T("c.expires"), "date", 12), (T("c.days_left"), "int", 9),
                        (T("c.allow_src"), "txt", 22), (T("c.clients"), "int", 10), (T("c.last_seen"), "dt", 19),
                        (T("c.created"), "dt", 19), (T("c.note"), "txt", 30)],
                rows, empty=T("empty"), bars=(6,),
                cf=[(8, "greaterThanOrEqual", ["100"], xl.BAD, xl.BADTX),
                    (8, "between", ["75", "99.999"], xl.WARN, xl.WARNTX),
                    (10, "between", ["0", "7"], xl.WARN, xl.WARNTX)],
                total=[T("total"), None, None, None, None, None, "sum", "sum"], ltr_cols=(11,))
        toc.append((nm, T("px.toc", n=cx.n(len(rows)))))

        nm = T("s.proxy_daily")
        ws = b.sheet(nm, T("pxd.t", d=cx.n(days)), T("pxd.note"), widths=[14, 14, 14], tab=xl.TEAL)
        rows = [(_date(d["day"]), _gb(d.get("bytes")), d.get("active")) for d in f.get("proxy_daily") or []]
        pf, pl = b.table(ws, 3, [(T("c.day"), "date", 14), (T("c.total_gb"), "gb", 14), (T("c.active"), "int", 14)],
                         rows, empty=T("empty"), bars=(1,), total=[T("total"), "sum", None], freeze=False, filt=False)
        if rows:
            b.chart(ws, pl + 3, 1, "bar", T("pxd.chart"), ws, [2], pf, pl, cat_col=1,
                    colors=[xl.PURPLE], width_cm=26, height_cm=8, y_title="GB")
        toc.append((nm, T("pxd.toc")))

    # ── کیفیتِ ارتباط (WG-NQMO)
    nq = f.get("nqmo")
    if "nqmo.view" in perms and nq is not None:
        nm = T("s.nqmo")
        ws = b.sheet(nm, T("nq.t"), T("nq.note"), widths=[18, 10, 22, 11, 11, 9, 10, 10, 10, 11, 14, 9, 26], tab=xl.BLUE, title_rows="3:3")
        if not nq.get("available"):
            b.para(ws, 3, cx.t("ui.nqmo.why." + (nq.get("why") or "error")))
        else:
            mode = nq.get("mode")
            rows = []
            for p in sorted(nq.get("peers") or [], key=lambda p: (-(p.get("open") or 0), p["name"].lower())):
                m = p.get("summary") or {}
                lp = m.get("loss_point")
                rows.append((p["name"], p["iface"], _nq_quality(m, mode, cx), m.get("rtt_ms_med"), m.get("rtt_ms_min"),
                             m.get("rtt_n") or 0, round(lp * 100, 3) if lp is not None else None,
                             round(m["loss_lb"] * 100, 3) if m.get("loss_lb") is not None else None,
                             round(m["loss_ub"] * 100, 3) if m.get("loss_ub") is not None else None,
                             m.get("loss_n") or 0,
                             cx.t("ui.nqmo.mtu." + m["mtu_status"]) if m.get("mtu_status") else "—",
                             p.get("open") or 0,
                             cx.t("ui.nqmo.cls." + p["top_class"]) if p.get("top_class") else ""))
            nf, nl = b.table(ws, 3, [(T("c.name"), "txt", 18), (T("c.iface"), "txt", 10), (T("nq.c.q"), "txt", 22),
                                     (T("nq.c.rtt"), "num1", 11), (T("nq.c.rtt_min"), "num1", 11), (T("nq.c.rtt_n"), "int", 9),
                                     (T("nq.c.loss"), "num2", 10), (T("nq.c.loss_lb"), "num2", 10), (T("nq.c.loss_ub"), "num2", 10),
                                     (T("nq.c.pkts"), "int", 11), (T("nq.c.mtu"), "txt", 14), (T("nq.c.open"), "int", 9),
                                     (T("nq.c.top"), "txt", 26)],
                             rows, empty=T("empty"), bars=(3,), cf=[(11, "greaterThan", ["0"], xl.WARN, xl.WARNTX)])
            r = nl + 3
            b.put(ws, r, 1, T("nq.global"), "txt", "sec", border=False)
            g = [(cx.t("ui.nqmo.cls." + d["class"]), cx.t("ui.nqmo.lv." + d["confidence"]),
                  d.get("subject") or cx.t("ui.nqmo.scope." + d["scope"])) for d in nq.get("global") or []]
            b.table(ws, r + 1, [(T("nq.c.class"), "txt", 26), (T("nq.c.conf"), "txt", 14), (T("c.subject"), "txt", 18)],
                    g, empty=T("empty"), freeze=False, filt=False)
        toc.append((nm, T("nq.toc")))

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
                       (T("k.generated"), now, "dt"), (T("k.range"), rw["kv"], "txt"),
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


def build_user(f, cx, xl, V):
    """گزارشِ کاملِ یک کاربر (وایرگارد یا پروکسی) در یک بازه. f = app.user_report_facts.

    هر روز و هر ساعتِ بازه یک ردیف دارد (صفر جایی که ترافیکی نبوده)، تا جمع‌ها و
    نمودارها بازه‌ی پیوسته را نشان بدهند نه فقط روزهای پر را."""
    T = lambda k, **kw: cx.t("xl." + k, **kw)          # noqa: E731
    perms = set(f.get("perms") or ())
    u = f.get("user") or {}
    wg = f.get("kind") == "wg"
    name = u.get("name") if wg else u.get("username")
    home = T("s.home")
    b = xl.Book(T("u.title", n=name), home, rtl=cx.rtl, words={
        "yes": T("yes"), "no": T("no"), "unknown": T("unknown"), "back": T("back"),
        "trimmed": T("trimmed"), "trimmed_empty": T("trimmed_empty")}, num=cx.n)
    b.props = {"title": T("u.title", n=name), "subject": T("u.subject"), "creator": "wg-panel",
               "keywords": "wireguard, proxy, report", "category": T("u.subject")}
    b.classification = T("class")
    now = _dt(f.get("now")) or datetime.now()
    days = int(f.get("days") or 1)
    mask = bool(f.get("mask", True))
    rw = range_words(f, cx, T)
    toc, findings = [], []
    W = [18, 14, 14, 14, 14, 14, 14, 14]
    dash = b.sheet(home, T("u.title", n=name), rw["home"], widths=W, tab=xl.GREEN, title_rows="1:1")

    # ── روزانه
    daily = f.get("daily") or []
    nm = T("s.daily")
    ws = b.sheet(nm, T("daily.t", d=cx.n(days)), T("u.daily.note"), widths=[14, 14, 14, 14], tab=xl.TEAL)
    if wg:
        drows = [(_date(d), _gb(rx), _gb(tx), _gb(rx + tx)) for d, rx, tx in daily]
        dcols = [(T("c.day"), "date", 14), (T("c.rx_gb"), "gb", 14), (T("c.tx_gb"), "gb", 14), (T("c.total_gb"), "gb", 14)]
        tot = [T("total"), "sum", "sum", "sum"]
        series, totcol = [2, 3], 4
    else:
        drows = [(_date(d), _gb(x)) for d, x in daily]
        dcols = [(T("c.day"), "date", 14), (T("c.total_gb"), "gb", 14)]
        tot = [T("total"), "sum"]
        series, totcol = [2], 2
    df, dl = b.table(ws, 3, dcols, drows, empty=T("empty"), bars=(totcol - 1,), total=tot, freeze=False, filt=False)
    if drows:
        b.chart(ws, dl + 3, 1, "bar", T("daily.chart"), ws, series, df, dl, cat_col=1, stacked=wg,
                colors=[xl.GREEN, xl.BLUE], width_cm=26, height_cm=8, y_title="GB")
        b.chart(dash, 40, 1, "bar", T("daily.chart"), ws, series, df, dl, cat_col=1, stacked=wg,
                colors=[xl.GREEN, xl.BLUE], width_cm=24, height_cm=7, y_title="GB")
    toc.append((nm, T("u.daily.toc", n=cx.n(len(drows)))))

    # ── ساعتی (۲۱ روزِ اخیر نگه داشته می‌شود)
    hourly = f.get("hourly") or []
    nm = T("s.hourly")
    note = T("u.hourly.note")
    if f.get("hourly_cut"):
        note += " " + T("u.hourly.cut", d=cx.n(21))
    ws = b.sheet(nm, T("u.hourly.t"), note, widths=[19, 14, 14, 14], tab=xl.TEAL)
    MB = 1024.0 ** 2
    if wg:
        hrows = [(_hour(hh), round(rx / MB, 1), round(tx / MB, 1), round((rx + tx) / MB, 1)) for hh, rx, tx in hourly]
        hcols = [(T("c.hour"), "dt", 19), (T("c.rx_mb"), "num1", 14), (T("c.tx_mb"), "num1", 14), (T("c.total_mb"), "num1", 14)]
        htot = [T("total"), "sum", "sum", "sum"]
    else:
        hrows = [(_hour(hh), round(x / MB, 1)) for hh, x in hourly]
        hcols = [(T("c.hour"), "dt", 19), (T("c.total_mb"), "num1", 14)]
        htot = [T("total"), "sum"]
    hf, hl = b.table(ws, 3, hcols, hrows, empty=T("empty"), bars=(len(hcols) - 1,), total=htot, freeze=True, filt=False)
    if hrows:
        b.chart(ws, hl + 3, 1, "line", T("u.hourly.chart"), ws, series, hf, hl, cat_col=1,
                colors=[xl.GREEN, xl.BLUE], width_cm=28, height_cm=8, y_title="MB")
    toc.append((nm, T("u.hourly.toc", n=cx.n(len(hrows)))))

    # ── جمع‌ها و یافته‌ها
    if wg:
        rx_t = sum(r[1] for r in daily)
        tx_t = sum(r[2] for r in daily)
        per_day = [(d, rx + tx) for d, rx, tx in daily]
    else:
        rx_t = tx_t = None
        per_day = [(d, x) for d, x in daily]
    total = sum(x for _, x in per_day)
    active = sum(1 for _, x in per_day if x > 0)
    peak = max(per_day, key=lambda x: x[1]) if per_day else None
    peak_h = None
    if hourly:
        ph = max(hourly, key=lambda r: sum(r[1:]))
        peak_h = (ph[0], sum(ph[1:]))
    if wg:
        mb = (u.get("month_rx") or 0) + (u.get("month_tx") or 0)
        life = (u.get("life_rx") or 0) + (u.get("life_tx") or 0)
    else:
        mb = u.get("month_bytes") or 0
        life = None
    q = _num(u.get("quota_gb"))
    pct = round(100.0 * mb / (q * GB), 1) if q else None
    exp = _date(u.get("expires"))
    left = (exp - now.date()).days if exp else None
    if pct is not None and pct >= 90:
        findings.append(("bad" if pct >= 100 else "warn", T("f.quota", n=name, p=cx.n(pct))))
    if left is not None and left < 0:
        findings.append(("bad", T("u.f.expired", d=cx.n(-left))))
    elif left is not None and left <= 7 and u.get("enabled"):
        findings.append(("warn", T("f.expiry", n=name, d=cx.n(left))))
    if u.get("auto_disabled"):
        findings.append(("bad", T("st.auto", r=u.get("auto_disabled"))))
    elif not u.get("enabled"):
        findings.append(("warn", T("st.off")))
    if total == 0:
        findings.append(("warn", T("u.f.idle")))

    # ── وایرگارد: مسیرِ کاربر (همان نمای ردگیریِ پنل، بومی) + جدولِ شواهدِ هر گام
    X = f.get("trace") if wg else None
    if X:
        nm = T("s.trace")
        scale = 0.5
        d = X["diagrams"][0]
        cw = d.get("colw", 200) * scale
        cols_n = max(8, int(math.ceil(cw * len(d["actors"]) / 60.0)) + 1)
        ws = b.sheet(nm, X.get("title") or T("tr.t"), T("tr.note"), widths=[10] * cols_n, tab=xl.GREEN)
        ws.right_margin = 1.0
        y0 = 24 + 30 + 8
        cv, cv_h = V.seq_to_canvas(X, xl, scale=scale)
        for k, it in enumerate(cv.items):
            x, w, yy, hh, xml, fh, fv = it
            cv.items[k] = (x, w, yy + y0, hh, xml, fh, fv)
        ws.canvas = cv
        top, r = 0.0, 1
        while top < y0 + cv_h + 10:
            top += ws.row_h.get(r, 15)
            r += 1
        tr = r + 1
        b.put(ws, tr - 1, 1, T("tr.table"), "txt", "sec", border=False)
        b.merge(ws, tr - 1, 1, tr - 1, min(cols_n, 8))
        dets = X.get("details") or {}
        trows = [(s.get("n"), s.get("label") or "", V.html_text((dets.get(s.get("id")) or {}).get("html") or ""))
                 for s in d.get("steps") or []]
        ws.widths = [8, 34, 70] + [10] * max(0, cols_n - 3)
        b.table(ws, tr, [(T("tr.c.n"), "int", 8), (T("tr.c.step"), "txt", 34), (T("c.details"), "txt", 70)],
                trows, empty=T("empty"), freeze=False, filt=False)
        if X.get("verdict") not in (None, "ok"):
            findings.append(("warn", (V.html_text((dets.get("s:v") or {}).get("html") or "")
                                      or d["steps"][-1].get("label") or "")))
        toc.append((nm, T("tr.toc")))

    # ── وایرگارد: کیفیتِ ارتباط و لینک‌های اشتراک
    if wg and f.get("nqmo") is not None:
        nq = f["nqmo"]
        nm = T("s.nqmo")
        ws = b.sheet(nm, T("nq.t"), T("nq.note"), widths=[22, 16, 16, 16], tab=xl.BLUE)
        r = 3
        if not nq.get("available"):
            r = b.para(ws, r, cx.t("ui.nqmo.why." + (nq.get("why") or "error")))
        else:
            m = nq.get("summary")
            if m is None:
                r = b.para(ws, r, cx.t("ui.nqmo.nosummary"))
            else:
                lp = m.get("loss_point")
                r = b.kv(ws, r, [
                    (T("nq.c.q"), _nq_quality(m, nq.get("mode"), cx), "txt"),
                    (T("nq.c.rtt"), m.get("rtt_ms_med"), "num1"), (T("nq.c.rtt_min"), m.get("rtt_ms_min"), "num1"),
                    (T("nq.c.rtt_n"), m.get("rtt_n") or 0, "int"),
                    (T("nq.c.loss"), round(lp * 100, 3) if lp is not None else None, "num2"),
                    (T("nq.c.loss_lb"), round(m["loss_lb"] * 100, 3) if m.get("loss_lb") is not None else None, "num2"),
                    (T("nq.c.loss_ub"), round(m["loss_ub"] * 100, 3) if m.get("loss_ub") is not None else None, "num2"),
                    (T("nq.c.pkts"), m.get("loss_n") or 0, "int"),
                    (T("nq.c.mtu"), cx.t("ui.nqmo.mtu." + m["mtu_status"]) if m.get("mtu_status") else "—", "txt")])
                if (m.get("quality") or "") in ("LOW", "MEDIUM", "HIGH"):
                    findings.append(("warn", T("u.f.nqmo", q=cx.t("ui.nqmo.q." + m["quality"]))))
            r += 1
            b.put(ws, r, 1, T("nq.diags"), "txt", "sec", border=False)
            dg = [(cx.t("ui.nqmo.cls." + d["class"]), cx.t("ui.nqmo.lv." + d["confidence"]),
                   _dt(d.get("since"))) for d in nq.get("diagnoses") or []]
            _f, r = b.table(ws, r + 1, [(T("nq.c.class"), "txt", 26), (T("nq.c.conf"), "txt", 16), (T("nq.c.since"), "dt", 19)],
                            dg, empty=T("empty"), freeze=False, filt=False)
            r += 3
            b.put(ws, r, 1, T("nq.recs"), "txt", "sec", border=False)
            rc = []
            for x in nq.get("recommendations") or []:
                src = x.get("current_source")
                rc.append((cx.t("ui.nqmo.tgt." + x["target"]) if x.get("target") in _NQ_TARGETS else str(x.get("target") or ""),
                           x.get("current_value"),
                           cx.t("ui.nqmo.src." + src) if src in ("CONFIG", "KERNEL") else str(src or ""),
                           x.get("suggested_value"),
                           cx.t("ui.nqmo.mtu." + x["status"]) if x.get("status") in _NQ_MTU else str(x.get("status") or "")))
            _f, r = b.table(ws, r + 1, [(T("nq.c.target"), "txt", 22), (T("nq.c.cur"), "int", 16), (T("nq.c.src"), "txt", 16),
                                        (T("nq.c.sug"), "int", 16), (T("nq.c.status"), "txt", 16)],
                            rc, empty=T("empty"), freeze=False, filt=False)
            hist = (m or {}).get("history")
            if hist:
                r += 3
                b.put(ws, r, 1, T("nq.hist"), "txt", "sec", border=False)
                n = len(hist["rtt_ms"])
                hr = [(_dt(hist["end"] - (n - 1 - i) * 3600), hist["rtt_ms"][i],
                       round(hist["loss"][i] * 100, 3) if hist["loss"][i] is not None else None) for i in range(n)]
                h0, h1 = b.table(ws, r + 1, [(T("c.hour"), "dt", 22), (T("nq.c.rtt"), "num1", 16), (T("nq.c.loss"), "num2", 16)],
                                 hr, empty=T("empty"), freeze=False, filt=False)
                b.chart(ws, h1 + 3, 1, "line", T("nq.hist"), ws, [2], h0, h1, cat_col=1, colors=[xl.BLUE],
                        width_cm=24, height_cm=7, y_title="ms")
        toc.append((nm, T("nq.toc")))

    if wg and f.get("shares"):
        nm = T("s.shares")
        ws = b.sheet(nm, T("sh.t"), T("sh.note"), widths=[19, 19, 10, 10, 10, 18], tab=xl.MUTE)
        sr = [(_dt(s.get("created")), _dt(s.get("expires")), T("yes") if s.get("single") else T("no"),
               s.get("views") or 0, T("yes") if s.get("revoked") else T("no"), s.get("creator") or "")
              for s in f["shares"]]
        b.table(ws, 3, [(T("sh.c.created"), "dt", 19), (T("sh.c.expires"), "dt", 19), (T("sh.c.single"), "txt", 10),
                        (T("sh.c.views"), "int", 10), (T("sh.c.revoked"), "txt", 10), (T("c.actor"), "txt", 18)],
                sr, empty=T("empty"))
        toc.append((nm, T("sh.toc", n=cx.n(len(sr)))))

    # ── پروکسی: مبدأها و مقصدها
    if not wg:
        nm = T("s.clients")
        ws = b.sheet(nm, T("cl.t"), T("cl.note"), widths=[22, 19, 19, 12, 12], tab=xl.PURPLE, title_rows="3:3")
        cr = [((mask_endpoint(c["ip"]) if mask else c["ip"]), _dt(c.get("first_seen")), _dt(c.get("last_seen")),
               c.get("hits") or 0, _gb(c.get("bytes"))) for c in sorted(f.get("clients") or [], key=lambda c: -(c.get("bytes") or 0))]
        b.table(ws, 3, [(T("c.ip"), "txt", 22), (T("c.first_seen"), "dt", 19), (T("c.last_seen"), "dt", 19),
                        (T("c.hits"), "int", 12), (T("c.total_gb"), "gb", 12)],
                cr, empty=T("empty"), bars=(4,), total=[T("total"), None, None, "sum", "sum"], ltr_cols=(0,))
        toc.append((nm, T("cl.toc", n=cx.n(len(cr)))))

        nm = T("s.dests")
        ws = b.sheet(nm, T("ds.t"), T("ds.note"), widths=[34, 19, 19, 11, 11, 11, 10, 12], tab=xl.PURPLE, title_rows="3:3")
        dr = []
        for x in sorted(f.get("dests") or [], key=lambda x: -(x.get("bytes") or 0)):
            hits = x.get("hits") or 0
            fail = x.get("fail") or 0
            dr.append((x["host"], _dt(x.get("first_seen")), _dt(x.get("last_seen")), hits, x.get("ok") or 0, fail,
                       round(100.0 * fail / hits, 1) if hits else None, _gb(x.get("bytes"))))
        b.table(ws, 3, [(T("c.host"), "txt", 34), (T("c.first_seen"), "dt", 19), (T("c.last_seen"), "dt", 19),
                        (T("c.hits"), "int", 11), (T("c.ok"), "int", 11), (T("c.fail"), "int", 11),
                        (T("c.fail_pct"), "pct", 10), (T("c.total_gb"), "gb", 12)],
                dr, empty=T("empty"), bars=(7,), cf=[(6, "greaterThanOrEqual", ["50"], xl.BAD, xl.BADTX)],
                total=[T("total"), None, None, "sum", "sum", "sum", None, "sum"], ltr_cols=(0,))
        toc.append((nm, T("ds.toc", n=cx.n(len(dr)))))

    # ── تاریخچه‌ی تغییرات (فقط با audit.view)
    if "audit" in f:
        nm = T("s.audit")
        ws = b.sheet(nm, T("u.audit.t"), T("u.audit.note"), widths=[19, 14, 24, 44, 15, 8], tab=xl.MUTE, title_rows="3:3")
        ar = [(_dt(r["ts"]), r.get("actor") or "", r.get("action_text") or r.get("action") or "",
               r.get("detail") or "", r.get("ip") or "", bool(r.get("ok"))) for r in f.get("audit") or []]
        b.table(ws, 3, [(T("c.when"), "dt", 19), (T("c.actor"), "txt", 14), (T("c.event"), "txt", 24),
                        (T("c.detail"), "txt", 44), (T("c.ip"), "txt", 15), (T("c.ok"), "txt", 8)],
                ar, empty=T("empty"), cf=[(5, "equal", ['"%s"' % T("no")], xl.BAD, xl.BADTX)], ltr_cols=(4,))
        toc.append((nm, T("audit.toc", n=cx.n(len(ar)))))

    # ── داشبورد
    r = 3
    if wg:
        meta = f.get("meta") or {}
        hs = u.get("handshake") or 0
        rate = _num(u.get("rate_mbit"))
        prof = [(T("c.name"), name, "txt"), (T("c.iface"), u.get("iface") or "", "txt"),
                (T("c.status"), _px_status(u, T), "txt"), (T("c.online"), T("yes") if u.get("online") else T("no"), "txt"),
                (T("c.hs"), _dt(hs), "dt"),
                (T("c.endpoint"), (mask_endpoint(u.get("endpoint")) if mask else (u.get("endpoint") or "")) or "—", "txt"),
                (T("c.allowed"), u.get("allowed_ips") or "", "txt"), (T("u.k.pubkey"), u.get("public_key") or "", "txt"),
                (T("c.quota_gb"), q, "gb"), (T("u.k.total_cap"), _num(meta.get("total_gb")), "gb"),
                (T("u.k.enforce"), meta.get("enforce_action") or "—", "txt"),
                (T("c.expires"), exp, "date"), (T("c.days_left"), left, "int"), (T("c.rate"), rate, "num1"),
                (T("u.k.dns"), meta.get("c_dns") or "—", "txt"), (T("u.k.mtu"), meta.get("c_mtu"), "int"),
                (T("u.k.keepalive"), meta.get("c_keepalive"), "int"),
                (T("u.k.c_allowed"), meta.get("c_allowed") or "—", "txt"), (T("c.note"), u.get("note") or "", "txt")]
    else:
        rate = _num(u.get("rate_kbit"))
        prof = [(T("c.username"), name, "txt"), (T("c.status"), _px_status(u, T), "txt"),
                (T("c.proto"), T("px.proto." + (u.get("protocol") or "both")), "txt"),
                (T("c.auth"), T("px.auth.src" if u.get("noauth") else "px.auth.pw"), "txt"),
                (T("c.allow_src"), u.get("allow_src") or "—", "txt"),
                (T("c.rate"), round(rate / 1000.0, 1) if rate else None, "num1"), (T("c.quota_gb"), q, "gb"),
                (T("c.expires"), exp, "date"), (T("c.days_left"), left, "int"),
                (T("c.created"), _dt(u.get("created")), "dt"), (T("c.note"), u.get("note") or "", "txt")]
    r = b.section(dash, r, T("u.h.profile"))
    r = b.kv(dash, r, prof)
    r = b.section(dash, r + 1, T("h.kpi"))
    cards = [(T("u.card.range"), _gb(total), "gb", rw["kv"], None),
             (T("u.card.avg"), _gb(total / days) if days else None, "gb", T("u.card.avg.sub"), None),
             (T("u.card.peak"), _gb(peak[1]) if peak else None, "gb",
              (cx.t("xl.u.card.peak.sub", d=_jal(peak[0], cx)) if peak and peak[1] else ""), None),
             (T("u.card.active"), active, "int", T("u.card.active.sub", d=cx.n(days)), "warn" if not active else "ok")]
    if wg:
        cards += [(T("c.rx_gb"), _gb(rx_t), "gb", "", None), (T("c.tx_gb"), _gb(tx_t), "gb", "", None)]
    cards += [(T("card.month"), _gb(mb), "gb", (T("u.card.quota.sub", p=cx.n(pct)) if pct is not None else ""),
               "bad" if (pct or 0) >= 100 else ("warn" if (pct or 0) >= 90 else None))]
    if life is not None:
        cards.append((T("c.life_gb"), _gb(life), "gb", "", None))
    if peak_h and peak_h[1]:
        cards.append((T("u.card.peak_h"), round(peak_h[1] / MB, 1), "num1", "MB · " + peak_h[0][11:13] + ":00 " + _jal(peak_h[0][:10], cx), None))
    r = b.cards(dash, r, cards, per_row=4, span=2)
    r = b.section(dash, r + 1, T("h.findings"))
    lvl_order = {"bad": 0, "warn": 1, "ok": 2}
    if findings:
        for lv, txt in sorted(findings, key=lambda x: lvl_order.get(x[0], 3)):
            b.put(dash, r, 1, T("sev." + lv), "txt", {"bad": "badtx", "warn": "warntx"}.get(lv, "oktx"),
                  {"bad": "bad", "warn": "warn"}.get(lv, "ok"), "c")
            b.put(dash, r, 2, txt, "txt", align="wrap")
            b.merge(dash, r, 2, r, 8)
            r += 1
    else:
        r = b.para(dash, r, T("f.none"))
    r = b.section(dash, r + 1, T("h.report"))
    r = b.kv(dash, r, [(T("k.host"), f.get("host") or "", "txt"), (T("k.build"), f.get("build") or "", "txt"),
                       (T("k.generated"), now, "dt"), (T("k.range"), rw["kv"], "txt"),
                       (T("k.mask"), T("yes") if mask else T("no"), "txt")])
    r = b.section(dash, r + 1, T("h.toc"))
    for nm_, desc in toc:
        b.link(dash, r, 1, nm_, nm_, border=True)
        b.put(dash, r, 2, desc, "txt")
        b.merge(dash, r, 2, r, 8)
        r += 1
    for k, ch in enumerate(dash.charts):
        dash.charts[k] = (r + 2,) + ch[1:]
    return b.save()


_NQ_TARGETS = ("CLIENT_IFACE_MTU", "SERVER_PEER_TCP_MSS")   # = کلیدهای ui.nqmo.tgt.* (تست می‌پاید)
_NQ_MTU = ("UNDETERMINED", "CANDIDATE_FOR_TESTING", "ESTIMATED", "VERIFIED")


def _hour(s):
    try:
        return datetime.strptime(str(s), "%Y-%m-%d %H")
    except (TypeError, ValueError):
        return None


def _jal(day, cx):
    """«YYYY-MM-DD» ⇒ متنِ تاریخ برای زیرنویس: در فارسی شمسی، وگرنه همان ISO."""
    d = _date(day)
    if d is None:
        return ""
    if not cx.fa:
        return d.isoformat()
    jy, jm, jd = _g2j(d.year, d.month, d.day)
    return cx.n("%04d/%02d/%02d" % (jy, jm, jd))


def _g2j(gy, gm, gd):
    """میلادی ⇒ شمسی (همان الگوریتمِ jdf ِ app._greg_to_jalali؛ این ماژول import نمی‌کند)."""
    g_dm = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    if gy > 1600:
        jy, gy = 979, gy - 1600
    else:
        jy, gy = 0, gy - 621
    gy2 = gy + 1 if gm > 2 else gy
    days = (365 * gy + (gy2 + 3) // 4 - (gy2 + 99) // 100 + (gy2 + 399) // 400 - 80 + gd + g_dm[gm - 1])
    jy += 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        return jy, 1 + days // 31, 1 + days % 31
    return jy, 7 + (days - 186) // 30, 1 + (days - 186) % 30
