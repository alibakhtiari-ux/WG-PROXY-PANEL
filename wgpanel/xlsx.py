# -*- coding: utf-8 -*-
"""نویسنده‌ی XLSX با کتابخانه‌ی استانداردِ خالص (zipfile + XML) — بی openpyxl.

روی سرور نه pip هست نه Docker، پس قواعدِ قالب‌بندیِ گزارش‌های Excel ِ پروژه‌ی
پایش (کتاب‌های /cms/ و /tshoot/، هر قاعده یک بار در Excel ِ مک سنجیده و
حادثه‌دار بوده) این‌جا مستقیم روی OOXML پیاده شده‌اند:

  • هرگز `Table` ِ Excel نه — Excel ِ مک دیالوگِ «We found a problem with some
    content» می‌دهد؛ فیلتر با autoFilter و نوارِ زبرا دستی.
  • هر رشته یک رشته است (shared string، هرگز <f>) ⇒ گاردِ formula-injection:
    نامِ دستگاهی که با «=» شروع شود فرمول نمی‌شود. ارقامِ فارسیِ رشته ⇒ لاتین
    (جست‌وجو و مرتب‌سازیِ Excel)؛ عددها خودشان عدد می‌مانند.
  • None خالی می‌ماند، هرگز ۰ («نامعلوم» ≠ صفر؛ میانگین و نمودار دروغ نگویند).
  • تاریخ عددِ سریالِ Excel با قالبِ تاریخ است (نه رشته)؛ مدت با [h]:mm:ss.
  • ارتفاعِ ردیفِ wrap صریح است (Excel خانه‌ی ادغام‌شده را خودکار بلند نمی‌کند).
  • rightToLeft + اندازه‌ی پنجره‌ی کتاب + tabSelected فقط روی برگه‌ی اول — بی
    این‌ها Excel ِ مک برگه‌ی RTL را «اسکرول‌شده» نشان می‌دهد.
  • freeze فقط یک بار؛ و هر برگه selection ِ سازگار با pane ِ خودش را دارد —
    selection ِ یتیم (pane ِ ناموجود) کتاب را در Excel ِ مک **بی‌صدا** باز
    نمی‌کند.
  • چاپ: A4، جا در عرض، سرصفحه‌ی تکرارشونده، پاصفحه‌ی «صفحه / کل» و نامِ برگه.
  • شکلِ بومی (DrawingML) در برگه‌ی RTL: هرگز grpSp؛ هر شکل یک oneCellAnchor ِ
    مستقل با x ِ آینه‌شده (x′ = W − x − w)؛ run های لاتین/فارسی جدا؛ حرکه‌ها
    حذف (Tahoma کسره را با فاصله‌ی بعدش می‌بلعد).

ماژول هیچ‌چیز از پنل import نمی‌کند (تابعِ خالص روی داده) تا بی سرور آزموده شود؛
متن‌های رابط (بله/خیر، «بازگشت»، …) را فراخواننده با `words` می‌دهد.
"""
import io
import math
import re
import zipfile
from datetime import date, datetime, timezone
from xml.sax.saxutils import escape as _xesc

# ── پالت (همان خانواده‌ی گزارش‌های Excel ِ پایش؛ هر کدام با متنِ سیاه کنتراستِ کافی) ──
GREEN, DARK = "0D6B5D", "0B564B"
BAD, BADTX = "FDE8E8", "9B1C1C"
OK, OKTX = "E6F4EA", "1E6B3A"
WARN, WARNTX = "FEF3C7", "92400E"
MUTE = "6B7280"
BAND = "F4F8F7"
KV = "F3F4F6"
BLUE, PURPLE, TEAL = "1D4ED8", "6D28D9", "0E7490"

FMT = {"int": "#,##0", "num1": "#,##0.0", "num2": "#,##0.00", "pct": '0.0"%"',
       "hms": "[h]:mm:ss", "dt": "yyyy-mm-dd hh:mm:ss", "date": "yyyy-mm-dd",
       "hm": "hh:mm", "gb": "#,##0.00", "mbps": "#,##0.0", "txt": None}
#: نوعی که مقدارش پیش از نوشتن مقیاس می‌خورد (ثانیه ⇒ کسرِ روز برای [h]:mm:ss)
SCALE = {"hms": 1.0 / 86400.0}
FA2LAT = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩٫", "01234567890123456789.")
ZERO_WIDTH = "​‌‍﻿"
BAD_SHEET = re.compile(r"[\[\]:*?/\\]")
#: نویسه‌ای که XML ِ 1.0 نمی‌پذیرد — یک بایتِ کنترلی در نامِ دستگاه کلِ فایل را خراب می‌کرد
_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")
MAX_CELL_CHARS = 32767           # سقفِ Excel برای یک خانه
MAX_CELLS = 250_000              # سقفِ حافظه‌ی کتاب (پنل روی سرورِ تولیدی است)
EXCEL_EPOCH = datetime(1899, 12, 30)
EMU_PT = 12700
EMU_CM = 360000

NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
NS_DRAW = ('xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" '
           'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
           'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')
REL_T = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
XML_HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

DEFAULT_WORDS = {"yes": "بله", "no": "خیر", "unknown": "نامعلوم", "back": "↩ بازگشت",
                 "trimmed": "⚠️ برگه‌ی «{sheet}»: {cut} ردیف برای سقفِ حافظه بریده شد ({keep} ردیف ماند).",
                 "trimmed_empty": "{empty} — ولی این برگه برای سقفِ حافظه بریده شد، نه خالی است ({n} ردیف)."}


def xml_text(s):
    """متنِ امن برای XML: نویسه‌ی غیرمجاز حذف، سپس گریز (نقل‌قول هم، برای صفت)."""
    return _xesc(_XML_BAD.sub("", str(s)), {'"': "&quot;"})


def col_letter(n):
    """۱ ⇒ A، ۲۷ ⇒ AA."""
    s = ""
    while n > 0:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def ref(r, c, absolute=False):
    if absolute:
        return "$%s$%d" % (col_letter(c), r)
    return "%s%d" % (col_letter(c), r)


def quote_sheet(name):
    """نامِ برگه در ارجاعِ فرمول/نمودار: همیشه داخلِ '…' با آپوستروفِ دوتایی."""
    return "'%s'" % str(name).replace("'", "''")


def excel_serial(v):
    """datetime/date ⇒ عددِ سریالِ Excel (روز از ۱۸۹۹-۱۲-۳۰). datetime ِ aware اول به محلی."""
    if isinstance(v, datetime):
        if v.tzinfo is not None:
            v = v.astimezone().replace(tzinfo=None)
        d = v - EXCEL_EPOCH
        return d.days + (d.seconds + d.microseconds / 1e6) / 86400.0
    d = datetime(v.year, v.month, v.day) - EXCEL_EPOCH
    return float(d.days)


def safe_sheet_name(name, taken):
    nm = (BAD_SHEET.sub("", _XML_BAD.sub("", str(name))).strip().strip("'") or "Sheet")[:31]
    base, k = nm, 2
    low = {t.lower() for t in taken}
    while nm.lower() in low:
        suf = " (%d)" % k
        nm = base[:31 - len(suf)] + suf
        k += 1
    return nm


def hf_text(s):
    """متنِ آزادِ سرصفحه/پاصفحه: «&» پیشوندِ کد است ⇒ «&&». متنی که با رقم شروع شود پشتِ
    کدِ اندازه («&8») می‌چسبید و اندازه‌ی قلم می‌شد ⇒ یک فاصله جلویش."""
    s = str(s or "").replace("&", "&&")
    return (" " + s) if s[:1].isdigit() else s


def text_width(text, bold=False, size=11):
    """تخمینِ عرضِ AutoFit ِ Excel (ضریب‌های سنجیده‌ی گزارش‌های پایش؛ همیشه بیش‌برآورد)."""
    s = str(text or "")
    for ch in ZERO_WIDTH:
        s = s.replace(ch, "")
    w = len(s) + 1.0
    if bold:
        w *= 1.1
    if size and size != 11:
        w *= float(size) / 11.0
    return w


def fit_height(text, width_units, line_pt=16, min_pt=18):
    """ارتفاعِ ردیف برای متنِ wrap — بیشینه‌ی «طول÷عرض» و شکستنِ حریصانه‌ی کلمه."""
    s = str(text or "")
    cap = max(10.0, float(width_units))
    by_len = math.ceil(len(s) / cap)
    by_word = 0
    for para in s.split("\n"):
        cur, ln = 0, 1
        for word in para.split():
            k = len(word)
            if cur and cur + 1 + k <= cap:
                cur += 1 + k
                continue
            if cur:
                ln += 1
            cur = k
            while cur > cap:
                ln += 1
                cur -= cap
        by_word += ln
    return max(min_pt, line_pt * (max(1, by_len, by_word) + 1))


def cols_within(widths, max_width):
    """شمارِ ستون‌های آغازینی که جمعِ عرضشان از max_width نمی‌گذرد (دست‌کم ۱)."""
    n, tot = 0, 0.0
    for w in widths:
        if n and tot + w > max_width:
            break
        tot += w
        n += 1
    return max(1, n)


# ── سبک‌ها ──────────────────────────────────────────────────────────────────
class _Styles:
    """ثبتِ تکراری‌زدای فونت/پرکردن/حاشیه/قالبِ عدد ⇒ اندیسِ xf."""

    def __init__(self):
        self.fonts = [(False, False, 11, None, False)]             # (b, i, sz, color, underline)
        self.fills = ["none", "gray125"]                            # دو پرکردنِ رزروشده‌ی Excel
        self.borders = [False, True]                                # بی‌حاشیه، حاشیه‌ی نازک
        self.numfmts = {}                                           # code ⇒ id (۱۶۴+)
        self.xfs: list = [(0, 0, 0, 0, None)]                       # (font, fill, border, numfmt, align)
        self._xf_idx: dict = {self.xfs[0]: 0}
        self.dxfs = []
        self._dxf_idx = {}

    def _font(self, f):
        f = tuple(f) if f else self.fonts[0]
        if f not in self.fonts:
            self.fonts.append(f)
        return self.fonts.index(f)

    def _fill(self, color):
        if not color:
            return 0
        if color not in self.fills:
            self.fills.append(color)
        return self.fills.index(color)

    def _numfmt(self, code):
        if not code:
            return 0
        builtin = {"#,##0": 3, "#,##0.00": 4, "yyyy-mm-dd": None}
        if builtin.get(code):
            return builtin[code]
        if code not in self.numfmts:
            self.numfmts[code] = 164 + len(self.numfmts)
        return self.numfmts[code]

    def xf(self, font=None, fill=None, border=False, numfmt=None, align=None):
        key = (self._font(font), self._fill(fill), 1 if border else 0, self._numfmt(numfmt),
               tuple(sorted(align.items())) if align else None)
        if key not in self._xf_idx:
            self._xf_idx[key] = len(self.xfs)
            self.xfs.append(key)
        return self._xf_idx[key]

    def dxf(self, fill, color=None):
        key = (fill, color)
        if key not in self._dxf_idx:
            self._dxf_idx[key] = len(self.dxfs)
            self.dxfs.append(key)
        return self._dxf_idx[key]

    def xml(self):
        o = [XML_HEAD, '<styleSheet xmlns="%s">' % NS_MAIN]
        if self.numfmts:
            o.append('<numFmts count="%d">' % len(self.numfmts))
            for code, i in sorted(self.numfmts.items(), key=lambda kv: kv[1]):
                o.append('<numFmt numFmtId="%d" formatCode="%s"/>' % (i, xml_text(code)))
            o.append("</numFmts>")
        o.append('<fonts count="%d">' % len(self.fonts))
        for b, it, sz, color, ul in self.fonts:
            o.append("<font>%s%s%s<sz val=\"%s\"/>%s<name val=\"Calibri\"/><family val=\"2\"/></font>"
                     % ("<b/>" if b else "", "<i/>" if it else "", "<u/>" if ul else "",
                        ("%g" % sz), '<color rgb="FF%s"/>' % color if color else ""))
        o.append("</fonts>")
        o.append('<fills count="%d">' % len(self.fills))
        for f in self.fills:
            if f in ("none", "gray125"):
                o.append('<fill><patternFill patternType="%s"/></fill>' % f)
            else:
                o.append('<fill><patternFill patternType="solid"><fgColor rgb="FF%s"/>'
                         '<bgColor indexed="64"/></patternFill></fill>' % f)
        o.append("</fills>")
        o.append('<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border>'
                 '<border><left style="thin"><color rgb="FFD9E2E0"/></left><right style="thin"><color rgb="FFD9E2E0"/></right>'
                 '<top style="thin"><color rgb="FFD9E2E0"/></top><bottom style="thin"><color rgb="FFD9E2E0"/></bottom>'
                 '<diagonal/></border></borders>')
        o.append('<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>')
        o.append('<cellXfs count="%d">' % len(self.xfs))
        for font, fill, border, nf, align in self.xfs:
            attrs = 'numFmtId="%d" fontId="%d" fillId="%d" borderId="%d" xfId="0"' % (nf, font, fill, border)
            if nf:
                attrs += ' applyNumberFormat="1"'
            if font:
                attrs += ' applyFont="1"'
            if fill:
                attrs += ' applyFill="1"'
            if border:
                attrs += ' applyBorder="1"'
            if align:
                a = " ".join('%s="%s"' % (k, v) for k, v in align)
                o.append('<xf %s applyAlignment="1"><alignment %s/></xf>' % (attrs, a))
            else:
                o.append("<xf %s/>" % attrs)
        o.append("</cellXfs>")
        o.append('<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>')
        o.append('<dxfs count="%d">' % len(self.dxfs))
        for fill, color in self.dxfs:
            o.append("<dxf>%s<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF%s\"/><bgColor rgb=\"FF%s\"/>"
                     "</patternFill></fill></dxf>" % ('<font><color rgb="FF%s"/></font>' % color if color else "", fill, fill))
        o.append("</dxfs>")
        o.append('<tableStyles count="0" defaultTableStyle="TableStyleMedium9" defaultPivotStyle="PivotStyleLight16"/>')
        o.append("</styleSheet>")
        return "".join(o)


# ── شکلِ بومی (DrawingML) ──────────────────────────────────────────────────
FONT_SHAPE = "Tahoma"
#: نویسه‌هایی که Tahoma ِ Office در شکل ندارد یا در PDF گم می‌کند
GLYPH = str.maketrans({"✓": "", "✗": "×", "⚠": "!", "⇐": "←", "⇒": "→", "●": "•", "◆": "•"})
HARAKAT = re.compile("[ً-ْ]")
ARABIC = re.compile("[؀-ۿﭐ-﻿]")
FA2EN = str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789")
SCRIPT_SPLIT = re.compile(r"(\([A-Za-z0-9][^()؀-ۿ]*\)|(?:\.?/)?[*+]?[A-Za-z0-9][A-Za-z0-9 .,:/_\-+=@*#\[\]]*[A-Za-z0-9*\]/)]|[*+]?[A-Za-z0-9])")
EMOJI = re.compile("[\U0001F000-\U0001FAFF☀-➿️]")


def _e(pt):
    return int(round(pt * EMU_PT))


def shape_clean(t):
    t = HARAKAT.sub("", str(t or "")).translate(GLYPH)
    t = EMOJI.sub("", t)
    # بازه/ساعت با ارقامِ فارسی و خطِ تیره در شکلِ Excel وارونه می‌شود ⇒ ارقامِ لاتین تا run ِ en شود
    t = re.sub(r"[۰-۹]+(?:[-:/.][۰-۹]+)+", lambda m: m.group(0).translate(FA2EN), t)
    return _XML_BAD.sub("", re.sub(r"\s+", " ", t).strip())


def para(text, sz_pt, bold=False, color="1D2433", align="ctr"):
    """یک پاراگرافِ شکل؛ لاتین/رقم run ِ en-US و فارسی run ِ fa-IR (bidi ِ Excel)."""
    text = shape_clean(text)
    ltr = not ARABIC.search(text)
    sz = int(round(sz_pt * 100))
    b = ' b="1"' if bold else ""

    def run(t, lang):
        return ('<a:r><a:rPr lang="%s" altLang="en-US" sz="%d"%s dirty="0"><a:solidFill><a:srgbClr val="%s"/></a:solidFill>'
                '<a:latin typeface="%s"/><a:cs typeface="%s"/></a:rPr><a:t>%s</a:t></a:r>'
                % (lang, sz, b, color, FONT_SHAPE, FONT_SHAPE, _xesc(t)))
    if not text:
        return '<a:p><a:endParaRPr lang="fa-IR" sz="%d"/></a:p>' % sz
    if ltr:
        runs = run(text, "en-US")
    else:
        parts = SCRIPT_SPLIT.split(text)
        if bold:                                    # Tahoma ِ bold فاصله‌ی مرزِ run ها را تقریباً صفر می‌کشد
            for i in range(0, len(parts), 2):
                if i + 1 < len(parts) and parts[i + 1] and parts[i].endswith(" "):
                    parts[i] += " "
                if i > 0 and parts[i - 1] and parts[i].startswith(" "):
                    parts[i] = " " + parts[i]
        runs = "".join(run(x, "en-US" if i % 2 else "fa-IR") for i, x in enumerate(parts) if x)
    return ('<a:p><a:pPr algn="%s" rtl="%d"><a:spcBef><a:spcPts val="0"/></a:spcBef><a:spcAft><a:spcPts val="0"/></a:spcAft></a:pPr>%s</a:p>'
            % (align, 0 if ltr else 1, runs))


def body(paras, ins=2, anchor="ctr", wrap="square"):
    return ('<xdr:txBody><a:bodyPr vertOverflow="overflow" horzOverflow="overflow" wrap="%s" lIns="%d" tIns="%d" rIns="%d" bIns="%d" '
            'rtlCol="0" anchor="%s"><a:noAutofit/></a:bodyPr><a:lstStyle/>%s</xdr:txBody>'
            % (wrap, _e(ins), _e(ins / 2), _e(ins), _e(ins / 2), anchor,
               "".join(paras) or '<a:p><a:endParaRPr lang="fa-IR"/></a:p>'))


class Canvas:
    """فهرستِ شکل‌ها در مختصاتِ **دیداری** (pt، مبدأ گوشه‌ی بالا-چپِ ناحیه‌ی نقاشی).
    آینه‌کردنِ x برای برگه‌ی RTL در `Book._drawing` انجام می‌شود، نه این‌جا."""

    def __init__(self, width_pt):
        self.width = float(width_pt)
        self.items, self.rels, self._id = [], [], 100

    def nid(self):
        self._id += 1
        return self._id

    def shape(self, name, x, y, w, h, fill=None, line=None, lw=0.75, txbody=None, geom="rect",
              dash=False, link=None, tip=""):
        sid = self.nid()
        hl = ""
        if link:
            rid = "rIdL%d" % (len(self.rels) + 1)
            self.rels.append((rid, link))
            hl = '<a:hlinkClick r:id="%s" tooltip="%s"/>' % (rid, xml_text(tip))
        fx = '<a:solidFill><a:srgbClr val="%s"/></a:solidFill>' % fill if fill else "<a:noFill/>"
        lx = ('<a:ln w="%d"><a:solidFill><a:srgbClr val="%s"/></a:solidFill>%s</a:ln>'
              % (_e(lw), line, '<a:prstDash val="dash"/>' if dash else "")) if line else "<a:ln><a:noFill/></a:ln>"
        av = '<a:gd name="adj" fmla="val 18000"/>' if geom == "roundRect" else ""
        self.items.append((x, w, y, h,
            '<xdr:sp macro="" textlink=""><xdr:nvSpPr><xdr:cNvPr id="%d" name="%s">%s</xdr:cNvPr><xdr:cNvSpPr%s/></xdr:nvSpPr>'
            '<xdr:spPr>%%XF%%<a:prstGeom prst="%s"><a:avLst>%s</a:avLst></a:prstGeom>%s%s</xdr:spPr>%s</xdr:sp>'
            % (sid, xml_text(name), hl, ' txBox="1"' if txbody is not None and not fill else "", geom, av, fx, lx,
               txbody if txbody is not None else body([])), False, False))
        return sid

    def line(self, name, x1, y1, x2, y2, color, lw=1.25, dash=False, arrow=True, both=False):
        """پیکانِ بومی؛ جهت با flip (سرِ پیکان tailEnd ِ نقطه‌ی پایان است)."""
        sid = self.nid()
        x, y, w, h = min(x1, x2), min(y1, y2), abs(x2 - x1), abs(y2 - y1)
        self.items.append((x, w, y, h,
            '<xdr:cxnSp macro=""><xdr:nvCxnSpPr><xdr:cNvPr id="%d" name="%s"/><xdr:cNvCxnSpPr/></xdr:nvCxnSpPr>'
            '<xdr:spPr>%%XF%%<a:prstGeom prst="straightConnector1"><a:avLst/></a:prstGeom><a:ln w="%d"><a:solidFill><a:srgbClr val="%s"/></a:solidFill>'
            '%s%s%s</a:ln></xdr:spPr></xdr:cxnSp>'
            % (sid, xml_text(name), _e(lw), color, '<a:prstDash val="dash"/>' if dash else "",
               '<a:headEnd type="triangle" w="med" len="med"/>' if both else "",
               '<a:tailEnd type="triangle" w="med" len="med"/>' if arrow else ""), x2 < x1, y2 < y1))
        return sid


# ── برگه ──────────────────────────────────────────────────────────────────
class Sheet:
    def __init__(self, book, name):
        self.book = book
        self.name = name
        self.cells = {}            # (r, c) ⇒ (value, xf)
        self.row_h = {}
        self.widths = []
        self.merges = []
        self.cf = []               # (sqref, xml بی priority)
        self.links = []            # (ref, location, display)
        self.freeze = None         # (row, col) ِ نخستین خانه‌ی بازِ پایین-چپ
        self.filter = None
        self.rtl = book.rtl
        self.tab = None
        self.landscape = True
        self.title_rows = None
        self.print_area = None
        self.row_breaks = []
        self.charts = []           # (row, col, w_cm, h_cm, chart_xml)
        self.canvas = None
        self.right_margin = 0.35

    @property
    def max_row(self):
        return max([r for r, _ in self.cells] + list(self.row_h) + [1])

    @property
    def max_col(self):
        return max([c for _, c in self.cells] + [len(self.widths), 1])

    def width_of(self, c):
        return self.widths[c - 1] if 0 < c <= len(self.widths) else 9.0


class Book:
    """کتابِ کار. API همان کتاب‌های پایش است: sheet/section/para/table/kv/cards/link/put."""

    def __init__(self, title, home, rtl=True, words=None, max_cells=None, num=str):
        self.title = title
        self.num = num                                # شمارِ داخلِ متن (ارقامِ فارسی در کتابِ فارسی)
        self.home = home
        self.rtl = bool(rtl)
        self.words = dict(DEFAULT_WORDS, **(words or {}))
        self.max_cells = int(max_cells or MAX_CELLS)
        self.cells = 0
        self.trimmed = []
        self.empty_tables = set()
        self.sheets = []
        self.classification = ""
        self.props = {}
        self.st = _Styles()
        self.sst, self._sst_idx = [], {}
        H = "right" if self.rtl else "left"
        self.F = {
            None: None,
            "ttl": (True, False, 13, DARK, False), "sec": (True, False, 11, DARK, False),
            "hdr": (True, False, 10, "FFFFFF", False), "note": (False, True, 9, MUTE, False),
            "lbl": (False, False, 9, MUTE, False), "big": (True, False, 18, DARK, False),
            "bigmute": (True, False, 14, MUTE, False), "sub": (False, False, 9, "374151", False),
            "link": (False, False, 10, "0B56A7", True), "b": (True, False, 10, None, False),
            "badtx": (False, False, 10, BADTX, False), "warntx": (False, False, 10, WARNTX, False),
            "oktx": (False, False, 10, OKTX, False),
        }
        self.P = {None: None, "hdr": GREEN, "kv": KV, "bad": BAD, "ok": OK, "warn": WARN,
                  "band": BAND, "card": "F7FAF9"}
        self.A = {
            None: None,
            "r": {"horizontal": H, "vertical": "center"},
            "c": {"horizontal": "center", "vertical": "center"},
            "wrap": {"horizontal": H, "vertical": "top", "wrapText": "1"},
            "hdr": {"horizontal": "center", "vertical": "center", "wrapText": "1"},
            "cwrap": {"horizontal": "center", "vertical": "center", "wrapText": "1"},
            "ltr": {"horizontal": "left", "vertical": "center", "readingOrder": "1"},
        }

    # ── سلول ──────────────────────────────────────────────────────────────
    def _val(self, v):
        if v is None or v == "":
            return None
        if isinstance(v, bool):
            return self.words["yes"] if v else self.words["no"]
        if isinstance(v, (datetime, date)):
            return v
        if isinstance(v, (int, float)):
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                return None
            return v
        s = _XML_BAD.sub("", str(v)).translate(FA2LAT)
        return s[:MAX_CELL_CHARS]

    def _s(self, s):
        i = self._sst_idx.get(s)
        if i is None:
            i = self._sst_idx[s] = len(self.sst)
            self.sst.append(s)
        return i

    def put(self, ws, r, c, v, kind="txt", font=None, fill=None, align=None, border=True):
        self.cells += 1
        val = self._val(v)
        if kind in SCALE and isinstance(val, (int, float)) and not isinstance(val, bool):
            val = val * SCALE[kind]
        nf = None
        if isinstance(val, datetime):
            nf = FMT["dt"] if kind not in ("date", "hm") else FMT[kind]
        elif isinstance(val, date):
            nf = FMT["date"]
        elif isinstance(val, (int, float)):
            nf = FMT.get(kind)
        al = self.A.get(align) if isinstance(align, str) else align
        xf = self.st.xf(self._f(font), self._p(fill), border, nf, al or self.A["r"])
        ws.cells[(r, c)] = (val, xf)
        return (r, c)

    def _f(self, font):
        return self.F.get(font, font) if isinstance(font, str) or font is None else font

    def _p(self, fill):
        return self.P.get(fill, fill) if isinstance(fill, str) or fill is None else fill

    def restyle(self, ws, r, c, font=None, fill=None, align=None, border=True, kind=None):
        """سبکِ خانه‌ی موجود را بی‌تغییرِ مقدار عوض می‌کند (پیوند روی شناسه‌ی جدول)."""
        val = ws.cells.get((r, c), (None, 0))[0]
        nf = None
        if isinstance(val, datetime):
            nf = FMT["dt"]
        elif isinstance(val, (int, float)) and kind:
            nf = FMT.get(kind)
        ws.cells[(r, c)] = (val, self.st.xf(self._f(font), self._p(fill), border, nf,
                                            self.A.get(align) if isinstance(align, str) else (align or self.A["r"])))

    def link(self, ws, r, c, text, sheet, row=1, border=False, align="r"):
        self.put(ws, r, c, text, "txt", "link", align=align, border=border)
        ws.links.append((ref(r, c), "%s!A%d" % (quote_sheet(sheet), row), str(text)))

    def link_cell(self, ws, r, c, sheet, row=1):
        """پیوندِ درون‌کتابی روی خانه‌ای که مقدار دارد (شناسه‌ی ردیف ⇒ برگه‌ی جزئیات)."""
        v = ws.cells.get((r, c), (None, 0))[0]
        if v is None:
            return
        self.restyle(ws, r, c, "link")
        ws.links.append((ref(r, c), "%s!A%d" % (quote_sheet(sheet), row), str(v)))

    def merge(self, ws, r1, c1, r2, c2):
        if (r1, c1) != (r2, c2):
            ws.merges.append("%s:%s" % (ref(r1, c1), ref(r2, c2)))

    # ── برگه ──────────────────────────────────────────────────────────────
    def sheet(self, name, title, note="", widths=(), landscape=True, title_rows=None, tab=None,
              note_max_width=None):
        nm = safe_sheet_name(name, [s.name for s in self.sheets])
        ws = Sheet(self, nm)
        self.sheets.append(ws)
        widths = list(widths) or [20]
        ws.widths = widths
        n = len(widths)
        has_back = nm != self.home and n >= 2
        link_col = min(6, n) if has_back else 0
        end = (link_col - 1) if has_back else n
        self.put(ws, 1, 1, title, "txt", "ttl", border=False)
        self.merge(ws, 1, 1, 1, end)
        tw = sum(widths[:end])
        ws.row_h[1] = 24
        if text_width(title, True, 13) > tw:
            self.put(ws, 1, 1, title, "txt", "ttl", align="wrap", border=False)
            ws.row_h[1] = max(24, fit_height(title, tw, 18))
        if has_back:
            lw = widths[link_col - 1]
            self.link(ws, 1, link_col, self.words["back"] if lw >= 10 else "↩", self.home, align="c")
        if note:
            nn = cols_within(widths, note_max_width) if note_max_width else n
            self.merge(ws, 2, 1, 2, nn)
            self.put(ws, 2, 1, note, "txt", "note", align="wrap", border=False)
            ws.row_h[2] = fit_height(note, sum(widths[:nn]))
        ws.tab = tab
        ws.landscape = landscape
        ws.title_rows = title_rows
        return ws

    def section(self, ws, r, text, ncols=None):
        n = ncols or len(ws.widths)
        w = sum(ws.widths[:n])
        wrap = text_width(text, True, 11) > w
        self.put(ws, r, 1, text, "txt", "sec", align="wrap" if wrap else "r", border=False)
        self.merge(ws, r, 1, r, n)
        ws.row_h[r] = fit_height(text, w) if wrap else 22
        return r + 1

    def para(self, ws, r, text, ncols=None, font="sub"):
        n = ncols or len(ws.widths)
        self.put(ws, r, 1, text, "txt", font, align="wrap", border=False)
        self.merge(ws, r, 1, r, n)
        ws.row_h[r] = fit_height(text, sum(ws.widths[:n]))
        return r + 1

    def header_row(self, ws, r, heads, filtered=False):
        for j, h in enumerate(heads, 1):
            self.put(ws, r, j, h, "txt", "hdr", "hdr", "hdr")
        cut = 2.5 if filtered else 0.0
        lines = 1
        for j, h in enumerate(heads):
            w = ws.width_of(j + 1)
            per = max(4.0, float(w) - 1.0 - cut)
            lines = max(lines, sum(max(1, math.ceil(len(p) / per)) for p in str(h).split("\n")))
        ws.row_h[r] = max(30, 15 * lines + 4)

    def table(self, ws, r0, cols, rows, empty="—", filt=True, freeze=True, bars=(), scales=(), cf=(),
              zebra=True, total=None, ltr_cols=()):
        """جدول از ردیفِ r0 ⇒ (نخستین، آخرین ردیفِ داده). `cols` = [(عنوان، نوع، عرض)].

        bars = اندیسِ ستون‌های DataBar · scales = [(اندیس، پایین، وسط، بالا)] ·
        cf = [(اندیس، عملگر، [مقدار]، پرکردن، رنگِ متن|None)] (cellIs) · total = ردیفِ
        جمعِ زیرِ جدول ("sum" | برچسب | None)، حساب‌شده در پایتون (نه فرمول) ·
        ltr_cols = ستون‌هایی که شناسه‌ی لاتین دارند (IP، کلید) و چپ‌چین می‌مانند."""
        heads = [c[0] for c in cols]
        if any(not str(h).strip() for h in heads):
            raise ValueError("empty header in %r" % ws.name)
        kinds = [c[1] for c in cols]
        for j, c in enumerate(cols, 1):               # عرضِ جدول بر عرضِ اعلام‌شده‌ی برگه غالب
            if j > len(ws.widths):
                ws.widths.append(c[2])
            else:
                ws.widths[j - 1] = max(ws.widths[j - 1], c[2])
        rows = list(rows)
        nrow = len(rows)
        if self.cells + (nrow + 2) * len(cols) > self.max_cells:
            keep = max(0, (self.max_cells - self.cells) // max(1, len(cols)) - 2)
            self.trimmed.append((ws.name, nrow - keep, keep))
            if not keep:
                empty = self.words["trimmed_empty"].format(empty=empty, n=self.num(nrow))
            rows = rows[:keep]
            nrow = keep
        can_filter = bool(filt and nrow and ws.filter is None)
        self.header_row(ws, r0, heads, filtered=can_filter)
        prose = {j for j, (h, k, w) in enumerate(cols) if k == "txt" and w >= 40}
        ltr = set(ltr_cols)
        for i, row in enumerate(rows):
            rr = r0 + 1 + i
            fill = "band" if (zebra and i % 2) else None
            mh = 0
            for j, kind in enumerate(kinds):
                v = row[j] if j < len(row) else None
                al = "wrap" if j in prose else ("ltr" if j in ltr else None)
                if kind == "txt" and isinstance(v, str) and j not in prose and j not in ltr \
                        and text_width(v) > cols[j][2]:
                    al = "wrap"
                self.put(ws, rr, j + 1, v, kind, fill=fill, align=al)
                if al == "wrap" and v not in (None, ""):
                    mh = max(mh, fit_height(v, cols[j][2]))
            if mh:
                ws.row_h[rr] = max(ws.row_h.get(rr, 0), mh)
        last = r0 + nrow
        if not nrow:
            self.empty_tables.add(ws.name)
            self.put(ws, r0 + 1, 1, empty, "txt", "note", align="wrap", border=False)
            self.merge(ws, r0 + 1, 1, r0 + 1, len(cols))
            ws.row_h[r0 + 1] = fit_height(empty, sum(c_[2] for c_ in cols))
            return r0 + 1, r0 + 1
        L = col_letter(len(cols))
        if can_filter:
            ws.filter = "A%d:%s%d" % (r0, L, last)
        if freeze and ws.freeze is None:
            ws.freeze = (r0 + 1, 2)
        for j in bars:
            cl = col_letter(j + 1)
            ws.cf.append(("%s%d:%s%d" % (cl, r0 + 1, cl, last),
                          '<cfRule type="dataBar" priority="@@PRIO@@"><dataBar><cfvo type="min"/><cfvo type="max"/>'
                          '<color rgb="FF7FBFB2"/></dataBar></cfRule>'))
        for j, lo, mid, hi in scales:
            cl = col_letter(j + 1)
            ws.cf.append(("%s%d:%s%d" % (cl, r0 + 1, cl, last),
                          '<cfRule type="colorScale" priority="@@PRIO@@"><colorScale><cfvo type="min"/>'
                          '<cfvo type="percentile" val="50"/><cfvo type="max"/><color rgb="FF%s"/>'
                          '<color rgb="FF%s"/><color rgb="FF%s"/></colorScale></cfRule>' % (lo, mid, hi)))
        for spec in cf:
            j, op, vals, fill = spec[:4]
            color = spec[4] if len(spec) > 4 else None
            cl = col_letter(j + 1)
            dx = self.st.dxf(fill, color)
            ws.cf.append(("%s%d:%s%d" % (cl, r0 + 1, cl, last),
                          '<cfRule type="cellIs" dxfId="%d" priority="@@PRIO@@" operator="%s">%s</cfRule>'
                          % (dx, op, "".join("<formula>%s</formula>" % xml_text(v) for v in vals))))
        if total:
            for j, kind in enumerate(kinds):
                spec = total[j] if j < len(total) else None
                v = None
                if spec == "sum":
                    xs = [row[j] for row in rows if j < len(row) and isinstance(row[j], (int, float))
                          and not isinstance(row[j], bool)]
                    v = round(sum(xs), 2) if xs else None
                elif spec is not None:
                    v = spec
                self.put(ws, last + 1, j + 1, v, "txt" if isinstance(v, str) else kind, "b", "kv")
        return r0 + 1, last

    def kv(self, ws, r, pairs):
        """جدولِ دوستونیِ «برچسب | مقدار» ⇒ ردیفِ بعد. pairs = [(برچسب، مقدار، نوع)]."""
        n = len(ws.widths)
        for lbl, val, kind in pairs:
            self.put(ws, r, 1, lbl, "txt", "b", "kv")
            vw = sum(ws.widths[1:]) or 20
            wrap = kind == "txt" and isinstance(val, str) and text_width(val) > vw
            self.put(ws, r, 2, val, kind, align="wrap" if wrap else None)
            for cc in range(3, n + 1):
                self.put(ws, r, cc, None)
            self.merge(ws, r, 2, r, n)
            if wrap:
                ws.row_h[r] = fit_height(val, vw)
            r += 1
        return r

    def cards(self, ws, r, cards, per_row=4, span=2):
        """کاشی‌های KPI: هر کاشی span ستون × سه ردیف (برچسب/مقدار/زیرنویس).
        cards = [(برچسب، مقدار، نوع، زیرنویس، لحن ok|warn|bad|None)] ⇒ ردیفِ بعد."""
        for i, (lbl, val, kind, sub, tone) in enumerate(cards):
            row = r + (i // per_row) * 4
            col = 1 + (i % per_row) * span
            fill = tone if tone in ("ok", "warn", "bad") else "card"
            for rr in range(row, row + 3):
                self.merge(ws, rr, col, rr, col + span - 1)
                for cc in range(col + 1, col + span):
                    self.put(ws, rr, cc, None, fill=fill)
            self.put(ws, row, col, lbl, "txt", "lbl", fill, "c")
            if val is None:
                self.put(ws, row + 1, col, self.words["unknown"], "txt", "bigmute", fill, "c")
            else:
                self.put(ws, row + 1, col, val, kind, "big", fill, "c")
            self.put(ws, row + 2, col, sub or "", "txt", "sub", fill, "cwrap")
            ws.row_h[row] = 18
            ws.row_h[row + 1] = 30
            w = sum(ws.widths[col - 1:col - 1 + span]) or 24
            ws.row_h[row + 2] = max(ws.row_h.get(row + 2, 0), fit_height(sub or "", w, 14, 18))
        rows = math.ceil(len(cards) / per_row) if cards else 0
        return r + rows * 4

    # ── نمودارِ بومی ───────────────────────────────────────────────────────
    def chart(self, host, row, col, kind, title, data_ws, series, r0, r1, cat_col=1, colors=(),
              stacked=False, horizontal=False, width_cm=24, height_cm=7.5, y_title="", y_min=None,
              y_max=None, dashed=()):
        """نمودارِ بومی روی برگه‌ی `host` با داده‌ی برگه‌ی `data_ws` (ردیف‌های r0..r1، سرصفحه در r0-1).
        kind = "bar" | "line". series = شماره‌ی ستون‌های داده (۱-مبنا). خالی ⇒ None (ساخته نمی‌شود)."""
        if r1 < r0 or data_ws.name in self.empty_tables or not series:
            return None
        sn = quote_sheet(data_ws.name)
        cat = "%s!$%s$%d:$%s$%d" % (sn, col_letter(cat_col), r0, col_letter(cat_col), r1)
        sers = []
        for i, c in enumerate(series):
            color = colors[i] if i < len(colors) else (GREEN, BLUE, BADTX, PURPLE, WARNTX, TEAL)[i % 6]
            if kind == "line":
                sp = '<c:spPr><a:ln w="22225" cap="rnd"><a:solidFill><a:srgbClr val="%s"/></a:solidFill>%s<a:round/></a:ln></c:spPr>' % (
                    color, '<a:prstDash val="dash"/>' if i in dashed else "")
                extra = '<c:marker><c:symbol val="none"/></c:marker>'
            else:
                sp = '<c:spPr><a:solidFill><a:srgbClr val="%s"/></a:solidFill></c:spPr>' % color
                extra = '<c:invertIfNegative val="0"/>'
            sers.append(
                '<c:ser><c:idx val="%d"/><c:order val="%d"/><c:tx><c:strRef><c:f>%s!$%s$%d</c:f></c:strRef></c:tx>%s%s'
                '<c:cat><c:strRef><c:f>%s</c:f></c:strRef></c:cat><c:val><c:numRef><c:f>%s!$%s$%d:$%s$%d</c:f></c:numRef></c:val>%s</c:ser>'
                % (i, i, sn, col_letter(c), r0 - 1, sp, extra, xml_text(cat), sn, col_letter(c), r0, col_letter(c), r1,
                   '<c:smooth val="0"/>' if kind == "line" else ""))
        if kind == "line":
            plot = ('<c:lineChart><c:grouping val="standard"/><c:varyColors val="0"/>%s<c:marker val="1"/>'
                    '<c:axId val="5001"/><c:axId val="5002"/></c:lineChart>' % "".join(sers))
        else:
            plot = ('<c:barChart><c:barDir val="%s"/><c:grouping val="%s"/><c:varyColors val="0"/>%s'
                    '<c:gapWidth val="60"/>%s<c:axId val="5001"/><c:axId val="5002"/></c:barChart>'
                    % ("bar" if horizontal else "col", "stacked" if stacked else "clustered", "".join(sers),
                       '<c:overlap val="100"/>' if stacked else ""))
        scal = '<c:orientation val="minMax"/>%s%s' % (
            '<c:max val="%s"/>' % y_max if y_max is not None else "", '<c:min val="%s"/>' % y_min if y_min is not None else "")
        rich = lambda t, sz: ('<c:tx><c:rich><a:bodyPr/><a:lstStyle/><a:p><a:pPr><a:defRPr sz="%d" b="1"/></a:pPr>'  # noqa: E731
                              '<a:r><a:rPr lang="fa-IR" sz="%d" b="1"/><a:t>%s</a:t></a:r></a:p></c:rich></c:tx>' % (sz, sz, xml_text(t)))
        ytitle = ('<c:title>%s<c:overlay val="0"/></c:title>' % rich(y_title, 900)) if y_title else ""
        xml = (XML_HEAD + '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
               'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="%s">'
               '<c:roundedCorners val="0"/><c:chart><c:title>%s<c:overlay val="0"/></c:title><c:autoTitleDeleted val="0"/>'
               '<c:plotArea><c:layout/>%s'
               '<c:catAx><c:axId val="5001"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/>'
               '<c:axPos val="%s"/><c:numFmt formatCode="General" sourceLinked="1"/><c:majorTickMark val="out"/>'
               '<c:minorTickMark val="none"/><c:tickLblPos val="nextTo"/><c:crossAx val="5002"/><c:crosses val="autoZero"/>'
               '<c:auto val="1"/><c:lblAlgn val="ctr"/><c:lblOffset val="100"/><c:noMultiLvlLbl val="0"/></c:catAx>'
               '<c:valAx><c:axId val="5002"/><c:scaling>%s</c:scaling><c:delete val="0"/><c:axPos val="%s"/>'
               '<c:majorGridlines><c:spPr><a:ln w="6350"><a:solidFill><a:srgbClr val="E5E7EB"/></a:solidFill></a:ln></c:spPr></c:majorGridlines>'
               '%s<c:numFmt formatCode="General" sourceLinked="1"/><c:majorTickMark val="out"/><c:minorTickMark val="none"/>'
               '<c:tickLblPos val="nextTo"/><c:crossAx val="5001"/><c:crosses val="autoZero"/><c:crossBetween val="between"/></c:valAx>'
               '</c:plotArea><c:legend><c:legendPos val="b"/><c:overlay val="0"/></c:legend><c:plotVisOnly val="1"/>'
               '<c:dispBlanksAs val="gap"/></c:chart></c:chartSpace>'
               % (NS_R, rich(title, 1200), plot, "l" if horizontal else "b", scal, "b" if horizontal else "l", ytitle))
        host.charts.append((row, col, width_cm, height_cm, xml))
        return True

    # ── ذخیره ─────────────────────────────────────────────────────────────
    def _sheet_xml(self, idx, ws, drawing_rid):
        o = [XML_HEAD, '<worksheet xmlns="%s" xmlns:r="%s">' % (NS_MAIN, NS_R)]
        o.append("<sheetPr>%s<pageSetUpPr fitToPage=\"1\"/></sheetPr>" % (
            '<tabColor rgb="FF%s"/>' % ws.tab if ws.tab else ""))
        mr, mc = ws.max_row, ws.max_col
        o.append('<dimension ref="A1:%s"/>' % ref(mr, mc))
        sv = '<sheetView%s showGridLines="0"%s workbookViewId="0">' % (
            ' rightToLeft="1"' if ws.rtl else "", ' tabSelected="1"' if idx == 0 else "")
        if ws.freeze:
            fr, fc = ws.freeze
            tl = ref(fr, fc)
            xs, ys = fc - 1, fr - 1
            if xs and ys:
                sv += ('<pane xSplit="%d" ySplit="%d" topLeftCell="%s" activePane="bottomRight" state="frozen"/>'
                       '<selection pane="topRight" activeCell="%s" sqref="%s"/>'
                       '<selection pane="bottomLeft" activeCell="%s" sqref="%s"/>'
                       '<selection pane="bottomRight" activeCell="%s" sqref="%s"/>'
                       % (xs, ys, tl, ref(1, fc), ref(1, fc), ref(fr, 1), ref(fr, 1), tl, tl))
            elif ys:
                sv += ('<pane ySplit="%d" topLeftCell="%s" activePane="bottomLeft" state="frozen"/>'
                       '<selection pane="bottomLeft" activeCell="%s" sqref="%s"/>' % (ys, tl, tl, tl))
            else:
                sv += ('<pane xSplit="%d" topLeftCell="%s" activePane="topRight" state="frozen"/>'
                       '<selection pane="topRight" activeCell="%s" sqref="%s"/>' % (xs, tl, tl, tl))
        else:
            sv += '<selection activeCell="A1" sqref="A1"/>'
        o.append("<sheetViews>%s</sheetView></sheetViews>" % sv)
        o.append('<sheetFormatPr defaultRowHeight="15"/>')
        if ws.widths:
            o.append("<cols>%s</cols>" % "".join(
                '<col min="%d" max="%d" width="%s" customWidth="1"/>' % (j, j, "%g" % float(w))
                for j, w in enumerate(ws.widths, 1)))
        o.append("<sheetData>")
        rows = {}
        for (r, c), cell in ws.cells.items():
            rows.setdefault(r, {})[c] = cell
        for r in sorted(set(rows) | set(ws.row_h)):
            ht = ws.row_h.get(r)
            o.append('<row r="%d"%s>' % (r, ' ht="%s" customHeight="1"' % ("%g" % ht) if ht else ""))
            for c in sorted(rows.get(r, {})):
                v, xf = rows[r][c]
                a = ref(r, c)
                s = ' s="%d"' % xf if xf else ""
                if v is None:
                    o.append('<c r="%s"%s/>' % (a, s))
                elif isinstance(v, str):
                    o.append('<c r="%s"%s t="s"><v>%d</v></c>' % (a, s, self._s(v)))
                elif isinstance(v, (datetime, date)):
                    o.append('<c r="%s"%s><v>%s</v></c>' % (a, s, repr(round(excel_serial(v), 8))))
                elif isinstance(v, bool):
                    o.append('<c r="%s"%s t="b"><v>%d</v></c>' % (a, s, 1 if v else 0))
                elif isinstance(v, int):
                    o.append('<c r="%s"%s><v>%d</v></c>' % (a, s, v))
                else:
                    o.append('<c r="%s"%s><v>%s</v></c>' % (a, s, repr(float(v))))
            o.append("</row>")
        o.append("</sheetData>")
        if ws.filter:
            o.append('<autoFilter ref="%s"/>' % ws.filter)
        if ws.merges:
            o.append('<mergeCells count="%d">%s</mergeCells>' % (
                len(ws.merges), "".join('<mergeCell ref="%s"/>' % m for m in ws.merges)))
        pr = 0
        for sq, rule in ws.cf:
            pr += 1
            o.append('<conditionalFormatting sqref="%s">%s</conditionalFormatting>' % (sq, rule.replace("@@PRIO@@", str(pr))))
        if ws.links:
            o.append("<hyperlinks>%s</hyperlinks>" % "".join(
                '<hyperlink ref="%s" location="%s" display="%s"/>' % (a, xml_text(loc), xml_text(disp))
                for a, loc, disp in ws.links))
        o.append('<printOptions horizontalCentered="1"/>')
        o.append('<pageMargins left="0.35" right="%s" top="0.8" bottom="0.5" header="0.3" footer="0.3"/>' % ws.right_margin)
        per_page = 160.0 if ws.landscape else 110.0
        o.append('<pageSetup paperSize="9" orientation="%s" fitToWidth="%d" fitToHeight="0"/>' % (
            "landscape" if ws.landscape else "portrait", max(1, math.ceil(sum(ws.widths) / per_page))))
        hdr = "&R&8%s" % hf_text(self.title)
        if self.classification:
            hdr = "&L&8%s" % hf_text(self.classification) + hdr
        o.append("<headerFooter><oddHeader>%s</oddHeader><oddFooter>&amp;L&amp;8&amp;P / &amp;N&amp;C&amp;8&amp;A</oddFooter></headerFooter>"
                 % xml_text(hdr))
        if ws.row_breaks:
            o.append('<rowBreaks count="%d" manualBreakCount="%d">%s</rowBreaks>' % (
                len(ws.row_breaks), len(ws.row_breaks),
                "".join('<brk id="%d" max="16383" man="1"/>' % b for b in ws.row_breaks)))
        if drawing_rid:
            o.append('<drawing r:id="%s"/>' % drawing_rid)
        o.append("</worksheet>")
        return "".join(o)

    def _row_tops(self, ws, upto):
        tops, acc = [], 0.0
        for r in range(1, upto + 2):
            tops.append(acc)
            acc += ws.row_h.get(r, 15)
        return tops

    def _drawing(self, ws, chart_ids):
        """(drawing.xml، rels) برای نمودارها و شکل‌های یک برگه."""
        import bisect
        out, rels, nid = [], [], 2
        for (row, col, wcm, hcm, _xml), cid in zip(ws.charts, chart_ids):
            rid = "rIdC%d" % cid
            rels.append((rid, "chart", "../charts/chart%d.xml" % cid))
            out.append('<xdr:oneCellAnchor><xdr:from><xdr:col>%d</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>%d</xdr:row>'
                       '<xdr:rowOff>0</xdr:rowOff></xdr:from><xdr:ext cx="%d" cy="%d"/><xdr:graphicFrame macro="">'
                       '<xdr:nvGraphicFramePr><xdr:cNvPr id="%d" name="Chart %d"/><xdr:cNvGraphicFramePr/></xdr:nvGraphicFramePr>'
                       '<xdr:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/></xdr:xfrm><a:graphic>'
                       '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart">'
                       '<c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" r:id="%s"/>'
                       '</a:graphicData></a:graphic></xdr:graphicFrame><xdr:clientData/></xdr:oneCellAnchor>'
                       % (col - 1, row - 1, int(wcm * EMU_CM), int(hcm * EMU_CM), nid, nid, rid))
            nid += 1
        cv = ws.canvas
        if cv is not None and cv.items:
            W = _e(cv.width)
            last_y = max(y + h for _x, _w, y, h, *_ in cv.items)
            n = 1
            while self._row_tops(ws, n)[-1] < last_y + 30:
                n += 50
            tops = self._row_tops(ws, n)
            cw = [_e(ws.width_of(c) * 6) for c in range(1, 400)]   # پهنای ستون در Excel ِ مک = width × 6 نقطه
            for x, w, y, h, item, fh, fv in cv.items:
                xl = (W - _e(x) - _e(w)) if ws.rtl else _e(x)
                item = item.replace("%XF%", '<a:xfrm%s%s><a:off x="%d" y="%d"/><a:ext cx="%d" cy="%d"/></a:xfrm>' % (
                    ' flipH="1"' if fh else "", ' flipV="1"' if fv else "",
                    xl, _e(y), max(0, _e(w)), max(0, _e(h))))
                col, rem = 0, max(0, xl)
                while col < len(cw) - 1 and rem >= cw[col]:
                    rem -= cw[col]
                    col += 1
                r = max(0, bisect.bisect_right(tops, y) - 1)
                roff = max(0, _e(y - tops[r]))
                out.append('<xdr:oneCellAnchor><xdr:from><xdr:col>%d</xdr:col><xdr:colOff>%d</xdr:colOff><xdr:row>%d</xdr:row>'
                           '<xdr:rowOff>%d</xdr:rowOff></xdr:from><xdr:ext cx="%d" cy="%d"/>%s<xdr:clientData/></xdr:oneCellAnchor>'
                           % (col, rem, r, roff, max(0, _e(w)), max(0, _e(h)), item))
            for rid, tgt in cv.rels:
                rels.append((rid, "hyperlink", tgt))
        xml = XML_HEAD + '<xdr:wsDr %s>%s</xdr:wsDr>' % (NS_DRAW, "".join(out))
        rx = XML_HEAD + '<Relationships xmlns="%s">%s</Relationships>' % (NS_REL, "".join(
            '<Relationship Id="%s" Type="%s%s" Target="%s"/>' % (rid, REL_T, typ, xml_text(t)) for rid, typ, t in rels))
        return xml, rx

    def save(self):
        if self.trimmed:
            home = next((s for s in self.sheets if s.name == self.home), self.sheets[0] if self.sheets else None)
            if home is not None:
                r = home.max_row + 2
                for nm, cut, keep in self.trimmed:
                    self.put(home, r, 1, self.words["trimmed"].format(sheet=nm, cut=self.num(cut), keep=self.num(keep)), "txt", "note", border=False)
                    r += 1
        if not self.sheets:
            self.sheet(self.home, self.title)
        files = {}
        ct = ['<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
              '<Default Extension="xml" ContentType="application/xml"/>',
              '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
              '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
              '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>',
              '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>',
              '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>']
        wb_rels = []
        sheets_xml, names = [], []
        chart_no, drawing_no = 0, 0
        for i, ws in enumerate(self.sheets):
            n = i + 1
            drid = None
            if ws.charts or (ws.canvas is not None and ws.canvas.items):
                drawing_no += 1
                ids = []
                for _row, _col, _w, _h, cx in ws.charts:
                    chart_no += 1
                    ids.append(chart_no)
                    files["xl/charts/chart%d.xml" % chart_no] = cx
                    ct.append('<Override PartName="/xl/charts/chart%d.xml" '
                              'ContentType="application/vnd.openxmlformats-officedocument.drawingml.chart+xml"/>' % chart_no)
                dx, drx = self._drawing(ws, ids)
                files["xl/drawings/drawing%d.xml" % drawing_no] = dx
                files["xl/drawings/_rels/drawing%d.xml.rels" % drawing_no] = drx
                ct.append('<Override PartName="/xl/drawings/drawing%d.xml" '
                          'ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>' % drawing_no)
                drid = "rIdD1"
                files["xl/worksheets/_rels/sheet%d.xml.rels" % n] = (
                    XML_HEAD + '<Relationships xmlns="%s"><Relationship Id="rIdD1" Type="%sdrawing" '
                    'Target="../drawings/drawing%d.xml"/></Relationships>' % (NS_REL, REL_T, drawing_no))
            files["xl/worksheets/sheet%d.xml" % n] = self._sheet_xml(i, ws, drid)
            ct.append('<Override PartName="/xl/worksheets/sheet%d.xml" '
                      'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % n)
            wb_rels.append('<Relationship Id="rId%d" Type="%sworksheet" Target="worksheets/sheet%d.xml"/>' % (n, REL_T, n))
            sheets_xml.append('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (xml_text(ws.name), n, n))
            q = quote_sheet(ws.name)
            if ws.filter:
                a, b = ws.filter.split(":")
                ca, na = re.fullmatch(r"([A-Z]+)(\d+)", a).groups()  # type: ignore[union-attr]
                cb, nb = re.fullmatch(r"([A-Z]+)(\d+)", b).groups()  # type: ignore[union-attr]
                names.append('<definedName name="_xlnm._FilterDatabase" localSheetId="%d" hidden="1">%s!$%s$%s:$%s$%s</definedName>'
                             % (i, xml_text(q), ca, na, cb, nb))
            if ws.print_area:
                names.append('<definedName name="_xlnm.Print_Area" localSheetId="%d">%s!%s</definedName>'
                             % (i, xml_text(q), ws.print_area))
            if ws.title_rows:
                a, b = ws.title_rows.split(":")
                names.append('<definedName name="_xlnm.Print_Titles" localSheetId="%d">%s!$%s:$%s</definedName>'
                             % (i, xml_text(q), a, b))
        k = len(self.sheets)
        wb_rels.append('<Relationship Id="rId%d" Type="%sstyles" Target="styles.xml"/>' % (k + 1, REL_T))
        wb_rels.append('<Relationship Id="rId%d" Type="%ssharedStrings" Target="sharedStrings.xml"/>' % (k + 2, REL_T))
        # styles و sharedStrings بعد از برگه‌ها ساخته می‌شوند — برگه‌ها هنوز رشته و سبک ثبت می‌کردند
        files["xl/styles.xml"] = self.st.xml()
        files["xl/sharedStrings.xml"] = (XML_HEAD + '<sst xmlns="%s" count="%d" uniqueCount="%d">%s</sst>' % (
            NS_MAIN, len(self.sst), len(self.sst),
            "".join('<si><t xml:space="preserve">%s</t></si>' % xml_text(s) for s in self.sst)))
        files["xl/workbook.xml"] = (
            XML_HEAD + '<workbook xmlns="%s" xmlns:r="%s"><workbookPr/><bookViews><workbookView xWindow="0" yWindow="0" '
            'windowWidth="14000" windowHeight="9000" activeTab="0"/></bookViews><sheets>%s</sheets>%s'
            '<calcPr calcId="191029"/></workbook>'
            % (NS_MAIN, NS_R, "".join(sheets_xml), ("<definedNames>%s</definedNames>" % "".join(names)) if names else ""))
        files["xl/_rels/workbook.xml.rels"] = XML_HEAD + '<Relationships xmlns="%s">%s</Relationships>' % (NS_REL, "".join(wb_rels))
        files["_rels/.rels"] = (
            XML_HEAD + '<Relationships xmlns="%s"><Relationship Id="rId1" Type="%sofficeDocument" Target="xl/workbook.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" '
            'Target="docProps/core.xml"/><Relationship Id="rId3" Type="%sextended-properties" Target="docProps/app.xml"/>'
            '</Relationships>' % (NS_REL, REL_T, REL_T))
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        p = self.props
        creator = p.get("creator") or "wg-panel"
        core = ['<dc:title>%s</dc:title>' % xml_text(p.get("title") or self.title),
                '<dc:creator>%s</dc:creator>' % xml_text(creator),
                '<cp:lastModifiedBy>%s</cp:lastModifiedBy>' % xml_text(creator)]
        for k_, tag in (("subject", "dc:subject"), ("description", "dc:description"),
                        ("keywords", "cp:keywords"), ("category", "cp:category")):
            if p.get(k_):
                core.append("<%s>%s</%s>" % (tag, xml_text(p[k_]), tag))
        core += ['<dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>' % now,
                 '<dcterms:modified xsi:type="dcterms:W3CDTF">%s</dcterms:modified>' % now]
        files["docProps/core.xml"] = (
            XML_HEAD + '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">%s'
            '</cp:coreProperties>' % "".join(core))
        files["docProps/app.xml"] = (
            XML_HEAD + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
            'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>%s</Application>'
            '<DocSecurity>0</DocSecurity><ScaleCrop>false</ScaleCrop><Company></Company><LinksUpToDate>false</LinksUpToDate>'
            '<SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>16.0300</AppVersion></Properties>'
            % xml_text(creator))
        files["[Content_Types].xml"] = (XML_HEAD + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">%s</Types>'
                                        % "".join(ct))
        order = ["[Content_Types].xml", "_rels/.rels", "docProps/app.xml", "docProps/core.xml", "xl/workbook.xml",
                 "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/sharedStrings.xml"]
        order += sorted(n for n in files if n not in order)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name in order:
                zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(zi, files[name].encode("utf-8"))
        return buf.getvalue()
