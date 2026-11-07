# -*- coding: utf-8 -*-
"""بررسیِ نحوِ JavaScript ِ درونِ wgpanel/web/ با `node --check`.

پایتون داخلِ رشته‌ها را نمی‌بیند: py_compile روی JS ِ خراب هم موفق می‌شود و
نتیجه صفحهٔ سفید در مرورگر است. این اسکریپت هر <script> ِ درون‌خطیِ
PAGE_HTML و SHARE_HTML و ماژولِ TV3D_JS را جدا می‌کند و به node می‌دهد. منبع: wgpanel/web/.

    python3 tests/check_js.py

کدِ خروج: ۰ یعنی همه سالم؛ ۱ یعنی خطای نحوی (یا الگوی استخراج دیگر با سورس
نمی‌خواند)؛ ۲ یعنی node نصب نیست. نامش عمداً با test_ شروع نمی‌شود تا
unittest discover آن را اجرا نکند — CI آن را به‌عنوانِ یک مرحلهٔ جدا اجرا
می‌کند و نبودنِ node آن‌جا باید شکست باشد، نه skip.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
BLOCKS = ("PAGE_HTML", "SHARE_HTML", "TV3D_JS")


WEB = {"PAGE_HTML": "page.html", "SHARE_HTML": "share.html",
       "TV3D_JS": "tv3d.mjs"}
# فایل‌های JS ِ مستقلِ صفحه (با <script src> بار می‌شوند، نه درون‌خطی)
STANDALONE = ("svgstudio.js", "studio.js")


def extract(pkg):
    """[(نامِ فایل، متنِ JS)] — همان جایگذاری‌هایی که سرور در زمانِ اجرا دارد."""
    out = []
    for name in BLOCKS:
        path = pkg / "web" / WEB[name]
        if not path.is_file():
            raise SystemExit("check_js: %s پیدا نشد" % path)
        body = path.read_text(encoding="utf-8")
        if name == "TV3D_JS":
            out.append(("tv3d.mjs", body))
            continue
        scripts = re.findall(
            r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", body, re.S)
        if not scripts:
            raise SystemExit("check_js: هیچ <script> ای در %s نیست" % name)
        for i, js in enumerate(scripts):
            js = js.replace("__PAYLOAD__", "null").replace(
                "__SHARE_BOOTSTRAP__", "var _T={},_FA=false;")
            out.append(("%s_%d.js" % (name, i), js))
    for fn in STANDALONE:
        path = pkg / "web" / fn
        if not path.is_file():
            raise SystemExit("check_js: %s پیدا نشد" % path)
        out.append((fn, path.read_text(encoding="utf-8")))
    return out


def main():
    node = shutil.which("node")
    if node is None:
        print("check_js: node is not installed", file=sys.stderr)
        return 2
    pkg = ROOT / "wgpanel"
    failed = []
    with tempfile.TemporaryDirectory(prefix="wgjs-check-") as tmp:
        files = extract(pkg)
        for fname, js in files:
            path = pathlib.Path(tmp) / fname
            path.write_text(js, encoding="utf-8")
            p = subprocess.run([node, "--check", str(path)],
                               capture_output=True, text=True)
            if p.returncode != 0:
                failed.append(fname)
                print("FAILED: %s\n%s" % (fname, p.stderr.strip()),
                      file=sys.stderr)
    print("check_js: %d scripts checked, %d failed"
          % (len(files), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
