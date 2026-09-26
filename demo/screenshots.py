# -*- coding: utf-8 -*-
"""اسکرین‌شات‌های README را از نو می‌سازد — با یک دستور.

    python3 demo/screenshots.py            # ⇐ docs/screenshots/*.png

دمو را در یک پوشه‌ی موقت از صفر می‌سازد، روی یک پورتِ جدا بالا می‌آورد،
demo/screenshots.mjs (Playwright) را اجرا می‌کند و نمودارِ PNG ِ تلگرام را
مستقیم با کدِ خودِ پنل می‌کشد. اگر Pillow نصب باشد تصویرها به ۲۵۶ رنگ و
پهنای مناسبِ README فشرده می‌شوند؛ بدونِ آن، همان PNG ِ خام ذخیره می‌شود.

نیازها: Node.js و Playwright (npm install playwright). پنل و دمو خودشان
فقط کتابخانه‌ی استانداردِ پایتون لازم دارند.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import run as demo  # noqa: E402

# نام ⇐ بیشترین پهنا پس از فشرده‌سازی (پیکسل)
SHOTS = {"overview.png": 2400, "client-chart.png": 2400, "heatmap.png": 2400,
         "rtl-fa.png": 2400, "light.png": 2400, "config-qr.png": 2400,
         "share-mobile.png": 780, "telegram-chart.png": 900}
# پیش‌نمایشِ مخزن: گرادیان دارد و ۲۵۶ رنگ آن را نواری می‌کند، پس فشرده
# نمی‌شود (سقفِ GitHub یک مگابایت است؛ این حدودِ ۲۵۰KB است).
SOCIAL = "social-preview.png"


def telegram_chart(m, path):
    """همان PNG ای که ربات برای «نمودارِ ۳۰ روزه‌ی کاربر» می‌فرستد."""
    pub = next(b["public_key"] for b in m.parse_user_blocks("wg0")
               if b["name"] == "bob-desktop")
    rows = m.META.usage_series("wg0", pub, "30d")
    png = m.render_chart_png(
        [([r["rx"] for r in rows], (63, 185, 80), "RX"),
         ([r["tx"] for r in rows], (88, 166, 255), "TX")],
        x_labels=m.BOT._xlabels(rows, "30d"), title="30D", bars=True)
    with open(path, "wb") as f:
        f.write(png)


def wait_http(url, proc, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            raise SystemExit("screenshots: the demo panel exited early")
        try:
            with urllib.request.urlopen(url, timeout=2):
                return
        except OSError:
            time.sleep(0.5)
    raise SystemExit("screenshots: the demo panel did not answer on " + url)


def shrink(src, dst, max_w):
    try:
        from PIL import Image
    except ImportError:
        shutil.copyfile(src, dst)
        return False
    im = Image.open(src).convert("RGB")
    if im.width > max_w:
        im = im.resize((max_w, round(im.height * max_w / im.width)),
                       Image.LANCZOS)
    im.quantize(colors=256, method=Image.Quantize.MEDIANCUT,
                dither=Image.Dither.NONE).save(dst, optimize=True)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "screenshots"))
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--warmup", type=int, default=180,
                    help="seconds to let the live samples build up first; "
                         "the table's sparklines show the last 3 minutes")
    a = ap.parse_args()
    work = tempfile.mkdtemp(prefix="wg-panel-shots-")
    state, raw = os.path.join(work, "demo"), os.path.join(work, "raw")
    os.makedirs(raw)
    m = demo.prepare(state, reset=True)
    token, err = m.create_share("wg0", "bob-desktop", 1440, False, "admin")
    if err:
        raise SystemExit("screenshots: share link: %s" % err)
    telegram_chart(m, os.path.join(raw, "telegram-chart.png"))

    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "run.py"),
                             "--dir", state, "--port", str(a.port)])
    try:
        base = "http://127.0.0.1:%d" % a.port
        wait_http(base + "/", proc)
        print("screenshots: warming up for %ds so the live charts fill"
              % a.warmup, flush=True)
        time.sleep(a.warmup)
        subprocess.run(["node", os.path.join(HERE, "screenshots.mjs"), base,
                        raw, token], check=True)
    finally:
        proc.terminate()
        proc.wait(timeout=20)

    os.makedirs(a.out, exist_ok=True)
    packed = False
    for name, max_w in SHOTS.items():
        packed = shrink(os.path.join(raw, name), os.path.join(a.out, name),
                        max_w) or packed
        print("  %-20s %4d KB" % (name, os.path.getsize(
            os.path.join(a.out, name)) // 1024))
    shutil.copyfile(os.path.join(raw, SOCIAL),
                    os.path.join(os.path.dirname(a.out), SOCIAL))
    print("  %-20s %4d KB  (docs/, for Settings → Social preview)"
          % (SOCIAL, os.path.getsize(os.path.join(os.path.dirname(a.out),
                                                  SOCIAL)) // 1024))
    if not packed:
        print("screenshots: Pillow is not installed — saved uncompressed PNGs")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
