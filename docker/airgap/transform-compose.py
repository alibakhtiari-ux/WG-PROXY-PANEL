#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تبدیلِ docker-compose.yml کانونی به نسخه‌ی آفلاین (airgap).

سه کار، نه بیشتر:
  ۱) حذفِ بلوکِ build: (در بسته‌ی آفلاین context ِ بیلد وجود ندارد)
  ۲) پین‌کردنِ image به تگِ نسخه (wg-panel:<12hex>) به‌جای :local
  ۳) جایگزینیِ سرآیندِ توضیحی با بنرِ آفلاین (دستورِ «up -d --build» گمراه‌کننده است)

عمداً «الگو-سخت‌گیر» است: اگر ساختارِ compose کانونی عوض شود و انتظارها را
نبیند، بلند می‌میرد تا بیلدِ بسته شکست بخورد — نه اینکه بی‌صدا composeِ
خرابی واردِ بسته شود. تستِ tests/test_docker_airgap.py همین را روی نسخه‌ی
کانونی اجرا می‌کند تا واگرایی پیش از بیلد دیده شود.

استفاده:  transform-compose.py <compose-in> <image-tag>   → خروجی روی stdout
"""
import re
import sys

BANNER = """\
# wg-panel — نسخه‌ی آفلاین (airgap): ایمیج از پیش با «docker load» وارد شده
# و این فایل هیچ build ای ندارد. راه‌اندازی:
#   docker compose up -d
# پیکربندی در .env (کنارِ همین فایل)؛ راهنمای کامل: README-OFFLINE.md
"""


def transform(text, image_tag):
    if not re.fullmatch(r"wg-panel:[0-9a-f]{12}", image_tag):
        raise SystemExit("تگِ ایمیج باید wg-panel:<12hex> باشد، نه %r" % image_tag)

    lines = text.splitlines(keepends=True)

    # ۳) سرآیند: خطوطِ کامنت/خالیِ ابتدای فایل تا اولین خطِ واقعی
    body = 0
    while body < len(lines) and (
            lines[body].lstrip().startswith("#") or not lines[body].strip()):
        body += 1
    if body == 0 or not lines[body].startswith("name:"):
        raise SystemExit("انتظارِ سرآیندِ کامنت و سپس «name:» برآورده نشد — "
                         "compose کانونی عوض شده؛ transform را هم‌گام کن.")
    out = [BANNER, "\n"] + lines[body:]

    # ۱) بلوکِ build: با دقیقاً دو زیرسطر (context/dockerfile)
    joined = "".join(out)
    build_re = re.compile(
        r"^([ \t]+)build:\n\1[ \t]+context: \.\.\n\1[ \t]+dockerfile: docker/Dockerfile\n",
        re.M)
    joined, n = build_re.subn("", joined)
    if n != 1:
        raise SystemExit("بلوکِ build: پیدا/حذف نشد (n=%d) — compose کانونی "
                         "عوض شده؛ transform را هم‌گام کن." % n)

    # ۲) پینِ ایمیج
    joined, n = re.subn(r"^([ \t]+)image: wg-panel:local$",
                        r"\1image: %s" % image_tag, joined, flags=re.M)
    if n != 1:
        raise SystemExit("خطِ «image: wg-panel:local» پیدا نشد (n=%d)." % n)

    if re.search(r"^\s*build\s*:", joined, re.M):
        raise SystemExit("بعد از تبدیل هنوز build: باقی است — انتظارها ناقص‌اند.")
    return joined


def main():
    if len(sys.argv) != 3:
        raise SystemExit("استفاده: transform-compose.py <docker-compose.yml> <wg-panel:12hex>")
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        sys.stdout.write(transform(f.read(), sys.argv[2]))


if __name__ == "__main__":
    main()
