#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wg-panel — لانچر.

خودِ پنل wg_panel.pyz است (ساخته‌شده از wgpanel/ با tools/build_pyz.py). این فایلِ
کوچک عمداً در همان مسیرِ قدیمی (/opt/wg-panel/wg_panel.py) می‌ماند تا هر چیزی که
امروز به آن اشاره می‌کند بی‌تغییر کار کند:
  · python3 /opt/wg-panel/wg_panel.py           ⇐ ExecStart ِ systemd، docker
  · python3 /opt/wg-panel/wg_panel.py --check   ⇐ خودآزماییِ آفلاینِ بیلد
  · import ِ همین فایل (اسکریپت‌های بکاپ)        ⇐ نام‌های عمومیِ wgpanel.app
"""
import os
import sys

_PYZ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wg_panel.pyz")

if not os.path.isfile(_PYZ):
    _msg = "wg-panel: %s نیست — wg_panel.pyz باید کنارِ این لانچر نصب شود" % _PYZ
    if __name__ == "__main__":
        sys.stderr.write(_msg + "\n")
        raise SystemExit(2)
    raise ImportError(_msg)

if __name__ == "__main__":
    import runpy
    runpy.run_path(_PYZ, run_name="__main__")
else:
    if _PYZ not in sys.path:
        sys.path.insert(0, _PYZ)
    from wgpanel.app import *  # noqa: F401,F403 — سازگاری با import‌کننده‌های قدیمی
