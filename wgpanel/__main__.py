"""نقطه‌ی ورود: `python3 -m wgpanel` (درختِ سورس) و `python3 wg_panel.pyz` (از راهِ __main__ ِ ریشه‌ی آرشیو)."""
import sys

if sys.argv[1:2] == ["--check"]:
    # خودآزماییِ آفلاینِ بیلد — عمداً wgpanel.app را import نمی‌کند
    # (import ِ app فایلِ traffic.db می‌سازد و سینگلتون‌ها را برپا می‌کند).
    from wgpanel._check import main as _check_main
    sys.exit(_check_main())

from wgpanel.app import main

main()
