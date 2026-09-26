#!/bin/bash
# healthcheck ِ کانتینر: «پنل جواب می‌دهد» + «اینترفیسِ اصلیِ کاربران زنده است».
# پورت/TLS/نامِ اینترفیس از خودِ config.json خوانده می‌شود تا با هر پیکربندی
# درست بماند (عدد گزارش است، نه حدس).
set -u

read -r scheme port iface < <(python3 - <<'PY'
import json
c = json.load(open("/opt/wg-panel/config.json"))
ifs = c.get("server_ifaces") or [""]
print("https" if c.get("tls_cert") else "http", c.get("port", 8787), ifs[0])
PY
) || exit 1

curl -fsk --max-time 8 -o /dev/null "$scheme://127.0.0.1:$port/" || exit 1

if [ -n "$iface" ]; then
    wg show "$iface" >/dev/null 2>&1 || exit 1
fi
exit 0
