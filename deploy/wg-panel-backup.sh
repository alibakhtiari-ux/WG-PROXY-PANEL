#!/bin/bash
# بکاپ شبانه‌ی سامانه‌ی wg-panel (اجرا با root از systemd timer)
# شامل: config.json (کاربران/نقش‌ها/secret/TLS)، traffic.db (اسنپ‌شات سازگارِ
# sqlite حتی وسط نوشتن WAL)، کانفیگ کلاینت‌ها، کانفیگ‌های WireGuard و Squid.
# خروجی: /var/backups/wg-panel/wg-panel-<تاریخ>.tar.gz (فقط root، نگهداشت ۱۴ نسخه)
set -euo pipefail

DEST=/var/backups/wg-panel
KEEP=14
TS=$(date +%Y%m%d-%H%M%S)
TMP=$(mktemp -d /tmp/wgpb.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

install -d -m 700 "$DEST"
mkdir -p "$TMP/wg-panel" "$TMP/wireguard" "$TMP/squid"

# اسنپ‌شات امنِ دیتابیس با API backup خود sqlite (نه cp، تا نیمه‌نوشته نگیریم)
python3 - "$TMP" <<'PY'
import sqlite3, sys
src = sqlite3.connect("file:/opt/wg-panel/traffic.db?mode=ro", uri=True)
dst = sqlite3.connect(sys.argv[1] + "/wg-panel/traffic.db")
with dst:
    src.backup(dst)
dst.close(); src.close()
PY

cp -a /opt/wg-panel/config.json /opt/wg-panel/wg_panel.py "$TMP/wg-panel/"
[ -f /opt/wg-panel/qr.js ] && cp -a /opt/wg-panel/qr.js "$TMP/wg-panel/"
# فایل‌های استاتیک نمای سه‌بعدی TV (vendorشده؛ اختیاری مثل qr.js)
for _f in three.module.min.js.gz three.core.min.js.gz three.LICENSE.txt; do
  [ -f "/opt/wg-panel/$_f" ] || continue
  cp -a "/opt/wg-panel/$_f" "$TMP/wg-panel/"
done
[ -d /opt/wg-panel/clients ] && cp -a /opt/wg-panel/clients "$TMP/wg-panel/"
cp -a /etc/wireguard/*.conf "$TMP/wireguard/" 2>/dev/null || true
[ -f /etc/squid/squid.conf ] && cp -a /etc/squid/squid.conf "$TMP/squid/"
[ -f /etc/squid/passwd ] && cp -a /etc/squid/passwd "$TMP/squid/"

OUT="$DEST/wg-panel-$TS.tar.gz"
tar -C "$TMP" -czf "$OUT" .
chmod 600 "$OUT"
ln -sf "wg-panel-$TS.tar.gz" "$DEST/latest.tar.gz"

# نگهداشت: فقط KEEP نسخه‌ی آخر
ls -1t "$DEST"/wg-panel-*.tar.gz | tail -n +$((KEEP + 1)) | xargs -r rm -f

echo "backup ok: $(basename "$OUT") ($(du -h "$OUT" | cut -f1))"
