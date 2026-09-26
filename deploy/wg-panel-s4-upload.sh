#!/bin/bash
# آپلودِ شبانه‌ی آخرین بکاپِ wg-panel به MEGA S4 (S3-compatible) با rclone.
# وابسته به بکاپِ محلیِ wg-panel-backup.service (که latest.tar.gz را می‌سازد).
# ریموتِ rclone و نامِ باکت از /etc/wg-panel-s4.env خوانده می‌شوند (فقط root).
set -euo pipefail

ENV_FILE=/etc/wg-panel-s4.env
SRC=/var/backups/wg-panel/latest.tar.gz
KEEP=30
# مسیرِ واحدِ config (پنل هم همین را می‌خواند — ProtectHome مانعِ /root است)
CONF=/etc/wg-panel-rclone.conf
[ -r "$CONF" ] || CONF=/root/.config/rclone/rclone.conf

[ -r "$ENV_FILE" ] || { echo "no $ENV_FILE"; exit 1; }
# shellcheck disable=SC1090
. "$ENV_FILE"   # باید REMOTE و BUCKET (و اختیاری PREFIX) را تعریف کند
: "${REMOTE:?REMOTE تعریف نشده}"
: "${BUCKET:?BUCKET تعریف نشده}"
PREFIX="${PREFIX:-wg-panel}"

# هشدارِ تلگرام (اختیاری): اگر پنل هشدار را فعال کرده باشد، شکستِ آپلود را
# از همان مسیرِ AlertManager (تونل → تلگرام) خبر می‌دهد.
notify() {
    python3 - "$1" 2>/dev/null <<'PY' || true
import sys, importlib.util
spec = importlib.util.spec_from_file_location("wgp", "/opt/wg-panel/wg_panel.py")
m = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(m); m.load_config()
    c = m.alert_cfg()
    if c["enabled"] and c["events"].get("backup", True):
        m.ALERTS.send_now(sys.argv[1])
except Exception:
    pass
PY
}

fail() { echo "$1" >&2; notify "آپلودِ بکاپ به MEGA S4 ناموفق شد: $1"; exit 1; }

[ -s "$SRC" ] || fail "بکاپِ محلی موجود نیست ($SRC)"
REAL=$(readlink -f "$SRC")
NAME=$(basename "$REAL")
DEST="${REMOTE}:${BUCKET}/${PREFIX}/${NAME}"
STATE=/var/backups/backup-state.json
LHASH=$(sha256sum "$REAL" | awk '{print $1}')
SIZE_B=$(stat -c %s "$REAL")

rclone copyto --s3-no-check-bucket --config "$CONF" "$REAL" "$DEST" \
    || fail "خطای rclone در آپلود $NAME"
echo "$LHASH" | rclone rcat --s3-no-check-bucket --config "$CONF" \
    "$DEST.sha256" 2>/dev/null || true

# --- راستی‌آزماییِ سختِ sha256: استریمِ برگشتی از MEGA و تطبیق با محلی.
#     فقط اگر عیناً برابر بود، نسخه‌های محلی پاک می‌شوند (سیاست: بدونِ
#     فایلِ بکاپ روی سرور).
RHASH=$(rclone cat --config "$CONF" "$DEST" | sha256sum | awk '{print $1}' || true)
if [ -z "$RHASH" ] || [ "$RHASH" != "$LHASH" ]; then
    fail "sha256 ریموت با محلی نمی‌خواند (local=$LHASH remote=${RHASH:-؟}) — بکاپِ محلی نگه داشته شد"
fi
echo "sha256 verified: $LHASH"

# نگهداشت: فقط KEEP فایلِ آخر در مقصد بماند
mapfile -t OLD < <(rclone lsf --config "$CONF" \
    "${REMOTE}:${BUCKET}/${PREFIX}/" 2>/dev/null \
    | grep '^wg-panel-.*\.tar\.gz$' | sort | head -n -"$KEEP")
for f in "${OLD[@]:-}"; do
    [ -n "$f" ] && rclone deletefile --config "$CONF" \
        "${REMOTE}:${BUCKET}/${PREFIX}/${f}" || true
    [ -n "$f" ] && rclone deletefile --config "$CONF" \
        "${REMOTE}:${BUCKET}/${PREFIX}/${f}.sha256" 2>/dev/null || true
done

# --- ثبتِ وضعیت برای پنل/دایجست، سپس پاک‌سازیِ نسخه‌های محلی
python3 - "$STATE" "$NAME" "$LHASH" "$SIZE_B" "$DEST" <<'PY' || fail "ثبتِ state ناموفق — بکاپِ محلی نگه داشته شد"
import json, os, sys, time
p, name, sha, size, target = sys.argv[1:6]
try:
    st = json.load(open(p))
except Exception:
    st = {}
st["panel"] = {"object": name, "sha256": sha, "size": int(size),
               "target": target, "uploaded": time.time(), "verified": True}
tmp = p + ".tmp"
json.dump(st, open(tmp, "w"), ensure_ascii=False, indent=1)
os.chmod(tmp, 0o600); os.replace(tmp, p)
PY
rm -f /var/backups/wg-panel/wg-panel-*.tar.gz \
      /var/backups/wg-panel/latest.tar.gz
echo "uploaded+verified $NAME -> $DEST — نسخه‌های محلی پاک شدند"
