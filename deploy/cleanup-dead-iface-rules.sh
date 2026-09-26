#!/bin/bash
# حذفِ جراحیِ قواعدِ iptables که به اینترفیس‌های ناموجود ارجاع می‌دهند.
# ۳۰ ژوئیه ۲۰۲۶ — §۳۱ ردیفِ ۱۳ سند.
#
# چرا iptables-restore نیست: جایگزینیِ یک‌جای جدول یعنی اگر فایل اشتباه باشد
# کلِ فایروال می‌رود. حذفِ تک‌تک هر گامش قابلِ بازگشت است و نمی‌تواند چیزی
# را که هدف نگرفته‌ایم از بین ببرد.
#
# ورودی: /root/iptables-backup-<TS>.v4  (اسنپ‌شاتِ پیش از پاکسازی)
# تست:   DRY_RUN=1 bash cleanup-dead-iface-rules.sh
set -u

DEAD="fallback wg0 wg1 wg2 wg3 wg4 wg5 wg6 wg7 wg8 wg16 wg17 wg18 wg19 tun0 tun1 tun2 tun3 tun4 tun5 tun6 IPIP01"
PAT=$(echo $DEAD | tr ' ' '|')
DRY=${DRY_RUN:-0}
SRC=${SRC:-/root/iptables-backup-$(cat /root/.cleanup-ts).v4}

# گاردِ ایمنی: اگر حتی یکی از فهرست زنده باشد، هیچ کاری نکن.
alive=""
for i in $DEAD; do
    ip link show "$i" >/dev/null 2>&1 && alive="$alive $i"
done
if [ -n "$alive" ]; then
    echo "ABORT: این اینترفیس‌ها زنده‌اند و در فهرستِ حذف بودند:$alive"
    exit 1
fi

[ -r "$SRC" ] || { echo "ABORT: فایلِ مرجع خوانده نشد: $SRC"; exit 1; }

ok=0; fail=0; table=""
while IFS= read -r line; do
    case "$line" in
        '*'*)  table="${line#\*}"; continue ;;
        -A*)   ;;
        *)     continue ;;
    esac
    printf '%s\n' "$line" | grep -qE -- "-[io] ($PAT)( |$)" || continue
    spec="${line#-A }"
    if [ "$DRY" = "1" ]; then
        printf 'DRY: iptables -t %s -D %s\n' "$table" "$spec"
        ok=$((ok+1))
    elif iptables -t "$table" -D $spec 2>/dev/null; then
        ok=$((ok+1))
    else
        printf 'FAILED: -t %s -D %s\n' "$table" "$spec"
        fail=$((fail+1))
    fi
done < "$SRC"

printf 'پردازش‌شده: %s   ناموفق: %s\n' "$ok" "$fail"
[ "$fail" -eq 0 ]
