#!/bin/bash
# پلِ هشدارِ ecmp-guard → تلگرام. ecmp-guard هنگامِ تغییرِ عضویتِ گروهِ ۹۱۰
# این را با یک آرگومانِ متنی صدا می‌زند (گاردِ -x دارد، پس نبودنش بی‌صدا
# بلعیده می‌شد — شکافی که در قطعیِ ۳۰ ژوئیه ۲۰۲۶ دیده شد).
#
# ارسال را به خودِ tunnel-guard می‌سپاریم (حالتِ TG_NOTIFY) تا خواندنِ توکن
# از config.json و انتخابِ اینترفیسِ خروج فقط یک پیاده‌سازی داشته باشد —
# نسخه‌ی موازی همیشه کهنه می‌شود.
#
# سورس: deploy/tunnel-guard-notify.sh → /usr/local/sbin/tunnel-guard-notify.sh
[ -n "${1:-}" ] || { echo "usage: $0 <message>" >&2; exit 2; }
TG_NOTIFY="$1" exec /usr/local/sbin/tunnel-guard.sh
