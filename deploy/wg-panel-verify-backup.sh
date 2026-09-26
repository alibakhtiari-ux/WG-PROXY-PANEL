#!/bin/bash
# صحت‌سنجیِ دوره‌ایِ بکاپ‌ها — نسخه‌ی MEGA-محور (سیاست: بکاپی روی سرور نمی‌ماند).
# برای بکاپِ پنل — و بکاپِ کاملِ سرور، اگر آن زنجیره به‌کار است — از خودِ MEGA S4:
#   تازگی (state + فهرستِ ریموت) + تطبیقِ sha256 استریمِ ریموت با sidecar
#   + سالم‌بودنِ آرشیو (tar از استریم) + وجودِ فایل‌های کلیدی
#   + یکپارچگیِ دیتابیسِ پنل (PRAGMA integrity_check روی نسخه‌ی داخلِ بکاپ).
# اگر مشکلی بود از مسیرِ خودِ پنل (تونل→تلگرام) هشدار می‌دهد. اجرا با root.
set -uo pipefail

MAX_AGE=$((36 * 3600))
ENV_FILE=/etc/wg-panel-s4.env
CONF=/etc/wg-panel-rclone.conf
[ -r "$CONF" ] || CONF=/root/.config/rclone/rclone.conf
STATE=/var/backups/backup-state.json
problems=""
add() { problems="$problems"$'\n'"$1"; }

if [ ! -r "$ENV_FILE" ]; then
    add "پرونده‌ی $ENV_FILE نیست — دسترسی به MEGA ممکن نیست"
else
    # shellcheck disable=SC1090
    . "$ENV_FILE"
fi
PREFIX="${PREFIX:-wg-panel}"

# زنجیره‌ی «بکاپِ کاملِ سرور» (host-backup-*.tar.gz) اسکریپتِ جدایی دارد که در
# این مخزن نیست. پیش‌تر همیشه سنجیده می‌شد، پس روی هر نصبی جز استقرارِ
# نگه‌دارنده این یونیت هر هفته «هیچ بکاپی روی MEGA نیست» می‌داد و failed
# می‌ماند. حالا فقط وقتی سنجیده می‌شود که به‌کار باشد: FULL_PREFIX صریحاً در
# $ENV_FILE آمده، یا state نشان می‌دهد این زنجیره دست‌کم یک بار آپلود کرده است.
# (همین دومی استقرارِ موجود را بی‌تغییر نگه می‌دارد، و زنجیره‌ای که زمانی
# کار می‌کرده و بعد خاموش شده همچنان گزارش می‌شود.)
full_in_use() {
    [ -n "${FULL_PREFIX:-}" ] && return 0
    python3 - "$STATE" <<'PY' 2>/dev/null
import json, sys
try:
    sys.exit(0 if "full" in json.load(open(sys.argv[1])) else 1)
except Exception:
    sys.exit(1)
PY
}
CHECK_FULL=0
full_in_use && CHECK_FULL=1
FULL_PREFIX="${FULL_PREFIX:-host-full}"

# $1=prefix  $2=name-pattern → جدیدترین آبجکت روی stdout
# کدِ خروج: 0 = فهرست‌گیری موفق بود (خروجیِ خالی یعنی واقعاً بکاپی نیست)
#           2 = فهرست‌گیری شکست خورد ⇒ وضعیت نامعلوم است، نه «غایب»
# چرا: پیش از این خطای rclone با 2>/dev/null بلعیده می‌شد و خروجیِ خالی
# برمی‌گشت، پس یک خطای گذرای MEGA عیناً مثلِ گم‌شدنِ بکاپ گزارش می‌شد.
# در ۲۶ ژوئیه ۲۰۲۶ همین اتفاق افتاد: هر دو زنجیره هم‌زمان «غایب» شدند
# (امضای شکستِ فهرست‌گیری) و یونیت چهار روز در حالتِ failed قفل ماند.
latest_obj() {
    local out rc i
    for i in 1 2 3; do
        out=$(rclone lsf --config "$CONF" "${REMOTE}:${BUCKET}/$1/" 2>/dev/null)
        rc=$?
        if [ "$rc" = "0" ]; then
            printf '%s\n' "$out" | grep -E "$2" | sort | tail -1
            return 0
        fi
        [ "$i" -lt 3 ] && sleep $((i * 5))
    done
    return 2
}

check_remote() {   # $1=label  $2=prefix  $3=pattern  $4=member  $5=state-key
    local label=$1 prefix=$2 pattern=$3 member=$4 key=$5
    local obj base rc
    obj=$(latest_obj "$prefix" "$pattern"); rc=$?
    if [ "$rc" != "0" ]; then
        add "$label: فهرست‌گیریِ MEGA پس از ۳ تلاش شکست خورد — وضعیتِ بکاپ نامعلوم است (نه لزوماً غایب)"
        return
    fi
    if [ -z "$obj" ]; then add "$label: هیچ بکاپی روی MEGA نیست"; return; fi
    base="${REMOTE}:${BUCKET}/${prefix}/${obj}"
    # تازگی از state (زمانِ آخرین آپلودِ تأییدشده)
    local age
    age=$(python3 - "$STATE" "$key" <<'PY' 2>/dev/null
import json, sys, time
try:
    st = json.load(open(sys.argv[1]))[sys.argv[2]]
    print(int(time.time() - float(st.get("uploaded", 0))))
except Exception:
    print(-1)
PY
)
    if [ "$age" = "-1" ]; then add "$label: state آپلود ثبت نشده"
    elif [ "$age" -gt "$MAX_AGE" ]; then
        add "$label: آخرین آپلودِ تأییدشده کهنه است ($((age/3600)) ساعت)"
    fi
    # sha256 مورد انتظار از sidecar ریموت
    local want listing tmphash
    want=$(rclone cat --config "$CONF" "$base.sha256" 2>/dev/null | awk '{print $1}')
    [ -z "$want" ] && { add "$label: sidecar sha256 روی MEGA نیست"; return; }
    # یک استریم: هم tar-listing هم sha256 (بدونِ ذخیره روی دیسک)
    tmphash=$(mktemp /tmp/vbk-hash.XXXXXX)
    if ! listing=$(rclone cat --config "$CONF" "$base" \
            | tee >(sha256sum | awk '{print $1}' > "$tmphash") \
            | tar -tz 2>/dev/null); then
        add "$label: آرشیوِ ریموت خراب/ناخوانا ($obj)"; rm -f "$tmphash"; return
    fi
    local got; got=$(cat "$tmphash"); rm -f "$tmphash"
    [ "$got" = "$want" ] \
        || add "$label: sha256 ریموت با sidecar نمی‌خواند ($obj)"
    grep -qF "$member" <<<"$listing" \
        || add "$label: فایلِ کلیدی در آرشیو نیست ($member)"
    echo "$label: $obj سالم (sha256=$got، اعضای آرشیو=$(wc -l <<<"$listing"))"
}

[ -n "${REMOTE:-}" ] && {
    check_remote "پنل"  "$PREFIX"      '^wg-panel-.*\.tar\.gz$'    "wg-panel/config.json" "panel"
    [ "$CHECK_FULL" = 1 ] \
        && check_remote "سرور" "$FULL_PREFIX" '^host-backup-.*\.tar\.gz$' "etc/letsencrypt" "full"
}

# یکپارچگیِ عمیقِ دیتابیسِ پنل از نسخه‌ی داخلِ بکاپِ ریموت
if [ -n "${REMOTE:-}" ]; then
    obj=$(latest_obj "$PREFIX" '^wg-panel-.*\.tar\.gz$')
    if [ -n "$obj" ]; then
        tmp=$(mktemp -d /tmp/vbk.XXXXXX); trap 'rm -rf "$tmp"' EXIT
        if rclone cat --config "$CONF" "${REMOTE}:${BUCKET}/${PREFIX}/${obj}" \
                | tar -xz -C "$tmp" --wildcards '*traffic.db' 2>/dev/null \
                && dbf=$(find "$tmp" -name traffic.db | head -1) && [ -n "$dbf" ]; then
            res=$(python3 - "$dbf" <<'PY'
import sqlite3, sys
try:
    c = sqlite3.connect(sys.argv[1])
    print(c.execute("PRAGMA integrity_check").fetchone()[0]); c.close()
except Exception as e:
    print("ERR:%s" % e)
PY
)
            [ "$res" = "ok" ] || add "دیتابیسِ پنل (در بکاپِ MEGA): integrity=$res"
        else
            add "دیتابیسِ پنل در بکاپِ MEGA نبود"
        fi
    fi
fi

# سیاست: هیچ تاربالِ بکاپی نباید روی سرور مانده باشد
left=$(ls /var/backups/wg-panel/*.tar.gz /var/backups/host-full/*.tar.gz 2>/dev/null | head -3)
[ -n "$left" ] && add "فایلِ بکاپِ محلی هنوز روی سرور است: $left"

if [ -n "$problems" ]; then
    msg="صحت‌سنجیِ بکاپ (MEGA) مشکل دارد:$problems"
    echo -e "$msg" >&2
    python3 - "$msg" 2>/dev/null <<'PY' || true
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
    exit 1
fi
if [ "$CHECK_FULL" = 1 ]; then
    echo "backup verify OK (پنل + سرور روی MEGA سالم/تازه، sha256 تطبیق، سرور بدونِ نسخه‌ی محلی)"
else
    echo "backup verify OK (پنل روی MEGA سالم/تازه، sha256 تطبیق، سرور بدونِ نسخه‌ی محلی؛ بکاپِ کاملِ سرور به‌کار نیست)"
fi
