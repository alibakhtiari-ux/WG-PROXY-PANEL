#!/bin/bash
# شیمِ systemctl برای کانتینر (systemd نداریم). فقط همان کارهایی را پوشش
# می‌دهد که wg_panel.py واقعاً صدا می‌زند؛ تستِ tests/test_docker_bundle.py
# تعدادِ call-siteهای systemctl در پنل را قفل کرده تا هر مصرفِ تازه، آگاهانه
# به این شیم اضافه شود (قاعده‌ی گاردِ خانوادگی).
#
# قراردادِ خروجی مطابقِ systemctl واقعی:
#   is-active  → چاپِ active/inactive + کدِ خروجِ 0/3
#   is-enabled → چاپِ enabled/disabled + کدِ خروجِ 0/1
#   start/stop روی وضعیتِ از قبل درست، موفق برمی‌گردد (no-op مثل systemd)
set -u

LOGDIR=/var/log/wg-panel/units
# stateِ یونیت‌ها روی **والیوم** می‌نشیند نه در /var/log (که والیوم نیست):
# «آخرین بکاپ» باید از بازآفرینیِ کانتینر جان سالم ببرد، وگرنه هر
# `compose down && up` صفحه‌ی بکاپ را به «هرگز اجرا نشده» برمی‌گرداند.
STATEDIR=/opt/wg-panel/units
mkdir -p "$LOGDIR" "$STATEDIR"
echo "$(date '+%F %T') systemctl $*" >> /var/log/wg-panel/systemctl-shim.log 2>/dev/null || true

verb="${1:-}"; shift || true

# جداکردنِ نامِ یونیت از فلگ‌ها، و گرفتنِ فهرستِ propertyهای «show -p».
# پنل آن را کاما-جداشده می‌فرستد: systemctl show X -p A,B,C
unit=""
props=""
_want_p=0
for a in "$@"; do
    if [ "$_want_p" = "1" ]; then props="$a"; _want_p=0; continue; fi
    case "$a" in
        -p|--property) _want_p=1 ;;
        --property=*)  props="${a#--property=}" ;;
        -p*)           props="${a#-p}" ;;
        -*)            ;;
        *)             [ -n "$unit" ] || unit="$a" ;;
    esac
done
unit="${unit%.service}"

# ---- کمکی‌ها --------------------------------------------------------------
_iface_of() { echo "${1#*@}"; }

_tunnel_active() {  # $1 = wg-quick@X | awg-quick@X
    local ifc; ifc=$(_iface_of "$1")
    case "$1" in
        awg-quick@*) command -v awg >/dev/null 2>&1 && awg show "$ifc" >/dev/null 2>&1 ;;
        *)           wg show "$ifc" >/dev/null 2>&1 ;;
    esac
}

_squid_active() { pgrep -x squid >/dev/null 2>&1; }

_start_tunnel() {  # $1 = unit
    local ifc log rc; ifc=$(_iface_of "$1"); log="$LOGDIR/$1.log"
    if [[ "$1" == awg-quick@* ]] && ! command -v awg-quick >/dev/null 2>&1; then
        echo "باینریِ awg-quick داخلِ ایمیج نیست (AmneziaWG در نسخه‌ی Docker به‌صورتِ پیش‌فرض پشتیبانی نمی‌شود)" >&2
        return 1
    fi
    _tunnel_active "$1" && return 0
    if [[ "$1" == awg-quick@* ]]; then awg-quick up "$ifc" >>"$log" 2>&1
    else                               wg-quick  up "$ifc" >>"$log" 2>&1; fi
    rc=$?
    [ $rc -ne 0 ] && tail -n 4 "$log" >&2
    return $rc
}

_stop_tunnel() {  # $1 = unit
    local ifc log rc; ifc=$(_iface_of "$1"); log="$LOGDIR/$1.log"
    _tunnel_active "$1" || return 0
    if [[ "$1" == awg-quick@* ]]; then awg-quick down "$ifc" >>"$log" 2>&1
    else                               wg-quick  down "$ifc" >>"$log" 2>&1; fi
    rc=$?
    [ $rc -ne 0 ] && tail -n 4 "$log" >&2
    return $rc
}

_start_squid() {
    _squid_active && return 0
    squid >>"$LOGDIR/squid.log" 2>&1
}

_stop_squid() {
    _squid_active || return 0
    squid -k shutdown >>"$LOGDIR/squid.log" 2>&1 || true
    for _ in $(seq 1 20); do _squid_active || return 0; sleep 0.5; done
    pkill -x squid 2>/dev/null || true
    return 0
}

# ثبتِ نتیجه‌ی اجرا — منبعِ ستون‌های «آخرین اجرا / نتیجه» در صفحه‌ی بکاپِ پنل.
# مقدارِ Result همان واژگانِ systemd است (success / exit-code) چون پنل عیناً
# با "success" مقایسه می‌کند.
_record_state() {  # $1 = unit، $2 = کدِ خروج
    local f="$STATEDIR/$1.service.json" result=success
    [ "$2" = "0" ] || result=exit-code
    printf '{"ts": %s, "status": "%s", "result": "%s"}\n' \
           "$(date +%s)" "$2" "$result" > "$f.tmp" 2>/dev/null \
        && mv -f "$f.tmp" "$f" 2>/dev/null || true
}

# oneshot ِ بکاپ: مثل systemd روی سرویسِ oneshot، تا پایانِ اجرا بلاک می‌شود
# و کدِ خروج همان نتیجه‌ی job است (پیش‌نیازِ دکمه‌ی «پشتیبان‌گیریِ دستی» پنل).
#
# 🪤 قفل لازم است چون از وقتی زمان‌بندِ درون‌کانتینری اضافه شد، دو مسیر
# می‌توانند هم‌زمان یک یونیت را بزنند (دکمه‌ی پنل و ۰۴:۳۰). systemd خودش
# یونیت را سریالایز می‌کند؛ بی‌قفل، دو `tar` هم‌زمان روی یک مقصد آرشیوِ
# نیمه‌کاره می‌سازند. flock همان رفتار را بازتولید می‌کند.
_run_oneshot() {  # $1 = unit
    local rc
    case "$1" in
        wg-panel-backup)
            flock "$STATEDIR/$1.lock" \
                /usr/local/sbin/wg-panel-backup.sh >>"$LOGDIR/$1.log" 2>&1
            rc=$?
            _record_state "$1" "$rc"
            [ $rc -ne 0 ] && tail -n 4 "$LOGDIR/$1.log" >&2
            return $rc ;;
        wg-panel-s4-upload)
            if [ ! -r /etc/wg-panel-s4.env ] || [ ! -r /etc/wg-panel-rclone.conf ]; then
                # عمداً state ثبت **نمی‌شود**: «آپلودِ ابری ندارم» یک انتخاب
                # است نه یک خرابی، و قرمزکردنِ آن ردیف هر شب دروغ بود.
                echo "Cloud upload is not configured: mount /etc/wg-panel-s4.env and /etc/wg-panel-rclone.conf (see docker/README.md) · آپلودِ ابری پیکربندی نشده است." >&2
                return 1
            fi
            flock "$STATEDIR/$1.lock" \
                /usr/local/sbin/wg-panel-s4-upload.sh >>"$LOGDIR/$1.log" 2>&1
            rc=$?
            _record_state "$1" "$rc"
            [ $rc -ne 0 ] && tail -n 4 "$LOGDIR/$1.log" >&2
            return $rc ;;
        *)
            echo "یونیتِ «$1» در نسخه‌ی Docker وجود ندارد" >&2
            return 1 ;;
    esac
}

# ---- بدنه‌ی اصلی -----------------------------------------------------------
case "$verb" in
    is-active)
        case "$unit" in
            wg-quick@*|awg-quick@*) _tunnel_active "$unit" && { echo active; exit 0; } ;;
            squid)                  _squid_active          && { echo active; exit 0; } ;;
            wg-panel)               echo active; exit 0 ;;
        esac
        echo inactive; exit 3 ;;

    is-enabled)
        # در کانتینر مفهومِ enable نداریم؛ چیزی که الان فعال است را «enabled»
        # گزارش می‌کنیم تا وضعیتِ پنل با واقعیت بخواند.
        case "$unit" in
            wg-quick@*|awg-quick@*) _tunnel_active "$unit" && { echo enabled; exit 0; } ;;
            squid)                  _squid_active          && { echo enabled; exit 0; } ;;
            wg-panel)               echo enabled; exit 0 ;;
        esac
        echo disabled; exit 1 ;;

    start)
        case "$unit" in
            wg-quick@*|awg-quick@*)             _start_tunnel "$unit"; exit $? ;;
            squid)                              _start_squid;          exit $? ;;
            wg-panel-backup|wg-panel-s4-upload) _run_oneshot "$unit";  exit $? ;;
            *) _run_oneshot "$unit"; exit $? ;;
        esac ;;

    stop)
        case "$unit" in
            wg-quick@*|awg-quick@*) _stop_tunnel "$unit"; exit $? ;;
            squid)                  _stop_squid;          exit $? ;;
            *) echo "یونیتِ «$unit» در نسخه‌ی Docker وجود ندارد" >&2; exit 1 ;;
        esac ;;

    restart)
        case "$unit" in
            wg-quick@*|awg-quick@*) _stop_tunnel "$unit" || true; _start_tunnel "$unit"; exit $? ;;
            squid)                  _stop_squid;                  _start_squid;          exit $? ;;
            *) echo "یونیتِ «$unit» در نسخه‌ی Docker وجود ندارد" >&2; exit 1 ;;
        esac ;;

    show)
        # پنل از همین خروجی ستون‌های «آخرین اجرا / نتیجه / اجرای بعدی» صفحه‌ی
        # بکاپ را می‌سازد (_unit_props و _sysd_ts در wg_panel.py).
        #
        # 🪤 پیش از این خروجی **خالی** بود با این توجیه که «دروغی نمی‌گوییم».
        # ولی پنل غیبتِ property را «هرگز اجرا نشده» و `Result != success` را
        # «ناموفق» تفسیر می‌کند، پس یک بکاپِ موفقِ همین‌الان روی صفحه قرمز
        # دیده می‌شد. سکوت در جایی که مصرف‌کننده پیش‌فرضِ منفی دارد، خودش
        # دروغ است — با شاهدِ عینی: آرشیوِ ۸۹۲KB ساخته شد و صفحه «اجرا نشده»
        # نشان داد.
        #
        # قالب دقیقاً همان systemd: «Key=Value»، و زمان به شکلِ
        # «Sun 2026-07-19 04:56:47 +0330» که _sysd_ts پارس می‌کند.
        UNIT="$unit" PROPS="$props" STATEDIR="$STATEDIR" python3 - <<'PY'
import json
import os
import time

unit = os.environ["UNIT"]
statedir = os.environ["STATEDIR"]
want = [p for p in os.environ.get("PROPS", "").split(",") if p.strip()]


def emit(key, value):
    # بی‌ -p، مثلِ systemd همه را چاپ می‌کنیم؛ با -p فقط خواسته‌شده‌ها.
    if not want or key in want:
        print("%s=%s" % (key, value))


def load(name):
    try:
        with open(os.path.join(statedir, name), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def sysd(ts):
    return time.strftime("%a %Y-%m-%d %H:%M:%S %z", time.localtime(float(ts)))


try:
    if unit.endswith(".timer"):
        st = load(unit + ".json")
        if st and st.get("next"):
            emit("NextElapseUSecRealtime", sysd(st["next"]))
    else:
        st = load(unit + ".service.json")
        if st and st.get("ts"):
            emit("ExecMainExitTimestamp", sysd(st["ts"]))
            emit("ExecMainStatus", str(st.get("status", "0")))
            emit("Result", str(st.get("result", "success")))
except (TypeError, ValueError, OSError):
    # هر stateِ خراب = سکوت، نه traceback روی صفحه‌ی پنل.
    pass
PY
        exit 0 ;;

    daemon-reload|reset-failed)
        exit 0 ;;

    *)
        echo "systemctl-shim: دستورِ «${verb:-}» پشتیبانی نمی‌شود" >&2
        exit 1 ;;
esac
