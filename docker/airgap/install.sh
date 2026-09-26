#!/usr/bin/env bash
# install.sh — نصبِ آفلاینِ wg-panel (نسخه‌ی Docker) روی اوبونتوی بدونِ اینترنت.
# داخلِ پوشه‌ی همین بسته اجرا می‌شود:  sudo bash install.sh [--server-host X] [--up]
#
#   --server-host X   نوشتنِ WG_SERVER_HOST در .env (IP/دامنه‌ی عمومیِ سرور)
#   --up              بعد از آماده‌سازی، «docker compose up -d» هم بزن
#
# idempotent است؛ اجرای دوباره بی‌ضرر است و داده‌ی data/ را دست نمی‌زند.
set -Eeuo pipefail

say() { printf '\033[34m[install]\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m[  ok  ]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[ fail ]\033[0m %s\n' "$*" >&2; exit 1; }

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SELF_DIR}"

SERVER_HOST=""
DO_UP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --server-host) SERVER_HOST="${2:?}"; shift 2 ;;
        --up)          DO_UP=1; shift ;;
        *) die "آرگومانِ ناشناخته: $1" ;;
    esac
done

[ "$(id -u)" = "0" ] || die "root لازم است:  sudo bash install.sh"
case "${SELF_DIR}" in
    *" "*) die "مسیرِ بسته فاصله دارد («${SELF_DIR}») — apt با file: آن را نمی‌خواند؛ بسته را به مسیری بدونِ فاصله ببرید (مثلاً /opt/wg-panel-offline)." ;;
esac

# ---------- ۰) یکپارچگیِ بسته — پیش از هر استفاده‌ای ----------
say "بررسیِ یکپارچگیِ بسته (checksums)…"
bash "${SELF_DIR}/verify-checksums.sh" || die "بسته ناقص/دستکاری‌شده است."
ok "یکپارچگی تأیید شد"

# ---------- ۱) سازگاریِ معماری ----------
BUNDLE_ARCH="$(cat "${SELF_DIR}/ARCH")"
HOST_ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)"
[ "${BUNDLE_ARCH}" = "${HOST_ARCH}" ] \
    || die "بسته برای ${BUNDLE_ARCH} است ولی این میزبان ${HOST_ARCH} — بسته را با «--arch ${HOST_ARCH}» دوباره بسازید."
VER="$(cat "${SELF_DIR}/VERSION")"
ok "معماری سازگار (${HOST_ARCH}) · نسخه‌ی پنل: ${VER}"

# ---------- ۲) docker + compose (از مخزنِ آفلاینِ داخلِ بسته) ----------
_need_docker=0;  command -v docker >/dev/null 2>&1 || _need_docker=1
_need_compose=0; docker compose version >/dev/null 2>&1 || _need_compose=1
if [ "${_need_docker}" = 1 ] || [ "${_need_compose}" = 1 ]; then
    [ -d "${SELF_DIR}/apt" ] \
        || die "docker/compose روی میزبان نیست و بسته هم بدونِ debs ساخته شده (--no-debs) — بسته‌ی کامل لازم است."
    say "نصبِ آفلاینِ docker از مخزنِ داخلِ بسته…"
    _list=/etc/apt/sources.list.d/wg-panel-docker-offline.list
    echo "deb [trusted=yes] file:${SELF_DIR}/apt ./" > "${_list}"
    # فقط همین منبع دیده شود — میزبانِ آفلاین به منابعِ اینترنتی دسترسی ندارد
    _apt_off=(-o "Dir::Etc::sourcelist=${_list}" -o "Dir::Etc::sourceparts=/dev/null")
    trap 'rm -f "${_list}"; apt-get update -qq >/dev/null 2>&1 || true' EXIT
    apt-get "${_apt_off[@]}" update -qq \
        || die "خواندنِ مخزنِ آفلاین شکست خورد."
    DEBIAN_FRONTEND=noninteractive apt-get "${_apt_off[@]}" install -y \
        --no-install-recommends docker.io docker-compose-v2 \
        || die "نصبِ docker.io/docker-compose-v2 از بسته شکست خورد."
    ok "docker و compose نصب شدند"
else
    ok "docker و compose از قبل روی میزبان هستند"
fi
systemctl enable --now docker >/dev/null 2>&1 || true
docker info >/dev/null 2>&1 || die "دیمنِ docker بالا نیامد — journalctl -u docker"

# ---------- ۳) ماژولِ wireguard روی میزبان ----------
if [ ! -e /sys/module/wireguard ]; then
    modprobe wireguard 2>/dev/null || true
fi
if [ -e /sys/module/wireguard ] || grep -qw wireguard /proc/modules 2>/dev/null; then
    echo wireguard > /etc/modules-load.d/wireguard.conf
    ok "ماژولِ wireguard در دسترس و ماندگار شد"
else
    die "ماژولِ wireguard لود نشد — کرنلِ این میزبان وایرگارد ندارد؟ (اوبونتوی ۲۲.۰۴+ آن را دارد)"
fi
# ifb: شکل‌دهیِ آپلودِ محدودیتِ سرعت؛ کانتینر نمی‌تواند لودش کند. اختیاری.
modprobe ifb 2>/dev/null || true
if [ -e /sys/module/ifb ]; then
    echo ifb > /etc/modules-load.d/ifb.conf
    ok "ماژولِ ifb (محدودیتِ آپلود) در دسترس و ماندگار شد"
else
    say "⚠️ ماژولِ ifb لود نشد — محدودیتِ سرعتِ آپلودِ کاربران اعمال نمی‌شود"
fi

# ---------- ۴) بارگذاریِ ایمیج ----------
_img_tar="$(ls "${SELF_DIR}"/wg-panel-image-*.tar.gz 2>/dev/null | head -1)"
[ -n "${_img_tar}" ] || die "فایلِ ایمیج (wg-panel-image-*.tar.gz) در بسته نیست."
if docker image inspect "wg-panel:${VER}" >/dev/null 2>&1; then
    ok "ایمیجِ wg-panel:${VER} از قبل load شده"
else
    say "docker load (چند دقیقه)…"
    docker load -i "${_img_tar}" >/dev/null || die "docker load شکست خورد."
    docker image inspect "wg-panel:${VER}" >/dev/null 2>&1 \
        || die "بعد از load، ایمیجِ wg-panel:${VER} دیده نمی‌شود."
    ok "ایمیج load شد: wg-panel:${VER}"
fi

# ---------- ۵) پیکربندی ----------
install -d -m 700 "${SELF_DIR}/data"
# .env توکنِ ربات و بقیه‌ی رازهای استقرار را می‌گیرد — همان رباتی که پیر
# می‌سازد و ورودِ پنل را تأیید می‌کند. `cp` ِ ساده مود را از umask می‌گرفت
# (معمولاً ۰۶۴۴) و روی هاستی با کاربرِ دوم خواندنی می‌ماند. همان دقتی که
# entrypoint.sh برای کلیدِ TLS دارد (chmod 600 و umask 077).
#
# زیرپوسته: تغییرِ umask به بقیه‌ی اسکریپت نشت نکند.
if [ ! -f "${SELF_DIR}/.env" ]; then
    (umask 077 && cp "${SELF_DIR}/.env.example" "${SELF_DIR}/.env")
    ok ".env از .env.example ساخته شد"
fi
# 🪤 نیمه‌ای که استقرارهای **موجود** را نجات می‌دهد: گاردِ `[ ! -f ]` یعنی
# مسیرِ بالا برای کسی که با نصابِ قدیمی .env ساخته اصلاً اجرا نمی‌شود.
[ -f "${SELF_DIR}/.env" ] && chmod 600 "${SELF_DIR}/.env"
if [ -n "${SERVER_HOST}" ]; then
    # 🪤 `sed -i` فایلِ موقت می‌سازد و rename می‌کند، پس فایلِ تازه مودِ
    # umask می‌گیرد و گامِ بالا را بی‌صدا برمی‌گرداند. ضمناً `.env.bak` ِ
    # میانی خودش یک کپیِ کاملِ رازهاست. کلِ بخش زیرِ umask 077.
    (
        umask 077
        if grep -q '^WG_SERVER_HOST=' "${SELF_DIR}/.env"; then
            sed -i.bak "s|^WG_SERVER_HOST=.*|WG_SERVER_HOST=${SERVER_HOST}|" "${SELF_DIR}/.env" \
                && rm -f "${SELF_DIR}/.env.bak"
        else
            printf 'WG_SERVER_HOST=%s\n' "${SERVER_HOST}" >> "${SELF_DIR}/.env"
        fi
    )
    chmod 600 "${SELF_DIR}/.env"
    ok "WG_SERVER_HOST=${SERVER_HOST} در .env نشست"
fi

# هشدارِ پورت‌های اشغال (فقط اطلاع؛ نصب را نمی‌شکند)
for p in $(grep -E '^(WG_PORT|WG_PANEL_PORT)=' "${SELF_DIR}/.env" | cut -d= -f2 | tr -d ' ') 18080; do
    if ss -H -lntu "sport = :${p}" 2>/dev/null | grep -q .; then
        say "⚠️ پورت ${p} روی میزبان اشغال است — پیش از up تکلیفش را روشن کنید."
    fi
done

# ---------- ۶) بالاآوردن (اختیاری) ----------
if [ "${DO_UP}" = 1 ]; then
    [ -n "${SERVER_HOST}" ] || grep -qE '^WG_SERVER_HOST=..' "${SELF_DIR}/.env" \
        || say "⚠️ WG_SERVER_HOST خالی است — Endpoint کانفیگِ کلاینت‌ها درست نخواهد بود."
    say "docker compose up -d …"
    docker compose up -d || die "compose up شکست خورد — docker compose logs"
    sleep 6
    docker compose ps
    ok "پنل باید روی https://<سرور>:$(grep -E '^WG_PANEL_PORT=' .env | cut -d= -f2 | tr -d ' ' || echo 8787) بالا باشد — اولین رمزِ واردشده ثبت می‌شود."
else
    echo
    ok "آماده است. گام‌های بعدی:"
    echo "      ویرایشِ ${SELF_DIR}/.env  (دست‌کم WG_SERVER_HOST)"
    echo "      cd ${SELF_DIR} && docker compose up -d"
fi
say "یادآوری: ufw پورت‌های publish شده‌ی docker را فیلتر نمی‌کند — محدودسازیِ پنل با WG_PANEL_ALLOW_IPS در .env."