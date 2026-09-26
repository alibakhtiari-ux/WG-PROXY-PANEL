#!/bin/bash
# نصبِ وابستگی‌های سیستمیِ wg-panel روی اوبونتو ۲۴.۰۴.
# چون مخزنِ اوبونتوی این سرور عمداً خاموش است، موقتاً یک منبعِ noble
# روشن می‌کنیم، نصب می‌کنیم، و دوباره خاموشش می‌کنیم (هرگز apt upgrade).
#
#   qrencode  → QR کانفیگِ وایرگارد/پروکسی در ربات (اگر نباشد، .conf می‌رود)
#   fail2ban  → بنِ فایروالیِ ورودهای ناموفقِ پنل (نسخه‌ی noble-updates لازم است
#               چون 1.0.2 پایه با پایتون ۳.۱۲ ناسازگار است — asynchat)
#   rclone    → آپلودِ بکاپ به MEGA S4 (باینریِ استاتیک، نه apt)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "با sudo/root اجرا کن"; exit 1; }

SRC=/etc/apt/sources.list.d/_tmp_deps.sources
RCTMP=""            # پوشه‌ی موقتِ rclone؛ همان trap ِ موجود پاکش می‌کند
cleanup() {
    rm -f "$SRC"
    if [ -n "${RCTMP:-}" ]; then rm -rf "${RCTMP}"; fi
    apt-get update -qq 2>/dev/null || true
}
trap cleanup EXIT

cat > "$SRC" <<EOF
Types: deb
URIs: http://ir.archive.ubuntu.com/ubuntu
Suites: noble noble-updates noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
apt-get update -qq 2>/dev/null

command -v qrencode >/dev/null || apt-get install -y -qq qrencode
command -v fail2ban-client >/dev/null || apt-get install -y -qq fail2ban
# اگر fail2ban نصب بود ولی نسخه‌ی قدیمی، ارتقا به noble-updates
apt-get install -y -qq --only-upgrade fail2ban 2>/dev/null || true

# rclone عمداً از apt نمی‌آید (باینریِ استاتیک) — پس زنجیره‌ی اعتمادِ apt
# را ندارد و باید صریحاً بسته شود. نسخه پین است، نه «هرچه تازه‌تر»: با
# نسخه‌ی شناور، دو نصب از یک کامیت دو باینریِ متفاوت می‌دهند و هیچ‌جا
# ثبت نمی‌شود کدام. برای ارتقا، هر دو ثابتِ زیر با هم عوض می‌شوند.
#
# منبعِ هش: https://downloads.rclone.org/v1.75.0/SHA256SUMS (۱۳ اوت ۲۰۲۶).
# آن فایل clearsigned ِ PGP است ولی امضایش تأیید نشد (gpg در دسترس نبود)،
# پس این هش «اصالتِ انتشار» را ثابت نمی‌کند — فقط آرتیفکت را در همان
# لحظه پین می‌کند تا جایگزینیِ بعدی گرفته شود.
RCLONE_VER="v1.75.0"
RCLONE_SHA256="aa2804e08f48250e71009c727124b6341cd0288465804a9a09d14663cabafbaa"

if ! command -v rclone >/dev/null; then
    _zip="rclone-${RCLONE_VER}-linux-amd64.zip"
    # mktemp -d و نه cd /tmp با نامِ ثابت: پوشه‌ی از پیش کاشته‌شده یا اجرای
    # موازی نباید بتواند تعیین کند چه چیزی نصب می‌شود.
    RCTMP="$(mktemp -d /tmp/rclone-install.XXXXXX)"
    curl -fsSL -o "${RCTMP}/${_zip}" \
        "https://downloads.rclone.org/${RCLONE_VER}/${_zip}"
    # fail-closed: عدمِ تطابق ⇒ خروج، نه هشدار. این باینری همان چیزی است
    # که /etc/wg-panel-rclone.conf و بکاپِ کاملِ سرور را دست می‌گیرد.
    echo "${RCLONE_SHA256}  ${RCTMP}/${_zip}" | sha256sum -c --strict - \
        || { echo "عدمِ تطابقِ SHA-256 برای ${_zip} — نصبِ rclone متوقف شد" >&2; exit 1; }
    unzip -oq "${RCTMP}/${_zip}" -d "${RCTMP}"
    install -m 755 "${RCTMP}/rclone-${RCLONE_VER}-linux-amd64/rclone" /usr/local/bin/rclone
    rm -rf "${RCTMP}"; RCTMP=""
fi

echo "== نصب‌شده:"
for c in qrencode fail2ban-client rclone; do
    printf "%-16s %s\n" "$c" "$(command -v $c || echo 'نصب نشد')"
done
