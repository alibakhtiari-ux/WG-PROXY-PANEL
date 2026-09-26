#!/bin/bash
# آماده‌سازیِ میزبانِ اوبونتو برای اجرای wg-panel با Docker Compose.
# idempotent است؛ چند بار اجراشدنش بی‌ضرر است.  اجرا:  sudo bash host-setup.sh
set -Eeuo pipefail

say() { echo "[host-setup] $*"; }

[ "$(id -u)" = "0" ] || { echo "This script needs root:  sudo bash host-setup.sh · این اسکریپت root می‌خواهد" >&2; exit 1; }

# ---------- سازگاریِ توزیع ----------
if [ -r /etc/os-release ]; then
    . /etc/os-release
    if [ "${ID:-}" != "ubuntu" ]; then
        say "⚠️ Only tested on Ubuntu 22.04/24.04 — this host: ${PRETTY_NAME:-unknown}"
    fi
fi

# ---------- Docker + Compose v2 ----------
if ! command -v docker >/dev/null 2>&1; then
    say "Installing docker.io and docker-compose-v2 from the Ubuntu repository…"
    apt-get update
    apt-get install -y docker.io docker-compose-v2
elif ! docker compose version >/dev/null 2>&1; then
    say "docker is present but the compose plugin is not — installing docker-compose-v2…"
    apt-get update
    apt-get install -y docker-compose-v2
else
    say "docker and compose are already installed."
fi
systemctl enable --now docker >/dev/null 2>&1 || true

# ---------- ماژولِ wireguard روی میزبان ----------
# کانتینر خودش ماژول لود نمی‌کند (و نباید بکند — SYS_MODULE نمی‌دهیم)؛
# پس اینجا لود و برای بوت‌های بعدی ماندگار می‌شود.
if [ ! -e /sys/module/wireguard ]; then
    modprobe wireguard 2>/dev/null || true
fi
if [ -e /sys/module/wireguard ] || grep -qw wireguard /proc/modules 2>/dev/null; then
    say "The wireguard module is available."
    echo wireguard > /etc/modules-load.d/wireguard.conf
else
    say "❌ The wireguard module would not load — does this host's kernel have WireGuard? · کرنلِ این میزبان وایرگارد ندارد؟"
    say "   (Ubuntu 22.04+ has it in-kernel; check custom kernels.)"
    exit 1
fi
# ifb: شکل‌دهیِ آپلودِ محدودیتِ سرعت. کانتینر نمی‌تواند لودش کند، و بدونِ آن
# محدودیتِ آپلود اعمال نمی‌شود. اختیاری است: نبودنش مانعِ نصب نیست.
modprobe ifb 2>/dev/null || true
if [ -e /sys/module/ifb ]; then
    echo ifb > /etc/modules-load.d/ifb.conf
else
    say "⚠️ The ifb module would not load — per-client upload limits will not apply. · ماژولِ ifb لود نشد؛ محدودیتِ آپلود اعمال نمی‌شود."
fi

# ---------- پیش‌بررسیِ پورت‌ها ----------
_env_get() {  # $1 = KEY، $2 = پیش‌فرض — از .env کنارِ همین اسکریپت
    local f; f="$(dirname "$0")/.env"
    local v=""
    [ -r "$f" ] && v=$(grep -E "^$1=" "$f" | tail -1 | cut -d= -f2- | tr -d ' ')
    echo "${v:-$2}"
}
WG_PORT=$(_env_get WG_PORT 51820)
PANEL_PORT=$(_env_get WG_PANEL_PORT 8787)

_port_busy() { ss -H -lntu "sport = :$1" 2>/dev/null | grep -q .; }
for p in "$WG_PORT" "$PANEL_PORT" 18080; do
    if _port_busy "$p"; then
        say "⚠️ Port $p is already in use on the host — resolve that before 'compose up'. · پیش از compose up تکلیفش را روشن کنید."
    fi
done

# ---------- یادآوریِ صادقانه‌ی فایروال ----------
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    say "⚠️ ufw is enabled, but docker-published ports bypass ufw and will be reachable. · پورت‌های publishشده‌ی docker از ufw عبور نمی‌کنند."
    say "   Restrict the panel with WG_PANEL_ALLOW_IPS in .env (the panel's own filter),"
    say "   or bind the panel port to 127.0.0.1 in docker-compose.yml."
fi

say "✅ Host is ready. Next:"
say "   cd \"$(cd "$(dirname "$0")" && pwd)\""
say "   (umask 077 && cp .env.example .env) && chmod 600 .env"
say "        ↑ .env holds the bot token — it is created with mode 600"
say "   Then set at least WG_SERVER_HOST in .env"
say "   docker compose up -d --build"
