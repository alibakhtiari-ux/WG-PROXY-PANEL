#!/bin/bash
# entrypoint ِ کانتینرِ wg-panel — بازتولیدِ همان بوت‌استرپِ نقشِ ansible،
# این‌بار داخلِ کانتینر و idempotent: هر گام «فقط اگر نبود» می‌سازد و
# داده‌های موجود (config.json، کلیدها، دیتابیس) را هرگز بازنویسی نمی‌کند.
set -Eeuo pipefail

say()  { echo "[wg-panel-docker] $*"; }
die()  { echo "[wg-panel-docker] ❌ $*" >&2; exit 1; }

PAYLOAD=/usr/local/share/wg-panel
DATA=/opt/wg-panel

# ---------- ۱) پیش‌نیازهای هسته — زودشکن با پیامِ قابلِ اقدام ----------
if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
fi
[ -c /dev/net/tun ] || die "/dev/net/tun is not available — do not remove the 'devices' section from docker-compose.yml. · /dev/net/tun در دسترس نیست — بخشِ devices در docker-compose.yml را حذف نکنید."

# ماژولِ wireguard باید روی «میزبان» لود باشد؛ داخلِ کانتینر فقط آزمایشش می‌کنیم.
if ! ip link add wg-selftest type wireguard 2>/tmp/wg-selftest.err; then
    say "❌ Creating a test wireguard interface failed · ساختِ اینترفیسِ آزمایشیِ wireguard شکست خورد:"
    sed 's/^/    /' /tmp/wg-selftest.err >&2 || true
    say "Run on the HOST:  sudo modprobe wireguard   (host-setup.sh makes it persistent) · روی میزبان اجرا کنید؛ host-setup.sh همین را ماندگار می‌کند."
    say "Also check that cap_add: NET_ADMIN is still in docker-compose.yml. · و مطمئن شوید cap_add: NET_ADMIN در docker-compose.yml حذف نشده است."
    exit 1
fi
ip link del wg-selftest

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
fi
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ] \
    || die "net.ipv4.ip_forward could not be enabled — do not remove the 'sysctls' section from docker-compose.yml. · net.ipv4.ip_forward فعال نشد."

# ---------- ۲) تازه‌کردنِ بارِ پنل داخلِ والیوم ----------
# کد از ایمیج می‌آید و داده از والیوم؛ ارتقا = بیلدِ دوباره‌ی ایمیج.
install -d -m 750 "$DATA"
install -m 640 "$PAYLOAD/wg_panel.py" "$DATA/wg_panel.py"
install -m 644 "$PAYLOAD/VERSION"     "$DATA/VERSION"
install -m 644 "$PAYLOAD/qr.js"       "$DATA/qr.js"
for f in three.module.min.js.gz three.core.min.js.gz three.LICENSE.txt; do
    install -m 644 "$PAYLOAD/$f" "$DATA/$f"
done
install -d -m 700 "$DATA/clients"
[ -f "$DATA/actions.log" ] || : > "$DATA/actions.log"
chmod 640 "$DATA/actions.log"
install -d -m 700 /etc/wireguard /etc/wireguard/backups
install -d -m 755 /var/log/wg-panel/units
# stateِ یونیت‌ها روی والیوم است تا «آخرین بکاپ» از بازآفرینیِ کانتینر رد شود
install -d -m 750 "$DATA/units"

# ---------- ۳) نشانیِ عمومیِ سرور (فقط برای نخستین بوت‌استرپ لازم است) ----------
SERVER_HOST="${WG_SERVER_HOST:-}"
if [ ! -f "$DATA/config.json" ] && [ -z "$SERVER_HOST" ]; then
    say "WG_SERVER_HOST is empty; trying to discover the public IPv4…"
    SERVER_HOST=$(curl -4fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)
    if [ -n "$SERVER_HOST" ]; then
        say "Public IP: $SERVER_HOST — if that is wrong, set WG_SERVER_HOST in .env and fix config.json. · اگر درست نیست، WG_SERVER_HOST را در .env بگذارید و config.json را اصلاح کنید."
    else
        SERVER_HOST="SET-ME.example.com"
        say "⚠️ Auto-discovery failed too — client Endpoints will be wrong until you fix server_host/server_endpoint in config.json. · تا اصلاحِ server_host/server_endpoint در config.json، Endpointِ کانفیگ‌ها نادرست است."
    fi
fi

# ---------- ۴) config.json (معادلِ config.json.j2 نقش؛ force:false) ----------
if [ ! -f "$DATA/config.json" ]; then
    say "Creating the initial config.json…"
    SERVER_HOST_RESOLVED="$SERVER_HOST" python3 - <<'PY'
import json, os, secrets

env = os.environ.get
tls    = env("WG_TLS_ENABLED", "true") == "true"
iface  = env("WG_IFACE", "wg1udp")
subnet = env("WG_SUBNET", "10.66.66.0/24")
host   = env("SERVER_HOST_RESOLVED", "")
port   = int(env("WG_PANEL_PORT", "8787"))
wgport = int(env("WG_PORT", "51820"))
allow  = [s.strip() for s in env("WG_PANEL_ALLOW_IPS", "").split(",") if s.strip()]
token  = env("WG_BOT_TOKEN", "")
chat   = env("WG_BOT_CHAT_ID", "")
owner  = env("WG_BOT_OWNER_ID", "")
label  = env("WG_SERVER_LABEL", "")

cfg = {
    "secret": secrets.token_hex(24),          # ۴۸ رقمِ هگز، مثلِ قالبِ نقش
    "port": port,
    "server_ifaces": [iface],
    "user_subnets": {iface: subnet},
    "server_host": host,
    "server_endpoint": "%s:%d" % (host, wgport),
    "client_dns": env("WG_CLIENT_DNS", "1.1.1.1, 8.8.8.8"),
    "client_mtu": 1420,
    "users": [{
        "username": env("WG_PANEL_ADMIN_USER", "admin"),
        "salt": "", "hash": "",                # رمز در نخستین ورود ثبت می‌شود
        "role": "admin", "totp": "", "stoken": "",
    }],
    "allow_ips": allow,
    "roles": {},
    "bot": {
        "enabled": bool(token and owner),
        "users": ([{"id": owner, "role": "owner", "name": ""}] if owner else []),
        "add_ifaces": [],
    },
    "alerts": {
        "enabled": bool(token and chat),
        "bot_token": token,
        "chat_id": chat,
        "iface": "",
    },
}
if tls:
    cfg["tls_cert"] = "/opt/wg-panel/tls/panel.crt"
    cfg["tls_key"]  = "/opt/wg-panel/tls/panel.key"
if label:
    cfg["server_label"] = label

path = "/opt/wg-panel/config.json"
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
fi

# پورت و TLS مؤثر همیشه از خودِ config.json خوانده می‌شود (نه از env) تا
# بوت‌های بعدی با والیومِ موجود دقیقاً همان رفتارِ نصب‌شده را ادامه بدهند.
PANEL_PORT=$(python3 -c 'import json;print(json.load(open("/opt/wg-panel/config.json")).get("port",8787))')
PANEL_TLS=$(python3 -c 'import json;print(1 if json.load(open("/opt/wg-panel/config.json")).get("tls_cert") else 0)')

# ---------- ۵) گواهیِ TLS (self-signed؛ فقط اگر نباشد — همان دستورِ نقش) ----------
if [ "$PANEL_TLS" = "1" ] && [ ! -f "$DATA/tls/panel.crt" ]; then
    say "Generating a self-signed certificate…"
    install -d -m 700 "$DATA/tls"
    _cn="${SERVER_HOST:-$(python3 -c 'import json;print(json.load(open("/opt/wg-panel/config.json")).get("server_host",""))')}"
    if [[ "$_cn" =~ ^[0-9.]+$ ]]; then _san="IP:$_cn"; else _san="DNS:$_cn"; fi
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout "$DATA/tls/panel.key" -out "$DATA/tls/panel.crt" \
        -subj "/CN=$_cn" -addext "subjectAltName=$_san" 2>/dev/null
    chmod 600 "$DATA/tls/panel.key"
    chmod 644 "$DATA/tls/panel.crt"
fi

# ---------- ۶) کانفیگِ اینترفیسِ کاربران (فقط اگر نباشد — همان بوت‌استرپِ نقش) ----------
WG_IFACE="${WG_IFACE:-wg1udp}"
WG_PORT="${WG_PORT:-51820}"
WG_SUBNET="${WG_SUBNET:-10.66.66.0/24}"
WG_GATEWAY_IP="${WG_GATEWAY_IP:-10.66.66.1}"
WG_WAN_IFACE="${WG_WAN_IFACE:-eth0}"

if [ ! -f "/etc/wireguard/${WG_IFACE}.conf" ]; then
    # 🪤 مقدارها از **محیط** خوانده می‌شوند، نه اینکه داخلِ سورسِ پایتون
    # درج شوند. الگوی قبلی (`python3 -c "… '$VAR' …"`) را شل بسط می‌داد،
    # پس مقداری با یک آپاستروف رشته را می‌بست و بقیه‌اش کد می‌شد — با
    # root، در بوت‌استرپِ اولِ کانتینر، پیش از آنکه چیزی وجود داشته باشد.
    # اثباتِ عملی: مقدارِ `10.0.0.0/24'); print('X'); ipaddress.ip_network('…`
    # با الگوی قبلی X را چاپ می‌کرد و ۰ برمی‌گشت.
    #
    # محرکِ واقعی مهاجم نیست: اپراتوری است که مقداری با آپاستروف تایپ
    # می‌کند و به‌جای «مقدار نامعتبر»، traceback می‌گیرد.
    #
    # الگوی درست از قبل چند ده خط بالاتر در همین فایل هست (خطِ ۶۷):
    # ‏`<<'PY'` با دلیمیترِ کوت‌شده + os.environ.
    WG_SUBNET="$WG_SUBNET" WG_GATEWAY_IP="$WG_GATEWAY_IP" python3 - <<'PY' \
        || die "Bootstrap of ${WG_IFACE} stopped — fix .env. · بوت‌استرپِ ${WG_IFACE} متوقف شد — .env را اصلاح کنید."
import ipaddress, os, sys
env = os.environ.get
try:
    net = ipaddress.ip_network(env("WG_SUBNET", ""), strict=True)
    gw = ipaddress.ip_address(env("WG_GATEWAY_IP", ""))
except ValueError as e:
    sys.exit("مقدار نامعتبر: %s" % e)
if gw not in net:
    sys.exit("WG_GATEWAY_IP (%s) داخل WG_SUBNET (%s) نیست"
             % (env("WG_GATEWAY_IP"), env("WG_SUBNET")))
PY
    say "Creating /etc/wireguard/${WG_IFACE}.conf …"
    umask 077
    _key=$(wg genkey)
    cat > "/etc/wireguard/${WG_IFACE}.conf" <<EOF
[Interface]
Address = ${WG_GATEWAY_IP}/${WG_SUBNET#*/}
ListenPort = ${WG_PORT}
PrivateKey = ${_key}
PostUp = iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -o ${WG_WAN_IFACE} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s ${WG_SUBNET} -o ${WG_WAN_IFACE} -j MASQUERADE
EOF
    unset _key
    umask 022
fi

# ---------- ۷) بالاآوردنِ اینترفیس‌های ثبت‌شده در config ----------
while IFS= read -r _if; do
    [ -n "$_if" ] || continue
    if [ ! -f "/etc/wireguard/${_if}.conf" ]; then
        say "⚠️ ${_if} is in config.json but /etc/wireguard/${_if}.conf is missing — skipped. · در config.json هست ولی فایلِ کانفیگش نیست."
        continue
    fi
    if ! wg show "$_if" >/dev/null 2>&1; then
        if wg-quick up "$_if" >>"/var/log/wg-panel/units/wg-quick@${_if}.log" 2>&1; then
            say "Interface ${_if} is up."
        else
            say "⚠️ Bringing up ${_if} failed — run: journalctl -u wg-quick@${_if}  inside the container. · برای دیدنِ دلیل همین را داخلِ کانتینر بزنید."
        fi
    fi
done < <(python3 -c 'import json;print("\n".join(json.load(open("/opt/wg-panel/config.json")).get("server_ifaces",[])))')

# ---------- ۸) fail2ban (اختیاری؛ پیش‌فرض روشن مثلِ نقش) ----------
if [ "${WG_F2B_ENABLED:-true}" = "true" ]; then
    install -m 644 "$PAYLOAD/fail2ban-wg-panel.filter.conf" /etc/fail2ban/filter.d/wg-panel.conf
    # پورتِ بن = پورتِ واقعیِ پنل از config.json (درسِ ۳۰ ژوئیه: بنِ همه‌ی
    # پورت‌ها مسیرِ بازیابی را می‌بندد). ignoreip علاوه بر loopback، شبکه‌ی
    # داخلیِ compose را هم می‌گیرد: درخواست‌هایی که docker-proxy رله می‌کند
    # (مثل IPv6→IPv4) با IP دروازه‌ی bridge دیده می‌شوند و بن‌کردنش یعنی
    # قطعِ همه‌ی همان مسیر برای همه.
    sed -e "s/^port .*/port     = ${PANEL_PORT}/" \
        -e "s|^ignoreip .*|ignoreip = 127.0.0.1/8 ::1 ${WG_DOCKER_SUBNET:-172.29.101.0/24}|" \
        "$PAYLOAD/fail2ban-wg-panel.jail.conf" > /etc/fail2ban/jail.d/wg-panel.conf
    # جیلِ پیش‌فرضِ sshd دبیان/اوبونتو در کانتینر بی‌معنی است (sshd نداریم)
    printf '[sshd]\nenabled = false\n' > /etc/fail2ban/jail.d/00-no-sshd.conf
    # «docker compose restart» فایل‌سیستم را نگه می‌دارد ⇒ سوکت/pid کهنه‌ی
    # /var/run/fail2ban می‌ماند و fail2ban با «unexpected state» بالا نمی‌آید.
    if ! pgrep -x fail2ban-server >/dev/null 2>&1; then
        rm -f /var/run/fail2ban/fail2ban.sock /var/run/fail2ban/fail2ban.pid
    fi
    if fail2ban-server -b >/dev/null 2>&1; then
        say "fail2ban is active (wg-panel jail on port ${PANEL_PORT})."
    else
        say "⚠️ fail2ban did not start — the panel continues without it."
    fi
fi

# ---------- ۹) زمان‌بندِ بکاپ — جانشینِ تایمرهای systemd ----------
# بدونِ این، نصبِ Docker هیچ بکاپِ خودکاری نداشت: خودِ پنل بکاپ را زمان‌بندی
# نمی‌کند، فقط یونیت‌ها را می‌خواند و با دکمه راه می‌اندازد. جزئیات و
# انحرافِ عمدی از Persistent=true در سرآیندِ wg-panel-cron.py.
# پیش از exec آغاز می‌شود، پس والدش همان پروسه‌ی پنل است و init:true (tini)
# در خاموشیِ کانتینر آن را درو می‌کند.
/usr/local/bin/wg-panel-cron &

say "Starting the panel on port ${PANEL_PORT} ($([ "$PANEL_TLS" = "1" ] && echo https || echo http)) — version: $(cat "$DATA/VERSION")"
exec python3 "$DATA/wg_panel.py"
