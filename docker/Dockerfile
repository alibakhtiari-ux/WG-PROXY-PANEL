# wg-panel — نسخه‌ی Docker برای نصب روی اوبونتوی دیگر (۲۲.۰۴/۲۴.۰۴)
#
# ⚠️ context بیلد باید «ریشه‌ی مخزن» باشد، نه پوشه‌ی docker/ (compose همین را
#    تنظیم کرده است). به همین دلیل wg_panel.py و فایل‌های نقشِ ansible مستقیم
#    از منبعِ کانونی کپی می‌شوند و هیچ نسخه‌ی دومی داخلِ docker/ نگه‌داری
#    نمی‌شود — همان دامی که بسته‌های online/airgap را کهنه می‌کرد (rebuild-drill)
#    اینجا از اساس ناممکن است.
#
# پایه ubuntu:24.04 است تا با تنها محیطِ پشتیبانی‌شده‌ی نقشِ ansible یکی باشد
# (python3 = 3.12، iptables-nft، همان مسیرهای squid/fail2ban).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# همه‌ی باینری‌هایی که wg_panel.py با run([...]) صدا می‌زند (استخراج از سورس):
#   wg/wg-quick ← wireguard-tools · ip/tc/ss ← iproute2 · iptables · ipset
#   ping ← iputils-ping · dig ← bind9-dnsutils · sysctl/pgrep ← procps
#   traceroute · mtr · curl · openssl · qrencode · squid · fail2ban · rclone
# (openresolv در نوبل حذف شده؛ پس در کانفیگِ «سمتِ سرور» خطِ DNS= نگذارید —
#  بوت‌استرپِ entrypoint هم نمی‌گذارد. DNS کلاینت‌ها ربطی به این ندارد.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        wireguard-tools \
        iproute2 \
        iptables \
        ipset \
        iputils-ping \
        bind9-dnsutils \
        procps \
        traceroute \
        mtr-tiny \
        curl \
        ca-certificates \
        openssl \
        qrencode \
        squid \
        fail2ban \
        rclone \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    # بسته‌ی ssl-cert (وابستگیِ squid) هنگامِ نصب یک جفت کلید/گواهیِ
    # «snakeoil» می‌سازد و آن‌ها در لایه‌ی ایمیج **پخته** می‌شوند — یعنی هر
    # کسی که این ایمیج را بگیرد همان کلیدِ خصوصی را دارد. پنل از آن استفاده
    # نمی‌کند (کلیدِ خودش را در اولین بوت داخلِ والیوم با مود ۶۰۰ می‌سازد) و
    # squid فقط در کامنت به آن اشاره دارد (هیچ https_port فعالی ندارد)، پس
    # حذفش بی‌خطر است و ایمیجِ توزیع‌شدنی هیچ کلیدِ خصوصی‌ای حمل نمی‌کند.
    && rm -f /etc/ssl/private/ssl-cert-snakeoil.key \
             /etc/ssl/certs/ssl-cert-snakeoil.pem

# ---- بارِ پنل (payload) — entrypoint در هر بوت آن را داخلِ والیومِ
#      /opt/wg-panel تازه می‌کند تا ارتقا = بیلدِ دوباره‌ی ایمیج باشد.
COPY wg_panel.py qr.js \
     three.module.min.js.gz three.core.min.js.gz three.LICENSE.txt \
     /usr/local/share/wg-panel/

# فایل‌های fail2ban از خودِ نقشِ ansible — یک منبع، بدونِ کپیِ دوم.
COPY deploy/fail2ban-wg-panel.filter.conf \
     deploy/fail2ban-wg-panel.jail.conf \
     /usr/local/share/wg-panel/

# اسکریپت‌های بکاپ (دکمه‌ی «پشتیبان‌گیریِ دستی» پنل از راهِ شیمِ systemctl
# همین‌ها را به‌صورتِ oneshot اجرا می‌کند).
COPY deploy/wg-panel-backup.sh \
     deploy/wg-panel-s4-upload.sh \
     /usr/local/sbin/

# ---- شیم‌ها و اسکریپت‌های خودِ کانتینر
# /usr/local/bin در PATH جلوتر از /usr/bin است، پس subprocessهای پنل که
# systemctl/journalctl را صدا می‌زنند به شیم می‌رسند نه به systemdِ غایب.
COPY docker/systemctl-shim.sh  /usr/local/bin/systemctl
COPY docker/journalctl-shim.sh /usr/local/bin/journalctl
COPY docker/healthcheck.sh     /usr/local/bin/wg-panel-health
COPY docker/entrypoint.sh      /usr/local/bin/wg-panel-entrypoint
# جانشینِ تایمرهای systemd — بی این، بکاپِ خودکار وجود ندارد.
COPY docker/wg-panel-cron.py   /usr/local/bin/wg-panel-cron

# همان گیتِ استقرارِ runbook، پخته‌شده در بیلد: py_compile باید سبز باشد و
# نحوِ bash همه‌ی اسکریپت‌ها سالم؛ VERSION = ۱۲ رقمِ اولِ SHA-256 خودِ پنل
# (همان قراردادِ نقشِ ansible و پنلِ مستقر).
RUN chmod 755 /usr/local/bin/systemctl /usr/local/bin/journalctl \
              /usr/local/bin/wg-panel-health /usr/local/bin/wg-panel-entrypoint \
              /usr/local/bin/wg-panel-cron \
    && chmod 750 /usr/local/sbin/wg-panel-backup.sh /usr/local/sbin/wg-panel-s4-upload.sh \
    && bash -n /usr/local/bin/systemctl /usr/local/bin/journalctl \
               /usr/local/bin/wg-panel-health /usr/local/bin/wg-panel-entrypoint \
               /usr/local/sbin/wg-panel-backup.sh /usr/local/sbin/wg-panel-s4-upload.sh \
    # cfile صریح به /tmp، وگرنه py_compile یک __pycache__ در /usr/local/bin
    # جا می‌گذارد؛ doraise هم خطای نحو را به شکستِ بیلد تبدیل می‌کند.
    && python3 -c "import py_compile; py_compile.compile('/usr/local/bin/wg-panel-cron', cfile='/tmp/cron.pyc', doraise=True)" \
    && rm -f /tmp/cron.pyc \
    && python3 -m py_compile /usr/local/share/wg-panel/wg_panel.py \
    && sha256sum /usr/local/share/wg-panel/wg_panel.py | cut -c1-12 \
         > /usr/local/share/wg-panel/VERSION \
    && rm -rf /usr/local/share/wg-panel/__pycache__

EXPOSE 8787/tcp 51820/udp 18080/tcp

ENTRYPOINT ["/usr/local/bin/wg-panel-entrypoint"]
