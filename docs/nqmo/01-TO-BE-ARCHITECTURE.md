# WG-NQMO — PHASE 1 · ۱. معماریِ هدف (TO-BE-ARCHITECTURE)

- **مبنا:** مخزنِ `wg-panel` در commit `b713e52` (build id `ffad648ed9ea`)، که همان کدِ Production است. **GitHub `main` مبنا نیست.**
- **وضعیت:** فقط طراحی. هیچ کدی نوشته نشده و هیچ چیزی روی سرور اجرا نشده.
- **ویرایش:** نسخه‌ی ۲، پس از بازبینیِ خصمانه (`REVIEW-findings.md`، ۲۴ یافته). نگاشتِ هر یافته به اصلاحش در `07-REVIEW-RESOLUTION.md` آمده است.

---

## ۰. تصمیم‌هایی که با شاهد گرفته شدند

| موضوع | تصمیم | شاهد |
|---|---|---|
| شمارشِ تکه‌ها، MSS و هدرِ WireGuard | **فقط AF_PACKET + cBPF.** هیچ قاعده‌ی nft یا iptables ای ساخته نمی‌شود. | tap منفعل است و از نظرِ ساختاری نمی‌تواند روی forwarding اثر بگذارد. پیش از defrag ِ netfilter می‌نشیند (`__netif_receive_skb_core`، پیش از `ip_rcv`)، پس تکه‌ها را می‌بیند. هدرِ رمزنشده‌ی WireGuard را هم می‌بیند. |
| loss ِ بالارو (کلاینت ← سرور) | **قابلِ اندازه‌گیری است**، از روی شکافِ counter ِ هر keypair، با کرانِ اطمینانِ آماری | `messages.h:105-108`: فیلدهای `type`، `key_idx` و `counter` رمزنشده‌اند. nonce برای هر keypair از صفر شروع می‌شود و یکنوا بالا می‌رود (`send.c:379-380`). بسته‌ای که پس از گرفتنِ nonce شکست بخورد، روی keypair ِ قدیمی دوباره صف می‌شود و آن keypair دوباره استفاده نمی‌شود، پس در جریانِ دیده‌شده شکاف نمی‌سازد (`send.c:383-413`). |
| RTT | **در هر handshake، منفعلانه.** نمونه‌ی RTT از جفت کردنِ Response با **نخستین data ِ همان keypair (counter=0)** با فیلترِ ثابت به دست می‌آید. زمان از **timestamp ِ کرنل** (`SO_TIMESTAMPNS`) گرفته می‌شود. | `receive.c:181-186`: پس از Response، آغازگر بلافاصله داده‌ی صف‌شده یا keepalive می‌فرستد. نخستین nonce ِ هر keypair صفر است. |
| داده‌ی `wg show` | **از پنل می‌آید (`nqmo-meta.json`). nqmo `CAP_NET_ADMIN` ندارد.** | `WG_CMD_GET_DEVICE` به هر دارنده‌ی `CAP_NET_ADMIN` کلیدِ خصوصیِ سرور و همه‌ی PSK ها را می‌دهد. نخِ Sampler ِ پنل همین حالا هر ۲ ثانیه `wg show` را با root اجرا می‌کند. |
| هشدار | **صندوقِ خروجیِ رویداد** (`notify_outbox`) در `state.json`، که پنل با `ALERTS.event("nqmo", …)` می‌فرستد. | `AlertManager.edge` (app.py:7229-7245) در نخستین دیدنِ یک کلید پیامی نمی‌دهد. در حالی که dedup، هیسترزیس، cooldown و ACK در خودِ nqmo هستند. |

**واقعیت‌های کرنل و میدان، سنجیده در سورسِ v6.8 یا روی سرور به‌صورتِ فقط‌خواندنی:**

- **DF ِ سمتِ سرور:** `socket.c:85-87` با `udp_tunnel_xmit_skb(..., df=0, ...)`. پس بسته‌ی بیرونیِ سرور ← کلاینت **هرگز DF ندارد**.
- **DF ِ سمتِ کلاینت به پیاده‌سازی بستگی دارد:**

  | پیاده‌سازیِ کلاینت | DF ِ بسته‌ی بیرونی | پیامد |
  |---|---|---|
  | کرنلِ لینوکس | ندارد (`df=0`) | بسته‌ی بزرگ در مسیر تکه‌تکه می‌شود |
  | wireguard-go روی لینوکس و اندروید | **دارد** (`IP_PMTUDISC_WANT` ِ پیش‌فرض) | اگر ICMP در مسیر فیلتر باشد، **سیاه‌چاله‌ی بی‌تکه** رخ می‌دهد |
  | wireguard-nt و اپل | **NOT_VERIFIED** | تا وقتی **per-peer از بیتِ DF ِ بسته‌های رسیده** خوانده نشده، هیچ فرضی گرفته نمی‌شود |

- **GRO:** سوکتِ WireGuard فقط `encap_rcv` دارد (`socket.c:355-356`) و `UDP_GRO` نمی‌گذارد. ادغام فقط با `rx-gro-list` ممکن است، که روی eth0 ِ سرور **`off`** است (سنجیده شد). گاردِ زمانِ اجرا روی `tot_len` ِ هدرِ IP همچنان می‌ماند.
- **شمارنده‌ها:**
  - `rx_frame_errors` ِ wg1udp یعنی مبدأِ بیرون از AllowedIPs (`receive.c:415-432`).
  - `tx_dropped` یعنی سرریزِ صفِ staged (`device.c:211-213`).
  - `tx_errors` یعنی مقصدی بی‌پیر (`device.c:224-231`).
  - `eth0 rx_dropped` (۵۳۳ هزار) فریم‌های بی‌پروتکل است، **نه** drop ِ صف. `rx_missed_errors` و `rx_fifo_errors` هر دو صفرند. پس این عدد هرگز شاهدِ loss حساب نمی‌شود.

---

## ۱. شکلِ کلی

```
                         Ubuntu (myserver)
 ┌──────────────────────────────────────────────────────────────────┐
 │  wg-nqmo.service  (کاربرِ wg-nqmo، فقط stdlib، بدونِ CAP_NET_ADMIN) │
 │   C1 meta-reader (10s) ◄── /run/wg-panel/nqmo-meta.json           │
 │   C2 kernel (/proc، /sys؛ 60s)    C4 tc-stats (tc -s show؛ 60s)   │
 │   C3 capture: S1 S2 S3 (سوکتِ ساده) + S4 (TPACKET_V3)  ◄─ فقط با  │
 │       drop-in ِ CAP_NET_RAW (گامِ D4)                              │
 │   C5 egress (از meta)   C6 resources                               │
 │          └──► bounded queues ──► Aggregator (60s)                  │
 │                         ├──► nqmo.db (SQLite ِ جدا، WAL)          │
 │   Baseline ─► Diagnose ─► Confidence ─► Recommend ─► Correlate    │
 │      state.json (اتمیک؛ شاملِ notify_outbox)   ctl.sock (uid 0)   │
 └─────────────────────────┬────────────────┬───────────────────────┘
                           │ read           │ ack / probe / mode
 ┌─────────────────────────┴────────────────┴───────────────────────┐
 │  wg-panel (موجود)                                                 │
 │   AlertMonitor: _export_nqmo_meta (هر ۶۰ث، مستقل از alerts.enabled)│
 │                 _check_nqmo ─► ALERTS.event("nqmo", …) ─► تلگرام   │
 │   build_metrics ◄─ state.json (wg_nqmo_* · {iface,name})          │
 │   /api/nqmo/* (RBAC ِ تازه) ─► تبِ «کیفیتِ ارتباط»                 │
 └───────────────────────────────────────────────────────────────────┘
```

## ۲. مرزِ مسئولیت‌ها

| مسئولیت | مالک | دلیل |
|---|---|---|
| خواندنِ کرنل (`wg show`) | **پنل** (که همین حالا هر ۲ ثانیه این کار را می‌کند) | تا راز وارد هیچ پروسه‌ی کم‌امتیازی نشود |
| شنودِ هدر، تجمیع، ذخیره، خطِ پایه، تشخیص، پیشنهاد، همبستگی، probe ِ دستی | **wg-nqmo** | Crash ِ nqmo پنل را نمی‌خواباند. وقتی پنل مرده است، C3 ادامه می‌دهد: handshake، endpoint، RTT، loss و تکه‌ها را مستقیم از سیم می‌بیند. فقط نام‌گذاری و شمارنده‌های بایت کهنه علامت می‌خورند. |
| تلگرام، Prometheus، وب، RBAC، ممیزی | **پنل** | سیستمِ اعلانِ موازی ممنوع است |
| هر تغییرِ شبکه | **هیچ‌کدام** | فقط پیشنهادِ متنی و راهنمای اعمالِ دستی (مالکش `tunnel-ops`) |

**استقلالِ کامل در برابرِ کمینه‌ی دسترسی:**
- پرامپت می‌خواهد موتور «تا حدی که منابعِ داده اجازه می‌دهند» با Crash ِ پنل کار کند.
- با این طراحی، **همه‌ی سنجه‌های کیفیت** (C2، C3، C6) مستقل‌اند.
- فقط داده‌ی کنترلی (نام، `rate_mbit`، `c_mtu`، شمارنده‌ی بایت، سلامتِ خروجی) به پنل وابسته است.
- این بده‌بستان آگاهانه است. جایگزینش دادنِ کلیدِ خصوصیِ سرور به یک پروسه‌ی دوم بود.

## ۳. IPC: سه کانال

| کانال | جهت | قرارداد |
|---|---|---|
| `/run/wg-panel/nqmo-meta.json` | پنل → nqmo | JSON ِ اتمیک، هر ۶۰ ثانیه. پوشه‌ی `/run/wg-panel` را **خودِ پنل** هنگامِ شروع می‌سازد (`os.makedirs`، مود ‎0750، `root:wg-nqmo`). اگر گروهِ `wg-nqmo` وجود نداشته باشد (nqmo نصب نشده)، پنل هیچ فایلی نمی‌نویسد و هیچ خطایی نمی‌دهد. محتوا در 05 §۵٫۱. **هیچ کلیدِ خصوصی یا PSK ای در آن نیست.** |
| `/var/lib/wg-nqmo/state.json` | nqmo → پنل | JSON ِ اتمیک با فیلدهای `generated_at`، `schema` و `notify_outbox` |
| `/run/wg-nqmo/ctl.sock` | پنل → nqmo | Unix stream، JSON-lines، سقفِ ۶۴KB، `SO_PEERCRED` با شرطِ uid=0. فقط برای `ack`، `probe` و `mode.get/set`. |

**هیچ نوشتنی در `traffic.db` ِ پنل انجام نمی‌شود.**

## ۴. حالت‌ها (هیچ‌کدام خودکار به بعدی نمی‌رود)

| حالت | فعال | خروجی |
|---|---|---|
| `OBSERVATION_ONLY` (پیش‌فرض) | C1، C2، C4، C5، C6. C3 فقط پس از D4. خطِ پایه ساخته می‌شود. تشخیص در «سایه» محاسبه می‌شود. | سلامتِ جمع‌کننده‌ها. **بدونِ تشخیص در UI و بدونِ هشدار.** |
| `DIAGNOSTICS_ENABLED` | + نمایشِ تشخیص | هشدار فقط برای HIGH و MEDIUM. MTU = `UNDETERMINED (DISABLED)` |
| `RECOMMENDATIONS_ENABLED` | + مدلِ پیشنهاد + probe ِ دستی (اگر `active_probes=true`) | پیشنهاد با یکی از چهار وضعیت |

- **راه‌های تغییرِ حالت:** فرمانِ `mode.set` (مجوزِ `nqmo.manage`، فقط یک پله) یا ویرایشِ config و سپس `reload`. هر دو ممیزی می‌شوند.
- **شرطِ نمایش داده‌شده برای ارتقا:** حداقل ۷ روز داده، و صفر HIGH ِ سایه روی پیرهایی که اپراتور «بی‌شکایت» علامت زده. **تصمیم با اپراتور است.**

## ۵. چرخه‌ی اجرا

- **نخِ اصلی:** زمان‌بندِ تک‌نخی با بودجه برای هر وظیفه. اگر وظیفه‌ای از بودجه بگذرد، آن دور رد می‌شود و `collector_gap` ثبت می‌شود.

  | وظیفه | دوره | بودجه |
  |---|---|---|
  | C1 (خواندنِ meta) | ۱۰ ثانیه | ۱ ثانیه |
  | C2 / C4 / C5 / C6 | ۶۰ ثانیه | ۲ ثانیه |
  | تجمیع و تحلیل | ۶۰ ثانیه | ۵ ثانیه |

- **نخِ کم‌نرخِ C3:** S1، S2، S3 و S5 روی سوکت‌های ساده با `recvmsg` و timestamp ِ کرنل (`SO_TIMESTAMPNS`)، با `select` و timeout ِ یک‌ثانیه‌ای.
- **نخِ S4:** `PACKET_RX_RING` با TPACKET_V3، بلوک‌های ۲۵۶KB × ۱۶ (۴MB، شمرده‌شده در `MemoryMax`). فریم‌ها به اندازه‌ی snaplen‌اند و timestamp رایگان است. **`SO_RCVBUF` به کار نمی‌رود**، چون truesize ِ هر skb بافر را عملاً به حدودِ ۱۰۰ بسته محدود می‌کند.
- **صف‌ها:** `queue.Queue(maxsize=20000)`. در صورتِ پُر شدن، کهنه‌ترین دور ریخته و شمارده می‌شود.
- **قاعده‌ی واحدِ کیفیت:** هر drop ِ سمتِ کرنل (`tp_drops` از `PACKET_STATISTICS`؛ چون با هر خواندن صفر می‌شود، پیش از بستنِ هر سوکت خوانده می‌شود) یا drop ِ سمتِ کاربر در یک پنجره، **آن پنجره را برای سنجه‌های همان جریان `INVALID` می‌کند**. سنجه‌های جریان‌های دیگر دست‌نخورده می‌مانند.
- **watchdog:** `sd_notify("WATCHDOG=1")` پس از هر چرخه‌ی موفقِ نخِ اصلی، با `WatchdogSec=90`. heartbeat ِ داخلیِ هر نخِ C3 اگر بیش از ۳۰ ثانیه بگذرد، فقط همان نخ بازسازی می‌شود.
- **`SIGHUP`:** پیکربندی کامل اعتبارسنجی می‌شود. اگر نامعتبر باشد، پیکربندیِ قبلی می‌ماند و خطا در `state.json` اعلام می‌شود.
- **`SIGTERM`:** flush، checkpoint، بستنِ سوکت‌ها، با سقفِ ۱۰ ثانیه.

## ۶. systemd و کمینه‌ی دسترسی

**یونیتِ پایه (گام D1): هیچ capability ای ندارد.**

```ini
[Unit]
Description=موتورِ کیفیتِ شبکه WG-NQMO (فقط مشاهده)
After=network-online.target
# عمداً بدونِ Requires/BindsTo/PartOf به wg-panel یا wg-quick: موتور ناظر است و
# نه افتادنش باید چیزی را بیندازد، نه چیزی باید منتظرش بماند.
# StartLimit* جایش [Unit] است؛ در [Service] بی‌صدا نادیده گرفته می‌شود.
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=notify
User=wg-nqmo
Group=wg-nqmo
ExecStart=/usr/bin/python3 -I /opt/wg-nqmo/wg_nqmo.pyz --run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=15
WatchdogSec=90
TimeoutStopSec=15
CPUQuota=20%
MemoryHigh=128M
MemoryMax=160M
TasksMax=32
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
OOMScoreAdjust=600
# بدونِ هیچ capability. گامِ D4 فقط با drop-in ِ جدا CAP_NET_RAW و AF_PACKET می‌دهد؛
# CAP_NET_ADMIN هرگز، چون خواندنِ کلیدِ خصوصی و PSK با `wg show` همان را می‌خواهد.
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077
StateDirectory=wg-nqmo
StateDirectoryMode=0750
RuntimeDirectory=wg-nqmo
RuntimeDirectoryMode=0750
ConfigurationDirectory=wg-nqmo

[Install]
WantedBy=multi-user.target
```

- `ProcSubset=pid` عمداً گذاشته نشده، چون `/proc/net` و `/proc/stat` را پنهان می‌کند.
- `SystemCallFilter=~@privileged @resources` فقط پس از آزمونِ آزمایشگاهی اضافه می‌شود.

**drop-in ِ گام D4** (`/etc/systemd/system/wg-nqmo.service.d/capture.conf`)، که فقط با مجوزِ شنودِ هدر نصب می‌شود:

```ini
[Service]
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_PACKET
```

**گامِ D9 (probe ِ دستی)** به `CAP_NET_RAW` نیاز ندارد. `ping` ِ iputils به سوکتِ datagram ِ ICMP برمی‌گردد. در آزمایشگاه بررسی می‌شود که `net.ipv4.ping_group_range` شاملِ گروهِ `wg-nqmo` باشد. اگر نباشد، از همان `CAP_NET_RAW` ِ D4 استفاده می‌شود.

**ریسکِ باقی‌مانده، صریح:**
- با drop-in ِ D4، اجرای کدِ دلخواه در nqmo یعنی **شنودِ کامل (با payload) و تزریقِ بسته روی همه‌ی اینترفیس‌ها**. snaplen ِ ۴۴ بایتی و `SO_LOCK_FILTER` فقط در برابرِ خطای کدِ خودمان محافظت می‌کنند، نه در برابرِ مهاجمِ صاحبِ پروسه.
- **کلیدِ خصوصیِ سرور و PSK ها در هیچ حالتی در دسترسِ nqmo نیستند.** دلیل: `CAP_NET_ADMIN` ندارد و به `/etc/wireguard` و `/opt/wg-panel` هم دسترسی ندارد.
- سطحِ حمله‌ی ورودی دو چیز است: ctl.sock (فقط uid 0)، و پارسِ طول‌ثابتِ هدرِ بسته‌ها با `struct.unpack`.

**allowlist ِ argv** (تنها مسیرِ exec؛ هر چیزِ دیگر `RuntimeError` می‌دهد):

```
tc  -s -j qdisc|class|filter show dev <IF>
ip  -j -d link show
ip  -j route get <IPv4> [from <IPv4>] [mark <hex>]
ip  -j nexthop show
ping -4 -n -q -M do -s <SIZE> -c <N> -W 1 -I wg1udp <TUNNEL_IP>    ← فقط probe؛ هر دو گیت
```

`wg show` و `awg show` **در allowlist نیستند.** دلیلِ هم‌ارزیِ `ip route get` با مسیرِ واقعیِ WireGuard در DIAGNOSTIC-ENGINE §۲ (کلاسِ ۶) آمده است.

## ۷. بسته‌بندی

- پکیجِ `nqmo/` در همین مخزن، فقط کتابخانه‌ی استاندارد. آرشیوِ قطعیِ `wg_nqmo.pyz` با الگوی `tools/build_pyz.py` ساخته می‌شود.
- خودآزمایی: **`python3 -I /opt/wg-nqmo/wg_nqmo.pyz --check`** که `NQMO_CHECK_OK` چاپ می‌کند.
- ماژول‌ها:
  ```
  nqmo/
    __main__.py   --run | --check
    config.py     runner.py   sched.py   store.py   export.py   ctl.py
    collect/
      meta.py       C1 + C5: خواندن و اعتبارسنجیِ nqmo-meta.json
      kernel.py     C2
      capture.py    S1 S2 S3 S5: recvmsg و SO_TIMESTAMPNS
      ring.py       S4: TPACKET_V3 با mmap
      bpf.py        برنامه‌های cBPF ِ از‌پیش‌کامپایل‌شده برای DLT_RAW
      wgparse.py
      tcstats.py    resources.py
    baseline.py   diagnose.py   confidence.py   recommend.py   correlate.py   asn.py   probe.py
  ```

## ۸. پوششی که عمداً نیست

| مورد | وضعیت |
|---|---|
| کاربرانِ AnyConnect | `NOT_COVERED`، صریحاً در UI |
| کاربرانِ Squid | فقط به‌عنوانِ بارِ سرور در C6 |
| جهتِ پایین‌رو به‌صورتِ منفعل | غیرقابلِ مشاهده. فقط با probe ِ دستی. |
| انتسابِ جریانِ هر کاربر به خروجیِ مشخص | ناممکن بدونِ conntrack ِ per-flow |
| IPv6 ِ داخلیِ تونل | S5 فقط IPv4 را می‌بیند. IPv6 روی سرور خاموش است. |
| اینترفیسِ کاربرِ AmneziaWG (در آینده) | C3 خاموش، چون قالبِ هدرش فرق دارد |
