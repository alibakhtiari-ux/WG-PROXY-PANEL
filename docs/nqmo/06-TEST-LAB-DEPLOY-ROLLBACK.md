# WG-NQMO — PHASE 1 · ۶. آزمایشگاه، برنامه‌ی آزمون، استقرار و بازگشت

## ۶٫۱ آزمایشگاهِ Ground Truth (روی مک، **نه** روی سرور)

- **میزبان:** یک VM ِ لینوکسیِ Ubuntu 24.04 در OrbStack. وجود و نسخه‌ی کرنلِ آن در شروعِ PHASE 2 سنجیده می‌شود. اگر کرنلِ VM با `6.8.0-lowlatency` ِ سرور فرق داشته باشد، رفتارهای کلیدی جداگانه روی سرور و **فقط به‌صورتِ منفعل** در فازِ OBSERVATION راستی‌آزمایی می‌شوند (↓ ۶٫۴).
- **توپولوژی با network namespace و veth:**

```
 [client-ns]──veth──[isp-ns]──veth──[server-ns: eth0 ◄ wg1udp, awg-sim, egress]──veth──[inet-ns]
   wg client          tc netem / MTU / nft-drop-frag / ICMP-filter         nqmo زیرِ آزمون
```

- **تزریقِ خرابیِ کنترل‌شده** (هر سناریو یک فایلِ YAML ِ کوچک با برچسبِ حقیقتِ زمینه دارد):
  - MTU ِ لینکِ isp: 1500، 1492 (PPPoE)، 1460، 1400، 1300
  - drop ِ تکه‌ها: `ip frag-off & 0x1fff != 0 drop`
  - فیلترِ ICMP
  - `netem loss 0.5–5%`، `delay`، `jitter` و `reorder`
  - `tbf rate` برای ازدحام
  - `htb` ِ همان پنل برای shaping
  - تغییرِ NAT mapping: بازنویسیِ پورت با SNAT ِ تازه
  - تونلِ تودرتو
  - بارِ CPU با `stress-ng`، اگر در دسترس باشد؛ وگرنه حلقه‌ی پایتون
- **سناریوهای افزوده پس از بازبینی:**
  - کلاینتِ wireguard-go (DF=1) همراه با فیلترِ ICMP در isp-ns؛
  - میانه‌ی بازسرهم‌کننده‌ی تکه‌ها (nft با `ct` و defrag در isp-ns)؛
  - کلاینتِ روتر با LAN ِ بی‌clamp (MSS ِ ۱۴۶۰)؛
  - CGNAT rebind ِ فقط-پورت؛
  - سیلِ handshake (Cookie Reply)؛
  - سنجشِ `rx-gro-list` روشن و خاموش.
- **کلاینت‌های واقعی:** `wireguard-tools` ِ لینوکس و `wireguard-go`. این دو، تفاوتِ DF و MSS ِ پیاده‌سازی‌ها را نشان می‌دهند. رفتارِ اندروید، iOS و ویندوز در آزمایشگاه شبیه‌سازی‌پذیر نیست. فقط از راهِ مشاهده‌ی منفعلِ S5 در فازِ OBSERVATION ثبت می‌شود و هیچ ادعایی درباره‌ی آن‌ها پیش از آن داده نمی‌شود.

## ۶٫۲ نگاشتِ ۴۰ سناریوی پرامپت

| سناریو | در آزمایشگاه | انتظار (حقیقتِ زمینه → خروجی) |
|---|---|---|
| ۱ سالم | ✅ | هیچ تشخیصِ HIGH، MEDIUM یا LOW ای نیست؛ MTU = VERIFIED (UPSTREAM) |
| ۲ غیرفعال · ۳ بی‌ترافیک · ۴ handshake ِ قدیمی | ✅ | `INSUFFICIENT_EVIDENCE`. برای (۴) با شرطِ ترافیکِ صف‌شده: HANDSHAKE_FAILURE |
| ۵ تغییرِ endpoint · ۶ تغییرِ IP · ۷ تغییرِ ASN | ✅ (ASN با فایلِ آزمایشیِ ساختگی) | `endpoint_change` و خطِ پایه‌ی تازه؛ نه تشخیصِ کاذب |
| ۸ تغییرِ اینترفیس · ۹ تغییرِ MTU · ۱۰ تغییرِ routing | ✅ | `config_event` + بازنشانیِ زمینه؛ ROUTING_ANOMALY فقط برای مسیرِ اشتباه |
| ۱۱ loss · ۱۲ ازدحام | ✅ | PACKET_LOSS و NETWORK_CONGESTION؛ **هرگز MTU** (R-MTU-1) |
| ۱۳ black hole · ۱۴ فیلترِ ICMP · ۱۵ تکه‌شدن | ✅ | به‌ترتیب: کلاسِ ۱۱ (الف) با HIGH پس از ۳ پنجره · **دو حالت:** کلاینتِ کرنلی (DF=0) ⇒ بی‌اثر؛ کلاینتِ wireguard-go (DF=1) ⇒ کلاسِ ۱۱ (ب) با سقفِ MEDIUM و CANDIDATE = L_max−60، **نه** PACKET_LOSS · کلاسِ ۱۰ + ESTIMATED = F−60 |
| ۱۶ ناپایداریِ UDP | ✅ | UDP_INSTABILITY |
| ۱۷ IPv4 · ۱۸ IPv6 | ✅ / ⚠ | IPv6: `UNDETERMINED` (IPV6_MODEL_NOT_VALIDATED) |
| ۱۹ مسیرِ نامتقارن | ✅ | ROUTING_ANOMALY، یا UNDETERMINED برای جهتِ ناپیدا |
| ۲۰ تونلِ تودرتو | ✅ | کارتِ `CONFIG_ADVISORY` (CALCULATED، بدونِ هشدار) + ESTIMATED، با ارزیابیِ همه‌ی nexthop ها |
| ۲۱–۲۲ shaping روشن و خاموش | ✅ | TRAFFIC_SHAPING_EFFECT؛ نه MTU |
| ۲۳ اتمامِ سهمیه · ۲۴ پیرِ غیرفعال‌شده | ✅ (با meta ِ ساختگی) | INSUFFICIENT؛ بدونِ هشدار |
| ۲۵ Squid · ۲۶ WARP · ۲۷ AmneziaWG · ۲۸ چند اینترفیس | ⚠ جزئی | WARP و خروجی: EGRESS_TUNNEL_DEGRADATION. awg: C3 خاموش و فقط C1 |
| ۲۹ تلگرام · ۳۰ Prometheus | ✅ واحد + HttpSmoke | dedup، cooldown و کاردینالیتی |
| ۳۱–۳۳ ری‌استارتِ موتور، پنل و WireGuard | ✅ | ادامه با داده‌ی کهنه‌ی علامت‌خورده؛ بدونِ تشخیصِ کاذب در پنجره‌ی گذار |
| ۳۴ قفلِ DB · ۳۵ خرابیِ DB | ✅ | busy_timeout و gap؛ `DB_RECREATED` |
| ۳۶ قطعِ شبکه · ۳۷ CPU ِ بالا · ۳۸ تعدادِ زیادِ پیر | ✅ (۳۸ با ۵۰۰ پیرِ ساختگی) | SERVER_RESOURCE؛ بودجه‌ی CPU و RAM |
| ۳۹ متریکِ ناقص · ۴۰ MTU ِ ناشناخته | ✅ | `INVALID` و `UNDETERMINED`. **معیارِ پذیرشِ قطعی** |

## ۶٫۳ معیارِ پذیرش (پیش از هر استقرار)

1. **صفر** تشخیصِ HIGH ِ نادرست در همه‌ی اجراهای آزمایشگاه. حداقلِ اجرا: ۲۰ تکرار برای هر سناریو، با بذرِ تصادفیِ متفاوتِ netem.
2. در سناریوهای «غیرقابلِ تشخیص» (۳۹ و ۴۰، ICMP ِ کلاینتِ خاموش، جهتِ پایین‌رو)، **۱۰۰٪** خروجی‌ها `UNDETERMINED` یا `INSUFFICIENT_EVIDENCE` باشند.
3. خطای `ESTIMATED` ِ MTU در برابرِ حقیقتِ زمینه **هرگز مثبت نباشد**، یعنی هرگز بالاتر از مقدارِ واقعی. بازه‌ها: برای پیشنهادِ مبتنی بر `F` ‎`[−7, 0]` بایت (فقط برای تکه‌کننده‌ی «تکه‌ی اولِ بیشینه»)، برای `L_max` و probe ‎`[−15, 0]` (کوانتیزه‌شدنِ پدینگ). در سناریوی میانه‌ی بازسرهم‌کننده، فقط شرطِ «نامثبت» سنجیده می‌شود.
4. precision و recall برای هر کلاس گزارش می‌شود، **فقط** با برچسبِ «روی آزمایشگاه، n=…». هیچ درصدی بدونِ این برچسب در هیچ سندی نمی‌آید.
5. اثرِ C3 روی ترافیکِ مرجع: اختلافِ میانه‌ی RTT و loss بین «C3 روشن» و «C3 خاموش» در بازه‌ی خطای اندازه‌گیری باشد.
6. باتریِ محلیِ مخزن (`verify-battery/run-local.sh`) سبز بماند، به‌علاوه‌ی تست‌های تازه‌ی nqmo.

**تست‌های خانوادگی تازه** (قاعده‌ی گاردِ خانوادگیِ CLAUDE.md):

| تست | چه چیزی را تضمین می‌کند |
|---|---|
| `NqmoNoMutationTests` | AST: هیچ exec ای بیرون از wrapper نیست؛ همه‌ی قالب‌های allowlist فقط show/get هستند؛ هیچ send ای روی AF_PACKET نیست |
| `NqmoNoSecretTests` | DB، state، لاگ و meta بدونِ کلید هستند |
| `NqmoNoInnerDestTests` | مقصدِ داخلیِ S5 در هیچ ردیف، state یا لاگی نیست |
| `NqmoSocketOrderTests` | هر سوکتِ AF_PACKET با پروتکلِ ۰ ساخته می‌شود و پیش از `bind` فیلتر و قفل می‌گیرد؛ allowlist شاملِ `wg` و `awg` نیست |
| `NqmoWilsonTests` | loss ِ واقعیِ ۰٫۳٪ در ۱۰ هزار پنجره‌ی شبیه‌سازی‌شده هیچ HIGH ای نمی‌سازد |
| `NqmoNoFabricationTests` | هر تابعِ پیشنهاد با ورودیِ ناقص `UNDETERMINED` می‌دهد (property-based با `random` ِ stdlib) |
| `NqmoMtuNotFromThroughputTests` | امضای تابع‌های MTU شاملِ rate نیست؛ افتِ نرخِ تنها، تشخیصِ MTU نمی‌سازد |
| `NqmoBpfEquivalenceTests` | bytecode برابر با عبارتِ tcpdump روی pcap های مرجع است |
| `NqmoPanelFlagOffParityTests` | با پرچمِ خاموش، `/metrics` و `/api/stats` برابرِ نسخه‌ی پایه‌اند |
| همگامیِ ansible و airgap | `AnsibleSyncTests` برای یونیت و فایل‌های تازه |

## ۶٫۴ DEPLOYMENT-GUIDE (مراحلِ کنترل‌شده؛ **هر گام تأییدِ جدا**)

| گام | چه چیزی | اثرِ زنده | ری‌استارتِ لازم | تأیید |
|---|---|---|---|---|
| D0 | `../WG-PROXY-PANEL` و گیت‌هاب: هیچ | — | — | — |
| D1 | نصبِ `wg_nqmo.pyz` و یونیت (`systemctl enable --now wg-nqmo`)، **بدونِ هیچ capability**؛ حالت `OBSERVATION_ONLY`؛ **C3 خاموش**؛ meta هنوز نیست ⇒ C1 و C5 برابرِ `INVALID` | صفر (فقط خواندن) | هیچ سرویسِ موجودی | ✅ لازم |
| D2 | پنل با پرچمِ `nqmo.enabled=false` (کد آماده و خاموش) | صفر | **`wg-panel` ری‌استارت می‌شود** (۱۱ نخ و ربات)؛ runbook ِ deploy-myserver با `--check` | ✅ لازم، به‌همراهِ پنجره‌ی زمانی |
| D3 | `nqmo.enabled=true` (meta و خواندنِ state؛ UI نشان می‌دهد «سایه») | صفر | **`wg-panel` ری‌استارت می‌شود** (پنل `config.json` را فقط هنگامِ شروع می‌خواند)؛ ترتیب: `stop`، نوشتنِ اتمیک، `start`، چون پنل با هر ورود این فایل را از روی حافظه بازنویسی می‌کند. | ✅ |
| D4 | **روشن کردنِ C3:** نصبِ drop-in ِ `CAP_NET_RAW` و `capture.enabled=true` | صفر روی ترافیک (tap ِ منفعل) | `daemon-reload` + **ری‌استارتِ خودِ wg-nqmo** (برای capability؛ هیچ سرویسِ دیگری متأثر نیست) | ✅ **مجوزِ شنودِ هدر** |
| D5 | نصبِ دیتابیسِ ASN | صفر | reload | ✅ **مجوزِ دانلود** |
| D6 | حداقل ۷ روز سایه، سپس گزارشِ «کاربرانِ بی‌شکایت با HIGH ِ سایه = ?» | — | — | — |
| D7 | `DIAGNOSTICS_ENABLED` | هشدارهای تلگرام شروع می‌شوند | — | ✅ |
| D8 | `RECOMMENDATIONS_ENABLED` (probe همچنان خاموش) | — | — | ✅ |
| D9 | `active_probes=true` (اختیاری) | حداکثر ۶۰KB برای هر اجرای دستی | reload | ✅ |

- پس از هر گام: `run-server.sh` (خواندنی، گامِ ۹ همین موتور را می‌سنجد) و به‌روزرسانیِ `myserver-changelog-20260729.html` (قیدِ ۳). موتور تا پیش از انتشار جزوِ نقشِ ansible و بسته‌های نصب نیست، پس `sync-files.sh` برایش لازم نیست؛ فایل‌هایش فقط در `deploy/` می‌مانند (`deploy/wg-nqmo.service` و `deploy/wg-nqmo.config.json`).
- **ری‌بوت در هیچ گامی لازم نیست و پیشنهاد هم نمی‌شود** (قیدِ ۱). یونیت `WantedBy=multi-user.target` دارد و هیچ وابستگیِ بوتیِ دیگری ندارد. اگر nqmo در بوت شکست بخورد، هیچ چیزِ دیگری متأثر نمی‌شود. ممیزیِ ایستای مسیرِ بوت با اسکیلِ `boot-path-audit` انجام می‌شود.
- دیپلوی از snapshot ِ commit انجام می‌شود (`git worktree add --detach`)، چون working tree کثیف است.

### فرمان‌های گامِ D1

آرشیو از snapshot ساخته می‌شود و شناسه‌اش همان ۱۲ رقمِ اولِ SHA-256 است. هر فرمان فقط اگر قبلی موفق بود اجرا می‌شود.

```bash
python3 tools/build_nqmo_pyz.py --out /tmp/wgdeploy/wg_nqmo.pyz
scp /tmp/wgdeploy/wg_nqmo.pyz deploy/wg-nqmo.service deploy/wg-nqmo.config.json myserver:/tmp/
# روی سرور:
sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin wg-nqmo
sudo install -d -m750 -o root -g wg-nqmo /opt/wg-nqmo
sudo install -m640 -o root -g wg-nqmo /tmp/wg_nqmo.pyz /opt/wg-nqmo/wg_nqmo.pyz
sudo install -d -m755 -o root -g root /etc/wg-nqmo
sudo install -m640 -o root -g wg-nqmo /tmp/wg-nqmo.config.json /etc/wg-nqmo/config.json
sudo install -m644 -o root -g root /tmp/wg-nqmo.service /etc/systemd/system/wg-nqmo.service
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/wg-nqmo.service          # خروجیِ خالی
sudo -u wg-nqmo python3 -I /opt/wg-nqmo/wg_nqmo.pyz --check              # NQMO_CHECK_OK
sudo systemctl enable --now wg-nqmo
```

- `daemon-reload` هیچ سرویسی را ری‌استارت نمی‌کند، ولی همه‌ی یونیت‌ها را دوباره می‌خواند.
- `NoNewPrivs` را فقط روی خودِ سرور می‌شود سنجید: ماشینِ LXC ِ آزمایشگاه این گزینه را اعمال نمی‌کند و همیشه صفر نشان می‌دهد.

### فرمان‌های گامِ D4

فایل‌ها: `deploy/wg-nqmo-capture.conf` و `deploy/wg-nqmo.capture.config.json`. فقط `wg-nqmo` ری‌استارت می‌شود.

```bash
sudo cp -p /etc/wg-nqmo/config.json /etc/wg-nqmo/config.json.bak-$TS
sudo install -d -m755 -o root -g root /etc/systemd/system/wg-nqmo.service.d
sudo install -m644 -o root -g root /tmp/wg-nqmo-capture.conf /etc/systemd/system/wg-nqmo.service.d/capture.conf
sudo install -m640 -o root -g wg-nqmo /tmp/wg-nqmo.capture.config.json /etc/wg-nqmo/config.json
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/wg-nqmo.service          # خروجیِ خالی
sudo -u wg-nqmo python3 -I /opt/wg-nqmo/wg_nqmo.pyz --check              # NQMO_CHECK_OK
sudo systemctl restart wg-nqmo
```

- پس از نصب، `CapPrm`، `CapEff`، `CapBnd` و `CapAmb` همگی باید دقیقاً `0000000000002000` باشند؛ گامِ ۹ ِ `run-server.sh` همین را می‌سنجد.
- `ctypes` زیرِ `MemoryDenyWriteExecute` هم در آزمایشگاه و هم روی سرور کار کرد.
- این تنظیم `ring_blocks=64` دارد، یعنی حدودِ ۶٫۴ ثانیه بافر. با مقدارِ پیش‌فرضِ ۱۶ (حدودِ ۱٫۶ ثانیه) روی myserver در ۴۲٪ دقیقه‌ها `KERNEL_DROP` دیده شد.
- RTT دستِ‌کم ۵ نمونه‌ی هندشیک می‌خواهد و گمشدگی پنجره‌ی ۵ دقیقه‌ایِ کامل؛ پس ستون‌ها چند دقیقه پس از روشن‌شدن پر می‌شوند، و پیرِ بی‌ترافیک خالی می‌ماند.

## ۶٫۵ ROLLBACK-PLAN

| سطح | فرمان | اثر |
|---|---|---|
| خاموشیِ فوریِ موتور | `sudo systemctl disable --now wg-nqmo` | **هیچ وضعیتِ شبکه‌ای برای برگرداندن وجود ندارد**، چون nqmo هرگز چیزی نساخته. پنل «در دسترس نیست» نشان می‌دهد. |
| خاموشیِ شنود | نصبِ `deploy/wg-nqmo.config.json`، حذفِ `wg-nqmo.service.d/capture.conf`، `daemon-reload` و **`restart wg-nqmo`** (reload کافی نیست: تغییرِ `capture` ری‌استارت می‌خواهد) | سوکت‌های AF_PACKET بسته و capability دوباره صفر می‌شود؛ در آزمایشگاه سنجیده شد |
| خاموشیِ یکپارچه‌سازی | `stop` پنل، `config.json → nqmo.enabled=false`، `start` | پنل دقیقاً به رفتارِ امروز برمی‌گردد (تستِ parity) |
| بازگشتِ کدِ پنل | `.bak-$TS` ِ `wg_panel.{py,pyz}` با همان runbook | مثلِ هر دیپلوی |
| بازگشتِ نسخه‌ی nqmo | `wg_nqmo.pyz.bak-$TS` | migration ِ رو به جلو با `user_version` ِ بالاتر ⇒ نسخه‌ی قدیمی فقط‌خواندنی می‌شود، که امن است |
| حذفِ کامل | `disable --now`، حذفِ یونیت + `daemon-reload`، `/opt/wg-nqmo`، `/etc/wg-nqmo`، `/var/lib/wg-nqmo` و کاربرِ `wg-nqmo` | — |

## ۶٫۶ OPERATIONS (خلاصه؛ سندِ کامل در PHASE 6)

- سلامت: `systemctl is-active wg-nqmo`، `wg_nqmo_up`، `wg_nqmo_state_age_seconds < 120`
- خودآزمایی: `python3 -I /opt/wg-nqmo/wg_nqmo.pyz --check`
- عیب‌یابی: `journalctl -u wg-nqmo` (لاگِ ساخت‌یافته‌ی JSON-lines) و جدولِ `collector_health`
- اسکیلِ تازه‌ی `nqmo-ops` در `.claude/skills/`، با تله‌ها و ترتیبِ عیب‌یابی

## ۶٫۷ آنچه پیش از PHASE 2 باید تصمیم بگیرید

1. **تأییدِ کلِ این طراحی** (اسنادِ ۰۱ تا ۰۶)، یا اصلاحات.
2. **viewer** مجوزِ `nqmo.view` را بگیرد یا نه.
3. **ربات** (P9، فرمانِ `/quality`) در دامنه باشد یا نه.
4. **`nqmo.db` در بکاپِ شبانه** باشد یا نه (پیشنهاد: نه).
5. **حریمِ خصوصی:** آیا `ctx_key` ِ `peer_hour` پس از ۳۰ روز به سطحِ کشور تقلیل یابد؟ (پیشنهاد: بله)
6. **محلِ اسناد:** فعلاً در scratchpad ِ نشست‌اند. انتقال به `docs/nqmo/` در مخزن؟
7. **آزمایشگاه:** OrbStack روی این مک در دسترس است؟ در شروعِ PHASE 2 می‌سنجم.
