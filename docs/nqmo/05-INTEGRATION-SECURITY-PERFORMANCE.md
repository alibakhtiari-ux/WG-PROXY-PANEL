# WG-NQMO — PHASE 1 · ۵. یکپارچه‌سازی، امنیت و کارایی

این سند API-CONTRACT، SECURITY-REVIEW (طراحی) و PERFORMANCE (بودجه و روشِ سنجش) را پوشش می‌دهد.

---

## ۵٫۱ تغییراتِ پنل (`wgpanel/app.py`)، کوچک و پشتِ پرچم

تمامِ این تغییرات پشتِ کلیدِ `config.json → nqmo.enabled` (پیش‌فرض `false`) قرار دارند. وقتی پرچم خاموش است، رفتارِ پنل **بایت‌به‌بایت** همان رفتارِ امروز است. یک تست این را نگهبانی می‌کند: خروجیِ `/metrics` و `/api/stats` با پرچمِ خاموش با نسخه‌ی پایه مقایسه می‌شود.

| # | تغییر | محل | ریسک |
|---|---|---|---|
| P1 | `_export_nqmo_meta()` در `AlertMonitor`. جزئیات در پایینِ جدول. | `AlertMonitor.run` | پایین. **فیلدهای ممنوع:** `psk`، `preshared`، `private`، `secret`، `token`. تستِ خانوادگی هم کلیدهای JSON و هم مقدارهای base64 ِ ۴۴کاراکتری را اسکن می‌کند. فقط pubkey های فهرست‌شده مجازند. |
| P2 | `nqmo_state()`: خواندنِ `/var/lib/wg-nqmo/state.json` با کشِ ۱۰ ثانیه‌ای. اگر فایل نباشد، خراب باشد یا بیش از ۱۸۰ ثانیه کهنه باشد، `{"available": false, "why": …}` برمی‌گرداند و **هرگز استثنا به بالا نمی‌دهد**. | تابعِ تازه | پایین |
| P3 | `_check_nqmo()`: صندوقِ خروجیِ رویدادها. جزئیات در پایینِ جدول. | `ALERT_EVENTS` + `_check_x` | پایین. تستِ `test_every_offered_alert_kind_has_an_emitter` آن را می‌گیرد. |
| P4 | `build_metrics`: افزودنِ سری‌های `wg_nqmo_*` از `nqmo_state()` ِ کش‌شده. **هیچ subprocess ای در زمانِ scrape اجرا نمی‌شود.** | انتهای `build_metrics` | پایین |
| P5 | API های تازه (جدولِ زیر) + افزودن به `PERM_MAP` | ناحیه‌ی HTTP | متوسط. تستِ `test_perm_map_covers_every_endpoint` ناظرش است. |
| P6 | مجوزهای تازه در `PERM_CATALOG`، گروهِ `nqmo` | ۱۰۳۹ | متوسط. `RbacTests` و `RoleEscalationTests`. |
| P7 | UI: تبِ «کیفیتِ ارتباط» + بخشِ «کیفیت و MTU» در کشوی هر کاربر | `wgpanel/web/page.html` | متوسط. باتری، گامِ نحوِ JS. |
| P8 | کلیدهای i18n (fa/en/ru/zh) | `wgpanel/i18n/catalog.json` | پایین. تست‌های هم‌ارزیِ کاتالوگ. |
| P9 | ربات: فرمانِ `/quality <name>`، فقط خواندنی | `TelegramBot` | پایین. **اختیاری**؛ با الگوی parity ِ bot-ops. |

**جزئیاتِ P1 (`_export_nqmo_meta`):**
- **دوره:** با `_due("nqmo_meta", 60)`. چرخه‌ی `AlertMonitor` ۳۰ ثانیه است (app.py:7277).
- **بیرون از شرطِ `if alert_cfg()["enabled"]`** و در `try` ِ جداگانه‌ی خودش. دلیل: هشدارها به‌طورِ پیش‌فرض خاموش‌اند و این خروجی نباید به آن‌ها گره بخورد. خطای `_check_tunnels` هم نباید جلویش را بگیرد.
- **داده** از `SAMPLER.snapshot()` و `META` و `TUNNELS` ِ موجود می‌آید. **هیچ subprocess ِ تازه‌ای ندارد.**
- **محل:** پوشه‌ی `/run/wg-panel` را خودِ پنل هنگامِ شروع می‌سازد (‎0750، `root:wg-nqmo`). اگر گروهِ `wg-nqmo` نباشد، هیچ فایلی نوشته نمی‌شود. فایل اتمیک نوشته می‌شود، با مودِ ‎0640.
- **محتوا:**
  ```
  {generated_at, client_mtu, wg1udp:{mtu, fwmark, local_ip},
   peers:{<pubkey>:{iface, name, enabled, tunnel_ip, c_mtu, rate_mbit,
                    endpoint, latest_handshake, rx_bytes, tx_bytes}},
   egress:{<if>:{kind, mtu, endpoint_dev, awg_s4, hs_age, rx_delta, health,
                 svc_ok, svc_latency_ms, mtr_loss, mtr_rtt, warp_ms, ecmp_member, ts}}}
  ```

**جزئیاتِ P3 (`_check_nqmo`):**
- خواندنِ `state.json → notify_outbox`. این فهرستی از رویدادهاست با شکلِ `{id, severity, key, text_key, params}`، و nqmo آن را پیشاپیش dedup کرده و هیسترزیس، cooldown، سقفِ نرخ و ACK را رویش اعمال کرده.
- برای هر `id` بزرگ‌تر از آخرین شناسه‌ی ارسال‌شده، `ALERTS.event("nqmo", A(text_key, **params))` فرستاده می‌شود.
- آخرین شناسه به‌صورتِ اتمیک در `/opt/wg-panel/nqmo-notified.last` ثبت می‌شود.
- **چرا `edge` نه:** `AlertManager.edge` در نخستین دیدنِ کلید چیزی نمی‌فرستد (app.py:7241، شرطِ `prev is not None`). کلیدها پس از ۷ روز هم هرس می‌شوند. ACK هم پارامترِ mute ندارد.
- `("nqmo", …)` به `ALERT_EVENTS` اضافه می‌شود.
- **از لایه‌ی تلگرامِ موجود استفاده می‌شود؛ هیچ ارسال‌کننده‌ی تازه‌ای ساخته نمی‌شود.**

**آنچه عوض نمی‌شود:** `Sampler`، `TrafficShaper`، `make_client_conf`، `traffic.db`، و هر مسیری که شبکه را تغییر می‌دهد.

## ۵٫۲ API-CONTRACT (پنل ↔ مرورگر)

همه‌ی مسیرها با `path == "…"` تعریف می‌شوند (قاعده‌ی wg-panel-core §۱)، نه `startswith`.

| مسیر | متد | مجوز | پاسخ |
|---|---|---|---|
| `/api/nqmo/status` | GET | `nqmo.view` | `{available, mode, generated_at, collectors:{C1..C8:{ok,last,error}}, coverage:{peers_total, peers_active, c3_enabled, asn_db:{date,stale}}, global:[diagnosis], groups_eligible, summary:{<name>:{state, top_class, confidence}}}` |
| `/api/nqmo/peer?name=<n>` | GET | `nqmo.view` | `{name, quality_state, last_activity, last_handshake, throughput, rtt:{med,n}, loss_up:{pct,n}, mtu:{config, device_lower_bound, upstream:{status, l_max, f}, recommendation:{target, value, status, direction_scope, rationale, limitations}}, diagnoses:[…], history_24h:[…]}`. **بدونِ IP ِ خام.** prefix و ASN فقط برای `nqmo.detail`. |
| `/api/nqmo/events?since=` | GET | `nqmo.view` | فهرستِ diagnosis و correlation، صفحه‌بندی‌شده (حداکثر ۲۰۰ مورد) |
| `/api/nqmo/ack` | POST | `nqmo.ack` | `{id}`، از راهِ `ctl.sock`. ثبت در `audit(actor,"nqmo","ack",…)` و `log_action` |
| `/api/nqmo/probe` | POST | `nqmo.probe` | `{name}` → `{run_id}` یا `{refused: reason}`. همه‌ی گیت‌های §۴٫۷ سمتِ nqmo دوباره سنجیده می‌شوند (دفاعِ دولایه). |
| `/api/nqmo/mode` | GET/POST | `nqmo.manage` | تغییرِ حالت فقط یک پله در هر بار. ممیزی می‌شود. |

قراردادِ ctl.sock (پنل → nqmo)، JSON-lines، یک درخواست برای هر اتصال:

```
{"v":1,"op":"ack","id":123,"actor":"admin"}          → {"ok":true}
{"v":1,"op":"probe","peer":"<name>","actor":"admin"}  → {"ok":true,"run_id":7} | {"ok":false,"refused":"MODE_GATE|FLAG_GATE|BUSY|RATE|STALE_HS"}
{"v":1,"op":"mode.get"}                              → {"ok":true,"mode":"OBSERVATION_ONLY"}
{"v":1,"op":"mode.set","to":"DIAGNOSTICS_ENABLED","actor":"admin"} → {"ok":true} | {"ok":false,"refused":"NOT_ADJACENT"}
```

ورودی با schema ِ سخت سنجیده می‌شود: کلیدِ ناشناخته، طولِ بیش از ۶۴KB یا `name` بیرون از regex ِ نام‌های پنل، رد می‌شود.

## ۵٫۳ RBAC

| مجوز | معنا | پیش‌فرضِ نقش‌ها |
|---|---|---|
| `nqmo.view` | وضعیتِ کیفیت و تشخیص، بدونِ prefix و ASN | admin، و viewer در صورتِ تأییدِ شما |
| `nqmo.detail` | prefix24، ASN، شواهدِ کامل | admin |
| `nqmo.ack` | تأییدِ دیده‌شدنِ هشدار | admin |
| `nqmo.probe` | اجرای probe ِ فعالِ دستی | فقط admin |
| `nqmo.manage` | تغییرِ حالت | فقط admin |

`ESCALATION_PERMS` (app.py:1114) عمداً دست نمی‌خورد. معنایش «مجوزی که به دارنده اجازه‌ی گرفتنِ مجوزِ بیشتر می‌دهد» است، و `role_is_privileged` بر پایه‌ی آن تصمیم می‌گیرد. `nqmo.probe` و `nqmo.manage` چنین نیستند. پیش‌فرضِ admin-only بودن از پیش‌فرض‌های نقش‌ها می‌آید.

## ۵٫۴ Telegram

- **dedup:** در خودِ nqmo انجام می‌شود (هیسترزیسِ R-HYST-1 و `notify_outbox` با شناسه‌ی یکتا). پنل فقط شناسه‌های تازه را با `ALERTS.event("nqmo", …)` می‌فرستد.
- **cooldown:** برای هر کلید، اگر یک تشخیص ظرفِ ۶ ساعت باز و بسته و دوباره باز شود، فقط در digest می‌آید (`nqmo_cooldown_h=6`).
- **سقفِ نرخ:** حداکثر ۶ پیامِ nqmo در ساعت برای کلِ سرور. مازاد در یک پیامِ تجمیعی جمع می‌شود.
- **شدت:** HIGH برابرِ 🔴 و MEDIUM برابرِ 🟠. LOW هرگز پیام نمی‌شود و فقط در UI می‌آید.
- **ACK:** از UI یا با دکمه‌ی inline ِ ربات انجام می‌شود (در صورتِ اجرای P9).
- **تاریخچه:** `/api/nqmo/events`. digest ِ روزانه بخشی برای nqmo می‌گیرد.
- قالبِ پیام همان ساختارِ پرامپت را دارد، با سه فیلدِ همیشگی: `Automatic Change: DISABLED`، `Recommendation status: …` و متنِ محدودیتِ جهت (بالارو یا پایین‌رو).
- **متن‌ها فقط از کاتالوگ می‌آیند.** تستِ `test_alerts_have_no_hardcoded_persian` نگهبانِ این است.

## ۵٫۵ Prometheus (کم‌کاردینالیتی، بدونِ کلید و بدونِ IP)

```
wg_nqmo_up                                   0|1
wg_nqmo_state_age_seconds
wg_nqmo_mode{mode}                           1   (۳ مقدارِ ثابت)
wg_nqmo_collector_ok{collector}              0|1 (۸ مقدار)
wg_nqmo_peer_quality_state{iface,name}       0=ok 1=low 2=medium 3=high -1=insufficient
wg_nqmo_peer_rtt_seconds{iface,name}         (فقط با n≥5)
wg_nqmo_peer_upstream_loss_ratio{iface,name} (فقط با n≥200)
wg_nqmo_peer_mtu_status{iface,name}          0=undetermined 1=candidate 2=estimated 3=verified
wg_nqmo_diagnoses_open{class}                (۱۳ مقدارِ ثابت)
wg_nqmo_mtu_suspected_events_total
wg_nqmo_insufficient_evidence_total
wg_nqmo_alerts_total
wg_nqmo_monitoring_errors_total{collector}
wg_nqmo_diagnostic_duration_seconds
wg_nqmo_active_peers
wg_nqmo_capture_drops_total{side}            kernel|user
```

- کاردینالیتی: حدودِ ۲۴ پیر × ۴ سری به‌علاوه‌ی حدودِ ۴۰ سریِ ثابت، یعنی کمتر از ۱۵۰ سری.
- برچسبِ `name` همان برچسبِ موجودِ `wg_peer_*` است.
- auth: همان Bearer ِ `metrics_token` و `allow_ips`.

## ۵٫۶ SECURITY-REVIEW (طراحی)

| الزام | سازوکار |
|---|---|
| عدمِ دسترسی و ذخیره‌ی Private Key یا PSK | nqmo **`CAP_NET_ADMIN` ندارد**، پس نه `wg show` می‌تواند بزند و نه genetlink ِ WireGuard را می‌تواند صدا کند. به `/etc/wireguard` و `/opt/wg-panel` هم دسترسی ندارد. meta ِ پنل فیلترِ کلید دارد و تستِ خانوادگی آن را نگهبانی می‌کند. |
| عدمِ ذخیره‌ی payload | snaplen ِ سخت درونِ cBPF. **هدرهای IP و UDP ِ بیرونی، و در S5 هدرِ IP و TCP ِ داخلی، گذرا وارد حافظه می‌شوند.** مقصدِ داخلی ذخیره یا لاگ نمی‌شود و تستِ `NqmoNoInnerDestTests` نگهبانِ این است. |
| بدونِ ارسال به cloud | هیچ سوکتِ AF_INET ِ خروجی‌ای جز `ping` ِ گیت‌دار در کد نیست. ASN آفلاین است. تستِ AST: هیچ `urllib`، `http.client` یا `connect()` ای نیست. |
| کمینه‌ی دسترسی | کاربرِ جدا، **بدونِ capability** تا گامِ D4، سپس فقط `CAP_NET_RAW` با drop-in، `ProtectSystem=strict`، `SystemCallFilter`، و بدونِ دسترسی به `/etc/wireguard` یا `/opt/wg-panel` |
| جداسازیِ دسترسی | پنل فایلِ nqmo را می‌خواند؛ nqmo فقط فایلِ meta ِ بی‌راز را. ctl.sock فقط uid=0 (پنل) را می‌پذیرد. |
| حفاظتِ IPC | سوکت با مودِ ‎0600 در `/run/wg-nqmo`، به‌علاوه‌ی `SO_PEERCRED`، سقفِ اندازه و timeout |
| اعتبارسنجیِ ورودی | schema ِ سخت برای ctl و config، regex برای iface و نام، `ipaddress` برای IP ها |
| جلوگیری از Command Injection | فقط argv، بدونِ shell، با allowlist ِ قالب‌ها |
| Audit | هر ack، probe و mode در `audit` ِ پنل و `nqmo.db` |
| عدمِ افشا | IP ِ خام ذخیره نمی‌شود (HMAC)؛ prefix و ASN پشتِ `nqmo.detail`؛ متریک بدونِ IP |
| محدودسازیِ Packet Capture | شش جریانِ ثابت (بدونِ فیلترِ پویا)، snaplen ِ سخت، ترتیبِ ایمنِ ساختِ سوکت (پروتکلِ ۰ ← attach ← lock ← bind)، `SO_LOCK_FILTER`، بدونِ ذخیره‌ی pcap، و C3 با پرچمِ جدا (`capture.enabled`، پیش‌فرض false) |
| زنجیره‌ی تأمین | فقط stdlib. bytecode ِ BPF در آزمایشگاه با tcpdump ِ رسمیِ Ubuntu تولید و با تست قفل می‌شود. pyz ِ قطعی با هش. |

**ریسکِ باقی‌مانده:**

| گام | دسترسیِ nqmo | پیامدِ اجرای کدِ دلخواه در nqmo |
|---|---|---|
| تا پیش از D4 | **هیچ capability ای ندارد** | فقط داده‌ی خودِ nqmo و meta ِ بی‌راز در دسترس است |
| پس از D4 (`CAP_NET_RAW`) | شنود و تزریق | مهاجم می‌تواند ترافیکِ **کامل، با payload**، را روی همه‌ی اینترفیس‌ها شنود کند و بسته تزریق کند. snaplen و `SO_LOCK_FILTER` فقط در برابرِ خطای کدِ خودمان محافظت می‌کنند. |

- کلیدِ خصوصیِ سرور و PSK ها در هیچ گامی در دسترس نیستند.
- سطحِ حمله‌ی ورودی دو چیز است: ctl.sock (فقط uid 0)، و پارسِ طول‌ثابتِ هدرها با `struct.unpack_from` و بررسیِ مرز.

## ۵٫۷ PERFORMANCE (بودجه، نه ادعا)

| منبع | بودجه‌ی طراحی | سقفِ سخت | روشِ سنجش |
|---|---|---|---|
| CPU ِ nqmo | کمتر از ۲٪ ِ یک هسته به‌طورِ میانگین | `CPUQuota=20%` در یونیت، با شنودِ هدر `200%` از drop-in ِ resources (§29.162: کمتر از آن بستنِ پنجره را throttle می‌کند) + خود-throttle ِ S4 در ۳۰٪ | `/proc/self/stat` در `global_minute` |
| RAM | کمتر از ۸۰MB (با ASN) | `MemoryMax=160M` | RSS در `global_minute` |
| Disk I/O | یک تراکنش در دقیقه، حدودِ ۷MB در روز | `IOSchedulingClass=idle`، `max_db_mb` | اندازه‌ی DB و WAL |
| Network | صفر در حالتِ منفعل؛ probe حداکثر ۶۰KB در هر اجرا | گیت‌ها | `probe_run.bytes_sent` |
| اثر روی پنل | خواندنِ یک فایل در هر ۱۰ ثانیه و نوشتنِ یک فایل در هر ۶۰ ثانیه | — | مقایسه‌ی زمانِ `/api/stats` پیش و پس |
| اثر روی ترافیک | **صفر از نظرِ ساختاری**: tap منفعل است و هیچ قاعده‌ی شبکه‌ای در کار نیست | — | سنجه‌ی آزمایشگاهی: loss و RTT ِ ترافیکِ مرجع با C3 روشن و خاموش |

**نقطه‌ی پرهزینه S4 است،** یعنی کلِ ترافیکِ ورودیِ WireGuard. طراحی از ابتدا `PACKET_RX_RING` / TPACKET_V3 با `mmap` را به کار می‌برد:
- فریم‌ها به اندازه‌ی snaplen‌اند و timestamp ِ کرنل رایگان است؛
- `SO_RCVBUF` به کار نمی‌رود، چون truesize ِ هر skb آن را عملاً به حدودِ ۱۰۰ تا ۲۰۰ بسته محدود می‌کرد.

پردازشِ پایتون با `struct.unpack_from` روی بلوک‌ها انجام می‌شود. هزینه‌ی واقعی در PHASE 5 روی آزمایشگاه و در فازِ OBSERVATION روی نرخِ واقعیِ سرور اندازه‌گیری می‌شود. اگر از بودجه گذشت، S4 به چرخشِ نمونه می‌رود (۵ ثانیه در هر ۶۰ ثانیه) و این در `quality_why` ثبت می‌شود.

سقفِ `CPUQuota=20%` نمی‌گذارد این هزینه به ترافیک یا پنل سرایت کند. چون زمان از timestamp ِ کرنل می‌آید، throttle شدنِ پروسه هم دقتِ RTT را خراب نمی‌کند.
