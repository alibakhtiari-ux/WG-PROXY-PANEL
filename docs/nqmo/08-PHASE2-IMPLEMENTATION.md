# WG-NQMO — PHASE 2 · پیاده‌سازیِ هسته (۲۵ اکتبر ۲۰۲۶)

**وضعیت:** کد در مخزن نوشته و آزموده شده است. **کامیت نشده.** **روی سرور هیچ چیزی نصب یا اجرا نشده است.**

مبنا commit `b713e52` است. کد در پکیجِ تازه‌ی `nqmo/` قرار دارد و فقط کتابخانه‌ی استانداردِ پایتون را به کار می‌برد. **هیچ فایلِ موجودی از جمله `wgpanel/` تغییر نکرده است.** یکپارچه‌سازی با پنل کارِ PHASE 4 است.

## ۱. آنچه ساخته شد

| فایل | نقش |
|---|---|
| `nqmo/config.py` | پیش‌فرض‌های محافظه‌کار. هر کلیدِ ناشناخته، نوعِ غلط یا مقدارِ بیرون از بازه رد می‌شود. |
| `nqmo/runner.py` | **تنها نقطه‌ای که پروسه اجرا می‌کند:** allowlist ِ `tc -s -j … show`، `ip -j -d link show`، `ip -j nexthop show` و `ip -j route get`. **`wg`، `awg` و `ping` در آن نیستند.** قالبِ ping تا PHASE 3 عمداً وجود ندارد. |
| `nqmo/sched.py` | زمان‌بند با بودجه برای هر وظیفه و backpressure، به‌علاوه‌ی `sd_notify` |
| `nqmo/store.py` | `nqmo.db` ِ جدا با WAL، migration با `user_version`، نسخه‌ی تازه‌تر یعنی حالتِ فقط‌خواندنی، و فایلِ خراب کنار گذاشته می‌شود. **فایلِ قفل‌شده یا باز‌نشدنی خطا می‌دهد و «خراب» حساب نمی‌شود.** |
| `nqmo/collect/meta.py` | خواندنِ meta ِ پنل به‌صورتِ fail-closed: نامِ کلیدِ ممنوع، کلیدِ جاسازی‌شده یا بی‌padding، NaN/Infinity و زمانِ آینده همه رد می‌شوند. endpoint یا IP ِ داخلیِ مشترک بینِ دو پیر به هیچ‌کس نسبت داده نمی‌شود. |
| `nqmo/collect/kernel.py` | `/proc/net/snmp`، `netstat`، `softnet_stat` و `/sys/class/net`. **`rx_dropped` عمداً کنار گذاشته شده.** |
| `nqmo/collect/tcstats.py` | نگاشتِ classid → IP از روی خودِ فیلترهای u32. هر چیزِ مبهم به هیچ‌کس نسبت داده نمی‌شود. |
| `nqmo/collect/bpf.py` | **تولیدشده** با `tools/gen_nqmo_bpf.py`: پنج برنامه‌ی cBPF برای DLT_RAW با snaplen ِ سخت |
| `nqmo/collect/wgparse.py` | پارسرهای طول‌ثابت با کنترلِ مرز. `parse_syn` مقصد را برنمی‌گرداند. |
| `nqmo/collect/capture.py` | سوکتِ منفعل با ترتیبِ ایمن: پروتکلِ ۰ ← فیلتر ← قفل ← timestamp ← bind |
| `nqmo/collect/ring.py` | TPACKET_V3 با `mmap`. بلوکِ `TP_STATUS_LOSING` **پیش از** فریم‌هایش gap اعلام می‌کند. |
| `nqmo/aggregate.py` | `KeypairTrack` (پنجره‌ی ۸۱۲۸ ِ خودِ WireGuard)، `S4Reducer` (در نخِ ring)، و `Aggregator` (سطلِ دقیقه بر پایه‌ی timestamp ِ کرنل، نگاشت بر پایه‌ی index) |
| `nqmo/engine.py` | نخ‌ها و مالکیتِ آن‌ها، flush ِ تأخیری، بازگشتِ خودکارِ سوکت، نخِ جدا برای tc، و reload ِ محدود |
| `nqmo/ctl.py` | ctl.sock: درخواست‌ها از راهِ صف به نخِ اصلی می‌روند |
| `nqmo/export.py` | `state.json` ِ اتمیک. `diagnoses` و `notify_outbox` فعلاً خالی‌اند (PHASE 3). |
| `tools/build_nqmo_pyz.py` | آرشیوِ قطعیِ `wg_nqmo.pyz`، با همان قراردادِ `build_pyz.py` |
| `tests/test_nqmo.py` | ۷۶ تست، از جمله نگهبان‌های خانوادگی |

## ۲. دورِ دومِ بازبینی (بازبینِ مستقلِ کد) و حلِ آن

بازبین ۲ BLOCKER، ۸ MAJOR و حدودِ ۱۵ MINOR پیدا کرد. همه پذیرفته و اصلاح شدند.

| # | یافته | اصلاح | تستِ نگهبان |
|---|---|---|---|
| B1 | نخِ ctl از اتصالِ SQLite ِ نخِ اصلی استفاده می‌کرد و نخش با نخستین `mode.set` می‌مرد | درخواست از راهِ صف به نخِ اصلی می‌رود (`serve_pending`). هر استثنا گرفته می‌شود. | `test_ctl_runs_on_main_thread_via_queue` (سوکتِ واقعی) |
| B2 | drop ِ حلقه ۶۰ ثانیه دیر دیده می‌شد و تا آن وقت loss ِ ساختگی ذخیره شده بود | پرچمِ `TP_STATUS_LOSING` ِ هر بلوک پیش از قضاوتِ فریم‌ها بررسی می‌شود. سوکت‌های کم‌نرخ هر ثانیه سنجیده می‌شوند. | `test_losing_block_yields_gap_before_its_frames`، `test_gap_keeps_judged_counts_and_never_invents_loss` |
| M1 | دلتای بایت در دقیقه‌ی بی‌meta دو بار شمرده می‌شد | هر meta دقیقاً یک بار، در دقیقه‌ی `generated_at` ِ خودش، با `c1_interval_s` ثبت می‌شود | `test_c1_deltas_counted_once_per_meta` |
| M2 | endpoint ِ مشترک (CGNAT) ترافیک را به پیرِ اشتباه می‌داد | نگاشت با index ِ handshake انجام می‌شود. ابهام یعنی هیچ‌کس. پیرِ غیرفعال نگاشت نمی‌شود. | `test_s4_summary_mapped_by_index_over_endpoint`، `test_ambiguous_endpoint_maps_to_nobody` |
| M3 | gap شمارش‌های قضاوت‌شده را هم دور می‌ریخت | پیش از دور ریختن fold می‌شود | `test_gap_keeps_judged_counts…` |
| M4 | نخِ شنود با یک خطای سوکت می‌مرد و برنمی‌گشت | هر سوکت جدا و با backoff دوباره باز می‌شود و gap ثبت می‌شود. نخِ مرده هم supervisor دارد. | `test_socket_error_reopens_and_reports_gap` |
| M5 | ردیف‌ها با C3 ِ خاموش «GOOD» می‌گرفتند | برچسب‌های `C3:DISABLED`، `C3:DOWN:<نخ>` و `STARTUP` | `test_minute_flow_…` |
| M6 | meta استثنای غیر-`MetaError` می‌داد و C1 را کور می‌کرد | همه به `MetaError` تبدیل می‌شوند. endpoint ِ IPv6 «مدل‌نشده» علامت می‌خورد و کلِ meta را رد نمی‌کند. | `NqmoMetaHardeningTests` |
| M7 | سیلِ S3 جدولِ orphan را پُر می‌کرد | تکه‌ی غیرِ‌پیر اصلاً ذخیره نمی‌شود. TTL در هر drain اعمال می‌شود. پُر شدن برچسب می‌گیرد. | `test_foreign_tail_fragments_are_not_stored` |
| M8 | گلوگاهِ S4 | کاهشِ S4 در نخِ ring انجام می‌شود و فقط خلاصه‌ها عبور می‌کنند. حالتِ sampling فریم‌ها را بی‌پارس آزاد می‌کند. tc در نخِ جدا اجرا می‌شود. صف‌ها جدا شدند. | اندازه‌گیری در PHASE 5 |

**MINOR ها:**
- لبه‌ی پذیرشِ `h−c = W` ِ WireGuard
- `parse_constant` برای NaN
- کلیدِ جاسازی‌شده
- bool به جای int
- `COMMIT` ِ ناموفق → ROLLBACK
- `umask 077`
- reload ِ محدود
- `ring_block_kb % 4`
- سطل‌بندی بر پایه‌ی timestamp و flush ِ جدا برای هر دقیقه‌ی عقب‌افتاده
- finalize ِ زودِ keypair ِ قدیمی پس از rekey
- گاردِ `INVALID_GRO`
- حذفِ ping
- نبودِ ردیف برای پیرِ بیکار
- Cookie ِ سراسری
- مقدارِ `secret` با طولِ نادرست ⇒ خطای مرگبار
- بازنشانیِ `prev` پس از شکستِ خواندنِ کرنل

## ۳. شاهدِ عددی (۲۵ اکتبر ۲۰۲۶)

| سنجه | عدد |
|---|---|
| `tests/test_nqmo.py` روی Python 3.14 | **۷۶/۷۶ سبز**، بدونِ هیچ ResourceWarning |
| همان روی Python 3.11 | **۷۶/۷۶ سبز** |
| نحوِ کل پکیج با `feature_version=(3,9)` | سالم. سرور 3.12 است. |
| `python3 -m nqmo --check` و `python3 -I wg_nqmo.pyz --check` | `NQMO_CHECK_OK 0.1.0` |
| `tools/gen_nqmo_bpf.py --check` | bpf.py به‌روز است |
| ساختِ pyz | قطعی (دو ساختِ پیاپی بایت‌به‌بایت یکی‌اند) |
| کلِ مجموعه‌ی مخزن (`unittest discover`) | ۱۲۷۰ تست، **۲ قرمز**، هر دو **پیش از این کار و بیرون از آن** (↓ §۴) |

## ۴. قرمزیِ از‌پیش‌موجودِ باتری (به `nqmo` ربط ندارد)

کامیتِ `b713e52` (۱۷ اکتبر) در `tests/test_mac_backup_pull.py:36` نامِ دامنه‌ی خصوصیِ سرور (همان الگوی نخستِ `publish/private-identifiers.txt`) را دارد. نتیجه:

- گاردِ `test_real_owner_identifiers_stay_out_of_tests` قرمز می‌شود.
- `test_a_planted_leak_is_reported…` هم قرمز می‌شود، چون اسکریپتِ انتشار پیش از اجرا کلِ تست‌ها را روی clone ِ HEAD می‌زند.

رفعش یک‌خطی است: نامِ میزبانِ خنثی در همان پیامِ ساختگیِ ssh. **عمداً دست نخورد**، چون بیرون از دامنه‌ی این کار و متعلق به نشستِ دیگری است.

## ۵. آنچه هنوز سنجیده نشده (صریح)

- **هیچ آزمونی روی لینوکسِ واقعی یا سوکتِ AF_PACKET ِ واقعی اجرا نشده است.** ترتیبِ ساختِ سوکت و چیدمانِ TPACKET_V3 با fake ها و سورسِ کرنل سنجیده شده‌اند. آزمونِ واقعی در آزمایشگاهِ OrbStack انجام می‌شود (نیازمندِ مجوزِ دانلودِ ایمیج).
- شکلِ دقیقِ JSON ِ `tc -j filter show` روی iproute2 ِ سرور: NOT_VERIFIED.
- هزینه‌ی CPU ِ S4 روی نرخِ واقعی: PHASE 5.
- تشخیص، سطحِ اطمینان، پیشنهادِ MTU و همبستگی: **PHASE 3**. هنوز نوشته نشده‌اند.

## ۶. تصمیم‌های پیش‌فرضِ گرفته‌شده (برگشت‌پذیر)

تصمیم‌های بازِ §۶٫۷ ِ سندِ 06 با پیش‌فرضِ محافظه‌کار گرفته شدند و هرکدام قابلِ تغییر است:

1. **viewer** مجوزِ `nqmo.view` ندارد؛ فقط admin.
2. **ربات** فعلاً در دامنه نیست.
3. **`nqmo.db`** در بکاپِ شبانه نیست.
4. **`ctx_key`** پس از ۳۰ روز به سطحِ کشور تقلیل می‌یابد (`retention_days.hour_ctx_coarsen=30`؛ اجرایش همراهِ rollup ِ ساعتی در PHASE 3).
5. **اسناد** به `docs/nqmo/` منتقل شدند.
