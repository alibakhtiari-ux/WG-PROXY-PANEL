# WG-NQMO — PHASE 1 · ۳. طراحیِ دیتابیس (DATABASE-DESIGN)

## تصمیم: SQLite ِ مستقل، نه `traffic.db`

| گزینه | ارزیابی |
|---|---|
| جدول‌های تازه در `traffic.db` | رد شد. فایلِ root با مودِ ۶۰۰ است و nqmo باید با کاربرِ جدا اجرا شود. WAL و `wal_checkpoint(TRUNCATE)` ِ پنل با یک نویسنده‌ی دوم تداخل می‌کند (قاعده‌ی «No Database Locking Impact»). |
| **`/var/lib/wg-nqmo/nqmo.db`** | **انتخاب شد.** WAL، `synchronous=NORMAL`، `busy_timeout=5000`. **تنها نویسنده خودِ nqmo است**؛ پنل اصلاً این فایل را باز نمی‌کند و فقط `state.json` را می‌خواند. |

**قراردادها:**
- یک اتصالِ نوشتنیِ ماندگار در نخِ اصلی. **همه‌ی نوشتن‌ها در یک تراکنشِ تکی در پایانِ هر چرخه‌ی ۶۰ ثانیه‌ای** انجام می‌شوند.
- migration با `PRAGMA user_version` و تابع‌های `migrate_N` ِ idempotent انجام می‌شود. نسخه‌ی ناشناخته‌ی بالاتر یعنی **امتناع از نوشتن و حالتِ فقط‌خواندنی**، که در `state.json` اعلام می‌شود.
- **خرابیِ دیتابیس:** در شروعِ کار `PRAGMA quick_check` اجرا می‌شود. اگر نتیجه‌اش `ok` نباشد:
  - فایل به `nqmo.db.corrupt-<ts>` تغییرنام می‌دهد؛
  - دیتابیسِ تازه ساخته می‌شود؛
  - رویدادِ `DB_RECREATED` ثبت می‌شود؛
  - خطِ پایه‌ها از صفر شروع می‌شوند و این صریحاً در UI نشان داده می‌شود.
  
  داده‌ی ساختگی جایگزینِ داده‌ی ازدست‌رفته نمی‌شود.
- پیش‌بینیِ حجم با ۲۴ پیر: حدودِ ۲۴ × ۱۴۴۰ = ۳۵ هزار ردیف در روز برای `peer_minute`، تقریباً ۲۰۰ بایت هرکدام، یعنی حدودِ ۷MB در روز. با نگهداریِ ۱۴ روز، حدودِ ۱۰۰MB. این عدد در آزمایشگاه سنجیده می‌شود. سقفِ سخت `max_db_mb=512` است: اگر از آن گذشت، نگهداری خودکار کوتاه می‌شود و هشدارِ `DB_SIZE_CAP` می‌آید.

## شِما

```sql
-- هویت: کلید = نامِ پیر در پنل + اثرانگشتِ pubkey (نه خودِ کلید)
CREATE TABLE peer (
  peer_id     INTEGER PRIMARY KEY,
  iface       TEXT NOT NULL,
  name        TEXT NOT NULL,
  key_fp      TEXT NOT NULL,          -- sha256(pubkey)[:16]؛ تغییرش ⇒ پیرِ نو (صدورِ دوباره‌ی کلید)
  first_seen  REAL NOT NULL,
  last_seen   REAL NOT NULL,
  UNIQUE(iface, name, key_fp)
);

-- ردیفِ دقیقه‌ای (تجمیع، نه خام)
CREATE TABLE peer_minute (
  peer_id INTEGER NOT NULL, ts INTEGER NOT NULL,             -- آغازِ دقیقه (UTC epoch)
  rx_bytes INTEGER, tx_bytes INTEGER,
  hs_age_max INTEGER,                                        -- بیشینه‌ی سنِ handshake در دقیقه
  ep_ctx INTEGER,                                            -- FK → endpoint_ctx
  ep_changed INTEGER NOT NULL DEFAULT 0,
  hs_init_in INTEGER, hs_resp_out INTEGER, hs_cookie_out INTEGER,  -- S1
  rtt_ms_min REAL, rtt_ms_med REAL, rtt_n INTEGER,           -- S1 (جفتِ Response ↔ data ِ counter=0)
  frag_first INTEGER, frag_incomplete INTEGER,               -- S2/S3
  frag_first_len_min INTEGER, frag_first_len_max INTEGER,
  frag_orig_len INTEGER,                                     -- O از هدرِ UDP ِ تکه‌ی اول
  s4_runs INTEGER, s4_expected INTEGER, s4_received INTEGER, s4_reorder INTEGER, s4_dup INTEGER,
  l_max_unfrag INTEGER,                                      -- بزرگ‌ترین طولِ بیرونیِ تکه‌نشده (S4)
  l_ceiling_share REAL,                                      -- سهمِ بسته‌ها در ۱۶ بایتِ زیرِ l_max (اثرِ سقف)
  df_ratio REAL,                                             -- سهمِ بسته‌های ورودیِ دارای DF
  mss_mode INTEGER, syn_n INTEGER, mss_exceeds INTEGER,      -- S5
  tc_drops INTEGER, tc_overlimits INTEGER, rate_limit_mbit INTEGER,  -- C4
  quality TEXT NOT NULL,                                     -- GOOD|DEGRADED|INVALID
  quality_why TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (peer_id, ts)
) WITHOUT ROWID;

-- زمینه‌ی endpoint بدونِ ذخیره‌ی IP ِ خام
CREATE TABLE endpoint_ctx (
  ctx_id INTEGER PRIMARY KEY,
  ip_hmac TEXT NOT NULL,            -- HMAC-SHA256(local_secret, ip:port)[:20] برای تشخیصِ تغییر
  prefix24 TEXT NOT NULL,           -- مثلاً 5.120.33.0/24 (همان سطحی که پنل نشان می‌دهد پایین‌تر است)
  asn INTEGER, asn_name TEXT, country TEXT,
  asn_db_sha TEXT,                  -- کدام نسخه‌ی دیتابیسِ ASN
  UNIQUE(ip_hmac, asn_db_sha)
);

CREATE TABLE peer_hour (            -- rollup برای خطِ پایه‌ی بلندمدت
  peer_id INTEGER NOT NULL, ts INTEGER NOT NULL,
  active_minutes INTEGER, rx_bytes INTEGER, tx_bytes INTEGER,
  rtt_ms_med REAL, rtt_n INTEGER,
  loss_expected INTEGER, loss_received INTEGER,
  frag_first INTEGER, frag_incomplete INTEGER,
  l_max_unfrag INTEGER, mss_mode INTEGER, df_ratio REAL,
  ctx_key TEXT NOT NULL,            -- (asn|prefix, client_mtu, rate_mbit, wg1udp_mtu)؛ پس از ۳۰ روز به سطحِ «کشور» تقلیل (اگر تأیید شود)
  quality_good_minutes INTEGER,
  PRIMARY KEY (peer_id, ts)
) WITHOUT ROWID;

CREATE TABLE global_minute (        -- C2/C4/C5/C6 ِ سراسری
  ts INTEGER PRIMARY KEY,
  frag_creates INTEGER, frag_fails INTEGER, reasm_reqds INTEGER, reasm_fails INTEGER, reasm_timeout INTEGER,
  icmp_out_unreach INTEGER, icmp_in_unreach INTEGER,
  udp_rcvbuf_err INTEGER, udp_sndbuf_err INTEGER,
  wg1_rx_frame_err INTEGER, wg1_tx_err INTEGER, wg1_tx_dropped INTEGER,
  eth0_rx_missed_fifo INTEGER,       -- rx_missed_errors+rx_fifo_errors+rx_over_errors (نه rx_dropped)
  softnet_dropped INTEGER, softnet_squeeze INTEGER, hs_cookie_out INTEGER,
  cpu_softirq_pct REAL, cpu_total_pct REAL, conntrack_pct REAL,
  egress_json TEXT,                 -- {iface: {healthy, hs_age, rx_delta, svc_ok, mtr_loss, ...}}
  nqmo_cpu_pct REAL, nqmo_rss_mb REAL,
  c3_kernel_drops INTEGER, c3_user_drops INTEGER,
  quality TEXT NOT NULL
);

CREATE TABLE config_event (         -- هر تغییرِ زمینه: MTU ِ اینترفیس، client_mtu، rate_mbit، route ِ endpoint، ECMP
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL,
  subject TEXT NOT NULL, old TEXT, new TEXT
);

CREATE TABLE diagnosis (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL,
  scope TEXT NOT NULL,              -- PEER|GROUP|GLOBAL|SERVER_TUNNEL
  subject TEXT NOT NULL,            -- peer_id | group key | iface
  class TEXT NOT NULL,              -- ↓ DIAGNOSTIC-ENGINE §۲
  confidence TEXT NOT NULL,         -- HIGH|MEDIUM|LOW|INSUFFICIENT_EVIDENCE
  window_start INTEGER NOT NULL, window_end INTEGER NOT NULL,
  evidence_json TEXT NOT NULL, counter_evidence_json TEXT NOT NULL,
  alternatives_json TEXT NOT NULL, data_quality TEXT NOT NULL,
  baseline_ref TEXT,                -- ctx_key + نسخه‌ی خطِ پایه
  mode TEXT NOT NULL,               -- حالتی که در آن ساخته شد (SHADOW در OBSERVATION_ONLY)
  state TEXT NOT NULL,              -- OPEN|CLEARED
  cleared_ts REAL, ack_by TEXT, ack_ts REAL
);
CREATE INDEX idx_diag_subject ON diagnosis(scope, subject, ts);

CREATE TABLE recommendation (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, peer_id INTEGER, iface TEXT,
  target TEXT NOT NULL,             -- CLIENT_IFACE_MTU|SERVER_IFACE_MTU|SERVER_TUNNEL_MTU|SERVER_PEER_TCP_MSS|WAN_MTU
  current_value INTEGER, current_source TEXT NOT NULL,   -- CONFIG|OBSERVED_MSS|KERNEL
  suggested_value INTEGER,                                -- NULL ⇐ UNDETERMINED
  status TEXT NOT NULL,             -- VERIFIED|ESTIMATED|CANDIDATE_FOR_TESTING|UNDETERMINED
  direction_scope TEXT NOT NULL,    -- UPSTREAM|DOWNSTREAM|ROUNDTRIP|SERVER_INTERNAL
  rationale_json TEXT NOT NULL, limitations_json TEXT NOT NULL,
  diagnosis_ids TEXT NOT NULL, superseded_by INTEGER
);

CREATE TABLE correlation_event (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL,
  group_type TEXT NOT NULL, group_key TEXT NOT NULL,
  active_peers INTEGER NOT NULL, affected_peers INTEGER NOT NULL,
  confidence TEXT NOT NULL, suspected_cause TEXT NOT NULL,
  mtu_related_evidence INTEGER NOT NULL, requires_investigation INTEGER NOT NULL,
  evidence_json TEXT NOT NULL, state TEXT NOT NULL
);

CREATE TABLE probe_run (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, peer_id INTEGER NOT NULL,
  requested_by TEXT NOT NULL, sizes_json TEXT NOT NULL, results_json TEXT NOT NULL,
  packets_sent INTEGER NOT NULL, bytes_sent INTEGER NOT NULL,
  verdict TEXT NOT NULL, aborted_reason TEXT
);

CREATE TABLE collector_health (   -- تجمیعِ دقیقه‌ای (C1 هر ۱۰ث چند اجرا در دقیقه دارد)
  ts INTEGER NOT NULL, collector TEXT NOT NULL,
  runs INTEGER NOT NULL, failures INTEGER NOT NULL,
  max_duration_ms REAL, last_error TEXT,
  kernel_drops INTEGER, user_drops INTEGER,
  PRIMARY KEY (collector, ts)
) WITHOUT ROWID;

CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);   -- schema, asn_db_sha/date, mode, local_secret_id
```

## نگهداری (هرس ساعتی، سپس `wal_checkpoint(TRUNCATE)` بیرون از تراکنش)

| جدول | نگهداری |
|---|---|
| `peer_minute`، `global_minute`، `collector_health` | ۱۴ روز |
| `peer_hour` | ۴۰۰ روز |
| `diagnosis`، `recommendation`، `correlation_event`، `probe_run`، `config_event` | ۱۸۳ روز (همسان با `audit` ِ پنل) |
| `endpoint_ctx` بدونِ ارجاع | ۳۰ روز |

## حریمِ خصوصی

- IP ِ خامِ endpoint ذخیره نمی‌شود. فقط `ip_hmac` ذخیره می‌شود؛ `local_secret` تصادفی است، در `/var/lib/wg-nqmo/secret` با مودِ ۶۰۰ نگه داشته می‌شود و هرگز خروجی داده نمی‌شود.
- ذخیره‌ی `prefix24` و ASN برای همبستگی ضروری است. همین سطح همین حالا در پنل برای `wg.view` قابلِ دیدن است، و سطحِ دقیق‌ترش (IP:port) هم دیده می‌شود.
- هیچ payload، کلید یا PSK ای ذخیره نمی‌شود.
- **آنچه گذرا در حافظه می‌آید** این است:
  - هدرهای IP و UDP ِ بیرونی، و ۱۶ بایت هدرِ **رمزنشده‌ی** WireGuard؛
  - در S5، **هدرِ IP و TCP ِ داخلی، یعنی مقصدِ هر اتصالِ تازه‌ی کاربر.**
  
  این مقصد هرگز ذخیره یا لاگ نمی‌شود و تستِ `NqmoNoInnerDestTests` نگهبانِ این است. با این حال این داده متادیتای مرور است و این واقعیت صریحاً ثبت می‌شود (جدولِ حریمِ خصوصی در 02).
- `peer_hour` ِ ۴۰۰روزه با ASN، تاریخچه‌ی بلندمدتِ شبکه‌ی هر کاربرِ نام‌دار است. **پیشنهاد:** پس از ۳۰ روز، `ctx_key` به سطحِ کشور تقلیل یابد. این تصمیمِ شماست.

## بکاپ و ارتقا

- `nqmo.db` **عمداً در بکاپِ شبانه‌ی پنل نیست.** این داده تشخیصی و بازسازی‌پذیر است و حجمش به بکاپِ MEGA اضافه نمی‌شود. اگر شما بخواهید، یک خطِ `sqlite3 backup` ِ WAL-safe به `wg-panel-backup.sh` اضافه می‌شود.
- ارتقا با migration ِ رو به جلو انجام می‌شود. rollback ِ نرم‌افزار به نسخه‌ی قبلی با `user_version` ِ بالاتر یعنی حالتِ فقط‌خواندنی، که امن است و داده پاک نمی‌شود.
