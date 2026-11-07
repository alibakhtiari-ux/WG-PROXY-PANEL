#!/usr/bin/env bash
# سورس: deploy/wg-nqmo-review.sh → /usr/local/sbin/wg-nqmo-review.sh
#
# بایگانیِ بازبینیِ هفت‌روزه‌ی WG-NQMO روی خودِ سرور (§29.158). state.json هر
# دقیقه بازنویسی می‌شود و تشخیص‌های سایه‌ای اصلاً در آن نیستند؛ این اسکریپت
# هر ساعت یک نسخه‌ی فشرده از state.json و یک خطِ خلاصه از پایگاهِ موتور
# (تشخیص‌ها به تفکیکِ وضعیت/کلاس/سطح، هزینه‌ی موتور، جمع‌آورها، خطاها) در
# /var/lib/wg-nqmo/review می‌نویسد، تا بازبینی به مکِ روشن وابسته نباشد.
#
# فقط می‌خوانَد: پایگاه با mode=ro باز می‌شود، state.json کپی می‌شود، هیچ
# فرمانِ شبکه‌ای نیست. با کاربرِ wg-nqmo اجرا می‌شود (مالکِ همان پوشه).
# idempotent: اجرای دوباره در همان ساعت فایلِ همان ساعت را بازنویسی می‌کند.
#   NR_STATE_DIR  پوشه‌ی داده‌ی موتور (پیش‌فرض /var/lib/wg-nqmo)
#   NR_DRY_RUN=1  فقط خلاصه را چاپ کن، چیزی ننویس
#   NR_KEEP_DAYS  نگه‌داریِ نسخه‌های ساعتی (پیش‌فرض ۱۴ روز)
set -uo pipefail

STATE_DIR="${NR_STATE_DIR:-/var/lib/wg-nqmo}"
OUT="$STATE_DIR/review"
KEEP="${NR_KEEP_DAYS:-14}"
STAMP="$(date +%Y%m%d-%H)"

if [ ! -r "$STATE_DIR/state.json" ]; then
  echo "wg-nqmo-review: $STATE_DIR/state.json خوانا نیست" >&2
  exit 1
fi

# خلاصه: یک خطِ JSON، فقط عدد و واژگانِ بسته (بدونِ نامِ پیر، IP یا کلید)
summary="$(python3 -I - "$STATE_DIR" <<'PY'
import json, sqlite3, sys, time
d = sys.argv[1]
st = json.load(open(d + "/state.json", encoding="utf-8"))
cov = st.get("coverage") or {}
out = {"ts": int(time.time()), "state_age_s": int(time.time() - st.get("generated_at", 0)),
       "mode": st.get("mode"), "collectors": st.get("collectors"),
       "engine": cov.get("engine"), "loop_ms": cov.get("loop_ms"),
       "peers_active": cov.get("peers_handshake_180s"),
       "peers_total": cov.get("peers_total"), "errors": len(st.get("errors") or []),
       "promotion": {"data_days": (st.get("promotion") or {}).get("data_days"),
                     "shadow_high_7d": sum((st.get("promotion") or {})
                                           .get("shadow_high_by_peer_7d", {}).values())},
       "diagnoses": {}}
try:
    c = sqlite3.connect("file:%s/nqmo.db?mode=ro" % d, uri=True)
    for state, cls, conf, mode, n in c.execute(
            "SELECT state, class, confidence, mode, COUNT(*) FROM diagnosis "
            "GROUP BY 1,2,3,4 ORDER BY 1,2,3,4"):
        out["diagnoses"]["%s/%s/%s/%s" % (state, mode, cls, conf)] = n
    out["notify_outbox"] = c.execute("SELECT COUNT(*) FROM notify_outbox").fetchone()[0]
    # کیفیتِ دقیقه‌های ساعتِ اخیر: چند دقیقه تمیز، چند با کدام توکن
    rows = c.execute("SELECT quality_why, COUNT(*) FROM peer_minute WHERE ts > ? "
                     "GROUP BY 1 ORDER BY 2 DESC LIMIT 6", (time.time() - 3600,)).fetchall()
    out["minute_quality_1h"] = {(k or "clean"): n for k, n in rows}
except Exception as e:                       # پایگاه قفل یا غایب: خلاصه بدونِ آن
    out["db_error"] = type(e).__name__
print(json.dumps(out, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
PY
)" || { echo "wg-nqmo-review: خلاصه ساخته نشد" >&2; exit 1; }

if [ "${NR_DRY_RUN:-0}" = "1" ]; then
  echo "$summary"
  exit 0
fi

mkdir -p "$OUT" || exit 1
gzip -c "$STATE_DIR/state.json" > "$OUT/state-$STAMP.json.gz.tmp" && \
  mv -f "$OUT/state-$STAMP.json.gz.tmp" "$OUT/state-$STAMP.json.gz"
echo "$summary" >> "$OUT/summary.jsonl"
# هرس: نسخه‌های ساعتیِ کهنه؛ summary.jsonl کوچک است (~۱KB در ساعت) و هرس نمی‌شود
find "$OUT" -name 'state-*.json.gz' -mtime +"$KEEP" -delete 2>/dev/null
echo "wg-nqmo-review: state-$STAMP.json.gz + summary ($(wc -l < "$OUT/summary.jsonl") خط)"
