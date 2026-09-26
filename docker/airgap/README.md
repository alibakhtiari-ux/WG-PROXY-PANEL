<div dir="rtl">

# ساختِ بسته‌ی آفلاینِ نسخه‌ی Docker (سمتِ build-host)

این پوشه «کارخانه‌ی» بسته‌ی آفلاین است؛ خودِ بسته‌ی خروجی در `dist/` ساخته
می‌شود (gitignore) و راهنمای **مصرفش** `README-OFFLINE.md` است که داخلِ بسته
می‌رود. برخلافِ `airgap/*` (نسخه‌ی systemd) به build-host ِ اوبونتویی نیاز
نیست — closure ِ .debها داخلِ کانتینرِ `ubuntu:24.04` با معماریِ «هدف» بسته
می‌شود، پس همین مک با OrbStack کافی است.

## ساخت

```bash
bash build-offline-bundle.sh
```

پیش‌فرض: `--arch amd64` (سرورِ معمول) + مخزنِ آفلاینِ docker + tarball.
گزینه‌ها: `--arch arm64` · `--no-debs` (میزبانِ هدف docker دارد) · `--no-tar`.

خروجی: `dist/wg-panel-docker-airgap-<12hex>-<arch>.tar.gz` — نسخه همان
۱۲ رقمِ اولِ SHA-256 ِ `wg_panel.py` است و تگِ ایمیجِ داخلِ بسته هم همان است.

## چرا اینجا «بسته‌ی کهنه» کم‌خطرتر از online/airgap ِ قدیمی است

- اسکریپت **اول گیتِ تست** را می‌زند (`test_docker_bundle` +
  `test_docker_airgap`) و ایمیج را همان لحظه از `wg_panel.py` کانونی می‌سازد؛
  هیچ کپیِ دومی در مخزن نگه‌داری نمی‌شود که بی‌نگهبان بپوسد.
- کهنگیِ بسته‌ی «جداشده» ذاتیِ هر بسته‌ی آفلاین است (rebuild-drill)؛ اینجا
  `VERSION` داخلِ tarball و تگِ ایمیج و `/opt/wg-panel/VERSION` داخلِ کانتینر
  هر سه یکی‌اند، پس سنِ بسته همیشه قابلِ استعلام است.

## سدِ نشت

فقط فایل‌های `bundle-files.txt` عیناً واردِ بسته می‌شوند (نصاب، verify،
README آفلاین، `.env.example`) + تولیدی‌ها (compose تبدیل‌شده، ایمیج، apt).
هیچ سند/اسکیل/تاریخچه‌ای از مخزن به بسته نمی‌رود — هم build script این را
enforce می‌کند (گاردِ `find`) هم `tests/test_docker_airgap.py`.

</div>
