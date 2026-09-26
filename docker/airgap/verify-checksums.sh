#!/usr/bin/env bash
# verify-checksums.sh — یکپارچگیِ بسته‌ی آفلاینِ Docker را با
# manifests/checksums.sha256 می‌سنجد. کدِ خروجِ غیرصفر = عدمِ تطابق
# (install.sh پیش از هر کاری همین را اجرا می‌کند — همان قراردادِ airgap/*).
set -Eeuo pipefail
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUMS="${_SELF_DIR}/manifests/checksums.sha256"
[ -f "${SUMS}" ] || { echo "checksums.sha256 نیست: ${SUMS}" >&2; exit 2; }
cd "${_SELF_DIR}"
if sha256sum -c --quiet --strict "manifests/checksums.sha256" 2>/dev/null \
   || shasum -a 256 -c "manifests/checksums.sha256" >/dev/null 2>&1; then
    echo "✓ یکپارچگیِ همه‌ی فایل‌های بسته تأیید شد."
else
    echo "✗ عدمِ تطابقِ checksum — بسته ناقص/دستکاری‌شده است." >&2
    exit 1
fi
