#!/usr/bin/env bash
# build-offline-bundle.sh — ساختِ بسته‌ی آفلاینِ نسخه‌ی Docker، روی ماشینی که
# اینترنت و docker دارد (همین مک با OrbStack کافی است). خروجی برای اوبونتوی
# ۲۴.۰۴ «بدونِ اینترنت» است.
#
# تفاوت با airgap/*/scripts/build-offline-bundle.sh (نسخه‌ی systemd):
#   • به build-host ِ اوبونتویی نیاز ندارد — closure ِ .debها داخلِ کانتینرِ
#     ubuntu:24.04 با معماریِ «هدف» بسته می‌شود، پس روی macOS هم معتبر است.
#   • هیچ کپیِ دومی از wg_panel.py در کار نیست: ایمیج همین‌جا از ریشه‌ی مخزن
#     بیلد و با تگِ نسخه (۱۲ رقمِ هش) ذخیره می‌شود.
#
# استفاده:
#   ./build-offline-bundle.sh                 # amd64 (سرورِ معمول) + debها + tar
#   ./build-offline-bundle.sh --arch arm64    # هدفِ arm64
#   ./build-offline-bundle.sh --no-debs       # بدونِ مخزنِ آفلاینِ docker
#                                             #   (وقتی میزبانِ هدف docker دارد)
#   ./build-offline-bundle.sh --no-tar        # فقط stage، بدونِ tarball
set -Eeuo pipefail

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${_SELF_DIR}/../.." && pwd)"
DIST="${_SELF_DIR}/dist"

log() { printf '\033[34m[build]\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m[ ok ]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

ARCH=amd64
WITH_DEBS=1
MAKE_TAR=1
while [ $# -gt 0 ]; do
    case "$1" in
        --arch)    ARCH="${2:?}"; shift 2 ;;
        --no-debs) WITH_DEBS=0; shift ;;
        --no-tar)  MAKE_TAR=0; shift ;;
        *) die "آرگومانِ ناشناخته: $1" ;;
    esac
done
case "$ARCH" in amd64|arm64) ;; *) die "معماری فقط amd64 یا arm64 — نه «$ARCH»";; esac

# بسته‌هایی که میزبانِ آفلاین برای اجرای compose لازم دارد — فقط همین‌ها؛
# بقیه (wireguard-tools، fail2ban، squid، …) داخلِ خودِ ایمیج‌اند.
TARGET_PACKAGES=(docker.io docker-compose-v2)

command -v docker >/dev/null 2>&1 || die "docker روی build-host نیست."
docker info >/dev/null 2>&1 || die "دیمنِ docker بالا نیست."

# ---------- ۰) گیتِ تست — بسته‌ی کهنه/شکسته اصلاً ساخته نشود ----------
log "گیتِ تست: tests/test_docker_bundle + tests/test_docker_airgap"
( cd "${REPO_ROOT}" && python3 -m unittest -q \
      tests.test_docker_bundle tests.test_docker_airgap ) \
    || die "تست‌ها قرمزند — اول سبزشان کن، بعد بسته بساز."
ok "تست‌ها سبز"

VER="$(shasum -a 256 "${REPO_ROOT}/wg_panel.py" 2>/dev/null | cut -c1-12)"
[ -n "$VER" ] || VER="$(sha256sum "${REPO_ROOT}/wg_panel.py" | cut -c1-12)"
IMAGE_TAG="wg-panel:${VER}"
BUNDLE_NAME="wg-panel-docker-airgap-${VER}-${ARCH}"
STAGE="${DIST}/${BUNDLE_NAME}"

log "نسخه: ${VER} · معماری: ${ARCH} · بسته: ${BUNDLE_NAME}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}/manifests"

# ---------- ۱) بیلدِ ایمیج برای معماریِ هدف، از ریشه‌ی مخزن ----------
log "بیلدِ ایمیج ${IMAGE_TAG} برای linux/${ARCH} …"
docker build --platform "linux/${ARCH}" \
    -t "${IMAGE_TAG}" \
    -f "${REPO_ROOT}/docker/Dockerfile" "${REPO_ROOT}" \
    || die "بیلدِ ایمیج شکست خورد."
# معماریِ واقعیِ ایمیج را بسنج — نه فرض
_img_arch="$(docker image inspect --format '{{.Architecture}}' "${IMAGE_TAG}")"
[ "${_img_arch}" = "${ARCH}" ] \
    || die "معماریِ ایمیجِ ساخته‌شده ${_img_arch} است نه ${ARCH}."
ok "ایمیج ساخته شد (${_img_arch})"

log "ذخیره‌ی ایمیج (docker save + gzip)…"
docker save "${IMAGE_TAG}" | gzip > "${STAGE}/wg-panel-image-${ARCH}.tar.gz"
ok "ایمیج: $(du -h "${STAGE}/wg-panel-image-${ARCH}.tar.gz" | cut -f1)"

# ---------- ۲) مخزنِ آفلاینِ docker برای میزبانِ هدف ----------
if [ "${WITH_DEBS}" = 1 ]; then
    log "بستنِ closure و دانلودِ .debهای docker داخلِ ubuntu:24.04/${ARCH} …"
    mkdir -p "${STAGE}/apt"
    docker run --rm --platform "linux/${ARCH}" \
        -v "${STAGE}/apt:/out" \
        -e PKGS="${TARGET_PACKAGES[*]}" \
        ubuntu:24.04 bash -Eeuo pipefail -c '
            export DEBIAN_FRONTEND=noninteractive
            [ "$(dpkg --print-architecture)" = "'"${ARCH}"'" ] \
                || { echo "معماریِ کانتینر با هدف نمی‌خواند" >&2; exit 1; }
            apt-get update -qq
            apt-get install -y -qq --no-install-recommends dpkg-dev apt-utils >/dev/null
            # closure = شبیه‌سازیِ نصب روی «وضعیتِ خالی» با حل‌کننده‌ی واقعیِ
            # apt — دقیقاً مجموعه‌ی سیستمِ تازه: یک گزینه از هر alternative،
            # با Pre-Depends، بدونِ تورمِ providerهای مجازی. (سه نسل ایرادِ
            # روشِ قبلی — mawk/\w، ‏--no-pre-depends، تورمِ apt-cache تا ۱۷GB
            # روی jammy — در §۲۹٫۶۶ سند، ۱۱ اوت ۲۰۲۶.)
            apt-get -o Dir::State::status=/dev/null --no-install-recommends \
                -s install $PKGS 2>/dev/null \
              | awk "/^Inst /{print \$2}" | sort -u > /tmp/set.uniq
            n_closure=$(wc -l < /tmp/set.uniq)
            echo "بسته‌ها در closure: ${n_closure}"
            # گاردِ کف: درختِ وابستگیِ docker.io قطعاً ده‌ها بسته است؛ عددِ
            # کوچک یعنی closure دوباره بی‌صدا خالی شده — بلند بمیر.
            [ "${n_closure}" -ge 10 ] \
                || { echo "closure مشکوکاً کوچک است (${n_closure}<10)" >&2; exit 1; }
            cd /out
            while read -r pkg; do
                [ -n "$pkg" ] || continue
                apt-get download "$pkg" 2>/dev/null \
                    || echo "⚠ ${pkg} دانلود نشد (مجازی/بی‌کاندید) — رد شد"
            done < /tmp/set.uniq
            n=$(find . -name "*.deb" | wc -l)
            [ "$n" -gt 0 ] || { echo "هیچ .debی نیامد" >&2; exit 1; }
            dpkg-scanpackages --multiversion . /dev/null > Packages 2>/dev/null
            gzip -9c Packages > Packages.gz
            # Release با hashهای واقعی (apt-ftparchive از apt-utils) تا apt
            # هشدارِ «No Hash entry» ندهد؛ trusted=yes ِ نصاب امضا نمی‌خواهد.
            apt-ftparchive \
                -o APT::FTPArchive::Release::Origin="wg-panel-docker-airgap" \
                -o APT::FTPArchive::Release::Label="wg-panel docker offline" \
                -o APT::FTPArchive::Release::Suite="stable" \
                -o APT::FTPArchive::Release::Codename="noble" \
                -o APT::FTPArchive::Release::Architectures="'"${ARCH}"'" \
                -o APT::FTPArchive::Release::Components="main" \
                release . > Release
            echo "دانلودِ ${n} فایلِ .deb کامل شد"
        ' || die "ساختِ مخزنِ آفلاینِ docker شکست خورد."
    ok "مخزنِ apt: $(find "${STAGE}/apt" -name '*.deb' | wc -l | tr -d ' ') بسته · $(du -sh "${STAGE}/apt" | cut -f1)"
else
    log "--no-debs: مخزنِ آفلاینِ docker رد شد (میزبانِ هدف باید خودش docker داشته باشد)"
fi

# ---------- ۳) فایل‌های بسته — فقط از فهرستِ سفیدِ bundle-files.txt ----------
# (سدِ نشت: هیچ سند/اسکیل/تاریخچه‌ای از مخزن واردِ بسته نمی‌شود؛ تست هم
#  همین فهرست را می‌پاید.)
log "کپیِ فایل‌های بسته از فهرستِ سفید…"
while IFS='|' read -r src dest; do
    case "$src" in ''|'#'*) continue ;; esac
    [ -f "${REPO_ROOT}/${src}" ] || die "منبعِ فهرستِ سفید نیست: ${src}"
    install -m 644 "${REPO_ROOT}/${src}" "${STAGE}/${dest}"
done < "${_SELF_DIR}/bundle-files.txt"
chmod 755 "${STAGE}/install.sh" "${STAGE}/verify-checksums.sh"

log "تولیدِ docker-compose.yml آفلاین (بدونِ build:، ایمیجِ پین‌شده)…"
python3 "${_SELF_DIR}/transform-compose.py" \
    "${REPO_ROOT}/docker/docker-compose.yml" "${IMAGE_TAG}" \
    > "${STAGE}/docker-compose.yml" \
    || die "تبدیلِ compose شکست خورد."

printf '%s\n' "${VER}"  > "${STAGE}/VERSION"
printf '%s\n' "${ARCH}" > "${STAGE}/ARCH"

# ---------- ۴) سدِ نشت (کمربند و بند) ----------
_leak="$(find "${STAGE}" -name '*.html' -o -name 'CLAUDE.md' -o -name 'SKILL.md' \
              -o -path '*/.claude/*' -o -name 'wg_panel.py' | head -5)"
[ -z "${_leak}" ] || die "فایلِ ممنوع داخلِ بسته: ${_leak}"

# ---------- ۵) checksums + tarball ----------
log "ساختِ manifests/checksums.sha256 …"
( cd "${STAGE}"
  find . -type f ! -path './manifests/*' | LC_ALL=C sort | sed 's|^\./||' \
      | xargs shasum -a 256 > manifests/checksums.sha256 2>/dev/null \
      || { find . -type f ! -path './manifests/*' | LC_ALL=C sort | sed 's|^\./||' \
           | xargs sha256sum > manifests/checksums.sha256; } )
ok "checksums: $(wc -l < "${STAGE}/manifests/checksums.sha256" | tr -d ' ') فایل"

if [ "${MAKE_TAR}" = 1 ]; then
    log "بستنِ tarball نهایی…"
    # COPYFILE_DISABLE + --no-xattrs: بدونِ این‌ها bsdtar ِ مک متادیتای
    # xattr (com.apple.provenance/macl) را در هدرهای pax می‌گذارد و GNU tar
    # روی سرورِ لینوکسی برای هر فایل هشدارِ «Ignoring unknown extended
    # header» چاپ می‌کند — بی‌ضرر ولی ترسناک برای اپراتور (دیده‌شده در
    # آزمونِ نصبِ واقعی، ۱۱ اوت ۲۰۲۶).
    ( cd "${DIST}" && COPYFILE_DISABLE=1 tar --no-xattrs -czf \
          "${BUNDLE_NAME}.tar.gz" "${BUNDLE_NAME}" )
    ok "بسته آماده است: dist/${BUNDLE_NAME}.tar.gz ($(du -h "${DIST}/${BUNDLE_NAME}.tar.gz" | cut -f1))"
fi

echo
ok "پایان. روی سرورِ آفلاین: tar -xzf ${BUNDLE_NAME}.tar.gz و سپس"
echo "      cd ${BUNDLE_NAME} && sudo bash install.sh --server-host <IP/دامنه> --up"
