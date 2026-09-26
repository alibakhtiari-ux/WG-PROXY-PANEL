#!/bin/bash
# شیمِ journalctl — پنل بعد از شکستِ start/stop تونل، ۸ خطِ آخرِ ژورنالِ
# یونیت را می‌خواهد. اینجا ژورنال همان لاگ‌فایلی است که شیمِ systemctl برای
# هر یونیت در /var/log/wg-panel/units/ می‌نویسد.
set -u

LOGDIR=/var/log/wg-panel/units
unit=""
lines=10

while [ $# -gt 0 ]; do
    case "$1" in
        -u) unit="${2:-}"; shift 2 ;;
        -n) lines="${2:-10}"; shift 2 ;;
        *)  shift ;;
    esac
done

unit="${unit%.service}"
f="$LOGDIR/${unit}.log"
if [ -n "$unit" ] && [ -f "$f" ]; then
    tail -n "$lines" "$f"
fi
exit 0
