#!/usr/bin/env bash
set -uo pipefail
HOST="${2:-ALL}"
echo "=== PAYLAŞILAN HAFIZA (peer) — ${HOST} ==="
if [ -s ${CYP_FEED_DIR:-/cyp}/findings.ndjson ]; then
  echo "🔴 ZATEN BULUNDU (peer uzmanlar) — TEKRARLAMA, üstüne ZİNCİRLE:"
  jq -r 'select(.title!=null) | "  - [\(.severity//"?")] \(.vuln_type//"?") @ \(.endpoint//"?") — \(.title)"' ${CYP_FEED_DIR:-/cyp}/findings.ndjson 2>/dev/null | sort -u | head -80
else
  echo "  (henüz peer bulgu yok — ilk koşu, sıfırdan keşfet)"
fi
exit 0
