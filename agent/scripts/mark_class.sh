#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; HOST="${2:-}"; CLS="${3:-}"
[[ -z "$SURF" || -z "$HOST" || -z "$CLS" ]] && { echo "KULLANIM: mark_class.sh <surface.json> <host> <sınıf>" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

NOW=$(date +%s)
jq --arg h "$HOST" --arg c "$CLS" --argjson now "$NOW" '
  (.assets[] | select(.host==$h) | .test_classes) //= {}
  | (.assets[] | select(.host==$h) | .test_classes[$c]) = true
  | (.agents[]? | select((.hosts // []) | index($h)) | .last_heartbeat) = $now
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
echo "✓ $HOST × $CLS → yapıldı (heartbeat tazelendi)"
