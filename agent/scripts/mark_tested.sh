#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; HOST="${2:-}"; DEPTH="${3:-L1}"
[[ -z "$SURF" || -z "$HOST" ]] && { echo "KULLANIM: mark_tested.sh <surface.json> <host> [depth]" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

NOW=$(date +%s)
jq --arg h "$HOST" --arg d "$DEPTH" --argjson now "$NOW" '
  (.assets[]    | select(.host==$h) | .depth_achieved) = $d
  | (.endpoints[] | select(.host==$h) | .tested) = true
  | (.endpoints[] | select(.host==$h and ((.depth_achieved//"L0")=="L0")) | .depth_achieved) = $d
  | (.agents[]? | select((.hosts // []) | index($h)) | .last_heartbeat) = $now
  | (.assets[]  | select(.host==$h) | .assigned_to) = ""
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
echo "✓ $HOST → depth=$DEPTH (asset + endpoints tested=true; heartbeat tazelendi, kira serbest)"
