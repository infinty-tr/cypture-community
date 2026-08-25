#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"
[[ -z "$SURF" ]] && SURF=$(ls -t targets/*/surface.json 2>/dev/null | head -1 || true)
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "HATA: surface.json yok" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

HI='admin|auth|login|sso|oauth|account|user|payment|pay|checkout|billing|api|gateway|portal|dashboard|internal|dev|staging|test|uat|qa|graphql|upload|file|secure|vpn|git|jenkins|jira|confluence'
MED='app|my|secure|shop|store|order|cart|profile|member|partner|service|mobile|m\.'

jq --arg hi "$HI" --arg med "$MED" '
  .assets |= map(
    .host as $h
    | .priority = (
        if ($h | test($hi)) then "high"
        elif ($h | test($med)) then "medium"
        else "low" end)
  )
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

echo "✓ önceliklendirildi: $SURF"
jq -r '"  high="+([.assets[]|select(.priority=="high")]|length|tostring)
      +"  medium="+([.assets[]|select(.priority=="medium")]|length|tostring)
      +"  low="+([.assets[]|select(.priority=="low")]|length|tostring)' "$SURF"
