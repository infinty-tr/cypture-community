#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; TID="${2:-}"; shift 2 || true
[[ -z "$SURF" || -z "$TID" || -z "${1:-}" ]] && { echo "KULLANIM: assign_agent.sh <surface.json> <task_id> <host> [host...]" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
NOW=$(date +%s)
HOSTS_JSON=$(printf '%s\n' "$@" | jq -R . | jq -cs .)

jq --arg t "$TID" --argjson hs "$HOSTS_JSON" --argjson now "$NOW" '
  .agents //= []
  | .agents = ((.agents | map(select(.task_id != $t))) + [{
      task_id:$t, hosts:$hs, assigned_at:$now, last_heartbeat:$now, status:"running"}])
  | reduce $hs[] as $h (.;
      (.assets[]? | select(.host==$h) | .assigned_to) = $t
      | (.assets[]? | select(.host==$h) | .assigned_at) = $now )
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
echo "✓ KİRALANDI: task=$TID hosts=$* (lease@$NOW). coverage_status bunları yeni-parti'den dışlar."
