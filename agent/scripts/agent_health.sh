#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: agent_health.sh <surface.json>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TTL="${AGENT_TTL:-600}"; NOW=$(date +%s)

STALE=$(jq -c --argjson now "$NOW" --argjson ttl "$TTL" '
  [ .agents[]? | select(.status=="running" and (($now - ((.last_heartbeat // .assigned_at // 0))) > $ttl)) ]
' "$SURF" 2>/dev/null || echo "[]")
CNT=$(jq 'length' <<<"$STALE")

if [[ "${CNT:-0}" -eq 0 ]]; then
  echo "WATCHDOG: tüm ajanlar canlı (TTL=${TTL}sn). stale=0."
  exit 0
fi

STALE_IDS=$(jq -c '[.[].task_id]' <<<"$STALE")
jq --argjson ids "$STALE_IDS" '
  (.agents[]? | select(.task_id as $t | $ids|index($t)) | .status) = "stale"
  | (.assets[]? | select((.assigned_to // "") as $t | $t!="" and ($ids|index($t))) | .assigned_to) = ""
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

echo "WATCHDOG: $CNT stale ajan kurtarıldı (TTL=${TTL}sn aşıldı). Kiralar serbest → host'lar re-queue."
while IFS= read -r row; do
  [[ -z "$row" ]] && continue
  TID=$(jq -r '.task_id' <<<"$row")
  HOSTS=$(jq -r '.hosts | join(" ")' <<<"$row")
  MODEL=$(bash "$ROOT/scripts/model_pick.sh" "$SURF" any 2>/dev/null || echo "NONE")
  echo "CANCEL: $TID"
  echo "RESPAWN: $HOSTS model=$MODEL"
done < <(jq -c '.[]' <<<"$STALE")
[[ "$(bash "$ROOT/scripts/model_pick.sh" "$SURF" any 2>/dev/null || echo NONE)" == "NONE" ]] && \
  echo "UYARI: healthy model YOK — respawn edemezsin; decide_next STOP NO_WORKING_MODEL verecek."
exit 0
