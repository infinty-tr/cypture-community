#!/usr/bin/env bash
set -uo pipefail
STATE=/cyp/state.json
cmd="${1:-}"; wave="${2:-}"; note="${3:-}"
command -v jq >/dev/null || exit 0
[ -f "$STATE" ] || echo '{"waves":[],"updated":0}' > "$STATE" 2>/dev/null || exit 0
TS=$(date +%s)
FCNT=$([ -f /cyp/findings.ndjson ] && grep -c '"title"' /cyp/findings.ndjson 2>/dev/null || echo 0)
case "$cmd" in
  record)
    jq --arg w "$wave" --arg n "$note" --argjson ts "$TS" --argjson fc "${FCNT:-0}" \
       '.waves += [{"wave":$w,"note":$n,"status":"running","ts":$ts,"findings":$fc}] | .updated=$ts' \
       "$STATE" > "$STATE.tmp" 2>/dev/null && mv "$STATE.tmp" "$STATE" || rm -f "$STATE.tmp" ;;
  done)
    jq --arg w "$wave" --argjson ts "$TS" --argjson fc "${FCNT:-0}" \
       '(.waves[] | select(.wave==$w and .status=="running") | .status) = "done"
        | (.waves[] | select(.wave==$w) | .findings) = $fc | .updated=$ts' \
       "$STATE" > "$STATE.tmp" 2>/dev/null && mv "$STATE.tmp" "$STATE" || rm -f "$STATE.tmp" ;;
  *) echo "KULLANIM: wave_state.sh record|done <wave> [note]" >&2; exit 2 ;;
esac
echo "state[$cmd]: $wave (bulgu=$FCNT)"
