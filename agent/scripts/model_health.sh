#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; MODEL="${2:-}"; MODE="${3:-}"; ERR="${4:-}"
[[ -z "$SURF" || -z "$MODEL" || -z "$MODE" ]] && { echo "KULLANIM: model_health.sh <surf> <model> <auto|up|down|exhausted|rate> [hata/not]" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
NOW=$(date +%s)
RATE_COOLDOWN="${RATE_COOLDOWN:-120}"; DOWN_COOLDOWN="${DOWN_COOLDOWN:-60}"

STATUS="$MODE"; RETRY_AT=0
if [[ "$MODE" == "auto" ]]; then
  E="$(printf '%s' "$ERR" | tr '[:upper:]' '[:lower:]')"
  if   printf '%s' "$E" | grep -qE 'quota|free.?(usage|tier|limit)|exhaust|insufficient|balance|payment|402|out of credit|no credit|billing|subscription|upgrade'; then STATUS="exhausted"
  elif printf '%s' "$E" | grep -qE 'rate.?limit|429|too many|throttl|slow down'; then STATUS="rate"; RETRY_AT=$((NOW+RATE_COOLDOWN))
  elif printf '%s' "$E" | grep -qE '5[0-9][0-9]|timeout|timed out|unavailable|overload|capacity|temporar'; then STATUS="down"; RETRY_AT=$((NOW+DOWN_COOLDOWN))
  else STATUS="down"  # tanınmayan → kalıcı-benzeri (retry_at=0)
  fi
elif [[ "$MODE" == "rate" ]]; then RETRY_AT=$((NOW+RATE_COOLDOWN))
fi

jq --arg m "$MODEL" --arg s "$STATUS" --arg e "$ERR" --argjson now "$NOW" --argjson ra "$RETRY_AT" '
  .run //= {} | .run.model_health //= {}
  | .run.model_health[$m] = {
      status: $s,
      retry_at: $ra,
      failures: ((.run.model_health[$m].failures // 0) + (if $s=="up" then 0 else 1 end)),
      last_error: (if $e=="" then (.run.model_health[$m].last_error // "") else $e end),
      ts: $now }
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

case "$STATUS" in
  up)        echo "✓ MODEL [$MODEL] → up";;
  exhausted) echo "✓ MODEL [$MODEL] → EXHAUSTED (kota/ödeme bitti) — bu koşu ATLA. model_pick sıradaki (paralı/çalışan) modeli verir.";;
  rate)      echo "✓ MODEL [$MODEL] → rate-limit (geçici, $((RETRY_AT-NOW))sn sonra tekrar uygun). Şimdilik sıradakiyle devam.";;
  *)         echo "✓ MODEL [$MODEL] → down${RETRY_AT:+ (retry $((RETRY_AT-NOW))sn)}. model_pick sıradakini verir.";;
esac
