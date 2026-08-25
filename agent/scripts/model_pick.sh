#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; ROLE="${2:-default}"
[[ -z "$SURF" ]] && { echo "KULLANIM: model_pick.sh <surface.json> <rol|any>" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REG="$ROOT/scripts/data/model_registry.txt"
[[ -f "$REG" ]] || { echo "HATA: model_registry.txt yok" >&2; exit 3; }
NOW=$(date +%s)

eligible() { jq -e --arg m "$1" --argjson now "$NOW" '
  (.run.model_health[$m]) as $h
  | if $h==null then true
    else (if $h.status=="up" then true elif $h.status=="exhausted" then false
          else (($h.retry_at // 0) > 0 and ($h.retry_at <= $now)) end) end' "$SURF" >/dev/null 2>&1; }
cooling() { jq -e --arg m "$1" --argjson now "$NOW" '
  (.run.model_health[$m]) as $h | ($h!=null) and (($h.retry_at // 0) > $now)' "$SURF" >/dev/null 2>&1; }

if [[ "$ROLE" == "any" ]]; then MINCAP=0
else
  MINCAP=$(grep -iE "^R[[:space:]]+${ROLE}([[:space:]]|$)" "$REG" 2>/dev/null | awk '{print $3}' | head -1)
  [[ -z "$MINCAP" ]] && MINCAP=$(grep -iE '^R[[:space:]]+default' "$REG" 2>/dev/null | awk '{print $3}' | head -1)
  MINCAP="${MINCAP:-0}"
fi

ELIG_MEET=""; ELIG_ALL=""; ANY_COOL=0
while read -r tag id free cost cap _; do
  [[ "$tag" != "M" || -z "$id" ]] && continue
  if eligible "$id"; then
    line="$((1-free)) $cost $((5-cap)) $id"          # free→0 önce, ucuz önce, yüksek-cap önce
    ELIG_ALL+="$line"$'\n'
    [[ "${cap:-0}" -ge "$MINCAP" ]] && ELIG_MEET+="$line"$'\n'
  else
    cooling "$id" && ANY_COOL=1
  fi
done < <(grep -E '^M[[:space:]]' "$REG")

POOL="$ELIG_MEET"; [[ -z "${POOL//[$'\n']}" ]] && POOL="$ELIG_ALL"   # min_cap karşılanmıyorsa degrade
if [[ -z "${POOL//[$'\n']}" ]]; then
  [[ "$ANY_COOL" -eq 1 ]] && { echo "WAIT"; exit 2; }
  echo "NONE"; exit 1
fi
printf '%s' "$POOL" | grep -v '^$' | sort -k1,1n -k2,2n -k3,3n | head -1 | awk '{print $4}'
exit 0
