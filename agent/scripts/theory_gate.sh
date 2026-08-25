#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"; HOST="${2:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "THEORY-GATE: NO_SURFACE"; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

OPEN=$(jq -r --arg h "$HOST" '
  [ .theory.open_questions[]? | select((.state//"open")=="open")
    | select($h=="" or ((.q//"")|ascii_downcase|contains($h|ascii_downcase)) or ((.host//"")==$h)) ] | length
' "$SURF" 2>/dev/null || echo 0)
OPEN="${OPEN:-0}"

if [[ "$OPEN" -gt 0 ]]; then
  echo "THEORY: INCOMPLETE — $OPEN açık teori sorusu${HOST:+ ($HOST)}. Avcı bunları cevaplamadan yüzey tükenmedi."
  jq -r --arg h "$HOST" '[.theory.open_questions[]?|select((.state//"open")=="open")
    |select($h=="" or ((.q//"")|ascii_downcase|contains($h|ascii_downcase)))][0:5][]
    | "  • ["+(.boundary//"?")+"] "+.q' "$SURF" 2>/dev/null || true
  exit 10
fi
echo "THEORY: COMPLETE — teori soruları kapalı${HOST:+ ($HOST)}."
exit 0
