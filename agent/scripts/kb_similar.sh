#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: kb_similar.sh <surface.json>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; KBD="$ROOT/targets/_knowledge"
SELF="$(jq -r '.target // ""' "$SURF")"
[[ -d "$KBD" ]] || { echo "KB-SIMILAR: korpus yok (ilk kosular)."; exit 0; }

firsttok(){ echo "$1" | tr '[:upper:]' '[:lower:]' | grep -oE '[a-z0-9.+_-]+' | head -1; }
mapfile -t MYTECH < <( { jq -r '(.assets[]?.tech[]?), (.run.kb_confirmed_tech[]?), (.theory.developer_profile.stack // "")' "$SURF" 2>/dev/null; } | while read -r t; do firsttok "$t"; done | sort -u | grep -v '^$')
[[ ${#MYTECH[@]} -eq 0 ]] && { echo "KB-SIMILAR: mevcut hedefin tech imzasi yok (once recon/theory_build)."; exit 0; }

PROG="$(mktemp)"; printf '%s\n' "${MYTECH[@]}" > "$PROG"

declare -A SCORE
shopt -s nullglob
BEST=""
for f in "$KBD"/*.json; do
  b="$(basename "$f")"; [[ "$b" == "_mined.json" ]] && continue
  jq -e . "$f" >/dev/null 2>&1 || continue
  tgt="$(jq -r '.target // ""' "$f")"; [[ -z "$tgt" || "$tgt" == "$SELF" ]] && continue
  ov=$(jq -r '.confirmed_tech[]?' "$f" 2>/dev/null | while read -r t; do firsttok "$t"; done | sort -u | grep -Fxf "$PROG" | grep -c . || true)
  [[ "${ov:-0}" -ge 1 ]] && SCORE["$f"]=$ov
done
shopt -u nullglob
rm -f "$PROG"

[[ ${#SCORE[@]} -eq 0 ]] && { echo "KB-SIMILAR: benzer gecmis hedef yok (tech ortusmesi)."; exit 0; }

SIMFILES=$(for f in "${!SCORE[@]}"; do echo "${SCORE[$f]} $f"; done | sort -rn | head -3 | awk '{print $2}')
ADD=0; SKIP=0
for f in $SIMFILES; do
  tgt="$(jq -r '.target' "$f")"
  while IFS=$'\t' read -r cls ep; do
    [[ -z "$cls" ]] && continue
    ang="GECMIS-BENZER ($tgt): $cls${ep:+ @ $ep} burada da cikmisti — ONCE dene (onsel, dogrula)."
    jq --arg c "$cls" --arg a "$ang" '
      .hypotheses = (.hypotheses // [])
      | if any(.hypotheses[]?; .angle==$a) then . else
        .hypotheses += [{id:("h-sim-"+($a|@base64|.[0:8])), host:"", param:"", class:$c, angle:$a,
          impact:4, intent:"gecmis-benzer", state:"open", priority_boost:true}] end
    ' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    ADD=$((ADD+1))
  done < <(jq -r '.known_findings[]? | ((.class // .type // "?"))+"\t"+((.endpoint // ""))' "$f" 2>/dev/null)
  while IFS= read -r d; do [[ -z "$d" ]] && continue
    jq --arg d "GECMIS-TEMIZ ($tgt): $d" '.kb_dead_ends = ((.kb_dead_ends // []) + [$d] | unique)' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    SKIP=$((SKIP+1))
  done < <(jq -r '.dead_ends[]? // empty' "$f" 2>/dev/null)
done

echo "KB-SIMILAR: $(echo "$SIMFILES" | grep -c .) benzer hedef → $ADD oncelikli hipotez (gecmiste bulunan) + $SKIP skip-notu (gecmiste temiz)."
echo "  Benzer: $(for f in $SIMFILES; do jq -r '.target' "$f"; done | tr '\n' ' ')"
jq -r '[.hypotheses[]?|select(.intent=="gecmis-benzer")][0:5][] | "  ↺ "+.angle' "$SURF" 2>/dev/null || true
exit 0
