#!/usr/bin/env bash
set -o pipefail
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KBD="$ROOT/targets/_knowledge"
PAT="$KBD/_global-patterns.md"; MINED="$KBD/_mined.json"
[[ -d "$KBD" ]] || { echo "KB-MINE: korpus yok ($KBD)"; exit 0; }

declare -A POS NEG TECHRUNS
RUNS=0
firsttok(){ echo "$1" | tr '[:upper:]' '[:lower:]' | grep -oE '[a-z0-9.+_-]+' | head -1; }

shopt -s nullglob
for f in "$KBD"/*.json; do
  [[ "$(basename "$f")" == "_mined.json" ]] && continue
  jq -e . "$f" >/dev/null 2>&1 || continue
  RUNS=$((RUNS+1))
  mapfile -t TECHS < <(jq -r '.confirmed_tech[]?' "$f" 2>/dev/null | while read -r t; do firsttok "$t"; done | sort -u | grep -v '^$')
  mapfile -t FINDS < <(jq -r '.known_findings[]?.class // empty' "$f" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u | grep -v '^$')
  mapfile -t DEADS < <(jq -r '.dead_ends[]? // empty' "$f" 2>/dev/null | grep -oiE 'sqli|xss|ssrf|idor|bola|lfi|rce|ssti|csrf|xxe|jwt|oauth|redirect|injection|upload|business' | tr '[:upper:]' '[:lower:]' | sort -u)
  for t in "${TECHS[@]:-}"; do [[ -z "$t" ]] && continue
    TECHRUNS["$t"]=$(( ${TECHRUNS["$t"]:-0} + 1 ))
    for c in "${FINDS[@]:-}"; do [[ -z "$c" ]] && continue; POS["$t|$c"]=$(( ${POS["$t|$c"]:-0} + 1 )); done
    for c in "${DEADS[@]:-}"; do [[ -z "$c" ]] && continue; NEG["$t|$c"]=$(( ${NEG["$t|$c"]:-0} + 1 )); done
  done
done
shopt -u nullglob

[[ "$RUNS" -eq 0 ]] && { echo "KB-MINE: korpusta islenebilir kayit yok."; exit 0; }

{
  echo "{"; echo "  \"runs\": $RUNS,"
  echo -n "  \"positive\": ["
  first=1; for k in "${!POS[@]}"; do t="${k%%|*}"; c="${k#*|}"; n="${POS[$k]}"; tr_="${TECHRUNS[$t]:-1}"
    [[ $first -eq 0 ]] && echo -n ","; first=0
    printf '{"tech":"%s","class":"%s","found":%s,"of":%s}' "$t" "$c" "$n" "$tr_"
  done; echo "],"
  echo -n "  \"negative\": ["
  first=1; for k in "${!NEG[@]}"; do t="${k%%|*}"; c="${k#*|}"; n="${NEG[$k]}"
    [[ $first -eq 0 ]] && echo -n ","; first=0
    printf '{"tech":"%s","class":"%s","clean":%s}' "$t" "$c" "$n"
  done; echo "]"; echo "}"
} | jq . > "$MINED" 2>/dev/null || echo '{}' > "$MINED"

[[ -f "$PAT" ]] || printf '# _global-patterns.md\n' > "$PAT"
sed '/^# === AUTO-MINED/,$d' "$PAT" > "$PAT.tmp" 2>/dev/null || cp "$PAT" "$PAT.tmp"
{
  echo "# === AUTO-MINED (kb_mine.sh — $RUNS kosudan ampirik, ELLE DUZENLEME) ==="
  for k in "${!POS[@]}"; do
    t="${k%%|*}"; c="${k#*|}"; n="${POS[$k]}"
    [[ "$n" -ge 1 ]] && echo "$t => $c :: AMPIRIK: gecmiste $t uzerinde $c $n kez bulundu — ONCE bunu dene"
  done
} >> "$PAT.tmp"
mv "$PAT.tmp" "$PAT"

echo "KB-MINE: $RUNS kosu tarandi → pozitif oruntu=${#POS[@]} negatif=${#NEG[@]}  ($MINED + _global-patterns.md guncellendi)"
[[ ${#POS[@]} -gt 0 ]] && { echo "  En sik (tech→sinif):"; for k in "${!POS[@]}"; do echo "${POS[$k]} ${k/|/ → }"; done | sort -rn | head -5 | sed 's/^/    /'; }
exit 0
