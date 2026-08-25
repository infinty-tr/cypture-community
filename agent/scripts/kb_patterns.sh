#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: kb_patterns.sh <surface.json>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PAT="$ROOT/targets/_knowledge/_global-patterns.md"
[[ -f "$PAT" ]] || { echo "KB-PATTERNS: $PAT yok, atlanıyor."; exit 0; }

ADD=0
while IFS=$'\t' read -r host tech; do
  [[ -z "$host" ]] && continue
  techl="$(printf '%s' "$tech" | tr '[:upper:]' '[:lower:]')"
  while IFS= read -r line; do
    line="${line%%$'\r'}"
    [[ "$line" == \#* || -z "${line// }" ]] && continue
    [[ "$line" != *"=>"* ]] && continue
    re="${line%%=>*}"; re="$(echo "$re" | xargs)"
    rest="${line#*=>}"; cls="$(echo "${rest%%::*}" | xargs)"; ang="$(echo "${rest#*::}" | xargs)"
    [[ -z "$re" || -z "$cls" ]] && continue
    printf '%s' "$techl" | grep -qiE "$re" || continue
    jq --arg h "$host" --arg c "$cls" --arg a "KB-PATTERN: $ang" '
      .hypotheses = (.hypotheses // [])
      | if any(.hypotheses[]?; .host==$h and .class==$c and (.id|startswith("h-kbpat"))) then .
        else .hypotheses += [{id:("h-kbpat-"+$h+"-"+$c), host:$h, param:"", class:$c, angle:$a, state:"open", priority_boost:true}] end
    ' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    ADD=$((ADD+1))
  done < "$PAT"
done < <(jq -r '.assets[]? | select((.tech//[])|length>0) | [.host, ((.tech//[])|join(" "))] | @tsv' "$SURF")

echo "KB-PATTERNS: $ADD önsel hipotez eklendi (tech→öncelik). Bunlar NEREYE bakılacağını söyler, kanıt değildir."
exit 0
