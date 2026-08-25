#!/usr/bin/env bash
set -uo pipefail
DIR="${1:-}"; PREFIX="${2:-}"
[[ -z "$DIR" ]] && { echo "KULLANIM: cyp_prefix.sh <dir> [prefix]" >&2; exit 2; }
mkdir -p "$DIR" 2>/dev/null || true
F="$DIR/.cyp_prefix"
if [[ -n "$PREFIX" ]]; then
  printf '%s\n' "$PREFIX" > "$F"
  echo "✓ Cypture prefix kaydedildi: $PREFIX → $F (alt ajanlar bunu okur)"
else
  if [[ -f "$F" ]]; then cat "$F"; else echo "" ; echo "(cypture prefix henüz keşfedilmedi — model send_request aracını bulup yazsın)" >&2; exit 1; fi
fi
