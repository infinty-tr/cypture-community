#!/usr/bin/env bash
set -uo pipefail
SURF="${1:?kullanım: shard_hosts.sh <surface.json> [num_shards]}"
N="${2:-${CYP_MAX_SHARDS:-2}}"
[ "$N" -ge 1 ] 2>/dev/null || N=2
[ -f "$SURF" ] || { echo "HATA: surface yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

OUT="$(dirname "$SURF")/shards"; mkdir -p "$OUT"; rm -f "$OUT"/shard_*.txt 2>/dev/null || true

HOSTS=$(jq -r '[.assets[]? | select((.live // true) != false) | .host] // [] | .[]' "$SURF" 2>/dev/null | awk 'NF')
URLS="$(dirname "$SURF")/urls.txt"
if [ -s "$URLS" ]; then
  EXTRA=$(sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##' "$URLS" | awk 'NF')
  HOSTS=$(printf '%s\n%s\n' "$HOSTS" "$EXTRA")
fi
HOSTS=$(printf '%s\n' "$HOSTS" | awk 'NF' | sort -u)
[ -z "$HOSTS" ] && { echo "UYARI: surface'te host yok — shard üretilmedi"; exit 0; }

CROWN='auth|admin|api|upload|login|panel|sso|account|pay|portal|manage|dashboard|internal|vpn|git|jenkins|cpanel|webmail|mail'
ORDERED=$( { printf '%s\n' "$HOSTS" | grep -iE "$CROWN"; printf '%s\n' "$HOSTS" | grep -ivE "$CROWN"; } | awk 'NF' )

i=0
while IFS= read -r h; do
  [ -z "$h" ] && continue
  idx=$(( i % N + 1 ))
  printf '%s\n' "$h" >> "$OUT/shard_${idx}.txt"
  i=$((i+1))
done <<< "$ORDERED"

NS=$(ls "$OUT"/shard_*.txt 2>/dev/null | wc -l | tr -d ' ')
echo "SHARD: $i canlı host → $NS shard ($OUT/shard_*.txt)"
for f in "$OUT"/shard_*.txt; do [ -f "$f" ] && echo "  $(basename "$f"): $(wc -l < "$f" | tr -d ' ') host"; done
