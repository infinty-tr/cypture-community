#!/usr/bin/env bash
set -u

TARGET="${1:-${CYP_TARGET:-}}"
CYP="${CYP_WEB_FEED:-/cyp}"
[ -z "$TARGET" ] && exit 0
command -v nuclei >/dev/null 2>&1 || exit 0
command -v jq >/dev/null 2>&1 || exit 0

case "$TARGET" in
  http://*|https://*) URLS=(-u "$TARGET") ;;
  *)                  URLS=(-u "http://$TARGET" -u "https://$TARGET") ;;
esac

mkdir -p "$CYP"

XARGS=()
[ -n "${CYP_NUCLEI_EXCLUDE_TAGS:-}" ] && XARGS=(-exclude-tags "$CYP_NUCLEI_EXCLUDE_TAGS")
timeout "${CYP_NUCLEI_MAXSEC:-600}" \
nuclei "${URLS[@]}" "${XARGS[@]}" -jsonl -silent -no-color \
       -severity "${CYP_NUCLEI_SEVERITY:-info,low,medium,high,critical}" \
       -c "${CYP_NUCLEI_CONC:-50}" -rate-limit "${CYP_NUCLEI_RL:-150}" \
       -bulk-size 32 -timeout 8 -retries 1 2>/dev/null | \
while IFS= read -r line; do
  [ -z "$line" ] && continue
  printf '%s\n' "$line" | jq -c '{
    title:      (.info.name // "Otomatik tarama bulgusu"),
    severity:   (.info.severity // "info"),
    vuln_type:  ((.info.tags // []) | if type=="array" then (join(", ")) else (.|tostring) end),
    endpoint:   (."matched-at" // .host // .url // ""),
    method:     (.type // "http"),
    evidence:   (((."matcher-name" // "") + " " + (((."extracted-results" // []) | if type=="array" then join(", ") else (.|tostring) end))) | gsub("^ +| +$";"")),
    confidence: "medium",
    verified:   false
  }' 2>/dev/null
done >> "$CYP/findings.ndjson"
