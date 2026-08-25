#!/usr/bin/env bash
set -euo pipefail
FND="${CYP_FINDINGS_FILE:-/cyp/findings.ndjson}"
OUT="${CYP_FINDINGS_OUT:-/cyp/findings.json}"
if [ ! -s "$FND" ]; then
  echo "[]" > "$OUT"
  echo "compile_findings: no input"
  exit 0
fi
jq -s '''[.[] | select(type=="object")] | unique_by(.title + "|" + (.endpoint // "") + "|" + .severity)''' "$FND" 2>/dev/null > "$OUT" || echo "[]" > "$OUT"
COUNT=$(jq length "$OUT" 2>/dev/null || echo 0)
echo "compile_findings: $COUNT findings"
