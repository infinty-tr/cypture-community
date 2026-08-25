#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"; CJSON="${2:-}"; THRESH="${3:-10}"
[[ -z "$SURF" || -z "$CJSON" ]] && { echo "KULLANIM: budget_guard.sh <surface.json> <cyp_json> [eşik]" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
[[ -f "$CJSON" ]] || { echo "HATA: cypture json yok: $CJSON" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

read -r TOTAL N429 <<<"$(jq -r '
  [ (.requests // .) | .[] ] as $r
  | [ ($r|length),
      ([ $r[] | select(((.statusCode // .status // 0)|tostring)=="429") ]|length) ] | @tsv' "$CJSON")"
RETRY=$(jq -r '[ (.requests // .) | .[] | (.respHeaders // .responseHeaders // .headers // "") | tostring | select(test("[Rr]etry-[Aa]fter"))]|length' "$CJSON" 2>/dev/null || echo 0)
TOTAL="${TOTAL:-0}"; N429="${N429:-0}"; RETRY="${RETRY:-0}"

THROTTLE="false"
if [[ "$N429" -ge "$THRESH" || "$RETRY" -ge "$THRESH" ]]; then THROTTLE="true"; fi

ASSET_COUNTS=$(jq -c '
  [ (.requests // .) | .[] | . as $req
    | ((($req.host // "") | if .!="" then . else (($req.url//"")|(capture("^https?://(?<x>[^:/?#]+)")? // {x:""}).x) end) | ascii_downcase) ]
  | group_by(.) | map({host:.[0], n:length}) ' "$CJSON" 2>/dev/null || echo "[]")

jq --argjson tot "$TOTAL" --arg thr "$THROTTLE" --argjson ac "$ASSET_COUNTS" '
  .run.budget_spent = $tot
  | .run.throttle = ($thr=="true")
  | reduce $ac[] as $a (.;
      (.assets[] | select(.host==$a.host) | .budget_spent) = $a.n )
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

BMAX=$(jq -r '.run.budget_max // 0' "$SURF")
echo "BÜTÇE: harcanan=$TOTAL/$BMAX  429=$N429  retry_after=$RETRY  throttle=$THROTTLE"
[[ "$THROTTLE" == "true" ]] && echo "  ⚠️ THROTTLE açık — test ajanları yavaşlasın / agresif sınıfları durdursun (WAF/rate-limit)."
if [[ "$TOTAL" -ge "$BMAX" && "$BMAX" -gt 0 ]]; then
  echo "  ⛔ BÜTÇE DOLDU — decide_next.sh → STOP BUDGET_EXHAUSTED verecek."
fi
exit 0
