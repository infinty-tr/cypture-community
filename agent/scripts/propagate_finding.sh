#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; SRCHOST="${2:-}"; CLS="${3:-}"; PARAM="${4:-}"
[[ -z "$SURF" || -z "$SRCHOST" || -z "$CLS" ]] && { echo "KULLANIM: propagate_finding.sh <surface.json> <host> <class> [param]" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

jq --arg sh "$SRCHOST" --arg c "$CLS" --arg p "$PARAM" '
  .hypotheses = (.hypotheses // [])
  | ( if $p != "" then [ .endpoints[]? | select((.params // []) | index($p)) | .host ] | unique else [] end ) as $pp
  | ( [ .assets[]? | select(.host != $sh)
        | select(((.applicable_classes // []) | index($c)))
        | select((((.test_classes // {}) | to_entries | map(select(.value==true)|.key)) | index($c)) | not)
        | .host ] | unique ) as $ch
  | reduce ($pp[]) as $eh (.;
      if any(.hypotheses[]?; .host==$eh and .param==$p and .class==$c) then .
      else .hypotheses += [{id:("h-prop-"+$eh+"-"+$c), host:$eh, param:$p, class:$c,
        angle:("YAYILDI: "+$c+" param "+$p+" "+$sh+" host da DOGRULANDI - burada da dene."),
        state:"open", priority_boost:true}] end)
  | reduce ($ch[]) as $hh (.;
      if any(.hypotheses[]?; .host==$hh and (.param==null or .param=="") and .class==$c) then .
      else .hypotheses += [{id:("h-prop-"+$hh+"-"+$c+"-cls"), host:$hh, param:"", class:$c,
        angle:("YAYILDI: "+$c+" "+$sh+" host da DOGRULANDI - bu hostta da yuksek-oncelikli dene."),
        state:"open", priority_boost:true}] end)
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

NH=$(jq '[.hypotheses[]?|select(.priority_boost==true)]|length' "$SURF")
echo "YAYILDI: '$CLS'${PARAM:+ param=$PARAM} ($SRCHOST doğrulandı) → diğer host/endpoint'lere boost hipotez. Toplam boost: $NH"
