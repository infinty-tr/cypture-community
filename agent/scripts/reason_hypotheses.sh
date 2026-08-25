#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; HOST="${2:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: reason_hypotheses.sh <surface.json> [host]" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

PROG="$(mktemp)"
cat > "$PROG" <<'JQ'
def b2class(b): if (b|test("business")) then "business_logic" elif (b|test("auth$|^auth")) then "auth_session" else "authz" end;
. as $root
| ($root.theory // {}) as $t
| .hypotheses //= []
| ( [ ($t.open_questions[]? | select((.state//"open")=="open")
        | {host:$host, param:"", class:b2class(.boundary//""), intent:(.q), impact:(.impact//3),
           angle:("TEORI-SORUSU: "+(.q)), state:"open", priority_boost:true}),
      ($t.trust_boundaries[]? as $b | $t.critical_flows[]? as $f
        | {host:$host, param:"", class:"authz", intent:($b.name+" x "+$f.name), impact:($b.weight//4),
           angle:("SINIR x AKIS: "+$b.name+" sinirini "+$f.name+" akisinda asabilir miyim? (kontrol: "+($b.control//"?")+")"),
           state:"open", priority_boost:true}),
      ($t.critical_flows[]? as $f | ($f.assumptions[]? )
        | {host:$host, param:"", class:"business_logic", intent:($f.name+": "+.), impact:5,
           angle:("VARSAYIM IHLALI ["+$f.name+"]: '"+.+"' varsayimini boz (negatif/eksik/replay/race/birim)."),
           state:"open", priority_boost:true}) ] ) as $cands
| .hypotheses += ( $cands | map(select(.angle as $a | ($root.hypotheses | any(.angle==$a)) | not))
                          | unique_by(.angle) )
JQ

jq --arg host "$HOST" -f "$PROG" "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
rm -f "$PROG"

N=$(jq -r '[.hypotheses[]?|select(.priority_boost==true and (.intent|type=="string"))]|length' "$SURF")
echo "NIYET HIPOTEZLERI uretildi (teoriden) → açık hipotez toplam: $(jq '[.hypotheses[]?|select(.state=="open")]|length' "$SURF")"
jq -r '[.hypotheses[]?|select(.state=="open" and (.intent//"")!="")] | sort_by(-(.impact//0))[0:6][] | "  - [x"+((.impact//0)|tostring)+" "+.class+"] "+.angle' "$SURF" 2>/dev/null || true
echo "  (score_hypotheses bunları iş-etkisine göre generic xss/coverage'in ustunde siralar.)"
