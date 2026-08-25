#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"; CJSON="${2:-}"
[[ -z "$SURF" || -z "$CJSON" ]] && { echo "KULLANIM: anomaly_scan.sh <surface.json> <cyp_json>" >&2; exit 2; }
[[ -f "$SURF" && -f "$CJSON" ]] || { echo "HATA: dosya yok" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

PROG="$(mktemp)"
cat > "$PROG" <<'JQ'
def host_of: (.host // ((.url//"")|(capture("^https?://(?<x>[^:/?#]+)")? // {x:""}).x));
def path_of: (.url//"")|sub("^https?://[^/]+";"")|sub("\\?.*$";"");
def parent(p): (p|sub("/[^/]*$";"")|if .=="" then "/" else . end);
def st: (.statusCode // .status // 0)|tonumber? // 0;
def tm: (.time // .duration // .ms // .responseTime // 0)|tonumber? // 0;

[ (.requests // .) | (if type=="array" then .[] else . end) ] as $R
# 1) sibling-status tutarsızlığı
| ( [ $R[] | {h:host_of, par:parent(path_of), s:st} ]
    | group_by(.h+"|"+.par)
    | map(select((map(.s)|any(. == 401 or . == 403)) and (map(.s)|any(. == 200))))
    | map({host:.[0].h, par:.[0].par}) ) as $sib
# 2) timing outlier (host bazında, >=4 istek varsa)
| ( [ $R[] | select(tm>0) | {h:host_of, p:path_of, t:tm} ]
    | group_by(.h)
    | map(select(length>=4))
    | map( (map(.t)|add/length) as $avg | .[] | select(.t > ($avg*3) and $avg>0) | {host:.h, path:.p, t:.t, avg:$avg}) ) as $tim
# 3) internal-field sızıntısı
| ( [ $R[] | {h:host_of, p:path_of, b:(.respBody // .responseBody // .body // "")}
        | select(.b|test("\"(is_)?admin\"\\s*:\\s*true|\"debug\"\\s*:\\s*true|\"internal\"\\s*:\\s*true|\"role\"\\s*:\\s*\"admin\"|\"is_staff\"\\s*:\\s*true";"i"))
        | {host:.h, path:.p} ] ) as $leak
| ( [ ($sib[] | {host:.host, param:"", class:"anomaly", impact:4, intent:("sibling-auth "+.par),
        angle:("ANOMALI: "+.host+" "+.par+" altinda bir kardesi 401/403 verirken digeri 200 — auth tutarsizligi, BFLA/erisim bosluğu dene."), state:"open", priority_boost:true}),
      ($tim[] | {host:.host, param:"", class:"anomaly", impact:3, intent:("timing "+.path),
        angle:("ANOMALI: "+.host+.path+" yanit suresi cok sapti (~"+(.t|floor|tostring)+"ms vs ort "+(.avg|floor|tostring)+"ms) — farkli kod yolu/blind enjeksiyon ipucu."), state:"open", priority_boost:true}),
      ($leak[] | {host:.host, param:"", class:"anomaly", impact:4, intent:("leak "+.path),
        angle:("ANOMALI: "+.host+.path+" yanitinda ic alan (admin/debug/internal/role) sizdi — yetki/ifsa zinciri dene."), state:"open", priority_boost:true}) ] ) as $cands
| $cands
JQ

CANDS="$(jq -c -f "$PROG" "$CJSON" 2>/dev/null || echo '[]')"
[[ -z "$CANDS" || "$CANDS" == "null" ]] && CANDS='[]'
jq --argjson c "$CANDS" '.hypotheses = ((.hypotheses // []) + ($c // []) | unique_by(.angle))' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
rm -f "$PROG"

N=$(jq '[.hypotheses[]?|select(.class=="anomaly" and .state=="open")]|length' "$SURF")
echo "ANOMALI TARAMASI: $(jq 'length' <<<"$CANDS") tuhaflik → açık anomaly hipotezi: $N"
jq -r '[.hypotheses[]?|select(.class=="anomaly" and .state=="open")][0:5][] | "  ? "+.angle' "$SURF" 2>/dev/null || true
exit 0
