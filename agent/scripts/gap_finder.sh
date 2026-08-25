#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: gap_finder.sh <surface.json>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

PROG="$(mktemp)"
cat > "$PROG" <<'JQ'
def parent(p): (p|sub("/[^/]*$";"")|if .=="" then "/" else . end);
[ .endpoints[]? | {host:.host, path:(.path//""), method:(.method//"GET"), auth:(.auth_required)} ] as $E
# 1) method-authz boşluğu (aynı host+path, auth_required farkli: biri true digeri false)
| ( $E | group_by(.host+"|"+.path)
    | map(select((map(.auth)|any(.==true)) and (map(.auth)|any(.==false))))
    | map({host:.[0].host, path:.[0].path}) ) as $ma
# 2) version-drift: ayni suffix v1 ve v2
| ( [ $E[] | select(.path|test("/v[0-9]/")) | {host:.host, suf:(.path|sub("/v[0-9]/";"/")), v:(.path|capture("/v(?<n>[0-9])/").n)} ]
    | group_by(.host+"|"+.suf) | map(select((map(.v)|unique|length)>1))
    | map({host:.[0].host, suf:.[0].suf}) ) as $vd
# 3) mixed-auth sibling (ayni parent, bazi auth bazi degil)
| ( $E | map(. + {par:parent(.path)}) | group_by(.host+"|"+.par)
    | map(select(length>1 and (map(.auth)|any(.==true)) and (map(.auth)|any(.==false or .==null))))
    | map({host:.[0].host, par:.[0].par}) ) as $sb
| ( [ ($ma[] | {host:.host, param:"", class:"gap", impact:5, intent:("method-authz "+.path),
        angle:("BOSLUK: "+.host+.path+" — bir method auth/sahiplik isterken digeri istemiyor. Zayif method ile (PUT/DELETE/PATCH) sahiplik atla."), state:"open", priority_boost:true}),
      ($vd[] | {host:.host, param:"", class:"gap", impact:4, intent:("version-drift "+.suf),
        angle:("BOSLUK: "+.host+" "+.suf+" hem v1 hem v2 var — eski surum authz/validasyonu v2 kadar zorlamiyor olabilir, /v1 ile dene."), state:"open", priority_boost:true}),
      ($sb[] | {host:.host, param:"", class:"gap", impact:4, intent:("mixed-auth "+.par),
        angle:("BOSLUK: "+.host+.par+" altinda bazi endpoint auth isterken bazisi istemiyor — korumasizi pivota kullan."), state:"open", priority_boost:true}) ] )
JQ

CANDS="$(jq -c -f "$PROG" "$SURF" 2>/dev/null || echo '[]')"
[[ -z "$CANDS" || "$CANDS" == "null" ]] && CANDS='[]'
jq --argjson c "$CANDS" '.hypotheses = ((.hypotheses // []) + ($c // []) | unique_by(.angle))' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
rm -f "$PROG"

N=$(jq '[.hypotheses[]?|select(.class=="gap" and .state=="open")]|length' "$SURF")
echo "BOSLUK ARAMA: $(jq 'length' <<<"$CANDS") tutarsizlik → açık gap hipotezi: $N"
jq -r '[.hypotheses[]?|select(.class=="gap" and .state=="open")][0:5][] | "  ⚠ "+.angle' "$SURF" 2>/dev/null || true
exit 0
