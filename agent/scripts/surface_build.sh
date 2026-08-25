#!/usr/bin/env bash
set -euo pipefail
OUTDIR="${1:-}"; URLS="${2:-}"
[[ -z "$OUTDIR" || -z "$URLS" ]] && { echo "KULLANIM: surface_build.sh <output_dir> <urls_file>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
[[ -f "$URLS" ]] || { echo "HATA: urls dosyası yok: $URLS" >&2; exit 3; }
mkdir -p "$OUTDIR"
SURF="$OUTDIR/surface.json"
[[ -f "$SURF" ]] || echo '{"target":"","assets":[],"endpoints":[],"params":[],"hypotheses":[],"findings":[]}' > "$SURF"

PARSED=$(awk '
  { u=$0; sub(/#.*$/,"",u); sub(/^[a-zA-Z]+:\/\//,"",u);
    host=u; path="/"; q="";
    i=index(u,"/");
    if(i>0){ host=substr(u,1,i-1); rest=substr(u,i); j=index(rest,"?");
             if(j>0){ path=substr(rest,1,j-1); q=substr(rest,j+1) } else path=rest }
    else { j=index(u,"?"); if(j>0){host=substr(u,1,j-1); q=substr(u,j+1)} }
    sub(/:[0-9]+$/,"",host);
    if(host ~ /\./) print host"\t"path"\t"q
  }' "$URLS" | sort -u)

[[ -z "$PARSED" ]] && { echo "UYARI: geçerli URL bulunamadı"; exit 0; }

while IFS=$'\t' read -r host _ _; do
  [[ -z "$host" ]] && continue
  jq --arg h "$host" '
    if any(.assets[]; .host==$h) then . else
      .assets += [{"host":$h,"ip":"","tech":[],"waf":"","auth":"","kind":"web","priority":"unset"}] end
  ' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
done <<< "$(echo "$PARSED" | cut -f1 | sort -u | sed 's/$/\t\t/')"

while IFS=$'\t' read -r host path q; do
  [[ -z "$host" ]] && continue
  eid="${host}${path}"
  jq --arg h "$host" --arg p "$path" --arg id "$eid" '
    if any(.endpoints[]; .id==$id) then . else
      .endpoints += [{"id":$id,"host":$h,"method":"GET","path":$p,"auth_required":null,
                      "params":[],"tech":"","tested":false,"depth_achieved":"L0","source":"recon"}] end
  ' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
  if [[ -n "$q" ]]; then
    IFS='&' read -ra kvs <<< "$q"
    for kv in "${kvs[@]}"; do
      name="${kv%%=*}"; [[ -z "$name" ]] && continue
      pid="${eid}::${name}"
      jq --arg pid "$pid" --arg n "$name" --arg e "$eid" '
        if any(.params[]; .id==$pid) then . else
          .params += [{"id":$pid,"endpoint":$e,"name":$n,"loc":"query","type":"",
                       "sink_guess":"","reflected":false,"tested":false}] end
        | (.endpoints[] | select(.id==$e) | .params) |= (. + [$n] | unique)
      ' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    done
  fi
done <<< "$PARSED"

echo "SURFACE: $SURF"
jq -r '"  assets="+( .assets|length|tostring )+"  endpoints="+( .endpoints|length|tostring )+"  params="+( .params|length|tostring )' "$SURF"
echo "  (sorgu örnekleri: jq '.endpoints[] | select(.tested==false)' $SURF)"
