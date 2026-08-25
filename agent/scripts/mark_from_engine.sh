#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; HOST="${2:-}"; CJSON="${3:-}"
[[ -z "$SURF" || -z "$HOST" || -z "$CJSON" ]] && { echo "KULLANIM: mark_from_engine.sh <surface.json> <host> <cyp_json>" >&2; exit 2; }
[[ -f "$SURF"  ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
[[ -f "$CJSON" ]] || { echo "HATA: cypture json yok: $CJSON" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

read -r TOTAL DPATHS MUT PARAM <<<"$(jq -r --arg h "$HOST" '
  ($h|ascii_downcase) as $hl
  | [ (.requests // .) | .[] | . as $req
      | (($req.host // "") |
         (if . != "" then . else (($req.url // "") | (capture("^https?://(?<x>[^:/?#]+)")? // {x:""}).x) end)
        | ascii_downcase) as $rh
      | select($rh == $hl) ] as $r
  | ($r | length) as $t
  | ([ $r[] | (.url|sub("\\?.*$";"")|sub("^https?://[^/]+";"")) ] | map(select(.!="")) | unique | length) as $dp
  | (any($r[]; (.method//"GET")|test("^(POST|PUT|DELETE|PATCH)$"))) as $mut
  | (any($r[]; .url|test("\\?"))) as $par
  | "\($t) \($dp) \($mut) \($par)"
' "$CJSON")"

if   [[ "$TOTAL" -eq 0 ]]; then DEPTH="L0"
elif [[ "$DPATHS" -le 1 ]]; then DEPTH="L1"
elif [[ "$DPATHS" -ge 5 && ( "$MUT" == "true" || "$PARAM" == "true" ) ]]; then DEPTH="L3"
elif [[ "$DPATHS" -ge 5 ]]; then DEPTH="L2"
else DEPTH="L1"; fi

echo "KANIT [$HOST]: istek=$TOTAL  farklı_path=$DPATHS  mutation=$MUT  param_probe=$PARAM  →  DERİNLİK=$DEPTH"

if [[ "$DEPTH" == "L0" ]]; then
  echo "  (Cypture'da trafik yok — bu host GERÇEKTEN test edilmemiş, işaretlenmedi.)"
  exit 0
fi

jq --arg h "$HOST" --arg d "$DEPTH" '
  (.assets[]    | select(.host==$h) | .depth_achieved) = $d
  | (.endpoints[] | select(.host==$h) | .tested) = true
  | (.endpoints[] | select(.host==$h and ((.depth_achieved//"L0")=="L0")) | .depth_achieved) = $d
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
echo "  ✓ surface.json güncellendi: $HOST → $DEPTH (KANITLI)"
