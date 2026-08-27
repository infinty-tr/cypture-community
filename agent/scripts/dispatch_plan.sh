#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-${WS:-.}/surface.json}"
URLS="${WS:-.}/urls.txt"
FIND="${CYP_FEED_DIR:-/cyp}/findings.ndjson"
blob=""
[ -s "$SURF" ] && blob+=" $(cat "$SURF" 2>/dev/null)"
[ -s "$URLS" ] && blob+=" $(cat "$URLS" 2>/dev/null)"
[ -s "$FIND" ] && blob+=" $(cat "$FIND" 2>/dev/null)"
lc=$(printf '%s' "$blob" | tr '[:upper:]' '[:lower:]')
want=""
add(){ case " $want " in *" $1 "*) ;; *) want="$want $1";; esac; }

EPN=0
if command -v jq >/dev/null 2>&1 && [ -s "$SURF" ]; then
  EPN=$(jq '[.assets[]?.endpoints[]?] | length' "$SURF" 2>/dev/null || echo 0)
fi
[ -z "$EPN" ] && EPN=0
WEBN=$(( (EPN + 11) / 12 )); [ "$WEBN" -lt 1 ] && WEBN=1; [ "$WEBN" -gt 3 ] && WEBN=3
for _ in $(seq 1 "$WEBN"); do want="$want web-test-agent"; done   # tekrarlı ekle (N tane)
if printf '%s' "$lc" | grep -qE '/api/|/api |/graphql|"api"|gateway|graphql|json.?api|/v[0-9]+/|rest api'; then
  add api-test-agent
fi
add fuzzing-agent

if printf '%s' "$lc" | grep -qE 'graphql|graphiql|/query|login|sign.?in|oauth|openid|jwt|bearer|session|/auth|password.?reset|mfa|2fa'; then
  add api-test-agent
fi

NF=0; [ -s "$FIND" ] && NF=$(grep -c . "$FIND" 2>/dev/null || echo 0)
[ "$NF" -ge 2 ] && add validator-agent                                       # ≥2 bulgu → doğrula + zincirle
printf '%s' "$lc" | grep -qE 'candidate|theoretical|aday|doğrulanmad|dogrulanmad' && add validator-agent

echo "SPAWN:${want}"
echo "# ipucu: endpoint=$EPN web=$WEBN bulgu=$NF — orchestrator SPAWN satırındaki HER uzmanı task() ile aç."
