#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; HOST="${2:-}"; HANDLE="${3:-}"; SESS="${4:-}"; ROLE="${5:-user}"
[[ -z "$SURF" || -z "$HOST" || -z "$HANDLE" || -z "$SESS" ]] && { echo "KULLANIM: mark_identity.sh <surface.json> <host> <handle> <cyp_session> [rol]" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

jq --arg h "$HOST" --arg ha "$HANDLE" --arg s "$SESS" --arg ro "$ROLE" '
  (.assets[] | select(.host==$h) | .identities) //= []
  | if any(.assets[]?|select(.host==$h).identities[]?; .handle==$ha)
    then (.assets[] | select(.host==$h) | .identities[] | select(.handle==$ha))
           |= (.cyp_session=$s | .status="acquired" | .acquired="done")
    else (.assets[] | select(.host==$h) | .identities) += [{
      handle:$ha, email:"", password:"", role:$ro, cyp_session:$s, status:"acquired", acquired:"manual"}]
    end
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

ACQ=$(jq -r --arg h "$HOST" '[.assets[]?|select(.host==$h).identities[]?|select(.status=="acquired")]|length' "$SURF")
echo "✓ KİMLİK [$HOST] $HANDLE → acquired (cyp_session=$SESS, rol=$ROLE). Edinilmiş kimlik: $ACQ"
[[ "$ACQ" -ge 2 ]] && echo "  ≥2 kimlik hazır → IDOR/BOLA (diff_idor.sh A/B) artık uygulanabilir."
