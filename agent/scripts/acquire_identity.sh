#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; HOST="${2:-}"; ROLE="${3:-user}"
[[ -z "$SURF" || -z "$HOST" ]] && { echo "KULLANIM: acquire_identity.sh <surface.json> <host> [rol]" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

RID="$(head -c4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || echo "$RANDOM$RANDOM")"
HANDLE="cyp_${ROLE}_${RID}"
EMAIL="${HANDLE}@example-mailbox.test"     # operatör gerçek doğrulanabilir kutu sağlamalı (skill'e bak)
PASS="Cyp!$(printf '%s' "$RID" | cut -c1-8)Aa9"

jq --arg h "$HOST" --arg ha "$HANDLE" --arg em "$EMAIL" --arg pw "$PASS" --arg ro "$ROLE" '
  (.assets[] | select(.host==$h) | .identities) //= []
  | if any(.assets[]?|select(.host==$h).identities[]?; .handle==$ha) then .
    else (.assets[] | select(.host==$h) | .identities) += [{
      handle:$ha, email:$em, password:$pw, role:$ro, cyp_session:"", status:"pending", acquired:"auto-pending"}]
    end
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

CNT=$(jq -r --arg h "$HOST" '[.assets[]?|select(.host==$h).identities[]?]|length' "$SURF")
cat <<EOF
KİMLİK SLOTU (pending) [$HOST] → handle=$HANDLE rol=$ROLE  (toplam kimlik: $CNT)
  email=$EMAIL  pass=$PASS
REÇETE (Cypture ile UYGULA — skills/identity-acquisition.md):
  1. Register endpoint'ini bul (recon/surface: /register /signup /api/.../users). Cypture ile POST et:
     email=$EMAIL  password=$PASS  (+ gerekli alanlar). CAPTCHA/e-posta doğrulaması varsa skill'deki fallback.
  2. Login et → Set-Cookie/token al → Cypture session oluştur (cyp_create_replay_session / set_session_request).
  3. KAYDET:  bash scripts/mark_identity.sh $SURF $HOST $HANDLE <cyp_session_id> $ROLE
  4. IDOR/BOLA için bunu İKİ kez yap (rol: user, sonra user2) → diff_idor.sh A/B kimlikleriyle çalışsın.
NOT: başarısız olsa bile DURMA — diğer sınıflara devam et (best-effort).
EOF
