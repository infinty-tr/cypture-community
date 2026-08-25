#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; HOST="${2:-}"; MAX="${3:-5}"
[[ -z "$SURF" || -z "$HOST" ]] && { echo "KULLANIM: next_hypothesis.sh <surface.json> <host> [maks]" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

APPLI=$(jq -r --arg h "$HOST" '(.assets[]|select(.host==$h).applicable_classes // []) | join(" ")' "$SURF")
DONE=$(jq -r --arg h "$HOST" '(.assets[]|select(.host==$h).test_classes // {}) | to_entries | map(select(.value==true)|.key) | join(" ")' "$SURF")
PARAMS=$(jq -r --arg h "$HOST" '[.endpoints[]?|select(.host==$h).params[]?] + [.params[]? | select(.endpoint|startswith($h)) | .name] | unique | .[]' "$SURF" 2>/dev/null | grep -v '^$' | tr '\n' ' ' || echo "")
DEPTH=$(jq -r --arg h "$HOST" '(.assets[]|select(.host==$h).depth_achieved // "L0")' "$SURF")

pending_classes() { for c in $APPLI; do echo " $DONE " | grep -qw "$c" || echo "$c"; done; }

angle_for() { case "$1" in
  injection|sqli)       echo "param '%P' SQL/komut sink olabilir — '/'' syntax + boolean çifti + SLEEP time probe (baseline'a dön: '' canary)." ;;
  xss)                  echo "param '%P' DOM/HTML'e yansıyor olabilir — benzersiz canary + bağlam (gövde/attr/script) özel kırılma; CSP/encode kontrol." ;;
  ssrf)                 echo "param '%P' URL/host alıyor olabilir — OOB canary ile sunucu-taraflı istek; iç meta-data (169.254.169.254) zinciri." ;;
  open_redirect)        echo "param '%P' redirect hedefi olabilir — //attacker, oauth state/token sızıntısı zinciri." ;;
  path_traversal|lfi)   echo "param '%P' dosya yolu olabilir — ../ traversal + null byte + wrapper; LFI→RCE/log-poison zinciri." ;;
  bola_idor|authz_idor) echo "param '%P' nesne id'si olabilir — 2 kimlikle (acquire_identity) diff_idor; sıralı/UUID enum." ;;
  mass_assignment)      echo "yazma endpoint'ine fazladan alan (role=admin, is_verified=true) enjekte et — privilege escalation zinciri." ;;
  jwt|oauth_flow)       echo "token alg=none / zayıf imza / kid path-traversal; oauth redirect_uri + state zinciri." ;;
  business_logic)       echo "akış sırası/negatif değer/yarış (race) — coupon/transfer/quota mantık atlatma." ;;
  prototype_pollution)  echo "JSON gövdesinde __proto__/constructor.prototype kirletme → gadget zinciri." ;;
  file_upload)          echo "uzantı/içerik-tip atlatma, polyglot, yol kontrolü → RCE/stored-XSS zinciri." ;;
  *)                    echo "sınıf '$1' için temel diagnostic probe + baseline kıyas; sinyal varsa derinleş." ;;
esac; }

N=0
EXISTING=$(jq -r --arg h "$HOST" '[.hypotheses[]?|select(.host==$h)]|length' "$SURF")
while read -r cls; do
  [[ -z "$cls" ]] && continue
  [[ "$N" -ge "$MAX" ]] && break
  if echo "$cls" | grep -qE 'injection|sqli|xss|ssrf|open_redirect|path_traversal|lfi|bola_idor|authz_idor' && [[ -n "${PARAMS// }" ]]; then
    for p in $PARAMS; do
      [[ "$N" -ge "$MAX" ]] && break
      ang=$(angle_for "$cls" | sed "s/%P/$p/g")
      jq --arg h "$HOST" --arg c "$cls" --arg p "$p" --arg a "$ang" --arg id "h-$HOST-$((EXISTING+N+1))" '
        if any(.hypotheses[]?; .host==$h and .param==$p and .class==$c) then .
        else .hypotheses += [{id:$id, host:$h, param:$p, class:$c, angle:$a, state:"open"}] end
      ' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
      N=$((N+1))
    done
  else
    ang=$(angle_for "$cls" | sed "s/%P/(host)/g")
    jq --arg h "$HOST" --arg c "$cls" --arg a "$ang" --arg id "h-$HOST-$((EXISTING+N+1))" '
      if any(.hypotheses[]?; .host==$h and (.param==null or .param=="") and .class==$c) then .
      else .hypotheses += [{id:$id, host:$h, param:"", class:$c, angle:$a, state:"open"}] end
    ' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    N=$((N+1))
  fi
done < <(pending_classes)

echo "HİPOTEZ ÜRETİLDİ [$HOST] (depth=$DEPTH): $N yeni açı → surface.json .hypotheses[]"
if [[ "$N" -eq 0 ]]; then
  echo "  (uygulanabilir sınıf × param tükendi — derinlik tavanı bu eksende dolu. decide_next.sh STOP'a düşebilir.)"
else
  jq -r --arg h "$HOST" '[.hypotheses[]?|select(.host==$h and .state=="open")] | .[-'"$N"':][] | "  • ["+.class+"] "+(.param // "(host)")+" → "+.angle' "$SURF" 2>/dev/null | head -n "$MAX" || true
fi
