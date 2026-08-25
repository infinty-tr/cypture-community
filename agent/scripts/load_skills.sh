#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"; HOST="${2:-}"
[ -z "$SURF" ] || [ -z "$HOST" ] && { echo "KULLANIM: load_skills.sh <surface.json> <host> [outfile]" >&2; exit 2; }
[ -f "$SURF" ] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"     # agent/
SKILLS="$ROOT/skills"
OUT="${3:-$(dirname "$SURF")/playbook.md}"

if [ "$HOST" = "ALL" ] || [ "$HOST" = "*" ]; then
  for H in $(jq -r '.assets[]?.host' "$SURF" 2>/dev/null | sort -u); do
    bash "$ROOT/scripts/class_select.sh" "$SURF" "$H" >/dev/null 2>&1 || true
  done
  CLASSES=$(jq -r '[.assets[]?.applicable_classes // [] | .[]] | unique | join(" ")' "$SURF" 2>/dev/null || echo "")
  TECH=$(jq -r '[.assets[]?.tech // [] | .[]] | unique | join(" ") | ascii_downcase' "$SURF" 2>/dev/null || echo "")
else
  HAVE=$(jq -r --arg h "$HOST" '(.assets[]?|select(.host==$h).applicable_classes // []) | length' "$SURF" 2>/dev/null || echo 0)
  if [ "${HAVE:-0}" -eq 0 ]; then
    bash "$ROOT/scripts/class_select.sh" "$SURF" "$HOST" >/dev/null 2>&1 || true
  fi
  CLASSES=$(jq -r --arg h "$HOST" '(.assets[]?|select(.host==$h).applicable_classes // []) | join(" ")' "$SURF" 2>/dev/null || echo "")
  TECH=$(jq -r --arg h "$HOST" '(.assets[]?|select(.host==$h).tech // []) | join(" ") | ascii_downcase' "$SURF" 2>/dev/null || echo "")
fi

declare -A MAP=(
  [injection]="vuln-sqli vuln-nosqli vuln-command-injection"
  [xss]="vuln-xss vuln-dom-xss-spa"
  [csrf]="vuln-csrf"
  [ssrf]="vuln-ssrf"
  [ssti]="vuln-ssti"
  [path_traversal]="vuln-lfi-path-traversal"
  [file_upload]="vuln-file-upload"
  [deserialization]="vuln-deserialization"
  [prototype_pollution]="vuln-prototype-pollution"
  [jwt]="vuln-jwt-attacks"
  [oauth_flow]="vuln-oauth-attacks"
  [cors]="vuln-cors-misconfig"
  [open_redirect]="vuln-open-redirect"
  [graphql]="vuln-graphql vuln-bfla"
  [bola_idor]="vuln-idor vuln-bfla"
  [authz_idor]="vuln-idor"
  [mass_assignment]="vuln-mass-assignment"
  [auth]="vuln-auth-session"
  [auth_bypass]="vuln-auth-session vuln-jwt-attacks vuln-ldap-injection vuln-xpath-injection vuln-saml-xml-signature"
  [session]="vuln-auth-session"
  [account_takeover]="vuln-auth-session vuln-oauth-attacks vuln-saml-xml-signature"
  [rate_limit]="vuln-rate-limit-resource vuln-race-condition"
  [business_logic]="vuln-business-logic vuln-race-condition"
  [race_condition]="vuln-race-condition"
  [subdomain_takeover]="vuln-subdomain-takeover"
  [host_header]="vuln-host-header-injection"
  [hpp]="vuln-http-parameter-pollution"
  [ldap]="vuln-ldap-injection"
  [xpath]="vuln-xpath-injection"
  [websocket]="vuln-websocket"
  [saml]="vuln-saml-xml-signature"
  [email_injection]="vuln-email-injection"
  [prompt_injection]="vuln-prompt-injection"
  [formula_injection]="vuln-formula-injection"
)
case "$TECH" in *xml*|*soap*) EXTRA="vuln-xxe";; *) EXTRA="";; esac
echo "$HOST$TECH" | grep -qiE 'cdn|cache|proxy|gateway|cloudflare|akamai|fastly|nginx|varnish' && EXTRA="$EXTRA vuln-http-request-smuggling vuln-crlf-header-injection vuln-cache-poisoning-deception"
echo "$HOST$TECH" | grep -qiE 'telerik|asp\.?net|x-aspnet|iis|struts|spring|log4j|java|jboss|weblogic|citrix|confluence|atlassian|jenkins|gitlab|sharepoint|exchange|owa|fortinet|fortigate|f5|big-?ip|drupal|wordpress|wp-|joomla|vbulletin|jira' && EXTRA="$EXTRA vuln-known-cve"
EXTRA="$EXTRA chain-recipes vuln-tls-crypto"

WANT=""
for c in $CLASSES; do WANT="$WANT ${MAP[$c]:-}"; done
WANT="$WANT $EXTRA"
WANT=$(printf '%s\n' $WANT | sort -u | grep -v '^$' || true)

CONTRACTS="core-contract calibration-and-honesty hunter-intuition business-logic-reasoning response-manipulation exploitation-impact attacker-mindset-and-persistence evidence-discipline baseline-and-signal depth-calibration signal-commentary redteam-primitives think-like-a-system"
REFS="access-control-reasoning chain-attack-builder out-of-band-testing data-flow-and-mental-model adversarial-verification oob-blind-confirmation auth-session-handling identity-acquisition vuln-dom-xss-spa"

{
  echo "# 📚 BU HOST İÇİN SEÇİLİ PLAYBOOK — $HOST"
  echo "> Otomatik üretildi (load_skills.sh). Sınıflar: ${CLASSES:-yok}. Tech: ${TECH:-yok}."
  echo "> Test ederken AŞAĞIDAKİ playbook'lara uy: sink → muhakeme → baseline → kademeli prob → kanıt kapısı → varyant → false-positive → durma."
  echo ""
  echo "## — Zorunlu sözleşmeler —"
  for s in $CONTRACTS; do
    [ -f "$SKILLS/$s.md" ] && { echo ""; echo "<!-- $s -->"; cat "$SKILLS/$s.md"; echo ""; }
  done
  echo ""
  echo "## — AUTHENTICATED TEST + TARAYICI (her host için ZORUNLU değerlendir) —"
  echo "- **Kimlik / oturum:** Operatör test hesabı verdiyse (operatör direktifinde ⚑ / aşağıdaki KİMLİK bloğunda) ONU kullan — kendin hesap açmak ZORUNDA değilsin. Cypture ile login ol (curl-direct YASAK) → Set-Cookie/token al → \`cyp_create_replay_session\` ile oturumu taşı. AUTHENTICATED yüzey en değerli bugların yeridir (IDOR/BOLA, yetki yükseltme, iş-mantığı, mass-assignment) — login-öncesi yüzeyle YETİNME. İki kimlik (A/B) varsa A-vs-B yetki testi yap: \`cyp_list_sessions\` ile hangi kimlik olduğunu izle, \`cyp_diff_requests\` ile A'nın B'nin verisini görüp görmediğini kıyasla. Reçete: skills/auth-session-handling.md + skills/identity-acquisition.md + skills/access-control-reasoning.md. Kimlik verilmemişse ve \`/register\` varsa kendin edin (identity-acquisition.md)."
  echo "- **Gerçek tarayıcı (SPA / JS-ağır hedef):** Ham HTTP yanıtı boş/iskelet (\"<div id=root>\") dönüyorsa, ya da DOM-XSS / client-side route / JS-only akış (login, ödeme) varsa SADECE ham yanıta bakma — \`cyp_browser_navigate\` ile GERÇEK Chromium'da render et (JS çalışır), \`cyp_browser_dom\` ile gerçek DOM'u oku, \`cyp_browser_eval\` ile durumu/route'ları çıkar. DOM-XSS kanıtı = sink'e payload → JS dialog (alert) yakalanır. 'JS çalıştırılamadı, ham yüzey tükendi' deyip GEÇME — tarayıcıyı kullan. Reçete: skills/vuln-dom-xss-spa.md."
  echo ""
  echo "## — Gerekince OKU (referans, inline değil) —"
  for s in $REFS; do [ -f "$SKILLS/$s.md" ] && echo "- skills/$s.md"; done
  echo ""
  echo "## — Bu host için zafiyet playbook'ları —"
  for s in $WANT; do
    if [ -f "$SKILLS/$s.md" ]; then echo ""; echo "<!-- $s -->"; cat "$SKILLS/$s.md"; echo ""; fi
  done
} > "$OUT" 2>/dev/null

echo "PLAYBOOK : $OUT  (sınıf=$(echo $CLASSES | wc -w), playbook=$(echo $WANT | wc -w))"
echo "SEÇİLEN  : $(echo $WANT | tr '\n' ' ')"
