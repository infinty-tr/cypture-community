#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; HOST="${2:-}"
[[ -z "$SURF" || -z "$HOST" ]] && { echo "KULLANIM: class_select.sh <surface.json> <host>" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

add() { CLASSES="$CLASSES $*"; }
CLASSES="info_disclosure security_headers cors"   # her host'ta temel

TECH=$(jq -r --arg h "$HOST" '(.assets[]|select(.host==$h).tech // []) | join(" ") | ascii_downcase' "$SURF" 2>/dev/null || echo "")

IS_API="no"
echo "$HOST" | grep -qiE 'api|gateway|graphql' && IS_API="yes"
echo "$TECH"  | grep -qiE 'graphql|rest|json.?api' && IS_API="yes"

if [[ "$IS_API" == "yes" ]]; then
  add auth bola_idor mass_assignment injection rate_limit ssrf
else
  add xss csrf                                    # HTML bağlamı
fi

echo "$HOST" | grep -qiE 'auth|login|sso|oauth|account|recovery|identity|session' && add auth_bypass jwt oauth_flow session account_takeover host_header ldap
echo "$HOST" | grep -qiE 'sso|saml|idp|federation'                                  && add saml
echo "$HOST" | grep -qiE 'dash|app|portal|console|admin|home|my|profile|member'    && add authz_idor business_logic
echo "$HOST" | grep -qiE 'upload|file|media|storage|asset|cdn'                      && add file_upload path_traversal
echo "$HOST" | grep -qiE 'graphql'                                                  && add graphql
echo "$HOST" | grep -qiE 'pay|cart|order|checkout|wallet|transfer|coupon|vote|bid'  && add race_condition business_logic
echo "$HOST" | grep -qiE 'chat|assistant|copilot|\bai\b|bot|search|ask|llm'         && add prompt_injection
echo "$HOST" | grep -qiE 'search|directory|lookup|query'                            && add ldap xpath

echo "$TECH" | grep -qiE 'node|express|next|nest'   && add prototype_pollution ssrf
echo "$TECH" | grep -qiE 'php|laravel|symfony|wordpress' && add path_traversal
echo "$TECH" | grep -qiE 'java|spring|struts'       && add deserialization ssrf ssti
echo "$TECH" | grep -qiE 'python|flask|django'      && add ssti deserialization
echo "$TECH" | grep -qiE 'ruby|rails'               && add deserialization ssti
echo "$TECH" | grep -qiE 'dotnet|asp|\.net'         && add deserialization
echo "$TECH" | grep -qiE 'wordpress|drupal|joomla'  && add xss

HAS_WRITE=$(jq -r --arg h "$HOST" '[.endpoints[]?|select(.host==$h and ((.method//"GET")|test("^(POST|PUT|PATCH|DELETE)$")))]|length' "$SURF" 2>/dev/null || echo 0)
[[ "${HAS_WRITE:-0}" -gt 0 ]] && add csrf mass_assignment race_condition host_header
echo "$TECH" | grep -qiE 'websocket|socket\.io|ws\b' && add websocket
jq -e --arg h "$HOST" '[.endpoints[]?|select(.host==$h and ((.url//.path//"")|test("(?i)wss?://|/ws|/socket|/cable")))]|length>0' "$SURF" >/dev/null 2>&1 && add websocket
QNAMES=$(jq -r --arg h "$HOST" '[.params[]? | select(.loc=="query") | . as $p | select((.endpoint|startswith($h)) or true)] | .[].name' "$SURF" 2>/dev/null | tr '\n' ' ' || echo "")
QNAMES=$(jq -r --arg h "$HOST" '
  (.endpoints[]?|select(.host==$h).params[]?) // empty' "$SURF" 2>/dev/null | tr '\n' ' ' || echo "")
if [[ -n "${QNAMES// }" ]]; then
  add injection hpp
  echo "$QNAMES" | grep -qiE '\b(next|url|redirect|return|dest|continue|goto|to|callback)\b' && add open_redirect
  echo "$QNAMES" | grep -qiE '\b(url|uri|link|src|target|callback|webhook|host|domain|feed|path|file|image)\b' && add ssrf
  echo "$QNAMES" | grep -qiE '\b(q|query|search|filter|name|user|uid|cn|dn|email|mail)\b' && add ldap xpath
fi
ENAMES=$(jq -r --arg h "$HOST" '[.endpoints[]?|select(.host==$h)|(.url//.path//"")]|join(" ")' "$SURF" 2>/dev/null || echo "")
echo "$ENAMES" | grep -qiE 'contact|feedback|invite|subscribe|newsletter|email|mail|reset|forgot|support|ticket' && add email_injection
echo "$ENAMES" | grep -qiE 'export|download|report|csv|xls|spreadsheet|backup|statement' && add formula_injection

UNIQ=$(printf '%s\n' $CLASSES | sort -u | grep -v '^$' | tr '\n' ' ')
JSON_ARR=$(printf '%s\n' $UNIQ | grep -v '^$' | jq -R . | jq -cs .)
jq --arg h "$HOST" --argjson arr "$JSON_ARR" '
  (.assets[] | select(.host==$h) | .applicable_classes) = $arr
' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"

echo "SINIF SEÇİMİ [$HOST] (api=$IS_API, tech='${TECH:-yok}'): $UNIQ"
