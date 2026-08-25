#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: chain_suggest.sh <surface.json>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

PATTERNS='
ssrf|-|SSRF→169.254.169.254 cloud metadata (IAM creds)→AWS CLI→S3/DB ele geçir
sqli|-|SQLi→users tablosu dump (email:hash)→hash crack→login endpoint ile ATO
lfi|-|LFI→/etc/passwd + .env (APP_KEY/secret) oku; log/upload poisoning→RCE zinciri
path_traversal|-|Path traversal→hassas dosya (config/key) oku→LFI→RCE
file_upload|@lfi|Upload (.php/polyglot) + LFI ile include→RCE
open_redirect|@oauth_flow|Open redirect + OAuth redirect_uri→authorization code/token hırsızlığı→ATO
open_redirect|@account_takeover|Open redirect→oturum/oauth token sızıntısı→ATO
idor|@account_takeover|IDOR→admin email/id sızdır→password reset tetikle→reset token IDOR→admin ATO
bola_idor|@account_takeover|BOLA→başka kullanıcı objesi→reset/2fa akışı→ATO
mass_assignment|@bola_idor|Mass assignment (role=admin)+IDOR edit→privilege escalation
xss|-|XSS→document.cookie/localStorage JWT çal→oturum tekrar→ATO (HttpOnly yoksa)
jwt|-|JWT alg=none / zayıf imza / kid path-traversal→admin token forge
ssti|-|SSTI→{{7*7}} doğrula→sandbox escape→RCE
xxe|-|XXE→file read (/etc/passwd) + OOB ile blind exfil→SSRF zinciri
'

mapfile -t ROWS < <(jq -r '.findings[]? | select(.state=="validated" or .state=="candidate") | (.type|ascii_downcase)+"\t"+(.host//"-")' "$SURF" 2>/dev/null || true)

ADD=0
for row in "${ROWS[@]:-}"; do
  [[ -z "$row" ]] && continue
  FTYPE="${row%%$'\t'*}"; FHOST="${row#*$'\t'}"
  while IFS='|' read -r trig pre desc; do
    [[ -z "${trig// }" ]] && continue
    trig="${trig// }"; pre="${pre// }"
    echo "$FTYPE" | grep -qiE "$trig" || continue
    if [[ "$pre" == @* ]]; then
      cls="${pre#@}"
      jq -e --arg h "$FHOST" --arg c "$cls" '
        any(.assets[]?; .host==$h and ((.applicable_classes//[])|index($c)))
        or any(.findings[]?; .host==$h and ((.type|ascii_downcase)|test($c)))' "$SURF" >/dev/null 2>&1 || continue
    fi
    jq --arg h "$FHOST" --arg d "$desc" '
      .hypotheses = (.hypotheses // [])
      | if any(.hypotheses[]?; .host==$h and .class=="chain" and .angle==$d) then .
        else .hypotheses += [{id:("h-chain-"+$h+"-"+(($d|explode|add|tostring))),
          host:$h, param:"", class:"chain", angle:$d, state:"open", priority_boost:true}] end
    ' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    ADD=$((ADD+1))
  done <<< "$PATTERNS"
done

NCH=$(jq '[.hypotheses[]?|select(.class=="chain" and .state=="open")]|length' "$SURF")
echo "ZİNCİR ÖNERİSİ: ${ADD} desen eşleşti → açık chain hipotezi: $NCH (score_hypotheses bunları EN ÖNE alır)."
[[ "$NCH" -gt 0 ]] && jq -r '[.hypotheses[]?|select(.class=="chain" and .state=="open")][0:5][] | "  ⛓  ["+.host+"] "+.angle' "$SURF"
exit 0
