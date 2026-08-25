#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: audit_signals.sh <surface.json> [signals.jsonl]" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
DIR="$(dirname "$SURF")"; ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIG="${2:-$DIR/signals.jsonl}"
[[ -f "$SIG" ]] || { echo "AUDIT: signals.jsonl yok ($SIG) — taranacak aday yok."; exit 0; }

map_type() { case "$1" in
  sql_error)      echo "sqli|confidentiality|HIGH|no|DB hata mesajı sızdı — SQL injection olası; boolean/time ile veri çekimi doğrulanmalı." ;;
  stack_trace)    echo "info_disclosure|confidentiality|LOW|no|Stack trace iç yapıyı/dosya yollarını sızdırıyor; bilgi ifşası." ;;
  reflection_xss) echo "xss|trust|MEDIUM|no|Girdi encode'suz yansıyor — XSS olası; bağlam-özel payload ile çalıştırma doğrulanmalı." ;;
  open_redirect)  echo "open_redirect|trust|LOW|no|Saldırgan-kontrollü host'a yönlendirme; phishing/oauth-token sızıntısı zinciri olası." ;;
  ssrf_oob)       echo "ssrf|confidentiality|HIGH|no|OOB etkileşim doğrulandı — sunucu saldırgan host'a istek attı (SSRF)." ;;
  xxe_oob)        echo "xxe|confidentiality|HIGH|no|XXE OOB doğrulandı — dış varlık dahil edildi (file read/SSRF zinciri)." ;;
  rce_oob)        echo "rce|trust|CRITICAL|no|RCE OOB doğrulandı — sunucuda komut çalıştı (OOB callback)." ;;
  xss_oob)        echo "xss|trust|HIGH|no|Blind XSS OOB — payload başka kullanıcı/admin bağlamında çalıştı." ;;
  sqli_oob)       echo "sqli|confidentiality|HIGH|no|OOB SQLi doğrulandı — DB dış DNS/HTTP isteği yaptı." ;;
  server_error)   echo "info_disclosure|restriction|INFO|no|Beklenmeyen 5xx; baseline 200 ile karşılaştırılıp tetikleyici doğrulanmalı." ;;
  secret_leak)    echo "info_disclosure|confidentiality|HIGH|no|Sır/anahtar yanıtta sızdı (kendi auth yankısı değil) — kimlik/erişim riski." ;;
  idor_candidate) echo "idor|authz|HIGH|yes|İki kimlik aynı kaynağı gördü — diff_idor POTENTIAL_IDOR ile doğrulanmalı." ;;
  *)              echo "info_disclosure|confidentiality|INFO|no|Sınıflandırılmamış sinyal — elle incele." ;;
esac; }

ADD=0; SKIP=0; REJ=0; LN=0
TMP="$(mktemp)"
while IFS= read -r s; do
  LN=$((LN+1))
  [[ -z "$s" ]] && continue
  jq -e . >/dev/null 2>&1 <<<"$s" || { continue; }
  HOST=$(jq -r '.host // ""' <<<"$s")
  RID=$(jq -r '.request_id // ""' <<<"$s")
  STYPE=$(jq -r '.signal_type // ""' <<<"$s")
  CONF=$(jq -r '.confidence // "low"' <<<"$s")
  SNIP=$(jq -r '.evidence_snippet // ""' <<<"$s")
  SREF="signals.jsonl:$LN"
  [[ -z "$STYPE" || -z "$RID" ]] && { continue; }

  if jq -e --arg sr "$SREF" --arg h "$HOST" --arg t "$STYPE" --arg r "$RID" \
       '[.findings[]? | select(.signal_ref==$sr or (.host==$h and .signal_ref!=null and (.deviation_req==$r)))] | length>0' "$SURF" >/dev/null 2>&1; then
    SKIP=$((SKIP+1)); continue
  fi

  IFS='|' read -r FTYPE BND SEV NEEDB IMP <<<"$(map_type "$STYPE")"

  jq -cn --arg t "$FTYPE" --arg h "$HOST" --arg b "$BND" --arg imp "$IMP" \
        --arg dr "$RID" --arg sev "$SEV" --arg sr "$SREF" --arg conf "$CONF" '
    {type:$t, host:$h, endpoint:"", boundary:$b, impact:$imp,
     baseline_req:"", deviation_req:$dr, severity:$sev, idor_verdict:"",
     signal_ref:$sr, confidence:$conf, state:"candidate"}' > "$TMP"

  if bash "$ROOT/scripts/validate_finding.sh" "$TMP" >/dev/null 2>&1; then
    jq --slurpfile f "$TMP" '.findings += $f' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    ADD=$((ADD+1))
  else
    REJ=$((REJ+1))
  fi
done < "$SIG"
rm -f "$TMP"

{ grep -c . "$SIG" 2>/dev/null || true; } > "$DIR/signals.audited"
echo "AUDIT: $ADD candidate eklendi · $SKIP zaten vardı · $REJ reddedildi (validate_finding)  → $SURF"
[[ "$ADD" -gt 0 ]] && echo "  Sıradaki: candidate'ları 2. ajanla ÇÜRÜT/DOĞRULA → state=validated|refuted. (idor/sqli için baseline_req ekle.)"
exit 0
