#!/usr/bin/env bash
set -euo pipefail
F="${1:-}"
[[ -z "$F" || ! -f "$F" ]] && { echo "KULLANIM: validate_finding.sh <finding.json>" >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
jq -e . "$F" >/dev/null 2>&1 || { echo "REJECTED: geçersiz JSON" ; exit 10; }

g() { jq -r --arg k "$1" '.[$k] // ""' "$F"; }
TYPE=$(g type); HOST=$(g host); EP=$(g endpoint); BND=$(g boundary)
IMP=$(g impact); BREQ=$(g baseline_req); DREQ=$(g deviation_req); SEV=$(g severity)
IV=$(g idor_verdict); SREF=$(g signal_ref)
TYPE_LC=$(printf '%s' "$TYPE" | tr '[:upper:]' '[:lower:]')

fail() { echo "REJECTED [$TYPE @ $HOST]: $1"; exit 10; }

case "$BND" in authz|authn|trust|restriction|confidentiality) ;; *)
  fail "geçerli 'boundary' yok (authz/authn/trust/restriction/confidentiality). Sınır aşılmadıysa bulgu DEĞİL." ;; esac

[[ -z "$IMP" ]] && fail "'impact' boş — 'saldırgan bununla NE yapar' yaz."
echo "$IMP" | grep -qiE '^(yok|none|n/a|bilinmiyor|belki|olabilir|potansiyel)\.?$' && fail "'impact' klişe/boş ('$IMP'). Somut etki gerekli."

[[ -z "$DREQ" ]] && fail "kanıt eksik — deviation_req (Cypture request_id) ZORUNLU. İstek atmadıysan bulgu yok."

if echo "$TYPE_LC" | grep -qE 'idor|bola|auth_bypass|authz'; then
  [[ -z "$BREQ" ]] && fail "kıyas-tabanlı tip ($TYPE) baseline_req ister (yetkili/normal istek). Tek istek bu sınırı kanıtlamaz."
fi

if echo "$TYPE_LC" | grep -qE 'idor|bola'; then
  echo "$IV" | grep -qi 'POTENTIAL_IDOR' || fail "IDOR/BOLA ama diff_idor verdict'i POTENTIAL_IDOR değil ('$IV'). Public/own veri = IDOR DEĞİL."
fi

if [[ "$SEV" == "CRITICAL" ]]; then
  case "$BND" in authz|trust) ;; *)
    fail "CRITICAL ancak boundary∈{authz,trust} ile mümkün (mevcut: '$BND'). Severity'yi düşür ya da sınırı doğru belirle." ;; esac
  if echo "$TYPE_LC" | grep -qE 'idor|bola'; then
    echo "$IV" | grep -qi 'POTENTIAL_IDOR' || fail "CRITICAL idor/bola için diff_idor POTENTIAL_IDOR verdict'i şart."
  elif echo "$TYPE_LC" | grep -qE 'sqli|injection|ssti|ssrf|rce|xxe|deser|nosqli|command'; then
    [[ -n "$SREF" || ( -n "$BREQ" && -n "$DREQ" ) ]] || fail "CRITICAL injection-sınıfı için signal_ref (collect_signals kanıtı) ya da baseline+deviation çifti şart."
  elif echo "$TYPE_LC" | grep -qE 'auth_bypass|account_takeover|ato'; then
    [[ -n "$BREQ" && -n "$DREQ" ]] || fail "CRITICAL auth_bypass için baseline(401/403)+deviation(200) çifti şart."
  else
    [[ -n "$SREF" ]] || fail "CRITICAL iddiası için somut hakem kanıtı (signal_ref ya da verdict) şart."
  fi
fi

PK=$(g proof_kind); EV=$(g extracted_evidence); ST=$(g status)
PK_LC=$(printf '%s' "$PK" | tr '[:upper:]' '[:lower:]')
ST_LC=$(printf '%s' "$ST" | tr '[:upper:]' '[:lower:]')
if [[ -z "$PK_LC" ]]; then
  if [[ -n "$BREQ" && -n "$DREQ" ]]; then PK_LC="differential"; else PK_LC="inferential"; fi
fi
case "$PK_LC" in extracted_data|executed_effect|differential|inferential) ;; *)
  fail "geçersiz proof_kind ('$PK'). İzinli: extracted_data|executed_effect|differential|inferential." ;; esac

if [[ "$ST_LC" == "confirmed" ]]; then
  case "$PK_LC" in
    extracted_data|executed_effect)
      [[ -n "$EV" ]] || fail "status=confirmed ama extracted_evidence boş. DOĞRULANDI için gerçek çıkarılmış veri/etki ŞART (ör. DB versiyon/satır, /etc/passwd içeriği, çalışan XSS ekran görüntüsü ref)." ;;
    *) fail "status=confirmed yalnız proof_kind∈{extracted_data,executed_effect} ile mümkün (mevcut: '$PK_LC'). boolean/timing/uzunluk farkı = OLASI/TEORİK, DOĞRULANDI DEĞİL." ;;
  esac
fi

if [[ "$SEV" == "CRITICAL" ]]; then
  case "$PK_LC" in
    extracted_data|executed_effect)
      [[ -n "$EV" ]] || fail "CRITICAL için gerçek çıkarılmış veri/etki (extracted_evidence) ŞART — salt sinyal/fark CRITICAL olamaz." ;;
    *) fail "CRITICAL ancak proof_kind∈{extracted_data,executed_effect}+extracted_evidence ile. '$PK_LC' = en çok HIGH(differential)/MEDIUM(inferential). Gerçek veri çıkar ya da severity'yi düşür." ;;
  esac
fi
if [[ "$SEV" == "HIGH" && "$PK_LC" == "inferential" ]]; then
  fail "HIGH en az differential (ölçülen baseline-sapma) ister. Salt boolean/timing/uzunluk (inferential) = MEDIUM tavanı + OLASI/TEORİK."
fi

case "$PK_LC" in
  extracted_data|executed_effect) STATUS_OUT="${ST_LC:-confirmed}";;
  differential) STATUS_OUT="probable";;
  *) STATUS_OUT="theoretical";;
esac

REQ=$(g request); RESP=$(g response); DUR=$(g duration_ms)
if [[ "$STATUS_OUT" == "confirmed" || "$SEV" == "CRITICAL" || "$SEV" == "HIGH" ]]; then
  [[ -n "$REQ"  ]] || fail "PoC eksik — 'request' (ham HTTP istek) yok. confirmed/HIGH+ bulgu reproduce edilebilir istek taşımalı (cyp_create_finding bunu otomatik ekler; elle yazıyorsan ham isteği koy)."
  [[ -n "$RESP" ]] || fail "PoC eksik — 'response' (ham HTTP yanıt) yok. confirmed/HIGH+ bulgu kanıt yanıtını taşımalı."
fi

FPS="$(dirname "$0")/fingerprint.sh"
LEDGER="${CYP_SEEN_LEDGER:-}"; [ -z "$LEDGER" ] && [ -n "${WS:-}" ] && LEDGER="$WS/seen_patterns.jsonl"
if [ -n "$LEDGER" ] && [ -f "$FPS" ]; then
  PFP=$(g param); [ -z "$PFP" ] && PFP=$(g parameter)
  bash "$FPS" add "$LEDGER" "$TYPE" "$EP" "$PFP" "$HOST" "$STATUS_OUT" >/dev/null 2>&1 || true
fi
echo "ACCEPTED [$SEV/$STATUS_OUT] $TYPE @ $HOST$EP — sınır=$BND, proof_kind=$PK_LC, kanıt=deviation:$DREQ${BREQ:+,baseline:$BREQ}${SREF:+,$SREF}${EV:+,extracted:VAR}. 2. ajan çürütmesine HAZIR."
exit 0
