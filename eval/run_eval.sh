#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
TARGET_NAME="${1:?kullanım: run_eval.sh <hedef-adı> (ör. juice-shop)}"
COMPOSE="targets/${TARGET_NAME}.yml"
EXPECTED="expected/${TARGET_NAME}.json"
[ -f "$COMPOSE" ] && [ -f "$EXPECTED" ] || { echo "HATA: $COMPOSE veya $EXPECTED yok"; exit 1; }

MODEL="${CYP_EVAL_MODEL:-strong}"
TIMEOUT="${CYP_EVAL_TIMEOUT:-1800}"
HOST="$(python3 -c "import json;print(json.load(open('$EXPECTED'))['target'])")"
ROOT="$(cd .. && pwd)"
B="http://127.0.0.1:7777"

set -a; . "$ROOT/.env"; set +a

echo "=== Hedef ayağa kaldırılıyor: $TARGET_NAME ($HOST) ==="
docker compose -f "$COMPOSE" up -d
echo "Hedefin hazır olması bekleniyor..."
for i in $(seq 1 30); do curl -s -o /dev/null --max-time 3 "http://$HOST" && break; sleep 3; done

echo "=== Tarama başlatılıyor (model=$MODEL) ==="
CA=$(curl -s -c /tmp/eval.jar -X POST $B/api/auth/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" | sed -n 's/.*"csrf":"\([^"]*\)".*/\1/p')
RESP=$(curl -s -b /tmp/eval.jar -X POST $B/api/admin/scans -H 'Content-Type: application/json' -H "X-CSRF-Token: $CA" \
  -d "{\"title\":\"eval-$TARGET_NAME\",\"scope_includes\":[\"$HOST\"],\"mode\":\"full\",\"model\":\"$MODEL\"}")
SID=$(echo "$RESP" | sed -n 's/.*"scan_id":"\([^"]*\)".*/\1/p')
[ -n "$SID" ] || { echo "HATA: tarama başlatılamadı: $RESP"; exit 1; }
echo "scan_id=$SID — tamamlanması bekleniyor (max ${TIMEOUT}sn)..."

START=$(date +%s)
while :; do
  ST=$(curl -s -b /tmp/eval.jar "$B/api/scans/$SID" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -1)
  echo "  [$(( $(date +%s)-START ))sn] durum=$ST"
  case "$ST" in completed|failed|stopped) break;; esac
  [ $(( $(date +%s)-START )) -ge "$TIMEOUT" ] && { echo "süre aşımı"; break; }
  sleep 20
done

echo "=== Bulgular çekiliyor + skorlanıyor ==="
curl -s -b /tmp/eval.jar "$B/api/scans/$SID/findings" > /tmp/eval-findings.json
python3 score.py "$EXPECTED" /tmp/eval-findings.json

echo "=== (Hedefi durdurmak için: docker compose -f $COMPOSE down) ==="
