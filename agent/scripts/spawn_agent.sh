#!/usr/bin/env bash
set -uo pipefail

AGENT="${1:?kullanım: spawn_agent.sh <ajan-adı> <görev>}"; shift
PROMPT="${*:?görev metni gerekli}"

# Feed/IPC dizini: konteynerde /cyp, host (live runner) modunda CYP_FEED_DIR.
FEED="${CYP_FEED_DIR:-/cyp}"

PLAYBOOK=""
case "$AGENT" in
  recon-agent) ;;  # keşif — playbook gerekmez, hızlı kalsın
  *)
    if [ -n "${WS:-}" ] && [ -s "${WS}/playbook.md" ]; then PLAYBOOK="${WS}/playbook.md"
    elif [ -n "${CYP_PLAYBOOK:-}" ] && [ -s "${CYP_PLAYBOOK}" ]; then PLAYBOOK="${CYP_PLAYBOOK}"; fi
    ;;
esac
if [ -n "$PLAYBOOK" ]; then
  PROMPT="⚡ ÖNCE UYGULA — ÖZETLEME (mutlak kural): Playbook'u/talimatı ASLA özetleme, açıklama, kopyalama ya da 'şunu yapacağım' diye anlatma. İLK çıktın bir ARAÇ ÇAĞRISI olmalı (\`cyp_send_request\`). Döküman/markdown/uzun düşünce ZİNCİRİ üretme → araç çağır → yanıtı oku → sonraki araç. Plan ANLATMA, İCRA ET.
ZORUNLU İLK İŞ: \`read $PLAYBOOK\` (seçili sözleşmeler + zafiyet playbook'ları) — OKU ve UYGULA, özetini YAZMA. Kendi genel bilgine değil ona göre: sink → baseline → kademeli prob → kanıt kapısı → varyant → durma.
BULGU KAYIT — ZORUNLU, HER TEYİTTE ANINDA (kusursuz exploit zincirini BEKLEME, teyitli ARA bulgu da): bir zafiyeti DOĞRULAR DOĞRULAMAZ çıktına TEK satır şu işareti yaz → [CYP-FINDING]{\"title\":\"...\",\"severity\":\"critical|high|medium|low|info\",\"vuln_type\":\"...\",\"endpoint\":\"...\",\"method\":\"...\",\"evidence\":\"...\",\"poc\":\"...\",\"confidence\":\"confirmed|likely\",\"verified\":true} — bu işaret TEK BAŞINA bulguyu panele düşürür (tool çağırmasan/dosya yazmasan BİLE; en sağlam kanal). Marker yazmadıysan bulgu YOK demektir; ASLA sadece anlatıp 'yazdım' deyip geçme. Ayrıca cyp_create_finding çağır + /cyp/findings.ndjson'a aynı JSON'u ekle.
PoC = MOTORDAN GEÇEN GERÇEK KANIT (düz 'şunu yaptım' anlatımı YETERSİZ): zafiyeti cyp_send_request ile fiilen SÖMÜR (istek kaydolsun) → yanıtta GÖRÜNEN gerçek veriyi (dosya içeriği, DB satırı, sürüm, komut çıktısı, başkasının verisi) extracted_evidence'a yaz + proof_kind=extracted_data|executed_effect; diferansiyel için cyp_set_baseline+cyp_diff_requests kullan. Motor bu extracted_evidence'ı KAYITLI yanıtta arar — uydurursan/yanıtta yoksa 'doğrulandı' VERİLMEZ. Her bulgu request+response taşımalı.
⛔ BLACKBOX — SADECE CANLI HEDEF: repo KLONLAMA (git clone), OSS kaynak kodu indirme/grep'leme, GitHub/GitLab/pkg.go.dev/NVD'ye kod okumak için curl/webfetch/web araştırması YASAK. Hedefi ('ezBookkeeping', 'WordPress' vb.) tanıman kaynağa bakma sebebi DEĞİL — cyp_send_request ile CANLI test etme sebebidir; bilinen açığın KANITINI canlı endpoint'te üret (kaynağı okuyarak değil). bash yalnız scripts/* yardımcıları, crt.sh recon ve 'curl -x http://127.0.0.1:8080' (hedefe proxy) içindir; başka amaçla git/curl-to-github/python-source KULLANMA.

${PROMPT}"
  echo "skill-inject: ${AGENT} → 'read $PLAYBOOK' direktifi (gömme yok, prompt küçük)" >&2
else
  PROMPT="BULGU MARKER: recon sırasında bir zafiyeti DOĞRULARSAN (LFI/XSS/SQLi/SSRF vb.) çıktına TEK satır yaz → [CYP-FINDING]{\"title\":\"...\",\"severity\":\"high\",\"vuln_type\":\"...\",\"endpoint\":\"...\",\"poc\":\"...\",\"verified\":true}; bu olmadan bulgu panele DÜŞMEZ, sadece anlatma.
⛔ BLACKBOX — SADECE CANLI HEDEF: repo KLONLAMA (git clone), OSS kaynak kodu indirme/grep'leme, GitHub/GitLab/pkg.go.dev/NVD'ye kod okumak için curl/webfetch YASAK. Hedefi tanıman kaynağa bakma değil cyp_send_request ile CANLI test sebebidir. bash yalnız scripts/* + crt.sh recon + 'curl -x http://127.0.0.1:8080' içindir.

${PROMPT}"
  echo "skill-inject: ${AGENT} → finding-marker (playbook yok)" >&2
fi

# Konteyner-yolu (/cyp) sabitlerini gerçek feed dizinine çevir (host modunda).
if [ "$FEED" != "/cyp" ]; then
  PROMPT="${PROMPT//\/cyp\//$FEED/}"
fi

AGENTS_DIR="$FEED/agents"
mkdir -p "$AGENTS_DIR"

MAX_PARALLEL="${CYP_MAX_PARALLEL:-6}"
while [ "$(grep -l running "$AGENTS_DIR"/*.status 2>/dev/null | wc -l)" -ge "$MAX_PARALLEL" ]; do
  for st in "$AGENTS_DIR"/*.status; do
    [ -e "$st" ] || continue
    [ "$(cat "$st" 2>/dev/null || true)" = "running" ] || continue
    hh="$(basename "$st" .status)"
    pp="$(cat "$AGENTS_DIR/$hh.pid" 2>/dev/null || true)"
    if [ -n "$pp" ] && ! kill -0 "$pp" 2>/dev/null; then
      echo done > "$st" 2>/dev/null || true
    fi
  done
  sleep 2
done

N=$(( $(ls -1 "$AGENTS_DIR" 2>/dev/null | grep -c "^${AGENT}-.*\.ndjson$") + 1 ))
HANDLE="${AGENT}-${N}"
OUT="$AGENTS_DIR/${HANDLE}.ndjson"
STATUS="$AGENTS_DIR/${HANDLE}.status"
LOG="$AGENTS_DIR/${HANDLE}.log"
echo running > "$STATUS"

RUN_MODEL="${CYP_MODEL:-}"
case "$AGENT" in
  web-test-agent|api-test-agent|reporter-agent)
    [ -n "${CYP_MODEL_REASONING:-}" ] && RUN_MODEL="${CYP_MODEL_REASONING}" ;;
esac
MODEL_ARG=(); [ -n "$RUN_MODEL" ] && MODEL_ARG=(-m "$RUN_MODEL")
PERM_ARG=();  [ -n "${CYP_SKIP_PERMS:-}" ] && PERM_ARG=(--dangerously-skip-permissions)

# Each sub-agent gets its OWN data dir so parallel agent runtimes don't serialize
# on a single shared data-dir lock (this is what lets a wave spawn many experts at
# once). Seed the auth into each isolated dir so every sub-agent can authenticate:
#   - container: the rebranded cypture-agent auth
#   - host: the operator's real opencode auth (XDG_DATA_HOME/opencode/auth.json)
DATA="/tmp/oc-${HANDLE}"
mkdir -p "$DATA/opencode" "$DATA/cypture-agent"
if [ -f /root/.local/share/cypture-agent/auth.json ]; then
  cp /root/.local/share/cypture-agent/auth.json "$DATA/cypture-agent/auth.json" 2>/dev/null || true
fi
SRC_AUTH="${OPENCODE_AUTH:-${XDG_DATA_HOME:-$HOME/.local/share}/opencode/auth.json}"
if [ -f "$SRC_AUTH" ]; then
  cp "$SRC_AUTH" "$DATA/opencode/auth.json" 2>/dev/null || true
fi

(
  cd "${CYP_PROJECT_ROOT:-/agent}" || exit 1
  XDG_DATA_HOME="$DATA" "${CYP_AGENT_BIN:-cypture-agent}" run --format json --agent "$AGENT" \
    "${MODEL_ARG[@]}" "${PERM_ARG[@]}" "$PROMPT" >"$OUT" 2>"$LOG"
  echo done > "$STATUS"
  rm -rf "$DATA" 2>/dev/null || true
) &
echo $! > "$AGENTS_DIR/${HANDLE}.pid"

echo "$HANDLE"
