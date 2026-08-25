#!/usr/bin/env bash
set -euo pipefail

SURF="${1:-}"
BATCH="${2:-8}"
NOW=$(date +%s); TTL="${AGENT_TTL:-600}"   # taze kira süresi (lease-aware NEXT batch)
if [[ -z "$SURF" ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  AT="$ROOT/.cypture/plugin/ACTIVE_TARGET"
  [[ -f "$AT" ]] && SURF="$(head -1 "$AT" | tr -d '[:space:]')"
fi
[[ -z "$SURF" ]] && SURF=$(ls -t targets/*/surface.json 2>/dev/null | head -1 || true)
if [[ -z "$SURF" || ! -f "$SURF" ]]; then
  echo "COVERAGE: NO_SURFACE — surface.json bulunamadı."
  echo "AKSİYON: Recon'u tamamla + scripts/surface_build.sh ile canlı host'ları surface.json'a INGEST et."
  exit 3
fi
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

UNTESTED_FILTER='
  . as $r
  | [ $r.assets[] | . as $a
      | select( (($a.depth_achieved // "L0") | test("^(L0)?$"))
                and ( ([ $r.endpoints[] | select(.host==$a.host and .tested==true) ] | length) == 0 ) ) ]
'

total=$(jq '[.assets[]]|length' "$SURF")
untested=$(jq "$UNTESTED_FILTER | length" "$SURF")
tested=$(( total - untested ))
ep_total=$(jq '[.endpoints[]]|length' "$SURF")
ep_untested=$(jq '[.endpoints[]|select(.tested!=true)]|length' "$SURF")
hi_untested=$(jq "$UNTESTED_FILTER | [.[]|select(.priority==\"high\")] | length" "$SURF")

echo "═══ KAPSAMA DURUMU ═══  ($SURF)"
echo "HOST    : toplam=$total   test_edildi(≥L1)=$tested   KALAN(L0)=$untested   (yüksek-değer kalan=$hi_untested)"
echo "ENDPOINT: toplam=$ep_total   test_edilmemiş=$ep_untested"

if [[ "$untested" -gt 0 ]]; then
  echo ""
  echo "SIRADAKİ PARTİ (öncelik sıralı, en çok $BATCH host) — bunları ŞİMDİ test ajanlarına dağıt:"
  jq -r --argjson now "$NOW" --argjson ttl "$TTL" "$UNTESTED_FILTER
    | map(select(((.assigned_to // \"\")==\"\") or (((\$now) - (.assigned_at // 0)) > \$ttl)))
    | sort_by(if .priority==\"high\" then 0 elif .priority==\"medium\" then 1 else 2 end)
    | .[0:$BATCH][] | \"  - \" + .host + \"   (priority=\" + (.priority // \"unset\") + \")\"" "$SURF"
  echo ""
  echo "COVERAGE: INCOMPLETE — $untested host hâlâ test edilmemiş (L0)."
  echo "AKSİYON (ZORUNLU): Yukarıdaki partiyi task() ile test ajanlarına SPAWN et. RAPOR YOK, DURMA YOK,"
  echo "                   KULLANICI BEKLEME YOK. Her dalga sonrası bu script'i TEKRAR çalıştır."
  exit 10
fi

echo ""
echo "COVERAGE: COMPLETE — tüm host'lar ≥L1 (hiç dokunulmamış host yok)."
echo "SONRAKİ: DERİNLİK KAPISI (KURAL 2) — TIER-1 host'ları L3+ derin mi? Değilse derinleş; öyleyse rapora geç."
exit 0
