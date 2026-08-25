#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"; CJSON="${2:-}"
[[ -z "$SURF" ]] && { echo "KULLANIM: wave_finalize.sh <surface.json> <cyp_json>" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
R() { bash "$ROOT/scripts/$1" "${@:2}" 2>&1 | sed 's/^/   /'; }

echo "═══ DALGA-SONU (wave_finalize) ═══  $SURF"
if [[ -n "$CJSON" && -f "$CJSON" ]]; then
  echo "▸ collect_signals"; R collect_signals.sh "$SURF" "$CJSON" | tail -1
  if jq -e '(.oob_canaries // []) | length > 0' "$SURF" >/dev/null 2>&1; then
    echo "▸ oob_poll";     R oob_poll.sh "$SURF" "$CJSON" | tail -1
  fi
  echo "▸ anomaly_scan (bu tuhaf?)"; R anomaly_scan.sh "$SURF" "$CJSON" | tail -1
fi
echo "▸ gap_finder (varsayım çöküşü)"; R gap_finder.sh "$SURF" | tail -1
echo "▸ audit_signals";    R audit_signals.sh "$SURF" | tail -1

if [[ -n "$CJSON" && -f "$CJSON" ]]; then
  echo "▸ mark_from_engine (her host, kanıtlı derinlik)"
  while IFS= read -r h; do [[ -z "$h" ]] && continue
    bash "$ROOT/scripts/mark_from_engine.sh" "$SURF" "$h" "$CJSON" 2>/dev/null | grep -E 'DERİNLİK=' | sed 's/^/   /' || true
  done < <(jq -r '.assets[]?.host' "$SURF")
  echo "▸ budget_guard";   R budget_guard.sh "$SURF" "$CJSON" | tail -1
fi

echo "▸ propagate_finding (validated → yay)"
while IFS=$'\t' read -r host type; do
  [[ -z "$host" || -z "$type" ]] && continue
  bash "$ROOT/scripts/propagate_finding.sh" "$SURF" "$host" "$type" "" >/dev/null 2>&1 || true
done < <(jq -r '.findings[]? | select(.state=="validated") | [.host,(.type)] | @tsv' "$SURF")
echo "   boost hipotez: $(jq '[.hypotheses[]?|select(.priority_boost==true)]|length' "$SURF")"

echo "▸ chain_suggest"; R chain_suggest.sh "$SURF" | grep -E 'ZİNCİR ÖNERİSİ' || true

echo "─── KARAR ───"
bash "$ROOT/scripts/decide_next.sh" "$SURF"
