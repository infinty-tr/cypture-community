#!/usr/bin/env bash
set -euo pipefail
RA="${1:-}"; SA="${2:-}"; RB="${3:-}"; SB="${4:-}"
[[ -z "$RA" || -z "$SA" || -z "$RB" || -z "$SB" ]] && { echo "KULLANIM: diff_idor.sh <respA> <statusA> <respB> <statusB>" >&2; exit 2; }
[[ -f "$RA" && -f "$RB" ]] || { echo "HATA: response dosyaları yok" >&2; exit 3; }

norm_tokens() { tr -s '[:space:]' '\n' < "$1" | sed -E 's/[0-9a-fA-F]{6,}/#/g; s/[0-9]{3,}/#/g' | grep -v '^$' || true; }
TA=$(norm_tokens "$RA"); TB=$(norm_tokens "$RB")

if [[ "$TA" == "$TB" ]]; then SIM="identical"; else
  tot=$(printf '%s\n' "$TA" | grep -c . || true)
  df=$(diff <(printf '%s\n' "$TA") <(printf '%s\n' "$TB") | grep -c '^[<>]' || true)
  if [[ "$tot" -gt 0 ]]; then
    pct=$(( df * 100 / (tot * 2) ))            # df hem < hem > sayar; ~2*tot ile normalize
    if [[ "$pct" -lt 25 ]]; then SIM="similar"; else SIM="different"; fi
  else SIM="different"; fi
fi

PRIV=$(grep -ciE '("?(email|user_?id|userId|owner|wallet|address|phone|ssn|api_?key|secret|private_?key|token)"?\s*[:=])|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$RA" 2>/dev/null || true); PRIV=${PRIV:-0}

echo "DIFF: A=$SA B=$SB benzerlik=$SIM özel_veri_işareti(A)=$PRIV"

case "$SB" in
  401|403)
    echo "VERDICT: SAFE — B reddedildi ($SB), erişim kontrolü çalışıyor. IDOR DEĞİL." ; exit 0 ;;
  404|400)
    echo "VERDICT: SAFE/NOT_VISIBLE — nesne B'ye görünmüyor ($SB). IDOR DEĞİL (ama enum dene)." ; exit 0 ;;
esac

if [[ "$SA" == "200" && "$SB" == "200" ]]; then
  if [[ "$SIM" == "identical" || "$SIM" == "similar" ]]; then
    if [[ "$PRIV" -gt 0 ]]; then
      echo "VERDICT: 🔴 POTENTIAL_IDOR — B, A'nın ÖZEL verisini gördü (sınır aşıldı). Doğrula: veri gerçekten A'ya mı ait?"
      exit 10
    else
      echo "VERDICT: LIKELY_PUBLIC — gövde aynı AMA özel-veri işareti yok = herkese açık içerik. IDOR DEĞİL (en fazla INFO)."
      exit 0
    fi
  else
    echo "VERDICT: LIKELY_SAFE — B farklı veri gördü (muhtemelen kendi kaydı / farklı public). IDOR DEĞİL."
    exit 0
  fi
fi
echo "VERDICT: INCONCLUSIVE — A=$SA B=$SB. Elle incele (ör. A yetkili 200 değilse karşılaştırma anlamsız)."
exit 0
