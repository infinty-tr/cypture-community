#!/usr/bin/env bash
set -uo pipefail

ok=0; warn=0; fail=0
chk() { # chk <etiket> <komut> <zorunlu|opsiyonel> [fallback notu]
  local label="$1" cmd="$2" req="$3" note="${4:-}"
  if command -v "$cmd" >/dev/null 2>&1; then
    printf "  ✅ %-14s %s\n" "$label" "$(command -v "$cmd")"; ok=$((ok+1))
  elif [[ "$req" == "zorunlu" ]]; then
    printf "  ❌ %-14s EKSİK (ZORUNLU) %s\n" "$label" "$note"; fail=$((fail+1))
  else
    printf "  🟡 %-14s yok (opsiyonel) %s\n" "$label" "$note"; warn=$((warn+1))
  fi
}

echo "== ÇEKİRDEK =="
chk jq jq zorunlu "→ sudo pacman -S jq"
chk curl curl zorunlu
echo "== RECON ARAÇLARI =="
chk subfinder subfinder zorunlu "→ subdomain keşfi"
chk httpx httpx zorunlu "→ canlı host/teknoloji"
chk gau gau opsiyonel "→ tarihsel URL"
chk katana katana opsiyonel "fallback: gau + waybackurls + hakrawler"
chk waybackurls waybackurls opsiyonel
chk hakrawler hakrawler opsiyonel
chk ffuf ffuf opsiyonel "→ dizin/param fuzz"
chk amass amass opsiyonel

echo "== PROXY (kendi cypture-engine motorumuz — MCP: cyp_* araçları) =="
if command -v cypture-engine >/dev/null 2>&1 \
   || [[ -x "${HOME:-/root}/.local/bin/cypture-engine" ]] \
   || [[ -x /root/.local/bin/cypture-engine ]] \
   || [[ -x /usr/local/bin/cypture-engine ]]; then
  printf "  ✅ %-14s var (cypture-engine — MCP cyp_* araçları AKTİF; HAM curl/wget DEĞİL)\n" "proxy-motoru"; ok=$((ok+1))
else
  printf "  ❌ %-14s EKSİK\n" "proxy-motoru"; fail=$((fail+1))
fi
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "${CYPTURE_ENGINE_URL:-http://localhost:8080}" 2>/dev/null || echo "000")
if [[ "$code" != "000" ]]; then printf "  ✅ %-14s %s (HTTP %s)\n" "Cypture proxy" "${CYPTURE_ENGINE_URL:-http://localhost:8080}" "$code"; ok=$((ok+1))
else printf "  ❌ %-14s erişilemedi — Cypture açık mı?\n" "Cypture proxy"; fail=$((fail+1)); fi
echo "  ℹ️  QuickSSRF (OOB): Cypture içinde elle doğrula — blind testler bunu kullanır."

echo "== AĞ (scope dataset) =="
if curl -fsI --max-time 6 "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json" >/dev/null 2>&1; then
  printf "  ✅ %-14s erişilebilir\n" "bounty-data"; ok=$((ok+1))
else printf "  🟡 %-14s erişilemedi (private API/elle scope gerekebilir)\n" "bounty-data"; warn=$((warn+1)); fi

echo ""
echo "SONUÇ: $ok OK · $warn uyarı · $fail kritik eksik"
if [[ $fail -gt 0 ]]; then echo "⛔ Kritik eksik var — gidermeden tam akış çalışmaz."; exit 1; fi
echo "✅ Çekirdek hazır. (Opsiyonel araçlar eksikse fallback'ler devrede.)"
