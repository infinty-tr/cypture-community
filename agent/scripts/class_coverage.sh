#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; MAX="${2:-12}"
if [[ -z "$SURF" ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"; AT="$ROOT/.cypture/plugin/ACTIVE_TARGET"
  [[ -f "$AT" ]] && SURF="$(head -1 "$AT" | tr -d '[:space:]')"
fi
[[ -z "$SURF" ]] && SURF=$(ls -t targets/*/surface.json 2>/dev/null | head -1 || true)
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "CLASS-COVERAGE: NO_SURFACE"; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }

classes_for() {
  local h="$1"; local c="info_disclosure security_headers cors"
  echo "$h" | grep -qiE 'api|gateway|graphql'        && c="$c auth bola_idor mass_assignment injection rate_limit ssrf"
  echo "$h" | grep -qiE 'auth|login|sso|oauth|account|recovery|identity|session' && c="$c auth_bypass jwt oauth_flow session account_takeover"
  echo "$h" | grep -qiE 'dash|app|portal|console|admin|home|my|account'          && c="$c authz_idor xss csrf business_logic"
  echo "$h" | grep -qiE 'upload|file|media|storage'  && c="$c file_upload path_traversal"
  echo "$c" | tr ' ' '\n' | sort -u | tr '\n' ' '
}

total_cells=0; done_cells=0; pending_hosts=0
declare -a REPORT

while IFS=$'\t' read -r host prio; do
  [[ -z "$host" ]] && continue
  applicable=$(jq -r --arg h "$host" '(.assets[]|select(.host==$h).applicable_classes // []) | join(" ")' "$SURF" 2>/dev/null)
  [[ -z "${applicable// }" ]] && applicable=$(classes_for "$host")
  done_list=$(jq -r --arg h "$host" '(.assets[]|select(.host==$h).test_classes // {}) | to_entries[] | select(.value==true) | .key' "$SURF" 2>/dev/null | tr '\n' ' ')
  pend=""
  for cls in $applicable; do
    total_cells=$((total_cells+1))
    if echo " $done_list " | grep -q " $cls "; then done_cells=$((done_cells+1)); else pend="$pend $cls"; fi
  done
  if [[ -n "${pend// }" ]]; then
    pending_hosts=$((pending_hosts+1))
    REPORT+=("  [$prio] $host → KALAN:${pend}")
  fi
done < <(jq -r '.assets[] | [.host, (.priority//"unset")] | @tsv' "$SURF" \
         | awk -F'\t' '{o=($2=="high"?0:($2=="medium"?1:2)); print o"\t"$0}' | sort -n | cut -f2-)

echo "═══ HOST × TEST-SINIFI KAPSAMASI ═══  ($SURF)"
echo "Hücre (host×sınıf): toplam=$total_cells  yapıldı=$done_cells  KALAN=$((total_cells-done_cells))  | eksik host=$pending_hosts"
if [[ "$pending_hosts" -gt 0 ]]; then
  echo ""
  echo "EKSİK HOST'LAR (öncelik sıralı, en çok $MAX):"
  printf '%s\n' "${REPORT[@]}" | head -n "$MAX"
  echo ""
  echo "CLASS-COVERAGE: INCOMPLETE — $((total_cells-done_cells)) (host×sınıf) hücresi test edilmemiş."
  echo "AKSİYON: Her host için KALAN sınıfları test et; bitince scripts/mark_class.sh <surface.json> <host> <sınıf>."
  exit 10
fi
echo ""
echo "CLASS-COVERAGE: COMPLETE — her host'un tüm uygulanabilir sınıfları test edildi."
exit 0
