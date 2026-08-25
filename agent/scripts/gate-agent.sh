#!/usr/bin/env bash
set -uo pipefail
AGENTS_DIR=/cyp/agents
MAX="${1:-${CYP_GATE_MAX_WAIT:-1800}}"
START=$(date +%s)

running_experts() {
  local n=0 s
  for s in "$AGENTS_DIR"/*.status; do
    [ -e "$s" ] || continue
    case "$(basename "$s")" in reporter-agent-*.status) continue ;; esac   # reporter'ın kendisi sayılmaz
    [ "$(cat "$s" 2>/dev/null || true)" = "running" ] && n=$((n+1))
  done
  echo "$n"
}

echo "🚦 RAPOR KAPISI: tüm test/exploit modülleri bitene dek reporter beklemede..."
stable=0
while : ; do
  r="$(running_experts)"
  if [ "$r" -eq 0 ]; then
    stable=$((stable+1))
    [ "$stable" -ge 2 ] && { echo "🟢 KAPI AÇIK: çalışan test/exploit modülü yok → rapor başlayabilir."; break; }
  else
    stable=0
  fi
  if [ $(( $(date +%s) - START )) -ge "$MAX" ]; then
    echo "🟡 KAPI ZAMAN AŞIMI (${MAX}s): hâlâ $r modül çalışıyor olabilir — eldekiyle rapora geçiliyor."
    break
  fi
  sleep 3
done
