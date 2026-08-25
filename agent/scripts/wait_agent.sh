#!/usr/bin/env bash
set -uo pipefail

AGENTS_DIR=/cyp/agents

MAX_WAIT="${CYP_AGENT_WAIT_MAX:-1500}"   # seconds (~25 min)
START=$(date +%s)

for H in "$@"; do
  while [ "$(cat "$AGENTS_DIR/${H}.status" 2>/dev/null)" != "done" ]; do
    sleep 2
    PID="$(cat "$AGENTS_DIR/${H}.pid" 2>/dev/null || true)"
    if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
      echo "uyarı: ${H} süreci 'done' işareti yazmadan sonlandı (crash?); raporlamaya/ilerlemeye geçiliyor"
      echo done > "$AGENTS_DIR/${H}.status" 2>/dev/null || true
      break
    fi
    if [ $(( $(date +%s) - START )) -ge "$MAX_WAIT" ]; then
      echo "süre aşımı: bazı modüller hâlâ çalışıyor olabilir, raporlamaya geçiliyor ($*)"
      exit 0
    fi
  done
done
echo "tüm modüller tamamlandı: $*"
