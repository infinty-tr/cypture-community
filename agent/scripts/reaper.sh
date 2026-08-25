#!/usr/bin/env bash
set -u
AGENTS_DIR=/cyp/agents
INTERVAL="${CYP_REAPER_INTERVAL:-30}"      # tarama periyodu (sn)
STALL_TTL="${CYP_REAPER_STALL_TTL:-900}"   # canlı-ama-sessiz eşiği (sn); 0 = (b)'yi kapat
LOG=/cyp/reaper.log
mkdir -p "$AGENTS_DIR" 2>/dev/null || true

log() { echo "[$(date -u +%H:%M:%S)] $*" >> "$LOG" 2>/dev/null || true; }
log "reaper başladı (interval=${INTERVAL}s stall_ttl=${STALL_TTL}s)"

while true; do
  now=$(date +%s)
  for st in "$AGENTS_DIR"/*.status; do
    [ -e "$st" ] || continue
    [ "$(cat "$st" 2>/dev/null || true)" = "running" ] || continue
    h="$(basename "$st" .status)"
    pid="$(cat "$AGENTS_DIR/$h.pid" 2>/dev/null || true)"

    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      log "REAP $h: süreç ölü (pid=$pid) → done (çökmüş)"
      echo done > "$st" 2>/dev/null || true
      continue
    fi

    if [ "${STALL_TTL}" -gt 0 ]; then
      nd="$AGENTS_DIR/$h.ndjson"
      if [ -f "$nd" ]; then
        mtime=$(stat -c %Y "$nd" 2>/dev/null || echo "$now")
        idle=$(( now - mtime ))
        if [ "$idle" -ge "$STALL_TTL" ]; then
          log "REAP $h: ${idle}sn tam sessiz (asılı, muhtemelen model) → kill+done"
          [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
          echo done > "$st" 2>/dev/null || true
        fi
      fi
    fi
  done
  sleep "$INTERVAL"
done
