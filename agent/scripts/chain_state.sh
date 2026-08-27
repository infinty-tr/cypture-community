#!/usr/bin/env bash
case "${1:-}" in
  list) [ -s ${CYP_FEED_DIR:-/cyp}/findings.ndjson ] && tail -20 ${CYP_FEED_DIR:-/cyp}/findings.ndjson 2>/dev/null || echo "(chain_state shim: veri yok)";;
  *) echo "(chain_state shim: bu ortamda yok — normal akışa devam et; koordinasyon ${CYP_FEED_DIR:-/cyp}/findings.ndjson üzerinden, test manuel: baseline→prob→cyp_diff_requests)";;
esac
exit 0
