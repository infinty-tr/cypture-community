#!/usr/bin/env bash
case "${1:-}" in
  list) [ -s /cyp/findings.ndjson ] && tail -20 /cyp/findings.ndjson 2>/dev/null || echo "(worklog shim: veri yok)";;
  *) echo "(worklog shim: bu ortamda yok — normal akışa devam et; koordinasyon /cyp/findings.ndjson üzerinden, test manuel: baseline→prob→cyp_diff_requests)";;
esac
exit 0
