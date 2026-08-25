#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"; CJSON="${2:-}"
[[ -z "$SURF" || -z "$CJSON" ]] && { echo "KULLANIM: oob_poll.sh <surface.json> <cyp_search_json>" >&2; exit 2; }
[[ -f "$SURF" ]] || { echo "HATA: surface.json yok: $SURF" >&2; exit 3; }
[[ -f "$CJSON" ]] || { echo "HATA: cypture json/metin yok: $CJSON" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
DIR="$(dirname "$SURF")"; OUT="$DIR/signals.jsonl"; : >> "$OUT"
MAX_POLLS="${OOB_MAX_POLLS:-3}"

sigtype() { case "$1" in
  ssrf) echo "ssrf_oob";; xxe) echo "xxe_oob";; rce|command|deser) echo "rce_oob";;
  xss) echo "xss_oob";; sqli) echo "sqli_oob";; *) echo "ssrf_oob";; esac; }

HAYBLOB="$(tr -d '\0' < "$CJSON")"   # tüm metni token araması için
HITS=0; POLLED=0
while IFS=$'\t' read -r tok host cls fqdn; do
  [[ -z "$tok" ]] && continue
  if printf '%s' "$HAYBLOB" | grep -qF "$tok"; then
    ST="$(sigtype "$cls")"
    jq -cn --arg h "$host" --arg t "$ST" --arg e "OOB callback: $fqdn (canary $tok tetiklendi)" \
      '{host:$h, request_id:("oob:"+$ARGS.positional[0]), signal_type:$t, evidence_snippet:$e, confidence:"high"}' \
      --args "$tok" >> "$OUT"
    jq --arg tok "$tok" '(.oob_canaries[]? | select(.token==$tok) | .confirmed) = true' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    HITS=$((HITS+1))
  else
    jq --arg tok "$tok" '(.oob_canaries[]? | select(.token==$tok) | .poll_count) = ((.oob_canaries[]?|select(.token==$tok).poll_count // 0)+1)' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    POLLED=$((POLLED+1))
  fi
done < <(jq -r '.oob_canaries[]? | select((.injected//false) and ((.confirmed//false)|not)) | [.token,.host,.class,.fqdn] | @tsv' "$SURF")

echo "OOB POLL: $HITS callback DOĞRULANDI (high-conf sinyal yazıldı) · $POLLED yoklandı (henüz yok)."
[[ "$HITS" -gt 0 ]] && echo "  Sıradaki: bash scripts/audit_signals.sh $SURF  → kör zafiyet candidate olur."
exit 0
