#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"; CJSON="${2:-}"; HOSTF="${3:-}"
[[ -z "$SURF" || -z "$CJSON" ]] && { echo "KULLANIM: collect_signals.sh <surface.json> <cyp_json> [host]" >&2; exit 2; }
[[ -f "$CJSON" ]] || { echo "HATA: cypture json yok: $CJSON" >&2; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
OUT="$(dirname "$SURF")/signals.jsonl"; : >> "$OUT"
OOB_HITS="${OOB_HITS:-}"

snip() { printf '%s' "$1" | tr '\n' ' ' | grep -oiE -e "$2" | head -1 | cut -c1-140; }
emit() { # emit host reqid type snippet confidence
  jq -cn --arg h "$1" --arg r "$2" --arg t "$3" --arg e "$4" --arg c "$5" \
    '{host:$h,request_id:$r,signal_type:$t,evidence_snippet:$e,confidence:$c}' >> "$OUT"
}

COUNT=0
while IFS= read -r item; do
  [[ -z "$item" ]] && continue
  RID=$(jq -r '(.id // .request_id // "") | tostring' <<<"$item")
  URL=$(jq -r '(.url // "")' <<<"$item")
  STATUS=$(jq -r '(.statusCode // .status // "") | tostring' <<<"$item")
  RBODY=$(jq -r '(.respBody // .responseBody // .body // "")' <<<"$item")
  RHEAD=$(jq -r '(.respHeaders // .responseHeaders // .headers // "") | if type=="object" then (to_entries|map(.key+": "+(.value|tostring))|join("\n")) else tostring end' <<<"$item")
  QBODY=$(jq -r '(.reqBody // .requestBody // "")' <<<"$item")
  HOST=$(jq -r '(.host // "")' <<<"$item")
  [[ -z "$HOST" || "$HOST" == "null" ]] && HOST=$(printf '%s' "$URL" | sed -E 's#^[a-z]+://##; s#[:/?#].*$##')
  [[ -n "$HOSTF" && "$HOST" != "$HOSTF" ]] && continue
  [[ -z "$RID" || "$RID" == "null" ]] && RID="(no-id:$HOST)"

  PROBED="no"; printf '%s %s' "$URL" "$QBODY" | grep -qE "('|%27|\"|<|>)" && PROBED="yes"

  if m=$(snip "$RBODY" 'SQL syntax|mysql_fetch|valid MySQL result|ORA-[0-9]{5}|PostgreSQL.*ERROR|PG::|SQLSTATE|SQLite3?::|Unclosed quotation|quoted string not properly|ODBC.*Driver|SQLServer|syntax error at or near'); [[ -n "$m" ]]; then
    if [[ "$PROBED" == "yes" ]]; then emit "$HOST" "$RID" "sql_error" "$m" "medium"; else emit "$HOST" "$RID" "sql_error" "$m" "low"; fi
    COUNT=$((COUNT+1))
  fi
  if [[ "$STATUS" == "500" || "$STATUS" == "200" || -z "$STATUS" ]]; then
    if m=$(snip "$RBODY" 'Traceback \(most recent call last\)|\.java:[0-9]+\)| at [A-Za-z0-9_.$]+\([A-Za-z0-9_]+\.java:[0-9]+\)|\.rb:[0-9]+:in |System\.[A-Za-z]+Exception|goroutine [0-9]+ |Fatal error: Uncaught|stack trace:|\.py\", line [0-9]+'); [[ -n "$m" ]]; then
      emit "$HOST" "$RID" "stack_trace" "$m" "medium"; COUNT=$((COUNT+1))
    fi
  fi
  while IFS= read -r val; do
    [[ -z "$val" ]] && continue
    printf '%s' "$val" | grep -qE '[<>]' || continue
    dec=$(printf '%s' "$val" | sed 's/%3C/</Ig; s/%3E/>/Ig; s/%22/"/Ig; s/%27/'\''/Ig')
    if printf '%s' "$RBODY" | grep -qF "$dec"; then
      enc=$(printf '%s' "$dec" | sed 's/</\&lt;/g; s/>/\&gt;/g')
      if printf '%s' "$RBODY" | grep -qF "$dec" && ! { printf '%s' "$RBODY" | grep -qF "$enc" && ! printf '%s' "$RBODY" | grep -qF "$dec"; }; then
        emit "$HOST" "$RID" "reflection_xss" "reflected: $(printf '%s' "$dec" | cut -c1-80)" "medium"; COUNT=$((COUNT+1))
      fi
    fi
  done < <(printf '%s' "$URL" | grep -oE '[?&][^=&]+=[^&]+' | sed -E 's/^[?&][^=]*=//')
  LOC=$(printf '%s\n' "$RHEAD" | grep -iE '^location:' | head -1 | sed -E 's/^[Ll]ocation:[[:space:]]*//; s/[[:space:]]*$//')
  if [[ -n "$LOC" ]]; then
    LHOST=$(printf '%s' "$LOC" | sed -E 's#^https?:##; s#^//##; s#[/?#].*$##')
    if [[ -n "$LHOST" && "$LHOST" != "$HOST" ]] && printf '%s %s' "$URL" "$QBODY" | grep -qiF "$LHOST"; then
      emit "$HOST" "$RID" "open_redirect" "Location:$LOC (self=$HOST)" "high"; COUNT=$((COUNT+1))
    fi
  fi
  if [[ -n "$OOB_HITS" && -f "$OOB_HITS" ]]; then
    while IFS= read -r canary; do
      [[ -z "$canary" ]] && continue
      if printf '%s %s' "$URL" "$QBODY" | grep -qF "$canary"; then
        emit "$HOST" "$RID" "ssrf_oob" "OOB hit canary=$canary" "high"; COUNT=$((COUNT+1)); break
      fi
    done < "$OOB_HITS"
  fi
  if [[ "$STATUS" == "500" || "$STATUS" == "502" || "$STATUS" == "503" ]]; then
    emit "$HOST" "$RID" "server_error" "HTTP $STATUS" "low"; COUNT=$((COUNT+1))
  fi
  if m=$(snip "$RBODY" '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{30,}|AIza[0-9A-Za-z_-]{30,}'); [[ -n "$m" ]]; then
    if printf '%s' "$QBODY" | grep -qF "$m"; then :  # istekteki kendi credential'ının yankısı → ele
    else emit "$HOST" "$RID" "secret_leak" "$m" "high"; COUNT=$((COUNT+1)); fi
  fi
done < <(jq -c '(.requests // .) | if type=="array" then .[] else . end' "$CJSON" 2>/dev/null)

echo "SİNYAL TARAMASI: $COUNT aday → $OUT  (host filtresi: ${HOSTF:-yok})"
echo "  Sıradaki: bash scripts/audit_signals.sh $SURF   (adayları validate_finding.sh'ten geçir)"
