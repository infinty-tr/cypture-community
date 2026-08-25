#!/usr/bin/env bash
set -euo pipefail
SURF="${1:-}"; OP="${2:-list}"
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "KULLANIM: belief.sh <surf> <assert|support|contradict|resolve|list> ..." >&2; exit 2; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
NOW=$(date +%s)
sel='select(.id==$k or ((.claim|ascii_downcase)|contains($k|ascii_downcase)))'

case "$OP" in
  assert)
    CLAIM="${3:-}"; CONF="${4:-0.5}"
    [[ -z "$CLAIM" ]] && { echo "KULLANIM: belief.sh <surf> assert \"<iddia>\" [conf]" >&2; exit 2; }
    RID="$(head -c4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || echo "$RANDOM")"
    jq --arg c "$CLAIM" --argjson cf "$CONF" --arg id "b-$RID" --argjson now "$NOW" '
      .beliefs = ((.beliefs // []) +
        (if any((.beliefs//[])[]; .claim==$c) then [] else
          [{id:$id, claim:$c, confidence:$cf, supports:[], contradicts:[], status:"open", ts:$now}] end))
    ' "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    echo "INANC + : \"$CLAIM\" (conf=$CONF)" ;;
  support|contradict)
    KEY="${3:-}"; DELTA="${4:-0.2}"; EV="${5:-}"
    [[ -z "$KEY" ]] && { echo "KULLANIM: belief.sh <surf> $OP <id|iddia> [delta] [kanit]" >&2; exit 2; }
    SIGN=1; [[ "$OP" == "contradict" ]] && SIGN=-1
    jq --arg k "$KEY" --argjson d "$DELTA" --argjson s "$SIGN" --arg ev "$EV" "
      (.beliefs[]? | $sel) |= (
        .confidence = ((((.confidence//0.5) + (\$s*\$d))) as \$nc | if \$nc>1 then 1 elif \$nc<0 then 0 else \$nc end)
        | (if \$s>0 then .supports = ((.supports//[]) + (if \$ev==\"\" then [] else [\$ev] end))
                   else .contradicts = ((.contradicts//[]) + (if \$ev==\"\" then [] else [\$ev] end)) end)
        | .status = (if .confidence <= 0.15 then \"refuted\" elif .confidence >= 0.85 then \"strong\" else (.status//\"open\") end) )
    " "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    echo "INANC $OP : '$KEY' (delta=$DELTA)$([[ -n "$EV" ]] && echo " kanit=$EV")" ;;
  resolve)
    KEY="${3:-}"; VERD="${4:-}"
    [[ -z "$KEY" || ! "$VERD" =~ ^(confirmed|refuted)$ ]] && { echo "KULLANIM: belief.sh <surf> resolve <id|iddia> <confirmed|refuted>" >&2; exit 2; }
    jq --arg k "$KEY" --arg v "$VERD" "(.beliefs[]? | $sel | .status) = \$v" "$SURF" > "$SURF.tmp" && mv "$SURF.tmp" "$SURF"
    echo "INANC resolve: '$KEY' -> $VERD$([[ "$VERD" == confirmed ]] && echo "  (simdi validate_finding ile KANITLA)")" ;;
  list)
    echo "INANC DEFTERI ($(jq '[.beliefs[]?]|length' "$SURF") teori):"
    jq -r '.beliefs[]? | "  ["+((.confidence//0)|tostring)+" "+(.status//"open")+"] "+.claim' "$SURF" 2>/dev/null || true ;;
  *) echo "Bilinmeyen op: $OP" >&2; exit 2 ;;
esac
