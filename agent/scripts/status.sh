#!/usr/bin/env bash
set -uo pipefail
SURF="${1:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -z "$SURF" ]]; then
  AT="$ROOT/.cypture/plugin/ACTIVE_TARGET"; [[ -f "$AT" ]] && SURF="$(head -1 "$AT" | tr -d '[:space:]')"
fi
[[ -z "$SURF" ]] && SURF=$(ls -t targets/*/surface.json 2>/dev/null | head -1 || true)
[[ -z "$SURF" || ! -f "$SURF" ]] && { echo "STATUS: surface.json yok (önce: bash scripts/pentest.sh <hedef>)"; exit 3; }
command -v jq >/dev/null || { echo "HATA: jq gerekli" >&2; exit 3; }
DIR="$(dirname "$SURF")"; SIG="$DIR/signals.jsonl"

read -r TARGET BSPENT BMAX STOPR START THROT <<<"$(jq -r '
  [(.target//"?"),(.run.budget_spent//0),(.run.budget_max//0),((.run.stop_reason//"")|if .=="" then "-" else . end),
   (.run.started_at//"-"),((.run.throttle//false)|tostring)] | @tsv' "$SURF")"
ELAP="-"
if [[ "$START" != "-" ]]; then
  s=$(date -d "$START" +%s 2>/dev/null || echo ""); n=$(date +%s)
  [[ -n "$s" ]] && { m=$(( (n - s)/60 )); ELAP="${m}m"; }
fi

read -r HT L0 L1 L2 L3 L4 HP <<<"$(jq -r '
  def d(x): (.depth_achieved // "L0")==x;
  [ (.assets|length),
    ([.assets[]|select(d("L0"))]|length), ([.assets[]|select(d("L1"))]|length),
    ([.assets[]|select(d("L2"))]|length), ([.assets[]|select(d("L3"))]|length),
    ([.assets[]|select(d("L4"))]|length),
    ([.assets[]|select(.priority=="high" and ((.depth_achieved//"L0")|test("^L[012]?$")))]|length)
  ] | @tsv' "$SURF")"

CLS="$(bash "$ROOT/scripts/class_coverage.sh" "$SURF" 2>/dev/null | grep -E 'Hücre' | head -1 | sed -E 's/.*toplam=//; s/  */ /g')"
CLS="${CLS:-?}"

CAND=$(jq '[.findings[]?|select(.state=="candidate")]|length' "$SURF")
VAL=$(jq '[.findings[]?|select(.state=="validated" or .state=="reported")]|length' "$SURF")
REF=$(jq '[.findings[]?|select(.state=="refuted")]|length' "$SURF")
RAW=0; [[ -f "$SIG" ]] && RAW=$(grep -c . "$SIG" 2>/dev/null || true); RAW="${RAW:-0}"
AUD=0; [[ -f "$DIR/signals.audited" ]] && AUD=$(tr -dc '0-9' < "$DIR/signals.audited" 2>/dev/null); AUD="${AUD:-0}"
RAW=$(( RAW - AUD )); [[ "$RAW" -lt 0 ]] && RAW=0

read -r AG_RUN AG_STALE OOB_PEND OOB_OK CHAINS HYP_OPEN <<<"$(jq -r '
  [ ([.agents[]?|select(.status=="running")]|length),
    ([.agents[]?|select(.status=="stale")]|length),
    ([.oob_canaries[]?|select((.injected//false) and ((.confirmed//false)|not))]|length),
    ([.oob_canaries[]?|select(.confirmed//false)]|length),
    ([.hypotheses[]?|select(.class=="chain" and .state=="open")]|length),
    ([.hypotheses[]?|select(.state=="open")]|length) ] | @tsv' "$SURF")"
MODELS_DOWN=$(jq -r '[(.run.model_health // {}) | to_entries[] | select(.value.status=="down" or .value.status=="exhausted") | .key] | join(",")' "$SURF")
KB_TECH=$(jq -r '(.run.kb_confirmed_tech // []) | join(",")' "$SURF")
read -r TH_PURP TH_OPENQ BEL_OPEN BEL_STRONG <<<"$(jq -r '
  [ (.theory.purpose // "-"),
    ([.theory.open_questions[]?|select((.state//"open")=="open")]|length),
    ([.beliefs[]?|select((.status//"open")=="open")]|length),
    ([.beliefs[]?|select(.status=="strong" or .status=="confirmed")]|length) ] | @tsv' "$SURF")"

NEXT="$(bash "$ROOT/scripts/decide_next.sh" "$SURF" 2>/dev/null | grep '^DECISION:' | tail -1)"

printf 'TARGET   %s   budget %s/%s   elapsed %s   throttle:%s   stop_reason: %s\n' "$TARGET" "$BSPENT" "$BMAX" "$ELAP" "$THROT" "$STOPR"
printf 'HOSTS    %s total | L0:%s L1:%s L2:%s L3:%s L4:%s   high-pending:%s\n' "$HT" "$L0" "$L1" "$L2" "$L3" "$L4" "$HP"
printf 'CLASSES  cells %s\n' "$CLS"
printf 'SIGNALS  candidate:%s  validated:%s  refuted:%s  raw_unaudited:%s\n' "$CAND" "$VAL" "$REF" "$RAW"
printf 'AGENTS   running:%s  stale:%s   | OOB pending:%s confirmed:%s   | chains:%s open_hyp:%s\n' "$AG_RUN" "$AG_STALE" "$OOB_PEND" "$OOB_OK" "$CHAINS" "$HYP_OPEN"
printf 'THEORY   %s   | açık-soru:%s  inanç(açık:%s güçlü:%s)\n' "$TH_PURP" "$TH_OPENQ" "$BEL_OPEN" "$BEL_STRONG"
printf 'MODELS   down/exhausted:[%s]   | KB tech:[%s]\n' "${MODELS_DOWN:-yok}" "${KB_TECH:-—}"
printf 'NEXT     %s\n' "${NEXT:-?}"
